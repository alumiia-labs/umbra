//! The isolation query of Part 10 §10.4.2: a probe on the chain under query,
//! and the receipts of each link of it after the epoch of the probe.

use std::{io::Write as _, time::Duration};

use tokio::sync::mpsc;
use umbra_core::{
    directory::{
        manifest::{ListedRelay, RelaySet},
        receipt::{judge_link, LinkVerdict, ReceiptAnswer, ReceiptQuery},
        EPOCH_SECONDS,
    },
    session::node::ClientNode,
};
use umbra_crypto::{hierarchy::RootIdentity, secret::Secret, sign::SigningKey};
use umbra_ffi::runtime::{run_client, Command, NoStore, OsRng, Update};
use umbra_transport::{https, native, Dial};

use super::{dial_of, info, relay_set, to_hex, unix_now, Settings};

/// The wait for the probe circuit and its loop.
const PROBE_WAIT: Duration = Duration::from_secs(120);
/// The wait after the end of the epoch of the probe: each relay closes its
/// windows at its next tick and sends each receipt back (`REL-176`).
const RECEIPT_SETTLE: u64 = 120;
/// The wait for the answer of one relay.
const ASK_WAIT: Duration = Duration::from_secs(15);

/// The verdict of one query: each link held, or the first that did not.
pub enum Verdict {
    /// Each link of the chain carried the probe.
    Held,
    /// One link did not.
    Link(LinkVerdict),
}

fn find<'a>(set: &'a RelaySet, relay_id: &[u8; 32]) -> Result<&'a ListedRelay, &'static str> {
    set.relays
        .iter()
        .find(|relay| relay.candidate.relay_id == *relay_id)
        .ok_or("a relay of the chain is not in the manifest")
}

/// Sends the probe on `chain` and gives the tag of each hop and the epoch
/// (`REL-109` to `REL-111`). The node holds that chain alone, and a fresh
/// identity, thus the probe is an ordinary client circuit.
async fn probe(
    settings: &Settings,
    set: &RelaySet,
    chain: &[[u8; 32]; 3],
) -> Result<([[u8; 16]; 3], u64), &'static str> {
    let [first, second, third] = chain;
    let (a, b, c) = (find(set, first)?, find(set, second)?, find(set, third)?);
    if !a.candidate.ingress {
        return Err("the chain does not start at an ingress relay");
    }
    let mut seed = [0u8; 32];
    umbra_crypto::rand_core::TryRng::try_fill_bytes(&mut OsRng, &mut seed)
        .map_err(|_| "no random bytes")?;
    let node = ClientNode::with_relays(
        info(a),
        vec![info(b), info(c)],
        RootIdentity::new(Secret::new(seed)),
    );
    let tls =
        native::tls_config_with_root_file(&settings.ca).map_err(|_| "the root does not read")?;
    let (commands, runtime_commands) = mpsc::unbounded_channel();
    let (runtime_updates, mut updates) = mpsc::unbounded_channel();
    let dial: Dial = dial_of(a);
    let run = tokio::spawn(run_client(
        node,
        dial,
        tls,
        runtime_commands,
        runtime_updates,
        Box::new(NoStore),
    ));
    let _ = commands.send(Command::OpenCircuit(*third));
    let deadline = tokio::time::Instant::now() + PROBE_WAIT;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let found = loop {
        tokio::select! {
            update = updates.recv() => match update {
                Some(Update::Probe { chain: took, tags }) if took == *chain => {
                    break Ok((tags, unix_now() / EPOCH_SECONDS));
                }
                Some(Update::Offline(_)) | None => break Err("the probe circuit ended"),
                _ => {}
            },
            _ = tick.tick() => {
                if tokio::time::Instant::now() > deadline {
                    break Err("the probe circuit did not build");
                }
                let _ = commands.send(Command::Probe);
            }
        }
    };
    drop(commands);
    let _ = run.await;
    found
}

/// The answer of one relay to a signed query, or none.
async fn ask(settings: &Settings, relay: &ListedRelay, body: &[u8]) -> Option<ReceiptAnswer> {
    let url = https::Url {
        host: relay.host.clone(),
        port: relay.port,
        path: "/receipt".into(),
        address: Some(std::net::IpAddr::from(relay.addr_v4)),
    };
    let tls = native::tls_config_with_root_file(&settings.ca).ok()?;
    let (status, answer) = https::post(
        &url,
        "application/octet-stream",
        &[],
        body,
        tls,
        64 * 1024,
        ASK_WAIT,
    )
    .await
    .ok()?;
    (status == 200)
        .then(|| ReceiptAnswer::parse(&answer).ok())
        .flatten()
}

/// Runs one isolation query on `chain` and gives its verdict and the epoch
/// of its probe (`REL-081` to `REL-084`).
pub async fn isolate(
    settings: &Settings,
    key: &SigningKey,
    chain: [[u8; 32]; 3],
) -> Result<(Verdict, u64), &'static str> {
    let set = relay_set(settings)?;
    let (tags, epoch) = probe(settings, &set, &chain).await?;
    println!("probe sent in epoch {epoch}, the receipts follow its end");
    let ready = (epoch + 1) * EPOCH_SECONDS + RECEIPT_SETTLE;
    tokio::time::sleep(Duration::from_secs(ready.saturating_sub(unix_now()))).await;
    // The link from hop k to hop k + 1 carries the tag of hop k + 1.
    let [first, second, third] = chain;
    let [_, second_tag, third_tag] = tags;
    for (from, to, tag) in [(first, second, second_tag), (second, third, third_tag)] {
        let query = ReceiptQuery {
            authority_index: settings.index,
            epoch,
            tag,
        };
        let body = query
            .sign(key, &mut OsRng)
            .map_err(|_| "the query does not sign")?;
        let taken = ask(settings, find(&set, &from)?, &body).await;
        let to_relay = find(&set, &to)?;
        let issued = ask(settings, to_relay, &body).await;
        let verdict = judge_link(
            from,
            to,
            &query,
            taken.as_ref(),
            issued.as_ref(),
            &to_relay.identity_pk,
        );
        if verdict != LinkVerdict::Held {
            return Ok((Verdict::Link(verdict), epoch));
        }
    }
    Ok((Verdict::Held, epoch))
}

/// Prints a verdict and keeps it in the file of verdicts, which the signer
/// of the manifest reads (`REL-083`, `REL-183`).
pub fn record(settings: &Settings, chain: &[[u8; 32]; 3], verdict: &Verdict, epoch: u64) {
    let line = match verdict {
        Verdict::Held => format!("held {}", chain.map(|relay| to_hex(&relay)).join(",")),
        Verdict::Link(LinkVerdict::Contradiction { relay }) => format!("expel {}", to_hex(relay)),
        Verdict::Link(LinkVerdict::LinkFault { from, to }) => {
            format!("link {} {} {epoch}", to_hex(from), to_hex(to))
        }
        Verdict::Link(LinkVerdict::Held) => return,
    };
    println!("verdict {line}");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&settings.verdicts)
    {
        let _ = writeln!(file, "{line}");
    }
}
