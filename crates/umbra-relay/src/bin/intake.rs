//! The intake of a directory with one operator (Part 10 §10.6.4). A relay
//! that wants to join asks it for its own address, for a test of its port,
//! and it sends its join request to it. The intake holds no key of the
//! directory, and it admits no relay: each request waits in the inbox for
//! the owner (`REL-012`).
//!
//! ```text
//! umbra-intake <settings file>
//! ```
//!
//! The settings file holds one `key=value` pair on each line:
//!
//! ```text
//! listen=127.0.0.1:7460
//! inbox=/var/lib/umbra-intake/inbox
//! as_table=/var/lib/umbra-intake/ip2asn-v4.tsv
//! own_operator=<operator name>
//! behind_proxy=yes
//! ```
//!
//! `as_table` names a file with one address range on each line: the first
//! address, the last address, the AS number, and the country of the
//! registry entry, with a tab between two values. The intake reads the file
//! again when it changes. With no table, the intake states the address
//! alone, and it compares no AS number.
//!
//! With `behind_proxy=yes`, a proxy on this machine states the address of
//! each client in the `X-Real-IP` header, and the intake answers no request
//! from another machine. Without that line, the address of the connection
//! is the address of the client.
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

use std::{collections::BTreeMap, path::PathBuf, process::ExitCode, sync::Arc};

use tokio::net::TcpListener;
use umbra_relay::intake_server::{serve, Intake, Settings};

fn read_settings(path: &str) -> Result<(String, Settings), &'static str> {
    let text = std::fs::read_to_string(path).map_err(|_| "the settings file does not read")?;
    let pairs: BTreeMap<&str, &str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.trim().split_once('='))
        .collect();

    let listen = pairs
        .get("listen")
        .ok_or("the settings hold no listen line")?;
    let inbox = pairs
        .get("inbox")
        .ok_or("the settings hold no inbox line")?;
    let settings = Settings {
        inbox: PathBuf::from(inbox),
        as_table: pairs.get("as_table").map(PathBuf::from),
        own_operator: pairs.get("own_operator").map(|name| (*name).to_owned()),
        behind_proxy: pairs.get("behind_proxy") == Some(&"yes"),
    };

    Ok(((*listen).to_owned(), settings))
}

fn run(path: &str) -> Result<(), &'static str> {
    let (listen, settings) = read_settings(path)?;
    std::fs::create_dir_all(&settings.inbox).map_err(|_| "the inbox cannot be made")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "the runtime does not start")?;

    runtime.block_on(async {
        let listener = TcpListener::bind(&listen)
            .await
            .map_err(|_| "the listen address cannot be bound")?;
        eprintln!("umbra-intake: listening on {listen}");

        serve(listener, Arc::new(Intake::new(settings))).await;
        Ok(())
    })
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let (Some(path), None) = (arguments.next(), arguments.next()) else {
        eprintln!("usage: umbra-intake <settings file>");
        return ExitCode::FAILURE;
    };

    match run(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(cause) => {
            eprintln!("umbra-intake: {cause}");
            ExitCode::FAILURE
        }
    }
}
