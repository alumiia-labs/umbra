//! A text client of the release network, for tests by hand. It runs the
//! exported surface of Part 14 §14.6.1, as the Android app does, over a
//! SQLite file of its own.
//!
//! ```text
//! umbra-cli [--dir <data directory>] [--assets <release assets>]
//! ```
//!
//! The data directory holds the store, the key of the software keystore,
//! the kept manifest, and the held key set. It defaults to
//! `target/umbra-cli` of the repository. The release assets are the files
//! that `scripts/release-network.sh` writes, and they default to
//! `android/app/src/release/assets`.
//!
//! The passphrase comes from the variable `UMBRA_CLI_PASSPHRASE`, or from
//! the first line of the standard input. The first start makes the store
//! under it.
//!
//! The keystore is a key in a file, thus the client gives no protection of
//! Part 14 §14.6.4. Use it for tests alone, never for real conversations.
//!
//! A line that starts with `/` is a command. Each other line goes as a
//! message to the current conversation.
//!
//! | Command | Action |
//! | --- | --- |
//! | `/invite` | Prints a one-time invitation link |
//! | `/accept <link>` | Opens the invitation link of another party |
//! | `/list` | Lists the conversations |
//! | `/use <number>` | Makes a conversation of the list the current one |
//! | `/quit` | Stops the network and ends the program |

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use umbra_crypto::{
    hmac::{digest::KeyInit, Hmac, Mac},
    sha2::Sha256,
};
use umbra_ffi::bindings::{
    advance_key_set, fetch_key_chain, fetch_manifest, init, newest_key_set, Config, FfiError,
    FfiEvent, Handle, Network, SecureElementCallback, TextSink,
};

/// The port of each carrier of the manifest (Part 3 §3.10).
const CARRIER_PORT: u16 = 443;
/// The wait before a new run after a run ended with a fault.
const RETRY_DELAY: Duration = Duration::from_secs(5);
/// A large measured time gives the floor cost of Argon2id, thus a start
/// takes about one second.
const ARGON2_FLOOR_MS: u64 = 60_000;

type Failure = String;

fn failed(context: &str, error: impl std::fmt::Debug) -> Failure {
    format!("{context}: {error:?}")
}

/// The software keystore: an HMAC key in a file of the data directory.
struct FileKeystore([u8; 32]);

impl SecureElementCallback for FileKeystore {
    fn keyed(&self, input: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| FfiError::Malformed)?;
        mac.update(&input);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

/// The text of one message, as the core renders it.
#[derive(Default)]
struct Rendered(Mutex<Vec<u16>>);

impl TextSink for Rendered {
    fn put(&self, code_units: Vec<u16>) -> Result<(), FfiError> {
        if let Ok(mut held) = self.0.lock() {
            *held = code_units;
        }
        Ok(())
    }
}

/// The values of the release assets that a run needs.
struct Pinned {
    keyset: Vec<u8>,
    carriers: Vec<(String, Vec<u8>)>,
    invitation_host: String,
    shipped_epoch: u64,
}

/// The paths and the state of one client.
struct Cli {
    handle: Arc<Handle>,
    pinned: Pinned,
    data: PathBuf,
    current: Mutex<Option<Vec<u8>>>,
}

fn main() {
    if let Err(failure) = run() {
        eprintln!("umbra-cli: {failure}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Failure> {
    let (data, assets) = arguments()?;
    fs::create_dir_all(&data).map_err(|e| failed("the data directory", e))?;
    let pinned = pinned(&assets)?;

    let mut input = io::stdin().lock();
    let handle = open(&data, &mut input)?;
    let cli = Arc::new(Cli {
        handle,
        pinned,
        data,
        current: Mutex::new(None),
    });

    cli.connect()?;
    let events = Arc::clone(&cli);
    thread::spawn(move || events.drain_events());

    println!("Type /help for the commands.");
    for line in input.lines() {
        let line = line.map_err(|e| failed("the standard input", e))?;
        if !cli.command(line.trim()) {
            break;
        }
    }

    cli.handle.disconnect();
    Ok(())
}

/// The data directory and the assets directory, from the arguments or
/// from their defaults in the repository.
fn arguments() -> Result<(PathBuf, PathBuf), Failure> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut data = repository.join("target/umbra-cli");
    let mut assets = repository.join("android/app/src/release/assets");

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--dir" => data = PathBuf::from(value),
            "--assets" => assets = PathBuf::from(value),
            _ => return Err(format!("unknown argument {flag}")),
        }
    }

    Ok((data, assets))
}

fn ipv4(text: &str) -> Option<Vec<u8>> {
    let octets: Vec<u8> = text
        .trim()
        .split('.')
        .map(|part| part.parse::<u8>().ok())
        .collect::<Option<_>>()?;
    (octets.len() == 4).then_some(octets)
}

/// A `<name or url>,<IPv4 address>` value of the network file.
fn endpoint(value: &str) -> Option<(String, Vec<u8>)> {
    let (name, address) = value.split_once(',')?;
    Some((name.trim().to_owned(), ipv4(address)?))
}

/// Reads the release assets, as the release app does (`REL-045`).
fn pinned(assets: &Path) -> Result<Pinned, Failure> {
    let read = |name: &str| {
        fs::read(assets.join(name)).map_err(|e| failed(&format!("the asset {name}"), e))
    };
    let text = String::from_utf8(read("umbra-network.properties")?)
        .map_err(|e| failed("the network file", e))?;
    let properties: HashMap<&str, &str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();

    let carriers: Vec<_> = properties
        .get("carriers")
        .unwrap_or(&"")
        .split(';')
        .filter_map(endpoint)
        .collect();
    if carriers.is_empty() {
        return Err("the network file names no carrier".into());
    }

    let invitation_host = properties
        .get("invitation_host")
        .ok_or("the network file names no invitation host")?
        .to_string();
    let shipped_epoch = properties
        .get("shipped_epoch")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|epoch| *epoch > 0)
        .ok_or("the network file names no shipped epoch")?;

    Ok(Pinned {
        keyset: read("umbra-keyset.bin")?,
        carriers,
        invitation_host,
        shipped_epoch,
    })
}

/// The key of the software keystore. The first start makes it.
fn keystore_key(data: &Path) -> Result<[u8; 32], Failure> {
    let path = data.join("element.key");
    if let Ok(bytes) = fs::read(&path) {
        return bytes
            .try_into()
            .map_err(|_| "the file element.key does not hold 32 bytes".into());
    }

    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| failed("the random source", e))?;
    fs::write(&path, key).map_err(|e| failed("the file element.key", e))?;
    restrict(&path)?;
    Ok(key)
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| failed("the permissions of a key file", e))
}

#[cfg(not(unix))]
fn restrict(_: &Path) -> Result<(), Failure> {
    Ok(())
}

fn passphrase(input: &mut impl BufRead) -> Result<Vec<u16>, Failure> {
    if let Ok(text) = std::env::var("UMBRA_CLI_PASSPHRASE") {
        return Ok(text.encode_utf16().collect());
    }

    print!("passphrase: ");
    io::stdout()
        .flush()
        .map_err(|e| failed("the standard output", e))?;
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|e| failed("the standard input", e))?;
    Ok(line.trim_end_matches(['\r', '\n']).encode_utf16().collect())
}

/// Opens the store. The first start makes it under the passphrase, and a
/// later start unlocks it.
fn open(data: &Path, input: &mut impl BufRead) -> Result<Arc<Handle>, Failure> {
    let database = data.join("client.db");
    let is_new = !database.exists();
    let config = Config {
        database_path: database.to_string_lossy().into_owned(),
        argon2_floor_ms: ARGON2_FLOOR_MS,
    };
    let element = Arc::new(FileKeystore(keystore_key(data)?)) as Arc<dyn SecureElementCallback>;
    let passphrase = passphrase(input)?;

    if is_new {
        return init(config, element, passphrase).map_err(|e| failed("the new store", e));
    }

    let handle = init(config, element, Vec::new()).map_err(|e| failed("the store", e))?;
    handle
        .unlock(passphrase)
        .map_err(|e| failed("the unlock", e))?;
    Ok(handle)
}

fn short(id: &[u8]) -> String {
    id.iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Cli {
    /// The network of the newest manifest that verifies (Part 10
    /// `NET-318`). A fresh manifest of a carrier comes first, and the kept
    /// one is the fallback.
    fn network(&self) -> Result<Network, Failure> {
        let kept_path = self.data.join("manifest.bin");
        let held_path = self.data.join("keyset-held.bin");
        let keyset = newest_key_set(fs::read(&held_path).ok(), self.pinned.keyset.clone());

        let fresh = self.pinned.carriers.iter().filter_map(|(host, address)| {
            fetch_manifest(host.clone(), address.clone(), CARRIER_PORT, None)
                .ok()
                .map(|manifest| (manifest, true))
        });
        let kept = fs::read(&kept_path).ok().map(|manifest| (manifest, false));

        for (manifest, is_fresh) in fresh.chain(kept) {
            let verified = match self.verify(&manifest, &keyset) {
                Ok(verified) => verified,
                Err(FfiError::Unverified) => {
                    // REL-200: a manifest under a later key set.
                    let Some((next, verified)) = self.advanced(&keyset, &manifest) else {
                        continue;
                    };
                    fs::write(&held_path, next).map_err(|e| failed("the held key set", e))?;
                    verified
                }
                Err(_) => continue,
            };

            if is_fresh {
                fs::write(&kept_path, &manifest).map_err(|e| failed("the kept manifest", e))?;
            }
            return Ok(verified);
        }

        Err("no carrier gave a manifest that verifies".into())
    }

    fn verify(&self, manifest: &[u8], keyset: &[u8]) -> Result<Network, FfiError> {
        // The client registers no push and holds no handle, thus the
        // network has no NDR and no directory.
        self.handle
            .network_of_manifest(
                manifest.to_vec(),
                keyset.to_vec(),
                self.pinned.shipped_epoch,
                self.pinned.invitation_host.clone(),
                None,
            )
            .map(|verified| verified.network)
    }

    /// The key set that the chain of a carrier reaches from `held`, with
    /// the network of `manifest` under it.
    fn advanced(&self, held: &[u8], manifest: &[u8]) -> Option<(Vec<u8>, Network)> {
        self.pinned.carriers.iter().find_map(|(host, address)| {
            let chain = fetch_key_chain(host.clone(), address.clone(), CARRIER_PORT, None).ok()?;
            let next = advance_key_set(held.to_vec(), chain).ok()?;
            if next == held {
                return None;
            }

            let network = self.verify(manifest, &next).ok()?;
            Some((next, network))
        })
    }

    fn connect(&self) -> Result<(), Failure> {
        let network = self.network()?;
        Arc::clone(&self.handle)
            .connect(network)
            .map_err(|e| failed("the start of the network", e))?;
        self.handle.set_foreground(true);
        println!("Connecting to the release network.");
        Ok(())
    }

    fn drain_events(self: Arc<Self>) {
        loop {
            if let Some(event) = self.handle.wait_event(1_000) {
                self.show(event);
            }
        }
    }

    fn show(self: &Arc<Self>, event: FfiEvent) {
        match event {
            FfiEvent::Online => println!("* online"),
            FfiEvent::Offline { cause } => {
                println!("* offline (cause {cause})");
                // Cause 0 is a stop of this program.
                if cause != 0 {
                    let cli = Arc::clone(self);
                    thread::spawn(move || {
                        thread::sleep(RETRY_DELAY);
                        if let Err(failure) = cli.connect() {
                            println!("* no new run: {failure}");
                        }
                    });
                }
            }
            FfiEvent::Invitation { link } => {
                println!("* invitation link, which works one time:\n{link}")
            }
            FfiEvent::InvitationGone => {
                println!("* the invitation is gone: another party opened it, or it expired")
            }
            FfiEvent::Contact { conversation } => {
                println!("* contact ready: {}", short(&conversation));
                let mut current = self
                    .current
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if current.is_none() {
                    println!("* {} is the current conversation", short(&conversation));
                    *current = Some(conversation);
                }
            }
            FfiEvent::Message {
                conversation,
                message,
            } => self.show_message(&conversation, message),
            FfiEvent::Delivery { state, .. } => {
                let word = match state {
                    1 => "accepted by the relay",
                    2 => "delivered",
                    3 => "read",
                    4 => "failed",
                    _ => return,
                };
                println!("* message {word}");
            }
            FfiEvent::ContactRequest => println!("* a contact request arrived"),
            FfiEvent::Refused => println!("* the client refused the command"),
            _ => {}
        }
    }

    fn show_message(&self, conversation: &[u8], message: Arc<umbra_ffi::bindings::MsgHandle>) {
        let is_outgoing = self
            .handle
            .msg_info(Arc::clone(&message))
            .map(|info| info.outgoing)
            .unwrap_or(true);
        if is_outgoing {
            return;
        }

        let rendered = Arc::new(Rendered::default());
        if self.handle.msg_render(message, rendered.clone()).is_err() {
            println!("[{}] (a message with no text)", short(conversation));
            return;
        }

        let units = rendered
            .0
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default();
        println!(
            "[{}] {}",
            short(conversation),
            String::from_utf16_lossy(&units)
        );
        let _ = self.handle.mark_read(conversation.to_vec());
    }

    /// Runs one line of the user. The result is false at `/quit`.
    fn command(&self, line: &str) -> bool {
        let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
        let result = match word {
            "" => Ok(()),
            "/quit" => return false,
            "/help" => {
                println!("/invite, /accept <link>, /list, /use <number>, /quit; another line is a message");
                Ok(())
            }
            "/invite" => self
                .handle
                .invite()
                .map_err(|e| failed("the invitation", e)),
            "/accept" => self
                .handle
                .accept(rest.trim().to_owned())
                .map_err(|e| failed("the accept", e)),
            "/list" => self.list(),
            "/use" => self.choose(rest.trim()),
            _ if word.starts_with('/') => Err(format!("unknown command {word}; type /help")),
            _ => self.send(line),
        };

        if let Err(failure) = result {
            println!("! {failure}");
        }
        true
    }

    fn list(&self) -> Result<(), Failure> {
        let conversations = self
            .handle
            .conversations()
            .map_err(|e| failed("the list", e))?;
        let current = self
            .current
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default();
        if conversations.is_empty() {
            println!("No conversation. Use /invite.");
        }

        for (number, conversation) in conversations.iter().enumerate() {
            let mark = if current.as_ref() == Some(conversation) {
                "*"
            } else {
                " "
            };
            println!("{mark} {} {}", number + 1, short(conversation));
        }
        Ok(())
    }

    fn choose(&self, number: &str) -> Result<(), Failure> {
        let index = number
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1))
            .ok_or("give the number of a conversation from /list")?;
        let conversations = self
            .handle
            .conversations()
            .map_err(|e| failed("the list", e))?;
        let chosen = conversations
            .get(index)
            .ok_or("no conversation has that number")?
            .clone();

        println!("* {} is the current conversation", short(&chosen));
        if let Ok(mut current) = self.current.lock() {
            *current = Some(chosen);
        }
        Ok(())
    }

    fn send(&self, text: &str) -> Result<(), Failure> {
        let conversation = self
            .current
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default()
            .ok_or("no current conversation; use /invite or /use")?;

        let draft = self
            .handle
            .new_draft(conversation)
            .map_err(|e| failed("the draft", e))?;
        draft
            .set_text(text.encode_utf16().collect())
            .map_err(|e| failed("the text", e))?;
        self.handle
            .send_draft(draft)
            .map_err(|e| failed("the send", e))?;
        Ok(())
    }
}
