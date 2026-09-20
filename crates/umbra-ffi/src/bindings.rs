//! The UniFFI scaffolding of Part 15 §15.6.1 over [`crate::client`] and the
//! SQLite backend.
//!
//! `Draft` and `MsgRef` cross as opaque object handles (`IMP-038`). Text
//! and the passphrase cross as UTF-16 code units and never as a Kotlin
//! `ByteArray` or a Kotlin `String` (`IMP-037`). UniFFI has no `CharArray`
//! type, thus the generated Kotlin takes a list of code units, and the
//! Kotlin wrapper of the app fills it from a `CharArray` that it overwrites
//! after the call.
//!
//! The network runtime sits behind the same handle. One tokio runtime of
//! two workers owns the client node and the socket, and a task of it gives
//! each update to the client under the lock of the handle.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Condvar, Mutex, MutexGuard, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::mpsc;
use umbra_core::{
    attach::{place::AttachmentRelay, transfer::Shape},
    directory::{
        bloc::BlocList,
        manifest::{RelayManifest, RelaySet},
        path::{Candidate, INGRESS_PINS},
        root::{ClockState, Consensus, DirectoryKeySet},
    },
    identity::invitation::{Fragment, FRAGMENT_LEN},
    session::node::{ClientNode, ContactId, RelayInfo, StateChange},
    store::wrap::{Cost, SecureElement, WrapHeader, M_KIB_FLOOR, T_FLOOR},
};
use umbra_crypto::handshake::nk::RelayStatic;
use umbra_transport::{native, Dial};
use zeroize::Zeroizing;

use crate::{
    bridge::{Bridge, NetEvent},
    client::Client,
    draft::Draft,
    runtime::{run_client, Ended, OsRng, Persist, Update},
    sqlite::SqliteBackend,
    transfers::{run_transfers, TransferCommand, TransferUpdate},
    ConversationId, Delivery, Error, Event, MsgRef, Sink,
};

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn unix_now() -> u64 {
    unix_now_ms() / 1_000
}

/// The error of the surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
pub enum FfiError {
    /// The client is locked.
    Locked,
    /// The passphrase does not open the store on this device.
    WrongPassphrase,
    /// The local store does not verify.
    Integrity,
    /// A value does not parse, or a draft holds nothing.
    Malformed,
    /// A value is above its bound.
    TooLong,
    /// The handle names no message, or the draft was sent already.
    NotFound,
    /// The platform store failed.
    Storage,
    /// An earlier fault closed the client.
    Closed,
    /// The network runtime does not run.
    Offline,
    /// A limit on the rate of an act holds it back for a short time.
    Busy,
    /// A signed object does not verify under the keys that the build holds.
    Unverified,
    /// A signed object is older than one that the client verified already.
    Stale,
}

impl core::fmt::Display for FfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Error> for FfiError {
    fn from(inner: Error) -> Self {
        match inner {
            Error::Locked => FfiError::Locked,
            Error::WrongPassphrase => FfiError::WrongPassphrase,
            Error::Integrity => FfiError::Integrity,
            Error::Malformed => FfiError::Malformed,
            Error::TooLong => FfiError::TooLong,
            Error::NotFound => FfiError::NotFound,
            Error::Storage => FfiError::Storage,
            Error::Closed => FfiError::Closed,
            Error::Offline => FfiError::Offline,
            Error::Busy => FfiError::Busy,
        }
    }
}

/// The keyed function of the secure element, which the platform computes
/// in StrongBox or in the TEE: `HMAC-SHA256(k_se, input)`. The input holds
/// the Argon2id output, and this is the one crossing that the platform
/// forces, because the keystore has a Java interface only.
#[uniffi::export(with_foreign)]
pub trait SecureElementCallback: Send + Sync {
    /// Returns the 32 bytes of the keyed function, or an empty list when
    /// the keystore fails.
    fn keyed(&self, input: Vec<u8>) -> Vec<u8>;
}

struct ForeignElement(Arc<dyn SecureElementCallback>);

impl SecureElement for ForeignElement {
    fn keyed(&self, input: &[u8]) -> Result<[u8; 32], umbra_core::Error> {
        let output = Zeroizing::new(self.0.keyed(input.to_vec()));
        output
            .as_slice()
            .try_into()
            .map_err(|_| umbra_core::Error::Storage)
    }
}

/// The view of the platform that takes the text of one message.
#[uniffi::export(with_foreign)]
pub trait TextSink: Send + Sync {
    /// Takes the UTF-16 code units of the text.
    fn put(&self, code_units: Vec<u16>);
}

/// The decoder of the platform that takes the file of one message. This is
/// the one place where the bytes of a file cross the surface (`IMP-166`):
/// the image decoder of the platform reads a byte array and nothing else.
/// The platform overwrites the array when the decode ends.
#[uniffi::export(with_foreign)]
pub trait FileSink: Send + Sync {
    /// Takes the bytes of the file.
    fn put(&self, bytes: Vec<u8>);
}

struct ForeignSink(Arc<dyn TextSink>);

impl Sink for ForeignSink {
    fn put(&mut self, code_units: &[u16]) {
        self.0.put(code_units.to_vec());
    }
}

/// The settings of `init`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Config {
    /// The path of the SQLite file in the private storage of the app.
    pub database_path: String,
    /// The milliseconds that one Argon2id try at the floor cost took on
    /// this device. The first launch reads it, and a later launch ignores
    /// it.
    pub argon2_floor_ms: u64,
}

/// One relay of the set of the client, with the facts that the invariants
/// of Part 3 §3.4.6 test.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RelayEndpoint {
    /// The host name that the TLS certificate names.
    pub host: String,
    /// The 4 bytes of the IPv4 address.
    pub ipv4: Vec<u8>,
    /// The port.
    pub port: u16,
    /// The 32 bytes of the static X25519 key.
    pub static_key: Vec<u8>,
    /// The 32 bytes of the relay identifier.
    pub relay_id: Vec<u8>,
    /// The layer: 1 for an ingress relay, 2, or 3 for a queue relay.
    pub layer: u8,
    /// The name of the operator. Two relays of one operator share no chain.
    pub operator: String,
    /// The name of the family, or none for a family of the operator alone.
    /// Two relays of one family share no chain.
    pub family: Option<String>,
    /// The two letters of the jurisdiction. Two relays of one jurisdiction
    /// bloc share no chain.
    pub country: String,
    /// The autonomous system. Two relays of one system share no chain.
    pub asn: u32,
    /// The 2 bytes of the IPv4 /16, or none for the /16 of `ipv4`. A test
    /// network on one machine names a network for each relay here, because
    /// each of its relays has the address of that machine.
    pub prefix: Option<Vec<u8>>,
    /// Whether the relay holds chunks of files (Part 13). A network from a
    /// descriptor text has no such relay.
    pub holds_files: bool,
}

/// The network of the client: a set of relays for its chains. The first
/// relay of layer 1 is the pinned ingress. The signed relay directory of
/// Part 10 replaces this record later.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Network {
    /// The relays, with one or more of each layer.
    pub relays: Vec<RelayEndpoint>,
    /// A PEM file of the one authority that the client trusts, for a test
    /// network. With no file the client trusts the web roots.
    pub root_ca_path: Option<String>,
    /// The invitation host of Part 4 §4.3.1, which each link names.
    pub invitation_host: String,
}

/// Reads the relay manifest from an HTTPS carrier of Part 3 §3.10: the host
/// of a relay or of its co-tenant site. The call blocks for up to 20
/// seconds. The carrier learns the address of this device and nothing else,
/// and [`Handle::network_of_manifest`] verifies what it gave.
///
/// `root_ca_path` is the authority of a test network, or none for the web
/// roots.
#[uniffi::export]
pub fn fetch_manifest(
    host: String,
    ipv4: Vec<u8>,
    port: u16,
    root_ca_path: Option<String>,
) -> Result<Vec<u8>, FfiError> {
    let address: [u8; 4] = ipv4
        .as_slice()
        .try_into()
        .map_err(|_| FfiError::Malformed)?;
    let dial = Dial {
        host,
        addr_v4: Some(address),
        addr_v6: None,
        port,
    };
    let tls = match &root_ca_path {
        Some(path) => native::tls_config_with_root_file(path),
        None => native::tls_config(),
    }
    .map_err(|_| FfiError::Malformed)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| FfiError::Offline)?;
    runtime
        .block_on(native::fetch_manifest(&dial, tls))
        .map_err(|_| FfiError::Offline)
}

/// One relay of a circuit, as the view of the connection shows it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Hop {
    /// The host name of the relay.
    pub host: String,
    /// The two letters of its jurisdiction.
    pub country: String,
    /// Its layer, from 1 to 3.
    pub layer: u8,
}

/// The state of the connection of this device (Part 3 §3.4).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Connection {
    /// Whether a run of the network is active.
    pub is_running: bool,
    /// Each circuit that holds its three hops, hop 1 first.
    pub circuits: Vec<Vec<Hop>>,
    /// The count of the different relays in those circuits.
    pub relays_in_use: u32,
    /// The count of the relays of the relay set.
    pub relays_known: u32,
    /// The pinned ingress relay that the run dials, or none with no run.
    pub ingress: Option<Hop>,
    /// The other pinned ingress relay, or none with one pin.
    pub standby: Option<Hop>,
    /// The highest epoch of the relay directory that this device verified,
    /// or zero for a network with no signed directory.
    pub directory_epoch: u64,
}

/// A network that a signed relay manifest gave.
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerifiedNetwork {
    /// The network, for [`Handle::connect`].
    pub network: Network,
    /// The epoch of the root of the manifest.
    pub epoch: u64,
    /// Whether the time of the root is more than one hour from the clock of
    /// the device. The interface shows that state (`REL-116`).
    pub is_clock_corrected: bool,
}

fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    // With no random bytes the order of the set stands, which pins a relay
    // that the set lists first. The authorities order the set by a hash.
    let _ = umbra_crypto::rand_core::TryRng::try_fill_bytes(&mut OsRng, &mut bytes);
    u64::from_be_bytes(bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The relays of a verified set in the form of a network. A relay with no
/// IPv4 address stays out, because this client dials IPv4 alone.
fn endpoints_of(set: &RelaySet) -> Vec<RelayEndpoint> {
    set.relays
        .iter()
        .filter(|relay| relay.addr_v4 != [0; 4])
        .map(|relay| RelayEndpoint {
            host: relay.host.clone(),
            ipv4: relay.addr_v4.to_vec(),
            port: relay.port,
            static_key: relay.ntor_pk.to_vec(),
            relay_id: relay.candidate.relay_id.to_vec(),
            layer: relay.candidate.layer,
            // The two values are opaque, and a network compares them alone.
            operator: to_hex(&relay.candidate.operator_id),
            family: Some(to_hex(&relay.candidate.family_id)),
            country: String::from_utf8_lossy(&relay.jurisdiction).into_owned(),
            asn: relay.candidate.asn,
            prefix: None,
            holds_files: relay.has_attachment_role && relay.candidate.is_exit(),
        })
        .collect()
}

/// The first line of a network descriptor. Version 1 holds three relay
/// lines with no facts: one path, the guard first.
const DESCRIPTOR_HEADER: &str = "umbra-network 2";
const DESCRIPTOR_HEADER_V1: &str = "umbra-network 1";

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// Reads a network descriptor: the text that an operator of a test network
/// gives to a tester. The relay directory of Part 10 replaces it later.
///
/// ```text
/// umbra-network 2
/// relay <host> <IPv4 address> <port> <static key, hex> <relay id, hex> \
///       layer=<1|2|3> operator=<name> country=<two letters> asn=<number> [prefix=<a.b>]
/// relay ...
/// invite <invitation host>
/// ```
///
/// Each `relay` line comes from `umbra-relay descriptor`. The set holds one
/// or more relays of each layer. A line that starts with `#` and an empty
/// line carry nothing.
/// `root_ca_path` is the authority of a test network, or none for the web
/// roots.
#[uniffi::export]
pub fn parse_network(text: String, root_ca_path: Option<String>) -> Result<Network, FfiError> {
    let mut lines = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty());
    let has_facts = match lines.next() {
        Some(DESCRIPTOR_HEADER) => true,
        Some(DESCRIPTOR_HEADER_V1) => false,
        _ => return Err(FfiError::Malformed),
    };
    let mut relays = Vec::new();
    let mut invitation_host = None;
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["relay", host, address, port, static_key, relay_id, facts @ ..] => {
                let address: std::net::Ipv4Addr =
                    address.parse().map_err(|_| FfiError::Malformed)?;
                let key = |text: &str| hex_bytes(text).filter(|bytes| bytes.len() == 32);
                let mut relay = RelayEndpoint {
                    host: (*host).to_owned(),
                    ipv4: address.octets().to_vec(),
                    port: port.parse().map_err(|_| FfiError::Malformed)?,
                    static_key: key(static_key).ok_or(FfiError::Malformed)?,
                    relay_id: key(relay_id).ok_or(FfiError::Malformed)?,
                    layer: 0,
                    operator: String::new(),
                    family: None,
                    country: String::new(),
                    asn: 0,
                    prefix: None,
                    holds_files: false,
                };
                if has_facts {
                    read_facts(&mut relay, facts)?;
                } else if facts.is_empty() {
                    // The one path of version 1: three operators in three
                    // places, each line one layer.
                    let place = u8::try_from(relays.len().saturating_add(1))
                        .map_err(|_| FfiError::Malformed)?;
                    relay.layer = place;
                    relay.operator = format!("relay-{place}");
                    relay.country = format!("Z{}", char::from(b'A'.saturating_add(place)));
                    relay.asn = u32::from(place);
                    relay.prefix = Some(vec![0, place]);
                } else {
                    return Err(FfiError::Malformed);
                }
                relays.push(relay);
            }
            ["invite", host] if invitation_host.is_none() => {
                invitation_host = Some((*host).to_owned());
            }
            _ => return Err(FfiError::Malformed),
        }
    }
    if !has_facts && relays.len() != 3 {
        return Err(FfiError::Malformed);
    }
    // A chain holds one relay of each layer.
    if (1..=3u8).any(|layer| !relays.iter().any(|relay| relay.layer == layer)) {
        return Err(FfiError::Malformed);
    }
    Ok(Network {
        relays,
        root_ca_path,
        invitation_host: invitation_host.ok_or(FfiError::Malformed)?,
    })
}

/// Reads the `key=value` words of a relay line of version 2. Each of the
/// four facts is there one time, and `prefix` is there at most one time.
fn read_facts(relay: &mut RelayEndpoint, facts: &[&str]) -> Result<(), FfiError> {
    let mut seen = Vec::new();
    for fact in facts {
        let (name, value) = fact.split_once('=').ok_or(FfiError::Malformed)?;
        if seen.contains(&name) {
            return Err(FfiError::Malformed);
        }
        seen.push(name);
        match name {
            "layer" => {
                relay.layer = value.parse().map_err(|_| FfiError::Malformed)?;
                if !(1..=3).contains(&relay.layer) {
                    return Err(FfiError::Malformed);
                }
            }
            "operator" if !value.is_empty() => value.clone_into(&mut relay.operator),
            "country" if value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase()) => {
                value.clone_into(&mut relay.country);
            }
            "asn" => relay.asn = value.parse().map_err(|_| FfiError::Malformed)?,
            "prefix" => {
                let octets: Vec<u8> = value
                    .split('.')
                    .map(str::parse)
                    .collect::<Result<_, _>>()
                    .map_err(|_| FfiError::Malformed)?;
                if octets.len() != 2 {
                    return Err(FfiError::Malformed);
                }
                relay.prefix = Some(octets);
            }
            _ => return Err(FfiError::Malformed),
        }
    }
    let has_each = ["layer", "operator", "country", "asn"]
        .iter()
        .all(|name| seen.contains(name));
    if has_each {
        Ok(())
    } else {
        Err(FfiError::Malformed)
    }
}

/// The facts of a relay of the set, for the selection of a chain. The
/// operator is its own family, because a descriptor holds no family
/// certificate.
fn relay_info(endpoint: &RelayEndpoint) -> Result<RelayInfo, FfiError> {
    let key = relay_static(endpoint)?;
    let operator =
        umbra_crypto::hash::sha3_256(&[b"umbra/test/operator", endpoint.operator.as_bytes()]);
    let family = endpoint.family.as_ref().map_or(operator, |family| {
        umbra_crypto::hash::sha3_256(&[b"umbra/test/family", family.as_bytes()])
    });
    let country: [u8; 2] = endpoint
        .country
        .as_bytes()
        .try_into()
        .map_err(|_| FfiError::Malformed)?;
    let prefix = match &endpoint.prefix {
        Some(prefix) => prefix.as_slice().try_into().ok(),
        None => endpoint
            .ipv4
            .get(..2)
            .and_then(|octets| octets.try_into().ok()),
    };
    Ok(RelayInfo {
        candidate: Candidate {
            relay_id: key.relay_id,
            operator_id: operator,
            family_id: family,
            bloc: BlocList::v1().bloc_of(&country),
            asn: endpoint.asn,
            v4_prefix: Some(prefix.ok_or(FfiError::Malformed)?),
            v6_prefix: None,
            ingress: endpoint.layer == 1,
            chain: endpoint.layer != 1,
            queue: endpoint.layer == 3,
            layer: endpoint.layer,
        },
        key,
    })
}

fn relay_static(endpoint: &RelayEndpoint) -> Result<RelayStatic, FfiError> {
    let s = endpoint.static_key.as_slice().try_into();
    let relay_id = endpoint.relay_id.as_slice().try_into();
    Ok(RelayStatic {
        s: s.map_err(|_| FfiError::Malformed)?,
        relay_id: relay_id.map_err(|_| FfiError::Malformed)?,
    })
}

/// What a conversation view shows beside the text of a message.
#[derive(uniffi::Record)]
pub struct MsgInfo {
    /// Whether this device sent the message.
    pub outgoing: bool,
    /// The delivery state, with the values of [`FfiEvent::Delivery`].
    pub delivery: u8,
    /// The send time that the sender wrote, in milliseconds.
    pub sent_at_ms: u64,
    /// The time of this device at the store of the message, in
    /// milliseconds. The list of [`Handle::messages`] is in this order.
    pub stored_at_ms: u64,
    /// Whether a deletion took the content. The row is a placeholder, and
    /// it has no text.
    pub deleted: bool,
    /// Whether its sender changed the text (`DEV-090`).
    pub edited: bool,
    /// Whether this device can change the text now: a text of this device,
    /// inside `EDIT_WINDOW`, below `EDIT_MAX`.
    pub editable: bool,
    /// Whether the message answers a message (Part 6 §6.6.5).
    pub is_reply: bool,
    /// The message that it answers. With `is_reply` and no handle here, the
    /// device does not hold that message, and the view says so (`WIR-173`).
    pub reply_to: Option<Arc<MsgHandle>>,
    /// The file of the message, or none.
    pub file: Option<MsgFile>,
}

/// The file of a message, with no byte of it.
#[derive(uniffi::Record)]
pub struct MsgFile {
    /// 1 while this device uploads it, 2 while this device did not fetch it
    /// yet, 3 when the store holds it, and 4 after a transfer that failed.
    pub state: u8,
    /// The media class of the descriptor.
    pub mime_class: u8,
    /// The width of an image or a video, else 0.
    pub pixel_w: u16,
    /// The height of an image or a video, else 0.
    pub pixel_h: u16,
    /// The duration of an audio or a video object, else 0.
    pub media_seconds: u16,
}

/// One reaction to a message. The emoji holds emoji code points and no
/// other text, thus it crosses as a string.
#[derive(uniffi::Record)]
pub struct MsgReaction {
    /// The emoji.
    pub emoji: String,
    /// Whether this device sent it.
    pub mine: bool,
}

/// Which receipts this device sends to one contact.
#[derive(uniffi::Record)]
pub struct Receipts {
    /// A delivery receipt follows each message that this device holds.
    pub delivery: bool,
    /// A read receipt follows each message that the user saw.
    pub read: bool,
}

/// What a conversation list shows for one conversation.
#[derive(uniffi::Record)]
pub struct Summary {
    /// The conversation.
    pub conversation: Vec<u8>,
    /// The name that the user of this device gave the contact, or an empty
    /// string. It is a label of the user and no message text, thus it
    /// crosses as a string.
    pub name: String,
    /// The newest message, or none. Its text goes into a sink, as each
    /// message text does (`IMP-037`).
    pub last_message: Option<Arc<MsgHandle>>,
    /// The store time of the newest message, in milliseconds, or zero.
    pub last_at_ms: u64,
    /// The received messages that the user did not see yet.
    pub unread: u32,
    /// Whether the user verified the key that the contact holds now.
    pub verified: bool,
}

/// One event of the stream.
#[derive(uniffi::Enum)]
pub enum FfiEvent {
    /// The circuit is ready.
    Online,
    /// The set of the circuits changed. [`Handle::connection`] gives it.
    Circuits,
    /// The state of the file of a message changed. [`Handle::msg_info`]
    /// gives it.
    File {
        /// The conversation.
        conversation: Vec<u8>,
        /// The message.
        message: Arc<MsgHandle>,
    },
    /// The run of the network ended. The cause is 0 for a stop by the
    /// application, 1 for a dial that failed, 2 for a link that closed, 3
    /// for a circuit that a relay destroyed, 4 for a fault in the client,
    /// and 5 for a store that took no batch.
    Offline {
        /// The cause.
        cause: u8,
    },
    /// The link of an invitation, which the user gives out of band. It
    /// works one time (Part 4 §4.3.1).
    Invitation {
        /// The link, with the 68-byte fragment after `#`.
        link: String,
    },
    /// The relay holds no blob for a link that the user accepted: a second
    /// party opened the link first, or the link passed its lifetime. The
    /// interface tells the user, because the first case is an attack that
    /// the two parties detect (`IDN-023`).
    InvitationGone,
    /// A contact is ready, and its conversation takes drafts.
    Contact {
        /// The conversation.
        conversation: Vec<u8>,
    },
    /// The client refused an invitation command, such as a bundle that does
    /// not parse.
    Refused,
    /// The code of a verification ceremony. The two users compare it by
    /// voice or in person (Part 4 §4.5.2).
    VerificationCode {
        /// The conversation.
        conversation: Vec<u8>,
        /// The six digits.
        code: String,
    },
    /// The user confirmed a ceremony, and the store holds the state.
    Verified {
        /// The conversation.
        conversation: Vec<u8>,
    },
    /// A ceremony did not start, or no complete ceremony was there to
    /// confirm. The store holds no new state.
    VerificationRefused {
        /// The conversation.
        conversation: Vec<u8>,
    },
    /// The contact added or removed a reaction in a conversation.
    Reacted {
        /// The conversation.
        conversation: Vec<u8>,
    },
    /// The contact changed the text of a message of a conversation.
    Edited {
        /// The conversation.
        conversation: Vec<u8>,
    },
    /// The contact deleted a message of a conversation, and a placeholder
    /// stands in its place.
    Deleted {
        /// The conversation.
        conversation: Vec<u8>,
    },
    /// A message arrived.
    Message {
        /// The conversation.
        conversation: Vec<u8>,
        /// The message.
        message: Arc<MsgHandle>,
    },
    /// The delivery state of a sent message changed. The state is 0 for
    /// queued, 1 for accepted, 2 for delivered, 3 for read, and 4 for
    /// failed.
    Delivery {
        /// The message.
        message: Arc<MsgHandle>,
        /// The state.
        state: u8,
    },
    /// The client locked.
    Locked,
    /// The local store does not verify.
    IntegrityFault,
}

/// A message, as an opaque handle.
#[derive(uniffi::Object)]
pub struct MsgHandle(MsgRef);

#[uniffi::export]
impl MsgHandle {
    /// The identity of the message for the platform: two handles of one
    /// message give one value. It is the surrogate of the row under the
    /// store key, and it is no `msg_id` and no `msg_ref` (`IMP-150`).
    pub fn key(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// A draft, as an opaque handle. The buffer behind it is zero bytes after
/// the send and after the drop (`IMP-039`).
#[derive(uniffi::Object)]
pub struct DraftHandle(Mutex<Option<Draft>>);

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock holds a state that a panic left. The release profile
    // aborts at a panic, thus the state behind the lock is whole.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[uniffi::export]
impl DraftHandle {
    /// Replaces the text of the draft.
    pub fn set_text(&self, code_units: Vec<u16>) -> Result<(), FfiError> {
        let code_units = Zeroizing::new(code_units);
        locked(&self.0)
            .as_mut()
            .ok_or(FfiError::NotFound)?
            .set_text(&code_units)
            .map_err(FfiError::from)
    }

    /// Makes the draft an answer to a message of its conversation, or takes
    /// that away.
    pub fn set_reply_to(&self, message: Option<Arc<MsgHandle>>) -> Result<(), FfiError> {
        locked(&self.0)
            .as_mut()
            .ok_or(FfiError::NotFound)?
            .set_reply_to(message.map(|handle| handle.0));
        Ok(())
    }

    /// Gives the draft its file. The core reads the bytes at `path`, which
    /// on Android is the path of an open descriptor of this process, thus
    /// the bytes of the file cross no surface. The four values are the media
    /// fields of the descriptor of Part 13 §13.3, after the re-encode of
    /// `ATT-155`.
    pub fn attach_file(
        &self,
        path: String,
        mime_class: u8,
        pixel_w: u16,
        pixel_h: u16,
        media_seconds: u16,
    ) -> Result<(), FfiError> {
        let plain = Zeroizing::new(std::fs::read(&path).map_err(|_| FfiError::NotFound)?);
        let shape = Shape {
            mime_class,
            media_seconds,
            pixel_w,
            pixel_h,
        };
        Ok(locked(&self.0)
            .as_mut()
            .ok_or(FfiError::NotFound)?
            .attach(plain, shape)?)
    }
}

struct Inner {
    /// The invitation host of the run, for the text of a link.
    invitation_host: String,
    client: Client<SqliteBackend, ForeignElement>,
    /// The bridge of one run of the network, or none when no run is active.
    bridge: Option<Bridge>,
    net_events: VecDeque<NetEvent>,
    /// The ingress relay that the run dials, for the confirmation of its pin.
    guard: Option<[u8; 32]>,
    /// Whether the next run dials the second pinned ingress relay. A dial
    /// that failed turns it, thus the loss of one relay stops no delivery.
    uses_second_pin: bool,
    /// The relays of the run, for the view of the connection.
    relays: Vec<RelayEndpoint>,
    /// The circuits of the run that hold their three hops.
    circuits: Vec<[[u8; 32]; 3]>,
    /// Whether an event tells the platform that the circuits changed.
    circuits_changed: bool,
    /// This handle, for the task that brings the results of the transfers.
    me: Weak<Handle>,
    /// The runtime of the run, which also runs the transfer task.
    spawner: Option<tokio::runtime::Handle>,
    /// The authority of a test network, for the link of the transfer task.
    root_ca_path: Option<String>,
    /// The commands of the transfer task, or none before the first
    /// transfer of a run.
    transfers: Option<mpsc::UnboundedSender<TransferCommand>>,
    /// The message of each transfer that runs, and whether it is an upload.
    transfer_tags: BTreeMap<u64, (crate::MsgRef, bool)>,
    next_transfer_tag: u64,
}

impl Inner {
    /// Gives each file job of the store to the transfer task (Part 13
    /// §13.8). With no run of the network the jobs wait in the store.
    fn pump_transfers(&mut self) {
        if self.bridge.is_none() {
            return;
        }
        let mut commands = Vec::new();
        while let Some(job) = self.client.take_upload() {
            let tag = self.next_tag(job.message, true);
            commands.push(TransferCommand::Upload {
                tag,
                plain: job.plain,
                shape: job.shape,
            });
        }
        while let Some(job) = self.client.take_download() {
            let tag = self.next_tag(job.message, false);
            commands.push(TransferCommand::Download {
                tag,
                descriptor: job.descriptor,
            });
        }
        while let Some(job) = self.client.take_erasure() {
            commands.push(TransferCommand::Erase {
                chunk_id: job.chunk_id,
                cred: job.cred,
                relays: job.relays,
            });
        }
        for command in commands {
            self.send_transfer(command);
        }
    }

    fn next_tag(&mut self, message: crate::MsgRef, is_upload: bool) -> u64 {
        self.next_transfer_tag = self.next_transfer_tag.wrapping_add(1);
        self.transfer_tags
            .insert(self.next_transfer_tag, (message, is_upload));
        self.next_transfer_tag
    }

    /// Sends one command to the transfer task. The task ends after a time
    /// with no transfer, thus a command can find none, and a new one starts.
    fn send_transfer(&mut self, command: TransferCommand) {
        let command = match &self.transfers {
            Some(sender) => match sender.send(command) {
                Ok(()) => return,
                Err(refused) => refused.0,
            },
            None => command,
        };
        self.transfers = self.start_transfers();
        let refused = match &self.transfers {
            Some(sender) => sender.send(command).err().map(|refused| refused.0),
            None => Some(command),
        };
        // No task runs: the transfer fails, and the user can ask again.
        if let Some(TransferCommand::Upload { tag, .. } | TransferCommand::Download { tag, .. }) =
            refused
        {
            self.end_transfer(TransferUpdate::Failed { tag });
        }
    }

    fn start_transfers(&mut self) -> Option<mpsc::UnboundedSender<TransferCommand>> {
        let spawner = self.spawner.clone()?;
        let guard_id = self.guard?;
        let guard = self
            .relays
            .iter()
            .find(|relay| relay.relay_id.as_slice() == guard_id.as_slice())?;
        let dial = Dial {
            host: guard.host.clone(),
            addr_v4: Some(guard.ipv4.as_slice().try_into().ok()?),
            addr_v6: None,
            port: guard.port,
        };
        let ingress = relay_info(guard).ok()?;
        let mut candidates = Vec::new();
        let mut holders = Vec::new();
        for relay in self.relays.iter().filter(|relay| relay.layer != 1) {
            let info = relay_info(relay).ok()?;
            if relay.holds_files {
                holders.push(AttachmentRelay {
                    relay_id: info.candidate.relay_id,
                    operator_id: info.candidate.operator_id,
                    family_id: info.candidate.family_id,
                });
            }
            candidates.push(info);
        }
        let tls = match &self.root_ca_path {
            Some(path) => native::tls_config_with_root_file(path),
            None => native::tls_config(),
        }
        .ok()?;
        let node =
            ClientNode::for_transfers(ingress, candidates, self.client.root_identity().ok()?);
        let (commands, task_commands) = mpsc::unbounded_channel();
        let (task_updates, mut updates) = mpsc::unbounded_channel();
        spawner.spawn(run_transfers(
            node,
            dial,
            tls,
            holders,
            task_commands,
            task_updates,
        ));
        let me = self.me.clone();
        spawner.spawn(async move {
            while let Some(update) = updates.recv().await {
                let Some(handle) = me.upgrade() else {
                    break;
                };
                handle.on_transfer_update(update);
            }
        });
        Some(commands)
    }

    /// Takes the end of one transfer into the store. A message that a
    /// deletion took since has no row, and its result goes nowhere.
    fn end_transfer(&mut self, update: TransferUpdate) {
        let Inner {
            client,
            bridge,
            transfer_tags,
            ..
        } = self;
        match update {
            TransferUpdate::Progress { .. } => {}
            TransferUpdate::Uploaded { tag, uploaded } => {
                if let Some((message, _)) = transfer_tags.remove(&tag) {
                    if client.upload_done(&message, &uploaded, &mut OsRng).is_ok() {
                        // The record with the descriptor goes to the send path.
                        if let Some(running) = bridge {
                            let _ = running.flush(client, &mut OsRng);
                        }
                    }
                }
            }
            TransferUpdate::Downloaded { tag, plain } => {
                if let Some((message, _)) = transfer_tags.remove(&tag) {
                    let _ = client.download_done(&message, &plain, &mut OsRng);
                }
            }
            TransferUpdate::Failed { tag } => match transfer_tags.remove(&tag) {
                Some((message, true)) => {
                    let _ = client.upload_failed(&message, &mut OsRng);
                }
                Some((message, false)) => {
                    let _ = client.download_failed(&message, &mut OsRng);
                }
                None => {}
            },
        }
    }

    fn has_event(&self) -> bool {
        self.client.has_event() || !self.net_events.is_empty() || self.circuits_changed
    }

    fn next_event(&mut self) -> Option<FfiEvent> {
        if let Some(event) = self.client.next_event() {
            return Some(match event {
                Event::Message {
                    conversation,
                    message,
                } => FfiEvent::Message {
                    conversation: conversation.0.to_vec(),
                    message: Arc::new(MsgHandle(message)),
                },
                Event::Delivery { message, delivery } => FfiEvent::Delivery {
                    message: Arc::new(MsgHandle(message)),
                    state: delivery as u8,
                },
                Event::Reacted { conversation, .. } => FfiEvent::Reacted {
                    conversation: conversation.0.to_vec(),
                },
                Event::Edited { conversation, .. } => FfiEvent::Edited {
                    conversation: conversation.0.to_vec(),
                },
                Event::Deleted { conversation, .. } => FfiEvent::Deleted {
                    conversation: conversation.0.to_vec(),
                },
                Event::File { message } => FfiEvent::File {
                    // A message that a deletion took since has no
                    // conversation, and the view of none changes.
                    conversation: self
                        .client
                        .conversation_of_message(&message)
                        .map_or(Vec::new(), |conversation| conversation.0.to_vec()),
                    message: Arc::new(MsgHandle(message)),
                },
                Event::Locked => FfiEvent::Locked,
                Event::IntegrityFault => FfiEvent::IntegrityFault,
            });
        }
        if core::mem::take(&mut self.circuits_changed) {
            return Some(FfiEvent::Circuits);
        }
        Some(match self.net_events.pop_front()? {
            NetEvent::Online => FfiEvent::Online,
            NetEvent::Offline(ended) => FfiEvent::Offline { cause: ended as u8 },
            NetEvent::Invitation(shared) => {
                // The app makes each invitation with a link. A stored
                // bundle of another path has no link, and it gives no event.
                let bytes: Result<&[u8; FRAGMENT_LEN], _> = shared.as_slice().try_into();
                let Some(fragment) = bytes.ok().and_then(|b| Fragment::from_bytes(b).ok()) else {
                    return self.next_event();
                };
                FfiEvent::Invitation {
                    link: fragment.link(&self.invitation_host),
                }
            }
            NetEvent::InvitationGone => FfiEvent::InvitationGone,
            NetEvent::VerificationCode(conversation, code) => FfiEvent::VerificationCode {
                conversation: conversation.0.to_vec(),
                code: umbra_core::identity::verify::digits(code),
            },
            NetEvent::Verified(conversation) => FfiEvent::Verified {
                conversation: conversation.0.to_vec(),
            },
            NetEvent::VerificationRefused(conversation) => FfiEvent::VerificationRefused {
                conversation: conversation.0.to_vec(),
            },
            NetEvent::Contact(conversation) => FfiEvent::Contact {
                conversation: conversation.0.to_vec(),
            },
            NetEvent::Refused => FfiEvent::Refused,
        })
    }

    /// The ratchet keys of the runtime leave RAM with `K_store`, thus a
    /// locked client runs no network.
    fn stop_network_if_locked(&mut self) {
        if !self.client.is_unlocked() {
            self.bridge = None;
        }
    }
}

/// The client of the device.
#[derive(uniffi::Object)]
pub struct Handle {
    /// The file of the store, for the write of a new wrap header.
    database_path: String,
    inner: Mutex<Inner>,
    /// Signals each change of the event stream to [`Handle::wait_event`].
    changed: Condvar,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

struct NoElement;

impl SecureElement for NoElement {
    fn keyed(&self, _input: &[u8]) -> Result<[u8; 32], umbra_core::Error> {
        Ok([0; 32])
    }
}

/// Runs one Argon2id try at the floor cost, and returns its time in
/// milliseconds. The platform gives the result to [`init`] at the first
/// launch, off the main thread.
#[uniffi::export]
pub fn measure_argon2_floor_ms() -> u64 {
    let floor = Cost {
        m_kib: M_KIB_FLOOR,
        t: T_FLOOR,
    };
    let start = std::time::Instant::now();
    // The key and the passphrase are fixed values, and the result drops.
    let _ = WrapHeader::wrap(
        &umbra_crypto::secret::Secret::new([0; 32]),
        b"calibration",
        floor,
        [0; 16],
        [0; 24],
        &NoElement,
    );
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl Drop for Handle {
    fn drop(&mut self) {
        // The last reference can drop on a worker of the runtime, and a
        // runtime that drops there panics. This form of the stop is safe on
        // each thread.
        if let Some(runtime) = locked(&self.runtime).take() {
            runtime.shutdown_background();
        }
    }
}

/// Opens the client. The first launch makes the store under `passphrase`,
/// and the client is unlocked. A later launch returns a locked client, and
/// the passphrase is not read.
#[uniffi::export]
pub fn init(
    config: Config,
    element: Arc<dyn SecureElementCallback>,
    passphrase: Vec<u16>,
) -> Result<Arc<Handle>, FfiError> {
    let passphrase = Zeroizing::new(passphrase);
    let backend = SqliteBackend::open(&config.database_path).map_err(|_| FfiError::Storage)?;
    let element = ForeignElement(element);
    let now = unix_now();
    let client = match backend.header().map_err(|_| FfiError::Storage)? {
        Some(header) => Client::open(backend, element, header, now),
        None => {
            let cost = Cost::calibrate(config.argon2_floor_ms);
            // The header goes into the same file as the records, thus the
            // connection opens a second time for the write of the header.
            let headers =
                SqliteBackend::open(&config.database_path).map_err(|_| FfiError::Storage)?;
            let client = Client::create(backend, element, &passphrase, cost, now, &mut OsRng)?;
            headers
                .set_header(client.header())
                .map_err(|_| FfiError::Storage)?;
            client
        }
    };
    Ok(Arc::new(Handle {
        database_path: config.database_path,
        inner: Mutex::new(Inner {
            invitation_host: String::new(),
            client,
            bridge: None,
            net_events: VecDeque::new(),
            guard: None,
            uses_second_pin: false,
            relays: Vec::new(),
            circuits: Vec::new(),
            circuits_changed: false,
            me: Weak::new(),
            spawner: None,
            root_ca_path: None,
            transfers: None,
            transfer_tags: BTreeMap::new(),
            next_transfer_tag: 0,
        }),
        changed: Condvar::new(),
        runtime: Mutex::new(None),
    }))
}

fn conversation_of(bytes: &[u8]) -> Result<ConversationId, FfiError> {
    Ok(ConversationId(
        bytes.try_into().map_err(|_| FfiError::Malformed)?,
    ))
}

/// The store of the client, as the runtime of one run sees it. It holds a
/// weak reference, thus a handle that the platform drops ends the run.
struct HandleStore {
    handle: Weak<Handle>,
    /// The batch of receipts that the last slot got.
    given: Option<crate::DueReceipt>,
}

impl Persist for HandleStore {
    fn commit(&mut self, changes: Vec<StateChange>, received: &[(ContactId, Vec<u8>)]) -> bool {
        let Some(handle) = self.handle.upgrade() else {
            return false;
        };
        let mut inner = locked(&handle.inner);
        // A locked client takes no batch, and the run ends (`IMP-127`).
        let committed = inner
            .client
            .commit_network(&changes, received, unix_now_ms(), &mut OsRng)
            .is_ok();
        drop(inner);
        handle.changed.notify_all();
        committed
    }

    fn due_receipt(&mut self, now: u64) -> Option<(ContactId, Vec<u8>)> {
        let handle = self.handle.upgrade()?;
        let mut inner = locked(&handle.inner);
        // A locked client gives none, and its receipts wait in the store.
        let due = inner.client.due_receipt(now, &mut OsRng).ok()??;
        let contact = inner.bridge.as_ref()?.contact_for(&due.conversation)?;
        let app = due.app.clone();
        self.given = Some(due);
        Some((contact, app))
    }

    fn receipt_sent(&mut self) {
        let (Some(handle), Some(given)) = (self.handle.upgrade(), self.given.take()) else {
            return;
        };
        let _ = locked(&handle.inner).client.receipt_sent(&given);
    }
}

impl Handle {
    /// A task of the runtime gives one update of the network to the client.
    fn on_transfer_update(&self, update: TransferUpdate) {
        locked(&self.inner).end_transfer(update);
        self.changed.notify_all();
    }

    fn on_update(&self, update: Update) {
        let mut inner = locked(&self.inner);
        let Inner {
            client,
            bridge,
            net_events,
            guard,
            uses_second_pin,
            circuits,
            circuits_changed,
            ..
        } = &mut *inner;
        let ended = matches!(update, Update::Offline(_));
        match &update {
            Update::Circuits(chains) => {
                circuits.clone_from(chains);
                *circuits_changed = true;
            }
            // A run that ended holds no circuit.
            Update::Offline(_) => {
                circuits.clear();
                *circuits_changed = true;
            }
            _ => {}
        }
        match (&update, *guard) {
            // The other pin takes the next run (`REL-155`).
            (Update::Offline(Ended::DialFailed), _) => *uses_second_pin = !*uses_second_pin,
            // A relay that served a session confirms its pin. A fault of the
            // store here costs the confirmation alone.
            (Update::Online, Some(relay_id)) => {
                if let Ok(mut pins) = client.ingress_pins() {
                    if pins.confirm(&relay_id) {
                        let _ = client.set_ingress_pins(&pins, &mut OsRng);
                    }
                }
            }
            _ => {}
        }
        if let Some(running) = bridge {
            // A fault of the store shows in the event stream of the client,
            // and such an update gives no event of the network.
            if let Ok(Some(event)) = running.on_update(client, update, unix_now_ms(), &mut OsRng) {
                net_events.push_back(event);
            }
        } else if let Update::Offline(cause) = update {
            net_events.push_back(NetEvent::Offline(cause));
        }
        if ended {
            *bridge = None;
            // The transfer task has a link of its own. It ends with the run,
            // and the store holds what it did not complete.
            inner.transfers = None;
        }
        // A record with a descriptor asks for its file.
        inner.pump_transfers();
        drop(inner);
        self.changed.notify_all();
    }
}

impl Handle {
    /// The file of a message, in the clear, for a caller in Rust.
    pub fn file_bytes(&self, message: &MsgHandle) -> Result<Zeroizing<Vec<u8>>, FfiError> {
        Ok(locked(&self.inner).client.file_bytes(&message.0)?)
    }
}

#[uniffi::export]
impl Handle {
    /// Verifies a relay manifest of Part 10 §10.5.5 under the key set that
    /// the build ships (`REL-039`), and gives its relays as a network.
    /// `shipped_epoch` is the epoch at the time of the build (`REL-045`). The
    /// store keeps the highest epoch that the device verified, thus an
    /// older manifest gives [`FfiError::Stale`] in each later run.
    pub fn network_of_manifest(
        &self,
        manifest: Vec<u8>,
        keyset: Vec<u8>,
        shipped_epoch: u64,
        invitation_host: String,
        root_ca_path: Option<String>,
    ) -> Result<VerifiedNetwork, FfiError> {
        let mut inner = locked(&self.inner);
        let floor = inner.client.directory_epoch()?.max(shipped_epoch);
        let (keyset, _) = DirectoryKeySet::parse(&keyset).map_err(|_| FfiError::Malformed)?;
        let mut consensus = Consensus::new(keyset, floor).map_err(|_| FfiError::Malformed)?;
        let manifest = RelayManifest::parse(&manifest).map_err(|_| FfiError::Malformed)?;
        let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), unix_now())
            .map_err(|cause| match cause {
                umbra_core::Error::Stale => FfiError::Stale,
                umbra_core::Error::Malformed => FfiError::Malformed,
                _ => FfiError::Unverified,
            })?;
        // The pins stay while the set lists them and their lifetime runs,
        // and an open place takes a random eligible relay (Part 10 §10.6.1).
        let now = consensus.client_clock(unix_now()).unwrap_or_else(unix_now);
        let mut eligible: Vec<(u64, Candidate)> = set
            .relays
            .iter()
            .filter(|relay| relay.candidate.ingress && relay.addr_v4 != [0; 4])
            .map(|relay| (random_u64(), relay.candidate))
            .collect();
        eligible.sort_by_key(|(draw, _)| *draw);
        let eligible: Vec<Candidate> = eligible.into_iter().map(|(_, relay)| relay).collect();
        let mut pins = inner.client.ingress_pins()?;
        if pins.refresh(&eligible, now) {
            inner.client.set_ingress_pins(&pins, &mut OsRng)?;
        }
        // The network holds the pinned ingress relays, the first pin first,
        // and no other relay of layer 1: the client dials no other one.
        let place = |relay: &RelayEndpoint| {
            pins.pins()
                .iter()
                .position(|pin| pin.relay_id.as_slice() == relay.relay_id.as_slice())
        };
        let mut relays = endpoints_of(&set);
        relays.retain(|relay| relay.layer != 1 || place(relay).is_some());
        relays.sort_by_key(|relay| place(relay).unwrap_or(usize::MAX));
        // A chain holds one relay of each layer.
        if (1..=3u8).any(|layer| !relays.iter().any(|relay| relay.layer == layer)) {
            return Err(FfiError::Malformed);
        }
        inner.client.set_directory_epoch(set.epoch, &mut OsRng)?;
        Ok(VerifiedNetwork {
            network: Network {
                relays,
                root_ca_path,
                invitation_host,
            },
            epoch: set.epoch,
            is_clock_corrected: consensus.clock_state() == ClockState::Corrected,
        })
    }

    /// The state of the connection: the circuits and their relays. A
    /// [`FfiEvent::Circuits`] says that it changed.
    pub fn connection(&self) -> Result<Connection, FfiError> {
        let inner = locked(&self.inner);
        let hop_of = |relay_id: &[u8; 32]| {
            inner
                .relays
                .iter()
                .find(|relay| relay.relay_id.as_slice() == relay_id.as_slice())
                .map(|relay| Hop {
                    host: relay.host.clone(),
                    country: relay.country.clone(),
                    layer: relay.layer,
                })
        };
        let mut in_use: Vec<[u8; 32]> = inner.circuits.iter().flatten().copied().collect();
        in_use.sort_unstable();
        in_use.dedup();
        let pins: Vec<&RelayEndpoint> = inner
            .relays
            .iter()
            .filter(|relay| relay.layer == 1)
            .take(INGRESS_PINS)
            .collect();
        let is_guard = |relay: &&&RelayEndpoint| {
            inner
                .guard
                .is_some_and(|guard| relay.relay_id.as_slice() == guard.as_slice())
        };
        let as_hop = |relay: &&RelayEndpoint| Hop {
            host: relay.host.clone(),
            country: relay.country.clone(),
            layer: relay.layer,
        };
        let is_running = inner.bridge.is_some();
        Ok(Connection {
            is_running,
            circuits: inner
                .circuits
                .iter()
                .map(|chain| chain.iter().filter_map(hop_of).collect())
                .collect(),
            relays_in_use: u32::try_from(in_use.len()).unwrap_or(u32::MAX),
            relays_known: u32::try_from(inner.relays.len()).unwrap_or(u32::MAX),
            ingress: pins
                .iter()
                .find(is_guard)
                .filter(|_| is_running)
                .map(as_hop),
            standby: pins.iter().find(|relay| !is_guard(relay)).map(as_hop),
            directory_epoch: inner.client.directory_epoch()?,
        })
    }

    /// Starts the network of an unlocked client. A [`FfiEvent::Online`]
    /// follows the build of the circuit. A second call ends the first run.
    pub fn connect(self: Arc<Self>, network: Network) -> Result<(), FfiError> {
        // The first two relays of layer 1 are the pinned ingress relays of
        // this client (Part 10 §10.6.1), and each relay of another layer is
        // a candidate of a chain. The run dials the first pin. After a dial
        // that failed it dials the second one.
        let pinned: Vec<&RelayEndpoint> = network
            .relays
            .iter()
            .filter(|relay| relay.layer == 1)
            .take(INGRESS_PINS)
            .collect();
        let uses_second = locked(&self.inner).uses_second_pin && pinned.len() > 1;
        let guard = *pinned
            .get(usize::from(uses_second))
            .ok_or(FfiError::Malformed)?;
        let ingress = relay_info(guard)?;
        let candidates = network
            .relays
            .iter()
            .filter(|relay| relay.layer != 1)
            .map(relay_info)
            .collect::<Result<Vec<_>, _>>()?;
        let address = guard.ipv4.as_slice().try_into();
        let dial = Dial {
            host: guard.host.clone(),
            addr_v4: Some(address.map_err(|_| FfiError::Malformed)?),
            addr_v6: None,
            port: guard.port,
        };
        let tls = match &network.root_ca_path {
            Some(path) => native::tls_config_with_root_file(path),
            None => native::tls_config(),
        }
        .map_err(|_| FfiError::Malformed)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| FfiError::Offline)?;

        let (commands, runtime_commands) = mpsc::unbounded_channel();
        let (runtime_updates, mut updates) = mpsc::unbounded_channel();
        {
            let mut inner = locked(&self.inner);
            inner.invitation_host.clone_from(&network.invitation_host);
            inner.guard = Some(ingress.key.relay_id);
            inner.relays.clone_from(&network.relays);
            inner.circuits.clear();
            inner.circuits_changed = true;
            inner.me = Arc::downgrade(&self);
            inner.spawner = Some(runtime.handle().clone());
            inner.root_ca_path.clone_from(&network.root_ca_path);
            inner.transfers = None;
            let Inner {
                client,
                bridge,
                net_events,
                ..
            } = &mut *inner;
            // The node continues each contact and each invitation of the
            // earlier runs.
            let mut node = ClientNode::with_relays(ingress, candidates, client.root_identity()?);
            let stored = client.stored_network()?;
            let mut contacts = BTreeMap::new();
            for (conversation, state) in &stored.contacts {
                let contact = node
                    .restore_contact(state)
                    .map_err(|_| FfiError::Integrity)?;
                contacts.insert(*conversation, contact);
            }
            for state in &stored.invitations {
                let bundle = node
                    .restore_invitation(state)
                    .map_err(|_| FfiError::Integrity)?;
                net_events.push_back(NetEvent::Invitation(bundle));
            }
            // Each record that no relay accepted in an earlier run goes
            // again. The runtime holds it until the circuit is ready.
            let mut running = Bridge::new(commands, contacts);
            client.requeue_waiting()?;
            // Each transfer that an earlier run left open starts again.
            client.requeue_transfers()?;
            running.flush(client, &mut OsRng)?;
            *bridge = Some(running);
            runtime.spawn(run_client(
                node,
                dial,
                tls,
                runtime_commands,
                runtime_updates,
                Box::new(HandleStore {
                    handle: Arc::downgrade(&self),
                    given: None,
                }),
            ));
        }
        // The task holds a weak reference, thus a handle that the platform
        // drops ends the runtime.
        let handle: Weak<Handle> = Arc::downgrade(&self);
        runtime.spawn(async move {
            while let Some(update) = updates.recv().await {
                let Some(handle) = handle.upgrade() else {
                    break;
                };
                handle.on_update(update);
            }
        });
        if let Some(earlier) = locked(&self.runtime).replace(runtime) {
            earlier.shutdown_background();
        }
        Ok(())
    }

    /// Ends the network. Each contact stays in the store, and the next
    /// [`Handle::connect`] continues it.
    pub fn disconnect(&self) {
        {
            let mut inner = locked(&self.inner);
            inner.bridge = None;
            inner.transfers = None;
            inner.spawner = None;
        }
        if let Some(runtime) = locked(&self.runtime).take() {
            runtime.shutdown_background();
        }
    }

    /// Asks for one invitation. A [`FfiEvent::Invitation`] follows.
    pub fn invite(&self) -> Result<(), FfiError> {
        let inner = locked(&self.inner);
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        Ok(bridge.invite()?)
    }

    /// Accepts the link of an inviter. The client makes the first fetch of
    /// the blob, which locks the invitation to this device. A
    /// [`FfiEvent::Contact`] follows, or a [`FfiEvent::InvitationGone`]. A
    /// link that names another host or that does not parse is an error.
    pub fn accept(&self, link: String) -> Result<(), FfiError> {
        let inner = locked(&self.inner);
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        let fragment = Fragment::parse(link.trim(), &inner.invitation_host)
            .map_err(|_| FfiError::Malformed)?;
        Ok(bridge.accept(fragment.to_bytes().to_vec())?)
    }

    /// The conversations of the device, one for each contact. The list
    /// needs no network.
    pub fn conversations(&self) -> Result<Vec<Vec<u8>>, FfiError> {
        let found = locked(&self.inner).client.conversations()?;
        Ok(found
            .into_iter()
            .map(|conversation| conversation.0.to_vec())
            .collect())
    }

    /// Which receipts this device sends to the contact of a conversation.
    /// The two are off for a new contact (`NET-059`).
    pub fn receipt_settings(&self, conversation: Vec<u8>) -> Result<Receipts, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let settings = locked(&self.inner).client.receipt_settings(conversation)?;
        Ok(Receipts {
            delivery: settings.delivery,
            read: settings.read,
        })
    }

    /// Sets the receipts of one contact.
    pub fn set_receipt_settings(
        &self,
        conversation: Vec<u8>,
        settings: Receipts,
    ) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let settings = crate::ReceiptSettings {
            delivery: settings.delivery,
            read: settings.read,
        };
        Ok(locked(&self.inner)
            .client
            .set_receipt_settings(conversation, settings, &mut OsRng)?)
    }

    /// Tells the client whether a view of the app is on the screen. A
    /// client in the background makes no cover cell (Part 3 §3.6.2). With
    /// no network the call does nothing.
    pub fn set_foreground(&self, is_foreground: bool) {
        if let Some(bridge) = locked(&self.inner).bridge.as_ref() {
            let _ = bridge.set_foreground(is_foreground);
        }
    }

    /// The 60-digit safety number of a conversation, in groups of five. It
    /// is a public value of the two devices and no secret.
    pub fn safety_number(&self, conversation: Vec<u8>) -> Result<String, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.safety_number(conversation)?)
    }

    /// Compares a safety number that the user scanned with the number of
    /// this device. A match records the verification.
    pub fn verify_by_number(&self, conversation: Vec<u8>, given: String) -> Result<bool, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        Ok(inner
            .client
            .verify_by_number(conversation, &given, unix_now_ms(), &mut OsRng)?)
    }

    /// Starts a verification ceremony. A [`FfiEvent::VerificationCode`]
    /// follows at the two devices.
    pub fn start_verification(&self, conversation: Vec<u8>) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let inner = locked(&self.inner);
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        Ok(bridge.verify(&conversation)?)
    }

    /// The user says that the two codes match. A [`FfiEvent::Verified`]
    /// follows.
    pub fn confirm_verification(&self, conversation: Vec<u8>) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let inner = locked(&self.inner);
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        Ok(bridge.confirm_verified(&conversation)?)
    }

    /// One summary for each contact, the newest conversation first.
    pub fn summaries(&self) -> Result<Vec<Summary>, FfiError> {
        let found = locked(&self.inner).client.summaries()?;
        Ok(found
            .into_iter()
            .map(|summary| Summary {
                conversation: summary.conversation.0.to_vec(),
                name: summary.name,
                last_message: summary.last.map(|last| Arc::new(MsgHandle(last))),
                last_at_ms: summary.last_at_ms,
                unread: summary.unread,
                verified: summary.verified,
            })
            .collect())
    }

    /// Gives a contact a name on this device. No peer and no relay learns
    /// it. An empty name takes the name away.
    pub fn set_contact_name(&self, conversation: Vec<u8>, name: String) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        Ok(inner
            .client
            .set_contact_name(conversation, &name, &mut OsRng)?)
    }

    /// The user saw each message of the conversation that the store holds.
    pub fn mark_read(&self, conversation: Vec<u8>) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        Ok(inner
            .client
            .mark_read(conversation, unix_now_ms(), &mut OsRng)?)
    }

    /// An empty draft for one conversation.
    pub fn new_draft(&self, conversation: Vec<u8>) -> Result<Arc<DraftHandle>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let draft = locked(&self.inner).client.new_draft(conversation);
        Ok(Arc::new(DraftHandle(Mutex::new(Some(draft)))))
    }

    /// Sends a draft. The handle of the draft is empty after this call.
    pub fn send_draft(&self, draft: Arc<DraftHandle>) -> Result<Arc<MsgHandle>, FfiError> {
        let draft = locked(&draft.0).take().ok_or(FfiError::NotFound)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        let message = client.send_draft(draft, unix_now_ms(), &mut OsRng)?;
        // With no network the record waits in the store.
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        // A file goes to the relays first, and its record follows.
        inner.pump_transfers();
        drop(inner);
        self.changed.notify_all();
        Ok(Arc::new(MsgHandle(message)))
    }

    /// Cancels a send that the send path did not take yet.
    pub fn cancel_send(&self, message: Arc<MsgHandle>) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.cancel_send(&message.0)?)
    }

    /// The next event, or none.
    pub fn next_event(&self) -> Option<FfiEvent> {
        locked(&self.inner).next_event()
    }

    /// The next event, and the call waits for it up to `timeout_ms`. One
    /// thread of the platform drains the stream with this call.
    pub fn wait_event(&self, timeout_ms: u32) -> Option<FfiEvent> {
        let timeout = Duration::from_millis(u64::from(timeout_ms));
        let (mut inner, _) = self
            .changed
            .wait_timeout_while(locked(&self.inner), timeout, |inner| !inner.has_event())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.next_event()
    }

    /// Renders the text of a message into a sink of the platform.
    pub fn msg_render(
        &self,
        message: Arc<MsgHandle>,
        sink: Arc<dyn TextSink>,
    ) -> Result<(), FfiError> {
        let mut sink = ForeignSink(sink);
        Ok(locked(&self.inner).client.render(&message.0, &mut sink)?)
    }

    /// Gives the file of a message to a decoder of the platform
    /// (`IMP-166`). The store must hold the file: a file in another state is
    /// `NotFound`. The copy of the core is zero bytes after the call.
    pub fn msg_file(
        &self,
        message: Arc<MsgHandle>,
        sink: Arc<dyn FileSink>,
    ) -> Result<(), FfiError> {
        let bytes = locked(&self.inner).client.file_bytes(&message.0)?;
        // The sink runs with no lock held: a decode takes time.
        sink.put(bytes.to_vec());
        Ok(())
    }

    /// The direction, the delivery state, and the send time of a message.
    pub fn msg_info(&self, message: Arc<MsgHandle>) -> Result<MsgInfo, FfiError> {
        let info = locked(&self.inner).client.info(&message.0)?;
        Ok(MsgInfo {
            outgoing: info.outgoing,
            delivery: info.delivery as u8,
            sent_at_ms: info.sent_at_ms,
            stored_at_ms: info.stored_at_ms,
            deleted: info.deleted,
            edited: info.revisions > 0,
            editable: info.outgoing
                && !info.deleted
                && info.has_text
                && info.revisions < crate::client::EDIT_MAX
                && unix_now_ms().saturating_sub(info.stored_at_ms) < crate::client::EDIT_WINDOW_MS,
            is_reply: info.reply != crate::ReplyTarget::None,
            reply_to: match info.reply {
                crate::ReplyTarget::Message(target) => Some(Arc::new(MsgHandle(target))),
                _ => None,
            },
            file: info.file.map(|file| MsgFile {
                state: file.state as u8,
                mime_class: file.shape.mime_class,
                pixel_w: file.shape.pixel_w,
                pixel_h: file.shape.pixel_h,
                media_seconds: file.shape.media_seconds,
            }),
        })
    }

    /// Asks again for the file of a received message whose download failed.
    /// A [`FfiEvent::File`] follows its end.
    pub fn fetch_file(&self, message: Arc<MsgHandle>) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner.client.fetch_file(&message.0, &mut OsRng)?;
        inner.pump_transfers();
        Ok(())
    }

    /// The reactions to a message, those of this device first.
    pub fn reactions(&self, message: Arc<MsgHandle>) -> Result<Vec<MsgReaction>, FfiError> {
        let found = locked(&self.inner).client.reactions(&message.0)?;
        Ok(found
            .into_iter()
            .map(|reaction| MsgReaction {
                emoji: reaction.emoji,
                mine: reaction.mine,
            })
            .collect())
    }

    /// Adds the reaction of this device to a message, or removes it when
    /// the device holds it already. A value that is no emoji is `Malformed`.
    pub fn react(&self, message: Arc<MsgHandle>, emoji: String) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.react(&message.0, &emoji, unix_now_ms(), &mut OsRng)?;
        // With no network the reaction waits in the store.
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        Ok(())
    }

    /// Changes the text of a message that this device sent, to the text of
    /// a draft. The handle of the draft is empty after this call.
    pub fn edit_message(
        &self,
        message: Arc<MsgHandle>,
        draft: Arc<DraftHandle>,
    ) -> Result<(), FfiError> {
        let draft = locked(&draft.0).take().ok_or(FfiError::NotFound)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.edit(&message.0, draft, unix_now_ms(), &mut OsRng)?;
        // With no network the edit waits in the store.
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        Ok(())
    }

    /// Removes a message, or the placeholder of a deleted one, from this
    /// device. No record leaves the device.
    pub fn delete_for_me(&self, message: Arc<MsgHandle>) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner.client.delete_for_me(&message.0)?;
        // ATT-161: the chunks of a file that this device uploaded go too.
        inner.pump_transfers();
        Ok(())
    }

    /// Asks the contact to delete a message that this device sent, and
    /// puts a placeholder in its place here. One such request leaves in
    /// each 10 seconds for one conversation, and a request before that
    /// time is `Busy`.
    pub fn delete_for_everyone(&self, message: Arc<MsgHandle>) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.delete_for_everyone(&message.0, unix_now_ms(), &mut OsRng)?;
        // With no network the request waits in the store.
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        inner.pump_transfers();
        Ok(())
    }

    /// The messages of one conversation, as handles, in the order in which
    /// this device stored them.
    pub fn messages(&self, conversation: Vec<u8>) -> Result<Vec<Arc<MsgHandle>>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let found = locked(&self.inner).client.messages(conversation)?;
        Ok(found
            .into_iter()
            .map(|message| Arc::new(MsgHandle(message)))
            .collect())
    }

    /// Locks the client, and ends the network with it.
    pub fn lock(&self) {
        let mut inner = locked(&self.inner);
        inner.client.lock();
        inner.stop_network_if_locked();
        drop(inner);
        self.changed.notify_all();
    }

    /// Unlocks the client with the passphrase.
    pub fn unlock(&self, passphrase: Vec<u16>) -> Result<(), FfiError> {
        let passphrase = Zeroizing::new(passphrase);
        let mut inner = locked(&self.inner);
        Ok(inner.client.unlock(&passphrase, unix_now())?)
    }

    /// The idle time of the auto-lock, in seconds. Zero means that the
    /// platform locks when the app leaves the screen.
    pub fn auto_lock_seconds(&self) -> Result<u64, FfiError> {
        Ok(locked(&self.inner).client.auto_lock_seconds()?)
    }

    /// Sets the idle time of the auto-lock: zero, or up to 1 800 seconds
    /// (`IMP-119`).
    pub fn set_auto_lock(&self, seconds: u64) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        Ok(inner.client.set_auto_lock(seconds, &mut OsRng)?)
    }

    /// Changes the passphrase of the device (`IMP-118`). The store key and
    /// each record stay. A wrong current passphrase changes nothing.
    pub fn change_passphrase(&self, current: Vec<u16>, new: Vec<u16>) -> Result<(), FfiError> {
        let current = Zeroizing::new(current);
        let new = Zeroizing::new(new);
        let mut inner = locked(&self.inner);
        let header = inner.client.rewrap(&current, &new, &mut OsRng)?;
        // The file takes the header first. A client that held a header
        // which the file does not hold would lock the user out at the next
        // launch.
        let file = SqliteBackend::open(&self.database_path).map_err(|_| FfiError::Storage)?;
        file.set_header(&header).map_err(|_| FfiError::Storage)?;
        inner.client.set_header(header);
        Ok(())
    }

    /// The user acted. The idle time of the auto-lock starts again
    /// (`IMP-119`). The platform calls it for an action of the user only,
    /// and never for a record that arrived.
    pub fn touch(&self) {
        locked(&self.inner).client.touch(unix_now());
    }

    /// The clock of the platform, for the auto-lock.
    pub fn tick(&self) {
        let mut inner = locked(&self.inner);
        inner.client.tick(unix_now());
        inner.stop_network_if_locked();
        drop(inner);
        self.changed.notify_all();
    }
}

// The delivery states that `FfiEvent::Delivery` carries stay in step with
// the core enum.
const _: () = assert!(Delivery::Failed as u8 == 4);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn descriptor() -> String {
        let relay = |n: u8| {
            format!(
                "relay relay{n}.example.org 203.0.113.{n} 443 {} {}",
                "ab".repeat(32),
                format!("{n:02x}").repeat(32)
            )
        };
        format!(
            "umbra-network 1
# the guard first
{}
{}

{}  # the queue relay
invite invite.example.org
",
            relay(1),
            relay(2),
            relay(3)
        )
    }

    #[test]
    fn a_descriptor_gives_the_three_relays_and_the_invitation_host() {
        let network = parse_network(descriptor(), None).unwrap();
        assert_eq!(network.relays.len(), 3);
        assert_eq!(network.relays[0].host, "relay1.example.org");
        assert_eq!(network.relays[0].ipv4, [203, 0, 113, 1]);
        assert_eq!(network.relays[2].port, 443);
        assert_eq!(network.relays[2].relay_id, [3; 32]);
        assert_eq!(network.invitation_host, "invite.example.org");
        assert_eq!(network.root_ca_path, None);
    }

    #[test]
    fn a_descriptor_with_a_fault_is_refused() {
        let good = descriptor();
        let two_relays = good.replacen("relay relay2", "# relay relay2", 1);
        let short_key = good.replacen(&"ab".repeat(32), "abcd", 1);
        let no_invite = good.replace("invite invite.example.org", "");
        let no_header = good.replace("umbra-network 1", "umbra-network 2");
        let unknown = format!(
            "{good}
guard relay1.example.org"
        );
        for bad in [two_relays, short_key, no_invite, no_header, unknown] {
            assert_eq!(parse_network(bad, None).err(), Some(FfiError::Malformed));
        }
    }
}
