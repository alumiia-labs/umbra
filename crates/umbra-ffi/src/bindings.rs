//! The UniFFI scaffolding of Part 14 §14.6.1 over [`crate::client`] and the
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
    collections::{BTreeMap, BTreeSet, VecDeque},
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
    group::{
        queue::{select_pair, Candidate as GroupRelay},
        GROUP_REPLICAS,
    },
    identity::invitation::{Fragment, FRAGMENT_LEN},
    session::node::{ClientNode, ContactId, Payment, RelayInfo, StateChange},
    store::wrap::{Cost, SecureElement, WrapHeader, M_KIB_FLOOR, T_FLOOR},
};
use umbra_crypto::handshake::nk::RelayStatic;
use umbra_transport::{
    https::Url,
    native::{self, NativeError},
    ndr::{self, NdrRoute},
    Dial,
};
use umbra_wire::ndr::{NdrResponse, TokenCarrier};
use zeroize::Zeroizing;

mod block;
mod directory;
mod link;

pub use link::{init_linked, Device, LinkStatus, Linked};

use crate::{
    bridge::{Bridge, NetEvent},
    client::Client,
    draft::Draft,
    groups::{run_groups, GroupCommand, GroupUpdate},
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

/// The width of a `QueueAddress` in a report queue of [`Network`].
const REPORT_ADDRESS_LEN: usize = 129;

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
    /// A different party now holds the handle (Part 9 §9.9.2). A hello goes
    /// only after the user confirms it (`DIS-085`).
    Takeover,
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

/// The file of one message for a media player of the platform, which reads
/// it in ranges (`IMP-166`). The copy sits in the memory of the core, and
/// no byte of it goes to a file.
#[derive(uniffi::Object)]
pub struct MediaSource {
    handle: Weak<Handle>,
    bytes: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

#[uniffi::export]
impl MediaSource {
    /// The size of the file in bytes, or 0 after a close.
    pub fn size(&self) -> u64 {
        locked(&self.bytes)
            .as_ref()
            .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX))
    }

    /// At most `len` bytes from `offset`. A read after the end gives none,
    /// and a read after a lock closes the source and fails.
    pub fn read_at(&self, offset: u64, len: u32) -> Result<Vec<u8>, FfiError> {
        let is_open = self
            .handle
            .upgrade()
            .is_some_and(|handle| locked(&handle.inner).client.is_unlocked());
        if !is_open {
            self.release();
            return Err(FfiError::Locked);
        }
        let held = locked(&self.bytes);
        let bytes = held.as_ref().ok_or(FfiError::NotFound)?;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let end = start
            .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
            .min(bytes.len());
        Ok(bytes.get(start..end).map_or(Vec::new(), <[u8]>::to_vec))
    }

    /// Drops the copy of the file.
    pub fn release(&self) {
        locked(&self.bytes).take();
    }
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

/// One introduction that waits for the user (Part 6 §6.6.7).
#[derive(uniffi::Record)]
pub struct FfiIntroduction {
    /// The row, for the answer.
    pub id: Vec<u8>,
    /// An offer: the contact introduces the user to `name`. Else a
    /// request: the contact asks to introduce the user to `name`.
    pub is_offer: bool,
    /// The pairwise conversation of the contact.
    pub from: Vec<u8>,
    /// The petname of the third party, as that contact uses it.
    pub name: String,
}

/// One offer of a group, or one contact that asked to come into one.
#[derive(uniffi::Record)]
pub struct FfiGroupOffer {
    /// The pairwise conversation that carried it.
    pub from: Vec<u8>,
    /// The group.
    pub group_id: Vec<u8>,
    /// The name of the group, for an offer. A join request carries none.
    pub name: String,
    /// For a join request: whether the admin let the contact in already.
    pub is_added: bool,
    /// For a join request that the admin let in: whether its snapshot is
    /// on its way to the chunk path. A snapshot that did not arrive leaves
    /// the join added, and a second press sends it again.
    pub is_moving: bool,
}

/// What a view shows of a group of Part 11.
#[derive(uniffi::Record)]
pub struct FfiGroupInfo {
    /// The group, which the join flow names. No relay reads it
    /// (`GRP-151`).
    pub group_id: Vec<u8>,
    /// The index of this device in the roster.
    pub own_index: u16,
    /// The active members.
    pub members: u32,
    /// The group epoch.
    pub epoch: u32,
    /// Whether both replicas hold a group queue. Until then no record
    /// leaves this device (`GRP-191`).
    pub is_ready: bool,
    /// Whether each replica refused the group queue. The group is closed,
    /// and this device sends nothing more to it (`GRP-210`).
    pub is_closed: bool,
    /// Whether the roster still holds this device.
    pub is_member: bool,
    /// Whether this owner must name another owner before a silent owner
    /// can leave (`GRP-184`).
    pub owner_needed: bool,
    /// Whether this device lacks the current epoch and the relay refused
    /// its request, thus it needs a new invitation (`GRP-297`).
    pub is_lapsed: bool,
    /// Whether a rival re-key took the index of this member, and its
    /// request to an admin waits for the admit (`GRP-373`).
    pub is_returning: bool,
    /// Whether no replica of the group answers, thus each record waits
    /// (`GRP-199`, `GRP-200`).
    pub is_unreachable: bool,
    /// Whether a record waits for a clock check (`GRP-229`).
    pub is_clock_suspect: bool,
    /// Whether a rival re-key took the index of this member, and it knows
    /// no contact in the group to ask (`GRP-374`).
    pub needs_invitation: bool,
}

/// The push state of this device (Part 8 §8.2).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PushStatus {
    /// The carrier of the token, or empty for none: the device polls.
    pub carrier: String,
    /// The queues that bound for push at their relays.
    pub bound_queues: u32,
    /// The handle groups that the NDR holds.
    pub registered_groups: u32,
}

/// The link-fault counts of this device (Part 10 §10.4.2), for the view of
/// the connection.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LinkFaultStatus {
    /// The loops sent in the epochs that the counts hold.
    pub loops_sent: u32,
    /// The loops that came back.
    pub loops_back: u32,
    /// The loops that did not come back in time.
    pub loops_lost: u32,
    /// The forced replacements of this epoch.
    pub forced: u32,
    /// The reports that wait for a slot.
    pub reports_waiting: u32,
    /// The report queues of the manifest of the last run.
    pub report_queues: u32,
}

/// A digest of a contact that differs from the view of this device (Part 9
/// `DIS-034`, Part 10 `REL-161`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GossipWarningInfo {
    /// "directory" for the tree head of the handle directory, "relays" for
    /// the consensus root of the relay directory.
    pub source: String,
    /// The tree size or the consensus epoch that the two views differ at.
    pub epoch: u64,
}

/// The role of one member of a group (§11.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiRole {
    /// Reads and posts nothing.
    Observer,
    /// Reads and posts.
    Member,
    /// Acts in a moderation epoch of Part 11 §11.9.6.
    Moderator,
    /// Adds a member, removes one, and holds the owner credentials.
    Admin,
    /// An admin that also grants a role.
    Owner,
}

/// One member of a group, as the member list shows it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGroupMember {
    /// The member index, which the roster gives.
    pub index: u16,
    /// The role.
    pub role: FfiRole,
    /// Whether the index is this device.
    pub is_self: bool,
    /// The contact behind the member, where this device knows it. A
    /// member that another admin brought in has none.
    pub contact: Option<Vec<u8>>,
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
    /// Whether the relay holds chunks of files (Part 12). A network from a
    /// descriptor text has no such relay.
    pub holds_files: bool,
    /// The ML-DSA-65 identity key of the relay, which signs its proof-of-work
    /// challenge (Part 13 `ABU-068`). A network from a descriptor text
    /// names none.
    pub identity_pk: Vec<u8>,
    /// The hops that the relay serves, as its signed entry gives them. A
    /// pending entry serves none (Part 10 `REL-158`). A network from a
    /// descriptor text names none, and the layer gives the hops.
    pub roles: Option<HopRoles>,
    /// The 6 bytes of the IPv6 /48, when the entry names an address.
    pub prefix_v6: Option<Vec<u8>>,
}

/// The hops that one relay serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct HopRoles {
    /// The first hop.
    pub ingress: bool,
    /// A hop inside a chain.
    pub chain: bool,
    /// The last hop, which holds queues.
    pub queue: bool,
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
    /// The OHTTP relay of the Notification Delivery Relay, as an `https`
    /// URL, which the build pins (Part 8 `NTF-127`). With none the device
    /// registers no push.
    pub ndr_relay_url: Option<String>,
    /// The key configuration of the gateway of the NDR, which the build
    /// pins beside the URL.
    pub ndr_key_config: Option<Vec<u8>>,
    /// The IPv4 address to dial for the OHTTP relay, in the place of the
    /// host of its URL, as a relay entry names one.
    pub ndr_relay_ipv4: Option<Vec<u8>>,
    /// The `POST /directory` URL of an ingress relay, which carries the
    /// requests to the directory of Part 9 (`DIS-162`). With none the
    /// device has no handle and no Public Address.
    pub directory_relay_url: Option<String>,
    /// The pins of the directory that the build ships (`DIS-163`).
    pub directory_pins: Option<Vec<u8>>,
    /// The IPv4 address to dial for that relay, as above.
    pub directory_relay_ipv4: Option<Vec<u8>>,
    /// The report queue of each authority that the manifest carried and
    /// that verified: the `QueueAddress` and the X25519 key, 161 bytes each
    /// (Part 10 `REL-168`).
    pub report_queues: Vec<Vec<u8>>,
    /// The removed links of the manifest that verified: the epoch and the
    /// two `relay_id` values, 72 bytes each (Part 10 `REL-185`).
    pub removed_links: Vec<Vec<u8>>,
    /// Whether the key set of the directory stands below `AUTHORITY_FLOOR`,
    /// which permits the bootstrap relaxation of Part 3 `NET-340`.
    pub is_provisional: bool,
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
    /// Whether a relay asks for a proof of work above the floor: the
    /// `admission surge` state of Part 14 §14.9.2 (`ABU-008`).
    pub admission_surge: bool,
    /// For each circuit, whether two of its relays share an operator or a
    /// family under the bootstrap relaxation (Part 3 `NET-343`).
    pub one_operator: Vec<bool>,
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
    /// Whether fewer authorities than `AUTHORITY_FLOOR` stand under
    /// different control: the `provisional directory` state (`REL-126`).
    pub is_provisional: bool,
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
            identity_pk: relay.identity_pk.clone(),
            roles: Some(HopRoles {
                ingress: relay.candidate.ingress,
                chain: relay.candidate.chain,
                queue: relay.candidate.queue,
            }),
            prefix_v6: relay.candidate.v6_prefix.map(|prefix| prefix.to_vec()),
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
                    identity_pk: Vec::new(),
                    roles: None,
                    prefix_v6: None,
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
        // The build pins the route to the NDR, and no relay gives it.
        ndr_relay_url: None,
        ndr_key_config: None,
        ndr_relay_ipv4: None,
        directory_relay_url: None,
        directory_pins: None,
        directory_relay_ipv4: None,
        report_queues: Vec::new(),
        removed_links: Vec::new(),
        is_provisional: false,
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
    let v6_prefix = match &endpoint.prefix_v6 {
        Some(prefix) => {
            Some(<[u8; 6]>::try_from(prefix.as_slice()).map_err(|_| FfiError::Malformed)?)
        }
        None => None,
    };
    // REL-158: the hops of a signed entry stand; a descriptor text gives
    // them by its layer.
    let roles = endpoint.roles.unwrap_or(HopRoles {
        ingress: endpoint.layer == 1,
        chain: endpoint.layer != 1,
        queue: endpoint.layer == 3,
    });
    Ok(RelayInfo {
        candidate: Candidate {
            relay_id: key.relay_id,
            operator_id: operator,
            family_id: family,
            bloc: BlocList::v1().bloc_of(&country),
            asn: endpoint.asn,
            v4_prefix: Some(prefix.ok_or(FfiError::Malformed)?),
            v6_prefix,
            ingress: roles.ingress,
            chain: roles.chain,
            queue: roles.queue,
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
    /// The period that a timer record set, in seconds, for the row that
    /// marks a timer change (`DEV-207`).
    pub timer: Option<u32>,
    /// The time at which the timer erases the message, in seconds.
    pub expires_at: Option<u64>,
    /// Whether the message is a poll: see [`Handle::poll_view`].
    pub poll: bool,
    /// Whether a message of a group names this member (Part 11 §11.11).
    pub mentions_me: bool,
    /// Whether a message of a group opened under the secret of a key supply
    /// (`WIR-462`). The view shows it apart (`WIR-463`).
    pub recovered: bool,
    /// How many forwards lie behind the text, or zero for an original.
    pub forward_depth: u8,
    /// The root of the thread of a group record, or none. The view groups
    /// the records of one root (`WIR-273`).
    pub thread: Option<Arc<MsgHandle>>,
    /// The moderator action on the message: 0 none, 1 hidden, 2 removed.
    pub moderation: u8,
    /// The role of the member that acted, with the values of [`FfiRole`],
    /// or 0.
    pub moderator_role: u8,
    /// The member index that sent a message of a group that arrived.
    pub sender: Option<u16>,
    /// Why a failed message of this device failed (`IMP-074`): 0 unknown,
    /// 1 a relay refused it, 2 no path took it, 3 its file did not upload,
    /// 4 no replica of the group took it, 5 the queue of the contact was
    /// full.
    pub failure: u8,
}

/// A share of the social half that a holder took (Part 4 §4.7.3).
#[derive(uniffi::Record)]
pub struct FfiGivenShare {
    /// The holder.
    pub conversation: Vec<u8>,
    /// The index of the share.
    pub index: u8,
    /// The shares that a recovery needs.
    pub threshold: u8,
    /// The shares of the split.
    pub count: u8,
}

/// A share that a contact gave to this user.
#[derive(uniffi::Record)]
pub struct FfiHeldShare {
    /// The shares that a recovery of that contact needs.
    pub threshold: u8,
    /// The shares of that split.
    pub count: u8,
    /// The index of this share.
    pub index: u8,
    /// The time of its arrival, in milliseconds.
    pub at_ms: u64,
}

/// What a reset started.
#[derive(uniffi::Record)]
pub struct ResetCounts {
    /// The contacts that take a key-change notice.
    pub contacts: u32,
    /// The groups that take a re-key.
    pub groups: u32,
}

/// A key-change notice that waits for the answer of the user (Part 4
/// §4.5.1).
#[derive(uniffi::Record)]
pub struct FfiKeyChange {
    /// The safety number under the new key, for a comparison out of band
    /// before the answer (`IDN-090`).
    pub new_safety_number: String,
    /// The time of its arrival, in milliseconds.
    pub at_ms: u64,
}

/// One change of the roster of a group, as the conversation shows it.
#[derive(uniffi::Record)]
pub struct FfiRosterNote {
    /// The time of the application, in milliseconds.
    pub at_ms: u64,
    /// 1 joined, 2 left, 3 removed for silence, 4 a new role, 5 a fork.
    pub kind: u8,
    /// The member index, or 0xFFFF for a fork that names nobody.
    pub index: u16,
    /// The new role of kind 4, with the values of [`FfiRole`], else 0.
    pub role: u8,
}

/// One moderation epoch that this device applied (`GRP-089`).
#[derive(uniffi::Record)]
pub struct FfiModNote {
    /// The time of the application, in milliseconds.
    pub at_ms: u64,
    /// The role of the acting member.
    pub actor_role: u8,
    /// The messages that it hid.
    pub hidden: u16,
    /// The messages that it removed.
    pub removed: u16,
    /// The messages that it put back.
    pub shown: u16,
}

/// A poll with the count that this device holds. The count is the local
/// view, and no agreed count (`GRP-147`, `GRP-148`).
#[derive(uniffi::Record)]
pub struct FfiPoll {
    /// The question.
    pub question: String,
    /// The options, in their order.
    pub options: Vec<String>,
    /// Whether a vote takes more than one option.
    pub multiple: bool,
    /// Whether the count stays hidden until the close.
    pub hidden: bool,
    /// The close time in seconds, or 0 for no close.
    pub closes_at: u64,
    /// Whether the poll closed.
    pub closed: bool,
    /// The votes that this device holds for each option, or none while a
    /// hidden poll is open.
    pub counts: Vec<u32>,
    /// The voters that this device holds.
    pub voters: u32,
    /// The options of the vote of the user.
    pub mine: Vec<u8>,
}

/// The timer of a conversation (`DEV-206`).
#[derive(uniffi::Record)]
pub struct ConversationTimer {
    /// The period in seconds, or 0 for no timer.
    pub seconds: u32,
    /// The time of the change on this device, in milliseconds, or 0 when no
    /// party set one.
    pub set_at_ms: u64,
    /// Whether the user set it, on this device or another of the set.
    pub by_user: bool,
}

/// The file of a message, with no byte of it.
#[derive(uniffi::Record)]
pub struct MsgFile {
    /// 1 while this device uploads it, 2 while this device fetches it, 3
    /// when the store holds it, 4 after a transfer that failed, and 5 while
    /// it waits for a tap above the automatic download limit (`IMP-167`).
    pub state: u8,
    /// The media class of the descriptor.
    pub mime_class: u8,
    /// The width of an image or a video, else 0.
    pub pixel_w: u16,
    /// The height of an image or a video, else 0.
    pub pixel_h: u16,
    /// The duration of an audio or a video object, else 0.
    pub media_seconds: u16,
    /// The name that the sender gave the file, if any (`WIR-531`).
    pub name: Option<String>,
    /// The size in bytes: exact when the store holds the file, and the
    /// padded size of the descriptor before that.
    pub size: u64,
    /// The chunks that moved in a transfer that runs, else 0.
    pub done: u32,
    /// The chunks of a transfer that runs, else 0.
    pub total: u32,
    /// Whether the sender gave a preview, which [`Handle::msg_preview`]
    /// gives (`WIR-533`).
    pub has_preview: bool,
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
    /// A contact offered a group. [`Handle::group_offers`] gives it.
    GroupOffer,
    /// A contact asks to introduce the user, or introduces the user to a
    /// third party. [`Handle::introductions`] gives it.
    Introduction,
    /// A contact asked to come into a group of this device.
    /// [`Handle::group_joiners`] gives it.
    GroupJoiner,
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
    /// The sync channel of another device of the set opened (Part 7
    /// `DEV-286`).
    DeviceLinked,
    /// Another device of the set added a conversation or named one.
    Conversations,
    /// A contact request arrived on a link or a handle of this device.
    /// [`Handle::contact_requests`] gives it.
    ContactRequest,
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
    /// A contact started or stopped typing in a conversation.
    Typing {
        /// The conversation.
        conversation: Vec<u8>,
        /// Whether the contact types.
        is_typing: bool,
    },
    /// A vote moved the count of a poll of a conversation.
    Voted {
        /// The conversation.
        conversation: Vec<u8>,
    },
    /// The contact changed the text of a message of a conversation.
    Edited {
        /// The conversation.
        conversation: Vec<u8>,
    },
    /// An edit or a deletion of this device reached no relay (`DEV-114`).
    ChangeFailed {
        /// The conversation.
        conversation: Vec<u8>,
        /// Whether the change was a deletion.
        is_delete: bool,
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

    /// Names members of a group in the draft, by their roster index.
    pub fn set_mentions(&self, members: Vec<u16>) -> Result<(), FfiError> {
        locked(&self.0)
            .as_mut()
            .ok_or(FfiError::NotFound)?
            .set_mentions(members);
        Ok(())
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
    /// fields of the descriptor of Part 12 §12.3, after the re-encode of
    /// `ATT-155`.
    ///
    /// `name` is the name of a document or of another file, with no path.
    /// An image, a video, and a voice recording take none (`ATT-192`).
    /// `preview` is a JPEG thumbnail of an image or of the first frame of a
    /// video (`WIR-533`). It is a picture as the file is, thus it crosses
    /// as bytes under the exception of `IMP-166`.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_file(
        &self,
        path: String,
        mime_class: u8,
        pixel_w: u16,
        pixel_h: u16,
        media_seconds: u16,
        name: Option<String>,
        preview: Option<Vec<u8>>,
    ) -> Result<(), FfiError> {
        let plain = Zeroizing::new(std::fs::read(&path).map_err(|_| FfiError::NotFound)?);
        let shape = Shape {
            mime_class,
            media_seconds,
            pixel_w,
            pixel_h,
        };
        let mut draft = locked(&self.0);
        let draft = draft.as_mut().ok_or(FfiError::NotFound)?;
        draft.attach(plain, shape)?;
        if let Some(name) = name {
            draft.set_file_name(&name)?;
        }
        if let Some(preview) = preview {
            draft.set_file_preview(&preview)?;
        }
        Ok(())
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
    /// Whether the directory of the run is provisional (`NET-340`).
    bootstrap: bool,
    /// Whether the next run dials the second pinned ingress relay. A dial
    /// that failed turns it, thus the loss of one relay stops no delivery.
    uses_second_pin: bool,
    /// The loop count and the forced replacements of the last run, which
    /// the next run continues (Part 10 `REL-172`).
    faults: umbra_core::session::faults::LinkFaults,
    /// The reports of a transfer run or a group run, which the next run of
    /// the queues takes (`ATT-119`, `GRP-197`).
    pending_faults: umbra_core::session::faults::LinkFaults,
    /// The report queues of the manifest of the last run.
    report_queue_count: u32,
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
    /// What each transfer that runs belongs to.
    transfer_tags: BTreeMap<u64, TransferWork>,
    /// The relays that refused a chunk with `BUSY` or `LIMIT`, which no
    /// fetch of this handle asks for it again inside the hold (`ATT-174`).
    hold_offs: Arc<Mutex<umbra_core::attach::place::HoldOffs>>,
    /// The files whose transfer run ended before them, the time before
    /// which none goes again, and the count of the ends in a row: a guard
    /// that is down draws no dial at each update (`NET-320`).
    interrupted: (Vec<crate::MsgRef>, u64, u32),
    /// The chunks that moved and the chunks in all of each file transfer
    /// that runs.
    file_progress: BTreeMap<crate::MsgRef, (u32, u32)>,
    /// The files whose progress moved by a step that a view shows.
    progress_events: VecDeque<crate::MsgRef>,
    next_transfer_tag: u64,
    /// The commands of the group task, or none before the first group
    /// command of a run.
    groups: Option<mpsc::UnboundedSender<GroupCommand>>,
    /// What each group command that runs belongs to.
    group_tags: BTreeMap<u64, GroupWork>,
    /// A copy of each `GNEW` and `GPOST` that the group task holds, by its
    /// tag, until an answer. A session that ends before one gives the
    /// same bytes to the next session (`NET-072`).
    group_sent: BTreeMap<u64, GroupCommand>,
    next_group_tag: u64,
    /// The groups that the run of the group queues reads. A subscription
    /// lives with its session, thus this set empties when the run ends.
    group_reading: BTreeSet<crate::ConversationId>,
    /// The groups whose `GSUB` found no circuit in this session. Each goes
    /// to the other replica once at once, and after that at the next pump
    /// that another cause brings, thus two replicas that are down give no
    /// build at each timeout.
    group_lost: BTreeSet<crate::ConversationId>,
    /// The replicas that refused a record of a group. Two of them close
    /// the group (`GRP-210`).
    group_refusals: BTreeSet<(crate::ConversationId, [u8; 32])>,
    /// The pinned route to the NDR, with the TLS configuration of the run.
    ndr: Option<(NdrRoute, Arc<native::ClientConfig>)>,
    /// The pinned route to the directory.
    directory: Option<directory::DirectoryLink>,
    /// The sync channels whose opening the link took (`DEV-003`).
    links_opened: BTreeSet<crate::ConversationId>,
    /// The rendezvous queues that the runtime made, by the tag of their
    /// command, until a call takes each one.
    rendezvous_ready: BTreeMap<u64, ([u8; 32], Vec<u8>)>,
    /// The tags of the rendezvous queues that no relay made.
    rendezvous_refused: BTreeSet<u64>,
    next_rendezvous_tag: u64,
    /// The introductions that the user allowed, each of which takes the
    /// next fresh invitation of the run (`WIR-199`).
    pending_grants: VecDeque<[u8; 16]>,
    /// The handle groups whose NDR call runs.
    ndr_in_flight: BTreeSet<[u8; 16]>,
    /// The time before which a call of a handle that the NDR did not take
    /// goes no more, and the count of its failures in a row.
    ndr_retry: BTreeMap<[u8; 16], (u64, u32)>,
    /// The group of each notify queue that the run makes, by tag.
    notify_pending: BTreeMap<u64, crate::ConversationId>,
    next_notify_tag: u64,
    /// Whether a handle group rotated in this run (`NTF-081`).
    rotated_in_run: bool,
    /// The silent channels of the last check, and the time of the next
    /// one (`NET-186`).
    silent: Vec<crate::ConversationId>,
    next_silence_check: u64,
    /// The dead-channel work that an update of the node gave.
    dead_work: Vec<crate::client::DeadWork>,
    /// Whether a view of the app is on the screen. A backup is written in
    /// the foreground only (`IDN-080`).
    is_foreground: bool,
    /// The restore that runs, from its first root to its rows.
    restore: Option<RestoreJob>,
    /// The number of the run of the network, which each connect moves.
    run: u64,
    /// The newest challenge of each relay, from the carrier of the manifest
    /// (Part 13 `ABU-065`, `ABU-105`), and the time of the fetch.
    challenges: umbra_core::abuse::pow::ChallengeBook,
    challenges_at: u64,
    /// The link of a device that runs (Part 7 §7.4), and the number of the
    /// last one.
    link: Option<link::LinkState>,
    link_serial: u64,
    /// Whether this device owns the channels of the set. A linked device
    /// runs no contact, no group, and no backup (`DEV-287`).
    owns_channels: bool,
    /// The time of the next record of a sync resend.
    next_sync_resend: u64,
}

/// The time between two records of a sync resend, in seconds: the mean of
/// the foreground cover clock of Part 3 §3.6.2, which is the ordinary send
/// rate of a sync channel, thus a resend is no burst (`DEV-073`).
const SYNC_RESEND_GAP: u64 = 20;

/// A restore of Part 4 §4.7.2 while it runs: the root key of the entered
/// code, the week whose root it reads, and the objects that it holds.
struct RestoreJob {
    key: umbra_core::identity::recovery::BackupRootKey,
    first_week: u32,
    week: u32,
    objects: Vec<Option<Zeroizing<Vec<u8>>>>,
    status: RestoreStatus,
    restored: Option<crate::client::RestoredBackup>,
}

/// Where a restore stands (Part 4 §4.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RestoreStatus {
    /// No restore runs.
    Idle,
    /// The root of a week is asked, `weeks_back` weeks before the current
    /// one.
    Searching {
        /// The weeks before the current one.
        weeks_back: u32,
    },
    /// The objects of the root come down.
    Fetching {
        /// The objects here.
        done: u32,
        /// The objects of the root.
        total: u32,
    },
    /// The rows are here, and `take_restored` gives them.
    Ready {
        /// The contacts that the backup holds.
        contacts: u32,
    },
    /// No root opens in `BACKUP_LOOKBACK` weeks (`IDN-116`).
    NotFound,
    /// The backup holds no identity (`IDN-155`).
    NoIdentity,
    /// A transfer failed. The user can start again.
    Failed,
}

/// The rows of a restore, which [`init_restored`] writes into a new store.
/// The platform holds this object and never reads it.
#[derive(uniffi::Object)]
pub struct Restored(Mutex<Option<crate::client::RestoredBackup>>);

#[uniffi::export]
impl Restored {
    /// The count of the contacts that the backup holds.
    pub fn contact_count(&self) -> u32 {
        locked(&self.0).as_ref().map_or(0, |restored| {
            u32::try_from(restored.contact_count()).unwrap_or(u32::MAX)
        })
    }
}

/// One step of a restore that a transfer gave.
enum RestoreStep {
    Root {
        week: u32,
        chunks: Vec<Vec<u8>>,
        answered: bool,
    },
    Object {
        index: usize,
        plain: Zeroizing<Vec<u8>>,
    },
    Failed,
}

/// What one command of the transfer task belongs to.
enum TransferWork {
    /// The catch-up object of a peer that lags, by its sync channel
    /// (`DEV-237`).
    CatchUpOut(crate::ConversationId),
    /// The catch-up object that a peer sent, by its sync channel
    /// (`DEV-239`).
    CatchUpIn(crate::ConversationId),
    /// The snapshot that this admin writes for a member behind the roster
    /// of a group, at its roster epoch (`GRP-330`).
    RecoverySnapshot {
        /// The group.
        conversation: crate::ConversationId,
        /// The roster epoch of the snapshot.
        roster_epoch: u32,
        /// The roster epoch of the member that asked.
        behind: u32,
    },
    /// The snapshot that this member fetches after a restore (`GRP-329`).
    RecoveryFetch(crate::ConversationId),
    /// The state of a group that goes to the other devices of the set
    /// (`DEV-298`).
    GroupState(crate::ConversationId),
    /// The state of a group that another device of the set published, by
    /// the subject of the group.
    GroupFetch([u8; 32]),
    /// One step of the link of a device, by the number of its link.
    Link {
        /// The link.
        serial: u64,
        /// The step.
        step: link::LinkStep,
        /// The `chunk_id` and the `cred_sk` of a slot that the step
        /// writes, which a write that ends after its link erases.
        erase: Option<([u8; 32], umbra_crypto::secret::Secret<32>)>,
    },
    /// The backup root of one week, which a restore reads (`IDN-101`).
    RestoreRoot {
        /// The week.
        week: u32,
    },
    /// One object that a restored root names, by its entry.
    RestoreObject(usize),
    /// A backup object of Part 4 §4.7.2, and what its upload commits.
    Backup(Box<crate::client::PendingBackup>),
    /// The backup root of the week, and the chunks that go after it
    /// (`IDN-099`).
    BackupRoot(Vec<umbra_core::attach::transfer::ChunkCredential>),
    /// The dead-channel blob of this device for one week (`NET-183`).
    DeadWrite {
        /// The conversation.
        conversation: crate::ConversationId,
        /// The week.
        week: u32,
        /// `cred_sk` of the blob, for its later `CDEL`.
        cred: umbra_crypto::secret::Secret<32>,
    },
    /// The dead-channel blob of the peer for one week (`NET-186`).
    DeadRead {
        /// The conversation.
        conversation: crate::ConversationId,
        /// The key that opens it.
        blob_key: umbra_crypto::secret::Secret<32>,
    },
    /// The file of a message, and whether it goes up.
    File {
        /// The message.
        message: crate::MsgRef,
        /// Whether the transfer is an upload.
        is_upload: bool,
    },
    /// The roster snapshot of a join, which an admin puts on the chunk
    /// path before it sends the admit (§11.9.1 step 3).
    Snapshot {
        /// The pairwise conversation of the joiner.
        from: crate::ConversationId,
        /// The group.
        group_id: [u8; 32],
        /// The member index that the admin gave the joiner.
        index: u16,
    },
    /// The roster snapshot that an admit named, which the joiner fetches
    /// before it holds the group (§11.9.1 step 5).
    Admit {
        /// The pairwise conversation that carried the admit.
        from: crate::ConversationId,
        /// The group.
        group_id: [u8; 32],
    },
    /// The slot object of a rotation above the inline carrier, whose
    /// record follows the upload (`GRP-283`).
    EpochSlots(Box<crate::client::EpochUpload>),
    /// The one chunk of a slot object that holds the slot of this member
    /// (`GRP-284`).
    EpochChunk {
        /// The group.
        conversation: crate::ConversationId,
        /// The chunk and the facts of its record.
        wanted: Box<umbra_core::group::state::WantedChunk>,
    },
}

/// What one command of the group task belongs to.
enum GroupWork {
    /// A `GNEW` of one replica of a group.
    Creation {
        /// The group.
        group_id: [u8; 32],
        /// The replica, 0 or 1.
        replica: u8,
    },
    /// A `GPOST` of one record at one replica. A record of the roster
    /// carries no message.
    Post {
        /// The message of this device, or none for a roster object.
        message: Option<crate::MsgRef>,
        /// The group.
        conversation: crate::ConversationId,
        /// The relay that takes this copy.
        relay: [u8; 32],
        /// Whether the record starts an epoch, thus a `GKEY` follows it
        /// at the replica that accepted it (`GRP-362`).
        is_rotation: bool,
        /// The row that keeps a record with no message until a replica
        /// accepts it.
        unsent: Option<[u8; 16]>,
    },
}

impl Inner {
    /// The privacy mode of the conversation of a message.
    fn mode_of_message(&self, message: &crate::MsgRef) -> umbra_core::session::node::DelayClass {
        self.client
            .conversation_of_message(message)
            .and_then(|conversation| self.client.privacy_mode(conversation))
            .unwrap_or_default()
    }

    /// Gives each file job of the store to the transfer task (Part 12
    /// §12.8). With no run of the network the jobs wait in the store.
    fn pump_transfers(&mut self) {
        if self.bridge.is_none() {
            return;
        }
        // NET-320: a file whose run ended goes again after its wait.
        if !self.interrupted.0.is_empty() && unix_now() >= self.interrupted.1 {
            for message in core::mem::take(&mut self.interrupted.0) {
                let _ = self.client.requeue_file(&message);
            }
        }
        let mut commands = Vec::new();
        while let Some(job) = self.client.take_upload() {
            let tag = self.next_tag(TransferWork::File {
                message: job.message,
                is_upload: true,
            });
            // ATT-167: the circuits of a file take the mode of its
            // conversation.
            commands.push(TransferCommand::Mode {
                tag,
                class: self.mode_of_message(&job.message),
            });
            commands.push(TransferCommand::Upload {
                tag,
                plain: job.plain,
                shape: job.shape,
            });
        }
        while let Some(job) = self.client.take_download() {
            let tag = self.next_tag(TransferWork::File {
                message: job.message,
                is_upload: false,
            });
            commands.push(TransferCommand::Mode {
                tag,
                class: self.mode_of_message(&job.message),
            });
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

    /// Gives each group job of the store to the group task (Part 11
    /// §11.2). With no run of the network the jobs wait in the store.
    fn pump_groups(&mut self) {
        if self.bridge.is_none() {
            return;
        }
        self.pump_recovery();
        // GRP-253, GRP-229: a record that waits leaves at its bound, and one
        // whose slot came inside the window opens, on each device.
        let _ = self.client.expire_group_holds(unix_now_ms(), &mut OsRng);
        // GRP-343: each device of a member reads each group on its own
        // circuit with its own cursor. A device that does not own the
        // channels writes nothing to a group queue (GRP-338).
        if !self.owns_channels {
            self.pump_group_reads();
            return;
        }
        let mut commands = Vec::new();
        while let Some(job) = self.client.take_group_creation() {
            let tag = self.next_group_tag(GroupWork::Creation {
                group_id: job.group_id,
                replica: job.replica,
            });
            commands.push(GroupCommand::Create {
                tag,
                relay: job.relay,
                read_pk: job.read_pk,
                write_pk: job.write_pk,
                own: job.own,
                payment: Payment::Free,
            });
        }
        if let Ok(subscriptions) = self.client.group_subscriptions(&mut OsRng) {
            for subscription in subscriptions {
                if !self.group_reading.insert(subscription.conversation) {
                    continue;
                }
                // GRP-208: a subscription after a long absence shows a gap.
                let _ = self.client.group_reads(
                    &[subscription.conversation],
                    unix_now_ms(),
                    &mut OsRng,
                );
                commands.push(GroupCommand::Subscribe {
                    relay: subscription.relay,
                    group_queue_id: subscription.group_queue_id,
                    read: subscription.read,
                    fallback: subscription.fallback,
                    from_seq: subscription.from_seq,
                });
            }
        }
        // §11.4.1: a trigger that no record answered rotates the epoch
        // after the backoff of this device.
        if let Ok(due) = self
            .client
            .groups_to_rotate(crate::runtime::unix_now().saturating_mul(1_000), &mut OsRng)
        {
            for conversation in due {
                let _ = self.client.rotate_group(
                    conversation,
                    crate::runtime::unix_now().saturating_mul(1_000),
                    &mut OsRng,
                );
            }
        }
        // §11.9.7: a quiet week gives one presence record, and an admin
        // removes a member that stayed silent for `GROUP_SILENT_EVICT`.
        let now_ms = crate::runtime::unix_now().saturating_mul(1_000);
        if let Ok(due) = self.client.groups_owing_presence(now_ms, &mut OsRng) {
            for conversation in due {
                let _ = self.client.post_presence(conversation, now_ms, &mut OsRng);
            }
        }
        if let Ok(silent) = self.client.members_to_evict(now_ms, &mut OsRng) {
            for (conversation, index, action) in silent {
                let _ = self
                    .client
                    .act_on_silence(conversation, index, action, now_ms, &mut OsRng);
            }
        }
        // GRP-401, GRP-402: an admin that left its role or the group
        // leaves with owner credentials that the relay still takes.
        if let Ok(due) = self.client.groups_owing_owners(now_ms, &mut OsRng) {
            for conversation in due {
                let _ = self.client.rotate_owners(conversation, now_ms, &mut OsRng);
            }
        }
        // §11.4.3: a group whose epoch this device lacks asks for it, and
        // a request of another member is answered after the backoff.
        if let Ok(lacking) = self.client.groups_lacking_epoch(now_ms) {
            for (conversation, epoch) in lacking {
                let _ = self
                    .client
                    .request_epoch(conversation, epoch, now_ms, &mut OsRng);
            }
        }
        // GRP-290: a lapsed member asks the members it knows as contacts.
        let mut asked = false;
        if let Ok(lapsed) = self.client.groups_to_ask_pairwise(now_ms) {
            for (conversation, epoch) in lapsed {
                asked |= self
                    .client
                    .request_epoch_pairwise(conversation, epoch, now_ms, &mut OsRng)
                    .is_ok_and(|sent| sent > 0);
            }
        }
        if asked {
            self.flush_outgoing();
        }
        for (conversation, index) in self.client.key_answers_due(now_ms) {
            let _ = self
                .client
                .answer_key_request(conversation, index, now_ms, &mut OsRng);
        }
        self.pump_epoch_transfers();
        // NTF-132, NTF-133: the notify queue of a group left, and one that
        // a new queue replaced, leave each replica and end.
        if let (Ok(endings), Some(running)) = (self.client.notify_endings_due(), &self.bridge) {
            for ending in endings {
                for registration in ending.unregistrations {
                    commands.push(GroupCommand::Notify {
                        relay: registration.relay,
                        group_queue_id: registration.group_queue_id,
                        read: registration.read,
                        queue: registration.queue,
                        on: false,
                    });
                }
                for queue in &ending.queues {
                    let _ = running.end_notify_queue(*queue);
                    let _ = self.client.unbind_queue(queue, &mut OsRng);
                }
                let _ = self.client.notify_ended(ending.conversation, &mut OsRng);
            }
        }
        // NTF-090, NTF-104: each group with no notify queue, or with one
        // past its rotation, gets a new one from the run of the queues.
        let now_s = crate::runtime::unix_now();
        if let (Ok(groups), Some(running)) =
            (self.client.groups_without_notify(now_s), &self.bridge)
        {
            for conversation in groups {
                if self
                    .notify_pending
                    .values()
                    .any(|held| *held == conversation)
                {
                    continue;
                }
                self.next_notify_tag = self.next_notify_tag.wrapping_add(1);
                if running.make_notify_queue(self.next_notify_tag).is_ok() {
                    self.notify_pending
                        .insert(self.next_notify_tag, conversation);
                }
            }
        }
        // NTF-093, NTF-102: the notify queue of each group at each replica,
        // and again before the relay forgets it.
        if let Ok(due) = self.client.notify_registrations_due(now_ms / 1_000) {
            for registration in due {
                commands.push(GroupCommand::Notify {
                    relay: registration.relay,
                    group_queue_id: registration.group_queue_id,
                    read: registration.read,
                    queue: registration.queue,
                    on: registration.on,
                });
                let _ = self.client.notify_registered(
                    registration.conversation,
                    registration.which,
                    now_ms / 1_000,
                    &mut OsRng,
                );
            }
        }
        while let Some(job) = self.client.take_group_rekey() {
            commands.push(GroupCommand::Rotate {
                relay: job.relay,
                group_queue_id: job.group_queue_id,
                own: job.own,
                next_own_pk: job.next_own_pk,
                read_pk: job.read_pk,
                write_pk: job.write_pk,
            });
        }
        let now = crate::runtime::unix_now();
        while let Some(job) = self.client.take_group_post() {
            // GRP-194: the same record goes to each replica, each under its
            // own tag, and the first `GSEQ` accepts it (`GRP-195`). A replica
            // that accepted it or gave up takes it no more, and each send
            // counts against the ARQ of its replica (`NET-271`).
            for (replica, pending) in job.replicas.iter().zip(job.pending) {
                if !pending {
                    continue;
                }
                if let Some(row) = job.unsent {
                    let _ = self
                        .client
                        .group_post_sent(&row, &replica.relay, now, &mut OsRng);
                }
                let tag = self.next_group_tag(GroupWork::Post {
                    message: job.message,
                    conversation: job.conversation,
                    relay: replica.relay,
                    is_rotation: job.is_rotation,
                    unsent: job.unsent,
                });
                commands.push(GroupCommand::Post {
                    tag,
                    relay: replica.relay,
                    group_queue_id: replica.group_queue_id,
                    write: umbra_crypto::secret::Secret::new(*job.write.expose()),
                    fallback: job
                        .fallback
                        .as_ref()
                        .map(|held| umbra_crypto::secret::Secret::new(*held.expose())),
                    record: job.record.clone(),
                });
            }
        }
        for command in commands {
            if let Some(tag) = command.tag() {
                self.group_sent.insert(tag, command.copy());
            }
            self.send_group(command);
        }
        // DEV-296: each record of the member goes to the other devices of
        // the set on their sync channels too.
        self.flush_outgoing();
    }

    /// The subscription of each group, and no write: the work that a
    /// record of the group left for the member goes to the device that owns
    /// the channels, and this device drops it.
    fn pump_group_reads(&mut self) {
        while self.client.take_group_creation().is_some() {}
        while self.client.take_group_rekey().is_some() {}
        while self.client.take_group_post().is_some() {}
        let mut commands = Vec::new();
        if let Ok(subscriptions) = self.client.group_subscriptions(&mut OsRng) {
            for subscription in subscriptions {
                if !self.group_reading.insert(subscription.conversation) {
                    continue;
                }
                // GRP-208: a subscription after a long absence shows a gap.
                let _ = self.client.group_reads(
                    &[subscription.conversation],
                    unix_now_ms(),
                    &mut OsRng,
                );
                commands.push(GroupCommand::Subscribe {
                    relay: subscription.relay,
                    group_queue_id: subscription.group_queue_id,
                    read: subscription.read,
                    fallback: subscription.fallback,
                    from_seq: subscription.from_seq,
                });
            }
        }
        // An epoch-key record on the chunk path opens here too (GRP-344).
        while self.client.take_epoch_upload().is_some() {}
        self.pump_epoch_transfers();
        for command in commands {
            self.send_group(command);
        }
    }

    /// Puts the slot object of each chunked rotation on the chunk path,
    /// and fetches the chunk of each chunked record that arrived.
    fn pump_epoch_transfers(&mut self) {
        while let Some(upload) = self.client.take_epoch_upload() {
            let plain = Zeroizing::new(upload.chunked.object.clone());
            let tag = self.next_tag(TransferWork::EpochSlots(Box::new(upload)));
            self.send_transfer(TransferCommand::Upload {
                tag,
                plain,
                // A slot object is no media of the user (Part 12 §12.3).
                shape: Shape::default(),
            });
        }
        while let Some((conversation, wanted)) = self.client.take_epoch_chunk() {
            // A fetch in flight serves a copy of its record, and at most
            // `EPOCH_CHUNKS_MAX` fetches of one epoch of one group run.
            let mut same_epoch = self.transfer_tags.values().filter_map(|work| match work {
                TransferWork::EpochChunk {
                    conversation: held,
                    wanted: other,
                } if *held == conversation && other.epoch == wanted.epoch => Some(other),
                _ => None,
            });
            let fetching = same_epoch.clone().any(|other| **other == wanted);
            if fetching
                || same_epoch
                    .nth(crate::client::EPOCH_CHUNKS_MAX.saturating_sub(1))
                    .is_some()
            {
                continue;
            }
            let Ok(descriptor) = umbra_wire::descriptor::FileDescriptor::parse(&wanted.descriptor)
            else {
                continue;
            };
            let index = wanted.chunk;
            let tag = self.next_tag(TransferWork::EpochChunk {
                conversation,
                wanted: Box::new(wanted),
            });
            self.send_transfer(TransferCommand::FetchChunk {
                tag,
                descriptor: Box::new(descriptor),
                index,
            });
        }
    }

    /// Two relays for the group queues of a new group: different
    /// operators and different blocs, from the relays of the run
    /// (`GRP-191`).
    fn group_replicas(&self) -> Result<[[u8; 32]; GROUP_REPLICAS], FfiError> {
        let mut candidates = Vec::new();
        for endpoint in self.relays.iter().filter(|relay| relay.layer == 3) {
            let info = relay_info(endpoint)?;
            // REL-158: a relay that holds no queue role serves no group.
            if !info.candidate.queue {
                continue;
            }
            // NET-344: a provisional directory counts each relay as its own
            // operator, and the bloc still counts.
            candidates.push(GroupRelay {
                relay_id: info.candidate.relay_id,
                operator_id: if self.bootstrap {
                    info.candidate.relay_id
                } else {
                    info.candidate.operator_id
                },
                bloc: info.candidate.bloc,
            });
        }
        Ok(select_pair(&candidates)
            .map_err(|_| FfiError::Offline)?
            .relays)
    }

    fn next_group_tag(&mut self, work: GroupWork) -> u64 {
        self.next_group_tag = self.next_group_tag.wrapping_add(1);
        self.group_tags.insert(self.next_group_tag, work);
        self.next_group_tag
    }

    /// Sends one command to the group task, and starts the task when the
    /// link of an earlier run ended.
    fn send_group(&mut self, command: GroupCommand) {
        let command = match &self.groups {
            Some(sender) => match sender.send(command) {
                Ok(()) => return,
                Err(refused) => refused.0,
            },
            None => command,
        };
        self.groups = self.start_groups();
        if let Some(sender) = &self.groups {
            let _ = sender.send(command);
        }
        // With no task the work stays in the store, and the next run of
        // `resume_group_work` brings it back.
    }

    fn start_groups(&mut self) -> Option<mpsc::UnboundedSender<GroupCommand>> {
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
        for relay in self.relays.iter().filter(|relay| relay.layer != 1) {
            candidates.push(relay_info(relay).ok()?);
        }
        let tls = match &self.root_ca_path {
            Some(path) => native::tls_config_with_root_file(path),
            None => native::tls_config(),
        }
        .ok()?;
        let mut node =
            ClientNode::for_groups(ingress, candidates, self.client.root_identity().ok()?);
        node.set_bootstrap(self.bootstrap);
        let (commands, task_commands) = mpsc::unbounded_channel();
        let (task_updates, mut updates) = mpsc::unbounded_channel();
        spawner.spawn(run_groups(node, dial, tls, task_commands, task_updates));
        let me = self.me.clone();
        spawner.spawn(async move {
            while let Some(update) = updates.recv().await {
                let Some(handle) = me.upgrade() else {
                    break;
                };
                handle.on_group_update(update);
            }
        });
        Some(commands)
    }

    /// Gives each record of this device to the send path at once.
    fn flush_outgoing(&mut self) {
        let Inner { client, bridge, .. } = self;
        if let Some(running) = bridge {
            let _ = running.flush(client, &mut OsRng);
        }
    }

    /// Puts each snapshot that this admin owes a member behind the roster
    /// on the chunk path, and fetches each one that a notice named for this
    /// member (`GRP-329`, `GRP-330`).
    fn pump_recovery(&mut self) {
        while let Some(job) = self.client.take_snapshot_job() {
            let tag = self.next_tag(TransferWork::RecoverySnapshot {
                conversation: job.conversation,
                roster_epoch: job.roster_epoch,
                behind: job.behind,
            });
            self.send_transfer(TransferCommand::Upload {
                tag,
                plain: Zeroizing::new(job.snapshot),
                // A snapshot is no media of the user (Part 12 §12.3).
                shape: Shape::default(),
            });
        }
        let Ok(fetches) = self.client.recovery_fetches() else {
            return;
        };
        for (conversation, descriptor) in fetches {
            let is_running = self.transfer_tags.values().any(
                |work| matches!(work, TransferWork::RecoveryFetch(held) if *held == conversation),
            );
            if is_running {
                continue;
            }
            let Ok(descriptor) = umbra_wire::descriptor::FileDescriptor::parse(&descriptor) else {
                let _ = self.client.recovery_failed(conversation, &mut OsRng);
                continue;
            };
            let tag = self.next_tag(TransferWork::RecoveryFetch(conversation));
            self.send_transfer(TransferCommand::Download {
                tag,
                descriptor: Box::new(descriptor),
            });
        }
    }

    /// Asks the chunk path for the snapshot of each admit that waits
    /// (`GRP-313`).
    fn fetch_admitted_snapshots(&mut self) {
        let Ok(waiting) = self.client.group_admits() else {
            return;
        };
        for admit in waiting {
            // One fetch of one admit at a time: a commit while it runs
            // starts no second one.
            let is_running = self.transfer_tags.values().any(|work| {
                matches!(work, TransferWork::Admit { from, group_id }
                    if *from == admit.from && *group_id == admit.group_id)
            });
            if is_running {
                continue;
            }
            let Ok(descriptor) = umbra_wire::descriptor::FileDescriptor::parse(&admit.descriptor)
            else {
                continue;
            };
            let tag = self.next_tag(TransferWork::Admit {
                from: admit.from,
                group_id: admit.group_id,
            });
            self.send_transfer(TransferCommand::Download {
                tag,
                descriptor: Box::new(descriptor),
            });
        }
    }

    /// Takes one answer of the group task into the store.
    fn end_group(&mut self, update: GroupUpdate) {
        if let GroupUpdate::Faults(held) = update {
            self.pending_faults.absorb(*held);
            return;
        }
        match &update {
            GroupUpdate::Posted { tag, .. } => crate::devlog::line(format!("group {tag}: posted")),
            GroupUpdate::Failed { tag, reason } => {
                crate::devlog::line(format!("group {tag}: failed {reason:?}"));
            }
            GroupUpdate::Created { tag, .. } => {
                crate::devlog::line(format!("group {tag}: created"))
            }
            _ => {}
        }
        let answered = match &update {
            GroupUpdate::Created { tag, .. }
            | GroupUpdate::Posted { tag, .. }
            | GroupUpdate::Unreachable { tag }
            | GroupUpdate::Failed { tag, .. } => Some(*tag),
            _ => None,
        };
        if let Some(tag) = answered {
            let sent = self.group_sent.remove(&tag);
            // ABU-048: a relay under load refused a `GNEW` with no
            // credential, and it goes once more with a token of this
            // device, or with a proof of work (`ABU-014`).
            if let (
                GroupUpdate::Failed {
                    reason: Some(umbra_queue::Reject::Admission),
                    ..
                },
                Some(GroupCommand::Create {
                    tag,
                    relay,
                    read_pk,
                    write_pk,
                    own,
                    payment: Payment::Free,
                }),
            ) = (&update, sent)
            {
                let now = crate::runtime::unix_now();
                let payment = match self.client.take_token(umbra_core::abuse::epoch_number(now)) {
                    Ok(Some(token)) => Payment::Token(token),
                    _ => Payment::Work,
                };
                let command = GroupCommand::Create {
                    tag,
                    relay,
                    read_pk,
                    write_pk,
                    own,
                    payment,
                };
                self.group_sent.insert(tag, command.copy());
                self.send_group(command);
                return;
            }
        }
        match update {
            GroupUpdate::Created {
                tag,
                relay,
                group_queue_id,
            } => {
                let Some(GroupWork::Creation { group_id, replica }) = self.group_tags.remove(&tag)
                else {
                    return;
                };
                let _ = self.client.group_queue_made(
                    &group_id,
                    replica,
                    relay,
                    group_queue_id,
                    &mut OsRng,
                );
                // The second queue makes the group ready, and each record
                // that waited for it goes now.
                self.pump_groups();
            }
            GroupUpdate::Posted { tag, relay, .. } => {
                // GRP-195: one replica accepted, thus the record is accepted.
                let Some(GroupWork::Post {
                    message,
                    conversation,
                    is_rotation,
                    unsent,
                    ..
                }) = self.group_tags.remove(&tag)
                else {
                    return;
                };
                self.group_refusals.remove(&(conversation, relay));
                // GRP-200: an answer of a replica ends the line of GRP-199.
                let _ = self
                    .client
                    .group_replica_reached(conversation, &relay, true, &mut OsRng);
                if let Some(row) = unsent {
                    let _ = self.client.group_post_accepted(&row, &relay, &mut OsRng);
                }
                if let Some(message) = message {
                    let _ =
                        self.client
                            .set_delivery(&message, crate::Delivery::Accepted, &mut OsRng);
                }
                // GRP-361: the `GKEY` waits for the replica that took the
                // epoch-key record, and it goes to that replica alone.
                if is_rotation {
                    if let Ok(Some(job)) = self.client.group_rekey_for(conversation, &relay) {
                        self.send_group(GroupCommand::Rotate {
                            relay: job.relay,
                            group_queue_id: job.group_queue_id,
                            own: job.own,
                            next_own_pk: job.next_own_pk,
                            read_pk: job.read_pk,
                            write_pk: job.write_pk,
                        });
                    }
                }
            }
            GroupUpdate::Record {
                group_queue_id,
                seq,
                record,
            } => {
                if let Ok(Some(conversation)) = self.client.conversation_of_queue(&group_queue_id) {
                    self.group_lost.remove(&conversation);
                }
                // GRP-200: a record of a replica is its answer.
                let _ = self.client.group_queue_reached(&group_queue_id, &mut OsRng);
                let _ = self.client.on_group_record(
                    &group_queue_id,
                    seq,
                    &record,
                    crate::runtime::unix_now().saturating_mul(1_000),
                    &mut OsRng,
                );
                self.pump_epoch_transfers();
            }
            // GRP-199: no circuit reached the replica of the record. The
            // store holds the record, and the next run asks for it again.
            GroupUpdate::Unreachable { tag } => {
                if let Some(GroupWork::Post {
                    conversation,
                    relay,
                    ..
                }) = self.group_tags.remove(&tag)
                {
                    let _ =
                        self.client
                            .group_replica_reached(conversation, &relay, false, &mut OsRng);
                }
            }
            GroupUpdate::Failed { tag, reason } => {
                // WIR-317: a group queue that the relay does not hold and a
                // credential that it refuses give one reason. A record that
                // each replica refuses names a group that is gone there,
                // and `GRP-210` closes it. The store holds the record of
                // any other reason, and the next run asks for it again.
                let Some(GroupWork::Post {
                    conversation,
                    relay,
                    ..
                }) = self.group_tags.remove(&tag)
                else {
                    return;
                };
                if reason != Some(umbra_queue::Reject::Rejected) {
                    return;
                }
                self.group_refusals.insert((conversation, relay));
                let refused = self
                    .group_refusals
                    .iter()
                    .filter(|(held, _)| *held == conversation)
                    .count();
                if refused >= GROUP_REPLICAS {
                    let _ = self.client.close_group(conversation, &mut OsRng);
                }
            }
            GroupUpdate::Unsent { tag } => {
                // A task that the run dropped starts no new session, and
                // the store brings each message back at the next run.
                let Some(command) = self.group_sent.remove(&tag) else {
                    return;
                };
                if self.groups.is_none() {
                    self.group_tags.remove(&tag);
                    return;
                }
                self.group_sent.insert(tag, command.copy());
                self.send_group(command);
            }
            GroupUpdate::SubscriptionLost { group_queue_id } => {
                let Ok(Some(conversation)) = self.client.conversation_of_queue(&group_queue_id)
                else {
                    return;
                };
                // GRP-391: the next `GSUB` of the group takes the other
                // replica, and a third waits for the next session.
                self.group_reading.remove(&conversation);
                if self.group_lost.insert(conversation) {
                    self.pump_groups();
                }
            }
            GroupUpdate::Reset => {
                // Each subscription ended with the session, and each group
                // takes one again in the next (`GRP-202`).
                self.group_reading.clear();
                self.group_lost.clear();
                self.pump_groups();
            }
            GroupUpdate::Faults(_) => {}
            GroupUpdate::Ended => {
                self.groups = None;
                self.group_tags.clear();
                self.group_sent.clear();
                self.group_reading.clear();
            }
        }
    }

    /// Sends each registration and removal that waits for the NDR, one
    /// call for each handle group, in a task of the run (Part 8 §8.2.7).
    fn pump_ndr(&mut self) {
        let (Some((route, tls)), Some(spawner)) = (self.ndr.clone(), self.spawner.clone()) else {
            return;
        };
        let Ok(calls) = self.client.ndr_calls_due(&mut OsRng) else {
            return;
        };
        let now = unix_now();
        for call in calls {
            // A call that failed waits for its backoff.
            if self
                .ndr_retry
                .get(&call.handle)
                .is_some_and(|(at, _)| now < *at)
            {
                continue;
            }
            if !self.ndr_in_flight.insert(call.handle) {
                continue;
            }
            let me = self.me.clone();
            let route = route.clone();
            let tls = tls.clone();
            spawner.spawn(async move {
                let answer = ndr::call(&route, &call.request, tls, &mut OsRng).await;
                if let Some(handle) = me.upgrade() {
                    handle.on_ndr_answer(&call, answer);
                }
            });
        }
    }

    /// The dead-channel work of Part 3 §3.2.6 that is due: the silent
    /// channels once each hour, and the blobs of this device and of each
    /// peer.
    /// One record of a sync resend at each `SYNC_RESEND_GAP` (`DEV-073`).
    fn pump_sync_resend(&mut self, now: u64) {
        if now < self.next_sync_resend {
            return;
        }
        self.next_sync_resend = now.saturating_add(SYNC_RESEND_GAP);
        let Inner { client, bridge, .. } = self;
        let Some(running) = bridge.as_mut() else {
            return;
        };
        if client.resend_one(now, &mut OsRng).unwrap_or(false) {
            let _ = running.flush(client, &mut OsRng);
        }
        self.pump_catch_up(now);
    }

    /// The catch-up object of each peer that lags goes on the chunk path,
    /// and each one that a peer sent comes from it (`DEV-236` to `DEV-239`).
    fn pump_catch_up(&mut self, now: u64) {
        let is_moving = |tags: &BTreeMap<u64, TransferWork>| {
            tags.values().any(|work| {
                matches!(
                    work,
                    TransferWork::CatchUpOut(_) | TransferWork::CatchUpIn(_)
                )
            })
        };
        if is_moving(&self.transfer_tags) {
            return;
        }
        if let Ok(Some(job)) = self.client.take_catch_up(now, &mut OsRng) {
            let tag = self.next_tag(TransferWork::CatchUpOut(job.channel));
            self.send_transfer(TransferCommand::Upload {
                tag,
                plain: job.object,
                // A catch-up object is no media of the user (Part 12 §12.3).
                shape: Shape::default(),
            });
            return;
        }
        let Ok(fetches) = self.client.catch_up_fetches() else {
            return;
        };
        if let Some((channel, descriptor)) = fetches.into_iter().next() {
            let Ok(descriptor) = umbra_wire::descriptor::FileDescriptor::parse(&descriptor) else {
                let _ = self.client.catch_up_failed(channel);
                return;
            };
            let tag = self.next_tag(TransferWork::CatchUpIn(channel));
            self.send_transfer(TransferCommand::Download {
                tag,
                descriptor: Box::new(descriptor),
            });
        }
    }

    /// The events of the network that belong to the link of a device.
    fn take_link_events(&mut self) {
        let mut kept = VecDeque::with_capacity(self.net_events.len());
        while let Some(event) = self.net_events.pop_front() {
            match event {
                NetEvent::DeviceInvitation(bundle) => self.link_bundle(&bundle),
                NetEvent::DeviceLinked(conversation) => {
                    // The event stays for the view, and each pump sees it
                    // again, thus the link takes it once.
                    if self.links_opened.insert(conversation) {
                        self.link_opened();
                    }
                    kept.push_back(NetEvent::DeviceLinked(conversation));
                }
                other => kept.push_back(other),
            }
        }
        self.net_events = kept;
    }

    fn pump_dead_channels(&mut self) {
        if self.bridge.is_none() || !self.owns_channels {
            return;
        }
        let now = unix_now();
        if now >= self.next_silence_check {
            self.next_silence_check = now.saturating_add(3_600);
            if let Ok(silent) = self.client.silent_conversations(unix_now_ms()) {
                self.silent = silent;
            }
        }
        let epoch = self.client.directory_epoch().unwrap_or(0);
        let silent = self.silent.clone();
        let Ok(work) = self
            .client
            .dead_channel_work(now, epoch, &silent, &mut OsRng)
        else {
            return;
        };
        for step in work {
            self.send_dead_work(step);
        }
    }

    /// The state of each group that the other devices of the set lack goes
    /// up, and the state of each group that another device published comes
    /// down (`DEV-298`, `DEV-299`).
    fn pump_group_state(&mut self) {
        if self.bridge.is_none() {
            return;
        }
        while let Some((conversation, plain)) = self.client.take_group_state(unix_now()) {
            let tag = self.next_tag(TransferWork::GroupState(conversation));
            self.send_transfer(TransferCommand::UploadBackup { tag, plain });
        }
        while let Some((subject, descriptor)) = self.client.take_group_fetch() {
            let tag = self.next_tag(TransferWork::GroupFetch(subject));
            self.send_transfer(TransferCommand::DownloadBackup { tag, descriptor });
        }
    }

    /// The backup object that is due goes up (Part 4 §4.7.2). One write
    /// runs at a time: the object, then its root.
    fn pump_backup(&mut self) {
        // A linked device writes no backup: the backup of the set is the
        // one of the device that owns the channels.
        if self.bridge.is_none() || !self.owns_channels {
            return;
        }
        let is_running = self
            .transfer_tags
            .values()
            .any(|work| matches!(work, TransferWork::Backup(_) | TransferWork::BackupRoot(_)));
        if is_running || self.client.directory_epoch().unwrap_or(0) == 0 {
            return;
        }
        let Ok(Some(due)) = self.client.backup_due(unix_now(), self.is_foreground) else {
            return;
        };
        let tag = self.next_tag(TransferWork::Backup(Box::new(due.pending)));
        self.send_transfer(TransferCommand::UploadBackup {
            tag,
            plain: due.plain,
        });
    }

    fn send_dead_work(&mut self, step: crate::client::DeadWork) {
        use crate::client::DeadWork;
        use umbra_crypto::secret::Secret;
        match step {
            DeadWork::Rotate { contact } => {
                if let Some(running) = &self.bridge {
                    let _ = running.rotate_now(umbra_core::session::node::ContactId(contact));
                }
            }
            DeadWork::Write {
                conversation,
                week,
                handle,
                cred,
                read_pk,
                chunk,
            } => {
                // One write of a blob runs at a time for a conversation.
                let is_running = self.transfer_tags.values().any(|work| {
                    matches!(work, TransferWork::DeadWrite { conversation: held, .. } if *held == conversation)
                });
                if is_running {
                    return;
                }
                let tag = self.next_tag(TransferWork::DeadWrite {
                    conversation,
                    week,
                    cred: Secret::new(*cred.expose()),
                });
                self.send_transfer(TransferCommand::WriteHandle {
                    tag,
                    handle,
                    cred,
                    read_pk,
                    chunk,
                    replaces: false,
                });
            }
            DeadWork::Read {
                conversation,
                handle,
                read,
                blob_key,
            } => {
                let tag = self.next_tag(TransferWork::DeadRead {
                    conversation,
                    blob_key,
                });
                self.send_transfer(TransferCommand::ReadHandle { tag, handle, read });
            }
            DeadWork::Erase {
                handle,
                cred,
                relays,
            } => self.send_transfer(TransferCommand::Erase {
                chunk_id: handle,
                cred,
                relays,
            }),
        }
    }

    fn next_tag(&mut self, work: TransferWork) -> u64 {
        self.next_transfer_tag = self.next_transfer_tag.wrapping_add(1);
        self.transfer_tags.insert(self.next_transfer_tag, work);
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
        // ABU-106: a new transfer task takes the challenges first, thus its
        // first registration carries a solution.
        if let Some(sender) = &self.transfers {
            let _ = sender.send(TransferCommand::Challenges {
                book: self.challenges.clone(),
                now: unix_now(),
            });
        }
        let refused = match &self.transfers {
            Some(sender) => sender.send(command).err().map(|refused| refused.0),
            None => Some(command),
        };
        // No task runs: the transfer fails, and the user can ask again.
        if let Some(
            TransferCommand::Upload { tag, .. }
            | TransferCommand::Download { tag, .. }
            | TransferCommand::FetchChunk { tag, .. }
            | TransferCommand::WriteHandle { tag, .. }
            | TransferCommand::ReadHandle { tag, .. }
            | TransferCommand::UploadBackup { tag, .. }
            | TransferCommand::DownloadBackup { tag, .. },
        ) = refused
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
                // NET-344: a provisional directory counts each relay as its
                // own operator and its own family, for the chunk relays and
                // the backup relays.
                let (operator_id, family_id) = if self.bootstrap {
                    (info.candidate.relay_id, info.candidate.relay_id)
                } else {
                    (info.candidate.operator_id, info.candidate.family_id)
                };
                holders.push(AttachmentRelay {
                    relay_id: info.candidate.relay_id,
                    operator_id,
                    family_id,
                });
            }
            candidates.push(info);
        }
        let tls = match &self.root_ca_path {
            Some(path) => native::tls_config_with_root_file(path),
            None => native::tls_config(),
        }
        .ok()?;
        let mut node =
            ClientNode::for_transfers(ingress, candidates, self.client.root_identity().ok()?);
        node.set_bootstrap(self.bootstrap);
        let (commands, task_commands) = mpsc::unbounded_channel();
        let (task_updates, mut updates) = mpsc::unbounded_channel();
        spawner.spawn(run_transfers(
            node,
            dial,
            tls,
            holders,
            self.hold_offs.clone(),
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
        if let TransferUpdate::Faults(held) = update {
            self.pending_faults.absorb(*held);
            return;
        }
        crate::devlog::line(match &update {
            TransferUpdate::Progress { tag, done, total } => {
                format!("transfer {tag}: {done} of {total}")
            }
            TransferUpdate::Uploaded { tag, .. } => format!("transfer {tag}: uploaded"),
            TransferUpdate::Downloaded { tag, .. } => format!("transfer {tag}: downloaded"),
            TransferUpdate::HandleWritten { tag, .. } => format!("transfer {tag}: handle written"),
            TransferUpdate::HandleRead { tag, .. } => format!("transfer {tag}: handle read"),
            TransferUpdate::Failed { tag } => format!("transfer {tag}: failed"),
            TransferUpdate::Interrupted { tag } => format!("transfer {tag}: interrupted"),
            TransferUpdate::Gone { tag } => format!("transfer {tag}: gone"),
            TransferUpdate::Faults(_) => return,
        });
        // NET-320: a file whose run ended goes again in the next run, from
        // its stored state; each other work takes the end as a failure, and
        // its own retry follows.
        let update = match update {
            TransferUpdate::Interrupted { tag } => {
                if let Some(TransferWork::File { message, .. }) = self.transfer_tags.get(&tag) {
                    let message = *message;
                    self.transfer_tags.remove(&tag);
                    self.file_progress.remove(&message);
                    let (waiting, at, ends) = &mut self.interrupted;
                    if !waiting.contains(&message) {
                        waiting.push(message);
                    }
                    let wait = (5u64 << (*ends).min(5)).min(120);
                    *at = unix_now().saturating_add(wait);
                    *ends = ends.saturating_add(1);
                    return;
                }
                TransferUpdate::Failed { tag }
            }
            other => other,
        };
        // ATT-052: a file whose chunk each replica lost ends there. Each
        // other transfer takes the loss as a failure.
        let (update, is_gone) = match update {
            TransferUpdate::Gone { tag } => (TransferUpdate::Failed { tag }, true),
            other => (other, false),
        };
        let Some(update) = self.link_update(update) else {
            return;
        };
        // A transfer that ends well ends the backoff of the runs.
        if matches!(
            update,
            TransferUpdate::Uploaded { .. } | TransferUpdate::Downloaded { .. }
        ) {
            self.interrupted.2 = 0;
        }
        let mut moved = false;
        let Inner {
            client,
            bridge,
            transfer_tags,
            file_progress,
            progress_events,
            ..
        } = self;
        // A transfer that ends takes its progress with it.
        if let TransferUpdate::Uploaded { tag, .. }
        | TransferUpdate::Downloaded { tag, .. }
        | TransferUpdate::Failed { tag } = &update
        {
            if let Some(TransferWork::File { message, .. }) = transfer_tags.get(tag) {
                file_progress.remove(message);
            }
        }
        let mut dead_work = Vec::new();
        let mut restore_step = None;
        let mut backup_root = None;
        let mut backup_erase = Vec::new();
        match update {
            TransferUpdate::Progress { tag, done, total } => {
                if let Some(TransferWork::File { message, .. }) = transfer_tags.get(&tag) {
                    // A view moves in steps of 5 %, thus a large file makes
                    // twenty events and not one for each chunk.
                    let step = |done: u32, total: u32| {
                        u64::from(done).saturating_mul(20) / u64::from(total.max(1))
                    };
                    let before = file_progress.insert(*message, (done, total));
                    if before.is_none_or(|(was, _)| step(was, total) != step(done, total)) {
                        progress_events.push_back(*message);
                    }
                }
            }
            TransferUpdate::HandleWritten { tag, relays } => match transfer_tags.remove(&tag) {
                // IDN-099: the new root is there, and the old objects go.
                Some(TransferWork::BackupRoot(erase)) => backup_erase = erase,
                Some(TransferWork::DeadWrite {
                    conversation,
                    week,
                    cred,
                }) => {
                    if let Ok(Some(erase)) =
                        client.dead_blob_written(conversation, week, cred, relays, &mut OsRng)
                    {
                        dead_work.push(erase);
                    }
                }
                _ => {}
            },
            // NET-190: a blob that opens gives the address of the peer. A
            // blob that does not open is an empty handle (`NET-192`).
            TransferUpdate::HandleRead {
                tag,
                chunks,
                answered,
            } => {
                let work = transfer_tags.remove(&tag);
                if let Some(TransferWork::RestoreRoot { week }) = &work {
                    restore_step = Some(RestoreStep::Root {
                        week: *week,
                        chunks: chunks.clone(),
                        answered,
                    });
                }
                if let Some(TransferWork::DeadRead {
                    conversation,
                    blob_key,
                }) = work
                {
                    // A relay that serves bytes that do not open stops no
                    // read: the first chunk that opens names the address.
                    let address = chunks.iter().find_map(|chunk| {
                        umbra_core::session::dead::open_blob(&blob_key, chunk).ok()
                    });
                    let contact = client.contact_id_of(conversation);
                    if let (Some(address), Ok(contact), Some(running)) =
                        (address, contact, bridge.as_mut())
                    {
                        let contact = umbra_core::session::node::ContactId(contact);
                        if running.peer_moved(contact, address).is_ok() {
                            if let Ok(Some(erase)) =
                                client.dead_channel_ended(conversation, &mut OsRng)
                            {
                                dead_work.push(erase);
                            }
                            // NET-193: each record with no receipt goes again.
                            if client.resend_unreceipted(conversation).is_ok() {
                                let _ = running.flush(client, &mut OsRng);
                            }
                        }
                    }
                }
            }
            TransferUpdate::Uploaded { tag, uploaded } => match transfer_tags.remove(&tag) {
                // IDN-098: the root of the week names the object.
                Some(TransferWork::Backup(pending)) => {
                    let epoch = client.directory_epoch().unwrap_or(0);
                    if let Ok(root) = client.backup_uploaded(*pending, &uploaded, epoch, &mut OsRng)
                    {
                        backup_root = Some(root);
                    }
                }
                Some(TransferWork::File { message, .. }) => {
                    if client.upload_done(&message, &uploaded, &mut OsRng).is_ok() {
                        // The record with the descriptor goes to the send path.
                        if let Some(running) = bridge {
                            let _ = running.flush(client, &mut OsRng);
                        }
                    }
                }
                Some(TransferWork::Snapshot {
                    from,
                    group_id,
                    index,
                }) => {
                    // GRP-312: the admit names the snapshot that the chunk
                    // path now holds.
                    let mut descriptor = vec![0u8; uploaded.descriptor.len()];
                    if uploaded.descriptor.encode(&mut descriptor).is_ok() {
                        let joiner = crate::client::GroupJoiner {
                            from,
                            group_id,
                            is_added: true,
                        };
                        let _ = client.admit_joiner(
                            &joiner,
                            index,
                            &descriptor,
                            unix_now_ms(),
                            &mut OsRng,
                        );
                        if let Some(running) = bridge {
                            let _ = running.flush(client, &mut OsRng);
                        }
                    }
                }
                Some(TransferWork::RecoverySnapshot {
                    conversation,
                    roster_epoch,
                    behind,
                }) => {
                    // GRP-330: the notice names the snapshot on the path.
                    let mut descriptor = vec![0u8; uploaded.descriptor.len()];
                    if uploaded.descriptor.encode(&mut descriptor).is_ok() {
                        moved = client
                            .post_snapshot_notice(
                                conversation,
                                roster_epoch,
                                behind,
                                &descriptor,
                                unix_now_ms(),
                                &mut OsRng,
                            )
                            .is_ok();
                    }
                }
                Some(TransferWork::CatchUpOut(channel)) => {
                    // DEV-238: the descriptor goes on the sync channel.
                    let mut descriptor = vec![0u8; uploaded.descriptor.len()];
                    if uploaded.descriptor.encode(&mut descriptor).is_ok()
                        && client
                            .catch_up_uploaded(channel, &descriptor, &mut OsRng)
                            .is_ok()
                    {
                        if let Some(running) = bridge {
                            let _ = running.flush(client, &mut OsRng);
                        }
                    }
                }
                Some(TransferWork::GroupState(conversation)) => {
                    let mut descriptor = vec![0u8; uploaded.descriptor.len()];
                    if uploaded.descriptor.encode(&mut descriptor).is_ok()
                        && client
                            .group_state_uploaded(conversation, &descriptor, &mut OsRng)
                            .is_ok()
                    {
                        if let Some(running) = bridge {
                            let _ = running.flush(client, &mut OsRng);
                        }
                    }
                }
                Some(TransferWork::EpochSlots(upload)) => {
                    let mut descriptor = vec![0u8; uploaded.descriptor.len()];
                    if uploaded.descriptor.encode(&mut descriptor).is_ok() {
                        moved = client
                            .post_chunked_epoch(&upload, &descriptor, unix_now_ms(), &mut OsRng)
                            .is_ok();
                    }
                }
                _ => {}
            },
            TransferUpdate::Downloaded { tag, plain } => match transfer_tags.remove(&tag) {
                Some(TransferWork::RestoreObject(index)) => {
                    restore_step = Some(RestoreStep::Object { index, plain });
                }
                Some(TransferWork::File { message, .. }) => {
                    let _ = client.download_done(&message, &plain, &mut OsRng);
                }
                // DEV-299: the group of another device is here, and this
                // device reads it from now on.
                Some(TransferWork::GroupFetch(subject)) => {
                    moved = client
                        .apply_group_state(&subject, &plain, &mut OsRng)
                        .is_ok();
                }
                // DEV-239: each record of the object counts as a record of
                // the sync channel.
                Some(TransferWork::CatchUpIn(channel)) => {
                    moved = client
                        .catch_up_fetched(channel, &plain, unix_now_ms(), &mut OsRng)
                        .is_ok();
                    if let Some(running) = bridge {
                        let _ = running.flush(client, &mut OsRng);
                    }
                }
                // GRP-329: the member takes the roster of the snapshot.
                Some(TransferWork::RecoveryFetch(conversation)) => {
                    moved = client
                        .recovery_fetched(conversation, &plain, unix_now_ms(), &mut OsRng)
                        .is_ok();
                }
                Some(TransferWork::Admit { from, group_id }) => {
                    // GRP-326: the snapshot verifies, and the joiner holds
                    // the group from here.
                    let _ =
                        client.accept_group_admit(from, &group_id, &plain, unix_now(), &mut OsRng);
                }
                Some(TransferWork::EpochChunk {
                    conversation,
                    wanted,
                }) => {
                    // An epoch that installs moves the replicas, and a
                    // record that waited for it may be a rotation too.
                    moved = client
                        .install_epoch_chunk(
                            conversation,
                            &wanted,
                            &plain,
                            unix_now_ms(),
                            &mut OsRng,
                        )
                        .is_ok();
                }
                _ => {}
            },
            // The top of this function took each such update as a failure.
            TransferUpdate::Gone { .. }
            | TransferUpdate::Interrupted { .. }
            | TransferUpdate::Faults(_) => {}
            TransferUpdate::Failed { tag } => match transfer_tags.remove(&tag) {
                Some(TransferWork::RestoreRoot { .. } | TransferWork::RestoreObject(_)) => {
                    restore_step = Some(RestoreStep::Failed);
                }
                Some(TransferWork::File {
                    message,
                    is_upload: true,
                }) => {
                    let _ = client.upload_failed(&message, &mut OsRng);
                }
                Some(TransferWork::File {
                    message,
                    is_upload: false,
                }) => {
                    let _ = if is_gone {
                        client.download_gone(&message, &mut OsRng)
                    } else {
                        client.download_failed(&message, &mut OsRng)
                    };
                }
                // A snapshot that did not move leaves the join where it
                // was, and the view offers the press that sends it again.
                Some(TransferWork::Snapshot { from, .. }) => client.snapshot_failed(from),
                Some(TransferWork::EpochSlots(upload)) => client.epoch_upload_failed(*upload),
                Some(TransferWork::GroupState(conversation)) => {
                    client.group_state_failed(conversation);
                }
                // DEV-240: the paced resend brings each record.
                Some(TransferWork::CatchUpIn(channel)) => {
                    let _ = client.catch_up_failed(channel);
                }
                // The gap asks again later.
                Some(TransferWork::RecoveryFetch(conversation)) => {
                    let _ = client.recovery_failed(conversation, &mut OsRng);
                }
                // A chunk that did not move leaves the epoch missing, and
                // the member asks for it (§11.4.3).
                _ => {}
            },
        }
        if moved {
            self.pump_groups();
        }
        for step in dead_work {
            self.send_dead_work(step);
        }
        if let Some(root) = backup_root {
            let tag = self.next_tag(TransferWork::BackupRoot(root.erase));
            // ATT-138: the root of the week replaces the one before it.
            self.send_transfer(TransferCommand::WriteHandle {
                tag,
                handle: root.handle,
                cred: root.cred,
                read_pk: root.read_pk,
                chunk: root.chunk,
                replaces: true,
            });
        }
        for credential in backup_erase {
            self.send_transfer(TransferCommand::Erase {
                chunk_id: credential.chunk_id,
                cred: credential.cred,
                relays: credential.relays,
            });
        }
        if let Some(step) = restore_step {
            self.restore_step(step);
        }
    }

    /// Asks for the backup root of `week` (`IDN-101`).
    fn ask_restore_root(&mut self, week: u32) {
        let Some(job) = self.restore.as_ref() else {
            return;
        };
        let credentials = job.key.epoch(week);
        let tag = self.next_tag(TransferWork::RestoreRoot { week });
        self.send_transfer(TransferCommand::ReadHandle {
            tag,
            handle: credentials.handle,
            read: credentials.read,
        });
    }

    /// One step of a restore: a root, or one object that it names.
    fn restore_step(&mut self, step: RestoreStep) {
        use umbra_core::{
            attach::segment::unpad_handle_object,
            identity::{recovery::BackupRoot, BACKUP_LOOKBACK},
        };
        let Some(job) = self.restore.as_mut() else {
            return;
        };
        match step {
            RestoreStep::Failed => job.status = RestoreStatus::Failed,
            RestoreStep::Root {
                week,
                chunks,
                answered,
            } => {
                // IDN-103, IDN-116: a root that does not open is an empty
                // epoch, and the search goes back until one opens. Each
                // chunk that a relay gave is tried, thus one relay that
                // serves junk hides no root.
                let credentials = job.key.epoch(week);
                let descriptors: Option<Vec<Vec<u8>>> = chunks.iter().find_map(|chunk| {
                    let mut buf = Vec::new();
                    let sealed = unpad_handle_object(chunk).ok()?;
                    let root = BackupRoot::open(&credentials, sealed, &mut buf).ok()?;
                    Some(
                        root.entries
                            .iter()
                            .map(|entry| entry.descriptor.to_vec())
                            .collect(),
                    )
                });
                // A week that no relay answered for certain is no empty
                // week: the restore fails, and a new attempt reads it again.
                if descriptors.is_none() && !answered {
                    job.status = RestoreStatus::Failed;
                    return;
                }
                let Some(descriptors) = descriptors else {
                    let back = job.first_week.saturating_sub(week).saturating_add(1);
                    if back >= BACKUP_LOOKBACK || week == 0 {
                        job.status = RestoreStatus::NotFound;
                        return;
                    }
                    job.week = week.saturating_sub(1);
                    job.status = RestoreStatus::Searching { weeks_back: back };
                    let next = job.week;
                    self.ask_restore_root(next);
                    return;
                };
                let total = u32::try_from(descriptors.len()).unwrap_or(u32::MAX);
                job.objects = descriptors.iter().map(|_| None).collect();
                job.status = RestoreStatus::Fetching { done: 0, total };
                for (index, bytes) in descriptors.iter().enumerate() {
                    let Ok(descriptor) = umbra_wire::descriptor::FileDescriptor::parse(bytes)
                    else {
                        if let Some(job) = self.restore.as_mut() {
                            job.status = RestoreStatus::Failed;
                        }
                        return;
                    };
                    let tag = self.next_tag(TransferWork::RestoreObject(index));
                    self.send_transfer(TransferCommand::DownloadBackup {
                        tag,
                        descriptor: Box::new(descriptor),
                    });
                }
            }
            RestoreStep::Object { index, plain } => {
                if let Some(slot) = job.objects.get_mut(index) {
                    *slot = Some(plain);
                }
                let total = u32::try_from(job.objects.len()).unwrap_or(u32::MAX);
                let done = job.objects.iter().filter(|object| object.is_some()).count();
                job.status = RestoreStatus::Fetching {
                    done: u32::try_from(done).unwrap_or(u32::MAX),
                    total,
                };
                if done < job.objects.len() {
                    return;
                }
                let objects: Vec<Zeroizing<Vec<u8>>> =
                    job.objects.iter_mut().filter_map(Option::take).collect();
                match crate::client::RestoredBackup::assemble(&objects) {
                    Ok(restored) => {
                        job.status = RestoreStatus::Ready {
                            contacts: u32::try_from(restored.contact_count()).unwrap_or(u32::MAX),
                        };
                        job.restored = Some(restored);
                    }
                    Err(Error::NotFound) => job.status = RestoreStatus::NoIdentity,
                    Err(_) => job.status = RestoreStatus::Failed,
                }
            }
        }
    }

    fn has_event(&self) -> bool {
        // A locked client gives no progress event, thus one waits and does
        // not wake the platform thread.
        self.client.has_event()
            || !self.net_events.is_empty()
            || self.circuits_changed
            || (self.client.is_unlocked() && !self.progress_events.is_empty())
    }

    fn next_event(&mut self) -> Option<FfiEvent> {
        if self.client.is_unlocked() {
            if let Some(message) = self.progress_events.pop_front() {
                let conversation = self
                    .client
                    .conversation_of_message(&message)
                    .map_or(Vec::new(), |conversation| conversation.0.to_vec());
                return Some(FfiEvent::File {
                    conversation,
                    message: Arc::new(MsgHandle(message)),
                });
            }
        }
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
                Event::Typing {
                    conversation,
                    is_typing,
                } => FfiEvent::Typing {
                    conversation: conversation.0.to_vec(),
                    is_typing,
                },
                Event::Voted { conversation, .. } => FfiEvent::Voted {
                    conversation: conversation.0.to_vec(),
                },
                Event::Edited { conversation, .. } => FfiEvent::Edited {
                    conversation: conversation.0.to_vec(),
                },
                Event::ChangeFailed {
                    conversation,
                    is_delete,
                } => FfiEvent::ChangeFailed {
                    conversation: conversation.0.to_vec(),
                    is_delete,
                },
                Event::Deleted { conversation, .. } => FfiEvent::Deleted {
                    conversation: conversation.0.to_vec(),
                },
                Event::Conversations => FfiEvent::Conversations,
                Event::File { message } => FfiEvent::File {
                    // A message that a deletion took since has no
                    // conversation, and the view of none changes.
                    conversation: self
                        .client
                        .conversation_of_message(&message)
                        .map_or(Vec::new(), |conversation| conversation.0.to_vec()),
                    message: Arc::new(MsgHandle(message)),
                },
                Event::GroupOffer { .. } => FfiEvent::GroupOffer,
                Event::Introduction { .. } => FfiEvent::Introduction,
                Event::GroupJoiner { .. } => FfiEvent::GroupJoiner,
                // The snapshot of an admit is already on its way: the
                // commit of the record asked for it.
                Event::GroupAdmit { .. } => return self.next_event(),
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
            // The link takes the bundle before the queue of events.
            NetEvent::DeviceInvitation(_) => return self.next_event(),
            NetEvent::DeviceLinked(_) => FfiEvent::DeviceLinked,
            NetEvent::Refused => FfiEvent::Refused,
            NetEvent::ContactRequest => FfiEvent::ContactRequest,
        })
    }

    /// The ratchet keys of the runtime leave RAM with `K_store`, thus a
    /// locked client runs no network.
    fn stop_network_if_locked(&mut self) {
        if !self.client.is_unlocked() {
            self.bridge = None;
            // A progress event names a message that the lock hides.
            self.progress_events.clear();
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

/// Whether the store at `database_path` holds the header of its wrap. A
/// first launch that ended before its header left a file with none, and
/// the next start is a first launch again, with its restore and its link.
#[uniffi::export]
pub fn store_has_header(database_path: String) -> bool {
    // A file that does not read is a store all the same: a first launch
    // would offer a restore that ends in the removal of that file.
    std::path::Path::new(&database_path).exists()
        && SqliteBackend::holds_header(&database_path).unwrap_or(true)
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

/// Hardens each later random value of this process under the key of the
/// store that is open (`IMP-093`).
fn harden(client: &Client<SqliteBackend, ForeignElement>) {
    if let Ok(key) = client.rng_harden_key() {
        crate::runtime::harden_with(key);
    }
}

/// The lines of the run for the developer, in a debug build. A release
/// build gives none.
#[uniffi::export]
pub fn take_debug_lines() -> Vec<String> {
    crate::devlog::take()
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
            // A caller that passed no floor held a file with no header: a
            // first launch that ended before its header. The store takes a
            // measured floor, and not the cost of a floor of zero.
            let floor = if config.argon2_floor_ms == 0 {
                measure_argon2_floor_ms()
            } else {
                config.argon2_floor_ms
            };
            let cost = Cost::calibrate(floor);
            // The header goes into the same file as the records, thus the
            // connection opens a second time for the write of the header.
            let headers =
                SqliteBackend::open(&config.database_path).map_err(|_| FfiError::Storage)?;
            let client = Client::create(backend, element, &passphrase, cost, now, &mut OsRng)?;
            headers
                .set_header(client.header())
                .map_err(|_| FfiError::Storage)?;
            harden(&client);
            client
        }
    };
    Ok(handle_of(config.database_path, client))
}

/// Makes the store of a restored device (Part 4 §4.7.2): the files of the
/// database go, a new store comes from the root seed of the backup under
/// `passphrase`, and it takes each row of the backup. The platform drops
/// the handle of the restore before this call, thus no connection holds
/// the file. Each contact is stale until its renewal (`IDN-183`).
#[uniffi::export]
pub fn init_restored(
    config: Config,
    element: Arc<dyn SecureElementCallback>,
    passphrase: Vec<u16>,
    restored: Arc<Restored>,
) -> Result<Arc<Handle>, FfiError> {
    let restored = locked(&restored.0).take().ok_or(FfiError::NotFound)?;
    init_store_from(config, element, passphrase, &restored, |client| {
        Ok(client.apply_restore(&restored, &mut OsRng)?)
    })
}

/// Makes a new store under the root seed of `restored`, in the place of
/// the files of the database, and runs `fill` on it before the handle.
fn init_store_from(
    config: Config,
    element: Arc<dyn SecureElementCallback>,
    passphrase: Vec<u16>,
    restored: &crate::client::RestoredBackup,
    fill: impl FnOnce(&mut Client<SqliteBackend, ForeignElement>) -> Result<(), FfiError>,
) -> Result<Arc<Handle>, FfiError> {
    let passphrase = Zeroizing::new(passphrase);
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = format!("{}{suffix}", config.database_path);
        if std::path::Path::new(&path).exists() {
            std::fs::remove_file(&path).map_err(|_| FfiError::Storage)?;
        }
    }
    let backend = SqliteBackend::open(&config.database_path).map_err(|_| FfiError::Storage)?;
    let headers = SqliteBackend::open(&config.database_path).map_err(|_| FfiError::Storage)?;
    let cost = Cost::calibrate(config.argon2_floor_ms);
    let mut client = Client::create_with_seed(
        backend,
        ForeignElement(element),
        &passphrase,
        cost,
        unix_now(),
        restored.seed(),
        &mut OsRng,
    )?;
    headers
        .set_header(client.header())
        .map_err(|_| FfiError::Storage)?;
    fill(&mut client)?;
    harden(&client);
    Ok(handle_of(config.database_path, client))
}

/// Makes the store of a device from a root seed (Part 4 `IDN-003`): the
/// root identity comes back, and no contact, no message, and no group. The
/// digits are `RecoveryDigits` of type `0x0004`, and a check that fails, or
/// another type, is `Malformed` or `Unverified` (`IDN-151`, `IDN-154`).
#[uniffi::export]
pub fn init_from_root_seed(
    config: Config,
    element: Arc<dyn SecureElementCallback>,
    passphrase: Vec<u16>,
    digits: Vec<u16>,
) -> Result<Arc<Handle>, FfiError> {
    use umbra_core::identity::recovery::{from_digits, DigitsType};
    let passphrase = Zeroizing::new(passphrase);
    let text = Zeroizing::new(String::from_utf16_lossy(&Zeroizing::new(digits)));
    let seed = from_digits(&text, DigitsType::Root).map_err(|cause| match cause {
        umbra_core::Error::Unverified => FfiError::Unverified,
        _ => FfiError::Malformed,
    })?;
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| FfiError::Malformed)?;
    let backend = SqliteBackend::open(&config.database_path).map_err(|_| FfiError::Storage)?;
    let headers = SqliteBackend::open(&config.database_path).map_err(|_| FfiError::Storage)?;
    let cost = Cost::calibrate(config.argon2_floor_ms);
    let client = Client::create_with_seed(
        backend,
        ForeignElement(element),
        &passphrase,
        cost,
        unix_now(),
        umbra_crypto::secret::Secret::new(seed),
        &mut OsRng,
    )?;
    headers
        .set_header(client.header())
        .map_err(|_| FfiError::Storage)?;
    harden(&client);
    Ok(handle_of(config.database_path, client))
}

/// The type of entered recovery digits (Part 4 §4.7.7): 1 for the
/// recovery code, 2 for the user half, 3 for a share of the social half,
/// 4 for the root seed,
/// and 0 for digits whose check fails (`IDN-151`). A screen names the type
/// that the user entered and the one that it asks for (`IDN-153`).
#[uniffi::export]
pub fn recovery_digits_kind(digits: Vec<u16>) -> u8 {
    use umbra_core::identity::recovery::{from_digits, DigitsType};
    let text = Zeroizing::new(String::from_utf16_lossy(&Zeroizing::new(digits)));
    let kinds = [
        (DigitsType::Code, 1),
        (DigitsType::User, 2),
        (DigitsType::Share, 3),
        (DigitsType::Root, 4),
    ];
    kinds
        .into_iter()
        .find(|(kind, _)| from_digits(&text, *kind).is_ok())
        .map_or(0, |(_, number)| number)
}

/// The handle of an open client.
fn handle_of(database_path: String, client: Client<SqliteBackend, ForeignElement>) -> Arc<Handle> {
    let owns_channels = client.owns_channels().unwrap_or(true);
    Arc::new(Handle {
        database_path,
        inner: Mutex::new(Inner {
            invitation_host: String::new(),
            client,
            bridge: None,
            net_events: VecDeque::new(),
            guard: None,
            bootstrap: false,
            uses_second_pin: false,
            faults: Default::default(),
            pending_faults: Default::default(),
            report_queue_count: 0,
            relays: Vec::new(),
            circuits: Vec::new(),
            circuits_changed: false,
            me: Weak::new(),
            spawner: None,
            root_ca_path: None,
            transfers: None,
            transfer_tags: BTreeMap::new(),
            hold_offs: Arc::default(),
            interrupted: (Vec::new(), 0, 0),
            file_progress: BTreeMap::new(),
            progress_events: VecDeque::new(),
            next_transfer_tag: 0,
            groups: None,
            group_tags: BTreeMap::new(),
            group_sent: BTreeMap::new(),
            next_group_tag: 0,
            group_reading: BTreeSet::new(),
            group_lost: BTreeSet::new(),
            group_refusals: BTreeSet::new(),
            ndr: None,
            directory: None,
            links_opened: BTreeSet::new(),
            rendezvous_ready: BTreeMap::new(),
            rendezvous_refused: BTreeSet::new(),
            next_rendezvous_tag: 0,
            pending_grants: VecDeque::new(),
            ndr_in_flight: BTreeSet::new(),
            ndr_retry: BTreeMap::new(),
            notify_pending: BTreeMap::new(),
            next_notify_tag: 0,
            rotated_in_run: false,
            silent: Vec::new(),
            next_silence_check: 0,
            dead_work: Vec::new(),
            is_foreground: false,
            restore: None,
            run: 0,
            challenges: umbra_core::abuse::pow::ChallengeBook::default(),
            challenges_at: 0,
            link: None,
            link_serial: 0,
            owns_channels,
            next_sync_resend: 0,
        }),
        changed: Condvar::new(),
        runtime: Mutex::new(None),
    })
}

fn conversation_of(bytes: &[u8]) -> Result<ConversationId, FfiError> {
    Ok(ConversationId(
        bytes.try_into().map_err(|_| FfiError::Malformed)?,
    ))
}

/// The record that one cover slot got from the store (Part 3 `NET-065`).
enum Given {
    /// A batch of receipts.
    Receipt(crate::DueReceipt),
    /// A transparency digest of one source.
    Digest(umbra_wire::app::keys::DigestSource),
}

/// The store of the client, as the runtime of one run sees it. It holds a
/// weak reference, thus a handle that the platform drops ends the run.
struct HandleStore {
    handle: Weak<Handle>,
    /// The run of this store. A run that a later connect replaced writes
    /// nothing.
    run: u64,
    /// What the last slot got: a batch of receipts, or a digest.
    given: Option<Given>,
}

impl Persist for HandleStore {
    fn commit(&mut self, changes: Vec<StateChange>, received: &[(ContactId, Vec<u8>)]) -> bool {
        let Some(handle) = self.handle.upgrade() else {
            return false;
        };
        let mut inner = locked(&handle.inner);
        // A replaced run ends with no write: the node of the new run holds
        // the state from the store, and an older node would overwrite it.
        if inner.run != self.run {
            return false;
        }
        // A locked client takes no batch, and the run ends (`IMP-127`).
        let committed = inner
            .client
            .commit_network(&changes, received, unix_now_ms(), &mut OsRng)
            .is_ok();
        // A record of a contact goes to the devices of the set, and one
        // that a peer handed to this device goes to its contact.
        let Inner { client, bridge, .. } = &mut *inner;
        if let Some(running) = bridge.as_mut() {
            let _ = running.flush(client, &mut OsRng);
        }
        // The join flow of Part 11 moves with a record of a contact: an
        // admit asks for its snapshot, and the work of a group goes out.
        // Neither waits for a view to read an event.
        inner.fetch_admitted_snapshots();
        inner.pump_groups();
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
        self.given = Some(Given::Receipt(due));
        Some((contact, app))
    }

    fn admission_token(&mut self, now: u64) -> Option<Vec<u8>> {
        let handle = self.handle.upgrade()?;
        let mut inner = locked(&handle.inner);
        inner
            .client
            .take_token(umbra_core::abuse::epoch_number(now))
            .ok()?
    }

    fn due_digest(&mut self, now: u64) -> Option<(ContactId, Vec<u8>)> {
        let handle = self.handle.upgrade()?;
        let inner = locked(&handle.inner);
        // NET-065: a transparency digest comes after a receipt and a
        // report, to one contact at random (DIS-029, DIS-031, REL-008).
        let (source, app) = inner.client.due_digest(now, &mut OsRng).ok()??;
        let contacts = inner.bridge.as_ref()?.contacts();
        let all: Vec<ConversationId> = contacts
            .iter()
            .map(|(conversation, _)| *conversation)
            .collect();
        let open = inner.client.gossip_contacts(&all).ok()?;
        let pick = usize::try_from(random_u64() % u64::try_from(open.len()).ok()?.max(1)).ok()?;
        let conversation = open.get(pick)?;
        let contact = inner.bridge.as_ref()?.contact_for(conversation)?;
        self.given = Some(Given::Digest(source));
        Some((contact, app))
    }

    fn digest_sent(&mut self) {
        self.receipt_sent();
    }

    fn receipt_sent(&mut self) {
        let (Some(handle), Some(given)) = (self.handle.upgrade(), self.given.take()) else {
            return;
        };
        let mut inner = locked(&handle.inner);
        let _ = match given {
            Given::Receipt(due) => inner.client.receipt_sent(&due),
            Given::Digest(source) => inner.client.digest_sent(source, unix_now(), &mut OsRng),
        };
    }
}

impl Handle {
    /// A task of the runtime gives one update of the network to the client.
    fn on_transfer_update(&self, update: TransferUpdate) {
        let mut inner = locked(&self.inner);
        inner.end_transfer(update);
        // A snapshot that arrived brought a group with it, and that group
        // takes its subscription now.
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
    }

    fn on_group_update(&self, update: GroupUpdate) {
        let mut inner = locked(&self.inner);
        inner.end_group(update);
        // A record of a group with a descriptor asks for its file.
        inner.pump_transfers();
        drop(inner);
        self.changed.notify_all();
    }

    fn on_update(&self, run: u64, update: Update) {
        let mut inner = locked(&self.inner);
        // The end of a run that a later connect replaced must not end the
        // new run: it would drop the bridge of that run.
        if inner.run != run {
            return;
        }
        let Inner {
            client,
            bridge,
            net_events,
            guard,
            uses_second_pin,
            faults,
            circuits,
            circuits_changed,
            notify_pending,
            rotated_in_run,
            ndr_retry,
            silent,
            dead_work,
            rendezvous_ready,
            rendezvous_refused,
            pending_grants,
            invitation_host,
            pending_faults,
            ..
        } = &mut *inner;
        let ended = matches!(update, Update::Offline(_));
        let is_tick = matches!(update, Update::Tick);
        match &update {
            Update::Circuits(chains) => {
                circuits.clone_from(chains);
                *circuits_changed = true;
            }
            // NTF-112: each queue with no binding asks its relay for the
            // notification key. NTF-007, NTF-081: one handle group that is
            // due rotates in a run, and its queues bind again.
            Update::Queues(queues) => {
                if !*rotated_in_run {
                    *rotated_in_run = client
                        .rotate_one_group(unix_now(), &mut OsRng)
                        .unwrap_or(false);
                }
                if let (Ok(unbound), Some(running)) = (
                    client.queues_to_bind(queues, unix_now(), &mut OsRng),
                    bridge.as_ref(),
                ) {
                    let mut sent = Vec::new();
                    for recipient_id in unbound {
                        if running.notify_queue(recipient_id).is_ok() {
                            sent.push(recipient_id);
                        }
                    }
                    client.binds_sent(&sent);
                }
            }
            // NET-182: a dead channel takes a new queue, and its blob names
            // it.
            Update::ChannelDead(contact) => {
                if let Ok(conversation) = client.conversation_for(&contact.0) {
                    let _ = client.channel_dead(conversation, unix_now(), &mut OsRng);
                }
                if let Some(running) = bridge.as_ref() {
                    let _ = running.rotate_now(*contact);
                }
            }
            // NET-103: the records in the hole are lost, and the
            // conversation says so.
            Update::DeliveryGap(contact) => {
                if let Ok(conversation) = client.conversation_for(&contact.0) {
                    let _ = client.delivery_gap(conversation, unix_now_ms(), &mut OsRng);
                }
            }
            Update::QueueRotated { contact, address } => {
                if let Ok(conversation) = client.conversation_for(&contact.0) {
                    let _ = client.dead_queue_rotated(conversation, address, &mut OsRng);
                }
            }
            // NET-190, NET-193: the peer moved, or a renewal replaced the
            // channel (NET-329). The channel lives, and each record with no
            // delivery receipt goes again.
            Update::PeerMoved(contact) | Update::ChannelRenewed(contact) => {
                if matches!(update, Update::ChannelRenewed(_)) {
                    let _ = client.restored_renewed(&contact.0, &mut OsRng);
                }
                if let Ok(conversation) = client.conversation_for(&contact.0) {
                    if let Ok(Some(erase)) = client.dead_channel_ended(conversation, &mut OsRng) {
                        dead_work.push(erase);
                    }
                    silent.retain(|held| *held != conversation);
                    if client.resend_unreceipted(conversation).is_ok() {
                        if let Some(running) = bridge.as_mut() {
                            let _ = running.flush(client, &mut OsRng);
                        }
                    }
                }
            }
            Update::RendezvousQueue {
                tag,
                recipient_id,
                address,
            } => {
                rendezvous_ready.insert(*tag, (*recipient_id, address.clone()));
            }
            Update::RendezvousRefused(tag) => {
                rendezvous_refused.insert(*tag);
            }
            // ABU-012: the request shows after its checks.
            Update::Hello { queue, envelope } => {
                if let Ok(Some(_)) = client.on_hello(queue, envelope, unix_now(), &mut OsRng) {
                    net_events.push_back(NetEvent::ContactRequest);
                }
            }
            Update::NotifyQueue {
                tag,
                recipient_id,
                address,
            } => {
                if let Some(conversation) = notify_pending.remove(tag) {
                    let _ = client.set_group_notify(
                        conversation,
                        *recipient_id,
                        address,
                        unix_now(),
                        &mut OsRng,
                    );
                }
            }
            // NTF-113: the binding goes sealed to that key.
            Update::NotifyKey {
                recipient_id,
                relay_ntf_pk,
            } => {
                let sealed = client
                    .binding_of(recipient_id)
                    .ok()
                    .flatten()
                    .zip(umbra_crypto::kem::PublicKey::from_bytes(relay_ntf_pk).ok())
                    .and_then(|(binding, key)| binding.seal(&key, recipient_id, &mut OsRng).ok());
                if let (Some(sealed), Some(running)) = (sealed, bridge.as_ref()) {
                    // NTF-125: a bind that a registration overtook asks for
                    // its key once more.
                    if running.bind_queue(*recipient_id, sealed).is_ok()
                        && !client.queue_bound(recipient_id, &mut OsRng).unwrap_or(true)
                    {
                        let _ = running.notify_queue(*recipient_id);
                    }
                }
            }
            Update::Faults(held) => {
                *faults = (**held).clone();
                faults.absorb(core::mem::take(pending_faults));
            }
            // NET-178: the push binding of a queue that ended goes with it.
            Update::QueueEnded(queue) => {
                let _ = client.unbind_queue(queue, &mut OsRng);
            }
            // A network that came back takes each NDR call at once.
            Update::Online => ndr_retry.clear(),
            // A run that ended holds no circuit, and a notify queue that it
            // did not make goes to the next run.
            Update::Offline(_) => {
                circuits.clear();
                *circuits_changed = true;
                notify_pending.clear();
                *rotated_in_run = false;
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
                match event {
                    // WIR-199: a fresh invitation of an allowed introduction
                    // goes in its grant, and the view gets no link.
                    NetEvent::Invitation(bundle) if !pending_grants.is_empty() => {
                        let bytes: Result<&[u8; FRAGMENT_LEN], _> = bundle.as_slice().try_into();
                        let link = bytes
                            .ok()
                            .and_then(|b| Fragment::from_bytes(b).ok())
                            .map(|fragment| fragment.link(invitation_host));
                        if let (Some(id), Some(link)) = (pending_grants.pop_front(), link) {
                            let _ = client.grant_introduction(
                                &id,
                                link.as_bytes(),
                                unix_now_ms(),
                                &mut OsRng,
                            );
                            let _ = running.flush(client, &mut OsRng);
                        }
                    }
                    other => net_events.push_back(other),
                }
            }
        } else if let Update::Offline(cause) = update {
            net_events.push_back(NetEvent::Offline(cause));
        }
        if ended {
            *bridge = None;
            // The transfer task and the group task each have a link of
            // their own. Both end with the run, and the store holds what
            // they did not complete.
            inner.transfers = None;
            inner.groups = None;
            inner.group_reading.clear();
        }
        // A record with a descriptor asks for its file.
        inner.take_link_events();
        inner.pump_transfers();
        inner.pump_group_state();
        inner.pump_groups();
        inner.pump_ndr();
        if is_tick {
            inner.pump_dead_channels();
            inner.pump_backup();
            // GRP-208: the read time of each group that a subscription reads.
            let reading: Vec<crate::ConversationId> = inner.group_reading.iter().copied().collect();
            let _ = inner
                .client
                .group_reads(&reading, unix_now_ms(), &mut OsRng);
            // DEV-057: an acknowledgment that its period made due.
            let Inner { client, bridge, .. } = &mut *inner;
            if client.queue_sync_acks(unix_now(), &mut OsRng).is_ok() {
                if let Some(running) = bridge.as_mut() {
                    let _ = running.flush(client, &mut OsRng);
                }
            }
        }
        let work = core::mem::take(&mut inner.dead_work);
        for step in work {
            inner.send_dead_work(step);
        }
        drop(inner);
        self.changed.notify_all();
    }

    /// The answer of the NDR to one call of this device.
    fn on_ndr_answer(
        &self,
        call: &crate::client::NdrCall,
        answer: Result<NdrResponse, NativeError>,
    ) {
        let mut inner = locked(&self.inner);
        inner.ndr_in_flight.remove(&call.handle);
        // A removal that the NDR refuses names a registration under another
        // secret, which no later call of this device removes, thus it ends
        // as one that the NDR took.
        let answer = match answer {
            Ok(NdrResponse::Refused | NdrResponse::Gone) if call.is_removal => {
                Ok(NdrResponse::Taken)
            }
            other => other,
        };
        // A call that failed goes again after a wait that doubles, from 30
        // seconds up to an hour.
        if matches!(answer, Ok(NdrResponse::Taken)) {
            inner.ndr_retry.remove(&call.handle);
        } else {
            let fails = inner
                .ndr_retry
                .get(&call.handle)
                .map_or(0, |(_, fails)| *fails);
            let wait = (30u64 << fails.min(7)).min(3_600);
            inner.ndr_retry.insert(
                call.handle,
                (unix_now().saturating_add(wait), fails.saturating_add(1)),
            );
        }
        if matches!(answer, Ok(NdrResponse::Taken)) {
            // NTF-125: each queue of the handle binds again at once.
            let again = inner
                .client
                .ndr_call_taken(call, &mut OsRng)
                .unwrap_or_default();
            if let Some(running) = inner.bridge.as_ref() {
                for recipient_id in again {
                    let _ = running.notify_queue(recipient_id);
                }
            }
        }
    }
}

/// The route to the NDR that the build pinned, or none.
fn ndr_route(network: &Network) -> Option<NdrRoute> {
    let mut relay = Url::parse(network.ndr_relay_url.as_deref()?)?;
    if let Some(ipv4) = &network.ndr_relay_ipv4 {
        let octets: [u8; 4] = ipv4.as_slice().try_into().ok()?;
        relay.address = Some(std::net::IpAddr::from(octets));
    }
    let (key_id, gateway) =
        umbra_crypto::ohttp::parse_key_config(network.ndr_key_config.as_deref()?).ok()?;
    Some(NdrRoute {
        relay,
        key_id,
        gateway,
    })
}

impl Handle {
    fn set_push_token(&self, token: Option<(TokenCarrier, &str)>) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner.client.set_push_token(token, &mut OsRng)?;
        // A new token goes to the NDR at once, whatever the earlier calls.
        inner.ndr_retry.clear();
        inner.pump_ndr();
        Ok(())
    }

    /// The count of the queues that bound for push, and of the handle
    /// groups that the NDR holds, for a caller in Rust.
    pub fn push_state(&self) -> Result<(usize, usize), FfiError> {
        Ok(locked(&self.inner).client.push_state()?)
    }

    /// The file of a message, in the clear, for a caller in Rust.
    pub fn file_bytes(&self, message: &MsgHandle) -> Result<Zeroizing<Vec<u8>>, FfiError> {
        Ok(locked(&self.inner).client.file_bytes(&message.0)?)
    }
}

#[uniffi::export]
impl Handle {
    /// The push state that the view of the connection shows: the carrier of
    /// the token that the NDR holds, the queues that bound for push, and the
    /// handle groups that the NDR holds (Part 8 §8.2).
    pub fn push_status(&self) -> Result<PushStatus, FfiError> {
        let inner = locked(&self.inner);
        let carrier = match inner
            .client
            .push_token()?
            .and_then(|token| token.first().copied())
        {
            Some(byte) if byte == TokenCarrier::Fcm as u8 => "FCM",
            Some(byte) if byte == TokenCarrier::UnifiedPush as u8 => "UnifiedPush",
            _ => "",
        };
        let (bound, registered) = inner.client.push_state()?;
        Ok(PushStatus {
            carrier: carrier.to_owned(),
            bound_queues: u32::try_from(bound).unwrap_or(u32::MAX),
            registered_groups: u32::try_from(registered).unwrap_or(u32::MAX),
        })
    }

    /// The link-fault counts of this device and of its run (Part 10
    /// §10.4.2).
    pub fn link_fault_status(&self) -> LinkFaultStatus {
        let inner = locked(&self.inner);
        let summary = inner.faults.summary(unix_now());
        LinkFaultStatus {
            loops_sent: u32::from(summary.loops_sent),
            loops_back: u32::from(summary.loops_back),
            loops_lost: u32::from(summary.loops_lost),
            forced: u32::from(summary.forced),
            reports_waiting: u32::from(summary.reports_waiting),
            report_queues: inner.report_queue_count,
        }
    }

    /// The digests of contacts that differ from the view of this device: a
    /// log served another view to one of the two.
    pub fn gossip_warnings(&self) -> Result<Vec<GossipWarningInfo>, FfiError> {
        let warnings = locked(&self.inner).client.gossip_warnings()?;
        Ok(warnings
            .into_iter()
            .map(|warning| GossipWarningInfo {
                source: match warning.source {
                    umbra_wire::app::keys::DigestSource::TreeHead => "directory",
                    _ => "relays",
                }
                .to_owned(),
                epoch: warning.epoch,
            })
            .collect())
    }

    /// Takes the FCM registration token that Firebase gave, or none when
    /// it took the token back. Each handle group of this device registers
    /// with the NDR under it, or leaves (Part 8 §8.2.7).
    pub fn set_fcm_token(&self, token: Option<String>) -> Result<(), FfiError> {
        self.set_push_token(token.as_deref().map(|token| (TokenCarrier::Fcm, token)))
    }

    /// Takes the endpoint of a UnifiedPush distributor, or none.
    pub fn set_push_endpoint(&self, endpoint: Option<String>) -> Result<(), FfiError> {
        let token = endpoint
            .as_deref()
            .map(|url| (TokenCarrier::UnifiedPush, url));
        self.set_push_token(token)
    }

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
        let is_provisional = keyset.independent_count < umbra_core::directory::AUTHORITY_FLOOR;
        let mut consensus = Consensus::new(keyset, floor).map_err(|_| FfiError::Malformed)?;
        // REL-035, REL-113: the correction of an earlier run makes a root
        // that is too old stale, although it names the stored epoch.
        consensus.set_correction(inner.client.directory_correction()?);
        let manifest = RelayManifest::parse(&manifest).map_err(|_| FfiError::Malformed)?;
        let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), unix_now())
            .map_err(|cause| match cause {
                umbra_core::Error::Stale => FfiError::Stale,
                umbra_core::Error::Malformed => FfiError::Malformed,
                _ => FfiError::Unverified,
            })?;
        if let Some(correction) = consensus.correction() {
            inner
                .client
                .set_directory_correction(correction, &mut OsRng)?;
        }
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
        if pins.refresh(&eligible, now, is_provisional) {
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
        // REL-008: the digest of this root is the one that the gossip sends
        // and compares.
        inner
            .client
            .keep_consensus_digest(set.epoch, &set.digest, &mut OsRng)?;
        Ok(VerifiedNetwork {
            network: Network {
                relays,
                root_ca_path,
                invitation_host,
                // The build pins the route to the NDR (`NTF-127`), thus no
                // manifest carries it and no relay chooses it (`NTF-029`).
                ndr_relay_url: None,
                ndr_key_config: None,
                ndr_relay_ipv4: None,
                directory_relay_url: None,
                directory_pins: None,
                directory_relay_ipv4: None,
                report_queues: set
                    .report_queues
                    .iter()
                    .map(|queue| [&queue.address[..], &queue.report_pk].concat())
                    .collect(),
                removed_links: set
                    .removed_links
                    .iter()
                    .map(|link| {
                        [&link.epoch.to_be_bytes()[..], &link.relay_a, &link.relay_b].concat()
                    })
                    .collect(),
                is_provisional,
            },
            epoch: set.epoch,
            is_clock_corrected: consensus.clock_state() == ClockState::Corrected,
            is_provisional,
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
            admission_surge: inner.challenges.is_surge(unix_now()),
            one_operator: inner
                .circuits
                .iter()
                .map(|chain| {
                    let hops: Vec<_> = chain
                        .iter()
                        .filter_map(|relay_id| {
                            let endpoint = inner
                                .relays
                                .iter()
                                .find(|relay| relay.relay_id.as_slice() == relay_id.as_slice())?;
                            relay_info(endpoint).ok().map(|info| info.candidate)
                        })
                        .collect();
                    hops.iter().enumerate().any(|(index, hop)| {
                        hops.iter()
                            .skip(index.saturating_add(1))
                            .any(|other| !hop.apart_operator(other))
                    })
                })
                .collect(),
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
        let run;
        {
            let mut inner = locked(&self.inner);
            inner.run = inner.run.wrapping_add(1);
            run = inner.run;
            // The run before ends here: a start that fails below leaves no
            // bridge of a run whose commits the new identifier refuses, and
            // a grant of that run captures no invitation of this one.
            inner.bridge = None;
            inner.pending_grants.clear();
            inner.invitation_host.clone_from(&network.invitation_host);
            inner.guard = Some(ingress.key.relay_id);
            inner.bootstrap = network.is_provisional;
            inner.relays.clone_from(&network.relays);
            inner.report_queue_count =
                u32::try_from(network.report_queues.len()).unwrap_or(u32::MAX);
            inner.circuits.clear();
            inner.circuits_changed = true;
            inner.me = Arc::downgrade(&self);
            inner.spawner = Some(runtime.handle().clone());
            inner.root_ca_path.clone_from(&network.root_ca_path);
            inner.ndr = ndr_route(&network).map(|route| (route, tls.clone()));
            inner.directory = network
                .directory_relay_url
                .as_deref()
                .zip(network.directory_pins.as_deref())
                .and_then(|(url, pins)| {
                    directory::DirectoryLink::new(
                        url,
                        network.directory_relay_ipv4.as_deref(),
                        pins,
                        tls.clone(),
                    )
                });
            inner.transfers = None;
            inner.groups = None;
            inner.group_reading.clear();
            inner.owns_channels = inner.client.owns_channels()?;
            let Inner {
                client,
                bridge,
                net_events,
                owns_channels,
                faults: inner_faults,
                pending_faults,
                ..
            } = &mut *inner;
            // The node continues each contact and each invitation of the
            // earlier runs. A linked device runs its sync channels alone:
            // the device that owns a channel reads its queue (`DEV-287`).
            let mut node = ClientNode::with_relays(ingress, candidates, client.root_identity()?);
            inner_faults.absorb(core::mem::take(pending_faults));
            node.set_faults(core::mem::take(inner_faults));
            node.set_bootstrap(network.is_provisional);
            // REL-185: no chain of this run holds a removed link.
            node.set_removed_links(
                network
                    .removed_links
                    .iter()
                    .filter_map(|link| {
                        let (epoch, relays) = link.split_at_checked(8)?;
                        let (a, b) = relays.split_at_checked(32)?;
                        Some(umbra_core::directory::removal::LinkRemoval::of(
                            u64::from_be_bytes(epoch.try_into().ok()?),
                            a.try_into().ok()?,
                            b.try_into().ok()?,
                        ))
                    })
                    .collect(),
            );
            // REL-169: the link-fault reports of this run go to these queues.
            node.set_report_queues(
                network
                    .report_queues
                    .iter()
                    .filter_map(|queue| {
                        let (address, key) = queue.split_at_checked(REPORT_ADDRESS_LEN)?;
                        Some((address.try_into().ok()?, key.try_into().ok()?))
                    })
                    .collect(),
            );
            // DEV-257: a revoked device whose channel a crash left, before
            // the node takes the channels of this run.
            let _ = client.end_revoked_channels(&mut OsRng);
            let stored = client.stored_network()?;
            let device_peers = client.device_peers()?;
            let mut contacts = BTreeMap::new();
            for (conversation, state) in &stored.contacts {
                if !*owns_channels && !device_peers.contains(conversation) {
                    continue;
                }
                let contact = node
                    .restore_contact(state)
                    .map_err(|_| FfiError::Integrity)?;
                contacts.insert(*conversation, contact);
            }
            // IDN-183: each contact of a restore is stale until its renewal
            // ends, in each run.
            for id in client.restored_stale()? {
                let _ = node.mark_stale(&umbra_core::session::node::ContactId(id));
            }
            let holds_half = !stored.invitations.is_empty();
            for state in &stored.invitations {
                let bundle = node
                    .restore_invitation(state)
                    .map_err(|_| FfiError::Integrity)?;
                // A renewal of Part 3 §3.2.6 is no invitation of the user.
                if !bundle.is_empty() {
                    net_events.push_back(NetEvent::Invitation(bundle));
                }
            }
            // Each rendezvous queue of a published entry takes its hellos
            // again.
            // A queue that no entry names is one whose publication the last
            // run did not finish, and it ends.
            let named: BTreeSet<[u8; 32]> = client
                .published()?
                .into_iter()
                .flat_map(|entry| {
                    core::iter::once(entry.queue).chain(entry.previous.map(|(queue, _)| queue))
                })
                .collect();
            for state in &stored.rendezvous_queues {
                let id = node
                    .restore_rendezvous_queue(state)
                    .map_err(|_| FfiError::Integrity)?;
                if !named.contains(&id) {
                    let _ = node.end_rendezvous_queue(&id, &mut OsRng);
                }
            }
            // Each notify queue of a group takes its digests again, and one
            // that no group names ends (`NTF-133`).
            let named = client.group_notify_queues()?;
            for state in &stored.notify_queues {
                let id = node
                    .restore_notify_queue(state)
                    .map_err(|_| FfiError::Integrity)?;
                if !named.contains(&id) {
                    let _ = node.end_notify_queue(&id, &mut OsRng);
                    let _ = client.unbind_queue(&id, &mut OsRng);
                }
            }
            // Each record that no relay accepted in an earlier run goes
            // again. The runtime holds it until the circuit is ready.
            let mut running = Bridge::new(commands, contacts);
            client.requeue_waiting()?;
            // Each transfer that an earlier run left open starts again.
            client.requeue_transfers()?;
            // DEV-294: an identity entry that an earlier run lost goes now.
            let _ = client.ensure_identity_entries(&mut OsRng);
            // DEV-013: a record that an earlier run took and did not store.
            let _ = client.replay_sync_inbox(unix_now_ms(), &mut OsRng);
            // DEV-294: a record whose entry came in an earlier run.
            let _ = client.replay_held_pairwise(&mut OsRng);
            // A group record takes a fresh nonce, thus the group work comes
            // back at the start of a run and not at the unlock.
            client.resume_group_work(&mut OsRng)?;
            // GRP-370: a member that a rival re-key put out and that did not
            // ask an admin yet asks now.
            client.ask_lost_groups(unix_now_ms(), &mut OsRng)?;
            // DEV-072: each record that a peer did not acknowledge goes
            // again on the channel of the new run, paced by the clock.
            client.start_sync_resend(&mut OsRng)?;
            running.flush(client, &mut OsRng)?;
            // DEV-286: the first run of a linked device opens the sync
            // channel of its provision. The bundle stays until the channel
            // opens, since a run can end before its accept goes out, and a
            // run that holds the half of that accept makes no second one.
            if let Some(bundle) = client.pending_sync_bundle()? {
                if !*owns_channels && !holds_half {
                    running.accept_device(bundle)?;
                }
            }
            // NET-028: the records of a conversation in another mode go on
            // circuits of that mode.
            for (conversation, contact) in running.contacts() {
                if let Ok(class) = client.privacy_mode(conversation) {
                    node.set_contact_class(&contact, class);
                }
            }
            *bridge = Some(running);
            runtime.spawn(run_client(
                node,
                dial,
                tls,
                runtime_commands,
                runtime_updates,
                Box::new(HandleStore {
                    handle: Arc::downgrade(&self),
                    run,
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
                handle.on_update(run, update);
            }
        });
        if let Some(earlier) = locked(&self.runtime).replace(runtime) {
            earlier.shutdown_background();
        }
        self.fetch_challenges();
        Ok(())
    }

    /// Fetches the challenges of the relays from the pinned ingress, the
    /// carrier of the manifest, on the path of the manifest fetch and on no
    /// session (`ABU-065`, `ABU-066`, `ABU-105`).
    fn fetch_challenges(self: &Arc<Self>) {
        let (spawner, dial, tls) = {
            let inner = locked(&self.inner);
            let Some(spawner) = inner.spawner.clone() else {
                return;
            };
            let Some(guard) = inner.guard.and_then(|guard| {
                inner
                    .relays
                    .iter()
                    .find(|relay| relay.relay_id.as_slice() == guard.as_slice())
                    .cloned()
            }) else {
                return;
            };
            let Ok(address) = <[u8; 4]>::try_from(guard.ipv4.as_slice()) else {
                return;
            };
            let dial = Dial {
                host: guard.host.clone(),
                addr_v4: Some(address),
                addr_v6: None,
                port: guard.port,
            };
            let tls = match &inner.root_ca_path {
                Some(path) => native::tls_config_with_root_file(path),
                None => native::tls_config(),
            };
            let Ok(tls) = tls else {
                return;
            };
            (spawner, dial, tls)
        };
        let me = Arc::downgrade(self);
        spawner.spawn(async move {
            if let Ok(bundle) = native::fetch_challenges(&dial, tls).await {
                if let Some(handle) = me.upgrade() {
                    handle.take_challenges(&bundle);
                }
            }
        });
    }

    /// Takes each challenge of a bundle under the identity key of its relay
    /// (`ABU-068`). The carrier is trusted with nothing.
    fn take_challenges(&self, bundle: &[u8]) {
        let Ok(challenges) = umbra_core::abuse::pow::ChallengeBook::parse_bundle(bundle) else {
            return;
        };
        let now = unix_now();
        let mut inner = locked(&self.inner);
        let was_surge = inner.challenges.is_surge(now);
        for challenge in challenges {
            let identity = inner
                .relays
                .iter()
                .find(|relay| relay.relay_id.as_slice() == challenge.verifier_id.as_slice())
                .and_then(|relay| {
                    umbra_crypto::sign::VerifyingKey::from_bytes(&relay.identity_pk).ok()
                });
            if let Some(identity) = identity {
                let _ = inner.challenges.take(challenge, &identity, now);
            }
        }
        // The view of the connection reads the surge state again.
        inner.challenges_at = now;
        if inner.challenges.is_surge(now) != was_surge {
            inner.circuits_changed = true;
        }
        // The run of the queues and the group task take them too, for a
        // `NEW` or a `GNEW` that pays with a proof of work (`ABU-014`).
        if let Some(running) = &inner.bridge {
            let _ = running.set_challenges(inner.challenges.clone(), now);
        }
        if let Some(sender) = &inner.groups {
            let _ = sender.send(GroupCommand::Challenges {
                book: inner.challenges.clone(),
                now,
            });
        }
        // A transfer task that runs takes the new challenges at once.
        if let Some(sender) = &inner.transfers {
            let _ = sender.send(TransferCommand::Challenges {
                book: inner.challenges.clone(),
                now,
            });
        }
    }

    /// The count of the relays whose challenge this device holds.
    pub fn challenges_held(&self) -> u32 {
        let inner = locked(&self.inner);
        let now = unix_now();
        let count = inner
            .relays
            .iter()
            .filter_map(|relay| <[u8; 32]>::try_from(relay.relay_id.as_slice()).ok())
            .filter(|relay_id| inner.challenges.get(relay_id, now).is_some())
            .count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Ends the network. Each contact stays in the store, and the next
    /// [`Handle::connect`] continues it.
    pub fn disconnect(&self) {
        {
            let mut inner = locked(&self.inner);
            inner.run = inner.run.wrapping_add(1);
            inner.bridge = None;
            inner.transfers = None;
            inner.groups = None;
            inner.group_reading.clear();
            inner.spawner = None;
        }
        if let Some(runtime) = locked(&self.runtime).take() {
            runtime.shutdown_background();
        }
    }

    /// Asks for one invitation. A [`FfiEvent::Invitation`] follows.
    pub fn invite(&self) -> Result<(), FfiError> {
        let inner = locked(&self.inner);
        // DEV-287: a contact of a linked device has no owner in the set.
        if !inner.owns_channels {
            return Err(FfiError::NotFound);
        }
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        Ok(bridge.invite()?)
    }

    /// Asks the contact of `to` to be introduced to the contact of
    /// `about`, by the petnames of this user (Part 6 §6.6.7).
    pub fn request_introduction(
        &self,
        to: Vec<u8>,
        about: Vec<u8>,
        about_name: String,
        to_name: String,
    ) -> Result<(), FfiError> {
        let to = conversation_of(&to)?;
        let about = conversation_of(&about)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.request_introduction(to, about, &about_name, &to_name, unix_now_ms(), &mut OsRng)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        Ok(())
    }

    /// Each request and each offer of a contact that waits for the user.
    pub fn introductions(&self) -> Result<Vec<FfiIntroduction>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .introductions()?
            .into_iter()
            .map(|intro| FfiIntroduction {
                id: intro.id.to_vec(),
                is_offer: intro.is_offer,
                from: intro.from.0.to_vec(),
                name: intro.name,
            })
            .collect())
    }

    /// The user allowed a request: a fresh one-time invitation goes to the
    /// introducer in the grant (`WIR-196`, `WIR-199`).
    pub fn allow_introduction(&self, id: Vec<u8>) -> Result<(), FfiError> {
        let id: [u8; 16] = id.try_into().map_err(|_| FfiError::Malformed)?;
        let mut inner = locked(&self.inner);
        if !inner.owns_channels {
            return Err(FfiError::NotFound);
        }
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        bridge.invite()?;
        inner.pending_grants.push_back(id);
        Ok(())
    }

    /// The user accepted an offer: this device opens the invitation, and
    /// the result is the petname that the introducer uses (`WIR-358`).
    pub fn accept_introduction(&self, id: Vec<u8>) -> Result<String, FfiError> {
        let id: [u8; 16] = id.try_into().map_err(|_| FfiError::Malformed)?;
        let (link, name) = locked(&self.inner).client.offer(&id)?;
        let link = String::from_utf8(link.to_vec()).map_err(|_| FfiError::Malformed)?;
        self.accept(link)?;
        // The accept went, thus a row that stays asks nothing of the user.
        let _ = locked(&self.inner).client.decline_introduction(&id);
        Ok(name)
    }

    /// The user declined a request or an offer.
    pub fn decline_introduction(&self, id: Vec<u8>) -> Result<(), FfiError> {
        let id: [u8; 16] = id.try_into().map_err(|_| FfiError::Malformed)?;
        Ok(locked(&self.inner).client.decline_introduction(&id)?)
    }

    /// Accepts the link of an inviter. The client makes the first fetch of
    /// the blob, which locks the invitation to this device. A
    /// [`FfiEvent::Contact`] follows, or a [`FfiEvent::InvitationGone`]. A
    /// link that names another host or that does not parse is an error.
    pub fn accept(&self, link: String) -> Result<(), FfiError> {
        let inner = locked(&self.inner);
        if !inner.owns_channels {
            return Err(FfiError::NotFound);
        }
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
        let mut inner = locked(&self.inner);
        inner.is_foreground = is_foreground;
        let Inner { client, bridge, .. } = &mut *inner;
        if let Some(running) = bridge.as_mut() {
            let _ = running.set_foreground(is_foreground);
            // The records that a push-wake session held go now.
            if is_foreground {
                let _ = running.flush(client, &mut OsRng);
            }
        }
    }

    /// Starts a push-wake session (Part 3 §3.9, Part 8 §8.4.1): a run that
    /// drains and acknowledges, carries no record on a sync channel, and
    /// ends after `WAKE_SESSION_MAX` unless the app enters the screen
    /// (`NET-097`, `NET-100`).
    pub fn connect_wake(self: Arc<Self>, network: Network) -> Result<(), FfiError> {
        self.clone().connect(network)?;
        if let Some(running) = locked(&self.inner).bridge.as_mut() {
            running.wake()?;
        }
        Ok(())
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

    /// Makes a private group of Part 11 with this device as its owner, and
    /// asks two relays of different operators and blocs for a group queue.
    /// The group sends nothing until both answered (`GRP-191`).
    pub fn create_group(&self, name: String) -> Result<Vec<u8>, FfiError> {
        let mut inner = locked(&self.inner);
        let relays = inner.group_replicas()?;
        let conversation = inner
            .client
            .create_group(&name, relays, unix_now(), &mut OsRng)?;
        inner.pump_groups();
        Ok(conversation.0.to_vec())
    }

    /// Step 1 of §11.9.1: offers a group to a contact on their pairwise
    /// channel. The invitee sees the offer and answers it.
    pub fn offer_group(&self, group: Vec<u8>, to: Vec<u8>) -> Result<(), FfiError> {
        let group = conversation_of(&group)?;
        let to = conversation_of(&to)?;
        let mut inner = locked(&self.inner);
        inner
            .client
            .offer_group(group, to, unix_now_ms(), &mut OsRng)?;
        inner.flush_outgoing();
        Ok(())
    }

    /// Each admission whose snapshot did not verify (`GRP-328`).
    pub fn failed_admissions(&self) -> Result<Vec<FfiGroupOffer>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .failed_admissions()?
            .into_iter()
            .map(|offer| FfiGroupOffer {
                from: offer.from.0.to_vec(),
                group_id: offer.group_id.to_vec(),
                name: offer.name,
                is_added: false,
                is_moving: false,
            })
            .collect())
    }

    /// The user saw a failed admission, and it leaves the store.
    pub fn dismiss_failed_admission(
        &self,
        from: Vec<u8>,
        group_id: Vec<u8>,
    ) -> Result<(), FfiError> {
        let from = conversation_of(&from)?;
        let group_id: [u8; 32] = group_id.try_into().map_err(|_| FfiError::Malformed)?;
        Ok(locked(&self.inner)
            .client
            .dismiss_failed_admission(from, &group_id)?)
    }

    /// The offers of a group that wait for the user (`GRP-170`).
    pub fn group_offers(&self) -> Result<Vec<FfiGroupOffer>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .group_offers()?
            .into_iter()
            .map(|offer| FfiGroupOffer {
                from: offer.from.0.to_vec(),
                group_id: offer.group_id.to_vec(),
                name: offer.name,
                is_added: false,
                is_moving: false,
            })
            .collect())
    }

    /// Step 2 of §11.9.1: the user accepted an offer, thus this device
    /// makes its group keys and asks to come in.
    pub fn accept_group_offer(&self, from: Vec<u8>, group_id: Vec<u8>) -> Result<(), FfiError> {
        let from = conversation_of(&from)?;
        let group_id: [u8; 32] = group_id.try_into().map_err(|_| FfiError::Malformed)?;
        let mut inner = locked(&self.inner);
        let held = inner
            .client
            .group_offers()?
            .into_iter()
            .find(|offer| offer.from == from && offer.group_id == group_id)
            .ok_or(FfiError::NotFound)?;
        inner
            .client
            .accept_group_offer(&held, unix_now_ms(), &mut OsRng)?;
        inner.flush_outgoing();
        Ok(())
    }

    /// The contacts that asked to come into a group of this device
    /// (`GRP-310`).
    pub fn group_joiners(&self) -> Result<Vec<FfiGroupOffer>, FfiError> {
        let inner = locked(&self.inner);
        let is_moving = |from: crate::ConversationId, group_id: [u8; 32]| {
            inner.transfer_tags.values().any(|work| {
                matches!(work, TransferWork::Snapshot { from: held, group_id: of, .. }
                    if *held == from && *of == group_id)
            })
        };
        Ok(inner
            .client
            .group_joiners()?
            .into_iter()
            .map(|joiner| FfiGroupOffer {
                from: joiner.from.0.to_vec(),
                group_id: joiner.group_id.to_vec(),
                name: String::new(),
                is_added: joiner.is_added,
                is_moving: is_moving(joiner.from, joiner.group_id),
            })
            .collect())
    }

    /// Steps 3 and 4 of §11.9.1: the admin adds the joiner, posts the add
    /// to each replica, and puts the roster snapshot on the chunk path.
    /// The admit follows the upload of that snapshot.
    pub fn admit_joiner(&self, from: Vec<u8>, group_id: Vec<u8>) -> Result<(), FfiError> {
        let from = conversation_of(&from)?;
        let group_id: [u8; 32] = group_id.try_into().map_err(|_| FfiError::Malformed)?;
        let mut inner = locked(&self.inner);
        let joiner = crate::client::GroupJoiner {
            from,
            group_id,
            is_added: false,
        };
        let admission = inner
            .client
            .add_joiner(&joiner, unix_now_ms(), &mut OsRng)?;
        inner.pump_groups();
        let tag = inner.next_tag(TransferWork::Snapshot {
            from,
            group_id,
            index: admission.index,
        });
        inner.send_transfer(TransferCommand::Upload {
            tag,
            plain: Zeroizing::new(admission.snapshot),
            // A snapshot is no media of the user (Part 12 §12.3).
            shape: Shape::default(),
        });
        Ok(())
    }

    /// Whether a conversation names a group.
    pub fn is_group(&self, conversation: Vec<u8>) -> Result<bool, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.is_group(conversation)?)
    }

    /// What a view shows of a group.
    pub fn group_info(&self, conversation: Vec<u8>) -> Result<FfiGroupInfo, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let inner = locked(&self.inner);
        let info = inner.client.group_info(conversation)?;
        let owner_needed = inner.client.owner_needed(conversation, unix_now_ms())?;
        let (is_returning, needs_invitation) = inner.client.return_state(conversation)?;
        Ok(FfiGroupInfo {
            owner_needed,
            is_returning,
            needs_invitation,
            is_lapsed: info.is_lapsed,
            is_closed: info.is_closed,
            group_id: info.group_id.to_vec(),
            own_index: info.own_index,
            members: info.members,
            epoch: info.epoch,
            is_ready: info.is_ready,
            is_member: info.is_member,
            is_unreachable: info.is_unreachable,
            is_clock_suspect: info.is_clock_suspect,
        })
    }

    /// The active members of a group in index order.
    pub fn group_members(&self, conversation: Vec<u8>) -> Result<Vec<FfiGroupMember>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner)
            .client
            .group_members(conversation)?
            .into_iter()
            .map(|member| FfiGroupMember {
                index: member.index,
                role: match member.role {
                    umbra_wire::group::control::Role::Observer => FfiRole::Observer,
                    umbra_wire::group::control::Role::Member => FfiRole::Member,
                    umbra_wire::group::control::Role::Moderator => FfiRole::Moderator,
                    umbra_wire::group::control::Role::Admin => FfiRole::Admin,
                    umbra_wire::group::control::Role::Owner => FfiRole::Owner,
                },
                is_self: member.is_self,
                contact: member.contact.map(|held| held.0.to_vec()),
            })
            .collect())
    }

    /// Gives a member a role, or takes it back. A rise to `admin` hands
    /// over the owner credentials, and a fall below it draws new ones.
    pub fn set_group_role(
        &self,
        conversation: Vec<u8>,
        index: u16,
        role: FfiRole,
    ) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let role = match role {
            FfiRole::Observer => umbra_wire::group::control::Role::Observer,
            FfiRole::Member => umbra_wire::group::control::Role::Member,
            FfiRole::Moderator => umbra_wire::group::control::Role::Moderator,
            FfiRole::Admin => umbra_wire::group::control::Role::Admin,
            FfiRole::Owner => umbra_wire::group::control::Role::Owner,
        };
        let mut inner = locked(&self.inner);
        inner
            .client
            .set_group_role(conversation, index, role, unix_now_ms(), &mut OsRng)?;
        inner.pump_groups();
        Ok(())
    }

    /// Removes a member and rotates the epoch in the same action
    /// (`GRP-264`), thus the member it removes reads no later record.
    pub fn remove_from_group(&self, conversation: Vec<u8>, index: u16) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        inner
            .client
            .remove_from_group(conversation, index, unix_now_ms(), &mut OsRng)?;
        inner.pump_groups();
        Ok(())
    }

    /// Leaves a group (`GRP-067`). The group keeps each message this
    /// device already sent.
    pub fn leave_group(&self, conversation: Vec<u8>) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        inner
            .client
            .leave_group(conversation, unix_now_ms(), &mut OsRng)?;
        inner.pump_groups();
        Ok(())
    }

    /// Gives a contact a name on this device. No peer and no relay learns
    /// it. An empty name takes the name away.
    pub fn set_contact_name(&self, conversation: Vec<u8>, name: String) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        inner
            .client
            .set_contact_name(conversation, &name, &mut OsRng)?;
        // DEV-197: the name goes to each device of the set.
        let Inner { client, bridge, .. } = &mut *inner;
        if let Some(running) = bridge.as_mut() {
            running.flush(client, &mut OsRng)?;
        }
        Ok(())
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

    /// Sends the file of a message of this device again, as a new message:
    /// a new upload under new credentials (Part 12 `ATT-054`).
    pub fn resend_file(&self, message: Arc<MsgHandle>) -> Result<Arc<MsgHandle>, FfiError> {
        let mut inner = locked(&self.inner);
        let again = inner
            .client
            .resend_file(&message.0, unix_now_ms(), &mut OsRng)?;
        inner.pump_transfers();
        drop(inner);
        self.changed.notify_all();
        Ok(Arc::new(MsgHandle(again)))
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
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
        Ok(Arc::new(MsgHandle(message)))
    }

    /// Whether a relay named the queue of the contact of a conversation full
    /// (Part 14 §14.9.2). Its records stay queued.
    pub fn queue_full(&self, conversation: Vec<u8>) -> Result<bool, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.queue_full(conversation))
    }

    /// The key-change notice that waits in a conversation, or none. While
    /// one waits the conversation takes no message (`IDN-025`).
    pub fn key_change(&self, conversation: Vec<u8>) -> Result<Option<FfiKeyChange>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let pending = locked(&self.inner).client.key_change(conversation)?;
        Ok(pending.map(|pending| FfiKeyChange {
            new_safety_number: pending.new_safety_number,
            at_ms: pending.at_ms,
        }))
    }

    /// Accepts the new key of one contact (`IDN-062`, `IDN-092`). The node
    /// that runs takes it too, thus its next handshake binds it.
    pub fn accept_key_change(&self, conversation: Vec<u8>) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        let (contact, key) = client.accept_key_change(conversation, &mut OsRng)?;
        if let Some(running) = bridge {
            running.peer_key(contact, key)?;
        }
        drop(inner);
        self.changed.notify_all();
        Ok(())
    }

    /// Resets the identity (Part 7 §7.7.1): a new identity root, a
    /// key-change notice to each contact at its own delay, a new device
    /// roster, and the re-key of each group. The network runs again under
    /// the new root. A set of more than one device takes none.
    pub fn reset_identity(self: Arc<Self>) -> Result<ResetCounts, FfiError> {
        let mut inner = locked(&self.inner);
        let summary = inner.client.reset_identity(unix_now_ms(), &mut OsRng)?;
        // DEV-263: the re-key of each group goes to the run at once.
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
        Ok(ResetCounts {
            contacts: summary.contacts,
            groups: summary.groups,
        })
    }

    /// Sends a failed message again, at the action of the user (`IMP-075`).
    pub fn send_again(&self, message: Arc<MsgHandle>) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.send_again(&message.0, unix_now_ms(), &mut OsRng)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
        Ok(())
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

    /// The time of the last backup of this device, in Unix seconds, or none
    /// (Part 4 §4.7.2).
    pub fn last_backup_at(&self) -> Option<u64> {
        locked(&self.inner).client.last_backup_at().ok().flatten()
    }

    /// Starts a restore of Part 4 §4.7.2 from the recovery code in
    /// `digits`, over the network of this handle: the root of the current
    /// week and then of each earlier week until one opens (`IDN-101`,
    /// `IDN-116`), and each object that it names. `restore_status` shows
    /// the progress. The KDF of the code runs in this call.
    pub fn restore_backup(&self, digits: Vec<u16>) -> Result<(), FfiError> {
        use umbra_core::identity::recovery::{from_digits, DigitsType, RecoveryCode};
        let text = Zeroizing::new(String::from_utf16_lossy(&Zeroizing::new(digits)));
        // IDN-151, IDN-154: the check and the type come before the KDF.
        let code = from_digits(&text, DigitsType::Code).map_err(|_| FfiError::Malformed)?;
        let key = RecoveryCode::from_bytes(&code)
            .and_then(|code| code.backup_root_key())
            .map_err(|error| FfiError::from(Error::from(error)))?;
        self.start_restore(key)
    }

    /// Starts a restore from `C_user` and shares of `C_social` that the
    /// holders read from their screens (Part 4 §4.7.3). The shares join
    /// before the KDF (`IDN-191`).
    pub fn restore_backup_with_shares(
        &self,
        user: Vec<u16>,
        shares: Vec<Vec<u16>>,
    ) -> Result<(), FfiError> {
        use umbra_core::identity::recovery::{from_digits, join_social, DigitsType, RecoveryCode};
        let text = Zeroizing::new(String::from_utf16_lossy(&Zeroizing::new(user)));
        let user = from_digits(&text, DigitsType::User).map_err(|_| FfiError::Malformed)?;
        let mut held = Vec::with_capacity(shares.len());
        for share in shares {
            let text = Zeroizing::new(String::from_utf16_lossy(&Zeroizing::new(share)));
            let bytes = from_digits(&text, DigitsType::Share).map_err(|_| FfiError::Malformed)?;
            held.push(<[u8; 17]>::try_from(bytes.as_slice()).map_err(|_| FfiError::Malformed)?);
        }
        let social = join_social(&held).map_err(|error| FfiError::from(Error::from(error)))?;
        let user: [u8; 16] = user
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Malformed)?;
        let key = RecoveryCode::new(umbra_crypto::secret::Secret::new(user), social)
            .backup_root_key()
            .map_err(|error| FfiError::from(Error::from(error)))?;
        self.start_restore(key)
    }

    /// Where the restore stands.
    pub fn restore_status(&self) -> RestoreStatus {
        locked(&self.inner)
            .restore
            .as_ref()
            .map_or(RestoreStatus::Idle, |job| job.status)
    }

    /// The rows of a restore that is ready, for [`init_restored`]. The
    /// restore of this handle ends.
    pub fn take_restored(&self) -> Result<Arc<Restored>, FfiError> {
        let mut inner = locked(&self.inner);
        let restored = inner
            .restore
            .as_mut()
            .and_then(|job| job.restored.take())
            .ok_or(FfiError::NotFound)?;
        inner.restore = None;
        Ok(Arc::new(Restored(Mutex::new(Some(restored)))))
    }

    /// Renders the root seed into a sink of the platform, as the 87 digits
    /// of `RecoveryDigits` of type `0x0004` (Part 4 `IDN-003`). The platform
    /// overwrites its buffer when the view ends (`IMP-037`).
    pub fn root_seed(&self, sink: Arc<dyn TextSink>) -> Result<(), FfiError> {
        let mut sink = ForeignSink(sink);
        Ok(locked(&self.inner).client.render_root_seed(&mut sink)?)
    }

    /// Renders the recovery code into a sink of the platform, as the 87
    /// digits of Part 4 §4.7.7 in groups of five (`IDN-149`). The platform
    /// overwrites its buffer when the view ends (`IMP-037`).
    pub fn recovery_code(&self, sink: Arc<dyn TextSink>) -> Result<(), FfiError> {
        let mut sink = ForeignSink(sink);
        Ok(locked(&self.inner)
            .client
            .render_recovery_code(&mut sink, &mut OsRng)?)
    }

    /// Splits the social half into one share for each holder, `threshold`
    /// of them for a recovery, and sends each on its pairwise channel
    /// (Part 4 §4.7.3).
    pub fn split_social(&self, holders: Vec<Vec<u8>>, threshold: u8) -> Result<(), FfiError> {
        let holders = holders
            .iter()
            .map(|holder| conversation_of(holder))
            .collect::<Result<Vec<_>, _>>()?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.split_social(&holders, threshold, unix_now_ms(), &mut OsRng)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        drop(inner);
        self.changed.notify_all();
        Ok(())
    }

    /// The holders of the current split of this user.
    pub fn shares_given(&self) -> Result<Vec<FfiGivenShare>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .shares_given()?
            .into_iter()
            .map(|share| FfiGivenShare {
                conversation: share.conversation.0.to_vec(),
                index: share.index,
                threshold: share.threshold,
                count: share.count,
            })
            .collect())
    }

    /// The share that a contact gave to this user, or none.
    pub fn held_share(&self, conversation: Vec<u8>) -> Result<Option<FfiHeldShare>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner)
            .client
            .held_share(conversation)?
            .map(|share| FfiHeldShare {
                threshold: share.threshold,
                count: share.count,
                index: share.index,
                at_ms: share.at_ms,
            }))
    }

    /// Writes the share that a contact gave to this user as 51 digits of
    /// Part 4 §4.7.7, for its holder to read to that contact.
    pub fn held_share_digits(
        &self,
        conversation: Vec<u8>,
        sink: Arc<dyn TextSink>,
    ) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut sink = ForeignSink(sink);
        Ok(locked(&self.inner)
            .client
            .render_held_share(conversation, &mut sink)?)
    }

    /// Writes the user half of the recovery code as 49 digits of Part 4
    /// §4.7.7.
    pub fn user_half(&self, sink: Arc<dyn TextSink>) -> Result<(), FfiError> {
        let mut sink = ForeignSink(sink);
        Ok(locked(&self.inner)
            .client
            .render_user_half(&mut sink, &mut OsRng)?)
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

    /// Opens the file of a message for a media player of the platform,
    /// which reads it in ranges (`IMP-166`). The source reads nothing after
    /// a lock, and its copy is zero bytes after [`MediaSource::release`] or
    /// its drop.
    pub fn open_media(
        self: Arc<Self>,
        message: Arc<MsgHandle>,
    ) -> Result<Arc<MediaSource>, FfiError> {
        let bytes = locked(&self.inner).client.file_bytes(&message.0)?;
        Ok(Arc::new(MediaSource {
            handle: Arc::downgrade(&self),
            bytes: Mutex::new(Some(bytes)),
        }))
    }

    /// Gives the preview of the file of a message to a decoder of the
    /// platform (`WIR-533`, `IMP-166`). A file with no preview is
    /// `NotFound`.
    pub fn msg_preview(
        &self,
        message: Arc<MsgHandle>,
        sink: Arc<dyn FileSink>,
    ) -> Result<(), FfiError> {
        let preview = locked(&self.inner)
            .client
            .file_extras(&message.0)?
            .preview
            .ok_or(FfiError::NotFound)?;
        sink.put(preview);
        Ok(())
    }

    /// The largest size of a received file whose download starts at once,
    /// in bytes (`IMP-167`). Zero means off, and `u64::MAX` means each file.
    pub fn auto_download_limit(&self) -> Result<u64, FfiError> {
        Ok(locked(&self.inner).client.auto_download_limit()?)
    }

    /// Sets the automatic download limit of this device.
    pub fn set_auto_download_limit(&self, bytes: u64) -> Result<(), FfiError> {
        Ok(locked(&self.inner)
            .client
            .set_auto_download_limit(bytes, &mut OsRng)?)
    }

    /// Whether the automatic download waits for a network with no cost by
    /// the byte (`IMP-168`).
    pub fn auto_download_unmetered_only(&self) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.unmetered_only()?)
    }

    /// Limits the automatic download to a network with no cost by the
    /// byte, or takes that limit away.
    pub fn set_auto_download_unmetered_only(&self, is_on: bool) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner.client.set_unmetered_only(is_on, &mut OsRng)?;
        // A file that waited for this network may start now.
        let is_metered = inner.client.is_metered();
        inner.client.set_metered(is_metered, &mut OsRng)?;
        inner.pump_transfers();
        drop(inner);
        self.changed.notify_all();
        Ok(())
    }

    /// The platform says whether the network of the device costs by the
    /// byte. On a network with no such cost the files that waited for it
    /// start (`IMP-168`).
    pub fn set_metered(&self, is_metered: bool) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        if inner.client.set_metered(is_metered, &mut OsRng)? > 0 {
            inner.pump_transfers();
            drop(inner);
            self.changed.notify_all();
        }
        Ok(())
    }

    /// Writes the file of a message to a place that the user named, as
    /// the save of one file (`IMP-045`). On Android `path` names an open
    /// descriptor of this process, `/proc/self/fd/<n>`, that the platform
    /// got for a document that the user created.
    pub fn save_file(&self, message: Arc<MsgHandle>, path: String) -> Result<(), FfiError> {
        let bytes = locked(&self.inner).client.file_bytes(&message.0)?;
        std::fs::write(&path, &*bytes).map_err(|_| FfiError::NotFound)
    }

    /// The direction, the delivery state, and the send time of a message.
    pub fn msg_info(&self, message: Arc<MsgHandle>) -> Result<MsgInfo, FfiError> {
        let inner = locked(&self.inner);
        let info = inner.client.info(&message.0)?;
        let extras = match info.file {
            Some(_) => inner.client.file_extras(&message.0)?,
            None => crate::client::FileExtras::default(),
        };
        let (done, total) = inner
            .file_progress
            .get(&message.0)
            .copied()
            .unwrap_or((0, 0));
        drop(inner);
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
                name: extras.name,
                size: file.size,
                done,
                total,
                has_preview: extras.preview.is_some(),
            }),
            timer: info.timer,
            expires_at: info.expires_at,
            poll: info.poll,
            mentions_me: info.mentions_me,
            recovered: info.recovered,
            forward_depth: info.forward_depth,
            thread: info.thread.map(|root| Arc::new(MsgHandle(root))),
            moderation: info.moderation,
            moderator_role: info.moderator_role,
            sender: info.sender,
            failure: info.failure.map_or(0, |cause| cause as u8),
        })
    }

    /// Hides (1), removes (2), or puts back (3) one message of a group, in a
    /// moderation epoch that this member signs (Part 11 §11.9.6).
    pub fn moderate(&self, message: Arc<MsgHandle>, action: u8) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner
            .client
            .moderate(&message.0, action, unix_now_ms(), &mut OsRng)?;
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
        Ok(())
    }

    /// The changes of the roster of a group that this device applied.
    pub fn roster_notes(&self, conversation: Vec<u8>) -> Result<Vec<FfiRosterNote>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let notes = locked(&self.inner).client.roster_notes(conversation)?;
        Ok(notes
            .into_iter()
            .map(|note| FfiRosterNote {
                at_ms: note.at_ms,
                kind: note.kind,
                index: note.index,
                role: note.role,
            })
            .collect())
    }

    /// The moderation epochs that this device applied in a conversation.
    pub fn moderation_notes(&self, conversation: Vec<u8>) -> Result<Vec<FfiModNote>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let notes = locked(&self.inner).client.moderation_notes(conversation)?;
        Ok(notes
            .into_iter()
            .map(|note| FfiModNote {
                at_ms: note.at_ms,
                actor_role: note.actor_role,
                hidden: note.hidden,
                removed: note.removed,
                shown: note.shown,
            })
            .collect())
    }

    /// The poll of a message with the count that this device holds.
    pub fn poll_view(&self, message: Arc<MsgHandle>) -> Result<FfiPoll, FfiError> {
        let view = locked(&self.inner)
            .client
            .poll_view(&message.0, unix_now())?;
        Ok(FfiPoll {
            question: view.question,
            options: view.options,
            multiple: view.multiple,
            hidden: view.hidden,
            closes_at: view.closes_at,
            closed: view.closed,
            counts: view.counts,
            voters: view.voters,
            mine: view.mine,
        })
    }

    /// Sends a poll. `open_seconds` is its period after the receive time of
    /// each party, or 0 for no close. A group above `POLL_GROUP_MAX`
    /// members takes none (`GRP-149`).
    pub fn send_poll(
        &self,
        conversation: Vec<u8>,
        question: String,
        options: Vec<String>,
        multiple: bool,
        hidden: bool,
        open_seconds: u32,
    ) -> Result<Arc<MsgHandle>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let options: Vec<&str> = options.iter().map(String::as_str).collect();
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        let message = client.send_poll(
            conversation,
            &question,
            &options,
            multiple,
            hidden,
            open_seconds,
            unix_now_ms(),
            &mut OsRng,
        )?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
        Ok(Arc::new(MsgHandle(message)))
    }

    /// Votes on a poll, or changes the vote of the user.
    pub fn vote(&self, poll: Arc<MsgHandle>, choices: Vec<u8>) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.vote(&poll.0, &choices, unix_now_ms(), &mut OsRng)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
        Ok(())
    }

    /// Whether this device sends typing records and shows those of its
    /// contacts. Off by default (Part 6 `WIR-077`).
    pub fn typing_enabled(&self) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.typing_enabled()?)
    }

    /// The draft of a conversation, as UTF-16 code units (Part 7 §7.5.3).
    pub fn draft(&self, conversation: Vec<u8>) -> Result<Vec<u16>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let held = locked(&self.inner).client.draft(conversation)?;
        Ok(held.to_vec())
    }

    /// Keeps the draft of a conversation, and an empty one erases it. The
    /// other devices of the set take it while the draft sync is on.
    pub fn set_draft(&self, conversation: Vec<u8>, code_units: Vec<u16>) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let code_units = Zeroizing::new(code_units);
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.set_draft(conversation, &code_units, &mut OsRng)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        Ok(())
    }

    /// The period of the history on this device, in seconds. The largest
    /// value keeps each message (Part 7 §7.5.2).
    pub fn history_age(&self) -> Result<u64, FfiError> {
        Ok(locked(&self.inner).client.history_age()?)
    }

    /// Sets the period of the history, at one day or more (`DEV-020`).
    pub fn set_history_age(&self, seconds: u64) -> Result<(), FfiError> {
        Ok(locked(&self.inner)
            .client
            .set_history_age(seconds, &mut OsRng)?)
    }

    /// The privacy mode of a conversation: 0 Fast, 1 Balanced, 2 Private
    /// (Part 3 §3.9).
    pub fn privacy_mode(&self, conversation: Vec<u8>) -> Result<u8, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.privacy_mode(conversation)? as u8)
    }

    /// Sets the privacy mode of a conversation. The run takes it at once.
    pub fn set_privacy_mode(&self, conversation: Vec<u8>, mode: u8) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let class = umbra_core::session::node::DelayClass::from_byte(mode)
            .map_err(|_| FfiError::Malformed)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.set_privacy_mode(conversation, class, &mut OsRng)?;
        if let Some(running) = bridge {
            if let Some(contact) = running.contact_for(&conversation) {
                running.set_class(contact, class)?;
            }
        }
        Ok(())
    }

    /// Whether the drafts go to the other devices of the set.
    pub fn draft_sync(&self) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.draft_sync()?)
    }

    /// Turns the draft sync on or off (Part 7 `DEV-202`).
    pub fn set_draft_sync(&self, is_on: bool) -> Result<(), FfiError> {
        Ok(locked(&self.inner)
            .client
            .set_draft_sync(is_on, &mut OsRng)?)
    }

    /// Turns the typing indicator on or off.
    pub fn set_typing_enabled(&self, is_on: bool) -> Result<(), FfiError> {
        Ok(locked(&self.inner)
            .client
            .set_typing_enabled(is_on, &mut OsRng)?)
    }

    /// The user typed in a conversation, or stopped. A record goes at most
    /// once in `TYPING_INTERVAL` to one peer (`WIR-285`).
    pub fn typing(&self, conversation: Vec<u8>, started: bool) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        if client.typing(conversation, started, unix_now_ms(), &mut OsRng)? {
            if let Some(running) = bridge {
                running.flush(client, &mut OsRng)?;
            }
        }
        Ok(())
    }

    /// Whether this device blocks a screenshot of a conversation. Off by
    /// default (Part 14 `IMP-059`).
    pub fn screenshot_blocked(&self, conversation: Vec<u8>) -> Result<bool, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner)
            .client
            .screenshot_blocked(conversation)?)
    }

    /// Turns the screenshot block of one conversation on or off
    /// (`IMP-058`).
    pub fn set_screenshot_blocked(
        &self,
        conversation: Vec<u8>,
        is_on: bool,
    ) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner)
            .client
            .set_screenshot_blocked(conversation, is_on, &mut OsRng)?)
    }

    /// The notification setting of a conversation: 0 each record, 1 the
    /// mentions of the user, 2 none (Part 7 §7.5.9).
    pub fn alert_setting(&self, conversation: Vec<u8>) -> Result<u8, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.alert_setting(conversation)?)
    }

    /// Sets the notification setting of a conversation, for each device of
    /// the set.
    pub fn set_alert_setting(&self, conversation: Vec<u8>, value: u8) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        client.set_alert_setting(conversation, value, &mut OsRng)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        Ok(())
    }

    /// Whether a message that arrived gives a notification under the
    /// setting of its conversation.
    pub fn should_alert(&self, message: Arc<MsgHandle>) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.should_alert(&message.0)?)
    }

    /// The periods that a conversation timer takes, in seconds (`WIR-201`).
    pub fn timer_values(&self) -> Vec<u32> {
        crate::client::TIMER_VALUES.to_vec()
    }

    /// The timer of a conversation.
    pub fn conversation_timer(&self, conversation: Vec<u8>) -> Result<ConversationTimer, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let setting = locked(&self.inner)
            .client
            .conversation_timer(conversation)?;
        Ok(setting.map_or(
            ConversationTimer {
                seconds: 0,
                set_at_ms: 0,
                by_user: false,
            },
            |setting| ConversationTimer {
                seconds: setting.seconds,
                set_at_ms: setting.set_at_ms,
                by_user: setting.by_user,
            },
        ))
    }

    /// Sets the timer of a conversation, and the record of the change goes
    /// to the other party or to the group (`DEV-205`). In a group a member
    /// below admin sets no timer (`DEV-248`).
    pub fn set_conversation_timer(
        &self,
        conversation: Vec<u8>,
        seconds: u32,
    ) -> Result<Arc<MsgHandle>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        let message =
            client.set_conversation_timer(conversation, seconds, unix_now_ms(), &mut OsRng)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
        Ok(Arc::new(MsgHandle(message)))
    }

    /// Asks for the file of a received message whose download failed, or
    /// that waits for a tap above the automatic download limit (`IMP-167`).
    /// A [`FfiEvent::File`] follows its end.
    pub fn fetch_file(&self, message: Arc<MsgHandle>) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner.client.fetch_file(&message.0, &mut OsRng)?;
        inner.pump_transfers();
        inner.pump_groups();
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

    /// Forwards the text of a message to a conversation, as a new message
    /// of this device (`WIR-177`). A text at `FORWARD_MAX_DEPTH` is
    /// `TooLong`.
    pub fn forward(
        &self,
        message: Arc<MsgHandle>,
        to: Vec<u8>,
    ) -> Result<Arc<MsgHandle>, FfiError> {
        let to = conversation_of(&to)?;
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        let sent = client.forward(&message.0, to, unix_now_ms(), &mut OsRng)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        inner.pump_groups();
        drop(inner);
        self.changed.notify_all();
        Ok(Arc::new(MsgHandle(sent)))
    }

    /// Removes a message, or the placeholder of a deleted one, from the
    /// devices of this user (`DEV-126`). The other party keeps its copy.
    pub fn delete_for_me(&self, message: Arc<MsgHandle>) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        let Inner { client, bridge, .. } = &mut *inner;
        // A set of one device has no sync channel, and nothing leaves. A
        // record that does not parse, as a placeholder, goes here alone.
        let _ = client.publish_own_deletion(&message.0, unix_now_ms(), &mut OsRng);
        client.delete_for_me(&message.0)?;
        if let Some(running) = bridge {
            running.flush(client, &mut OsRng)?;
        }
        // ATT-161: the chunks of a file that this device uploaded go too.
        inner.pump_transfers();
        inner.pump_groups();
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
        inner.pump_groups();
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
        inner.client.unlock(&passphrase, unix_now())?;
        harden(&inner.client);
        Ok(())
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

    /// The clock of the platform, for the auto-lock, and for the fetch of
    /// the challenges of the relays at each `POW_CHALLENGE_PERIOD`
    /// (`ABU-057`, `ABU-106`).
    pub fn tick(self: Arc<Self>) {
        let mut inner = locked(&self.inner);
        let now = unix_now();
        inner.client.tick(now);
        inner.stop_network_if_locked();
        inner.pump_link(now);
        inner.pump_sync_resend(now);
        // DEV-210: a timed message goes at its deadline, on each device.
        let _ = inner.client.sweep_timed(now);
        // Part 7 §7.5.2: the history older than its period leaves, once a
        // day at most.
        let _ = inner.client.sweep_history(now, &mut OsRng);
        // DEV-031: the floor of the insertion stamp stays across a run that
        // the platform ends with no lock.
        let _ = inner.client.keep_stamp(&mut OsRng);
        // IDN-162: one table of the daily scan; a difference raises an
        // IntegrityFault event.
        let _ = inner.client.audit_step(now);
        // IDN-063: each key-change notice of a reset goes at its delay.
        if inner.client.send_due_notices(now, &mut OsRng).unwrap_or(0) > 0 {
            let Inner { client, bridge, .. } = &mut *inner;
            if let Some(running) = bridge {
                let _ = running.flush(client, &mut OsRng);
            }
        }
        let is_due = inner.bridge.is_some()
            && now.saturating_sub(inner.challenges_at) >= umbra_core::abuse::POW_CHALLENGE_PERIOD;
        drop(inner);
        if is_due {
            self.fetch_challenges();
        }
        self.changed.notify_all();
    }
}

impl Handle {
    /// Starts the search for the root of a backup under `key`.
    fn start_restore(
        &self,
        key: umbra_core::identity::recovery::BackupRootKey,
    ) -> Result<(), FfiError> {
        use umbra_core::session::dead::week_of;
        let mut inner = locked(&self.inner);
        let epoch = inner.client.directory_epoch()?;
        if inner.bridge.is_none() || epoch == 0 {
            return Err(FfiError::Offline);
        }
        let week = week_of(epoch);
        inner.restore = Some(RestoreJob {
            key,
            first_week: week,
            week,
            objects: Vec::new(),
            status: RestoreStatus::Searching { weeks_back: 0 },
            restored: None,
        });
        inner.ask_restore_root(week);
        Ok(())
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
