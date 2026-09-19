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
    identity::invitation::{Fragment, FRAGMENT_LEN},
    session::node::{ClientNode, ContactId, StateChange},
    store::wrap::{Cost, SecureElement, WrapHeader, M_KIB_FLOOR, T_FLOOR},
};
use umbra_crypto::handshake::nk::RelayStatic;
use umbra_transport::{native, Dial};
use zeroize::Zeroizing;

use crate::{
    bridge::{Bridge, NetEvent},
    client::Client,
    draft::Draft,
    runtime::{run_client, OsRng, Persist, Update},
    sqlite::SqliteBackend,
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

/// One relay of the path of the client.
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
}

/// The network of the client: the guard, the middle relay, and the queue
/// relay. The relay directory of Part 10 replaces this record later.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Network {
    /// The three relays of the path, the guard first.
    pub relays: Vec<RelayEndpoint>,
    /// A PEM file of the one authority that the client trusts, for a test
    /// network. With no file the client trusts the web roots.
    pub root_ca_path: Option<String>,
    /// The invitation host of Part 4 §4.3.1, which each link names.
    pub invitation_host: String,
}

/// The first line of a network descriptor.
const DESCRIPTOR_HEADER: &str = "umbra-network 1";

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
/// umbra-network 1
/// relay <host> <IPv4 address> <port> <static key, hex> <relay id, hex>
/// relay ...                            # the middle relay
/// relay ...                            # the queue relay
/// invite <invitation host>
/// ```
///
/// The three `relay` lines come from `umbra-relay descriptor`, the guard
/// first. A line that starts with `#` and an empty line carry nothing.
/// `root_ca_path` is the authority of a test network, or none for the web
/// roots.
#[uniffi::export]
pub fn parse_network(text: String, root_ca_path: Option<String>) -> Result<Network, FfiError> {
    let mut lines = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty());
    if lines.next() != Some(DESCRIPTOR_HEADER) {
        return Err(FfiError::Malformed);
    }
    let mut relays = Vec::new();
    let mut invitation_host = None;
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["relay", host, address, port, static_key, relay_id] => {
                let address: std::net::Ipv4Addr =
                    address.parse().map_err(|_| FfiError::Malformed)?;
                let key = |text: &str| hex_bytes(text).filter(|bytes| bytes.len() == 32);
                relays.push(RelayEndpoint {
                    host: (*host).to_owned(),
                    ipv4: address.octets().to_vec(),
                    port: port.parse().map_err(|_| FfiError::Malformed)?,
                    static_key: key(static_key).ok_or(FfiError::Malformed)?,
                    relay_id: key(relay_id).ok_or(FfiError::Malformed)?,
                });
            }
            ["invite", host] if invitation_host.is_none() => {
                invitation_host = Some((*host).to_owned());
            }
            _ => return Err(FfiError::Malformed),
        }
    }
    if relays.len() != 3 {
        return Err(FfiError::Malformed);
    }
    Ok(Network {
        relays,
        root_ca_path,
        invitation_host: invitation_host.ok_or(FfiError::Malformed)?,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
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
}

/// One event of the stream.
#[derive(uniffi::Enum)]
pub enum FfiEvent {
    /// The circuit is ready.
    Online,
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

    /// Adds a file by its reference on the platform.
    pub fn attach(&self, file_ref: String) -> Result<(), FfiError> {
        locked(&self.0)
            .as_mut()
            .ok_or(FfiError::NotFound)?
            .attach(file_ref);
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
}

impl Inner {
    fn has_event(&self) -> bool {
        self.client.has_event() || !self.net_events.is_empty()
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
                Event::Locked => FfiEvent::Locked,
                Event::IntegrityFault => FfiEvent::IntegrityFault,
            });
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
        inner: Mutex::new(Inner {
            invitation_host: String::new(),
            client,
            bridge: None,
            net_events: VecDeque::new(),
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
struct HandleStore(Weak<Handle>);

impl Persist for HandleStore {
    fn commit(&mut self, changes: Vec<StateChange>, received: &[(ContactId, Vec<u8>)]) -> bool {
        let Some(handle) = self.0.upgrade() else {
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
}

impl Handle {
    /// A task of the runtime gives one update of the network to the client.
    fn on_update(&self, update: Update) {
        let mut inner = locked(&self.inner);
        let Inner {
            client,
            bridge,
            net_events,
            ..
        } = &mut *inner;
        let ended = matches!(update, Update::Offline(_));
        if let Some(running) = bridge {
            // A fault of the store shows in the event stream of the client,
            // and such an update gives no event of the network.
            if let Ok(Some(event)) = running.on_update(client, update, &mut OsRng) {
                net_events.push_back(event);
            }
        } else if let Update::Offline(cause) = update {
            net_events.push_back(NetEvent::Offline(cause));
        }
        if ended {
            *bridge = None;
        }
        drop(inner);
        self.changed.notify_all();
    }
}

#[uniffi::export]
impl Handle {
    /// Starts the network of an unlocked client. A [`FfiEvent::Online`]
    /// follows the build of the circuit. A second call ends the first run.
    pub fn connect(self: Arc<Self>, network: Network) -> Result<(), FfiError> {
        let [guard, middle, queue_relay] = network.relays.as_slice() else {
            return Err(FfiError::Malformed);
        };
        let path = [
            relay_static(guard)?,
            relay_static(middle)?,
            relay_static(queue_relay)?,
        ];
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
            let Inner {
                client,
                bridge,
                net_events,
                ..
            } = &mut *inner;
            // The node continues each contact and each invitation of the
            // earlier runs.
            let mut node = ClientNode::new(path, client.root_identity()?);
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
            running.flush(client, &mut OsRng)?;
            *bridge = Some(running);
            runtime.spawn(run_client(
                node,
                dial,
                tls,
                runtime_commands,
                runtime_updates,
                Box::new(HandleStore(Arc::downgrade(&self))),
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
        locked(&self.inner).bridge = None;
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

    /// The direction, the delivery state, and the send time of a message.
    pub fn msg_info(&self, message: Arc<MsgHandle>) -> Result<MsgInfo, FfiError> {
        let info = locked(&self.inner).client.info(&message.0)?;
        Ok(MsgInfo {
            outgoing: info.outgoing,
            delivery: info.delivery as u8,
            sent_at_ms: info.sent_at_ms,
            stored_at_ms: info.stored_at_ms,
        })
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
