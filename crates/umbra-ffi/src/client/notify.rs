//! The push registrations of this device (Part 8 §8.2): the root of each
//! queue relay, the handle groups of at most `MAX_QUEUES_PER_HANDLE` queues
//! with their `k_tok` and removal secret, the binding of each queue, and the
//! push endpoint that the platform gave. A device in Direct mode binds each
//! queue for the watch of a locked client in its place (§8.4.3).
//!
//! The store keeps what a registration needs across runs: a queue binds
//! once, a group registers once, and a new endpoint registers each group
//! again under its removal secret (`NTF-124`). A group rotates each 7 days
//! and at each change of the contact set, one group in one run
//! (`NTF-007`, `NTF-008`, `NTF-080`, `NTF-081`).
//!
//! A device in Periodic mode holds no handle group. It holds one timer
//! registration of its own token at the NDR, which wakes it on a fixed
//! clock, and it binds its queues for the watch as Direct mode does
//! (`NTF-150` to `NTF-153`).

use umbra_core::notify::ndr::next_removal;
use umbra_core::{
    notify::{binding::Binding, HANDLE_LEN, MAX_QUEUES_PER_HANDLE, ROTATE_INTERVAL, WATCH_HANDLE},
    session::node::stored_contact_queues,
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::{
    aead, hash::sha3_256, hkdf::Hkdf, labels, rand_core::CryptoRng, secret::Secret, sha3::Sha3_256,
};
use umbra_wire::ndr::{encode_token, NdrRequest, TokenCarrier, NDR_REQUEST_LEN, PUSH_TOKEN_MAX};

use zeroize::Zeroizing;

use super::{Client, SETTINGS};
use crate::{ConversationId, Error, Event};

/// The value that the wake table holds in the place of the conversation of
/// a queue that raises no alert (`ABU-029`, `DEV-219`). No conversation has
/// this identifier: an identifier is a keyed hash of its contact.
pub const WAKE_SILENT: [u8; 16] = umbra_core::notify::wakekey::WAKE_SILENT;

/// The root of each queue relay: `relay_id`, `k_ntf_root`, `relay_idx`. A
/// group of the first form took the root of its relay. Each group holds a
/// root of its own now, thus the root of a relay is zero bytes once no row
/// of the first form needs it.
const NOTIFY_RELAY: TableId = TableId(0x19);
/// Each handle group: `handle`, `relay_id`, `k_tok`, the removal secret,
/// the registration state, and the count of its queues.
pub(super) const NOTIFY_GROUP: TableId = TableId(0x1A);
/// Each queue with a binding: `recipient_id`, `handle`, `queue_alias`,
/// whether its `NBIND` left, and its `notifier_id` or zero bytes.
const NOTIFY_QUEUE: TableId = TableId(0x1B);
/// The push token of the platform as the NDR takes it: the carrier byte
/// and its target (`NTF-123`).
pub(super) const PUSH_TOKEN_SETTING: &[u8] = b"push-token";
/// The hash of the contact set at the last check of `NTF-008`.
pub(super) const CONTACT_SET_SETTING: &[u8] = b"push-contact-set";
/// Whether this device binds its queues for the watch of a locked client
/// (Direct mode, `NTF-142`): one byte, 1 for on.
const WATCH_SETTING: &[u8] = b"push-watch";
/// The push token of the timer of Periodic mode, as the NDR takes it
/// (`NTF-150`). A device holds this token or the one of Instant mode, and
/// never both (`NTF-151`).
pub(super) const TIMER_TOKEN_SETTING: &[u8] = b"push-timer-token";
/// The timer registration: its handle, its removal secret, its state, and
/// the time of its last `NTIMER` (`NTF-152`).
const TIMER_SETTING: &[u8] = b"push-timer";
/// The mark that the push path of a store of an earlier build had its one
/// repair (`Client::repair_push_path`): one byte, 1. A new store holds it
/// from its first commit.
pub(super) const PUSH_REPAIRED_SETTING: &[u8] = b"push-repaired";
/// The settings of the push path, which belong to this device alone: no
/// backup and no link carries them (Part 4 `IDN-180`). A copy of the timer
/// on another device would end the timer of this one with its `NUNREG`.
pub(super) const DEVICE_SETTINGS: [&[u8]; 6] = [
    PUSH_TOKEN_SETTING,
    CONTACT_SET_SETTING,
    WATCH_SETTING,
    TIMER_TOKEN_SETTING,
    TIMER_SETTING,
    PUSH_REPAIRED_SETTING,
];
const TIMER_LEN: usize = HANDLE_LEN + 32 + 1 + 8;

const RELAY_LEN: usize = 32 + 32 + 2;
/// A group row of the first form, before the root and the rotation time.
const GROUP_LEN_V1: usize = 16 + 32 + 32 + 32 + 1 + 1 + 1;
const GROUP_LEN: usize = GROUP_LEN_V1 + 32 + 8;
/// A group of pairwise queues.
const PAIRWISE: u8 = 0;
/// A group of notify queues, which holds no pairwise queue (`NTF-091`).
const DIGEST: u8 = 1;
/// A group of one rendezvous queue of Part 9 §9.6, which holds no other
/// queue (`NTF-043`, `NTF-044`).
const RENDEZVOUS: u8 = 2;
/// A queue row of the first form, before the `notifier_id`.
const QUEUE_LEN_V1: usize = 32 + 16 + 16 + 1;
const QUEUE_LEN: usize = QUEUE_LEN_V1 + 32;

/// The NDR does not hold the group.
const UNREGISTERED: u8 = 0;
/// The NDR holds the group under the present endpoint.
const REGISTERED: u8 = 1;
/// The NDR holds the group under an earlier endpoint.
const STALE: u8 = 2;
/// A rotation replaced the group, and its `NUNREG` waits (`NTF-007`).
const RETIRED: u8 = 3;

struct Relay {
    relay_id: [u8; 32],
    root: Secret<32>,
    relay_idx: u16,
}

struct Group {
    handle: [u8; 16],
    relay_id: [u8; 32],
    k_tok: Secret<32>,
    removal: Secret<32>,
    state: u8,
    count: u8,
    class: u8,
    /// `k_ntf_root` of the group, which rotates with the triple
    /// (`NTF-007`). A row of the first form takes the root of its relay.
    root: Option<Secret<32>>,
    /// The time of the last rotation, or 0.
    rotated_at: u64,
}

/// The timer registration of Periodic mode (`NTF-150`).
struct Timer {
    handle: [u8; HANDLE_LEN],
    removal: Secret<32>,
    state: u8,
    /// The time of the last `NTIMER` that the NDR took, or 0.
    registered_at: u64,
}

impl Timer {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            [
                self.handle.as_slice(),
                self.removal.expose(),
                &[self.state],
                &self.registered_at.to_be_bytes(),
            ]
            .concat(),
        )
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != TIMER_LEN {
            return Err(Error::Malformed);
        }

        let mut at = 0;
        let handle = take(bytes, &mut at)?;
        let removal = Secret::new(take(bytes, &mut at)?);
        let [state] = take(bytes, &mut at)?;
        let registered_at = u64::from_be_bytes(take(bytes, &mut at)?);

        Ok(Timer {
            handle,
            removal,
            state,
            registered_at,
        })
    }
}

struct Queue {
    recipient_id: [u8; 32],
    handle: [u8; 16],
    alias: [u8; 16],
    bound: bool,
    /// The `notifier_id` that the relay drew at the last `NKEY` (§8.2.4).
    notifier_id: Option<[u8; 32]>,
}

fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N], Error> {
    let end = at.checked_add(N).ok_or(Error::Malformed)?;
    let out = bytes
        .get(*at..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::Malformed)?;
    *at = end;

    Ok(out)
}

impl Relay {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            [
                self.relay_id.as_slice(),
                self.root.expose(),
                &self.relay_idx.to_be_bytes(),
            ]
            .concat(),
        )
    }

    /// The row of the relay with no root, which no group needs.
    fn without_root(&self) -> Self {
        Relay {
            relay_id: self.relay_id,
            root: Secret::new([0; 32]),
            relay_idx: self.relay_idx,
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RELAY_LEN {
            return Err(Error::Malformed);
        }

        let mut at = 0;

        Ok(Relay {
            relay_id: take(bytes, &mut at)?,
            root: Secret::new(take(bytes, &mut at)?),
            relay_idx: u16::from_be_bytes(take(bytes, &mut at)?),
        })
    }
}

impl Group {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let root = Zeroizing::new(self.root.as_ref().map_or([0u8; 32], |held| *held.expose()));
        Zeroizing::new(
            [
                self.handle.as_slice(),
                &self.relay_id,
                self.k_tok.expose(),
                self.removal.expose(),
                &[self.state, self.count, self.class],
                root.as_slice(),
                &self.rotated_at.to_be_bytes(),
            ]
            .concat(),
        )
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != GROUP_LEN && bytes.len() != GROUP_LEN_V1 {
            return Err(Error::Malformed);
        }

        let mut at = 0;
        let handle = take(bytes, &mut at)?;
        let relay_id = take(bytes, &mut at)?;
        let k_tok = Secret::new(take(bytes, &mut at)?);
        let removal = Secret::new(take(bytes, &mut at)?);
        let [state, count, class] = take(bytes, &mut at)?;
        let (root, rotated_at) = if bytes.len() == GROUP_LEN {
            (
                Some(Secret::new(take(bytes, &mut at)?)),
                u64::from_be_bytes(take(bytes, &mut at)?),
            )
        } else {
            (None, 0)
        };

        Ok(Group {
            handle,
            relay_id,
            k_tok,
            removal,
            state,
            count,
            class,
            root,
            rotated_at,
        })
    }
}

impl Queue {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            [
                self.recipient_id.as_slice(),
                &self.handle,
                &self.alias,
                &[u8::from(self.bound)],
                &self.notifier_id.unwrap_or([0; 32]),
            ]
            .concat(),
        )
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != QUEUE_LEN && bytes.len() != QUEUE_LEN_V1 {
            return Err(Error::Malformed);
        }

        let mut at = 0;
        let recipient_id = take(bytes, &mut at)?;
        let handle = take(bytes, &mut at)?;
        let alias = take(bytes, &mut at)?;
        let [bound] = take(bytes, &mut at)?;
        let notifier_id = if bytes.len() == QUEUE_LEN {
            Some(take::<32>(bytes, &mut at)?).filter(|id| *id != [0; 32])
        } else {
            None
        };

        Ok(Queue {
            recipient_id,
            handle,
            alias,
            bound: bound == 1,
            notifier_id,
        })
    }
}

/// One row under its natural key, with a value that can hold a secret.
type Row = (TableId, Vec<u8>, Zeroizing<Vec<u8>>);

/// One watch of a locked client: the relay of the queue, its
/// `notifier_id`, its notifier secret (`NTF-145`), and whether it runs on
/// a circuit of its own, as the watch of a rendezvous queue does
/// (`NTF-142`).
pub type WatchEntry = ([u8; 32], [u8; 32], Secret<32>, bool);

/// One request that waits for the NDR, with what its answer changes.
pub struct NdrCall {
    /// The handle of the group.
    pub handle: [u8; 16],
    /// Whether the request removes the group (`NUNREG`).
    pub is_removal: bool,
    /// Whether the registration moves the group to the next removal secret
    /// of its chain (`NTF-124`).
    pub advances: bool,
    /// The request.
    pub request: Box<[u8; NDR_REQUEST_LEN]>,
    /// The digest of the push token that a registration carries, or zero
    /// bytes for a removal.
    pub token: [u8; 32],
    /// Whether the call is of the timer of Periodic mode (`NTF-150`).
    pub is_timer: bool,
    /// The time at which the call left.
    pub at: u64,
}

/// A push token as the NDR takes it, or no bytes for none (`NTF-123`).
fn plain_token(token: Option<(TokenCarrier, &str)>) -> Result<Vec<u8>, Error> {
    let Some((carrier, target)) = token else {
        return Ok(Vec::new());
    };

    // NTF-123: a token of the carrier, printable ASCII.
    let mut plain = [0u8; PUSH_TOKEN_MAX];
    let n = encode_token(carrier, target.as_bytes(), &mut plain).map_err(|_| Error::TooLong)?;
    let plain = plain.get(..n).ok_or(Error::Malformed)?.to_vec();
    umbra_wire::ndr::parse_token(&plain).map_err(|_| Error::Malformed)?;
    Ok(plain)
}

/// Each inbound queue of a contact row: the contact, and each queue that
/// its stored channel reads (`NTF-135`). A rotation keeps the contact under
/// its first queue, thus the contact alone misses the queues after it.
pub(super) fn contact_queues(plain: &[u8]) -> Vec<[u8; 32]> {
    let Some((contact, state)) = plain.split_first_chunk::<32>() else {
        return Vec::new();
    };

    let mut queues = vec![*contact];
    for queue in stored_contact_queues(state).unwrap_or_default() {
        if !queues.contains(&queue) {
            queues.push(queue);
        }
    }
    queues
}

fn random<const N: usize, R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The push token that the platform gave, as the NDR takes it, if any.
    pub fn push_token(&self) -> Result<Option<Vec<u8>>, Error> {
        let open = self.open_ref()?;
        let row = open.store.row_id(SETTINGS, PUSH_TOKEN_SETTING);
        Ok(open
            .store
            .get(SETTINGS, &row)?
            .filter(|token| !token.is_empty()))
    }

    /// Takes a new push token of a carrier, or none when the platform took
    /// it back. Each group that the NDR holds registers again under the new
    /// one, or leaves with none. A token ends the timer of Periodic mode
    /// (`NTF-151`).
    pub fn set_push_token<R: CryptoRng + ?Sized>(
        &mut self,
        token: Option<(TokenCarrier, &str)>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let plain = plain_token(token)?;
        if !plain.is_empty() {
            self.set_timer_token(None, rng)?;
        }
        let held = self.push_token()?.unwrap_or_default();
        if held == plain {
            return Ok(());
        }

        // NTF-143: a binding names the handle of its group under a token,
        // and `WATCH_HANDLE` with none. Thus each queue binds again when a
        // token comes or leaves, and the caller binds them at once.
        let moves_bindings = held.is_empty() != plain.is_empty();
        let mut rows = vec![(SETTINGS, PUSH_TOKEN_SETTING.to_vec(), Zeroizing::new(plain))];
        for mut group in self.notify_groups()? {
            if group.state == REGISTERED {
                group.state = STALE;
                rows.push((NOTIFY_GROUP, group.handle.to_vec(), group.encode()));
            }
        }
        if moves_bindings {
            rows.extend(self.unbound_queues()?);
        }

        self.put_rows(&rows, rng)
    }

    /// The row of each queue with no binding: its handle changed, thus it
    /// binds again under a new `NKEY`.
    fn unbound_queues(&self) -> Result<Vec<Row>, Error> {
        let mut rows = Vec::new();
        for (_, bytes) in self.open_ref()?.store.list(NOTIFY_QUEUE, None)? {
            let Ok(mut queue) = Queue::parse(&bytes) else {
                continue;
            };

            queue.bound = false;
            queue.notifier_id = None;
            rows.push((NOTIFY_QUEUE, queue.recipient_id.to_vec(), queue.encode()));
        }

        Ok(rows)
    }

    /// The push token of the timer of Periodic mode, as the NDR takes it,
    /// if any (`NTF-150`).
    pub fn timer_token(&self) -> Result<Option<Vec<u8>>, Error> {
        let open = self.open_ref()?;
        let row = open.store.row_id(SETTINGS, TIMER_TOKEN_SETTING);
        Ok(open
            .store
            .get(SETTINGS, &row)?
            .filter(|token| !token.is_empty()))
    }

    /// Whether the NDR holds the timer under the present token.
    pub fn timer_registered(&self) -> Result<bool, Error> {
        Ok(self.timer_token()?.is_some()
            && self.timer()?.is_some_and(|timer| timer.state == REGISTERED))
    }

    /// The timer registration, if one is held or waits.
    fn timer(&self) -> Result<Option<Timer>, Error> {
        let open = self.open_ref()?;
        let row = open.store.row_id(SETTINGS, TIMER_SETTING);
        Ok(open
            .store
            .get(SETTINGS, &row)?
            .and_then(|bytes| Timer::parse(&bytes).ok()))
    }

    /// Takes the push token of the timer of Periodic mode, or none when the
    /// mode left. The NDR holds the timer under a handle of its own, which
    /// names no queue, and a token of the timer ends each handle group
    /// (`NTF-150`, `NTF-151`).
    pub fn set_timer_token<R: CryptoRng + ?Sized>(
        &mut self,
        token: Option<(TokenCarrier, &str)>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let plain = plain_token(token)?;
        if !plain.is_empty() {
            self.set_push_token(None, rng)?;
        }
        if self.timer_token()?.unwrap_or_default() == plain {
            return Ok(());
        }

        let mut rows = vec![(
            SETTINGS,
            TIMER_TOKEN_SETTING.to_vec(),
            Zeroizing::new(plain.clone()),
        )];
        let mut deleted = Vec::new();
        match (self.timer()?, plain.is_empty()) {
            // A new token moves the timer that the NDR holds.
            (Some(mut timer), _) if timer.state == REGISTERED => {
                timer.state = STALE;
                rows.push((SETTINGS, TIMER_SETTING.to_vec(), timer.encode()));
            }
            // A timer that the NDR never held leaves with the token.
            (Some(timer), true) if timer.state == UNREGISTERED => {
                deleted.push((SETTINGS, TIMER_SETTING.to_vec()));
            }
            (Some(_), _) => {}
            (None, false) => {
                let timer = Timer {
                    handle: random(rng),
                    removal: Secret::new(random(rng)),
                    state: UNREGISTERED,
                    registered_at: 0,
                };
                rows.push((SETTINGS, TIMER_SETTING.to_vec(), timer.encode()));
            }
            (None, true) => {}
        }

        self.write_rows(&rows, &deleted, rng)
    }

    /// The call of the timer that waits for the NDR, if any: an `NTIMER`
    /// for a timer that it does not hold under the present token or that
    /// it took more than `ROTATE_INTERVAL` ago, or an `NUNREG` for a timer
    /// whose token left (`NTF-152`).
    fn timer_call(&self, now: u64) -> Result<Option<NdrCall>, Error> {
        let Some(timer) = self.timer()? else {
            return Ok(None);
        };

        let mut out = Box::new([0u8; NDR_REQUEST_LEN]);
        let Some(plain) = self.timer_token()? else {
            if timer.state == UNREGISTERED {
                return Ok(None);
            }

            NdrRequest::Unregister {
                handle: timer.handle,
                removal: Secret::new(*timer.removal.expose()),
            }
            .encode(&mut out)
            .map_err(|_| Error::Malformed)?;
            return Ok(Some(NdrCall {
                handle: timer.handle,
                is_removal: true,
                advances: false,
                request: out,
                token: [0; 32],
                is_timer: true,
                at: now,
            }));
        };

        let fresh = now.saturating_sub(timer.registered_at) < ROTATE_INTERVAL;
        if timer.state == REGISTERED && fresh {
            return Ok(None);
        }

        // NTF-124: a timer that the NDR holds moves on its removal secret,
        // and the move takes the next secret of the chain.
        let advances = timer.state != UNREGISTERED;
        let removal = if advances {
            next_removal(&timer.removal)
        } else {
            Secret::new(*timer.removal.expose())
        };
        NdrRequest::Timer {
            handle: timer.handle,
            token: &plain,
            removal_hash: sha3_256(&[removal.expose()]),
            prior: Secret::new(*timer.removal.expose()),
        }
        .encode(&mut out)
        .map_err(|_| Error::Malformed)?;

        Ok(Some(NdrCall {
            handle: timer.handle,
            is_removal: false,
            advances,
            request: out,
            token: sha3_256(&[plain.as_slice()]),
            is_timer: true,
            at: now,
        }))
    }

    /// The NDR took a call of the timer.
    fn timer_call_taken<R: CryptoRng + ?Sized>(
        &mut self,
        call: &NdrCall,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut timer) = self.timer()?.filter(|timer| timer.handle == call.handle) else {
            return Ok(());
        };

        if call.advances {
            timer.removal = next_removal(&timer.removal);
        }

        let current = self
            .timer_token()?
            .map(|token| sha3_256(&[token.as_slice()]));
        if call.is_removal {
            // A token that came back since the removal registers anew.
            if current.is_none() {
                return self.write_rows(&[], &[(SETTINGS, TIMER_SETTING.to_vec())], rng);
            }
            timer.state = UNREGISTERED;
        } else if current == Some(call.token) {
            timer.state = REGISTERED;
            timer.registered_at = call.at;
        } else {
            timer.state = STALE;
        }

        self.put_rows(&[(SETTINGS, TIMER_SETTING.to_vec(), timer.encode())], rng)
    }

    /// Writes rows under their natural keys in one batch.
    fn put_rows<R: CryptoRng + ?Sized>(&mut self, rows: &[Row], rng: &mut R) -> Result<(), Error> {
        self.write_rows(rows, &[], rng)
    }

    /// Writes rows and deletes rows under their natural keys in one batch.
    fn write_rows<R: CryptoRng + ?Sized>(
        &mut self,
        rows: &[Row],
        deleted: &[(TableId, Vec<u8>)],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let keyed: Vec<_> = rows
            .iter()
            .map(|(table, natural, value)| (*table, open.store.row_id(*table, natural), value))
            .collect();
        let gone: Vec<_> = deleted
            .iter()
            .map(|(table, natural)| (*table, open.store.row_id(*table, natural)))
            .collect();
        let mut batch = open.store.begin();
        for (table, row, value) in keyed {
            batch.put(table, row, None, value, rng)?;
        }
        for (table, row) in gone {
            batch.delete(table, row);
        }

        batch.commit()?;
        let binds = |table: &TableId| [NOTIFY_RELAY, NOTIFY_GROUP, NOTIFY_QUEUE].contains(table);
        if rows.iter().any(|(table, ..)| binds(table))
            || deleted.iter().any(|(table, _)| binds(table))
        {
            self.wake_changed();
        }

        Ok(())
    }

    /// NTF-135: the wake table of the platform follows each change of a
    /// binding. One waiting event covers each change before it.
    pub(crate) fn wake_changed(&mut self) {
        if !self.events.contains(&Event::WakeTable) {
            self.events.push_back(Event::WakeTable);
        }
    }

    /// The hash of the contact set, for `NTF-008`.
    fn contact_set(&self) -> Result<[u8; 32], Error> {
        let store = &self.open_ref()?.store;
        let mut rows: Vec<_> = store
            .list(TableId::CONTACT, None)?
            .into_iter()
            .map(|(row, _)| row)
            .collect();
        rows.sort_unstable();
        let parts: Vec<&[u8]> = rows.iter().map(|row| row.as_slice()).collect();

        Ok(sha3_256(&parts))
    }

    /// Rotates one handle group that is due: 7 days after its last
    /// rotation, or at a change of the contact set (`NTF-007`, `NTF-008`).
    /// The group takes a fresh handle, `k_tok`, removal secret, and
    /// `k_ntf_root`, and each of its queues binds again under a new
    /// `NKEY`, which draws a new `notifier_id`. The old handle waits for its
    /// `NUNREG`. The caller rotates one group in one run (`NTF-080`,
    /// `NTF-081`). The result says whether a group rotated.
    pub fn rotate_one_group<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        if !self.binds()? {
            return Ok(false);
        }

        let mut groups = self.notify_groups()?;
        let mut rows = Vec::new();
        let set = self.contact_set()?;
        let known = {
            let store = &self.open_ref()?.store;
            let row = store.row_id(SETTINGS, CONTACT_SET_SETTING);
            store.get(SETTINGS, &row)?
        };

        // The first check records the set, and each later change of it
        // makes each group due.
        if known.as_deref() != Some(set.as_slice()) {
            if known.is_some() {
                for group in &mut groups {
                    group.rotated_at = 0;
                }
            }

            rows.push((
                SETTINGS,
                CONTACT_SET_SETTING.to_vec(),
                Zeroizing::new(set.to_vec()),
            ));
        }

        // Each group row below holds its root, thus no relay root stays.
        rows.extend(self.unused_relay_roots()?);
        let due = groups.iter().position(|group| {
            group.state != RETIRED && now.saturating_sub(group.rotated_at) >= ROTATE_INTERVAL
        });
        let Some(at) = due else {
            rows.extend(
                groups
                    .iter()
                    .map(|group| (NOTIFY_GROUP, group.handle.to_vec(), group.encode())),
            );
            return self.put_rows(&rows, rng).map(|()| false);
        };

        let old = groups.swap_remove(at);
        let old_handle = old.handle;
        let mut fresh = Group {
            handle: random(rng),
            relay_id: old.relay_id,
            k_tok: Secret::new(random(rng)),
            removal: Secret::new(random(rng)),
            state: UNREGISTERED,
            count: 0,
            class: old.class,
            root: Some(Secret::new(random(rng))),
            rotated_at: now,
        };
        let mut deleted = Vec::new();

        // A handle that the NDR never held needs no NUNREG.
        if old.state == UNREGISTERED {
            deleted.push((NOTIFY_GROUP, old.handle.to_vec()));
        } else {
            let retired = Group {
                state: RETIRED,
                count: 0,
                ..old
            };
            rows.push((NOTIFY_GROUP, retired.handle.to_vec(), retired.encode()));
        }

        let queues = self.open_ref()?.store.list(NOTIFY_QUEUE, None)?;
        for (_, bytes) in queues {
            let Ok(mut queue) = Queue::parse(&bytes) else {
                continue;
            };

            // NTF-034: the group takes again the queues that it holds now.
            if queue.handle == old_handle {
                fresh.count = fresh.count.saturating_add(1);
                queue.handle = fresh.handle;
                queue.bound = false;
                queue.notifier_id = None;
                rows.push((NOTIFY_QUEUE, queue.recipient_id.to_vec(), queue.encode()));
            }
        }

        rows.push((NOTIFY_GROUP, fresh.handle.to_vec(), fresh.encode()));
        rows.extend(
            groups
                .iter()
                .map(|group| (NOTIFY_GROUP, group.handle.to_vec(), group.encode())),
        );
        self.write_rows(&rows, &deleted, rng)?;

        Ok(true)
    }

    /// Whether a queue is a notify queue of Part 8 §8.5.2.
    fn is_rendezvous_queue(&self, recipient_id: &[u8; 32]) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(super::discovery::RENDEZVOUS_STATE, recipient_id);
        Ok(store
            .get(super::discovery::RENDEZVOUS_STATE, &row)?
            .is_some())
    }

    fn is_notify_queue(&self, recipient_id: &[u8; 32]) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(super::NOTIFY_STATE, recipient_id);
        Ok(store.get(super::NOTIFY_STATE, &row)?.is_some())
    }

    /// Each handle group. A row that does not read is no group: one such
    /// row stops no rotation, no wake table, and no NDR call.
    fn notify_groups(&self) -> Result<Vec<Group>, Error> {
        let relays = self.notify_relays()?;
        let mut groups = Vec::new();
        for (_, bytes) in self.open_ref()?.store.list(NOTIFY_GROUP, None)? {
            let bytes = Zeroizing::new(bytes);
            match Group::parse(&bytes) {
                Ok(group) => groups.push(group),
                Err(_) => crate::devlog::line("push: a group row does not read"),
            }
        }

        // A row of the first form holds the root of its relay.
        for group in &mut groups {
            if group.root.is_none() {
                group.root = relays
                    .iter()
                    .find(|relay| relay.relay_id == group.relay_id)
                    .filter(|relay| relay.root.expose() != &[0; 32])
                    .map(|relay| Secret::new(*relay.root.expose()));
            }
        }

        Ok(groups)
    }

    /// Each queue relay. A row that does not read is no relay.
    fn notify_relays(&self) -> Result<Vec<Relay>, Error> {
        let mut relays = Vec::new();
        for (_, bytes) in self.open_ref()?.store.list(NOTIFY_RELAY, None)? {
            let bytes = Zeroizing::new(bytes);
            match Relay::parse(&bytes) {
                Ok(relay) => relays.push(relay),
                Err(_) => crate::devlog::line("push: a relay row does not read"),
            }
        }

        Ok(relays)
    }

    /// The row of each relay that still holds a root, with zero bytes in
    /// its place. Each group row that a rotation or a bind writes holds the
    /// root that it uses, thus the root of the relay serves no binding.
    fn unused_relay_roots(&self) -> Result<Vec<Row>, Error> {
        Ok(self
            .notify_relays()?
            .iter()
            .filter(|relay| relay.root.expose() != &[0; 32])
            .map(|relay| {
                let row = relay.without_root();
                (NOTIFY_RELAY, row.relay_id.to_vec(), row.encode())
            })
            .collect())
    }

    fn notify_queue(&self, recipient_id: &[u8; 32]) -> Result<Option<Queue>, Error> {
        let open = self.open_ref()?;
        let row = open.store.row_id(NOTIFY_QUEUE, recipient_id);
        open.store
            .get(NOTIFY_QUEUE, &row)?
            .map(|bytes| Queue::parse(&bytes))
            .transpose()
    }

    /// Gives each queue of `queues`, with its relay, a handle group and an
    /// alias, and returns each queue that has no binding yet: its `NKEY`
    /// goes next. With no push endpoint no queue binds.
    pub fn queues_to_bind<R: CryptoRng + ?Sized>(
        &mut self,
        queues: &[([u8; 32], [u8; 32])],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<[u8; 32]>, Error> {
        if !self.binds()? {
            return Ok(Vec::new());
        }

        let mut relays = self.notify_relays()?;
        let mut groups = self.notify_groups()?;
        let mut unbound = Vec::new();
        let mut new_queues = Vec::new();
        for (recipient_id, relay_id) in queues {
            match self.notify_queue(recipient_id)? {
                Some(queue) if queue.bound => continue,
                Some(_) => {
                    unbound.push(*recipient_id);
                    continue;
                }
                None => {}
            }

            if !relays.iter().any(|relay| relay.relay_id == *relay_id) {
                let relay_idx = u16::try_from(relays.len()).map_err(|_| Error::TooLong)?;

                // Each group draws a root of its own (`NTF-007`).
                relays.push(Relay {
                    relay_id: *relay_id,
                    root: Secret::new([0; 32]),
                    relay_idx,
                });
            }

            // NTF-031, NTF-032: a group holds at most eight queues of one
            // relay, and a notify queue shares a group with no pairwise
            // queue (`NTF-091`).
            let (class, room_of) = if self.is_notify_queue(recipient_id)? {
                (DIGEST, MAX_QUEUES_PER_HANDLE)
            } else if self.is_rendezvous_queue(recipient_id)? {
                // NTF-043, NTF-044: a rendezvous queue has a handle of its
                // own, which no pairwise queue shares.
                (RENDEZVOUS, 1)
            } else {
                (PAIRWISE, MAX_QUEUES_PER_HANDLE)
            };
            let room = groups.iter().position(|group| {
                group.relay_id == *relay_id
                    && group.class == class
                    && group.state != RETIRED
                    && usize::from(group.count) < room_of
            });
            let at = match room {
                Some(at) => at,
                None => {
                    groups.push(Group {
                        handle: random(rng),
                        relay_id: *relay_id,
                        k_tok: Secret::new(random(rng)),
                        removal: Secret::new(random(rng)),
                        state: UNREGISTERED,
                        count: 0,
                        class,
                        root: Some(Secret::new(random(rng))),
                        rotated_at: now,
                    });
                    groups.len().saturating_sub(1)
                }
            };
            let group = groups.get_mut(at).ok_or(Error::Malformed)?;
            group.count = group.count.saturating_add(1);
            new_queues.push(Queue {
                recipient_id: *recipient_id,
                handle: group.handle,
                alias: random(rng),
                bound: false,
                notifier_id: None,
            });
            unbound.push(*recipient_id);
        }

        if new_queues.is_empty() {
            return Ok(unbound);
        }

        // Each group row below holds its root, thus no relay root stays.
        let rows: Vec<_> = relays
            .iter()
            .map(|relay| {
                let row = relay.without_root();
                (NOTIFY_RELAY, row.relay_id.to_vec(), row.encode())
            })
            .chain(
                groups
                    .iter()
                    .map(|group| (NOTIFY_GROUP, group.handle.to_vec(), group.encode())),
            )
            .chain(
                new_queues
                    .iter()
                    .map(|queue| (NOTIFY_QUEUE, queue.recipient_id.to_vec(), queue.encode())),
            )
            .collect();
        self.put_rows(&rows, rng)?;

        Ok(unbound)
    }

    /// The wake table of Part 8 `NTF-135`: each root that a binding uses,
    /// and each queue alias with the conversation of its queue. The
    /// platform seals it under its keystore, thus a locked client opens a
    /// blob with it (`NTF-136`). An alias whose queue raises no alert names
    /// [`WAKE_SILENT`] in the place of its conversation, and an alias of a
    /// muted conversation holds the end of its mute (`DEV-331`). The
    /// platform writes the table again after each block, and a change of a
    /// notification setting or a mute gives [`Event::WakeTable`].
    pub fn wake_table(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut roots: Vec<[u8; 32]> = Vec::new();

        // A group of the first form took the root of its relay, and the
        // group list holds that root for it. Each binding uses the root of
        // its group, a retired group too until its queues bind again.
        for group in self.notify_groups()? {
            if let Some(root) = &group.root {
                if !roots.contains(root.expose()) {
                    roots.push(*root.expose());
                }
            }
        }

        // A group notify queue names its group by its own row.
        let mut conversations = self.group_notify_conversations()?;
        let store = &self.open_ref()?.store;

        // A contact row starts with the contact, which is the RecipientId
        // of its first queue. A rotation gives it a new queue under the
        // same contact, thus the stored channel names each queue.
        for (row, plain) in store.list(TableId::CONTACT, None)? {
            let plain = Zeroizing::new(plain);
            conversations.extend(contact_queues(&plain).into_iter().map(|queue| (queue, row)));
        }

        // ABU-029, DEV-219: a locked client reads no setting, thus the
        // table says which queue raises no alert. Such a queue is the queue
        // of a blocked contact, of a conversation that shows no
        // notification, or of a sync channel. A sync channel is no
        // conversation of a view.
        // DEV-331: a mute with no end is silent, and a locked client reads
        // the end of each other mute from the table.
        let mut silent = self.device_peers()?;
        let mut mutes: Vec<(ConversationId, u64)> = Vec::new();
        for (_, conversation) in &conversations {
            let conversation = ConversationId(*conversation);
            if silent.contains(&conversation) {
                continue;
            }

            let muted_until_ms = self.muted_until(conversation)?;
            if self.is_blocked(conversation)?
                || self.alert_setting(conversation)? == super::ALERT_NONE
                || muted_until_ms == super::MUTE_FOREVER
            {
                silent.push(conversation);
            } else if muted_until_ms > 0 {
                mutes.push((conversation, muted_until_ms.div_ceil(1_000)));
            }
        }

        // DEV-340: the queue of a removed contact names no conversation,
        // and a push of it shows nothing.
        let removed = self.removed_queues()?;
        let store = &self.open_ref()?.store;
        let mut aliases = Vec::new();
        let mut muted = Vec::new();
        for queue in store
            .list(NOTIFY_QUEUE, None)?
            .iter()
            .filter_map(|(_, bytes)| Queue::parse(bytes).ok())
        {
            let conversation = conversations
                .iter()
                .find(|(recipient, _)| *recipient == queue.recipient_id)
                .map_or([0; 16], |(_, conversation)| *conversation);
            if silent.contains(&ConversationId(conversation))
                || removed.contains(&queue.recipient_id)
            {
                aliases.push((queue.alias, WAKE_SILENT));
                continue;
            }

            aliases.push((queue.alias, conversation));
            if let Some((_, until)) = mutes
                .iter()
                .find(|(muted, _)| *muted == ConversationId(conversation))
            {
                muted.push((queue.alias, *until));
            }
        }
        let table = umbra_core::notify::wakekey::WakeTable {
            roots,
            aliases,
            muted,
        };

        // The drop of the table wipes its roots.
        let encoded = Zeroizing::new(table.encode()?);

        Ok(encoded)
    }

    /// NTF-084: three blobs in a row did not open, thus each root is lost
    /// or the clock moved. Each group is due at once, and the rotation of
    /// `NTF-007` gives it a fresh root, one group in each run.
    pub fn renew_push_roots<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        let rows: Vec<_> = self
            .notify_groups()?
            .into_iter()
            .filter(|group| group.state != RETIRED)
            .map(|group| {
                let due = Group {
                    rotated_at: 0,
                    ..group
                };
                (NOTIFY_GROUP, due.handle.to_vec(), due.encode())
            })
            .collect();
        self.put_rows(&rows, rng)
    }

    /// The count of the queues whose `NBIND` left, and of the groups that
    /// the NDR holds under the present endpoint.
    pub fn push_state(&self) -> Result<(usize, usize), Error> {
        let bound = self
            .open_ref()?
            .store
            .list(NOTIFY_QUEUE, None)?
            .iter()
            .filter_map(|(_, bytes)| Queue::parse(bytes).ok())
            .filter(|queue| queue.bound)
            .count();
        let registered = self
            .notify_groups()?
            .iter()
            .filter(|group| group.state == REGISTERED)
            .count();

        Ok((bound, registered))
    }

    /// The binding of a queue, for the `NBIND` that answers its `NPK`
    /// (`NTF-113`).
    pub fn binding_of(&self, recipient_id: &[u8; 32]) -> Result<Option<Binding>, Error> {
        let Some(queue) = self.notify_queue(recipient_id)? else {
            return Ok(None);
        };

        let Some(group) = self
            .notify_groups()?
            .into_iter()
            .find(|group| group.handle == queue.handle)
        else {
            return Ok(None);
        };
        let Some(relay) = self
            .notify_relays()?
            .into_iter()
            .find(|relay| relay.relay_id == group.relay_id)
        else {
            return Ok(None);
        };
        let Some(root) = group.root else {
            return Ok(None);
        };

        // NTF-143: with no push token the binding serves the watch alone,
        // and it names no handle and no token key of an NDR.
        let (handle, k_tok) = if self.push_token()?.is_some() {
            (group.handle, group.k_tok)
        } else {
            (WATCH_HANDLE, Secret::new([0; 32]))
        };

        Ok(Some(Binding {
            root,
            handle,
            k_tok,
            queue_alias: queue.alias,
            relay_idx: relay.relay_idx,
        }))
    }

    /// Whether the queues of this device bind: under a push token, or for
    /// the watch of Direct mode (`NTF-142`).
    pub(crate) fn binds(&self) -> Result<bool, Error> {
        Ok(self.push_token()?.is_some() || self.locked_watch()?)
    }

    /// Whether this device binds its queues for the watch of a locked
    /// client (Direct mode, `NTF-142`).
    pub fn locked_watch(&self) -> Result<bool, Error> {
        let open = self.open_ref()?;
        let row = open.store.row_id(SETTINGS, WATCH_SETTING);
        Ok(open.store.get(SETTINGS, &row)?.as_deref() == Some(&[1u8][..]))
    }

    /// Turns the watch of Direct mode on or off. Each queue binds again at
    /// the next run, because the handle of its binding changes with it.
    pub fn set_watch<R: CryptoRng + ?Sized>(&mut self, on: bool, rng: &mut R) -> Result<(), Error> {
        if self.locked_watch()? == on {
            return Ok(());
        }

        let mut rows = vec![(
            SETTINGS,
            WATCH_SETTING.to_vec(),
            Zeroizing::new(vec![u8::from(on)]),
        )];
        rows.extend(self.unbound_queues()?);

        self.put_rows(&rows, rng)
    }

    /// Repairs the push path of a store of an earlier build, one time. Such
    /// a build bound a queue of Periodic mode under the handle of Instant
    /// mode, and the `gone` of that handle ended the binding at the relay
    /// (`NTF-143`). A device linked from it could also remove the timer of
    /// this device at the NDR (`NTF-152`). In both cases the store holds the
    /// binding and the timer as fresh, thus no later step binds the queue or
    /// moves the timer again. Each queue of the watch therefore binds again
    /// at the next run, and a held timer moves at the next call to the NDR.
    ///
    /// Until the run binds a queue again, the watch table holds no entry for
    /// it. A rendezvous queue binds after the delay of Part 9 `DIS-015`, thus
    /// a lock in that time gives the locked device no wake for it until the
    /// next unlock. This happens one time, and no record is lost. A store of
    /// this build holds the mark from its first commit and takes no repair.
    pub fn repair_push_path<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        let open = self.open_ref()?;
        let mark = open.store.row_id(SETTINGS, PUSH_REPAIRED_SETTING);
        if open.store.get(SETTINGS, &mark)?.is_some() {
            return Ok(());
        }

        let mut rows = vec![(
            SETTINGS,
            PUSH_REPAIRED_SETTING.to_vec(),
            Zeroizing::new(vec![1u8]),
        )];
        if self.locked_watch()? && self.push_token()?.is_none() {
            rows.extend(self.unbound_queues()?);
        }
        if let Some(mut timer) = self.timer()?.filter(|timer| timer.state == REGISTERED) {
            timer.state = STALE;
            rows.push((SETTINGS, TIMER_SETTING.to_vec(), timer.encode()));
        }

        self.put_rows(&rows, rng)
    }

    /// The notifier secret of a queue (Part 8 §8.2.4): `HKDF-SHA3-256` of
    /// the root of its group, with the `RecipientId` as the salt. It
    /// rotates with that root (`NTF-007`), and the store holds no copy.
    pub fn notifier_secret(&self, recipient_id: &[u8; 32]) -> Result<Option<Secret<32>>, Error> {
        let Some(binding) = self.binding_of(recipient_id)? else {
            return Ok(None);
        };

        let kdf = Hkdf::<Sha3_256>::new(Some(recipient_id), binding.root.expose());
        let mut secret = Secret::<32>::zeroed();
        kdf.expand(labels::NTF_NOTIFIER, secret.expose_mut())
            .map_err(|_| Error::Malformed)?;

        Ok(Some(secret))
    }

    /// The relay drew the `notifier_id` of a queue at its `NKEY`.
    pub fn set_notifier_id<R: CryptoRng + ?Sized>(
        &mut self,
        recipient_id: &[u8; 32],
        notifier_id: [u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut queue) = self.notify_queue(recipient_id)? else {
            return Ok(());
        };
        if queue.notifier_id == Some(notifier_id) {
            return Ok(());
        }

        queue.notifier_id = Some(notifier_id);
        self.put_rows(
            &[(NOTIFY_QUEUE, recipient_id.to_vec(), queue.encode())],
            rng,
        )
    }

    /// Each watch of a locked client: the relay, the `notifier_id`, and
    /// the notifier secret of each queue whose binding left (`NTF-145`).
    /// The list is empty while the watch is off.
    pub fn watch_entries(&self) -> Result<Vec<WatchEntry>, Error> {
        if !self.locked_watch()? || self.push_token()?.is_some() {
            return Ok(Vec::new());
        }

        let groups = self.notify_groups()?;
        let mut out = Vec::new();
        for (_, bytes) in self.open_ref()?.store.list(NOTIFY_QUEUE, None)? {
            let Ok(queue) = Queue::parse(&bytes) else {
                continue;
            };
            let Some(notifier_id) = queue.notifier_id.filter(|_| queue.bound) else {
                continue;
            };
            let Some(group) = groups.iter().find(|group| group.handle == queue.handle) else {
                continue;
            };

            // DIS-014: the relay can resolve a rendezvous queue to its
            // published entry, thus its watch shares no circuit.
            if let Some(secret) = self.notifier_secret(&queue.recipient_id)? {
                let apart = group.class == RENDEZVOUS;
                out.push((group.relay_id, notifier_id, secret, apart));
            }
        }

        Ok(out)
    }

    /// A queue ended: its binding leaves, and its group holds one queue
    /// less.
    pub fn unbind_queue<R: CryptoRng + ?Sized>(
        &mut self,
        recipient_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        self.binding.remove(recipient_id);
        let Some(queue) = self.notify_queue(recipient_id)? else {
            return Ok(());
        };

        let mut rows = Vec::new();
        if let Some(mut group) = self
            .notify_groups()?
            .into_iter()
            .find(|group| group.handle == queue.handle)
        {
            group.count = group.count.saturating_sub(1);
            rows.push((NOTIFY_GROUP, group.handle.to_vec(), group.encode()));
        }
        self.write_rows(&rows, &[(NOTIFY_QUEUE, recipient_id.to_vec())], rng)
    }

    /// The `NBIND` of a queue left. A relay gives it no answer, and a lost
    /// one binds again at the next `NKEY` after a new run. The result is
    /// false when a registration of its handle overtook the bind: the relay
    /// may have dropped it at a `gone`, thus the queue asks for its key and
    /// binds once more (`NTF-125`).
    pub fn queue_bound<R: CryptoRng + ?Sized>(
        &mut self,
        recipient_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<bool, Error> {
        if self.binding.remove(recipient_id) == Some(true) {
            self.binding.insert(*recipient_id, false);
            return Ok(false);
        }
        let Some(mut queue) = self.notify_queue(recipient_id)? else {
            return Ok(true);
        };

        queue.bound = true;
        self.put_rows(
            &[(NOTIFY_QUEUE, recipient_id.to_vec(), queue.encode())],
            rng,
        )?;

        Ok(true)
    }

    /// The `NKEY` of each queue in `recipient_ids` left, and its bind is on
    /// its way.
    pub fn binds_sent(&mut self, recipient_ids: &[[u8; 32]]) {
        for recipient_id in recipient_ids {
            self.binding.insert(*recipient_id, false);
        }
    }

    /// The requests that wait for the NDR at `now`: an `NREG` for each group
    /// that it does not hold under the present endpoint, or an `NUNREG` for
    /// each group it holds when the platform took the endpoint back, and the
    /// call of the timer of Periodic mode.
    pub fn ndr_calls_due<R: CryptoRng + ?Sized>(
        &self,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<NdrCall>, Error> {
        let token = self.push_token()?;
        let mut calls: Vec<NdrCall> = self.timer_call(now)?.into_iter().collect();
        for group in self.notify_groups()? {
            let request = match (&token, group.state) {
                // NTF-007: the handle that a rotation replaced leaves.
                (_, RETIRED) => {
                    let mut out = Box::new([0u8; NDR_REQUEST_LEN]);
                    NdrRequest::Unregister {
                        handle: group.handle,
                        removal: Secret::new(*group.removal.expose()),
                    }
                    .encode(&mut out)
                    .map_err(|_| Error::Malformed)?;
                    NdrCall {
                        handle: group.handle,
                        is_removal: true,
                        advances: false,
                        request: out,
                        token: [0; 32],
                        is_timer: false,
                        at: now,
                    }
                }
                (Some(_), REGISTERED) | (None, UNREGISTERED) => continue,
                (Some(plain), state) => {
                    let nonce: [u8; 24] = random(rng);

                    // NTF-123: `ct_token` seals the token under `k_tok`,
                    // bound to the handle.
                    let mut ct_token = plain.clone();
                    let tag = aead::seal(&group.k_tok, &nonce, &group.handle, &mut ct_token)
                        .map_err(|_| Error::Malformed)?;
                    ct_token.extend_from_slice(&tag);

                    // NTF-124: a handle that the NDR holds moves on its
                    // removal secret, and the next registration takes the
                    // next secret of the chain. The request carries the
                    // secret that the device holds in `prior` in each case:
                    // the NDR reads it for a handle that it holds, thus a
                    // first registration whose answer was lost goes again.
                    let advances = state == STALE;
                    let prior = Secret::new(*group.removal.expose());
                    let removal = if advances {
                        next_removal(&group.removal)
                    } else {
                        Secret::new(*group.removal.expose())
                    };
                    let mut out = Box::new([0u8; NDR_REQUEST_LEN]);
                    NdrRequest::Register {
                        handle: group.handle,
                        nonce,
                        ct_token: &ct_token,
                        removal_hash: sha3_256(&[removal.expose()]),
                        prior,
                    }
                    .encode(&mut out)
                    .map_err(|_| Error::Malformed)?;
                    NdrCall {
                        handle: group.handle,
                        is_removal: false,
                        advances,
                        request: out,
                        token: sha3_256(&[plain.as_slice()]),
                        is_timer: false,
                        at: now,
                    }
                }
                (None, _) => {
                    let mut out = Box::new([0u8; NDR_REQUEST_LEN]);
                    NdrRequest::Unregister {
                        handle: group.handle,
                        removal: Secret::new(*group.removal.expose()),
                    }
                    .encode(&mut out)
                    .map_err(|_| Error::Malformed)?;
                    NdrCall {
                        handle: group.handle,
                        is_removal: true,
                        advances: false,
                        request: out,
                        token: [0; 32],
                        is_timer: false,
                        at: now,
                    }
                }
            };
            calls.push(request);
        }

        Ok(calls)
    }

    /// The NDR took a call: the group is registered under the present
    /// endpoint, or it left. The result is each queue that binds again now.
    pub fn ndr_call_taken<R: CryptoRng + ?Sized>(
        &mut self,
        call: &NdrCall,
        rng: &mut R,
    ) -> Result<Vec<[u8; 32]>, Error> {
        if call.is_timer {
            return self.timer_call_taken(call, rng).map(|()| Vec::new());
        }

        let Some(mut group) = self
            .notify_groups()?
            .into_iter()
            .find(|group| group.handle == call.handle)
        else {
            return Ok(Vec::new());
        };

        // NTF-124: the registration took the next secret of the chain.
        if call.advances {
            group.removal = next_removal(&group.removal);
        }
        if group.state == RETIRED {
            // NTF-007: a retired handle leaves at its `NUNREG` alone; a
            // registration that landed after the retirement leaves the row,
            // thus the `NUNREG` still goes.
            if call.is_removal {
                self.write_rows(&[], &[(NOTIFY_GROUP, group.handle.to_vec())], rng)?;
            } else {
                self.put_rows(
                    &[(NOTIFY_GROUP, group.handle.to_vec(), group.encode())],
                    rng,
                )?;
            }
            return Ok(Vec::new());
        }

        // A registration under a token that the platform replaced since
        // holds the handle under the old token, thus the handle moves again.
        let current = self
            .push_token()?
            .map(|token| sha3_256(&[token.as_slice()]));
        group.state = if call.is_removal {
            UNREGISTERED
        } else if current == Some(call.token) {
            REGISTERED
        } else {
            STALE
        };

        // NTF-125: a relay that pushed before this registration got `gone`
        // and dropped its binding, thus each queue of the handle binds again.
        let mut unbound = Vec::new();
        let mut again = Vec::new();
        if !call.is_removal {
            for (_, bytes) in self.open_ref()?.store.list(NOTIFY_QUEUE, None)? {
                let Ok(mut queue) = Queue::parse(&bytes) else {
                    continue;
                };
                if queue.handle != group.handle {
                    continue;
                }

                if queue.bound {
                    queue.bound = false;
                    unbound.push((NOTIFY_QUEUE, queue.recipient_id.to_vec(), queue.encode()));
                    again.push(queue.recipient_id);
                } else if let Some(overtaken) = self.binding.get_mut(&queue.recipient_id) {
                    // A bind on its way may meet the `gone` too.
                    *overtaken = true;
                }
            }
        }

        unbound.push((NOTIFY_GROUP, group.handle.to_vec(), group.encode()));
        self.put_rows(&unbound, rng)?;
        self.binds_sent(&again);

        Ok(again)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use umbra_core::{
        identity::backup::{BackupObject, BackupRow},
        notify::wakekey::WakeTable,
        session::{
            channel::Inbound,
            node::{ContactId, StateChange},
        },
        store::{
            engine::MemoryBackend,
            wrap::{Cost, SecureElement},
        },
        Error as CoreError,
    };
    use umbra_crypto::{
        hmac::{digest::KeyInit, Hmac, Mac},
        rand_core::{TryCryptoRng, TryRng},
        sha2::Sha256,
        stored::Writer,
        x25519::StaticSecret,
    };

    use super::*;
    use crate::client::RestoredBackup;

    struct Rng(u64);

    impl TryRng for Rng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            Ok(self.0 >> 11 ^ self.0 << 7)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }

            Ok(())
        }
    }

    impl TryCryptoRng for Rng {}

    struct Element([u8; 32]);

    impl SecureElement for Element {
        fn keyed(&self, input: &[u8]) -> Result<[u8; 32], CoreError> {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| CoreError::Malformed)?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().into())
        }
    }

    type Device = Client<MemoryBackend, Element>;

    const T0: u64 = 1_700_000_000;
    const RELAY: [u8; 32] = [0xA1; 32];
    const CONTACT: [u8; 32] = [9; 32];
    const ROTATED: [u8; 32] = [0x21; 32];

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn new_client(seed: Option<Secret<32>>, rng: &mut Rng) -> Device {
        let passphrase = units("correct horse");
        let cost = Cost { m_kib: 64, t: 1 };
        match seed {
            Some(seed) => Client::create_with_seed(
                MemoryBackend::default(),
                Element([1; 32]),
                &passphrase,
                cost,
                1_000,
                seed,
                rng,
            ),
            None => Client::create(
                MemoryBackend::default(),
                Element([1; 32]),
                &passphrase,
                cost,
                1_000,
                rng,
            ),
        }
        .unwrap()
    }

    /// A stored contact of an early form whose channel reads `inbound`, and
    /// `previous` while a rotation runs. The channel ends after its queues,
    /// because the wake table reads no ratchet.
    fn contact_state(inbound: [u8; 32], previous: Option<[u8; 32]>) -> Zeroizing<Vec<u8>> {
        let end = |queue: [u8; 32]| {
            Inbound::new(
                queue,
                [3; 32],
                StaticSecret::from([4; 32]),
                &Secret::new([5; 32]),
                0,
            )
        };
        let mut channel = Writer::new();
        channel.u8(0x03);
        // The writer side of the queue of the peer.
        channel.bytes(&[7; 128]);
        end(inbound).export(&mut channel).unwrap();
        channel.u8(u8::from(previous.is_some()));
        if let Some(previous) = previous {
            end(previous).export(&mut channel).unwrap();
        }

        let mut state = Writer::new();
        state.u8(0x01);
        state.bytes(&[5; 16]);
        state.bytes(&[5; 32]);
        state.var(&channel.finish()).unwrap();
        state.finish()
    }

    /// A client with one contact whose channel reads `inbound` and
    /// `previous`, and the conversation of that contact.
    fn client_with_contact(
        inbound: [u8; 32],
        previous: Option<[u8; 32]>,
        rng: &mut Rng,
    ) -> (Device, ConversationId) {
        let mut client = new_client(None, rng);
        let change = StateChange::Contact {
            contact: ContactId(CONTACT),
            state: contact_state(inbound, previous),
        };
        client
            .commit_network(&[change], &[], T0 * 1_000, rng)
            .unwrap();
        let conversation = client.conversation_for(&CONTACT).unwrap();
        (client, conversation)
    }

    /// Each alias of the wake table with the conversation that it names.
    fn aliases(client: &Device) -> Vec<([u8; 16], [u8; 16])> {
        WakeTable::parse(&client.wake_table().unwrap())
            .unwrap()
            .aliases
            .clone()
    }

    /// NTF-135, ABU-029, DEV-331: a rotation gives a contact a new queue
    /// under the same contact. The alias of that queue names the
    /// conversation, and it is silent while the contact is blocked, muted
    /// with no end, or removed (`DEV-340`). Before this, the table matched
    /// the queue to the contact alone, and the alias named no conversation.
    #[test]
    fn the_queue_of_a_rotation_names_its_conversation_and_follows_its_settings() {
        let mut rng = Rng(7);
        let (mut client, conversation) = client_with_contact(ROTATED, Some(CONTACT), &mut rng);
        client
            .set_push_token(Some((TokenCarrier::Fcm, "fcm-token")), &mut rng)
            .unwrap();
        let queues = [(ROTATED, RELAY), (CONTACT, RELAY)];
        assert_eq!(
            client.queues_to_bind(&queues, T0, &mut rng).unwrap().len(),
            2
        );
        let alias = client.binding_of(&ROTATED).unwrap().unwrap().queue_alias;
        let first = client.binding_of(&CONTACT).unwrap().unwrap().queue_alias;

        let mut held = aliases(&client);
        held.sort_unstable();
        let mut expected = [(alias, conversation.0), (first, conversation.0)];
        expected.sort_unstable();
        assert_eq!(held, expected);

        // The rotation ends: the first queue leaves.
        client.unbind_queue(&CONTACT, &mut rng).unwrap();
        let change = StateChange::Contact {
            contact: ContactId(CONTACT),
            state: contact_state(ROTATED, None),
        };
        client
            .commit_network(&[change], &[], T0 * 1_000 + 1, &mut rng)
            .unwrap();
        assert_eq!(aliases(&client), [(alias, conversation.0)]);

        client
            .set_muted_until(conversation, super::super::MUTE_FOREVER, &mut rng)
            .unwrap();
        assert_eq!(aliases(&client), [(alias, WAKE_SILENT)]);
        client.set_muted_until(conversation, 0, &mut rng).unwrap();
        client.set_blocked(conversation, true, &mut rng).unwrap();
        assert_eq!(aliases(&client), [(alias, WAKE_SILENT)]);
        client.set_blocked(conversation, false, &mut rng).unwrap();
        assert_eq!(aliases(&client), [(alias, conversation.0)]);

        client.remove_contact(conversation, &mut rng).unwrap();
        assert_eq!(aliases(&client), [(alias, WAKE_SILENT)]);
    }

    /// NTF-143, NTF-153: the handle of a binding changes when a push token
    /// comes or leaves, thus each queue binds again. Before this, a queue
    /// that bound under the handle of Instant mode kept it in Periodic mode,
    /// and a `gone` of that handle ended its watch.
    #[test]
    fn a_token_that_comes_or_leaves_binds_each_queue_again() {
        let mut rng = Rng(8);
        let mut client = new_client(None, &mut rng);
        let queues = [(ROTATED, RELAY)];
        let bind = |client: &mut Device, rng: &mut Rng| {
            let unbound = client.queues_to_bind(&queues, T0, rng).unwrap();
            for queue in &unbound {
                client.queue_bound(queue, rng).unwrap();
            }
            unbound
        };

        // Instant mode, then the watch of Periodic mode before its token.
        client
            .set_push_token(Some((TokenCarrier::Fcm, "instant")), &mut rng)
            .unwrap();
        assert_eq!(bind(&mut client, &mut rng), [ROTATED]);
        client.set_watch(true, &mut rng).unwrap();
        assert_eq!(bind(&mut client, &mut rng), [ROTATED]);
        assert_ne!(
            client.binding_of(&ROTATED).unwrap().unwrap().handle,
            WATCH_HANDLE
        );

        // The token of the timer ends the token of Instant mode.
        client
            .set_timer_token(Some((TokenCarrier::Fcm, "timer")), &mut rng)
            .unwrap();
        assert_eq!(bind(&mut client, &mut rng), [ROTATED]);
        assert_eq!(
            client.binding_of(&ROTATED).unwrap().unwrap().handle,
            WATCH_HANDLE
        );

        // A change of the token of one mode keeps the handle.
        client
            .set_timer_token(Some((TokenCarrier::Fcm, "timer-2")), &mut rng)
            .unwrap();
        assert!(bind(&mut client, &mut rng).is_empty());

        // Back to Instant mode while the watch is still on.
        client
            .set_push_token(Some((TokenCarrier::Fcm, "instant-2")), &mut rng)
            .unwrap();
        assert_eq!(bind(&mut client, &mut rng), [ROTATED]);
        assert_ne!(
            client.binding_of(&ROTATED).unwrap().unwrap().handle,
            WATCH_HANDLE
        );
    }

    /// NTF-143, NTF-152: a store of an earlier build can hold a queue bound
    /// under the handle of Instant mode, which the relay dropped at its
    /// `gone`, and a fresh timer that a linked device removed at the NDR.
    /// The store shows both as fresh, thus nothing bound or moved them again
    /// for up to `ROTATE_INTERVAL`. The repair binds each queue of the watch
    /// again and moves the timer again, one time.
    #[test]
    fn the_first_unlock_repairs_the_push_path_of_an_earlier_build() {
        let mut rng = Rng(10);
        let mut client = new_client(None, &mut rng);
        // An earlier build made the store with no mark.
        client.remove_setting(PUSH_REPAIRED_SETTING).unwrap();
        let queues = [(ROTATED, RELAY)];
        let bind = |client: &mut Device, rng: &mut Rng| {
            let unbound = client.queues_to_bind(&queues, T0, rng).unwrap();
            for queue in &unbound {
                client.queue_bound(queue, rng).unwrap();
                client.set_notifier_id(queue, [0x33; 32], rng).unwrap();
            }
            unbound
        };
        let timer_call = |client: &Device, now: u64, rng: &mut Rng| {
            client
                .ndr_calls_due(now, rng)
                .unwrap()
                .into_iter()
                .find(|call| call.is_timer)
        };

        // Periodic mode: the queue binds for the watch, and the NDR holds the
        // timer.
        client.set_watch(true, &mut rng).unwrap();
        client
            .set_timer_token(Some((TokenCarrier::Fcm, "timer")), &mut rng)
            .unwrap();
        assert_eq!(bind(&mut client, &mut rng), [ROTATED]);
        let call = timer_call(&client, T0, &mut rng).unwrap();
        client.ndr_call_taken(&call, &mut rng).unwrap();
        assert!(client.timer_registered().unwrap());
        assert!(bind(&mut client, &mut rng).is_empty());
        assert!(timer_call(&client, T0 + 60, &mut rng).is_none());
        assert_eq!(client.watch_entries().unwrap().len(), 1);

        // The repair: the queue binds again, and the timer moves again on
        // the next secret of its chain.
        client.repair_push_path(&mut rng).unwrap();
        assert!(client.watch_entries().unwrap().is_empty());
        assert_eq!(bind(&mut client, &mut rng), [ROTATED]);
        let call = timer_call(&client, T0 + 60, &mut rng).unwrap();
        assert!(!call.is_removal);
        assert!(call.advances);
        client.ndr_call_taken(&call, &mut rng).unwrap();
        assert!(client.timer_registered().unwrap());

        // It runs one time.
        client.repair_push_path(&mut rng).unwrap();
        assert!(bind(&mut client, &mut rng).is_empty());
        assert!(timer_call(&client, T0 + 120, &mut rng).is_none());
        assert_eq!(client.watch_entries().unwrap().len(), 1);
    }

    /// A new store, and one that a restore or a link makes, holds the mark
    /// of the repair from its first commit. Before this, the first unlock
    /// of such a store dropped each binding of the watch, and a lock before
    /// the run bound them again gave the locked device no wake.
    #[test]
    fn a_store_of_this_build_takes_no_repair() {
        let mut rng = Rng(11);
        let queues = [(ROTATED, RELAY)];
        for seed in [None, Some(Secret::new([7; 32]))] {
            let mut client = new_client(seed, &mut rng);
            client.set_watch(true, &mut rng).unwrap();
            let unbound = client.queues_to_bind(&queues, T0, &mut rng).unwrap();
            assert_eq!(unbound, [ROTATED]);
            client.queue_bound(&ROTATED, &mut rng).unwrap();
            client
                .set_notifier_id(&ROTATED, [0x33; 32], &mut rng)
                .unwrap();
            assert_eq!(client.watch_entries().unwrap().len(), 1);

            client.repair_push_path(&mut rng).unwrap();
            assert_eq!(client.watch_entries().unwrap().len(), 1);
            assert!(client
                .queues_to_bind(&queues, T0, &mut rng)
                .unwrap()
                .is_empty());
        }
    }

    /// IDN-180, NTF-152: no backup carries the timer of Periodic mode, its
    /// token, or the watch, and a restore of an object of an earlier build
    /// takes none of them. Before this, a linked device sent the `NUNREG`
    /// of the timer of the device that it came from.
    #[test]
    fn no_backup_carries_the_push_path_of_its_device() {
        let mut rng = Rng(9);
        let mut client = new_client(None, &mut rng);
        client.set_watch(true, &mut rng).unwrap();
        client
            .set_timer_token(Some((TokenCarrier::Fcm, "timer")), &mut rng)
            .unwrap();
        let call = client.ndr_calls_due(T0, &mut rng).unwrap().remove(0);
        assert!(call.is_timer);
        client.ndr_call_taken(&call, &mut rng).unwrap();
        assert!(client.timer_registered().unwrap());

        let store = &client.open_ref().unwrap().store;
        let local: Vec<_> = DEVICE_SETTINGS
            .iter()
            .map(|key| store.row_id(SETTINGS, key))
            .collect();
        let held: Vec<_> = DEVICE_SETTINGS
            .iter()
            .filter_map(|key| {
                let row = store.row_id(SETTINGS, key);
                let plain = store.get(SETTINGS, &row).unwrap()?;
                Some(BackupRow::Put {
                    table: SETTINGS,
                    row,
                    owner: None,
                    plain: Zeroizing::new(plain),
                })
            })
            .collect();
        assert_eq!(held.len(), 4);

        let upload = client.backup_due(T0, true).unwrap().unwrap();
        let mut full = BackupObject::parse(&upload.plain).unwrap();
        assert!(!full.rows.iter().any(|row| matches!(
            row,
            BackupRow::Put { table, row, .. } if *table == SETTINGS && local.contains(row)
        )));

        // An object of an earlier build carried them.
        full.rows.extend(held);
        let restored = RestoredBackup::assemble(&[full.encode().unwrap()]).unwrap();
        let mut other = new_client(Some(restored.seed()), &mut rng);
        other.apply_restore(&restored, &mut rng).unwrap();
        assert!(other.timer_token().unwrap().is_none());
        assert!(other.timer().unwrap().is_none());
        assert!(!other.locked_watch().unwrap());
        assert!(other.ndr_calls_due(T0, &mut rng).unwrap().is_empty());
    }
}
