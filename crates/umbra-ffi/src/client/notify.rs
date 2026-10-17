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

use umbra_core::notify::ndr::next_removal;
use umbra_core::{
    notify::{binding::Binding, MAX_QUEUES_PER_HANDLE, ROTATE_INTERVAL, WATCH_HANDLE},
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
/// `notifier_id`, and its notifier secret (`NTF-145`).
pub type WatchEntry = ([u8; 32], [u8; 32], Secret<32>);

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
    /// one, or leaves with none.
    pub fn set_push_token<R: CryptoRng + ?Sized>(
        &mut self,
        token: Option<(TokenCarrier, &str)>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let plain = match token {
            Some((carrier, target)) => {
                // NTF-123: a token of the carrier, printable ASCII, and an
                // https URL for UnifiedPush.
                let mut plain = [0u8; PUSH_TOKEN_MAX];
                let n = encode_token(carrier, target.as_bytes(), &mut plain)
                    .map_err(|_| Error::TooLong)?;
                let plain = plain.get(..n).ok_or(Error::Malformed)?.to_vec();
                umbra_wire::ndr::parse_token(&plain).map_err(|_| Error::Malformed)?;
                plain
            }
            None => Vec::new(),
        };
        if self.push_token()?.unwrap_or_default() == plain {
            return Ok(());
        }

        let mut rows = vec![(SETTINGS, PUSH_TOKEN_SETTING.to_vec(), Zeroizing::new(plain))];
        for mut group in self.notify_groups()? {
            if group.state == REGISTERED {
                group.state = STALE;
                rows.push((NOTIFY_GROUP, group.handle.to_vec(), group.encode()));
            }
        }

        self.put_rows(&rows, rng)
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

        // A contact row starts with the RecipientId of its inbound queue.
        for (row, plain) in store.list(TableId::CONTACT, None)? {
            let plain = Zeroizing::new(plain);
            if let Some(recipient) = plain.get(..32).and_then(|id| <[u8; 32]>::try_from(id).ok()) {
                conversations.push((recipient, row));
            }
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
            if silent.contains(&ConversationId(conversation)) {
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
        for (_, bytes) in self.open_ref()?.store.list(NOTIFY_QUEUE, None)? {
            let Ok(mut queue) = Queue::parse(&bytes) else {
                continue;
            };

            queue.bound = false;
            queue.notifier_id = None;
            rows.push((NOTIFY_QUEUE, queue.recipient_id.to_vec(), queue.encode()));
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

            if let Some(secret) = self.notifier_secret(&queue.recipient_id)? {
                out.push((group.relay_id, notifier_id, secret));
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

    /// The requests that wait for the NDR: an `NREG` for each group that
    /// it does not hold under the present endpoint, or an `NUNREG` for each
    /// group it holds when the platform took the endpoint back.
    pub fn ndr_calls_due<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<Vec<NdrCall>, Error> {
        let token = self.push_token()?;
        let mut calls = Vec::new();
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
