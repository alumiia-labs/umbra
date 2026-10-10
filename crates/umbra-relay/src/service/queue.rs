//! The pairwise queues of one relay (Part 3 §3.2, Part 6 §6.4): `NEW`,
//! `SEND`, `SUB`, `UNSUB`, `ACK`, `NKEY`, and `DEL`, with the answer of
//! each one and the push of a `MSG` to the circuit that subscribed.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use umbra_core::{
    abuse::admission::{Accepts, RelayGate},
    notify::{
        binding::Binding,
        blob, epoch_of,
        push::{Push, PushScheduler},
        HANDLE_LEN, PUSH_TTL_MESSAGE,
    },
};
use umbra_crypto::{
    auth::CommandAuthKey,
    kem::KeyPair,
    rand_core::CryptoRng,
    secret::Secret,
    stored::{Reader, Writer},
    x25519::StaticSecret,
    zeroize::Zeroize,
};
use umbra_queue::{
    params::{
        store_grace_time, store_time, DRAIN_THRESHOLD, INVITE_RESERVE_TTL, INVITE_TTL, MSG_TTL,
    },
    relay::{
        queue::{Queue, QueueKeys},
        session::Session,
        Stored,
    },
    Reject,
};
use umbra_wire::{
    bucket::Bucket,
    command::{
        blob_bucket, iblob_payload, iput_parse, Cmd, Command, IdsPayload, NewPayload, IGET_LEN,
        LINK_ID_LEN,
    },
    ndr::{NdrRequest, NDR_REQUEST_LEN},
    queue::msg_from_send,
};

use super::{answer, Drain, Drains, Outbound, Reply};
use crate::{
    circuits::CircuitKey,
    store::{Loaded, StoreChange, StoredInvitation as Invitation},
};

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

/// The queues of the relay, by `RecipientId`.
#[derive(Default)]
pub struct QueueService {
    /// The invitations, by link identifier. A queue holds one at most.
    invitations: BTreeMap<[u8; LINK_ID_LEN], Invitation>,
    queues: BTreeMap<[u8; 32], Queue>,
    /// `RecipientId` by `SenderId`.
    by_sender: BTreeMap<[u8; 32], [u8; 32]>,
    /// The circuit that holds the subscription of a queue.
    subscribers: BTreeMap<[u8; 32], CircuitKey>,
    /// The changes since the last [`QueueService::take_changes`].
    changes: Vec<StoreChange>,
    /// The notification state of a queue relay (Part 8 §8.2.3).
    notify: Option<Notify>,
    /// The `corr_id` of each recent deposit, which a second copy repeats
    /// (`WIR-527`), in the order of its arrival.
    deposited: VecDeque<[u8; 16]>,
    /// The same values in a set, thus a capsule costs no scan of the list
    /// before its auth verifies.
    deposited_set: BTreeSet<[u8; 16]>,
}

/// The deposits whose `corr_id` a queue relay holds (`WIR-527`).
const DEPOSIT_SEEN: usize = 4_096;

/// One `NPUSH` for the NDR, which the runtime sends over OHTTP.
#[derive(Clone, PartialEq, Eq)]
pub struct NdrPush {
    /// The handle, for the answer `gone`.
    pub handle: [u8; HANDLE_LEN],
    /// The request.
    pub request: Box<[u8; NDR_REQUEST_LEN]>,
}

/// The request holds `k_tok`, thus this drop wipes it when the push leaves
/// memory (Part 8 §8.2.1).
impl Drop for NdrPush {
    fn drop(&mut self) {
        self.request.as_mut().zeroize();
    }
}

/// The request holds `k_tok`, thus no debug form shows it.
impl core::fmt::Debug for NdrPush {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NdrPush")
    }
}

/// The notification key of the relay, the push scheduler, and the pushes
/// that wait for the runtime.
struct Notify {
    pair: KeyPair,
    scheduler: PushScheduler,
    /// The queue of the last arrival of each handle, whose alias the next
    /// blob of that handle carries.
    latest: BTreeMap<[u8; HANDLE_LEN], [u8; 32]>,
    /// The pushes that the scheduler gave and that wait for their blob.
    due: Vec<Push>,
    pushes: Vec<NdrPush>,
}

/// The handle of the binding of a queue.
fn handle_of(queue: &Queue) -> Option<[u8; HANDLE_LEN]> {
    Binding::parse(queue.binding()?.expose())
        .ok()
        .map(|binding| binding.handle)
}

fn random_id<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut id = [0u8; 32];
    rng.fill_bytes(&mut id);
    id
}

/// The `MSG` of one stored record, in the bucket that its length gives.
fn msg_of<R: CryptoRng + ?Sized>(
    recipient_id: [u8; 32],
    seq: u32,
    record: &[u8],
    rng: &mut R,
) -> Option<Outbound> {
    let bucket = BUCKETS
        .into_iter()
        .find(|bucket| bucket.l6_record() == record.len())?;
    let mut payload = vec![0u8; record.len().saturating_add(4)];
    msg_from_send(seq, record, bucket, &mut payload).ok()?;
    let mut corr_id = [0u8; 16];
    // WIR-495: a command that the relay starts draws its own corr_id.
    rng.fill_bytes(&mut corr_id);
    let command = Command {
        cmd: Cmd::Msg,
        corr_id,
        queue_id: recipient_id,
        auth: [0; 32],
        payload: &payload,
    };
    let mut encoded = vec![0u8; command.len()];
    command.encode(&mut encoded).ok()?;
    Some(Outbound { bucket, encoded })
}

impl QueueService {
    /// Gives this relay its notification key, thus it answers `NKEY` with
    /// an `NPK` and pushes for each queue with a binding (`NTF-112`).
    pub fn set_notify_key(&mut self, pair: KeyPair) {
        self.notify = Some(Notify {
            pair,
            scheduler: PushScheduler::default(),
            latest: BTreeMap::new(),
            due: Vec::new(),
            pushes: Vec::new(),
        });
    }

    /// Takes the notification key of `earlier`, a service of the same relay.
    pub fn keep_notify_of(&mut self, earlier: &mut QueueService) {
        self.notify = earlier.notify.take();
    }

    /// The pushes that wait for the runtime.
    pub fn take_ndr_pushes(&mut self) -> Vec<NdrPush> {
        self.notify
            .as_mut()
            .map(|notify| core::mem::take(&mut notify.pushes))
            .unwrap_or_default()
    }

    /// The pushes due at `now`: the end of a coalescing window and each
    /// re-push (`NTF-049`, `NTF-066`).
    pub fn push_tick<R: CryptoRng + ?Sized>(&mut self, now: u64, rng: &mut R) {
        match self.notify.as_mut() {
            Some(notify) => {
                let due = notify.scheduler.tick(now);
                notify.due.extend(due);
            }
            None => return,
        }
        self.seal_due(now, rng);
        // WIR-041: a handle that no push waits for names no queue here, and
        // a queue that a DEL ended leaves no identifier in memory.
        if let Some(notify) = self.notify.as_mut() {
            let scheduler = &notify.scheduler;
            let queues = &self.queues;
            notify.latest.retain(|handle, recipient_id| {
                scheduler.holds(handle) && queues.contains_key(recipient_id)
            });
        }
    }

    /// The NDR named a handle gone: each queue under it drops its binding,
    /// and no push of that handle follows (`NTF-125`).
    pub fn ndr_gone(&mut self, handle: &[u8; HANDLE_LEN]) {
        let under: Vec<[u8; 32]> = self
            .queues
            .iter()
            .filter(|(_, queue)| handle_of(queue).as_ref() == Some(handle))
            .map(|(id, _)| *id)
            .collect();
        for recipient_id in under {
            if let Some(queue) = self.queues.get_mut(&recipient_id) {
                queue.clear_binding();
            }
            self.head_changed(recipient_id);
        }
    }

    /// An arrival at a queue with a binding, which no live subscription
    /// took (`NTF-128`). A `digest` arrival is the deposit of a group
    /// relay, and its push takes the flag of a digest inside its blob
    /// (`NTF-086`). The push waits for [`QueueService::seal_due`].
    fn on_arrival(&mut self, recipient_id: [u8; 32], digest: bool, now: u64) {
        let Some(handle) = self.queues.get(&recipient_id).and_then(handle_of) else {
            return;
        };
        let Some(notify) = self.notify.as_mut() else {
            return;
        };
        notify.latest.insert(handle, recipient_id);
        if let Some(push) = notify.scheduler.on_arrival(handle, digest, now) {
            notify.due.push(push);
        }
    }

    /// Seals the blob of each push that waits.
    fn seal_due<R: CryptoRng + ?Sized>(&mut self, now: u64, rng: &mut R) {
        let due = match self.notify.as_mut() {
            Some(notify) => core::mem::take(&mut notify.due),
            None => return,
        };
        for push in due {
            self.queue_push(push, now, rng);
        }
    }

    /// A drain of a queue ends the re-push of its handle (`NTF-066`).
    fn on_drain(&mut self, recipient_id: &[u8; 32]) {
        let handle = self.queues.get(recipient_id).and_then(handle_of);
        if let (Some(handle), Some(notify)) = (handle, self.notify.as_mut()) {
            notify.scheduler.on_drain(&handle);
        }
    }

    /// Seals the blob of one push under the binding of the queue of the
    /// last arrival of its handle, and queues the `NPUSH` (`NTF-114`).
    fn queue_push<R: CryptoRng + ?Sized>(&mut self, push: Push, now: u64, rng: &mut R) {
        let Some(notify) = self.notify.as_mut() else {
            return;
        };
        let Some(queue) = notify
            .latest
            .get(&push.handle)
            .and_then(|recipient_id| self.queues.get(recipient_id))
        else {
            return;
        };
        let Some(binding) = queue
            .binding()
            .and_then(|held| Binding::parse(held.expose()).ok())
        else {
            return;
        };
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let plain = blob::Plain {
            relay_idx: binding.relay_idx,
            queue_alias: binding.queue_alias,
            waiting_count: u8::try_from(queue.waiting()).unwrap_or(u8::MAX),
            // The field holds the low 32 bits of the clock.
            relay_ts: u32::try_from(now & u64::from(u32::MAX)).unwrap_or(0),
            flags: if push.digest { blob::FLAG_DIGEST } else { 0 },
        };
        let Ok(sealed) = blob::seal(&binding.root, epoch_of(now), nonce, &plain) else {
            return;
        };
        let mut request = Box::new([0u8; NDR_REQUEST_LEN]);
        let encoded = NdrRequest::Push {
            handle: binding.handle,
            k_tok: Secret::new(*binding.k_tok.expose()),
            // NTF-086: each push takes one expiry. The kind of a push
            // shows in no field outside the blob.
            ttl: u32::try_from(PUSH_TTL_MESSAGE).unwrap_or(u32::MAX),
            blob: sealed,
        }
        .encode(&mut request);
        if encoded.is_ok() {
            notify.pushes.push(NdrPush {
                handle: binding.handle,
                request,
            });
        }
    }

    /// Stores one record that a sender authorized, and gives the capacity
    /// left and the `MSG` of a live subscription. A record that no live
    /// subscription takes goes to the push scheduler (`NTF-128`), as a
    /// digest when `digest` is set (`NTF-086`).
    fn store_record<R: CryptoRng + ?Sized>(
        &mut self,
        recipient_id: [u8; 32],
        record: &[u8],
        digest: bool,
        now: u64,
        rng: &mut R,
    ) -> Result<(u32, Option<Reply>), Reject> {
        let queue = self.queues.get_mut(&recipient_id).ok_or(Reject::Rejected)?;
        let seq = queue.send(record, now)?;
        let remaining = u32::try_from(queue.remaining()).unwrap_or(u32::MAX);
        self.changes.push(StoreChange::Record {
            recipient_id,
            record: Stored {
                seq,
                accepted_at: store_time(now),
                bytes: record.to_vec(),
            },
        });
        self.head_changed(recipient_id);
        let live = self.subscribers.get(&recipient_id).and_then(|subscriber| {
            msg_of(recipient_id, seq, record, rng).map(|outbound| Reply {
                circuit: *subscriber,
                outbound,
            })
        });
        if live.is_none() {
            self.on_arrival(recipient_id, digest, now);
            self.seal_due(now, rng);
        }
        Ok((remaining, live))
    }

    /// One `SEND` of another relay, from an `UMBRA_DEPOSIT` capsule: the
    /// digest of a group (`WIR-526`). Its auth derives from
    /// the static key of this relay, a `corr_id` that came before drops,
    /// and no answer goes back. The result is the `MSG` of a live
    /// subscription.
    pub fn deposit<R: CryptoRng + ?Sized>(
        &mut self,
        command: &Command<'_>,
        relay_static: &StaticSecret,
        now: u64,
        rng: &mut R,
    ) -> Option<Reply> {
        if command.cmd != Cmd::Send || self.deposited_set.contains(&command.corr_id) {
            return None;
        }
        let recipient_id = *self.by_sender.get(&command.queue_id)?;
        let qs_auth_pk = self.queues.get(&recipient_id)?.keys().qs_auth_pk;
        let key = CommandAuthKey::derive(relay_static, &qs_auth_pk).ok()?;
        command.verify(&key, b"").ok()?;
        if self.deposited.len() >= DEPOSIT_SEEN {
            if let Some(oldest) = self.deposited.pop_front() {
                self.deposited_set.remove(&oldest);
            }
        }
        self.deposited.push_back(command.corr_id);
        self.deposited_set.insert(command.corr_id);
        // NTF-086: a deposit is a digest, and the blob of its push says so.
        self.store_record(recipient_id, command.payload, true, now, rng)
            .ok()
            .and_then(|(_, live)| live)
    }

    /// The queues and the invitations of an earlier run. A queue whose
    /// stored form has a fault is dropped, and the others stay.
    pub fn restore(loaded: Loaded) -> Self {
        let mut service = QueueService {
            invitations: loaded.invitations,
            ..QueueService::default()
        };
        for (recipient_id, stored) in loaded.queues {
            let mut reader = Reader::new(&stored.head);
            let restored = Queue::restore(&mut reader, stored.records)
                .ok()
                .filter(|queue| queue.keys().recipient_id == recipient_id);
            let Some(queue) = restored else {
                // NET-302, NET-303: a queue that serves no one leaves the
                // file too.
                service
                    .changes
                    .push(StoreChange::QueueDeleted { recipient_id });
                continue;
            };
            service
                .by_sender
                .insert(queue.keys().sender_id, recipient_id);
            service.queues.insert(recipient_id, queue);
        }
        // An invitation of a queue that is gone serves no party.
        let gone: Vec<[u8; LINK_ID_LEN]> = service
            .invitations
            .iter()
            .filter(|(_, held)| !service.queues.contains_key(&held.recipient_id))
            .map(|(link_id, _)| *link_id)
            .collect();
        for link_id in gone {
            service.invitations.remove(&link_id);
            service
                .changes
                .push(StoreChange::InvitationDeleted { link_id });
        }
        service
    }

    /// The changes since the last call. The process commits them before it
    /// sends an output of the same call of the node (`NET-298`).
    pub fn take_changes(&mut self) -> Vec<StoreChange> {
        core::mem::take(&mut self.changes)
    }

    /// Records the head of a queue after a change of it.
    fn head_changed(&mut self, recipient_id: [u8; 32]) {
        if let Some(queue) = self.queues.get(&recipient_id) {
            let mut writer = Writer::new();
            queue.export_head(&mut writer);
            self.changes.push(StoreChange::Queue {
                recipient_id,
                head: writer.finish().to_vec(),
            });
        }
    }

    /// Records an invitation, with its time as the store holds it. A
    /// reservation that took no blob lives `INVITE_RESERVE_TTL`, far below
    /// the grain, thus its time rounds down and it ends no later than its
    /// own (`WIR-508`, `NET-301`).
    fn invitation_changed(&mut self, link_id: [u8; LINK_ID_LEN], mut held: Invitation) {
        held.at = if held.blob.is_none() {
            store_grace_time(held.at)
        } else {
            store_time(held.at)
        };
        self.changes.push(StoreChange::Invitation { link_id, held });
    }

    /// Ends each invitation of a queue.
    fn end_invitations(&mut self, recipient_id: [u8; 32]) {
        let ended: Vec<_> = self
            .invitations
            .iter()
            .filter(|(_, held)| held.recipient_id == recipient_id)
            .map(|(link_id, _)| *link_id)
            .collect();
        for link_id in ended {
            self.invitations.remove(&link_id);
            self.changes
                .push(StoreChange::InvitationDeleted { link_id });
        }
    }

    /// The count of the queues.
    pub fn len(&self) -> usize {
        self.queues.len()
    }

    /// Whether the relay holds no queue.
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    /// Handles one command of the queue range on `circuit`. A `SUB` with a
    /// backlog above `DRAIN_THRESHOLD` gives no `MSG`. It leaves a drain in
    /// `drains`, and the node asks for its records in steps
    /// ([`QueueService::drain_step`]).
    #[allow(clippy::too_many_arguments)]
    pub fn handle<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
        drains: &mut Drains,
        gate: &mut RelayGate,
        accepts: &Accepts<'_>,
        command: &Command<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<Reply>, Reject> {
        match command.cmd {
            Cmd::New => {
                let new = NewPayload::parse(command.payload).map_err(|_| Reject::Rejected)?;
                session.accept(command, &new.qr_auth_pk)?;
                session.room()?;
                gate.admit(&new.admission, accepts, now)?;
                let keys = QueueKeys {
                    recipient_id: random_id(rng),
                    sender_id: random_id(rng),
                    qr_auth_pk: new.qr_auth_pk,
                    qs_auth_pk: new.qs_auth_pk,
                };
                let ids = IdsPayload {
                    recipient_id: keys.recipient_id,
                    sender_id: keys.sender_id,
                    relay_session_pk: session.relay_session_pk(),
                };
                session.bind_queue(keys.recipient_id)?;
                let recipient_id = keys.recipient_id;
                self.by_sender.insert(keys.sender_id, recipient_id);
                self.queues.insert(recipient_id, Queue::new(keys, now));
                self.head_changed(recipient_id);
                let mut payload = [0u8; 96];
                ids.encode(&mut payload).map_err(|_| Reject::Busy)?;
                Ok(vec![answer(circuit, command, Cmd::Ids, &payload)])
            }
            Cmd::Send => {
                // WIR-317: an unknown queue and a failed auth give one reason.
                let recipient_id = *self
                    .by_sender
                    .get(&command.queue_id)
                    .ok_or(Reject::Rejected)?;
                let queue = self.queues.get(&recipient_id).ok_or(Reject::Rejected)?;
                session.accept(command, &queue.keys().qs_auth_pk)?;
                let (remaining, live) =
                    self.store_record(recipient_id, command.payload, false, now, rng)?;
                // WIR-496: the QUOTA is the relay acknowledgment.
                let mut replies = vec![answer(
                    circuit,
                    command,
                    Cmd::Quota,
                    &remaining.to_be_bytes(),
                )];
                replies.extend(live);
                Ok(replies)
            }
            Cmd::Iget => {
                // WIR-509: the fetch names no queue.
                if command.queue_id != [0; 32] {
                    return Err(Reject::Rejected);
                }
                // The party holds no key of the queue yet. It signs under
                // the lock key, thus the lock names a key that it holds.
                let payload: &[u8; IGET_LEN] =
                    command.payload.try_into().map_err(|_| Reject::Rejected)?;
                let (link_id, lock_pk) = payload.split_at(LINK_ID_LEN);
                let link_id: [u8; LINK_ID_LEN] =
                    link_id.try_into().map_err(|_| Reject::Rejected)?;
                let lock_pk: [u8; 32] = lock_pk.try_into().map_err(|_| Reject::Rejected)?;
                // WIR-317: an unknown link, a link with no blob, and a
                // failed auth give one reason.
                let held = self.invitations.get(&link_id).ok_or(Reject::Rejected)?;
                let blob = held.blob.as_ref().ok_or(Reject::Rejected)?;
                session.accept(command, &lock_pk)?;
                let bucket = blob_bucket(blob.len()).ok_or(Reject::Rejected)?;
                let payload = iblob_payload(blob, bucket).map_err(|_| Reject::Busy)?;
                // IDN-023: the first fetch takes the blob and locks the
                // queue. A second fetch finds no link.
                let recipient_id = held.recipient_id;
                self.invitations.remove(&link_id);
                self.changes
                    .push(StoreChange::InvitationDeleted { link_id });
                if let Some(queue) = self.queues.get_mut(&recipient_id) {
                    queue.lock_sender(lock_pk);
                }
                self.head_changed(recipient_id);
                Ok(vec![answer(circuit, command, Cmd::Iblob, &payload)])
            }
            Cmd::Sub
            | Cmd::Unsub
            | Cmd::Ack
            | Cmd::Del
            | Cmd::Nkey
            | Cmd::Nbind
            | Cmd::Ires
            | Cmd::Iput => self.recipient_command(circuit, session, drains, command, now, rng),
            // A cover command of a client names no queue. It gets no answer,
            // and it is no activity of a queue (`NET-196`).
            Cmd::Cover => Ok(Vec::new()),
            _ => Err(Reject::Rejected),
        }
    }

    fn recipient_command<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
        drains: &mut Drains,
        command: &Command<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<Reply>, Reject> {
        let recipient_id = command.queue_id;
        let queue = self.queues.get_mut(&recipient_id).ok_or(Reject::Rejected)?;
        session.accept(command, &queue.keys().qr_auth_pk)?;
        let replies = self.owner_command(circuit, session, drains, command, now, rng)?;
        // A subscription and an acknowledgment drain the queue.
        if matches!(command.cmd, Cmd::Sub | Cmd::Ack) {
            self.on_drain(&recipient_id);
        }
        // Each command of the owner moves the head: the time of the last
        // activity at the least. A `DEL` left no queue, and then no head.
        self.head_changed(recipient_id);
        Ok(replies)
    }

    /// A command that `QR_auth` authorized.
    fn owner_command<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
        drains: &mut Drains,
        command: &Command<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<Reply>, Reject> {
        let recipient_id = command.queue_id;
        let queue = self.queues.get_mut(&recipient_id).ok_or(Reject::Rejected)?;
        match command.cmd {
            Cmd::Sub => {
                // NET-037, NET-349: a backlog above the threshold is a
                // drain. The relay reads the bound from the lengths of the
                // records before it copies one of them.
                let is_drain = queue.pending().nth(DRAIN_THRESHOLD).is_some();
                let named = if is_drain {
                    let lengths = queue.pending().map(|stored| stored.bytes.len());
                    match drains.admit(&recipient_id, lengths, now) {
                        Ok(bytes) => Some(bytes),
                        Err(reject) => {
                            // A refused `SUB` leaves no subscription. With
                            // one, each later record would go as a live
                            // `MSG` above a backlog that never left. The
                            // client would see a hole, and its `ACK` past
                            // that hole would erase the backlog. With none,
                            // each later record is an arrival that no
                            // subscription took, and it takes its push
                            // (`NTF-128`).
                            if self.subscribers.get(&recipient_id) == Some(&circuit) {
                                self.subscribers.remove(&recipient_id);
                                queue.subscribe(false, now);
                            }
                            drains.end(&recipient_id);
                            return Err(reject);
                        }
                    }
                } else {
                    None
                };
                session.bind_queue(recipient_id)?;
                queue.subscribe(true, now);
                self.subscribers.insert(recipient_id, circuit);
                match named {
                    Some(left) => {
                        drains.hold(Drain {
                            queue_id: recipient_id,
                            after: queue.last_ack(),
                            end: queue.next_seq(),
                            left,
                        });
                        Ok(Vec::new())
                    }
                    None => {
                        drains.end(&recipient_id);
                        // WIR-110: each record that no ACK covers goes out.
                        Ok(queue
                            .pending()
                            .filter_map(|stored| {
                                msg_of(recipient_id, stored.seq, &stored.bytes, rng)
                            })
                            .map(|outbound| Reply { circuit, outbound })
                            .collect())
                    }
                }
            }
            Cmd::Unsub => {
                queue.subscribe(false, now);
                self.subscribers.remove(&recipient_id);
                drains.end(&recipient_id);
                Ok(Vec::new())
            }
            Cmd::Ack => {
                let seq: [u8; 4] = command.payload.try_into().map_err(|_| Reject::Rejected)?;
                let seq = u32::from_be_bytes(seq);
                // An ACK above the last record of the queue names no record,
                // and it would move the cursor past the next one.
                if seq >= queue.next_seq() {
                    return Err(Reject::Rejected);
                }
                // An ACK at or below the last one moves nothing, thus it
                // costs the store no commit.
                if seq <= queue.last_ack() {
                    return Ok(Vec::new());
                }
                queue.ack(seq);
                self.changes.push(StoreChange::Acked { recipient_id, seq });
                Ok(Vec::new())
            }
            Cmd::Nkey => {
                let notifier_pk: [u8; 32] =
                    command.payload.try_into().map_err(|_| Reject::Rejected)?;
                let notifier_id = random_id(rng);
                queue.set_notifier(notifier_pk, notifier_id);
                let mut replies = Vec::new();
                // NTF-112: the notification key goes before the `NID`.
                if let Some(notify) = &self.notify {
                    let public = notify.pair.public().to_bytes();
                    replies.push(answer(circuit, command, Cmd::Npk, &public));
                }
                replies.push(answer(circuit, command, Cmd::Nid, &notifier_id));
                Ok(replies)
            }
            Cmd::Nbind => {
                // NTF-113: the binding opens under the notification key of
                // this relay, bound to the queue. It gets no answer.
                let notify = self.notify.as_ref().ok_or(Reject::Rejected)?;
                let binding = Binding::open(&notify.pair, &recipient_id, command.payload)
                    .map_err(|_| Reject::Rejected)?;
                let plain = binding.encode().map_err(|_| Reject::Rejected)?;
                queue.set_binding(Secret::new(plain));
                Ok(Vec::new())
            }
            Cmd::Ires => {
                // One queue holds one invitation. A second `IRES` takes the
                // place of the first, and the first link ends.
                self.end_invitations(recipient_id);
                let mut link_id = [0u8; LINK_ID_LEN];
                rng.fill_bytes(&mut link_id);
                let held = Invitation {
                    recipient_id,
                    blob: None,
                    at: now,
                };
                self.invitations.insert(link_id, held.clone());
                self.invitation_changed(link_id, held);
                Ok(vec![answer(circuit, command, Cmd::Ilink, &link_id)])
            }
            Cmd::Iput => {
                let (link_id, blob) = iput_parse(command.payload).map_err(|_| Reject::Rejected)?;
                let held = self
                    .invitations
                    .get_mut(&link_id)
                    .filter(|held| held.recipient_id == recipient_id && held.blob.is_none())
                    .ok_or(Reject::Rejected)?;
                held.blob = Some(blob.to_vec());
                // IDN-126: the lifetime runs from the store of the blob.
                held.at = now;
                let held = held.clone();
                self.invitation_changed(link_id, held);
                Ok(vec![answer(circuit, command, Cmd::Ilink, &link_id)])
            }
            Cmd::Del => {
                session.unbind_queue(&recipient_id);
                self.end_invitations(recipient_id);
                // WIR-039 to WIR-042: no identifier of the queue stays.
                if let Some(queue) = self.queues.remove(&recipient_id) {
                    self.by_sender.remove(&queue.keys().sender_id);
                    drop(queue.delete());
                }
                self.changes
                    .push(StoreChange::QueueDeleted { recipient_id });
                self.subscribers.remove(&recipient_id);
                drains.end(&recipient_id);
                Ok(Vec::new())
            }
            _ => Err(Reject::Rejected),
        }
    }

    /// The next records of `drain` for `circuit`, as `MSG` commands of
    /// about `room` bytes together, and whether the drain ended. The step
    /// stops after the record that reaches `room`, thus each step moves the
    /// drain. A drain ends at its last record, and when the queue left or
    /// its subscription went to another circuit.
    pub fn drain_step<R: CryptoRng + ?Sized>(
        &self,
        circuit: &CircuitKey,
        drain: &mut Drain,
        room: usize,
        rng: &mut R,
    ) -> (Vec<Outbound>, bool) {
        let live = self.subscribers.get(&drain.queue_id) == Some(circuit);
        let Some(queue) = self.queues.get(&drain.queue_id).filter(|_| live) else {
            return (Vec::new(), true);
        };
        let mut out = Vec::new();
        let mut sent = 0usize;
        for stored in queue.pending_after(drain.after) {
            if stored.seq >= drain.end {
                break;
            }
            if sent >= room {
                return (out, false);
            }
            drain.after = stored.seq;
            drain.left = drain.left.saturating_sub(stored.bytes.len());
            if let Some(outbound) = msg_of(drain.queue_id, stored.seq, &stored.bytes, rng) {
                sent = sent.saturating_add(outbound.encoded.len());
                out.push(outbound);
            }
        }
        (out, true)
    }

    /// A circuit ended, thus its subscriptions end. A record that a
    /// subscription took and that no `ACK` covers gets no push here. A
    /// client holds each `ACK` for `RECEIPT_MIN_DELAY` and it does not send
    /// one because it leaves (`NET-048`, `NET-050`). An orderly end soon
    /// after an arrival thus leaves a record with no `ACK`. This relay
    /// cannot tell that end from a lost link: the end of a circuit carries
    /// no cause. A push at each such end would wake a device for a record
    /// that it holds. A wake session ends before the floor of the `ACK`,
    /// thus it would give the next push. The record stays in the queue,
    /// and the next subscription takes it again.
    pub fn circuit_closed(&mut self, circuit: &CircuitKey, now: u64) {
        let ended: Vec<[u8; 32]> = self
            .subscribers
            .iter()
            .filter(|(_, held)| *held == circuit)
            .map(|(recipient_id, _)| *recipient_id)
            .collect();
        for recipient_id in ended {
            self.subscribers.remove(&recipient_id);
            if let Some(queue) = self.queues.get_mut(&recipient_id) {
                queue.subscribe(false, now);
            }
        }
    }

    /// The client of a circuit paused its session (`WIR-546`): each
    /// subscription of the circuit ends as at the end of the circuit. A
    /// record that arrives after it finds no subscription, and it takes
    /// its push.
    pub fn circuit_paused(&mut self, circuit: &CircuitKey, now: u64) {
        self.circuit_closed(circuit, now);
    }

    /// Expires each record past `MSG_TTL`, and erases each idle queue.
    pub fn sweep(&mut self, now: u64) {
        let past_lifetime = |held: &Invitation| {
            let limit = match held.blob {
                Some(_) => INVITE_TTL,
                None => INVITE_RESERVE_TTL,
            };
            now.saturating_sub(held.at) >= limit
        };
        let ended: Vec<_> = self
            .invitations
            .iter()
            .filter(|(_, held)| past_lifetime(held))
            .map(|(link_id, _)| *link_id)
            .collect();
        for link_id in ended {
            self.invitations.remove(&link_id);
            self.changes
                .push(StoreChange::InvitationDeleted { link_id });
        }
        for queue in self.queues.values_mut() {
            queue.expire(now);
        }
        // The store drops the same records as `Queue::expire`.
        if let Some(limit) = now.checked_sub(MSG_TTL) {
            self.changes.push(StoreChange::Expired {
                accepted_before: limit.saturating_add(1),
            });
        }
        let idle: Vec<[u8; 32]> = self
            .queues
            .iter()
            .filter(|(_, queue)| queue.idle(now))
            .map(|(recipient_id, _)| *recipient_id)
            .collect();
        for recipient_id in idle {
            if let Some(queue) = self.queues.remove(&recipient_id) {
                self.by_sender.remove(&queue.keys().sender_id);
            }
            self.end_invitations(recipient_id);
            self.changes
                .push(StoreChange::QueueDeleted { recipient_id });
            self.subscribers.remove(&recipient_id);
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::store::StoredQueue;
    use umbra_core::notify::{blob::Receiver, seeded_pair};

    #[test]
    fn a_stored_queue_that_does_not_parse_leaves_the_store() {
        let mut loaded = Loaded::default();
        loaded.queues.insert(
            [1; 32],
            StoredQueue {
                head: Vec::new(),
                records: Vec::new(),
            },
        );
        loaded.invitations.insert(
            [2; LINK_ID_LEN],
            crate::store::StoredInvitation {
                recipient_id: [1; 32],
                blob: None,
                at: 0,
            },
        );
        let mut service = QueueService::restore(loaded);
        let changes = service.take_changes();
        assert!(changes.contains(&StoreChange::QueueDeleted {
            recipient_id: [1; 32]
        }));
        assert!(changes.contains(&StoreChange::InvitationDeleted {
            link_id: [2; LINK_ID_LEN]
        }));
    }
    use umbra_crypto::{
        auth::CommandAuthKey,
        rand_core::{TryCryptoRng, TryRng},
        rsabssa::PublicKey2048,
        x25519::{PublicKey as XPublic, StaticSecret},
    };
    use umbra_wire::{admission::Admission, command::NBIND_LEN};

    struct Rng(u8);
    impl TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0 = self.0.wrapping_add(1);
            dst.fill(self.0);
            Ok(())
        }
    }
    impl TryCryptoRng for Rng {}

    const CIRCUIT: CircuitKey = CircuitKey {
        link: 2,
        circ_id: [7; 16],
    };
    const NOW: u64 = 1_800_000_000;

    struct Bench {
        service: QueueService,
        session: Session,
        drains: Drains,
        gate: RelayGate,
        issuer: std::collections::BTreeMap<u32, PublicKey2048>,
        rng: Rng,
        corr: u8,
    }

    impl Bench {
        fn new() -> Self {
            let mut service = QueueService::default();
            service.set_notify_key(seeded_pair(b"test", &[3; 32]));
            Bench {
                service,
                session: Session::for_circuit(&[7; 16], StaticSecret::from([9; 32])),
                drains: Drains::default(),
                gate: RelayGate::new([1; 32]),
                issuer: std::collections::BTreeMap::new(),
                rng: Rng(0),
                corr: 0,
            }
        }

        fn send(
            &mut self,
            cmd: Cmd,
            queue_id: [u8; 32],
            payload: &[u8],
            signer: &StaticSecret,
        ) -> Result<Vec<Reply>, Reject> {
            self.corr += 1;
            let mut command = Command {
                cmd,
                corr_id: [self.corr; 16],
                queue_id,
                auth: [0; 32],
                payload,
            };
            let key = CommandAuthKey::derive(signer, &self.session.relay_session_pk()).unwrap();
            command.sign(&key, b"").unwrap();
            let accepts = Accepts::CrossRelay(&self.issuer);
            self.service.handle(
                CIRCUIT,
                &mut self.session,
                &mut self.drains,
                &mut self.gate,
                &accepts,
                &command,
                NOW,
                &mut self.rng,
            )
        }
    }

    fn payloads(replies: &[Reply]) -> Vec<(Cmd, Vec<u8>)> {
        replies
            .iter()
            .map(|reply| {
                let (command, _) =
                    Command::parse(&reply.outbound.encoded, reply.outbound.bucket).unwrap();
                (command.cmd, command.payload.to_vec())
            })
            .collect()
    }

    #[test]
    fn a_bound_queue_pushes_once_for_an_arrival_that_no_subscription_took() {
        let mut bench = Bench::new();
        let qr = StaticSecret::from([4; 32]);
        let qs = StaticSecret::from([5; 32]);
        let new = NewPayload {
            qr_auth_pk: *XPublic::from(&qr).as_bytes(),
            qs_auth_pk: *XPublic::from(&qs).as_bytes(),
            admission: Admission::NONE,
        };
        let mut out = [0u8; 128];
        let n = new.encode(&mut out).unwrap();
        let ids = bench.send(Cmd::New, [0; 32], &out[..n], &qr).unwrap();
        let ids = IdsPayload::parse(&payloads(&ids)[0].1).unwrap();

        // NTF-112: the `NPK` goes before the `NID`, under one `corr_id`.
        let answers = bench
            .send(Cmd::Nkey, ids.recipient_id, &[6; 32], &qr)
            .unwrap();
        let answers = payloads(&answers);
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].0, Cmd::Npk);
        assert_eq!(answers[1].0, Cmd::Nid);
        let relay_ntf = umbra_crypto::kem::PublicKey::from_bytes(&answers[0].1).unwrap();

        // NTF-113: the device seals its binding to that key.
        let binding = Binding {
            root: Secret::new([0x21; 32]),
            handle: [0x22; 16],
            k_tok: Secret::new([0x23; 32]),
            queue_alias: [0x24; 16],
            relay_idx: 3,
        };
        let sealed = binding
            .seal(&relay_ntf, &ids.recipient_id, &mut bench.rng)
            .unwrap();
        assert_eq!(sealed.len(), NBIND_LEN);
        let none = bench
            .send(Cmd::Nbind, ids.recipient_id, &sealed, &qr)
            .unwrap();
        assert!(none.is_empty());
        // A binding sealed for another queue does not open.
        assert!(bench
            .send(Cmd::Nbind, ids.recipient_id, &[0; NBIND_LEN], &qr)
            .is_err());

        // An arrival with no subscription gives one `NPUSH`, and a second
        // one inside the window gives none (`NTF-048`).
        let record = vec![0x55; Bucket::B0.l6_record()];
        bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        let pushes = bench.service.take_ndr_pushes();
        assert_eq!(pushes.len(), 1);
        let NdrRequest::Push {
            handle, ttl, blob, ..
        } = NdrRequest::parse(&pushes[0].request[..]).unwrap()
        else {
            panic!("not a push");
        };
        assert_eq!(handle, [0x22; 16]);
        assert_eq!(u64::from(ttl), umbra_core::notify::PUSH_TTL_MESSAGE);
        let plain = Receiver::new(Secret::new([0x21; 32]))
            .open(&blob, NOW)
            .unwrap();
        assert_eq!(plain.queue_alias, [0x24; 16]);
        assert_eq!(plain.relay_idx, 3);
        assert_eq!(plain.waiting_count, 1);

        // NTF-049: the end of the window gives the push of the second one.
        bench.service.push_tick(NOW + 10, &mut Rng(9));
        assert_eq!(bench.service.take_ndr_pushes().len(), 1);

        // NTF-128: a record that a live subscription takes gives no push.
        bench.send(Cmd::Sub, ids.recipient_id, &[], &qr).unwrap();
        bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        bench.service.push_tick(NOW + 30, &mut Rng(10));
        assert!(bench.service.take_ndr_pushes().is_empty());

        // NTF-129: the binding outlives a restart in the head.
        let mut loaded = Loaded::default();
        for change in bench.service.take_changes() {
            loaded.apply(&change);
        }
        let mut restored = QueueService::restore(loaded);
        restored.keep_notify_of(&mut bench.service);
        assert!(restored.queues[&ids.recipient_id].binding().is_some());

        // NTF-125: the answer `gone` drops the binding.
        restored.ndr_gone(&[0x22; 16]);
        assert!(restored.queues[&ids.recipient_id].binding().is_none());
    }

    /// A queue with a binding under the handle `[0x22; 16]`, with the keys
    /// of its recipient and of its sender.
    fn bound_queue(bench: &mut Bench) -> (IdsPayload, StaticSecret, StaticSecret) {
        let qr = StaticSecret::from([4; 32]);
        let qs = StaticSecret::from([5; 32]);
        let new = NewPayload {
            qr_auth_pk: *XPublic::from(&qr).as_bytes(),
            qs_auth_pk: *XPublic::from(&qs).as_bytes(),
            admission: Admission::NONE,
        };
        let mut out = [0u8; 128];
        let n = new.encode(&mut out).unwrap();
        let ids = bench.send(Cmd::New, [0; 32], &out[..n], &qr).unwrap();
        let ids = IdsPayload::parse(&payloads(&ids)[0].1).unwrap();
        let answers = bench
            .send(Cmd::Nkey, ids.recipient_id, &[6; 32], &qr)
            .unwrap();
        let relay_ntf = umbra_crypto::kem::PublicKey::from_bytes(&payloads(&answers)[0].1).unwrap();
        let binding = Binding {
            root: Secret::new([0x21; 32]),
            handle: [0x22; 16],
            k_tok: Secret::new([0x23; 32]),
            queue_alias: [0x24; 16],
            relay_idx: 3,
        };
        let sealed = binding
            .seal(&relay_ntf, &ids.recipient_id, &mut bench.rng)
            .unwrap();
        bench
            .send(Cmd::Nbind, ids.recipient_id, &sealed, &qr)
            .unwrap();
        (ids, qr, qs)
    }

    /// The expiry and the flags of one push, as the device reads them.
    fn ttl_and_flags(push: &NdrPush, now: u64) -> (u64, u8) {
        let NdrRequest::Push { ttl, blob, .. } = NdrRequest::parse(&push.request[..]).unwrap()
        else {
            panic!("not a push");
        };
        let plain = Receiver::new(Secret::new([0x21; 32]))
            .open(&blob, now)
            .unwrap();
        (u64::from(ttl), plain.flags)
    }

    #[test]
    fn a_deposit_and_a_send_push_with_one_expiry_and_the_blob_alone_names_a_digest() {
        let mut bench = Bench::new();
        let (ids, _qr, qs) = bound_queue(&mut bench);
        let relay_static = StaticSecret::from([8; 32]);
        let record = vec![0x55; Bucket::B0.l6_record()];
        let deposit = |corr: u8| {
            let key = CommandAuthKey::derive(&qs, XPublic::from(&relay_static).as_bytes()).unwrap();
            let mut command = Command {
                cmd: Cmd::Send,
                corr_id: [corr; 16],
                queue_id: ids.sender_id,
                auth: [0; 32],
                payload: &record,
            };
            command.sign(&key, b"").unwrap();
            let mut encoded = vec![0u8; command.len()];
            command.encode(&mut encoded).unwrap();
            encoded
        };

        // NTF-086: the push of a deposit carries the digest flag inside
        // its blob, and the expiry of a message push.
        let encoded = deposit(0xA1);
        let (command, _) = Command::parse(&encoded, Bucket::B0).unwrap();
        let live = bench
            .service
            .deposit(&command, &relay_static, NOW, &mut bench.rng);
        assert!(live.is_none());
        let pushes = bench.service.take_ndr_pushes();
        assert_eq!(pushes.len(), 1);
        assert_eq!(
            ttl_and_flags(&pushes[0], NOW),
            (umbra_core::notify::PUSH_TTL_MESSAGE, blob::FLAG_DIGEST)
        );
        // WIR-527: the same deposit again stores nothing and pushes nothing.
        let waiting = bench.service.queues[&ids.recipient_id].waiting();
        assert!(bench
            .service
            .deposit(&command, &relay_static, NOW + 60, &mut bench.rng)
            .is_none());
        assert_eq!(bench.service.queues[&ids.recipient_id].waiting(), waiting);
        assert!(bench.service.take_ndr_pushes().is_empty());

        // NTF-065: a `SEND` after the window pushes as a message, with
        // the same expiry.
        let later = NOW + 60;
        let mut command = Command {
            cmd: Cmd::Send,
            corr_id: [0xB1; 16],
            queue_id: ids.sender_id,
            auth: [0; 32],
            payload: &record,
        };
        let key = CommandAuthKey::derive(&qs, &bench.session.relay_session_pk()).unwrap();
        command.sign(&key, b"").unwrap();
        let accepts = Accepts::CrossRelay(&bench.issuer);
        bench
            .service
            .handle(
                CIRCUIT,
                &mut bench.session,
                &mut bench.drains,
                &mut bench.gate,
                &accepts,
                &command,
                later,
                &mut bench.rng,
            )
            .unwrap();
        let pushes = bench.service.take_ndr_pushes();
        assert_eq!(pushes.len(), 1);
        assert_eq!(
            ttl_and_flags(&pushes[0], later),
            (umbra_core::notify::PUSH_TTL_MESSAGE, 0)
        );
    }

    /// The sequence of each `MSG` among `records`.
    fn seqs(records: &[Outbound]) -> Vec<u32> {
        records
            .iter()
            .map(|outbound| {
                let (command, _) = Command::parse(&outbound.encoded, outbound.bucket).unwrap();
                assert_eq!(command.cmd, Cmd::Msg);
                u32::from_be_bytes(command.payload[..4].try_into().unwrap())
            })
            .collect()
    }

    #[test]
    fn a_sub_of_a_long_backlog_leaves_a_drain_that_steps_through_the_queue() {
        let mut bench = Bench::new();
        let (ids, qr, qs) = bound_queue(&mut bench);
        let record = vec![0x55; Bucket::B0.l6_record()];
        let count = u32::try_from(DRAIN_THRESHOLD).unwrap() + 5;
        for _ in 0..count {
            bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        }
        // NET-037, NET-349: the `SUB` gives no `MSG` and copies no record.
        // It leaves a drain that names each record that no `ACK` covers.
        let replies = bench.send(Cmd::Sub, ids.recipient_id, &[], &qr).unwrap();
        assert!(replies.is_empty());
        let held = bench.drains.of(&ids.recipient_id).unwrap().clone();
        let first = bench.service.queues[&ids.recipient_id].last_ack() + 1;
        assert_eq!((held.after, held.end), (first - 1, first + count));
        assert_eq!(held.left, record.len() * DRAIN_THRESHOLD + record.len() * 5);
        // A record that arrives now goes as a live `MSG`, and the drain
        // does not name it.
        let replies = bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        assert_eq!(replies.len(), 2);

        // Each step gives the next records, about the room that it has.
        let mut drain = held;
        let room = 3 * record.len();
        let mut taken = Vec::new();
        let mut steps = 0;
        loop {
            let (records, ended) =
                bench
                    .service
                    .drain_step(&CIRCUIT, &mut drain, room, &mut bench.rng);
            steps += 1;
            taken.extend(seqs(&records));
            if ended {
                break;
            }
            assert_eq!(records.len(), 3);
        }
        assert!(steps > 20);
        assert_eq!(taken, (first..first + count).collect::<Vec<u32>>());
        assert_eq!(drain.left, 0);

        // An `ACK` in the middle of a drain takes its records out of it.
        let mut drain = bench.drains.of(&ids.recipient_id).unwrap().clone();
        let acked = first + 9;
        bench
            .send(Cmd::Ack, ids.recipient_id, &acked.to_be_bytes(), &qr)
            .unwrap();
        let (records, _) =
            bench
                .service
                .drain_step(&CIRCUIT, &mut drain, usize::MAX, &mut bench.rng);
        assert_eq!(
            seqs(&records),
            (acked + 1..first + count).collect::<Vec<u32>>()
        );
        // A drain of a queue whose subscription went to another circuit
        // ends, and so does the drain of an `UNSUB`.
        let other = CircuitKey {
            link: 9,
            circ_id: [1; 16],
        };
        let mut drain = bench.drains.of(&ids.recipient_id).unwrap().clone();
        assert_eq!(
            bench
                .service
                .drain_step(&other, &mut drain, usize::MAX, &mut bench.rng),
            (Vec::new(), true)
        );
        bench.send(Cmd::Unsub, ids.recipient_id, &[], &qr).unwrap();
        assert!(bench.drains.is_empty());
    }

    #[test]
    fn a_refused_sub_leaves_no_subscription_and_its_arrivals_take_their_push() {
        let mut bench = Bench::new();
        let (ids, qr, qs) = bound_queue(&mut bench);
        let record = vec![0x55; Bucket::B0.l6_record()];
        for _ in 0..=DRAIN_THRESHOLD {
            bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        }
        // The circuit asks for its drains of one minute. Each one takes the
        // place of the one before it.
        for _ in 0..crate::service::DRAINS_PER_MINUTE {
            assert!(bench
                .send(Cmd::Sub, ids.recipient_id, &[], &qr)
                .unwrap()
                .is_empty());
        }
        assert!(bench.service.subscribers.contains_key(&ids.recipient_id));
        bench.service.push_tick(NOW + 20, &mut Rng(8));
        drop(bench.service.take_ndr_pushes());
        // NET-349: one more gets `LIMIT`. It leaves no subscription and no
        // drain. Before this, the relay kept the subscription of a refused
        // `SUB`. Each later record then went as a live `MSG` above a backlog
        // that never left.
        assert_eq!(
            bench.send(Cmd::Sub, ids.recipient_id, &[], &qr),
            Err(Reject::Limit)
        );
        assert!(!bench.service.subscribers.contains_key(&ids.recipient_id));
        assert!(!bench.service.queues[&ids.recipient_id].subscribed());
        assert!(bench.drains.is_empty());
        // NTF-128: the next record is an arrival that no subscription took:
        // it gives the `QUOTA` alone, and it takes its push.
        let replies = bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        assert_eq!(replies.len(), 1);
        bench.service.push_tick(NOW + 40, &mut Rng(9));
        assert_eq!(bench.service.take_ndr_pushes().len(), 1);
    }

    #[test]
    fn a_subscription_that_ends_before_the_ack_gives_no_push() {
        let mut bench = Bench::new();
        let (ids, qr, qs) = bound_queue(&mut bench);
        let record = vec![0x55; Bucket::B0.l6_record()];

        // NET-050: a client holds its `ACK` for `RECEIPT_MIN_DELAY`, thus
        // a circuit that ends soon after an arrival leaves the record
        // with no `ACK`. The device holds it, and no push goes.
        bench.send(Cmd::Sub, ids.recipient_id, &[], &qr).unwrap();
        let replies = bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        assert_eq!(replies.len(), 2);
        bench.service.circuit_closed(&CIRCUIT, NOW + 2);
        bench.service.push_tick(NOW + 3, &mut Rng(10));
        assert!(bench.service.take_ndr_pushes().is_empty());

        // The same holds for an `UNSUB`.
        bench.send(Cmd::Sub, ids.recipient_id, &[], &qr).unwrap();
        bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        bench.send(Cmd::Unsub, ids.recipient_id, &[], &qr).unwrap();
        bench.service.push_tick(NOW + 4, &mut Rng(11));
        assert!(bench.service.take_ndr_pushes().is_empty());

        // A record that arrives with no subscription takes its push.
        bench.send(Cmd::Send, ids.sender_id, &record, &qs).unwrap();
        bench.service.push_tick(NOW + 5, &mut Rng(12));
        assert_eq!(bench.service.take_ndr_pushes().len(), 1);
    }
}
