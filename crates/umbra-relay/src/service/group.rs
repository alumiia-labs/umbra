//! The group queues of one relay (Part 3 §3.2.7, Part 6 §6.4.5): the
//! eleven commands `GNEW`, `GPOST`, `GSUB`, `GUNSUB`, `GKEY`, `GDEL`,
//! `GNREG`, and `GNUNREG`, with the answer of each one and the `GMSG` that
//! goes to each circuit that subscribed.
//!
//! The relay holds no member list and no per-reader cursor (`NET-227`,
//! `NET-228`). A reader names its own `from_seq` at each `GSUB`.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};

use umbra_core::{
    abuse::admission::{Accepts, RelayGate},
    notify::{
        digest::{DigestGate, Policy},
        GROUP_DIGEST_MIN_GAP,
    },
};
use umbra_crypto::{
    rand_core::CryptoRng,
    stored::{Reader, Writer},
};
use umbra_queue::{
    params::{store_time, DRAIN_THRESHOLD},
    relay::{group::GroupQueue, session::Session, Stored},
    Reject,
};
use umbra_wire::{
    address::LEN as QUEUE_ADDRESS_LEN,
    command::{Cmd, Command},
    group::{
        encode_gmsg, parse_gsub, GkeyPayload, GnewPayload, GroupCmd, GroupNotifyRegistration,
        GseqPayload, GSEQ_LEN,
    },
};

use super::{answer, DigestDue, Drain, Drains, Outbound, Reply, BUCKETS};
use crate::{
    circuits::CircuitKey,
    store::{Loaded, StoreChange},
};

/// One group queue with the state that the relay holds beside it.
struct Served {
    queue: GroupQueue,
    digests: DigestGate,
    /// The address of each registered notify queue, by its `sender_id`.
    /// The relay holds it in memory only (`NTF-100`).
    notify: BTreeMap<[u8; 32], [u8; QUEUE_ADDRESS_LEN]>,
    /// The digests that are due and that wait for the turn of this queue.
    /// The map gives the post count of each one, by the `sender_id` of its
    /// notify queue.
    waiting: BTreeMap<[u8; 32], u8>,
    /// The count of the registrations that each circuit made. It names no
    /// registration, thus it links none to a session (`NTF-095`).
    registered_by: BTreeMap<CircuitKey, u8>,
    /// The circuits that subscribed. A group queue has many readers, and
    /// the relay holds no cursor of any of them.
    subscribers: Vec<CircuitKey>,
}

impl Served {
    fn new(queue: GroupQueue) -> Self {
        Served {
            queue,
            digests: DigestGate::new(Policy::Group),
            notify: BTreeMap::new(),
            waiting: BTreeMap::new(),
            registered_by: BTreeMap::new(),
            subscribers: Vec::new(),
        }
    }
}

/// The digests that the relay hands out in one second, over all its group
/// queues. Each one costs the node a seal and a signature, and each one for
/// another relay costs a connection. One post of a group with
/// `GROUP_NOTIFIER_MAX` registrations thus does not hold the node for the
/// time of them all. A digest above the bound waits for the next second.
pub const DIGESTS_PER_SECOND: usize = 512;

/// The registrations that one circuit makes for one group queue. A device
/// holds one notify queue for a group, and two while it rotates that queue
/// (`NTF-105`). A party that fills a group queue with registrations thus
/// builds one circuit for each four of them.
pub const GNREG_PER_CIRCUIT: u8 = 4;

/// The group queues that the relay serves, by `GroupQueueId`.
#[derive(Default)]
pub struct GroupService {
    served: BTreeMap<[u8; 32], Served>,
    /// The changes since the last [`GroupService::take_changes`].
    changes: Vec<StoreChange>,
    /// The group queues that hold a digest that waits.
    waiting: BTreeSet<[u8; 32]>,
    /// The group queues whose post left a digest for the end of the gap,
    /// with a time at which each such gap ended (`NTF-098`). The clock
    /// looks at these queues alone, and at each one until that time.
    gapped: BTreeMap<[u8; 32], u64>,
    /// The second of the clock, and the digests handed out in it.
    handed: (u64, usize),
    /// The group queue that took the last turn of the last hand-out. The
    /// next one starts after it, thus no group queue holds the others back.
    /// Each group queue that waits takes its turn, however many wait.
    turn: Option<[u8; 32]>,
}

/// The `GMSG` of one record, in the bucket that the record length gives.
/// The bucket of a `GPOST` and of its `GMSG` is one (`WIR-372`).
fn gmsg_of<R: CryptoRng + ?Sized>(
    group_queue_id: [u8; 32],
    seq: u32,
    record: &[u8],
    rng: &mut R,
) -> Option<Outbound> {
    let bucket = BUCKETS
        .into_iter()
        .find(|bucket| bucket.group_record() == record.len())?;
    let mut payload = vec![0u8; bucket.l5_payload()];
    encode_gmsg(seq, record, bucket, &mut payload).ok()?;
    let mut corr_id = [0u8; 16];
    // WIR-495: a command that the relay starts draws its own corr_id.
    rng.fill_bytes(&mut corr_id);
    let command = Command {
        cmd: Cmd::Group(GroupCmd::Gmsg),
        corr_id,
        queue_id: group_queue_id,
        auth: [0; 32],
        payload: &payload,
    };
    let mut encoded = vec![0u8; command.len()];
    command.encode(&mut encoded).ok()?;
    Some(Outbound { bucket, encoded })
}

/// Verifies a command under the current credential, and under the previous
/// one while its grace holds (`NET-243`, `WIR-393`, `WIR-394`).
fn accept_either(
    session: &mut Session,
    command: &Command<'_>,
    keys: ([u8; 32], Option<[u8; 32]>),
) -> Result<(), Reject> {
    let (current, previous) = keys;
    match session.accept(command, &current) {
        Ok(()) => Ok(()),
        Err(refused) => match previous {
            Some(previous) => session.accept(command, &previous),
            None => Err(refused),
        },
    }
}

fn sender_id_of(queue: &[u8; QUEUE_ADDRESS_LEN]) -> [u8; 32] {
    umbra_crypto::bytes::part::<33, 32, QUEUE_ADDRESS_LEN>(queue)
}

impl GroupService {
    /// The group queues of an earlier run. A queue whose stored form has
    /// a fault is dropped, and the others stay. Each live session and
    /// each subscription of that run is gone, and the members open them
    /// again.
    pub fn restore(loaded: &Loaded) -> Self {
        let mut service = GroupService::default();
        for (group_queue_id, stored) in &loaded.group_queues {
            let mut reader = Reader::new(&stored.head);
            let restored = GroupQueue::restore(&mut reader, stored.records.clone())
                .ok()
                .filter(|queue| queue.id() == *group_queue_id);
            let Some(queue) = restored else {
                // NET-302, NET-303: a queue that serves no one leaves the
                // file too.
                service.changes.push(StoreChange::GroupQueueDeleted {
                    group_queue_id: *group_queue_id,
                });
                continue;
            };
            service.served.insert(*group_queue_id, Served::new(queue));
        }
        service
    }

    /// The changes since the last call. The process commits them before it
    /// sends an output of the same call (`NET-298`).
    pub fn take_changes(&mut self) -> Vec<StoreChange> {
        core::mem::take(&mut self.changes)
    }

    /// Records the head of a group queue after a change of it.
    fn head_changed(&mut self, group_queue_id: [u8; 32]) {
        if let Some(served) = self.served.get(&group_queue_id) {
            let mut writer = Writer::new();
            served.queue.export_head(&mut writer);
            self.changes.push(StoreChange::GroupQueue {
                group_queue_id,
                head: writer.finish().to_vec(),
            });
        }
    }

    /// The count of the group queues.
    pub fn len(&self) -> usize {
        self.served.len()
    }

    /// Whether the relay serves no group queue.
    pub fn is_empty(&self) -> bool {
        self.served.is_empty()
    }

    /// Handles one command of the group range on `circuit`, and returns the
    /// answer with the `GMSG` of a fresh record and the digests it made due.
    /// A `GSUB` with a backlog above `DRAIN_THRESHOLD` gives no `GMSG`. It
    /// leaves a drain in `drains`, and the node asks for its records in
    /// steps ([`GroupService::drain_step`]).
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
    ) -> Result<(Vec<Reply>, Vec<DigestDue>), Reject> {
        let Cmd::Group(cmd) = command.cmd else {
            return Err(Reject::Rejected);
        };
        if cmd == GroupCmd::Gnew {
            return Ok((
                vec![self.create(circuit, session, gate, accepts, command, now, rng)?],
                Vec::new(),
            ));
        }
        // WIR-317: an unknown group queue and a failed auth give one reason.
        let group_queue_id = command.queue_id;
        let served = self
            .served
            .get_mut(&group_queue_id)
            .ok_or(Reject::Rejected)?;
        match cmd {
            GroupCmd::Gpost => {
                accept_either(session, command, served.queue.write_pks(now))?;
                // WIR-370: a post fills the record row of one bucket.
                // WIR-408, WIR-409: the relay reads the version and the kind
                // of the record, and refuses one that the table does not hold.
                let payload = command.payload;
                let fills_bucket = BUCKETS
                    .into_iter()
                    .any(|bucket| bucket.group_record() == payload.len());
                let is_known = payload.first() == Some(&umbra_wire::group::record::VERSION)
                    && matches!(payload.get(1), Some(0x01 | 0x02));
                if !fills_bucket || !is_known {
                    return Err(Reject::Rejected);
                }
                // WIR-374: a post carries no admission.
                let posted = served.queue.post(command.payload, now)?;
                if posted.fresh {
                    self.changes.push(StoreChange::GroupRecord {
                        group_queue_id,
                        record: Stored {
                            seq: posted.seq,
                            accepted_at: store_time(now),
                            bytes: command.payload.to_vec(),
                        },
                    });
                    if let Some(through_seq) = posted.dropped_through {
                        self.changes.push(StoreChange::GroupTrimmed {
                            group_queue_id,
                            through_seq,
                        });
                    }
                    self.head_changed(group_queue_id);
                }
                let served = self
                    .served
                    .get_mut(&group_queue_id)
                    .ok_or(Reject::Rejected)?;
                let mut replies = vec![answer(
                    circuit,
                    command,
                    Cmd::Group(GroupCmd::Gseq),
                    &Self::gseq(command.corr_id, posted.seq)?,
                )];
                let mut is_due = false;
                if posted.fresh {
                    // WIR-388: each session that subscribed takes the record.
                    for subscriber in &served.subscribers {
                        if let Some(outbound) =
                            gmsg_of(group_queue_id, posted.seq, command.payload, rng)
                        {
                            replies.push(Reply {
                                circuit: *subscriber,
                                outbound,
                            });
                        }
                    }
                    // NTF-096: each registration takes its digest. NTF-098:
                    // one that the gap holds back goes at the end of the gap.
                    // The clock looks at the queue until the gap of this
                    // post ended. Before this, the time of an earlier post
                    // stayed, and a digest that this post left waited for
                    // the next post or for the sweep.
                    if Self::digests_of(served, Tick::Post(now)) {
                        let end = now.saturating_add(GROUP_DIGEST_MIN_GAP);
                        self.gapped
                            .entry(group_queue_id)
                            .and_modify(|held| *held = (*held).max(end))
                            .or_insert(end);
                    }
                    is_due = !served.waiting.is_empty();
                }
                if is_due {
                    self.waiting.insert(group_queue_id);
                }
                Ok((replies, self.release(now)))
            }
            GroupCmd::Gsub => {
                accept_either(session, command, served.queue.read_pks(now))?;
                let from_seq = parse_gsub(command.payload).map_err(|_| Reject::Rejected)?;
                // NET-237, NET-349: a backlog above the threshold is a
                // drain. The relay reads the bound from the lengths of the
                // records before it copies one of them.
                let is_drain = served.queue.since(from_seq).nth(DRAIN_THRESHOLD).is_some();
                let named = if is_drain {
                    let lengths = served
                        .queue
                        .since(from_seq)
                        .map(|stored| stored.bytes.len());
                    match drains.admit(&group_queue_id, lengths, now) {
                        Ok(bytes) => Some(bytes),
                        Err(reject) => {
                            // A refused `GSUB` leaves no subscription, thus
                            // no `GMSG` goes above a backlog that never
                            // left.
                            served.subscribers.retain(|held| *held != circuit);
                            drains.end(&group_queue_id);
                            return Err(reject);
                        }
                    }
                } else {
                    None
                };
                session.bind_queue(group_queue_id)?;
                // NET-250: a `GSUB` is activity of the queue.
                served.queue.touch(now);
                self.changes.push(StoreChange::GroupQueue {
                    group_queue_id,
                    head: {
                        let mut writer = Writer::new();
                        served.queue.export_head(&mut writer);
                        writer.finish().to_vec()
                    },
                });
                let served = self
                    .served
                    .get_mut(&group_queue_id)
                    .ok_or(Reject::Rejected)?;
                if !served.subscribers.contains(&circuit) {
                    served.subscribers.push(circuit);
                }
                if let Some(left) = named {
                    drains.hold(Drain {
                        queue_id: group_queue_id,
                        after: from_seq,
                        end: served.queue.next_seq(),
                        left,
                    });
                    return Ok((Vec::new(), Vec::new()));
                }
                drains.end(&group_queue_id);
                // WIR-387: each retained record above `from_seq`, in order.
                Ok((
                    served
                        .queue
                        .since(from_seq)
                        .filter_map(|stored| {
                            gmsg_of(group_queue_id, stored.seq, &stored.bytes, rng)
                        })
                        .map(|outbound| Reply { circuit, outbound })
                        .collect(),
                    Vec::new(),
                ))
            }
            GroupCmd::Gunsub => {
                accept_either(session, command, served.queue.read_pks(now))?;
                served.subscribers.retain(|held| *held != circuit);
                drains.end(&group_queue_id);
                Ok((Vec::new(), Vec::new()))
            }
            GroupCmd::Gnreg | GroupCmd::Gnunreg => {
                accept_either(session, command, served.queue.read_pks(now))?;
                // WIR-401: the version of the registration.
                GroupNotifyRegistration::parse(command.payload).map_err(|_| Reject::Rejected)?;
                let address: [u8; QUEUE_ADDRESS_LEN] = command
                    .payload
                    .get(1..)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Reject::Rejected)?;
                let sender_id = sender_id_of(&address);
                if cmd == GroupCmd::Gnreg {
                    // A registration that the queue holds already is no new
                    // one, and it counts for no circuit.
                    let is_new = !served.notify.contains_key(&sender_id);
                    let made = served.registered_by.entry(circuit).or_insert(0);
                    if is_new && *made >= GNREG_PER_CIRCUIT {
                        return Err(Reject::Limit);
                    }
                    // NET-252: the count bound answers with `LIMIT`.
                    served
                        .digests
                        .register(sender_id, now)
                        .map_err(|_| Reject::Limit)?;
                    if is_new {
                        *made = made.saturating_add(1);
                    }
                    served.notify.insert(sender_id, address);
                } else {
                    served.digests.unregister(&sender_id);
                    served.notify.remove(&sender_id);
                    served.waiting.remove(&sender_id);
                }
                Ok((Vec::new(), Vec::new()))
            }
            GroupCmd::Gkey => {
                session.accept(command, &served.queue.own_pk())?;
                let keys = GkeyPayload::parse(command.payload).map_err(|_| Reject::Rejected)?;
                served
                    .queue
                    .rotate(keys.read_pk, keys.write_pk, keys.own_pk, now);
                self.head_changed(group_queue_id);
                Ok((Vec::new(), Vec::new()))
            }
            GroupCmd::Gdel => {
                session.accept(command, &served.queue.own_pk())?;
                // NET-022: the place of the queue serves the next one.
                session.unbind_queue(&group_queue_id);
                drains.end(&group_queue_id);
                // NET-244, NET-245: the records, the notifiers, and the
                // identifier leave together.
                if let Some(served) = self.served.remove(&group_queue_id) {
                    drop(served.queue.delete());
                }
                self.forget(&group_queue_id);
                self.changes
                    .push(StoreChange::GroupQueueDeleted { group_queue_id });
                Ok((Vec::new(), Vec::new()))
            }
            // A relay does not take the commands that it sends.
            GroupCmd::Gnew | GroupCmd::Gids | GroupCmd::Gseq | GroupCmd::Gmsg => {
                Err(Reject::Rejected)
            }
        }
    }

    /// A `GNEW`: the admission of Part 13, a `GroupQueueId` from the relay
    /// CSPRNG, and one `GIDS` in the same session (`WIR-373`, `WIR-376`,
    /// `WIR-377`).
    #[allow(clippy::too_many_arguments)]
    fn create<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
        gate: &mut RelayGate,
        accepts: &Accepts<'_>,
        command: &Command<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Reply, Reject> {
        let new = GnewPayload::parse(command.payload).map_err(|_| Reject::Rejected)?;
        // NET-260: the creator authorizes its own `GNEW` under the owner
        // credential of the payload, as a `NEW` goes under `QR_auth_pk`.
        session.accept(command, &new.own_pk)?;
        session.room()?;
        gate.admit(&new.admission, accepts, now)?;
        let mut group_queue_id = [0u8; 32];
        rng.fill_bytes(&mut group_queue_id);
        session.bind_queue(group_queue_id)?;
        self.served.insert(
            group_queue_id,
            Served::new(GroupQueue::new(
                group_queue_id,
                new.read_pk,
                new.write_pk,
                new.own_pk,
                now,
            )),
        );
        self.head_changed(group_queue_id);
        Ok(answer(
            circuit,
            command,
            Cmd::Group(GroupCmd::Gids),
            &group_queue_id,
        ))
    }

    fn gseq(corr_id: [u8; 16], seq: u32) -> Result<[u8; GSEQ_LEN], Reject> {
        let mut payload = [0u8; GSEQ_LEN];
        GseqPayload { corr_id, seq }
            .encode(&mut payload)
            .map_err(|_| Reject::Busy)?;
        Ok(payload)
    }

    /// Puts the digests that a post or the clock made due among those that
    /// wait for the turn of the queue. A registration that waits already
    /// takes the posts of both in one digest. The result is whether a post
    /// left a registration for the end of the gap.
    fn digests_of(served: &mut Served, now: Tick) -> bool {
        let (due, is_post) = match now {
            Tick::Post(at) => (served.digests.on_post(at), true),
            Tick::Clock(at) => (served.digests.tick(at), false),
        };
        let held_back = is_post && due.len() < served.digests.len();
        for digest in due {
            let count = served.waiting.entry(digest.queue).or_insert(0);
            *count = count.saturating_add(digest.post_count);
        }
        held_back
    }

    /// Hands out the digests that wait, at most `DIGESTS_PER_SECOND` in one
    /// second of the clock over all group queues. Each group queue that
    /// waits takes an equal share, in turns, and then what the others left.
    /// Thus a group queue with many registrations holds back neither the
    /// node nor the digests of another group queue.
    fn release(&mut self, now: u64) -> Vec<DigestDue> {
        if self.handed.0 != now {
            self.handed = (now, 0);
        }
        let mut left = DIGESTS_PER_SECOND.saturating_sub(self.handed.1);
        if left == 0 || self.waiting.is_empty() {
            return Vec::new();
        }
        let order: Vec<[u8; 32]> = match self.turn {
            Some(turn) => self
                .waiting
                .range((Bound::Excluded(turn), Bound::Unbounded))
                .chain(self.waiting.range(..=turn))
                .copied()
                .collect(),
            None => self.waiting.iter().copied().collect(),
        };
        let share = (left / order.len().max(1)).max(1);
        let mut out = Vec::new();
        // The last group queue that took a digest in the turns of the
        // shares.
        let mut last = None;
        for (is_share, limit) in [(true, share), (false, usize::MAX)] {
            for group_queue_id in &order {
                let Some(served) = self.served.get_mut(group_queue_id) else {
                    continue;
                };
                let mut turn_left = limit.min(left);
                if is_share && turn_left > 0 && !served.waiting.is_empty() {
                    last = Some(*group_queue_id);
                }
                while turn_left > 0 {
                    let Some((sender_id, post_count)) = served.waiting.pop_first() else {
                        break;
                    };
                    turn_left = turn_left.saturating_sub(1);
                    left = left.saturating_sub(1);
                    // NTF-099: the digest names no record and no member.
                    if let Some(queue) = served.notify.get(&sender_id) {
                        out.push(DigestDue {
                            id: *group_queue_id,
                            queue: *queue,
                            post_count,
                        });
                    }
                }
            }
        }
        let served = &self.served;
        self.waiting.retain(|group_queue_id| {
            served
                .get(group_queue_id)
                .is_some_and(|served| !served.waiting.is_empty())
        });
        // Before this, the turn moved by one group queue at each call. With
        // more group queues than digests of one second, the same ones then
        // took each turn, and the others waited for them all.
        self.turn = last.or(self.turn);
        self.handed.1 = DIGESTS_PER_SECOND.saturating_sub(left);
        out
    }

    /// The digests due at `now`. A digest is due when the gap of its group
    /// queue held it back and that gap ended (`NTF-098`). A digest that
    /// waited for its turn is due too. The runtime calls it about once each
    /// second.
    pub fn digest_tick(&mut self, now: u64) -> Vec<DigestDue> {
        for group_queue_id in self.gapped.keys() {
            if let Some(served) = self.served.get_mut(group_queue_id) {
                Self::digests_of(served, Tick::Clock(now));
                if !served.waiting.is_empty() {
                    self.waiting.insert(*group_queue_id);
                }
            }
        }
        self.gapped.retain(|_, end| *end > now);
        self.release(now)
    }

    /// The next records of `drain`, as `GMSG` commands of about `room`
    /// bytes together, and whether the drain ended. The step stops after
    /// the record that reaches `room`, thus each step moves the drain. A
    /// drain ends at its last record, and when the group queue left.
    pub fn drain_step<R: CryptoRng + ?Sized>(
        &self,
        drain: &mut Drain,
        room: usize,
        rng: &mut R,
    ) -> (Vec<Outbound>, bool) {
        let Some(served) = self.served.get(&drain.queue_id) else {
            return (Vec::new(), true);
        };
        let mut out = Vec::new();
        let mut sent = 0usize;
        for stored in served.queue.since(drain.after) {
            if stored.seq >= drain.end {
                break;
            }
            if sent >= room {
                return (out, false);
            }
            drain.after = stored.seq;
            drain.left = drain.left.saturating_sub(stored.bytes.len());
            if let Some(outbound) = gmsg_of(drain.queue_id, stored.seq, &stored.bytes, rng) {
                sent = sent.saturating_add(outbound.encoded.len());
                out.push(outbound);
            }
        }
        (out, true)
    }

    /// Drops what the service holds beside a group queue that left.
    fn forget(&mut self, group_queue_id: &[u8; 32]) {
        self.waiting.remove(group_queue_id);
        self.gapped.remove(group_queue_id);
    }

    /// A circuit ended, thus its subscriptions end.
    pub fn circuit_closed(&mut self, circuit: &CircuitKey) {
        for served in self.served.values_mut() {
            served.subscribers.retain(|held| held != circuit);
            served.registered_by.remove(circuit);
        }
    }

    /// The client of a circuit paused its session (`WIR-546`): each
    /// subscription of the circuit ends. The circuit stays, and with it the
    /// count of its registrations.
    pub fn circuit_paused(&mut self, circuit: &CircuitKey) {
        for served in self.served.values_mut() {
            served.subscribers.retain(|held| held != circuit);
        }
    }

    /// The periodic work: the retention of each queue, the digests that the
    /// gap held back, and each queue past `GROUP_IDLE_TTL`.
    pub fn sweep(&mut self, now: u64) -> Vec<DigestDue> {
        let mut trimmed = Vec::new();
        for (group_queue_id, served) in &mut self.served {
            if let Some(through_seq) = served.queue.expire(now) {
                trimmed.push(StoreChange::GroupTrimmed {
                    group_queue_id: *group_queue_id,
                    through_seq,
                });
            }
            Self::digests_of(served, Tick::Clock(now));
            let digests = &served.digests;
            // NTF-102: the address leaves with its registration.
            served
                .notify
                .retain(|sender_id, _| digests.holds(sender_id));
            served
                .waiting
                .retain(|sender_id, _| digests.holds(sender_id));
            if !served.waiting.is_empty() {
                self.waiting.insert(*group_queue_id);
            }
        }
        self.changes.append(&mut trimmed);
        // NET-249: a queue with no post and no subscription leaves.
        let idle: Vec<[u8; 32]> = self
            .served
            .iter()
            .filter(|(_, served)| served.queue.idle(now))
            .map(|(group_queue_id, _)| *group_queue_id)
            .collect();
        for group_queue_id in idle {
            self.served.remove(&group_queue_id);
            self.forget(&group_queue_id);
            self.changes
                .push(StoreChange::GroupQueueDeleted { group_queue_id });
        }
        self.digest_tick(now)
    }
}

enum Tick {
    Post(u64),
    Clock(u64),
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
    use umbra_crypto::{
        auth::CommandAuthKey,
        rsabssa::PublicKey2048,
        secret::Secret,
        x25519::{PublicKey as XPublic, StaticSecret},
    };
    use umbra_queue::params::{GROUP_IDLE_TTL, GROUP_WRITE_GRACE};
    use umbra_wire::bucket::Bucket;
    use umbra_wire::{
        address::QueueAddress,
        admission::Admission,
        group::{split_gmsg, NOTIFY_REGISTRATION_LEN},
    };

    struct Rng(u8);
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from(self.0))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.0))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0 = self.0.wrapping_add(1);
            dst.fill(self.0);
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    const CIRCUIT: CircuitKey = CircuitKey {
        link: 1,
        circ_id: [9; 16],
    };
    const OTHER: CircuitKey = CircuitKey {
        link: 2,
        circ_id: [8; 16],
    };

    struct Relay {
        service: GroupService,
        session: Session,
        drains: Drains,
        gate: RelayGate,
        issuer: std::collections::BTreeMap<u32, PublicKey2048>,
        relay_pk: [u8; 32],
        rng: Rng,
        corr: u16,
    }

    impl Relay {
        fn new() -> Self {
            let relay_sk = StaticSecret::from([7u8; 32]);
            let relay_pk = *XPublic::from(&relay_sk).as_bytes();
            Relay {
                service: GroupService::default(),
                session: Session::for_circuit(&[9; 16], relay_sk),
                drains: Drains::default(),
                gate: RelayGate::new([3; 32]),
                issuer: std::collections::BTreeMap::new(),
                relay_pk,
                rng: Rng(0x40),
                corr: 0,
            }
        }

        /// One authorized command of a member that holds `auth_sk`.
        fn send(
            &mut self,
            circuit: CircuitKey,
            cmd: GroupCmd,
            queue_id: [u8; 32],
            payload: &[u8],
            auth_sk: &StaticSecret,
            now: u64,
        ) -> Result<(Vec<Reply>, Vec<DigestDue>), Reject> {
            self.corr = self.corr.wrapping_add(1);
            let key = CommandAuthKey::derive(auth_sk, &self.relay_pk).unwrap();
            let mut corr_id = [0u8; 16];
            corr_id[..2].copy_from_slice(&self.corr.to_be_bytes());
            let mut command = Command {
                cmd: Cmd::Group(cmd),
                corr_id,
                queue_id,
                auth: [0; 32],
                payload,
            };
            command.sign(&key, b"").unwrap();
            let accepts = Accepts::CrossRelay(&self.issuer);
            self.service.handle(
                circuit,
                &mut self.session,
                &mut self.drains,
                &mut self.gate,
                &accepts,
                &command,
                now,
                &mut self.rng,
            )
        }
    }

    fn public(sk: &StaticSecret) -> [u8; 32] {
        *XPublic::from(sk).as_bytes()
    }

    /// A content record of bucket `B0`: the version and the kind of
    /// `WIR-409`, and a fill.
    fn record(byte: u8) -> Vec<u8> {
        let mut record = vec![byte; Bucket::B0.group_record()];
        record[0] = umbra_wire::group::record::VERSION;
        record[1] = 0x01;
        record
    }

    fn registration(sender: u8) -> Vec<u8> {
        registration_of([sender; 32])
    }

    fn registration_of(sender_id: [u8; 32]) -> Vec<u8> {
        let mut payload = vec![0u8; NOTIFY_REGISTRATION_LEN];
        GroupNotifyRegistration {
            queue: QueueAddress {
                relay_id: [1; 32],
                sender_id,
                qs_auth_sk: Secret::new([2; 32]),
                qe: Secret::new([3; 32]),
            },
        }
        .encode(&mut payload)
        .unwrap();
        payload
    }

    /// A group queue with its three credentials, and the relay that holds it.
    fn opened(now: u64) -> (Relay, [u8; 32], StaticSecret, StaticSecret, StaticSecret) {
        let (read, write, own) = (
            StaticSecret::from([11u8; 32]),
            StaticSecret::from([12u8; 32]),
            StaticSecret::from([13u8; 32]),
        );
        let mut relay = Relay::new();
        let id = created(&mut relay, &read, &write, &own, now);
        (relay, id, read, write, own)
    }

    /// One more group queue of `relay` under the three credentials.
    fn created(
        relay: &mut Relay,
        read: &StaticSecret,
        write: &StaticSecret,
        own: &StaticSecret,
        now: u64,
    ) -> [u8; 32] {
        let mut payload = vec![0u8; 200];
        let used = GnewPayload {
            read_pk: public(read),
            write_pk: public(write),
            own_pk: public(own),
            admission: Admission::NONE,
        }
        .encode(&mut payload)
        .unwrap();
        payload.truncate(used);
        let (replies, _) = relay
            .send(CIRCUIT, GroupCmd::Gnew, [0; 32], &payload, own, now)
            .unwrap();
        let (gids, _) = Command::parse(&replies[0].outbound.encoded, Bucket::B0).unwrap();
        assert_eq!(gids.cmd, Cmd::Group(GroupCmd::Gids));
        gids.payload.try_into().unwrap()
    }

    /// The registration of index `index`, from a circuit of its own for
    /// each `GNREG_PER_CIRCUIT` of them.
    fn register_many(relay: &mut Relay, id: [u8; 32], read: &StaticSecret, count: u16, now: u64) {
        for index in 0..count {
            let mut sender_id = [0x70u8; 32];
            sender_id[..2].copy_from_slice(&index.to_be_bytes());
            let mut circ_id = [0x60u8; 16];
            circ_id[..2].copy_from_slice(&(index / u16::from(GNREG_PER_CIRCUIT)).to_be_bytes());
            let circuit = CircuitKey { link: 5, circ_id };
            relay
                .send(
                    circuit,
                    GroupCmd::Gnreg,
                    id,
                    &registration_of(sender_id),
                    read,
                    now,
                )
                .unwrap();
        }
    }

    #[test]
    fn a_creation_a_post_and_a_subscription_hold() {
        let now = 1_000;
        let (mut relay, id, read, write, _own) = opened(now);
        assert_eq!(relay.service.len(), 1);
        assert!(!relay.service.is_empty());

        // A post with no reader answers with its sequence alone.
        let first = record(1);
        let (replies, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &first, &write, now)
            .unwrap();
        assert_eq!(replies.len(), 1);
        assert!(due.is_empty());
        let (gseq, _) = Command::parse(&replies[0].outbound.encoded, Bucket::B0).unwrap();
        assert_eq!(gseq.cmd, Cmd::Group(GroupCmd::Gseq));
        assert_eq!(GseqPayload::parse(gseq.payload).unwrap().seq, 1);

        // A reader from 0 takes the record that waits.
        let mut from_seq = [0u8; 4];
        let (replies, _) = relay
            .send(OTHER, GroupCmd::Gsub, id, &from_seq, &read, now)
            .unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].circuit, OTHER);
        let (gmsg, _) = Command::parse(&replies[0].outbound.encoded, Bucket::B0).unwrap();
        assert_eq!(gmsg.cmd, Cmd::Group(GroupCmd::Gmsg));
        assert_eq!(
            split_gmsg(gmsg.payload, Bucket::B0).unwrap(),
            (1, &first[..])
        );

        // A second post reaches the reader, and the same bytes again do not.
        let second = record(2);
        let (replies, _) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &second, &write, now)
            .unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[1].circuit, OTHER);
        let (replies, _) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &second, &write, now)
            .unwrap();
        assert_eq!(replies.len(), 1);
        let (gseq, _) = Command::parse(&replies[0].outbound.encoded, Bucket::B0).unwrap();
        assert_eq!(GseqPayload::parse(gseq.payload).unwrap().seq, 2);

        // A `GUNSUB` ends the subscription, and a cursor above 1 skips the
        // record that the reader holds.
        relay
            .send(OTHER, GroupCmd::Gunsub, id, &[], &read, now)
            .unwrap();
        from_seq.copy_from_slice(&1u32.to_be_bytes());
        let (replies, _) = relay
            .send(OTHER, GroupCmd::Gsub, id, &from_seq, &read, now)
            .unwrap();
        assert_eq!(replies.len(), 1);
        relay.service.circuit_closed(&OTHER);
        let (replies, _) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(3), &write, now)
            .unwrap();
        assert_eq!(replies.len(), 1);
    }

    #[test]
    fn a_new_owner_key_ends_the_old_one_at_once() {
        let now = 1_000;
        let (mut relay, id, read, write, own) = opened(now);
        let next = StaticSecret::from([0x31u8; 32]);
        let mut payload = [0u8; 96];
        GkeyPayload {
            read_pk: public(&read),
            write_pk: public(&write),
            own_pk: public(&next),
        }
        .encode(&mut payload)
        .unwrap();
        relay
            .send(CIRCUIT, GroupCmd::Gkey, id, &payload, &own, now)
            .unwrap();
        // WIR-522: the owner key takes no grace, thus an admin that left
        // its role and holds the old one deletes nothing.
        assert_eq!(
            relay.send(CIRCUIT, GroupCmd::Gdel, id, &[], &own, now + 1),
            Err(Reject::Rejected)
        );
        assert_eq!(
            relay.send(CIRCUIT, GroupCmd::Gkey, id, &payload, &own, now + 1),
            Err(Reject::Rejected)
        );
        relay
            .send(CIRCUIT, GroupCmd::Gdel, id, &[], &next, now + 2)
            .unwrap();
    }

    #[test]
    fn a_rotation_holds_the_previous_key_and_a_deletion_leaves_nothing() {
        let now = 1_000;
        let (mut relay, id, read, write, own) = opened(now);
        let (fresh_read, fresh_write) = (
            StaticSecret::from([21u8; 32]),
            StaticSecret::from([22u8; 32]),
        );
        let mut payload = [0u8; 96];
        GkeyPayload {
            read_pk: public(&fresh_read),
            write_pk: public(&fresh_write),
            own_pk: public(&own),
        }
        .encode(&mut payload)
        .unwrap();
        relay
            .send(CIRCUIT, GroupCmd::Gkey, id, &payload, &own, now)
            .unwrap();
        // The previous writer key holds inside its grace and not after it.
        let inside = now + GROUP_WRITE_GRACE - 1;
        relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(1), &write, inside)
            .unwrap();
        let after = now + GROUP_WRITE_GRACE;
        assert_eq!(
            relay.send(CIRCUIT, GroupCmd::Gpost, id, &record(2), &write, after),
            Err(Reject::Rejected)
        );
        relay
            .send(
                CIRCUIT,
                GroupCmd::Gpost,
                id,
                &record(2),
                &fresh_write,
                after,
            )
            .unwrap();
        // The previous reader key has a grace of its own.
        let mut from_seq = [0u8; 4];
        from_seq.copy_from_slice(&0u32.to_be_bytes());
        relay
            .send(OTHER, GroupCmd::Gsub, id, &from_seq, &read, after)
            .unwrap();

        // A `GDEL` takes the queue, and a later command finds nothing.
        relay
            .send(CIRCUIT, GroupCmd::Gdel, id, &[], &own, after)
            .unwrap();
        assert!(relay.service.is_empty());
        assert_eq!(
            relay.send(
                CIRCUIT,
                GroupCmd::Gpost,
                id,
                &record(3),
                &fresh_write,
                after
            ),
            Err(Reject::Rejected)
        );
    }

    #[test]
    fn a_relay_that_restarts_serves_the_group_and_its_records() {
        let now = 1_000;
        let (mut relay, id, read, write, own) = opened(now);
        let first = record(1);
        relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &first, &write, now)
            .unwrap();
        let fresh = StaticSecret::from([0x21u8; 32]);
        let mut payload = [0u8; 96];
        GkeyPayload {
            read_pk: public(&fresh),
            write_pk: public(&fresh),
            own_pk: public(&own),
        }
        .encode(&mut payload)
        .unwrap();

        // The store holds what the run gave it.
        let mut store = Loaded::default();
        for change in relay.service.take_changes() {
            store.apply(&change);
        }
        assert_eq!(store.group_queues.len(), 1);

        // A second run of the relay reads it, and the reader of the epoch
        // takes the record that waited.
        let mut second = Relay::new();
        second.service = GroupService::restore(&store);
        assert_eq!(second.service.len(), 1);
        let from_seq = [0u8; 4];
        let (replies, _) = second
            .send(OTHER, GroupCmd::Gsub, id, &from_seq, &read, now + 1)
            .unwrap();
        assert_eq!(replies.len(), 1);
        let (gmsg, _) = Command::parse(&replies[0].outbound.encoded, Bucket::B0).unwrap();
        assert_eq!(
            split_gmsg(gmsg.payload, Bucket::B0).unwrap(),
            (1, &first[..])
        );

        // NET-232: the sequence continues, thus a second record takes no
        // number that a reader holds already.
        let (replies, _) = second
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(2), &write, now + 1)
            .unwrap();
        let (gseq, _) = Command::parse(&replies[0].outbound.encoded, Bucket::B0).unwrap();
        assert_eq!(GseqPayload::parse(gseq.payload).unwrap().seq, 2);

        // A group queue that a `GDEL` took leaves the store, thus no later
        // run serves it (`NET-245`).
        second
            .send(CIRCUIT, GroupCmd::Gdel, id, &[], &own, now + 1)
            .unwrap();
        for change in second.service.take_changes() {
            store.apply(&change);
        }
        assert!(store.group_queues.is_empty());
        assert!(GroupService::restore(&store).is_empty());
    }

    #[test]
    fn a_registration_takes_one_digest_for_each_post_after_the_gap() {
        let now = 1_000;
        let (mut relay, id, read, write, _own) = opened(now);
        relay
            .send(CIRCUIT, GroupCmd::Gnreg, id, &registration(5), &read, now)
            .unwrap();
        let (_, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(1), &write, now)
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].post_count, 1);
        // NTF-097: a second record inside the gap holds its digest back.
        let (_, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(2), &write, now + 1)
            .unwrap();
        assert!(due.is_empty());
        let due = relay.service.sweep(now + 11);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].post_count, 1);
        // The registration leaves at a `GNUNREG`.
        relay
            .send(
                CIRCUIT,
                GroupCmd::Gnunreg,
                id,
                &registration(5),
                &read,
                now + 11,
            )
            .unwrap();
        let (_, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(3), &write, now + 30)
            .unwrap();
        assert!(due.is_empty());
        // NET-249: the idle life takes the queue.
        relay.service.sweep(now + 30 + GROUP_IDLE_TTL);
        assert!(relay.service.is_empty());
    }

    #[test]
    fn the_digest_of_a_post_inside_the_gap_goes_at_the_end_of_the_gap() {
        let now = 1_000;
        let (mut relay, id, read, write, _own) = opened(now);
        relay
            .send(CIRCUIT, GroupCmd::Gnreg, id, &registration(5), &read, now)
            .unwrap();
        let (_, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(1), &write, now)
            .unwrap();
        assert_eq!(due.len(), 1);
        let (_, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(2), &write, now + 3)
            .unwrap();
        assert!(due.is_empty());
        // NTF-098: the tick of each second gives it at the end of the gap,
        // and one time.
        assert!(relay
            .service
            .digest_tick(now + GROUP_DIGEST_MIN_GAP - 1)
            .is_empty());
        let due = relay.service.digest_tick(now + GROUP_DIGEST_MIN_GAP);
        assert_eq!(due.len(), 1);
        assert_eq!((due[0].id, due[0].post_count), (id, 1));
        assert!(relay
            .service
            .digest_tick(now + GROUP_DIGEST_MIN_GAP + 1)
            .is_empty());
        // A post inside the gap of that digest moves the time until which
        // the clock looks at the queue. Its digest goes at the end of its
        // own gap, and it waits for no other post and no sweep.
        let (_, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, id, &record(3), &write, now + 12)
            .unwrap();
        assert!(due.is_empty());
        for at in 13..2 * GROUP_DIGEST_MIN_GAP {
            assert!(relay.service.digest_tick(now + at).is_empty());
        }
        let due = relay.service.digest_tick(now + 2 * GROUP_DIGEST_MIN_GAP);
        assert_eq!(due.len(), 1);
        assert_eq!((due[0].id, due[0].post_count), (id, 1));
    }

    #[test]
    fn a_gsub_of_a_long_backlog_steps_through_the_queue_and_a_refused_one_leaves_no_subscription() {
        let now = 1_000;
        let (mut relay, id, read, write, _own) = opened(now);
        // NET-241: the posts of two minutes.
        let count = u8::try_from(DRAIN_THRESHOLD).unwrap() + 10;
        for index in 0..count {
            let at = now + u64::from(index / 60) * 61;
            relay
                .send(OTHER, GroupCmd::Gpost, id, &record(index), &write, at)
                .unwrap();
        }
        let at = now + 200;
        let from_seq = 3u32;
        // NET-237, NET-349: the `GSUB` gives no `GMSG` and copies no record.
        let (replies, _) = relay
            .send(
                CIRCUIT,
                GroupCmd::Gsub,
                id,
                &from_seq.to_be_bytes(),
                &read,
                at,
            )
            .unwrap();
        assert!(replies.is_empty());
        let next = relay.service.served[&id].queue.next_seq();
        let named = relay.service.served[&id].queue.since(from_seq).count();
        let held = relay.drains.of(&id).unwrap().clone();
        assert_eq!((held.after, held.end), (from_seq, next));
        assert_eq!(held.left, named * record(0).len());
        assert!(named > DRAIN_THRESHOLD);

        // Each step gives the next records, about the room that it has.
        let mut drain = held;
        let mut taken = Vec::new();
        loop {
            let (records, ended) =
                relay
                    .service
                    .drain_step(&mut drain, 2 * record(0).len(), &mut relay.rng);
            for outbound in &records {
                let (command, _) = Command::parse(&outbound.encoded, outbound.bucket).unwrap();
                assert_eq!(command.cmd, Cmd::Group(GroupCmd::Gmsg));
                let (seq, _) = split_gmsg(command.payload, outbound.bucket).unwrap();
                taken.push(seq);
            }
            if ended {
                break;
            }
            assert_eq!(records.len(), 2);
        }
        assert_eq!(taken, (from_seq + 1..next).collect::<Vec<u32>>());

        // A `GSUB` below the threshold ends the drain and gives its records
        // as before.
        let (replies, _) = relay
            .send(
                CIRCUIT,
                GroupCmd::Gsub,
                id,
                &(next - 3).to_be_bytes(),
                &read,
                at,
            )
            .unwrap();
        assert_eq!(replies.len(), 2);
        assert!(relay.drains.is_empty());

        // The circuit asks for the drains of one minute, and one more gets
        // `LIMIT`. It leaves no subscription, thus the next post gives the
        // circuit no `GMSG` above a backlog that never left.
        let minute = at + 60;
        for _ in 0..crate::service::DRAINS_PER_MINUTE {
            relay
                .send(
                    CIRCUIT,
                    GroupCmd::Gsub,
                    id,
                    &0u32.to_be_bytes(),
                    &read,
                    minute,
                )
                .unwrap();
        }
        assert!(relay.service.served[&id].subscribers.contains(&CIRCUIT));
        assert_eq!(
            relay.send(
                CIRCUIT,
                GroupCmd::Gsub,
                id,
                &0u32.to_be_bytes(),
                &read,
                minute
            ),
            Err(Reject::Limit)
        );
        assert!(!relay.service.served[&id].subscribers.contains(&CIRCUIT));
        assert!(relay.drains.is_empty());
        let (replies, _) = relay
            .send(
                OTHER,
                GroupCmd::Gpost,
                id,
                &record(200),
                &write,
                minute + 60,
            )
            .unwrap();
        assert_eq!(replies.len(), 1);
    }

    #[test]
    fn a_group_queue_takes_its_turn_however_many_wait() {
        let now = 1_000;
        let mut service = GroupService::default();
        let count = DIGESTS_PER_SECOND + 40;
        let mut ids = Vec::new();
        for index in 0..count {
            let mut id = [0x60u8; 32];
            id[..2].copy_from_slice(&u16::try_from(index).unwrap().to_be_bytes());
            let mut served = Served::new(GroupQueue::new(id, [1; 32], [2; 32], [3; 32], now));
            served.notify.insert([5; 32], [0; QUEUE_ADDRESS_LEN]);
            service.served.insert(id, served);
            ids.push(id);
        }
        // Each group queue holds one digest that waits, in each second.
        let wait = |service: &mut GroupService| {
            for id in &ids {
                let served = service.served.get_mut(id).unwrap();
                served.waiting.insert([5; 32], 1);
                service.waiting.insert(*id);
            }
        };
        wait(&mut service);
        let first = service.release(now);
        assert_eq!(first.len(), DIGESTS_PER_SECOND);
        wait(&mut service);
        let second = service.release(now + 1);
        assert_eq!(second.len(), DIGESTS_PER_SECOND);
        // The group queues that the first second left take the first turns
        // of the next one. Before this, the same ones took each second.
        let served: BTreeSet<[u8; 32]> = first.iter().chain(&second).map(|due| due.id).collect();
        assert_eq!(served.len(), count);
    }

    #[test]
    fn a_circuit_registers_a_bounded_count_of_notify_queues() {
        let now = 1_000;
        let (mut relay, id, read, _write, _own) = opened(now);
        for sender in 0..GNREG_PER_CIRCUIT {
            relay
                .send(
                    CIRCUIT,
                    GroupCmd::Gnreg,
                    id,
                    &registration(sender),
                    &read,
                    now,
                )
                .unwrap();
        }
        // One more from that circuit answers with `LIMIT`, and a
        // registration that the queue holds already is no new one.
        assert_eq!(
            relay.send(
                CIRCUIT,
                GroupCmd::Gnreg,
                id,
                &registration(0x40),
                &read,
                now
            ),
            Err(Reject::Limit)
        );
        relay
            .send(CIRCUIT, GroupCmd::Gnreg, id, &registration(0), &read, now)
            .unwrap();
        // Another circuit has a count of its own, and so has a circuit
        // that takes the place of one that ended.
        relay
            .send(OTHER, GroupCmd::Gnreg, id, &registration(0x40), &read, now)
            .unwrap();
        relay.service.circuit_closed(&CIRCUIT);
        relay
            .send(
                CIRCUIT,
                GroupCmd::Gnreg,
                id,
                &registration(0x41),
                &read,
                now,
            )
            .unwrap();
    }

    #[test]
    fn a_group_with_many_registrations_takes_its_digests_in_turns() {
        let now = 1_000;
        let (mut relay, large, read, write, own) = opened(now);
        let small = created(&mut relay, &read, &write, &own, now);
        let many = u16::try_from(2 * DIGESTS_PER_SECOND).unwrap() + 88;
        register_many(&mut relay, large, &read, many, now);
        register_many(&mut relay, small, &read, 3, now);

        // One post of the large group hands out the digests of one second,
        // and the others wait.
        let (_, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, large, &record(1), &write, now)
            .unwrap();
        assert_eq!(due.len(), DIGESTS_PER_SECOND);
        // A post of the small group inside that second waits too.
        let (_, due) = relay
            .send(CIRCUIT, GroupCmd::Gpost, small, &record(1), &write, now)
            .unwrap();
        assert!(due.is_empty());
        assert!(relay.service.digest_tick(now).is_empty());
        // The next second gives each group that waits its share. The small
        // one thus takes each digest of its own, whatever the count of the
        // large one.
        let due = relay.service.digest_tick(now + 1);
        assert_eq!(due.len(), DIGESTS_PER_SECOND);
        assert_eq!(due.iter().filter(|digest| digest.id == small).count(), 3);
        // The large one takes the others in the seconds after it, and it
        // loses none.
        let due = relay.service.digest_tick(now + 2);
        assert_eq!(due.len(), 88 + 3);
        assert!(due.iter().all(|digest| digest.id == large));
        assert!(relay.service.digest_tick(now + 3).is_empty());
    }

    #[test]
    fn a_deleted_group_queue_frees_its_place_in_the_session() {
        let now = 1_000;
        let (mut relay, id, read, write, own) = opened(now);
        // NET-022: a session serves `MAX_QUEUES_PER_SESSION` queues, and a
        // `GDEL` gives the place of its queue back.
        relay
            .send(CIRCUIT, GroupCmd::Gdel, id, &[], &own, now)
            .unwrap();
        for _ in 0..=umbra_queue::params::MAX_QUEUES_PER_SESSION {
            let id = created(&mut relay, &read, &write, &own, now);
            relay
                .send(CIRCUIT, GroupCmd::Gdel, id, &[], &own, now)
                .unwrap();
        }
        created(&mut relay, &read, &write, &own, now);
    }
}
