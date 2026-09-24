//! The group queues of one relay (Part 3 §3.2.7, Part 6 §6.4.5): the
//! eleven commands `GNEW`, `GPOST`, `GSUB`, `GUNSUB`, `GKEY`, `GDEL`,
//! `GNREG`, and `GNUNREG`, with the answer of each one and the `GMSG` that
//! goes to each circuit that subscribed.
//!
//! The relay holds no member list and no per-reader cursor (`NET-227`,
//! `NET-228`). A reader names its own `from_seq` at each `GSUB`.

use std::collections::BTreeMap;

use umbra_core::{
    abuse::admission::{Accepts, RelayGate},
    notify::digest::{DigestGate, Policy},
};
use umbra_crypto::{
    rand_core::CryptoRng,
    stored::{Reader, Writer},
};
use umbra_queue::{
    params::store_time,
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

use super::{answer, DigestDue, Outbound, Reply, BUCKETS};
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
    /// The circuits that subscribed. A group queue has many readers, and
    /// the relay holds no cursor of any of them.
    subscribers: Vec<CircuitKey>,
}

/// The group queues that the relay serves, by `GroupQueueId`.
#[derive(Default)]
pub struct GroupService {
    served: BTreeMap<[u8; 32], Served>,
    /// The changes since the last [`GroupService::take_changes`].
    changes: Vec<StoreChange>,
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
    let mut sender_id = [0u8; 32];
    sender_id.copy_from_slice(queue.get(33..65).unwrap_or(&[0; 32]));
    sender_id
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
            let Ok(queue) = GroupQueue::restore(&mut reader, stored.records.clone()) else {
                continue;
            };
            if queue.id() != *group_queue_id {
                continue;
            }
            service.served.insert(
                *group_queue_id,
                Served {
                    queue,
                    digests: DigestGate::new(Policy::Group),
                    notify: BTreeMap::new(),
                    subscribers: Vec::new(),
                },
            );
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
    #[allow(clippy::too_many_arguments)]
    pub fn handle<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
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
                let mut due = Vec::new();
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
                    due = Self::digests_of(group_queue_id, served, Tick::Post(now));
                }
                Ok((replies, due))
            }
            GroupCmd::Gsub => {
                accept_either(session, command, served.queue.read_pks(now))?;
                let from_seq = parse_gsub(command.payload).map_err(|_| Reject::Rejected)?;
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
                    // NET-252: the count bound answers with `LIMIT`.
                    served
                        .digests
                        .register(sender_id, now)
                        .map_err(|_| Reject::Limit)?;
                    served.notify.insert(sender_id, address);
                } else {
                    served.digests.unregister(&sender_id);
                    served.notify.remove(&sender_id);
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
                // NET-244, NET-245: the records, the notifiers, and the
                // identifier leave together.
                if let Some(served) = self.served.remove(&group_queue_id) {
                    drop(served.queue.delete());
                }
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
        gate.admit(&new.admission, accepts, now)?;
        let mut group_queue_id = [0u8; 32];
        rng.fill_bytes(&mut group_queue_id);
        session.bind_queue(group_queue_id)?;
        self.served.insert(
            group_queue_id,
            Served {
                queue: GroupQueue::new(group_queue_id, new.read_pk, new.write_pk, new.own_pk, now),
                digests: DigestGate::new(Policy::Group),
                notify: BTreeMap::new(),
                subscribers: Vec::new(),
            },
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

    fn digests_of(group_queue_id: [u8; 32], served: &mut Served, now: Tick) -> Vec<DigestDue> {
        let due = match now {
            Tick::Post(at) => served.digests.on_post(at),
            Tick::Clock(at) => served.digests.tick(at),
        };
        due.into_iter()
            .filter_map(|digest| {
                // NTF-099: the digest names no record and no member.
                served.notify.get(&digest.queue).map(|queue| DigestDue {
                    id: group_queue_id,
                    queue: *queue,
                    post_count: digest.post_count,
                })
            })
            .collect()
    }

    /// A circuit ended, thus its subscriptions end.
    pub fn circuit_closed(&mut self, circuit: &CircuitKey) {
        for served in self.served.values_mut() {
            served.subscribers.retain(|held| held != circuit);
        }
    }

    /// The periodic work: the retention of each queue, the digests that the
    /// gap held back, and each queue past `GROUP_IDLE_TTL`.
    pub fn sweep(&mut self, now: u64) -> Vec<DigestDue> {
        let mut due = Vec::new();
        let mut trimmed = Vec::new();
        for (group_queue_id, served) in &mut self.served {
            if let Some(through_seq) = served.queue.expire(now) {
                trimmed.push(StoreChange::GroupTrimmed {
                    group_queue_id: *group_queue_id,
                    through_seq,
                });
            }
            due.extend(Self::digests_of(*group_queue_id, served, Tick::Clock(now)));
            let digests = &served.digests;
            // NTF-102: the address leaves with its registration.
            served
                .notify
                .retain(|sender_id, _| digests.holds(sender_id));
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
            self.changes
                .push(StoreChange::GroupQueueDeleted { group_queue_id });
        }
        due
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
        gate: RelayGate,
        issuer: PublicKey2048,
        relay_pk: [u8; 32],
        rng: Rng,
        corr: u8,
    }

    impl Relay {
        fn new() -> Self {
            let relay_sk = StaticSecret::from([7u8; 32]);
            let relay_pk = *XPublic::from(&relay_sk).as_bytes();
            Relay {
                service: GroupService::default(),
                session: Session::for_circuit(&[9; 16], relay_sk),
                gate: RelayGate::new([3; 32]),
                issuer: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
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
            let mut command = Command {
                cmd: Cmd::Group(cmd),
                corr_id: [self.corr; 16],
                queue_id,
                auth: [0; 32],
                payload,
            };
            command.sign(&key, b"").unwrap();
            let accepts = Accepts::CrossRelay(&self.issuer);
            self.service.handle(
                circuit,
                &mut self.session,
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

    fn record(byte: u8) -> Vec<u8> {
        vec![byte; Bucket::B0.group_record()]
    }

    fn registration(sender: u8) -> Vec<u8> {
        let mut payload = vec![0u8; NOTIFY_REGISTRATION_LEN];
        GroupNotifyRegistration {
            queue: QueueAddress {
                relay_id: [1; 32],
                sender_id: [sender; 32],
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
        let mut payload = vec![0u8; 200];
        let used = GnewPayload {
            read_pk: public(&read),
            write_pk: public(&write),
            own_pk: public(&own),
            admission: Admission::NONE,
        }
        .encode(&mut payload)
        .unwrap();
        payload.truncate(used);
        let (replies, _) = relay
            .send(CIRCUIT, GroupCmd::Gnew, [0; 32], &payload, &own, now)
            .unwrap();
        let (gids, _) = Command::parse(&replies[0].outbound.encoded, Bucket::B0).unwrap();
        assert_eq!(gids.cmd, Cmd::Group(GroupCmd::Gids));
        let id: [u8; 32] = gids.payload.try_into().unwrap();
        (relay, id, read, write, own)
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
}
