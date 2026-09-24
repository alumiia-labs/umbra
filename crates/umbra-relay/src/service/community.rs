//! The community caches of one relay (Part 12 §12.3.3, §12.6.4): `PULL`
//! with its `PAGE`, `PUB` with its `PUBACK`, and the two registration
//! commands of the digest path.
//!
//! A pull changes no state, and a registration holds a queue and no other
//! value. The two sets meet nowhere (`COM-373`).

use std::collections::BTreeMap;

use umbra_core::{
    abuse::admission::{Accepts, Admitted, RelayGate},
    community::{
        pull::{
            NotifyRegistration, PullRequest, CMD_NREG, CMD_NUNREG, CMD_PAGE, CMD_PUB, CMD_PUBACK,
            CMD_PULL,
        },
        pull_secret,
        record::record_len,
        relay::CommunityCache,
        RecordType,
    },
    notify::digest::{DigestGate, Policy},
};
use umbra_crypto::x25519::{PublicKey as XPublic, StaticSecret};

use crate::store::{Loaded, StoreChange};
use umbra_queue::{relay::session::Session, Reject};
use umbra_wire::{
    address::LEN as QUEUE_ADDRESS_LEN,
    admission::Admission,
    command::{Cmd, Command},
};

use super::{answer, DigestDue, Reply};
use crate::circuits::CircuitKey;

struct Served {
    cache: CommunityCache,
    digests: DigestGate,
    /// The address of each registered queue, by its `sender_id`. The relay
    /// holds it in memory only (`COM-369`).
    queues: BTreeMap<[u8; 32], [u8; QUEUE_ADDRESS_LEN]>,
}

/// The communities that the relay serves.
pub struct CommunityService {
    served: BTreeMap<[u8; 32], Served>,
    capacity_bytes: usize,
    /// The changes of the stored state since the last call of
    /// [`CommunityService::take_changes`] (`COM-412`).
    changes: Vec<StoreChange>,
}

/// `pull_pk`, which each party derives from `community_id` (`COM-175`).
fn pull_public(community_id: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*pull_secret(community_id).expose());
    *XPublic::from(&secret).as_bytes()
}

fn sender_id_of(queue: &[u8; QUEUE_ADDRESS_LEN]) -> [u8; 32] {
    let mut sender_id = [0u8; 32];
    sender_id.copy_from_slice(queue.get(33..65).unwrap_or(&[0; 32]));
    sender_id
}

impl CommunityService {
    /// A service that gives each community `capacity_bytes` of post
    /// records.
    pub fn new(capacity_bytes: usize) -> Self {
        CommunityService {
            served: BTreeMap::new(),
            capacity_bytes,
            changes: Vec::new(),
        }
    }

    /// The service of an earlier run: each community takes its records
    /// again, in `seq` order and at the `seq` each one had (`COM-413`).
    /// A registration of a notify queue does not come back, as the
    /// session that carried it ended.
    pub fn restore(capacity_bytes: usize, loaded: &Loaded) -> Self {
        let mut service = CommunityService::new(capacity_bytes);
        for (community_id, records) in &loaded.communities {
            let mut cache = CommunityCache::new(*community_id, capacity_bytes);
            for (seq, (accepted_at, record)) in records {
                let _ = cache.restore(record, *seq, *accepted_at);
            }
            // A replay can drop a record that the store still holds, as the
            // resolution of a window does.
            for seq in cache.take_forgotten() {
                service.changes.push(StoreChange::CommunityForget {
                    community_id: *community_id,
                    seq,
                });
            }
            if cache.control().has_genesis() {
                service.served.insert(
                    *community_id,
                    Served {
                        cache,
                        digests: DigestGate::new(Policy::Community),
                        queues: BTreeMap::new(),
                    },
                );
            }
        }
        service
    }

    /// The changes of the stored state since the last call.
    pub fn take_changes(&mut self) -> Vec<StoreChange> {
        core::mem::take(&mut self.changes)
    }

    fn note_forgotten(&mut self, community_id: [u8; 32]) {
        let Some(served) = self.served.get_mut(&community_id) else {
            return;
        };
        for seq in served.cache.take_forgotten() {
            self.changes
                .push(StoreChange::CommunityForget { community_id, seq });
        }
    }

    /// The count of the communities.
    pub fn len(&self) -> usize {
        self.served.len()
    }

    /// Whether the relay serves no community.
    pub fn is_empty(&self) -> bool {
        self.served.is_empty()
    }

    /// Handles one command of the community range, and returns the answer
    /// with the digests that a fresh post made due.
    #[allow(clippy::too_many_arguments)]
    pub fn handle(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
        gate: &mut RelayGate,
        accepts: &Accepts<'_>,
        command: &Command<'_>,
        now: u64,
    ) -> Result<(Vec<Reply>, Vec<DigestDue>), Reject> {
        let community_id = command.queue_id;
        session.accept(command, &pull_public(&community_id))?;
        let Cmd::Community(byte) = command.cmd else {
            return Err(Reject::Rejected);
        };
        match byte {
            CMD_PULL => {
                let request = PullRequest::parse(command.payload).map_err(|_| Reject::Rejected)?;
                // COM-199.
                if request.community_id != community_id {
                    return Err(Reject::Rejected);
                }
                let served = self.served.get(&community_id).ok_or(Reject::Rejected)?;
                let page = served.cache.pull(&request)?;
                Ok((
                    vec![answer(circuit, command, Cmd::Community(CMD_PAGE), &page)],
                    Vec::new(),
                ))
            }
            CMD_PUB => self.publish(circuit, gate, accepts, command, now),
            CMD_NREG | CMD_NUNREG => {
                let registration =
                    NotifyRegistration::parse(command.payload).map_err(|_| Reject::Rejected)?;
                if registration.community_id != community_id {
                    return Err(Reject::Rejected);
                }
                let served = self.served.get_mut(&community_id).ok_or(Reject::Rejected)?;
                let sender_id = sender_id_of(&registration.queue);
                if byte == CMD_NREG {
                    served
                        .digests
                        .register(sender_id, now)
                        .map_err(|_| Reject::Limit)?;
                    served.queues.insert(sender_id, registration.queue);
                } else {
                    served.digests.unregister(&sender_id);
                    served.queues.remove(&sender_id);
                }
                Ok((Vec::new(), Vec::new()))
            }
            _ => Err(Reject::Rejected),
        }
    }

    fn publish(
        &mut self,
        circuit: CircuitKey,
        gate: &mut RelayGate,
        accepts: &Accepts<'_>,
        command: &Command<'_>,
        now: u64,
    ) -> Result<(Vec<Reply>, Vec<DigestDue>), Reject> {
        let community_id = command.queue_id;
        let split = record_len(command.payload).map_err(|_| Reject::Rejected)?;
        let (record, trailer) = command.payload.split_at(split);
        let (admission, used) = Admission::parse(trailer).map_err(|_| Reject::Rejected)?;
        if used != trailer.len() {
            return Err(Reject::Rejected);
        }
        // A credential that does not verify rejects the command. No
        // credential is no fault here: the cache asks for one where a rule
        // needs it (`COM-150`, `COM-205`).
        let admitted = !matches!(gate.admit(&admission, accepts, now)?, Admitted::Free);

        // COM-206: a community starts with its genesis roster.
        let is_roster = RecordType::of(record) == Ok(RecordType::Roster);
        if !self.served.contains_key(&community_id) && !is_roster {
            return Err(Reject::Rejected);
        }
        let capacity = self.capacity_bytes;
        let served = self.served.entry(community_id).or_insert_with(|| Served {
            cache: CommunityCache::new(community_id, capacity),
            digests: DigestGate::new(Policy::Community),
            queues: BTreeMap::new(),
        });
        let before = served.cache.next_seq();
        let published = served.cache.publish(record, admitted, now);
        let is_new = served.cache.next_seq() > before;
        if !served.cache.control().has_genesis() {
            self.served.remove(&community_id);
        }
        let published = published?;
        // COM-412: the relay keeps what it accepted across a
        // restart.
        if is_new {
            self.changes.push(StoreChange::CommunityRecord {
                community_id,
                seq: published.seq,
                accepted_at: now,
                record: record.to_vec(),
            });
        }
        self.note_forgotten(community_id);
        let reply = answer(
            circuit,
            command,
            Cmd::Community(CMD_PUBACK),
            &published.seq.to_be_bytes(),
        );
        let mut due = Vec::new();
        if published.fresh_post {
            if let Some(served) = self.served.get_mut(&community_id) {
                due = Self::digests_of(community_id, served, Tick::Post(now));
            }
        }
        Ok((vec![reply], due))
    }

    fn digests_of(community_id: [u8; 32], served: &mut Served, now: Tick) -> Vec<DigestDue> {
        let due = match now {
            Tick::Post(at) => served.digests.on_post(at),
            Tick::Clock(at) => served.digests.tick(at),
        };
        due.into_iter()
            .filter_map(|digest| {
                // COM-372: the digest names no post, no pseudonym, and no index.
                served.queues.get(&digest.queue).map(|queue| DigestDue {
                    id: community_id,
                    queue: *queue,
                    post_count: digest.post_count,
                })
            })
            .collect()
    }

    /// The periodic work: the retention of each cache, the digests that a
    /// budget held back, and the registrations past their life.
    pub fn sweep(&mut self, now: u64) -> Vec<DigestDue> {
        let mut due = Vec::new();
        for (community_id, served) in &mut self.served {
            served.cache.sweep(now);
            // A pruned record leaves the store too (`COM-227`).
            for seq in served.cache.take_forgotten() {
                self.changes.push(StoreChange::CommunityForget {
                    community_id: *community_id,
                    seq,
                });
            }
            due.extend(Self::digests_of(*community_id, served, Tick::Clock(now)));
            let digests = &served.digests;
            // COM-375: the address leaves with its registration.
            served
                .queues
                .retain(|sender_id, _| digests.holds(sender_id));
        }
        due
    }
}

enum Tick {
    Post(u64),
    Clock(u64),
}
