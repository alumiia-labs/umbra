//! One group at one device (Part 11): the roster, the epochs, the sender
//! and the receiver, the pair keys, and the replicas of the group queue.
//!
//! The type holds the state and builds the bytes. It opens no socket and
//! sends no command: the caller carries a record to the group queue with
//! [`crate::session::node::ClientNode::group`].

use alloc::{boxed::Box, vec::Vec};

use umbra_crypto::{
    group::{
        chain::{Credentials, EpochSecret},
        pair::PairKey,
        MemberKeys, TAG_LEN,
    },
    hash::sha3_256,
    rand_core::{CryptoRng, TryCryptoRng},
    secret::Secret,
    stored::{Reader, Writer},
    zeroize::Zeroizing,
};
use umbra_wire::{
    bucket::Bucket,
    group::{
        control::{
            Chain, ControlType, GrantingEpoch, GroupControl, GroupMemberEntry, JoinRecord,
            MemberKemKey, ModAction, ModerationEpoch, PlainEpoch, PlainOp, ReplicaRef, Role,
            RosterSnapshot,
        },
        record::{
            slot_len, Carrier, EpochKeyBody, GroupQueueRecord, RecordKind, SlotPayload,
            EPOCH_KEY_FIXED, REPLICAS,
        },
    },
};

use super::{
    backoff,
    epoch::{
        aged_runs, one_slot, rotate, start_slot_place, Base, EpochState, EpochStore, Included,
    },
    join::{admit, admit_slot, Admitted},
    queue::Replicas,
    receive::{Context, Outcome, Receiver},
    roster::{Applied, Member, Roster, Trigger, STORED_VERSION},
    send::{send_slot, PairCache, Sender},
    slot_of, GROUP_REPLICAS, GROUP_ROSTER_WAIT,
};
use crate::Error;

/// The epochs that wait at most for a roster object or for the clock
/// (`GRP-357`). Each one opened and verified under a pair key with an
/// active member, thus a party outside the group fills no place.
const PENDING_MAX: usize = 8;

/// The chunked epoch-key records that wait at most. No key of this member
/// opened one, and no field names the party that posted it. Thus the bound
/// is small, and a record of a higher epoch leaves first.
const WAITING_MAX: usize = 4;

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

/// The smallest bucket that holds a dense tag vector of `members` tags and
/// an `AppMessage` of `app_len` bytes (§11.2).
pub fn bucket_for(members: usize, app_len: usize) -> Option<Bucket> {
    let need = members.saturating_mul(TAG_LEN).saturating_add(app_len);
    BUCKETS
        .into_iter()
        .find(|bucket| need <= bucket.tags_and_app())
}

/// The smallest bucket that holds an inline epoch-key body of these slots
/// (`GRP-280`).
fn bucket_for_slots(admin_slots: usize, plain_slots: usize) -> Option<Bucket> {
    let need = EPOCH_KEY_FIXED
        .saturating_add(admin_slots.saturating_mul(slot_len(REPLICAS)))
        .saturating_add(plain_slots.saturating_mul(slot_len(0)));
    BUCKETS
        .into_iter()
        .find(|bucket| need <= bucket.group_body())
}

/// Where the slots of a rotation go (§11.4.2).
pub enum EpochCarrier {
    /// The epoch-key record, one copy for each replica.
    Inline(Vec<u8>),
    /// The slot object for the chunk path, and the facts that its record
    /// names after the upload (`GRP-281` to `GRP-283`).
    Chunked(ChunkedEpoch),
}

/// The slots of a rotation above the inline carrier.
pub struct ChunkedEpoch {
    /// Whole blocks of `SEGMENT_SIZE` bytes, each holding `slots_per_chunk`
    /// slots in index order and then zero bytes (`GRP-281`).
    pub object: Vec<u8>,
    /// The slots in each block (`GRP-282`).
    pub slots_per_chunk: u16,
    /// The count of slots.
    pub slot_count: u16,
    /// `t_e` of the new epoch.
    pub start_slot: u32,
    /// The roster epoch whose active members hold the slots.
    pub roster_epoch: u32,
}

/// The one chunk of a chunked epoch-key record that holds the slot of
/// this member (`GRP-284`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WantedChunk {
    /// The `FileDescriptor` bytes of the slot object.
    pub descriptor: Vec<u8>,
    /// The chunk: the rank of this member among the included members,
    /// over `slots_per_chunk`.
    pub chunk: u32,
    /// The epoch that the record starts.
    pub epoch: u32,
    /// `t_e`.
    pub start_slot: u32,
    /// The roster epoch of the slots.
    pub roster_epoch: u32,
    /// The count of slots.
    pub slot_count: u16,
    /// The slots in each block.
    pub slots_per_chunk: u16,
}

/// What a rotation produced.
pub struct Rotation {
    /// The epoch-key record, or the slot object that its record follows.
    pub carrier: EpochCarrier,
    /// The epoch it starts.
    pub epoch: u32,
    /// The write credential of the epoch before this one, under which the
    /// record goes to each replica. The relay holds it for
    /// `GROUP_WRITE_GRACE`, and it takes the credential of the new epoch
    /// only after a `GKEY` (`GRP-362`).
    pub write: Secret<32>,
}

/// The index and the keys of this member before a re-key (§11.12). The
/// member reads with them until an epoch-key record holds a slot for its new
/// index, and then they go (`GRP-372`).
struct Previous {
    index: u16,
    keys: Box<MemberKeys>,
    pairs: PairCache,
}

/// The slot of this member in an epoch-key record, opened and with its tag
/// verified, and the facts of the record around it.
struct Opened {
    epoch: u32,
    start_slot: u32,
    roster_epoch: u32,
    payload: SlotPayload,
    /// Whether the slot was one of the index that stands, and not of the
    /// index before a re-key (`GRP-372`).
    is_current: bool,
    /// Whether the record holds a slot for each member of its roster
    /// epoch. A record that does not is a key supply (`GRP-375`), and the
    /// index rule of `GRP-273` does not order its secret.
    serves_all: bool,
    /// The time of its first arrival.
    arrived_at: u64,
}

/// A chunked epoch-key record of an epoch above the current one that
/// this member does not fetch yet (`GRP-284`, `GRP-357`).
struct Waiting {
    epoch: u32,
    start_slot: u32,
    body: Vec<u8>,
    arrived_at: u64,
}

/// One group at one device.
pub struct Group {
    own_index: u16,
    previous: Option<Previous>,
    /// The three keys of this member. They are boxed because an ML-DSA
    /// signing key is large, and a group moves by value.
    keys: Box<MemberKeys>,
    roster: Roster,
    epochs: EpochStore,
    sender: Sender,
    receiver: Receiver,
    pairs: PairCache,
    /// The owner credential of each replica. The creator drew them, and
    /// each member of role `admin` or above holds them (`GRP-188`,
    /// `GRP-190`). A plain member holds none.
    owners: Option<[Secret<32>; GROUP_REPLICAS]>,
    replicas: Option<Replicas>,
    /// The head of the roster chain that the last roster object displaced
    /// (`GRP-117`). The client takes it, and publishes it again when this
    /// member made it (`GRP-119`).
    displaced: Option<super::roster::Displaced>,
    /// The epochs whose slot opened and that do not install yet (`GRP-357`,
    /// `GRP-383`). The roster object that calls for one has not arrived, or
    /// its `t_e` lies above the clock.
    pending: Vec<Opened>,
    /// The chunked records of such epochs, whose slot no fetch gave yet.
    waiting: Vec<Waiting>,
}

impl Group {
    /// The group of its creator: a fresh epoch secret, a fresh owner
    /// credential for each replica, and the roster of `GRP-151` with the
    /// creator at index 0 (`GRP-220`, `GRP-188`).
    pub fn create<R: CryptoRng + TryCryptoRng + ?Sized>(
        group_id: [u8; 32],
        seed: &Secret<32>,
        now: u64,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let keys = MemberKeys::from_seed(seed);
        let creator = Member {
            index: 0,
            role: Role::Owner,
            pair_pk: keys.pair_public(),
            roster_pk_hash: sha3_256(&[&keys.roster().verifying_key().to_bytes()]),
            kem_pk_hash: sha3_256(&[&keys.kem().public().to_bytes()]),
            kem_pk: Some(keys.kem().public().to_bytes().to_vec()),
            roster_pk: Some(keys.roster().verifying_key().to_bytes().to_vec()),
            active: true,
        };
        let secret = EpochSecret::generate(rng)?;
        let mut epochs = EpochStore::default();
        epochs.install(EpochState::new(
            secret,
            &group_id,
            1,
            slot_of(now),
            0,
            0,
            now,
        ))?;
        let mut owners = [Secret::<32>::zeroed(), Secret::<32>::zeroed()];
        for owner in &mut owners {
            rng.try_fill_bytes(owner.expose_mut())
                .map_err(|_| Error::Unverified)?;
        }
        Ok(Group {
            own_index: 0,
            previous: None,
            displaced: None,
            pending: Vec::new(),
            waiting: Vec::new(),
            roster: Roster::genesis(group_id, creator, now),
            keys: Box::new(keys),
            epochs,
            sender: Sender::default(),
            receiver: Receiver::new(0),
            pairs: PairCache::default(),
            owners: Some(owners),
            replicas: None,
        })
    }

    /// The group of a member that an admit and a snapshot admitted
    /// (`GRP-313`). It holds no owner credential, thus it rotates nothing.
    pub fn joined(admitted: Admitted, seed: &Secret<32>) -> Result<Self, Error> {
        let keys = MemberKeys::from_seed(seed);
        // GRP-326: the entry of the admit holds the keys of this member.
        if !admitted.holds_keys(&keys) {
            return Err(Error::Unverified);
        }
        let mut epochs = EpochStore::default();
        epochs.install(admitted.epoch)?;
        Ok(Group {
            own_index: admitted.index,
            previous: None,
            displaced: None,
            pending: Vec::new(),
            waiting: Vec::new(),
            keys: Box::new(keys),
            roster: admitted.roster,
            epochs,
            sender: Sender::default(),
            receiver: Receiver::new(admitted.index),
            pairs: PairCache::default(),
            owners: None,
            replicas: Some(Replicas::from_admit(admitted.replicas)),
        })
    }

    /// Writes the group to the stored form of Part 14 §14.6.4. It holds
    /// no `GroupRosterSeed_g`: the local identity table of Part 4 §4.7.2
    /// holds that seed (`GRP-055`), and [`Group::restore`] takes it.
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut w = Writer::new();
        w.u8(STORED_VERSION);
        w.u16(self.own_index);
        self.roster.export(&mut w)?;
        self.epochs.export(&mut w);
        self.sender.export(&mut w)?;
        self.receiver.export(&mut w)?;
        w.flag(self.owners.is_some());
        if let Some(owners) = &self.owners {
            for owner in owners {
                w.bytes(owner.expose());
            }
        }
        w.flag(self.replicas.is_some());
        if let Some(replicas) = &self.replicas {
            replicas.export(&mut w);
        }
        // The index before a re-key. Its seed is a row of the local identity
        // table, as the seed of the member is.
        w.flag(self.previous.is_some());
        if let Some(previous) = &self.previous {
            w.u16(previous.index);
        }
        // The epochs that wait for a roster object or for the clock.
        w.u32(super::roster::count(self.pending.len())?);
        for held in &self.pending {
            w.u32(held.epoch);
            w.u32(held.start_slot);
            w.u32(held.roster_epoch);
            w.u16(held.payload.rotator);
            w.bytes(held.payload.epoch_secret.expose());
            w.u32(super::roster::count(held.payload.own_sks.len())?);
            for own in &held.payload.own_sks {
                w.bytes(own.expose());
            }
            w.flag(held.is_current);
            w.flag(held.serves_all);
            w.u64(held.arrived_at);
        }
        w.u32(super::roster::count(self.waiting.len())?);
        for held in &self.waiting {
            w.u32(held.epoch);
            w.u32(held.start_slot);
            w.u64(held.arrived_at);
            w.var(&held.body)?;
        }
        Ok(w.finish())
    }

    /// Reads a group that [`Group::export`] wrote, with the seed of its
    /// row in the local identity table. The pair keys are a cache, thus
    /// the restored group derives each one again at its first use.
    pub fn restore(bytes: &[u8], seed: &Secret<32>) -> Result<Self, Error> {
        Self::restore_with_previous(bytes, seed, None)
    }

    /// As [`Group::restore`], with the seed of the member before a re-key
    /// when the stored form names an index before it (§11.12). A form that
    /// names one and no seed keeps no index before it.
    pub fn restore_with_previous(
        bytes: &[u8],
        seed: &Secret<32>,
        previous_seed: Option<&Secret<32>>,
    ) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != STORED_VERSION {
            return Err(Error::Stale);
        }
        let own_index = r.u16()?;
        let roster = Roster::import(&mut r)?;
        let epochs = EpochStore::import(&mut r)?;
        let sender = Sender::import(&mut r)?;
        let receiver = Receiver::import(&mut r)?;
        let owners = if r.flag()? {
            Some([Secret::new(r.array()?), Secret::new(r.array()?)])
        } else {
            None
        };
        let replicas = if r.flag()? {
            Some(Replicas::import(&mut r)?)
        } else {
            None
        };
        // A form of an earlier build ends here.
        let previous_index = if r.end().is_ok() {
            None
        } else if r.flag()? {
            Some(r.u16()?)
        } else {
            None
        };
        // A form before the epochs that wait ends here.
        let mut pending = Vec::new();
        let mut waiting = Vec::new();
        if r.end().is_err() {
            for _ in 0..r.u32()? {
                let epoch = r.u32()?;
                let start_slot = r.u32()?;
                let roster_epoch = r.u32()?;
                let rotator = r.u16()?;
                let epoch_secret = Secret::new(r.array()?);
                let mut own_sks = Vec::new();
                for _ in 0..r.u32()? {
                    own_sks.push(Secret::new(r.array()?));
                }
                pending.push(Opened {
                    epoch,
                    start_slot,
                    roster_epoch,
                    payload: SlotPayload {
                        rotator,
                        epoch_secret,
                        tag: [0; TAG_LEN],
                        own_sks,
                    },
                    is_current: r.flag()?,
                    serves_all: r.flag()?,
                    arrived_at: r.u64()?,
                });
            }
            for _ in 0..r.u32()? {
                waiting.push(Waiting {
                    epoch: r.u32()?,
                    start_slot: r.u32()?,
                    arrived_at: r.u64()?,
                    body: r.var()?.to_vec(),
                });
            }
        }
        r.end()?;
        let previous = previous_index
            .zip(previous_seed)
            .map(|(index, seed)| Previous {
                index,
                keys: Box::new(MemberKeys::from_seed(seed)),
                pairs: PairCache::default(),
            });
        Ok(Group {
            own_index,
            previous,
            displaced: None,
            pending,
            waiting,
            keys: Box::new(MemberKeys::from_seed(seed)),
            roster,
            epochs,
            sender,
            receiver,
            pairs: PairCache::default(),
            owners,
            replicas,
        })
    }

    /// The group.
    pub fn group_id(&self) -> &[u8; 32] {
        self.roster.group_id()
    }

    /// The index of this member.
    pub const fn own_index(&self) -> u16 {
        self.own_index
    }

    /// `GroupRosterKey_g.pk` of this member. The roster of a member that
    /// joined holds the hash of it alone, thus the key comes from the seed.
    pub fn own_roster_pk(&self) -> Vec<u8> {
        self.keys.roster().verifying_key().to_bytes().to_vec()
    }

    /// The roster.
    pub const fn roster(&self) -> &Roster {
        &self.roster
    }

    /// The group epoch.
    pub fn epoch(&self) -> u32 {
        self.epochs.epoch()
    }

    /// The reader and writer credentials of the current epoch, which
    /// authorize the group-queue commands (`GRP-222`).
    pub fn credentials(&self) -> Option<&Credentials> {
        self.epochs.credentials()
    }

    /// The reader and writer credentials of the previous epoch, while its
    /// grace holds (`GRP-398`).
    pub fn previous_credentials(&self) -> Option<&Credentials> {
        self.epochs.previous_credentials()
    }

    /// The owner credential of one replica, which an admin holds.
    pub fn owner(&self, replica: usize) -> Option<&Secret<32>> {
        self.owners.as_ref().and_then(|owners| owners.get(replica))
    }

    /// The replicas, after the two `GNEW` commands named them.
    pub const fn replicas(&self) -> Option<&Replicas> {
        self.replicas.as_ref()
    }

    /// The replicas, for the cursor of each one.
    pub const fn replicas_mut(&mut self) -> Option<&mut Replicas> {
        self.replicas.as_mut()
    }

    /// Records the two group queues that the creator made.
    pub fn set_replicas(&mut self, refs: [ReplicaRef; GROUP_REPLICAS]) {
        self.replicas = Some(Replicas::fresh(refs));
    }

    /// Builds one content record for `app`, in the smallest bucket that
    /// holds the tag vector and the message (`GRP-238`, `GRP-211`).
    pub fn post<R: CryptoRng + ?Sized>(
        &mut self,
        app: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        // GRP-415: an index that left the active set posts nothing; each
        // member drops its record under GRP-257.
        if self.own_role().is_none() {
            return Err(Error::NoPath);
        }
        // GRP-076: each member discards a roster object above a rate, thus
        // this member posts none.
        if self.rate_bars(app, now) {
            return Err(Error::NoPath);
        }
        // GRP-231, GRP-386: the previous epoch ends with its grace.
        self.epochs.expire(now);
        let members = self.roster.active_count();
        let bucket = bucket_for(members, app.len()).ok_or(Error::NoPath)?;
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        self.sender.build(
            self.own_index,
            &self.keys,
            &self.roster,
            &mut self.epochs,
            &mut self.pairs,
            app,
            bucket,
            nonce,
            now,
        )
    }

    /// Whether `app` carries a roster object of this member that the rates
    /// of `GRP-076` refuse in a record of `now`. The record of such an
    /// object goes out later.
    pub fn rate_bars(&self, app: &[u8], now: u64) -> bool {
        let Ok(message) = umbra_wire::app::AppMessage::parse(app, umbra_wire::app::Channel::Group)
        else {
            return false;
        };
        if message.kind != umbra_wire::app::AppKind::GroupControl {
            return false;
        }
        GroupControl::parse(message.body)
            .ok()
            .and_then(|control| Roster::rate_kind(&control))
            .is_some_and(|kind| {
                !self
                    .roster
                    .rate_allows(self.own_index, kind, send_slot(&self.epochs, now))
            })
    }

    /// Builds one content record under an earlier roster epoch that the
    /// roster history holds, for a member behind the roster (`GRP-330`).
    pub fn post_at_roster<R: CryptoRng + ?Sized>(
        &mut self,
        app: &[u8],
        roster_epoch: u32,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        if self.own_role().is_none() || roster_epoch > self.roster.epoch_index() {
            return Err(Error::NoPath);
        }
        self.epochs.expire(now);
        let members = self
            .roster
            .active_at(roster_epoch)
            .ok_or(Error::NoPath)?
            .len();
        let bucket = bucket_for(members, app.len()).ok_or(Error::NoPath)?;
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        self.sender.build_at(
            self.own_index,
            &self.keys,
            &self.roster,
            &mut self.epochs,
            &mut self.pairs,
            app,
            bucket,
            nonce,
            now,
            roster_epoch,
        )
    }

    /// Builds one `GroupPresence` record (§11.9.7). The caller sends it in
    /// each `PRESENCE_INTERVAL` in which it posted nothing else
    /// (`GRP-128`).
    pub fn presence<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        self.sender.build_presence(
            self.own_index,
            &self.keys,
            &self.roster,
            &mut self.epochs,
            &mut self.pairs,
            nonce,
            msg_id,
            now,
        )
    }

    /// The role of this member, or none after it left the roster.
    pub fn own_role(&self) -> Option<Role> {
        self.roster
            .member(self.own_index)
            .filter(|member| member.active)
            .map(|member| member.role)
    }

    /// Reads one record that a `GMSG` carried. The bucket comes from the
    /// record length, which the relay does not change (`WIR-372`).
    pub fn receive(&mut self, record: &[u8], now: u64) -> Result<Outcome, Error> {
        self.epochs.expire(now);
        let bucket = BUCKETS
            .into_iter()
            .find(|bucket| bucket.group_record() == record.len())
            .ok_or(Error::Malformed)?;
        self.receive_in(record, bucket, now)
    }

    /// A record of `bucket`, under the index that stands and then, for a
    /// record tagged for it, under the index before a re-key.
    fn receive_in(&mut self, record: &[u8], bucket: Bucket, now: u64) -> Result<Outcome, Error> {
        let mut ctx = Context {
            roster: &self.roster,
            epochs: &mut self.epochs,
            pairs: &mut self.pairs,
            own: &self.keys,
        };
        let first = self.receiver.receive(record, bucket, &mut ctx, now);
        // GRP-372: a record that a member tagged for the index before the
        // re-key opens with the keys of that index.
        let Some(previous) = self.previous.as_mut() else {
            return first;
        };
        if !matches!(first, Err(Error::Unverified)) {
            return first;
        }
        let current = self.receiver.own_index();
        self.receiver.set_own_index(previous.index);
        let mut ctx = Context {
            roster: &self.roster,
            epochs: &mut self.epochs,
            pairs: &mut previous.pairs,
            own: &previous.keys,
        };
        let second = self.receiver.receive(record, bucket, &mut ctx, now);
        self.receiver.set_own_index(current);
        second
    }

    /// Takes the roster of a snapshot that an admin wrote at the current
    /// roster epoch for this member (`GRP-329`, `GRP-330`). A member that a
    /// restore left behind the roster reads the members it lacks from it.
    /// The path verifies from the creator key that this roster holds, the
    /// snapshot is ahead of this roster, and it holds this member under its
    /// own keys. The `chain_hash` comes from the admin that wrote it: no
    /// record of this member names that epoch.
    pub fn recover_roster(&mut self, bytes: &[u8], now: u64) -> Result<(), Error> {
        let snapshot = RosterSnapshot::parse(bytes)?;
        if snapshot.group_id != *self.group_id()
            || snapshot.roster_epoch <= self.roster.epoch_index()
        {
            return Err(Error::Unverified);
        }
        // Each owner whose key this roster holds can be the creator of the
        // path. This member is the creator when it holds index 0, which the
        // creation gave and no later object gives (`GRP-306`). The key of
        // each other member starts no path: a snapshot with no role holder
        // but that member would verify with no grant at all.
        let mut keys: Vec<Vec<u8>> = self
            .roster
            .active()
            .filter(|member| member.role == Role::Owner)
            .filter_map(|member| member.roster_pk.clone())
            .collect();
        if self.own_index == 0 {
            keys.push(self.own_roster_pk());
        }
        let mut roster = keys
            .iter()
            .find_map(|key| Roster::from_snapshot(&snapshot, &snapshot.chain_hash, key, now).ok())
            .ok_or(Error::Unverified)?;
        // GRP-320: the snapshot names the active members alone, and a
        // member that left can hold the highest index.
        roster.open_next_index();
        let own = roster
            .member(self.own_index)
            .filter(|member| member.active)
            .ok_or(Error::Unverified)?;
        let own_kem = sha3_256(&[&self.keys.kem().public().to_bytes()]);
        if own.pair_pk != self.keys.pair_public() || own.kem_pk_hash != own_kem {
            return Err(Error::Unverified);
        }
        self.roster = roster;
        Ok(())
    }

    /// Tries each held record again, after a roster object or a clock
    /// check (`GRP-252`, `GRP-229`).
    pub fn retry_held(&mut self, now: u64) -> Vec<Outcome> {
        // GRP-357: an epoch that waited for the roster object comes first,
        // and each record that waited for its key opens after it.
        let mut out = self.retry_epochs(now);
        // GRP-372: each record takes both indexes of a re-key, as a record
        // that arrives does, thus one tagged for the index before stays.
        for (bytes, bucket, arrived_at) in self.receiver.take_held() {
            match self.receive_in(&bytes, bucket, now) {
                Ok(Outcome::Held | Outcome::ClockSuspect) => {
                    self.receiver.keep_arrival(arrived_at);
                }
                Ok(outcome) => out.push(outcome),
                Err(_) => {}
            }
        }
        out
    }

    /// The record of a re-key of this member to `fresh` (§11.12,
    /// `GRP-365`). It goes out as a group record under the index that
    /// stands, and [`Group::adopt_rekey`] follows its send.
    pub fn rekey_object<R: TryCryptoRng + ?Sized>(
        &self,
        fresh: &super::join::JoinKeys,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        super::join::rekey_record(&self.keys, fresh, &self.roster, self.own_index, true, rng)
    }

    /// Moves this member to the index and the keys of its re-key, after the
    /// record went out (`GRP-367`). The index and the keys before it stay
    /// until an epoch-key record holds a slot for the new index
    /// (`GRP-372`). The result is the new index.
    pub fn adopt_rekey(
        &mut self,
        object: &[u8],
        seed: &Secret<32>,
        now: u64,
    ) -> Result<u16, Error> {
        let control = GroupControl::parse(object)?;
        let slot = send_slot(&self.epochs, now);
        let new = match self.apply_roster(&control, self.own_index, slot, now) {
            Ok(Applied::Rekeyed { new, .. }) => new,
            Ok(_) => return Err(Error::Malformed),
            // DEV-300: a linked device can read the record on the group
            // queue before its seed comes on the sync channel.
            Err(Error::Stale) => self
                .roster
                .holds_rekey(&control, self.own_index)
                .ok_or(Error::Stale)?,
            Err(error) => return Err(error),
        };
        let keys = core::mem::replace(&mut self.keys, Box::new(MemberKeys::from_seed(seed)));
        let pairs = core::mem::take(&mut self.pairs);
        self.previous = Some(Previous {
            index: self.own_index,
            keys,
            pairs,
        });
        self.own_index = new;
        self.receiver.set_own_index(new);
        // The counter of a sender runs for each index.
        self.sender = Sender::default();
        Ok(new)
    }

    /// Whether this member still reads with the keys before a re-key.
    pub fn has_previous(&self) -> bool {
        self.previous.is_some()
    }

    /// Whether the keys of this member come from `seed`: the client checks
    /// which of its stored seeds the group reads with after a re-key went
    /// back (`GRP-411`).
    pub fn reads_with(&self, seed: &Secret<32>) -> bool {
        let key = |keys: &MemberKeys| {
            umbra_crypto::hash::sha3_256(&[&keys.roster().verifying_key().to_bytes()])
        };
        key(&self.keys) == key(&MemberKeys::from_seed(seed))
    }

    /// Whether a re-key that another holder of the keys of this member made
    /// took the index of this member (`GRP-369`). The member then reads with
    /// the keys of that index until an admin adds it again (`GRP-370`,
    /// `GRP-371`), or the group needs a new invitation (`GRP-374`).
    pub fn lost_rekey(&self) -> bool {
        self.previous.is_none()
            && self
                .roster
                .member(self.own_index)
                .is_some_and(|member| !member.active)
            && self.roster.successor_of(self.own_index).is_some()
    }

    /// The `RekeyRecord` of `GRP-370` for the pairwise channel to an admin:
    /// the chain fields are zero, the index is the one that this member
    /// held, and the signature is under the keys of that index.
    pub fn pairwise_rekey_object<R: TryCryptoRng + ?Sized>(
        &self,
        fresh: &super::join::JoinKeys,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        if !self.lost_rekey() {
            return Err(Error::NoPath);
        }
        super::join::rekey_record(&self.keys, fresh, &self.roster, self.own_index, false, rng)
    }

    /// Discards each held record past `GROUP_ROSTER_WAIT` at `now`, and
    /// returns the count, which the client shows as a gap (`GRP-253`,
    /// `GRP-254`).
    pub fn expire_held(&mut self, now: u64) -> usize {
        let current = self.epochs.epoch();
        self.pending
            .retain(|held| now.saturating_sub(held.arrived_at) < GROUP_ROSTER_WAIT);
        self.waiting
            .retain(|held| now.saturating_sub(held.arrived_at) < GROUP_ROSTER_WAIT);
        // A record that left the list at its bound is a gap too.
        self.receiver
            .expire_held(now, current)
            .saturating_add(self.receiver.take_evicted())
    }

    /// Whether a gap in the counter of one sender passed
    /// `GROUP_GAP_TIMEOUT`, thus the reader fetches from the other replica
    /// (`GRP-205`).
    pub fn needs_other_replica(&self, now: u64) -> bool {
        self.receiver.needs_other_replica(now)
    }

    /// The plain epoch that adds a joiner, from the `JoinRecord` that the
    /// pairwise channel carried (`GRP-310`).
    pub fn add_object(&self, join: &JoinRecord<'_>) -> Result<Vec<u8>, Error> {
        super::join::add_epoch(&self.roster, join)
    }

    /// The plain epoch that removes `index` (`GRP-382`). The caller posts
    /// it and rotates directly after it (`GRP-264`).
    pub fn remove_object(&self, index: u16) -> Result<Vec<u8>, Error> {
        self.plain_epoch(PlainOp::Remove { index })
    }

    /// The granting epoch that gives `role` to the member at `index`,
    /// signed under the roster key of this member (`GRP-060`, `GRP-061`).
    /// It carries that key, whose hash the roster entry of this member
    /// binds (`GRP-316`). The roster checks the authority when it applies
    /// the epoch; this call refuses a member below `admin` at once.
    pub fn grant<R: TryCryptoRng + ?Sized>(
        &self,
        index: u16,
        role: Role,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        if self.own_role().is_none_or(|own| own < Role::Admin) {
            return Err(Error::Unverified);
        }
        let grantee = self
            .roster
            .member(index)
            .filter(|member| member.active)
            .ok_or(Error::NoPath)?;
        let granter_pk = self.keys.roster().verifying_key().to_bytes();
        let mut epoch = GrantingEpoch {
            chain: Chain {
                group_id: *self.roster.group_id(),
                epoch_index: self.roster.epoch_index().saturating_add(1),
                previous_epoch_hash: *self.roster.chain_hash(),
            },
            granter_index: self.own_index,
            grantee_index: index,
            grantee_roster_pk_hash: grantee.roster_pk_hash,
            role,
            granter_roster_pk: &granter_pk,
            sig: &[],
        };
        let sig = self.keys.roster().sign(&epoch.preimage(), rng)?.to_bytes();
        epoch.sig = &sig;
        let mut payload = alloc::vec![0u8; 6_000];
        let n = epoch.encode(&mut payload)?;
        super::join::wrap(
            ControlType::GrantingEpoch,
            payload.get(..n).ok_or(Error::Malformed)?,
        )
    }

    /// The moderation epoch of `actions`, each an action byte and the
    /// `msg_id` of its target, signed under the roster key of this member
    /// (`GRP-077`, `GRP-078`). The preimage names no author (`GRP-179`),
    /// thus each hint is `0xFFFF`. A member below `moderator` makes none
    /// (`GRP-081`).
    pub fn moderate<R: TryCryptoRng + ?Sized>(
        &self,
        actions: &[(u8, [u8; 16])],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let Some(role) = self.own_role().filter(|role| *role >= Role::Moderator) else {
            return Err(Error::Unverified);
        };
        let actor_pk = self.keys.roster().verifying_key().to_bytes();
        let mut epoch = ModerationEpoch {
            chain: Chain {
                group_id: *self.roster.group_id(),
                epoch_index: self.roster.epoch_index().saturating_add(1),
                previous_epoch_hash: *self.roster.chain_hash(),
            },
            actor_index: self.own_index,
            actor_role: role,
            actions: actions
                .iter()
                .map(|(action, target)| ModAction {
                    action: *action,
                    target: *target,
                    author_hint: 0xFFFF,
                })
                .collect(),
            actor_roster_pk: &actor_pk,
            sig: &[],
        };
        let sig = self.keys.roster().sign(&epoch.preimage(), rng)?.to_bytes();
        epoch.sig = &sig;
        let mut payload = alloc::vec![0u8; 6_000];
        let n = epoch.encode(&mut payload)?;
        super::join::wrap(
            ControlType::ModerationEpoch,
            payload.get(..n).ok_or(Error::Malformed)?,
        )
    }

    /// Whether this member may leave (`GRP-067`). The last owner of a group
    /// that holds another member first gives `owner` to one of them. Thus
    /// no group stays with members and no owner. An owner that leaves
    /// another owner behind leaves, and so does the last member.
    pub fn may_leave(&self) -> bool {
        self.own_role() != Some(Role::Owner)
            || self.roster.owner_count() > 1
            || self.roster.active_count() <= 1
    }

    /// The plain epoch by which this member leaves (`GRP-067`). An owner
    /// that [`Group::may_leave`] holds back gets none.
    pub fn leave_object(&self) -> Result<Vec<u8>, Error> {
        if !self.may_leave() {
            return Err(Error::NoPath);
        }
        self.plain_epoch(PlainOp::SelfRemoval)
    }

    fn plain_epoch(&self, op: PlainOp<'_>) -> Result<Vec<u8>, Error> {
        let epoch = PlainEpoch {
            chain: Chain {
                group_id: *self.roster.group_id(),
                epoch_index: self.roster.epoch_index().saturating_add(1),
                previous_epoch_hash: *self.roster.chain_hash(),
            },
            op,
        };
        let mut payload = alloc::vec![0u8; 1_400];
        let n = epoch.encode(&mut payload)?;
        super::join::wrap(
            ControlType::PlainEpoch,
            payload.get(..n).ok_or(Error::Malformed)?,
        )
    }

    /// Whether the key of the current epoch reaches a party that a trigger
    /// since its roster epoch removed, thus this member rotates before it
    /// posts a record that is no roster object (`GRP-422`). A member that
    /// the trigger excludes posts nothing, and it withholds nothing.
    pub fn withholds(&self) -> bool {
        let Some(current) = self.epochs.current() else {
            return false;
        };
        let triggers = self.roster.triggers_since(current.roster_epoch());
        !triggers.is_empty()
            && !triggers
                .iter()
                .any(|trigger| trigger.excluded == Some(self.own_index))
    }

    /// The rotator of the current epoch secret.
    pub fn epoch_rotator(&self) -> Option<u16> {
        self.epochs.current().map(EpochState::rotator)
    }

    /// The rotation this group owes at `now`, from a trigger on the roster
    /// chain since the current epoch or from the age of that epoch
    /// (§11.4.1). A member the trigger excludes owes none (`GRP-356`).
    pub fn owes_rotation(&self, now: u64) -> Option<Trigger> {
        let current = self.epochs.current()?;
        if !self.roster.member(self.own_index).is_some_and(|m| m.active) {
            return None;
        }
        let triggers = self.roster.triggers_since(current.roster_epoch());
        if triggers
            .iter()
            .any(|trigger| trigger.excluded == Some(self.own_index))
        {
            return None;
        }
        if let Some(last) = triggers.last() {
            return Some(*last);
        }
        // GRP-360: the age of the epoch is a trigger of its own.
        current.aged(now).then_some(Trigger {
            excluded: None,
            roster_epoch: self.roster.epoch_index(),
        })
    }

    /// The backoff of this member at a trigger it did not cause
    /// (`GRP-358`, `GRP-380`). The admin that caused the trigger draws
    /// none, under `GRP-264`.
    pub fn rotation_delay<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> u64 {
        let role = self
            .roster
            .member(self.own_index)
            .map_or(Role::Member, |member| member.role);
        backoff::rotation_delay(role, rng.next_u32())
    }

    /// Whether an active member of the roster holds no KEM key here yet,
    /// thus a rotation waits for that key (`GRP-422`, `GRP-329`).
    pub fn lacks_member_key(&self) -> bool {
        self.roster.active().any(|member| member.kem_pk.is_none())
    }

    /// Builds the epoch-key record of the next epoch and installs it here
    /// (§11.4.1 step 2, `GRP-276` to `GRP-280`). Each member the roster
    /// holds now takes one slot, and a member it dropped takes none. The
    /// group queue keeps the credentials of the epoch before this one for
    /// its graces, thus a member that has not read the record still reads.
    pub fn rotate<R: CryptoRng + TryCryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<Rotation, Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        let epoch = current.epoch().checked_add(1).ok_or(Error::NoPath)?;
        let write = current.credentials().write_secret();
        let roster_epoch = self.roster.epoch_index();
        // GRP-288: the checks of the new epoch count from this one, or
        // from the base of it for a second epoch of one roster epoch.
        let (base, repeat) = current.base_of_next(roster_epoch);
        if !self.roster.member(self.own_index).is_some_and(|m| m.active) {
            return Err(Error::Unverified);
        }
        // GRP-387: only a rotator at `admin` or above holds the owner
        // credentials, and a rotator below it fills no slot with them.
        let own_sks = self.owners.as_ref().filter(|_| {
            self.roster
                .member(self.own_index)
                .is_some_and(|member| member.role >= Role::Admin)
        });
        let mut members: Vec<(u16, Role, Vec<u8>, PairKey)> = Vec::new();
        for member in self.roster.active() {
            let kem_pk = member.kem_pk.clone().ok_or(Error::NoPath)?;
            // GRP-237, GRP-308: a member whose key gives no pair key, or
            // whose KEM key does not decode, takes no slot. The roster
            // takes no such key (`GRP-320`); one that an earlier roster
            // took stops no rotation, and an admin removes that index.
            let Ok(pair) = self.keys.pair_key(&member.pair_pk, self.roster.group_id()) else {
                continue;
            };
            if umbra_crypto::kem::PublicKey::from_bytes(&kem_pk).is_err() {
                continue;
            }
            members.push((member.index, member.role, kem_pk, pair));
        }
        let included: Vec<Included<'_>> = members
            .iter()
            .map(|(index, role, kem_pk, pair)| Included {
                index: *index,
                role: *role,
                kem_pk,
                pair_key: pair,
            })
            .collect();
        let admins = included
            .iter()
            .filter(|member| member.role >= Role::Admin && own_sks.is_some())
            .count();
        // GRP-280: the slots go inline when a bucket holds them, and on
        // the chunk path otherwise.
        let bucket =
            bucket_for_slots(admins, included.len().saturating_sub(admins)).unwrap_or(Bucket::B3);
        let slot_count = u16::try_from(included.len()).map_err(|_| Error::Malformed)?;
        let output = rotate(
            self.roster.group_id(),
            epoch,
            roster_epoch,
            self.own_index,
            &included,
            own_sks,
            now,
            bucket,
            rng,
        )?;
        let carrier = match (output.inline, output.chunks) {
            (Some(body), _) => {
                // GRP-383: the header carries `t_{e+1}` in its slot field.
                let record = GroupQueueRecord {
                    kind: RecordKind::EpochKey,
                    epoch,
                    slot: output.start_slot,
                    nonce: [0; 12],
                    body: &body,
                };
                let mut bytes = alloc::vec![0u8; bucket.group_record()];
                let n = record.encode(bucket, &mut bytes)?;
                bytes.truncate(n);
                EpochCarrier::Inline(bytes)
            }
            (None, Some(chunks)) => EpochCarrier::Chunked(ChunkedEpoch {
                object: chunks.concat(),
                slots_per_chunk: output.slots_per_chunk,
                slot_count,
                start_slot: output.start_slot,
                roster_epoch,
            }),
            (None, None) => return Err(Error::Malformed),
        };
        self.epochs.install(
            EpochState::new(
                output.secret,
                self.roster.group_id(),
                epoch,
                output.start_slot,
                roster_epoch,
                self.own_index,
                now,
            )
            .after(base, repeat),
        )?;
        self.roster.note_rotation(roster_epoch);
        let current = self.epochs.epoch();
        self.pending.retain(|held| held.epoch >= current);
        self.waiting.retain(|held| held.epoch > current);
        Ok(Rotation {
            carrier,
            epoch,
            write,
        })
    }

    /// The epoch-key record of a chunked rotation, after the slot object
    /// reached the chunk path under `descriptor` (`GRP-283`).
    pub fn chunked_record(
        &self,
        epoch: u32,
        chunked: &ChunkedEpoch,
        descriptor: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let body = EpochKeyBody {
            roster_epoch: chunked.roster_epoch,
            slot_count: chunked.slot_count,
            carrier: Carrier::Chunked {
                slots_per_chunk: chunked.slots_per_chunk,
                descriptor,
            },
        };
        let need = EPOCH_KEY_FIXED
            .saturating_add(4)
            .saturating_add(descriptor.len());
        let bucket = BUCKETS
            .into_iter()
            .find(|bucket| need <= bucket.group_body())
            .ok_or(Error::Malformed)?;
        let mut body_bytes = alloc::vec![0u8; bucket.group_body()];
        let n = body.encode(bucket, &mut body_bytes)?;
        body_bytes.truncate(n);
        let record = GroupQueueRecord {
            kind: RecordKind::EpochKey,
            epoch,
            slot: chunked.start_slot,
            nonce: [0; 12],
            body: &body_bytes,
        };
        let mut bytes = alloc::vec![0u8; bucket.group_record()];
        let n = record.encode(bucket, &mut bytes)?;
        bytes.truncate(n);
        Ok(bytes)
    }

    /// The chunk that holds the slot of this member, when an epoch-key
    /// record carries its slots on the chunk path; none for an inline
    /// record (`GRP-284`). This member fetches that chunk alone
    /// (`GRP-285`).
    pub fn wanted_chunk(
        &self,
        epoch: u32,
        start_slot: u32,
        body: &[u8],
        now: u64,
    ) -> Result<Option<WantedChunk>, Error> {
        let parsed = EpochKeyBody::parse(body, |_| Some(0));
        let Ok(EpochKeyBody {
            roster_epoch,
            slot_count,
            carrier:
                Carrier::Chunked {
                    slots_per_chunk,
                    descriptor,
                },
        }) = parsed
        else {
            return Ok(None);
        };
        self.check_epoch(epoch)?;
        // GRP-357: any writer of the queue posts such a record at any time.
        // Thus this member fetches a chunk only for an epoch that a trigger
        // calls for, inside the bound of `GRP-288`. A record that comes
        // before its roster object waits, and `Group::retry_held` gives it
        // back. The slot names the rotator, thus its check follows the
        // fetch.
        if epoch > self.epochs.epoch() {
            self.check_above(epoch, roster_epoch, start_slot, None, false, now)?;
        }
        // The rotation served the active set of its roster epoch in index
        // order, thus the rank of this member there names its block.
        // A rotation of a roster epoch before a re-key served the index
        // before it (GRP-372).
        let rank = self
            .roster
            .rank_at(roster_epoch, self.own_index)
            .or_else(|| {
                self.previous
                    .as_ref()
                    .and_then(|previous| self.roster.rank_at(roster_epoch, previous.index))
            })
            .ok_or(Error::NoPath)?;
        let chunk = rank / usize::from(slots_per_chunk);
        Ok(Some(WantedChunk {
            descriptor: descriptor.to_vec(),
            chunk: u32::try_from(chunk).map_err(|_| Error::Malformed)?,
            epoch,
            start_slot,
            roster_epoch,
            slot_count,
            slots_per_chunk,
        }))
    }

    /// Installs the epoch from the block of the chunk path that holds the
    /// slot of this member (`GRP-284`, `GRP-286`).
    pub fn install_chunk(
        &mut self,
        wanted: &WantedChunk,
        block: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        self.check_epoch(wanted.epoch)?;
        let first = usize::try_from(wanted.chunk)
            .map_err(|_| Error::Malformed)?
            .saturating_mul(usize::from(wanted.slots_per_chunk));
        let count = usize::from(wanted.slots_per_chunk)
            .min(usize::from(wanted.slot_count).saturating_sub(first));
        let mut refused = Error::NoPath;
        // GRP-388: the rotator's role sets the length of an admin slot.
        for admin_layout in [true, false] {
            let Some(slots) = self.block_slots(block, count, admin_layout) else {
                continue;
            };
            match self.read_own_slot(wanted.roster_epoch, &slots, wanted.epoch, wanted.start_slot) {
                Ok((payload, is_current)) => {
                    // The other blocks hold the other slots, thus the count
                    // alone says whether the record served the group.
                    let serves_all = self.serves_all(wanted.roster_epoch, wanted.slot_count, None);
                    return self.install_opened(
                        Opened {
                            epoch: wanted.epoch,
                            start_slot: wanted.start_slot,
                            roster_epoch: wanted.roster_epoch,
                            payload,
                            is_current,
                            serves_all,
                            arrived_at: now,
                        },
                        now,
                    );
                }
                Err(error) => refused = error,
            }
        }
        Err(refused)
    }

    /// Whether a record holds a slot for each member that was active at
    /// `roster_epoch` (`GRP-276`). The record has `slot_count` slots, for
    /// the members of `indices` when the slots are inline. A record that
    /// does not is a key supply, and its secret takes no part in the index
    /// rule of `GRP-273`.
    fn serves_all(&self, roster_epoch: u32, slot_count: u16, indices: Option<&[u16]>) -> bool {
        match (self.roster.active_at(roster_epoch), indices) {
            (Some(set), Some(held)) => set.iter().all(|index| held.contains(index)),
            (Some(set), None) => usize::from(slot_count) >= set.len(),
            (None, _) => slot_count > 1,
        }
    }

    /// The slots of one block of the chunk path under one layout, or none
    /// when the block does not hold `count` of them.
    fn block_slots<'a>(
        &self,
        block: &'a [u8],
        count: usize,
        admin_layout: bool,
    ) -> Option<Vec<umbra_wire::group::record::KemSlot<'a>>> {
        let mut slots = Vec::with_capacity(count);
        let mut at = 0usize;
        for _ in 0..count {
            let head = block.get(at..at.checked_add(2)?)?;
            let index = u16::from_be_bytes([*head.first()?, *head.get(1)?]);
            let role = self.roster.member(index)?.role;
            let own = if admin_layout && role >= Role::Admin {
                REPLICAS
            } else {
                0
            };
            let start = at.checked_add(2)?;
            let end = start.checked_add(slot_len(own).checked_sub(2)?)?;
            slots.push(umbra_wire::group::record::KemSlot {
                index,
                sealed: block.get(start..end)?,
            });
            at = end;
        }
        // GRP-281: zero bytes fill the rest of the block.
        block
            .get(at..)?
            .iter()
            .all(|byte| *byte == 0)
            .then_some(slots)
    }

    /// Installs the epoch that an epoch-key record starts (`GRP-286`,
    /// `GRP-356`, `GRP-357`). A record that holds no slot for this member
    /// leaves the state as it was, and §11.4.3 covers the repair. A record
    /// of an epoch above the current one can open before the roster calls
    /// for it. Such a record waits here, and `Group::retry_held` installs
    /// it after the roster object that it answers.
    pub fn install_epoch_key(
        &mut self,
        epoch: u32,
        start_slot: u32,
        body: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        if let Err(error) = self.check_epoch(epoch) {
            // GRP-288: a record below the current epoch installs nothing.
            // Its slot can still tell that the current epoch is the second
            // of its roster epoch, and it opens for that alone.
            let can_tell = self.epochs.current().is_some_and(|current| {
                !current.is_repeat() && current.base().is_some_and(|base| epoch > base.epoch)
            });
            if can_tell {
                if let Ok(opened) = self.open_epoch_slot(epoch, start_slot, body, now) {
                    self.note_lower(&opened);
                }
            }
            return Err(error);
        }
        match self.open_epoch_slot(epoch, start_slot, body, now) {
            Ok(opened) => self.install_opened(opened, now),
            Err(error) => {
                self.keep_waiting(epoch, start_slot, body, now);
                Err(error)
            }
        }
    }

    /// GRP-288: a record of an epoch below the current one installs
    /// nothing.
    fn check_epoch(&self, epoch: u32) -> Result<(), Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        if epoch < current.epoch() {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Whether the roster calls for an epoch above the current one at `now`
    /// (`GRP-357`, `GRP-360`). A trigger since the roster epoch of the
    /// current epoch calls for one, and so does the age of that epoch. A
    /// rival re-key at that roster epoch that leaves room for one more
    /// epoch calls for one too (`GRP-369`).
    fn rotation_called(&self, now: u64) -> bool {
        self.epochs.current().is_some_and(|current| {
            !self
                .roster
                .triggers_since(current.roster_epoch())
                .is_empty()
                || current.aged(now)
                || self.roster.rival_allows_rotation(current.roster_epoch())
        })
    }

    /// Whether an epoch-key record that names `roster_epoch` can answer a
    /// trigger that the roster of this member never held (`GRP-357`,
    /// `GRP-288`). A member that an admit placed holds the roster from the
    /// epoch of its add on. It holds the chain of its epoch with no `K_e`
    /// (`GRP-313`, `GRP-384`). A trigger before its add is thus no fact
    /// that it reads. The rotation that answers that trigger can come after
    /// the add, at the end of a backoff. Such a member takes the epoch
    /// directly above its own when the record names a roster epoch at or
    /// above that of its add. `check_above` holds the number to that one,
    /// and the rotator to an active member that no later trigger excludes.
    /// One epoch answers each trigger before the add, thus a higher number
    /// waits for a trigger that the member reads. The epoch that it
    /// installs holds `K_e`, thus this state ends there.
    fn first_since_admission(&self, roster_epoch: u32) -> bool {
        self.epochs
            .current()
            .is_some_and(|current| !current.holds_secret())
            && roster_epoch >= self.roster.admission_epoch()
    }

    /// GRP-356: the record of an epoch above the current one names a roster
    /// epoch at or above the first trigger since the current epoch. Its
    /// rotator is no index that a trigger since then excludes. Thus a
    /// removed member cannot post a later epoch under any roster epoch. An
    /// honest rotator that a later trigger removed rotates again under Part
    /// 11 §11.4.3. A key supply of an epoch that a held record names
    /// (`supplied`) carries the roster epoch of its rotation (`GRP-375`).
    /// That roster epoch can lie below the first trigger that this member
    /// holds, and never below the roster epoch of the current epoch. The
    /// number of such a record lies inside the bound of `GRP-288`.
    fn check_rotator(
        &self,
        epoch: u32,
        roster_epoch: u32,
        rotator: u16,
        supplied: bool,
    ) -> Result<(), Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        if epoch > current.epoch() {
            return self.check_from(
                current.as_base(),
                1,
                epoch,
                roster_epoch,
                current.start_slot(),
                Some(rotator),
                supplied,
            );
        }
        if epoch < current.epoch() {
            return Ok(());
        }
        // A second record of the current epoch races the first (GRP-273,
        // GRP-288). It answers the triggers since the base of that epoch,
        // as the first did. A stored form before the base holds the epoch
        // before, inside its grace. Without either no check holds, and the
        // record installs nowhere here.
        let base = current
            .base()
            .map(|base| base.roster_epoch)
            .or_else(|| self.epochs.previous().map(EpochState::roster_epoch))
            .ok_or(Error::Unverified)?;
        self.check_triggers(base, roster_epoch, Some(rotator), supplied)
    }

    /// The checks of `GRP-356` on a record, with the triggers counted from
    /// the roster epoch `base`. A chunked record names no rotator before
    /// its fetch, and `rotator` is none for it.
    fn check_triggers(
        &self,
        base: u32,
        roster_epoch: u32,
        rotator: Option<u16>,
        supplied: bool,
    ) -> Result<(), Error> {
        let triggers = self.roster.triggers_since(base);
        let first = triggers.iter().map(|trigger| trigger.roster_epoch).min();
        let floor = if supplied { Some(base) } else { first };
        if floor.is_some_and(|floor| roster_epoch < floor) {
            return Err(Error::Unverified);
        }
        // GRP-356: an index that any trigger since the epoch before
        // excludes rotates nothing, whatever roster epoch its record names.
        let excluded = triggers
            .iter()
            .any(|trigger| rotator.is_some() && trigger.excluded == rotator);
        if excluded {
            return Err(Error::Unverified);
        }
        Ok(())
    }

    /// The checks of an epoch above the current one, counted from `base`:
    /// `GRP-356`, and the bound of `GRP-288` on its number.
    ///
    /// The number of an epoch gives no authority, and it is no free name. A
    /// rotation needs the number above it, and no epoch installs below the
    /// current one. A record of the highest number would thus end each
    /// later rotation. An honest epoch lies at most this far above `base`,
    /// in three terms. The first is two epochs for each roster epoch from
    /// the one of `base` to the one of the record. A trigger takes one
    /// roster epoch, and a rival re-key takes a second epoch of its roster
    /// epoch (`GRP-369`). The second is `slack`, for a second epoch of the
    /// roster epoch of `base` itself. The third is one epoch for each
    /// `GROUP_EPOCH_MAX_AGE` between the two start slots (`GRP-360`). Each
    /// term comes from the record and from `base`. Thus two members that
    /// hold one base give one record one verdict, whatever each one read of
    /// the roster.
    #[allow(clippy::too_many_arguments)]
    fn check_from(
        &self,
        base: Base,
        slack: u32,
        epoch: u32,
        roster_epoch: u32,
        start_slot: u32,
        rotator: Option<u16>,
        supplied: bool,
    ) -> Result<(), Error> {
        self.check_triggers(base.roster_epoch, roster_epoch, rotator, supplied)?;
        let room = roster_epoch
            .saturating_sub(base.roster_epoch)
            .saturating_mul(2)
            .saturating_add(slack)
            .saturating_add(aged_runs(base.start_slot, start_slot));
        if epoch.saturating_sub(base.epoch) > room {
            return Err(Error::Unverified);
        }
        Ok(())
    }

    /// Whether a record of an epoch above the current one installs
    /// (`GRP-288`, `GRP-356`, `GRP-357`). The result is the base that its
    /// epoch takes, with the mark of a second epoch of one roster epoch. It
    /// installs in one of three ways:
    ///
    /// - as the successor of the current epoch: the roster calls for a
    ///   rotation since that epoch, and the checks count from it;
    /// - as the first epoch of a member that an admit placed, under the
    ///   number directly above its own (`first_since_admission`);
    /// - as a rival of the current epoch: no trigger since that epoch calls
    ///   for it, and the checks pass from its base.
    ///
    /// A rival comes when two members answer one trigger from two epochs,
    /// after the order of `GRP-117` displaced a head that one of them held.
    /// Their records then carry two numbers, and the higher number stands
    /// at each member. A member that took the lower one first takes the
    /// higher one here. A member that took the higher one first refuses the
    /// lower one as stale. The base stays, thus the bound gives the two
    /// members the same room for each later record. No chain of such epochs
    /// runs past it.
    ///
    /// A second epoch of one roster epoch keeps the base of the first one
    /// in each way. Thus the base is a fact of the records and not of their
    /// order.
    fn check_above(
        &self,
        epoch: u32,
        roster_epoch: u32,
        start_slot: u32,
        rotator: Option<u16>,
        supplied: bool,
        now: u64,
    ) -> Result<(Option<Base>, bool), Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        let own = current.as_base();
        let above = current.base_of_next(roster_epoch);
        if self.rotation_called(now)
            && self
                .check_from(own, 1, epoch, roster_epoch, start_slot, rotator, supplied)
                .is_ok()
        {
            return Ok(above);
        }
        if self.first_since_admission(roster_epoch)
            && epoch == current.epoch().saturating_add(1)
            && self
                .check_triggers(own.roster_epoch, roster_epoch, rotator, supplied)
                .is_ok()
        {
            return Ok(above);
        }
        let base = current.base().ok_or(Error::Unverified)?;
        let age = u64::from(base.start_slot).saturating_mul(crate::group::GROUP_SLOT);
        let called = !self.roster.triggers_since(base.roster_epoch).is_empty()
            || now.saturating_sub(age) >= crate::group::GROUP_EPOCH_MAX_AGE;
        if !called {
            return Err(Error::Unverified);
        }
        self.check_from(base, 0, epoch, roster_epoch, start_slot, rotator, supplied)?;
        Ok((Some(base), above.1))
    }

    /// A record of a number below the current one whose slot opened
    /// (`GRP-288`). It can name the roster epoch of the current epoch, and
    /// be an epoch of the base of the current one. The current epoch is
    /// then the second of that roster epoch here, as at a member that
    /// installed the two in their order. The count of `GRP-369` and the
    /// base of the next epoch are then one at both.
    fn note_lower(&mut self, opened: &Opened) {
        let Some(current) = self.epochs.current() else {
            return;
        };
        let Some(base) = current.base() else {
            return;
        };
        let rotator = opened.payload.rotator;
        let is_lower = opened.epoch < current.epoch()
            && opened.epoch > base.epoch
            && opened.roster_epoch == current.roster_epoch()
            && opened.serves_all
            && !current.is_repeat();
        if !is_lower
            || self.role_at(rotator, opened.roster_epoch).is_none()
            || self
                .check_from(
                    base,
                    0,
                    opened.epoch,
                    opened.roster_epoch,
                    opened.start_slot,
                    Some(rotator),
                    false,
                )
                .is_err()
        {
            return;
        }
        self.epochs.mark_repeat();
        self.roster.note_rotation(opened.roster_epoch);
    }

    /// Whether an opened slot installs at `now`, and the base that its
    /// epoch takes. `NoPath` is the answer for a slot that can install
    /// later: its roster object has not arrived, or its `t_e` lies above
    /// the clock.
    ///
    /// An epoch above the next one installs under the checks of the next
    /// one and inside the bound of `check_from` (`GRP-288`). The secret
    /// comes from the rotator, and the tag proves that rotator to this
    /// member. `GRP-356` and `GRP-357` bind it to the roster. An index that
    /// a trigger excludes fails `check_triggers` under each number, and a
    /// record with no trigger fails under each number. A strict successor
    /// rule would keep a member that missed an epoch below the group for
    /// the life of the epoch. It would do the same to a member whose chain
    /// never held the trigger, because the order of `GRP-117` displaced
    /// that head.
    fn check_install(&self, opened: &Opened, now: u64) -> Result<(Option<Base>, bool), Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        if opened.epoch < current.epoch() {
            return Err(Error::Stale);
        }
        // GRP-383: `t_e` lies inside the bound of the clock. An epoch that
        // starts above it takes no record until the clock reaches it. An
        // epoch that starts below it is past `GROUP_EPOCH_MAX_AGE` at once.
        match start_slot_place(opened.start_slot, now) {
            core::cmp::Ordering::Greater => return Err(Error::NoPath),
            core::cmp::Ordering::Less => return Err(Error::Stale),
            core::cmp::Ordering::Equal => {}
        }
        // The roster object that the record answers has not arrived.
        if opened.roster_epoch > self.roster.epoch_index() {
            return Err(Error::NoPath);
        }
        if self
            .role_at(opened.payload.rotator, opened.roster_epoch)
            .is_none()
        {
            return Err(Error::Unverified);
        }
        let supplied = !opened.serves_all && self.receiver.holds_epoch_record(opened.epoch);
        if opened.epoch > current.epoch() {
            return self.check_above(
                opened.epoch,
                opened.roster_epoch,
                opened.start_slot,
                Some(opened.payload.rotator),
                supplied,
                now,
            );
        }
        self.check_rotator(
            opened.epoch,
            opened.roster_epoch,
            opened.payload.rotator,
            supplied,
        )?;
        // A second secret of the current epoch stands where the first one
        // does.
        Ok((current.base(), current.is_repeat()))
    }

    /// Installs what an opened slot gives, or keeps it for a later try.
    fn install_opened(&mut self, opened: Opened, now: u64) -> Result<(), Error> {
        // GRP-400: a slot with no epoch secret hands the owner credentials
        // and installs no epoch. Only a slot of the current epoch holds it.
        if umbra_crypto::ct_eq(opened.payload.epoch_secret.expose(), &[0; 32]) {
            if opened.epoch != self.epochs.epoch() || opened.payload.own_sks.len() != GROUP_REPLICAS
            {
                return Err(Error::Unverified);
            }
            // GRP-379, GRP-401: only an admin of the roster that stands
            // hands them. A member that left the role or the group keeps
            // its pair key. Its slot would put its own bytes in the place
            // of the credentials that the relay holds.
            if !self
                .roster
                .member(opened.payload.rotator)
                .is_some_and(|member| member.active && member.role >= Role::Admin)
            {
                return Err(Error::Unverified);
            }
            self.take_owners(&opened.payload);
            // GRP-372: a slot for the new index ends the keys before it.
            if opened.is_current {
                self.previous = None;
            }
            return Ok(());
        }
        let (base, repeat) = match self.check_install(&opened, now) {
            Ok(place) => place,
            Err(error) => {
                if matches!(error, Error::Unverified | Error::NoPath) {
                    self.keep_pending(opened);
                }
                return Err(error);
            }
        };
        let before = self.epochs.epoch();
        let secret = EpochSecret::from_secret(Secret::new(*opened.payload.epoch_secret.expose()));
        // GRP-386: the two queue credentials come from `K_e`.
        let mut state = EpochState::new(
            secret,
            self.roster.group_id(),
            opened.epoch,
            opened.start_slot,
            opened.roster_epoch,
            opened.payload.rotator,
            now,
        )
        .after(base, repeat);
        if !opened.serves_all {
            state = state.supplied();
        }
        self.epochs.install(state)?;
        let current = self.epochs.epoch();
        if current != before {
            // GRP-369: an epoch after a rival re-key answers it.
            self.roster.note_rotation(opened.roster_epoch);
            self.pending.retain(|held| held.epoch >= current);
            self.waiting.retain(|held| held.epoch > current);
        }
        self.take_owners(&opened.payload);
        // GRP-372: a slot for the new index ends the keys before it.
        if opened.is_current {
            self.previous = None;
        }
        Ok(())
    }

    /// Keeps an opened slot of an epoch above the current one that does not
    /// install yet. Its rotator is an active member, thus a member that
    /// left fills no place, and the oldest one leaves at the bound.
    fn keep_pending(&mut self, opened: Opened) {
        let rotator = opened.payload.rotator;
        let is_known = self.pending.iter().any(|held| {
            held.epoch == opened.epoch
                && held.payload.rotator == rotator
                && umbra_crypto::ct_eq(
                    held.payload.epoch_secret.expose(),
                    opened.payload.epoch_secret.expose(),
                )
        });
        if is_known
            || opened.epoch <= self.epochs.epoch()
            || !self.roster.member(rotator).is_some_and(|m| m.active)
        {
            return;
        }
        if self.pending.len() >= PENDING_MAX {
            self.pending.remove(0);
        }
        self.pending.push(opened);
    }

    /// Keeps the body of a chunked epoch-key record of an epoch above the
    /// current one for which this member fetches no chunk yet. Any writer
    /// of the queue posts such a body, and nothing in it verifies before
    /// the fetch. Thus a body that no rotation can give stays out, and at
    /// the bound the body of the highest epoch leaves. The next epoch is
    /// the lowest one, and a body of a later epoch takes no place of it.
    fn keep_waiting(&mut self, epoch: u32, start_slot: u32, body: &[u8], now: u64) {
        let Ok(EpochKeyBody {
            roster_epoch,
            slot_count,
            carrier: Carrier::Chunked { .. },
        }) = EpochKeyBody::parse(body, |_| Some(0))
        else {
            return;
        };
        // GRP-383: a start slot past the age bound installs nothing.
        // GRP-256: a record below the admission of this member holds no
        // slot for it.
        let is_possible = start_slot_place(start_slot, now) != core::cmp::Ordering::Less
            && roster_epoch >= self.roster.admission_epoch()
            && slot_count > 0
            && usize::from(slot_count) <= super::GROUP_MAX;
        if !is_possible
            || epoch <= self.epochs.epoch()
            || self
                .waiting
                .iter()
                .any(|held| held.epoch == epoch && held.body == body)
        {
            return;
        }
        if self.waiting.len() >= WAITING_MAX {
            // The highest epoch leaves, and of one epoch the body that came
            // last. A body that came first keeps its place.
            let Some((last, highest)) = self
                .waiting
                .iter()
                .enumerate()
                .max_by_key(|(_, held)| (held.epoch, held.arrived_at))
                .map(|(place, held)| (place, held.epoch))
            else {
                return;
            };
            if epoch >= highest {
                return;
            }
            self.waiting.remove(last);
        }
        self.waiting.push(Waiting {
            epoch,
            start_slot,
            body: body.to_vec(),
            arrived_at: now,
        });
    }

    /// Tries each epoch that waits again, in the order of the epochs
    /// (`GRP-357`). An epoch that installs gives `Outcome::EpochInstalled`,
    /// and a chunked record that this member fetches now comes back as the
    /// `Outcome::EpochKey` that it was.
    fn retry_epochs(&mut self, now: u64) -> Vec<Outcome> {
        let mut out = Vec::new();
        let mut pending = core::mem::take(&mut self.pending);
        pending.sort_by_key(|held| held.epoch);
        for held in pending {
            if now.saturating_sub(held.arrived_at) >= GROUP_ROSTER_WAIT {
                continue;
            }
            let epoch = held.epoch;
            // A slot that waits again went back to the list.
            if self.install_opened(held, now).is_ok() {
                out.push(Outcome::EpochInstalled { epoch });
            }
        }
        for held in core::mem::take(&mut self.waiting) {
            if held.epoch <= self.epochs.epoch()
                || now.saturating_sub(held.arrived_at) >= GROUP_ROSTER_WAIT
            {
                continue;
            }
            let fetches = matches!(
                self.wanted_chunk(held.epoch, held.start_slot, &held.body, now),
                Ok(Some(_))
            );
            if fetches {
                out.push(Outcome::EpochKey {
                    epoch: held.epoch,
                    start_slot: held.start_slot,
                    body: held.body,
                });
            } else {
                self.waiting.push(held);
            }
        }
        out
    }

    /// Takes the owner credentials of a slot that carries them.
    fn take_owners(&mut self, payload: &SlotPayload) {
        if payload.own_sks.len() == GROUP_REPLICAS {
            let mut owners = [Secret::<32>::zeroed(), Secret::<32>::zeroed()];
            for (held, given) in owners.iter_mut().zip(payload.own_sks.iter()) {
                *held = Secret::new(*given.expose());
            }
            self.owners = Some(owners);
        }
    }

    /// Draws a new owner credential for each replica and holds it here,
    /// and gives the ones it replaced, which authorize the `GKEY` that
    /// moves each replica to the new ones (`WIR-522`, `GRP-401`).
    pub fn replace_owners<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<[Secret<32>; GROUP_REPLICAS], Error> {
        let old = self.owners.take().ok_or(Error::NoPath)?;
        let mut owners = [Secret::<32>::zeroed(), Secret::<32>::zeroed()];
        for owner in &mut owners {
            rng.fill_bytes(owner.expose_mut());
        }
        self.owners = Some(owners);
        Ok(old)
    }

    /// The one-slot record that hands the owner credentials that this
    /// member holds to the member at `index`, which holds `admin` or above
    /// (`GRP-298`, `GRP-400`).
    pub fn owner_delivery<R: CryptoRng + ?Sized>(
        &self,
        index: u16,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        if self.own_role().is_none_or(|own| own < Role::Admin) {
            return Err(Error::Unverified);
        }
        let owners = self.owners.as_ref().ok_or(Error::NoPath)?;
        let member = self
            .roster
            .member(index)
            .filter(|member| member.active && member.role >= Role::Admin)
            .ok_or(Error::NoPath)?;
        let kem_pk = member.kem_pk.clone().ok_or(Error::NoPath)?;
        let pair = self
            .keys
            .pair_key(&member.pair_pk, self.roster.group_id())?;
        let included = Included {
            index,
            role: member.role,
            kem_pk: &kem_pk,
            pair_key: &pair,
        };
        // GRP-400: no epoch secret, thus a promotee that joined inside the
        // epoch learns no record before its join.
        let roster_epoch = self.roster.epoch_index();
        self.one_slot_record(
            &included,
            roster_epoch,
            &Secret::new([0; 32]),
            Some(owners),
            rng,
        )
    }

    /// A one-slot epoch-key record of the current epoch for one member.
    fn one_slot_record<R: CryptoRng + ?Sized>(
        &self,
        member: &Included<'_>,
        roster_epoch: u32,
        secret: &Secret<32>,
        own_sks: Option<&[Secret<32>; GROUP_REPLICAS]>,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        let admins = usize::from(own_sks.is_some());
        let bucket = bucket_for_slots(admins, 1 - admins).ok_or(Error::NoPath)?;
        let body = one_slot(
            self.roster.group_id(),
            current.epoch(),
            current.start_slot(),
            roster_epoch,
            self.own_index,
            member,
            secret,
            own_sks,
            bucket,
            rng,
        )?;
        let record = GroupQueueRecord {
            kind: RecordKind::EpochKey,
            epoch: current.epoch(),
            slot: current.start_slot(),
            nonce: [0; 12],
            body: &body,
        };
        let mut bytes = alloc::vec![0u8; bucket.group_record()];
        let n = record.encode(bucket, &mut bytes)?;
        bytes.truncate(n);
        Ok(bytes)
    }

    /// Whether a record of an epoch that this member holds waits because
    /// its slot lies above the window at `now`: evidence of a clock
    /// movement, and the `clock` state of Part 14 §14.9.2 (`GRP-229`). A
    /// record below the window came late, as after a time offline, and
    /// names no clock.
    pub fn holds_clock_suspect(&self, now: u64) -> bool {
        self.held_at(now, core::cmp::Ordering::Greater)
    }

    /// Whether a record of an epoch that this member holds waits and its
    /// slot lies inside the window at `now`, thus a retry opens it: the
    /// clock check of `GRP-229`, after a clock movement or as the window
    /// moves. An epoch whose `t_e` lay above the clock at its arrival, and
    /// that the clock reached, installs at a retry too (`GRP-383`).
    pub fn holds_openable(&self, now: u64) -> bool {
        let reached = |held: &Opened| {
            start_slot_place(held.start_slot, held.arrived_at) == core::cmp::Ordering::Greater
                && start_slot_place(held.start_slot, now) == core::cmp::Ordering::Equal
        };
        self.held_at(now, core::cmp::Ordering::Equal) || self.pending.iter().any(reached)
    }

    fn held_at(&self, now: u64, place: core::cmp::Ordering) -> bool {
        self.receiver.held_slots().into_iter().any(|(epoch, slot)| {
            self.epochs.holds_epoch(epoch) && EpochStore::place_of(slot, now) == place
        })
    }

    /// The epoch that this member lacks: a record of a later epoch waits,
    /// and no epoch-key record of it opened here (§11.4.3, `GRP-289`).
    pub fn lacks_epoch(&self) -> Option<u32> {
        self.receiver
            .newest_held_epoch()
            .filter(|epoch| *epoch > self.epochs.epoch())
    }

    /// Whether this member may answer a `KeyRequest` of scope `0x02` from
    /// `index` for `epoch` (`GRP-375`, `GRP-377`, `GRP-404`): the epoch is
    /// the current one, this member holds its `K_e`, and the rotation of
    /// that epoch included `index`. A member that joined inside the epoch
    /// holds the chain from its join, and `K_e` would give it the records
    /// before that join.
    pub fn may_supply(&self, index: u16, epoch: u32) -> bool {
        let Some(current) = self.epochs.current() else {
            return false;
        };
        current.epoch() == epoch
            && current.holds_secret()
            && index != self.own_index
            && self
                .roster
                .member(index)
                .is_some_and(|member| member.active)
            && self
                .roster
                .active_at(current.roster_epoch())
                .is_some_and(|set| set.contains(&index))
            // GRP-369: a rival changed the keys at that index, and the
            // rotation of this epoch may have served the keys that lost.
            // The next epoch serves the keys that stand.
            && !self
                .roster
                .rival_bars_supply(index, current.roster_epoch())
    }

    /// The one-slot record that gives `K_e` of the current epoch to the
    /// member at `index`, with `own_count` 0 (`GRP-375`).
    pub fn key_supply<R: CryptoRng + ?Sized>(
        &self,
        index: u16,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        if !self.may_supply(index, current.epoch()) {
            return Err(Error::Unverified);
        }
        let member = self.roster.member(index).ok_or(Error::NoPath)?;
        let kem_pk = member.kem_pk.clone().ok_or(Error::NoPath)?;
        let pair = self
            .keys
            .pair_key(&member.pair_pk, self.roster.group_id())?;
        let included = Included {
            index,
            role: member.role,
            kem_pk: &kem_pk,
            pair_key: &pair,
        };
        // The roster epoch of the rotation, thus the requester counts the
        // triggers after it as every other member does (`GRP-357`).
        let secret = Secret::new(*current.secret().expose().expose());
        self.one_slot_record(&included, current.roster_epoch(), &secret, None, rng)
    }

    /// The member indices that the slots of an epoch-key body serve, under
    /// either layout of `GRP-388`. A member that waits to answer a request
    /// stands down when a one-slot record for that index arrives first.
    pub fn slot_indices(&self, body: &[u8]) -> Vec<u16> {
        for admin_layout in [true, false] {
            let parsed = EpochKeyBody::parse(body, |index| {
                self.roster.member(index).map(|member| {
                    if admin_layout && member.role >= Role::Admin {
                        REPLICAS
                    } else {
                        0
                    }
                })
            });
            if let Ok(EpochKeyBody {
                carrier: Carrier::Inline(slots),
                ..
            }) = parsed
            {
                return slots.iter().map(|slot| slot.index).collect();
            }
        }
        Vec::new()
    }

    /// Opens this member's slot in an epoch-key body and verifies its tag.
    /// The rotator's role sets the length of an admin slot and no field in
    /// the clear names the rotator, thus the admin layout is read first
    /// and the layout of a rotator that holds no owner credential after it
    /// (`GRP-388`).
    fn open_epoch_slot(
        &self,
        epoch: u32,
        start_slot: u32,
        body: &[u8],
        now: u64,
    ) -> Result<Opened, Error> {
        let mut refused = Error::Malformed;
        for admin_layout in [true, false] {
            let parsed = EpochKeyBody::parse(body, |index| {
                self.roster.member(index).map(|member| {
                    if admin_layout && member.role >= Role::Admin {
                        REPLICAS
                    } else {
                        0
                    }
                })
            });
            let Ok(parsed) = parsed else {
                continue;
            };
            let Carrier::Inline(slots) = &parsed.carrier else {
                // GRP-284: the slot of a chunked record is on the chunk
                // path, and `install_chunk` reads it.
                return Err(Error::NoPath);
            };
            match self.read_own_slot(parsed.roster_epoch, slots, epoch, start_slot) {
                Ok((payload, is_current)) => {
                    let indices: Vec<u16> = slots.iter().map(|slot| slot.index).collect();
                    let serves_all =
                        self.serves_all(parsed.roster_epoch, parsed.slot_count, Some(&indices));
                    return Ok(Opened {
                        epoch,
                        start_slot,
                        roster_epoch: parsed.roster_epoch,
                        payload,
                        is_current,
                        serves_all,
                        arrived_at: now,
                    });
                }
                Err(error) => refused = error,
            }
        }
        Err(refused)
    }

    /// Opens and verifies the slot of this member. `role_at` bars a
    /// rotator that the roster did not hold at `roster_epoch`, which is
    /// the index each trigger of that epoch excludes (`GRP-356`).
    /// The result says whether the slot was one of the index that stands,
    /// and not of the index before a re-key (`GRP-372`).
    fn read_own_slot(
        &self,
        roster_epoch: u32,
        slots: &[umbra_wire::group::record::KemSlot<'_>],
        epoch: u32,
        start_slot: u32,
    ) -> Result<(SlotPayload, bool), Error> {
        match self.read_slot_as(
            self.own_index,
            &self.keys,
            roster_epoch,
            slots,
            epoch,
            start_slot,
        ) {
            Ok(payload) => Ok((payload, true)),
            Err(error) => match &self.previous {
                Some(previous) => self
                    .read_slot_as(
                        previous.index,
                        &previous.keys,
                        roster_epoch,
                        slots,
                        epoch,
                        start_slot,
                    )
                    .map(|payload| (payload, false)),
                None => Err(error),
            },
        }
    }

    fn read_slot_as(
        &self,
        own_index: u16,
        keys: &MemberKeys,
        roster_epoch: u32,
        slots: &[umbra_wire::group::record::KemSlot<'_>],
        epoch: u32,
        start_slot: u32,
    ) -> Result<SlotPayload, Error> {
        let pair_with = |index: u16| {
            let member = self.roster.member(index)?;
            keys.pair_key(&member.pair_pk, self.roster.group_id()).ok()
        };
        super::epoch::open_own_slot(
            slots,
            own_index,
            keys,
            self.roster.group_id(),
            epoch,
            start_slot,
            roster_epoch,
            |index| self.role_at(index, roster_epoch),
            pair_with,
        )
    }

    /// The role of a rotator at `index` whose record names `roster_epoch`
    /// (`GRP-356`, `GRP-379`). The result is none when the member is not
    /// active now or was not active then. The record names its roster epoch
    /// itself, and the roster keeps the role of an entry that left. Thus
    /// the role of an entry counts only while the entry is active. A member
    /// that left the group gets none under any roster epoch. A member that
    /// left a role gets the role that it holds now, thus its slot hands no
    /// owner credentials. The history bounds the second test, thus an epoch
    /// that it does not hold leaves the first one alone.
    fn role_at(&self, index: u16, roster_epoch: u32) -> Option<Role> {
        let member = self.roster.member(index).filter(|member| member.active)?;
        self.roster
            .active_at(roster_epoch)
            .is_none_or(|set| set.contains(&index))
            .then_some(member.role)
    }

    /// Applies a roster object that this member made, after the member
    /// built the record that carries it at `now` (`GRP-389`). A pair key of
    /// a removed member leaves with it.
    pub fn apply_control(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
        now: u64,
    ) -> Result<Applied, Error> {
        let slot = send_slot(&self.epochs, now);
        self.apply_control_at(control, sender, slot, now)
    }

    /// The slot of a record of this member that goes out at `now`
    /// (`GRP-246`). A linked device gives a roster object of its member
    /// the slot of the record that carried it with this value.
    pub fn slot_of_record(&self, now: u64) -> u32 {
        send_slot(&self.epochs, now)
    }

    /// Applies a roster object that a verified tag attributes to `sender`
    /// (`GRP-318`). `slot` is the slot of the record that carried it, on
    /// which the rates of `GRP-076` count.
    pub fn apply_control_at(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
        slot: u32,
        now: u64,
    ) -> Result<Applied, Error> {
        let applied = self.apply_roster(control, sender, slot, now)?;
        self.revert_orphaned_rekey();
        Ok(applied)
    }

    /// Goes back to the index and the keys before a re-key of this member,
    /// when the roster no longer holds the keys of that re-key at its index
    /// and still holds the keys before it: a rival took its place
    /// (`GRP-369`, `GRP-411`), or an epoch of another member came first
    /// (`GRP-117`). The keys before it still read the group.
    fn revert_orphaned_rekey(&mut self) {
        let Some(previous) = self.previous.as_ref() else {
            return;
        };
        let holds = |index: u16, keys: &MemberKeys| {
            let hash = umbra_crypto::hash::sha3_256(&[&keys.roster().verifying_key().to_bytes()]);
            self.roster
                .member(index)
                .is_some_and(|member| member.roster_pk_hash == hash)
        };
        let holds_own = self
            .roster
            .member(self.own_index)
            .is_some_and(|member| member.active)
            && holds(self.own_index, &self.keys);
        if holds_own || !holds(previous.index, &previous.keys) {
            return;
        }
        if let Some(previous) = self.previous.take() {
            self.keys = previous.keys;
            self.pairs = previous.pairs;
            self.own_index = previous.index;
            self.receiver.set_own_index(previous.index);
            self.sender = Sender::default();
        }
    }

    /// The head of the roster chain that the last roster object displaced,
    /// once (`GRP-119`).
    pub fn take_displaced(&mut self) -> Option<super::roster::Displaced> {
        self.displaced.take()
    }

    /// Applies a roster object to the roster, and drops a pair key that no
    /// longer fits: the key of a member that left, and the key at an index
    /// whose keys a rival re-key changed.
    fn apply_roster(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
        slot: u32,
        now: u64,
    ) -> Result<Applied, Error> {
        let applied = self.roster.apply_at(control, sender, slot, now);
        // GRP-369: the second of two re-keys of one index verified now,
        // whichever one stands. The epochs of their roster epoch that this
        // member installed count from here, as they do at a member that
        // read the two first. With one such epoch, a rival that took the
        // place of the head is a trigger. The slot of that epoch for the
        // new index went to the keys that lost.
        if self.roster.take_rival_seen() {
            let head = self.roster.epoch_index();
            let held = self
                .epochs
                .current()
                .filter(|current| current.roster_epoch() == head)
                .map_or(0, |current| if current.is_repeat() { 2 } else { 1 });
            let took_place = matches!(applied, Ok(Applied::Rekeyed { replaced: true, .. }));
            self.roster.rival_after_rotation(held, took_place);
        }
        let applied = applied?;
        // GRP-263: the history keeps what the epochs of this member name.
        let keep_from = self.epochs.oldest_roster_epoch().unwrap_or(u32::MAX);
        self.roster.retain_history(now, keep_from);
        // GRP-117: another head took the place of the last one, and each
        // pair key comes from the roster again.
        if let Some(displaced) = self.roster.take_displaced() {
            self.pairs = PairCache::default();
            if let Some(previous) = self.previous.as_mut() {
                previous.pairs = PairCache::default();
            }
            self.displaced = Some(displaced);
        }
        match &applied {
            Applied::Removed(trigger) => {
                if let Some(index) = trigger.excluded {
                    self.pairs.remove(index);
                    self.receiver.removed(index);
                }
            }
            Applied::Rekeyed {
                new,
                replaced: true,
                ..
            } => {
                self.pairs.remove(*new);
                if let Some(previous) = self.previous.as_mut() {
                    previous.pairs.remove(*new);
                }
            }
            _ => {}
        }
        Ok(applied)
    }

    /// The admit for the member at `index`, with the slot key of its join
    /// and the two replicas (`GRP-312`), at the roster epoch that stands.
    pub fn admit_for(&self, index: u16, descriptor: &[u8], now: u64) -> Result<Vec<u8>, Error> {
        self.admit_at(index, self.roster.epoch_index(), descriptor, [0; 2], now)
    }

    /// The admit at `roster_epoch`, the roster epoch of the add and of its
    /// snapshot (`GRP-323`). The roster can move between the add and the
    /// admit, and the joiner checks the two against each other. `seqs` is
    /// the `seq` of the add at each replica, from its `GSEQ` (`GRP-311`),
    /// and the joiner subscribes from there.
    pub fn admit_at(
        &self,
        index: u16,
        roster_epoch: u32,
        descriptor: &[u8],
        seqs: [u32; 2],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        let replicas = self.replicas.as_ref().ok_or(Error::NoPath)?;
        let mut refs = [
            *replicas.reference(0).ok_or(Error::NoPath)?,
            *replicas.reference(1).ok_or(Error::NoPath)?,
        ];
        for (reference, seq) in refs.iter_mut().zip(seqs) {
            reference.seq_of_add = seq;
        }
        let slot = admit_slot(slot_of(now), current.start_slot());
        // GRP-423: an admin that joined inside the epoch holds no `K_e`,
        // thus it derives from its own chain.
        let started;
        let (chain, slot) = if current.holds_secret() {
            started = current.secret().start(
                self.roster.group_id(),
                current.epoch(),
                current.start_slot(),
            );
            (&started, slot)
        } else {
            let chain = current.chain();
            (chain, slot.max(chain.slot()))
        };
        admit(
            *self.roster.group_id(),
            index,
            current.epoch(),
            current.start_slot(),
            slot,
            chain,
            current.credentials(),
            roster_epoch,
            refs,
            descriptor,
        )
    }

    /// The roster snapshot that a joiner verifies against the hash of its
    /// add record (`GRP-326`). The path carries the granting epochs, and a
    /// group with no member above `member` has none.
    pub fn snapshot(&self, path: &[u8]) -> Result<Vec<u8>, Error> {
        let entries: Vec<GroupMemberEntry> = self.roster.entries();
        let keys: Vec<MemberKemKey<'_>> = self
            .roster
            .active()
            .filter_map(|member| {
                Some(MemberKemKey {
                    index: member.index,
                    kem_pk: member.kem_pk.as_deref()?,
                })
            })
            .collect();
        if keys.len() != entries.len() {
            return Err(Error::NoPath);
        }
        let snapshot = RosterSnapshot {
            group_id: *self.roster.group_id(),
            roster_epoch: self.roster.epoch_index(),
            chain_hash: *self.roster.chain_hash(),
            entries,
            keys,
            path,
        };
        let mut out = alloc::vec![0u8; snapshot.len()];
        let n = snapshot.encode(&mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::{abuse::test_rng::Rng, group::join::JoinKeys};
    use umbra_wire::{
        app::{AppKind, AppMessage, Channel},
        group::control::ControlType,
    };

    fn text(body: &str) -> Vec<u8> {
        let message = AppMessage {
            kind: AppKind::Text,
            msg_id: [7; 16],
            sent_at: 1_700_000_000_000,
            body: body.as_bytes(),
        };
        let mut out = alloc::vec![0u8; message.len()];
        let n = message.encode(&mut out).unwrap();
        out.truncate(n);
        out
    }

    /// Whether a record came back under a counter that its receiver took
    /// already (`GRP-206`).
    fn is_repeat(outcome: &Outcome) -> bool {
        matches!(outcome, Outcome::Content { repeated: true, .. })
    }

    /// The seed of the joiner in [`pair`], which a restore needs again.
    /// `Rng` is the test generator, thus the value is fixed.
    const JOINER_SEED: Secret<32> = Secret::new([0x09; 32]);

    /// The creator and one member that its add and its admit placed.
    fn pair(now: u64) -> (Group, Group, Vec<u8>) {
        pair_at(now, now)
    }

    /// A group made at `created` that a member joins at `now`.
    fn pair_at(created: u64, now: u64) -> (Group, Group, Vec<u8>) {
        let mut rng = Rng(9);
        let creator_seed = Secret::new([0x21; 32]);
        let mut creator = Group::create([0x55; 32], &creator_seed, created, &mut rng).unwrap();
        creator.set_replicas([
            ReplicaRef {
                relay_id: [1; 32],
                group_queue_id: [2; 32],
                seq_of_add: 0,
            },
            ReplicaRef {
                relay_id: [3; 32],
                group_queue_id: [4; 32],
                seq_of_add: 0,
            },
        ]);

        let joiner_keys = JoinKeys {
            seed: JOINER_SEED,
            keys: MemberKeys::from_seed(&JOINER_SEED),
        };
        let kem_pk = joiner_keys.keys.kem().public().to_bytes();
        let record = JoinRecord {
            group_id: *creator.group_id(),
            keys: joiner_keys.wire_keys(&kem_pk),
        };
        let add = creator.add_object(&record).unwrap();
        let control = GroupControl::parse(&add).unwrap();
        let add_hash = control.epoch_hash();
        assert_eq!(
            creator.apply_control(&control, 0, now).unwrap(),
            Applied::Added(1)
        );

        let admit_bytes = creator.admit_for(1, b"", now).unwrap();
        let admit_control = GroupControl::parse(&admit_bytes).unwrap();
        assert_eq!(admit_control.control_type, ControlType::Invitation);
        let invitation =
            umbra_wire::group::control::GroupInvitation::parse(admit_control.payload).unwrap();
        let snapshot_bytes = creator.snapshot(&[]).unwrap();
        let snapshot = RosterSnapshot::parse(&snapshot_bytes).unwrap();
        let creator_pk = creator.keys.roster().verifying_key().to_bytes();
        let admitted =
            crate::group::join::accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, now)
                .unwrap();
        let member = Group::joined(admitted, &joiner_keys.seed).unwrap();
        (creator, member, add)
    }

    #[test]
    fn two_members_read_each_other_and_a_third_party_reads_nothing() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        assert_eq!(creator.roster().active_count(), 2);
        assert_eq!(member.own_index(), 1);
        assert_eq!(member.epoch(), creator.epoch());
        // GRP-222: the two members derive one pair of credentials.
        assert_eq!(
            creator.credentials().unwrap().read_public(),
            member.credentials().unwrap().read_public()
        );
        // A member that joined holds no owner credential (`GRP-188`).
        assert!(creator.owner(0).is_some());
        assert!(member.owner(0).is_none());
        // GRP-076: the snapshot of a join carries no count of the rates.
        assert!(creator.roster().rates_are_whole());
        assert!(!member.roster().rates_are_whole());

        let mut rng = Rng(11);
        let record = creator
            .post(&text("from the creator"), now, &mut rng)
            .unwrap();
        assert_eq!(record.len(), Bucket::B0.group_record());
        let Outcome::Content { sender, app, .. } = member.receive(&record, now).unwrap() else {
            panic!("the member did not read the record");
        };
        assert_eq!(sender, 0);
        assert_eq!(
            AppMessage::parse(&app, Channel::Group).unwrap().body,
            b"from the creator"
        );

        // The sender reads no record of its own: its own tag is zero bytes.
        assert!(creator.receive(&record, now).is_err());
        // GRP-259, GRP-206: the same record again carries the mark of a
        // repeated counter, and the store drops it by its `msg_id`.
        assert!(is_repeat(&member.receive(&record, now).unwrap()));

        let back = member.post(&text("and back"), now, &mut rng).unwrap();
        let Outcome::Content { sender, app, .. } = creator.receive(&back, now).unwrap() else {
            panic!("the creator did not read the answer");
        };
        assert_eq!(sender, 1);
        assert_eq!(
            AppMessage::parse(&app, Channel::Group).unwrap().body,
            b"and back"
        );

        // A party of the same group id with another epoch secret reads
        // nothing, thus the epoch key and not the group id opens a record.
        let mut other =
            Group::create(*creator.group_id(), &Secret::new([0x99; 32]), now, &mut rng).unwrap();
        assert!(other.receive(&record, now).is_err());
    }

    #[test]
    fn a_record_outside_the_slot_window_waits_for_a_clock_check() {
        // GRP-229: a record from a clock that runs ahead waits, names the
        // clock state, and opens once the clock of the member reaches it.
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(12);
        let ahead = now + 10 * crate::group::GROUP_SLOT;
        let record = creator.post(&text("from ahead"), ahead, &mut rng).unwrap();
        assert_eq!(member.receive(&record, now).unwrap(), Outcome::ClockSuspect);
        assert!(member.holds_clock_suspect(now));
        assert!(!member.holds_openable(now));
        assert!(member.holds_openable(ahead));
        let opened = member.retry_held(ahead);
        assert!(matches!(opened[..], [Outcome::Content { sender: 0, .. }]));
        assert!(!member.holds_clock_suspect(ahead));
    }

    #[test]
    fn a_restored_group_keeps_its_place_in_the_group() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(13);
        let first = creator
            .post(&text("before the restart"), now, &mut rng)
            .unwrap();
        assert!(matches!(
            member.receive(&first, now).unwrap(),
            Outcome::Content { .. }
        ));

        // The store seals these bytes; the seed sits in the identity table.
        let creator_bytes = creator.export().unwrap();
        let member_bytes = member.export().unwrap();
        let mut creator = Group::restore(&creator_bytes, &Secret::new([0x21; 32])).unwrap();
        let mut member = Group::restore(&member_bytes, &JOINER_SEED).unwrap();
        assert_eq!(creator.own_index(), 0);
        assert_eq!(member.own_index(), 1);
        assert_eq!(member.roster().active_count(), 2);
        assert_eq!(member.epoch(), creator.epoch());
        assert_eq!(
            creator.credentials().unwrap().write_public(),
            member.credentials().unwrap().write_public()
        );
        // The owner credentials came back, and a member still holds none.
        assert!(creator.owner(1).is_some());
        assert!(member.owner(0).is_none());
        // The replicas came back with their cursors.
        assert_eq!(
            creator.replicas().unwrap().reference(1).unwrap().relay_id,
            [3; 32]
        );

        // GRP-259: the counter of each side survived, thus the record of
        // before the restart is a repeat and the next one is not.
        assert!(is_repeat(&member.receive(&first, now).unwrap()));
        let second = creator
            .post(&text("after the restart"), now, &mut rng)
            .unwrap();
        let Outcome::Content { counter, app, .. } = member.receive(&second, now).unwrap() else {
            panic!("the restored member read nothing");
        };
        assert_eq!(counter, 2);
        assert_eq!(
            AppMessage::parse(&app, Channel::Group).unwrap().body,
            b"after the restart"
        );

        // A stored object of another version is refused, and so is a
        // trailing byte.
        let mut wrong = creator_bytes.to_vec();
        wrong[0] = 0x02;
        assert!(Group::restore(&wrong, &Secret::new([0x21; 32])).is_err());
        let mut long = creator_bytes.to_vec();
        long.push(0);
        assert!(Group::restore(&long, &Secret::new([0x21; 32])).is_err());
    }

    /// The creator, the member of [`pair`], and a third member that the
    /// creator added the same way.
    fn trio(now: u64) -> (Group, Group, Group) {
        let (mut creator, mut member, _) = pair(now);
        const THIRD_SEED: Secret<32> = Secret::new([0x33; 32]);
        let keys = JoinKeys {
            seed: THIRD_SEED,
            keys: MemberKeys::from_seed(&THIRD_SEED),
        };
        let kem_pk = keys.keys.kem().public().to_bytes();
        let record = JoinRecord {
            group_id: *creator.group_id(),
            keys: keys.wire_keys(&kem_pk),
        };
        let add = creator.add_object(&record).unwrap();
        let control = GroupControl::parse(&add).unwrap();
        let add_hash = control.epoch_hash();
        assert_eq!(
            creator.apply_control(&control, 0, now).unwrap(),
            Applied::Added(2)
        );
        member.apply_control(&control, 0, now).unwrap();
        let admit_bytes = creator.admit_for(2, b"", now).unwrap();
        let admit_control = GroupControl::parse(&admit_bytes).unwrap();
        let invitation =
            umbra_wire::group::control::GroupInvitation::parse(admit_control.payload).unwrap();
        let snapshot_bytes = creator.snapshot(&[]).unwrap();
        let snapshot = RosterSnapshot::parse(&snapshot_bytes).unwrap();
        let creator_pk = creator.keys.roster().verifying_key().to_bytes();
        let admitted =
            crate::group::join::accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, now)
                .unwrap();
        let third = Group::joined(admitted, &THIRD_SEED).unwrap();
        (creator, member, third)
    }

    #[test]
    fn the_admit_hands_the_key_of_the_join_slot_and_of_no_slot_before_it() {
        // GRP-312: a joiner reads no record from before its add. The admit
        // two days into the epoch names the slot of the admit, and its key
        // is the key of that slot.
        let created = 1_700_000_000;
        let now = created + 2 * 86_400;
        let (creator, _, _) = pair_at(created, now);
        let admit_bytes = creator.admit_for(2, b"", now).unwrap();
        let control = GroupControl::parse(&admit_bytes).unwrap();
        let invitation =
            umbra_wire::group::control::GroupInvitation::parse(control.payload).unwrap();
        let umbra_wire::group::control::InvitationStage::Admit(admit) = invitation.stage else {
            panic!("the record is no admit");
        };
        assert_eq!(admit.t_join, slot_of(now));
        assert!(admit.t_e < admit.t_join);
        let current = creator.epochs.current().unwrap();
        let chain =
            current
                .secret()
                .start(creator.group_id(), current.epoch(), current.start_slot());
        assert_eq!(
            chain.slot_key(admit.t_join).unwrap().expose(),
            &admit.slot_key
        );
        assert_ne!(
            chain.slot_key(admit.t_join - 1).unwrap().expose(),
            &admit.slot_key
        );
    }

    #[test]
    fn an_admin_that_joined_inside_the_epoch_admits_a_member_that_reads() {
        // GRP-423: the member of index 1 joined inside the epoch and holds
        // no `K_e`; its admit comes from its own chain, and the third member
        // reads the records of the creator after it.
        // The member joins two days into the epoch, thus its chain starts
        // after `t_e`.
        let created = 1_700_000_000;
        let now = created + 2 * 86_400;
        let (mut creator, mut member, _) = pair_at(created, now);
        let later = now + 3 * crate::group::GROUP_SLOT;
        const THIRD_SEED: Secret<32> = Secret::new([0x34; 32]);
        let keys = JoinKeys {
            seed: THIRD_SEED,
            keys: MemberKeys::from_seed(&THIRD_SEED),
        };
        let kem_pk = keys.keys.kem().public().to_bytes();
        let record = JoinRecord {
            group_id: *creator.group_id(),
            keys: keys.wire_keys(&kem_pk),
        };
        let add = creator.add_object(&record).unwrap();
        let control = GroupControl::parse(&add).unwrap();
        let add_hash = control.epoch_hash();
        creator.apply_control(&control, 0, later).unwrap();
        member.apply_control(&control, 0, later).unwrap();
        let admit_bytes = member.admit_for(2, b"", later).unwrap();
        let invitation = umbra_wire::group::control::GroupInvitation::parse(
            GroupControl::parse(&admit_bytes).unwrap().payload,
        )
        .unwrap();
        let snapshot_bytes = creator.snapshot(&[]).unwrap();
        let snapshot = RosterSnapshot::parse(&snapshot_bytes).unwrap();
        let creator_pk = creator.keys.roster().verifying_key().to_bytes();
        let admitted =
            crate::group::join::accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, later)
                .unwrap();
        let mut third = Group::joined(admitted, &THIRD_SEED).unwrap();
        let mut rng = Rng(43);
        let post = creator
            .post(&text("after the admit"), later, &mut rng)
            .unwrap();
        let Outcome::Content { sender, .. } = third.receive(&post, later).unwrap() else {
            panic!("the third member did not read the record");
        };
        assert_eq!(sender, 0);
    }

    /// The inline epoch-key record of a rotation.
    fn inline(rotation: &Rotation) -> &[u8] {
        match &rotation.carrier {
            EpochCarrier::Inline(record) => record,
            EpochCarrier::Chunked(_) => panic!("the rotation went on the chunk path"),
        }
    }

    /// The record of a rotation, at the bucket its length names.
    fn parse_record(bytes: &[u8]) -> umbra_wire::group::record::GroupQueueRecord<'_> {
        let bucket = BUCKETS
            .into_iter()
            .find(|bucket| bucket.group_record() == bytes.len())
            .unwrap();
        umbra_wire::group::record::GroupQueueRecord::parse(bytes, bucket).unwrap()
    }

    /// Moves a roster object from its maker to each other member.
    fn spread(object: &[u8], sender: u16, others: &mut [&mut Group], now: u64) {
        let control = GroupControl::parse(object).unwrap();
        for group in others {
            group.apply_control(&control, sender, now).unwrap();
        }
    }

    #[test]
    fn a_removal_rotates_and_the_removed_member_reads_no_further_record() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(21);
        assert_eq!(creator.roster().active_count(), 3);
        // No trigger stands before the removal.
        assert!(creator.owes_rotation(now).is_none());

        let removal = creator.remove_object(1).unwrap();
        let control = GroupControl::parse(&removal).unwrap();
        assert!(matches!(
            creator.apply_control(&control, 0, now).unwrap(),
            Applied::Removed(_)
        ));
        spread(&removal, 0, &mut [&mut member, &mut third], now);
        assert_eq!(creator.roster().active_count(), 2);

        // GRP-264: the admin that removed rotates, and the member it
        // removed owes no rotation of its own (`GRP-356`).
        let trigger = creator.owes_rotation(now).unwrap();
        assert_eq!(trigger.excluded, Some(1));
        assert!(member.owes_rotation(now).is_none());
        assert!(third.owes_rotation(now).is_some());
        // GRP-422: until the next epoch, a post waits for a rotation.
        assert!(third.withholds());
        assert!(!member.withholds());
        // GRP-356: a rotation by the removed index, or one that names the
        // roster epoch before the removal, installs nowhere.
        let next_epoch = third.epoch() + 1;
        let removed_at = third.roster().epoch_index();
        assert!(third
            .check_rotator(next_epoch, removed_at, 1, false)
            .is_err());
        assert!(third
            .check_rotator(next_epoch, removed_at - 1, 0, false)
            .is_err());
        assert!(third
            .check_rotator(next_epoch, removed_at, 0, false)
            .is_ok());

        let first_epoch = creator.epoch();
        let rotation = creator.rotate(now, &mut rng).unwrap();
        assert_eq!(rotation.epoch, first_epoch + 1);
        assert_eq!(creator.epoch(), first_epoch + 1);
        assert!(creator.owes_rotation(now).is_none());
        assert!(!creator.withholds());

        let record = parse_record(inline(&rotation));
        assert_eq!(record.kind, RecordKind::EpochKey);
        assert_eq!(record.nonce, [0; 12]);
        third
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(third.epoch(), first_epoch + 1);
        // GRP-276: the removed member holds no slot in the record.
        assert!(member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .is_err());

        // The two that stayed still read each other in the new epoch.
        let next = creator
            .post(&text("after the removal"), now, &mut rng)
            .unwrap();
        let Outcome::Content { sender, app, .. } = third.receive(&next, now).unwrap() else {
            panic!("the member that stayed read nothing");
        };
        assert_eq!(sender, 0);
        assert_eq!(
            AppMessage::parse(&app, Channel::Group).unwrap().body,
            b"after the removal"
        );
        // The removed member holds the old epoch alone, thus the record
        // of the new one never opens and it waits until it expires.
        assert!(!matches!(
            member.receive(&next, now).unwrap(),
            Outcome::Content { .. }
        ));
        assert_eq!(member.receiver.held_count(), 1);
    }

    #[test]
    fn a_record_that_fills_a_hole_shows_and_a_repeat_carries_its_mark() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(41);
        let records: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                creator
                    .post(&text(&alloc::format!("m{i}")), now, &mut rng)
                    .unwrap()
            })
            .collect();
        assert!(matches!(
            member.receive(&records[0], now).unwrap(),
            Outcome::Content { .. }
        ));
        assert!(matches!(
            member.receive(&records[2], now).unwrap(),
            Outcome::Content { .. }
        ));
        // GRP-259, GRP-205: the other replica gives the record of the hole.
        assert!(matches!(
            member.receive(&records[1], now).unwrap(),
            Outcome::Content { .. }
        ));
        assert!(is_repeat(&member.receive(&records[1], now).unwrap()));
        assert!(is_repeat(&member.receive(&records[0], now).unwrap()));
    }

    #[test]
    fn a_member_rekeys_and_reads_with_the_keys_before_until_its_new_slot() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(31);
        // A record of the creator before the re-key, which the member reads
        // after it.
        let before = creator
            .post(&text("before the rekey"), now, &mut rng)
            .unwrap();

        let seed = Secret::new([0x44; 32]);
        let fresh = JoinKeys {
            seed: Secret::new(*seed.expose()),
            keys: MemberKeys::from_seed(&seed),
        };
        let object = member.rekey_object(&fresh, &mut rng).unwrap();
        // GRP-365: the record goes out under the index that stands.
        let app = AppMessage {
            kind: AppKind::GroupControl,
            msg_id: [8; 16],
            sent_at: 1_700_000_000_000,
            body: &object,
        };
        let mut bytes = alloc::vec![0u8; app.len()];
        let n = app.encode(&mut bytes).unwrap();
        bytes.truncate(n);
        let record = member.post(&bytes, now, &mut rng).unwrap();
        let Outcome::Content { sender, app, .. } = creator.receive(&record, now).unwrap() else {
            panic!("the creator read no re-key");
        };
        assert_eq!(sender, 1);
        let control =
            GroupControl::parse(AppMessage::parse(&app, Channel::Group).unwrap().body).unwrap();
        assert!(matches!(
            creator.apply_control(&control, 1, now).unwrap(),
            Applied::Rekeyed { old: 1, new: 2, .. }
        ));
        assert_eq!(member.adopt_rekey(&object, &seed, now).unwrap(), 2);
        assert!(member.has_previous());

        // The stored form keeps the index before, with the seed of its row.
        let back =
            Group::restore_with_previous(&member.export().unwrap(), &seed, Some(&JOINER_SEED))
                .unwrap();
        assert_eq!(back.own_index(), 2);
        assert!(back.has_previous());

        // GRP-372: the record from before opens with the keys before, and a
        // record after the re-key with the new ones.
        assert!(matches!(
            member.receive(&before, now).unwrap(),
            Outcome::Content { sender: 0, .. }
        ));
        let after = creator
            .post(&text("after the rekey"), now, &mut rng)
            .unwrap();
        assert!(matches!(
            member.receive(&after, now).unwrap(),
            Outcome::Content { sender: 0, .. }
        ));
        // The member posts under its new index, and the creator reads it.
        let from_new = member
            .post(&text("from the new index"), now, &mut rng)
            .unwrap();
        assert!(matches!(
            creator.receive(&from_new, now).unwrap(),
            Outcome::Content { sender: 2, .. }
        ));

        // GRP-368: the re-key excludes the index before. The rotation holds
        // a slot for the new index, and the keys before it go.
        assert_eq!(creator.owes_rotation(now).unwrap().excluded, Some(1));
        let rotation = creator.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&rotation));
        member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert!(!member.has_previous());
        assert_eq!(member.epoch(), creator.epoch());
    }

    /// A group control object as the `AppMessage` of a group post.
    fn control_app(object: &[u8], msg_id: u8) -> Vec<u8> {
        let app = AppMessage {
            kind: AppKind::GroupControl,
            msg_id: [msg_id; 16],
            sent_at: 1_700_000_000_000,
            body: object,
        };
        let mut bytes = alloc::vec![0u8; app.len()];
        let n = app.encode(&mut bytes).unwrap();
        bytes.truncate(n);
        bytes
    }

    /// Reads a record, and applies the roster object that it carries.
    fn read_control(group: &mut Group, record: &[u8], now: u64) -> Result<Applied, Error> {
        let outcome = group.receive(record, now).unwrap();
        let Outcome::Content { sender, app, .. } = outcome else {
            panic!("the record carried no content: {outcome:?}");
        };
        let control =
            GroupControl::parse(AppMessage::parse(&app, Channel::Group).unwrap().body).unwrap();
        group.apply_control(&control, sender, now)
    }

    #[test]
    fn a_rival_rekey_with_the_lower_hash_takes_the_index_and_the_loser_goes_back() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(41);
        let creator_seed = Secret::new([0x21; 32]);
        // A second reader that gets the two re-keys in the other order.
        let mut late = Group::restore(&creator.export().unwrap(), &creator_seed).unwrap();

        // The member moves to new keys, and posts the record first.
        let seed = Secret::new([0x44; 32]);
        let fresh = JoinKeys {
            seed: Secret::new(*seed.expose()),
            keys: MemberKeys::from_seed(&seed),
        };
        let object = member.rekey_object(&fresh, &mut rng).unwrap();
        let record = member
            .post(&control_app(&object, 8), now, &mut rng)
            .unwrap();
        // A removed device holds the keys of the member, and it makes a
        // rival with a lower hash, as an attacker grinds one (§11.12).
        let mut rival = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        // A linked device of the member, which reads the record on the queue
        // before the seed comes on its sync channel (DEV-300).
        let mut linked = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        member.adopt_rekey(&object, &seed, now).unwrap();
        let hash = GroupControl::parse(&object).unwrap().epoch_hash();
        let mut attempt = 0u8;
        let rival_object = loop {
            let seed = Secret::new([0x60u8.wrapping_add(attempt); 32]);
            let keys = JoinKeys {
                seed: Secret::new(*seed.expose()),
                keys: MemberKeys::from_seed(&seed),
            };
            let made = rival.rekey_object(&keys, &mut rng).unwrap();
            if GroupControl::parse(&made).unwrap().epoch_hash() < hash {
                break made;
            }
            attempt += 1;
        };
        let rival_hash = GroupControl::parse(&rival_object).unwrap().epoch_hash();
        let rival_record = rival
            .post(&control_app(&rival_object, 9), now, &mut rng)
            .unwrap();

        // GRP-369: the reader applies the first re-key, and the rival with
        // the lower hash takes its place. One member made two successors,
        // thus the fork shows and names it.
        assert!(matches!(
            read_control(&mut creator, &record, now).unwrap(),
            Applied::Rekeyed {
                old: 1,
                new: 2,
                replaced: false,
                ..
            }
        ));
        assert!(matches!(
            read_control(&mut creator, &rival_record, now).unwrap(),
            Applied::Rekeyed {
                old: 1,
                new: 2,
                replaced: true,
                ..
            }
        ));
        assert_eq!(*creator.roster().chain_hash(), rival_hash);
        assert_eq!(creator.roster().forks().len(), 1);
        assert_eq!(creator.roster().forks()[0].named, Some(1));
        assert_eq!(creator.roster().successor_of(1), Some(2));
        assert_eq!(creator.roster().active_count(), 2);
        // The same record again changes nothing.
        assert_eq!(
            read_control(&mut creator, &rival_record, now),
            Err(Error::Stale)
        );

        assert!(matches!(
            read_control(&mut linked, &record, now).unwrap(),
            Applied::Rekeyed {
                replaced: false,
                ..
            }
        ));
        assert_eq!(linked.adopt_rekey(&object, &seed, now).unwrap(), 2);
        assert!(linked.has_previous());

        // The other order gives the same chain, and the higher hash stays out.
        read_control(&mut late, &rival_record, now).unwrap();
        assert_eq!(read_control(&mut late, &record, now), Err(Error::Stale));
        assert_eq!(late.roster().chain_hash(), creator.roster().chain_hash());
        assert_eq!(late.roster().forks().len(), 1);

        // The member reads the rival with no tag for itself, and goes back
        // to the index and the keys before its re-key.
        assert_eq!(member.own_index(), 2);
        assert!(!member.lost_rekey());
        assert!(matches!(
            read_control(&mut member, &rival_record, now).unwrap(),
            Applied::Rekeyed { replaced: true, .. }
        ));
        assert_eq!(member.own_index(), 1);
        assert!(!member.has_previous());
        assert!(member.lost_rekey());
        assert!(member.own_role().is_none());
        assert_eq!(
            member.post(&text("after the loss"), now, &mut rng),
            Err(Error::NoPath)
        );

        // GRP-370: the record for the pairwise channel has zero chain fields.
        let pairwise = member.pairwise_rekey_object(&fresh, &mut rng).unwrap();
        let control = GroupControl::parse(&pairwise).unwrap();
        let parsed = umbra_wire::group::control::RekeyRecord::parse(control.payload).unwrap();
        assert!(parsed.chain_is_zero());
        assert_eq!(parsed.old_index, 1);

        // The stored form keeps the head of the chain and the loss.
        let back = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        assert!(back.lost_rekey());
        let back = Group::restore(&creator.export().unwrap(), &creator_seed).unwrap();
        assert_eq!(back.roster().head_rekey(), creator.roster().head_rekey());
        assert_eq!(back.roster().successor_of(1), Some(2));
    }

    #[test]
    fn an_owner_epoch_at_the_same_predecessor_displaces_a_member_rekey() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(71);

        // The member re-keys, and the owner adds a joiner at the same
        // predecessor before it read the re-key.
        let seed = Secret::new([0x45; 32]);
        let fresh = JoinKeys {
            seed: Secret::new(*seed.expose()),
            keys: MemberKeys::from_seed(&seed),
        };
        let rekey = member.rekey_object(&fresh, &mut rng).unwrap();
        let rekey_record = member.post(&control_app(&rekey, 8), now, &mut rng).unwrap();
        member.adopt_rekey(&rekey, &seed, now).unwrap();
        assert_eq!(member.own_index(), 2);

        let joiner = JoinKeys::make(&mut rng).unwrap();
        let kem_pk = joiner.keys.kem().public().to_bytes();
        let add = creator
            .add_object(&JoinRecord {
                group_id: *creator.group_id(),
                keys: joiner.wire_keys(&kem_pk),
            })
            .unwrap();
        let add_record = creator.post(&control_app(&add, 9), now, &mut rng).unwrap();
        creator
            .apply_control(&GroupControl::parse(&add).unwrap(), 0, now)
            .unwrap();

        // GRP-117: the owner comes first. The creator keeps its add, and the
        // member goes back to its index and its keys before the re-key.
        assert_eq!(
            read_control(&mut creator, &rekey_record, now),
            Err(Error::Stale)
        );
        assert!(creator.take_displaced().is_none());
        assert_eq!(
            read_control(&mut member, &add_record, now).unwrap(),
            Applied::Added(2)
        );
        let displaced = member.take_displaced().unwrap();
        assert_eq!(displaced.maker, 1);
        assert_eq!(member.own_index(), 1);
        assert!(!member.has_previous());
        assert!(!member.lost_rekey());
        assert!(member.own_role().is_some());
        assert_eq!(member.roster().chain_hash(), creator.roster().chain_hash());

        // GRP-119: the member re-keys again against the new head, and the
        // creator takes it.
        let again = member.rekey_object(&fresh, &mut rng).unwrap();
        let again_record = member
            .post(&control_app(&again, 10), now, &mut rng)
            .unwrap();
        member.adopt_rekey(&again, &seed, now).unwrap();
        assert!(matches!(
            read_control(&mut creator, &again_record, now).unwrap(),
            Applied::Rekeyed { old: 1, new: 3, .. }
        ));
        assert_eq!(member.roster().chain_hash(), creator.roster().chain_hash());
    }

    #[test]
    fn a_member_behind_the_roster_takes_the_snapshot_of_an_admin() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        // The member misses the add of a third member, as a restore from
        // an old backup does.
        const THIRD_SEED: Secret<32> = Secret::new([0x33; 32]);
        let keys = MemberKeys::from_seed(&THIRD_SEED);
        let kem_pk = keys.kem().public().to_bytes();
        let join = JoinKeys {
            seed: THIRD_SEED,
            keys,
        };
        let record = JoinRecord {
            group_id: *creator.group_id(),
            keys: join.wire_keys(&kem_pk),
        };
        let add = creator.add_object(&record).unwrap();
        creator
            .apply_control(&GroupControl::parse(&add).unwrap(), 0, now)
            .unwrap();
        assert_eq!(member.roster().active_count(), 2);

        // GRP-330: the admin writes a snapshot at its epoch, and GRP-329:
        // the member takes the members that it lacked.
        let snapshot = creator.snapshot(&[]).unwrap();
        member.recover_roster(&snapshot, now).unwrap();
        assert_eq!(member.roster().active_count(), 3);
        assert_eq!(
            member.roster().epoch_index(),
            creator.roster().epoch_index()
        );
        assert!(member.roster().member(2).unwrap().kem_pk.is_some());
        // A snapshot at the epoch it holds already changes nothing.
        assert!(member.recover_roster(&snapshot, now).is_err());
    }

    #[test]
    fn a_plain_member_rotates_and_its_record_carries_no_owner_credential() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(23);
        // The member that leaves is the trigger, and the plain member
        // that stays answers it (`GRP-355`).
        let leave = third.leave_object().unwrap();
        let control = GroupControl::parse(&leave).unwrap();
        third.apply_control(&control, 2, now).unwrap();
        spread(&leave, 2, &mut [&mut creator, &mut member], now);
        assert_eq!(creator.roster().active_count(), 2);

        assert!(member.owner(0).is_none());
        let rotation = member.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&rotation));
        // GRP-388: the creator is an owner, thus the admin layout is the
        // first one read, and the plain layout is the one that opens.
        creator
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(creator.epoch(), member.epoch());
        // GRP-379: the rotation of a plain member hands no owner
        // credential, and the owner keeps the one it already holds.
        assert!(creator.owner(0).is_some());

        let next = member
            .post(&text("from the plain member"), now, &mut rng)
            .unwrap();
        let Outcome::Content { app, .. } = creator.receive(&next, now).unwrap() else {
            panic!("the owner read nothing");
        };
        assert_eq!(
            AppMessage::parse(&app, Channel::Group).unwrap().body,
            b"from the plain member"
        );
    }

    #[test]
    fn a_rotation_needs_a_trigger_and_the_age_is_one() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(27);
        // The member joined inside the epoch and holds no `K_e`, thus it
        // takes the first epoch after its add. From there on it counts the
        // triggers of its own roster.
        let first = creator.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&first));
        member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        // GRP-357: no trigger stands, thus the record is refused.
        let rotation = creator.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&rotation));
        assert_eq!(
            member.install_epoch_key(record.epoch, record.slot, record.body, now),
            Err(Error::Unverified)
        );
        // GRP-360: the age of the epoch is a trigger of its own.
        let aged = now + crate::group::GROUP_EPOCH_MAX_AGE;
        assert!(member.owes_rotation(aged).is_some());
        member
            .install_epoch_key(record.epoch, record.slot, record.body, aged)
            .unwrap();
        assert_eq!(member.epoch(), rotation.epoch);
        // GRP-288: the epoch before the current one does not install.
        assert_eq!(
            member.install_epoch_key(1, record.slot, record.body, aged),
            Err(Error::Stale)
        );
        // The backoff of a role holder is shorter than that of a member.
        assert!(creator.rotation_delay(&mut Rng(3)) <= member.rotation_delay(&mut Rng(3)));
    }

    #[test]
    fn a_late_joiner_takes_the_rotation_of_the_aged_epoch() {
        // GRP-224, GRP-360: the member joins 20 days into the epoch; the
        // age runs from `t_e`, thus the rotation at 30 days installs.
        let created = 1_700_000_000;
        let joined = created + 20 * 86_400;
        let (mut creator, mut member, _) = pair_at(created, joined);
        let aged = created + crate::group::GROUP_EPOCH_MAX_AGE;
        assert!(member.owes_rotation(aged).is_some());
        let rotation = creator.rotate(aged, &mut Rng(29)).unwrap();
        let record = parse_record(inline(&rotation));
        member
            .install_epoch_key(record.epoch, record.slot, record.body, aged)
            .unwrap();
        assert_eq!(member.epoch(), rotation.epoch);
    }

    #[test]
    fn a_joiner_takes_the_rotation_of_a_trigger_before_its_add() {
        // GRP-357, GRP-288: a member leaves, and the creator adds and
        // admits a joiner before a rotation answers the leave. The roster
        // of the joiner starts at its add, thus it holds no trigger.
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let leave = member.leave_object().unwrap();
        let control = GroupControl::parse(&leave).unwrap();
        member.apply_control(&control, 1, now).unwrap();
        spread(&leave, 1, &mut [&mut creator], now);
        assert!(creator.owes_rotation(now).is_some());

        const LATE_SEED: Secret<32> = Secret::new([0x35; 32]);
        let keys = JoinKeys {
            seed: LATE_SEED,
            keys: MemberKeys::from_seed(&LATE_SEED),
        };
        let kem_pk = keys.keys.kem().public().to_bytes();
        let record = JoinRecord {
            group_id: *creator.group_id(),
            keys: keys.wire_keys(&kem_pk),
        };
        let add = creator.add_object(&record).unwrap();
        let control = GroupControl::parse(&add).unwrap();
        let add_hash = control.epoch_hash();
        assert_eq!(
            creator.apply_control(&control, 0, now).unwrap(),
            Applied::Added(2)
        );
        let admit_bytes = creator.admit_for(2, b"", now).unwrap();
        let invitation = umbra_wire::group::control::GroupInvitation::parse(
            GroupControl::parse(&admit_bytes).unwrap().payload,
        )
        .unwrap();
        let snapshot_bytes = creator.snapshot(&[]).unwrap();
        let snapshot = RosterSnapshot::parse(&snapshot_bytes).unwrap();
        let creator_pk = creator.keys.roster().verifying_key().to_bytes();
        let admitted =
            crate::group::join::accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, now)
                .unwrap();
        let mut joiner = Group::joined(admitted, &LATE_SEED).unwrap();
        assert!(joiner.owes_rotation(now).is_none());
        assert!(!joiner.rotation_called(now));

        // The rotation of the leave follows the admit, and the joiner
        // installs it and reads under it.
        let mut rng = Rng(31);
        let first_epoch = joiner.epoch();
        let rotation = creator.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&rotation));
        // A record that names a roster epoch before the add installs
        // nothing, and the member that left holds no slot.
        let add_epoch = joiner.roster().admission_epoch();
        assert!(!joiner.first_since_admission(add_epoch - 1));
        assert!(member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .is_err());
        joiner
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(joiner.epoch(), first_epoch + 1);
        let post = creator
            .post(&text("after the rotation"), now, &mut rng)
            .unwrap();
        let Outcome::Content { sender, app, .. } = joiner.receive(&post, now).unwrap() else {
            panic!("the joiner read nothing");
        };
        assert_eq!(sender, 0);
        assert_eq!(
            AppMessage::parse(&app, Channel::Group).unwrap().body,
            b"after the rotation"
        );
        // The epoch that it installed holds `K_e`, thus the next one needs
        // a trigger that its own roster holds.
        let again = creator.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&again));
        assert_eq!(
            joiner.install_epoch_key(record.epoch, record.slot, record.body, now),
            Err(Error::Unverified)
        );
    }

    #[test]
    fn a_presence_record_reaches_the_admins_alone_and_leaves_no_gap() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(31);
        let presence = member.presence(now, &mut rng).unwrap();
        // GRP-216: one sparse record in `B0`.
        assert_eq!(presence.len(), Bucket::B0.group_record());
        // GRP-217: the owner finds its tag and reads a presence signal.
        assert_eq!(
            creator.receive(&presence, now).unwrap(),
            Outcome::Presence { sender: 1 }
        );
        // GRP-322: a plain member finds no entry and discards the record.
        assert!(third.receive(&presence, now).is_err());

        // GRP-395: the presence took no step of the counter, thus the next
        // record of the member is its first, and no reader sees a gap.
        let text_record = member
            .post(&text("after a quiet week"), now, &mut rng)
            .unwrap();
        for reader in [&mut creator, &mut third] {
            let Outcome::Content { counter, .. } = reader.receive(&text_record, now).unwrap()
            else {
                panic!("the record did not open");
            };
            assert_eq!(counter, 1);
            assert!(!reader.needs_other_replica(now + crate::group::GROUP_GAP_TIMEOUT));
        }
        // A second presence at the same counter is no duplicate at the admin.
        let again = member.presence(now, &mut rng).unwrap();
        assert_eq!(
            creator.receive(&again, now).unwrap(),
            Outcome::Presence { sender: 1 }
        );
        assert_eq!(creator.own_role(), Some(Role::Owner));
        assert_eq!(third.own_role(), Some(Role::Member));
    }

    #[test]
    fn an_admin_grants_a_role_that_every_member_verifies() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(37);
        // A member below `admin` grants nothing (`GRP-063`).
        assert_eq!(
            member.grant(2, Role::Moderator, &mut rng),
            Err(Error::Unverified)
        );
        let grant = creator.grant(2, Role::Moderator, &mut rng).unwrap();
        let control = GroupControl::parse(&grant).unwrap();
        for group in [&mut creator, &mut member, &mut third] {
            assert_eq!(
                group.apply_control(&control, 0, now).unwrap(),
                Applied::Granted {
                    index: 2,
                    role: Role::Moderator
                }
            );
        }
        assert_eq!(third.own_role(), Some(Role::Moderator));
        // A demotion goes the same way, and each roster agrees.
        let demote = creator.grant(2, Role::Member, &mut rng).unwrap();
        let control = GroupControl::parse(&demote).unwrap();
        for group in [&mut creator, &mut member, &mut third] {
            group.apply_control(&control, 0, now).unwrap();
        }
        assert_eq!(member.roster().member(2).unwrap().role, Role::Member);
        assert_eq!(creator.roster().chain_hash(), third.roster().chain_hash());
    }

    #[test]
    fn a_new_admin_takes_the_owner_credentials_and_no_epoch_secret() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(41);
        let grant = creator.grant(2, Role::Admin, &mut rng).unwrap();
        let control = GroupControl::parse(&grant).unwrap();
        for group in [&mut creator, &mut member, &mut third] {
            group.apply_control(&control, 0, now).unwrap();
        }
        assert!(third.owner(0).is_none());
        let before = third.credentials().unwrap().read_public();

        // GRP-400: the slot carries no epoch secret, thus a member that
        // joined inside the epoch learns nothing of the records before it.
        let delivery = creator.owner_delivery(2, &mut rng).unwrap();
        let record = parse_record(&delivery);
        assert_eq!(record.epoch, creator.epoch());
        third
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(
            third.owner(1).unwrap().expose(),
            creator.owner(1).unwrap().expose()
        );
        assert_eq!(third.epoch(), creator.epoch());
        assert_eq!(third.credentials().unwrap().read_public(), before);
        // A member that the record does not serve finds no slot in it.
        assert!(member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .is_err());
        // A member below `admin` hands out nothing.
        assert!(member.owner_delivery(2, &mut rng).is_err());

        // WIR-522: new owner credentials reach the admin the same way, and
        // the replaced ones authorize the `GKEY` that moves the relay.
        let old = creator.replace_owners(&mut rng).unwrap();
        assert_ne!(old[0].expose(), creator.owner(0).unwrap().expose());
        let again = creator.owner_delivery(2, &mut rng).unwrap();
        let record = parse_record(&again);
        third
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(
            third.owner(0).unwrap().expose(),
            creator.owner(0).unwrap().expose()
        );
    }

    #[test]
    fn a_joiner_verifies_a_role_whose_granter_lost_its_own() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(43);
        let apply = |bytes: &[u8], sender: u16, groups: [&mut Group; 3]| {
            let control = GroupControl::parse(bytes).unwrap();
            for group in groups {
                group.apply_control(&control, sender, now).unwrap();
            }
        };
        let to_admin = creator.grant(1, Role::Admin, &mut rng).unwrap();
        apply(&to_admin, 0, [&mut creator, &mut member, &mut third]);
        let to_moderator = member.grant(2, Role::Moderator, &mut rng).unwrap();
        apply(&to_moderator, 1, [&mut creator, &mut member, &mut third]);
        let demotion = creator.grant(1, Role::Member, &mut rng).unwrap();
        apply(&demotion, 0, [&mut creator, &mut member, &mut third]);

        // GRP-068, GRP-069: the path holds the grant of the moderator and
        // the grant that made its granter an admin, and not the demotion.
        let kept: Vec<&[u8]> = alloc::vec![&to_admin, &to_moderator, &demotion];
        let (path, positions) = creator.roster().authority_path(&kept).unwrap();
        assert_eq!(positions, alloc::vec![0, 1]);

        // A fourth member joins with that path and verifies it in chain
        // order, though its granter holds no role now.
        const FOURTH_SEED: Secret<32> = Secret::new([0x44; 32]);
        let keys = JoinKeys {
            seed: FOURTH_SEED,
            keys: MemberKeys::from_seed(&FOURTH_SEED),
        };
        let kem_pk = keys.keys.kem().public().to_bytes();
        let add = creator
            .add_object(&JoinRecord {
                group_id: *creator.group_id(),
                keys: keys.wire_keys(&kem_pk),
            })
            .unwrap();
        let control = GroupControl::parse(&add).unwrap();
        let add_hash = control.epoch_hash();
        creator.apply_control(&control, 0, now).unwrap();
        let admit = creator.admit_for(3, b"", now).unwrap();
        let invitation = umbra_wire::group::control::GroupInvitation::parse(
            GroupControl::parse(&admit).unwrap().payload,
        )
        .unwrap();
        let creator_pk = creator.keys.roster().verifying_key().to_bytes();
        let snapshot_bytes = creator.snapshot(&path).unwrap();
        let snapshot = RosterSnapshot::parse(&snapshot_bytes).unwrap();
        let admitted =
            crate::group::join::accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, now)
                .unwrap();
        assert_eq!(admitted.roster.member(2).unwrap().role, Role::Moderator);

        // GRP-399: with no path, the role of the moderator stands on
        // nothing, and the snapshot fails.
        let bare = creator.snapshot(&[]).unwrap();
        let bare = RosterSnapshot::parse(&bare).unwrap();
        assert!(
            crate::group::join::accept_admit(&invitation, &bare, &add_hash, &creator_pk, now)
                .is_err()
        );
    }

    #[test]
    fn a_member_that_missed_an_epoch_asks_and_one_that_joined_inside_it_gets_nothing() {
        let now = 1_700_000_000;
        let (mut creator, mut member, third) = trio(now);
        let mut rng = Rng(47);
        // The third member leaves, and the creator rotates. The member
        // reads the removal, and the epoch-key record never reaches it.
        let leave = third.leave_object().unwrap();
        let control = GroupControl::parse(&leave).unwrap();
        for group in [&mut creator, &mut member] {
            group.apply_control(&control, 2, now).unwrap();
        }
        creator.rotate(now, &mut rng).unwrap();
        let later = creator
            .post(&text("under the epoch it lacks"), now, &mut rng)
            .unwrap();
        assert!(!matches!(
            member.receive(&later, now).unwrap(),
            Outcome::Content { .. }
        ));
        // GRP-289: the held record names the epoch it lacks.
        assert_eq!(member.lacks_epoch(), Some(creator.epoch()));

        // GRP-375: the creator holds `K_e` and supplies it, and the record
        // that waited opens after the install.
        assert!(creator.may_supply(1, creator.epoch()));
        let supply = creator.key_supply(1, &mut rng).unwrap();
        let record = parse_record(&supply);
        assert_eq!(creator.slot_indices(record.body), alloc::vec![1]);
        member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(member.epoch(), creator.epoch());
        assert_eq!(member.lacks_epoch(), None);
        let opened = member.retry_held(now);
        assert!(matches!(opened.first(), Some(Outcome::Content { .. })));

        // GRP-404: a member that joined inside the epoch holds no claim to
        // `K_e`, and a member that holds none supplies nothing.
        const FIFTH_SEED: Secret<32> = Secret::new([0x55; 32]);
        let keys = JoinKeys {
            seed: FIFTH_SEED,
            keys: MemberKeys::from_seed(&FIFTH_SEED),
        };
        let kem_pk = keys.keys.kem().public().to_bytes();
        let add = creator
            .add_object(&JoinRecord {
                group_id: *creator.group_id(),
                keys: keys.wire_keys(&kem_pk),
            })
            .unwrap();
        let control = GroupControl::parse(&add).unwrap();
        let Applied::Added(index) = creator.apply_control(&control, 0, now).unwrap() else {
            panic!("the add added nobody");
        };
        assert!(!creator.may_supply(index, creator.epoch()));
        assert!(creator.key_supply(index, &mut rng).is_err());
        assert!(!creator.may_supply(1, creator.epoch() + 1));
    }

    #[test]
    fn a_rotation_above_the_inline_carrier_goes_on_the_chunk_path() {
        let now = 1_700_000_000;
        let mut rng = Rng(53);
        let mut creator =
            Group::create([0x66; 32], &Secret::new([0x21; 32]), now, &mut rng).unwrap();
        creator.set_replicas([
            ReplicaRef {
                relay_id: [1; 32],
                group_queue_id: [2; 32],
                seq_of_add: 0,
            },
            ReplicaRef {
                relay_id: [3; 32],
                group_queue_id: [4; 32],
                seq_of_add: 0,
            },
        ]);
        // 29 members join, thus the group holds 30, above the 27 slots of
        // the inline carrier.
        let mut last = None;
        for seed in 1..=29u8 {
            let join_seed = Secret::new([seed; 32]);
            let keys = JoinKeys {
                seed: Secret::new([seed; 32]),
                keys: MemberKeys::from_seed(&join_seed),
            };
            let kem_pk = keys.keys.kem().public().to_bytes();
            let add = creator
                .add_object(&JoinRecord {
                    group_id: *creator.group_id(),
                    keys: keys.wire_keys(&kem_pk),
                })
                .unwrap();
            let control = GroupControl::parse(&add).unwrap();
            let add_hash = control.epoch_hash();
            let Applied::Added(index) = creator.apply_control(&control, 0, now).unwrap() else {
                panic!("the add added nobody");
            };
            last = Some((index, add_hash, keys));
        }
        let (index, add_hash, keys) = last.unwrap();
        let admit = creator.admit_for(index, b"", now).unwrap();
        let invitation = umbra_wire::group::control::GroupInvitation::parse(
            GroupControl::parse(&admit).unwrap().payload,
        )
        .unwrap();
        let snapshot_bytes = creator.snapshot(&[]).unwrap();
        let snapshot = RosterSnapshot::parse(&snapshot_bytes).unwrap();
        let creator_pk = creator.keys.roster().verifying_key().to_bytes();
        let admitted =
            crate::group::join::accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, now)
                .unwrap();
        let mut member = Group::joined(admitted, &keys.seed).unwrap();

        // A removal leaves 29 members, and the rotation goes on the chunk
        // path (`GRP-280`).
        let removal = creator.remove_object(5).unwrap();
        let control = GroupControl::parse(&removal).unwrap();
        creator.apply_control(&control, 0, now).unwrap();
        member.apply_control(&control, 0, now).unwrap();
        let rotation = creator.rotate(now, &mut rng).unwrap();
        let EpochCarrier::Chunked(chunked) = &rotation.carrier else {
            panic!("29 slots went inline");
        };
        assert_eq!(chunked.slot_count, 29);
        assert_eq!(chunked.slots_per_chunk, 27);
        assert_eq!(chunked.object.len(), 2 * crate::attach::SEGMENT_SIZE);

        // GRP-283: the record names the object by its descriptor, and the
        // member finds the one chunk that holds its slot (`GRP-284`).
        let bytes = creator
            .chunked_record(rotation.epoch, chunked, b"a descriptor")
            .unwrap();
        let record = parse_record(&bytes);
        let wanted = member
            .wanted_chunk(record.epoch, record.slot, record.body, now)
            .unwrap()
            .unwrap();
        assert_eq!(wanted.descriptor, b"a descriptor");
        // The member holds the last index, rank 28, thus block 1.
        assert_eq!(wanted.chunk, 1);
        let segment = crate::attach::SEGMENT_SIZE;
        // Block 0 holds the slots of rank 0 to 26 and none of this member.
        assert!(member
            .install_chunk(&wanted, &chunked.object[..segment], now)
            .is_err());
        assert_eq!(member.epoch(), 1);
        let block = &chunked.object[segment..2 * segment];
        member.install_chunk(&wanted, block, now).unwrap();
        assert_eq!(member.epoch(), creator.epoch());
        let next = creator
            .post(&text("to twenty-nine"), now, &mut rng)
            .unwrap();
        assert!(matches!(
            member.receive(&next, now).unwrap(),
            Outcome::Content { .. }
        ));
    }

    /// The seed of the third member of [`trio`].
    const THIRD: Secret<32> = Secret::new([0x33; 32]);

    /// A joiner record of the keys of `seed`.
    fn join_of(group: &Group, seed: u8) -> (JoinKeys, [u8; 1_216]) {
        let seed = Secret::new([seed; 32]);
        let keys = JoinKeys {
            seed: Secret::new(*seed.expose()),
            keys: MemberKeys::from_seed(&seed),
        };
        let kem_pk = keys.keys.kem().public().to_bytes();
        let _ = group;
        (keys, kem_pk)
    }

    /// Adds a member of the keys of `seed` at each of `groups`, from the
    /// creator at index 0, and gives its index.
    fn add_member(creator: &mut Group, others: &mut [&mut Group], seed: u8, now: u64) -> u16 {
        let (keys, kem_pk) = join_of(creator, seed);
        let add = creator
            .add_object(&JoinRecord {
                group_id: *creator.group_id(),
                keys: keys.wire_keys(&kem_pk),
            })
            .unwrap();
        let control = GroupControl::parse(&add).unwrap();
        let Applied::Added(index) = creator.apply_control(&control, 0, now).unwrap() else {
            panic!("the add added nobody");
        };
        spread(&add, 0, others, now);
        index
    }

    #[test]
    fn an_epoch_that_starts_outside_the_bound_of_the_clock_waits_or_is_refused() {
        let now = 1_700_000_000;
        let slot = crate::group::GROUP_SLOT;
        let (mut creator, mut member, third) = trio(now);
        let mut rng = Rng(61);
        let leave = third.leave_object().unwrap();
        spread(&leave, 2, &mut [&mut creator, &mut member], now);

        // GRP-383: a rotator whose clock runs ten slots ahead. Each sender
        // of that epoch would wait ten hours for its first slot. Thus the
        // epoch waits, and the member writes under the epoch that it holds.
        let ahead = now + 10 * slot;
        let rotation = creator.rotate(ahead, &mut rng).unwrap();
        let record = parse_record(inline(&rotation));
        assert_eq!(record.slot, slot_of(ahead));
        assert_eq!(
            member.install_epoch_key(record.epoch, record.slot, record.body, now),
            Err(Error::NoPath)
        );
        assert_eq!(member.epoch(), 1);
        assert!(member.post(&text("still here"), now, &mut rng).is_ok());
        assert!(member.retry_held(now).is_empty());
        // The sweep of the client tries the slot again when the clock
        // reached its bound, and not before.
        assert!(!member.holds_openable(now));
        assert!(member.holds_openable(ahead - 2 * slot));
        // The stored form keeps the slot that waits. The clock reaches the
        // bound of `GROUP_SLOT_SKEW`, and the epoch installs.
        let mut member = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        let near = ahead - 2 * slot;
        assert!(matches!(
            member.retry_held(near)[..],
            [Outcome::EpochInstalled { epoch: 2 }]
        ));
        assert_eq!(member.epoch(), 2);
        // GRP-246: the clock lies below `t_e`, and the record takes `t_e`.
        let post = member.post(&text("in the skew"), near, &mut rng).unwrap();
        assert_eq!(parse_record(&post).slot, slot_of(ahead));
        assert!(matches!(
            creator.receive(&post, ahead).unwrap(),
            Outcome::Content { sender: 1, .. }
        ));

        // An epoch that starts more than `GROUP_EPOCH_MAX_AGE` below the
        // clock is past that age at once. The member refuses it and keeps
        // nothing.
        let (mut creator, mut member, third) = trio(now);
        let leave = third.leave_object().unwrap();
        spread(&leave, 2, &mut [&mut creator, &mut member], now);
        let rotation = creator.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&rotation));
        let late = now + crate::group::GROUP_EPOCH_MAX_AGE + 2 * slot;
        assert_eq!(
            member.install_epoch_key(record.epoch, record.slot, record.body, late),
            Err(Error::Stale)
        );
        assert!(member.retry_held(late).is_empty());
        assert_eq!(member.epoch(), 1);
    }

    #[test]
    fn a_member_whose_chain_never_held_a_displaced_trigger_takes_the_epoch_after_it() {
        // The owner at index 0, an admin at index 1, a reader at index 2,
        // and a member at index 3 that the admin removes.
        let now = 1_700_000_000;
        let (mut owner, mut admin, mut reader) = trio(now);
        let mut rng = Rng(63);
        // The two members joined inside epoch 1 and hold no `K_e`, and such
        // a member takes the first epoch after its add. Epoch 2 reaches
        // each of them first, thus each one counts the triggers of its own
        // roster from here on.
        let settled = owner.rotate(now, &mut rng).unwrap();
        let settled = parse_record(inline(&settled));
        for group in [&mut admin, &mut reader] {
            group
                .install_epoch_key(settled.epoch, settled.slot, settled.body, now)
                .unwrap();
        }
        let grant = owner.grant(1, Role::Admin, &mut rng).unwrap();
        owner
            .apply_control(&GroupControl::parse(&grant).unwrap(), 0, now)
            .unwrap();
        spread(&grant, 0, &mut [&mut admin, &mut reader], now);
        assert_eq!(
            add_member(&mut owner, &mut [&mut admin, &mut reader], 0x41, now),
            3
        );
        let base = reader.roster().epoch_index();

        // GRP-264: the admin removes index 3 and rotates at once. The owner
        // adds a joiner at the same predecessor before it reads either.
        let removal = admin.remove_object(3).unwrap();
        admin
            .apply_control(&GroupControl::parse(&removal).unwrap(), 1, now)
            .unwrap();
        let first = admin.rotate(now, &mut rng).unwrap();
        let first = parse_record(inline(&first));
        let (joiner, kem_pk) = join_of(&owner, 0x42);
        let add = owner
            .add_object(&JoinRecord {
                group_id: *owner.group_id(),
                keys: joiner.wire_keys(&kem_pk),
            })
            .unwrap();
        let add_control = GroupControl::parse(&add).unwrap();
        owner.apply_control(&add_control, 0, now).unwrap();

        // GRP-117: the add of the owner comes first. The reader takes it,
        // and the removal is stale there. The epoch of the admin answers a
        // trigger that the chain of the reader never held.
        reader.apply_control(&add_control, 0, now).unwrap();
        let removal_control = GroupControl::parse(&removal).unwrap();
        assert_eq!(
            reader.apply_control(&removal_control, 1, now),
            Err(Error::Stale)
        );
        assert_eq!(
            reader.install_epoch_key(first.epoch, first.slot, first.body, now),
            Err(Error::Unverified)
        );
        assert_eq!(reader.epoch(), 2);

        // The admin reads the add, its removal goes, and it publishes the
        // removal again on the new head and rotates again (GRP-119).
        admin.apply_control(&add_control, 0, now).unwrap();
        assert_eq!(admin.take_displaced().unwrap().maker, 1);
        assert_eq!(admin.epoch(), 3);
        let again = admin.remove_object(3).unwrap();
        admin
            .apply_control(&GroupControl::parse(&again).unwrap(), 1, now)
            .unwrap();
        assert_eq!(admin.owes_rotation(now).unwrap().excluded, Some(3));
        // A record of the admin under the epoch that the reader lacks.
        let between = admin
            .post(&text("between the two epochs"), now, &mut rng)
            .unwrap();
        let supply = admin.key_supply(2, &mut rng).unwrap();
        let second = admin.rotate(now, &mut rng).unwrap();
        let second = parse_record(inline(&second));
        assert_eq!(second.epoch, 4);

        // The owner reads the second epoch before the removal that it
        // answers: the slot opens and waits, and the removal installs it.
        assert_eq!(
            owner.apply_control(&removal_control, 1, now),
            Err(Error::Stale)
        );
        assert_eq!(
            owner.install_epoch_key(second.epoch, second.slot, second.body, now),
            Err(Error::NoPath)
        );
        assert_eq!(owner.epoch(), 2);
        owner
            .apply_control(&GroupControl::parse(&again).unwrap(), 1, now)
            .unwrap();
        assert!(matches!(
            owner.retry_held(now)[..],
            [Outcome::EpochInstalled { epoch: 4 }]
        ));

        // The reader takes the removal. The first epoch still names a
        // roster epoch below the trigger, thus it stays out (GRP-356).
        reader
            .apply_control(&GroupControl::parse(&again).unwrap(), 1, now)
            .unwrap();
        assert_eq!(reader.roster().epoch_index(), base + 2);
        assert!(reader.retry_held(now).is_empty());
        assert_eq!(reader.epoch(), 2);
        // The member that the removal took out rotates nothing, under any
        // number of an epoch.
        assert!(reader.check_rotator(3, base + 2, 3, false).is_err());
        assert!(reader.check_rotator(9, base + 2, 3, false).is_err());
        assert!(reader.check_rotator(9, base + 2, 1, false).is_ok());
        // GRP-375: a key supply of that epoch names the roster epoch of its
        // rotation. With no record of the epoch here it waits; the record
        // that the reader holds for that epoch lets it install, and the
        // record opens.
        let supply = parse_record(&supply);
        assert_eq!(
            reader.install_epoch_key(supply.epoch, supply.slot, supply.body, now),
            Err(Error::Unverified)
        );
        assert_eq!(
            reader.receive(&between, now).unwrap(),
            Outcome::ClockSuspect
        );
        assert_eq!(reader.lacks_epoch(), Some(3));
        let released = reader.retry_held(now);
        assert!(matches!(
            released[..],
            [
                Outcome::EpochInstalled { epoch: 3 },
                Outcome::Content { sender: 1, .. }
            ]
        ));
        // The key of that epoch reaches the member that the removal took
        // out, thus the reader owes a rotation and withholds (GRP-422).
        assert!(reader.withholds());
        reader
            .install_epoch_key(second.epoch, second.slot, second.body, now)
            .unwrap();
        assert!(!reader.withholds());

        // A reader that never took the first epoch takes the second one
        // from epoch 2 (GRP-288), and each member holds one key.
        let mut direct =
            Group::restore(&owner.export().unwrap(), &Secret::new([0x21; 32])).unwrap();
        assert_eq!(direct.epoch(), 4);
        for group in [&mut owner, &mut reader, &mut direct] {
            assert_eq!(group.epoch(), admin.epoch());
            assert_eq!(
                group.credentials().unwrap().read_public(),
                admin.credentials().unwrap().read_public()
            );
        }
        let post = admin.post(&text("after the race"), now, &mut rng).unwrap();
        for group in [&mut owner, &mut reader] {
            assert!(matches!(
                group.receive(&post, now).unwrap(),
                Outcome::Content { sender: 1, .. }
            ));
        }
    }

    #[test]
    fn a_rival_that_replaces_the_rekey_after_its_rotation_is_a_trigger_in_each_order() {
        let now = 1_700_000_000;
        let (mut creator, member, mut third) = trio(now);
        let mut rng = Rng(67);
        // A third reader that takes the records in another order.
        let late = Group::restore(&third.export().unwrap(), &THIRD).unwrap();
        // Two holders of the keys of index 1 each re-key at one
        // predecessor. The record with the higher hash arrives first.
        let rival = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        let (one, _) = join_of(&member, 0x51);
        let (two, _) = join_of(&member, 0x52);
        let one = member.rekey_object(&one, &mut rng).unwrap();
        let two = rival.rekey_object(&two, &mut rng).unwrap();
        let hash = |object: &[u8]| GroupControl::parse(object).unwrap().epoch_hash();
        let (high, low) = if hash(&one) > hash(&two) {
            (one, two)
        } else {
            (two, one)
        };
        let (high, low) = (
            GroupControl::parse(&high).unwrap(),
            GroupControl::parse(&low).unwrap(),
        );

        // The creator takes the first re-key and rotates. The slot of the
        // new index goes to the keys of that re-key.
        creator.apply_control(&high, 1, now).unwrap();
        let first = creator.rotate(now, &mut rng).unwrap();
        let first = parse_record(inline(&first));
        assert!(creator.owes_rotation(now).is_none());
        assert!(creator.may_supply(3, creator.epoch()));
        // GRP-369: the rival takes the place of the re-key. The epoch of
        // the creator is one of that roster epoch, thus the keys that lost
        // hold it. The rival is a trigger, and no supply goes to the index.
        assert!(matches!(
            creator.apply_control(&low, 1, now).unwrap(),
            Applied::Rekeyed { replaced: true, .. }
        ));
        assert_eq!(creator.owes_rotation(now).unwrap().excluded, None);
        assert!(creator.withholds());
        assert!(!creator.may_supply(3, creator.epoch()));
        let second = creator.rotate(now, &mut rng).unwrap();
        let second = parse_record(inline(&second));
        assert!(creator.owes_rotation(now).is_none());
        assert!(!creator.withholds());
        // A rotation that no trigger calls for.
        let surplus = Group::restore(&creator.export().unwrap(), &Secret::new([0x21; 32]))
            .unwrap()
            .rotate(now, &mut rng)
            .unwrap();
        let surplus = parse_record(inline(&surplus));

        // A member that took the rival before the first epoch cannot know
        // which keys that epoch served. It owes no rotation, it takes the
        // second epoch, and it takes no third one.
        third.apply_control(&high, 1, now).unwrap();
        third.apply_control(&low, 1, now).unwrap();
        third
            .install_epoch_key(first.epoch, first.slot, first.body, now)
            .unwrap();
        assert!(third.owes_rotation(now).is_none());
        assert!(!third.may_supply(3, third.epoch()));
        third
            .install_epoch_key(second.epoch, second.slot, second.body, now)
            .unwrap();
        assert_eq!(
            third.install_epoch_key(surplus.epoch, surplus.slot, surplus.body, now),
            Err(Error::Unverified)
        );

        // A member that reads the record that stands first verifies the
        // rival as a record that lost. The mark of the rival is a fact of
        // the two records, thus this member takes the second epoch too.
        let mut winner = Group::restore(&late.export().unwrap(), &THIRD).unwrap();
        winner.apply_control(&low, 1, now).unwrap();
        winner
            .install_epoch_key(first.epoch, first.slot, first.body, now)
            .unwrap();
        assert!(winner.may_supply(3, winner.epoch()));
        assert_eq!(winner.apply_control(&high, 1, now), Err(Error::Stale));
        assert!(!winner.may_supply(3, winner.epoch()));
        assert!(winner.owes_rotation(now).is_none());
        winner
            .install_epoch_key(second.epoch, second.slot, second.body, now)
            .unwrap();
        assert_eq!(
            winner.install_epoch_key(surplus.epoch, surplus.slot, surplus.body, now),
            Err(Error::Unverified)
        );

        // Each order of the two re-keys and the two epochs ends in one
        // state. That state is the second epoch, the head of the record
        // that stands, and one base. The member owes no rotation, and no
        // room stays for a third epoch.
        let start = late.export().unwrap();
        let mut places = Vec::new();
        let items = [0usize, 1, 2, 3];
        let mut orders = Vec::new();
        for a in items {
            for b in items {
                for c in items {
                    for d in items {
                        let order = [a, b, c, d];
                        if items.iter().all(|item| order.contains(item)) {
                            orders.push(order);
                        }
                    }
                }
            }
        }
        assert_eq!(orders.len(), 24);
        for order in orders {
            let mut group = Group::restore(&start, &THIRD).unwrap();
            for item in order {
                let _ = match item {
                    0 => group.apply_control(&high, 1, now).map(|_| ()),
                    1 => group.apply_control(&low, 1, now).map(|_| ()),
                    2 => group.install_epoch_key(first.epoch, first.slot, first.body, now),
                    _ => group.install_epoch_key(second.epoch, second.slot, second.body, now),
                };
                group.retry_held(now);
            }
            // Each replica gives each record. A record that came before
            // the roster object that names its members opens at its second
            // copy.
            for record in [&first, &second] {
                let _ = group.install_epoch_key(record.epoch, record.slot, record.body, now);
                group.retry_held(now);
            }
            assert_eq!(group.epoch(), 3, "{order:?}");
            assert_eq!(
                group.credentials().unwrap().read_public(),
                creator.credentials().unwrap().read_public(),
                "{order:?}"
            );
            assert_eq!(
                group.roster().chain_hash(),
                creator.roster().chain_hash(),
                "{order:?}"
            );
            assert!(group.owes_rotation(now).is_none(), "{order:?}");
            assert!(!group.withholds(), "{order:?}");
            assert!(group.may_supply(3, 3), "{order:?}");
            let state = group.epochs.current().unwrap();
            places.push((state.base(), state.is_repeat()));
            assert_eq!(places.first(), places.last(), "{order:?}");
            assert_eq!(
                group.install_epoch_key(surplus.epoch, surplus.slot, surplus.body, now),
                Err(Error::Unverified),
                "{order:?}"
            );
            // The stored form keeps the count of the rival.
            let mut again = Group::restore(&group.export().unwrap(), &THIRD).unwrap();
            assert_eq!(
                again.install_epoch_key(surplus.epoch, surplus.slot, surplus.body, now),
                Err(Error::Unverified),
                "{order:?}"
            );
        }
    }

    /// An epoch-key record of the number `epoch` that the member of `group`
    /// builds for each member of its roster, whatever epoch it holds.
    fn forged_rotation(group: &Group, epoch: u32, now: u64, rng: &mut Rng) -> Vec<u8> {
        let members: Vec<(u16, Role, Vec<u8>, PairKey)> = group
            .roster
            .active()
            .filter_map(|member| {
                let pair = group
                    .keys
                    .pair_key(&member.pair_pk, group.group_id())
                    .ok()?;
                Some((member.index, member.role, member.kem_pk.clone()?, pair))
            })
            .collect();
        let included: Vec<Included<'_>> = members
            .iter()
            .map(|(index, role, kem_pk, pair)| Included {
                index: *index,
                role: *role,
                kem_pk,
                pair_key: pair,
            })
            .collect();
        let bucket = bucket_for_slots(0, included.len()).unwrap();
        let output = rotate(
            group.group_id(),
            epoch,
            group.roster.epoch_index(),
            group.own_index,
            &included,
            None,
            now,
            bucket,
            rng,
        )
        .unwrap();
        let body = output.inline.unwrap();
        let record = GroupQueueRecord {
            kind: RecordKind::EpochKey,
            epoch,
            slot: output.start_slot,
            nonce: [0; 12],
            body: &body,
        };
        let mut bytes = alloc::vec![0u8; bucket.group_record()];
        let n = record.encode(bucket, &mut bytes).unwrap();
        bytes.truncate(n);
        bytes
    }

    #[test]
    fn an_epoch_far_above_the_current_one_installs_nowhere_and_one_missed_epoch_does() {
        let now = 1_700_000_000;
        let mut rng = Rng(73);
        // GRP-288: a member that an admit placed holds no `K_e` and no
        // trigger. It takes the epoch directly above its own, and no
        // higher one, thus no record parts it from each later epoch.
        let (mut creator, mut joiner, _) = pair(now);
        for epoch in [u32::MAX, 3] {
            let forged = forged_rotation(&creator, epoch, now, &mut rng);
            let record = parse_record(&forged);
            assert_eq!(
                joiner.install_epoch_key(record.epoch, record.slot, record.body, now),
                Err(Error::Unverified)
            );
        }
        assert_eq!(joiner.epoch(), 1);
        let next = creator.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&next));
        joiner
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(joiner.epoch(), 2);

        // Each member holds `K_e` of epoch 2, and a member leaves.
        let (mut creator, mut member, mut third) = trio(now);
        let settled = creator.rotate(now, &mut rng).unwrap();
        let settled = parse_record(inline(&settled));
        for group in [&mut member, &mut third] {
            group
                .install_epoch_key(settled.epoch, settled.slot, settled.body, now)
                .unwrap();
        }
        let leave = third.leave_object().unwrap();
        spread(&leave, 2, &mut [&mut creator, &mut member], now);
        // An active member that the trigger does not exclude names the
        // highest number, and a number far above the bound. With either
        // one installed, no rotation could follow.
        for epoch in [u32::MAX, creator.epoch() + 20] {
            let forged = forged_rotation(&member, epoch, now, &mut rng);
            let record = parse_record(&forged);
            assert_eq!(
                creator.install_epoch_key(record.epoch, record.slot, record.body, now),
                Err(Error::Unverified)
            );
        }
        assert_eq!(creator.epoch(), 2);
        // The stored form holds the same bound.
        let mut again =
            Group::restore(&creator.export().unwrap(), &Secret::new([0x21; 32])).unwrap();
        let forged = forged_rotation(&member, u32::MAX, now, &mut rng);
        let record = parse_record(&forged);
        assert_eq!(
            again.install_epoch_key(record.epoch, record.slot, record.body, now),
            Err(Error::Unverified)
        );

        // The member misses the epoch that answers the leave. The next
        // trigger brings an epoch two above its own, and it installs.
        let missed = creator.rotate(now, &mut rng).unwrap();
        assert_eq!(missed.epoch, 3);
        assert_eq!(add_member(&mut creator, &mut [&mut member], 0x72, now), 3);
        let removal = creator.remove_object(3).unwrap();
        creator
            .apply_control(&GroupControl::parse(&removal).unwrap(), 0, now)
            .unwrap();
        spread(&removal, 0, &mut [&mut member], now);
        let next = creator.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&next));
        assert_eq!(record.epoch, 4);
        assert_eq!(member.epoch(), 2);
        member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(member.epoch(), 4);
        assert_eq!(
            member.credentials().unwrap().read_public(),
            creator.credentials().unwrap().read_public()
        );
        // The number above it is free, thus the next rotation runs.
        assert_eq!(member.rotate(now, &mut rng).unwrap().epoch, 5);
    }

    #[test]
    fn two_epochs_of_two_numbers_for_one_trigger_end_on_the_higher_one_in_each_order() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(75);
        let settled = creator.rotate(now, &mut rng).unwrap();
        let settled = parse_record(inline(&settled));
        for group in [&mut member, &mut third] {
            group
                .install_epoch_key(settled.epoch, settled.slot, settled.body, now)
                .unwrap();
        }
        // A member leaves, and the member at index 1 rotates. The creator
        // never holds that epoch, as after the order of `GRP-117` displaced
        // the head that carried its trigger.
        let leave = third.leave_object().unwrap();
        spread(&leave, 2, &mut [&mut creator, &mut member], now);
        assert_eq!(member.rotate(now, &mut rng).unwrap().epoch, 3);
        // One more trigger, which each of the two answers from its own
        // epoch: the creator with epoch 3, and the member with epoch 4.
        assert_eq!(add_member(&mut creator, &mut [&mut member], 0x71, now), 3);
        let removal = creator.remove_object(3).unwrap();
        creator
            .apply_control(&GroupControl::parse(&removal).unwrap(), 0, now)
            .unwrap();
        spread(&removal, 0, &mut [&mut member], now);
        let below = creator.export().unwrap();
        let above = member.export().unwrap();
        let low = creator.rotate(now, &mut rng).unwrap();
        let high = member.rotate(now, &mut rng).unwrap();
        assert_eq!((low.epoch, high.epoch), (3, 4));
        let (low, high) = (parse_record(inline(&low)), parse_record(inline(&high)));
        let surplus = Group::restore(&member.export().unwrap(), &JOINER_SEED)
            .unwrap()
            .rotate(now, &mut rng)
            .unwrap();
        let surplus = parse_record(inline(&surplus));

        // GRP-288: one reader holds the epoch of the creator, and one holds
        // the epoch of the member. Each reads the two records in each
        // order. Each one ends on the higher number, owes no rotation, and
        // gives a later record one verdict.
        let mut ends = Vec::new();
        for (start, seed) in [(&below, [0x21; 32]), (&above, *JOINER_SEED.expose())] {
            for order in [[&low, &high], [&high, &low]] {
                let mut group = Group::restore(start, &Secret::new(seed)).unwrap();
                for record in order {
                    let _ = group.install_epoch_key(record.epoch, record.slot, record.body, now);
                    group.retry_held(now);
                }
                assert_eq!(group.epoch(), 4);
                assert_eq!(
                    group.credentials().unwrap().read_public(),
                    member.credentials().unwrap().read_public()
                );
                assert!(group.owes_rotation(now).is_none());
                let state = group.epochs.current().unwrap();
                let place = (state.base(), state.is_repeat());
                let verdict =
                    group.install_epoch_key(surplus.epoch, surplus.slot, surplus.body, now);
                ends.push((place, verdict));
            }
        }
        // The reader below the two records holds one base in each order.
        assert_eq!(ends[0], ends[1]);
        assert_eq!(ends[2].1, ends[3].1);
        // The rotator of the lower number follows, and the one of the
        // higher number stays.
        creator
            .install_epoch_key(high.epoch, high.slot, high.body, now)
            .unwrap();
        assert_eq!(
            member.install_epoch_key(low.epoch, low.slot, low.body, now),
            Err(Error::Stale)
        );
        assert_eq!(creator.epoch(), member.epoch());
    }

    #[test]
    fn a_member_that_left_the_group_hands_no_owner_credentials() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(69);
        let grant = creator.grant(1, Role::Admin, &mut rng).unwrap();
        creator
            .apply_control(&GroupControl::parse(&grant).unwrap(), 0, now)
            .unwrap();
        spread(&grant, 0, &mut [&mut member, &mut third], now);
        let delivery = creator.owner_delivery(1, &mut rng).unwrap();
        let record = parse_record(&delivery);
        member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        // The admin builds a delivery of bytes of its own, and it leaves.
        // Its entry keeps the role `admin`, and its pair key still derives.
        member.replace_owners(&mut rng).unwrap();
        let forged = member.owner_delivery(0, &mut rng).unwrap();
        let leave = member.leave_object().unwrap();
        spread(&leave, 1, &mut [&mut creator, &mut third], now);
        assert_eq!(creator.roster().member(1).unwrap().role, Role::Admin);
        // GRP-379, GRP-401: the record names a roster epoch at which the
        // member was active. Its rotator is not active now, thus the
        // credentials that the relay holds stay.
        let held = *creator.owner(0).unwrap().expose();
        let record = parse_record(&forged);
        assert_eq!(
            creator.install_epoch_key(record.epoch, record.slot, record.body, now),
            Err(Error::Unverified)
        );
        assert_eq!(*creator.owner(0).unwrap().expose(), held);
        assert!(creator.retry_held(now).is_empty());
    }

    #[test]
    fn a_one_slot_record_of_the_current_epoch_takes_no_place_of_its_secret() {
        let now = 1_700_000_000;
        let (mut creator, mut member, third) = trio(now);
        let mut rng = Rng(71);
        let leave = third.leave_object().unwrap();
        spread(&leave, 2, &mut [&mut creator, &mut member], now);
        // The member at index 1 rotates, and each member holds its secret.
        let rotation = member.rotate(now, &mut rng).unwrap();
        let record = parse_record(inline(&rotation));
        creator
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        assert_eq!(member.epoch_rotator(), Some(1));
        let before = member.credentials().unwrap().write_public();

        // GRP-273: inside the grace the member at index 0 posts a one-slot
        // record of that epoch for index 1, with a secret of its own. The
        // index rule would give it the place of the true secret.
        let target = creator.roster().member(1).unwrap();
        let kem_pk = target.kem_pk.clone().unwrap();
        let pair = creator
            .keys
            .pair_key(&target.pair_pk, creator.group_id())
            .unwrap();
        let included = Included {
            index: 1,
            role: Role::Member,
            kem_pk: &kem_pk,
            pair_key: &pair,
        };
        let roster_epoch = creator.roster().epoch_index();
        let false_supply = creator
            .one_slot_record(
                &included,
                roster_epoch,
                &Secret::new([9; 32]),
                None,
                &mut rng,
            )
            .unwrap();
        let record = parse_record(&false_supply);
        member
            .install_epoch_key(record.epoch, record.slot, record.body, now)
            .unwrap();
        // The secret opens records and takes no place: the member writes
        // under the secret that the group holds.
        assert_eq!(member.epoch_rotator(), Some(1));
        assert_eq!(member.credentials().unwrap().write_public(), before);
        let post = member.post(&text("still read"), now, &mut rng).unwrap();
        assert!(matches!(
            creator.receive(&post, now).unwrap(),
            Outcome::Content { sender: 1, .. }
        ));
        // The stored form keeps the two apart.
        let mut member = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        assert_eq!(member.epoch_rotator(), Some(1));
        // A true supply of the secret that the member holds changes nothing.
        let supply = creator.key_supply(1, &mut rng).unwrap();
        let record = parse_record(&supply);
        assert_eq!(
            member.install_epoch_key(record.epoch, record.slot, record.body, now),
            Err(Error::Stale)
        );
    }

    #[test]
    fn a_roster_from_a_snapshot_takes_the_index_of_the_group_once() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        // The member misses two adds and the removal of the newest member,
        // as a restore from an old backup does.
        assert_eq!(add_member(&mut creator, &mut [], 0x61, now), 2);
        assert_eq!(add_member(&mut creator, &mut [], 0x62, now), 3);
        let removal = creator.remove_object(3).unwrap();
        creator
            .apply_control(&GroupControl::parse(&removal).unwrap(), 0, now)
            .unwrap();
        let snapshot = creator.snapshot(&[]).unwrap();
        member.recover_roster(&snapshot, now).unwrap();
        assert_eq!(member.roster().active_count(), 3);
        // GRP-320: the snapshot holds the active members alone, thus the
        // highest index that the group used lies above each entry. The next
        // add gives it, and the index after that one is exact again.
        assert_eq!(member.roster().next_index().unwrap(), 3);
        // GRP-329: until then the member builds no re-key from its own
        // count. Each other member holds index 4 as the next one, and a
        // record under index 3 would stand at this member alone.
        let (fresh, _) = join_of(&member, 0x66);
        assert_eq!(
            member.rekey_object(&fresh, &mut Rng(77)).err(),
            Some(Error::NoPath)
        );
        assert_eq!(add_member(&mut creator, &mut [&mut member], 0x63, now), 4);
        assert_eq!(member.roster().next_index().unwrap(), 5);
        assert!(member.rekey_object(&fresh, &mut Rng(77)).is_ok());
        let (keys, kem_pk) = join_of(&creator, 0x64);
        let record = JoinRecord {
            group_id: *creator.group_id(),
            keys: keys.wire_keys(&kem_pk),
        };
        let add = creator.add_object(&record).unwrap();
        let mut ahead =
            Group::restore(&creator.export().unwrap(), &Secret::new([0x21; 32])).unwrap();
        assert_eq!(add_member(&mut ahead, &mut [], 0x65, now), 5);
        let skipped = ahead.add_object(&record).unwrap();
        assert_eq!(
            member.apply_control(&GroupControl::parse(&skipped).unwrap(), 0, now),
            Err(Error::NoPath)
        );
        member
            .apply_control(&GroupControl::parse(&add).unwrap(), 0, now)
            .unwrap();
        // The stored form keeps an open index.
        let (mut creator, mut member, _) = pair(now);
        assert_eq!(add_member(&mut creator, &mut [], 0x61, now), 2);
        let removal = creator.remove_object(2).unwrap();
        creator
            .apply_control(&GroupControl::parse(&removal).unwrap(), 0, now)
            .unwrap();
        member
            .recover_roster(&creator.snapshot(&[]).unwrap(), now)
            .unwrap();
        let mut member = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        assert_eq!(add_member(&mut creator, &mut [&mut member], 0x63, now), 3);
    }

    #[test]
    fn the_key_of_a_member_starts_no_authority_path_unless_it_holds_index_zero() {
        let now = 1_700_000_000;
        let (creator, mut member, _) = pair(now);
        // GRP-399: a snapshot that makes the member at index 1 the one
        // owner, with no grant. Its own key as the start of the path would
        // back that role with nothing.
        let mut entries = creator.roster().entries();
        entries[0].role = Role::Member;
        entries[1].role = Role::Owner;
        let keys: Vec<MemberKemKey<'_>> = creator
            .roster()
            .active()
            .map(|member| MemberKemKey {
                index: member.index,
                kem_pk: member.kem_pk.as_deref().unwrap(),
            })
            .collect();
        let forged = RosterSnapshot {
            group_id: *creator.group_id(),
            roster_epoch: creator.roster().epoch_index() + 1,
            chain_hash: [0x77; 32],
            entries,
            keys,
            path: &[],
        };
        let mut bytes = alloc::vec![0u8; forged.len()];
        let n = forged.encode(&mut bytes).unwrap();
        assert_eq!(
            member.recover_roster(&bytes[..n], now),
            Err(Error::Unverified)
        );
        assert_eq!(member.own_role(), Some(Role::Member));
    }

    #[test]
    fn a_second_roster_object_of_the_head_maker_reaches_the_roster_and_each_reader_orders_the_two()
    {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(73);
        // Two devices hold the keys of index 1. One re-keys, and one
        // leaves, at one predecessor and under one counter.
        let mut other = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        let (fresh, _) = join_of(&member, 0x71);
        let rekey = member.rekey_object(&fresh, &mut rng).unwrap();
        let rekey = member.post(&control_app(&rekey, 8), now, &mut rng).unwrap();
        let leave = other.leave_object().unwrap();
        let leave = other.post(&control_app(&leave, 9), now, &mut rng).unwrap();

        // GRP-070, GRP-257: each head takes index 1 out of the active set,
        // and the second object still reaches the roster. Each reader shows
        // the fork and holds the head of the lower hash.
        let _ = read_control(&mut creator, &rekey, now);
        let _ = read_control(&mut creator, &leave, now);
        let _ = read_control(&mut third, &leave, now);
        let _ = read_control(&mut third, &rekey, now);
        assert_eq!(creator.roster().chain_hash(), third.roster().chain_hash());
        assert_eq!(creator.roster().forks().len(), 1);
        assert_eq!(third.roster().forks().len(), 1);
        assert_eq!(
            creator.roster().active_count(),
            third.roster().active_count()
        );
        assert!(!creator.roster().member(1).unwrap().active);
        // A record of that index that is no roster object stays out.
        let late = other.post(&text("after the head"), now, &mut rng).unwrap();
        assert_eq!(creator.receive(&late, now), Err(Error::Unverified));
    }

    #[test]
    fn two_records_under_one_counter_both_come_back_and_a_repeated_request_does_not() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(75);
        // GRP-342: two devices of one member post at an ownership change,
        // each under the counter that the sync gave it.
        let mut other = Group::restore(&member.export().unwrap(), &JOINER_SEED).unwrap();
        let first = member.post(&text("from the phone"), now, &mut rng).unwrap();
        let second = other.post(&text("from the tablet"), now, &mut rng).unwrap();
        assert!(matches!(
            creator.receive(&first, now).unwrap(),
            Outcome::Content {
                counter: 1,
                repeated: false,
                ..
            }
        ));
        // GRP-206: the counter gives the order alone. The second record is
        // no copy, and the store tells that by its `msg_id`.
        let Outcome::Content {
            counter,
            repeated,
            app,
            ..
        } = creator.receive(&second, now).unwrap()
        else {
            panic!("the second record did not come back");
        };
        assert_eq!((counter, repeated), (1, true));
        assert_eq!(
            AppMessage::parse(&app, Channel::Group).unwrap().body,
            b"from the tablet"
        );
        // A request for a key enters no store, thus its copy goes.
        let request = AppMessage {
            kind: AppKind::KeyRequest,
            msg_id: [3; 16],
            sent_at: 1_700_000_000_000,
            body: b"a request",
        };
        let mut bytes = alloc::vec![0u8; request.len()];
        let n = request.encode(&mut bytes).unwrap();
        let record = member.post(&bytes[..n], now, &mut rng).unwrap();
        assert!(matches!(
            creator.receive(&record, now).unwrap(),
            Outcome::Content {
                counter: 2,
                repeated: false,
                ..
            }
        ));
        assert_eq!(creator.receive(&record, now).unwrap(), Outcome::Duplicate);
    }

    #[test]
    fn the_last_owner_of_a_group_with_members_gets_no_self_removal() {
        let now = 1_700_000_000;
        let (mut creator, mut member, mut third) = trio(now);
        let mut rng = Rng(77);
        // GRP-067: the one owner of three members stays until another
        // member holds `owner`. A member below `owner` leaves.
        assert!(!creator.may_leave());
        assert_eq!(creator.leave_object().err(), Some(Error::NoPath));
        assert!(member.may_leave());
        let grant = creator.grant(1, Role::Owner, &mut rng).unwrap();
        creator
            .apply_control(&GroupControl::parse(&grant).unwrap(), 0, now)
            .unwrap();
        spread(&grant, 0, &mut [&mut member, &mut third], now);
        // One owner stays behind, thus this one leaves.
        assert!(creator.may_leave());
        assert!(creator.leave_object().is_ok());
        // The one owner of two members leaves the other with no owner.
        let (creator, other, _) = pair(now);
        assert!(!creator.may_leave());
        assert!(other.may_leave());
    }

    #[test]
    fn a_member_posts_no_roster_object_above_the_rate() {
        let now = 1_700_000_000;
        let (mut creator, _, _) = pair(now);
        let mut rng = Rng(79);
        // GRP-076: the add of the pair is one object of this slot. The
        // creator adds and removes a member until the slot is full.
        let mut made = 1;
        while made + 2 < crate::group::ROSTER_SLOT_RATE {
            let index = add_member(&mut creator, &mut [], 0x70, now);
            let removal = creator.remove_object(index).unwrap();
            creator
                .apply_control(&GroupControl::parse(&removal).unwrap(), 0, now)
                .unwrap();
            made += 2;
        }
        add_member(&mut creator, &mut [], 0x70, now);
        assert_eq!(made + 1, crate::group::ROSTER_SLOT_RATE);
        let (keys, kem_pk) = join_of(&creator, 0x72);
        let add = creator
            .add_object(&JoinRecord {
                group_id: *creator.group_id(),
                keys: keys.wire_keys(&kem_pk),
            })
            .unwrap();
        let app = control_app(&add, 4);
        assert!(creator.rate_bars(&app, now));
        assert_eq!(creator.post(&app, now, &mut rng), Err(Error::NoPath));
        assert_eq!(
            creator.apply_control(&GroupControl::parse(&add).unwrap(), 0, now),
            Err(Error::Unverified)
        );
        // A record that is no roster object goes out, and the next slot
        // takes the object.
        assert!(!creator.rate_bars(&text("a text"), now));
        let next = now + crate::group::GROUP_SLOT;
        assert!(!creator.rate_bars(&app, next));
        assert!(creator.post(&app, next, &mut rng).is_ok());
    }

    #[test]
    fn the_bucket_grows_with_the_member_count() {
        // The dense vector costs 12 bytes for each member, and §11.2 states
        // that the modal 350-byte text stays in `B1` up to N = 124.
        let app_of = |text: usize| text + umbra_wire::app::HEADER_LEN;
        assert_eq!(bucket_for(3, app_of(269)), Some(Bucket::B0));
        assert_eq!(bucket_for(3, app_of(270)), Some(Bucket::B1));
        assert_eq!(bucket_for(124, app_of(350)), Some(Bucket::B1));
        assert_eq!(bucket_for(125, app_of(350)), Some(Bucket::B2));
        assert_eq!(bucket_for(500, app_of(1_985)), Some(Bucket::B2));
        assert_eq!(bucket_for(500, 1 << 20), None);
    }

    #[test]
    fn an_observer_posts_no_message_and_still_leaves() {
        let now = 1_700_000_000;
        let (mut creator, mut member, _) = pair(now);
        let mut rng = Rng(83);
        let grant = creator.grant(1, Role::Observer, &mut rng).unwrap();
        let grant = GroupControl::parse(&grant).unwrap();
        creator.apply_control(&grant, 0, now).unwrap();
        member.apply_control(&grant, 0, now).unwrap();
        assert_eq!(member.own_role(), Some(Role::Observer));
        // §11.9: an observer reads the group and posts nothing to it.
        let said = member
            .post(&text("from an observer"), now, &mut rng)
            .unwrap();
        assert_eq!(creator.receive(&said, now), Err(Error::Unverified));
        // Its roster objects still apply.
        let leave = member.leave_object().unwrap();
        let leave = member.post(&control_app(&leave, 9), now, &mut rng).unwrap();
        assert!(matches!(
            read_control(&mut creator, &leave, now),
            Ok(Applied::Removed(_))
        ));
    }

    /// A chunked epoch-key body of `roster_epoch` with a descriptor of
    /// `mark`.
    fn chunked(roster_epoch: u32, mark: u8) -> Vec<u8> {
        let descriptor = [mark; 40];
        let body = EpochKeyBody {
            roster_epoch,
            slot_count: 2,
            carrier: Carrier::Chunked {
                slots_per_chunk: 1,
                descriptor: &descriptor,
            },
        };
        let mut out = alloc::vec![0u8; Bucket::B0.group_body()];
        let n = body.encode(Bucket::B0, &mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn a_chunked_body_of_a_later_epoch_takes_no_place_of_the_next_one() {
        let now = 1_700_000_000;
        let (mut creator, _, _) = pair(now);
        let t = slot_of(now);
        let e = creator.epoch();
        // Any writer of the queue posts bodies of later epochs first.
        for (step, mark) in [(5u32, 1u8), (6, 2), (7, 3), (8, 4)] {
            let _ = creator.install_epoch_key(e + step, t, &chunked(1, mark), now);
        }
        assert_eq!(creator.waiting.len(), WAITING_MAX);
        // The body of the next epoch takes the place of the highest one.
        let _ = creator.install_epoch_key(e + 1, t, &chunked(1, 9), now);
        let held: Vec<u32> = creator.waiting.iter().map(|held| held.epoch).collect();
        assert!(held.contains(&(e + 1)) && !held.contains(&(e + 8)));
        // A body of a later epoch than each one held goes, and so does
        // one whose start slot is past the age bound (GRP-383).
        let _ = creator.install_epoch_key(e + 9, t, &chunked(1, 10), now);
        assert!(!creator.waiting.iter().any(|held| held.epoch == e + 9));
        let _ = creator.install_epoch_key(e + 2, 0, &chunked(1, 11), now);
        assert!(!creator.waiting.iter().any(|held| held.epoch == e + 2));
        // Of one epoch, the body that came first keeps its place.
        let _ = creator.install_epoch_key(e + 1, t, &chunked(1, 12), now + 1);
        assert!(creator
            .waiting
            .iter()
            .any(|held| held.epoch == e + 1 && held.body == chunked(1, 9)));
    }
}
