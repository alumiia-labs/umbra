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
    epoch::{one_slot, rotate, EpochState, EpochStore, Included},
    join::{admit, admit_slot, Admitted},
    queue::Replicas,
    receive::{Context, Outcome, Receiver},
    roster::{Applied, Member, Roster, Trigger, STORED_VERSION},
    send::{PairCache, Sender},
    slot_of, GROUP_REPLICAS,
};
use crate::Error;

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
        let mut epochs = EpochStore::default();
        epochs.install(admitted.epoch)?;
        Ok(Group {
            own_index: admitted.index,
            previous: None,
            displaced: None,
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
        // path, and this member is the creator when it holds no other.
        let mut keys: Vec<Vec<u8>> = self
            .roster
            .active()
            .filter(|member| member.role == Role::Owner)
            .filter_map(|member| member.roster_pk.clone())
            .collect();
        keys.push(self.own_roster_pk());
        let roster = keys
            .iter()
            .find_map(|key| Roster::from_snapshot(&snapshot, &snapshot.chain_hash, key, now).ok())
            .ok_or(Error::Unverified)?;
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
        // GRP-372: each record takes both indexes of a re-key, as a record
        // that arrives does, thus one tagged for the index before stays.
        let mut out = Vec::new();
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
        let new = match self.apply_roster(&control, self.own_index, now) {
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
        self.receiver.expire_held(now, current)
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

    /// The plain epoch by which this member leaves (`GRP-067`).
    pub fn leave_object(&self) -> Result<Vec<u8>, Error> {
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
            let pair = self
                .keys
                .pair_key(&member.pair_pk, self.roster.group_id())?;
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
        self.epochs.install(EpochState::new(
            output.secret,
            self.roster.group_id(),
            epoch,
            output.start_slot,
            roster_epoch,
            self.own_index,
            now,
        ))?;
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
        self.check_epoch_key(epoch, now)?;
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
        self.check_epoch_key(wanted.epoch, now)?;
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
                    self.finish_install(
                        wanted.epoch,
                        wanted.start_slot,
                        wanted.roster_epoch,
                        &payload,
                        now,
                    )?;
                    // GRP-372: a slot for the new index ends the keys before it.
                    if is_current {
                        self.previous = None;
                    }
                    return Ok(());
                }
                Err(error) => refused = error,
            }
        }
        Err(refused)
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
    /// leaves the state as it was, and §11.4.3 covers the repair.
    pub fn install_epoch_key(
        &mut self,
        epoch: u32,
        start_slot: u32,
        body: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        self.check_epoch_key(epoch, now)?;
        let (payload, roster_epoch, is_current) = self.open_epoch_slot(epoch, start_slot, body)?;
        self.finish_install(epoch, start_slot, roster_epoch, &payload, now)?;
        // GRP-372: a slot for the new index ends the keys before it.
        if is_current {
            self.previous = None;
        }
        Ok(())
    }

    /// Whether an epoch-key record of `epoch` may install at `now`
    /// (`GRP-357`, `GRP-288`).
    fn check_epoch_key(&self, epoch: u32, now: u64) -> Result<(), Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        if epoch == current.epoch().saturating_add(1) {
            // GRP-357: a rotation that no trigger called for is refused.
            if self
                .roster
                .triggers_since(current.roster_epoch())
                .is_empty()
                && !current.aged(now)
            {
                return Err(Error::Unverified);
            }
        } else if epoch != current.epoch() {
            // GRP-288: an epoch below the current one, and one above the
            // next. A second record of the current epoch races, and
            // `EpochStore::install` settles it by the rotator index.
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// GRP-356: the record of the next epoch names a roster epoch at or
    /// above the first trigger since the epoch before, and its rotator is no
    /// index that a trigger since then excludes. Thus a removed member
    /// cannot post the next epoch under any roster epoch; an honest rotator
    /// that a later trigger removed rotates again under Part 11 §11.4.3.
    fn check_rotator(&self, epoch: u32, roster_epoch: u32, rotator: u16) -> Result<(), Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        // A second record of the current epoch races the first, and it
        // answers the triggers since the epoch before, as the first did
        // (GRP-273, GRP-288). Without that epoch no check holds, and the
        // record installs nowhere here.
        let base = if epoch == current.epoch().saturating_add(1) {
            current.roster_epoch()
        } else if epoch == current.epoch() {
            self.epochs
                .previous()
                .ok_or(Error::Unverified)?
                .roster_epoch()
        } else {
            return Ok(());
        };
        let triggers = self.roster.triggers_since(base);
        let first = triggers.iter().map(|trigger| trigger.roster_epoch).min();
        if first.is_some_and(|first| roster_epoch < first) {
            return Err(Error::Unverified);
        }
        // GRP-356: an index that any trigger since the epoch before
        // excludes rotates nothing, whatever roster epoch its record names.
        let excluded = triggers
            .iter()
            .any(|trigger| trigger.excluded == Some(rotator));
        if excluded {
            return Err(Error::Unverified);
        }
        Ok(())
    }

    /// Installs what an opened slot gives.
    fn finish_install(
        &mut self,
        epoch: u32,
        start_slot: u32,
        roster_epoch: u32,
        payload: &SlotPayload,
        now: u64,
    ) -> Result<(), Error> {
        // GRP-400: a slot with no epoch secret hands the owner credentials
        // and installs no epoch. Only a slot of the current epoch holds it.
        if payload.epoch_secret.expose() == &[0; 32] {
            if epoch != self.epochs.epoch() || payload.own_sks.len() != GROUP_REPLICAS {
                return Err(Error::Unverified);
            }
            self.take_owners(payload);
            return Ok(());
        }
        self.check_rotator(epoch, roster_epoch, payload.rotator)?;
        let secret = EpochSecret::from_secret(Secret::new(*payload.epoch_secret.expose()));
        // GRP-386: the two queue credentials come from `K_e`.
        self.epochs.install(EpochState::new(
            secret,
            self.roster.group_id(),
            epoch,
            start_slot,
            roster_epoch,
            payload.rotator,
            now,
        ))?;
        self.take_owners(payload);
        Ok(())
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
    /// moves.
    pub fn holds_openable(&self, now: u64) -> bool {
        self.held_at(now, core::cmp::Ordering::Equal)
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
            && current.secret().expose().expose() != &[0; 32]
            && index != self.own_index
            && self
                .roster
                .member(index)
                .is_some_and(|member| member.active)
            && self
                .roster
                .active_at(current.roster_epoch())
                .is_some_and(|set| set.contains(&index))
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
    ) -> Result<(SlotPayload, u32, bool), Error> {
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
                Ok((payload, is_current)) => return Ok((payload, parsed.roster_epoch, is_current)),
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
        let (payload, _) = super::epoch::open_own_slot(
            slots,
            own_index,
            keys,
            self.roster.group_id(),
            epoch,
            roster_epoch,
            |index| self.role_at(index, roster_epoch),
            pair_with,
        )?;
        let pair = pair_with(payload.rotator).ok_or(Error::NoPath)?;
        super::epoch::verify_slot_tag(
            &pair,
            self.roster.group_id(),
            epoch,
            start_slot,
            roster_epoch,
            &payload,
        )?;
        Ok(payload)
    }

    /// The role of `index` at `roster_epoch`, and none when the member was
    /// not active then (`GRP-356`). The history bounds the answer, thus an
    /// epoch it no longer keeps falls back to the current set.
    fn role_at(&self, index: u16, roster_epoch: u32) -> Option<Role> {
        let member = self.roster.member(index)?;
        let active = self
            .roster
            .active_at(roster_epoch)
            .map_or(member.active, |set| set.contains(&index));
        active.then_some(member.role)
    }

    /// Applies a roster object that a verified tag attributes to `sender`
    /// (`GRP-318`). A pair key of a removed member leaves with it.
    pub fn apply_control(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
        now: u64,
    ) -> Result<Applied, Error> {
        let applied = self.apply_roster(control, sender, now)?;
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
        now: u64,
    ) -> Result<Applied, Error> {
        let applied = self.roster.apply(control, sender, now)?;
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
    /// and the two replicas (`GRP-312`, `GRP-233`), at the roster epoch
    /// that stands.
    pub fn admit_for(
        &self,
        index: u16,
        history_window_seconds: u64,
        descriptor: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        self.admit_at(
            index,
            self.roster.epoch_index(),
            history_window_seconds,
            descriptor,
            now,
        )
    }

    /// The admit at `roster_epoch`, the roster epoch of the add and of its
    /// snapshot (`GRP-323`). The roster can move between the add and the
    /// admit, and the joiner checks the two against each other.
    pub fn admit_at(
        &self,
        index: u16,
        roster_epoch: u32,
        history_window_seconds: u64,
        descriptor: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        let replicas = self.replicas.as_ref().ok_or(Error::NoPath)?;
        let refs = [
            *replicas.reference(0).ok_or(Error::NoPath)?,
            *replicas.reference(1).ok_or(Error::NoPath)?,
        ];
        let slot = admit_slot(slot_of(now), current.start_slot(), history_window_seconds);
        // GRP-423: an admin that joined inside the epoch holds no `K_e`,
        // thus it derives from its own chain, and the history window ends
        // at the oldest slot of that chain.
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

        let admit_bytes = creator.admit_for(1, 0, b"", now).unwrap();
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
        // GRP-259: the same record again is a duplicate.
        assert_eq!(member.receive(&record, now).unwrap(), Outcome::Duplicate);

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
        // before the restart is a duplicate and the next one is not.
        assert_eq!(member.receive(&first, now).unwrap(), Outcome::Duplicate);
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
        let admit_bytes = creator.admit_for(2, 0, b"", now).unwrap();
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
    fn an_admin_that_joined_inside_the_epoch_admits_a_member_that_reads() {
        // GRP-423: the member of index 1 joined inside the epoch and holds
        // no `K_e`; its admit comes from its own chain, and the third member
        // reads the records of the creator after it.
        // The member joins two days into the epoch, thus its chain starts
        // after `t_e`, and the history window stops at its join.
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
        // A history window reaches no slot before the chain of the member.
        let admit_bytes = member.admit_for(2, 7 * 86_400, b"", later).unwrap();
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
        assert!(third.check_rotator(next_epoch, removed_at, 1).is_err());
        assert!(third.check_rotator(next_epoch, removed_at - 1, 0).is_err());
        assert!(third.check_rotator(next_epoch, removed_at, 0).is_ok());

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
    fn a_record_that_fills_a_hole_shows_and_a_repeat_does_not() {
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
        assert_eq!(
            member.receive(&records[1], now).unwrap(),
            Outcome::Duplicate
        );
        assert_eq!(
            member.receive(&records[0], now).unwrap(),
            Outcome::Duplicate
        );
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
        let admit = creator.admit_for(3, 0, b"", now).unwrap();
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
        let admit = creator.admit_for(index, 0, b"", now).unwrap();
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
}
