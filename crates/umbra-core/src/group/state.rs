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
            MemberKemKey, PlainEpoch, PlainOp, ReplicaRef, Role, RosterSnapshot,
        },
        record::{
            slot_len, Carrier, EpochKeyBody, GroupQueueRecord, RecordKind, SlotPayload,
            EPOCH_KEY_FIXED, REPLICAS,
        },
    },
};

use super::{
    backoff,
    epoch::{owner_delivery, rotate, EpochState, EpochStore, Included},
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

/// What a rotation produced.
pub struct Rotation {
    /// The epoch-key record, one copy for each replica.
    pub record: Vec<u8>,
    /// The epoch it starts.
    pub epoch: u32,
    /// The write credential of the epoch before this one, under which the
    /// record goes to each replica. The relay holds it for
    /// `GROUP_WRITE_GRACE`, and it takes the credential of the new epoch
    /// only after a `GKEY` (`GRP-362`).
    pub write: Secret<32>,
}

/// One group at one device.
pub struct Group {
    own_index: u16,
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

    /// Writes the group to the stored form of Part 15 §15.6.4. It holds
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
        Ok(w.finish())
    }

    /// Reads a group that [`Group::export`] wrote, with the seed of its
    /// row in the local identity table. The pair keys are a cache, thus
    /// the restored group derives each one again at its first use.
    pub fn restore(bytes: &[u8], seed: &Secret<32>) -> Result<Self, Error> {
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
        r.end()?;
        Ok(Group {
            own_index,
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
        let mut ctx = Context {
            roster: &self.roster,
            epochs: &mut self.epochs,
            pairs: &mut self.pairs,
            own: &self.keys,
        };
        self.receiver.receive(record, bucket, &mut ctx, now)
    }

    /// Tries each held record again, after a roster object or a clock
    /// check (`GRP-252`, `GRP-229`).
    pub fn retry_held(&mut self, now: u64) -> Vec<Outcome> {
        let mut ctx = Context {
            roster: &self.roster,
            epochs: &mut self.epochs,
            pairs: &mut self.pairs,
            own: &self.keys,
        };
        self.receiver.retry_held(&mut ctx, now)
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
        // GRP-281: a group above the inline carrier writes its slots on
        // the chunk path, which this device does not do yet.
        let bucket =
            bucket_for_slots(admins, included.len().saturating_sub(admins)).ok_or(Error::NoPath)?;
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
        let body = output.inline.ok_or(Error::NoPath)?;
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
            record: bytes,
            epoch,
            write,
        })
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
        let current = self.epochs.current().ok_or(Error::NoPath)?;
        let current_epoch = current.epoch();
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
        let (payload, roster_epoch) = self.open_epoch_slot(epoch, start_slot, body)?;
        // GRP-400: a slot with no epoch secret hands the owner credentials
        // and installs no epoch. Only a slot of the current epoch holds it.
        if payload.epoch_secret.expose() == &[0; 32] {
            if epoch != current_epoch || payload.own_sks.len() != GROUP_REPLICAS {
                return Err(Error::Unverified);
            }
            self.take_owners(&payload);
            return Ok(());
        }
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
        self.take_owners(&payload);
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
        let current = self.epochs.current().ok_or(Error::NoPath)?;
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
        let bucket = bucket_for_slots(1, 0).ok_or(Error::NoPath)?;
        let body = owner_delivery(
            self.roster.group_id(),
            current.epoch(),
            current.start_slot(),
            self.roster.epoch_index(),
            self.own_index,
            &included,
            owners,
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
    ) -> Result<(SlotPayload, u32), Error> {
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
                // GRP-283: a chunked record waits for the chunk path.
                return Err(Error::NoPath);
            };
            match self.read_own_slot(parsed.roster_epoch, slots, epoch, start_slot) {
                Ok(payload) => return Ok((payload, parsed.roster_epoch)),
                Err(error) => refused = error,
            }
        }
        Err(refused)
    }

    /// Opens and verifies the slot of this member. `role_at` bars a
    /// rotator that the roster did not hold at `roster_epoch`, which is
    /// the index each trigger of that epoch excludes (`GRP-356`).
    fn read_own_slot(
        &self,
        roster_epoch: u32,
        slots: &[umbra_wire::group::record::KemSlot<'_>],
        epoch: u32,
        start_slot: u32,
    ) -> Result<SlotPayload, Error> {
        let (payload, _) = super::epoch::open_own_slot(
            slots,
            self.own_index,
            &self.keys,
            self.roster.group_id(),
            epoch,
            roster_epoch,
            |index| self.role_at(index, roster_epoch),
            |index| self.pair_key_with(index),
        )?;
        let pair = self.pair_key_with(payload.rotator).ok_or(Error::NoPath)?;
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

    fn pair_key_with(&self, index: u16) -> Option<PairKey> {
        let member = self.roster.member(index)?;
        self.keys
            .pair_key(&member.pair_pk, self.roster.group_id())
            .ok()
    }

    /// Applies a roster object that a verified tag attributes to `sender`
    /// (`GRP-318`). A pair key of a removed member leaves with it.
    pub fn apply_control(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
        now: u64,
    ) -> Result<Applied, Error> {
        let applied = self.roster.apply(control, sender, now)?;
        if let Applied::Removed(trigger) = &applied {
            if let Some(index) = trigger.excluded {
                self.pairs.remove(index);
                self.receiver.removed(index);
            }
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
        let chain = current.secret().start(
            self.roster.group_id(),
            current.epoch(),
            current.start_slot(),
        );
        admit(
            *self.roster.group_id(),
            index,
            current.epoch(),
            slot,
            &chain,
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
        let mut rng = Rng(9);
        let creator_seed = Secret::new([0x21; 32]);
        let mut creator = Group::create([0x55; 32], &creator_seed, now, &mut rng).unwrap();
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

        let first_epoch = creator.epoch();
        let rotation = creator.rotate(now, &mut rng).unwrap();
        assert_eq!(rotation.epoch, first_epoch + 1);
        assert_eq!(creator.epoch(), first_epoch + 1);
        assert!(creator.owes_rotation(now).is_none());

        let record = parse_record(&rotation.record);
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
        let record = parse_record(&rotation.record);
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
        let record = parse_record(&rotation.record);
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
