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
    group::control::{
        GroupControl, GroupMemberEntry, JoinRecord, MemberKemKey, ReplicaRef, Role, RosterSnapshot,
    },
};

use super::{
    epoch::{EpochState, EpochStore},
    join::{admit, admit_slot, Admitted},
    queue::Replicas,
    receive::{Context, Outcome, Receiver},
    roster::{Applied, Member, Roster, STORED_VERSION},
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

    /// Reads one record that a `GMSG` carried. The bucket comes from the
    /// record length, which the relay does not change (`WIR-372`).
    pub fn receive(&mut self, record: &[u8], now: u64) -> Result<Outcome, Error> {
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
    /// and the two replicas (`GRP-312`, `GRP-233`).
    pub fn admit_for(
        &self,
        index: u16,
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
            self.roster.epoch_index(),
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
