//! The receiving side of a group record (Part 11 §11.3.5, §11.2.2): the
//! epoch and the slot window, the open under each candidate key, the
//! roster epoch the record names, the tag at the receiver's own position,
//! the counter of each sender with its gap, and the records held for a
//! roster that has not arrived.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::group::{
    pair::{app_hash, RecordTag},
    MemberKeys,
};
use umbra_wire::{
    bucket::Bucket,
    group::record::{open_content, ContentPlain, GroupQueueRecord, RecordKind},
};

use umbra_crypto::stored::{Reader, Writer};

use super::{
    epoch::EpochStore,
    roster::{count, Roster, STORED_VERSION},
    send::PairCache,
    GROUP_GAP_TIMEOUT, GROUP_ROSTER_WAIT,
};
use crate::Error;

/// What the receiver holds and reads.
pub struct Context<'a> {
    /// The roster.
    pub roster: &'a Roster,
    /// The epochs.
    pub epochs: &'a mut EpochStore,
    /// The pair keys.
    pub pairs: &'a mut PairCache,
    /// The member's own keys.
    pub own: &'a MemberKeys,
}

/// The place of a bucket in [`Bucket::ALL`], for a stored record.
fn bucket_byte(bucket: Bucket) -> u8 {
    u8::try_from(
        Bucket::ALL
            .into_iter()
            .position(|held| held == bucket)
            .unwrap_or(0),
    )
    .unwrap_or(0)
}

/// The outcome of one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A content record that verified.
    Content {
        /// The member the tag names (`GRP-243`).
        sender: u16,
        /// The counter, for the order of `GRP-302`.
        counter: u32,
        /// The roster epoch the record named.
        roster_epoch: u32,
        /// The group epoch.
        epoch: u32,
        /// The `AppMessage` bytes.
        app: Vec<u8>,
        /// Whether the record came under the previous epoch.
        previous_epoch: bool,
    },
    /// An epoch-key record, for the epoch module.
    EpochKey {
        /// The epoch it starts.
        epoch: u32,
        /// `t_e`.
        start_slot: u32,
        /// The `EpochKeyBody` bytes.
        body: Vec<u8>,
    },
    /// The record names a roster epoch ahead of the local roster, and it
    /// waits (`GRP-252`).
    Held,
    /// The slot is outside the window, and the record waits for a clock
    /// check (`GRP-229`).
    ClockSuspect,
    /// A repeated or lower counter (`GRP-259`).
    Duplicate,
}

struct HeldRecord {
    bytes: Vec<u8>,
    bucket: Bucket,
    arrived_at: u64,
}

/// The receiver state of one member in one group.
pub struct Receiver {
    own_index: u16,
    counters: BTreeMap<(u16, u32), u32>,
    held: Vec<HeldRecord>,
    gaps: BTreeMap<u16, u64>,
}

impl Receiver {
    /// A receiver at `own_index`.
    pub const fn new(own_index: u16) -> Self {
        Receiver {
            own_index,
            counters: BTreeMap::new(),
            held: Vec::new(),
            gaps: BTreeMap::new(),
        }
    }

    /// Writes the receiver to its stored form. The held records travel
    /// with it, because a roster that has not arrived outlives a run.
    pub fn export(&self, w: &mut Writer) -> Result<(), Error> {
        w.u8(STORED_VERSION);
        w.u16(self.own_index);
        w.u32(count(self.counters.len())?);
        for ((sender, epoch), counter) in &self.counters {
            w.u16(*sender);
            w.u32(*epoch);
            w.u32(*counter);
        }
        w.u32(count(self.held.len())?);
        for held in &self.held {
            w.u8(bucket_byte(held.bucket));
            w.u64(held.arrived_at);
            w.var(&held.bytes)?;
        }
        w.u32(count(self.gaps.len())?);
        for (sender, since) in &self.gaps {
            w.u16(*sender);
            w.u64(*since);
        }
        Ok(())
    }

    /// Reads a receiver that [`Receiver::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.u8()? != STORED_VERSION {
            return Err(Error::Stale);
        }
        let own_index = r.u16()?;
        let mut counters = BTreeMap::new();
        for _ in 0..r.u32()? {
            let sender = r.u16()?;
            let epoch = r.u32()?;
            counters.insert((sender, epoch), r.u32()?);
        }
        let mut held = Vec::new();
        for _ in 0..r.u32()? {
            let bucket = *Bucket::ALL
                .get(usize::from(r.u8()?))
                .ok_or(Error::Malformed)?;
            let arrived_at = r.u64()?;
            held.push(HeldRecord {
                bucket,
                arrived_at,
                bytes: r.var()?.to_vec(),
            });
        }
        let mut gaps = BTreeMap::new();
        for _ in 0..r.u32()? {
            gaps.insert(r.u16()?, r.u64()?);
        }
        Ok(Receiver {
            own_index,
            counters,
            held,
            gaps,
        })
    }

    /// The roster epoch a plaintext names, before the parse.
    fn roster_epoch_of(plain: &[u8]) -> Result<u32, Error> {
        let bytes: [u8; 4] = plain
            .get(6..10)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Processes one record at `now`.
    pub fn receive(
        &mut self,
        bytes: &[u8],
        bucket: Bucket,
        ctx: &mut Context<'_>,
        now: u64,
    ) -> Result<Outcome, Error> {
        let record = GroupQueueRecord::parse(bytes, bucket)?;
        if record.kind == RecordKind::EpochKey {
            return Ok(Outcome::EpochKey {
                epoch: record.epoch,
                start_slot: record.slot,
                body: record.body.to_vec(),
            });
        }
        let keys = match ctx.epochs.record_keys(record.epoch, record.slot, now) {
            Ok(keys) => keys,
            Err(Error::Stale) => {
                self.hold(bytes, bucket, now);
                return Ok(Outcome::ClockSuspect);
            }
            Err(e) => return Err(e),
        };
        let mut opened: Option<(Vec<u8>, bool)> = None;
        for (key, previous) in &keys {
            let mut out = alloc::vec![0u8; bucket.group_record()];
            if let Ok(n) = open_content(&record, key, ctx.roster.group_id(), &mut out) {
                out.truncate(n);
                opened = Some((out, *previous));
                break;
            }
        }
        // One error covers the open, the tag, and the parse (GRP-251).
        let (plain_bytes, previous_epoch) = opened.ok_or(Error::Unverified)?;
        let roster_epoch = Self::roster_epoch_of(&plain_bytes)?;
        if roster_epoch > ctx.roster.epoch_index() {
            self.hold(bytes, bucket, now);
            return Ok(Outcome::Held);
        }
        if roster_epoch < ctx.roster.admission_epoch() {
            return Err(Error::Stale);
        }
        let roster = ctx.roster;
        let plain = ContentPlain::parse(&plain_bytes, |re| {
            roster
                .active_at(re)
                .and_then(|set| u16::try_from(set.len()).ok())
        })?;
        let sender = plain.sender_index;
        // The sender must be in the current roster (GRP-257, GRP-232).
        if !roster.member(sender).is_some_and(|m| m.active) || sender == self.own_index {
            return Err(Error::Unverified);
        }
        let rank = roster
            .rank_at(roster_epoch, self.own_index)
            .ok_or(Error::Unverified)?;
        let tag = plain
            .tags
            .tag_for(rank, self.own_index)
            .ok_or(Error::Unverified)?;
        let key = ctx.pairs.get(sender, roster, ctx.own)?;
        key.verify_record_tag(
            &RecordTag {
                group_id: roster.group_id(),
                epoch: record.epoch,
                slot: record.slot,
                sender_index: sender,
                counter: plain.counter,
                roster_epoch,
                app_hash: &app_hash(plain.app),
            },
            &tag,
        )?;
        let last = self.counters.entry((sender, record.epoch)).or_insert(0);
        if plain.counter <= *last {
            return Ok(Outcome::Duplicate);
        }
        if plain.counter > last.saturating_add(1) {
            self.gaps.entry(sender).or_insert(now);
        } else {
            self.gaps.remove(&sender);
        }
        *last = plain.counter;
        Ok(Outcome::Content {
            sender,
            counter: plain.counter,
            roster_epoch,
            epoch: record.epoch,
            app: plain.app.to_vec(),
            previous_epoch,
        })
    }

    fn hold(&mut self, bytes: &[u8], bucket: Bucket, now: u64) {
        self.held.push(HeldRecord {
            bytes: bytes.to_vec(),
            bucket,
            arrived_at: now,
        });
    }

    /// The records held.
    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// Tries each held record again, after a roster record or a clock
    /// check, and returns what resolved.
    pub fn retry_held(&mut self, ctx: &mut Context<'_>, now: u64) -> Vec<Outcome> {
        let held = core::mem::take(&mut self.held);
        let mut out = Vec::new();
        for record in held {
            match self.receive(&record.bytes, record.bucket, ctx, now) {
                Ok(Outcome::Held | Outcome::ClockSuspect) => {
                    // `receive` pushed it again; keep its first arrival.
                    if let Some(last) = self.held.last_mut() {
                        last.arrived_at = record.arrived_at;
                    }
                }
                Ok(outcome) => out.push(outcome),
                Err(_) => {}
            }
        }
        out
    }

    /// Discards each held record past `GROUP_ROSTER_WAIT`, and returns the
    /// count, which the client shows as a gap (`GRP-253`, `GRP-254`).
    pub fn expire_held(&mut self, now: u64) -> usize {
        let before = self.held.len();
        self.held
            .retain(|h| now.saturating_sub(h.arrived_at) < GROUP_ROSTER_WAIT);
        before.saturating_sub(self.held.len())
    }

    /// Whether a counter gap of one sender stood longer than
    /// `GROUP_GAP_TIMEOUT`, or a record waits for a roster, which sends the
    /// reader to the other replica (`GRP-205`, `GRP-255`).
    pub fn needs_other_replica(&self, now: u64) -> bool {
        !self.held.is_empty()
            || self
                .gaps
                .values()
                .any(|since| now.saturating_sub(*since) >= GROUP_GAP_TIMEOUT)
    }

    /// The last counter seen from `sender` in `epoch`.
    pub fn last_counter(&self, sender: u16, epoch: u32) -> u32 {
        self.counters.get(&(sender, epoch)).copied().unwrap_or(0)
    }

    /// Forgets a removed member's counters and gap (`GRP-245` companion).
    pub fn removed(&mut self, sender: u16) {
        self.counters.retain(|(s, _), _| *s != sender);
        self.gaps.remove(&sender);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        group::{
            epoch::EpochState,
            roster::tests::{add_control, entry_of},
            send::Sender,
            test_util::member,
            GROUP_SLOT,
        },
    };
    use umbra_crypto::{group::chain::EpochSecret, secret::Secret};
    use umbra_wire::group::control::{GroupControl, Role};

    fn epochs(group: &[u8; 32], seed: u64, now: u64) -> EpochStore {
        let mut store = EpochStore::default();
        let secret = EpochSecret::generate(&mut Rng(seed)).unwrap();
        store
            .install(EpochState::new(
                secret,
                group,
                1,
                crate::group::slot_of(now),
                1,
                0,
                now,
            ))
            .unwrap();
        store
    }

    #[test]
    fn a_record_opens_verifies_its_tag_and_tracks_the_counter() {
        let group = [7u8; 32];
        let now = 2_000 * GROUP_SLOT;
        let alice = member(1);
        let bob = member(2);
        let mut roster = Roster::genesis(group, entry_of(&alice, 0, Role::Owner), 0);
        let add = add_control(&roster, &bob, 1);
        roster
            .apply(&GroupControl::parse(&add).unwrap(), 0, 1)
            .unwrap();

        // Both hold the same epoch secret.
        let secret = EpochSecret::generate(&mut Rng(9)).unwrap();
        let mut alice_epochs = EpochStore::default();
        alice_epochs
            .install(EpochState::new(
                EpochSecret::from_secret(Secret::new(*secret.expose().expose())),
                &group,
                1,
                crate::group::slot_of(now),
                1,
                0,
                now,
            ))
            .unwrap();
        let mut bob_epochs = EpochStore::default();
        bob_epochs
            .install(EpochState::new(
                secret,
                &group,
                1,
                crate::group::slot_of(now),
                1,
                0,
                now,
            ))
            .unwrap();

        let mut sender = Sender::default();
        let mut alice_pairs = PairCache::default();
        let record = sender
            .build(
                0,
                &alice,
                &roster,
                &mut alice_epochs,
                &mut alice_pairs,
                b"app bytes",
                Bucket::B1,
                [3; 12],
                now,
            )
            .unwrap();
        assert_eq!(record.len(), Bucket::B1.group_record());

        let mut bob_pairs = PairCache::default();
        let mut rx = Receiver::new(1);
        let mut ctx = Context {
            roster: &roster,
            epochs: &mut bob_epochs,
            pairs: &mut bob_pairs,
            own: &bob,
        };
        let outcome = rx.receive(&record, Bucket::B1, &mut ctx, now + 5).unwrap();
        assert!(
            matches!(outcome, Outcome::Content { sender: 0, counter: 1, app, .. } if app == b"app bytes")
        );
        assert_eq!(
            rx.receive(&record, Bucket::B1, &mut ctx, now + 6).unwrap(),
            Outcome::Duplicate
        );
        // A corrupt byte fails as one error.
        let mut bad = record.clone();
        bad[40] ^= 1;
        assert_eq!(
            rx.receive(&bad, Bucket::B1, &mut ctx, now + 7),
            Err(Error::Unverified)
        );
        // A gap shows after the timeout.
        let _skip = sender
            .build(
                0,
                &alice,
                &roster,
                &mut alice_epochs,
                &mut alice_pairs,
                b"two",
                Bucket::B1,
                [4; 12],
                now,
            )
            .unwrap();
        let third = sender
            .build(
                0,
                &alice,
                &roster,
                &mut alice_epochs,
                &mut alice_pairs,
                b"three",
                Bucket::B1,
                [5; 12],
                now,
            )
            .unwrap();
        assert!(matches!(
            rx.receive(&third, Bucket::B1, &mut ctx, now + 8).unwrap(),
            Outcome::Content { counter: 3, .. }
        ));
        assert!(!rx.needs_other_replica(now + 8));
        assert!(rx.needs_other_replica(now + 8 + GROUP_GAP_TIMEOUT));
        assert_eq!(rx.last_counter(0, 1), 3);
    }

    #[test]
    fn a_record_ahead_of_the_roster_is_held_and_expires() {
        let group = [7u8; 32];
        let now = 2_000 * GROUP_SLOT;
        let alice = member(1);
        let bob = member(2);
        let carol = member(3);
        let mut alice_roster = Roster::genesis(group, entry_of(&alice, 0, Role::Owner), 0);
        let add_bob = add_control(&alice_roster, &bob, 1);
        alice_roster
            .apply(&GroupControl::parse(&add_bob).unwrap(), 0, 1)
            .unwrap();
        let mut bob_roster = Roster::genesis(group, entry_of(&alice, 0, Role::Owner), 0);
        bob_roster
            .apply(&GroupControl::parse(&add_bob).unwrap(), 0, 1)
            .unwrap();
        // Alice adds Carol; Bob has not read that yet.
        let add_carol = add_control(&alice_roster, &carol, 2);
        alice_roster
            .apply(&GroupControl::parse(&add_carol).unwrap(), 0, 2)
            .unwrap();

        let mut alice_epochs = epochs(&group, 9, now);
        let mut bob_epochs = epochs(&group, 9, now);
        let mut sender = Sender::default();
        let mut alice_pairs = PairCache::default();
        let record = sender
            .build(
                0,
                &alice,
                &alice_roster,
                &mut alice_epochs,
                &mut alice_pairs,
                b"hi",
                Bucket::B1,
                [3; 12],
                now,
            )
            .unwrap();
        let mut bob_pairs = PairCache::default();
        let mut rx = Receiver::new(1);
        let mut ctx = Context {
            roster: &bob_roster,
            epochs: &mut bob_epochs,
            pairs: &mut bob_pairs,
            own: &bob,
        };
        assert_eq!(
            rx.receive(&record, Bucket::B1, &mut ctx, now).unwrap(),
            Outcome::Held
        );
        assert_eq!(rx.held_count(), 1);
        assert!(rx.needs_other_replica(now));
        // The roster arrives, and the held record resolves.
        bob_roster
            .apply(&GroupControl::parse(&add_carol).unwrap(), 0, 3)
            .unwrap();
        let mut ctx = Context {
            roster: &bob_roster,
            epochs: &mut bob_epochs,
            pairs: &mut bob_pairs,
            own: &bob,
        };
        let resolved = rx.retry_held(&mut ctx, now + 1);
        assert_eq!(resolved.len(), 1);
        assert_eq!(rx.held_count(), 0);
        // A held record past the wait is discarded and counted.
        rx.hold(&record, Bucket::B1, now);
        assert_eq!(rx.expire_held(now + GROUP_ROSTER_WAIT), 1);
    }
}
