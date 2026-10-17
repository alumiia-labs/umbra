//! The receiving side of a group record (Part 11 §11.3.5, §11.2.2): the
//! epoch and the slot window, the open under each candidate key, the
//! roster epoch the record names, the tag at the receiver's own position,
//! the counter of each sender with its gap, and the records held for a
//! roster that has not arrived.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_crypto::group::{
    pair::{app_hash, RecordTag},
    MemberKeys,
};
use umbra_wire::{
    app::{AppKind, AppMessage, Channel},
    bucket::Bucket,
    group::{
        control::{ControlType, GroupControl, Role},
        record::{open_content, ContentPlain, GroupQueueRecord, RecordKind, Tags},
    },
};

use umbra_crypto::stored::{Reader, Writer};

use super::{
    epoch::EpochStore,
    roster::{count, Roster, STORED_VERSION},
    send::PairCache,
    GROUP_GAP_TIMEOUT, GROUP_ROSTER_WAIT,
};
use crate::Error;

/// The records that a receiver holds at most, for a roster or for a key.
const HELD_MAX: usize = 512;

/// The bytes of the records that a receiver holds at most. A receiver holds
/// a record before any tag check, thus a writer of the queue chooses its
/// bucket.
const HELD_BYTES_MAX: usize = 4 * 1_024 * 1_024;

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
        /// The slot of the record header, on which the rates of the roster
        /// chain count (`GRP-076`).
        slot: u32,
        /// The `AppMessage` bytes.
        app: Vec<u8>,
        /// Whether the record came under the previous epoch.
        previous_epoch: bool,
        /// Whether the counter is one that this receiver took already from
        /// that sender in that epoch. The record is a copy, or a second
        /// record of a device race (`GRP-342`), and the triple of `GRP-035`
        /// tells the two apart (`GRP-206`).
        repeated: bool,
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
    /// A `GroupPresence` that verified at this admin (`GRP-217`). It is
    /// a signal of activity alone, and it moves no counter (`GRP-395`).
    Presence {
        /// The member the tag names.
        sender: u16,
    },
    /// The record names a roster epoch ahead of the local roster, and it
    /// waits (`GRP-252`).
    Held,
    /// The slot is outside the window, and the record waits for a clock
    /// check (`GRP-229`).
    ClockSuspect,
    /// A request or a supply of a key under a counter that this receiver
    /// took already (`GRP-259`). Such a record enters no store, thus its
    /// copy goes here.
    Duplicate,
    /// An epoch whose slot opened earlier installed now, after the roster
    /// object or the hour that it waited for (`GRP-357`).
    EpochInstalled {
        /// The epoch that it started.
        epoch: u32,
    },
}

struct HeldRecord {
    bytes: Vec<u8>,
    bucket: Bucket,
    arrived_at: u64,
    /// Whether the record opened under a key of this member and waits for
    /// a roster epoch (`GRP-252`). A record that no key opened yet goes
    /// first at the bound.
    opened: bool,
}

/// Whether an `AppMessage` carries a `GroupPresence` of the one version
/// (`WIR-492`).
fn is_presence(app: &[u8]) -> bool {
    let Ok(message) = AppMessage::parse(app, Channel::Group) else {
        return false;
    };
    if message.kind != AppKind::GroupControl {
        return false;
    }

    GroupControl::parse(message.body).is_ok_and(|control| {
        control.control_type == ControlType::Presence
            && control.payload == [crate::group::send::PRESENCE_VERSION]
    })
}

/// Whether an `AppMessage` carries a `RekeyRecord` (§11.12).
fn is_rekey(app: &[u8]) -> bool {
    let Ok(message) = AppMessage::parse(app, Channel::Group) else {
        return false;
    };

    message.kind == AppKind::GroupControl
        && GroupControl::parse(message.body)
            .is_ok_and(|control| control.control_type == ControlType::Rekey)
}

/// Whether an `AppMessage` carries an object of the roster chain
/// (§11.9.2, §11.9.6, §11.12).
fn is_roster_object(app: &[u8]) -> bool {
    let Ok(message) = AppMessage::parse(app, Channel::Group) else {
        return false;
    };

    message.kind == AppKind::GroupControl
        && GroupControl::parse(message.body).is_ok_and(|control| {
            matches!(
                control.control_type,
                ControlType::PlainEpoch
                    | ControlType::GrantingEpoch
                    | ControlType::ModerationEpoch
                    | ControlType::Rekey
            )
        })
}

/// Whether an observer may post an `AppMessage` (§11.9): a roster object, a
/// request or a supply of a key, and the deletion of its own message.
fn observer_may_post(app: &[u8]) -> bool {
    AppMessage::parse(app, Channel::Group).is_ok_and(|message| {
        matches!(
            message.kind,
            AppKind::GroupControl | AppKind::KeyRequest | AppKind::KeySupply | AppKind::Delete
        )
    })
}

/// Whether an `AppMessage` is a request or a supply of a key (§11.4.3).
fn is_key_exchange(app: &[u8]) -> bool {
    AppMessage::parse(app, Channel::Group)
        .is_ok_and(|message| matches!(message.kind, AppKind::KeyRequest | AppKind::KeySupply))
}

/// The receiver state of one member in one group.
pub struct Receiver {
    own_index: u16,
    counters: BTreeMap<(u16, u32), u32>,
    held: Vec<HeldRecord>,
    gaps: BTreeMap<u16, u64>,
    /// The counters below the highest one of a sender and an epoch that no
    /// record filled yet: a record that fills one is a reorder, and it
    /// shows (`GRP-259`, `GRP-205`).
    holes: BTreeSet<(u16, u32, u32)>,
    /// The held records that left at the bound since the last count, which
    /// the client shows as a gap (`GRP-254`).
    evicted: usize,
}

/// The stored form of a receiver with its holes; the form before them is
/// `STORED_VERSION`, which a read still takes.
const RECEIVER_VERSION: u8 = 0x02;

/// The holes that one sender keeps in one epoch. A gap above it leaves its
/// oldest holes, whose records then count as repeats, and the gap shows.
const HOLES_MAX: usize = 256;

/// `HOLES_MAX` as a counter distance.
const HOLES_MAX_COUNTER: u32 = 256;

impl Receiver {
    /// The index whose tags this receiver checks.
    pub const fn own_index(&self) -> u16 {
        self.own_index
    }

    /// The member moved to a new index at a re-key (Part 11 §11.12).
    pub fn set_own_index(&mut self, own_index: u16) {
        self.own_index = own_index;
    }

    /// A receiver at `own_index`.
    pub const fn new(own_index: u16) -> Self {
        Receiver {
            own_index,
            counters: BTreeMap::new(),
            held: Vec::new(),
            gaps: BTreeMap::new(),
            holes: BTreeSet::new(),
            evicted: 0,
        }
    }

    /// Writes the receiver to its stored form. The held records travel
    /// with it, because a roster that has not arrived outlives a run.
    pub fn export(&self, w: &mut Writer) -> Result<(), Error> {
        w.u8(RECEIVER_VERSION);
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

        w.u32(count(self.holes.len())?);
        for (sender, epoch, counter) in &self.holes {
            w.u16(*sender);
            w.u32(*epoch);
            w.u32(*counter);
        }

        Ok(())
    }

    /// Reads a receiver that [`Receiver::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        let version = r.u8()?;
        if version != STORED_VERSION && version != RECEIVER_VERSION {
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
                opened: false,
            });
        }

        let mut gaps = BTreeMap::new();
        for _ in 0..r.u32()? {
            gaps.insert(r.u16()?, r.u64()?);
        }

        let mut holes = BTreeSet::new();
        if version == RECEIVER_VERSION {
            for _ in 0..r.u32()? {
                holes.insert((r.u16()?, r.u32()?, r.u32()?));
            }
        }

        Ok(Receiver {
            own_index,
            counters,
            held,
            gaps,
            holes,
            evicted: 0,
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
                self.hold(bytes, bucket, now, false);
                return Ok(Outcome::ClockSuspect);
            }
            Err(e) => return Err(e),
        };

        let mut opened: Option<(Vec<u8>, bool, bool)> = None;
        for key in &keys {
            let mut out = alloc::vec![0u8; bucket.group_record()];
            if let Ok(n) = open_content(&record, &key.key, ctx.roster.group_id(), &mut out) {
                out.truncate(n);
                opened = Some((out, key.previous, key.alternate));
                break;
            }
        }

        // One error covers the open, the tag, and the parse (GRP-251).
        let (plain_bytes, previous_epoch, under_alternate) = opened.ok_or(Error::Unverified)?;
        let roster_epoch = Self::roster_epoch_of(&plain_bytes)?;

        if roster_epoch > ctx.roster.epoch_index() {
            self.hold(bytes, bucket, now, true);
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
        let rekey = is_rekey(plain.app);

        if sender == self.own_index {
            // GRP-369: a re-key under the index of this member that another
            // holder of its keys made. A record holds no tag for its own
            // sender, and the signature under the old roster key names the
            // maker, which the roster checks. Each other record of this
            // index is an echo.
            if !rekey {
                return Err(Error::Unverified);
            }
            return Ok(Outcome::Content {
                sender,
                counter: plain.counter,
                roster_epoch,
                epoch: record.epoch,
                slot: record.slot,
                app: plain.app.to_vec(),
                previous_epoch,
                repeated: false,
            });
        }

        // The sender must be in the current roster (GRP-257, GRP-232). A
        // rival of the re-key at the head of the chain comes from the index
        // that re-key excluded, at the roster epoch before it (GRP-369).
        let before_head = roster_epoch.saturating_add(1) == roster.epoch_index();
        let is_rival = rekey
            && roster
                .head_rekey()
                .is_some_and(|head| head.old_index == sender)
            && before_head;

        // GRP-070: a second roster object from the maker of the head, at
        // the roster epoch before it. A head that removed its maker, by a
        // self-removal or a re-key, would drop it here. One order of
        // arrival would then show the fork and the other would not. The
        // roster takes it and orders the two.
        let is_second =
            before_head && roster.head_maker() == Some(sender) && is_roster_object(plain.app);
        let is_active = roster.member(sender).is_some_and(|m| m.active);
        if !is_active && !is_rival && !is_second {
            return Err(Error::Unverified);
        }

        let rank = roster
            .rank_at(roster_epoch, self.own_index)
            .ok_or(Error::Unverified)?;
        let tag = plain
            .tags
            .tag_for(rank, self.own_index)
            .ok_or(Error::Unverified)?;

        // GRP-245: the pair key of an index that left the active set stays
        // out of the cache, and this one check derives it.
        let derived;
        let key = if is_active {
            ctx.pairs.get(sender, roster, ctx.own)?
        } else {
            let peer = roster.member(sender).ok_or(Error::Unverified)?;
            derived = ctx.own.pair_key(&peer.pair_pk, roster.group_id())?;
            &derived
        };

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

        // GRP-217: a sparse record is a presence record or nothing, and
        // GRP-395 keeps it out of the counter of its sender.
        if matches!(plain.tags, Tags::Sparse(_)) {
            if !is_presence(plain.app) {
                return Err(Error::Unverified);
            }
            return Ok(Outcome::Presence { sender });
        }

        // An observer reads the group and posts nothing to it. Its roster
        // objects, its key exchange, and the deletion of its own earlier
        // messages still apply (§11.9).
        let is_observer = roster
            .member(sender)
            .is_some_and(|member| member.role == Role::Observer);
        if is_observer && !observer_may_post(plain.app) {
            return Err(Error::Unverified);
        }

        // GRP-273: a member other than its supplier writes under the
        // supplied secret, thus the group holds that secret.
        if under_alternate && !previous_epoch {
            ctx.epochs.confirm_alternate(sender);
        }

        let epoch = record.epoch;
        let mut repeated = false;
        let last = self.counters.entry((sender, epoch)).or_insert(0);
        if plain.counter > *last {
            // GRP-259: each counter between the last and this one is a
            // hole, which a record of the other replica can fill.
            // A jump keeps the newest HOLES_MAX holes alone, thus a counter
            // far above the last one costs no more.
            let from = last
                .saturating_add(1)
                .max(plain.counter.saturating_sub(HOLES_MAX_COUNTER));
            *last = plain.counter;
            for missing in from..plain.counter {
                self.holes.insert((sender, epoch, missing));
            }

            // The holes of an epoch before the previous one name records
            // that no key opens any more (GRP-250).
            let floor = epoch.saturating_sub(1);
            self.holes.retain(|(_, held, _)| *held >= floor);

            let mut of_sender: Vec<(u16, u32, u32)> = self
                .holes
                .range((sender, epoch, 0)..=(sender, epoch, u32::MAX))
                .copied()
                .collect();
            if of_sender.len() > HOLES_MAX {
                let excess = of_sender.len() - HOLES_MAX;
                for old in of_sender.drain(..excess) {
                    self.holes.remove(&old);
                }
            }
        } else if self.holes.remove(&(sender, epoch, plain.counter)) {
            // A reorder or a record that the other replica held: it fills
            // its hole, and it shows (GRP-205).
        } else {
            // GRP-206, GRP-259: the counter gives the order and the gaps,
            // and it identifies no record. Two devices of one member can
            // give two records one counter (GRP-342), and a jump above
            // `HOLES_MAX` keeps no hole for the records below it. The store
            // drops a copy by the triple of GRP-035. A request or a supply
            // of a key enters no store, thus its copy goes here.
            if is_key_exchange(plain.app) {
                return Ok(Outcome::Duplicate);
            }
            repeated = true;
        }

        let has_hole = self
            .holes
            .range((sender, 0, 0)..=(sender, u32::MAX, u32::MAX))
            .next()
            .is_some();
        if has_hole {
            self.gaps.entry(sender).or_insert(now);
        } else {
            self.gaps.remove(&sender);
        }

        // GRP-369: two holders of the keys of one index each count on their
        // own, thus a rival re-key can come under a counter that the other
        // one passed. The roster knows a re-key again by its hash.
        Ok(Outcome::Content {
            sender,
            counter: plain.counter,
            roster_epoch,
            epoch: record.epoch,
            slot: record.slot,
            app: plain.app.to_vec(),
            previous_epoch,
            repeated,
        })
    }

    fn hold(&mut self, bytes: &[u8], bucket: Bucket, now: u64, opened: bool) {
        self.held.push(HeldRecord {
            bytes: bytes.to_vec(),
            bucket,
            arrived_at: now,
            opened,
        });

        // A receiver holds a record before any tag check, thus a writer of
        // the queue could fill the list. At the bound of the count or of
        // the bytes, the oldest record that no key opened leaves. After
        // those, the oldest record leaves. Each one counts for the gap of
        // GRP-254.
        loop {
            let held_bytes: usize = self.held.iter().map(|held| held.bytes.len()).sum();
            if self.held.len() <= HELD_MAX && held_bytes <= HELD_BYTES_MAX {
                break;
            }

            let last = self.held.len().saturating_sub(1);
            let gone = self
                .held
                .iter()
                .take(last)
                .position(|held| !held.opened)
                .unwrap_or(0);
            self.held.remove(gone);
            self.evicted = self.evicted.saturating_add(1);
        }
    }

    /// Whether a held content record names `epoch`: the sign that the
    /// epoch exists at a writer of the queue (§11.4.3).
    pub fn holds_epoch_record(&self, epoch: u32) -> bool {
        self.held.iter().any(|held| {
            GroupQueueRecord::parse(&held.bytes, held.bucket)
                .is_ok_and(|record| record.kind != RecordKind::EpochKey && record.epoch == epoch)
        })
    }

    /// The records held.
    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// The epoch and the slot of each content record held.
    pub fn held_slots(&self) -> Vec<(u32, u32)> {
        self.held
            .iter()
            .filter_map(|held| GroupQueueRecord::parse(&held.bytes, held.bucket).ok())
            .filter(|record| record.kind != RecordKind::EpochKey)
            .map(|record| (record.epoch, record.slot))
            .collect()
    }

    /// The newest group epoch among the records held, which names an
    /// epoch this member may lack (§11.4.3).
    pub fn newest_held_epoch(&self) -> Option<u32> {
        self.held
            .iter()
            .filter_map(|held| GroupQueueRecord::parse(&held.bytes, held.bucket).ok())
            .map(|record| record.epoch)
            .max()
    }

    /// Takes the held records, for a caller that tries each one again: a
    /// record that waits again is held again by the receive, and
    /// [`Receiver::keep_arrival`] gives it its first arrival back.
    pub(crate) fn take_held(&mut self) -> Vec<(Vec<u8>, Bucket, u64)> {
        core::mem::take(&mut self.held)
            .into_iter()
            .map(|held| (held.bytes, held.bucket, held.arrived_at))
            .collect()
    }

    /// The records that left the list at its bound since the last call.
    pub(crate) fn take_evicted(&mut self) -> usize {
        core::mem::take(&mut self.evicted)
    }

    /// Gives the record held last its first arrival.
    pub(crate) fn keep_arrival(&mut self, arrived_at: u64) {
        if let Some(last) = self.held.last_mut() {
            last.arrived_at = arrived_at;
        }
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

    /// Discards each held record past `GROUP_ROSTER_WAIT` that waits for a
    /// roster epoch, and returns the count, which the client shows as a gap
    /// (`GRP-253`, `GRP-254`). A record of the epoch after `current_epoch`
    /// waits for its key and not for a roster, and it stays up to
    /// `GROUP_RETENTION` (Part 11 §11.4.3).
    pub fn expire_held(&mut self, now: u64, current_epoch: u32) -> usize {
        let before = self.held.len();
        self.held.retain(|h| {
            // A record of the next epoch waits for its key up to the
            // retention of the queue; each other record waits for a roster.
            let waits_for_key = GroupQueueRecord::parse(&h.bytes, h.bucket)
                .is_ok_and(|record| record.epoch == current_epoch.saturating_add(1));
            let wait = if waits_for_key {
                umbra_queue::params::GROUP_RETENTION
            } else {
                GROUP_ROSTER_WAIT
            };
            now.saturating_sub(h.arrived_at) < wait
        });

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
        self.holes.retain(|(s, _, _)| *s != sender);
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
            matches!(outcome, Outcome::Content { sender: 0, counter: 1, repeated: false, app, .. } if app == b"app bytes")
        );

        // GRP-206: the counter identifies no record, thus a copy comes
        // back with its mark, and the store drops it by its `msg_id`.
        assert!(matches!(
            rx.receive(&record, Bucket::B1, &mut ctx, now + 6).unwrap(),
            Outcome::Content {
                counter: 1,
                repeated: true,
                ..
            }
        ));

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
        rx.hold(&record, Bucket::B1, now, true);
        assert_eq!(
            rx.expire_held(now + GROUP_ROSTER_WAIT, bob_epochs.epoch()),
            1
        );

        // At the bound a record that no key opened leaves before one that
        // waits for its roster, and each one that leaves counts (GRP-254).
        rx.hold(&record, Bucket::B1, now, true);
        for _ in 0..HELD_MAX {
            rx.hold(&record, Bucket::B1, now, false);
        }
        assert_eq!(rx.held_count(), HELD_MAX);
        assert!(rx.held[0].opened);
        assert_eq!(rx.take_evicted(), 1);
        assert_eq!(rx.take_evicted(), 0);

        // The bytes have a bound too: a record of `B3` is 32 KiB.
        let large = alloc::vec![0u8; Bucket::B3.group_record()];
        for _ in 0..HELD_MAX {
            rx.hold(&large, Bucket::B3, now, false);
        }
        let held: usize = rx.held.iter().map(|held| held.bytes.len()).sum();
        assert!(held <= HELD_BYTES_MAX);
        assert!(rx.held[0].opened);
        assert!(rx.take_evicted() > 0);
    }
}
