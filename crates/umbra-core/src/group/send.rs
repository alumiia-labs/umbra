//! The sending side of a group record (Part 11 §11.3.3, §11.3.4, §11.9.7):
//! the pair-key cache, the counter of each epoch, the dense tag vector of a
//! content record, and the sparse vector of a presence record.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::group::{
    pair::{app_hash, PairKey, RecordTag},
    MemberKeys, TAG_LEN,
};
use umbra_wire::{
    app::{AppKind, AppMessage},
    bucket::Bucket,
    group::{
        control::{ControlType, GroupControl, Role},
        record::{seal_content, ContentPlain, Tags},
    },
};

/// The one version of a `GroupPresence` (Part 6 §6.6.3, `WIR-492`).
pub const PRESENCE_VERSION: u8 = 0x01;

use umbra_crypto::stored::{Reader, Writer};

use super::{
    epoch::EpochStore,
    roster::{count, Roster, STORED_VERSION},
    slot_of,
};
use crate::Error;

/// The cached `K_ij` of each member (§11.3.3).
#[derive(Default)]
pub struct PairCache {
    keys: BTreeMap<u16, PairKey>,
}

impl PairCache {
    /// The pair key with the active member at `index`, derived at the first
    /// use (`GRP-236`). The cache holds no key of a member that left
    /// (`GRP-245`), thus an index outside the active set gives none.
    pub fn get(
        &mut self,
        index: u16,
        roster: &Roster,
        own: &MemberKeys,
    ) -> Result<&PairKey, Error> {
        if let alloc::collections::btree_map::Entry::Vacant(slot) = self.keys.entry(index) {
            let peer = roster
                .member(index)
                .filter(|member| member.active)
                .ok_or(Error::NoPath)?;
            slot.insert(own.pair_key(&peer.pair_pk, roster.group_id())?);
        }
        self.keys.get(&index).ok_or(Error::NoPath)
    }

    /// Drops the key of a removed member (`GRP-245`).
    pub fn remove(&mut self, index: u16) {
        self.keys.remove(&index);
    }
}

/// The slot of a record that goes out at `now` (`GRP-246`): the slot of the
/// clock, and `t_e` while the clock lies below it. A rotator whose clock
/// runs ahead inside `GROUP_SLOT_SKEW` starts an epoch whose chain holds no
/// key of an earlier slot. Each receiver takes a slot of that skew
/// (`GRP-228`).
pub fn send_slot(epochs: &EpochStore, now: u64) -> u32 {
    let slot = slot_of(now);
    epochs
        .current()
        .map_or(slot, |current| slot.max(current.start_slot()))
}

/// The counters of the sending device, one for each epoch (`GRP-246`,
/// `GRP-339`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sender {
    counters: BTreeMap<u32, u32>,
}

impl Sender {
    /// The last counter sent in `epoch`.
    pub fn counter(&self, epoch: u32) -> u32 {
        self.counters.get(&epoch).copied().unwrap_or(0)
    }

    /// Continues from a synced counter at an ownership change (`GRP-342`).
    pub fn set_counter(&mut self, epoch: u32, value: u32) {
        let slot = self.counters.entry(epoch).or_insert(0);
        if value > *slot {
            *slot = value;
        }
    }

    /// Writes the counters to their stored form.
    pub fn export(&self, w: &mut Writer) -> Result<(), Error> {
        w.u8(STORED_VERSION);
        w.u32(count(self.counters.len())?);
        for (epoch, counter) in &self.counters {
            w.u32(*epoch);
            w.u32(*counter);
        }
        Ok(())
    }

    /// Reads the counters that [`Sender::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.u8()? != STORED_VERSION {
            return Err(Error::Stale);
        }
        let mut counters = BTreeMap::new();
        for _ in 0..r.u32()? {
            counters.insert(r.u32()?, r.u32()?);
        }
        Ok(Sender { counters })
    }

    fn next_counter(&mut self, epoch: u32) -> Result<u32, Error> {
        let slot = self.counters.entry(epoch).or_insert(0);
        *slot = slot.checked_add(1).ok_or(Error::NoPath)?;
        Ok(*slot)
    }

    /// Builds and seals a content record for `app` at `now`
    /// (`GRP-238`, `GRP-239`, `GRP-246`). `nonce` comes from the device
    /// CSPRNG.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &mut self,
        own_index: u16,
        own: &MemberKeys,
        roster: &Roster,
        epochs: &mut EpochStore,
        pairs: &mut PairCache,
        app: &[u8],
        bucket: Bucket,
        nonce: [u8; 12],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let roster_epoch = roster.epoch_index();
        self.build_at(
            own_index,
            own,
            roster,
            epochs,
            pairs,
            app,
            bucket,
            nonce,
            now,
            roster_epoch,
        )
    }

    /// As [`Sender::build`], under an earlier `roster_epoch` that the
    /// roster history holds: the tags go to the members active at it. A
    /// member behind the roster checks such a record under the epoch it
    /// holds (`GRP-330`). A member whose pair key this roster lost since
    /// takes a tag of zeros. A member whose `pair_pk` gives no pair key
    /// takes one too (`GRP-237`). One entry that fails stops no record to
    /// each other member.
    #[allow(clippy::too_many_arguments)]
    pub fn build_at(
        &mut self,
        own_index: u16,
        own: &MemberKeys,
        roster: &Roster,
        epochs: &mut EpochStore,
        pairs: &mut PairCache,
        app: &[u8],
        bucket: Bucket,
        nonce: [u8; 12],
        now: u64,
        roster_epoch: u32,
    ) -> Result<Vec<u8>, Error> {
        let epoch = epochs.epoch();
        if epoch == 0 {
            return Err(Error::NoPath);
        }
        let slot = send_slot(epochs, now);
        let record_key = &epochs.send_key(slot, now)?;
        let active = roster
            .active_at(roster_epoch)
            .ok_or(Error::NoPath)?
            .to_vec();
        let counter = self.next_counter(epoch)?;
        let hash = app_hash(app);
        let mut tags = Vec::with_capacity(active.len().saturating_mul(TAG_LEN));
        for index in &active {
            if *index == own_index {
                tags.extend_from_slice(&[0u8; TAG_LEN]);
                continue;
            }
            let Ok(key) = pairs.get(*index, roster, own) else {
                tags.extend_from_slice(&[0u8; TAG_LEN]);
                continue;
            };
            tags.extend_from_slice(&key.record_tag(&RecordTag {
                group_id: roster.group_id(),
                epoch,
                slot,
                sender_index: own_index,
                counter,
                roster_epoch,
                app_hash: &hash,
            }));
        }
        let plain = ContentPlain {
            sender_index: own_index,
            counter,
            roster_epoch,
            tags: Tags::Dense(&tags),
            app,
        };
        let mut out = alloc::vec![0u8; bucket.group_record()];
        let n = seal_content(
            &plain,
            record_key,
            nonce,
            roster.group_id(),
            epoch,
            slot,
            bucket,
            &mut out,
        )?;
        out.truncate(n);
        Ok(out)
    }

    /// Builds and seals a `GroupPresence` record, tagged for each member
    /// at `admin` or above and no other (`GRP-128`, `GRP-321`). It carries
    /// the counter of the last record of this device in the epoch and takes
    /// no step of it, because only an admin reads it (`GRP-395`).
    #[allow(clippy::too_many_arguments)]
    pub fn build_presence(
        &mut self,
        own_index: u16,
        own: &MemberKeys,
        roster: &Roster,
        epochs: &mut EpochStore,
        pairs: &mut PairCache,
        nonce: [u8; 12],
        msg_id: [u8; 16],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let epoch = epochs.epoch();
        let slot = send_slot(epochs, now);
        let record_key = &epochs.send_key(slot, now)?;
        let roster_epoch = roster.epoch_index();
        let counter = self.counter(epoch);
        let version = [PRESENCE_VERSION];
        let control = GroupControl {
            control_type: ControlType::Presence,
            payload: &version,
        };
        let mut body = [0u8; 8];
        let body_len = control.encode(&mut body)?;
        let message = AppMessage {
            kind: AppKind::GroupControl,
            msg_id,
            sent_at: now.saturating_mul(1_000),
            body: body.get(..body_len).ok_or(Error::Malformed)?,
        };
        let mut app = alloc::vec![0u8; message.len()];
        let app_len = message.encode(&mut app)?;
        app.truncate(app_len);
        let app = app.as_slice();
        let hash = app_hash(app);
        let targets: Vec<u16> = roster
            .active()
            .filter(|m| m.role >= Role::Admin && m.index != own_index)
            .map(|m| m.index)
            .collect();
        let mut entries = Vec::with_capacity(targets.len());
        for index in targets {
            // GRP-237: an admin whose key gives no pair key takes no entry.
            let Ok(key) = pairs.get(index, roster, own) else {
                continue;
            };
            entries.push((
                index,
                key.record_tag(&RecordTag {
                    group_id: roster.group_id(),
                    epoch,
                    slot,
                    sender_index: own_index,
                    counter,
                    roster_epoch,
                    app_hash: &hash,
                }),
            ));
        }
        let plain = ContentPlain {
            sender_index: own_index,
            counter,
            roster_epoch,
            tags: Tags::Sparse(entries),
            app,
        };
        let mut out = alloc::vec![0u8; Bucket::B0.group_record()];
        let n = seal_content(
            &plain,
            record_key,
            nonce,
            roster.group_id(),
            epoch,
            slot,
            Bucket::B0,
            &mut out,
        )?;
        out.truncate(n);
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::group::{
        roster::tests::{add_control, entry_of, plain_control},
        test_util::member,
    };
    use umbra_wire::group::control::PlainOp;

    #[test]
    fn the_cache_derives_no_key_of_a_member_that_left() {
        let creator = member(1);
        let mut roster = Roster::genesis([7; 32], entry_of(&creator, 0, Role::Owner), 0);
        let add = add_control(&roster, &member(2), 1);
        roster
            .apply(&GroupControl::parse(&add).unwrap(), 0, 1)
            .unwrap();
        let mut pairs = PairCache::default();
        assert!(pairs.get(1, &roster, &creator).is_ok());
        let remove = plain_control(&roster, PlainOp::Remove { index: 1 });
        roster
            .apply(&GroupControl::parse(&remove).unwrap(), 0, 2)
            .unwrap();
        pairs.remove(1);
        // GRP-245: a record under the roster epoch before the removal gives
        // that member a tag of zeros, and the cache stays without its key.
        assert_eq!(pairs.get(1, &roster, &creator).err(), Some(Error::NoPath));
        assert!(pairs.keys.is_empty());
    }
}
