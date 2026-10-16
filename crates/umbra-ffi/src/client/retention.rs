//! The retention of the history on this device (Part 7 §7.5.2). A message
//! older than the period that the user sets leaves the device, and each
//! device of the set does so on its own. `SYNC_MAX_AGE` is the default, and
//! one day is the least period. A record that a peer synced carries its
//! source and its causal counter, thus the removal moves the watermark of
//! that source (`DEV-015`) and never past a record that the device still
//! holds (`DEV-016`). The watermarks also live in the settings, which the
//! backup carries (`DEV-019`). A tombstone stays (`DEV-014`).
//!
//! A limit of this client: `SYNC_MAX_BYTES` removes nothing yet.

use std::collections::BTreeMap;

use umbra_core::{
    devset::{engine::SyncEngine, DeviceId, SYNC_MAX_AGE},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{conversation_of, info_of, Client};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

/// The source device and the causal counter of each message that a peer
/// synced, by the row of the message.
pub(super) const SYNC_ORIGIN: TableId = TableId(0x4C);
/// The period of the history, in seconds.
const HISTORY_AGE: &[u8] = b"history-age";
/// The watermark of each source, as `source || BE64(counter)` in turn.
const WATERMARKS: &[u8] = b"sync-watermarks";
/// The time of the last sweep, which runs once a day.
const SWEPT_AT: &[u8] = b"history-swept";
/// The least period (Part 7 §7.5.2).
pub const HISTORY_AGE_MIN: u64 = 86_400;
/// A period that removes nothing.
pub const HISTORY_AGE_ALL: u64 = u64::MAX;
const SWEEP_EVERY: u64 = 86_400;

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The period of the history on this device, in seconds.
    pub fn history_age(&self) -> Result<u64, Error> {
        Ok(self
            .setting(HISTORY_AGE)?
            .and_then(|held| held.try_into().ok())
            .map_or(SYNC_MAX_AGE, u64::from_be_bytes))
    }

    /// Sets the period of the history (`DEV-020`). A period below one day
    /// is refused.
    pub fn set_history_age<R: CryptoRng + ?Sized>(
        &mut self,
        seconds: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if seconds < HISTORY_AGE_MIN {
            return Err(Error::Malformed);
        }
        self.remove_setting(SWEPT_AT)?;
        self.put_setting(HISTORY_AGE, &seconds.to_be_bytes(), rng)
    }

    /// The watermark of `source`, for a test.
    #[doc(hidden)]
    pub fn sync_watermark(&self, source: &DeviceId) -> Result<u64, Error> {
        Ok(self
            .sync_engine()?
            .map_or(0, |engine| engine.watermarks().get(source)))
    }

    /// The blinded subject of a conversation in a synced record, for a
    /// test.
    #[doc(hidden)]
    pub fn sync_subject(
        &mut self,
        conversation: ConversationId,
    ) -> Result<Option<[u8; 32]>, Error> {
        self.subject_of(conversation)
    }

    /// Keeps the source and the counter of a message that a peer synced.
    pub(super) fn keep_sync_origin<R: CryptoRng + ?Sized>(
        &mut self,
        message: RowIdRef,
        source: &DeviceId,
        counter: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        if open.store.get(TableId::MESSAGE, &message)?.is_none() {
            return Ok(());
        }
        let value = [source.as_slice(), &counter.to_be_bytes()].concat();
        let mut batch = open.store.begin();
        batch.put(SYNC_ORIGIN, message, None, &value, rng)?;
        Ok(batch.commit()?)
    }

    /// The watermarks that the settings hold, for an engine that the store
    /// did not hold, as after a restore (`DEV-019`).
    pub(super) fn seed_watermarks(&self, engine: &mut SyncEngine) -> Result<(), Error> {
        let Some(held) = self.setting(WATERMARKS)? else {
            return Ok(());
        };
        for entry in held.as_chunks::<24>().0 {
            let (source, counter) = entry.split_at(16);
            let source: DeviceId = source.try_into().map_err(|_| Error::Integrity)?;
            let counter: [u8; 8] = counter.try_into().map_err(|_| Error::Integrity)?;
            engine
                .watermarks_mut()
                .advance(source, u64::from_be_bytes(counter));
        }
        Ok(())
    }

    /// Removes each message older than the period, once a day at most. The
    /// result is the count of messages that left.
    pub fn sweep_history<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<usize, Error> {
        let swept = self
            .setting(SWEPT_AT)?
            .and_then(|held| held.try_into().ok())
            .map(u64::from_be_bytes);
        if swept.is_some_and(|at| now.saturating_sub(at) < SWEEP_EVERY) {
            return Ok(0);
        }
        self.put_setting(SWEPT_AT, &now.to_be_bytes(), rng)?;
        let age = self.history_age()?;
        if age == HISTORY_AGE_ALL {
            return Ok(0);
        }
        let cutoff_ms = now.saturating_sub(age).saturating_mul(1_000);
        let mut due: Vec<(ConversationId, MsgRef)> = Vec::new();
        for (row, plain) in self.open_ref()?.store.list(TableId::MESSAGE, None)? {
            let plain = Zeroizing::new(plain);
            let info = info_of(&plain)?;
            // A message that waits for its send stays.
            if info.outgoing && info.delivery == Delivery::Queued {
                continue;
            }
            if info.stored_at_ms < cutoff_ms {
                due.push((conversation_of(&plain)?, MsgRef(row)));
            }
        }
        if due.is_empty() {
            return Ok(0);
        }
        // DEV-015: the removal of a synced record moves the watermark of
        // its source.
        let mut pruned: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for (conversation, message) in &due {
            if let Some(origin) = self.open_ref()?.store.get(SYNC_ORIGIN, &message.0)? {
                if let Some((source, counter)) = origin_of(&origin) {
                    let top = pruned.entry(source).or_insert(0);
                    *top = (*top).max(counter);
                }
            }
            // A fault of one message keeps it for the next sweep, and it
            // stops no other removal. ATT-161: the end of the period is no
            // deletion, thus no chunk of a file leaves its relay here.
            if self.remove_aged(message).is_err() {
                continue;
            }
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            batch.delete(SYNC_ORIGIN, message.0);
            batch.commit()?;
            self.events.push_back(Event::Deleted {
                conversation: *conversation,
                message: *message,
            });
        }
        let messages: Vec<MsgRef> = due.iter().map(|(_, message)| *message).collect();
        self.drop_sync_sent_of(&messages)?;
        self.advance_watermarks(pruned, rng)?;
        Ok(due.len())
    }

    /// Moves the watermark of each source to the highest removed counter,
    /// and below the lowest counter that this device still holds
    /// (`DEV-016`).
    fn advance_watermarks<R: CryptoRng + ?Sized>(
        &mut self,
        pruned: BTreeMap<DeviceId, u64>,
        rng: &mut R,
    ) -> Result<(), Error> {
        if pruned.is_empty() {
            return Ok(());
        }
        let mut lowest_held: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for (_, origin) in self.open_ref()?.store.list(SYNC_ORIGIN, None)? {
            if let Some((source, counter)) = origin_of(&origin) {
                let low = lowest_held.entry(source).or_insert(u64::MAX);
                *low = (*low).min(counter);
            }
        }
        let Some(mut engine) = self.sync_engine()? else {
            return Ok(());
        };
        for (source, top) in pruned {
            let below = lowest_held
                .get(&source)
                .map_or(top, |low| top.min(low.saturating_sub(1)));
            engine.watermarks_mut().advance(source, below);
        }
        let mut copy = Vec::new();
        for source in engine.peers().copied().collect::<Vec<_>>() {
            let mark = engine.watermarks().get(&source);
            if mark > 0 {
                copy.extend_from_slice(&source);
                copy.extend_from_slice(&mark.to_be_bytes());
            }
        }
        self.put_engine(&engine, None, rng)?;
        self.put_setting(WATERMARKS, &copy, rng)
    }
}

/// The key of a message row, for [`Client::keep_sync_origin`].
pub(super) type RowIdRef = umbra_core::store::record::RowId;

fn origin_of(value: &[u8]) -> Option<(DeviceId, u64)> {
    let source: DeviceId = value.get(..16)?.try_into().ok()?;
    let counter: [u8; 8] = value.get(16..24)?.try_into().ok()?;
    Some((source, u64::from_be_bytes(counter)))
}
