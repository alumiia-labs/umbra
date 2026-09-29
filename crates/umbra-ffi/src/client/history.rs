//! The holes in the history that the other devices of the set sync (Part 7
//! §7.5.5 rules 6 and 7). A hole is the first range of the causal counter of
//! a source device that this device does not hold while it holds a later
//! one. While the source can still send it again, the history is arriving
//! (`DEV-076`). After `SYNC_MAX_AGE`, or once the source left the set, no
//! device holds the range, and the hole is a history gap that the view
//! shows and does not hide (`DEV-077` to `DEV-079`).

use umbra_core::{
    devset::{engine::SyncEngine, link::label_text, roster::Roster, DeviceId, SYNC_MAX_AGE},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;

use super::Client;
use crate::Error;

/// Each hole of a source device, by the device: the device, the first and
/// the last counter, the time that this device first saw it, and the label.
const SYNC_HOLES: TableId = TableId(0x48);

const HOLE_LEN: usize = 16 + 8 + 8 + 8 + 32;

/// A hole in the synced history, as the view shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryHole {
    /// The label of the source device.
    pub label: String,
    /// How many records of the source the range holds.
    pub count: u64,
    /// The source can still send the range again (`DEV-076`). Else the
    /// hole is a history gap (`DEV-077`).
    pub is_arriving: bool,
}

fn u64_at(value: &[u8], at: usize) -> Result<u64, Error> {
    value
        .get(at..at.saturating_add(8))
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(Error::Integrity)
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Keeps the hole of each source of `engine` at `now`: a new range takes
    /// the time of its first sight, and a range that closed leaves. The row
    /// of a source that left the set stays, since no device fills it.
    pub(super) fn keep_history_holes<R: CryptoRng + ?Sized>(
        &mut self,
        engine: &SyncEngine,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let roster = self.roster_bytes()?;
        let roster = roster.as_deref().map(Roster::parse).transpose()?;
        let peers: Vec<DeviceId> = engine.peers().copied().collect();
        let mut writes = Vec::new();
        let store = &self.open_ref()?.store;
        for peer in peers {
            let row = store.row_id(SYNC_HOLES, &peer);
            let held = store.get(SYNC_HOLES, &row)?;
            let Some((from, to)) = engine.missing(&peer) else {
                if held.is_some() {
                    writes.push((row, None));
                }
                continue;
            };
            let since = match held {
                Some(value) if u64_at(&value, 16)? == from => u64_at(&value, 32)?,
                _ => now,
            };
            let label = roster
                .as_ref()
                .and_then(|roster| roster.entry(&peer).map(|entry| entry.label))
                .unwrap_or([0; 32]);
            let value = [
                peer.as_slice(),
                &from.to_be_bytes(),
                &to.to_be_bytes(),
                &since.to_be_bytes(),
                &label,
            ]
            .concat();
            writes.push((row, Some(value)));
        }
        if writes.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for (row, value) in writes {
            match value {
                Some(value) => batch.put(SYNC_HOLES, row, None, &value, rng)?,
                None => batch.delete(SYNC_HOLES, row),
            }
        }
        Ok(batch.commit()?)
    }

    /// Each hole in the synced history at `now`. A source that left the set
    /// sends nothing again, thus its hole is a gap.
    pub fn history_holes(&self, now: u64) -> Result<Vec<HistoryHole>, Error> {
        let peers: Vec<DeviceId> = match self.sync_engine()? {
            Some(engine) => engine.peers().copied().collect(),
            None => Vec::new(),
        };
        let mut out = Vec::new();
        for (_, value) in self.open_ref()?.store.list(SYNC_HOLES, None)? {
            if value.len() != HOLE_LEN {
                return Err(Error::Integrity);
            }
            let device: DeviceId = value
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Integrity)?;
            let from = u64_at(&value, 16)?;
            let to = u64_at(&value, 24)?;
            let since = u64_at(&value, 32)?;
            let label: [u8; 32] = value
                .get(40..)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Integrity)?;
            out.push(HistoryHole {
                label: label_text(&label),
                count: to.saturating_sub(from).saturating_add(1),
                is_arriving: peers.contains(&device) && now.saturating_sub(since) < SYNC_MAX_AGE,
            });
        }
        Ok(out)
    }
}
