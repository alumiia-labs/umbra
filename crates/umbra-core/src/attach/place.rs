//! The placement list of a handle-addressed chunk (Part 13 §13.4.2), the
//! resolution of a relay hint (§13.3.2), and the order of a fetch across
//! the replicas (§13.4, §13.11).

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::{hash::sha3_256, labels};

use super::{seal, BACKUP_REPLICAS, FETCH_RETRY_HOLD, PLACE_PROBE};
use crate::Error;

/// A relay of the current consensus that declares the attachment role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentRelay {
    /// The relay.
    pub relay_id: [u8; 32],
    /// The operator, for `ATT-017`.
    pub operator_id: [u8; 32],
    /// The family, for the placement list.
    pub family_id: [u8; 32],
}

/// `rank(h, r) = SHA3-256("umbra/v1/chunk-place" || h || relay_id_r)`.
pub fn rank(handle: &[u8; 32], relay_id: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[labels::CHUNK_PLACE, handle, relay_id])
}

/// The placement list of `handle`: the attachment relays in ascending
/// rank, with each relay whose family an earlier relay holds left out.
pub fn placement_list(handle: &[u8; 32], relays: &[AttachmentRelay]) -> Vec<[u8; 32]> {
    let mut ranked: Vec<([u8; 32], &AttachmentRelay)> = relays
        .iter()
        .map(|r| (rank(handle, &r.relay_id), r))
        .collect();
    ranked.sort_unstable_by_key(|entry| entry.0);
    let mut families: Vec<[u8; 32]> = Vec::new();
    let mut list = Vec::new();
    for (_, relay) in ranked {
        if families.contains(&relay.family_id) {
            continue;
        }
        families.push(relay.family_id);
        list.push(relay.relay_id);
    }
    list
}

/// The relays a writer selects: the first `BACKUP_REPLICAS` of the list
/// that did not fail, in list order (`ATT-133`, `ATT-134`).
pub fn writer_targets(list: &[[u8; 32]], failed: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, Error> {
    let targets: Vec<[u8; 32]> = list
        .iter()
        .filter(|r| !failed.contains(r))
        .take(BACKUP_REPLICAS)
        .copied()
        .collect();
    if targets.len() < BACKUP_REPLICAS {
        return Err(Error::NoPath);
    }
    Ok(targets)
}

/// The relays a reader asks, in list order and at most `PLACE_PROBE`
/// (`ATT-136`, `ATT-137`).
pub fn reader_probes(list: &[[u8; 32]]) -> &[[u8; 32]] {
    list.get(..list.len().min(PLACE_PROBE)).unwrap_or(&[])
}

/// Resolves a hint against the relays of the current consensus: exactly
/// one match, or the replica is unreachable or unresolvable (`ATT-008`
/// to `ATT-013`).
pub fn resolve_hint(
    hint: &[u8; 12],
    relay_ids: impl Iterator<Item = [u8; 32]>,
) -> Result<[u8; 32], Error> {
    if *hint == [0; 12] {
        return Err(Error::NoPath);
    }
    let mut found = None;
    for relay_id in relay_ids {
        if seal::relay_hint(&relay_id) == *hint {
            if found.is_some() {
                return Err(Error::NoPath);
            }
            found = Some(relay_id);
        }
    }
    found.ok_or(Error::NoPath)
}

/// The relays that answered `BUSY` or `LIMIT` for a chunk, which the same
/// `CGET` does not reach again inside `FETCH_RETRY_HOLD` (`ATT-174`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HoldOffs {
    entries: BTreeMap<([u8; 32], [u8; 32]), u64>,
}

impl HoldOffs {
    /// Records the refusal of `relay_id` for `chunk_id` at `now`.
    pub fn note(&mut self, chunk_id: [u8; 32], relay_id: [u8; 32], now: u64) {
        self.entries.insert((chunk_id, relay_id), now);
    }

    /// Whether the relay is inside its hold-off for the chunk.
    pub fn blocked(&self, chunk_id: &[u8; 32], relay_id: &[u8; 32], now: u64) -> bool {
        self.entries
            .get(&(*chunk_id, *relay_id))
            .is_some_and(|at| now.saturating_sub(*at) < FETCH_RETRY_HOLD)
    }

    /// Drops each hold-off that ended.
    pub fn expire(&mut self, now: u64) {
        self.entries
            .retain(|_, at| now.saturating_sub(*at) < FETCH_RETRY_HOLD);
    }
}

/// The order in which one fetch tries the replicas of a chunk: a random
/// permutation of the resolved relays, with each held-off relay left out
/// (`ATT-019`, `ATT-173`). `random` gives a value below its argument.
pub fn fetch_order(
    chunk_id: &[u8; 32],
    replicas: &[[u8; 32]],
    hold_offs: &HoldOffs,
    now: u64,
    random: &mut dyn FnMut(u32) -> u32,
) -> Vec<[u8; 32]> {
    let mut order: Vec<[u8; 32]> = replicas
        .iter()
        .filter(|r| !hold_offs.blocked(chunk_id, r, now))
        .copied()
        .collect();
    // Fisher–Yates from the end, with one random draw per position.
    let mut end = order.len();
    while end > 1 {
        let bound = u32::try_from(end).unwrap_or(u32::MAX);
        let pick = usize::try_from(random(bound)).unwrap_or(0) % end;
        order.swap(pick, end.saturating_sub(1));
        end = end.saturating_sub(1);
    }
    order
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn relay(id: u8, family: u8) -> AttachmentRelay {
        AttachmentRelay {
            relay_id: [id; 32],
            operator_id: [id; 32],
            family_id: [family; 32],
        }
    }

    #[test]
    fn the_placement_list_ranks_and_drops_a_repeated_family() {
        let relays = [
            relay(1, 1),
            relay(2, 2),
            relay(3, 1),
            relay(4, 3),
            relay(5, 4),
        ];
        let list = placement_list(&[7; 32], &relays);
        assert_eq!(list.len(), 4);
        let ranks: Vec<[u8; 32]> = list.iter().map(|r| rank(&[7; 32], r)).collect();
        assert!(ranks.windows(2).all(|w| w[0] < w[1]));
        // A different handle gives a different order, and the same handle
        // gives the same list at each party.
        assert_eq!(list, placement_list(&[7; 32], &relays));
        let other = placement_list(&[8; 32], &relays);
        assert_eq!(other.len(), 4);
        let targets = writer_targets(&list, &[]).unwrap();
        assert_eq!(targets, list[..2]);
        let replaced = writer_targets(&list, &[list[0]]).unwrap();
        assert_eq!(replaced, list[1..3]);
        assert!(writer_targets(&list, &list[..3]).is_err());
        assert_eq!(reader_probes(&list), &list[..4]);
        assert_eq!(reader_probes(&list[..2]), &list[..2]);
    }

    #[test]
    fn a_hint_resolves_to_exactly_one_relay() {
        let ids = [[1u8; 32], [2; 32], [3; 32]];
        let hint = seal::relay_hint(&[2; 32]);
        assert_eq!(resolve_hint(&hint, ids.iter().copied()).unwrap(), [2; 32]);
        assert_eq!(
            resolve_hint(&hint, ids[..1].iter().copied()),
            Err(Error::NoPath)
        );
        let twice = [[2u8; 32], [2; 32]];
        assert_eq!(
            resolve_hint(&hint, twice.iter().copied()),
            Err(Error::NoPath)
        );
        assert_eq!(
            resolve_hint(&[0; 12], ids.iter().copied()),
            Err(Error::NoPath)
        );
    }

    #[test]
    fn a_fetch_order_is_a_permutation_that_skips_a_held_off_relay() {
        let replicas = [[1u8; 32], [2; 32], [3; 32]];
        let mut hold = HoldOffs::default();
        hold.note([9; 32], [2; 32], 100);
        let mut counter = 0u32;
        let mut random = |bound: u32| {
            counter = counter.wrapping_add(1);
            counter % bound
        };
        let order = fetch_order(&[9; 32], &replicas, &hold, 200, &mut random);
        assert_eq!(order.len(), 2);
        assert!(order.contains(&[1; 32]) && order.contains(&[3; 32]));
        let later = fetch_order(
            &[9; 32],
            &replicas,
            &hold,
            100 + FETCH_RETRY_HOLD,
            &mut random,
        );
        assert_eq!(later.len(), 3);
        hold.expire(100 + FETCH_RETRY_HOLD);
        assert!(!hold.blocked(&[9; 32], &[2; 32], 100));
        // A different draw gives a different order.
        let mut first = |_: u32| 0u32;
        let a = fetch_order(&[9; 32], &replicas, &hold, 0, &mut first);
        let mut last = |bound: u32| bound - 1;
        let b = fetch_order(&[9; 32], &replicas, &hold, 0, &mut last);
        assert_ne!(a, b);
    }
}
