//! Path selection under the hard constraints of Part 3 §3.4.6 and Part 10
//! §10.6: operator, family, jurisdiction bloc, autonomous system, and
//! prefix disjointness, the layer order, and the one relaxation the
//! specification permits.

use alloc::vec::Vec;

use super::{
    bloc::{BlocId, BlocList},
    descriptor::{roles, RelayEntry},
    layer::layer,
    INGRESS_PIN_CONFIRMED, INGRESS_PIN_UNCONFIRMED,
};
use crate::Error;

/// The facts of one relay that the invariants test, taken from its entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The relay.
    pub relay_id: [u8; 32],
    /// `operator_id` of the entry.
    pub operator_id: [u8; 32],
    /// `family_id` of the descriptor.
    pub family_id: [u8; 32],
    /// The bloc of the jurisdiction.
    pub bloc: BlocId,
    /// The autonomous system.
    pub asn: u32,
    /// The IPv4 /16, if the relay has an IPv4 address.
    pub v4_prefix: Option<[u8; 2]>,
    /// The IPv6 /48, if the relay has an IPv6 address.
    pub v6_prefix: Option<[u8; 6]>,
    /// Whether the entry carries the ingress flag.
    pub ingress: bool,
    /// Whether the descriptor offers the chain role.
    pub chain: bool,
    /// Whether the descriptor offers the queue role. The last relay of a
    /// circuit serves the commands of a client, thus it needs this role.
    pub queue: bool,
    /// The layer under the accepted root, for a chain relay.
    pub layer: u8,
}

impl Candidate {
    /// Reads the facts from a verified entry under the accepted root.
    pub fn from_entry(
        entry: &RelayEntry<'_>,
        blocs: &BlocList,
        root: &[u8; 32],
        epoch: u64,
    ) -> Self {
        let d = &entry.descriptor;
        let v4_prefix = (d.addr_v4 != [0; 4]).then(|| [d.addr_v4[0], d.addr_v4[1]]);
        let v6_prefix = (d.addr_v6 != [0; 16]).then(|| {
            let mut p = [0u8; 6];
            p.copy_from_slice(d.addr_v6.get(..6).unwrap_or(&[0; 6]));
            p
        });
        Candidate {
            relay_id: d.relay_id,
            operator_id: entry.operator_id,
            family_id: d.family_id,
            bloc: blocs.bloc_of(&d.jurisdiction),
            asn: d.asn,
            v4_prefix,
            v6_prefix,
            ingress: entry.ingress(),
            chain: d.roles & roles::CHAIN != 0,
            queue: d.roles & roles::QUEUE != 0,
            layer: layer(root, epoch, &d.relay_id),
        }
    }

    /// Whether the relay can be the last relay of a circuit: a chain relay of
    /// layer 3 with the queue role, and no ingress. The layer function gives
    /// each relay a layer, and an ingress relay can thus read as layer 3.
    pub fn is_exit(&self) -> bool {
        self.layer == 3 && self.chain && self.queue && !self.ingress
    }

    /// Whether two relays may share a chain under invariants 1 and 3.
    fn disjoint_hard(&self, other: &Candidate) -> bool {
        self.operator_id != other.operator_id
            && self.family_id != other.family_id
            && self.asn != other.asn
            && !(self.v4_prefix.is_some() && self.v4_prefix == other.v4_prefix)
            && !(self.v6_prefix.is_some() && self.v6_prefix == other.v6_prefix)
    }
}

/// A chain of three hops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    /// The relays at hops 1, 2, and 3.
    pub hops: [[u8; 32]; 3],
    /// Whether invariant 2 was relaxed at hop 2 (`NET-200`), which the
    /// client shows (`NET-201`).
    pub relaxed: bool,
}

/// Checks a chain against the invariants (`NET-032`). `relax` permits the
/// relaxation of `NET-200`.
pub fn check(
    hop1: &Candidate,
    hop2: &Candidate,
    hop3: &Candidate,
    relax: bool,
) -> Result<Chain, Error> {
    // Invariant 4: the ingress at hop 1, then layer 2, then layer 3, and no
    // ingress-flagged relay at hop 2 or 3 (REL-133, REL-134).
    if !hop1.ingress || hop2.ingress || hop3.ingress || !hop2.chain || !hop3.chain {
        return Err(Error::NoPath);
    }
    if hop2.layer != 2 || hop3.layer != 3 || !hop3.queue {
        return Err(Error::NoPath);
    }
    // Invariants 1 and 3 at every pair.
    if !hop1.disjoint_hard(hop2) || !hop1.disjoint_hard(hop3) || !hop2.disjoint_hard(hop3) {
        return Err(Error::NoPath);
    }
    // Invariant 2: hops 1 and 3 always; hop 2 unless relaxed (NET-202).
    if hop1.bloc == hop3.bloc {
        return Err(Error::NoPath);
    }
    let hop2_shares = hop1.bloc == hop2.bloc || hop2.bloc == hop3.bloc;
    if hop2_shares && !relax {
        return Err(Error::NoPath);
    }
    Ok(Chain {
        hops: [hop1.relay_id, hop2.relay_id, hop3.relay_id],
        relaxed: hop2_shares,
    })
}

/// Selects a chain: the pinned ingress, then the first pair of candidates
/// in the order given that satisfies every invariant, then the first pair
/// under the relaxation, then failure (`NET-033`). The caller gives the
/// candidates in a consensus-random order (`REL-015`).
pub fn select(ingress: &Candidate, candidates: &[Candidate]) -> Result<Chain, Error> {
    for relax in [false, true] {
        for hop2 in candidates.iter().filter(|c| c.layer == 2) {
            for hop3 in candidates.iter().filter(|c| c.is_exit()) {
                if let Ok(chain) = check(ingress, hop2, hop3, relax) {
                    return Ok(chain);
                }
            }
        }
    }
    Err(Error::NoPath)
}

/// One pinned ingress relay (Part 10 §10.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressPin {
    /// The relay.
    pub relay_id: [u8; 32],
    /// When the pin was made.
    pub pinned_at: u64,
    /// Whether the relay confirmed the pin by serving a session.
    pub confirmed: bool,
}

impl IngressPin {
    /// Whether the pin reached its lifetime at `now`.
    pub fn expired(&self, now: u64) -> bool {
        let life = if self.confirmed {
            INGRESS_PIN_CONFIRMED
        } else {
            INGRESS_PIN_UNCONFIRMED
        };
        now.saturating_sub(self.pinned_at) >= life
    }
}

/// The two pinned ingress relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressPins {
    pins: Vec<IngressPin>,
}

impl IngressPins {
    /// Two pins from the two entries the caller selected at random among
    /// the eligible ones.
    pub fn new(first: [u8; 32], second: [u8; 32], now: u64) -> Self {
        IngressPins {
            pins: alloc::vec![
                IngressPin {
                    relay_id: first,
                    pinned_at: now,
                    confirmed: false
                },
                IngressPin {
                    relay_id: second,
                    pinned_at: now,
                    confirmed: false
                },
            ],
        }
    }

    /// The pins.
    pub fn pins(&self) -> &[IngressPin] {
        &self.pins
    }

    /// Marks a pin confirmed.
    pub fn confirm(&mut self, relay_id: &[u8; 32]) {
        if let Some(p) = self.pins.iter_mut().find(|p| p.relay_id == *relay_id) {
            p.confirmed = true;
        }
    }

    /// Replaces the pin of `relay_id` with `replacement` at `now`, at a
    /// rotation or at a forced replacement the client reports (`REL-016`).
    pub fn replace(&mut self, relay_id: &[u8; 32], replacement: [u8; 32], now: u64) {
        if let Some(p) = self.pins.iter_mut().find(|p| p.relay_id == *relay_id) {
            *p = IngressPin {
                relay_id: replacement,
                pinned_at: now,
                confirmed: false,
            };
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    fn cand(id: u8, bloc: BlocId, layer: u8, ingress: bool) -> Candidate {
        Candidate {
            relay_id: [id; 32],
            operator_id: [id; 32],
            family_id: [id; 32],
            bloc,
            asn: u32::from(id),
            v4_prefix: Some([id, 0]),
            v6_prefix: None,
            ingress,
            chain: true,
            queue: true,
            layer,
        }
    }

    #[test]
    fn the_invariants_hold_and_the_relaxation_is_the_last_resort() {
        let list = BlocList::v1();
        let eu = list.bloc_of(b"DE");
        let five = list.bloc_of(b"US");
        let ch = list.bloc_of(b"CH");
        let ingress = cand(1, eu, 0, true);
        let good2 = cand(2, five, 2, false);
        let good3 = cand(3, ch, 3, false);
        assert_eq!(
            check(&ingress, &good2, &good3, false).unwrap(),
            Chain {
                hops: [[1; 32], [2; 32], [3; 32]],
                relaxed: false
            }
        );
        // Wrong layer order, an ingress at hop 2, a shared ASN.
        assert!(check(&ingress, &good3, &good2, false).is_err());
        assert!(check(&ingress, &cand(2, five, 2, true), &good3, false).is_err());
        let mut same_asn = good3;
        same_asn.asn = 2;
        assert!(check(&ingress, &good2, &same_asn, false).is_err());
        // Hop 1 and hop 3 in one bloc never pass; hop 2 sharing passes only relaxed.
        assert!(check(&ingress, &good2, &cand(4, eu, 3, false), true).is_err());
        let shared2 = cand(5, eu, 2, false);
        assert!(check(&ingress, &shared2, &good3, false).is_err());
        assert!(check(&ingress, &shared2, &good3, true).unwrap().relaxed);
        // Selection prefers the strict chain over the relaxed one.
        let chosen = select(&ingress, &[shared2, good3, good2]).unwrap();
        assert!(!chosen.relaxed);
        let only_relaxed = select(&ingress, &[shared2, good3]).unwrap();
        assert!(only_relaxed.relaxed);
        assert_eq!(select(&ingress, &[good2]), Err(Error::NoPath));
    }

    #[test]
    fn the_pins_live_sixty_or_one_hundred_twenty_days() {
        let mut pins = IngressPins::new([1; 32], [2; 32], 0);
        pins.confirm(&[1; 32]);
        assert!(pins.pins()[0].expired(INGRESS_PIN_CONFIRMED));
        assert!(!pins.pins()[1].expired(INGRESS_PIN_CONFIRMED));
        assert!(pins.pins()[1].expired(INGRESS_PIN_UNCONFIRMED));
        pins.replace(&[1; 32], [3; 32], 10);
        assert_eq!(pins.pins()[0].relay_id, [3; 32]);
        assert!(!pins.pins()[0].confirmed);
    }
}
