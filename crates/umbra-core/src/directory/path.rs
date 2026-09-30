//! Path selection under the hard constraints of Part 3 §3.4.6 and Part 10
//! §10.6: operator, family, jurisdiction bloc, autonomous system, and
//! prefix disjointness, the layer order, and the one relaxation the
//! specification permits.

use alloc::vec::Vec;

use super::{
    bloc::{BlocId, BlocList},
    descriptor::{roles, RelayEntry},
    removal::LinkRemoval,
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
    /// The verified class of the entry, 0 to 3 (§10.2).
    pub class: u8,
}

/// The weight of each class in a draw, in proportion to its rate of 100,
/// 250, 500, and 1 000 Mbit/s (`REL-196`).
pub const CLASS_WEIGHTS: [u64; 4] = [2, 5, 10, 20];
/// The lowest class of an ingress relay: 250 Mbit/s (§10.6.1).
pub const INGRESS_CLASS_MIN: u8 = 1;

/// The weight of `class` in a draw; a class above C3 counts as C3.
pub fn class_weight(class: u8) -> u64 {
    CLASS_WEIGHTS
        .get(usize::from(class))
        .copied()
        .unwrap_or(CLASS_WEIGHTS[3])
}

/// Orders `candidates` by a random draw in proportion to the weight of the
/// class of each (`REL-196`): each place takes one of the relays left, and
/// a relay of C3 comes before one of C0 ten times as often. `random` gives
/// a value below its argument. The class comes from the signed entry and
/// from no measurement of this client (`REL-014`).
///
/// The relays of one class weigh the same, thus each class is shuffled on
/// its own, and each place draws a class in proportion to the relays it
/// has left times its weight. The draw is exact, and it costs time linear
/// in the relays.
pub fn weighted_order(
    candidates: &[Candidate],
    random: &mut dyn FnMut(u64) -> u64,
) -> Vec<Candidate> {
    let mut classes: [Vec<Candidate>; 4] = Default::default();
    for candidate in candidates {
        let class = usize::from(candidate.class.min(3));
        if let Some(bucket) = classes.get_mut(class) {
            bucket.push(*candidate);
        }
    }
    // Fisher–Yates in each class, from the end.
    for bucket in &mut classes {
        let mut end = bucket.len();
        while end > 1 {
            let bound = u64::try_from(end).unwrap_or(u64::MAX);
            let pick = usize::try_from(random(bound)).unwrap_or(0) % end;
            bucket.swap(pick, end.saturating_sub(1));
            end = end.saturating_sub(1);
        }
    }
    let mut out = Vec::with_capacity(candidates.len());
    loop {
        let mass = |class: usize, bucket: &Vec<Candidate>| {
            u64::try_from(bucket.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(class_weight(u8::try_from(class).unwrap_or(3)))
        };
        let total: u64 = classes
            .iter()
            .enumerate()
            .map(|(class, bucket)| mass(class, bucket))
            .sum();
        if total == 0 {
            break;
        }
        let mut at = random(total);
        let mut chosen = None;
        for (class, bucket) in classes.iter().enumerate() {
            let share = mass(class, bucket);
            if at < share {
                chosen = Some(class);
                break;
            }
            at = at.saturating_sub(share);
        }
        let Some(candidate) = chosen
            .or_else(|| classes.iter().rposition(|bucket| !bucket.is_empty()))
            .and_then(|class| classes.get_mut(class))
            .and_then(Vec::pop)
        else {
            break;
        };
        out.push(candidate);
    }
    out
}

impl Candidate {
    /// Reads the facts from a verified entry.
    pub fn from_entry(entry: &RelayEntry<'_>, blocs: &BlocList) -> Self {
        let d = &entry.descriptor;
        let v4_prefix = (d.addr_v4 != [0; 4]).then(|| [d.addr_v4[0], d.addr_v4[1]]);
        let v6_prefix = (d.addr_v6 != [0; 16]).then(|| {
            let mut p = [0u8; 6];
            p.copy_from_slice(d.addr_v6.get(..6).unwrap_or(&[0; 6]));
            p
        });
        // REL-158: a pending entry names no layer yet, thus it serves no
        // hop. The three roles go away together, and each selection path
        // then passes it by.
        let placed = !entry.pending();
        Candidate {
            relay_id: d.relay_id,
            operator_id: entry.operator_id,
            family_id: d.family_id,
            bloc: blocs.bloc_of(&d.jurisdiction),
            asn: d.asn,
            v4_prefix,
            v6_prefix,
            // §10.6.1: an ingress relay holds 250 Mbit/s or more.
            ingress: placed && entry.ingress() && entry.class >= INGRESS_CLASS_MIN,
            chain: placed && d.roles & roles::CHAIN != 0,
            queue: placed && d.roles & roles::QUEUE != 0,
            layer: entry.layer(),
            class: entry.class,
        }
    }

    /// Whether the relay can be the last relay of a circuit: a chain relay of
    /// layer 3 with the queue role, and no ingress.
    pub fn is_exit(&self) -> bool {
        self.layer == 3 && self.chain && self.queue && !self.ingress
    }

    /// Whether two relays stand under different operators and families:
    /// invariant 1.
    pub fn apart_operator(&self, other: &Candidate) -> bool {
        self.operator_id != other.operator_id && self.family_id != other.family_id
    }

    /// Whether two relays share no autonomous system and no prefix:
    /// invariant 3.
    fn apart_network(&self, other: &Candidate) -> bool {
        self.asn != other.asn
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
    /// Whether two hops share an operator or a family under the bootstrap
    /// relaxation (`NET-340`), which the client shows (`NET-343`).
    pub one_operator: bool,
    /// Whether hop 1 and hop 3 share a bloc under the bootstrap relaxation
    /// of `NET-350`; the route view names the country of each hop.
    pub one_bloc: bool,
    /// Whether two hops share an autonomous system or a prefix under the
    /// bootstrap relaxation of `NET-350`.
    pub one_network: bool,
}

/// The relaxations that one selection pass permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Relax {
    /// Hop 2 may share a bloc with hop 1 or hop 3 (`NET-200`).
    pub hop2: bool,
    /// Two hops may share an operator or a family (`NET-340`).
    pub operator: bool,
    /// Hop 1 and hop 3 may share a bloc (`NET-350`).
    pub bloc: bool,
    /// Two hops may share an autonomous system or a prefix (`NET-350`).
    pub network: bool,
}

impl Relax {
    /// No relaxation.
    pub const NONE: Relax = Relax {
        hop2: false,
        operator: false,
        bloc: false,
        network: false,
    };
}

/// Checks a chain against the invariants (`NET-032`) under the
/// relaxations of `relax`.
pub fn check(
    hop1: &Candidate,
    hop2: &Candidate,
    hop3: &Candidate,
    relax: Relax,
) -> Result<Chain, Error> {
    // Invariant 4: the ingress at hop 1, then layer 2, then layer 3, and no
    // ingress-flagged relay at hop 2 or 3 (REL-133, REL-134).
    if !hop1.ingress || hop2.ingress || hop3.ingress || !hop2.chain || !hop3.chain {
        return Err(Error::NoPath);
    }
    if hop2.layer != 2 || hop3.layer != 3 || !hop3.queue {
        return Err(Error::NoPath);
    }
    // Three relays, and not one relay twice.
    if hop1.relay_id == hop2.relay_id
        || hop1.relay_id == hop3.relay_id
        || hop2.relay_id == hop3.relay_id
    {
        return Err(Error::NoPath);
    }
    // Invariant 3 at every pair unless the bootstrap relaxation of NET-350
    // holds.
    let one_network =
        !hop1.apart_network(hop2) || !hop1.apart_network(hop3) || !hop2.apart_network(hop3);
    if one_network && !relax.network {
        return Err(Error::NoPath);
    }
    // Invariant 1 unless the bootstrap relaxation holds (NET-340, NET-342).
    let one_operator =
        !hop1.apart_operator(hop2) || !hop1.apart_operator(hop3) || !hop2.apart_operator(hop3);
    if one_operator && !relax.operator {
        return Err(Error::NoPath);
    }
    // Invariant 2: hops 1 and 3 unless the bootstrap relaxation of NET-350
    // holds; hop 2 unless relaxed (NET-202).
    let shares_ends = hop1.bloc == hop3.bloc;
    if shares_ends && !relax.bloc {
        return Err(Error::NoPath);
    }
    let hop2_shares = hop1.bloc == hop2.bloc || hop2.bloc == hop3.bloc;
    if hop2_shares && !relax.hop2 {
        return Err(Error::NoPath);
    }
    Ok(Chain {
        hops: [hop1.relay_id, hop2.relay_id, hop3.relay_id],
        relaxed: hop2_shares,
        one_operator,
        one_bloc: shares_ends,
        one_network,
    })
}

/// Selects a chain: the pinned ingress, then the first pair of candidates
/// in the order given that satisfies every invariant, then the first pair
/// under the relaxation, then failure (`NET-033`). The caller gives the
/// candidates in a consensus-random order (`REL-015`).
pub fn select(ingress: &Candidate, candidates: &[Candidate]) -> Result<Chain, Error> {
    select_avoiding(ingress, candidates, &[], false)
}

/// As [`select`], and no two adjacent relays of the chain form a link of
/// `removed` (Part 10 `REL-185`). `bootstrap` says that the directory is
/// provisional, and a chain of one operator then follows each chain that
/// satisfies invariant 1 (`NET-340` to `NET-342`).
pub fn select_avoiding(
    ingress: &Candidate,
    candidates: &[Candidate],
    removed: &[LinkRemoval],
    bootstrap: bool,
) -> Result<Chain, Error> {
    let is_removed = |one: &Candidate, other: &Candidate| {
        removed
            .iter()
            .any(|link| link.names(&one.relay_id, &other.relay_id))
    };
    // NET-342, NET-350: the relaxations of a provisional directory come
    // last, one at a time: the operator, the bloc of hop 1 and hop 3, and
    // the network.
    let strict = Relax::NONE;
    let hop2 = Relax {
        hop2: true,
        ..strict
    };
    let operator = Relax {
        operator: true,
        ..strict
    };
    let both = Relax {
        operator: true,
        ..hop2
    };
    let bloc = Relax { bloc: true, ..both };
    let network = Relax {
        network: true,
        ..bloc
    };
    let levels: &[Relax] = if bootstrap {
        &[strict, hop2, operator, both, bloc, network]
    } else {
        &[strict, hop2]
    };
    for &relax in levels {
        for hop2 in candidates
            .iter()
            .filter(|c| c.layer == 2 && !is_removed(ingress, c))
        {
            for hop3 in candidates
                .iter()
                .filter(|c| c.is_exit() && !is_removed(hop2, c))
            {
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

/// The count of pins that a client holds (Part 10 §10.6.1).
pub const INGRESS_PINS: usize = 2;
/// The stored width of one pin: the relay, the time, and the confirmed byte.
const PIN_LEN: usize = 32 + 8 + 1;

/// The two pinned ingress relays. A relay set with one eligible relay gives
/// one pin, and the second place stays open for a later set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IngressPins {
    pins: Vec<IngressPin>,
}

impl IngressPins {
    /// No pin: the state of a client before its first relay set.
    pub fn empty() -> Self {
        IngressPins::default()
    }

    /// Brings the pins in line with a relay set at `now`. A pin stays while
    /// its relay is ingress eligible and its lifetime runs (`REL-153`). An
    /// open place takes the first relay of `eligible` that shares no
    /// operator and no family with the other pin (`REL-154`). In a
    /// provisional directory, `bootstrap`, a place with no such relay takes
    /// another relay of the same operator, and a pin of that kind ends when
    /// the relaxation ends (`NET-344`, `NET-345`). The caller gives
    /// `eligible` in a random order. The function reads no measure of speed
    /// (`REL-014`). It returns whether a pin changed.
    pub fn refresh(&mut self, eligible: &[Candidate], now: u64, bootstrap: bool) -> bool {
        let before = self.pins.clone();
        let of = |relay_id: &[u8; 32]| eligible.iter().find(|c| c.relay_id == *relay_id);
        let listed = |pin: &IngressPin| of(&pin.relay_id).is_some_and(|relay| relay.ingress);
        self.pins.retain(|pin| listed(pin) && !pin.expired(now));
        if !bootstrap {
            if let [first, second] = &self.pins[..] {
                let shared = of(&first.relay_id)
                    .zip(of(&second.relay_id))
                    .is_some_and(|(a, b)| !a.apart_operator(b));
                if shared {
                    self.pins.truncate(1);
                }
            }
        }
        for one_operator in [false, true] {
            if one_operator && !bootstrap {
                break;
            }
            for relay in eligible.iter().filter(|relay| relay.ingress) {
                if self.pins.len() >= INGRESS_PINS {
                    break;
                }
                let is_apart = self
                    .pins
                    .iter()
                    .filter_map(|pin| of(&pin.relay_id))
                    .all(|held| {
                        held.relay_id != relay.relay_id
                            && (one_operator || held.apart_operator(relay))
                    });
                if is_apart {
                    self.pins.push(IngressPin {
                        relay_id: relay.relay_id,
                        pinned_at: now,
                        confirmed: false,
                    });
                }
            }
        }
        self.pins != before
    }

    /// The stored form: 41 bytes for each pin.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.pins.len().saturating_mul(PIN_LEN));
        for pin in &self.pins {
            out.extend_from_slice(&pin.relay_id);
            out.extend_from_slice(&pin.pinned_at.to_be_bytes());
            out.push(u8::from(pin.confirmed));
        }
        out
    }

    /// Reads the stored form.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if !bytes.len().is_multiple_of(PIN_LEN) || bytes.len() > INGRESS_PINS * PIN_LEN {
            return Err(Error::Malformed);
        }
        let mut pins = Vec::with_capacity(INGRESS_PINS);
        for pin in bytes.as_chunks::<PIN_LEN>().0 {
            let mut r = umbra_wire::codec::Reader::new(pin);
            let relay_id = r.array().map_err(|_| Error::Malformed)?;
            let pinned_at = u64::from_be_bytes(r.array().map_err(|_| Error::Malformed)?);
            let confirmed = match r.u8().map_err(|_| Error::Malformed)? {
                0 => false,
                1 => true,
                _ => return Err(Error::Malformed),
            };
            pins.push(IngressPin {
                relay_id,
                pinned_at,
                confirmed,
            });
        }
        Ok(IngressPins { pins })
    }

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

    /// Marks a pin confirmed, and returns whether that changed it.
    pub fn confirm(&mut self, relay_id: &[u8; 32]) -> bool {
        match self.pins.iter_mut().find(|p| p.relay_id == *relay_id) {
            Some(pin) if !pin.confirmed => {
                pin.confirmed = true;
                true
            }
            _ => false,
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
            class: 2,
        }
    }

    #[test]
    fn a_network_in_one_country_builds_under_the_provisional_directory_alone() {
        // NET-350: each relay in the United States, at three providers.
        let us = BlocList::v1().bloc_of(b"US");
        let mut ingress = cand(1, us, 0, true);
        ingress.operator_id = [0xAA; 32];
        let mut hop2 = cand(2, us, 2, false);
        hop2.operator_id = [0xAA; 32];
        let mut hop3 = cand(3, us, 3, false);
        hop3.operator_id = [0xAA; 32];
        assert_eq!(
            select_avoiding(&ingress, &[hop2, hop3], &[], false),
            Err(Error::NoPath)
        );
        let chain = select_avoiding(&ingress, &[hop2, hop3], &[], true).unwrap();
        assert!(chain.one_bloc && chain.one_operator && chain.relaxed);
        // NET-350: one provider at each hop also passes, last, and only in
        // the provisional directory.
        let mut same_provider = hop3;
        same_provider.asn = ingress.asn;
        same_provider.v4_prefix = ingress.v4_prefix;
        assert_eq!(
            select_avoiding(&ingress, &[hop2, same_provider], &[], false),
            Err(Error::NoPath)
        );
        let one_host = select_avoiding(&ingress, &[hop2, same_provider], &[], true).unwrap();
        assert!(one_host.one_network);
        let first = select_avoiding(&ingress, &[hop2, same_provider, hop3], &[], true).unwrap();
        assert!(!first.one_network);
        // A chain with hop 1 and hop 3 in two blocs comes first.
        let mut abroad = hop3;
        abroad.relay_id = [9; 32];
        abroad.asn = 99;
        abroad.v4_prefix = Some([10, 99]);
        abroad.bloc = BlocList::v1().bloc_of(b"CH");
        let first = select_avoiding(&ingress, &[hop2, hop3, abroad], &[], true).unwrap();
        assert!(!first.one_bloc);
    }

    #[test]
    fn a_faster_class_comes_first_in_proportion_to_its_weight() {
        // REL-196: a C3 relay against a C0 relay leads 20 draws in 22.
        let mut fast = cand(1, BlocId::Own([b'A', 1]), 2, false);
        fast.class = 3;
        let mut slow = cand(2, BlocId::Own([b'A', 2]), 2, false);
        slow.class = 0;
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut random = |bound: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % bound
        };
        let rounds = 22_000;
        let mut leads = 0u32;
        for _ in 0..rounds {
            let order = weighted_order(&[slow, fast], &mut random);
            assert_eq!(order.len(), 2);
            if order[0].relay_id == fast.relay_id {
                leads += 1;
            }
        }
        assert!((19_600..20_400).contains(&leads), "{leads}");
    }

    #[test]
    fn a_removed_link_leaves_each_chain_that_holds_it_and_no_other() {
        let list = BlocList::v1();
        let ingress = cand(1, list.bloc_of(b"DE"), 0, true);
        let middles = [
            cand(2, list.bloc_of(b"US"), 2, false),
            cand(4, list.bloc_of(b"JP"), 2, false),
        ];
        let exits = [
            cand(3, list.bloc_of(b"CH"), 3, false),
            cand(5, list.bloc_of(b"BR"), 3, false),
        ];
        let all: Vec<Candidate> = middles.iter().chain(&exits).copied().collect();
        assert_eq!(
            select(&ingress, &all).unwrap().hops,
            [[1; 32], [2; 32], [3; 32]]
        );
        // REL-185: the link 2-3 goes, in the order the removal names it.
        let removed = [LinkRemoval::of(7, [3; 32], [2; 32])];
        assert_eq!(
            select_avoiding(&ingress, &all, &removed, false)
                .unwrap()
                .hops,
            [[1; 32], [2; 32], [5; 32]]
        );
        // The link 1-2 goes too: relay 2 serves no chain from this ingress.
        let both = [removed[0], LinkRemoval::of(7, [1; 32], [2; 32])];
        assert_eq!(
            select_avoiding(&ingress, &all, &both, false).unwrap().hops,
            [[1; 32], [4; 32], [3; 32]]
        );
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
            check(
                &ingress,
                &good2,
                &good3,
                Relax {
                    hop2: false,
                    operator: false,
                    bloc: false,
                    network: false
                }
            )
            .unwrap(),
            Chain {
                hops: [[1; 32], [2; 32], [3; 32]],
                relaxed: false,
                one_operator: false,
                one_bloc: false,
                one_network: false,
            }
        );
        // Wrong layer order, an ingress at hop 2, a shared ASN.
        assert!(check(
            &ingress,
            &good3,
            &good2,
            Relax {
                hop2: false,
                operator: false,
                bloc: false,
                network: false
            }
        )
        .is_err());
        assert!(check(&ingress, &cand(2, five, 2, true), &good3, Relax::NONE).is_err());
        let mut same_asn = good3;
        same_asn.asn = 2;
        assert!(check(
            &ingress,
            &good2,
            &same_asn,
            Relax {
                hop2: false,
                operator: false,
                bloc: false,
                network: false
            }
        )
        .is_err());
        // Hop 1 and hop 3 in one bloc never pass; hop 2 sharing passes only relaxed.
        assert!(check(
            &ingress,
            &good2,
            &cand(4, eu, 3, false),
            Relax {
                hop2: true,
                operator: false,
                bloc: false,
                network: false
            }
        )
        .is_err());
        let shared2 = cand(5, eu, 2, false);
        assert!(check(
            &ingress,
            &shared2,
            &good3,
            Relax {
                hop2: false,
                operator: false,
                bloc: false,
                network: false
            }
        )
        .is_err());
        assert!(
            check(
                &ingress,
                &shared2,
                &good3,
                Relax {
                    hop2: true,
                    operator: false,
                    bloc: false,
                    network: false
                }
            )
            .unwrap()
            .relaxed
        );
        // Selection prefers the strict chain over the relaxed one.
        let chosen = select(&ingress, &[shared2, good3, good2]).unwrap();
        assert!(!chosen.relaxed);
        let only_relaxed = select(&ingress, &[shared2, good3]).unwrap();
        assert!(only_relaxed.relaxed);
        assert_eq!(select(&ingress, &[good2]), Err(Error::NoPath));

        // NET-340: one operator at hop 2 and hop 3 passes only under the
        // bootstrap relaxation, and a chain of other operators comes first
        // (NET-342).
        let mut own2 = good2;
        own2.operator_id = ingress.operator_id;
        assert!(check(
            &ingress,
            &own2,
            &good3,
            Relax {
                hop2: false,
                operator: false,
                bloc: false,
                network: false
            }
        )
        .is_err());
        assert!(
            check(
                &ingress,
                &own2,
                &good3,
                Relax {
                    hop2: false,
                    operator: true,
                    bloc: false,
                    network: false
                }
            )
            .unwrap()
            .one_operator
        );
        assert_eq!(
            select_avoiding(&ingress, &[own2, good3], &[], false),
            Err(Error::NoPath)
        );
        let bootstrap = select_avoiding(&ingress, &[own2, good3], &[], true).unwrap();
        assert!(bootstrap.one_operator);
        // A strict chain with the bloc relaxed comes before one operator.
        let first = select_avoiding(&ingress, &[own2, shared2, good3], &[], true).unwrap();
        assert!(!first.one_operator && first.relaxed);
        // Invariant 3 holds under the relaxation.
        let mut own_asn = own2;
        own_asn.asn = good3.asn;
        assert!(check(
            &ingress,
            &own_asn,
            &good3,
            Relax {
                hop2: true,
                operator: true,
                bloc: false,
                network: false
            }
        )
        .is_err());
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

    #[test]
    fn the_pins_follow_the_relay_set_and_no_other_cause() {
        let list = BlocList::v1();
        let eu = list.bloc_of(b"DE");
        let ids = |pins: &IngressPins| -> Vec<u8> {
            pins.pins().iter().map(|pin| pin.relay_id[0]).collect()
        };
        let mut same_operator = cand(2, eu, 0, true);
        same_operator.operator_id = [1; 32];
        let set = [
            cand(1, eu, 0, true),
            same_operator,
            cand(9, eu, 2, false),
            cand(3, eu, 0, true),
            cand(4, eu, 0, true),
        ];
        // The first relay, and then the first one of another operator. A
        // relay with no ingress flag takes no place.
        let mut pins = IngressPins::empty();
        assert!(pins.refresh(&set, 100, false));
        assert_eq!(ids(&pins), [1, 3]);
        // The same set in another order changes nothing.
        let mut turned = set;
        turned.reverse();
        assert!(!pins.refresh(&turned, 200, false));
        assert_eq!(ids(&pins), [1, 3]);

        // The stored form gives the same pins.
        assert!(pins.confirm(&[1; 32]));
        assert!(!pins.confirm(&[1; 32]));
        let stored = pins.encode();
        assert_eq!(stored.len(), 82);
        assert_eq!(IngressPins::parse(&stored).unwrap(), pins);
        assert!(IngressPins::parse(&stored[..81]).is_err());
        assert!(IngressPins::parse(&[stored.clone(), stored.clone()].concat()).is_err());
        let mut wrong = stored;
        wrong[40] = 2;
        assert!(IngressPins::parse(&wrong).is_err());

        // The confirmed pin ends at 60 days, and the other one stays.
        assert!(pins.refresh(&set, 100 + INGRESS_PIN_CONFIRMED, false));
        assert_eq!(ids(&pins), [3, 1]);
        assert_eq!(pins.pins()[1].pinned_at, 100 + INGRESS_PIN_CONFIRMED);
        // A relay that left the set loses its pin, and one relay gives one pin.
        assert!(pins.refresh(&set[..1], 100 + INGRESS_PIN_CONFIRMED + 1, false));
        assert_eq!(ids(&pins), [1]);
        assert!(!pins.refresh(&set[..1], 100 + INGRESS_PIN_CONFIRMED + 2, false));

        // NET-344: a provisional directory with one operator gives two pins
        // of that operator, and the second one ends with the relaxation
        // (NET-345).
        let one = [cand(1, eu, 0, true), same_operator];
        let mut pins = IngressPins::empty();
        assert!(pins.refresh(&one, 100, false));
        assert_eq!(ids(&pins), [1]);
        assert!(pins.refresh(&one, 101, true));
        assert_eq!(ids(&pins), [1, 2]);
        assert!(!pins.refresh(&one, 102, true));
        assert!(pins.refresh(&one, 103, false));
        assert_eq!(ids(&pins), [1]);
        // A relay of another operator comes first under the relaxation too.
        let mixed = [cand(1, eu, 0, true), same_operator, cand(3, eu, 0, true)];
        let mut pins = IngressPins::empty();
        assert!(pins.refresh(&mixed, 100, true));
        assert_eq!(ids(&pins), [1, 3]);
    }
}
