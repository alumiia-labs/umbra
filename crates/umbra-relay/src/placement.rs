//! The place of this relay in a signed relay set: its layer, and the relays
//! of the next layer that it can extend a circuit to (Part 10 §10.5.4).

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use umbra_core::directory::{
    bloc::BlocList,
    manifest::{ListedRelay, RelayManifest, RelaySet},
    measure::MeasurerTrust,
    root::{Consensus, DirectoryKeySet, DirectoryRoot},
    CLOCK_SKEW, CONSENSUS_VALIDITY,
};
use umbra_transport::Dial;

/// Why a manifest gives this relay no place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    /// The manifest or the key set does not verify.
    Unverified,
    /// The manifest holds a part of the relay set (`REL-147`).
    Partial,
    /// The manifest does not list this relay.
    NotListed,
    /// The entry of this relay names another static key than its settings.
    OtherKey,
}

/// The place of one relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The layer of this relay, from 1 to 3 (`REL-061`).
    pub layer: u8,
    /// Where to dial each relay of the next layer (`NET-167`).
    pub next: BTreeMap<[u8; 32], Dial>,
    /// The layer and the static key of each relay with the chain role in a
    /// layer after this one, for the loop chains of this relay (Part 3
    /// `NET-363`).
    pub chain_keys: BTreeMap<[u8; 32], (u8, [u8; 32])>,
    /// The relays of the layer before, which dial this relay for the
    /// circuits of their clients (Part 3 `NET-332`).
    pub previous: BTreeSet<[u8; 32]>,
    /// The address of each relay of the set. The cap of one address counts
    /// none of them (Part 3 `NET-334`).
    pub addresses: BTreeSet<IpAddr>,
    /// The time at which the root of the manifest ends: `CONSENSUS_VALIDITY`
    /// and `CLOCK_SKEW` after its start (`REL-035`).
    pub valid_until: u64,
    /// Where to dial each other relay with the attachment role, for the
    /// copy of a chunk (Part 12 §12.4.1).
    pub replicas: BTreeMap<[u8; 32], Dial>,
    /// Where to dial each queue relay, with its static key, for the deposit
    /// of a digest (Part 6 `WIR-526`).
    pub queue_relays: BTreeMap<[u8; 32], (Dial, [u8; 32])>,
    /// Where to dial each carrier of the manifest, the relays with the
    /// ingress flag, which serve the challenge of this relay (`ABU-102`).
    pub carriers: BTreeMap<[u8; 32], Dial>,
    /// The identity key of each relay of the set, for a challenge that this
    /// relay carries (`ABU-103`).
    pub identities: BTreeMap<[u8; 32], Vec<u8>>,
    /// Whether this relay has the attachment role.
    pub has_attachment_role: bool,
    /// The epoch of the root.
    pub epoch: u64,
    /// The key set and the revoked list of the root, under which this
    /// relay accepts a `MeasurerCert` (`REL-066`, `REL-104`).
    pub measurer_trust: MeasurerTrust,
}

fn layer_of(relay: &ListedRelay) -> u8 {
    relay.candidate.layer
}

fn dial_of(relay: &ListedRelay) -> Dial {
    Dial {
        host: relay.host.clone(),
        addr_v4: (relay.addr_v4 != [0; 4]).then_some(relay.addr_v4),
        addr_v6: (relay.addr_v6 != [0; 16]).then_some(relay.addr_v6),
        port: relay.port,
    }
}

impl Placement {
    /// Where to dial each relay that takes a push of this relay. A push is a
    /// chunk copy (Part 12 §12.4.1), the challenge of this relay
    /// (`ABU-102`), or the deposit of a digest (`WIR-526`). Each goes on a
    /// one-shot connection.
    pub fn pushes(&self) -> BTreeMap<[u8; 32], Dial> {
        let mut pushes = self.replicas.clone();
        for (relay_id, dial) in &self.carriers {
            pushes.entry(*relay_id).or_insert_with(|| dial.clone());
        }
        for (relay_id, (dial, _)) in &self.queue_relays {
            pushes.entry(*relay_id).or_insert_with(|| dial.clone());
        }
        pushes
    }
}

/// Reads the place of the relay `relay_id` with the static key `ntor_pk`
/// from a manifest under the key set `keyset`. The manifest must hold the
/// whole relay set, because a relay that it leaves out is no next hop.
pub fn placement(
    manifest: &[u8],
    keyset: &[u8],
    relay_id: &[u8; 32],
    ntor_pk: &[u8; 32],
    device_clock: u64,
) -> Result<Placement, PlacementError> {
    let unverified = |_| PlacementError::Unverified;
    let keyset_bytes = keyset;
    let (keyset, _) = DirectoryKeySet::parse(keyset).map_err(unverified)?;
    // The operator of a relay gives it the manifest from its own disk, thus
    // no shipped epoch bounds the age of it.
    let mut consensus = Consensus::new(keyset, 0).map_err(unverified)?;
    let manifest = RelayManifest::parse(manifest).map_err(unverified)?;
    let root = DirectoryRoot::parse(manifest.root).map_err(unverified)?;
    let valid_until = root
        .epoch_start_unix
        .saturating_add(CONSENSUS_VALIDITY)
        .saturating_add(CLOCK_SKEW);
    // The signatures of the root cover the list, and `RelaySet::accept`
    // below verifies them.
    let measurer_trust = MeasurerTrust {
        keyset: keyset_bytes.to_vec(),
        revoked: root.revoked,
    };
    let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), device_clock)
        .map_err(unverified)?;
    // REL-147: a part of the set passes each proof. It would give this
    // relay a next layer, a previous layer, and an address set that each
    // lack a relay. A part thus places no relay.
    if !set.is_whole {
        return Err(PlacementError::Partial);
    }
    let own = set
        .relays
        .iter()
        .find(|relay| relay.candidate.relay_id == *relay_id)
        .ok_or(PlacementError::NotListed)?;
    if own.ntor_pk != *ntor_pk {
        return Err(PlacementError::OtherKey);
    }
    let layer = layer_of(own);
    let next = set
        .relays
        .iter()
        .filter(|relay| relay.candidate.chain && layer_of(relay) == layer.saturating_add(1))
        .map(|relay| (relay.candidate.relay_id, dial_of(relay)))
        .collect();
    let chain_keys = set
        .relays
        .iter()
        .filter(|relay| relay.candidate.chain && layer_of(relay) > layer)
        .map(|relay| (relay.candidate.relay_id, (layer_of(relay), relay.ntor_pk)))
        .collect();
    let previous = set
        .relays
        .iter()
        .filter(|relay| relay.candidate.chain && layer_of(relay).saturating_add(1) == layer)
        .map(|relay| relay.candidate.relay_id)
        .collect();
    let addresses = set
        .relays
        .iter()
        .flat_map(|relay| {
            let v4 = (relay.addr_v4 != [0; 4]).then(|| IpAddr::from(relay.addr_v4));
            let v6 = (relay.addr_v6 != [0; 16]).then(|| IpAddr::from(relay.addr_v6));
            v4.into_iter().chain(v6)
        })
        .collect();
    let replicas = set
        .relays
        .iter()
        .filter(|relay| relay.has_attachment_role && relay.candidate.relay_id != *relay_id)
        .map(|relay| (relay.candidate.relay_id, dial_of(relay)))
        .collect();
    let queue_relays = set
        .relays
        .iter()
        .filter(|relay| layer_of(relay) == 3 && relay.candidate.relay_id != *relay_id)
        .map(|relay| (relay.candidate.relay_id, (dial_of(relay), relay.ntor_pk)))
        .collect();
    let carriers = set
        .relays
        .iter()
        .filter(|relay| relay.candidate.ingress)
        .map(|relay| (relay.candidate.relay_id, dial_of(relay)))
        .collect();
    let identities = set
        .relays
        .iter()
        .map(|relay| (relay.candidate.relay_id, relay.identity_pk.clone()))
        .collect();
    Ok(Placement {
        layer,
        next,
        chain_keys,
        previous,
        addresses,
        valid_until,
        replicas,
        queue_relays,
        carriers,
        identities,
        has_attachment_role: own.has_attachment_role,
        epoch: set.epoch,
        measurer_trust,
    })
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
    use umbra_core::directory::{
        authority::{entry_of, keyset_bytes, sign_manifest, Admission, Listing, GENESIS_ROOT},
        descriptor::{roles, RelayDescriptor, RelayEntry, HOST_LEN},
    };
    use umbra_crypto::{rand_core, secret::Secret, sign::SigningKey};

    struct Rng(u8);
    impl rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(self.0);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Rng {}

    /// The entry of the relay `seed`, and what its settings hold of it.
    fn relay(seed: u8, is_ingress: bool) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let mut host = [0u8; HOST_LEN];
        host[..9].copy_from_slice(b"localhost");
        let relay_roles = if is_ingress {
            roles::INGRESS_OFFERED | roles::CHAIN
        } else {
            roles::QUEUE | roles::CHAIN
        };
        let descriptor = RelayDescriptor {
            relay_id: [0; 32],
            identity_pk: &[],
            ntor_pk: [seed; 32],
            addr_v4: [127, seed, 0, 1],
            addr_v6: [0; 16],
            port: 7_440 + u16::from(seed),
            host,
            asn: u32::from(seed),
            jurisdiction: *b"SE",
            family_id: [seed; 32],
            capacity_class: 2,
            roles: relay_roles,
            chunk_store_gib: 0,
            valid_after: 0,
            sig: &[],
        }
        .sign(
            &SigningKey::from_seed(Secret::new([seed; 32])),
            &mut Rng(seed),
        )
        .unwrap();
        let listing = Listing {
            descriptor: &descriptor,
            operator_id: [seed; 32],
            class: 2,
            is_ingress,
        };
        let entry = entry_of(
            &listing,
            Admission::Placed {
                root: GENESIS_ROOT,
                epoch: 0,
            },
        )
        .unwrap();
        let relay_id = RelayEntry::parse(&entry).unwrap().descriptor.relay_id;
        (entry, relay_id, [seed; 32])
    }

    #[test]
    fn a_relay_reads_its_layer_and_the_next_layer_from_a_manifest() {
        let keys: Vec<SigningKey> = (0..7u8)
            .map(|index| SigningKey::from_seed(Secret::new([0xB0 + index; 32])))
            .collect();
        let relays: Vec<_> = (1..=9u8).map(|seed| relay(seed, seed == 1)).collect();
        let entries = relays.iter().map(|(entry, _, _)| entry.clone()).collect();
        let manifest = sign_manifest(
            &keys,
            &[0, 1, 2, 3, 4],
            1,
            700,
            entries,
            &BlocList::v1(),
            &mut Rng(3),
        )
        .unwrap();
        let keyset = keyset_bytes(&keys, 1).unwrap();
        let place = |relay_id: &[u8; 32], key: &[u8; 32]| {
            placement(&manifest, &keyset, relay_id, key, 700 * 3_600)
        };

        let placed: Vec<Placement> = relays
            .iter()
            .map(|(_, relay_id, key)| place(relay_id, key).unwrap())
            .collect();
        let count_of = |layer: u8| placed.iter().filter(|p| p.layer == layer).count();
        assert_eq!(placed[0].layer, 1);
        assert_eq!(count_of(1), 1);
        assert!(count_of(2) > 0 && count_of(3) > 0);
        for place in &placed {
            // A relay dials each relay of the next layer, and no other one.
            let expected = match place.layer {
                3 => 0,
                layer => count_of(layer + 1),
            };
            assert_eq!(place.next.len(), expected);
            assert_eq!(place.epoch, 700);
            // NET-332: the relays that dial this one are the layer before.
            let before = match place.layer {
                1 => 0,
                layer => count_of(layer - 1),
            };
            assert_eq!(place.previous.len(), before);
            // NET-334: the set gives the address of each of its relays.
            assert_eq!(place.addresses.len(), relays.len());
            assert!(place.valid_until > 700 * 3_600);
            // REL-066: a `MeasurerCert` verifies under the key set of the
            // root, with its revoked list.
            assert_eq!(place.measurer_trust.keyset, keyset);
            assert!(place.measurer_trust.revoked.is_empty());
        }
        let of_layer_2 = placed.iter().position(|p| p.layer == 2).unwrap();
        let (_, id_of_2, _) = &relays[of_layer_2];
        assert!(placed[0].next.contains_key(id_of_2));
        assert_eq!(placed[0].next[id_of_2].port, 7_441 + of_layer_2 as u16);

        let (_, relay_id, key) = &relays[2];
        assert_eq!(place(&[9; 32], key), Err(PlacementError::NotListed));
        assert_eq!(place(relay_id, &[0xEE; 32]), Err(PlacementError::OtherKey));
        let other_keys: Vec<SigningKey> = (0..7u8)
            .map(|index| SigningKey::from_seed(Secret::new([0xC0 + index; 32])))
            .collect();
        let other_keyset = keyset_bytes(&other_keys, 1).unwrap();
        assert_eq!(
            placement(&manifest, &other_keyset, relay_id, key, 0),
            Err(PlacementError::Unverified)
        );
    }

    #[test]
    fn a_manifest_that_holds_a_part_of_the_set_places_no_relay() {
        let keys: Vec<SigningKey> = (0..7u8)
            .map(|index| SigningKey::from_seed(Secret::new([0xB0 + index; 32])))
            .collect();
        let relays: Vec<_> = (1..=9u8).map(|seed| relay(seed, seed == 1)).collect();
        let entries = relays.iter().map(|(entry, _, _)| entry.clone()).collect();
        let whole = sign_manifest(
            &keys,
            &[0, 1, 2, 3, 4],
            1,
            700,
            entries,
            &BlocList::v1(),
            &mut Rng(3),
        )
        .unwrap();
        let keyset = keyset_bytes(&keys, 1).unwrap();
        let (_, relay_id, key) = &relays[0];
        assert!(placement(&whole, &keyset, relay_id, key, 700 * 3_600).is_ok());

        // REL-147: each entry that stays has its proof under the signed
        // root, and the manifest lacks one relay. The relay that it lists
        // takes no place from it.
        let mut part = RelayManifest::parse(&whole).unwrap();
        let other = part
            .entries
            .iter()
            .position(|proven| {
                RelayEntry::parse(proven.entry).unwrap().descriptor.relay_id != *relay_id
            })
            .unwrap();
        part.entries.remove(other);
        let part = part.encode().unwrap();
        assert_eq!(
            placement(&part, &keyset, relay_id, key, 700 * 3_600),
            Err(PlacementError::Partial)
        );
    }
}
