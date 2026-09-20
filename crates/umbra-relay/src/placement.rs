//! The place of this relay in a signed relay set: its layer, and the relays
//! of the next layer that it can extend a circuit to (Part 10 §10.5.4).

use std::collections::BTreeMap;

use umbra_core::directory::{
    bloc::BlocList,
    manifest::{ListedRelay, RelayManifest, RelaySet},
    root::{Consensus, DirectoryKeySet},
};
use umbra_transport::Dial;

/// Why a manifest gives this relay no place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    /// The manifest or the key set does not verify.
    Unverified,
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
    /// The epoch of the root.
    pub epoch: u64,
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
    let (keyset, _) = DirectoryKeySet::parse(keyset).map_err(unverified)?;
    // The operator of a relay gives it the manifest from its own disk, thus
    // no shipped epoch bounds the age of it.
    let mut consensus = Consensus::new(keyset, 0).map_err(unverified)?;
    let manifest = RelayManifest::parse(manifest).map_err(unverified)?;
    let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), device_clock)
        .map_err(unverified)?;
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
    Ok(Placement {
        layer,
        next,
        epoch: set.epoch,
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
        authority::{entry_of, keyset_bytes, sign_manifest, Listing, GENESIS_ROOT},
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
        let entry = entry_of(&listing, &GENESIS_ROOT, 0).unwrap();
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
}
