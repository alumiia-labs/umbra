//! The authority side of Part 10: the entry of a relay, the key set, and a
//! signed manifest. A test network and the test vectors use it. A client
//! calls nothing here.

use alloc::vec::Vec;

use umbra_crypto::{
    rand_core::TryCryptoRng,
    sign::{SigningKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};

use super::{
    bloc::BlocList,
    descriptor::{flags, roles, RelayDescriptor, RelayEntry, ENTRY_LEN},
    layer::layer,
    manifest::{ProvenEntry, RelayManifest},
    root::{AuthoritySig, DirectoryKeySet, DirectoryRoot},
    tree, EPOCH_SECONDS,
};
use crate::Error;

/// The root that the layer function takes for a relay of the first root of
/// a network. No root comes before that one.
pub const GENESIS_ROOT: [u8; 32] = [0; 32];

/// Where a relay of the chain population stands in its admission
/// (§10.5.4). An ingress relay takes neither state: `REL-156` names the
/// chain population alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The root lists the relay and places it in no layer. The layer comes
    /// from this root, and the next root carries it (`REL-156`).
    Pending,
    /// The root places the relay, under the root that listed it as pending
    /// (`REL-060`). `GENESIS_ROOT` at epoch 0 places the relays of the
    /// first root of a directory (`REL-159`).
    Placed {
        /// The root that listed the relay as pending.
        root: [u8; 32],
        /// Its epoch.
        epoch: u64,
    },
}

/// What an authority verified of one relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listing<'a> {
    /// The signed descriptor of the relay.
    pub descriptor: &'a [u8],
    /// One opaque value for each beneficial control.
    pub operator_id: [u8; 32],
    /// The verified class, 0 to 3.
    pub class: u8,
    /// Whether the relay is ingress eligible (`REL-130`).
    pub is_ingress: bool,
}

/// The entry of a relay at one stage of its admission (`REL-060`,
/// `REL-156`).
pub fn entry_of(listing: &Listing<'_>, admission: Admission) -> Result<Vec<u8>, Error> {
    let descriptor = RelayDescriptor::parse(listing.descriptor)?;
    let exit_roles = roles::QUEUE | roles::CHAIN;
    let flags = if listing.is_ingress {
        if descriptor.roles & roles::INGRESS_OFFERED == 0 {
            return Err(Error::Malformed);
        }
        flags::INGRESS
    } else {
        match admission {
            // REL-156: the first root of a chain relay places it nowhere.
            Admission::Pending => flags::PENDING,
            Admission::Placed { root, epoch } => {
                if descriptor.roles & exit_roles == exit_roles
                    && layer(&root, epoch, &descriptor.relay_id) == 3
                {
                    flags::LAYER_3
                } else {
                    0
                }
            }
        }
    };
    let entry = RelayEntry {
        descriptor,
        operator_id: listing.operator_id,
        class: listing.class,
        flags,
    };
    let mut out = alloc::vec![0u8; ENTRY_LEN];
    entry.encode(&mut out)?;
    // The rules of a client hold for what an authority signs.
    RelayEntry::parse(&out)?;
    Ok(out)
}

/// The canonical key set of `keys`, each under a control of its own.
pub fn keyset_bytes(keys: &[SigningKey], keyset_epoch: u64) -> Result<Vec<u8>, Error> {
    keyset_bytes_with(
        keys,
        keyset_epoch,
        u8::try_from(keys.len()).map_err(|_| Error::Malformed)?,
    )
}

/// The canonical key set of `keys`, with `independent_count` authorities
/// under different beneficial control (`REL-125`). A count below
/// `AUTHORITY_FLOOR` makes the directory provisional (`REL-126`).
pub fn keyset_bytes_with(
    keys: &[SigningKey],
    keyset_epoch: u64,
    independent_count: u8,
) -> Result<Vec<u8>, Error> {
    let public: Vec<[u8; VERIFYING_KEY_LEN]> = keys
        .iter()
        .map(|key| key.verifying_key().to_bytes())
        .collect();
    let keyset = DirectoryKeySet {
        keyset_epoch,
        independent_count,
        keys: public.iter().map(|key| key.as_slice()).collect(),
    };
    let mut out = alloc::vec![0u8; keyset.len()];
    keyset.encode(&mut out)?;
    Ok(out)
}

/// A manifest of the whole relay set `entries` for `epoch`, under the
/// signatures of the authorities `signers` of `keys`.
pub fn sign_manifest<R: TryCryptoRng + ?Sized>(
    keys: &[SigningKey],
    signers: &[u8],
    keyset_epoch: u64,
    epoch: u64,
    entries: Vec<Vec<u8>>,
    blocs: &BlocList,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let keyset = keyset_bytes(keys, keyset_epoch)?;
    sign_manifest_under(keys, &keyset, signers, epoch, entries, blocs, rng)
}

/// As [`sign_manifest`], under the key set bytes `keyset` of `keys`, as
/// [`keyset_bytes_with`] gives them.
pub fn sign_manifest_under<R: TryCryptoRng + ?Sized>(
    keys: &[SigningKey],
    keyset: &[u8],
    signers: &[u8],
    epoch: u64,
    mut entries: Vec<Vec<u8>>,
    blocs: &BlocList,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    // REL-054 and REL-055: ascending `relay_id`, each one time.
    let id_of = |entry: &Vec<u8>| entry.get(1..33).map(<[u8]>::to_vec);
    entries.sort_by_key(id_of);
    if entries.windows(2).any(|pair| match pair {
        [a, b] => id_of(a) == id_of(b),
        _ => false,
    }) {
        return Err(Error::Malformed);
    }
    let leaves: Vec<[u8; 32]> = entries.iter().map(|entry| tree::leaf(entry)).collect();
    let (keyset, _) = DirectoryKeySet::parse(keyset)?;
    let mut root = DirectoryRoot {
        epoch,
        epoch_start_unix: epoch.saturating_mul(EPOCH_SECONDS),
        root: tree::root(&leaves).ok_or(Error::Malformed)?,
        keyset_hash: keyset.hash()?,
        bloc_hash: blocs.hash()?,
        revoked: Vec::new(),
        sigs: Vec::new(),
    };
    let preimage = root.preimage();
    let mut signers = signers.to_vec();
    signers.sort_unstable();
    let mut signatures: Vec<(u8, [u8; SIGNATURE_LEN])> = Vec::with_capacity(signers.len());
    for index in signers {
        let key = keys.get(usize::from(index)).ok_or(Error::Malformed)?;
        signatures.push((index, key.sign(&preimage, rng)?.to_bytes()));
    }
    root.sigs = signatures
        .iter()
        .map(|(authority_index, sig)| AuthoritySig {
            authority_index: *authority_index,
            sig: sig.as_slice(),
        })
        .collect();
    let mut root_bytes = alloc::vec![0u8; 24_000];
    let root_len = root.encode(&mut root_bytes)?;
    root_bytes.truncate(root_len);

    let mut proven = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        proven.push(ProvenEntry {
            entry,
            proof: tree::prove(&leaves, index).ok_or(Error::Malformed)?,
        });
    }
    RelayManifest {
        root: &root_bytes,
        entries: proven,
        queues: Vec::new(),
        removals: Vec::new(),
    }
    .encode()
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
    use crate::directory::{
        descriptor::{tests::Rng, HOST_LEN},
        manifest::RelaySet,
        root::Consensus,
    };
    use alloc::vec;
    use umbra_crypto::secret::Secret;

    fn descriptor(seed: u8, roles: u8) -> Vec<u8> {
        let mut host = [0u8; HOST_LEN];
        host[..9].copy_from_slice(b"localhost");
        RelayDescriptor {
            relay_id: [0; 32],
            identity_pk: &[],
            ntor_pk: [seed; 32],
            addr_v4: [10, seed, 0, 1],
            addr_v6: [0; 16],
            port: 7_440 + u16::from(seed),
            host,
            asn: 64_500 + u32::from(seed),
            jurisdiction: *b"SE",
            family_id: [seed; 32],
            capacity_class: 2,
            roles,
            chunk_store_gib: 0,
            valid_after: 0,
            sig: &[],
        }
        .sign(
            &SigningKey::from_seed(Secret::new([seed; 32])),
            &mut Rng(seed),
        )
        .unwrap()
    }

    #[test]
    fn a_pending_relay_carries_no_traffic_and_takes_its_layer_from_that_root() {
        let exit_roles = roles::QUEUE | roles::CHAIN;
        let bytes = descriptor(11, exit_roles);
        let pending = entry_of(&listing(&bytes, false), Admission::Pending).unwrap();
        let read = RelayEntry::parse(&pending).unwrap();
        assert!(read.pending());
        // REL-157: the pending root names no layer.
        assert_eq!(read.layer(), 2);

        // REL-158: no hop takes it, whatever its descriptor offers.
        let blocs = BlocList::v1();
        let candidate = crate::directory::path::Candidate::from_entry(&read, &blocs);
        assert!(!candidate.chain && !candidate.queue && !candidate.ingress);
        assert!(!candidate.is_exit());

        // The layer of the next root comes from the pending root, and no
        // earlier root moves it.
        let pending_root = [0x5C; 32];
        let placed = entry_of(
            &listing(&bytes, false),
            Admission::Placed {
                root: pending_root,
                epoch: 77,
            },
        )
        .unwrap();
        let read = RelayEntry::parse(&placed).unwrap();
        assert!(!read.pending());
        assert_eq!(
            read.layer(),
            layer(&pending_root, 77, &read.descriptor.relay_id)
        );

        // An entry that sets the pending bit with the layer bit is a fault
        // of the authority, and a client rejects it (`REL-157`).
        let mut both = placed.clone();
        let flags = both.len() - 1;
        both[flags] = flags::PENDING | flags::LAYER_3;
        assert!(RelayEntry::parse(&both).is_err());
        both[flags] = flags::PENDING | flags::INGRESS;
        assert!(RelayEntry::parse(&both).is_ok());
        both[flags] = 0x08;
        assert!(RelayEntry::parse(&both).is_err());
    }

    #[test]
    fn a_client_accepts_what_an_authority_signs() {
        let keys: Vec<SigningKey> = (0..7u8)
            .map(|index| SigningKey::from_seed(Secret::new([0xA0 + index; 32])))
            .collect();
        let exit_roles = roles::QUEUE | roles::CHAIN;
        let ingress = descriptor(1, roles::INGRESS_OFFERED | roles::CHAIN);
        let mut entries = vec![entry_of(
            &listing(&ingress, true),
            Admission::Placed {
                root: GENESIS_ROOT,
                epoch: 0,
            },
        )
        .unwrap()];
        let mut expected_exits = 0;
        for seed in 2..10u8 {
            let bytes = descriptor(seed, exit_roles);
            let entry = entry_of(
                &listing(&bytes, false),
                Admission::Placed {
                    root: GENESIS_ROOT,
                    epoch: 0,
                },
            )
            .unwrap();
            let read = RelayEntry::parse(&entry).unwrap();
            // The flag follows the function, and no party selects it.
            assert_eq!(
                read.layer(),
                layer(&GENESIS_ROOT, 0, &read.descriptor.relay_id)
            );
            expected_exits += usize::from(read.layer() == 3);
            entries.push(entry);
        }
        // A relay with no queue role is of layer 2 under each root.
        let plain = descriptor(10, roles::CHAIN);
        let entry = entry_of(
            &listing(&plain, false),
            Admission::Placed {
                root: GENESIS_ROOT,
                epoch: 0,
            },
        )
        .unwrap();
        assert_eq!(RelayEntry::parse(&entry).unwrap().layer(), 2);
        entries.push(entry);
        // An ingress flag needs the offer of the relay.
        assert!(entry_of(
            &listing(&plain, true),
            Admission::Placed {
                root: GENESIS_ROOT,
                epoch: 0
            }
        )
        .is_err());

        let blocs = BlocList::v1();
        let manifest = sign_manifest(
            &keys,
            &[6, 0, 1, 3, 4],
            1,
            500,
            entries.clone(),
            &blocs,
            &mut Rng(9),
        )
        .unwrap();
        let keyset = keyset_bytes(&keys, 1).unwrap();
        let (keyset, _) = DirectoryKeySet::parse(&keyset).unwrap();
        let mut consensus = Consensus::new(keyset, 400).unwrap();
        let read = RelayManifest::parse(&manifest).unwrap();
        let set = RelaySet::accept(&mut consensus, &read, &blocs, 500 * 3_600).unwrap();
        assert_eq!(set.relays.len(), 10);
        let exits = set.relays.iter().filter(|relay| relay.candidate.is_exit());
        assert_eq!(exits.count(), expected_exits);
        assert!(expected_exits > 0 && expected_exits < 8);
        assert_eq!(set.relays.iter().filter(|r| r.candidate.ingress).count(), 1);

        // One relay two times gives no manifest.
        entries.push(entries[0].clone());
        assert!(sign_manifest(
            &keys,
            &[0, 1, 2, 3, 4],
            1,
            500,
            entries,
            &blocs,
            &mut Rng(9)
        )
        .is_err());
    }

    /// Each relay of this test has an operator of its own.
    fn listing(descriptor: &[u8], is_ingress: bool) -> Listing<'_> {
        Listing {
            descriptor,
            operator_id: [descriptor[40]; 32],
            class: 2,
            is_ingress,
        }
    }
}
