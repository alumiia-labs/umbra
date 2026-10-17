//! The verified read of the log of Part 9 §9.5 through the directory of
//! §9.10: the search key of a label (`DIS-164`), the lookup and its proof
//! under a head that verifies under the pinned key set (`DIS-054` to
//! `DIS-062`, `DIS-066`), the consistency of each new head with the held one
//! (`DIS-061`), a version of a label (`DIS-183`), and the key of an issuer
//! (Part 13 §13.5). A client and a relay each read the log with these, over
//! a [`LogChannel`] that carries one padded request and keeps the held head
//! and the held key set. A head under a later key set takes the signed
//! rotations to that set (`DIS-199`), and a head past its freshness gives
//! the degraded read of `DIS-067`.

use alloc::vec::Vec;

use umbra_crypto::{rand_core::TryCryptoRng, rsabssa::PublicKey2048, vrf};
use umbra_wire::directory::{Kind, Status};

use super::{
    dirclient::{self, DirError, DirectoryPins},
    head::{AcceptedHead, Freshness, HeadState, LogKeySet, SignedTreeHead, KEYSET_LEN},
    translog::LookupProof,
};
use crate::abuse::{
    epoch_number,
    issuer::{issuer_label_input, IssuerKeyEntry},
    token::TYPE_CROSS_RELAY,
};

/// A head that a reader accepted: its size, its root, and its timestamp.
pub type HeldHead = (u64, [u8; 32], u64);

/// The tries of a lookup whose head and proof name two epochs, since an
/// epoch closed between the two requests.
pub const HEAD_TRIES: usize = 3;

/// The key-set requests of one head. Each answer holds a few rotations, and
/// a rotation is rare (`DIS-199`).
pub const KEYSET_ROUNDS: usize = 4;

/// Why a read of the log gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// No answer came.
    Offline,
    /// The directory is busy, or an epoch closed at each try.
    Busy,
    /// The log is older than a head that the reader holds, or the clock of
    /// a head is off.
    Stale,
    /// An answer did not verify.
    Unverified,
    /// The label holds no entry.
    NotFound,
    /// An answer did not parse.
    Malformed,
    /// A request did not fit its size.
    TooLong,
}

impl From<DirError> for ReadError {
    fn from(error: DirError) -> Self {
        match error {
            DirError::Malformed | DirError::Status(Status::Malformed) => ReadError::Malformed,
            DirError::Status(Status::Refused) => ReadError::Unverified,
            DirError::Status(Status::NotFound) => ReadError::NotFound,
            DirError::Status(Status::Stale) => ReadError::Stale,
            DirError::Status(Status::Busy | Status::Done) => ReadError::Busy,
        }
    }
}

/// The path of a reader to the directory, and what it holds.
pub trait LogChannel {
    /// Carries one padded request, and gives the padded response.
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, ReadError>;
    /// The keys that the build or the configuration pins.
    fn pins(&self) -> &DirectoryPins;
    /// The newest head that the reader accepted.
    fn held(&self) -> Option<HeldHead>;
    /// Holds a newer head.
    fn set_held(&self, head: HeldHead);
    /// The clock, in seconds.
    fn now(&self) -> u64;
    /// The encoded `LogKeySet` that the reader holds: the genesis set of
    /// the pins, or a later set that a signed rotation gave (`DIS-199`).
    fn keyset(&self) -> Vec<u8> {
        self.pins().keyset.clone()
    }
    /// Holds a later key set, which a signed rotation gave.
    fn set_keyset(&self, _keyset: Vec<u8>) {}
}

/// An entry as the log shows it under a head that verified.
pub struct Found {
    /// The entry bytes, or none for a label with no version.
    pub entry: Option<Vec<u8>>,
    /// The newest version of the label.
    pub version: Option<u32>,
    /// The sealed profile blob that the directory keeps beside the label.
    pub blob: Option<Vec<u8>>,
    /// Whether the read is the degraded read of `DIS-067`: the head failed
    /// its freshness, thus the result is unverified (`DIS-068`).
    pub degraded: bool,
}

/// Sends one request and returns the body of a done answer.
pub fn send<C: LogChannel + ?Sized>(
    channel: &C,
    kind: Kind,
    body: &[u8],
) -> Result<Vec<u8>, ReadError> {
    let request = dirclient::request(kind, body).map_err(|_| ReadError::TooLong)?;
    let response = channel.call(&request)?;
    Ok(dirclient::done(&response)?)
}

fn keyset_hash(bytes: &[u8]) -> Result<[u8; 32], ReadError> {
    LogKeySet::parse(bytes)
        .and_then(|(set, _)| set.hash())
        .map_err(|_| ReadError::Malformed)
}

/// The key set that a head names: the held set, or a later one after the
/// signed rotations from the held set (`DIS-064`, `DIS-065`, `DIS-199`).
/// The reader keeps each rotation that verified.
pub fn keyset_for<C: LogChannel + ?Sized>(
    channel: &C,
    wanted: &[u8; 32],
) -> Result<Vec<u8>, ReadError> {
    let mut held = channel.keyset();
    if keyset_hash(&held)? == *wanted {
        return Ok(held);
    }

    for _ in 0..KEYSET_ROUNDS {
        let epoch = LogKeySet::parse(&held)
            .map_err(|_| ReadError::Malformed)?
            .0
            .keyset_epoch;
        let answer = send(channel, Kind::KeySet, &dirclient::keyset_body(epoch))?;
        let signed = dirclient::parse_keysets(&answer).map_err(|_| ReadError::Malformed)?;
        if signed.is_empty() {
            break;
        }

        for link in &signed {
            let (set, _) = LogKeySet::parse(&held).map_err(|_| ReadError::Malformed)?;
            let next = set.rotate(link).map_err(|_| ReadError::Unverified)?;

            let mut bytes = alloc::vec![0u8; KEYSET_LEN];
            let used = next.encode(&mut bytes).map_err(|_| ReadError::Malformed)?;
            bytes.truncate(used);

            channel.set_keyset(bytes.clone());
            held = bytes;

            if keyset_hash(&held)? == *wanted {
                return Ok(held);
            }
        }
    }

    // DIS-060: no signed rotation reaches the set of the head.
    Err(ReadError::Unverified)
}

/// Verifies a head under the held key set (`DIS-054` to `DIS-060`), and
/// tests its clock (`DIS-011`, `DIS-062`).
pub fn verify_head<'a, C: LogChannel + ?Sized>(
    channel: &C,
    bytes: &'a [u8],
    now: u64,
) -> Result<(SignedTreeHead<'a>, Freshness), ReadError> {
    let head = SignedTreeHead::parse(bytes).map_err(|_| ReadError::Malformed)?;
    let held = keyset_for(channel, &head.keyset_hash)?;
    let (keyset, _) = LogKeySet::parse(&held).map_err(|_| ReadError::Malformed)?;
    let heads = HeadState::new(keyset).map_err(|_| ReadError::Malformed)?;
    let freshness = heads.check(&head, now).map_err(|_| ReadError::Unverified)?;
    Ok((head, freshness))
}

/// The ECVRF key of the log.
pub fn vrf_key<C: LogChannel + ?Sized>(channel: &C) -> Result<vrf::PublicKey, ReadError> {
    vrf::PublicKey::from_bytes(&channel.pins().vrf_public).map_err(|_| ReadError::Malformed)
}

/// The search key of a label input, under a proof of work at the floor
/// (`DIS-164`).
pub fn search_key<C: LogChannel + ?Sized, R: TryCryptoRng + ?Sized>(
    channel: &C,
    input: &[u8],
    rng: &mut R,
) -> Result<[u8; 64], ReadError> {
    let pk = channel.pins().voprf_public;
    let epoch = epoch_number(channel.now());
    let (state, body) = dirclient::evaluate_request(input, &pk, epoch, None, rng)
        .map_err(|_| ReadError::Malformed)?;

    let evaluated = send(channel, Kind::Evaluate, &body)?;
    dirclient::evaluate_finish(&state, &evaluated, &pk).map_err(|_| ReadError::Unverified)
}

/// Whether a head extends the held head: a smaller log is a rollback
/// (`DIS-061`), a second root at one size is a split view, and a larger log
/// proves that it holds the held one. `false` is a proof that names another
/// head, which a new lookup settles.
pub fn extends_held<C: LogChannel + ?Sized>(
    channel: &C,
    head: &SignedTreeHead<'_>,
    now: u64,
) -> Result<bool, ReadError> {
    let Some((size, root, _)) = channel.held() else {
        return Ok(true);
    };

    if head.tree_size < size {
        return Err(ReadError::Stale);
    }

    if head.tree_size == size {
        return if head.root == root {
            Ok(true)
        } else {
            Err(ReadError::Unverified)
        };
    }

    let answer = send(channel, Kind::Head, &size.to_be_bytes())?;
    let (newest, consistency) = dirclient::parse_head(&answer).map_err(|_| ReadError::Malformed)?;
    let (newest, _) = verify_head(channel, &newest, now)?;

    if newest.tree_size != head.tree_size || newest.root != head.root {
        return Ok(false);
    }

    super::logtree::verify_consistency(size, &root, head.tree_size, &head.root, &consistency)
        .map_err(|_| ReadError::Unverified)?;
    Ok(true)
}

/// Verifies the head of an answer and holds it when it extends the held
/// head, or gives none for a head whose proof names another epoch. A head
/// past its freshness is stale here.
pub fn accept_head<C: LogChannel + ?Sized>(
    channel: &C,
    bytes: &[u8],
) -> Result<Option<AcceptedHead>, ReadError> {
    match read_head(channel, bytes)? {
        Some((_, true)) => Err(ReadError::Stale),
        Some((head, false)) => Ok(Some(head)),
        None => Ok(None),
    }
}

/// The head of an answer, and whether it gives the degraded read
/// (`DIS-067`). A fresh head that extends the held head is held. A head past
/// its freshness is not held, and it still extends the held head, thus
/// `DIS-061` holds in the degraded read too.
pub fn read_head<C: LogChannel + ?Sized>(
    channel: &C,
    bytes: &[u8],
) -> Result<Option<(AcceptedHead, bool)>, ReadError> {
    let now = channel.now();
    let (head, freshness) = verify_head(channel, bytes, now)?;
    if !extends_held(channel, &head, now)? {
        return Ok(None);
    }

    let degraded = freshness == Freshness::Degraded;
    if !degraded {
        channel.set_held((head.tree_size, head.root, head.timestamp));
    }

    Ok(Some((
        AcceptedHead {
            tree_size: head.tree_size,
            root: head.root,
            timestamp: head.timestamp,
            accepted_at: now,
        },
        degraded,
    )))
}

/// The lookup proof of a search key under the newest head, after the head
/// verified under the held key set (`DIS-066`). A head past its freshness
/// is stale here.
pub fn lookup<C: LogChannel + ?Sized>(
    channel: &C,
    search_key: &[u8; 64],
) -> Result<(LookupProof, AcceptedHead, Option<Vec<u8>>), ReadError> {
    match lookup_read(channel, search_key)? {
        (_, _, _, true) => Err(ReadError::Stale),
        (proof, head, blob, false) => Ok((proof, head, blob)),
    }
}

/// A lookup and whether it is the degraded read (`DIS-067`).
type LookupRead = (LookupProof, AcceptedHead, Option<Vec<u8>>, bool);

fn lookup_read<C: LogChannel + ?Sized>(
    channel: &C,
    search_key: &[u8; 64],
) -> Result<LookupRead, ReadError> {
    for _ in 0..HEAD_TRIES {
        let looked = send(channel, Kind::Lookup, search_key)?;
        let (bytes, blob, proof) =
            dirclient::parse_lookup(&looked).map_err(|_| ReadError::Malformed)?;

        if let Some((head, degraded)) = read_head(channel, &bytes)? {
            return Ok((proof, head, blob, degraded));
        }
    }
    Err(ReadError::Busy)
}

/// The entry of one version of a label, verified under the log
/// (`DIS-183`, `DIS-184`).
pub fn version_entry<C: LogChannel + ?Sized>(
    channel: &C,
    search_key: &[u8; 64],
    version: u32,
) -> Result<Vec<u8>, ReadError> {
    let body = dirclient::version_body(search_key, version);

    for _ in 0..HEAD_TRIES {
        let answer = send(channel, Kind::Version, &body)?;
        let (bytes, proof) = dirclient::parse_version(&answer).map_err(|_| ReadError::Malformed)?;

        if let Some(head) = accept_head(channel, &bytes)? {
            return proof
                .verify(search_key, version, &vrf_key(channel)?, &head)
                .map(<[u8]>::to_vec)
                .map_err(|_| ReadError::Unverified);
        }
    }
    Err(ReadError::Busy)
}

/// The newest entry of a label input and its search key.
pub fn find_keyed<C: LogChannel + ?Sized, R: TryCryptoRng + ?Sized>(
    channel: &C,
    input: &[u8],
    rng: &mut R,
) -> Result<(Found, [u8; 64]), ReadError> {
    let search_key = search_key(channel, input, rng)?;

    // DIS-067: a head past its freshness still completes the lookup.
    let (proof, head, blob, degraded) = lookup_read(channel, &search_key)?;
    let entry = proof
        .verify(&search_key, &vrf_key(channel)?, &head)
        .map_err(|_| ReadError::Unverified)?
        .map(<[u8]>::to_vec);

    let found = Found {
        entry,
        version: proof.newest,
        blob,
        degraded,
    };
    Ok((found, search_key))
}

/// The key of the cross-relay issuer of `epoch` from the log: version 0 of
/// its label, of that type and that epoch (Part 13 `ABU-099` to `ABU-101`).
pub fn cross_relay_key<C: LogChannel + ?Sized, R: TryCryptoRng + ?Sized>(
    channel: &C,
    epoch: u32,
    rng: &mut R,
) -> Result<PublicKey2048, ReadError> {
    let (found, _) = find_keyed(channel, &issuer_label_input(TYPE_CROSS_RELAY, epoch), rng)?;

    // An unverified read gives no key that admits a token.
    if found.degraded {
        return Err(ReadError::Stale);
    }

    let bytes = found.entry.ok_or(ReadError::NotFound)?;
    let entry = IssuerKeyEntry::parse(&bytes).map_err(|_| ReadError::Unverified)?;
    if found.version != Some(0) || entry.token_type != TYPE_CROSS_RELAY || entry.epoch != epoch {
        return Err(ReadError::Unverified);
    }

    PublicKey2048::from_modulus(&entry.public_key).map_err(|_| ReadError::Unverified)
}
