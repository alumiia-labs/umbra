//! The key chain of Part 10 §10.5.2: each `SignedKeySet` since the first key
//! set, in order, each one under five or more signatures of the set before
//! it (`REL-036`). A carrier serves it beside the manifest (`REL-199`), and
//! a client or a relay that holds an older key set walks it forward
//! (`REL-200`).
//!
//! ```text
//! KeyChain {
//!     version     u8          // 0x01
//!     count       u8          // 1 to KEYCHAIN_MAX (28)
//!     links       [count] { len u32, SignedKeySet }
//! }
//! ```

use alloc::vec::Vec;

use umbra_crypto::{labels, rand_core::TryCryptoRng, sign::SigningKey};
use umbra_wire::codec::{Reader, Writer};

use super::root::DirectoryKeySet;
use crate::Error;

/// The links that one chain holds at most. A rotation is rare; the bound
/// keeps a carrier from making a client verify an unbounded chain, and 28
/// links of about 36 850 bytes fit the 1 MiB body of `REL-199`.
pub const KEYCHAIN_MAX: usize = 28;

/// The `SignedKeySet` of `next`, a canonical key set, under each key of
/// `previous` (`REL-036`, `REL-042`).
pub fn sign_keyset<R: TryCryptoRng + ?Sized>(
    previous: &[SigningKey],
    next: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let (parsed, used) = DirectoryKeySet::parse(next)?;
    if used != next.len() {
        return Err(Error::Malformed);
    }
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(labels::DIRECTORY_KEYSET);
    preimage.push(0x01);
    preimage.extend_from_slice(&parsed.keyset_epoch.to_be_bytes());
    preimage.extend_from_slice(&parsed.hash()?);
    let mut sigs = Vec::with_capacity(previous.len());
    for key in previous {
        sigs.push(key.sign(&preimage, rng)?.to_bytes());
    }
    let count = u8::try_from(sigs.len()).map_err(|_| Error::Malformed)?;
    let mut out = alloc::vec![0u8; next.len().saturating_add(1).saturating_add(sigs.len().saturating_mul(1 + umbra_crypto::sign::SIGNATURE_LEN))];
    out.get_mut(..next.len())
        .ok_or(Error::Malformed)?
        .copy_from_slice(next);
    let mut w = Writer::new(out.get_mut(next.len()..).ok_or(Error::Malformed)?);
    w.u8(count)?;
    for (index, sig) in (0u8..).zip(sigs.iter()) {
        w.u8(index)?;
        w.put(sig)?;
    }
    Ok(out)
}

/// The links of a chain, in order.
pub fn links(chain: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let mut r = Reader::new(chain);
    if r.u8()? != 0x01 {
        return Err(Error::Malformed);
    }
    let count = usize::from(r.u8()?);
    if count == 0 || count > KEYCHAIN_MAX {
        return Err(Error::Malformed);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = usize::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
        out.push(r.take(len)?);
    }
    r.finish()?;
    Ok(out)
}

/// The chain of `links`, each a `SignedKeySet`.
pub fn encode(links: &[&[u8]]) -> Result<Vec<u8>, Error> {
    if links.is_empty() || links.len() > KEYCHAIN_MAX {
        return Err(Error::Malformed);
    }
    let size = links
        .iter()
        .map(|link| link.len().saturating_add(4))
        .sum::<usize>()
        .saturating_add(2);
    let mut out = alloc::vec![0u8; size];
    let mut w = Writer::new(&mut out);
    w.u8(0x01)?;
    w.u8(u8::try_from(links.len()).map_err(|_| Error::Malformed)?)?;
    for link in links {
        w.u32(u32::try_from(link.len()).map_err(|_| Error::Malformed)?)?;
        w.put(link)?;
    }
    Ok(out)
}

/// Walks `chain` forward from the canonical key set `held` (`REL-200`): each
/// link at or below the held epoch is passed over, and each later one must
/// verify under the set before it (`REL-036`, `REL-037`). The result is the
/// canonical bytes of the newest set, which is `held` when no link is newer.
/// A link that does not verify ends the walk with an error, and the caller
/// keeps the set it held.
pub fn advance(held: &[u8], chain: &[u8]) -> Result<Vec<u8>, Error> {
    let (mut current, used) = DirectoryKeySet::parse(held)?;
    let mut current_bytes = held.get(..used).ok_or(Error::Malformed)?;
    for link in links(chain)? {
        let (next, next_used) = DirectoryKeySet::parse(link)?;
        if next.keyset_epoch <= current.keyset_epoch {
            continue;
        }
        let accepted = current.rotate(link)?;
        if accepted != next {
            return Err(Error::Unverified);
        }
        current = accepted;
        current_bytes = link.get(..next_used).ok_or(Error::Malformed)?;
    }
    Ok(current_bytes.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use umbra_crypto::secret::Secret;

    use super::*;
    use crate::directory::authority::keyset_bytes_with;

    struct Rng(u8);
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dst {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }
    impl TryCryptoRng for Rng {}

    fn keys(tag: u8) -> Vec<SigningKey> {
        (0..7u8)
            .map(|i| SigningKey::from_seed(Secret::new([tag.wrapping_add(i); 32])))
            .collect()
    }

    #[test]
    fn a_chain_moves_a_held_key_set_forward_and_never_back() {
        let first_keys = keys(1);
        let second_keys = keys(40);
        let third_keys = keys(80);
        let first = keyset_bytes_with(&first_keys, 1, 1).unwrap();
        let second = keyset_bytes_with(&second_keys, 2, 1).unwrap();
        let third = keyset_bytes_with(&third_keys, 3, 1).unwrap();
        let link2 = sign_keyset(&first_keys, &second, &mut Rng(1)).unwrap();
        let link3 = sign_keyset(&second_keys, &third, &mut Rng(2)).unwrap();
        let chain = encode(&[&link2, &link3]).unwrap();

        // REL-200: the first set walks to the third.
        assert_eq!(advance(&first, &chain).unwrap(), third);
        // The second set passes over the link it holds.
        assert_eq!(advance(&second, &chain).unwrap(), third);
        // A newer set than each link stays where it is.
        assert_eq!(advance(&third, &chain).unwrap(), third);

        // A link under keys of no held set does not verify (REL-036).
        let forged = sign_keyset(&third_keys, &second, &mut Rng(3)).unwrap();
        let bad = encode(&[&forged]).unwrap();
        assert!(advance(&first, &bad).is_err());
        // A chain of no link, and one of bytes after the last, are refused.
        assert!(links(&[0x01, 0x00]).is_err());
        let mut long = chain.clone();
        long.push(0);
        assert!(links(&long).is_err());
    }
}
