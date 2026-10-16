//! HPKE of RFC 9180 in the base mode, which is AUX-6 of Part 5 §5.1: the
//! notification boundary of Part 8 and the OHTTP hop of RFC 9458.
//!
//! The key schedule is generic over the KEM and the KDF hash. The UMBRA
//! suite is `UMBRA-KEM` with HKDF-SHA3-256 and ChaCha20-Poly1305 under the
//! suite ids of Part 5 §5.10. The RFC vector runs the same schedule under
//! DHKEM(X25519, HKDF-SHA256) in the tests, thus the schedule itself is
//! checked against a published value.

use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::SimpleHkdf;
use hmac::digest::{common::BlockSizeUser, Digest, OutputSizeUser};
use rand_core::CryptoRng;
use sha3::Sha3_256;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    kem::{self, Ciphertext, KeyPair, PublicKey},
    secret::Secret,
    Error,
};

/// The AEAD key length.
pub const KEY_LEN: usize = 32;
/// The AEAD nonce length.
pub const NONCE_LEN: usize = 12;
/// The AEAD tag length.
pub const TAG_LEN: usize = 16;
/// The base mode.
const MODE_BASE: u8 = 0x00;

/// A KEM for the key schedule, with the AEAD id its suite carries.
pub trait KemSuite {
    /// The kem_id of the suite id.
    const KEM_ID: u16;
    /// The aead_id of the suite id.
    const AEAD_ID: u16;
    /// The recipient public key.
    type Public;
    /// The recipient key pair.
    type Pair;
    /// `Encap`: the shared secret and its encapsulation.
    fn encap<R: CryptoRng + ?Sized>(pk: &Self::Public, rng: &mut R) -> (Secret<32>, Vec<u8>);
    /// `Decap`.
    fn decap(pair: &Self::Pair, enc: &[u8]) -> Result<Secret<32>, Error>;
}

/// `UMBRA-KEM` as the HPKE KEM, under kem_id `0x0001` of Part 5 §5.4.
pub struct UmbraKem;

impl KemSuite for UmbraKem {
    const KEM_ID: u16 = 0x0001;
    const AEAD_ID: u16 = AEAD_ID;
    type Public = PublicKey;
    type Pair = KeyPair;

    fn encap<R: CryptoRng + ?Sized>(pk: &PublicKey, rng: &mut R) -> (Secret<32>, Vec<u8>) {
        let (ct, ss) = kem::encapsulate(pk, rng);
        (ss, ct.as_bytes().to_vec())
    }

    fn decap(pair: &KeyPair, enc: &[u8]) -> Result<Secret<32>, Error> {
        let ct = Ciphertext::from_bytes(enc)?;
        pair.decapsulate(&ct)
    }
}

/// The hash bound of a KDF.
pub trait KdfHash: Digest + BlockSizeUser + Clone {
    /// The kdf_id of the suite id.
    const KDF_ID: u16;
}

impl KdfHash for Sha3_256 {
    const KDF_ID: u16 = 0x0001;
}

#[cfg(test)]
impl KdfHash for sha2::Sha256 {
    const KDF_ID: u16 = 0x0001;
}

/// The aead_id of ChaCha20-Poly1305 in the UMBRA namespace.
pub const AEAD_ID: u16 = 0x0001;

/// The labeled-expand function of one hash, held by a context.
type Expand = fn(&[u8], &[u8], &[u8], &[u8], &mut [u8]) -> Result<(), Error>;

fn suite_id<K: KemSuite, H: KdfHash>() -> [u8; 10] {
    let aead_id = K::AEAD_ID;
    let mut out = *b"HPKE\0\0\0\0\0\0";
    if let Some(s) = out.get_mut(4..6) {
        s.copy_from_slice(&K::KEM_ID.to_be_bytes());
    }
    if let Some(s) = out.get_mut(6..8) {
        s.copy_from_slice(&H::KDF_ID.to_be_bytes());
    }
    if let Some(s) = out.get_mut(8..10) {
        s.copy_from_slice(&aead_id.to_be_bytes());
    }
    out
}

/// `LabeledExtract(salt, label, ikm)` as a PRK.
fn labeled_extract<H: KdfHash>(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut labeled = Vec::with_capacity(7 + suite.len() + label.len() + ikm.len());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let (mut prk, _) = SimpleHkdf::<H>::extract(Some(salt), &labeled);
    let out = prk.to_vec();
    prk.zeroize();
    out
}

/// `LabeledExpand(prk, label, info, L)`.
fn labeled_expand<H: KdfHash>(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let len = u16::try_from(out.len()).map_err(|_| Error::Length)?;
    let kdf = SimpleHkdf::<H>::from_prk(prk).map_err(|_| Error::Length)?;
    kdf.expand_multi_info(&[&len.to_be_bytes(), b"HPKE-v1", suite, label, info], out)
        .map_err(|_| Error::Length)
}

/// An HPKE context: the AEAD key, the base nonce, the sequence, and the
/// exporter secret.
pub struct Context {
    key: Secret<KEY_LEN>,
    base_nonce: [u8; NONCE_LEN],
    seq: u64,
    exporter: Vec<u8>,
    suite: [u8; 10],
    kdf: Expand,
}

impl Drop for Context {
    fn drop(&mut self) {
        self.base_nonce.zeroize();
        self.exporter.zeroize();
    }
}

impl Context {
    /// `KeySchedule` in the base mode (RFC 9180 §5.1).
    fn key_schedule<K: KemSuite, H: KdfHash>(
        shared_secret: &Secret<32>,
        info: &[u8],
    ) -> Result<Self, Error> {
        let suite = suite_id::<K, H>();
        let psk_id_hash = labeled_extract::<H>(&suite, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract::<H>(&suite, b"", b"info_hash", info);
        let mut context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
        context.push(MODE_BASE);
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);
        // The wrapper wipes the secret on each path out of the call.
        let secret = Zeroizing::new(labeled_extract::<H>(
            &suite,
            shared_secret.expose(),
            b"secret",
            b"",
        ));
        let mut key = Secret::<KEY_LEN>::zeroed();
        labeled_expand::<H>(&suite, &secret, b"key", &context, key.expose_mut())?;
        let mut base_nonce = [0u8; NONCE_LEN];
        labeled_expand::<H>(&suite, &secret, b"base_nonce", &context, &mut base_nonce)?;
        let mut exporter = alloc::vec![0u8; <H as OutputSizeUser>::output_size()];
        labeled_expand::<H>(&suite, &secret, b"exp", &context, &mut exporter)?;
        Ok(Context {
            key,
            base_nonce,
            seq: 0,
            exporter,
            suite,
            kdf: labeled_expand::<H>,
        })
    }

    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = self.base_nonce;
        let seq = self.seq.to_be_bytes();
        for (n, s) in nonce.iter_mut().rev().zip(seq.iter().rev()) {
            *n ^= s;
        }
        nonce
    }

    /// `Seal`: the ciphertext with its tag, at the next sequence number.
    pub fn seal(&mut self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce();
        let mut out = plain.to_vec();
        let tag = ChaCha20Poly1305::new(self.key.expose().into())
            .encrypt_inout_detached(&Nonce::from(nonce), aad, out.as_mut_slice().into())
            .map_err(|_| Error::Length)?;
        out.extend_from_slice(&tag);
        self.seq = self.seq.checked_add(1).ok_or(Error::Length)?;
        Ok(out)
    }

    /// `Open`: the plaintext, at the next sequence number.
    pub fn open(&mut self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
        if sealed.len() < TAG_LEN {
            return Err(Error::Length);
        }
        let split = sealed.len().saturating_sub(TAG_LEN);
        let mut out = sealed.get(..split).ok_or(Error::Length)?.to_vec();
        let tag: [u8; TAG_LEN] = sealed
            .get(split..)
            .and_then(|t| t.try_into().ok())
            .ok_or(Error::Length)?;
        let nonce = self.nonce();
        ChaCha20Poly1305::new(self.key.expose().into())
            .decrypt_inout_detached(
                &Nonce::from(nonce),
                aad,
                out.as_mut_slice().into(),
                &Tag::from(tag),
            )
            .map_err(|_| Error::Aead)?;
        self.seq = self.seq.checked_add(1).ok_or(Error::Length)?;
        Ok(out)
    }

    /// `Export(exporter_context, L)`.
    pub fn export(&self, context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        (self.kdf)(&self.suite, &self.exporter, b"sec", context, out)
    }

    #[cfg(test)]
    fn from_shared_secret<K: KemSuite, H: KdfHash>(
        ss: &Secret<32>,
        info: &[u8],
    ) -> Result<Self, Error> {
        Self::key_schedule::<K, H>(ss, info)
    }
}

/// `SetupBaseS`: the encapsulation to send and the sender context.
pub fn setup_sender<K: KemSuite, H: KdfHash, R: CryptoRng + ?Sized>(
    pk: &K::Public,
    info: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Context), Error> {
    let (ss, enc) = K::encap(pk, rng);
    let context = Context::key_schedule::<K, H>(&ss, info)?;
    Ok((enc, context))
}

/// `SetupBaseR`: the recipient context from an encapsulation.
pub fn setup_recipient<K: KemSuite, H: KdfHash>(
    pair: &K::Pair,
    enc: &[u8],
    info: &[u8],
) -> Result<Context, Error> {
    let ss = K::decap(pair, enc)?;
    Context::key_schedule::<K, H>(&ss, info)
}

/// Single-shot `Seal` under the UMBRA suite: `enc || ct`.
pub fn seal<R: CryptoRng + ?Sized>(
    pk: &PublicKey,
    info: &[u8],
    aad: &[u8],
    plain: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let (mut out, mut context) = setup_sender::<UmbraKem, Sha3_256, R>(pk, info, rng)?;
    out.extend_from_slice(&context.seal(aad, plain)?);
    Ok(out)
}

/// Single-shot `Open` under the UMBRA suite.
pub fn open(pair: &KeyPair, info: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    let enc = sealed.get(..kem::CIPHERTEXT_LEN).ok_or(Error::Length)?;
    let ct = sealed.get(kem::CIPHERTEXT_LEN..).ok_or(Error::Length)?;
    let mut context = setup_recipient::<UmbraKem, Sha3_256>(pair, enc, info)?;
    context.open(aad, ct)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey as XPublic, StaticSecret};

    /// DHKEM(X25519, HKDF-SHA256) of RFC 9180 §4.1, for the vector only.
    struct DhKemX25519;

    impl DhKemX25519 {
        fn shared(dh: &[u8; 32], enc: &[u8; 32], pk_r: &[u8; 32]) -> Secret<32> {
            let suite = *b"KEM\x00\x20";
            let eae_prk = labeled_extract::<Sha256>(&suite, b"", b"eae_prk", dh);
            let mut ctx = [0u8; 64];
            ctx[..32].copy_from_slice(enc);
            ctx[32..].copy_from_slice(pk_r);
            let mut ss = Secret::<32>::zeroed();
            labeled_expand::<Sha256>(&suite, &eae_prk, b"shared_secret", &ctx, ss.expose_mut())
                .unwrap();
            ss
        }
    }

    impl KemSuite for DhKemX25519 {
        const KEM_ID: u16 = 0x0020;
        const AEAD_ID: u16 = 0x0003;
        type Public = ([u8; 32], StaticSecret);
        type Pair = StaticSecret;

        fn encap<R: CryptoRng + ?Sized>(pk: &Self::Public, _: &mut R) -> (Secret<32>, Vec<u8>) {
            // The vector fixes the ephemeral key, which the "public" carries.
            let (pk_r, sk_e) = pk;
            let enc = XPublic::from(sk_e).to_bytes();
            let dh = sk_e.diffie_hellman(&XPublic::from(*pk_r)).to_bytes();
            (Self::shared(&dh, &enc, pk_r), enc.to_vec())
        }

        fn decap(sk_r: &StaticSecret, enc: &[u8]) -> Result<Secret<32>, Error> {
            let enc: [u8; 32] = enc.try_into().map_err(|_| Error::Length)?;
            let dh = sk_r.diffie_hellman(&XPublic::from(enc)).to_bytes();
            let pk_r = XPublic::from(sk_r).to_bytes();
            Ok(Self::shared(&dh, &enc, &pk_r))
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const VECTOR: &str = include_str!("../../../tests/vectors/rfc9180/a2_base.txt");

    fn field(name: &str) -> Vec<u8> {
        let line = VECTOR
            .lines()
            .find(|l| l.starts_with(&alloc::format!("{name}=")))
            .unwrap();
        hex(line.split_once('=').unwrap().1.trim())
    }

    #[test]
    fn the_rfc_9180_base_vector_holds_for_the_key_schedule() {
        let sk_e = StaticSecret::from(<[u8; 32]>::try_from(field("skEm")).unwrap());
        let sk_r = StaticSecret::from(<[u8; 32]>::try_from(field("skRm")).unwrap());
        let pk_r: [u8; 32] = field("pkRm").try_into().unwrap();
        assert_eq!(XPublic::from(&sk_r).to_bytes()[..], pk_r[..]);
        let info = field("info");
        let mut rng = crate::test_rng::TestRng::new(b"unused");
        let (enc, mut sender) =
            setup_sender::<DhKemX25519, Sha256, _>(&(pk_r, sk_e), &info, &mut rng).unwrap();
        assert_eq!(enc, field("enc"));
        assert_eq!(sender.key.expose()[..], field("key")[..]);
        assert_eq!(sender.base_nonce[..], field("base_nonce")[..]);
        assert_eq!(sender.exporter, field("exporter_secret"));
        let mut recipient = setup_recipient::<DhKemX25519, Sha256>(&sk_r, &enc, &info).unwrap();
        // The vector encrypts at sequence numbers 0, 1, 2, 4, 255, and 256.
        for (i, seq) in [0u64, 1, 2, 4, 255, 256].into_iter().enumerate() {
            sender.seq = seq;
            recipient.seq = seq;
            let ct = sender
                .seal(
                    &field(&alloc::format!("aad{i}")),
                    &field(&alloc::format!("pt{i}")),
                )
                .unwrap();
            assert_eq!(ct, field(&alloc::format!("ct{i}")), "sequence {seq}");
            let pt = recipient
                .open(&field(&alloc::format!("aad{i}")), &ct)
                .unwrap();
            assert_eq!(pt, field(&alloc::format!("pt{i}")));
        }
        for i in 0..3 {
            let mut out = [0u8; 32];
            sender
                .export(&field(&alloc::format!("exporter_context{i}")), &mut out)
                .unwrap();
            assert_eq!(out[..], field(&alloc::format!("exported_value{i}"))[..]);
        }
        // The shared secret alone gives the same schedule.
        let ss = Secret::new(<[u8; 32]>::try_from(field("shared_secret")).unwrap());
        let again = Context::from_shared_secret::<DhKemX25519, Sha256>(&ss, &info).unwrap();
        assert_eq!(again.key.expose(), sender.key.expose());
    }

    #[test]
    fn the_umbra_suite_seals_and_opens_and_binds_its_info_and_aad() {
        let mut rng = crate::test_rng::TestRng::new(b"hpke");
        let pair = KeyPair::generate(&mut rng);
        let other = KeyPair::generate(&mut rng);
        let sealed = seal(
            pair.public(),
            b"umbra/v1/ntf-root",
            b"aad",
            b"root",
            &mut rng,
        )
        .unwrap();
        assert_eq!(sealed.len(), kem::CIPHERTEXT_LEN + 4 + TAG_LEN);
        assert_eq!(
            open(&pair, b"umbra/v1/ntf-root", b"aad", &sealed).unwrap(),
            b"root"
        );
        assert!(open(&pair, b"other", b"aad", &sealed).is_err());
        assert!(open(&pair, b"umbra/v1/ntf-root", b"x", &sealed).is_err());
        assert!(open(&other, b"umbra/v1/ntf-root", b"aad", &sealed).is_err());
        assert!(open(&pair, b"umbra/v1/ntf-root", b"aad", &sealed[..100]).is_err());
        // A context carries a sequence, thus two seals differ and open in
        // order only.
        let (enc, mut s) =
            setup_sender::<UmbraKem, Sha3_256, _>(pair.public(), b"i", &mut rng).unwrap();
        let mut r = setup_recipient::<UmbraKem, Sha3_256>(&pair, &enc, b"i").unwrap();
        let c0 = s.seal(b"", b"zero").unwrap();
        let c1 = s.seal(b"", b"one").unwrap();
        assert!(r.open(b"", &c1).is_err());
        let mut r = setup_recipient::<UmbraKem, Sha3_256>(&pair, &enc, b"i").unwrap();
        assert_eq!(r.open(b"", &c0).unwrap(), b"zero");
        assert_eq!(r.open(b"", &c1).unwrap(), b"one");
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        s.export(b"ctx", &mut a).unwrap();
        r.export(b"ctx", &mut b).unwrap();
        assert_eq!(a, b);
    }
}
