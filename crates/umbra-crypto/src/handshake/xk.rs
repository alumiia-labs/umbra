//! `UMBRA-XKhfs`, the pairwise handshake of Part 5 §5.4.2 and §5.4.8.
//!
//! Three flights over 1.5 round trips. The responder's static key and its
//! one-time prekey arrive out of band in the invitation. The initiator shows
//! its static key in flight 3 only, under a key that absorbed `ee` and the
//! ML-KEM secret of flight 2 (identity-hiding grade 8, §5.4.3).

use kem::{Decapsulate, Encapsulate};
use ml_kem::{array::Array, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, Seed};
use rand_core::CryptoRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as XPublic, ReusableSecret, StaticSecret};

use super::{contributory, suite, AddressType, State, Trace, VersionRange, TAG_LEN};
use crate::{kem::KeyPair, labels, secret::Secret, Error};

const NAME: &[u8] = b"UMBRA-XKhfs/v1";
/// The one handshake mode of v1.
pub const MODE: u8 = 0x01;
/// Size of an ML-KEM-768 encapsulation key.
/// The length of an ML-KEM-768 encapsulation key.
pub const EK_LEN: usize = 1184;
/// Size of an ML-KEM-768 ciphertext.
const CT_LEN: usize = 1088;
/// Size of `n_hs`.
pub const NONCE_LEN: usize = 16;
/// Size of a prekey identifier.
pub const PID_LEN: usize = 16;

/// The fixed part of flight 1, before the payload.
pub const FLIGHT1_FIXED: usize = 2 + 1 + PID_LEN + 32 + EK_LEN + CT_LEN + TAG_LEN;
/// The fixed part of flight 2, before the payload.
pub const FLIGHT2_FIXED: usize = 32 + CT_LEN + TAG_LEN;
/// The fixed part of flight 3, before the payload.
pub const FLIGHT3_FIXED: usize = 32 + TAG_LEN + TAG_LEN;
/// Bytes a payload adds beyond its application data: the AEAD tag.
pub const PAYLOAD_OVERHEAD: usize = TAG_LEN;
/// The largest application payload of one flight. Part 3 rule `NET-173` puts
/// a 129-byte `QueueAddress` in `app_1`, and no rule puts more in any flight.
pub const MAX_APP_LEN: usize = 1024;

const _: () = assert!(FLIGHT1_FIXED == 2339);
const _: () = assert!(FLIGHT2_FIXED == 1136);
const _: () = assert!(FLIGHT3_FIXED == 64);

/// A one-time ML-KEM-768 prekey of §5.4.5. The responder makes one for each
/// invitation and erases it at consumption.
pub struct OneTimePrekey {
    dk: DecapsulationKey<MlKem768>,
    ek: [u8; EK_LEN],
    id: [u8; PID_LEN],
}

impl OneTimePrekey {
    /// Makes a prekey from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = Secret::<64>::zeroed();
        rng.fill_bytes(seed.expose_mut());
        Self::from_seed(seed)
    }

    /// Makes a prekey from the seeds `d || z`.
    pub fn from_seed(seed: Secret<64>) -> Self {
        let dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed.expose()));
        let ek: [u8; EK_LEN] = dk.encapsulation_key().to_bytes().into();
        Self {
            id: prekey_id(&ek),
            dk,
            ek,
        }
    }

    /// The encapsulation key `s1`, as the invitation carries it.
    pub fn encapsulation_key(&self) -> &[u8; EK_LEN] {
        &self.ek
    }

    /// The identifier `pid` (`CRY-084`).
    pub fn id(&self) -> &[u8; PID_LEN] {
        &self.id
    }
}

/// `pid = SHA3-256("umbra/v1/prekey-id" || s1)[0..16]`.
pub fn prekey_id(s1: &[u8; EK_LEN]) -> [u8; PID_LEN] {
    let mut h = Sha3_256::new();
    h.update(labels::PREKEY_ID);
    h.update(s1);
    let out: [u8; 32] = h.finalize().into();
    let mut id = [0u8; PID_LEN];
    id.copy_from_slice(&out[..PID_LEN]);
    id
}

/// The keys that a completed handshake gives (`Split`).
pub struct SessionKeys {
    /// The initial root key `RK` of §5.5.1.
    pub rk: Secret<32>,
    /// The header key of the initiator-to-responder direction.
    pub hk_i2r: Secret<32>,
    /// The header key of the responder-to-initiator direction.
    pub hk_r2i: Secret<32>,
    /// The transcript hash at the split, for Part 7 §7.4 step 3.
    pub transcript: [u8; 32],
    /// The responder's flight-2 ephemeral, which is its first ratchet key.
    pub dh_initial: InitialDh,
}

/// The responder's first ratchet key, as each side holds it.
pub enum InitialDh {
    /// At the initiator: the public key `er` of flight 2.
    Peer([u8; 32]),
    /// At the responder: the private key of `er`.
    Own(StaticSecret),
}

impl InitialDh {
    /// The peer's public key, at the initiator.
    pub fn peer_public(&self) -> Option<[u8; 32]> {
        match self {
            Self::Peer(pk) => Some(*pk),
            Self::Own(_) => None,
        }
    }

    /// The own private key, at the responder.
    pub fn into_own_secret(self) -> Option<StaticSecret> {
        match self {
            Self::Own(sk) => Some(sk),
            Self::Peer(_) => None,
        }
    }
}

/// The fields the initiator holds before flight 1, from the invitation.
pub struct Invitation<'a> {
    /// `responder_static_x25519`.
    pub s: [u8; 32],
    /// `responder_kem_ek`, the one-time prekey.
    pub s1: &'a [u8; EK_LEN],
    /// The range the responder advertises.
    pub range_r: VersionRange,
}

fn prologue(
    mode: u8,
    range_i: VersionRange,
    range_r: VersionRange,
    address: AddressType,
) -> [u8; 15] {
    let mut p = [0u8; 15];
    p[0] = suite::VERSION;
    p[1] = mode;
    p[2..4].copy_from_slice(&suite::KEM.to_be_bytes());
    p[4..6].copy_from_slice(&suite::SIG.to_be_bytes());
    p[6..8].copy_from_slice(&suite::AEAD.to_be_bytes());
    p[8..10].copy_from_slice(&suite::KDF.to_be_bytes());
    p[10] = range_i.min;
    p[11] = range_i.max;
    p[12] = range_r.min;
    p[13] = range_r.max;
    p[14] = address as u8;
    p
}

fn init(
    mode: u8,
    range_i: VersionRange,
    range_r: VersionRange,
    address: AddressType,
    s: &[u8; 32],
    s1: &[u8; EK_LEN],
) -> State {
    let mut st = State::new(NAME);
    st.mix_hash(&prologue(mode, range_i, range_r, address));
    st.mix_hash(s);
    st.mix_hash(s1);
    st
}

fn split(st: &State, dh_initial: InitialDh) -> SessionKeys {
    SessionKeys {
        rk: st.derive(&[labels::RATCHET_ROOT]),
        hk_i2r: st.derive(&[labels::HEADER_KEY, &[0x01]]),
        hk_r2i: st.derive(&[labels::HEADER_KEY, &[0x02]]),
        transcript: *st.h(),
        dh_initial,
    }
}

/// The initiator between flight 1 and flight 3.
pub struct Initiator {
    st: State,
    e_sk: ReusableSecret,
    e1_dk: DecapsulationKey<MlKem768>,
    n_hs: [u8; NONCE_LEN],
}

impl Initiator {
    /// Writes flight 1 into `out` and returns the initiator and the length.
    ///
    /// `out` needs `FLIGHT1_FIXED + NONCE_LEN + app_1.len() + PAYLOAD_OVERHEAD`
    /// bytes. The coins come from `rng`, which is the hardened generator of
    /// §5.9 on a protocol path.
    #[allow(clippy::too_many_arguments)]
    pub fn flight1<R: CryptoRng + ?Sized, T: Trace>(
        invitation: &Invitation<'_>,
        range_i: VersionRange,
        address: AddressType,
        app_1: &[u8],
        rng: &mut R,
        out: &mut [u8],
        trace: &mut T,
    ) -> Result<(Self, usize), Error> {
        range_i.negotiate(invitation.range_r)?;
        if app_1.len() > MAX_APP_LEN {
            return Err(Error::Length);
        }
        let total = FLIGHT1_FIXED + NONCE_LEN + app_1.len() + PAYLOAD_OVERHEAD;
        let out = out.get_mut(..total).ok_or(Error::Length)?;
        let mut st = init(
            MODE,
            range_i,
            invitation.range_r,
            address,
            &invitation.s,
            invitation.s1,
        );
        let (head, rest) = out.split_at_mut(3);
        head.copy_from_slice(&[range_i.min, range_i.max, MODE]);

        // 0. pid
        let (pid_out, rest) = rest.split_at_mut(PID_LEN);
        pid_out.copy_from_slice(&prekey_id(invitation.s1));
        st.mix_hash(pid_out);
        st.trace(trace, "1.0 pid");
        // 1. e
        let e_sk = ReusableSecret::random_from_rng(rng);
        let e = XPublic::from(&e_sk);
        let (e_out, rest) = rest.split_at_mut(32);
        e_out.copy_from_slice(e.as_bytes());
        st.mix_hash(e.as_bytes());
        st.trace(trace, "1.1 e");
        // 2. es
        let es = e_sk.diffie_hellman(&XPublic::from(invitation.s));
        contributory(&es)?;
        st.mix_key(es.as_bytes());
        st.trace(trace, "1.2 es");
        // 3. e1
        let mut seed = Secret::<64>::zeroed();
        rng.fill_bytes(seed.expose_mut());
        let e1_dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed.expose()));
        let (e1_out, rest) = rest.split_at_mut(EK_LEN);
        e1_out.copy_from_slice(&e1_dk.encapsulation_key().to_bytes());
        st.mix_hash(e1_out);
        st.trace(trace, "1.3 e1");
        // 4. skem1
        let s1 = EncapsulationKey::<MlKem768>::new(&Array::from(*invitation.s1))
            .map_err(|_| Error::Key)?;
        let (skem1, ss1) = s1.encapsulate_with_rng(rng);
        let (skem1_out, rest) = rest.split_at_mut(CT_LEN);
        skem1_out.copy_from_slice(&skem1);
        st.mix_hash(skem1_out);
        st.mix_key(&ss1);
        st.trace(trace, "1.4 skem1");
        // 5. tag1
        let (tag1_out, rest) = rest.split_at_mut(TAG_LEN);
        tag1_out.copy_from_slice(&st.seal(&mut [])?);
        st.trace(trace, "1.5 tag1");
        // 6. payload1
        let mut n_hs = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut n_hs);
        let (pt, tag_out) = rest.split_at_mut(NONCE_LEN + app_1.len());
        {
            let (nonce_out, app_out) = pt.split_at_mut(NONCE_LEN);
            nonce_out.copy_from_slice(&n_hs);
            app_out.copy_from_slice(app_1);
        }
        tag_out.copy_from_slice(&st.seal(pt)?);
        st.trace(trace, "1.6 payload1");

        Ok((
            Self {
                st,
                e_sk,
                e1_dk,
                n_hs,
            },
            total,
        ))
    }

    /// Reads flight 2 and writes `app_2` into `app_out`. Returns its length.
    pub fn read_flight2<T: Trace>(
        &mut self,
        flight: &[u8],
        app_out: &mut [u8],
        trace: &mut T,
    ) -> Result<usize, Error> {
        let payload_len = flight
            .len()
            .checked_sub(FLIGHT2_FIXED)
            .ok_or(Error::Length)?;
        let app_len = payload_len
            .checked_sub(NONCE_LEN + PAYLOAD_OVERHEAD)
            .ok_or(Error::Length)?;
        let app_out = app_out.get_mut(..app_len).ok_or(Error::Length)?;
        let (er, rest) = flight.split_at(32);
        let (ekem1, rest) = rest.split_at(CT_LEN);
        let (tag2, payload) = rest.split_at(TAG_LEN);
        let st = &mut self.st;
        // 1. er
        let er: [u8; 32] = er.try_into().map_err(|_| Error::Length)?;
        st.mix_hash(&er);
        st.trace(trace, "2.1 er");
        // 2. ee
        let ee = self.e_sk.diffie_hellman(&XPublic::from(er));
        contributory(&ee)?;
        st.mix_key(ee.as_bytes());
        st.trace(trace, "2.2 ee");
        // 3. ekem1
        let ct: ml_kem::Ciphertext<MlKem768> = Array::try_from(ekem1).map_err(|_| Error::Length)?;
        let ss2 = self.e1_dk.decapsulate(&ct);
        st.mix_hash(ekem1);
        st.mix_key(&ss2);
        st.trace(trace, "2.3 ekem1");
        // 4. tag2
        st.open(&mut [], tag2)?;
        st.trace(trace, "2.4 tag2");
        // 5. payload2
        let (ct, tag) = payload.split_at(payload_len - PAYLOAD_OVERHEAD);
        let mut buf = [0u8; NONCE_LEN + MAX_APP_LEN];
        let buf = buf.get_mut(..ct.len()).ok_or(Error::Length)?;
        buf.copy_from_slice(ct);
        st.open(buf, tag)?;
        st.trace(trace, "2.5 payload2");
        let (nonce_in, app_in) = buf.split_at(NONCE_LEN);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(nonce_in, &self.n_hs[..])) {
            return Err(Error::Handshake);
        }
        app_out.copy_from_slice(app_in);
        Ok(app_len)
    }

    /// Writes flight 3 into `out` with the initiator's static identity
    /// `s_i`, and returns the session keys and the length. `out` needs
    /// `FLIGHT3_FIXED + app_3.len() + PAYLOAD_OVERHEAD` bytes.
    pub fn flight3<T: Trace>(
        mut self,
        s_i: &KeyPair,
        er: &[u8; 32],
        app_3: &[u8],
        out: &mut [u8],
        trace: &mut T,
    ) -> Result<(SessionKeys, usize), Error> {
        let total = FLIGHT3_FIXED + app_3.len() + PAYLOAD_OVERHEAD;
        let out = out.get_mut(..total).ok_or(Error::Length)?;
        let st = &mut self.st;
        // 1. s_ct
        let (s_ct, rest) = out.split_at_mut(32 + TAG_LEN);
        let (s_pt, s_tag) = s_ct.split_at_mut(32);
        s_pt.copy_from_slice(&s_i.x25519_public());
        s_tag.copy_from_slice(&st.seal(s_pt)?);
        st.trace(trace, "3.1 s_ct");
        // 2. se
        let se = s_i.x25519_secret().diffie_hellman(&XPublic::from(*er));
        contributory(&se)?;
        st.mix_key(se.as_bytes());
        st.trace(trace, "3.2 se");
        // 3. tag3
        let (tag3, rest) = rest.split_at_mut(TAG_LEN);
        tag3.copy_from_slice(&st.seal(&mut [])?);
        st.trace(trace, "3.3 tag3");
        // 4. payload3
        let (pt, tag) = rest.split_at_mut(app_3.len());
        pt.copy_from_slice(app_3);
        tag.copy_from_slice(&st.seal(pt)?);
        st.trace(trace, "3.4 payload3");
        // 5. split
        let keys = split(st, InitialDh::Peer(*er));
        st.trace(trace, "3.5 split");
        Ok((keys, total))
    }
}

/// The responder between flight 1 and flight 3.
pub struct Responder {
    st: State,
    e: [u8; 32],
    e1: [u8; EK_LEN],
    er_sk: Option<StaticSecret>,
    n_hs: [u8; NONCE_LEN],
}

/// What the responder learns from flight 1 before it answers.
pub struct Flight1 {
    /// The application payload `app_1` length written into `app_out`.
    pub app_len: usize,
}

impl Responder {
    /// Reads the header of flight 1: the initiator's range, the mode, and
    /// the prekey identifier. The caller resolves `pid` with
    /// [`super::find_prekey`] and then calls [`Responder::read_flight1`].
    pub fn peek(flight: &[u8]) -> Result<(VersionRange, u8, [u8; PID_LEN]), Error> {
        if flight.len() < FLIGHT1_FIXED + NONCE_LEN + PAYLOAD_OVERHEAD {
            return Err(Error::Length);
        }
        let (head, rest) = flight.split_at(3);
        let (&min, &max, &mode) = match head {
            [a, b, c] => (a, b, c),
            _ => return Err(Error::Length),
        };
        let mut pid = [0u8; PID_LEN];
        pid.copy_from_slice(rest.get(..PID_LEN).ok_or(Error::Length)?);
        Ok((VersionRange { min, max }, mode, pid))
    }

    /// Reads flight 1 with the responder's static identity `s_r` and the
    /// prekey that `pid` named. The prekey is consumed (`CRY-089`).
    pub fn read_flight1<T: Trace>(
        s_r: &KeyPair,
        prekey: OneTimePrekey,
        range_r: VersionRange,
        address: AddressType,
        flight: &[u8],
        app_out: &mut [u8],
        trace: &mut T,
    ) -> Result<(Self, Flight1), Error> {
        let (range_i, mode, pid) = Self::peek(flight)?;
        // CRY-102 and CRY-126: the checks run before any hash.
        range_i.negotiate(range_r)?;
        if mode != MODE {
            return Err(Error::Handshake);
        }
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&pid[..], &prekey.id[..])) {
            return Err(Error::Handshake);
        }
        let payload_len = flight.len() - FLIGHT1_FIXED;
        let app_len = payload_len - NONCE_LEN - PAYLOAD_OVERHEAD;
        let app_out = app_out.get_mut(..app_len).ok_or(Error::Length)?;

        let s = s_r.x25519_public();
        let mut st = init(mode, range_i, range_r, address, &s, &prekey.ek);
        let (_, rest) = flight.split_at(3);
        let (pid_b, rest) = rest.split_at(PID_LEN);
        let (e, rest) = rest.split_at(32);
        let (e1, rest) = rest.split_at(EK_LEN);
        let (skem1, rest) = rest.split_at(CT_LEN);
        let (tag1, payload) = rest.split_at(TAG_LEN);

        st.mix_hash(pid_b);
        st.trace(trace, "1.0 pid");
        let e: [u8; 32] = e.try_into().map_err(|_| Error::Length)?;
        st.mix_hash(&e);
        st.trace(trace, "1.1 e");
        let es = s_r.x25519_secret().diffie_hellman(&XPublic::from(e));
        contributory(&es)?;
        st.mix_key(es.as_bytes());
        st.trace(trace, "1.2 es");
        let e1: [u8; EK_LEN] = e1.try_into().map_err(|_| Error::Length)?;
        st.mix_hash(&e1);
        st.trace(trace, "1.3 e1");
        let ct: ml_kem::Ciphertext<MlKem768> = Array::try_from(skem1).map_err(|_| Error::Length)?;
        let ss1 = prekey.dk.decapsulate(&ct);
        st.mix_hash(skem1);
        st.mix_key(&ss1);
        st.trace(trace, "1.4 skem1");
        st.open(&mut [], tag1)?;
        st.trace(trace, "1.5 tag1");
        let (ct, tag) = payload.split_at(payload_len - PAYLOAD_OVERHEAD);
        let mut buf = [0u8; NONCE_LEN + MAX_APP_LEN];
        let buf = buf.get_mut(..ct.len()).ok_or(Error::Length)?;
        buf.copy_from_slice(ct);
        st.open(buf, tag)?;
        st.trace(trace, "1.6 payload1");
        let (nonce_in, app_in) = buf.split_at(NONCE_LEN);
        let mut n_hs = [0u8; NONCE_LEN];
        n_hs.copy_from_slice(nonce_in);
        app_out.copy_from_slice(app_in);
        drop(prekey);
        Ok((
            Self {
                st,
                e,
                e1,
                er_sk: None,
                n_hs,
            },
            Flight1 { app_len },
        ))
    }

    /// Writes flight 2 into `out` and returns the length. `out` needs
    /// `FLIGHT2_FIXED + NONCE_LEN + app_2.len() + PAYLOAD_OVERHEAD` bytes.
    pub fn flight2<R: CryptoRng + ?Sized, T: Trace>(
        &mut self,
        app_2: &[u8],
        rng: &mut R,
        out: &mut [u8],
        trace: &mut T,
    ) -> Result<usize, Error> {
        if app_2.len() > MAX_APP_LEN {
            return Err(Error::Length);
        }
        let total = FLIGHT2_FIXED + NONCE_LEN + app_2.len() + PAYLOAD_OVERHEAD;
        let out = out.get_mut(..total).ok_or(Error::Length)?;
        let st = &mut self.st;
        // 1. er
        let er_sk = StaticSecret::random_from_rng(rng);
        let er = XPublic::from(&er_sk);
        let (er_out, rest) = out.split_at_mut(32);
        er_out.copy_from_slice(er.as_bytes());
        st.mix_hash(er.as_bytes());
        st.trace(trace, "2.1 er");
        // 2. ee
        let ee = er_sk.diffie_hellman(&XPublic::from(self.e));
        contributory(&ee)?;
        st.mix_key(ee.as_bytes());
        st.trace(trace, "2.2 ee");
        // 3. ekem1
        let e1 =
            EncapsulationKey::<MlKem768>::new(&Array::from(self.e1)).map_err(|_| Error::Key)?;
        let (ekem1, ss2) = e1.encapsulate_with_rng(rng);
        let (ekem1_out, rest) = rest.split_at_mut(CT_LEN);
        ekem1_out.copy_from_slice(&ekem1);
        st.mix_hash(ekem1_out);
        st.mix_key(&ss2);
        st.trace(trace, "2.3 ekem1");
        // 4. tag2
        let (tag2, rest) = rest.split_at_mut(TAG_LEN);
        tag2.copy_from_slice(&st.seal(&mut [])?);
        st.trace(trace, "2.4 tag2");
        // 5. payload2
        let (pt, tag) = rest.split_at_mut(NONCE_LEN + app_2.len());
        {
            let (nonce_out, app_out) = pt.split_at_mut(NONCE_LEN);
            nonce_out.copy_from_slice(&self.n_hs);
            app_out.copy_from_slice(app_2);
        }
        tag.copy_from_slice(&st.seal(pt)?);
        st.trace(trace, "2.5 payload2");
        self.er_sk = Some(er_sk);
        Ok(total)
    }

    /// Reads flight 3, writes `app_3` into `app_out`, and returns the
    /// session keys, the initiator's static X25519 key, and the length.
    pub fn read_flight3<T: Trace>(
        mut self,
        flight: &[u8],
        app_out: &mut [u8],
        trace: &mut T,
    ) -> Result<(SessionKeys, [u8; 32], usize), Error> {
        let er_sk = self.er_sk.take().ok_or(Error::Handshake)?;
        let payload_len = flight
            .len()
            .checked_sub(FLIGHT3_FIXED)
            .ok_or(Error::Length)?;
        let app_len = payload_len
            .checked_sub(PAYLOAD_OVERHEAD)
            .ok_or(Error::Length)?;
        let app_out = app_out.get_mut(..app_len).ok_or(Error::Length)?;
        let st = &mut self.st;
        let (s_ct, rest) = flight.split_at(32 + TAG_LEN);
        let (tag3, payload) = rest.split_at(TAG_LEN);
        // 1. s_ct
        let (s_enc, s_tag) = s_ct.split_at(32);
        let mut s_i = [0u8; 32];
        s_i.copy_from_slice(s_enc);
        st.open(&mut s_i, s_tag)?;
        st.trace(trace, "3.1 s_ct");
        // 2. se
        let se = er_sk.diffie_hellman(&XPublic::from(s_i));
        contributory(&se)?;
        st.mix_key(se.as_bytes());
        st.trace(trace, "3.2 se");
        // 3. tag3
        st.open(&mut [], tag3)?;
        st.trace(trace, "3.3 tag3");
        // 4. payload3
        let (ct, tag) = payload.split_at(app_len);
        app_out.copy_from_slice(ct);
        st.open(app_out, tag)?;
        st.trace(trace, "3.4 payload3");
        // 5. split
        let keys = split(st, InitialDh::Own(er_sk));
        st.trace(trace, "3.5 split");
        Ok((keys, s_i, app_len))
    }

    /// The responder's ephemeral public key `er`, which the initiator needs
    /// for `se`; the caller takes it from flight 2's first 32 bytes.
    pub fn er_of(flight2: &[u8]) -> Result<[u8; 32], Error> {
        flight2
            .get(..32)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Length)
    }
}
