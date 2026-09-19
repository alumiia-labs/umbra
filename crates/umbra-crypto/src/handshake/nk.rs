//! `UMBRA-NKhfs`, the circuit-hop handshake of Part 5 §5.4.9.
//!
//! Two flights and no payload. The client has no static key; the relay's
//! static key is the `ntor_pk` of its descriptor. The result is one secret,
//! `ss_hop`, from which Part 3 §3.4.4 derives the hop key material.

use kem::{Decapsulate, Encapsulate};
use ml_kem::{array::Array, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, Seed};
use rand_core::CryptoRng;
use x25519_dalek::{PublicKey as XPublic, ReusableSecret, StaticSecret};

use super::{contributory, suite, State, Trace, TAG_LEN};
use crate::{labels, secret::Secret, Error};

const NAME: &[u8] = b"UMBRA-NKhfs/v1";
const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;

/// Size of flight 1.
pub const FLIGHT1_LEN: usize = 32 + EK_LEN + TAG_LEN;
/// Size of flight 2.
pub const FLIGHT2_LEN: usize = 32 + CT_LEN + TAG_LEN;

const _: () = assert!(FLIGHT1_LEN == 1232);
const _: () = assert!(FLIGHT2_LEN == 1136);

/// The relay's static X25519 key, as its descriptor publishes it.
pub struct RelayStatic {
    /// `ntor_pk`.
    pub s: [u8; 32],
    /// `relay_id` of the same descriptor.
    pub relay_id: [u8; 32],
}

fn prologue(relay_id: &[u8; 32]) -> [u8; 41] {
    let mut p = [0u8; 41];
    p[0] = suite::VERSION;
    p[1..3].copy_from_slice(&suite::KEM.to_be_bytes());
    p[3..5].copy_from_slice(&suite::SIG.to_be_bytes());
    p[5..7].copy_from_slice(&suite::AEAD.to_be_bytes());
    p[7..9].copy_from_slice(&suite::KDF.to_be_bytes());
    p[9..].copy_from_slice(relay_id);
    p
}

fn init(relay: &RelayStatic) -> State {
    let mut st = State::new(NAME);
    st.mix_hash(&prologue(&relay.relay_id));
    st.mix_hash(&relay.s);
    st
}

fn split(st: &State) -> Secret<32> {
    st.derive(&[labels::ONION_HOP])
}

/// The client between flight 1 and flight 2.
pub struct Client {
    st: State,
    e_sk: ReusableSecret,
    e1_dk: DecapsulationKey<MlKem768>,
}

impl Client {
    /// Writes flight 1 into `out`, which needs `FLIGHT1_LEN` bytes.
    pub fn flight1<R: CryptoRng + ?Sized, T: Trace>(
        relay: &RelayStatic,
        rng: &mut R,
        out: &mut [u8],
        trace: &mut T,
    ) -> Result<Self, Error> {
        let out = out.get_mut(..FLIGHT1_LEN).ok_or(Error::Length)?;
        let mut st = init(relay);
        let (e_out, rest) = out.split_at_mut(32);
        let (e1_out, tag_out) = rest.split_at_mut(EK_LEN);
        // 1. e
        let e_sk = ReusableSecret::random_from_rng(rng);
        let e = XPublic::from(&e_sk);
        e_out.copy_from_slice(e.as_bytes());
        st.mix_hash(e.as_bytes());
        st.trace(trace, "1.1 e");
        // 2. es
        let es = e_sk.diffie_hellman(&XPublic::from(relay.s));
        contributory(&es)?;
        st.mix_key(es.as_bytes());
        st.trace(trace, "1.2 es");
        // 3. e1
        let mut seed = Secret::<64>::zeroed();
        rng.fill_bytes(seed.expose_mut());
        let e1_dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed.expose()));
        e1_out.copy_from_slice(&e1_dk.encapsulation_key().to_bytes());
        st.mix_hash(e1_out);
        st.trace(trace, "1.3 e1");
        // 4. tag1
        tag_out.copy_from_slice(&st.seal(&mut [])?);
        st.trace(trace, "1.4 tag1");
        Ok(Self { st, e_sk, e1_dk })
    }

    /// Reads flight 2 and returns `ss_hop`.
    pub fn read_flight2<T: Trace>(
        mut self,
        flight: &[u8],
        trace: &mut T,
    ) -> Result<Secret<32>, Error> {
        let flight = flight.get(..FLIGHT2_LEN).ok_or(Error::Length)?;
        if flight.len() != FLIGHT2_LEN {
            return Err(Error::Length);
        }
        let (er, rest) = flight.split_at(32);
        let (ekem1, tag2) = rest.split_at(CT_LEN);
        let st = &mut self.st;
        let er: [u8; 32] = er.try_into().map_err(|_| Error::Length)?;
        st.mix_hash(&er);
        st.trace(trace, "2.1 er");
        let ee = self.e_sk.diffie_hellman(&XPublic::from(er));
        contributory(&ee)?;
        st.mix_key(ee.as_bytes());
        st.trace(trace, "2.2 ee");
        let ct: ml_kem::Ciphertext<MlKem768> = Array::try_from(ekem1).map_err(|_| Error::Length)?;
        let ss2 = self.e1_dk.decapsulate(&ct);
        st.mix_hash(ekem1);
        st.mix_key(&ss2);
        st.trace(trace, "2.3 ekem1");
        st.open(&mut [], tag2)?;
        st.trace(trace, "2.4 tag2");
        let ss_hop = split(st);
        st.trace(trace, "2.5 split");
        Ok(ss_hop)
    }
}

/// The relay side, which reads flight 1 and answers with flight 2.
pub struct Relay {
    st: State,
    e: [u8; 32],
    e1: [u8; EK_LEN],
}

impl Relay {
    /// Reads flight 1 under the relay's static secret `s_sk`.
    pub fn read_flight1<T: Trace>(
        relay: &RelayStatic,
        s_sk: &StaticSecret,
        flight: &[u8],
        trace: &mut T,
    ) -> Result<Self, Error> {
        let flight = flight.get(..FLIGHT1_LEN).ok_or(Error::Length)?;
        let (e, rest) = flight.split_at(32);
        let (e1, tag1) = rest.split_at(EK_LEN);
        let mut st = init(relay);
        let e: [u8; 32] = e.try_into().map_err(|_| Error::Length)?;
        st.mix_hash(&e);
        st.trace(trace, "1.1 e");
        let es = s_sk.diffie_hellman(&XPublic::from(e));
        contributory(&es)?;
        st.mix_key(es.as_bytes());
        st.trace(trace, "1.2 es");
        let e1: [u8; EK_LEN] = e1.try_into().map_err(|_| Error::Length)?;
        st.mix_hash(&e1);
        st.trace(trace, "1.3 e1");
        st.open(&mut [], tag1)?;
        st.trace(trace, "1.4 tag1");
        Ok(Self { st, e, e1 })
    }

    /// Writes flight 2 into `out`, which needs `FLIGHT2_LEN` bytes, and
    /// returns `ss_hop`. The ephemeral private key is erased.
    pub fn flight2<R: CryptoRng + ?Sized, T: Trace>(
        self,
        rng: &mut R,
        out: &mut [u8],
        trace: &mut T,
    ) -> Result<Secret<32>, Error> {
        self.flight2_keeping_er(rng, out, trace)
            .map(|(ss_hop, _)| ss_hop)
    }

    /// Writes flight 2 and returns `ss_hop` with the private half of `er`.
    /// The queue relay of a circuit keeps that key as `RelaySession_sk` of
    /// Part 3 §3.2.3 for the life of the circuit, as the responder of §5.4
    /// keeps its `er_sk` under `CRY-136`.
    pub fn flight2_keeping_er<R: CryptoRng + ?Sized, T: Trace>(
        mut self,
        rng: &mut R,
        out: &mut [u8],
        trace: &mut T,
    ) -> Result<(Secret<32>, StaticSecret), Error> {
        let out = out.get_mut(..FLIGHT2_LEN).ok_or(Error::Length)?;
        let (er_out, rest) = out.split_at_mut(32);
        let (ekem1_out, tag_out) = rest.split_at_mut(CT_LEN);
        let st = &mut self.st;
        let er_sk = StaticSecret::random_from_rng(rng);
        let er = XPublic::from(&er_sk);
        er_out.copy_from_slice(er.as_bytes());
        st.mix_hash(er.as_bytes());
        st.trace(trace, "2.1 er");
        let ee = er_sk.diffie_hellman(&XPublic::from(self.e));
        contributory(&ee)?;
        st.mix_key(ee.as_bytes());
        st.trace(trace, "2.2 ee");
        let e1 =
            EncapsulationKey::<MlKem768>::new(&Array::from(self.e1)).map_err(|_| Error::Key)?;
        let (ekem1, ss2) = e1.encapsulate_with_rng(rng);
        ekem1_out.copy_from_slice(&ekem1);
        st.mix_hash(ekem1_out);
        st.mix_key(&ss2);
        st.trace(trace, "2.3 ekem1");
        tag_out.copy_from_slice(&st.seal(&mut [])?);
        st.trace(trace, "2.4 tag2");
        let ss_hop = split(st);
        st.trace(trace, "2.5 split");
        Ok((ss_hop, er_sk))
    }
}
