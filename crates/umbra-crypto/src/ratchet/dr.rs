//! The header-encrypted Double Ratchet of Part 5 §5.5.1 and the ratchet
//! record of Part 6 §6.5.
//!
//! The DH ratchet is X25519. A ratchet step runs one HKDF that gives the
//! next root key, the chain key, and the next header key together. The chain
//! advances by HMAC with the two constants of the specification. Each header
//! travels encrypted (`CRY-017`), thus a relay reads no `dh_pk`, no `pn`, and
//! no `n`.
//!
//! **The initial ratchet key.** Part 5 §5.4.8 gives `RK` and the two header
//! keys and names no initial DH key. This code takes the responder's flight-2
//! ephemeral `er` as the responder's first ratchet key: the initiator holds
//! its public half from the flight, and the responder keeps its private half
//! until the first ratchet step replaces it.
//!
//! Skipped message keys are bounded by the constants of §5.5.4, which are
//! enforced and not advisory.

use alloc::vec::Vec;

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::CryptoRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    handshake::xk::SessionKeys,
    labels,
    secret::Secret,
    stored::{Reader, Writer},
    Error,
};

/// `MAX_SKIP`, the skipped keys one chain may leave.
pub const MAX_SKIP: u32 = 1000;
/// `MAX_STORED`, the skipped keys one session may hold.
pub const MAX_STORED: usize = 2000;
/// `SKIP_TTL` in seconds: 45 days, equal to `MSG_TTL`.
pub const SKIP_TTL: u64 = 45 * 86_400;

/// The record version of Part 6 §6.5.
pub const VERSION: u8 = 0x02;
/// The encrypted header: `dh_pk` 32, `pn` 4, `n` 4, and the tag.
pub const HDR_CT_LEN: usize = 56;
/// The record less the body: `version`, `ctx`, `hdr_nonce`, `hdr_ct`,
/// `pq_frame_len`, and `body_nonce`.
pub const RECORD_FIXED: usize = 1 + 4 + 12 + HDR_CT_LEN + 1 + 12;
/// The body AEAD tag.
pub const BODY_TAG_LEN: usize = 16;
/// The longest braid frame.
pub const MAX_PQ_FRAME: usize = 135;

const _: () = assert!(RECORD_FIXED == 86);

/// The role of a party, which fixes the header keys of the first chains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The party that sent flight 1.
    Initiator,
    /// The party that sent flight 2.
    Responder,
}

/// A skipped message key, held until its record arrives or `SKIP_TTL` ends.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Skipped {
    hk: [u8; 32],
    n: u32,
    mk: [u8; 32],
    #[zeroize(skip)]
    stored_at: u64,
}

/// One party's state of one pairwise session.
///
/// The field names follow the symbols of Part 5 §5.5.1 and of the Double
/// Ratchet specification, thus a reader can hold the text beside the code:
/// `rk` is the root key, `dh_s` and `dh_r` the sending and received ratchet
/// keys, `ck_s` and `ck_r` the chain keys, `hk_s` and `hk_r` the header keys,
/// `nhk_s` and `nhk_r` the next header keys, `n_s` and `n_r` the chain
/// positions, and `pn` the length of the previous sending chain.
pub struct Session {
    rk: Secret<32>,
    dh_s: StaticSecret,
    dh_r: Option<[u8; 32]>,
    ck_s: Option<Secret<32>>,
    ck_r: Option<Secret<32>>,
    hk_s: Option<Secret<32>>,
    nhk_s: Secret<32>,
    hk_r: Option<Secret<32>>,
    nhk_r: Secret<32>,
    n_s: u32,
    n_r: u32,
    pn: u32,
    send_index: u16,
    session_tag: [u8; 2],
    skipped: Vec<Skipped>,
    mixed: u32,
}

/// A parsed record header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The sender's current ratchet public key.
    pub dh_pk: [u8; 32],
    /// The length of the previous sending chain.
    pub pn: u32,
    /// The position in the current sending chain.
    pub n: u32,
}

/// The context field, readable without a header key (`WIR-252`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ctx {
    /// `SHA3-256("umbra/v1/session-tag" || RK)[0..2]` of the initial root key.
    pub session_tag: [u8; 2],
    /// The low 16 bits of the sender's record count in the session.
    pub send_index: u16,
}

/// What a received record gives besides its plaintext.
pub struct Received<'a> {
    /// The context field.
    pub ctx: Ctx,
    /// The decrypted header.
    pub header: Header,
    /// The braid frame, if the record carried one.
    pub pq_frame: Option<&'a [u8]>,
    /// The plaintext length written into the caller's buffer.
    pub len: usize,
}

/// `KDF_RK`: one HKDF call gives the next root key, the chain key, and the
/// next header key, in that order (`CRY-063`).
/// The two points of a ratchet step at which the braid of §5.5.2 mixes a
/// post-quantum secret into the root key. A step derives the receiving chain
/// first and the sending chain second; the peer derives the same two chains
/// in the mirror order, thus a mix before one of them lands on one root key
/// at both parties.
pub trait StepHooks {
    /// The generator of the new ratchet key of the step.
    type Rng: CryptoRng + ?Sized;

    /// The generator.
    fn rng(&mut self) -> &mut Self::Rng;

    /// Before the receiving chain of the step derives. `frame` is the braid
    /// frame of the record that carried the new ratchet key. Returns an
    /// epoch and its secret to mix, or nothing.
    fn before_receive_chain(
        &mut self,
        header: &Header,
        frame: Option<&[u8]>,
    ) -> Option<(u32, Secret<32>)>;

    /// Before the sending chain of the step derives. Returns an epoch and its
    /// secret to mix, or nothing.
    fn before_send_chain(&mut self) -> Option<(u32, Secret<32>)>;
}

/// The hooks of a session with no braid: nothing is mixed.
pub struct NoBraid<'a, R: ?Sized> {
    /// The generator of the new ratchet key.
    pub rng: &'a mut R,
}

impl<R: CryptoRng + ?Sized> StepHooks for NoBraid<'_, R> {
    type Rng = R;
    fn rng(&mut self) -> &mut R {
        self.rng
    }
    fn before_receive_chain(&mut self, _: &Header, _: Option<&[u8]>) -> Option<(u32, Secret<32>)> {
        None
    }
    fn before_send_chain(&mut self) -> Option<(u32, Secret<32>)> {
        None
    }
}

fn kdf_rk(root_key: &Secret<32>, dh_output: &[u8; 32]) -> (Secret<32>, Secret<32>, Secret<32>) {
    let kdf = Hkdf::<Sha3_256>::new(Some(root_key.expose()), dh_output);
    let mut output = Secret::<96>::zeroed();
    let _ = kdf.expand(labels::RATCHET_ROOT, output.expose_mut());

    let mut next_root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];
    let mut next_header_key = [0u8; 32];
    let (root_part, rest) = output.expose().split_at(32);
    let (chain_part, header_part) = rest.split_at(32);
    next_root_key.copy_from_slice(root_part);
    chain_key.copy_from_slice(chain_part);
    next_header_key.copy_from_slice(header_part);

    (
        Secret::new(next_root_key),
        Secret::new(chain_key),
        Secret::new(next_header_key),
    )
}

fn hmac_chain(chain_key: &Secret<32>, constant: u8) -> Secret<32> {
    // HMAC accepts any key length, thus the Result never carries Err.
    let mut mac = match Hmac::<Sha3_256>::new_from_slice(chain_key.expose()) {
        Ok(mac) => mac,
        Err(_) => Hmac::<Sha3_256>::new(&Default::default()),
    };
    mac.update(labels::RATCHET_CHAIN);
    mac.update(&[constant]);
    Secret::new(mac.finalize().into_bytes().into())
}

/// `MK = HMAC(CK, label || 0x01)`, `CK' = HMAC(CK, label || 0x02)`.
fn kdf_ck(chain_key: &Secret<32>) -> (Secret<32>, Secret<32>) {
    let next_chain_key = hmac_chain(chain_key, 0x02);
    let message_key = hmac_chain(chain_key, 0x01);
    (next_chain_key, message_key)
}

fn dh(secret: &StaticSecret, public: &[u8; 32]) -> Result<[u8; 32], Error> {
    let shared = secret.diffie_hellman(&XPublic::from(*public));
    if !shared.was_contributory() {
        return Err(Error::Ratchet);
    }
    Ok(*shared.as_bytes())
}

fn seal(key: &Secret<32>, nonce: &[u8; 12], ad: &[u8], buf: &mut [u8]) -> Result<[u8; 16], Error> {
    let tag = ChaCha20Poly1305::new(key.expose().into())
        .encrypt_inout_detached(&Nonce::from(*nonce), ad, buf.into())
        .map_err(|_| Error::Ratchet)?;
    Ok(tag.into())
}

fn open(
    key: &Secret<32>,
    nonce: &[u8; 12],
    ad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let tag: [u8; 16] = tag.try_into().map_err(|_| Error::Ratchet)?;
    ChaCha20Poly1305::new(key.expose().into())
        .decrypt_inout_detached(&Nonce::from(*nonce), ad, buf.into(), &Tag::from(tag))
        .map_err(|_| Error::Ratchet)
}

fn write_secret(writer: &mut Writer, secret: &Secret<32>) {
    writer.bytes(secret.expose());
}

fn read_secret(reader: &mut Reader<'_>) -> Result<Secret<32>, Error> {
    Ok(Secret::new(reader.array()?))
}

impl Session {
    /// Writes the state of the session for the at-rest store. The bytes hold
    /// each key of the session, thus they go into a sealed record only.
    pub(crate) fn export(&self, writer: &mut Writer) -> Result<(), Error> {
        write_secret(writer, &self.rk);
        writer.bytes(self.dh_s.as_bytes());
        writer.option(self.dh_r.as_ref(), |w, key| w.bytes(key));
        writer.option(self.ck_s.as_ref(), write_secret);
        writer.option(self.ck_r.as_ref(), write_secret);
        writer.option(self.hk_s.as_ref(), write_secret);
        write_secret(writer, &self.nhk_s);
        writer.option(self.hk_r.as_ref(), write_secret);
        write_secret(writer, &self.nhk_r);
        writer.u32(self.n_s);
        writer.u32(self.n_r);
        writer.u32(self.pn);
        writer.u16(self.send_index);
        writer.bytes(&self.session_tag);
        writer.u32(self.mixed);
        writer.u32(u32::try_from(self.skipped.len()).map_err(|_| Error::Length)?);
        for skipped in &self.skipped {
            writer.bytes(&skipped.hk);
            writer.u32(skipped.n);
            writer.bytes(&skipped.mk);
            writer.u64(skipped.stored_at);
        }
        Ok(())
    }

    /// Reads the state that [`Session::export`] wrote.
    pub(crate) fn restore(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let rk = read_secret(reader)?;
        let dh_s = StaticSecret::from(reader.array::<32>()?);
        let dh_r = reader.option(|r| r.array::<32>())?;
        let ck_s = reader.option(read_secret)?;
        let ck_r = reader.option(read_secret)?;
        let hk_s = reader.option(read_secret)?;
        let nhk_s = read_secret(reader)?;
        let hk_r = reader.option(read_secret)?;
        let nhk_r = read_secret(reader)?;
        let n_s = reader.u32()?;
        let n_r = reader.u32()?;
        let pn = reader.u32()?;
        let send_index = reader.u16()?;
        let session_tag = reader.array()?;
        let mixed = reader.u32()?;
        let count = usize::try_from(reader.u32()?).map_err(|_| Error::Length)?;
        // CRY-023: a stored session holds no more keys than a live one.
        if count > MAX_STORED {
            return Err(Error::Ratchet);
        }
        let mut skipped = Vec::with_capacity(count);
        for _ in 0..count {
            skipped.push(Skipped {
                hk: reader.array()?,
                n: reader.u32()?,
                mk: reader.array()?,
                stored_at: reader.u64()?,
            });
        }
        Ok(Self {
            rk,
            dh_s,
            dh_r,
            ck_s,
            ck_r,
            hk_s,
            nhk_s,
            hk_r,
            nhk_r,
            n_s,
            n_r,
            pn,
            send_index,
            session_tag,
            skipped,
            mixed,
        })
    }

    /// Starts a session from the split of a completed handshake.
    pub fn new<R: CryptoRng + ?Sized>(
        keys: SessionKeys,
        role: Role,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let SessionKeys {
            rk,
            hk_i2r,
            hk_r2i,
            dh_initial,
            ..
        } = keys;
        let mut tag_hash = Sha3_256::new();
        tag_hash.update(labels::SESSION_TAG);
        tag_hash.update(rk.expose());
        let tag_digest: [u8; 32] = tag_hash.finalize().into();
        let mut session_tag = [0u8; 2];
        session_tag.copy_from_slice(tag_digest.get(..2).ok_or(Error::Length)?);

        let session = match role {
            Role::Initiator => {
                let peer = dh_initial.peer_public().ok_or(Error::Ratchet)?;
                let dh_s = StaticSecret::random_from_rng(rng);
                let (root_key, ck_s, nhk_s) = kdf_rk(&rk, &dh(&dh_s, &peer)?);
                Self {
                    rk: root_key,
                    dh_s,
                    dh_r: Some(peer),
                    ck_s: Some(ck_s),
                    ck_r: None,
                    hk_s: Some(hk_i2r),
                    nhk_s,
                    hk_r: None,
                    nhk_r: hk_r2i,
                    n_s: 0,
                    n_r: 0,
                    pn: 0,
                    send_index: 0,
                    session_tag,
                    skipped: Vec::new(),
                    mixed: 0,
                }
            }
            Role::Responder => {
                let own = dh_initial.into_own_secret().ok_or(Error::Ratchet)?;
                Self {
                    rk,
                    dh_s: own,
                    dh_r: None,
                    ck_s: None,
                    ck_r: None,
                    hk_s: None,
                    nhk_s: hk_r2i,
                    hk_r: None,
                    nhk_r: hk_i2r,
                    n_s: 0,
                    n_r: 0,
                    pn: 0,
                    send_index: 0,
                    session_tag,
                    skipped: Vec::new(),
                    mixed: 0,
                }
            }
        };
        Ok(session)
    }

    /// The context field of the next record this party sends.
    pub fn ctx(&self) -> Ctx {
        Ctx {
            session_tag: self.session_tag,
            send_index: self.send_index,
        }
    }

    /// Reads the context field of a record without a key (`WIR-252`).
    pub fn peek_ctx(record: &[u8]) -> Result<Ctx, Error> {
        match record {
            [VERSION, t0, t1, i0, i1, ..] => Ok(Ctx {
                session_tag: [*t0, *t1],
                send_index: u16::from_be_bytes([*i0, *i1]),
            }),
            _ => Err(Error::Length),
        }
    }

    /// Bytes a record adds to its plaintext with a frame of `pq_frame_len`.
    pub const fn overhead(pq_frame_len: usize) -> usize {
        RECORD_FIXED + pq_frame_len + BODY_TAG_LEN
    }

    /// Encrypts `plaintext` into `out` as one record with the optional braid
    /// `pq_frame`, and returns the record length.
    pub fn send<R: CryptoRng + ?Sized>(
        &mut self,
        plaintext: &[u8],
        pq_frame: Option<&[u8]>,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let frame = pq_frame.unwrap_or(&[]);
        if frame.len() > MAX_PQ_FRAME {
            return Err(Error::Length);
        }

        let record_len = Self::overhead(frame.len()) + plaintext.len();
        let record = out.get_mut(..record_len).ok_or(Error::Length)?;

        // The message key comes from the sending chain, which advances once.
        let chain_key = self.ck_s.take().ok_or(Error::Ratchet)?;
        let header_key = self.hk_s.as_ref().ok_or(Error::Ratchet)?;
        let (next_chain_key, message_key) = kdf_ck(&chain_key);
        self.ck_s = Some(next_chain_key);

        // Everything before the body nonce is the associated data of the
        // body, thus a frame cannot move to another record.
        let prefix_len = 5 + 12 + HDR_CT_LEN + 1 + frame.len();
        let (prefix, body_region) = record.split_at_mut(prefix_len);

        // version || ctx
        let (version_and_ctx, after_ctx) = prefix.split_at_mut(5);
        let send_index = self.send_index.to_be_bytes();
        version_and_ctx.copy_from_slice(&[
            VERSION,
            self.session_tag[0],
            self.session_tag[1],
            send_index[0],
            send_index[1],
        ]);

        // hdr_nonce || hdr_ct, where hdr_ct = AEAD(dh_pk || pn || n) and its tag
        let (header_nonce, after_header_nonce) = after_ctx.split_at_mut(12);
        rng.fill_bytes(header_nonce);
        let header_nonce_value: [u8; 12] = (*header_nonce).try_into().map_err(|_| Error::Length)?;

        let (header_ct, after_header) = after_header_nonce.split_at_mut(HDR_CT_LEN);
        let (header_plain, header_tag) = header_ct.split_at_mut(40);
        let (dh_pk_out, counters_out) = header_plain.split_at_mut(32);
        dh_pk_out.copy_from_slice(XPublic::from(&self.dh_s).as_bytes());
        let (pn_out, n_out) = counters_out.split_at_mut(4);
        pn_out.copy_from_slice(&self.pn.to_be_bytes());
        n_out.copy_from_slice(&self.n_s.to_be_bytes());
        let tag = seal(
            header_key,
            &header_nonce_value,
            version_and_ctx,
            header_plain,
        )?;
        header_tag.copy_from_slice(&tag);

        // pq_frame_len || pq_frame
        let (frame_len_out, frame_out) = after_header.split_at_mut(1);
        frame_len_out.copy_from_slice(&[frame.len() as u8]);
        frame_out.copy_from_slice(frame);

        // body_nonce || body_ct
        let (body_nonce, body) = body_region.split_at_mut(12);
        rng.fill_bytes(body_nonce);
        let body_nonce_value: [u8; 12] = (*body_nonce).try_into().map_err(|_| Error::Length)?;

        let (body_plain, body_tag) = body.split_at_mut(plaintext.len());
        body_plain.copy_from_slice(plaintext);
        let tag = seal(&message_key, &body_nonce_value, prefix, body_plain)?;
        body_tag.copy_from_slice(&tag);

        self.n_s = self.n_s.checked_add(1).ok_or(Error::Ratchet)?;
        self.send_index = self.send_index.wrapping_add(1);
        Ok(record_len)
    }

    /// Decrypts `record` into `out`. `now` is the wall clock in seconds, for
    /// the age of a stored skipped key.
    pub fn receive<'a, R: CryptoRng + ?Sized>(
        &mut self,
        record: &'a [u8],
        now: u64,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<Received<'a>, Error> {
        self.receive_with(record, now, out, &mut NoBraid { rng })
    }

    /// [`Session::receive`] with the braid hooks of a ratchet step. The
    /// generator of a new ratchet key comes from the hooks.
    pub fn receive_with<'a, H: StepHooks>(
        &mut self,
        record: &'a [u8],
        now: u64,
        out: &mut [u8],
        hooks: &mut H,
    ) -> Result<Received<'a>, Error> {
        let ctx = Self::peek_ctx(record)?;
        // The sender picks the length of a record, thus each split checks
        // it and a short record is one error, never a panic.
        let (head, rest) = record.split_at_checked(5).ok_or(Error::Length)?;
        let (hdr_nonce, rest) = rest.split_at_checked(12).ok_or(Error::Length)?;
        let hdr_nonce: [u8; 12] = hdr_nonce.try_into().map_err(|_| Error::Length)?;
        let (hdr_ct, rest) = rest.split_at_checked(HDR_CT_LEN).ok_or(Error::Length)?;
        let (flen, rest) = rest.split_at_checked(1).ok_or(Error::Length)?;
        let frame_len = usize::from(*flen.first().ok_or(Error::Length)?);
        if frame_len != 0 && frame_len != 39 && frame_len != 71 && frame_len != 135 {
            return Err(Error::Length);
        }
        let (frame, rest) = rest.split_at_checked(frame_len).ok_or(Error::Length)?;
        let (body_nonce, body) = rest.split_at_checked(12).ok_or(Error::Length)?;
        let body_nonce: [u8; 12] = body_nonce.try_into().map_err(|_| Error::Length)?;
        let pt_len = body.len().checked_sub(BODY_TAG_LEN).ok_or(Error::Length)?;
        let (body_ct, body_tag) = body.split_at_checked(pt_len).ok_or(Error::Length)?;
        let ad_len = 5 + 12 + HDR_CT_LEN + 1 + frame_len;
        let (ad, _) = record.split_at_checked(ad_len).ok_or(Error::Length)?;
        let out = out.get_mut(..pt_len).ok_or(Error::Length)?;

        // A skipped key first. The key leaves the store only when the body
        // opens under it, thus a body that a relay changed costs no key.
        if let Some((index, header, mk)) = self.try_skipped(&hdr_nonce, head, hdr_ct) {
            out.copy_from_slice(body_ct);
            open(&mk, &body_nonce, ad, out, body_tag)?;
            self.skipped.swap_remove(index);
            return Ok(Received {
                ctx,
                header,
                pq_frame: (frame_len > 0).then_some(frame),
                len: pt_len,
            });
        }
        let (header, ratchet) = self.decrypt_header(&hdr_nonce, head, hdr_ct)?;
        // A record below the chain that no skipped key names is a replay:
        // it moves no chain.
        if !ratchet && header.n < self.n_r {
            return Err(Error::Ratchet);
        }
        if ratchet {
            self.skip(header.pn, now)?;
            let frame_of_step = (frame_len > 0).then_some(frame);
            self.dh_ratchet(&header, frame_of_step, hooks)?;
        }
        self.skip(header.n, now)?;
        let ck = self.ck_r.take().ok_or(Error::Ratchet)?;
        let (ck_next, mk) = kdf_ck(&ck);
        self.ck_r = Some(ck_next);
        self.n_r = self.n_r.checked_add(1).ok_or(Error::Ratchet)?;
        out.copy_from_slice(body_ct);
        open(&mk, &body_nonce, ad, out, body_tag)?;
        Ok(Received {
            ctx,
            header,
            pq_frame: (frame_len > 0).then_some(frame),
            len: pt_len,
        })
    }

    /// Drops every skipped key older than `SKIP_TTL` at `now`.
    pub fn prune(&mut self, now: u64) {
        self.skipped
            .retain(|s| now.saturating_sub(s.stored_at) < SKIP_TTL);
    }

    /// The count of skipped keys held.
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// The skipped key whose header key opens the header, with its index.
    /// The caller removes it once the body opens.
    fn try_skipped(
        &self,
        nonce: &[u8; 12],
        ad: &[u8],
        hdr_ct: &[u8],
    ) -> Option<(usize, Header, Secret<32>)> {
        self.skipped.iter().enumerate().find_map(|(i, s)| {
            let hk = Secret::new(s.hk);
            let h = open_header(&hk, nonce, ad, hdr_ct).ok()?;
            (h.n == s.n).then(|| (i, h, Secret::new(s.mk)))
        })
    }

    fn decrypt_header(
        &self,
        nonce: &[u8; 12],
        ad: &[u8],
        hdr_ct: &[u8],
    ) -> Result<(Header, bool), Error> {
        if let Some(hk) = self.hk_r.as_ref() {
            if let Ok(h) = open_header(hk, nonce, ad, hdr_ct) {
                return Ok((h, false));
            }
        }
        let h = open_header(&self.nhk_r, nonce, ad, hdr_ct)?;
        Ok((h, true))
    }

    /// Stores the keys of the receiving chain up to `until` (`MAX_SKIP`,
    /// `MAX_STORED`).
    fn skip(&mut self, until: u32, now: u64) -> Result<(), Error> {
        let Some(ck) = self.ck_r.take() else {
            return Ok(());
        };
        let hk = match self.hk_r.as_ref() {
            Some(h) => *h.expose(),
            None => {
                self.ck_r = Some(ck);
                return Ok(());
            }
        };
        if until.saturating_sub(self.n_r) > MAX_SKIP {
            self.ck_r = Some(ck);
            return Err(Error::Ratchet);
        }
        let mut ck = ck;
        while self.n_r < until {
            if self.skipped.len() >= MAX_STORED {
                self.ck_r = Some(ck);
                return Err(Error::Ratchet);
            }
            let (next, mk) = kdf_ck(&ck);
            self.skipped.push(Skipped {
                hk,
                n: self.n_r,
                mk: *mk.expose(),
                stored_at: now,
            });
            ck = next;
            self.n_r += 1;
        }
        self.ck_r = Some(ck);
        Ok(())
    }

    fn dh_ratchet<H: StepHooks>(
        &mut self,
        header: &Header,
        frame: Option<&[u8]>,
        hooks: &mut H,
    ) -> Result<(), Error> {
        self.pn = self.n_s;
        self.n_s = 0;
        self.n_r = 0;
        self.hk_s = Some(take_secret(&mut self.nhk_s));
        self.hk_r = Some(take_secret(&mut self.nhk_r));
        self.dh_r = Some(header.dh_pk);

        if let Some((epoch, secret)) = hooks.before_receive_chain(header, frame) {
            self.mix_root(epoch, &secret);
        }
        let (root_key, ck_r, nhk_r) = kdf_rk(&self.rk, &dh(&self.dh_s, &header.dh_pk)?);
        self.rk = root_key;
        self.ck_r = Some(ck_r);
        self.nhk_r = nhk_r;

        if let Some((epoch, secret)) = hooks.before_send_chain() {
            self.mix_root(epoch, &secret);
        }
        self.dh_s = StaticSecret::random_from_rng(hooks.rng());
        let (root_key, ck_s, nhk_s) = kdf_rk(&self.rk, &dh(&self.dh_s, &header.dh_pk)?);
        self.rk = root_key;
        self.ck_s = Some(ck_s);
        self.nhk_s = nhk_s;
        Ok(())
    }

    /// `RK <- HKDF(salt = RK, ikm = ss_pq, info = "umbra/v1/pq-epoch" || BE32(epoch))`
    /// (`CRY-064`).
    fn mix_root(&mut self, epoch: u32, secret: &Secret<32>) {
        let kdf = Hkdf::<Sha3_256>::new(Some(self.rk.expose()), secret.expose());
        let mut next = Secret::<32>::zeroed();
        let _ = kdf.expand_multi_info(&[labels::PQ_EPOCH, &epoch.to_be_bytes()], next.expose_mut());
        self.rk = next;
        self.mixed = self.mixed.saturating_add(1);
    }

    /// The count of post-quantum secrets mixed into the root key so far.
    pub fn mixed(&self) -> u32 {
        self.mixed
    }

    /// Whether a sending chain exists. A responder has none before the
    /// first record of the initiator arrives, because that record carries
    /// the ratchet key of the initiator.
    pub fn can_send(&self) -> bool {
        self.ck_s.is_some()
    }

    /// The position of the next record in the sending chain; zero at a
    /// chain start.
    pub fn sending_position(&self) -> u32 {
        self.n_s
    }
}

fn take_secret(s: &mut Secret<32>) -> Secret<32> {
    let out = Secret::new(*s.expose());
    *s = Secret::zeroed();
    out
}

fn open_header(
    hk: &Secret<32>,
    nonce: &[u8; 12],
    ad: &[u8],
    hdr_ct: &[u8],
) -> Result<Header, Error> {
    let (ct, tag) = hdr_ct.split_at(40);
    let mut pt = [0u8; 40];
    pt.copy_from_slice(ct);
    open(hk, nonce, ad, &mut pt, tag)?;
    let (pk, tail) = pt.split_at(32);
    let (pn, n) = tail.split_at(4);
    let mut dh_pk = [0u8; 32];
    dh_pk.copy_from_slice(pk);
    Ok(Header {
        dh_pk,
        pn: u32::from_be_bytes(pn.try_into().map_err(|_| Error::Length)?),
        n: u32::from_be_bytes(n.try_into().map_err(|_| Error::Length)?),
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
    use crate::{
        handshake::xk::{InitialDh, SessionKeys},
        test_rng::TestRng,
    };
    use alloc::{vec, vec::Vec};

    fn pair(seed: &[u8]) -> (Session, Session, TestRng) {
        let mut rng = TestRng::new(seed);
        let er_sk = StaticSecret::random_from_rng(&mut rng);
        let er = *XPublic::from(&er_sk).as_bytes();
        let keys = |dh| SessionKeys {
            rk: Secret::new([1u8; 32]),
            hk_i2r: Secret::new([2u8; 32]),
            hk_r2i: Secret::new([3u8; 32]),
            transcript: [0u8; 32],
            dh_initial: dh,
        };
        let a = Session::new(keys(InitialDh::Peer(er)), Role::Initiator, &mut rng).unwrap();
        let b = Session::new(keys(InitialDh::Own(er_sk)), Role::Responder, &mut rng).unwrap();
        (a, b, rng)
    }

    fn send(s: &mut Session, rng: &mut TestRng, msg: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; Session::overhead(0) + msg.len()];
        let n = s.send(msg, None, rng, &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn recv(s: &mut Session, rng: &mut TestRng, rec: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; rec.len()];
        let r = s.receive(rec, 1_000, rng, &mut out)?;
        out.truncate(r.len);
        Ok(out)
    }

    #[test]
    fn conversation_in_both_directions_with_ratchet_steps() {
        let (mut a, mut b, mut rng) = pair(b"dr");
        for round in 0..5u8 {
            let m1 = send(&mut a, &mut rng, &[round, 1]);
            let m2 = send(&mut a, &mut rng, &[round, 2]);
            assert_eq!(recv(&mut b, &mut rng, &m1).unwrap(), [round, 1]);
            assert_eq!(recv(&mut b, &mut rng, &m2).unwrap(), [round, 2]);
            let r1 = send(&mut b, &mut rng, &[round, 3]);
            assert_eq!(recv(&mut a, &mut rng, &r1).unwrap(), [round, 3]);
        }
        assert_eq!(a.ctx().send_index, 10);
        assert_eq!(b.ctx().send_index, 5);
        assert_eq!(
            Session::peek_ctx(&send(&mut a, &mut rng, b"x"))
                .unwrap()
                .session_tag,
            a.session_tag
        );
    }

    #[test]
    fn out_of_order_records_use_skipped_keys_across_a_ratchet_step() {
        let (mut a, mut b, mut rng) = pair(b"skip");
        let m0 = send(&mut a, &mut rng, b"m0");
        let m1 = send(&mut a, &mut rng, b"m1");
        let m2 = send(&mut a, &mut rng, b"m2");
        assert_eq!(recv(&mut b, &mut rng, &m2).unwrap(), b"m2");
        assert_eq!(b.skipped_len(), 2);
        let r0 = send(&mut b, &mut rng, b"r0");
        assert_eq!(recv(&mut a, &mut rng, &r0).unwrap(), b"r0");
        let m3 = send(&mut a, &mut rng, b"m3"); // new chain after the step
        assert_eq!(recv(&mut b, &mut rng, &m3).unwrap(), b"m3");
        assert_eq!(recv(&mut b, &mut rng, &m0).unwrap(), b"m0");
        assert_eq!(recv(&mut b, &mut rng, &m1).unwrap(), b"m1");
        assert_eq!(b.skipped_len(), 0);
        // a replay fails: the key is gone
        assert_eq!(recv(&mut b, &mut rng, &m1).err(), Some(Error::Ratchet));
    }

    #[test]
    fn a_changed_byte_fails_and_a_frame_is_bound() {
        let (mut a, mut b, mut rng) = pair(b"tamper");
        let mut out = vec![0u8; Session::overhead(39) + 4];
        let frame = [7u8; 39];
        let n = a.send(b"text", Some(&frame), &mut rng, &mut out).unwrap();
        let mut rec = out[..n].to_vec();
        let mut pt = vec![0u8; 8];
        let r = b.receive(&rec, 0, &mut rng, &mut pt).unwrap();
        assert_eq!(r.pq_frame, Some(&frame[..]));
        assert_eq!(&pt[..r.len], b"text");
        rec[90] ^= 1; // inside the frame
        let (mut a2, mut b2, mut rng2) = pair(b"tamper");
        let n = a2.send(b"text", Some(&frame), &mut rng2, &mut out).unwrap();
        let mut rec2 = out[..n].to_vec();
        rec2[90] ^= 1;
        assert_eq!(
            b2.receive(&rec2, 0, &mut rng2, &mut pt).err(),
            Some(Error::Ratchet)
        );
        let _ = rec;
    }

    #[test]
    fn max_skip_is_enforced() {
        let (mut a, mut b, mut rng) = pair(b"maxskip");
        for _ in 0..(MAX_SKIP + 1) {
            let _ = send(&mut a, &mut rng, b"x");
        }
        let far = send(&mut a, &mut rng, b"far");
        assert_eq!(recv(&mut b, &mut rng, &far).err(), Some(Error::Ratchet));
        assert_eq!(b.skipped_len(), 0);
    }

    #[test]
    fn prune_drops_old_keys() {
        let (mut a, mut b, mut rng) = pair(b"prune");
        let _ = send(&mut a, &mut rng, b"lost");
        let m = send(&mut a, &mut rng, b"m");
        let mut out = vec![0u8; 8];
        b.receive(&m, 100, &mut rng, &mut out).unwrap();
        assert_eq!(b.skipped_len(), 1);
        b.prune(100 + SKIP_TTL - 1);
        assert_eq!(b.skipped_len(), 1);
        b.prune(100 + SKIP_TTL);
        assert_eq!(b.skipped_len(), 0);
    }
}
