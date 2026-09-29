//! The chunked ML-KEM braid of Part 5 §5.5.2 and §5.5.3, joined to the
//! Double Ratchet.
//!
//! Each party runs one strand of epochs. An epoch carries the party's new
//! encapsulation key and a ciphertext against a key of the peer, coded into
//! chunks that ride one per record. The two strands interlock under four
//! rules that the specification leaves open:
//!
//! 1. **Targets are implicit.** The initiator's epoch `e` encapsulates to the
//!    responder's key of epoch `e − 1`; the responder's epoch `e` encapsulates
//!    to the initiator's key of epoch `e`. No field names the target.
//! 2. **The initiator's first epoch carries an empty ciphertext**, because no
//!    responder key exists yet. The responder starts its first epoch once it
//!    has rebuilt the initiator's first.
//! 3. **An epoch advances only at a DH chain start**, thus every record of a
//!    chain carries one epoch number, and any record of the chain reveals it.
//!    A chain-start record always carries a frame.
//! 4. **The secret of an epoch enters the root key at the owner's first DH
//!    step whose chain carries the next epoch.** The owner mixes before it
//!    derives that sending chain; the peer mixes before it derives the same
//!    chain as its receiving chain, when it sees the higher epoch number.
//!
//! An epoch is complete when the peer's ciphertext against its key has been
//! rebuilt. A party starts the next epoch at the first chain start after its
//! epoch is complete and a limit of §5.5.3 has occurred (`CRY-133`).

use alloc::vec::Vec;

use kem::{Decapsulate, Encapsulate};
use ml_kem::{array::Array, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, Seed};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{
    codeword::{Collector, Kind, Material, Width},
    dr::{Header, Received, Role, Session, StepHooks},
};
use crate::{
    handshake::xk::SessionKeys,
    secret::Secret,
    stored::{Reader, Writer},
    Error,
};

/// `N`, the records after which a sender starts a new epoch.
pub const EPOCH_RECORDS: u32 = 100;
/// `T`, the seconds after which a sender starts a new epoch.
pub const EPOCH_SECONDS: u64 = 7 * 86_400;
/// The fixed part of a braid frame: `epoch`, `kind`, `index`.
pub const FRAME_FIXED: usize = 7;

/// A party's strand plus what it holds of the peer's strand.
struct Braid {
    role: Role,
    width: Width,

    // own strand
    epoch: u32,
    own_dk: Option<DecapsulationKey<MlKem768>>,
    material: Option<Material>,
    next_chunk: usize,
    records_in_epoch: u32,
    epoch_started_at: u64,
    complete: bool,
    /// The secret of the own epoch, from the peer's ciphertext, awaiting the
    /// mix at the next advance.
    own_secret: Option<Secret<32>>,

    // peer strand
    peer_epoch: u32,
    collector: Option<Collector>,
    peer_ek: Option<(u32, [u8; 1184])>,
    /// The secret this party made when it encapsulated to the peer's key of
    /// the named epoch, awaiting the peer's advance past that epoch.
    peer_secret: Option<(u32, Secret<32>)>,
}

/// A session with both ratchets.
pub struct Ratchet {
    session: Session,
    braid: Braid,
}

/// What a received record gives.
pub struct Opened {
    /// The Double Ratchet header and context.
    pub header: Header,
    /// The plaintext length written into the caller's buffer.
    pub len: usize,
    /// The peer's epoch as the record named it, if it carried a frame.
    pub peer_epoch: Option<u32>,
}

fn target_of(role: Role, epoch: u32) -> Option<u32> {
    match role {
        Role::Initiator => epoch.checked_sub(1).filter(|target| *target > 0),
        Role::Responder => Some(epoch),
    }
}

fn is_target_of(role: Role, own_epoch: u32, peer_epoch: u32) -> bool {
    // The peer's epoch `peer_epoch` targets this party's epoch `own_epoch`
    // exactly when the mirror of `target_of` holds.
    target_of(role.mirror(), peer_epoch) == Some(own_epoch)
}

impl Role {
    fn mirror(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

impl Braid {
    fn start_epoch<R: CryptoRng + ?Sized>(
        &mut self,
        epoch: u32,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut seed = Secret::<64>::zeroed();
        rng.fill_bytes(seed.expose_mut());
        let dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed.expose()));
        let ek: [u8; 1184] = dk.encapsulation_key().to_bytes().into();

        let mut ct = [0u8; 1088];
        if let Some(target) = target_of(self.role, epoch) {
            let (target_epoch, peer_ek) = self.peer_ek.as_ref().ok_or(Error::Ratchet)?;
            if *target_epoch != target {
                return Err(Error::Ratchet);
            }
            let peer_ek = EncapsulationKey::<MlKem768>::new(&Array::from(*peer_ek))
                .map_err(|_| Error::Key)?;
            let (ciphertext, shared) = peer_ek.encapsulate_with_rng(rng);
            ct.copy_from_slice(&ciphertext);
            self.peer_secret = Some((target, Secret::new(shared.into())));
        }

        self.epoch = epoch;
        self.own_dk = Some(dk);
        self.material = Some(Material::new(&ek, &ct));
        self.next_chunk = 0;
        self.records_in_epoch = 0;
        self.epoch_started_at = now;
        self.complete = false;
        Ok(())
    }

    fn limit_reached(&self, now: u64) -> bool {
        self.records_in_epoch >= EPOCH_RECORDS
            || now.saturating_sub(self.epoch_started_at) >= EPOCH_SECONDS
    }

    /// Whether the next chain start advances the epoch, and to which.
    fn next_epoch(&self, now: u64) -> Option<u32> {
        if self.epoch == 0 {
            // The responder's first epoch waits for the initiator's first key.
            return match (self.role, self.peer_ek.as_ref()) {
                (Role::Responder, Some((1, _))) => Some(1),
                _ => None,
            };
        }
        (self.complete && self.limit_reached(now)).then_some(self.epoch + 1)
    }

    /// The next chunk of the own epoch as a frame, written into `out`.
    fn frame(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let material = self.material.as_ref().ok_or(Error::Ratchet)?;
        let width = self.width;
        let code = width.code();
        let len = FRAME_FIXED + width.bytes();
        let out = out.get_mut(..len).ok_or(Error::Length)?;
        let (head, chunk) = out.split_at_mut(FRAME_FIXED);
        let index = self.next_chunk;
        let kind = width.kind_at(index)? as u8;
        let epoch = self.epoch.to_be_bytes();
        let index_bytes = (index as u16).to_be_bytes();
        head.copy_from_slice(&[
            epoch[0],
            epoch[1],
            epoch[2],
            epoch[3],
            kind,
            index_bytes[0],
            index_bytes[1],
        ]);
        material.chunk(width, index, chunk)?;
        // After the last chunk the sender returns to the first (CRY-131).
        self.next_chunk = (index + 1) % code.n();
        self.records_in_epoch = self.records_in_epoch.saturating_add(1);
        Ok(len)
    }

    /// Absorbs a received frame. Returns the peer's epoch it named.
    fn absorb(&mut self, frame: &[u8]) -> Result<u32, Error> {
        let (head, chunk) = frame.split_at_checked(FRAME_FIXED).ok_or(Error::Length)?;
        let epoch = u32::from_be_bytes(
            head.get(..4)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Length)?,
        );
        let kind = Kind::from_byte(*head.get(4).ok_or(Error::Length)?)?;
        let index = usize::from(u16::from_be_bytes(
            head.get(5..7)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Length)?,
        ));
        let width = Width::from_frame_len(frame.len() as u8)?;
        if width.kind_at(index)? != kind {
            return Err(Error::Ratchet);
        }

        if epoch < self.peer_epoch {
            // A late chunk of an epoch the peer left; nothing to rebuild.
            return Ok(epoch);
        }
        if epoch > self.peer_epoch {
            self.peer_epoch = epoch;
            self.collector = Some(Collector::new(width));
        }
        let collector = self.collector.as_mut().ok_or(Error::Ratchet)?;
        if collector.width() != width {
            return Err(Error::Ratchet);
        }
        let already_done = collector.complete();
        let done = collector.put(index, chunk)?;
        if done && !already_done {
            let material = collector.rebuild()?;
            let ek = material.encapsulation_key()?;
            self.peer_ek = Some((epoch, ek));
            let ct = material.ciphertext();
            if ct.iter().any(|b| *b != 0) && is_target_of(self.role, self.epoch, epoch) {
                let dk = self.own_dk.as_ref().ok_or(Error::Ratchet)?;
                let ct: ml_kem::Ciphertext<MlKem768> = Array::from(ct);
                let shared = dk.decapsulate(&ct);
                self.own_secret = Some(Secret::new(shared.into()));
                self.complete = true;
            }
        }
        Ok(epoch)
    }
}

/// The hooks that connect the braid to a ratchet step.
struct Hooks<'a, R: ?Sized> {
    braid: &'a mut Braid,
    now: u64,
    rng: &'a mut R,
}

impl<R: CryptoRng + ?Sized> StepHooks for Hooks<'_, R> {
    type Rng = R;

    fn rng(&mut self) -> &mut R {
        self.rng
    }

    fn before_receive_chain(
        &mut self,
        _: &Header,
        frame: Option<&[u8]>,
    ) -> Option<(u32, Secret<32>)> {
        // Rule 4 at the peer: a chain with a higher epoch means the peer
        // completed the one before it, whose secret this party made.
        let frame = frame?;
        let head = frame.get(..4)?;
        let chain_epoch = u32::from_be_bytes(head.try_into().ok()?);
        let (target, _) = self.braid.peer_secret.as_ref()?;
        if chain_epoch > *target {
            let (epoch, secret) = self.braid.peer_secret.take()?;
            return Some((epoch, secret));
        }
        None
    }

    fn before_send_chain(&mut self) -> Option<(u32, Secret<32>)> {
        // Rule 4 at the owner: an advance at this chain start mixes the
        // secret of the epoch that completed.
        let next = self.braid.next_epoch(self.now)?;
        let completed = self.braid.epoch;
        let secret = self.braid.own_secret.take();
        self.braid.start_epoch(next, self.now, self.rng).ok()?;
        secret.map(|s| (completed, s))
    }
}

/// The version byte of a stored ratchet.
const STORED_VERSION: u8 = 0x01;

impl Braid {
    fn export(&self, writer: &mut Writer) -> Result<(), Error> {
        writer.flag(self.role == Role::Initiator);
        writer.u8(self.width.to_byte());
        writer.u32(self.epoch);
        // A key of this code comes from a seed, thus the seed restores it.
        let seed = match &self.own_dk {
            Some(dk) => Some(dk.to_seed().ok_or(Error::Key)?),
            None => None,
        };
        writer.option(seed.as_ref(), |w, seed| w.bytes(seed));
        writer.option(self.material.as_ref(), |w, material| w.bytes(&material.0));
        writer.u32(u32::try_from(self.next_chunk).map_err(|_| Error::Length)?);
        writer.u32(self.records_in_epoch);
        writer.u64(self.epoch_started_at);
        writer.flag(self.complete);
        writer.option(self.own_secret.as_ref(), |w, s| w.bytes(s.expose()));
        writer.u32(self.peer_epoch);
        writer.flag(self.collector.is_some());
        if let Some(collector) = &self.collector {
            collector.export(writer)?;
        }
        writer.option(self.peer_ek.as_ref(), |w, (epoch, ek)| {
            w.u32(*epoch);
            w.bytes(ek);
        });
        writer.option(self.peer_secret.as_ref(), |w, (epoch, secret)| {
            w.u32(*epoch);
            w.bytes(secret.expose());
        });
        Ok(())
    }

    fn restore(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let role = if reader.flag()? {
            Role::Initiator
        } else {
            Role::Responder
        };
        let width = Width::from_byte(reader.u8()?)?;
        let epoch = reader.u32()?;
        let own_dk = reader
            .option(|r| r.array::<64>())?
            .map(|seed| DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed)));
        let material = reader.option(|r| Ok(Material(r.array()?)))?;
        let next_chunk = usize::try_from(reader.u32()?).map_err(|_| Error::Length)?;
        let records_in_epoch = reader.u32()?;
        let epoch_started_at = reader.u64()?;
        let complete = reader.flag()?;
        let own_secret = reader.option(|r| Ok(Secret::new(r.array()?)))?;
        let peer_epoch = reader.u32()?;
        let collector = reader.option(Collector::restore)?;
        let peer_ek = reader.option(|r| Ok((r.u32()?, r.array()?)))?;
        let peer_secret = reader.option(|r| Ok((r.u32()?, Secret::new(r.array()?))))?;
        Ok(Braid {
            role,
            width,
            epoch,
            own_dk,
            material,
            next_chunk,
            records_in_epoch,
            epoch_started_at,
            complete,
            own_secret,
            peer_epoch,
            collector,
            peer_ek,
            peer_secret,
        })
    }
}

impl Ratchet {
    /// Writes the state of both ratchets for the at-rest store of Part 14
    /// §14.6.4. The bytes hold each key of the session. A client stores
    /// them before a record of [`Ratchet::send`] leaves the device, because
    /// an earlier state would seal a second record under the same key.
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut writer = Writer::new();
        writer.u8(STORED_VERSION);
        self.session.export(&mut writer)?;
        self.braid.export(&mut writer)?;
        Ok(writer.finish())
    }

    /// Reads the state that [`Ratchet::export`] wrote.
    pub fn restore(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        if reader.u8()? != STORED_VERSION {
            return Err(Error::Length);
        }
        let session = Session::restore(&mut reader)?;
        let braid = Braid::restore(&mut reader)?;
        reader.end()?;
        Ok(Self { session, braid })
    }

    /// Starts both ratchets from a completed handshake.
    pub fn new<R: CryptoRng + ?Sized>(
        keys: SessionKeys,
        role: Role,
        width: Width,
        now: u64,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let session = Session::new(keys, role, rng)?;
        let mut braid = Braid {
            role,
            width,
            epoch: 0,
            own_dk: None,
            material: None,
            next_chunk: 0,
            records_in_epoch: 0,
            epoch_started_at: now,
            complete: false,
            own_secret: None,
            peer_epoch: 0,
            collector: None,
            peer_ek: None,
            peer_secret: None,
        };
        if role == Role::Initiator {
            braid.start_epoch(1, now, rng)?;
        }
        Ok(Self { session, braid })
    }

    /// Whether a sending chain exists. A responder has none before the
    /// first record of the initiator arrives.
    pub fn can_send(&self) -> bool {
        self.session.can_send()
    }

    /// The own epoch, zero before the first.
    pub fn epoch(&self) -> u32 {
        self.braid.epoch
    }

    /// The newest epoch of the peer seen, zero before the first.
    pub fn peer_epoch(&self) -> u32 {
        self.braid.peer_epoch
    }

    /// Whether the own epoch is complete.
    pub fn epoch_complete(&self) -> bool {
        self.braid.complete
    }

    /// The count of post-quantum secrets mixed into the root key so far.
    pub fn mixed(&self) -> u32 {
        self.session.mixed()
    }

    /// The record overhead when a frame rides the record.
    pub fn overhead_with_frame(&self) -> usize {
        Session::overhead(FRAME_FIXED + self.braid.width.bytes())
    }

    /// The context field of the next record this party sends: its
    /// `send_index` names the record in a later key request (`WIR-254`).
    pub fn next_ctx(&self) -> super::dr::Ctx {
        self.session.ctx()
    }

    /// Encrypts `plaintext` into `out`. `frame_allowed` says whether the
    /// bucket has room for this epoch's frame; a chain-start record needs it.
    pub fn send<R: CryptoRng + ?Sized>(
        &mut self,
        plaintext: &[u8],
        frame_allowed: bool,
        now: u64,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let _ = now;
        let chain_start = self.session.sending_position() == 0;
        let has_epoch = self.braid.material.is_some();
        if chain_start && has_epoch && !frame_allowed {
            return Err(Error::Length);
        }
        let mut frame = [0u8; FRAME_FIXED + 128];
        let frame = if has_epoch && frame_allowed {
            let len = self.braid.frame(&mut frame)?;
            frame.get(..len)
        } else {
            None
        };
        self.session.send(plaintext, frame, rng, out)
    }

    /// Decrypts `record` into `out`.
    pub fn receive<R: CryptoRng + ?Sized>(
        &mut self,
        record: &[u8],
        now: u64,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<Opened, Error> {
        let received: Received<'_> = {
            let mut hooks = Hooks {
                braid: &mut self.braid,
                now,
                rng,
            };
            self.session.receive_with(record, now, out, &mut hooks)?
        };
        let peer_epoch = match received.pq_frame {
            Some(frame) => Some(self.braid.absorb(frame)?),
            None => None,
        };
        Ok(Opened {
            header: received.header,
            len: received.len,
            peer_epoch,
        })
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
    use crate::{
        handshake::xk::{InitialDh, SessionKeys},
        test_rng::TestRng,
    };
    use alloc::{vec, vec::Vec};
    use x25519_dalek::{PublicKey as XPublic, StaticSecret};

    fn pair(seed: &[u8], width: Width) -> (Ratchet, Ratchet, TestRng) {
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
        let a = Ratchet::new(
            keys(InitialDh::Peer(er)),
            Role::Initiator,
            width,
            0,
            &mut rng,
        )
        .unwrap();
        let b = Ratchet::new(
            keys(InitialDh::Own(er_sk)),
            Role::Responder,
            width,
            0,
            &mut rng,
        )
        .unwrap();
        (a, b, rng)
    }

    fn send(r: &mut Ratchet, rng: &mut TestRng, msg: &[u8], now: u64) -> Vec<u8> {
        let mut out = vec![0u8; r.overhead_with_frame() + msg.len()];
        let n = r.send(msg, true, now, rng, &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn recv(r: &mut Ratchet, rng: &mut TestRng, rec: &[u8], now: u64) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; rec.len()];
        let o = r.receive(rec, now, rng, &mut out)?;
        out.truncate(o.len);
        Ok(out)
    }

    /// Alternates bursts of `burst` records each way for `rounds` rounds and
    /// checks every record decrypts.
    fn converse(
        a: &mut Ratchet,
        b: &mut Ratchet,
        rng: &mut TestRng,
        rounds: usize,
        burst: usize,
        now: &mut u64,
    ) {
        for round in 0..rounds {
            for i in 0..burst {
                let m = send(a, rng, &[round as u8, i as u8], *now);
                assert_eq!(recv(b, rng, &m, *now).unwrap(), [round as u8, i as u8]);
                *now += 1;
            }
            for i in 0..burst {
                let m = send(b, rng, &[round as u8, i as u8, 9], *now);
                assert_eq!(recv(a, rng, &m, *now).unwrap(), [round as u8, i as u8, 9]);
                *now += 1;
            }
        }
    }

    fn stored_and_read_again(ratchet: &Ratchet) -> Ratchet {
        let bytes = ratchet.export().unwrap();
        let again = Ratchet::restore(&bytes).unwrap();
        assert_eq!(*again.export().unwrap(), *bytes);
        again
    }

    #[test]
    fn a_stored_ratchet_continues_the_session_across_epochs() {
        let (mut a, mut b, mut rng) = pair(b"stored", Width::W64);
        let mut now = 0u64;
        // Each party stops and starts again between the rounds, in each
        // state of the braid: before an epoch, inside a codeword, and
        // after several mixes.
        for _ in 0..9 {
            converse(&mut a, &mut b, &mut rng, 1, 23, &mut now);
            a = stored_and_read_again(&a);
            b = stored_and_read_again(&b);
        }
        assert!(a.epoch() >= 2, "initiator epoch {}", a.epoch());
        assert!(a.mixed() >= 1);
        assert_eq!(a.mixed(), b.mixed());
    }

    #[test]
    fn a_stored_ratchet_keeps_its_skipped_keys() {
        let (mut a, mut b, mut rng) = pair(b"skipped", Width::W64);
        let late = send(&mut a, &mut rng, b"late", 0);
        let first = send(&mut a, &mut rng, b"first", 1);
        assert_eq!(recv(&mut b, &mut rng, &first, 1).unwrap(), b"first");
        let mut b = stored_and_read_again(&b);
        assert_eq!(recv(&mut b, &mut rng, &late, 2).unwrap(), b"late");
        // The key served one record, in the stored form too.
        let mut b = stored_and_read_again(&b);
        assert!(recv(&mut b, &mut rng, &late, 3).is_err());
    }

    #[test]
    fn a_stored_ratchet_with_a_fault_does_not_restore() {
        let (a, _, _) = pair(b"fault", Width::W64);
        let bytes = a.export().unwrap();
        assert!(Ratchet::restore(&bytes[..bytes.len() - 1]).is_err());
        let mut long = bytes.to_vec();
        long.push(0);
        assert!(Ratchet::restore(&long).is_err());
        let mut version = bytes.to_vec();
        version[0] = 0x02;
        assert!(Ratchet::restore(&version).is_err());
    }

    #[test]
    fn strands_interlock_and_the_root_keys_stay_in_step() {
        let (mut a, mut b, mut rng) = pair(b"braid", Width::W64);
        let mut now = 0u64;
        assert_eq!(a.epoch(), 1);
        assert_eq!(b.epoch(), 0);
        // 41 records each way carry a full codeword; the responder then
        // starts its first epoch at its next chain start.
        converse(&mut a, &mut b, &mut rng, 1, 45, &mut now);
        assert_eq!(a.peer_epoch(), 0);
        assert_eq!(b.peer_epoch(), 1);
        converse(&mut a, &mut b, &mut rng, 1, 1, &mut now);
        assert_eq!(b.epoch(), 1);
        // the initiator rebuilds R.1, completes I.1, and advances at the
        // next chain start once N records passed
        converse(&mut a, &mut b, &mut rng, 3, 45, &mut now);
        assert!(a.epoch() >= 2, "initiator epoch {}", a.epoch());
        assert!(b.epoch() >= 1);
        // many more rounds: the root key mix stays synchronized, thus every
        // record still opens
        converse(&mut a, &mut b, &mut rng, 12, 45, &mut now);
        assert!(a.epoch() >= 4, "initiator epoch {}", a.epoch());
        assert!(b.epoch() >= 3, "responder epoch {}", b.epoch());
    }

    #[test]
    fn loss_inside_the_parity_budget_still_heals() {
        let (mut a, mut b, mut rng) = pair(b"loss", Width::W128);
        let mut now = 0u64;
        let mut counter = 0u32;
        for round in 0..30 {
            for i in 0..12u8 {
                let m = send(&mut a, &mut rng, &[round, i], now);
                counter += 1;
                // drop every 11th record; the code absorbs 3 of 21 per epoch
                if !counter.is_multiple_of(11) {
                    assert_eq!(recv(&mut b, &mut rng, &m, now).unwrap(), [round, i]);
                }
                now += 1;
            }
            for i in 0..12u8 {
                let m = send(&mut b, &mut rng, &[round, i, 9], now);
                counter += 1;
                if !counter.is_multiple_of(11) {
                    assert_eq!(recv(&mut a, &mut rng, &m, now).unwrap(), [round, i, 9]);
                }
                now += 1;
            }
        }
        assert!(a.epoch() >= 3, "initiator epoch {}", a.epoch());
        assert!(b.epoch() >= 2, "responder epoch {}", b.epoch());
    }

    #[test]
    fn a_chain_start_without_a_frame_is_refused() {
        let (mut a, _, mut rng) = pair(b"start", Width::W64);
        let mut out = vec![0u8; 512];
        assert_eq!(
            a.send(b"x", false, 0, &mut rng, &mut out).err(),
            Some(Error::Length)
        );
        assert!(a.send(b"x", true, 0, &mut rng, &mut out).is_ok());
        // inside a chain a record may go without a frame
        assert!(a.send(b"y", false, 0, &mut rng, &mut out).is_ok());
    }

    #[test]
    fn the_time_limit_inside_an_incomplete_epoch_keeps_the_epoch_number() {
        let (mut a, mut b, mut rng) = pair(b"time", Width::W64);
        let mut now = 0u64;
        // a few records, then seven days pass inside epoch 1
        converse(&mut a, &mut b, &mut rng, 2, 3, &mut now);
        now += EPOCH_SECONDS;
        converse(&mut a, &mut b, &mut rng, 2, 3, &mut now);
        assert_eq!(
            a.epoch(),
            1,
            "T occurred, the epoch is incomplete, the number holds"
        );
        assert!(!a.epoch_complete());
    }
}
