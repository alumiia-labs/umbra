//! The circuit build of Part 3 §3.4.3: the `HopHello` of an `EXTEND` cell,
//! the `HopReply` of an `EXTENDED` cell, and the `UMBRA-NKhfs` handshake
//! behind them.
//!
//! A build cell to hop `n` travels under the layers of hops 1 to `n − 1`
//! and under no other layer, thus the hello to hop 1 travels with a zero
//! tag and a plaintext body.

use umbra_crypto::{
    handshake::{
        nk::{self, RelayStatic, FLIGHT1_LEN, FLIGHT2_LEN},
        NoTrace,
    },
    rand_core::CryptoRng,
    secret::Secret,
    x25519::StaticSecret,
};
use umbra_wire::{
    bucket::Bucket,
    cell::{pad_body, unpad_body, CellCommand},
    codec::{Reader, Writer},
};

use crate::Error;

/// The length of a `HopHello`.
pub const HELLO_LEN: usize = 32 + FLIGHT1_LEN;
/// The length of a `HopReply`.
pub const REPLY_LEN: usize = FLIGHT2_LEN;
/// The bucket of every build cell (`NET-150`, `NET-151`).
pub const BUILD_BUCKET: Bucket = Bucket::B1;

const _: () = assert!(HELLO_LEN == 1_264);
const _: () = assert!(REPLY_LEN == 1_136);

/// The payload of an `EXTEND` cell.
pub struct HopHello<'a> {
    /// The relay that answers.
    pub relay_id: [u8; 32],
    /// Flight 1 of Part 5 §5.4.9.
    pub flight1: &'a [u8],
}

impl<'a> HopHello<'a> {
    /// Writes the hello.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.flight1.len() != FLIGHT1_LEN {
            return Err(Error::Length);
        }
        let mut w = Writer::new(out);
        w.put(&self.relay_id)?;
        w.put(self.flight1)?;
        Ok(w.position())
    }

    /// Reads a hello.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let relay_id = r.array()?;
        let flight1 = r.take(FLIGHT1_LEN)?;
        r.finish()?;
        Ok(HopHello { relay_id, flight1 })
    }
}

/// Writes the body of a build cell in bucket `B1`: the command byte, the
/// payload, and the padding of Part 6 §6.3.
pub fn build_cell_body(command: CellCommand, payload: &[u8], body: &mut [u8]) -> Result<(), Error> {
    if !matches!(command, CellCommand::Extend | CellCommand::Extended) {
        return Err(Error::Build);
    }
    pad_body(BUILD_BUCKET, command, payload, body)?;
    Ok(())
}

/// Reads the body of a build cell and returns its command and its payload.
/// A build cell whose command is not `EXTEND` or `EXTENDED` is dropped
/// (`NET-157`).
pub fn read_cell_body(body: &[u8]) -> Result<(CellCommand, &[u8]), Error> {
    let (command, payload) = unpad_body(body)?;
    if !matches!(command, CellCommand::Extend | CellCommand::Extended) {
        return Err(Error::Build);
    }
    Ok((command, payload))
}

/// The client between its hello and the reply of one hop.
pub struct Pending(nk::Client);

impl Pending {
    /// Makes the hello to `relay`, written into `out` at `HELLO_LEN` bytes.
    pub fn hello<R: CryptoRng + ?Sized>(
        relay: &RelayStatic,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<Self, Error> {
        let out = out.get_mut(..HELLO_LEN).ok_or(Error::Length)?;
        let (id, flight) = out.split_at_mut(32);
        id.copy_from_slice(&relay.relay_id);
        let client = nk::Client::flight1(relay, rng, flight, &mut NoTrace)?;
        Ok(Pending(client))
    }

    /// Reads the reply and returns `ss_hop`.
    pub fn finish(self, reply: &[u8]) -> Result<Secret<32>, Error> {
        if reply.len() != REPLY_LEN {
            return Err(Error::Length);
        }
        Ok(self.0.read_flight2(reply, &mut NoTrace)?)
    }
}

/// The relay side of one build: reads a hello addressed to this relay
/// (`NET-153`), writes the reply into `out` at `REPLY_LEN` bytes, and
/// returns `ss_hop`.
pub fn answer<R: CryptoRng + ?Sized>(
    relay: &RelayStatic,
    static_secret: &StaticSecret,
    hello: &[u8],
    rng: &mut R,
    out: &mut [u8],
) -> Result<Secret<32>, Error> {
    let hello = HopHello::parse(hello)?;
    if hello.relay_id != relay.relay_id {
        return Err(Error::Build);
    }
    let responder = nk::Relay::read_flight1(relay, static_secret, hello.flight1, &mut NoTrace)?;
    let out = out.get_mut(..REPLY_LEN).ok_or(Error::Length)?;
    Ok(responder.flight2(rng, out, &mut NoTrace)?)
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
    use umbra_crypto::x25519::PublicKey as XPublic;

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
            for (i, b) in dst.iter_mut().enumerate() {
                *b = self.0.wrapping_add(i as u8);
            }
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    #[test]
    fn one_hop_builds_and_both_ends_hold_one_secret() {
        let s_sk = StaticSecret::from([5u8; 32]);
        let relay = RelayStatic {
            s: *XPublic::from(&s_sk).as_bytes(),
            relay_id: [6; 32],
        };
        let mut hello = [0u8; HELLO_LEN];
        let pending = Pending::hello(&relay, &mut Rng(1), &mut hello).unwrap();
        let mut body = [0u8; BUILD_BUCKET.body_len()];
        build_cell_body(CellCommand::Extend, &hello, &mut body).unwrap();
        let (cmd, payload) = read_cell_body(&body).unwrap();
        assert_eq!(cmd, CellCommand::Extend);
        let mut reply = [0u8; REPLY_LEN];
        let at_relay = answer(&relay, &s_sk, payload, &mut Rng(2), &mut reply).unwrap();
        let at_client = pending.finish(&reply).unwrap();
        assert_eq!(at_relay.expose(), at_client.expose());

        // NET-153: a hello for another relay is dropped.
        let other = RelayStatic {
            relay_id: [7; 32],
            ..relay
        };
        assert!(answer(&other, &s_sk, &hello, &mut Rng(3), &mut reply).is_err());
        // NET-157: a DATA cell is not a build cell.
        assert!(build_cell_body(CellCommand::Data, &hello, &mut body).is_err());
        pad_body(BUILD_BUCKET, CellCommand::Data, &hello, &mut body).unwrap();
        assert!(read_cell_body(&body).is_err());
    }
}
