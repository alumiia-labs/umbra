//! Contact setup over two queues (Part 3 §3.2.6, Part 5 §5.4): the bundle
//! that an inviter gives out of band, and the three flights of the
//! pairwise handshake. Each flight travels as an L6 record of kind
//! `0x05`: one byte with the flight number, and then the flight.
//!
//! The inviter is the responder of the handshake. Flight 1 arrives on the
//! queue of the bundle and names the first queue of the invitee in `app_1`
//! (`NET-173`). Flight 2 goes to that queue (`NET-174`), and the inviter
//! takes it as the outbound queue of the contact after flight 3 verifies
//! (`NET-175`).

use alloc::vec::Vec;

use umbra_crypto::{
    handshake::{
        find_prekey,
        xk::{
            Initiator, Invitation, OneTimePrekey, Responder, SessionKeys, EK_LEN, FLIGHT1_FIXED,
            FLIGHT2_FIXED, FLIGHT3_FIXED, NONCE_LEN, PAYLOAD_OVERHEAD,
        },
        AddressType, NoTrace, VersionRange,
    },
    kem::KeyPair,
    rand_core::CryptoRng,
};
use umbra_wire::address::{QueueAddress, LEN as QUEUE_ADDRESS_LEN};

use crate::{identity::invitation::Bundle, Error};

/// The one protocol version of this revision.
pub const VERSION_RANGE: VersionRange = VersionRange { min: 1, max: 1 };

/// The number of flight 1 in a handshake record (`WIR-502`).
pub const FLIGHT_1: u8 = 1;
/// The number of flight 2.
pub const FLIGHT_2: u8 = 2;
/// The number of flight 3.
pub const FLIGHT_3: u8 = 3;

fn numbered(number: u8, flight: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(flight.len().saturating_add(1));
    inner.push(number);
    inner.extend_from_slice(flight);
    inner
}

fn flight_of(inner: &[u8], number: u8) -> Result<&[u8], Error> {
    match inner.split_first() {
        Some((first, flight)) if *first == number => Ok(flight),
        _ => Err(Error::Malformed),
    }
}

/// The inviter between the issue of a bundle and flight 3.
pub struct Inviter {
    prekey: Option<OneTimePrekey>,
    responder: Option<Responder>,
    reply_to: Option<QueueAddress>,
}

impl Inviter {
    /// Issues one invitation for the pairwise identity `identity`, and
    /// returns the encoded bundle. `first_queue` is a queue that the
    /// inviter made with a `NEW` before this call (`NET-170`, `NET-172`).
    pub fn issue<R: CryptoRng + ?Sized>(
        identity: &KeyPair,
        first_queue: QueueAddress,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>), Error> {
        let prekey = OneTimePrekey::generate(rng);
        let bundle = Bundle {
            responder_static_x25519: identity.x25519_public(),
            responder_kem_ek: prekey.encapsulation_key(),
            version_range: [VERSION_RANGE.min, VERSION_RANGE.max],
            queue_address: first_queue,
            relay_bundle: &[],
        };
        let mut encoded = alloc::vec![0u8; bundle.len()];
        let used = bundle.encode(&mut encoded)?;
        encoded.truncate(used);
        Ok((
            Inviter {
                prekey: Some(prekey),
                responder: None,
                reply_to: None,
            },
            encoded,
        ))
    }

    /// The number of the flight that this inviter waits for (`WIR-503`).
    pub fn awaits(&self) -> u8 {
        if self.prekey.is_some() {
            FLIGHT_1
        } else {
            FLIGHT_3
        }
    }

    /// Reads flight 1 and writes flight 2. The result is the inner record
    /// of flight 2 and the queue that it goes to. The prekey serves one
    /// flight 1, thus a second one fails.
    pub fn on_flight1<R: CryptoRng + ?Sized>(
        &mut self,
        identity: &KeyPair,
        inner: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, &QueueAddress), Error> {
        let flight = flight_of(inner, FLIGHT_1)?;
        let (_, _, pid) = Responder::peek(flight)?;
        // The lookup runs in constant time over the one prekey of the
        // invitation, as it does over a list. A flight that names a second
        // prekey spends nothing.
        let held = self.prekey.as_ref().ok_or(Error::Stale)?;
        find_prekey(&pid, core::iter::once(held.id())).ok_or(Error::Unverified)?;
        let prekey = self.prekey.take().ok_or(Error::Stale)?;
        let mut app_1 = [0u8; QUEUE_ADDRESS_LEN];
        let (mut responder, read) = Responder::read_flight1(
            identity,
            prekey,
            VERSION_RANGE,
            AddressType::Pairwise,
            flight,
            &mut app_1,
            &mut NoTrace,
        )?;
        if read.app_len != QUEUE_ADDRESS_LEN {
            return Err(Error::Malformed);
        }
        let reply_to = QueueAddress::parse(&app_1)?;
        let mut flight2 = alloc::vec![0u8; FLIGHT2_FIXED + NONCE_LEN + PAYLOAD_OVERHEAD];
        let used = responder.flight2(&[], rng, &mut flight2, &mut NoTrace)?;
        flight2.truncate(used);
        self.responder = Some(responder);
        Ok((numbered(FLIGHT_2, &flight2), self.reply_to.insert(reply_to)))
    }

    /// Reads flight 3. The result is the keys of the session, the static
    /// key of the invitee, and the queue of the invitee, which is the
    /// outbound queue of the contact from now on.
    pub fn on_flight3(
        mut self,
        inner: &[u8],
    ) -> Result<(SessionKeys, [u8; 32], QueueAddress), Error> {
        let flight = flight_of(inner, FLIGHT_3)?;
        let responder = self.responder.take().ok_or(Error::Stale)?;
        let reply_to = self.reply_to.take().ok_or(Error::Stale)?;
        let (keys, initiator_static, _) = responder.read_flight3(flight, &mut [], &mut NoTrace)?;
        Ok((keys, initiator_static, reply_to))
    }
}

/// The invitee between flight 1 and flight 3.
pub struct Invitee {
    initiator: Initiator,
}

impl Invitee {
    /// Checks a bundle before the client makes a queue for it. A value of
    /// the user that does not parse thus fails at the call, and not later
    /// on the network path.
    pub fn check(bundle: &[u8]) -> Result<(), Error> {
        let bundle = Bundle::parse(bundle)?;
        if bundle.responder_kem_ek.len() != EK_LEN {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Reads a bundle and writes flight 1, with the first queue of the
    /// invitee in `app_1`. The result holds the inner record of flight 1
    /// and the queue of the inviter that it goes to.
    pub fn accept<R: CryptoRng + ?Sized>(
        bundle: &[u8],
        own_queue: &QueueAddress,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>, QueueAddress), Error> {
        let bundle = Bundle::parse(bundle)?;
        let s1: &[u8; EK_LEN] = bundle
            .responder_kem_ek
            .try_into()
            .map_err(|_| Error::Malformed)?;
        let [min, max] = bundle.version_range;
        let invitation = Invitation {
            s: bundle.responder_static_x25519,
            s1,
            range_r: VersionRange { min, max },
        };
        let mut app_1 = [0u8; QUEUE_ADDRESS_LEN];
        own_queue.encode(&mut app_1)?;
        let mut flight1 =
            alloc::vec![0u8; FLIGHT1_FIXED + NONCE_LEN + QUEUE_ADDRESS_LEN + PAYLOAD_OVERHEAD];
        let (initiator, used) = Initiator::flight1(
            &invitation,
            VERSION_RANGE,
            AddressType::Pairwise,
            &app_1,
            rng,
            &mut flight1,
            &mut NoTrace,
        )?;
        flight1.truncate(used);
        Ok((
            Invitee { initiator },
            numbered(FLIGHT_1, &flight1),
            bundle.queue_address,
        ))
    }

    /// Reads flight 2 and writes flight 3 under the pairwise identity of
    /// the invitee. The result is the keys of the session and the inner
    /// record of flight 3.
    pub fn on_flight2(
        mut self,
        identity: &KeyPair,
        inner: &[u8],
    ) -> Result<(SessionKeys, Vec<u8>), Error> {
        let flight = flight_of(inner, FLIGHT_2)?;
        self.initiator.read_flight2(flight, &mut [], &mut NoTrace)?;
        let er = Responder::er_of(flight)?;
        let mut flight3 = alloc::vec![0u8; FLIGHT3_FIXED + PAYLOAD_OVERHEAD];
        let (keys, used) =
            self.initiator
                .flight3(identity, &er, &[], &mut flight3, &mut NoTrace)?;
        flight3.truncate(used);
        Ok((keys, numbered(FLIGHT_3, &flight3)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use umbra_crypto::{hierarchy::RootIdentity, secret::Secret};

    use super::*;
    use crate::abuse::test_rng::Rng;

    fn queue(tag: u8) -> QueueAddress {
        QueueAddress {
            relay_id: [tag; 32],
            sender_id: [tag ^ 0x55; 32],
            qs_auth_sk: Secret::new([tag ^ 0x0F; 32]),
            qe: Secret::new([tag ^ 0xF0; 32]),
        }
    }

    #[test]
    fn three_flights_give_both_parties_one_session() {
        let mut rng = Rng(1);
        let inviter_identity = RootIdentity::new(Secret::new([1; 32])).pairwise_identity(&[1; 16]);
        let invitee_identity = RootIdentity::new(Secret::new([2; 32])).pairwise_identity(&[2; 16]);

        let (mut inviter, bundle) = Inviter::issue(&inviter_identity, queue(10), &mut rng).unwrap();
        let (invitee, flight1, to) = Invitee::accept(&bundle, &queue(20), &mut rng).unwrap();
        assert_eq!(to.sender_id, queue(10).sender_id);
        assert!(flight1.len() > 2_000, "flight 1 needs bucket B2");

        let (flight2, reply_to) = inviter
            .on_flight1(&inviter_identity, &flight1, &mut rng)
            .unwrap();
        assert_eq!(reply_to.sender_id, queue(20).sender_id);
        // The prekey serves one flight 1.
        assert!(inviter
            .on_flight1(&inviter_identity, &flight1, &mut rng)
            .is_err());

        let (invitee_keys, flight3) = invitee.on_flight2(&invitee_identity, &flight2).unwrap();
        let (inviter_keys, initiator_static, outbound) = inviter.on_flight3(&flight3).unwrap();
        assert_eq!(invitee_keys.rk.expose(), inviter_keys.rk.expose());
        assert_eq!(invitee_keys.transcript, inviter_keys.transcript);
        assert_eq!(initiator_static, invitee_identity.x25519_public());
        assert_eq!(outbound.sender_id, queue(20).sender_id);
    }

    #[test]
    fn a_flight_under_another_number_is_rejected() {
        let mut rng = Rng(1);
        let identity = RootIdentity::new(Secret::new([1; 32])).pairwise_identity(&[1; 16]);
        let (mut inviter, bundle) = Inviter::issue(&identity, queue(10), &mut rng).unwrap();
        let (_, mut flight1, _) = Invitee::accept(&bundle, &queue(20), &mut rng).unwrap();
        flight1[0] = 3;
        assert!(inviter.on_flight1(&identity, &flight1, &mut rng).is_err());
    }
}
