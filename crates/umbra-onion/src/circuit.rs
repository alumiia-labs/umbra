//! The client circuit and the relay hop of Part 3 §3.4.4: the nesting of
//! the three layers, the check at the endpoint, and the key update at the
//! hop 3 layer.

use subtle::ConstantTimeEq;
use umbra_crypto::secret::Secret;

use crate::{
    layer::{HopKeys, KeySet, BLOCK},
    Error, HOPS,
};

/// The client end of one circuit: three key sets and the circuit identifier
/// of the first link.
pub struct Circuit {
    hops: [KeySet; HOPS],
    circ_id: [u8; 16],
    sent: u32,
    received: u32,
}

impl Circuit {
    /// Builds the circuit state from the three hop secrets, hop 1 first.
    pub fn new(hop_secrets: &[Secret<32>; HOPS], circ_id: [u8; 16]) -> Self {
        Circuit {
            hops: [
                KeySet::derive(&hop_secrets[0], 1),
                KeySet::derive(&hop_secrets[1], 2),
                KeySet::derive(&hop_secrets[2], 3),
            ],
            circ_id,
            sent: 0,
            received: 0,
        }
    }

    /// The circuit identifier on the link to hop 1.
    pub fn circ_id(&self) -> [u8; 16] {
        self.circ_id
    }

    /// The cells sent and received so far, against `CIRCUIT_MAX_CELLS`.
    pub fn cells(&self) -> (u32, u32) {
        (self.sent, self.received)
    }

    /// The forward key set of one hop, for a conformance check.
    pub fn forward_keys(&self, hop: usize) -> Option<&HopKeys> {
        self.hops.get(hop.checked_sub(1)?).map(|k| &k.forward)
    }

    /// The backward key set of one hop, for a conformance check.
    pub fn backward_keys(&self, hop: usize) -> Option<&HopKeys> {
        self.hops.get(hop.checked_sub(1)?).map(|k| &k.backward)
    }

    /// Wraps a body for the queue relay: the innermost left block is zero,
    /// and the layers of hops 3, 2, and 1 follow in that order (`NET-124`
    /// to `NET-126`). Returns the `tag` field; `body` holds `Y_R`.
    pub fn seal(&mut self, body: &mut [u8]) -> Result<[u8; BLOCK], Error> {
        let mut left = [0u8; BLOCK];
        for (index, hop) in self.hops.iter_mut().enumerate().rev() {
            left = hop.forward.encipher(&left, body)?;
            if index == HOPS - 1 {
                hop.forward.update(&left);
            }
        }
        self.sent = self.sent.saturating_add(1);
        Ok(left)
    }

    /// Removes the three backward layers and makes the check of `NET-114`.
    /// The body holds the payload on success and nothing usable on failure
    /// (`NET-130`).
    pub fn open(&mut self, tag: &[u8; BLOCK], body: &mut [u8]) -> Result<(), Error> {
        let mut left = *tag;
        let mut hop3_input = [0u8; BLOCK];
        for (index, hop) in self.hops.iter_mut().enumerate() {
            if index == HOPS - 1 {
                hop3_input = left;
            }
            left = hop.backward.decipher(&left, body)?;
        }
        if !bool::from(left.ct_eq(&[0u8; BLOCK])) {
            return Err(Error::Rejected);
        }
        if let Some(last) = self.hops.last_mut() {
            last.backward.update(&hop3_input);
        }
        self.received = self.received.saturating_add(1);
        Ok(())
    }
}

/// The client end of a circuit under build (Part 3 §3.4.3): the key sets
/// of the hops that answered so far. A build cell to hop *n* travels under
/// the layers of hops 1 to *n* − 1, and the chaining values that those
/// cells move stay in the finished circuit.
pub struct CircuitBuild {
    hops: [Option<KeySet>; HOPS],
    circ_id: [u8; 16],
}

impl CircuitBuild {
    /// A build with no hop, on a `circ_id` from the CSPRNG (`NET-154`).
    pub fn new(circ_id: [u8; 16]) -> Self {
        CircuitBuild {
            hops: [None, None, None],
            circ_id,
        }
    }

    /// The circuit identifier on the link to hop 1.
    pub fn circ_id(&self) -> [u8; 16] {
        self.circ_id
    }

    /// The count of the hops that answered.
    pub fn built(&self) -> usize {
        self.hops.iter().flatten().count()
    }

    /// Wraps the body of an `EXTEND` cell for the next hop, and returns the
    /// `tag`. With no hop built, the body stays plain and the tag is zero.
    /// No layer runs the key update, because no layer is the hop 3 layer
    /// of a finished circuit yet.
    pub fn seal(&mut self, body: &mut [u8]) -> Result<[u8; BLOCK], Error> {
        let mut left = [0u8; BLOCK];
        for hop in self.hops.iter_mut().rev().flatten() {
            left = hop.forward.encipher(&left, body)?;
        }
        Ok(left)
    }

    /// Removes the backward layers of an `EXTENDED` cell and makes the
    /// check of `NET-114`.
    pub fn open(&mut self, tag: &[u8; BLOCK], body: &mut [u8]) -> Result<(), Error> {
        let mut left = *tag;
        for hop in self.hops.iter_mut().flatten() {
            left = hop.backward.decipher(&left, body)?;
        }
        if bool::from(left.ct_eq(&[0u8; BLOCK])) {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    }

    /// Adds the hop that answered, from its `ss_hop`.
    pub fn push(&mut self, ss_hop: &Secret<32>) -> Result<(), Error> {
        let built = self.built();
        let index = u32::try_from(built.saturating_add(1)).map_err(|_| Error::Build)?;
        let slot = self.hops.get_mut(built).ok_or(Error::Build)?;
        *slot = Some(KeySet::derive(ss_hop, index));
        Ok(())
    }

    /// The finished circuit, after the third hop answered.
    pub fn finish(self) -> Result<Circuit, Error> {
        let [Some(first), Some(second), Some(third)] = self.hops else {
            return Err(Error::Build);
        };
        Ok(Circuit {
            hops: [first, second, third],
            circ_id: self.circ_id,
            sent: 0,
            received: 0,
        })
    }
}

/// The position of a relay on a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// Hop 1 or hop 2: removes one layer and forwards.
    Middle,
    /// Hop 3: removes the last layer and checks the left block.
    Endpoint,
}

/// A relay's end of one circuit.
pub struct RelayHop {
    keys: KeySet,
    position: Position,
}

impl RelayHop {
    /// Builds the hop state from `ss_hop` at `hop_index` (1 to 3).
    pub fn new(ss_hop: &Secret<32>, hop_index: u32, position: Position) -> Self {
        RelayHop {
            keys: KeySet::derive(ss_hop, hop_index),
            position,
        }
    }

    /// The position.
    pub fn position(&self) -> Position {
        self.position
    }

    /// The forward key set, for a conformance check.
    pub fn forward_keys(&self) -> &HopKeys {
        &self.keys.forward
    }

    /// Removes this hop's forward layer (`NET-127`, `NET-128`). A middle
    /// hop returns the tag for the next hop. The endpoint checks the left
    /// block (`NET-114`), updates its key set (`NET-205`), and returns the
    /// zero block.
    pub fn forward(&mut self, tag: &[u8; BLOCK], body: &mut [u8]) -> Result<[u8; BLOCK], Error> {
        let x_l = self.keys.forward.decipher(tag, body)?;
        match self.position {
            Position::Middle => Ok(x_l),
            Position::Endpoint => {
                if !bool::from(x_l.ct_eq(&[0u8; BLOCK])) {
                    return Err(Error::Rejected);
                }
                self.keys.forward.update(tag);
                Ok([0u8; BLOCK])
            }
        }
    }

    /// Removes the forward layer of a cell at a relay of layer 1 or 2
    /// whose circuit holds no next hop yet. That relay is the endpoint of
    /// the cell, thus it makes the check of `NET-114`. It runs no key
    /// update, because that update belongs to the hop 3 layer.
    pub fn forward_build(&mut self, tag: &[u8; BLOCK], body: &mut [u8]) -> Result<(), Error> {
        let x_l = self.keys.forward.decipher(tag, body)?;
        if bool::from(x_l.ct_eq(&[0u8; BLOCK])) {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    }

    /// Adds the backward layer over the body of an `EXTENDED` cell, with
    /// `X_L` of 16 zero bytes and no key update (`NET-199`).
    pub fn backward_build(&mut self, body: &mut [u8]) -> Result<[u8; BLOCK], Error> {
        self.keys.backward.encipher(&[0u8; BLOCK], body)
    }

    /// Adds this hop's backward layer. The endpoint starts from the zero
    /// block and updates its key set after the step (`NET-206`); a middle
    /// hop takes the tag that arrived from the hop after it.
    pub fn backward(
        &mut self,
        tag_in: &[u8; BLOCK],
        body: &mut [u8],
    ) -> Result<[u8; BLOCK], Error> {
        match self.position {
            Position::Middle => self.keys.backward.encipher(tag_in, body),
            Position::Endpoint => {
                let y_l = self.keys.backward.encipher(&[0u8; BLOCK], body)?;
                self.keys.backward.update(&y_l);
                Ok(y_l)
            }
        }
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

    fn secrets() -> [Secret<32>; HOPS] {
        [
            Secret::new([1; 32]),
            Secret::new([2; 32]),
            Secret::new([3; 32]),
        ]
    }

    fn relays() -> [RelayHop; HOPS] {
        let s = secrets();
        [
            RelayHop::new(&s[0], 1, Position::Middle),
            RelayHop::new(&s[1], 2, Position::Middle),
            RelayHop::new(&s[2], 3, Position::Endpoint),
        ]
    }

    #[test]
    fn a_cell_crosses_three_hops_in_both_directions() {
        let mut client = Circuit::new(&secrets(), [9; 16]);
        let mut relays = relays();
        for round in 0..3u8 {
            let mut body = [round; 2_016];
            let mut tag = client.seal(&mut body).unwrap();
            for hop in relays.iter_mut() {
                tag = hop.forward(&tag, &mut body).unwrap();
            }
            assert_eq!(body, [round; 2_016]);
            assert_eq!(tag, [0; 16]);

            let mut reply = [0x50 + round; 2_016];
            let mut tag = [0u8; 16];
            for hop in relays.iter_mut().rev() {
                tag = hop.backward(&tag, &mut reply).unwrap();
            }
            client.open(&tag, &mut reply).unwrap();
            assert_eq!(reply, [0x50 + round; 2_016]);
        }
        assert_eq!(client.cells(), (3, 3));
    }

    #[test]
    fn a_change_at_hop_2_dies_at_the_endpoint_and_a_replay_dies_too() {
        let mut client = Circuit::new(&secrets(), [9; 16]);
        let mut chain = relays();
        let mut body = [1u8; 480];
        let tag = client.seal(&mut body).unwrap();
        let saved = (tag, body);
        let tag = chain[0].forward(&tag, &mut body).unwrap();
        body[7] ^= 1;
        let tag = chain[1].forward(&tag, &mut body).unwrap();
        assert_eq!(chain[2].forward(&tag, &mut body), Err(Error::Rejected));

        // A fresh set of relays takes the same cell twice.
        let mut chain = relays();
        let (mut tag, mut body) = saved;
        for hop in chain.iter_mut() {
            tag = hop.forward(&tag, &mut body).unwrap();
        }
        let (mut tag, mut body) = saved;
        let mut failed = false;
        for hop in chain.iter_mut() {
            match hop.forward(&tag, &mut body) {
                Ok(t) => tag = t,
                Err(Error::Rejected) => failed = true,
                Err(e) => panic!("{e}"),
            }
        }
        assert!(failed);
    }

    #[test]
    fn the_endpoint_key_set_moves_at_each_cell_and_the_middle_ones_stay() {
        let mut client = Circuit::new(&secrets(), [9; 16]);
        let before = [
            client.forward_keys(1).unwrap().fingerprint(),
            client.forward_keys(2).unwrap().fingerprint(),
            client.forward_keys(3).unwrap().fingerprint(),
        ];
        let mut body = [0u8; 480];
        client.seal(&mut body).unwrap();
        // Hops 1 and 2 move their chaining value only; hop 3 replaces keys.
        assert_ne!(client.forward_keys(1).unwrap().fingerprint(), before[0]);
        assert_ne!(client.forward_keys(3).unwrap().fingerprint(), before[2]);
        // The relay reaches the same key set after the same cell.
        let mut cell = [0u8; 480];
        let mut c = Circuit::new(&secrets(), [9; 16]);
        let tag = c.seal(&mut cell).unwrap();
        let mut r = relays();
        let tag = r[0].forward(&tag, &mut cell).unwrap();
        let tag = r[1].forward(&tag, &mut cell).unwrap();
        r[2].forward(&tag, &mut cell).unwrap();
        assert_eq!(
            r[2].forward_keys().fingerprint(),
            c.forward_keys(3).unwrap().fingerprint()
        );
    }
}
