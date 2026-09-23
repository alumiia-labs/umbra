//! The circuits that one relay holds (Part 3 §3.4.3, §3.4.4): the answer
//! to a build cell, the move of a cell to the next hop and back, the
//! extension of a circuit by one hop, and the endpoint that hands a
//! recovered body to the services of the relay.
//!
//! The table takes no socket. Each call returns the cells to send and the
//! bodies to serve, and the node moves them.

use std::collections::BTreeMap;

use umbra_crypto::{
    handshake::nk::RelayStatic, rand_core::CryptoRng, secret::Secret, x25519::StaticSecret,
};
use umbra_onion::{
    build::{
        answer, answer_at_queue_relay, build_cell_body, read_cell_body, HopHello, BUILD_BUCKET,
        REPLY_LEN,
    },
    circuit::{Position, RelayHop},
    CIRCUIT_MAX_AGE, CIRCUIT_MAX_CELLS,
};
use umbra_wire::{
    bucket::Bucket,
    cell::{pad_body, unpad_body, Cell, CellCommand},
};

/// A connection of the relay, to a client or to another relay.
pub type LinkId = u64;

/// One circuit on one link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CircuitKey {
    /// The link.
    pub link: LinkId,
    /// The circuit identifier on that link.
    pub circ_id: [u8; 16],
}

/// What the table asks of the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a cell on a link.
    Send {
        /// The link.
        link: LinkId,
        /// The cell bytes.
        cell: Vec<u8>,
    },
    /// Extend the circuit `from` to the relay `relay_id` with this body
    /// (`NET-162`, `NET-163`). The node selects the link and calls
    /// [`CircuitTable::bind_next`].
    Extend {
        /// The held circuit.
        from: CircuitKey,
        /// The relay of the next hop.
        relay_id: [u8; 32],
        /// The body of the `EXTEND` cell, as recovered.
        body: Vec<u8>,
    },
    /// The endpoint recovered the content of a `DATA` cell.
    Serve {
        /// The circuit.
        circuit: CircuitKey,
        /// The bucket of the cell.
        bucket: Bucket,
        /// The commands of the cell.
        content: Vec<u8>,
    },
    /// The endpoint recovered a loop cover cell, which goes back to its
    /// originator on the next pacing tick.
    Loop {
        /// The circuit.
        circuit: CircuitKey,
    },
    /// The circuit ended, and the services drop what they hold for it.
    Closed {
        /// The circuit.
        circuit: CircuitKey,
    },
}

struct Held {
    hop: RelayHop,
    next: Option<CircuitKey>,
    /// The next hop did not answer the `EXTEND` yet.
    extending: bool,
    /// `RelaySession_sk` at a relay of layer 3 (`NET-285`).
    session_secret: Option<StaticSecret>,
    created_at: u64,
    /// The cells toward the queue relay and toward the client, against
    /// `CIRCUIT_MAX_CELLS` (`NET-321`).
    cells: (u32, u32),
}

impl Held {
    /// Counts one cell in one direction, and tells whether the circuit
    /// stays under `CIRCUIT_MAX_CELLS` (`NET-321`).
    fn count(&mut self, is_forward: bool) -> bool {
        let count = if is_forward {
            &mut self.cells.0
        } else {
            &mut self.cells.1
        };
        *count = count.saturating_add(1);
        *count <= CIRCUIT_MAX_CELLS
    }
}

fn cell_bytes(circ_id: &[u8; 16], tag: &[u8; 16], body: &[u8]) -> Vec<u8> {
    [circ_id.as_slice(), tag, body].concat()
}

/// The circuits of one relay.
pub struct CircuitTable {
    relay: RelayStatic,
    static_secret: StaticSecret,
    layer: u8,
    held: BTreeMap<CircuitKey, Held>,
    /// The held circuit behind each circuit that this relay opened to a
    /// next hop.
    back: BTreeMap<CircuitKey, CircuitKey>,
}

impl CircuitTable {
    /// The table of a relay in `layer`, which is 1, 2, or 3.
    pub fn new(relay: RelayStatic, static_secret: StaticSecret, layer: u8) -> Self {
        CircuitTable {
            relay,
            static_secret,
            layer,
            held: BTreeMap::new(),
            back: BTreeMap::new(),
        }
    }

    /// The count of the held circuits.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether the table holds no circuit.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// `RelaySession_sk` of a circuit that ends at this relay.
    pub fn session_secret(&self, circuit: &CircuitKey) -> Option<&StaticSecret> {
        self.held.get(circuit)?.session_secret.as_ref()
    }

    /// Whether a circuit identifier is free on a link (`NET-155`).
    pub fn is_free(&self, key: &CircuitKey) -> bool {
        !self.held.contains_key(key) && !self.back.contains_key(key)
    }

    /// Takes one cell from a link.
    pub fn on_cell<R: CryptoRng + ?Sized>(
        &mut self,
        link: LinkId,
        cell: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Vec<Action> {
        let Ok((parsed, bucket)) = Cell::parse(cell) else {
            return Vec::new();
        };
        let key = CircuitKey {
            link,
            circ_id: *parsed.circ_id,
        };
        let mut body = parsed.body.to_vec();
        if let Some(client_side) = self.back.get(&key).copied() {
            return self.backward(client_side, parsed.tag, body);
        }
        if self.held.contains_key(&key) {
            return self.forward(key, bucket, parsed.tag, &mut body);
        }
        self.build(key, parsed.tag, &body, now, rng)
    }

    /// A cell on a circuit identifier that the relay does not hold is a
    /// build cell (`NET-156` to `NET-161`).
    fn build<R: CryptoRng + ?Sized>(
        &mut self,
        key: CircuitKey,
        tag: &[u8; 16],
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Vec<Action> {
        if *tag != [0u8; 16] {
            return Vec::new();
        }
        let Ok((CellCommand::Extend, hello)) = read_cell_body(body) else {
            return Vec::new();
        };
        let mut reply = [0u8; REPLY_LEN];
        let answered: Result<(Secret<32>, Option<StaticSecret>), _> = if self.layer == 3 {
            answer_at_queue_relay(&self.relay, &self.static_secret, hello, rng, &mut reply)
                .map(|(ss, session)| (ss, Some(session)))
        } else {
            answer(&self.relay, &self.static_secret, hello, rng, &mut reply).map(|ss| (ss, None))
        };
        // NET-153: a hello for another relay gets no answer.
        let Ok((ss_hop, session_secret)) = answered else {
            return Vec::new();
        };
        let position = if self.layer == 3 {
            Position::Endpoint
        } else {
            Position::Middle
        };
        self.held.insert(
            key,
            Held {
                hop: RelayHop::new(&ss_hop, u32::from(self.layer), position),
                next: None,
                extending: false,
                session_secret,
                created_at: now,
                cells: (1, 1),
            },
        );
        let mut out = vec![0u8; BUILD_BUCKET.body_len()];
        if build_cell_body(CellCommand::Extended, &reply, &mut out).is_err() {
            return Vec::new();
        }
        vec![Action::Send {
            link: key.link,
            cell: cell_bytes(&key.circ_id, &[0u8; 16], &out),
        }]
    }

    fn forward(
        &mut self,
        key: CircuitKey,
        bucket: Bucket,
        tag: &[u8; 16],
        body: &mut [u8],
    ) -> Vec<Action> {
        let Some(held) = self.held.get_mut(&key) else {
            return Vec::new();
        };
        if !held.count(true) {
            return self.close(key);
        }
        if let Some(next) = held.next {
            // NET-129: a relay in the middle makes no check.
            return match held.hop.forward(tag, body) {
                Ok(next_tag) => vec![Action::Send {
                    link: next.link,
                    cell: cell_bytes(&next.circ_id, &next_tag, body),
                }],
                Err(_) => self.close(key),
            };
        }
        let recovered = if self.layer == 3 {
            held.hop.forward(tag, body).map(|_| ())
        } else {
            held.hop.forward_build(tag, body)
        };
        // NET-115: a failed check ends the circuit.
        if recovered.is_err() {
            return self.close(key);
        }
        let Ok((command, content)) = unpad_body(body) else {
            return self.close(key);
        };
        match (command, self.layer) {
            (CellCommand::Destroy, _) => self.close(key),
            (CellCommand::Data, 3) => vec![Action::Serve {
                circuit: key,
                bucket,
                content: content.to_vec(),
            }],
            (CellCommand::Loop, 3) => vec![Action::Loop { circuit: key }],
            // NET-166: a relay of layer 3 extends no circuit.
            (CellCommand::Extend, 1 | 2) => match HopHello::parse(content) {
                Ok(hello) => vec![Action::Extend {
                    from: key,
                    relay_id: hello.relay_id,
                    body: body.to_vec(),
                }],
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// Binds a new circuit to the next hop behind a held circuit, and
    /// gives the build cell to send on it (`NET-198`, `NET-163`). The node
    /// drew `next.circ_id` from its CSPRNG (`NET-154`).
    pub fn bind_next(&mut self, from: CircuitKey, next: CircuitKey, body: &[u8]) -> Vec<Action> {
        let free = self.is_free(&next);
        let Some(held) = self.held.get_mut(&from) else {
            return Vec::new();
        };
        // NET-165: a circuit with a next hop extends no more.
        if held.next.is_some() || !free {
            return Vec::new();
        }
        held.next = Some(next);
        held.extending = true;
        self.back.insert(next, from);
        vec![Action::Send {
            link: next.link,
            cell: cell_bytes(&next.circ_id, &[0u8; 16], body),
        }]
    }

    fn backward(
        &mut self,
        client_side: CircuitKey,
        tag: &[u8; 16],
        mut body: Vec<u8>,
    ) -> Vec<Action> {
        let Some(held) = self.held.get_mut(&client_side) else {
            return Vec::new();
        };
        if !held.count(false) {
            return self.close(client_side);
        }
        let layered = if held.extending {
            // NET-164, NET-199: the answer of the next hop is plain, and it
            // goes back under this layer alone.
            if *tag != [0u8; 16] {
                return Vec::new();
            }
            held.extending = false;
            held.hop.backward_build(&mut body)
        } else {
            held.hop.backward(tag, &mut body)
        };
        match layered {
            Ok(out_tag) => vec![Action::Send {
                link: client_side.link,
                cell: cell_bytes(&client_side.circ_id, &out_tag, &body),
            }],
            Err(_) => self.close(client_side),
        }
    }

    /// A cell of this relay to the client of a circuit that ends here.
    pub fn originate(
        &mut self,
        circuit: &CircuitKey,
        bucket: Bucket,
        command: CellCommand,
        content: &[u8],
    ) -> Option<Action> {
        let held = self.held.get_mut(circuit)?;
        // The sweep ends a circuit past its cells, and nothing more leaves
        // on it before that.
        if !held.count(false) {
            return None;
        }
        let mut body = vec![0u8; bucket.body_len()];
        pad_body(bucket, command, content, &mut body).ok()?;
        let tag = held.hop.backward(&[0u8; 16], &mut body).ok()?;
        Some(Action::Send {
            link: circuit.link,
            cell: cell_bytes(&circuit.circ_id, &tag, &body),
        })
    }

    fn close(&mut self, key: CircuitKey) -> Vec<Action> {
        if let Some(held) = self.held.remove(&key) {
            if let Some(next) = held.next {
                self.back.remove(&next);
            }
        }
        vec![Action::Closed { circuit: key }]
    }

    /// A link closed: each circuit on it ends.
    pub fn link_closed(&mut self, link: LinkId) -> Vec<Action> {
        let on_link: Vec<CircuitKey> = self
            .held
            .keys()
            .filter(|key| key.link == link)
            .copied()
            .collect();
        let behind: Vec<CircuitKey> = self
            .back
            .iter()
            .filter(|(next, _)| next.link == link)
            .map(|(_, client_side)| *client_side)
            .collect();
        on_link
            .into_iter()
            .chain(behind)
            .flat_map(|key| self.close(key))
            .collect()
    }

    /// Ends each circuit past `CIRCUIT_MAX_AGE` or past `CIRCUIT_MAX_CELLS`
    /// in one direction (`NET-320`, `NET-321`).
    pub fn expire(&mut self, now: u64) -> Vec<Action> {
        let aged: Vec<CircuitKey> = self
            .held
            .iter()
            .filter(|(_, held)| {
                now.saturating_sub(held.created_at) >= CIRCUIT_MAX_AGE
                    || held.cells.0 > CIRCUIT_MAX_CELLS
                    || held.cells.1 > CIRCUIT_MAX_CELLS
            })
            .map(|(key, _)| *key)
            .collect();
        aged.into_iter().flat_map(|key| self.close(key)).collect()
    }
}
