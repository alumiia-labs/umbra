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

/// `LINK_CIRCUITS_MAX`: the circuits that one client link holds at an
/// ingress relay (Part 3 `NET-331`).
pub const LINK_CIRCUITS_MAX: u32 = 256;
/// `LINK_BUILD_BURST`: the builds that one client link may send at once
/// (`NET-332`).
pub const LINK_BUILD_BURST: u32 = 64;
/// `LINK_BUILD_RATE`: the builds that one client link gets back each
/// second after its burst (`NET-332`).
pub const LINK_BUILD_RATE: u32 = 1;

/// What one client link spent of its circuits and its builds.
#[derive(Debug, Clone, Copy)]
struct LinkBudget {
    circuits: u32,
    builds: u32,
    refilled_at: u64,
}

impl LinkBudget {
    const fn new(now: u64) -> Self {
        LinkBudget {
            circuits: 0,
            builds: LINK_BUILD_BURST,
            refilled_at: now,
        }
    }

    /// Takes one build at `now`, or refuses it.
    fn take(&mut self, now: u64) -> bool {
        let seconds = now.saturating_sub(self.refilled_at);
        let refill = u32::try_from(seconds)
            .unwrap_or(u32::MAX)
            .saturating_mul(LINK_BUILD_RATE);
        self.builds = self.builds.saturating_add(refill).min(LINK_BUILD_BURST);
        self.refilled_at = now;
        if self.circuits >= LINK_CIRCUITS_MAX || self.builds == 0 {
            return false;
        }
        self.builds -= 1;
        self.circuits += 1;
        true
    }
}

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
    /// Tell the neighbor on `link` that the circuit of `circ_id` ended
    /// (`NET-322`).
    Destroy {
        /// The link to the neighbor.
        link: LinkId,
        /// The circuit on that link.
        circ_id: [u8; 16],
    },
    /// The end of a circuit that waited for its delayed cells: the node
    /// hands it to [`CircuitTable::end_now`] (`NET-339`).
    End {
        /// The circuit.
        key: CircuitKey,
        /// The link that told this relay of the end, which gets no
        /// `Destroy`.
        from: Option<LinkId>,
    },
    /// An action of a forward cell that waits for the per-hop delay of its
    /// circuit (Part 3 §3.9). The time never goes below the one of an
    /// earlier cell of the circuit, thus the delay keeps the order.
    Delayed {
        /// The release time, in milliseconds of the node clock.
        at_ms: u64,
        /// The circuit of the cell, which the node names to
        /// [`CircuitTable::released`] at the release.
        circuit: CircuitKey,
        /// The action.
        action: Box<Action>,
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
    /// The mean of the per-hop delay of the mode of the circuit (§3.9).
    delay_mean_ms: u64,
    /// The release time of the last delayed cell of the circuit.
    released_at_ms: u64,
    /// The end of the circuit waits for its delayed cells.
    ending: bool,
    /// The delayed actions of the circuit that the node holds.
    delayed_out: u32,
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
    /// The budget of each client link at an ingress relay (`NET-331`,
    /// `NET-332`). A link of a relay of another layer carries the circuits
    /// of many clients, thus it has none.
    budgets: BTreeMap<LinkId, LinkBudget>,
    /// The chains that this relay opened as one hop since the last take
    /// (`REL-189`).
    builds: u64,
    /// The clock of the per-hop delay, in milliseconds.
    clock_ms: u64,
}

impl CircuitTable {
    /// The chains that this relay opened since the last call.
    pub fn take_builds(&mut self) -> u64 {
        core::mem::take(&mut self.builds)
    }

    /// The table of a relay in `layer`, which is 1, 2, or 3.
    pub fn new(relay: RelayStatic, static_secret: StaticSecret, layer: u8) -> Self {
        CircuitTable {
            relay,
            static_secret,
            layer,
            held: BTreeMap::new(),
            back: BTreeMap::new(),
            budgets: BTreeMap::new(),
            builds: 0,
            clock_ms: 0,
        }
    }

    /// Sets the clock of the per-hop delay before a call.
    pub fn set_clock_ms(&mut self, now_ms: u64) {
        self.clock_ms = now_ms;
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
            let actions = self.forward(key, bucket, parsed.tag, &mut body);
            return self.delay(key, actions, rng);
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
        // NET-331, NET-332: a client link above its circuits or its rate of
        // builds gets no answer, before the handshake costs this relay a
        // key agreement.
        if self.layer == 1 {
            let budget = self
                .budgets
                .entry(key.link)
                .or_insert_with(|| LinkBudget::new(now));
            if !budget.take(now) {
                return Vec::new();
            }
        }
        let mut reply = [0u8; REPLY_LEN];
        let answered: Result<(Secret<32>, Option<StaticSecret>), _> = if self.layer == 3 {
            answer_at_queue_relay(&self.relay, &self.static_secret, hello, rng, &mut reply)
                .map(|(ss, session)| (ss, Some(session)))
        } else {
            answer(&self.relay, &self.static_secret, hello, rng, &mut reply).map(|ss| (ss, None))
        };
        // NET-153: a hello for another relay gets no answer.
        let Ok((ss_hop, session_secret)) = answered else {
            self.release(key.link);
            return Vec::new();
        };
        let position = if self.layer == 3 {
            Position::Endpoint
        } else {
            Position::Middle
        };
        // NET-337: a hello with no known mode failed its parse above.
        let delay_mean_ms = HopHello::parse(hello).map_or(0, |held| held.delay_class.mean_ms());
        self.held.insert(
            key,
            Held {
                hop: RelayHop::new(&ss_hop, u32::from(self.layer), position),
                next: None,
                extending: false,
                session_secret,
                created_at: now,
                cells: (1, 1),
                delay_mean_ms,
                released_at_ms: 0,
                ending: false,
                delayed_out: 0,
            },
        );
        self.builds = self.builds.saturating_add(1);
        let mut out = vec![0u8; BUILD_BUCKET.body_len()];
        if build_cell_body(CellCommand::Extended, &reply, &mut out).is_err() {
            return Vec::new();
        }
        vec![Action::Send {
            link: key.link,
            cell: cell_bytes(&key.circ_id, &[0u8; 16], &out),
        }]
    }

    /// Holds the actions of a forward cell for the per-hop delay of its
    /// circuit: an exponential draw with the mean of its mode (`NET-338`),
    /// at or after the release of the cell before it (`NET-339`). A build
    /// cell and an end of the circuit go at once.
    fn delay<R: CryptoRng + ?Sized>(
        &mut self,
        key: CircuitKey,
        actions: Vec<Action>,
        rng: &mut R,
    ) -> Vec<Action> {
        let now_ms = self.clock_ms;
        let Some(held) = self.held.get_mut(&key) else {
            return actions;
        };
        if held.delay_mean_ms == 0 {
            return actions;
        }
        actions
            .into_iter()
            .map(|action| match action {
                Action::Send { .. } | Action::Serve { .. } | Action::Loop { .. } => {
                    let draw = rng.next_u32();
                    let wait = umbra_core::group::backoff::exponential(held.delay_mean_ms, draw);
                    let at_ms = now_ms.saturating_add(wait).max(held.released_at_ms);
                    held.released_at_ms = at_ms;
                    held.delayed_out = held.delayed_out.saturating_add(1);
                    Action::Delayed {
                        at_ms,
                        circuit: key,
                        action: Box::new(action),
                    }
                }
                other => other,
            })
            .collect()
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
            // NET-169: the client ended its build here, and the relays
            // after this one learn it by the link (`NET-322`).
            (CellCommand::Destroy, _) => self.end(key, Some(key.link)),
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
        self.end(key, None)
    }

    /// Ends a circuit, and tells each neighbor on a link other than
    /// `from` with a `Destroy` (`NET-322`). The client side of a circuit
    /// is its key, and the next hop is `next`.
    fn end(&mut self, key: CircuitKey, from: Option<LinkId>) -> Vec<Action> {
        // NET-339: a forward cell that waits for its delay goes before the
        // end of its circuit, and the endpoint serves it under the key of
        // the circuit. The end waits until the last one left.
        if let Some(held) = self.held.get_mut(&key) {
            if held.ending {
                return Vec::new();
            }
            if held.delayed_out > 0 {
                held.ending = true;
                return vec![Action::Delayed {
                    at_ms: held.released_at_ms,
                    circuit: key,
                    action: Box::new(Action::End { key, from }),
                }];
            }
        }
        self.end_now(key, from)
    }

    /// The node ran a delayed action of `circuit`.
    pub fn released(&mut self, circuit: &CircuitKey) {
        if let Some(held) = self.held.get_mut(circuit) {
            held.delayed_out = held.delayed_out.saturating_sub(1);
        }
    }

    /// Ends a circuit at once: the node runs it for an [`Action::End`].
    pub fn end_now(&mut self, key: CircuitKey, from: Option<LinkId>) -> Vec<Action> {
        let Some(held) = self.held.remove(&key) else {
            return Vec::new();
        };
        self.release(key.link);
        let mut actions = Vec::new();
        if let Some(next) = held.next {
            self.back.remove(&next);
            if Some(next.link) != from {
                actions.push(Action::Destroy {
                    link: next.link,
                    circ_id: next.circ_id,
                });
            }
        }
        if Some(key.link) != from {
            actions.push(Action::Destroy {
                link: key.link,
                circ_id: key.circ_id,
            });
        }
        actions.push(Action::Closed { circuit: key });
        actions
    }

    /// A neighbor ended the circuit of `circ_id` on `link`: this relay ends
    /// its part and tells the other neighbor (`NET-322`).
    pub fn on_destroy(&mut self, link: LinkId, circ_id: [u8; 16]) -> Vec<Action> {
        let key = CircuitKey { link, circ_id };
        if self.held.contains_key(&key) {
            return self.end(key, Some(link));
        }
        match self.back.get(&key).copied() {
            Some(client_side) => self.end(client_side, Some(link)),
            None => Vec::new(),
        }
    }

    /// Gives one circuit of a client link back to its budget.
    fn release(&mut self, link: LinkId) {
        if let Some(budget) = self.budgets.get_mut(&link) {
            budget.circuits = budget.circuits.saturating_sub(1);
        }
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
        let actions = on_link
            .into_iter()
            .chain(behind)
            .flat_map(|key| self.end(key, Some(link)))
            .collect();
        self.budgets.remove(&link);
        actions
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_client_link_builds_its_burst_then_one_each_second() {
        let mut budget = LinkBudget::new(100);
        // NET-332: the burst passes, and the build after it does not.
        for _ in 0..LINK_BUILD_BURST {
            assert!(budget.take(100));
        }
        assert!(!budget.take(100));
        // Five seconds give five builds back.
        for _ in 0..5 {
            assert!(budget.take(105));
        }
        assert!(!budget.take(105));
    }

    #[test]
    fn a_client_link_holds_at_most_its_circuits() {
        let mut budget = LinkBudget::new(0);
        let mut now = 0;
        while budget.circuits < LINK_CIRCUITS_MAX {
            now += 1;
            assert!(budget.take(now));
        }
        // NET-331: the next build fails even with builds in hand.
        now += 1_000;
        assert!(!budget.take(now));
        budget.circuits -= 1;
        assert!(budget.take(now));
    }
}
