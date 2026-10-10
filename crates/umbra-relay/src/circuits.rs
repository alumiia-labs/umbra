//! The circuits that one relay holds (Part 3 §3.4.3, §3.4.4): the answer
//! to a build cell, the move of a cell to the next hop and back, the
//! extension of a circuit by one hop, and the endpoint that hands a
//! recovered body to the services of the relay.
//!
//! The table takes no socket. Each call returns the cells to send and the
//! bodies to serve, and the node moves them.

use std::collections::{BTreeMap, BTreeSet};

use umbra_crypto::{
    handshake::nk::RelayStatic, rand_core::CryptoRng, secret::Secret, x25519::StaticSecret,
};
use umbra_onion::{
    build::{
        answer, answer_at_queue_relay, build_cell_body, read_cell_body, HopHello, BUILD_BUCKET,
        REPLY_LEN,
    },
    circuit::{Position, RelayHop},
    CIRCUIT_BUILD_TIMEOUT, CIRCUIT_MAX_AGE, CIRCUIT_MAX_CELLS,
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

/// `RELAY_LINK_BUILD_BURST`: the builds that one link of a relay of the
/// layer before may send at once (`NET-332`). Such a link carries the
/// circuits of many clients.
pub const RELAY_LINK_BUILD_BURST: u32 = 8_192;
/// `RELAY_LINK_BUILD_RATE`: the builds that one such link gets back each
/// second after its burst (`NET-332`).
pub const RELAY_LINK_BUILD_RATE: u32 = 1_024;
/// `RELAY_CIRCUITS_MAX`: the circuits that one relay holds at once
/// (`NET-331`).
pub const RELAY_CIRCUITS_MAX: usize = 1 << 19;

/// Who holds the circuits of a link, for the share of the table that one
/// party takes (`NET-331`). The links of one holder count together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Holder {
    /// The address of a client at an ingress relay, as the runtime gives
    /// it. It is an IPv4 address, or the first 64 bits of an IPv6 address.
    /// The table holds it for the life of the link and writes it nowhere.
    Source([u8; 16]),
    /// A relay of the layer before, by the `relay_id` of its hello.
    Relay([u8; 32]),
    /// A link whose peer the relay cannot name, as in a test network.
    Link(LinkId),
}

/// Who sends the build cells of a link (`NET-331`, `NET-332`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A client, or a peer that named no relay: the link holds
    /// `LINK_CIRCUITS_MAX` circuits and builds at `LINK_BUILD_RATE`.
    Client,
    /// A relay of the layer before, whose link carries the circuits of
    /// many clients: it builds at `RELAY_LINK_BUILD_RATE`.
    Relay,
    /// A link that builds no circuit here. This relay dialed it, or it
    /// named no relay of the layer before at a relay of layer 2 or 3.
    Barred,
}

/// What one link spent of its circuits and its builds.
#[derive(Debug, Clone, Copy)]
struct LinkBudget {
    circuits: u32,
    builds: u32,
    refilled_at: u64,
    /// The circuits, the burst, and the rate of the origin of the link.
    circuits_max: u32,
    burst: u32,
    rate: u32,
}

impl LinkBudget {
    const fn new(origin: Origin, now: u64) -> Self {
        let (circuits_max, burst, rate) = match origin {
            Origin::Relay => (u32::MAX, RELAY_LINK_BUILD_BURST, RELAY_LINK_BUILD_RATE),
            Origin::Client | Origin::Barred => {
                (LINK_CIRCUITS_MAX, LINK_BUILD_BURST, LINK_BUILD_RATE)
            }
        };
        LinkBudget {
            circuits: 0,
            builds: burst,
            refilled_at: now,
            circuits_max,
            burst,
            rate,
        }
    }

    /// Takes one build at `now`, or refuses it.
    fn take(&mut self, now: u64) -> bool {
        let seconds = now.saturating_sub(self.refilled_at);
        let refill = u32::try_from(seconds)
            .unwrap_or(u32::MAX)
            .saturating_mul(self.rate);
        self.builds = self.builds.saturating_add(refill).min(self.burst);
        self.refilled_at = now;
        if self.circuits >= self.circuits_max || self.builds == 0 {
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
    /// The time at which the `EXTEND` went to the next hop.
    extended_at: u64,
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
    /// The holder of the link of the circuit at its build.
    holder: Holder,
    /// The place of the circuit among those of its holder, by the time of
    /// its last forward cell.
    seat: u64,
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
    /// The budget of each link that built a circuit here (`NET-331`,
    /// `NET-332`).
    budgets: BTreeMap<LinkId, LinkBudget>,
    /// The holder of each link that the node named one for.
    holders: BTreeMap<LinkId, Holder>,
    /// The circuits of each holder, and the same counts in their order.
    /// The table thus finds the holder of the most circuits with no scan.
    counts: BTreeMap<Holder, u32>,
    ranked: BTreeSet<(u32, Holder)>,
    /// The circuits of each holder, the one whose last forward cell is the
    /// oldest first. A build that finds no room ends the first one of a
    /// holder (`NET-331`). Before this, the table ended the oldest circuit
    /// that took no cell after its build. A few addresses that sent one
    /// cell on each circuit then held each place for `CIRCUIT_MAX_AGE`.
    seats: BTreeSet<(Holder, u64, CircuitKey)>,
    seat_seq: u64,
    /// The circuits that the table holds at most.
    held_max: usize,
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
            holders: BTreeMap::new(),
            counts: BTreeMap::new(),
            ranked: BTreeSet::new(),
            seats: BTreeSet::new(),
            seat_seq: 0,
            held_max: RELAY_CIRCUITS_MAX,
            builds: 0,
            clock_ms: 0,
        }
    }

    /// Sets the clock of the per-hop delay before a call.
    pub fn set_clock_ms(&mut self, now_ms: u64) {
        self.clock_ms = now_ms;
    }

    /// Sets the circuits that the table holds at most, for a test.
    #[doc(hidden)]
    pub fn set_held_max(&mut self, held_max: usize) {
        self.held_max = held_max;
    }

    /// Names the holder of `link`: the address of a client, or the relay
    /// of a hello that verified. A link that holds a circuit keeps the
    /// holder of its first build.
    pub fn set_holder(&mut self, link: LinkId, holder: Holder) {
        if self.circuits_on(link) == 0 {
            self.holders.insert(link, holder);
        }
    }

    /// The holder of `link`.
    fn holder_of(&self, link: LinkId) -> Holder {
        self.holders
            .get(&link)
            .copied()
            .unwrap_or(Holder::Link(link))
    }

    /// The circuits that one holder has in a table at its count: an equal
    /// part of the table. The count of the holders includes `joining`. A
    /// holder that builds at its share then ends one of its own circuits,
    /// thus no set of holders takes the places of another one.
    fn share(&self, joining: &Holder) -> usize {
        let holders = self
            .counts
            .len()
            .saturating_add(usize::from(!self.counts.contains_key(joining)));
        (self.held_max / holders.max(1)).max(1)
    }

    /// Moves the count of the circuits of `holder` by one.
    fn count(&mut self, holder: Holder, up: bool) {
        let before = self.counts.get(&holder).copied().unwrap_or(0);
        let after = if up {
            before.saturating_add(1)
        } else {
            before.saturating_sub(1)
        };
        self.ranked.remove(&(before, holder));
        if after == 0 {
            self.counts.remove(&holder);
        } else {
            self.counts.insert(holder, after);
            self.ranked.insert((after, holder));
        }
    }

    /// The circuit of `holder` whose last forward cell is the oldest.
    fn stalest(&self, holder: Holder) -> Option<CircuitKey> {
        let first = (
            holder,
            0,
            CircuitKey {
                link: 0,
                circ_id: [0; 16],
            },
        );
        self.seats
            .range(first..)
            .next()
            .filter(|(held, _, _)| *held == holder)
            .map(|(_, _, key)| *key)
    }

    /// Makes room for one build of `holder` in a table at its count
    /// (`NET-331`). A holder at its share ends its own stalest circuit. A
    /// holder below it ends the stalest circuit of the holder of the most
    /// circuits. A table below its count ends no circuit. Each step is a
    /// search in an ordered set.
    fn make_room(&mut self, holder: Holder) -> Vec<Action> {
        if self.held.len() < self.held_max {
            return Vec::new();
        }
        let own = self.counts.get(&holder).copied().unwrap_or(0);
        let from = if usize::try_from(own).unwrap_or(usize::MAX) >= self.share(&holder) {
            Some(holder)
        } else {
            self.ranked.last().map(|(_, most)| *most)
        };
        match from.and_then(|from| self.stalest(from)) {
            Some(stalest) => self.end_now(stalest, None),
            None => Vec::new(),
        }
    }

    /// Whether the table holds a circuit of `circ_id` on `link`, on the
    /// side of the client or on the side of the next hop.
    pub fn holds(&self, link: LinkId, circ_id: [u8; 16]) -> bool {
        !self.is_free(&CircuitKey { link, circ_id })
    }

    /// The circuits that `link` built here and that the table still holds.
    pub fn circuits_on(&self, link: LinkId) -> u32 {
        self.budgets.get(&link).map_or(0, |budget| budget.circuits)
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

    /// Takes one cell from a link. `origin` says who builds on that link.
    pub fn on_cell<R: CryptoRng + ?Sized>(
        &mut self,
        link: LinkId,
        cell: &[u8],
        origin: Origin,
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
        self.build(key, parsed.tag, &body, origin, now, rng)
    }

    /// A cell on a circuit identifier that the relay does not hold is a
    /// build cell (`NET-156` to `NET-161`).
    fn build<R: CryptoRng + ?Sized>(
        &mut self,
        key: CircuitKey,
        tag: &[u8; 16],
        body: &[u8],
        origin: Origin,
        now: u64,
        rng: &mut R,
    ) -> Vec<Action> {
        // NET-332: a link that builds no circuit here gets no answer.
        if *tag != [0u8; 16] || origin == Origin::Barred {
            return Vec::new();
        }
        let Ok((CellCommand::Extend, hello)) = read_cell_body(body) else {
            return Vec::new();
        };
        // NET-153: a hello for another relay gets no answer. The relay reads
        // the name before the budget, thus such a hello costs its link no
        // build and this relay no key agreement. NET-337: a hello with no
        // known mode does not parse.
        let Ok(named) = HopHello::parse(hello) else {
            return Vec::new();
        };
        if named.relay_id != self.relay.relay_id {
            return Vec::new();
        }
        let delay_mean_ms = named.delay_class.mean_ms();
        // NET-331, NET-332: a link above its circuits or its rate of builds
        // gets no answer, before the handshake costs this relay a key
        // agreement.
        let budget = self
            .budgets
            .entry(key.link)
            .or_insert_with(|| LinkBudget::new(origin, now));
        if !budget.take(now) {
            return Vec::new();
        }
        let mut reply = [0u8; REPLY_LEN];
        let answered: Result<(Secret<32>, Option<StaticSecret>), _> = if self.layer == 3 {
            answer_at_queue_relay(&self.relay, &self.static_secret, hello, rng, &mut reply)
                .map(|(ss, session)| (ss, Some(session)))
        } else {
            answer(&self.relay, &self.static_secret, hello, rng, &mut reply).map(|ss| (ss, None))
        };
        // A handshake that fails gets no answer. It cost a key agreement,
        // thus it keeps the build that it took of the budget.
        let Ok((ss_hop, session_secret)) = answered else {
            self.release(key.link);
            return Vec::new();
        };
        // NET-331: the room for the circuit, after the answer: a build that
        // gets no answer ends no circuit.
        let holder = self.holder_of(key.link);
        let mut actions = self.make_room(holder);
        let position = if self.layer == 3 {
            Position::Endpoint
        } else {
            Position::Middle
        };
        self.seat_seq = self.seat_seq.wrapping_add(1);
        self.seats.insert((holder, self.seat_seq, key));
        self.count(holder, true);
        self.held.insert(
            key,
            Held {
                hop: RelayHop::new(&ss_hop, u32::from(self.layer), position),
                next: None,
                extending: false,
                extended_at: 0,
                session_secret,
                created_at: now,
                cells: (1, 1),
                delay_mean_ms,
                released_at_ms: 0,
                ending: false,
                delayed_out: 0,
                holder,
                seat: self.seat_seq,
            },
        );
        self.builds = self.builds.saturating_add(1);
        let mut out = vec![0u8; BUILD_BUCKET.body_len()];
        if build_cell_body(CellCommand::Extended, &reply, &mut out).is_err() {
            return actions;
        }
        actions.push(Action::Send {
            link: key.link,
            cell: cell_bytes(&key.circ_id, &[0u8; 16], &out),
        });
        actions
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
        // NET-331: a forward cell moves the circuit behind each other one of
        // its holder. A build thus ends a circuit that carries cells last.
        self.seat_seq = self.seat_seq.wrapping_add(1);
        self.seats.remove(&(held.holder, held.seat, key));
        held.seat = self.seat_seq;
        self.seats.insert((held.holder, held.seat, key));
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
    pub fn bind_next(
        &mut self,
        from: CircuitKey,
        next: CircuitKey,
        body: &[u8],
        now: u64,
    ) -> Vec<Action> {
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
        held.extended_at = now;
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
        self.seats.remove(&(held.holder, held.seat, key));
        self.count(held.holder, false);
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

    /// Ends the circuit of `circ_id` on `link`, whose cell found no room in
    /// the backlog of that link, and tells each neighbor (`NET-349`). The
    /// link and each other circuit on it stay.
    pub fn shed(&mut self, link: LinkId, circ_id: [u8; 16]) -> Vec<Action> {
        let key = CircuitKey { link, circ_id };
        if self.held.contains_key(&key) {
            return self.end(key, None);
        }
        match self.back.get(&key).copied() {
            Some(client_side) => self.end(client_side, None),
            None => Vec::new(),
        }
    }

    /// Gives one circuit of a link back to its budget.
    fn release(&mut self, link: LinkId) {
        if let Some(budget) = self.budgets.get_mut(&link) {
            budget.circuits = budget.circuits.saturating_sub(1);
        }
    }

    /// A link closed: each circuit on it ends.
    pub fn link_closed(&mut self, link: LinkId) -> Vec<Action> {
        // The circuits of one link are neighbors in each map, thus the end
        // of a link reads no circuit of another one.
        let of_link = CircuitKey {
            link,
            circ_id: [0; 16],
        }..=CircuitKey {
            link,
            circ_id: [0xFF; 16],
        };
        let on_link: Vec<CircuitKey> = self
            .held
            .range(of_link.clone())
            .map(|(key, _)| *key)
            .collect();
        let behind: Vec<CircuitKey> = self
            .back
            .range(of_link)
            .map(|(_, client_side)| *client_side)
            .collect();
        let actions = on_link
            .into_iter()
            .chain(behind)
            .flat_map(|key| self.end(key, Some(link)))
            .collect();
        self.budgets.remove(&link);
        self.holders.remove(&link);
        actions
    }

    /// Ends each circuit past `CIRCUIT_MAX_AGE` or past `CIRCUIT_MAX_CELLS`
    /// in one direction (`NET-320`, `NET-321`), and each circuit whose next
    /// hop gave no `EXTENDED` in `CIRCUIT_BUILD_TIMEOUT`. The client ended
    /// that build (`NET-169`), and its `DESTROY` is one more layer down.
    /// This relay moves it on as a cell of the middle and cannot read it.
    /// Before this, a next hop that never took the `EXTEND` left the circuit
    /// here until `CIRCUIT_MAX_AGE`.
    pub fn expire(&mut self, now: u64) -> Vec<Action> {
        let aged: Vec<CircuitKey> = self
            .held
            .iter()
            .filter(|(_, held)| {
                now.saturating_sub(held.created_at) >= CIRCUIT_MAX_AGE
                    || (held.extending
                        && now.saturating_sub(held.extended_at) >= CIRCUIT_BUILD_TIMEOUT)
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
        let mut budget = LinkBudget::new(Origin::Client, 100);
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
    fn a_relay_link_builds_its_own_burst_and_holds_no_count_of_circuits() {
        let mut budget = LinkBudget::new(Origin::Relay, 100);
        // NET-332: the link of a relay carries the circuits of many
        // clients, and its builds have a bound all the same.
        for _ in 0..RELAY_LINK_BUILD_BURST {
            assert!(budget.take(100));
        }
        assert!(!budget.take(100));
        for _ in 0..RELAY_LINK_BUILD_RATE {
            assert!(budget.take(101));
        }
        assert!(!budget.take(101));
        assert!(budget.circuits > LINK_CIRCUITS_MAX);
    }

    #[test]
    fn each_holder_has_an_equal_part_of_the_table() {
        let secret = StaticSecret::from([7; 32]);
        let relay = RelayStatic {
            s: [0; 32],
            relay_id: [1; 32],
        };
        let mut table = CircuitTable::new(relay, secret, 1);
        table.set_held_max(12);
        let (one, other) = (Holder::Source([1; 16]), Holder::Source([2; 16]));
        // NET-331: one holder alone has the whole table, and each further
        // one makes the part of each smaller. A table with more holders
        // than places still gives each one a circuit.
        assert_eq!(table.share(&one), 12);
        table.count(one, true);
        assert_eq!(table.share(&one), 12);
        assert_eq!(table.share(&other), 6);
        table.count(other, true);
        table.count(other, true);
        assert_eq!(table.share(&Holder::Link(9)), 4);
        assert_eq!(table.ranked.last(), Some(&(2, other)));
        table.count(other, false);
        table.count(other, false);
        assert_eq!(table.share(&one), 12);
        assert_eq!(table.counts.len(), 1);
        table.set_held_max(0);
        assert_eq!(table.share(&other), 1);
        // The links of one address count together, and a link that the
        // node named no holder for counts alone.
        table.set_holder(4, one);
        table.set_holder(6, one);
        assert_eq!(table.holder_of(4), table.holder_of(6));
        assert_eq!(table.holder_of(8), Holder::Link(8));
        table.link_closed(4);
        assert_eq!(table.holder_of(4), Holder::Link(4));
    }

    #[test]
    fn a_client_link_holds_at_most_its_circuits() {
        let mut budget = LinkBudget::new(Origin::Client, 0);
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
