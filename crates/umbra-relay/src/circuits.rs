//! The circuits that one relay holds (Part 3 §3.4.3, §3.4.4): the answer
//! to a build cell, the move of a cell to the next hop and back, the
//! extension of a circuit by one hop, and the endpoint that hands a
//! recovered body to the services of the relay.
//!
//! The table takes no socket. Each call returns the cells to send and the
//! bodies to serve, and the node moves them.

use std::collections::{BTreeMap, BTreeSet, HashSet};

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

/// `RELAY_LINK_BUILD_BURST`: the builds that the links of one relay of the
/// layer before may send at once together (`NET-332`). Such a link carries
/// the circuits of many clients.
pub const RELAY_LINK_BUILD_BURST: u32 = 8_192;
/// `RELAY_LINK_BUILD_RATE`: the builds that the links of one such relay
/// get back together each second after their burst (`NET-332`).
pub const RELAY_LINK_BUILD_RATE: u32 = 1_024;
/// `RELAY_CIRCUITS_MAX`: the circuits that one relay holds at once
/// (`NET-331`).
pub const RELAY_CIRCUITS_MAX: usize = 1 << 19;
/// `SOURCE_BUILD_BURST`: the builds that the links of one address may send
/// at once (`NET-332`). The count of an address outlives its links.
pub const SOURCE_BUILD_BURST: u32 = 256;
/// `SOURCE_BUILD_RATE`: the builds that one address gets back each second
/// after its burst (`NET-332`).
pub const SOURCE_BUILD_RATE: u32 = 4;
/// The addresses whose build count the table holds at once. Each address
/// above it shares one count, thus a party with many addresses grows no
/// map.
pub const SOURCE_BUDGETS_MAX: usize = 1 << 16;
/// The key of the count that the addresses above `SOURCE_BUDGETS_MAX`
/// share. No address of a peer cuts to it.
const OVERFLOW_SOURCE: [u8; 16] = [0xFF; 16];
/// `HELLO_REPLAY_MIN`: the ephemeral keys of the last hellos that a relay
/// keeps at least, to refuse a repeat before its key agreement (`NET-361`).
pub const HELLO_REPLAY_MIN: usize = 1 << 16;
/// `CIRCUIT_DELAYED_MAX`: the forward cells of one circuit that wait for
/// their per-hop delay at once (`NET-362`).
pub const CIRCUIT_DELAYED_MAX: u32 = 1_024;

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
    /// A link that named no relay at a relay of layer 2 or 3. It builds a
    /// measurement candidate alone, under the budget of a client link
    /// (`NET-353`).
    Measurer,
}

/// The measurement state of a circuit (Part 10 §10.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Measure {
    /// A circuit of a client or of a relay.
    No,
    /// A circuit that a link with no `RelayHello` built at a relay of
    /// layer 2 or 3. It serves a `MEAS_OPEN` and nothing else (`NET-353`).
    Candidate,
    /// A circuit with an open measurement session, which ends at this
    /// time (`REL-201`).
    Open { until: u64 },
}

/// The builds that one party holds: a token bucket (`NET-332`).
#[derive(Debug, Clone, Copy)]
struct Tokens {
    builds: u32,
    refilled_at: u64,
}

impl Tokens {
    const fn full(burst: u32, now: u64) -> Self {
        Tokens {
            builds: burst,
            refilled_at: now,
        }
    }

    /// Gives back `rate` builds for each second since the last refill, up
    /// to `burst`. A clock that steps back gives nothing.
    fn refill(&mut self, now: u64, burst: u32, rate: u32) {
        let seconds = now.saturating_sub(self.refilled_at);
        let refill = u32::try_from(seconds)
            .unwrap_or(u32::MAX)
            .saturating_mul(rate);

        self.builds = self.builds.saturating_add(refill).min(burst);
        self.refilled_at = self.refilled_at.max(now);
    }
}

/// The circuits, the burst, and the rate of builds of a link of `origin`.
const fn limits_of(origin: Origin) -> (u32, u32, u32) {
    match origin {
        Origin::Relay => (u32::MAX, RELAY_LINK_BUILD_BURST, RELAY_LINK_BUILD_RATE),
        Origin::Client | Origin::Barred | Origin::Measurer => {
            (LINK_CIRCUITS_MAX, LINK_BUILD_BURST, LINK_BUILD_RATE)
        }
    }
}

/// What one link spent of its circuits and its builds.
#[derive(Debug, Clone, Copy)]
struct LinkBudget {
    circuits: u32,
    tokens: Tokens,
    /// The circuits, the burst, and the rate of the origin of the link.
    circuits_max: u32,
    burst: u32,
    rate: u32,
}

impl LinkBudget {
    const fn new(origin: Origin, now: u64) -> Self {
        let (circuits_max, burst, rate) = limits_of(origin);
        LinkBudget {
            circuits: 0,
            tokens: Tokens::full(burst, now),
            circuits_max,
            burst,
            rate,
        }
    }

    /// Takes the limits of the origin of the link now. A link that built a
    /// measurement candidate before its `RelayHello` verified then builds
    /// as the link of a relay.
    fn retune(&mut self, origin: Origin) {
        let (circuits_max, burst, rate) = limits_of(origin);
        self.circuits_max = circuits_max;
        self.burst = burst;
        self.rate = rate;
        self.tokens.builds = self.tokens.builds.min(burst);
    }

    /// Whether the link holds room for one more build at `now`.
    fn has_room(&mut self, now: u64) -> bool {
        self.tokens.refill(now, self.burst, self.rate);
        self.circuits < self.circuits_max && self.tokens.builds > 0
    }

    /// Takes one build at `now`, or refuses it.
    #[cfg(test)]
    fn take(&mut self, now: u64) -> bool {
        if !self.has_room(now) {
            return false;
        }

        self.tokens.builds -= 1;
        self.circuits += 1;
        true
    }
}

/// The ephemeral keys of the last hellos that this relay ran a key
/// agreement for (`NET-361`). Two sets of at most `HELLO_REPLAY_MIN` each
/// take turns, thus the relay keeps at least the last `HELLO_REPLAY_MIN`.
#[derive(Default)]
struct Hellos {
    current: HashSet<[u8; 16]>,
    previous: HashSet<[u8; 16]>,
}

impl Hellos {
    fn holds(&self, ephemeral: &[u8; 16]) -> bool {
        self.current.contains(ephemeral) || self.previous.contains(ephemeral)
    }

    fn keep(&mut self, ephemeral: [u8; 16]) {
        if self.current.len() >= HELLO_REPLAY_MIN {
            self.previous = core::mem::take(&mut self.current);
        }

        self.current.insert(ephemeral);
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
    /// A link with no `RelayHello` built a measurement candidate
    /// (`NET-353`). The node counts it as one measurement attempt.
    Candidate {
        /// The circuit.
        circuit: CircuitKey,
    },
    /// The relay recovered the content of a `MEAS_OPEN` cell. The node
    /// verifies it and calls [`CircuitTable::open_measure`], or it ends the
    /// circuit.
    MeasOpen {
        /// The circuit.
        circuit: CircuitKey,
        /// The certificate and the signature.
        content: Vec<u8>,
    },
    /// The relay recovered the content of a `MEAS_ECHO` cell of an open
    /// measurement session. The node calls [`CircuitTable::echo`] when the
    /// link holds room for the cell (`REL-003`).
    Echo {
        /// The circuit.
        circuit: CircuitKey,
        /// The content, which goes back as it came.
        content: Vec<u8>,
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
    /// The pause of a circuit that waited for its delayed cells: the node
    /// hands it to [`CircuitTable::pause_now`].
    Pause {
        /// The circuit.
        key: CircuitKey,
    },
    /// Tell the next hop on `link` that the client of the circuit of
    /// `circ_id` reads no cell until it resumes (`WIR-545`).
    PauseNext {
        /// The link to the next hop.
        link: LinkId,
        /// The circuit on that link.
        circ_id: [u8; 16],
    },
    /// The client of a circuit that ends here reads no cell until it
    /// resumes: the services end its subscriptions, and its pacing clock
    /// stops (`WIR-546`).
    Paused {
        /// The circuit.
        circuit: CircuitKey,
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
    /// The circuit asked for its next hop with an `EXTEND`, and that hop
    /// did not answer yet. The `EXTEND` can wait for the link to that hop.
    extending: bool,
    /// The time of that `EXTEND`.
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
    measure: Measure,
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
    /// The address of each link, as the runtime cut it.
    sources: BTreeMap<LinkId, [u8; 16]>,
    /// The builds of each address (`NET-332`). A count outlives the links
    /// of its address, thus a new connection gets no new burst. A count
    /// that is full again leaves, because a new one is the same.
    source_budgets: BTreeMap<[u8; 16], Tokens>,
    /// The relay of the layer before that the hello of each link named.
    relay_links: BTreeMap<LinkId, [u8; 32]>,
    /// The builds of each relay of the layer before, over each link that
    /// its hello names (`NET-332`). A count outlives the links of its
    /// relay, as the count of an address does. Before this, each link had
    /// a budget of its own. A relay that opened many links, or a new link
    /// after each burst, then forced a key agreement for each build of
    /// each budget.
    relay_budgets: BTreeMap<[u8; 32], Tokens>,
    /// The ephemeral keys of the last hellos (`NET-361`).
    hellos: Hellos,
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
            sources: BTreeMap::new(),
            source_budgets: BTreeMap::new(),
            relay_links: BTreeMap::new(),
            relay_budgets: BTreeMap::new(),
            hellos: Hellos::default(),
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
    /// holder of its first build. The builds of a link count against the
    /// relay of its hello from that hello on (`NET-332`), also on a link
    /// that built a measurement candidate before it.
    pub fn set_holder(&mut self, link: LinkId, holder: Holder) {
        if let Holder::Relay(relay_id) = holder {
            self.relay_links.insert(link, relay_id);
        }

        if self.circuits_on(link) == 0 {
            self.holders.insert(link, holder);
        }
    }

    /// Names the address of `link`, as the runtime cut it. The builds of
    /// a client link and of the link of a measurer count against that
    /// address too (`NET-332`).
    pub fn set_source(&mut self, link: LinkId, source: [u8; 16]) {
        self.sources.insert(link, source);
    }

    /// Takes one build of `link` at `now` from the budget of the link, and
    /// from the budget of its address or of the relay of its hello, or
    /// refuses it (`NET-331`, `NET-332`).
    fn take_build(&mut self, link: LinkId, origin: Origin, now: u64) -> bool {
        let budget = self
            .budgets
            .entry(link)
            .or_insert_with(|| LinkBudget::new(origin, now));
        budget.retune(origin);

        if !budget.has_room(now) {
            return false;
        }

        let source = match origin {
            Origin::Client | Origin::Measurer => self.sources.get(&link).copied(),
            Origin::Relay | Origin::Barred => None,
        };

        if let Some(source) = source {
            let key = if self.source_budgets.contains_key(&source)
                || self.source_budgets.len() < SOURCE_BUDGETS_MAX
            {
                source
            } else {
                OVERFLOW_SOURCE
            };

            let tokens = self
                .source_budgets
                .entry(key)
                .or_insert(Tokens::full(SOURCE_BUILD_BURST, now));
            tokens.refill(now, SOURCE_BUILD_BURST, SOURCE_BUILD_RATE);
            if tokens.builds == 0 {
                return false;
            }

            tokens.builds -= 1;
        }

        let relay = match origin {
            Origin::Relay => self.relay_links.get(&link).copied(),
            Origin::Client | Origin::Barred | Origin::Measurer => None,
        };

        // The hello names a relay of the relay set, thus the map holds one
        // count for each relay of the layer before at most.
        if let Some(relay_id) = relay {
            let tokens = self
                .relay_budgets
                .entry(relay_id)
                .or_insert(Tokens::full(RELAY_LINK_BUILD_BURST, now));
            tokens.refill(now, RELAY_LINK_BUILD_BURST, RELAY_LINK_BUILD_RATE);
            if tokens.builds == 0 {
                return false;
            }

            tokens.builds -= 1;
        }

        budget.tokens.builds -= 1;
        budget.circuits += 1;
        true
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
            let actions = self.forward(key, bucket, parsed.tag, &mut body, now);
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

        // NET-361: a hello whose ephemeral key this relay ran an agreement
        // for gets no answer. A repeat would cost that agreement again and
        // give its sender no key, and it costs the sender nothing.
        let Some(ephemeral) = named.flight1.first_chunk::<16>().copied() else {
            return Vec::new();
        };

        if self.hellos.holds(&ephemeral) {
            return Vec::new();
        }

        let delay_mean_ms = named.delay_class.mean_ms();

        // NET-331, NET-332: a link above its circuits or its rate of builds,
        // or an address above its rate, gets no answer, before the
        // handshake costs this relay a key agreement.
        if !self.take_build(key.link, origin, now) {
            return Vec::new();
        }

        self.hellos.keep(ephemeral);

        let is_candidate = origin == Origin::Measurer;
        let mut reply = [0u8; REPLY_LEN];
        // A candidate ends at this relay in each layer, and it serves no
        // command, thus it takes no session key.
        let answered: Result<(Secret<32>, Option<StaticSecret>), _> = if self.layer == 3
            && !is_candidate
        {
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

        let position = if self.layer == 3 && !is_candidate {
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
                measure: if is_candidate {
                    Measure::Candidate
                } else {
                    Measure::No
                },
            },
        );

        if is_candidate {
            actions.push(Action::Candidate { circuit: key });
        } else {
            // REL-189: a measurement circuit is no chain.
            self.builds = self.builds.saturating_add(1);
        }

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

        // A measurement circuit holds no cell: its relay is the one hop.
        if held.delay_mean_ms == 0 || held.measure != Measure::No {
            return actions;
        }

        // NET-362: a circuit holds at most `CIRCUIT_DELAYED_MAX` cells for
        // their delay. A cell that dropped would break the chain of its
        // layer, thus the circuit ends.
        let held_back = actions
            .iter()
            .filter(|action| {
                matches!(
                    action,
                    Action::Send { .. } | Action::Serve { .. } | Action::Loop { .. }
                )
            })
            .count();
        let held_back = u32::try_from(held_back).unwrap_or(u32::MAX);
        if held.delayed_out.saturating_add(held_back) > CIRCUIT_DELAYED_MAX {
            return self.close(key);
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
        now: u64,
    ) -> Vec<Action> {
        let Some(held) = self.held.get_mut(&key) else {
            return Vec::new();
        };

        // NET-339: the end of the circuit waits for its delayed cells, and
        // a forward cell after that end goes nowhere.
        if held.ending {
            return Vec::new();
        }

        let measure = held.measure;
        let over = match measure {
            // REL-201: the end of the session bounds the circuit, and
            // `CIRCUIT_MAX_CELLS` does not.
            Measure::Open { until } => now >= until,
            Measure::Candidate => {
                !held.count(true) || now.saturating_sub(held.created_at) >= CIRCUIT_BUILD_TIMEOUT
            }
            Measure::No => !held.count(true),
        };

        if over {
            return self.close(key);
        }

        // A candidate ends at each cell but a `MEAS_OPEN` that the node
        // verifies, and [`CircuitTable::close`] gives that end no sign.
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

        let is_extending = held.extending;
        let recovered = if self.layer == 3 && measure == Measure::No {
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

        match (measure, command) {
            // NET-169, NET-322: the client ended its circuit here. The
            // relays before this one moved the `DESTROY` as a cell of the
            // middle, thus they learn the end from this relay by the link.
            // An ingress relay took it from the client itself, and the
            // relay of a measurement circuit from its measurer: that link
            // gets no `Destroy`. Before this, hops 1 and 2 kept a retired
            // circuit until `CIRCUIT_MAX_AGE`.
            (_, CellCommand::Destroy) => {
                let from = (self.layer == 1 || measure != Measure::No).then_some(key.link);
                return self.end(key, from);
            }
            // REL-002: the echo of an open session, in bucket `B0` alone
            // (`REL-041`). Each other cell of that circuit drops.
            (Measure::Open { .. }, CellCommand::MeasEcho) if bucket == Bucket::B0 => {
                return vec![Action::Echo {
                    circuit: key,
                    content: content.to_vec(),
                }];
            }
            (Measure::Open { .. }, _) => return Vec::new(),
            // NET-353: a candidate serves a `MEAS_OPEN` and ends at each
            // other cell.
            (Measure::Candidate, CellCommand::MeasOpen) if bucket == Bucket::B3 => {
                return vec![Action::MeasOpen {
                    circuit: key,
                    content: content.to_vec(),
                }];
            }
            (Measure::Candidate, _) => return self.close(key),
            // An ingress relay takes each client link, thus a measurer
            // opens its session on a circuit of one hop there.
            (Measure::No, CellCommand::MeasOpen)
                if self.layer == 1 && !is_extending && bucket == Bucket::B3 =>
            {
                return vec![Action::MeasOpen {
                    circuit: key,
                    content: content.to_vec(),
                }];
            }
            (Measure::No, _) => {}
        }

        match (command, self.layer) {
            (CellCommand::Data, 3) => vec![Action::Serve {
                circuit: key,
                bucket,
                content: content.to_vec(),
            }],
            (CellCommand::Loop, 3) => vec![Action::Loop { circuit: key }],
            // NET-166: a relay of layer 3 extends no circuit.
            (CellCommand::Extend, 1 | 2) => {
                // NET-150, NET-319: one `EXTEND` in `B1` for each circuit.
                // A second one while the first waits for its next hop ends
                // the circuit. Before this, each one held a copy of its body
                // at the node until the dial opened.
                if is_extending || bucket != BUILD_BUCKET {
                    return self.close(key);
                }

                let Ok(relay_id) = HopHello::parse(content).map(|hello| hello.relay_id) else {
                    return Vec::new();
                };

                if let Some(held) = self.held.get_mut(&key) {
                    held.extending = true;
                    held.extended_at = now;
                }

                vec![Action::Extend {
                    from: key,
                    relay_id,
                    body: body.to_vec(),
                }]
            }
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

    /// Whether `circuit` is a measurement candidate (`NET-353`).
    pub fn is_candidate(&self, circuit: &CircuitKey) -> bool {
        self.held
            .get(circuit)
            .is_some_and(|held| held.measure == Measure::Candidate)
    }

    /// Opens the measurement session of `circuit`, which ends at `until`.
    /// False for a circuit that the table does not hold, that holds a next
    /// hop, or that holds a session already.
    pub fn open_measure(&mut self, circuit: &CircuitKey, until: u64) -> bool {
        match self.held.get_mut(circuit) {
            Some(held) if held.next.is_none() && !matches!(held.measure, Measure::Open { .. }) => {
                held.measure = Measure::Open { until };
                true
            }
            _ => false,
        }
    }

    /// The echo of one `MEAS_ECHO` cell: the same content under the
    /// backward layer of this relay, in the form of a build cell
    /// (`REL-003`).
    pub fn echo(&mut self, circuit: &CircuitKey, content: &[u8]) -> Option<Action> {
        let held = self.held.get_mut(circuit)?;
        if !matches!(held.measure, Measure::Open { .. }) {
            return None;
        }

        let mut body = vec![0u8; Bucket::B0.body_len()];
        pad_body(Bucket::B0, CellCommand::MeasEcho, content, &mut body).ok()?;
        let tag = held.hop.backward_build(&mut body).ok()?;

        Some(Action::Send {
            link: circuit.link,
            cell: cell_bytes(&circuit.circ_id, &tag, &body),
        })
    }

    /// Ends a circuit for a cause of this relay. A measurement candidate
    /// ends with no `Destroy` to its link: a rejected measurement attempt
    /// gets no sign (`NET-353`, `REL-205`).
    fn close(&mut self, key: CircuitKey) -> Vec<Action> {
        let from = self.is_candidate(&key).then_some(key.link);
        self.end(key, from)
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

    /// The client of the circuit of `circ_id` on `link` paused its session
    /// (`WIR-545`, `WIR-546`). `link` is the side of the client. A record
    /// that names no circuit of that side drops, thus a next hop pauses
    /// nothing. The pause goes behind each forward cell of the circuit that
    /// waits for its delay here. A cell that arrived at the endpoint after
    /// the pause would start the pacing again, and the cells of that pacing
    /// would end the circuit at the ingress relay.
    pub fn on_pause(&mut self, link: LinkId, circ_id: [u8; 16]) -> Vec<Action> {
        let key = CircuitKey { link, circ_id };
        let Some(held) = self.held.get_mut(&key) else {
            return Vec::new();
        };

        if held.ending {
            return Vec::new();
        }

        if held.delayed_out > 0 {
            held.delayed_out = held.delayed_out.saturating_add(1);
            return vec![Action::Delayed {
                at_ms: held.released_at_ms,
                circuit: key,
                action: Box::new(Action::Pause { key }),
            }];
        }

        self.pause_now(key)
    }

    /// Moves the pause of a circuit on: to the next hop, or to the
    /// services of a circuit that ends here. The node runs it for an
    /// [`Action::Pause`].
    pub fn pause_now(&mut self, key: CircuitKey) -> Vec<Action> {
        let Some(held) = self.held.get(&key) else {
            return Vec::new();
        };

        match held.next {
            Some(next) => vec![Action::PauseNext {
                link: next.link,
                circ_id: next.circ_id,
            }],
            None if self.layer == 3 => vec![Action::Paused { circuit: key }],
            None => Vec::new(),
        }
    }

    /// Pauses each circuit that `link` built here: its client parks its
    /// session (`WIR-541`, `WIR-542`).
    pub fn pause_link(&mut self, link: LinkId) -> Vec<Action> {
        let of_link = CircuitKey {
            link,
            circ_id: [0; 16],
        }..=CircuitKey {
            link,
            circ_id: [0xFF; 16],
        };

        let on_link: Vec<CircuitKey> = self.held.range(of_link).map(|(key, _)| *key).collect();

        on_link
            .into_iter()
            .flat_map(|key| self.on_pause(key.link, key.circ_id))
            .collect()
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
        self.sources.remove(&link);
        self.relay_links.remove(&link);
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
                let age = now.saturating_sub(held.created_at);
                let measured = match held.measure {
                    Measure::No => false,
                    // NET-353: a candidate with no `MEAS_OPEN` in its time.
                    Measure::Candidate => age >= CIRCUIT_BUILD_TIMEOUT,
                    // REL-201: the end of the session.
                    Measure::Open { until } => now >= until,
                };

                measured
                    || age >= CIRCUIT_MAX_AGE
                    || (held.extending
                        && now.saturating_sub(held.extended_at) >= CIRCUIT_BUILD_TIMEOUT)
                    || held.cells.0 > CIRCUIT_MAX_CELLS
                    || held.cells.1 > CIRCUIT_MAX_CELLS
            })
            .map(|(key, _)| *key)
            .collect();

        // NET-332: the count of an address or of a relay that is full
        // again leaves.
        self.source_budgets.retain(|_, tokens| {
            tokens.refill(now, SOURCE_BUILD_BURST, SOURCE_BUILD_RATE);
            tokens.builds < SOURCE_BUILD_BURST
        });
        self.relay_budgets.retain(|_, tokens| {
            tokens.refill(now, RELAY_LINK_BUILD_BURST, RELAY_LINK_BUILD_RATE);
            tokens.builds < RELAY_LINK_BUILD_BURST
        });

        aged.into_iter().flat_map(|key| self.close(key)).collect()
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
    use umbra_crypto::x25519::PublicKey as XPublic;
    use umbra_onion::{
        build::{DelayClass, Pending, HELLO_LEN},
        layer::KeySet,
    };

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

    struct Rng(u64);

    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            Ok(self.0 >> 11 ^ self.0 << 7)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dst {
                *byte = self.try_next_u64()? as u8;
            }
            Ok(())
        }
    }

    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    /// A relay of `layer` and its table.
    fn relay(seed: u8, layer: u8) -> (RelayStatic, CircuitTable) {
        let secret = StaticSecret::from([seed; 32]);
        let relay = RelayStatic {
            s: *XPublic::from(&secret).as_bytes(),
            relay_id: [seed; 32],
        };

        let table = CircuitTable::new(
            RelayStatic {
                s: relay.s,
                relay_id: relay.relay_id,
            },
            secret,
            layer,
        );

        (relay, table)
    }

    /// The plain build cell of a hello to `relay` on `circ_id`.
    fn build_cell(
        relay: &RelayStatic,
        circ_id: [u8; 16],
        class: DelayClass,
        rng: &mut Rng,
    ) -> (Vec<u8>, Pending) {
        let mut hello = [0u8; HELLO_LEN];
        let pending = Pending::hello(relay, class, rng, &mut hello).unwrap();

        let mut body = vec![0u8; BUILD_BUCKET.body_len()];
        build_cell_body(CellCommand::Extend, &hello, &mut body).unwrap();

        ([circ_id.as_slice(), &[0u8; 16], &body].concat(), pending)
    }

    /// Builds one hop at `table` on `link`, and gives the key set of that
    /// hop.
    fn one_hop(
        table: &mut CircuitTable,
        relay: &RelayStatic,
        link: LinkId,
        circ_id: [u8; 16],
        class: DelayClass,
        rng: &mut Rng,
    ) -> KeySet {
        let (cell, pending) = build_cell(relay, circ_id, class, rng);
        let actions = table.on_cell(link, &cell, Origin::Relay, 100, rng);

        let [Action::Send { cell, .. }] = &actions[..] else {
            panic!("no answer: {actions:?}");
        };

        let (_, reply) = read_cell_body(&cell[32..]).unwrap();
        let ss = pending.finish(reply).unwrap();

        KeySet::derive(&ss, u32::from(table.layer))
    }

    /// A forward cell of `command` under the layer of `hop`, which runs the
    /// key update of a hop 3 layer when `endpoint` holds.
    fn sealed(
        hop: &mut KeySet,
        circ_id: [u8; 16],
        bucket: Bucket,
        command: CellCommand,
        endpoint: bool,
    ) -> Vec<u8> {
        let mut body = vec![0u8; bucket.body_len()];
        pad_body(bucket, command, &[], &mut body).unwrap();
        let tag = hop.forward.encipher(&[0u8; 16], &mut body).unwrap();

        if endpoint {
            hop.forward.update(&tag);
        }

        [circ_id.as_slice(), &tag, &body].concat()
    }

    fn answered(actions: &[Action]) -> bool {
        actions
            .iter()
            .any(|action| matches!(action, Action::Send { .. }))
    }

    #[test]
    fn a_repeated_hello_gets_no_answer_and_costs_no_build() {
        let (relay, mut table) = relay(0xA1, 1);
        let mut rng = Rng(3);
        let (cell, _) = build_cell(&relay, [1; 16], DelayClass::Fast, &mut rng);

        assert!(answered(&table.on_cell(
            2,
            &cell,
            Origin::Client,
            100,
            &mut rng
        )));

        // NET-361: the same hello on another circuit, and on another link,
        // gets no answer before the key agreement.
        let mut again = cell.clone();
        again[..16].copy_from_slice(&[2; 16]);

        assert!(table
            .on_cell(2, &again, Origin::Client, 100, &mut rng)
            .is_empty());

        again[..16].copy_from_slice(&[3; 16]);
        assert!(table
            .on_cell(4, &again, Origin::Client, 100, &mut rng)
            .is_empty());

        assert_eq!(table.circuits_on(2), 1);
        assert_eq!(table.circuits_on(4), 0);

        // A fresh hello passes.
        let (fresh, _) = build_cell(&relay, [4; 16], DelayClass::Fast, &mut rng);
        assert!(answered(&table.on_cell(
            2,
            &fresh,
            Origin::Client,
            100,
            &mut rng
        )));
    }

    #[test]
    fn an_address_keeps_its_build_count_across_its_links() {
        let (relay, mut table) = relay(0xA1, 1);
        let mut rng = Rng(5);
        let source = [0x20; 16];
        let mut circ = 0u32;
        let mut build = |table: &mut CircuitTable, link: LinkId, rng: &mut Rng, now: u64| {
            circ += 1;
            let mut circ_id = [0u8; 16];
            circ_id[..4].copy_from_slice(&circ.to_be_bytes());
            let (cell, _) = build_cell(&relay, circ_id, DelayClass::Fast, rng);
            answered(&table.on_cell(link, &cell, Origin::Client, now, rng))
        };

        // NET-332: four links of one address spend the burst of the address
        // together.
        let links = u64::from(SOURCE_BUILD_BURST / LINK_BUILD_BURST);
        for link in 0..links {
            table.set_source(link, source);
            for _ in 0..LINK_BUILD_BURST {
                assert!(build(&mut table, link, &mut rng, 100));
            }
        }

        // A new connection of that address gets no new burst, and one of
        // another address does.
        table.set_source(50, source);
        assert!(!build(&mut table, 50, &mut rng, 100));

        table.set_source(51, [0x21; 16]);
        assert!(build(&mut table, 51, &mut rng, 100));

        // The count outlives the links of the address.
        for link in 0..links {
            table.link_closed(link);
        }

        table.link_closed(50);
        table.set_source(52, source);
        assert!(!build(&mut table, 52, &mut rng, 100));

        // One second gives `SOURCE_BUILD_RATE` builds back.
        for _ in 0..SOURCE_BUILD_RATE {
            assert!(build(&mut table, 52, &mut rng, 101));
        }
        assert!(!build(&mut table, 52, &mut rng, 101));

        // A count that is full again leaves the table at the sweep.
        assert_eq!(table.source_budgets.len(), 2);
        table.expire(101 + u64::from(SOURCE_BUILD_BURST));
        assert!(table.source_budgets.is_empty());
    }

    #[test]
    fn the_links_of_one_relay_share_its_build_count() {
        let (_, mut table) = relay(0xB2, 2);
        let peer = [0x51; 32];

        // NET-332: two links whose hello names one relay spend one burst
        // together. Before this, each link had a burst of its own.
        table.set_holder(1, Holder::Relay(peer));
        table.set_holder(2, Holder::Relay(peer));
        for _ in 0..RELAY_LINK_BUILD_BURST / 2 {
            assert!(table.take_build(1, Origin::Relay, 100));
            assert!(table.take_build(2, Origin::Relay, 100));
        }

        assert!(!table.take_build(1, Origin::Relay, 100));
        assert!(!table.take_build(2, Origin::Relay, 100));

        // The count outlives the links of the relay, thus a new link gets
        // no new burst.
        table.link_closed(1);
        table.link_closed(2);
        table.set_holder(3, Holder::Relay(peer));
        assert!(!table.take_build(3, Origin::Relay, 100));

        // Another relay has a count of its own, and a link with no hello
        // has the budget of its link alone.
        table.set_holder(4, Holder::Relay([0x52; 32]));
        assert!(table.take_build(4, Origin::Relay, 100));
        assert!(table.take_build(5, Origin::Relay, 100));

        // One second gives `RELAY_LINK_BUILD_RATE` builds back.
        for _ in 0..RELAY_LINK_BUILD_RATE {
            assert!(table.take_build(3, Origin::Relay, 101));
        }
        assert!(!table.take_build(3, Origin::Relay, 101));

        // A count that is full again leaves the table at the sweep.
        assert_eq!(table.relay_budgets.len(), 2);
        let full = u64::from(RELAY_LINK_BUILD_BURST / RELAY_LINK_BUILD_RATE);
        table.expire(101 + full);
        assert!(table.relay_budgets.is_empty());
    }

    #[test]
    fn a_link_that_built_as_a_measurer_builds_as_a_relay_after_its_hello() {
        let mut budget = LinkBudget::new(Origin::Measurer, 0);
        for _ in 0..LINK_BUILD_BURST {
            assert!(budget.take(0));
        }

        assert!(!budget.take(0));

        // NET-332: the hello verified, and the link takes the limits of a
        // relay link at its next build.
        budget.retune(Origin::Relay);
        assert!(budget.take(1));
        assert_eq!(budget.circuits_max, u32::MAX);
        assert!(budget.tokens.builds >= RELAY_LINK_BUILD_RATE - 1);
    }

    #[test]
    fn the_hop_that_reads_a_destroy_tells_the_hop_before_it() {
        let mut rng = Rng(7);
        // NET-322: at layer 2 the previous hop moved the `DESTROY` as a
        // cell of the middle, thus it learns the end by the link.
        let (relay, mut table) = relay(0xB2, 2);
        let mut hop = one_hop(&mut table, &relay, 1, [5; 16], DelayClass::Fast, &mut rng);
        let cell = sealed(&mut hop, [5; 16], Bucket::B0, CellCommand::Destroy, false);
        let actions = table.on_cell(1, &cell, Origin::Relay, 101, &mut rng);

        assert!(actions.contains(&Action::Destroy {
            link: 1,
            circ_id: [5; 16]
        }));
        assert!(table.is_empty());

        // An ingress relay took it from the client itself.
        let (relay, mut table) = self::relay(0xA1, 1);
        let mut hop = one_hop(&mut table, &relay, 2, [6; 16], DelayClass::Fast, &mut rng);
        let cell = sealed(&mut hop, [6; 16], Bucket::B0, CellCommand::Destroy, false);
        let actions = table.on_cell(2, &cell, Origin::Client, 101, &mut rng);

        assert!(!actions
            .iter()
            .any(|action| matches!(action, Action::Destroy { .. })));
        assert!(table.is_empty());
    }

    #[test]
    fn a_circuit_asks_for_its_next_hop_once_and_in_b1() {
        let mut rng = Rng(9);
        let (relay, mut table) = relay(0xB2, 2);
        let (next, _) = self::relay(0xC3, 3);
        let mut hello = [0u8; HELLO_LEN];
        let _ = Pending::hello(&next, DelayClass::Fast, &mut rng, &mut hello).unwrap();
        let extend = |hop: &mut KeySet, circ_id: [u8; 16], bucket: Bucket| {
            let mut body = vec![0u8; bucket.body_len()];
            pad_body(bucket, CellCommand::Extend, &hello, &mut body).unwrap();
            let tag = hop.forward.encipher(&[0u8; 16], &mut body).unwrap();
            [circ_id.as_slice(), &tag, &body].concat()
        };

        let mut hop = one_hop(&mut table, &relay, 1, [5; 16], DelayClass::Fast, &mut rng);
        let cell = extend(&mut hop, [5; 16], Bucket::B1);
        let actions = table.on_cell(1, &cell, Origin::Relay, 101, &mut rng);
        assert!(matches!(actions[..], [Action::Extend { .. }]));

        // NET-319: a second `EXTEND` while the first waits ends the circuit.
        let cell = extend(&mut hop, [5; 16], Bucket::B1);
        let actions = table.on_cell(1, &cell, Origin::Relay, 101, &mut rng);
        assert!(actions.contains(&Action::Closed {
            circuit: CircuitKey {
                link: 1,
                circ_id: [5; 16]
            }
        }));

        // NET-150: an `EXTEND` in another bucket ends its circuit, and its
        // body goes nowhere.
        let mut hop = one_hop(&mut table, &relay, 1, [6; 16], DelayClass::Fast, &mut rng);
        let cell = extend(&mut hop, [6; 16], Bucket::B3);
        let actions = table.on_cell(1, &cell, Origin::Relay, 101, &mut rng);

        assert!(!actions
            .iter()
            .any(|action| matches!(action, Action::Extend { .. })));
        assert!(table.is_empty());
    }

    #[test]
    fn a_circuit_holds_a_bounded_count_of_delayed_cells_and_none_after_its_end() {
        let mut rng = Rng(11);
        let (relay, mut table) = relay(0xC3, 3);
        let mut hop = one_hop(
            &mut table,
            &relay,
            1,
            [5; 16],
            DelayClass::Private,
            &mut rng,
        );

        for _ in 0..CIRCUIT_DELAYED_MAX {
            let cell = sealed(&mut hop, [5; 16], Bucket::B0, CellCommand::Loop, true);
            let actions = table.on_cell(1, &cell, Origin::Relay, 101, &mut rng);
            assert!(matches!(actions[..], [Action::Delayed { .. }]));
        }

        // NET-362: the cell above the bound ends the circuit after the cells
        // that wait.
        let cell = sealed(&mut hop, [5; 16], Bucket::B0, CellCommand::Loop, true);
        let actions = table.on_cell(1, &cell, Origin::Relay, 101, &mut rng);
        let [Action::Delayed { action, .. }] = &actions[..] else {
            panic!("{actions:?}");
        };

        assert!(matches!(**action, Action::End { .. }));

        // NET-339: a forward cell of a circuit whose end waits goes nowhere.
        let cell = sealed(&mut hop, [5; 16], Bucket::B0, CellCommand::Loop, true);
        assert!(table
            .on_cell(1, &cell, Origin::Relay, 101, &mut rng)
            .is_empty());
        assert!(table.holds(1, [5; 16]));
    }
}
