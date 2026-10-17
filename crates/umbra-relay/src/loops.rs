//! The loop cover of a relay (Part 3 §3.6.3, `NET-069`, `NET-363`). A relay
//! of layer 1 or 2 holds one loop chain through each relay of the next
//! layer that it holds a link to, and the chain ends at a relay of layer 3.
//! The relay sends one `LOOP` cell on each chain at `RELAY_LOOP_RATE`, and
//! the relay of layer 3 sends the cell back on the pacing clock of that
//! circuit (`NET-060`). The cells of this relay thus go on the links between
//! relays in the shape of the cells of a client, and the relay counts each
//! loop that did not come back.
//!
//! The table takes no socket and reads no clock. Each call returns the
//! cells to send, and the node frames them.

use std::collections::BTreeMap;

use umbra_crypto::{handshake::nk::RelayStatic, rand_core::CryptoRng};
use umbra_onion::{
    build::{build_cell_body, read_cell_body, DelayClass, Pending, BUILD_BUCKET, HELLO_LEN},
    layer::{KeySet, BLOCK},
    CIRCUIT_BUILD_TIMEOUT, CIRCUIT_MAX_AGE, CIRCUIT_MAX_CELLS,
};
use umbra_wire::{
    bucket::Bucket,
    cell::{pad_body, unpad_body, Cell, CellCommand},
};

use crate::circuits::{CircuitKey, CircuitTable, LinkId};

/// `RELAY_LOOP_RATE`: one loop cell on each loop chain each this many
/// seconds, from the previous loop on that chain (`NET-069`).
pub const RELAY_LOOP_PERIOD: u64 = 10;
/// A chain ends this long before `CIRCUIT_MAX_AGE`, as the circuit of a
/// client does under `NET-320`, thus no relay ends it first.
const LOOP_AGE_MARGIN: u64 = 60;
/// A chain ends this many cells before `CIRCUIT_MAX_CELLS` in one
/// direction (`NET-321`).
const LOOP_CELL_MARGIN: u32 = 64;
/// The wait after a chain that failed or that a relay ended, before the
/// next build through the same relay.
const LOOP_REBUILD_WAIT: u64 = RELAY_LOOP_PERIOD;

/// Where one chain is.
enum Stage {
    /// The hop at `hops.len()` of the path did not answer yet.
    Building { pending: Box<Pending>, since: u64 },
    /// Each hop answered.
    Ready,
}

/// One loop chain of this relay.
struct Chain {
    /// The relays of the chain, the next hop first. The last one is of
    /// layer 3.
    path: Vec<RelayStatic>,
    /// The key set of each hop that answered.
    hops: Vec<KeySet>,
    link: LinkId,
    circ_id: [u8; 16],
    stage: Stage,
    born: u64,
    last_loop: u64,
    /// The cells sent and received, against `CIRCUIT_MAX_CELLS`.
    cells: (u32, u32),
}

/// Wraps a forward body under the layers of `hops`, the last hop first,
/// and gives the `tag`. The last layer runs the key update of a hop 3
/// layer when `endpoint` holds (`NET-204`).
fn seal(hops: &mut [KeySet], body: &mut [u8], endpoint: bool) -> Option<[u8; BLOCK]> {
    let last = hops.len().checked_sub(1);
    let mut left = [0u8; BLOCK];

    for (index, hop) in hops.iter_mut().enumerate().rev() {
        left = hop.forward.encipher(&left, body).ok()?;
        if endpoint && Some(index) == last {
            hop.forward.update(&left);
        }
    }

    Some(left)
}

/// Removes the backward layers of `hops`, the next hop first, and makes the
/// check of `NET-114`. The last layer runs the key update of a hop 3 layer
/// when `endpoint` holds (`NET-207`).
fn open(hops: &mut [KeySet], tag: &[u8; BLOCK], body: &mut [u8], endpoint: bool) -> Option<()> {
    let last = hops.len().checked_sub(1);
    let mut left = *tag;
    let mut last_input = [0u8; BLOCK];

    for (index, hop) in hops.iter_mut().enumerate() {
        if Some(index) == last {
            last_input = left;
        }
        left = hop.backward.decipher(&left, body).ok()?;
    }

    if !umbra_crypto::ct_eq(&left, &[0u8; BLOCK]) {
        return None;
    }

    if endpoint {
        hops.last_mut()?.backward.update(&last_input);
    }

    Some(())
}

impl Chain {
    /// The cell of `command` in `bucket` on this chain, under each layer.
    /// The last layer of a chain under build is no hop 3 layer yet, thus
    /// it runs no key update.
    fn cell(&mut self, bucket: Bucket, command: CellCommand) -> Option<(LinkId, Vec<u8>)> {
        let mut body = vec![0u8; bucket.body_len()];
        pad_body(bucket, command, &[], &mut body).ok()?;

        let endpoint = matches!(self.stage, Stage::Ready);
        let tag = seal(&mut self.hops, &mut body, endpoint)?;

        self.cells.0 = self.cells.0.saturating_add(1);
        Some((self.link, [self.circ_id.as_slice(), &tag, &body].concat()))
    }

    /// The `DESTROY` of this chain, which ends the part of each relay of it
    /// (`NET-322`).
    fn destroy(&mut self) -> Option<(LinkId, Vec<u8>)> {
        let bucket = if matches!(self.stage, Stage::Ready) {
            Bucket::B0
        } else {
            BUILD_BUCKET
        };

        self.cell(bucket, CellCommand::Destroy)
    }

    /// Whether the chain passed its age or its cells (`NET-320`,
    /// `NET-321`).
    fn is_spent(&self, now: u64) -> bool {
        let cells_max = CIRCUIT_MAX_CELLS.saturating_sub(LOOP_CELL_MARGIN);
        now.saturating_sub(self.born) >= CIRCUIT_MAX_AGE.saturating_sub(LOOP_AGE_MARGIN)
            || self.cells.0 >= cells_max
            || self.cells.1 >= cells_max
    }
}

/// The loop chains of one relay.
pub struct Loops {
    layer: u8,
    /// The static key of each relay of the next layer.
    next: BTreeMap<[u8; 32], [u8; 32]>,
    /// The static key of each relay of layer 3, where the chain of a relay
    /// of layer 1 ends.
    exits: BTreeMap<[u8; 32], [u8; 32]>,
    /// The chain through each relay of the next layer.
    chains: BTreeMap<[u8; 32], Chain>,
    /// The relay of the chain of each circuit of this relay.
    by_circuit: BTreeMap<CircuitKey, [u8; 32]>,
    /// The time before which no chain builds through a relay.
    held_off: BTreeMap<[u8; 32], u64>,
    sent: u64,
    returned: u64,
}

impl Loops {
    /// The loop chains of a relay of `layer`. They hold no relay until
    /// [`Loops::set_relays`], thus a relay with no relay set makes no loop.
    pub fn new(layer: u8) -> Self {
        Loops {
            layer,
            next: BTreeMap::new(),
            exits: BTreeMap::new(),
            chains: BTreeMap::new(),
            by_circuit: BTreeMap::new(),
            held_off: BTreeMap::new(),
            sent: 0,
            returned: 0,
        }
    }

    /// The relays of the layers after this one, by `relay_id`, with the
    /// layer and the static key of each. A chain through a relay that the
    /// set names no more ends at the next tick.
    pub fn set_relays(&mut self, relays: &BTreeMap<[u8; 32], (u8, [u8; 32])>) {
        let of_layer = |layer: u8| {
            relays
                .iter()
                .filter(|(_, (held, _))| *held == layer)
                .map(|(relay_id, (_, s))| (*relay_id, *s))
                .collect::<BTreeMap<_, _>>()
        };

        self.next = of_layer(self.layer.saturating_add(1));
        self.exits = of_layer(3);
    }

    /// The loops that this relay sent and those that came back.
    pub fn counts(&self) -> (u64, u64) {
        (self.sent, self.returned)
    }

    /// Whether the cell of `circ_id` on `link` belongs to a loop chain.
    pub fn owns(&self, link: LinkId, circ_id: [u8; 16]) -> bool {
        self.by_circuit.contains_key(&CircuitKey { link, circ_id })
    }

    fn remove(&mut self, relay_id: &[u8; 32], hold_off_until: Option<u64>) -> Option<Chain> {
        let chain = self.chains.remove(relay_id)?;
        self.by_circuit.remove(&CircuitKey {
            link: chain.link,
            circ_id: chain.circ_id,
        });

        if let Some(until) = hold_off_until {
            self.held_off.insert(*relay_id, until);
        }

        Some(chain)
    }

    /// The work of one tick at `now`: a chain past its build time or its
    /// age ends, a chain whose period ran sends its loop, and a relay of
    /// the next layer with a link and no chain gets one. `next_hops` names
    /// the link to each relay of the next layer.
    pub fn tick<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        next_hops: &BTreeMap<[u8; 32], LinkId>,
        circuits: &CircuitTable,
        rng: &mut R,
    ) -> Vec<(LinkId, Vec<u8>)> {
        let mut cells = Vec::new();
        if self.layer >= 3 {
            return cells;
        }

        let ended: Vec<([u8; 32], bool)> = self
            .chains
            .iter()
            .filter_map(|(relay_id, chain)| {
                let gone = !self.next.contains_key(relay_id)
                    || next_hops.get(relay_id) != Some(&chain.link);
                match chain.stage {
                    Stage::Building { since, .. }
                        if gone || now.saturating_sub(since) >= CIRCUIT_BUILD_TIMEOUT =>
                    {
                        Some((*relay_id, true))
                    }
                    Stage::Ready if gone || chain.is_spent(now) => Some((*relay_id, false)),
                    _ => None,
                }
            })
            .collect();

        for (relay_id, failed) in ended {
            let wait = failed.then_some(now.saturating_add(LOOP_REBUILD_WAIT));
            if let Some(mut chain) = self.remove(&relay_id, wait) {
                cells.extend(chain.destroy());
            }
        }

        for chain in self.chains.values_mut() {
            if matches!(chain.stage, Stage::Ready)
                && now.saturating_sub(chain.last_loop) >= RELAY_LOOP_PERIOD
            {
                if let Some(cell) = chain.cell(Bucket::B0, CellCommand::Loop) {
                    cells.push(cell);
                    chain.last_loop = now;
                    self.sent = self.sent.saturating_add(1);
                }
            }
        }

        self.held_off.retain(|_, until| *until > now);
        let wanted: Vec<([u8; 32], LinkId)> = next_hops
            .iter()
            .filter(|(relay_id, _)| {
                self.next.contains_key(*relay_id)
                    && !self.chains.contains_key(*relay_id)
                    && !self.held_off.contains_key(*relay_id)
            })
            .map(|(relay_id, link)| (*relay_id, *link))
            .collect();

        for (relay_id, link) in wanted {
            cells.extend(self.start(relay_id, link, now, circuits, rng));
        }

        cells
    }

    /// Starts the chain through `relay_id` on `link`: the hello to that
    /// relay goes in a plain build cell (`NET-150`).
    fn start<R: CryptoRng + ?Sized>(
        &mut self,
        relay_id: [u8; 32],
        link: LinkId,
        now: u64,
        circuits: &CircuitTable,
        rng: &mut R,
    ) -> Option<(LinkId, Vec<u8>)> {
        let s = *self.next.get(&relay_id)?;
        let mut path = vec![RelayStatic { s, relay_id }];
        if self.layer == 1 {
            // A relay of layer 2 extends to each relay of layer 3, thus the
            // exit is a draw among them.
            let count = u32::try_from(self.exits.len()).ok().filter(|n| *n > 0)?;
            let at = usize::try_from(rng.next_u32() % count).ok()?;
            let (exit_id, exit_s) = self.exits.iter().nth(at)?;
            path.push(RelayStatic {
                s: *exit_s,
                relay_id: *exit_id,
            });
        }

        let mut key = CircuitKey {
            link,
            circ_id: [0; 16],
        };

        // NET-154, NET-155.
        loop {
            rng.fill_bytes(&mut key.circ_id);
            if circuits.is_free(&key) && !self.by_circuit.contains_key(&key) {
                break;
            }
        }

        let first = path.first()?;
        let mut hello = [0u8; HELLO_LEN];
        // The chain takes the default mode, thus its cells take the delay
        // of most circuits (§3.9).
        let pending = Pending::hello(first, DelayClass::Balanced, rng, &mut hello).ok()?;

        let mut body = vec![0u8; BUILD_BUCKET.body_len()];
        build_cell_body(CellCommand::Extend, &hello, &mut body).ok()?;

        self.by_circuit.insert(key, relay_id);
        self.chains.insert(
            relay_id,
            Chain {
                path,
                hops: Vec::new(),
                link,
                circ_id: key.circ_id,
                stage: Stage::Building {
                    pending: Box::new(pending),
                    since: now,
                },
                born: now,
                last_loop: now,
                cells: (1, 0),
            },
        );

        Some((
            link,
            [key.circ_id.as_slice(), &[0u8; BLOCK], &body].concat(),
        ))
    }

    /// Takes one cell of a loop chain: the answer of a hop, which sends the
    /// next hello or makes the chain ready, or a cell of the relay of layer
    /// 3. A cell that fails its check ends the chain (`NET-115`).
    pub fn on_cell<R: CryptoRng + ?Sized>(
        &mut self,
        link: LinkId,
        cell: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Vec<(LinkId, Vec<u8>)> {
        let Ok((parsed, _)) = Cell::parse(cell) else {
            return Vec::new();
        };

        let key = CircuitKey {
            link,
            circ_id: *parsed.circ_id,
        };
        let Some(relay_id) = self.by_circuit.get(&key).copied() else {
            return Vec::new();
        };

        let mut body = parsed.body.to_vec();
        let step = self
            .chains
            .get_mut(&relay_id)
            .and_then(|chain| Self::step(chain, self.layer, parsed.tag, &mut body, rng));

        match step {
            Some(Step::Loop) => {
                self.returned = self.returned.saturating_add(1);
                Vec::new()
            }
            Some(Step::Quiet) => Vec::new(),
            Some(Step::Send(cell)) => vec![cell],
            None => {
                let wait = now.saturating_add(LOOP_REBUILD_WAIT);
                self.remove(&relay_id, Some(wait))
                    .and_then(|mut chain| chain.destroy())
                    .into_iter()
                    .collect()
            }
        }
    }

    fn step<R: CryptoRng + ?Sized>(
        chain: &mut Chain,
        layer: u8,
        tag: &[u8; BLOCK],
        body: &mut [u8],
        rng: &mut R,
    ) -> Option<Step> {
        chain.cells.1 = chain.cells.1.saturating_add(1);
        let stage = core::mem::replace(&mut chain.stage, Stage::Ready);
        let Stage::Building { pending, since } = stage else {
            open(&mut chain.hops, tag, body, true)?;
            let (command, _) = unpad_body(body).ok()?;
            return Some(if command == CellCommand::Loop {
                Step::Loop
            } else {
                Step::Quiet
            });
        };

        // NET-164, NET-199: the answer comes back under the layers of the
        // hops before it, with no key update.
        open(&mut chain.hops, tag, body, false)?;
        let (command, reply) = read_cell_body(body).ok()?;
        if command != CellCommand::Extended {
            return None;
        }

        let ss_hop = pending.finish(reply).ok()?;
        let index = u32::try_from(chain.hops.len()).ok()?;
        // The layer of the hop is its hop index (`NET-106`).
        let hop_layer = u32::from(layer).saturating_add(1).saturating_add(index);
        chain.hops.push(KeySet::derive(&ss_hop, hop_layer));

        let Some(next) = chain.path.get(chain.hops.len()) else {
            chain.last_loop = chain.born;
            return Some(Step::Quiet);
        };

        let mut hello = [0u8; HELLO_LEN];
        let pending = Pending::hello(next, DelayClass::Balanced, rng, &mut hello).ok()?;
        chain.stage = Stage::Building {
            pending: Box::new(pending),
            since,
        };

        let mut body = vec![0u8; BUILD_BUCKET.body_len()];
        build_cell_body(CellCommand::Extend, &hello, &mut body).ok()?;
        let tag = seal(&mut chain.hops, &mut body, false)?;

        chain.cells.0 = chain.cells.0.saturating_add(1);
        Some(Step::Send((
            chain.link,
            [chain.circ_id.as_slice(), &tag, &body].concat(),
        )))
    }

    /// A relay ended the circuit of `circ_id` on `link` (`NET-322`). The
    /// result says whether it was a loop chain.
    pub fn on_destroy(&mut self, link: LinkId, circ_id: [u8; 16], now: u64) -> bool {
        let Some(relay_id) = self.by_circuit.get(&CircuitKey { link, circ_id }).copied() else {
            return false;
        };

        self.remove(&relay_id, Some(now.saturating_add(LOOP_REBUILD_WAIT)));
        true
    }

    /// The link of `link` closed, and each chain on it ended.
    pub fn link_closed(&mut self, link: LinkId) {
        let on_link: Vec<[u8; 32]> = self
            .chains
            .iter()
            .filter(|(_, chain)| chain.link == link)
            .map(|(relay_id, _)| *relay_id)
            .collect();

        for relay_id in on_link {
            self.remove(&relay_id, None);
        }
    }
}

/// What one cell of a chain gave.
enum Step {
    /// A loop came back.
    Loop,
    /// A cell that asks for nothing: a cover cell of the pacing clock, or
    /// the answer of the last hop.
    Quiet,
    /// The next hello.
    Send((LinkId, Vec<u8>)),
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
    use crate::circuits::{Action, Origin};
    use umbra_crypto::x25519::{PublicKey as XPublic, StaticSecret};

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
                .wrapping_add(1);
            Ok(self.0 >> 11)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dst {
                *byte = self.try_next_u64()? as u8;
            }
            Ok(())
        }
    }

    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

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

    /// The actions with each delay taken off.
    fn now_due(table: &mut CircuitTable, actions: Vec<Action>) -> Vec<Action> {
        actions
            .into_iter()
            .map(|action| match action {
                Action::Delayed {
                    circuit, action, ..
                } => {
                    table.released(&circuit);
                    *action
                }
                other => other,
            })
            .collect()
    }

    #[test]
    fn a_relay_of_layer_1_sends_a_loop_on_its_chain_and_counts_it_back() {
        // Link 1 joins relay A of layer 1 to B of layer 2, and link 3 joins
        // B to C of layer 3.
        let (b, mut table_b) = relay(0xB2, 2);
        let (c, mut table_c) = relay(0xC3, 3);
        let mut loops = Loops::new(1);
        loops.set_relays(&BTreeMap::from([
            (b.relay_id, (2, b.s)),
            (c.relay_id, (3, c.s)),
        ]));

        let (_, table_a) = relay(0xA1, 1);
        let mut rng = Rng(7);
        let next_hops = BTreeMap::from([(b.relay_id, 1)]);
        let mut now = 1_000;

        // NET-363: the relay starts a chain through each relay of the next
        // layer that it holds a link to.
        let cells = loops.tick(now, &next_hops, &table_a, &mut rng);
        let [(1, hello)] = &cells[..] else {
            panic!("no build cell");
        };

        // B answers on the link of A.
        let actions = table_b.on_cell(1, hello, Origin::Relay, now, &mut rng);
        let [Action::Send { link: 1, cell }] = &actions[..] else {
            panic!("B gave no answer");
        };
        assert!(loops.owns(1, cell[..16].try_into().unwrap()));

        // A sends the hello of C under the layer of B.
        let cells = loops.on_cell(1, cell, now, &mut rng);
        let [(1, extend)] = &cells[..] else {
            panic!("no EXTEND for C");
        };

        let actions = table_b.on_cell(1, extend, Origin::Relay, now, &mut rng);
        let actions = now_due(&mut table_b, actions);
        let [Action::Extend { from, body, .. }] = &actions[..] else {
            panic!("B did not extend");
        };

        let next = CircuitKey {
            link: 3,
            circ_id: [9; 16],
        };
        let actions = table_b.bind_next(*from, next, body, now);
        let [Action::Send { link: 3, cell }] = &actions[..] else {
            panic!("no build cell to C");
        };

        let actions = table_c.on_cell(3, cell, Origin::Relay, now, &mut rng);
        let [Action::Send { link: 3, cell }] = &actions[..] else {
            panic!("C gave no answer");
        };

        let actions = table_b.on_cell(3, cell, Origin::Relay, now, &mut rng);
        let [Action::Send { link: 1, cell }] = &actions[..] else {
            panic!("B did not move the answer back");
        };

        assert!(loops.on_cell(1, cell, now, &mut rng).is_empty());

        // NET-069: one loop each `RELAY_LOOP_PERIOD`, and C sends it back.
        assert!(loops
            .tick(now + 1, &next_hops, &table_a, &mut rng)
            .is_empty());

        for round in 1..=3u64 {
            now += RELAY_LOOP_PERIOD;
            let cells = loops.tick(now, &next_hops, &table_a, &mut rng);
            let [(1, cell)] = &cells[..] else {
                panic!("no loop");
            };

            let actions = table_b.on_cell(1, cell, Origin::Relay, now, &mut rng);
            let actions = now_due(&mut table_b, actions);
            let [Action::Send { link: 3, cell }] = &actions[..] else {
                panic!("B did not move the loop");
            };

            let actions = table_c.on_cell(3, cell, Origin::Relay, now, &mut rng);
            let actions = now_due(&mut table_c, actions);
            let [Action::Loop { circuit }] = &actions[..] else {
                panic!("C did not take the loop");
            };

            let back = table_c
                .originate(circuit, Bucket::B0, CellCommand::Loop, &[])
                .unwrap();
            let Action::Send { link: 3, cell } = back else {
                panic!("C sent nothing back");
            };

            let actions = table_b.on_cell(3, &cell, Origin::Relay, now, &mut rng);
            let [Action::Send { link: 1, cell }] = &actions[..] else {
                panic!("B did not move the loop back");
            };

            assert!(loops.on_cell(1, cell, now, &mut rng).is_empty());
            assert_eq!(loops.counts(), (round, round));
        }

        // A relay that ends the circuit ends the chain, and the next one
        // waits for `LOOP_REBUILD_WAIT`.
        let circ_id = hello[..16].try_into().unwrap();
        assert!(loops.on_destroy(1, circ_id, now));
        assert!(!loops.owns(1, circ_id));

        assert!(loops
            .tick(now + 1, &next_hops, &table_a, &mut rng)
            .is_empty());

        let cells = loops.tick(now + LOOP_REBUILD_WAIT, &next_hops, &table_a, &mut rng);
        assert_eq!(cells.len(), 1);

        // A link that closes ends the chain on it.
        loops.link_closed(1);
        assert!(loops.chains.is_empty() && loops.by_circuit.is_empty());
    }

    #[test]
    fn a_relay_of_layer_3_makes_no_chain_and_a_relay_with_no_set_makes_none() {
        let (_, table) = relay(0xC3, 3);
        let mut rng = Rng(1);
        let mut loops = Loops::new(3);
        loops.set_relays(&BTreeMap::from([([1; 32], (3, [2; 32]))]));

        assert!(loops
            .tick(10, &BTreeMap::from([([1; 32], 1)]), &table, &mut rng)
            .is_empty());

        let mut loops = Loops::new(2);
        assert!(loops
            .tick(10, &BTreeMap::from([([1; 32], 1)]), &table, &mut rng)
            .is_empty());
    }
}
