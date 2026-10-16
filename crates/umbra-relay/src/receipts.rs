//! The link receipts of this relay (Part 10 §10.4.2): the peer of each relay
//! link, the window of cells that this relay takes on each such link, the
//! leaves of the cells that it sends until a receipt covers them, and the
//! receipts that it issued and took, each with its leaves, for the answer to
//! an isolation query.

use std::collections::{BTreeMap, VecDeque};

use umbra_core::directory::{
    receipt::{
        cell_leaf, Found, LinkReceipt, ReceiptAnswer, ReceiptQuery, RECEIPT_RETENTION,
        RECEIPT_WINDOW,
    },
    tree, EPOCH_SECONDS,
};
use umbra_crypto::{rand_core::CryptoRng, sign::SigningKey};
use umbra_queue::params::store_time;

use crate::circuits::LinkId;

/// The receipts that a relay with no receipt file keeps at one time, of
/// each kind. A window holds at most `RECEIPT_WINDOW` leaves of 32 bytes,
/// thus this bounds the memory of the book near 256 MiB when each window is
/// full. A relay that carries more cells in `RECEIPT_RETENTION` keeps its
/// receipts in a file ([`ReceiptShelf`]).
const HELD_MAX: usize = 4_096;
/// The leaves of the cells sent on one link that no receipt covered yet. A
/// peer that returns no receipt does not hold more than this.
const SENT_MAX: usize = 4 * RECEIPT_WINDOW as usize;

struct Window {
    epoch: u64,
    window: u32,
    leaves: Vec<[u8; 32]>,
}

/// A receipt that the book keeps, with the leaves that its root covers.
#[derive(Clone)]
pub struct KeptReceipt {
    /// Whether this relay issued the receipt; else it took it.
    pub issued: bool,
    /// The epoch of the receipt.
    pub epoch: u64,
    /// The signed receipt.
    pub signed: Vec<u8>,
    /// The leaves under its `batch_root`, in order.
    pub leaves: Vec<[u8; 32]>,
    /// The time at which the book kept it, at the end of its grain. A
    /// receipt file then shows no time to the second, and a receipt leaves
    /// at most one grain after its retention (`NET-301`, `REL-074`).
    pub at: u64,
}

/// Where the book keeps its receipts for `RECEIPT_RETENTION` (`REL-073`).
pub trait ReceiptShelf: Send {
    /// Keeps one receipt. A fault keeps nothing.
    fn keep(&mut self, kept: KeptReceipt) -> Result<(), crate::store::StoreFault>;
    /// The receipts of `epoch` whose leaves may hold `leaf`, those issued
    /// first.
    fn find(&self, epoch: u64, leaf: &[u8; 32]) -> Vec<KeptReceipt>;
    /// Erases each receipt kept before `floor` (`REL-074`).
    fn erase_before(&mut self, floor: u64);
    /// The receipts that it holds: those issued, and those taken.
    fn held(&self) -> (usize, usize);
}

/// The shelf of a relay with no receipt file: the receipts sit in RAM, at
/// most `HELD_MAX` of each kind.
#[derive(Default)]
pub struct MemoryShelf {
    issued: VecDeque<KeptReceipt>,
    taken: VecDeque<KeptReceipt>,
}

impl ReceiptShelf for MemoryShelf {
    fn keep(&mut self, kept: KeptReceipt) -> Result<(), crate::store::StoreFault> {
        let list = if kept.issued {
            &mut self.issued
        } else {
            &mut self.taken
        };
        if list.len() >= HELD_MAX {
            list.pop_front();
        }
        list.push_back(kept);
        Ok(())
    }

    fn find(&self, epoch: u64, leaf: &[u8; 32]) -> Vec<KeptReceipt> {
        self.issued
            .iter()
            .chain(self.taken.iter())
            .filter(|kept| kept.epoch == epoch && kept.leaves.contains(leaf))
            .cloned()
            .collect()
    }

    fn erase_before(&mut self, floor: u64) {
        self.issued.retain(|kept| kept.at >= floor);
        self.taken.retain(|kept| kept.at >= floor);
    }

    fn held(&self) -> (usize, usize) {
        (self.issued.len(), self.taken.len())
    }
}

/// The shelf of a book.
struct Shelf(Box<dyn ReceiptShelf>);

impl Default for Shelf {
    fn default() -> Self {
        Shelf(Box::new(MemoryShelf::default()))
    }
}

/// The receipts of one relay.
#[derive(Default)]
pub struct ReceiptBook {
    /// The relay at the other end of each relay link (`REL-174`).
    peers: BTreeMap<LinkId, [u8; 32]>,
    /// The open window of the cells taken on each relay link.
    taking: BTreeMap<LinkId, Window>,
    /// The next window of each link in the current epoch.
    next_window: BTreeMap<LinkId, (u64, u32)>,
    /// The leaves of the cells sent on each relay link, the oldest first.
    sent: BTreeMap<LinkId, VecDeque<[u8; 32]>>,
    /// The receipts that this relay issued and took.
    shelf: Shelf,
    /// The queries of each authority in the current epoch (`REL-186`).
    queries: BTreeMap<u8, (u64, u32)>,
    /// The chains of the current epoch: the epoch and the count.
    chains: (u64, u64),
    /// The two shares of the chain count of each ended epoch (`REL-190`).
    shares: BTreeMap<u64, [u64; 2]>,
    /// The time of the last erase of old receipts.
    erased_at: u64,
}

/// What the book does with a query that verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// A query that the relay answers, and that counts in `REL-186`.
    Fresh,
    /// The epoch of the query holds nothing here: an empty answer, and no
    /// count.
    Outside,
    /// The authority is above its bound (`REL-187`).
    Above,
}

/// The time between two erases of old receipts: a receipt leaves at most
/// this long after `RECEIPT_RETENTION`, and the shelf takes no write at
/// each tick.
const ERASE_EVERY: u64 = 60;

/// The leaf of a cell: its tag follows its `circ_id` (Part 3 §3.4.4).
fn leaf_of(cell: &[u8]) -> Option<[u8; 32]> {
    let tag: [u8; 16] = cell.get(16..32)?.try_into().ok()?;
    Some(cell_leaf(&tag))
}

impl ReceiptBook {
    /// The book keeps its receipts on `shelf` from now on.
    pub fn set_shelf(&mut self, shelf: Box<dyn ReceiptShelf>) {
        self.shelf = Shelf(shelf);
    }

    /// The link runs to the relay `relay_id`: this relay dialed it, or its
    /// hello verified.
    pub fn set_peer(&mut self, link: LinkId, relay_id: [u8; 32]) {
        self.peers.insert(link, relay_id);
    }

    /// The relay at the other end of `link`, when it is a relay link.
    pub fn peer(&self, link: LinkId) -> Option<[u8; 32]> {
        self.peers.get(&link).copied()
    }

    /// A link closed. Its open window goes with it, because no peer takes
    /// its receipt.
    pub fn link_closed(&mut self, link: LinkId) {
        self.peers.remove(&link);
        self.taking.remove(&link);
        self.next_window.remove(&link);
        self.sent.remove(&link);
    }

    /// This relay took `cell` on `link` at `now`. The result is the signed
    /// receipt of each window that closed, for the peer (`REL-175` to
    /// `REL-177`).
    pub fn cell_taken<R: CryptoRng + ?Sized>(
        &mut self,
        link: LinkId,
        cell: &[u8],
        own_id: &[u8; 32],
        key: &SigningKey,
        now: u64,
        rng: &mut R,
    ) -> Vec<Vec<u8>> {
        let (Some(_), Some(leaf)) = (self.peer(link), leaf_of(cell)) else {
            return Vec::new();
        };
        let epoch = now / EPOCH_SECONDS;
        let mut out = Vec::new();
        // REL-176: a window of an earlier epoch closes first.
        if self
            .taking
            .get(&link)
            .is_some_and(|open| open.epoch < epoch)
        {
            out.extend(self.close(link, own_id, key, now, rng));
        }
        let open = match self.taking.get_mut(&link) {
            Some(open) => open,
            None => {
                let window = match self.next_window.get(&link) {
                    Some((held, next)) if *held == epoch => *next,
                    _ => 0,
                };
                self.taking.entry(link).or_insert(Window {
                    epoch,
                    window,
                    leaves: Vec::new(),
                })
            }
        };
        open.leaves.push(leaf);
        if open.leaves.len() >= RECEIPT_WINDOW as usize {
            out.extend(self.close(link, own_id, key, now, rng));
        }
        out
    }

    fn close<R: CryptoRng + ?Sized>(
        &mut self,
        link: LinkId,
        own_id: &[u8; 32],
        key: &SigningKey,
        now: u64,
        rng: &mut R,
    ) -> Option<Vec<u8>> {
        let open = self.taking.remove(&link)?;
        let from_relay = self.peer(link)?;
        self.next_window
            .insert(link, (open.epoch, open.window.saturating_add(1)));
        let receipt = LinkReceipt {
            from_relay,
            to_relay: *own_id,
            epoch: open.epoch,
            window: open.window,
            cell_count: u32::try_from(open.leaves.len()).ok()?,
            batch_root: tree::root(&open.leaves)?,
        };
        let signed = receipt.sign(key, rng).ok()?;
        // A shelf that faults keeps nothing, and the peer takes the receipt
        // all the same.
        let _ = self.shelf.0.keep(KeptReceipt {
            issued: true,
            epoch: receipt.epoch,
            signed: signed.clone(),
            leaves: open.leaves,
            at: store_time(now),
        });
        Some(signed)
    }

    /// Closes each window of an epoch before `now` and gives its receipt
    /// for its link (`REL-176`), and erases each receipt past
    /// `RECEIPT_RETENTION` (`REL-074`).
    pub fn tick<R: CryptoRng + ?Sized>(
        &mut self,
        own_id: &[u8; 32],
        key: &SigningKey,
        now: u64,
        rng: &mut R,
    ) -> Vec<(LinkId, Vec<u8>)> {
        let epoch = now / EPOCH_SECONDS;
        let old: Vec<LinkId> = self
            .taking
            .iter()
            .filter(|(_, open)| open.epoch < epoch)
            .map(|(link, _)| *link)
            .collect();
        let mut out = Vec::new();
        for link in old {
            if let Some(signed) = self.close(link, own_id, key, now, rng) {
                out.push((link, signed));
            }
        }
        if now.saturating_sub(self.erased_at) >= ERASE_EVERY {
            self.erased_at = now;
            self.shelf
                .0
                .erase_before(now.saturating_sub(RECEIPT_RETENTION).saturating_add(1));
        }
        out
    }

    /// This relay sent `cell` on `link`.
    pub fn cell_sent(&mut self, link: LinkId, cell: &[u8]) {
        let (Some(_), Some(leaf)) = (self.peer(link), leaf_of(cell)) else {
            return;
        };
        let sent = self.sent.entry(link).or_default();
        if sent.len() >= SENT_MAX {
            sent.pop_front();
        }
        sent.push_back(leaf);
    }

    /// Takes a receipt that the peer of `link` issued for cells of this
    /// relay: its signature under `identity_pk` of the peer, and its root
    /// over the next `cell_count` leaves that this relay sent (`REL-178`).
    /// The result says whether the book kept it.
    pub fn receipt_taken(
        &mut self,
        link: LinkId,
        signed: &[u8],
        own_id: &[u8; 32],
        identity_pk: &[u8],
        now: u64,
    ) -> bool {
        let Some(peer) = self.peer(link) else {
            return false;
        };
        // The checks that cost no signature come first, thus a receipt that
        // names other relays or other cells costs none.
        let Ok(receipt) = LinkReceipt::parse(signed) else {
            return false;
        };
        if receipt.to_relay != peer || receipt.from_relay != *own_id {
            return false;
        }
        let Some(sent) = self.sent.get_mut(&link) else {
            return false;
        };
        let count = receipt.cell_count as usize;
        if sent.len() < count {
            return false;
        }
        let leaves: Vec<[u8; 32]> = sent.iter().take(count).copied().collect();
        if tree::root(&leaves) != Some(receipt.batch_root) {
            return false;
        }
        if LinkReceipt::verify(signed, identity_pk).is_err() {
            return false;
        }
        sent.drain(..count);
        self.shelf
            .0
            .keep(KeptReceipt {
                issued: false,
                epoch: receipt.epoch,
                signed: signed.to_vec(),
                leaves,
                at: store_time(now),
            })
            .is_ok()
    }

    /// The receipts that the book holds: those it issued, and those it took.
    pub fn held(&self) -> (usize, usize) {
        self.shelf.0.held()
    }

    /// Takes one query of `authority` for the epoch `asked` that verified
    /// at `now`, and says what the relay does with it. A query of an epoch
    /// after the one of `now`, or of one before `RECEIPT_RETENTION`, holds
    /// nothing here. `ended` also puts the epoch of `now` outside, for a
    /// query that asks for what an ended epoch leaves. Each other query
    /// counts in the bound of its authority (`REL-186`).
    pub fn admit_query(&mut self, authority: u8, asked: u64, ended: bool, now: u64) -> Asked {
        let epoch = now / EPOCH_SECONDS;
        let floor = epoch.saturating_sub(RECEIPT_RETENTION / EPOCH_SECONDS);
        if asked > epoch || asked < floor || (ended && asked == epoch) {
            return Asked::Outside;
        }
        if !self.admit(authority, now) {
            return Asked::Above;
        }
        Asked::Fresh
    }

    /// Whether one more query of `authority` fits in the epoch of `now`
    /// (`REL-186`, `REL-187`). A query that fits counts.
    pub fn admit(&mut self, authority: u8, now: u64) -> bool {
        let epoch = now / EPOCH_SECONDS;
        let held = self.queries.entry(authority).or_insert((epoch, 0));
        if held.0 != epoch {
            *held = (epoch, 0);
        }
        if held.1 >= umbra_core::directory::stat::RECEIPT_QUERY_MAX {
            return false;
        }
        held.1 = held.1.saturating_add(1);
        true
    }

    /// Counts the chains that this relay opened, and makes the shares of
    /// each epoch that ended (`REL-189` to `REL-191`). An epoch with no chain
    /// gives the shares of 0, thus a share says nothing of the load.
    pub fn count_chains<R: CryptoRng + ?Sized>(&mut self, built: u64, now: u64, rng: &mut R) {
        let epoch = now / EPOCH_SECONDS;
        let (held, count) = self.chains;
        if held != epoch {
            if held != 0 {
                self.shares
                    .insert(held, umbra_core::directory::stat::split(count, rng));
            }
            self.chains = (epoch, 0);
        }
        self.chains.1 = self.chains.1.saturating_add(built);
        let floor = epoch.saturating_sub(RECEIPT_RETENTION / EPOCH_SECONDS);
        self.shares.retain(|held, _| *held >= floor);
    }

    /// The share of an aggregator for one epoch (`REL-192`).
    pub fn share(&self, aggregator: u8, epoch: u64) -> Option<u64> {
        let [zero, one] = self.shares.get(&epoch)?;
        match aggregator {
            0 => Some(*zero),
            1 => Some(*one),
            _ => None,
        }
    }

    /// The answer to a query that verified (`REL-179`): the receipt of its
    /// epoch that covers its cell, issued or taken, with the proof.
    pub fn answer(&self, query: &ReceiptQuery) -> ReceiptAnswer {
        let leaf = query.leaf();
        for held in self.shelf.0.find(query.epoch, &leaf) {
            if held.epoch != query.epoch {
                continue;
            }
            let Some(index) = held.leaves.iter().position(|held| *held == leaf) else {
                continue;
            };
            let Some(proof) = tree::prove(&held.leaves, index) else {
                continue;
            };
            return ReceiptAnswer {
                found: if held.issued {
                    Found::Issued
                } else {
                    Found::Taken
                },
                receipt: held.signed,
                leaf_index: u32::try_from(index).unwrap_or(u32::MAX),
                proof,
            };
        }
        ReceiptAnswer::none()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use umbra_crypto::secret::Secret;

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
            Ok(self.0)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dest {
                *byte = self.try_next_u64()? as u8;
            }
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    #[test]
    fn an_ended_epoch_leaves_two_shares_of_its_chains_and_no_count() {
        let mut book = ReceiptBook::default();
        let mut rng = Rng(5);
        let start = 100 * EPOCH_SECONDS;
        book.count_chains(3, start, &mut rng);
        book.count_chains(4, start + 10, &mut rng);
        assert_eq!(book.share(0, 100), None);
        // REL-190: the epoch ends, and its shares sum to its count.
        book.count_chains(0, start + EPOCH_SECONDS, &mut rng);
        let shares = [book.share(0, 100).unwrap(), book.share(1, 100).unwrap()];
        assert_eq!(umbra_core::directory::stat::combine(shares), 7);
        assert_eq!(book.share(2, 100), None);
        // An epoch with no chain leaves the shares of 0.
        book.count_chains(0, start + 2 * EPOCH_SECONDS, &mut rng);
        let empty = [book.share(0, 101).unwrap(), book.share(1, 101).unwrap()];
        assert_eq!(umbra_core::directory::stat::combine(empty), 0);
        // REL-191: the shares leave after RECEIPT_RETENTION.
        book.count_chains(0, start + RECEIPT_RETENTION + 2 * EPOCH_SECONDS, &mut rng);
        assert_eq!(book.share(0, 100), None);
    }

    fn cell(i: u32) -> Vec<u8> {
        let mut cell = vec![0u8; 64];
        cell[..4].copy_from_slice(&i.to_be_bytes());
        cell[16..20].copy_from_slice(&(!i).to_be_bytes());
        cell
    }

    #[test]
    fn a_query_of_an_epoch_that_holds_nothing_counts_toward_no_bound() {
        let mut book = ReceiptBook::default();
        let now = 500 * EPOCH_SECONDS + 7;
        // An epoch that did not start, and one past the retention.
        assert_eq!(book.admit_query(3, 501, false, now), Asked::Outside);
        let old = 500 - RECEIPT_RETENTION / EPOCH_SECONDS - 1;
        assert_eq!(book.admit_query(3, old, false, now), Asked::Outside);
        // REL-192: the epoch that runs has no share yet.
        assert_eq!(book.admit_query(3, 500, true, now), Asked::Outside);
        // REL-187: the bound holds for each other query, and none of the
        // queries above counted.
        for _ in 0..umbra_core::directory::stat::RECEIPT_QUERY_MAX {
            assert_eq!(book.admit_query(3, 499, true, now), Asked::Fresh);
        }
        assert_eq!(book.admit_query(3, 500, false, now), Asked::Above);
    }

    #[test]
    fn a_window_of_cells_gets_a_receipt_that_the_sender_keeps() {
        let mut rng = Rng(1);
        let (a, b) = ([0xA1; 32], [0xB2; 32]);
        let b_key = SigningKey::from_seed(Secret::new([7; 32]));
        let b_pk = b_key.verifying_key().to_bytes();
        let (at_a, at_b) = (1, 2);
        let mut sender = ReceiptBook::default();
        let mut taker = ReceiptBook::default();
        sender.set_peer(at_a, b);
        taker.set_peer(at_b, a);
        let now = 490_000 * EPOCH_SECONDS + 10;
        let mut receipts = Vec::new();
        for i in 0..RECEIPT_WINDOW + 5 {
            sender.cell_sent(at_a, &cell(i));
            receipts.extend(taker.cell_taken(at_b, &cell(i), &b, &b_key, now, &mut rng));
        }
        assert_eq!(receipts.len(), 1, "one full window");
        assert!(sender.receipt_taken(at_a, &receipts[0], &a, &b_pk, now));
        assert!(
            !sender.receipt_taken(at_a, &receipts[0], &a, &b_pk, now),
            "no second time"
        );

        // REL-176: the partial window closes at the end of the epoch.
        let later = now + EPOCH_SECONDS;
        let partial = taker.tick(&b, &b_key, later, &mut rng);
        assert_eq!(partial.len(), 1);
        let read = LinkReceipt::parse(&partial[0].1).unwrap();
        assert_eq!((read.window, read.cell_count), (1, 5));
        assert!(sender.receipt_taken(at_a, &partial[0].1, &a, &b_pk, later));

        // Each side answers for the cell: the taker issued, the sender took.
        let query = ReceiptQuery {
            authority_index: 0,
            relay_id: b,
            epoch: 490_000,
            tag: cell(1_026)[16..32].try_into().unwrap(),
        };
        let issued = taker.answer(&query);
        assert_eq!(issued.found, Found::Issued);
        assert_eq!(issued.covers(&query, &b_pk).unwrap().window, 1);
        let taken = sender.answer(&query);
        assert_eq!(taken.found, Found::Taken);
        taken.covers(&query, &b_pk).unwrap();
        let unknown = ReceiptQuery { epoch: 1, ..query };
        assert_eq!(taker.answer(&unknown).found, Found::None);

        // REL-074, NET-301: a receipt goes after its retention, at most one
        // grain late, since the book holds its time to the end of its grain.
        taker.tick(&b, &b_key, later + RECEIPT_RETENTION, &mut rng);
        assert_eq!(taker.answer(&query).found, Found::Issued);
        let grain = umbra_queue::params::STORE_TIME_GRAIN;
        taker.tick(&b, &b_key, later + RECEIPT_RETENTION + grain, &mut rng);
        assert_eq!(taker.answer(&query).found, Found::None);
    }

    #[test]
    fn a_receipt_over_other_cells_or_on_a_client_link_goes() {
        let mut rng = Rng(2);
        let (a, b) = ([0xA1; 32], [0xB2; 32]);
        let b_key = SigningKey::from_seed(Secret::new([8; 32]));
        let b_pk = b_key.verifying_key().to_bytes();
        let mut sender = ReceiptBook::default();
        let mut taker = ReceiptBook::default();
        // REL-174: a link with no peer takes no receipt.
        assert!(taker
            .cell_taken(9, &cell(0), &b, &b_key, 0, &mut rng)
            .is_empty());
        sender.set_peer(1, b);
        taker.set_peer(2, a);
        for i in 0..3 {
            sender.cell_sent(1, &cell(i));
            // The taker saw other cells.
            taker.cell_taken(2, &cell(i + 100), &b, &b_key, 5, &mut rng);
        }
        let receipts = taker.tick(&b, &b_key, EPOCH_SECONDS + 5, &mut rng);
        assert!(!sender.receipt_taken(1, &receipts[0].1, &a, &b_pk, 10));
    }
}
