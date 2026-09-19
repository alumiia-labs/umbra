//! The hash chain of one author in one community (Part 12 §12.4.1): the
//! links, the author side with the checkpoint cadence and the withdrawal
//! list, and the reader side that recomputes a window from the hashes it
//! holds.

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

use umbra_crypto::{hash::sha3_256, labels, rand_core::TryCryptoRng};

use super::{
    identity::AuthorIdentity,
    record::{post_hash, Checkpoint, CheckpointFields, CommunityPost, Withdrawn},
    SIG_INTERVAL, SIG_MAX_AGE, SIG_MIN_INTERVAL, WITHDRAW_MAX,
};
use crate::Error;

/// The free space of a `B2` cell beside a checkpoint (§12.4.1 rule 4).
pub const CHECKPOINT_FREE_SPACE: usize = 2_569;

/// `link_0`.
pub fn link_zero(community_id: &[u8; 32], pseudonym: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[labels::COMMUNITY_CHAIN, community_id, pseudonym])
}

/// `link_n = SHA3-256(link_{n-1} || SHA3-256(post_n))`. A reader computes
/// the value, and no relay serves it (`COM-016`).
pub fn next_link(previous: &[u8; 32], post_hash: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[previous, post_hash])
}

/// The chain of the device that owns it (§12.3.2, one owner for each
/// chain). The state is what the chain owner persists and syncs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorChain {
    community_id: [u8; 32],
    next_index: u32,
    signed_head: [u8; 32],
    head: [u8; 32],
    /// The link and the append time of each post with no checkpoint.
    unsigned: VecDeque<([u8; 32], u64)>,
    last_checkpoint_at: Option<u64>,
    withdrawals: BTreeSet<u32>,
}

impl AuthorChain {
    /// The empty chain of `pseudonym`.
    pub fn new(community_id: [u8; 32], pseudonym: &[u8; 32]) -> Self {
        let zero = link_zero(&community_id, pseudonym);
        AuthorChain {
            community_id,
            next_index: 0,
            signed_head: zero,
            head: zero,
            unsigned: VecDeque::new(),
            last_checkpoint_at: None,
            withdrawals: BTreeSet::new(),
        }
    }

    /// The index of the next post.
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Appends a post and returns its encoding.
    pub fn append(
        &mut self,
        author: &AuthorIdentity,
        amends: u32,
        body: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let encoded = CommunityPost {
            pseudonym: author.pseudonym(),
            index: self.next_index,
            amends,
            body,
        }
        .encode()?;
        let following = self.next_index.checked_add(1).ok_or(Error::NoPath)?;
        self.head = next_link(&self.head, &post_hash(&encoded));
        self.unsigned.push_back((self.head, now));
        self.next_index = following;
        Ok(encoded)
    }

    /// Queues the withdrawal of `index`. It travels in the next checkpoint
    /// of the ordinary cadence and makes none itself (`COM-094`).
    pub fn withdraw(&mut self, index: u32) -> Result<(), Error> {
        if index >= self.next_index {
            return Err(Error::Malformed);
        }
        self.withdrawals.insert(index);
        Ok(())
    }

    /// Whether a withdrawal waits for a checkpoint, thus the interface
    /// does not show it as complete (`COM-096`).
    pub fn withdrawal_pending(&self, index: u32) -> bool {
        self.withdrawals.contains(&index)
    }

    /// Whether rule 1 asks for a checkpoint and rule 2 and rule 3 permit
    /// one (`COM-045` to `COM-048`).
    pub fn checkpoint_due(&self, now: u64) -> bool {
        let Some((_, oldest_at)) = self.unsigned.front() else {
            return false;
        };
        let spaced = self
            .last_checkpoint_at
            .is_none_or(|at| now.saturating_sub(at) >= SIG_MIN_INTERVAL);
        let full = self.unsigned.len() >= SIG_INTERVAL as usize;
        let aged = now.saturating_sub(*oldest_at) >= SIG_MAX_AGE;
        spaced && (full || aged)
    }

    /// Signs a checkpoint over the oldest posts with none, `SIG_INTERVAL`
    /// at the most, with the queued withdrawals that its history holds.
    pub fn checkpoint<R: TryCryptoRng + ?Sized>(
        &mut self,
        author: &AuthorIdentity,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        if !self.checkpoint_due(now) {
            return Err(Error::NoPath);
        }
        let covered = self.unsigned.len().min(SIG_INTERVAL as usize);
        let covered_u32 = u32::try_from(covered).map_err(|_| Error::NoPath)?;
        let unsigned_u32 = u32::try_from(self.unsigned.len()).map_err(|_| Error::NoPath)?;
        let start_index = self.next_index.saturating_sub(unsigned_u32);
        let end_index = start_index.saturating_add(covered_u32).saturating_sub(1);
        let (current_head, _) = *self
            .unsigned
            .get(covered.saturating_sub(1))
            .ok_or(Error::NoPath)?;
        let named: Vec<u32> = self
            .withdrawals
            .iter()
            .copied()
            .filter(|index| *index <= end_index)
            .take(WITHDRAW_MAX)
            .collect();
        let fields = CheckpointFields {
            community_id: self.community_id,
            start_index,
            end_index,
            previous_signed_head: self.signed_head,
            current_head,
            withdrawn: Withdrawn::from_indexes(&named)?,
        };
        let encoded = Checkpoint::sign(author, &fields, rng)?;
        self.unsigned.drain(..covered);
        self.signed_head = current_head;
        self.last_checkpoint_at = Some(now);
        for index in named {
            self.withdrawals.remove(&index);
        }
        Ok(encoded)
    }

    /// Whether a post of `post_len` bytes travels in the cell of a
    /// checkpoint that covers it alone (`COM-049`, `COM-050`).
    pub fn shares_the_checkpoint_cell(post_len: usize) -> bool {
        post_len <= CHECKPOINT_FREE_SPACE
    }
}

/// Selects one hash for each index of a window, such that the chain from
/// `previous_signed_head` reaches `current_head` (§12.4.4 rule 6,
/// `COM-216`). `candidates` holds the hashes at each index in order, which
/// are one or two. The result is the position of the admitted hash at each
/// index.
///
/// A window with an index that has no hash is partial, and the caller does
/// not verify it (`COM-086`), thus that input is `NoPath` here.
pub fn resolve_window(
    checkpoint: &Checkpoint<'_>,
    candidates: &[Vec<[u8; 32]>],
) -> Result<Vec<usize>, Error> {
    let span = checkpoint
        .end_index
        .saturating_sub(checkpoint.start_index)
        .saturating_add(1);
    if candidates.len() != span as usize || candidates.iter().any(Vec::is_empty) {
        return Err(Error::NoPath);
    }
    // COM-212 bounds the window, and a relay holds two bodies at the most,
    // thus the search tries 32 combinations at the most.
    if candidates.iter().any(|c| c.len() > 2) {
        return Err(Error::Malformed);
    }
    let combinations = 1usize << candidates.len();
    for combination in 0..combinations {
        let mut link = checkpoint.previous_signed_head;
        let mut chosen = Vec::with_capacity(candidates.len());
        let mut valid = true;
        for (position, hashes) in candidates.iter().enumerate() {
            let pick = (combination >> position) & 1;
            let Some(hash) = hashes.get(pick) else {
                valid = false;
                break;
            };
            link = next_link(&link, hash);
            chosen.push(pick);
        }
        if valid && link == checkpoint.current_head {
            return Ok(chosen);
        }
    }
    Err(Error::Unverified)
}

/// What a checkpoint did to the chain of a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// The window verifies. The value is the position of the admitted hash
    /// at each index.
    Window(Vec<usize>),
    /// The reader holds this checkpoint already.
    Duplicate,
    /// A second checkpoint verifies at one triple and differs, or two
    /// windows do not join. The interface shows a fork of the pseudonym
    /// (`COM-019`, `COM-020`).
    Fork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowHeads {
    start_index: u32,
    previous_signed_head: [u8; 32],
    current_head: [u8; 32],
    withdrawn: Withdrawn,
}

/// The verified windows of one pseudonym at a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderChain {
    community_id: [u8; 32],
    pseudonym: [u8; 32],
    /// The windows by `end_index`.
    windows: BTreeMap<u32, WindowHeads>,
    withdrawn: BTreeSet<u32>,
}

impl ReaderChain {
    /// The empty state for `pseudonym`.
    pub fn new(community_id: [u8; 32], pseudonym: [u8; 32]) -> Self {
        ReaderChain {
            community_id,
            pseudonym,
            windows: BTreeMap::new(),
            withdrawn: BTreeSet::new(),
        }
    }

    /// Whether a verified checkpoint covers `index`, thus the post at it
    /// is settled.
    pub fn is_settled(&self, index: u32) -> bool {
        self.windows
            .range(index..)
            .next()
            .is_some_and(|(_, window)| window.start_index <= index)
    }

    /// Whether a verified checkpoint withdraws `index`, which authorizes a
    /// stub there (§12.5.2 rule 3).
    pub fn is_withdrawn(&self, index: u32) -> bool {
        self.withdrawn.contains(&index)
    }

    /// The highest settled index.
    pub fn settled_through(&self) -> Option<u32> {
        self.windows.keys().next_back().copied()
    }

    fn joins(&self, heads: &WindowHeads, end_index: u32) -> bool {
        let zero = link_zero(&self.community_id, &self.pseudonym);
        if heads.start_index == 0 && heads.previous_signed_head != zero {
            return false;
        }
        let before = heads
            .start_index
            .checked_sub(1)
            .and_then(|end| self.windows.get(&end));
        if before.is_some_and(|w| w.current_head != heads.previous_signed_head) {
            return false;
        }
        let overlaps = self
            .windows
            .range(heads.start_index..)
            .next()
            .is_some_and(|(end, w)| *end != end_index && w.start_index <= end_index);
        if overlaps {
            return false;
        }
        let after = self
            .windows
            .range(end_index.saturating_add(1)..)
            .next()
            .filter(|(_, w)| Some(w.start_index) == end_index.checked_add(1));
        !after.is_some_and(|(_, w)| w.previous_signed_head != heads.current_head)
    }

    /// Verifies a checkpoint and its window (`COM-038`, `COM-212`, §12.4.4
    /// rule 6). The state changes only when each check passes.
    pub fn accept(
        &mut self,
        checkpoint: &Checkpoint<'_>,
        candidates: &[Vec<[u8; 32]>],
    ) -> Result<Settled, Error> {
        if checkpoint.pseudonym != self.pseudonym {
            return Err(Error::Unverified);
        }
        checkpoint.verify(&self.community_id)?;
        let heads = WindowHeads {
            start_index: checkpoint.start_index,
            previous_signed_head: checkpoint.previous_signed_head,
            current_head: checkpoint.current_head,
            withdrawn: checkpoint.withdrawn,
        };
        if let Some(held) = self.windows.get(&checkpoint.end_index) {
            return Ok(if *held == heads {
                Settled::Duplicate
            } else {
                Settled::Fork
            });
        }
        if !self.joins(&heads, checkpoint.end_index) {
            return Ok(Settled::Fork);
        }
        let chosen = resolve_window(checkpoint, candidates)?;
        self.windows.insert(checkpoint.end_index, heads);
        self.withdrawn.extend(checkpoint.withdrawn.indexes());
        Ok(Settled::Window(chosen))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        community::{test_util::author, NO_INDEX},
    };

    fn hashes_of(posts: &[Vec<u8>]) -> Vec<Vec<[u8; 32]>> {
        posts.iter().map(|p| alloc::vec![post_hash(p)]).collect()
    }

    #[test]
    fn the_cadence_follows_the_count_the_age_and_the_minimum_interval() {
        let identity = author(1);
        let mut chain = AuthorChain::new([9; 32], &identity.pseudonym());
        assert!(
            !chain.checkpoint_due(0),
            "a checkpoint covers one post at the least"
        );
        assert!(chain.checkpoint(&identity, 0, &mut Rng(1)).is_err());

        chain.append(&identity, NO_INDEX, b"one", 1_000).unwrap();
        assert!(!chain.checkpoint_due(1_000 + SIG_MAX_AGE - 1));
        assert!(chain.checkpoint_due(1_000 + SIG_MAX_AGE));

        for n in 0..4u64 {
            chain
                .append(&identity, NO_INDEX, b"more", 1_001 + n)
                .unwrap();
        }
        assert!(
            chain.checkpoint_due(1_010),
            "SIG_INTERVAL posts have no checkpoint"
        );
        let bytes = chain.checkpoint(&identity, 1_010, &mut Rng(2)).unwrap();
        let first = Checkpoint::parse(&bytes).unwrap();
        assert_eq!((first.start_index, first.end_index), (0, 4));

        for n in 0..7u64 {
            chain
                .append(&identity, NO_INDEX, b"burst", 1_020 + n)
                .unwrap();
        }
        assert!(
            !chain.checkpoint_due(1_030),
            "one checkpoint in SIG_MIN_INTERVAL"
        );
        let bytes = chain.checkpoint(&identity, 1_070, &mut Rng(3)).unwrap();
        let second = Checkpoint::parse(&bytes).unwrap();
        assert_eq!((second.start_index, second.end_index), (5, 9));
        assert_eq!(second.previous_signed_head, first.current_head);
        assert!(
            !chain.checkpoint_due(1_140),
            "two posts, young, and not SIG_INTERVAL"
        );
        assert!(chain.checkpoint_due(1_020 + 5 + SIG_MAX_AGE));

        assert!(AuthorChain::shares_the_checkpoint_cell(246));
        assert!(!AuthorChain::shares_the_checkpoint_cell(2_570));
    }

    #[test]
    fn a_withdrawal_rides_the_next_checkpoint_and_makes_none() {
        let identity = author(1);
        let mut chain = AuthorChain::new([9; 32], &identity.pseudonym());
        chain.append(&identity, NO_INDEX, b"regret", 0).unwrap();
        let first = chain
            .checkpoint(&identity, SIG_MAX_AGE, &mut Rng(1))
            .unwrap();
        assert!(Checkpoint::parse(&first)
            .unwrap()
            .withdrawn
            .indexes()
            .next()
            .is_none());

        chain.withdraw(0).unwrap();
        assert!(
            chain.withdraw(1).is_err(),
            "the index is outside the history"
        );
        assert!(chain.withdrawal_pending(0));
        assert!(
            !chain.checkpoint_due(u64::MAX),
            "a withdrawal is no cause of a checkpoint"
        );

        chain.append(&identity, NO_INDEX, b"next", 10_000).unwrap();
        let second = chain
            .checkpoint(&identity, 10_000 + SIG_MAX_AGE, &mut Rng(2))
            .unwrap();
        assert!(Checkpoint::parse(&second).unwrap().withdrawn.names(0));
        assert!(!chain.withdrawal_pending(0));
    }

    #[test]
    fn a_reader_recomputes_the_window_and_selects_between_two_bodies() {
        let identity = author(1);
        let community = [9; 32];
        let mut chain = AuthorChain::new(community, &identity.pseudonym());
        let posts: Vec<Vec<u8>> = (0..5u8)
            .map(|n| chain.append(&identity, NO_INDEX, &[n; 40], 0).unwrap())
            .collect();
        let bytes = chain.checkpoint(&identity, 1, &mut Rng(1)).unwrap();
        let checkpoint = Checkpoint::parse(&bytes).unwrap();

        let mut reader = ReaderChain::new(community, identity.pseudonym());
        let mut partial = hashes_of(&posts);
        partial[2].clear();
        assert_eq!(reader.accept(&checkpoint, &partial), Err(Error::NoPath));

        let mut replaced = hashes_of(&posts);
        replaced[1] = alloc::vec![[0xAA; 32]];
        assert_eq!(
            reader.accept(&checkpoint, &replaced),
            Err(Error::Unverified)
        );

        let mut reordered = hashes_of(&posts);
        reordered.swap(0, 1);
        assert_eq!(
            reader.accept(&checkpoint, &reordered),
            Err(Error::Unverified)
        );
        assert!(!reader.is_settled(0));

        // A second party put a body at index 3 first. The head admits the
        // body of the author, at position 1.
        let mut contested = hashes_of(&posts);
        contested[3].insert(0, [0xBB; 32]);
        assert_eq!(
            reader.accept(&checkpoint, &contested).unwrap(),
            Settled::Window(alloc::vec![0, 0, 0, 1, 0])
        );
        assert!(reader.is_settled(0) && reader.is_settled(4) && !reader.is_settled(5));
        assert_eq!(
            reader.accept(&checkpoint, &contested).unwrap(),
            Settled::Duplicate
        );
        assert_eq!(reader.settled_through(), Some(4));
    }

    #[test]
    fn two_checkpoints_at_one_triple_are_a_fork_of_the_pseudonym() {
        let identity = author(1);
        let community = [9; 32];
        let mut honest = AuthorChain::new(community, &identity.pseudonym());
        let mut second_device = honest.clone();
        let post_a = honest.append(&identity, NO_INDEX, b"a", 0).unwrap();
        let post_b = second_device.append(&identity, NO_INDEX, b"b", 0).unwrap();
        let cp_a = honest
            .checkpoint(&identity, SIG_MAX_AGE, &mut Rng(1))
            .unwrap();
        let cp_b = second_device
            .checkpoint(&identity, SIG_MAX_AGE, &mut Rng(2))
            .unwrap();

        let mut reader = ReaderChain::new(community, identity.pseudonym());
        let settled = reader
            .accept(&Checkpoint::parse(&cp_a).unwrap(), &hashes_of(&[post_a]))
            .unwrap();
        assert_eq!(settled, Settled::Window(alloc::vec![0]));
        let forked = reader
            .accept(&Checkpoint::parse(&cp_b).unwrap(), &hashes_of(&[post_b]))
            .unwrap();
        assert_eq!(forked, Settled::Fork);

        // A checkpoint of another pseudonym does not enter this chain.
        let other = author(2);
        let mut other_chain = AuthorChain::new(community, &other.pseudonym());
        let post = other_chain.append(&other, NO_INDEX, b"c", 0).unwrap();
        let cp = other_chain
            .checkpoint(&other, SIG_MAX_AGE, &mut Rng(3))
            .unwrap();
        assert!(reader
            .accept(&Checkpoint::parse(&cp).unwrap(), &hashes_of(&[post]))
            .is_err());
    }
}
