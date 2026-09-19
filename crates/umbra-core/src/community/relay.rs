//! The cache of one community at one relay (Part 12 §12.3.3, §12.4.4,
//! §12.4.6, §12.5.2): the acceptance of a `PUB`, the relay sequence, the
//! two bodies of a pending triple, the stub in the place of a body that an
//! artifact names, the pages of the four selectors, the rates, and the
//! retention with the chain floor.
//!
//! The cache holds no subscriber list, and a pull changes no state
//! (§12.3.1). The digest registrations of §12.6.4 live in
//! [`crate::notify::digest`], and they meet this type nowhere (`COM-373`).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_crypto::{rand_core::TryCryptoRng, sign::SigningKey};
use umbra_queue::Reject;

use super::{
    authority::{ControlChain, Outcome},
    chain::resolve_window,
    control::{ControlBody, ControlObject},
    meta::{CommunityMeta, MetaChain},
    pull::{
        PullEntry, PullRequest, PullResponse, Selector, NEWEST, PAGE_ENTRY_OVERHEAD,
        PAGE_HEADER_LEN, PAGE_MAX,
    },
    record::{post_hash, Checkpoint, CommunityPost, OperatorRemoval, PostStub},
    social::{classify, PostClass},
    RecordType, COMMUNITY_RETENTION, CONTROL_RATE_WINDOW, MOD_EPOCH_COMMUNITY_RATE,
    POST_RATE_LIMIT, POST_RATE_WINDOW, REACT_RATE_LIMIT, REPOST_RATE_LIMIT,
};

/// The answer to an accepted `PUB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Published {
    /// The `seq` of the record, for the `PUBACK` (`COM-202`, `COM-203`).
    pub seq: u64,
    /// A post that the cache did not hold arrived, thus the digest gate of
    /// Part 8 §8.5.1 counts it (`COM-371`).
    pub fresh_post: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RateClass {
    Post,
    Reaction,
    Repost,
    Checkpoint,
    Metadata,
}

impl RateClass {
    fn limit(self) -> usize {
        (match self {
            RateClass::Reaction => REACT_RATE_LIMIT,
            RateClass::Repost => REPOST_RATE_LIMIT,
            RateClass::Post | RateClass::Checkpoint | RateClass::Metadata => POST_RATE_LIMIT,
        }) as usize
    }
}

struct Body {
    hash: [u8; 32],
    seq: u64,
    bytes: Vec<u8>,
    accepted_at: u64,
    /// The seq and the encoding of the `OperatorRemoval` of this body.
    operator_removal: Option<(u64, Vec<u8>)>,
}

struct Window {
    seq: u64,
    bytes: Vec<u8>,
    start_index: u32,
    accepted_at: u64,
    /// The recomputation admitted one body at each index (`COM-216`).
    resolved: bool,
}

#[derive(Default)]
struct AuthorStore {
    floor: u32,
    posts: BTreeMap<u32, Vec<Body>>,
    /// The checkpoints by `end_index`.
    windows: BTreeMap<u32, Window>,
    withdrawn: BTreeSet<u32>,
}

impl AuthorStore {
    fn window_over(&self, index: u32) -> Option<(u32, &Window)> {
        self.windows
            .range(index..)
            .next()
            .filter(|(_, window)| window.start_index <= index)
            .map(|(end, window)| (*end, window))
    }
}

enum SeqEntry {
    /// A control object, a metadata record, or an operator removal.
    Fixed(Vec<u8>),
    Post {
        pseudonym: [u8; 32],
        index: u32,
        hash: [u8; 32],
    },
    Checkpoint {
        pseudonym: [u8; 32],
        end_index: u32,
    },
}

/// The cache of one community.
pub struct CommunityCache {
    community_id: [u8; 32],
    control: ControlChain,
    meta: MetaChain,
    next_seq: u64,
    by_seq: BTreeMap<u64, SeqEntry>,
    fixed_seq: BTreeMap<[u8; 32], u64>,
    authors: BTreeMap<[u8; 32], AuthorStore>,
    rates: BTreeMap<([u8; 32], RateClass), Vec<u64>>,
    moderation_times: Vec<([u8; 32], u64)>,
    roster_time: Option<u64>,
    stored_bytes: usize,
    capacity_bytes: usize,
}

impl CommunityCache {
    /// An empty cache that holds `capacity_bytes` of post records at the
    /// most.
    pub fn new(community_id: [u8; 32], capacity_bytes: usize) -> Self {
        CommunityCache {
            community_id,
            control: ControlChain::new(community_id),
            meta: MetaChain::new(community_id),
            next_seq: 1,
            by_seq: BTreeMap::new(),
            fixed_seq: BTreeMap::new(),
            authors: BTreeMap::new(),
            rates: BTreeMap::new(),
            moderation_times: Vec::new(),
            roster_time: None,
            stored_bytes: 0,
            capacity_bytes,
        }
    }

    /// The control chain that the cache verified.
    pub fn control(&self) -> &ControlChain {
        &self.control
    }

    /// Whether the store is full, thus the relay signals a capacity fault
    /// to the directory (`COM-236`).
    pub fn is_full(&self) -> bool {
        self.stored_bytes >= self.capacity_bytes
    }

    fn take_seq(&mut self) -> Result<u64, Reject> {
        let seq = self.next_seq;
        self.next_seq = seq.checked_add(1).ok_or(Reject::Busy)?;
        Ok(seq)
    }

    /// Counts one record of `class` for `key`. Above the limit, the proof
    /// of work of Part 14 §14.8 is the valve (`COM-148`, `COM-150`).
    fn check_rate(
        &mut self,
        key: [u8; 32],
        class: RateClass,
        admitted: bool,
        now: u64,
    ) -> Result<(), Reject> {
        let times = self.rates.entry((key, class)).or_default();
        times.retain(|at| now.saturating_sub(*at) < POST_RATE_WINDOW);
        if times.len() >= class.limit() && !admitted {
            return Err(Reject::Admission);
        }
        Ok(())
    }

    fn note_rate(&mut self, key: [u8; 32], class: RateClass, now: u64) {
        self.rates.entry((key, class)).or_default().push(now);
    }

    /// Accepts the record of a `PUB`. `admitted` is the verdict of the
    /// Part 14 gate on the `Admission` at the end of the payload: a token
    /// or a proof of work verified.
    pub fn publish(
        &mut self,
        record: &[u8],
        admitted: bool,
        now: u64,
    ) -> Result<Published, Reject> {
        let record_type = RecordType::of(record).map_err(|_| Reject::Rejected)?;
        // COM-206: the genesis roster comes first.
        let is_roster = record_type == RecordType::Roster;
        if !self.control.has_genesis() && !is_roster {
            return Err(Reject::Rejected);
        }
        match record_type {
            RecordType::Post => self.publish_post(record, admitted, now),
            RecordType::Checkpoint => self.publish_checkpoint(record, admitted, now),
            RecordType::Roster | RecordType::ModeratorSet | RecordType::ModerationEpoch => {
                self.publish_control(record, admitted, now)
            }
            RecordType::Meta => self.publish_meta(record, admitted, now),
            // COM-197, COM-198: a relay makes each stub and each operator
            // removal itself, and a report travels to a report queue.
            RecordType::Stub | RecordType::Report | RecordType::OperatorRemoval => {
                Err(Reject::Rejected)
            }
        }
    }

    fn publish_control(
        &mut self,
        record: &[u8],
        admitted: bool,
        now: u64,
    ) -> Result<Published, Reject> {
        let object = ControlObject::parse(record).map_err(|_| Reject::Rejected)?;
        // COM-199.
        if object.community_id != self.community_id {
            return Err(Reject::Rejected);
        }
        let hash = object.hash().map_err(|_| Reject::Rejected)?;
        if let Some(seq) = self.fixed_seq.get(&hash) {
            return Ok(Published {
                seq: *seq,
                fresh_post: false,
            });
        }
        // COM-205.
        if object.epoch_index == 0 && !admitted {
            return Err(Reject::Admission);
        }
        let is_moderation = matches!(object.body, ControlBody::Moderation { .. });
        let recent = |at: u64| now.saturating_sub(at) < CONTROL_RATE_WINDOW;
        if is_moderation {
            // COM-310, COM-311.
            self.moderation_times.retain(|(_, at)| recent(*at));
            let by_actor = self
                .moderation_times
                .iter()
                .any(|(actor, _)| *actor == object.actor);
            if by_actor || self.moderation_times.len() >= MOD_EPOCH_COMMUNITY_RATE {
                return Err(Reject::Limit);
            }
        } else if self.roster_time.is_some_and(recent) {
            // COM-312.
            return Err(Reject::Limit);
        }

        let actor = object.actor;
        match self.control.apply(object, now) {
            Ok(Outcome::Selected | Outcome::ActionsApplied) => {}
            _ => return Err(Reject::Rejected),
        }
        if is_moderation {
            self.moderation_times.push((actor, now));
        } else {
            self.roster_time = Some(now);
        }
        let seq = self.store_fixed(hash, record)?;
        // A successor that won the selection displaced objects, and the
        // cache serves the selected chain only.
        let displaced: Vec<[u8; 32]> = self
            .fixed_seq
            .keys()
            .filter(|held| !self.control.holds(held) && !self.meta.holds(held))
            .copied()
            .collect();
        for gone in displaced {
            if let Some(seq) = self.fixed_seq.remove(&gone) {
                self.by_seq.remove(&seq);
            }
        }
        Ok(Published {
            seq,
            fresh_post: false,
        })
    }

    fn store_fixed(&mut self, hash: [u8; 32], record: &[u8]) -> Result<u64, Reject> {
        let seq = self.take_seq()?;
        self.by_seq.insert(seq, SeqEntry::Fixed(record.to_vec()));
        self.fixed_seq.insert(hash, seq);
        Ok(seq)
    }

    fn publish_meta(
        &mut self,
        record: &[u8],
        admitted: bool,
        now: u64,
    ) -> Result<Published, Reject> {
        let meta = CommunityMeta::parse(record).map_err(|_| Reject::Rejected)?;
        if meta.community_id != self.community_id {
            return Err(Reject::Rejected);
        }
        let hash = meta.hash().map_err(|_| Reject::Rejected)?;
        if let Some(seq) = self.fixed_seq.get(&hash) {
            return Ok(Published {
                seq: *seq,
                fresh_post: false,
            });
        }
        let actor = meta.actor;
        // COM-211.
        self.check_rate(actor, RateClass::Metadata, admitted, now)?;
        let held_above: Vec<[u8; 32]> = self
            .meta
            .records_from(meta.meta_index)
            .filter_map(|held| held.hash().ok())
            .collect();
        match self.meta.apply(meta, self.control.authority()) {
            Ok(Outcome::Selected) => {}
            _ => return Err(Reject::Rejected),
        }
        self.note_rate(actor, RateClass::Metadata, now);
        for gone in held_above.iter().filter(|hash| !self.meta.holds(hash)) {
            if let Some(seq) = self.fixed_seq.remove(gone) {
                self.by_seq.remove(&seq);
            }
        }
        let seq = self.store_fixed(hash, record)?;
        Ok(Published {
            seq,
            fresh_post: false,
        })
    }

    fn publish_checkpoint(
        &mut self,
        record: &[u8],
        admitted: bool,
        now: u64,
    ) -> Result<Published, Reject> {
        let checkpoint = Checkpoint::parse(record).map_err(|_| Reject::Rejected)?;
        let pseudonym = checkpoint.pseudonym;
        // COM-298.
        if self.control.moderation().is_banned(&pseudonym) {
            return Err(Reject::Rejected);
        }
        let floor = self.authors.get(&pseudonym).map_or(0, |a| a.floor);
        // COM-229.
        if checkpoint.start_index < floor {
            return Err(Reject::Rejected);
        }
        if let Some(author) = self.authors.get(&pseudonym) {
            if let Some(held) = author.windows.get(&checkpoint.end_index) {
                let same =
                    Checkpoint::parse(&held.bytes).is_ok_and(|h| h.fields() == checkpoint.fields());
                return if same {
                    Ok(Published {
                        seq: held.seq,
                        fresh_post: false,
                    })
                } else {
                    Err(Reject::Rejected)
                };
            }
            let overlaps = author
                .window_over(checkpoint.start_index)
                .or_else(|| author.window_over(checkpoint.end_index))
                .is_some();
            if overlaps {
                return Err(Reject::Rejected);
            }
        }
        // COM-208, COM-210.
        checkpoint
            .verify(&self.community_id)
            .map_err(|_| Reject::Rejected)?;
        self.check_rate(pseudonym, RateClass::Checkpoint, admitted, now)?;
        self.note_rate(pseudonym, RateClass::Checkpoint, now);

        let seq = self.take_seq()?;
        let end_index = checkpoint.end_index;
        let author = self.authors.entry(pseudonym).or_default();
        author.withdrawn.extend(checkpoint.withdrawn.indexes());
        author.windows.insert(
            end_index,
            Window {
                seq,
                bytes: record.to_vec(),
                start_index: checkpoint.start_index,
                accepted_at: now,
                resolved: false,
            },
        );
        self.by_seq.insert(
            seq,
            SeqEntry::Checkpoint {
                pseudonym,
                end_index,
            },
        );
        self.resolve(&pseudonym, end_index);
        Ok(Published {
            seq,
            fresh_post: false,
        })
    }

    /// The body that the head of the window at `end_index` admits at each
    /// index, when the cache holds a body at each index of that window.
    /// `offer` is a body that is not stored yet, and it stands alone at
    /// its index.
    fn resolution(
        &self,
        pseudonym: &[u8; 32],
        end_index: u32,
        offer: Option<(u32, [u8; 32])>,
    ) -> Option<Vec<(u32, [u8; 32])>> {
        let author = self.authors.get(pseudonym)?;
        let window = author.windows.get(&end_index)?;
        let checkpoint = Checkpoint::parse(&window.bytes).ok()?;
        let indexes = checkpoint.start_index..=end_index;
        let candidates: Vec<Vec<[u8; 32]>> = indexes
            .clone()
            .map(|index| match offer {
                Some((at, hash)) if at == index => alloc::vec![hash],
                _ => author
                    .posts
                    .get(&index)
                    .map(|bodies| bodies.iter().map(|b| b.hash).collect())
                    .unwrap_or_default(),
            })
            .collect();
        let chosen = resolve_window(&checkpoint, &candidates).ok()?;
        indexes
            .zip(&candidates)
            .zip(chosen)
            .map(|((index, hashes), pick)| hashes.get(pick).map(|hash| (index, *hash)))
            .collect()
    }

    /// Keeps the admitted body at each index of a window and drops each
    /// other one (`COM-216`, `COM-217`).
    fn resolve(&mut self, pseudonym: &[u8; 32], end_index: u32) {
        let Some(admitted) = self.resolution(pseudonym, end_index, None) else {
            return;
        };
        let Some(author) = self.authors.get_mut(pseudonym) else {
            return;
        };
        let mut dropped = Vec::new();
        for (index, hash) in admitted {
            if let Some(bodies) = author.posts.get_mut(&index) {
                bodies.retain(|body| {
                    let keep = body.hash == hash;
                    if !keep {
                        dropped.push((body.seq, body.bytes.len()));
                    }
                    keep
                });
            }
        }
        if let Some(window) = author.windows.get_mut(&end_index) {
            window.resolved = true;
        }
        for (seq, len) in dropped {
            self.by_seq.remove(&seq);
            self.stored_bytes = self.stored_bytes.saturating_sub(len);
        }
    }

    fn publish_post(
        &mut self,
        record: &[u8],
        admitted: bool,
        now: u64,
    ) -> Result<Published, Reject> {
        let post = CommunityPost::parse(record).map_err(|_| Reject::Rejected)?;
        let pseudonym = post.pseudonym;
        let index = post.index;
        let hash = post_hash(record);

        let (floor, held, slots, window) = match self.authors.get(&pseudonym) {
            Some(author) => {
                let bodies = author.posts.get(&index);
                (
                    author.floor,
                    bodies
                        .and_then(|b| b.iter().find(|body| body.hash == hash).map(|body| body.seq)),
                    bodies.map_or(0, Vec::len),
                    author.window_over(index).map(|(end, w)| (end, w.resolved)),
                )
            }
            None => (0, None, 0, None),
        };
        if let Some(seq) = held {
            return Ok(Published {
                seq,
                fresh_post: false,
            });
        }
        let moderation = self.control.moderation();
        // COM-228, COM-298, COM-304, COM-218.
        if index < floor
            || moderation.is_banned(&pseudonym)
            || moderation.lock_at(now).is_some()
            || window.is_some_and(|(_, resolved)| resolved)
        {
            return Err(Reject::Rejected);
        }
        let class = classify(post.body).map_err(|_| Reject::Rejected)?;
        let current_meta = self.meta.current();
        // COM-330, COM-331.
        let forbidden = match class {
            PostClass::Reaction => current_meta.is_some_and(CommunityMeta::reactions_off),
            PostClass::Repost => current_meta.is_some_and(CommunityMeta::reposts_off),
            PostClass::Post => false,
        };
        if forbidden {
            return Err(Reject::Rejected);
        }
        // COM-214: a third body enters only when a held head admits it.
        let replaces = slots >= 2;
        if replaces {
            let admits = window.is_some_and(|(end, _)| {
                self.resolution(&pseudonym, end, Some((index, hash)))
                    .is_some()
            });
            if !admits {
                return Err(Reject::Rejected);
            }
        }
        // COM-235.
        if self.stored_bytes.saturating_add(record.len()) > self.capacity_bytes {
            return Err(Reject::Busy);
        }
        let rate_class = match class {
            PostClass::Post => RateClass::Post,
            PostClass::Reaction => RateClass::Reaction,
            PostClass::Repost => RateClass::Repost,
        };
        self.check_rate(pseudonym, rate_class, admitted, now)?;
        self.note_rate(pseudonym, rate_class, now);

        let seq = self.take_seq()?;
        let author = self.authors.entry(pseudonym).or_default();
        let bodies = author.posts.entry(index).or_default();
        if replaces {
            for body in bodies.drain(..) {
                self.by_seq.remove(&body.seq);
                self.stored_bytes = self.stored_bytes.saturating_sub(body.bytes.len());
            }
        }
        bodies.push(Body {
            hash,
            seq,
            bytes: record.to_vec(),
            accepted_at: now,
            operator_removal: None,
        });
        self.stored_bytes = self.stored_bytes.saturating_add(record.len());
        self.by_seq.insert(
            seq,
            SeqEntry::Post {
                pseudonym,
                index,
                hash,
            },
        );
        if let Some((end, _)) = window {
            self.resolve(&pseudonym, end);
        }
        Ok(Published {
            seq,
            fresh_post: true,
        })
    }

    /// Removes one body under a legal order, and signs the artifact that
    /// authorizes the stub at this relay (`COM-357`, `COM-358`).
    pub fn remove_under_order<R: TryCryptoRng + ?Sized>(
        &mut self,
        relay_key: &SigningKey,
        relay_id: [u8; 32],
        pseudonym: &[u8; 32],
        index: u32,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Reject> {
        let seq = self.take_seq()?;
        let community_id = self.community_id;
        let body = self
            .authors
            .get_mut(pseudonym)
            .and_then(|author| author.posts.get_mut(&index))
            .and_then(|bodies| bodies.first_mut())
            .ok_or(Reject::Rejected)?;
        let stub = PostStub {
            pseudonym: *pseudonym,
            index,
            post_hash: body.hash,
        };
        let removal = OperatorRemoval::sign(relay_key, community_id, &stub, relay_id, now, rng)
            .map_err(|_| Reject::Busy)?;
        body.operator_removal = Some((seq, removal.clone()));
        self.by_seq.insert(seq, SeqEntry::Fixed(removal));
        Ok(())
    }

    /// The record that the cache serves for one body: the body, or the
    /// stub when an artifact names the index (`COM-082`, `COM-083`,
    /// `COM-085`, `COM-097`, `COM-297`, `COM-352`).
    fn served(
        &self,
        author: &AuthorStore,
        pseudonym: &[u8; 32],
        index: u32,
        body: &Body,
    ) -> Vec<u8> {
        let stubbed = body.operator_removal.is_some()
            || author.withdrawn.contains(&index)
            || self.control.moderation().is_removed(pseudonym, index);
        if !stubbed {
            return body.bytes.clone();
        }
        PostStub {
            pseudonym: *pseudonym,
            index,
            post_hash: body.hash,
        }
        .encode()
        .unwrap_or_default()
    }

    fn materialize(&self, entry: &SeqEntry) -> Option<Vec<u8>> {
        match entry {
            SeqEntry::Fixed(bytes) => Some(bytes.clone()),
            SeqEntry::Post {
                pseudonym,
                index,
                hash,
            } => {
                let author = self.authors.get(pseudonym)?;
                let body = author.posts.get(index)?.iter().find(|b| b.hash == *hash)?;
                Some(self.served(author, pseudonym, *index, body))
            }
            SeqEntry::Checkpoint {
                pseudonym,
                end_index,
            } => Some(
                self.authors
                    .get(pseudonym)?
                    .windows
                    .get(end_index)?
                    .bytes
                    .clone(),
            ),
        }
    }

    /// Answers a `PULL` with an encoded `PAGE`. The call reads the cache
    /// and changes nothing, thus it leaves no trace of the reader.
    pub fn pull(&self, request: &PullRequest) -> Result<Vec<u8>, Reject> {
        if request.community_id != self.community_id {
            return Err(Reject::Rejected);
        }
        let mut page = Page::new(usize::from(request.count));
        let (floor, next) = match request.selector {
            Selector::Sequence => self.page_by_seq(request.from, &mut page),
            Selector::Chain => self.page_by_chain(&request.pseudonym, request.from, &mut page),
            Selector::Control => {
                let from = u32::try_from(request.from).unwrap_or(u32::MAX);
                let mut objects: Vec<&ControlObject> = self.control.objects_from(from).collect();
                objects.sort_by_key(|object| object.epoch_index);
                let mut next = request.from;
                for object in objects {
                    let (Ok(bytes), Ok(hash)) = (object.encode(), object.hash()) else {
                        continue;
                    };
                    let seq = self.fixed_seq.get(&hash).copied().unwrap_or(0);
                    if !page.push(seq, bytes) {
                        break;
                    }
                    next = u64::from(object.epoch_index).saturating_add(1);
                }
                (0, next)
            }
            Selector::Meta => {
                let from = u32::try_from(request.from).unwrap_or(u32::MAX);
                let mut next = request.from;
                for meta in self.meta.records_from(from) {
                    let (Ok(bytes), Ok(hash)) = (meta.encode(), meta.hash()) else {
                        continue;
                    };
                    let seq = self.fixed_seq.get(&hash).copied().unwrap_or(0);
                    if !page.push(seq, bytes) {
                        break;
                    }
                    next = u64::from(meta.meta_index).saturating_add(1);
                }
                (0, next)
            }
        };
        let response = PullResponse {
            community_id: self.community_id,
            selector: request.selector,
            floor,
            next,
            entries: page
                .entries
                .iter()
                .map(|(seq, record)| PullEntry { seq: *seq, record })
                .collect(),
        };
        response.encode().map_err(|_| Reject::Busy)
    }

    fn page_by_seq(&self, from: u64, page: &mut Page) -> (u64, u64) {
        // COM-183.
        let floor = self.by_seq.keys().next().copied().unwrap_or(0);
        if from == NEWEST {
            for (seq, entry) in self.by_seq.iter().rev() {
                let Some(record) = self.materialize(entry) else {
                    continue;
                };
                if !page.push(*seq, record) {
                    break;
                }
            }
            page.entries.reverse();
            // COM-187: 0 under the sentinel when the page is empty.
            let next = page
                .entries
                .last()
                .map_or(0, |(seq, _)| seq.saturating_add(1));
            return (floor, next);
        }
        let mut next = from;
        for (seq, entry) in self.by_seq.range(from..) {
            let Some(record) = self.materialize(entry) else {
                continue;
            };
            if !page.push(*seq, record) {
                break;
            }
            next = seq.saturating_add(1);
        }
        (floor, next)
    }

    fn page_by_chain(&self, pseudonym: &[u8; 32], from: u64, page: &mut Page) -> (u64, u64) {
        let Some(author) = self.authors.get(pseudonym) else {
            return (0, from);
        };
        // COM-184.
        let floor = u64::from(author.floor);
        let from_index = u32::try_from(from).unwrap_or(u32::MAX);
        let mut next = from;
        for (index, bodies) in author.posts.range(from_index..) {
            // The records of one index travel as one unit, with the
            // checkpoint behind the last index of its window.
            let mut unit: Vec<(u64, Vec<u8>)> = Vec::new();
            for body in bodies {
                unit.push((body.seq, self.served(author, pseudonym, *index, body)));
                if let Some((seq, removal)) = &body.operator_removal {
                    unit.push((*seq, removal.clone()));
                }
            }
            if let Some(window) = author.windows.get(index) {
                unit.push((window.seq, window.bytes.clone()));
            }
            if !page.push_unit(unit) {
                break;
            }
            next = u64::from(*index).saturating_add(1);
        }
        (floor, next)
    }

    /// Prunes each record past `COMMUNITY_RETENTION`, a window as one unit
    /// and the lowest index first, and drops each rate counter past its
    /// window (`COM-151`, `COM-225` to `COM-227`).
    pub fn sweep(&mut self, now: u64) {
        let aged = |accepted_at: u64| now.saturating_sub(accepted_at) >= COMMUNITY_RETENTION;
        for author in self.authors.values_mut() {
            loop {
                let lowest_post = author.posts.keys().next().copied();
                let lowest_window = author
                    .windows
                    .iter()
                    .map(|(end, window)| (window.start_index, *end))
                    .min();
                let unit = match (lowest_post, lowest_window) {
                    (Some(post), Some((start, end))) if start <= post => (start, end, true),
                    (Some(post), _) => (post, post, false),
                    (None, Some((start, end))) => (start, end, true),
                    (None, None) => break,
                };
                let (start, end, has_window) = unit;
                let window_aged = !has_window
                    || author
                        .windows
                        .get(&end)
                        .is_some_and(|w| aged(w.accepted_at));
                let posts_aged = author
                    .posts
                    .range(start..=end)
                    .all(|(_, bodies)| bodies.iter().all(|body| aged(body.accepted_at)));
                if !(window_aged && posts_aged) {
                    break;
                }
                if let Some(window) = author.windows.remove(&end).filter(|_| has_window) {
                    self.by_seq.remove(&window.seq);
                }
                let indexes: Vec<u32> = author.posts.range(start..=end).map(|(i, _)| *i).collect();
                for index in indexes {
                    for body in author.posts.remove(&index).unwrap_or_default() {
                        self.by_seq.remove(&body.seq);
                        if let Some((seq, _)) = body.operator_removal {
                            self.by_seq.remove(&seq);
                        }
                        self.stored_bytes = self.stored_bytes.saturating_sub(body.bytes.len());
                    }
                }
                author.floor = author.floor.max(end.saturating_add(1));
            }
        }
        self.rates.retain(|_, times| {
            times.retain(|at| now.saturating_sub(*at) < POST_RATE_WINDOW);
            !times.is_empty()
        });
    }
}

/// The entries of one page under the two bounds of `COM-182`.
struct Page {
    entries: Vec<(u64, Vec<u8>)>,
    count_max: usize,
    len: usize,
}

impl Page {
    fn new(count_max: usize) -> Self {
        Page {
            entries: Vec::new(),
            count_max,
            len: PAGE_HEADER_LEN,
        }
    }

    fn push(&mut self, seq: u64, record: Vec<u8>) -> bool {
        self.push_unit(alloc::vec![(seq, record)])
    }

    fn push_unit(&mut self, unit: Vec<(u64, Vec<u8>)>) -> bool {
        let unit_len: usize = unit
            .iter()
            .map(|(_, record)| PAGE_ENTRY_OVERHEAD.saturating_add(record.len()))
            .sum();
        let fits = self.entries.len().saturating_add(unit.len()) <= self.count_max
            && self.len.saturating_add(unit_len) <= PAGE_MAX;
        if fits {
            self.len = self.len.saturating_add(unit_len);
            self.entries.extend(unit);
        }
        fits
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use umbra_crypto::secret::Secret;

    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        community::{
            authority::tests::{genesis_entries, moderation, sign, ADMIN, MODERATOR, OWNER_A},
            chain::AuthorChain,
            community_id,
            control::{ActionKind, Role},
            identity::AuthorIdentity,
            social::{reaction_body, text_body, PostRef},
            test_util::{author, role},
            ADMISSION_OPEN, NO_INDEX, PULL_BATCH, SIG_MAX_AGE,
        },
    };

    const CAPACITY: usize = 1 << 20;

    /// A cache with the genesis roster and one moderator.
    fn cache() -> ([u8; 32], CommunityCache) {
        let owner = role(OWNER_A);
        let id = community_id(ADMISSION_OPEN, owner.public_key()).unwrap();
        let mut cache = CommunityCache::new(id, CAPACITY);
        let roster = sign(
            &owner,
            id,
            (0, [0; 32]),
            ControlBody::Roster {
                entries: genesis_entries(),
                cosigns: Vec::new(),
            },
        );
        let bytes = roster.encode().unwrap();
        assert_eq!(cache.publish(&bytes, false, 0), Err(Reject::Admission));
        assert_eq!(cache.publish(&bytes, true, 0).unwrap().seq, 1);
        let set = sign(
            &role(ADMIN),
            id,
            (1, roster.hash().unwrap()),
            ControlBody::ModeratorSet {
                moderators: alloc::vec![role(MODERATOR).pseudonym()],
            },
        );
        assert_eq!(
            cache.publish(&set.encode().unwrap(), false, 10),
            Err(Reject::Limit),
            "one roster object in each minute"
        );
        assert_eq!(
            cache
                .publish(&set.encode().unwrap(), false, 60)
                .unwrap()
                .seq,
            2
        );
        (id, cache)
    }

    fn text(id: &[u8; 32], words: &str) -> Vec<u8> {
        text_body(id, words, None, &[]).unwrap()
    }

    fn post(
        chain: &mut AuthorChain,
        identity: &AuthorIdentity,
        id: &[u8; 32],
        words: &str,
        now: u64,
    ) -> Vec<u8> {
        chain
            .append(identity, NO_INDEX, &text(id, words), now)
            .unwrap()
    }

    fn pull(cache: &CommunityCache, selector: Selector, pseudonym: [u8; 32], from: u64) -> Vec<u8> {
        cache
            .pull(&PullRequest {
                community_id: *cache.control().community_id(),
                selector,
                pseudonym,
                from,
                count: PULL_BATCH,
            })
            .unwrap()
    }

    fn types_of(page: &[u8]) -> Vec<RecordType> {
        PullResponse::parse(page)
            .unwrap()
            .entries
            .iter()
            .map(|entry| RecordType::of(entry.record).unwrap())
            .collect()
    }

    #[test]
    fn no_record_enters_before_the_genesis_roster() {
        let owner = role(OWNER_A);
        let id = community_id(ADMISSION_OPEN, owner.public_key()).unwrap();
        let mut cache = CommunityCache::new(id, CAPACITY);
        let identity = author(20);
        let mut chain = AuthorChain::new(id, &identity.pseudonym());
        let first = post(&mut chain, &identity, &id, "early", 0);
        assert_eq!(cache.publish(&first, true, 0), Err(Reject::Rejected));

        let (_, mut cache) = self::cache();
        let stub = PostStub {
            pseudonym: [1; 32],
            index: 0,
            post_hash: [2; 32],
        };
        assert_eq!(
            cache.publish(&stub.encode().unwrap(), true, 0),
            Err(Reject::Rejected)
        );
        let published = cache.publish(&first, false, 100).unwrap();
        assert!(published.fresh_post);
        assert_eq!(
            cache.publish(&first, false, 101).unwrap(),
            Published {
                seq: published.seq,
                fresh_post: false
            }
        );
    }

    #[test]
    fn a_window_travels_with_its_checkpoint_and_a_removal_gives_a_stub() {
        let (id, mut cache) = cache();
        let identity = author(20);
        let me = identity.pseudonym();
        let mut chain = AuthorChain::new(id, &me);
        for n in 0..5 {
            let bytes = post(&mut chain, &identity, &id, "post", 100 + n);
            cache.publish(&bytes, false, 100 + n).unwrap();
        }
        let checkpoint = chain.checkpoint(&identity, 200, &mut Rng(1)).unwrap();
        cache.publish(&checkpoint, false, 200).unwrap();

        let page = pull(&cache, Selector::Chain, me, 0);
        let mut expected = alloc::vec![RecordType::Post; 5];
        expected.push(RecordType::Checkpoint);
        assert_eq!(types_of(&page), expected);
        let parsed = PullResponse::parse(&page).unwrap();
        assert_eq!((parsed.floor, parsed.next), (0, 5));

        let removal = sign(
            &role(MODERATOR),
            id,
            (2, cache.control().head().unwrap().0),
            moderation(Role::Moderator, ActionKind::Remove, me, 2),
        );
        cache
            .publish(&removal.encode().unwrap(), false, 300)
            .unwrap();
        let page = pull(&cache, Selector::Chain, me, 0);
        expected[2] = RecordType::Stub;
        assert_eq!(types_of(&page), expected);

        // A restore serves the body again, because the cache kept it.
        let restore = sign(
            &role(ADMIN),
            id,
            (3, cache.control().head().unwrap().0),
            moderation(Role::Admin, ActionKind::Restore, me, 2),
        );
        cache
            .publish(&restore.encode().unwrap(), false, 400)
            .unwrap();
        expected[2] = RecordType::Post;
        assert_eq!(types_of(&pull(&cache, Selector::Chain, me, 0)), expected);

        let control = pull(&cache, Selector::Control, [0; 32], 1);
        assert_eq!(
            types_of(&control),
            [
                RecordType::ModeratorSet,
                RecordType::ModerationEpoch,
                RecordType::ModerationEpoch
            ]
        );
        let newest = PullResponse::parse(&pull(&cache, Selector::Sequence, [0; 32], NEWEST))
            .unwrap()
            .entries
            .len();
        assert_eq!(newest, 10);
    }

    #[test]
    fn a_second_body_waits_for_the_head_and_the_head_admits_a_third() {
        let (id, mut cache) = cache();
        let identity = author(20);
        let me = identity.pseudonym();
        let mut chain = AuthorChain::new(id, &me);
        let genuine = post(&mut chain, &identity, &id, "mine", 100);

        let forge = |words: &str| {
            CommunityPost {
                pseudonym: me,
                index: 0,
                amends: NO_INDEX,
                body: &text(&id, words),
            }
            .encode()
            .unwrap()
        };
        cache.publish(&forge("fake one"), false, 90).unwrap();
        cache.publish(&forge("fake two"), false, 91).unwrap();
        assert_eq!(
            cache.publish(&genuine, false, 100),
            Err(Reject::Rejected),
            "a third body"
        );
        assert_eq!(
            types_of(&pull(&cache, Selector::Chain, me, 0)).len(),
            2,
            "each pending body"
        );

        let checkpoint = chain
            .checkpoint(&identity, 100 + SIG_MAX_AGE, &mut Rng(1))
            .unwrap();
        cache
            .publish(&checkpoint, false, 100 + SIG_MAX_AGE)
            .unwrap();
        assert_eq!(
            cache.publish(&forge("fake three"), false, 4_000),
            Err(Reject::Rejected)
        );
        cache.publish(&genuine, false, 4_000).unwrap();

        let page = pull(&cache, Selector::Chain, me, 0);
        let parsed = PullResponse::parse(&page).unwrap();
        assert_eq!(types_of(&page), [RecordType::Post, RecordType::Checkpoint]);
        assert_eq!(parsed.entries[0].record, genuine.as_slice());
        assert_eq!(
            cache.publish(&forge("fake four"), false, 4_100),
            Err(Reject::Rejected)
        );
    }

    #[test]
    fn the_rates_the_dial_the_ban_and_the_lock_bound_a_pub() {
        let (id, mut cache) = cache();
        let identity = author(20);
        let me = identity.pseudonym();
        let mut chain = AuthorChain::new(id, &me);
        for n in 0..u64::from(POST_RATE_LIMIT) {
            let bytes = post(&mut chain, &identity, &id, "post", 100 + n);
            cache.publish(&bytes, false, 100 + n).unwrap();
        }
        let over = post(&mut chain, &identity, &id, "one more", 200);
        assert_eq!(cache.publish(&over, false, 200), Err(Reject::Admission));
        // A reaction has its own budget, and the proof of work is the valve.
        let target = PostRef {
            pseudonym: me,
            index: 0,
        };
        let reaction = chain
            .append(
                &identity,
                NO_INDEX,
                &reaction_body(
                    &id,
                    target,
                    umbra_wire::app::signal::ReactionAction::Add,
                    "👍",
                )
                .unwrap(),
                200,
            )
            .unwrap();
        cache.publish(&over, true, 200).unwrap();
        cache.publish(&reaction, false, 201).unwrap();
        let later = post(
            &mut chain,
            &identity,
            &id,
            "after the window",
            100 + POST_RATE_WINDOW,
        );
        cache.sweep(100 + POST_RATE_WINDOW + POST_RATE_LIMIT as u64);
        cache
            .publish(
                &later,
                false,
                100 + POST_RATE_WINDOW + POST_RATE_LIMIT as u64,
            )
            .unwrap();

        let head = |cache: &CommunityCache| {
            let (hash, index) = cache.control().head().unwrap();
            (index + 1, hash)
        };
        let lock = sign(
            &role(ADMIN),
            id,
            head(&cache),
            moderation(Role::Admin, ActionKind::Lock, [0; 32], 600),
        );
        cache
            .publish(&lock.encode().unwrap(), false, 10_000)
            .unwrap();
        let other = author(21);
        let mut other_chain = AuthorChain::new(id, &other.pseudonym());
        let locked = post(&mut other_chain, &other, &id, "locked out", 10_100);
        assert_eq!(cache.publish(&locked, false, 10_100), Err(Reject::Rejected));
        cache.publish(&locked, false, 10_600).unwrap();

        let ban = sign(
            &role(ADMIN),
            id,
            head(&cache),
            moderation(Role::Admin, ActionKind::Ban, other.pseudonym(), 0),
        );
        cache
            .publish(&ban.encode().unwrap(), false, 10_700)
            .unwrap();
        let banned = post(&mut other_chain, &other, &id, "banned", 10_800);
        assert_eq!(cache.publish(&banned, false, 10_800), Err(Reject::Rejected));
        assert_eq!(
            types_of(&pull(&cache, Selector::Chain, other.pseudonym(), 0)),
            [RecordType::Stub]
        );
    }

    #[test]
    fn the_owner_dial_turns_the_reactions_off() {
        use crate::community::meta::{Category, CommunityMetaBody, MetaDraft, FLAG_REACTIONS_OFF};

        let (id, mut cache) = cache();
        let body = CommunityMetaBody {
            category: Category::General,
            name: "Quiet".into(),
            text: alloc::string::String::new(),
            rules: alloc::string::String::new(),
            icon: Vec::new(),
        };
        let draft = MetaDraft {
            community_id: id,
            meta_index: 0,
            previous_meta: [0; 32],
            relays: alloc::vec![[1; 12], [2; 12], [3; 12]],
            flags: FLAG_REACTIONS_OFF,
            body: &body,
            nonce: [4; 12],
        };
        let meta =
            CommunityMeta::sign(&role(OWNER_A), &Secret::new([6; 32]), draft, &mut Rng(1)).unwrap();
        let bytes = meta.encode().unwrap();
        let seq = cache.publish(&bytes, false, 100).unwrap().seq;
        assert_eq!(cache.publish(&bytes, false, 101).unwrap().seq, seq);
        assert_eq!(
            types_of(&pull(&cache, Selector::Meta, [0; 32], 0)),
            [RecordType::Meta]
        );

        let identity = author(20);
        let mut chain = AuthorChain::new(id, &identity.pseudonym());
        let first = post(&mut chain, &identity, &id, "a post", 200);
        cache.publish(&first, false, 200).unwrap();
        let target = PostRef {
            pseudonym: identity.pseudonym(),
            index: 0,
        };
        let body = reaction_body(
            &id,
            target,
            umbra_wire::app::signal::ReactionAction::Add,
            "👍",
        )
        .unwrap();
        let reaction = chain.append(&identity, NO_INDEX, &body, 201).unwrap();
        assert_eq!(cache.publish(&reaction, false, 201), Err(Reject::Rejected));
    }

    #[test]
    fn a_prune_moves_the_chain_floor_and_never_back() {
        let (id, mut cache) = cache();
        let identity = author(20);
        let me = identity.pseudonym();
        let mut chain = AuthorChain::new(id, &me);
        let old: Vec<Vec<u8>> = (0..2)
            .map(|n| post(&mut chain, &identity, &id, "old", 100 + n))
            .collect();
        for bytes in &old {
            cache.publish(bytes, false, 100).unwrap();
        }
        let first = chain
            .checkpoint(&identity, 100 + SIG_MAX_AGE, &mut Rng(1))
            .unwrap();
        cache.publish(&first, false, 100 + SIG_MAX_AGE).unwrap();
        let recent_at = 100 + COMMUNITY_RETENTION;
        let recent = post(&mut chain, &identity, &id, "recent", recent_at);
        cache.publish(&recent, false, recent_at).unwrap();

        cache.sweep(recent_at);
        let page = PullResponse::parse(&pull(&cache, Selector::Chain, me, 0))
            .unwrap()
            .floor;
        assert_eq!(page, 0, "the checkpoint of the window is not aged yet");

        cache.sweep(recent_at + SIG_MAX_AGE);
        let page = pull(&cache, Selector::Chain, me, 0);
        let parsed = PullResponse::parse(&page).unwrap();
        assert_eq!((parsed.floor, parsed.next), (2, 3));
        assert_eq!(types_of(&page), [RecordType::Post]);
        assert_eq!(
            cache.publish(&old[0], false, recent_at + SIG_MAX_AGE),
            Err(Reject::Rejected)
        );
        assert_eq!(
            cache.publish(&first, false, recent_at + SIG_MAX_AGE),
            Err(Reject::Rejected)
        );
        // The control chain has no retention bound.
        assert_eq!(
            types_of(&pull(&cache, Selector::Control, [0; 32], 0)).len(),
            2
        );
    }

    #[test]
    fn an_operator_removal_travels_beside_its_stub() {
        let (id, mut cache) = cache();
        let identity = author(20);
        let me = identity.pseudonym();
        let mut chain = AuthorChain::new(id, &me);
        let bytes = post(&mut chain, &identity, &id, "ordered away", 100);
        cache.publish(&bytes, false, 100).unwrap();
        let relay_key = SigningKey::from_seed(Secret::new([5; 32]));
        cache
            .remove_under_order(&relay_key, [6; 32], &me, 0, 200, &mut Rng(1))
            .unwrap();
        let page = pull(&cache, Selector::Chain, me, 0);
        assert_eq!(
            types_of(&page),
            [RecordType::Stub, RecordType::OperatorRemoval]
        );
        let parsed = PullResponse::parse(&page).unwrap();
        let removal = OperatorRemoval::parse(parsed.entries[1].record).unwrap();
        removal
            .verify(
                parsed.entries[1].record,
                &id,
                &relay_key.verifying_key().to_bytes(),
            )
            .unwrap();
        assert_eq!(removal.post_hash, post_hash(&bytes));
        assert!(cache
            .remove_under_order(&relay_key, [6; 32], &me, 9, 200, &mut Rng(1))
            .is_err());
    }

    #[test]
    fn a_full_store_rejects_a_post_with_busy() {
        let owner = role(OWNER_A);
        let id = community_id(ADMISSION_OPEN, owner.public_key()).unwrap();
        let mut small = CommunityCache::new(id, 300);
        let roster = sign(
            &owner,
            id,
            (0, [0; 32]),
            ControlBody::Roster {
                entries: genesis_entries(),
                cosigns: Vec::new(),
            },
        );
        small.publish(&roster.encode().unwrap(), true, 0).unwrap();
        let identity = author(20);
        let mut chain = AuthorChain::new(id, &identity.pseudonym());
        small
            .publish(
                &post(&mut chain, &identity, &id, &"a".repeat(150), 1),
                false,
                1,
            )
            .unwrap();
        let second = post(&mut chain, &identity, &id, &"b".repeat(150), 2);
        assert_eq!(small.publish(&second, false, 2), Err(Reject::Busy));
        assert!(!small.is_full());
    }
}
