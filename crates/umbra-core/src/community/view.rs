//! What a reader shows of a community from the records it holds (Part 12
//! §12.4, §12.5, §12.7): the control chain and the metadata under it, and
//! each post with its state under the checkpoints of its chain.
//!
//! The view runs over each record that the device holds, in any order.
//! The relays serve the records of one community in an order of their
//! own (`COM-180`), thus the view sorts each chain before it applies it.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use umbra_crypto::secret::Secret;
use umbra_wire::app::{
    rich::{community_reply_id, RichRecord},
    signal::{ReactionAction, ReactionBody},
    AppKind, Channel,
};

use super::{
    authority::ControlChain,
    chain::{ReaderChain, Settled},
    control::ControlObject,
    meta::{CommunityMeta, MetaChain},
    record::{post_hash, Checkpoint, CommunityPost},
    RecordType,
};

/// What a post carries, from the `inner_kind` of its `RichRecord`
/// (§12.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostKind {
    /// A text, which can answer another post.
    Text,
    /// A reaction to another post (`COM-322`). The view tallies it, and it
    /// shows as no post of its own.
    Reaction,
    /// A repost (`COM-325`).
    Repost,
    /// Another kind, or a body that does not parse.
    Other,
}

/// The reactions of one emoji on one post (`COM-333`, `COM-334`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionCount {
    /// The emoji.
    pub emoji: String,
    /// Each pseudonym whose last reaction of this emoji adds it.
    pub by: Vec<[u8; 32]>,
}

/// One post as a reader shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostView {
    /// The hash of the post, which names it.
    pub hash: [u8; 32],
    /// The authoring pseudonym.
    pub pseudonym: [u8; 32],
    /// The position in the chain of that pseudonym.
    pub index: u32,
    /// Whether a verified checkpoint covers the post (§12.4.1).
    pub is_settled: bool,
    /// Whether a moderation epoch removes the post (§12.5.2).
    pub is_removed: bool,
    /// Whether the author withdrew the post in a checkpoint (`COM-094`).
    pub is_withdrawn: bool,
    /// Whether a ban stands on the author (`COM-298`).
    pub is_author_banned: bool,
    /// What the post carries.
    pub kind: PostKind,
    /// The `community_reply_id` of this post, which a reply and a reaction
    /// name (`COM-161`, `COM-323`).
    pub reply_id: [u8; 16],
    /// The `community_reply_id` that this post answers, if it answers one.
    pub reply_to: Option<[u8; 16]>,
    /// The reactions to this post, by emoji.
    pub reactions: Vec<ReactionCount>,
}

/// What a reader shows of a community.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommunityView {
    /// Whether the genesis roster verified (`COM-120`).
    pub has_genesis: bool,
    /// The name of the current metadata that verified under the roster,
    /// opened with the key of the link (`COM-243`).
    pub name: Option<String>,
    /// Each post that the view admits, by chain and index. A second body
    /// at a settled index that the checkpoint does not admit is not here
    /// (`COM-220`).
    pub posts: Vec<PostView>,
    /// Each pseudonym whose checkpoints fork (`COM-019`).
    pub forked: Vec<[u8; 32]>,
    /// The hash and the `epoch_index` of the head of the control chain,
    /// which the next control object names (`COM-377`, `COM-378`).
    pub control_head: Option<([u8; 32], u32)>,
    /// Each entry of the current roster: the role, the report key, and
    /// the report queue of each owner and admin (§12.5.3).
    pub roster: Vec<super::control::RosterEntry>,
    /// Whether the current metadata turns reactions off (`COM-330`).
    pub reactions_off: bool,
    /// Whether the current metadata turns reposts off (`COM-331`).
    pub reposts_off: bool,
}

/// The bodies at each index of one chain, with the hash of each post.
type Chain<'a> = BTreeMap<u32, Vec<([u8; 32], &'a [u8])>>;

/// One reaction slot: the target, the emoji, and the pseudonym.
type ReactionSlot = ([u8; 16], String, [u8; 32]);

/// The view of `community_id` from `records`. `now` is the clock of this
/// party, and a lock of a moderation epoch counts from it.
pub fn view(
    community_id: &[u8; 32],
    meta_key: &Secret<32>,
    records: &[&[u8]],
    now: u64,
) -> CommunityView {
    let mut control = Vec::new();
    let mut metas = Vec::new();
    let mut posts: BTreeMap<[u8; 32], Chain<'_>> = BTreeMap::new();
    let mut checkpoints: Vec<Checkpoint<'_>> = Vec::new();
    for record in records {
        match RecordType::of(record) {
            Ok(RecordType::Roster | RecordType::ModerationEpoch | RecordType::ModeratorSet) => {
                if let Ok(object) = ControlObject::parse(record) {
                    control.push(object);
                }
            }
            Ok(RecordType::Meta) => {
                if let Ok(meta) = CommunityMeta::parse(record) {
                    metas.push(meta);
                }
            }
            Ok(RecordType::Post) => {
                if let Ok(post) = CommunityPost::parse(record) {
                    let hashes = posts
                        .entry(post.pseudonym)
                        .or_default()
                        .entry(post.index)
                        .or_default();
                    let hash = post_hash(record);
                    if !hashes.iter().any(|(held, _)| *held == hash) {
                        hashes.push((hash, post.body));
                    }
                }
            }
            Ok(RecordType::Checkpoint) => {
                if let Ok(checkpoint) = Checkpoint::parse(record) {
                    checkpoints.push(checkpoint);
                }
            }
            _ => {}
        }
    }

    // COM-378: each object follows the one before it, thus the chain takes
    // them in order of their index.
    let mut chain = ControlChain::new(*community_id);
    control.sort_by_key(|object| object.epoch_index);
    for object in control {
        let _ = chain.apply(object, now);
    }
    let mut out = CommunityView {
        has_genesis: chain.has_genesis(),
        control_head: chain.head(),
        roster: chain.authority().roster().to_vec(),
        ..CommunityView::default()
    };
    if !out.has_genesis {
        return out;
    }
    let mut meta_chain = MetaChain::new(*community_id);
    metas.sort_by_key(|meta| meta.meta_index);
    for meta in metas {
        let _ = meta_chain.apply(meta, chain.authority());
    }
    out.name = meta_chain
        .current()
        .and_then(|meta| meta.open(meta_key).ok())
        .map(|body| body.name);
    if let Some(meta) = meta_chain.current() {
        out.reactions_off = meta.reactions_off();
        out.reposts_off = meta.reposts_off();
    }

    // Each checkpoint settles the window of its chain with the hashes that
    // the view holds at each index. A window with an index that has no
    // hash is partial and waits (`COM-086`).
    let mut readers: BTreeMap<[u8; 32], ReaderChain> = BTreeMap::new();
    let mut dropped: BTreeSet<[u8; 32]> = BTreeSet::new();
    checkpoints.sort_by_key(|checkpoint| (checkpoint.pseudonym, checkpoint.end_index));
    for checkpoint in &checkpoints {
        let Some(held) = posts.get(&checkpoint.pseudonym) else {
            continue;
        };
        let candidates: Option<Vec<Vec<[u8; 32]>>> = (checkpoint.start_index
            ..=checkpoint.end_index)
            .map(|index| {
                held.get(&index)
                    .map(|bodies| bodies.iter().map(|(hash, _)| *hash).collect())
            })
            .collect();
        let Some(candidates) = candidates else {
            continue;
        };
        let reader = readers
            .entry(checkpoint.pseudonym)
            .or_insert_with(|| ReaderChain::new(*community_id, checkpoint.pseudonym));
        match reader.accept(checkpoint, &candidates) {
            // COM-220: the body that the window admits stays, and each
            // other body at that index goes.
            Ok(Settled::Window(chosen)) => {
                for (hashes, position) in candidates.iter().zip(chosen) {
                    for (at, hash) in hashes.iter().enumerate() {
                        if at != position {
                            dropped.insert(*hash);
                        }
                    }
                }
            }
            Ok(Settled::Fork) => {
                if !out.forked.contains(&checkpoint.pseudonym) {
                    out.forked.push(checkpoint.pseudonym);
                }
            }
            Ok(Settled::Duplicate) | Err(_) => {}
        }
    }

    let moderation = chain.moderation();
    // COM-334: one pseudonym counts one time for each target and emoji,
    // and the record of its highest index decides.
    let mut last: BTreeMap<ReactionSlot, (u32, bool)> = BTreeMap::new();
    for (pseudonym, indexes) in &posts {
        let reader = readers.get(pseudonym);
        for (index, bodies) in indexes {
            for (hash, body) in bodies {
                if dropped.contains(hash) {
                    continue;
                }
                let is_removed = moderation.is_removed(pseudonym, *index);
                let rich = RichRecord::parse(body, Channel::Community).ok();
                let kind = match rich.as_ref().map(|rich| rich.inner_kind) {
                    Some(AppKind::Text) => PostKind::Text,
                    Some(AppKind::Reaction) => PostKind::Reaction,
                    Some(AppKind::CommunityRepost) => PostKind::Repost,
                    _ => PostKind::Other,
                };
                if let (PostKind::Reaction, Some(rich), false) = (kind, &rich, is_removed) {
                    if let Ok(reaction) = ReactionBody::parse(rich.inner_body) {
                        let key = (reaction.target, String::from(reaction.emoji), *pseudonym);
                        let adds = reaction.action == ReactionAction::Add;
                        let slot = last.entry(key).or_insert((*index, adds));
                        if *index >= slot.0 {
                            *slot = (*index, adds);
                        }
                    }
                }
                let reply_to = rich
                    .as_ref()
                    .map(|rich| rich.reply_target)
                    .filter(|target| *target != [0; 16]);
                out.posts.push(PostView {
                    hash: *hash,
                    pseudonym: *pseudonym,
                    index: *index,
                    is_settled: reader.is_some_and(|held| held.is_settled(*index)),
                    is_removed,
                    is_withdrawn: reader.is_some_and(|held| held.is_withdrawn(*index)),
                    is_author_banned: moderation.is_banned(pseudonym),
                    kind,
                    reply_id: community_reply_id(community_id, pseudonym, *index),
                    reply_to,
                    reactions: Vec::new(),
                });
            }
        }
    }
    let mut counts: BTreeMap<[u8; 16], BTreeMap<String, Vec<[u8; 32]>>> = BTreeMap::new();
    for ((target, emoji, pseudonym), (_, adds)) in last {
        if adds {
            counts
                .entry(target)
                .or_default()
                .entry(emoji)
                .or_default()
                .push(pseudonym);
        }
    }
    for post in &mut out.posts {
        if let Some(by_emoji) = counts.get(&post.reply_id) {
            post.reactions = by_emoji
                .iter()
                .map(|(emoji, by)| ReactionCount {
                    emoji: emoji.clone(),
                    by: by.clone(),
                })
                .collect();
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        community::{
            authority::tests::{genesis_entries, sign, OWNER_A},
            chain::AuthorChain,
            community_id,
            control::ControlBody,
            link::CommunityLink,
            meta::{Category, CommunityMetaBody, MetaDraft},
            social::text_body,
            test_util::{author, role},
            ADMISSION_OPEN, NO_INDEX, SIG_INTERVAL,
        },
    };

    #[test]
    fn a_reader_names_the_community_and_settles_the_posts_of_a_checkpoint() {
        let owner = role(OWNER_A);
        let id = community_id(ADMISSION_OPEN, owner.public_key()).unwrap();
        let roster = sign(
            &owner,
            id,
            (0, [0; 32]),
            ControlBody::Roster {
                entries: genesis_entries(),
                cosigns: Vec::new(),
            },
        )
        .encode()
        .unwrap();
        let link = CommunityLink {
            community_id: id,
            hints: alloc::vec![[1; 12], [2; 12], [3; 12]],
            fragment: [4; 16],
        };
        let body = CommunityMetaBody {
            category: Category::None,
            name: "Trail club".into(),
            text: String::new(),
            rules: String::new(),
            icon: Vec::new(),
        };
        let meta = CommunityMeta::sign(
            &owner,
            &link.meta_key(),
            MetaDraft {
                community_id: id,
                meta_index: 0,
                previous_meta: [0; 32],
                relays: link.hints.clone(),
                flags: 0,
                body: &body,
                nonce: [5; 12],
            },
            &mut Rng(6),
        )
        .unwrap()
        .encode()
        .unwrap();
        let writer = author(7);
        let mut chain = AuthorChain::new(id, &writer.pseudonym());
        let mut posts = Vec::new();
        for number in 0..SIG_INTERVAL {
            let text = text_body(&id, &alloc::format!("post {number}"), None, &[]).unwrap();
            posts.push(chain.append(&writer, NO_INDEX, &text, 10).unwrap());
        }
        let checkpoint = chain.checkpoint(&writer, 11, &mut Rng(8)).unwrap();
        let late = text_body(&id, "late", None, &[]).unwrap();
        let pending = chain.append(&writer, NO_INDEX, &late, 12).unwrap();

        // The relays serve the records in an order of their own.
        let mut records: Vec<&[u8]> = alloc::vec![&checkpoint, &pending, &meta];
        records.extend(posts.iter().map(Vec::as_slice));
        records.push(&roster);
        let seen = view(&id, &link.meta_key(), &records, 20);
        assert!(seen.has_genesis);
        assert_eq!(seen.name.as_deref(), Some("Trail club"));
        assert_eq!(seen.posts.len(), SIG_INTERVAL as usize + 1);
        let settled = seen.posts.iter().filter(|post| post.is_settled).count();
        assert_eq!(settled, SIG_INTERVAL as usize);
        assert!(!seen.posts.last().unwrap().is_settled);
        assert!(seen.forked.is_empty());

        // A reply names its target, and the last reaction of each
        // pseudonym decides (COM-333, COM-334).
        let target = crate::community::social::PostRef {
            pseudonym: writer.pseudonym(),
            index: 0,
        };
        let reader = author(9);
        let mut other = AuthorChain::new(id, &reader.pseudonym());
        let reply_body = text_body(&id, "yes", Some(target), &[]).unwrap();
        let reply = other.append(&reader, NO_INDEX, &reply_body, 13).unwrap();
        let like =
            |action| crate::community::social::reaction_body(&id, target, action, "👍").unwrap();
        let add = other
            .append(&reader, NO_INDEX, &like(ReactionAction::Add), 14)
            .unwrap();
        let mut social: Vec<&[u8]> = records.clone();
        social.push(&reply);
        social.push(&add);
        let seen = view(&id, &link.meta_key(), &social, 20);
        let first = seen
            .posts
            .iter()
            .find(|p| p.pseudonym == writer.pseudonym() && p.index == 0)
            .unwrap();
        assert_eq!(first.reactions.len(), 1);
        assert_eq!(first.reactions[0].emoji, "👍");
        assert_eq!(first.reactions[0].by, alloc::vec![reader.pseudonym()]);
        let answer = seen
            .posts
            .iter()
            .find(|p| p.hash == post_hash(&reply))
            .unwrap();
        assert_eq!(answer.kind, PostKind::Text);
        assert_eq!(answer.reply_to, Some(first.reply_id));
        let taken = other
            .append(&reader, NO_INDEX, &like(ReactionAction::Remove), 15)
            .unwrap();
        social.push(&taken);
        let seen = view(&id, &link.meta_key(), &social, 20);
        let first = seen
            .posts
            .iter()
            .find(|p| p.pseudonym == writer.pseudonym() && p.index == 0)
            .unwrap();
        assert!(first.reactions.is_empty());
        assert!(!seen.reactions_off);

        // A wrong key opens no name, and no genesis gives no view.
        let other = CommunityLink {
            fragment: [9; 16],
            ..link.clone()
        };
        assert_eq!(view(&id, &other.meta_key(), &records, 20).name, None);
        let headless: Vec<&[u8]> = records[..records.len() - 1].to_vec();
        let seen = view(&id, &link.meta_key(), &headless, 20);
        assert!(!seen.has_genesis && seen.posts.is_empty());
    }
}
