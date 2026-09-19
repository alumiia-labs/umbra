//! The social records of a community (Part 12 §12.5.4, §12.6.1 to
//! §12.6.3): the body of a post with its mention list and its reply
//! target, the reaction and its tally, the repost, the contact key of a
//! pseudonym, and the local mute list.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use umbra_crypto::kem::PUBLIC_KEY_LEN;
use umbra_wire::{
    address::{QueueAddress, LEN as QUEUE_ADDRESS_LEN},
    app::{
        rich::{community_reply_id, mention_id, RichRecord},
        signal::{ReactionAction, ReactionBody},
        AppKind, Channel,
    },
    codec::{Reader, Writer},
};

use super::{identity::AuthorIdentity, link::CommunityLink, MUTE_LIST_MAX, VERSION};
use crate::Error;

/// The length of a `CommunityContact`.
pub const COMMUNITY_CONTACT_LEN: usize = 1 + PUBLIC_KEY_LEN + QUEUE_ADDRESS_LEN;

/// The rate class of a post, which a relay reads from the public
/// `inner_kind` byte (`COM-328`, `COM-329`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PostClass {
    /// Counted under `POST_RATE_LIMIT`.
    Post,
    /// Counted under `REACT_RATE_LIMIT`.
    Reaction,
    /// Counted under `REPOST_RATE_LIMIT`.
    Repost,
}

/// Reads the body of a `CommunityPost` and gives its class. The body
/// starts with a `RichRecord` (`COM-158`), its forward depth is zero
/// (`COM-162`), and a reaction holds no reply target and no mention
/// (`COM-324`).
pub fn classify(body: &[u8]) -> Result<PostClass, Error> {
    let rich = RichRecord::parse(body, Channel::Community)?;
    if rich.forward_depth != 0 {
        return Err(Error::Malformed);
    }
    match rich.inner_kind {
        AppKind::Reaction => {
            if rich.reply_target != [0; 16] || !rich.mentions.is_empty() {
                return Err(Error::Malformed);
            }
            ReactionBody::parse(rich.inner_body)?;
            Ok(PostClass::Reaction)
        }
        AppKind::CommunityRepost => {
            RepostBody::parse(rich.inner_body)?;
            Ok(PostClass::Repost)
        }
        AppKind::CommunityContact => {
            CommunityContact::parse(rich.inner_body)?;
            Ok(PostClass::Post)
        }
        _ => Ok(PostClass::Post),
    }
}

/// The triple of a post, for a reply target and a reaction target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostRef {
    /// The authoring pseudonym.
    pub pseudonym: [u8; 32],
    /// The index in the chain of that pseudonym.
    pub index: u32,
}

impl PostRef {
    /// `community_reply_id` of Part 6 §6.6.5 (`COM-161`).
    pub fn reply_id(&self, community_id: &[u8; 32]) -> [u8; 16] {
        community_reply_id(community_id, &self.pseudonym, self.index)
    }
}

fn rich_body(record: &RichRecord<'_>) -> Result<Vec<u8>, Error> {
    let mut out = alloc::vec![0u8; record.len()];
    let used = record.encode(Channel::Community, &mut out)?;
    out.truncate(used);
    Ok(out)
}

/// The body of a text post, with the members it names and the post it
/// answers (`COM-158` to `COM-161`).
pub fn text_body(
    community_id: &[u8; 32],
    text: &str,
    reply_to: Option<PostRef>,
    mentioned: &[[u8; 32]],
) -> Result<Vec<u8>, Error> {
    let mut mentions: Vec<[u8; 16]> = mentioned
        .iter()
        .map(|pseudonym| mention_id(community_id, pseudonym))
        .collect();
    mentions.sort_unstable();
    mentions.dedup();
    rich_body(&RichRecord {
        reply_target: reply_to.map_or([0; 16], |target| target.reply_id(community_id)),
        thread_root: [0; 16],
        forward_depth: 0,
        mentions,
        inner_kind: AppKind::Text,
        inner_body: text.as_bytes(),
    })
}

/// The body of a reaction to `target` (`COM-322`, `COM-323`).
pub fn reaction_body(
    community_id: &[u8; 32],
    target: PostRef,
    action: ReactionAction,
    emoji: &str,
) -> Result<Vec<u8>, Error> {
    let reaction = ReactionBody {
        target: target.reply_id(community_id),
        action,
        emoji,
    };
    let mut inner = [0u8; 64];
    let used = reaction.encode(&mut inner)?;
    rich_body(&RichRecord {
        reply_target: [0; 16],
        thread_root: [0; 16],
        forward_depth: 0,
        mentions: Vec::new(),
        inner_kind: AppKind::Reaction,
        inner_body: inner.get(..used).ok_or(Error::Malformed)?,
    })
}

/// Whether a post names the user (`COM-165`). The client finds this at the
/// pull, and asks no relay.
pub fn names(body: &[u8], community_id: &[u8; 32], own_pseudonym: &[u8; 32]) -> bool {
    RichRecord::parse(body, Channel::Community).is_ok_and(|rich| {
        rich.mentions
            .contains(&mention_id(community_id, own_pseudonym))
    })
}

/// A `RepostBody`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepostBody {
    /// The community of the target post.
    pub origin_community: [u8; 32],
    /// The target post.
    pub target: PostRef,
    /// The link of the origin community, or empty for a repost inside one
    /// community.
    pub link: String,
}

impl RepostBody {
    /// A repost of `target` into `this_community`. The link of another
    /// origin drops hints from its end until it fits the length byte.
    pub fn new(
        this_community: &[u8; 32],
        target: PostRef,
        origin: &CommunityLink,
    ) -> Result<Self, Error> {
        let mut link = String::new();
        if origin.community_id != *this_community {
            let mut trimmed = origin.clone();
            link = trimmed.format()?;
            while link.len() > usize::from(u8::MAX) {
                trimmed.hints.pop();
                link = trimmed.format()?;
            }
        }
        Ok(RepostBody {
            origin_community: origin.community_id,
            target,
            link,
        })
    }

    /// The body of the `CommunityPost` that carries the repost
    /// (`COM-325`).
    pub fn post_body(&self) -> Result<Vec<u8>, Error> {
        let mut inner = alloc::vec![0u8; 70 + self.link.len()];
        let mut w = Writer::new(&mut inner);
        w.u8(VERSION)?;
        w.put(&self.origin_community)?;
        w.put(&self.target.pseudonym)?;
        w.u32(self.target.index)?;
        w.u8(u8::try_from(self.link.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.link.as_bytes())?;
        rich_body(&RichRecord {
            reply_target: [0; 16],
            thread_root: [0; 16],
            forward_depth: 0,
            mentions: Vec::new(),
            inner_kind: AppKind::CommunityRepost,
            inner_body: &inner,
        })
    }

    /// Reads the inner body of a repost. A link, when one is present,
    /// names the origin community.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let origin_community = r.array()?;
        let target = PostRef {
            pseudonym: r.array()?,
            index: r.u32()?,
        };
        let link_len = usize::from(r.u8()?);
        let link: String = core::str::from_utf8(r.take(link_len)?)
            .map_err(|_| Error::Malformed)?
            .into();
        r.finish()?;
        if !link.is_empty() && CommunityLink::parse(&link)?.community_id != origin_community {
            return Err(Error::Malformed);
        }
        Ok(RepostBody {
            origin_community,
            target,
            link,
        })
    }

    /// Whether the record is valid in `this_community`: `link_len` is 0
    /// exactly when the origin is this community.
    pub fn fits(&self, this_community: &[u8; 32]) -> bool {
        (self.origin_community == *this_community) == self.link.is_empty()
    }
}

/// A `CommunityContact`: the key and the queue that take a hello to a
/// pseudonym (§12.6.3). A client publishes one only after an explicit act
/// of the user (`COM-336`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommunityContact {
    /// The encapsulation key, or zero bytes to withdraw.
    pub contact_pk: [u8; PUBLIC_KEY_LEN],
    /// The encoded `QueueAddress` of the rendezvous queue.
    pub rendezvous: [u8; QUEUE_ADDRESS_LEN],
}

impl CommunityContact {
    /// The contact record of `author` at `rendezvous`, which no other
    /// object names (`COM-339`).
    pub fn publish(author: &AuthorIdentity, rendezvous: &QueueAddress) -> Result<Self, Error> {
        let mut queue = [0u8; QUEUE_ADDRESS_LEN];
        rendezvous.encode(&mut queue)?;
        Ok(CommunityContact {
            contact_pk: author.contact_key().public().to_bytes(),
            rendezvous: queue,
        })
    }

    /// The record that withdraws the contact key.
    pub fn withdraw() -> Self {
        let mut rendezvous = [0u8; QUEUE_ADDRESS_LEN];
        if let Some(version) = rendezvous.first_mut() {
            *version = umbra_wire::address::VERSION;
        }
        CommunityContact {
            contact_pk: [0; PUBLIC_KEY_LEN],
            rendezvous,
        }
    }

    /// Whether the record withdraws the key.
    pub fn is_withdrawal(&self) -> bool {
        self.contact_pk == [0; PUBLIC_KEY_LEN]
    }

    /// The body of the `CommunityPost` that carries the record
    /// (`COM-337`).
    pub fn post_body(&self) -> Result<Vec<u8>, Error> {
        let mut inner = [0u8; COMMUNITY_CONTACT_LEN];
        let mut w = Writer::new(&mut inner);
        w.u8(VERSION)?;
        w.put(&self.contact_pk)?;
        w.put(&self.rendezvous)?;
        rich_body(&RichRecord {
            reply_target: [0; 16],
            thread_root: [0; 16],
            forward_depth: 0,
            mentions: Vec::new(),
            inner_kind: AppKind::CommunityContact,
            inner_body: &inner,
        })
    }

    /// Reads the inner body of a contact record.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let contact = CommunityContact {
            contact_pk: r.array()?,
            rendezvous: r.array()?,
        };
        r.finish()?;
        QueueAddress::parse(&contact.rendezvous)?;
        Ok(contact)
    }
}

/// One reaction slot: the target, the emoji, and the pseudonym.
type ReactionSlot = ([u8; 16], String, [u8; 32]);

/// The reaction counts of one community, from the records that the client
/// pulled (`COM-333`). One pseudonym counts one time for each target and
/// emoji, and its last action decides (`COM-334`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReactionTally {
    /// The index of the deciding record and whether it adds, by target,
    /// emoji, and pseudonym.
    last: BTreeMap<ReactionSlot, (u32, bool)>,
}

impl ReactionTally {
    /// Records the reaction that `pseudonym` made at `index` of its chain.
    pub fn record(&mut self, pseudonym: [u8; 32], index: u32, reaction: &ReactionBody<'_>) {
        let key = (reaction.target, String::from(reaction.emoji), pseudonym);
        let adds = reaction.action == ReactionAction::Add;
        let slot = self.last.entry(key).or_insert((index, adds));
        if index >= slot.0 {
            *slot = (index, adds);
        }
    }

    /// The count of `emoji` on `target`, without the muted pseudonyms
    /// (`COM-315`).
    pub fn count(&self, target: &[u8; 16], emoji: &str, mutes: &MuteList) -> usize {
        self.last
            .iter()
            .filter(|((t, e, p), (_, adds))| {
                t == target && e == emoji && *adds && !mutes.contains(p)
            })
            .count()
    }
}

/// The mute list of one community (§12.5.4). It is local state that syncs
/// inside the device set, and no record leaves the device for it
/// (`COM-319`, `COM-320`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MuteList {
    muted: BTreeSet<[u8; 32]>,
    hidden: u32,
}

impl MuteList {
    /// Mutes a pseudonym (`COM-314`, `COM-321`).
    pub fn mute(&mut self, pseudonym: [u8; 32]) -> Result<(), Error> {
        if self.muted.len() >= MUTE_LIST_MAX && !self.muted.contains(&pseudonym) {
            return Err(Error::NoPath);
        }
        self.muted.insert(pseudonym);
        Ok(())
    }

    /// Removes a mute.
    pub fn unmute(&mut self, pseudonym: &[u8; 32]) {
        self.muted.remove(pseudonym);
    }

    /// Whether the pseudonym is muted.
    pub fn contains(&self, pseudonym: &[u8; 32]) -> bool {
        self.muted.contains(pseudonym)
    }

    /// Whether the client renders a record of `pseudonym`. A hidden record
    /// adds to the count that the interface shows (`COM-315`, `COM-316`).
    /// The chain of a muted pseudonym still verifies (`COM-318`), thus the
    /// caller asks this after the verification.
    pub fn renders(&mut self, pseudonym: &[u8; 32]) -> bool {
        if self.muted.contains(pseudonym) {
            self.hidden = self.hidden.saturating_add(1);
            return false;
        }
        true
    }

    /// The count of the hidden records.
    pub fn hidden_count(&self) -> u32 {
        self.hidden
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::community::{control::tests::queue, test_util::author};

    const COMMUNITY: [u8; 32] = [9; 32];

    #[test]
    fn a_body_gives_its_rate_class_and_a_mention_is_found_locally() {
        let me = [4; 32];
        let target = PostRef {
            pseudonym: [1; 32],
            index: 7,
        };
        let text = text_body(&COMMUNITY, "hello", Some(target), &[me, [5; 32], me]).unwrap();
        assert_eq!(classify(&text).unwrap(), PostClass::Post);
        assert!(names(&text, &COMMUNITY, &me));
        assert!(!names(&text, &COMMUNITY, &[6; 32]));
        assert!(!names(&text, &[8; 32], &me), "the scope is the community");

        let reaction = reaction_body(&COMMUNITY, target, ReactionAction::Add, "👍").unwrap();
        assert_eq!(classify(&reaction).unwrap(), PostClass::Reaction);

        assert!(classify(b"plain bytes").is_err());
        let mut forwarded = text.clone();
        forwarded[33] = 1;
        assert!(classify(&forwarded).is_err());
    }

    #[test]
    fn a_repost_carries_a_link_for_another_origin_only() {
        let target = PostRef {
            pseudonym: [1; 32],
            index: 7,
        };
        let here = CommunityLink {
            community_id: COMMUNITY,
            hints: alloc::vec![[1; 12]],
            fragment: [2; 16],
        };
        let inside = RepostBody::new(&COMMUNITY, target, &here).unwrap();
        assert!(inside.link.is_empty() && inside.fits(&COMMUNITY));
        assert_eq!(
            classify(&inside.post_body().unwrap()).unwrap(),
            PostClass::Repost
        );

        let elsewhere = CommunityLink {
            community_id: [7; 32],
            hints: alloc::vec![[1; 12]; 8],
            fragment: [2; 16],
        };
        let across = RepostBody::new(&COMMUNITY, target, &elsewhere).unwrap();
        assert!(across.link.len() <= 255);
        assert_eq!(CommunityLink::parse(&across.link).unwrap().hints.len(), 7);
        assert!(across.fits(&COMMUNITY) && !across.fits(&[7; 32]));
        let body = across.post_body().unwrap();
        let rich = RichRecord::parse(&body, Channel::Community).unwrap();
        assert_eq!(RepostBody::parse(rich.inner_body).unwrap(), across);

        let mut lying = across.clone();
        lying.origin_community = [6; 32];
        assert!(classify(&lying.post_body().unwrap()).is_err());
    }

    #[test]
    fn a_contact_record_holds_1346_bytes_and_withdraws_with_a_zero_key() {
        let identity = author(1);
        let contact = CommunityContact::publish(&identity, &queue(3)).unwrap();
        assert_eq!(COMMUNITY_CONTACT_LEN, 1_346);
        let body = contact.post_body().unwrap();
        assert_eq!(classify(&body).unwrap(), PostClass::Post);
        let rich = RichRecord::parse(&body, Channel::Community).unwrap();
        let parsed = CommunityContact::parse(rich.inner_body).unwrap();
        assert_eq!(parsed, contact);
        assert!(!parsed.is_withdrawal());

        let gone = CommunityContact::withdraw();
        let rich_bytes = gone.post_body().unwrap();
        let rich = RichRecord::parse(&rich_bytes, Channel::Community).unwrap();
        assert!(CommunityContact::parse(rich.inner_body)
            .unwrap()
            .is_withdrawal());
    }

    #[test]
    fn the_last_action_of_a_pseudonym_decides_and_a_mute_hides() {
        let target = [3; 16];
        let add = ReactionBody {
            target,
            action: ReactionAction::Add,
            emoji: "👍",
        };
        let remove = ReactionBody {
            action: ReactionAction::Remove,
            ..add.clone()
        };
        let mut tally = ReactionTally::default();
        let mut mutes = MuteList::default();
        tally.record([1; 32], 2, &add);
        tally.record([1; 32], 9, &add);
        tally.record([2; 32], 5, &remove);
        tally.record([2; 32], 3, &add);
        tally.record([3; 32], 1, &add);
        assert_eq!(tally.count(&target, "👍", &mutes), 2);
        assert_eq!(tally.count(&target, "👎", &mutes), 0);

        mutes.mute([3; 32]).unwrap();
        assert_eq!(tally.count(&target, "👍", &mutes), 1);
        assert!(!mutes.renders(&[3; 32]));
        assert!(mutes.renders(&[1; 32]));
        assert_eq!(mutes.hidden_count(), 1);
        mutes.unmute(&[3; 32]);
        assert!(mutes.renders(&[3; 32]));

        let mut full = MuteList::default();
        for n in 0..MUTE_LIST_MAX as u32 {
            let mut p = [0u8; 32];
            p[..4].copy_from_slice(&n.to_be_bytes());
            full.mute(p).unwrap();
        }
        assert!(full.mute([0xFF; 32]).is_err());
    }
}
