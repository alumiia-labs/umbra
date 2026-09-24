//! The posts of this device in its communities (Part 12 §12.4.1): the
//! chain of the authoring identity in each community, and the outbox of
//! the records that each relay of the community has not taken yet.
//!
//! A post goes to each relay of its community, and it goes again at each
//! session until the relay answers (`COM-200`, `COM-201`). The outbox
//! keeps the bytes, thus each relay gets the same record.

use umbra_core::{
    community::{
        chain::AuthorChain,
        control::{ActionKind, ControlBody, ControlObject, ModerationAction, Role},
        identity::{AuthorIdentity, RoleIdentity},
        social::{reaction_body, text_body, PostRef},
        COMMUNITY_RELAY_MAX, NO_INDEX,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{hash::sha3_256, rand_core::CryptoRng, zeroize::Zeroizing};
use umbra_wire::app::signal::ReactionAction;

use super::{communities::COMMUNITY, Client};
use crate::Error;

/// The chain of this device in each community, owned by the community row.
/// A backup carries it: a restored device that posted at index 0 again
/// would fork its own chain.
pub(super) const COMMUNITY_AUTHOR: TableId = TableId(0x25);
/// Each record of this device that a relay of its community has not taken,
/// by its hash, owned by the community row.
pub(super) const COMMUNITY_OUTBOX: TableId = TableId(0x26);

/// An outbox row: the time of the post, a bit for each relay that took
/// it, a bit for each relay that refused it, and the record.
const OUTBOX_HEAD: usize = 8 + 1 + 1;

// A bit for each relay of a community.
const _: () = assert!(COMMUNITY_RELAY_MAX <= 8);

/// One record for one relay, which the caller sends with no admission
/// (Part 14 `ABU-049`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostSend {
    /// The community.
    pub community_id: [u8; 32],
    /// The relay.
    pub relay: [u8; 32],
    /// The hash of the record, which names it in the outbox.
    pub key: [u8; 32],
    /// The encoded record.
    pub record: Vec<u8>,
}

/// One act of moderation that the platform asks for (§12.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModerationRequest {
    /// Remove one post, by its hash.
    RemovePost {
        /// The hash of the post.
        key: [u8; 32],
    },
    /// Ban an authoring pseudonym, and remove each post of it that this
    /// device holds when `remove_history` holds (`COM-297`).
    Ban {
        /// The pseudonym.
        author: [u8; 32],
        /// Whether the ban removes the history too.
        remove_history: bool,
    },
    /// End the ban of a pseudonym.
    Unban {
        /// The pseudonym.
        author: [u8; 32],
    },
}

fn keyed(community_id: &[u8; 32], hash: &[u8; 32]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(community_id);
    key[32..].copy_from_slice(hash);
    key
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Posts a text in a community under the authoring identity of this
    /// device there. A checkpoint follows when the cadence of §12.4.1 asks
    /// for one. The post shows at once, and it goes to each relay.
    /// `reply_to` names the post that this one answers (`COM-161`).
    pub fn post_to_community<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        text: &[u8],
        reply_to: Option<&[u8; 32]>,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let text = core::str::from_utf8(text).map_err(|_| Error::Malformed)?;
        if text.trim().is_empty() {
            return Err(Error::Malformed);
        }
        let target = match reply_to {
            Some(key) => Some(self.post_ref(community_id, key, now)?),
            None => None,
        };
        let body = text_body(community_id, text, target, &[]).map_err(|_| Error::TooLong)?;
        self.append_own_post(community_id, &body, now, rng)
    }

    /// Adds or takes back a reaction of this device to a post (`COM-322`
    /// to `COM-324`). A reaction is a record of the chain, thus the relays
    /// count it and it shows in the tally of each reader.
    pub fn react_to_community_post<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        key: &[u8; 32],
        emoji: &str,
        adds: bool,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !super::is_emoji(emoji) {
            return Err(Error::Malformed);
        }
        // COM-332: a reaction that the owner dial forbids does not leave.
        if self.community_view_of(community_id, now)?.reactions_off {
            return Err(Error::Busy);
        }
        let target = self.post_ref(community_id, key, now)?;
        let action = if adds {
            ReactionAction::Add
        } else {
            ReactionAction::Remove
        };
        let body = reaction_body(community_id, target, action, emoji)?;
        self.append_own_post(community_id, &body, now, rng)
    }

    /// The pseudonym and the index of a post of the view.
    fn post_ref(
        &self,
        community_id: &[u8; 32],
        key: &[u8; 32],
        now: u64,
    ) -> Result<PostRef, Error> {
        let view = self.community_view_of(community_id, now)?;
        let post = view
            .posts
            .iter()
            .find(|post| post.hash == *key)
            .ok_or(Error::NotFound)?;
        Ok(PostRef {
            pseudonym: post.pseudonym,
            index: post.index,
        })
    }

    /// Appends one body to the chain of this device, with a checkpoint when
    /// the cadence asks for one.
    fn append_own_post<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let (owner, row) = self.community_row_of(community_id)?;
        let author = AuthorIdentity::from_seed(&row.author_seed);
        let mut chain = self.author_chain(community_id, &author)?;
        let body = body.to_vec();
        let post = chain
            .append(&author, NO_INDEX, &body, now)
            .map_err(|_| Error::TooLong)?;
        let mut records = vec![post];
        // COM-045 to COM-048.
        if chain.checkpoint_due(now) {
            records.push(chain.checkpoint(&author, now, rng)?);
        }
        self.put_own_records(&owner, community_id, Some(&chain), &records, now, rng)
    }

    /// Signs a moderation epoch under the owner role of this device, on the
    /// head of the control chain that it holds (`COM-377`, `COM-378`). The
    /// epoch shows at once, and it goes to each relay as a post does.
    pub fn moderate_community<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        request: &ModerationRequest,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let (owner, row) = self.community_row_of(community_id)?;
        let role_seed = row.role_seed.as_ref().ok_or(Error::NotFound)?;
        let role = RoleIdentity::from_seed(role_seed);
        let view = self.community_view_of(community_id, now)?;
        // COM-121, COM-122: the roster names the signer in its role.
        let actor_role = view
            .roster
            .iter()
            .find(|entry| entry.pseudonym == role.pseudonym())
            .map(|entry| entry.role)
            .filter(|held| matches!(held, Role::Owner | Role::Admin))
            .ok_or(Error::NotFound)?;
        let (head, index) = view.control_head.ok_or(Error::NotFound)?;
        let action = match request {
            ModerationRequest::RemovePost { key } => {
                let post = view
                    .posts
                    .iter()
                    .find(|post| post.hash == *key)
                    .ok_or(Error::NotFound)?;
                ModerationAction {
                    kind: ActionKind::Remove,
                    target: post.pseudonym,
                    index: post.index,
                }
            }
            ModerationRequest::Ban {
                author,
                remove_history,
            } => {
                let highest = view
                    .posts
                    .iter()
                    .filter(|post| post.pseudonym == *author)
                    .map(|post| post.index)
                    .max();
                ModerationAction {
                    kind: ActionKind::Ban,
                    target: *author,
                    index: highest.filter(|_| *remove_history).unwrap_or(NO_INDEX),
                }
            }
            ModerationRequest::Unban { author } => ModerationAction {
                kind: ActionKind::Unban,
                target: *author,
                index: NO_INDEX,
            },
        };
        let record = ControlObject::sign(
            &role,
            *community_id,
            index.checked_add(1).ok_or(Error::Malformed)?,
            head,
            ControlBody::Moderation {
                actor_role,
                actions: vec![action],
            },
            rng,
        )?
        .encode()?;
        self.put_own_records(&owner, community_id, None, &[record], now, rng)
    }

    /// Signs the checkpoint of each chain whose cadence asks for one: a
    /// post with no checkpoint for `SIG_MAX_AGE` gets one (`COM-046`).
    pub fn community_checkpoints_due<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut due = Vec::new();
        {
            let store = &self.open_ref()?.store;
            for (_, plain) in store.list(COMMUNITY_AUTHOR, None)? {
                let chain = AuthorChain::from_bytes(&plain).map_err(|_| Error::Integrity)?;
                if chain.checkpoint_due(now) {
                    due.push(chain);
                }
            }
        }
        for mut chain in due {
            let community_id = *chain.community_id();
            let (owner, row) = self.community_row_of(&community_id)?;
            let author = AuthorIdentity::from_seed(&row.author_seed);
            let checkpoint = chain.checkpoint(&author, now, rng)?;
            self.put_own_records(&owner, &community_id, Some(&chain), &[checkpoint], now, rng)?;
        }
        Ok(())
    }

    /// The community row and its row id, or `NotFound`.
    pub(super) fn community_row_of(
        &self,
        community_id: &[u8; 32],
    ) -> Result<(RowId, super::communities::CommunityRow), Error> {
        let store = &self.open_ref()?.store;
        let row_id = store.row_id(COMMUNITY, community_id);
        let plain = store.get(COMMUNITY, &row_id)?.ok_or(Error::NotFound)?;
        Ok((
            row_id,
            super::communities::CommunityRow::parse(&Zeroizing::new(plain))?,
        ))
    }

    fn author_chain(
        &self,
        community_id: &[u8; 32],
        author: &AuthorIdentity,
    ) -> Result<AuthorChain, Error> {
        let store = &self.open_ref()?.store;
        let row_id = store.row_id(COMMUNITY_AUTHOR, community_id);
        match store.get(COMMUNITY_AUTHOR, &row_id)? {
            Some(plain) => AuthorChain::from_bytes(&plain).map_err(|_| Error::Integrity),
            None => Ok(AuthorChain::new(*community_id, &author.pseudonym())),
        }
    }

    /// Stores the chain, where one moved, and puts each record in the
    /// outbox and among the records of the community, in one batch.
    fn put_own_records<R: CryptoRng + ?Sized>(
        &mut self,
        owner: &RowId,
        community_id: &[u8; 32],
        chain: Option<&AuthorChain>,
        records: &[Vec<u8>],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let chain_bytes = chain.map(AuthorChain::to_bytes).transpose()?;
        let open = self.open_mut()?;
        let author_row = open.store.row_id(COMMUNITY_AUTHOR, community_id);
        let mut rows = Vec::new();
        for record in records {
            let hash = sha3_256(&[record]);
            let outbox = open
                .store
                .row_id(COMMUNITY_OUTBOX, &keyed(community_id, &hash));
            let mut value = Vec::with_capacity(OUTBOX_HEAD + record.len());
            value.extend_from_slice(&now.to_be_bytes());
            value.extend_from_slice(&[0, 0]);
            value.extend_from_slice(record);
            let shown = open.store.row_id(
                super::communities::COMMUNITY_RECORD,
                &keyed(community_id, &hash),
            );
            let mut record_value = Vec::with_capacity(8 + record.len());
            record_value.extend_from_slice(&now.to_be_bytes());
            record_value.extend_from_slice(record);
            rows.push((outbox, value, shown, record_value));
        }
        let mut batch = open.store.begin();
        if let Some(chain_bytes) = chain_bytes {
            batch.put(
                COMMUNITY_AUTHOR,
                author_row,
                Some(*owner),
                &chain_bytes,
                rng,
            )?;
        }
        for (outbox, value, shown, record_value) in rows {
            batch.put(COMMUNITY_OUTBOX, outbox, Some(*owner), &value, rng)?;
            batch.put(
                super::communities::COMMUNITY_RECORD,
                shown,
                Some(*owner),
                &record_value,
                rng,
            )?;
        }
        Ok(batch.commit()?)
    }

    /// Each record of the outbox for each relay that has not answered it,
    /// oldest first, thus a checkpoint follows the posts that it covers.
    pub fn community_publish_sends(&self) -> Result<Vec<PostSend>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (owner, plain) in store.list(COMMUNITY, None)? {
            let row = super::communities::CommunityRow::parse(&Zeroizing::new(plain))?;
            let mut held = Vec::new();
            for (_, value) in store.list(COMMUNITY_OUTBOX, Some(&owner))? {
                let (head, record) = value
                    .split_at_checked(OUTBOX_HEAD)
                    .ok_or(Error::Integrity)?;
                let (at, marks) = head.split_at(8);
                let at = u64::from_be_bytes(at.try_into().map_err(|_| Error::Integrity)?);
                let done = marks.iter().fold(0u8, |done, mark| done | mark);
                held.push((at, done, record.to_vec()));
            }
            held.sort();
            for (_, done, record) in held {
                let key = sha3_256(&[&record]);
                for (index, relay) in row.relays.iter().enumerate() {
                    if done & (1 << index) != 0 {
                        continue;
                    }
                    out.push(PostSend {
                        community_id: row.community_id,
                        relay: *relay,
                        key,
                        record: record.clone(),
                    });
                }
            }
        }
        Ok(out)
    }

    /// A relay answered a record of the outbox: it holds it, or it refused
    /// it with a `NACK`, which ends the resends there (`COM-201`). A record
    /// that each relay answered leaves the outbox.
    pub fn community_published<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        key: &[u8; 32],
        relay: &[u8; 32],
        refused: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let (owner, row) = self.community_row_of(community_id)?;
        let Some(index) = row.relays.iter().position(|held| held == relay) else {
            return Ok(());
        };
        let open = self.open_mut()?;
        let outbox = open
            .store
            .row_id(COMMUNITY_OUTBOX, &keyed(community_id, key));
        let Some(mut value) = open.store.get(COMMUNITY_OUTBOX, &outbox)? else {
            return Ok(());
        };
        let slot = if refused { 9 } else { 8 };
        *value.get_mut(slot).ok_or(Error::Integrity)? |= 1 << index;
        let done = value.get(8).copied().unwrap_or(0) | value.get(9).copied().unwrap_or(0);
        let all = u8::try_from((1u16 << row.relays.len()) - 1).unwrap_or(u8::MAX);
        let mut batch = open.store.begin();
        if done & all == all {
            batch.delete(COMMUNITY_OUTBOX, outbox);
        } else {
            batch.put(COMMUNITY_OUTBOX, outbox, Some(owner), &value, rng)?;
        }
        Ok(batch.commit()?)
    }

    /// The count of the records of a community that a relay has not taken.
    pub(super) fn community_pending(&self, owner: &RowId) -> Result<usize, Error> {
        Ok(self
            .open_ref()?
            .store
            .list(COMMUNITY_OUTBOX, Some(owner))?
            .len())
    }
}
