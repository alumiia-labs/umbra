//! The posts of this device in its communities (Part 12 §12.4.1): the
//! chain of the authoring identity in each community, and the outbox of
//! the records that each relay of the community has not taken yet.
//!
//! A post goes to each relay of its community, and it goes again at each
//! session until the relay answers (`COM-200`, `COM-201`). The outbox
//! keeps the bytes, thus each relay gets the same record.

use umbra_core::{
    community::{
        chain::AuthorChain, identity::AuthorIdentity, social::text_body, COMMUNITY_RELAY_MAX,
        NO_INDEX,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{hash::sha3_256, rand_core::CryptoRng, zeroize::Zeroizing};

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
    pub fn post_to_community<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        text: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let text = core::str::from_utf8(text).map_err(|_| Error::Malformed)?;
        if text.trim().is_empty() {
            return Err(Error::Malformed);
        }
        let (owner, row) = self.community_row_of(community_id)?;
        let author = AuthorIdentity::from_seed(&row.author_seed);
        let mut chain = self.author_chain(community_id, &author)?;
        let body = text_body(community_id, text, None, &[]).map_err(|_| Error::TooLong)?;
        let post = chain
            .append(&author, NO_INDEX, &body, now)
            .map_err(|_| Error::TooLong)?;
        let mut records = vec![post];
        // COM-045 to COM-048.
        if chain.checkpoint_due(now) {
            records.push(chain.checkpoint(&author, now, rng)?);
        }
        self.put_author_records(&owner, community_id, &chain, &records, now, rng)
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
            self.put_author_records(&owner, &community_id, &chain, &[checkpoint], now, rng)?;
        }
        Ok(())
    }

    /// The community row and its row id, or `NotFound`.
    fn community_row_of(
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

    /// Stores the chain and puts each record in the outbox and among the
    /// records of the community, in one batch.
    fn put_author_records<R: CryptoRng + ?Sized>(
        &mut self,
        owner: &RowId,
        community_id: &[u8; 32],
        chain: &AuthorChain,
        records: &[Vec<u8>],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let chain_bytes = chain.to_bytes()?;
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
        batch.put(
            COMMUNITY_AUTHOR,
            author_row,
            Some(*owner),
            &chain_bytes,
            rng,
        )?;
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
