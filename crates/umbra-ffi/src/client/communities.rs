//! The public communities of this device (Part 12): each community that
//! the user joined, the cursor of each of its relays, and the records that
//! the pulls brought.
//!
//! A community row holds what a restore needs: the link, the relays, and
//! the seed of the authoring identity (`COM-027`). A backup carries it.
//! The cursors and the records are a cache of what the relays serve, and
//! a restored device pulls them again from the newest records
//! (`COM-195`).

use umbra_core::{
    community::{
        link::CommunityLink,
        pull::{PullRequest, PullResponse, RelayCursor, Selector, CURSOR_LEN, CURSOR_LEN_V1},
        pull_interval, COMMUNITY_RELAY_MAX, META_NAME_MAX, PULL_BATCH, PULL_INTERVAL_MAX,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{hash::sha3_256, rand_core::CryptoRng, secret::Secret, zeroize::Zeroizing};

use super::Client;
use crate::Error;

/// Each community of this device, by `community_id`.
pub(super) const COMMUNITY: TableId = TableId(0x21);
/// The cursor of each relay of a community, owned by its community row.
const COMMUNITY_CURSOR: TableId = TableId(0x22);
/// Each record that a pull brought, by its hash, owned by its community
/// row. Two relays serve one record, and it is here one time (§12.2.1).
pub(super) const COMMUNITY_RECORD: TableId = TableId(0x23);
/// The next index of the control chain and of the metadata that the pulls
/// of the join ask for (`COM-196`), owned by the community row. A
/// community with no row starts both at 0.
const COMMUNITY_JOIN: TableId = TableId(0x27);
const JOIN_ROW_LEN: usize = 1 + 8 + 1 + 8 + 8;

/// The pulls of the join of one community: the next index of each chain,
/// or none when the chain is whole, and the time of the next try.
struct JoinRow {
    control: Option<u64>,
    meta: Option<u64>,
    retry_at: u64,
}

impl JoinRow {
    fn new() -> Self {
        JoinRow {
            control: Some(0),
            meta: Some(0),
            retry_at: 0,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(JOIN_ROW_LEN);
        for next in [self.control, self.meta] {
            out.push(u8::from(next.is_some()));
            out.extend_from_slice(&next.unwrap_or(0).to_be_bytes());
        }
        out.extend_from_slice(&self.retry_at.to_be_bytes());
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != JOIN_ROW_LEN {
            return Err(Error::Integrity);
        }
        let number = |at: usize| -> Result<u64, Error> {
            let part = bytes.get(at..at + 8).ok_or(Error::Integrity)?;
            Ok(u64::from_be_bytes(
                part.try_into().map_err(|_| Error::Integrity)?,
            ))
        };
        let flag = |at: usize| bytes.get(at).copied() == Some(1);
        Ok(JoinRow {
            control: flag(0).then_some(number(1)?),
            meta: flag(9).then_some(number(10)?),
            retry_at: number(18)?,
        })
    }
}

const ROW_VERSION: u8 = 0x01;
const CURSOR_ROW_LEN: usize = 32 + CURSOR_LEN + 8 + 8;

/// One community of this device.
pub(super) struct CommunityRow {
    pub(super) community_id: [u8; 32],
    pub(super) fragment: [u8; 16],
    pub(super) joined_at: u64,
    /// The seed of the authoring identity of this device in the community.
    pub(super) author_seed: Secret<32>,
    /// The seed of the owner role identity, on a device that owns the
    /// community.
    pub(super) role_seed: Option<Secret<32>>,
    pub(super) relays: Vec<[u8; 32]>,
    pub(super) name: String,
}

impl CommunityRow {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.relays.is_empty() || self.relays.len() > COMMUNITY_RELAY_MAX {
            return Err(Error::Malformed);
        }
        if self.name.len() > META_NAME_MAX {
            return Err(Error::TooLong);
        }
        let mut out = Vec::new();
        out.push(ROW_VERSION);
        out.extend_from_slice(&self.community_id);
        out.extend_from_slice(&self.fragment);
        out.extend_from_slice(&self.joined_at.to_be_bytes());
        out.extend_from_slice(self.author_seed.expose());
        match &self.role_seed {
            Some(seed) => {
                out.push(1);
                out.extend_from_slice(seed.expose());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 32]);
            }
        }
        out.push(u8::try_from(self.relays.len()).map_err(|_| Error::Malformed)?);
        for relay in &self.relays {
            out.extend_from_slice(relay);
        }
        out.push(u8::try_from(self.name.len()).map_err(|_| Error::TooLong)?);
        out.extend_from_slice(self.name.as_bytes());
        Ok(out)
    }

    pub(super) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut at = 0usize;
        let mut take = |len: usize| -> Result<&[u8], Error> {
            let part = bytes.get(at..at + len).ok_or(Error::Integrity)?;
            at += len;
            Ok(part)
        };
        let array32 = |part: &[u8]| -> Result<[u8; 32], Error> {
            part.try_into().map_err(|_| Error::Integrity)
        };
        if take(1)? != [ROW_VERSION] {
            return Err(Error::Integrity);
        }
        let community_id = array32(take(32)?)?;
        let fragment: [u8; 16] = take(16)?.try_into().map_err(|_| Error::Integrity)?;
        let joined_at = u64::from_be_bytes(take(8)?.try_into().map_err(|_| Error::Integrity)?);
        let author_seed = Secret::new(array32(take(32)?)?);
        let has_role = take(1)? == [1];
        let role = array32(take(32)?)?;
        let role_seed = has_role.then(|| Secret::new(role));
        let count = usize::from(*take(1)?.first().ok_or(Error::Integrity)?);
        if count == 0 || count > COMMUNITY_RELAY_MAX {
            return Err(Error::Integrity);
        }
        let mut relays = Vec::with_capacity(count);
        for _ in 0..count {
            relays.push(array32(take(32)?)?);
        }
        let name_len = usize::from(*take(1)?.first().ok_or(Error::Integrity)?);
        let name = String::from_utf8(take(name_len)?.to_vec()).map_err(|_| Error::Integrity)?;
        if at != bytes.len() {
            return Err(Error::Integrity);
        }
        Ok(CommunityRow {
            community_id,
            fragment,
            joined_at,
            author_seed,
            role_seed,
            relays,
            name,
        })
    }
}

/// The cursor of one relay of a community, and the times of its next
/// pulls.
struct CursorRow {
    relay: [u8; 32],
    cursor: RelayCursor,
    /// The next steady-state pull (`COM-174`).
    pull_at: u64,
    /// The next pull of the history behind the first page (`COM-092`).
    backfill_at: u64,
}

impl CursorRow {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CURSOR_ROW_LEN);
        out.extend_from_slice(&self.relay);
        out.extend_from_slice(&self.cursor.to_bytes());
        out.extend_from_slice(&self.pull_at.to_be_bytes());
        out.extend_from_slice(&self.backfill_at.to_be_bytes());
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        // A row of the first form holds a cursor with no backfill window.
        let cursor_len = match bytes.len() {
            CURSOR_ROW_LEN => CURSOR_LEN,
            len if len == CURSOR_ROW_LEN - CURSOR_LEN + CURSOR_LEN_V1 => CURSOR_LEN_V1,
            _ => return Err(Error::Integrity),
        };
        let (relay, rest) = bytes.split_at(32);
        let (cursor, rest) = rest.split_at(cursor_len);
        let (pull_at, backfill_at) = rest.split_at(8);
        Ok(CursorRow {
            relay: relay.try_into().map_err(|_| Error::Integrity)?,
            cursor: RelayCursor::from_bytes(cursor).map_err(|_| Error::Integrity)?,
            pull_at: u64::from_be_bytes(pull_at.try_into().map_err(|_| Error::Integrity)?),
            backfill_at: u64::from_be_bytes(backfill_at.try_into().map_err(|_| Error::Integrity)?),
        })
    }
}

/// One community as the platform lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityInfo {
    /// The community.
    pub community_id: [u8; 32],
    /// The name of its metadata, or empty before one verifies.
    pub name: String,
    /// The relays that serve it.
    pub relays: Vec<[u8; 32]>,
    /// The time of the join, in Unix seconds.
    pub joined_at: u64,
    /// The count of the records that this device holds.
    pub records: usize,
    /// Whether this device holds an owner role of it.
    pub is_owner: bool,
    /// The count of the records of this device that a relay has not taken.
    pub pending: usize,
}

/// One post of a community as the platform lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityPostInfo {
    /// The hash of the post, which names it.
    pub key: [u8; 32],
    /// The authoring pseudonym.
    pub author: [u8; 32],
    /// The position in the chain of that pseudonym.
    pub index: u32,
    /// The time the post reached this device, in Unix seconds.
    pub at: u64,
    /// Whether a verified checkpoint covers the post (§12.4.1).
    pub is_settled: bool,
    /// Whether this device wrote the post.
    pub is_own: bool,
    /// Whether a ban stands on the author (`COM-298`).
    pub is_author_banned: bool,
}

/// A community row, the view of its records, and those records with the
/// time each one arrived.
type HeldView = (
    CommunityRow,
    umbra_core::community::view::CommunityView,
    Vec<(u64, Vec<u8>)>,
);

/// One pull that is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityPull {
    /// The community.
    pub community_id: [u8; 32],
    /// The relay.
    pub relay: [u8; 32],
    /// The encoded `PullRequest`.
    pub request: Vec<u8>,
    /// What the pull asks for.
    pub kind: PullKind,
}

/// What one pull asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullKind {
    /// The records after the cursor of the relay (`COM-191`).
    Steady,
    /// The history behind the first page, from this `seq` (`COM-092`).
    Backfill(u64),
    /// The control chain from an `epoch_index` (`COM-196`).
    Control,
    /// The metadata from a `meta_index` (`COM-196`).
    Meta,
}

fn chain_request(community_id: [u8; 32], selector: Selector, from: u64) -> Result<Vec<u8>, Error> {
    Ok(PullRequest {
        community_id,
        selector,
        pseudonym: [0; 32],
        from,
        count: PULL_BATCH,
    }
    .encode()?
    .to_vec())
}

fn cursor_key(community_id: &[u8; 32], relay: &[u8; 32]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(community_id);
    key[32..].copy_from_slice(relay);
    key
}

fn record_key(community_id: &[u8; 32], record: &[u8]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(community_id);
    key[32..].copy_from_slice(&sha3_256(&[record]));
    key
}

fn draw<R: CryptoRng + ?Sized>(rng: &mut R) -> u32 {
    let mut bytes = [0u8; 4];
    rng.fill_bytes(&mut bytes);
    u32::from_be_bytes(bytes)
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn community_row(
        &self,
        community_id: &[u8; 32],
    ) -> Result<Option<(RowId, CommunityRow)>, Error> {
        let store = &self.open_ref()?.store;
        let row_id = store.row_id(COMMUNITY, community_id);
        match store.get(COMMUNITY, &row_id)? {
            Some(plain) => Ok(Some((row_id, CommunityRow::parse(&plain)?))),
            None => Ok(None),
        }
    }

    /// Joins the community of a link. `relays` are the relays of the
    /// relay set that its hints name (`COM-246`); the relays of a verified
    /// metadata record replace them later (`COM-247`). A join of a held
    /// community keeps it as it is.
    pub fn join_community<R: CryptoRng + ?Sized>(
        &mut self,
        link: &CommunityLink,
        relays: Vec<[u8; 32]>,
        now: u64,
        rng: &mut R,
    ) -> Result<[u8; 32], Error> {
        if self.community_row(&link.community_id)?.is_some() {
            return Ok(link.community_id);
        }
        // COM-027: the authoring seed comes from the device CSPRNG.
        let mut seed = Secret::new([0u8; 32]);
        rng.fill_bytes(seed.expose_mut());
        let row = CommunityRow {
            community_id: link.community_id,
            fragment: link.fragment,
            joined_at: now,
            author_seed: seed,
            role_seed: None,
            relays,
            name: String::new(),
        };
        self.put_community(&row, rng)?;
        Ok(link.community_id)
    }

    pub(super) fn put_community<R: CryptoRng + ?Sized>(
        &mut self,
        row: &CommunityRow,
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = Zeroizing::new(row.encode()?);
        let open = self.open_mut()?;
        let row_id = open.store.row_id(COMMUNITY, &row.community_id);
        let mut batch = open.store.begin();
        batch.put(COMMUNITY, row_id, None, &value, rng)?;
        Ok(batch.commit()?)
    }

    /// Each community of this device, in the order of the join.
    pub fn communities(&self) -> Result<Vec<CommunityInfo>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (row_id, plain) in store.list(COMMUNITY, None)? {
            let row = CommunityRow::parse(&Zeroizing::new(plain))?;
            let records = store.list(COMMUNITY_RECORD, Some(&row_id))?.len();
            out.push(CommunityInfo {
                community_id: row.community_id,
                name: row.name,
                relays: row.relays,
                joined_at: row.joined_at,
                records,
                is_owner: row.role_seed.is_some(),
                pending: self.community_pending(&row_id)?,
            });
        }
        out.sort_by_key(|info| (info.joined_at, info.community_id));
        Ok(out)
    }

    /// The link of a community, with the hints of its relays (`COM-245`).
    pub fn community_link(&self, community_id: &[u8; 32]) -> Result<CommunityLink, Error> {
        let (_, row) = self.community_row(community_id)?.ok_or(Error::NotFound)?;
        Ok(CommunityLink {
            community_id: row.community_id,
            hints: row
                .relays
                .iter()
                .map(umbra_core::attach::seal::relay_hint)
                .collect(),
            fragment: row.fragment,
        })
    }

    /// Leaves a community: its row, its cursors, and its records go.
    pub fn leave_community(&mut self, community_id: &[u8; 32]) -> Result<(), Error> {
        let Some((row_id, _)) = self.community_row(community_id)? else {
            return Ok(());
        };
        let open = self.open_mut()?;
        let owned: Vec<(TableId, RowId)> = [
            COMMUNITY_CURSOR,
            COMMUNITY_RECORD,
            COMMUNITY_JOIN,
            super::posting::COMMUNITY_AUTHOR,
            super::posting::COMMUNITY_OUTBOX,
            super::reports::COMMUNITY_REPORT,
        ]
        .into_iter()
        .map(|table| {
            Ok::<_, Error>(
                open.store
                    .list(table, Some(&row_id))?
                    .into_iter()
                    .map(move |(id, _)| (table, id))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
        let mut batch = open.store.begin();
        for (table, id) in owned {
            batch.delete(table, id);
        }
        batch.delete(COMMUNITY, row_id);
        Ok(batch.commit()?)
    }

    /// Each pull that is due at `now`: a steady-state pull of each relay of
    /// each community at its own `PULL_INTERVAL` (`COM-174`), and one pull
    /// of the history behind the first page in each interval (`COM-092`).
    /// The next time of each one moves here, thus a pull that fails waits
    /// for the next interval.
    pub fn take_community_pulls<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<CommunityPull>, Error> {
        let mut rows = Vec::new();
        {
            let store = &self.open_ref()?.store;
            for (row_id, plain) in store.list(COMMUNITY, None)? {
                let row = CommunityRow::parse(&Zeroizing::new(plain))?;
                for relay in &row.relays {
                    let key = store.row_id(COMMUNITY_CURSOR, &cursor_key(&row.community_id, relay));
                    let cursor = match store.get(COMMUNITY_CURSOR, &key)? {
                        Some(plain) => CursorRow::parse(&plain)?,
                        None => CursorRow {
                            relay: *relay,
                            cursor: RelayCursor::default(),
                            pull_at: 0,
                            backfill_at: 0,
                        },
                    };
                    rows.push((row_id, row.community_id, key, cursor));
                }
            }
        }
        let mut pulls = Vec::new();
        let mut moved = Vec::new();
        for (owner, community_id, key, mut cursor) in rows {
            let mut did_move = false;
            if cursor.pull_at <= now {
                let request = cursor.cursor.request(community_id).encode()?;
                pulls.push(CommunityPull {
                    community_id,
                    relay: cursor.relay,
                    request: request.to_vec(),
                    kind: PullKind::Steady,
                });
                cursor.pull_at = now.saturating_add(pull_interval(draw(rng)));
                did_move = true;
            }
            if cursor.backfill_at <= now {
                if let Some(request) = cursor.cursor.backfill_request(community_id) {
                    pulls.push(CommunityPull {
                        community_id,
                        relay: cursor.relay,
                        request: request.encode()?.to_vec(),
                        kind: PullKind::Backfill(request.from),
                    });
                    cursor.backfill_at = now.saturating_add(pull_interval(draw(rng)));
                    did_move = true;
                }
            }
            if did_move {
                moved.push((owner, key, cursor));
            }
        }
        // COM-196, COM-246: the join pulls the control chain and the
        // metadata from their start, from the first relay of the community.
        let mut joins = Vec::new();
        {
            let store = &self.open_ref()?.store;
            for (owner, plain) in store.list(COMMUNITY, None)? {
                let row = CommunityRow::parse(&Zeroizing::new(plain))?;
                let key = store.row_id(COMMUNITY_JOIN, &row.community_id);
                let mut join = match store.get(COMMUNITY_JOIN, &key)? {
                    Some(plain) => JoinRow::parse(&plain)?,
                    None => JoinRow::new(),
                };
                let (Some(relay), true) = (row.relays.first(), join.retry_at <= now) else {
                    continue;
                };
                if join.control.is_none() && join.meta.is_none() {
                    continue;
                }
                for (next, selector, kind) in [
                    (join.control, Selector::Control, PullKind::Control),
                    (join.meta, Selector::Meta, PullKind::Meta),
                ] {
                    if let Some(from) = next {
                        pulls.push(CommunityPull {
                            community_id: row.community_id,
                            relay: *relay,
                            request: chain_request(row.community_id, selector, from)?,
                            kind,
                        });
                    }
                }
                // A pull that gets no answer goes again later.
                join.retry_at = now.saturating_add(PULL_INTERVAL_MAX);
                joins.push((owner, key, join));
            }
        }
        if !moved.is_empty() || !joins.is_empty() {
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for (owner, key, cursor) in &moved {
                batch.put(COMMUNITY_CURSOR, *key, Some(*owner), &cursor.encode(), rng)?;
            }
            for (owner, key, join) in &joins {
                batch.put(COMMUNITY_JOIN, *key, Some(*owner), &join.encode(), rng)?;
            }
            batch.commit()?;
        }
        Ok(pulls)
    }

    /// Takes the page that answers `pull`, and keeps each record that this
    /// device does not hold. A full page under the sequence selector gives
    /// the next pull of the same session (`COM-194`).
    pub fn on_community_page<R: CryptoRng + ?Sized>(
        &mut self,
        pull: &CommunityPull,
        page: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Option<CommunityPull>, Error> {
        let response = PullResponse::parse(page)?;
        if response.community_id != pull.community_id {
            return Err(Error::Malformed);
        }
        let Some((owner, _)) = self.community_row(&pull.community_id)? else {
            // The user left the community while the pull was out.
            return Ok(None);
        };
        let open = self.open_mut()?;
        let key = open.store.row_id(
            COMMUNITY_CURSOR,
            &cursor_key(&pull.community_id, &pull.relay),
        );
        let mut cursor = match open.store.get(COMMUNITY_CURSOR, &key)? {
            Some(plain) => CursorRow::parse(&plain)?,
            None => CursorRow {
                relay: pull.relay,
                cursor: RelayCursor::default(),
                pull_at: now,
                backfill_at: now,
            },
        };
        let join_key = open.store.row_id(COMMUNITY_JOIN, &pull.community_id);
        let mut join = match open.store.get(COMMUNITY_JOIN, &join_key)? {
            Some(plain) => Some(JoinRow::parse(&plain)?),
            None => None,
        };
        let again = match pull.kind {
            PullKind::Backfill(from) => {
                cursor.cursor.on_backfill_page(&response, from);
                None
            }
            PullKind::Steady => cursor
                .cursor
                .on_page(&response)?
                .pull_again
                .then_some((Selector::Sequence, 0)),
            // COM-411: a page of a chain asks for the next one at once, and
            // an empty page ends the pulls of that chain.
            PullKind::Control | PullKind::Meta => {
                let (selector, held) = match pull.kind {
                    PullKind::Control => (
                        Selector::Control,
                        &mut join.get_or_insert_with(JoinRow::new).control,
                    ),
                    _ => (
                        Selector::Meta,
                        &mut join.get_or_insert_with(JoinRow::new).meta,
                    ),
                };
                let goes_on = !response.entries.is_empty();
                *held = goes_on.then_some(response.next);
                goes_on.then_some((selector, response.next))
            }
        };
        let mut fresh = Vec::new();
        for entry in &response.entries {
            let record_id = open.store.row_id(
                COMMUNITY_RECORD,
                &record_key(&pull.community_id, entry.record),
            );
            if open.store.get(COMMUNITY_RECORD, &record_id)?.is_none() {
                fresh.push((record_id, entry.record));
            }
        }
        let fresh_count = fresh.len();
        let mut batch = open.store.begin();
        if matches!(pull.kind, PullKind::Steady | PullKind::Backfill(_)) {
            batch.put(COMMUNITY_CURSOR, key, Some(owner), &cursor.encode(), rng)?;
        }
        if let Some(join) = &join {
            batch.put(COMMUNITY_JOIN, join_key, Some(owner), &join.encode(), rng)?;
        }
        for (record_id, record) in fresh {
            let mut value = Vec::with_capacity(8 + record.len());
            value.extend_from_slice(&now.to_be_bytes());
            value.extend_from_slice(record);
            batch.put(COMMUNITY_RECORD, record_id, Some(owner), &value, rng)?;
        }
        batch.commit()?;
        if fresh_count > 0 {
            self.name_from_view(&pull.community_id, now, rng)?;
        }
        let Some((selector, from)) = again else {
            return Ok(None);
        };
        let request = match selector {
            Selector::Sequence => cursor.cursor.request(pull.community_id).encode()?.to_vec(),
            _ => chain_request(pull.community_id, selector, from)?,
        };
        Ok(Some(CommunityPull {
            community_id: pull.community_id,
            relay: pull.relay,
            request,
            kind: pull.kind,
        }))
    }

    /// What a reader shows of a community from the records that this device
    /// holds (`umbra_core::community::view`).
    fn community_view(&self, community_id: &[u8; 32], now: u64) -> Result<HeldView, Error> {
        let (_, row) = self.community_row(community_id)?.ok_or(Error::NotFound)?;
        let records = self.community_records(community_id)?;
        let link = CommunityLink {
            community_id: *community_id,
            hints: Vec::new(),
            fragment: row.fragment,
        };
        let slices: Vec<&[u8]> = records
            .iter()
            .map(|(_, record)| record.as_slice())
            .collect();
        let view = umbra_core::community::view::view(community_id, &link.meta_key(), &slices, now);
        Ok((row, view, records))
    }

    /// The view of a community, for the moderation of this device.
    pub(super) fn community_view_of(
        &self,
        community_id: &[u8; 32],
        now: u64,
    ) -> Result<umbra_core::community::view::CommunityView, Error> {
        Ok(self.community_view(community_id, now)?.1)
    }

    /// Each post of a community that the view admits, oldest first. A post
    /// that a moderation epoch removes, or that its author withdrew, is
    /// not here.
    pub fn community_posts(
        &self,
        community_id: &[u8; 32],
        now: u64,
    ) -> Result<Vec<CommunityPostInfo>, Error> {
        let (row, view, records) = self.community_view(community_id, now)?;
        let own = umbra_core::community::identity::AuthorIdentity::from_seed(&row.author_seed)
            .pseudonym();
        let arrived: std::collections::BTreeMap<[u8; 32], u64> = records
            .iter()
            .map(|(at, record)| (sha3_256(&[record]), *at))
            .collect();
        let mut out: Vec<CommunityPostInfo> = view
            .posts
            .into_iter()
            .filter(|post| !post.is_removed && !post.is_withdrawn)
            .map(|post| CommunityPostInfo {
                key: post.hash,
                author: post.pseudonym,
                index: post.index,
                at: arrived.get(&post.hash).copied().unwrap_or(0),
                is_settled: post.is_settled,
                is_own: post.pseudonym == own,
                is_author_banned: post.is_author_banned,
            })
            .collect();
        out.sort_by_key(|post| (post.at, post.author, post.index));
        Ok(out)
    }

    /// Writes the text of one post into `sink`. A post of another kind than
    /// a text shows no text.
    pub fn render_community_post(
        &self,
        community_id: &[u8; 32],
        key: &[u8; 32],
        sink: &mut dyn crate::Sink,
    ) -> Result<(), Error> {
        let store = &self.open_ref()?.store;
        let mut natural = [0u8; 64];
        natural[..32].copy_from_slice(community_id);
        natural[32..].copy_from_slice(key);
        let row_id = store.row_id(COMMUNITY_RECORD, &natural);
        let plain = Zeroizing::new(
            store
                .get(COMMUNITY_RECORD, &row_id)?
                .ok_or(Error::NotFound)?,
        );
        let record = plain.get(8..).ok_or(Error::Integrity)?;
        let post = umbra_core::community::record::CommunityPost::parse(record)?;
        let rich = umbra_wire::app::rich::RichRecord::parse(
            post.body,
            umbra_wire::app::Channel::Community,
        )?;
        let text = match rich.inner_kind {
            umbra_wire::app::AppKind::Text => {
                core::str::from_utf8(rich.inner_body).map_err(|_| Error::Integrity)?
            }
            _ => "",
        };
        let mut units = Zeroizing::new(Vec::with_capacity(text.len()));
        units.extend(text.encode_utf16());
        sink.put(&units);
        Ok(())
    }

    /// The name of a community from its verified metadata, for a device
    /// that joined by a link and holds none yet (`COM-247`).
    fn name_from_view<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let (mut row, view, _) = self.community_view(community_id, now)?;
        let Some(name) = view.name.filter(|name| *name != row.name) else {
            return Ok(());
        };
        row.name = name;
        self.put_community(&row, rng)
    }

    /// Each record of a community that this device holds, with the time it
    /// arrived, oldest first.
    pub fn community_records(&self, community_id: &[u8; 32]) -> Result<Vec<(u64, Vec<u8>)>, Error> {
        let Some((owner, _)) = self.community_row(community_id)? else {
            return Err(Error::NotFound);
        };
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (_, plain) in store.list(COMMUNITY_RECORD, Some(&owner))? {
            if plain.len() < 8 {
                return Err(Error::Integrity);
            }
            let (at, record) = plain.split_at(8);
            let at = u64::from_be_bytes(at.try_into().map_err(|_| Error::Integrity)?);
            out.push((at, record.to_vec()));
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_community_row_round_trips_and_rejects_a_bad_count() {
        let row = CommunityRow {
            community_id: [1; 32],
            fragment: [2; 16],
            joined_at: 77,
            author_seed: Secret::new([3; 32]),
            role_seed: Some(Secret::new([4; 32])),
            relays: vec![[5; 32], [6; 32], [7; 32]],
            name: "trail club".into(),
        };
        let bytes = row.encode().unwrap();
        let back = CommunityRow::parse(&bytes).unwrap();
        assert_eq!(back.community_id, row.community_id);
        assert_eq!(back.fragment, row.fragment);
        assert_eq!(back.joined_at, 77);
        assert_eq!(back.author_seed.expose(), &[3; 32]);
        assert_eq!(back.role_seed.unwrap().expose(), &[4; 32]);
        assert_eq!(back.relays, row.relays);
        assert_eq!(back.name, "trail club");
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(CommunityRow::parse(&extra).is_err());
        let empty = CommunityRow {
            relays: Vec::new(),
            ..row
        };
        assert!(empty.encode().is_err());
    }

    #[test]
    fn a_join_row_round_trips() {
        let row = JoinRow {
            control: Some(30),
            meta: None,
            retry_at: 99,
        };
        let back = JoinRow::parse(&row.encode()).unwrap();
        assert_eq!(
            (back.control, back.meta, back.retry_at),
            (Some(30), None, 99)
        );
        let fresh = JoinRow::parse(&JoinRow::new().encode()).unwrap();
        assert_eq!((fresh.control, fresh.meta), (Some(0), Some(0)));
        assert!(JoinRow::parse(&[0; 3]).is_err());
    }

    #[test]
    fn a_cursor_row_round_trips() {
        let row = CursorRow {
            relay: [9; 32],
            cursor: RelayCursor::default(),
            pull_at: 5,
            backfill_at: 6,
        };
        let back = CursorRow::parse(&row.encode()).unwrap();
        assert_eq!(back.relay, [9; 32]);
        assert_eq!(back.cursor, RelayCursor::default());
        assert_eq!((back.pull_at, back.backfill_at), (5, 6));
    }
}
