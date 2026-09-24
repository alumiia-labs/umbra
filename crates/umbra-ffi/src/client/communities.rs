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
        pull::{PullResponse, RelayCursor, CURSOR_LEN},
        pull_interval, COMMUNITY_RELAY_MAX, META_NAME_MAX,
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
const COMMUNITY_RECORD: TableId = TableId(0x23);

const ROW_VERSION: u8 = 0x01;
const CURSOR_ROW_LEN: usize = 32 + CURSOR_LEN + 8 + 8;

/// One community of this device.
struct CommunityRow {
    community_id: [u8; 32],
    fragment: [u8; 16],
    joined_at: u64,
    /// The seed of the authoring identity of this device in the community.
    author_seed: Secret<32>,
    /// The seed of the owner role identity, on a device that owns the
    /// community.
    role_seed: Option<Secret<32>>,
    relays: Vec<[u8; 32]>,
    name: String,
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

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
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
        if bytes.len() != CURSOR_ROW_LEN {
            return Err(Error::Integrity);
        }
        let (relay, rest) = bytes.split_at(32);
        let (cursor, rest) = rest.split_at(CURSOR_LEN);
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
}

/// One pull that is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityPull {
    /// The community.
    pub community_id: [u8; 32],
    /// The relay.
    pub relay: [u8; 32],
    /// The encoded `PullRequest`.
    pub request: Vec<u8>,
    /// The `from` of a pull of the history behind the first page, or none
    /// for a steady-state pull.
    pub backfill_from: Option<u64>,
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

    fn put_community<R: CryptoRng + ?Sized>(
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
        let owned: Vec<(TableId, RowId)> = [COMMUNITY_CURSOR, COMMUNITY_RECORD]
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
                    backfill_from: None,
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
                        backfill_from: Some(request.from),
                    });
                    cursor.backfill_at = now.saturating_add(pull_interval(draw(rng)));
                    did_move = true;
                }
            }
            if did_move {
                moved.push((owner, key, cursor));
            }
        }
        if !moved.is_empty() {
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for (owner, key, cursor) in &moved {
                batch.put(COMMUNITY_CURSOR, *key, Some(*owner), &cursor.encode(), rng)?;
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
        let again = match pull.backfill_from {
            Some(from) => {
                cursor.cursor.on_backfill_page(&response, from);
                false
            }
            None => cursor.cursor.on_page(&response)?.pull_again,
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
        let mut batch = open.store.begin();
        batch.put(COMMUNITY_CURSOR, key, Some(owner), &cursor.encode(), rng)?;
        for (record_id, record) in fresh {
            let mut value = Vec::with_capacity(8 + record.len());
            value.extend_from_slice(&now.to_be_bytes());
            value.extend_from_slice(record);
            batch.put(COMMUNITY_RECORD, record_id, Some(owner), &value, rng)?;
        }
        batch.commit()?;
        if !again {
            return Ok(None);
        }
        let request = cursor.cursor.request(pull.community_id).encode()?;
        Ok(Some(CommunityPull {
            community_id: pull.community_id,
            relay: pull.relay,
            request: request.to_vec(),
            backfill_from: None,
        }))
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
