//! The dead-channel state of each contact (Part 3 §3.2.6): whether the
//! channel is dead, the address of the new queue that its blob carries,
//! the blob of the last week that this device wrote, and the time of the
//! next fetch of the blob of the peer.
//!
//! A row exists while the channel is dead or silent, and while a blob of
//! this device waits for its `CDEL`. The store keeps it across runs: the
//! state of a week outlives a run.

use umbra_core::{
    attach::CHUNK_SIZE,
    session::{
        dead::{seal_blob, week_of},
        node::stored_dead_channel,
    },
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::{
    rand_core::CryptoRng,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
    zeroize::Zeroizing,
};
use umbra_wire::address::LEN as ADDRESS_LEN;

use super::{info_of, Client, ConversationId, Outgoing, MESSAGE_PREFIX, QUEUE_ID_LEN};
use crate::{Delivery, Error, MsgRef};

/// The dead-channel state of each contact, by conversation.
const DEAD_CHANNEL: TableId = TableId(0x1E);

/// `DEAD_CHANNEL_SILENCE` of Part 3 §3.2.4, in milliseconds.
pub const DEAD_CHANNEL_SILENCE_MS: u64 = 7 * 86_400 * 1_000;
/// The window of `NET-188`, in seconds.
const FETCH_WINDOW: u64 = 86_400;
/// No week: the value of a week field that names none.
const NO_WEEK: u32 = u32::MAX;
/// The relays of one blob (`BACKUP_REPLICAS`).
const BLOB_RELAYS: usize = umbra_core::attach::BACKUP_REPLICAS;

/// The row: the flag of a dead channel, the time it died, the address of
/// the new queue, the week, the credential and the relays of the blob of
/// this device, and the week and the time of the next fetch.
const ROW_LEN: usize = 1 + 8 + 1 + ADDRESS_LEN + 4 + 32 + 1 + 32 * BLOB_RELAYS + 4 + 8;

struct DeadRow {
    dead: bool,
    dead_since: u64,
    address: Option<Zeroizing<Vec<u8>>>,
    written_week: u32,
    written_cred: Secret<32>,
    written_relays: Vec<[u8; 32]>,
    fetch_week: u32,
    fetch_at: u64,
}

impl DeadRow {
    fn empty() -> Self {
        DeadRow {
            dead: false,
            dead_since: 0,
            address: None,
            written_week: NO_WEEK,
            written_cred: Secret::new([0; 32]),
            written_relays: Vec::new(),
            fetch_week: NO_WEEK,
            fetch_at: 0,
        }
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(ROW_LEN));
        out.push(u8::from(self.dead));
        out.extend_from_slice(&self.dead_since.to_be_bytes());
        match &self.address {
            Some(address) => {
                out.push(1);
                out.extend_from_slice(address);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; ADDRESS_LEN]);
            }
        }
        out.extend_from_slice(&self.written_week.to_be_bytes());
        out.extend_from_slice(self.written_cred.expose());
        let count = self.written_relays.len().min(BLOB_RELAYS);
        out.push(u8::try_from(count).unwrap_or(0));
        for at in 0..BLOB_RELAYS {
            out.extend_from_slice(self.written_relays.get(at).unwrap_or(&[0; 32]));
        }
        out.extend_from_slice(&self.fetch_week.to_be_bytes());
        out.extend_from_slice(&self.fetch_at.to_be_bytes());
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ROW_LEN {
            return Err(Error::Integrity);
        }
        let mut at = 0usize;
        let mut take = |len: usize| -> Result<&[u8], Error> {
            let part = bytes.get(at..at + len).ok_or(Error::Integrity)?;
            at += len;
            Ok(part)
        };
        let array = |part: &[u8]| -> Result<[u8; 8], Error> {
            part.try_into().map_err(|_| Error::Integrity)
        };
        let dead = take(1)? == [1];
        let dead_since = u64::from_be_bytes(array(take(8)?)?);
        let has_address = take(1)? == [1];
        let address = take(ADDRESS_LEN)?;
        let address = has_address.then(|| Zeroizing::new(address.to_vec()));
        let week = |part: &[u8]| -> Result<u32, Error> {
            Ok(u32::from_be_bytes(
                part.try_into().map_err(|_| Error::Integrity)?,
            ))
        };
        let written_week = week(take(4)?)?;
        let cred: [u8; 32] = take(32)?.try_into().map_err(|_| Error::Integrity)?;
        let count = usize::from(*take(1)?.first().ok_or(Error::Integrity)?);
        let mut written_relays = Vec::new();
        for index in 0..BLOB_RELAYS {
            let relay: [u8; 32] = take(32)?.try_into().map_err(|_| Error::Integrity)?;
            if index < count {
                written_relays.push(relay);
            }
        }
        let fetch_week = week(take(4)?)?;
        let fetch_at = u64::from_be_bytes(array(take(8)?)?);
        Ok(DeadRow {
            dead,
            dead_since,
            address,
            written_week,
            written_cred: Secret::new(cred),
            written_relays,
            fetch_week,
            fetch_at,
        })
    }
}

/// One step of the dead-channel work for the transfer run.
pub enum DeadWork {
    /// Make a new queue for the contact (`NET-182`): its address is not
    /// here yet.
    Rotate {
        /// The contact, by the identifier of its first queue.
        contact: [u8; 32],
    },
    /// Write the blob of this device for `week` (`NET-183`, `NET-184`).
    Write {
        /// The conversation.
        conversation: ConversationId,
        /// The week.
        week: u32,
        /// The `chunk_id`.
        handle: [u8; 32],
        /// `cred_sk` of the chunk (`ATT-140`).
        cred: Secret<32>,
        /// The public half of `read_sk`.
        read_pk: [u8; 32],
        /// The padded chunk.
        chunk: Vec<u8>,
    },
    /// Read the blob of the peer for `week` (`NET-186`).
    Read {
        /// The conversation.
        conversation: ConversationId,
        /// The `chunk_id`.
        handle: [u8; 32],
        /// `read_sk` of the chunk.
        read: Secret<32>,
        /// The key that opens the blob.
        blob_key: Secret<32>,
    },
    /// Erase the blob of an earlier week (`NET-185`), or of a channel that
    /// lives again.
    Erase {
        /// The `chunk_id`.
        handle: [u8; 32],
        /// `cred_sk` of the chunk.
        cred: Secret<32>,
        /// The relays that hold it.
        relays: Vec<[u8; 32]>,
    },
}

fn read_pk(read: &Secret<32>) -> [u8; 32] {
    *XPublic::from(&StaticSecret::from(*read.expose())).as_bytes()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn dead_row(&self, conversation: ConversationId) -> Result<Option<DeadRow>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(DEAD_CHANNEL, &conversation.0);
        let Some(plain) = store.get(DEAD_CHANNEL, &row)? else {
            return Ok(None);
        };
        DeadRow::parse(&Zeroizing::new(plain)).map(Some)
    }

    fn put_dead_row<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        row: Option<&DeadRow>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let key = open.store.row_id(DEAD_CHANNEL, &conversation.0);
        let mut batch = open.store.begin();
        match row {
            Some(row) => batch.put(DEAD_CHANNEL, key, None, &row.encode(), rng)?,
            None => batch.delete(DEAD_CHANNEL, key),
        }
        Ok(batch.commit()?)
    }

    /// The identifier of the first queue of a contact, which names it to
    /// the node.
    pub fn contact_id_of(&self, conversation: ConversationId) -> Result<[u8; 32], Error> {
        let store = &self.open_ref()?.store;
        let plain = Zeroizing::new(
            store
                .get(TableId::CONTACT, &conversation.0)?
                .ok_or(Error::NotFound)?,
        );
        plain
            .get(..QUEUE_ID_LEN)
            .and_then(|id| id.try_into().ok())
            .ok_or(Error::Integrity)
    }

    /// A relay refused a record to the newest address of a contact with
    /// `REJECTED`: the channel is dead (Part 3 §3.2.6).
    pub fn channel_dead<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut row = self.dead_row(conversation)?.unwrap_or_else(DeadRow::empty);
        if row.dead {
            return Ok(());
        }
        row.dead = true;
        row.dead_since = now;
        row.address = None;
        self.put_dead_row(conversation, Some(&row), rng)
    }

    /// The contact reads a new queue: a dead channel names it in its blob.
    pub fn dead_queue_rotated<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        address: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut row) = self.dead_row(conversation)? else {
            return Ok(());
        };
        if !row.dead || address.len() != ADDRESS_LEN {
            return Ok(());
        }
        row.address = Some(Zeroizing::new(address.to_vec()));
        self.put_dead_row(conversation, Some(&row), rng)
    }

    /// The peer moved, on the channel or by its blob: the channel lives,
    /// and the blob of this device goes (`NET-190`). The result is the
    /// erase of that blob, when one was written.
    pub fn dead_channel_ended<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<Option<DeadWork>, Error> {
        let Some(row) = self.dead_row(conversation)? else {
            return Ok(None);
        };
        let erase = self.erase_of(conversation, &row)?;
        self.put_dead_row(conversation, None, rng)?;
        Ok(erase)
    }

    fn erase_of(
        &self,
        conversation: ConversationId,
        row: &DeadRow,
    ) -> Result<Option<DeadWork>, Error> {
        if row.written_week == NO_WEEK || row.written_relays.is_empty() {
            return Ok(None);
        }
        let (secret, own_pk, _) = self.dead_channel_of(conversation)?;
        Ok(Some(DeadWork::Erase {
            handle: secret.handle(&own_pk, row.written_week),
            cred: Secret::new(*row.written_cred.expose()),
            relays: row.written_relays.clone(),
        }))
    }

    fn dead_channel_of(
        &self,
        conversation: ConversationId,
    ) -> Result<(umbra_crypto::dead::DeadChannel, [u8; 32], [u8; 32]), Error> {
        let store = &self.open_ref()?.store;
        let plain = Zeroizing::new(
            store
                .get(TableId::CONTACT, &conversation.0)?
                .ok_or(Error::NotFound)?,
        );
        let state = plain.get(QUEUE_ID_LEN..).ok_or(Error::Integrity)?;
        Ok(stored_dead_channel(state, &self.root_identity()?)?)
    }

    /// The blob of `week` is at `relays` under `cred`. The result is the
    /// erase of the blob of the week before (`NET-185`).
    pub fn dead_blob_written<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        week: u32,
        cred: Secret<32>,
        relays: Vec<[u8; 32]>,
        rng: &mut R,
    ) -> Result<Option<DeadWork>, Error> {
        let Some(mut row) = self.dead_row(conversation)? else {
            return Ok(None);
        };
        let erase = if row.written_week == week {
            None
        } else {
            self.erase_of(conversation, &row)?
        };
        row.written_week = week;
        row.written_cred = cred;
        row.written_relays = relays;
        self.put_dead_row(conversation, Some(&row), rng)?;
        Ok(erase)
    }

    /// Each pairwise conversation whose oldest record with no delivery
    /// receipt is older than `DEAD_CHANNEL_SILENCE` (`NET-186`).
    pub fn silent_conversations(&self, now_ms: u64) -> Result<Vec<ConversationId>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (row, plain) in store.list(TableId::CONTACT, None)? {
            drop(Zeroizing::new(plain));
            let conversation = ConversationId(row);
            let mut is_silent = false;
            for (_, message) in store.list(TableId::MESSAGE, Some(&conversation.0))? {
                let message = Zeroizing::new(message);
                let Ok(info) = info_of(&message) else {
                    continue;
                };
                if info.outgoing
                    && info.delivery == Delivery::Accepted
                    && now_ms.saturating_sub(info.stored_at_ms) >= DEAD_CHANNEL_SILENCE_MS
                {
                    is_silent = true;
                    break;
                }
            }
            if is_silent {
                out.push(conversation);
            }
        }
        Ok(out)
    }

    /// NET-193: each record of a conversation that a relay took and that
    /// holds no delivery receipt goes to the send path again. The receiver
    /// drops a copy that it holds by its `msg_id`.
    pub fn resend_unreceipted(&mut self, conversation: ConversationId) -> Result<(), Error> {
        let store = &self.open_ref()?.store;
        let mut records = Vec::new();
        for (row, message) in store.list(TableId::MESSAGE, Some(&conversation.0))? {
            let message = Zeroizing::new(message);
            let Ok(info) = info_of(&message) else {
                continue;
            };
            if info.outgoing && info.delivery == Delivery::Accepted {
                let app = message.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
                records.push((
                    info.stored_at_ms,
                    Outgoing {
                        message: MsgRef(row),
                        conversation,
                        app: app.to_vec(),
                    },
                ));
            }
        }
        records.sort_by_key(|(stored_at, _)| *stored_at);
        self.outgoing
            .extend(records.into_iter().map(|(_, record)| record));
        Ok(())
    }

    /// The dead-channel work that is due at `now` in the week of
    /// `consensus_epoch`: a new queue for a dead channel with none, the
    /// blob of each dead channel for the week, and the fetch of the blob
    /// of the peer of each dead or silent channel at a random time in the
    /// window (`NET-182` to `NET-188`).
    pub fn dead_channel_work<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        consensus_epoch: u64,
        silent: &[ConversationId],
        rng: &mut R,
    ) -> Result<Vec<DeadWork>, Error> {
        // NET-203: the week comes from an accepted root, and no root gives
        // no week.
        if consensus_epoch == 0 {
            return Ok(Vec::new());
        }
        let week = week_of(consensus_epoch);
        let mut conversations: Vec<ConversationId> = silent.to_vec();
        let store = &self.open_ref()?.store;
        // A row names its conversation by the key alone, thus each contact
        // is asked.
        for (row, plain) in store.list(TableId::CONTACT, None)? {
            drop(Zeroizing::new(plain));
            let conversation = ConversationId(row);
            if !conversations.contains(&conversation) && self.dead_row(conversation)?.is_some() {
                conversations.push(conversation);
            }
        }
        let mut work = Vec::new();
        for conversation in conversations {
            let is_silent = silent.contains(&conversation);
            let mut row = self.dead_row(conversation)?.unwrap_or_else(DeadRow::empty);
            if !row.dead && !is_silent {
                // The condition ended: the row goes, with its blob.
                work.extend(self.erase_of(conversation, &row)?);
                self.put_dead_row(conversation, None, rng)?;
                continue;
            }
            let (secret, own_pk, peer_pk) = self.dead_channel_of(conversation)?;
            if row.dead {
                match &row.address {
                    None => work.push(DeadWork::Rotate {
                        contact: self.contact_id_of(conversation)?,
                    }),
                    Some(address) if row.written_week != week => {
                        let mut nonce = [0u8; 24];
                        rng.fill_bytes(&mut nonce);
                        let chunk = seal_blob(&secret.blob_key(&own_pk, week), address, nonce)?;
                        debug_assert_eq!(chunk.len(), CHUNK_SIZE);
                        let mut cred = Secret::new([0u8; 32]);
                        rng.fill_bytes(cred.expose_mut());
                        work.push(DeadWork::Write {
                            conversation,
                            week,
                            handle: secret.handle(&own_pk, week),
                            cred,
                            read_pk: read_pk(&secret.read_secret(&own_pk, week)),
                            chunk,
                        });
                    }
                    Some(_) => {}
                }
            }
            // NET-187, NET-188: one fetch in each week, at a uniform time in
            // the 24 hours from the start of the condition or of the week.
            if row.fetch_week != week {
                if row.fetch_at == 0 {
                    let mut draw = [0u8; 8];
                    rng.fill_bytes(&mut draw);
                    row.fetch_at = now.saturating_add(u64::from_be_bytes(draw) % FETCH_WINDOW);
                } else if now >= row.fetch_at {
                    for at_week in [week, week.saturating_sub(1)] {
                        work.push(DeadWork::Read {
                            conversation,
                            handle: secret.handle(&peer_pk, at_week),
                            read: secret.read_secret(&peer_pk, at_week),
                            blob_key: secret.blob_key(&peer_pk, at_week),
                        });
                    }
                    row.fetch_week = week;
                    row.fetch_at = 0;
                }
            }
            self.put_dead_row(conversation, Some(&row), rng)?;
        }
        Ok(work)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use umbra_crypto::{secret::Secret, zeroize::Zeroizing};
    use umbra_wire::address::LEN;

    use super::{DeadRow, NO_WEEK, ROW_LEN};

    #[test]
    fn a_row_reads_back_as_it_was_written() {
        let row = DeadRow {
            dead: true,
            dead_since: 1_800_000_000,
            address: Some(Zeroizing::new(vec![7; LEN])),
            written_week: 3_000,
            written_cred: Secret::new([9; 32]),
            written_relays: vec![[1; 32], [2; 32]],
            fetch_week: NO_WEEK,
            fetch_at: 44,
        };
        let bytes = row.encode();
        assert_eq!(bytes.len(), ROW_LEN);
        let back = DeadRow::parse(&bytes).unwrap();
        assert!(back.dead);
        assert_eq!(back.address.as_deref(), Some(&vec![7; LEN]));
        assert_eq!(back.written_relays, vec![[1; 32], [2; 32]]);
        assert_eq!(
            (back.written_week, back.fetch_week, back.fetch_at),
            (3_000, NO_WEEK, 44)
        );
        assert_eq!(
            DeadRow::parse(&DeadRow::empty().encode()).unwrap().address,
            None
        );
    }
}
