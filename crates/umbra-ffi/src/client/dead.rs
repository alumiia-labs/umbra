//! The dead-channel state of each contact (Part 3 §3.2.6): whether the
//! channel is dead, the address of the new queue that its blob carries,
//! the blob of the last week that this device wrote, and the time of the
//! next fetch of the blob of the peer.
//!
//! A row exists while the channel is dead or silent, and while a blob of
//! this device waits for its `CDEL`. The store keeps it across runs: the
//! state of a week outlives a run.
//!
//! A channel is silent when a relay acknowledged a record of this device
//! and no record of the peer followed in `DEAD_CHANNEL_SILENCE`. A setting
//! of the conversation holds the time of the first such acknowledgment
//! that no record of the peer followed yet. A record of the peer ends it.
//! The two receipts are off by default (`NET-059`), thus the signal reads
//! none of them.

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

use super::{info_of, Client, ConversationId, Outgoing, MESSAGE_PREFIX, QUEUE_ID_LEN, SETTINGS};
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

/// The name of the setting that holds the unanswered time of a
/// conversation, before the identifier of the conversation (Part 3 §3.2.6).
/// That time is the first relay acknowledgment that no record of the peer
/// followed yet, in milliseconds. A conversation with no such
/// acknowledgment holds none.
const UNANSWERED_SETTING: &[u8] = b"unanswered/";

/// The row: the flag of a dead channel, the time it died, the address of
/// the new queue, the week, the credential and the relays of the blob of
/// this device, and the week and the time of the next fetch.
const ROW_LEN: usize = 1 + 8 + 1 + ADDRESS_LEN + 4 + 32 + 1 + 32 * BLOB_RELAYS + 4 + 8;
/// The tail of a row that holds a candidate address of the peer
/// (`NET-190`): one byte and the address. A row of an earlier build, and a
/// row with no candidate, end before it.
const CANDIDATE_TAIL: usize = 1 + ADDRESS_LEN;
/// The tail behind a candidate address. It says whether the record of
/// `NET-191` left for the address. It holds the time this device first held
/// it, and the week of the blob that gave it. A row of an earlier build
/// ends before it: its candidate took no record, and its time starts at the
/// next check.
const SENT_TAIL: usize = 1 + 8 + 4;

struct DeadRow {
    dead: bool,
    dead_since: u64,
    address: Option<Zeroizing<Vec<u8>>>,
    written_week: u32,
    written_cred: Secret<32>,
    written_relays: Vec<[u8; 32]>,
    fetch_week: u32,
    fetch_at: u64,
    /// The address that the blob of the peer gave (`NET-190`). It is the
    /// address of no record of the user.
    candidate: Option<Zeroizing<Vec<u8>>>,
    /// Whether the address of this device went to the candidate, or a
    /// relay answered the bundle of a renewal that went there (`NET-191`,
    /// `NET-330`). A later run then sends nothing more to it.
    candidate_sent: bool,
    /// The time this device first held the candidate, in seconds, from
    /// which `DEAD_CHANNEL_SILENCE` counts to its end. Zero is the row of
    /// an earlier build, and the next check starts it.
    candidate_since: u64,
    /// The week of the blob that gave the candidate, or [`NO_WEEK`].
    candidate_week: u32,
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
            candidate: None,
            candidate_sent: false,
            candidate_since: 0,
            candidate_week: NO_WEEK,
        }
    }

    /// Ends the candidate, with each fact of it.
    fn end_candidate(&mut self) {
        self.candidate = None;
        self.candidate_sent = false;
        self.candidate_since = 0;
        self.candidate_week = NO_WEEK;
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

        // The row has one length. The count names the relays, and zero
        // bytes fill the places after them.
        for at in 0..BLOB_RELAYS {
            out.extend_from_slice(self.written_relays.get(at).unwrap_or(&[0; 32]));
        }

        out.extend_from_slice(&self.fetch_week.to_be_bytes());
        out.extend_from_slice(&self.fetch_at.to_be_bytes());
        if let Some(candidate) = self.candidate.as_ref().filter(|c| c.len() == ADDRESS_LEN) {
            out.push(1);
            out.extend_from_slice(candidate);
            out.push(u8::from(self.candidate_sent));
            out.extend_from_slice(&self.candidate_since.to_be_bytes());
            out.extend_from_slice(&self.candidate_week.to_be_bytes());
        }

        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let with_candidate = ROW_LEN + CANDIDATE_TAIL;
        if ![ROW_LEN, with_candidate, with_candidate + SENT_TAIL].contains(&bytes.len()) {
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
        let candidate = if bytes.len() == ROW_LEN {
            None
        } else {
            if take(1)? != [1] {
                return Err(Error::Integrity);
            }

            Some(Zeroizing::new(take(ADDRESS_LEN)?.to_vec()))
        };
        let (candidate_sent, candidate_since, candidate_week) =
            if bytes.len() == with_candidate + SENT_TAIL {
                let sent = match take(1)? {
                    [0] => false,
                    [1] => true,
                    _ => return Err(Error::Integrity),
                };
                (sent, u64::from_be_bytes(array(take(8)?)?), week(take(4)?)?)
            } else {
                (false, 0, NO_WEEK)
            };

        Ok(DeadRow {
            dead,
            dead_since,
            address,
            written_week,
            written_cred: Secret::new(cred),
            written_relays,
            fetch_week,
            fetch_at,
            candidate,
            candidate_sent,
            candidate_since,
            candidate_week,
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
        /// The week of the blob.
        week: u32,
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
        // Part 7 §7.7 step 2c: the new queue is the rotation that a
        // revocation owed this contact.
        self.rotation_done(conversation, rng)?;
        let Some(mut row) = self.dead_row(conversation)? else {
            return Ok(());
        };
        if address.len() != ADDRESS_LEN {
            return Ok(());
        }

        // NET-191: a candidate that took the address of the queue before
        // takes the new one, one time.
        let sends_again = row.candidate.is_some() && row.candidate_sent;
        if !row.dead && !sends_again {
            return Ok(());
        }

        row.candidate_sent = false;
        if row.dead {
            row.address = Some(Zeroizing::new(address.to_vec()));
        }

        self.put_dead_row(conversation, Some(&row), rng)
    }

    /// Whether the channel of a conversation is dead or silent, or was at
    /// the last check of the dead-channel work: its row is there.
    /// `NET-193` sends the records of such a channel again at a new
    /// address of the peer, and the ones of no other channel.
    pub fn channel_was_down(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(self.dead_row(conversation)?.is_some())
    }

    /// The blob of the peer gave `address` (`NET-190`): a candidate
    /// address, which the row keeps for the next run. The channel holds
    /// the address that it held before, and no record of the user goes to
    /// the candidate. The result says whether the channel is dead. It is
    /// none when the channel is neither dead nor silent any more: the
    /// candidate of such a channel ends.
    pub fn hold_candidate<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        address: &[u8],
        rng: &mut R,
    ) -> Result<Option<bool>, Error> {
        let held = self.hold_candidate_of(conversation, address, NO_WEEK, rng)?;
        Ok(held.map(|(dead, _)| dead))
    }

    /// As [`Client::hold_candidate`], for the blob of `week`. The two
    /// blobs of one fetch arrive apart, and the one of the later week names
    /// the candidate (`NET-190`). An address of an earlier week than the
    /// one that the row holds changes nothing, and the result is none. The
    /// result says whether the channel is dead, and whether the candidate
    /// took its record of `NET-191` already. An address that the row holds
    /// keeps that fact and its time, and another address starts both again.
    pub fn hold_candidate_of<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        address: &[u8],
        week: u32,
        rng: &mut R,
    ) -> Result<Option<(bool, bool)>, Error> {
        let Some(mut row) = self.dead_row(conversation)? else {
            return Ok(None);
        };
        if address.len() != ADDRESS_LEN {
            return Ok(None);
        }

        let names_week = week != NO_WEEK && row.candidate_week != NO_WEEK;
        let is_held = row
            .candidate
            .as_ref()
            .is_some_and(|held| held.as_slice() == address);
        if is_held {
            if week != NO_WEEK && (!names_week || week > row.candidate_week) {
                row.candidate_week = week;
            }
        } else {
            if row.candidate.is_some() && names_week && week < row.candidate_week {
                return Ok(None);
            }

            row.candidate = Some(Zeroizing::new(address.to_vec()));
            row.candidate_sent = false;
            row.candidate_since = self.known_now_ms()? / 1_000;
            row.candidate_week = week;
        }

        self.put_dead_row(conversation, Some(&row), rng)?;

        Ok(Some((row.dead, row.candidate_sent)))
    }

    /// The address of this device left for the candidate of a
    /// conversation (`NET-191`), or a relay answered the bundle of a
    /// renewal that went there. The row keeps that, thus no later run
    /// sends to the candidate again.
    pub fn candidate_sent<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut row) = self.dead_row(conversation)? else {
            return Ok(());
        };
        if row.candidate.is_none() || row.candidate_sent {
            return Ok(());
        }

        row.candidate_sent = true;
        self.put_dead_row(conversation, Some(&row), rng)
    }

    /// Each candidate address that the store holds, with its contact,
    /// whether the channel is dead, and whether the candidate took its
    /// record already. A run that starts gives them to its node, which
    /// holds none of an earlier run.
    #[allow(clippy::type_complexity)]
    pub fn held_candidates(
        &self,
    ) -> Result<Vec<(ConversationId, [u8; 32], Zeroizing<Vec<u8>>, bool, bool)>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (row, plain) in store.list(TableId::CONTACT, None)? {
            drop(Zeroizing::new(plain));
            let conversation = ConversationId(row);
            let Some(held) = self.dead_row(conversation)? else {
                continue;
            };

            if let Some(candidate) = held.candidate {
                out.push((
                    conversation,
                    self.contact_id_of(conversation)?,
                    candidate,
                    held.dead,
                    held.candidate_sent,
                ));
            }
        }

        Ok(out)
    }

    /// The peer gave its address in a record of kind `0x33` under the
    /// ratchet, or a renewal replaced the channel. The channel lives, and
    /// the blob of this device goes with its row and its candidate
    /// (`NET-190`). The result is the erase of that blob, when this device
    /// wrote one.
    pub fn dead_channel_ended<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<Option<DeadWork>, Error> {
        // The record that moved the peer is a sign of it.
        self.peer_heard(conversation)?;
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

    /// The newest time that this device knows with no call of the
    /// platform, in milliseconds. It comes from the insertion stamp, which
    /// follows the clock of each commit, and the last tick.
    fn known_now_ms(&self) -> Result<u64, Error> {
        Ok(self
            .open_ref()?
            .stamp
            .last
            .max(self.clock.saturating_mul(1_000)))
    }

    /// A relay acknowledged the record of `message`. When no earlier
    /// acknowledgment of its conversation waits for a record of the peer,
    /// `DEAD_CHANNEL_SILENCE` counts from this one (Part 3 §3.2.6). A
    /// record of a group, and one of no contact, starts nothing.
    pub(super) fn relay_accepted<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        rng: &mut R,
    ) -> Result<(), Error> {
        let now_ms = self.known_now_ms()?;
        let open = self.open_mut()?;
        let Some(plain) = open.store.get(TableId::MESSAGE, &message.0)? else {
            return Ok(());
        };

        let conversation = super::conversation_of(&Zeroizing::new(plain))?;
        let Some(contact) = open.store.get(TableId::CONTACT, &conversation.0)? else {
            return Ok(());
        };

        drop(Zeroizing::new(contact));
        let name = [UNANSWERED_SETTING, conversation.0.as_slice()].concat();
        let row = open.store.row_id(SETTINGS, &name);
        if open.store.get(SETTINGS, &row)?.is_some() {
            return Ok(());
        }

        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &now_ms.to_be_bytes(), rng)?;

        Ok(batch.commit()?)
    }

    /// A record that opened under the ratchet of the contact arrived: a
    /// sign of the peer (Part 3 §3.2.6). The silence of the channel ends,
    /// and the next acknowledgment of a relay starts it again.
    pub(super) fn peer_heard(&mut self, conversation: ConversationId) -> Result<(), Error> {
        let open = self.open_mut()?;
        let name = [UNANSWERED_SETTING, conversation.0.as_slice()].concat();
        let row = open.store.row_id(SETTINGS, &name);
        if open.store.get(SETTINGS, &row)?.is_none() {
            return Ok(());
        }

        let mut batch = open.store.begin();
        batch.delete(SETTINGS, row);

        Ok(batch.commit()?)
    }

    /// Each pairwise conversation in which a relay acknowledged a record
    /// of this device `DEAD_CHANNEL_SILENCE` ago or earlier (`NET-186`). No
    /// record of the peer arrived since. No receipt enters the signal,
    /// because the two receipts are off by default (`NET-059`).
    pub fn silent_conversations(&self, now_ms: u64) -> Result<Vec<ConversationId>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (row, plain) in store.list(TableId::CONTACT, None)? {
            drop(Zeroizing::new(plain));
            let conversation = ConversationId(row);
            let name = [UNANSWERED_SETTING, conversation.0.as_slice()].concat();
            let since = store
                .get(SETTINGS, &store.row_id(SETTINGS, &name))?
                .and_then(|bytes| bytes.as_slice().try_into().ok())
                .map(u64::from_be_bytes);
            if since.is_some_and(|since| now_ms.saturating_sub(since) >= DEAD_CHANNEL_SILENCE_MS) {
                out.push(conversation);
            }
        }

        Ok(out)
    }

    /// NET-193: each record of a conversation that a relay took and that
    /// holds no delivery receipt goes to the send path again. The receiver
    /// drops a copy that it holds by its `msg_id`.
    ///
    /// The set has two bounds. A relay holds a record for `MSG_TTL` at
    /// most, thus an older record left its queue to the contact or to
    /// nothing. The queue that died took none of it. A receipt of the
    /// contact proves that it read its queue up to the record that the
    /// receipt names. Thus each record that this device stored before the
    /// newest receipted one arrived too. With the receipts off the first
    /// bound alone holds. A placeholder is no record of the wire.
    pub fn resend_unreceipted(&mut self, conversation: ConversationId) -> Result<(), Error> {
        let now_ms = self.known_now_ms()?;
        let store = &self.open_ref()?.store;
        let ttl_ms = umbra_queue::params::MSG_TTL.saturating_mul(1_000);
        let mut receipted = 0u64;
        for (_, message) in store.list(TableId::MESSAGE, Some(&conversation.0))? {
            let message = Zeroizing::new(message);
            let Ok(info) = info_of(&message) else {
                continue;
            };

            if info.outgoing && matches!(info.delivery, Delivery::Delivered | Delivery::Read) {
                receipted = receipted.max(info.stored_at_ms);
            }
        }

        let mut records = Vec::new();
        for (row, message) in store.list(TableId::MESSAGE, Some(&conversation.0))? {
            let message = Zeroizing::new(message);

            // IMP-121: the plaintext names its owner. A record of another
            // conversation never goes to this contact.
            if super::conversation_of(&message)? != conversation {
                return Err(Error::Integrity);
            }
            let Ok(info) = info_of(&message) else {
                continue;
            };

            let is_bound = info.stored_at_ms > receipted
                && now_ms.saturating_sub(info.stored_at_ms) < ttl_ms
                && !info.deleted;
            if info.outgoing && info.delivery == Delivery::Accepted && is_bound {
                let app = message.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
                records.push((
                    info.stored_at_ms,
                    Outgoing {
                        message: MsgRef(row),
                        conversation,
                        // WIR-071: the wire carries the raw target of a
                        // reply, and the row holds its reference.
                        app: self.with_raw_targets(conversation, app)?,
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
            // NET-194, NET-197: a blocked contact has no blob of this device,
            // and this device reads none of it.
            if self.is_blocked(conversation)? {
                if let Some(row) = self.dead_row(conversation)? {
                    work.extend(self.erase_of(conversation, &row)?);
                    self.put_dead_row(conversation, None, rng)?;
                }
                continue;
            }

            let is_silent = silent.contains(&conversation);
            let mut row = self.dead_row(conversation)?.unwrap_or_else(DeadRow::empty);
            if !row.dead && !is_silent {
                // The condition ended: the row goes, with its blob.
                work.extend(self.erase_of(conversation, &row)?);
                self.put_dead_row(conversation, None, rng)?;
                continue;
            }

            // NET-190: a candidate that gave no address of the peer in
            // `DEAD_CHANNEL_SILENCE` ends, and the row holds it no more. A
            // blob of a later fetch that names it gives a new candidate.
            if row.candidate.is_some() {
                let age = now.saturating_sub(row.candidate_since);
                if row.candidate_since == 0 {
                    row.candidate_since = now;
                } else if age >= DEAD_CHANNEL_SILENCE_MS / 1_000 {
                    row.end_candidate();
                }
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
                            week: at_week,
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
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
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
            ..DeadRow::empty()
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

        // NET-190: a row with a candidate address holds it in a tail, and a
        // row of an earlier build, which ends before it, holds none.
        assert_eq!(back.candidate, None);
        let with = DeadRow {
            candidate: Some(Zeroizing::new(vec![8; LEN])),
            ..back
        };
        let bytes = with.encode();
        let earlier = ROW_LEN + super::CANDIDATE_TAIL;
        assert_eq!(bytes.len(), earlier + super::SENT_TAIL);
        let again = DeadRow::parse(&bytes).unwrap();
        assert_eq!(again.candidate.as_deref(), Some(&vec![8; LEN]));
        assert_eq!(again.address.as_deref(), Some(&vec![7; LEN]));
        assert!(DeadRow::parse(bytes.split_last().unwrap().1).is_err());

        // NET-191: the row says whether the candidate took its record,
        // since when this device holds it, and the week of its blob.
        assert_eq!(
            (
                again.candidate_sent,
                again.candidate_since,
                again.candidate_week
            ),
            (false, 0, NO_WEEK)
        );
        let sent = DeadRow {
            candidate_sent: true,
            candidate_since: 1_800_000_500,
            candidate_week: 3_001,
            ..again
        };
        let told = DeadRow::parse(&sent.encode()).unwrap();
        assert_eq!(
            (
                told.candidate_sent,
                told.candidate_since,
                told.candidate_week
            ),
            (true, 1_800_000_500, 3_001)
        );

        // A row of an earlier build holds the candidate alone: it took no
        // record, and its time starts at the next check.
        let old = DeadRow::parse(&sent.encode()[..earlier]).unwrap();
        assert_eq!(old.candidate.as_deref(), Some(&vec![8; LEN]));
        assert_eq!(
            (old.candidate_sent, old.candidate_since, old.candidate_week),
            (false, 0, NO_WEEK)
        );
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn a_candidate_keeps_its_one_send_across_runs_and_ends_after_a_week() {
        use umbra_core::{
            session::node::{ContactId, StateChange},
            store::{
                engine::MemoryBackend,
                wrap::{Cost, SecureElement},
            },
        };

        use crate::{client::Client, runtime::OsRng};

        struct Element;

        impl SecureElement for Element {
            fn keyed(&self, input: &[u8]) -> Result<[u8; 32], umbra_core::Error> {
                Ok(umbra_crypto::hash::sha3_256(&[input]))
            }
        }

        let mut rng = OsRng;
        let passphrase: Vec<u16> = "correct horse".encode_utf16().collect();
        let cost = Cost { m_kib: 64, t: 1 };
        let mut client = Client::create(
            MemoryBackend::default(),
            Element,
            &passphrase,
            cost,
            1_000,
            &mut rng,
        )
        .unwrap();
        let peer = ContactId([0x57; 32]);
        let peer_static = super::read_pk(&Secret::new([7; 32]));
        let contact = StateChange::Contact {
            contact: peer,
            state: Zeroizing::new([&[0x01][..], &[5; 16], &peer_static, &[0; 8]].concat()),
        };
        client
            .commit_network(&[contact], &[], 1_000_000, &mut rng)
            .unwrap();
        let conversation = client.conversation_for(&peer.0).unwrap();
        client.channel_dead(conversation, 1_000, &mut rng).unwrap();

        // The clock of the platform, from which the time of a candidate
        // counts.
        client.touch(2_000);
        client.tick(2_000);
        let (first, second) = (vec![7u8; LEN], vec![8u8; LEN]);
        let held = |client: &Client<MemoryBackend, Element>| {
            let held = client.held_candidates().unwrap();
            assert_eq!(held.len(), 1);
            (held[0].2.to_vec(), held[0].3, held[0].4)
        };

        // NET-190: the two blobs of one fetch arrive apart, and the one of
        // the later week names the candidate, whichever answers last.
        let took = client.hold_candidate_of(conversation, &first, 3_001, &mut rng);
        assert_eq!(took.unwrap(), Some((true, false)));
        let took = client.hold_candidate_of(conversation, &second, 3_000, &mut rng);
        assert_eq!(took.unwrap(), None);
        assert_eq!(held(&client), (first.clone(), true, false));

        // NET-191: the row keeps the one send, thus the next run gets the
        // candidate as one that took its record. A blob of a later week
        // that names the same address changes nothing.
        client.candidate_sent(conversation, &mut rng).unwrap();
        assert_eq!(held(&client), (first.clone(), true, true));
        let took = client.hold_candidate_of(conversation, &first, 3_002, &mut rng);
        assert_eq!(took.unwrap(), Some((true, true)));

        // One more record goes after a rotation of the own queue.
        let mut own = vec![0u8; LEN];
        umbra_wire::address::QueueAddress {
            relay_id: [1; 32],
            sender_id: [2; 32],
            qs_auth_sk: Secret::new([3; 32]),
            qe: Secret::new([4; 32]),
        }
        .encode(&mut own)
        .unwrap();
        client
            .dead_queue_rotated(conversation, &own, &mut rng)
            .unwrap();
        assert_eq!(held(&client), (first.clone(), true, false));

        // Another address of a later week is a new candidate.
        client.candidate_sent(conversation, &mut rng).unwrap();
        let took = client.hold_candidate_of(conversation, &second, 3_003, &mut rng);
        assert_eq!(took.unwrap(), Some((true, false)));
        assert_eq!(held(&client), (second, true, false));

        // NET-190: a candidate that gave no address of the peer in
        // `DEAD_CHANNEL_SILENCE` ends, and the store holds it no more.
        let epoch = 3_003 * 168;
        let since = client.dead_row(conversation).unwrap().unwrap();
        let since = since.candidate_since;
        assert_eq!(since, 2_000);
        let end = since + super::DEAD_CHANNEL_SILENCE_MS / 1_000;
        client
            .dead_channel_work(end - 1, epoch, &[], &mut rng)
            .unwrap();
        assert_eq!(client.held_candidates().unwrap().len(), 1);
        client.dead_channel_work(end, epoch, &[], &mut rng).unwrap();
        assert!(client.held_candidates().unwrap().is_empty());
        assert!(client.channel_was_down(conversation).unwrap());
    }
}
