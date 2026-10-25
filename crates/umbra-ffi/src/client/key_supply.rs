//! The key request of scope `0x01` of Part 6 §6.6.11 on a pairwise channel.
//! A record of a contact that does not open names its hole by its
//! `send_index` (`WIR-254`), and this device asks the contact for it on the
//! pairwise channel (`WIR-455`). The contact sends the message again under
//! the current ratchet with its original `msg_id` (`WIR-339`, `WIR-348`),
//! or answers that it holds it no more (`WIR-340`), and this device then
//! shows a delivery failure (`WIR-341`).
//!
//! This device keeps the `send_index` of the record and no copy of it
//! (`WIR-050`, `WIR-571`): no later key opens it, and the send again brings
//! the content back. A hole above the rate of `WIR-337` gets no request, and
//! the conversation shows a gap in its place (`WIR-572`). One limit of this
//! client: a reply that goes again names no target, since the store holds
//! the target as a reference alone after the first send.

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    keys::{KeyRequest, KeyScope, KeySupply, SupplyStatus},
    AppKind, AppMessage, Channel,
};
use zeroize::Zeroizing;

use super::{
    info_of,
    roster_notes::{RosterNote, NOTE_NOBODY},
    Client, Outgoing, EPHEMERAL, MESSAGE_PREFIX,
};
use crate::{ConversationId, Error, MsgRef};

/// The message of this device that each `send_index` of a conversation
/// named, under the row of the conversation and the index. The index wraps
/// at 65 536, and a later record takes the place of an earlier one.
pub(super) const SEND_INDEX: TableId = TableId(0x43);
/// Each key request of this device that waits for its supply, and the time
/// of each request to a peer for its rate (`WIR-337`, `WIR-347`). A group
/// request names no index of the session, thus it takes one of
/// `KEY_REQUEST_RATE` places of the peer, which it shares.
pub(super) const KEY_ASKED: TableId = TableId(0x44);

/// The note of a record that did not open and that its sender holds no
/// more (`WIR-341`).
pub const NOTE_LOST: u8 = 7;

/// `KEY_REQUEST_RATE` of Part 11 §11.10: the key requests to one peer in
/// each 24 hours.
const KEY_REQUEST_RATE: usize = umbra_core::group::KEY_REQUEST_RATE as usize;
const DAY: u64 = 86_400;

fn index_key(conversation: ConversationId, index: u16) -> Vec<u8> {
    [conversation.0.as_slice(), b"index", &index.to_be_bytes()].concat()
}

fn asked_key(conversation: ConversationId, index: u16) -> Vec<u8> {
    [conversation.0.as_slice(), b"asked", &index.to_be_bytes()].concat()
}

fn group_asked_key(conversation: ConversationId, place: u8) -> Vec<u8> {
    [conversation.0.as_slice(), b"group-asked", &[place]].concat()
}

/// The time of the last gap that a hole above the rate showed. Its value is
/// 9 bytes, thus the rate, which counts the values of 8 bytes, does not
/// count it.
fn above_rate_key(conversation: ConversationId) -> Vec<u8> {
    [conversation.0.as_slice(), b"above-rate"].concat()
}

/// The mark of a request whose supply came, beside its row. The row of the
/// request keeps its time for the rate, and the mark is one byte, thus the
/// rate does not count it.
fn answered_key(conversation: ConversationId, index: u16) -> Vec<u8> {
    [conversation.0.as_slice(), b"answered", &index.to_be_bytes()].concat()
}

/// The setting that counts the key requests of a peer that this device
/// answered, before the conversation (`WIR-338`). The value is the start of
/// the 24 hours, then the count.
pub(super) const SERVED_SETTING: &[u8] = b"key-served/";

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The node sealed a record of `message` under `index`.
    pub fn note_send_index<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        index: u16,
        rng: &mut R,
    ) -> Result<(), Error> {
        let conversation = self.conversation_of_message(message)?;
        let open = self.open_mut()?;
        let row = open
            .store
            .row_id(SEND_INDEX, &index_key(conversation, index));
        let mut batch = open.store.begin();
        batch.put(SEND_INDEX, row, Some(conversation.0), &message.0, rng)?;

        Ok(batch.commit()?)
    }

    fn send_key_record<R: CryptoRng + ?Sized>(
        &mut self,
        to: ConversationId,
        kind: AppKind,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind,
            msg_id,
            sent_at: now_ms,
            body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        self.outgoing.push_back(Outgoing {
            message: EPHEMERAL,
            conversation: to,
            app,
        });

        Ok(())
    }

    fn session_request(index: u16) -> KeyRequest {
        KeyRequest {
            scope: KeyScope::Session,
            // The pairwise channel names the session and the peer, thus
            // the identifier carries nothing more.
            id: [0; 32],
            epoch: 0,
            index: u32::from(index),
        }
    }

    /// A record of the contact of `conversation` did not open, and its
    /// context names `index`. One request goes for each hole, and no more
    /// than `KEY_REQUEST_RATE` to one peer in 24 hours (`WIR-337`). A hole
    /// above that rate shows a gap (`WIR-572`).
    pub fn lost_record<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        index: u16,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let now = now_ms / 1_000;
        let store = &self.open_ref()?.store;
        let row = store.row_id(KEY_ASKED, &asked_key(conversation, index));
        let answered = store.row_id(KEY_ASKED, &answered_key(conversation, index));

        // WIR-347: one request for one hole. The index wraps at 65 536,
        // thus a request older than 24 hours named another record. A new
        // hole at its index takes a request of its own.
        let is_recent = store.get(KEY_ASKED, &row)?.is_some_and(|at| {
            <[u8; 8]>::try_from(at.as_slice())
                .is_ok_and(|at| now.saturating_sub(u64::from_be_bytes(at)) < DAY)
        });
        if is_recent {
            return Ok(false);
        }

        if self.requests_to(conversation, now)? >= KEY_REQUEST_RATE {
            self.gap_above_rate(conversation, now_ms, rng)?;
            return Ok(false);
        }

        let request = Self::session_request(index);
        let mut body = vec![0u8; umbra_wire::app::keys::REQUEST_LEN];
        request.encode(&mut body)?;
        self.send_key_record(conversation, AppKind::KeyRequest, &body, now_ms, rng)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(
            KEY_ASKED,
            row,
            Some(conversation.0),
            &now.to_be_bytes(),
            rng,
        )?;
        batch.delete(KEY_ASKED, answered);
        batch.commit()?;

        Ok(true)
    }

    /// Shows a delivery gap for a hole that the rate keeps from its request
    /// (`WIR-572`). One gap in 24 hours stands for each such hole of the
    /// peer, thus a peer that sends records that do not open fills no view.
    fn gap_above_rate<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let now = now_ms / 1_000;
        let store = &self.open_ref()?.store;
        let row = store.row_id(KEY_ASKED, &above_rate_key(conversation));
        let is_shown = store.get(KEY_ASKED, &row)?.is_some_and(|held| {
            held.get(..8)
                .and_then(|at| <[u8; 8]>::try_from(at).ok())
                .is_some_and(|at| now.saturating_sub(u64::from_be_bytes(at)) < DAY)
        });
        if is_shown {
            return Ok(());
        }

        // A fault between the two writes shows the gap a second time, and
        // it loses none.
        self.delivery_gap(conversation, now_ms, rng)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        let shown = [now.to_be_bytes().as_slice(), &[0]].concat();
        batch.put(KEY_ASKED, row, Some(conversation.0), &shown, rng)?;

        Ok(batch.commit()?)
    }

    /// The key requests of this device to the peer of a conversation in the
    /// 24 hours before `now`, of each scope. A mark of a supply is one byte,
    /// thus it does not count.
    fn requests_to(&self, conversation: ConversationId, now: u64) -> Result<usize, Error> {
        let store = &self.open_ref()?.store;
        Ok(store
            .list(KEY_ASKED, Some(&conversation.0))?
            .iter()
            .filter_map(|(_, at)| <[u8; 8]>::try_from(at.as_slice()).ok())
            .filter(|at| now.saturating_sub(u64::from_be_bytes(*at)) < DAY)
            .count())
    }

    /// Counts one group key request of this device to the peer of a
    /// conversation, and says whether it may go. The requests of each scope
    /// to one peer share `KEY_REQUEST_RATE` in 24 hours (`WIR-337`), since
    /// the peer counts them together (`WIR-338`).
    pub(super) fn asks_peer<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        if self.requests_to(conversation, now)? >= KEY_REQUEST_RATE {
            return Ok(false);
        }

        // The request takes the place of the oldest one, thus the rows of
        // one peer stay at the rate.
        let store = &self.open_ref()?.store;
        let mut oldest = (u64::MAX, 0u8);
        for place in (0..KEY_REQUEST_RATE).filter_map(|place| u8::try_from(place).ok()) {
            let row = store.row_id(KEY_ASKED, &group_asked_key(conversation, place));
            let at = store
                .get(KEY_ASKED, &row)?
                .and_then(|at| <[u8; 8]>::try_from(at.as_slice()).ok())
                .map_or(0, u64::from_be_bytes);
            if at < oldest.0 {
                oldest = (at, place);
            }
        }

        let open = self.open_mut()?;
        let row = open
            .store
            .row_id(KEY_ASKED, &group_asked_key(conversation, oldest.1));
        let mut batch = open.store.begin();
        batch.put(
            KEY_ASKED,
            row,
            Some(conversation.0),
            &now.to_be_bytes(),
            rng,
        )?;
        batch.commit()?;

        Ok(true)
    }

    /// Counts one key request of the peer of a conversation, and says
    /// whether it is inside `KEY_REQUEST_RATE` in 24 hours (`WIR-338`).
    pub(super) fn serves_key_request<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let key = [SERVED_SETTING, conversation.0.as_slice()].concat();
        let held = self.setting(&key)?;
        let field = |at: usize| -> Option<[u8; 8]> {
            held.as_deref()?
                .get(at..at.checked_add(8)?)?
                .try_into()
                .ok()
        };
        let (mut since, mut count) = (
            field(0).map_or(0, u64::from_be_bytes),
            field(8).map_or(0, u64::from_be_bytes),
        );
        if now.saturating_sub(since) >= DAY {
            since = now;
            count = 0;
        }
        if count >= KEY_REQUEST_RATE as u64 {
            return Ok(false);
        }

        count = count.saturating_add(1);
        let value = [since.to_be_bytes(), count.to_be_bytes()].concat();
        self.put_setting(&key, &value, rng)?;

        Ok(true)
    }

    /// A contact asks for a record of this device by its `send_index`: the
    /// message goes again with its `msg_id`, or the supply says that this
    /// device holds it no more.
    pub(super) fn on_session_key_request<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Ok(request) = KeyRequest::parse(body) else {
            return Ok(());
        };
        let Ok(index) = u16::try_from(request.index) else {
            return Ok(());
        };

        // WIR-338: a request above the rate goes, with no record again and
        // no supply, thus a contact makes no flood of this device.
        if !self.serves_key_request(conversation, now_ms / 1_000, rng)? {
            return Ok(());
        }

        let store = &self.open_ref()?.store;
        let row = store.row_id(SEND_INDEX, &index_key(conversation, index));
        let again = match store.get(SEND_INDEX, &row)? {
            Some(message) => {
                let message: [u8; 16] = message
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Integrity)?;
                match store.get(TableId::MESSAGE, &message)? {
                    Some(plain) => {
                        let plain = Zeroizing::new(plain);
                        let info = info_of(&plain)?;
                        (info.outgoing && !info.deleted)
                            .then(|| plain.get(MESSAGE_PREFIX..).map(<[u8]>::to_vec))
                            .flatten()
                    }
                    None => None,
                }
            }
            None => None,
        };
        let status = match again {
            // WIR-348: the same record, thus the same `msg_id`, under the
            // current ratchet state.
            Some(app) if AppMessage::parse(&app, Channel::Pairwise).is_ok() => {
                self.outgoing.push_back(Outgoing {
                    message: EPHEMERAL,
                    conversation,
                    app,
                });
                SupplyStatus::Resent
            }
            _ => SupplyStatus::NotHeld,
        };
        let supply = KeySupply {
            request,
            status,
            body: &[],
        };
        let mut out = vec![0u8; umbra_wire::app::keys::SUPPLY_LEN];
        let used = supply.encode(&mut out)?;
        out.truncate(used);
        self.send_key_record(conversation, AppKind::KeySupply, &out, now_ms, rng)
    }

    /// A contact answered a key request. A supply that answers no request
    /// of this device goes (`WIR-347`, `WIR-459`), and one that says the
    /// contact holds the record no more puts a note of a delivery failure
    /// in the conversation (`WIR-341`).
    pub(super) fn on_key_supply<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Ok(supply) = KeySupply::parse(body) else {
            return Ok(());
        };
        if supply.request.scope != KeyScope::Session {
            return Ok(());
        }
        let Ok(index) = u16::try_from(supply.request.index) else {
            return Ok(());
        };

        let open = self.open_ref()?;
        let row = open
            .store
            .row_id(KEY_ASKED, &asked_key(conversation, index));
        if open.store.get(KEY_ASKED, &row)?.is_none() {
            return Ok(());
        }

        // WIR-347: one supply answers one request. A copy of a supply that
        // came finds the mark, and it changes nothing.
        let answered = open
            .store
            .row_id(KEY_ASKED, &answered_key(conversation, index));
        if open.store.get(KEY_ASKED, &answered)?.is_some() {
            return Ok(());
        }

        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(KEY_ASKED, answered, Some(conversation.0), &[1], rng)?;
        batch.commit()?;
        if supply.status == SupplyStatus::NotHeld {
            self.put_roster_note(
                conversation,
                RosterNote {
                    at_ms: now_ms,
                    kind: NOTE_LOST,
                    index: NOTE_NOBODY,
                    role: 0,
                },
                rng,
            )?;
        }

        Ok(())
    }
}
