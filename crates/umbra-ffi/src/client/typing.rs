//! The typing indicator of Part 6 §6.6.9 on a pairwise channel. It is off
//! by default (`WIR-077`), a group takes none (`GRP-300`), and no store
//! holds a typing record (`WIR-287`).

use umbra_core::store::{engine::Backend, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{signal::TypingState, AppKind, AppMessage};

use super::{Client, Outgoing, SETTINGS};
use crate::{ConversationId, Error, MsgRef};

/// `TYPING_INTERVAL`: the least time between two typing records to one
/// peer, in milliseconds (`WIR-285`).
pub const TYPING_INTERVAL_MS: u64 = 10_000;
/// `TYPING_TTL`: the time after which a receiver clears a typing state, in
/// milliseconds (`WIR-286`).
pub const TYPING_TTL_MS: u64 = 15_000;

const TYPING_SETTING: &[u8] = b"typing";

/// The message of an ephemeral record: no row holds it, thus the send path
/// reports no delivery for it and publishes it on no sync channel.
pub const EPHEMERAL: MsgRef = MsgRef([0; 16]);

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Whether this device sends typing records and shows those of its
    /// contacts. The value is off until the user turns it on (`WIR-077`).
    pub fn typing_enabled(&self) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, TYPING_SETTING);
        Ok(store.get(SETTINGS, &row)?.as_deref() == Some(&[1]))
    }

    /// Turns the typing indicator on or off.
    pub fn set_typing_enabled<R: CryptoRng + ?Sized>(
        &mut self,
        is_on: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, TYPING_SETTING);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &[u8::from(is_on)], rng)?;
        Ok(batch.commit()?)
    }

    /// The user typed in a pairwise conversation, or stopped. A record goes
    /// when the indicator is on and `TYPING_INTERVAL` passed since the last
    /// one to that peer (`WIR-285`). The result says whether one went.
    pub fn typing<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        started: bool,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        if !self.typing_enabled()? || self.is_group(conversation)? {
            return Ok(false);
        }
        let last = self.typing_sent.get(&conversation).copied();
        if last.is_some_and(|at| now_ms.saturating_sub(at) < TYPING_INTERVAL_MS) {
            return Ok(false);
        }
        let mut body = [0u8; 2];
        let state = if started {
            TypingState::Started
        } else {
            TypingState::Stopped
        };
        state.encode(&mut body)?;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::Typing,
            msg_id,
            sent_at: now_ms,
            body: &body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        self.typing_sent.insert(conversation, now_ms);
        self.outgoing.push_back(Outgoing {
            message: EPHEMERAL,
            conversation,
            app,
        });
        Ok(true)
    }
}
