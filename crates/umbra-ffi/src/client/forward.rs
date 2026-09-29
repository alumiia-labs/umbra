//! The forward of a text (Part 6 §6.6.5). A forward is a new message with a
//! new `msg_id` (`WIR-062`), and its rich record carries the depth of the
//! record that it forwards plus one (`WIR-177`, `WIR-178`). A record at
//! `FORWARD_MAX_DEPTH` goes no further.

use umbra_core::{
    devset::FORWARD_MAX_DEPTH,
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{rich::RichRecord, AppKind, AppMessage, Channel};
use zeroize::Zeroizing;

use super::{Client, MESSAGE_PREFIX};
use crate::{ConversationId, Error, MsgRef};

/// The forward depth of a stored record: the field of its rich record, or
/// zero for an original (`WIR-179`).
pub(super) fn depth_of(app: &[u8]) -> u8 {
    AppMessage::parse(app, Channel::Pairwise)
        .ok()
        .filter(|parsed| parsed.kind == AppKind::Rich)
        .and_then(|parsed| RichRecord::parse(parsed.body, Channel::Group).ok())
        .map_or(0, |rich| rich.forward_depth)
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Forwards the text of `message` to `to`, as a new message of this
    /// device. A record with no text, and one at `FORWARD_MAX_DEPTH`, takes
    /// no forward.
    pub fn forward<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        to: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let parsed = AppMessage::parse(app, Channel::Pairwise)?;
        let text = super::text_of(&parsed)?;
        let depth = depth_of(app);
        if depth >= FORWARD_MAX_DEPTH {
            return Err(Error::TooLong);
        }
        let is_group = self.is_group(to)?;
        let channel = if is_group {
            Channel::Group
        } else {
            Channel::Pairwise
        };
        let record = RichRecord {
            reply_target: [0; 16],
            thread_root: [0; 16],
            forward_depth: depth.saturating_add(1),
            mentions: Vec::new(),
            inner_kind: AppKind::Text,
            inner_body: text,
        };
        let mut body = Zeroizing::new(vec![0u8; record.len()]);
        record.encode(channel, &mut body)?;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let forwarded = AppMessage {
            kind: AppKind::Rich,
            msg_id,
            sent_at: now_ms,
            body: &body,
        };
        let mut out = Zeroizing::new(vec![0u8; forwarded.len()]);
        forwarded.encode(&mut out)?;
        drop(plain);
        self.send_app(to, msg_id, &out, is_group, now_ms, rng)
    }
}
