//! The forward of a text (Part 6 §6.6.5). A forward is a new message with a
//! new `msg_id` (`WIR-062`), and its rich record carries the depth of the
//! record that it forwards plus one (`WIR-177`, `WIR-178`). A record at
//! `FORWARD_MAX_DEPTH` goes no further.
//!
//! The forward policy of Part 7 §7.5.10 is the request of a party that no
//! client forwards its messages of one conversation. The store holds the
//! newest policy of each direction, and the forward path obeys the one of
//! the other party (`DEV-322`).

use umbra_core::{
    devset::FORWARD_MAX_DEPTH,
    store::{
        engine::{Backend, Store},
        record::TableId,
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::{
    app::{
        rich::RichRecord,
        signal::{ForwardPolicy, FORWARD_POLICY_LEN},
        AppKind, AppMessage, Channel,
    },
    group::control::Role,
};
use zeroize::Zeroizing;

use super::{info_of, stored_message, Client, Outgoing, MESSAGE_PREFIX, OUTBOX, OUTGOING};
use crate::{ConversationId, Delivery, Error, MsgRef};

/// The forward policy of each conversation: the counter and the flag of the
/// user, then the counter and the flag of the other party. A group holds
/// its one policy in the second place.
pub(super) const FORWARD_POLICY: TableId = TableId(0x56);
const SIDE_LEN: usize = 5;

/// The newest policy of one direction of a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardSide {
    /// The counter of the newest policy record, or 0 when none came.
    pub seq: u32,
    /// Whether the party prohibits the forward of its messages.
    pub prohibits: bool,
}

impl ForwardSide {
    /// Whether `policy` takes the place of this value (`DEV-323`): a higher
    /// counter wins, and at one counter the prohibition wins.
    fn yields_to(&self, policy: &ForwardPolicy) -> bool {
        policy.seq > self.seq || (policy.seq == self.seq && policy.prohibits && !self.prohibits)
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let seq: [u8; 4] = bytes
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Integrity)?;
        Ok(ForwardSide {
            seq: u32::from_be_bytes(seq),
            prohibits: bytes.get(4) == Some(&1),
        })
    }
}

/// The forward policy of the two directions of one conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardSetting {
    /// The policy of the user for the messages of the user.
    pub own: ForwardSide,
    /// The policy of the other party, or of a group.
    pub peer: ForwardSide,
}

impl ForwardSetting {
    pub(super) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(SIDE_LEN.saturating_mul(2)));
        for side in [self.own, self.peer] {
            out.extend_from_slice(&side.seq.to_be_bytes());
            out.push(u8::from(side.prohibits));
        }

        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIDE_LEN.saturating_mul(2) {
            return Err(Error::Integrity);
        }

        let (own, peer) = bytes.split_at(SIDE_LEN);

        Ok(ForwardSetting {
            own: ForwardSide::parse(own)?,
            peer: ForwardSide::parse(peer)?,
        })
    }

    /// Takes a policy record of one direction. The result is whether the
    /// setting changed.
    pub(super) fn take(&mut self, policy: &ForwardPolicy, from_user: bool) -> bool {
        let side = if from_user {
            &mut self.own
        } else {
            &mut self.peer
        };
        if !side.yields_to(policy) {
            return false;
        }
        *side = ForwardSide {
            seq: policy.seq,
            prohibits: policy.prohibits,
        };

        true
    }
}

/// The stored forward policy of a conversation, or the default of none.
pub(super) fn setting_in<B: Backend>(
    store: &Store<B>,
    conversation: ConversationId,
) -> Result<ForwardSetting, Error> {
    let row = store.row_id(FORWARD_POLICY, &conversation.0);
    store
        .get(FORWARD_POLICY, &row)?
        .map_or(Ok(ForwardSetting::default()), |value| {
            ForwardSetting::parse(&Zeroizing::new(value))
        })
}

/// The flag of a `ForwardPolicy` body, for the row that marks the change.
pub(super) fn policy_body(body: &[u8]) -> Option<bool> {
    ForwardPolicy::parse(body)
        .ok()
        .map(|policy| policy.prohibits)
}

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
    /// no forward. A message whose sender prohibits the forward takes none
    /// (`DEV-322`).
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
        if self.forward_prohibited_of(&plain)? {
            return Err(Error::Refused);
        }

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

    /// The forward policy of a conversation (`DEV-321`).
    pub fn forward_setting(&self, conversation: ConversationId) -> Result<ForwardSetting, Error> {
        setting_in(&self.open_ref()?.store, conversation)
    }

    /// Whether the user prohibits the forward in a conversation: the policy
    /// of the user, or the one policy of a group.
    pub fn prohibits_forward(&self, conversation: ConversationId) -> Result<bool, Error> {
        let setting = self.forward_setting(conversation)?;
        Ok(if self.is_group(conversation)? {
            setting.peer.prohibits
        } else {
            setting.own.prohibits
        })
    }

    /// Whether the policy of the other party prohibits the forward of a
    /// stored message: a message that arrived, in a conversation whose
    /// other party prohibits it (`DEV-322`).
    pub(super) fn forward_prohibited_of(&self, plain: &[u8]) -> Result<bool, Error> {
        if info_of(plain)?.outgoing {
            return Ok(false);
        }

        let conversation = super::conversation_of(plain)?;

        Ok(self.forward_setting(conversation)?.peer.prohibits)
    }

    /// Takes the policy record of a group: the one policy of the group, in
    /// the place of the other party (`DEV-325`). The result is whether the
    /// policy changed.
    pub(super) fn take_group_forward_policy<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        policy: &ForwardPolicy,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let mut setting = self.forward_setting(conversation)?;
        if !setting.take(policy, false) {
            return Ok(false);
        }

        let open = self.open_mut()?;
        let row = open.store.row_id(FORWARD_POLICY, &conversation.0);
        let mut batch = open.store.begin();
        batch.put(
            FORWARD_POLICY,
            row,
            Some(conversation.0),
            &setting.encode(),
            rng,
        )?;
        batch.commit()?;

        Ok(true)
    }

    /// Sets the forward policy of the user in a conversation and sends the
    /// policy record to the other party, or to the group (`DEV-321`). In a
    /// group a member below `admin` sets no policy (`DEV-325`). The record
    /// is a row of the conversation, as a timer change is.
    pub fn set_forward_policy<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        prohibits: bool,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        let is_group = self.is_group(conversation)?;
        let mut setting = self.forward_setting(conversation)?;
        let held = if is_group { setting.peer } else { setting.own };
        let policy = ForwardPolicy {
            seq: held.seq.checked_add(1).ok_or(Error::TooLong)?,
            prohibits,
        };
        let mut body = [0u8; FORWARD_POLICY_LEN];
        policy.encode(&mut body)?;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::ForwardPolicy,
            msg_id,
            sent_at: now_ms,
            body: &body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        if is_group {
            if self
                .group_of(conversation)?
                .own_role()
                .is_none_or(|role| role < Role::Admin)
            {
                return Err(Error::Malformed);
            }
            let message = self.post_to_group(conversation, msg_id, &app, now_ms, rng)?;
            self.take_group_forward_policy(conversation, &policy, rng)?;
            return Ok(message);
        }

        setting.take(&policy, true);
        let open = self.open_mut()?;
        let reference = super::msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        let setting_row = open.store.row_id(FORWARD_POLICY, &conversation.0);
        let plain = stored_message(
            OUTGOING,
            Delivery::Queued,
            conversation,
            open.stamp.next(now_ms),
            &app,
        );

        // The record and the setting go in one commit, thus no crash leaves
        // a setting that the other party never gets.
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
        batch.put(OUTBOX, row, None, &super::outbox_row(), rng)?;
        batch.put(
            FORWARD_POLICY,
            setting_row,
            Some(conversation.0),
            &setting.encode(),
            rng,
        )?;
        batch.commit()?;
        let message = MsgRef(row);
        self.outgoing.push_back(Outgoing {
            message,
            conversation,
            app,
        });

        Ok(message)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_higher_counter_wins_and_the_prohibition_wins_at_one_counter() {
        let mut setting = ForwardSetting::default();
        let on = |seq| ForwardPolicy {
            seq,
            prohibits: true,
        };
        let off = |seq| ForwardPolicy {
            seq,
            prohibits: false,
        };
        assert!(setting.take(&off(1), false));
        assert!(setting.take(&on(1), false));
        assert!(!setting.take(&off(1), false));
        assert!(!setting.take(&on(1), false));
        assert!(setting.take(&off(2), false));
        assert!(!setting.take(&on(1), false));
        assert_eq!(setting.peer.seq, 2);
        assert!(!setting.peer.prohibits);

        // The two directions are independent.
        assert_eq!(setting.own, ForwardSide::default());
        assert!(setting.take(&on(1), true));
        assert!(setting.own.prohibits && !setting.peer.prohibits);
        let stored = setting.encode();
        assert_eq!(ForwardSetting::parse(&stored).unwrap(), setting);
        assert!(ForwardSetting::parse(&stored[..9]).is_err());
    }

    #[test]
    fn the_mark_of_a_change_reads_the_flag() {
        assert_eq!(policy_body(&[1, 0, 0, 0, 1, 1]), Some(true));
        assert_eq!(policy_body(&[1, 0, 0, 0, 1, 0]), Some(false));
        assert_eq!(policy_body(&[1, 0, 0, 0, 0, 1]), None);
    }
}
