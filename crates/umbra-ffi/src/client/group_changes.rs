//! The sender of each message of a group, and the edit and the deletion of
//! an author in a group (Part 7 §7.5.6, Part 11 §11.9.6). A receiver takes
//! either from the member that the verified tag of the target named, and
//! from no other. There is no role check and no signature, thus the
//! deniability of Part 5 §5.7 holds. A tombstone is terminal, and an edit
//! after it changes nothing.

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    edit::{DeleteBody, DeleteScope, EditBody},
    AppKind, AppMessage,
};
use zeroize::Zeroizing;

use super::{info_of, msg_ref, row_with_text, Client, EDIT_MAX, EDIT_WINDOW_MS, REVISION};
use crate::{ConversationId, Error, Event, MsgRef};

/// The member index that sent each message of a group that arrived, under
/// the row of the message: the conversation and the index.
pub(super) const GROUP_SENDER: TableId = TableId(0x3B);

/// A message of a group that the author of a change sent, with its row.
type Authored = (MsgRef, Zeroizing<Vec<u8>>);

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Keeps the sender of a message of a group that arrived.
    pub(super) fn put_group_sender<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: MsgRef,
        sender: u16,
        is_recovered: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        // WIR-462: a record that opened under the secret of a key supply
        // keeps that mark after the sender.
        let value = [
            conversation.0.as_slice(),
            &sender.to_be_bytes(),
            if is_recovered { &[1u8][..] } else { &[] },
        ]
        .concat();
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP_SENDER, message.0, Some(conversation.0), &value, rng)?;
        Ok(batch.commit()?)
    }

    /// The member index that sent a message of a group, or none for a
    /// message of this member.
    pub fn group_sender(&self, message: &MsgRef) -> Result<Option<u16>, Error> {
        let Some(value) = self.open_ref()?.store.get(GROUP_SENDER, &message.0)? else {
            return Ok(None);
        };
        let index: [u8; 2] = value
            .get(16..18)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Integrity)?;
        Ok(Some(u16::from_be_bytes(index)))
    }

    /// Whether a message of a group opened under an epoch secret that a
    /// one-slot epoch-key record gave (`WIR-462`). The view shows it apart
    /// from a record whose counter this device tracked (`WIR-463`).
    pub fn is_recovered(&self, message: &MsgRef) -> Result<bool, Error> {
        Ok(self
            .open_ref()?
            .store
            .get(GROUP_SENDER, &message.0)?
            .is_some_and(|value| value.get(18) == Some(&1)))
    }

    /// The row of a target of a group, when the author of the change sent
    /// it: `sender` for a member, or none for this member on any device of
    /// the set.
    fn authored_target(
        &self,
        conversation: ConversationId,
        target: &[u8; 16],
        sender: Option<u16>,
    ) -> Result<Option<Authored>, Error> {
        let open = self.open_ref()?;
        let reference = msg_ref(&open.device_set_key, target);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let message = MsgRef(open.store.row_id(TableId::MESSAGE, &natural));
        let Some(plain) = open.store.get(TableId::MESSAGE, &message.0)? else {
            return Ok(None);
        };
        let plain = Zeroizing::new(plain);
        let info = info_of(&plain)?;
        let is_author = match sender {
            Some(index) => !info.outgoing && self.group_sender(&message)? == Some(index),
            None => info.outgoing,
        };
        if !is_author || info.deleted {
            return Ok(None);
        }
        Ok(Some((message, plain)))
    }

    /// Applies an edit or a deletion of an author in a group. A change that
    /// names a message of another member, or one that does not parse,
    /// changes nothing.
    pub(super) fn take_group_change<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        sender: Option<u16>,
        parsed: &AppMessage<'_>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        match parsed.kind {
            AppKind::Delete => {
                let targets = match DeleteBody::parse(parsed.body) {
                    Ok(body) if body.scope == DeleteScope::OtherParty => body.targets,
                    _ => return Ok(()),
                };
                for target in targets {
                    let Some((message, _)) = self.authored_target(conversation, &target, sender)?
                    else {
                        continue;
                    };
                    self.leave_placeholder(conversation, message, rng)?;
                    self.events.push_back(Event::Deleted {
                        conversation,
                        message,
                    });
                }
            }
            AppKind::Edit => {
                let Ok(edit) = EditBody::parse(parsed.body) else {
                    return Ok(());
                };
                let Some((message, plain)) =
                    self.authored_target(conversation, &edit.target, sender)?
                else {
                    return Ok(());
                };
                let info = info_of(&plain)?;
                let open = self.open_ref()?;
                let count = match open.store.get(REVISION, &message.0)? {
                    None => 0,
                    Some(count) => *count.first().ok_or(Error::Integrity)?,
                };
                // DEV-087, DEV-088: inside the window of the store time of
                // this device, and below the limit.
                let in_window = now_ms.saturating_sub(info.stored_at_ms) < EDIT_WINDOW_MS;
                if !in_window || count >= EDIT_MAX {
                    return Ok(());
                }
                let Ok(changed) = row_with_text(&plain, edit.new_body.as_bytes()) else {
                    return Ok(());
                };
                let open = self.open_mut()?;
                let mut batch = open.store.begin();
                batch.put(
                    TableId::MESSAGE,
                    message.0,
                    Some(conversation.0),
                    &changed,
                    rng,
                )?;
                batch.put(REVISION, message.0, None, &[count.saturating_add(1)], rng)?;
                // IMP-154: the earlier text leaves the log of the store.
                batch.erase_earlier();
                batch.commit()?;
                self.events.push_back(Event::Edited {
                    conversation,
                    message,
                });
            }
            _ => {}
        }
        Ok(())
    }
}
