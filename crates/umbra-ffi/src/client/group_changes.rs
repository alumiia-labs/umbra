//! The sender of each message of a group, and the edit and the deletion of
//! an author in a group (Part 7 §7.5.6, Part 11 §11.9.6). A receiver takes
//! either from the member that the verified tag of the target named, and
//! from no other. There is no role check and no signature, thus the
//! deniability of Part 5 §5.7 holds. A tombstone is terminal, and an edit
//! after it changes nothing.
//!
//! A re-key moves a member to a new index (Part 11 §11.12), and the member
//! keeps its messages. A change from the index that a re-key of the author
//! moved to counts as one of the author. The two replicas give no order,
//! thus a change can arrive before its target. It then waits in the pending
//! reference table of Part 7 §7.5.6 under the member that sent it
//! (`DEV-093`). It applies when the target of that member arrives.

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    edit::{DeleteBody, DeleteScope, EditBody},
    AppKind, AppMessage,
};
use zeroize::Zeroizing;

use super::{
    info_of, msg_ref, row_with_text, Client, EDIT_MAX, EDIT_WINDOW_MS, PENDING, PENDING_ROW_LEN,
    REF_ORPHAN_MAX, REF_ORPHAN_TTL, REVISION,
};
use crate::{ConversationId, Error, Event, MsgRef};

/// The member index that sent each message of a group that arrived, under
/// the row of the message: the conversation and the index.
pub(super) const GROUP_SENDER: TableId = TableId(0x3B);

/// A message of a group that the author of a change sent, with its row.
type Authored = (MsgRef, Zeroizing<Vec<u8>>);

/// A pending entry of a group, with its row.
type Held = ([u8; 16], Zeroizing<Vec<u8>>);

/// What a change of a group finds at its target.
enum Target {
    /// The message, which the author of the change sent.
    Held(Authored),
    /// A message of another member, or a tombstone: the change is none.
    Barred,
    /// No message yet (`DEV-093`).
    Absent,
}

/// The key of a pending reference of a group: the target, and the member
/// index that sent the change (`DEV-094`).
fn pending_group_key(natural: &[u8], sender: u16) -> Vec<u8> {
    [natural, b"member", &sender.to_be_bytes()].concat()
}

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

    /// Whether the member at `sender` now is the member that sent a message
    /// from the index `author` (Part 11 §11.12). The index is the same, or
    /// each re-key of that member since moved it there. An index whose keys
    /// a rival re-key changed holds keys that the member did not make
    /// (`GRP-369`). Thus it takes no message of the member while the roster
    /// holds that fact.
    fn is_same_member(
        &self,
        conversation: ConversationId,
        author: u16,
        sender: u16,
    ) -> Result<bool, Error> {
        if author == sender {
            return Ok(true);
        }
        let group = self.group_of(conversation)?;
        let roster = group.roster();
        let contested = roster
            .rekey_replaced()
            .is_some_and(|rival| rival.new_index == sender);
        Ok(!contested && roster.successor_of(author) == Some(sender))
    }

    /// The row of a target of a group, when the author of the change sent
    /// it: `sender` for a member, or none for this member on any device of
    /// the set.
    fn authored_target(
        &self,
        conversation: ConversationId,
        target: &[u8; 16],
        sender: Option<u16>,
    ) -> Result<Target, Error> {
        let open = self.open_ref()?;
        let reference = msg_ref(&open.device_set_key, target);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let message = MsgRef(open.store.row_id(TableId::MESSAGE, &natural));
        let Some(plain) = open.store.get(TableId::MESSAGE, &message.0)? else {
            return Ok(Target::Absent);
        };
        let plain = Zeroizing::new(plain);
        let info = info_of(&plain)?;
        let is_author = match (sender, self.group_sender(&message)?) {
            (Some(index), Some(author)) => {
                !info.outgoing && self.is_same_member(conversation, author, index)?
            }
            (Some(_), None) => false,
            (None, _) => info.outgoing,
        };
        if !is_author || info.deleted {
            return Ok(Target::Barred);
        }
        Ok(Target::Held((message, plain)))
    }

    /// Keeps a change of the member at `sender` whose target did not arrive
    /// yet (`DEV-093`). The row holds the conversation, the `msg_ref` of
    /// the target, the time, and the new text of an edit. A deletion that
    /// waits for the same target stays, and a conversation holds no more
    /// than `REF_ORPHAN_MAX` of them (`DEV-095`).
    fn hold_group_change<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        target: &[u8; 16],
        sender: u16,
        text: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let reference = msg_ref(&open.device_set_key, target);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open
            .store
            .row_id(PENDING, &pending_group_key(&natural, sender));
        let held = open.store.get(PENDING, &row)?.map(Zeroizing::new);
        let is_deleted = held
            .as_ref()
            .is_some_and(|entry| entry.len() == PENDING_ROW_LEN);
        let is_full = held.is_none()
            && open.store.list(PENDING, Some(&conversation.0))?.len() >= REF_ORPHAN_MAX;
        if is_deleted || is_full {
            return Ok(());
        }
        let entry = Zeroizing::new(
            [
                conversation.0.as_slice(),
                &reference,
                &(now_ms / 1_000).to_be_bytes(),
                text,
            ]
            .concat(),
        );
        let mut batch = open.store.begin();
        batch.put(PENDING, row, Some(conversation.0), &entry, rng)?;
        Ok(batch.commit()?)
    }

    /// The pending entry of a change of the author of a message of a group
    /// that arrives from `sender` now, at the index `index` (`DEV-093`).
    /// An entry above `REF_ORPHAN_TTL` counts for nothing (`DEV-095`).
    fn held_group_entry(
        &self,
        conversation: ConversationId,
        msg_id: &[u8; 16],
        index: u16,
        now_ms: u64,
    ) -> Result<Option<Held>, Error> {
        let open = self.open_ref()?;
        let reference = msg_ref(&open.device_set_key, msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open
            .store
            .row_id(PENDING, &pending_group_key(&natural, index));
        let Some(entry) = open.store.get(PENDING, &row)?.map(Zeroizing::new) else {
            return Ok(None);
        };
        let at = entry
            .get(32..PENDING_ROW_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(Error::Integrity)?;
        if (now_ms / 1_000).saturating_sub(at) >= REF_ORPHAN_TTL {
            return Ok(None);
        }
        Ok(Some((row, entry)))
    }

    /// Whether a deletion of its author waits for a message of a group that
    /// arrives from `sender` now (`DEV-093`). The deletion came before its
    /// target, thus the view shows nothing at that position (`DEV-102`).
    /// The entry stays until `REF_ORPHAN_TTL`. Each replica gives the
    /// message, and the copy of the other one stays out with it. The change
    /// is one of that index, or of the index that a re-key of that member
    /// moved it to.
    pub(super) fn held_group_deletion(
        &self,
        conversation: ConversationId,
        msg_id: &[u8; 16],
        sender: u16,
        now_ms: u64,
    ) -> Result<bool, Error> {
        let moved = self.group_of(conversation)?.roster().successor_of(sender);
        for index in [Some(sender), moved].into_iter().flatten() {
            if !self.is_same_member(conversation, sender, index)? {
                continue;
            }
            let held = self.held_group_entry(conversation, msg_id, index, now_ms)?;
            // An entry with no text is a deletion.
            if held.is_some_and(|(_, entry)| entry.len() == PENDING_ROW_LEN) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Applies the edit that waited for a message of a group that arrived
    /// from `sender` now (`DEV-093`). The change is one of that index, or
    /// of the index that a re-key of that member moved it to. A deletion
    /// that waited took the message before its row (`held_group_deletion`).
    pub(super) fn take_held_group_change<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: MsgRef,
        msg_id: &[u8; 16],
        sender: u16,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let moved = self.group_of(conversation)?.roster().successor_of(sender);
        for index in [Some(sender), moved].into_iter().flatten() {
            if !self.is_same_member(conversation, sender, index)? {
                continue;
            }
            let Some((row, entry)) = self.held_group_entry(conversation, msg_id, index, now_ms)?
            else {
                continue;
            };
            let text = entry.get(PENDING_ROW_LEN..).ok_or(Error::Integrity)?;
            // An entry with no text is a deletion, and it stays.
            if text.is_empty() {
                continue;
            }
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            batch.delete(PENDING, row);
            batch.commit()?;
            self.put_group_edit(conversation, message, text, now_ms, rng)?;
        }
        Ok(())
    }

    /// Gives a message of a group the text of an edit of its author
    /// (`DEV-087`, `DEV-088`). The edit must be inside the window of the
    /// store time of this device and below the limit.
    fn put_group_edit<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: MsgRef,
        text: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_ref()?;
        let Some(plain) = open.store.get(TableId::MESSAGE, &message.0)? else {
            return Ok(());
        };
        let plain = Zeroizing::new(plain);
        let info = info_of(&plain)?;
        let count = match open.store.get(REVISION, &message.0)? {
            None => 0,
            Some(count) => *count.first().ok_or(Error::Integrity)?,
        };
        let in_window = now_ms.saturating_sub(info.stored_at_ms) < EDIT_WINDOW_MS;
        if info.deleted || !in_window || count >= EDIT_MAX {
            return Ok(());
        }
        let Ok(changed) = row_with_text(&plain, text) else {
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
        Ok(())
    }

    /// Applies an edit or a deletion of an author in a group. A change that
    /// names a message of another member, or one that does not parse,
    /// changes nothing. A change of a member whose target did not arrive
    /// yet waits for it (`DEV-093`).
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
                    let message = match self.authored_target(conversation, &target, sender)? {
                        Target::Held((message, _)) => message,
                        Target::Barred => continue,
                        Target::Absent => {
                            if let Some(index) = sender {
                                self.hold_group_change(
                                    conversation,
                                    &target,
                                    index,
                                    &[],
                                    now_ms,
                                    rng,
                                )?;
                            }
                            continue;
                        }
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
                let text = edit.new_body.as_bytes();
                match self.authored_target(conversation, &edit.target, sender)? {
                    Target::Held((message, _)) => {
                        self.put_group_edit(conversation, message, text, now_ms, rng)?;
                    }
                    Target::Barred => {}
                    Target::Absent => {
                        // An entry with no text is a deletion, thus an edit
                        // to no text waits for nothing.
                        if let Some(index) = sender.filter(|_| !text.is_empty()) {
                            self.hold_group_change(
                                conversation,
                                &edit.target,
                                index,
                                text,
                                now_ms,
                                rng,
                            )?;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}
