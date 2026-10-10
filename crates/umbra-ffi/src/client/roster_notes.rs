//! The changes of the roster of a group, as the conversation shows them: a
//! member that joins, one that leaves, one that an admin removed for its
//! silence (`GRP-050`), a new role, and a fork of the chain (`GRP-070` to
//! `GRP-074`). A note is local state of this device and no record. A
//! pairwise conversation takes one kind of note, the delivery gap of Part 3
//! `NET-103`.

use umbra_core::{
    group::{roster::Fork, state::Group},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::group::control::Role;

use super::{Client, Silence};
use crate::{ConversationId, Error};

/// One row for each change of a roster that this device applied: the
/// conversation, the time, the kind, the member index, and the role.
pub(super) const ROSTER_NOTES: TableId = TableId(0x3C);

/// A member joined.
pub const NOTE_JOINED: u8 = 1;
/// A member left, by its own act or by a removal.
pub const NOTE_LEFT: u8 = 2;
/// This admin removed a member for its silence (`GRP-050`).
pub const NOTE_EVICTED: u8 = 3;
/// A member took a new role.
pub const NOTE_ROLE: u8 = 4;
/// One member made two successors of one epoch (`GRP-070`). The index names
/// that member where a signature names it (`GRP-072`), and it is `0xFFFF`
/// for plain epochs, which name nobody (`GRP-073`, `GRP-074`).
pub const NOTE_FORK: u8 = 5;

/// This device acknowledged the queue of the contact above a hole, thus
/// the records in that hole are lost (Part 3 `NET-103`, Part 6 `WIR-117`),
/// or it read no replica of a group for longer than `GROUP_RETENTION`
/// (Part 11 `GRP-208`).
pub const NOTE_GAP: u8 = 6;

/// The least time between two moves of the read time of a group, in
/// seconds.
const READ_CLOCK_STEP: u64 = 86_400;

/// The index of a note that names no member.
pub const NOTE_NOBODY: u16 = 0xFFFF;

/// One change of a roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterNote {
    /// The time of the application, in milliseconds.
    pub at_ms: u64,
    /// The kind, one of the `NOTE_` values.
    pub kind: u8,
    /// The member index, or `NOTE_NOBODY`.
    pub index: u16,
    /// The new role of `NOTE_ROLE`, else 0.
    pub role: u8,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Keeps one change of a roster, and the view of the conversation
    /// reads it again.
    pub(super) fn put_roster_note<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        note: RosterNote,
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = [
            conversation.0.as_slice(),
            &note.at_ms.to_be_bytes(),
            &[note.kind],
            &note.index.to_be_bytes(),
            &[note.role],
        ]
        .concat();
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        let open = self.open_mut()?;
        let row = open.store.row_id(ROSTER_NOTES, &key);
        let mut batch = open.store.begin();
        batch.put(ROSTER_NOTES, row, Some(conversation.0), &value, rng)?;
        batch.commit()?;
        self.groups.noted.insert(conversation);
        Ok(())
    }

    /// Keeps a delivery gap in a conversation (`NET-103`). The
    /// conversation shows it, thus it is never complete to the view
    /// (`WIR-118`).
    pub fn delivery_gap<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.put_roster_note(
            conversation,
            RosterNote {
                at_ms: now_ms,
                kind: NOTE_GAP,
                index: NOTE_NOBODY,
                role: 0,
            },
            rng,
        )
    }

    /// Takes the reads of the groups that this device subscribes to now
    /// (`GRP-208`). A group that no subscription read for more than
    /// `GROUP_RETENTION` shows a gap: the replicas erased the records of
    /// that period, and no party holds them. The read time moves once in
    /// `READ_CLOCK_STEP` at most, thus a subscription that runs costs no
    /// write at each tick.
    ///
    /// The call directly after [`Client::group_subscriptions`] names a
    /// group whose `GSUB` goes now, and the session of that group starts
    /// here. Each other call names the groups that a subscription reads at
    /// this tick, and it is the sign of life of each watch (`GRP-396`).
    pub fn group_reads<R: CryptoRng + ?Sized>(
        &mut self,
        conversations: &[ConversationId],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let now = now_ms / 1_000;
        if self.groups.offered {
            for &conversation in conversations {
                self.group_read_started(conversation, now, rng)?;
            }
        } else {
            self.group_reads_live(conversations, now);
        }
        for &conversation in conversations {
            let key = [conversation.0.as_slice(), b"read"].concat();
            let last = self.clock(&key)?;
            if last.is_some_and(|at| now.saturating_sub(at) > umbra_queue::params::GROUP_RETENTION)
            {
                self.put_roster_note(
                    conversation,
                    RosterNote {
                        at_ms: now_ms,
                        kind: NOTE_GAP,
                        index: NOTE_NOBODY,
                        role: 0,
                    },
                    rng,
                )?;
                // GRP-329: the roster objects of that period are gone too.
                self.request_roster_snapshot(conversation, now_ms, rng)?;
            }
            if last.is_none_or(|at| now.saturating_sub(at) >= READ_CLOCK_STEP) {
                self.put_clock(conversation, key, now, rng)?;
            }
        }
        Ok(())
    }

    /// Keeps each fork that the roster found since `before` of them
    /// (`GRP-070`).
    pub(super) fn note_forks<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        before: usize,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let forks: Vec<Fork> = group
            .roster()
            .forks()
            .iter()
            .skip(before)
            .copied()
            .collect();
        for fork in forks {
            self.put_roster_note(
                conversation,
                RosterNote {
                    at_ms: now_ms,
                    kind: NOTE_FORK,
                    index: fork.named.unwrap_or(NOTE_NOBODY),
                    role: 0,
                },
                rng,
            )?;
        }
        Ok(())
    }

    /// Acts on the silence of a member, and the note of a removal says why
    /// (`GRP-050`).
    pub fn act_on_silence<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        index: u16,
        action: Silence,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        match action {
            Silence::Remove => {
                self.groups.evicting = Some((conversation, index));
                let removed = self.remove_from_group(conversation, index, now_ms, rng);
                self.groups.evicting = None;
                removed
            }
            Silence::Demote => self.set_group_role(conversation, index, Role::Member, now_ms, rng),
        }
    }

    /// The changes of the roster of a conversation, in the order of time.
    pub fn roster_notes(&self, conversation: ConversationId) -> Result<Vec<RosterNote>, Error> {
        let mut notes = Vec::new();
        for (_, value) in self
            .open_ref()?
            .store
            .list(ROSTER_NOTES, Some(&conversation.0))?
        {
            let at: [u8; 8] = value
                .get(16..24)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?;
            let index: [u8; 2] = value
                .get(25..27)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?;
            notes.push(RosterNote {
                at_ms: u64::from_be_bytes(at),
                kind: *value.get(24).ok_or(Error::Integrity)?,
                index: u16::from_be_bytes(index),
                role: *value.get(27).ok_or(Error::Integrity)?,
            });
        }
        notes.sort_by_key(|note| note.at_ms);
        Ok(notes)
    }
}
