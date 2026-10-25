//! The poll of Part 6 §6.6.6 and Part 11 §11.11: the close time of each
//! poll, the last vote of each voter, and the count that this device holds.
//! A group has no total order across senders, thus the count is the local
//! view and no agreed count (`GRP-146`, `GRP-147`, `WIR-191`).

use std::collections::BTreeSet;

use umbra_core::store::{
    engine::Backend,
    record::{RowId, TableId},
    wrap::SecureElement,
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    poll::{Poll, PollVote, OPTION_MAX},
    AppKind, AppMessage, Channel,
};
use zeroize::Zeroizing;

use super::{
    conversation_of, msg_ref, outbox_row, stored_message, Client, Outgoing, MESSAGE_PREFIX, OUTBOX,
    OUTGOING,
};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

/// The close time of each poll, under the row of its message: the
/// conversation and the time in seconds, or 0 for no close.
pub(super) const POLLS: TableId = TableId(0x36);
/// The last vote of each voter on each poll.
pub(super) const VOTES: TableId = TableId(0x37);

/// The voter of a vote of the user, on any device of the set.
pub(super) const VOTER_SELF: u16 = 0xFFFF;
/// The voter of a vote of the other party of a pairwise conversation.
pub(super) const VOTER_PEER: u16 = 0xFFFE;

/// The fixed part of a row of [`VOTES`]: the conversation, the row of the
/// poll, the voter, and the place of the vote in the order of its voter.
const VOTE_PREFIX: usize = 16 + 16 + 2 + 8;

/// A poll as this device holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollView {
    /// The question.
    pub question: String,
    /// The options, in their order.
    pub options: Vec<String>,
    /// Whether a vote takes more than one option.
    pub multiple: bool,
    /// Whether the count stays hidden until the close.
    pub hidden: bool,
    /// The close time in seconds, or 0 for no close.
    pub closes_at: u64,
    /// Whether the poll closed at `now`.
    pub closed: bool,
    /// The votes that this device holds for each option. It is empty while
    /// a hidden poll is open.
    pub counts: Vec<u32>,
    /// The voters that this device holds.
    pub voters: u32,
    /// The options of the vote of the user.
    pub mine: Vec<u8>,
}

/// The close time of a poll that a device took at `now` (`WIR-187`).
pub(super) fn poll_row(
    conversation: ConversationId,
    open_seconds: u32,
    now: u64,
) -> Zeroizing<Vec<u8>> {
    let closes_at = if open_seconds == 0 {
        0
    } else {
        now.saturating_add(u64::from(open_seconds))
    };
    Zeroizing::new([conversation.0.as_slice(), &closes_at.to_be_bytes()].concat())
}

fn closes_at_of(value: &[u8]) -> Result<u64, Error> {
    let at = value
        .get(16..24)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Integrity)?;
    Ok(u64::from_be_bytes(at))
}

/// The natural key of the vote of one voter on one poll.
fn vote_key(poll: &MsgRef, voter: u16) -> [u8; 18] {
    let mut key = [0u8; 18];
    key[..16].copy_from_slice(&poll.0);
    key[16..].copy_from_slice(&voter.to_be_bytes());
    key
}

/// The row of the poll that a vote body names, from its `target`.
pub(super) fn vote_target(body: &[u8]) -> Option<[u8; 16]> {
    body.get(1..17).and_then(|b| b.try_into().ok())
}

/// `POLL_OPEN_MIN` of Part 6 §6.6.6: the shortest period of a poll that
/// this client sends, in seconds.
pub const POLL_OPEN_MIN: u32 = 300;
/// `POLL_OPEN_MAX`: the longest such period, in seconds.
pub const POLL_OPEN_MAX: u32 = 30 * 86_400;

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The poll row of a message, its app bytes, and its conversation.
    fn poll_record(&self, poll: &MsgRef) -> Result<(ConversationId, Zeroizing<Vec<u8>>), Error> {
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &poll.0)?
                .ok_or(Error::NotFound)?,
        );
        let conversation = conversation_of(&plain)?;
        let app = Zeroizing::new(
            plain
                .get(MESSAGE_PREFIX..)
                .ok_or(Error::Integrity)?
                .to_vec(),
        );
        if AppMessage::parse(&app, Channel::Group)?.kind != AppKind::Poll {
            return Err(Error::Malformed);
        }

        Ok((conversation, app))
    }

    /// The close time of a poll, or 0 for no close.
    fn closes_at(&self, poll: &MsgRef) -> Result<u64, Error> {
        match self.open_ref()?.store.get(POLLS, &poll.0)? {
            Some(value) => closes_at_of(&value),
            None => Ok(0),
        }
    }

    /// Keeps the close time of a poll that this device took or sent.
    pub(super) fn open_poll<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        poll: MsgRef,
        open_seconds: u32,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = poll_row(conversation, open_seconds, now);
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(POLLS, poll.0, Some(conversation.0), &value, rng)?;
        Ok(batch.commit()?)
    }

    /// Takes one vote of `voter` at `position` in the order of that voter.
    /// A vote on a poll that this device does not hold, a vote that does not
    /// parse against its poll, and a vote after the close go (`WIR-189`). A
    /// later vote of one voter takes the place of an earlier one
    /// (`WIR-190`). The result is the poll that the vote moved.
    pub(super) fn take_vote<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        body: &[u8],
        voter: u16,
        position: u64,
        now: u64,
        rng: &mut R,
    ) -> Result<Option<MsgRef>, Error> {
        let Some(target) = vote_target(body) else {
            return Ok(None);
        };

        let open = self.open_ref()?;
        let reference = msg_ref(&open.device_set_key, &target);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let poll = MsgRef(open.store.row_id(TableId::MESSAGE, &natural));
        let Ok((held_in, app)) = self.poll_record(&poll) else {
            return Ok(None);
        };

        // GRP-142: a vote names a poll of its own conversation.
        if held_in != conversation {
            return Ok(None);
        }

        let parsed = AppMessage::parse(&app, Channel::Group)?;
        let Ok(question) = Poll::parse(parsed.body) else {
            return Ok(None);
        };
        let Ok(vote) = PollVote::parse(body, &question) else {
            return Ok(None);
        };

        let closes_at = self.closes_at(&poll)?;
        if closes_at != 0 && now > closes_at {
            return Ok(None);
        }

        // WIR-190: a member that re-keyed votes under its newest index, thus
        // its vote before the re-key and after it are one vote.
        let voter = if voter == VOTER_SELF {
            voter
        } else {
            self.group_of(conversation)
                .ok()
                .and_then(|group| group.roster().successor_of(voter))
                .unwrap_or(voter)
        };
        let open = self.open_ref()?;
        let row = open.store.row_id(VOTES, &vote_key(&poll, voter));
        if let Some(held) = open.store.get(VOTES, &row)? {
            let at: [u8; 8] = held
                .get(34..VOTE_PREFIX)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?;
            if u64::from_be_bytes(at) > position {
                return Ok(None);
            }
        }

        let value = Zeroizing::new(
            [
                conversation.0.as_slice(),
                &poll.0,
                &voter.to_be_bytes(),
                &position.to_be_bytes(),
                &vote.choices,
            ]
            .concat(),
        );
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(VOTES, row, Some(conversation.0), &value, rng)?;
        batch.commit()?;
        self.events.push_back(Event::Voted {
            conversation,
            message: poll,
        });

        Ok(Some(poll))
    }

    /// Sends a poll to a conversation. A group above `POLL_GROUP_MAX`
    /// members takes none (`GRP-149`).
    #[allow(clippy::too_many_arguments)]
    pub fn send_poll<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        question: &str,
        options: &[&str],
        multiple: bool,
        hidden: bool,
        open_seconds: u32,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        let is_group = self.is_group(conversation)?;
        if is_group
            && self.group_of(conversation)?.roster().active_count()
                > umbra_core::group::POLL_GROUP_MAX
        {
            return Err(Error::TooLong);
        }

        // A poll that hides its count until the close needs a close.
        if hidden && open_seconds == 0 {
            return Err(Error::Malformed);
        }

        // WIR-557: no period, or one inside the two bounds.
        if open_seconds != 0 && !(POLL_OPEN_MIN..=POLL_OPEN_MAX).contains(&open_seconds) {
            return Err(Error::Malformed);
        }

        let poll = Poll {
            multiple,
            hidden,
            open_seconds,
            question,
            options: options.to_vec(),
        };
        let mut body = vec![
            0u8;
            8usize
                .saturating_add(question.len())
                .saturating_add(options.len() * 101)
        ];
        let used = poll.encode(&mut body)?;
        body.truncate(used);
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::Poll,
            msg_id,
            sent_at: now_ms,
            body: &body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        let now = now_ms / 1_000;
        let message = if is_group {
            let message = self.post_to_group(conversation, msg_id, &app, now_ms, rng)?;
            self.open_poll(conversation, message, open_seconds, now, rng)?;
            message
        } else {
            let open = self.open_mut()?;
            let reference = msg_ref(&open.device_set_key, &msg_id);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            let plain = stored_message(
                OUTGOING,
                Delivery::Queued,
                conversation,
                open.stamp.next(now_ms),
                &app,
            );
            let value = poll_row(conversation, open_seconds, now);
            let mut batch = open.store.begin();
            batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
            batch.put(OUTBOX, row, None, &outbox_row(), rng)?;
            batch.put(POLLS, row, Some(conversation.0), &value, rng)?;
            batch.commit()?;
            let message = MsgRef(row);
            self.stamp_deadline(conversation, message, AppKind::Poll, now, rng)?;
            self.outgoing.push_back(Outgoing {
                message,
                conversation,
                app,
            });
            message
        };
        self.auto_lock.touch(now);

        Ok(message)
    }

    /// Votes on a poll, or changes the vote of the user. The vote goes as one
    /// record of the conversation, and in a group as one group record and
    /// never to the author alone (`GRP-336`, `GRP-337`).
    pub fn vote<R: CryptoRng + ?Sized>(
        &mut self,
        poll: &MsgRef,
        choices: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let (conversation, app) = self.poll_record(poll)?;
        let parsed = AppMessage::parse(&app, Channel::Group)?;
        let question = Poll::parse(parsed.body)?;
        let now = now_ms / 1_000;
        let closes_at = self.closes_at(poll)?;
        if closes_at != 0 && now > closes_at {
            return Err(Error::Closed);
        }
        self.refuse_observer(conversation, AppKind::PollVote)?;

        let vote = PollVote {
            target: parsed.msg_id,
            choices: choices.to_vec(),
        };
        let mut body = vec![0u8; 18usize.saturating_add(OPTION_MAX)];
        let used = vote.encode(&question, &mut body)?;
        body.truncate(used);
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::PollVote,
            msg_id,
            sent_at: now_ms,
            body: &body,
        };
        let mut request = vec![0u8; record.len()];
        record.encode(&mut request)?;
        self.take_vote(conversation, &body, VOTER_SELF, now_ms, now, rng)?;
        if self.is_group(conversation)? {
            self.post_to_group(conversation, msg_id, &request, now_ms, rng)?;
        } else {
            // The request row holds the record for its send, and no view
            // shows it.
            let open = self.open_mut()?;
            let reference = msg_ref(&open.device_set_key, &msg_id);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            let stored = stored_message(
                OUTGOING,
                Delivery::Queued,
                conversation,
                open.stamp.next(now_ms),
                &request,
            );
            let mut batch = open.store.begin();
            batch.put(TableId::MESSAGE, row, Some(conversation.0), &stored, rng)?;
            batch.put(OUTBOX, row, None, &outbox_row(), rng)?;
            batch.commit()?;
            self.outgoing.push_back(Outgoing {
                message: MsgRef(row),
                conversation,
                app: request,
            });
        }

        self.auto_lock.touch(now);

        Ok(())
    }

    /// The poll of a message with the count that this device holds at
    /// `now`. The view shows that the count is the local one (`GRP-148`).
    pub fn poll_view(&self, poll: &MsgRef, now: u64) -> Result<PollView, Error> {
        let (conversation, app) = self.poll_record(poll)?;
        let parsed = AppMessage::parse(&app, Channel::Group)?;
        let question = Poll::parse(parsed.body)?;
        let closes_at = self.closes_at(poll)?;
        let closed = closes_at != 0 && now > closes_at;
        let mut counts = vec![0u32; question.options.len()];
        let mut mine = Vec::new();

        // WIR-190: one vote for each member, under its newest index, and
        // the latest position of that member wins.
        let group = self.group_of(conversation).ok();
        let mut by_member: std::collections::BTreeMap<u16, (u64, Vec<u8>)> =
            std::collections::BTreeMap::new();
        for (_, value) in self.open_ref()?.store.list(VOTES, Some(&conversation.0))? {
            let value = Zeroizing::new(value);
            if value.get(16..32) != Some(poll.0.as_slice()) {
                continue;
            }

            let voter: [u8; 2] = value
                .get(32..34)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?;
            let voter = u16::from_be_bytes(voter);
            let position = value
                .get(34..VOTE_PREFIX)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u64::from_be_bytes);
            let choices = value.get(VOTE_PREFIX..).ok_or(Error::Integrity)?;
            if voter == VOTER_SELF {
                mine = choices.to_vec();
            }

            let member = if voter == VOTER_SELF {
                voter
            } else {
                group
                    .as_ref()
                    .and_then(|group| group.roster().successor_of(voter))
                    .unwrap_or(voter)
            };
            let held = by_member
                .entry(member)
                .or_insert((position, choices.to_vec()));
            if position > held.0 {
                *held = (position, choices.to_vec());
            }
        }

        let voters = u32::try_from(by_member.len()).unwrap_or(u32::MAX);
        for (_, choices) in by_member.values() {
            for choice in choices {
                if let Some(count) = counts.get_mut(usize::from(*choice)) {
                    *count = count.saturating_add(1);
                }
            }
        }

        if question.hidden && !closed {
            counts.clear();
        }

        Ok(PollView {
            question: question.question.to_owned(),
            options: question
                .options
                .iter()
                .map(|option| (*option).to_owned())
                .collect(),
            multiple: question.multiple,
            hidden: question.hidden,
            closes_at,
            closed,
            counts,
            voters,
            mine,
        })
    }

    /// The rows of the votes on a poll, for its erasure.
    pub(super) fn vote_rows(
        &self,
        poll: &MsgRef,
        conversation: ConversationId,
    ) -> Result<Vec<RowId>, Error> {
        self.votes_on(&BTreeSet::from([poll.0]), conversation)
    }

    /// The rows of the votes in a conversation on each poll of `polls`.
    pub(super) fn votes_on(
        &self,
        polls: &BTreeSet<RowId>,
        conversation: ConversationId,
    ) -> Result<Vec<RowId>, Error> {
        let mut rows = Vec::new();
        for (row, value) in self.open_ref()?.store.list(VOTES, Some(&conversation.0))? {
            let poll = value
                .get(16..32)
                .and_then(|bytes| RowId::try_from(bytes).ok());
            if poll.is_some_and(|poll| polls.contains(&poll)) {
                rows.push(row);
            }
        }

        Ok(rows)
    }
}
