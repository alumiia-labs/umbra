//! Social recovery of Part 4 §4.7.3: the shares of `C_social` that this
//! user gave to contacts, and the shares that contacts gave to this user.
//! A share alone recovers nothing, and `C_user` stays with the user.

use umbra_core::{
    identity::recovery::{split_social, to_digits, DigitsType},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{recovery::RecoveryShare, AppKind, AppMessage};
use zeroize::Zeroizing;

use super::{msg_ref, outbox_row, stored_message, Client, Outgoing, OUTBOX, OUTGOING};
use crate::{ConversationId, Delivery, Error, Event, MsgRef, Sink};

/// The last share that each contact gave to this user, under the row of the
/// conversation: the conversation, the time, and the `RecoveryShare` body.
pub(super) const SHARES_HELD: TableId = TableId(0x3F);
/// The share of the current split that each holder took, under the row of
/// the conversation: the conversation, the time, and the index, the
/// threshold, and the count.
pub(super) const SHARES_GIVEN: TableId = TableId(0x40);

/// A share that a contact gave to this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldShare {
    /// The shares that a recovery of that contact needs.
    pub threshold: u8,
    /// The shares of that split.
    pub count: u8,
    /// The index of this share.
    pub index: u8,
    /// The time of its arrival, in milliseconds.
    pub at_ms: u64,
}

/// A share of the current split of this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GivenShare {
    /// The holder.
    pub conversation: ConversationId,
    /// The index of the share.
    pub index: u8,
    /// The shares that a recovery needs.
    pub threshold: u8,
    /// The shares of the split.
    pub count: u8,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Splits `C_social` into one share for each holder, `threshold` of them
    /// for a recovery, and sends each share on the pairwise channel of its
    /// holder (`IDN-083`, `IDN-187`, `IDN-188`). A new split draws a new
    /// `set_id`, and it takes the place of the last one (`IDN-192`).
    pub fn split_social<R: CryptoRng + ?Sized>(
        &mut self,
        holders: &[ConversationId],
        threshold: u8,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let count = u8::try_from(holders.len()).map_err(|_| Error::TooLong)?;
        let mut unique = holders.to_vec();
        unique.sort_unstable();
        unique.dedup();
        if threshold < 2 || count < threshold || unique.len() != holders.len() {
            return Err(Error::Malformed);
        }
        let device_peers = self.device_peers()?;
        for holder in holders {
            if self.is_group(*holder)?
                || device_peers.contains(holder)
                || self.is_ended_channel(*holder)?
            {
                return Err(Error::Malformed);
            }
        }
        let code = self.recovery_code(rng)?;
        let mut coeffs = Zeroizing::new(vec![0u8; usize::from(threshold - 1) * 16]);
        rng.fill_bytes(&mut coeffs);
        // IDN-084, IDN-085: the social half alone goes into a share.
        let shares = split_social(code.social(), threshold, count, &coeffs)?;
        let mut set_id = [0u8; 16];
        rng.fill_bytes(&mut set_id);
        let old: Vec<[u8; 16]> = self
            .open_ref()?
            .store
            .list(SHARES_GIVEN, None)?
            .into_iter()
            .map(|(row, _)| row)
            .collect();
        let mut sends = Vec::with_capacity(shares.len());
        for (holder, share) in holders.iter().zip(shares.iter()) {
            let body = Zeroizing::new(
                RecoveryShare {
                    set_id,
                    threshold,
                    count,
                    share: *share,
                }
                .encode()?,
            );
            let mut msg_id = [0u8; 16];
            rng.fill_bytes(&mut msg_id);
            let record = AppMessage {
                kind: AppKind::RecoveryShare,
                msg_id,
                sent_at: now_ms,
                body: body.as_ref(),
            };
            let mut app = Zeroizing::new(vec![0u8; record.len()]);
            record.encode(&mut app)?;
            sends.push((*holder, msg_id, app, share[0]));
        }
        let open = self.open_mut()?;
        let rows: Vec<[u8; 16]> = sends
            .iter()
            .map(|(holder, msg_id, _, _)| {
                let reference = msg_ref(&open.device_set_key, msg_id);
                open.store.row_id(
                    TableId::MESSAGE,
                    &[holder.0.as_slice(), &reference].concat(),
                )
            })
            .collect();
        let mut batch = open.store.begin();
        for row in old {
            batch.delete(SHARES_GIVEN, row);
        }
        let mut outgoing = Vec::with_capacity(sends.len());
        for ((holder, _, app, index), row) in sends.iter().zip(rows) {
            // The request row holds the record for its send, and no view
            // shows it.
            let stored = stored_message(
                OUTGOING,
                Delivery::Queued,
                *holder,
                open.stamp.next(now_ms),
                app,
            );
            batch.put(TableId::MESSAGE, row, Some(holder.0), &stored, rng)?;
            batch.put(OUTBOX, row, None, &outbox_row(), rng)?;
            let given = [
                holder.0.as_slice(),
                &now_ms.to_be_bytes(),
                &[*index, threshold, count],
            ]
            .concat();
            batch.put(SHARES_GIVEN, holder.0, Some(holder.0), &given, rng)?;
            outgoing.push(Outgoing {
                message: MsgRef(row),
                conversation: *holder,
                app: app.to_vec(),
            });
        }
        batch.commit()?;
        self.outgoing.extend(outgoing);
        Ok(())
    }

    /// The holders of the current split.
    pub fn shares_given(&self) -> Result<Vec<GivenShare>, Error> {
        let mut given = Vec::new();
        for (row, value) in self.open_ref()?.store.list(SHARES_GIVEN, None)? {
            let [index, threshold, count] = value
                .get(24..27)
                .and_then(|b| <[u8; 3]>::try_from(b).ok())
                .ok_or(Error::Integrity)?;
            given.push(GivenShare {
                conversation: ConversationId(row),
                index,
                threshold,
                count,
            });
        }
        given.sort_by_key(|share| share.index);
        Ok(given)
    }

    /// Keeps the share that a contact gave to this user, in the place of an
    /// earlier one (`IDN-189`). A body that does not parse changes nothing.
    pub(super) fn take_share<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if RecoveryShare::parse(body).is_err() {
            return Ok(());
        }
        let value =
            Zeroizing::new([conversation.0.as_slice(), &now_ms.to_be_bytes(), body].concat());
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(
            SHARES_HELD,
            conversation.0,
            Some(conversation.0),
            &value,
            rng,
        )?;
        batch.commit()?;
        self.events.push_back(Event::Conversations);
        Ok(())
    }

    fn held_body(
        &self,
        conversation: ConversationId,
    ) -> Result<Option<(u64, RecoveryShare)>, Error> {
        let Some(value) = self.open_ref()?.store.get(SHARES_HELD, &conversation.0)? else {
            return Ok(None);
        };
        let value = Zeroizing::new(value);
        let at: [u8; 8] = value
            .get(16..24)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Integrity)?;
        let body = RecoveryShare::parse(value.get(24..).ok_or(Error::Integrity)?)?;
        Ok(Some((u64::from_be_bytes(at), body)))
    }

    /// The share that a contact gave to this user, or none.
    pub fn held_share(&self, conversation: ConversationId) -> Result<Option<HeldShare>, Error> {
        Ok(self
            .held_body(conversation)?
            .map(|(at_ms, body)| HeldShare {
                threshold: body.threshold,
                count: body.count,
                index: body.share[0],
                at_ms,
            }))
    }

    /// Writes the share that a contact gave to this user into `sink`, as
    /// `RecoveryDigits` of type `0x0003`: the one way it goes back
    /// (`IDN-189`, `IDN-190`).
    pub fn render_held_share(
        &self,
        conversation: ConversationId,
        sink: &mut dyn Sink,
    ) -> Result<(), Error> {
        let (_, body) = self.held_body(conversation)?.ok_or(Error::NotFound)?;
        let digits = to_digits(DigitsType::Share, &body.share)?;
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(digits.encode_utf16().collect());
        sink.put(&units);
        Ok(())
    }

    /// Writes `C_user` into `sink` as `RecoveryDigits` of type `0x0002`,
    /// the half that stays with the user (`IDN-149`).
    pub fn render_user_half<R: CryptoRng + ?Sized>(
        &mut self,
        sink: &mut dyn Sink,
        rng: &mut R,
    ) -> Result<(), Error> {
        let code = self.recovery_code(rng)?;
        let digits = to_digits(DigitsType::User, code.user().expose())?;
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(digits.encode_utf16().collect());
        sink.put(&units);
        Ok(())
    }
}
