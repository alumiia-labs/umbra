//! The full identity reset of Part 7 §7.7.1 on the sending side: a new
//! identity root, a key-change notice to each contact at its own delay
//! (Part 4 §4.5.1), a new device roster, and the re-key of each group.
//!
//! The reset keeps the storage seed. `K_store` wraps the database, and
//! `K_set` names each stored message by `msg_ref`. A new `K_set` would
//! strand each stored reference, and a reply holds its target as a
//! reference alone, thus no migration could recover it. The identity root
//! is a row of its own, and each pairwise key and each key of discovery
//! comes from it (`DEV-305`, `DEV-306`).

use umbra_core::{
    identity::keychange::sweep_delay,
    session::node::stored_contact_salt,
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::{hierarchy::RootIdentity, rand_core::CryptoRng, secret::Secret};
use umbra_wire::app::{keys::KeyChangeNotice, AppKind, AppMessage};
use zeroize::Zeroizing;

use super::{
    msg_ref, outbox_row, stored_message, Client, Outgoing, OUTBOX, OUTGOING, QUEUE_ID_LEN,
};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

/// The identity root after a reset, in the local identity table. A device
/// with no reset holds none, and its storage seed is its identity root.
pub(super) const IDENTITY_ROOT_KEY: &[u8] = b"identity-root";
/// The key-change notices that wait for their delay: the conversation, the
/// time at which the notice goes, and the record. A row stays until a relay
/// took its notice (`IDN-063`). The row of a notice on the send path holds
/// [`IN_FLIGHT`], and a notice that failed takes a new delay.
pub(super) const RESET_NOTICES: TableId = TableId(0x3E);
/// The time of a notice that the send path holds.
const IN_FLIGHT: u64 = u64::MAX;

/// What a reset started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetSummary {
    /// The contacts that take a key-change notice.
    pub contacts: u32,
    /// The groups that take a re-key.
    pub groups: u32,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The identity root: the row of a reset, or the storage seed.
    pub(super) fn identity_seed(&self) -> Result<Option<[u8; 32]>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(TableId::LOCAL_IDENTITY, IDENTITY_ROOT_KEY);
        match store.get(TableId::LOCAL_IDENTITY, &row)? {
            Some(seed) => Ok(Some(
                seed.as_slice().try_into().map_err(|_| Error::Integrity)?,
            )),
            None => Ok(None),
        }
    }

    /// Makes a new identity root and starts each step of §7.7.1. A set of
    /// more than one device takes no reset: each other device leaves the
    /// set first, thus the new root and the new roster reach no device in
    /// hostile hands (`DEV-307`).
    pub fn reset_identity<R: CryptoRng + umbra_crypto::rand_core::TryCryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<ResetSummary, Error> {
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        if self.devices()?.len() > 1 {
            return Err(Error::Busy);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut());
        let root = RootIdentity::new(Secret::new(*seed));
        let now = now_ms / 1_000;
        // DEV-172, DEV-173: a new roster key and a new roster epoch 0. Each
        // key comes before the first write, thus a fault leaves no half of
        // a reset.
        let (device, roster) = self.new_device_set(rng)?;

        // Part 4 §4.5.1: one notice for each contact, on its own channel,
        // at its own delay (IDN-063, IDN-064). A group takes none
        // (IDN-056), and neither does a sync channel of a device.
        let device_peers = self.device_peers()?;
        let mut notices = Vec::new();
        for (row, plain) in self.open_ref()?.store.list(TableId::CONTACT, None)? {
            let conversation = ConversationId(row);
            if device_peers.contains(&conversation) || self.is_ended_channel(conversation)? {
                continue;
            }
            let plain = Zeroizing::new(plain);
            let Some(state) = plain.get(QUEUE_ID_LEN..) else {
                continue;
            };
            // A contact whose channel another device owns has no ratchet
            // here, and its salt alone.
            let Ok(salt) = stored_contact_salt(state) else {
                continue;
            };
            let public = root.pairwise_identity(&salt).public().to_bytes();
            let (x25519, mlkem) = public.split_at(32);
            let notice = KeyChangeNotice {
                new_x25519_pk: x25519.try_into().map_err(|_| Error::Integrity)?,
                new_mlkem_pk: mlkem,
            };
            let mut body = vec![0u8; umbra_wire::app::keys::KEY_CHANGE_LEN];
            notice.encode(&mut body)?;
            let mut msg_id = [0u8; 16];
            rng.fill_bytes(&mut msg_id);
            let record = AppMessage {
                kind: AppKind::KeyChange,
                msg_id,
                sent_at: now_ms,
                body: &body,
            };
            let mut app = vec![0u8; record.len()];
            record.encode(&mut app)?;
            let due = now.saturating_add(sweep_delay(rng.next_u64()));
            notices.push((conversation, due, app));
        }
        // DEV-306, DIS-093: the directory holds the key of the root before
        // the reset for each entry that this device publishes. The device
        // keeps that root for those entries alone, in the commit of the new
        // root. Thus it still takes a hello, renews, rotates, and retires
        // each one, and it strands no handle and no link.
        let earlier_roots = self.roots_for_published()?;
        let open = self.open_mut()?;
        let identity_row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, IDENTITY_ROOT_KEY);
        let earlier_row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, super::discovery::EARLIER_ROOTS_KEY);
        let mut batch = open.store.begin();
        batch.put(
            TableId::LOCAL_IDENTITY,
            identity_row,
            None,
            seed.as_ref(),
            rng,
        )?;
        if let Some(earlier_roots) = &earlier_roots {
            batch.put(
                TableId::LOCAL_IDENTITY,
                earlier_row,
                None,
                earlier_roots,
                rng,
            )?;
        }
        for (conversation, due, app) in &notices {
            let value =
                Zeroizing::new([conversation.0.as_slice(), &due.to_be_bytes(), app].concat());
            batch.put(
                RESET_NOTICES,
                conversation.0,
                Some(conversation.0),
                &value,
                rng,
            )?;
        }
        batch.commit()?;
        self.keep_device_set(&device, &roster, rng)?;
        // DEV-263: the group re-key of Part 11 §11.12 in each group.
        let groups = self.group_conversations()?.len();
        self.rekey_groups(now_ms, rng)?;
        self.events.push_back(Event::Conversations);
        Ok(ResetSummary {
            contacts: u32::try_from(notices.len()).unwrap_or(u32::MAX),
            groups: u32::try_from(groups).unwrap_or(u32::MAX),
        })
    }

    /// Whether the record `app` of a conversation waits for the send path.
    fn is_waiting_record(&self, conversation: ConversationId, app: &[u8]) -> Result<bool, Error> {
        let Ok(parsed) = AppMessage::parse(app, umbra_wire::app::Channel::Pairwise) else {
            return Ok(false);
        };
        let open = self.open_ref()?;
        let reference = msg_ref(&open.device_set_key, &parsed.msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        Ok(open.store.get(OUTBOX, &row)?.is_some())
    }

    /// The key-change notices that no relay took yet, for the view of the
    /// identity: the reset is complete for a contact when its notice left.
    pub fn notices_waiting(&self) -> Result<usize, Error> {
        Ok(self.open_ref()?.store.list(RESET_NOTICES, None)?.len())
    }

    /// Hands each notice whose delay passed at `now` to the send path. The
    /// record goes on the pairwise session that exists (`IDN-055`), and no
    /// view shows it. The row stays until a relay took the notice, thus a
    /// notice that reached no relay goes again. The result counts the
    /// notices that went.
    pub fn send_due_notices<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<usize, Error> {
        let mut due = Vec::new();
        for (row, value) in self.open_ref()?.store.list(RESET_NOTICES, None)? {
            let value = Zeroizing::new(value);
            let at: [u8; 8] = value
                .get(16..24)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?;
            let app = value.get(24..).ok_or(Error::Integrity)?;
            // A notice that the send path lost, as a row that left the
            // store under it, is due again.
            let is_lost = u64::from_be_bytes(at) == IN_FLIGHT
                && !self.is_waiting_record(ConversationId(row), app)?;
            if u64::from_be_bytes(at) <= now || is_lost {
                due.push((ConversationId(row), app.to_vec()));
            }
        }
        for (conversation, app) in &due {
            // A notice that does not read is one drop, and it stops no
            // other notice.
            let Ok(parsed) = AppMessage::parse(app, umbra_wire::app::Channel::Pairwise) else {
                let open = self.open_mut()?;
                let mut batch = open.store.begin();
                batch.delete(RESET_NOTICES, conversation.0);
                batch.commit()?;
                continue;
            };
            let open = self.open_mut()?;
            let reference = msg_ref(&open.device_set_key, &parsed.msg_id);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            let stored = stored_message(
                OUTGOING,
                Delivery::Queued,
                *conversation,
                open.stamp.next(now.saturating_mul(1_000)),
                app,
            );
            let mut batch = open.store.begin();
            batch.put(TableId::MESSAGE, row, Some(conversation.0), &stored, rng)?;
            batch.put(OUTBOX, row, None, &outbox_row(), rng)?;
            let held =
                Zeroizing::new([conversation.0.as_slice(), &IN_FLIGHT.to_be_bytes(), app].concat());
            batch.put(
                RESET_NOTICES,
                conversation.0,
                Some(conversation.0),
                &held,
                rng,
            )?;
            batch.commit()?;
            self.outgoing.push_back(Outgoing {
                message: MsgRef(row),
                conversation: *conversation,
                app: app.clone(),
            });
        }
        Ok(due.len())
    }
}
