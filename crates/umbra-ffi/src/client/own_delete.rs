//! The deletion for the devices of one user (Part 7 §7.5.7, `DEV-126`). A
//! "delete for me" removes the message on this device and asks each other
//! device of the set to remove it too, with a `Delete` record of scope
//! `0x01` on the sync channel (`WIR-084`). The other party keeps its copy.

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    edit::{DeleteBody, DeleteScope},
    AppKind, AppMessage, Channel,
};
use zeroize::Zeroizing;

use super::{conversation_of, msg_ref, sync::Synced, Client, MESSAGE_PREFIX};
use crate::{Error, Event, MsgRef};

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Asks each other device of the set to remove `message`. The caller
    /// removes it on this device after this call, since the record names
    /// the message by its raw `msg_id`.
    pub fn publish_own_deletion<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let conversation = conversation_of(&plain)?;
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let target = AppMessage::parse(app, Channel::Pairwise)
            .or_else(|_| AppMessage::parse(app, Channel::Group))?
            .msg_id;
        let body = DeleteBody {
            scope: DeleteScope::OwnDevices,
            targets: vec![target],
        };
        let mut encoded = vec![0u8; body.len()];
        body.encode(&mut encoded)?;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::Delete,
            msg_id,
            sent_at: now_ms,
            body: &encoded,
        };
        let mut out = vec![0u8; record.len()];
        record.encode(&mut out)?;
        self.publish_sync(conversation, &out, true, None, now_ms / 1_000, rng)
    }

    /// Takes each deletion for the devices of this user out of the records
    /// that another device of the set sent, and removes its targets here.
    /// The other records go on.
    pub(super) fn take_own_deletions(&mut self, synced: Vec<Synced>) -> Result<Vec<Synced>, Error> {
        let mut kept = Vec::with_capacity(synced.len());
        let mut gone = Vec::new();
        for record in synced {
            let targets = AppMessage::parse(&record.app, Channel::Pairwise)
                .ok()
                .filter(|parsed| parsed.kind == AppKind::Delete && record.from_user)
                .and_then(|parsed| DeleteBody::parse(parsed.body).ok())
                .filter(|body| body.scope == DeleteScope::OwnDevices)
                .map(|body| body.targets);
            let Some(targets) = targets else {
                kept.push(record);
                continue;
            };
            let open = self.open_ref()?;
            for target in targets {
                let reference = msg_ref(&open.device_set_key, &target);
                let natural = [record.conversation.0.as_slice(), &reference].concat();
                let row = open.store.row_id(TableId::MESSAGE, &natural);
                if open.store.get(TableId::MESSAGE, &row)?.is_some() {
                    gone.push((record.conversation, MsgRef(row)));
                }
            }
        }
        for (conversation, message) in gone {
            self.delete_for_me(&message)?;
            self.events.push_back(Event::Deleted {
                conversation,
                message,
            });
        }
        Ok(kept)
    }
}
