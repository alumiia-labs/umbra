//! The catch-up object of Part 7 §7.5.1. A peer whose acknowledgment lags
//! by more than `SYNC_CATCHUP_LAG` takes each retained record above it in
//! one object on the chunk path (`DEV-236`, `DEV-237`), whose descriptor
//! goes on the sync channel (`DEV-238`). The peer applies each record of
//! the object as if the sync channel carried it (`DEV-239`), and the paced
//! resend goes on for each record that it did not acknowledge (`DEV-240`).

use umbra_core::{
    devset::DeviceId,
    session::node::ContactId,
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    devset::{ControlType, DeviceSetBody},
    AppKind, AppMessage,
};
use zeroize::Zeroizing;

use super::{
    sync::{counter_key, SYNC_SENT},
    Client,
};
use crate::{ConversationId, Error};

/// The descriptor of each catch-up object that a peer sent, by the
/// conversation of its sync channel.
const CATCHUP_IN: TableId = TableId(0x4B);
/// The setting that names the acknowledged counter of a peer at its last
/// catch-up object, thus one lag makes one object.
const CATCHUP_SENT: &[u8] = b"catch-up/";

/// A catch-up object that goes on the chunk path.
pub struct CatchUp {
    /// The sync channel of the peer.
    pub channel: ConversationId,
    /// The records, each as `BE32(len) || body`.
    pub object: Zeroizing<Vec<u8>>,
}

fn sent_key(peer: &DeviceId) -> Vec<u8> {
    [CATCHUP_SENT, peer.as_slice()].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The catch-up object of the next peer that lags (`DEV-236`).
    pub fn take_catch_up<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<Option<CatchUp>, Error> {
        let Some(engine) = self.sync_engine()? else {
            return Ok(None);
        };
        let channels = self.peer_channels()?;
        let peers: Vec<DeviceId> = engine.peers().copied().collect();
        for peer in peers {
            let Some(channel) = channels.get(&peer).copied() else {
                continue;
            };
            if !engine.needs_catch_up(&peer) {
                continue;
            }
            let acked = engine.acked_of(&peer).unwrap_or(0);
            let done = self
                .setting(&sent_key(&peer))?
                .and_then(|held| held.try_into().ok())
                .map(u64::from_be_bytes);
            if done == Some(acked) {
                continue;
            }
            let mut object = Zeroizing::new(Vec::new());
            for counter in engine.retained_counters(&peer) {
                let store = &self.open_ref()?.store;
                let row = store.row_id(SYNC_SENT, &counter_key(counter));
                let Some(value) = store.get(SYNC_SENT, &row)? else {
                    continue;
                };
                let Some(body) = value.get(8..).map(<[u8]>::to_vec) else {
                    continue;
                };
                // A timed record carries the period that remains now.
                let Some(body) = self.restamped(body, now)? else {
                    continue;
                };
                let len = u32::try_from(body.len()).map_err(|_| Error::TooLong)?;
                object.extend_from_slice(&len.to_be_bytes());
                object.extend_from_slice(&body);
            }
            self.put_setting(&sent_key(&peer), &acked.to_be_bytes(), rng)?;
            if object.is_empty() {
                continue;
            }
            return Ok(Some(CatchUp { channel, object }));
        }
        Ok(None)
    }

    /// The chunk path holds the object, and its descriptor goes to the
    /// peer (`DEV-238`).
    pub fn catch_up_uploaded<R: CryptoRng + ?Sized>(
        &mut self,
        channel: ConversationId,
        descriptor: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let body = DeviceSetBody::Control {
            control_type: ControlType::CatchUpDescriptor,
            payload: descriptor,
        };
        let mut encoded = vec![0u8; descriptor.len().saturating_add(16)];
        let n = body.encode(&mut encoded)?;
        encoded.truncate(n);
        self.queue_sync(channel, &encoded, None, rng)
    }

    /// A peer sent the descriptor of a catch-up object.
    pub(super) fn keep_catch_up<R: CryptoRng + ?Sized>(
        &mut self,
        channel: ConversationId,
        descriptor: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(CATCHUP_IN, &channel.0);
        let mut batch = open.store.begin();
        batch.put(CATCHUP_IN, row, None, descriptor, rng)?;
        Ok(batch.commit()?)
    }

    /// Each catch-up object that this device fetches: the sync channel and
    /// the descriptor.
    pub fn catch_up_fetches(&self) -> Result<Vec<(ConversationId, Vec<u8>)>, Error> {
        let mut out = Vec::new();
        for channel in self.device_peers()? {
            let store = &self.open_ref()?.store;
            let row = store.row_id(CATCHUP_IN, &channel.0);
            if let Some(descriptor) = store.get(CATCHUP_IN, &row)? {
                out.push((channel, descriptor));
            }
        }
        Ok(out)
    }

    /// The fetched object: each record goes in as a record of the sync
    /// channel, in the order of the object (`DEV-239`).
    pub fn catch_up_fetched<R: CryptoRng + ?Sized>(
        &mut self,
        channel: ConversationId,
        object: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.catch_up_failed(channel)?;
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::CONTACT, &channel.0)?
                .ok_or(Error::NotFound)?,
        );
        let contact: [u8; 32] = plain
            .get(..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Integrity)?;
        let mut received = Vec::new();
        let mut rest = object;
        while !rest.is_empty() {
            let len: [u8; 4] = rest
                .get(..4)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Malformed)?;
            let end = usize::try_from(u32::from_be_bytes(len))
                .map_err(|_| Error::Malformed)?
                .saturating_add(4);
            let body = rest.get(4..end).ok_or(Error::Malformed)?;
            rest = rest.get(end..).ok_or(Error::Malformed)?;
            let mut msg_id = [0u8; 16];
            rng.fill_bytes(&mut msg_id);
            let record = AppMessage {
                kind: AppKind::DeviceSet,
                msg_id,
                sent_at: 0,
                body,
            };
            let mut app = vec![0u8; record.len()];
            record.encode(&mut app)?;
            received.push((ContactId(contact), app));
        }
        self.commit_network(&[], &received, now_ms, rng)
    }

    /// The object did not come: the paced resend brings each record.
    pub fn catch_up_failed(&mut self, channel: ConversationId) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(CATCHUP_IN, &channel.0);
        let mut batch = open.store.begin();
        batch.delete(CATCHUP_IN, row);
        Ok(batch.commit()?)
    }
}
