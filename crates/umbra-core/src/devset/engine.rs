//! The sync engine of one device (Part 7 §7.5): it ties the machines of
//! [`super::sync`] into the path of a record through the device set. A
//! device publishes each record to each peer and retains it until the peer
//! acknowledges it. It takes the records of each peer, acknowledges the
//! point below which it needs no resend, and applies mutable state by the
//! last writer.
//!
//! The sending device is the durable log of the set (`DEV-013`). The
//! engine holds the counters and the references, and the local database
//! holds the bodies under their `msg_ref`.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_wire::app::{
    devset::{ControlType, DeviceSetBody},
    rich::RichRecord,
    AppKind, AppMessage, Channel, Class,
};

use umbra_crypto::stored;

use super::{
    sync::{
        bounded, AckBatch, CausalContext, InteractiveBucket, MutableItem, Origin, RetainedLog,
        SyncedRecord, Watermarks,
    },
    DeviceId, MAX_DEVICES,
};
use crate::Error;

/// What the engine holds for one peer device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Peer {
    log: RetainedLog,
    acks: AckBatch,
    bucket: InteractiveBucket,
    /// Each record of the peer at or below this counter needs no resend
    /// (`DEV-055`).
    contiguous: u64,
    /// The counters above `contiguous` that the device holds.
    ahead: BTreeSet<u64>,
    /// The counter below which the paced resend already went out.
    resent_to: u64,
    /// A resend is in progress (`DEV-076`).
    resending: bool,
}

/// A record that the engine published: the body of an `AppMessage` of kind
/// `0x20`, which goes to each peer on its sync channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The causal counter of the record.
    pub counter: u64,
    /// The body bytes.
    pub body: Vec<u8>,
}

/// What the engine made of an inbound sync body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// A conversation record to apply, with the remaining period of its
    /// timer.
    Record {
        /// The conversation and the author.
        origin: Origin,
        /// The causal counter of the source, which the retention of
        /// §7.5.2 names in a watermark (`DEV-015`).
        counter: u64,
        /// The `AppMessage` bytes of the peer.
        inner: Vec<u8>,
        /// The `expires_in` of the context, or zero.
        expires_in: u32,
    },
    /// An item of mutable state that wins, to apply.
    Mutable {
        /// The row of the mutable-state table.
        item: u8,
        /// The scope of the row.
        key: Vec<u8>,
        /// The new value.
        value: Vec<u8>,
        /// The Lamport counter of the write, which a relay keeps.
        lamport: u64,
        /// The device that wrote the value, which a relay keeps.
        writer: DeviceId,
    },
    /// An item of mutable state that loses to the value held (`DEV-270`).
    Superseded,
    /// A record that the device holds already (`DEV-025`).
    Duplicate,
    /// A record at or below the watermark of its source (`DEV-037`). The
    /// device acknowledges it, thus the peer stops the resend.
    Declined,
    /// A sync acknowledgment of the peer. A resend starts (`DEV-071`).
    Acknowledged,
    /// A control record that another module applies: a roster epoch, an
    /// ownership claim, a catch-up descriptor, or a seed update.
    Control {
        /// The type.
        control_type: ControlType,
        /// The payload.
        payload: Vec<u8>,
    },
}

/// The winners of mutable items that an engine holds at most (`DEV-310`).
const MUTABLE_HELD: usize = 65_536;
/// The winners above `MUTABLE_HELD` before a trim.
const MUTABLE_SLACK: usize = 4_096;

/// The sync state of one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncEngine {
    own: DeviceId,
    lamport: u64,
    counter: u64,
    peers: BTreeMap<DeviceId, Peer>,
    watermarks: Watermarks,
    /// The Lamport counter and the writer of each mutable item held.
    mutable: BTreeMap<(u8, Vec<u8>), (u64, DeviceId)>,
    /// The delivery items of `mutable`, thus an insert under the bound of
    /// `DEV-310` reads no other item.
    deliveries: usize,
}

fn class_of(inner: &[u8]) -> Result<Class, Error> {
    let message = AppMessage::parse(inner, Channel::Pairwise)?;
    // DEV-174: a wrapper takes the class of its inner kind.
    Ok(match message.kind.class() {
        Class::Inner => RichRecord::parse(message.body, Channel::Group)?
            .inner_kind
            .class(),
        class => class,
    })
}

impl SyncEngine {
    /// The engine of `own` with the other devices of the roster.
    pub fn new(own: DeviceId, peers: &[DeviceId]) -> Result<Self, Error> {
        if peers.len() >= MAX_DEVICES || peers.contains(&own) {
            return Err(Error::Malformed);
        }
        Ok(SyncEngine {
            own,
            lamport: 0,
            counter: 0,
            peers: peers.iter().map(|peer| (*peer, Peer::default())).collect(),
            watermarks: Watermarks::default(),
            mutable: BTreeMap::new(),
            deliveries: 0,
        })
    }

    /// The causal counter of this device.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The watermarks, which a backup and an archive carry (`DEV-019`).
    pub fn watermarks(&self) -> &Watermarks {
        &self.watermarks
    }

    /// The watermarks, for a prune under §7.5.2 and for a `live` link.
    pub fn watermarks_mut(&mut self) -> &mut Watermarks {
        &mut self.watermarks
    }

    /// A device joined the roster (`DEV-009`).
    pub fn add_peer(&mut self, peer: DeviceId) -> Result<(), Error> {
        // A peer that the engine holds already counts once.
        if self.peers.contains_key(&peer) {
            return Ok(());
        }
        if self.peers.len().saturating_add(1) >= MAX_DEVICES || peer == self.own {
            return Err(Error::NoPath);
        }
        self.peers.entry(peer).or_default();
        Ok(())
    }

    /// Each record of `peer` at or below `counter` came by another path, as
    /// the snapshot of a link (`DEV-311`), thus the peer resends none of
    /// them and the next one names no hole.
    pub fn start_peer_at(&mut self, peer: &DeviceId, counter: u64) {
        if let Some(held) = self.peers.get_mut(peer) {
            if counter > held.contiguous {
                held.contiguous = counter;
                held.ahead.retain(|ahead| *ahead > counter);
                while held.ahead.remove(&held.contiguous.saturating_add(1)) {
                    held.contiguous = held.contiguous.saturating_add(1);
                }
            }
        }
    }

    /// A device left the roster. Its retained records leave with it.
    pub fn remove_peer(&mut self, peer: &DeviceId) {
        self.peers.remove(peer);
    }

    fn context(&mut self, expires_in: u32) -> CausalContext {
        self.lamport = self.lamport.saturating_add(1);
        let lamport = self.lamport;
        self.context_at(lamport, expires_in)
    }

    /// A context of the next counter under `lamport`, which a relay keeps
    /// from the item that it carries (`DEV-308`).
    fn context_at(&mut self, lamport: u64, expires_in: u32) -> CausalContext {
        self.counter = self.counter.saturating_add(1);
        let mut vector: Vec<(DeviceId, u64)> = self
            .peers
            .iter()
            .map(|(device, peer)| (*device, peer.contiguous))
            .collect();
        vector.push((self.own, self.counter));
        vector.sort_unstable();
        CausalContext {
            lamport,
            vector,
            expires_in,
        }
    }

    fn retain(&mut self, reference: [u8; 16], now: u64) {
        let counter = self.counter;
        for peer in self.peers.values_mut() {
            peer.log.sent(reference, counter, now);
        }
    }

    /// Publishes a conversation record to the device set. `inner` is the
    /// `AppMessage`, and `msg_ref` is its stored reference. A peer signal
    /// and an ephemeral record do not travel on a sync channel (`DEV-023`,
    /// `DEV-042`).
    pub fn publish(
        &mut self,
        inner: &[u8],
        origin: Origin,
        msg_ref: [u8; 16],
        expires_in: u32,
        now: u64,
    ) -> Result<Published, Error> {
        if matches!(class_of(inner)?, Class::PeerSignal | Class::Ephemeral) {
            return Err(Error::Malformed);
        }
        let record = SyncedRecord {
            context: self.context(expires_in),
            origin,
            inner,
        };
        let mut body = alloc::vec![0u8; inner.len().saturating_add(256)];
        let used = record.encode(&mut body)?;
        body.truncate(used);
        self.retain(msg_ref, now);
        Ok(Published {
            counter: self.counter,
            body,
        })
    }

    /// Publishes one item of mutable state. `slot_ref` names the item in
    /// the local database, thus a resend carries the value that the device
    /// holds then.
    pub fn publish_mutable(
        &mut self,
        item: u8,
        key: &[u8],
        value: &[u8],
        slot_ref: [u8; 16],
        now: u64,
    ) -> Result<Published, Error> {
        let mutable = MutableItem {
            context: self.context(0),
            writer: self.own,
            item,
            key,
            value,
        };
        let mut body = alloc::vec![0u8; key.len().saturating_add(value.len()).saturating_add(256)];
        let used = mutable.encode(&mut body)?;
        body.truncate(used);
        self.put_mutable((item, key.to_vec()), (self.lamport, self.own));
        self.retain(slot_ref, now);
        Ok(Published {
            counter: self.counter,
            body,
        })
    }

    /// Publishes again an item of mutable state that a peer published, at
    /// the Lamport counter and under the writer of that write (`DEV-308`).
    /// The item takes a counter of this device, and it keeps the time and
    /// the writer of its write, thus it supersedes no later write of any
    /// device, and a tie breaks as at the writer.
    #[allow(clippy::too_many_arguments)]
    pub fn relay_mutable(
        &mut self,
        item: u8,
        key: &[u8],
        value: &[u8],
        lamport: u64,
        writer: DeviceId,
        slot_ref: [u8; 16],
        now: u64,
    ) -> Result<Published, Error> {
        let mutable = MutableItem {
            context: self.context_at(lamport, 0),
            writer,
            item,
            key,
            value,
        };
        let mut body = alloc::vec![0u8; key.len().saturating_add(value.len()).saturating_add(256)];
        let used = mutable.encode(&mut body)?;
        body.truncate(used);
        self.retain(slot_ref, now);
        Ok(Published {
            counter: self.counter,
            body,
        })
    }

    /// Whether an interactive record to `peer` goes at once. With an empty
    /// bucket the record waits for the pacing clock, and the interface
    /// says so (`DEV-195`, `DEV-241`).
    pub fn interactive(&mut self, peer: &DeviceId, now: u64) -> bool {
        self.peers
            .get_mut(peer)
            .is_some_and(|state| state.bucket.take(now))
    }

    /// Takes the counter of a record of `source` into the acknowledgment
    /// state. Returns false for a counter that the device holds.
    fn take_counter(&mut self, source: &DeviceId, counter: u64, now: u64) -> Result<bool, Error> {
        let peer = self.peers.get_mut(source).ok_or(Error::Unverified)?;
        if counter <= peer.contiguous || !peer.ahead.insert(counter) {
            return Ok(false);
        }
        while peer.ahead.remove(&peer.contiguous.saturating_add(1)) {
            peer.contiguous = peer.contiguous.saturating_add(1);
        }
        peer.acks.took(peer.contiguous, now);
        Ok(true)
    }

    /// Takes the body of an `AppMessage` of kind `0x20` that arrived on
    /// the sync channel of `source`. The caller rejects that kind on each
    /// other channel (`DEV-052`).
    pub fn receive(&mut self, source: &DeviceId, body: &[u8], now: u64) -> Result<Taken, Error> {
        // DEV-257: a device that is no peer, as one that the roster
        // revoked, gives nothing to this device.
        if !self.peers.contains_key(source) {
            return Err(Error::Unverified);
        }
        match DeviceSetBody::parse(body)? {
            DeviceSetBody::Record(_) => {
                let record = SyncedRecord::parse(body)?;
                let counter = record.context.counter_of(source).ok_or(Error::Malformed)?;
                if matches!(
                    class_of(record.inner)?,
                    Class::PeerSignal | Class::Ephemeral
                ) {
                    return Err(Error::Malformed);
                }
                self.lamport = self.lamport.max(record.context.lamport);
                // A record below the watermark is one that the device
                // pruned or declined. It needs no resend.
                let declined = !self.watermarks.accepts(source, counter);
                if !self.take_counter(source, counter, now)? {
                    return Ok(Taken::Duplicate);
                }
                if declined {
                    return Ok(Taken::Declined);
                }
                Ok(Taken::Record {
                    origin: record.origin,
                    counter,
                    inner: record.inner.to_vec(),
                    expires_in: record.context.expires_in,
                })
            }
            DeviceSetBody::MutableState(_) => {
                let item = MutableItem::parse(body)?;
                let counter = item.context.counter_of(source).ok_or(Error::Malformed)?;
                self.lamport = self.lamport.max(item.context.lamport);
                if !self.take_counter(source, counter, now)? {
                    return Ok(Taken::Duplicate);
                }
                let slot = (item.item, item.key.to_vec());
                let offered = (item.context.lamport, item.writer);
                // DEV-270: the higher Lamport counter, then the lower writer.
                // A relay keeps both (DEV-308), thus one write holds one
                // pair, and each device ends on one value.
                let wins = self.mutable.get(&slot).is_none_or(|(lamport, writer)| {
                    offered.0 > *lamport || (offered.0 == *lamport && offered.1 < *writer)
                });
                if !wins {
                    return Ok(Taken::Superseded);
                }
                self.put_mutable(slot, offered);
                Ok(Taken::Mutable {
                    item: item.item,
                    key: item.key.to_vec(),
                    value: item.value.to_vec(),
                    lamport: item.context.lamport,
                    writer: item.writer,
                })
            }
            control @ DeviceSetBody::Control { .. } => {
                if let Some(counter) = control.sync_ack() {
                    let peer = self.peers.get_mut(source).ok_or(Error::Unverified)?;
                    // A peer cannot acknowledge a record that no one sent.
                    if counter > self.counter {
                        return Err(Error::Unverified);
                    }
                    peer.log.acknowledged(counter);
                    peer.resent_to = peer.log.acked();
                    peer.resending = peer.log.to_resend().next().is_some();
                    return Ok(Taken::Acknowledged);
                }
                let DeviceSetBody::Control {
                    control_type,
                    payload,
                } = control
                else {
                    return Err(Error::Malformed);
                };
                Ok(Taken::Control {
                    control_type,
                    payload: payload.to_vec(),
                })
            }
        }
    }

    /// The sync acknowledgments that are due at `now`, as the body of an
    /// `AppMessage` of kind `0x20` for each peer. The engine does not
    /// retain them and does not count them (`DEV-062`, `DEV-063`).
    pub fn acknowledgments(&mut self, now: u64) -> Result<Vec<(DeviceId, Vec<u8>)>, Error> {
        let mut out = Vec::new();
        for (device, peer) in &mut self.peers {
            let Some(counter) = peer.acks.due(now) else {
                continue;
            };
            let payload = counter.to_be_bytes();
            let body = DeviceSetBody::Control {
                control_type: ControlType::SyncAck,
                payload: &payload,
            };
            let mut bytes = [0u8; 11];
            let used = body.encode(&mut bytes)?;
            out.push((*device, bytes.get(..used).ok_or(Error::Malformed)?.to_vec()));
            peer.acks.sent();
        }
        Ok(out)
    }

    /// The sync channel of `peer` has a new queue, thus each retained
    /// record goes again (`DEV-072`).
    pub fn new_queue(&mut self, peer: &DeviceId) {
        if let Some(state) = self.peers.get_mut(peer) {
            state.resent_to = state.log.acked();
            state.resending = state.log.to_resend().next().is_some();
        }
    }

    /// The reference and the counter of the next record to resend to
    /// `peer`. The caller sends one at each send opportunity of the
    /// channel, and never a burst (`DEV-073`, `DEV-074`).
    pub fn next_resend(&mut self, peer: &DeviceId) -> Option<([u8; 16], u64)> {
        let state = self.peers.get_mut(peer)?;
        if !state.resending {
            return None;
        }
        let floor = state.resent_to;
        let next = state
            .log
            .to_resend()
            .find(|retained| retained.counter > floor)
            .map(|retained| (retained.msg_ref, retained.counter));
        match next {
            Some((_, counter)) => state.resent_to = counter,
            None => state.resending = false,
        }
        next
    }

    /// Whether a resend is in progress, thus the interface shows that the
    /// history still arrives (`DEV-076`).
    pub fn resending(&self) -> bool {
        self.peers.values().any(|peer| peer.resending)
    }

    /// Whether `peer` lags enough for a catch-up object (`DEV-236`).
    pub fn needs_catch_up(&self, peer: &DeviceId) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|state| state.log.needs_catch_up(self.counter))
    }

    /// The first counter range of `source` that the device does not hold
    /// while it holds a later one. After `SYNC_MAX_AGE` with no resend the
    /// interface shows that range as a history gap (`DEV-077`).
    pub fn missing(&self, source: &DeviceId) -> Option<(u64, u64)> {
        let state = self.peers.get(source)?;
        let first_held = *state.ahead.first()?;
        Some((
            state.contiguous.saturating_add(1),
            first_held.saturating_sub(1),
        ))
    }

    /// Drops each retained record past `SYNC_MAX_AGE` (`DEV-075`).
    pub fn expire(&mut self, now: u64) {
        for peer in self.peers.values_mut() {
            peer.log.expire(now);
        }
    }

    /// The counter at or below which `peer` acknowledged each record.
    pub fn acked_of(&self, peer: &DeviceId) -> Option<u64> {
        self.peers.get(peer).map(|state| state.log.acked())
    }

    /// Each counter that `peer` did not acknowledge and that the log
    /// retains, in order: the records of a catch-up object (`DEV-236`).
    pub fn retained_counters(&self, peer: &DeviceId) -> Vec<u64> {
        self.peers
            .get(peer)
            .map(|state| state.log.to_resend().map(|held| held.counter).collect())
            .unwrap_or_default()
    }

    /// The lowest counter that the log of a peer still retains, or the
    /// next counter when no log retains one: each stored body below it
    /// waits for no resend.
    pub fn retained_floor(&self) -> u64 {
        self.peers
            .values()
            .filter_map(|peer| peer.log.oldest())
            .min()
            .unwrap_or_else(|| self.counter.saturating_add(1))
    }

    /// Forgets the winners of the oldest delivery items once the engine
    /// holds more than `MUTABLE_HELD` of them (`DEV-310`): an item of each
    /// message would grow the engine with each message, and the stored
    /// engine past its bound would open no more. A delivery item converges
    /// forward, thus a late write that wins again changes no device; an
    /// item of another table keeps its winner. The drop takes
    /// `MUTABLE_SLACK` at once, thus its cost spreads over the inserts.
    fn trim_mutable(&mut self) {
        if self.deliveries <= MUTABLE_HELD.saturating_add(MUTABLE_SLACK) {
            return;
        }
        let is_delivery = |key: &(u8, Vec<u8>)| key.0 == super::sync::ITEM_DELIVERY;
        let mut lamports: Vec<u64> = self
            .mutable
            .iter()
            .filter(|(key, _)| is_delivery(key))
            .map(|(_, (lamport, _))| *lamport)
            .collect();
        lamports.sort_unstable();
        let excess = lamports.len().saturating_sub(MUTABLE_HELD);
        let floor = lamports.get(excess).copied().unwrap_or(0);
        self.mutable
            .retain(|key, (lamport, _)| !is_delivery(key) || *lamport >= floor);
        self.deliveries = self.mutable.keys().filter(|key| is_delivery(key)).count();
    }

    /// Holds the winner of one item, and trims the delivery items
    /// (`DEV-310`).
    fn put_mutable(&mut self, slot: (u8, Vec<u8>), winner: (u64, DeviceId)) {
        let is_delivery = slot.0 == super::sync::ITEM_DELIVERY;
        if self.mutable.insert(slot, winner).is_none() && is_delivery {
            self.deliveries = self.deliveries.saturating_add(1);
        }
        self.trim_mutable();
    }

    /// Whether the engine holds a write of the item `item` under `key`.
    pub fn holds_mutable(&self, item: u8, key: &[u8]) -> bool {
        self.mutable.contains_key(&(item, key.to_vec()))
    }

    /// The peers of the engine.
    pub fn peers(&self) -> impl Iterator<Item = &DeviceId> {
        self.peers.keys()
    }

    /// The counter at or below which each peer acknowledged each record,
    /// thus no record there waits for a resend.
    pub fn acked_by_all(&self) -> u64 {
        self.peers
            .values()
            .map(|peer| peer.log.acked())
            .min()
            .unwrap_or(self.counter)
    }

    /// The stored form of the engine, which the device keeps across runs
    /// (`DEV-013`). The token bucket starts full at a restore.
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        let mut w = stored::Writer::new();
        w.u8(0x01);
        w.bytes(&self.own);
        w.u64(self.lamport);
        w.u64(self.counter);
        w.u8(u8::try_from(self.peers.len()).map_err(|_| Error::Malformed)?);
        for (device, peer) in &self.peers {
            w.bytes(device);
            peer.log.export(&mut w);
            peer.acks.export(&mut w);
            w.u64(peer.contiguous);
            w.u32(u32::try_from(peer.ahead.len()).map_err(|_| Error::Malformed)?);
            for counter in &peer.ahead {
                w.u64(*counter);
            }
            w.u64(peer.resent_to);
            w.u8(u8::from(peer.resending));
        }
        self.watermarks.export(&mut w);
        w.u32(u32::try_from(self.mutable.len()).map_err(|_| Error::Malformed)?);
        for ((item, key), (lamport, writer)) in &self.mutable {
            w.u8(*item);
            w.var(key)?;
            w.u64(*lamport);
            w.bytes(writer);
        }
        Ok(w.finish().to_vec())
    }

    /// An engine from its stored form.
    pub fn restore(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = stored::Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let own: DeviceId = r.array()?;
        let lamport = r.u64()?;
        let counter = r.u64()?;
        let count = usize::from(r.u8()?);
        if count >= MAX_DEVICES {
            return Err(Error::Malformed);
        }
        let mut peers = BTreeMap::new();
        for _ in 0..count {
            let device: DeviceId = r.array()?;
            let log = RetainedLog::restore(&mut r)?;
            let acks = AckBatch::restore(&mut r)?;
            let contiguous = r.u64()?;
            let mut ahead = BTreeSet::new();
            for _ in 0..bounded(r.u32()?)? {
                ahead.insert(r.u64()?);
            }
            let resent_to = r.u64()?;
            let resending = r.u8()? == 1;
            peers.insert(
                device,
                Peer {
                    log,
                    acks,
                    bucket: InteractiveBucket::default(),
                    contiguous,
                    ahead,
                    resent_to,
                    resending,
                },
            );
        }
        let watermarks = Watermarks::restore(&mut r)?;
        let mut mutable = BTreeMap::new();
        for _ in 0..bounded(r.u32()?)? {
            let item = r.u8()?;
            let key = r.var()?.to_vec();
            let lamport = r.u64()?;
            let writer: DeviceId = r.array()?;
            mutable.insert((item, key), (lamport, writer));
        }
        r.end()?;
        let deliveries = mutable
            .keys()
            .filter(|(item, _)| *item == super::sync::ITEM_DELIVERY)
            .count();
        Ok(SyncEngine {
            own,
            lamport,
            counter,
            peers,
            watermarks,
            mutable,
            deliveries,
        })
    }
}

/// Rejects an application kind that a sync channel does not carry, for a
/// caller that holds the parsed message.
pub fn carried_on_sync(kind: AppKind) -> bool {
    !matches!(kind.class(), Class::PeerSignal | Class::Ephemeral)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::devset::{SYNC_ACK_BATCH, SYNC_ACK_MAX_DELAY, SYNC_CATCHUP_LAG, SYNC_MAX_AGE};

    const PHONE: DeviceId = [1; 16];
    const LAPTOP: DeviceId = [2; 16];
    const TABLET: DeviceId = [3; 16];
    const ORIGIN: Origin = Origin {
        scope: crate::devset::sync::SCOPE_PAIRWISE,
        subject: [7; 32],
        author: crate::devset::sync::AUTHOR_PEER,
    };

    fn message(kind: AppKind, tag: u8) -> Vec<u8> {
        let body: &[u8] = match kind {
            AppKind::Text => b"hello",
            _ => &[],
        };
        let app = AppMessage {
            kind,
            msg_id: [tag; 16],
            sent_at: 0,
            body,
        };
        let mut out = alloc::vec![0u8; app.len()];
        app.encode(&mut out).unwrap();
        out
    }

    fn pair() -> (SyncEngine, SyncEngine) {
        (
            SyncEngine::new(PHONE, &[LAPTOP, TABLET]).unwrap(),
            SyncEngine::new(LAPTOP, &[PHONE, TABLET]).unwrap(),
        )
    }

    #[test]
    fn a_second_link_starts_at_the_counter_of_its_snapshot() {
        // DEV-311: the phone published two records before the laptop
        // linked, and the snapshot holds them; the third names no hole.
        let (mut phone, _) = pair();
        for tag in 1..=2 {
            phone
                .publish(&message(AppKind::Text, tag), ORIGIN, [tag; 16], 0, 5)
                .unwrap();
        }
        let third = phone
            .publish(&message(AppKind::Text, 3), ORIGIN, [3; 16], 0, 6)
            .unwrap();
        let mut late = SyncEngine::new(LAPTOP, &[PHONE]).unwrap();
        late.start_peer_at(&PHONE, 2);
        late.receive(&PHONE, &third.body, 7).unwrap();
        assert_eq!(late.missing(&PHONE), None);
        // With no start point, the two earlier records are a hole.
        let mut blind = SyncEngine::new(LAPTOP, &[PHONE]).unwrap();
        blind.receive(&PHONE, &third.body, 7).unwrap();
        assert_eq!(blind.missing(&PHONE), Some((1, 2)));
    }

    #[test]
    fn a_trim_forgets_the_oldest_delivery_items_alone() {
        // DEV-310: the delivery winners past the bound go, the oldest
        // first, and an item of another table keeps its winner.
        let (mut phone, _) = pair();
        let delivery = crate::devset::sync::ITEM_DELIVERY;
        phone.put_mutable((1, alloc::vec![0]), (0, PHONE));
        let count = MUTABLE_HELD + MUTABLE_SLACK + 1;
        for at in 0..count {
            let key = u32::try_from(at).unwrap().to_be_bytes().to_vec();
            phone.put_mutable((delivery, key), (u64::try_from(at).unwrap() + 1, PHONE));
        }
        assert!(phone.holds_mutable(1, &[0]));
        assert!(!phone.holds_mutable(delivery, &0u32.to_be_bytes()));
        let newest = u32::try_from(count - 1).unwrap().to_be_bytes();
        assert!(phone.holds_mutable(delivery, &newest));
        assert_eq!(phone.mutable.len(), MUTABLE_HELD + 1);
        assert_eq!(phone.deliveries, MUTABLE_HELD);
        let back = SyncEngine::restore(&phone.export().unwrap()).unwrap();
        assert_eq!(back, phone);
    }

    #[test]
    fn the_stored_form_holds_the_counters_the_log_and_the_items() {
        let (mut phone, mut laptop) = pair();
        let first = phone
            .publish(&message(AppKind::Text, 1), ORIGIN, [1; 16], 0, 5)
            .unwrap();
        phone
            .publish(&message(AppKind::Text, 2), ORIGIN, [2; 16], 0, 6)
            .unwrap();
        phone
            .publish_mutable(1, &[3; 32], &[1], [3; 16], 7)
            .unwrap();
        laptop.receive(&PHONE, &first.body, 8).unwrap();
        for engine in [&phone, &laptop] {
            let back = SyncEngine::restore(&engine.export().unwrap()).unwrap();
            assert_eq!(&back, engine);
        }
        // The laptop holds counter 1 after a restart, thus the record is a
        // duplicate there.
        let mut back = SyncEngine::restore(&laptop.export().unwrap()).unwrap();
        assert_eq!(
            back.receive(&PHONE, &first.body, 9).unwrap(),
            Taken::Duplicate
        );
        assert!(SyncEngine::restore(&[0x02]).is_err());
    }

    #[test]
    fn a_record_reaches_the_peer_one_time_and_the_acknowledgment_ends_the_resend() {
        let (mut phone, mut laptop) = pair();
        let text = message(AppKind::Text, 1);
        let published = phone.publish(&text, ORIGIN, [1; 16], 0, 100).unwrap();
        assert_eq!(published.counter, 1);
        assert_eq!(
            laptop.receive(&PHONE, &published.body, 110).unwrap(),
            Taken::Record {
                origin: ORIGIN,
                counter: 1,
                inner: text.clone(),
                expires_in: 0
            }
        );
        assert_eq!(
            laptop.receive(&PHONE, &published.body, 111).unwrap(),
            Taken::Duplicate
        );
        assert!(
            laptop.receive(&[9; 16], &published.body, 111).is_err(),
            "no such device"
        );

        // One record is no batch, thus the period gives the acknowledgment.
        assert!(laptop
            .acknowledgments(110 + SYNC_ACK_MAX_DELAY - 1)
            .unwrap()
            .is_empty());
        let acks = laptop.acknowledgments(110 + SYNC_ACK_MAX_DELAY).unwrap();
        assert_eq!(acks.len(), 1);
        assert_eq!((acks[0].0, acks[0].1.len()), (PHONE, 11));
        assert!(
            laptop.acknowledgments(u64::MAX).unwrap().is_empty(),
            "no new record, no ack"
        );

        phone.new_queue(&LAPTOP);
        assert_eq!(phone.next_resend(&LAPTOP), Some(([1; 16], 1)));
        assert_eq!(
            phone.receive(&LAPTOP, &acks[0].1, 200).unwrap(),
            Taken::Acknowledged
        );
        assert_eq!(phone.next_resend(&LAPTOP), None);
        // The tablet acknowledged nothing, thus its copy stays.
        phone.new_queue(&TABLET);
        assert!(phone.resending());
        assert_eq!(phone.next_resend(&TABLET), Some(([1; 16], 1)));
        assert_eq!(phone.next_resend(&TABLET), None);
        assert!(!phone.resending());
    }

    #[test]
    fn a_batch_of_records_gives_one_acknowledgment_at_the_contiguous_point() {
        let (mut phone, mut laptop) = pair();
        let mut bodies = Vec::new();
        for n in 0..SYNC_ACK_BATCH + 1 {
            let text = message(AppKind::Text, n as u8);
            bodies.push(
                phone
                    .publish(&text, ORIGIN, [n as u8; 16], 0, 100)
                    .unwrap()
                    .body,
            );
        }
        // The second record is late.
        for (position, body) in bodies.iter().enumerate() {
            if position != 1 {
                laptop.receive(&PHONE, body, 100).unwrap();
            }
        }
        assert_eq!(laptop.missing(&PHONE), Some((2, 2)));
        let acks = laptop.acknowledgments(100).unwrap();
        let body = DeviceSetBody::parse(&acks[0].1).unwrap();
        assert_eq!(body.sync_ack(), Some(1), "the point stays below the hole");

        phone.receive(&LAPTOP, &acks[0].1, 101).unwrap();
        assert_eq!(phone.next_resend(&LAPTOP), Some(([1; 16], 2)));
        laptop.receive(&PHONE, &bodies[1], 102).unwrap();
        assert_eq!(laptop.missing(&PHONE), None);
        let acks = laptop.acknowledgments(102 + SYNC_ACK_MAX_DELAY).unwrap();
        let body = DeviceSetBody::parse(&acks[0].1).unwrap();
        assert_eq!(body.sync_ack(), Some(u64::from(SYNC_ACK_BATCH) + 1));

        // An acknowledgment above the own counter names no record.
        let forged = DeviceSetBody::Control {
            control_type: ControlType::SyncAck,
            payload: &1_000u64.to_be_bytes(),
        };
        let mut bytes = [0u8; 11];
        forged.encode(&mut bytes).unwrap();
        assert!(phone.receive(&LAPTOP, &bytes, 103).is_err());
    }

    #[test]
    fn the_last_writer_wins_and_the_lower_device_breaks_a_tie() {
        let (mut phone, mut laptop) = pair();
        let from_phone = phone
            .publish_mutable(1, b"conversation", b"read to 5", [7; 16], 10)
            .unwrap();
        let from_laptop = laptop
            .publish_mutable(1, b"conversation", b"read to 9", [7; 16], 10)
            .unwrap();
        // The two writes hold one Lamport counter, thus the lower device wins.
        assert_eq!(
            laptop.receive(&PHONE, &from_phone.body, 11).unwrap(),
            Taken::Mutable {
                item: 1,
                key: b"conversation".to_vec(),
                value: b"read to 5".to_vec(),
                lamport: 1,
                writer: PHONE,
            }
        );
        assert_eq!(
            phone.receive(&LAPTOP, &from_laptop.body, 11).unwrap(),
            Taken::Superseded
        );

        // DEV-308: the tablet owns the channels, and its relay of the write
        // of the phone keeps the phone as its writer. The laptop took its own
        // write at the same counter, and the relay wins there as it won at
        // the tablet, and not by the device of the tablet.
        let (mut phone2, mut laptop2) = pair();
        let mut tablet = SyncEngine::new(TABLET, &[PHONE, LAPTOP]).unwrap();
        let a = phone2
            .publish_mutable(1, b"conversation", b"read to 5", [7; 16], 10)
            .unwrap();
        let b = laptop2
            .publish_mutable(1, b"conversation", b"read to 9", [7; 16], 10)
            .unwrap();
        let Taken::Mutable {
            lamport, writer, ..
        } = tablet.receive(&PHONE, &a.body, 11).unwrap()
        else {
            panic!("the first write applies");
        };
        assert_eq!(
            tablet.receive(&LAPTOP, &b.body, 11).unwrap(),
            Taken::Superseded
        );
        let relay = tablet
            .relay_mutable(
                1,
                b"conversation",
                b"read to 5",
                lamport,
                writer,
                [8; 16],
                12,
            )
            .unwrap();
        assert!(matches!(
            laptop2.receive(&TABLET, &relay.body, 13).unwrap(),
            Taken::Mutable { writer: PHONE, .. }
        ));
        assert_eq!(
            phone2.receive(&TABLET, &relay.body, 13).unwrap(),
            Taken::Superseded
        );

        // A later write of the laptop wins at each device.
        let later = laptop
            .publish_mutable(1, b"conversation", b"read to 12", [7; 16], 20)
            .unwrap();
        assert!(matches!(
            phone.receive(&LAPTOP, &later.body, 21).unwrap(),
            Taken::Mutable { .. }
        ));
    }

    #[test]
    fn a_watermark_declines_history_and_still_acknowledges_it() {
        let (mut phone, mut laptop) = pair();
        let old = phone
            .publish(&message(AppKind::Text, 1), ORIGIN, [1; 16], 0, 10)
            .unwrap();
        let new = phone
            .publish(&message(AppKind::Text, 2), ORIGIN, [2; 16], 0, 20)
            .unwrap();
        // The laptop linked with the live scope after the first record.
        laptop.watermarks_mut().set_live(&[(PHONE, 1)]);
        assert_eq!(
            laptop.receive(&PHONE, &old.body, 30).unwrap(),
            Taken::Declined
        );
        assert!(matches!(
            laptop.receive(&PHONE, &new.body, 31).unwrap(),
            Taken::Record { .. }
        ));
        let acks = laptop.acknowledgments(31 + SYNC_ACK_MAX_DELAY).unwrap();
        assert_eq!(
            DeviceSetBody::parse(&acks[0].1).unwrap().sync_ack(),
            Some(2)
        );
    }

    #[test]
    fn a_sync_channel_carries_no_peer_signal_and_no_ephemeral_record() {
        let (mut phone, _) = pair();
        assert!(phone
            .publish(&message(AppKind::ReadReceipt, 1), ORIGIN, [1; 16], 0, 0)
            .is_err());
        assert!(phone
            .publish(&message(AppKind::Typing, 1), ORIGIN, [1; 16], 0, 0)
            .is_err());
        assert_eq!(phone.counter(), 0, "a rejected record takes no counter");
        assert!(carried_on_sync(AppKind::Delete) && !carried_on_sync(AppKind::Typing));
    }

    #[test]
    fn a_lagging_peer_needs_a_catch_up_object_and_old_records_expire() {
        let (mut phone, _) = pair();
        for n in 0..=SYNC_CATCHUP_LAG {
            phone
                .publish(
                    &message(AppKind::Text, 1),
                    ORIGIN,
                    [(n % 251) as u8; 16],
                    0,
                    50,
                )
                .unwrap();
        }
        assert!(phone.needs_catch_up(&LAPTOP));
        assert!(phone.interactive(&LAPTOP, 60));
        let floor = phone.retained_floor();
        phone.expire(50 + SYNC_MAX_AGE);
        assert!(phone.retained_floor() > floor);
        phone.new_queue(&LAPTOP);
        assert_eq!(phone.next_resend(&LAPTOP), None);

        assert!(SyncEngine::new(PHONE, &[PHONE]).is_err());
        let mut full = SyncEngine::new(
            PHONE,
            &[
                [2; 16], [3; 16], [4; 16], [5; 16], [6; 16], [7; 16], [8; 16],
            ],
        )
        .unwrap();
        assert!(full.add_peer([9; 16]).is_err(), "MAX_DEVICES");
    }
}
