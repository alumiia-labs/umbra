//! The creation of a community (Part 12 §12.5.5): the exchange of the
//! second owner on a pairwise channel, the signed genesis roster and first
//! metadata, and their publication at each relay of that metadata.
//!
//! A row lives from the create or the offer until the community forms. Its
//! role seed and its report queue then pass to the community row, and the
//! signed genesis records stay in the row until each relay took them, thus
//! a resend carries the same bytes (`COM-201`).

use umbra_core::{
    attach::seal::relay_hint,
    community::{
        community_id,
        control::{ControlBody, ControlObject, Role, RosterEntry},
        exchange::{OwnerExchange, OwnerStep},
        identity::RoleIdentity,
        link::CommunityLink,
        meta::{Category, CommunityMeta, CommunityMetaBody, MetaDraft},
        ADMISSION_OPEN, COMMUNITY_MIN_RELAYS, COMMUNITY_RELAY_MAX, META_NAME_MAX,
    },
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::{rand_core::CryptoRng, secret::Secret, zeroize::Zeroizing};
use umbra_wire::{address::QueueAddress, app::AppKind};

use super::{
    communities::{CommunityRow, COMMUNITY},
    Client,
};
use crate::{ConversationId, Error, Event};

/// Each community in its creation, by `community_id`.
const COMMUNITY_FORMING: TableId = TableId(0x24);

const ROW_VERSION: u8 = 0x01;

/// The side of this device in the exchange.
const CREATOR: u8 = 0;
const SECOND: u8 = 1;

/// The report queue of the role is on its way (`COM-401`, `COM-404`).
const MAKING_QUEUE: u8 = 0;
/// The creator sent the offer, or the second owner holds one that waits
/// for the user.
const OFFERED: u8 = 1;
/// The second owner sent its accept, and it waits for the formed step.
const ACCEPTED: u8 = 2;
/// The creator holds an accept and publishes the genesis (`COM-403`).
const PUBLISHING: u8 = 3;

/// One community in its creation.
struct FormingRow {
    community_id: [u8; 32],
    side: u8,
    phase: u8,
    contact: ConversationId,
    role_seed: Secret<32>,
    fragment: [u8; 16],
    /// The `RecipientId` and the encoded `QueueAddress` of the report
    /// queue of the role.
    report_queue: Option<([u8; 32], Vec<u8>)>,
    name: String,
    /// The relays of the first metadata, which the creator chose.
    relays: Vec<[u8; 32]>,
    /// Two bits for each relay: its `PUBACK` of the roster, then of the
    /// metadata (`COM-407`).
    acked: u16,
    /// The encoded genesis roster and first metadata.
    roster: Vec<u8>,
    meta: Vec<u8>,
}

fn put_bytes16(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(
        &u16::try_from(bytes.len())
            .map_err(|_| Error::TooLong)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

impl FormingRow {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut out = Zeroizing::new(Vec::new());
        out.push(ROW_VERSION);
        out.extend_from_slice(&self.community_id);
        out.push(self.side);
        out.push(self.phase);
        out.extend_from_slice(&self.contact.0);
        out.extend_from_slice(self.role_seed.expose());
        out.extend_from_slice(&self.fragment);
        match &self.report_queue {
            Some((recipient_id, address)) => {
                out.push(1);
                out.extend_from_slice(recipient_id);
                put_bytes16(&mut out, address)?;
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 32]);
                put_bytes16(&mut out, &[])?;
            }
        }
        if self.name.len() > META_NAME_MAX {
            return Err(Error::TooLong);
        }
        out.push(u8::try_from(self.name.len()).map_err(|_| Error::TooLong)?);
        out.extend_from_slice(self.name.as_bytes());
        if self.relays.len() > COMMUNITY_RELAY_MAX {
            return Err(Error::Malformed);
        }
        out.push(u8::try_from(self.relays.len()).map_err(|_| Error::Malformed)?);
        for relay in &self.relays {
            out.extend_from_slice(relay);
        }
        out.extend_from_slice(&self.acked.to_be_bytes());
        put_bytes16(&mut out, &self.roster)?;
        put_bytes16(&mut out, &self.meta)?;
        Ok(out)
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut at = 0usize;
        let mut take = |len: usize| -> Result<&[u8], Error> {
            let part = bytes.get(at..at + len).ok_or(Error::Integrity)?;
            at += len;
            Ok(part)
        };
        let byte = |part: &[u8]| part.first().copied().ok_or(Error::Integrity);
        let array32 = |part: &[u8]| -> Result<[u8; 32], Error> {
            part.try_into().map_err(|_| Error::Integrity)
        };
        let len16 = |part: &[u8]| -> Result<usize, Error> {
            Ok(usize::from(u16::from_be_bytes(
                part.try_into().map_err(|_| Error::Integrity)?,
            )))
        };
        if byte(take(1)?)? != ROW_VERSION {
            return Err(Error::Integrity);
        }
        let community_id = array32(take(32)?)?;
        let side = byte(take(1)?)?;
        let phase = byte(take(1)?)?;
        let contact = ConversationId(take(16)?.try_into().map_err(|_| Error::Integrity)?);
        let role_seed = Secret::new(array32(take(32)?)?);
        let fragment: [u8; 16] = take(16)?.try_into().map_err(|_| Error::Integrity)?;
        let has_queue = byte(take(1)?)? == 1;
        let recipient_id = array32(take(32)?)?;
        let address_len = len16(take(2)?)?;
        let address = take(address_len)?.to_vec();
        let report_queue = has_queue.then_some((recipient_id, address));
        let name_len = usize::from(byte(take(1)?)?);
        let name = String::from_utf8(take(name_len)?.to_vec()).map_err(|_| Error::Integrity)?;
        let count = usize::from(byte(take(1)?)?);
        let mut relays = Vec::with_capacity(count);
        for _ in 0..count {
            relays.push(array32(take(32)?)?);
        }
        let acked = u16::from_be_bytes(take(2)?.try_into().map_err(|_| Error::Integrity)?);
        let roster_len = len16(take(2)?)?;
        let roster = take(roster_len)?.to_vec();
        let meta_len = len16(take(2)?)?;
        let meta = take(meta_len)?.to_vec();
        if at != bytes.len() {
            return Err(Error::Integrity);
        }
        Ok(FormingRow {
            community_id,
            side,
            phase,
            contact,
            role_seed,
            fragment,
            report_queue,
            name,
            relays,
            acked,
            roster,
            meta,
        })
    }

    fn all_acked(&self) -> bool {
        let bits = self.relays.len() * 2;
        bits > 0 && u32::from(self.acked).trailing_ones() as usize >= bits
    }
}

/// An offer of the co-ownership of a community that waits for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityOffer {
    /// The community.
    pub community_id: [u8; 32],
    /// The name of its first metadata.
    pub name: String,
    /// The pairwise conversation that carried it.
    pub from: ConversationId,
}

/// One community in its creation, as the platform lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormingInfo {
    /// The community.
    pub community_id: [u8; 32],
    /// The name of its first metadata.
    pub name: String,
    /// The contact of the exchange.
    pub contact: ConversationId,
    /// Whether this device made the community.
    pub is_creator: bool,
    /// 0: the report queue is on its way; 1: the offer waits for the
    /// other party; 2: the accept waits for the formed step; 3: the relays
    /// take the genesis.
    pub phase: u8,
    /// The count of the relays that took both genesis records.
    pub relays_done: u8,
}

/// One genesis record for one relay, which the caller sends with its
/// `Admission`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisSend {
    /// The community.
    pub community_id: [u8; 32],
    /// The relay.
    pub relay: [u8; 32],
    /// The metadata, or else the roster, which takes the admission of
    /// `COM-205`.
    pub is_meta: bool,
    /// The encoded record.
    pub record: Vec<u8>,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn forming_row(&self, community_id: &[u8; 32]) -> Result<Option<FormingRow>, Error> {
        let store = &self.open_ref()?.store;
        let row_id = store.row_id(COMMUNITY_FORMING, community_id);
        match store.get(COMMUNITY_FORMING, &row_id)? {
            Some(plain) => Ok(Some(FormingRow::parse(&Zeroizing::new(plain))?)),
            None => Ok(None),
        }
    }

    fn forming_rows(&self) -> Result<Vec<FormingRow>, Error> {
        let store = &self.open_ref()?.store;
        store
            .list(COMMUNITY_FORMING, None)?
            .into_iter()
            .map(|(_, plain)| FormingRow::parse(&Zeroizing::new(plain)))
            .collect()
    }

    fn put_forming<R: CryptoRng + ?Sized>(
        &mut self,
        row: Option<&FormingRow>,
        community_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = row.map(FormingRow::encode).transpose()?;
        let open = self.open_mut()?;
        let row_id = open.store.row_id(COMMUNITY_FORMING, community_id);
        let mut batch = open.store.begin();
        match value {
            Some(value) => batch.put(COMMUNITY_FORMING, row_id, None, &value, rng)?,
            None => batch.delete(COMMUNITY_FORMING, row_id),
        }
        Ok(batch.commit()?)
    }

    fn send_exchange<R: CryptoRng + ?Sized>(
        &mut self,
        contact: ConversationId,
        exchange: &OwnerExchange,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let body = exchange.encode()?;
        self.send_pairwise_app(contact, AppKind::CommunityOwner, &body, now_ms, rng)
    }

    /// Starts a community with the name of its first metadata, the relays
    /// of that metadata, and the contact that the user asks to own it too
    /// (`COM-401`). The caller makes the report queue of the role next,
    /// and gives it to [`Client::forming_queue_made`].
    pub fn create_community<R: CryptoRng + ?Sized>(
        &mut self,
        name: &str,
        contact: ConversationId,
        relays: Vec<[u8; 32]>,
        rng: &mut R,
    ) -> Result<[u8; 32], Error> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Malformed);
        }
        if name.len() > META_NAME_MAX {
            return Err(Error::TooLong);
        }
        if relays.len() < COMMUNITY_MIN_RELAYS || relays.len() > COMMUNITY_RELAY_MAX {
            return Err(Error::Offline);
        }
        // COM-402: the second owner is a contact of this device.
        self.contact_id_of(contact)?;
        // COM-005: the genesis role pseudonym comes from a seed of its own.
        let mut role_seed = Secret::new([0u8; 32]);
        rng.fill_bytes(role_seed.expose_mut());
        let role = RoleIdentity::from_seed(&role_seed);
        let community = community_id(ADMISSION_OPEN, role.public_key())?;
        // COM-242: the fragment of the link.
        let mut fragment = [0u8; 16];
        rng.fill_bytes(&mut fragment);
        let row = FormingRow {
            community_id: community,
            side: CREATOR,
            phase: MAKING_QUEUE,
            contact,
            role_seed,
            fragment,
            report_queue: None,
            name: name.into(),
            relays,
            acked: 0,
            roster: Vec::new(),
            meta: Vec::new(),
        };
        self.put_forming(Some(&row), &community, rng)?;
        Ok(community)
    }

    /// Each community in its creation, but an offer that waits for the
    /// user, which [`Client::community_offers`] gives.
    pub fn forming_communities(&self) -> Result<Vec<FormingInfo>, Error> {
        Ok(self
            .forming_rows()?
            .into_iter()
            .filter(|row| !(row.side == SECOND && row.phase == OFFERED))
            .map(|row| {
                let done = (0..row.relays.len())
                    .filter(|index| (row.acked >> (index * 2)) & 0b11 == 0b11)
                    .count();
                FormingInfo {
                    community_id: row.community_id,
                    name: row.name,
                    contact: row.contact,
                    is_creator: row.side == CREATOR,
                    phase: row.phase,
                    relays_done: u8::try_from(done).unwrap_or(u8::MAX),
                }
            })
            .collect())
    }

    /// Each community whose role waits for its report queue.
    pub fn forming_queues_due(&self) -> Result<Vec<[u8; 32]>, Error> {
        Ok(self
            .forming_rows()?
            .into_iter()
            .filter(|row| row.phase == MAKING_QUEUE)
            .map(|row| row.community_id)
            .collect())
    }

    /// The report queue of the role exists. The creator sends its offer
    /// (`COM-402`), and the second owner sends its accept (`COM-404`).
    pub fn forming_queue_made<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        recipient_id: [u8; 32],
        address: Vec<u8>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut row) = self.forming_row(community_id)? else {
            return Err(Error::NotFound);
        };
        if row.phase != MAKING_QUEUE {
            return Ok(());
        }
        let step = if row.side == CREATOR {
            row.phase = OFFERED;
            OwnerStep::Offer {
                name: row.name.clone(),
            }
        } else {
            let role = RoleIdentity::from_seed(&row.role_seed);
            let queue = QueueAddress::parse(&address)?;
            let entry = RosterEntry::new(Role::Owner, &role, &queue)?.to_bytes()?;
            row.phase = ACCEPTED;
            OwnerStep::Accept {
                entry: entry.to_vec(),
            }
        };
        row.report_queue = Some((recipient_id, address));
        let exchange = OwnerExchange {
            community_id: *community_id,
            step,
        };
        self.send_exchange(row.contact, &exchange, now_ms, rng)?;
        self.put_forming(Some(&row), community_id, rng)
    }

    /// Each offer of a co-ownership that waits for the user.
    pub fn community_offers(&self) -> Result<Vec<CommunityOffer>, Error> {
        Ok(self
            .forming_rows()?
            .into_iter()
            .filter(|row| row.side == SECOND && row.phase == OFFERED)
            .map(|row| CommunityOffer {
                community_id: row.community_id,
                name: row.name,
                from: row.contact,
            })
            .collect())
    }

    /// The user accepts an offer. The role seed comes from the device
    /// CSPRNG (`COM-404`), and the caller makes the report queue next.
    pub fn accept_community_offer<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut row = self
            .forming_row(community_id)?
            .filter(|row| row.side == SECOND && row.phase == OFFERED)
            .ok_or(Error::NotFound)?;
        rng.fill_bytes(row.role_seed.expose_mut());
        row.phase = MAKING_QUEUE;
        self.put_forming(Some(&row), community_id, rng)
    }

    /// The user declines an offer.
    pub fn decline_community_offer<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let row = self
            .forming_row(community_id)?
            .filter(|row| row.side == SECOND && row.phase == OFFERED)
            .ok_or(Error::NotFound)?;
        let exchange = OwnerExchange {
            community_id: *community_id,
            step: OwnerStep::Decline,
        };
        self.send_exchange(row.contact, &exchange, now_ms, rng)?;
        self.put_forming(None, community_id, rng)
    }

    /// Takes one step of an exchange from a contact. It gives the report
    /// queue of a creation that a decline ended, which the caller ends.
    pub(super) fn on_owner_exchange<R: CryptoRng + ?Sized>(
        &mut self,
        from: ConversationId,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Option<[u8; 32]>, Error> {
        // COM-409.
        let Ok(exchange) = OwnerExchange::parse(body) else {
            return Ok(None);
        };
        let community = exchange.community_id;
        let held = self.forming_row(&community)?;
        match exchange.step {
            OwnerStep::Offer { name } => {
                let store = &self.open_ref()?.store;
                let joined = store
                    .get(COMMUNITY, &store.row_id(COMMUNITY, &community))?
                    .is_some();
                if held.is_some() || joined {
                    return Ok(None);
                }
                let row = FormingRow {
                    community_id: community,
                    side: SECOND,
                    phase: OFFERED,
                    contact: from,
                    role_seed: Secret::new([0; 32]),
                    fragment: [0; 16],
                    report_queue: None,
                    name,
                    relays: Vec::new(),
                    acked: 0,
                    roster: Vec::new(),
                    meta: Vec::new(),
                };
                self.put_forming(Some(&row), &community, rng)?;
                self.events.push_back(Event::CommunityOffer { from });
                Ok(None)
            }
            OwnerStep::Accept { entry } => {
                // COM-406: an accept of a held offer, from its contact, one
                // time.
                let Some(mut row) = held.filter(|row| {
                    row.side == CREATOR && row.phase == OFFERED && row.contact == from
                }) else {
                    return Ok(None);
                };
                let peer = RosterEntry::from_bytes(&entry)?;
                let role = RoleIdentity::from_seed(&row.role_seed);
                if peer.role != Role::Owner || peer.pseudonym == role.pseudonym() {
                    return Ok(None);
                }
                let (_, address) = row.report_queue.clone().ok_or(Error::Integrity)?;
                let own = RosterEntry::new(Role::Owner, &role, &QueueAddress::parse(&address)?)?;
                // COM-385: the genesis names its actor in an owner entry.
                row.roster = ControlObject::sign(
                    &role,
                    community,
                    0,
                    [0; 32],
                    ControlBody::Roster {
                        entries: vec![own, peer],
                        cosigns: Vec::new(),
                    },
                    rng,
                )?
                .encode()?;
                let link = CommunityLink {
                    community_id: community,
                    hints: row.relays.iter().map(relay_hint).collect(),
                    fragment: row.fragment,
                };
                let body = CommunityMetaBody {
                    category: Category::None,
                    name: row.name.clone(),
                    text: String::new(),
                    rules: String::new(),
                    icon: Vec::new(),
                };
                let mut nonce = [0u8; 12];
                rng.fill_bytes(&mut nonce);
                row.meta = CommunityMeta::sign(
                    &role,
                    &link.meta_key(),
                    MetaDraft {
                        community_id: community,
                        meta_index: 0,
                        previous_meta: [0; 32],
                        relays: link.hints.clone(),
                        flags: 0,
                        body: &body,
                        nonce,
                    },
                    rng,
                )?
                .encode()?;
                row.phase = PUBLISHING;
                self.put_forming(Some(&row), &community, rng)?;
                let _ = now;
                Ok(None)
            }
            OwnerStep::Decline => {
                let Some(row) = held.filter(|row| {
                    row.side == CREATOR && row.phase == OFFERED && row.contact == from
                }) else {
                    return Ok(None);
                };
                self.put_forming(None, &community, rng)?;
                Ok(row.report_queue.map(|(recipient_id, _)| recipient_id))
            }
            OwnerStep::Formed { fragment, relays } => {
                // COM-408: a formed step of an accept that this device sent
                // to that contact.
                let Some(row) = held.filter(|row| {
                    row.side == SECOND && row.phase == ACCEPTED && row.contact == from
                }) else {
                    return Ok(None);
                };
                self.form(row, fragment, relays, now, rng)?;
                Ok(None)
            }
        }
    }

    /// The community of a row stands: its role passes to a community row,
    /// and the pulls start.
    fn form<R: CryptoRng + ?Sized>(
        &mut self,
        row: FormingRow,
        fragment: [u8; 16],
        relays: Vec<[u8; 32]>,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut author_seed = Secret::new([0u8; 32]);
        rng.fill_bytes(author_seed.expose_mut());
        let community = CommunityRow {
            community_id: row.community_id,
            fragment,
            joined_at: now,
            author_seed,
            role_seed: Some(Secret::new(*row.role_seed.expose())),
            relays,
            name: row.name.clone(),
        };
        self.put_community(&community, rng)?;
        self.put_forming(None, &row.community_id, rng)
    }

    /// Each genesis record that a relay has not taken yet. The roster goes
    /// first at each relay, because a relay takes no record of a community
    /// before it holds the genesis (`COM-206`).
    pub fn genesis_sends(&self) -> Result<Vec<GenesisSend>, Error> {
        let mut out = Vec::new();
        for row in self.forming_rows()? {
            if row.phase != PUBLISHING {
                continue;
            }
            for (index, relay) in row.relays.iter().enumerate() {
                let roster_bit = 1u16 << (index * 2);
                let meta_bit = 1u16 << (index * 2 + 1);
                let (is_meta, record) = if row.acked & roster_bit == 0 {
                    (false, &row.roster)
                } else if row.acked & meta_bit == 0 {
                    (true, &row.meta)
                } else {
                    continue;
                };
                out.push(GenesisSend {
                    community_id: row.community_id,
                    relay: *relay,
                    is_meta,
                    record: record.clone(),
                });
            }
        }
        Ok(out)
    }

    /// A relay took one genesis record. When each relay holds both, the
    /// creator names the formed community to the second owner
    /// (`COM-407`), and it holds the community. The result says whether
    /// the community formed.
    pub fn genesis_acked<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: &[u8; 32],
        relay: &[u8; 32],
        is_meta: bool,
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let Some(mut row) = self
            .forming_row(community_id)?
            .filter(|row| row.phase == PUBLISHING)
        else {
            return Ok(false);
        };
        let Some(index) = row.relays.iter().position(|held| held == relay) else {
            return Ok(false);
        };
        row.acked |= 1u16 << (index * 2 + usize::from(is_meta));
        if !row.all_acked() {
            self.put_forming(Some(&row), community_id, rng)?;
            return Ok(false);
        }
        let exchange = OwnerExchange {
            community_id: *community_id,
            step: OwnerStep::Formed {
                fragment: row.fragment,
                relays: row.relays.clone(),
            },
        };
        self.send_exchange(row.contact, &exchange, now.saturating_mul(1_000), rng)?;
        let (fragment, relays) = (row.fragment, row.relays.clone());
        self.form(row, fragment, relays, now, rng)?;
        Ok(true)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_forming_row_round_trips_and_counts_its_acks() {
        let mut row = FormingRow {
            community_id: [1; 32],
            side: CREATOR,
            phase: PUBLISHING,
            contact: ConversationId([2; 16]),
            role_seed: Secret::new([3; 32]),
            fragment: [4; 16],
            report_queue: Some(([5; 32], vec![6; 129])),
            name: "trail club".into(),
            relays: vec![[7; 32], [8; 32], [9; 32]],
            acked: 0b11_1111,
            roster: vec![10; 300],
            meta: vec![11; 200],
        };
        let back = FormingRow::parse(&row.encode().unwrap()).unwrap();
        assert_eq!(back.community_id, row.community_id);
        assert_eq!(back.contact, row.contact);
        assert_eq!(back.report_queue, row.report_queue);
        assert_eq!(back.name, row.name);
        assert_eq!(back.relays, row.relays);
        assert_eq!((&back.roster, &back.meta), (&row.roster, &row.meta));
        assert!(back.all_acked());
        row.acked = 0b01_1111;
        assert!(!row.all_acked());
    }
}
