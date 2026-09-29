//! The contact share of Part 6 §6.6.7: an introduction in three records.
//! Alice asks Bob with a `request` that names Carol by the petname of
//! Alice, Bob answers Alice with a `grant` that carries a fresh one-time
//! invitation, and Alice gives that invitation to Carol in an `offer`. No
//! record carries an address of a third party (`WIR-192`, `WIR-193`), and
//! Bob and Carol each act before anything moves (`WIR-196`, `WIR-358`).
//!
//! The records go as ephemeral records: no row of a message holds them,
//! and they take no delivery state and no sync copy.

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    share::{ContactShare, ShareType},
    AppKind, AppMessage,
};
use zeroize::Zeroizing;

use super::{Client, Outgoing, EPHEMERAL};
use crate::{ConversationId, Error, Event};

/// One row for each introduction that waits: the kind, the conversation of
/// the other party of the record, the third conversation of a request of
/// this device, the two names, and the invitation of an offer.
pub(super) const INTROS: TableId = TableId(0x42);

/// A request of this device that waits for its grant.
const ASKED: u8 = 1;
/// A request of a contact that waits for the user (`WIR-196`).
const REQUEST_IN: u8 = 2;
/// An offer of a contact that waits for the user (`WIR-358`).
const OFFER_IN: u8 = 3;

/// The longest petname that a record carries, in bytes.
const NAME_MAX: usize = 255;

/// An introduction that waits for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Introduction {
    /// The row.
    pub id: [u8; 16],
    /// Whether it is an offer: a contact introduces this user to a third
    /// party. Else it is a request: a contact asks to introduce this user.
    pub is_offer: bool,
    /// The contact that sent it.
    pub from: ConversationId,
    /// The petname of the third party, as that contact uses it.
    pub name: String,
}

struct Row {
    kind: u8,
    peer: ConversationId,
    third: ConversationId,
    name: String,
    third_name: String,
    link: Zeroizing<Vec<u8>>,
}

fn encode_row(row: &Row) -> Result<Zeroizing<Vec<u8>>, Error> {
    let name = row.name.as_bytes();
    let third_name = row.third_name.as_bytes();
    let mut out = Zeroizing::new(Vec::new());
    out.push(row.kind);
    out.extend_from_slice(&row.peer.0);
    out.extend_from_slice(&row.third.0);
    out.push(u8::try_from(name.len()).map_err(|_| Error::TooLong)?);
    out.extend_from_slice(name);
    out.push(u8::try_from(third_name.len()).map_err(|_| Error::TooLong)?);
    out.extend_from_slice(third_name);
    out.extend_from_slice(&row.link);
    Ok(out)
}

fn read_row(value: &[u8]) -> Result<Row, Error> {
    let take16 = |at: usize| -> Result<ConversationId, Error> {
        Ok(ConversationId(
            value
                .get(at..at + 16)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?,
        ))
    };
    let kind = *value.first().ok_or(Error::Integrity)?;
    let peer = take16(1)?;
    let third = take16(17)?;
    let name_len = usize::from(*value.get(33).ok_or(Error::Integrity)?);
    let name = value.get(34..34 + name_len).ok_or(Error::Integrity)?;
    let at = 34 + name_len;
    let third_len = usize::from(*value.get(at).ok_or(Error::Integrity)?);
    let third_name = value
        .get(at + 1..at + 1 + third_len)
        .ok_or(Error::Integrity)?;
    let link = value.get(at + 1 + third_len..).ok_or(Error::Integrity)?;
    Ok(Row {
        kind,
        peer,
        third,
        name: String::from_utf8(name.to_vec()).map_err(|_| Error::Integrity)?,
        third_name: String::from_utf8(third_name.to_vec()).map_err(|_| Error::Integrity)?,
        link: Zeroizing::new(link.to_vec()),
    })
}

fn fit(name: &str) -> &str {
    let mut end = name.len().min(NAME_MAX);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name.get(..end).unwrap_or("")
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn send_share<R: CryptoRng + ?Sized>(
        &mut self,
        to: ConversationId,
        share: &ContactShare<'_>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut body = vec![0u8; 5 + share.name.len() + share.body.len()];
        let used = share.encode(&mut body)?;
        body.truncate(used);
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::ContactShare,
            msg_id,
            sent_at: now_ms,
            body: &body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        self.outgoing.push_back(Outgoing {
            message: EPHEMERAL,
            conversation: to,
            app,
        });
        Ok(())
    }

    fn put_intro<R: CryptoRng + ?Sized>(&mut self, row: &Row, rng: &mut R) -> Result<(), Error> {
        let value = encode_row(row)?;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(INTROS, id, Some(row.peer.0), &value, rng)?;
        Ok(batch.commit()?)
    }

    fn drop_intro(&mut self, id: &[u8; 16]) -> Result<(), Error> {
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.delete(INTROS, *id);
        Ok(batch.commit()?)
    }

    fn intro_row(&self, id: &[u8; 16]) -> Result<Row, Error> {
        let value = Zeroizing::new(
            self.open_ref()?
                .store
                .get(INTROS, id)?
                .ok_or(Error::NotFound)?,
        );
        read_row(&value)
    }

    /// Asks the contact of `to` to be introduced to the contact of `about`
    /// (`WIR-194`). The request names `about` by the petname of this user,
    /// and it carries no address. `to_name` is the petname of this user for
    /// the contact of `to`, which the offer to `about` carries later.
    pub fn request_introduction<R: CryptoRng + ?Sized>(
        &mut self,
        to: ConversationId,
        about: ConversationId,
        about_name: &str,
        to_name: &str,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if to == about || self.is_group(to)? || self.is_group(about)? {
            return Err(Error::Malformed);
        }
        let about_name = fit(about_name);
        let share = ContactShare {
            share_type: ShareType::Request,
            name: about_name,
            body: &[],
        };
        self.send_share(to, &share, now_ms, rng)?;
        self.put_intro(
            &Row {
                kind: ASKED,
                peer: to,
                third: about,
                name: about_name.to_owned(),
                third_name: fit(to_name).to_owned(),
                link: Zeroizing::new(Vec::new()),
            },
            rng,
        )
    }

    /// Takes a contact share of a contact.
    pub(super) fn take_intro<R: CryptoRng + ?Sized>(
        &mut self,
        from: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Ok(share) = ContactShare::parse(body) else {
            return Ok(());
        };
        match share.share_type {
            // WIR-196: a request waits for the user.
            ShareType::Request => {
                self.put_intro(
                    &Row {
                        kind: REQUEST_IN,
                        peer: from,
                        third: ConversationId([0; 16]),
                        name: share.name.to_owned(),
                        third_name: String::new(),
                        link: Zeroizing::new(Vec::new()),
                    },
                    rng,
                )?;
                self.events.push_back(Event::Introduction { from });
            }
            // WIR-195: a grant answers a request of this device, and its
            // invitation goes to the third party in an offer.
            ShareType::Grant => {
                let mut asked = None;
                for (id, value) in self.open_ref()?.store.list(INTROS, Some(&from.0))? {
                    let row = read_row(&Zeroizing::new(value))?;
                    if row.kind == ASKED && row.peer == from && row.name == share.name {
                        asked = Some((id, row));
                        break;
                    }
                }
                let Some((id, row)) = asked else {
                    return Ok(());
                };
                let offer = ContactShare {
                    share_type: ShareType::Offer,
                    name: &row.third_name,
                    body: share.body,
                };
                self.send_share(row.third, &offer, now_ms, rng)?;
                self.drop_intro(&id)?;
            }
            // WIR-358: an offer waits for the user.
            ShareType::Offer => {
                self.put_intro(
                    &Row {
                        kind: OFFER_IN,
                        peer: from,
                        third: ConversationId([0; 16]),
                        name: share.name.to_owned(),
                        third_name: String::new(),
                        link: Zeroizing::new(share.body.to_vec()),
                    },
                    rng,
                )?;
                self.events.push_back(Event::Introduction { from });
            }
        }
        Ok(())
    }

    /// Each request and each offer of a contact that waits for the user.
    pub fn introductions(&self) -> Result<Vec<Introduction>, Error> {
        let mut out = Vec::new();
        for (id, value) in self.open_ref()?.store.list(INTROS, None)? {
            let row = read_row(&Zeroizing::new(value))?;
            if row.kind == REQUEST_IN || row.kind == OFFER_IN {
                out.push(Introduction {
                    id,
                    is_offer: row.kind == OFFER_IN,
                    from: row.peer,
                    name: row.name,
                });
            }
        }
        Ok(out)
    }

    /// The user allowed a request: the grant carries `link`, a fresh
    /// one-time invitation of this device that no other grant carries
    /// (`WIR-199`, `WIR-200`).
    pub fn grant_introduction<R: CryptoRng + ?Sized>(
        &mut self,
        id: &[u8; 16],
        link: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let row = self.intro_row(id)?;
        if row.kind != REQUEST_IN || link.is_empty() {
            return Err(Error::Malformed);
        }
        let share = ContactShare {
            share_type: ShareType::Grant,
            name: &row.name,
            body: link,
        };
        self.send_share(row.peer, &share, now_ms, rng)?;
        self.drop_intro(id)
    }

    /// The user accepted an offer: the invitation that it carries, and the
    /// petname that the introducer uses for that party.
    pub fn take_offer(&mut self, id: &[u8; 16]) -> Result<(Zeroizing<Vec<u8>>, String), Error> {
        let row = self.intro_row(id)?;
        if row.kind != OFFER_IN {
            return Err(Error::Malformed);
        }
        self.drop_intro(id)?;
        Ok((row.link, row.name))
    }

    /// The user declined a request or an offer. No record answers it.
    pub fn decline_introduction(&mut self, id: &[u8; 16]) -> Result<(), Error> {
        let row = self.intro_row(id)?;
        if row.kind == ASKED {
            return Err(Error::Malformed);
        }
        self.drop_intro(id)
    }
}
