//! The bridge between the client of the device and the network runtime. It
//! gives each outgoing record of the client to the runtime, and it commits
//! each received record to the store before the runtime acknowledges it to
//! the relay (`WIR-115`). It holds no socket and no task, thus a test drives
//! it with plain values.

use std::collections::BTreeMap;

use tokio::sync::mpsc::UnboundedSender;
use umbra_core::{
    session::node::ContactId,
    store::{engine::Backend, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;

use crate::{
    client::Client,
    runtime::{Command, Update},
    ConversationId, Delivery, Error, MsgRef,
};

/// What the network tells the platform. The event stream of the client
/// carries handles, and this one carries the state of the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    /// The circuit is ready.
    Online,
    /// The connection or the circuit ended. Each contact of this session is
    /// gone, because the ratchet state sits in RAM only.
    Offline,
    /// The bundle of an invitation, which the user gives out of band.
    Invitation(Vec<u8>),
    /// A contact is ready, and its conversation takes drafts.
    Contact(ConversationId),
}

/// The state of the bridge for one run of the network runtime.
pub struct Bridge {
    commands: UnboundedSender<Command>,
    contacts: BTreeMap<ConversationId, ContactId>,
    sent: BTreeMap<u64, MsgRef>,
    next_tag: u64,
}

impl Bridge {
    /// A bridge over the command channel of one runtime.
    pub fn new(commands: UnboundedSender<Command>) -> Self {
        Bridge {
            commands,
            contacts: BTreeMap::new(),
            sent: BTreeMap::new(),
            next_tag: 0,
        }
    }

    fn command(&self, command: Command) -> Result<(), Error> {
        self.commands.send(command).map_err(|_| Error::Offline)
    }

    /// Asks for one invitation. A [`NetEvent::Invitation`] follows.
    pub fn invite(&self) -> Result<(), Error> {
        self.command(Command::Invite)
    }

    /// Accepts the bundle of an inviter. A [`NetEvent::Contact`] follows.
    pub fn accept(&self, bundle: Vec<u8>) -> Result<(), Error> {
        self.command(Command::Accept(bundle))
    }

    /// Gives each record that waits in the client to the runtime. A record
    /// for a conversation with no contact in this session fails.
    pub fn flush<B: Backend, E: SecureElement, R: CryptoRng + ?Sized>(
        &mut self,
        client: &mut Client<B, E>,
        rng: &mut R,
    ) -> Result<(), Error> {
        while let Some(outgoing) = client.take_outgoing() {
            let tag = self.next_tag;
            self.next_tag = self.next_tag.wrapping_add(1);
            let taken = self
                .contacts
                .get(&outgoing.conversation)
                .is_some_and(|contact| {
                    let send = Command::Send {
                        contact: *contact,
                        app: outgoing.app.clone(),
                        tag,
                    };
                    self.commands.send(send).is_ok()
                });
            if taken {
                self.sent.insert(tag, outgoing.message);
            } else {
                client.set_delivery(&outgoing.message, Delivery::Failed, rng)?;
            }
        }
        Ok(())
    }

    /// Applies one update of the runtime to the client.
    pub fn on_update<B: Backend, E: SecureElement, R: CryptoRng + ?Sized>(
        &mut self,
        client: &mut Client<B, E>,
        update: Update,
        rng: &mut R,
    ) -> Result<Option<NetEvent>, Error> {
        Ok(match update {
            Update::Online => Some(NetEvent::Online),
            Update::Offline => Some(NetEvent::Offline),
            Update::Invitation(bundle) => Some(NetEvent::Invitation(bundle)),
            Update::Contact { contact, .. } => {
                let conversation = client.conversation_for(&contact.0)?;
                self.contacts.insert(conversation, contact);
                Some(NetEvent::Contact(conversation))
            }
            Update::Message { contact, app } => {
                let conversation = client.conversation_for(&contact.0)?;
                client.receive(conversation, &app, rng)?;
                // The store holds the record, thus the relay can drop it.
                self.command(Command::Committed(contact))?;
                None
            }
            Update::Sent(tag) => {
                if let Some(message) = self.sent.remove(&tag) {
                    client.set_delivery(&message, Delivery::Accepted, rng)?;
                }
                None
            }
            Update::Failed(tag) => {
                if let Some(message) = self.sent.remove(&tag) {
                    client.set_delivery(&message, Delivery::Failed, rng)?;
                }
                None
            }
        })
    }
}
