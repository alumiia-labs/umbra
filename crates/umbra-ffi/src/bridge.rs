//! The bridge between the client of the device and the network runtime. It
//! gives each outgoing record of the client to the runtime, and it turns
//! each update of the runtime into a delivery state or an event. The store
//! takes the received records through [`crate::runtime::Persist`], in one
//! batch with the ratchet state that opened them. The bridge holds no
//! socket and no task, thus a test drives it with plain values.

use std::collections::BTreeMap;

use tokio::sync::mpsc::UnboundedSender;
use umbra_core::{
    session::node::ContactId,
    store::{engine::Backend, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::{
    client::Client,
    runtime::{Command, Ended, Update},
    ConversationId, Delivery, Error, MsgRef,
};

/// What the network tells the platform. The event stream of the client
/// carries handles, and this one carries the state of the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    /// The circuit is ready.
    Online,
    /// The run of the network ended. Each contact stays in the store.
    Offline(Ended),
    /// The fragment of an invitation link, which the user gives out of
    /// band.
    Invitation(Vec<u8>),
    /// The relay holds no blob for a link that the user accepted.
    InvitationGone,
    /// The code of a verification ceremony, which the two users compare.
    VerificationCode(ConversationId, u32),
    /// The user confirmed a ceremony, and the store holds the state.
    Verified(ConversationId),
    /// A ceremony did not start, or no complete ceremony was there to
    /// confirm.
    VerificationRefused(ConversationId),
    /// A contact is ready, and its conversation takes drafts.
    Contact(ConversationId),
    /// The bundle of the sync channel of a device (Part 7 `DEV-286`), for
    /// the provision of a link.
    DeviceInvitation(Vec<u8>),
    /// The sync channel of another device of this set opened. No view
    /// shows it as a contact.
    DeviceLinked(ConversationId),
    /// The client refused an invitation command, such as a bundle that does
    /// not parse.
    Refused,
    /// A contact request arrived on a rendezvous queue (Part 9 §9.6).
    ContactRequest,
}

/// The state of the bridge for one run of the network runtime.
pub struct Bridge {
    commands: UnboundedSender<Command>,
    contacts: BTreeMap<ConversationId, ContactId>,
    sent: BTreeMap<u64, MsgRef>,
    next_tag: u64,
}

impl Bridge {
    /// A bridge over the command channel of one runtime. `contacts` holds
    /// each contact of the earlier runs.
    pub fn new(
        commands: UnboundedSender<Command>,
        contacts: BTreeMap<ConversationId, ContactId>,
    ) -> Self {
        Bridge {
            commands,
            contacts,
            sent: BTreeMap::new(),
            next_tag: 0,
        }
    }

    fn command(&self, command: Command) -> Result<(), Error> {
        self.commands.send(command).map_err(|_| Error::Offline)
    }

    /// Makes a notify queue of Part 8 §8.5.2 under a tag of the caller.
    pub fn make_notify_queue(&self, tag: u64) -> Result<(), Error> {
        self.command(Command::MakeNotifyQueue(tag))
    }

    /// Makes a new queue for a dead channel (`NET-182`).
    pub fn rotate_now(&self, contact: ContactId) -> Result<(), Error> {
        self.command(Command::RotateNow(contact))
    }

    /// The peer moved to `address` (`NET-190`).
    pub fn peer_moved(&self, contact: ContactId, address: Zeroizing<Vec<u8>>) -> Result<(), Error> {
        self.command(Command::PeerMoved { contact, address })
    }

    /// Ends a notify queue with a `DEL`.
    pub fn end_notify_queue(&self, recipient_id: [u8; 32]) -> Result<(), Error> {
        self.command(Command::EndNotifyQueue(recipient_id))
    }

    /// Makes a rendezvous queue of Part 9 §9.6 under a tag of the caller.
    pub fn make_rendezvous_queue(&self, tag: u64) -> Result<(), Error> {
        self.command(Command::MakeRendezvousQueue(tag))
    }

    /// Ends a rendezvous queue with a `DEL`.
    pub fn end_rendezvous_queue(&self, recipient_id: [u8; 32]) -> Result<(), Error> {
        self.command(Command::EndRendezvousQueue(recipient_id))
    }

    /// Sends a hello of Part 9 §9.6 to the rendezvous queue of an entry.
    pub fn hello(
        &self,
        entry_pk: Vec<u8>,
        rendezvous: Vec<u8>,
        profile: Vec<u8>,
        token: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        self.command(Command::Hello {
            entry_pk,
            rendezvous,
            profile,
            token,
        })
    }

    /// Sends the `NKEY` of an inbound queue (Part 8 §8.2.3).
    pub fn notify_queue(&self, recipient_id: [u8; 32]) -> Result<(), Error> {
        self.command(Command::NotifyQueue(recipient_id))
    }

    /// Sends the sealed binding of an inbound queue as its `NBIND`.
    pub fn bind_queue(&self, recipient_id: [u8; 32], sealed: Vec<u8>) -> Result<(), Error> {
        self.command(Command::BindQueue {
            recipient_id,
            sealed,
        })
    }

    /// Asks for one invitation. A [`NetEvent::Invitation`] follows.
    pub fn invite(&self) -> Result<(), Error> {
        self.command(Command::Invite)
    }

    /// Asks for the invitation of the sync channel of a device. A
    /// [`NetEvent::DeviceInvitation`] follows.
    pub fn invite_device(&self) -> Result<(), Error> {
        self.command(Command::InviteDevice)
    }

    /// Accepts the sync bundle of a provision. A [`NetEvent::DeviceLinked`]
    /// follows.
    pub fn accept_device(&self, bundle: Vec<u8>) -> Result<(), Error> {
        self.command(Command::AcceptDevice(bundle))
    }

    /// Accepts the fragment of a link. A [`NetEvent::Contact`] follows, or
    /// a [`NetEvent::InvitationGone`].
    pub fn accept(&self, fragment: Vec<u8>) -> Result<(), Error> {
        self.command(Command::Accept(fragment))
    }

    /// Tells the runtime whether a view of the app is on the screen. The
    /// cover clock makes a cover cell in the foreground only.
    pub fn set_foreground(&self, is_foreground: bool) -> Result<(), Error> {
        self.command(Command::Foreground(is_foreground))
    }

    /// The contact of each conversation of the run.
    pub fn contacts(&self) -> Vec<(ConversationId, ContactId)> {
        self.contacts
            .iter()
            .map(|(conversation, contact)| (*conversation, *contact))
            .collect()
    }

    /// The contact of a conversation, for a record that the store made.
    pub fn contact_for(&self, conversation: &ConversationId) -> Option<ContactId> {
        self.contacts.get(conversation).copied()
    }

    fn contact_of(&self, conversation: &ConversationId) -> Result<ContactId, Error> {
        self.contacts
            .get(conversation)
            .copied()
            .ok_or(Error::NotFound)
    }

    /// Starts a verification ceremony. A [`NetEvent::VerificationCode`]
    /// follows at the two devices.
    pub fn verify(&self, conversation: &ConversationId) -> Result<(), Error> {
        self.command(Command::Verify(self.contact_of(conversation)?))
    }

    /// The user says that the two codes match. A [`NetEvent::Verified`]
    /// follows.
    pub fn confirm_verified(&self, conversation: &ConversationId) -> Result<(), Error> {
        self.command(Command::ConfirmVerified(self.contact_of(conversation)?))
    }

    /// Gives each record that waits in the client to the runtime. A record
    /// for a conversation with no contact in this session fails.
    pub fn flush<B: Backend, E: SecureElement, R: CryptoRng + ?Sized>(
        &mut self,
        client: &mut Client<B, E>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
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
                // DEV-268: each record of the user goes to each device of
                // the set, but one that a peer handed to this device.
                if !client.was_handed(&outgoing.message) {
                    client.publish_sync(
                        outgoing.conversation,
                        &outgoing.app,
                        true,
                        None,
                        now,
                        rng,
                    )?;
                }
            } else if client.hands_off(outgoing.conversation)? {
                // DEV-047: this device owns no channel, and the owner sends
                // the record. Its state follows the record to the owner.
                client.publish_sync(
                    outgoing.conversation,
                    &outgoing.app,
                    true,
                    Some(outgoing.message),
                    now,
                    rng,
                )?;
            } else {
                client.set_delivery(&outgoing.message, Delivery::Failed, rng)?;
            }
        }
        while let Some(send) = client.take_sync_send() {
            let Some(contact) = self.contacts.get(&send.peer).copied() else {
                continue;
            };
            let tag = self.next_tag;
            self.next_tag = self.next_tag.wrapping_add(1);
            let command = Command::Send {
                contact,
                app: send.app,
                tag,
            };
            if self.commands.send(command).is_ok() {
                if let Some(message) = send.message {
                    self.sent.insert(tag, message);
                }
            }
        }
        Ok(())
    }

    /// Applies one update of the runtime to the client.
    pub fn on_update<B: Backend, E: SecureElement, R: CryptoRng + ?Sized>(
        &mut self,
        client: &mut Client<B, E>,
        update: Update,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Option<NetEvent>, Error> {
        Ok(match update {
            // The handle keeps the circuits, and the bridge has no part in it.
            // The bindings of Part 8 take these before the bridge.
            Update::Circuits(_)
            | Update::Queues(_)
            | Update::QueueEnded(_)
            | Update::ChannelDead(_)
            | Update::QueueRotated { .. }
            | Update::PeerMoved(_)
            | Update::ChannelRenewed(_)
            | Update::Tick
            | Update::NotifyKey { .. }
            | Update::NotifyQueue { .. }
            | Update::RendezvousQueue { .. }
            | Update::RendezvousRefused(_)
            | Update::Hello { .. }
            | Update::Digest { .. }
            // The report queue belongs to an authority, and no app holds one.
            | Update::ReportQueue { .. }
            | Update::LinkFault(_)
            | Update::Faults(_) => None,
            Update::Online => Some(NetEvent::Online),
            Update::Offline(ended) => Some(NetEvent::Offline(ended)),
            Update::Invitation(bundle) => Some(NetEvent::Invitation(bundle)),
            Update::DeviceInvitation(bundle) => Some(NetEvent::DeviceInvitation(bundle)),
            Update::Refused => Some(NetEvent::Refused),
            Update::InvitationGone => Some(NetEvent::InvitationGone),
            Update::Contact {
                contact, is_device, ..
            } => {
                let conversation = client.conversation_for(&contact.0)?;
                self.contacts.insert(conversation, contact);
                if is_device {
                    client.mark_device_peer(conversation, rng)?;
                    Some(NetEvent::DeviceLinked(conversation))
                } else {
                    // DEV-294: each device of the set holds the conversation.
                    client.publish_identity_entry(conversation, rng)?;
                    self.flush(client, rng)?;
                    Some(NetEvent::Contact(conversation))
                }
            }
            // The store took the record in the batch of its ratchet state.
            Update::Message { .. } => None,
            Update::VerificationCode { contact, code } => Some(NetEvent::VerificationCode(
                client.conversation_for(&contact.0)?,
                code,
            )),
            Update::VerificationRefused(contact) => Some(NetEvent::VerificationRefused(
                client.conversation_for(&contact.0)?,
            )),
            Update::Verified {
                contact,
                peer_static,
            } => {
                let conversation = client.conversation_for(&contact.0)?;
                client.set_verified(conversation, &peer_static, now_ms, rng)?;
                Some(NetEvent::Verified(conversation))
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
