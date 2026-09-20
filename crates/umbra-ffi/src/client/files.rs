//! The files of the messages (Part 13) in the store of one device.
//!
//! The plaintext of a file sits in the encrypted store and nowhere else:
//! from the moment the user attaches it, thus an upload continues after a
//! new start, and from the moment a download ends. Three tables hold the
//! state of a file, its bytes, and the write credential of each chunk that
//! this device uploaded (`ATT-160`).

use std::collections::VecDeque;

use umbra_core::{
    attach::{
        transfer::{ChunkCredential, Shape, Uploaded},
        MAX_DESCRIPTOR_REFS,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{rand_core::CryptoRng, secret::Secret};
use umbra_wire::{
    app::{AppKind, AppMessage, Channel},
    descriptor::{FileDescriptor, Level},
};
use zeroize::Zeroizing;

use super::{conversation_of, info_of, outbox_row, Client, Outgoing, MESSAGE_PREFIX, OUTBOX};
use crate::{Delivery, Error, Event, MsgRef};

/// The state and the shape of the file of a message.
pub(super) const FILE_STATE: TableId = TableId(0x0F);
/// The plaintext of the file of a message.
pub(super) const FILE_DATA: TableId = TableId(0x10);
/// The write credential of each chunk of a file that this device uploaded.
pub(super) const CHUNK_CRED: TableId = TableId(0x11);

const STATE_ROW_LEN: usize = 8;

/// Where the file of a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileState {
    /// This device sends the file, and the relays do not hold each chunk yet.
    Uploading = 1,
    /// A contact sent the file, and this device did not fetch it yet.
    Wanted = 2,
    /// The store holds the file.
    Ready = 3,
    /// The transfer ended with no result. A new attempt can follow.
    Failed = 4,
}

impl FileState {
    const fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => FileState::Uploading,
            2 => FileState::Wanted,
            3 => FileState::Ready,
            4 => FileState::Failed,
            _ => return None,
        })
    }
}

/// What a view needs of the file of a message, with no byte of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileInfo {
    /// Where the file is.
    pub state: FileState,
    /// The class and the size of the media, from the descriptor.
    pub shape: Shape,
}

/// A file that waits for the transfer task.
pub struct UploadJob {
    /// The message.
    pub message: MsgRef,
    /// The file.
    pub plain: Zeroizing<Vec<u8>>,
    /// The descriptor fields that the seal does not fix.
    pub shape: Shape,
}

/// A descriptor whose file this device wants.
pub struct DownloadJob {
    /// The message.
    pub message: MsgRef,
    /// The descriptor of the record.
    pub descriptor: Box<FileDescriptor>,
}

/// One chunk that this device uploaded, and that a deletion took (`ATT-161`).
pub struct ErasureJob {
    /// The chunk.
    pub chunk_id: [u8; 32],
    /// `cred_sk` of the chunk.
    pub cred: Secret<32>,
    /// Each relay that holds a copy.
    pub relays: Vec<[u8; 32]>,
}

/// The queues between the store and the transfer task.
#[derive(Default)]
pub(super) struct FileQueues {
    pub uploads: VecDeque<UploadJob>,
    pub downloads: VecDeque<DownloadJob>,
    pub erasures: VecDeque<ErasureJob>,
}

fn state_row(state: FileState, shape: &Shape) -> Vec<u8> {
    let mut row = Vec::with_capacity(STATE_ROW_LEN);
    row.push(state as u8);
    row.push(shape.mime_class);
    row.extend_from_slice(&shape.pixel_w.to_be_bytes());
    row.extend_from_slice(&shape.pixel_h.to_be_bytes());
    row.extend_from_slice(&shape.media_seconds.to_be_bytes());
    row
}

fn read_state_row(row: &[u8]) -> Result<FileInfo, Error> {
    let bytes: [u8; STATE_ROW_LEN] = row.try_into().map_err(|_| Error::Integrity)?;
    let [state, mime_class, w0, w1, h0, h1, s0, s1] = bytes;
    Ok(FileInfo {
        state: FileState::from_byte(state).ok_or(Error::Integrity)?,
        shape: Shape {
            mime_class,
            pixel_w: u16::from_be_bytes([w0, w1]),
            pixel_h: u16::from_be_bytes([h0, h1]),
            media_seconds: u16::from_be_bytes([s0, s1]),
        },
    })
}

pub(super) fn shape_of(descriptor: &FileDescriptor) -> Shape {
    Shape {
        mime_class: descriptor.mime_class,
        media_seconds: descriptor.media_seconds,
        pixel_w: descriptor.pixel_w,
        pixel_h: descriptor.pixel_h,
    }
}

/// The descriptor of an attachment record, when this device can fetch it:
/// level `0x00` with at most the refs of one descriptor.
pub(super) fn fetchable(body: &[u8]) -> Option<FileDescriptor> {
    let descriptor = FileDescriptor::parse(body).ok()?;
    let is_in_reach = descriptor.level == Level::Data
        && !descriptor.refs.is_empty()
        && descriptor.refs.len() <= MAX_DESCRIPTOR_REFS;
    is_in_reach.then_some(descriptor)
}

/// The state row of a file that a contact sent.
pub(super) fn incoming_state_row(body: &[u8]) -> (Vec<u8>, Option<FileDescriptor>) {
    match fetchable(body) {
        Some(descriptor) => (
            state_row(FileState::Wanted, &shape_of(&descriptor)),
            Some(descriptor),
        ),
        // A descriptor that this device cannot read shows as a file that
        // did not arrive, and the message stays.
        None => (state_row(FileState::Failed, &Shape::default()), None),
    }
}

fn credentials_row(credentials: &[ChunkCredential]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut row = Zeroizing::new(Vec::new());
    row.extend_from_slice(
        &u16::try_from(credentials.len())
            .map_err(|_| Error::TooLong)?
            .to_be_bytes(),
    );
    for credential in credentials {
        row.extend_from_slice(&credential.chunk_id);
        row.extend_from_slice(credential.cred.expose());
        row.push(u8::try_from(credential.relays.len()).map_err(|_| Error::TooLong)?);
        for relay in &credential.relays {
            row.extend_from_slice(relay);
        }
    }
    Ok(row)
}

fn read_credentials_row(row: &[u8]) -> Result<Vec<ErasureJob>, Error> {
    let mut at = 0usize;
    let mut take = |len: usize| {
        let bytes = row.get(at..at.saturating_add(len)).ok_or(Error::Integrity);
        at = at.saturating_add(len);
        bytes
    };
    let count: [u8; 2] = take(2)?.try_into().map_err(|_| Error::Integrity)?;
    let mut jobs = Vec::new();
    for _ in 0..u16::from_be_bytes(count) {
        let chunk_id: [u8; 32] = take(32)?.try_into().map_err(|_| Error::Integrity)?;
        let cred: [u8; 32] = take(32)?.try_into().map_err(|_| Error::Integrity)?;
        let relay_count = usize::from(*take(1)?.first().ok_or(Error::Integrity)?);
        let mut relays = Vec::with_capacity(relay_count);
        for _ in 0..relay_count {
            relays.push(take(32)?.try_into().map_err(|_| Error::Integrity)?);
        }
        jobs.push(ErasureJob {
            chunk_id,
            cred: Secret::new(cred),
            relays,
        });
    }
    Ok(jobs)
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The next file for the transfer task to upload.
    pub fn take_upload(&mut self) -> Option<UploadJob> {
        self.files.uploads.pop_front()
    }

    /// The next descriptor whose file the transfer task fetches.
    pub fn take_download(&mut self) -> Option<DownloadJob> {
        self.files.downloads.pop_front()
    }

    /// The next chunk that the transfer task erases at its relays.
    pub fn take_erasure(&mut self) -> Option<ErasureJob> {
        self.files.erasures.pop_front()
    }

    /// The state and the shape of the file of a message, or none for a
    /// message with no file.
    pub fn file_info(&self, message: &MsgRef) -> Result<Option<FileInfo>, Error> {
        let store = &self.open_ref()?.store;
        match store.get(FILE_STATE, &message.0)? {
            Some(row) => read_state_row(&row).map(Some),
            None => Ok(None),
        }
    }

    /// The file of a message, in the clear. The caller overwrites it after
    /// the use.
    pub fn file_bytes(&self, message: &MsgRef) -> Result<Zeroizing<Vec<u8>>, Error> {
        let store = &self.open_ref()?.store;
        store
            .get(FILE_DATA, &message.0)?
            .map(Zeroizing::new)
            .ok_or(Error::NotFound)
    }

    fn set_file_state<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        state: FileState,
        rng: &mut R,
    ) -> Result<RowId, Error> {
        let info = self.file_info(message)?.ok_or(Error::NotFound)?;
        let open = self.open_mut()?;
        let plain = open
            .store
            .get(TableId::MESSAGE, &message.0)?
            .ok_or(Error::NotFound)?;
        let conversation = conversation_of(&plain)?;
        let mut batch = open.store.begin();
        batch.put(
            FILE_STATE,
            message.0,
            Some(conversation.0),
            &state_row(state, &info.shape),
            rng,
        )?;
        batch.commit()?;
        Ok(conversation.0)
    }

    /// The relays hold each chunk of the file of a message. The record with
    /// the descriptor goes to the send path, and the store keeps the write
    /// credential of each chunk until the erase (`ATT-160`).
    pub fn upload_done<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        uploaded: &Uploaded,
        rng: &mut R,
    ) -> Result<(), Error> {
        let info = self.file_info(message)?.ok_or(Error::NotFound)?;
        let open = self.open_mut()?;
        let mut plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let conversation = conversation_of(&plain)?;
        let mut body = Zeroizing::new(vec![0u8; uploaded.descriptor.len()]);
        uploaded.descriptor.encode(&mut body)?;
        let app = {
            let held = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
            let parsed = AppMessage::parse(held, Channel::Pairwise)?;
            let record = AppMessage {
                kind: AppKind::Attachment,
                msg_id: parsed.msg_id,
                sent_at: parsed.sent_at,
                body: &body,
            };
            let mut app = Zeroizing::new(vec![0u8; record.len()]);
            record.encode(&mut app)?;
            app
        };
        plain.truncate(MESSAGE_PREFIX);
        plain.extend_from_slice(&app);
        let mut batch = open.store.begin();
        batch.put(
            TableId::MESSAGE,
            message.0,
            Some(conversation.0),
            &plain,
            rng,
        )?;
        batch.put(OUTBOX, message.0, None, &outbox_row(), rng)?;
        batch.put(
            CHUNK_CRED,
            message.0,
            Some(conversation.0),
            &credentials_row(&uploaded.credentials)?,
            rng,
        )?;
        batch.put(
            FILE_STATE,
            message.0,
            Some(conversation.0),
            &state_row(FileState::Ready, &info.shape),
            rng,
        )?;
        batch.commit()?;
        self.outgoing.push_back(Outgoing {
            message: *message,
            conversation,
            app: app.to_vec(),
        });
        self.events.push_back(Event::File { message: *message });
        Ok(())
    }

    /// The upload of the file of a message ended with no result, and the
    /// message fails with it.
    pub fn upload_failed<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.set_file_state(message, FileState::Failed, rng)?;
        self.set_delivery(message, Delivery::Failed, rng)?;
        self.events.push_back(Event::Delivery {
            message: *message,
            delivery: Delivery::Failed,
        });
        Ok(())
    }

    /// The file of a received message arrived, and its digest holds.
    pub fn download_done<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        file: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let conversation = self.set_file_state(message, FileState::Ready, rng)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(FILE_DATA, message.0, Some(conversation), file, rng)?;
        batch.commit()?;
        self.events.push_back(Event::File { message: *message });
        Ok(())
    }

    /// The download of the file of a message ended with no result.
    pub fn download_failed<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.set_file_state(message, FileState::Failed, rng)?;
        self.events.push_back(Event::File { message: *message });
        Ok(())
    }

    /// Asks again for the file of a received message whose download failed.
    pub fn fetch_file<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        rng: &mut R,
    ) -> Result<(), Error> {
        let info = self.file_info(message)?.ok_or(Error::NotFound)?;
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        if info.state != FileState::Failed || info_of(&plain)?.outgoing {
            return Err(Error::Malformed);
        }
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let parsed = AppMessage::parse(app, Channel::Pairwise)?;
        let descriptor = fetchable(parsed.body).ok_or(Error::Malformed)?;
        self.set_file_state(message, FileState::Wanted, rng)?;
        self.files.downloads.push_back(DownloadJob {
            message: *message,
            descriptor: Box::new(descriptor),
        });
        Ok(())
    }

    /// Puts each transfer that an earlier run left open into its queue
    /// again: the store holds the file of an upload, and the record holds
    /// the descriptor of a download.
    pub fn requeue_transfers(&mut self) -> Result<(), Error> {
        self.files.uploads.clear();
        self.files.downloads.clear();
        let store = &self.open_ref()?.store;
        let mut uploads = Vec::new();
        let mut downloads = Vec::new();
        for (row, state) in store.list(FILE_STATE, None)? {
            let info = read_state_row(&state)?;
            let Some(plain) = store.get(TableId::MESSAGE, &row)? else {
                continue;
            };
            let plain = Zeroizing::new(plain);
            match info.state {
                FileState::Uploading => {
                    let Some(file) = store.get(FILE_DATA, &row)? else {
                        continue;
                    };
                    uploads.push(UploadJob {
                        message: MsgRef(row),
                        plain: Zeroizing::new(file),
                        shape: info.shape,
                    });
                }
                FileState::Wanted => {
                    let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
                    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
                    if let Some(descriptor) = fetchable(parsed.body) {
                        downloads.push(DownloadJob {
                            message: MsgRef(row),
                            descriptor: Box::new(descriptor),
                        });
                    }
                }
                FileState::Ready | FileState::Failed => {}
            }
        }
        self.files.uploads.extend(uploads);
        self.files.downloads.extend(downloads);
        Ok(())
    }

    /// The chunks of the file of a message that this device uploaded, for
    /// the erase of `ATT-161`. The caller deletes the three file rows in its
    /// batch, and it queues these after the commit.
    pub(super) fn file_erasures(&self, message: &MsgRef) -> Result<Vec<ErasureJob>, Error> {
        let store = &self.open_ref()?.store;
        match store.get(CHUNK_CRED, &message.0)? {
            Some(row) => read_credentials_row(&Zeroizing::new(row)),
            None => Ok(Vec::new()),
        }
    }
}

/// The state row of a file that this device sends.
pub(super) fn outgoing_state_row(shape: &Shape) -> Vec<u8> {
    state_row(FileState::Uploading, shape)
}
