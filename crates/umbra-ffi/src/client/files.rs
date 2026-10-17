//! The files of the messages (Part 12) in the store of one device.
//!
//! The plaintext of a file sits in the encrypted store and nowhere else:
//! from the moment the user attaches it, thus an upload continues after a
//! new start, and from the moment a download ends. Three tables hold the
//! state of a file, its bytes, and the write credential of each chunk that
//! this device uploaded (`ATT-160`). A fourth one keeps those credentials
//! past the deletion of the message, until each relay erased its chunk
//! (`ATT-161`).

use std::collections::{BTreeMap, VecDeque};

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
    descriptor::{AttachmentBody, FileDescriptor},
};
use zeroize::Zeroizing;

use super::{conversation_of, info_of, outbox_row, Client, Outgoing, MESSAGE_PREFIX, OUTBOX};
use crate::{draft::DraftFile, Delivery, Error, Event, MsgRef};

/// The state and the shape of the file of a message.
pub(super) const FILE_STATE: TableId = TableId(0x0F);
/// The plaintext of the file of a message.
pub(super) const FILE_DATA: TableId = TableId(0x10);
/// The write credential of each chunk of a file that this device uploaded.
pub(super) const CHUNK_CRED: TableId = TableId(0x11);
/// The erase of the chunks of each file that this device uploaded
/// (`ATT-160`, `ATT-161`). The upload writes two rows under the message: a
/// copy of the credentials, and a hold. A deletion of the message takes the
/// hold and the row of `CHUNK_CRED` away (`IMP-164`), and the copy is then
/// due. The copy stays until each relay answered the `CDEL`, across each
/// lock and each new start. `CHUNK_LIFE_MAX` after the upload ends it too.
/// A message that leaves with no erase of its chunks takes the copy and the
/// hold along, thus no credential outlives its message there.
pub(super) const ERASE_DUE: TableId = TableId(0x55);
/// The first byte of a credentials row of `ERASE_DUE` (`IMP-130`). The time
/// of the upload in seconds follows it, and then the credentials as a row
/// of `CHUNK_CRED` holds them.
const ERASE_VERSION: u8 = 0x01;
/// The one byte of a hold row of `ERASE_DUE`.
const ERASE_HOLD: u8 = 0x00;
/// The first byte of a row of `ERASE_DUE` that holds one object of a device
/// link (Part 7 `DEV-003`). The time of the write in seconds follows it,
/// and then the credential as a row of `CHUNK_CRED` holds it. Such a row
/// has no hold and no message. It is due when its link runs no more, and
/// the caller says when that is.
const ERASE_LINK: u8 = 0x02;
/// The version and the time of a credentials row of `ERASE_DUE`.
const ERASE_HEAD: usize = 1 + 8;

/// The natural key of the row of `ERASE_DUE` of one link object.
fn link_key(chunk_id: &[u8; 32]) -> Vec<u8> {
    [b"link".as_slice(), chunk_id.as_slice()].concat()
}

/// The natural key of the hold row of a message.
fn hold_key(message: &RowId) -> Vec<u8> {
    [b"hold".as_slice(), message.as_slice()].concat()
}

/// The state, the class, and the three media fields. A row of this
/// version adds the size and the name after them.
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
    /// A contact sent the file, and it is above the automatic download
    /// limit of this device. It waits for a tap (`IMP-167`).
    Held = 5,
    /// Each replica of a chunk of the file holds none. No new attempt
    /// finds it, and only the sender can send it again (`ATT-052`,
    /// `ATT-054`).
    Gone = 6,
}

impl FileState {
    const fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => FileState::Uploading,
            2 => FileState::Wanted,
            3 => FileState::Ready,
            4 => FileState::Failed,
            5 => FileState::Held,
            6 => FileState::Gone,
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
    /// The size in bytes: exact when the store holds the file, and the
    /// padded size of the descriptor while it does not. Zero in a row of an
    /// earlier version.
    pub size: u64,
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

/// The erase of the file of one message, between the read of its
/// credentials and the commit of the deletion ([`Client::file_erasures`]).
pub(super) struct FileErasure {
    jobs: Vec<ErasureJob>,
    /// Whether `ERASE_DUE` holds a copy of the credentials.
    is_kept: bool,
    /// The hold row of the message in `ERASE_DUE`.
    hold: RowId,
}

impl FileErasure {
    /// The rows of `ERASE_DUE` that the deletion batch of the caller takes.
    /// The batch takes the hold alone when chunks go at their relays, thus
    /// the copy is due from the commit on. It takes the copy too when none
    /// goes.
    pub(super) fn rows(&self, message: &MsgRef) -> Vec<RowId> {
        if self.jobs.is_empty() {
            vec![message.0, self.hold]
        } else {
            vec![self.hold]
        }
    }
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
    /// The row of `ERASE_DUE` of each chunk whose `CDEL` has no answer yet,
    /// and the count of those chunks for each row.
    pub erasing: BTreeMap<[u8; 32], RowId>,
    pub erase_left: BTreeMap<RowId, usize>,
    /// Whether the platform said that the network costs by the byte.
    pub is_metered: bool,
}

/// The name and the preview that the body of a file carries (`WIR-531`,
/// `WIR-533`). The state row keeps them, thus a view reads no record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileExtras {
    /// The name of the file.
    pub name: Option<String>,
    /// A JPEG thumbnail of an image or of the first frame of a video.
    pub preview: Option<Vec<u8>>,
}

impl FileExtras {
    fn of_body(body: &[u8]) -> Self {
        AttachmentBody::parse(body).map_or_else(
            |_| FileExtras::default(),
            |parsed| FileExtras {
                name: parsed.name.map(std::borrow::Cow::into_owned),
                preview: parsed.preview.map(<[u8]>::to_vec),
            },
        )
    }
}

fn state_row(state: FileState, shape: &Shape, size: u64, extras: &FileExtras) -> Vec<u8> {
    let name = extras.name.as_deref().map_or(&[][..], str::as_bytes);
    let preview = extras.preview.as_deref().unwrap_or(&[]);
    let mut row = Vec::with_capacity(STATE_ROW_LEN + 10 + name.len() + preview.len());
    row.push(state as u8);
    row.push(shape.mime_class);
    row.extend_from_slice(&shape.pixel_w.to_be_bytes());
    row.extend_from_slice(&shape.pixel_h.to_be_bytes());
    row.extend_from_slice(&shape.media_seconds.to_be_bytes());
    row.extend_from_slice(&size.to_be_bytes());

    // The name takes one length byte and the preview two, as the body of
    // `WIR-531` does. A value too long for its field passes neither
    // `WIR-532` nor `WIR-533`, thus it never reaches this row.
    let name = if name.len() <= usize::from(u8::MAX) {
        name
    } else {
        &[]
    };
    row.push(u8::try_from(name.len()).unwrap_or(0));
    row.extend_from_slice(name);
    let preview = if preview.len() <= usize::from(u16::MAX) {
        preview
    } else {
        &[]
    };
    row.extend_from_slice(&u16::try_from(preview.len()).unwrap_or(0).to_be_bytes());
    row.extend_from_slice(preview);
    row
}

/// The name and the preview in a state row. A row of an earlier version
/// holds neither, or the name alone. A name that the store took before
/// `WIR-532` can hold a bidirectional format character. The name reads with
/// none, as the parser of the body reads it, thus the record that carries
/// it encodes again.
fn extras_of_state_row(row: &[u8]) -> FileExtras {
    let rest = row.get(STATE_ROW_LEN + 8..).unwrap_or(&[]);
    let Some((&name_len, rest)) = rest.split_first() else {
        return FileExtras::default();
    };
    let name = rest
        .get(..usize::from(name_len))
        .and_then(|name| core::str::from_utf8(name).ok())
        .map(crate::draft::without_bidi_marks)
        .filter(|name| !name.is_empty());
    let rest = rest.get(usize::from(name_len)..).unwrap_or(&[]);
    let preview = rest
        .get(..2)
        .and_then(|len| <[u8; 2]>::try_from(len).ok())
        .map(|len| usize::from(u16::from_be_bytes(len)))
        .and_then(|len| rest.get(2..2 + len))
        .filter(|preview| !preview.is_empty())
        .map(<[u8]>::to_vec);
    FileExtras { name, preview }
}

fn read_state_row(row: &[u8]) -> Result<FileInfo, Error> {
    let head = row.get(..STATE_ROW_LEN).ok_or(Error::Integrity)?;
    let bytes: [u8; STATE_ROW_LEN] = head.try_into().map_err(|_| Error::Integrity)?;
    let [state, mime_class, w0, w1, h0, h1, s0, s1] = bytes;
    let size = row
        .get(STATE_ROW_LEN..STATE_ROW_LEN + 8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map_or(0, u64::from_be_bytes);

    Ok(FileInfo {
        size,
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
/// either level, with at most the refs of one descriptor (`IMP-163`).
pub(super) fn fetchable(body: &[u8]) -> Option<FileDescriptor> {
    let descriptor = AttachmentBody::parse(body).ok()?.descriptor;
    let is_in_reach = !descriptor.refs.is_empty() && descriptor.refs.len() <= MAX_DESCRIPTOR_REFS;

    // ATT-142: a descriptor of a conversation names three replicas.
    let names_each = umbra_core::attach::manifest::reject_null_hints(&descriptor.refs).is_ok();
    (is_in_reach && names_each).then_some(descriptor)
}

/// The state row of a file that a contact sent, and its descriptor when
/// its download starts at once: at most `limit` bytes of padded size
/// (`IMP-163`). A larger file waits for a tap (`IMP-167`).
/// The state of a file as a backup or a link snapshot carries it
/// (`IDN-186`): the bytes stay on this device, thus a file that another
/// device can fetch waits for a tap there, and each other file failed.
pub(super) fn carried_state(row: &mut [u8]) {
    if let Some(state) = row.first_mut() {
        *state = match FileState::from_byte(*state) {
            Some(FileState::Wanted | FileState::Ready | FileState::Held) => FileState::Held,
            Some(FileState::Gone) => FileState::Gone,
            _ => FileState::Failed,
        } as u8;
    }
}

pub(super) fn incoming_state_row(body: &[u8], limit: u64) -> (Vec<u8>, Option<FileDescriptor>) {
    let extras = FileExtras::of_body(body);
    match fetchable(body) {
        Some(descriptor) => {
            let size = u64::from(descriptor.padded_size);
            let state = if size <= limit {
                FileState::Wanted
            } else {
                FileState::Held
            };
            (
                state_row(state, &shape_of(&descriptor), size, &extras),
                (state == FileState::Wanted).then_some(descriptor),
            )
        }
        // A descriptor that this device cannot read shows as a file that
        // did not arrive, and the message stays.
        None => (
            state_row(
                FileState::Failed,
                &Shape::default(),
                0,
                &FileExtras::default(),
            ),
            None,
        ),
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

    /// The name and the preview of the file of a message, when its sender
    /// gave them (`WIR-531`, `WIR-533`).
    pub fn file_extras(&self, message: &MsgRef) -> Result<FileExtras, Error> {
        let store = &self.open_ref()?.store;
        Ok(store
            .get(FILE_STATE, &message.0)?
            .map_or_else(FileExtras::default, |row| extras_of_state_row(&row)))
    }

    /// The name of the file of a message, when its sender gave one.
    pub fn file_name(&self, message: &MsgRef) -> Result<Option<String>, Error> {
        Ok(self.file_extras(message)?.name)
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
        self.put_file_state(message, state, info.size, rng)
    }

    /// Writes the state row of a file with a new state and size, and keeps
    /// its shape and its name.
    fn put_file_state<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        state: FileState,
        size: u64,
        rng: &mut R,
    ) -> Result<RowId, Error> {
        let info = self.file_info(message)?.ok_or(Error::NotFound)?;
        let extras = self.file_extras(message)?;
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
            &state_row(state, &info.shape, size, &extras),
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
        let extras = self.file_extras(message)?;
        let now = self.clock;
        let open = self.open_mut()?;
        let mut plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let conversation = conversation_of(&plain)?;

        // ATT-160: the copy of the credentials for the erase, and its hold.
        let credentials = credentials_row(&uploaded.credentials)?;
        let mut erase = Zeroizing::new(Vec::with_capacity(
            ERASE_HEAD.saturating_add(credentials.len()),
        ));
        erase.push(ERASE_VERSION);
        erase.extend_from_slice(&now.to_be_bytes());
        erase.extend_from_slice(&credentials);
        let hold = open.store.row_id(ERASE_DUE, &hold_key(&message.0));

        // WIR-531: the name travels after the descriptor, inside the record.
        let descriptor = FileDescriptor::parse(&{
            let mut bytes = Zeroizing::new(vec![0u8; uploaded.descriptor.len()]);
            uploaded.descriptor.encode(&mut bytes)?;
            bytes
        })?;
        let held = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let stored = AppMessage::parse(held, Channel::Pairwise)?;

        // WIR-535: the record held the caption alone until now.
        let caption = match core::str::from_utf8(stored.body) {
            Ok(text) if !text.is_empty() => Some(text),
            Ok(_) => None,
            Err(_) => return Err(Error::Integrity),
        };
        let attachment = AttachmentBody {
            descriptor,
            name: extras.name.as_deref().map(std::borrow::Cow::Borrowed),
            preview: extras.preview.as_deref(),
            caption,
        };
        let mut body = Zeroizing::new(vec![0u8; attachment.len()]);
        attachment.encode(&mut body)?;
        let app = {
            let parsed = &stored;
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
            &credentials,
            rng,
        )?;

        // The two rows name no conversation, thus a deletion that goes by
        // the owner of a row takes neither.
        batch.put(ERASE_DUE, message.0, None, &erase, rng)?;
        batch.put(ERASE_DUE, hold, None, &[ERASE_HOLD], rng)?;
        batch.put(
            FILE_STATE,
            message.0,
            Some(conversation.0),
            &state_row(FileState::Ready, &info.shape, info.size, &extras),
            rng,
        )?;
        batch.commit()?;

        // A file of a group goes to the group queue, and on no pairwise
        // channel (Part 11 §11.2).
        if self.is_group(conversation)? {
            let sent_at = AppMessage::parse(&app, Channel::Pairwise)?.sent_at;
            self.queue_group_post(conversation, Some(*message), &app, sent_at, rng)?;
        } else {
            self.outgoing.push_back(Outgoing {
                message: *message,
                conversation,
                app: app.to_vec(),
            });
        }

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
        self.fail(message, crate::FailureCause::Upload, rng)?;
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
        let size = u64::try_from(file.len()).unwrap_or(u64::MAX);
        let conversation = self.put_file_state(message, FileState::Ready, size, rng)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(FILE_DATA, message.0, Some(conversation), file, rng)?;
        batch.commit()?;
        self.events.push_back(Event::File { message: *message });

        Ok(())
    }

    /// The download of the file of a message ended with no result. A new
    /// attempt can follow, until `CHUNK_LIFE_MAX` after the arrival of the
    /// message. No relay holds a chunk past that time (`ATT-160`), thus the
    /// file is gone then (`ATT-052`). A replica that no consensus names any
    /// more answers nothing (`ATT-010`). Without this bound its file would
    /// fail at each tap with no end.
    pub fn download_failed<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        rng: &mut R,
    ) -> Result<(), Error> {
        let state = if self.is_past_chunk_life(message)? {
            FileState::Gone
        } else {
            FileState::Failed
        };
        self.set_file_state(message, state, rng)?;
        self.events.push_back(Event::File { message: *message });

        Ok(())
    }

    /// Whether `CHUNK_LIFE_MAX` passed since the store took a message. The
    /// time is the one of this device: the upload came before it, and the
    /// time that the sender wrote proves nothing.
    fn is_past_chunk_life(&self, message: &MsgRef) -> Result<bool, Error> {
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let stored_at = info_of(&plain)?.stored_at_ms / 1_000;

        Ok(self.clock.saturating_sub(stored_at) >= umbra_core::attach::CHUNK_LIFE_MAX)
    }

    /// Each replica of a chunk of the file of a received message holds
    /// none (`ATT-052`). The view names the file and shows no part of it
    /// (`ATT-053`), and no tap fetches it again.
    pub fn download_gone<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.set_file_state(message, FileState::Gone, rng)?;
        self.events.push_back(Event::File { message: *message });
        Ok(())
    }

    /// Sends the file of a message of this device again, as a new message
    /// in its conversation (`ATT-054`). It is a new upload under new
    /// credentials, and not a lease extension. The store holds the file of
    /// each message that this device sent.
    pub fn resend_file<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        let info = self.file_info(message)?.ok_or(Error::NotFound)?;
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        if !info_of(&plain)?.outgoing {
            return Err(Error::Malformed);
        }

        let conversation = conversation_of(&plain)?;
        let extras = self.file_extras(message)?;
        let file = DraftFile {
            plain: self.file_bytes(message)?,
            shape: info.shape,
            name: extras.name,
            preview: extras.preview,
        };
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        self.send_file(conversation, msg_id, file, &[], now_ms, rng)
    }

    /// Starts the transfer of the file of a message again after it failed:
    /// the download of a received file, or the upload of a file of this
    /// device.
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

        // A tap fetches a file that failed, and a file that waits for it
        // (`IMP-167`).
        if !matches!(info.state, FileState::Failed | FileState::Held) {
            return Err(Error::Malformed);
        }

        // A restored or linked store holds no file of the send, and the
        // file of the record comes down as the file of a contact does.
        let held = if info_of(&plain)?.outgoing {
            self.file_bytes(message).ok()
        } else {
            None
        };
        if let Some(file) = held {
            // The store holds the file of this device from the send, thus a
            // second upload needs no second read of its source (`IMP-160`).
            self.set_file_state(message, FileState::Uploading, rng)?;
            self.set_delivery(message, Delivery::Queued, rng)?;
            self.files.uploads.push_back(UploadJob {
                message: *message,
                plain: file,
                shape: info.shape,
            });
            return Ok(());
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

    /// The platform says whether the network costs by the byte. On a
    /// network with no such cost, each file that waits at or below the
    /// limit starts its download, when the user limits the automatic
    /// download to that network (`IMP-168`). The result counts them.
    pub fn set_metered<R: CryptoRng + ?Sized>(
        &mut self,
        is_metered: bool,
        rng: &mut R,
    ) -> Result<usize, Error> {
        self.files.is_metered = is_metered;
        if is_metered || !self.unmetered_only()? {
            return Ok(0);
        }

        let limit = self.auto_download_limit()?;
        let store = &self.open_ref()?.store;
        let mut waiting = Vec::new();
        for (row, state) in store.list(FILE_STATE, None)? {
            let info = read_state_row(&state)?;
            if info.state != FileState::Held || info.size > limit {
                continue;
            }
            let Some(plain) = store.get(TableId::MESSAGE, &row)? else {
                continue;
            };

            let plain = Zeroizing::new(plain);
            let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
            let parsed = AppMessage::parse(app, Channel::Pairwise)?;
            if let Some(descriptor) = fetchable(parsed.body) {
                waiting.push((MsgRef(row), descriptor));
            }
        }

        let count = waiting.len();
        for (message, descriptor) in waiting {
            self.set_file_state(&message, FileState::Wanted, rng)?;
            self.files.downloads.push_back(DownloadJob {
                message,
                descriptor: Box::new(descriptor),
            });
            self.events.push_back(Event::File { message });
        }

        Ok(count)
    }

    /// Whether the platform said that the network costs by the byte.
    pub fn is_metered(&self) -> bool {
        self.files.is_metered
    }

    /// The limit that applies now: the limit of the user, or none on a
    /// metered network when the user limits the automatic download to a
    /// network with no such cost (`IMP-168`).
    pub(super) fn download_limit_now(&self) -> Result<u64, Error> {
        if self.files.is_metered && self.unmetered_only()? {
            return Ok(0);
        }

        self.auto_download_limit()
    }

    /// Puts each transfer that an earlier run left open into its queue
    /// again: the store holds the file of an upload, and the record holds
    /// the descriptor of a download.
    pub fn requeue_transfers(&mut self) -> Result<(), Error> {
        self.files.uploads.clear();
        self.files.downloads.clear();
        let rows: Vec<RowId> = self
            .open_ref()?
            .store
            .list(FILE_STATE, None)?
            .into_iter()
            .map(|(row, _)| row)
            .collect();
        for row in rows {
            self.requeue_file(&MsgRef(row))?;
        }

        // ATT-161: each `CDEL` that an earlier run did not complete.
        self.requeue_erasures()
    }

    /// Puts the chunks of each due row of `ERASE_DUE` into the work list
    /// again (`ATT-161`). A row is due when a deletion took its hold and
    /// its row of `CHUNK_CRED`, and a relay did not answer its `CDEL` yet.
    /// A row older than `CHUNK_LIFE_MAX` leaves, because no relay holds its
    /// chunks (`ATT-160`).
    fn requeue_erasures(&mut self) -> Result<(), Error> {
        let now = self.clock;
        let open = self.open_mut()?;
        let mut due = Vec::new();
        let mut ended = Vec::new();
        for (row, plain) in open.store.list(ERASE_DUE, None)? {
            let plain = Zeroizing::new(plain);
            let Some((head, credentials)) = plain.split_at_checked(ERASE_HEAD) else {
                // A hold row. Its credentials row takes it along.
                continue;
            };

            // IMP-130: a row of a version that this build does not read
            // stays, and it stops no unlock and no run.
            if head.first() != Some(&ERASE_VERSION) {
                continue;
            }

            let at = head
                .get(1..)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map_or(0, u64::from_be_bytes);
            let hold = open.store.row_id(ERASE_DUE, &hold_key(&row));
            if at != 0 && now.saturating_sub(at) >= umbra_core::attach::CHUNK_LIFE_MAX {
                ended.push((row, hold));
                continue;
            }

            let is_held = open.store.get(ERASE_DUE, &hold)?.is_some();
            if open.store.get(CHUNK_CRED, &row)?.is_some() {
                continue;
            }

            // A hold with no row of `CHUNK_CRED`: the message left on a
            // path that erases no chunk. A removal by a moderator and the
            // removal of its conversation are such paths. No later deletion
            // names the copy, thus it goes, and no `CDEL` leaves for it.
            if is_held {
                ended.push((row, hold));
                continue;
            }

            if let Ok(jobs) = read_credentials_row(credentials) {
                due.push((row, jobs));
            }
        }

        if !ended.is_empty() {
            let mut batch = open.store.begin();
            for (row, hold) in ended {
                batch.delete(ERASE_DUE, row);
                batch.delete(ERASE_DUE, hold);
            }

            batch.commit()?;
        }

        for (row, jobs) in due {
            self.erase_from(row, jobs);
        }

        Ok(())
    }

    /// Keeps the erasure of one object that a device link put on the chunk
    /// path (`DEV-003`), from the write of the object on. The memory of a
    /// link ends at a lock and with its process. The object would then stay
    /// at its relays for its whole lifetime. The row leaves when each relay
    /// answered the `CDEL` ([`Client::chunk_erased`]).
    pub fn keep_erasure<R: CryptoRng + ?Sized>(
        &mut self,
        chunk_id: &[u8; 32],
        cred: &Secret<32>,
        relays: &[[u8; 32]],
        rng: &mut R,
    ) -> Result<(), Error> {
        let now = self.clock;
        let credentials = credentials_row(&[ChunkCredential {
            chunk_id: *chunk_id,
            cred: Secret::new(*cred.expose()),
            relays: relays.to_vec(),
        }])?;
        let mut value = Zeroizing::new(Vec::with_capacity(
            ERASE_HEAD.saturating_add(credentials.len()),
        ));
        value.push(ERASE_LINK);
        value.extend_from_slice(&now.to_be_bytes());
        value.extend_from_slice(&credentials);
        let open = self.open_mut()?;
        let row = open.store.row_id(ERASE_DUE, &link_key(chunk_id));
        let mut batch = open.store.begin();
        batch.put(ERASE_DUE, row, None, &value, rng)?;
        batch.commit()?;

        // The answer to a `CDEL` of this run takes the row away.
        self.files.erasing.insert(*chunk_id, row);
        self.files.erase_left.insert(row, 1);

        Ok(())
    }

    /// The erasure of each link object that the store keeps, for a caller
    /// that runs no link. Each one is the object of a link that ended. A
    /// row older than `CHUNK_LIFE_MAX` leaves, because no relay holds its
    /// object (`ATT-160`).
    pub fn kept_erasures(&mut self) -> Result<Vec<ErasureJob>, Error> {
        let now = self.clock;
        let open = self.open_mut()?;
        let mut due = Vec::new();
        let mut ended = Vec::new();
        for (row, plain) in open.store.list(ERASE_DUE, None)? {
            let plain = Zeroizing::new(plain);
            let Some((head, credentials)) = plain.split_at_checked(ERASE_HEAD) else {
                continue;
            };
            if head.first() != Some(&ERASE_LINK) {
                continue;
            }

            let at = head
                .get(1..)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map_or(0, u64::from_be_bytes);
            if at != 0 && now.saturating_sub(at) >= umbra_core::attach::CHUNK_LIFE_MAX {
                ended.push(row);
                continue;
            }

            if let Ok(jobs) = read_credentials_row(credentials) {
                due.push((row, jobs));
            }
        }

        if !ended.is_empty() {
            let mut batch = open.store.begin();
            for row in ended {
                batch.delete(ERASE_DUE, row);
            }

            batch.commit()?;
        }

        let mut out = Vec::new();
        for (row, jobs) in due {
            self.files.erase_left.insert(row, jobs.len());
            for job in jobs {
                self.files.erasing.insert(job.chunk_id, row);
                out.push(job);
            }
        }

        Ok(out)
    }

    /// Puts the chunks of one row of `ERASE_DUE` into the work list, each
    /// one once, and counts the answers that the row waits for.
    fn erase_from(&mut self, row: RowId, jobs: Vec<ErasureJob>) {
        let files = &mut self.files;
        for job in &jobs {
            files.erasing.insert(job.chunk_id, row);
        }

        files.erase_left.insert(row, jobs.len());
        for job in jobs {
            if !files
                .erasures
                .iter()
                .any(|waiting| waiting.chunk_id == job.chunk_id)
            {
                files.erasures.push_back(job);
            }
        }
    }

    /// Each relay of one chunk answered its `CDEL` (`ATT-161`). The row of
    /// `ERASE_DUE` leaves with the last chunk of its file. A chunk whose
    /// answer a lock or a new start lost goes again, and a relay that holds
    /// it no more answers that too.
    pub fn chunk_erased(&mut self, chunk_id: &[u8; 32]) -> Result<(), Error> {
        let Some(row) = self.files.erasing.remove(chunk_id) else {
            return Ok(());
        };

        let left = self.files.erase_left.get(&row).copied().unwrap_or(0);
        if left > 1 {
            self.files.erase_left.insert(row, left.saturating_sub(1));
            return Ok(());
        }

        self.files.erase_left.remove(&row);
        let open = self.open_mut()?;
        let hold = open.store.row_id(ERASE_DUE, &hold_key(&row));
        let mut batch = open.store.begin();
        batch.delete(ERASE_DUE, row);
        batch.delete(ERASE_DUE, hold);

        Ok(batch.commit()?)
    }

    /// Puts the transfer of one file back into the work list, when its
    /// state waits for one: a run that ended took it along, and nothing
    /// failed (`NET-320`).
    pub fn requeue_file(&mut self, message: &MsgRef) -> Result<(), Error> {
        // A file in the work list takes no second place in it.
        if self.files.uploads.iter().any(|job| job.message == *message)
            || self
                .files
                .downloads
                .iter()
                .any(|job| job.message == *message)
        {
            return Ok(());
        }
        let store = &self.open_ref()?.store;
        let Some(state) = store.get(FILE_STATE, &message.0)? else {
            return Ok(());
        };

        let info = read_state_row(&state)?;
        let Some(plain) = store.get(TableId::MESSAGE, &message.0)? else {
            return Ok(());
        };

        let plain = Zeroizing::new(plain);
        match info.state {
            FileState::Uploading => {
                let Some(file) = store.get(FILE_DATA, &message.0)? else {
                    return Ok(());
                };

                self.files.uploads.push_back(UploadJob {
                    message: *message,
                    plain: Zeroizing::new(file),
                    shape: info.shape,
                });
            }
            FileState::Wanted => {
                let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
                let parsed = AppMessage::parse(app, Channel::Pairwise)?;
                if let Some(descriptor) = fetchable(parsed.body) {
                    self.files.downloads.push_back(DownloadJob {
                        message: *message,
                        descriptor: Box::new(descriptor),
                    });
                }
            }
            // A held file waits for a tap and not for a new start.
            FileState::Ready | FileState::Failed | FileState::Held | FileState::Gone => {}
        }

        Ok(())
    }

    /// The chunks of the file of a message that this device uploaded, for
    /// the erase of `ATT-161`. The call writes nothing. The caller deletes
    /// the three file rows and the rows of [`FileErasure::rows`] in its
    /// batch, and it calls [`Client::start_erasures`] after the commit.
    ///
    /// The batch of the caller takes the hold of the message out of
    /// `ERASE_DUE` with the row of `CHUNK_CRED`. Thus the copy of the
    /// credentials there is due from that commit on, and the erase lives
    /// through a lock and a new start. A deletion that does not commit, or
    /// that a check refuses, leaves the hold, and nothing is due.
    pub(super) fn file_erasures(&self, message: &MsgRef) -> Result<FileErasure, Error> {
        let store = &self.open_ref()?.store;
        let jobs = match store.get(CHUNK_CRED, &message.0)? {
            Some(row) => read_credentials_row(&Zeroizing::new(row))?,
            None => Vec::new(),
        };

        Ok(FileErasure {
            jobs,
            // A file of an earlier version holds no copy, and its erase
            // waits in the memory alone.
            is_kept: store.get(ERASE_DUE, &message.0)?.is_some(),
            hold: store.row_id(ERASE_DUE, &hold_key(&message.0)),
        })
    }

    /// The rows of `ERASE_DUE` of a message that leaves with no erase of
    /// its chunks: the copy of the credentials and its hold. The caller
    /// deletes them in the batch that takes the message.
    pub(super) fn erase_rows(&self, message: &MsgRef) -> Result<[RowId; 2], Error> {
        let store = &self.open_ref()?.store;
        Ok([message.0, store.row_id(ERASE_DUE, &hold_key(&message.0))])
    }

    /// Puts the chunks of a deleted message into the work list, after the
    /// commit of its deletion.
    pub(super) fn start_erasures(&mut self, message: &MsgRef, erasure: FileErasure) {
        if erasure.is_kept && !erasure.jobs.is_empty() {
            for job in &erasure.jobs {
                self.files.erasing.insert(job.chunk_id, message.0);
            }

            self.files.erase_left.insert(message.0, erasure.jobs.len());
        }

        self.files.erasures.extend(erasure.jobs);
    }
}

/// The state row of a file that this device sends.
pub(super) fn outgoing_state_row(shape: &Shape, size: u64, extras: &FileExtras) -> Vec<u8> {
    state_row(FileState::Uploading, shape, size, extras)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_carried_file_waits_for_a_tap_or_failed() {
        let shape = Shape::default();
        let extras = FileExtras::default();
        for (from, to) in [
            (FileState::Ready, FileState::Held),
            (FileState::Wanted, FileState::Held),
            (FileState::Held, FileState::Held),
            (FileState::Uploading, FileState::Failed),
            (FileState::Failed, FileState::Failed),
            (FileState::Gone, FileState::Gone),
        ] {
            let mut row = state_row(from, &shape, 7, &extras);
            let rest = row[1..].to_vec();
            carried_state(&mut row);
            assert_eq!(row[0], to as u8);

            // IDN-186: the shape, the size, and the extras stay.
            assert_eq!(row[1..], rest[..]);
        }
    }

    #[test]
    fn a_stored_name_with_a_bidirectional_mark_reads_with_none() {
        // A row of a build before `WIR-532` forbade the marks.
        let extras = FileExtras {
            name: Some("report\u{202E}fdp.exe".to_owned()),
            preview: None,
        };
        let row = state_row(FileState::Ready, &Shape::default(), 7, &extras);
        let read = extras_of_state_row(&row).name.unwrap();
        assert_eq!(read, "reportfdp.exe");
        assert!(umbra_wire::descriptor::is_file_name(&read));

        // A name of marks alone is no name.
        let extras = FileExtras {
            name: Some("\u{200E}\u{2069}".to_owned()),
            preview: None,
        };
        let row = state_row(FileState::Ready, &Shape::default(), 7, &extras);
        assert_eq!(extras_of_state_row(&row).name, None);
    }

    #[test]
    fn a_stored_record_whose_name_holds_a_bidirectional_mark_still_gives_its_file() {
        use umbra_wire::descriptor::{ChunkRef, Level};
        let descriptor = FileDescriptor {
            level: Level::Data,
            file_key: Secret::new([6; 32]),
            file_nonce: [7; 24],
            commit: [8; 32],
            digest: [9; 32],
            media_seconds: 0,
            padded_size: umbra_wire::descriptor::CHUNK_SIZE,
            mime_class: umbra_wire::descriptor::class::DOC,
            pixel_w: 0,
            pixel_h: 0,
            refs: vec![ChunkRef {
                relay_id: [1; 32],
                chunk_id: [2; 32],
                cred_pk: [3; 32],
                replicas: [[4; 12], [5; 12]],
            }],
        };

        // The body as a build before the rule of the marks wrote it.
        let name = "a\u{200E}b.pdf";
        let mut body = vec![0u8; descriptor.len()];
        descriptor.encode(&mut body).unwrap();
        body.push(u8::try_from(name.len()).unwrap());
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&[0, 0]);

        // The file stays in reach, and its name shows with no mark.
        assert_eq!(fetchable(&body).unwrap().refs.len(), 1);
        let (row, wanted) = incoming_state_row(&body, u64::MAX);
        assert!(wanted.is_some());
        assert_eq!(row[0], FileState::Wanted as u8);
        assert_eq!(extras_of_state_row(&row).name.as_deref(), Some("ab.pdf"));
    }
}
