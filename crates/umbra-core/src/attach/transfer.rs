//! The transfer of one file over the chunk commands of a transfer node
//! (Part 12 §12.4.1, §12.8): an upload that places each chunk at `REPLICAS`
//! relays, and a download that reads each chunk from one of them.
//!
//! The two drivers read no clock and draw each random value from the caller.
//! A file above `MAX_DESCRIPTOR_REFS` chunks takes the manifest level of
//! §12.3.4: the upload places the data chunks, then the manifest of their
//! refs as a file of its own under `K_manifest`, and the download reads the
//! manifest before the data.

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicUsize, Ordering};

use umbra_crypto::{rand_core::CryptoRng, secret::Secret, x25519::StaticSecret};
use umbra_queue::Reject;
use umbra_wire::descriptor::{ChunkRef, FileDescriptor, Level};

use super::{
    manifest::{self, Replicas},
    place::{fetch_order, resolve_hint, AttachmentRelay, HoldOffs},
    seal::{manifest_key, open_chunk, read_secret, seal_file, Assembler, SealedFile},
    upload::ChunkUpload,
    MAX_CONCURRENT_DOWN, MAX_CONCURRENT_UP, MAX_DATA_CHUNKS, REPLICAS,
};
use crate::{
    session::node::{ChunkJob, ChunkOutcome, ClientNode},
    Error,
};

/// How many times an upload asks a replica for its proof again. The copy
/// of a `CREP` travels on a connection of its own, thus a `CVFY` can arrive
/// before it.
pub const VERIFY_ATTEMPTS: u8 = 6;
/// How many ticks of the caller a chunk command waits for its answer. A
/// relay that is out of reach gives none, and the upload must not wait
/// without an end.
pub const STEP_TIMEOUT_TICKS: u32 = 30;
/// How many times one chunk takes a new relay or a new start before the
/// upload fails.
pub const CHUNK_REPAIRS_MAX: u8 = 3;
/// The chunks of one upload that started and that are not placed. A
/// replica that gives no proof thus holds the upload at this count.
pub const UNPLACED_UP_MAX: usize = 4 * MAX_CONCURRENT_UP;
/// The chunks of one upload that register, or that hold their tokens and
/// wait for their `CPUT` (`ATT-199`). A registration takes a round trip of
/// its own, thus it starts long before its place in the window opens.
pub const REGISTER_AHEAD_MAX: usize = 2 * MAX_CONCURRENT_UP;
/// The window of a transfer at its start (`ATT-198`, `ATT-210`). The clock
/// of a step starts when the command enters the link, thus a slow link with
/// a wide window runs each step into `STEP_TIMEOUT_TICKS`.
pub const WINDOW_START: usize = 32;
/// The window never closes below this count.
pub const WINDOW_MIN: usize = 8;
/// A command with its answer inside this many ticks opens the window.
pub const WINDOW_FAST_TICKS: u32 = 8;
/// A command with its answer after this many ticks closes the window.
pub const WINDOW_SLOW_TICKS: u32 = 15;

/// The `CGET` of all downloads of one client (`ATT-165`). The downloads of
/// one transfer run share one budget. A [`ChunkFetch`] and a read of a handle
/// each hold one `CGET` outside it.
#[derive(Debug, Default)]
pub struct DownloadBudget {
    held: AtomicUsize,
    open: AtomicUsize,
}

impl DownloadBudget {
    /// The places of one download. An equal share keeps a large file from
    /// each place that the next file needs.
    fn share(&self) -> usize {
        let open = self.open.load(Ordering::Relaxed).max(1);

        (MAX_CONCURRENT_DOWN / open).max(1)
    }

    fn has_room(&self) -> bool {
        self.held.load(Ordering::Relaxed) < MAX_CONCURRENT_DOWN
    }

    fn take(&self) {
        self.held.fetch_add(1, Ordering::Relaxed);
    }

    fn give(&self, count: usize) {
        self.held.fetch_sub(count, Ordering::Relaxed);
    }

    fn join(&self) {
        self.open.fetch_add(1, Ordering::Relaxed);
    }

    fn leave(&self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The chunk commands that a transfer holds in flight at the most. The time
/// of each answer moves it (`ATT-198`, `ATT-210`).
#[derive(Clone, Copy)]
struct Window {
    size: usize,
    /// The size that the window can reach now.
    ceiling: usize,
    /// The size that the rule of the direction permits.
    most: usize,
}

impl Window {
    /// The window of an upload: it opens up to `most` with no proof.
    const fn free(most: usize) -> Self {
        Window {
            size: WINDOW_START,
            ceiling: most,
            most,
        }
    }

    /// The window of a download: it opens by proof alone (`ATT-210`).
    const fn proven(most: usize) -> Self {
        Window {
            size: WINDOW_START,
            ceiling: WINDOW_START,
            most,
        }
    }

    /// A command took its answer after `age` ticks (`ATT-210`). A fast
    /// answer shows that the link carried `carried` chunks in
    /// `WINDOW_FAST_TICKS`.
    fn on_proof(&mut self, age: u32, carried: usize) {
        if age <= WINDOW_FAST_TICKS {
            let proven = carried.saturating_mul(2).min(self.most);
            self.ceiling = self.ceiling.max(proven);
        }

        self.on_answer(age);

        if age >= WINDOW_SLOW_TICKS {
            self.ceiling = self.size;
        }
    }

    /// An answer came `age` ticks after its command.
    fn on_answer(&mut self, age: u32) {
        if age <= WINDOW_FAST_TICKS {
            self.size = self.size.saturating_add(2).min(self.ceiling);
        } else if age >= WINDOW_SLOW_TICKS {
            self.size = self.size.saturating_sub(4).max(WINDOW_MIN);
        }
    }

    /// A command took no answer inside `STEP_TIMEOUT_TICKS`.
    fn on_silence(&mut self) {
        self.size = (self.size / 2).max(WINDOW_MIN);
    }
}

fn random_below<R: CryptoRng + ?Sized>(rng: &mut R, bound: u32) -> u32 {
    let bound = bound.max(1);
    // A draw at or above the highest multiple of the bound goes again, thus
    // each value below the bound is equally likely.
    let zone = u32::MAX - u32::MAX % bound;

    loop {
        let mut bytes = [0u8; 4];
        rng.fill_bytes(&mut bytes);
        let value = u32::from_be_bytes(bytes);
        if value < zone {
            return value % bound;
        }
    }
}

fn random_bytes<R: CryptoRng + ?Sized, const N: usize>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// What the uploader keeps of one chunk until the chunk is erased
/// (`ATT-160`): with it the device sends the `CDEL` of `ATT-161`.
pub struct ChunkCredential {
    /// The chunk.
    pub chunk_id: [u8; 32],
    /// `cred_sk` of the chunk.
    pub cred: Secret<32>,
    /// Each relay that holds a copy.
    pub relays: Vec<[u8; 32]>,
}

/// A file that the relays hold.
pub struct Uploaded {
    /// The descriptor, which goes into a record of the conversation.
    pub descriptor: FileDescriptor,
    /// The write credential of each chunk.
    pub credentials: Vec<ChunkCredential>,
}

/// What a step of a transfer gave.
pub enum Progress<T> {
    /// The transfer goes on. The two values are the chunks done and the
    /// chunk count.
    Running(u32, u32),
    /// The transfer is complete.
    Done(T),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Register(usize),
    Put,
    Replicate,
    Verify(usize),
    /// The registration at the relay that takes the place of a replica
    /// which failed its proof (`ATT-118`).
    RegisterFresh(usize),
    /// The bytes for that relay, from this device.
    PutFresh(usize),
    /// The bytes of a copy that did not come, from this device to the relay
    /// of the draw that waits for it (`ATT-197`).
    PutMissing(usize),
}

struct ChunkState {
    upload: ChunkUpload,
    cred: [u8; 32],
    relays: Vec<[u8; 32]>,
    tokens: Vec<Option<[u8; 32]>>,
    /// The replicas that still owe a proof, with the attempts that remain.
    unverified: Vec<(usize, u8)>,
    /// The relays that failed for this chunk. No new draw takes one of them.
    failed: Vec<[u8; 32]>,
    /// The new relays and the new starts that this chunk took.
    repairs: u8,
    is_started: bool,
    /// The caller has the credential and the relays of this start
    /// ([`Upload::take_started`]).
    is_noted: bool,
    /// Each relay gave its token, thus the chunk waits for its `CPUT`.
    is_registered: bool,
    /// The `CPUT` left.
    is_put: bool,
    /// The first relay answered the `CPUT`.
    is_stored: bool,
    is_done: bool,
}

/// The class of an upload: an attachment of Part 12, or a backup object
/// of Part 4 §4.7.2 in the backup class of §12.3.3 rule 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Class {
    /// The relays of each chunk.
    replicas: usize,
    /// Whether the registration is a `BNEW`.
    is_backup: bool,
    /// The data chunk count above which the file takes the manifest level.
    descriptor_refs: usize,
}

impl Class {
    /// An attachment: `REPLICAS` relays, `CNEW`, and the manifest level
    /// above `MESSAGE_DESCRIPTOR_REFS` (`ATT-073`).
    pub const ATTACHMENT: Class = Class {
        replicas: REPLICAS,
        is_backup: false,
        descriptor_refs: super::MESSAGE_DESCRIPTOR_REFS,
    };
    /// A backup object: `BACKUP_REPLICAS` relays (`IDN-076`), `BNEW`
    /// (`IDN-117`), and the manifest level above `BACKUP_DESC_REFS`
    /// (`IDN-096`).
    pub const BACKUP: Class = Class {
        replicas: super::BACKUP_REPLICAS,
        is_backup: true,
        descriptor_refs: crate::identity::BACKUP_DESC_REFS,
    };
}

/// The upload of one file.
pub struct Upload {
    class: Class,
    sealed: SealedFile,
    file_key: Secret<32>,
    file_nonce: [u8; 24],
    /// The key of the chunks of this phase: `file_key`, then `K_manifest`.
    chunk_key: Secret<32>,
    /// The placed data chunks of a file of level `0x01`, while its manifest
    /// goes up (§12.3.4).
    data: Option<DataPhase>,
    /// The data chunk count of the file.
    data_chunks: usize,
    shape: Shape,
    chunks: Vec<ChunkState>,
    /// The relays with the attachment role, for a new draw.
    pool: Vec<AttachmentRelay>,
    /// Each command with no answer yet, and the tick of its send.
    waiting: BTreeMap<u64, (usize, Step, u32)>,
    /// The proofs that a later tick asks for again: the chunk, the replica,
    /// and the tick.
    retries: Vec<(usize, usize, u32)>,
    /// The `CPUT` that this upload holds in flight at the most (`ATT-198`).
    window: Window,
    ticks: u32,
    /// The name of this upload at the node. It is a random value that leaves
    /// the device in no form. The solution of a registration serves one
    /// upload alone (Part 13 `ABU-108`).
    admissions: u64,
    /// A chunk started or took a new relay since the last
    /// [`Upload::take_started`].
    has_unnoted: bool,
    /// The chunks of the data phase that the manifest phase took before the
    /// caller had them.
    noted_late: Vec<ChunkCredential>,
    /// The first asks for the proofs of new copies, as the chunk and the
    /// replica: those of this turn of [`Upload::ask_proofs`], and those of
    /// the turn before. A copy travels on a connection of its own, and a
    /// `CVFY` that overtakes it costs a wait of `ATT-190`.
    proofs_new: Vec<(usize, usize)>,
    proofs_due: Vec<(usize, usize)>,
}

/// The credentials of the placed data chunks of a file of level `0x01`,
/// and the fields of the file that its descriptor carries.
struct DataPhase {
    credentials: Vec<ChunkCredential>,
    commit: [u8; 32],
    digest: [u8; 32],
    padded_size: u32,
}

/// The fields of a descriptor that the seal does not fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Shape {
    /// The media class.
    pub mime_class: u8,
    /// The duration of an audio or a video object, else 0.
    pub media_seconds: u16,
    /// The width of an image or a video, else 0.
    pub pixel_w: u16,
    /// The height of an image or a video, else 0.
    pub pixel_h: u16,
}

impl Upload {
    /// Seals `plain` under a fresh key, and selects the relays of each chunk
    /// from `relays`: `REPLICAS` relays of different operators, one draw for
    /// each chunk (`ATT-017`, `ATT-122`).
    pub fn new<R: CryptoRng + ?Sized>(
        plain: &[u8],
        shape: Shape,
        relays: &[AttachmentRelay],
        rng: &mut R,
    ) -> Result<Self, Error> {
        Self::with_class(plain, shape, relays, Class::ATTACHMENT, rng)
    }

    /// The upload of `plain` in `class`.
    pub fn with_class<R: CryptoRng + ?Sized>(
        plain: &[u8],
        shape: Shape,
        relays: &[AttachmentRelay],
        class: Class,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let file_key = Secret::new(random_bytes(rng));
        let file_nonce = random_bytes(rng);
        let sealed = seal_file(&file_key, &file_nonce, plain)?;

        // ATT-082: one manifest level holds `MAX_DATA_CHUNKS`.
        if sealed.chunks.len() > MAX_DATA_CHUNKS {
            return Err(Error::Malformed);
        }

        let mut chunks = Vec::with_capacity(sealed.chunks.len());
        for _ in &sealed.chunks {
            chunks.push(ChunkState::draw(
                relays,
                Vec::new(),
                0,
                class.replicas,
                rng,
            )?);
        }

        Ok(Upload {
            class,
            data_chunks: sealed.chunks.len(),
            sealed,
            chunk_key: Secret::new(*file_key.expose()),
            data: None,
            file_key,
            file_nonce,
            shape,
            chunks,
            pool: relays.to_vec(),
            waiting: BTreeMap::new(),
            retries: Vec::new(),
            window: Window::free(MAX_CONCURRENT_UP),
            ticks: 0,
            admissions: u64::from_be_bytes(random_bytes(rng)),
            has_unnoted: false,
            noted_late: Vec::new(),
            proofs_new: Vec::new(),
            proofs_due: Vec::new(),
        })
    }

    /// Whether the answer with this handle belongs to this upload.
    pub fn owns(&self, handle: u64) -> bool {
        self.waiting.contains_key(&handle)
    }

    /// How many times a chunk of this upload took a new relay or a new start.
    pub fn repairs(&self) -> u32 {
        self.chunks
            .iter()
            .map(|chunk| u32::from(chunk.repairs))
            .sum()
    }

    /// The write credential of each chunk that started, or that took a new
    /// relay, since the last call. Relays can hold such a chunk when the
    /// upload ends with no result, thus the caller keeps each one until
    /// then (`ATT-160`, `ATT-204`). A relay whose registration has no
    /// answer yet can still register, thus each relay of a start counts.
    /// The caller calls this after each call into the upload.
    pub fn take_started(&mut self) -> Vec<ChunkCredential> {
        let mut started = core::mem::take(&mut self.noted_late);
        if !core::mem::take(&mut self.has_unnoted) {
            return started;
        }

        for chunk in &mut self.chunks {
            if chunk.is_started && !chunk.is_noted {
                chunk.is_noted = true;
                started.push(ChunkCredential {
                    chunk_id: *chunk.upload.chunk_id(),
                    cred: Secret::new(chunk.cred),
                    relays: chunk.relays.clone(),
                });
            }
        }
        started
    }

    /// Each `CPUT` that has no answer yet, a `CPUT` of a repair among them
    /// (`ATT-164`). A chunk past its `CPUT` holds no place, thus its `CREP`
    /// and its proofs travel while the next `CPUT` is in flight (`ATT-166`,
    /// `ATT-178`).
    fn in_flight(&self) -> usize {
        self.waiting
            .values()
            .filter(|(_, step, _)| {
                matches!(step, Step::Put | Step::PutFresh(_) | Step::PutMissing(_))
            })
            .count()
    }

    /// The chunks that register, or that wait for their `CPUT`.
    fn ahead(&self) -> usize {
        self.chunks
            .iter()
            .filter(|chunk| chunk.is_started && !chunk.is_put && !chunk.is_done)
            .count()
    }

    /// The chunks that started and that are not placed.
    fn unplaced(&self) -> usize {
        self.chunks
            .iter()
            .filter(|chunk| chunk.is_started && !chunk.is_done)
            .count()
    }

    /// The name of this upload at the admissions of its node (`ABU-108`).
    pub fn admission_name(&self) -> u64 {
        self.admissions
    }

    /// The registrations that this upload sends to each relay, with no
    /// repair: those of its data chunks, and those of its manifest chunks,
    /// whose relays a later draw gives. The caller solves for them ahead.
    pub fn registrations(&self) -> BTreeMap<[u8; 32], usize> {
        let manifest = if self.data_chunks > self.class.descriptor_refs {
            manifest::manifest_chunks(self.data_chunks)
        } else {
            0
        };

        let mut counts: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for relay in self.chunks.iter().flat_map(|chunk| chunk.relays.iter()) {
            let count = counts.entry(*relay).or_insert(manifest);
            *count = count.saturating_add(1);
        }

        counts
    }

    /// The `CPUT` that this upload holds in flight at the most (`ATT-198`).
    pub fn window(&self) -> usize {
        self.window.size
    }

    /// Whether the manifest of this upload goes up, for a test over real
    /// sockets.
    #[cfg(feature = "sockets-test")]
    pub fn is_in_manifest_phase(&self) -> bool {
        self.data.is_some()
    }

    /// The chunks placed, and the chunk count of both phases.
    fn progress(&self) -> (u32, u32) {
        let placed = self.chunks.iter().filter(|chunk| chunk.is_done).count();
        let manifest = if self.data_chunks > self.class.descriptor_refs {
            manifest::manifest_chunks(self.data_chunks)
        } else {
            0
        };
        let done = if self.data.is_some() {
            self.data_chunks.saturating_add(placed)
        } else {
            placed
        };
        let total = self.data_chunks.saturating_add(manifest);

        (
            u32::try_from(done).unwrap_or(u32::MAX),
            u32::try_from(total).unwrap_or(u32::MAX),
        )
    }

    /// The refs and the credentials of the placed chunks of this phase.
    fn placed(&self) -> Result<(Vec<ChunkRef>, Vec<ChunkCredential>), Error> {
        let mut refs: Vec<ChunkRef> = Vec::with_capacity(self.chunks.len());
        let mut credentials = Vec::with_capacity(self.chunks.len());
        for chunk in &self.chunks {
            refs.extend(chunk.upload.chunk_refs()?);
            credentials.push(ChunkCredential {
                chunk_id: *chunk.upload.chunk_id(),
                cred: Secret::new(chunk.cred),
                relays: chunk.relays.clone(),
            });
        }

        Ok((refs, credentials))
    }

    /// The data chunks are placed, and the manifest of their refs goes up
    /// as a file under `K_manifest` (`ATT-073`, `ATT-075`, `ATT-077`).
    fn start_manifest<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.noted_late = self.take_started();
        let (refs, credentials) = self.placed()?;
        let plain = manifest::build(&refs)?;
        let key = manifest_key(&self.file_key, &self.file_nonce);
        let sealed = seal_file(&key, &self.file_nonce, &plain)?;

        let mut chunks = Vec::with_capacity(sealed.chunks.len());
        for _ in &sealed.chunks {
            chunks.push(ChunkState::draw(
                &self.pool,
                Vec::new(),
                0,
                self.class.replicas,
                rng,
            )?);
        }

        let data = core::mem::replace(&mut self.sealed, sealed);
        self.data = Some(DataPhase {
            credentials,
            commit: data.commit,
            digest: data.digest,
            padded_size: data.padded_size,
        });
        self.chunk_key = key;
        self.chunks = chunks;
        self.retries.clear();

        Ok(())
    }

    fn send<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        index: usize,
        step: Step,
        rng: &mut R,
    ) -> Result<(), Error> {
        // A `CREP` changes the state of the chunk, thus it comes first.
        let targets = match step {
            Step::Replicate => {
                let chunk = self.chunks.get_mut(index).ok_or(Error::Malformed)?;
                chunk.upload.crep()?.targets
            }
            _ => Vec::new(),
        };

        let chunk = self.chunks.get(index).ok_or(Error::Malformed)?;
        let bytes = || {
            self.sealed
                .chunks
                .get(index)
                .cloned()
                .ok_or(Error::Malformed)
        };
        let cred = StaticSecret::from(chunk.cred);
        let chunk_id = *chunk.upload.chunk_id();
        let relay_at = |at: usize| chunk.relays.get(at).copied().ok_or(Error::Malformed);

        let (relay, job) = match step {
            Step::PutFresh(at) | Step::PutMissing(at) => {
                let storage_token = chunk
                    .tokens
                    .get(at)
                    .copied()
                    .flatten()
                    .ok_or(Error::Malformed)?;
                let job = ChunkJob::Put {
                    cred,
                    storage_token,
                    chunk: bytes()?,
                };
                (relay_at(at)?, job)
            }
            Step::Register(at) | Step::RegisterFresh(at) => {
                let index = u32::try_from(index).map_err(|_| Error::Malformed)?;
                let read = read_secret(&self.chunk_key, index);
                let job = ChunkJob::Register {
                    cred,
                    read_pk: *umbra_crypto::x25519::PublicKey::from(&read).as_bytes(),
                    is_backup: self.class.is_backup,
                };
                (relay_at(at)?, job)
            }
            Step::Put => {
                let target = *chunk.upload.put_target(chunk.relays.len())?;
                let job = ChunkJob::Put {
                    cred,
                    storage_token: target.storage_token,
                    chunk: bytes()?,
                };
                (target.relay_id, job)
            }
            Step::Replicate => {
                let job = ChunkJob::Replicate {
                    cred,
                    targets,
                    chunk: bytes()?,
                };
                (relay_at(0)?, job)
            }
            Step::Verify(at) => (
                relay_at(at)?,
                ChunkJob::Verify {
                    cred,
                    chunk: bytes()?,
                },
            ),
        };

        let handle = node.chunk_of(self.admissions, relay, chunk_id, job, rng)?;
        self.waiting.insert(handle, (index, step, self.ticks));
        Ok(())
    }

    /// A relay refused a step, gave a wrong proof, or gave no answer in
    /// time. After the `CREP` one replica takes a new relay (`ATT-118`).
    /// Before it, or when no relay can take that place, the chunk starts
    /// again (`ATT-189`).
    fn repair<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        index: usize,
        step: Step,
        rng: &mut R,
    ) -> Result<(), Error> {
        let chunk = self.chunks.get_mut(index).ok_or(Error::Malformed)?;
        chunk.repairs = chunk.repairs.saturating_add(1);
        if chunk.repairs > CHUNK_REPAIRS_MAX {
            return Err(Error::Unverified);
        }

        let chunk_id = *chunk.upload.chunk_id();
        match step {
            Step::Verify(at)
            | Step::RegisterFresh(at)
            | Step::PutFresh(at)
            | Step::PutMissing(at) => {
                let bad = *chunk.relays.get(at).ok_or(Error::Malformed)?;
                chunk.failed.push(bad);

                let others: Vec<[u8; 32]> = chunk
                    .relays
                    .iter()
                    .enumerate()
                    .filter(|(place, _)| *place != at)
                    .map(|(_, relay)| *relay)
                    .collect();
                let fresh = match fresh_relay(&self.pool, &others, &chunk.failed, rng) {
                    Ok(fresh) => fresh,
                    // ATT-202: no relay of the set can take the place, thus
                    // the chunk starts again, and its copies go.
                    Err(Error::NoPath) => return self.restart(node, index, None, None, rng),
                    Err(error) => return Err(error),
                };

                erase(node, bad, chunk_id, chunk.cred, rng);
                *chunk.relays.get_mut(at).ok_or(Error::Malformed)? = fresh;
                *chunk.tokens.get_mut(at).ok_or(Error::Malformed)? = None;
                if !chunk.unverified.iter().any(|(of, _)| *of == at) {
                    chunk.unverified.push((at, VERIFY_ATTEMPTS));
                }
                chunk.is_done = false;
                chunk.is_noted = false;
                self.has_unnoted = true;
                self.retries
                    .retain(|(of, place, _)| (*of, *place) != (index, at));

                self.send(node, index, Step::RegisterFresh(at), rng)
            }

            Step::Register(at) => {
                let bad = chunk.relays.get(at).copied();
                self.restart(node, index, bad, Some(at), rng)
            }

            Step::Put | Step::Replicate => {
                let bad = chunk.relays.first().copied();
                self.restart(node, index, bad, None, rng)
            }
        }
    }

    /// Starts a chunk again at a new draw of relays, under a new identifier
    /// and a new credential (`ATT-036`, `ATT-189`). The draw leaves out
    /// each relay that failed for the chunk, and `bad` with them, while the
    /// set holds enough other operators (`ATT-202`). Each relay that can hold a
    /// registration or a copy of the old start takes a `CDEL`.
    fn restart<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        index: usize,
        bad: Option<[u8; 32]>,
        refused: Option<usize>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let chunk = self.chunks.get_mut(index).ok_or(Error::Malformed)?;
        let mut failed = core::mem::take(&mut chunk.failed);
        failed.extend(bad);

        let chunk_id = *chunk.upload.chunk_id();
        let cred = chunk.cred;

        // A registration of the old start that waits for its solution never
        // leaves, at each relay of the draw.
        for relay in &chunk.relays {
            node.drop_unsolved(&chunk_id, relay);
        }

        for relay in chunk.erase_targets(refused) {
            erase(node, relay, chunk_id, cred, rng);
        }

        let repairs = chunk.repairs;
        // The answers of the old start name no step of this upload, and no
        // proof of it is asked again.
        self.waiting.retain(|_, (of, _, _)| *of != index);
        self.retries.retain(|(of, _, _)| *of != index);
        self.proofs_new.retain(|(of, _)| *of != index);
        self.proofs_due.retain(|(of, _)| *of != index);
        let mut next = ChunkState::draw(&self.pool, failed, repairs, self.class.replicas, rng)?;
        next.is_started = true;
        let replicas = next.relays.len();
        *self.chunks.get_mut(index).ok_or(Error::Malformed)? = next;
        self.has_unnoted = true;

        for at in 0..replicas {
            self.send(node, index, Step::Register(at), rng)?;
        }
        Ok(())
    }

    /// A replica gave no proof of its copy: it answered that it holds no
    /// such chunk, or it gave no answer in time. The copy can be on its way
    /// still, thus the proof is asked again some times (`ATT-190`). Then a
    /// fresh relay takes the place (`ATT-118`), or this device sends the
    /// bytes itself (`ATT-197`).
    fn copy_missing<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        index: usize,
        at: usize,
        is_answer: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let chunk = self.chunks.get_mut(index).ok_or(Error::Malformed)?;
        let entry = chunk
            .unverified
            .iter_mut()
            .find(|(of, _)| *of == at)
            .ok_or(Error::Malformed)?;
        entry.1 = entry.1.saturating_sub(1);
        let left = entry.1;

        if left > 0 {
            // ATT-190: each wait is two times the one before, thus the asks
            // give a copy about 30 ticks to arrive.
            let asked = u32::from(VERIFY_ATTEMPTS.saturating_sub(left));
            let wait = 1u32 << asked.saturating_sub(1).min(8);
            self.retries
                .push((index, at, self.ticks.saturating_add(wait)));
            return Ok(());
        }

        let others: Vec<[u8; 32]> = chunk
            .relays
            .iter()
            .enumerate()
            .filter(|(place, _)| *place != at)
            .map(|(_, relay)| *relay)
            .collect();
        let bad = chunk.relays.get(at).copied();
        let failed: Vec<[u8; 32]> = chunk.failed.iter().copied().chain(bad).collect();
        if has_fresh_relay(&self.pool, &others, &failed) {
            // ATT-119: a relay that answered that it holds no copy failed
            // its proof. An answer that did not come proves no fault
            // (`ATT-203`).
            if let (true, Some(bad)) = (is_answer, bad) {
                node.report_relay(&bad);
            }
            return self.repair(node, index, Step::Verify(at), rng);
        }

        // ATT-197: no other relay can take the copy, and this relay holds a
        // registration. Thus the bytes go to it from this device.
        entry.1 = VERIFY_ATTEMPTS;
        chunk.repairs = chunk.repairs.saturating_add(1);
        if chunk.repairs > CHUNK_REPAIRS_MAX {
            return Err(Error::Unverified);
        }
        self.send(node, index, Step::PutMissing(at), rng)
    }

    /// Moves the clock of the upload one tick: a step past
    /// `STEP_TIMEOUT_TICKS` takes its repair, each proof that a replica did
    /// not hold is asked for again, and each chunk that has room starts.
    /// The caller calls it at the start and at each tick of its clock, and
    /// an answer moves no clock.
    pub fn tick<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.ticks = self.ticks.saturating_add(1);

        // A registration that waits for its solution did not leave, thus a
        // slow solve counts against no step.
        for handle in node.unsolved_handles(self.admissions) {
            if let Some((_, _, sent)) = self.waiting.get_mut(&handle) {
                *sent = self.ticks;
            }
        }

        let late: Vec<(u64, usize, Step)> = self
            .waiting
            .iter()
            .filter(|(_, (_, _, sent))| self.ticks.saturating_sub(*sent) >= STEP_TIMEOUT_TICKS)
            .map(|(handle, (index, step, _))| (*handle, *index, *step))
            .collect();

        for (handle, index, step) in late {
            // A start that took the chunk since removed the step already.
            if self.waiting.remove(&handle).is_none() {
                continue;
            }

            match step {
                Step::Put => {
                    self.window.on_silence();
                    self.repair(node, index, step, rng)?;
                }
                // ATT-203: a proof that did not come counts as one ask.
                Step::Verify(at) => self.copy_missing(node, index, at, false, rng)?,
                // ATT-203: a `CPUT` of ATT-197 with no answer counts as a
                // refused one, thus the proof goes again. A fresh relay
                // gets no copy, and another one takes its place.
                Step::PutMissing(at) => self.retries.push((index, at, self.ticks)),
                _ => self.repair(node, index, step, rng)?,
            }
        }

        let ticks = self.ticks;
        let (due, later): (Vec<_>, Vec<_>) = core::mem::take(&mut self.retries)
            .into_iter()
            .partition(|(_, _, at_tick)| *at_tick <= ticks);
        self.retries = later;
        for (index, at, _) in due {
            self.send(node, index, Step::Verify(at), rng)?;
        }

        self.ask_proofs(node, rng)?;
        self.fill(node, rng)
    }

    /// Whether a first ask for a proof waits for [`Upload::ask_proofs`].
    pub fn has_proofs(&self) -> bool {
        !self.proofs_new.is_empty() || !self.proofs_due.is_empty()
    }

    /// One turn of a clock of the caller that is shorter than its tick: each
    /// first ask for a proof that waited one whole turn leaves. A tick is
    /// also a turn, thus no caller needs this clock.
    pub fn ask_proofs<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        let due = core::mem::replace(&mut self.proofs_due, core::mem::take(&mut self.proofs_new));

        for (index, at) in due {
            self.send(node, index, Step::Verify(at), rng)?;
        }

        Ok(())
    }

    /// Sends each `CPUT` that has room in the window of `ATT-198`, and
    /// starts the registrations of the chunks that come next. A chunk thus
    /// holds its tokens when a place opens, and the window waits for no
    /// registration.
    fn fill<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        while self.in_flight() < self.window.size {
            let Some(index) = self
                .chunks
                .iter()
                .position(|chunk| chunk.is_registered && !chunk.is_put)
            else {
                break;
            };
            self.chunks.get_mut(index).ok_or(Error::Malformed)?.is_put = true;
            self.send(node, index, Step::Put, rng)?;
        }

        while self.ahead() < REGISTER_AHEAD_MAX && self.unplaced() < UNPLACED_UP_MAX {
            let Some(index) = self.chunks.iter().position(|chunk| !chunk.is_started) else {
                break;
            };
            let replicas = {
                let chunk = self.chunks.get_mut(index).ok_or(Error::Malformed)?;
                chunk.is_started = true;
                chunk.relays.len()
            };
            self.has_unnoted = true;
            // ATT-096: a registration at each relay before the bytes.
            for at in 0..replicas {
                self.send(node, index, Step::Register(at), rng)?;
            }
        }

        Ok(())
    }

    /// Takes the answer to one chunk command. An answer with a handle of
    /// another transfer changes nothing.
    pub fn on_outcome<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<Uploaded>, Error> {
        let Some((index, step, sent)) = self.waiting.remove(&handle) else {
            let (done, total) = self.progress();
            return Ok(Progress::Running(done, total));
        };

        // ATT-198: the time of a `CPUT` to its answer moves the window.
        if matches!((step, &outcome), (Step::Put, ChunkOutcome::Stored)) {
            self.window.on_answer(self.ticks.saturating_sub(sent));
        }

        let chunk = self.chunks.get_mut(index).ok_or(Error::Malformed)?;
        match (step, outcome) {
            (Step::Register(at), ChunkOutcome::Registered(token)) => {
                *chunk.tokens.get_mut(at).ok_or(Error::Malformed)? = Some(token);
                if chunk.tokens.iter().all(Option::is_some) {
                    // The first relay of the draw takes the `CPUT`.
                    let pairs: Vec<_> = chunk.relays.iter().zip(&chunk.tokens).collect();
                    for (relay, token) in pairs {
                        chunk
                            .upload
                            .register(*relay, token.ok_or(Error::Malformed)?)?;
                    }
                    // The `CPUT` leaves when the window has room.
                    chunk.is_registered = true;
                }
            }

            (Step::Put, ChunkOutcome::Stored) => {
                let replicas = chunk.relays.len();
                chunk.upload.put_done(replicas)?;
                chunk.is_stored = true;
                self.send(node, index, Step::Replicate, rng)?;
            }

            (Step::Replicate, ChunkOutcome::Replicated) => {
                // ATT-113, ATT-120: each copy proves itself. The relay of the
                // `CPUT` gave its proof already.
                let copies = chunk.relays.len().saturating_sub(1);
                chunk.unverified = (1..=copies).map(|copy| (copy, VERIFY_ATTEMPTS)).collect();
                if chunk.unverified.is_empty() {
                    chunk.is_done = true;
                }
                self.proofs_new
                    .extend(chunk.unverified.iter().map(|(at, _)| (index, *at)));
            }

            (Step::Verify(at), ChunkOutcome::Verified) => {
                chunk.unverified.retain(|(of, _)| *of != at);
                chunk.is_done = chunk.unverified.is_empty();
            }

            // The copy can be on its way still, thus a refusal gets some
            // more attempts. A wrong proof gets none.
            (Step::Verify(at), ChunkOutcome::Refused(_)) => {
                self.copy_missing(node, index, at, true, rng)?;
            }

            // ATT-197: the copy of the first relay came while the bytes of
            // this device were on their way. The relay holds the chunk, and
            // its proof says so.
            (Step::PutMissing(at), ChunkOutcome::Refused(_)) => {
                self.retries.push((index, at, self.ticks));
            }

            (Step::RegisterFresh(at), ChunkOutcome::Registered(token)) => {
                *chunk.tokens.get_mut(at).ok_or(Error::Malformed)? = Some(token);
                let fresh = *chunk.relays.get(at).ok_or(Error::Malformed)?;
                // The registration that the new relay takes the place of:
                // the one whose relay the chunk holds no more.
                let stale = chunk
                    .upload
                    .relays()
                    .find(|relay| !chunk.relays.contains(relay))
                    .copied()
                    .ok_or(Error::Malformed)?;
                chunk.upload.replace_replica(&stale, fresh, token);
                self.send(node, index, Step::PutFresh(at), rng)?;
            }

            // ATT-186: the answer of a `CPUT` is a proof of the bytes.
            (Step::PutFresh(at) | Step::PutMissing(at), ChunkOutcome::Stored) => {
                chunk.unverified.retain(|(of, _)| *of != at);
                chunk.is_done = chunk.unverified.is_empty();
            }

            // ATT-119: a replica that failed its proof is a link fault.
            (Step::Verify(at), _) => {
                if let Some(bad) = chunk.relays.get(at).copied() {
                    node.report_relay(&bad);
                }
                self.repair(node, index, step, rng)?;
            }

            _ => self.repair(node, index, step, rng)?,
        }

        if self.chunks.iter().all(|chunk| chunk.is_done) {
            if self.data.is_some() || self.data_chunks <= self.class.descriptor_refs {
                return self.finish().map(Progress::Done);
            }
            self.start_manifest(rng)?;
        }

        // An answer fills the room it left, and it moves no clock.
        self.fill(node, rng)?;
        let (done, total) = self.progress();
        Ok(Progress::Running(done, total))
    }

    fn finish(&mut self) -> Result<Uploaded, Error> {
        let (refs, mut credentials) = self.placed()?;

        // A file of level `0x01` names its manifest chunks, and the data
        // chunks keep their credentials for a renewal and an erase.
        let (level, commit, digest, padded_size) = match self.data.take() {
            Some(data) => {
                credentials.extend(data.credentials);
                (Level::Manifest, data.commit, data.digest, data.padded_size)
            }
            None => (
                Level::Data,
                self.sealed.commit,
                self.sealed.digest,
                self.sealed.padded_size,
            ),
        };

        Ok(Uploaded {
            descriptor: FileDescriptor {
                level,
                file_key: Secret::new(*self.file_key.expose()),
                file_nonce: self.file_nonce,
                commit,
                digest,
                media_seconds: self.shape.media_seconds,
                padded_size,
                mime_class: self.shape.mime_class,
                pixel_w: self.shape.pixel_w,
                pixel_h: self.shape.pixel_h,
                refs,
            },
            credentials,
        })
    }
}

/// Sends a `CDEL` for a chunk that can sit at `relay`: a registration or a
/// copy. No answer is needed: without it a registration ends at
/// `CHUNK_PENDING_TTL` (`ATT-181`), and a copy at `CHUNK_TTL`.
fn erase<R: CryptoRng + ?Sized>(
    node: &mut ClientNode,
    relay: [u8; 32],
    chunk_id: [u8; 32],
    cred: [u8; 32],
    rng: &mut R,
) {
    // A registration that still waits for its solution never leaves.
    node.drop_unsolved(&chunk_id, &relay);

    let job = ChunkJob::Erase {
        cred: StaticSecret::from(cred),
    };
    let _ = node.chunk(relay, chunk_id, job, rng);
}

impl ChunkState {
    /// The relays that take a `CDEL` when the chunk starts again
    /// (`ATT-189`). They are each relay that gave a token, and each relay
    /// whose `CNEW` has no answer yet. A relay with no answer can register
    /// after the new start. Its `CID` then names no step of the upload, thus
    /// no later `CDEL` would go to it. A relay refuses a `CDEL` of a chunk
    /// that it does not hold, and that costs nothing. The relay of
    /// `refused`, whose registration failed, holds none and takes none.
    fn erase_targets(&self, refused: Option<usize>) -> Vec<[u8; 32]> {
        self.relays
            .iter()
            .zip(&self.tokens)
            .enumerate()
            .filter(|(at, (_, token))| token.is_some() || Some(*at) != refused)
            .map(|(_, (relay, _))| *relay)
            .collect()
    }

    /// A chunk under a new identifier and a new credential, at a new draw of
    /// relays that leaves out each relay of `failed` (`ATT-034`, `ATT-055`).
    fn draw<R: CryptoRng + ?Sized>(
        pool: &[AttachmentRelay],
        failed: Vec<[u8; 32]>,
        repairs: u8,
        replicas: usize,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let picked = pick_relays(pool, &failed, replicas, rng)?;
        let cred: [u8; 32] = random_bytes(rng);

        Ok(ChunkState {
            upload: ChunkUpload::new(random_bytes(rng), StaticSecret::from(cred)),
            cred,
            tokens: alloc::vec![None; picked.len()],
            relays: picked,
            unverified: Vec::new(),
            failed,
            repairs,
            is_started: false,
            is_noted: false,
            is_registered: false,
            is_put: false,
            is_stored: false,
            is_done: false,
        })
    }
}

/// Whether [`fresh_relay`] has a relay to give.
fn has_fresh_relay(pool: &[AttachmentRelay], others: &[[u8; 32]], failed: &[[u8; 32]]) -> bool {
    let operators: Vec<[u8; 32]> = pool
        .iter()
        .filter(|relay| others.contains(&relay.relay_id))
        .map(|relay| relay.operator_id)
        .collect();

    pool.iter().any(|relay| {
        !others.contains(&relay.relay_id)
            && !failed.contains(&relay.relay_id)
            && !operators.contains(&relay.operator_id)
    })
}

/// One relay for the place of a replica that failed: no relay of `failed`,
/// no relay of `others`, and no operator of `others` (`ATT-017`).
fn fresh_relay<R: CryptoRng + ?Sized>(
    pool: &[AttachmentRelay],
    others: &[[u8; 32]],
    failed: &[[u8; 32]],
    rng: &mut R,
) -> Result<[u8; 32], Error> {
    let operators: Vec<[u8; 32]> = pool
        .iter()
        .filter(|relay| others.contains(&relay.relay_id))
        .map(|relay| relay.operator_id)
        .collect();

    let free: Vec<&AttachmentRelay> = pool
        .iter()
        .filter(|relay| {
            !others.contains(&relay.relay_id)
                && !failed.contains(&relay.relay_id)
                && !operators.contains(&relay.operator_id)
        })
        .collect();

    let bound = u32::try_from(free.len()).map_err(|_| Error::Malformed)?;
    let at = usize::try_from(random_below(rng, bound)).map_err(|_| Error::Malformed)?;
    free.get(at)
        .map(|relay| relay.relay_id)
        .ok_or(Error::NoPath)
}

/// `replicas` relays of different operators, in a random order. A relay of
/// `failed` serves only when the other relays give too few operators: a
/// set of `replicas` relays then starts a chunk again at the same relays
/// (`ATT-202`). A relay set with fewer operators gives no upload, because
/// the redundancy is mandatory (§12.4).
fn pick_relays<R: CryptoRng + ?Sized>(
    relays: &[AttachmentRelay],
    failed: &[[u8; 32]],
    replicas: usize,
    rng: &mut R,
) -> Result<Vec<[u8; 32]>, Error> {
    let (fresh, stale): (Vec<AttachmentRelay>, Vec<AttachmentRelay>) = relays
        .iter()
        .partition(|relay| !failed.contains(&relay.relay_id));

    let mut picked: Vec<AttachmentRelay> = Vec::with_capacity(replicas);
    for mut pool in [fresh, stale] {
        while picked.len() < replicas && !pool.is_empty() {
            let bound = u32::try_from(pool.len()).map_err(|_| Error::Malformed)?;
            let at = usize::try_from(random_below(rng, bound)).map_err(|_| Error::Malformed)?;
            let relay = pool.swap_remove(at.min(pool.len().saturating_sub(1)));
            if picked
                .iter()
                .all(|held| held.operator_id != relay.operator_id)
            {
                picked.push(relay);
            }
        }
    }

    if picked.len() < replicas {
        return Err(Error::NoPath);
    }

    Ok(picked.into_iter().map(|relay| relay.relay_id).collect())
}

struct Wanted {
    /// The replicas that this fetch did not ask yet, the next one last.
    order: Vec<[u8; 32]>,
    bytes: Option<Vec<u8>>,
    /// The answers to this chunk, and the ones that said the relay holds
    /// no such chunk.
    answers: u32,
    refusals: u32,
    /// The replicas that this fetch does not ask. It does not ask a relay
    /// inside its hold-off (`ATT-174`). It does not ask a hint that names no
    /// relay or two relays of the consensus (`ATT-010`, `ATT-012`). The
    /// chunk may sit there, thus the refusals of the others lose no file.
    left_out: u32,
}

impl Wanted {
    /// Whether each replica that the refs name answered that it holds no
    /// such chunk (`ATT-052`).
    const fn is_gone(&self) -> bool {
        self.order.is_empty()
            && self.bytes.is_none()
            && self.refusals > 0
            && self.refusals == self.answers
            && self.left_out == 0
    }
}

/// The download of one file. A file of level `0x01` reads its manifest
/// first (`ATT-079`).
pub struct Download {
    /// The open file or manifest, until its last chunk.
    assembler: Option<Assembler>,
    /// The key of the chunks of this phase: `K_manifest`, then `file_key`.
    chunk_key: Secret<32>,
    chunk_ids: Vec<[u8; 32]>,
    wanted: Vec<Wanted>,
    /// The first chunk of `wanted` that took no `CGET`. A chunk leaves this
    /// count at its first `CGET` and never comes back.
    unasked: usize,
    /// The chunks that wait for a place in the window, thus a link that fell
    /// does not take a second copy of its backlog. Each one has the handle
    /// of its late `CGET`, when that `CGET` can still serve it.
    silent: VecDeque<(usize, Option<u64>)>,
    /// Each `CGET` that waits for its answer.
    waiting: BTreeMap<u64, Fetching>,
    /// Each `CGET` past `STEP_TIMEOUT_TICKS` whose chunk waits in `silent`.
    /// A relay cannot take a `CGET` back, thus its answer is on the link.
    late: BTreeMap<u64, Fetching>,
    /// The tick of each chunk answer of the last `WINDOW_FAST_TICKS`.
    carried: VecDeque<u32>,
    /// The places of all downloads of this client (`ATT-165`).
    budget: Arc<DownloadBudget>,
    /// The `CGET` that this download holds in flight at the most (`ATT-165`).
    window: Window,
    /// The ticks of the caller since the start.
    ticks: u32,
    /// The data phase of a file of level `0x01`, while its manifest comes.
    then: Option<DataPlan>,
    /// The relays that the fetch orders leave out (`ATT-174`), and the time
    /// that they hold at.
    hold_offs: HoldOffs,
    now: u64,
    /// Each chunk and relay that answered `BUSY` or `LIMIT`, for the
    /// hold-offs of the caller.
    refused: Vec<([u8; 32], [u8; 32])>,
}

/// One `CGET` that waits for its answer.
struct Fetching {
    /// The chunk.
    index: usize,
    /// The tick of its send.
    sent: u32,
    /// The commands in flight at its send.
    ahead: usize,
    relay: [u8; 32],
}

/// What the data phase of a file of level `0x01` needs.
struct DataPlan {
    assembler: Assembler,
    file_key: Secret<32>,
    data_chunks: usize,
    relays: Vec<AttachmentRelay>,
}

/// The fetch order of each chunk: its relays and the relays its hints name
/// (`ATT-008`), in a random order across the replicas (`ATT-019`).
fn plan<R: CryptoRng + ?Sized>(
    chunks: &[Replicas],
    relays: &[AttachmentRelay],
    hold_offs: &HoldOffs,
    now: u64,
    rng: &mut R,
) -> Vec<Wanted> {
    chunks
        .iter()
        .map(|chunk| {
            let mut replicas = chunk.relay_ids.clone();

            // ATT-010, ATT-012: a hint that does not resolve is a replica
            // out of reach, and no statement that the chunk is gone.
            let mut unresolved = 0usize;
            for hint in &chunk.hints {
                let ids = relays.iter().map(|relay| relay.relay_id);
                match resolve_hint(hint, ids) {
                    Ok(relay) if !replicas.contains(&relay) => replicas.push(relay),
                    Ok(_) => {}
                    Err(_) => unresolved = unresolved.saturating_add(1),
                }
            }

            let mut order = fetch_order(&chunk.chunk_id, &replicas, hold_offs, now, &mut |bound| {
                random_below(rng, bound)
            });
            order.reverse();
            let left_out = replicas
                .len()
                .saturating_sub(order.len())
                .saturating_add(unresolved);

            Wanted {
                order,
                bytes: None,
                answers: 0,
                refusals: 0,
                left_out: u32::try_from(left_out).unwrap_or(u32::MAX),
            }
        })
        .collect()
}

impl Download {
    /// Reads the descriptor, and resolves each replica hint against the
    /// relays of the set (`ATT-008`). A hint that names no relay or two
    /// relays gives no replica, and the other ones serve.
    pub fn new<R: CryptoRng + ?Sized>(
        descriptor: &FileDescriptor,
        relays: &[AttachmentRelay],
        rng: &mut R,
    ) -> Result<Self, Error> {
        Self::with_class(descriptor, relays, Class::ATTACHMENT, rng)
    }

    /// The download of a backup object, which takes the manifest level
    /// above `BACKUP_DESC_REFS` data chunks (`IDN-096`).
    pub fn new_backup<R: CryptoRng + ?Sized>(
        descriptor: &FileDescriptor,
        relays: &[AttachmentRelay],
        rng: &mut R,
    ) -> Result<Self, Error> {
        Self::with_class(descriptor, relays, Class::BACKUP, rng)
    }

    fn with_class<R: CryptoRng + ?Sized>(
        descriptor: &FileDescriptor,
        relays: &[AttachmentRelay],
        class: Class,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let data = Assembler::for_data(descriptor)?;
        let file_key = Secret::new(*descriptor.file_key.expose());
        let (assembler, chunk_key, expected, then) = match descriptor.level {
            Level::Data => (data, file_key, descriptor.refs.len(), None),
            Level::Manifest => {
                let data_chunks =
                    usize::try_from(data.chunk_count()).map_err(|_| Error::Malformed)?;
                let assembler = Assembler::for_manifest(descriptor)?;
                let manifest_chunks =
                    usize::try_from(assembler.chunk_count()).map_err(|_| Error::Malformed)?;

                // ATT-073: a manifest names more data chunks than one
                // descriptor holds. ATT-184: a manifest with a second ref
                // for a chunk takes more chunks than one ref for each.
                if data_chunks <= class.descriptor_refs
                    || !manifest::manifest_chunk_range(data_chunks).contains(&manifest_chunks)
                {
                    return Err(Error::Malformed);
                }

                let then = DataPlan {
                    assembler: data,
                    file_key,
                    data_chunks,
                    relays: relays.to_vec(),
                };
                let key = manifest_key(&descriptor.file_key, &descriptor.file_nonce);
                (assembler, key, manifest_chunks, Some(then))
            }
        };

        let chunks = manifest::collapse(&descriptor.refs, expected)?;
        Ok(Download {
            assembler: Some(assembler),
            chunk_key,
            chunk_ids: chunks.iter().map(|chunk| chunk.chunk_id).collect(),
            wanted: plan(&chunks, relays, &HoldOffs::default(), 0, rng),
            unasked: 0,
            silent: VecDeque::new(),
            waiting: BTreeMap::new(),
            late: BTreeMap::new(),
            carried: VecDeque::new(),
            budget: Arc::new(DownloadBudget {
                held: AtomicUsize::new(0),
                open: AtomicUsize::new(1),
            }),
            window: Window::proven(MAX_CONCURRENT_DOWN),
            ticks: 0,
            then,
            hold_offs: HoldOffs::default(),
            now: 0,
            refused: Vec::new(),
        })
    }

    /// The download shares `budget` with each other download of its client
    /// (`ATT-165`). The caller sets it before the first tick.
    #[must_use]
    pub fn with_budget(mut self, budget: &Arc<DownloadBudget>) -> Self {
        self.budget.leave();
        budget.join();
        self.budget = Arc::clone(budget);
        self
    }

    /// The download leaves out each relay inside its hold-off for a chunk
    /// at `now` (`ATT-174`), in each phase.
    #[must_use]
    pub fn with_hold_offs(mut self, hold_offs: &HoldOffs, now: u64) -> Self {
        for (wanted, chunk_id) in self.wanted.iter_mut().zip(&self.chunk_ids) {
            let before = wanted.order.len();
            wanted
                .order
                .retain(|relay| !hold_offs.blocked(chunk_id, relay, now));
            let left_out = before.saturating_sub(wanted.order.len());
            wanted.left_out = wanted
                .left_out
                .saturating_add(u32::try_from(left_out).unwrap_or(u32::MAX));
        }

        self.hold_offs = hold_offs.clone();
        self.now = now;
        self
    }

    /// Each chunk and relay that answered `BUSY` or `LIMIT` since the last
    /// call (`ATT-174`).
    pub fn take_refused(&mut self) -> Vec<([u8; 32], [u8; 32])> {
        core::mem::take(&mut self.refused)
    }

    /// The manifest opened: the data phase reads the chunks that it names
    /// (`ATT-079`, `ATT-184`).
    fn start_data<R: CryptoRng + ?Sized>(
        &mut self,
        manifest_plain: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let then = self.then.take().ok_or(Error::Stale)?;
        let refs = manifest::parse(manifest_plain)?;
        let chunks = manifest::collapse(&refs, then.data_chunks)?;

        self.chunk_ids = chunks.iter().map(|chunk| chunk.chunk_id).collect();
        self.wanted = plan(&chunks, &then.relays, &self.hold_offs, self.now, rng);
        self.unasked = 0;
        self.chunk_key = then.file_key;
        self.assembler = Some(then.assembler);
        Ok(())
    }

    fn ask<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        index: usize,
        rng: &mut R,
    ) -> Result<(), Error> {
        let wanted = self.wanted.get_mut(index).ok_or(Error::Malformed)?;
        // No replica is left: the file is out of reach.
        let relay = wanted.order.pop().ok_or(Error::NoPath)?;

        let chunk_id = *self.chunk_ids.get(index).ok_or(Error::Malformed)?;
        let read = read_secret(
            &self.chunk_key,
            u32::try_from(index).map_err(|_| Error::Malformed)?,
        );
        let handle = node.chunk(relay, chunk_id, ChunkJob::Fetch { read }, rng)?;
        let fetching = Fetching {
            index,
            sent: self.ticks,
            ahead: self.waiting.len(),
            relay,
        };
        self.waiting.insert(handle, fetching);
        self.budget.take();
        Ok(())
    }

    /// The `CGET` that this download holds in flight at the most (`ATT-165`).
    pub fn window(&self) -> usize {
        self.window.size
    }

    /// Whether the answer with this handle belongs to this download.
    pub fn owns(&self, handle: u64) -> bool {
        self.waiting.contains_key(&handle) || self.late.contains_key(&handle)
    }

    /// Whether each replica of one chunk answered that it holds no such
    /// chunk (Part 12 `ATT-052`). No new attempt finds that chunk, thus the
    /// file is lost. A download that failed for another cause gives false,
    /// and a later attempt can end well. Such a cause is a circuit that fell
    /// or a relay inside its hold-off (`ATT-174`). A replica whose hint the
    /// consensus of this device does not resolve is one too (`ATT-010`,
    /// `ATT-012`).
    pub fn is_gone(&self) -> bool {
        self.wanted.iter().any(Wanted::is_gone)
    }

    /// Moves the clock of the download one tick: a chunk past
    /// `STEP_TIMEOUT_TICKS` waits for a place, and it goes to the next
    /// replica (`ATT-019`, `ATT-210`). Each chunk that has room is asked for. The caller calls it at the start
    /// and at each tick of its clock, and an answer moves no clock. A lost
    /// answer thus holds no download until its circuit ends.
    pub fn tick<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.ticks = self.ticks.saturating_add(1);
        let late: Vec<u64> = self
            .waiting
            .iter()
            .filter(|(_, fetching)| self.ticks.saturating_sub(fetching.sent) >= STEP_TIMEOUT_TICKS)
            .map(|(handle, _)| *handle)
            .collect();

        for handle in late {
            let Some(fetching) = self.waiting.remove(&handle) else {
                continue;
            };

            self.budget.give(1);
            self.window.on_silence();
            self.window.ceiling = self.window.size;
            if let Some(wanted) = self.wanted.get_mut(fetching.index) {
                wanted.answers = wanted.answers.saturating_add(1);
            }
            self.silent.push_back((fetching.index, Some(handle)));
            self.late.insert(handle, fetching);
        }

        self.fill(node, rng)
    }

    /// Asks for each chunk that has room in the window of `ATT-210`.
    fn fill<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        while self.has_room() {
            let index = match self.silent.pop_front() {
                Some((index, None)) => index,
                Some((index, Some(handle))) => {
                    // The late answer served this chunk already.
                    if self.late.remove(&handle).is_none() {
                        continue;
                    }

                    index
                }
                None if self.unasked < self.wanted.len() => {
                    let index = self.unasked;
                    self.unasked = index.saturating_add(1);
                    index
                }
                None => break,
            };
            self.ask(node, index, rng)?;
        }

        Ok(())
    }

    /// Whether this download can hold one more `CGET` (`ATT-165`, `ATT-210`).
    fn has_room(&self) -> bool {
        let places = self.window.size.min(self.budget.share());

        self.waiting.len() < places && self.budget.has_room()
    }

    /// The chunks that the link carried in the last `WINDOW_FAST_TICKS`, with
    /// the answer of this tick. No window asks for more than `MAX_CONCURRENT_DOWN`,
    /// thus the count ends there.
    fn count_carried(&mut self) -> usize {
        let from = self.ticks.saturating_sub(WINDOW_FAST_TICKS);
        while self.carried.front().is_some_and(|tick| *tick < from) {
            self.carried.pop_front();
        }

        if self.carried.len() >= MAX_CONCURRENT_DOWN {
            self.carried.pop_front();
        }
        self.carried.push_back(self.ticks);

        self.carried.len()
    }

    /// Takes the answer to one `CGET`. The plaintext comes when the last
    /// chunk opens and the digest holds (`ATT-031`). An answer with a handle
    /// of another transfer changes nothing.
    pub fn on_outcome<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<Vec<u8>>, Error> {
        if self.step(node, handle, outcome, rng)? {
            let assembler = self.assembler.take().ok_or(Error::Stale)?;
            let plain = assembler.finish()?;
            if self.then.is_none() {
                return Ok(Progress::Done(plain));
            }
            self.start_data(&plain, rng)?;
            self.fill(node, rng)?;
        }

        let assembler = self.assembler.as_ref().ok_or(Error::Stale)?;
        Ok(Progress::Running(
            assembler.next_index(),
            assembler.chunk_count(),
        ))
    }

    fn step<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let on_time = self.waiting.remove(&handle);
        let is_late = on_time.is_none();
        let Some(fetching) = on_time.or_else(|| self.late.remove(&handle)) else {
            return Ok(false);
        };
        if !is_late {
            self.budget.give(1);
        }
        let Fetching { index, relay, .. } = fetching;

        // ATT-210: the time of a `CGET` to its answer moves the window. A
        // relay that answers late holds commands that never reached the
        // link, thus the count of commands ahead proves no rate alone.
        if matches!(outcome, ChunkOutcome::Fetched(_)) {
            let age = self.ticks.saturating_sub(fetching.sent);
            let carried = self.count_carried();
            self.window.on_proof(age, fetching.ahead.min(carried));
        }

        // ATT-150: a chunk that does not open under its tag is one bad
        // replica, and the next replica serves it (ATT-019). The chunk
        // opens once, and its segment waits for its turn.
        let opened = match &outcome {
            ChunkOutcome::Fetched(bytes) => {
                let position = u32::try_from(index).map_err(|_| Error::Malformed)?;
                self.assembler
                    .as_ref()
                    .and_then(|assembler| assembler.open_at(position, bytes))
            }
            _ => None,
        };

        let wanted = self.wanted.get_mut(index).ok_or(Error::Malformed)?;
        if !is_late {
            wanted.answers = wanted.answers.saturating_add(1);
        }
        let is_served = match outcome {
            ChunkOutcome::Fetched(_) if opened.is_some() => {
                wanted.bytes = opened;
                true
            }
            ChunkOutcome::Fetched(_) => {
                wanted.refusals = wanted.refusals.saturating_add(1);
                false
            }
            // ATT-019: the next replica. WIR-317 gives one reason to an
            // unknown chunk, and the read secret of a descriptor is right.
            ChunkOutcome::Refused(Reject::Rejected) => {
                wanted.refusals = wanted.refusals.saturating_add(1);
                false
            }
            // ATT-173, ATT-174: the next replica, and this relay takes no
            // same `CGET` inside the hold.
            ChunkOutcome::Refused(Reject::Busy | Reject::Limit) => {
                let chunk_id = *self.chunk_ids.get(index).ok_or(Error::Malformed)?;
                self.refused.push((chunk_id, relay));
                false
            }
            _ => false,
        };

        // A late `CGET` held no place, thus its next ask waits for one.
        if !is_served {
            if is_late {
                self.silent.push_back((index, None));
            } else {
                self.ask(node, index, rng)?;
            }
        }

        // The chunks open in their order.
        let assembler = self.assembler.as_mut().ok_or(Error::Stale)?;
        loop {
            let next = usize::try_from(assembler.next_index()).map_err(|_| Error::Malformed)?;
            let Some(segment) = self.wanted.get_mut(next).and_then(|w| w.bytes.take()) else {
                break;
            };
            assembler.accept_opened(&segment)?;
        }

        let is_complete = assembler.is_complete();
        self.fill(node, rng)?;
        Ok(is_complete)
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        self.budget.give(self.waiting.len());
        self.budget.leave();
    }
}

/// The fetch of one chunk of a file, which opens alone under its index
/// (Part 11 `GRP-284`, `GRP-285`): the slot of one member in a chunked
/// epoch-key record. No other chunk of the file leaves the relays.
pub struct ChunkFetch {
    file_key: Secret<32>,
    file_nonce: [u8; 24],
    index: u32,
    is_last: bool,
    chunk_id: [u8; 32],
    /// The replicas that this fetch did not ask yet, the next one last.
    order: Vec<[u8; 32]>,
    /// The `CGET` that waits for its answer, and the tick of its send.
    waiting: Option<(u64, u32)>,
    /// The relay of the last `CGET`.
    asked: [u8; 32],
    /// The ticks of the caller since the start.
    ticks: u32,
    /// Each relay that answered `BUSY` or `LIMIT`, for the hold-offs of the
    /// caller (`ATT-174`).
    refused: Vec<[u8; 32]>,
}

impl ChunkFetch {
    /// The fetch of chunk `index` of `descriptor`, over each replica that
    /// its reference names (`ATT-008`, `ATT-019`).
    pub fn new<R: CryptoRng + ?Sized>(
        descriptor: &FileDescriptor,
        index: u32,
        relays: &[AttachmentRelay],
        rng: &mut R,
    ) -> Result<Self, Error> {
        if descriptor.level != Level::Data {
            return Err(Error::Malformed);
        }

        // ATT-026, ATT-029: the key commitment holds before any chunk opens,
        // and ATT-067: the refs name each chunk of the padded size.
        crate::attach::seal::verify_commit(descriptor)?;
        let chunk_count = descriptor.padded_size / umbra_wire::descriptor::CHUNK_SIZE;
        if usize::try_from(chunk_count).ok() != Some(descriptor.refs.len()) {
            return Err(Error::Malformed);
        }

        let position = usize::try_from(index).map_err(|_| Error::Malformed)?;
        let chunk_ref = descriptor.refs.get(position).ok_or(Error::Malformed)?;
        let mut replicas = alloc::vec![chunk_ref.relay_id];
        for hint in &chunk_ref.replicas {
            let ids = relays.iter().map(|relay| relay.relay_id);
            if let Ok(relay) = resolve_hint(hint, ids) {
                replicas.push(relay);
            }
        }

        let mut order = fetch_order(
            &chunk_ref.chunk_id,
            &replicas,
            &HoldOffs::default(),
            0,
            &mut |bound| random_below(rng, bound),
        );
        order.reverse();

        Ok(ChunkFetch {
            file_key: Secret::new(*descriptor.file_key.expose()),
            file_nonce: descriptor.file_nonce,
            index,
            is_last: position.saturating_add(1) == descriptor.refs.len(),
            chunk_id: chunk_ref.chunk_id,
            order,
            waiting: None,
            asked: [0; 32],
            ticks: 0,
            refused: Vec::new(),
        })
    }

    /// The fetch leaves out each relay inside its hold-off at `now`
    /// (`ATT-174`).
    #[must_use]
    pub fn with_hold_offs(mut self, hold_offs: &HoldOffs, now: u64) -> Self {
        let chunk_id = self.chunk_id;
        self.order
            .retain(|relay| !hold_offs.blocked(&chunk_id, relay, now));
        self
    }

    /// Each chunk and relay that answered `BUSY` or `LIMIT` since the last
    /// call (`ATT-174`).
    pub fn take_refused(&mut self) -> Vec<([u8; 32], [u8; 32])> {
        let chunk_id = self.chunk_id;
        core::mem::take(&mut self.refused)
            .into_iter()
            .map(|relay| (chunk_id, relay))
            .collect()
    }

    /// Whether the answer with this handle belongs to this fetch.
    pub fn owns(&self, handle: u64) -> bool {
        self.waiting.is_some_and(|(held, _)| held == handle)
    }

    /// Moves the clock one tick, and asks the next replica when no
    /// question waits or when the one that waits is past
    /// `STEP_TIMEOUT_TICKS`. An answer moves no clock.
    pub fn tick<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.ticks = self.ticks.saturating_add(1);
        if self
            .waiting
            .is_some_and(|(_, sent)| self.ticks.saturating_sub(sent) >= STEP_TIMEOUT_TICKS)
        {
            self.waiting = None;
        }

        self.ask(node, rng)
    }

    /// Asks the next replica, when no question waits.
    fn ask<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.waiting.is_some() {
            return Ok(());
        }

        // No replica is left: the chunk is out of reach.
        let relay = self.order.pop().ok_or(Error::NoPath)?;
        let read = read_secret(&self.file_key, self.index);
        let handle = node.chunk(relay, self.chunk_id, ChunkJob::Fetch { read }, rng)?;
        self.waiting = Some((handle, self.ticks));
        self.asked = relay;
        Ok(())
    }

    /// Takes the answer to the `CGET`, and gives the opened segment.
    pub fn on_outcome<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<Vec<u8>>, Error> {
        if !self.owns(handle) {
            return Ok(Progress::Running(0, 1));
        }

        self.waiting = None;
        if matches!(outcome, ChunkOutcome::Refused(Reject::Busy | Reject::Limit)) {
            self.refused.push(self.asked);
        }

        if let ChunkOutcome::Fetched(bytes) = outcome {
            if let Ok(plain) = open_chunk(
                &self.file_key,
                &self.file_nonce,
                self.index,
                self.is_last,
                &bytes,
            ) {
                return Ok(Progress::Done(plain));
            }
        }

        // ATT-019: the next replica.
        self.ask(node, rng)?;
        Ok(Progress::Running(0, 1))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::abuse::test_rng::Rng;
    use crate::attach::seal::relay_hint;

    fn relay(id: u8) -> AttachmentRelay {
        AttachmentRelay {
            relay_id: [id; 32],
            operator_id: [id; 32],
            family_id: [id; 32],
        }
    }

    #[test]
    fn a_draw_below_a_bound_stays_below_it() {
        let mut rng = Rng(5);
        let mut seen = [false; 3];
        for _ in 0..64 {
            let value = random_below(&mut rng, 3);
            assert!(value < 3);
            seen[value as usize] = true;
        }

        assert!(seen.iter().all(|held| *held));
        assert_eq!(random_below(&mut rng, 0), 0);
        assert_eq!(random_below(&mut rng, 1), 0);
    }

    /// One chunk at relay 1 in full and at relays 2 and 3 by hint.
    fn three_replicas() -> [Replicas; 1] {
        [Replicas {
            chunk_id: [7; 32],
            cred_pk: [8; 32],
            relay_ids: alloc::vec![[1; 32]],
            hints: alloc::vec![relay_hint(&[2; 32]), relay_hint(&[3; 32])],
        }]
    }

    /// Each replica that the plan asks answers that it holds no chunk.
    fn refuse_each(wanted: &mut Wanted) {
        while wanted.order.pop().is_some() {
            wanted.answers += 1;
            wanted.refusals += 1;
        }
    }

    #[test]
    fn a_file_is_gone_when_each_named_replica_refused_and_not_before() {
        let set = [relay(1), relay(2), relay(3)];
        let none = HoldOffs::default();
        let mut wanted = plan(&three_replicas(), &set, &none, 0, &mut Rng(1));
        assert_eq!(wanted[0].order.len(), 3);
        assert_eq!(wanted[0].left_out, 0);
        assert!(!wanted[0].is_gone());
        refuse_each(&mut wanted[0]);
        assert!(wanted[0].is_gone());

        // An answer that did not come is no refusal.
        let mut slow = plan(&three_replicas(), &set, &none, 0, &mut Rng(2));
        refuse_each(&mut slow[0]);
        slow[0].refusals -= 1;
        assert!(!slow[0].is_gone());
    }

    #[test]
    fn a_hint_that_does_not_resolve_is_out_of_reach_and_not_gone() {
        // ATT-010: the consensus of this device holds relay 1 alone, and
        // relay 1 lost the chunk. The two other replicas may hold it.
        let none = HoldOffs::default();
        let mut wanted = plan(&three_replicas(), &[relay(1)], &none, 0, &mut Rng(1));
        assert_eq!(wanted[0].order, alloc::vec![[1u8; 32]]);
        assert_eq!(wanted[0].left_out, 2);
        refuse_each(&mut wanted[0]);
        assert!(!wanted[0].is_gone());

        // ATT-012: a hint that two relays of the consensus match counts
        // the same.
        let twice = [relay(1), relay(2), relay(2)];
        let mut wanted = plan(&three_replicas(), &twice, &none, 0, &mut Rng(2));
        assert_eq!(wanted[0].left_out, 2);
        refuse_each(&mut wanted[0]);
        assert!(!wanted[0].is_gone());

        // ATT-174: a relay inside its hold-off counts the same.
        let set = [relay(1), relay(2), relay(3)];
        let mut hold = HoldOffs::default();
        hold.note([7; 32], [2; 32], 100);
        let mut wanted = plan(&three_replicas(), &set, &hold, 200, &mut Rng(3));
        assert_eq!(wanted[0].left_out, 1);
        refuse_each(&mut wanted[0]);
        assert!(!wanted[0].is_gone());
    }

    #[test]
    fn a_new_start_erases_at_each_relay_that_can_hold_a_registration() {
        let pool = [relay(1), relay(2), relay(3)];
        let mut chunk = ChunkState::draw(&pool, Vec::new(), 0, 3, &mut Rng(1)).unwrap();
        let relays = chunk.relays.clone();

        // ATT-189: the first relay gave its token, the second refused, and
        // the `CNEW` at the third has no answer yet. The third can register
        // after the new start, thus it takes a `CDEL` too.
        chunk.tokens[0] = Some([9; 32]);
        assert_eq!(
            chunk.erase_targets(Some(1)),
            alloc::vec![relays[0], relays[2]]
        );

        // A `CPUT` or a `CREP` that failed erases at each relay.
        chunk.tokens = alloc::vec![Some([9; 32]); 3];
        assert_eq!(chunk.erase_targets(None), relays);
    }

    #[test]
    fn a_set_of_as_many_relays_as_replicas_starts_a_chunk_again_at_them() {
        // ATT-189: three file relays, and one failed. The new start takes
        // the same three under a new identifier.
        let pool = [relay(1), relay(2), relay(3)];
        let chunk = ChunkState::draw(&pool, alloc::vec![[2; 32]], 1, 3, &mut Rng(4)).unwrap();
        let mut relays = chunk.relays.clone();
        relays.sort_unstable();
        assert_eq!(relays, alloc::vec![[1; 32], [2; 32], [3; 32]]);
        assert_eq!(chunk.failed, alloc::vec![[2; 32]]);

        // A relay that failed serves only when no other one is left.
        let pool = [relay(1), relay(2), relay(3), relay(4)];
        for seed in 0..32 {
            let failed = alloc::vec![[1; 32], [2; 32]];
            let chunk = ChunkState::draw(&pool, failed, 1, 3, &mut Rng(seed)).unwrap();
            assert!(chunk.relays.contains(&[3; 32]));
            assert!(chunk.relays.contains(&[4; 32]));
        }

        // Two operators give no three replicas.
        let few = [relay(1), relay(2)];
        assert!(matches!(
            ChunkState::draw(&few, alloc::vec![[1; 32]], 1, 3, &mut Rng(5)),
            Err(Error::NoPath)
        ));
    }

    #[test]
    fn an_upload_gives_the_credential_of_each_chunk_once_at_its_start() {
        let pool = [relay(1), relay(2), relay(3)];
        let plain = alloc::vec![7u8; crate::attach::SEGMENT_SIZE * 3];
        let mut upload = Upload::new(&plain, Shape::default(), &pool, &mut Rng(6)).unwrap();
        assert!(upload.take_started().is_empty());

        // ATT-160: two chunks went to their relays, and the third did not.
        upload.chunks[0].is_started = true;
        upload.chunks[1].is_started = true;
        upload.has_unnoted = true;
        let started = upload.take_started();
        assert_eq!(started.len(), 2);
        for (credential, chunk) in started.iter().zip(&upload.chunks) {
            assert_eq!(credential.chunk_id, *chunk.upload.chunk_id());
            assert_eq!(*credential.cred.expose(), chunk.cred);
            assert_eq!(credential.relays, chunk.relays);
        }
        assert!(upload.take_started().is_empty());
    }

    /// A transfer node that holds each command: no relay of the set has a
    /// key, thus no circuit starts and no answer comes.
    fn silent_node() -> ClientNode {
        use crate::directory::{bloc::BlocId, path::Candidate};
        use crate::session::node::RelayInfo;
        use umbra_crypto::{handshake::nk::RelayStatic, hierarchy::RootIdentity};

        let ingress = RelayInfo {
            candidate: Candidate {
                relay_id: [0xEE; 32],
                operator_id: [0xEE; 32],
                family_id: [0xEE; 32],
                bloc: BlocId::Own([0; 2]),
                asn: 0,
                v4_prefix: None,
                v6_prefix: None,
                v4: None,
                ingress: true,
                chain: false,
                queue: false,
                layer: 1,
                class: 0,
            },
            key: RelayStatic {
                s: [0; 32],
                relay_id: [0xEE; 32],
            },
        };
        ClientNode::for_transfers(ingress, Vec::new(), RootIdentity::new(Secret::new([4; 32])))
    }

    #[test]
    fn a_window_of_a_download_opens_by_proof_alone() {
        let mut window = Window::proven(MAX_CONCURRENT_DOWN);

        // ATT-210: the first commands left ahead of a queue that did not
        // form yet, thus their answers prove nothing.
        window.on_proof(1, 0);
        window.on_proof(1, 3);
        assert_eq!(window.size, WINDOW_START);

        // A fast answer behind 20 commands proves 40.
        window.on_proof(8, 20);
        assert_eq!((window.size, window.ceiling), (34, 40));
        for _ in 0..8 {
            window.on_proof(8, 20);
        }
        assert_eq!(window.size, 40);

        // ATT-198: an answer between the two times moves nothing.
        window.on_proof(WINDOW_FAST_TICKS + 1, 100);
        assert_eq!((window.size, window.ceiling), (40, 40));

        // A window that closed takes a new proof.
        window.on_proof(WINDOW_SLOW_TICKS, 100);
        assert_eq!((window.size, window.ceiling), (36, 36));
        window.on_proof(1, 10);
        assert_eq!(window.size, 36);
        window.on_proof(1, 19);
        assert_eq!((window.size, window.ceiling), (38, 38));

        // ATT-165: no proof passes the ceiling, and no answer the floor.
        window.on_proof(1, 4 * MAX_CONCURRENT_DOWN);
        assert_eq!(window.ceiling, MAX_CONCURRENT_DOWN);
        for _ in 0..64 {
            window.on_proof(WINDOW_SLOW_TICKS, 0);
        }
        assert_eq!(window.size, WINDOW_MIN);
    }

    /// One file of `chunks` chunks at relays 1, 2, and 3, with the bytes of
    /// each chunk.
    fn fetchable(chunks: usize) -> (FileDescriptor, Vec<Vec<u8>>, Vec<u8>) {
        let key = Secret::new([9; 32]);
        let nonce = [8; 24];
        let plain: Vec<u8> = (0..crate::attach::SEGMENT_SIZE * chunks - 77)
            .map(|at| (at % 253) as u8)
            .collect();
        let sealed = seal_file(&key, &nonce, &plain).unwrap();

        let refs = (0..chunks)
            .map(|at| {
                let mut chunk_id = [0u8; 32];
                chunk_id[..8].copy_from_slice(&(at as u64).to_be_bytes());
                ChunkRef {
                    relay_id: [1; 32],
                    chunk_id,
                    cred_pk: [3; 32],
                    replicas: [relay_hint(&[2; 32]), relay_hint(&[3; 32])],
                }
            })
            .collect();
        let descriptor = FileDescriptor {
            level: Level::Data,
            file_key: key,
            file_nonce: nonce,
            commit: sealed.commit,
            digest: sealed.digest,
            media_seconds: 0,
            padded_size: sealed.padded_size,
            mime_class: 5,
            pixel_w: 0,
            pixel_h: 0,
            refs,
        };

        (descriptor, sealed.chunks, plain)
    }

    /// What some downloads did on a link of a modeled rate.
    #[derive(Debug, Default)]
    struct LinkRun {
        /// The largest window, and the smallest one after it.
        peak: usize,
        low_after_peak: usize,
        /// The `CGET` that passed `STEP_TIMEOUT_TICKS` and took a next ask.
        silences: usize,
        /// The longest wait of a `CGET` for its answer.
        slowest: u32,
        /// The most `CGET` of all downloads at one time.
        most_in_flight: usize,
        /// The tick of the first answer of the last file to take one.
        last_start: u32,
        ticks: u32,
    }

    /// One download of `over_links`.
    struct OnLink {
        download: Download,
        sealed: Vec<Vec<u8>>,
        plain: Vec<u8>,
        next_handle: u64,
        has_answer: bool,
    }

    /// One `CGET` on its way: its answer enters the link at `ready`.
    struct Command {
        ready: u32,
        file: usize,
        handle: u64,
        index: usize,
    }

    /// Runs one download over a link. See [`over_links`].
    fn over_link(chunks: usize, rate: impl Fn(u32) -> u32) -> LinkRun {
        over_links(1, chunks, rate, |_| 0)
    }

    /// Runs `files` downloads at one time over one link, with a round trip
    /// of one tick. Relay `id` adds `lag(id)` ticks before its answer. The
    /// link carries `rate(tick)` hundredths of a chunk in each tick, in the
    /// order of the answers. A relay cannot take a `CGET` back, thus an
    /// answer that the client gave up on still takes its part of the link.
    fn over_links(
        files: usize,
        chunks: usize,
        rate: impl Fn(u32) -> u32,
        lag: impl Fn(u8) -> u32,
    ) -> LinkRun {
        let pool = [relay(1), relay(2), relay(3)];
        let mut node = silent_node();
        let mut rng = Rng(11);
        let budget = Arc::new(DownloadBudget::default());
        let mut open: Vec<Option<OnLink>> = (0..files)
            .map(|_| {
                let (descriptor, sealed, plain) = fetchable(chunks);
                let download = Download::new(&descriptor, &pool, &mut rng).unwrap();
                Some(OnLink {
                    download: download.with_budget(&budget),
                    sealed,
                    plain,
                    next_handle: 0,
                    has_answer: false,
                })
            })
            .collect();

        let mut parked: Vec<Command> = Vec::new();
        let mut queue: VecDeque<Command> = VecDeque::new();
        let mut credit = 0;
        let mut run = LinkRun {
            low_after_peak: usize::MAX,
            ..LinkRun::default()
        };

        for tick in 1..=6_000 {
            run.ticks = tick;
            for held in open.iter_mut().flatten() {
                held.download.tick(&mut node, &mut rng).unwrap();
            }
            credit = (credit + rate(tick)).min(100 + rate(tick));

            loop {
                let in_flight = open
                    .iter()
                    .flatten()
                    .map(|held| held.download.waiting.len());
                run.most_in_flight = run.most_in_flight.max(in_flight.sum());

                // Each new command takes its way to its relay.
                for (file, held) in open.iter_mut().enumerate() {
                    let Some(held) = held else { continue };
                    for (handle, fetching) in held.download.waiting.range(held.next_handle..) {
                        parked.push(Command {
                            ready: tick + 1 + lag(fetching.relay[0]),
                            file,
                            handle: *handle,
                            index: fetching.index,
                        });
                        held.next_handle = handle + 1;
                    }
                }

                let (due, later) = core::mem::take(&mut parked)
                    .into_iter()
                    .partition(|command| command.ready <= tick);
                let due: Vec<Command> = due;
                parked = later;
                queue.extend(due);

                if credit < 100 || queue.is_empty() {
                    break;
                }
                credit -= 100;

                let command = queue.pop_front().unwrap();
                let Some(held) = open[command.file].as_mut() else {
                    continue;
                };

                if let Some(fetching) = held.download.waiting.get(&command.handle) {
                    run.slowest = run.slowest.max(tick - fetching.sent);
                }
                if !held.has_answer {
                    held.has_answer = true;
                    run.last_start = run.last_start.max(tick);
                }

                let bytes = held.sealed[command.index].clone();
                let outcome = ChunkOutcome::Fetched(bytes);
                let step = held
                    .download
                    .on_outcome(&mut node, command.handle, outcome, &mut rng);
                if let Progress::Done(fetched) = step.unwrap() {
                    assert!(fetched == held.plain, "the file came back changed");
                    run.note_end(&held.download);
                    open[command.file] = None;
                    if open.iter().all(Option::is_none) {
                        return run;
                    }
                    continue;
                }

                let window = held.download.window();
                if window > run.peak {
                    run.peak = window;
                    run.low_after_peak = window;
                }
                run.low_after_peak = run.low_after_peak.min(window);
            }
        }

        panic!("the downloads did not end: {run:?}");
    }

    impl LinkRun {
        /// Each answer past the first of a chunk stands for one silence.
        fn note_end(&mut self, download: &Download) {
            let silences = download.wanted.iter().map(|wanted| wanted.answers - 1);
            self.silences += silences.sum::<u32>() as usize;
        }
    }

    /// The chunks of one cell in a tick of 1 s on a link of `kbit` kbit/s,
    /// in hundredths.
    fn hundredths(kbit: u32) -> u32 {
        kbit * 1_000 * 100 / (8 * 32_860)
    }

    #[test]
    fn a_slow_link_holds_the_window_and_no_step_times_out() {
        // A window of `MAX_CONCURRENT_DOWN` holds its last chunk about 34 s
        // on 1 Mbit/s, past `STEP_TIMEOUT_TICKS`.
        for kbit in [500, 750, 1_000, 2_000] {
            let run = over_link(160, |_| hundredths(kbit));

            assert_eq!(run.silences, 0, "{kbit} kbit/s: {run:?}");
            assert!(run.slowest < WINDOW_SLOW_TICKS + 4, "{kbit}: {run:?}");
            assert!(run.peak <= 2 * 8 * hundredths(kbit) as usize / 100 + 2 * 8);
        }
    }

    #[test]
    fn a_link_that_falls_closes_the_window_and_the_file_still_comes() {
        // The link carries 5 Mbit/s until the window stands at its ceiling
        // of proof. Then it falls, with a full window in flight.
        for kbit in [500, 1_000] {
            let run = over_link(360, |tick| hundredths(if tick < 12 { 5_000 } else { kbit }));

            assert_eq!(run.peak, MAX_CONCURRENT_DOWN, "{kbit} kbit/s: {run:?}");
            assert!(run.low_after_peak <= WINDOW_START, "{kbit}: {run:?}");
        }
    }

    #[test]
    fn a_relay_that_answers_late_proves_no_rate_of_the_link() {
        // Relay 1 holds its commands for 14 ticks on a link of 1 Mbit/s, thus
        // an answer of another relay comes with many commands ahead of it
        // that are not on the link.
        let run = over_links(1, 300, |_| hundredths(1_000), |id| u32::from(id == 1) * 14);

        // ATT-210: the link carries about 30 chunks in `WINDOW_FAST_TICKS`.
        assert!(run.peak <= 2 * 30 + 2 * 8, "{run:?}");
        assert_eq!(run.silences, 0, "{run:?}");
    }

    /// A download of 40 chunks that took no answer past the step timeout.
    fn gone_silent() -> (Download, ClientNode, Rng, Vec<Vec<u8>>, Vec<u64>) {
        let pool = [relay(1), relay(2), relay(3)];
        let (descriptor, sealed, _) = fetchable(40);
        let mut node = silent_node();
        let mut rng = Rng(12);
        let mut download = Download::new(&descriptor, &pool, &mut rng).unwrap();
        download.tick(&mut node, &mut rng).unwrap();
        let first: Vec<u64> = download.waiting.keys().copied().collect();

        for _ in 0..STEP_TIMEOUT_TICKS {
            download.tick(&mut node, &mut rng).unwrap();
        }

        (download, node, rng, sealed, first)
    }

    #[test]
    fn a_silence_halves_the_window_and_takes_its_ceiling_down() {
        let (download, ..) = gone_silent();

        // ATT-198: each of the 32 `CGET` halves the window, to its floor.
        assert_eq!(download.window.size, WINDOW_MIN);
        // ATT-210: the limit falls with it, below its start.
        assert_eq!(download.window.ceiling, WINDOW_MIN);
        assert_eq!(download.waiting.len(), WINDOW_MIN);
        // A silence gives its place back, thus no later download stalls.
        assert_eq!(download.budget.held.load(Ordering::Relaxed), WINDOW_MIN);
    }

    #[test]
    fn a_silence_counts_as_one_answer_at_its_tick() {
        let (download, ..) = gone_silent();

        // No answer is no statement that the relay lacks the chunk. The count
        // of `is_gone` thus holds it while the chunk waits for a place.
        let waits = download.silent.iter().filter(|(_, late)| late.is_some());
        for (index, _) in waits {
            assert_eq!(download.wanted[*index].answers, 1);
            assert_eq!(download.wanted[*index].refusals, 0);
        }
    }

    #[test]
    fn a_silent_chunk_is_no_refusal() {
        let pool = [relay(1), relay(2), relay(3)];
        let (descriptor, sealed, _) = fetchable(40);
        let mut node = silent_node();
        let mut rng = Rng(12);
        let mut download = Download::new(&descriptor, &pool, &mut rng).unwrap();
        download.tick(&mut node, &mut rng).unwrap();

        // The first two replicas of chunks 30 and 31 refuse.
        for target in [30usize, 31] {
            for _ in 0..2 {
                let asked = &download.waiting;
                let (handle, _) = asked.iter().find(|(_, c)| c.index == target).unwrap();
                let handle = *handle;
                let outcome = ChunkOutcome::Refused(Reject::Rejected);
                download
                    .on_outcome(&mut node, handle, outcome, &mut rng)
                    .unwrap();
            }
        }
        assert!(download.wanted[31].order.is_empty());

        // The third replica of each one gives no answer, nor does any other.
        for _ in 0..STEP_TIMEOUT_TICKS {
            download.tick(&mut node, &mut rng).unwrap();
        }

        // The other chunks come, and chunk 30 then has no replica left.
        // ATT-052: chunk 31 can sit at its third relay, thus the file is not
        // gone. Before this count, it stayed `Gone` for good.
        let error = loop {
            let (handle, fetching) = download.waiting.iter().next().unwrap();
            let handle = *handle;
            let outcome = ChunkOutcome::Fetched(sealed[fetching.index].clone());
            if let Err(error) = download.on_outcome(&mut node, handle, outcome, &mut rng) {
                break error;
            }
        };

        assert!(matches!(error, Error::NoPath));
        assert!(!download.is_gone());
    }

    #[test]
    fn a_silent_chunk_goes_before_a_chunk_with_no_ask() {
        let (download, ..) = gone_silent();

        // The file has 40 chunks, and the first 32 went silent. The places
        // of the window go to those.
        assert_eq!(download.unasked, WINDOW_START);
        assert!(download.waiting.values().all(|c| c.index < WINDOW_START));
        assert_eq!(download.silent.len(), WINDOW_START - WINDOW_MIN);
    }

    #[test]
    fn a_ceiling_below_the_start_opens_by_a_new_proof_alone() {
        let mut window = Window::proven(MAX_CONCURRENT_DOWN);
        window.size = 12;
        window.ceiling = 12;

        // ATT-210: a slow answer takes the limit below 32, and a fast answer
        // with no proof does not bring 32 back.
        window.on_proof(WINDOW_SLOW_TICKS, 0);
        assert_eq!((window.size, window.ceiling), (8, 8));
        window.on_proof(1, 2);
        assert_eq!((window.size, window.ceiling), (8, 8));
        window.on_proof(1, 5);
        assert_eq!((window.size, window.ceiling), (10, 10));
    }

    #[test]
    fn a_late_answer_serves_its_chunk_and_closes_the_window() {
        let (mut download, mut node, mut rng, sealed, first) = gone_silent();
        let (handle, index) = first
            .iter()
            .filter_map(|handle| download.late.get(handle).map(|c| (*handle, c.index)))
            .next()
            .unwrap();
        download.window.size = 20;
        download.window.ceiling = 20;

        // ATT-210: the answer comes while the chunk waits for a place.
        assert!(download.owns(handle));
        let outcome = ChunkOutcome::Fetched(sealed[index].clone());
        download
            .on_outcome(&mut node, handle, outcome, &mut rng)
            .unwrap();

        assert!(!download.owns(handle));
        assert_eq!(download.wanted[index].answers, 1, "no silence counts");
        assert_eq!(download.window.size, 16, "a slow answer closes it");
        assert_eq!(download.window.ceiling, 16);

        // The next places pass this chunk: it asks no second replica.
        let replicas = download.wanted[index].order.len();
        download.window.size = MAX_CONCURRENT_DOWN;
        download.fill(&mut node, &mut rng).unwrap();
        assert!(download.silent.is_empty());
        assert!(download.waiting.values().all(|c| c.index != index));
        assert_eq!(download.wanted[index].order.len(), replicas);
    }

    #[test]
    fn a_late_refusal_waits_for_a_place_of_its_own() {
        let (mut download, mut node, mut rng, _, first) = gone_silent();
        let handle = *first
            .iter()
            .find(|handle| download.late.contains_key(handle))
            .unwrap();
        let held = download.waiting.len();
        let outcome = ChunkOutcome::Refused(Reject::Rejected);

        download
            .on_outcome(&mut node, handle, outcome, &mut rng)
            .unwrap();

        assert_eq!(download.waiting.len(), held, "no place above the window");
    }

    #[test]
    fn the_downloads_of_a_client_share_one_budget() {
        // ATT-165: three files at 20 Mbit/s. Each one could prove 128.
        let run = over_links(3, 200, |_| hundredths(20_000), |_| 0);
        assert!(run.most_in_flight <= MAX_CONCURRENT_DOWN, "{run:?}");
        assert!(run.most_in_flight > MAX_CONCURRENT_DOWN / 2, "{run:?}");
        // An equal share: no file waits for the end of the file before it.
        assert!(run.last_start <= 2, "{run:?}");
        assert_eq!(run.silences, 0, "{run:?}");
    }

    #[test]
    fn a_second_file_takes_an_equal_share_of_the_places() {
        let budget = Arc::new(DownloadBudget::default());
        let pool = [relay(1), relay(2), relay(3)];
        let (descriptor, ..) = fetchable(100);
        let mut node = silent_node();
        let mut rng = Rng(14);

        let mut first = Download::new(&descriptor, &pool, &mut rng)
            .unwrap()
            .with_budget(&budget);
        let mut second = Download::new(&descriptor, &pool, &mut rng)
            .unwrap()
            .with_budget(&budget);
        first.window.size = MAX_CONCURRENT_DOWN;
        first.window.ceiling = MAX_CONCURRENT_DOWN;

        // ATT-165: a window that could take each place leaves half of them.
        first.tick(&mut node, &mut rng).unwrap();
        assert_eq!(first.waiting.len(), MAX_CONCURRENT_DOWN / 2);
        second.tick(&mut node, &mut rng).unwrap();
        assert_eq!(second.waiting.len(), WINDOW_START);
    }

    #[test]
    fn a_file_that_joins_late_takes_no_place_above_the_budget() {
        let budget = Arc::new(DownloadBudget::default());
        let pool = [relay(1), relay(2), relay(3)];
        let (descriptor, ..) = fetchable(MAX_CONCURRENT_DOWN + 4);
        let mut node = silent_node();
        let mut rng = Rng(15);

        let mut first = Download::new(&descriptor, &pool, &mut rng)
            .unwrap()
            .with_budget(&budget);
        first.window.size = MAX_CONCURRENT_DOWN;
        first.window.ceiling = MAX_CONCURRENT_DOWN;
        first.tick(&mut node, &mut rng).unwrap();
        assert_eq!(first.waiting.len(), MAX_CONCURRENT_DOWN);

        // ATT-165: the first file holds each place, and its share falls only
        // as its commands end.
        let mut second = Download::new(&descriptor, &pool, &mut rng)
            .unwrap()
            .with_budget(&budget);
        second.tick(&mut node, &mut rng).unwrap();
        assert!(second.waiting.is_empty());
        assert_eq!(budget.held.load(Ordering::Relaxed), MAX_CONCURRENT_DOWN);
    }

    #[test]
    fn a_download_that_ends_gives_its_places_back() {
        let budget = Arc::new(DownloadBudget::default());
        let pool = [relay(1), relay(2), relay(3)];
        let (descriptor, ..) = fetchable(4);
        let mut node = silent_node();
        let mut rng = Rng(13);

        let mut first = Download::new(&descriptor, &pool, &mut rng)
            .unwrap()
            .with_budget(&budget);
        first.tick(&mut node, &mut rng).unwrap();
        assert_eq!(budget.held.load(Ordering::Relaxed), 4);
        assert_eq!(budget.share(), MAX_CONCURRENT_DOWN);

        let second = Download::new(&descriptor, &pool, &mut rng)
            .unwrap()
            .with_budget(&budget);
        assert_eq!(budget.share(), MAX_CONCURRENT_DOWN / 2);

        drop(first);
        drop(second);
        assert_eq!(budget.held.load(Ordering::Relaxed), 0);
        assert_eq!(budget.open.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_late_cput_asks_the_proof_again_only_at_a_relay_of_the_draw() {
        let pool = [relay(1), relay(2), relay(3), relay(4)];
        let mut node = silent_node();
        let mut rng = Rng(9);

        for is_missing in [false, true] {
            let mut upload = Upload::new(&[5u8; 100], Shape::default(), &pool, &mut rng).unwrap();

            // The first relay holds the chunk, and the third relay holds no
            // copy yet.
            let chunk = &mut upload.chunks[0];
            chunk.is_started = true;
            chunk.is_noted = true;
            chunk.tokens = alloc::vec![Some([9; 32]); 3];
            chunk.unverified = alloc::vec![(2, VERIFY_ATTEMPTS)];
            let third = chunk.relays[2];
            let step = if is_missing {
                Step::PutMissing(2)
            } else {
                Step::PutFresh(2)
            };
            upload.send(&mut node, 0, step, &mut rng).unwrap();

            for _ in 0..STEP_TIMEOUT_TICKS {
                upload.tick(&mut node, &mut rng).unwrap();
            }

            let waits: Vec<Step> = upload.waiting.values().map(|(_, step, _)| *step).collect();
            let noted = upload.take_started();
            if is_missing {
                // ATT-203: the relay of the draw holds its registration, and
                // its proof goes again.
                assert_eq!(upload.chunks[0].relays[2], third);
                assert!(waits.contains(&Step::Verify(2)));
                assert!(noted.is_empty());
            } else {
                // ATT-118: a fresh relay that gave no answer leaves, and
                // another one takes its place. The caller gets that relay.
                let fresh = upload.chunks[0].relays[2];
                assert_ne!(fresh, third);
                assert!(waits.contains(&Step::RegisterFresh(2)));
                assert!(!waits.contains(&Step::Verify(2)));
                assert_eq!(noted.len(), 1);
                assert!(noted[0].relays.contains(&fresh));
            }
        }
    }

    #[test]
    fn the_first_ask_for_a_proof_waits_one_whole_turn() {
        let pool = [relay(1), relay(2), relay(3)];
        let mut node = silent_node();
        let mut rng = Rng(13);
        let mut upload = Upload::new(&[5u8; 100], Shape::default(), &pool, &mut rng).unwrap();
        upload.proofs_new.push((0, 1));
        assert!(upload.has_proofs());

        // The turn that finds a new copy sends nothing.
        upload.ask_proofs(&mut node, &mut rng).unwrap();
        assert!(upload.waiting.is_empty());

        // The next turn sends the ask.
        upload.ask_proofs(&mut node, &mut rng).unwrap();
        let steps: Vec<Step> = upload.waiting.values().map(|(_, step, _)| *step).collect();
        assert!(steps == [Step::Verify(1)]);
        assert!(!upload.has_proofs());
    }

    /// A book with a live challenge of each relay of `pool`.
    fn book_of(pool: &[AttachmentRelay], now: u64) -> crate::abuse::pow::ChallengeBook {
        use crate::abuse::pow::{ChallengeBook, PowChallenge};
        use umbra_crypto::sign::SigningKey;

        let key = SigningKey::from_seed(Secret::new([1; 32]));
        let mut book = ChallengeBook::default();
        for relay in pool {
            let mut challenge = PowChallenge {
                verifier_id: relay.relay_id,
                seed: [3; 32],
                effort: 0,
                issued_at: now,
                signature: Vec::new(),
            };
            challenge.sign(&key, &mut Rng(2)).unwrap();
            book.take(challenge, &key.verifying_key(), now).unwrap();
        }

        book
    }

    #[test]
    fn the_clock_of_a_registration_starts_at_its_release() {
        use crate::abuse::{pow::PowSolution, POW_CHUNK_FLOOR};

        let pool = [relay(1), relay(2), relay(3)];
        let mut node = silent_node();
        let mut rng = Rng(11);
        node.set_challenges(book_of(&pool, 1_000), 1_000);
        let mut upload = Upload::new(&[5u8; 100], Shape::default(), &pool, &mut rng).unwrap();
        let name = upload.admission_name();
        node.chunk_admissions().solve_apart(name);

        // ABU-107: each registration waits, and nothing solves on the node.
        upload.tick(&mut node, &mut rng).unwrap();
        assert_eq!(node.unsolved_of(name).len(), 3);

        // A slow solve costs no repair.
        for _ in 0..2 * STEP_TIMEOUT_TICKS {
            upload.tick(&mut node, &mut rng).unwrap();
        }
        assert_eq!(upload.chunks[0].repairs, 0);

        // A solution frees the registration of its relay alone, and the
        // clock of that step starts.
        let first = upload.chunks[0].relays[0];
        let solution = PowSolution::solve(&first, &[3; 32], POW_CHUNK_FLOOR, &mut rng).unwrap();
        node.chunk_admissions().stock(name, first, solution);
        node.release_unsolved(name, &mut rng).unwrap();
        assert_eq!(node.unsolved_of(name).len(), 2);
        for _ in 1..STEP_TIMEOUT_TICKS {
            upload.tick(&mut node, &mut rng).unwrap();
        }
        assert_eq!(upload.chunks[0].repairs, 0);
        upload.tick(&mut node, &mut rng).unwrap();
        assert_eq!(upload.chunks[0].repairs, 1);

        // The bound of ATT-190 ends an upload whose released step gets no
        // answer.
        let mut ended = Ok(());
        for _ in 0..(u32::from(CHUNK_REPAIRS_MAX) + 1) * STEP_TIMEOUT_TICKS {
            ended = upload.tick(&mut node, &mut rng);
            if ended.is_err() {
                break;
            }
        }
        assert!(ended.is_err());
    }

    #[test]
    fn a_new_start_drops_each_registration_that_waits() {
        let pool = [relay(1), relay(2), relay(3)];
        let mut node = silent_node();
        let mut rng = Rng(14);
        node.set_challenges(book_of(&pool, 1_000), 1_000);
        let mut upload = Upload::new(&[5u8; 100], Shape::default(), &pool, &mut rng).unwrap();
        let name = upload.admission_name();
        node.chunk_admissions().solve_apart(name);
        upload.tick(&mut node, &mut rng).unwrap();

        // The relay of the failed step takes no `CDEL`, and its registration
        // still waits.
        upload
            .restart(&mut node, 0, None, Some(0), &mut rng)
            .unwrap();

        // Only the registrations of the new start wait.
        let waits = node.unsolved_of(name);
        assert_eq!(waits.len(), 3);
        assert!(waits.values().all(|count| *count == 1));
    }

    #[test]
    fn the_end_of_an_upload_holds_back_its_commands_and_no_erase() {
        use crate::abuse::{pow::PowSolution, POW_CHUNK_FLOOR};

        let pool = [relay(1), relay(2), relay(3)];
        let mut node = silent_node();
        let mut rng = Rng(15);
        node.set_challenges(book_of(&pool, 1_000), 1_000);
        let mut upload = Upload::new(&[5u8; 100], Shape::default(), &pool, &mut rng).unwrap();
        let name = upload.admission_name();
        node.chunk_admissions().solve_apart(name);
        upload.tick(&mut node, &mut rng).unwrap();

        // A registration waits for its circuit, and so does a `CDEL`.
        let first = upload.chunks[0].relays[0];
        let solution = PowSolution::solve(&first, &[3; 32], POW_CHUNK_FLOOR, &mut rng).unwrap();
        node.chunk_admissions().stock(name, first, solution);
        node.release_unsolved(name, &mut rng).unwrap();
        erase(&mut node, first, [9; 32], [8; 32], &mut rng);
        assert_eq!(node.held_chunk_uploads().len(), 2);

        node.end_upload(name);

        let held = node.held_chunk_uploads();
        assert_eq!(held.len(), 1);
        assert!(!held.contains(&name));
    }

    #[test]
    fn a_stop_of_the_solves_frees_each_registration() {
        let pool = [relay(1), relay(2), relay(3)];
        let mut node = silent_node();
        let mut rng = Rng(12);
        node.set_challenges(book_of(&pool, 1_000), 1_000);
        let mut upload = Upload::new(&[5u8; 100], Shape::default(), &pool, &mut rng).unwrap();
        let name = upload.admission_name();
        node.chunk_admissions().solve_apart(name);
        upload.tick(&mut node, &mut rng).unwrap();

        // The upload goes on with a solve at each send.
        node.chunk_admissions().end_apart(name);
        node.release_unsolved(name, &mut rng).unwrap();

        assert!(node.unsolved_of(name).is_empty());
    }
}
