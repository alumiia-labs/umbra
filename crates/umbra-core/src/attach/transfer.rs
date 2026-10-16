//! The transfer of one file over the chunk commands of a transfer node
//! (Part 12 §12.4.1, §12.8): an upload that places each chunk at `REPLICAS`
//! relays, and a download that reads each chunk from one of them.
//!
//! The two drivers read no clock and draw each random value from the caller.
//! A file above `MAX_DESCRIPTOR_REFS` chunks takes the manifest level of
//! §12.3.4: the upload places the data chunks, then the manifest of their
//! refs as a file of its own under `K_manifest`, and the download reads the
//! manifest before the data.

use alloc::{collections::BTreeMap, vec::Vec};

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
/// The `CPUT` window at the start of an upload (`ATT-198`). The clock of a
/// step starts when the command enters the link, thus a slow uplink with a
/// wide window runs each step into `STEP_TIMEOUT_TICKS`.
pub const UP_WINDOW_START: usize = 32;
/// The window never closes below this count.
pub const UP_WINDOW_MIN: usize = 8;
/// A `CPUT` with its answer inside this many ticks opens the window.
pub const UP_WINDOW_FAST_TICKS: u32 = 8;
/// A `CPUT` with its answer after this many ticks closes the window.
pub const UP_WINDOW_SLOW_TICKS: u32 = 15;

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
    /// The proofs that a later tick asks for again.
    /// The proofs to ask for again: the chunk, the replica, and the tick.
    retries: Vec<(usize, usize, u32)>,
    /// The `CPUT` that this upload holds in flight at the most (`ATT-198`).
    window: usize,
    ticks: u32,
    /// The name of this upload at the node. It is a random value that leaves
    /// the device in no form. The solution of a registration serves one
    /// upload alone (Part 13 `ABU-108`).
    admissions: u64,
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
            window: UP_WINDOW_START,
            ticks: 0,
            admissions: u64::from_be_bytes(random_bytes(rng)),
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

    /// Each `CPUT` that has no answer yet, a `CPUT` of a repair among them
    /// (`ATT-164`). A chunk past its `CPUT` holds no place, thus its `CREP`
    /// and its proofs travel while the next `CPUT` is in flight (`ATT-166`,
    /// `ATT-178`).
    fn in_flight(&self) -> usize {
        self.waiting
            .values()
            .filter(|(_, step, _)| matches!(step, Step::Put | Step::PutFresh(_)))
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
        self.window
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
            Step::PutFresh(at) => {
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
    /// Before it the chunk starts again at a new draw, under a new
    /// identifier and a new credential (`ATT-036`).
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
        let erase = |node: &mut ClientNode, relay: [u8; 32], cred: [u8; 32], rng: &mut R| {
            // The relay can hold a registration or a bad copy. No answer is
            // needed, and its life ends at `CHUNK_TTL` without this.
            let job = ChunkJob::Erase {
                cred: StaticSecret::from(cred),
            };
            let _ = node.chunk(relay, chunk_id, job, rng);
        };
        match step {
            Step::Verify(at) | Step::RegisterFresh(at) | Step::PutFresh(at) => {
                let bad = *chunk.relays.get(at).ok_or(Error::Malformed)?;
                // ATT-119: a replica that failed its proof is a link fault.
                if matches!(step, Step::Verify(_)) {
                    node.report_relay(&bad);
                }
                chunk.failed.push(bad);
                let others: Vec<[u8; 32]> = chunk
                    .relays
                    .iter()
                    .enumerate()
                    .filter(|(place, _)| *place != at)
                    .map(|(_, relay)| *relay)
                    .collect();
                let fresh = fresh_relay(&self.pool, &others, &chunk.failed, rng)?;
                erase(node, bad, chunk.cred, rng);
                *chunk.relays.get_mut(at).ok_or(Error::Malformed)? = fresh;
                *chunk.tokens.get_mut(at).ok_or(Error::Malformed)? = None;
                if !chunk.unverified.iter().any(|(of, _)| *of == at) {
                    chunk.unverified.push((at, VERIFY_ATTEMPTS));
                }
                chunk.is_done = false;
                self.retries
                    .retain(|(of, place, _)| (*of, *place) != (index, at));
                self.send(node, index, Step::RegisterFresh(at), rng)
            }
            Step::Register(_) | Step::Put | Step::Replicate => {
                let bad = match step {
                    Step::Register(at) => chunk.relays.get(at).copied(),
                    _ => chunk.relays.first().copied(),
                };
                let mut failed = core::mem::take(&mut chunk.failed);
                failed.extend(bad);
                let refused = match step {
                    Step::Register(at) => Some(at),
                    _ => None,
                };
                let cred = chunk.cred;
                for relay in chunk.erase_targets(refused) {
                    erase(node, relay, cred, rng);
                }
                let repairs = chunk.repairs;
                // The answers of the old start name no step of this upload.
                self.waiting.retain(|_, (of, _, _)| *of != index);
                let mut next =
                    ChunkState::draw(&self.pool, failed, repairs, self.class.replicas, rng)?;
                next.is_started = true;
                let replicas = next.relays.len();
                *self.chunks.get_mut(index).ok_or(Error::Malformed)? = next;
                for at in 0..replicas {
                    self.send(node, index, Step::Register(at), rng)?;
                }
                Ok(())
            }
        }
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
        let late: Vec<(u64, usize, Step)> = self
            .waiting
            .iter()
            .filter(|(_, (_, _, sent))| self.ticks.saturating_sub(*sent) >= STEP_TIMEOUT_TICKS)
            .map(|(handle, (index, step, _))| (*handle, *index, *step))
            .collect();
        for (handle, index, step) in late {
            // A start that took the chunk since removed the step already.
            if self.waiting.remove(&handle).is_some() {
                if matches!(step, Step::Put) {
                    self.window = (self.window / 2).max(UP_WINDOW_MIN);
                }
                self.repair(node, index, step, rng)?;
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
        self.fill(node, rng)
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
        while self.in_flight() < self.window {
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
            let age = self.ticks.saturating_sub(sent);
            if age <= UP_WINDOW_FAST_TICKS {
                self.window = self.window.saturating_add(2).min(MAX_CONCURRENT_UP);
            } else if age >= UP_WINDOW_SLOW_TICKS {
                self.window = self.window.saturating_sub(4).max(UP_WINDOW_MIN);
            }
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
                let due: Vec<usize> = chunk.unverified.iter().map(|(at, _)| *at).collect();
                for at in due {
                    self.send(node, index, Step::Verify(at), rng)?;
                }
            }
            (Step::Verify(at), ChunkOutcome::Verified) => {
                chunk.unverified.retain(|(of, _)| *of != at);
                chunk.is_done = chunk.unverified.is_empty();
            }
            // The copy can be on its way still, thus a refusal gets some
            // more attempts. A wrong proof gets none.
            (Step::Verify(at), ChunkOutcome::Refused(_)) => {
                let entry = chunk
                    .unverified
                    .iter_mut()
                    .find(|(of, _)| *of == at)
                    .ok_or(Error::Malformed)?;
                entry.1 = entry.1.saturating_sub(1);
                let left = entry.1;
                if left == 0 {
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
                        self.repair(node, index, step, rng)?;
                    } else {
                        // ATT-197: no other relay can take the copy, and
                        // this relay holds a registration. Thus the bytes
                        // go to it from this device.
                        chunk.repairs = chunk.repairs.saturating_add(1);
                        if chunk.repairs > CHUNK_REPAIRS_MAX {
                            return Err(Error::Unverified);
                        }
                        entry.1 = VERIFY_ATTEMPTS;
                        self.send(node, index, Step::PutFresh(at), rng)?;
                    }
                } else {
                    // ATT-190: each wait is two times the one before, thus
                    // the asks give a copy about 30 ticks to arrive.
                    let asked = u32::from(VERIFY_ATTEMPTS.saturating_sub(left));
                    let wait = 1u32 << asked.saturating_sub(1).min(8);
                    self.retries
                        .push((index, at, self.ticks.saturating_add(wait)));
                }
            }
            // The copy of the relay before came while the bytes of this
            // device were on their way: the relay holds the chunk, and its
            // proof says so.
            (Step::PutFresh(at), ChunkOutcome::Refused(_))
                if chunk.tokens.get(at).copied().flatten().is_some()
                    && chunk
                        .upload
                        .relays()
                        .any(|relay| chunk.relays.get(at) == Some(relay)) =>
            {
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
            (Step::PutFresh(at), ChunkOutcome::Stored) => {
                chunk.unverified.retain(|(of, _)| *of != at);
                chunk.is_done = chunk.unverified.is_empty();
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
            is_registered: false,
            is_put: false,
            is_stored: false,
            is_done: false,
        })
    }
}

/// One relay for the place of a replica that failed: no relay of `failed`,
/// no relay of `others`, and no operator of `others` (`ATT-017`).
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

/// `replicas` relays of different operators, in a random order. A relay
/// set with fewer operators gives no upload, because the redundancy is
/// mandatory (§12.4).
fn pick_relays<R: CryptoRng + ?Sized>(
    relays: &[AttachmentRelay],
    failed: &[[u8; 32]],
    replicas: usize,
    rng: &mut R,
) -> Result<Vec<[u8; 32]>, Error> {
    let mut pool: Vec<AttachmentRelay> = relays
        .iter()
        .filter(|relay| !failed.contains(&relay.relay_id))
        .copied()
        .collect();
    let mut picked: Vec<AttachmentRelay> = Vec::with_capacity(replicas);
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
    if picked.len() < replicas {
        return Err(Error::NoPath);
    }
    Ok(picked.into_iter().map(|relay| relay.relay_id).collect())
}

struct Wanted {
    /// The replicas that this fetch did not ask yet, the next one last.
    order: Vec<[u8; 32]>,
    bytes: Option<Vec<u8>>,
    is_asked: bool,
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
    /// Each `CGET` that waits for its answer: the chunk, the tick of its
    /// send, and the relay.
    waiting: BTreeMap<u64, (usize, u32, [u8; 32])>,
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
                is_asked: false,
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
            waiting: BTreeMap::new(),
            ticks: 0,
            then,
            hold_offs: HoldOffs::default(),
            now: 0,
            refused: Vec::new(),
        })
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
        wanted.is_asked = true;
        let chunk_id = *self.chunk_ids.get(index).ok_or(Error::Malformed)?;
        let read = read_secret(
            &self.chunk_key,
            u32::try_from(index).map_err(|_| Error::Malformed)?,
        );
        let handle = node.chunk(relay, chunk_id, ChunkJob::Fetch { read }, rng)?;
        self.waiting.insert(handle, (index, self.ticks, relay));
        Ok(())
    }

    /// Whether the answer with this handle belongs to this download.
    pub fn owns(&self, handle: u64) -> bool {
        self.waiting.contains_key(&handle)
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

    /// Moves the clock of the download one tick: a `CGET` past
    /// `STEP_TIMEOUT_TICKS` goes to the next replica (`ATT-019`), and each
    /// chunk that has room is asked for. The caller calls it at the start
    /// and at each tick of its clock, and an answer moves no clock. A lost
    /// answer thus holds no download until its circuit ends.
    pub fn tick<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.ticks = self.ticks.saturating_add(1);
        let late: Vec<(u64, usize)> = self
            .waiting
            .iter()
            .filter(|(_, (_, sent, _))| self.ticks.saturating_sub(*sent) >= STEP_TIMEOUT_TICKS)
            .map(|(handle, (index, _, _))| (*handle, *index))
            .collect();
        for (handle, index) in late {
            self.waiting.remove(&handle);
            // No answer is no statement that the relay lacks the chunk.
            let wanted = self.wanted.get_mut(index).ok_or(Error::Malformed)?;
            wanted.answers = wanted.answers.saturating_add(1);
            self.ask(node, index, rng)?;
        }
        self.fill(node, rng)
    }

    /// Asks for each chunk that has room under `MAX_CONCURRENT_DOWN`.
    fn fill<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        while self.waiting.len() < MAX_CONCURRENT_DOWN {
            let Some(index) = self.wanted.iter().position(|wanted| !wanted.is_asked) else {
                break;
            };
            self.ask(node, index, rng)?;
        }
        Ok(())
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
        let Some((index, _, relay)) = self.waiting.remove(&handle) else {
            return Ok(false);
        };
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
        wanted.answers = wanted.answers.saturating_add(1);
        match outcome {
            ChunkOutcome::Fetched(_) if opened.is_some() => wanted.bytes = opened,
            ChunkOutcome::Fetched(_) => {
                wanted.refusals = wanted.refusals.saturating_add(1);
                self.ask(node, index, rng)?;
            }
            // ATT-019: the next replica. WIR-317 gives one reason to an
            // unknown chunk, and the read secret of a descriptor is right.
            ChunkOutcome::Refused(Reject::Rejected) => {
                wanted.refusals = wanted.refusals.saturating_add(1);
                self.ask(node, index, rng)?;
            }
            // ATT-173, ATT-174: the next replica, and this relay takes no
            // same `CGET` inside the hold.
            ChunkOutcome::Refused(Reject::Busy | Reject::Limit) => {
                let chunk_id = *self.chunk_ids.get(index).ok_or(Error::Malformed)?;
                self.refused.push((chunk_id, relay));
                self.ask(node, index, rng)?;
            }
            _ => self.ask(node, index, rng)?,
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
}
