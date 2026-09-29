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
    upload::{sample_positions, ChunkUpload},
    verify_sample, MAX_CONCURRENT_DOWN, MAX_CONCURRENT_UP, MAX_DATA_CHUNKS, REPLICAS,
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

fn random_below<R: CryptoRng + ?Sized>(rng: &mut R, bound: u32) -> u32 {
    let mut bytes = [0u8; 4];
    rng.fill_bytes(&mut bytes);
    u32::from_be_bytes(bytes) % bound.max(1)
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
    retries: Vec<(usize, usize)>,
    ticks: u32,
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
            ticks: 0,
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

    fn in_flight(&self) -> usize {
        self.chunks
            .iter()
            .filter(|chunk| chunk.is_started && !chunk.is_done)
            .count()
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
        let handle = node.chunk(relay, chunk_id, job, rng)?;
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
                    .retain(|(of, place)| (*of, *place) != (index, at));
                self.send(node, index, Step::RegisterFresh(at), rng)
            }
            Step::Register(_) | Step::Put | Step::Replicate => {
                let bad = match step {
                    Step::Register(at) => chunk.relays.get(at).copied(),
                    _ => chunk.relays.first().copied(),
                };
                let mut failed = core::mem::take(&mut chunk.failed);
                failed.extend(bad);
                let held: Vec<[u8; 32]> = chunk
                    .relays
                    .iter()
                    .zip(&chunk.tokens)
                    .filter(|(_, token)| token.is_some())
                    .map(|(relay, _)| *relay)
                    .collect();
                let cred = chunk.cred;
                for relay in held {
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
                self.repair(node, index, step, rng)?;
            }
        }
        for (index, at) in core::mem::take(&mut self.retries) {
            self.send(node, index, Step::Verify(at), rng)?;
        }
        self.fill(node, rng)
    }

    /// Starts each chunk that has room under `MAX_CONCURRENT_UP`.
    fn fill<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        while self.in_flight() < MAX_CONCURRENT_UP {
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
        let Some((index, step, _)) = self.waiting.remove(&handle) else {
            let (done, total) = self.progress();
            return Ok(Progress::Running(done, total));
        };
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
                    self.send(node, index, Step::Put, rng)?;
                }
            }
            (Step::Put, ChunkOutcome::Stored) => {
                let replicas = chunk.relays.len();
                chunk.upload.put_done(replicas)?;
                self.send(node, index, Step::Replicate, rng)?;
            }
            (Step::Replicate, ChunkOutcome::Replicated) => {
                // ATT-113, ATT-120: a random sample of the copies proves
                // itself. The relay of the `CPUT` gave its proof already.
                let copies = u32::try_from(chunk.relays.len().saturating_sub(1))
                    .map_err(|_| Error::Malformed)?;
                let sample = verify_sample(usize::try_from(copies).unwrap_or(0));
                let picked =
                    sample_positions(copies, sample, &mut |bound| random_below(rng, bound));
                chunk.unverified = picked
                    .into_iter()
                    .map(|copy| {
                        (
                            usize::try_from(copy).unwrap_or(0).saturating_add(1),
                            VERIFY_ATTEMPTS,
                        )
                    })
                    .collect();
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
                if entry.1 == 0 {
                    self.repair(node, index, step, rng)?;
                } else {
                    self.retries.push((index, at));
                }
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
            is_done: false,
        })
    }
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
    /// Each `CGET` that waits for its answer: the chunk, and the tick of
    /// its send.
    waiting: BTreeMap<u64, (usize, u32)>,
    /// The ticks of the caller since the start.
    ticks: u32,
    /// The data phase of a file of level `0x01`, while its manifest comes.
    then: Option<DataPlan>,
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
    rng: &mut R,
) -> Vec<Wanted> {
    let hold_offs = HoldOffs::default();
    chunks
        .iter()
        .map(|chunk| {
            let mut replicas = chunk.relay_ids.clone();
            for hint in &chunk.hints {
                let ids = relays.iter().map(|relay| relay.relay_id);
                if let Ok(relay) = resolve_hint(hint, ids) {
                    if !replicas.contains(&relay) {
                        replicas.push(relay);
                    }
                }
            }
            let mut order = fetch_order(&chunk.chunk_id, &replicas, &hold_offs, 0, &mut |bound| {
                random_below(rng, bound)
            });
            order.reverse();
            Wanted {
                order,
                bytes: None,
                is_asked: false,
                answers: 0,
                refusals: 0,
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
                // descriptor holds.
                if data_chunks <= class.descriptor_refs
                    || manifest_chunks != manifest::manifest_chunks(data_chunks)
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
            wanted: plan(&chunks, relays, rng),
            waiting: BTreeMap::new(),
            ticks: 0,
            then,
        })
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
        self.wanted = plan(&chunks, &then.relays, rng);
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
        self.waiting.insert(handle, (index, self.ticks));
        Ok(())
    }

    /// Whether the answer with this handle belongs to this download.
    pub fn owns(&self, handle: u64) -> bool {
        self.waiting.contains_key(&handle)
    }

    /// Whether each replica of one chunk answered that it holds no such
    /// chunk (Part 12 `ATT-052`). No new attempt finds that chunk, thus
    /// the file is lost. A download that failed for another cause, as a
    /// circuit that fell, gives false.
    pub fn is_gone(&self) -> bool {
        self.wanted.iter().any(|wanted| {
            wanted.order.is_empty()
                && wanted.bytes.is_none()
                && wanted.refusals > 0
                && wanted.refusals == wanted.answers
        })
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
            .filter(|(_, (_, sent))| self.ticks.saturating_sub(*sent) >= STEP_TIMEOUT_TICKS)
            .map(|(handle, (index, _))| (*handle, *index))
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
        let Some((index, _)) = self.waiting.remove(&handle) else {
            return Ok(false);
        };
        let wanted = self.wanted.get_mut(index).ok_or(Error::Malformed)?;
        wanted.answers = wanted.answers.saturating_add(1);
        match outcome {
            ChunkOutcome::Fetched(bytes) => wanted.bytes = Some(bytes),
            // ATT-019: the next replica. WIR-317 gives one reason to an
            // unknown chunk, and the read secret of a descriptor is right.
            ChunkOutcome::Refused(Reject::Rejected) => {
                wanted.refusals = wanted.refusals.saturating_add(1);
                self.ask(node, index, rng)?;
            }
            _ => self.ask(node, index, rng)?,
        }
        // The chunks open in their order.
        let assembler = self.assembler.as_mut().ok_or(Error::Stale)?;
        loop {
            let next = usize::try_from(assembler.next_index()).map_err(|_| Error::Malformed)?;
            let Some(bytes) = self.wanted.get_mut(next).and_then(|w| w.bytes.take()) else {
                break;
            };
            assembler.accept(&bytes)?;
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
    /// The ticks of the caller since the start.
    ticks: u32,
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
            ticks: 0,
        })
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
