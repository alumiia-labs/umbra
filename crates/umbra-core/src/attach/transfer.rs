//! The transfer of one file over the chunk commands of a transfer node
//! (Part 13 §13.4.1, §13.8): an upload that places each chunk at `REPLICAS`
//! relays, and a download that reads each chunk from one of them.
//!
//! The two drivers read no clock and draw each random value from the caller.
//! They handle a descriptor of level `0x00`, thus a file of at most
//! `MAX_DESCRIPTOR_REFS` chunks. The manifest level of §13.3.4 is not built
//! here yet.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::{rand_core::CryptoRng, secret::Secret, x25519::StaticSecret};
use umbra_wire::descriptor::{ChunkRef, FileDescriptor, Level};

use super::{
    place::{fetch_order, resolve_hint, AttachmentRelay, HoldOffs},
    seal::{read_secret, seal_file, Assembler, SealedFile},
    upload::{sample_positions, ChunkUpload},
    verify_sample, MAX_CONCURRENT_DOWN, MAX_CONCURRENT_UP, MAX_DESCRIPTOR_REFS, REPLICAS,
};
use crate::{
    session::node::{ChunkJob, ChunkOutcome, ClientNode},
    Error,
};

/// How many times an upload asks a replica for its proof again. The copy
/// of a `CREP` travels on a connection of its own, thus a `CVFY` can arrive
/// before it.
pub const VERIFY_ATTEMPTS: u8 = 6;

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
}

struct ChunkState {
    upload: ChunkUpload,
    cred: [u8; 32],
    relays: Vec<[u8; 32]>,
    tokens: Vec<Option<[u8; 32]>>,
    /// The replicas that still owe a proof, with the attempts that remain.
    unverified: Vec<(usize, u8)>,
    is_started: bool,
    is_done: bool,
}

/// The upload of one file.
pub struct Upload {
    sealed: SealedFile,
    file_key: Secret<32>,
    file_nonce: [u8; 24],
    shape: Shape,
    chunks: Vec<ChunkState>,
    waiting: BTreeMap<u64, (usize, Step)>,
    /// The proofs that a later tick asks for again.
    retries: Vec<(usize, usize)>,
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
        let file_key = Secret::new(random_bytes(rng));
        let file_nonce = random_bytes(rng);
        let sealed = seal_file(&file_key, &file_nonce, plain)?;
        if sealed.chunks.len() > MAX_DESCRIPTOR_REFS {
            return Err(Error::Malformed);
        }
        let mut chunks = Vec::with_capacity(sealed.chunks.len());
        for _ in &sealed.chunks {
            let picked = pick_relays(relays, rng)?;
            let cred: [u8; 32] = random_bytes(rng);
            chunks.push(ChunkState {
                // ATT-034, ATT-055: each value from the CSPRNG, one for each
                // chunk.
                upload: ChunkUpload::new(random_bytes(rng), StaticSecret::from(cred)),
                cred,
                tokens: alloc::vec![None; picked.len()],
                relays: picked,
                unverified: Vec::new(),
                is_started: false,
                is_done: false,
            });
        }
        Ok(Upload {
            sealed,
            file_key,
            file_nonce,
            shape,
            chunks,
            waiting: BTreeMap::new(),
            retries: Vec::new(),
        })
    }

    fn in_flight(&self) -> usize {
        self.chunks
            .iter()
            .filter(|chunk| chunk.is_started && !chunk.is_done)
            .count()
    }

    fn done(&self) -> u32 {
        let count = self.chunks.iter().filter(|chunk| chunk.is_done).count();
        u32::try_from(count).unwrap_or(u32::MAX)
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
            Step::Register(at) => {
                let index = u32::try_from(index).map_err(|_| Error::Malformed)?;
                let read = read_secret(&self.file_key, index);
                let job = ChunkJob::Register {
                    cred,
                    read_pk: *umbra_crypto::x25519::PublicKey::from(&read).as_bytes(),
                    is_backup: false,
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
        self.waiting.insert(handle, (index, step));
        Ok(())
    }

    /// Starts each chunk that has room under `MAX_CONCURRENT_UP`, and asks
    /// again for each proof that a replica did not hold at the last answer.
    /// The caller calls it at the start and at each tick of its clock.
    pub fn tick<R: CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        for (index, at) in core::mem::take(&mut self.retries) {
            self.send(node, index, Step::Verify(at), rng)?;
        }
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
        let total = u32::try_from(self.chunks.len()).unwrap_or(u32::MAX);
        let Some((index, step)) = self.waiting.remove(&handle) else {
            return Ok(Progress::Running(self.done(), total));
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
            // The copy can be on its way still. A wrong proof is final.
            (Step::Verify(at), ChunkOutcome::Refused(_)) => {
                let entry = chunk
                    .unverified
                    .iter_mut()
                    .find(|(of, _)| *of == at)
                    .ok_or(Error::Malformed)?;
                entry.1 = entry.1.saturating_sub(1);
                if entry.1 == 0 {
                    return Err(Error::Unverified);
                }
                self.retries.push((index, at));
            }
            _ => return Err(Error::Unverified),
        }
        if self.chunks.iter().all(|chunk| chunk.is_done) {
            return self.finish().map(Progress::Done);
        }
        self.tick(node, rng)?;
        Ok(Progress::Running(self.done(), total))
    }

    fn finish(&mut self) -> Result<Uploaded, Error> {
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
        Ok(Uploaded {
            descriptor: FileDescriptor {
                level: Level::Data,
                file_key: Secret::new(*self.file_key.expose()),
                file_nonce: self.file_nonce,
                commit: self.sealed.commit,
                digest: self.sealed.digest,
                media_seconds: self.shape.media_seconds,
                padded_size: self.sealed.padded_size,
                mime_class: self.shape.mime_class,
                pixel_w: self.shape.pixel_w,
                pixel_h: self.shape.pixel_h,
                refs,
            },
            credentials,
        })
    }
}

/// `REPLICAS` relays of different operators, in a random order. A relay set
/// with fewer operators gives no upload, because the redundancy is
/// mandatory (§13.4).
fn pick_relays<R: CryptoRng + ?Sized>(
    relays: &[AttachmentRelay],
    rng: &mut R,
) -> Result<Vec<[u8; 32]>, Error> {
    let mut pool: Vec<AttachmentRelay> = relays.to_vec();
    let mut picked: Vec<AttachmentRelay> = Vec::with_capacity(REPLICAS);
    while picked.len() < REPLICAS && !pool.is_empty() {
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
    if picked.len() < REPLICAS {
        return Err(Error::NoPath);
    }
    Ok(picked.into_iter().map(|relay| relay.relay_id).collect())
}

struct Wanted {
    /// The replicas that this fetch did not ask yet, the next one last.
    order: Vec<[u8; 32]>,
    bytes: Option<Vec<u8>>,
    is_asked: bool,
}

/// The download of one file of level `0x00`.
pub struct Download {
    /// The open file, until its last chunk.
    assembler: Option<Assembler>,
    file_key: Secret<32>,
    chunk_ids: Vec<[u8; 32]>,
    wanted: Vec<Wanted>,
    waiting: BTreeMap<u64, usize>,
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
        if descriptor.level != Level::Data {
            return Err(Error::Malformed);
        }
        let assembler = Assembler::for_data(descriptor)?;
        let hold_offs = HoldOffs::default();
        let mut wanted = Vec::with_capacity(descriptor.refs.len());
        for chunk_ref in &descriptor.refs {
            let mut replicas = alloc::vec![chunk_ref.relay_id];
            for hint in &chunk_ref.replicas {
                let ids = relays.iter().map(|relay| relay.relay_id);
                if let Ok(relay) = resolve_hint(hint, ids) {
                    replicas.push(relay);
                }
            }
            // ATT-019: a random order across the replicas.
            let mut order = fetch_order(
                &chunk_ref.chunk_id,
                &replicas,
                &hold_offs,
                0,
                &mut |bound| random_below(rng, bound),
            );
            order.reverse();
            wanted.push(Wanted {
                order,
                bytes: None,
                is_asked: false,
            });
        }
        Ok(Download {
            assembler: Some(assembler),
            file_key: Secret::new(*descriptor.file_key.expose()),
            chunk_ids: descriptor.refs.iter().map(|r| r.chunk_id).collect(),
            wanted,
            waiting: BTreeMap::new(),
        })
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
            &self.file_key,
            u32::try_from(index).map_err(|_| Error::Malformed)?,
        );
        let handle = node.chunk(relay, chunk_id, ChunkJob::Fetch { read }, rng)?;
        self.waiting.insert(handle, index);
        Ok(())
    }

    /// Asks for each chunk that has room under `MAX_CONCURRENT_DOWN`.
    pub fn tick<R: CryptoRng + ?Sized>(
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
            return assembler.finish().map(Progress::Done);
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
        let Some(index) = self.waiting.remove(&handle) else {
            return Ok(false);
        };
        match outcome {
            ChunkOutcome::Fetched(bytes) => {
                self.wanted.get_mut(index).ok_or(Error::Malformed)?.bytes = Some(bytes);
            }
            // ATT-019: the next replica.
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
        self.tick(node, rng)?;
        Ok(is_complete)
    }
}
