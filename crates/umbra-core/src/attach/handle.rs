//! The write and the read of one handle-addressed chunk (Part 12 §12.4.2):
//! the backup root of Part 4 §4.7.2 and the dead-channel blob of Part 3
//! §3.2.6. The two parties hold one secret, thus the reader needs no
//! descriptor, and the placement list names the relays.
//!
//! Each driver is sans-IO in the manner of [`super::transfer`]: the runtime
//! calls `tick` once each second and passes each chunk answer to
//! `on_outcome`.

use alloc::vec::Vec;

use umbra_crypto::{secret::Secret, x25519::StaticSecret};

use super::{
    command::{ReplicaTarget, TOKEN_LEN},
    place::{placement_list, reader_probes, writer_targets, AttachmentRelay},
    transfer::{Progress, STEP_TIMEOUT_TICKS},
    CHUNK_SIZE,
};
use crate::{
    session::node::{ChunkJob, ChunkOutcome, ClientNode},
    Error,
};

/// What a question waits for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Erase,
    Register,
    Put,
    Replicate,
}

/// The write of one handle-addressed chunk to the first `BACKUP_REPLICAS`
/// relays of its placement list (`ATT-133` to `ATT-135`), after a `CDEL`
/// at each relay that can hold an earlier chunk under the same handle
/// (`ATT-138`). The result is the relays that hold the chunk.
pub struct HandleWrite {
    handle: [u8; 32],
    cred: Secret<32>,
    read_pk: [u8; 32],
    chunk: Vec<u8>,
    list: Vec<[u8; 32]>,
    failed: Vec<[u8; 32]>,
    /// The relays of the write, each with its token once it registered.
    targets: Vec<([u8; 32], Option<[u8; TOKEN_LEN]>)>,
    step: Step,
    /// Each question that waits: its handle, its relay, and its tick.
    waiting: Vec<(u64, [u8; 32], u32)>,
    ticks: u32,
    started: bool,
}

impl HandleWrite {
    /// The write of `chunk`, `CHUNK_SIZE` bytes, under `handle`. `cred` is
    /// `cred_sk` of `ATT-034`, and `read_pk` the public half of `read_sk`.
    /// With `replaces`, a `CDEL` goes first to each relay that a reader
    /// asks (`ATT-138`).
    pub fn new(
        handle: [u8; 32],
        cred: Secret<32>,
        read_pk: [u8; 32],
        chunk: Vec<u8>,
        replaces: bool,
        relays: &[AttachmentRelay],
    ) -> Result<Self, Error> {
        if chunk.len() != CHUNK_SIZE {
            return Err(Error::Malformed);
        }

        let list = placement_list(&handle, relays);
        let targets = writer_targets(&list, &[])?
            .into_iter()
            .map(|relay| (relay, None))
            .collect();

        Ok(HandleWrite {
            handle,
            cred,
            read_pk,
            chunk,
            list,
            failed: Vec::new(),
            targets,
            step: if replaces {
                Step::Erase
            } else {
                Step::Register
            },
            waiting: Vec::new(),
            ticks: 0,
            started: false,
        })
    }

    /// Whether the answer with this handle belongs to this write.
    pub fn owns(&self, handle: u64) -> bool {
        self.waiting.iter().any(|(held, _, _)| *held == handle)
    }

    fn cred(&self) -> StaticSecret {
        StaticSecret::from(*self.cred.expose())
    }

    fn ask<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        relay: [u8; 32],
        job: ChunkJob,
        rng: &mut R,
    ) -> Result<(), Error> {
        // ABU-108: the solution of a registration serves this handle
        // alone, thus the handle names the upload.
        let upload = self
            .handle
            .first_chunk::<8>()
            .map_or(0, |prefix| u64::from_be_bytes(*prefix));

        let handle = node.chunk_of(upload, relay, self.handle, job, rng)?;
        self.waiting.push((handle, relay, self.ticks));
        Ok(())
    }

    /// Sends the questions of the step, when none waits.
    fn start_step<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        match self.step {
            Step::Erase => {
                for relay in reader_probes(&self.list).to_vec() {
                    let job = ChunkJob::Erase { cred: self.cred() };
                    self.ask(node, relay, job, rng)?;
                }
            }

            Step::Register => {
                let open: Vec<[u8; 32]> = self
                    .targets
                    .iter()
                    .filter(|(_, token)| token.is_none())
                    .map(|(relay, _)| *relay)
                    .collect();
                for relay in open {
                    let job = ChunkJob::Register {
                        cred: self.cred(),
                        read_pk: self.read_pk,
                        is_backup: true,
                    };
                    self.ask(node, relay, job, rng)?;
                }
            }

            Step::Put => {
                let (relay, token) = *self.targets.first().ok_or(Error::NoPath)?;
                let job = ChunkJob::Put {
                    cred: self.cred(),
                    storage_token: token.ok_or(Error::NoPath)?,
                    chunk: self.chunk.clone(),
                };
                self.ask(node, relay, job, rng)?;
            }

            Step::Replicate => {
                let (relay, _) = *self.targets.first().ok_or(Error::NoPath)?;
                let targets = self
                    .targets
                    .iter()
                    .skip(1)
                    .map(|(relay_id, token)| {
                        Ok(ReplicaTarget {
                            relay_id: *relay_id,
                            storage_token: token.ok_or(Error::NoPath)?,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                let job = ChunkJob::Replicate {
                    cred: self.cred(),
                    targets,
                    chunk: self.chunk.clone(),
                };
                self.ask(node, relay, job, rng)?;
            }
        }

        Ok(())
    }

    /// Starts the write, and ends a question that no relay answered in
    /// `STEP_TIMEOUT_TICKS`: an erase counts as done, and a registration
    /// moves to the next relay of the list.
    pub fn tick<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.ticks = self.ticks.saturating_add(1);
        if !self.started {
            self.started = true;
            return self.start_step(node, rng);
        }

        let late: Vec<(u64, [u8; 32], u32)> = self
            .waiting
            .iter()
            .filter(|(_, _, at)| self.ticks.saturating_sub(*at) >= STEP_TIMEOUT_TICKS)
            .copied()
            .collect();

        for (handle, _, _) in late {
            self.on_outcome(
                node,
                handle,
                ChunkOutcome::Refused(umbra_queue::Reject::Busy),
                rng,
            )?;
        }

        Ok(())
    }

    /// Takes one chunk answer. The result is the relays that hold the chunk.
    pub fn on_outcome<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<Vec<[u8; 32]>>, Error> {
        let Some(at) = self.waiting.iter().position(|(held, _, _)| *held == handle) else {
            return Ok(Progress::Running(0, 1));
        };
        let (_, relay, _) = self.waiting.remove(at);

        match (self.step, outcome) {
            // An erase of a chunk that the relay does not hold is refused,
            // and it is done as well.
            (Step::Erase, _) => {}
            (Step::Register, ChunkOutcome::Registered(token)) => {
                if let Some(target) = self.targets.iter_mut().find(|(held, _)| *held == relay) {
                    target.1 = Some(token);
                }
            }

            // ATT-134: the next relay of the list takes the place.
            (Step::Register, _) => {
                self.failed.push(relay);

                let next = writer_targets(&self.list, &self.failed)?;
                let replacement = next
                    .into_iter()
                    .find(|candidate| !self.targets.iter().any(|(held, _)| held == candidate))
                    .ok_or(Error::NoPath)?;
                if let Some(target) = self.targets.iter_mut().find(|(held, _)| *held == relay) {
                    *target = (replacement, None);
                }

                // The list order puts the lowest rank first (`ATT-135`).
                let list = &self.list;
                self.targets.sort_by_key(|(held, _)| {
                    list.iter()
                        .position(|entry| entry == held)
                        .unwrap_or(usize::MAX)
                });

                let job = ChunkJob::Register {
                    cred: self.cred(),
                    read_pk: self.read_pk,
                    is_backup: true,
                };
                self.ask(node, replacement, job, rng)?;
            }

            (Step::Put, ChunkOutcome::Stored) => {}
            (Step::Replicate, ChunkOutcome::Replicated) => {}
            // A put or a copy that failed ends the write, and the caller
            // writes again later.
            _ => return Err(Error::NoPath),
        }

        if !self.waiting.is_empty() {
            return Ok(Progress::Running(0, 1));
        }

        self.step = match self.step {
            Step::Erase => Step::Register,
            Step::Register => Step::Put,
            Step::Put if self.targets.len() > 1 => Step::Replicate,
            Step::Put | Step::Replicate => {
                return Ok(Progress::Done(
                    self.targets.iter().map(|(relay, _)| *relay).collect(),
                ));
            }
        };

        self.start_step(node, rng)?;
        Ok(Progress::Running(0, 1))
    }
}

/// The read of one handle-addressed chunk: a `CGET` to each relay of the
/// placement list in list order, at most `PLACE_PROBE` of them
/// (`ATT-136`, `ATT-137`). The result is each distinct chunk that a relay
/// gave, in list order, and whether each relay answered: a relay that
/// serves bytes that do not open stops no read, and a read that no relay
/// answered is no empty handle.
pub struct HandleRead {
    handle: [u8; 32],
    read: Secret<32>,
    /// The relays that this read did not ask yet, the next one last.
    order: Vec<[u8; 32]>,
    waiting: Option<(u64, u32)>,
    ticks: u32,
    found: Vec<Vec<u8>>,
    answered: bool,
}

/// What a handle read found: each distinct chunk, and whether a relay gave
/// a definitive answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleFound {
    /// The chunks, in the order of the placement list.
    pub chunks: Vec<Vec<u8>>,
    /// Whether one relay at least answered with a chunk or with the plain
    /// refusal of a chunk it does not hold. A read of timeouts and of
    /// relays under load alone knows nothing of the handle.
    pub answered: bool,
}

impl HandleRead {
    /// The read of the chunk under `handle` with `read_sk` of `read`.
    pub fn new(handle: [u8; 32], read: Secret<32>, relays: &[AttachmentRelay]) -> Self {
        let list = placement_list(&handle, relays);
        let mut order = reader_probes(&list).to_vec();
        order.reverse();

        HandleRead {
            handle,
            read,
            order,
            waiting: None,
            ticks: 0,
            found: Vec::new(),
            answered: false,
        }
    }

    /// Whether the answer with this handle belongs to this read.
    pub fn owns(&self, handle: u64) -> bool {
        self.waiting.is_some_and(|(held, _)| held == handle)
    }

    /// Asks the next relay when no question waits, and moves past one that
    /// did not answer in `STEP_TIMEOUT_TICKS`. The result is `Done(None)`
    /// when no relay is left.
    pub fn tick<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<Progress<HandleFound>, Error> {
        self.ticks = self.ticks.saturating_add(1);
        if let Some((_, at)) = self.waiting {
            if self.ticks.saturating_sub(at) < STEP_TIMEOUT_TICKS {
                return Ok(Progress::Running(0, 1));
            }
            self.waiting = None;
        }

        let Some(relay) = self.order.pop() else {
            return Ok(Progress::Done(HandleFound {
                chunks: core::mem::take(&mut self.found),
                answered: self.answered,
            }));
        };

        let read = StaticSecret::from(*self.read.expose());
        let handle = node.chunk(relay, self.handle, ChunkJob::Fetch { read }, rng)?;
        self.waiting = Some((handle, self.ticks));
        Ok(Progress::Running(0, 1))
    }

    /// Takes the answer to a `CGET`. A relay that holds no chunk passes
    /// the read to the next one.
    pub fn on_outcome<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<HandleFound>, Error> {
        if !self.owns(handle) {
            return Ok(Progress::Running(0, 1));
        }

        self.waiting = None;
        match outcome {
            ChunkOutcome::Fetched(bytes) => {
                self.answered = true;
                if !self.found.contains(&bytes) {
                    self.found.push(bytes);
                }
            }
            // A relay under load or that takes no credential now says
            // nothing of the handle.
            ChunkOutcome::Refused(
                umbra_queue::Reject::Busy
                | umbra_queue::Reject::Limit
                | umbra_queue::Reject::Admission,
            ) => {}
            _ => self.answered = true,
        }

        self.tick(node, rng)
    }
}
