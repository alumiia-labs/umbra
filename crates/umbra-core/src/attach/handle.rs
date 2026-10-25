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
    transfer::{Progress, CHUNK_REPAIRS_MAX, STEP_TIMEOUT_TICKS, VERIFY_ATTEMPTS},
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
    /// The proof of each copy (`ATT-113`, `ATT-135`).
    Verify,
    /// The `CDEL` of a write that failed (`ATT-207`).
    Abort,
}

/// One question that waits for its answer.
#[derive(Clone, Copy)]
struct Question {
    handle: u64,
    relay: [u8; 32],
    tick: u32,
    /// The `CPUT` of `ATT-197` in the verify step, and not a `CVFY`.
    is_copy: bool,
    /// A `BNEW`, whose answer says whether the relay took the write.
    registers: bool,
}

/// The write of one handle-addressed chunk to the first `BACKUP_REPLICAS`
/// relays of its placement list (`ATT-133` to `ATT-135`), after a `CDEL`
/// at each relay that can hold an earlier chunk under the same handle
/// (`ATT-138`). The result is the relays that proved that they hold the
/// chunk. A write that fails erases what it placed before it gives its
/// fault (`ATT-207`), thus a later write of the handle finds no copy of it.
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
    /// Each question that waits.
    waiting: Vec<Question>,
    /// Each copy that owes its proof, with the asks that remain
    /// (`ATT-190`).
    unverified: Vec<([u8; 32], u8)>,
    /// The proofs that a later tick asks for: the relay and the tick.
    retries: Vec<([u8; 32], u32)>,
    /// The copies that this device sent itself (`ATT-197`).
    copies: u8,
    /// The relays whose registration got no answer: each one can hold it.
    silent: Vec<[u8; 32]>,
    /// The fault of a write that erases what it placed, which the write
    /// gives at the end of that erase.
    failure: Option<Error>,
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
            unverified: Vec::new(),
            retries: Vec::new(),
            copies: 0,
            silent: Vec::new(),
            failure: None,
            ticks: 0,
            started: false,
        })
    }

    /// Whether the answer with this handle belongs to this write.
    pub fn owns(&self, handle: u64) -> bool {
        self.waiting
            .iter()
            .any(|question| question.handle == handle)
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
        let is_copy = self.step == Step::Verify && matches!(job, ChunkJob::Put { .. });
        let registers = matches!(job, ChunkJob::Register { .. });
        // ABU-108: the solution of a registration serves this handle
        // alone, thus the handle names the upload.
        let upload = self
            .handle
            .first_chunk::<8>()
            .map_or(0, |prefix| u64::from_be_bytes(*prefix));

        let handle = node.chunk_of(upload, relay, self.handle, job, rng)?;
        self.waiting.push(Question {
            handle,
            relay,
            tick: self.ticks,
            is_copy,
            registers,
        });
        Ok(())
    }

    fn ask_proof<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        relay: [u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let job = ChunkJob::Verify {
            cred: self.cred(),
            chunk: self.chunk.clone(),
        };
        self.ask(node, relay, job, rng)
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

            // ATT-113, ATT-120: each copy proves itself. The relay of the
            // `CPUT` proved its bytes in its answer (`ATT-186`).
            Step::Verify => {
                self.unverified = self
                    .targets
                    .iter()
                    .skip(1)
                    .map(|(relay, _)| (*relay, VERIFY_ATTEMPTS))
                    .collect();
                for (relay, _) in self.unverified.clone() {
                    self.ask_proof(node, relay, rng)?;
                }
            }

            // The erase of a failed write asks its relays in `abort`.
            Step::Abort => {}
        }

        Ok(())
    }

    /// Starts the write, and ends a question that no relay answered in
    /// `STEP_TIMEOUT_TICKS`: an erase counts as done, a registration moves
    /// to the next relay of the list, and a proof is asked again
    /// (`ATT-203`). A write that fails erases what it placed first
    /// (`ATT-207`).
    pub fn tick<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        match self.tick_step(node, rng) {
            Err(error) if self.step != Step::Abort => self.abort(node, error, rng),
            ticked => ticked,
        }
    }

    fn tick_step<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.ticks = self.ticks.saturating_add(1);
        if !self.started {
            self.started = true;
            return self.start_step(node, rng);
        }

        let late: Vec<u64> = self
            .waiting
            .iter()
            .filter(|question| self.ticks.saturating_sub(question.tick) >= STEP_TIMEOUT_TICKS)
            .map(|question| question.handle)
            .collect();

        // A registration with no answer can stand at its relay.
        for question in self
            .waiting
            .iter()
            .filter(|held| held.registers && late.contains(&held.handle))
        {
            if !self.silent.contains(&question.relay) {
                self.silent.push(question.relay);
            }
        }

        for handle in late {
            self.on_outcome(
                node,
                handle,
                ChunkOutcome::Refused(umbra_queue::Reject::Busy),
                rng,
            )?;
        }

        let ticks = self.ticks;
        let (due, later): (Vec<_>, Vec<_>) = core::mem::take(&mut self.retries)
            .into_iter()
            .partition(|(_, at_tick)| *at_tick <= ticks);
        self.retries = later;
        for (relay, _) in due {
            self.ask_proof(node, relay, rng)?;
        }

        Ok(())
    }

    /// Takes one chunk answer. The result is the relays that hold the chunk.
    /// A write that fails erases what it placed first, and it gives its
    /// fault when each relay answered that `CDEL` (`ATT-207`).
    pub fn on_outcome<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<Vec<[u8; 32]>>, Error> {
        if self.step == Step::Abort {
            return self.on_erased(node, handle, &outcome, rng);
        }

        match self.on_step(node, handle, outcome, rng) {
            Err(error) => self
                .abort(node, error, rng)
                .map(|()| Progress::Running(0, 1)),
            stepped => stepped,
        }
    }

    /// Ends a write that failed with `error` (`ATT-207`). A `CDEL` goes to
    /// each relay that took a registration of this write, or that did not
    /// answer one. A registration that waits for its answer keeps its
    /// place, and its answer decides. With no such relay the result is
    /// `error` at once.
    fn abort<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        error: Error,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut placed: Vec<[u8; 32]> = Vec::new();
        let mut registering: Vec<Question> = Vec::new();
        if self.started && self.step != Step::Erase {
            registering = core::mem::take(&mut self.waiting)
                .into_iter()
                .filter(|question| question.registers && !self.silent.contains(&question.relay))
                .collect();
            let registered = self
                .targets
                .iter()
                .filter(|(_, token)| token.is_some())
                .map(|(relay, _)| *relay);
            for relay in registered.chain(self.silent.iter().copied()) {
                if !placed.contains(&relay) {
                    placed.push(relay);
                }
            }
        }

        self.step = Step::Abort;
        self.failure = Some(error);
        self.waiting = registering;
        self.retries.clear();
        self.unverified.clear();
        for relay in placed {
            self.erase_at(node, relay, rng);
        }

        if self.waiting.is_empty() {
            return Err(error);
        }
        Ok(())
    }

    /// Sends the `CDEL` of a failed write to one relay. A command that does
    /// not leave stops no other one.
    fn erase_at<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        relay: [u8; 32],
        rng: &mut R,
    ) {
        let job = ChunkJob::Erase { cred: self.cred() };
        let _ = self.ask(node, relay, job, rng);
    }

    /// Takes one answer in the erase of a write that failed. A registration
    /// that the relay took, or that got no answer, gets its `CDEL` now. A
    /// relay that refused it holds no part of this write, and under
    /// `ATT-058` it can hold the copy of an earlier write. Each other answer
    /// ends the wait for its relay. A `CDEL` that a relay refuses under load
    /// leaves the copy there until its TTL, as one with no answer does.
    fn on_erased<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: &ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<Vec<[u8; 32]>>, Error> {
        let Some(at) = self
            .waiting
            .iter()
            .position(|question| question.handle == handle)
        else {
            return Ok(Progress::Running(0, 1));
        };
        let question = self.waiting.remove(at);

        let stands =
            matches!(outcome, ChunkOutcome::Registered(_)) || self.silent.contains(&question.relay);
        if question.registers && stands {
            self.erase_at(node, question.relay, rng);
        }

        if self.waiting.is_empty() {
            return Err(self.failure.unwrap_or(Error::NoPath));
        }
        Ok(Progress::Running(0, 1))
    }

    fn on_step<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        handle: u64,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<Vec<[u8; 32]>>, Error> {
        let Some(at) = self
            .waiting
            .iter()
            .position(|question| question.handle == handle)
        else {
            return Ok(Progress::Running(0, 1));
        };
        let question = self.waiting.remove(at);
        let relay = question.relay;

        match (self.step, outcome) {
            // An erase of a chunk that the relay does not hold is refused,
            // and it is done as well.
            (Step::Erase, _) => {}
            (Step::Register, ChunkOutcome::Registered(token)) => {
                if let Some(target) = self.targets.iter_mut().find(|(held, _)| *held == relay) {
                    target.1 = Some(token);
                }
            }

            // ATT-134: the next relay of the list takes the place. A relay
            // that refused holds no registration of this write, and it can
            // hold the copy of an earlier write: the erase of `ATT-207`
            // passes it. One with no answer stays in `silent`.
            (Step::Register, _) => {
                self.failed.push(relay);
                self.targets.retain(|(held, _)| *held != relay);

                let next = writer_targets(&self.list, &self.failed)?;
                let replacement = next
                    .into_iter()
                    .find(|candidate| !self.targets.iter().any(|(held, _)| held == candidate))
                    .ok_or(Error::NoPath)?;
                self.targets.push((replacement, None));

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
            (Step::Verify, outcome) => return self.on_proof(node, question, outcome, rng),
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
            Step::Replicate => Step::Verify,
            Step::Put | Step::Verify => return Ok(Progress::Done(self.holders())),
            Step::Abort => return Err(self.failure.unwrap_or(Error::NoPath)),
        };

        self.start_step(node, rng)?;
        Ok(Progress::Running(0, 1))
    }

    fn holders(&self) -> Vec<[u8; 32]> {
        self.targets.iter().map(|(relay, _)| *relay).collect()
    }

    /// Takes the answer to a proof of a copy, or to the `CPUT` that this
    /// device sent in place of a copy that did not arrive. The write ends
    /// when each copy proved its bytes.
    fn on_proof<R: umbra_crypto::rand_core::CryptoRng + ?Sized>(
        &mut self,
        node: &mut ClientNode,
        question: Question,
        outcome: ChunkOutcome,
        rng: &mut R,
    ) -> Result<Progress<Vec<[u8; 32]>>, Error> {
        let relay = question.relay;
        match (question.is_copy, outcome) {
            (false, ChunkOutcome::Verified) | (true, ChunkOutcome::Stored) => {
                self.unverified.retain(|(held, _)| *held != relay);
            }

            // ATT-197: the copy of the first relay came while the bytes of
            // this device were on their way, and the proof says so.
            (true, ChunkOutcome::Refused(_)) => self.retries.push((relay, self.ticks)),

            // ATT-190: the copy can be on its way still.
            (false, ChunkOutcome::Refused(_)) => {
                let entry = self
                    .unverified
                    .iter_mut()
                    .find(|(held, _)| *held == relay)
                    .ok_or(Error::Malformed)?;
                entry.1 = entry.1.saturating_sub(1);

                if entry.1 > 0 {
                    // Each wait is two times the one before.
                    let asked = u32::from(VERIFY_ATTEMPTS.saturating_sub(entry.1));
                    let wait = 1u32 << asked.saturating_sub(1).min(8);
                    self.retries.push((relay, self.ticks.saturating_add(wait)));
                } else {
                    // ATT-197: the relay holds its registration, thus the
                    // bytes go to it from this device.
                    entry.1 = VERIFY_ATTEMPTS;
                    self.copies = self.copies.saturating_add(1);
                    if self.copies > CHUNK_REPAIRS_MAX {
                        return Err(Error::Unverified);
                    }

                    let storage_token = self
                        .targets
                        .iter()
                        .find(|(held, _)| *held == relay)
                        .and_then(|(_, token)| *token)
                        .ok_or(Error::NoPath)?;
                    let job = ChunkJob::Put {
                        cred: self.cred(),
                        storage_token,
                        chunk: self.chunk.clone(),
                    };
                    self.ask(node, relay, job, rng)?;
                }
            }

            // ATT-118: a wrong proof ends the write, and the caller writes
            // again later.
            _ => return Err(Error::Unverified),
        }

        if self.unverified.is_empty() {
            return Ok(Progress::Done(self.holders()));
        }
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
