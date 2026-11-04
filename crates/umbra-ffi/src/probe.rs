//! The timestamps of one transfer task, for a measurement over real sockets
//! alone. A task with no probe in its scope adds no stamp.

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Instant,
};

use umbra_core::{
    attach::transfer::Upload,
    session::node::{ChunkMark, ChunkOutcome, ClientNode},
};

tokio::task_local! {
    static PROBE: Arc<Probe>;
}

/// A point in the start of a transfer task or of an upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    /// The task holds its connection and its node.
    Connected,
    /// One circuit is ready.
    CircuitReady,
    /// The upload sealed its file.
    Sealed,
    /// The upload holds the solutions that it made ahead.
    Solved,
}

/// A part of one turn of the loop of the task. A lap ends a part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lap {
    /// The capsules entered the link.
    Send,
    /// The task waited for a capsule, read it, and gave it to its node, or
    /// it took a command or a tick.
    Receive,
    /// The transfers took the answers.
    Answers,
    /// The commands of the caller started.
    Commands,
}

/// What one task did, with the time of each step.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    /// The time of [`Point::Connected`].
    pub connected: Option<Instant>,
    /// The time of each [`Point::CircuitReady`].
    pub circuits: Vec<Instant>,
    /// The time of [`Point::Sealed`].
    pub sealed: Option<Instant>,
    /// The time of [`Point::Solved`].
    pub solved: Option<Instant>,
    /// The solutions that the upload made ahead.
    pub solved_ahead: usize,
    /// The solves on the thread of the task.
    pub solved_at_send: u32,
    /// The start of the manifest phase.
    pub manifest: Option<Instant>,
    /// The `CPUT` or `CGET` window of the transfer, at each change.
    pub windows: Vec<(Instant, usize)>,
    /// The new relays and the new starts of the upload, in both phases.
    pub repairs: u32,
    /// Those of the data phase, whose chunks the manifest phase replaces.
    pub data_repairs: u32,
    /// Each chunk command, with the time that it entered the link.
    pub sent: Vec<(Instant, ChunkMark)>,
    /// Each held command that its circuit released, with its handle.
    pub released: Vec<(Instant, u64)>,
    /// Each answer: its time, its handle, and whether it refused.
    pub answered: Vec<(Instant, u64, bool)>,
    /// The end of each part of each turn of the loop of the task.
    pub laps: Vec<(Instant, Lap)>,
}

/// The trace of one task.
#[derive(Debug, Default)]
pub struct Probe(Mutex<Trace>);

impl Probe {
    /// A copy of the trace so far.
    pub fn trace(&self) -> Trace {
        self.0
            .lock()
            .map_or_else(|_| Trace::default(), |t| t.clone())
    }
}

/// `work` with `probe` in its scope.
pub fn scoped<F: Future>(probe: Arc<Probe>, work: F) -> impl Future<Output = F::Output> {
    PROBE.scope(probe, work)
}

fn with(change: impl FnOnce(&mut Trace)) {
    let _ = PROBE.try_with(|probe| {
        if let Ok(mut trace) = probe.0.lock() {
            change(&mut trace);
        }
    });
}

/// Stamps `point`.
pub(crate) fn point(point: Point) {
    let now = Instant::now();
    with(|trace| match point {
        Point::Connected => trace.connected = Some(now),
        Point::CircuitReady => trace.circuits.push(now),
        Point::Sealed => trace.sealed = Some(now),
        Point::Solved => trace.solved = Some(now),
    });
}

/// Stamps the solutions that an upload made ahead.
pub(crate) fn solved_ahead(count: usize) {
    with(|trace| trace.solved_ahead = trace.solved_ahead.saturating_add(count));
}

/// Stamps each chunk command that `node` took since the last call. The
/// capsules of those commands enter the link next.
pub(crate) fn sent(node: &mut ClientNode) {
    let marks = node.take_chunk_marks();
    let releases = node.take_chunk_releases();
    let solved_at_send = node.chunk_admissions().solved_at_send();
    let now = Instant::now();

    with(|trace| {
        trace.solved_at_send = solved_at_send;
        trace.sent.extend(marks.into_iter().map(|mark| (now, mark)));
        trace
            .released
            .extend(releases.into_iter().map(|handle| (now, handle)));
    });
}

/// Ends one part of a turn of the loop of the task.
pub(crate) fn lap(lap: Lap) {
    let now = Instant::now();

    with(|trace| trace.laps.push((now, lap)));
}

/// Stamps the answer to the command of `handle`.
pub(crate) fn answered(handle: u64, outcome: &ChunkOutcome) {
    let now = Instant::now();
    let is_refused = matches!(outcome, ChunkOutcome::Refused(_));

    with(|trace| trace.answered.push((now, handle, is_refused)));
}

/// Stamps the window of a transfer at each change.
pub(crate) fn window(window: usize) {
    let now = Instant::now();

    with(|trace| {
        if trace.windows.last().map(|(_, held)| *held) != Some(window) {
            trace.windows.push((now, window));
        }
    });
}

/// Stamps the state of `upload` after a call into it.
pub(crate) fn upload(upload: &Upload) {
    let now = Instant::now();
    window(upload.window());

    with(|trace| {
        if upload.is_in_manifest_phase() && trace.manifest.is_none() {
            trace.manifest = Some(now);
        }
        if upload.is_in_manifest_phase() {
            trace.repairs = trace.data_repairs.saturating_add(upload.repairs());
        } else {
            trace.data_repairs = upload.repairs();
            trace.repairs = trace.data_repairs;
        }
    });
}
