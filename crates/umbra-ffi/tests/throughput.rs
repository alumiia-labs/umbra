//! The throughput of attachment transfers on loopback, over the real
//! transfer task and real relays. Each measurement takes a fresh network of
//! seven relays and a fresh client, thus a transfer pays for its dial, its
//! circuits, and its proof of work, as the first transfer of an app does.
//!
//! The two tests are `#[ignore]`d, and a release build runs them:
//!
//! ```text
//! cargo test --release --locked -p umbra-ffi --features bindings,sockets-test \
//!     --test throughput -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `throughput_table` reads these variables. Each one is optional.
//!
//! | Variable | Default | Meaning |
//! | --- | --- | --- |
//! | `UMBRA_BENCH_RUNS` | 3 | The runs of each combination |
//! | `UMBRA_BENCH_SIZES` | 8,64 | The file sizes in MiB |
//! | `UMBRA_BENCH_MODES` | fast,balanced,private | The privacy modes |
//! | `UMBRA_BENCH_DIRECTIONS` | upload,download | The directions |
//! | `UMBRA_BENCH_CAP_SECS` | 600 | The time limit of one combination |
//! | `UMBRA_BENCH_LINK_MBIT` | 0 | The rate of the link of the measured client, 0 for none |
//!
//! A rate above 0 puts a shaper between the measured client and its ingress
//! relay. It carries the bytes of each direction at that rate, and the bytes
//! above it wait in the shaper and in the sockets, as on the link of a phone.
//! The seed upload of a download takes no shaper.
//!
//! `upload_breakdown` and `download_breakdown` read the runs and the limit,
//! and these variables.
//!
//! | Variable | Default | Meaning |
//! | --- | --- | --- |
//! | `UMBRA_BENCH_BREAKDOWN_MODE` | fast up, private down | The privacy mode |
//! | `UMBRA_BENCH_BREAKDOWN_MIB` | 8 | The file size in MiB |
//!
//! `download_breakdown` splits the step of a `CGET` at each hop: the draw of
//! `NET-338`, the extra hold of `NET-339`, the wait for the clock of the
//! relay, and the way back. It sets the hold against the model of Part 12
//! §12.7.2.
//!
//! A run that sent more `CPUT` than chunks lost a copy. It is marked, and the
//! median leaves it out. Runs of 64 MiB start 31 s apart on Windows.
//!
//! All parties share one machine, thus a number shows the limit of this
//! code on loopback. It is no figure for a real network. Mbit/s counts the
//! bytes of the file, and the padding and the copies of the relays do not
//! count.

#![cfg(all(feature = "bindings", feature = "sockets-test"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

#[allow(dead_code)]
mod network;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use network::{start_signed_network_tuned, SignedNetwork, TransferSet, Tuning};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    runtime::Runtime,
    sync::mpsc,
};
use umbra_core::{
    attach::transfer::{Shape, Uploaded},
    session::node::{ChunkKind, DelayClass},
};
use umbra_ffi::{
    probe::{self, Lap, Probe, Trace},
    transfers::{TransferCommand, TransferUpdate},
};
use umbra_relay::{
    busy::{BusyGauge, Timed},
    hops::{self, HopTrace},
    server::PACING_MEAN_MS,
};
use umbra_transport::Dial;
use umbra_wire::descriptor::FileDescriptor;
use zeroize::Zeroizing;

const MIB: usize = 1 << 20;
/// The chunk store of each relay. The store of a test network does not hold
/// the copies of a file of 64 MiB.
const RELAY_STORE: u64 = 1 << 32;
const SAMPLE_PERIOD: Duration = Duration::from_millis(50);
const TAG: u64 = 1;
const UPLOADER: u8 = 0x81;
const DOWNLOADER: u8 = 0x82;

/// A task that runs for this part of the time is the limit of the flow.
const SATURATED: f64 = 0.9;
/// A window that is full for this part of the time is the limit of the flow.
const WINDOW_BINDS: f64 = 0.8;
/// An answer that takes the task this long holds a solve of `ABU-107` on the
/// thread of the task. The other work of an answer takes milliseconds.
const STALL: Duration = Duration::from_millis(100);
/// Stalls that hold this part of the time are the limit of the flow.
const STALLS_BIND: f64 = 0.5;
/// The file size of a run that can use up the dynamic ports of Windows. Each
/// copy of a relay takes a port, and the port stays in TIME_WAIT for about
/// 120 s. A copy that gets no port is lost, and it costs 31 s of `ATT-190`.
const BIG_RUN: usize = 64 * MIB;
/// The time between the starts of two such runs on Windows.
const BIG_RUN_GAP: Duration = Duration::from_secs(31);

static LAST_BIG_RUN: Mutex<Option<Instant>> = Mutex::new(None);

/// Waits until a big run can start.
fn pace_big_run(size: usize) {
    if !cfg!(windows) || size < BIG_RUN {
        return;
    }

    let mut last = LAST_BIG_RUN.lock().unwrap();
    let left = last.and_then(|start| BIG_RUN_GAP.checked_sub(start.elapsed()));
    if let Some(left) = left {
        std::thread::sleep(left);
    }
    *last = Some(Instant::now());
}

/// The rate of the link of the measured client in bytes each second, or
/// none for loopback alone.
fn link_rate() -> Option<f64> {
    let text = std::env::var("UMBRA_BENCH_LINK_MBIT").unwrap_or_else(|_| "0".to_owned());
    let mbit: f64 = text.parse().expect("UMBRA_BENCH_LINK_MBIT");
    (mbit > 0.0).then_some(mbit * 1e6 / 8.0)
}

/// The time on the link that an idle shaper keeps as credit. A sleep on
/// Windows ends up to about 16 ms late, and the credit gives that time back.
const SHAPER_CREDIT: Duration = Duration::from_millis(50);

/// Carries the bytes of one direction at `rate`. A byte leaves when the
/// bytes before it took their time on the link, thus a burst waits here.
async fn shape(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, rate: f64) {
    let mut bytes = vec![0u8; 16 * 1024];
    let mut free_at = tokio::time::Instant::now();

    loop {
        let count = match from.read(&mut bytes).await {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };

        let now = tokio::time::Instant::now();
        let earliest = now.checked_sub(SHAPER_CREDIT).unwrap_or(now);
        free_at = free_at.max(earliest) + Duration::from_secs_f64(count as f64 / rate);
        tokio::time::sleep_until(free_at).await;
        if to.write_all(&bytes[..count]).await.is_err() {
            break;
        }
    }

    let _ = to.shutdown().await;
}

/// A shaper in front of the ingress relay at `guard`, and the dial of it.
fn start_shaper(relays: &Runtime, guard: &Dial, rate: f64) -> Dial {
    let listener = relays
        .block_on(TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let ingress = (std::net::Ipv4Addr::from(guard.addr_v4.unwrap()), guard.port);

    relays.spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let Ok(relay) = TcpStream::connect(ingress).await else {
                continue;
            };
            let _ = (client.set_nodelay(true), relay.set_nodelay(true));
            let (client_in, client_out) = client.into_split();
            let (relay_in, relay_out) = relay.into_split();
            tokio::spawn(shape(client_in, relay_out, rate));
            tokio::spawn(shape(relay_in, client_out, rate));
        }
    });

    Dial {
        addr_v4: Some([127, 0, 0, 1]),
        port,
        ..guard.clone()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Direction {
    Upload,
    Download,
}

impl Direction {
    fn name(self) -> &'static str {
        match self {
            Direction::Upload => "upload",
            Direction::Download => "download",
        }
    }
}

fn mode_of(name: &str) -> DelayClass {
    match name {
        "fast" => DelayClass::Fast,
        "balanced" => DelayClass::Balanced,
        "private" => DelayClass::Private,
        other => panic!("no mode {other}"),
    }
}

fn mode_name(class: DelayClass) -> &'static str {
    match class {
        DelayClass::Fast => "Fast",
        DelayClass::Balanced => "Balanced",
        DelayClass::Private => "Private",
    }
}

struct Options {
    runs: usize,
    sizes: Vec<usize>,
    modes: Vec<DelayClass>,
    directions: Vec<Direction>,
    cap: Duration,
}

fn listed(name: &str, default: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .split(',')
        .map(|item| item.trim().to_lowercase())
        .collect()
}

impl Options {
    fn read() -> Self {
        let number = |name: &str, default: &str| -> u64 {
            let text = std::env::var(name).unwrap_or_else(|_| default.to_owned());
            text.parse().expect(name)
        };
        let modes = listed("UMBRA_BENCH_MODES", "fast,balanced,private")
            .iter()
            .map(|mode| mode_of(mode))
            .collect();
        let directions = listed("UMBRA_BENCH_DIRECTIONS", "upload,download")
            .iter()
            .map(|direction| match direction.as_str() {
                "upload" => Direction::Upload,
                "download" => Direction::Download,
                other => panic!("no direction {other}"),
            })
            .collect();
        let sizes = listed("UMBRA_BENCH_SIZES", "8,64")
            .iter()
            .map(|size| size.parse().expect("a size in MiB"))
            .collect();

        Options {
            runs: usize::try_from(number("UMBRA_BENCH_RUNS", "3"))
                .unwrap()
                .max(1),
            sizes,
            modes,
            directions,
            cap: Duration::from_secs(number("UMBRA_BENCH_CAP_SECS", "600")),
        }
    }
}

/// The time that each party ran so far.
#[derive(Clone)]
struct Snapshot {
    at: Instant,
    client_task: Duration,
    client_workers: Duration,
    relay_workers: Duration,
    relay_nodes: Vec<Duration>,
}

/// The time on the worker threads of a runtime.
fn workers_busy(runtime: &Runtime) -> Duration {
    let metrics = runtime.metrics();
    (0..metrics.num_workers())
        .map(|worker| metrics.worker_total_busy_duration(worker))
        .sum()
}

/// What ended a run that gave no result.
#[derive(Debug)]
enum Stop {
    Failed(&'static str),
    Capped { done: u32, total: u32 },
}

enum Ended {
    Uploaded(Box<Uploaded>),
    Downloaded(Zeroizing<Vec<u8>>),
}

/// One measured transfer.
struct Run {
    seconds: f64,
    started: Instant,
    ended_at: Instant,
    chunks: u32,
    trace: Trace,
    samples: Vec<Snapshot>,
    faults: u32,
}

impl Run {
    fn final_window(&self) -> usize {
        self.trace.windows.last().map_or(0, |window| window.1)
    }

    fn peak_window(&self) -> usize {
        let sizes = self.trace.windows.iter().map(|window| window.1);
        sizes.max().unwrap_or(0)
    }

    /// The `CGET` that left. A count above the chunks of the file shows a
    /// step that timed out.
    fn fetches(&self) -> usize {
        let sent = self.trace.sent.iter();
        sent.filter(|(_, mark)| mark.kind == ChunkKind::Fetch)
            .count()
    }

    /// The `CPUT` above the chunk count: a copy that a relay lost took
    /// `ATT-197`, or a chunk started again.
    fn lost_copies(&self) -> usize {
        let puts = self
            .trace
            .sent
            .iter()
            .filter(|(_, mark)| mark.kind == ChunkKind::Put)
            .count();

        puts.saturating_sub(self.chunks as usize)
    }
}

/// One fresh network with its runtimes. The client runtime ends first.
struct Bench {
    clients: Runtime,
    relays: Runtime,
    network: SignedNetwork,
    set: TransferSet,
    /// The shaped link of the measured client (`UMBRA_BENCH_LINK_MBIT`).
    shaped: Option<Dial>,
}

impl Bench {
    fn start() -> Self {
        let relays = Runtime::new().unwrap();
        let clients = Runtime::new().unwrap();

        // NET-360: an answer falls back to the pacing clock when its link is
        // full, thus the clock runs at the value of a deployment.
        let tuning = Tuning {
            pacing_mean_ms: PACING_MEAN_MS,
            chunk_capacity: RELAY_STORE,
        };
        let network = start_signed_network_tuned(&relays, None, None, None, false, &tuning);
        let set = TransferSet::read(&network, &clients);
        let shaped = link_rate().map(|rate| start_shaper(&relays, &set.guard(), rate));

        Bench {
            clients,
            relays,
            network,
            set,
            shaped,
        }
    }

    fn snapshot(&self, client_task: &BusyGauge) -> Snapshot {
        Snapshot {
            at: Instant::now(),
            client_task: client_task.total(),
            client_workers: workers_busy(&self.clients),
            relay_workers: workers_busy(&self.relays),
            relay_nodes: self.network.node_busy.iter().map(|g| g.total()).collect(),
        }
    }

    /// Runs one transfer on a new task and a new connection. The time runs
    /// from the start of the task to the last answer.
    fn transfer(
        &self,
        seed: u8,
        class: DelayClass,
        command: TransferCommand,
        cap: Duration,
        is_measured: bool,
    ) -> Result<(Run, Ended), Stop> {
        let probe = Arc::new(Probe::default());
        let client_busy = Arc::new(BusyGauge::default());
        let guard = match (&self.shaped, is_measured) {
            (Some(shaped), true) => shaped.clone(),
            _ => self.set.guard(),
        };
        let (task, commands, mut updates) = self.set.task_via(seed, guard);
        let mut samples = vec![self.snapshot(&client_busy)];

        let started = Instant::now();
        let running = probe::scoped(probe.clone(), task);
        let joined = self.clients.spawn(Timed::new(client_busy.clone(), running));
        commands
            .send(TransferCommand::Mode { tag: TAG, class })
            .ok()
            .unwrap();
        commands.send(command).ok().unwrap();

        let mut chunks = (0, 0);
        let mut faults = 0;
        let ended = self.clients.block_on(self.watch(
            &mut updates,
            &client_busy,
            &mut samples,
            &mut chunks,
            &mut faults,
            cap,
        ));
        let ended_at = Instant::now();
        samples.push(self.snapshot(&client_busy));

        // The trace stays with the probe. The end of the task needs no time
        // of this run.
        drop(commands);
        self.clients.block_on(async {
            let _ = tokio::time::timeout(Duration::from_secs(3), joined).await;
        });

        let run = Run {
            seconds: ended_at.duration_since(started).as_secs_f64(),
            started,
            ended_at,
            chunks: chunks.1,
            trace: probe.trace(),
            samples,
            faults,
        };
        Ok((run, ended?))
    }

    /// Reads the updates until the end of the transfer, and takes a sample
    /// of each gauge at each period.
    async fn watch(
        &self,
        updates: &mut mpsc::UnboundedReceiver<TransferUpdate>,
        client_busy: &BusyGauge,
        samples: &mut Vec<Snapshot>,
        chunks: &mut (u32, u32),
        faults: &mut u32,
        cap: Duration,
    ) -> Result<Ended, Stop> {
        let deadline = tokio::time::Instant::now() + cap;
        let mut period = tokio::time::interval(SAMPLE_PERIOD);

        loop {
            let update = tokio::select! {
                update = updates.recv() => update,
                _ = period.tick() => {
                    samples.push(self.snapshot(client_busy));
                    continue;
                }
                () = tokio::time::sleep_until(deadline) => {
                    return Err(Stop::Capped { done: chunks.0, total: chunks.1 });
                }
            };

            match update {
                Some(TransferUpdate::Progress { done, total, .. }) => *chunks = (done, total),
                Some(TransferUpdate::Chains(_)) => {}
                Some(TransferUpdate::Faults(_)) => *faults = faults.saturating_add(1),
                Some(TransferUpdate::Uploaded { uploaded, .. }) => {
                    return Ok(Ended::Uploaded(uploaded));
                }
                Some(TransferUpdate::Downloaded { plain, .. }) => {
                    return Ok(Ended::Downloaded(plain));
                }
                Some(TransferUpdate::Failed { .. }) => return Err(Stop::Failed("failed")),
                Some(TransferUpdate::Interrupted { .. }) => {
                    return Err(Stop::Failed("interrupted"));
                }
                Some(TransferUpdate::Gone { .. }) => return Err(Stop::Failed("gone")),
                Some(_) => {}
                None => return Err(Stop::Failed("the task ended")),
            }
        }
    }

    /// An upload. A measured one takes the shaped link, and a seed upload
    /// of a download does not.
    fn upload(
        &self,
        class: DelayClass,
        plain: &[u8],
        cap: Duration,
        is_measured: bool,
    ) -> Result<(Run, FileDescriptor), Stop> {
        let command = TransferCommand::Upload {
            tag: TAG,
            plain: Zeroizing::new(plain.to_vec()),
            shape: Shape::default(),
        };
        let (run, ended) = self.transfer(UPLOADER, class, command, cap, is_measured)?;
        let Ended::Uploaded(uploaded) = ended else {
            return Err(Stop::Failed("no descriptor"));
        };

        Ok((run, uploaded.descriptor))
    }

    fn download(
        &self,
        class: DelayClass,
        descriptor: FileDescriptor,
        plain: &[u8],
        cap: Duration,
    ) -> Result<Run, Stop> {
        let command = TransferCommand::Download {
            tag: TAG,
            descriptor: Box::new(descriptor),
        };
        let (run, ended) = self.transfer(DOWNLOADER, class, command, cap, true)?;
        let Ended::Downloaded(fetched) = ended else {
            return Err(Stop::Failed("no file"));
        };

        assert!(*fetched == *plain, "the file came back changed");
        Ok(run)
    }
}

fn file_of(size_mib: usize) -> Vec<u8> {
    (0..size_mib * MIB).map(|at| (at % 253) as u8).collect()
}

/// One transfer on a fresh network. A download reads a file that a Fast
/// upload placed, and the time of that upload does not count.
fn measure(
    direction: Direction,
    class: DelayClass,
    plain: &[u8],
    cap: Duration,
) -> Result<Run, Stop> {
    pace_big_run(plain.len());

    let bench = Bench::start();
    match direction {
        Direction::Upload => bench.upload(class, plain, cap, true).map(|(run, _)| run),
        Direction::Download => {
            let (_, descriptor) = bench.upload(DelayClass::Fast, plain, cap, false)?;
            bench.download(class, descriptor, plain, cap)
        }
    }
}

/// A span of time of one kind.
#[derive(Clone, Copy)]
struct Span {
    from: f64,
    to: f64,
    kind: usize,
}

/// The time inside `from..to` that each kind holds, one kind at a time: at
/// each moment the open span with the lowest kind takes the time. The last
/// entry is the time with no span open.
fn exclusive(spans: &[Span], kinds: usize, from: f64, to: f64) -> Vec<f64> {
    let mut edges: Vec<(f64, usize, i64)> = Vec::with_capacity(spans.len() * 2);
    for span in spans {
        edges.push((span.from.clamp(from, to), span.kind, 1));
        edges.push((span.to.clamp(from, to), span.kind, -1));
    }
    edges.sort_by(|a, b| a.0.total_cmp(&b.0));

    let mut open = vec![0i64; kinds];
    let mut totals = vec![0f64; kinds + 1];
    let mut at = from;
    for (time, kind, change) in edges {
        let holder = open.iter().position(|count| *count > 0).unwrap_or(kinds);
        totals[holder] += time - at;
        at = time;
        open[kind] += change;
    }
    totals[kinds] += to - at;

    totals
}

/// The part of `from..to` that at least one span covers.
fn covered(spans: &[Span], from: f64, to: f64) -> f64 {
    let only: Vec<Span> = spans.iter().map(|span| Span { kind: 0, ..*span }).collect();
    let totals = exclusive(&only, 1, from, to);
    totals[0]
}

/// One chunk command with its answer.
struct Asked {
    kind: ChunkKind,
    sent: Instant,
    released: Option<Instant>,
    answered: Option<Instant>,
    is_refused: bool,
    chunk: ([u8; 32], [u8; 32]),
}

fn asked_of(trace: &Trace) -> Vec<Asked> {
    let answers: BTreeMap<u64, (Instant, bool)> = trace
        .answered
        .iter()
        .map(|(at, handle, is_refused)| (*handle, (*at, *is_refused)))
        .collect();
    let released: BTreeMap<u64, Instant> = trace
        .released
        .iter()
        .map(|(at, handle)| (*handle, *at))
        .collect();

    trace
        .sent
        .iter()
        .map(|(sent, mark)| {
            let answer = answers.get(&mark.handle);
            Asked {
                kind: mark.kind,
                sent: *sent,
                released: released.get(&mark.handle).copied(),
                answered: answer.map(|(at, _)| *at),
                is_refused: answer.is_some_and(|(_, is_refused)| *is_refused),
                chunk: (mark.chunk_id, mark.relay),
            }
        })
        .collect()
}

/// The time from each refused `CVFY` to the next one for that copy: the wait
/// of that proof for a tick (`ATT-190`).
fn retry_waits(asked: &[Asked]) -> Vec<(Instant, Instant)> {
    let mut waits = Vec::new();
    let mut proofs: Vec<&Asked> = asked
        .iter()
        .filter(|command| command.kind == ChunkKind::Verify)
        .collect();
    proofs.sort_by_key(|command| command.sent);

    for (at, proof) in proofs.iter().enumerate() {
        let (true, Some(refused)) = (proof.is_refused, proof.answered) else {
            continue;
        };
        let next = proofs[at + 1..]
            .iter()
            .find(|later| later.chunk == proof.chunk);
        if let Some(next) = next {
            waits.push((refused, next.sent));
        }
    }

    waits
}

/// The load of the parties while the chunks moved, as a part of the time.
/// A value of 1.0 is one thread, all the time.
struct Load {
    client_task: f64,
    client_workers: f64,
    relay_workers: f64,
    relay_nodes: Vec<f64>,
}

fn load_between(samples: &[Snapshot], from: Instant, to: Instant) -> Load {
    let start = samples
        .iter()
        .rev()
        .find(|s| s.at <= from)
        .unwrap_or(&samples[0]);
    let end = samples
        .iter()
        .find(|s| s.at >= to)
        .unwrap_or(&samples[samples.len() - 1]);
    let wall = end.at.duration_since(start.at).as_secs_f64().max(1e-9);
    let part =
        |after: Duration, before: Duration| after.saturating_sub(before).as_secs_f64() / wall;

    Load {
        client_task: part(end.client_task, start.client_task),
        client_workers: part(end.client_workers, start.client_workers),
        relay_workers: part(end.relay_workers, start.relay_workers),
        relay_nodes: end
            .relay_nodes
            .iter()
            .zip(&start.relay_nodes)
            .map(|(after, before)| part(*after, *before))
            .collect(),
    }
}

/// The command that moves the bytes of the file.
fn main_kind(direction: Direction) -> ChunkKind {
    match direction {
        Direction::Upload => ChunkKind::Put,
        Direction::Download => ChunkKind::Fetch,
    }
}

/// How the commands of the window filled it: the part of the time with a
/// full window, and the mean of the commands in flight.
fn window_use(run: &Run, direction: Direction) -> (f64, f64) {
    let kind = main_kind(direction);
    let asked = asked_of(&run.trace);
    let mut edges: Vec<(Instant, i64)> = Vec::new();
    for command in asked.iter().filter(|command| command.kind == kind) {
        edges.push((command.sent, 1));
        edges.push((command.answered.unwrap_or(run.ended_at), -1));
    }
    edges.sort_by_key(|edge| edge.0);
    let (Some(first), Some(last)) = (edges.first(), edges.last()) else {
        return (0.0, 0.0);
    };
    let (start, end) = (first.0, last.0);

    let window_at = |moment: Instant| {
        let changes = &run.trace.windows;
        let current = changes.iter().rev().find(|(at, _)| *at <= moment);
        current.or(changes.first()).map_or(0, |window| window.1)
    };

    let mut open = 0i64;
    let mut at = start;
    let mut full = 0.0;
    let mut weighted = 0.0;
    for (moment, change) in &edges {
        let length = moment.duration_since(at).as_secs_f64();
        weighted += length * open as f64;
        if usize::try_from(open).unwrap_or(0) >= window_at(at) {
            full += length;
        }
        at = *moment;
        open += change;
    }

    let span = end.duration_since(start).as_secs_f64().max(1e-9);
    (full / span, weighted / span)
}

/// The span in which the data moves: the first and the last answer of the
/// main command of the direction.
fn moving_span(run: &Run, direction: Direction) -> (Instant, Instant) {
    let kind = main_kind(direction);
    let asked = asked_of(&run.trace);
    let of_kind = || asked.iter().filter(|command| command.kind == kind);

    let from = of_kind().map(|c| c.sent).min().unwrap_or(run.started);
    let to = of_kind()
        .filter_map(|c| c.answered)
        .max()
        .unwrap_or(run.ended_at);
    (from, to)
}

/// What the transfer task did with its time inside `from..to`, as a part
/// of that time: the sends, the answers, and the commands of the caller.
/// A wait for a capsule and the work on a capsule share one lap, thus the
/// work on a capsule is what the time of the task leaves over.
struct ClientParts {
    send: f64,
    answers: f64,
    commands: f64,
    /// The answers that took at least [`STALL`].
    stalls: u32,
    /// The time of those answers, as a part of the span.
    stalled: f64,
}

fn client_parts(trace: &Trace, from: Instant, to: Instant) -> ClientParts {
    let span = to.duration_since(from).as_secs_f64().max(1e-9);
    let mut parts = ClientParts {
        send: 0.0,
        answers: 0.0,
        commands: 0.0,
        stalls: 0,
        stalled: 0.0,
    };

    for pair in trace.laps.windows(2) {
        let (start, (end, lap)) = (pair[0].0, pair[1]);
        if start < from || end > to {
            continue;
        }

        let part = end.duration_since(start).as_secs_f64() / span;
        match lap {
            Lap::Send => parts.send += part,
            Lap::Answers => {
                parts.answers += part;
                if end.duration_since(start) >= STALL {
                    parts.stalls += 1;
                    parts.stalled += part;
                }
            }
            Lap::Commands => parts.commands += part,
            Lap::Receive => {}
        }
    }

    parts
}

fn verdict(load: &Load, full: f64, stalled: f64) -> String {
    let busiest = load.relay_nodes.iter().copied().fold(0.0, f64::max);
    if stalled >= STALLS_BIND {
        return "CPU, client task, proof of work at a send".to_owned();
    }
    if load.client_task >= SATURATED {
        return "CPU, client task".to_owned();
    }
    if busiest >= SATURATED {
        return "CPU, relay node task".to_owned();
    }
    if full >= WINDOW_BINDS {
        return "window".to_owned();
    }
    "step time".to_owned()
}

fn median_of(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

/// One line of the table, for one combination.
struct Row {
    direction: Direction,
    size_mib: usize,
    class: DelayClass,
    seconds: Vec<f64>,
    window: usize,
    limits: String,
    note: String,
}

fn mbit(size_mib: usize, seconds: f64) -> f64 {
    (size_mib * MIB * 8) as f64 / seconds / 1e6
}

fn print_table(rows: &[Row]) {
    println!();
    println!("Measured on loopback: all parties share this machine.");
    if let Some(rate) = link_rate() {
        println!(
            "The link of the measured client carries {:.1} Mbit/s.",
            rate * 8.0 / 1e6
        );
    }
    println!(
        "{:<8} {:>4} {:<8} {:>4} {:>8} {:>17} {:>8} {:>17} {:>6}  note",
        "dir", "MiB", "mode", "runs", "median s", "range s", "Mbit/s", "range Mbit/s", "window"
    );

    for row in rows {
        let name = format!(
            "{:<8} {:>4} {:<8}",
            row.direction.name(),
            row.size_mib,
            mode_name(row.class)
        );
        if row.seconds.is_empty() {
            println!("{name} {:>4} {:>8} {:>17}  {}", 0, "-", "-", row.note);
            continue;
        }

        let mut seconds = row.seconds.clone();
        let median = median_of(&mut seconds);
        let (low, high) = (seconds[0], seconds[seconds.len() - 1]);
        println!(
            "{name} {:>4} {median:>8.2} {:>17} {:>8.1} {:>17} {:>6}  {}",
            seconds.len(),
            format!("{low:.2} to {high:.2}"),
            mbit(row.size_mib, median),
            format!(
                "{:.1} to {:.1}",
                mbit(row.size_mib, high),
                mbit(row.size_mib, low)
            ),
            row.window,
            row.note
        );
    }

    println!();
    println!("Where the time goes, in the median run, while the chunks move:");
    println!(
        "{:<8} {:>4} {:<8} {:>6} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>6} {:>7}  limit",
        "dir",
        "MiB",
        "mode",
        "full",
        "flight",
        "client",
        "c.send",
        "c.ans",
        "c.recv",
        "c.all",
        "r.node",
        "r.all",
        "step ms",
        "stalls",
        "stall s"
    );
    for row in rows {
        if !row.limits.is_empty() {
            println!(
                "{:<8} {:>4} {:<8} {}",
                row.direction.name(),
                row.size_mib,
                mode_name(row.class),
                row.limits
            );
        }
    }
    println!();
    println!("full: the part of the time with a full window. flight: the mean in flight.");
    println!("client: the transfer task, in threads. c.all: all client workers, in threads.");
    println!(
        "c.send, c.ans, c.recv: the task in its sends, its answers, and its received capsules."
    );
    println!("r.node: the busiest relay node task. r.all: all relay workers, in threads.");
    println!("step ms: the mean time of a CPUT or a CGET, from the link to its answer.");
    println!("stalls: the answers that held the task for {STALL:?} or more, with their time.");
    println!("limit: CPU at {SATURATED} of a thread, window at {WINDOW_BINDS} of the time.");
    println!("step time: no CPU and no window limit, thus the time of each step governs.");
}

/// The mean time of a `CPUT` or a `CGET`, in seconds.
fn mean_step(run: &Run, direction: Direction) -> f64 {
    let kind = main_kind(direction);
    let times: Vec<f64> = asked_of(&run.trace)
        .iter()
        .filter(|command| command.kind == kind)
        .filter_map(|command| {
            let end = command.answered?;
            Some(end.duration_since(command.sent).as_secs_f64())
        })
        .collect();

    times.iter().sum::<f64>() / times.len().max(1) as f64
}

fn limits_of(run: &Run, direction: Direction) -> String {
    let (from, to) = moving_span(run, direction);
    let load = load_between(&run.samples, from, to);
    let busiest = load.relay_nodes.iter().copied().fold(0.0, f64::max);
    let (full, flight) = window_use(run, direction);
    let parts = client_parts(&run.trace, from, to);
    let received = load.client_task - parts.send - parts.answers - parts.commands;

    format!(
        "{:>5.0}% {:>7.1} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.2} {:>7.0} {:>6} {:>7.2}  {}",
        full * 100.0,
        flight,
        load.client_task,
        parts.send,
        parts.answers,
        received.max(0.0),
        load.client_workers,
        busiest,
        load.relay_workers,
        mean_step(run, direction) * 1e3,
        parts.stalls,
        parts.stalled * to.duration_since(from).as_secs_f64(),
        verdict(&load, full, parts.stalled)
    )
}

/// All runs of one combination, inside the time limit.
fn run_combination(
    direction: Direction,
    size_mib: usize,
    class: DelayClass,
    plain: &[u8],
    options: &Options,
) -> Row {
    let start = Instant::now();
    let mut runs: Vec<Run> = Vec::new();
    let mut note = String::new();

    for attempt in 0..options.runs {
        // The time of an attempt holds its network and its seed upload.
        let spent = start.elapsed();
        let attempt_time = spent.as_secs_f64() / attempt.max(1) as f64;
        if attempt > 0 && spent.as_secs_f64() + attempt_time > options.cap.as_secs_f64() {
            note = format!("{attempt} of {} runs fit the limit", options.runs);
            break;
        }

        match measure(direction, class, plain, options.cap.saturating_sub(spent)) {
            Ok(run) => {
                let lost = run.lost_copies();
                println!(
                    "{} {size_mib} MiB {}: {:.2} s, {} chunks, {} repairs, {} faults, {} CGET, window {} at the peak, {} at the end{}",
                    direction.name(),
                    mode_name(class),
                    run.seconds,
                    run.chunks,
                    run.trace.repairs,
                    run.faults,
                    run.fetches(),
                    run.peak_window(),
                    run.final_window(),
                    if lost > 0 {
                        format!(", MARKED: {lost} lost copies")
                    } else {
                        String::new()
                    }
                );
                runs.push(run);
            }
            Err(Stop::Capped { done, total }) => {
                note = format!(
                    "stopped at the limit with {done} of {total} chunks done, in run {}",
                    attempt + 1
                );
                println!(
                    "{} {size_mib} MiB {}: {note}",
                    direction.name(),
                    mode_name(class)
                );
                break;
            }
            Err(Stop::Failed(cause)) => {
                note = format!("run {} ended: {cause}", attempt + 1);
                println!(
                    "{} {size_mib} MiB {}: {note}",
                    direction.name(),
                    mode_name(class)
                );
            }
        }
    }

    // A run that lost copies shows the ports of this machine, and not the
    // code. With no other run the marked runs stay.
    let marked = runs.iter().filter(|run| run.lost_copies() > 0).count();
    if marked > 0 {
        note = format!(
            "{marked} of {} runs marked: lost copies. {note}",
            runs.len()
        );
    }
    if marked < runs.len() {
        runs.retain(|run| run.lost_copies() == 0);
    }

    runs.sort_by(|a, b| a.seconds.total_cmp(&b.seconds));
    let median = runs.get(runs.len() / 2);
    Row {
        direction,
        size_mib,
        class,
        seconds: runs.iter().map(|run| run.seconds).collect(),
        window: median.map_or(0, Run::final_window),
        limits: median.map_or(String::new(), |run| limits_of(run, direction)),
        note,
    }
}

#[test]
#[ignore = "a measurement of minutes: run it in a release build"]
fn throughput_table() {
    let options = Options::read();
    let mut rows = Vec::new();

    // The time of a smaller file predicts the time of a larger one.
    let mut known: BTreeMap<(Direction, DelayClass), (usize, f64)> = BTreeMap::new();

    for size_mib in &options.sizes {
        let plain = file_of(*size_mib);

        for class in &options.modes {
            for direction in &options.directions {
                let predicted = known
                    .get(&(*direction, *class))
                    .map(|(size, seconds)| seconds * *size_mib as f64 / *size as f64);

                if let Some(predicted) = predicted {
                    if predicted > options.cap.as_secs_f64() {
                        println!(
                            "skip {} {size_mib} MiB {}: {predicted:.0} s predicted",
                            direction.name(),
                            mode_name(*class)
                        );
                        rows.push(Row {
                            direction: *direction,
                            size_mib: *size_mib,
                            class: *class,
                            seconds: Vec::new(),
                            window: 0,
                            limits: String::new(),
                            note: format!("skipped: {predicted:.0} s predicted"),
                        });
                        continue;
                    }
                }

                let row = run_combination(*direction, *size_mib, *class, &plain, &options);
                if !row.seconds.is_empty() {
                    let mut seconds = row.seconds.clone();
                    let median = median_of(&mut seconds);
                    known.insert((*direction, *class), (*size_mib, median));
                }
                rows.push(row);
            }
        }
    }

    print_table(&rows);
}

const STEP_NAMES: [&str; 6] = [
    "circuits",
    "CPUT",
    "CREP",
    "CVFY",
    "registrations",
    "tick wait",
];

fn step_of(kind: ChunkKind) -> Option<usize> {
    match kind {
        ChunkKind::Put => Some(1),
        ChunkKind::Replicate => Some(2),
        ChunkKind::Verify => Some(3),
        ChunkKind::Register => Some(4),
        _ => None,
    }
}

/// The spans of each step of an upload, in the seconds of the run.
fn spans_of(run: &Run, asked: &[Asked]) -> Vec<Span> {
    let at = |moment: Instant| moment.duration_since(run.started).as_secs_f64();
    let mut spans = Vec::new();

    for command in asked {
        let Some(kind) = step_of(command.kind) else {
            continue;
        };
        let answered = command.answered.unwrap_or(run.ended_at);

        // A held command waits for its circuit, then for its answer.
        let mut begin = command.sent;
        if let Some(released) = command.released {
            spans.push(Span {
                from: at(begin),
                to: at(released),
                kind: 0,
            });
            begin = released;
        }

        spans.push(Span {
            from: at(begin),
            to: at(answered),
            kind,
        });
    }

    for (from, to) in retry_waits(asked) {
        spans.push(Span {
            from: at(from),
            to: at(to),
            kind: 5,
        });
    }

    spans
}

fn print_row(name: &str, seconds: f64, total: f64) {
    println!(
        "  {name:<26} {seconds:>8.3} {:>6.1}%",
        seconds / total * 100.0
    );
}

fn print_latencies(run: &Run, asked: &[Asked]) {
    let at = |moment: Instant| moment.duration_since(run.started).as_secs_f64();
    println!();
    println!("The time of each command, from its entry into the link to its answer:");
    println!(
        "  {:<12} {:>6} {:>7} {:>8} {:>8} {:>8} {:>8} {:>9}",
        "command", "count", "refused", "mean ms", "p50 ms", "p95 ms", "max ms", "open s"
    );

    for (kind, name) in [
        (ChunkKind::Register, "CNEW"),
        (ChunkKind::Put, "CPUT"),
        (ChunkKind::Replicate, "CREP"),
        (ChunkKind::Verify, "CVFY"),
    ] {
        let of_kind: Vec<&Asked> = asked.iter().filter(|c| c.kind == kind).collect();
        let mut times: Vec<f64> = of_kind
            .iter()
            .filter_map(|c| {
                c.answered
                    .map(|end| end.duration_since(c.sent).as_secs_f64())
            })
            .collect();
        if times.is_empty() {
            continue;
        }
        times.sort_by(f64::total_cmp);

        let refused = of_kind.iter().filter(|c| c.is_refused).count();
        let spans: Vec<Span> = of_kind
            .iter()
            .filter_map(|c| {
                c.answered.map(|end| Span {
                    from: at(c.sent),
                    to: at(end),
                    kind: 0,
                })
            })
            .collect();
        let ms = |part: f64| times[((times.len() - 1) as f64 * part) as usize] * 1e3;
        let mean = times.iter().sum::<f64>() / times.len() as f64 * 1e3;

        println!(
            "  {name:<12} {:>6} {refused:>7} {mean:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>9.3}",
            of_kind.len(),
            ms(0.5),
            ms(0.95),
            ms(1.0),
            covered(&spans, 0.0, run.seconds)
        );
    }
}

fn print_breakdown(run: &Run, class: DelayClass) {
    let trace = &run.trace;
    let asked = asked_of(trace);
    let at = |moment: Option<Instant>| {
        moment.map_or(0.0, |m| m.duration_since(run.started).as_secs_f64())
    };
    let total = run.seconds;

    let connected = at(trace.connected);
    let first_circuit = at(trace.circuits.first().copied());
    let sealed = at(trace.sealed);
    let solved = at(trace.solved);
    let first_sent = at(trace.sent.first().map(|(sent, _)| *sent));
    let data_end = trace.manifest.map_or(total, |manifest| at(Some(manifest)));

    println!();
    println!(
        "An upload in {} mode, measured on loopback: {total:.3} s, {} chunks.",
        mode_name(class),
        run.chunks
    );
    println!(
        "  {:<26} {:>8} {:>7}",
        "step, one at a time", "seconds", "share"
    );
    print_row("dial and TLS", connected, total);
    print_row("first circuit", first_circuit - connected, total);
    print_row("seal", sealed - first_circuit, total);
    print_row("proof of work, ahead", solved - sealed, total);
    print_row("start of the first tick", first_sent - solved, total);

    let spans = spans_of(run, &asked);
    let data = exclusive(&spans, STEP_NAMES.len(), first_sent, data_end);
    for (name, seconds) in STEP_NAMES.iter().zip(&data) {
        print_row(&format!("data: {name}"), *seconds, total);
    }
    print_row("data: nothing open", data[STEP_NAMES.len()], total);

    let manifest = exclusive(&spans, STEP_NAMES.len(), data_end, total);
    for (name, seconds) in STEP_NAMES.iter().zip(&manifest) {
        print_row(&format!("manifest: {name}"), *seconds, total);
    }
    print_row("manifest: nothing open", manifest[STEP_NAMES.len()], total);

    print_latencies(run, &asked);

    let waits = retry_waits(&asked);
    let wait_spans: Vec<Span> = waits
        .iter()
        .map(|(from, to)| Span {
            from: at(Some(*from)),
            to: at(Some(*to)),
            kind: 0,
        })
        .collect();
    let wait_sum = wait_spans
        .iter()
        .fold(0.0, |sum, span| sum + span.to - span.from);

    println!();
    println!(
        "Proofs that waited for a tick: {}, {wait_sum:.3} s in sum, {:.3} s of the run.",
        waits.len(),
        covered(&wait_spans, 0.0, total)
    );
    println!(
        "Commands held for a circuit: {}, the last released at {:.3} s.",
        trace.released.len(),
        at(trace.released.last().map(|(released, _)| *released))
    );
    println!(
        "Threads for the proof of work: {}.",
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    );
    println!(
        "Solutions: {} ahead, {} at a send. Final window: {}. Repairs: {}. Faults: {}.",
        trace.solved_ahead,
        trace.solved_at_send,
        run.final_window(),
        trace.repairs,
        run.faults
    );

    let (full, flight) = window_use(run, Direction::Upload);
    let (from, to) = moving_span(run, Direction::Upload);
    let load = load_between(&run.samples, from, to);
    println!(
        "While the CPUT commands moved: window full {:.0}% of the time, {flight:.1} in flight.",
        full * 100.0
    );
    println!(
        "Threads in use: client task {:.2}, client workers {:.2}, relay workers {:.2}.",
        load.client_task, load.client_workers, load.relay_workers
    );
    let parts = client_parts(trace, from, to);
    println!(
        "Client task, in threads: sends {:.2}, answers {:.2}, commands {:.2}, received capsules {:.2}.",
        parts.send,
        parts.answers,
        parts.commands,
        (load.client_task - parts.send - parts.answers - parts.commands).max(0.0)
    );
    println!(
        "Answers that held the task for {STALL:?} or more: {}, {:.3} s in sum.",
        parts.stalls,
        parts.stalled * to.duration_since(from).as_secs_f64()
    );
    let nodes: Vec<String> = load
        .relay_nodes
        .iter()
        .map(|load| format!("{load:.2}"))
        .collect();
    println!("Relay node tasks, each: {}.", nodes.join(" "));
}

#[test]
#[ignore = "a measurement of a minute: run it in a release build"]
fn upload_breakdown() {
    let options = Options::read();
    let class = mode_of(&listed("UMBRA_BENCH_BREAKDOWN_MODE", "fast")[0]);
    let size_mib = listed("UMBRA_BENCH_BREAKDOWN_MIB", "8")[0].parse().unwrap();
    let plain = file_of(size_mib);

    for _ in 0..options.runs {
        match measure(Direction::Upload, class, &plain, options.cap) {
            Ok(run) => print_breakdown(&run, class),
            Err(stop) => println!("the run ended: {stop:?}"),
        }
    }
}

/// One `CGET` with the service of its chunk at the relay.
struct Fetched {
    sent: Instant,
    served: Instant,
    answered: Instant,
    in_cell: u32,
}

/// Each answered `CGET` of `run`, with the first service of its chunk after
/// its send.
fn fetched_of(run: &Run, hops: &HopTrace) -> Vec<Fetched> {
    let mut served: BTreeMap<[u8; 32], Vec<(Instant, u32)>> = BTreeMap::new();
    for stamp in &hops.served {
        served
            .entry(stamp.chunk_id)
            .or_default()
            .push((stamp.at, stamp.in_cell));
    }

    asked_of(&run.trace)
        .iter()
        .filter(|command| command.kind == ChunkKind::Fetch)
        .filter_map(|command| {
            let answered = command.answered?;
            let services = served.get(&command.chunk.0)?;
            let (at, in_cell) = services
                .iter()
                .find(|(at, _)| *at >= command.sent && *at <= answered)?;
            Some(Fetched {
                sent: command.sent,
                served: *at,
                answered,
                in_cell: *in_cell,
            })
        })
        .collect()
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let (sum, count) = values.fold((0.0, 0usize), |(sum, count), value| {
        (sum + value, count + 1)
    });
    sum / count.max(1) as f64
}

/// A draw of the model, from an exponential distribution.
struct ModelRng(u64);

impl ModelRng {
    fn exponential(&mut self, mean: f64) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        let uniform = ((self.0 >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
        -mean * uniform.ln()
    }
}

/// The mean hold at each of three hops in the model of §12.7.2: Poisson
/// cells at `rate` on one circuit, an exponential draw with `mean_s` at
/// each hop, and no release before the cell ahead (`NET-339`).
fn model_holds(rate: f64, mean_s: f64) -> [f64; 3] {
    const CELLS: usize = 200_000;
    let mut rng = ModelRng(0x9E37_79B9_7F4A_7C15);
    let mut arrivals = Vec::with_capacity(CELLS);
    let mut at = 0.0;
    for _ in 0..CELLS {
        at += rng.exponential(1.0 / rate);
        arrivals.push(at);
    }

    let mut holds = [0.0; 3];
    for hold in &mut holds {
        let mut released = 0.0f64;
        let mut sum = 0.0;
        for arrival in &mut arrivals {
            released = released.max(*arrival + rng.exponential(mean_s));
            sum += released - *arrival;
            *arrival = released;
        }
        *hold = sum / CELLS as f64;
    }

    holds
}

fn print_download_breakdown(run: &Run, hops: &HopTrace, class: DelayClass) {
    let fetched = fetched_of(run, hops);
    let (from, to) = moving_span(run, Direction::Download);
    let span = to.duration_since(from).as_secs_f64().max(1e-9);
    let seconds = |from: Instant, to: Instant| to.saturating_duration_since(from).as_secs_f64();
    let exits: std::collections::BTreeSet<[u8; 32]> = asked_of(&run.trace)
        .iter()
        .filter(|command| command.kind == ChunkKind::Fetch)
        .map(|command| command.chunk.1)
        .collect();

    println!();
    println!(
        "A download in {} mode, measured on loopback: {:.3} s, {} chunks, {} CGET matched.",
        mode_name(class),
        run.seconds,
        run.chunks,
        fetched.len()
    );
    let step = mean(fetched.iter().map(|f| seconds(f.sent, f.answered)));
    let forward = mean(fetched.iter().map(|f| seconds(f.sent, f.served)));
    let back = mean(fetched.iter().map(|f| seconds(f.served, f.answered)));
    let per_cell = mean(fetched.iter().map(|f| f64::from(f.in_cell)));
    println!("  step, from the link to the answer   {:>8.3} s", step);
    println!("  forward, from the link to the relay {:>8.3} s", forward);
    println!("  back, from the relay to the answer  {:>8.3} s", back);
    println!("  CGET in the cell of a CGET          {per_cell:>8.2}");

    let mean_s = class.mean_ms() as f64 / 1e3;
    println!();
    println!(
        "  {:<6} {:>7} {:>7} {:>8} {:>8} {:>8} {:>8} {:>9} {:>9}",
        "hop",
        "cells",
        "cell/s",
        "draw ms",
        "hold ms",
        "extra ms",
        "late ms",
        "circuits",
        "model ms"
    );
    let mut held_total = 0.0;
    let mut cells_at_exit = 0usize;
    for layer in 1..=3u8 {
        let in_span = |at: Instant| at >= from && at <= to;
        let drawn: Vec<_> = hops
            .drawn
            .iter()
            .filter(|stamp| stamp.layer == layer && in_span(stamp.at))
            .collect();
        let released: Vec<_> = hops
            .released
            .iter()
            .filter(|stamp| stamp.layer == layer && in_span(stamp.at))
            .collect();
        let draw = mean(drawn.iter().map(|stamp| stamp.draw_ms as f64));
        let hold = mean(drawn.iter().map(|stamp| stamp.hold_ms as f64));
        let late = mean(released.iter().map(|stamp| stamp.late_ms as f64));
        held_total += (hold + late) / 1e3;
        if layer == 3 {
            cells_at_exit = drawn.len();
        }

        let circuits = exits.len().max(1);
        let rate = drawn.len() as f64 / span / circuits as f64;
        let model = model_holds(rate, mean_s);
        println!(
            "  {layer:<6} {:>7} {:>7.2} {draw:>8.0} {hold:>8.0} {:>8.0} {late:>8.0} {circuits:>9} {:>9.0}",
            drawn.len(),
            rate,
            hold - draw,
            model[usize::from(layer) - 1] * 1e3
        );
    }

    let rate = cells_at_exit as f64 / span / exits.len().max(1) as f64;
    let model: f64 = model_holds(rate, mean_s).iter().sum();
    println!();
    println!(
        "  held at the three hops, with the clock {:>8.3} s",
        held_total
    );
    println!(
        "  the rest of the forward time          {:>8.3} s",
        forward - held_total
    );
    println!(
        "  model of the three hops at {rate:.2} cells/s on each circuit: {model:.3} s, and {:.3} s for one cell alone",
        3.0 * mean_s
    );
    let (full, flight) = window_use(run, Direction::Download);
    println!(
        "  window full {:.0}% of the time, {flight:.1} in flight, {:.2} CGET/s",
        full * 100.0,
        fetched.len() as f64 / span
    );
}

#[test]
#[ignore = "a measurement of minutes: run it in a release build"]
fn download_breakdown() {
    let options = Options::read();
    let class = mode_of(&listed("UMBRA_BENCH_BREAKDOWN_MODE", "private")[0]);
    let size_mib = listed("UMBRA_BENCH_BREAKDOWN_MIB", "8")[0].parse().unwrap();
    let plain = file_of(size_mib);

    for _ in 0..options.runs {
        pace_big_run(plain.len());
        let bench = Bench::start();
        let Ok((_, descriptor)) = bench.upload(DelayClass::Fast, &plain, options.cap, false) else {
            println!("the upload ended");
            continue;
        };

        hops::start();
        let downloaded = bench.download(class, descriptor, &plain, options.cap);
        let trace = hops::take();
        match downloaded {
            Ok(run) => print_download_breakdown(&run, &trace, class),
            Err(stop) => println!("the run ended: {stop:?}"),
        }
    }
}

#[test]
fn the_steps_of_a_run_add_up_to_the_run() {
    let span = |from, to, kind| Span { from, to, kind };
    let spans = [span(1.0, 4.0, 1), span(2.0, 3.0, 0), span(6.0, 7.0, 1)];

    let totals = exclusive(&spans, 2, 0.0, 10.0);

    assert_eq!(totals, vec![1.0, 3.0, 6.0]);
    assert_eq!(covered(&spans, 0.0, 10.0), 4.0);
}
