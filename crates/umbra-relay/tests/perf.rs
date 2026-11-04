//! The cost of the cell path, the queue store, and the chunk store of a
//! relay. Each test is `#[ignore]`, and each one prints what it measured.
//!
//! `cargo test --release -p umbra-relay --features native --test perf --
//! --ignored --nocapture --test-threads=1`

#![cfg(feature = "native")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::TcpListener as StdListener,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    runtime::Builder,
};
use umbra_core::attach::store::{Class, Credentials, HeldChunk};
use umbra_crypto::{
    auth::CommandAuthKey,
    handshake::nk::RelayStatic,
    rand_core::TryRng,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_onion::{
    build::{build_cell_body, read_cell_body, DelayClass, Pending, BUILD_BUCKET, HELLO_LEN},
    circuit::MeasureCircuit,
    layer::KeySet,
};
use umbra_queue::relay::Stored;
use umbra_relay::{
    circuits::{CircuitKey, LinkId},
    node::{Backlog, Config, Output, RelayNode},
    server::{run_relay, tls_acceptor, Carried, OsRng},
    sqlite_store::SqliteStore,
    store::{MemoryStore, RelayStore, StoreChange},
};
use umbra_transport::{
    link::{ClientLink, RelayLink},
    native::{self, TcpLink},
    upgrade, websocket, Dial,
};
use umbra_wire::{
    admission::Admission,
    bucket::Bucket,
    capsule,
    cell::{pad_body, unpad_body, Cell, CellCommand},
    command::{Cmd, Command, IdsPayload, NewPayload},
    session::SessionControl,
};

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];
/// The cells between two calls that close a group of inputs, as the node
/// task does (`INPUTS_PER_COMMIT`).
const GROUP: u32 = 64;
const NOW: u64 = 1_800_000_000;
/// The link of the peer before this relay.
const BEFORE: LinkId = 1;
/// The link to the next relay.
const NEXT: LinkId = 2;

fn fixture(name: &str) -> String {
    format!(
        "{}/../../tests/fixtures/tls/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn relay_static(seed: u8) -> (RelayStatic, StaticSecret) {
    let secret = StaticSecret::from([seed; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&secret).as_bytes(),
        relay_id: [seed; 32],
    };

    (relay, secret)
}

/// A link that the writer of the runtime keeps empty.
struct Calm;

impl Backlog for Calm {
    fn of(&self, _link: LinkId) -> Option<(usize, usize)> {
        Some((0, 64 << 20))
    }
}

/// The plain build cell of a hello to `relay` on `circ_id`.
fn hello_cell(relay: &RelayStatic, circ_id: [u8; 16], class: DelayClass) -> (Vec<u8>, Pending) {
    let mut hello = [0u8; HELLO_LEN];
    let pending = Pending::hello(relay, class, &mut OsRng, &mut hello).unwrap();

    let mut body = vec![0u8; BUILD_BUCKET.body_len()];
    build_cell_body(CellCommand::Extend, &hello, &mut body).unwrap();

    ([circ_id.as_slice(), &[0; 16], &body].concat(), pending)
}

/// The `EXTEND` cell to `next` under the layer of the hop that answered
/// with the cell `answer`. The layer of a relay of layer 2 takes hop index
/// 2, and a measurement circuit names that index.
fn extend_cell(answer: &[u8], pending: Pending, next: &RelayStatic) -> Vec<u8> {
    let (parsed, _) = Cell::parse(answer).unwrap();
    let (_, reply) = read_cell_body(parsed.body).unwrap();
    let ss_hop = pending.finish(reply).unwrap();
    let mut hop = MeasureCircuit::new(&ss_hop, 2, *parsed.circ_id);

    let (cell, _) = hello_cell(next, *parsed.circ_id, DelayClass::Fast);
    let mut body = cell[32..].to_vec();
    let tag = hop.seal(&mut body).unwrap();
    [parsed.circ_id.as_slice(), &tag, &body].concat()
}

/// The cell that a capsule of a link carries.
fn cell_of(link: &mut ClientLink, capsule_bytes: &[u8]) -> Vec<u8> {
    let (_, value, _) = capsule::parse(capsule_bytes).unwrap();
    link.receive(value).unwrap().unwrap().to_vec()
}

/// A relay of layer 2 with `circuits` circuits from `BEFORE` to `NEXT`.
struct Middle {
    node: RelayNode,
    client: ClientLink,
    /// The session of the next relay, for a cell that comes back.
    next: RelayLink,
    /// The identifier of each circuit on `BEFORE`.
    before: Vec<[u8; 16]>,
    /// The identifier of each circuit on `NEXT`.
    after: Vec<[u8; 16]>,
}

impl Middle {
    fn new(circuits: usize, class: DelayClass) -> Self {
        let (relay, static_secret) = relay_static(0x22);
        let (next_relay, _) = relay_static(0x33);
        let for_client = RelayStatic {
            s: relay.s,
            relay_id: relay.relay_id,
        };

        let mut node = RelayNode::new(Config {
            relay,
            static_secret,
            layer: 2,
            chunk_capacity: 0,
        });
        node.set_backlog(Box::new(Calm));

        let mut buffer = vec![0u8; 40_000];
        let (mut client, used) =
            ClientLink::open([1; 8], Secret::new([2; 32]), &mut buffer).unwrap();
        assert!(node
            .on_capsule(BEFORE, &buffer[..used], NOW, &mut OsRng)
            .is_empty());

        let outputs = node.dialed(
            NEXT,
            next_relay.relay_id,
            [9; 8],
            Secret::new([8; 32]),
            NOW,
            &mut OsRng,
        );
        let Output::Send { capsule: open, .. } = &outputs[0] else {
            panic!("no open");
        };
        let (_, value, _) = capsule::parse(open).unwrap();
        let mut next = RelayLink::open(SessionControl::parse(value).unwrap()).unwrap();

        let mut before = Vec::new();
        let mut after = Vec::new();

        for index in 0..circuits {
            let mut circ_id = [0xC0; 16];
            circ_id[..8].copy_from_slice(&(index as u64).to_be_bytes());

            let (cell, pending) = hello_cell(&for_client, circ_id, class);
            let used = client.send(&cell, &mut buffer).unwrap();
            let outputs = node.on_capsule(BEFORE, &buffer[..used], NOW, &mut OsRng);

            let Output::Send { capsule, .. } = &outputs[0] else {
                panic!("no answer");
            };
            let answer = cell_of(&mut client, capsule);

            let cell = extend_cell(&answer, pending, &next_relay);
            let used = client.send(&cell, &mut buffer).unwrap();

            let mut outputs = node.on_capsule(BEFORE, &buffer[..used], NOW, &mut OsRng);
            outputs.extend(node.release_delayed(u64::MAX, NOW, &mut OsRng));

            let Output::Send { capsule, .. } = &outputs[0] else {
                panic!("no extend");
            };
            let (_, value, _) = capsule::parse(capsule).unwrap();
            let cell = next.receive(value).unwrap().unwrap();

            // The first cell of the next hop is the answer to its build,
            // and it ends the `extending` state of the circuit.
            let circ_after: [u8; 16] = cell[..16].try_into().unwrap();
            let answer = [
                circ_after.as_slice(),
                &[0; 16],
                &vec![0u8; BUILD_BUCKET.body_len()],
            ]
            .concat();
            let used = next.send(&answer, &mut buffer).unwrap();
            node.on_capsule(NEXT, &buffer[..used], NOW, &mut OsRng);

            before.push(circ_id);
            after.push(circ_after);
        }

        node.flushed();
        Middle {
            node,
            client,
            next,
            before,
            after,
        }
    }

    /// Takes `count` capsules of `template` on `link`. Each one takes the
    /// next `seq` from `seq` and the next circuit of `circuits`. Gives the
    /// nanoseconds of one cell.
    fn run(
        &mut self,
        link: LinkId,
        template: &mut [u8],
        circuits: &[[u8; 16]],
        mut seq: u32,
        count: u32,
    ) -> f64 {
        let start = Instant::now();

        for index in 0..count {
            template[14..17].copy_from_slice(&seq.to_be_bytes()[1..]);
            seq += 1;

            let circuit = &circuits[index as usize % circuits.len()];
            template[18..34].copy_from_slice(circuit);

            let outputs = self.node.on_capsule(link, template, NOW, &mut OsRng);
            drop(outputs);

            if index % GROUP == 0 {
                let due = self.node.release_delayed(u64::MAX, NOW, &mut OsRng);
                drop(due);
                drop(self.node.take_changes());
                self.node.flushed();
            }
        }

        let due = self.node.release_delayed(u64::MAX, NOW, &mut OsRng);
        drop(due);
        start.elapsed().as_nanos() as f64 / f64::from(count)
    }
}

/// The cells that one round of the node takes in a bucket.
fn node_cells(bucket: Bucket) -> u32 {
    match bucket {
        Bucket::B0 => 200_000,
        Bucket::B1 => 120_000,
        Bucket::B2 => 50_000,
        Bucket::B3 => 15_000,
    }
}

/// The rounds of one bucket. The lowest round is the one that other work of
/// the machine touched the least.
const NODE_ROUNDS: u32 = 15;

/// The lowest and the median nanoseconds of one cell, forward and backward.
fn node_run(bucket: Bucket, class: DelayClass) -> [(f64, f64); 2] {
    const CIRCUITS: usize = 1_024;

    let mut middle = Middle::new(CIRCUITS, class);
    let count = node_cells(bucket);
    let cell = vec![0x5Au8; bucket.cell_len()];
    let mut buffer = vec![0u8; 40_000];

    let used = middle.client.send(&cell, &mut buffer).unwrap();
    let mut forward_template = buffer[..used].to_vec();
    let before = middle.before.clone();
    let mut forward_seq = middle.client.next_seq();

    let used = middle.next.send(&cell, &mut buffer).unwrap();
    let mut backward_template = buffer[..used].to_vec();
    let after = middle.after.clone();
    let mut backward_seq = CIRCUITS as u32;

    let mut forward = Vec::new();
    let mut backward = Vec::new();

    for _ in 0..NODE_ROUNDS {
        forward.push(middle.run(BEFORE, &mut forward_template, &before, forward_seq, count));
        forward_seq += count;

        backward.push(middle.run(NEXT, &mut backward_template, &after, backward_seq, count));
        backward_seq += count;
    }

    let lowest = |values: &[f64]| values.iter().copied().fold(f64::MAX, f64::min);
    [
        (lowest(&forward), median(forward)),
        (lowest(&backward), median(backward)),
    ]
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

#[test]
#[ignore = "a timing run"]
fn perf_a_cell_at_one_hop_in_the_node() {
    for (name, class) in [
        ("fast", DelayClass::Fast),
        ("balanced", DelayClass::Balanced),
    ] {
        for bucket in BUCKETS {
            let [forward, backward] = node_run(bucket, class);
            println!(
                "node {name} {bucket:?}: forward low {:.0} ns median {:.0} ns, backward low \
                 {:.0} ns median {:.0} ns",
                forward.0, forward.1, backward.0, backward.1
            );
        }
    }
}

/// The two ends of one TLS session, after its handshake.
fn tls_pair() -> (rustls::ClientConnection, rustls::ServerConnection) {
    let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
    let acceptor = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut client = rustls::ClientConnection::new(trust, name).unwrap();
    let mut server = rustls::ServerConnection::new(acceptor.config().clone()).unwrap();

    while client.is_handshaking() || server.is_handshaking() {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets().unwrap();

        let mut wire = Vec::new();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut wire.as_slice()).unwrap();
        client.process_new_packets().unwrap();
    }

    (client, server)
}

#[test]
#[ignore = "a timing run"]
fn perf_the_tls_records_of_one_cell() {
    let (mut client, mut server) = tls_pair();
    let suite = client.negotiated_cipher_suite().unwrap().suite();
    println!("tls suite: {suite:?}");

    for bucket in BUCKETS {
        let frame = vec![0xA5u8; bucket.cell_len() + 22];
        let mut plain = vec![0u8; frame.len()];
        let mut wire = Vec::with_capacity(frame.len() * 2);
        let count = u32::try_from((1 << 30) / frame.len()).unwrap().min(400_000);
        let mut seal = Duration::ZERO;
        let mut open = Duration::ZERO;

        for _ in 0..count {
            wire.clear();

            let start = Instant::now();
            client.writer().write_all(&frame).unwrap();
            client.write_tls(&mut wire).unwrap();
            seal += start.elapsed();

            let start = Instant::now();
            let mut source = wire.as_slice();
            while !source.is_empty() {
                server.read_tls(&mut source).unwrap();
                server.process_new_packets().unwrap();
            }
            server.reader().read_exact(&mut plain).unwrap();
            open += start.elapsed();
        }

        let seal = seal.as_nanos() as f64 / f64::from(count);
        let open = open.as_nanos() as f64 / f64::from(count);
        println!("tls {bucket:?}: seal {seal:.0} ns, open {open:.0} ns");
    }
}

/// What stops and counts one socket run.
#[derive(Default)]
struct Run {
    stop: AtomicBool,
    /// The cells that left for the relay.
    sent: AtomicU64,
    /// The cells that reached the far end of the relay.
    cells: AtomicU64,
    /// Each load connection holds its circuits, and the cells start.
    go: AtomicBool,
    /// The circuits of the next hop that hold their first answer.
    extended: AtomicU64,
    /// The circuits of the run. A sink sends after each one holds its first
    /// answer. A cell before that moves no circuit of the run.
    circuits: AtomicU64,
}

impl Run {
    fn is_built(&self) -> bool {
        let extended = self.extended.load(Ordering::Relaxed);
        extended > 0 && extended >= self.circuits.load(Ordering::Relaxed)
    }

    /// Waits while `flight` cells or more are inside the relay. A run that
    /// fills a link above its mark ends circuits (`NET-349`), thus the
    /// load stays below it, and the rate is the one of the relay.
    async fn pace(&self, flight: u64) {
        loop {
            let sent = self.sent.load(Ordering::Relaxed);
            let arrived = self.cells.load(Ordering::Relaxed);
            if sent.saturating_sub(arrived) < flight {
                return;
            }

            tokio::task::yield_now().await;
        }
    }
}

/// The bytes that one run holds inside the relay, far below the mark of a
/// link.
const FLIGHT_BYTES: u64 = 8 << 20;
/// The frames that the sink sends in one write of its socket.
const SINK_GROUP: usize = 32;

fn flight_of(bucket: Bucket) -> u64 {
    FLIGHT_BYTES / bucket.cell_len() as u64
}

/// A socket that holds what a TLS session writes until a flush. Each frame
/// of the sink takes its own record, and the sink is no limit of a run.
struct Held<S> {
    stream: S,
    held: Vec<u8>,
    written: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for Held<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Held<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().held.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.written < this.held.len() {
            let rest = &this.held[this.written..];
            this.written += ready!(Pin::new(&mut this.stream).poll_write(cx, rest))?;
        }

        this.held.clear();
        this.written = 0;
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

type SinkStream = tokio_rustls::server::TlsStream<Held<TcpStream>>;

/// The direction of one socket run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Way {
    /// From an accepted link to a dialed link.
    Forward,
    /// From a dialed link to an accepted link.
    Backward,
}

/// The circuits of one load connection. A circuit carries 8 192 cells, and
/// a run sends fewer than these circuits hold.
const LOAD_CIRCUITS: usize = 256;
/// The links and the circuits of each link of a run with a link for each
/// few cells, as a relay with many clients has.
const FAN_LINKS: u8 = 64;
const FAN_CIRCUITS: usize = 32;
/// The load connections of one run.
const LOAD_LINKS: u8 = 8;
const WARM: Duration = Duration::from_secs(1);
const WINDOW: Duration = Duration::from_secs(4);

/// Builds `LOAD_CIRCUITS` circuits on a new connection, and gives the
/// link, its session, and the `circ_id` of each circuit.
async fn load_link(
    dial: &Dial,
    seed: u8,
    circuit_count: usize,
) -> (TcpLink, ClientLink, Vec<[u8; 16]>) {
    let (relay, _) = relay_static(0x22);
    let (next_relay, _) = relay_static(0x33);
    let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
    let mut tcp = TcpLink::connect(dial, trust, [seed; 16], [seed; 4])
        .await
        .unwrap();

    let mut buffer = vec![0u8; 40_000];
    let (mut client, used) =
        ClientLink::open([seed; 8], Secret::new([seed; 32]), &mut buffer).unwrap();
    tcp.send(&buffer[..used]).await.unwrap();

    let mut circuits = Vec::new();
    for index in 0..circuit_count {
        let mut circ_id = [seed; 16];
        circ_id[..8].copy_from_slice(&(index as u64).to_be_bytes());

        let (cell, pending) = hello_cell(&relay, circ_id, DelayClass::Fast);
        let used = client.send(&cell, &mut buffer).unwrap();
        tcp.send(&buffer[..used]).await.unwrap();

        // The answer of the next hop to an earlier circuit can come first,
        // and only the plain answer of this hop holds a zero tag.
        let answer = loop {
            let capsule = tcp.recv().await.unwrap();
            if capsule::parse(&capsule).unwrap().0 != capsule::CapsuleType::Cell {
                continue;
            }

            let cell = cell_of(&mut client, &capsule);
            if cell.len() == BUILD_BUCKET.cell_len() && cell[16..32] == [0; 16] {
                break cell;
            }
        };

        let cell = extend_cell(&answer, pending, &next_relay);
        let used = client.send(&cell, &mut buffer).unwrap();
        tcp.send(&buffer[..used]).await.unwrap();

        circuits.push(circ_id);
    }

    (tcp, client, circuits)
}

/// Sends cells of `bucket` on each circuit in turns, until the run stops.
async fn blast(
    link: TcpLink,
    mut client: ClientLink,
    circuits: Vec<[u8; 16]>,
    bucket: Bucket,
    run: Arc<Run>,
) {
    let (mut reader, mut writer) = link.split();
    let counter = run.clone();
    let way_back = tokio::spawn(async move {
        while let Ok(capsule) = reader.recv().await {
            if capsule.len() == bucket.cell_len() + 18 {
                counter.cells.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    while !run.go.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let cell = vec![0x5Au8; bucket.cell_len()];
    let mut buffer = vec![0u8; 40_000];
    let mut index = 0usize;

    while !run.stop.load(Ordering::Relaxed) {
        run.pace(flight_of(bucket)).await;

        let circuit = &circuits[index % circuits.len()];
        index = index.wrapping_add(1);

        let used = client.send(&cell, &mut buffer).unwrap();
        buffer[18..34].copy_from_slice(circuit);
        let capsule = vec![buffer[..used].to_vec()];
        if writer.send_all(&capsule).await.is_err() {
            break;
        }

        run.sent.fetch_add(1, Ordering::Relaxed);
    }

    way_back.abort();
}

/// The relay of the next layer. It takes each connection of the relay under
/// test, answers each new circuit once, and counts the cells that arrive. A
/// run `Backward` sends cells on each circuit in turns.
async fn sink(listener: TcpListener, bucket: Bucket, way: Way, run: Arc<Run>) {
    let acceptor = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();

    loop {
        let (tcp, _) = listener.accept().await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let acceptor = acceptor.clone();
        let run = run.clone();
        tokio::spawn(async move {
            let tcp = Held {
                stream: tcp,
                held: Vec::new(),
                written: 0,
            };
            let stream = acceptor.accept(tcp).await.unwrap();
            let _ = sink_link(stream, bucket, way, run).await;
        });
    }
}

async fn sink_link(mut stream: SinkStream, bucket: Bucket, way: Way, run: Arc<Run>) -> Option<()> {
    let mut inbound = Vec::new();
    let mut chunk = vec![0u8; 1 << 16];

    let request = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        inbound.extend_from_slice(&chunk[..n]);
        if let Ok(Some((request, used))) = upgrade::parse_request(&inbound) {
            inbound.drain(..used);
            break request;
        }
    };

    stream
        .write_all(upgrade::response(&request.key).as_bytes())
        .await
        .ok()?;
    stream.flush().await.ok()?;

    let (mut reader, writer) = tokio::io::split(stream);
    let (ids, new_ids) = tokio::sync::mpsc::unbounded_channel::<[u8; 16]>();
    let (opened, is_open) = tokio::sync::oneshot::channel::<RelayLink>();
    let back_run = run.clone();
    tokio::spawn(sink_writer(writer, new_ids, is_open, bucket, way, back_run));

    let mut opened = Some(opened);
    let mut link: Option<RelayLink> = None;
    let mut out = vec![0u8; 40_000];

    loop {
        let mut taken = 0usize;
        while let Ok(Some((len, used))) = websocket::decode(&inbound[taken..], true, &mut out) {
            taken += used;
            let (kind, value, _) = capsule::parse(&out[..len]).ok()?;

            if kind == capsule::CapsuleType::Session {
                let Ok(control) = SessionControl::parse(value) else {
                    continue;
                };

                if matches!(control, SessionControl::Open { .. }) {
                    let SessionControl::Open {
                        session_id,
                        session_secret,
                    } = control
                    else {
                        continue;
                    };

                    let again = SessionControl::Open {
                        session_id,
                        session_secret: Secret::new(*session_secret.expose()),
                    };
                    let _ = opened.take()?.send(RelayLink::open(again).ok()?);
                    link = RelayLink::open(SessionControl::Open {
                        session_id,
                        session_secret,
                    })
                    .ok();
                }

                continue;
            }

            if kind != capsule::CapsuleType::Cell {
                continue;
            }

            let cell = link.as_mut()?.receive(value).ok()??;
            if cell.len() == BUILD_BUCKET.cell_len() {
                let _ = ids.send(cell[..16].try_into().ok()?);
            }

            if cell.len() == bucket.cell_len() && way == Way::Forward {
                run.cells.fetch_add(1, Ordering::Relaxed);
            }
        }

        inbound.drain(..taken);

        let n = reader.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        inbound.extend_from_slice(&chunk[..n]);
    }
}

async fn sink_writer(
    mut writer: tokio::io::WriteHalf<SinkStream>,
    mut new_ids: tokio::sync::mpsc::UnboundedReceiver<[u8; 16]>,
    is_open: tokio::sync::oneshot::Receiver<RelayLink>,
    bucket: Bucket,
    way: Way,
    run: Arc<Run>,
) -> Option<()> {
    let mut link = is_open.await.ok()?;
    let mut circuits: Vec<[u8; 16]> = Vec::new();
    let answer = vec![0u8; BUILD_BUCKET.cell_len()];
    let cell = vec![0x5Au8; bucket.cell_len()];
    let mut buffer = vec![0u8; 40_000];
    let mut frame = vec![0u8; 40_000];
    let mut index = 0usize;

    // The sink answers each build.
    while !run.is_built() {
        let circ_id = new_ids.recv().await?;
        let mut first = answer.clone();
        first[..16].copy_from_slice(&circ_id);
        circuits.push(circ_id);
        run.extended.fetch_add(1, Ordering::Relaxed);

        let used = link.send(&first, &mut buffer).ok()?;
        let n = websocket::encode(&buffer[..used], None, &mut frame).ok()?;
        writer.write_all(&frame[..n]).await.ok()?;
        writer.flush().await.ok()?;
    }

    while way == Way::Backward && !run.stop.load(Ordering::Relaxed) {
        for _ in 0..SINK_GROUP {
            run.pace(flight_of(bucket)).await;

            let circuit = circuits[index % circuits.len()];
            index = index.wrapping_add(1);
            let used = link.send(&cell, &mut buffer).ok()?;
            buffer[18..34].copy_from_slice(&circuit);

            let n = websocket::encode(&buffer[..used], None, &mut frame).ok()?;
            writer.write_all(&frame[..n]).await.ok()?;
            run.sent.fetch_add(1, Ordering::Relaxed);
        }

        writer.flush().await.ok()?;
    }

    new_ids.recv().await?;
    None
}

/// Runs one relay on `relay_threads` threads, and gives the cells of
/// `bucket` that it moves in one second.
fn socket_run(
    bucket: Bucket,
    way: Way,
    connections: u8,
    circuit_count: usize,
    relay_threads: usize,
) -> f64 {
    let run = Arc::new(Run {
        circuits: AtomicU64::new(u64::from(connections) * circuit_count as u64),
        ..Run::default()
    });

    let sink_port = StdListener::bind("127.0.0.1:0").unwrap();
    let sink_addr = sink_port.local_addr().unwrap();
    sink_port.set_nonblocking(true).unwrap();
    let relay_port = StdListener::bind("127.0.0.1:0").unwrap();
    let relay_addr = relay_port.local_addr().unwrap();
    relay_port.set_nonblocking(true).unwrap();

    let dial_of = |port: u16| Dial {
        host: "localhost".to_owned(),
        addr_v4: Some([127, 0, 0, 1]),
        addr_v6: None,
        port,
    };
    let (next_relay, _) = relay_static(0x33);
    let next_hops = BTreeMap::from([(next_relay.relay_id, dial_of(sink_addr.port()))]);

    // The relay runs on threads of its own. Thus the load and the sink
    // take no time of it.
    let relay_thread = std::thread::spawn(move || {
        let runtime = if relay_threads == 1 {
            Builder::new_current_thread().enable_all().build().unwrap()
        } else {
            Builder::new_multi_thread()
                .worker_threads(relay_threads)
                .enable_all()
                .build()
                .unwrap()
        };

        runtime.block_on(async move {
            let (relay, static_secret) = relay_static(0x22);
            let node = RelayNode::new(Config {
                relay,
                static_secret,
                layer: 2,
                chunk_capacity: 0,
            });
            let listener = TcpListener::from_std(relay_port).unwrap();
            let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
            let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
            let store = Box::new(MemoryStore::default());
            let relay = run_relay(
                node,
                listener,
                tls,
                next_hops,
                BTreeMap::new(),
                trust,
                1_000,
                store,
                Carried::default(),
            );

            // The run ends with the process of the test.
            let _ = tokio::time::timeout(WARM * 40, relay).await;
        });
    });

    let load = Builder::new_multi_thread()
        .worker_threads(12)
        .enable_all()
        .build()
        .unwrap();

    let rate = load.block_on(async {
        let listener = TcpListener::from_std(sink_port).unwrap();
        tokio::spawn(sink(listener, bucket, way, run.clone()));

        let dial = dial_of(relay_addr.port());
        for seed in 0..connections {
            let (link, client, circuits) = load_link(&dial, 0x40 + seed, circuit_count).await;
            if way == Way::Forward {
                tokio::spawn(blast(link, client, circuits, bucket, run.clone()));
            } else {
                let (mut reader, writer) = link.split();
                let counter = run.clone();
                tokio::spawn(async move {
                    let _held = writer;
                    while let Ok(capsule) = reader.recv().await {
                        if capsule.len() == bucket.cell_len() + 18 {
                            counter.cells.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        }

        while !run.is_built() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        run.go.store(true, Ordering::Relaxed);
        tokio::time::sleep(WARM).await;
        let first = run.cells.load(Ordering::Relaxed);
        let start = Instant::now();
        tokio::time::sleep(WINDOW).await;
        let last = run.cells.load(Ordering::Relaxed);
        let rate = (last - first) as f64 / start.elapsed().as_secs_f64();
        run.stop.store(true, Ordering::Relaxed);
        rate
    });

    load.shutdown_background();
    drop(relay_thread);
    rate
}

#[test]
#[ignore = "a timing run"]
fn perf_a_relay_on_one_thread_over_loopback() {
    for bucket in BUCKETS {
        for way in [Way::Forward, Way::Backward] {
            let rate = socket_run(bucket, way, LOAD_LINKS, LOAD_CIRCUITS, 1);
            println!(
                "socket {bucket:?} {way:?} one thread: {rate:.0} cells/s, {:.1} MB/s",
                rate * bucket.cell_len() as f64 / 1e6
            );
        }
    }
}

#[test]
#[ignore = "a timing run"]
fn perf_a_relay_on_four_threads_over_loopback() {
    for way in [Way::Forward, Way::Backward] {
        let rate = socket_run(Bucket::B0, way, LOAD_LINKS, LOAD_CIRCUITS, 4);
        println!("socket B0 {way:?} four threads: {rate:.0} cells/s");
    }
}

/// Cells to and from many links: a write and a read of a socket for each
/// few cells. Coalescing gives this case the least.
#[test]
#[ignore = "a timing run"]
fn perf_a_relay_with_many_links() {
    for way in [Way::Backward, Way::Forward] {
        let rate = socket_run(Bucket::B0, way, FAN_LINKS, FAN_CIRCUITS, 1);
        println!("socket B0 {way:?} fan one thread: {rate:.0} cells/s");
    }
}

/// The cost of the socket alone: one write of a `B0` record at a time, on
/// one thread, to a thread that reads and drops.
#[test]
#[ignore = "a timing run"]
fn perf_one_socket_write() {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    std::thread::spawn(move || {
        let mut chunk = vec![0u8; 1 << 20];
        while let Ok((mut peer, _)) = listener.accept() {
            while matches!(peer.read(&mut chunk), Ok(n) if n > 0) {}
        }
    });

    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    for group in [1usize, 8, 64] {
        let rate = runtime.block_on(async {
            let mut tcp = TcpStream::connect(address).await.unwrap();
            tcp.set_nodelay(true).unwrap();

            let record = vec![0x11u8; 560 * group];
            let count = 400_000 / group;
            let start = Instant::now();
            for _ in 0..count {
                tcp.write_all(&record).await.unwrap();
            }

            (count * group) as f64 / start.elapsed().as_secs_f64()
        });

        println!(
            "socket write of {group} records in one call: {:.0} ns for a record",
            1e9 / rate
        );
    }
}

/// One circuit that ends at a relay of layer 3, as its client holds it.
struct Endpoint {
    node: RelayNode,
    client: ClientLink,
    keys: KeySet,
    circuit: CircuitKey,
    session_pk: [u8; 32],
}

impl Endpoint {
    fn new() -> Self {
        let (relay, static_secret) = relay_static(0x44);
        let for_client = RelayStatic {
            s: relay.s,
            relay_id: relay.relay_id,
        };

        let mut node = RelayNode::new(Config {
            relay,
            static_secret,
            layer: 3,
            chunk_capacity: 0,
        });
        node.set_backlog(Box::new(Calm));

        let mut buffer = vec![0u8; 40_000];
        let (mut client, used) =
            ClientLink::open([1; 8], Secret::new([2; 32]), &mut buffer).unwrap();
        node.on_capsule(BEFORE, &buffer[..used], NOW, &mut OsRng);

        let circ_id = [0xD0; 16];
        let (cell, pending) = hello_cell(&for_client, circ_id, DelayClass::Fast);
        let used = client.send(&cell, &mut buffer).unwrap();
        let outputs = node.on_capsule(BEFORE, &buffer[..used], NOW, &mut OsRng);

        let Output::Send { capsule, .. } = &outputs[0] else {
            panic!("no answer");
        };
        let answer = cell_of(&mut client, capsule);
        let (parsed, _) = Cell::parse(&answer).unwrap();
        let (_, reply) = read_cell_body(parsed.body).unwrap();
        let (ss_hop, session_pk) = pending.finish_at_queue_relay(reply).unwrap();

        Endpoint {
            node,
            client,
            keys: KeySet::derive(&ss_hop, 3),
            circuit: CircuitKey {
                link: BEFORE,
                circ_id,
            },
            session_pk,
        }
    }

    /// The capsule of one signed command in its `DATA` cell, under the
    /// layer of the circuit, which moves at each cell (`NET-205`).
    fn sealed(
        &mut self,
        cmd: Cmd,
        queue_id: [u8; 32],
        payload: &[u8],
        signer: &StaticSecret,
        bucket: Bucket,
    ) -> Vec<u8> {
        let mut corr_id = [0u8; 16];
        OsRng.try_fill_bytes(&mut corr_id).unwrap();

        let mut command = Command {
            cmd,
            corr_id,
            queue_id,
            auth: [0; 32],
            payload,
        };
        let key = CommandAuthKey::derive(signer, &self.session_pk).unwrap();
        command.sign(&key, b"").unwrap();

        let mut encoded = vec![0u8; command.len()];
        command.encode(&mut encoded).unwrap();

        let mut body = vec![0u8; bucket.body_len()];
        pad_body(bucket, CellCommand::Data, &encoded, &mut body).unwrap();
        let tag = self.keys.forward.encipher(&[0; 16], &mut body).unwrap();
        self.keys.forward.update(&tag);

        let cell = [self.circuit.circ_id.as_slice(), &tag, &body].concat();
        let mut buffer = vec![0u8; 40_000];
        let used = self.client.send(&cell, &mut buffer).unwrap();
        buffer.truncate(used);
        buffer
    }

    /// The answer that the next tick of the pacing clock sends.
    fn answer(&mut self) -> Vec<u8> {
        let outputs = self
            .node
            .pacing_tick(&self.circuit, NOW, &mut OsRng)
            .into_iter();

        let capsule = outputs
            .filter_map(|output| match output {
                Output::Send { capsule, .. } => Some(capsule),
                _ => None,
            })
            .next()
            .unwrap();

        let cell = cell_of(&mut self.client, &capsule);
        let (parsed, _) = Cell::parse(&cell).unwrap();
        let mut body = parsed.body.to_vec();
        self.keys.backward.decipher(parsed.tag, &mut body).unwrap();
        self.keys.backward.update(parsed.tag);

        let (_, content) = unpad_body(&body).unwrap();
        let (command, _) = Command::parse(content, Bucket::B0).unwrap();
        command.payload.to_vec()
    }
}

/// Makes a queue on the circuit of `endpoint`, whose first command also makes
/// the endpoint state of that circuit.
fn new_queue(endpoint: &mut Endpoint, qr: &StaticSecret, qs: &StaticSecret) -> IdsPayload {
    let new = NewPayload {
        qr_auth_pk: *XPublic::from(qr).as_bytes(),
        qs_auth_pk: *XPublic::from(qs).as_bytes(),
        admission: Admission::NONE,
    };
    let mut payload = [0u8; 128];
    let used = new.encode(&mut payload).unwrap();

    let capsule = endpoint.sealed(Cmd::New, [0; 32], &payload[..used], qr, Bucket::B0);
    endpoint.node.on_capsule(BEFORE, &capsule, NOW, &mut OsRng);
    IdsPayload::parse(&endpoint.answer()).unwrap()
}

/// The microseconds of one `SEND` at the node, with no commit of the store.
fn send_run(bucket: Bucket) -> Vec<f64> {
    let mut endpoint = Endpoint::new();
    let qr = StaticSecret::from([4; 32]);
    let qs = StaticSecret::from([5; 32]);
    let ids = new_queue(&mut endpoint, &qr, &qs);

    let record = vec![0x77u8; bucket.l6_record()];
    let capsules: Vec<Vec<u8>> = (0..240)
        .map(|_| endpoint.sealed(Cmd::Send, ids.sender_id, &record, &qs, bucket))
        .collect();

    let mut took = Vec::new();
    for capsule in &capsules {
        let start = Instant::now();
        let outputs = endpoint.node.on_capsule(BEFORE, capsule, NOW, &mut OsRng);
        let changes = endpoint.node.take_changes();
        took.push(start.elapsed().as_secs_f64() * 1e6);

        assert!(changes.len() >= 2);
        drop(outputs);
    }

    took
}

#[test]
#[ignore = "a timing run"]
fn perf_a_send_at_the_queue_relay() {
    let secret = StaticSecret::from([5; 32]);
    let public = *XPublic::from(&StaticSecret::from([6; 32])).as_bytes();
    let start = Instant::now();
    for _ in 0..2_000 {
        std::hint::black_box(CommandAuthKey::derive(&secret, &public).unwrap());
    }
    let derive = start.elapsed().as_secs_f64() * 1e6 / 2_000.0;
    println!("send: the key of one command takes {derive:.1} us");

    for bucket in BUCKETS {
        let mut took = Vec::new();
        for _ in 0..8 {
            took.extend(send_run(bucket));
        }
        println!("send {bucket:?} at the node: {:.1} us", median(took));
    }
}

/// The working set of this process, on a machine with PowerShell.
fn working_set() -> Option<f64> {
    let script = format!("(Get-Process -Id {}).WorkingSet64", std::process::id());
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;

    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

/// The memory of one circuit at a middle relay, with its allocator cost.
#[test]
#[ignore = "a timing run"]
fn perf_the_memory_of_a_circuit() {
    const CIRCUITS: usize = 8_000;

    let before = working_set().unwrap();
    let middle = Middle::new(CIRCUITS, DelayClass::Fast);
    let after = working_set().unwrap();
    assert_eq!(middle.before.len(), CIRCUITS);

    println!(
        "memory of a circuit: {:.0} bytes",
        (after - before) / CIRCUITS as f64
    );
}

/// One tick of the pacing clock of an idle circuit: a `B0` cover cell. The
/// relay of a call pays this for each circuit that ends at it.
#[test]
#[ignore = "a timing run"]
fn perf_a_pacing_tick() {
    let mut took = Vec::new();

    for _ in 0..4 {
        let mut endpoint = Endpoint::new();
        let qr = StaticSecret::from([4; 32]);
        let qs = StaticSecret::from([5; 32]);
        new_queue(&mut endpoint, &qr, &qs);

        for _ in 0..8_000 {
            let start = Instant::now();
            let outputs = endpoint
                .node
                .pacing_tick(&endpoint.circuit, NOW, &mut OsRng);
            took.push(start.elapsed().as_secs_f64() * 1e6);
            assert_eq!(outputs.len(), 1);
        }
    }

    println!("tick of a cover cell: {:.1} us", median(took));
}

/// The path of a new store file under the temporary directory.
fn store_path(name: &str) -> String {
    let directory = std::env::temp_dir().join(format!("umbra-perf-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path.to_str().unwrap().to_owned()
}

/// The two changes of one accepted `SEND`, with its record of `len` bytes.
fn send_changes(queue: u32, seq: u32, len: usize, out: &mut Vec<StoreChange>) {
    let mut recipient_id = [0u8; 32];
    recipient_id[..4].copy_from_slice(&queue.to_be_bytes());

    out.push(StoreChange::Record {
        recipient_id,
        record: Stored {
            seq,
            accepted_at: NOW,
            bytes: vec![0x77; len],
        },
    });
    out.push(StoreChange::Queue {
        recipient_id,
        head: vec![0x55; 256],
    });
}

#[test]
#[ignore = "a timing run"]
fn perf_the_queue_store() {
    for group in [1u32, 8, 64] {
        let path = store_path(&format!("queue-{group}.db"));
        let mut store = SqliteStore::open(&path).unwrap();

        let commits = 2_048 / group;
        let mut seq = 0u32;
        let mut took = Vec::new();

        for _ in 0..commits {
            let mut changes = Vec::new();
            for _ in 0..group {
                seq += 1;
                send_changes(seq % 256, seq, 396, &mut changes);
            }

            let start = Instant::now();
            store.commit(&changes).unwrap();
            took.push(start.elapsed().as_secs_f64() * 1e6);
        }

        let per_commit = median(took);
        println!(
            "store group of {group} SEND: {per_commit:.0} us for a commit, {:.0} us for a record",
            per_commit / f64::from(group)
        );
    }

    // The cost of the statements alone: a file in memory takes no sync.
    let mut store = SqliteStore::open(":memory:").unwrap();
    let mut took = Vec::new();
    let mut seq = 0u32;

    for _ in 0..512 {
        let mut changes = Vec::new();
        for _ in 0..64 {
            seq += 1;
            send_changes(seq % 256, seq, 396, &mut changes);
        }

        let start = Instant::now();
        store.commit(&changes).unwrap();
        took.push(start.elapsed().as_secs_f64() * 1e6);
    }

    println!("store group of 64 in memory: {:.0} us", median(took));

    let path = store_path("acks.db");
    let mut store = SqliteStore::open(&path).unwrap();
    let mut changes = Vec::new();
    for seq in 1..=256 {
        send_changes(1, seq, 396, &mut changes);
    }
    store.commit(&changes).unwrap();

    let mut recipient_id = [0u8; 32];
    recipient_id[..4].copy_from_slice(&1u32.to_be_bytes());
    let mut took = Vec::new();

    for seq in 1..=256 {
        let changes = [StoreChange::Acked { recipient_id, seq }];
        let start = Instant::now();
        store.commit(&changes).unwrap();
        took.push(start.elapsed().as_secs_f64() * 1e6);
    }

    println!("store ACK: {:.0} us for a commit", median(took));
}

#[test]
#[ignore = "a timing run"]
fn perf_the_chunk_store() {
    let path = store_path("chunks.db");
    let mut store = SqliteStore::open(&path).unwrap();
    let mut took = Vec::new();

    for index in 0..512u32 {
        let mut chunk_id = [0u8; 32];
        chunk_id[..4].copy_from_slice(&index.to_be_bytes());

        let changes = [StoreChange::Chunk {
            chunk_id,
            held: Box::new(HeldChunk {
                class: Class::Attachment,
                credentials: Credentials {
                    cred_pk: [1; 32],
                    read_pk: [2; 32],
                },
                bytes: vec![0x33; 32_768],
                registered_at: NOW,
                renewed_at: NOW,
                erase_at: NOW + 86_400,
            }),
        }];

        let start = Instant::now();
        store.commit(&changes).unwrap();
        took.push(start.elapsed().as_secs_f64() * 1e6);
    }

    println!("store CPUT of 32 KiB: {:.0} us for a commit", median(took));
}
