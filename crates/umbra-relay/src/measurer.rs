//! The measurer of Part 10 §10.3: the class test of one relay over `k`
//! connections, and the slots of a set of relays by co-residency cluster.
//!
//! A class test proves a threshold. The measurer sends `MEAS_ECHO` cells at
//! 2.25 times the rate of the class for one slot, and the relay passes when
//! the echoes that came back inside the slot reach the rate of the class.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::mpsc;
use umbra_core::directory::{
    descriptor::RelayDescriptor,
    measure::{
        capacity_needed, open_content, CLASS_RATES, CLUSTER_FULL, CLUSTER_SAMPLE, MEAS_CIRCUITS_MAX,
    },
};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    rand_core::{TryCryptoRng, TryRng},
    secret::Secret,
    sign::SigningKey,
};
use umbra_onion::{
    build::{build_cell_body, read_cell_body, DelayClass, Pending, BUILD_BUCKET, HELLO_LEN},
    circuit::MeasureCircuit,
    CIRCUIT_BUILD_TIMEOUT,
};
use umbra_transport::{
    link::ClientLink,
    native::{TcpLink, TcpReader, TcpWriter},
    Dial,
};
use umbra_wire::{
    bucket::Bucket,
    capsule::{self, CapsuleType},
    cell::{pad_body, unpad_body, Cell, CellCommand},
};

use crate::server::OsRng;

/// The connections of one class test, when the settings name no count.
pub const SOCKETS: usize = 4;
/// The cells of one write to one connection at most.
const BATCH_CELLS: u64 = 128;
/// The period at which a connection computes the cells that are due.
const PACE: Duration = Duration::from_millis(2);

/// One relay under test.
#[derive(Debug, Clone)]
pub struct Target {
    /// The `relay_id` of the descriptor.
    pub relay_id: [u8; 32],
    /// The X25519 static of the hop handshake.
    pub ntor_pk: [u8; 32],
    /// The layer of the relay, 1 to 3. The hop keys take it as the hop
    /// index.
    pub layer: u8,
    /// Where to dial the relay.
    pub dial: Dial,
    /// The autonomous system.
    pub asn: u32,
    /// The IPv4 address, or zero.
    pub addr_v4: [u8; 4],
    /// The IPv6 address, or zero.
    pub addr_v6: [u8; 16],
    /// The family, or zero.
    pub family_id: [u8; 32],
    /// The class that the relay declares.
    pub capacity_class: u8,
}

impl Target {
    /// The target of a signed descriptor, for a relay of `layer`.
    pub fn of(descriptor: &[u8], layer: u8) -> Option<Self> {
        let parsed = RelayDescriptor::parse(descriptor).ok()?;
        Some(Target::of_descriptor(&parsed, layer))
    }

    /// The target of a descriptor that the caller verified, for a relay of
    /// `layer`.
    pub fn of_descriptor(parsed: &RelayDescriptor<'_>, layer: u8) -> Self {
        Target {
            relay_id: parsed.relay_id,
            ntor_pk: parsed.ntor_pk,
            layer,
            dial: Dial {
                host: parsed.host_str().to_owned(),
                addr_v4: (parsed.addr_v4 != [0; 4]).then_some(parsed.addr_v4),
                addr_v6: (parsed.addr_v6 != [0; 16]).then_some(parsed.addr_v6),
                port: parsed.port,
            },
            asn: parsed.asn,
            addr_v4: parsed.addr_v4,
            addr_v6: parsed.addr_v6,
            family_id: parsed.family_id,
            capacity_class: parsed.capacity_class,
        }
    }

    /// Whether two relays are of one cluster (§10.3): one ASN, one IPv4
    /// /24, one IPv6 /48, or one family.
    fn is_near(&self, other: &Target) -> bool {
        self.asn == other.asn
            || (self.addr_v4 != [0; 4] && self.addr_v4.get(..3) == other.addr_v4.get(..3))
            || (self.addr_v6 != [0; 16] && self.addr_v6.get(..6) == other.addr_v6.get(..6))
            || (self.family_id != [0; 32] && self.family_id == other.family_id)
    }
}

/// The rates and the length of one class test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// The rate that the measurer sends, in bits each second.
    pub send_bits: u64,
    /// The rate of echoes at which the relay passes, in bits each second.
    pub pass_bits: u64,
    /// The length of the slot.
    pub slot: Duration,
    /// The connections, 1 to `MEAS_CIRCUITS_MAX`.
    pub sockets: usize,
}

impl Plan {
    /// The test of `class` over a slot of `slot`. `scale` divides each
    /// rate, for a test network on one machine; a deployment uses 1.
    pub fn of(class: u8, slot: Duration, sockets: usize, scale: u64) -> Option<Self> {
        let scale = scale.max(1);
        Some(Plan {
            send_bits: capacity_needed(class)? / scale,
            pass_bits: CLASS_RATES.get(usize::from(class))? / scale,
            slot,
            sockets: sockets.clamp(1, MEAS_CIRCUITS_MAX),
        })
    }
}

/// What one class test counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// The cells that the measurer sent in the slot.
    pub sent: u64,
    /// The echoes that came back in the slot.
    pub echoed: u64,
    /// The rate of the echoes, in bits each second.
    pub echoed_bits: u64,
    /// Whether the relay held the rate of the class.
    pub passed: bool,
}

/// Why a class test gave no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasureError {
    /// A connection did not open.
    Connect,
    /// The relay gave the build cell no answer.
    Build,
    /// The relay opened no measurement session: the echo of the first cell
    /// did not come back. A relay gives a rejected `MEAS_OPEN` no sign
    /// (`REL-069`).
    NoSession,
    /// A local step failed.
    Local,
}

fn bits_of_cells(cells: u64) -> u64 {
    cells.saturating_mul(Bucket::B0.cell_len() as u64 * 8)
}

/// The link session and the circuit of one connection with an open
/// measurement session on it.
struct Socket {
    link: ClientLink,
    circuit: MeasureCircuit,
}

/// One connection: its session, and its two halves.
type Opened = (Socket, TcpReader, TcpWriter);

impl Socket {
    fn frame(&mut self, command: CellCommand, bucket: Bucket, content: &[u8]) -> Option<Vec<u8>> {
        let mut body = vec![0u8; bucket.body_len()];
        pad_body(bucket, command, content, &mut body).ok()?;
        let tag = self.circuit.seal(&mut body).ok()?;
        let cell = [self.circuit.circ_id().as_slice(), &tag, &body].concat();
        let mut capsule = vec![0u8; cell.len() + 64];
        let used = self.link.send(&cell, &mut capsule).ok()?;
        capsule.truncate(used);
        Some(capsule)
    }

    /// Whether a capsule of the relay is an echo of this circuit. An echo
    /// that follows a dropped one fails the check of its layer one time,
    /// and the layer then holds the chaining value again.
    fn is_echo(&mut self, bytes: &[u8]) -> bool {
        let Ok((CapsuleType::Cell, value, _)) = capsule::parse(bytes) else {
            return false;
        };
        let Ok(Some(cell)) = self.link.receive(value) else {
            return false;
        };
        let Ok((parsed, Bucket::B0)) = Cell::parse(cell) else {
            return false;
        };
        if *parsed.circ_id != self.circuit.circ_id() {
            return false;
        }
        let mut body = parsed.body.to_vec();
        self.circuit.open(parsed.tag, &mut body).is_ok()
            && matches!(unpad_body(&body), Ok((CellCommand::MeasEcho, _)))
    }
}

/// Opens one connection to `target`, builds the circuit of one hop, sends
/// the `MEAS_OPEN`, and waits for the echo of one cell (`REL-064`,
/// `REL-065`).
async fn open_socket(
    target: &Target,
    cert: &[u8],
    key: &SigningKey,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Opened, MeasureError> {
    let mut rng = OsRng;
    let mut draw = [0u8; 16 + 4 + 8 + 32 + 16];
    rng.try_fill_bytes(&mut draw)
        .map_err(|_| MeasureError::Local)?;
    let take = |from: usize, len: usize| draw.get(from..from + len).unwrap_or(&[]);
    let ws_key: [u8; 16] = take(0, 16).try_into().map_err(|_| MeasureError::Local)?;
    let mask: [u8; 4] = take(16, 4).try_into().map_err(|_| MeasureError::Local)?;
    let session_id: [u8; 8] = take(20, 8).try_into().map_err(|_| MeasureError::Local)?;
    let secret: [u8; 32] = take(28, 32).try_into().map_err(|_| MeasureError::Local)?;
    let circ_id: [u8; 16] = take(60, 16).try_into().map_err(|_| MeasureError::Local)?;

    let wait = Duration::from_secs(CIRCUIT_BUILD_TIMEOUT);
    let mut tcp = tokio::time::timeout(wait, TcpLink::connect(&target.dial, tls, ws_key, mask))
        .await
        .map_err(|_| MeasureError::Connect)?
        .map_err(|_| MeasureError::Connect)?;
    let mut buffer = vec![0u8; 40_000];
    let (mut link, used) = ClientLink::open(session_id, Secret::new(secret), &mut buffer)
        .map_err(|_| MeasureError::Local)?;
    tcp.send(buffer.get(..used).unwrap_or(&[]))
        .await
        .map_err(|_| MeasureError::Connect)?;

    // The build cell of one hop travels under no layer.
    let relay = RelayStatic {
        s: target.ntor_pk,
        relay_id: target.relay_id,
    };
    let mut hello = [0u8; HELLO_LEN];
    let pending = Pending::hello(&relay, DelayClass::Fast, &mut rng, &mut hello)
        .map_err(|_| MeasureError::Local)?;
    let mut body = vec![0u8; BUILD_BUCKET.body_len()];
    build_cell_body(CellCommand::Extend, &hello, &mut body).map_err(|_| MeasureError::Local)?;
    let cell = [circ_id.as_slice(), &[0u8; 16], &body].concat();
    let used = link
        .send(&cell, &mut buffer)
        .map_err(|_| MeasureError::Local)?;
    tcp.send(buffer.get(..used).unwrap_or(&[]))
        .await
        .map_err(|_| MeasureError::Connect)?;
    let ss_hop = tokio::time::timeout(wait, async {
        loop {
            let bytes = tcp.recv().await.map_err(|_| MeasureError::Build)?;
            let Ok((CapsuleType::Cell, value, _)) = capsule::parse(&bytes) else {
                continue;
            };
            let Ok(Some(cell)) = link.receive(value) else {
                continue;
            };
            let (parsed, _) = Cell::parse(cell).map_err(|_| MeasureError::Build)?;
            if *parsed.circ_id != circ_id || *parsed.tag != [0u8; 16] {
                return Err(MeasureError::Build);
            }
            let (_, reply) = read_cell_body(parsed.body).map_err(|_| MeasureError::Build)?;
            return pending.finish(reply).map_err(|_| MeasureError::Build);
        }
    })
    .await
    .map_err(|_| MeasureError::Build)??;

    let circuit = MeasureCircuit::new(&ss_hop, u32::from(target.layer), circ_id);
    let content = open_content(cert, key, &target.relay_id, &circ_id, &mut rng)
        .map_err(|_| MeasureError::Local)?;
    let (mut reader, mut writer) = tcp.split();
    let mut socket = Socket { link, circuit };
    let open = socket
        .frame(CellCommand::MeasOpen, Bucket::B3, &content)
        .ok_or(MeasureError::Local)?;
    // The echo of one cell shows the open session: the relay answers the
    // `MEAS_OPEN` itself with nothing.
    let first = socket
        .frame(CellCommand::MeasEcho, Bucket::B0, &[0u8; 8])
        .ok_or(MeasureError::Local)?;
    writer
        .send_all(&[open, first])
        .await
        .map_err(|_| MeasureError::Connect)?;
    let echoed = tokio::time::timeout(wait, async {
        loop {
            match reader.recv().await {
                Ok(bytes) if socket.is_echo(&bytes) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    if echoed {
        Ok((socket, reader, writer))
    } else {
        Err(MeasureError::NoSession)
    }
}

/// Runs the slot on one connection: sends at `cells_each_second`, and
/// counts the cells that left and the echoes that came back before `end`.
async fn run_socket(
    opened: Opened,
    cells_each_second: f64,
    start: Instant,
    end: Instant,
) -> (u64, u64) {
    let (mut socket, mut reader, mut writer) = opened;
    // The writing half runs as its own task, thus a write that waits for
    // the relay holds no read back.
    let (batches, mut waiting) = mpsc::channel::<Vec<Vec<u8>>>(2);
    let write = tokio::spawn(async move {
        while let Some(batch) = waiting.recv().await {
            if writer.send_all(&batch).await.is_err() {
                break;
            }
        }
    });
    let (mut sent, mut echoed) = (0u64, 0u64);
    tokio::time::sleep_until(start.into()).await;
    let mut pace = tokio::time::interval(PACE);
    let mut counter = 0u64;
    loop {
        let now = Instant::now();
        if now >= end {
            break;
        }
        let due = (now.duration_since(start).as_secs_f64() * cells_each_second) as u64;
        let owed = due.saturating_sub(sent).min(BATCH_CELLS);
        tokio::select! {
            received = reader.recv() => match received {
                Ok(bytes) => {
                    if socket.is_echo(&bytes) && Instant::now() < end {
                        echoed += 1;
                    }
                }
                Err(_) => break,
            },
            permit = batches.reserve(), if owed > 0 => {
                let Ok(permit) = permit else {
                    break;
                };
                let mut batch = Vec::with_capacity(owed as usize);
                for _ in 0..owed {
                    counter = counter.wrapping_add(1);
                    let Some(capsule) =
                        socket.frame(CellCommand::MeasEcho, Bucket::B0, &counter.to_be_bytes())
                    else {
                        break;
                    };
                    batch.push(capsule);
                }
                sent += batch.len() as u64;
                permit.send(batch);
            }
            _ = pace.tick() => {}
            () = tokio::time::sleep_until(end.into()) => break,
        }
    }
    // The measurer ends its circuit and its session (Part 6 `WIR-246`):
    // the relay parks nothing of it.
    let mut last = Vec::new();
    last.extend(socket.frame(CellCommand::Destroy, Bucket::B0, &[]));
    let mut close = vec![0u8; 64];
    if let Ok(used) = socket.link.close(&mut close) {
        close.truncate(used);
        last.push(close);
    }
    let _ = batches.send(last).await;
    drop(batches);
    let _ = tokio::time::timeout(Duration::from_secs(2), write).await;
    (sent, echoed)
}

/// Runs the class test of `plan` against `target` with the certificate
/// `cert` and its key.
pub async fn measure(
    target: &Target,
    cert: &[u8],
    key: &SigningKey,
    plan: Plan,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Outcome, MeasureError> {
    let mut sockets = Vec::with_capacity(plan.sockets);
    // One connection after the other: a relay runs few TLS handshakes of
    // one address at once (Part 3 §3.13).
    for _ in 0..plan.sockets {
        sockets.push(open_socket(target, cert, key, tls.clone()).await?);
    }
    let cell_bits = bits_of_cells(1) as f64;
    let each = plan.send_bits as f64 / cell_bits / plan.sockets as f64;
    let start = Instant::now() + Duration::from_millis(50);
    let end = start + plan.slot;
    let runs: Vec<_> = sockets
        .into_iter()
        .map(|socket| tokio::spawn(run_socket(socket, each, start, end)))
        .collect();
    let (mut sent, mut echoed) = (0u64, 0u64);
    for run in runs {
        let (one_sent, one_echoed) = run.await.map_err(|_| MeasureError::Local)?;
        sent += one_sent;
        echoed += one_echoed;
    }
    let millis = u64::try_from(plan.slot.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    let echoed_bits = bits_of_cells(echoed).saturating_mul(1_000) / millis;
    Ok(Outcome {
        sent,
        echoed,
        echoed_bits,
        passed: echoed_bits >= plan.pass_bits,
    })
}

/// The relays that one measurer of `capacity_bits` tests in one slot at
/// `class`: each test needs 2.25 times the rate of the class (§10.3).
pub fn slot_width(capacity_bits: u64, class: u8) -> usize {
    capacity_needed(class)
        .filter(|needed| *needed > 0)
        .map_or(0, |needed| {
            usize::try_from(capacity_bits / needed).unwrap_or(usize::MAX)
        })
}

/// The highest class that a measurer of `capacity_bits` tests, or none
/// for a measurer below the capacity of a C0 test.
pub fn highest_class(capacity_bits: u64) -> Option<u8> {
    (0..=3u8)
        .rev()
        .find(|class| slot_width(capacity_bits, *class) >= 1)
}

/// The clusters of `targets`: the relays that share an ASN, an IPv4 /24,
/// an IPv6 /48, or a family, and each relay that such a relay reaches
/// (§10.3). The result holds the index of each target one time.
pub fn clusters(targets: &[Target]) -> Vec<Vec<usize>> {
    let mut cluster_of: Vec<usize> = (0..targets.len()).collect();
    for (index, target) in targets.iter().enumerate() {
        for (other_index, other) in targets.iter().enumerate().skip(index + 1) {
            if !target.is_near(other) {
                continue;
            }
            let (Some(from), Some(to)) = (
                cluster_of.get(other_index).copied(),
                cluster_of.get(index).copied(),
            ) else {
                continue;
            };
            for held in &mut cluster_of {
                if *held == from {
                    *held = to;
                }
            }
        }
    }
    let mut grouped: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, cluster) in cluster_of.into_iter().enumerate() {
        grouped.entry(cluster).or_default().push(index);
    }
    grouped.into_values().collect()
}

/// The slots of one run over `targets`, for a measurer that tests `width`
/// relays in one slot.
///
/// A cluster of `CLUSTER_FULL` relays or fewer is one slot (`REL-099`). A
/// larger cluster goes in samples of `CLUSTER_SAMPLE` relays, in an order
/// that the measurer draws from `rng`, thus the cluster does not know the
/// relays of the next slot (`REL-100`). Each relay is in one slot, thus
/// the run tests a cluster of `n` relays in `ceil(n / CLUSTER_SAMPLE)`
/// slots (`REL-101`). A measurer whose capacity holds fewer relays than a
/// slot needs takes `width` relays in each slot, and the second value
/// tells of it.
pub fn slots<R: TryCryptoRng + ?Sized>(
    targets: &[Target],
    width: usize,
    rng: &mut R,
) -> (Vec<Vec<usize>>, bool) {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut is_narrow = false;
    for mut cluster in clusters(targets) {
        let sample = if cluster.len() <= CLUSTER_FULL {
            cluster.len()
        } else {
            CLUSTER_SAMPLE
        };
        if sample > width {
            is_narrow = true;
        }
        // A uniform order, by the Fisher-Yates method.
        for last in (1..cluster.len()).rev() {
            let draw = rng.try_next_u64().unwrap_or(0);
            let pick = usize::try_from(draw % (last as u64 + 1)).unwrap_or(0);
            cluster.swap(last, pick);
        }
        for slot in cluster.chunks(sample.min(width).max(1)) {
            out.push(slot.to_vec());
        }
    }
    (out, is_narrow)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    fn target(asn: u32, v4: [u8; 4], family: u8) -> Target {
        Target {
            relay_id: [0; 32],
            ntor_pk: [0; 32],
            layer: 1,
            dial: Dial {
                host: String::new(),
                addr_v4: Some(v4),
                addr_v6: None,
                port: 443,
            },
            asn,
            addr_v4: v4,
            addr_v6: [0; 16],
            family_id: [family; 32],
            capacity_class: 1,
        }
    }

    #[test]
    fn the_relays_of_one_asn_one_prefix_or_one_family_are_one_cluster() {
        let targets = [
            target(1, [10, 0, 0, 1], 0),
            target(2, [10, 0, 1, 1], 0),
            // The ASN of the first one.
            target(1, [10, 0, 2, 1], 0),
            // The /24 of the second one, and the family of the last one.
            target(3, [10, 0, 1, 9], 7),
            target(4, [10, 0, 4, 1], 0),
            target(5, [10, 0, 5, 1], 7),
        ];
        let mut found = clusters(&targets);
        found.sort();
        assert_eq!(found, vec![vec![0, 2], vec![1, 3, 5], vec![4]]);
    }

    #[test]
    fn a_small_cluster_is_one_slot_and_a_large_one_goes_in_samples() {
        // REL-099: four relays of one ASN in one slot.
        let four: Vec<Target> = (0..4u8).map(|n| target(1, [10, n, 0, 1], 0)).collect();
        let (found, is_narrow) = slots(&four, 4, &mut OsRng);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].len(), 4);
        assert!(!is_narrow);
        // REL-100, REL-101: nine relays in ceil(9 / 4) slots, each relay
        // one time.
        let nine: Vec<Target> = (0..9u8).map(|n| target(1, [10, n, 0, 1], 0)).collect();
        let (found, is_narrow) = slots(&nine, 8, &mut OsRng);
        assert_eq!(found.len(), 3);
        assert!(!is_narrow);
        let mut seen: Vec<usize> = found.concat();
        seen.sort_unstable();
        assert_eq!(seen, (0..9).collect::<Vec<_>>());
        assert!(found.iter().all(|slot| slot.len() <= CLUSTER_SAMPLE));
        // The order comes from the generator: two runs differ.
        let orders: std::collections::BTreeSet<Vec<Vec<usize>>> =
            (0..16).map(|_| slots(&nine, 8, &mut OsRng).0).collect();
        assert!(orders.len() > 1);
        // A measurer of the launch network holds two C0 tests in a slot.
        let six: Vec<Target> = (0..6u8).map(|n| target(1, [10, n, 0, 1], 0)).collect();
        let (found, is_narrow) = slots(&six, 2, &mut OsRng);
        assert_eq!(found.len(), 3);
        assert!(is_narrow);
    }

    #[test]
    fn a_server_of_500_mbit_tests_two_relays_at_c0_and_no_class_above() {
        let capacity = 500_000_000;
        assert_eq!(slot_width(capacity, 0), 2);
        assert_eq!(slot_width(capacity, 1), 0);
        assert_eq!(highest_class(capacity), Some(0));
        assert_eq!(highest_class(224_999_999), None);
        assert_eq!(highest_class(1_125_000_000), Some(2));
        assert_eq!(highest_class(2_250_000_000), Some(3));
    }
}
