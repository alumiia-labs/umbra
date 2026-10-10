//! The runtime of the attachment transfers (Part 12 §12.8): one task with a
//! node and a connection of its own, beside the run of the queues. Thus the
//! resend of one chunk stalls no message, and the two flows do not mix in
//! one stream (`ATT-024`, `ATT-048`).
//!
//! The task dials the pinned ingress relay at its first transfer. It ends
//! when no transfer is left for [`IDLE_END`], and the next transfer starts a
//! new one.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use tokio::sync::mpsc;
use umbra_core::{
    attach::{
        handle::{HandleRead, HandleWrite},
        place::{AttachmentRelay, HoldOffs},
        transfer::{ChunkFetch, Class, Download, Progress, Shape, Upload, Uploaded},
    },
    session::node::{ChunkJob, ChunkOutcome, ClientEvent, ClientNode},
};
use umbra_crypto::{rand_core::TryRng, x25519::StaticSecret};
use umbra_transport::{
    native::{self, ClientConfig},
    race::{Plan, Wire},
    Dial,
};
use umbra_wire::descriptor::FileDescriptor;
use zeroize::Zeroizing;

use crate::runtime::OsRng;

/// How long the task keeps its connection with no transfer.
pub const IDLE_END: Duration = Duration::from_secs(60);
/// The tick of the drivers: a proof that a replica did not hold yet goes
/// again at the next one.
const TICK: Duration = Duration::from_secs(1);

/// What the caller asks of the task.
pub enum TransferCommand {
    /// The challenges of a fetch, for the registrations of the chunk path
    /// (Part 13 `ABU-106`). No update follows.
    Challenges {
        /// The challenges, each verified under the key of its relay.
        book: umbra_core::abuse::pow::ChallengeBook,
        /// The time of the fetch.
        now: u64,
    },
    /// The privacy mode of the transfer of `tag`, which comes before its
    /// `Upload` or `Download`: its circuits take that mode (Part 12
    /// `ATT-167`). A transfer with none takes Balanced.
    Mode {
        /// The tag of the transfer.
        tag: u64,
        /// The mode of the conversation of the file.
        class: umbra_core::session::node::DelayClass,
    },
    /// Upload one file. The plaintext leaves the memory with the command.
    Upload {
        /// A value of the caller, which comes back in each update.
        tag: u64,
        /// The file, after the re-encode of `ATT-155`.
        plain: Zeroizing<Vec<u8>>,
        /// The descriptor fields that the seal does not fix.
        shape: Shape,
    },
    /// Erase one chunk that this device uploaded, at each relay that holds
    /// a copy (`ATT-161`). An `Erased` follows when each relay answered.
    Erase {
        /// The chunk.
        chunk_id: [u8; 32],
        /// `cred_sk` of the chunk.
        cred: umbra_crypto::secret::Secret<32>,
        /// Each relay that holds a copy.
        relays: Vec<[u8; 32]>,
    },
    /// Fetch the file of one descriptor.
    Download {
        /// A value of the caller, which comes back in each update.
        tag: u64,
        /// The descriptor of a received record.
        descriptor: Box<FileDescriptor>,
    },
    /// Fetch one chunk of a file and open it alone: the slot of this member
    /// in a chunked epoch-key record (Part 11 `GRP-284`). The update is
    /// `Downloaded` with that one segment.
    FetchChunk {
        /// A value of the caller, which comes back in each update.
        tag: u64,
        /// The descriptor of the slot object.
        descriptor: Box<FileDescriptor>,
        /// The chunk.
        index: u32,
    },
    /// Fetch one backup object of Part 4 §4.7.2, whose descriptor a backup
    /// root named. A `Downloaded` or a `Failed` follows.
    DownloadBackup {
        /// A value of the caller, which comes back in each update.
        tag: u64,
        /// The descriptor.
        descriptor: Box<FileDescriptor>,
    },
    /// Upload one backup object of Part 4 §4.7.2 in the backup class. An
    /// `Uploaded` or a `Failed` follows.
    UploadBackup {
        /// A value of the caller, which comes back in each update.
        tag: u64,
        /// The encoded object.
        plain: Zeroizing<Vec<u8>>,
    },
    /// Write one handle-addressed chunk (Part 12 §12.4.2). A
    /// `HandleWritten` or a `Failed` follows.
    WriteHandle {
        /// A value of the caller, which comes back in the update.
        tag: u64,
        /// The `chunk_id`.
        handle: [u8; 32],
        /// `cred_sk` of the chunk.
        cred: umbra_crypto::secret::Secret<32>,
        /// The public half of `read_sk`.
        read_pk: [u8; 32],
        /// The padded chunk.
        chunk: Vec<u8>,
        /// Whether a chunk under this handle goes first (`ATT-138`).
        replaces: bool,
    },
    /// Read one handle-addressed chunk. A `HandleRead` follows.
    ReadHandle {
        /// A value of the caller, which comes back in the update.
        tag: u64,
        /// The `chunk_id`.
        handle: [u8; 32],
        /// `read_sk` of the chunk.
        read: umbra_crypto::secret::Secret<32>,
    },
}

/// What the task tells the caller.
pub enum TransferUpdate {
    /// Chunks done, and the chunk count.
    Progress {
        /// The tag of the command.
        tag: u64,
        /// The chunks done.
        done: u32,
        /// The chunk count.
        total: u32,
    },
    /// The relays hold the file.
    Uploaded {
        /// The tag of the command.
        tag: u64,
        /// The descriptor and the write credentials.
        uploaded: Box<Uploaded>,
    },
    /// The file of a descriptor, in the clear.
    Downloaded {
        /// The tag of the command.
        tag: u64,
        /// The plaintext.
        plain: Zeroizing<Vec<u8>>,
    },
    /// The relays that hold a handle-addressed chunk.
    HandleWritten {
        /// The tag of the command.
        tag: u64,
        /// The relays.
        relays: Vec<[u8; 32]>,
    },
    /// The chunks under a handle, each distinct one that a relay gave, and
    /// whether each relay asked answered (`ATT-136`).
    HandleRead {
        /// The tag of the command.
        tag: u64,
        /// The chunks, in the order of the placement list.
        chunks: Vec<Vec<u8>>,
        /// Whether each relay answered: a read that no relay answered is
        /// no empty handle.
        answered: bool,
    },
    /// The transfer ended with no result. The caller can ask again.
    Failed {
        /// The tag of the command.
        tag: u64,
    },
    /// The run ended before the transfer did: a lost or aged circuit, or a
    /// dial that failed. Nothing of the transfer failed, and the caller
    /// sends it in the next run (`NET-320`).
    Interrupted {
        /// The tag of the command.
        tag: u64,
    },
    /// Each replica of a chunk of the download holds none. No new attempt
    /// finds the file (Part 12 `ATT-052`).
    Gone {
        /// The tag of the command.
        tag: u64,
    },
    /// A chunk relay failed its proof, and the report of its chain goes
    /// in the next run of the queues (`ATT-119`).
    Faults(Box<umbra_core::session::faults::LinkFaults>),
    /// Each relay of one chunk answered its `CDEL`: it erased the chunk, or
    /// it holds none under that credential (`ATT-161`). The caller keeps
    /// the credential until this update, and an erase with none goes again
    /// in a later run.
    Erased {
        /// The chunk.
        chunk_id: [u8; 32],
    },
}

enum Active {
    One(Box<ChunkFetch>),
    Up(Box<Upload>),
    Down(Box<Download>),
    Write(Box<HandleWrite>),
    Read(Box<HandleRead>),
}

/// Runs the transfers until the link ends, or until no transfer is left for
/// [`IDLE_END`]. Each transfer that is open at the end fails.
pub async fn run_transfers(
    mut node: ClientNode,
    guard: Dial,
    tls: Arc<ClientConfig>,
    relays: Vec<AttachmentRelay>,
    hold_offs: Arc<std::sync::Mutex<HoldOffs>>,
    mut commands: mpsc::UnboundedReceiver<TransferCommand>,
    updates: mpsc::UnboundedSender<TransferUpdate>,
) {
    let mut rng = OsRng;
    // ATT-174: the relays that refused a chunk, which the runs of this
    // handle share, as the fetch orders take them at each start.
    let held = || {
        let now = crate::runtime::unix_now();
        let holds = hold_offs.lock().map_or_else(
            |_| HoldOffs::default(),
            |mut holds| {
                holds.expire(now);
                holds.clone()
            },
        );
        (holds, now)
    };
    let mut active: BTreeMap<u64, Active> = BTreeMap::new();
    // ATT-167: the mode of each transfer, which the node takes before each
    // call into it.
    let mut classes: BTreeMap<u64, umbra_core::session::node::DelayClass> = BTreeMap::new();
    let mut early: Vec<TransferCommand> = Vec::new();
    // ATT-161: the chunk of each `CDEL` with no answer yet, by the handle
    // of the command. For each chunk: the answers that it waits for, and
    // whether each answer so far says that the relay holds it no more.
    let mut erasing: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    let mut erase_left: BTreeMap<[u8; 32], (usize, bool)> = BTreeMap::new();
    // A run that ends ends no transfer: each one goes again in the next run.
    let fail_each = |active: &BTreeMap<u64, Active>, early: &[TransferCommand]| {
        for tag in active.keys() {
            let _ = updates.send(TransferUpdate::Interrupted { tag: *tag });
        }
        for command in early {
            // An erase that did not leave, or that has no answer, gives no
            // update. The store of the caller keeps its credential, and the
            // next run sends the `CDEL` again (`ATT-161`).
            if let TransferCommand::Upload { tag, .. }
            | TransferCommand::Download { tag, .. }
            | TransferCommand::FetchChunk { tag, .. }
            | TransferCommand::WriteHandle { tag, .. }
            | TransferCommand::ReadHandle { tag, .. }
            | TransferCommand::UploadBackup { tag, .. }
            | TransferCommand::DownloadBackup { tag, .. } = command
            {
                let _ = updates.send(TransferUpdate::Interrupted { tag: *tag });
            }
        }
    };

    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    let connected = native::connect(&guard, tls, plan, key, mask, Duration::from_secs(10)).await;
    // Each exit closes the channel first and fails each command in it, thus
    // no command waits for an answer that no task gives.
    let drain = |commands: &mut mpsc::UnboundedReceiver<TransferCommand>,
                 early: &mut Vec<TransferCommand>| {
        commands.close();
        while let Ok(command) = commands.try_recv() {
            early.push(command);
        }
    };
    let Ok(mut link) = connected else {
        crate::devlog::line("transfers: the dial failed");
        drain(&mut commands, &mut early);
        fail_each(&active, &early);
        return;
    };
    if node.connected(&mut rng).is_err() {
        crate::devlog::line("transfers: the node did not start");
        drain(&mut commands, &mut early);
        fail_each(&active, &early);
        return;
    }

    let mut is_ready = false;
    let mut idle_since = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(TICK);
    'run: loop {
        for capsule in node.take_capsules() {
            if link.send(&capsule).await.is_err() {
                break 'run;
            }
        }
        let events = tokio::select! {
            received = link.recv() => match received {
                Ok(bytes) => match node.on_capsule(&bytes, crate::runtime::unix_now(), &mut rng) {
                    Ok(events) => events,
                    Err(_) => break 'run,
                },
                Err(_) => break 'run,
            },
            command = commands.recv() => match command {
                Some(command) => {
                    early.push(command);
                    Vec::new()
                }
                None => break 'run,
            },
            _ = tick.tick() => {
                node.set_challenge_clock(crate::runtime::unix_now());
                if active.is_empty() && early.is_empty() {
                    if idle_since.elapsed() >= IDLE_END {
                        break 'run;
                    }
                } else {
                    idle_since = tokio::time::Instant::now();
                }
                let mut failed = Vec::new();
                let mut read = Vec::new();
                for (tag, transfer) in &mut active {
                    node.set_chunk_class(classes.get(tag).copied().unwrap_or_default());
                    let ticked = match transfer {
                        Active::One(fetch) => fetch.tick(&mut node, &mut rng),
                        Active::Up(upload) => upload.tick(&mut node, &mut rng),
                        Active::Down(download) => download.tick(&mut node, &mut rng),
                        Active::Write(write) => write.tick(&mut node, &mut rng),
                        // A read that no relay answered ends at a tick.
                        Active::Read(reading) => match reading.tick(&mut node, &mut rng) {
                            Ok(Progress::Done(chunk)) => {
                                read.push((*tag, chunk));
                                Ok(())
                            }
                            Ok(Progress::Running(..)) => Ok(()),
                            Err(error) => Err(error),
                        },
                    };
                    if ticked.is_err() {
                        failed.push(*tag);
                    }
                }
                for tag in failed {
                    crate::devlog::line(format!("transfers: tag {tag} failed at a tick"));
                    active.remove(&tag);
                    let _ = updates.send(TransferUpdate::Failed { tag });
                }
                for (tag, found) in read {
                    active.remove(&tag);
                    let _ = updates.send(TransferUpdate::HandleRead {
                        tag,
                        chunks: found.chunks,
                        answered: found.answered,
                    });
                }
                // CIRCUIT_BUILD_TIMEOUT: a build that no relay answers ends,
                // and a run with no circuit left ends with it.
                node.on_tick(crate::runtime::unix_now())
            }
        };
        // The node commits nothing: a transfer node holds no contact. The
        // changes leave it, thus they do not pile up.
        let _ = node.take_changes();
        for event in events {
            match event {
                ClientEvent::CircuitReady => {
                    crate::devlog::line("transfers: circuit ready");
                    is_ready = true;
                }
                ClientEvent::CircuitLost | ClientEvent::CircuitAged => {
                    crate::devlog::line("transfers: circuit lost or aged");
                    break 'run;
                }
                ClientEvent::Chunk { handle, outcome } => {
                    // ATT-161: the answer of a `CDEL`. A relay that erased
                    // the chunk and a relay that holds none under the
                    // credential are both done (`WIR-317`). A relay under
                    // load is not, and the erase goes again in a later run.
                    if let Some(chunk_id) = erasing.remove(&handle) {
                        let is_gone = matches!(
                            outcome,
                            ChunkOutcome::Erased
                                | ChunkOutcome::Refused(umbra_queue::Reject::Rejected)
                        );
                        let (left, each) = erase_left.remove(&chunk_id).unwrap_or((1, true));
                        let each = each && is_gone;
                        if left > 1 {
                            erase_left.insert(chunk_id, (left.saturating_sub(1), each));
                        } else if each {
                            let _ = updates.send(TransferUpdate::Erased { chunk_id });
                        }
                        continue;
                    }
                    let owner = active.iter().find_map(|(tag, transfer)| {
                        let owns = match transfer {
                            Active::One(fetch) => fetch.owns(handle),
                            Active::Up(upload) => upload.owns(handle),
                            Active::Down(download) => download.owns(handle),
                            Active::Write(write) => write.owns(handle),
                            Active::Read(read) => read.owns(handle),
                        };
                        owns.then_some(*tag)
                    });
                    let Some(tag) = owner else { continue };
                    let Some(transfer) = active.get_mut(&tag) else {
                        continue;
                    };
                    node.set_chunk_class(classes.get(&tag).copied().unwrap_or_default());
                    let step = match transfer {
                        Active::One(fetch) => fetch
                            .on_outcome(&mut node, handle, outcome, &mut rng)
                            .map(|progress| match progress {
                                Progress::Running(done, total) => {
                                    TransferUpdate::Progress { tag, done, total }
                                }
                                Progress::Done(plain) => TransferUpdate::Downloaded {
                                    tag,
                                    plain: Zeroizing::new(plain),
                                },
                            }),
                        Active::Up(upload) => upload
                            .on_outcome(&mut node, handle, outcome, &mut rng)
                            .map(|progress| match progress {
                                Progress::Running(done, total) => {
                                    TransferUpdate::Progress { tag, done, total }
                                }
                                Progress::Done(uploaded) => TransferUpdate::Uploaded {
                                    tag,
                                    uploaded: Box::new(uploaded),
                                },
                            }),
                        Active::Down(download) => {
                            match download.on_outcome(&mut node, handle, outcome, &mut rng) {
                                Ok(Progress::Running(done, total)) => {
                                    Ok(TransferUpdate::Progress { tag, done, total })
                                }
                                Ok(Progress::Done(plain)) => Ok(TransferUpdate::Downloaded {
                                    tag,
                                    plain: Zeroizing::new(plain),
                                }),
                                Err(_) if download.is_gone() => Ok(TransferUpdate::Gone { tag }),
                                Err(error) => Err(error),
                            }
                        }
                        Active::Write(write) => write
                            .on_outcome(&mut node, handle, outcome, &mut rng)
                            .map(|progress| match progress {
                                Progress::Running(done, total) => {
                                    TransferUpdate::Progress { tag, done, total }
                                }
                                Progress::Done(relays) => {
                                    TransferUpdate::HandleWritten { tag, relays }
                                }
                            }),
                        Active::Read(read) => read
                            .on_outcome(&mut node, handle, outcome, &mut rng)
                            .map(|progress| match progress {
                                Progress::Running(done, total) => {
                                    TransferUpdate::Progress { tag, done, total }
                                }
                                Progress::Done(found) => TransferUpdate::HandleRead {
                                    tag,
                                    chunks: found.chunks,
                                    answered: found.answered,
                                },
                            }),
                    };
                    let refused = match transfer {
                        Active::One(fetch) => fetch.take_refused(),
                        Active::Down(download) => download.take_refused(),
                        _ => Vec::new(),
                    };
                    if !refused.is_empty() {
                        if let Ok(mut holds) = hold_offs.lock() {
                            let now = crate::runtime::unix_now();
                            for (chunk_id, relay_id) in refused {
                                holds.note(chunk_id, relay_id, now);
                            }
                        }
                    }
                    let update = step.unwrap_or_else(|error| {
                        crate::devlog::line(format!("transfers: tag {tag} failed: {error:?}"));
                        TransferUpdate::Failed { tag }
                    });
                    if !matches!(update, TransferUpdate::Progress { .. }) {
                        active.remove(&tag);
                    }
                    let _ = updates.send(update);
                    if node.faults().due().is_some() {
                        let faults = Box::new(node.take_faults());
                        let _ = updates.send(TransferUpdate::Faults(faults));
                    }
                }
                _ => {}
            }
        }
        if !is_ready {
            continue;
        }
        for command in early.drain(..) {
            match command {
                TransferCommand::FetchChunk {
                    tag,
                    descriptor,
                    index,
                } => {
                    // ATT-167: each start takes a mode of its own, not the mode
                    // of the transfer before it.
                    node.set_chunk_class(umbra_core::session::node::DelayClass::default());
                    let (holds, now) = held();
                    let started =
                        ChunkFetch::new(&descriptor, index, &relays, &mut rng).and_then(|fetch| {
                            let mut fetch = fetch.with_hold_offs(&holds, now);
                            fetch.tick(&mut node, &mut rng)?;
                            Ok(fetch)
                        });
                    match started {
                        Ok(fetch) => {
                            active.insert(tag, Active::One(Box::new(fetch)));
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
                TransferCommand::Mode { tag, class } => {
                    classes.insert(tag, class);
                }
                TransferCommand::Upload { tag, plain, shape } => {
                    node.set_chunk_class(classes.get(&tag).copied().unwrap_or_default());
                    let started =
                        Upload::new(&plain, shape, &relays, &mut rng).and_then(|mut upload| {
                            upload.tick(&mut node, &mut rng)?;
                            Ok(upload)
                        });
                    match started {
                        Ok(upload) => {
                            active.insert(tag, Active::Up(Box::new(upload)));
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
                TransferCommand::Challenges { book, now } => {
                    node.set_challenges(book, now);
                }
                TransferCommand::Erase {
                    chunk_id,
                    cred,
                    relays,
                } => {
                    // ATT-167: each start takes a mode of its own, not the mode
                    // of the transfer before it.
                    node.set_chunk_class(umbra_core::session::node::DelayClass::default());
                    // No transfer owns the handles, thus the task counts
                    // the answers itself. A command that did not leave
                    // counts as an answer that is not done.
                    let mut left = 0usize;
                    let mut each = !relays.is_empty();
                    for relay in relays {
                        let job = ChunkJob::Erase {
                            cred: StaticSecret::from(*cred.expose()),
                        };
                        match node.chunk(relay, chunk_id, job, &mut rng) {
                            Ok(handle) => {
                                erasing.insert(handle, chunk_id);
                                left = left.saturating_add(1);
                            }
                            Err(_) => each = false,
                        }
                    }
                    if left > 0 {
                        // A second erase of one chunk adds to the first.
                        let waits = erase_left.entry(chunk_id).or_insert((0, true));
                        *waits = (waits.0.saturating_add(left), waits.1 && each);
                    }
                    idle_since = tokio::time::Instant::now();
                }
                TransferCommand::DownloadBackup { tag, descriptor } => {
                    // ATT-167: each start takes a mode of its own, not the mode
                    // of the transfer before it.
                    node.set_chunk_class(umbra_core::session::node::DelayClass::default());
                    let (holds, now) = held();
                    let started =
                        Download::new_backup(&descriptor, &relays, &mut rng).and_then(|download| {
                            let mut download = download.with_hold_offs(&holds, now);
                            download.tick(&mut node, &mut rng)?;
                            Ok(download)
                        });
                    match started {
                        Ok(download) => {
                            active.insert(tag, Active::Down(Box::new(download)));
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
                TransferCommand::UploadBackup { tag, plain } => {
                    // ATT-167: each start takes a mode of its own, not the mode
                    // of the transfer before it.
                    node.set_chunk_class(umbra_core::session::node::DelayClass::default());
                    let started = Upload::with_class(
                        &plain,
                        Shape::default(),
                        &relays,
                        Class::BACKUP,
                        &mut rng,
                    )
                    .and_then(|mut upload| {
                        upload.tick(&mut node, &mut rng)?;
                        Ok(upload)
                    });
                    match started {
                        Ok(upload) => {
                            active.insert(tag, Active::Up(Box::new(upload)));
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
                TransferCommand::WriteHandle {
                    tag,
                    handle,
                    cred,
                    read_pk,
                    chunk,
                    replaces,
                } => {
                    // ATT-167: each start takes a mode of its own, not the mode
                    // of the transfer before it.
                    node.set_chunk_class(umbra_core::session::node::DelayClass::default());
                    let started = HandleWrite::new(handle, cred, read_pk, chunk, replaces, &relays)
                        .and_then(|mut write| {
                            write.tick(&mut node, &mut rng)?;
                            Ok(write)
                        });
                    match started {
                        Ok(write) => {
                            active.insert(tag, Active::Write(Box::new(write)));
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
                TransferCommand::ReadHandle { tag, handle, read } => {
                    // ATT-167: each start takes a mode of its own, not the mode
                    // of the transfer before it.
                    node.set_chunk_class(umbra_core::session::node::DelayClass::default());
                    let mut reading = HandleRead::new(handle, read, &relays);
                    match reading.tick(&mut node, &mut rng) {
                        Ok(Progress::Running(..)) => {
                            active.insert(tag, Active::Read(Box::new(reading)));
                        }
                        Ok(Progress::Done(found)) => {
                            let _ = updates.send(TransferUpdate::HandleRead {
                                tag,
                                chunks: found.chunks,
                                answered: found.answered,
                            });
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
                TransferCommand::Download { tag, descriptor } => {
                    node.set_chunk_class(classes.get(&tag).copied().unwrap_or_default());
                    let (holds, now) = held();
                    let started =
                        Download::new(&descriptor, &relays, &mut rng).and_then(|download| {
                            let mut download = download.with_hold_offs(&holds, now);
                            download.tick(&mut node, &mut rng)?;
                            Ok(download)
                        });
                    match started {
                        Ok(download) => {
                            active.insert(tag, Active::Down(Box::new(download)));
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
            }
        }
    }
    crate::devlog::line(format!(
        "transfers: the run ended with {} open and {} waiting",
        active.len(),
        early.len()
    ));
    drain(&mut commands, &mut early);
    fail_each(&active, &early);
}
