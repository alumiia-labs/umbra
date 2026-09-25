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
        place::AttachmentRelay,
        transfer::{ChunkFetch, Class, Download, Progress, Shape, Upload, Uploaded},
    },
    session::node::{ChunkJob, ClientEvent, ClientNode},
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
    /// a copy (`ATT-161`). No update follows.
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
    /// The chunk under a handle, or `None` when no relay holds one.
    HandleRead {
        /// The tag of the command.
        tag: u64,
        /// The chunk.
        chunk: Option<Vec<u8>>,
    },
    /// The transfer ended with no result. The caller can ask again.
    Failed {
        /// The tag of the command.
        tag: u64,
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
    mut commands: mpsc::UnboundedReceiver<TransferCommand>,
    updates: mpsc::UnboundedSender<TransferUpdate>,
) {
    let mut rng = OsRng;
    let mut active: BTreeMap<u64, Active> = BTreeMap::new();
    let mut early: Vec<TransferCommand> = Vec::new();
    let fail_each = |active: &BTreeMap<u64, Active>, early: &[TransferCommand]| {
        for tag in active.keys() {
            let _ = updates.send(TransferUpdate::Failed { tag: *tag });
        }
        for command in early {
            // An erase that did not leave is lost with this run. The relays
            // erase the chunk at the end of its life (`ATT-046`).
            if let TransferCommand::Upload { tag, .. }
            | TransferCommand::Download { tag, .. }
            | TransferCommand::FetchChunk { tag, .. }
            | TransferCommand::WriteHandle { tag, .. }
            | TransferCommand::ReadHandle { tag, .. }
            | TransferCommand::UploadBackup { tag, .. }
            | TransferCommand::DownloadBackup { tag, .. } = command
            {
                let _ = updates.send(TransferUpdate::Failed { tag: *tag });
            }
        }
    };

    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    let connected = native::connect(&guard, tls, plan, key, mask, Duration::from_secs(10)).await;
    let Ok(mut link) = connected else {
        while let Ok(command) = commands.try_recv() {
            early.push(command);
        }
        fail_each(&active, &early);
        return;
    };
    if node.connected(&mut rng).is_err() {
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
                    active.remove(&tag);
                    let _ = updates.send(TransferUpdate::Failed { tag });
                }
                for (tag, chunk) in read {
                    active.remove(&tag);
                    let _ = updates.send(TransferUpdate::HandleRead { tag, chunk });
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
                ClientEvent::CircuitReady => is_ready = true,
                ClientEvent::CircuitLost | ClientEvent::CircuitAged => break 'run,
                ClientEvent::Chunk { handle, outcome } => {
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
                        Active::Down(download) => download
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
                                Progress::Done(chunk) => TransferUpdate::HandleRead { tag, chunk },
                            }),
                    };
                    let update = step.unwrap_or(TransferUpdate::Failed { tag });
                    if !matches!(update, TransferUpdate::Progress { .. }) {
                        active.remove(&tag);
                    }
                    let _ = updates.send(update);
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
                    let started = ChunkFetch::new(&descriptor, index, &relays, &mut rng).and_then(
                        |mut fetch| {
                            fetch.tick(&mut node, &mut rng)?;
                            Ok(fetch)
                        },
                    );
                    match started {
                        Ok(fetch) => {
                            active.insert(tag, Active::One(Box::new(fetch)));
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
                TransferCommand::Upload { tag, plain, shape } => {
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
                    for relay in relays {
                        let job = ChunkJob::Erase {
                            cred: StaticSecret::from(*cred.expose()),
                        };
                        // No transfer owns the handle, thus the answer goes
                        // nowhere.
                        let _ = node.chunk(relay, chunk_id, job, &mut rng);
                    }
                    idle_since = tokio::time::Instant::now();
                }
                TransferCommand::DownloadBackup { tag, descriptor } => {
                    let started = Download::new_backup(&descriptor, &relays, &mut rng).and_then(
                        |mut download| {
                            download.tick(&mut node, &mut rng)?;
                            Ok(download)
                        },
                    );
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
                    let mut reading = HandleRead::new(handle, read, &relays);
                    match reading.tick(&mut node, &mut rng) {
                        Ok(Progress::Running(..)) => {
                            active.insert(tag, Active::Read(Box::new(reading)));
                        }
                        Ok(Progress::Done(chunk)) => {
                            let _ = updates.send(TransferUpdate::HandleRead { tag, chunk });
                        }
                        Err(_) => {
                            let _ = updates.send(TransferUpdate::Failed { tag });
                        }
                    }
                }
                TransferCommand::Download { tag, descriptor } => {
                    let started =
                        Download::new(&descriptor, &relays, &mut rng).and_then(|mut download| {
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
    fail_each(&active, &early);
}
