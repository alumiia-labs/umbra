//! The runtime of the attachment transfers (Part 13 §13.8): one task with a
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
        place::AttachmentRelay,
        transfer::{Download, Progress, Shape, Upload, Uploaded},
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
    /// The transfer ended with no result. The caller can ask again.
    Failed {
        /// The tag of the command.
        tag: u64,
    },
}

enum Active {
    Up(Box<Upload>),
    Down(Box<Download>),
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
            if let TransferCommand::Upload { tag, .. } | TransferCommand::Download { tag, .. } =
                command
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
                if active.is_empty() && early.is_empty() {
                    if idle_since.elapsed() >= IDLE_END {
                        break 'run;
                    }
                } else {
                    idle_since = tokio::time::Instant::now();
                }
                let mut failed = Vec::new();
                for (tag, transfer) in &mut active {
                    let ticked = match transfer {
                        Active::Up(upload) => upload.tick(&mut node, &mut rng),
                        Active::Down(download) => download.tick(&mut node, &mut rng),
                    };
                    if ticked.is_err() {
                        failed.push(*tag);
                    }
                }
                for tag in failed {
                    active.remove(&tag);
                    let _ = updates.send(TransferUpdate::Failed { tag });
                }
                Vec::new()
            }
        };
        // The node commits nothing: a transfer node holds no contact. The
        // changes leave it, thus they do not pile up.
        let _ = node.take_changes();
        for event in events {
            match event {
                ClientEvent::CircuitReady => is_ready = true,
                ClientEvent::CircuitLost => break 'run,
                ClientEvent::Chunk { handle, outcome } => {
                    let owner = active.iter().find_map(|(tag, transfer)| {
                        let owns = match transfer {
                            Active::Up(upload) => upload.owns(handle),
                            Active::Down(download) => download.owns(handle),
                        };
                        owns.then_some(*tag)
                    });
                    let Some(tag) = owner else { continue };
                    let Some(transfer) = active.get_mut(&tag) else {
                        continue;
                    };
                    let step = match transfer {
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
