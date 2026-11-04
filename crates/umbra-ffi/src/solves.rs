//! The proof of work of the uploads of one transfer task (Part 13 `ABU-107`).
//! A solve on the task holds each send and each answer of the task, thus the
//! solves run on threads of their own, and a registration with no solution
//! waits at its node. One batch runs at a time, and it ends at its count.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use tokio::sync::mpsc;
use umbra_core::{
    abuse::{pow::PowSolution, POW_CHUNK_ALLOWANCE},
    attach::transfer::Upload,
    session::node::ClientNode,
};

use crate::runtime::{unix_now, OsRng};

/// The solutions that an upload holds ahead for one relay at the most. A
/// solution serves while its challenge is the newest, and an upload can end
/// early, thus a stock for a long upload ends unused.
const SOLVE_AHEAD_MAX: usize = 8;
/// A stock under this count at one relay starts a batch. Thus a batch holds
/// more than one solution, and each thread start pays for several.
const SOLVE_AHEAD_LOW: usize = SOLVE_AHEAD_MAX / 2;

/// The solutions to make at one relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Job {
    relay: [u8; 32],
    seed: [u8; 32],
    effort: u32,
    left: usize,
}

/// One result of a batch.
pub(crate) enum Solved {
    /// One solution for the upload `name`.
    One {
        name: u64,
        relay: [u8; 32],
        solution: PowSolution,
    },
    /// The batch of the upload `name` ended with `count` solutions.
    Ended { name: u64, count: usize },
}

/// The solves of one upload. A drop stops them, thus each way that an upload
/// ends stops its threads.
pub(crate) struct UploadSolves {
    name: u64,
    /// The registrations at each relay that no solution covers yet.
    uncovered: BTreeMap<[u8; 32], usize>,
    stop: Arc<AtomicBool>,
}

impl UploadSolves {
    /// The solves of `upload`. From now on its registrations wait for them.
    pub(crate) fn new(node: &mut ClientNode, upload: &Upload) -> Self {
        let name = upload.admission_name();
        node.chunk_admissions().solve_apart(name);

        UploadSolves {
            name,
            uncovered: upload.registrations(),
            stop: Arc::default(),
        }
    }

    /// The name of the upload at its node.
    pub(crate) fn name(&self) -> u64 {
        self.name
    }

    /// One solution for `relay` came.
    pub(crate) fn cover(&mut self, relay: &[u8; 32]) {
        if let Some(uncovered) = self.uncovered.get_mut(relay) {
            *uncovered = uncovered.saturating_sub(usize::from(POW_CHUNK_ALLOWANCE));
        }
    }

    /// Stops each thread of this upload.
    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// The batch that this upload needs now, if any. A repair or a new
    /// challenge needs more registrations than the count at the start, and
    /// the registrations that wait at the node ask for those solutions.
    fn jobs(&mut self, node: &mut ClientNode) -> Vec<Job> {
        if !node.chunk_admissions().is_apart(self.name) {
            return Vec::new();
        }

        let waiting = node.unsolved_of(self.name);
        for relay in waiting.keys() {
            self.uncovered.entry(*relay).or_default();
        }

        let admissions = node.chunk_admissions();
        let mut jobs = Vec::new();
        let mut is_due = false;
        for (relay, uncovered) in &self.uncovered {
            let Some((seed, effort)) = admissions.work(relay) else {
                continue;
            };

            let stocked = admissions.stocked(self.name, relay);
            let waits = waiting.get(relay).copied().unwrap_or(0);
            let left = waits
                .max(*uncovered)
                .div_ceil(usize::from(POW_CHUNK_ALLOWANCE))
                .min(SOLVE_AHEAD_MAX.saturating_sub(stocked));
            if left == 0 {
                continue;
            }

            is_due = is_due || waits > 0 || stocked < SOLVE_AHEAD_LOW;
            jobs.push(Job {
                relay: *relay,
                seed,
                effort,
                left,
            });
        }

        if is_due {
            jobs
        } else {
            Vec::new()
        }
    }
}

impl Drop for UploadSolves {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The batches of one transfer task.
pub(crate) struct Solves {
    sender: mpsc::UnboundedSender<Solved>,
    receiver: mpsc::UnboundedReceiver<Solved>,
    is_running: bool,
}

impl Solves {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();

        Solves {
            sender,
            receiver,
            is_running: false,
        }
    }

    /// The next result of the batch that runs. With no batch this waits.
    pub(crate) async fn recv(&mut self) -> Option<Solved> {
        self.receiver.recv().await
    }

    /// The batch that ran ended.
    pub(crate) fn ended(&mut self) {
        self.is_running = false;
    }

    /// Starts a batch for the first upload that needs one. One batch at a
    /// time keeps the threads of two uploads to the thread count of one.
    pub(crate) fn top_up<'a>(
        &mut self,
        node: &mut ClientNode,
        uploads: impl Iterator<Item = &'a mut UploadSolves>,
    ) {
        if self.is_running {
            return;
        }

        for upload in uploads {
            let jobs = upload.jobs(node);
            if jobs.is_empty() {
                continue;
            }

            self.is_running = true;
            let batch = Batch {
                name: upload.name,
                stop: upload.stop.clone(),
                until: node.chunk_admissions().solve_until(),
                sender: self.sender.clone(),
            };
            let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
            tokio::task::spawn_blocking(move || batch.run(jobs, threads));
            return;
        }
    }
}

/// What the threads of one batch share.
struct Batch {
    name: u64,
    stop: Arc<AtomicBool>,
    /// The end of the period of `ABU-069`.
    until: u64,
    sender: mpsc::UnboundedSender<Solved>,
}

impl Batch {
    fn run(&self, jobs: Vec<Job>, threads: usize) {
        let jobs = Mutex::new(jobs);

        let count = std::thread::scope(|scope| {
            // A thread that does not start costs its share. With no thread
            // the count is 0, and the upload solves at its sends.
            let workers: Vec<_> = (0..threads)
                .filter_map(|_| {
                    std::thread::Builder::new()
                        .spawn_scoped(scope, || self.work(&jobs))
                        .ok()
                })
                .collect();

            workers
                .into_iter()
                .map(|worker| worker.join().unwrap_or(0))
                .sum()
        });

        let _ = self.sender.send(Solved::Ended {
            name: self.name,
            count,
        });
    }

    /// Runs attempts until each job ends, and gives the count of solutions.
    fn work(&self, jobs: &Mutex<Vec<Job>>) -> usize {
        let mut count = 0usize;

        while !self.stop.load(Ordering::Relaxed) && unix_now() < self.until {
            // The job with the most left takes the next attempt.
            let next = jobs.lock().ok().and_then(|jobs| {
                jobs.iter()
                    .filter(|job| job.left > 0)
                    .max_by_key(|job| job.left)
                    .copied()
            });
            let Some(job) = next else {
                break;
            };

            let attempt = PowSolution::attempt(&job.relay, &job.seed, job.effort, &mut OsRng);
            let Ok(found) = attempt else {
                break;
            };
            let Some(solution) = found else {
                continue;
            };

            let Ok(mut jobs) = jobs.lock() else {
                break;
            };
            let open = jobs
                .iter_mut()
                .find(|open| open.relay == job.relay && open.left > 0);
            if let Some(open) = open {
                open.left = open.left.saturating_sub(1);
                count = count.saturating_add(1);
                let _ = self.sender.send(Solved::One {
                    name: self.name,
                    relay: job.relay,
                    solution,
                });
            }
        }

        count
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const EFFORT: u32 = 2;

    fn job(relay: u8, left: usize) -> Job {
        Job {
            relay: [relay; 32],
            seed: [9; 32],
            effort: EFFORT,
            left,
        }
    }

    fn batch(stop: bool, until: u64) -> (Batch, mpsc::UnboundedReceiver<Solved>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let batch = Batch {
            name: 7,
            stop: Arc::new(AtomicBool::new(stop)),
            until,
            sender,
        };

        (batch, receiver)
    }

    fn results(mut receiver: mpsc::UnboundedReceiver<Solved>) -> (Vec<[u8; 32]>, usize) {
        let mut relays = Vec::new();
        let mut ended = 0;
        while let Ok(solved) = receiver.try_recv() {
            match solved {
                Solved::One {
                    name,
                    relay,
                    solution,
                } => {
                    assert_eq!(name, 7);
                    solution.check(&relay).unwrap();
                    relays.push(relay);
                }
                Solved::Ended { name, count } => {
                    assert_eq!(name, 7);
                    assert_eq!(count, relays.len());
                    ended += 1;
                }
            }
        }

        (relays, ended)
    }

    #[test]
    fn a_batch_makes_its_count_and_ends() {
        let (batch, receiver) = batch(false, u64::MAX);

        batch.run(vec![job(1, 2), job(2, 1)], 3);

        let (mut relays, ended) = results(receiver);
        relays.sort_unstable();
        assert_eq!(relays, vec![[1; 32], [1; 32], [2; 32]]);
        assert_eq!(ended, 1);
    }

    #[test]
    fn a_stopped_batch_makes_nothing_and_still_ends() {
        let (batch, receiver) = batch(true, u64::MAX);

        batch.run(vec![job(1, 2)], 2);

        assert_eq!(results(receiver), (Vec::new(), 1));
    }

    #[test]
    fn an_upload_that_ends_stops_its_threads() {
        let stop = Arc::new(AtomicBool::new(false));
        let upload = UploadSolves {
            name: 7,
            uncovered: BTreeMap::new(),
            stop: stop.clone(),
        };

        drop(upload);

        assert!(stop.load(Ordering::Relaxed));
    }

    #[test]
    fn no_attempt_starts_past_the_period_of_the_fetch() {
        let (batch, receiver) = batch(false, unix_now());

        batch.run(vec![job(1, 2)], 2);

        assert_eq!(results(receiver), (Vec::new(), 1));
    }
}
