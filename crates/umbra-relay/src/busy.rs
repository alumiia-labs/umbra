//! The time that one task runs, for a measurement over real sockets alone.
//! A task runs only inside its polls, thus the sum of their times shows
//! whether the task is the limit of a flow.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

/// The time that a task ran.
#[derive(Debug, Default)]
pub struct BusyGauge {
    nanos: AtomicU64,
}

impl BusyGauge {
    /// The time that the task ran so far.
    pub fn total(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::Relaxed))
    }

    fn add(&self, time: Duration) {
        let nanos = u64::try_from(time.as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, Ordering::Relaxed);
    }
}

/// A future that adds the time of each poll to its gauge.
pub struct Timed<F> {
    work: Pin<Box<F>>,
    gauge: Arc<BusyGauge>,
}

impl<F: Future> Timed<F> {
    /// Times `work` on `gauge`.
    pub fn new(gauge: Arc<BusyGauge>, work: F) -> Self {
        Timed {
            work: Box::pin(work),
            gauge,
        }
    }
}

impl<F: Future> Future for Timed<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        let start = Instant::now();
        let polled = this.work.as_mut().poll(context);
        this.gauge.add(start.elapsed());
        polled
    }
}
