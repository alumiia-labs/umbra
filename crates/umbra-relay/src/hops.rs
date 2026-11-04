//! The stamps of the forward cells at each hop, for a measurement over real
//! sockets alone. A relay adds no stamp until a test starts a trace.

use std::{sync::Mutex, time::Instant};

/// One forward cell that took its per-hop delay (`NET-338`).
#[derive(Debug, Clone, Copy)]
pub struct Drawn {
    /// The layer of the relay.
    pub layer: u8,
    /// The time that the cell came.
    pub at: Instant,
    /// The draw of the delay, in milliseconds.
    pub draw_ms: u64,
    /// The time to the release of the cell, in milliseconds. It is above
    /// the draw when an earlier cell of the circuit goes later (`NET-339`).
    pub hold_ms: u64,
}

/// One forward cell that left its delay.
#[derive(Debug, Clone, Copy)]
pub struct Released {
    /// The layer of the relay.
    pub layer: u8,
    /// The time that the cell left.
    pub at: Instant,
    /// The time after the release time of the cell, in milliseconds: the
    /// wait for the clock of the relay.
    pub late_ms: u64,
}

/// One `CGET` that the relay of its chunk served.
#[derive(Debug, Clone, Copy)]
pub struct Served {
    /// The time of the service.
    pub at: Instant,
    /// The chunk.
    pub chunk_id: [u8; 32],
    /// The `CGET` in the cell of this one.
    pub in_cell: u32,
}

/// The stamps of all relays of this process.
#[derive(Debug, Clone, Default)]
pub struct HopTrace {
    /// Each forward cell that took a delay.
    pub drawn: Vec<Drawn>,
    /// Each forward cell that left its delay.
    pub released: Vec<Released>,
    /// Each `CGET` that a relay served.
    pub served: Vec<Served>,
}

static TRACE: Mutex<Option<HopTrace>> = Mutex::new(None);

/// Starts a new trace, and drops the one before.
pub fn start() {
    if let Ok(mut trace) = TRACE.lock() {
        *trace = Some(HopTrace::default());
    }
}

/// Ends the trace and gives it.
pub fn take() -> HopTrace {
    TRACE
        .lock()
        .ok()
        .and_then(|mut trace| trace.take())
        .unwrap_or_default()
}

fn with(change: impl FnOnce(&mut HopTrace)) {
    if let Ok(mut trace) = TRACE.lock() {
        if let Some(trace) = trace.as_mut() {
            change(trace);
        }
    }
}

pub(crate) fn drawn(layer: u8, draw_ms: u64, hold_ms: u64) {
    let at = Instant::now();

    with(|trace| {
        trace.drawn.push(Drawn {
            layer,
            at,
            draw_ms,
            hold_ms,
        });
    });
}

pub(crate) fn released(layer: u8, late_ms: u64) {
    let at = Instant::now();

    with(|trace| trace.released.push(Released { layer, at, late_ms }));
}

pub(crate) fn served(chunk_ids: &[[u8; 32]]) {
    let at = Instant::now();
    let in_cell = u32::try_from(chunk_ids.len()).unwrap_or(u32::MAX);

    with(|trace| {
        trace.served.extend(chunk_ids.iter().map(|chunk_id| Served {
            at,
            chunk_id: *chunk_id,
            in_cell,
        }));
    });
}
