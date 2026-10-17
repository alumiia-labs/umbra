//! The keys of the cross-relay issuer that a relay takes from the log
//! (Part 13 §13.5): the key of each epoch, read under a head that verifies
//! under the pinned key set of the log (`ABU-099` to `ABU-101`). A relay
//! then verifies a token of that epoch under that key, and a key that no
//! head of the log names admits nothing.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::mpsc;
use umbra_core::{
    abuse::epoch_number,
    discovery::{
        dirclient::DirectoryPins,
        reader::{self, HeldHead, LogChannel, ReadError},
    },
};
use umbra_transport::directory::{call, DirectoryRoute};

use crate::server::Input;

/// The wait between two reads when each key is held.
const READ_EVERY: Duration = Duration::from_secs(600);
/// The wait after a read that failed, as at a start before the route opens.
const READ_AGAIN: Duration = Duration::from_secs(30);

/// The pinned route of a relay to the directory, and the head it holds.
pub struct IssuerReader {
    route: DirectoryRoute,
    pins: DirectoryPins,
    tls: Arc<rustls::ClientConfig>,
    held: Mutex<Option<HeldHead>>,
}

impl IssuerReader {
    /// A reader over `route` under `pins`.
    pub fn new(route: DirectoryRoute, pins: DirectoryPins, tls: Arc<rustls::ClientConfig>) -> Self {
        IssuerReader {
            route,
            pins,
            tls,
            held: Mutex::new(None),
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl LogChannel for IssuerReader {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, ReadError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ReadError::Offline)?;

        let mut rng = crate::server::OsRng;
        runtime
            .block_on(call(&self.route, request, self.tls.clone(), &mut rng))
            .map_err(|_| ReadError::Offline)
    }

    fn pins(&self) -> &DirectoryPins {
        &self.pins
    }

    fn held(&self) -> Option<HeldHead> {
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_held(&self, head: HeldHead) {
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(head);
    }

    fn now(&self) -> u64 {
        unix_now()
    }
}

/// The epochs whose key a relay holds at `epoch`: the one before it, this
/// one, and the next one. A verifier still accepts the tokens of the one
/// before (`ABU-095`). The key of the next one enters the log before its
/// epoch (`ABU-098`).
fn wanted_epochs(epoch: u32) -> Vec<u32> {
    let mut wanted = vec![epoch.saturating_sub(1), epoch, epoch.saturating_add(1)];
    wanted.dedup();
    wanted
}

/// Reads the key of the epoch before, of this epoch, and of the next one,
/// and hands each new one to the node. A relay that starts inside an epoch
/// thus accepts a token of the epoch before it (`ABU-095`).
/// It runs on a thread of its own, since each read blocks.
pub fn keep_reading(reader: IssuerReader, inputs: mpsc::Sender<Input>) {
    let mut held: Vec<u32> = Vec::new();
    // The epoch before the first one of a log has no key. One line says
    // that its key did not come, and the read goes again at the long wait.
    let mut told_before = None;

    loop {
        let mut failed = false;
        let epoch = epoch_number(unix_now());
        held.retain(|known| *known >= epoch.saturating_sub(1));

        for wanted in wanted_epochs(epoch) {
            if held.contains(&wanted) {
                continue;
            }

            let mut rng = crate::server::OsRng;
            let read = reader::cross_relay_key(&reader, wanted, &mut rng);

            if let Err(error) = &read {
                if wanted >= epoch {
                    eprintln!("the issuer key of epoch {wanted} did not come: {error:?}");
                    failed = true;
                } else if told_before != Some(wanted) {
                    eprintln!("the issuer key of epoch {wanted} did not come: {error:?}");
                    told_before = Some(wanted);
                }
            }

            if let Ok(key) = read {
                if inputs
                    .blocking_send(Input::IssuerKey {
                        epoch: wanted,
                        key: Box::new(key),
                    })
                    .is_err()
                {
                    return;
                }
                eprintln!("the issuer key of epoch {wanted} came from the log");
                held.push(wanted);
            }
        }

        std::thread::sleep(if failed { READ_AGAIN } else { READ_EVERY });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_reads_the_key_of_the_epoch_before_too() {
        // ABU-095: a token of the epoch before passes, thus the relay holds its key.
        assert_eq!(wanted_epochs(7), [6, 7, 8]);
        // The first epoch has none before it, and no epoch reads twice.
        assert_eq!(wanted_epochs(0), [0, 1]);
        assert_eq!(wanted_epochs(u32::MAX), [u32::MAX - 1, u32::MAX]);
    }
}
