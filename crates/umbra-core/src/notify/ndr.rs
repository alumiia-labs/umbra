//! The Notification Delivery Relay of Part 8 §8.2: the registrations, and
//! the dispatch that opens a push token for one push and keeps nothing.
//!
//! The NDR holds `(handle, ct_token)` and the hash of a removal secret for
//! each registration. It never holds `k_tok`: a push brings it, the token
//! opens, and both leave with the delivery (§8.2.1).
//!
//! A timer registration of Periodic mode holds the plain token instead,
//! because the NDR pushes to it on a clock of its own and no queue relay
//! brings a key (`NTF-150`). It names no queue, thus it binds the token to
//! nothing that a queue relay knows.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_crypto::{aead, hash::sha3_256, secret::Secret, zeroize::Zeroizing};
use umbra_wire::ndr::{parse_token, NdrRequest, NdrResponse, TokenCarrier, BLOB_LEN, HANDLE_LEN};

use super::{PERIODIC_INTERVAL, PUSH_TTL_MESSAGE};

/// One registration, as the store of the NDR holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The nonce of the seal of the token, or zero bytes for a timer.
    pub nonce: [u8; 24],
    /// The sealed push token with its tag, or the plain token of a timer.
    pub ct_token: Vec<u8>,
    /// `SHA3-256` of the removal secret (`NTF-124`).
    pub removal_hash: [u8; 32],
    /// The time of the `NREG` that made or moved it, in seconds
    /// (`NTF-138`).
    pub registered_at: u64,
    /// Whether a push went to the provider under it. A move keeps the mark,
    /// and the bound of the NDR reads it (§8.2.7).
    pub pushed: bool,
    /// Whether it is a timer registration of Periodic mode (`NTF-150`).
    pub timer: bool,
}

/// The second of each `PERIODIC_INTERVAL` at which the NDR pushes to a
/// timer registration (`NTF-150`). The handle is random, thus the phases
/// spread over the interval, and the NDR stores no phase.
pub fn phase_of(handle: &[u8; HANDLE_LEN]) -> u64 {
    let mut head = [0u8; 8];
    for (slot, byte) in head.iter_mut().zip(handle.iter()) {
        *slot = *byte;
    }
    u64::from_be_bytes(head) % PERIODIC_INTERVAL
}

/// The time that a registration lives after its last `NREG` (`NTF-138`).
pub const NDR_REG_TTL: u64 = 60 * 86_400;

/// Whether a registration made at `registered_at` lived past
/// `NDR_REG_TTL` at `now`.
const fn expired(registered_at: u64, now: u64) -> bool {
    now.saturating_sub(registered_at) >= NDR_REG_TTL
}

/// One change of the stored registrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdrChange {
    /// A registration is new, or it replaced one.
    Registered {
        /// The handle.
        handle: [u8; HANDLE_LEN],
        /// The registration.
        held: Held,
    },
    /// A registration left: an `NUNREG`, or a token that the provider
    /// named gone.
    Unregistered {
        /// The handle.
        handle: [u8; HANDLE_LEN],
    },
    /// The first push of a registration went to the provider.
    Pushed {
        /// The handle.
        handle: [u8; HANDLE_LEN],
    },
}

/// One push for the provider. The target is the open push token, which
/// the server uses for this one request and drops.
pub struct Delivery {
    /// The handle, for `Ndr::gone` when the provider refuses the target.
    pub handle: [u8; HANDLE_LEN],
    /// The provider, which is FCM (`NTF-134`).
    pub carrier: TokenCarrier,
    /// The FCM registration token.
    pub target: Zeroizing<Vec<u8>>,
    /// The expiry for the provider, in seconds.
    pub ttl: u32,
    /// The blob of a push of a queue relay, or none for a tick of the
    /// fixed clock, which carries no content (`NTF-150`).
    pub blob: Option<[u8; BLOB_LEN]>,
}

/// The removal secret of the next registration of a handle (Part 8
/// `NTF-124`): each registration after the first takes the next secret of
/// the chain.
pub fn next_removal(removal: &Secret<32>) -> Secret<32> {
    Secret::new(sha3_256(&[
        umbra_crypto::labels::NDR_REMOVAL,
        removal.expose(),
    ]))
}

/// Whether `secret` opens a registration whose removal hash is `held`: the
/// secret of that registration, or the one before it in the chain, whose
/// move the device may not have seen taken.
fn opens_registration(secret: &Secret<32>, held: &[u8; 32]) -> bool {
    let presented = sha3_256(&[secret.expose()]);
    let chained = sha3_256(&[next_removal(secret).expose()]);
    umbra_crypto::ct_eq(&presented, held) | umbra_crypto::ct_eq(&chained, held)
}

/// The Notification Delivery Relay.
#[derive(Default)]
pub struct Ndr {
    held: BTreeMap<[u8; HANDLE_LEN], Held>,
    /// Each timer registration by its phase, for the clock (`NTF-150`).
    timers: BTreeSet<(u64, [u8; HANDLE_LEN])>,
    changes: Vec<NdrChange>,
}

impl Ndr {
    /// An NDR that holds the registrations of an earlier run.
    pub fn restore(held: impl IntoIterator<Item = ([u8; HANDLE_LEN], Held)>) -> Self {
        let held: BTreeMap<[u8; HANDLE_LEN], Held> = held.into_iter().collect();
        let timers = held
            .iter()
            .filter(|(_, registration)| registration.timer)
            .map(|(handle, _)| (phase_of(handle), *handle))
            .collect();

        Ndr {
            held,
            timers,
            changes: Vec::new(),
        }
    }

    /// The timer registrations that the NDR holds.
    pub fn timers(&self) -> usize {
        self.timers.len()
    }

    /// The tick of each timer registration whose phase falls after `from`
    /// and at or before `to` (`NTF-150`). A registration past its time
    /// gives none, and the sweep of `NTF-138` drops it.
    pub fn ticks(&self, from: u64, to: u64) -> Vec<Delivery> {
        if to <= from {
            return Vec::new();
        }

        let (start, end) = (from % PERIODIC_INTERVAL, to % PERIODIC_INTERVAL);
        let lowest = (0, [0u8; HANDLE_LEN]);
        let highest = (u64::MAX, [0xFF; HANDLE_LEN]);
        let after = (start, [0xFF; HANDLE_LEN]);
        let through = (end, [0xFF; HANDLE_LEN]);

        // A span of one interval or more reaches each phase. A span that
        // passes the end of the interval reaches the phases on both sides.
        let mut due: Vec<&(u64, [u8; HANDLE_LEN])> = if to - from >= PERIODIC_INTERVAL {
            self.timers.iter().collect()
        } else if start < end {
            self.timers.range(after..=through).collect()
        } else {
            self.timers
                .range(after..=highest)
                .chain(self.timers.range(lowest..=through))
                .collect()
        };
        due.dedup();

        due.into_iter()
            .filter_map(|(_, handle)| {
                let held = self.held.get(handle)?;
                if expired(held.registered_at, to) {
                    return None;
                }

                let (carrier, target) = parse_token(&held.ct_token).ok()?;
                Some(Delivery {
                    handle: *handle,
                    carrier,
                    target: Zeroizing::new(target.to_vec()),
                    ttl: u32::try_from(PERIODIC_INTERVAL).unwrap_or(u32::MAX),
                    blob: None,
                })
            })
            .collect()
    }

    /// Marks the registration of `handle` as one that took a push. The
    /// result is whether the mark is new, and then a change waits.
    pub fn took_push(&mut self, handle: &[u8; HANDLE_LEN]) -> bool {
        match self.held.get_mut(handle) {
            Some(held) if !held.pushed => {
                held.pushed = true;
                self.changes.push(NdrChange::Pushed { handle: *handle });
                true
            }
            _ => false,
        }
    }

    /// The registrations held.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The changes since the last call, which the server commits before it
    /// sends the answer of the same call.
    pub fn take_changes(&mut self) -> Vec<NdrChange> {
        core::mem::take(&mut self.changes)
    }

    /// Serves one request. A push gives the delivery that the server hands
    /// to the provider. Each refusal gives one answer (`WIR-032`).
    pub fn handle(&mut self, request: &[u8], now: u64) -> (NdrResponse, Option<Delivery>) {
        match NdrRequest::parse(request) {
            Ok(parsed) => self.serve(parsed, now),
            Err(_) => (NdrResponse::Refused, None),
        }
    }

    /// Drops each registration that no `NREG` renewed inside
    /// `NDR_REG_TTL` (`NTF-138`). The result is the count that left.
    pub fn expire(&mut self, now: u64) -> usize {
        let gone: Vec<[u8; HANDLE_LEN]> = self
            .held
            .iter()
            .filter(|(_, held)| expired(held.registered_at, now))
            .map(|(handle, _)| *handle)
            .collect();

        for handle in &gone {
            self.drop_handle(*handle);
        }

        gone.len()
    }

    /// Holds a registration under `handle`, new or moved. A handle that is
    /// held moves on its removal secret alone (`NTF-124`). The result is
    /// whether the NDR took it.
    fn hold(&mut self, handle: [u8; HANDLE_LEN], mut held: Held, prior: &Secret<32>) -> bool {
        // NTF-124: a handle that is held moves on its removal secret alone,
        // thus a queue relay that knows the handle cannot point it
        // elsewhere. The secret of the held registration moves it, and so
        // does the secret before it in the chain: that request repeats a
        // move whose answer was lost.
        if let Some(before) = self.held.get(&handle) {
            if !opens_registration(prior, &before.removal_hash) {
                return false;
            }
            held.pushed = before.pushed;
            if before.timer {
                self.timers.remove(&(phase_of(&handle), handle));
            }
        }

        if held.timer {
            self.timers.insert((phase_of(&handle), handle));
        }
        self.held.insert(handle, held.clone());
        self.changes.push(NdrChange::Registered { handle, held });
        true
    }

    fn serve(&mut self, request: NdrRequest<'_>, now: u64) -> (NdrResponse, Option<Delivery>) {
        match request {
            NdrRequest::Register {
                handle,
                nonce,
                ct_token,
                removal_hash,
                prior,
            } => {
                let held = Held {
                    nonce,
                    ct_token: ct_token.to_vec(),
                    removal_hash,
                    registered_at: now,
                    pushed: false,
                    timer: false,
                };
                if self.hold(handle, held, &prior) {
                    (NdrResponse::Taken, None)
                } else {
                    (NdrResponse::Refused, None)
                }
            }
            NdrRequest::Timer {
                handle,
                token,
                removal_hash,
                prior,
            } => {
                // NTF-134: the NDR posts to FCM alone, thus it holds no token
                // of another carrier for its clock.
                if parse_token(token).is_err() {
                    return (NdrResponse::Refused, None);
                }

                let held = Held {
                    nonce: [0; 24],
                    ct_token: token.to_vec(),
                    removal_hash,
                    registered_at: now,
                    pushed: false,
                    timer: true,
                };
                if self.hold(handle, held, &prior) {
                    (NdrResponse::Taken, None)
                } else {
                    (NdrResponse::Refused, None)
                }
            }
            NdrRequest::Unregister { handle, removal } => {
                match self.held.get(&handle) {
                    Some(held) if opens_registration(&removal, &held.removal_hash) => {
                        self.drop_handle(handle);
                        (NdrResponse::Taken, None)
                    }
                    // NTF-124: a handle that the NDR does not hold left
                    // already, thus a repeat of a lost answer ends.
                    None => (NdrResponse::Taken, None),
                    Some(_) => (NdrResponse::Refused, None),
                }
            }
            NdrRequest::Push {
                handle,
                k_tok,
                ttl,
                blob,
            } => {
                // NTF-125: a handle that no registration holds is gone, thus
                // the queue relay stops its pushes to it.
                let Some(held) = self.held.get(&handle) else {
                    return (NdrResponse::Gone, None);
                };

                // NTF-138: a registration past its time is gone too.
                if expired(held.registered_at, now) {
                    self.drop_handle(handle);
                    return (NdrResponse::Gone, None);
                }

                // NTF-150: a timer names no queue, thus no queue relay
                // pushes to it, and its plain token opens under no key.
                if held.timer {
                    return (NdrResponse::Refused, None);
                }

                let split = held.ct_token.len().saturating_sub(aead::TAG_LEN);
                let (Some(body), Some(tag)) =
                    (held.ct_token.get(..split), held.ct_token.get(split..))
                else {
                    return (NdrResponse::Refused, None);
                };
                let mut token = Zeroizing::new(body.to_vec());
                if aead::open(&k_tok, &held.nonce, &handle, &mut token, tag).is_err() {
                    return (NdrResponse::Refused, None);
                }

                // NTF-134: the NDR posts to FCM alone, and to no address
                // that a caller named. The reserved carrier does not read.
                let Ok((carrier, target)) = parse_token(&token) else {
                    return (NdrResponse::Refused, None);
                };

                let delivery = Delivery {
                    handle,
                    carrier,
                    target: Zeroizing::new(target.to_vec()),
                    // NTF-125: the NDR bounds the expiry that a relay asks.
                    ttl: ttl.min(u32::try_from(PUSH_TTL_MESSAGE).unwrap_or(u32::MAX)),
                    blob: Some(blob),
                };
                (NdrResponse::Taken, Some(delivery))
            }
        }
    }

    /// The provider named the target of `handle` gone: the NDR drops the
    /// registration, and the next push of that handle is refused.
    pub fn gone(&mut self, handle: [u8; HANDLE_LEN]) {
        if self.held.contains_key(&handle) {
            self.drop_handle(handle);
        }
    }

    fn drop_handle(&mut self, handle: [u8; HANDLE_LEN]) {
        if self.held.remove(&handle).is_some_and(|held| held.timer) {
            self.timers.remove(&(phase_of(&handle), handle));
        }
        self.changes.push(NdrChange::Unregistered { handle });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::{abuse::test_rng::Rng, notify::token::HandleSet};
    use umbra_crypto::secret::Secret;
    use umbra_wire::ndr::{encode_token, NDR_REQUEST_LEN, PUSH_TOKEN_MAX};

    const NOW: u64 = 1_700_000_000;

    fn request(request: &NdrRequest<'_>) -> [u8; NDR_REQUEST_LEN] {
        let mut out = [0u8; NDR_REQUEST_LEN];
        request.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn a_push_opens_the_token_once_and_the_removal_needs_its_secret() {
        let mut rng = Rng(2);
        let set = HandleSet::assign(&[[1; 32]], &[], &[], 0, &mut rng).unwrap();
        let group = &set.groups()[0];
        let mut plain = [0u8; PUSH_TOKEN_MAX];
        let n = encode_token(TokenCarrier::Fcm, b"fcm-device-1", &mut plain).unwrap();
        let registration = group.registration(&plain[..n], [4; 24]).unwrap();
        let removal = Secret::new([9; 32]);
        let register = |prior: [u8; 32], removal_hash: [u8; 32]| {
            request(&NdrRequest::Register {
                handle: group.handle,
                nonce: registration.nonce,
                ct_token: &registration.ct_token,
                removal_hash,
                prior: Secret::new(prior),
            })
        };
        let mut ndr = Ndr::default();
        let hash = sha3_256(&[removal.expose()]);
        assert_eq!(
            ndr.handle(&register([0; 32], hash), NOW).0,
            NdrResponse::Taken
        );
        assert_eq!(ndr.take_changes().len(), 1);

        // NTF-124: the same registration again, whose answer was lost, is
        // taken when it carries the secret that the device holds; with no
        // secret it moves nothing.
        assert_eq!(
            ndr.handle(&register([0; 32], hash), NOW).0,
            NdrResponse::Refused
        );
        assert_eq!(
            ndr.handle(&register([9; 32], hash), NOW).0,
            NdrResponse::Taken
        );
        assert_eq!(ndr.take_changes().len(), 1);

        // The push brings `k_tok`, and the delivery names the endpoint.
        let push = |k_tok: [u8; 32]| {
            request(&NdrRequest::Push {
                handle: group.handle,
                k_tok: Secret::new(k_tok),
                ttl: 999_999,
                blob: [6; BLOB_LEN],
            })
        };
        let (answer, delivery) = ndr.handle(&push(*group.k_tok.expose()), NOW);
        assert_eq!(answer, NdrResponse::Taken);
        let delivery = delivery.unwrap();
        assert_eq!(delivery.carrier, TokenCarrier::Fcm);
        assert_eq!(&delivery.target[..], b"fcm-device-1");
        assert_eq!(u64::from(delivery.ttl), PUSH_TTL_MESSAGE);
        assert_eq!(ndr.handle(&push([0; 32]), NOW).0, NdrResponse::Refused);

        // NTF-138: the registration lives `NDR_REG_TTL` after its NREG, and
        // a sweep before that keeps it.
        let last = NOW + NDR_REG_TTL - 1;
        assert_eq!(ndr.expire(last), 0);
        assert_eq!(
            ndr.handle(&push(*group.k_tok.expose()), last).0,
            NdrResponse::Taken
        );

        let mut later = Ndr::restore(ndr.held.clone());
        assert_eq!(
            later
                .handle(&push(*group.k_tok.expose()), NOW + NDR_REG_TTL)
                .0,
            NdrResponse::Gone
        );
        assert!(later.is_empty());

        let mut swept = Ndr::restore(ndr.held.clone());
        assert_eq!(swept.expire(NOW + NDR_REG_TTL), 1);
        assert_eq!(
            swept.take_changes(),
            alloc::vec![NdrChange::Unregistered {
                handle: group.handle
            }]
        );

        // NTF-124: a registration over a held handle needs the secret of
        // the one it replaces, and so does the removal.
        assert_eq!(
            ndr.handle(&register([1; 32], [5; 32]), NOW).0,
            NdrResponse::Refused
        );

        let wrong = request(&NdrRequest::Unregister {
            handle: group.handle,
            removal: Secret::new([1; 32]),
        });
        assert_eq!(ndr.handle(&wrong, NOW).0, NdrResponse::Refused);
        assert!(ndr.take_changes().is_empty());

        let right = request(&NdrRequest::Unregister {
            handle: group.handle,
            removal,
        });
        assert_eq!(ndr.handle(&right, NOW).0, NdrResponse::Taken);
        assert!(ndr.is_empty());

        // NTF-124: the removal again, whose answer was lost, is taken.
        assert_eq!(ndr.handle(&right, NOW).0, NdrResponse::Taken);

        // NTF-125: a push to a handle that left is gone.
        assert_eq!(
            ndr.handle(&push(*group.k_tok.expose()), NOW).0,
            NdrResponse::Gone
        );

        // NTF-134: a carrier that the NDR does not serve takes no push.
        let n = encode_token(
            TokenCarrier::UnifiedPush,
            b"https://evil.example/x",
            &mut plain,
        )
        .unwrap();
        let other = group.registration(&plain[..n], [5; 24]).unwrap();
        let taken = ndr.handle(
            &request(&NdrRequest::Register {
                handle: group.handle,
                nonce: other.nonce,
                ct_token: &other.ct_token,
                removal_hash: hash,
                prior: Secret::new([9; 32]),
            }),
            NOW,
        );
        assert_eq!(taken.0, NdrResponse::Taken);

        let (answer, delivery) = ndr.handle(&push(*group.k_tok.expose()), NOW);
        assert_eq!(answer, NdrResponse::Refused);
        assert!(delivery.is_none());
    }

    #[test]
    fn the_handle_of_a_watch_takes_no_registration_and_a_move_keeps_the_push_mark() {
        let mut rng = Rng(3);
        let set = HandleSet::assign(&[[1; 32]], &[], &[], 0, &mut rng).unwrap();
        let group = &set.groups()[0];
        let mut plain = [0u8; PUSH_TOKEN_MAX];
        let n = encode_token(TokenCarrier::Fcm, b"fcm-device-1", &mut plain).unwrap();
        let registration = group.registration(&plain[..n], [4; 24]).unwrap();
        let hash = sha3_256(&[&[9u8; 32][..]]);
        let register = request(&NdrRequest::Register {
            handle: group.handle,
            nonce: registration.nonce,
            ct_token: &registration.ct_token,
            removal_hash: hash,
            prior: Secret::new([9; 32]),
        });

        // NTF-143: the same `NREG` under 16 zero bytes is refused, and the
        // NDR holds nothing.
        let mut watch = register;
        watch[1..=HANDLE_LEN].fill(0);
        let mut ndr = Ndr::default();
        assert_eq!(ndr.handle(&watch, NOW).0, NdrResponse::Refused);
        assert!(ndr.is_empty() && ndr.take_changes().is_empty());

        assert_eq!(ndr.handle(&register, NOW).0, NdrResponse::Taken);
        drop(ndr.take_changes());

        // The first push marks the registration once, and a move keeps it.
        assert!(ndr.took_push(&group.handle));
        assert!(!ndr.took_push(&group.handle));
        assert!(!ndr.took_push(&[5; 16]));
        assert_eq!(
            ndr.take_changes(),
            alloc::vec![NdrChange::Pushed {
                handle: group.handle
            }]
        );

        assert_eq!(ndr.handle(&register, NOW + 1).0, NdrResponse::Taken);
        let changes = ndr.take_changes();
        assert!(matches!(
            changes.as_slice(),
            [NdrChange::Registered { held, .. }] if held.pushed
        ));
    }

    #[test]
    fn a_gone_target_drops_the_registration_and_a_restart_keeps_the_rest() {
        let held = Held {
            nonce: [1; 24],
            ct_token: alloc::vec![2; 40],
            removal_hash: [3; 32],
            registered_at: NOW,
            pushed: false,
            timer: false,
        };
        let mut ndr = Ndr::restore([([7; 16], held.clone()), ([8; 16], held)]);
        assert_eq!(ndr.len(), 2);

        ndr.gone([7; 16]);
        ndr.gone([9; 16]);
        assert_eq!(ndr.len(), 1);
        assert_eq!(
            ndr.take_changes(),
            [NdrChange::Unregistered { handle: [7; 16] }]
        );
        assert_eq!(ndr.handle(&[0; 12], NOW).0, NdrResponse::Refused);
    }

    fn timer(
        handle: [u8; 16],
        token: &[u8],
        removal: [u8; 32],
        prior: [u8; 32],
    ) -> [u8; NDR_REQUEST_LEN] {
        request(&NdrRequest::Timer {
            handle,
            token,
            removal_hash: sha3_256(&[&removal[..]]),
            prior: Secret::new(prior),
        })
    }

    fn fcm(target: &[u8]) -> Vec<u8> {
        let mut plain = [0u8; PUSH_TOKEN_MAX];
        let n = encode_token(TokenCarrier::Fcm, target, &mut plain).unwrap();
        plain[..n].to_vec()
    }

    #[test]
    fn a_timer_ticks_once_in_each_interval_at_the_phase_of_its_handle() {
        let mut handle = [7u8; 16];
        handle[..8].copy_from_slice(&100u64.to_be_bytes());
        assert_eq!(phase_of(&handle), 100);

        let mut ndr = Ndr::default();
        let token = fcm(b"fcm-device-1");
        assert_eq!(
            ndr.handle(&timer(handle, &token, [9; 32], [0; 32]), NOW).0,
            NdrResponse::Taken
        );
        assert_eq!(ndr.timers(), 1);
        assert!(matches!(
            ndr.take_changes().as_slice(),
            [NdrChange::Registered { held, .. }] if held.timer && held.ct_token == token
        ));

        // NTF-150: one tick in each interval, at the phase, with no blob and
        // the interval as its expiry.
        let base = NOW - NOW % PERIODIC_INTERVAL + PERIODIC_INTERVAL;
        assert!(ndr.ticks(base, base + 99).is_empty());
        let due = ndr.ticks(base + 99, base + 100);
        assert_eq!(due.len(), 1);
        assert_eq!(&due[0].target[..], b"fcm-device-1");
        assert!(due[0].blob.is_none());
        assert_eq!(u64::from(due[0].ttl), PERIODIC_INTERVAL);
        assert!(ndr
            .ticks(base + 100, base + PERIODIC_INTERVAL + 99)
            .is_empty());

        // A span that passes the end of the interval reaches both sides.
        let mut late = [8u8; 16];
        late[..8].copy_from_slice(&(PERIODIC_INTERVAL - 1).to_be_bytes());
        ndr.handle(&timer(late, &token, [9; 32], [0; 32]), NOW);
        let wrap = ndr.ticks(base - 10, base + 150);
        assert_eq!(wrap.len(), 2);
        assert_eq!(ndr.ticks(base, base + 10 * PERIODIC_INTERVAL).len(), 2);

        // NTF-150: no queue relay pushes to a timer.
        let push = request(&NdrRequest::Push {
            handle,
            k_tok: Secret::new([0; 32]),
            ttl: 60,
            blob: [6; BLOB_LEN],
        });
        assert_eq!(ndr.handle(&push, NOW).0, NdrResponse::Refused);

        // NTF-124: a move needs the secret, and a restart keeps the clock.
        assert_eq!(
            ndr.handle(
                &timer(handle, &fcm(b"fcm-device-2"), [10; 32], [1; 32]),
                NOW
            )
            .0,
            NdrResponse::Refused
        );
        assert_eq!(
            ndr.handle(
                &timer(handle, &fcm(b"fcm-device-2"), [10; 32], [9; 32]),
                NOW
            )
            .0,
            NdrResponse::Taken
        );
        let restored = Ndr::restore(ndr.held.clone());
        assert_eq!(restored.timers(), 2);
        assert_eq!(
            &restored.ticks(base + 99, base + 100)[0].target[..],
            b"fcm-device-2"
        );

        // NTF-138: a timer past its time ticks no more.
        assert!(ndr
            .ticks(NOW + NDR_REG_TTL, NOW + NDR_REG_TTL + PERIODIC_INTERVAL)
            .is_empty());

        // NTF-125: a gone token and an `NUNREG` end the clock.
        ndr.gone(late);
        let removal = request(&NdrRequest::Unregister {
            handle,
            removal: Secret::new([10; 32]),
        });
        assert_eq!(ndr.handle(&removal, NOW).0, NdrResponse::Taken);
        assert_eq!(ndr.timers(), 0);
        assert!(ndr.ticks(base, base + PERIODIC_INTERVAL).is_empty());
    }

    #[test]
    fn a_timer_takes_no_token_of_another_carrier() {
        let mut plain = [0u8; PUSH_TOKEN_MAX];
        let n = encode_token(
            TokenCarrier::UnifiedPush,
            b"https://evil.example/x",
            &mut plain,
        )
        .unwrap();
        let mut ndr = Ndr::default();
        assert_eq!(
            ndr.handle(&timer([3; 16], &plain[..n], [9; 32], [0; 32]), NOW)
                .0,
            NdrResponse::Refused
        );
        assert!(ndr.is_empty());
    }
}
