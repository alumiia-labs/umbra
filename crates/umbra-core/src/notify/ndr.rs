//! The Notification Delivery Relay of Part 8 §8.2: the registrations, and
//! the dispatch that opens a push token for one push and keeps nothing.
//!
//! The NDR holds `(handle, ct_token)` and the hash of a removal secret for
//! each registration. It never holds `k_tok`: a push brings it, the token
//! opens, and both leave with the delivery (§8.2.1).

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::{aead, hash::sha3_256, zeroize::Zeroizing};
use umbra_wire::ndr::{parse_token, NdrRequest, NdrResponse, TokenCarrier, BLOB_LEN, HANDLE_LEN};

use super::PUSH_TTL_MESSAGE;

/// One registration, as the store of the NDR holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The nonce of the seal of the token.
    pub nonce: [u8; 24],
    /// The sealed push token with its tag.
    pub ct_token: Vec<u8>,
    /// `SHA3-256` of the removal secret (`NTF-124`).
    pub removal_hash: [u8; 32],
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
}

/// One push for the provider. The target is the open push token, which
/// the server uses for this one request and drops.
pub struct Delivery {
    /// The handle, for `Ndr::gone` when the provider refuses the target.
    pub handle: [u8; HANDLE_LEN],
    /// The provider.
    pub carrier: TokenCarrier,
    /// The endpoint URL of UnifiedPush, or the FCM registration token.
    pub target: Zeroizing<Vec<u8>>,
    /// The expiry for the provider, in seconds.
    pub ttl: u32,
    /// The blob.
    pub blob: [u8; BLOB_LEN],
}

/// The Notification Delivery Relay.
#[derive(Default)]
pub struct Ndr {
    held: BTreeMap<[u8; HANDLE_LEN], Held>,
    changes: Vec<NdrChange>,
}

impl Ndr {
    /// An NDR that holds the registrations of an earlier run.
    pub fn restore(held: impl IntoIterator<Item = ([u8; HANDLE_LEN], Held)>) -> Self {
        Ndr {
            held: held.into_iter().collect(),
            changes: Vec::new(),
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
    pub fn handle(&mut self, request: &[u8]) -> (NdrResponse, Option<Delivery>) {
        match NdrRequest::parse(request) {
            Ok(parsed) => self.serve(parsed),
            Err(_) => (NdrResponse::Refused, None),
        }
    }

    fn serve(&mut self, request: NdrRequest<'_>) -> (NdrResponse, Option<Delivery>) {
        match request {
            NdrRequest::Register {
                handle,
                nonce,
                ct_token,
                removal_hash,
                prior,
            } => {
                // NTF-124: a handle that is held moves on its removal secret
                // alone, thus a queue relay that knows the handle cannot
                // point it elsewhere.
                if let Some(held) = self.held.get(&handle) {
                    let presented = sha3_256(&[prior.expose()]);
                    if !umbra_crypto::ct_eq(&presented, &held.removal_hash) {
                        return (NdrResponse::Refused, None);
                    }
                }
                let held = Held {
                    nonce,
                    ct_token: ct_token.to_vec(),
                    removal_hash,
                };
                self.held.insert(handle, held.clone());
                self.changes.push(NdrChange::Registered { handle, held });
                (NdrResponse::Taken, None)
            }
            NdrRequest::Unregister { handle, removal } => {
                let presented = sha3_256(&[removal.expose()]);
                match self.held.get(&handle) {
                    Some(held) if umbra_crypto::ct_eq(&presented, &held.removal_hash) => {
                        self.drop_handle(handle);
                        (NdrResponse::Taken, None)
                    }
                    _ => (NdrResponse::Refused, None),
                }
            }
            NdrRequest::Push {
                handle,
                k_tok,
                ttl,
                blob,
            } => {
                let Some(held) = self.held.get(&handle) else {
                    return (NdrResponse::Refused, None);
                };
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
                let Ok((carrier, target)) = parse_token(&token) else {
                    return (NdrResponse::Refused, None);
                };
                let delivery = Delivery {
                    handle,
                    carrier,
                    target: Zeroizing::new(target.to_vec()),
                    // NTF-125: the NDR bounds the expiry that a relay asks.
                    ttl: ttl.min(u32::try_from(PUSH_TTL_MESSAGE).unwrap_or(u32::MAX)),
                    blob,
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
        self.held.remove(&handle);
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
        let n = encode_token(
            TokenCarrier::UnifiedPush,
            b"https://push.example/up/device-1",
            &mut plain,
        )
        .unwrap();
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
        assert_eq!(ndr.handle(&register([0; 32], hash)).0, NdrResponse::Taken);
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
        let (answer, delivery) = ndr.handle(&push(*group.k_tok.expose()));
        assert_eq!(answer, NdrResponse::Taken);
        let delivery = delivery.unwrap();
        assert_eq!(delivery.carrier, TokenCarrier::UnifiedPush);
        assert_eq!(&delivery.target[..], b"https://push.example/up/device-1");
        assert_eq!(u64::from(delivery.ttl), PUSH_TTL_MESSAGE);
        assert_eq!(ndr.handle(&push([0; 32])).0, NdrResponse::Refused);

        // NTF-124: a registration over a held handle needs the secret of
        // the one it replaces, and so does the removal.
        assert_eq!(
            ndr.handle(&register([1; 32], [5; 32])).0,
            NdrResponse::Refused
        );
        let wrong = request(&NdrRequest::Unregister {
            handle: group.handle,
            removal: Secret::new([1; 32]),
        });
        assert_eq!(ndr.handle(&wrong).0, NdrResponse::Refused);
        assert!(ndr.take_changes().is_empty());
        let right = request(&NdrRequest::Unregister {
            handle: group.handle,
            removal,
        });
        assert_eq!(ndr.handle(&right).0, NdrResponse::Taken);
        assert!(ndr.is_empty());
        assert_eq!(
            ndr.handle(&push(*group.k_tok.expose())).0,
            NdrResponse::Refused
        );
    }

    #[test]
    fn a_gone_target_drops_the_registration_and_a_restart_keeps_the_rest() {
        let held = Held {
            nonce: [1; 24],
            ct_token: alloc::vec![2; 40],
            removal_hash: [3; 32],
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
        assert_eq!(ndr.handle(&[0; 12]).0, NdrResponse::Refused);
    }
}
