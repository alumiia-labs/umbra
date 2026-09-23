//! The push registrations of this device (Part 8 §8.2): the root of each
//! queue relay, the handle groups of at most `MAX_QUEUES_PER_HANDLE` queues
//! with their `k_tok` and removal secret, the binding of each queue, and the
//! push endpoint that the platform gave.
//!
//! The store keeps what a registration needs across runs: a queue binds
//! once, a group registers once, and a new endpoint registers each group
//! again under its removal secret (`NTF-124`).

use umbra_core::{
    notify::{binding::Binding, MAX_QUEUES_PER_HANDLE},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::{aead, hash::sha3_256, rand_core::CryptoRng, secret::Secret};
use umbra_wire::ndr::{encode_token, NdrRequest, TokenCarrier, NDR_REQUEST_LEN, PUSH_TOKEN_MAX};

use super::{Client, SETTINGS};
use crate::Error;

/// The root of each queue relay: `relay_id`, `k_ntf_root`, `relay_idx`.
const NOTIFY_RELAY: TableId = TableId(0x19);
/// Each handle group: `handle`, `relay_id`, `k_tok`, the removal secret,
/// the registration state, and the count of its queues.
const NOTIFY_GROUP: TableId = TableId(0x1A);
/// Each queue with a binding: `recipient_id`, `handle`, `queue_alias`, and
/// whether its `NBIND` left.
const NOTIFY_QUEUE: TableId = TableId(0x1B);
/// The push endpoint of the platform, a UnifiedPush URL.
const PUSH_ENDPOINT_SETTING: &[u8] = b"push-endpoint";

const RELAY_LEN: usize = 32 + 32 + 2;
const GROUP_LEN: usize = 16 + 32 + 32 + 32 + 1 + 1;
const QUEUE_LEN: usize = 32 + 16 + 16 + 1;

/// The NDR does not hold the group.
const UNREGISTERED: u8 = 0;
/// The NDR holds the group under the present endpoint.
const REGISTERED: u8 = 1;
/// The NDR holds the group under an earlier endpoint.
const STALE: u8 = 2;

struct Relay {
    relay_id: [u8; 32],
    root: Secret<32>,
    relay_idx: u16,
}

struct Group {
    handle: [u8; 16],
    relay_id: [u8; 32],
    k_tok: Secret<32>,
    removal: Secret<32>,
    state: u8,
    count: u8,
}

struct Queue {
    recipient_id: [u8; 32],
    handle: [u8; 16],
    alias: [u8; 16],
    bound: bool,
}

fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N], Error> {
    let end = at.checked_add(N).ok_or(Error::Malformed)?;
    let out = bytes
        .get(*at..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::Malformed)?;
    *at = end;
    Ok(out)
}

impl Relay {
    fn encode(&self) -> Vec<u8> {
        [
            self.relay_id.as_slice(),
            self.root.expose(),
            &self.relay_idx.to_be_bytes(),
        ]
        .concat()
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RELAY_LEN {
            return Err(Error::Malformed);
        }
        let mut at = 0;
        Ok(Relay {
            relay_id: take(bytes, &mut at)?,
            root: Secret::new(take(bytes, &mut at)?),
            relay_idx: u16::from_be_bytes(take(bytes, &mut at)?),
        })
    }
}

impl Group {
    fn encode(&self) -> Vec<u8> {
        [
            self.handle.as_slice(),
            &self.relay_id,
            self.k_tok.expose(),
            self.removal.expose(),
            &[self.state, self.count],
        ]
        .concat()
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != GROUP_LEN {
            return Err(Error::Malformed);
        }
        let mut at = 0;
        let handle = take(bytes, &mut at)?;
        let relay_id = take(bytes, &mut at)?;
        let k_tok = Secret::new(take(bytes, &mut at)?);
        let removal = Secret::new(take(bytes, &mut at)?);
        let [state, count] = take(bytes, &mut at)?;
        Ok(Group {
            handle,
            relay_id,
            k_tok,
            removal,
            state,
            count,
        })
    }
}

impl Queue {
    fn encode(&self) -> Vec<u8> {
        [
            self.recipient_id.as_slice(),
            &self.handle,
            &self.alias,
            &[u8::from(self.bound)],
        ]
        .concat()
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != QUEUE_LEN {
            return Err(Error::Malformed);
        }
        let mut at = 0;
        let recipient_id = take(bytes, &mut at)?;
        let handle = take(bytes, &mut at)?;
        let alias = take(bytes, &mut at)?;
        let [bound] = take(bytes, &mut at)?;
        Ok(Queue {
            recipient_id,
            handle,
            alias,
            bound: bound == 1,
        })
    }
}

/// One request that waits for the NDR, with what its answer changes.
pub struct NdrCall {
    /// The handle of the group.
    pub handle: [u8; 16],
    /// Whether the request removes the group (`NUNREG`).
    pub is_removal: bool,
    /// The request.
    pub request: Box<[u8; NDR_REQUEST_LEN]>,
}

fn random<const N: usize, R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The push endpoint that the platform gave, if any.
    pub fn push_endpoint(&self) -> Result<Option<String>, Error> {
        let open = self.open_ref()?;
        let row = open.store.row_id(SETTINGS, PUSH_ENDPOINT_SETTING);
        Ok(open
            .store
            .get(SETTINGS, &row)?
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|url| !url.is_empty()))
    }

    /// Takes a new push endpoint, or none when the platform took it back.
    /// Each group that the NDR holds registers again under the new one, or
    /// leaves with none.
    pub fn set_push_endpoint<R: CryptoRng + ?Sized>(
        &mut self,
        endpoint: Option<&str>,
        rng: &mut R,
    ) -> Result<(), Error> {
        if let Some(url) = endpoint {
            // NTF-123: the token of a UnifiedPush endpoint is an https URL.
            let mut plain = [0u8; PUSH_TOKEN_MAX];
            let n = encode_token(TokenCarrier::UnifiedPush, url.as_bytes(), &mut plain)
                .map_err(|_| Error::TooLong)?;
            umbra_wire::ndr::parse_token(plain.get(..n).ok_or(Error::Malformed)?)
                .map_err(|_| Error::Malformed)?;
        }
        if self.push_endpoint()?.as_deref() == endpoint {
            return Ok(());
        }
        let mut rows = vec![(
            SETTINGS,
            PUSH_ENDPOINT_SETTING.to_vec(),
            endpoint.unwrap_or_default().as_bytes().to_vec(),
        )];
        for mut group in self.notify_groups()? {
            if group.state == REGISTERED {
                group.state = STALE;
                rows.push((NOTIFY_GROUP, group.handle.to_vec(), group.encode()));
            }
        }
        self.put_rows(&rows, rng)
    }

    /// Writes rows under their natural keys in one batch.
    fn put_rows<R: CryptoRng + ?Sized>(
        &mut self,
        rows: &[(TableId, Vec<u8>, Vec<u8>)],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let keyed: Vec<_> = rows
            .iter()
            .map(|(table, natural, value)| (*table, open.store.row_id(*table, natural), value))
            .collect();
        let mut batch = open.store.begin();
        for (table, row, value) in keyed {
            batch.put(table, row, None, value, rng)?;
        }
        batch.commit()?;
        Ok(())
    }

    fn notify_groups(&self) -> Result<Vec<Group>, Error> {
        self.open_ref()?
            .store
            .list(NOTIFY_GROUP, None)?
            .iter()
            .map(|(_, bytes)| Group::parse(bytes))
            .collect()
    }

    fn notify_relays(&self) -> Result<Vec<Relay>, Error> {
        self.open_ref()?
            .store
            .list(NOTIFY_RELAY, None)?
            .iter()
            .map(|(_, bytes)| Relay::parse(bytes))
            .collect()
    }

    fn notify_queue(&self, recipient_id: &[u8; 32]) -> Result<Option<Queue>, Error> {
        let open = self.open_ref()?;
        let row = open.store.row_id(NOTIFY_QUEUE, recipient_id);
        open.store
            .get(NOTIFY_QUEUE, &row)?
            .map(|bytes| Queue::parse(&bytes))
            .transpose()
    }

    /// Gives each queue of `queues`, with its relay, a handle group and an
    /// alias, and returns each queue that has no binding yet: its `NKEY`
    /// goes next. With no push endpoint no queue binds.
    pub fn queues_to_bind<R: CryptoRng + ?Sized>(
        &mut self,
        queues: &[([u8; 32], [u8; 32])],
        rng: &mut R,
    ) -> Result<Vec<[u8; 32]>, Error> {
        if self.push_endpoint()?.is_none() {
            return Ok(Vec::new());
        }
        let mut relays = self.notify_relays()?;
        let mut groups = self.notify_groups()?;
        let mut unbound = Vec::new();
        let mut new_queues = Vec::new();
        for (recipient_id, relay_id) in queues {
            match self.notify_queue(recipient_id)? {
                Some(queue) if queue.bound => continue,
                Some(_) => {
                    unbound.push(*recipient_id);
                    continue;
                }
                None => {}
            }
            if !relays.iter().any(|relay| relay.relay_id == *relay_id) {
                let relay_idx = u16::try_from(relays.len()).map_err(|_| Error::TooLong)?;
                relays.push(Relay {
                    relay_id: *relay_id,
                    root: Secret::new(random(rng)),
                    relay_idx,
                });
            }
            // NTF-031, NTF-032: a group holds at most eight queues of one
            // relay.
            let room = groups.iter().position(|group| {
                group.relay_id == *relay_id && usize::from(group.count) < MAX_QUEUES_PER_HANDLE
            });
            let at = match room {
                Some(at) => at,
                None => {
                    groups.push(Group {
                        handle: random(rng),
                        relay_id: *relay_id,
                        k_tok: Secret::new(random(rng)),
                        removal: Secret::new(random(rng)),
                        state: UNREGISTERED,
                        count: 0,
                    });
                    groups.len().saturating_sub(1)
                }
            };
            let group = groups.get_mut(at).ok_or(Error::Malformed)?;
            group.count = group.count.saturating_add(1);
            new_queues.push(Queue {
                recipient_id: *recipient_id,
                handle: group.handle,
                alias: random(rng),
                bound: false,
            });
            unbound.push(*recipient_id);
        }
        if new_queues.is_empty() {
            return Ok(unbound);
        }
        let rows: Vec<_> = relays
            .iter()
            .map(|relay| (NOTIFY_RELAY, relay.relay_id.to_vec(), relay.encode()))
            .chain(
                groups
                    .iter()
                    .map(|group| (NOTIFY_GROUP, group.handle.to_vec(), group.encode())),
            )
            .chain(
                new_queues
                    .iter()
                    .map(|queue| (NOTIFY_QUEUE, queue.recipient_id.to_vec(), queue.encode())),
            )
            .collect();
        self.put_rows(&rows, rng)?;
        Ok(unbound)
    }

    /// The count of the queues whose `NBIND` left, and of the groups that
    /// the NDR holds under the present endpoint.
    pub fn push_state(&self) -> Result<(usize, usize), Error> {
        let bound = self
            .open_ref()?
            .store
            .list(NOTIFY_QUEUE, None)?
            .iter()
            .filter_map(|(_, bytes)| Queue::parse(bytes).ok())
            .filter(|queue| queue.bound)
            .count();
        let registered = self
            .notify_groups()?
            .iter()
            .filter(|group| group.state == REGISTERED)
            .count();
        Ok((bound, registered))
    }

    /// The binding of a queue, for the `NBIND` that answers its `NPK`
    /// (`NTF-113`).
    pub fn binding_of(&self, recipient_id: &[u8; 32]) -> Result<Option<Binding>, Error> {
        let Some(queue) = self.notify_queue(recipient_id)? else {
            return Ok(None);
        };
        let Some(group) = self
            .notify_groups()?
            .into_iter()
            .find(|group| group.handle == queue.handle)
        else {
            return Ok(None);
        };
        let Some(relay) = self
            .notify_relays()?
            .into_iter()
            .find(|relay| relay.relay_id == group.relay_id)
        else {
            return Ok(None);
        };
        Ok(Some(Binding {
            root: relay.root,
            handle: group.handle,
            k_tok: group.k_tok,
            queue_alias: queue.alias,
            relay_idx: relay.relay_idx,
        }))
    }

    /// The `NBIND` of a queue left. A relay gives it no answer, and a lost
    /// one binds again at the next `NKEY` after a new run.
    pub fn queue_bound<R: CryptoRng + ?Sized>(
        &mut self,
        recipient_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut queue) = self.notify_queue(recipient_id)? else {
            return Ok(());
        };
        queue.bound = true;
        self.put_rows(
            &[(NOTIFY_QUEUE, recipient_id.to_vec(), queue.encode())],
            rng,
        )
    }

    /// The requests that wait for the NDR: an `NREG` for each group that
    /// it does not hold under the present endpoint, or an `NUNREG` for each
    /// group it holds when the platform took the endpoint back.
    pub fn ndr_calls_due<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<Vec<NdrCall>, Error> {
        let endpoint = self.push_endpoint()?;
        let mut calls = Vec::new();
        for group in self.notify_groups()? {
            let request = match (&endpoint, group.state) {
                (Some(_), REGISTERED) | (None, UNREGISTERED) => continue,
                (Some(url), state) => {
                    let mut plain = [0u8; PUSH_TOKEN_MAX];
                    let n = encode_token(TokenCarrier::UnifiedPush, url.as_bytes(), &mut plain)
                        .map_err(|_| Error::TooLong)?;
                    let nonce: [u8; 24] = random(rng);
                    // NTF-123: `ct_token` seals the token under `k_tok`,
                    // bound to the handle.
                    let mut ct_token = plain.get(..n).ok_or(Error::Malformed)?.to_vec();
                    let tag = aead::seal(&group.k_tok, &nonce, &group.handle, &mut ct_token)
                        .map_err(|_| Error::Malformed)?;
                    ct_token.extend_from_slice(&tag);
                    // NTF-124: a handle that the NDR holds moves on its
                    // removal secret; a new one names zero.
                    let prior = if state == STALE {
                        Secret::new(*group.removal.expose())
                    } else {
                        Secret::new([0; 32])
                    };
                    let mut out = Box::new([0u8; NDR_REQUEST_LEN]);
                    NdrRequest::Register {
                        handle: group.handle,
                        nonce,
                        ct_token: &ct_token,
                        removal_hash: sha3_256(&[group.removal.expose()]),
                        prior,
                    }
                    .encode(&mut out)
                    .map_err(|_| Error::Malformed)?;
                    NdrCall {
                        handle: group.handle,
                        is_removal: false,
                        request: out,
                    }
                }
                (None, _) => {
                    let mut out = Box::new([0u8; NDR_REQUEST_LEN]);
                    NdrRequest::Unregister {
                        handle: group.handle,
                        removal: Secret::new(*group.removal.expose()),
                    }
                    .encode(&mut out)
                    .map_err(|_| Error::Malformed)?;
                    NdrCall {
                        handle: group.handle,
                        is_removal: true,
                        request: out,
                    }
                }
            };
            calls.push(request);
        }
        Ok(calls)
    }

    /// The NDR took a call: the group is registered under the present
    /// endpoint, or it left.
    pub fn ndr_call_taken<R: CryptoRng + ?Sized>(
        &mut self,
        call: &NdrCall,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut group) = self
            .notify_groups()?
            .into_iter()
            .find(|group| group.handle == call.handle)
        else {
            return Ok(());
        };
        group.state = if call.is_removal {
            UNREGISTERED
        } else {
            REGISTERED
        };
        self.put_rows(
            &[(NOTIFY_GROUP, group.handle.to_vec(), group.encode())],
            rng,
        )
    }
}
