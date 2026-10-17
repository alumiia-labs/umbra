//! The chunk service of Part 12: the registration of a chunk, its bytes, a
//! fetch, a proof of possession, and the erase. The store of
//! `umbra_core::attach` holds the rules of the two classes, of the quota,
//! and of the egress budget. This service authorizes each command and gives
//! the answer.
//!
//! Each held chunk goes to the durable store of the relay before the
//! answer that names it (`ATT-191`). A registration that waits for its
//! bytes stays in RAM, and a restart ends it.

use std::collections::BTreeMap;

use umbra_core::{
    abuse::admission::{Accepts, RelayGate},
    attach::{
        command::{
            chunk_payload, fixed_payload, ChunkCmd, CrepPayload, CrputPayload, RegisterPayload,
            ReplicaTarget, NONCE_LEN, PROOF_LEN,
        },
        store::{ChunkStore, Class, Credentials},
    },
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_queue::{params::store_time, relay::session::Session, Reject};
use umbra_wire::command::{Cmd, Command};

use super::{answer, Reply};
use crate::{
    circuits::CircuitKey,
    store::{Loaded, StoreChange},
};

/// One copy that this relay owes to a target of a `CREP` (`ATT-102`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    /// The chunk.
    pub chunk_id: [u8; 32],
    /// The relay that takes the copy, and the token that it issued.
    pub target: ReplicaTarget,
    /// The bytes that the `CPUT` gave, without a change (`ATT-104`).
    pub chunk: Vec<u8>,
}

/// The chunk service of one relay.
pub struct ChunkService {
    store: ChunkStore,
    pushes: Vec<Push>,
    changes: Vec<StoreChange>,
    /// The copies that each held chunk sent at a `CREP`: an owner that
    /// repeats the command makes this relay dial no more than
    /// `COPIES_MAX` times for one chunk.
    copies: BTreeMap<[u8; 32], u8>,
}

/// The copies that one chunk sends in its life: the replicas of `ATT-104`
/// and the ones that replace a replica whose copy did not verify.
const COPIES_MAX: u8 = 8;

impl ChunkService {
    /// A service over a store of `capacity` bytes.
    pub const fn new(capacity: u64) -> Self {
        ChunkService {
            store: ChunkStore::new(capacity),
            pushes: Vec::new(),
            changes: Vec::new(),
            copies: BTreeMap::new(),
        }
    }

    /// A service that holds the chunks of an earlier run. It takes the
    /// chunks out of `loaded`, thus a full store is in memory one time.
    pub fn restore(capacity: u64, loaded: &mut Loaded) -> Self {
        let mut service = ChunkService::new(capacity);
        for (chunk_id, held) in core::mem::take(&mut loaded.chunks) {
            service.store.restore(chunk_id, held);
        }
        service
    }

    /// The changes of the stored chunks since the last call.
    pub fn take_changes(&mut self) -> Vec<StoreChange> {
        for chunk_id in self.store.take_erased() {
            self.changes.push(StoreChange::ChunkDeleted { chunk_id });
        }
        core::mem::take(&mut self.changes)
    }

    /// Records a chunk that took its bytes.
    fn note_held(&mut self, chunk_id: [u8; 32]) {
        if let Some(mut held) = self.store.export(&chunk_id) {
            // NET-301: the file holds each time to the hour.
            held.registered_at = store_time(held.registered_at);
            held.renewed_at = store_time(held.renewed_at);
            held.erase_at = store_time(held.erase_at);
            self.changes.push(StoreChange::Chunk {
                chunk_id,
                held: Box::new(held),
            });
        }
    }

    /// The chunks held.
    pub fn held_count(&self) -> usize {
        self.store.held_count()
    }

    /// The copies that wait for a link to their target. The caller sends one
    /// `CRPUT` for each, and it keeps no token after that (`ATT-106`).
    pub fn take_pushes(&mut self) -> Vec<Push> {
        core::mem::take(&mut self.pushes)
    }

    /// Erases what passed its time, and trims the store to its target.
    pub fn sweep(&mut self, now: u64) {
        self.store.sweep(now);
        self.store.trim();

        let store = &self.store;
        self.copies
            .retain(|chunk_id, _| store.bytes(chunk_id).is_some());
    }

    /// The proof that answers an accepted `CPUT` and an accepted `CREP`
    /// (`ATT-186`): the `corr_id` of the command is the nonce, thus the
    /// answer shows that the relay holds the bytes.
    fn held_proof(&self, command: &Command<'_>) -> Result<[u8; PROOF_LEN], Reject> {
        self.store
            .prove(&command.queue_id, &command.corr_id)
            .ok_or(Reject::Rejected)
    }

    /// Serves one command of a client at the end of a circuit.
    #[allow(clippy::too_many_arguments)]
    pub fn handle<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
        gate: &mut RelayGate,
        accepts: &Accepts<'_>,
        command: &Command<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<Reply>, Reject> {
        let Cmd::Attachment(byte) = command.cmd else {
            return Err(Reject::Rejected);
        };

        let cmd = ChunkCmd::from_byte(byte).map_err(|_| Reject::Rejected)?;
        let chunk_id = command.queue_id;

        let reply = |cmd: ChunkCmd, payload: &[u8]| {
            vec![answer(
                circuit,
                command,
                Cmd::Attachment(cmd.to_byte()),
                payload,
            )]
        };

        match cmd {
            ChunkCmd::Cnew | ChunkCmd::Bnew => {
                let register =
                    RegisterPayload::parse(command.payload).map_err(|_| Reject::Rejected)?;
                // ATT-180: the key of the payload authorizes its own command.
                session.accept(command, &register.cred_pk)?;

                // ABU-106, ABU-107: a token, or a solution that admits up to
                // POW_CHUNK_ALLOWANCE registrations. It names the holder of
                // the upload quota (ATT-092).
                let holder = gate.admit_chunk(&register.admission, accepts, now)?;

                let mut storage_token = [0u8; 32];
                rng.fill_bytes(&mut storage_token);

                let class = if cmd == ChunkCmd::Bnew {
                    Class::Backup
                } else {
                    Class::Attachment
                };

                self.store.register(
                    chunk_id,
                    class,
                    Credentials {
                        cred_pk: register.cred_pk,
                        read_pk: register.read_pk,
                    },
                    holder,
                    storage_token,
                    now,
                )?;

                Ok(reply(ChunkCmd::Cid, &storage_token))
            }
            ChunkCmd::Cput => {
                // WIR-317: an unknown chunk and a failed auth give one reason.
                let registration = self.store.registration(&chunk_id).ok_or(Reject::Rejected)?;
                let (cred_pk, token) =
                    (registration.credentials.cred_pk, registration.storage_token);
                // ATT-042: the authorized bytes hold the token.
                session.accept_bound(command, &cred_pk, &token)?;

                let chunk = chunk_payload(command.payload).map_err(|_| Reject::Rejected)?;
                self.store.put(chunk_id, chunk, now)?;
                self.note_held(chunk_id);

                Ok(reply(ChunkCmd::Cprf, &self.held_proof(command)?))
            }
            ChunkCmd::Cget => {
                let read_pk = self.credentials(&chunk_id)?.read_pk;
                session.accept(command, &read_pk)?;
                let chunk = self.store.get(&chunk_id, now)?.to_vec();
                Ok(reply(ChunkCmd::Cdat, &chunk))
            }
            ChunkCmd::Crnw => {
                // ATT-126: a renewal has no answer, and a refused one has
                // none too. A `NACK` for a chunk that the relay does not
                // hold would show the state that the rule keeps for a fetch.
                let Ok(credentials) = self.credentials(&chunk_id) else {
                    return Ok(Vec::new());
                };

                if session.accept(command, &credentials.read_pk).is_err() {
                    return Ok(Vec::new());
                }

                if self.store.renew(&chunk_id, now).is_ok() {
                    if let Some(erase_at) = self.store.erase_at(&chunk_id) {
                        self.changes.push(StoreChange::ChunkRenewed {
                            chunk_id,
                            renewed_at: store_time(now),
                            erase_at: store_time(erase_at),
                        });
                    }
                }

                Ok(Vec::new())
            }
            ChunkCmd::Cvfy => {
                let cred_pk = self.credentials(&chunk_id)?.cred_pk;
                session.accept(command, &cred_pk)?;

                let nonce: [u8; NONCE_LEN] =
                    fixed_payload(command.payload).map_err(|_| Reject::Rejected)?;
                let proof = self
                    .store
                    .prove(&chunk_id, &nonce)
                    .ok_or(Reject::Rejected)?;

                Ok(reply(ChunkCmd::Cprf, &proof))
            }
            ChunkCmd::Crep => {
                let cred_pk = self.credentials(&chunk_id)?.cred_pk;
                session.accept(command, &cred_pk)?;

                let targets = CrepPayload::parse(command.payload).map_err(|_| Reject::Rejected)?;
                let proof = self.held_proof(command)?;

                // A copy for a replica is no fetch, thus it takes nothing from
                // the egress budget of §12.11.
                let chunk = self
                    .store
                    .bytes(&chunk_id)
                    .ok_or(Reject::Rejected)?
                    .to_vec();

                let sent = self.copies.entry(chunk_id).or_insert(0);
                for target in targets.targets {
                    if *sent >= COPIES_MAX {
                        break;
                    }
                    *sent = sent.saturating_add(1);
                    self.pushes.push(Push {
                        chunk_id,
                        target,
                        chunk: chunk.clone(),
                    });
                }

                Ok(reply(ChunkCmd::Cprf, &proof))
            }
            ChunkCmd::Cdel => {
                // A registration with no bytes has its credential too.
                let cred_pk = match self.store.registration(&chunk_id) {
                    Some(registration) => registration.credentials.cred_pk,
                    None => self.credentials(&chunk_id)?.cred_pk,
                };

                session.accept(command, &cred_pk)?;

                self.store.delete(&chunk_id)?;
                self.copies.remove(&chunk_id);

                // ATT-187: the relay holds no byte of the chunk.
                Ok(reply(ChunkCmd::Cprf, &[0; PROOF_LEN]))
            }
            // A relay sends these, and a client sends none of them.
            ChunkCmd::Cid | ChunkCmd::Cdat | ChunkCmd::Cprf | ChunkCmd::Crput => {
                Err(Reject::Rejected)
            }
        }
    }

    /// Takes the copy of another relay, on the token that the `CID` of this
    /// relay gave (`ATT-107` to `ATT-112`).
    pub fn replica_put(
        &mut self,
        chunk_id: [u8; 32],
        payload: &[u8],
        now: u64,
    ) -> Result<(), Reject> {
        let copy = CrputPayload::parse(payload).map_err(|_| Reject::Rejected)?;
        self.store
            .replica_put(chunk_id, &copy.storage_token, copy.chunk, now)?;
        self.note_held(chunk_id);
        Ok(())
    }

    fn credentials(&self, chunk_id: &[u8; 32]) -> Result<Credentials, Reject> {
        self.store.credentials(chunk_id).ok_or(Reject::Rejected)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use umbra_core::attach::{seal, CHUNK_SIZE};
    use umbra_crypto::{
        auth::CommandAuthKey,
        rand_core::{TryCryptoRng, TryRng},
        rsabssa::PublicKey2048,
        x25519::{PublicKey as XPublic, StaticSecret},
    };
    use umbra_wire::admission::Admission;

    struct Rng(u8);

    impl TryRng for Rng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.0 = self.0.wrapping_add(1);
            dst.fill(self.0);
            Ok(())
        }
    }

    impl TryCryptoRng for Rng {}

    /// A relay with one circuit, and a client that signs for it.
    struct Bench {
        service: ChunkService,
        session: Session,
        gate: RelayGate,
        issuer: std::collections::BTreeMap<u32, PublicKey2048>,
        rng: Rng,
        corr: u8,
    }

    const CIRCUIT: CircuitKey = CircuitKey {
        link: 2,
        circ_id: [7; 16],
    };

    impl Bench {
        fn new() -> Self {
            Bench {
                service: ChunkService::new(1 << 24),
                session: Session::for_circuit(&[7; 16], StaticSecret::from([9; 32])),
                gate: RelayGate::new([1; 32]),
                issuer: std::collections::BTreeMap::new(),
                rng: Rng(0),
                corr: 0,
            }
        }

        /// Sends one command under the secret `signer`, with `bind` in the
        /// authorized bytes. Gives the answers and the `corr_id`.
        fn send(
            &mut self,
            cmd: ChunkCmd,
            chunk_id: [u8; 32],
            payload: &[u8],
            signer: &StaticSecret,
            bind: &[u8],
        ) -> (Result<Vec<Reply>, Reject>, [u8; 16]) {
            self.corr += 1;
            let corr_id = [self.corr; 16];

            let mut command = Command {
                cmd: Cmd::Attachment(cmd.to_byte()),
                corr_id,
                queue_id: chunk_id,
                auth: [0; 32],
                payload,
            };

            let key = CommandAuthKey::derive(signer, &self.session.relay_session_pk()).unwrap();
            command.sign(&key, bind).unwrap();

            let accepts = Accepts::CrossRelay(&self.issuer);
            let result = self.service.handle(
                CIRCUIT,
                &mut self.session,
                &mut self.gate,
                &accepts,
                &command,
                1_000,
                &mut self.rng,
            );

            (result, corr_id)
        }
    }

    /// The payload of the one answer of a command.
    fn payload_of(result: Result<Vec<Reply>, Reject>, cmd: ChunkCmd) -> Vec<u8> {
        let replies = result.unwrap();
        assert_eq!(replies.len(), 1);

        let (command, _) =
            Command::parse(&replies[0].outbound.encoded, replies[0].outbound.bucket).unwrap();
        assert_eq!(command.cmd, Cmd::Attachment(cmd.to_byte()));
        command.payload.to_vec()
    }

    impl Bench {
        /// A `CNEW` payload with a solution to the challenge of this relay
        /// at `POW_CHUNK_FLOOR` (`ABU-106`).
        fn register_payload(&mut self, cred: &StaticSecret, read: &StaticSecret) -> Vec<u8> {
            let challenge = self.gate.pow.issue(0, 1_000, &mut self.rng).unwrap();
            let solution = umbra_core::abuse::pow::PowSolution::solve(
                &[1; 32],
                &challenge.seed,
                umbra_core::abuse::POW_CHUNK_FLOOR,
                &mut self.rng,
            )
            .unwrap();

            let mut body = [0u8; umbra_core::abuse::pow::SOLUTION_LEN];
            let used = solution.encode(&mut body).unwrap();
            let admission = Admission {
                kind: umbra_wire::admission::AdmissionKind::Pow,
                body: &body[..used],
            };

            let payload = RegisterPayload {
                cred_pk: *XPublic::from(cred).as_bytes(),
                read_pk: *XPublic::from(read).as_bytes(),
                admission,
            };

            let mut out = vec![0u8; 64 + admission.len()];
            let used = payload.encode(&mut out).unwrap();
            out.truncate(used);

            out
        }
    }

    #[test]
    fn a_registration_with_no_solution_fails_and_one_solution_serves_its_allowance() {
        let mut bench = Bench::new();
        let cred = StaticSecret::from([3; 32]);
        let read = StaticSecret::from([4; 32]);

        // ABU-106: a registration with no token and no solution fails, even
        // at an effort of 0.
        let bare = RegisterPayload {
            cred_pk: *XPublic::from(&cred).as_bytes(),
            read_pk: *XPublic::from(&read).as_bytes(),
            admission: Admission::NONE,
        };

        let mut out = vec![0u8; 64 + Admission::NONE.len()];
        let used = bare.encode(&mut out).unwrap();
        let (refused, _) = bench.send(ChunkCmd::Cnew, [0xE0; 32], &out[..used], &cred, b"");
        assert_eq!(refused.err(), Some(Reject::Admission));

        // ABU-107: one solution admits POW_CHUNK_ALLOWANCE registrations, and
        // not one more.
        let register = bench.register_payload(&cred, &read);

        for i in 0..umbra_core::abuse::POW_CHUNK_ALLOWANCE {
            let mut id = [0xE1; 32];
            id[..2].copy_from_slice(&i.to_be_bytes());
            let (answer, _) = bench.send(ChunkCmd::Cnew, id, &register, &cred, b"");
            assert!(answer.is_ok(), "registration {i}");
        }

        let (over, _) = bench.send(ChunkCmd::Cnew, [0xE2; 32], &register, &cred, b"");
        assert_eq!(over.err(), Some(Reject::Admission));
    }

    #[test]
    fn a_held_chunk_outlives_a_restart_and_an_erased_one_does_not() {
        use crate::store::{MemoryStore, RelayStore};

        let mut bench = Bench::new();
        let mut disk = MemoryStore::default();
        let cred = StaticSecret::from([3; 32]);
        let read = StaticSecret::from([4; 32]);

        let chunk = vec![0x5A; CHUNK_SIZE];
        let register = bench.register_payload(&cred, &read);

        let (cid, _) = bench.send(ChunkCmd::Cnew, [0xC1; 32], &register, &cred, b"");
        let token = payload_of(cid, ChunkCmd::Cid);

        // A registration with no bytes stays in RAM.
        assert!(bench.service.take_changes().is_empty());

        let (put, _) = bench.send(ChunkCmd::Cput, [0xC1; 32], &chunk, &cred, &token);
        payload_of(put, ChunkCmd::Cprf);

        // ATT-191: the bytes go to the store with the answer.
        let changes = bench.service.take_changes();
        assert!(matches!(&changes[..], [StoreChange::Chunk { .. }]));
        disk.commit(&changes).unwrap();

        let (renewed, _) = bench.send(ChunkCmd::Crnw, [0xC1; 32], &[], &read, b"");
        assert_eq!(renewed, Ok(Vec::new()));
        disk.commit(&bench.service.take_changes()).unwrap();

        let (cid, _) = bench.send(ChunkCmd::Cnew, [0xC2; 32], &register, &cred, b"");
        payload_of(cid, ChunkCmd::Cid);

        // The next run holds the chunk, and the registration is gone.
        let mut loaded = disk.load().unwrap();
        // NET-301: the file holds the time to the hour.
        assert_eq!(loaded.chunks[&[0xC1; 32]].renewed_at, store_time(1_000));
        let erase_at = loaded.chunks[&[0xC1; 32]].erase_at;
        assert_eq!(erase_at % 3_600, 0);

        bench.service = ChunkService::restore(1 << 24, &mut loaded);
        // The service took the bytes, and no second copy stays.
        assert!(loaded.chunks.is_empty());
        assert_eq!(bench.service.held_count(), 1);

        let (got, _) = bench.send(ChunkCmd::Cget, [0xC1; 32], &[], &read, b"");
        assert_eq!(payload_of(got, ChunkCmd::Cdat), chunk);

        let (lost, _) = bench.send(ChunkCmd::Cput, [0xC2; 32], &chunk, &cred, &token);
        assert_eq!(lost, Err(Reject::Rejected));

        // ATT-046: the erase time ends the chunk in the store too.
        bench.service.sweep(erase_at);
        disk.commit(&bench.service.take_changes()).unwrap();
        assert!(disk.load().unwrap().chunks.is_empty());
    }

    #[test]
    fn a_chunk_goes_in_with_its_credential_and_out_with_the_other_one() {
        let mut bench = Bench::new();
        let cred = StaticSecret::from([3; 32]);
        let read = StaticSecret::from([4; 32]);
        let chunk_id = [0xC1; 32];
        let chunk = vec![0x5A; CHUNK_SIZE];
        let register = bench.register_payload(&cred, &read);

        let (cid, _) = bench.send(ChunkCmd::Cnew, chunk_id, &register, &cred, b"");
        let token = payload_of(cid, ChunkCmd::Cid);
        assert_eq!(token.len(), 32);

        // ATT-058: a second registration of the identifier.
        let (again, _) = bench.send(ChunkCmd::Cnew, chunk_id, &register, &cred, b"");
        assert_eq!(again, Err(Reject::Rejected));

        // ATT-042: a `CPUT` with no token in its authorized bytes, one under
        // the read credential, and one of a wrong length.
        let (no_bind, _) = bench.send(ChunkCmd::Cput, chunk_id, &chunk, &cred, b"");
        assert_eq!(no_bind, Err(Reject::Rejected));

        let (wrong_key, _) = bench.send(ChunkCmd::Cput, chunk_id, &chunk, &read, &token);
        assert_eq!(wrong_key, Err(Reject::Rejected));

        let (short, _) = bench.send(ChunkCmd::Cput, chunk_id, &chunk[1..], &cred, &token);
        assert_eq!(short, Err(Reject::Rejected));

        assert_eq!(bench.service.held_count(), 0);

        // ATT-186: the answer of the `CPUT` proves the bytes under its
        // `corr_id`.
        let (put, corr_id) = bench.send(ChunkCmd::Cput, chunk_id, &chunk, &cred, &token);
        assert_eq!(
            payload_of(put, ChunkCmd::Cprf),
            seal::proof(&corr_id, &chunk)
        );

        assert_eq!(bench.service.held_count(), 1);

        // ATT-040, ATT-041: each credential opens its own commands alone.
        let (by_cred, _) = bench.send(ChunkCmd::Cget, chunk_id, &[], &cred, b"");
        assert_eq!(by_cred, Err(Reject::Rejected));

        let (got, _) = bench.send(ChunkCmd::Cget, chunk_id, &[], &read, b"");
        assert_eq!(payload_of(got, ChunkCmd::Cdat), chunk);

        let (by_read, _) = bench.send(ChunkCmd::Cvfy, chunk_id, &[8; 16], &read, b"");
        assert_eq!(by_read, Err(Reject::Rejected));

        let (proof, _) = bench.send(ChunkCmd::Cvfy, chunk_id, &[8; 16], &cred, b"");
        assert_eq!(
            payload_of(proof, ChunkCmd::Cprf),
            seal::proof(&[8; 16], &chunk)
        );

        // ATT-126: a renewal has no answer.
        let (renewed, _) = bench.send(ChunkCmd::Crnw, chunk_id, &[], &read, b"");
        assert_eq!(renewed, Ok(Vec::new()));

        // ATT-126: a renewal of a chunk that the relay does not hold, and
        // one under another key, get no `NACK` too.
        let (unknown, _) = bench.send(ChunkCmd::Crnw, [0xEE; 32], &[], &read, b"");
        assert_eq!(unknown, Ok(Vec::new()));
        let (refused, _) = bench.send(ChunkCmd::Crnw, chunk_id, &[], &cred, b"");
        assert_eq!(refused, Ok(Vec::new()));

        // A `CREP` gives one copy for each target, and a proof as its answer.
        let targets = CrepPayload {
            targets: vec![
                ReplicaTarget {
                    relay_id: [0xB1; 32],
                    storage_token: [0xB2; 32],
                },
                ReplicaTarget {
                    relay_id: [0xC1; 32],
                    storage_token: [0xC2; 32],
                },
            ],
        };
        let mut crep = vec![0u8; targets.len()];
        targets.encode(&mut crep).unwrap();

        let (replicated, corr_id) = bench.send(ChunkCmd::Crep, chunk_id, &crep, &cred, b"");
        assert_eq!(
            payload_of(replicated, ChunkCmd::Cprf),
            seal::proof(&corr_id, &chunk)
        );

        let pushes = bench.service.take_pushes();
        assert_eq!(pushes.len(), 2);

        assert!(pushes
            .iter()
            .all(|push| push.chunk == chunk && push.chunk_id == chunk_id));
        assert_eq!(pushes[1].target.storage_token, [0xC2; 32]);

        assert!(bench.service.take_pushes().is_empty());

        // ATT-187: the erase, and then the chunk is unknown.
        let (erased, _) = bench.send(ChunkCmd::Cdel, chunk_id, &[], &cred, b"");
        assert_eq!(payload_of(erased, ChunkCmd::Cprf), [0; PROOF_LEN]);

        let (gone, _) = bench.send(ChunkCmd::Cget, chunk_id, &[], &read, b"");
        assert_eq!(gone, Err(Reject::Rejected));
    }

    #[test]
    fn a_copy_of_another_relay_goes_in_on_the_token_alone() {
        let mut bench = Bench::new();
        let cred = StaticSecret::from([3; 32]);
        let read = StaticSecret::from([4; 32]);
        let chunk_id = [0xD1; 32];
        let chunk = vec![0x77; CHUNK_SIZE];
        let register = bench.register_payload(&cred, &read);
        let (cid, _) = bench.send(ChunkCmd::Cnew, chunk_id, &register, &cred, b"");
        let token: [u8; 32] = payload_of(cid, ChunkCmd::Cid).try_into().unwrap();

        let copy = |token: [u8; 32], chunk: &[u8]| {
            let mut out = vec![0u8; 32 + CHUNK_SIZE];
            CrputPayload {
                storage_token: token,
                chunk,
            }
            .encode(&mut out)
            .unwrap();
            out
        };

        // ATT-107: another token opens nothing. ATT-111: the length is fixed.
        let wrong_token = copy([0; 32], &chunk);
        assert_eq!(
            bench.service.replica_put(chunk_id, &wrong_token, 1_000),
            Err(Reject::Rejected)
        );

        let good = copy(token, &chunk);
        assert_eq!(
            bench.service.replica_put(chunk_id, &good[1..], 1_000),
            Err(Reject::Rejected)
        );

        bench.service.replica_put(chunk_id, &good, 1_000).unwrap();

        // ATT-110: one copy for each registration.
        assert_eq!(
            bench.service.replica_put(chunk_id, &good, 1_000),
            Err(Reject::Rejected)
        );

        let (got, _) = bench.send(ChunkCmd::Cget, chunk_id, &[], &read, b"");
        assert_eq!(payload_of(got, ChunkCmd::Cdat), chunk);
    }
}
