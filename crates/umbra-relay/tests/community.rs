//! The community service of a relay: a community starts with an admitted
//! genesis roster, a post makes a digest for a registered queue, and a pull
//! gives the records and leaves no state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use umbra_core::{
    abuse::{
        admission::{Accepts, RelayGate},
        pow::PowSolution,
    },
    community::{
        chain::AuthorChain,
        community_id,
        control::{ControlBody, ControlObject, Role, RosterEntry},
        identity::{AuthorIdentity, RoleIdentity},
        pull::{
            NotifyRegistration, PullRequest, PullResponse, Selector, CMD_NREG, CMD_PAGE, CMD_PUB,
            CMD_PULL,
        },
        pull_secret,
        social::text_body,
        ADMISSION_OPEN, NO_INDEX, PULL_BATCH,
    },
};
use umbra_crypto::{
    auth::CommandAuthKey,
    rand_core::{TryCryptoRng, TryRng},
    rsabssa::PublicKey2048,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_queue::{relay::session::Session, Reject};
use umbra_relay::{
    circuits::CircuitKey,
    service::{
        community::{CommunityService, DigestDue},
        Reply,
    },
};
use umbra_wire::{
    address::{QueueAddress, LEN as QUEUE_ADDRESS_LEN},
    admission::AdmissionKind,
    command::{Cmd, Command},
};

struct Rng(u64);

impl TryRng for Rng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        Ok(self.0 >> 11 ^ self.0 << 7)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for Rng {}

fn queue_address(tag: u8) -> QueueAddress {
    QueueAddress {
        relay_id: [tag; 32],
        sender_id: [tag ^ 0x55; 32],
        qs_auth_sk: Secret::new([tag ^ 0x0F; 32]),
        qe: Secret::new([tag ^ 0xF0; 32]),
    }
}

struct Harness {
    service: CommunityService,
    session: Session,
    gate: RelayGate,
    issuer: PublicKey2048,
    community: [u8; 32],
    key: CommandAuthKey,
    circuit: CircuitKey,
    corr: u8,
}

type Handled = Result<(Vec<Reply>, Vec<DigestDue>), Reject>;

impl Harness {
    fn command(&mut self, byte: u8, payload: &[u8], now: u64) -> Handled {
        self.corr += 1;
        let mut command = Command {
            cmd: Cmd::Community(byte),
            corr_id: [self.corr; 16],
            queue_id: self.community,
            auth: [0; 32],
            payload,
        };
        command.sign(&self.key, b"").unwrap();
        let accepts = Accepts::CrossRelay(&self.issuer);
        self.service.handle(
            self.circuit,
            &mut self.session,
            &mut self.gate,
            &accepts,
            &command,
            now,
        )
    }

    fn publish(&mut self, record: &[u8], work: Option<&PowSolution>, now: u64) -> Handled {
        let mut payload = record.to_vec();
        match work {
            None => payload.extend_from_slice(&[AdmissionKind::None as u8, 0, 0]),
            Some(solution) => {
                let mut body = [0u8; 128];
                let used = solution.encode(&mut body).unwrap();
                payload.push(AdmissionKind::Pow as u8);
                payload.extend_from_slice(&(used as u16).to_be_bytes());
                payload.extend_from_slice(&body[..used]);
            }
        }
        self.command(CMD_PUB, &payload, now)
    }
}

#[test]
fn a_community_starts_with_an_admitted_roster_and_serves_a_pull() {
    let owner = RoleIdentity::from_seed(&Secret::new([1; 32]));
    let second = RoleIdentity::from_seed(&Secret::new([2; 32]));
    let community = community_id(ADMISSION_OPEN, owner.public_key()).unwrap();
    let session_secret = StaticSecret::from([9; 32]);
    let session_pk = *XPublic::from(&session_secret).as_bytes();
    let pull = StaticSecret::from(*pull_secret(&community).expose());
    let mut harness = Harness {
        service: CommunityService::new(1 << 20),
        session: Session::for_circuit(&[7; 16], session_secret),
        gate: RelayGate::new([0x13; 32]),
        issuer: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
        community,
        key: CommandAuthKey::derive(&pull, &session_pk).unwrap(),
        circuit: CircuitKey {
            link: 1,
            circ_id: [7; 16],
        },
        corr: 0,
    };
    let mut rng = Rng(3);
    let roster = ControlObject::sign(
        &owner,
        community,
        0,
        [0; 32],
        ControlBody::Roster {
            entries: vec![
                RosterEntry::new(Role::Owner, &owner, &queue_address(1)).unwrap(),
                RosterEntry::new(Role::Owner, &second, &queue_address(2)).unwrap(),
            ],
            cosigns: Vec::new(),
        },
        &mut rng,
    )
    .unwrap()
    .encode()
    .unwrap();

    // COM-205: the creation of a community needs a credential.
    assert_eq!(
        harness.publish(&roster, None, 100).err(),
        Some(Reject::Admission)
    );
    assert!(harness.service.is_empty());
    let challenge = harness.gate.pow.issue(0, 100, &mut rng).unwrap();
    let work = PowSolution::solve(
        &challenge.verifier_id,
        &challenge.seed,
        challenge.effort,
        &mut rng,
    )
    .unwrap();
    let (replies, _) = harness.publish(&roster, Some(&work), 100).unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(harness.service.len(), 1);

    // A subscriber registers a queue, and then a post makes a digest.
    let mut queue = [0u8; QUEUE_ADDRESS_LEN];
    queue_address(5).encode(&mut queue).unwrap();
    let registration = NotifyRegistration {
        community_id: community,
        queue,
    };
    harness
        .command(CMD_NREG, &registration.encode().unwrap(), 150)
        .unwrap();

    let author = AuthorIdentity::from_seed(&Secret::new([4; 32]));
    let mut chain = AuthorChain::new(community, &author.pseudonym());
    let body = text_body(&community, "the first post", None, &[]).unwrap();
    let post = chain.append(&author, NO_INDEX, &body, 200).unwrap();
    let (_, digests) = harness.publish(&post, None, 200).unwrap();
    assert_eq!(digests.len(), 1);
    assert_eq!(
        (digests[0].community_id, digests[0].post_count),
        (community, 1)
    );
    assert_eq!(digests[0].queue, queue);

    // A pull gives the roster and the post, and it leaves no state.
    let request = PullRequest {
        community_id: community,
        selector: Selector::Sequence,
        pseudonym: [0; 32],
        from: 0,
        count: PULL_BATCH,
    }
    .encode()
    .unwrap();
    let (replies, digests) = harness.command(CMD_PULL, &request, 300).unwrap();
    assert!(digests.is_empty());
    let outbound = &replies[0].outbound;
    let (page, _) = Command::parse(&outbound.encoded, outbound.bucket).unwrap();
    assert_eq!(page.cmd, Cmd::Community(CMD_PAGE));
    let response = PullResponse::parse(page.payload).unwrap();
    assert_eq!(response.entries.len(), 2);
    assert_eq!(response.entries[1].record, post.as_slice());

    // A command under another key than the pull key is rejected.
    harness.key = CommandAuthKey::derive(&StaticSecret::from([8; 32]), &session_pk).unwrap();
    assert_eq!(
        harness.command(CMD_PULL, &request, 301).err(),
        Some(Reject::Rejected)
    );
}
