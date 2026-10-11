//! A transport session at a relay: the session secret and its resume count
//! (Part 6 §6.2.3), the relay's session key for the deniable authenticator,
//! the accepted `corr_id` set (`NET-122`), and the queue count bound
//! (`NET-022`).

use alloc::{collections::BTreeSet, vec::Vec};

use umbra_crypto::{
    auth::CommandAuthKey,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_wire::{command::Command, session::SessionControl};

use crate::{params::MAX_QUEUES_PER_SESSION, Reject};

/// The commands that one session authenticates at most, which bounds its
/// replay set.
const SEEN_MAX: usize = 65_536;

/// One session.
pub struct Session {
    id: [u8; 8],
    secret: Secret<32>,
    resume_count: u32,
    relay_session_sk: StaticSecret,
    seen: BTreeSet<[u8; 16]>,
    queues: Vec<[u8; 32]>,
}

impl Session {
    /// Opens a session from a `SessionOpen`, with the relay's session key
    /// for the authenticator of Part 3 §3.2.3.
    pub fn open(control: SessionControl, relay_session_sk: StaticSecret) -> Result<Self, Reject> {
        match control {
            SessionControl::Open {
                session_id,
                session_secret,
            } => Ok(Session {
                id: session_id,
                secret: session_secret,
                resume_count: 0,
                relay_session_sk,
                seen: BTreeSet::new(),
                queues: Vec::new(),
            }),
            _ => Err(Reject::Rejected),
        }
    }

    /// The session of a command that arrives over a circuit, which is
    /// that circuit (`NET-287`). `relay_session_sk` is the private half of
    /// the `er` of the circuit (`NET-285`). A circuit does not resume, thus
    /// the session holds no resume secret.
    pub fn for_circuit(circ_id: &[u8; 16], relay_session_sk: StaticSecret) -> Self {
        Session {
            id: umbra_crypto::bytes::part::<0, 8, 16>(circ_id),
            secret: Secret::new([0; 32]),
            resume_count: u32::MAX,
            relay_session_sk,
            seen: BTreeSet::new(),
            queues: Vec::new(),
        }
    }

    /// The session identifier.
    pub fn id(&self) -> [u8; 8] {
        self.id
    }

    /// `RelaySession_pk`, which the `IDS` carries to the client.
    pub fn relay_session_pk(&self) -> [u8; 32] {
        *XPublic::from(&self.relay_session_sk).as_bytes()
    }

    /// Binds a resume to this session (`WIR-237` to `WIR-241`).
    pub fn resume(&mut self, control: &SessionControl) -> Result<(), Reject> {
        let (count, _, _) = control
            .verify_resume(&self.secret, &self.id, self.resume_count)
            .map_err(|_| Reject::Rejected)?;
        self.resume_count = count;
        Ok(())
    }

    /// Verifies a command under the `auth` public key that the queue holds
    /// for its sender, and refuses a `corr_id` this session accepted before
    /// (`NET-121`, `NET-122`).
    pub fn accept(&mut self, command: &Command<'_>, auth_pk: &[u8; 32]) -> Result<(), Reject> {
        self.accept_bound(command, auth_pk, b"")
    }

    /// As [`Session::accept`], for a command whose authorized bytes hold a
    /// `bind` value (`NET-120`), as the `storage_token` of a `CPUT`.
    pub fn accept_bound(
        &mut self,
        command: &Command<'_>,
        auth_pk: &[u8; 32],
        bind: &[u8],
    ) -> Result<(), Reject> {
        if self.seen.contains(&command.corr_id) {
            return Err(Reject::Rejected);
        }
        // NET-122: the replay check holds each `corr_id` of the session, and
        // a session past `SEEN_MAX` commands takes no more; its client
        // builds a new circuit, as at `CIRCUIT_MAX_CELLS`.
        if self.seen.len() >= SEEN_MAX {
            return Err(Reject::Limit);
        }
        let key = CommandAuthKey::derive(&self.relay_session_sk, auth_pk)
            .map_err(|_| Reject::Rejected)?;
        command.verify(&key, bind).map_err(|_| Reject::Rejected)?;
        self.seen.insert(command.corr_id);
        Ok(())
    }

    /// Records that this session serves `queue_id`, at most
    /// `MAX_QUEUES_PER_SESSION` queues (`NET-022`).
    pub fn bind_queue(&mut self, queue_id: [u8; 32]) -> Result<(), Reject> {
        if self.queues.contains(&queue_id) {
            return Ok(());
        }
        if self.queues.len() >= MAX_QUEUES_PER_SESSION {
            return Err(Reject::Limit);
        }
        self.queues.push(queue_id);
        Ok(())
    }

    /// Refuses a new queue when the session serves `MAX_QUEUES_PER_SESSION`
    /// already. A relay checks it before it spends the admission of a `NEW`
    /// or a `GNEW`, thus a refused command costs the client no token.
    pub fn room(&self) -> Result<(), Reject> {
        if self.queues.len() >= MAX_QUEUES_PER_SESSION {
            return Err(Reject::Limit);
        }
        Ok(())
    }

    /// Ends the service of `queue_id`, which a `DEL` removed. Its place
    /// serves the next queue (`NET-022`).
    pub fn unbind_queue(&mut self, queue_id: &[u8; 32]) {
        self.queues.retain(|held| held != queue_id);
    }

    /// The queues this session serves.
    pub fn queues(&self) -> &[[u8; 32]] {
        &self.queues
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
    use umbra_wire::command::Cmd;

    #[test]
    fn a_session_verifies_commands_once_and_bounds_its_queues() {
        let relay_sk = StaticSecret::from([1u8; 32]);
        let open = SessionControl::Open {
            session_id: [2; 8],
            session_secret: Secret::new([3; 32]),
        };
        let mut session = Session::open(open, relay_sk).unwrap();
        let client_sk = StaticSecret::from([4u8; 32]);
        let client_pk = *XPublic::from(&client_sk).as_bytes();
        let key = CommandAuthKey::derive(&client_sk, &session.relay_session_pk()).unwrap();
        let mut cmd = Command {
            cmd: Cmd::Sub,
            corr_id: [5; 16],
            queue_id: [6; 32],
            auth: [0; 32],
            payload: &[],
        };
        cmd.sign(&key, b"").unwrap();
        session.accept(&cmd, &client_pk).unwrap();
        // The same corr_id again is a replay.
        assert_eq!(session.accept(&cmd, &client_pk), Err(Reject::Rejected));
        cmd.corr_id = [7; 16];
        assert_eq!(session.accept(&cmd, &[9; 32]), Err(Reject::Rejected));
        cmd.sign(&key, b"").unwrap();
        session.accept(&cmd, &client_pk).unwrap();

        for i in 0..MAX_QUEUES_PER_SESSION {
            session.bind_queue([i as u8; 32]).unwrap();
        }
        assert_eq!(session.bind_queue([0xFF; 32]), Err(Reject::Limit));
        session.bind_queue([0; 32]).unwrap();
        // A deleted queue frees its place.
        session.unbind_queue(&[1; 32]);
        session.bind_queue([0xFF; 32]).unwrap();

        let resume = SessionControl::resume(&Secret::new([3; 32]), [2; 8], 1, 0, 0);
        session.resume(&resume).unwrap();
        assert_eq!(session.resume(&resume), Err(Reject::Rejected));
        assert!(Session::open(resume, StaticSecret::from([1u8; 32])).is_err());
    }
}
