//! The session link of Part 6 §6.2.2 and §6.2.3, on both ends.
//!
//! A session outlives its connection. The client opens it once, frames
//! each cell with a sequence, and can resume it on a new connection inside
//! `SESSION_RESUME_WINDOW`. The relay binds the session to at most one
//! connection and drops a frame whose sequence it accepted before. No type
//! here waits, reads, or writes: the runtime moves the bytes.
//!
//! A resume sends no frame again. Each onion layer chains on the cell
//! before it, thus a circuit does not continue past a lost cell. The two
//! ends compare their frame counts at the resume, and a resume holds only
//! when no frame is lost in either direction. A client that pauses its
//! session before it closes the connection makes that certain. A link thus
//! keeps no cell.

use alloc::collections::BTreeSet;

use umbra_crypto::secret::Secret;
use umbra_wire::{
    capsule::{self, CapsuleType, HEADER_LEN},
    session::{SessionControl, SessionFrame, SEQ_MAX},
};

use crate::Error;

/// `SESSION_RESUME_WINDOW`, in seconds.
pub const RESUME_WINDOW: u64 = 4 * 3_600;
/// The span of frame sequences below the highest one in which a relay
/// remembers each sequence that it accepted (`WIR-141`).
pub const ACCEPTED_SPAN: usize = 1_000;
/// `SESSION_PAUSE_WAIT`: the time that a client waits for the
/// `SessionPaused` of its relay, in seconds (`WIR-540`).
pub const PAUSE_WAIT: u64 = 2;

/// One `UMBRA_SESSION` capsule of `control`.
fn control_capsule(control: &SessionControl, out: &mut [u8]) -> Result<usize, Error> {
    let mut record = [0u8; 41];
    let n = control.encode(&mut record)?;
    Ok(capsule::encode(
        CapsuleType::Session,
        record.get(..n).ok_or(Error::Capacity)?,
        out,
    )?)
}

/// What the client keeps for a session.
pub struct ClientLink {
    id: [u8; 8],
    secret: Secret<32>,
    next_seq: u32,
    resume_count: u32,
    connected: bool,
    /// The client sent its `SessionPause`, and it sends no further frame
    /// on this connection.
    pausing: bool,
    /// The relay answered with its `SessionPaused`.
    paused: bool,
    closed_at: Option<u64>,
    /// The count of the frames of the relay that the client accepted.
    received: u32,
}

impl ClientLink {
    /// Opens a session with an identifier and a secret from the CSPRNG
    /// (`WIR-136`, `WIR-231`), and returns the capsule that goes first on
    /// the connection (`WIR-229`).
    pub fn open(id: [u8; 8], secret: Secret<32>, out: &mut [u8]) -> Result<(Self, usize), Error> {
        let control = SessionControl::Open {
            session_id: id,
            session_secret: Secret::new(*secret.expose()),
        };
        let used = control_capsule(&control, out)?;
        Ok((
            ClientLink {
                id,
                secret,
                next_seq: 0,
                resume_count: 0,
                connected: true,
                pausing: false,
                paused: false,
                closed_at: None,
                received: 0,
            },
            used,
        ))
    }

    /// The session identifier.
    pub fn id(&self) -> [u8; 8] {
        self.id
    }

    /// The next frame sequence.
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// The count of the frames of the relay that the client accepted.
    pub fn received(&self) -> u32 {
        self.received
    }

    /// Whether the link takes a cell now: it holds a connection, and the
    /// client did not pause the session on it.
    pub fn sends(&self) -> bool {
        self.connected && !self.pausing
    }

    /// Frames `cell` into a cell capsule (`WIR-138`) and returns the
    /// capsule length. Fails when `seq` would wrap (`WIR-139`), and after
    /// a pause (`WIR-539`). The link keeps no copy of the cell (`WIR-525`).
    pub fn send(&mut self, cell: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if !self.sends() || self.next_seq >= SEQ_MAX {
            return Err(Error::State);
        }

        let frame = SessionFrame {
            session_id: self.id,
            seq: self.next_seq,
            cell,
        };

        let used = frame_capsule(&frame, out)?;
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(used)
    }

    /// Takes a frame of the relay. Returns the cell, or `None` for a frame
    /// whose sequence the client accepted before (`WIR-141`). The relay
    /// sends in order over TLS, thus one count serves.
    pub fn receive<'a>(&mut self, capsule_value: &'a [u8]) -> Result<Option<&'a [u8]>, Error> {
        let (frame, _) = SessionFrame::parse(capsule_value)?;
        if frame.session_id != self.id {
            return Err(Error::Refused);
        }

        if frame.seq < self.received {
            return Ok(None);
        }

        self.received = frame.seq.saturating_add(1);
        Ok(Some(frame.cell))
    }

    /// The `SessionPause` capsule (`WIR-539`). The link frames no cell
    /// after it on this connection.
    pub fn pause(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        if !self.sends() {
            return Err(Error::State);
        }

        let used = control_capsule(
            &SessionControl::Pause {
                session_id: self.id,
            },
            out,
        )?;
        self.pausing = true;
        Ok(used)
    }

    /// Takes the `SessionPaused` of the relay. Each frame of the relay on
    /// this connection came before it (`WIR-541`).
    pub fn on_paused(&mut self, control: &SessionControl) -> Result<(), Error> {
        match control {
            SessionControl::Paused { session_id } if *session_id == self.id && self.pausing => {
                self.paused = true;
                Ok(())
            }
            _ => Err(Error::Refused),
        }
    }

    /// Whether the client sent its `SessionPause` on this connection.
    pub fn is_pausing(&self) -> bool {
        self.pausing
    }

    /// Whether the relay answered the pause of this connection.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// The connection dropped at `now`.
    pub fn connection_lost(&mut self, now: u64) {
        self.connected = false;
        self.closed_at = Some(now);
    }

    /// Whether a resume is still possible at `now` (`WIR-245`).
    pub fn may_resume(&self, now: u64) -> bool {
        self.closed_at
            .is_some_and(|at| now.saturating_sub(at) < RESUME_WINDOW)
    }

    /// The capsule that goes first on a new connection: a resume with the
    /// next count and the two frame counts (`WIR-234` to `WIR-236`), or an
    /// error when the window passed and the client must open a new session.
    pub fn resume(&mut self, now: u64, out: &mut [u8]) -> Result<usize, Error> {
        if !self.may_resume(now) {
            return Err(Error::State);
        }

        let count = self.resume_count.saturating_add(1);
        let control =
            SessionControl::resume(&self.secret, self.id, count, self.next_seq, self.received);
        let used = control_capsule(&control, out)?;

        self.resume_count = count;
        self.connected = true;
        self.pausing = false;
        self.paused = false;
        self.closed_at = None;
        Ok(used)
    }

    /// The close capsule that ends the session by the client's choice
    /// (`WIR-246`). A client that keeps its session pauses it in place of
    /// this record (`WIR-360`).
    pub fn close(self, out: &mut [u8]) -> Result<usize, Error> {
        control_capsule(
            &SessionControl::Close {
                session_id: self.id,
            },
            out,
        )
    }
}

/// One cell capsule around `frame`. The frame goes in place after the
/// header, thus no second copy.
fn frame_capsule(frame: &SessionFrame<'_>, out: &mut [u8]) -> Result<usize, Error> {
    let (head, tail) = out.split_at_mut(HEADER_LEN.min(out.len()));
    let n = frame.encode(tail)?;
    let head: &mut [u8; HEADER_LEN] = head.try_into().map_err(|_| Error::Capacity)?;
    encode_header(n, head)?;
    Ok(HEADER_LEN.saturating_add(n))
}

fn encode_header(value_len: usize, out: &mut [u8; HEADER_LEN]) -> Result<(), Error> {
    let len = u32::try_from(value_len).map_err(|_| Error::Capacity)?;
    let kind = (0x4000u16 | CapsuleType::Cell as u16).to_be_bytes();
    let len = (0x8000_0000u32 | len).to_be_bytes();
    *out = [kind[0], kind[1], len[0], len[1], len[2], len[3]];
    Ok(())
}

/// Why a relay did not bind a `SessionResume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeFault {
    /// The record does not verify, repeats a count, or came after the
    /// window (`WIR-237`, `WIR-238`, `WIR-244`). The session stays as it
    /// is: a party without the secret ends no session.
    Refused,
    /// The record verifies, and its frame counts differ from the counts of
    /// the relay (`WIR-544`). A frame is lost, thus each circuit of the
    /// session is broken, and the relay discards the session.
    Lost,
}

/// What the relay keeps for a session.
pub struct RelayLink {
    id: [u8; 8],
    secret: Secret<32>,
    resume_count: u32,
    /// The frame sequences that the relay accepted inside the span below
    /// the highest one. A sequence below that span is a duplicate, and the
    /// set stays bounded whatever a peer sends.
    accepted: BTreeSet<u32>,
    top: Option<u32>,
    bound: bool,
    closed_at: Option<u64>,
    next_seq: u32,
}

impl RelayLink {
    /// The identifier of the session, which a `RelayHello` binds (Part 10
    /// `REL-173`).
    pub fn session_id(&self) -> [u8; 8] {
        self.id
    }

    /// Accepts a `SessionOpen` (`WIR-232`). The caller checks that no live
    /// session holds the identifier (`WIR-233`).
    pub fn open(control: SessionControl) -> Result<Self, Error> {
        match control {
            SessionControl::Open {
                session_id,
                session_secret,
            } => Ok(RelayLink {
                id: session_id,
                secret: session_secret,
                resume_count: 0,
                accepted: BTreeSet::new(),
                top: None,
                bound: true,
                closed_at: None,
                next_seq: 0,
            }),
            _ => Err(Error::Refused),
        }
    }

    /// The session identifier.
    pub fn id(&self) -> [u8; 8] {
        self.id
    }

    /// Whether a connection holds the session now.
    pub fn is_bound(&self) -> bool {
        self.bound
    }

    /// Takes a frame. Returns the cell, or `None` for a duplicate the relay
    /// already accepted (`WIR-141`).
    pub fn receive<'a>(&mut self, capsule_value: &'a [u8]) -> Result<Option<&'a [u8]>, Error> {
        if !self.bound {
            return Err(Error::State);
        }

        let (frame, _) = SessionFrame::parse(capsule_value)?;
        if frame.session_id != self.id {
            return Err(Error::Refused);
        }

        let span = u32::try_from(ACCEPTED_SPAN).unwrap_or(u32::MAX);
        let floor = self.top.map_or(0, |top| top.saturating_sub(span));
        let is_below = self.top.is_some() && frame.seq < floor;
        if is_below || !self.accepted.insert(frame.seq) {
            return Ok(None);
        }

        if self.top.is_none_or(|top| frame.seq > top) {
            self.top = Some(frame.seq);
            let floor = frame.seq.saturating_sub(span);
            self.accepted = self.accepted.split_off(&floor);
        }
        Ok(Some(frame.cell))
    }

    /// Frames a cell of the relay into a cell capsule, with the frame
    /// sequence of the relay direction (`WIR-138`, `WIR-139`).
    pub fn send(&mut self, cell: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if !self.bound || self.next_seq >= SEQ_MAX {
            return Err(Error::State);
        }

        let frame = SessionFrame {
            session_id: self.id,
            seq: self.next_seq,
            cell,
        };

        let used = frame_capsule(&frame, out)?;
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(used)
    }

    /// Takes the `SessionPause` of the client at `now`, and gives the
    /// `SessionPaused` capsule (`WIR-541`). The link frames no cell after
    /// it until a resume binds it again.
    pub fn pause(
        &mut self,
        control: &SessionControl,
        now: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        match control {
            SessionControl::Pause { session_id } if *session_id == self.id && self.bound => {
                let used = control_capsule(
                    &SessionControl::Paused {
                        session_id: self.id,
                    },
                    out,
                )?;
                self.bound = false;
                self.closed_at = Some(now);
                Ok(used)
            }
            _ => Err(Error::Refused),
        }
    }

    /// The connection dropped at `now`; the state stays for the window
    /// (`WIR-243`). The window of a paused session runs from its pause.
    pub fn connection_lost(&mut self, now: u64) {
        if self.bound {
            self.bound = false;
            self.closed_at = Some(now);
        }
    }

    /// Whether the relay may discard the state at `now` (`WIR-244`).
    pub fn expired(&self, now: u64) -> bool {
        self.closed_at
            .is_some_and(|at| now.saturating_sub(at) >= RESUME_WINDOW)
    }

    /// Binds a resume to a new connection (`WIR-237` to `WIR-242`,
    /// `WIR-544`). The caller closes the previous connection if it is
    /// open, and it discards the session after [`ResumeFault::Lost`].
    pub fn resume(&mut self, control: &SessionControl, now: u64) -> Result<(), ResumeFault> {
        if self.expired(now) {
            return Err(ResumeFault::Refused);
        }

        let (count, sent, received) = control
            .verify_resume(&self.secret, &self.id, self.resume_count)
            .map_err(|_| ResumeFault::Refused)?;
        self.resume_count = count;

        let taken = self.top.map_or(0, |top| top.saturating_add(1));
        if sent != taken || received != self.next_seq {
            return Err(ResumeFault::Lost);
        }

        self.bound = true;
        self.closed_at = None;
        Ok(())
    }

    /// A `SessionClose` for this session (`WIR-247`).
    pub fn close(self, control: &SessionControl) -> Result<(), Error> {
        match control {
            SessionControl::Close { session_id } if *session_id == self.id => Ok(()),
            _ => Err(Error::Refused),
        }
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
    use alloc::vec;

    /// A client and a relay that hold one session.
    fn pair(buf: &mut [u8]) -> (ClientLink, RelayLink) {
        let (client, n) = ClientLink::open([1; 8], Secret::new([2; 32]), buf).unwrap();
        let (kind, value, _) = capsule::parse(&buf[..n]).unwrap();
        assert_eq!(kind, CapsuleType::Session);
        let relay = RelayLink::open(SessionControl::parse(value).unwrap()).unwrap();
        (client, relay)
    }

    fn control(buf: &[u8]) -> SessionControl {
        let (kind, value, _) = capsule::parse(buf).unwrap();
        assert_eq!(kind, CapsuleType::Session);
        SessionControl::parse(value).unwrap()
    }

    /// Moves one cell in each direction.
    fn exchange(client: &mut ClientLink, relay: &mut RelayLink, buf: &mut [u8]) {
        let cell = vec![7u8; 512];
        let n = client.send(&cell, buf).unwrap();
        let (_, value, _) = capsule::parse(&buf[..n]).unwrap();
        assert_eq!(relay.receive(value).unwrap(), Some(&cell[..]));

        let n = relay.send(&cell, buf).unwrap();
        let (_, value, _) = capsule::parse(&buf[..n]).unwrap();
        assert_eq!(client.receive(value).unwrap(), Some(&cell[..]));
    }

    #[test]
    fn a_frame_that_a_link_accepted_before_drops() {
        let mut buf = vec![0u8; 40_000];
        let (mut client, mut relay) = pair(&mut buf);
        let cell = vec![7u8; 512];
        let n = client.send(&cell, &mut buf).unwrap();
        let (kind, value, _) = capsule::parse(&buf[..n]).unwrap();
        assert_eq!(kind, CapsuleType::Cell);
        assert_eq!(relay.receive(value).unwrap(), Some(&cell[..]));
        assert_eq!(relay.receive(value).unwrap(), None);

        let n = relay.send(&cell, &mut buf).unwrap();
        let (_, value, _) = capsule::parse(&buf[..n]).unwrap();
        assert_eq!(client.receive(value).unwrap(), Some(&cell[..]));
        assert_eq!(client.receive(value).unwrap(), None);
        assert_eq!((client.next_seq(), client.received()), (1, 1));
    }

    #[test]
    fn a_paused_session_resumes_on_a_new_connection_with_equal_counts() {
        let mut buf = vec![0u8; 40_000];
        let (mut client, mut relay) = pair(&mut buf);
        exchange(&mut client, &mut relay, &mut buf);
        exchange(&mut client, &mut relay, &mut buf);

        // WIR-539: the client frames no cell after its pause.
        let n = client.pause(&mut buf).unwrap();
        let pause = control(&buf[..n]);
        assert!(client.is_pausing() && !client.is_paused());
        assert!(client.send(&[7u8; 512], &mut buf).is_err());
        assert!(client.pause(&mut buf).is_err());

        // WIR-541: the relay answers, and it frames no cell after it.
        let n = relay.pause(&pause, 1_000, &mut buf).unwrap();
        let paused = control(&buf[..n]);
        assert!(!relay.is_bound());
        assert!(relay.send(&[7u8; 512], &mut buf).is_err());

        client.on_paused(&paused).unwrap();
        assert!(client.is_paused());
        client.connection_lost(1_001);

        // The window of the relay runs from the pause.
        relay.connection_lost(1_500);
        assert!(relay.expired(1_000 + RESUME_WINDOW));

        let n = client.resume(2_000, &mut buf).unwrap();
        let resume = control(&buf[..n]);
        assert!(matches!(
            resume,
            SessionControl::Resume {
                resume_count: 1,
                sent: 2,
                received: 2,
                ..
            }
        ));
        relay.resume(&resume, 2_000).unwrap();
        assert!(relay.is_bound());

        // WIR-238: the same record binds no second connection.
        assert_eq!(relay.resume(&resume, 2_001), Err(ResumeFault::Refused));
        exchange(&mut client, &mut relay, &mut buf);
        assert_eq!((client.next_seq(), client.received()), (3, 3));
    }

    #[test]
    fn a_resume_with_a_lost_frame_in_either_direction_is_lost() {
        let mut buf = vec![0u8; 40_000];
        let cell = vec![7u8; 512];

        // A frame of the client that the relay did not take.
        let (mut client, mut relay) = pair(&mut buf);
        exchange(&mut client, &mut relay, &mut buf);
        client.send(&cell, &mut buf).unwrap();
        client.connection_lost(1_000);
        relay.connection_lost(1_000);
        let n = client.resume(1_010, &mut buf).unwrap();
        assert_eq!(
            relay.resume(&control(&buf[..n]), 1_010),
            Err(ResumeFault::Lost)
        );
        assert!(!relay.is_bound());

        // A frame of the relay that the client did not take.
        let (mut client, mut relay) = pair(&mut buf);
        exchange(&mut client, &mut relay, &mut buf);
        relay.send(&cell, &mut buf).unwrap();
        client.connection_lost(1_000);
        relay.connection_lost(1_000);
        let n = client.resume(1_010, &mut buf).unwrap();
        assert_eq!(
            relay.resume(&control(&buf[..n]), 1_010),
            Err(ResumeFault::Lost)
        );

        // A session that carried no frame resumes with two counts of zero.
        let (mut client, mut relay) = pair(&mut buf);
        client.connection_lost(1_000);
        relay.connection_lost(1_000);
        let n = client.resume(1_010, &mut buf).unwrap();
        relay.resume(&control(&buf[..n]), 1_010).unwrap();
    }

    #[test]
    fn a_resume_that_does_not_verify_leaves_the_session_as_it_is() {
        let mut buf = vec![0u8; 40_000];
        let (mut client, mut relay) = pair(&mut buf);
        exchange(&mut client, &mut relay, &mut buf);
        client.connection_lost(1_000);
        relay.connection_lost(1_000);

        // WIR-237: a party without the secret names the right counts.
        let forged = SessionControl::resume(&Secret::new([9; 32]), [1; 8], 1, 1, 1);
        assert_eq!(relay.resume(&forged, 1_010), Err(ResumeFault::Refused));

        // The `auth` covers the two counts. A record with a count that its
        // `auth` does not cover is thus no proof of a lost frame.
        let SessionControl::Resume {
            session_id,
            resume_count,
            auth,
            ..
        } = SessionControl::resume(&Secret::new([2; 32]), [1; 8], 1, 1, 1)
        else {
            panic!("no resume");
        };
        let moved = SessionControl::Resume {
            session_id,
            resume_count,
            sent: 2,
            received: 1,
            auth,
        };
        assert_eq!(relay.resume(&moved, 1_010), Err(ResumeFault::Refused));

        // The session still takes the resume of its client.
        let n = client.resume(1_020, &mut buf).unwrap();
        relay.resume(&control(&buf[..n]), 1_020).unwrap();
    }

    #[test]
    fn the_window_ends_a_resume_at_both_ends() {
        let mut buf = vec![0u8; 40_000];
        let (mut client, mut relay) = pair(&mut buf);
        client.connection_lost(2_000);
        relay.connection_lost(2_000);
        assert!(client.may_resume(2_000 + RESUME_WINDOW - 1));
        let late = SessionControl::resume(&Secret::new([2; 32]), [1; 8], 1, 0, 0);
        // WIR-244, WIR-245.
        assert!(!client.may_resume(2_000 + RESUME_WINDOW));
        assert!(client.resume(2_000 + RESUME_WINDOW, &mut buf).is_err());
        assert!(relay.expired(2_000 + RESUME_WINDOW));
        assert_eq!(
            relay.resume(&late, 2_000 + RESUME_WINDOW),
            Err(ResumeFault::Refused)
        );

        let n = client.close(&mut buf).unwrap();
        relay.close(&control(&buf[..n])).unwrap();
    }

    #[test]
    fn a_pause_record_of_another_session_changes_nothing() {
        let mut buf = vec![0u8; 40_000];
        let (mut client, mut relay) = pair(&mut buf);
        let other = SessionControl::Pause { session_id: [9; 8] };
        assert!(relay.pause(&other, 1_000, &mut buf).is_err());
        assert!(relay.is_bound());

        // A `SessionPaused` that the client did not ask for binds nothing.
        let early = SessionControl::Paused { session_id: [1; 8] };
        assert!(client.on_paused(&early).is_err());
        assert!(!client.is_paused());
    }
}
