//! The session link of Part 6 §6.2.2 and §6.2.3, on both ends.
//!
//! A session outlives its connection. The client opens it once, frames
//! each cell with a sequence, and can resume it on a new connection inside
//! `SESSION_RESUME_WINDOW`. The relay binds the session to at most one
//! connection and drops a frame whose sequence it accepted before. No type
//! here waits, reads, or writes: the runtime moves the bytes.
//!
//! v1 defers the resume (Part 3 §3.8). After a lost connection
//! a client opens a new session, and the ARQ of Part 3 §3.7 sends each
//! record again. Thus a link keeps no cell unless its owner asks for the
//! resend window with [`ClientLink::keep_for_resume`].

use alloc::{
    collections::{BTreeSet, VecDeque},
    vec::Vec,
};

use umbra_crypto::secret::Secret;
use umbra_wire::{
    capsule::{self, CapsuleType, HEADER_LEN},
    session::{SessionControl, SessionFrame, SEQ_MAX, SESSION_FRAME_OVERHEAD},
};

use crate::Error;

/// `SESSION_RESUME_WINDOW`, in seconds.
pub const RESUME_WINDOW: u64 = 4 * 3_600;
/// The in-flight window of Part 3 §3.7 item 4.
pub const RESEND_WINDOW: usize = 1_000;

/// What the client keeps for a session.
pub struct ClientLink {
    id: [u8; 8],
    secret: Secret<32>,
    next_seq: u32,
    resume_count: u32,
    connected: bool,
    closed_at: Option<u64>,
    /// Whether the link keeps each cell for a resume. A link that never
    /// resumes keeps none. Nothing would drain the window of a client, and
    /// an upload would hold 1 000 cells of it for no use.
    keeps: bool,
    window: VecDeque<(u32, Vec<u8>)>,
    /// The highest frame sequence of the relay that the client accepted.
    relay_seq: Option<u32>,
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
        let mut record = [0u8; 41];
        let n = control.encode(&mut record)?;
        let used = capsule::encode(
            CapsuleType::Session,
            record.get(..n).ok_or(Error::Capacity)?,
            out,
        )?;
        Ok((
            ClientLink {
                id,
                secret,
                next_seq: 0,
                resume_count: 0,
                connected: true,
                closed_at: None,
                keeps: false,
                window: VecDeque::new(),
                relay_seq: None,
            },
            used,
        ))
    }

    /// Keeps a copy of each later cell in the resend window, for a link
    /// that resumes its session (`WIR-525`). The owner then names each
    /// frame that the relay drained with [`ClientLink::drained`].
    pub fn keep_for_resume(&mut self) {
        self.keeps = true;
    }

    /// The session identifier.
    pub fn id(&self) -> [u8; 8] {
        self.id
    }

    /// The next frame sequence.
    pub fn next_seq(&self) -> u32 {
        self.next_seq
    }

    /// Frames `cell` into a cell capsule (`WIR-138`) and returns the
    /// capsule length. Fails when `seq` would wrap (`WIR-139`). A link
    /// that resumes keeps a copy in the resend window, and a full window
    /// drops its oldest frame (`WIR-525`). A link that does not resume
    /// keeps no copy (Part 3 §3.8).
    pub fn send(&mut self, cell: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if !self.connected {
            return Err(Error::State);
        }
        if self.next_seq >= SEQ_MAX {
            return Err(Error::State);
        }
        let seq = self.next_seq;
        let used = self.frame(seq, false, cell, out)?;
        if self.keeps {
            if self.window.len() >= RESEND_WINDOW {
                self.window.pop_front();
            }
            self.window.push_back((seq, cell.to_vec()));
        }
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(used)
    }

    fn frame(&self, seq: u32, resend: bool, cell: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let frame = SessionFrame {
            session_id: self.id,
            seq,
            resend,
            cell,
        };
        // The frame goes in place after the header, thus no second copy.
        let (head, tail) = out.split_at_mut(HEADER_LEN.min(out.len()));
        let n = frame.encode(tail)?;
        let head: &mut [u8; HEADER_LEN] = head.try_into().map_err(|_| Error::Capacity)?;
        encode_header(n, head)?;
        Ok(HEADER_LEN.saturating_add(n))
    }

    /// Takes a frame of the relay. Returns the cell, or `None` for a frame
    /// whose sequence the client accepted before (`WIR-141`). The relay
    /// sends in order over TLS or QUIC, thus one high-water mark serves.
    pub fn receive<'a>(&mut self, capsule_value: &'a [u8]) -> Result<Option<&'a [u8]>, Error> {
        let (frame, _) = SessionFrame::parse(capsule_value)?;
        if frame.session_id != self.id {
            return Err(Error::Refused);
        }
        if self.relay_seq.is_some_and(|seen| frame.seq <= seen) {
            return Ok(None);
        }
        self.relay_seq = Some(frame.seq);
        Ok(Some(frame.cell))
    }

    /// A frame the relay drained: everything at or below `seq` leaves the
    /// window. The end-to-end ARQ of Part 3 §3.7 gives this signal; the
    /// frame carries no acknowledgment of its own.
    pub fn drained(&mut self, seq: u32) {
        while self.window.front().is_some_and(|(s, _)| *s <= seq) {
            self.window.pop_front();
        }
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
    /// next count (`WIR-234` to `WIR-236`), or an error when the window
    /// passed and the client must open a new session.
    pub fn resume(&mut self, now: u64, out: &mut [u8]) -> Result<usize, Error> {
        if !self.may_resume(now) {
            return Err(Error::State);
        }
        self.resume_count = self.resume_count.saturating_add(1);
        let control = SessionControl::resume(&self.secret, self.id, self.resume_count);
        let mut record = [0u8; 29];
        let n = control.encode(&mut record)?;
        let used = capsule::encode(
            CapsuleType::Session,
            record.get(..n).ok_or(Error::Capacity)?,
            out,
        )?;
        self.connected = true;
        self.closed_at = None;
        Ok(used)
    }

    /// The frames to send again after a resume, each with the resend bit
    /// and its first sequence (`WIR-140`). The caller sends them in order.
    pub fn resend_all(&self, out: &mut Vec<Vec<u8>>) -> Result<(), Error> {
        for (seq, cell) in &self.window {
            let mut buf = alloc::vec![0u8; cell.len() + SESSION_FRAME_OVERHEAD + HEADER_LEN];
            let n = self.frame(*seq, true, cell, &mut buf)?;
            buf.truncate(n);
            out.push(buf);
        }
        Ok(())
    }

    /// The close capsule that ends the session by the client's choice
    /// (`WIR-246`). A push wake closes the connection without it
    /// (`WIR-360`).
    pub fn close(self, out: &mut [u8]) -> Result<usize, Error> {
        let control = SessionControl::Close {
            session_id: self.id,
        };
        let mut record = [0u8; 9];
        let n = control.encode(&mut record)?;
        Ok(capsule::encode(
            CapsuleType::Session,
            record.get(..n).ok_or(Error::Capacity)?,
            out,
        )?)
    }
}

fn encode_header(value_len: usize, out: &mut [u8; HEADER_LEN]) -> Result<(), Error> {
    let len = u32::try_from(value_len).map_err(|_| Error::Capacity)?;
    let kind = (0x4000u16 | CapsuleType::Cell as u16).to_be_bytes();
    let len = (0x8000_0000u32 | len).to_be_bytes();
    *out = [kind[0], kind[1], len[0], len[1], len[2], len[3]];
    Ok(())
}

/// What the relay keeps for a session.
pub struct RelayLink {
    id: [u8; 8],
    secret: Secret<32>,
    resume_count: u32,
    /// The frame sequences that the relay accepted inside the window below
    /// the highest one. A client resends inside `RESEND_WINDOW` only, thus
    /// a sequence below that window is a duplicate, and the set stays
    /// bounded whatever a peer sends.
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
        let window = u32::try_from(RESEND_WINDOW).unwrap_or(u32::MAX);
        let floor = self.top.map_or(0, |top| top.saturating_sub(window));
        let is_below = self.top.is_some() && frame.seq < floor;
        if is_below || !self.accepted.insert(frame.seq) {
            return Ok(None);
        }
        if self.top.is_none_or(|top| frame.seq > top) {
            self.top = Some(frame.seq);
            let floor = frame.seq.saturating_sub(window);
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
            resend: false,
            cell,
        };
        let (head, tail) = out.split_at_mut(HEADER_LEN.min(out.len()));
        let n = frame.encode(tail)?;
        let head: &mut [u8; HEADER_LEN] = head.try_into().map_err(|_| Error::Capacity)?;
        encode_header(n, head)?;
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(HEADER_LEN.saturating_add(n))
    }

    /// The connection dropped at `now`; the state stays for the window
    /// (`WIR-243`).
    pub fn connection_lost(&mut self, now: u64) {
        self.bound = false;
        self.closed_at = Some(now);
    }

    /// Whether the relay may discard the state at `now` (`WIR-244`).
    pub fn expired(&self, now: u64) -> bool {
        self.closed_at
            .is_some_and(|at| now.saturating_sub(at) >= RESUME_WINDOW)
    }

    /// Binds a resume to a new connection (`WIR-237` to `WIR-242`). The
    /// caller closes the previous connection if it is open.
    pub fn resume(&mut self, control: &SessionControl, now: u64) -> Result<(), Error> {
        if self.expired(now) {
            return Err(Error::Refused);
        }
        let count = control
            .verify_resume(&self.secret, &self.id, self.resume_count)
            .map_err(|_| Error::Refused)?;
        self.resume_count = count;
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

    #[test]
    fn a_link_that_does_not_resume_keeps_no_cell() {
        let mut buf = vec![0u8; 40_000];
        let (mut client, _) = ClientLink::open([1; 8], Secret::new([2; 32]), &mut buf).unwrap();
        let cell = vec![7u8; 512];
        // Part 3 §3.8: a v1 client opens a new session after a lost
        // connection, thus an upload leaves no cell behind.
        for _ in 0..RESEND_WINDOW + 200 {
            client.send(&cell, &mut buf).unwrap();
        }
        assert!(client.window.is_empty());
        assert_eq!(client.next_seq(), 1_200);
        // The signal of a drained frame changes nothing.
        client.drained(5);
        let mut none = Vec::new();
        client.resend_all(&mut none).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn a_full_window_drops_its_oldest_frame_and_refuses_no_send() {
        let mut buf = vec![0u8; 40_000];
        let (mut client, _) = ClientLink::open([1; 8], Secret::new([2; 32]), &mut buf).unwrap();
        client.keep_for_resume();
        let cell = vec![7u8; 512];
        // WIR-525: a long upload sends past the window.
        for _ in 0..RESEND_WINDOW + 200 {
            client.send(&cell, &mut buf).unwrap();
        }
        assert_eq!(client.window.len(), RESEND_WINDOW);
        assert_eq!(client.window.front().map(|(seq, _)| *seq), Some(200));
    }

    #[test]
    fn a_session_survives_a_connection_and_drops_a_duplicate() {
        let mut buf = vec![0u8; 40_000];
        let (mut client, n) = ClientLink::open([1; 8], Secret::new([2; 32]), &mut buf).unwrap();
        let (kind, value, _) = capsule::parse(&buf[..n]).unwrap();
        assert_eq!(kind, CapsuleType::Session);
        let mut relay = RelayLink::open(SessionControl::parse(value).unwrap()).unwrap();
        client.keep_for_resume();

        let cell = vec![7u8; 512];
        let n = client.send(&cell, &mut buf).unwrap();
        let (kind, value, _) = capsule::parse(&buf[..n]).unwrap();
        assert_eq!(kind, CapsuleType::Cell);
        assert_eq!(relay.receive(value).unwrap(), Some(&cell[..]));
        assert_eq!(relay.receive(value).unwrap(), None);

        client.connection_lost(1_000);
        relay.connection_lost(1_000);
        assert!(client.send(&cell, &mut buf).is_err());
        let n = client.resume(1_500, &mut buf).unwrap();
        let (_, value, _) = capsule::parse(&buf[..n]).unwrap();
        relay
            .resume(&SessionControl::parse(value).unwrap(), 1_500)
            .unwrap();
        let mut again = Vec::new();
        client.resend_all(&mut again).unwrap();
        assert_eq!(again.len(), 1);
        let (_, value, _) = capsule::parse(&again[0]).unwrap();
        let (frame, _) = SessionFrame::parse(value).unwrap();
        assert!(frame.resend);
        assert_eq!(frame.seq, 0);
        assert_eq!(relay.receive(value).unwrap(), None);
        client.drained(0);
        let mut none = Vec::new();
        client.resend_all(&mut none).unwrap();
        assert!(none.is_empty());

        client.connection_lost(2_000);
        relay.connection_lost(2_000);
        assert!(!client.may_resume(2_000 + RESUME_WINDOW));
        assert!(client.resume(2_000 + RESUME_WINDOW, &mut buf).is_err());
        assert!(relay.expired(2_000 + RESUME_WINDOW));
        let n = client.close(&mut buf).unwrap();
        let (_, value, _) = capsule::parse(&buf[..n]).unwrap();
        relay.close(&SessionControl::parse(value).unwrap()).unwrap();
    }
}
