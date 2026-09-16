//! The queue command of Part 6 §6.4 (L5) and its deniable authenticator
//! (Part 3 §3.2.3).
//!
//! One namespace holds every command byte, including the attachment, the
//! community, and the group-queue ranges. A parser reads the byte in this
//! namespace only (`WIR-008`).

use umbra_crypto::auth::{CommandAuthKey, AUTH_LEN};

use crate::{
    bucket::{Bucket, COMMAND_HEADER},
    codec::{Reader, Writer},
    group::GroupCmd,
    Error,
};

/// The command version.
pub const VERSION: u8 = 0x01;

/// The command byte. The ranges hold their own byte, checked at parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    /// `0x01`, sent by the recipient.
    New,
    /// `0x02`, sent by the relay.
    Ids,
    /// `0x10`, sent by the sender.
    Send,
    /// `0x11`, sent by the relay.
    Msg,
    /// `0x12`, sent by the recipient.
    Ack,
    /// `0x20`.
    Sub,
    /// `0x21`.
    Unsub,
    /// `0x30`.
    Nkey,
    /// `0x31`, sent by the relay.
    Nid,
    /// `0x40`.
    Del,
    /// `0x50`, sent by the relay.
    Quota,
    /// `0x51`, sent by the relay.
    Nack,
    /// `0x60`, indistinguishable from `SEND` and `MSG` after L4.
    Cover,
    /// `0x70` to `0x7B`, Part 13 §13.3.3.
    Attachment(u8),
    /// `0x80` to `0x85`, Part 12 §12.3.3.
    Community(u8),
    /// `0x90` to `0x9A`, §6.4.5.
    Group(GroupCmd),
}

impl Cmd {
    /// The byte of the command.
    pub const fn to_byte(self) -> u8 {
        match self {
            Cmd::New => 0x01,
            Cmd::Ids => 0x02,
            Cmd::Send => 0x10,
            Cmd::Msg => 0x11,
            Cmd::Ack => 0x12,
            Cmd::Sub => 0x20,
            Cmd::Unsub => 0x21,
            Cmd::Nkey => 0x30,
            Cmd::Nid => 0x31,
            Cmd::Del => 0x40,
            Cmd::Quota => 0x50,
            Cmd::Nack => 0x51,
            Cmd::Cover => 0x60,
            Cmd::Attachment(b) | Cmd::Community(b) => b,
            Cmd::Group(g) => g as u8,
        }
    }

    /// The command of a byte, in this namespace only.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x01 => Cmd::New,
            0x02 => Cmd::Ids,
            0x10 => Cmd::Send,
            0x11 => Cmd::Msg,
            0x12 => Cmd::Ack,
            0x20 => Cmd::Sub,
            0x21 => Cmd::Unsub,
            0x30 => Cmd::Nkey,
            0x31 => Cmd::Nid,
            0x40 => Cmd::Del,
            0x50 => Cmd::Quota,
            0x51 => Cmd::Nack,
            0x60 => Cmd::Cover,
            0x70..=0x7B => Cmd::Attachment(b),
            0x80..=0x85 => Cmd::Community(b),
            0x90..=0x9A => match GroupCmd::from_byte(b) {
                Ok(g) => Cmd::Group(g),
                Err(e) => return Err(e),
            },
            _ => return Err(Error::Malformed),
        })
    }

    /// The `payload_len` that the tables of §6.4 and §6.4.5 fix for this
    /// command at `bucket`, or `None` when the length is not fixed.
    pub fn fixed_payload_len(self, bucket: Bucket) -> Option<usize> {
        match self {
            Cmd::Send => Some(bucket.l6_record()),
            Cmd::Msg | Cmd::Cover => Some(bucket.l5_payload()),
            Cmd::Ack | Cmd::Quota => Some(4),
            Cmd::Sub | Cmd::Unsub | Cmd::Del => Some(0),
            Cmd::Nkey | Cmd::Nid => Some(32),
            Cmd::Ids => Some(IDS_LEN),
            Cmd::Nack => Some(crate::nack::LEN),
            Cmd::Group(g) => g.fixed_payload_len(bucket),
            _ => None,
        }
    }
}

/// A queue command with its header fields.
pub struct Command<'a> {
    /// The command.
    pub cmd: Cmd,
    /// Random and unique for each command.
    pub corr_id: [u8; 16],
    /// The identifier that `cmd` names: a queue, a chunk, a community, or a
    /// group queue.
    pub queue_id: [u8; 32],
    /// The deniable authenticator, or zero bytes where the table gives none.
    pub auth: [u8; AUTH_LEN],
    /// The payload.
    pub payload: &'a [u8],
}

impl<'a> Command<'a> {
    /// The encoded length.
    pub fn len(&self) -> usize {
        COMMAND_HEADER.saturating_add(self.payload.len())
    }

    /// Whether the payload is empty. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Writes the command and returns its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let payload_len = u16::try_from(self.payload.len()).map_err(|_| Error::Capacity)?;
        let mut w = Writer::new(out);
        w.u8(VERSION)?;
        w.u8(self.cmd.to_byte())?;
        w.put(&self.corr_id)?;
        w.put(&self.queue_id)?;
        w.put(&self.auth)?;
        w.u16(payload_len)?;
        w.put(self.payload)?;
        Ok(w.position())
    }

    /// Reads one command from the front of a command area, and checks the
    /// payload length that the tables fix for `cmd` at `bucket`. Returns the
    /// count of bytes it took, thus a batch parses in a loop (§6.4.1).
    pub fn parse(bytes: &'a [u8], bucket: Bucket) -> Result<(Self, usize), Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let cmd = Cmd::from_byte(r.u8()?)?;
        let corr_id = r.array()?;
        let queue_id = r.array()?;
        let auth = r.array()?;
        let payload_len = usize::from(r.u16()?);
        if cmd
            .fixed_payload_len(bucket)
            .is_some_and(|fixed| fixed != payload_len)
        {
            return Err(Error::Malformed);
        }
        let payload = r.take(payload_len)?;
        Ok((
            Command {
                cmd,
                corr_id,
                queue_id,
                auth,
                payload,
            },
            r.position(),
        ))
    }

    /// The `authorized_bytes` of `NET-118`, as the parts the MAC absorbs in
    /// order. `bind` is empty for a queue command (`NET-119`).
    fn authorized_parts<'b>(
        &'b self,
        cmd_byte: &'b [u8; 1],
        len_bytes: &'b [u8; 2],
        bind: &'b [u8],
    ) -> [&'b [u8]; 6] {
        [
            &[VERSION],
            cmd_byte,
            &self.queue_id,
            len_bytes,
            self.payload,
            bind,
        ]
    }

    /// Computes `auth` under `key` and stores it.
    pub fn sign(&mut self, key: &CommandAuthKey, bind: &[u8]) -> Result<(), Error> {
        let cmd_byte = [self.cmd.to_byte()];
        let len_bytes = u16::try_from(self.payload.len())
            .map_err(|_| Error::Capacity)?
            .to_be_bytes();
        self.auth = key.mac(
            &self.corr_id,
            &self.authorized_parts(&cmd_byte, &len_bytes, bind),
        );
        Ok(())
    }

    /// Verifies `auth` under `key` (`NET-121`).
    pub fn verify(&self, key: &CommandAuthKey, bind: &[u8]) -> Result<(), Error> {
        let cmd_byte = [self.cmd.to_byte()];
        let len_bytes = u16::try_from(self.payload.len())
            .map_err(|_| Error::Malformed)?
            .to_be_bytes();
        key.verify(
            &self.corr_id,
            &self.authorized_parts(&cmd_byte, &len_bytes, bind),
            &self.auth,
        )?;
        Ok(())
    }
}

/// The length of an `IDS` payload.
pub const IDS_LEN: usize = 96;
/// The length of a `NEW` payload at an empty admission.
pub const NEW_NONE_LEN: usize = 67;

/// The payload of `NEW` (§6.4).
pub struct NewPayload<'a> {
    /// `QR_auth` of Part 3 §3.2.2.
    pub qr_auth_pk: [u8; 32],
    /// `QS_auth` of Part 3 §3.2.2.
    pub qs_auth_pk: [u8; 32],
    /// The admission trailer.
    pub admission: crate::admission::Admission<'a>,
}

impl<'a> NewPayload<'a> {
    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put(&self.qr_auth_pk)?;
        w.put(&self.qs_auth_pk)?;
        let n = self.admission.encode(w.tail())?;
        Ok(w.position().saturating_add(n))
    }

    /// Reads the payload (`WIR-488`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let qr_auth_pk = r.array()?;
        let qs_auth_pk = r.array()?;
        let (admission, used) = crate::admission::Admission::parse(r.rest())?;
        if used != bytes.len().saturating_sub(64) {
            return Err(Error::Malformed);
        }
        Ok(NewPayload {
            qr_auth_pk,
            qs_auth_pk,
            admission,
        })
    }
}

/// The payload of `IDS` (§6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdsPayload {
    /// `RecipientId`.
    pub recipient_id: [u8; 32],
    /// `SenderId`.
    pub sender_id: [u8; 32],
    /// `RelaySession_pk` of Part 3 §3.2.3.
    pub relay_session_pk: [u8; 32],
}

impl IdsPayload {
    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put(&self.recipient_id)?;
        w.put(&self.sender_id)?;
        w.put(&self.relay_session_pk)?;
        Ok(w.position())
    }

    /// Reads the payload (`WIR-488`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let out = IdsPayload {
            recipient_id: r.array()?,
            sender_id: r.array()?,
            relay_session_pk: r.array()?,
        };
        r.finish()?;
        Ok(out)
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
    use umbra_crypto::x25519::{PublicKey as XPublic, StaticSecret};

    fn key_pair() -> (CommandAuthKey, CommandAuthKey) {
        let client = StaticSecret::from([3u8; 32]);
        let relay = StaticSecret::from([4u8; 32]);
        (
            CommandAuthKey::derive(&client, XPublic::from(&relay).as_bytes()).unwrap(),
            CommandAuthKey::derive(&relay, XPublic::from(&client).as_bytes()).unwrap(),
        )
    }

    #[test]
    fn a_signed_command_round_trips_and_binds_its_fields() {
        let (client, relay) = key_pair();
        let mut cmd = Command {
            cmd: Cmd::Ack,
            corr_id: [1; 16],
            queue_id: [2; 32],
            auth: [0; 32],
            payload: &[0, 0, 0, 7],
        };
        cmd.sign(&client, b"").unwrap();
        let mut out = vec![0u8; cmd.len() + 3];
        let n = cmd.encode(&mut out).unwrap();
        assert_eq!(n, 88);
        let (back, used) = Command::parse(&out, Bucket::B0).unwrap();
        assert_eq!(used, 88);
        assert_eq!(back.cmd, Cmd::Ack);
        back.verify(&relay, b"").unwrap();
        assert!(back.verify(&relay, b"x").is_err());
        out[1] = 0x40;
        assert!(Command::parse(&out, Bucket::B0).is_err());
        out[1] = 0x20;
        assert!(Command::parse(&out, Bucket::B0).is_err());
        out[0] = 0x02;
        assert!(Command::parse(&out, Bucket::B0).is_err());
    }

    #[test]
    fn the_send_and_msg_lengths_hold_at_each_bucket() {
        for bucket in Bucket::ALL {
            let send = vec![0u8; bucket.l6_record()];
            let cmd = Command {
                cmd: Cmd::Send,
                corr_id: [0; 16],
                queue_id: [0; 32],
                auth: [0; 32],
                payload: &send,
            };
            assert_eq!(cmd.len(), bucket.command_area() - 4);
            let msg = vec![0u8; bucket.l5_payload()];
            let cmd = Command {
                cmd: Cmd::Msg,
                payload: &msg,
                ..cmd
            };
            assert_eq!(cmd.len(), bucket.command_area());
            let mut out = vec![0u8; cmd.len()];
            cmd.encode(&mut out).unwrap();
            assert!(Command::parse(&out, bucket).is_ok());
            let wrong = Bucket::ALL.into_iter().find(|b| *b != bucket).unwrap();
            assert!(Command::parse(&out, wrong).is_err());
        }
    }

    #[test]
    fn the_new_and_ids_payloads_hold_their_lengths() {
        let mut out = [0u8; 100];
        let new = NewPayload {
            qr_auth_pk: [1; 32],
            qs_auth_pk: [2; 32],
            admission: crate::admission::Admission::NONE,
        };
        assert_eq!(new.encode(&mut out).unwrap(), NEW_NONE_LEN);
        assert_eq!(NewPayload::parse(&out[..67]).unwrap().qs_auth_pk, [2; 32]);
        assert!(NewPayload::parse(&out[..68]).is_err());
        let ids = IdsPayload {
            recipient_id: [3; 32],
            sender_id: [4; 32],
            relay_session_pk: [5; 32],
        };
        assert_eq!(ids.encode(&mut out).unwrap(), IDS_LEN);
        assert_eq!(IdsPayload::parse(&out[..96]).unwrap(), ids);
        assert_eq!(Cmd::Quota.fixed_payload_len(Bucket::B0), Some(4));
        assert_eq!(Cmd::Nkey.fixed_payload_len(Bucket::B0), Some(32));
    }

    #[test]
    fn the_namespace_is_closed() {
        for b in [
            0x00u8, 0x03, 0x13, 0x22, 0x32, 0x41, 0x52, 0x61, 0x6F, 0x7C, 0x86, 0x9B, 0x9F, 0xA0,
            0xFF,
        ] {
            assert!(Cmd::from_byte(b).is_err(), "{b:#x}");
        }
        for b in [0x70u8, 0x7B, 0x80, 0x85, 0x90, 0x9A] {
            assert_eq!(Cmd::from_byte(b).unwrap().to_byte(), b);
        }
    }
}
