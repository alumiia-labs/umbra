//! The queue command of Part 6 §6.4 (L5) and its deniable authenticator
//! (Part 3 §3.2.3).
//!
//! One namespace holds every command byte, including the attachment and
//! the group-queue ranges. A parser reads the byte in this namespace only
//! (`WIR-008`).

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
    /// `0x03`, sent by the recipient: it asks for the link identifier of
    /// an invitation (Part 4 §4.3.1).
    Ires,
    /// `0x04`, sent by the relay: the link identifier.
    Ilink,
    /// `0x05`, sent by the recipient: the invitation blob.
    Iput,
    /// `0x06`, sent by the party that holds the link: the first fetch.
    Iget,
    /// `0x07`, sent by the relay: the invitation blob.
    Iblob,
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
    /// `0x32`, sent by the relay: its notification key, Part 8 §8.2.3.
    Npk,
    /// `0x33`, sent by the recipient: the sealed binding, Part 8 §8.2.3.
    Nbind,
    /// `0x34`, sent by the notifier: the watch of a queue, Part 8 §8.4.3.
    Nsub,
    /// `0x35`, sent by the relay: the blob of one arrival on a watch.
    Nwake,
    /// `0x40`.
    Del,
    /// `0x50`, sent by the relay.
    Quota,
    /// `0x51`, sent by the relay.
    Nack,
    /// `0x60`, indistinguishable from `SEND` and `MSG` after L4.
    Cover,
    /// `0x70` to `0x7B`, Part 12 §12.3.3.
    Attachment(u8),
    /// `0x90` to `0x9A`, §6.4.5.
    Group(GroupCmd),
}

impl Cmd {
    /// The byte of the command.
    pub const fn to_byte(self) -> u8 {
        match self {
            Cmd::New => 0x01,
            Cmd::Ids => 0x02,
            Cmd::Ires => 0x03,
            Cmd::Ilink => 0x04,
            Cmd::Iput => 0x05,
            Cmd::Iget => 0x06,
            Cmd::Iblob => 0x07,
            Cmd::Send => 0x10,
            Cmd::Msg => 0x11,
            Cmd::Ack => 0x12,
            Cmd::Sub => 0x20,
            Cmd::Unsub => 0x21,
            Cmd::Nkey => 0x30,
            Cmd::Nid => 0x31,
            Cmd::Npk => 0x32,
            Cmd::Nbind => 0x33,
            Cmd::Nsub => 0x34,
            Cmd::Nwake => 0x35,
            Cmd::Del => 0x40,
            Cmd::Quota => 0x50,
            Cmd::Nack => 0x51,
            Cmd::Cover => 0x60,
            Cmd::Attachment(b) => b,
            Cmd::Group(g) => g as u8,
        }
    }

    /// The command of a byte, in this namespace only.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x01 => Cmd::New,
            0x02 => Cmd::Ids,
            0x03 => Cmd::Ires,
            0x04 => Cmd::Ilink,
            0x05 => Cmd::Iput,
            0x06 => Cmd::Iget,
            0x07 => Cmd::Iblob,
            0x10 => Cmd::Send,
            0x11 => Cmd::Msg,
            0x12 => Cmd::Ack,
            0x20 => Cmd::Sub,
            0x21 => Cmd::Unsub,
            0x30 => Cmd::Nkey,
            0x31 => Cmd::Nid,
            0x32 => Cmd::Npk,
            0x33 => Cmd::Nbind,
            0x34 => Cmd::Nsub,
            0x35 => Cmd::Nwake,
            0x40 => Cmd::Del,
            0x50 => Cmd::Quota,
            0x51 => Cmd::Nack,
            0x60 => Cmd::Cover,
            0x70..=0x7B => Cmd::Attachment(b),
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
            Cmd::Sub | Cmd::Unsub | Cmd::Del | Cmd::Ires | Cmd::Nsub => Some(0),
            Cmd::Ilink => Some(LINK_ID_LEN),
            Cmd::Iget => Some(IGET_LEN),
            // WIR-505: a blob fills the record length of its bucket, as a
            // `SEND` does, thus its length names no bundle.
            Cmd::Iput | Cmd::Iblob => Some(bucket.l6_record()),
            Cmd::Nkey | Cmd::Nid => Some(32),
            Cmd::Npk => Some(NPK_LEN),
            Cmd::Nbind => Some(NBIND_LEN),
            Cmd::Nwake => Some(NWAKE_LEN),
            Cmd::Ids => Some(IDS_LEN),
            Cmd::Nack => Some(crate::nack::LEN),
            Cmd::Attachment(b) => attachment_payload_len(b),
            Cmd::Group(g) => g.fixed_payload_len(bucket),
            _ => None,
        }
    }
}

/// The `payload_len` that Part 12 §12.3.3 fixes for an attachment command,
/// or `None` for `CNEW`, `BNEW`, and `CREP`, whose payload has a field of
/// its own length. A bucket changes none of them.
const fn attachment_payload_len(b: u8) -> Option<usize> {
    const CHUNK: usize = crate::descriptor::CHUNK_SIZE as usize;
    match b {
        // CID: `storage_token`. CPRF: `proof`.
        0x71 | 0x79 => Some(32),
        // CPUT and CDAT: one chunk (`ATT-043`).
        0x72 | 0x74 => Some(CHUNK),
        // CGET, CDEL, and CRNW: empty.
        0x73 | 0x75 | 0x7A => Some(0),
        // CRPUT: `storage_token` and one chunk.
        0x77 => Some(32 + CHUNK),
        // CVFY: `nonce`.
        0x78 => Some(16),
        _ => None,
    }
}

/// A queue command with its header fields.
pub struct Command<'a> {
    /// The command.
    pub cmd: Cmd,
    /// Random and unique for each command.
    pub corr_id: [u8; 16],
    /// The identifier that `cmd` names: a queue, a chunk, or a group
    /// queue.
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
/// The length of the link identifier of an invitation (Part 4 §4.3.1).
pub const LINK_ID_LEN: usize = 24;
/// The length of an `IGET` payload: the link identifier and the lock key.
pub const IGET_LEN: usize = LINK_ID_LEN + 32;

/// Writes the payload of an `IPUT` at `bucket`: the link identifier, the
/// true length of the blob, the blob, and the zero fill.
pub fn iput_payload(
    link_id: &[u8; LINK_ID_LEN],
    blob: &[u8],
    bucket: Bucket,
) -> Result<alloc::vec::Vec<u8>, Error> {
    let mut out = alloc::vec![0u8; bucket.l6_record()];
    let mut w = Writer::new(&mut out);
    w.put(link_id)?;
    w.u16(u16::try_from(blob.len()).map_err(|_| Error::Capacity)?)?;
    w.put(blob)?;
    Ok(out)
}

/// Reads the payload of an `IPUT`.
pub fn iput_parse(payload: &[u8]) -> Result<([u8; LINK_ID_LEN], &[u8]), Error> {
    let mut r = Reader::new(payload);
    let link_id = r.array()?;
    Ok((link_id, filled_blob(&mut r)?))
}

/// Writes the payload of an `IBLOB` at `bucket`.
pub fn iblob_payload(blob: &[u8], bucket: Bucket) -> Result<alloc::vec::Vec<u8>, Error> {
    let mut out = alloc::vec![0u8; bucket.l6_record()];
    let mut w = Writer::new(&mut out);
    w.u16(u16::try_from(blob.len()).map_err(|_| Error::Capacity)?)?;
    w.put(blob)?;
    Ok(out)
}

/// Reads the payload of an `IBLOB`.
pub fn iblob_parse(payload: &[u8]) -> Result<&[u8], Error> {
    filled_blob(&mut Reader::new(payload))
}

/// A blob behind its true length, with a fill that MUST be zero bytes
/// (`WIR-506`).
fn filled_blob<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let len = usize::from(r.u16()?);
    let blob = r.take(len)?;
    if len == 0 || r.rest().iter().any(|byte| *byte != 0) {
        return Err(Error::Malformed);
    }
    Ok(blob)
}

/// The smallest bucket whose record length holds an invitation blob with
/// the fields of an `IPUT` before it.
pub fn blob_bucket(blob_len: usize) -> Option<Bucket> {
    [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3]
        .into_iter()
        .find(|bucket| LINK_ID_LEN + 2 + blob_len <= bucket.l6_record())
}
/// The length of an `NPK` payload: the `UMBRA-KEM` public key of the relay.
pub const NPK_LEN: usize = 1_216;
/// The length of an `NBIND` payload: the HPKE encapsulation of 1 120 bytes,
/// the 98-byte binding of Part 8 §8.2.3, and the 16-byte tag.
pub const NBIND_LEN: usize = 1_120 + 98 + 16;
/// The length of an `NWAKE` payload: the blob of Part 8 §8.2.2.
pub const NWAKE_LEN: usize = 69;
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

    #[test]
    fn an_invitation_blob_fills_its_bucket_and_reads_back() {
        let blob = vec![7u8; 1_400];
        let bucket = blob_bucket(blob.len()).unwrap();
        assert_eq!(bucket, Bucket::B1);
        let put = iput_payload(&[9; LINK_ID_LEN], &blob, bucket).unwrap();
        assert_eq!(Some(put.len()), Cmd::Iput.fixed_payload_len(bucket));
        assert_eq!(
            iput_parse(&put).unwrap(),
            ([9; LINK_ID_LEN], blob.as_slice())
        );
        let given = iblob_payload(&blob, bucket).unwrap();
        assert_eq!(iblob_parse(&given).unwrap(), blob.as_slice());

        // WIR-506: a fill that is not zero bytes is a fault, and so is an
        // empty blob.
        let mut dirty = given.clone();
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(iblob_parse(&dirty), Err(Error::Malformed));
        assert!(iblob_parse(&iblob_payload(&[], Bucket::B0).unwrap()).is_err());
        assert_eq!(blob_bucket(40_000), None);
    }

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
        assert_eq!(Cmd::Nsub.fixed_payload_len(Bucket::B0), Some(0));
        assert_eq!(Cmd::Nwake.fixed_payload_len(Bucket::B0), Some(NWAKE_LEN));
    }

    #[test]
    fn the_namespace_is_closed() {
        for b in [
            0x00u8, 0x08, 0x13, 0x22, 0x36, 0x41, 0x52, 0x61, 0x6F, 0x7C, 0x80, 0x85, 0x86, 0x9B,
            0x9F, 0xA0, 0xFF,
        ] {
            assert!(Cmd::from_byte(b).is_err(), "{b:#x}");
        }
        for b in [0x03u8, 0x07, 0x34, 0x35, 0x70, 0x7B, 0x90, 0x9A] {
            assert_eq!(Cmd::from_byte(b).unwrap().to_byte(), b);
        }
    }

    #[test]
    fn an_attachment_command_holds_the_length_of_its_payload() {
        let encode = |cmd: u8, payload: &[u8]| {
            let command = Command {
                cmd: Cmd::Attachment(cmd),
                corr_id: [0; 16],
                queue_id: [0; 32],
                auth: [0; 32],
                payload,
            };
            let mut out = vec![0u8; command.len()];
            command.encode(&mut out).unwrap();
            out
        };
        // A CGET carries no payload, and a CVFY carries a 16-byte nonce.
        assert!(Command::parse(&encode(0x73, &[]), Bucket::B0).is_ok());
        assert!(Command::parse(&encode(0x73, &[0]), Bucket::B0).is_err());
        assert!(Command::parse(&encode(0x78, &[0; 16]), Bucket::B0).is_ok());
        assert!(Command::parse(&encode(0x78, &[0; 17]), Bucket::B0).is_err());
        // A CPUT carries one chunk, at any bucket.
        let chunk = vec![0u8; crate::descriptor::CHUNK_SIZE as usize];
        assert!(Command::parse(&encode(0x72, &chunk), Bucket::B3).is_ok());
        assert!(Command::parse(&encode(0x72, &chunk[1..]), Bucket::B3).is_err());
        // A CNEW carries an `Admission` of its own length.
        assert_eq!(Cmd::Attachment(0x70).fixed_payload_len(Bucket::B0), None);
        assert_eq!(Cmd::Attachment(0x76).fixed_payload_len(Bucket::B0), None);
    }
}
