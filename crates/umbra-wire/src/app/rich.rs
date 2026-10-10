//! The rich record of Part 6 §6.6.5: a reply, a thread, a forward, and
//! mentions around one inner record.

use alloc::vec::Vec;

use umbra_crypto::{hash::sha3_256, labels};

use crate::{
    app::{check_body, strictly_increasing, AppKind, Channel},
    codec::{Reader, Writer},
    Error,
};

/// The record version.
pub const VERSION: u8 = 0x02;
/// The fixed part.
pub const FIXED: usize = 40;
/// `MENTION_MAX`.
pub const MENTION_MAX: usize = 16;

/// A rich record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichRecord<'a> {
    /// The record this record answers, or zero bytes.
    pub reply_target: [u8; 16],
    /// The first record of the thread, or zero bytes.
    pub thread_root: [u8; 16],
    /// 0 for an original record.
    pub forward_depth: u8,
    /// The mention identifiers, in strictly increasing byte order.
    pub mentions: Vec<[u8; 16]>,
    /// The kind of the inner record.
    pub inner_kind: AppKind,
    /// The inner body.
    pub inner_body: &'a [u8],
}

impl<'a> RichRecord<'a> {
    /// The encoded length.
    pub fn len(&self) -> usize {
        FIXED
            .saturating_add(self.mentions.len().saturating_mul(16))
            .saturating_add(self.inner_body.len())
    }

    /// Whether the inner body is empty. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.inner_body.is_empty()
    }

    fn check(&self, channel: Channel) -> Result<(), Error> {
        let zero = [0u8; 16];
        if matches!(self.inner_kind, AppKind::Rich | AppKind::GroupControl) {
            return Err(Error::Malformed);
        }
        if self.mentions.len() > MENTION_MAX || !strictly_increasing(&self.mentions) {
            return Err(Error::Malformed);
        }
        if channel == Channel::Pairwise && (!self.mentions.is_empty() || self.thread_root != zero) {
            return Err(Error::Malformed);
        }
        // WIR-268: a thread root needs a reply target.
        if self.thread_root != zero && self.reply_target == zero {
            return Err(Error::Malformed);
        }
        // WIR-259 and WIR-362: the inner body holds the rules of its kind,
        // as the body of a message of that kind does.
        check_body(self.inner_kind, self.inner_body, channel)
    }

    /// Writes the record.
    pub fn encode(&self, channel: Channel, out: &mut [u8]) -> Result<usize, Error> {
        self.check(channel)?;
        let mut w = Writer::new(out);
        w.u8(VERSION)?;
        w.put(&self.reply_target)?;
        w.put(&self.thread_root)?;
        w.u8(self.forward_depth)?;
        w.u8(u8::try_from(self.mentions.len()).map_err(|_| Error::Malformed)?)?;
        for m in &self.mentions {
            w.put(m)?;
        }
        w.u8(self.inner_kind as u8)?;
        w.u32(u32::try_from(self.inner_body.len()).map_err(|_| Error::Capacity)?)?;
        w.put(self.inner_body)?;
        Ok(w.position())
    }

    /// Reads a record (`WIR-161` to `WIR-166`, `WIR-265`, `WIR-270`,
    /// `WIR-176`).
    pub fn parse(bytes: &'a [u8], channel: Channel) -> Result<Self, Error> {
        if bytes.len() < 41 {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let reply_target = r.array()?;
        let thread_root = r.array()?;
        let forward_depth = r.u8()?;
        let mention_count = usize::from(r.u8()?);
        if mention_count > MENTION_MAX {
            return Err(Error::Malformed);
        }
        let mut mentions = Vec::with_capacity(mention_count);
        for _ in 0..mention_count {
            mentions.push(r.array()?);
        }
        let inner_kind = AppKind::from_byte(r.u8()?)?;
        let inner_len = usize::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
        let inner_body = r.take(inner_len)?;
        r.finish()?;
        let out = RichRecord {
            reply_target,
            thread_root,
            forward_depth,
            mentions,
            inner_kind,
            inner_body,
        };
        out.check(channel)?;
        Ok(out)
    }
}

/// `mention_id = SHA3-256("umbra/v1/mention" || scope_id || member_key)[0..16]`
/// (`WIR-174`).
pub fn mention_id(scope_id: &[u8; 32], member_key: &[u8; 32]) -> [u8; 16] {
    truncate(sha3_256(&[labels::MENTION, scope_id, member_key]))
}

fn truncate(full: [u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Some(head) = full.get(..16) {
        out.copy_from_slice(head);
    }
    out
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

    fn plain() -> RichRecord<'static> {
        RichRecord {
            reply_target: [0; 16],
            thread_root: [0; 16],
            forward_depth: 0,
            mentions: Vec::new(),
            inner_kind: AppKind::Text,
            inner_body: b"hi",
        }
    }

    #[test]
    fn the_five_cases_of_wir_203_round_trip() {
        let mut out = [0u8; 400];
        let reply = RichRecord {
            reply_target: [1; 16],
            ..plain()
        };
        let threaded = RichRecord {
            reply_target: [1; 16],
            thread_root: [2; 16],
            ..plain()
        };
        let mentions = RichRecord {
            mentions: (0..16u8).map(|i| [i; 16]).collect(),
            ..plain()
        };
        for (rec, channel) in [
            (plain(), Channel::Pairwise),
            (reply, Channel::Pairwise),
            (threaded, Channel::Group),
            (mentions, Channel::Group),
        ] {
            let n = rec.encode(channel, &mut out).unwrap();
            assert_eq!(n, rec.len());
            assert_eq!(RichRecord::parse(&out[..n], channel).unwrap(), rec);
        }
        assert_eq!(crate::bucket::Bucket::B0.text_default_chunk() - FIXED, 115);
    }

    #[test]
    fn the_rejections_of_wir_204_hold() {
        let mut out = [0u8; 400];
        let nested = RichRecord {
            inner_kind: AppKind::Rich,
            ..plain()
        };
        assert!(nested.encode(Channel::Group, &mut out).is_err());
        let many = RichRecord {
            mentions: (0..17u8).map(|i| [i; 16]).collect(),
            ..plain()
        };
        assert!(many.encode(Channel::Group, &mut out).is_err());
        let repeated = RichRecord {
            mentions: vec![[1; 16], [1; 16]],
            ..plain()
        };
        assert!(repeated.encode(Channel::Group, &mut out).is_err());
        let out_of_order = RichRecord {
            mentions: vec![[2; 16], [1; 16]],
            ..plain()
        };
        assert!(out_of_order.encode(Channel::Group, &mut out).is_err());
        let mention_pairwise = RichRecord {
            mentions: vec![[1; 16]],
            ..plain()
        };
        assert!(mention_pairwise
            .encode(Channel::Pairwise, &mut out)
            .is_err());
        let root_pairwise = RichRecord {
            reply_target: [1; 16],
            thread_root: [2; 16],
            ..plain()
        };
        assert!(root_pairwise.encode(Channel::Pairwise, &mut out).is_err());
        let root_no_reply = RichRecord {
            thread_root: [2; 16],
            ..plain()
        };
        assert!(root_no_reply.encode(Channel::Group, &mut out).is_err());
        let n = plain().encode(Channel::Group, &mut out).unwrap();
        out[0] = 0x01;
        assert!(RichRecord::parse(&out[..n], Channel::Group).is_err());
        out[0] = 0x02;
        assert!(RichRecord::parse(&out[..n + 1], Channel::Group).is_err());
        assert_ne!(
            mention_id(&[1; 32], &[2; 32]),
            mention_id(&[3; 32], &[2; 32])
        );
    }

    #[test]
    fn an_inner_body_holds_the_rules_of_its_kind() {
        let mut out = [0u8; 400];
        // WIR-259: an inner text that is not UTF-8, from a sender and from
        // a peer.
        let bad_text = RichRecord {
            inner_body: &[0xFF],
            ..plain()
        };
        assert!(bad_text.encode(Channel::Group, &mut out).is_err());
        let n = plain().encode(Channel::Group, &mut out).unwrap();
        out[n - 1] = 0xFF;
        assert!(RichRecord::parse(&out[..n], Channel::Group).is_err());
        assert!(RichRecord::parse(&out[..n], Channel::Pairwise).is_err());
        // WIR-362: an inner verification commit of a wrong length.
        let short_commit = RichRecord {
            inner_kind: AppKind::VerifyCommit,
            inner_body: &[0; 63],
            ..plain()
        };
        assert!(short_commit.encode(Channel::Pairwise, &mut out).is_err());
        // A queue address is a record of a pairwise channel alone.
        let address = RichRecord {
            inner_kind: AppKind::QueueAddress,
            inner_body: &[0; crate::address::LEN],
            ..plain()
        };
        assert!(address.encode(Channel::Group, &mut out).is_err());
        // WIR-163: a wrapper carries no control record.
        let control = RichRecord {
            inner_kind: AppKind::GroupControl,
            ..plain()
        };
        assert!(control.encode(Channel::Group, &mut out).is_err());
    }
}
