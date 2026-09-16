//! The reaction, the typing indicator, the receipt, and the conversation
//! timer of Part 6 §6.6.8 and §6.6.9.

use alloc::vec::Vec;

use crate::{
    app::strictly_increasing,
    codec::{Reader, Writer},
    Error,
};

/// `REACTION_MAX_BYTES`.
pub const REACTION_MAX_BYTES: usize = 64;
/// `RECEIPT_BATCH_MAX`, from Part 3 §3.5.4.
pub const RECEIPT_BATCH_MAX: usize = 9;
/// `TIMER_VALUES` of Part 7 §7.8, in seconds.
pub const TIMER_VALUES: [u32; 9] = [
    0, 30, 300, 3_600, 28_800, 86_400, 604_800, 2_419_200, 7_776_000,
];

/// The action of a reaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReactionAction {
    /// Add the reaction.
    Add = 0x01,
    /// Remove it.
    Remove = 0x02,
}

/// A reaction to one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionBody<'a> {
    /// The `msg_id` the reaction names.
    pub target: [u8; 16],
    /// The action.
    pub action: ReactionAction,
    /// The emoji, 1 to `REACTION_MAX_BYTES` bytes of UTF-8.
    pub emoji: &'a str,
}

impl<'a> ReactionBody<'a> {
    /// Writes the body.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.emoji.is_empty() || self.emoji.len() > REACTION_MAX_BYTES {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.target)?;
        w.u8(self.action as u8)?;
        w.u8(u8::try_from(self.emoji.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.emoji.as_bytes())?;
        Ok(w.position())
    }

    /// Reads a body (`WIR-276` to `WIR-279`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let target = r.array()?;
        let action = match r.u8()? {
            0x01 => ReactionAction::Add,
            0x02 => ReactionAction::Remove,
            _ => return Err(Error::Malformed),
        };
        let len = usize::from(r.u8()?);
        if len == 0 || len > REACTION_MAX_BYTES {
            return Err(Error::Malformed);
        }
        let emoji = core::str::from_utf8(r.take(len)?).map_err(|_| Error::Malformed)?;
        r.finish()?;
        Ok(ReactionBody {
            target,
            action,
            emoji,
        })
    }
}

/// The state of a typing indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TypingState {
    /// Typing started.
    Started = 0x01,
    /// Typing stopped.
    Stopped = 0x02,
}

impl TypingState {
    /// Writes the 2-byte body.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(self as u8)?;
        Ok(w.position())
    }

    /// Reads a body (`WIR-283`, `WIR-284`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let state = match r.u8()? {
            0x01 => TypingState::Started,
            0x02 => TypingState::Stopped,
            _ => return Err(Error::Malformed),
        };
        r.finish()?;
        Ok(state)
    }
}

/// A delivery receipt or a read receipt over a batch of targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptBody {
    /// The targets, in strictly increasing byte order.
    pub targets: Vec<[u8; 16]>,
}

impl ReceiptBody {
    fn check(&self) -> Result<(), Error> {
        if self.targets.is_empty()
            || self.targets.len() > RECEIPT_BATCH_MAX
            || !strictly_increasing(&self.targets)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Writes the body.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(u8::try_from(self.targets.len()).map_err(|_| Error::Malformed)?)?;
        for t in &self.targets {
            w.put(t)?;
        }
        Ok(w.position())
    }

    /// Reads a body (`WIR-288` to `WIR-291`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let count = usize::from(r.u8()?);
        if count == 0 || count > RECEIPT_BATCH_MAX {
            return Err(Error::Malformed);
        }
        let mut targets = Vec::with_capacity(count);
        for _ in 0..count {
            targets.push(r.array()?);
        }
        r.finish()?;
        let out = ReceiptBody { targets };
        out.check()?;
        Ok(out)
    }
}

/// The conversation timer, one value of `TIMER_VALUES`.
pub fn encode_timer(seconds: u32, out: &mut [u8]) -> Result<usize, Error> {
    if !TIMER_VALUES.contains(&seconds) {
        return Err(Error::Malformed);
    }
    let mut w = Writer::new(out);
    w.u8(0x01)?;
    w.u32(seconds)?;
    Ok(w.position())
}

/// Reads a timer (`WIR-202`).
pub fn parse_timer(bytes: &[u8]) -> Result<u32, Error> {
    let mut r = Reader::new(bytes);
    if r.u8()? != 0x01 {
        return Err(Error::Malformed);
    }
    let seconds = r.u32()?;
    r.finish()?;
    if TIMER_VALUES.contains(&seconds) {
        Ok(seconds)
    } else {
        Err(Error::Malformed)
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
    use alloc::{string::String, vec};

    #[test]
    fn the_reaction_holds_its_bounds() {
        let mut out = [0u8; 100];
        let r = ReactionBody {
            target: [1; 16],
            action: ReactionAction::Add,
            emoji: "👍",
        };
        let n = r.encode(&mut out).unwrap();
        assert_eq!(n, 19 + 4);
        assert_eq!(ReactionBody::parse(&out[..n]).unwrap(), r);
        let long: String = "a".repeat(64);
        let max = ReactionBody {
            emoji: &long,
            ..r.clone()
        };
        let n = max.encode(&mut out).unwrap();
        assert_eq!(n, 83);
        let over: String = "a".repeat(65);
        assert!(ReactionBody {
            emoji: &over,
            ..r.clone()
        }
        .encode(&mut out)
        .is_err());
        out[17] = 0x03;
        assert!(ReactionBody::parse(&out[..n]).is_err());
    }

    #[test]
    fn the_typing_and_the_receipt_and_the_timer_hold_their_sets() {
        let mut out = [0u8; 200];
        assert_eq!(TypingState::Started.encode(&mut out).unwrap(), 2);
        assert_eq!(TypingState::parse(&out[..2]).unwrap(), TypingState::Started);
        out[1] = 0x00;
        assert!(TypingState::parse(&out[..2]).is_err());
        let receipt = ReceiptBody {
            targets: (0..9u8).map(|i| [i; 16]).collect(),
        };
        let n = receipt.encode(&mut out).unwrap();
        assert_eq!(n, 146);
        assert_eq!(ReceiptBody::parse(&out[..n]).unwrap(), receipt);
        assert!(ReceiptBody {
            targets: (0..10u8).map(|i| [i; 16]).collect()
        }
        .encode(&mut out)
        .is_err());
        assert!(ReceiptBody {
            targets: vec![[2; 16], [1; 16]]
        }
        .encode(&mut out)
        .is_err());
        assert!(ReceiptBody {
            targets: Vec::new()
        }
        .encode(&mut out)
        .is_err());
        for v in TIMER_VALUES {
            let n = encode_timer(v, &mut out).unwrap();
            assert_eq!(parse_timer(&out[..n]).unwrap(), v);
        }
        assert!(encode_timer(4_337, &mut out).is_err());
    }
}
