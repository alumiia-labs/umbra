//! The poll and the poll vote of Part 6 §6.6.6.

use alloc::vec::Vec;

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// `POLL_OPTION_MAX`.
pub const OPTION_MAX: usize = 12;
/// `POLL_QUESTION_MAX`, bytes of `question`.
pub const QUESTION_MAX: usize = 200;
/// `POLL_OPTION_TEXT_MAX`, bytes of one option.
pub const OPTION_TEXT_MAX: usize = 100;

/// A poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poll<'a> {
    /// Bit 0 of `flags`: more than one choice.
    pub multiple: bool,
    /// Bit 1 of `flags`: hidden until close.
    pub hidden: bool,
    /// The period after the local receive time, or 0 for no close.
    pub open_seconds: u32,
    /// The question.
    pub question: &'a str,
    /// 2 to `OPTION_MAX` options.
    pub options: Vec<&'a str>,
}

impl<'a> Poll<'a> {
    fn check(&self) -> Result<(), Error> {
        if self.question.len() > QUESTION_MAX
            || self.options.len() < 2
            || self.options.len() > OPTION_MAX
            || self
                .options
                .iter()
                .any(|o| o.is_empty() || o.len() > OPTION_TEXT_MAX)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Writes the poll.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(u8::from(self.multiple) | (u8::from(self.hidden) << 1))?;
        w.u32(self.open_seconds)?;
        w.u8(u8::try_from(self.question.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.question.as_bytes())?;
        w.u8(u8::try_from(self.options.len()).map_err(|_| Error::Malformed)?)?;
        for o in &self.options {
            w.u8(u8::try_from(o.len()).map_err(|_| Error::Malformed)?)?;
            w.put(o.as_bytes())?;
        }
        Ok(w.position())
    }

    /// Reads a poll (`WIR-180` to `WIR-182`, `WIR-274`, `WIR-275`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let flags = r.u8()?;
        if flags & !0x03 != 0 {
            return Err(Error::Malformed);
        }

        let open_seconds = r.u32()?;
        let q_len = usize::from(r.u8()?);
        let question = core::str::from_utf8(r.take(q_len)?).map_err(|_| Error::Malformed)?;

        let option_count = usize::from(r.u8()?);
        let mut options = Vec::with_capacity(option_count.min(OPTION_MAX));
        for _ in 0..option_count {
            let len = usize::from(r.u8()?);
            options.push(core::str::from_utf8(r.take(len)?).map_err(|_| Error::Malformed)?);
        }
        r.finish()?;

        let out = Poll {
            multiple: flags & 0x01 != 0,
            hidden: flags & 0x02 != 0,
            open_seconds,
            question,
            options,
        };
        out.check()?;
        Ok(out)
    }
}

/// A vote on a poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollVote {
    /// The `msg_id` of the poll.
    pub target: [u8; 16],
    /// The option indices, in strictly increasing order.
    pub choices: Vec<u8>,
}

impl PollVote {
    fn check(&self, multiple: bool, option_count: usize) -> Result<(), Error> {
        if self.choices.is_empty()
            || self.choices.len() > OPTION_MAX
            || (!multiple && self.choices.len() > 1)
            || self.choices.windows(2).any(|w| match w {
                [a, b] => a >= b,
                _ => false,
            })
            || self.choices.iter().any(|c| usize::from(*c) >= option_count)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Writes the vote against the poll it answers.
    pub fn encode(&self, poll: &Poll<'_>, out: &mut [u8]) -> Result<usize, Error> {
        self.check(poll.multiple, poll.options.len())?;
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.target)?;
        w.u8(u8::try_from(self.choices.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.choices)?;
        Ok(w.position())
    }

    /// Reads a vote against the poll it answers (`WIR-183` to `WIR-186`).
    pub fn parse(bytes: &[u8], poll: &Poll<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let target = r.array()?;
        let count = usize::from(r.u8()?);
        let choices = r.take(count)?.to_vec();
        r.finish()?;

        let out = PollVote { target, choices };
        out.check(poll.multiple, poll.options.len())?;
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
    use alloc::{string::String, vec};

    fn poll() -> Poll<'static> {
        Poll {
            multiple: true,
            hidden: false,
            open_seconds: 3_600,
            question: "which",
            options: vec!["a", "b", "c"],
        }
    }

    #[test]
    fn a_poll_and_a_vote_round_trip_at_the_bounds() {
        let mut out = [0u8; 2_000];
        let n = poll().encode(&mut out).unwrap();
        assert_eq!(Poll::parse(&out[..n]).unwrap(), poll());

        let q: String = "q".repeat(QUESTION_MAX);
        let o: String = "o".repeat(OPTION_TEXT_MAX);
        let big = Poll {
            multiple: false,
            hidden: true,
            open_seconds: 0,
            question: &q,
            options: vec![&o; OPTION_MAX],
        };
        let n = big.encode(&mut out).unwrap();
        assert_eq!(n, 1_420);
        assert_eq!(Poll::parse(&out[..n]).unwrap(), big);

        let vote = PollVote {
            target: [1; 16],
            choices: vec![0, 2],
        };
        let n = vote.encode(&poll(), &mut out).unwrap();
        assert_eq!(n, 20);
        assert_eq!(PollVote::parse(&out[..n], &poll()).unwrap(), vote);
    }

    #[test]
    fn the_rejections_of_wir_206_hold() {
        let mut out = [0u8; 2_000];
        let one = Poll {
            options: vec!["a"],
            ..poll()
        };
        assert!(one.encode(&mut out).is_err());

        let long_q = "q".repeat(201);
        let bad = Poll {
            question: &long_q,
            ..poll()
        };
        assert!(bad.encode(&mut out).is_err());

        let empty = Poll {
            options: vec!["a", ""],
            ..poll()
        };
        assert!(empty.encode(&mut out).is_err());

        for choices in [vec![3], vec![1, 1], vec![2, 1], vec![]] {
            let v = PollVote {
                target: [1; 16],
                choices,
            };
            assert!(v.encode(&poll(), &mut out).is_err());
        }

        let single = Poll {
            multiple: false,
            ..poll()
        };
        let v = PollVote {
            target: [1; 16],
            choices: vec![0, 1],
        };
        assert!(v.encode(&single, &mut out).is_err());

        let n = poll().encode(&mut out).unwrap();
        out[1] = 0x04;
        assert!(Poll::parse(&out[..n]).is_err());
    }
}
