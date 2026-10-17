//! The wake key of Part 8 §8.4.1: what a locked client holds outside
//! `K_store` to open a push blob (`NTF-135`, `NTF-136`).
//!
//! An open client writes the table below, and the platform seals it under
//! a keystore key that needs no passphrase. A locked client opens a blob
//! with it and learns which conversation waits, and no message: the record
//! stays at the relay until the unlock.
//!
//! ```text
//! WakeTable {
//!     version     u8                 // 0x02
//!     root_count  u16
//!     roots       [root_count][32]u8 // each k_ntf_root that a binding uses
//!     alias_count u16
//!     aliases     [alias_count] { queue_alias [16]u8, conversation [16]u8 }
//!     muted_count u16
//!     muted       [muted_count] { queue_alias [16]u8, until u64 }
//! }
//! ```
//!
//! A conversation of 16 zero bytes names a queue of no conversation, as a
//! rendezvous queue: its alert names none. A conversation of [`WAKE_SILENT`]
//! names a queue that raises no alert. A muted alias raises no alert before
//! its `until`, in seconds of the Unix time, since a locked client cannot
//! write the table again at the end of a mute. A table of version `0x01`
//! has no `muted` part.

use alloc::vec::Vec;

use umbra_crypto::{secret::Secret, zeroize::Zeroize};
use umbra_wire::codec::{Reader, Writer};

use super::blob::{epoch_of_blob, Plain, Receiver, FLAG_URGENT};
use crate::Error;

/// The roots and the aliases that one table holds at most.
pub const WAKE_ENTRIES_MAX: usize = 4_096;

/// The conversation of a queue that raises no alert. No conversation has
/// this identifier: an identifier is a keyed hash.
pub const WAKE_SILENT: [u8; 16] = [0xFF; 16];

/// What a wake table holds. The roots open each blob of the device, thus
/// the drop wipes them and no debug form shows them.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct WakeTable {
    /// Each `k_ntf_root` that a binding of this device uses.
    pub roots: Vec<[u8; 32]>,
    /// Each queue alias, with the conversation of its queue.
    pub aliases: Vec<([u8; 16], [u8; 16])>,
    /// Each queue alias whose conversation is muted, with the end of the
    /// mute in seconds of the Unix time.
    pub muted: Vec<([u8; 16], u64)>,
}

impl Drop for WakeTable {
    fn drop(&mut self) {
        self.roots.zeroize();
    }
}

impl core::fmt::Debug for WakeTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WakeTable")
            .field("roots", &self.roots.len())
            .field("aliases", &self.aliases.len())
            .field("muted", &self.muted.len())
            .finish()
    }
}

/// What a locked client learns from one blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Woken {
    /// The blob opened: the conversation of its queue, or none, the count of
    /// records that wait, and whether the sender marked it urgent.
    Opened {
        /// The conversation, or none for a queue of no conversation.
        conversation: Option<[u8; 16]>,
        /// The records that wait at the relay, saturated at 255.
        waiting: u8,
        /// Bit 0 of the flags.
        urgent: bool,
    },
    /// The blob names an epoch outside the window, and no open ran
    /// (`NTF-076`). It counts as no failure.
    OutsideWindow,
    /// No root of the table opens the blob: a failure of `NTF-077`.
    Failed,
}

impl WakeTable {
    /// The encoded table.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.roots.len() > WAKE_ENTRIES_MAX
            || self.aliases.len() > WAKE_ENTRIES_MAX
            || self.muted.len() > WAKE_ENTRIES_MAX
        {
            return Err(Error::Malformed);
        }

        let size =
            1 + 2 + self.roots.len() * 32 + 2 + self.aliases.len() * 32 + 2 + self.muted.len() * 24;
        let mut out = alloc::vec![0u8; size];
        let mut w = Writer::new(&mut out);
        w.u8(0x02)?;

        w.u16(u16::try_from(self.roots.len()).map_err(|_| Error::Malformed)?)?;
        for root in &self.roots {
            w.put(root)?;
        }

        w.u16(u16::try_from(self.aliases.len()).map_err(|_| Error::Malformed)?)?;
        for (alias, conversation) in &self.aliases {
            w.put(alias)?;
            w.put(conversation)?;
        }

        w.u16(u16::try_from(self.muted.len()).map_err(|_| Error::Malformed)?)?;
        for (alias, until) in &self.muted {
            w.put(alias)?;
            w.put(&until.to_be_bytes())?;
        }

        Ok(out)
    }

    /// Reads a table.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != 0x01 && version != 0x02 {
            return Err(Error::Malformed);
        }

        let roots_len = usize::from(r.u16()?);
        if roots_len > WAKE_ENTRIES_MAX {
            return Err(Error::Malformed);
        }
        let mut roots = Vec::with_capacity(roots_len);
        for _ in 0..roots_len {
            roots.push(r.array()?);
        }

        let aliases_len = usize::from(r.u16()?);
        if aliases_len > WAKE_ENTRIES_MAX {
            return Err(Error::Malformed);
        }
        let mut aliases = Vec::with_capacity(aliases_len);
        for _ in 0..aliases_len {
            aliases.push((r.array()?, r.array()?));
        }

        let mut muted = Vec::new();
        if version == 0x02 {
            let muted_len = usize::from(r.u16()?);
            if muted_len > WAKE_ENTRIES_MAX {
                return Err(Error::Malformed);
            }
            muted.reserve(muted_len);
            for _ in 0..muted_len {
                muted.push((r.array()?, u64::from_be_bytes(r.array()?)));
            }
        }
        r.finish()?;

        Ok(WakeTable {
            roots,
            aliases,
            muted,
        })
    }

    /// Opens `blob` at `now` under each root in turn (`NTF-075`, `NTF-076`).
    /// The caller counts each `Failed` toward `NTF_FAIL_MAX`, and an
    /// `Opened` sets the count back (`NTF-077` to `NTF-079`).
    pub fn open(&self, blob: &[u8], now: u64) -> Result<Woken, Error> {
        let epoch = epoch_of_blob(blob)?;
        if !Receiver::in_window(epoch, now) {
            return Ok(Woken::OutsideWindow);
        }

        let opened: Option<Plain> = self
            .roots
            .iter()
            .find_map(|root| Receiver::new(Secret::new(*root)).open(blob, now).ok());
        let Some(plain) = opened else {
            return Ok(Woken::Failed);
        };

        // A muted queue names the silent conversation until its mute ends.
        let conversation = self
            .aliases
            .iter()
            .find(|(alias, _)| *alias == plain.queue_alias)
            .map(|(_, conversation)| *conversation)
            .filter(|conversation| *conversation != [0; 16])
            .map(|conversation| {
                let is_muted = self
                    .muted
                    .iter()
                    .any(|(alias, until)| *alias == plain.queue_alias && now < *until);
                if is_muted {
                    WAKE_SILENT
                } else {
                    conversation
                }
            });

        Ok(Woken::Opened {
            conversation,
            waiting: plain.waiting_count,
            urgent: plain.flags & FLAG_URGENT != 0,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::notify::{blob::seal, epoch_of};

    #[test]
    fn a_locked_client_learns_the_conversation_of_a_blob_and_no_more() {
        let now = 1_700_000_000;
        let epoch = epoch_of(now);
        let plain = Plain {
            relay_idx: 1,
            queue_alias: [7; 16],
            waiting_count: 2,
            relay_ts: 5,
            flags: FLAG_URGENT,
        };
        let blob = seal(&Secret::new([3; 32]), epoch, [4; 24], &plain).unwrap();
        let table = WakeTable {
            roots: alloc::vec![[9; 32], [3; 32]],
            aliases: alloc::vec![([7; 16], [5; 16]), ([8; 16], [0; 16])],
            muted: alloc::vec![([8; 16], u64::MAX)],
        };
        let table = WakeTable::parse(&table.encode().unwrap()).unwrap();

        assert_eq!(
            table.open(&blob, now).unwrap(),
            Woken::Opened {
                conversation: Some([5; 16]),
                waiting: 2,
                urgent: true,
            }
        );

        // NTF-076: a blob of another day runs no open, and counts as no
        // failure.
        assert_eq!(
            table.open(&blob, now + 3 * 86_400).unwrap(),
            Woken::OutsideWindow
        );

        // NTF-077: no root opens it.
        let other = WakeTable {
            roots: alloc::vec![[9; 32]],
            aliases: alloc::vec![],
            muted: alloc::vec![],
        };
        assert_eq!(other.open(&blob, now).unwrap(), Woken::Failed);

        // A queue of no conversation names none.
        let unnamed = WakeTable {
            roots: alloc::vec![[3; 32]],
            aliases: alloc::vec![([7; 16], [0; 16])],
            muted: alloc::vec![],
        };
        assert!(matches!(
            unnamed.open(&blob, now).unwrap(),
            Woken::Opened {
                conversation: None,
                ..
            }
        ));

        assert!(WakeTable::parse(&[0x01, 0, 0, 0, 0, 0]).is_err());
        assert!(WakeTable::parse(&[0x03, 0, 0, 0, 0]).is_err());

        // A table of the first version holds no mute.
        assert_eq!(
            WakeTable::parse(&[0x01, 0, 0, 0, 0]).unwrap(),
            WakeTable::default()
        );
    }

    #[test]
    fn a_muted_queue_raises_no_alert_before_the_end_of_its_mute() {
        let now = 1_700_000_000;
        let plain = Plain {
            relay_idx: 1,
            queue_alias: [7; 16],
            waiting_count: 1,
            relay_ts: 5,
            flags: 0,
        };
        let blob = seal(&Secret::new([3; 32]), epoch_of(now), [4; 24], &plain).unwrap();
        let table = WakeTable {
            roots: alloc::vec![[3; 32]],
            aliases: alloc::vec![([7; 16], [5; 16])],
            muted: alloc::vec![([7; 16], now + 60)],
        };
        let table = WakeTable::parse(&table.encode().unwrap()).unwrap();
        let conversation = |at| match table.open(&blob, at).unwrap() {
            Woken::Opened { conversation, .. } => conversation,
            _ => None,
        };

        // DEV-331: the mute holds while the client is locked, and it ends
        // at its time with no write of the table.
        assert_eq!(conversation(now), Some(WAKE_SILENT));
        assert_eq!(conversation(now + 60), Some([5; 16]));
    }
}
