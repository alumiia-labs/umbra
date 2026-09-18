//! The fixed 69-byte notification blob of Part 8 §8.2.2 and the calendar
//! key schedule of §8.2.3, at the queue relay that seals and at the device
//! that opens.

use umbra_crypto::{aead, hkdf::Hkdf, labels, secret::Secret, sha3::Sha3_256};
use umbra_wire::codec::{Reader, Writer};

use super::{epoch_of, NTF_FAIL_MAX};
use crate::Error;

/// The blob length.
pub const BLOB_LEN: usize = 69;
/// The plaintext length.
pub const PLAIN_LEN: usize = 24;
/// The version byte.
pub const VERSION: u8 = 0x01;
/// Bit 0 of `flags`.
pub const FLAG_URGENT: u8 = 0x01;
/// Bit 1 of `flags`.
pub const FLAG_DIGEST: u8 = 0x02;
const FLAG_RESERVED: u8 = 0xFC;

/// The plaintext of a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plain {
    /// The relay, as a device-local index.
    pub relay_idx: u16,
    /// A device-local random alias of the queue.
    pub queue_alias: [u8; 16],
    /// The records waiting, saturated at 255.
    pub waiting_count: u8,
    /// The relay clock, in seconds, truncated.
    pub relay_ts: u32,
    /// Bit 0 urgent, bit 1 digest.
    pub flags: u8,
}

impl Plain {
    fn encode(&self) -> Result<[u8; PLAIN_LEN], Error> {
        if self.flags & FLAG_RESERVED != 0 {
            return Err(Error::Malformed);
        }
        let mut out = [0u8; PLAIN_LEN];
        let mut w = Writer::new(&mut out);
        w.u16(self.relay_idx)?;
        w.put(&self.queue_alias)?;
        w.u8(self.waiting_count)?;
        w.u32(self.relay_ts)?;
        w.u8(self.flags)?;
        Ok(out)
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let out = Plain {
            relay_idx: r.u16()?,
            queue_alias: r.array()?,
            waiting_count: r.u8()?,
            relay_ts: r.u32()?,
            flags: r.u8()?,
        };
        r.finish()?;
        // A reserved bit rejects the blob (NTF-037).
        if out.flags & FLAG_RESERVED != 0 {
            return Err(Error::Malformed);
        }
        Ok(out)
    }
}

/// `k_epoch = HKDF-SHA3-256(k_ntf_root, salt = epoch_be32, info =
/// "umbra/v1/ntf")`.
pub fn epoch_key(root: &Secret<32>, epoch: u32) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(Some(&epoch.to_be_bytes()), root.expose());
    let mut key = Secret::<32>::zeroed();
    let _ = kdf.expand(labels::NTF, key.expose_mut());
    key
}

fn associated_data(epoch: u32) -> [u8; 5] {
    let mut ad = [0u8; 5];
    ad[0] = VERSION;
    if let Some(tail) = ad.get_mut(1..) {
        tail.copy_from_slice(&epoch.to_be_bytes());
    }
    ad
}

/// Seals a blob at the relay for `epoch` (`NTF-003`, `NTF-035`).
pub fn seal(
    root: &Secret<32>,
    epoch: u32,
    nonce: [u8; 24],
    plain: &Plain,
) -> Result<[u8; BLOB_LEN], Error> {
    let mut body = plain.encode()?;
    let tag = aead::seal(
        &epoch_key(root, epoch),
        &nonce,
        &associated_data(epoch),
        &mut body,
    )?;
    let mut out = [0u8; BLOB_LEN];
    let mut w = Writer::new(&mut out);
    w.u8(VERSION)?;
    w.u32(epoch)?;
    w.put(&nonce)?;
    w.put(&body)?;
    w.put(&tag)?;
    Ok(out)
}

/// The epoch a blob names, read before any open (`NTF-076`).
pub fn epoch_of_blob(blob: &[u8]) -> Result<u32, Error> {
    if blob.len() != BLOB_LEN {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(blob);
    if r.u8()? != VERSION {
        return Err(Error::Malformed);
    }
    r.u32().map_err(Error::from)
}

/// The device side: the root, and the count of consecutive failed opens.
pub struct Receiver {
    root: Secret<32>,
    failures: u32,
}

impl Receiver {
    /// A receiver over `k_ntf_root`.
    pub const fn new(root: Secret<32>) -> Self {
        Receiver { root, failures: 0 }
    }

    /// Whether `epoch` is inside the acceptance window at `now`: the epoch
    /// of the device, the one before, and the one after (`NTF-075`).
    pub fn in_window(epoch: u32, now: u64) -> bool {
        let mine = epoch_of(now);
        epoch == mine || epoch == mine.wrapping_sub(1) || epoch == mine.wrapping_add(1)
    }

    /// Opens a blob at `now`. A blob outside the window is rejected without
    /// an open; a failed open counts, and a success resets the count
    /// (`NTF-076` to `NTF-079`).
    pub fn open(&mut self, blob: &[u8], now: u64) -> Result<Plain, Error> {
        let epoch = epoch_of_blob(blob)?;
        if !Self::in_window(epoch, now) {
            return Err(Error::Stale);
        }
        let mut r = Reader::new(blob);
        let _ = r.take(5)?;
        let nonce: [u8; 24] = r.array()?;
        let mut body: [u8; PLAIN_LEN] = r.array()?;
        let tag = r.take(aead::TAG_LEN)?;
        let opened = aead::open(
            &epoch_key(&self.root, epoch),
            &nonce,
            &associated_data(epoch),
            &mut body,
            tag,
        );
        match opened {
            Ok(()) => {
                self.failures = 0;
                Plain::parse(&body)
            }
            Err(_) => {
                self.failures = self.failures.saturating_add(1);
                Err(Error::Unverified)
            }
        }
    }

    /// Whether `NTF_FAIL_MAX` consecutive opens failed, which shows the
    /// clock state and re-establishes the root (`NTF-078`, `NTF-084`).
    pub const fn clock_suspect(&self) -> bool {
        self.failures >= NTF_FAIL_MAX
    }

    /// Replaces the root after a re-establishment, and clears the count.
    pub fn reset(&mut self, root: Secret<32>) {
        self.root = root;
        self.failures = 0;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::notify::EPOCH_SECONDS;

    fn plain() -> Plain {
        Plain {
            relay_idx: 3,
            queue_alias: [7; 16],
            waiting_count: 2,
            relay_ts: 1_700_000_000,
            flags: FLAG_URGENT,
        }
    }

    #[test]
    fn a_blob_is_69_bytes_and_opens_inside_the_window_only() {
        let root = Secret::new([1; 32]);
        let now = 100 * EPOCH_SECONDS + 5;
        let epoch = epoch_of(now);
        let blob = seal(&root, epoch, [2; 24], &plain()).unwrap();
        assert_eq!(blob.len(), BLOB_LEN);
        let mut rx = Receiver::new(Secret::new([1; 32]));
        assert_eq!(rx.open(&blob, now).unwrap(), plain());
        assert_eq!(rx.open(&blob, now + EPOCH_SECONDS).unwrap(), plain());
        assert_eq!(rx.open(&blob, now - EPOCH_SECONDS).unwrap(), plain());
        assert_eq!(rx.open(&blob, now + 2 * EPOCH_SECONDS), Err(Error::Stale));
        assert!(!rx.clock_suspect());
        // A wrong root fails, and three failures show the clock state.
        let mut other = Receiver::new(Secret::new([9; 32]));
        for _ in 0..NTF_FAIL_MAX {
            assert_eq!(other.open(&blob, now), Err(Error::Unverified));
        }
        assert!(other.clock_suspect());
        other.reset(Secret::new([1; 32]));
        assert!(other.open(&blob, now).is_ok());
        assert!(!other.clock_suspect());
        // The epoch is bound: a blob re-labeled with another epoch fails.
        let mut relabeled = blob;
        relabeled[1..5].copy_from_slice(&(epoch + 1).to_be_bytes());
        assert_eq!(rx.open(&relabeled, now), Err(Error::Unverified));
        assert!(rx.open(&blob[..68], now).is_err());
    }

    #[test]
    fn a_reserved_flag_bit_is_rejected_on_both_ends() {
        let root = Secret::new([1; 32]);
        let bad = Plain {
            flags: 0x04,
            ..plain()
        };
        assert!(seal(&root, 1, [0; 24], &bad).is_err());
        let digest = Plain {
            flags: FLAG_DIGEST,
            ..plain()
        };
        let blob = seal(&root, 1, [0; 24], &digest).unwrap();
        let mut rx = Receiver::new(root);
        assert_eq!(
            rx.open(&blob, EPOCH_SECONDS + 1).unwrap().flags,
            FLAG_DIGEST
        );
        assert_ne!(
            epoch_key(&Secret::new([1; 32]), 1).expose(),
            epoch_key(&Secret::new([1; 32]), 2).expose()
        );
    }
}
