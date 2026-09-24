//! The relay-local spend set of Part 13 §13.7: the nonces of the current
//! epoch and of the one before it, and nothing global.

use alloc::collections::BTreeSet;

use crate::Error;

/// The spent nonces of one verifier over two epochs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpendSet {
    epochs: [(u32, BTreeSet<[u8; 32]>); 2],
}

impl SpendSet {
    /// Spends `nonce` of `token_epoch` at the current `epoch`, or rejects
    /// a repeat or an epoch outside the two accepted (`ABU-080`,
    /// `ABU-081`).
    pub fn spend(&mut self, epoch: u32, token_epoch: u32, nonce: [u8; 32]) -> Result<(), Error> {
        if token_epoch != epoch && token_epoch != epoch.wrapping_sub(1) {
            return Err(Error::Stale);
        }
        // A new current epoch retires the set two epochs back.
        for (held_epoch, set) in &mut self.epochs {
            if *held_epoch != epoch && *held_epoch != epoch.wrapping_sub(1) {
                set.clear();
                *held_epoch = token_epoch;
            }
        }
        let slot = match self.epochs.iter_mut().find(|(e, _)| *e == token_epoch) {
            Some(slot) => slot,
            None => self
                .epochs
                .iter_mut()
                .find(|(_, set)| set.is_empty())
                .ok_or(Error::Stale)?,
        };
        slot.0 = token_epoch;
        if !slot.1.insert(nonce) {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// The nonces held.
    pub fn len(&self) -> usize {
        self.epochs.iter().map(|(_, s)| s.len()).sum()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_spends_once_over_two_epochs() {
        let mut set = SpendSet::default();
        set.spend(10, 10, [1; 32]).unwrap();
        assert_eq!(set.spend(10, 10, [1; 32]), Err(Error::Stale));
        set.spend(10, 9, [1; 32]).unwrap();
        assert_eq!(set.spend(10, 8, [2; 32]), Err(Error::Stale));
        assert_eq!(set.spend(10, 11, [2; 32]), Err(Error::Stale));
        assert_eq!(set.len(), 2);
        set.spend(11, 11, [3; 32]).unwrap();
        assert_eq!(set.spend(11, 10, [1; 32]), Err(Error::Stale));
        set.spend(12, 12, [4; 32]).unwrap();
        set.spend(12, 11, [1; 32]).unwrap();
        assert_eq!(set.spend(12, 11, [3; 32]), Err(Error::Stale));
        assert!(!set.is_empty());
    }
}
