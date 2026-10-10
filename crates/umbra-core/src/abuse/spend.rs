//! The relay-local spend set of Part 13 §13.7: the nonces of the current
//! epoch and of the one before it, and nothing global.

use alloc::collections::BTreeSet;

use crate::Error;

/// The spent nonces of one verifier over two epochs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpendSet {
    epochs: [Option<(u32, BTreeSet<[u8; 32]>)>; 2],
}

impl SpendSet {
    /// Spends `nonce` of `token_epoch` at the current `epoch`, or rejects
    /// a repeat or an epoch outside the two accepted (`ABU-080`,
    /// `ABU-081`).
    pub fn spend(&mut self, epoch: u32, token_epoch: u32, nonce: [u8; 32]) -> Result<(), Error> {
        if token_epoch != epoch && token_epoch != epoch.wrapping_sub(1) {
            return Err(Error::Stale);
        }
        // A new current epoch retires the set two epochs back. A retired
        // slot holds no epoch, thus two slots never hold the same one. The
        // slot of the next epoch stays (`ABU-114`). A clock that steps back
        // over an epoch boundary must not let the tokens of that epoch spend
        // a second time. A slot further ahead retires, thus a clock that was
        // far ahead for a time does not hold both slots until its epoch
        // comes.
        let live = epoch.saturating_sub(1)..=epoch.saturating_add(1);
        for slot in &mut self.epochs {
            if slot.as_ref().is_some_and(|(held, _)| !live.contains(held)) {
                *slot = None;
            }
        }
        let held = self
            .epochs
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|(held, _)| *held == token_epoch));
        let index = held
            .or_else(|| self.epochs.iter().position(Option::is_none))
            .ok_or(Error::Stale)?;
        let (_, set) = self
            .epochs
            .get_mut(index)
            .ok_or(Error::Stale)?
            .get_or_insert_with(|| (token_epoch, BTreeSet::new()));
        if !set.insert(nonce) {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Takes back a nonce of `token_epoch` that a store kept, at the start
    /// of a run (`ABU-114`). The store gives them in the order of their
    /// epochs, and a repeat spends nothing more.
    pub fn restore(&mut self, token_epoch: u32, nonce: [u8; 32]) {
        let _ = self.spend(token_epoch, token_epoch, nonce);
    }

    /// The nonces held.
    pub fn len(&self) -> usize {
        self.epochs.iter().flatten().map(|(_, s)| s.len()).sum()
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

    #[test]
    fn a_retired_slot_takes_no_second_label_of_the_same_epoch() {
        let mut set = SpendSet::default();
        set.spend(20, 20, [1; 32]).unwrap();
        set.spend(20, 19, [2; 32]).unwrap();
        set.spend(21, 20, [3; 32]).unwrap();
        set.spend(21, 21, [4; 32]).unwrap();
        // The first spend of epoch 22 is a token of 21: the slot of 20
        // retires, and the nonce of 21 stays spent.
        assert_eq!(set.spend(22, 21, [4; 32]), Err(Error::Stale));
        set.spend(22, 22, [5; 32]).unwrap();
        assert_eq!(set.spend(22, 22, [5; 32]), Err(Error::Stale));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_clock_that_steps_back_keeps_the_nonces_of_the_later_epoch() {
        let mut set = SpendSet::default();
        set.spend(11, 11, [1; 32]).unwrap();
        set.spend(11, 10, [2; 32]).unwrap();
        // The clock reads epoch 10 for a time. Both slots are in use, thus a
        // token of epoch 9 finds no slot, and the set refuses it.
        set.spend(10, 10, [3; 32]).unwrap();
        assert_eq!(set.spend(10, 9, [4; 32]), Err(Error::Stale));
        // The clock is right again, and the nonce of epoch 11 stays spent.
        assert_eq!(set.spend(11, 11, [1; 32]), Err(Error::Stale));
        assert_eq!(set.spend(11, 10, [2; 32]), Err(Error::Stale));
        assert_eq!(set.len(), 3);
        // A slot more than one epoch ahead of the clock retires.
        let mut ahead = SpendSet::default();
        ahead.spend(50, 50, [1; 32]).unwrap();
        ahead.spend(50, 49, [2; 32]).unwrap();
        ahead.spend(11, 11, [3; 32]).unwrap();
        ahead.spend(11, 10, [4; 32]).unwrap();
        assert_eq!(ahead.len(), 2);
    }
}
