//! The table MAC of Part 4 §4.6: an XOR accumulator of keyed row tags
//! under a key from the at-rest master key, updated at each commit batch
//! and verified at the unlock.

use umbra_crypto::{
    hkdf::Hkdf,
    hmac::{digest::KeyInit, Hmac, Mac},
    labels,
    secret::Secret,
    sha3::Sha3_256,
};

use crate::Error;

/// `K_tab`, derived from `K_store` and never stored (`IDN-034`, `IDN-035`).
pub struct TableKey(Secret<32>);

impl TableKey {
    /// Derives the key from the at-rest master key.
    pub fn derive(store_key: &Secret<32>) -> Self {
        let kdf = Hkdf::<Sha3_256>::new(None, store_key.expose());
        let mut key = Secret::<32>::zeroed();
        let _ = kdf.expand(labels::TABLE_MAC, key.expose_mut());
        TableKey(key)
    }

    fn mac(&self) -> Hmac<Sha3_256> {
        Hmac::<Sha3_256>::new_from_slice(self.0.expose())
            .unwrap_or_else(|_| Hmac::<Sha3_256>::new(&Default::default()))
    }

    /// `row_tag_i` over the record tag of a live row (`IDN-066`).
    pub fn row_tag(&self, table_id: &[u8], row_id: &[u8], record_tag: &[u8; 16]) -> [u8; 32] {
        let mut mac = self.mac();
        mac.update(&[0x01]);
        mac.update(table_id);
        mac.update(row_id);
        mac.update(record_tag);
        mac.finalize().into_bytes().into()
    }

    /// `row_tag_i` of a store of record version `0x02`. The tag reads the
    /// owner column too. Thus a scan finds a row that a party with the file
    /// moved to another owner or hid from each owner (`IDN-033`, Part 14
    /// `IMP-121`). `table_id` holds the version after the table. The owner
    /// flag is `0x01` with the owner, or `0x00` with none.
    pub fn row_tag_owned(
        &self,
        table_id: &[u8],
        row_id: &[u8],
        owner: Option<&[u8]>,
        record_tag: &[u8; 16],
    ) -> [u8; 32] {
        let mut mac = self.mac();
        mac.update(&[0x01]);
        mac.update(table_id);
        mac.update(row_id);
        match owner {
            Some(owner) => {
                mac.update(&[0x01]);
                mac.update(owner);
            }
            None => mac.update(&[0x00]),
        }
        mac.update(record_tag);
        mac.finalize().into_bytes().into()
    }

    /// `table_mac` over the accumulator.
    pub fn table_mac(
        &self,
        table_id: &[u8],
        row_count: u64,
        commit_counter: u64,
        accum: &[u8; 32],
    ) -> [u8; 32] {
        let mut mac = self.mac();
        mac.update(&[0x02]);
        mac.update(table_id);
        mac.update(&row_count.to_be_bytes());
        mac.update(&commit_counter.to_be_bytes());
        mac.update(accum);
        mac.finalize().into_bytes().into()
    }
}

/// The MAC state of one table, updated incrementally (`IDN-068`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableState {
    accum: [u8; 32],
    row_count: u64,
    commit_counter: u64,
}

fn xor_into(dst: &mut [u8; 32], src: &[u8; 32]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

impl Default for TableState {
    fn default() -> Self {
        Self::new()
    }
}

impl TableState {
    /// An empty table.
    pub const fn new() -> Self {
        TableState {
            accum: [0; 32],
            row_count: 0,
            commit_counter: 0,
        }
    }

    /// Restores a state the client stored beside the table.
    pub const fn restore(accum: [u8; 32], row_count: u64, commit_counter: u64) -> Self {
        TableState {
            accum,
            row_count,
            commit_counter,
        }
    }

    /// The stored fields.
    pub fn fields(&self) -> ([u8; 32], u64, u64) {
        (self.accum, self.row_count, self.commit_counter)
    }

    /// A row entered the table.
    pub fn insert(&mut self, row_tag: &[u8; 32]) {
        xor_into(&mut self.accum, row_tag);
        self.row_count = self.row_count.saturating_add(1);
    }

    /// A row changed: the old tag leaves and the new one enters.
    pub fn update(&mut self, old_tag: &[u8; 32], new_tag: &[u8; 32]) {
        xor_into(&mut self.accum, old_tag);
        xor_into(&mut self.accum, new_tag);
    }

    /// A row left the table.
    pub fn remove(&mut self, row_tag: &[u8; 32]) {
        xor_into(&mut self.accum, row_tag);
        self.row_count = self.row_count.saturating_sub(1);
    }

    /// Ends a commit batch and returns the MAC to store (`IDN-036`).
    pub fn commit(&mut self, key: &TableKey, table_id: &[u8]) -> [u8; 32] {
        self.commit_counter = self.commit_counter.saturating_add(1);
        key.table_mac(table_id, self.row_count, self.commit_counter, &self.accum)
    }

    /// The MAC of the state as it is, with no commit.
    pub fn mac(&self, key: &TableKey, table_id: &[u8]) -> [u8; 32] {
        key.table_mac(table_id, self.row_count, self.commit_counter, &self.accum)
    }

    /// Verifies the stored MAC at the unlock (`IDN-038`), without a scan.
    pub fn verify(&self, key: &TableKey, table_id: &[u8], stored: &[u8; 32]) -> Result<(), Error> {
        let expected = key.table_mac(table_id, self.row_count, self.commit_counter, &self.accum);
        if umbra_crypto::ct_eq(&expected, stored) {
            Ok(())
        } else {
            Err(Error::Unverified)
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

    #[test]
    fn a_rollback_of_one_row_changes_the_mac() {
        let key = TableKey::derive(&Secret::new([1; 32]));
        let mut state = TableState::new();
        let t1 = key.row_tag(b"messages", b"row-1", &[1; 16]);
        let t2 = key.row_tag(b"messages", b"row-2", &[2; 16]);
        state.insert(&t1);
        state.insert(&t2);
        let mac = state.commit(&key, b"messages");
        state.verify(&key, b"messages", &mac).unwrap();
        // The same rows in the other order give the same accumulator.
        let mut other = TableState::new();
        other.insert(&t2);
        other.insert(&t1);
        other.commit(&key, b"messages");
        assert_eq!(other.fields().0, state.fields().0);
        // A row rolled back to an earlier ciphertext changes the MAC.
        let t1_old = key.row_tag(b"messages", b"row-1", &[9; 16]);
        let mut rolled = state.clone();
        rolled.update(&t1, &t1_old);
        assert!(rolled.verify(&key, b"messages", &mac).is_err());
        // A removed row changes the count and the MAC.
        state.remove(&t2);
        assert!(state.verify(&key, b"messages", &mac).is_err());
        let (accum, rows, commits) = state.fields();
        let restored = TableState::restore(accum, rows, commits);
        assert_eq!(restored, state);
    }

    #[test]
    fn a_row_tag_of_the_later_version_reads_the_owner() {
        let key = TableKey::derive(&Secret::new([1; 32]));
        let table = [0x01, 0x02];
        let with = key.row_tag_owned(&table, &[3; 16], Some(&[4; 16]), &[1; 16]);
        assert_ne!(
            with,
            key.row_tag_owned(&table, &[3; 16], Some(&[5; 16]), &[1; 16])
        );
        assert_ne!(with, key.row_tag_owned(&table, &[3; 16], None, &[1; 16]));
        // The form of the earlier version gives another tag for one row.
        assert_ne!(
            key.row_tag_owned(&table, &[3; 16], None, &[1; 16]),
            key.row_tag(&[0x01], &[3; 16], &[1; 16])
        );
        let state = TableState::restore([7; 32], 2, 9);
        let mac = state.mac(&key, &table);
        state.verify(&key, &table, &mac).unwrap();
        assert!(state.verify(&key, &[0x01], &mac).is_err());
    }
}
