//! The record layer of the local database (Part 14 §14.6.4): one key for
//! each record from a random salt beside it, the table and the row in the
//! associated data, and the keyed surrogate that names a row.

use alloc::vec::Vec;

use umbra_crypto::{
    aead,
    hkdf::Hkdf,
    hmac::{digest::KeyInit, Hmac, Mac},
    labels,
    rand_core::CryptoRng,
    secret::Secret,
    sha3::Sha3_256,
};

use crate::Error;

/// The length of `record_salt`.
pub const SALT_LEN: usize = 16;
/// The length of a surrogate row identifier.
pub const ROW_ID_LEN: usize = 16;
/// The bytes of a sealed record around its ciphertext.
pub const OVERHEAD: usize = SALT_LEN + aead::NONCE_LEN + aead::TAG_LEN;

/// A table identifier. This type names no closed list of tables, because
/// Part 4 §4.6 binds each table that a client adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableId(pub u8);

impl TableId {
    /// The messages.
    pub const MESSAGE: TableId = TableId(0x01);
    /// The tombstones.
    pub const TOMBSTONE: TableId = TableId(0x02);
    /// The contacts.
    pub const CONTACT: TableId = TableId(0x03);
    /// The queues.
    pub const QUEUE: TableId = TableId(0x04);
    /// The verification states.
    pub const VERIFICATION: TableId = TableId(0x05);
    /// The local identity table of Part 4 §4.2.4.
    pub const LOCAL_IDENTITY: TableId = TableId(0x06);
}

/// A surrogate row identifier: a keyed hash of the natural key of the
/// row. The database indexes on it, and it shows no contact and no
/// conversation to a party without `K_store`.
pub type RowId = [u8; ROW_ID_LEN];

/// `K_row`, the key of the surrogate identifiers.
pub struct RowKey(Secret<32>);

impl RowKey {
    /// Derives the key from the at-rest master key.
    pub fn derive(store_key: &Secret<32>) -> Self {
        let kdf = Hkdf::<Sha3_256>::new(None, store_key.expose());
        let mut key = Secret::<32>::zeroed();
        // 32 bytes is below the HKDF bound, thus expand cannot fail.
        let _ = kdf.expand(labels::ROW_ID, key.expose_mut());
        RowKey(key)
    }

    /// `HMAC-SHA3-256(K_row, table_id || natural_key)[0..16]`.
    pub fn row_id(&self, table: TableId, natural_key: &[u8]) -> RowId {
        // A 32-byte key is inside the HMAC key bound, thus this cannot fail.
        let mut mac = Hmac::<Sha3_256>::new_from_slice(self.0.expose())
            .unwrap_or_else(|_| Hmac::<Sha3_256>::new(&Default::default()));
        mac.update(&[table.0]);
        mac.update(natural_key);
        let full = mac.finalize().into_bytes();
        let mut id = [0u8; ROW_ID_LEN];
        id.copy_from_slice(full.get(..ROW_ID_LEN).unwrap_or(&[0; ROW_ID_LEN]));
        id
    }
}

fn associated_data(table: TableId, row_id: &RowId) -> [u8; 1 + ROW_ID_LEN] {
    let mut ad = [0u8; 1 + ROW_ID_LEN];
    if let Some((first, rest)) = ad.split_first_mut() {
        *first = table.0;
        rest.copy_from_slice(row_id);
    }
    ad
}

fn record_key(
    store_key: &Secret<32>,
    salt: &[u8; SALT_LEN],
    table: TableId,
    row_id: &RowId,
) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(Some(salt), store_key.expose());
    let mut key = Secret::<32>::zeroed();
    // IMP-023: the label, the table, and the row, and no other input.
    let _ = kdf.expand_multi_info(
        &[labels::RECORD_KEY, &associated_data(table, row_id)],
        key.expose_mut(),
    );
    key
}

/// A record as the database holds it: `record_salt || nonce || ct || tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecord(Vec<u8>);

impl SealedRecord {
    /// Seals `plaintext` for one row, with a fresh salt and a fresh nonce
    /// from `rng` at each write (`IMP-040`).
    pub fn seal<R: CryptoRng + ?Sized>(
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; aead::NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let mut body = plaintext.to_vec();
        let key = record_key(store_key, &salt, table, row_id);
        let tag = aead::seal(&key, &nonce, &associated_data(table, row_id), &mut body)?;
        let mut out = Vec::with_capacity(OVERHEAD.saturating_add(body.len()));
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(SealedRecord(out))
    }

    /// Takes the bytes that a backend read.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < OVERHEAD {
            return Err(Error::Malformed);
        }
        Ok(SealedRecord(bytes))
    }

    /// The bytes that a backend writes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The record tag, which the table MAC reads (`IDN-066`).
    pub fn tag(&self) -> [u8; aead::TAG_LEN] {
        let mut tag = [0u8; aead::TAG_LEN];
        let start = self.0.len().saturating_sub(aead::TAG_LEN);
        tag.copy_from_slice(self.0.get(start..).unwrap_or(&[0; aead::TAG_LEN]));
        tag
    }

    /// Opens the record of one row. A record from another row or another
    /// table fails, because the associated data names both (`IDN-029`).
    pub fn open(
        &self,
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
    ) -> Result<Vec<u8>, Error> {
        let (salt, rest) = self.0.split_at_checked(SALT_LEN).ok_or(Error::Malformed)?;
        let (nonce, rest) = rest
            .split_at_checked(aead::NONCE_LEN)
            .ok_or(Error::Malformed)?;
        let body_len = rest
            .len()
            .checked_sub(aead::TAG_LEN)
            .ok_or(Error::Malformed)?;
        let (body, tag) = rest.split_at(body_len);
        let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| Error::Malformed)?;
        let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().map_err(|_| Error::Malformed)?;
        // IMP-041: a zero salt marks a discarded key, and no party derives
        // that key again.
        if salt == [0u8; SALT_LEN] {
            return Err(Error::Stale);
        }
        let mut plain = body.to_vec();
        let key = record_key(store_key, &salt, table, row_id);
        aead::open(
            &key,
            &nonce,
            &associated_data(table, row_id),
            &mut plain,
            tag,
        )
        .map_err(|_| Error::Unverified)?;
        Ok(plain)
    }

    /// Discards the record key: the salt becomes zero bytes (`IMP-041`).
    /// The tag stays, thus the table MAC does not change.
    pub fn discard_key(&mut self) {
        for byte in self.0.iter_mut().take(SALT_LEN) {
            *byte = 0;
        }
    }

    /// Whether the key of the record is discarded.
    pub fn is_discarded(&self) -> bool {
        self.0.iter().take(SALT_LEN).all(|byte| *byte == 0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::abuse::test_rng::Rng;

    #[test]
    fn a_record_opens_in_its_own_row_and_nowhere_else() {
        let store_key = Secret::new([1; 32]);
        let rows = RowKey::derive(&store_key);
        let row = rows.row_id(TableId::MESSAGE, b"conversation 7, message 3");
        let other_row = rows.row_id(TableId::MESSAGE, b"conversation 7, message 4");
        assert_ne!(row, other_row);
        assert_ne!(
            row,
            rows.row_id(TableId::CONTACT, b"conversation 7, message 3")
        );
        assert_ne!(
            row,
            RowKey::derive(&Secret::new([2; 32]))
                .row_id(TableId::MESSAGE, b"conversation 7, message 3")
        );

        let mut rng = Rng(1);
        let sealed =
            SealedRecord::seal(&store_key, TableId::MESSAGE, &row, b"hello", &mut rng).unwrap();
        assert_eq!(sealed.as_bytes().len(), OVERHEAD + 5);
        assert_eq!(
            sealed.open(&store_key, TableId::MESSAGE, &row).unwrap(),
            b"hello"
        );
        assert!(sealed
            .open(&store_key, TableId::MESSAGE, &other_row)
            .is_err());
        assert!(sealed.open(&store_key, TableId::CONTACT, &row).is_err());
        assert!(sealed
            .open(&Secret::new([2; 32]), TableId::MESSAGE, &row)
            .is_err());

        // Each write draws a new salt and a new nonce.
        let again =
            SealedRecord::seal(&store_key, TableId::MESSAGE, &row, b"hello", &mut rng).unwrap();
        assert_ne!(again.as_bytes()[..40], sealed.as_bytes()[..40]);
        assert_ne!(again.tag(), sealed.tag());
    }

    #[test]
    fn a_discarded_key_does_not_come_back_from_the_master_key() {
        let store_key = Secret::new([1; 32]);
        let row = [5; ROW_ID_LEN];
        let mut sealed =
            SealedRecord::seal(&store_key, TableId::MESSAGE, &row, b"erase me", &mut Rng(1))
                .unwrap();
        let tag = sealed.tag();
        sealed.discard_key();
        assert!(sealed.is_discarded());
        assert_eq!(sealed.tag(), tag);
        assert_eq!(
            sealed.open(&store_key, TableId::MESSAGE, &row),
            Err(Error::Stale)
        );
        assert!(SealedRecord::from_bytes(alloc::vec![0; OVERHEAD - 1]).is_err());
    }
}
