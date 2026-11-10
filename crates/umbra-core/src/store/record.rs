//! The record layer of the local database (Part 14 §14.6.4). It gives one
//! key for each record from a random salt beside it. The associated data
//! holds the version, the table, the row, and the owner. The keyed
//! surrogate names a row.

use alloc::vec::Vec;

use umbra_crypto::{
    aead, hash::hmac_sha3_256, hkdf::Hkdf, hmac::Mac, labels, rand_core::CryptoRng, secret::Secret,
    sha3::Sha3_256,
};

use crate::Error;

/// The length of `record_salt`.
pub const SALT_LEN: usize = 16;
/// The length of a surrogate row identifier.
pub const ROW_ID_LEN: usize = 16;
/// The bytes of a sealed record around its ciphertext.
pub const OVERHEAD: usize = SALT_LEN + aead::NONCE_LEN + aead::TAG_LEN;
/// The record version that this build writes. Its associated data holds
/// the version, the table, the row, and the owner of the row (`IMP-121`).
/// Version `0x01` held the table and the row alone, and a store of that
/// version moves to this one at its first write (`IMP-130`).
pub const RECORD_VERSION: u8 = 0x02;
/// The longest associated data of a record: the version, the table, the
/// row, the owner flag, and the owner.
const OWNED_DATA_LEN: usize = 2 + ROW_ID_LEN + 1 + ROW_ID_LEN;

/// A table identifier. This type names no closed list of tables, because
/// Part 4 §4.6 binds each table that a client adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableId(pub u8);

impl TableId {
    /// The set of tables: it holds no row, and its MAC counts each table
    /// of the store (Part 4 `IDN-193`).
    pub const SET: TableId = TableId(0x00);
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
        umbra_crypto::kdf::expand_into(&kdf, &[labels::ROW_ID], &mut key);
        RowKey(key)
    }

    /// `HMAC-SHA3-256(K_row, table_id || natural_key)[0..16]`.
    pub fn row_id(&self, table: TableId, natural_key: &[u8]) -> RowId {
        let mut mac = hmac_sha3_256(self.0.expose());
        mac.update(&[table.0]);
        mac.update(natural_key);

        let full: [u8; 32] = mac.finalize().into_bytes().into();
        umbra_crypto::bytes::part::<0, ROW_ID_LEN, 32>(&full)
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

/// The associated data of a record of [`RECORD_VERSION`]: `version ||
/// table_id || row_id || owner_flag || owner`. The flag is `0x01` with the
/// 16 bytes of the owner, or `0x00` with no more bytes. Thus the two forms
/// and the 17 bytes of version `0x01` parse in one way.
fn owned_data(
    table: TableId,
    row_id: &RowId,
    owner: Option<&RowId>,
) -> ([u8; OWNED_DATA_LEN], usize) {
    let mut ad = [0u8; OWNED_DATA_LEN];
    let mut len = 0usize;
    let mut push = |bytes: &[u8]| {
        let end = len.saturating_add(bytes.len());
        if let Some(slot) = ad.get_mut(len..end) {
            slot.copy_from_slice(bytes);
            len = end;
        }
    };

    push(&[RECORD_VERSION, table.0]);
    push(row_id);
    match owner {
        Some(owner) => {
            push(&[0x01]);
            push(owner);
        }
        None => push(&[0x00]),
    }

    (ad, len)
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
    umbra_crypto::kdf::expand_into(
        &kdf,
        &[labels::RECORD_KEY, &associated_data(table, row_id)],
        &mut key,
    );
    key
}

/// A record as the database holds it: `record_salt || nonce || ct || tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecord(Vec<u8>);

impl SealedRecord {
    /// Seals `plaintext` for one row of one owner, with a fresh salt and a
    /// fresh nonce from `rng` at each write (`IMP-040`).
    pub fn seal<R: CryptoRng + ?Sized>(
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
        owner: Option<&RowId>,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (ad, len) = owned_data(table, row_id, owner);
        let ad = ad.get(..len).unwrap_or(&[]);
        Self::seal_under(store_key, table, row_id, ad, plaintext, rng)
    }

    /// Seals a record of version `0x01`, for a test that builds the store
    /// of an earlier build.
    #[cfg(test)]
    pub(crate) fn seal_earlier<R: CryptoRng + ?Sized>(
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let ad = associated_data(table, row_id);
        Self::seal_under(store_key, table, row_id, &ad, plaintext, rng)
    }

    fn seal_under<R: CryptoRng + ?Sized>(
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
        ad: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; aead::NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        // The seal runs on the record in its place. Thus the largest row of
        // a store, a whole file, has one copy beside its plaintext.
        let head = SALT_LEN + aead::NONCE_LEN;
        let mut out = Vec::with_capacity(OVERHEAD.saturating_add(plaintext.len()));
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);

        let key = record_key(store_key, &salt, table, row_id);
        let sealed = match out.get_mut(head..) {
            Some(body) => aead::seal(&key, &nonce, ad, body),
            None => Err(umbra_crypto::Error::Queue),
        };

        match sealed {
            Ok(tag) => {
                out.extend_from_slice(&tag);
                Ok(SealedRecord(out))
            }
            Err(error) => {
                // The buffer can hold a part of the plaintext.
                umbra_crypto::zeroize::Zeroize::zeroize(&mut out);
                Err(error.into())
            }
        }
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

    /// The bytes that a backend writes, with no copy of them.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// The record tag, which the table MAC reads (`IDN-066`). Bytes below
    /// the length of a tag give an error and no tag.
    pub fn tag(&self) -> Result<[u8; aead::TAG_LEN], Error> {
        self.0.last_chunk().copied().ok_or(Error::Malformed)
    }

    /// Opens the record of one row of one owner. A record from another
    /// row, another table, or another owner fails, because the associated
    /// data names the three (`IDN-029`). A record of version `0x01` fails
    /// too, because its associated data holds no version.
    pub fn open(
        &self,
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
        owner: Option<&RowId>,
    ) -> Result<Vec<u8>, Error> {
        let (ad, len) = owned_data(table, row_id, owner);
        self.open_under(store_key, table, row_id, ad.get(..len).unwrap_or(&[]))
    }

    /// [`SealedRecord::open`] in the buffer of the record. Thus the largest
    /// row of a store, a whole file, has no second copy at the read.
    pub fn into_open(
        self,
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
        owner: Option<&RowId>,
    ) -> Result<Vec<u8>, Error> {
        let (ad, len) = owned_data(table, row_id, owner);
        let ad = ad.get(..len).unwrap_or(&[]);
        let mut bytes = self.0;

        let (salt, nonce, body_len) = Self::frame(&bytes)?;
        if salt == [0u8; SALT_LEN] {
            return Err(Error::Stale);
        }

        let head = SALT_LEN + aead::NONCE_LEN;
        let end = head.saturating_add(body_len);
        let key = record_key(store_key, &salt, table, row_id);
        let (body, tag) = bytes
            .get_mut(head..)
            .ok_or(Error::Malformed)?
            .split_at_mut(body_len);
        aead::open(&key, &nonce, ad, body, tag).map_err(|_| Error::Unverified)?;

        // The move leaves a part of the plaintext behind the new end.
        bytes.copy_within(head..end, 0);
        if let Some(rest) = bytes.get_mut(body_len..) {
            umbra_crypto::zeroize::Zeroize::zeroize(rest);
        }
        bytes.truncate(body_len);
        Ok(bytes)
    }

    /// Opens a record of version `0x01`, whose associated data names the
    /// table and the row alone. Only the store of an earlier build holds
    /// one. The pass that moves it to [`RECORD_VERSION`] calls this, and a
    /// read before that pass.
    pub fn open_earlier(
        &self,
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
    ) -> Result<Vec<u8>, Error> {
        self.open_under(store_key, table, row_id, &associated_data(table, row_id))
    }

    fn open_under(
        &self,
        store_key: &Secret<32>,
        table: TableId,
        row_id: &RowId,
        ad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (salt, nonce, body_len) = Self::frame(&self.0)?;

        // IMP-041: a zero salt marks a discarded key, and no party derives
        // that key again.
        if salt == [0u8; SALT_LEN] {
            return Err(Error::Stale);
        }

        let head = SALT_LEN + aead::NONCE_LEN;
        let rest = self.0.get(head..).ok_or(Error::Malformed)?;
        let (body, tag) = rest.split_at(body_len);
        let mut plain = body.to_vec();
        let key = record_key(store_key, &salt, table, row_id);
        aead::open(&key, &nonce, ad, &mut plain, tag).map_err(|_| Error::Unverified)?;
        Ok(plain)
    }

    /// The salt, the nonce, and the length of the ciphertext of a record.
    fn frame(bytes: &[u8]) -> Result<([u8; SALT_LEN], [u8; aead::NONCE_LEN], usize), Error> {
        let (salt, rest) = bytes.split_at_checked(SALT_LEN).ok_or(Error::Malformed)?;
        let (nonce, rest) = rest
            .split_at_checked(aead::NONCE_LEN)
            .ok_or(Error::Malformed)?;
        let body_len = rest
            .len()
            .checked_sub(aead::TAG_LEN)
            .ok_or(Error::Malformed)?;
        let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| Error::Malformed)?;
        let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().map_err(|_| Error::Malformed)?;
        Ok((salt, nonce, body_len))
    }

    /// What the table MAC reads of the record: its tag, and for a record
    /// whose key is discarded the tag with a mark. A salt that a party
    /// with the file sets to zero bytes thus shows in the scan of the
    /// table (`IDN-031`, `IDN-163`), and a store with no discarded record
    /// keeps its MAC.
    pub fn mac_input(&self) -> Result<[u8; aead::TAG_LEN], Error> {
        Self::mac_input_of(&self.0)
    }

    /// [`SealedRecord::mac_input`] of the bytes that a backend holds, with
    /// no copy of them.
    pub fn mac_input_of(bytes: &[u8]) -> Result<[u8; aead::TAG_LEN], Error> {
        if bytes.len() < OVERHEAD {
            return Err(Error::Malformed);
        }

        let mut tag: [u8; aead::TAG_LEN] = bytes.last_chunk().copied().ok_or(Error::Malformed)?;

        if bytes.iter().take(SALT_LEN).all(|byte| *byte == 0) {
            for byte in &mut tag {
                *byte = !*byte;
            }
        }
        Ok(tag)
    }

    /// Discards the record key: the salt becomes zero bytes (`IMP-041`).
    /// The table MAC reads the change through [`SealedRecord::mac_input`].
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
    use umbra_crypto::hmac::{digest::KeyInit, Hmac};

    #[test]
    fn the_row_id_is_the_mac_of_the_slice_key() {
        let rows = RowKey::derive(&Secret::new([1; 32]));
        let mut old = Hmac::<Sha3_256>::new_from_slice(rows.0.expose()).unwrap();
        old.update(&[TableId::MESSAGE.0]);
        old.update(b"conversation 7");
        let full: [u8; 32] = old.finalize().into_bytes().into();

        assert_eq!(
            rows.row_id(TableId::MESSAGE, b"conversation 7"),
            full[..ROW_ID_LEN]
        );
    }

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
        let table = TableId::MESSAGE;
        let sealed = SealedRecord::seal(&store_key, table, &row, None, b"hello", &mut rng).unwrap();
        assert_eq!(sealed.as_bytes().len(), OVERHEAD + 5);
        assert_eq!(
            sealed.open(&store_key, table, &row, None).unwrap(),
            b"hello"
        );

        assert!(sealed.open(&store_key, table, &other_row, None).is_err());
        assert!(sealed
            .open(&store_key, TableId::CONTACT, &row, None)
            .is_err());
        assert!(sealed
            .open(&Secret::new([2; 32]), table, &row, None)
            .is_err());

        // Each write draws a new salt and a new nonce.
        let again = SealedRecord::seal(&store_key, table, &row, None, b"hello", &mut rng).unwrap();
        assert_ne!(again.as_bytes()[..40], sealed.as_bytes()[..40]);
        assert_ne!(again.tag().unwrap(), sealed.tag().unwrap());
    }

    #[test]
    fn a_record_opens_under_its_own_owner_and_its_own_version_only() {
        let store_key = Secret::new([1; 32]);
        let row = [5; ROW_ID_LEN];
        let owner = [6; ROW_ID_LEN];
        let other = [7; ROW_ID_LEN];
        let mut rng = Rng(1);
        let table = TableId::MESSAGE;

        let sealed =
            SealedRecord::seal(&store_key, table, &row, Some(&owner), b"hello", &mut rng).unwrap();
        assert_eq!(
            sealed.open(&store_key, table, &row, Some(&owner)).unwrap(),
            b"hello"
        );

        // IMP-121: the owner column of another conversation, or none.
        assert_eq!(
            sealed.open(&store_key, table, &row, Some(&other)),
            Err(Error::Unverified)
        );
        assert_eq!(
            sealed.open(&store_key, table, &row, None),
            Err(Error::Unverified)
        );

        // A row with no owner does not open under one.
        let alone = SealedRecord::seal(&store_key, table, &row, None, b"hello", &mut rng).unwrap();
        assert!(alone.open(&store_key, table, &row, Some(&owner)).is_err());

        // IMP-130: the two versions do not read each other.
        assert!(sealed.open_earlier(&store_key, table, &row).is_err());
        assert!(alone.open_earlier(&store_key, table, &row).is_err());
        let earlier =
            SealedRecord::seal_earlier(&store_key, table, &row, b"hello", &mut rng).unwrap();
        assert_eq!(
            earlier.open_earlier(&store_key, table, &row).unwrap(),
            b"hello"
        );
        assert!(earlier.open(&store_key, table, &row, None).is_err());
        assert!(earlier.open(&store_key, table, &row, Some(&owner)).is_err());
    }

    #[test]
    fn an_open_in_the_record_buffer_matches_an_open_of_a_copy() {
        let store_key = Secret::new([1; 32]);
        let row = [5; ROW_ID_LEN];
        let owner = [6; ROW_ID_LEN];
        let table = TableId::MESSAGE;
        let mut rng = Rng(1);

        let plains: [&[u8]; 3] = [b"", b"hello", &[7; 300]];
        for plain in plains {
            let sealed =
                SealedRecord::seal(&store_key, table, &row, Some(&owner), plain, &mut rng).unwrap();
            assert_eq!(
                sealed
                    .clone()
                    .into_open(&store_key, table, &row, Some(&owner)),
                sealed.open(&store_key, table, &row, Some(&owner))
            );
            assert_eq!(
                sealed
                    .clone()
                    .into_open(&store_key, table, &row, Some(&owner))
                    .unwrap(),
                plain
            );
            assert_eq!(
                sealed.into_open(&store_key, table, &row, None),
                Err(Error::Unverified)
            );
        }

        let mut discarded =
            SealedRecord::seal(&store_key, table, &row, None, b"gone", &mut rng).unwrap();
        discarded.discard_key();
        assert_eq!(
            discarded.into_open(&store_key, table, &row, None),
            Err(Error::Stale)
        );
    }

    #[test]
    fn a_discarded_key_does_not_come_back_from_the_master_key() {
        let store_key = Secret::new([1; 32]);
        let row = [5; ROW_ID_LEN];
        let table = TableId::MESSAGE;
        let mut sealed =
            SealedRecord::seal(&store_key, table, &row, None, b"erase me", &mut Rng(1)).unwrap();

        let tag = sealed.tag().unwrap();
        sealed.discard_key();
        assert!(sealed.is_discarded());
        assert_eq!(sealed.tag(), Ok(tag));

        // The read of the stored bytes gives the same input as the record,
        // and bytes below the length of a record give an error and no tag.
        let marked = tag.map(|byte| !byte);
        assert_eq!(sealed.mac_input(), Ok(marked));
        assert_eq!(SealedRecord::mac_input_of(sealed.as_bytes()), Ok(marked));
        assert_eq!(
            SealedRecord::mac_input_of(&[0; OVERHEAD - 1]),
            Err(Error::Malformed)
        );
        assert_eq!(
            sealed.open(&store_key, table, &row, None),
            Err(Error::Stale)
        );
        assert!(SealedRecord::from_bytes(alloc::vec![0; OVERHEAD - 1]).is_err());
    }
}
