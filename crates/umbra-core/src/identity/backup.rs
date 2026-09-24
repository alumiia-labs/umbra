//! The backup object of Part 4 §4.7.2: the rows of the store that a
//! restore needs, as the store of this device holds them. A full object
//! holds each such row; a delta holds each row put or deleted since the
//! object before it.
//!
//! A row travels under its surrogate identifier and in its plaintext. The
//! identifier comes from `K_store`, and `K_store` comes from the root
//! seed, thus a restore under the same seed gives each row its place
//! again. The object is sealed as a file of Part 12, and the backup root
//! names it.

use alloc::vec::Vec;

use umbra_crypto::{
    stored::{Reader, Writer},
    zeroize::Zeroizing,
};

use crate::{
    store::record::{RowId, TableId},
    Error,
};

/// The version of a backup object.
pub const OBJECT_VERSION: u8 = 0x01;

/// The kind of an object: a full object.
pub const KIND_FULL: u8 = 0x01;
/// The kind of an object: a delta.
pub const KIND_DELTA: u8 = 0x02;

const OP_PUT: u8 = 0x01;
const OP_DELETE: u8 = 0x02;

/// One change of one row.
pub enum BackupRow {
    /// The row holds this plaintext.
    Put {
        /// The table.
        table: TableId,
        /// The surrogate identifier.
        row: RowId,
        /// The owner column, when the row has one.
        owner: Option<RowId>,
        /// The plaintext.
        plain: Zeroizing<Vec<u8>>,
    },
    /// The row is gone.
    Delete {
        /// The table.
        table: TableId,
        /// The surrogate identifier.
        row: RowId,
    },
}

/// One backup object.
pub struct BackupObject {
    /// [`KIND_FULL`] or [`KIND_DELTA`].
    pub kind: u8,
    /// The time of the write, in Unix seconds of this device.
    pub written_at: u64,
    /// For a delta, `written_at` of the object that it follows; 0 for a
    /// full object.
    pub base_at: u64,
    /// The rows, in the order of their application.
    pub rows: Vec<BackupRow>,
}

impl BackupObject {
    /// The bytes of the object, before the seal of Part 12 §12.3.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.kind != KIND_FULL && self.kind != KIND_DELTA {
            return Err(Error::Malformed);
        }
        if self.kind == KIND_FULL && self.base_at != 0 {
            return Err(Error::Malformed);
        }
        let mut writer = Writer::new();
        writer.u8(OBJECT_VERSION);
        writer.u8(self.kind);
        writer.u64(self.written_at);
        writer.u64(self.base_at);
        writer.u32(u32::try_from(self.rows.len()).map_err(|_| Error::Malformed)?);
        for row in &self.rows {
            match row {
                BackupRow::Put {
                    table,
                    row,
                    owner,
                    plain,
                } => {
                    writer.u8(OP_PUT);
                    writer.u8(table.0);
                    writer.bytes(row);
                    match owner {
                        Some(owner) => {
                            writer.u8(1);
                            writer.bytes(owner);
                        }
                        None => writer.u8(0),
                    }
                    writer.var(plain)?;
                }
                BackupRow::Delete { table, row } => {
                    // A full object holds rows, and no deletion.
                    if self.kind == KIND_FULL {
                        return Err(Error::Malformed);
                    }
                    writer.u8(OP_DELETE);
                    writer.u8(table.0);
                    writer.bytes(row);
                }
            }
        }
        Ok(writer.finish())
    }

    /// Reads an object that [`BackupObject::encode`] wrote.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        if reader.u8()? != OBJECT_VERSION {
            return Err(Error::Malformed);
        }
        let kind = reader.u8()?;
        if kind != KIND_FULL && kind != KIND_DELTA {
            return Err(Error::Malformed);
        }
        let written_at = reader.u64()?;
        let base_at = reader.u64()?;
        if kind == KIND_FULL && base_at != 0 {
            return Err(Error::Malformed);
        }
        let count = reader.u32()?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let op = reader.u8()?;
            let table = TableId(reader.u8()?);
            let row: RowId = reader.array()?;
            rows.push(match op {
                OP_PUT => {
                    let owner = match reader.u8()? {
                        0 => None,
                        1 => Some(reader.array()?),
                        _ => return Err(Error::Malformed),
                    };
                    let plain = Zeroizing::new(reader.var()?.to_vec());
                    BackupRow::Put {
                        table,
                        row,
                        owner,
                        plain,
                    }
                }
                OP_DELETE if kind == KIND_DELTA => BackupRow::Delete { table, row },
                _ => return Err(Error::Malformed),
            });
        }
        reader.end()?;
        Ok(BackupObject {
            kind,
            written_at,
            base_at,
            rows,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use alloc::vec;

    use umbra_crypto::zeroize::Zeroizing;

    use super::{BackupObject, BackupRow, KIND_DELTA, KIND_FULL};
    use crate::store::record::TableId;

    #[test]
    fn a_full_object_and_a_delta_read_back_as_they_were_written() {
        let full = BackupObject {
            kind: KIND_FULL,
            written_at: 1_800_000_000,
            base_at: 0,
            rows: vec![
                BackupRow::Put {
                    table: TableId(0x03),
                    row: [1; 16],
                    owner: None,
                    plain: Zeroizing::new(vec![9; 40]),
                },
                BackupRow::Put {
                    table: TableId(0x01),
                    row: [2; 16],
                    owner: Some([3; 16]),
                    plain: Zeroizing::new(vec![]),
                },
            ],
        };
        let bytes = full.encode().unwrap();
        let back = BackupObject::parse(&bytes).unwrap();
        assert_eq!(
            (back.kind, back.written_at, back.rows.len()),
            (KIND_FULL, 1_800_000_000, 2)
        );
        let BackupRow::Put { owner, plain, .. } = &back.rows[1] else {
            panic!("a put");
        };
        assert_eq!((*owner, plain.len()), (Some([3; 16]), 0));

        let delta = BackupObject {
            kind: KIND_DELTA,
            written_at: 1_800_086_400,
            base_at: 1_800_000_000,
            rows: vec![BackupRow::Delete {
                table: TableId(0x03),
                row: [1; 16],
            }],
        };
        let back = BackupObject::parse(&delta.encode().unwrap()).unwrap();
        assert!(matches!(
            back.rows[..],
            [BackupRow::Delete { row: [1, ..], .. }]
        ));

        // A full object holds no deletion, and no base.
        let wrong = BackupObject {
            kind: KIND_FULL,
            ..delta
        };
        assert!(wrong.encode().is_err());
        let mut bytes = bytes.to_vec();
        bytes.push(0);
        assert!(BackupObject::parse(&bytes).is_err());
    }
}
