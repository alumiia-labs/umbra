//! The four buckets and the capacity of each layer (Part 6 §6.9).
//!
//! The capacity is a client-side selection rule (`WIR-103`). A relay never
//! reads a capacity from a served cell (`WIR-105`).

/// The onion overhead of a cell: `circ_id` and `tag` (§6.3).
pub const CELL_OVERHEAD: usize = 32;
/// The command header of §6.4.
pub const COMMAND_HEADER: usize = 84;
/// The L6 overhead of §6.4.2 rule 2: version, nonce, tag, and the true
/// length inside the ciphertext.
pub const L6_OVERHEAD: usize = 32;
/// The L7 overhead at the default braid chunk: the ratchet record, a 71-byte
/// braid frame, and the body tag (§6.9).
pub const L7_OVERHEAD_DEFAULT_CHUNK: usize = 173;
/// The L7 overhead with no braid frame.
pub const L7_OVERHEAD_NO_FRAME: usize = 102;
/// The `AppMessage` header of §6.6.
pub const APP_HEADER: usize = 30;
/// The fixed part of a `GroupQueueRecord` (§6.4.6).
pub const GROUP_RECORD_FIXED: usize = 24;
/// The AEAD tag of a group content record.
pub const GROUP_RECORD_TAG: usize = 16;
/// The fixed fields of `ContentPlain`.
pub const CONTENT_PLAIN_FIXED: usize = 15;
/// `GROUP_TAG_LEN`.
pub const GROUP_TAG_LEN: usize = umbra_crypto::group::TAG_LEN;

/// One of the four cell sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Bucket {
    /// 512 bytes.
    B0,
    /// 2 048 bytes.
    B1,
    /// 8 192 bytes.
    B2,
    /// 32 768 bytes.
    B3,
}

impl Bucket {
    /// The four buckets, smallest first.
    pub const ALL: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

    /// The bucket of a cell of `len` bytes, if one exists.
    pub fn from_cell_len(len: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.cell_len() == len)
    }

    /// The smallest bucket whose `capacity` holds `need` bytes.
    pub fn fitting(need: usize, capacity: impl Fn(Bucket) -> Option<usize>) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|b| capacity(*b).is_some_and(|c| c >= need))
    }

    /// The cell length.
    pub const fn cell_len(self) -> usize {
        match self {
            Bucket::B0 => 512,
            Bucket::B1 => 2_048,
            Bucket::B2 => 8_192,
            Bucket::B3 => 32_768,
        }
    }

    /// The `body` of the cell, after `circ_id` and `tag`.
    pub const fn body_len(self) -> usize {
        self.cell_len() - CELL_OVERHEAD
    }

    /// The command area: the body less the command byte and one padding
    /// marker.
    pub const fn command_area(self) -> usize {
        self.body_len() - 2
    }

    /// The L5 payload of a `MSG` or a `GMSG`.
    pub const fn l5_payload(self) -> usize {
        self.command_area() - COMMAND_HEADER
    }

    /// The L6 record on a `MSG`, which is the payload of a `SEND`.
    pub const fn l6_record(self) -> usize {
        self.l5_payload() - 4
    }

    /// The L7 record inside the L6 layer.
    pub const fn l7_record(self) -> usize {
        self.l6_record() - L6_OVERHEAD
    }

    /// The `AppMessage` with a default braid chunk.
    pub const fn app_default_chunk(self) -> usize {
        self.l7_record() - L7_OVERHEAD_DEFAULT_CHUNK
    }

    /// The `AppMessage` with no braid frame.
    pub const fn app_no_frame(self) -> usize {
        self.l7_record() - L7_OVERHEAD_NO_FRAME
    }

    /// The text of an `AppMessage` with a default braid chunk.
    pub const fn text_default_chunk(self) -> usize {
        self.app_default_chunk() - APP_HEADER
    }

    /// The text of an `AppMessage` with no braid frame.
    pub const fn text_no_frame(self) -> usize {
        self.app_no_frame() - APP_HEADER
    }

    /// The `GroupQueueRecord` on a `GMSG`, which is the payload of a `GPOST`.
    pub const fn group_record(self) -> usize {
        self.l5_payload() - 4
    }

    /// The `body` of a `GroupQueueRecord`.
    pub const fn group_body(self) -> usize {
        self.group_record() - GROUP_RECORD_FIXED
    }

    /// The `ContentPlain` of a content record.
    pub const fn content_plain(self) -> usize {
        self.group_body() - GROUP_RECORD_TAG
    }

    /// The tags and the `app` of a content record.
    pub const fn tags_and_app(self) -> usize {
        self.content_plain() - CONTENT_PLAIN_FIXED
    }

    /// The `app` of a dense content record at `members` active members, if
    /// the bucket holds one.
    pub fn group_app(self, members: usize) -> Option<usize> {
        self.tags_and_app()
            .checked_sub(members.checked_mul(GROUP_TAG_LEN)?)
    }

    /// The text of a dense content record at `members` active members.
    pub fn group_text(self, members: usize) -> Option<usize> {
        self.group_app(members)?.checked_sub(APP_HEADER)
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
    fn the_table_of_part_6_holds() {
        let rows = [
            (Bucket::B0, 480, 478, 394, 390, 358, 185, 155, 226),
            (
                Bucket::B1,
                2_016,
                2_014,
                1_930,
                1_926,
                1_894,
                1_721,
                1_691,
                1_762,
            ),
            (
                Bucket::B2,
                8_160,
                8_158,
                8_074,
                8_070,
                8_038,
                7_865,
                7_835,
                7_906,
            ),
            (
                Bucket::B3,
                32_736,
                32_734,
                32_650,
                32_646,
                32_614,
                32_441,
                32_411,
                32_482,
            ),
        ];
        for (b, body, area, l5, l6, l7, app, text, text_no) in rows {
            assert_eq!(b.body_len(), body);
            assert_eq!(b.command_area(), area);
            assert_eq!(b.l5_payload(), l5);
            assert_eq!(b.l6_record(), l6);
            assert_eq!(b.l7_record(), l7);
            assert_eq!(b.app_default_chunk(), app);
            assert_eq!(b.text_default_chunk(), text);
            assert_eq!(b.text_no_frame(), text_no);
        }
    }

    #[test]
    fn the_group_table_of_part_6_holds() {
        let rows = [
            (Bucket::B0, 390, 366, 350, 335),
            (Bucket::B1, 1_926, 1_902, 1_886, 1_871),
            (Bucket::B2, 8_070, 8_046, 8_030, 8_015),
            (Bucket::B3, 32_646, 32_622, 32_606, 32_591),
        ];
        for (b, record, body, plain, tags) in rows {
            assert_eq!(b.group_record(), record);
            assert_eq!(b.group_body(), body);
            assert_eq!(b.content_plain(), plain);
            assert_eq!(b.tags_and_app(), tags);
        }
        assert_eq!(Bucket::B0.group_text(3), Some(269));
        assert_eq!(Bucket::B0.group_text(25), Some(5));
        assert_eq!(Bucket::B0.group_text(120), None);
        assert_eq!(Bucket::B1.group_text(120), Some(401));
        assert_eq!(Bucket::B2.group_text(500), Some(1_985));
        assert_eq!(Bucket::B3.group_text(500), Some(26_561));
        // The modal 350-byte text takes B1 up to 124 members.
        assert_eq!(
            Bucket::fitting(350, |b| b.group_text(124)),
            Some(Bucket::B1)
        );
        assert_eq!(
            Bucket::fitting(350, |b| b.group_text(125)),
            Some(Bucket::B2)
        );
        assert_eq!(Bucket::from_cell_len(2_048), Some(Bucket::B1));
        assert_eq!(Bucket::from_cell_len(2_047), None);
    }
}
