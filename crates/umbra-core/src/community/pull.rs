//! The pull protocol of a community (Part 12 §12.3.3, §12.6.4): the
//! request, the page, the notification registration, the cursor that a
//! client holds for each relay, the backfill of a join, and the rule of
//! one community for each transport session.
//!
//! No structure here holds a value that binds it to a client, a device, or
//! an earlier session (`COM-172`).

use alloc::vec::Vec;

use umbra_wire::{
    address::LEN as QUEUE_ADDRESS_LEN,
    codec::{Reader, Writer},
};

use super::{PULL_BATCH, VERSION};
use crate::Error;

/// `PULL`.
pub const CMD_PULL: u8 = 0x80;
/// `PAGE`.
pub const CMD_PAGE: u8 = 0x81;
/// `PUB`.
pub const CMD_PUB: u8 = 0x82;
/// `PUBACK`.
pub const CMD_PUBACK: u8 = 0x83;
/// `NREG`.
pub const CMD_NREG: u8 = 0x84;
/// `NUNREG`.
pub const CMD_NUNREG: u8 = 0x85;

/// The length of a `PullRequest`.
pub const PULL_REQUEST_LEN: usize = 75;
/// The header of a `PullResponse`.
pub const PAGE_HEADER_LEN: usize = 51;
/// The bytes that a `PullEntry` adds to its record.
pub const PAGE_ENTRY_OVERHEAD: usize = 10;
/// The `B3` L5 payload, which bounds a page (`COM-182`).
pub const PAGE_MAX: usize = 32_650;
/// The length of a `NotifyRegistration`.
pub const NOTIFY_REGISTRATION_LEN: usize = 162;
/// The `from` value that asks for the newest records.
pub const NEWEST: u64 = u64::MAX;

/// What a pull selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Selector {
    /// Each record in the order of the relay sequence.
    Sequence = 0x01,
    /// The posts, the stubs, and the checkpoints of one pseudonym.
    Chain = 0x02,
    /// The control chain.
    Control = 0x03,
    /// The metadata records.
    Meta = 0x04,
}

impl Selector {
    fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => Selector::Sequence,
            0x02 => Selector::Chain,
            0x03 => Selector::Control,
            0x04 => Selector::Meta,
            _ => return Err(Error::Malformed),
        })
    }
}

/// A `PullRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullRequest {
    /// The community.
    pub community_id: [u8; 32],
    /// The selector.
    pub selector: Selector,
    /// The chain under `Selector::Chain`, and zero bytes otherwise.
    pub pseudonym: [u8; 32],
    /// The first `seq`, `index`, `epoch_index`, or `meta_index`.
    pub from: u64,
    /// 1 to `PULL_BATCH`.
    pub count: u8,
}

impl PullRequest {
    fn check(&self) -> Result<(), Error> {
        // COM-188, COM-189.
        let sentinel_misused = self.from == NEWEST && self.selector != Selector::Sequence;
        let pseudonym_misused = (self.selector == Selector::Chain) == (self.pseudonym == [0; 32]);
        if self.count == 0 || self.count > PULL_BATCH || sentinel_misused || pseudonym_misused {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Encodes the request.
    pub fn encode(&self) -> Result<[u8; PULL_REQUEST_LEN], Error> {
        self.check()?;
        let mut out = [0u8; PULL_REQUEST_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.put(&self.community_id)?;
        w.u8(self.selector as u8)?;
        w.put(&self.pseudonym)?;
        w.put(&self.from.to_be_bytes())?;
        w.u8(self.count)?;
        Ok(out)
    }

    /// Reads a request.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let request = PullRequest {
            community_id: r.array()?,
            selector: Selector::from_byte(r.u8()?)?,
            pseudonym: r.array()?,
            from: u64::from_be_bytes(r.array()?),
            count: r.u8()?,
        };
        r.finish()?;
        request.check()?;
        Ok(request)
    }
}

/// One entry of a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullEntry<'a> {
    /// The relay-local sequence number of the record.
    pub seq: u64,
    /// One community record.
    pub record: &'a [u8],
}

/// A `PullResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullResponse<'a> {
    /// The community.
    pub community_id: [u8; 32],
    /// The selector of the request.
    pub selector: Selector,
    /// The seq floor, the chain floor, or 0.
    pub floor: u64,
    /// The value that follows the last entry.
    pub next: u64,
    /// The entries.
    pub entries: Vec<PullEntry<'a>>,
}

impl<'a> PullResponse<'a> {
    /// The encoded length.
    pub fn len(&self) -> usize {
        self.entries.iter().fold(PAGE_HEADER_LEN, |sum, entry| {
            sum.saturating_add(PAGE_ENTRY_OVERHEAD)
                .saturating_add(entry.record.len())
        })
    }

    /// Whether the page holds no entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Encodes the page.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.entries.len() > usize::from(PULL_BATCH) || self.len() > PAGE_MAX {
            return Err(Error::Malformed);
        }
        let mut out = alloc::vec![0u8; self.len()];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.put(&self.community_id)?;
        w.u8(self.selector as u8)?;
        w.put(&self.floor.to_be_bytes())?;
        w.put(&self.next.to_be_bytes())?;
        w.u8(u8::try_from(self.entries.len()).map_err(|_| Error::Malformed)?)?;
        for entry in &self.entries {
            w.put(&entry.seq.to_be_bytes())?;
            w.u16(u16::try_from(entry.record.len()).map_err(|_| Error::Malformed)?)?;
            w.put(entry.record)?;
        }
        Ok(out)
    }

    /// Reads a page.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > PAGE_MAX {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let community_id = r.array()?;
        let selector = Selector::from_byte(r.u8()?)?;
        let floor = u64::from_be_bytes(r.array()?);
        let next = u64::from_be_bytes(r.array()?);
        let count = r.u8()?;
        if count > PULL_BATCH {
            return Err(Error::Malformed);
        }
        let mut entries = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let seq = u64::from_be_bytes(r.array()?);
            let record_len = usize::from(r.u16()?);
            entries.push(PullEntry {
                seq,
                record: r.take(record_len)?,
            });
        }
        r.finish()?;
        Ok(PullResponse {
            community_id,
            selector,
            floor,
            next,
            entries,
        })
    }
}

/// A `NotifyRegistration`, the payload of `NREG` and of `NUNREG`. It holds
/// a queue and no pseudonym (`COM-374`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyRegistration {
    /// The community.
    pub community_id: [u8; 32],
    /// The encoded `QueueAddress` of the notification queue.
    pub queue: [u8; QUEUE_ADDRESS_LEN],
}

impl NotifyRegistration {
    /// Encodes the registration.
    pub fn encode(&self) -> Result<[u8; NOTIFY_REGISTRATION_LEN], Error> {
        let mut out = [0u8; NOTIFY_REGISTRATION_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.put(&self.community_id)?;
        w.put(&self.queue)?;
        Ok(out)
    }

    /// Reads a registration.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let registration = NotifyRegistration {
            community_id: r.array()?,
            queue: r.array()?,
        };
        r.finish()?;
        umbra_wire::address::QueueAddress::parse(&registration.queue)?;
        Ok(registration)
    }
}

/// What one page under the sequence selector tells the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageNote {
    /// The `seq` range that the relay pruned behind the cursor, which is
    /// not a gap (`COM-193`).
    pub pruned: Option<(u64, u64)>,
    /// The page is full, thus the client pulls again in this session
    /// (`COM-194`).
    pub pull_again: bool,
}

/// The cursor of one community at one relay (`COM-190`). A `seq` of one
/// relay has no meaning at another relay (`COM-180`), thus each relay has
/// its own cursor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayCursor {
    next: Option<u64>,
    lowest_seen: Option<u64>,
    floor: u64,
}

impl RelayCursor {
    /// The next steady-state request. The first one asks for the newest
    /// records (`COM-195`), and each one asks for `PULL_BATCH` (`COM-192`).
    pub fn request(&self, community_id: [u8; 32]) -> PullRequest {
        PullRequest {
            community_id,
            selector: Selector::Sequence,
            pseudonym: [0; 32],
            from: self.next.unwrap_or(NEWEST),
            count: PULL_BATCH,
        }
    }

    /// The next backfill request behind the first page, or `None` when the
    /// history reaches the floor. It has the shape of a steady-state pull,
    /// and the caller sends one in each `PULL_INTERVAL` at the most
    /// (`COM-091`, `COM-092`).
    pub fn backfill_request(&self, community_id: [u8; 32]) -> Option<PullRequest> {
        let lowest = self.lowest_seen?;
        if lowest <= self.floor {
            return None;
        }
        let from = lowest.saturating_sub(u64::from(PULL_BATCH)).max(self.floor);
        Some(PullRequest {
            community_id,
            selector: Selector::Sequence,
            pseudonym: [0; 32],
            from,
            count: PULL_BATCH,
        })
    }

    /// Takes a page that answers [`RelayCursor::request`].
    pub fn on_page(&mut self, page: &PullResponse<'_>) -> Result<PageNote, Error> {
        if page.selector != Selector::Sequence {
            return Err(Error::Malformed);
        }
        let pruned = self
            .next
            .filter(|cursor| page.floor > *cursor)
            .map(|cursor| (cursor, page.floor));
        self.floor = page.floor;
        self.note_lowest(page);
        self.next = Some(page.next);
        Ok(PageNote {
            pruned,
            pull_again: page.entries.len() == usize::from(PULL_BATCH),
        })
    }

    /// Takes a page that answers [`RelayCursor::backfill_request`]. The
    /// steady-state cursor does not move.
    pub fn on_backfill_page(&mut self, page: &PullResponse<'_>, from: u64) {
        self.floor = page.floor;
        self.lowest_seen = Some(self.lowest_seen.map_or(from, |lowest| lowest.min(from)));
        self.note_lowest(page);
    }

    fn note_lowest(&mut self, page: &PullResponse<'_>) {
        if let Some(first) = page.entries.first() {
            self.lowest_seen = Some(self.lowest_seen.map_or(first.seq, |l| l.min(first.seq)));
        }
    }
}

/// The community of one transport session (`COM-173`). A `NREG` rides the
/// same session as the pulls of its community (`COM-368`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullSession {
    community_id: Option<[u8; 32]>,
}

impl PullSession {
    /// Binds the session to the first community, and rejects a second one.
    pub fn admit(&mut self, community_id: &[u8; 32]) -> Result<(), Error> {
        match self.community_id {
            Some(bound) if bound != *community_id => Err(Error::NoPath),
            _ => {
                self.community_id = Some(*community_id);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_request_holds_75_bytes_and_obeys_the_selector_rules() {
        let request = PullRequest {
            community_id: [9; 32],
            selector: Selector::Chain,
            pseudonym: [1; 32],
            from: 40,
            count: 30,
        };
        let bytes = request.encode().unwrap();
        assert_eq!(bytes.len(), 75);
        assert_eq!(PullRequest::parse(&bytes).unwrap(), request);

        let bad = [
            PullRequest {
                count: 0,
                ..request
            },
            PullRequest {
                count: 31,
                ..request
            },
            PullRequest {
                from: NEWEST,
                ..request
            },
            PullRequest {
                pseudonym: [0; 32],
                ..request
            },
            PullRequest {
                selector: Selector::Control,
                ..request
            },
        ];
        for request in bad {
            assert!(request.encode().is_err());
        }
        let mut unknown = bytes;
        unknown[33] = 0x05;
        assert!(PullRequest::parse(&unknown).is_err());
    }

    #[test]
    fn a_page_round_trips_and_stays_inside_the_b3_payload() {
        let record = [7u8; 246];
        let page = PullResponse {
            community_id: [9; 32],
            selector: Selector::Sequence,
            floor: 3,
            next: 33,
            entries: (0..30)
                .map(|n| PullEntry {
                    seq: 3 + n,
                    record: &record,
                })
                .collect(),
        };
        let bytes = page.encode().unwrap();
        assert_eq!(bytes.len(), 7_731);
        assert_eq!(PullResponse::parse(&bytes).unwrap(), page);

        let large = alloc::vec![0u8; 32_590];
        let over = PullResponse {
            entries: alloc::vec![PullEntry {
                seq: 1,
                record: &large
            }],
            ..page.clone()
        };
        assert!(over.encode().is_err());
        let fits = PullResponse {
            entries: alloc::vec![PullEntry {
                seq: 1,
                record: &large[..32_589]
            }],
            ..page
        };
        assert_eq!(fits.encode().unwrap().len(), PAGE_MAX);
    }

    #[test]
    fn the_cursor_starts_at_the_newest_and_reads_a_prune_as_no_gap() {
        let community = [9; 32];
        let mut cursor = RelayCursor::default();
        assert_eq!(cursor.request(community).from, NEWEST);
        assert!(cursor.backfill_request(community).is_none());

        let record = [0u8; 8];
        let full: Vec<PullEntry<'_>> = (0..30)
            .map(|n| PullEntry {
                seq: 100 + n,
                record: &record,
            })
            .collect();
        let page = PullResponse {
            community_id: community,
            selector: Selector::Sequence,
            floor: 20,
            next: 130,
            entries: full,
        };
        let note = cursor.on_page(&page).unwrap();
        assert!(note.pull_again && note.pruned.is_none());
        assert_eq!(cursor.request(community).from, 130);
        assert_eq!(cursor.request(community).count, PULL_BATCH);

        // The backfill walks down to the floor in pulls of one shape.
        let backfill = cursor.backfill_request(community).unwrap();
        assert_eq!((backfill.from, backfill.count), (70, PULL_BATCH));
        let older = PullResponse {
            entries: alloc::vec![PullEntry {
                seq: 75,
                record: &record
            }],
            next: 100,
            ..page.clone()
        };
        cursor.on_backfill_page(&older, 70);
        assert_eq!(cursor.backfill_request(community).unwrap().from, 40);
        cursor.on_backfill_page(
            &PullResponse {
                entries: Vec::new(),
                ..older.clone()
            },
            40,
        );
        assert_eq!(cursor.backfill_request(community).unwrap().from, 20);
        cursor.on_backfill_page(
            &PullResponse {
                entries: Vec::new(),
                ..older
            },
            20,
        );
        assert!(cursor.backfill_request(community).is_none());
        assert_eq!(
            cursor.request(community).from,
            130,
            "the backfill does not move the cursor"
        );

        let later = PullResponse {
            floor: 500,
            next: 501,
            entries: alloc::vec![PullEntry {
                seq: 500,
                record: &record
            }],
            ..page
        };
        let note = cursor.on_page(&later).unwrap();
        assert_eq!(note.pruned, Some((130, 500)));
        assert!(!note.pull_again);
    }

    #[test]
    fn a_session_pulls_one_community() {
        let mut session = PullSession::default();
        session.admit(&[1; 32]).unwrap();
        session.admit(&[1; 32]).unwrap();
        assert!(session.admit(&[2; 32]).is_err());

        let registration = NotifyRegistration {
            community_id: [1; 32],
            queue: {
                let mut q = [5u8; QUEUE_ADDRESS_LEN];
                q[0] = 0x01;
                q
            },
        };
        let bytes = registration.encode().unwrap();
        assert_eq!(bytes.len(), 162);
        assert_eq!(NotifyRegistration::parse(&bytes).unwrap(), registration);
    }
}
