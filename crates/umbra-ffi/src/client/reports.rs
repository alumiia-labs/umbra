//! The reports of Part 12 §12.5.3: a member seals a report of a post to
//! one role holder of the roster, and a role holder of this device opens
//! each report that reaches its report queue and holds it until the post
//! that it names checks out.
//!
//! A report names a post and a cause, and no field names the reporter
//! (`COM-272`). A role holder forwards no report (`COM-286`), thus a
//! backup carries none.

use umbra_core::{
    community::{
        identity::RoleIdentity,
        report::{self, CommunityReport, Reason},
        REPORT_HOLD, REPORT_NOTE_MAX,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{hash::sha3_256, rand_core::CryptoRng, zeroize::Zeroizing};

use super::{
    communities::{CommunityRow, COMMUNITY},
    Client,
};
use crate::Error;

/// Each report that a role holder of this device holds, by the hash of the
/// report, owned by the community row.
pub(super) const COMMUNITY_REPORT: TableId = TableId(0x28);

/// A report that the platform shows to a role holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportInfo {
    /// The report, by the hash of its encoding.
    pub id: [u8; 32],
    /// The hash of the post that it names.
    pub post_key: [u8; 32],
    /// The cause, the byte of the table of §12.5.3.
    pub reason: u8,
    /// Whether the report holds a note.
    pub has_note: bool,
    /// The time the report reached this device, in Unix seconds.
    pub at: u64,
}

/// A held report: its row, its identity, the time of its arrival, and the
/// report.
type HeldReport = (RowId, [u8; 32], u64, CommunityReport);

fn reason_of(byte: u8) -> Result<Reason, Error> {
    Ok(match byte {
        0x01 => Reason::Spam,
        0x02 => Reason::Harassment,
        0x03 => Reason::Illegal,
        0x04 => Reason::Rules,
        0x05 => Reason::Other,
        _ => return Err(Error::Malformed),
    })
}

fn report_key(community_id: &[u8; 32], id: &[u8; 32]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(community_id);
    key[32..].copy_from_slice(id);
    key
}

/// What a report leaves to send: the encoded `QueueAddress` of the report
/// queue of the role holder, and the sealed `ReportRecord`.
pub struct ReportSend {
    /// The report queue.
    pub address: Vec<u8>,
    /// The record.
    pub record: Vec<u8>,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Seals a report of one post to one entry of the roster that the
    /// device CSPRNG selects (`COM-268`, `COM-270`). `note` is UTF-8 text of
    /// `REPORT_NOTE_MAX` bytes at the most.
    pub fn prepare_community_report<R: CryptoRng + ?Sized>(
        &self,
        community_id: &[u8; 32],
        post_key: &[u8; 32],
        reason: u8,
        note: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<ReportSend, Error> {
        let reason = reason_of(reason)?;
        if note.len() > REPORT_NOTE_MAX {
            return Err(Error::TooLong);
        }
        let note = core::str::from_utf8(note).map_err(|_| Error::Malformed)?;
        let view = self.community_view_of(community_id, now_ms / 1_000)?;
        let post = view
            .posts
            .iter()
            .find(|post| post.hash == *post_key)
            .ok_or(Error::NotFound)?;
        let report = CommunityReport {
            community_id: *community_id,
            pseudonym: post.pseudonym,
            index: post.index,
            post_hash: post.hash,
            reason,
            note: note.into(),
        };
        let verifier = report::select_verifier(&view.roster, rng).ok_or(Error::NotFound)?;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = report::seal(verifier, &report, msg_id, now_ms, rng)?;
        Ok(ReportSend {
            address: verifier.report_queue.to_vec(),
            record,
        })
    }

    /// Opens a report record that reached a report queue of this device,
    /// under the role of each community that this device holds one of.
    /// A record that no role opens goes with no signal (`COM-282`). The
    /// result says whether a report entered.
    pub fn on_community_report<R: CryptoRng + ?Sized>(
        &mut self,
        record: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let mut opened = None;
        {
            let store = &self.open_ref()?.store;
            for (owner, plain) in store.list(COMMUNITY, None)? {
                let row = CommunityRow::parse(&Zeroizing::new(plain))?;
                let Some(seed) = row.role_seed.as_ref() else {
                    continue;
                };
                let role = RoleIdentity::from_seed(seed);
                if let Ok(report) = report::open(&role, record) {
                    if report.community_id == row.community_id {
                        opened = Some((owner, report));
                        break;
                    }
                }
            }
        }
        let Some((owner, report)) = opened else {
            return Ok(false);
        };
        let encoded = report.encode()?;
        let id = sha3_256(&[&encoded]);
        let mut value = Vec::with_capacity(8 + encoded.len());
        value.extend_from_slice(&now.to_be_bytes());
        value.extend_from_slice(&encoded);
        let open = self.open_mut()?;
        let row_id = open
            .store
            .row_id(COMMUNITY_REPORT, &report_key(&report.community_id, &id));
        let mut batch = open.store.begin();
        batch.put(COMMUNITY_REPORT, row_id, Some(owner), &value, rng)?;
        batch.commit()?;
        Ok(true)
    }

    fn held_reports(&self, community_id: &[u8; 32]) -> Result<Vec<HeldReport>, Error> {
        let store = &self.open_ref()?.store;
        let owner = store.row_id(COMMUNITY, community_id);
        let mut out = Vec::new();
        for (row_id, plain) in store.list(COMMUNITY_REPORT, Some(&owner))? {
            let (at, encoded) = plain.split_at_checked(8).ok_or(Error::Integrity)?;
            let at = u64::from_be_bytes(at.try_into().map_err(|_| Error::Integrity)?);
            let report = CommunityReport::parse(encoded).map_err(|_| Error::Integrity)?;
            out.push((row_id, sha3_256(&[encoded]), at, report));
        }
        Ok(out)
    }

    /// The reports of a community to show. A report shows when the view
    /// holds its post with the same hash (`COM-283`, `COM-290`). A report
    /// whose post differs goes (`COM-284`), one whose post a moderation
    /// epoch removed goes, and one that waited `REPORT_HOLD` for its post
    /// goes (`COM-285`, `COM-291`).
    pub fn community_reports(
        &mut self,
        community_id: &[u8; 32],
        now: u64,
    ) -> Result<Vec<ReportInfo>, Error> {
        let view = self.community_view_of(community_id, now)?;
        let mut shown = Vec::new();
        let mut gone = Vec::new();
        for (row_id, id, at, report) in self.held_reports(community_id)? {
            let at_pair = view
                .posts
                .iter()
                .find(|post| post.pseudonym == report.pseudonym && post.index == report.index);
            match at_pair {
                Some(post) if post.hash == report.post_hash && !post.is_removed => {
                    shown.push(ReportInfo {
                        id,
                        post_key: post.hash,
                        reason: report.reason as u8,
                        has_note: !report.note.is_empty(),
                        at,
                    });
                }
                Some(_) => gone.push(row_id),
                None if now.saturating_sub(at) >= REPORT_HOLD => gone.push(row_id),
                None => {}
            }
        }
        if !gone.is_empty() {
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for row_id in gone {
                batch.delete(COMMUNITY_REPORT, row_id);
            }
            batch.commit()?;
        }
        shown.sort_by_key(|report| report.at);
        Ok(shown)
    }

    /// Writes the note of a report into `sink`.
    pub fn render_community_report_note(
        &self,
        community_id: &[u8; 32],
        id: &[u8; 32],
        sink: &mut dyn crate::Sink,
    ) -> Result<(), Error> {
        let (_, _, _, report) = self
            .held_reports(community_id)?
            .into_iter()
            .find(|(_, held, _, _)| held == id)
            .ok_or(Error::NotFound)?;
        let mut units = Zeroizing::new(Vec::with_capacity(report.note.len()));
        units.extend(report.note.encode_utf16());
        sink.put(&units);
        Ok(())
    }

    /// Dismisses a report: the role holder read it.
    pub fn dismiss_community_report(
        &mut self,
        community_id: &[u8; 32],
        id: &[u8; 32],
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row_id = open
            .store
            .row_id(COMMUNITY_REPORT, &report_key(community_id, id));
        let mut batch = open.store.begin();
        batch.delete(COMMUNITY_REPORT, row_id);
        Ok(batch.commit()?)
    }
}
