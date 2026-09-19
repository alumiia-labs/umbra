//! The abuse report of a community (Part 12 §12.5.1, §12.5.3): the report
//! object, the record that seals it to one role holder, the uniform choice
//! of that role holder, and the hold of a report whose post the chain does
//! not show yet.

use alloc::{string::String, vec::Vec};

use umbra_crypto::{
    aead,
    hkdf::Hkdf,
    kem::{self, Ciphertext, PublicKey, CIPHERTEXT_LEN},
    labels,
    rand_core::CryptoRng,
    secret::Secret,
    sha3::Sha3_256,
};
use umbra_wire::{
    app::{AppKind, AppMessage, Channel},
    codec::{Reader, Writer},
};

use super::{
    control::RosterEntry, identity::RoleIdentity, record::post_hash, RecordType, REPORT_HOLD,
    REPORT_NOTE_MAX, VERSION,
};
use crate::Error;

/// The L6 record kind of a report record (Part 6 §6.4.2).
pub const L6_KIND_REPORT: u8 = 0x03;
/// The bytes of a report record before the ciphertext.
pub const REPORT_RECORD_HEADER: usize = CIPHERTEXT_LEN + 12;

/// The closed list of causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    /// Spam.
    Spam = 0x01,
    /// Harassment.
    Harassment = 0x02,
    /// Illegal content.
    Illegal = 0x03,
    /// A breach of the community rules.
    Rules = 0x04,
    /// Other.
    Other = 0x05,
}

/// A `CommunityReport`. It names a post and a cause, and no field names
/// the reporter (`COM-272`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityReport {
    /// The community.
    pub community_id: [u8; 32],
    /// The authoring pseudonym of the reported post.
    pub pseudonym: [u8; 32],
    /// The index of that post.
    pub index: u32,
    /// `SHA3-256` of the encoded post.
    pub post_hash: [u8; 32],
    /// The cause.
    pub reason: Reason,
    /// The note, 0 to `REPORT_NOTE_MAX` bytes.
    pub note: String,
}

impl CommunityReport {
    /// Encodes the report.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.note.len() > REPORT_NOTE_MAX {
            return Err(Error::Malformed);
        }
        let mut out = alloc::vec![0u8; 104 + self.note.len()];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u8(RecordType::Report as u8)?;
        w.put(&self.community_id)?;
        w.put(&self.pseudonym)?;
        w.u32(self.index)?;
        w.put(&self.post_hash)?;
        w.u8(self.reason as u8)?;
        w.u8(u8::try_from(self.note.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.note.as_bytes())?;
        Ok(out)
    }

    /// Reads a report.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION || r.u8()? != RecordType::Report as u8 {
            return Err(Error::Malformed);
        }
        let community_id = r.array()?;
        let pseudonym = r.array()?;
        let index = r.u32()?;
        let post_hash = r.array()?;
        let reason = match r.u8()? {
            0x01 => Reason::Spam,
            0x02 => Reason::Harassment,
            0x03 => Reason::Illegal,
            0x04 => Reason::Rules,
            0x05 => Reason::Other,
            _ => return Err(Error::Malformed),
        };
        let note_len = usize::from(r.u8()?);
        if note_len > REPORT_NOTE_MAX {
            return Err(Error::Malformed);
        }
        let note = core::str::from_utf8(r.take(note_len)?)
            .map_err(|_| Error::Malformed)?
            .into();
        r.finish()?;
        Ok(CommunityReport {
            community_id,
            pseudonym,
            index,
            post_hash,
            reason,
            note,
        })
    }
}

/// Selects one entry of the current roster with the same probability for
/// each (`COM-268`, `COM-287`, `COM-269`). A rejected draw removes the bias
/// of the remainder.
pub fn select_verifier<'a, R: CryptoRng + ?Sized>(
    roster: &'a [RosterEntry],
    rng: &mut R,
) -> Option<&'a RosterEntry> {
    let count = u8::try_from(roster.len()).ok().filter(|n| *n > 0)?;
    let bound = u8::MAX - (u8::MAX % count);
    loop {
        let mut draw = [0u8; 1];
        rng.fill_bytes(&mut draw);
        let [value] = draw;
        if value < bound {
            return roster.get(usize::from(value % count));
        }
    }
}

fn report_key(shared_secret: &Secret<32>) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(Some(labels::REPORT_KEY), shared_secret.expose());
    let mut key = Secret::<32>::zeroed();
    // 32 bytes is below the HKDF bound, thus expand cannot fail.
    let _ = kdf.expand(&[], key.expose_mut());
    key
}

/// Seals a report to the `report_ek` of `verifier`. The result is the L6
/// plaintext of kind `0x03` after the kind byte, which the reporter sends
/// in bucket `B1` to the report queue of that entry (`COM-266`, `COM-270`,
/// `COM-271`).
pub fn seal<R: CryptoRng + ?Sized>(
    verifier: &RosterEntry,
    report: &CommunityReport,
    msg_id: [u8; 16],
    sent_at: u64,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    // COM-153: the key is a UMBRA-KEM key, and an ML-DSA key does not parse.
    let report_ek = PublicKey::from_bytes(&verifier.report_ek)?;
    let body = report.encode()?;
    let message = AppMessage {
        kind: AppKind::CommunityRecord,
        msg_id,
        sent_at,
        body: &body,
    };
    let (ct, shared_secret) = kem::encapsulate(&report_ek, rng);
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let mut out = alloc::vec![0u8; REPORT_RECORD_HEADER + message.len() + aead::TAG_LEN];
    let (header, rest) = out.split_at_mut(REPORT_RECORD_HEADER);
    let mut w = Writer::new(header);
    w.put(ct.as_bytes())?;
    w.put(&nonce)?;
    let (plain, tag_slot) = rest.split_at_mut(message.len());
    message.encode(plain)?;
    let tag = aead::seal_ietf(&report_key(&shared_secret), &nonce, ct.as_bytes(), plain)?;
    tag_slot.copy_from_slice(&tag);
    Ok(out)
}

/// Opens a report record with `RoleReportKey_r`. A record that fails one
/// step is discarded without a signal, thus each failure is one error
/// (`COM-281`, `COM-289`, `COM-282`).
pub fn open(role: &RoleIdentity, record: &[u8]) -> Result<CommunityReport, Error> {
    let mut r = Reader::new(record);
    let ct = Ciphertext::from_bytes(r.take(CIPHERTEXT_LEN)?)?;
    let nonce: [u8; 12] = r.array()?;
    let rest = r.rest();
    let split = rest
        .len()
        .checked_sub(aead::TAG_LEN)
        .ok_or(Error::Malformed)?;
    let (sealed, tag) = rest.split_at(split);
    let mut plain = sealed.to_vec();
    let shared_secret = role.report_key().decapsulate(&ct)?;
    aead::open_ietf(
        &report_key(&shared_secret),
        &nonce,
        ct.as_bytes(),
        &mut plain,
        tag,
    )?;
    let message = AppMessage::parse(&plain, Channel::Community)?;
    if message.kind != AppKind::CommunityRecord {
        return Err(Error::Malformed);
    }
    CommunityReport::parse(message.body)
}

/// The reports of one role holder that wait for their post (§12.5.3 rule
/// 9). A role holder forwards no report outside the roster (`COM-286`),
/// thus this type has no export.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeldReports {
    held: Vec<(CommunityReport, u64)>,
}

impl HeldReports {
    /// Holds a report that arrived at `now`.
    pub fn hold(&mut self, report: CommunityReport, now: u64) {
        self.held.push((report, now));
    }

    /// The count of the held reports.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether no report waits.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Compares each held report with the chain after a pull. `post_at`
    /// gives the encoded post at a pair, if the role holder fetched one.
    /// The result holds the reports to show. A report whose hash differs
    /// is discarded (`COM-284`), a report with no post waits (`COM-285`),
    /// and a report that waited `REPORT_HOLD` is discarded (`COM-291`).
    pub fn resolve<'p>(
        &mut self,
        post_at: impl Fn(&[u8; 32], u32) -> Option<&'p [u8]>,
        now: u64,
    ) -> Vec<CommunityReport> {
        let mut verified = Vec::new();
        let mut waiting = Vec::new();
        for (report, arrived_at) in self.held.drain(..) {
            match post_at(&report.pseudonym, report.index) {
                Some(post) if post_hash(post) == report.post_hash => verified.push(report),
                Some(_) => {}
                None if now.saturating_sub(arrived_at) < REPORT_HOLD => {
                    waiting.push((report, arrived_at));
                }
                None => {}
            }
        }
        self.held = waiting;
        verified
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use umbra_wire::bucket::Bucket;

    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        community::{
            control::{tests::entry, Role},
            test_util::role,
        },
    };

    fn report(note_len: usize) -> CommunityReport {
        CommunityReport {
            community_id: [9; 32],
            pseudonym: [1; 32],
            index: 4,
            post_hash: post_hash(b"the post"),
            reason: Reason::Harassment,
            note: "n".repeat(note_len),
        }
    }

    #[test]
    fn a_report_reaches_one_role_holder_and_no_other() {
        let full = report(REPORT_NOTE_MAX);
        assert_eq!(full.encode().unwrap().len(), 304);
        assert!(report(REPORT_NOTE_MAX + 1).encode().is_err());

        let verifier = entry(Role::Admin, 3);
        let record = seal(&verifier, &full, [5; 16], 1_000, &mut Rng(1)).unwrap();
        assert_eq!(record.len(), 1_482);
        assert!(
            record.len() < Bucket::B1.l6_record(),
            "the kind byte and the record fit B1"
        );
        assert_eq!(open(&role(3), &record).unwrap(), full);
        assert!(open(&role(4), &record).is_err());

        let mut changed = record.clone();
        changed[REPORT_RECORD_HEADER + 40] ^= 1;
        assert!(open(&role(3), &changed).is_err());
        assert!(open(&role(3), &record[..REPORT_RECORD_HEADER + 8]).is_err());
    }

    #[test]
    fn the_choice_of_the_verifier_is_uniform_over_the_roster() {
        let roster: Vec<RosterEntry> = (1..=3u8).map(|n| entry(Role::Admin, n)).collect();
        let mut rng = Rng(7);
        let mut counts = [0u32; 3];
        for _ in 0..600 {
            let chosen = select_verifier(&roster, &mut rng).unwrap();
            let position = roster
                .iter()
                .position(|e| e.pseudonym == chosen.pseudonym)
                .unwrap();
            counts[position] += 1;
        }
        assert!(counts.iter().all(|c| (150..=250).contains(c)), "{counts:?}");
        assert!(select_verifier(&[], &mut rng).is_none());
    }

    #[test]
    fn a_held_report_shows_after_its_post_matches_and_expires_without_one() {
        let mut held = HeldReports::default();
        held.hold(report(0), 100);
        let mut wrong = report(0);
        wrong.index = 5;
        held.hold(wrong, 100);
        let mut late = report(0);
        late.index = 6;
        held.hold(late, 100);

        let chain = |_: &[u8; 32], index: u32| -> Option<&'static [u8]> {
            match index {
                5 => Some(b"another post"),
                _ => None,
            }
        };
        assert!(held.resolve(chain, 200).is_empty());
        assert_eq!(held.len(), 2, "the report with a different hash is gone");

        let chain = |_: &[u8; 32], index: u32| -> Option<&'static [u8]> {
            (index == 4).then_some(b"the post".as_slice())
        };
        let shown = held.resolve(chain, 300);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].index, 4);
        assert_eq!(held.len(), 1);
        assert!(held.resolve(chain, 100 + REPORT_HOLD).is_empty());
        assert!(held.is_empty());
    }
}
