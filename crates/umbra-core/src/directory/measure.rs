//! The measurement of Part 10 §10.2 and §10.3: the certificate of a
//! measurer, the content of a `MEAS_OPEN` cell, the result of a class test,
//! and the class that a directory authority lists from the results.

use alloc::vec::Vec;

use umbra_crypto::{
    labels,
    rand_core::TryCryptoRng,
    sign::{Signature, SigningKey, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::codec::Reader;

use super::{
    root::{AuthoritySig, DirectoryKeySet},
    AUTHORITY_COUNT, MEASURER_REVOKE_MAX,
};
use crate::Error;

/// `MEASURER_CERT_TTL`: the longest life of a certificate, in consensus
/// epochs (`REL-070`).
pub const MEASURER_CERT_TTL: u64 = 168;
/// The valid signatures that a certificate needs (`REL-103`).
pub const MEASURER_SIGNATURES: usize = 2;
/// The rate of each class C0 to C3, in bits each second (§10.2).
pub const CLASS_RATES: [u64; 4] = [100_000_000, 250_000_000, 500_000_000, 1_000_000_000];
/// The capacity that a class test needs: this many quarters of the rate of
/// the class, which is 2.25 times that rate (§10.3).
pub const CAPACITY_QUARTERS: u64 = 9;
/// The length of a slot, in seconds (§10.3).
pub const SLOT_SECONDS: u64 = 30;
/// `MEAS_SESSION_MAX`: the time after which a relay ends a measurement
/// session, in seconds. It is the slot and a margin of 15 s.
pub const MEAS_SESSION_MAX: u64 = 45;
/// `MEAS_SESSIONS_MAX`: the measurement sessions that one relay holds at
/// once.
pub const MEAS_SESSIONS_MAX: usize = 4;
/// `MEAS_CIRCUITS_MAX`: the circuits of one measurement session.
pub const MEAS_CIRCUITS_MAX: usize = 16;
/// `MEAS_ATTEMPT_BURST`: the measurement attempts that one address holds
/// (`REL-069`).
pub const MEAS_ATTEMPT_BURST: u32 = 16;
/// `MEAS_ATTEMPT_PERIOD`: the seconds after which a spent attempt comes
/// back (`REL-069`).
pub const MEAS_ATTEMPT_PERIOD: u64 = 60;
/// `CLUSTER_FULL`: the largest cluster that one slot measures in full
/// (`REL-099`).
pub const CLUSTER_FULL: usize = 4;
/// `CLUSTER_SAMPLE`: the relays of a larger cluster in one slot
/// (`REL-100`).
pub const CLUSTER_SAMPLE: usize = 4;
/// The 7-day epoch of the class growth cap, in consensus epochs
/// (`REL-001`).
pub const CLASS_STEP_EPOCHS: u64 = 168;

/// The fixed part of a `MeasurerCert`, before `sig_count`.
const CERT_FIXED_LEN: usize = 1 + 16 + VERIFYING_KEY_LEN + 8;

/// The key set, the revoked list, and the epoch under which a relay
/// accepts a certificate (`REL-066`, `REL-067`, `REL-104`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeasurerTrust {
    /// The canonical `DirectoryKeySet` of the current root.
    pub keyset: Vec<u8>,
    /// `revoked` of the current root.
    pub revoked: Vec<[u8; 16]>,
}

/// The certificate of a measurer (§10.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurerCert<'a> {
    /// The identifier that the `revoked` list names.
    pub measurer_id: [u8; 16],
    /// The ML-DSA-65 key of the measurer.
    pub mldsa_pk: &'a [u8],
    /// The consensus epoch after which the certificate is void.
    pub not_after: u64,
    /// The signatures of the authorities, in ascending order of index.
    pub sigs: Vec<AuthoritySig<'a>>,
}

fn cert_preimage(measurer_id: &[u8; 16], mldsa_pk: &[u8], not_after: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(labels::MEASURER_CERT.len() + CERT_FIXED_LEN);
    out.extend_from_slice(labels::MEASURER_CERT);
    out.push(0x01);
    out.extend_from_slice(measurer_id);
    out.extend_from_slice(mldsa_pk);
    out.extend_from_slice(&not_after.to_be_bytes());
    out
}

/// Issues a certificate for the key `mldsa_pk` at the consensus epoch
/// `epoch`, void after `lifetime` epochs, under the key of each authority
/// of `signers` (`REL-070`, `REL-103`).
pub fn issue_cert<R: TryCryptoRng + ?Sized>(
    measurer_id: [u8; 16],
    mldsa_pk: &[u8],
    epoch: u64,
    lifetime: u64,
    signers: &[(u8, &SigningKey)],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let unordered = signers
        .windows(2)
        .any(|pair| matches!(pair, [one, other] if one.0 >= other.0));
    if lifetime > MEASURER_CERT_TTL
        || mldsa_pk.len() != VERIFYING_KEY_LEN
        || !(MEASURER_SIGNATURES..=AUTHORITY_COUNT).contains(&signers.len())
        || unordered
    {
        return Err(Error::Malformed);
    }
    let not_after = epoch.checked_add(lifetime).ok_or(Error::Malformed)?;
    let preimage = cert_preimage(&measurer_id, mldsa_pk, not_after);
    let mut out = preimage
        .get(labels::MEASURER_CERT.len()..)
        .ok_or(Error::Malformed)?
        .to_vec();
    out.push(u8::try_from(signers.len()).map_err(|_| Error::Malformed)?);
    for (index, key) in signers {
        out.push(*index);
        out.extend_from_slice(&key.sign(&preimage, rng)?.to_bytes());
    }
    Ok(out)
}

impl<'a> MeasurerCert<'a> {
    /// Reads a certificate from the front of `bytes`, and returns the bytes
    /// that it took. The signatures are checked by [`MeasurerCert::verify`].
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let measurer_id = r.array()?;
        let mldsa_pk = r.take(VERIFYING_KEY_LEN)?;
        let not_after = u64::from_be_bytes(r.array()?);
        let count = usize::from(r.u8()?);
        if !(MEASURER_SIGNATURES..=AUTHORITY_COUNT).contains(&count) {
            return Err(Error::Malformed);
        }
        let mut sigs = Vec::with_capacity(count);
        let mut last: Option<u8> = None;
        for _ in 0..count {
            let authority_index = r.u8()?;
            // One canonical form, and no authority counts two times.
            if last.is_some_and(|l| l >= authority_index) {
                return Err(Error::Malformed);
            }
            last = Some(authority_index);
            sigs.push(AuthoritySig {
                authority_index,
                sig: r.take(SIGNATURE_LEN)?,
            });
        }
        Ok((
            MeasurerCert {
                measurer_id,
                mldsa_pk,
                not_after,
                sigs,
            },
            r.position(),
        ))
    }

    /// Verifies the certificate at the consensus epoch `epoch` under
    /// `keyset`, with the `revoked` list of the current root (`REL-066`,
    /// `REL-067`, `REL-103`, `REL-104`).
    pub fn verify(
        &self,
        keyset: &DirectoryKeySet<'_>,
        revoked: &[[u8; 16]],
        epoch: u64,
    ) -> Result<(), Error> {
        if self.not_after < epoch {
            return Err(Error::Stale);
        }
        if revoked.len() > MEASURER_REVOKE_MAX || revoked.contains(&self.measurer_id) {
            return Err(Error::Unverified);
        }
        let preimage = cert_preimage(&self.measurer_id, self.mldsa_pk, self.not_after);
        let mut valid = 0usize;
        for s in &self.sigs {
            if keyset
                .verify_by(s.authority_index, &preimage, s.sig)
                .is_ok()
            {
                valid = valid.saturating_add(1);
            }
        }
        if valid >= MEASURER_SIGNATURES {
            Ok(())
        } else {
            Err(Error::Unverified)
        }
    }
}

fn open_preimage(relay_id: &[u8; 32], circ_id: &[u8; 16]) -> Vec<u8> {
    [labels::MEASURER_OPEN, relay_id.as_slice(), circ_id].concat()
}

/// The content of a `MEAS_OPEN` cell: the certificate `cert`, and the
/// signature of `key` over the relay under test and the circuit
/// (`REL-065`).
pub fn open_content<R: TryCryptoRng + ?Sized>(
    cert: &[u8],
    key: &SigningKey,
    relay_id: &[u8; 32],
    circ_id: &[u8; 16],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let sig = key.sign(&open_preimage(relay_id, circ_id), rng)?;
    Ok([cert, sig.to_bytes().as_slice()].concat())
}

/// Verifies the content of a `MEAS_OPEN` cell that the relay `relay_id`
/// took on the circuit `circ_id` at the consensus epoch `epoch`, and
/// returns the `measurer_id`.
///
/// The signature of the measurer runs first. A cell under a key that the
/// sender made thus costs one verification and no more of them than a cell
/// under a certificate.
pub fn verify_open(
    content: &[u8],
    trust: &MeasurerTrust,
    epoch: u64,
    relay_id: &[u8; 32],
    circ_id: &[u8; 16],
) -> Result<[u8; 16], Error> {
    let (cert, used) = MeasurerCert::parse(content)?;
    let sig = content.get(used..).ok_or(Error::Malformed)?;
    if sig.len() != SIGNATURE_LEN {
        return Err(Error::Malformed);
    }
    let (keyset, _) = DirectoryKeySet::parse(&trust.keyset)?;
    if cert.not_after < epoch {
        return Err(Error::Stale);
    }
    if trust.revoked.contains(&cert.measurer_id) {
        return Err(Error::Unverified);
    }
    let key = VerifyingKey::from_bytes(cert.mldsa_pk)?;
    key.verify(
        &open_preimage(relay_id, circ_id),
        &Signature::from_bytes(sig)?,
    )?;
    cert.verify(&keyset, &trust.revoked, epoch)?;
    Ok(cert.measurer_id)
}

/// The capacity that a test of `class` needs, in bits each second.
pub fn capacity_needed(class: u8) -> Option<u64> {
    CLASS_RATES
        .get(usize::from(class))
        .map(|rate| rate.saturating_mul(CAPACITY_QUARTERS) / 4)
}

/// The result of one class test: one line of the results file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassResult {
    /// The relay.
    pub relay_id: [u8; 32],
    /// The class of the test, 0 to 3.
    pub class: u8,
    /// Whether the relay held the rate of the class.
    pub passed: bool,
    /// The consensus epoch of the slot.
    pub epoch: u64,
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl ClassResult {
    /// Reads the line `<relay_id in hex> <class> <pass|fail> <epoch>`.
    pub fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split_ascii_whitespace();
        let id = fields.next()?.as_bytes();
        if id.len() != 64 {
            return None;
        }
        let mut relay_id = [0u8; 32];
        for (byte, [high, low]) in relay_id.iter_mut().zip(id.as_chunks::<2>().0) {
            *byte = hex_digit(*high)? << 4 | hex_digit(*low)?;
        }
        let class: u8 = fields.next()?.parse().ok()?;
        let passed = match fields.next()? {
            "pass" => true,
            "fail" => false,
            _ => return None,
        };
        let epoch = fields.next()?.parse().ok()?;
        if class > 3 || fields.next().is_some() {
            return None;
        }
        Some(ClassResult {
            relay_id,
            class,
            passed,
            epoch,
        })
    }

    /// Writes the line, with no line end.
    pub fn line(&self) -> alloc::string::String {
        use core::fmt::Write;
        let mut out = alloc::string::String::with_capacity(96);
        for byte in &self.relay_id {
            let _ = write!(out, "{byte:02x}");
        }
        let word = if self.passed { "pass" } else { "fail" };
        let _ = write!(out, " {} {word} {}", self.class, self.epoch);
        out
    }
}

/// The class that the results verify for the relay `relay_id` whose
/// operator declares `declared`, or none for a relay below C0 (`REL-197`).
///
/// A failed test at a class is evidence against that class and each one
/// above it, until a newer test at that class or above passes. A class with
/// no evidence against it stays as declared: this is the rule of a
/// provisional directory (§10.2).
pub fn verified_class(relay_id: &[u8; 32], declared: u8, results: &[ClassResult]) -> Option<u8> {
    let own = || results.iter().filter(|result| result.relay_id == *relay_id);
    let lowest_failed = own()
        .filter(|failed| !failed.passed)
        .filter(|failed| {
            !own().any(|passed| {
                passed.passed && passed.class >= failed.class && passed.epoch > failed.epoch
            })
        })
        .map(|failed| failed.class)
        .min();
    match lowest_failed {
        None => Some(declared.min(3)),
        Some(0) => None,
        Some(failed) => Some(declared.min(failed - 1)),
    }
}

/// The class of one relay in the listing, and the consensus epoch of its
/// last step up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Staged {
    /// The listed class.
    pub class: u8,
    /// The epoch of the last increase, or of the first listing.
    pub stepped_at: u64,
}

/// The class to list at `epoch` for a relay that `verified` verifies, from
/// the class `before` of the last listing. A demotion applies at once
/// (`REL-095`, `REL-096`), and the class rises by one step in each 7-day
/// epoch at most (`REL-001`). A relay with no listing before takes the
/// verified class.
pub fn staged_class(before: Option<Staged>, verified: u8, epoch: u64) -> Staged {
    match before {
        None => Staged {
            class: verified,
            stepped_at: epoch,
        },
        Some(before) if verified <= before.class => Staged {
            class: verified,
            stepped_at: before.stepped_at,
        },
        Some(before) if epoch.saturating_sub(before.stepped_at) >= CLASS_STEP_EPOCHS => Staged {
            class: before.class.saturating_add(1),
            stepped_at: epoch,
        },
        Some(before) => before,
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
    use crate::directory::{authority::keyset_bytes, descriptor::tests::Rng};
    use umbra_crypto::secret::Secret;

    fn keys() -> Vec<SigningKey> {
        (0..7u8)
            .map(|index| SigningKey::from_seed(Secret::new([index + 1; 32])))
            .collect()
    }

    fn measurer() -> SigningKey {
        SigningKey::from_seed(Secret::new([0x55; 32]))
    }

    fn cert(keys: &[SigningKey], signers: &[u8], epoch: u64, lifetime: u64) -> Vec<u8> {
        let signers: Vec<(u8, &SigningKey)> = signers
            .iter()
            .map(|index| (*index, &keys[usize::from(*index)]))
            .collect();
        issue_cert(
            [7; 16],
            &measurer().verifying_key().to_bytes(),
            epoch,
            lifetime,
            &signers,
            &mut Rng(1),
        )
        .unwrap()
    }

    #[test]
    fn a_certificate_of_two_authorities_verifies_and_has_the_width_of_the_text() {
        let keys = keys();
        let keyset = keyset_bytes(&keys, 1).unwrap();
        let (keyset, _) = DirectoryKeySet::parse(&keyset).unwrap();
        let bytes = cert(&keys, &[0, 3], 500, MEASURER_CERT_TTL);
        // §10.3.1: 8 598 bytes at two signatures.
        assert_eq!(bytes.len(), 8_598);
        let (parsed, used) = MeasurerCert::parse(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(parsed.not_after, 668);
        assert_eq!(parsed.verify(&keyset, &[], 500), Ok(()));
        assert_eq!(parsed.verify(&keyset, &[], 668), Ok(()));
        assert_eq!(cert(&keys, &[0, 1, 2, 3, 4, 5, 6], 500, 1).len(), 25_148);
    }

    #[test]
    fn a_certificate_of_one_authority_fails() {
        let keys = keys();
        let keyset = keyset_bytes(&keys, 1).unwrap();
        let (keyset, _) = DirectoryKeySet::parse(&keyset).unwrap();
        // REL-103: the issue refuses one signer, and a parser refuses the
        // count.
        let one = [(0u8, &keys[0])];
        let pk = measurer().verifying_key().to_bytes();
        assert_eq!(
            issue_cert([7; 16], &pk, 500, 1, &one, &mut Rng(1)),
            Err(Error::Malformed)
        );
        let mut bytes = cert(&keys, &[0, 3], 500, 1);
        let count_at = CERT_FIXED_LEN;
        bytes[count_at] = 1;
        bytes.truncate(count_at + 1 + 1 + SIGNATURE_LEN);
        assert_eq!(MeasurerCert::parse(&bytes), Err(Error::Malformed));
        // Two entries, of which one signature is of another key: one valid
        // signature is not two.
        let mut bytes = cert(&keys, &[0, 3], 500, 1);
        bytes[count_at + 1 + 1 + SIGNATURE_LEN] = 4;
        let (parsed, _) = MeasurerCert::parse(&bytes).unwrap();
        assert_eq!(parsed.verify(&keyset, &[], 500), Err(Error::Unverified));
    }

    #[test]
    fn a_certificate_past_its_epoch_fails() {
        let keys = keys();
        let keyset = keyset_bytes(&keys, 1).unwrap();
        let (keyset, _) = DirectoryKeySet::parse(&keyset).unwrap();
        let bytes = cert(&keys, &[1, 2], 500, 10);
        let (parsed, _) = MeasurerCert::parse(&bytes).unwrap();
        // REL-067.
        assert_eq!(parsed.verify(&keyset, &[], 510), Ok(()));
        assert_eq!(parsed.verify(&keyset, &[], 511), Err(Error::Stale));
        // REL-070: no issue above the TTL.
        let pk = measurer().verifying_key().to_bytes();
        let signers = [(1u8, &keys[1]), (2u8, &keys[2])];
        assert_eq!(
            issue_cert(
                [7; 16],
                &pk,
                500,
                MEASURER_CERT_TTL + 1,
                &signers,
                &mut Rng(1)
            ),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn a_revoked_certificate_fails() {
        let keys = keys();
        let keyset = keyset_bytes(&keys, 1).unwrap();
        let (keyset, _) = DirectoryKeySet::parse(&keyset).unwrap();
        let bytes = cert(&keys, &[1, 2], 500, 10);
        let (parsed, _) = MeasurerCert::parse(&bytes).unwrap();
        // REL-104.
        assert_eq!(parsed.verify(&keyset, &[[8; 16]], 500), Ok(()));
        assert_eq!(
            parsed.verify(&keyset, &[[8; 16], [7; 16]], 500),
            Err(Error::Unverified)
        );
    }

    #[test]
    fn one_authority_two_times_fails() {
        let keys = keys();
        // REL-103: two signatures of one authority are one decision.
        let pk = measurer().verifying_key().to_bytes();
        let twice = [(2u8, &keys[2]), (2u8, &keys[2])];
        assert_eq!(
            issue_cert([7; 16], &pk, 500, 1, &twice, &mut Rng(1)),
            Err(Error::Malformed)
        );
        let mut bytes = cert(&keys, &[2, 3], 500, 1);
        let second = CERT_FIXED_LEN + 1 + 1 + SIGNATURE_LEN;
        let first_sig = bytes[CERT_FIXED_LEN + 2..second].to_vec();
        bytes[second] = 2;
        bytes[second + 1..].copy_from_slice(&first_sig);
        assert_eq!(MeasurerCert::parse(&bytes), Err(Error::Malformed));
    }

    #[test]
    fn an_open_binds_the_relay_and_the_circuit() {
        let keys = keys();
        let trust = MeasurerTrust {
            keyset: keyset_bytes(&keys, 1).unwrap(),
            revoked: Vec::new(),
        };
        let bytes = cert(&keys, &[0, 1], 500, 10);
        let content =
            open_content(&bytes, &measurer(), &[0x11; 32], &[0xA0; 16], &mut Rng(2)).unwrap();
        // §10.3.1: 11 907 bytes at two signatures.
        assert_eq!(content.len(), 8_598 + SIGNATURE_LEN);
        assert_eq!(
            verify_open(&content, &trust, 500, &[0x11; 32], &[0xA0; 16]),
            Ok([7; 16])
        );
        // The relay under test cannot open a session at another relay with
        // the cell that it took, and no party moves it to another circuit.
        assert_eq!(
            verify_open(&content, &trust, 500, &[0x12; 32], &[0xA0; 16]),
            Err(Error::Unverified)
        );
        assert_eq!(
            verify_open(&content, &trust, 500, &[0x11; 32], &[0xA1; 16]),
            Err(Error::Unverified)
        );
        let revoked = MeasurerTrust {
            revoked: alloc::vec![[7; 16]],
            ..trust.clone()
        };
        assert_eq!(
            verify_open(&content, &revoked, 500, &[0x11; 32], &[0xA0; 16]),
            Err(Error::Unverified)
        );
        assert_eq!(
            verify_open(&content, &trust, 511, &[0x11; 32], &[0xA0; 16]),
            Err(Error::Stale)
        );
        // A signature of another key than the one of the certificate.
        let other = SigningKey::from_seed(Secret::new([0x56; 32]));
        let content = open_content(&bytes, &other, &[0x11; 32], &[0xA0; 16], &mut Rng(2)).unwrap();
        assert_eq!(
            verify_open(&content, &trust, 500, &[0x11; 32], &[0xA0; 16]),
            Err(Error::Unverified)
        );
    }

    #[test]
    fn a_result_line_reads_back() {
        let result = ClassResult {
            relay_id: [0xAB; 32],
            class: 2,
            passed: false,
            epoch: 490_000,
        };
        let line = result.line();
        assert_eq!(ClassResult::parse(&line), Some(result));
        assert_eq!(ClassResult::parse("ab 2 fail 1"), None);
        assert_eq!(ClassResult::parse(&line.replace("fail", "maybe")), None);
        assert_eq!(ClassResult::parse(&line.replace(" 2 ", " 4 ")), None);
    }

    #[test]
    fn the_results_verify_a_class() {
        let id = [1u8; 32];
        let result = |class, passed, epoch| ClassResult {
            relay_id: id,
            class,
            passed,
            epoch,
        };
        // No result: the declared class stays.
        assert_eq!(verified_class(&id, 2, &[]), Some(2));
        // A result of another relay is no evidence.
        let other = ClassResult {
            relay_id: [2; 32],
            ..result(0, false, 9)
        };
        assert_eq!(verified_class(&id, 2, &[other]), Some(2));
        // A pass at C0 confirms C0, and no test ran above it.
        assert_eq!(verified_class(&id, 2, &[result(0, true, 5)]), Some(2));
        // A failed test at C1 leaves C0.
        assert_eq!(verified_class(&id, 2, &[result(1, false, 5)]), Some(0));
        // REL-197: a failed test at C0 removes the relay.
        assert_eq!(verified_class(&id, 2, &[result(0, false, 5)]), None);
        // The newest evidence decides.
        let healed = [result(1, false, 5), result(1, true, 6)];
        assert_eq!(verified_class(&id, 2, &healed), Some(2));
        let failed = [result(1, true, 5), result(1, false, 6)];
        assert_eq!(verified_class(&id, 2, &failed), Some(0));
        // A newer pass above a failed class is evidence for that class.
        let above = [result(0, false, 5), result(2, true, 6)];
        assert_eq!(verified_class(&id, 2, &above), Some(2));
        // The declared class is the upper bound (`REL-129`).
        assert_eq!(verified_class(&id, 1, &[result(3, true, 5)]), Some(1));
    }

    #[test]
    fn a_class_rises_one_step_in_one_epoch_and_falls_at_once() {
        let listed = Staged {
            class: 0,
            stepped_at: 1_000,
        };
        // REL-001: the results verify C2, and the listing takes one step
        // when 7 days passed since the last one.
        assert_eq!(staged_class(Some(listed), 2, 1_167), listed);
        let one = staged_class(Some(listed), 2, 1_168);
        assert_eq!(
            one,
            Staged {
                class: 1,
                stepped_at: 1_168
            }
        );
        assert_eq!(staged_class(Some(one), 2, 1_169), one);
        assert_eq!(staged_class(Some(one), 2, 1_335), one);
        let two = staged_class(Some(one), 2, 1_336);
        assert_eq!(two.class, 2);
        assert_eq!(staged_class(Some(two), 2, 9_000), two);
        // REL-095, REL-096: a demotion takes each step at once.
        let fallen = staged_class(Some(two), 0, 1_337);
        assert_eq!(
            fallen,
            Staged {
                class: 0,
                stepped_at: 1_336
            }
        );
        // A first listing takes the verified class.
        assert_eq!(staged_class(None, 3, 77).class, 3);
    }

    #[test]
    fn the_capacity_of_a_test_is_two_and_a_quarter_times_the_class() {
        assert_eq!(capacity_needed(0), Some(225_000_000));
        assert_eq!(capacity_needed(1), Some(562_500_000));
        assert_eq!(capacity_needed(2), Some(1_125_000_000));
        assert_eq!(capacity_needed(3), Some(2_250_000_000));
        assert_eq!(capacity_needed(4), None);
    }
}
