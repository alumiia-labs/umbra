//! The link certificate of a relay in pin form (Part 10 `REL-143`): one
//! self-signed X.509 certificate with an Ed25519 key.
//!
//! The descriptor of the relay carries the SHA3-256 of the certificate, and
//! a dialer accepts that certificate alone (Part 3 `NET-380`). Thus the
//! relay needs no DNS name and no certificate authority. The relay makes
//! the certificate one time and keeps it, because a new certificate needs a
//! new descriptor.

use std::{io::Write, path::Path};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use umbra_crypto::zeroize::Zeroizing;

/// The `AlgorithmIdentifier` of Ed25519 (RFC 8410 §3).
const ED25519: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
/// The `[0]` field that says X.509 version 3. The TLS stack reads the key
/// of no other version.
const VERSION_3: [u8; 5] = [0xA0, 0x03, 0x02, 0x01, 0x02];
/// The common name of the subject and of the issuer. No dialer reads it.
const COMMON_NAME: &[u8] = b"umbra relay link";
/// The start of the validity, as a `UTCTime`. A time of the clock would say
/// when the operator made the relay.
const NOT_BEFORE: &[u8] = b"250101000000Z";
/// The end of the validity, as a `GeneralizedTime`: the value of RFC 5280
/// §4.1.2.5 for a certificate with no end. The pin of the descriptor ends
/// the life of the certificate, and no date does.
const NOT_AFTER: &[u8] = b"99991231235959Z";
/// The `[3]` field with one extension: the critical `basicConstraints` of
/// an end-entity certificate.
const EXTENSIONS: [u8; 18] = [
    0xA3, 0x10, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02,
    0x30, 0x00,
];

/// A link certificate and its key.
pub struct LinkCertificate {
    /// The certificate, in DER.
    pub certificate: Vec<u8>,
    /// The key, as a PKCS#8 document in DER.
    pub key: Zeroizing<Vec<u8>>,
}

/// One DER value: the tag, the length, and the parts of the content.
fn der(tag: u8, parts: &[&[u8]]) -> Option<Vec<u8>> {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(len.saturating_add(4));

    out.push(tag);
    match len {
        0..=0x7F => out.push(u8::try_from(len).ok()?),
        0x80..=0xFF => out.extend_from_slice(&[0x81, u8::try_from(len).ok()?]),
        _ => {
            out.push(0x82);
            out.extend_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
        }
    }

    for part in parts {
        out.extend_from_slice(part);
    }
    Some(out)
}

/// The `Name` of the subject and of the issuer: one common name.
fn name() -> Option<Vec<u8>> {
    let common_name_oid = [0x06, 0x03, 0x55, 0x04, 0x03];
    let value = der(0x0C, &[COMMON_NAME])?;
    let attribute = der(0x30, &[&common_name_oid, &value])?;
    der(0x30, &[&der(0x31, &[&attribute])?])
}

/// The certificate of `key` with the serial number `serial`, signed by
/// `key`.
fn certificate_of(key: &Ed25519KeyPair, mut serial: [u8; 16]) -> Option<Vec<u8>> {
    // A DER integer with these two bits is positive and has no zero byte
    // at its start.
    if let Some(first) = serial.first_mut() {
        *first = (*first & 0x7F) | 0x40;
    }

    let name = name()?;
    let validity = der(
        0x30,
        &[&der(0x17, &[NOT_BEFORE])?, &der(0x18, &[NOT_AFTER])?],
    )?;
    let public_key = der(0x03, &[&[0], key.public_key().as_ref()])?;
    let key_info = der(0x30, &[&ED25519, &public_key])?;

    let to_be_signed = der(
        0x30,
        &[
            &VERSION_3,
            &der(0x02, &[&serial])?,
            &ED25519,
            &name,
            &validity,
            &name,
            &key_info,
            &EXTENSIONS,
        ],
    )?;

    let signature = key.sign(&to_be_signed);
    let signature = der(0x03, &[&[0], signature.as_ref()])?;
    der(0x30, &[&to_be_signed, &ED25519, &signature])
}

/// Makes a new link certificate with a new key.
pub fn make() -> Option<LinkCertificate> {
    let key = Ed25519KeyPair::generate().ok()?;
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).ok()?;

    Some(LinkCertificate {
        certificate: certificate_of(&key, serial)?,
        key: Zeroizing::new(key.to_pkcs8v1().ok()?.as_ref().to_vec()),
    })
}

/// The two files of the link certificate for the `link` line `base`.
fn files_of(base: &str) -> (String, String) {
    (format!("{base}.cert"), format!("{base}.key"))
}

/// Writes a new file that its owner alone reads.
fn write_new(path: &Path, bytes: &[u8]) -> Option<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).ok()?;
    file.write_all(bytes).ok()?;
    file.sync_all().ok()
}

/// Reads the link certificate of the `link` line `base`, from the files
/// `<base>.cert` and `<base>.key` in DER. With neither file, it makes the
/// certificate and writes the two files.
///
/// With one file alone it gives `None`. A new certificate would then take
/// the place of one that a descriptor names, and each dialer would refuse
/// the relay with no cause that the operator sees.
pub fn load_or_make(base: &str) -> Option<LinkCertificate> {
    let (certificate_file, key_file) = files_of(base);
    let certificate = std::fs::read(&certificate_file);
    let key = std::fs::read(&key_file).map(Zeroizing::new);

    match (certificate, key) {
        (Ok(certificate), Ok(key)) => Some(LinkCertificate { certificate, key }),
        (Err(_), Err(_)) => {
            let made = make()?;

            // The certificate takes its name last, thus a stop between the
            // two writes leaves a key file alone, which the next start
            // refuses.
            write_new(Path::new(&key_file), &made.key)?;
            let part = format!("{certificate_file}.part");
            std::fs::write(&part, &made.certificate).ok()?;
            std::fs::rename(&part, &certificate_file).ok()?;
            Some(made)
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_der_value_takes_the_shortest_length() {
        assert_eq!(der(0x04, &[&[7; 3]]).unwrap()[..2], [0x04, 3]);
        assert_eq!(der(0x04, &[&[7; 0x7F]]).unwrap()[..2], [0x04, 0x7F]);
        assert_eq!(der(0x04, &[&[7; 0x80]]).unwrap()[..3], [0x04, 0x81, 0x80]);
        assert_eq!(
            der(0x04, &[&[7; 0x100]]).unwrap()[..4],
            [0x04, 0x82, 0x01, 0x00]
        );
        assert!(der(0x04, &[&vec![7; 0x1_0000]]).is_none());
    }

    #[test]
    fn two_certificates_differ_and_each_key_loads() {
        let one = make().unwrap();
        let other = make().unwrap();
        assert_ne!(one.certificate, other.certificate);

        let key = Ed25519KeyPair::from_pkcs8(&one.key).unwrap();
        assert!(one
            .certificate
            .windows(32)
            .any(|window| window == key.public_key().as_ref()));
    }

    #[test]
    fn the_certificate_stays_across_a_load_and_one_file_alone_is_refused() {
        let directory = std::env::temp_dir().join(format!("umbra-link-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let base = directory.join("link");
        let base = base.to_str().unwrap();
        let (certificate_file, key_file) = files_of(base);
        let _ = std::fs::remove_file(&certificate_file);
        let _ = std::fs::remove_file(&key_file);

        let made = load_or_make(base).unwrap();
        let read = load_or_make(base).unwrap();
        assert_eq!(made.certificate, read.certificate);
        assert_eq!(*made.key, *read.key);

        std::fs::remove_file(&certificate_file).unwrap();
        assert!(load_or_make(base).is_none());

        let _ = std::fs::remove_dir_all(&directory);
    }
}
