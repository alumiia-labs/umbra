//! The canonical form of a handle (Part 9 §9.3.2), the format of §9.9, the
//! profile blob key of §9.3.1, and the label inputs of the three index
//! spaces under one VOPRF key.

use alloc::{string::String, vec::Vec};

use umbra_crypto::{aead, hkdf::Hkdf, labels, secret::Secret, sha3::Sha3_256};
use umbra_wire::codec::{Reader, Writer};

use crate::Error;

/// The byte limit of the `name` part after the profile (`DIS-090`).
pub const NAME_MAX: usize = 32;
/// The fewest digits of a discriminator.
pub const DISCRIMINATOR_MIN: usize = 2;
/// The most digits of a discriminator.
pub const DISCRIMINATOR_MAX: usize = 9;
/// The fragment of a shared handle link, in bytes.
pub const FRAGMENT_LEN: usize = 16;
/// The version byte of a sealed profile blob.
pub const BLOB_VERSION: u8 = 0x01;

/// A profile function: the `UsernameCaseMapped` output of a `name` part,
/// or `None` when the profile rejects it (`DIS-088`, `DIS-089`).
pub type Profile<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The `UsernameCaseMapped` profile of RFC 8265 over the PRECIS tables.
#[cfg(feature = "precis")]
pub fn username_case_mapped(name: &str) -> Option<String> {
    use precis_profiles::precis_core::profile::PrecisFastInvocation;
    precis_profiles::UsernameCaseMapped::enforce(name)
        .ok()
        .map(|cow| cow.into_owned())
}

/// A handle in its canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    name: String,
    discriminator: String,
}

impl Handle {
    /// Parses `@name#dddd` and applies the profile to the `name` part
    /// (`DIS-088` to `DIS-092`).
    pub fn parse(raw: &str, profile: Profile<'_>) -> Result<Self, Error> {
        let body = raw.strip_prefix('@').ok_or(Error::Malformed)?;
        let (name, discriminator) = body.rsplit_once('#').ok_or(Error::Malformed)?;
        let digits = discriminator.len();
        if !(DISCRIMINATOR_MIN..=DISCRIMINATOR_MAX).contains(&digits)
            || !discriminator.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Malformed);
        }
        if name.is_empty() {
            return Err(Error::Malformed);
        }
        let mapped = profile(name).ok_or(Error::Malformed)?;
        if mapped.is_empty() || mapped.len() > NAME_MAX {
            return Err(Error::Malformed);
        }
        Ok(Handle {
            name: mapped,
            discriminator: String::from(discriminator),
        })
    }

    /// Whether a registration `name` part is already canonical
    /// (`DIS-091`): the profile changes nothing.
    pub fn is_canonical_name(name: &str, profile: Profile<'_>) -> bool {
        profile(name).is_some_and(|mapped| mapped == name)
    }

    /// The `name` part after the profile.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The discriminator digits.
    pub fn discriminator(&self) -> &str {
        &self.discriminator
    }

    /// The canonical handle string.
    pub fn canonical(&self) -> String {
        let mut out = String::with_capacity(
            self.name
                .len()
                .saturating_add(self.discriminator.len())
                .saturating_add(2),
        );
        out.push('@');
        out.push_str(&self.name);
        out.push('#');
        out.push_str(&self.discriminator);
        out
    }

    /// The VOPRF input of the handle index (§9.3.1): the canonical handle
    /// alone.
    pub fn label_input(&self) -> Vec<u8> {
        self.canonical().into_bytes()
    }

    /// The profile blob key (§9.3.1): HKDF-SHA3-256 with the fragment as
    /// the key material and the label then the canonical handle as the
    /// info.
    pub fn blob_key(&self, fragment: &[u8; FRAGMENT_LEN]) -> Secret<32> {
        let kdf = Hkdf::<Sha3_256>::new(None, fragment);
        let mut key = Secret::<32>::zeroed();
        let _ = kdf.expand_multi_info(
            &[labels::PROFILE_BLOB, self.canonical().as_bytes()],
            key.expose_mut(),
        );
        key
    }

    /// Seals a profile blob: the version, the nonce, and the ciphertext
    /// with its tag, with the canonical handle as associated data.
    pub fn seal_blob(
        &self,
        fragment: &[u8; FRAGMENT_LEN],
        nonce: [u8; 24],
        profile: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; 1 + 24 + profile.len() + aead::TAG_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(BLOB_VERSION)?;
        w.put(&nonce)?;
        w.put(profile)?;
        let body = w.written().get_mut(25..).ok_or(Error::Malformed)?;
        let tag = aead::seal(
            &self.blob_key(fragment),
            &nonce,
            self.canonical().as_bytes(),
            body,
        )?;
        let at = 25usize.saturating_add(profile.len());
        out.get_mut(at..)
            .ok_or(Error::Malformed)?
            .copy_from_slice(&tag);
        Ok(out)
    }

    /// Opens a profile blob.
    pub fn open_blob(&self, fragment: &[u8; FRAGMENT_LEN], blob: &[u8]) -> Result<Vec<u8>, Error> {
        let mut r = Reader::new(blob);
        if r.u8()? != BLOB_VERSION {
            return Err(Error::Malformed);
        }
        let nonce: [u8; 24] = r.array()?;
        let rest = r.rest();
        if rest.len() < aead::TAG_LEN {
            return Err(Error::Malformed);
        }
        let split = rest.len().saturating_sub(aead::TAG_LEN);
        let mut plain = rest.get(..split).ok_or(Error::Malformed)?.to_vec();
        let tag = rest.get(split..).ok_or(Error::Malformed)?;
        aead::open(
            &self.blob_key(fragment),
            &nonce,
            self.canonical().as_bytes(),
            &mut plain,
            tag,
        )?;
        Ok(plain)
    }
}

/// The VOPRF input of the address index (§9.3.3).
pub fn address_label_input(address: &[u8; 20]) -> Vec<u8> {
    [labels::ADDRESS_INDEX, address].concat()
}

/// The VOPRF input of the listing index (§9.12).
pub fn listing_label_input(community_id: &[u8; 32]) -> Vec<u8> {
    [labels::COMMUNITY_LISTING, community_id].concat()
}

/// A profile for tests and for a platform without the PRECIS tables: ASCII
/// letters, digits, and a few marks, lower-cased. It is not the profile
/// of `DIS-088`.
pub fn ascii_profile(name: &str) -> Option<String> {
    if name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
    {
        Some(name.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_parses_to_its_canonical_form() {
        let h = Handle::parse("@Alice#1234", &ascii_profile).unwrap();
        assert_eq!(h.canonical(), "@alice#1234");
        assert_eq!(h.name(), "alice");
        assert_eq!(h.discriminator(), "1234");
        assert!(Handle::parse("alice#1234", &ascii_profile).is_err());
        assert!(Handle::parse("@alice#1", &ascii_profile).is_err());
        assert!(Handle::parse("@alice#1234567890", &ascii_profile).is_err());
        assert!(Handle::parse("@alice#12a4", &ascii_profile).is_err());
        assert!(Handle::parse("@#1234", &ascii_profile).is_err());
        assert!(Handle::parse("@a b#1234", &ascii_profile).is_err());
        let long = alloc::format!("@{}#12", "a".repeat(33));
        assert!(Handle::parse(&long, &ascii_profile).is_err());
        assert!(Handle::is_canonical_name("alice", &ascii_profile));
        assert!(!Handle::is_canonical_name("Alice", &ascii_profile));
        assert_ne!(
            address_label_input(&[1; 20]),
            listing_label_input(&[1; 32])[..32].to_vec()
        );
    }

    #[test]
    fn the_profile_blob_opens_under_the_fragment_and_the_handle() {
        let h = Handle::parse("@bob#42", &ascii_profile).unwrap();
        let blob = h.seal_blob(&[3; 16], [4; 24], b"Bob;welcome").unwrap();
        assert_eq!(h.open_blob(&[3; 16], &blob).unwrap(), b"Bob;welcome");
        assert!(h.open_blob(&[5; 16], &blob).is_err());
        let other = Handle::parse("@bob#43", &ascii_profile).unwrap();
        assert!(other.open_blob(&[3; 16], &blob).is_err());
        assert!(h.open_blob(&[3; 16], &blob[..30]).is_err());
    }

    #[cfg(feature = "precis")]
    #[test]
    fn the_precis_profile_maps_case_and_width_and_rejects_a_space() {
        assert_eq!(username_case_mapped("Alice").unwrap(), "alice");
        assert_eq!(username_case_mapped("ＡＢＣ").unwrap(), "abc");
        assert!(username_case_mapped("a b").is_none());
        let h = Handle::parse("@Ärger#12", &username_case_mapped).unwrap();
        assert_eq!(h.canonical(), "@ärger#12");
    }
}
