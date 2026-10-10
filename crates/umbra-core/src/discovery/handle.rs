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
/// The prefix of the link of a handle with its profile (§9.3.1).
pub const PROFILE_LINK_PREFIX: &str = "umbra://h/";

/// Reads `umbra://h/<name>%23<discriminator>#<fragment>`: the handle, and
/// the fragment in the base32 of Part 4 (`DIS-179`). A `#` in place of the
/// `%23` reads too, because the last `#` starts the fragment. The parser
/// reads the one `%23` before the discriminator as `#`, and no other one. A
/// name holds no `%` (`DIS-089`), thus a second `%23` is no part of a
/// handle.
pub fn parse_profile_link(
    text: &str,
    profile: Profile<'_>,
) -> Result<(Handle, [u8; FRAGMENT_LEN]), Error> {
    let rest = text
        .trim()
        .strip_prefix(PROFILE_LINK_PREFIX)
        .ok_or(Error::Malformed)?;
    let (handle, fragment) = rest.rsplit_once('#').ok_or(Error::Malformed)?;
    let handle = match handle.rsplit_once("%23") {
        Some((name, discriminator)) => alloc::format!("@{name}#{discriminator}"),
        None => alloc::format!("@{handle}"),
    };
    let handle = Handle::parse(&handle, profile)?;
    let mut out = [0u8; FRAGMENT_LEN];
    crate::identity::address::base32_decode(fragment, &mut out)?;
    Ok((handle, out))
}

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

/// The marks that no `name` part holds (`DIS-089`): `#` starts the
/// discriminator, `@` starts a handle, and `%` and `/` have a meaning in the
/// link of `DIS-179`. The `IdentifierClass` of RFC 8264 passes each of them.
const NAME_MARKS: [char; 4] = ['#', '%', '@', '/'];

/// Whether the output of the profile is a `name` part: not empty, within
/// the limit of `DIS-090`, and with none of the marks.
fn is_name(mapped: &str) -> bool {
    is_held_name(mapped) && !mapped.contains(NAME_MARKS)
}

/// Whether the output of the profile is the `name` part of a handle that a
/// directory holds already. A registration before `DIS-089` named the marks
/// could hold one.
fn is_held_name(mapped: &str) -> bool {
    !mapped.is_empty() && mapped.len() <= NAME_MAX
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
        Self::parse_with(raw, profile, is_name)
    }

    /// Parses the handle of a label that a directory holds already, for a
    /// write of its holder (`DIS-171`). Such a write is a new queue, a new
    /// key, or the tombstone. A handle that its holder registered before
    /// `DIS-089` named the four marks can hold one. Its holder still writes
    /// and retires it. No registration and no lookup reads a handle this
    /// way.
    pub fn parse_held(raw: &str, profile: Profile<'_>) -> Result<Self, Error> {
        Self::parse_with(raw, profile, is_held_name)
    }

    fn parse_with(
        raw: &str,
        profile: Profile<'_>,
        is_name: fn(&str) -> bool,
    ) -> Result<Self, Error> {
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
        if !is_name(&mapped) {
            return Err(Error::Malformed);
        }
        Ok(Handle {
            name: mapped,
            discriminator: String::from(discriminator),
        })
    }

    /// Whether a registration `name` part is already canonical
    /// (`DIS-091`): the profile changes nothing, and the result is a name.
    pub fn is_canonical_name(name: &str, profile: Profile<'_>) -> bool {
        profile(name).is_some_and(|mapped| mapped == name && is_name(&mapped))
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

    /// The link of this handle with the fragment that opens its profile
    /// blob (`DIS-179`).
    pub fn profile_link(&self, fragment: &[u8; FRAGMENT_LEN]) -> String {
        alloc::format!(
            "{PROFILE_LINK_PREFIX}{}%23{}#{}",
            self.name,
            self.discriminator,
            crate::identity::address::base32(fragment)
        )
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
    }

    #[test]
    fn a_profile_link_reads_back() {
        let h = Handle::parse("@bob#42", &ascii_profile).unwrap();
        let link = h.profile_link(&[0xA5; 16]);
        assert!(link.starts_with("umbra://h/bob%2342#"), "{link}");
        let (back, fragment) = parse_profile_link(&link, &ascii_profile).unwrap();
        assert_eq!(back.canonical(), "@bob#42");
        assert_eq!(fragment, [0xA5; 16]);
        let plain = link.replace("%23", "#");
        assert_eq!(
            parse_profile_link(&plain, &ascii_profile)
                .unwrap()
                .0
                .canonical(),
            "@bob#42"
        );
        assert!(parse_profile_link("umbra://h/bob%2342", &ascii_profile).is_err());
        // DIS-179: the parser reads one `%23`, thus a second one is no `#`
        // of a name.
        let twice = link.replace("bob", "a%23b");
        assert!(parse_profile_link(&twice, &ascii_profile).is_err());
        assert!(parse_profile_link("umbra://p/bob%2342#00", &ascii_profile).is_err());
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
    fn a_name_holds_no_mark_of_the_handle_or_of_its_link() {
        // The profile of RFC 8265 passes each of these marks, thus the
        // profile alone does not keep them out of a name (`DIS-089`).
        for mark in ["#", "%", "@", "/"] {
            let name = alloc::format!("a{mark}b");
            assert!(username_case_mapped(&name).is_some(), "{mark}");
            let handle = alloc::format!("@{name}#12");
            assert!(Handle::parse(&handle, &username_case_mapped).is_err());
            assert!(!Handle::is_canonical_name(&name, &username_case_mapped));
        }
        // A label that a directory holds already reads with a mark, thus
        // its holder still writes and retires it.
        for held in ["@alice#12#34", "@a%23b#12", "@a@b#12", "@a/b#12"] {
            assert!(Handle::parse(held, &username_case_mapped).is_err());
            let handle = Handle::parse_held(held, &username_case_mapped).unwrap();
            assert_eq!(handle.canonical(), held);
        }
        assert!(Handle::parse_held("@#12", &username_case_mapped).is_err());
        assert!(Handle::parse_held("@Alice#12", &username_case_mapped)
            .is_ok_and(|handle| handle.canonical() == "@alice#12"));
        // Two discriminators, and a name that reads as another handle
        // after the `%23` of its link.
        assert!(Handle::parse("@alice#12#34", &username_case_mapped).is_err());
        assert!(Handle::parse("@a%23b#12", &username_case_mapped).is_err());
        // A full-width mark maps to the plain one, and it goes too.
        assert!(Handle::parse("@a＃b#12", &username_case_mapped).is_err());
        assert!(Handle::is_canonical_name("alice", &username_case_mapped));
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
