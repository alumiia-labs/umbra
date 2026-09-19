//! The community link of Part 12 §12.7, and the key of the metadata blob
//! that its fragment gives. A relay reads `community_id` in each command
//! and never sees the fragment (`COM-244`).

use alloc::{format, string::String, vec::Vec};

use umbra_crypto::{hkdf::Hkdf, labels, secret::Secret, sha3::Sha3_256};

use super::COMMUNITY_RELAY_MAX;
use crate::{
    identity::address::{base32, base32_decode},
    Error,
};

const PREFIX: &str = "umbra://c/";
const HINTS: &str = "?r=";

/// The length of a `RelayRef` (Part 13 §13.3.2).
pub const RELAY_REF_LEN: usize = 12;
/// The length of the fragment.
pub const FRAGMENT_LEN: usize = 16;

/// A community link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityLink {
    /// The community.
    pub community_id: [u8; 32],
    /// The relays that served the community when a party made the link.
    /// The `relays` list of a verified `CommunityMeta` replaces them
    /// (`COM-247`).
    pub hints: Vec<[u8; RELAY_REF_LEN]>,
    /// 128 bits from the device CSPRNG of the creator (`COM-242`).
    pub fragment: [u8; FRAGMENT_LEN],
}

impl CommunityLink {
    fn check(&self) -> Result<(), Error> {
        if self.hints.is_empty() || self.hints.len() > COMMUNITY_RELAY_MAX {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// The text of the link.
    pub fn format(&self) -> Result<String, Error> {
        self.check()?;
        let hints: Vec<String> = self.hints.iter().map(|hint| base32(hint)).collect();
        Ok(format!(
            "{PREFIX}{}{HINTS}{}#{}",
            base32(&self.community_id),
            hints.join(","),
            base32(&self.fragment)
        ))
    }

    /// Reads a link.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let rest = text.strip_prefix(PREFIX).ok_or(Error::Malformed)?;
        let (before_fragment, fragment_text) = rest.split_once('#').ok_or(Error::Malformed)?;
        let (id_text, hints_text) = before_fragment.split_once(HINTS).ok_or(Error::Malformed)?;
        let mut community_id = [0u8; 32];
        base32_decode(id_text, &mut community_id)?;
        let mut fragment = [0u8; FRAGMENT_LEN];
        base32_decode(fragment_text, &mut fragment)?;
        let mut hints = Vec::new();
        for hint_text in hints_text.split(',') {
            let mut hint = [0u8; RELAY_REF_LEN];
            base32_decode(hint_text, &mut hint)?;
            hints.push(hint);
        }
        let link = CommunityLink {
            community_id,
            hints,
            fragment,
        };
        link.check()?;
        Ok(link)
    }

    /// `meta_key`: HKDF-SHA3-256 with the fragment as the key material, and
    /// the label then `community_id` as the info (`COM-243`).
    pub fn meta_key(&self) -> Secret<32> {
        let kdf = Hkdf::<Sha3_256>::new(None, &self.fragment);
        let mut key = Secret::<32>::zeroed();
        // 32 bytes is below the HKDF bound, thus expand cannot fail.
        let _ = kdf.expand_multi_info(
            &[labels::COMMUNITY_META_BLOB, &self.community_id],
            key.expose_mut(),
        );
        key
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_link_round_trips_with_the_stated_character_counts() {
        let link = CommunityLink {
            community_id: [0xA5; 32],
            hints: alloc::vec![[1; 12], [2; 12], [3; 12]],
            fragment: [0x3C; 16],
        };
        let text = link.format().unwrap();
        let expected = PREFIX.len() + 52 + HINTS.len() + 3 * 20 + 2 + 1 + 26;
        assert_eq!(text.len(), expected);
        assert_eq!(CommunityLink::parse(&text).unwrap(), link);

        let other = CommunityLink {
            fragment: [0x3D; 16],
            ..link.clone()
        };
        assert_ne!(link.meta_key().expose(), other.meta_key().expose());

        assert!(CommunityLink::parse(&text.replace('#', "")).is_err());
        assert!(CommunityLink::parse(&text.replace("?r=", "?x=")).is_err());
        assert!(CommunityLink {
            hints: Vec::new(),
            ..link.clone()
        }
        .format()
        .is_err());
        assert!(CommunityLink {
            hints: alloc::vec![[0; 12]; 9],
            ..link
        }
        .format()
        .is_err());
    }
}
