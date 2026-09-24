//! The exchange of the second owner at the creation of a community (Part 12
//! §12.5.5): the creator offers the co-ownership to one contact on their
//! pairwise channel, the contact accepts with its roster entry or declines,
//! and the creator names the formed community.

use alloc::vec::Vec;

use super::{control::ROSTER_ENTRY_LEN, link::FRAGMENT_LEN, COMMUNITY_RELAY_MAX, META_NAME_MAX};
use crate::Error;

const OFFER: u8 = 0x01;
const ACCEPT: u8 = 0x02;
const DECLINE: u8 = 0x03;
const FORMED: u8 = 0x04;

/// One step of the exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerStep {
    /// The creator offers the co-ownership, with the name of the first
    /// metadata.
    Offer {
        /// 1 to `META_NAME_MAX` bytes of UTF-8.
        name: alloc::string::String,
    },
    /// The contact accepts with the owner entry of its role (`COM-404`).
    Accept {
        /// The encoded `RosterEntry`.
        entry: Vec<u8>,
    },
    /// The contact declines.
    Decline,
    /// The genesis stands at each relay of the metadata (`COM-407`).
    Formed {
        /// The fragment of the link.
        fragment: [u8; FRAGMENT_LEN],
        /// The `relay_id` of each relay of the metadata.
        relays: Vec<[u8; 32]>,
    },
}

/// A `CommunityOwnerExchange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerExchange {
    /// The community.
    pub community_id: [u8; 32],
    /// The step.
    pub step: OwnerStep,
}

impl OwnerExchange {
    /// Encodes the exchange.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let step = match &self.step {
            OwnerStep::Offer { .. } => OFFER,
            OwnerStep::Accept { .. } => ACCEPT,
            OwnerStep::Decline => DECLINE,
            OwnerStep::Formed { .. } => FORMED,
        };
        out.push(step);
        out.extend_from_slice(&self.community_id);
        match &self.step {
            OwnerStep::Offer { name } => {
                if name.is_empty() || name.len() > META_NAME_MAX {
                    return Err(Error::Malformed);
                }
                out.push(u8::try_from(name.len()).map_err(|_| Error::Malformed)?);
                out.extend_from_slice(name.as_bytes());
            }
            OwnerStep::Accept { entry } => {
                if entry.len() != ROSTER_ENTRY_LEN {
                    return Err(Error::Malformed);
                }
                out.extend_from_slice(entry);
            }
            OwnerStep::Decline => {}
            OwnerStep::Formed { fragment, relays } => {
                if relays.is_empty() || relays.len() > COMMUNITY_RELAY_MAX {
                    return Err(Error::Malformed);
                }
                out.extend_from_slice(fragment);
                out.push(u8::try_from(relays.len()).map_err(|_| Error::Malformed)?);
                for relay in relays {
                    out.extend_from_slice(relay);
                }
            }
        }
        Ok(out)
    }

    /// Reads an exchange, and rejects a step outside the four and a rest
    /// of another length than its step (`COM-409`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (&step, rest) = bytes.split_first().ok_or(Error::Malformed)?;
        let (id, rest) = rest.split_at_checked(32).ok_or(Error::Malformed)?;
        let community_id: [u8; 32] = id.try_into().map_err(|_| Error::Malformed)?;
        let step = match step {
            OFFER => {
                let (&len, name) = rest.split_first().ok_or(Error::Malformed)?;
                if name.len() != usize::from(len) || name.is_empty() || name.len() > META_NAME_MAX {
                    return Err(Error::Malformed);
                }
                let name = core::str::from_utf8(name).map_err(|_| Error::Malformed)?;
                OwnerStep::Offer { name: name.into() }
            }
            ACCEPT => {
                if rest.len() != ROSTER_ENTRY_LEN {
                    return Err(Error::Malformed);
                }
                super::control::RosterEntry::from_bytes(rest)?;
                OwnerStep::Accept {
                    entry: rest.to_vec(),
                }
            }
            DECLINE if rest.is_empty() => OwnerStep::Decline,
            FORMED => {
                let (fragment, rest) = rest
                    .split_at_checked(FRAGMENT_LEN)
                    .ok_or(Error::Malformed)?;
                let (&count, rest) = rest.split_first().ok_or(Error::Malformed)?;
                let count = usize::from(count);
                if count == 0 || count > COMMUNITY_RELAY_MAX || rest.len() != count * 32 {
                    return Err(Error::Malformed);
                }
                let relays = rest
                    .chunks(32)
                    .map(|relay| relay.try_into().map_err(|_| Error::Malformed))
                    .collect::<Result<Vec<[u8; 32]>, Error>>()?;
                OwnerStep::Formed {
                    fragment: fragment.try_into().map_err(|_| Error::Malformed)?,
                    relays,
                }
            }
            _ => return Err(Error::Malformed),
        };
        Ok(OwnerExchange { community_id, step })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::community::{
        control::{Role, RosterEntry},
        identity::RoleIdentity,
    };
    use umbra_crypto::secret::Secret;
    use umbra_wire::address::QueueAddress;

    #[test]
    fn each_step_round_trips_and_a_wrong_length_is_refused() {
        let role = RoleIdentity::from_seed(&Secret::new([7; 32]));
        let queue = QueueAddress {
            relay_id: [1; 32],
            sender_id: [2; 32],
            qs_auth_sk: Secret::new([3; 32]),
            qe: Secret::new([4; 32]),
        };
        let entry = RosterEntry::new(Role::Owner, &role, &queue)
            .unwrap()
            .to_bytes()
            .unwrap()
            .to_vec();
        let steps = [
            OwnerStep::Offer {
                name: "trail club".into(),
            },
            OwnerStep::Accept {
                entry: entry.clone(),
            },
            OwnerStep::Decline,
            OwnerStep::Formed {
                fragment: [5; 16],
                relays: alloc::vec![[6; 32], [7; 32], [8; 32]],
            },
        ];
        for step in steps {
            let exchange = OwnerExchange {
                community_id: [9; 32],
                step,
            };
            let bytes = exchange.encode().unwrap();
            assert_eq!(OwnerExchange::parse(&bytes).unwrap(), exchange);
            let mut longer = bytes.clone();
            longer.push(0);
            assert!(OwnerExchange::parse(&longer).is_err());
        }
        // COM-409: a step outside the four.
        let mut other = OwnerExchange {
            community_id: [9; 32],
            step: OwnerStep::Decline,
        }
        .encode()
        .unwrap();
        other[0] = 0x05;
        assert!(OwnerExchange::parse(&other).is_err());
        // The accept is the size of COM-404 and its header.
        let accept = OwnerExchange {
            community_id: [9; 32],
            step: OwnerStep::Accept { entry },
        };
        assert_eq!(accept.encode().unwrap().len(), 1_411);
    }
}
