//! The device-set sync record of Part 6 §6.6 kind `0x20` and the
//! `DeviceSetControl` wrapper of Part 7 §7.5.5.
//!
//! The wrapper gives each control object a type byte in its own namespace.
//! The roster epoch, the ownership claim, and the seed update keep their
//! layouts in Part 7, and this module hands their bytes through.

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The sub-kind byte that starts the body of kind `0x20`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubKind {
    /// Mutable state.
    MutableState = 0x01,
    /// A `DeviceSetControl` record.
    Control = 0x02,
}

/// The type of a device-set control record. The list is closed
/// (`DEV-053`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlType {
    /// A `SyncAck`, 8 bytes.
    SyncAck = 0x01,
    /// A roster epoch of Part 7 §7.3.1.
    RosterEpoch = 0x02,
    /// An ownership claim record of Part 7 §7.3.1.
    OwnershipClaim = 0x03,
    /// A `FileDescriptor` of a catch-up object.
    CatchUpDescriptor = 0x04,
    /// A `SyncSeedUpdate` of Part 7 §7.7.
    SyncSeedUpdate = 0x05,
}

impl ControlType {
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(ControlType::SyncAck),
            0x02 => Ok(ControlType::RosterEpoch),
            0x03 => Ok(ControlType::OwnershipClaim),
            0x04 => Ok(ControlType::CatchUpDescriptor),
            0x05 => Ok(ControlType::SyncSeedUpdate),
            _ => Err(Error::Malformed),
        }
    }
}

/// The body of an `AppMessage` of kind `0x20`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceSetBody<'a> {
    /// Sub-kind `0x01`; Part 7 §7.5.3 gives the payload.
    MutableState(&'a [u8]),
    /// Sub-kind `0x02`.
    Control {
        /// The type.
        control_type: ControlType,
        /// The object that `control_type` names.
        payload: &'a [u8],
    },
}

impl<'a> DeviceSetBody<'a> {
    /// Writes the body.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        match self {
            DeviceSetBody::MutableState(payload) => {
                w.u8(SubKind::MutableState as u8)?;
                w.put(payload)?;
            }
            DeviceSetBody::Control {
                control_type,
                payload,
            } => {
                if *control_type == ControlType::SyncAck && payload.len() != 8 {
                    return Err(Error::Malformed);
                }
                w.u8(SubKind::Control as u8)?;
                w.u8(0x01)?;
                w.u8(*control_type as u8)?;
                w.put(payload)?;
            }
        }
        Ok(w.position())
    }

    /// Reads a body.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        match r.u8()? {
            0x01 => Ok(DeviceSetBody::MutableState(r.rest())),
            0x02 => {
                if r.u8()? != 0x01 {
                    return Err(Error::Malformed);
                }
                let control_type = ControlType::from_byte(r.u8()?)?;
                let payload = r.rest();
                if control_type == ControlType::SyncAck && payload.len() != 8 {
                    return Err(Error::Malformed);
                }
                Ok(DeviceSetBody::Control {
                    control_type,
                    payload,
                })
            }
            _ => Err(Error::Malformed),
        }
    }

    /// The `counter` of a `SyncAck`, when this is one.
    pub fn sync_ack(&self) -> Option<u64> {
        match self {
            DeviceSetBody::Control {
                control_type: ControlType::SyncAck,
                payload,
            } => Some(u64::from_be_bytes((*payload).try_into().ok()?)),
            _ => None,
        }
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
    fn the_sync_ack_is_eleven_bytes_and_the_type_list_is_closed() {
        let mut out = [0u8; 32];
        let ack = DeviceSetBody::Control {
            control_type: ControlType::SyncAck,
            payload: &9u64.to_be_bytes(),
        };
        assert_eq!(ack.encode(&mut out).unwrap(), 11);
        let back = DeviceSetBody::parse(&out[..11]).unwrap();
        assert_eq!(back.sync_ack(), Some(9));
        assert!(DeviceSetBody::parse(&out[..10]).is_err());
        out[2] = 0x06;
        assert!(DeviceSetBody::parse(&out[..11]).is_err());
        out[0] = 0x03;
        assert!(DeviceSetBody::parse(&out[..11]).is_err());
        let state = DeviceSetBody::MutableState(b"state");
        let n = state.encode(&mut out).unwrap();
        assert_eq!(DeviceSetBody::parse(&out[..n]).unwrap(), state);
    }
}
