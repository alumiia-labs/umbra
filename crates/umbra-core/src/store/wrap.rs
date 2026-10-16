//! The wrap of the at-rest master key (Part 14 §14.6.4, §14.7.4): Argon2id
//! over the passphrase, one keyed operation in the secure element of the
//! platform, and XChaCha20-Poly1305 over `K_store`. Each try of a
//! passphrase needs the secure element, thus a brute force runs on the
//! seized device.

use umbra_crypto::{aead, hkdf::Hkdf, kdf, labels, secret::Secret, sha3::Sha3_256};
use umbra_wire::codec::{Reader, Writer};

use crate::Error;

/// The version byte of a `WrapHeader`.
pub const VERSION: u8 = 0x01;
/// The length of a `WrapHeader`.
pub const HEADER_LEN: usize = 1 + 4 + 4 + 16 + 24 + 32 + 16;
/// The time of one try that the calibration aims at, in milliseconds.
pub const TARGET_MS: u64 = 3_000;
/// The floor of the Argon2id memory, in KiB.
pub const M_KIB_FLOOR: u32 = 64 * 1_024;
/// The floor of the Argon2id passes.
pub const T_FLOOR: u32 = 3;
/// The default idle time before the client locks, in seconds.
pub const AUTO_LOCK_DEFAULT: u64 = 15 * 60;
/// The longest idle time that a user can set, in seconds.
pub const AUTO_LOCK_MAX: u64 = 30 * 60;

const WRAP_INPUT_LEN: usize = labels::AT_REST_WRAP.len() + 32;

/// The keyed function of the platform: StrongBox or the TEE on Android
/// (`IMP-062`), and a non-extractable Web Cryptography key in a browser
/// (`IMP-106`). The key has no export path, and a use of it asks for no
/// user authentication (`IMP-065`).
pub trait SecureElement {
    /// `HMAC-SHA256(k_se, input)`.
    fn keyed(&self, input: &[u8]) -> Result<[u8; 32], Error>;
}

/// The Argon2id cost of one store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    /// The memory in KiB.
    pub m_kib: u32,
    /// The passes.
    pub t: u32,
}

/// The greatest memory that a header may name: four times the floor
/// (`IMP-175`).
pub const M_KIB_MAX: u32 = 4 * M_KIB_FLOOR;
/// The greatest pass count that a header may name: the calibration of a
/// device that runs one pass in a millisecond (`IMP-175`).
pub const T_MAX: u32 = 3_000;

impl Cost {
    /// Whether a header may carry this cost: a party with the file that
    /// raises it makes no unlock allocate without bound. A cost below the
    /// floor of `IMP-116` comes from no client, and no later wrap at a
    /// passphrase change takes it (`IMP-175`).
    pub const fn is_bounded(&self) -> bool {
        self.m_kib >= M_KIB_FLOOR && self.m_kib <= M_KIB_MAX && self.t >= T_FLOOR && self.t <= T_MAX
    }

    /// The cost for a device that ran the floor cost in `floor_ms`
    /// milliseconds. The memory stays at the floor, and the passes grow
    /// until one try takes about `TARGET_MS`.
    pub fn calibrate(floor_ms: u64) -> Self {
        let per_pass = (floor_ms / u64::from(T_FLOOR)).max(1);
        let passes = u32::try_from(TARGET_MS.div_ceil(per_pass)).unwrap_or(u32::MAX);
        Cost {
            m_kib: M_KIB_FLOOR,
            t: passes.clamp(T_FLOOR, T_MAX),
        }
    }
}

/// What the client stores beside the database to open it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapHeader {
    /// The Argon2id cost.
    pub cost: Cost,
    /// `salt_pw`.
    pub salt: [u8; 16],
    /// `nonce_w`.
    pub nonce: [u8; 24],
    /// `wrapped`, without its tag.
    pub wrapped: [u8; 32],
    /// The tag of `wrapped`.
    pub tag: [u8; 16],
}

fn wrap_key(
    passphrase: &[u8],
    cost: Cost,
    salt: &[u8; 16],
    element: &impl SecureElement,
) -> Result<Secret<32>, Error> {
    let a = kdf::argon2id(passphrase, salt, cost.m_kib, cost.t)?;
    // IMP-061: S, and then K_wrap, take the inputs of §14.6.4 and no other.
    let mut input = Secret::<WRAP_INPUT_LEN>::zeroed();
    let (label_part, a_part) = input.expose_mut().split_at_mut(labels::AT_REST_WRAP.len());
    label_part.copy_from_slice(labels::AT_REST_WRAP);
    a_part.copy_from_slice(a.expose());
    let s = Secret::new(element.keyed(input.expose())?);
    let kdf = Hkdf::<Sha3_256>::new(Some(a.expose()), s.expose());
    let mut key = Secret::<32>::zeroed();
    // 32 bytes is below the HKDF bound, thus expand cannot fail.
    let _ = kdf.expand(labels::AT_REST_WRAP, key.expose_mut());
    Ok(key)
}

impl WrapHeader {
    /// Wraps `store_key` under `passphrase`. `salt` and `nonce` come from
    /// the CSPRNG. A passphrase change wraps the same key again under a
    /// new salt and a new nonce.
    pub fn wrap(
        store_key: &Secret<32>,
        passphrase: &[u8],
        cost: Cost,
        salt: [u8; 16],
        nonce: [u8; 24],
        element: &impl SecureElement,
    ) -> Result<Self, Error> {
        let key = wrap_key(passphrase, cost, &salt, element)?;
        let mut wrapped = *store_key.expose();
        let tag = aead::seal(&key, &nonce, labels::AT_REST_WRAP, &mut wrapped)?;
        Ok(WrapHeader {
            cost,
            salt,
            nonce,
            wrapped,
            tag,
        })
    }

    /// Opens `K_store`. A wrong passphrase and another secure element give
    /// one error.
    pub fn unwrap(
        &self,
        passphrase: &[u8],
        element: &impl SecureElement,
    ) -> Result<Secret<32>, Error> {
        let key = wrap_key(passphrase, self.cost, &self.salt, element)?;
        let mut store_key = Secret::new(self.wrapped);
        aead::open(
            &key,
            &self.nonce,
            labels::AT_REST_WRAP,
            store_key.expose_mut(),
            &self.tag,
        )
        .map_err(|_| Error::Unverified)?;
        Ok(store_key)
    }

    /// Encodes the header.
    pub fn encode(&self) -> Result<[u8; HEADER_LEN], Error> {
        let mut out = [0u8; HEADER_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u32(self.cost.m_kib)?;
        w.u32(self.cost.t)?;
        w.put(&self.salt)?;
        w.put(&self.nonce)?;
        w.put(&self.wrapped)?;
        w.put(&self.tag)?;
        Ok(out)
    }

    /// Reads a header.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let header = WrapHeader {
            cost: Cost {
                m_kib: r.u32()?,
                t: r.u32()?,
            },
            salt: r.array()?,
            nonce: r.array()?,
            wrapped: r.array()?,
            tag: r.array()?,
        };
        r.finish()?;
        if !header.cost.is_bounded() {
            return Err(Error::Malformed);
        }
        Ok(header)
    }
}

/// The idle timer that locks the store. A lock drops `K_store` from RAM,
/// and the next unlock pays the Argon2id cost again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoLock {
    idle_limit: u64,
    last_activity: u64,
}

impl AutoLock {
    /// A timer with the default limit, started at `now`.
    pub fn new(now: u64) -> Self {
        AutoLock {
            idle_limit: AUTO_LOCK_DEFAULT,
            last_activity: now,
        }
    }

    /// Sets the idle limit, which stays at or below `AUTO_LOCK_MAX`.
    pub fn set_limit(&mut self, seconds: u64) {
        self.idle_limit = seconds.clamp(1, AUTO_LOCK_MAX);
    }

    /// The user acted at `now`.
    pub fn touch(&mut self, now: u64) {
        self.last_activity = now;
    }

    /// Whether the client locks at `now`. A reading below the last action
    /// comes from a source that is not monotonic (`IMP-119`), and the timer
    /// then locks: a step back of such a source never keeps the store open
    /// above its limit.
    pub fn due(&self, now: u64) -> bool {
        now < self.last_activity || now - self.last_activity >= self.idle_limit
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use umbra_crypto::{
        hmac::{digest::KeyInit, Hmac, Mac},
        sha2::Sha256,
    };

    use super::*;

    /// A software stand-in for the secure element.
    pub struct SoftwareElement(pub [u8; 32]);

    impl SecureElement for SoftwareElement {
        fn keyed(&self, input: &[u8]) -> Result<[u8; 32], Error> {
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| Error::Malformed)?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().into())
        }
    }

    const CHEAP: Cost = Cost { m_kib: 64, t: 1 };

    #[test]
    fn the_key_opens_with_the_passphrase_and_the_element_only() {
        let element = SoftwareElement([1; 32]);
        let store_key = Secret::new([7; 32]);
        let header = WrapHeader::wrap(
            &store_key,
            b"correct horse",
            CHEAP,
            [2; 16],
            [3; 24],
            &element,
        )
        .unwrap();
        let bytes = header.encode().unwrap();
        assert_eq!(bytes.len(), 97);
        // IMP-175: a header below the floor does not parse, and one at the
        // floor does.
        assert_eq!(WrapHeader::parse(&bytes), Err(Error::Malformed));
        let floor = WrapHeader {
            cost: Cost {
                m_kib: M_KIB_FLOOR,
                t: T_FLOOR,
            },
            ..header
        };
        assert_eq!(WrapHeader::parse(&floor.encode().unwrap()).unwrap(), floor);
        for cost in [
            Cost {
                m_kib: M_KIB_FLOOR - 1,
                t: T_FLOOR,
            },
            Cost {
                m_kib: M_KIB_FLOOR,
                t: T_FLOOR - 1,
            },
            Cost {
                m_kib: M_KIB_MAX + 1,
                t: T_FLOOR,
            },
            Cost {
                m_kib: M_KIB_FLOOR,
                t: T_MAX + 1,
            },
        ] {
            let header = WrapHeader { cost, ..header };
            assert!(WrapHeader::parse(&header.encode().unwrap()).is_err());
        }
        let parsed = header;
        assert_eq!(
            parsed.unwrap(b"correct horse", &element).unwrap().expose(),
            store_key.expose()
        );
        assert_eq!(
            parsed.unwrap(b"wrong horse", &element).err(),
            Some(Error::Unverified)
        );
        // A copy of the file on another device holds another element key.
        let other = SoftwareElement([9; 32]);
        assert!(parsed.unwrap(b"correct horse", &other).is_err());

        let changed =
            WrapHeader::wrap(&store_key, b"new phrase", CHEAP, [4; 16], [5; 24], &element).unwrap();
        assert_eq!(
            changed.unwrap(b"new phrase", &element).unwrap().expose(),
            store_key.expose()
        );
    }

    #[test]
    fn the_calibration_keeps_the_floor_and_the_timer_locks_when_idle() {
        assert_eq!(
            Cost::calibrate(3_000),
            Cost {
                m_kib: M_KIB_FLOOR,
                t: 3
            }
        );
        assert_eq!(Cost::calibrate(900).t, 10);
        assert_eq!(
            Cost::calibrate(30_000).t,
            T_FLOOR,
            "a slow device keeps the floor"
        );
        assert_eq!(Cost::calibrate(0).t, 3_000);

        let mut timer = AutoLock::new(1_000);
        assert!(!timer.due(1_000 + AUTO_LOCK_DEFAULT - 1));
        assert!(timer.due(1_000 + AUTO_LOCK_DEFAULT));
        timer.touch(1_500);
        assert!(!timer.due(1_000 + AUTO_LOCK_DEFAULT));
        timer.set_limit(86_400);
        assert!(timer.due(1_500 + AUTO_LOCK_MAX));
        // A reading below the last action locks.
        assert!(timer.due(1_499));
    }
}
