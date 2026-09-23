//! The recovery code of Part 4 §4.7.1 and the encrypted backup of §4.7.2.
//!
//! The code is two independent CSPRNG outputs (`IDN-070`), and the store
//! keeps it beside the root seed. It leaves the core only as the digits of
//! §4.7.7, through a sink of the platform (`IMP-037`), and never as hex
//! (`IDN-041`).

use umbra_core::{
    identity::recovery::{to_digits, DigitsType, RecoveryCode},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::{rand_core::CryptoRng, secret::Secret, zeroize::Zeroizing};

use super::Client;
use crate::{Error, Sink};

/// The row of the recovery code in the local identity table.
const RECOVERY_CODE_KEY: &[u8] = b"recovery-code";

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The recovery code of this device. A store that holds none makes one
    /// now: a store of a build before the code, or a new one (`IDN-070`).
    pub fn recovery_code<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<RecoveryCode, Error> {
        let open = self.open_mut()?;
        let row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, RECOVERY_CODE_KEY);
        if let Some(bytes) = open.store.get(TableId::LOCAL_IDENTITY, &row)? {
            let bytes = Zeroizing::new(bytes);
            return Ok(RecoveryCode::from_bytes(&bytes)?);
        }
        // IDN-070: two independent outputs of the CSPRNG.
        let mut user = Secret::new([0u8; 16]);
        rng.fill_bytes(user.expose_mut());
        let mut social = Secret::new([0u8; 16]);
        rng.fill_bytes(social.expose_mut());
        let code = RecoveryCode::new(user, social);
        let mut batch = open.store.begin();
        batch.put(
            TableId::LOCAL_IDENTITY,
            row,
            None,
            code.bytes().expose(),
            rng,
        )?;
        batch.commit()?;
        Ok(code)
    }

    /// Writes the recovery code into `sink` as `RecoveryDigits` of type
    /// `0x0001`, 87 digits in groups of five (`IDN-149`).
    pub fn render_recovery_code<R: CryptoRng + ?Sized>(
        &mut self,
        sink: &mut dyn Sink,
        rng: &mut R,
    ) -> Result<(), Error> {
        let code = self.recovery_code(rng)?;
        let digits = to_digits(DigitsType::Code, code.bytes().expose())?;
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(digits.encode_utf16().collect());
        sink.put(&units);
        Ok(())
    }
}
