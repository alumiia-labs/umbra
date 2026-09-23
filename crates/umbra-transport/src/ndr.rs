//! One call to the Notification Delivery Relay of Part 8 §8.2: an NDR
//! request in OHTTP through an OHTTP relay, and the answer of the NDR.
//! A queue relay calls it for a push, and a device for its registrations.

use std::{sync::Arc, time::Duration};

use rustls::ClientConfig;
use umbra_crypto::{kem::PublicKey, ohttp, rand_core::CryptoRng};
use umbra_wire::ndr::{NdrResponse, NDR_REQUEST_LEN};

use crate::{
    https::{self, Url},
    native::NativeError,
    Error,
};

/// The OHTTP relay and the gateway key behind it, which the build or the
/// settings file pins (`NTF-127`).
#[derive(Clone)]
pub struct NdrRoute {
    /// The `POST` target of the OHTTP relay.
    pub relay: Url,
    /// The key id of the gateway.
    pub key_id: u8,
    /// The public key of the gateway.
    pub gateway: PublicKey,
}

/// The wait for one call, which covers the post of the NDR to the provider.
pub const NDR_WAIT: Duration = Duration::from_secs(20);

/// Sends one request and reads the answer. The OHTTP relay learns the
/// sender and a length that each request shares, and the NDR learns the
/// request and the relay alone.
pub async fn call<R: CryptoRng + ?Sized>(
    route: &NdrRoute,
    request: &[u8; NDR_REQUEST_LEN],
    tls: Arc<ClientConfig>,
    rng: &mut R,
) -> Result<NdrResponse, NativeError> {
    let (sealed, key) = ohttp::encapsulate_request(route.key_id, &route.gateway, request, rng)
        .map_err(|_| Error::Refused)?;
    let (status, body) = https::post(
        &route.relay,
        "message/ohttp-req",
        &[],
        &sealed,
        tls,
        1_024,
        NDR_WAIT,
    )
    .await?;
    if status != 200 {
        return Err(Error::Refused.into());
    }
    let plain = ohttp::decapsulate_response(&key, &body).map_err(|_| Error::Refused)?;
    NdrResponse::parse(&plain).map_err(|_| Error::Refused.into())
}
