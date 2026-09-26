//! One call to the directory and the issuer of Part 9 §9.10: a padded
//! `DirRequest` in OHTTP through the `POST /directory` path of an ingress
//! relay, and the padded `DirResponse` (`DIS-162`).

use std::{sync::Arc, time::Duration};

use rustls::ClientConfig;
use umbra_crypto::{ohttp, rand_core::CryptoRng};

use crate::{https, native::NativeError, ndr::NdrRoute, Error};

/// The route to the directory: the same shape as the route to the NDR, with
/// the key that the build pins (`DIS-163`).
pub type DirectoryRoute = NdrRoute;

/// The wait for one call.
pub const DIRECTORY_WAIT: Duration = Duration::from_secs(20);

/// The longest encapsulated response: the largest `DirResponse`, the nonce,
/// and the tag.
const RESPONSE_MAX: usize = 131_072;

/// Sends one padded request and returns the padded response.
pub async fn call<R: CryptoRng + ?Sized>(
    route: &DirectoryRoute,
    request: &[u8],
    tls: Arc<ClientConfig>,
    rng: &mut R,
) -> Result<Vec<u8>, NativeError> {
    let (sealed, key) = ohttp::encapsulate_request(route.key_id, &route.gateway, request, rng)
        .map_err(|_| Error::Refused)?;
    let (status, body) = https::post(
        &route.relay,
        "message/ohttp-req",
        &[],
        &sealed,
        tls,
        RESPONSE_MAX,
        DIRECTORY_WAIT,
    )
    .await?;
    if status != 200 {
        return Err(Error::Refused.into());
    }
    Ok(ohttp::decapsulate_response(&key, &body).map_err(|_| Error::Refused)?)
}
