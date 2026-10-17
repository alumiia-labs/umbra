//! The aggregators of Part 10 §10.8: each takes its share of the chain
//! count of a relay with a signed query, and adds Laplace noise to it before
//! any other party reads it (`REL-192`, `REL-193`). The sum of the two noised
//! shares is the chain count that the fault rate reads (`REL-194`).
//!
//! The two aggregators are two authorities. This program plays each one
//! that its settings name, and a test network names both. A network whose
//! aggregators run apart carries each noised share from one to the other,
//! and this program does not.

use std::time::Duration;

use umbra_core::directory::{
    manifest::ListedRelay,
    stat::{self, StatAnswer, StatQuery, AGGREGATORS, CHAIN_NOISE_SCALE},
};
use umbra_crypto::rand_core::TryRng;
use umbra_ffi::runtime::OsRng;
use umbra_transport::https;

use super::Settings;

/// The wait for the answer of one relay.
const ASK_WAIT: Duration = Duration::from_secs(15);

/// A sample of Laplace(`b`), rounded to an integer: the inverse of its
/// distribution at a uniform point of (−½, ½).
fn laplace(b: f64) -> Option<i64> {
    let mut bytes = [0u8; 8];
    OsRng.try_fill_bytes(&mut bytes).ok()?;

    // 53 bits give each value of the unit interval that an f64 holds.
    let unit = (u64::from_be_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64;
    let u = unit - 0.5;
    let magnitude = -b * (1.0 - 2.0 * u.abs()).max(f64::MIN_POSITIVE).ln();
    let sample = if u < 0.0 { -magnitude } else { magnitude };

    // A sample far outside the range of a count is no count.
    (sample.abs() < 1e15).then(|| sample.round() as i64)
}

/// The share of aggregator `index` at one relay for `epoch`, with its noise
/// (`REL-193`).
async fn noised_share(
    settings: &Settings,
    relay: &ListedRelay,
    index: u8,
    epoch: u64,
) -> Option<u64> {
    // REL-192: the query names the relay, thus it reads no share elsewhere.
    let query = StatQuery {
        authority_index: index,
        relay_id: relay.candidate.relay_id,
        epoch,
    };
    let body = query
        .sign(&super::authority_key(settings, index)?, &mut OsRng)
        .ok()?;

    let url = https::Url {
        host: relay.host.clone(),
        port: relay.port,
        path: "/stat".into(),
        address: Some(std::net::IpAddr::from(relay.addr_v4)),
    };
    let tls = super::tls_of(settings).ok()?;
    let (status, answer) = https::post(
        &url,
        "application/octet-stream",
        &[],
        &body,
        tls,
        64,
        ASK_WAIT,
    )
    .await
    .ok()?;
    if status != 200 {
        return None;
    }

    let share = StatAnswer::parse(&answer).ok()?.share?;
    Some(stat::add_noise(share, laplace(CHAIN_NOISE_SCALE)?))
}

/// The noised chain count of a relay in `epoch`, or none when an
/// aggregator of the two is not this program or a relay gave no share
/// (`REL-194`).
pub async fn chain_count(settings: &Settings, relay: &ListedRelay, epoch: u64) -> Option<u64> {
    let mut noised = [0u64; 2];
    for (index, slot) in (0..AGGREGATORS).zip(noised.iter_mut()) {
        if !settings.aggregators.contains(&index) {
            return None;
        }
        *slot = noised_share(settings, relay, index, epoch).await?;
    }
    Some(stat::combine(noised))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_noise_centers_on_zero_at_its_scale() {
        let samples: Vec<i64> = (0..4_000).filter_map(|_| laplace(10.0)).collect();
        assert_eq!(samples.len(), 4_000);
        let mean = samples.iter().sum::<i64>() as f64 / 4_000.0;
        let spread = samples.iter().map(|s| s.abs()).sum::<i64>() as f64 / 4_000.0;

        // The mean of Laplace(b) is 0, and the mean of its magnitude is b.
        assert!(mean.abs() < 1.5, "mean {mean}");
        assert!((spread - 10.0).abs() < 1.5, "spread {spread}");
    }
}
