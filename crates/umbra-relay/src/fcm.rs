//! The FCM sender of the Notification Delivery Relay (Part 8 §8.2): the
//! HTTP v1 API of Firebase Cloud Messaging under the service account of the
//! deployment. The NDR alone holds that account, and no queue relay touches
//! it.
//!
//! The access token comes from the OAuth 2.0 token endpoint of the account
//! for a JWT that the account key signs under RS256, and it serves until
//! shortly before its expiry. The key signs through the `aws-lc-rs` that the
//! TLS stack holds already, and the few JSON fields that this needs are read
//! and written here, thus no crate enters register R3 (Part 15 §15.2.3).

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{rand::SystemRandom, signature::RsaKeyPair};
use tokio::sync::Mutex;
use umbra_transport::https::{self, Url};

/// The scope of a token that sends FCM messages.
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// The FCM API of a real deployment.
pub const FCM_API: &str = "https://fcm.googleapis.com";
/// The life of a JWT assertion, in seconds.
const ASSERTION_LIFE: u64 = 3_600;
/// A token that ends inside this margin is fetched again, in seconds.
const TOKEN_MARGIN: u64 = 60;
/// The wait for the token endpoint and for FCM.
const WAIT: Duration = Duration::from_secs(10);

/// Reads the string of `key` in a flat JSON object, with the escapes that a
/// service account file holds.
pub fn json_string(json: &str, key: &str) -> Option<String> {
    let rest = value_after(json, key)?.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let code: String = chars.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&code, 16).ok()?)?);
                }
                other => out.push(other),
            },
            other => out.push(other),
        }
    }
}

/// Reads the unsigned number of `key` in a flat JSON object.
pub fn json_number(json: &str, key: &str) -> Option<u64> {
    let rest = value_after(json, key)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn value_after<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let quoted = format!("\"{key}\"");
    let at = json.find(&quoted)?.checked_add(quoted.len())?;
    let rest = json.get(at..)?.trim_start().strip_prefix(':')?;
    Some(rest.trim_start())
}

/// Writes a JSON string with its quotes.
fn json_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Base64url with no padding (RFC 4648 §5), for a JWT and a data field.
pub fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let byte = |i: usize| u32::from(group.get(i).copied().unwrap_or(0));
        let n = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        let take = group.len().saturating_add(1);
        for i in 0..take {
            let index = usize::try_from((n >> (18 - 6 * i)) & 0x3F).unwrap_or(0);
            out.extend(TABLE.get(index).map(|symbol| char::from(*symbol)));
        }
    }
    out
}

/// Decodes the standard base64 of a PEM body.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let clean: Vec<u8> = text
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for group in clean.chunks(4) {
        let mut n = 0u32;
        for (i, c) in group.iter().enumerate() {
            n |= value(*c)? << (18 - 6 * i);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(bytes.get(1..group.len())?);
    }
    Some(out)
}

/// The facts of a service account file that the sender needs.
pub struct ServiceAccount {
    /// The account address, the issuer of each assertion.
    pub client_email: String,
    /// The Firebase project.
    pub project_id: String,
    /// The token endpoint of the account.
    pub token_uri: Url,
    /// The token endpoint as the file writes it: the audience of each
    /// assertion, which the endpoint compares byte for byte.
    audience: String,
    key: RsaKeyPair,
}

impl ServiceAccount {
    /// Reads a service account file of Google Cloud.
    pub fn parse(json: &str) -> Option<ServiceAccount> {
        let pem = json_string(json, "private_key")?;
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = base64_decode(&body)?;
        let audience = json_string(json, "token_uri")?;
        Some(ServiceAccount {
            client_email: json_string(json, "client_email")?,
            project_id: json_string(json, "project_id")?,
            token_uri: Url::parse(&audience)?,
            audience,
            key: RsaKeyPair::from_pkcs8(&der).ok()?,
        })
    }

    /// A JWT assertion for the token endpoint at `now`, signed RS256.
    fn assertion(&self, now: u64) -> Option<String> {
        let header = base64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = format!(
            "{{\"iss\":{},\"scope\":{},\"aud\":{},\"iat\":{now},\"exp\":{}}}",
            json_quote(&self.client_email),
            json_quote(SCOPE),
            json_quote(&self.audience),
            now.saturating_add(ASSERTION_LIFE),
        );
        let signed = format!("{header}.{}", base64url(claims.as_bytes()));
        let mut signature = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(
                &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signed.as_bytes(),
                &mut signature,
            )
            .ok()?;
        Some(format!("{signed}.{}", base64url(&signature)))
    }
}

/// The FCM sender: the account, the API, and the token that serves now.
pub struct Fcm {
    account: ServiceAccount,
    send: Url,
    tls: Arc<rustls::ClientConfig>,
    token: Mutex<Option<(String, u64)>>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl Fcm {
    /// A sender for `account` at the API of `api`, which is [`FCM_API`]
    /// in a deployment.
    pub fn new(account: ServiceAccount, api: &str, tls: Arc<rustls::ClientConfig>) -> Option<Self> {
        let send = Url::parse(&format!(
            "{api}/v1/projects/{}/messages:send",
            account.project_id
        ))?;
        Some(Fcm {
            account,
            send,
            tls,
            token: Mutex::new(None),
        })
    }

    /// The access token, fetched again near its end.
    async fn access_token(&self) -> Option<String> {
        let mut held = self.token.lock().await;
        let now = unix_now();
        if let Some((token, until)) = held.as_ref() {
            if now.saturating_add(TOKEN_MARGIN) < *until {
                return Some(token.clone());
            }
        }
        let assertion = self.account.assertion(now)?;
        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );
        let (status, answer) = https::post(
            &self.account.token_uri,
            "application/x-www-form-urlencoded",
            &[],
            body.as_bytes(),
            self.tls.clone(),
            16_384,
            WAIT,
        )
        .await
        .ok()?;
        if status != 200 {
            return None;
        }
        let answer = core::str::from_utf8(&answer).ok()?;
        let token = json_string(answer, "access_token")?;
        let life = json_number(answer, "expires_in").unwrap_or(3_600);
        *held = Some((token.clone(), now.saturating_add(life)));
        Some(token)
    }

    /// Sends one data message of high priority to `token` with the blob in
    /// base64url and the expiry of the push (`NTF-065`), with no collapse
    /// key (`NTF-088`). Gives the status of FCM: 404 names a token that is
    /// gone (`NTF-125`).
    pub async fn send(&self, token: &str, blob: &[u8], ttl: u32) -> Option<u16> {
        let access = self.access_token().await?;
        let message = format!(
            "{{\"message\":{{\"token\":{},\"data\":{{\"b\":{}}},\"android\":{{\"priority\":\"HIGH\",\"ttl\":\"{ttl}s\"}}}}}}",
            json_quote(token),
            json_quote(&base64url(blob)),
        );
        let authorization = format!("Bearer {access}");
        https::post(
            &self.send,
            "application/json",
            &[("Authorization", &authorization)],
            message.as_bytes(),
            self.tls.clone(),
            16_384,
            WAIT,
        )
        .await
        .ok()
        .map(|(status, _)| status)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn json_fields_and_base64_read_and_write() {
        let json = r#"{ "a" : "x\ny\"z", "n": 3599, "u": "A" }"#;
        assert_eq!(json_string(json, "a").unwrap(), "x\ny\"z");
        assert_eq!(json_number(json, "n"), Some(3599));
        assert_eq!(json_string(json, "u").unwrap(), "A");
        assert_eq!(json_string(json, "missing"), None);
        assert_eq!(json_quote("a\"b\\c\n"), r#""a\"b\\c\u000a""#);
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xFB, 0xFF]), "-_8");
        assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
    }
}
