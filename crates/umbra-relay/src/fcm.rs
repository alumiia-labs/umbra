//! The FCM sender of the Notification Delivery Relay (Part 8 §8.2): the
//! HTTP v1 API of Firebase Cloud Messaging under the service account of the
//! deployment. The NDR alone holds that account, and no queue relay touches
//! it.
//!
//! The access token comes from the OAuth 2.0 token endpoint of the account
//! for a JWT that the account key signs under RS256, and it serves until
//! shortly before its expiry. The key signs through the `aws-lc-rs` that the
//! TLS stack holds already, and the few JSON fields that this needs are read
//! and written here, thus no crate enters register R3 (Part 14 §14.2.3).

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{rand::SystemRandom, signature::RsaKeyPair};
use tokio::sync::Mutex;
use umbra_crypto::zeroize::Zeroizing;
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
/// The time after a fetch of the access token that failed in which no
/// second fetch goes, in seconds. The NDR refuses a push inside it at once.
/// A token endpoint that is down thus holds no connection for `WAIT`.
const TOKEN_RETRY: u64 = 5;
/// The error code of FCM for a registration token that is gone.
const UNREGISTERED: &str = "UNREGISTERED";
/// The error code of FCM for a request with a field that is not valid.
const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";

/// What FCM did with one push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// FCM took the push.
    Taken,
    /// FCM named the registration token gone (`NTF-125`).
    Gone,
    /// FCM named the registration token one that it never gave, as a token
    /// that a party made up. The push did not go.
    Invalid,
    /// The push did not go, and the token stays.
    Refused,
}

/// Reads the answer of FCM to one send. FCM gives the status 404 for a
/// token that is gone, and for other faults too, as a project that does
/// not exist. Thus the token is gone only when the error body names
/// `UNREGISTERED`, and a fault of the settings drops no registration
/// (`NTF-130`). A status 400 names the token not valid only when its body
/// names the registration token: a fault of another field of the message
/// is a fault of the NDR, and it says nothing of the token.
pub fn sent_of(status: u16, body: &[u8]) -> Sent {
    let field = |key: &str| {
        core::str::from_utf8(body)
            .ok()
            .and_then(|body| json_string(body, key))
    };

    match status {
        200..=299 => Sent::Taken,
        404 if field("errorCode").as_deref() == Some(UNREGISTERED) => Sent::Gone,
        400 if field("errorCode").as_deref() == Some(INVALID_ARGUMENT) => {
            let names_token = field("field").as_deref() == Some("message.token")
                || field("message").is_some_and(|text| text.contains("registration token"));
            if names_token {
                Sent::Invalid
            } else {
                Sent::Refused
            }
        }
        _ => Sent::Refused,
    }
}

/// Reads the string of `key` in a flat JSON object, with the escapes that a
/// service account file holds.
pub fn json_string(json: &str, key: &str) -> Option<String> {
    let rest = value_after(json, key)?.strip_prefix('"')?;

    // The string can be a key, thus it takes its full room at once and no
    // growth leaves a copy behind.
    let mut out = String::with_capacity(rest.len());
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

/// Decodes the standard base64 of a PEM body. The body is a key, thus each
/// buffer wipes itself.
fn base64_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
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

    let mut clean = Zeroizing::new(Vec::with_capacity(text.len()));
    clean.extend(
        text.bytes()
            .filter(|c| !c.is_ascii_whitespace() && *c != b'='),
    );

    let mut out = Zeroizing::new(Vec::with_capacity(clean.len() * 3 / 4 + 3));
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
    /// Reads a service account file of Google Cloud. Each copy of the key
    /// wipes itself when the read ends.
    pub fn parse(json: &str) -> Option<ServiceAccount> {
        let pem = Zeroizing::new(json_string(json, "private_key")?);
        let mut body = Zeroizing::new(String::with_capacity(pem.len()));
        for line in pem.lines().filter(|line| !line.starts_with("-----")) {
            body.push_str(line);
        }

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

/// The access token that serves now with its end, and the time of the
/// last fetch that failed.
#[derive(Default)]
struct Access {
    token: Option<(String, u64)>,
    failed_at: Option<u64>,
}

/// The FCM sender: the account, the API, and the token that serves now.
pub struct Fcm {
    account: ServiceAccount,
    send: Url,
    tls: Arc<rustls::ClientConfig>,
    access: Mutex<Access>,
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
            access: Mutex::new(Access::default()),
        })
    }

    /// The access token, fetched again near its end. One fetch runs at a
    /// time. A fetch that fails refuses each push that waited for it, and
    /// no second fetch goes inside `TOKEN_RETRY`.
    async fn access_token(&self) -> Option<String> {
        let mut held = self.access.lock().await;
        let now = unix_now();

        if let Some((token, until)) = held.token.as_ref() {
            if now.saturating_add(TOKEN_MARGIN) < *until {
                return Some(token.clone());
            }
        }

        if held
            .failed_at
            .is_some_and(|at| now.saturating_sub(at) < TOKEN_RETRY)
        {
            return None;
        }

        let fetched = self.fetch_token(now).await;
        match &fetched {
            Some((token, until)) => {
                held.token = Some((token.clone(), *until));
                held.failed_at = None;
            }
            None => held.failed_at = Some(unix_now()),
        }

        fetched.map(|(token, _)| token)
    }

    /// One fetch of the access token at the token endpoint, with its end.
    async fn fetch_token(&self, now: u64) -> Option<(String, u64)> {
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
        Some((token, now.saturating_add(life)))
    }

    /// Sends one data message to `token` with the expiry of the push
    /// (`NTF-065`) and no collapse key (`NTF-088`): the blob in base64url at
    /// high priority, or the tick of the fixed clock at normal priority
    /// (`NTF-039`, `NTF-150`). Gives what FCM did with it ([`sent_of`]). The
    /// body holds the push token, thus the send wipes it at its end (§8.2.1).
    pub async fn send(&self, token: &str, blob: Option<&[u8]>, ttl: u32) -> Sent {
        let Some(access) = self.access_token().await else {
            return Sent::Refused;
        };

        let message = message_of(token, blob, ttl);
        let authorization = format!("Bearer {access}");

        let answer = https::post(
            &self.send,
            "application/json",
            &[("Authorization", &authorization)],
            message.as_bytes(),
            self.tls.clone(),
            16_384,
            WAIT,
        )
        .await;

        match answer {
            Ok((status, body)) => sent_of(status, &body),
            Err(_) => Sent::Refused,
        }
    }
}

/// The body of one send (`NTF-130`). It takes its full length at the start,
/// thus no shorter copy of the push token stays in freed memory. A tick
/// carries the one field `t`, and Doze may defer it (`NTF-039`).
fn message_of(token: &str, blob: Option<&[u8]>, ttl: u32) -> Zeroizing<String> {
    let quoted = Zeroizing::new(json_quote(token));
    let mut message = Zeroizing::new(String::with_capacity(quoted.len().saturating_add(256)));

    message.push_str("{\"message\":{\"token\":");
    message.push_str(&quoted);
    match blob {
        Some(blob) => {
            message.push_str(",\"data\":{\"b\":");
            message.push_str(&json_quote(&base64url(blob)));
            message.push_str("},\"android\":{\"priority\":\"HIGH\",\"ttl\":\"");
        }
        None => message
            .push_str(",\"data\":{\"t\":\"1\"},\"android\":{\"priority\":\"NORMAL\",\"ttl\":\""),
    }
    message.push_str(&ttl.to_string());
    message.push_str("s\"}}}");
    message
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

        assert_eq!(base64_decode("Zm9vYmE=").unwrap().as_slice(), b"fooba");
        assert_eq!(base64_decode("Zm9v\nYmFy").unwrap().as_slice(), b"foobar");
    }

    #[test]
    fn a_token_is_gone_only_when_the_error_body_names_it_unregistered() {
        // NTF-130: the body of FCM for a registration token that is gone.
        let gone = br#"{"error":{"code":404,"message":"Requested entity was not found.","status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#;
        assert_eq!(sent_of(404, gone), Sent::Gone);

        // A project that does not exist gives 404 too, and it names no
        // token: the registration stays.
        let other = br#"{"error":{"code":404,"message":"Requested entity was not found.","status":"NOT_FOUND"}}"#;
        assert_eq!(sent_of(404, other), Sent::Refused);

        assert_eq!(sent_of(404, b"<html>not found</html>"), Sent::Refused);
        assert_eq!(sent_of(200, b"{}"), Sent::Taken);
        assert_eq!(sent_of(400, gone), Sent::Refused);
        assert_eq!(sent_of(503, b""), Sent::Refused);
    }

    #[test]
    fn a_token_is_not_valid_only_when_the_error_body_names_the_token() {
        // The body of FCM for a token that it never gave.
        let invalid = br#"{"error":{"code":400,"message":"The registration token is not a valid FCM registration token","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"INVALID_ARGUMENT"}]}}"#;
        assert_eq!(sent_of(400, invalid), Sent::Invalid);
        let by_field = br#"{"error":{"code":400,"message":"Invalid value","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"INVALID_ARGUMENT"},{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.token","description":"Invalid value"}]}]}}"#;
        assert_eq!(sent_of(400, by_field), Sent::Invalid);

        // A fault of another field is a fault of the NDR, and the token
        // stays.
        let ttl = br#"{"error":{"code":400,"message":"Invalid value at 'message.android.ttl'","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"INVALID_ARGUMENT"},{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"message.android.ttl","description":"Invalid value"}]}]}}"#;
        assert_eq!(sent_of(400, ttl), Sent::Refused);
        assert_eq!(sent_of(404, invalid), Sent::Refused);
    }

    #[test]
    fn the_body_of_a_send_is_a_data_message_of_high_priority() {
        // NTF-130: one data field, no `notification` field.
        assert_eq!(
            message_of("tok\"en", Some(b"foo"), 3_600).as_str(),
            r#"{"message":{"token":"tok\"en","data":{"b":"Zm9v"},"android":{"priority":"HIGH","ttl":"3600s"}}}"#
        );
    }

    #[test]
    fn the_body_of_a_tick_names_no_content_and_takes_normal_priority() {
        // NTF-039, NTF-150: the tick of the fixed clock is no high-priority
        // message, and its one field carries nothing.
        assert_eq!(
            message_of("token", None, 1_800).as_str(),
            r#"{"message":{"token":"token","data":{"t":"1"},"android":{"priority":"NORMAL","ttl":"1800s"}}}"#
        );
    }
}
