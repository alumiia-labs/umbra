//! The client side of the requests of Part 9 §9.10 and Part 13 §13.9: the
//! body of each request, and the check of each answer. The caller carries
//! the padded `DirRequest` in OHTTP.

use alloc::{vec, vec::Vec};

use umbra_crypto::{
    rand_core::TryCryptoRng,
    rsabssa::PublicKey2048,
    voprf::{BatchEvaluation, BlindState, Evaluation},
};
use umbra_wire::{
    admission::{Admission, AdmissionKind},
    codec::Reader,
    directory::{self, put_var16, take_var16, Kind, Status, ISSUE_REQUEST_MAX},
};

use super::{
    challenge::{Purpose, CHALLENGE_LEN},
    service::{issue_seed, issue_verifier, lookup_seed, lookup_verifier},
    translog::{LookupProof, VersionProof},
};
use crate::{
    abuse::{
        pow::{PowSolution, SOLUTION_LEN},
        token::{
            CrossRelayRequest, FirstPartyRequest, Token, TokenChallenge, TYPE_CROSS_RELAY,
            TYPE_FIRST_PARTY,
        },
        POW_EFFORT_MAX, POW_LOOKUP_FLOOR,
    },
    Error,
};

/// The padded request of `kind`.
pub fn request(kind: Kind, body: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(directory::encode_request(kind, body)?)
}

/// The body of a response whose status is done, or the status.
pub fn done(response: &[u8]) -> Result<Vec<u8>, DirError> {
    let (status, body) = directory::parse_response(response).map_err(|_| DirError::Malformed)?;
    match status {
        Status::Done => Ok(body.to_vec()),
        other => Err(DirError::Status(other)),
    }
}

/// Why a directory request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirError {
    /// The response did not parse, or its content did not verify.
    Malformed,
    /// The directory answered with this status.
    Status(Status),
}

impl From<Error> for DirError {
    fn from(_: Error) -> Self {
        DirError::Malformed
    }
}

/// A request for first-party tokens on path 3, with the proof of work of
/// each token solved (`ABU-076`, `ABU-109`). This takes some seconds.
pub fn issue_request<R: TryCryptoRng + ?Sized>(
    epoch: u32,
    issuer_pk: &[u8; 32],
    count: usize,
    rng: &mut R,
) -> Result<(FirstPartyRequest, Vec<u8>), Error> {
    if count == 0 || count > ISSUE_REQUEST_MAX {
        return Err(Error::Malformed);
    }
    let challenge = TokenChallenge {
        token_type: TYPE_FIRST_PARTY,
        epoch,
        redemption_context: [0; 32],
    };
    let (state, blinded) = FirstPartyRequest::new(count, &challenge, issuer_pk, rng)?;
    let verifier = issue_verifier(issuer_pk);
    let mut body = Vec::new();
    body.extend_from_slice(&TYPE_FIRST_PARTY.to_be_bytes());
    body.extend_from_slice(&epoch.to_be_bytes());
    body.push(u8::try_from(count).map_err(|_| Error::Malformed)?);
    for element in &blinded {
        let solution =
            PowSolution::solve(&verifier, &issue_seed(epoch, element), POW_EFFORT_MAX, rng)?;
        let mut encoded = [0u8; SOLUTION_LEN];
        solution.encode(&mut encoded)?;
        body.extend_from_slice(element);
        body.extend_from_slice(&encoded);
    }
    Ok((state, body))
}

/// A request for `count` cross-relay tokens of `epoch` (Part 13 §13.3.1),
/// each blinded under the key of the issuer that the log gives, and each
/// paid with a proof of work at `POW_EFFORT_MAX` (`ABU-076`).
pub fn cross_relay_issue_request<R: TryCryptoRng + ?Sized>(
    epoch: u32,
    issuer_pk: &PublicKey2048,
    count: usize,
    rng: &mut R,
) -> Result<(CrossRelayRequest, Vec<u8>), Error> {
    if count == 0 || count > ISSUE_REQUEST_MAX {
        return Err(Error::Malformed);
    }
    let challenge = TokenChallenge {
        token_type: TYPE_CROSS_RELAY,
        epoch,
        redemption_context: [0; 32],
    };
    let (state, blinded) = CrossRelayRequest::new(count, &challenge, issuer_pk, rng)?;
    let verifier = issue_verifier(issuer_pk.modulus());
    let mut body = Vec::new();
    body.extend_from_slice(&TYPE_CROSS_RELAY.to_be_bytes());
    body.extend_from_slice(&epoch.to_be_bytes());
    body.push(u8::try_from(count).map_err(|_| Error::Malformed)?);
    for message in &blinded {
        let solution =
            PowSolution::solve(&verifier, &issue_seed(epoch, message), POW_EFFORT_MAX, rng)?;
        let mut encoded = [0u8; SOLUTION_LEN];
        solution.encode(&mut encoded)?;
        body.extend_from_slice(message);
        body.extend_from_slice(&encoded);
    }
    Ok((state, body))
}

/// The cross-relay tokens of an issuance response, each verified under the
/// key of the issuer.
pub fn cross_relay_issue_finish(
    state: &CrossRelayRequest,
    body: &[u8],
    issuer_pk: &PublicKey2048,
) -> Result<Vec<Token>, Error> {
    let mut r = Reader::new(body);
    let count = usize::from(r.u8()?);
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        signatures.push(r.take(PublicKey2048::MODULUS_LEN)?.to_vec());
    }
    r.finish()?;
    state.finalize(&signatures, issuer_pk)
}

/// The tokens of an issuance response, after the batch proof verified.
pub fn issue_finish(
    state: &FirstPartyRequest,
    body: &[u8],
    issuer_pk: &[u8; 32],
) -> Result<Vec<Token>, Error> {
    let mut r = Reader::new(body);
    let count = usize::from(r.u8()?);
    let mut elements = Vec::with_capacity(count);
    for _ in 0..count {
        elements.push(r.array()?);
    }
    let proof = r.array()?;
    r.finish()?;
    state.finalize(&BatchEvaluation { elements, proof }, issuer_pk)
}

/// The encoded bytes of a token.
pub fn token_bytes(token: &Token) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; token.len()];
    let used = token.encode(&mut out)?;
    out.truncate(used);
    Ok(out)
}

/// An evaluation request for `label_input`, under a first-party token when
/// the caller gives one, or else a proof of work at `POW_LOOKUP_FLOOR`
/// (`DIS-164`, `DIS-165`).
pub fn evaluate_request<R: TryCryptoRng + ?Sized>(
    label_input: &[u8],
    directory_pk: &[u8; 32],
    epoch: u32,
    token: Option<&[u8]>,
    rng: &mut R,
) -> Result<(BlindState, Vec<u8>), Error> {
    let (state, blinded) = BlindState::blind(label_input, rng)?;
    let mut encoded = [0u8; SOLUTION_LEN];
    let admission = match token {
        Some(token) => Admission {
            kind: AdmissionKind::Token,
            body: token,
        },
        None => {
            let solution = PowSolution::solve(
                &lookup_verifier(directory_pk),
                &lookup_seed(epoch, &blinded),
                POW_LOOKUP_FLOOR,
                rng,
            )?;
            solution.encode(&mut encoded)?;
            Admission {
                kind: AdmissionKind::Pow,
                body: &encoded,
            }
        }
    };
    let mut body = vec![0u8; admission.len() + 32];
    let used = admission.encode(&mut body)?;
    body.truncate(used);
    body.extend_from_slice(&blinded);
    Ok((state, body))
}

/// The search key of an evaluation response, after its proof verified.
pub fn evaluate_finish(
    state: &BlindState,
    body: &[u8],
    directory_pk: &[u8; 32],
) -> Result<[u8; 64], Error> {
    let mut r = Reader::new(body);
    let evaluation = Evaluation {
        element: r.array()?,
        proof: r.array()?,
    };
    r.finish()?;
    Ok(state.finalize(&evaluation, directory_pk)?)
}

/// A lookup response: the head and the proof.
/// A parsed lookup: the head bytes, the sealed profile blob, and the proof.
pub type Looked = (Vec<u8>, Option<Vec<u8>>, LookupProof);

/// A lookup response: the head, the sealed profile blob of the label when
/// it holds one (`DIS-175`), and the proof.
pub fn parse_lookup(body: &[u8]) -> Result<Looked, Error> {
    let mut r = Reader::new(body);
    let head = take_var16(&mut r)?.to_vec();
    let blob = take_var16(&mut r)?;
    let blob = (!blob.is_empty()).then(|| blob.to_vec());
    let proof = LookupProof::parse(r.rest())?;
    Ok((head, blob, proof))
}

/// The body of a version request (`DIS-079`).
pub fn version_body(search_key: &[u8; 64], version: u32) -> Vec<u8> {
    [&search_key[..], &version.to_be_bytes()].concat()
}

/// A version response: the head bytes and the proof.
pub fn parse_version(body: &[u8]) -> Result<(Vec<u8>, VersionProof), Error> {
    let mut r = Reader::new(body);
    let head = take_var16(&mut r)?.to_vec();
    let proof = VersionProof::parse(r.rest())?;
    Ok((head, proof))
}

/// The body of a blob challenge (`DIS-175`).
pub fn blob_challenge_body(label_input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = vec![0x03];
    put_var16(&mut body, label_input)?;
    Ok(body)
}

/// The body of a blob write: the label, the answer, and the sealed blob,
/// or no blob to drop it.
pub fn blob_body(label_input: &[u8], answer: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    put_var16(&mut body, label_input)?;
    body.extend_from_slice(answer);
    put_var16(&mut body, blob)?;
    Ok(body)
}

/// A head response: the head and the consistency proof.
pub fn parse_head(body: &[u8]) -> Result<(Vec<u8>, Vec<[u8; 32]>), Error> {
    let mut r = Reader::new(body);
    let head = take_var16(&mut r)?.to_vec();
    let count = usize::from(r.u8()?);
    let mut proof = Vec::with_capacity(count);
    for _ in 0..count {
        proof.push(r.array()?);
    }
    r.finish()?;
    Ok((head, proof))
}

/// The purpose byte of a registration challenge (`DIS-197`).
pub const REGISTER_PURPOSE: u8 = 0x04;

/// The body of a registration challenge: the label input and the key of the
/// entry that registers (`DIS-197`). The directory encapsulates to that key.
pub fn register_challenge_body(label_input: &[u8], entry_pk: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = vec![REGISTER_PURPOSE];
    put_var16(&mut body, label_input)?;
    body.extend_from_slice(entry_pk);
    Ok(body)
}

/// A registration challenge response: the challenge, and the version that
/// the entry must carry (`DIS-170`). The holder answers it as the write
/// challenge of that version, with the answer over the entry (`DIS-197`).
pub fn parse_register_challenge(body: &[u8]) -> Result<(Vec<u8>, Purpose), Error> {
    let challenge = body.get(..CHALLENGE_LEN).ok_or(Error::Malformed)?.to_vec();
    let version: [u8; 4] = body
        .get(CHALLENGE_LEN..)
        .and_then(|rest| rest.try_into().ok())
        .ok_or(Error::Malformed)?;
    Ok((
        challenge,
        Purpose::Write {
            version_new: u32::from_be_bytes(version),
        },
    ))
}

/// The body of a registration: the token, the label, the entry, the answer
/// to the registration challenge, and the lease of a timed link.
pub fn register_body(
    token: &[u8],
    label_input: &[u8],
    entry: &[u8],
    answer: &[u8; 32],
    lease: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let mut body = token.to_vec();
    put_var16(&mut body, label_input)?;
    put_var16(&mut body, entry)?;
    body.extend_from_slice(answer);
    // DIS-172: the end of a timed link, which the directory keeps.
    if let Some(seconds) = lease {
        body.extend_from_slice(&seconds.to_be_bytes());
    }
    Ok(body)
}

/// The body of a key-set request: the `keyset_epoch` that the reader holds.
pub fn keyset_body(keyset_epoch: u64) -> Vec<u8> {
    keyset_epoch.to_be_bytes().to_vec()
}

/// A key-set response: each `SignedLogKeySet` after the held set, in order
/// (`DIS-198`).
pub fn parse_keysets(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut r = Reader::new(body);
    let count = usize::from(r.u8()?);
    let mut sets = Vec::with_capacity(count);
    for _ in 0..count {
        sets.push(take_var16(&mut r)?.to_vec());
    }
    r.finish()?;
    Ok(sets)
}

/// The body of a challenge request: renew or write.
pub fn challenge_body(renew: bool, label_input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = vec![if renew { 0x01 } else { 0x02 }];
    put_var16(&mut body, label_input)?;
    Ok(body)
}

/// A challenge response: the challenge and its purpose. `version` is the
/// version the client holds, which a write challenge adds one to.
pub fn parse_challenge(body: &[u8], version: u32) -> Result<(Vec<u8>, Purpose), Error> {
    let challenge = body.get(..CHALLENGE_LEN).ok_or(Error::Malformed)?.to_vec();
    let purpose = match body.get(CHALLENGE_LEN..) {
        Some([]) => Purpose::Write {
            version_new: version.checked_add(1).ok_or(Error::Malformed)?,
        },
        Some(rest) => Purpose::Renew {
            lease_epoch: u64::from_be_bytes(rest.try_into().map_err(|_| Error::Malformed)?),
        },
        None => return Err(Error::Malformed),
    };
    Ok((challenge, purpose))
}

/// The body of a write.
pub fn write_body(label_input: &[u8], answer: &[u8; 32], entry: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    put_var16(&mut body, label_input)?;
    body.extend_from_slice(answer);
    put_var16(&mut body, entry)?;
    Ok(body)
}

/// The body of a renewal.
pub fn renew_body(label_input: &[u8], answer: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    put_var16(&mut body, label_input)?;
    body.extend_from_slice(answer);
    Ok(body)
}

/// What a client build pins for the directory (`DIS-163`): the key
/// configuration of its OHTTP gateway, the genesis `LogKeySet`, the ECVRF
/// key of the log, and the VOPRF key of the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryPins {
    /// The OHTTP key configuration.
    pub key_config: Vec<u8>,
    /// The encoded `LogKeySet`.
    pub keyset: Vec<u8>,
    /// The ECVRF key of the log.
    pub vrf_public: [u8; 32],
    /// The VOPRF key of the directory.
    pub voprf_public: [u8; 32],
}

impl DirectoryPins {
    /// The bytes that a build ships.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        put_var16(&mut out, &self.key_config)?;
        put_var16(&mut out, &self.keyset)?;
        out.extend_from_slice(&self.vrf_public);
        out.extend_from_slice(&self.voprf_public);
        Ok(out)
    }

    /// Reads the bytes that a build ships.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let key_config = take_var16(&mut r)?.to_vec();
        let keyset = take_var16(&mut r)?.to_vec();
        let pins = DirectoryPins {
            key_config,
            keyset,
            vrf_public: r.array()?,
            voprf_public: r.array()?,
        };
        r.finish()?;
        Ok(pins)
    }
}
