//! The link receipts of Part 10 §10.4.2: the `LinkReceipt` that a relay
//! issues for a window of cells, the `RelayHello` that names the relay that
//! dialed a link, and the `ReceiptQuery` and `ReceiptAnswer` of an isolation
//! query.

use alloc::vec::Vec;

use umbra_crypto::{
    labels,
    rand_core::CryptoRng,
    sign::{Signature, SigningKey, VerifyingKey, SIGNATURE_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::{
    root::DirectoryKeySet,
    tree::{self, Step},
};
use crate::Error;

/// The encoded width of a `LinkReceipt`.
pub const RECEIPT_LEN: usize = 1 + 32 + 32 + 8 + 4 + 4 + 32 + SIGNATURE_LEN;
/// The encoded width of a `RelayHello`.
pub const RELAY_HELLO_LEN: usize = 1 + 32 + SIGNATURE_LEN;
/// The encoded width of a `ReceiptQuery`.
pub const RECEIPT_QUERY_LEN: usize = 1 + 1 + 32 + 8 + 16 + SIGNATURE_LEN;
/// `RECEIPT_WINDOW`: the cells of one receipt.
pub const RECEIPT_WINDOW: u32 = 1_024;
/// `RECEIPT_RETENTION`, in seconds.
pub const RECEIPT_RETENTION: u64 = 48 * 3_600;
/// The most steps of the proof of one leaf of a window.
const STEPS_MAX: usize = 16;

/// The leaf of one cell: the tree leaf over its tag (`REL-175`).
pub fn cell_leaf(tag: &[u8; 16]) -> [u8; 32] {
    tree::leaf(tag)
}

fn verify_under(identity_pk: &[u8], message: &[u8], sig: &[u8]) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(identity_pk)?;
    key.verify(message, &Signature::from_bytes(sig)?)
        .map_err(|_| Error::Unverified)
}

/// A receipt of one window of cells on one link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkReceipt {
    /// The relay that sent the cells.
    pub from_relay: [u8; 32],
    /// The relay that took them and signed.
    pub to_relay: [u8; 32],
    /// The consensus epoch.
    pub epoch: u64,
    /// The window inside that epoch.
    pub window: u32,
    /// The cells of the window.
    pub cell_count: u32,
    /// The root over their leaves.
    pub batch_root: [u8; 32],
}

impl LinkReceipt {
    fn fields(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.u8(0x01)?;
        w.put(&self.from_relay)?;
        w.put(&self.to_relay)?;
        w.put(&self.epoch.to_be_bytes())?;
        w.put(&self.window.to_be_bytes())?;
        w.put(&self.cell_count.to_be_bytes())?;
        w.put(&self.batch_root)?;
        Ok(())
    }

    fn preimage(&self) -> Result<Vec<u8>, Error> {
        let mut body = [0u8; RECEIPT_LEN - SIGNATURE_LEN];
        self.fields(&mut Writer::new(&mut body))?;
        Ok([labels::LINK_RECEIPT, &body].concat())
    }

    /// Signs the receipt with the identity key of `to_relay` (`REL-072`).
    pub fn sign<R: CryptoRng + ?Sized>(
        &self,
        key: &SigningKey,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let sig = key.sign(&self.preimage()?, rng)?;
        let mut out = alloc::vec![0u8; RECEIPT_LEN];
        let mut w = Writer::new(&mut out);
        self.fields(&mut w)?;
        w.put(&sig.to_bytes())?;
        Ok(out)
    }

    /// Reads a receipt with no check of its signature.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let receipt = LinkReceipt {
            from_relay: r.array()?,
            to_relay: r.array()?,
            epoch: u64::from_be_bytes(r.array()?),
            window: u32::from_be_bytes(r.array()?),
            cell_count: u32::from_be_bytes(r.array()?),
            batch_root: r.array()?,
        };
        r.take(SIGNATURE_LEN)?;
        r.finish()?;
        if receipt.cell_count == 0 || receipt.cell_count > RECEIPT_WINDOW {
            return Err(Error::Malformed);
        }
        Ok(receipt)
    }

    /// Reads a receipt and verifies it under the identity key of its
    /// `to_relay` (`REL-178`).
    pub fn verify(bytes: &[u8], identity_pk: &[u8]) -> Result<Self, Error> {
        let receipt = Self::parse(bytes)?;
        let sig = bytes
            .get(RECEIPT_LEN - SIGNATURE_LEN..)
            .ok_or(Error::Malformed)?;
        verify_under(identity_pk, &receipt.preimage()?, sig)?;
        Ok(receipt)
    }
}

/// What the signature of a `RelayHello` covers: the relay that dialed, the
/// relay that it dialed, and the session of the link. The dialer chooses
/// the session, thus the session alone binds no link. The relay that took a
/// hello could show it to a third relay under the same session.
fn hello_preimage(relay_id: &[u8; 32], to_relay: &[u8; 32], session_id: &[u8; 8]) -> Vec<u8> {
    [
        labels::RELAY_HELLO,
        relay_id.as_slice(),
        to_relay.as_slice(),
        session_id,
    ]
    .concat()
}

/// The `RelayHello` of a relay that dialed the relay `to_relay` on a link
/// with the session `session_id` (`REL-173`).
pub fn relay_hello<R: CryptoRng + ?Sized>(
    relay_id: &[u8; 32],
    to_relay: &[u8; 32],
    session_id: &[u8; 8],
    key: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let sig = key.sign(&hello_preimage(relay_id, to_relay, session_id), rng)?;
    Ok([&[0x01][..], relay_id, &sig.to_bytes()].concat())
}

/// The relay that a `RelayHello` names, after its signature verified under
/// the identity key that `identity_of` gives for it (`REL-174`). `own` is
/// the relay that took the hello. A hello for another relay does not
/// verify.
pub fn verify_relay_hello(
    bytes: &[u8],
    own: &[u8; 32],
    session_id: &[u8; 8],
    identity_of: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<[u8; 32], Error> {
    let mut r = Reader::new(bytes);
    if r.u8()? != 0x01 {
        return Err(Error::Malformed);
    }
    let relay_id: [u8; 32] = r.array()?;
    let sig = r.take(SIGNATURE_LEN)?;
    r.finish()?;
    // A relay does not dial itself.
    if relay_id == *own {
        return Err(Error::Unverified);
    }
    let identity_pk = identity_of(&relay_id).ok_or(Error::Unverified)?;
    verify_under(
        &identity_pk,
        &hello_preimage(&relay_id, own, session_id),
        sig,
    )?;
    Ok(relay_id)
}

/// A query of an authority to one relay for the receipt of one cell
/// (`REL-081`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptQuery {
    /// The index of the authority in the key set.
    pub authority_index: u8,
    /// The relay that the query asks. The signature covers it, thus the
    /// query of one relay is no query at another (`REL-179`).
    pub relay_id: [u8; 32],
    /// The consensus epoch of the probe.
    pub epoch: u64,
    /// The tag of the cell as one link carried it.
    pub tag: [u8; 16],
}

impl ReceiptQuery {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECEIPT_QUERY_LEN);
        out.push(0x01);
        out.push(self.authority_index);
        out.extend_from_slice(&self.relay_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.tag);
        out
    }

    /// Signs the query with the key of its authority.
    pub fn sign<R: CryptoRng + ?Sized>(
        &self,
        key: &SigningKey,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let body = self.body();
        let sig = key.sign(&[labels::RECEIPT_QUERY, &body].concat(), rng)?;
        Ok([body.as_slice(), &sig.to_bytes()].concat())
    }

    /// Reads a query and verifies it under `keyset` (`REL-179`). The relay
    /// that took it then tests `relay_id` against its own with
    /// [`ReceiptQuery::asks`].
    pub fn verify(bytes: &[u8], keyset: &DirectoryKeySet<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let query = ReceiptQuery {
            authority_index: r.u8()?,
            relay_id: r.array()?,
            epoch: u64::from_be_bytes(r.array()?),
            tag: r.array()?,
        };
        let sig = r.take(SIGNATURE_LEN)?;
        r.finish()?;
        let preimage = [labels::RECEIPT_QUERY, &query.body()].concat();
        keyset.verify_by(query.authority_index, &preimage, sig)?;
        Ok(query)
    }

    /// Whether the query asks the relay `own`. A relay answers no other
    /// query (`REL-179`).
    pub fn asks(&self, own: &[u8; 32]) -> bool {
        self.relay_id == *own
    }

    /// The leaf of the cell that the query names.
    pub fn leaf(&self) -> [u8; 32] {
        cell_leaf(&self.tag)
    }
}

/// Whether `proof` has the shape of the proof of the leaf at `index` in a
/// tree of `count` leaves (§10.5.3). That shape is one step at each level
/// where the node has a sibling, on the side that the index gives.
fn proof_fits(proof: &[Step], index: u32, count: u32) -> bool {
    if index >= count {
        return false;
    }
    let (mut at, mut width) = (index, count);
    let mut steps = proof.iter();
    while width > 1 {
        let sibling = at ^ 1;
        if sibling < width {
            match steps.next() {
                Some(step) if step.sibling_right == (sibling > at) => {}
                _ => return false,
            }
        }
        at /= 2;
        width = width.div_ceil(2);
    }
    steps.next().is_none()
}

/// Which receipt an answer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// The relay holds no receipt of the cell.
    None = 0x00,
    /// A receipt that the relay issued: the cell reached it.
    Issued = 0x01,
    /// A receipt that the relay took: it sent the cell.
    Taken = 0x02,
}

/// The answer of a relay to a `ReceiptQuery`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAnswer {
    /// Which receipt it holds.
    pub found: Found,
    /// The signed receipt, when one was found.
    pub receipt: Vec<u8>,
    /// The index of the leaf in its window.
    pub leaf_index: u32,
    /// The proof of the leaf under `batch_root`.
    pub proof: Vec<Step>,
}

impl ReceiptAnswer {
    /// The answer of a relay that holds no receipt of the cell.
    pub fn none() -> Self {
        ReceiptAnswer {
            found: Found::None,
            receipt: Vec::new(),
            leaf_index: 0,
            proof: Vec::new(),
        }
    }

    /// Writes the answer.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0x01, self.found as u8];
        if self.found == Found::None {
            return Ok(out);
        }
        if self.receipt.len() != RECEIPT_LEN || self.proof.len() > STEPS_MAX {
            return Err(Error::Malformed);
        }
        out.extend_from_slice(&self.receipt);
        out.extend_from_slice(&self.leaf_index.to_be_bytes());
        out.push(u8::try_from(self.proof.len()).map_err(|_| Error::Malformed)?);
        for step in &self.proof {
            out.push(u8::from(step.sibling_right));
            out.extend_from_slice(&step.sibling);
        }
        Ok(out)
    }

    /// Reads an answer. The caller verifies the receipt and the proof.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let found = match r.u8()? {
            0x00 => Found::None,
            0x01 => Found::Issued,
            0x02 => Found::Taken,
            _ => return Err(Error::Malformed),
        };
        if found == Found::None {
            r.finish()?;
            return Ok(Self::none());
        }
        let receipt = r.take(RECEIPT_LEN)?.to_vec();
        let leaf_index = u32::from_be_bytes(r.array()?);
        let count = usize::from(r.u8()?);
        if count > STEPS_MAX {
            return Err(Error::Malformed);
        }
        let mut proof = Vec::with_capacity(count);
        for _ in 0..count {
            let sibling_right = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::Malformed),
            };
            proof.push(Step {
                sibling: r.array()?,
                sibling_right,
            });
        }
        r.finish()?;
        Ok(ReceiptAnswer {
            found,
            receipt,
            leaf_index,
            proof,
        })
    }

    /// Whether the receipt verifies under the identity key of its
    /// `to_relay` and the proof puts the cell of `query` under its root, at
    /// `leaf_index` among the `cell_count` cells of the receipt.
    pub fn covers(
        &self,
        query: &ReceiptQuery,
        to_identity_pk: &[u8],
    ) -> Result<LinkReceipt, Error> {
        let receipt = LinkReceipt::verify(&self.receipt, to_identity_pk)?;
        if receipt.epoch != query.epoch {
            return Err(Error::Unverified);
        }
        if !proof_fits(&self.proof, self.leaf_index, receipt.cell_count) {
            return Err(Error::Unverified);
        }
        tree::verify(&query.tag, &self.proof, &receipt.batch_root)?;
        Ok(receipt)
    }
}

/// What an isolation query found on one link of a probe chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkVerdict {
    /// The relay at the end of the link issued the receipt of the probe
    /// cell: the link carried it.
    Held,
    /// The relay at the end of the link denied a batch that the relay
    /// before it holds under its signature: a contradiction (`REL-083`).
    Contradiction {
        /// The relay that denied.
        relay: [u8; 32],
    },
    /// No receipt of the cell on the link names one relay (`REL-084`).
    LinkFault {
        /// The relay that sent.
        from: [u8; 32],
        /// The relay that took, or did not.
        to: [u8; 32],
    },
}

/// Judges the link `from` → `to` for the probe cell that `query` names by
/// its tag at `to`. `from_answer` is the answer of `from` (a receipt that it
/// took), `to_answer` the answer of `to` (a receipt that it issued), and
/// `None` a relay that gave no answer. A receipt counts when it verifies
/// under `to_identity_pk`, names the link, and covers the cell.
///
/// A contradiction needs the denial itself (`REL-083`). `to` answered that
/// it holds no receipt of a cell, and `from` holds that receipt under the
/// signature of `to`. A relay that gave no answer denied nothing, and a
/// relay before it can cause that silence. Thus no answer removes the link
/// and names no relay (`REL-084`).
pub fn judge_link(
    from: [u8; 32],
    to: [u8; 32],
    query: &ReceiptQuery,
    from_answer: Option<&ReceiptAnswer>,
    to_answer: Option<&ReceiptAnswer>,
    to_identity_pk: &[u8],
) -> LinkVerdict {
    let covers = |answer: Option<&ReceiptAnswer>, found: Found| {
        answer
            .filter(|answer| answer.found == found)
            .and_then(|answer| answer.covers(query, to_identity_pk).ok())
            .is_some_and(|receipt| receipt.from_relay == from && receipt.to_relay == to)
    };
    let denied = to_answer.is_some_and(|answer| answer.found == Found::None);
    if covers(to_answer, Found::Issued) {
        LinkVerdict::Held
    } else if denied && covers(from_answer, Found::Taken) {
        LinkVerdict::Contradiction { relay: to }
    } else {
        LinkVerdict::LinkFault { from, to }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::directory::{descriptor::tests::Rng, root::tests::authorities};

    #[test]
    fn a_receipt_answers_a_query_with_the_proof_of_its_cell() {
        let mut rng = Rng(5);
        let keys = authorities(60);
        let relay = &keys[6];
        let tags: Vec<[u8; 16]> = (0..40u8).map(|i| [i ^ 0x55; 16]).collect();
        let leaves: Vec<[u8; 32]> = tags.iter().map(cell_leaf).collect();
        let receipt = LinkReceipt {
            from_relay: [1; 32],
            to_relay: [2; 32],
            epoch: 9,
            window: 0,
            cell_count: 40,
            batch_root: tree::root(&leaves).unwrap(),
        };
        let signed = receipt.sign(relay, &mut rng).unwrap();
        assert_eq!(signed.len(), RECEIPT_LEN);
        let pk = relay.verifying_key().to_bytes();
        assert_eq!(LinkReceipt::verify(&signed, &pk).unwrap(), receipt);
        assert!(LinkReceipt::verify(&signed, &keys[0].verifying_key().to_bytes()).is_err());

        // The query of an authority, and the answer that covers its cell.
        let pks: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let keyset = DirectoryKeySet {
            keyset_epoch: 1,
            independent_count: 7,
            keys: pks.iter().map(|k| &k[..]).collect(),
        };
        let query = ReceiptQuery {
            authority_index: 3,
            relay_id: [2; 32],
            epoch: 9,
            tag: tags[17],
        };
        let asked = query.sign(&keys[3], &mut rng).unwrap();
        assert_eq!(asked.len(), RECEIPT_QUERY_LEN);
        assert_eq!(ReceiptQuery::verify(&asked, &keyset).unwrap(), query);
        assert!(ReceiptQuery::verify(&query.sign(&keys[4], &mut rng).unwrap(), &keyset).is_err());
        // REL-179: the query asks one relay, and the name of another relay
        // in its bytes ends the signature.
        assert!(query.asks(&[2; 32]) && !query.asks(&[1; 32]));
        let mut moved = asked.clone();
        moved[2] ^= 1;
        assert!(ReceiptQuery::verify(&moved, &keyset).is_err());
        let answer = ReceiptAnswer {
            found: Found::Issued,
            receipt: signed.clone(),
            leaf_index: 17,
            proof: tree::prove(&leaves, 17).unwrap(),
        };
        let read = ReceiptAnswer::parse(&answer.encode().unwrap()).unwrap();
        assert_eq!(read, answer);
        assert_eq!(read.covers(&query, &pk).unwrap(), receipt);
        // The proof of another cell does not cover this one.
        let other = ReceiptAnswer {
            leaf_index: 18,
            proof: tree::prove(&leaves, 18).unwrap(),
            ..answer
        };
        assert!(other.covers(&query, &pk).is_err());
        // An index that the proof does not lead to, and one past the cells.
        for leaf_index in [16, 40] {
            let elsewhere = ReceiptAnswer {
                leaf_index,
                ..read.clone()
            };
            assert!(elsewhere.covers(&query, &pk).is_err());
        }
        assert_eq!(
            ReceiptAnswer::parse(&ReceiptAnswer::none().encode().unwrap()).unwrap(),
            ReceiptAnswer::none()
        );
    }

    #[test]
    fn a_link_holds_or_names_the_relay_that_denied_or_neither() {
        let mut rng = Rng(7);
        let keys = authorities(80);
        let to_key = &keys[1];
        let to_pk = to_key.verifying_key().to_bytes();
        let (from, to) = ([0xA1; 32], [0xB2; 32]);
        let tags: Vec<[u8; 16]> = (0..8u8).map(|i| [i; 16]).collect();
        let leaves: Vec<[u8; 32]> = tags.iter().map(cell_leaf).collect();
        let signed = LinkReceipt {
            from_relay: from,
            to_relay: to,
            epoch: 3,
            window: 0,
            cell_count: 8,
            batch_root: tree::root(&leaves).unwrap(),
        }
        .sign(to_key, &mut rng)
        .unwrap();
        let query = ReceiptQuery {
            authority_index: 0,
            relay_id: to,
            epoch: 3,
            tag: tags[5],
        };
        let answer = |found| ReceiptAnswer {
            found,
            receipt: signed.clone(),
            leaf_index: 5,
            proof: tree::prove(&leaves, 5).unwrap(),
        };
        let (taken, issued, none) = (
            answer(Found::Taken),
            answer(Found::Issued),
            ReceiptAnswer::none(),
        );
        let judge = |f: Option<&ReceiptAnswer>, t: Option<&ReceiptAnswer>| {
            judge_link(from, to, &query, f, t, &to_pk)
        };
        assert_eq!(judge(Some(&taken), Some(&issued)), LinkVerdict::Held);
        assert_eq!(judge(None, Some(&issued)), LinkVerdict::Held);
        // REL-083: the relay denied what it signed.
        assert_eq!(
            judge(Some(&taken), Some(&none)),
            LinkVerdict::Contradiction { relay: to }
        );
        // REL-084: neither side shows the cell, or a side gives no answer.
        // A relay that gave no answer denied nothing. Thus the verdict does
        // not name it, whatever the relay before it shows.
        assert_eq!(
            judge(Some(&taken), None),
            LinkVerdict::LinkFault { from, to }
        );
        assert_eq!(
            judge(Some(&none), Some(&none)),
            LinkVerdict::LinkFault { from, to }
        );
        assert_eq!(judge(None, None), LinkVerdict::LinkFault { from, to });
        // A receipt under another key names no one.
        let forged = judge_link(
            from,
            to,
            &query,
            Some(&taken),
            Some(&none),
            &keys[2].verifying_key().to_bytes(),
        );
        assert_eq!(forged, LinkVerdict::LinkFault { from, to });
    }

    #[test]
    fn a_hello_names_its_relay_on_its_own_session_alone() {
        let mut rng = Rng(6);
        let keys = authorities(70);
        let pk = keys[0].verifying_key().to_bytes().to_vec();
        let hello = relay_hello(&[4; 32], &[5; 32], &[9; 8], &keys[0], &mut rng).unwrap();
        assert_eq!(hello.len(), RELAY_HELLO_LEN);
        let known = |id: &[u8; 32]| (*id == [4; 32]).then(|| pk.clone());
        let verify =
            |own: &[u8; 32], session: &[u8; 8]| verify_relay_hello(&hello, own, session, known);
        assert_eq!(verify(&[5; 32], &[9; 8]).unwrap(), [4; 32]);
        assert!(verify(&[5; 32], &[8; 8]).is_err());
        assert!(verify_relay_hello(&hello, &[5; 32], &[9; 8], |_| None).is_err());
    }

    #[test]
    fn a_hello_for_one_relay_names_no_one_at_another() {
        let mut rng = Rng(8);
        let keys = authorities(70);
        let pk = keys[0].verifying_key().to_bytes().to_vec();
        let known = |_: &[u8; 32]| Some(pk.clone());
        // REL-174: relay 5 took the hello of relay 4, and it shows that
        // hello to relay 6 under the same session.
        let hello = relay_hello(&[4; 32], &[5; 32], &[9; 8], &keys[0], &mut rng).unwrap();
        assert!(verify_relay_hello(&hello, &[6; 32], &[9; 8], known).is_err());
        // A hello that names the relay that took it names no dialer.
        let own = relay_hello(&[6; 32], &[6; 32], &[9; 8], &keys[0], &mut rng).unwrap();
        assert!(verify_relay_hello(&own, &[6; 32], &[9; 8], known).is_err());
    }
}
