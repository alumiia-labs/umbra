//! The link of a new device to a device set (Part 7 §7.4): the ticket that
//! the QR code carries, the offer and the hello that the two devices put on
//! handle-addressed chunks (Part 12 §12.4.2), the code that the user
//! compares, and the sealed provision that makes the new device a member.
//!
//! The new device holds no root identity until the provision arrives, thus
//! the link uses no queue and no pairwise channel. Each object sits under a
//! handle that both devices derive, and the relay set places it.

use alloc::vec::Vec;

use umbra_crypto::zeroize::Zeroizing;
use umbra_crypto::{
    aead,
    hash::sha3_256,
    kem::{self, Ciphertext, KeyPair, PublicKey, CIPHERTEXT_LEN, PUBLIC_KEY_LEN},
    labels,
    rand_core::{CryptoRng, TryCryptoRng},
    secret::Secret,
    sign::{SigningKey, VERIFYING_KEY_LEN},
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_wire::codec::{Reader, Writer};

use super::{
    roster::{DeviceEntry, SyncScope},
    DeviceId,
};
use crate::Error;

/// The length of an encoded [`LinkTicket`].
pub const TICKET_LEN: usize = 49;
/// The prefix of the text of a ticket in a QR code.
pub const TICKET_PREFIX: &str = "UMBRA-LINK:";
/// The length of the label of a device.
pub const LABEL_LEN: usize = 32;

/// What the QR code of the existing device carries (`DEV-005`): a nonce
/// and the hash of the offer. The offer itself sits on the chunk path, thus
/// the code stays small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkTicket {
    /// Fresh for each link, from the CSPRNG.
    pub nonce: [u8; 16],
    /// SHA3-256 of the encoded offer under `LINK_OFFER`.
    pub commit: [u8; 32],
}

impl LinkTicket {
    /// The 49 bytes: version `0x01`, the nonce, and the commitment.
    pub fn encode(&self) -> [u8; TICKET_LEN] {
        let mut out = [0u8; TICKET_LEN];
        let (head, rest) = out.split_at_mut(1);
        head.copy_from_slice(&[0x01]);
        let (nonce, commit) = rest.split_at_mut(16);
        nonce.copy_from_slice(&self.nonce);
        commit.copy_from_slice(&self.commit);
        out
    }

    /// Reads a ticket.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let ticket = LinkTicket {
            nonce: r.array()?,
            commit: r.array()?,
        };
        r.finish()?;
        Ok(ticket)
    }

    /// The text of the QR code: the prefix and the base64url of the ticket.
    pub fn to_text(&self) -> alloc::string::String {
        let mut text = alloc::string::String::from(TICKET_PREFIX);
        text.push_str(&base64url(&self.encode()));
        text
    }

    /// Reads the text of a QR code.
    pub fn from_text(text: &str) -> Result<Self, Error> {
        let body = text
            .trim()
            .strip_prefix(TICKET_PREFIX)
            .ok_or(Error::Malformed)?;
        Self::parse(&from_base64url(body).ok_or(Error::Malformed)?)
    }
}

/// The address and the two keys of one handle-addressed chunk of a link.
pub struct Slot {
    /// The `chunk_id`.
    pub handle: [u8; 32],
    /// `cred_sk`, which writes the chunk.
    pub cred: Secret<32>,
    /// `read_sk`, which reads it.
    pub read: Secret<32>,
}

impl Slot {
    fn derive(label: &[u8], secret: &[&[u8]]) -> Self {
        let part = |name: &[u8]| {
            let mut parts: Vec<&[u8]> = alloc::vec![label];
            parts.extend_from_slice(secret);
            parts.push(name);
            sha3_256(&parts)
        };
        Slot {
            handle: part(b"handle"),
            cred: Secret::new(part(b"cred")),
            read: Secret::new(part(b"read")),
        }
    }

    /// The public half of `read_sk`, which the write carries.
    pub fn read_pk(&self) -> [u8; 32] {
        *XPublic::from(&StaticSecret::from(*self.read.expose())).as_bytes()
    }
}

/// The slot of the offer of the existing device (`DEV-280`).
pub fn offer_slot(nonce: &[u8; 16]) -> Slot {
    Slot::derive(labels::LINK_OFFER, &[nonce])
}

/// The slot of the hello of the new device (`DEV-281`). Each holder of the
/// ticket can write it, and the code of `DEV-283` shows which one did.
pub fn hello_slot(nonce: &[u8; 16]) -> Slot {
    Slot::derive(labels::LINK_HELLO, &[nonce])
}

/// The offer: the ephemeral `link_pk` of the existing device.
pub struct LinkOffer {
    /// An `UMBRA-KEM` key for this link alone.
    pub link_pk: PublicKey,
}

impl LinkOffer {
    /// Version `0x01` and the key.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = alloc::vec![0x01];
        out.extend_from_slice(&self.link_pk.to_bytes());
        out
    }

    /// Reads an offer, and checks it against the commitment of the ticket.
    pub fn parse(bytes: &[u8], ticket: &LinkTicket) -> Result<Self, Error> {
        if commit(bytes) != ticket.commit {
            return Err(Error::Unverified);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let link_pk = PublicKey::from_bytes(r.take(PUBLIC_KEY_LEN)?)?;
        r.finish()?;
        Ok(LinkOffer { link_pk })
    }
}

/// The commitment of an encoded offer, which the ticket carries.
pub fn commit(offer: &[u8]) -> [u8; 32] {
    sha3_256(&[labels::LINK_OFFER, offer])
}

/// The hello of the new device: one encapsulation to `link_pk`, and its
/// identity in the set under a key of that secret (`DEV-168`, `DEV-224`).
/// A relay that holds the chunk reads no key and no label.
pub struct LinkHello {
    /// The random `device_id` of the new device.
    pub device_id: DeviceId,
    /// The public `DeviceKey` of the new device.
    pub device_pk: PublicKey,
    /// The public `DeviceRosterKey` of the new device.
    pub roster_pk: Vec<u8>,
    /// The label that the user gave the new device.
    pub label: [u8; LABEL_LEN],
    /// The encapsulation to `link_pk`.
    pub ct: Ciphertext,
}

/// The length of the sealed body of a hello.
const HELLO_BODY_LEN: usize = 16 + PUBLIC_KEY_LEN + VERIFYING_KEY_LEN + LABEL_LEN;
/// The length of an encoded hello.
pub const HELLO_LEN: usize = 1 + CIPHERTEXT_LEN + aead::NONCE_LEN + aead::TAG_LEN + HELLO_BODY_LEN;

fn hello_key(ss: &Secret<32>, nonce: &[u8; 16]) -> Secret<32> {
    Secret::new(sha3_256(&[labels::LINK_HELLO, ss.expose(), nonce, b"seal"]))
}

impl LinkHello {
    /// Version `0x01`, `ct`, and the four other fields sealed under the key
    /// of `ss` and the nonce of the ticket.
    pub fn seal<R: CryptoRng + ?Sized>(
        &self,
        ss: &Secret<32>,
        nonce: &[u8; 16],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        if self.roster_pk.len() != VERIFYING_KEY_LEN {
            return Err(Error::Malformed);
        }
        let mut body = Zeroizing::new(alloc::vec![0u8; HELLO_BODY_LEN]);
        let mut w = Writer::new(&mut body);
        w.put(&self.device_id)?;
        w.put(&self.device_pk.to_bytes())?;
        w.put(&self.roster_pk)?;
        w.put(&self.label)?;
        let mut seal_nonce = [0u8; aead::NONCE_LEN];
        rng.fill_bytes(&mut seal_nonce);
        let tag = aead::seal(
            &hello_key(ss, nonce),
            &seal_nonce,
            labels::LINK_HELLO,
            &mut body,
        )?;
        let mut out = Vec::with_capacity(HELLO_LEN);
        out.push(0x01);
        out.extend_from_slice(self.ct.as_bytes());
        out.extend_from_slice(&seal_nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Reads a hello with the key of the offer: the decapsulation of `ct`
    /// gives the key of the body.
    fn open(
        link_key: &KeyPair,
        nonce: &[u8; 16],
        bytes: &[u8],
    ) -> Result<(Self, Secret<32>), Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let ct = Ciphertext::from_bytes(r.take(CIPHERTEXT_LEN)?)?;
        let seal_nonce: [u8; aead::NONCE_LEN] = r.array()?;
        let tag = r.take(aead::TAG_LEN)?;
        let mut body = Zeroizing::new(r.take(HELLO_BODY_LEN)?.to_vec());
        r.finish()?;
        let ss = Secret::new(*link_key.decapsulate(&ct)?.expose());
        aead::open(
            &hello_key(&ss, nonce),
            &seal_nonce,
            labels::LINK_HELLO,
            &mut body,
            tag,
        )
        .map_err(|_| Error::Unverified)?;
        let mut r = Reader::new(&body);
        let hello = LinkHello {
            device_id: r.array()?,
            device_pk: PublicKey::from_bytes(r.take(PUBLIC_KEY_LEN)?)?,
            roster_pk: r.take(VERIFYING_KEY_LEN)?.to_vec(),
            label: r.array()?,
            ct,
        };
        r.finish()?;
        Ok((hello, ss))
    }
}

/// The secret of one link, and what the two devices derive from it
/// (`DEV-282` to `DEV-284`).
pub struct LinkSecret {
    ss: Secret<32>,
    transcript: [u8; 32],
}

impl LinkSecret {
    /// The side of the new device: one encapsulation to the offer.
    pub fn encapsulate<R: CryptoRng + ?Sized>(
        offer: &LinkOffer,
        rng: &mut R,
    ) -> (Ciphertext, Secret<32>) {
        let (ct, ss) = kem::encapsulate(&offer.link_pk, rng);
        (ct, Secret::new(*ss.expose()))
    }

    /// The secret from the shared value of the KEM, the nonce of the
    /// ticket, and the two objects.
    pub fn new(ss: Secret<32>, nonce: &[u8; 16], offer: &[u8], hello: &[u8]) -> Self {
        LinkSecret {
            transcript: sha3_256(&[labels::LINK_TRANSCRIPT, nonce, offer, hello]),
            ss,
        }
    }

    /// The side of the existing device: the hello opens under the key of
    /// the offer, and the secret follows.
    pub fn decapsulate(
        link_key: &KeyPair,
        nonce: &[u8; 16],
        offer: &[u8],
        hello_bytes: &[u8],
    ) -> Result<(LinkHello, Self), Error> {
        let (hello, ss) = LinkHello::open(link_key, nonce, hello_bytes)?;
        Ok((hello, Self::new(ss, nonce, offer, hello_bytes)))
    }

    /// The six-digit code that the user compares on the two screens
    /// (`DEV-283`): the first four bytes of a hash of the secret and the
    /// transcript, as a number modulo 1 000 000.
    pub fn code(&self) -> u32 {
        let digest = sha3_256(&[labels::LINK_CODE, self.ss.expose(), &self.transcript]);
        let head = [digest[0], digest[1], digest[2], digest[3]];
        u32::from_be_bytes(head) % 1_000_000
    }

    /// The slot of the provision, which only the two devices know.
    pub fn provision_slot(&self) -> Slot {
        Slot::derive(
            labels::LINK_PROVISION,
            &[self.ss.expose(), &self.transcript],
        )
    }

    fn seal_key(&self) -> Secret<32> {
        Secret::new(sha3_256(&[
            labels::LINK_PROVISION,
            self.ss.expose(),
            &self.transcript,
            b"seal",
        ]))
    }

    /// Seals a provision for its handle-addressed chunk: the nonce, the
    /// tag, and the ciphertext.
    pub fn seal<R: CryptoRng + ?Sized>(
        &self,
        provision: &Provision,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut body = Zeroizing::new(provision.encode()?);
        let mut nonce = [0u8; aead::NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let tag = aead::seal(&self.seal_key(), &nonce, labels::LINK_PROVISION, &mut body)?;
        let mut out = Vec::with_capacity(nonce.len() + tag.len() + body.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Opens a sealed provision.
    pub fn open(&self, sealed: &[u8]) -> Result<Provision, Error> {
        let nonce: [u8; aead::NONCE_LEN] = sealed
            .get(..aead::NONCE_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Malformed)?;
        let tag = sealed
            .get(aead::NONCE_LEN..aead::NONCE_LEN + aead::TAG_LEN)
            .ok_or(Error::Malformed)?;
        let mut body = Zeroizing::new(
            sealed
                .get(aead::NONCE_LEN + aead::TAG_LEN..)
                .ok_or(Error::Malformed)?
                .to_vec(),
        );
        aead::open(
            &self.seal_key(),
            &nonce,
            labels::LINK_PROVISION,
            &mut body,
            tag,
        )
        .map_err(|_| Error::Unverified)?;
        Provision::parse(&body)
    }
}

/// What the existing device gives the new one (`DEV-004`): the descriptor
/// of the snapshot of the store on the chunk path. The snapshot holds the
/// roster that adds the new device and the bundle that opens the sync
/// channel of the two (`DEV-286`), thus the provision stays one chunk at
/// `MAX_DEVICES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provision {
    /// The `device_id` of the existing device.
    pub from_device: DeviceId,
    /// The encoded `FileDescriptor` of the snapshot.
    pub snapshot: Vec<u8>,
}

impl Provision {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; 1 + 16 + 4 + self.snapshot.len()];
        let mut w = Writer::new(&mut out);
        w.u8(0x01)?;
        w.put(&self.from_device)?;
        w.u32(u32::try_from(self.snapshot.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.snapshot)?;
        Ok(out)
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let from_device = r.array()?;
        let len = usize::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
        let snapshot = r.take(len)?.to_vec();
        r.finish()?;
        Ok(Provision {
            from_device,
            snapshot,
        })
    }
}

/// The keys of one device in its set (`DEV-143`, `DEV-165`, `DEV-224`):
/// its random `device_id`, its `DeviceKey`, and its `DeviceRosterKey`.
/// The two secret keys never leave the device.
pub struct DeviceIdentity {
    /// Random, from the CSPRNG of the device.
    pub device_id: DeviceId,
    /// The label that the user gave the device.
    pub label: [u8; LABEL_LEN],
    kem_x: Secret<32>,
    kem_dz: Secret<64>,
    roster_seed: Secret<32>,
}

impl DeviceIdentity {
    /// A new identity with fresh values.
    pub fn generate<R: CryptoRng + ?Sized>(label: &str, rng: &mut R) -> Self {
        let mut device_id = [0u8; 16];
        rng.fill_bytes(&mut device_id);
        let mut kem_x = [0u8; 32];
        rng.fill_bytes(&mut kem_x);
        let mut kem_dz = [0u8; 64];
        rng.fill_bytes(&mut kem_dz);
        let mut roster_seed = [0u8; 32];
        rng.fill_bytes(&mut roster_seed);
        DeviceIdentity {
            device_id,
            label: label_bytes(label),
            kem_x: Secret::new(kem_x),
            kem_dz: Secret::new(kem_dz),
            roster_seed: Secret::new(roster_seed),
        }
    }

    /// The `DeviceKey`.
    pub fn device_key(&self) -> KeyPair {
        KeyPair::from_seeds(
            Secret::new(*self.kem_x.expose()),
            Secret::new(*self.kem_dz.expose()),
        )
    }

    /// The `DeviceRosterKey`.
    pub fn roster_key(&self) -> SigningKey {
        SigningKey::from_seed(Secret::new(*self.roster_seed.expose()))
    }

    /// The stored form: 16 + 32 + 32 + 64 + 32 bytes.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(176));
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.label);
        out.extend_from_slice(self.kem_x.expose());
        out.extend_from_slice(self.kem_dz.expose());
        out.extend_from_slice(self.roster_seed.expose());
        out
    }

    /// Reads the stored form.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let identity = DeviceIdentity {
            device_id: r.array()?,
            label: r.array()?,
            kem_x: Secret::new(r.array()?),
            kem_dz: Secret::new(r.array()?),
            roster_seed: Secret::new(r.array()?),
        };
        r.finish()?;
        Ok(identity)
    }
}

/// The owned parts of a [`DeviceEntry`], which borrows its keys.
pub struct EntryKeys {
    /// The `DeviceKey` public key.
    pub device_pk: [u8; PUBLIC_KEY_LEN],
    /// The `DeviceRosterKey` public key.
    pub roster_pk: Vec<u8>,
}

impl EntryKeys {
    /// The keys of a device identity.
    pub fn of(identity: &DeviceIdentity) -> Self {
        EntryKeys {
            device_pk: identity.device_key().public().to_bytes(),
            roster_pk: identity.roster_key().verifying_key().to_bytes().to_vec(),
        }
    }

    /// The keys of a hello.
    pub fn of_hello(hello: &LinkHello) -> Self {
        EntryKeys {
            device_pk: hello.device_pk.to_bytes(),
            roster_pk: hello.roster_pk.clone(),
        }
    }

    /// The entry of a roster that these keys name.
    pub fn entry(
        &self,
        device_id: DeviceId,
        label: [u8; LABEL_LEN],
        added_epoch: u64,
        sync_scope: SyncScope,
    ) -> Result<DeviceEntry<'_>, Error> {
        let (x, m) = self.device_pk.split_at(32);
        Ok(DeviceEntry {
            device_id,
            x25519_pk: x.try_into().map_err(|_| Error::Malformed)?,
            mlkem_pk: m,
            mldsa_pk: &self.roster_pk,
            label,
            added_epoch,
            sync_scope,
        })
    }
}

/// A label as its 32 bytes: UTF-8, cut at a character boundary, and padded
/// with zeros.
pub fn label_bytes(label: &str) -> [u8; LABEL_LEN] {
    let mut out = [0u8; LABEL_LEN];
    let mut end = label.len().min(LABEL_LEN);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    if let (Some(to), Some(from)) = (out.get_mut(..end), label.as_bytes().get(..end)) {
        to.copy_from_slice(from);
    }
    out
}

/// A label as text: the UTF-8 before the first zero byte.
pub fn label_text(label: &[u8; LABEL_LEN]) -> alloc::string::String {
    let end = label.iter().position(|b| *b == 0).unwrap_or(LABEL_LEN);
    alloc::string::String::from_utf8_lossy(label.get(..end).unwrap_or(&[])).into_owned()
}

/// Signs a roster under the `DeviceRosterKey` of the signer (`DEV-166`),
/// and gives its encoding.
pub fn sign_roster<R: TryCryptoRng + ?Sized>(
    roster: &super::roster::Roster<'_>,
    key: &SigningKey,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let sig = key.sign(&roster.preimage()?, rng)?.to_bytes();
    let signed = super::roster::Roster {
        sig: &sig,
        ..roster.clone()
    };
    let mut out = alloc::vec![0u8; signed.len()];
    let used = signed.encode(&mut out)?;
    out.truncate(used);
    Ok(out)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(bytes: &[u8]) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            let index = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
            out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
        }
    }
    out
}

fn from_base64url(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let value = u32::try_from(ALPHABET.iter().position(|a| *a == c)?).ok()?;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::devset::roster::Roster;

    struct Rng(u64);
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            Ok(self.0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for b in dst {
                *b = (self.try_next_u64()? >> 33) as u8;
            }
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    #[test]
    fn the_two_devices_reach_one_code_and_one_provision() {
        let mut rng = Rng(5);
        // The existing device: its offer, and the ticket of the QR code.
        let link_key = KeyPair::generate(&mut rng);
        let offer = LinkOffer {
            link_pk: link_key.public().clone(),
        };
        let offer_bytes = offer.encode();
        let ticket = LinkTicket {
            nonce: [7; 16],
            commit: commit(&offer_bytes),
        };
        let text = ticket.to_text();
        assert!(text.starts_with(TICKET_PREFIX));
        assert_eq!(LinkTicket::from_text(&text).unwrap(), ticket);

        // The new device: the offer checks against the ticket, and one
        // that another party wrote does not.
        let scanned = LinkTicket::from_text(&text).unwrap();
        let offer = LinkOffer::parse(&offer_bytes, &scanned).unwrap();
        let other = LinkOffer {
            link_pk: KeyPair::generate(&mut rng).public().clone(),
        };
        assert!(LinkOffer::parse(&other.encode(), &scanned).is_err());
        let identity = DeviceIdentity::generate("Tablet", &mut rng);
        let (ct, ss) = LinkSecret::encapsulate(&offer, &mut rng);
        let hello = LinkHello {
            device_id: identity.device_id,
            device_pk: identity.device_key().public().clone(),
            roster_pk: identity.roster_key().verifying_key().to_bytes().to_vec(),
            label: identity.label,
            ct,
        };
        let hello_bytes = hello.seal(&ss, &scanned.nonce, &mut rng).unwrap();
        assert_eq!(hello_bytes.len(), HELLO_LEN);
        // The label is not in the clear.
        assert!(!hello_bytes.windows(6).any(|w| w == b"Tablet"));
        let joined = LinkSecret::new(ss, &scanned.nonce, &offer_bytes, &hello_bytes);

        // The existing device reads the hello: the same code. A hello under
        // another nonce does not open.
        assert!(LinkSecret::decapsulate(&link_key, &[8; 16], &offer_bytes, &hello_bytes).is_err());
        let (read, offered) =
            LinkSecret::decapsulate(&link_key, &ticket.nonce, &offer_bytes, &hello_bytes).unwrap();
        assert_eq!(label_text(&read.label), "Tablet");
        assert_eq!(read.device_id, identity.device_id);
        assert_eq!(offered.code(), joined.code());
        assert!(offered.code() < 1_000_000);
        assert_eq!(
            offered.provision_slot().handle,
            joined.provision_slot().handle
        );

        // The provision opens at the new device alone.
        let provision = Provision {
            from_device: [1; 16],
            snapshot: alloc::vec![3; 200],
        };
        let sealed = offered.seal(&provision, &mut rng).unwrap();
        assert_eq!(joined.open(&sealed).unwrap(), provision);
        let stranger = LinkSecret::new(
            Secret::new([9; 32]),
            &ticket.nonce,
            &offer_bytes,
            &hello_bytes,
        );
        assert!(stranger.open(&sealed).is_err());
    }

    #[test]
    fn a_device_signs_a_roster_that_verifies_and_keeps_its_identity() {
        let mut rng = Rng(8);
        let identity = DeviceIdentity::generate("Phone of Dana, a long name that is cut", &mut rng);
        assert_eq!(label_text(&identity.label).len(), LABEL_LEN);
        let back = DeviceIdentity::parse(&identity.encode()).unwrap();
        assert_eq!(back.device_id, identity.device_id);
        assert_eq!(
            back.device_key().public().to_bytes(),
            identity.device_key().public().to_bytes()
        );
        let keys = EntryKeys::of(&identity);
        let genesis = Roster {
            epoch: 0,
            devices: alloc::vec![keys
                .entry(identity.device_id, identity.label, 0, SyncScope::Full)
                .unwrap()],
            revoked: Vec::new(),
            claims: Vec::new(),
            prev_hash: [0; 32],
            signer_id: identity.device_id,
            sig: &[0; umbra_crypto::sign::SIGNATURE_LEN],
        };
        let bytes = sign_roster(&genesis, &identity.roster_key(), &mut rng).unwrap();
        Roster::parse(&bytes).unwrap().verify_genesis().unwrap();
    }
}
