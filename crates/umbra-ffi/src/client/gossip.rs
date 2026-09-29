//! The transparency gossip of this device (Part 9 §9.5.3, Part 10 `REL-008`):
//! the digest of the newest tree head of the handle directory and of the
//! consensus root, one of each source in each `GOSSIP_INTERVAL`, to one
//! contact in a scheduled cover slot; and the comparison of each digest that
//! a contact sent. A digest names an epoch and a hash, and no contact learns
//! more than that this device reads the same directory.

use umbra_core::{
    directory::CLOCK_SKEW,
    discovery::{GOSSIP_INTERVAL, TREE_HEAD_FRESHNESS},
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    keys::{DigestBody, DigestSource, DIGEST_LEN},
    AppKind, AppMessage,
};
use zeroize::Zeroizing;

use super::Client;
use crate::{ConversationId, Error};

/// The gossip state. Each value starts with its kind byte, thus a listing
/// tells the rows apart.
const GOSSIP: TableId = TableId(0x33);
/// The time that a digest of one source left: the source, the time.
const SENT: u8 = 1;
/// The digest of a consensus root that this device verified: the epoch,
/// the digest.
const ROOT: u8 = 2;
/// A tree head of a contact that waits for a consistency proof: the size,
/// the root (`DIS-136`).
const CHECK: u8 = 3;
/// A warning: the source, the epoch (`DIS-034`, `REL-161`).
const WARNING: u8 = 4;

/// The rows of the gossip table, each with its value.
type Rows = Vec<(RowId, Zeroizing<Vec<u8>>)>;

/// The consensus epochs whose digests this device keeps: the validity of a
/// root (Part 10 `REL-162`), thus a contact one epoch behind still
/// compares.
const ROOTS_KEPT: u64 = 3;
/// The tree heads of contacts that wait for a check at one time.
const CHECKS_MAX: usize = 4;

/// A tree head of a contact that waits for a consistency proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadCheck {
    /// The size of the head.
    pub tree_size: u64,
    /// Its root.
    pub root: [u8; 32],
}

/// A digest of a contact that differs from the view of this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipWarning {
    /// The source of the digest.
    pub source: DigestSource,
    /// The epoch or the tree size that it names.
    pub epoch: u64,
}

fn source_byte(source: DigestSource) -> u8 {
    source as u8
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn gossip_rows(&self) -> Result<Rows, Error> {
        let store = &self.open_ref()?.store;
        Ok(store
            .list(GOSSIP, None)?
            .into_iter()
            .map(|(row, plain)| (row, Zeroizing::new(plain)))
            .collect())
    }

    fn put_gossip<R: CryptoRng + ?Sized>(
        &mut self,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(GOSSIP, key);
        let mut batch = open.store.begin();
        batch.put(GOSSIP, row, None, value, rng)?;
        Ok(batch.commit()?)
    }

    fn drop_gossip(&mut self, rows: Vec<RowId>) -> Result<(), Error> {
        if rows.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in rows {
            batch.delete(GOSSIP, row);
        }
        Ok(batch.commit()?)
    }

    /// Keeps the digest of a consensus root that this device verified, and
    /// drops the digests of epochs older than `ROOTS_KEPT`.
    pub fn keep_consensus_digest<R: CryptoRng + ?Sized>(
        &mut self,
        epoch: u64,
        digest: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let key = [&[ROOT][..], &epoch.to_be_bytes()].concat();
        let value = [&[ROOT][..], &epoch.to_be_bytes(), digest].concat();
        self.put_gossip(&key, &value, rng)?;
        let mut old = Vec::new();
        for (row, value) in self.gossip_rows()? {
            if let Some((held, _)) = root_of(&value) {
                if held.saturating_add(ROOTS_KEPT) <= epoch {
                    old.push(row);
                }
            }
        }
        self.drop_gossip(old)
    }

    fn consensus_digest(&self, epoch: Option<u64>) -> Result<Option<(u64, [u8; 32])>, Error> {
        let mut found: Option<(u64, [u8; 32])> = None;
        for (_, value) in self.gossip_rows()? {
            let Some((held, digest)) = root_of(&value) else {
                continue;
            };
            let wanted = match epoch {
                Some(epoch) => held == epoch,
                None => found.is_none_or(|(newest, _)| held > newest),
            };
            if wanted {
                found = Some((held, digest));
            }
        }
        Ok(found)
    }

    fn last_sent(&self, source: DigestSource) -> Result<Option<u64>, Error> {
        for (_, value) in self.gossip_rows()? {
            if value.len() == 10
                && value.first() == Some(&SENT)
                && value.get(1) == Some(&source_byte(source))
            {
                let at: [u8; 8] = value
                    .get(2..10)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Integrity)?;
                return Ok(Some(u64::from_be_bytes(at)));
            }
        }
        Ok(None)
    }

    /// The digest that may take a cover slot at `now` (`DIS-028`,
    /// `DIS-072`, `REL-008`), as the record of an application message, or
    /// none. The caller names the contact and marks it sent.
    pub fn due_digest<R: CryptoRng + ?Sized>(
        &self,
        now: u64,
        rng: &mut R,
    ) -> Result<Option<(DigestSource, Vec<u8>)>, Error> {
        for source in [DigestSource::TreeHead, DigestSource::ConsensusRoot] {
            if self
                .last_sent(source)?
                .is_some_and(|at| now < at.saturating_add(GOSSIP_INTERVAL))
            {
                continue;
            }
            let named = match source {
                DigestSource::TreeHead => self.newest_head()?.map(|(size, root, _)| (size, root)),
                _ => self.consensus_digest(None)?,
            };
            let Some((epoch, digest)) = named else {
                continue;
            };
            let mut body = [0u8; DIGEST_LEN];
            DigestBody {
                source,
                epoch,
                digest,
            }
            .encode(&mut body)?;
            let mut msg_id = [0u8; 16];
            rng.fill_bytes(&mut msg_id);
            let record = AppMessage {
                kind: AppKind::TransparencyDigest,
                msg_id,
                sent_at: now.saturating_mul(1_000),
                body: &body,
            };
            let mut app = vec![0u8; record.len()];
            record.encode(&mut app)?;
            return Ok(Some((source, app)));
        }
        Ok(None)
    }

    /// The contacts that a digest may go to: no channel of another device
    /// of the set, and no blocked contact (`DIS-031`).
    pub fn gossip_contacts(&self, all: &[ConversationId]) -> Result<Vec<ConversationId>, Error> {
        let peers = self.device_peers()?;
        let mut out = Vec::new();
        for conversation in all {
            if !peers.contains(conversation) && !self.is_blocked(*conversation)? {
                out.push(*conversation);
            }
        }
        Ok(out)
    }

    /// A digest of `source` left in a cover slot at `now`.
    pub fn digest_sent<R: CryptoRng + ?Sized>(
        &mut self,
        source: DigestSource,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let key = [SENT, source_byte(source)];
        let value = [&[SENT, source_byte(source)][..], &now.to_be_bytes()].concat();
        self.put_gossip(&key, &value, rng)
    }

    /// Compares the digests that contacts sent against the view of this
    /// device (`DIS-033`, `DIS-034`, `DIS-071`, `REL-161`). A tree head of
    /// a size that this device does not hold waits for a consistency proof
    /// (`DIS-136`), and a consensus root of an epoch that it does not hold
    /// goes.
    pub fn take_digests<R: CryptoRng + ?Sized>(
        &mut self,
        digests: &[DigestBody],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        for digest in digests {
            match digest.source {
                DigestSource::TreeHead => {
                    let heads = self.held_heads()?;
                    // DIS-071: the degraded read shows no split view.
                    let fresh = heads.iter().any(|(_, _, timestamp)| {
                        timestamp.saturating_add(TREE_HEAD_FRESHNESS + CLOCK_SKEW) >= now
                    });
                    if !fresh {
                        continue;
                    }
                    match heads.iter().find(|(size, _, _)| *size == digest.epoch) {
                        Some((_, root, _)) if *root == digest.digest => {}
                        Some(_) => self.warn(DigestSource::TreeHead, digest.epoch, rng)?,
                        None => self.wait_for_check(digest.epoch, &digest.digest, rng)?,
                    }
                }
                DigestSource::ConsensusRoot => {
                    if let Some((_, held)) = self.consensus_digest(Some(digest.epoch))? {
                        if held != digest.digest {
                            self.warn(DigestSource::ConsensusRoot, digest.epoch, rng)?;
                        }
                    }
                }
                // Part 15 §15.5: this build reads no release log.
                DigestSource::ReleaseLog => {}
            }
        }
        Ok(())
    }

    fn wait_for_check<R: CryptoRng + ?Sized>(
        &mut self,
        tree_size: u64,
        root: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.head_checks()?.len() >= CHECKS_MAX {
            return Ok(());
        }
        let key = [&[CHECK][..], &tree_size.to_be_bytes(), root].concat();
        let value = key.clone();
        self.put_gossip(&key, &value, rng)
    }

    /// The tree heads of contacts that wait for a consistency proof.
    pub fn head_checks(&self) -> Result<Vec<HeadCheck>, Error> {
        let mut out = Vec::new();
        for (_, value) in self.gossip_rows()? {
            if value.len() == 41 && value.first() == Some(&CHECK) {
                out.push(HeadCheck {
                    tree_size: u64::from_be_bytes(
                        value
                            .get(1..9)
                            .and_then(|bytes| bytes.try_into().ok())
                            .ok_or(Error::Integrity)?,
                    ),
                    root: value
                        .get(9..41)
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or(Error::Integrity)?,
                });
            }
        }
        Ok(out)
    }

    /// The check of a tree head of a contact ended: a proof that failed is
    /// a split view (`DIS-034`).
    pub fn head_check_done<R: CryptoRng + ?Sized>(
        &mut self,
        check: &HeadCheck,
        is_split: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let key = [&[CHECK][..], &check.tree_size.to_be_bytes(), &check.root].concat();
        let row = self.open_ref()?.store.row_id(GOSSIP, &key);
        self.drop_gossip(vec![row])?;
        if is_split {
            self.warn(DigestSource::TreeHead, check.tree_size, rng)?;
        }
        Ok(())
    }

    fn warn<R: CryptoRng + ?Sized>(
        &mut self,
        source: DigestSource,
        epoch: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let key = [WARNING, source_byte(source)];
        let value = [&[WARNING, source_byte(source)][..], &epoch.to_be_bytes()].concat();
        self.put_gossip(&key, &value, rng)
    }

    /// The warnings that the view shows: a contact holds another view of a
    /// log that this device verified.
    pub fn gossip_warnings(&self) -> Result<Vec<GossipWarning>, Error> {
        let mut out = Vec::new();
        for (_, value) in self.gossip_rows()? {
            if value.len() != 10 || value.first() != Some(&WARNING) {
                continue;
            }
            let source = match value.get(1) {
                Some(0x01) => DigestSource::TreeHead,
                Some(0x02) => DigestSource::ConsensusRoot,
                _ => continue,
            };
            let epoch = u64::from_be_bytes(
                value
                    .get(2..10)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Integrity)?,
            );
            out.push(GossipWarning { source, epoch });
        }
        Ok(out)
    }
}

fn root_of(value: &[u8]) -> Option<(u64, [u8; 32])> {
    if value.len() != 41 || value.first() != Some(&ROOT) {
        return None;
    }
    let epoch = u64::from_be_bytes(value.get(1..9)?.try_into().ok()?);
    Some((epoch, value.get(9..41)?.try_into().ok()?))
}
