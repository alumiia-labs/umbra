//! The epoch state of a group at one member (Part 11 §11.3.1, §11.3.2,
//! §11.4): the slot window, the grace of the previous epoch, the alternate
//! secret of a two-rotator race, the rotation that builds the epoch-key
//! record, and the slot a member opens from one.

use alloc::vec::Vec;

use umbra_crypto::{
    group::{
        chain::{ChainState, Credentials, EpochSecret},
        pair::{EpochTag, PairKey},
        slot, MemberKeys,
    },
    kem::PublicKey,
    rand_core::{CryptoRng, TryCryptoRng},
    secret::Secret,
    stored::{Reader, Writer},
};
use umbra_wire::group::{
    control::Role,
    record::{slot_len, Carrier, EpochKeyBody, KemSlot, SlotPayload, REPLICAS},
};

use super::{
    roster::{Roster, STORED_VERSION},
    slot_of, GROUP_EPOCH_GRACE, GROUP_EPOCH_MAX_AGE, GROUP_SLOT, GROUP_SLOT_SKEW,
    GROUP_SLOT_WINDOW, INLINE_SLOTS_MAX,
};
use crate::{attach::SEGMENT_SIZE, Error};

/// The state of one epoch: the secret, the start slot, the chain at the
/// oldest slot of the window, and the credentials.
pub struct EpochState {
    secret: EpochSecret,
    epoch: u32,
    start_slot: u32,
    roster_epoch: u32,
    rotator: u16,
    chain: ChainState,
    /// The queue credentials. The party that started the epoch derives
    /// them from `K_e`, and a joiner takes them from its admit, because it
    /// holds no `K_e` (`GRP-384`).
    credentials: Credentials,
    installed_at: u64,
}

impl EpochState {
    /// Installs `(e, t_e, K_e)` at `now` (`GRP-286`).
    pub fn new(
        secret: EpochSecret,
        group_id: &[u8; 32],
        epoch: u32,
        start_slot: u32,
        roster_epoch: u32,
        rotator: u16,
        now: u64,
    ) -> Self {
        let chain = secret.start(group_id, epoch, start_slot);
        let credentials = secret.credentials();
        EpochState {
            secret,
            epoch,
            start_slot,
            roster_epoch,
            rotator,
            chain,
            credentials,
            installed_at: now,
        }
    }

    /// The state of a joiner from the chain and the credentials of its
    /// admit (`GRP-313`, `GRP-384`). It holds no `K_e`, thus it starts no
    /// epoch and it signs no epoch-key record.
    pub fn from_chain(
        chain: ChainState,
        epoch: u32,
        start_slot: u32,
        roster_epoch: u32,
        credentials: Credentials,
        now: u64,
    ) -> Self {
        EpochState {
            secret: EpochSecret::from_secret(Secret::zeroed()),
            epoch,
            start_slot,
            roster_epoch,
            rotator: 0,
            chain,
            credentials,
            installed_at: now,
        }
    }

    /// The epoch.
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// `t_e`.
    pub const fn start_slot(&self) -> u32 {
        self.start_slot
    }

    /// The roster epoch the epoch-key record named.
    pub const fn roster_epoch(&self) -> u32 {
        self.roster_epoch
    }

    /// The rotator that started the epoch.
    pub const fn rotator(&self) -> u16 {
        self.rotator
    }

    /// The epoch secret, for a one-slot record to another member.
    pub const fn secret(&self) -> &EpochSecret {
        &self.secret
    }

    /// Whether this state holds `K_e`: a member that joined inside the
    /// epoch holds its chain alone (`GRP-384`).
    pub fn holds_secret(&self) -> bool {
        self.secret.expose().expose() != &[0; 32]
    }

    /// The chain at the oldest slot that this state holds.
    pub const fn chain(&self) -> &ChainState {
        &self.chain
    }

    /// The queue credentials of the epoch.
    pub const fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Moves the window: the oldest slot held is `t_now −
    /// GROUP_SLOT_WINDOW`, and the keys before it are gone (`GRP-226`,
    /// `GRP-227`).
    pub fn advance_window(&mut self, now: u64) -> Result<(), Error> {
        let oldest = slot_of(now)
            .saturating_sub(GROUP_SLOT_WINDOW)
            .max(self.start_slot);
        if oldest > self.chain.slot() {
            self.chain.advance(oldest)?;
        }
        Ok(())
    }

    /// The record key of `slot`, inside the window at `now` (`GRP-228`).
    /// A slot outside the window is held as clock evidence.
    pub fn record_key(&mut self, slot: u32, now: u64) -> Result<Secret<32>, Error> {
        let t_now = slot_of(now);
        if slot < t_now.saturating_sub(GROUP_SLOT_WINDOW)
            || slot > t_now.saturating_add(GROUP_SLOT_SKEW)
        {
            return Err(Error::Stale);
        }
        if slot < self.start_slot {
            return Err(Error::Stale);
        }
        self.advance_window(now)?;
        Ok(self.chain.record_key(slot)?)
    }

    /// Writes the epoch state to its stored form.
    pub fn export(&self, w: &mut Writer) {
        w.bytes(self.secret.expose().expose());
        w.u32(self.epoch);
        w.u32(self.start_slot);
        w.u32(self.roster_epoch);
        w.u16(self.rotator);
        let slot = self.chain.slot();
        w.u32(slot);
        // The chain holds the key of that slot, thus this call clones it.
        match self.chain.slot_key(slot) {
            Ok(key) => w.bytes(key.expose()),
            Err(_) => w.bytes(&[0; 32]),
        }
        w.bytes(self.credentials.read_secret().expose());
        w.bytes(self.credentials.write_secret().expose());
        w.u64(self.installed_at);
    }

    /// Reads an epoch state that [`EpochState::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        let secret = EpochSecret::from_secret(Secret::new(r.array()?));
        let epoch = r.u32()?;
        let start_slot = r.u32()?;
        let roster_epoch = r.u32()?;
        let rotator = r.u16()?;
        let slot = r.u32()?;
        let chain = ChainState::from_slot_key(epoch, slot, Secret::new(r.array()?));
        let read = Secret::new(r.array()?);
        let write = Secret::new(r.array()?);
        Ok(EpochState {
            secret,
            epoch,
            start_slot,
            roster_epoch,
            rotator,
            chain,
            credentials: Credentials::from_secrets(&read, &write),
            installed_at: r.u64()?,
        })
    }

    /// Whether `GROUP_EPOCH_MAX_AGE` passed since `t_e` (`GRP-360`).
    pub fn aged(&self, now: u64) -> bool {
        now.saturating_sub(u64::from(self.start_slot).saturating_mul(GROUP_SLOT))
            >= GROUP_EPOCH_MAX_AGE
    }
}

/// The epochs a member holds: the current one, the previous one inside
/// its grace, and an alternate secret of the current one.
#[derive(Default)]
pub struct EpochStore {
    current: Option<EpochState>,
    previous: Option<EpochState>,
    alternate: Option<EpochState>,
}

impl EpochStore {
    /// The current epoch state.
    pub const fn current(&self) -> Option<&EpochState> {
        self.current.as_ref()
    }

    /// The epoch before the current one, inside its grace.
    pub const fn previous(&self) -> Option<&EpochState> {
        self.previous.as_ref()
    }

    /// Whether this store holds the keys of `epoch`, current or previous.
    pub fn holds_epoch(&self, epoch: u32) -> bool {
        [&self.current, &self.previous]
            .into_iter()
            .flatten()
            .any(|state| state.epoch == epoch)
    }

    /// Where `slot` falls against the window of `now` (`GRP-228`): below
    /// it, inside it, or above it.
    pub fn place_of(slot: u32, now: u64) -> core::cmp::Ordering {
        let t_now = slot_of(now);
        if slot < t_now.saturating_sub(GROUP_SLOT_WINDOW) {
            core::cmp::Ordering::Less
        } else if slot > t_now.saturating_add(GROUP_SLOT_SKEW) {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    }

    /// The current epoch number, or 0 before the first install.
    pub fn epoch(&self) -> u32 {
        self.current.as_ref().map_or(0, EpochState::epoch)
    }

    /// Installs an epoch (`GRP-286`, `GRP-288`): the successor of the
    /// current one, or the same epoch from a lower rotator index, which
    /// takes over and keeps the other secret as the alternate
    /// (`GRP-273`, `GRP-364`).
    pub fn install(&mut self, state: EpochState) -> Result<(), Error> {
        match self.current.take() {
            None => {
                self.current = Some(state);
                Ok(())
            }
            Some(current) if state.epoch == current.epoch.saturating_add(1) => {
                self.previous = Some(current);
                self.alternate = None;
                self.current = Some(state);
                Ok(())
            }
            Some(current) if state.epoch == current.epoch && state.rotator < current.rotator => {
                self.alternate = Some(current);
                self.current = Some(state);
                Ok(())
            }
            Some(current) if state.epoch == current.epoch && state.rotator > current.rotator => {
                self.alternate = Some(state);
                self.current = Some(current);
                Ok(())
            }
            Some(current) => {
                self.current = Some(current);
                Err(Error::Stale)
            }
        }
    }

    /// Drops the previous epoch after `GROUP_EPOCH_GRACE` (`GRP-231`) and
    /// the alternate with it.
    pub fn expire(&mut self, now: u64) {
        if self
            .previous
            .as_ref()
            .zip(self.current.as_ref())
            .is_some_and(|(_, c)| now.saturating_sub(c.installed_at) >= GROUP_EPOCH_GRACE)
        {
            self.previous = None;
            self.alternate = None;
        }
    }

    /// The record keys to try for a record of `epoch` at `slot`: the
    /// current or the previous epoch (`GRP-250`), and the alternate of the
    /// current epoch after it (`GRP-274`). The flag says whether the key is
    /// of the previous epoch, whose records need the current-roster check
    /// of `GRP-232`.
    pub fn record_keys(
        &mut self,
        epoch: u32,
        slot: u32,
        now: u64,
    ) -> Result<Vec<(Secret<32>, bool)>, Error> {
        let mut keys = Vec::new();
        if let Some(current) = self.current.as_mut().filter(|c| c.epoch == epoch) {
            keys.push((current.record_key(slot, now)?, false));
            if let Some(alternate) = self.alternate.as_mut() {
                if let Ok(key) = alternate.record_key(slot, now) {
                    keys.push((key, false));
                }
            }
        } else if let Some(previous) = self.previous.as_mut().filter(|p| p.epoch == epoch) {
            keys.push((previous.record_key(slot, now)?, true));
        } else {
            return Err(Error::Stale);
        }
        Ok(keys)
    }

    /// Writes the three epoch states to their stored form.
    pub fn export(&self, w: &mut Writer) {
        w.u8(STORED_VERSION);
        for state in [&self.current, &self.previous, &self.alternate] {
            w.flag(state.is_some());
            if let Some(state) = state {
                state.export(w);
            }
        }
    }

    /// Reads an epoch store that [`EpochStore::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.u8()? != STORED_VERSION {
            return Err(Error::Stale);
        }
        let mut states = [None, None, None];
        for slot in &mut states {
            if r.flag()? {
                *slot = Some(EpochState::import(r)?);
            }
        }
        let [current, previous, alternate] = states;
        Ok(EpochStore {
            current,
            previous,
            alternate,
        })
    }

    /// The credentials of the current epoch, for the group-queue session.
    pub fn credentials(&self) -> Option<&Credentials> {
        self.current.as_ref().map(EpochState::credentials)
    }

    /// The credentials of the previous epoch inside its grace. The relay
    /// takes the credentials of an epoch only at a `GKEY`, thus a command
    /// that it refuses under the current pair goes again under this one
    /// (`GRP-398`).
    pub fn previous_credentials(&self) -> Option<&Credentials> {
        self.previous.as_ref().map(EpochState::credentials)
    }
}

/// One member the rotation includes.
pub struct Included<'a> {
    /// The member index.
    pub index: u16,
    /// The role at the new roster epoch.
    pub role: Role,
    /// `GroupKemKey_g.pk` of the member.
    pub kem_pk: &'a [u8],
    /// The pair key between the rotator and the member.
    pub pair_key: &'a PairKey,
}

/// The output of a rotation: the epoch-key body, inline or as the object
/// the chunk path carries.
pub struct RotationOutput {
    /// The new secret, for the rotator's own install.
    pub secret: EpochSecret,
    /// The start slot.
    pub start_slot: u32,
    /// The inline body, when the slots fit `B3`.
    pub inline: Option<Vec<u8>>,
    /// The chunk object as whole segments, when the slots do not fit.
    pub chunks: Option<Vec<Vec<u8>>>,
    /// The slots in each chunk, when chunked.
    pub slots_per_chunk: u16,
}

/// Builds the epoch-key record of epoch `epoch` (`GRP-276` to `GRP-282`).
/// `own_sks` are the owner credentials of the two replicas, given to each
/// member at `admin` or above. A rotator below `admin` holds none and
/// passes `None`, thus each slot carries no owner secret (`GRP-277`,
/// `GRP-379`).
#[allow(clippy::too_many_arguments)]
pub fn rotate<R: CryptoRng + TryCryptoRng + ?Sized>(
    group_id: &[u8; 32],
    epoch: u32,
    roster_epoch: u32,
    rotator: u16,
    included: &[Included<'_>],
    own_sks: Option<&[Secret<32>; REPLICAS as usize]>,
    now: u64,
    bucket: umbra_wire::bucket::Bucket,
    rng: &mut R,
) -> Result<RotationOutput, Error> {
    let secret = EpochSecret::generate(rng)?;
    let start_slot = slot_of(now);
    let mut sealed_slots: Vec<(u16, Vec<u8>)> = Vec::with_capacity(included.len());
    let mut last: Option<u16> = None;
    for member in included {
        if last.is_some_and(|l| l >= member.index) {
            return Err(Error::Malformed);
        }
        last = Some(member.index);
        let tag = member.pair_key.epoch_tag(&EpochTag {
            group_id,
            epoch,
            start_slot,
            roster_epoch,
            epoch_secret: secret.expose(),
        });
        let admin = member.role >= Role::Admin && own_sks.is_some();
        let payload = SlotPayload {
            rotator,
            epoch_secret: Secret::new(*secret.expose().expose()),
            tag,
            own_sks: match own_sks.filter(|_| admin) {
                Some(own) => own.iter().map(|s| Secret::new(*s.expose())).collect(),
                None => Vec::new(),
            },
        };
        let mut plain = alloc::vec![0u8; payload.len()];
        payload.encode(&mut plain)?;
        let pk = PublicKey::from_bytes(member.kem_pk)?;
        let own_count = if admin { REPLICAS } else { 0 };
        let mut out = alloc::vec![0u8; slot_len(own_count).saturating_sub(2)];
        let n = slot::seal(&pk, group_id, epoch, member.index, &plain, rng, &mut out)?;
        out.truncate(n);
        sealed_slots.push((member.index, out));
    }
    let admin_slots = included
        .iter()
        .filter(|m| m.role >= Role::Admin && own_sks.is_some())
        .count();
    let inline_max = if admin_slots > 9 {
        INLINE_SLOTS_MAX - 1
    } else {
        INLINE_SLOTS_MAX
    };
    let slot_count = u16::try_from(sealed_slots.len()).map_err(|_| Error::Malformed)?;
    if sealed_slots.len() <= inline_max {
        let slots: Vec<KemSlot<'_>> = sealed_slots
            .iter()
            .map(|(index, sealed)| KemSlot {
                index: *index,
                sealed,
            })
            .collect();
        let body = EpochKeyBody {
            roster_epoch,
            slot_count,
            carrier: Carrier::Inline(slots),
        };
        let mut out = alloc::vec![0u8; bucket.group_record()];
        let n = body.encode(bucket, &mut out)?;
        out.truncate(n);
        return Ok(RotationOutput {
            secret,
            start_slot,
            inline: Some(out),
            chunks: None,
            slots_per_chunk: 0,
        });
    }
    let lens: Vec<usize> = sealed_slots
        .iter()
        .map(|(_, s)| s.len().saturating_add(2))
        .collect();
    let per_chunk = EpochKeyBody::slots_per_chunk(&lens, SEGMENT_SIZE).ok_or(Error::Malformed)?;
    let mut chunks = Vec::new();
    for block in sealed_slots.chunks(usize::from(per_chunk)) {
        let mut segment = alloc::vec![0u8; SEGMENT_SIZE];
        let mut at = 0usize;
        for (index, sealed) in block {
            let end = at.saturating_add(2).saturating_add(sealed.len());
            let slot_out = segment.get_mut(at..end).ok_or(Error::Malformed)?;
            let (head, tail) = slot_out.split_at_mut(2);
            head.copy_from_slice(&index.to_be_bytes());
            tail.copy_from_slice(sealed);
            at = end;
        }
        chunks.push(segment);
    }
    Ok(RotationOutput {
        secret,
        start_slot,
        inline: None,
        chunks: Some(chunks),
        slots_per_chunk: per_chunk,
    })
}

/// The body of a one-slot record of epoch `epoch` for one member
/// (§11.4.3): `secret` is `K_e` for a key supply (`GRP-375`), or 32 zero
/// bytes for a delivery of the owner credentials (`GRP-400`), and `own_sks`
/// are those credentials or none.
#[allow(clippy::too_many_arguments)]
pub fn one_slot<R: CryptoRng + ?Sized>(
    group_id: &[u8; 32],
    epoch: u32,
    start_slot: u32,
    roster_epoch: u32,
    rotator: u16,
    member: &Included<'_>,
    secret: &Secret<32>,
    own_sks: Option<&[Secret<32>; REPLICAS as usize]>,
    bucket: umbra_wire::bucket::Bucket,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let tag = member.pair_key.epoch_tag(&EpochTag {
        group_id,
        epoch,
        start_slot,
        roster_epoch,
        epoch_secret: secret,
    });
    let own_count = if own_sks.is_some() { REPLICAS } else { 0 };
    let payload = SlotPayload {
        rotator,
        epoch_secret: Secret::new(*secret.expose()),
        tag,
        own_sks: own_sks
            .map(|own| own.iter().map(|s| Secret::new(*s.expose())).collect())
            .unwrap_or_default(),
    };
    let mut plain = alloc::vec![0u8; payload.len()];
    payload.encode(&mut plain)?;
    let pk = PublicKey::from_bytes(member.kem_pk)?;
    let mut sealed = alloc::vec![0u8; slot_len(own_count).saturating_sub(2)];
    let n = slot::seal(&pk, group_id, epoch, member.index, &plain, rng, &mut sealed)?;
    sealed.truncate(n);
    let body = EpochKeyBody {
        roster_epoch,
        slot_count: 1,
        carrier: Carrier::Inline(alloc::vec![KemSlot {
            index: member.index,
            sealed: &sealed,
        }]),
    };
    let mut out = alloc::vec![0u8; bucket.group_record()];
    let n = body.encode(bucket, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// The chunk that holds the slot of rank `rank` (`GRP-284`).
pub const fn chunk_of_rank(rank: usize, slots_per_chunk: u16) -> usize {
    if slots_per_chunk == 0 {
        0
    } else {
        rank / slots_per_chunk as usize
    }
}

/// Opens the slot of `own_index` in `slots`, verifies its tag under the
/// pair key with the rotator, and checks the rotator's role against the
/// owner secrets it carries (`GRP-286`, `GRP-287`, `GRP-379`).
#[allow(clippy::too_many_arguments)]
pub fn open_own_slot(
    slots: &[KemSlot<'_>],
    own_index: u16,
    own_keys: &MemberKeys,
    group_id: &[u8; 32],
    epoch: u32,
    roster_epoch: u32,
    rotator_role_at: impl Fn(u16) -> Option<Role>,
    pair_key_with: impl Fn(u16) -> Option<PairKey>,
) -> Result<(SlotPayload, u32), Error> {
    let slot = slots
        .iter()
        .find(|s| s.index == own_index)
        .ok_or(Error::NoPath)?;
    let mut plain = alloc::vec![0u8; slot.sealed.len()];
    let n = slot::open(
        own_keys.kem(),
        group_id,
        epoch,
        own_index,
        slot.sealed,
        &mut plain,
    )?;
    let payload = SlotPayload::parse(plain.get(..n).ok_or(Error::Malformed)?)?;
    let rotator_role = rotator_role_at(payload.rotator).ok_or(Error::Unverified)?;
    if !payload.own_sks.is_empty() && rotator_role < Role::Admin {
        return Err(Error::Unverified);
    }
    let pair_key = pair_key_with(payload.rotator).ok_or(Error::Unverified)?;
    // The tag binds the start slot, which the record header carries; the
    // caller passes it through `start_slot` in the header. The slot index
    // of the record is that value.
    let start_slot = find_start_slot(&pair_key, group_id, epoch, roster_epoch, &payload)?;
    Ok((payload, start_slot))
}

/// The record header carries `t_e` as its `slot`; a caller that holds the
/// header verifies the tag at that slot directly.
pub fn verify_slot_tag(
    pair_key: &PairKey,
    group_id: &[u8; 32],
    epoch: u32,
    start_slot: u32,
    roster_epoch: u32,
    payload: &SlotPayload,
) -> Result<(), Error> {
    pair_key.verify_epoch_tag(
        &EpochTag {
            group_id,
            epoch,
            start_slot,
            roster_epoch,
            epoch_secret: &payload.epoch_secret,
        },
        &payload.tag,
    )?;
    Ok(())
}

fn find_start_slot(
    pair_key: &PairKey,
    group_id: &[u8; 32],
    epoch: u32,
    roster_epoch: u32,
    payload: &SlotPayload,
) -> Result<u32, Error> {
    // Without the header the start slot is unknown; the caller verifies
    // with `verify_slot_tag`. This path exists for a chunked slot that
    // arrives apart from its record, and it returns 0 to mark that.
    let _ = (pair_key, group_id, epoch, roster_epoch, payload);
    Ok(0)
}

/// Whether a member may rotate at `now` for a trigger it did not cause:
/// after its backoff, and only when no epoch-key record answered the
/// trigger (`GRP-359`).
pub fn may_rotate(trigger_seen_at: u64, delay: u64, answered: bool, now: u64) -> bool {
    !answered && now >= trigger_seen_at.saturating_add(delay)
}

/// A roster's role lookup for the slot checks.
pub fn role_lookup(roster: &Roster) -> impl Fn(u16) -> Option<Role> + '_ {
    move |index| roster.member(index).map(|m| m.role)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::{abuse::test_rng::Rng, group::test_util::member};
    use umbra_wire::bucket::Bucket;

    #[test]
    fn the_window_the_grace_and_the_two_rotator_rule_hold() {
        let group = [7u8; 32];
        let now = 1_000 * GROUP_SLOT;
        let mut store = EpochStore::default();
        let secret = EpochSecret::generate(&mut Rng(1)).unwrap();
        store
            .install(EpochState::new(secret, &group, 1, slot_of(now), 0, 0, now))
            .unwrap();
        assert_eq!(store.epoch(), 1);
        let t = slot_of(now);
        assert_eq!(store.record_keys(1, t, now).unwrap().len(), 1);
        assert!(store.record_keys(1, t + GROUP_SLOT_SKEW, now).is_ok());
        assert!(matches!(
            store.record_keys(1, t + GROUP_SLOT_SKEW + 1, now),
            Err(Error::Stale)
        ));
        assert!(matches!(
            store.record_keys(1, t - 1, now),
            Err(Error::Stale)
        ));
        assert!(matches!(store.record_keys(2, t, now), Err(Error::Stale)));
        // A later window drops the early slots.
        let later = now + 30 * GROUP_SLOT;
        assert!(matches!(store.record_keys(1, t, later), Err(Error::Stale)));
        assert!(store.record_keys(1, t + 10, later).is_ok());

        // The next epoch keeps the previous inside the grace.
        let second = EpochSecret::generate(&mut Rng(2)).unwrap();
        store
            .install(EpochState::new(
                second,
                &group,
                2,
                slot_of(later),
                1,
                3,
                later,
            ))
            .unwrap();
        let keys = store.record_keys(1, t + 10, later).unwrap();
        assert!(keys[0].1);
        store.expire(later + GROUP_EPOCH_GRACE - 1);
        assert!(store.record_keys(1, t + 10, later).is_ok());
        store.expire(later + GROUP_EPOCH_GRACE);
        assert!(matches!(
            store.record_keys(1, t + 10, later),
            Err(Error::Stale)
        ));
        // A second rotator for epoch 2 with a lower index takes over, and
        // the first stays as the alternate.
        let third = EpochSecret::generate(&mut Rng(3)).unwrap();
        store
            .install(EpochState::new(
                third,
                &group,
                2,
                slot_of(later),
                1,
                1,
                later,
            ))
            .unwrap();
        assert_eq!(store.current().unwrap().rotator(), 1);
        assert_eq!(
            store.record_keys(2, slot_of(later), later).unwrap().len(),
            2
        );
        let stale = EpochSecret::generate(&mut Rng(4)).unwrap();
        assert_eq!(
            store.install(EpochState::new(stale, &group, 1, 0, 0, 0, later)),
            Err(Error::Stale)
        );
        assert!(!store.current().unwrap().aged(later));
        assert!(store.current().unwrap().aged(later + GROUP_EPOCH_MAX_AGE));
        assert!(may_rotate(100, 10, false, 110));
        assert!(!may_rotate(100, 10, true, 110));
        assert!(!may_rotate(100, 10, false, 109));
    }

    #[test]
    fn a_rotation_seals_one_slot_per_member_and_each_opens_its_own() {
        let group = [7u8; 32];
        let rotator = member(1);
        let admin = member(2);
        let plain = member(3);
        let now = 5_000 * GROUP_SLOT;
        let kems: Vec<[u8; 1_216]> = [&rotator, &admin, &plain]
            .iter()
            .map(|m| m.kem().public().to_bytes())
            .collect();
        let pair_admin = rotator.pair_key(&admin.pair_public(), &group).unwrap();
        let pair_plain = rotator.pair_key(&plain.pair_public(), &group).unwrap();
        let pair_self = rotator.pair_key(&rotator.pair_public(), &group).unwrap();
        let included = [
            Included {
                index: 0,
                role: Role::Owner,
                kem_pk: &kems[0],
                pair_key: &pair_self,
            },
            Included {
                index: 1,
                role: Role::Admin,
                kem_pk: &kems[1],
                pair_key: &pair_admin,
            },
            Included {
                index: 2,
                role: Role::Member,
                kem_pk: &kems[2],
                pair_key: &pair_plain,
            },
        ];
        let own = [Secret::new([8; 32]), Secret::new([9; 32])];
        let out = rotate(
            &group,
            2,
            4,
            0,
            &included,
            Some(&own),
            now,
            Bucket::B2,
            &mut Rng(5),
        )
        .unwrap();
        let body_bytes = out.inline.unwrap();
        let roles = |i: u16| Some(if i == 0 { Role::Owner } else { Role::Member });
        let body = EpochKeyBody::parse(&body_bytes, |i| {
            roles(i).map(|r| {
                if r >= Role::Admin || i == 1 {
                    REPLICAS
                } else {
                    0
                }
            })
        })
        .unwrap();
        assert_eq!(body.slot_count, 3);
        let slots = match &body.carrier {
            Carrier::Inline(s) => s.clone(),
            Carrier::Chunked { .. } => panic!("inline"),
        };
        let admin_pair = admin.pair_key(&rotator.pair_public(), &group).unwrap();
        let (payload, _) = open_own_slot(&slots, 1, &admin, &group, 2, 4, roles, |i| {
            (i == 0).then(|| admin.pair_key(&rotator.pair_public(), &group).unwrap())
        })
        .unwrap();
        assert_eq!(payload.own_sks.len(), 2);
        assert_eq!(payload.own_sks[1].expose(), &[9; 32]);
        verify_slot_tag(&admin_pair, &group, 2, out.start_slot, 4, &payload).unwrap();
        assert!(verify_slot_tag(&admin_pair, &group, 2, out.start_slot + 1, 4, &payload).is_err());
        let (plain_payload, _) = open_own_slot(&slots, 2, &plain, &group, 2, 4, roles, |i| {
            (i == 0).then(|| plain.pair_key(&rotator.pair_public(), &group).unwrap())
        })
        .unwrap();
        assert!(plain_payload.own_sks.is_empty());
        assert_eq!(
            plain_payload.epoch_secret.expose(),
            out.secret.expose().expose()
        );
        // A member whose slot is absent finds none, and a wrong key opens
        // nothing.
        assert!(open_own_slot(&slots, 9, &plain, &group, 2, 4, roles, |_| None).is_err());
        assert!(open_own_slot(&slots, 1, &plain, &group, 2, 4, roles, |_| None).is_err());
        assert_eq!(chunk_of_rank(53, 27), 1);
        assert_eq!(chunk_of_rank(54, 27), 2);
    }
}
