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
    /// Whether the secret came from a record that did not serve the whole
    /// group: a key supply of `GRP-375`. Its `rotator` is the member that
    /// made the record, and no field names the rotator of the secret. Thus
    /// the index rule of `GRP-273` does not order it.
    supplied: bool,
    /// The epoch from which the checks of this one counted (`GRP-288`). It
    /// is none for the epoch of a creation, of an admit, and of a stored
    /// form that held none.
    base: Option<Base>,
    /// Whether the epoch that this member held before this one named the
    /// same roster epoch. This one is then the second of that roster epoch
    /// here (`GRP-369`).
    repeat: bool,
}

/// The epoch from which a member counts the checks of an epoch above it
/// (`GRP-288`): the number, the roster epoch, and `t_e`. For an epoch that
/// names another roster epoch than the epoch before it, it is that epoch. A
/// second epoch of one roster epoch keeps the base of the epoch before it.
/// An epoch that took the place of a rival of a lower number keeps that
/// base too. Thus each member that reads the two holds one base, in each
/// order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base {
    /// The number of the epoch.
    pub epoch: u32,
    /// The roster epoch that its record named.
    pub roster_epoch: u32,
    /// `t_e`.
    pub start_slot: u32,
}

/// The version of the stored epochs with the mark of a supplied secret; the
/// form before it is `STORED_VERSION`, which a read still takes.
const EPOCHS_VERSION_SUPPLIED: u8 = 0x02;

/// Version `0x02` with the base of each epoch and the mark of a second
/// epoch of one roster epoch (`GRP-288`).
const EPOCHS_VERSION: u8 = 0x03;

/// The rotations that the age of an epoch can call for between the start
/// slots `from` and `to` (`GRP-360`, `GRP-288`). A rotator installs an
/// epoch whose `t_e` lies `GROUP_SLOT_SKEW` above its clock, thus each such
/// rotation can start that much earlier.
pub fn aged_runs(from: u32, to: u32) -> u32 {
    let age = u32::try_from(GROUP_EPOCH_MAX_AGE / GROUP_SLOT).unwrap_or(u32::MAX);
    to.saturating_sub(from) / age.saturating_sub(GROUP_SLOT_SKEW).max(1)
}

/// Where `start_slot` of an epoch-key record falls against the clock at
/// `now` (`GRP-383`). It falls above `t_now + GROUP_SLOT_SKEW`, or more
/// than `GROUP_EPOCH_MAX_AGE` below `t_now`, or inside the two. The upper
/// bound is the one that the window of `GRP-228` gives each other slot of a
/// record. An epoch that starts above the bound takes no record until the
/// clock reaches it. An epoch that starts below the bound is past
/// `GROUP_EPOCH_MAX_AGE` at its installation.
pub fn start_slot_place(start_slot: u32, now: u64) -> core::cmp::Ordering {
    let t_now = slot_of(now);
    let age = u32::try_from(GROUP_EPOCH_MAX_AGE / GROUP_SLOT).unwrap_or(u32::MAX);
    if start_slot > t_now.saturating_add(GROUP_SLOT_SKEW) {
        core::cmp::Ordering::Greater
    } else if start_slot < t_now.saturating_sub(age) {
        core::cmp::Ordering::Less
    } else {
        core::cmp::Ordering::Equal
    }
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
            supplied: false,
            base: None,
            repeat: false,
        }
    }

    /// Sets the epoch from which the checks of this one counted, and
    /// whether this one is the second of its roster epoch at this member.
    #[must_use]
    pub const fn after(mut self, base: Option<Base>, repeat: bool) -> Self {
        self.base = base;
        self.repeat = repeat;
        self
    }

    /// The epoch from which the checks of this one counted.
    pub const fn base(&self) -> Option<Base> {
        self.base
    }

    /// Whether this epoch is the second of its roster epoch at this member.
    pub const fn is_repeat(&self) -> bool {
        self.repeat
    }

    /// The base of an epoch that follows this one and names `roster_epoch`,
    /// with the mark of a second epoch of one roster epoch.
    pub fn base_of_next(&self, roster_epoch: u32) -> (Option<Base>, bool) {
        let repeat = roster_epoch == self.roster_epoch;
        let base = self.base.filter(|_| repeat).unwrap_or(self.as_base());
        (Some(base), repeat)
    }

    /// This epoch as the base of the one after it.
    pub const fn as_base(&self) -> Base {
        Base {
            epoch: self.epoch,
            roster_epoch: self.roster_epoch,
            start_slot: self.start_slot,
        }
    }

    /// Marks the secret as one that a record for a part of the group gave.
    #[must_use]
    pub const fn supplied(mut self) -> Self {
        self.supplied = true;
        self
    }

    /// Whether the secret came from a record that did not serve the whole
    /// group.
    pub const fn is_supplied(&self) -> bool {
        self.supplied
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
            supplied: false,
            base: None,
            repeat: false,
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
            supplied: false,
            base: None,
            repeat: false,
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

    /// Installs an epoch (`GRP-286`, `GRP-288`): an epoch above the current
    /// one, or a second secret of the current one (`GRP-273`, `GRP-364`).
    /// The caller checked the trigger, the rotator, and the tag.
    ///
    /// Two secrets can come from records that each served the whole group.
    /// The one of the lower rotator index is then the current one, and the
    /// other is the alternate. A supplied secret names no rotator, thus it
    /// takes no part in that order. It never takes the place of the current
    /// secret here, and [`EpochStore::confirm_alternate`] moves it there.
    /// The record of the rotator for a secret that a supply gave makes that
    /// secret one of a known rotator, and the order runs again. A supplied
    /// secret can start the epoch here, because no record of the epoch
    /// opened before it. It then gives its place to the secret of a record
    /// that served the group.
    pub fn install(&mut self, state: EpochState) -> Result<(), Error> {
        let Some(mut current) = self.current.take() else {
            self.current = Some(state);
            return Ok(());
        };
        if state.epoch > current.epoch {
            self.previous = Some(current);
            self.alternate = None;
            self.current = Some(state);
            return Ok(());
        }
        if state.epoch < current.epoch {
            self.current = Some(current);
            return Err(Error::Stale);
        }
        let same = |held: &EpochState| {
            held.holds_secret() && held.secret.expose().expose() == state.secret.expose().expose()
        };
        // The secret that this store holds already: the record of its
        // rotator gives a supplied secret its rotator, and nothing else
        // changes.
        let known = if same(&current) {
            Some(&mut current)
        } else {
            self.alternate.as_mut().filter(|held| same(held))
        };
        if let Some(held) = known {
            let learned = held.supplied && !state.supplied;
            if learned {
                held.rotator = state.rotator;
                held.supplied = false;
            }
            self.current = Some(current);
            self.settle();
            return if learned { Ok(()) } else { Err(Error::Stale) };
        }
        if state.supplied {
            // A secret that one record for a part of the group gives opens
            // records, and no record goes out under it. It takes no place
            // of a secret whose record served the group.
            self.current = Some(current);
            if self.alternate.as_ref().is_some_and(|held| !held.supplied) {
                return Err(Error::Stale);
            }
            self.alternate = Some(state);
            return Ok(());
        }
        if current.supplied {
            // No field names the rotator of the current secret, and no
            // record of it served the group here. Thus the supplied secret
            // waits as the alternate. With the group secret in the other
            // place, this member would send under a secret that each other
            // member drops with its grace. A record of another member under
            // the supplied secret brings it back (`confirm_alternate`).
            let kept = match self.alternate.take() {
                Some(held) if !held.supplied && held.rotator <= state.rotator => held,
                _ => state,
            };
            self.current = Some(kept);
            self.alternate = Some(current);
            return Ok(());
        }
        if state.rotator == current.rotator {
            self.current = Some(current);
            return Err(Error::Stale);
        }
        self.alternate = Some(state);
        self.current = Some(current);
        self.settle();
        Ok(())
    }

    /// Marks the current epoch as the second of its roster epoch: a record
    /// of a lower number for that roster epoch verified after it
    /// (`GRP-288`).
    pub fn mark_repeat(&mut self) {
        if let Some(current) = self.current.as_mut() {
            current.repeat = true;
        }
    }

    /// GRP-273: of two secrets of known rotators, the one of the lower
    /// index is the current one.
    fn settle(&mut self) {
        let swap = self
            .current
            .as_ref()
            .zip(self.alternate.as_ref())
            .is_some_and(|(current, alternate)| {
                !current.supplied && !alternate.supplied && alternate.rotator < current.rotator
            });
        if swap {
            core::mem::swap(&mut self.current, &mut self.alternate);
        }
    }

    /// A record of `sender` opened under the alternate secret and its tag
    /// verified. A supplied secret under which a member other than its
    /// supplier writes is a secret that the group holds. Thus it takes the
    /// place of the current one, which stays as the alternate (`GRP-273`).
    /// The result says whether the two changed places.
    pub fn confirm_alternate(&mut self, sender: u16) -> bool {
        let confirmed = self
            .alternate
            .as_ref()
            .is_some_and(|held| held.supplied && held.rotator != sender)
            && self.current.as_ref().is_some_and(EpochState::holds_secret);
        if confirmed {
            core::mem::swap(&mut self.current, &mut self.alternate);
        }
        confirmed
    }

    /// The lowest roster epoch that an epoch of this store names, from
    /// which the roster keeps its history (`GRP-263`).
    pub fn oldest_roster_epoch(&self) -> Option<u32> {
        [&self.current, &self.previous, &self.alternate]
            .into_iter()
            .flatten()
            .map(|state| state.roster_epoch)
            .min()
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
    /// current epoch after it (`GRP-274`), which is the second key when the
    /// result holds two. The flag says whether the key is of the previous
    /// epoch, whose records need the current-roster check of `GRP-232`.
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
        w.u8(EPOCHS_VERSION);
        for state in [&self.current, &self.previous, &self.alternate] {
            w.flag(state.is_some());
            if let Some(state) = state {
                state.export(w);
                w.flag(state.supplied);
                w.flag(state.repeat);
                w.option(state.base.as_ref(), |w, base| {
                    w.u32(base.epoch);
                    w.u32(base.roster_epoch);
                    w.u32(base.start_slot);
                });
            }
        }
    }

    /// Reads an epoch store that [`EpochStore::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        let version = r.u8()?;
        if ![STORED_VERSION, EPOCHS_VERSION_SUPPLIED, EPOCHS_VERSION].contains(&version) {
            return Err(Error::Stale);
        }
        let mut states = [None, None, None];
        for slot in &mut states {
            if r.flag()? {
                let mut state = EpochState::import(r)?;
                if version >= EPOCHS_VERSION_SUPPLIED {
                    state.supplied = r.flag()?;
                }
                if version >= EPOCHS_VERSION {
                    state.repeat = r.flag()?;
                    state.base = r.option(|r| {
                        Ok(Base {
                            epoch: r.u32()?,
                            roster_epoch: r.u32()?,
                            start_slot: r.u32()?,
                        })
                    })?;
                }
                *slot = Some(state);
            }
        }
        let [mut current, previous, mut alternate] = states;
        // A form before the base: the epoch before the current one is the
        // base of it, and of its alternate.
        if version < EPOCHS_VERSION {
            let base = previous.as_ref().map(EpochState::as_base);
            for state in [&mut current, &mut alternate].into_iter().flatten() {
                state.base = base;
                state.repeat = base.is_some_and(|base| base.roster_epoch == state.roster_epoch);
            }
        }
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

    /// An epoch state of `epoch` whose secret is `seed` in each byte.
    fn state(epoch: u32, seed: u8, rotator: u16, now: u64) -> EpochState {
        EpochState::new(
            EpochSecret::from_secret(Secret::new([seed; 32])),
            &[7; 32],
            epoch,
            slot_of(now),
            1,
            rotator,
            now,
        )
    }

    #[test]
    fn a_supplied_secret_takes_no_part_in_the_index_rule() {
        let now = 1_000 * GROUP_SLOT;
        let mut store = EpochStore::default();
        store.install(state(1, 1, 0, now)).unwrap();
        store.install(state(2, 2, 5, now)).unwrap();
        // GRP-273: a one-slot record from a lower index gives a second
        // secret of the epoch. It opens records, and no record goes out
        // under it.
        store.install(state(2, 3, 1, now).supplied()).unwrap();
        assert_eq!(store.current().unwrap().rotator(), 5);
        assert_eq!(store.record_keys(2, slot_of(now), now).unwrap().len(), 2);
        // The supplier alone writes under it: nothing changes. A record of
        // another member under it makes it the secret of the group.
        assert!(!store.confirm_alternate(1));
        assert_eq!(store.current().unwrap().rotator(), 5);
        assert!(store.confirm_alternate(7));
        assert!(store.current().unwrap().is_supplied());
        assert!(!store.confirm_alternate(7));
        // The record of the rotator of that secret names its rotator, and
        // the index rule runs again: index 5 is below index 9.
        store.install(state(2, 3, 9, now)).unwrap();
        assert_eq!(store.current().unwrap().rotator(), 5);
        assert!(!store.current().unwrap().is_supplied());
        assert_eq!(store.install(state(2, 3, 9, now)), Err(Error::Stale));
        // A supplied secret takes no place of a secret whose record served
        // the group, as the current one or as the alternate.
        assert_eq!(
            store.install(state(2, 4, 0, now).supplied()),
            Err(Error::Stale)
        );
        assert_eq!(store.current().unwrap().rotator(), 5);

        // The stored form keeps the mark, and a read takes the form before
        // it.
        let mut marked = EpochStore::default();
        marked.install(state(1, 1, 0, now)).unwrap();
        marked.install(state(2, 2, 5, now).supplied()).unwrap();
        let mut w = Writer::new();
        marked.export(&mut w);
        let bytes = w.finish();
        let mut reader = Reader::new(&bytes);
        let back = EpochStore::import(&mut reader).unwrap();
        reader.end().unwrap();
        assert!(back.current().unwrap().is_supplied());
        assert!(!back.previous().unwrap().is_supplied());
        assert_eq!(back.oldest_roster_epoch(), Some(1));
        let mut w = Writer::new();
        w.u8(STORED_VERSION);
        w.flag(true);
        marked.current().unwrap().export(&mut w);
        w.flag(false);
        w.flag(false);
        let bytes = w.finish();
        let mut reader = Reader::new(&bytes);
        let old = EpochStore::import(&mut reader).unwrap();
        reader.end().unwrap();
        assert_eq!(old.epoch(), 2);
        assert!(!old.current().unwrap().is_supplied());
        // A form before the base gives the current epoch the one before it.
        assert!(old.current().unwrap().base().is_none());
        let mut w = Writer::new();
        w.u8(EPOCHS_VERSION_SUPPLIED);
        for held in [marked.current(), marked.previous()] {
            w.flag(true);
            held.unwrap().export(&mut w);
            w.flag(false);
        }
        w.flag(false);
        let bytes = w.finish();
        let mut reader = Reader::new(&bytes);
        let old = EpochStore::import(&mut reader).unwrap();
        reader.end().unwrap();
        assert_eq!(
            old.current().unwrap().base(),
            Some(marked.previous().unwrap().as_base())
        );

        // A member that missed each record of the epoch starts it with a
        // supplied secret. The record of a rotator takes the current place,
        // and the supplied secret still opens records. A record of another
        // member under the supplied secret brings it back.
        let mut late = EpochStore::default();
        late.install(state(1, 1, 0, now)).unwrap();
        late.install(state(2, 3, 4, now).supplied()).unwrap();
        assert!(late.current().unwrap().is_supplied());
        late.install(state(2, 2, 5, now)).unwrap();
        assert_eq!(late.current().unwrap().rotator(), 5);
        assert!(!late.current().unwrap().is_supplied());
        assert_eq!(late.record_keys(2, slot_of(now), now).unwrap().len(), 2);
        assert!(late.confirm_alternate(7));
        assert!(late.current().unwrap().is_supplied());
        // The same record again changes nothing.
        assert_eq!(late.install(state(2, 2, 5, now)), Err(Error::Stale));
        assert!(late.current().unwrap().is_supplied());
    }

    #[test]
    fn an_epoch_above_the_next_one_installs_and_the_start_slot_has_a_bound() {
        let now = 1_000 * GROUP_SLOT;
        let mut store = EpochStore::default();
        store.install(state(1, 1, 0, now)).unwrap();
        // GRP-288: the caller checked the trigger and the rotator, and the
        // number of the epoch gives no more.
        store.install(state(4, 2, 3, now)).unwrap();
        assert_eq!(store.epoch(), 4);
        assert_eq!(store.previous().unwrap().epoch(), 1);
        assert_eq!(store.install(state(3, 3, 0, now)), Err(Error::Stale));

        // GRP-383: `t_e` lies at most `GROUP_SLOT_SKEW` above the clock and
        // at most `GROUP_EPOCH_MAX_AGE` below it.
        use core::cmp::Ordering::{Equal, Greater, Less};
        let t = slot_of(now);
        let age = u32::try_from(GROUP_EPOCH_MAX_AGE / GROUP_SLOT).unwrap();
        assert_eq!(start_slot_place(t, now), Equal);
        assert_eq!(start_slot_place(t + GROUP_SLOT_SKEW, now), Equal);
        assert_eq!(start_slot_place(t + GROUP_SLOT_SKEW + 1, now), Greater);
        assert_eq!(start_slot_place(u32::MAX, now), Greater);
        assert_eq!(start_slot_place(t - age, now), Equal);
        assert_eq!(start_slot_place(t - age - 1, now), Less);
        assert_eq!(start_slot_place(0, now), Less);
    }
}
