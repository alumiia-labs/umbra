//! The automated Sybil detection of Part 10 §10.7.2.
//!
//! An [`Observation`] is the relay set of one published root. The history
//! is the observations of [`SYBIL_WINDOW`], the oldest one first. The four
//! detectors read the history and give the alerts of its newest epoch:
//!
//! | Detector | Finds |
//! | --- | --- |
//! | [`churn`] | Many relays that take or lose one state in one step. |
//! | [`uptime`] | Relays of different operators that change state together. |
//! | [`similarity`] | A new relay whose host name is near that of another operator. |
//! | [`rotation`] | One address that shows a new identity again and again. |
//!
//! An alert goes to a person. No detector removes a relay, and no detector
//! reads a file or a clock.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use umbra_core::directory::descriptor::{flags, RelayEntry};
use umbra_crypto::hex;

/// The epochs of history that the detectors read: 14 days. This is the
/// ingress staging of §10.7.1, the longest one. Thus each relay stays under
/// the detectors until its staging is complete.
pub const SYBIL_WINDOW: u64 = 336;

/// The share of the relay set, in parts of 1 000, that may take or lose
/// one state in one epoch. §10.5.3 expects about 8 changes at 3 000 relays,
/// and this share gives 30 there. The static count of Tor was the
/// documented bug (§10.7.2).
pub const SYBIL_CHURN_SHARE: usize = 10;

/// The lowest churn threshold. A network of ten relays that takes one,
/// two, or three new relays in one epoch gives no alert.
pub const SYBIL_CHURN_FLOOR: usize = 3;

/// The state changes of one relay in the window before the uptime detector
/// reads it: two restarts. One shared outage of a data center is no signal.
pub const SYBIL_UPTIME_CHANGES: usize = 4;

/// The lowest Pearson correlation of two relays of one group. Two relays
/// that miss one shared restart in ten stay at or above it.
pub const SYBIL_UPTIME_CORRELATION: f64 = 0.9;

/// The most relays that the uptime detector compares in one epoch. The
/// cost grows with the square of this count. A larger group that changes
/// in one step is above the churn threshold already.
pub const SYBIL_UPTIME_RELAYS: usize = 256;

/// The largest distance of two host names that the similarity detector
/// reports, in parts of 1 000 of the longer name: one edit in five
/// characters. `relay1.example.net` and `relay2.example.net` are below it,
/// and `relay.alice.org` and `relay.bob.org` are above it.
pub const SYBIL_NEAR_DISTANCE: usize = 200;

/// The nearest relays that one similarity alert names. A person reads
/// three lines, and a longer list hides the nearest one.
pub const SYBIL_NEAR_COUNT: usize = 3;

/// The most new relays that the similarity detector compares in one epoch.
/// Each one costs a comparison with the whole set. A larger group of new
/// relays is above the churn threshold already.
pub const SYBIL_NEAR_NEW: usize = 64;

/// The identities of one address in the window that give a rotation alert:
/// two that left and a new one. A lost key gives two identities, and a
/// third one inside 14 days is a pattern.
pub const SYBIL_ROTATION_IDS: usize = 3;

/// One relay of one observation: what the directory set for it, and the
/// descriptor fields that its operator selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// `relay_id` of the descriptor.
    pub relay_id: [u8; 32],
    /// `operator_id` of the entry.
    pub operator_id: [u8; 32],
    /// `flags` of the entry.
    pub flags: u8,
    /// The IPv4 address, or zero.
    pub addr_v4: [u8; 4],
    /// The IPv6 address, or zero.
    pub addr_v6: [u8; 16],
    /// The port.
    pub port: u16,
    /// The co-tenant host name.
    pub host: String,
    /// The autonomous system.
    pub asn: u32,
    /// ISO 3166-1 alpha-2.
    pub jurisdiction: [u8; 2],
    /// `family_id` of the descriptor, or zero for no family.
    pub family_id: [u8; 32],
}

impl Observed {
    /// The observed fields of a verified entry.
    pub fn of(entry: &RelayEntry<'_>) -> Self {
        let descriptor = &entry.descriptor;

        Observed {
            relay_id: descriptor.relay_id,
            operator_id: entry.operator_id,
            flags: entry.flags,
            addr_v4: descriptor.addr_v4,
            addr_v6: descriptor.addr_v6,
            port: descriptor.port,
            host: descriptor.host_str().to_owned(),
            asn: descriptor.asn,
            jurisdiction: descriptor.jurisdiction,
            family_id: descriptor.family_id,
        }
    }

    /// Whether the root lists the relay and places it in no layer yet.
    pub fn is_pending(&self) -> bool {
        self.flags & flags::PENDING != 0
    }

    /// Whether the relay may serve at hop 1.
    pub fn is_ingress(&self) -> bool {
        self.flags & flags::INGRESS != 0
    }

    /// The address that a client dials: the IPv4 address, or the IPv6
    /// address of a relay with no IPv4 address.
    pub fn address(&self) -> IpAddr {
        if self.addr_v4 == [0; 4] {
            IpAddr::V6(Ipv6Addr::from(self.addr_v6))
        } else {
            IpAddr::V4(Ipv4Addr::from(self.addr_v4))
        }
    }

    /// Whether the two relays declare one control: one operator or one
    /// family. A `family_id` of zero bytes is no family (`REL-209`).
    fn is_kin(&self, other: &Observed) -> bool {
        self.operator_id == other.operator_id
            || (self.family_id != [0; 32] && self.family_id == other.family_id)
    }
}

/// The relay set of one published root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The epoch of the root.
    pub epoch: u64,
    /// Each relay of the root.
    pub relays: Vec<Observed>,
}

/// The detector that made an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// [`churn`].
    Churn,
    /// [`uptime`].
    Uptime,
    /// [`similarity`].
    Similarity,
    /// [`rotation`].
    Rotation,
}

impl AlertKind {
    fn name(self) -> &'static str {
        match self {
            AlertKind::Churn => "churn",
            AlertKind::Uptime => "uptime",
            AlertKind::Similarity => "similarity",
            AlertKind::Rotation => "rotation",
        }
    }
}

/// One alert for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// The detector.
    pub kind: AlertKind,
    /// The epoch of the observation that gave the alert.
    pub epoch: u64,
    /// The `relay_id` of each relay that the alert names.
    pub relays: Vec<[u8; 32]>,
    /// One line that says what the detector found.
    pub detail: String,
}

impl Alert {
    /// The alert as one line of text.
    pub fn line(&self) -> String {
        let relays: Vec<String> = self.relays.iter().map(|relay| hex::write(relay)).collect();

        format!(
            "sybil kind={} epoch={} relays={} detail={}",
            self.kind.name(),
            self.epoch,
            relays.join(","),
            self.detail
        )
    }
}

/// Adds `now` to `history` and drops each observation outside
/// [`SYBIL_WINDOW`]. A second root of one epoch replaces the first one.
pub fn record(history: &mut Vec<Observation>, now: Observation) {
    history.retain(|held| {
        held.epoch < now.epoch && now.epoch.saturating_sub(held.epoch) < SYBIL_WINDOW
    });
    history.push(now);
}

/// The alerts of the newest observation of `history`, from each detector.
pub fn detect(history: &[Observation]) -> Vec<Alert> {
    let mut alerts = churn(history);
    alerts.extend(uptime(history));
    alerts.extend(similarity(history));
    alerts.extend(rotation(history));
    alerts
}

/// One state of an entry, which has its own churn series.
#[derive(Debug, Clone, Copy)]
enum State {
    Pending,
    Placed,
    Ingress,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Placed => "placed",
            State::Ingress => "ingress",
        }
    }

    fn holds(self, relay: &Observed) -> bool {
        match self {
            State::Pending => relay.is_pending(),
            State::Placed => !relay.is_pending(),
            State::Ingress => relay.is_ingress(),
        }
    }

    fn relays_of(self, observation: &Observation) -> BTreeSet<[u8; 32]> {
        observation
            .relays
            .iter()
            .filter(|relay| self.holds(relay))
            .map(|relay| relay.relay_id)
            .collect()
    }
}

/// The most relays that may take or lose one state between two
/// observations, for a set of `size` relays and `gap` epochs between them.
fn churn_threshold(size: usize, gap: u64) -> usize {
    let share = size.saturating_mul(SYBIL_CHURN_SHARE) / 1_000;
    let for_one_epoch = share.max(SYBIL_CHURN_FLOOR);

    // A signer that missed epochs shows the honest churn of each of them
    // in one step.
    let epochs = usize::try_from(gap.max(1)).unwrap_or(usize::MAX);
    for_one_epoch.saturating_mul(epochs)
}

/// The churn of each state between the two newest observations. An alert
/// names the relays that took one state, or the relays that lost it, when
/// their count is above the threshold.
pub fn churn(history: &[Observation]) -> Vec<Alert> {
    let [.., before, now] = history else {
        return Vec::new();
    };

    let gap = now.epoch.saturating_sub(before.epoch);
    let size = before.relays.len();
    let threshold = churn_threshold(size, gap);

    let mut alerts = Vec::new();
    for state in [State::Pending, State::Placed, State::Ingress] {
        let held_before = state.relays_of(before);
        let held_now = state.relays_of(now);

        let took: Vec<[u8; 32]> = held_now.difference(&held_before).copied().collect();
        let lost: Vec<[u8; 32]> = held_before.difference(&held_now).copied().collect();

        for (relays, change) in [(took, "took"), (lost, "lost")] {
            if relays.len() <= threshold {
                continue;
            }

            alerts.push(Alert {
                kind: AlertKind::Churn,
                epoch: now.epoch,
                detail: format!(
                    "{} relays {change} the {} state in {} epochs; \
                     the threshold is {threshold} for a set of {size} relays",
                    relays.len(),
                    state.name(),
                    gap.max(1),
                ),
                relays,
            });
        }
    }
    alerts
}

/// The state changes of one row of the uptime matrix.
fn changes(row: &[bool]) -> usize {
    row.windows(2)
        .filter(|pair| matches!(pair, [before, after] if before != after))
        .count()
}

/// The Pearson correlation of two rows of the uptime matrix, or none for
/// a row that never changes.
fn pearson(one: &[bool], other: &[bool]) -> Option<f64> {
    let count = |holds: fn(bool, bool) -> bool| {
        let cells = one.iter().zip(other).filter(|(a, b)| holds(**a, **b));
        u32::try_from(cells.count()).ok().map(f64::from)
    };

    let n = count(|_, _| true)?;
    let x = count(|a, _| a)?;
    let y = count(|_, b| b)?;
    let xy = count(|a, b| a && b)?;

    // A cell is 0 or 1, thus the sum of the squares is the sum.
    let spread = (n * x - x * x) * (n * y - y * y);
    if spread <= 0.0 {
        return None;
    }

    Some((n * xy - x * y) / spread.sqrt())
}

/// The newest entry of the relay `relay_id` in `history`.
fn newest_of<'a>(history: &'a [Observation], relay_id: &[u8; 32]) -> Option<&'a Observed> {
    history
        .iter()
        .rev()
        .flat_map(|observation| observation.relays.iter())
        .find(|relay| relay.relay_id == *relay_id)
}

/// The uptime matrix: one row for each relay, one cell for each
/// observation. A relay is up when a root lists it and places it.
fn uptime_matrix(history: &[Observation]) -> BTreeMap<[u8; 32], Vec<bool>> {
    let mut rows: BTreeMap<[u8; 32], Vec<bool>> = BTreeMap::new();
    for (column, observation) in history.iter().enumerate() {
        for relay in observation
            .relays
            .iter()
            .filter(|relay| !relay.is_pending())
        {
            let row = rows
                .entry(relay.relay_id)
                .or_insert_with(|| vec![false; history.len()]);
            if let Some(cell) = row.get_mut(column) {
                *cell = true;
            }
        }
    }
    rows
}

/// One row of the uptime matrix.
#[derive(Clone, Copy)]
struct Row<'a> {
    relay_id: &'a [u8; 32],
    cells: &'a [bool],
    /// The state changes of the row.
    changes: usize,
}

/// The groups of relays that change state together (synchronized
/// restarts). The detector reads the relays that changed state in the
/// newest observation and at least [`SYBIL_UPTIME_CHANGES`] times in the
/// window. Thus a group gives an alert when it moves, and not in each
/// epoch of the window. A group of one operator or one family gives none:
/// that control is declared.
pub fn uptime(history: &[Observation]) -> Vec<Alert> {
    let Some(now) = history.last() else {
        return Vec::new();
    };

    let rows = uptime_matrix(history);
    let mut moved: Vec<Row<'_>> = rows
        .iter()
        .map(|(relay_id, cells)| Row {
            relay_id,
            cells,
            changes: changes(cells),
        })
        .filter(|row| {
            let moved_now = matches!(row.cells, [.., before, after] if before != after);
            moved_now && row.changes >= SYBIL_UPTIME_CHANGES
        })
        .collect();

    // The bound keeps the relays with the most changes.
    moved.sort_by_key(|row| core::cmp::Reverse(row.changes));
    moved.truncate(SYBIL_UPTIME_RELAYS);

    // Each relay joins the first group whose first relay it follows, thus
    // a relay costs one comparison for each group.
    let mut groups: Vec<Vec<Row<'_>>> = Vec::new();
    for row in moved {
        let group = groups.iter_mut().find(|group| {
            group
                .first()
                .and_then(|first| pearson(first.cells, row.cells))
                .is_some_and(|correlation| correlation >= SYBIL_UPTIME_CORRELATION)
        });

        match group {
            Some(group) => group.push(row),
            None => groups.push(vec![row]),
        }
    }

    let mut alerts = Vec::new();
    for group in groups {
        let members: Vec<&Observed> = group
            .iter()
            .filter_map(|row| newest_of(history, row.relay_id))
            .collect();
        let Some(first) = members.first() else {
            continue;
        };

        if members.iter().all(|member| member.is_kin(first)) {
            continue;
        }

        let operators: BTreeSet<[u8; 32]> =
            members.iter().map(|member| member.operator_id).collect();
        let least = group.iter().map(|row| row.changes).min().unwrap_or(0);

        alerts.push(Alert {
            kind: AlertKind::Uptime,
            epoch: now.epoch,
            relays: members.iter().map(|member| member.relay_id).collect(),
            detail: format!(
                "{} relays of {} operators changed state together, \
                 each one {least} times or more in {} observations",
                members.len(),
                operators.len(),
                history.len(),
            ),
        });
    }
    alerts
}

/// The Levenshtein distance of two strings of bytes.
fn levenshtein(one: &[u8], other: &[u8]) -> usize {
    let mut row: Vec<usize> = (0..=other.len()).collect();

    for (done, a) in one.iter().enumerate() {
        let mut diagonal = done;
        let mut left = done.saturating_add(1);
        let mut next = Vec::with_capacity(row.len());
        next.push(left);

        for (b, above) in other.iter().zip(row.iter().skip(1)) {
            let replace = diagonal.saturating_add(usize::from(a != b));
            let insert = left.saturating_add(1);
            let delete = above.saturating_add(1);

            left = replace.min(insert).min(delete);
            diagonal = *above;
            next.push(left);
        }
        row = next;
    }

    row.last().copied().unwrap_or(0)
}

/// The distance of two host names in parts of 1 000 of the longer one, or
/// none above [`SYBIL_NEAR_DISTANCE`]. A DNS name has no case.
fn near_distance(one: &str, other: &str) -> Option<usize> {
    let longer = one.len().max(other.len());
    let scaled = |edits: usize| edits.saturating_mul(1_000).checked_div(longer);

    // The distance is the difference of the lengths or more, thus most
    // pairs cost no table.
    if scaled(one.len().abs_diff(other.len()))? > SYBIL_NEAR_DISTANCE {
        return None;
    }

    let edits = levenshtein(
        one.to_ascii_lowercase().as_bytes(),
        other.to_ascii_lowercase().as_bytes(),
    );
    scaled(edits).filter(|distance| *distance <= SYBIL_NEAR_DISTANCE)
}

/// The `relay_id` of each relay of `observations`.
fn relay_ids(observations: &[Observation]) -> BTreeSet<[u8; 32]> {
    observations
        .iter()
        .flat_map(|observation| observation.relays.iter())
        .map(|relay| relay.relay_id)
        .collect()
}

/// The nearest neighbors of each new relay. A relay is new when no earlier
/// observation of the history holds it. The detector compares its host
/// name with that of each relay of another operator and another family.
///
/// The host name is the one descriptor field with free text. The network
/// gives the address, the ASN, and the jurisdiction, and the family is a
/// hash. The detail of the alert shows the address and the ASN of each
/// neighbor.
pub fn similarity(history: &[Observation]) -> Vec<Alert> {
    let [earlier @ .., now] = history else {
        return Vec::new();
    };
    // The first observation holds new relays alone.
    if earlier.is_empty() {
        return Vec::new();
    }

    let known = relay_ids(earlier);
    let new_relays = now
        .relays
        .iter()
        .filter(|relay| !known.contains(&relay.relay_id))
        .take(SYBIL_NEAR_NEW);

    let mut alerts = Vec::new();
    for new in new_relays {
        let mut near: Vec<(usize, &Observed)> = now
            .relays
            .iter()
            .filter(|other| other.relay_id != new.relay_id && !other.is_kin(new))
            .filter_map(|other| Some((near_distance(&new.host, &other.host)?, other)))
            .collect();
        if near.is_empty() {
            continue;
        }

        near.sort_by_key(|(distance, other)| (*distance, other.relay_id));
        near.truncate(SYBIL_NEAR_COUNT);

        let neighbors: Vec<String> = near
            .iter()
            .map(|(distance, other)| {
                format!(
                    "{} at {} AS{} (distance {distance} of 1000)",
                    other.host,
                    other.address(),
                    other.asn
                )
            })
            .collect();

        let mut relays = vec![new.relay_id];
        relays.extend(near.iter().map(|(_, other)| other.relay_id));

        alerts.push(Alert {
            kind: AlertKind::Similarity,
            epoch: now.epoch,
            relays,
            detail: format!(
                "the new relay {} at {} AS{} is near a relay of another operator: {}",
                new.host,
                new.address(),
                new.asn,
                neighbors.join(", ")
            ),
        });
    }
    alerts
}

/// Each address that shows a new identity again and again. The detector
/// counts the identities that left an address in the window, and the new
/// one. Relays that share an address at one time are no rotation. An
/// address gives an alert in the epoch that shows the new identity.
pub fn rotation(history: &[Observation]) -> Vec<Alert> {
    let [earlier @ .., now] = history else {
        return Vec::new();
    };

    let known = relay_ids(earlier);
    let listed_now = relay_ids(core::slice::from_ref(now));

    let mut shown: BTreeMap<IpAddr, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for relay in history.iter().flat_map(|held| held.relays.iter()) {
        shown
            .entry(relay.address())
            .or_default()
            .insert(relay.relay_id);
    }

    let mut alerts = Vec::new();
    for (address, identities) in shown {
        let has_new = now
            .relays
            .iter()
            .any(|relay| relay.address() == address && !known.contains(&relay.relay_id));
        if !has_new {
            continue;
        }

        let left = identities.difference(&listed_now).count();
        let count = left.saturating_add(1);
        if count < SYBIL_ROTATION_IDS {
            continue;
        }

        alerts.push(Alert {
            kind: AlertKind::Rotation,
            epoch: now.epoch,
            relays: identities.into_iter().collect(),
            detail: format!(
                "the address {address} shows a new relay identity, and {left} identities \
                 left it in the last {SYBIL_WINDOW} epochs"
            ),
        });
    }
    alerts
}

/// The history as the text of the history file. One `epoch <number>` line
/// starts each observation. One line for each relay follows it:
/// `<relay_id> <operator_id> <flags> <IPv4> <IPv6> <port> <ASN>
/// <jurisdiction> <family_id> <host>`, with each byte field in hex.
pub fn history_text(history: &[Observation]) -> String {
    let mut text = String::new();
    for observation in history {
        text.push_str(&format!("epoch {}\n", observation.epoch));

        for relay in &observation.relays {
            text.push_str(&format!(
                "{} {} {} {} {} {} {} {} {} {}\n",
                hex::write(&relay.relay_id),
                hex::write(&relay.operator_id),
                relay.flags,
                hex::write(&relay.addr_v4),
                hex::write(&relay.addr_v6),
                relay.port,
                relay.asn,
                hex::write(&relay.jurisdiction),
                hex::write(&relay.family_id),
                relay.host,
            ));
        }
    }
    text
}

fn read_observed(line: &str) -> Option<Observed> {
    let mut words = line.split_whitespace();

    let relay = Observed {
        relay_id: hex::read_array(words.next()?)?,
        operator_id: hex::read_array(words.next()?)?,
        flags: words.next()?.parse().ok()?,
        addr_v4: hex::read_array(words.next()?)?,
        addr_v6: hex::read_array(words.next()?)?,
        port: words.next()?.parse().ok()?,
        asn: words.next()?.parse().ok()?,
        jurisdiction: hex::read_array(words.next()?)?,
        family_id: hex::read_array(words.next()?)?,
        // A relay in pin form has no host name (Part 10 `REL-143`).
        host: words.next().unwrap_or_default().to_owned(),
    };

    words.next().is_none().then_some(relay)
}

/// Reads the text of a history file, or gives none for a text with a
/// fault. A reader that drops a bad line would show a relay that left and
/// came back, thus one bad line refuses the whole text.
pub fn read_history(text: &str) -> Option<Vec<Observation>> {
    let mut history: Vec<Observation> = Vec::new();

    for line in text.lines() {
        if let Some(epoch) = line.strip_prefix("epoch ") {
            let epoch = epoch.parse().ok()?;
            if history.last().is_some_and(|held| held.epoch >= epoch) {
                return None;
            }

            history.push(Observation {
                epoch,
                relays: Vec::new(),
            });
            continue;
        }

        history.last_mut()?.relays.push(read_observed(line)?);
    }

    Some(history)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    fn id(number: u32) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..4].copy_from_slice(&number.to_be_bytes());
        out
    }

    /// The placed relay `number` of the operator `operator`.
    fn relay(number: u32, operator: u32, host: &str) -> Observed {
        let [_, b, c, d] = number.to_be_bytes();

        Observed {
            relay_id: id(number),
            operator_id: id(operator),
            flags: 0,
            addr_v4: [10, b, c, d],
            addr_v6: [0; 16],
            port: 443,
            host: host.to_owned(),
            asn: 64_500,
            jurisdiction: *b"DE",
            family_id: [0; 32],
        }
    }

    /// The relays `numbers`, each of its own operator, with host names
    /// that are far from each other.
    fn set(numbers: impl IntoIterator<Item = u32>) -> Vec<Observed> {
        numbers
            .into_iter()
            .map(|number| {
                let host = format!("{}.example", hex::write(&sha_like(number)));
                relay(number, number, &host)
            })
            .collect()
    }

    /// Sixteen bytes that differ much between two numbers.
    fn sha_like(number: u32) -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut state = u64::from(number) + 1;
        for byte in &mut out {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *byte = (state >> 56) as u8;
        }
        out
    }

    fn pending(mut relay: Observed) -> Observed {
        relay.flags = flags::PENDING;
        relay
    }

    fn at(epoch: u64, relays: Vec<Observed>) -> Observation {
        Observation { epoch, relays }
    }

    #[test]
    fn one_new_relay_in_a_set_of_ten_gives_no_churn_alert() {
        let mut later = set(0..10);
        later.push(pending(relay(10, 10, "new.example")));
        let history = [at(100, set(0..10)), at(101, later)];
        assert!(churn(&history).is_empty());

        // Three new relays are at the floor, and one relay that leaves is
        // below it.
        let history = [at(100, set(0..10)), at(101, set(1..13))];
        assert!(churn(&history).is_empty());

        // One observation has nothing before it.
        assert!(churn(&[at(100, set(0..50))]).is_empty());
    }

    #[test]
    fn forty_relays_that_appear_in_one_epoch_give_a_churn_alert() {
        let mut later = set(0..10);
        later.extend(set(10..50).into_iter().map(pending));
        let history = [at(100, set(0..10)), at(101, later)];

        let alerts = churn(&history);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Churn);
        assert_eq!(alerts[0].epoch, 101);
        assert_eq!(alerts[0].relays.len(), 40);
        assert!(alerts[0]
            .detail
            .contains("40 relays took the pending state"));
        assert!(alerts[0].detail.contains("threshold is 3"));
    }

    #[test]
    fn the_churn_threshold_follows_the_size_of_the_set() {
        assert_eq!(churn_threshold(10, 1), SYBIL_CHURN_FLOOR);
        assert_eq!(churn_threshold(3_000, 1), 30);
        assert_eq!(churn_threshold(3_000, 4), 120);

        // Twenty new relays at 3 000 are honest growth, and forty are not.
        let quiet = [at(100, set(0..3_000)), at(101, set(0..3_020))];
        assert!(churn(&quiet).is_empty());
        let loud = [at(100, set(0..3_000)), at(101, set(0..3_040))];
        assert_eq!(churn(&loud).len(), 1);

        // Forty relays that leave give an alert too.
        let gone = [at(100, set(0..3_040)), at(101, set(0..3_000))];
        let alerts = churn(&gone);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].detail.contains("lost the placed state"));

        // The same step after four missed epochs is honest.
        let late = [at(100, set(0..3_000)), at(104, set(0..3_040))];
        assert!(churn(&late).is_empty());
    }

    /// Forty observations of eight steady relays and of the relays of
    /// `restarts`: each one is absent in the columns of its list.
    fn restart_history(restarts: &[(Observed, &[usize])]) -> Vec<Observation> {
        (0..40usize)
            .map(|column| {
                let mut relays = set(100..108);
                for (relay, down) in restarts {
                    if !down.contains(&column) {
                        relays.push(relay.clone());
                    }
                }
                at(1_000 + column as u64, relays)
            })
            .collect()
    }

    #[test]
    fn two_relays_that_restart_together_five_times_give_an_uptime_alert() {
        let down = [5usize, 12, 19, 26, 38];
        let history = restart_history(&[
            (relay(1, 1, "one.example"), &down),
            (relay(2, 2, "other.example"), &down),
        ]);

        let alerts = uptime(&history);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Uptime);
        assert_eq!(alerts[0].epoch, 1_039);
        assert_eq!(alerts[0].relays, [id(1), id(2)]);
        assert!(alerts[0].detail.contains("2 relays of 2 operators"));

        // The group gives no alert in an epoch in which it does not move.
        let mut still = history.clone();
        still.push(at(1_040, history[39].relays.clone()));
        assert!(uptime(&still).is_empty());
    }

    #[test]
    fn restarts_at_different_times_or_of_one_operator_give_no_uptime_alert() {
        // The two relays share the last restart alone.
        let history = restart_history(&[
            (relay(1, 1, "one.example"), &[5, 12, 19, 26, 38]),
            (relay(2, 2, "other.example"), &[8, 15, 22, 29, 38]),
        ]);
        assert!(uptime(&history).is_empty());

        // One operator restarts its relays together.
        let down = [5usize, 12, 19, 26, 38];
        let history = restart_history(&[
            (relay(1, 7, "one.example"), &down),
            (relay(2, 7, "other.example"), &down),
        ]);
        assert!(uptime(&history).is_empty());

        // One shared restart is no pattern.
        let history = restart_history(&[
            (relay(1, 1, "one.example"), &[38]),
            (relay(2, 2, "other.example"), &[38]),
        ]);
        assert!(uptime(&history).is_empty());
    }

    #[test]
    fn the_correlation_of_two_rows_is_that_of_pearson() {
        let row = [true, false, true, true, false, true];
        let inverse = row.map(|cell| !cell);
        assert!((pearson(&row, &row).unwrap() - 1.0).abs() < 1e-9);
        assert!((pearson(&row, &inverse).unwrap() + 1.0).abs() < 1e-9);
        assert!(pearson(&row, &[true; 6]).is_none());
        assert_eq!(changes(&row), 4);
    }

    #[test]
    fn a_near_copy_of_a_host_name_of_another_operator_gives_an_alert() {
        let mut earlier = set(0..8);
        earlier.push(relay(20, 20, "relay1.example.net"));
        let mut later = earlier.clone();
        later.push(pending(relay(21, 21, "Relay2.example.net")));
        let history = [at(100, earlier), at(101, later)];

        let alerts = similarity(&history);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Similarity);
        assert_eq!(alerts[0].relays, [id(21), id(20)]);
        assert!(alerts[0].detail.contains("relay1.example.net at 10.0.0.20"));
        assert!(alerts[0].detail.contains("distance 55 of 1000"));
    }

    #[test]
    fn a_new_relay_with_its_own_host_name_gives_no_similarity_alert() {
        let mut earlier = set(0..8);
        earlier.push(relay(20, 20, "relay.alice.org"));

        // Another operator with another name.
        let mut later = earlier.clone();
        later.push(relay(21, 21, "relay.bob.org"));
        assert!(similarity(&[at(100, earlier.clone()), at(101, later)]).is_empty());

        // The same operator with a near name.
        let mut later = earlier.clone();
        later.push(relay(21, 20, "relay2.alice.org"));
        assert!(similarity(&[at(100, earlier.clone()), at(101, later)]).is_empty());

        // The same family with a near name.
        let mut with_family = earlier.clone();
        with_family[8].family_id = [9; 32];
        let mut later = with_family.clone();
        let mut cousin = relay(22, 22, "relay3.alice.org");
        cousin.family_id = [9; 32];
        later.push(cousin);
        assert!(similarity(&[at(100, with_family), at(101, later)]).is_empty());

        // A relay that the history holds already is not new.
        let mut old = earlier.clone();
        old.push(relay(21, 21, "relay.alice.org"));
        assert!(similarity(&[at(100, old.clone()), at(101, old)]).is_empty());

        // The first observation gives no alert.
        let mut first = earlier;
        first.push(relay(21, 21, "relay.alice.org"));
        assert!(similarity(&[at(100, first)]).is_empty());
    }

    #[test]
    fn the_distance_is_that_of_levenshtein() {
        assert_eq!(levenshtein(b"kitten", b"sitting"), 3);
        assert_eq!(levenshtein(b"", b"abc"), 3);
        assert_eq!(levenshtein(b"abc", b""), 3);
        assert_eq!(levenshtein(b"abc", b"abc"), 0);
        assert_eq!(near_distance("a.example", "A.EXAMPLE"), Some(0));
        assert_eq!(near_distance("relay.alice.org", "relay.bob.org"), None);
        assert_eq!(near_distance("", ""), None);
        // A relay in pin form has no name, thus it is near no relay.
        assert_eq!(near_distance("", "a.example"), None);
        assert_eq!(near_distance("a.example", ""), None);
    }

    /// One address that holds the relay of `numbers` in turn, one in each
    /// epoch, beside eight steady relays.
    fn rotation_history(numbers: &[u32]) -> Vec<Observation> {
        numbers
            .iter()
            .zip(100u64..)
            .map(|(number, epoch)| {
                let mut relays = set(100..108);
                let mut turn = relay(*number, 50, "turn.example");
                turn.addr_v4 = [192, 0, 2, 1];
                relays.push(turn);
                at(epoch, relays)
            })
            .collect()
    }

    #[test]
    fn an_address_that_shows_four_identities_gives_a_rotation_alert() {
        let alerts = rotation(&rotation_history(&[1, 2, 3, 4]));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Rotation);
        assert_eq!(alerts[0].epoch, 103);
        assert_eq!(alerts[0].relays, [id(1), id(2), id(3), id(4)]);
        assert!(alerts[0].detail.contains("the address 192.0.2.1"));
        assert!(alerts[0].detail.contains("3 identities left it"));

        // The alert comes with the new identity, and not in each epoch.
        assert!(rotation(&rotation_history(&[1, 2, 3, 4, 4])).is_empty());
    }

    #[test]
    fn a_new_key_or_shared_address_gives_no_rotation_alert() {
        // One lost key: two identities.
        assert!(rotation(&rotation_history(&[1, 1, 2])).is_empty());
        assert!(rotation(&rotation_history(&[1])).is_empty());

        // Four relays that share one address at one time.
        let shared = |numbers: core::ops::Range<u32>| {
            let mut relays = set(100..108);
            relays.extend(numbers.map(|number| {
                let mut relay = relay(number, 50, "shared.example");
                relay.addr_v4 = [192, 0, 2, 1];
                relay
            }));
            relays
        };
        assert!(rotation(&[at(100, shared(0..1)), at(101, shared(0..4))]).is_empty());
    }

    #[test]
    fn a_relay_with_no_ipv4_address_rotates_at_its_ipv6_address() {
        let mut history = rotation_history(&[1, 2, 3]);
        for observation in &mut history {
            let turn = observation.relays.last_mut().unwrap();
            turn.addr_v4 = [0; 4];
            turn.addr_v6 = [0x20; 16];
        }

        let alerts = rotation(&history);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].detail.contains("2020:2020"));
    }

    #[test]
    fn the_history_keeps_the_window_and_one_observation_for_each_epoch() {
        let mut history = Vec::new();
        record(&mut history, at(1_000, set(0..2)));
        record(&mut history, at(1_001, set(0..2)));
        // A second root of one epoch.
        record(&mut history, at(1_001, set(0..3)));
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].relays.len(), 3);

        record(&mut history, at(1_000 + SYBIL_WINDOW, set(0..2)));
        let epochs: Vec<u64> = history.iter().map(|held| held.epoch).collect();
        assert_eq!(epochs, [1_001, 1_000 + SYBIL_WINDOW]);
    }

    #[test]
    fn the_history_text_reads_back_and_a_bad_line_refuses_it() {
        let mut relays = set(0..3);
        relays.push(pending(relay(9, 9, "new.example")));
        // A relay in pin form has no host name (Part 10 `REL-143`).
        relays.push(relay(10, 10, ""));
        let history = vec![at(100, set(0..3)), at(101, Vec::new()), at(105, relays)];

        let text = history_text(&history);
        assert_eq!(read_history(&text), Some(history));
        assert_eq!(read_history(""), Some(Vec::new()));

        // A relay line with no epoch, a line that is cut, a word too many,
        // and two epochs out of order.
        let line = text.lines().nth(1).unwrap();
        assert_eq!(read_history(line), None);
        assert_eq!(read_history(&text[..text.len() - 20]), None);
        assert_eq!(read_history(&format!("epoch 1\n{line} more\n")), None);
        assert_eq!(read_history("epoch 5\nepoch 5\n"), None);
        assert_eq!(read_history("not a history"), None);
    }

    #[test]
    fn an_alert_is_one_line_with_its_kind_its_epoch_and_its_relays() {
        let alert = Alert {
            kind: AlertKind::Rotation,
            epoch: 7,
            relays: vec![[0xAB; 32], [0xCD; 32]],
            detail: "what a person reads".to_owned(),
        };
        assert_eq!(
            alert.line(),
            format!(
                "sybil kind=rotation epoch=7 relays={},{} detail=what a person reads",
                "ab".repeat(32),
                "cd".repeat(32)
            )
        );
    }

    #[test]
    fn each_detector_reads_one_history() {
        let mut later = set(0..10);
        later.extend(set(10..50).into_iter().map(pending));
        let history = [at(100, set(0..10)), at(101, later)];
        assert_eq!(detect(&history).len(), 1);
        assert!(detect(&[]).is_empty());
    }
}
