//! The search of the messages of this device (Part 14 §14.6.7). The index
//! sits in memory alone (`IMP-176`): the store seals each record on its own,
//! and an index in a file is a second copy of each text. It leaves the
//! memory at a lock (`IMP-177`), and each result is a row that the store
//! holds at the time of the query (`IMP-178`).

use std::collections::{BTreeMap, BTreeSet};

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_wire::app::{AppKind, AppMessage, Channel};
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};
use zeroize::{Zeroize, Zeroizing};

use super::{conversation_of, info_of, is_request, shown_text, Client, MESSAGE_PREFIX};
use crate::{ConversationId, Error, MsgRef};

/// The largest count of results of one query (`IMP-179`).
pub const SEARCH_RESULTS_MAX: usize = 200;
/// The longest query, in bytes of its folded form.
const QUERY_MAX: usize = 256;
/// The largest count of words of one query.
const TERMS_MAX: usize = 8;
/// The shortest and the longest word that takes a spelling error, in
/// characters. A shorter word is near to too many other words.
const NEAR_MIN: usize = 5;
const NEAR_MAX: usize = 32;
/// The length from which a word takes two spelling errors.
const NEAR_TWO: usize = 8;

/// The rank of a result. A lower value comes first.
pub const TIER_PHRASE: u8 = 0;
/// Each word of the query is in the text, in any order.
pub const TIER_WORDS: u8 = 1;
/// A word of the query has a spelling error.
pub const TIER_NEAR: u8 = 2;

/// One result of a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchHit {
    /// The message.
    pub message: MsgRef,
    /// The conversation of the message.
    pub conversation: ConversationId,
    /// The rank: [`TIER_PHRASE`], [`TIER_WORDS`], or [`TIER_NEAR`].
    pub tier: u8,
    /// The first match in the shown text, as a range of UTF-16 code units.
    pub start: u32,
    /// The end of that range.
    pub end: u32,
}

/// The order of the results of a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchOrder {
    /// The best rank first, and the newest first in each rank.
    #[default]
    Rank,
    /// The newest message first, in each rank together.
    Newest,
    /// The oldest message first, in each rank together.
    Oldest,
}

/// The side that sent a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchFrom {
    /// Each side.
    #[default]
    Any,
    /// The user of this device.
    Me,
    /// A contact, or a member of a group.
    Others,
}

/// The limits of one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SearchOptions {
    /// One conversation, or each one.
    pub scope: Option<ConversationId>,
    /// The order of the results.
    pub order: SearchOrder,
    /// The side that sent the message.
    pub from: SearchFrom,
    /// Whether a result is a message with a file.
    pub files_only: bool,
    /// The oldest insertion stamp of a result, in milliseconds, or 0 for
    /// each age.
    pub since_ms: u64,
}

impl SearchOptions {
    fn keeps(&self, entry: &Entry) -> bool {
        self.scope.is_none_or(|scope| scope == entry.conversation)
            && match self.from {
                SearchFrom::Any => true,
                SearchFrom::Me => entry.outgoing,
                SearchFrom::Others => !entry.outgoing,
            }
            && (!self.files_only || entry.has_file)
            && entry.stored_at_ms >= self.since_ms
    }
}

/// The values of one message that a limit of a query reads.
#[derive(Clone, Copy)]
struct Entry {
    message: MsgRef,
    conversation: ConversationId,
    stored_at_ms: u64,
    outgoing: bool,
    has_file: bool,
}

/// One message of the index.
struct Doc {
    entry: Entry,
    start: usize,
    end: usize,
}

/// The index of one build. Each part is zero bytes after the drop.
#[derive(Default)]
struct Index {
    docs: Vec<Doc>,
    /// The folded text of each message, one after the other.
    text: Vec<u8>,
    /// The messages of each group of three bytes of the folded text.
    grams: BTreeMap<u32, Vec<u32>>,
    /// The messages of each word that takes a spelling error.
    words: BTreeMap<Box<[u8]>, Vec<u32>>,
}

impl Drop for Index {
    fn drop(&mut self) {
        self.text.zeroize();
        for (mut gram, mut list) in core::mem::take(&mut self.grams) {
            gram.zeroize();
            list.zeroize();
        }
        for (mut word, mut list) in core::mem::take(&mut self.words) {
            word.zeroize();
            list.zeroize();
        }
        for doc in &mut self.docs {
            doc.entry.message.0.zeroize();
            doc.entry.conversation.0.zeroize();
        }
    }
}

/// A build that did not read each conversation yet.
struct Build {
    index: Index,
    pending: Vec<ConversationId>,
}

/// The search state of a client.
#[derive(Default)]
pub(super) struct Search {
    ready: Option<Index>,
    building: Option<Build>,
}

/// Folds `text` for a comparison: no case, no accent, and one space for
/// each run of white space. `emit` takes each byte of the folded form with
/// the range of UTF-16 code units of its source character.
fn fold_with(text: &str, mut emit: impl FnMut(u8, u32, u32)) {
    let mut at = 0u32;
    let mut is_after_space = true;
    for source in text.chars() {
        let units = u32::try_from(source.len_utf16()).unwrap_or(0);
        let (start, end) = (at, at.saturating_add(units));
        at = end;
        if source.is_whitespace() {
            if !is_after_space {
                emit(b' ', start, end);
            }
            is_after_space = true;
            continue;
        }
        for part in core::iter::once(source).nfd() {
            if is_combining_mark(part) {
                continue;
            }
            for lower in part.to_lowercase() {
                let mut bytes = [0u8; 4];
                for byte in lower.encode_utf8(&mut bytes).bytes() {
                    emit(byte, start, end);
                }
                bytes.zeroize();
                is_after_space = false;
            }
        }
    }
}

/// The folded form of `text`, with no space at its end.
fn fold(text: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len()));
    fold_with(text, |byte, _, _| out.push(byte));
    while out.last() == Some(&b' ') {
        out.pop();
    }
    out
}

/// The place of `needle` in `hay`, from `from` on.
fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    hay.get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|place| place.saturating_add(from))
}

/// The key of a group of three bytes.
fn gram_key(window: &[u8]) -> Option<u32> {
    match window {
        [a, b, c] => Some(u32::from(*a) << 16 | u32::from(*b) << 8 | u32::from(*c)),
        _ => None,
    }
}

/// Each word of a folded text with its byte range. A word is a run of
/// letters and digits.
fn words(text: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let text = core::str::from_utf8(text).unwrap_or_default();
    let mut rest = text.char_indices().peekable();
    core::iter::from_fn(move || {
        while rest.peek().is_some_and(|(_, c)| !c.is_alphanumeric()) {
            rest.next();
        }
        let (start, _) = *rest.peek()?;
        let mut end = start;
        while let Some((at, c)) = rest.peek().copied() {
            if !c.is_alphanumeric() {
                break;
            }
            end = at.saturating_add(c.len_utf8());
            rest.next();
        }
        Some((start, text.as_bytes().get(start..end)?))
    })
}

/// The count of spelling errors that a word of the query takes.
fn errors_for(word: &[u8]) -> usize {
    let Ok(word) = core::str::from_utf8(word) else {
        return 0;
    };
    if !word.chars().all(char::is_alphanumeric) {
        return 0;
    }
    match word.chars().count() {
        n if !(NEAR_MIN..=NEAR_MAX).contains(&n) => 0,
        n if n < NEAR_TWO => 1,
        _ => 2,
    }
}

/// Whether `a` becomes `b` with at most `max` changes: a character more, a
/// character less, a different character, or two neighbors that changed
/// places.
fn is_near(a: &[char], b: &[char], max: usize) -> bool {
    // The rows sit on the stack, thus a pass over each word of the index
    // makes no allocation. A longer word takes no spelling error.
    const WIDTH: usize = NEAR_MAX + 3;
    if a.len().abs_diff(b.len()) > max || a.len() > NEAR_MAX + 2 || b.len() > NEAR_MAX + 2 {
        return false;
    }
    let mut before = [usize::MAX; WIDTH];
    let mut last = [usize::MAX; WIDTH];
    for (j, value) in last.iter_mut().enumerate().take(b.len().saturating_add(1)) {
        *value = j;
    }
    for (i, x) in a.iter().enumerate() {
        let mut row = [usize::MAX; WIDTH];
        let mut left = i.saturating_add(1);
        let mut least = left;
        if let Some(first) = row.first_mut() {
            *first = left;
        }
        for (j, y) in b.iter().enumerate() {
            let cost = usize::from(x != y);
            let up = last.get(j.saturating_add(1)).copied().unwrap_or(usize::MAX);
            let diagonal = last.get(j).copied().unwrap_or(usize::MAX);
            let mut best = left
                .saturating_add(1)
                .min(up.saturating_add(1))
                .min(diagonal.saturating_add(cost));
            let is_swap = i > 0
                && j > 0
                && a.get(i.wrapping_sub(1)) == Some(y)
                && b.get(j.wrapping_sub(1)) == Some(x);
            if is_swap {
                let earlier = before.get(j.wrapping_sub(1)).copied().unwrap_or(usize::MAX);
                best = best.min(earlier.saturating_add(1));
            }
            if let Some(place) = row.get_mut(j.saturating_add(1)) {
                *place = best;
            }
            left = best;
            least = least.min(best);
        }
        if least > max {
            return false;
        }
        before = last;
        last = row;
    }
    last.get(b.len()).is_some_and(|value| *value <= max)
}

/// The characters of a word of the index, in a buffer on the stack.
fn word_chars(word: &[u8], buffer: &mut [char; NEAR_MAX]) -> usize {
    let mut count = 0usize;
    for (place, c) in buffer
        .iter_mut()
        .zip(core::str::from_utf8(word).unwrap_or_default().chars())
    {
        *place = c;
        count = count.saturating_add(1);
    }
    count
}

fn chars_of(word: &[u8]) -> Vec<char> {
    core::str::from_utf8(word)
        .unwrap_or_default()
        .chars()
        .collect()
}

/// The values that are in the two sorted lists.
fn both(a: &[u32], b: &[u32]) -> Vec<u32> {
    let (mut i, mut j) = (0usize, 0usize);
    let mut out = Vec::new();
    while let (Some(x), Some(y)) = (a.get(i), b.get(j)) {
        match x.cmp(y) {
            core::cmp::Ordering::Less => i = i.saturating_add(1),
            core::cmp::Ordering::Greater => j = j.saturating_add(1),
            core::cmp::Ordering::Equal => {
                out.push(*x);
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
        }
    }
    out
}

/// The values that are in one of the two sorted lists.
fn either(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out: Vec<u32> = a.iter().chain(b).copied().collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The best match of a folded query in a folded text: the rank, and the
/// byte range of the first match.
fn rank(text: &[u8], query: &[u8]) -> Option<(u8, usize, usize)> {
    if let Some(at) = find(text, query, 0) {
        return Some((TIER_PHRASE, at, at.saturating_add(query.len())));
    }
    let mut tier = TIER_WORDS;
    let mut first = None;
    for term in query.split(|byte| *byte == b' ').take(TERMS_MAX) {
        let place = match find(text, term, 0) {
            Some(at) => (at, at.saturating_add(term.len())),
            None => {
                let max = errors_for(term);
                if max == 0 {
                    return None;
                }
                let wanted = chars_of(term);
                let (at, word) =
                    words(text).find(|(_, word)| is_near(&wanted, &chars_of(word), max))?;
                tier = TIER_NEAR;
                (at, at.saturating_add(word.len()))
            }
        };
        first.get_or_insert(place);
    }
    first.map(|(start, end)| (tier, start, end))
}

impl Index {
    fn text_of(&self, doc: &Doc) -> &[u8] {
        self.text.get(doc.start..doc.end).unwrap_or_default()
    }

    /// Adds bytes to the text. A growth of the buffer leaves no copy of the
    /// old one.
    fn push_text(&mut self, bytes: &[u8]) {
        let needed = self.text.len().saturating_add(bytes.len());
        if needed > self.text.capacity() {
            let mut wider = Vec::with_capacity(needed.saturating_mul(2).max(4_096));
            wider.extend_from_slice(&self.text);
            self.text.zeroize();
            self.text = wider;
        }
        self.text.extend_from_slice(bytes);
    }

    /// Adds one message with its folded text.
    fn add(&mut self, entry: Entry, folded: &[u8]) {
        let Ok(id) = u32::try_from(self.docs.len()) else {
            return;
        };
        if folded.is_empty() {
            return;
        }
        let start = self.text.len();
        self.push_text(folded);
        self.docs.push(Doc {
            entry,
            start,
            end: self.text.len(),
        });
        for key in folded.windows(3).filter_map(gram_key) {
            let list = self.grams.entry(key).or_default();
            if list.last() != Some(&id) {
                list.push(id);
            }
        }
        for (_, word) in words(folded) {
            if errors_for(word) == 0 {
                continue;
            }
            let list = match self.words.get_mut(word) {
                Some(list) => list,
                None => self.words.entry(word.into()).or_default(),
            };
            if list.last() != Some(&id) {
                list.push(id);
            }
        }
    }

    fn doc(&self, id: u32) -> Option<&Doc> {
        usize::try_from(id).ok().and_then(|at| self.docs.get(at))
    }

    /// The messages that can hold `term`: each one holds each group of
    /// three bytes of it. A term below three bytes has no group, thus each
    /// message can hold it.
    fn possible_holders(&self, term: &[u8]) -> Vec<u32> {
        if term.len() < 3 {
            return (0..u32::try_from(self.docs.len()).unwrap_or(u32::MAX)).collect();
        }
        let mut lists: Vec<&Vec<u32>> = Vec::new();
        for key in term.windows(3).filter_map(gram_key) {
            match self.grams.get(&key) {
                Some(list) => lists.push(list),
                None => return Vec::new(),
            }
        }
        lists.sort_unstable_by_key(|list| list.len());
        let mut found: Option<Vec<u32>> = None;
        for list in lists {
            found = Some(match found {
                Some(held) => both(&held, list),
                None => list.clone(),
            });
        }
        found.unwrap_or_default()
    }

    /// The messages whose text holds `term`.
    fn holders(&self, term: &[u8]) -> Vec<u32> {
        self.possible_holders(term)
            .into_iter()
            .filter(|id| {
                self.doc(*id)
                    .is_some_and(|doc| find(self.text_of(doc), term, 0).is_some())
            })
            .collect()
    }

    /// `ids` inside the limits of the query, the newest first, or the
    /// oldest first for that order.
    fn ordered(&self, ids: Vec<u32>, options: &SearchOptions) -> Vec<(u32, &Doc)> {
        let mut found: Vec<(u32, &Doc)> = ids
            .into_iter()
            .filter_map(|id| Some((id, self.doc(id)?)))
            .filter(|(_, doc)| options.keeps(&doc.entry))
            .collect();
        found.sort_unstable_by(|(_, a), (_, b)| {
            let by_age = a.entry.stored_at_ms.cmp(&b.entry.stored_at_ms);
            let by_age = if options.order == SearchOrder::Oldest {
                by_age
            } else {
                by_age.reverse()
            };
            by_age.then(a.entry.message.cmp(&b.entry.message))
        });
        found
    }

    /// The messages that hold a word near to `term`.
    fn near_holders(&self, term: &[u8]) -> Vec<u32> {
        let max = errors_for(term);
        if max == 0 {
            return Vec::new();
        }
        let wanted = chars_of(term);
        let mut buffer = ['\0'; NEAR_MAX];
        let mut lists = Vec::new();
        for (word, list) in &self.words {
            if word.len().abs_diff(term.len()) > max.saturating_mul(4) {
                continue;
            }
            let count = word_chars(word, &mut buffer);
            if is_near(&wanted, buffer.get(..count).unwrap_or_default(), max) {
                lists.push(list);
            }
        }
        let mut found: Vec<u32> = lists.into_iter().flatten().copied().collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// At most `max` candidates of a folded query, in the order of the
    /// query. A later rank is read only when the ranks before it gave less
    /// than `max`, thus a query with many results compares few texts.
    fn candidates(&self, query: &[u8], options: &SearchOptions, max: usize) -> Vec<&Doc> {
        let terms: Vec<&[u8]> = query.split(|byte| *byte == b' ').take(TERMS_MAX).collect();
        if options.order != SearchOrder::Rank {
            // An order by age reads each rank together: each message that
            // can hold each word, or a word near to it.
            let mut possible: Option<Vec<u32>> = None;
            for term in &terms {
                let wider = either(&self.possible_holders(term), &self.near_holders(term));
                possible = Some(possible.map_or(wider.clone(), |held| both(&held, &wider)));
            }
            return self
                .ordered(possible.unwrap_or_default(), options)
                .into_iter()
                .filter(|(_, doc)| rank(self.text_of(doc), query).is_some())
                .map(|(_, doc)| doc)
                .take(max)
                .collect();
        }
        let mut taken = BTreeSet::new();
        let mut found = Vec::new();
        for (id, doc) in self.ordered(self.possible_holders(query), options) {
            if found.len() >= max {
                return found;
            }
            if find(self.text_of(doc), query, 0).is_some() {
                taken.insert(id);
                found.push(doc);
            }
        }
        if terms.len() > 1 {
            let mut possible: Option<Vec<u32>> = None;
            for term in &terms {
                let holders = self.possible_holders(term);
                possible = Some(possible.map_or(holders.clone(), |held| both(&held, &holders)));
            }
            for (id, doc) in self.ordered(possible.unwrap_or_default(), options) {
                if found.len() >= max {
                    return found;
                }
                let text = self.text_of(doc);
                let holds_each = terms.iter().all(|term| find(text, term, 0).is_some());
                if holds_each && taken.insert(id) {
                    found.push(doc);
                }
            }
        }
        if found.len() >= max || terms.iter().all(|term| errors_for(term) == 0) {
            return found;
        }
        let mut near: Option<Vec<u32>> = None;
        for term in &terms {
            let wider = either(&self.holders(term), &self.near_holders(term));
            near = Some(near.map_or(wider.clone(), |held| both(&held, &wider)));
        }
        for (id, doc) in self.ordered(near.unwrap_or_default(), options) {
            if found.len() >= max {
                break;
            }
            if taken.insert(id) {
                found.push(doc);
            }
        }
        found
    }
}

/// The text of a stored message that a search reads: the shown text, and
/// the name of a file.
fn searched_text(plain: &[u8]) -> Result<Zeroizing<String>, Error> {
    let shown = core::str::from_utf8(shown_text(plain)?).map_err(|_| Error::Integrity)?;
    let mut text = Zeroizing::new(String::from(shown));
    let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
    if parsed.kind == AppKind::Attachment {
        if let Ok(body) = umbra_wire::descriptor::AttachmentBody::parse(parsed.body) {
            if let Some(name) = body.name {
                text.push('\n');
                text.push_str(&name);
            }
        }
    }
    Ok(text)
}

/// The values of a stored message that a limit of a query reads.
fn entry_of(message: MsgRef, plain: &[u8]) -> Result<Entry, Error> {
    let info = info_of(plain)?;
    let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
    Ok(Entry {
        message,
        conversation: conversation_of(plain)?,
        stored_at_ms: info.stored_at_ms,
        outgoing: info.outgoing,
        has_file: AppMessage::parse(app, Channel::Pairwise)?.kind == AppKind::Attachment,
    })
}

/// Whether a view shows the row and a search can read its text.
fn is_searched(plain: &[u8]) -> Result<bool, Error> {
    Ok(!is_request(plain)? && !info_of(plain)?.deleted)
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Starts a build of the search index. The index that a build made
    /// before stays in use until this build ends.
    pub fn search_begin(&mut self) -> Result<(), Error> {
        let pending = self.conversations()?;
        self.search.building = Some(Build {
            index: Index::default(),
            pending,
        });
        Ok(())
    }

    /// One step of the build: the messages of one conversation. The result
    /// says whether the build is complete. Thus no step holds the client
    /// for the time of the full history.
    pub fn search_step(&mut self) -> Result<bool, Error> {
        // The build leaves the client for the step, thus the read of the
        // store and the write of the index hold no part of each other.
        let Some(mut build) = self.search.building.take() else {
            return Ok(true);
        };
        let Some(conversation) = build.pending.pop() else {
            self.search.ready = Some(build.index);
            return Ok(true);
        };
        let open = self.open_ref()?;
        for (row, plain) in open.store.list(TableId::MESSAGE, Some(&conversation.0))? {
            let plain = Zeroizing::new(plain);
            // IMP-121: the plaintext names its owner.
            if conversation_of(&plain)? != conversation {
                return Err(Error::Integrity);
            }
            if !is_searched(&plain)? {
                continue;
            }
            let Ok(text) = searched_text(&plain) else {
                continue;
            };
            build
                .index
                .add(entry_of(MsgRef(row), &plain)?, &fold(&text));
        }
        self.search.building = Some(build);
        Ok(false)
    }

    /// Whether a build made an index and no lock removed it.
    pub fn is_search_ready(&self) -> bool {
        self.search.ready.is_some()
    }

    /// Removes the search index from the memory.
    pub fn search_end(&mut self) {
        self.search = Search::default();
    }

    /// The messages that match a query, as UTF-16 code units, inside the
    /// limits of `options`. The store confirms each result
    /// (`IMP-178`): a message that it holds no more, or whose text changed,
    /// is not one. The client keeps no query (`IMP-180`).
    pub fn search(&self, query: &[u16], options: &SearchOptions) -> Result<Vec<SearchHit>, Error> {
        let open = self.open_ref()?;
        let typed = Zeroizing::new(String::from_utf16(query).map_err(|_| Error::Malformed)?);
        let query = fold(&typed);
        if query.is_empty() || query.len() > QUERY_MAX {
            return Ok(Vec::new());
        }
        let index = match (&self.search.ready, &self.search.building) {
            (Some(index), _) => index,
            (None, Some(build)) => &build.index,
            (None, None) => return Ok(Vec::new()),
        };
        let mut hits = Vec::new();
        // A row that the store holds no more takes a place of the first read.
        for doc in index.candidates(&query, options, SEARCH_RESULTS_MAX.saturating_mul(2)) {
            if hits.len() >= SEARCH_RESULTS_MAX {
                break;
            }
            let Some(plain) = open.store.get(TableId::MESSAGE, &doc.entry.message.0)? else {
                continue;
            };
            let plain = Zeroizing::new(plain);
            if conversation_of(&plain)? != doc.entry.conversation || !is_searched(&plain)? {
                continue;
            }
            // The limits read the row of the store too: an edit can
            // take the file of a message away.
            if !options.keeps(&entry_of(doc.entry.message, &plain)?) {
                continue;
            }
            let Ok(text) = searched_text(&plain) else {
                continue;
            };
            let shown_units = shown_text(&plain)
                .ok()
                .and_then(|shown| core::str::from_utf8(shown).ok())
                .map_or(0, |shown| shown.encode_utf16().count());
            let mut folded = Zeroizing::new(Vec::new());
            let mut places = Vec::new();
            fold_with(&text, |byte, start, end| {
                folded.push(byte);
                places.push((start, end));
            });
            let Some((tier, from, to)) = rank(&folded, &query) else {
                continue;
            };
            let start = places.get(from).map_or(0, |(start, _)| *start);
            let end = to
                .checked_sub(1)
                .and_then(|last| places.get(last))
                .map_or(start, |(_, end)| *end);
            // A match in the name of a file is outside the shown text, thus
            // it marks nothing.
            let limit = u32::try_from(shown_units).unwrap_or(u32::MAX);
            let (start, end) = if end <= limit { (start, end) } else { (0, 0) };
            hits.push(SearchHit {
                message: doc.entry.message,
                conversation: doc.entry.conversation,
                tier,
                start,
                end,
            });
        }
        // A text that changed after the build can have a different rank.
        if options.order == SearchOrder::Rank {
            hits.sort_by_key(|hit| hit.tier);
        }
        Ok(hits)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn entry(id: u8, conversation: u8, stored_at_ms: u64) -> Entry {
        Entry {
            message: MsgRef([id; 16]),
            conversation: ConversationId([conversation; 16]),
            stored_at_ms,
            outgoing: id % 2 == 1,
            has_file: false,
        }
    }

    fn index_of(texts: &[&str]) -> Index {
        let mut index = Index::default();
        for (at, text) in texts.iter().enumerate() {
            let id = u8::try_from(at).unwrap();
            index.add(entry(id, 0, u64::from(id)), &fold(text));
        }
        index
    }

    fn found(index: &Index, query: &str) -> Vec<u8> {
        index
            .candidates(&fold(query), &SearchOptions::default(), usize::MAX)
            .into_iter()
            .map(|doc| doc.entry.message.0[0])
            .collect()
    }

    #[test]
    fn a_fold_removes_case_accents_and_runs_of_space() {
        assert_eq!(fold("  Café   CRÈME\n").as_slice(), b"cafe creme");
        assert_eq!(fold("Ünïcödé").as_slice(), b"unicode");
    }

    #[test]
    fn a_part_of_a_word_and_a_part_of_a_sentence_match() {
        let index = index_of(&["happy birthday to you", "see you at the station", "no"]);
        assert_eq!(found(&index, "birth"), [0]);
        assert_eq!(found(&index, "you at the"), [1]);
        assert_eq!(found(&index, "you"), [1, 0]);
    }

    #[test]
    fn words_match_in_each_order_after_the_exact_phrase() {
        let index = index_of(&[
            "friday dinner at eight",
            "dinner on friday",
            "dinner friday",
        ]);
        // The phrase comes first, then the newest of the other two.
        assert_eq!(found(&index, "dinner friday"), [2, 1, 0]);
    }

    #[test]
    fn a_misspelled_word_matches_after_each_exact_match() {
        let index = index_of(&["the restaurant was full", "resturant", "rest"]);
        assert_eq!(found(&index, "resturant"), [1, 0]);
        // Each of the two texts holds a word with two errors or less.
        assert_eq!(found(&index, "restuarant"), [1, 0]);
        // A short word takes no spelling error.
        assert_eq!(found(&index, "rast"), [] as [u8; 0]);
    }

    #[test]
    fn a_query_of_one_or_two_letters_reads_the_text() {
        let index = index_of(&["ok", "look", "no"]);
        assert_eq!(found(&index, "ok"), [1, 0]);
        assert_eq!(found(&index, "n"), [2]);
    }

    #[test]
    fn a_text_with_no_spaces_matches_by_its_characters() {
        let index = index_of(&["明日は東京に行きます", "東京"]);
        assert_eq!(found(&index, "東京"), [1, 0]);
    }

    #[test]
    fn a_scope_keeps_the_results_of_one_conversation() {
        let mut index = Index::default();
        index.add(entry(1, 1, 1), &fold("train"));
        index.add(entry(2, 2, 2), &fold("train"));
        let options = SearchOptions {
            scope: Some(ConversationId([1; 16])),
            ..SearchOptions::default()
        };
        let found = index.candidates(&fold("train"), &options, usize::MAX);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entry.message, MsgRef([1; 16]));
    }

    #[test]
    fn an_order_by_age_reads_each_rank_together() {
        let index = index_of(&[
            "dinner on friday",
            "friday dinner",
            "freiday dinner",
            "lunch",
        ]);
        let by = |order| {
            let options = SearchOptions {
                order,
                ..SearchOptions::default()
            };
            index
                .candidates(&fold("friday dinner"), &options, usize::MAX)
                .into_iter()
                .map(|doc| doc.entry.message.0[0])
                .collect::<Vec<u8>>()
        };
        assert_eq!(by(SearchOrder::Rank), [1, 0, 2]);
        assert_eq!(by(SearchOrder::Newest), [2, 1, 0]);
        assert_eq!(by(SearchOrder::Oldest), [0, 1, 2]);
    }

    #[test]
    fn a_limit_keeps_the_side_the_age_and_the_files() {
        let mut index = Index::default();
        // The message 1 is of this user, and the message 2 has a file.
        index.add(entry(1, 0, 10), &fold("harbor"));
        let mut with_file = entry(2, 0, 20);
        with_file.has_file = true;
        index.add(with_file, &fold("harbor"));
        let ids = |options: SearchOptions| {
            index
                .candidates(&fold("harbor"), &options, usize::MAX)
                .into_iter()
                .map(|doc| doc.entry.message.0[0])
                .collect::<Vec<u8>>()
        };
        let any = SearchOptions::default();
        assert_eq!(ids(any), [2, 1]);
        assert_eq!(
            ids(SearchOptions {
                from: SearchFrom::Me,
                ..any
            }),
            [1]
        );
        assert_eq!(
            ids(SearchOptions {
                from: SearchFrom::Others,
                ..any
            }),
            [2]
        );
        assert_eq!(
            ids(SearchOptions {
                files_only: true,
                ..any
            }),
            [2]
        );
        assert_eq!(
            ids(SearchOptions {
                since_ms: 15,
                ..any
            }),
            [2]
        );
    }

    #[test]
    fn a_rank_gives_the_range_of_the_first_match() {
        assert_eq!(rank(b"see you soon", b"you"), Some((TIER_PHRASE, 4, 7)));
        assert_eq!(
            rank(b"dinner on friday", b"friday dinner"),
            Some((TIER_WORDS, 10, 16))
        );
        assert_eq!(
            rank(b"the restaurant", b"resturant"),
            Some((TIER_NEAR, 4, 14))
        );
        assert_eq!(rank(b"the station", b"airport"), None);
    }

    #[test]
    fn two_neighbors_that_changed_places_are_one_error() {
        let near =
            |a: &str, b: &str, max| is_near(&chars_of(a.as_bytes()), &chars_of(b.as_bytes()), max);
        assert!(near("recieve", "receive", 1));
        assert!(near("adress", "address", 1));
        assert!(!near("station", "stadium", 1));
        assert!(near("restuarant", "restaurant", 2));
    }

    /// The time and the memory of an index of 100 000 messages. Run it
    /// with `--release --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check"]
    fn measure_one_hundred_thousand_messages() {
        const WORDS: &[&str] = &[
            "the",
            "meeting",
            "tomorrow",
            "dinner",
            "restaurant",
            "station",
            "train",
            "please",
            "photo",
            "birthday",
            "weekend",
            "project",
            "schedule",
            "airport",
            "message",
            "coffee",
            "tonight",
            "family",
            "question",
            "answer",
            "möglich",
            "straße",
            "naïve",
            "東京",
        ];
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            usize::try_from(seed % 1_000_003).unwrap()
        };
        let started = std::time::Instant::now();
        let mut index = Index::default();
        for id in 0..100_000u32 {
            let mut text = String::new();
            for _ in 0..(4 + next() % 12) {
                let word = WORDS[next() % WORDS.len()];
                text.push_str(word);
                // A part of the words is rare, as names are.
                if next() % 5 == 0 {
                    text.push_str(&format!("{}", next() % 5_000));
                }
                text.push(' ');
            }
            let mut message = [0u8; 16];
            message[..4].copy_from_slice(&id.to_be_bytes());
            let mut entry = entry(0, 0, u64::from(id));
            entry.message = MsgRef(message);
            index.add(entry, &fold(&text));
        }
        let build = started.elapsed();
        let postings: usize = index.grams.values().map(Vec::len).sum::<usize>()
            + index.words.values().map(Vec::len).sum::<usize>();
        let keys: usize = index
            .words
            .keys()
            .map(|word| word.len() + 48)
            .sum::<usize>()
            + index.grams.len() * 40;
        std::println!(
            "build {build:?}; text {} KiB; postings {} KiB; keys about {} KiB; grams {}; words {}",
            index.text.len() / 1_024,
            postings * 4 / 1_024,
            keys / 1_024,
            index.grams.len(),
            index.words.len(),
        );
        for query in [
            "restaurant",
            "resturant",
            "dinner tomorrow",
            "st",
            "station4711",
            "東京",
        ] {
            let started = std::time::Instant::now();
            let count = index
                .candidates(
                    &fold(query),
                    &SearchOptions::default(),
                    SEARCH_RESULTS_MAX * 2,
                )
                .len();
            std::println!("{query:?}: {count} candidates in {:?}", started.elapsed());
        }
    }
}
