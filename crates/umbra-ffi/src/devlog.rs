//! Lines of the run for the developer, in a debug build alone. The app of
//! a debug build drains them into the log of the platform. A release build
//! keeps no line, thus no fact of the run leaves by this path.
//!
//! A line names a step, a tag, or an error kind. It never holds a key, a
//! plaintext, an address, or an identifier of a contact.

#[cfg(debug_assertions)]
use std::{collections::VecDeque, sync::Mutex};

/// The most lines that wait for the app; the oldest one goes first.
#[cfg(debug_assertions)]
const MAX_LINES: usize = 500;

#[cfg(debug_assertions)]
static LINES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Keeps one line, in a debug build.
#[cfg(debug_assertions)]
pub fn line(text: impl Into<String>) {
    let mut lines = LINES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if lines.len() >= MAX_LINES {
        lines.pop_front();
    }
    lines.push_back(text.into());
}

/// Keeps no line in a release build.
#[cfg(not(debug_assertions))]
pub fn line(_text: impl Into<String>) {}

/// Each line that waits, in its order. A release build gives none.
pub fn take() -> Vec<String> {
    #[cfg(debug_assertions)]
    {
        let mut lines = LINES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lines.drain(..).collect()
    }
    #[cfg(not(debug_assertions))]
    {
        Vec::new()
    }
}
