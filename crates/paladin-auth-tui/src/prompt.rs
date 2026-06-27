// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared zeroizing passphrase-input buffer.
//!
//! Holds typed characters in a `zeroize::Zeroizing<String>` so the
//! bytes are wiped on drop. Per `docs/IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6)": "All passphrase-entry fields (unlock, encrypted
//! Paladin Auth import, encrypted export, passphrase set/change) ... keep
//! typed bytes in zeroizing buffers, convert to `secrecy::SecretString`
//! only for core calls, and zeroize on submit, cancel, modal close,
//! and auto-lock."
//!
//! This module is the data half of the eventual passphrase-input
//! widget; rendering (cursor, mask glyph, focus styling) is added
//! later alongside the unlock / modal UI slices.

use std::fmt;

use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

/// Zeroizing buffer for typed passphrase characters.
///
/// The `Debug` implementation redacts the typed bytes — and even their
/// length — so logs, panic messages, and reducer-state dumps never
/// leak passphrase material (per `CLAUDE.md` "No `Debug` impls that
/// leak bytes").
#[derive(Default)]
pub struct PassphraseBuffer {
    inner: Zeroizing<String>,
}

impl PassphraseBuffer {
    /// Create an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one character to the buffer.
    pub fn push(&mut self, c: char) {
        self.inner.push(c);
    }

    /// Remove and return the last character, if any.
    pub fn pop(&mut self) -> Option<char> {
        self.inner.pop()
    }

    /// Zero out the buffer's bytes and set its length to zero.
    pub fn clear(&mut self) {
        self.inner.zeroize();
    }

    /// True when no characters are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Borrow the buffered bytes as a `&str` for rendering or
    /// comparison in tests. Callers must not log or persist the result.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Move the buffered bytes into a `SecretString` for a core call
    /// and clear the buffer in place.
    ///
    /// The returned `SecretString` zeros its bytes on drop.
    pub fn take(&mut self) -> SecretString {
        let owned: String = self.inner.as_str().to_owned();
        self.inner.zeroize();
        SecretString::from(owned)
    }
}

impl fmt::Debug for PassphraseBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PassphraseBuffer(<redacted>)")
    }
}
