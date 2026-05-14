// SPDX-License-Identifier: AGPL-3.0-or-later

//! TUI clipboard adapter — the only impure boundary between
//! [`crate::app::effect`] and the OS clipboard.
//!
//! Production calls [`arboard`]; under the `paladin-tui/test-hooks`
//! cargo feature an env-var-driven dryrun short-circuit lets reducer /
//! effect tests exercise the copy → schedule → only-if-unchanged
//! auto-clear flows end-to-end without a system clipboard server. The
//! pattern mirrors [`paladin-cli`'s `clipboard`
//! adapter](../../../paladin-cli/src/clipboard.rs) so the two
//! front-ends share the same DRYRUN contract — see
//! `IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear" and the
//! `test-hooks` feature comment in `Cargo.toml`.
//!
//! All error paths collapse to `Err(())` because the underlying
//! `arboard` error strings are not part of the §6 status-line wire
//! shape (the front-end surfaces `clipboard_write_failed`
//! unconditionally on write failure).

/// Read the current clipboard contents.
///
/// In production (`#[cfg(not(feature = "test-hooks"))]`) this calls
/// [`arboard::Clipboard::get_text`]. Errors collapse to `Err(())`.
#[cfg(not(feature = "test-hooks"))]
#[allow(clippy::result_unit_err)]
pub fn read_text() -> Result<String, ()> {
    arboard::Clipboard::new()
        .and_then(|mut cb| cb.get_text())
        .map_err(|_| ())
}

/// Write `text` to the system clipboard.
///
/// In production (`#[cfg(not(feature = "test-hooks"))]`) this calls
/// [`arboard::Clipboard::set_text`]. Errors collapse to `Err(())`.
#[cfg(not(feature = "test-hooks"))]
#[allow(clippy::result_unit_err)]
pub fn write_text(text: &str) -> Result<(), ()> {
    arboard::Clipboard::new()
        .and_then(|mut cb| cb.set_text(text.to_string()))
        .map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Test-build backend (gated on `paladin-tui/test-hooks`).
//
// Honors `PALADIN_CLIPBOARD_DRYRUN` so reducer / effect tests can
// exercise copy → schedule → only-if-unchanged auto-clear without a
// system clipboard server:
//
//   * `PALADIN_CLIPBOARD_DRYRUN=1` → bypass arboard, route reads and
//     writes through an in-process fake addressable through
//     [`seed_test_clipboard`] / [`read_test_clipboard`].
//   * `PALADIN_CLIPBOARD_DRYRUN=fail` → bypass arboard, return
//     `Err(())` for both `read_text` and `write_text` so the
//     `clipboard_write_failed` / read-failure branches stay covered.
//   * any other value (or unset) → fall through to the real arboard
//     backend.
//
// The in-process fake lives in a process-global `Mutex<String>` so
// every adapter call sees the same state regardless of which thread
// it runs on. A second mutex ([`test_clipboard_lock`]) serializes
// test functions that touch the env var, since `std::env::set_var`
// is process-wide and the `cargo test` binary runs tests in
// parallel by default.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-hooks")]
use std::sync::{Mutex, MutexGuard};

#[cfg(feature = "test-hooks")]
static FAKE: Mutex<String> = Mutex::new(String::new());

#[cfg(feature = "test-hooks")]
static TEST_GUARD: Mutex<()> = Mutex::new(());

/// Acquire the process-wide test-clipboard lock. Holding this guard
/// serializes any test that touches `PALADIN_CLIPBOARD_DRYRUN` or the
/// in-process fake clipboard so the env-var manipulation does not
/// race with parallel-running tests.
///
/// Available only under `cfg(feature = "test-hooks")`.
#[cfg(feature = "test-hooks")]
pub fn test_clipboard_lock() -> MutexGuard<'static, ()> {
    // `PoisonError::into_inner` lets a test continue after a peer
    // test panicked mid-section — the panic is already surfaced by
    // the test runner, and re-poisoning here would just mask the
    // failure of the still-running test.
    TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Seed the in-process fake clipboard with `text`. The next
/// `PALADIN_CLIPBOARD_DRYRUN=1`-gated [`read_text`] call returns
/// exactly these bytes.
///
/// Available only under `cfg(feature = "test-hooks")`.
#[cfg(feature = "test-hooks")]
pub fn seed_test_clipboard(text: impl Into<String>) {
    *FAKE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = text.into();
}

/// Read the current in-process fake clipboard contents. Mirrors what
/// a `PALADIN_CLIPBOARD_DRYRUN=1`-gated [`read_text`] would return.
///
/// Available only under `cfg(feature = "test-hooks")`.
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn read_test_clipboard() -> String {
    FAKE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Read the current clipboard contents.
///
/// Test-hooks build: honors `PALADIN_CLIPBOARD_DRYRUN` —
/// `=1` routes to the in-process fake (returning the bytes set by
/// [`seed_test_clipboard`] / written by the gated [`write_text`]),
/// `=fail` returns `Err(())`, any other value (or unset) falls
/// through to the real `arboard` backend. Errors collapse to
/// `Err(())` for parity with the production signature.
#[cfg(feature = "test-hooks")]
#[allow(clippy::result_unit_err)]
pub fn read_text() -> Result<String, ()> {
    use std::ffi::OsStr;
    if let Some(v) = std::env::var_os("PALADIN_CLIPBOARD_DRYRUN") {
        if v == OsStr::new("1") {
            return Ok(FAKE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone());
        }
        if v == OsStr::new("fail") {
            return Err(());
        }
    }
    arboard::Clipboard::new()
        .and_then(|mut cb| cb.get_text())
        .map_err(|_| ())
}

/// Write `text` to the system clipboard.
///
/// Test-hooks build: honors `PALADIN_CLIPBOARD_DRYRUN` —
/// `=1` routes to the in-process fake so the bytes are observable
/// through [`read_test_clipboard`], `=fail` returns `Err(())`,
/// any other value (or unset) falls through to the real `arboard`
/// backend. Errors collapse to `Err(())` for parity with the
/// production signature.
#[cfg(feature = "test-hooks")]
#[allow(clippy::result_unit_err)]
pub fn write_text(text: &str) -> Result<(), ()> {
    use std::ffi::OsStr;
    if let Some(v) = std::env::var_os("PALADIN_CLIPBOARD_DRYRUN") {
        if v == OsStr::new("1") {
            *FAKE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = text.to_string();
            return Ok(());
        }
        if v == OsStr::new("fail") {
            return Err(());
        }
    }
    arboard::Clipboard::new()
        .and_then(|mut cb| cb.set_text(text.to_string()))
        .map_err(|_| ())
}
