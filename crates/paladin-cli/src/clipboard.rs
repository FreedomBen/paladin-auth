// SPDX-License-Identifier: AGPL-3.0-or-later

//! CLI clipboard adapter for `paladin copy`. Production calls
//! [`arboard`]; under the `paladin-cli/test-hooks` cargo feature an
//! env-var-driven dryrun short-circuit lets process-level integration
//! tests exercise `paladin copy` end-to-end without a system clipboard
//! server. See `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Clipboard copy side
//! effects" and the test-hooks bullet.
//!
//! The CLI is stateless per docs/DESIGN.md §8 — this adapter does **not**
//! schedule a wipe / auto-clear regardless of `clipboard.clear_enabled`
//! in vault settings. That preference is stored for the TUI / GUI and
//! ignored at runtime by the CLI.

use paladin_core::AccountSummary;

use crate::output::error::CliError;

/// Attempt to write `code` to the system clipboard. On any backend
/// error, returns [`CliError::ClipboardWriteFailed`] carrying the
/// supplied `account` (which already reflects persisted post-advance
/// state for HOTP) and `counter_used` (the pre-advance counter for
/// HOTP, `None` for TOTP) — matching the §5 wire shape.
///
/// The CLI never schedules an auto-clear; the call returns as soon as
/// the backend confirms the write.
pub fn copy(
    code: &str,
    account: AccountSummary,
    counter_used: Option<u64>,
) -> Result<(), CliError> {
    if backend_set_text(code).is_err() {
        return Err(CliError::ClipboardWriteFailed {
            account,
            counter_used,
        });
    }
    Ok(())
}

/// Production backend: real arboard call. Any backend error collapses
/// to `Err(())` because the CLI's failure envelope already carries the
/// account context — the underlying arboard error string is not part
/// of the §5 wire schema.
#[cfg(not(feature = "test-hooks"))]
fn backend_set_text(payload: &str) -> Result<(), ()> {
    arboard::Clipboard::new()
        .and_then(|mut cb| cb.set_text(payload.to_string()))
        .map_err(|_| ())
}

/// Test-build backend (gated on `paladin-cli/test-hooks`): honors
/// `PALADIN_CLIPBOARD_DRYRUN` so process-level tests can exercise
/// `paladin copy` without a clipboard server.
///
/// - `PALADIN_CLIPBOARD_DRYRUN=1` → bypass arboard, return `Ok(())`.
/// - `PALADIN_CLIPBOARD_DRYRUN=fail` → bypass arboard, return `Err(())`
///   so the test can assert the `clipboard_write_failed` envelope.
/// - any other value (or unset) → fall through to the real arboard
///   backend.
#[cfg(feature = "test-hooks")]
fn backend_set_text(payload: &str) -> Result<(), ()> {
    use std::ffi::OsStr;
    if let Some(v) = std::env::var_os("PALADIN_CLIPBOARD_DRYRUN") {
        if v == OsStr::new("1") {
            return Ok(());
        }
        if v == OsStr::new("fail") {
            return Err(());
        }
    }
    arboard::Clipboard::new()
        .and_then(|mut cb| cb.set_text(payload.to_string()))
        .map_err(|_| ())
}
