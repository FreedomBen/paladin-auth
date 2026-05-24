// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clipboard auto-clear pure-logic glue for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
//! §"Auto-lock and clipboard auto-clear (per §7)", the GUI owns the
//! [`gdk::Clipboard`][gdk_clipboard] reads / writes and the timer
//! plumbing, but every policy decision routes through
//! [`paladin_core::ClipboardClearPolicy`]:
//!
//! * `schedule` at copy time (returns `None` when the user has not
//!   opted in).
//! * `should_clear` on wake against the current clipboard text
//!   (only-if-unchanged).
//!
//! Per the §"Tests > Pure-logic unit tests > `tests/clipboard_clear_logic.rs`"
//! checklist, stale tokens are dropped first by the policy and the
//! pending copied value is zeroized after a clear attempt or stale-
//! token supersession via the [`Zeroizing`] wrapper around the
//! captured byte buffer.
//!
//! Clipboard auto-clear is **mode-agnostic** — it fires for both
//! plaintext and encrypted vaults (only auto-lock is plaintext-no-op,
//! and that rule lives in [`paladin_core::IdlePolicy`]).
//!
//! [gdk_clipboard]: https://gtk-rs.org/gtk4-rs/git/docs/gdk4/struct.Clipboard.html

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::time::{Instant, SystemTime};

use zeroize::Zeroizing;

use paladin_core::{
    AccountId, AccountKindSummary, ClipboardClearPolicy, ClipboardClearToken, Vault, VaultSettings,
};

use crate::hotp_reveal::RevealWindow;

/// Pending wipe-after-copy entry carried on the GUI's model state.
///
/// Mirrors the TUI's `PendingClipboardClear` so both front ends share
/// the same shape. The captured `value` is wrapped in [`Zeroizing`]
/// so dropping the struct zeroes the bytes in place — required by
/// the §"Tests" bullet *"Pending copied value is zeroized after a
/// clear attempt or stale-token drop"*.
pub struct PendingClipboardClear {
    /// Monotonic token returned by [`ClipboardClearPolicy::schedule`].
    /// A later schedule on the same vault settings supersedes this
    /// one and the older [`PendingClipboardClear`] is dropped,
    /// zeroizing its captured bytes.
    pub token: ClipboardClearToken,
    /// The bytes the copy effect wrote to the clipboard. Compared
    /// byte-equal against the current clipboard contents when the
    /// wake fires; only-if-unchanged. Wrapped in [`Zeroizing`] so
    /// the bytes are wiped on drop.
    pub value: Zeroizing<Vec<u8>>,
    /// Monotonic wake-deadline; the timer thread sleeps until this
    /// instant and then fires the `ClipboardClearWake` message.
    pub deadline: Instant,
}

impl PendingClipboardClear {
    /// Construct a pending wipe entry from a freshly issued
    /// `(token, deadline)` pair and the captured clipboard bytes.
    ///
    /// Public so callers (and tests) can build the struct from the
    /// individual pieces; prefer [`schedule_copy`] for the normal
    /// "user copied a code" path because it routes through the
    /// policy and respects the opt-in / disabled gate.
    #[must_use]
    pub fn new(token: ClipboardClearToken, value: Zeroizing<Vec<u8>>, deadline: Instant) -> Self {
        Self {
            token,
            value,
            deadline,
        }
    }
}

/// Schedule a clipboard wipe-after-copy for the captured `value`.
///
/// Routes through
/// [`ClipboardClearPolicy::schedule`][paladin_core::ClipboardClearPolicy::schedule].
/// Returns `Some(pending)` when the user has opted in via
/// [`VaultSettings::clipboard_clear_enabled`], `None` otherwise. The
/// policy advances a process-wide monotonic token counter only on a
/// `Some` return, so token issuance stays strictly contiguous across
/// enable / disable transitions.
///
/// The caller is expected to:
/// 1. Drop any previous [`PendingClipboardClear`] (the [`Zeroizing`]
///    wrapper zeroes the older captured bytes via `Drop`).
/// 2. Schedule a wake via `glib::timeout_add_local` at the returned
///    `deadline`.
#[must_use]
pub fn schedule_copy(
    now: Instant,
    settings: &VaultSettings,
    value: Zeroizing<Vec<u8>>,
) -> Option<PendingClipboardClear> {
    let (token, deadline) = ClipboardClearPolicy::schedule(now, settings)?;
    Some(PendingClipboardClear::new(token, value, deadline))
}

/// Outcome of a clipboard auto-clear wake event.
///
/// The wake adapter consumes this decision to decide whether to call
/// `gdk::Clipboard::set_text("")` or leave the clipboard alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeDecision {
    /// The wake's token is stale (an older entry, superseded by a
    /// fresher `schedule_copy`). The wake is a no-op; the *current*
    /// pending entry stays in place. The stale wake itself was
    /// dropped first by the policy gate — `should_clear` is never
    /// consulted.
    Stale,
    /// The clipboard contents differ from the captured bytes — the
    /// user copied something else in the interim. The wipe stays
    /// its hand and the caller drops the pending entry (zeroizing
    /// the captured bytes via [`Zeroizing`]).
    Mismatch,
    /// The clipboard still byte-equals the captured bytes. The
    /// caller writes empty text and drops the pending entry
    /// (zeroizing the captured bytes via [`Zeroizing`]).
    Clear,
}

/// Decide what to do on a clipboard auto-clear wake.
///
/// Gates on the token first: a stale wake (different from the
/// current pending's token) returns [`WakeDecision::Stale`] without
/// consulting [`ClipboardClearPolicy::should_clear`]. When the wake
/// token matches, the byte-equality decision routes through
/// [`ClipboardClearPolicy::should_clear`] against `current_clipboard`.
///
/// The pure-logic helper does **not** drop `pending` — the caller
/// owns the model state and is responsible for the move/drop that
/// triggers the [`Zeroizing`] wipe.
#[must_use]
pub fn evaluate_wake(
    pending: &PendingClipboardClear,
    event_token: ClipboardClearToken,
    current_clipboard: &[u8],
) -> WakeDecision {
    if pending.token != event_token {
        return WakeDecision::Stale;
    }
    if ClipboardClearPolicy::should_clear(&pending.value, current_clipboard) {
        WakeDecision::Clear
    } else {
        WakeDecision::Mismatch
    }
}

/// Resolve the clipboard payload for a row-level copy request.
///
/// Returns the bytes the widget layer should write through
/// `gdk::Clipboard::set_text` wrapped in [`Zeroizing`] so the capture
/// wipes on drop. The lookup mirrors the row-display projection rules
/// in [`crate::account_row::code_display`] / [`copy_enabled`]:
///
/// * TOTP rows always produce bytes — the helper re-derives the code
///   via [`Vault::totp_code`] against `wall_clock` so the value
///   stays in lockstep with the visible row label.
/// * HOTP rows produce bytes iff `reveal_windows` carries an open
///   [`RevealWindow`] for `id`. The reveal window is the only source
///   of truth for an HOTP code; the helper never re-reads
///   `Vault::hotp_peek` so a click outside the reveal window cannot
///   leak a code the user has not requested.
/// * Returns [`None`] for an `id` that no longer appears in
///   `vault.summaries()` (raced removal), for an HOTP row without an
///   open reveal, and for any TOTP `Vault::totp_code` failure.
///
/// The function is `(GTK, gdk::Clipboard)`-free so the routing rules
/// are exercised by `tests/clipboard_clear_logic.rs` without a
/// display server. The caller is expected to:
///
/// 1. Write the returned bytes through `gdk::Clipboard::set_text`.
/// 2. Hand them to [`schedule_copy`] so the auto-clear policy can
///    arm against the captured value.
#[must_use]
pub fn prepare_copy_bytes<S: BuildHasher>(
    vault: &Vault,
    reveal_windows: &HashMap<AccountId, RevealWindow, S>,
    id: AccountId,
    wall_clock: SystemTime,
) -> Option<Zeroizing<Vec<u8>>> {
    let summary = vault.summaries().find(|s| s.id == id)?;
    match summary.kind {
        AccountKindSummary::Totp => {
            let code = vault.totp_code(id, wall_clock).ok()?;
            Some(Zeroizing::new(code.code.into_bytes()))
        }
        AccountKindSummary::Hotp => {
            let window = reveal_windows.get(&id)?;
            Some(Zeroizing::new(window.code.as_bytes().to_vec()))
        }
    }
}

/// Format the toast body raised on the `adw::ToastOverlay` after a
/// successful row-level copy.
///
/// The toast confirms the write actually happened (the only feedback
/// channel for a fast clipboard interaction) and, when the user has
/// opted into clipboard auto-clear via
/// [`VaultSettings::clipboard_clear_enabled`], folds the configured
/// clear deadline into the same message so the security-relevant
/// "the code is on the clipboard *and* it will clear in N seconds"
/// state is visible in one surface.
///
/// Pure-logic so the strings are exercised by
/// `tests/clipboard_clear_logic.rs` without a display server.
#[must_use]
pub fn format_copy_toast(settings: &VaultSettings) -> String {
    if settings.clipboard_clear_enabled() {
        format!(
            "Code copied — clears in {}s",
            settings.clipboard_clear_secs()
        )
    } else {
        "Code copied".to_string()
    }
}

/// Resolve the upcoming TOTP code for the row identified by `id`
/// and return its digits wrapped in a [`Zeroizing`] buffer ready
/// for the `gdk::Clipboard::set_text` / [`schedule_copy`] pipeline.
///
/// Mirrors [`prepare_copy_bytes`] but reads
/// [`Vault::totp_next_code`] instead of [`Vault::totp_code`].
/// HOTP rows / unknown ids / pre-Unix-epoch clocks all collapse to
/// `None`; the caller in `AppModel` treats `None` as "silently
/// drop" exactly like the current-code copy path so a stray
/// click through the `win.copy-next-code` action group on a HOTP
/// selection is a benign no-op.
#[must_use]
pub fn prepare_copy_next_code_bytes(
    vault: &Vault,
    id: AccountId,
    wall_clock: SystemTime,
) -> Option<Zeroizing<Vec<u8>>> {
    let code = vault.totp_next_code(id, wall_clock).ok()?;
    Some(Zeroizing::new(code.code.into_bytes()))
}

/// Format the `adw::Toast` body raised after a successful Next
/// code copy.
///
/// Pinned wording: `Next code copied, valid in {seconds_until_valid}s`.
/// Duplicated against `paladin_tui::app::state::format_next_code_copied`
/// because the two binary crates can't depend on each other and
/// `paladin-core` shouldn't grow a text helper for a single
/// wording.  The two strings are pinned in tests so a drift
/// between the GTK and the TUI surfaces as a failing assertion
/// rather than as an inconsistent UX.
///
/// `seconds_until_valid` is the count of seconds remaining in the
/// *current* TOTP window — once that window flips, the digits in
/// the user's clipboard become the new "current" code.  Always in
/// the inclusive range `1..=period` because the toast is raised
/// after a successful copy that itself sampled the same `now`.
#[must_use]
pub fn format_next_code_copy_toast(seconds_until_valid: u32) -> String {
    format!("Next code copied, valid in {seconds_until_valid}s")
}
