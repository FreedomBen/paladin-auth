// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clipboard auto-clear pure-logic glue for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md`
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

use std::time::Instant;

use zeroize::Zeroizing;

use paladin_core::{ClipboardClearPolicy, ClipboardClearToken, VaultSettings};

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
