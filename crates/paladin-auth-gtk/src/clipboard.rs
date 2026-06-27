// SPDX-License-Identifier: AGPL-3.0-or-later

//! GDK clipboard glue for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Auto-lock and clipboard
//! auto-clear (per §7)" and the §"Milestone 7 checklist" bullet
//! "Wire `gdk::Clipboard.read_text` / `set_text` for the copy and
//! clear paths inside `clipboard.rs`", the GUI owns the
//! [`gdk::Clipboard`] reads / writes and the timer plumbing while
//! every policy decision routes through
//! [`paladin_auth_core::ClipboardClearPolicy`] (via the pure-logic
//! [`crate::clipboard_clear`] module):
//!
//! * Opt-in gate and monotonic token issuance live on
//!   [`paladin_auth_core::ClipboardClearPolicy::schedule`] (re-exported by
//!   [`crate::clipboard_clear::schedule_copy`]).
//! * The only-if-unchanged byte-equality decision lives on
//!   [`paladin_auth_core::ClipboardClearPolicy::should_clear`] (re-exported
//!   by [`crate::clipboard_clear::evaluate_wake`]).
//! * The captured payload zeroes on drop via the
//!   [`Zeroizing<Vec<u8>>`] field on
//!   [`crate::clipboard_clear::PendingClipboardClear`].
//!
//! This module is the only place in `paladin-auth-gtk` that touches the
//! GDK clipboard surface; centralizing the `set_text` / `read_text`
//! calls here keeps the `gtk::gdk` boundary auditable and lets the
//! widget-bound wrappers stay free of policy decisions.
//!
//! Clipboard auto-clear is **mode-agnostic** — it fires for both
//! plaintext and encrypted vaults (only auto-lock is plaintext-no-op,
//! and that rule lives in [`paladin_auth_core::policy::auto_lock::IdlePolicy`]).
//!
//! The byte-encoding helpers ([`payload_text`] /
//! [`captured_clipboard_bytes`]) are display-server-free and are
//! exercised by `tests/clipboard_logic.rs`. The widget-bound
//! wrappers ([`write_payload`] / [`clear`] / [`read_text_async`])
//! need a live `gdk::Display` and are exercised by `tests/gtk_smoke.rs`
//! alongside the rest of the GUI bootstrap.

use std::borrow::Cow;

use relm4::gtk::gdk;
use relm4::gtk::gio;
use zeroize::Zeroizing;

/// Encode clipboard payload bytes as text for [`gdk::Clipboard::set_text`].
///
/// OTP codes are always ASCII digits (TOTP: `Vault::totp_code`; HOTP:
/// the open [`crate::hotp_reveal::RevealWindow`]'s `code` field), so
/// the conversion is the borrowed-`&str` case in practice — pinned by
/// `payload_text_passes_ascii_otp_code_unchanged` in
/// `tests/clipboard_logic.rs`. UTF-8-lossy substitution is the
/// defensive fallback for an invariant violation rather than a
/// routine path.
#[must_use]
pub fn payload_text(bytes: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

/// Pack the result of a [`gdk::Clipboard::read_text_async`] into the
/// [`Zeroizing<Vec<u8>>`] buffer the
/// [`paladin_auth_core::ClipboardClearPolicy::should_clear`] byte-equality
/// check expects.
///
/// * `None` (no clipboard text, read failure, or empty clipboard) →
///   empty buffer. The pending-clear `value` is non-empty when an
///   OTP code has been captured, so an empty current buffer
///   guarantees the [`crate::clipboard_clear::WakeDecision::Mismatch`]
///   outcome in [`crate::clipboard_clear::evaluate_wake`] — the
///   wipe stays its hand instead of clobbering whatever (or
///   nothing) the user has on the clipboard.
/// * `Some(text)` → the text's UTF-8 bytes copied into a fresh
///   `Zeroizing<Vec<u8>>` so the captured comparison value zeroes on
///   drop.
#[must_use]
pub fn captured_clipboard_bytes(text: Option<&str>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(text.map(|s| s.as_bytes().to_vec()).unwrap_or_default())
}

/// Write `bytes` to `clipboard` via [`gdk::Clipboard::set_text`].
///
/// Marks the GDK copy of the OTP payload as the live clipboard text.
/// The captured [`Zeroizing<Vec<u8>>`] the caller hands to
/// [`crate::clipboard_clear::schedule_copy`] is the auto-clear
/// policy's own copy; the GDK-side bytes are wiped via [`clear`]
/// on a [`crate::clipboard_clear::WakeDecision::Clear`] wake
/// outcome.
pub fn write_payload(clipboard: &gdk::Clipboard, bytes: &[u8]) {
    clipboard.set_text(&payload_text(bytes));
}

/// Wipe `clipboard` by writing an empty string via
/// [`gdk::Clipboard::set_text`].
///
/// Called from the `ClipboardWakeRead → Clear` branch in
/// `AppModel::update` after
/// [`crate::clipboard_clear::evaluate_wake`] confirms the
/// only-if-unchanged byte-equality. The corresponding
/// [`crate::clipboard_clear::PendingClipboardClear`] is dropped in
/// lockstep, zeroizing its captured `Zeroizing<Vec<u8>>` payload.
pub fn clear(clipboard: &gdk::Clipboard) {
    clipboard.set_text("");
}

/// Issue an asynchronous read against `clipboard` and route the
/// captured bytes through `callback`.
///
/// Wraps [`gdk::Clipboard::read_text_async`] so the only place that
/// has to spell out the [`gio::Cancellable`] type parameter and the
/// `Result<Option<GString>, glib::Error>` → [`Zeroizing<Vec<u8>>`]
/// conversion is this module. The callback receives a
/// [`Zeroizing<Vec<u8>>`] buffer suitable for
/// [`paladin_auth_core::ClipboardClearPolicy::should_clear`] /
/// [`crate::clipboard_clear::evaluate_wake`]:
///
/// * Read failures and an empty clipboard both collapse to an empty
///   buffer (via [`captured_clipboard_bytes`]) so the wake guarantees
///   the [`crate::clipboard_clear::WakeDecision::Mismatch`] decision
///   — the captured pending bytes are non-empty by construction.
/// * On a successful read with non-empty text, the UTF-8 bytes flow
///   through to the callback inside a fresh `Zeroizing` wrapper so
///   the post-comparison drop wipes the buffer in place.
pub fn read_text_async<F>(clipboard: &gdk::Clipboard, callback: F)
where
    F: FnOnce(Zeroizing<Vec<u8>>) + 'static,
{
    clipboard.read_text_async(None::<&gio::Cancellable>, move |result| {
        let bytes = match result {
            Ok(Some(text)) => captured_clipboard_bytes(Some(text.as_str())),
            Ok(None) | Err(_) => captured_clipboard_bytes(None),
        };
        callback(bytes);
    });
}
