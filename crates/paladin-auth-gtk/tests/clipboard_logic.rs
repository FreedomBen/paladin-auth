// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic tests for [`paladin_auth_gtk::clipboard`].
//!
//! The GDK boundary itself (`gdk::Clipboard::set_text` /
//! `read_text_async`) needs a live `gdk::Display` and is exercised by
//! the `xvfb-run` smoke test alongside the rest of the GUI bootstrap.
//! The byte-encoding helpers between
//! [`paladin_auth_core::ClipboardClearPolicy`] (which speaks bytes) and the
//! GDK text APIs (which speak UTF-8 strings) are pure logic and live
//! here.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/clipboard_logic.rs`"
//! checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * [`payload_text`] returns the OTP-code bytes unchanged for the
//!   ASCII-only case and falls back to UTF-8 lossy substitution for
//!   defensive non-UTF-8 inputs.
//! * [`captured_clipboard_bytes`] wraps the
//!   `Option<&str>` projection of `read_text_async`'s result in a
//!   [`Zeroizing<Vec<u8>>`] so the captured comparison value zeroes
//!   on drop, with `None` and `Some("")` both collapsing to an empty
//!   buffer so the only-if-unchanged check in
//!   [`paladin_auth_gtk::clipboard_clear::evaluate_wake`] resolves to
//!   `Mismatch` in those cases.

use zeroize::Zeroizing;

use paladin_auth_gtk::clipboard::{captured_clipboard_bytes, payload_text};

#[test]
fn payload_text_passes_ascii_otp_code_unchanged() {
    // OTP codes are always ASCII digits, so the conversion is the
    // borrowed-`&str` case and no allocation is taken.
    let bytes = b"123456";
    let text = payload_text(bytes);
    assert_eq!(text.as_ref(), "123456");
    assert!(
        matches!(text, std::borrow::Cow::Borrowed(_)),
        "ASCII OTP code must avoid the allocating lossy path"
    );
}

#[test]
fn payload_text_handles_empty_bytes() {
    let text = payload_text(b"");
    assert_eq!(text.as_ref(), "");
}

#[test]
fn payload_text_replaces_invalid_utf8_with_replacement_char() {
    // 0xff is not a valid start byte for any UTF-8 sequence, so
    // `from_utf8_lossy` substitutes U+FFFD and the result is still a
    // well-formed `&str` suitable for `gdk::Clipboard::set_text`.
    let bytes = &[0xffu8, b'1', b'2'];
    let text = payload_text(bytes);
    assert!(
        text.contains('\u{FFFD}'),
        "invalid UTF-8 must surface as the replacement character"
    );
    assert!(text.ends_with("12"));
}

#[test]
fn captured_clipboard_bytes_returns_empty_for_none() {
    // No clipboard text (read failure, empty clipboard, or
    // non-text MIME type) collapses to an empty buffer; this
    // guarantees `evaluate_wake` returns `Mismatch` because the
    // pending entry's captured `value` is non-empty by construction.
    let captured = captured_clipboard_bytes(None);
    assert!(captured.is_empty());
}

#[test]
fn captured_clipboard_bytes_returns_empty_for_empty_string() {
    // Symmetric with the `None` case: a clipboard read that yielded
    // an empty `GString` must not be treated as "still the captured
    // code" — the captured pending bytes are non-empty so byte
    // equality fails.
    let captured = captured_clipboard_bytes(Some(""));
    assert!(captured.is_empty());
}

#[test]
fn captured_clipboard_bytes_carries_utf8_payload() {
    let captured = captured_clipboard_bytes(Some("654321"));
    assert_eq!(&captured[..], b"654321");
}

#[test]
fn captured_clipboard_bytes_is_zeroizing_typed() {
    // Structural assertion: the captured bytes are wrapped in
    // `Zeroizing<Vec<u8>>` so dropping the buffer wipes the payload
    // in place. The function signature pins this — if it ever loses
    // the `Zeroizing` wrapper this test fails to type-check.
    let captured: Zeroizing<Vec<u8>> = captured_clipboard_bytes(Some("abc"));
    assert_eq!(&captured[..], b"abc");
}
