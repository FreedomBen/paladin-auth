// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase K coverage — `validate_label` at the public surface
// (docs/DESIGN.md §4.1 / §4.7).
//
// `validate_label` is re-exported from `paladin_auth_core` so the TUI /
// GUI Rename modal can pre-validate user input before emitting a
// save effect (the post-emission `Vault::rename` re-validates
// idempotently). Internal-scope coverage lives next to the function;
// these tests pin the contract at the boundary external crates see.

use paladin_auth_core::{validate_label, ErrorKind};

#[test]
fn validate_label_trims_ascii_whitespace_and_returns_owned_string() {
    let s = validate_label("  alice  ").expect("non-empty trim");
    assert_eq!(s, "alice");
}

#[test]
fn validate_label_trims_unicode_whitespace() {
    // U+3000 (ideographic space) is matched by `str::trim`.
    let s = validate_label("\u{3000}bob\u{3000}").expect("unicode trim");
    assert_eq!(s, "bob");
}

#[test]
fn validate_label_preserves_interior_whitespace() {
    let s = validate_label("alice  in wonderland").expect("interior ws");
    assert_eq!(s, "alice  in wonderland");
}

#[test]
fn validate_label_rejects_empty_input() {
    let err = validate_label("").expect_err("empty");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let s = format!("{err}");
    assert!(s.contains("label"), "want field 'label' in {s}");
    assert!(s.contains("empty"), "want reason 'empty' in {s}");
}

#[test]
fn validate_label_rejects_whitespace_only_input() {
    let err = validate_label("   \t \n").expect_err("ws-only");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    assert!(format!("{err}").contains("empty"));
}

#[test]
fn validate_label_accepts_128_byte_boundary_and_rejects_129() {
    let ok = "a".repeat(128);
    let s = validate_label(&ok).expect("128 bytes ok");
    assert_eq!(s.len(), 128);

    let too_long = "a".repeat(129);
    let err = validate_label(&too_long).expect_err("129 bytes too long");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let s = format!("{err}");
    assert!(s.contains("label"), "want field 'label' in {s}");
    assert!(s.contains("too_long"), "want reason 'too_long' in {s}");
}
