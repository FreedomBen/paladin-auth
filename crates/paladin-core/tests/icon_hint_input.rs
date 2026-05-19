// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase K coverage — `IconHintInput` tri-state behavior through
// `validate_manual` at the public surface (DESIGN.md §4.1 / §4.7).
//
// Internal unit tests cover `IconHintInput::resolve` in isolation;
// this file pins the end-to-end contract a TUI / GUI manual-add
// modal exercises: `Default` derives a slug from the issuer,
// `Clear` suppresses any issuer-derived slug, and `Slug(...)`
// overrides the issuer-derived default.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput};
use secrecy::SecretString;

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn input(issuer: Option<&str>, icon_hint: IconHintInput) -> AccountInput {
    AccountInput {
        label: "alice".to_string(),
        issuer: issuer.map(String::from),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: Some(30),
        counter: None,
        icon_hint,
    }
}

#[test]
fn icon_hint_default_with_issuer_derives_lowercase_slug() {
    let validated = validate_manual(input(Some("GitHub"), IconHintInput::Default), import_time())
        .expect("valid input");
    assert_eq!(validated.account.icon_hint(), Some("github"));
}

#[test]
fn icon_hint_default_with_no_issuer_is_none() {
    let validated =
        validate_manual(input(None, IconHintInput::Default), import_time()).expect("valid input");
    assert_eq!(validated.account.icon_hint(), None);
}

#[test]
fn icon_hint_clear_suppresses_issuer_default() {
    // §4.1: `Clear` is the explicit user-override that wins over the
    // issuer-derived default — the modal "no icon" choice must not
    // be silently overridden when an issuer is present.
    let validated = validate_manual(input(Some("GitHub"), IconHintInput::Clear), import_time())
        .expect("valid input");
    assert_eq!(validated.account.icon_hint(), None);
}

#[test]
fn icon_hint_slug_overrides_issuer_default() {
    let validated = validate_manual(
        input(
            Some("GitHub"),
            IconHintInput::Slug("custom-icon".to_string()),
        ),
        import_time(),
    )
    .expect("valid input");
    assert_eq!(validated.account.icon_hint(), Some("custom-icon"));
}

#[test]
fn icon_hint_slug_rejects_invalid_grammar_with_icon_hint_field() {
    let err = validate_manual(
        input(None, IconHintInput::Slug("Has Spaces!".to_string())),
        import_time(),
    )
    .expect_err("invalid slug");
    let s = format!("{err}");
    assert!(s.contains("icon_hint"), "want field 'icon_hint' in {s}");
}
