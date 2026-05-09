// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase B audit (DESIGN.md §8 / IMPLEMENTATION_PLAN_01_CORE.md
// Phase B): the `Debug` output of every secret-bearing public type
// must omit the raw secret bytes (and any passphrase or AEAD key
// material). Companion to the trybuild compile-fail tests in
// `tests/trybuild/` that prove `Secret` / `AccountInput` are
// `!Debug` and `Account` / `Secret` are `!Serialize`.
//
// Fixture is a uniquely-recognizable 20-byte secret (`CAFE-BABE-
// DEAD-BEEF` repeating) plus a canary passphrase string. Each test
// asserts that the type's `Debug` output does not contain the
// secret in any plausible textual encoding (rust slice format,
// upper/lower hex, RFC 4648 base32 with and without padding, raw
// UTF-8 lossy bytes).

#![cfg(unix)]

use base32::Alphabet;
use paladin_core::{
    validate_manual, Account, AccountInput, AccountKindInput, Algorithm, Argon2Params,
    EncryptionOptions, IconHintInput, Store, Vault, VaultInit,
};
use secrecy::SecretString;
use static_assertions::assert_not_impl_all;
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime};

const FIXTURE_SECRET_BYTES: [u8; 20] = [
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
    0xCA, 0xFE, 0xBA, 0xBE,
];

const PASSPHRASE_CANARY: &str = "PaladinAuditCanaryPassphrase-DoNotLeak-9876543210";

fn fixture_base32_unpadded() -> String {
    base32::encode(Alphabet::Rfc4648 { padding: false }, &FIXTURE_SECRET_BYTES)
}

fn fixture_base32_padded() -> String {
    base32::encode(Alphabet::Rfc4648 { padding: true }, &FIXTURE_SECRET_BYTES)
}

fn fixture_account_input() -> AccountInput {
    AccountInput {
        label: "audit-account".into(),
        issuer: Some("AuditCo".into()),
        secret: SecretString::from(fixture_base32_unpadded()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    }
}

fn fixture_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn fixture_account() -> Account {
    validate_manual(fixture_account_input(), fixture_now())
        .expect("fixture validates")
        .account
}

#[track_caller]
fn assert_no_secret_substring_in(label: &str, haystack: &str) {
    let b32_unpadded = fixture_base32_unpadded();
    let b32_padded = fixture_base32_padded();
    assert!(
        !haystack.contains(&b32_unpadded),
        "{label} Debug output leaked unpadded base32 secret\n\
         haystack: {haystack:?}"
    );
    assert!(
        !haystack.contains(&b32_padded),
        "{label} Debug output leaked padded base32 secret\n\
         haystack: {haystack:?}"
    );

    let mut hex_lower = String::with_capacity(FIXTURE_SECRET_BYTES.len() * 2);
    for b in FIXTURE_SECRET_BYTES {
        write!(hex_lower, "{b:02x}").unwrap();
    }
    let mut hex_upper = String::with_capacity(FIXTURE_SECRET_BYTES.len() * 2);
    for b in FIXTURE_SECRET_BYTES {
        write!(hex_upper, "{b:02X}").unwrap();
    }
    assert!(
        !haystack.contains(&hex_lower),
        "{label} Debug output leaked lowercase-hex secret bytes"
    );
    assert!(
        !haystack.contains(&hex_upper),
        "{label} Debug output leaked uppercase-hex secret bytes"
    );

    let slice_dbg = format!("{:?}", FIXTURE_SECRET_BYTES.as_slice());
    assert!(
        !haystack.contains(&slice_dbg),
        "{label} Debug output leaked rust-formatted secret slice"
    );

    let lossy = String::from_utf8_lossy(&FIXTURE_SECRET_BYTES).into_owned();
    if !lossy.is_empty() && lossy.chars().any(char::is_alphanumeric) {
        assert!(
            !haystack.contains(&lossy),
            "{label} Debug output leaked UTF-8 lossy secret bytes"
        );
    }
}

#[test]
fn account_debug_omits_secret_bytes() {
    let acct = fixture_account();
    let s = format!("{acct:?}");
    assert!(s.contains("Account"), "expected type name in Debug: {s}");
    assert_no_secret_substring_in("Account", &s);
}

#[test]
fn validated_account_debug_omits_secret_bytes() {
    let v = validate_manual(fixture_account_input(), fixture_now()).expect("validates");
    let s = format!("{v:?}");
    assert!(
        s.contains("ValidatedAccount"),
        "expected type name in Debug: {s}"
    );
    assert_no_secret_substring_in("ValidatedAccount", &s);
}

#[test]
fn encryption_options_debug_omits_passphrase() {
    let opts = EncryptionOptions::with_params(
        SecretString::from(PASSPHRASE_CANARY.to_string()),
        Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        },
    )
    .expect("non-empty passphrase, in-bounds params");
    let s = format!("{opts:?}");
    assert!(
        s.contains("EncryptionOptions"),
        "expected type name in Debug: {s}"
    );
    assert!(
        !s.contains(PASSPHRASE_CANARY),
        "EncryptionOptions Debug leaked passphrase canary: {s}"
    );
    assert!(
        s.contains("REDACTED"),
        "expected redaction marker in Debug: {s}"
    );
}

fn empty_plaintext_vault() -> Vault {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("0700 parent");
    let path = dir.path().join("vault.bin");
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    // Hold the tempdir until vault is constructed; on drop the file is
    // unlinked automatically. The Debug audit only inspects the
    // in-memory `Vault` value, so the on-disk file's lifetime is
    // irrelevant past this point.
    drop(dir);
    vault
}

#[test]
fn vault_debug_does_not_recurse_into_accounts() {
    let v = empty_plaintext_vault();
    let s = format!("{v:?}");
    assert!(s.contains("Vault"), "expected type name in Debug: {s}");
    assert!(
        s.contains("accounts"),
        "expected accounts field in Debug: {s}"
    );
    // The §4.7 Debug contract: Vault prints `accounts: <count>`,
    // never the per-account struct. A future regression that adds
    // `&self.accounts` would surface `Account { ... }` substrings in
    // the rendered Debug — none of those appear here.
    assert!(
        !s.contains("Account {"),
        "Vault Debug must not recurse into Account struct: {s}"
    );
    assert!(
        !s.contains("Secret {"),
        "Vault Debug must not surface Secret type: {s}"
    );
    assert!(
        !s.contains("expose_secret"),
        "Vault Debug must not name expose_secret: {s}"
    );
    assert!(
        !s.contains(PASSPHRASE_CANARY),
        "Vault Debug must not surface cached passphrase: {s}"
    );
}

// `AccountInput` and `Secret` are public secret-bearing types whose
// `!Debug` and `!Serialize` posture is enforced at compile time. The
// trybuild driver in `tests/trybuild_audit.rs` covers the
// out-of-tree compile-fail check; these in-tree static assertions
// keep the guarantee enforceable from a single `cargo test` run
// even when `TRYBUILD=` is set to skip the trybuild subprocess.
assert_not_impl_all!(paladin_core::Secret: std::fmt::Debug);
assert_not_impl_all!(paladin_core::AccountInput: std::fmt::Debug);
assert_not_impl_all!(paladin_core::Secret: serde::Serialize);
assert_not_impl_all!(paladin_core::Account: serde::Serialize);
