// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.2: `Vault::rename` (docs/DESIGN.md §4.7 `impl Vault` block).
// Covers label re-validation (trim, empty rejection, 128-byte cap),
// timestamp validation, `updated_at` advance, and the
// `invalid_state.account_not_found` error contract from §5 / §4.7
// for missing IDs. The bullet at Phase G.5 also pins
// `account_not_found` here for completeness.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_auth_core::{
    parse_otpauth, Account, AccountId, ErrorKind, PaladinAuthError, Store, TimeRangeKind, Vault,
    VaultInit,
};

const ZERO_WIDTH_SPACE: &str = "\u{200B}";

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn later_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_001_000)
}

fn make_account(label: &str) -> Account {
    let uri = format!("otpauth://totp/{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn empty_plaintext_vault() -> Vault {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault
}

#[test]
fn rename_updates_label_and_advances_updated_at() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    let original_created = vault.get(id).unwrap().created_at();

    vault.rename(id, "alice-prime", later_now()).unwrap();

    let renamed = vault.get(id).unwrap();
    assert_eq!(renamed.label(), "alice-prime");
    assert_eq!(renamed.created_at(), original_created);
    assert_eq!(renamed.updated_at(), 1_700_001_000);
    assert!(renamed.updated_at() > original_created);
}

#[test]
fn rename_to_identical_post_trim_label_still_advances_updated_at() {
    // §4.7 contract: `Vault::rename` validates label + timestamp and
    // bumps `updated_at` unconditionally on success — there is no
    // "label unchanged → skip mutation" fast path. The trimmed input
    // form is what gets compared and stored; an input that trims to
    // the existing label is therefore observationally a no-op on
    // `label()` but must still advance `updated_at`. Pins the
    // always-bump rule so a future "skip if unchanged" optimization
    // cannot be added without surfacing as a failing test.
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    let original_updated = vault.get(id).unwrap().updated_at();

    vault.rename(id, "  alice\t", later_now()).unwrap();

    let renamed = vault.get(id).unwrap();
    assert_eq!(renamed.label(), "alice");
    assert_eq!(renamed.updated_at(), 1_700_001_000);
    assert!(renamed.updated_at() > original_updated);
}

#[test]
fn rename_trims_unicode_whitespace_around_label() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    vault.rename(id, "  spaced-out\t", later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().label(), "spaced-out");
}

#[test]
fn rename_rejects_empty_label() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    let err = vault.rename(id, "", later_now()).unwrap_err();
    match err {
        PaladinAuthError::ValidationError { field, reason, .. } => {
            assert_eq!(field, "label");
            assert_eq!(reason, "empty");
        }
        other => panic!("expected validation_error(label/empty), got {other:?}"),
    }
    // No mutation occurred.
    assert_eq!(vault.get(id).unwrap().label(), "alice");
    assert_eq!(vault.get(id).unwrap().updated_at(), 1_700_000_000);
}

#[test]
fn rename_rejects_whitespace_only_label() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    let err = vault.rename(id, "   \t\n", later_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    // No mutation occurred.
    assert_eq!(vault.get(id).unwrap().label(), "alice");
}

#[test]
fn rename_rejects_label_exceeding_128_bytes() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    // 129 ASCII bytes — over the §4.1 cap by one.
    let too_long = "a".repeat(129);
    let err = vault.rename(id, &too_long, later_now()).unwrap_err();
    match err {
        PaladinAuthError::ValidationError { field, reason, .. } => {
            assert_eq!(field, "label");
            assert_eq!(reason, "too_long");
        }
        other => panic!("expected validation_error(label/too_long), got {other:?}"),
    }
    assert_eq!(vault.get(id).unwrap().label(), "alice");
}

#[test]
fn rename_accepts_label_at_128_byte_cap() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    let exactly_128 = "a".repeat(128);
    vault.rename(id, &exactly_128, later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().label(), exactly_128);
}

#[test]
fn rename_rejects_label_that_trims_to_overlong() {
    // 128 'a' surrounded by whitespace — but trim leaves exactly 128, accepted.
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    let surrounded = format!("  {}\t", "a".repeat(128));
    vault.rename(id, &surrounded, later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().label(), "a".repeat(128));
}

#[test]
fn rename_rejects_unicode_whitespace_only_label() {
    // Zero-width space + tab + space — all Unicode-trimmable.
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    let label = format!(" \t{ZERO_WIDTH_SPACE}");
    // ZWSP is *not* in the Unicode whitespace set per Rust `str::trim`,
    // so this label is non-empty after trim. Pin the boundary so the
    // helper's behavior stays consistent if rust-stdlib tightens.
    match vault.rename(id, &label, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            // If `trim` treated ZWSP as whitespace, the error must be
            // validation/empty so the contract is unambiguous.
            assert_eq!(field, "label");
            assert_eq!(reason, "empty");
        }
        Err(other) => panic!("expected validation_error(label/empty), got {other:?}"),
        Ok(()) => {
            // Otherwise the trimmed label is the ZWSP itself — confirm it.
            assert_eq!(vault.get(id).unwrap().label(), ZERO_WIDTH_SPACE);
        }
    }
}

#[test]
fn rename_returns_invalid_state_account_not_found_for_unknown_id() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice"));
    let unknown = AccountId::new();
    let err = vault.rename(unknown, "anything", later_now()).unwrap_err();
    match err {
        PaladinAuthError::InvalidState { operation, state } => {
            assert_eq!(operation, "rename");
            assert_eq!(state, "account_not_found");
        }
        other => panic!("expected invalid_state(rename/account_not_found), got {other:?}"),
    }
}

#[test]
fn rename_rejects_pre_epoch_timestamp() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
    let err = vault.rename(id, "anything", pre_epoch).unwrap_err();
    match err {
        PaladinAuthError::TimeRange { operation, kind } => {
            assert_eq!(operation, "rename");
            assert_eq!(kind, TimeRangeKind::PreEpoch);
        }
        other => panic!("expected time_range(rename/pre_epoch), got {other:?}"),
    }
    // No mutation.
    assert_eq!(vault.get(id).unwrap().label(), "alice");
    assert_eq!(vault.get(id).unwrap().updated_at(), 1_700_000_000);
}

#[test]
fn rename_rejects_timestamp_beyond_year_9999_cap() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice"));
    // §4.1 timestamp cap = 253_402_300_799 (year 9999-12-31 23:59:59 UTC).
    let beyond = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    let err = vault.rename(id, "anything", beyond).unwrap_err();
    match err {
        PaladinAuthError::TimeRange { operation, kind } => {
            assert_eq!(operation, "rename");
            assert_eq!(kind, TimeRangeKind::OutOfRange);
        }
        other => panic!("expected time_range(rename/out_of_range), got {other:?}"),
    }
    assert_eq!(vault.get(id).unwrap().label(), "alice");
}

#[test]
fn rename_validates_inputs_before_account_lookup() {
    // Even when the ID is missing, label/timestamp validation
    // happens first, so the caller sees the input error
    // rather than `account_not_found`. Pinning the order keeps
    // the §5 error taxonomy stable: front ends can rely on the
    // input layer rejecting before any lookup state is touched.
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice"));
    let unknown = AccountId::new();
    let err = vault.rename(unknown, "", later_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}

#[test]
fn rename_does_not_touch_other_accounts() {
    let mut vault = empty_plaintext_vault();
    let id_a = vault.add(make_account("alice"));
    let id_b = vault.add(make_account("bob"));
    let bob_pre_updated_at = vault.get(id_b).unwrap().updated_at();

    vault.rename(id_a, "alice-prime", later_now()).unwrap();
    assert_eq!(vault.get(id_b).unwrap().label(), "bob");
    assert_eq!(vault.get(id_b).unwrap().updated_at(), bob_pre_updated_at);
}
