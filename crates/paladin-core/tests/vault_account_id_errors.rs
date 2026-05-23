// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.8: pin the stable `invalid_state` operation/state pairs
// returned by every `Vault` method that takes an `AccountId`
// (docs/DESIGN.md §4.7 stable error matrix). One file exercises the full
// matrix so a refactor that swaps an operation tag, state tag, or
// error kind cannot pass tests by only updating the per-method file.
//
// The pairs locked here, per docs/DESIGN.md §4.7:
//
//   | Method         | Missing ID         | Wrong kind |
//   |----------------|--------------------|------------|
//   | `rename`       | `account_not_found`| n/a        |
//   | `totp_code`    | `account_not_found`| `not_totp` |
//   | `hotp_peek`    | `account_not_found`| `not_hotp` |
//   | `hotp_advance` | `account_not_found`| `not_hotp` |

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_otpauth, Account, AccountId, ErrorKind, PaladinError, Store, TimeRangeKind, Vault,
    VaultInit,
};
use tempfile::TempDir;

const RFC_SHA1_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn at_unix(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn make_hotp_account(label: &str, counter: u64) -> Account {
    let uri = format!(
        "otpauth://hotp/{label}?secret={RFC_SHA1_SECRET_B32}&counter={counter}&algorithm=SHA1&digits=6",
    );
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn make_totp_account(label: &str, period: u32, digits: u8) -> Account {
    let uri = format!(
        "otpauth://totp/{label}?secret={RFC_SHA1_SECRET_B32}&algorithm=SHA1&digits={digits}&period={period}",
    );
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn vault_with_path() -> (Vault, Store, TempDir) {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    (vault, store, dir)
}

fn assert_invalid_state(err: PaladinError, op: &'static str, state: &'static str) {
    assert_eq!(err.kind(), ErrorKind::InvalidState, "wrong error kind");
    match err {
        PaladinError::InvalidState {
            operation,
            state: actual_state,
        } => {
            assert_eq!(operation, op, "operation tag");
            assert_eq!(actual_state, state, "state tag");
        }
        other => panic!("expected invalid_state({op}/{state}), got {other:?}"),
    }
}

// ---- account_not_found across all four methods --------------------

#[test]
fn rename_returns_invalid_state_account_not_found_for_unknown_id() {
    // Pinned here as part of the §4.7 matrix. The vault_rename.rs
    // suite also exercises this case; the duplicate is intentional —
    // this file is the single canonical home of the matrix.
    let (mut vault, _store, _dir) = vault_with_path();
    vault.add(make_totp_account("alice", 30, 6));
    let unknown = AccountId::new();
    let err = vault
        .rename(unknown, "anything", fixture_now())
        .unwrap_err();
    assert_invalid_state(err, "rename", "account_not_found");
}

#[test]
fn totp_code_returns_invalid_state_account_not_found_for_unknown_id() {
    let (mut vault, _store, _dir) = vault_with_path();
    vault.add(make_totp_account("alice", 30, 6));
    let unknown = AccountId::new();
    let err = vault.totp_code(unknown, fixture_now()).unwrap_err();
    assert_invalid_state(err, "totp_code", "account_not_found");
}

#[test]
fn hotp_peek_returns_invalid_state_account_not_found_for_unknown_id() {
    let (mut vault, _store, _dir) = vault_with_path();
    vault.add(make_hotp_account("alice", 0));
    let unknown = AccountId::new();
    let err = vault.hotp_peek(unknown).unwrap_err();
    assert_invalid_state(err, "hotp_peek", "account_not_found");
}

#[test]
fn hotp_advance_returns_invalid_state_account_not_found_for_unknown_id() {
    let (mut vault, store, _dir) = vault_with_path();
    vault.add(make_hotp_account("alice", 0));
    let unknown = AccountId::new();
    let err = vault
        .hotp_advance(&store, unknown, fixture_now())
        .unwrap_err();
    assert_invalid_state(err, "hotp_advance", "account_not_found");
}

// ---- not_totp / not_hotp on the wrong kind ------------------------

#[test]
fn totp_code_returns_invalid_state_not_totp_for_hotp_account() {
    let (mut vault, _store, _dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 0));
    let err = vault.totp_code(id, fixture_now()).unwrap_err();
    assert_invalid_state(err, "totp_code", "not_totp");
}

#[test]
fn hotp_peek_returns_invalid_state_not_hotp_for_totp_account() {
    let (mut vault, _store, _dir) = vault_with_path();
    let id = vault.add(make_totp_account("alice", 30, 6));
    let err = vault.hotp_peek(id).unwrap_err();
    assert_invalid_state(err, "hotp_peek", "not_hotp");
}

#[test]
fn hotp_advance_returns_invalid_state_not_hotp_for_totp_account() {
    let (mut vault, store, _dir) = vault_with_path();
    let id = vault.add(make_totp_account("alice", 30, 6));
    let err = vault.hotp_advance(&store, id, fixture_now()).unwrap_err();
    assert_invalid_state(err, "hotp_advance", "not_hotp");
}

// ---- non-mutation invariants on the failure paths -----------------

#[test]
fn account_not_found_failures_leave_other_accounts_unchanged() {
    // No method on the matrix mutates other accounts as a side effect
    // of the missing-ID lookup. After each failure, the surviving
    // account's fields must be byte-identical to the pre-call values.
    let (mut vault, store, _dir) = vault_with_path();
    let totp_id = vault.add(make_totp_account("alice", 30, 6));
    let hotp_id = vault.add(make_hotp_account("bob", 5));
    let totp_pre_updated = vault.get(totp_id).unwrap().updated_at();
    let hotp_pre_updated = vault.get(hotp_id).unwrap().updated_at();
    let hotp_pre_counter = vault.get(hotp_id).unwrap().counter();

    let unknown = AccountId::new();
    let _ = vault.rename(unknown, "x", fixture_now()).unwrap_err();
    let _ = vault.totp_code(unknown, fixture_now()).unwrap_err();
    let _ = vault.hotp_peek(unknown).unwrap_err();
    let _ = vault
        .hotp_advance(&store, unknown, fixture_now())
        .unwrap_err();

    assert_eq!(vault.get(totp_id).unwrap().updated_at(), totp_pre_updated);
    assert_eq!(vault.get(totp_id).unwrap().label(), "alice");
    assert_eq!(vault.get(hotp_id).unwrap().updated_at(), hotp_pre_updated);
    assert_eq!(vault.get(hotp_id).unwrap().label(), "bob");
    assert_eq!(vault.get(hotp_id).unwrap().counter(), hotp_pre_counter);
}

#[test]
fn not_hotp_on_hotp_advance_does_not_mutate_or_save() {
    // §4.7: `hotp_advance` against a TOTP account must surface
    // `not_hotp` before any in-memory mutation and before the
    // `Store::save` path is entered. After persisting a baseline,
    // the on-disk primary file must remain byte-identical and the
    // account's `updated_at` must not move.
    let (mut vault, store, dir) = vault_with_path();
    let id = vault.add(make_totp_account("alice", 30, 6));
    vault.save(&store).expect("baseline save");
    let path = dir.path().join("vault.bin");
    let primary_before = std::fs::read(&path).unwrap();
    let pre_updated = vault.get(id).unwrap().updated_at();

    let err = vault
        .hotp_advance(&store, id, at_unix(1_700_001_000))
        .unwrap_err();
    assert_invalid_state(err, "hotp_advance", "not_hotp");

    assert_eq!(vault.get(id).unwrap().updated_at(), pre_updated);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        primary_before,
        "hotp_advance on a TOTP account must not rewrite the primary",
    );
}

// ---- validation ordering: input checks fire before lookup ---------

#[test]
fn hotp_advance_time_range_outranks_account_not_found() {
    // §5 / §4.7: `hotp_advance` validates the supplied timestamp
    // first, so a pre-epoch `now` against an unknown ID surfaces
    // `time_range`, not `account_not_found`. Pinning this order
    // keeps the §5 error taxonomy stable for front ends that
    // distinguish input errors from state errors.
    let (mut vault, store, _dir) = vault_with_path();
    vault.add(make_hotp_account("alice", 0));
    let unknown = AccountId::new();
    let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
    let err = vault.hotp_advance(&store, unknown, pre_epoch).unwrap_err();
    match err {
        PaladinError::TimeRange { operation, kind } => {
            assert_eq!(operation, "hotp_advance");
            assert_eq!(kind, TimeRangeKind::PreEpoch);
        }
        other => panic!("expected time_range(hotp_advance/pre_epoch), got {other:?}"),
    }
}

#[test]
fn rename_validation_outranks_account_not_found_for_unknown_id() {
    // Mirrors the analogous test in vault_rename.rs but pinned here
    // alongside the rest of the matrix so the canonical file
    // documents both the stable `invalid_state` pair *and* its
    // input-precedence guarantee.
    let (mut vault, _store, _dir) = vault_with_path();
    vault.add(make_totp_account("alice", 30, 6));
    let unknown = AccountId::new();
    let err = vault.rename(unknown, "", fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}
