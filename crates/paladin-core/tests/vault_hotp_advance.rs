// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.5: `Vault::hotp_advance` core semantics — happy path,
// `updated_at` advance, `time_range` validation, and persistence to
// disk (DESIGN.md §4.7 `impl Vault` block / §5 error taxonomy).
// Fault-injection rollback / durability-unconfirmed coverage lives in
// `tests/fault_injection.rs` so every test that touches the
// process-wide `PALADIN_FAULT_INJECT` env var serializes on the
// shared mutex defined there.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_otpauth, Account, AccountKindSummary, ErrorKind, PaladinError, Store, TimeRangeKind,
    Vault, VaultInit, VaultLock,
};
use tempfile::TempDir;

const HOTP_SECRET_B32: &str = "JBSWY3DPEHPK3PXP";

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn later_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_001_000)
}

fn make_hotp_account(label: &str, counter: u64) -> Account {
    let uri = format!("otpauth://hotp/{label}?secret={HOTP_SECRET_B32}&counter={counter}");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn vault_with_path() -> (Vault, Store, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    (vault, store, dir)
}

#[test]
fn hotp_advance_advances_counter_and_updates_updated_at_on_success() {
    let (mut vault, store, _dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 7));
    assert_eq!(vault.get(id).unwrap().counter(), Some(7));
    let pre_updated_at = vault.get(id).unwrap().updated_at();

    let code = vault
        .hotp_advance(&store, id, later_now())
        .expect("hotp_advance must succeed without faults");
    // The returned code is computed at the *pre-advance* counter
    // (RFC 4226: emit the code, then increment), so a peek at the
    // pre-advance counter would have produced the same digits.
    assert_eq!(code.counter_used, Some(7));
    assert!(!code.code.is_empty());
    assert!(code.valid_from.is_none());
    assert!(code.valid_until.is_none());

    // In-memory state moved forward.
    assert_eq!(vault.get(id).unwrap().counter(), Some(8));
    assert_eq!(vault.get(id).unwrap().updated_at(), 1_700_001_000);
    assert!(vault.get(id).unwrap().updated_at() > pre_updated_at);
}

#[test]
fn hotp_advance_persists_to_disk_so_a_reopen_sees_the_new_counter() {
    let (mut vault, store, dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 41));
    vault
        .hotp_advance(&store, id, later_now())
        .expect("hotp_advance must succeed");
    drop(vault);
    drop(store);

    let path = dir.path().join("vault.bin");
    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen must succeed");
    let account = reopened
        .get(id)
        .expect("account must be present after reopen");
    assert_eq!(account.kind(), AccountKindSummary::Hotp);
    assert_eq!(account.counter(), Some(42));
    assert_eq!(account.updated_at(), 1_700_001_000);
}

#[test]
fn hotp_advance_rejects_pre_epoch_timestamp_before_any_mutation_or_save() {
    let (mut vault, store, _dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 3));
    let pre_counter = vault.get(id).unwrap().counter();
    let pre_updated_at = vault.get(id).unwrap().updated_at();
    let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);

    let err = vault.hotp_advance(&store, id, pre_epoch).unwrap_err();
    match err {
        PaladinError::TimeRange { operation, kind } => {
            assert_eq!(operation, "hotp_advance");
            assert_eq!(kind, TimeRangeKind::PreEpoch);
        }
        other => panic!("expected time_range(hotp_advance/pre_epoch), got {other:?}"),
    }

    // No counter advance and no updated_at bump.
    assert_eq!(vault.get(id).unwrap().counter(), pre_counter);
    assert_eq!(vault.get(id).unwrap().updated_at(), pre_updated_at);
}

#[test]
fn hotp_advance_rejects_timestamp_beyond_year_9999_cap_before_any_mutation_or_save() {
    let (mut vault, store, _dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 3));
    let pre_counter = vault.get(id).unwrap().counter();
    let pre_updated_at = vault.get(id).unwrap().updated_at();
    // §4.1 timestamp cap = 253_402_300_799 (year 9999-12-31 23:59:59 UTC).
    let beyond = UNIX_EPOCH + Duration::from_secs(253_402_300_800);

    let err = vault.hotp_advance(&store, id, beyond).unwrap_err();
    match err {
        PaladinError::TimeRange { operation, kind } => {
            assert_eq!(operation, "hotp_advance");
            assert_eq!(kind, TimeRangeKind::OutOfRange);
        }
        other => panic!("expected time_range(hotp_advance/out_of_range), got {other:?}"),
    }

    assert_eq!(vault.get(id).unwrap().counter(), pre_counter);
    assert_eq!(vault.get(id).unwrap().updated_at(), pre_updated_at);
}

#[test]
fn hotp_advance_time_range_does_not_write_to_the_store() {
    // §5: invalid timestamps surface `time_range` "before mutation or
    // save". Confirm the on-disk bytes are byte-identical to the
    // pre-advance vault — i.e. the `Store::save` path was never
    // entered.
    let (mut vault, store, dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 11));
    vault.save(&store).expect("baseline save");
    let path = dir.path().join("vault.bin");
    let primary_before = std::fs::read(&path).unwrap();

    let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
    let err = vault.hotp_advance(&store, id, pre_epoch).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimeRange);

    assert_eq!(
        std::fs::read(&path).unwrap(),
        primary_before,
        "primary vault file must not have been rewritten",
    );
}
