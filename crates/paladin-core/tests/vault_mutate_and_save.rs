// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.9 / G.10: `Vault::mutate_and_save` (DESIGN.md §4.7
// `impl Vault` block). Front-end crates (CLI, TUI, GUI) drive
// add / remove / settings flows through this single helper so
// rollback machinery does not duplicate across crates.
//
// Coverage in this file (no fault-injection):
//   - returns the closure's success value unchanged on a clean save
//   - persists mutations to disk on a clean save
//   - restores **accounts** when the mutation closure returns `Err`
//   - restores **`VaultSettings`** when the mutation closure returns `Err`
//   - cross-field rollback (accounts AND settings) on closure `Err`
//   - the `Store::save` path is not entered when the closure errors
//
// Save-error rollback (`save_not_committed` and the
// `save_durability_unconfirmed` retain-mutation case) lives in
// `tests/fault_injection.rs` so every test that touches the
// process-wide `PALADIN_FAULT_INJECT` env var serializes on the
// shared mutex defined there.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_otpauth, Account, AccountId, ErrorKind, ImportConflict, PaladinError, Store,
    ValidatedAccount, Vault, VaultInit, VaultLock,
};
use tempfile::TempDir;

const SECRET_B32: &str = "JBSWY3DPEHPK3PXP";
const SYNTHETIC_REASON: &str = "synthetic-mutate-error";

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_totp_account(label: &str) -> Account {
    let uri = format!("otpauth://totp/{label}?secret={SECRET_B32}");
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

fn synthetic_error() -> PaladinError {
    PaladinError::InvalidPayload {
        reason: SYNTHETIC_REASON,
    }
}

// ---- happy path ---------------------------------------------------

#[test]
fn mutate_and_save_returns_closure_success_value_on_clean_save() {
    let (mut vault, store, _dir) = vault_with_path();
    let returned = vault
        .mutate_and_save(&store, |v| {
            let id = v.add(make_totp_account("alice"));
            Ok::<AccountId, PaladinError>(id)
        })
        .expect("mutate_and_save must succeed without faults");
    assert_eq!(vault.iter().count(), 1);
    assert_eq!(vault.get(returned).unwrap().label(), "alice");
}

#[test]
fn mutate_and_save_passes_unit_success_value_through_unchanged() {
    let (mut vault, store, _dir) = vault_with_path();
    let _: () = vault
        .mutate_and_save(&store, |v| {
            v.set_auto_lock_enabled(true);
            Ok::<(), PaladinError>(())
        })
        .expect("clean save");
    assert!(vault.settings().auto_lock_enabled());
}

#[test]
fn mutate_and_save_persists_mutations_to_disk_on_clean_save() {
    let (mut vault, store, dir) = vault_with_path();
    vault
        .mutate_and_save(&store, |v| {
            v.add(make_totp_account("alice"));
            v.set_auto_lock_enabled(true);
            v.set_clipboard_clear_secs(45)?;
            Ok::<(), PaladinError>(())
        })
        .expect("clean save");
    drop(vault);
    drop(store);

    // Reopen and confirm the mutation is on disk.
    let path = dir.path().join("vault.bin");
    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen");
    assert_eq!(reopened.iter().count(), 1);
    assert_eq!(
        reopened.iter().next().unwrap().label(),
        "alice",
        "added account must survive the save round-trip",
    );
    assert!(reopened.settings().auto_lock_enabled());
    assert_eq!(reopened.settings().clipboard_clear_secs(), 45);
}

// ---- rollback on closure error ------------------------------------

#[test]
fn mutate_and_save_restores_accounts_on_closure_error_after_add() {
    let (mut vault, store, _dir) = vault_with_path();
    let alice_id = vault.add(make_totp_account("alice"));
    vault.save(&store).expect("baseline save");

    let err = vault
        .mutate_and_save(&store, |v| -> Result<(), PaladinError> {
            v.add(make_totp_account("bob"));
            Err(synthetic_error())
        })
        .expect_err("closure error must propagate");
    match err {
        PaladinError::InvalidPayload { reason } => assert_eq!(reason, SYNTHETIC_REASON),
        other => panic!("expected synthetic error, got {other:?}"),
    }

    // Bob was added inside the closure but rolled back; only alice remains.
    let labels: Vec<_> = vault.iter().map(|a| a.label().to_string()).collect();
    assert_eq!(labels, vec!["alice"]);
    assert!(vault.get(alice_id).is_some());
}

#[test]
fn mutate_and_save_restores_accounts_on_closure_error_after_remove() {
    let (mut vault, store, _dir) = vault_with_path();
    let alice_id = vault.add(make_totp_account("alice"));
    let bob_id = vault.add(make_totp_account("bob"));
    vault.save(&store).expect("baseline save");

    let err = vault
        .mutate_and_save(&store, |v| -> Result<(), PaladinError> {
            v.remove(alice_id);
            Err(synthetic_error())
        })
        .expect_err("closure error must propagate");
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);

    // Both accounts still present, in original insertion order.
    let ids: Vec<_> = vault.iter().map(Account::id).collect();
    assert_eq!(ids, vec![alice_id, bob_id]);
}

#[test]
fn mutate_and_save_restores_accounts_on_closure_error_after_import_merge() {
    let (mut vault, store, _dir) = vault_with_path();
    // Baseline: a single "alice" already in the vault.
    let alice_id = vault.add(make_totp_account("alice"));
    vault.save(&store).expect("baseline save");

    // Inside the closure, run a Replace import that both replaces
    // alice (collides on secret/label) and appends bob (no collision),
    // then return Err so mutate_and_save rolls everything back.
    let incoming: Vec<ValidatedAccount> = vec![
        parse_otpauth(
            &format!("otpauth://totp/alice?secret={SECRET_B32}"),
            fixture_now(),
        )
        .unwrap(),
        parse_otpauth(
            &format!("otpauth://totp/bob?secret={SECRET_B32}"),
            fixture_now(),
        )
        .unwrap(),
    ];

    let err = vault
        .mutate_and_save(&store, |v| -> Result<(), PaladinError> {
            let report = v
                .import_accounts(incoming, ImportConflict::Replace, fixture_now())
                .expect("import inside closure");
            // Confirm the merge actually fired before we error out:
            assert_eq!(report.replaced, 1);
            assert_eq!(report.imported, 1);
            assert_eq!(v.iter().count(), 2);
            Err(synthetic_error())
        })
        .expect_err("closure error must propagate");
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);

    // Rollback: only the original alice remains, with the original id.
    let labels: Vec<_> = vault.iter().map(|a| a.label().to_string()).collect();
    assert_eq!(labels, vec!["alice"]);
    let ids: Vec<_> = vault.iter().map(Account::id).collect();
    assert_eq!(ids, vec![alice_id]);
}

#[test]
fn mutate_and_save_restores_settings_on_closure_error() {
    let (mut vault, store, _dir) = vault_with_path();
    // Vault opens with §5 defaults: both toggles off, timeouts 300/20.
    let pre_settings = *vault.settings();

    let err = vault
        .mutate_and_save(&store, |v| -> Result<(), PaladinError> {
            v.set_auto_lock_enabled(true);
            v.set_auto_lock_timeout_secs(900)?;
            v.set_clipboard_clear_enabled(true);
            v.set_clipboard_clear_secs(120)?;
            Err(synthetic_error())
        })
        .expect_err("closure error must propagate");
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);

    // Every settings field reverted to the pre-call value.
    assert_eq!(*vault.settings(), pre_settings);
    assert!(!vault.settings().auto_lock_enabled());
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);
    assert!(!vault.settings().clipboard_clear_enabled());
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);
}

#[test]
fn mutate_and_save_cross_field_rollback_on_closure_error() {
    // §4.7 G.10: when the closure mutates accounts AND settings then
    // returns `Err`, both fields revert. Front ends rely on this
    // joint-rollback so a multi-step preferences-and-accounts flow
    // never half-applies.
    let (mut vault, store, _dir) = vault_with_path();
    let alice_id = vault.add(make_totp_account("alice"));
    vault.save(&store).expect("baseline save");
    let pre_settings = *vault.settings();
    let pre_alice_updated = vault.get(alice_id).unwrap().updated_at();

    let err = vault
        .mutate_and_save(&store, |v| -> Result<(), PaladinError> {
            v.add(make_totp_account("bob"));
            v.set_auto_lock_enabled(true);
            v.set_clipboard_clear_secs(60)?;
            Err(synthetic_error())
        })
        .expect_err("closure error must propagate");
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);

    // Accounts: bob was rolled back, alice unchanged.
    let labels: Vec<_> = vault.iter().map(|a| a.label().to_string()).collect();
    assert_eq!(labels, vec!["alice"]);
    assert_eq!(vault.get(alice_id).unwrap().updated_at(), pre_alice_updated);
    // Settings: every field reverted.
    assert_eq!(*vault.settings(), pre_settings);
}

#[test]
fn mutate_and_save_does_not_save_when_closure_returns_error() {
    // The §4.3 atomic write pipeline must not run when the closure
    // errors — so the on-disk primary stays byte-identical to the
    // pre-call snapshot.
    let (mut vault, store, dir) = vault_with_path();
    vault.add(make_totp_account("alice"));
    vault.save(&store).expect("baseline save");
    let path = dir.path().join("vault.bin");
    let primary_before = std::fs::read(&path).unwrap();

    let err = vault
        .mutate_and_save(&store, |v| -> Result<(), PaladinError> {
            v.add(make_totp_account("bob"));
            Err(synthetic_error())
        })
        .expect_err("closure error must propagate");
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);

    assert_eq!(
        std::fs::read(&path).unwrap(),
        primary_before,
        "save must not be entered when the closure returns Err",
    );
}

// ---- closure body sees the live, mutated vault --------------------

#[test]
fn mutate_and_save_closure_sees_prior_mutations_inside_the_call() {
    // The closure receives `&mut Vault`, so subsequent statements
    // inside it observe earlier mutations. This pins the contract
    // for callers that compose multiple steps.
    let (mut vault, store, _dir) = vault_with_path();
    let observed = vault
        .mutate_and_save(&store, |v| -> Result<usize, PaladinError> {
            v.add(make_totp_account("alice"));
            v.add(make_totp_account("bob"));
            Ok(v.iter().count())
        })
        .expect("clean save");
    assert_eq!(observed, 2);
    assert_eq!(vault.iter().count(), 2);
}
