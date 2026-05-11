// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase H passphrase transitions under save-pipeline fault injection
// (DESIGN.md §4.5 / §4.3).
//
// Pins the §4.5 commit-point semantics:
//
// * pre-commit failure (`pre_commit` fault) — the on-disk primary
//   is untouched, in-memory mode/key roll back to the prior state,
//   and the typed error is `save_not_committed`. Subsequent regular
//   `Vault::save` runs through the *prior* mode/crypto unchanged.
// * post-commit failure (`post_commit` fault) — the on-disk primary
//   already carries the new mode/key, so the in-memory `Vault` and
//   `Store` are updated to match the on-disk state and the typed
//   error is `save_durability_unconfirmed`. Subsequent regular saves
//   use the *new* mode/crypto.

#![cfg(feature = "test-fault-injection")]

mod common;

use common::test_tempdir;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    inspect, parse_otpauth, Account, Argon2Params, EncryptionOptions, ErrorKind, Store, VaultInit,
    VaultLock, VaultStatus,
};
use secrecy::SecretString;
use tempfile::TempDir;

const ENV: &str = "PALADIN_FAULT_INJECT";
const PRE: &str = "pre_commit";
const POST: &str = "post_commit";

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn run_serial<F: FnOnce()>(f: F) {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::env::remove_var(ENV);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::env::remove_var(ENV);
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn with_fault<R>(phase: &str, f: impl FnOnce() -> R) -> R {
    std::env::set_var(ENV, phase);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::env::remove_var(ENV);
    match result {
        Ok(v) => v,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn vault_test_dir() -> TempDir {
    let dir = test_tempdir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod tempdir 0700");
    dir
}

fn vault_path_in(dir: &TempDir) -> PathBuf {
    dir.path().join("vault.bin")
}

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn cheap_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    }
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(pp(passphrase), cheap_params())
        .expect("cheap_params are in §4.4 bounds and the passphrase is non-empty")
}

// -----------------------------------------------------------------------------
// set_passphrase
// -----------------------------------------------------------------------------

#[test]
fn set_passphrase_pre_commit_failure_rolls_back_to_plaintext() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        let err = with_fault(PRE, || {
            vault.set_passphrase(&store, cheap_options("hunter2"))
        })
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::SaveNotCommitted);

        // In-memory rolled back: still plaintext, no cache.
        assert!(!vault.is_encrypted());
        // On-disk primary unchanged (still plaintext).
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
        // Regular save still works under prior mode.
        vault.add(make_account("bob", Some("Acme")));
        vault.save(&store).unwrap();
        // Reopen as plaintext recovers the new account too.
        drop(vault);
        let (vault2, _store2) = Store::open(&path, VaultLock::Plaintext).unwrap();
        assert_eq!(vault2.accounts().len(), 2);
    });
}

#[test]
fn set_passphrase_post_commit_failure_marks_in_memory_encrypted() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        let err = with_fault(POST, || {
            vault.set_passphrase(&store, cheap_options("hunter2"))
        })
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::SaveDurabilityUnconfirmed);

        // In-memory matches on-disk: encrypted with cache populated.
        assert!(vault.is_encrypted());
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
        // Subsequent regular save uses the new (encrypted) crypto.
        vault.save(&store).unwrap();
        drop(vault);
        let (vault2, _store2) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
        assert_eq!(vault2.accounts().len(), 1);
    });
}

// -----------------------------------------------------------------------------
// change_passphrase
// -----------------------------------------------------------------------------

#[test]
fn change_passphrase_pre_commit_failure_keeps_old_key() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = vault_path_in(&dir);
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        let err = with_fault(PRE, || {
            vault.change_passphrase(&store, cheap_options("hunter3"))
        })
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::SaveNotCommitted);

        // Still encrypted, cache still under OLD key.
        assert!(vault.is_encrypted());
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
        // Regular save under old key still works.
        vault.add(make_account("bob", Some("Acme")));
        vault.save(&store).unwrap();
        // Old passphrase still opens the file.
        drop(vault);
        let (vault2, _store2) =
            Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("old key still valid");
        assert_eq!(vault2.accounts().len(), 2);
    });
}

#[test]
fn change_passphrase_post_commit_failure_swaps_to_new_key() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = vault_path_in(&dir);
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        let err = with_fault(POST, || {
            vault.change_passphrase(&store, cheap_options("hunter3"))
        })
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::SaveDurabilityUnconfirmed);

        // In-memory matches on-disk: cache holds NEW key.
        assert!(vault.is_encrypted());
        // Subsequent save uses the new key.
        vault.save(&store).unwrap();
        drop(vault);
        // Old passphrase is dead.
        let old_err = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap_err();
        assert_eq!(old_err.kind(), ErrorKind::DecryptFailed);
        // New passphrase works.
        let (_v, _s) = Store::open(&path, VaultLock::Encrypted(pp("hunter3"))).unwrap();
    });
}

// -----------------------------------------------------------------------------
// remove_passphrase
// -----------------------------------------------------------------------------

#[test]
fn remove_passphrase_pre_commit_failure_keeps_encrypted_mode() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = vault_path_in(&dir);
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        let err = with_fault(PRE, || vault.remove_passphrase(&store)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::SaveNotCommitted);

        // Still encrypted with cache intact.
        assert!(vault.is_encrypted());
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
        // Regular save still works.
        vault.save(&store).unwrap();
        drop(vault);
        let (vault2, _store2) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
        assert_eq!(vault2.accounts().len(), 1);
    });
}

#[test]
fn remove_passphrase_post_commit_failure_drops_cache() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = vault_path_in(&dir);
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        let err = with_fault(POST, || vault.remove_passphrase(&store)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::SaveDurabilityUnconfirmed);

        // In-memory matches on-disk: cache cleared, mode plaintext.
        assert!(!vault.is_encrypted());
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
        // Subsequent regular save uses plaintext.
        vault.save(&store).unwrap();
        drop(vault);
        let (vault2, _store2) = Store::open(&path, VaultLock::Plaintext).unwrap();
        assert_eq!(vault2.accounts().len(), 1);
    });
}
