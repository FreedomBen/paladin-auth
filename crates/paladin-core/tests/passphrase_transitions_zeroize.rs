// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase H cached-key/passphrase zeroization (docs/DESIGN.md §4.4 / §4.5).
//
// Pins the cached-cache lifecycle for `Vault::change_passphrase` and
// `Vault::remove_passphrase`:
//
// * successful commit replaces the cache with new material (or drops
//   it for `remove_passphrase`); the previously-cached AEAD key
//   bytes and passphrase bytes are zeroized **in place** before the
//   underlying allocations are freed. The witness records the
//   post-zeroize state of those allocations through a borrow taken
//   between the in-place zeroize and the auto-drop, equivalent to
//   the design's `*const [u8; 32]` byte-precise check (the crate is
//   `#![forbid(unsafe_code)]` and so the witness uses a safe
//   `&[u8]` borrow rather than a raw pointer);
// * pre-commit failure leaves the cache pointing at the prior
//   key/passphrase (witness silent on the cache during the rolled
//   back call — the only post-commit witness records come from the
//   pending material drop, never from the active cache);
// * post-commit `save_durability_unconfirmed` replaces the cache to
//   match the new on-disk mode (same witness records as a
//   successful commit) so subsequent saves do not write stale
//   crypto over the committed transition.
//
// A regression that "swaps a buffer with a new allocation while old
// bytes leak" — i.e. drops the prior cache without first running the
// in-place zeroize — surfaces here as `all_zero == false` on at
// least one observation.

#![cfg(feature = "test-zeroize-witness")]

mod common;

use common::test_tempdir;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::zeroize_witness::{
    clear_observations, take_observations, Observation, WitnessSite,
};
use paladin_core::{
    parse_otpauth, Account, Argon2Params, EncryptionOptions, Store, VaultInit, VaultLock,
};
use secrecy::SecretString;
use tempfile::TempDir;

// All tests in this binary touch the witness's thread-local AND, when
// the `test-fault-injection` feature is also enabled, the global
// `PALADIN_FAULT_INJECT` env var. Serialize through a single mutex so
// parallel test runners do not race a fault setting against an
// unrelated zeroize observation.
static SERIAL: Mutex<()> = Mutex::new(());

#[cfg(feature = "test-fault-injection")]
const FAULT_ENV: &str = "PALADIN_FAULT_INJECT";

fn run_serial<F: FnOnce()>(f: F) {
    let _guard = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    #[cfg(feature = "test-fault-injection")]
    std::env::remove_var(FAULT_ENV);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    #[cfg(feature = "test-fault-injection")]
    std::env::remove_var(FAULT_ENV);
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
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

fn cheap_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    }
}

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(pp(passphrase), cheap_params())
        .expect("cheap_params are in §4.4 bounds and the passphrase is non-empty")
}

fn key_drops(obs: &[Observation]) -> Vec<&Observation> {
    obs.iter()
        .filter(|o| o.site == WitnessSite::EncryptedCacheKeyDrop)
        .collect()
}

fn passphrase_drops(obs: &[Observation]) -> Vec<&Observation> {
    obs.iter()
        .filter(|o| o.site == WitnessSite::EncryptedCachePassphraseDrop)
        .collect()
}

// -----------------------------------------------------------------------------
// change_passphrase: success path zeroizes the prior cache
// -----------------------------------------------------------------------------

#[test]
fn change_passphrase_success_zeroizes_old_key_and_passphrase() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        // Drain any observations from setup writes (the encrypt-pre-AEAD
        // pipeline records observations on every encrypted save).
        clear_observations();

        vault
            .change_passphrase(&store, cheap_options("hunter3"))
            .expect("change_passphrase commits");

        let obs = take_observations();
        let key_obs = key_drops(&obs);
        let pp_obs = passphrase_drops(&obs);
        assert_eq!(
            key_obs.len(),
            1,
            "exactly one cached-key drop on cache replacement, got {key_obs:?}",
        );
        assert!(
            key_obs[0].all_zero,
            "cached AEAD key bytes zeroized before deallocation",
        );
        assert_eq!(key_obs[0].original_len, 32, "AEAD key is 32 bytes");

        assert_eq!(
            pp_obs.len(),
            1,
            "exactly one cached-passphrase drop on cache replacement, got {pp_obs:?}",
        );
        assert!(
            pp_obs[0].all_zero,
            "cached passphrase bytes zeroized before deallocation",
        );
        assert_eq!(
            pp_obs[0].original_len,
            "hunter2".len(),
            "passphrase length matches OLD passphrase",
        );
    });
}

// -----------------------------------------------------------------------------
// remove_passphrase: success path zeroizes the prior cache
// -----------------------------------------------------------------------------

#[test]
fn remove_passphrase_success_zeroizes_old_key_and_passphrase() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options("hunter-zoo"))).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        clear_observations();
        vault.remove_passphrase(&store).expect("remove_passphrase");

        let obs = take_observations();
        let key_obs = key_drops(&obs);
        let pp_obs = passphrase_drops(&obs);
        assert_eq!(key_obs.len(), 1, "one key-drop, got {key_obs:?}");
        assert!(
            key_obs[0].all_zero,
            "cached AEAD key zeroized when remove drops the cache",
        );
        assert_eq!(pp_obs.len(), 1, "one passphrase-drop, got {pp_obs:?}");
        assert!(pp_obs[0].all_zero, "cached passphrase zeroized");
        assert_eq!(pp_obs[0].original_len, "hunter-zoo".len());
    });
}

// -----------------------------------------------------------------------------
// set_passphrase: starting state has no cache, so no cache-drop fires
// -----------------------------------------------------------------------------

#[test]
fn set_passphrase_does_not_observe_a_cache_drop_when_starting_plaintext() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        clear_observations();
        vault
            .set_passphrase(&store, cheap_options("hunter2"))
            .unwrap();

        let obs = take_observations();
        assert!(
            key_drops(&obs).is_empty(),
            "no prior cache to zeroize on set_passphrase from plaintext, saw {:?}",
            key_drops(&obs),
        );
        assert!(
            passphrase_drops(&obs).is_empty(),
            "no prior cache to zeroize, saw {:?}",
            passphrase_drops(&obs),
        );
    });
}

// -----------------------------------------------------------------------------
// Vault drop on its own zeroizes the cache (independent of transitions).
// -----------------------------------------------------------------------------

#[test]
fn dropping_an_encrypted_vault_zeroizes_cached_key_and_passphrase() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (vault, _store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
        clear_observations();
        drop(vault);

        let obs = take_observations();
        let key_obs = key_drops(&obs);
        let pp_obs = passphrase_drops(&obs);
        assert_eq!(key_obs.len(), 1, "one key-drop on Vault drop");
        assert!(key_obs[0].all_zero);
        assert_eq!(pp_obs.len(), 1, "one passphrase-drop on Vault drop");
        assert!(pp_obs[0].all_zero);
    });
}

// -----------------------------------------------------------------------------
// Open-side cache also zeroizes (covers the `from_payload_encrypted` path).
// -----------------------------------------------------------------------------

#[test]
fn dropping_a_reopened_encrypted_vault_zeroizes_cached_key_and_passphrase() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (vault, store) = Store::create(
            &path,
            VaultInit::Encrypted(cheap_options("a-very-long-passphrase")),
        )
        .unwrap();
        drop(vault);
        let _ = store;
        let (vault2, _store2) =
            Store::open(&path, VaultLock::Encrypted(pp("a-very-long-passphrase")))
                .expect("reopen with same passphrase");

        clear_observations();
        drop(vault2);

        let obs = take_observations();
        let key_obs = key_drops(&obs);
        let pp_obs = passphrase_drops(&obs);
        assert_eq!(key_obs.len(), 1);
        assert!(key_obs[0].all_zero);
        assert_eq!(pp_obs.len(), 1);
        assert!(pp_obs[0].all_zero);
        assert_eq!(pp_obs[0].original_len, "a-very-long-passphrase".len());
    });
}

// -----------------------------------------------------------------------------
// Pre-commit failure: cache is left in place, no cache-drop witnessed for the
// active vault during the rolled-back call. (Combined feature gate.)
// -----------------------------------------------------------------------------

#[cfg(feature = "test-fault-injection")]
#[test]
fn change_passphrase_pre_commit_does_not_zeroize_active_cache() {
    run_serial(|| {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).unwrap();

        clear_observations();
        std::env::set_var(FAULT_ENV, "pre_commit");
        let err = vault
            .change_passphrase(&store, cheap_options("hunter3"))
            .unwrap_err();
        std::env::remove_var(FAULT_ENV);
        assert_eq!(err.kind(), paladin_core::ErrorKind::SaveNotCommitted);

        let obs = take_observations();
        let active_key_drops: Vec<_> = key_drops(&obs)
            .into_iter()
            .filter(|o| o.original_len == 32)
            .collect();
        assert!(
            active_key_drops.is_empty(),
            "no active-cache key drop on pre-commit failure, saw {active_key_drops:?}",
        );
        assert!(vault.is_encrypted());
    });
}
