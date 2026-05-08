// SPDX-License-Identifier: AGPL-3.0-or-later
//
// AEAD key cache assertions (DESIGN.md §4.4 / Phase F.13).
//
// `Store::open` and `Store::create` derive the 32-byte AEAD key once
// via Argon2id and cache it on the returned `Vault`. Subsequent
// `Vault::save` calls must reuse the cached key without re-running
// Argon2id; otherwise every HOTP advance would pay another KDF run
// against the §4.4 cost defaults.
//
// Asserted deterministically via the `argon2_derivation_count` test
// hook exposed when the `test-fault-injection` cargo feature is on:
// every call to `argon2id_derive_key` increments a process-wide
// atomic, so a delta of zero across N saves proves the cache hit.
//
// Plaintext-vault no-cache and encrypted-vault has-cache shape
// invariants are pinned through the public `Vault::is_encrypted`
// getter (which inspects the same `Option<EncryptedCache>` field
// the cache machinery uses).

#![cfg(feature = "test-fault-injection")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    argon2_derivation_count, parse_otpauth, Account, Argon2Params, EncryptionOptions, Store,
    VaultInit, VaultLock,
};
use secrecy::SecretString;
use tempfile::TempDir;

// The Argon2id derivation counter is a process-wide static, so tests
// in this binary that read its delta must serialize. Other test
// binaries (e.g. `tests/encrypted_lifecycle.rs`) link their own
// instance of `paladin-core` and so cannot affect this counter.
static ARGON2_LOCK: Mutex<()> = Mutex::new(());

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn vault_test_dir() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod tempdir 0700");
    dir
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(
        SecretString::from(passphrase.to_string()),
        Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        },
    )
    .expect("cheap params are in §4.4 bounds and the passphrase is non-empty")
}

#[test]
fn save_after_create_does_not_re_run_argon2id() {
    let _guard = ARGON2_LOCK.lock().unwrap();
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");

    let baseline = argon2_derivation_count();
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).expect("create");
    let after_create = argon2_derivation_count();
    assert!(
        after_create > baseline,
        "create must run Argon2id at least once (baseline {baseline}, after_create {after_create})",
    );

    let pre_saves = argon2_derivation_count();
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).expect("first save");
    vault.add(make_account("bob", Some("Acme")));
    vault.save(&store).expect("second save");
    vault.add(make_account("carol", Some("Acme")));
    vault.save(&store).expect("third save");

    assert_eq!(
        argon2_derivation_count() - pre_saves,
        0,
        "Vault::save must reuse the cached AEAD key — no Argon2id re-runs after create",
    );
}

#[test]
fn save_after_open_does_not_re_run_argon2id() {
    let _guard = ARGON2_LOCK.lock().unwrap();
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");

    let (_vault, _store) = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2")))
        .expect("seed encrypted vault");

    let pre_open = argon2_derivation_count();
    let (mut vault, store) = Store::open(
        &path,
        VaultLock::Encrypted(SecretString::from("hunter2".to_string())),
    )
    .expect("re-open");
    let after_open = argon2_derivation_count();
    assert!(
        after_open - pre_open >= 1,
        "open must run Argon2id once (delta {})",
        after_open - pre_open,
    );

    let pre_saves = argon2_derivation_count();
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).expect("first save");
    vault.add(make_account("bob", Some("Acme")));
    vault.save(&store).expect("second save");

    assert_eq!(
        argon2_derivation_count() - pre_saves,
        0,
        "Vault::save must reuse the cached AEAD key — no Argon2id re-runs after open",
    );
}

#[test]
fn plaintext_vault_holds_no_cached_key_or_passphrase() {
    // F.13 — plaintext vaults must not carry an `EncryptedCache`. The
    // public `Vault::is_encrypted()` projection inspects the same
    // `Option<EncryptedCache>` field the cache machinery uses, so a
    // `false` return here proves the field is `None` for plaintext
    // mode. A regression that retained a stale cache from a prior
    // encrypted session would surface as `is_encrypted() == true`
    // here.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).expect("plaintext create");
    assert!(
        !vault.is_encrypted(),
        "plaintext vault must hold no cached AEAD key or passphrase",
    );
}

#[test]
fn encrypted_vault_holds_cached_key_and_passphrase() {
    // F.13 complement: an encrypted vault must carry the cache so
    // saves can reuse the derived AEAD key. Without this, the
    // counter-based reuse tests above would silently pass when the
    // cache field was unconditionally `None`.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).expect("create");
    assert!(
        vault.is_encrypted(),
        "encrypted vault must carry an AEAD-key + passphrase cache",
    );
}
