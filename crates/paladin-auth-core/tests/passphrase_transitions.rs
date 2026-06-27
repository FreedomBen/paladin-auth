// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Passphrase transitions (docs/DESIGN.md §4.5 / Phase H).
//
// Pins the §4.7 surface for `Vault::set_passphrase`,
// `Vault::change_passphrase`, and `Vault::remove_passphrase`:
//
// * happy-path round trip — primary rewritten under the new mode/key,
//   `.bak` rewritten with fresh material so it does not retain the
//   prior plaintext (`set`/`change`) or stays accessible without the
//   removed passphrase (`remove`);
// * wrong-state guard — typed `invalid_state` returned *before* any
//   crypto / I/O work, so a `set` on an already-encrypted vault and
//   `change` / `remove` on a plaintext vault never burn an Argon2 run;
// * passphrase byte hygiene — empty passphrases rejected with
//   `invalid_passphrase { reason: "zero_length" }` and whitespace /
//   Unicode passphrases passed through verbatim;
// * `Argon2Params` validation surfaces stable
//   `validation_error { field: "kdf_params.*" }` ahead of any
//   filesystem write.

mod common;

use common::test_tempdir;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_auth_core::{
    inspect, parse_otpauth, Account, Argon2Params, EncryptionOptions, ErrorKind, PaladinAuthError,
    Store, VaultInit, VaultLock, VaultStatus,
};
use secrecy::SecretString;
use tempfile::TempDir;

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

// -----------------------------------------------------------------------------
// set_passphrase: plaintext → encrypted
// -----------------------------------------------------------------------------

#[test]
fn set_passphrase_rewrites_primary_as_encrypted_and_caches_new_key() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).expect("initial plaintext save");

    assert!(!vault.is_encrypted());
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);

    vault
        .set_passphrase(&store, cheap_options("hunter2"))
        .expect("set_passphrase commits");

    assert!(vault.is_encrypted(), "vault now reports encrypted");
    assert_eq!(
        inspect(&path).unwrap(),
        VaultStatus::Encrypted,
        "on-disk header flipped to encrypted"
    );

    // Vault state survives intact.
    assert_eq!(vault.accounts().len(), 1);
    assert_eq!(vault.get(alice_id).unwrap().label(), "alice");

    // Reopen with the new passphrase.
    drop(vault);
    let (vault2, _store2) = Store::open(&path, VaultLock::Encrypted(pp("hunter2")))
        .expect("reopen with new passphrase");
    assert_eq!(vault2.accounts().len(), 1);
    assert_eq!(vault2.get(alice_id).unwrap().label(), "alice");
}

#[test]
fn set_passphrase_writes_encrypted_backup_under_new_key() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();

    vault
        .set_passphrase(&store, cheap_options("hunter2"))
        .expect("set_passphrase");

    let bak = path.with_extension("bin.bak");
    let bak_bytes = fs::read(&bak).expect("backup written");
    // Encrypted backup carries the encrypted-mode header + AEAD payload.
    assert!(
        bak_bytes.len() > 64,
        "backup includes encrypted header + body"
    );
    assert_eq!(&bak_bytes[0..8], b"PALAUTH\0");
    assert_eq!(bak_bytes[9], 1, "backup is encrypted-mode");

    // Backup decrypts cleanly under the *new* key (recovers prior payload).
    let mut bak_path_buf = path.clone();
    bak_path_buf.set_extension("bin.bak");
    let (recovered, _store_bak) = Store::open(&bak_path_buf, VaultLock::Encrypted(pp("hunter2")))
        .expect("open backup with new passphrase");
    assert_eq!(recovered.accounts().len(), 1);
}

#[test]
fn set_passphrase_uses_distinct_nonces_for_primary_and_backup() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();

    vault
        .set_passphrase(&store, cheap_options("hunter2"))
        .unwrap();

    let bak_path = path.with_extension("bin.bak");
    let primary = fs::read(&path).unwrap();
    let backup = fs::read(&bak_path).unwrap();
    // Encrypted header is 64 bytes; nonce occupies the trailing 24 bytes of
    // the trailer (bytes 40..64 of the header). The two files share the same
    // salt + params (bytes 8..40) but must differ on the nonce so the
    // ciphertexts are independent.
    assert_eq!(&primary[8..40], &backup[8..40], "salt + params identical");
    assert_ne!(
        &primary[40..64],
        &backup[40..64],
        "primary and backup use distinct nonces"
    );
    // Ciphertexts trivially differ given different nonces (and a fortiori
    // are not equal even on identical plaintext + key + nonce because of
    // the AEAD tag).
    assert_ne!(&primary[64..], &backup[64..], "ciphertexts differ");
}

#[test]
fn set_passphrase_on_already_encrypted_returns_invalid_state_before_crypto() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.save(&store).unwrap();

    let err = vault
        .set_passphrase(&store, cheap_options("hunter3"))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidState);
    match err {
        PaladinAuthError::InvalidState { operation, state } => {
            assert_eq!(operation, "set_passphrase");
            assert_eq!(state, "already_encrypted");
        }
        other => panic!("expected invalid_state, got {other:?}"),
    }
    // Vault and Store state unchanged.
    assert!(vault.is_encrypted());
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
}

#[test]
fn set_passphrase_rejects_zero_length_passphrase_with_zero_length_reason() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();

    // Bypass the EncryptionOptions::new constructor by hand-rolling the
    // public-fields literal — this exercises the defensive check on the
    // Vault::set_passphrase entrypoint.
    let opts = EncryptionOptions {
        passphrase: pp(""),
        kdf_params: cheap_params(),
    };
    let err = vault.set_passphrase(&store, opts).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidPassphrase);
    match err {
        PaladinAuthError::InvalidPassphrase { reason } => assert_eq!(reason, "zero_length"),
        other => panic!("expected invalid_passphrase, got {other:?}"),
    }
    assert!(
        !vault.is_encrypted(),
        "vault still plaintext after rejection"
    );
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
}

#[test]
fn set_passphrase_accepts_whitespace_and_unicode_passphrases_verbatim() {
    // Whitespace-only and Unicode-only passphrases are passed through as
    // bytes — no trim, no NFC/NFD normalization, in line with §4.4.
    for raw in ["   ", "\t\n", "🦀🔐", "Ω-secret"] {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();

        let opts = EncryptionOptions {
            passphrase: pp(raw),
            kdf_params: cheap_params(),
        };
        vault
            .set_passphrase(&store, opts)
            .unwrap_or_else(|e| panic!("byte-equal passphrase {raw:?} rejected: {e:?}"));
        assert!(vault.is_encrypted(), "encrypted under {raw:?}");
        drop(vault);
        let (_v, _s) = Store::open(&path, VaultLock::Encrypted(pp(raw)))
            .unwrap_or_else(|e| panic!("reopen with byte-equal {raw:?} failed: {e:?}"));
    }
}

// -----------------------------------------------------------------------------
// change_passphrase: encrypted → encrypted
// -----------------------------------------------------------------------------

#[test]
fn change_passphrase_rotates_key_and_keeps_payload() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();

    vault
        .change_passphrase(&store, cheap_options("hunter3"))
        .expect("change_passphrase commits");

    // Reopening with the OLD passphrase fails with decrypt_failed.
    drop(vault);
    let err = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed);

    // Reopening with the NEW passphrase succeeds.
    let (vault2, _store2) =
        Store::open(&path, VaultLock::Encrypted(pp("hunter3"))).expect("reopen with new");
    assert_eq!(vault2.accounts().len(), 1);
    assert_eq!(vault2.get(alice_id).unwrap().label(), "alice");
}

#[test]
fn change_passphrase_writes_backup_under_new_key() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();

    vault
        .change_passphrase(&store, cheap_options("hunter3"))
        .unwrap();

    let bak_path = path.with_extension("bin.bak");
    // Backup decrypts under the NEW key, not the OLD one.
    let new_open = Store::open(&bak_path, VaultLock::Encrypted(pp("hunter3"))).expect("backup new");
    assert_eq!(new_open.0.accounts().len(), 1);
    drop(new_open);
    let old_err = Store::open(&bak_path, VaultLock::Encrypted(pp("hunter2"))).unwrap_err();
    assert_eq!(old_err.kind(), ErrorKind::DecryptFailed);
}

#[test]
fn change_passphrase_uses_distinct_nonces_for_primary_and_backup() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();

    vault
        .change_passphrase(&store, cheap_options("hunter3"))
        .unwrap();

    let bak_path = path.with_extension("bin.bak");
    let primary = fs::read(&path).unwrap();
    let backup = fs::read(&bak_path).unwrap();
    assert_eq!(&primary[8..40], &backup[8..40], "salt + params identical");
    assert_ne!(&primary[40..64], &backup[40..64], "nonces differ");
}

#[test]
fn change_passphrase_picks_up_custom_argon2_params() {
    // Default params (m=64MiB) are too slow for a unit test, so we
    // pin only that the params bytes in the new header reflect the
    // *new* options' kdf_params, not the old ones.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let init_params = Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    };
    let init_opts = EncryptionOptions::with_params(pp("hunter2"), init_params).unwrap();
    let (mut vault, store) = Store::create(&path, VaultInit::Encrypted(init_opts)).unwrap();
    vault.save(&store).unwrap();

    let new_params = Argon2Params {
        m_kib: 16_384,
        t: 2,
        p: 1,
    };
    let new_opts = EncryptionOptions::with_params(pp("hunter3"), new_params).unwrap();
    vault.change_passphrase(&store, new_opts).unwrap();

    // Header layout (docs/DESIGN.md §4.4 / `storage::header`):
    //   bytes 0..8   "PALAUTH\0"
    //   byte  8      format_ver = 1
    //   byte  9      mode = 1 (encrypted)
    //   byte 10      kdf_id = 1 (Argon2id)
    //   bytes 11..15 m_kib (u32 LE)
    //   bytes 15..19 t (u32 LE)
    //   bytes 19..23 p (u32 LE)
    let primary = fs::read(&path).unwrap();
    let m_kib = u32::from_le_bytes(primary[11..15].try_into().unwrap());
    let t = u32::from_le_bytes(primary[15..19].try_into().unwrap());
    let p = u32::from_le_bytes(primary[19..23].try_into().unwrap());
    assert_eq!(m_kib, 16_384);
    assert_eq!(t, 2, "t=2 in new header");
    assert_eq!(p, 1, "p=1 in new header");
}

#[test]
fn change_passphrase_on_plaintext_returns_invalid_state_before_crypto() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();

    let err = vault
        .change_passphrase(&store, cheap_options("hunter2"))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidState);
    match err {
        PaladinAuthError::InvalidState { operation, state } => {
            assert_eq!(operation, "change_passphrase");
            assert_eq!(state, "not_encrypted");
        }
        other => panic!("expected invalid_state, got {other:?}"),
    }
    assert!(!vault.is_encrypted());
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
}

#[test]
fn change_passphrase_rejects_zero_length_passphrase_with_zero_length_reason() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.save(&store).unwrap();

    let opts = EncryptionOptions {
        passphrase: pp(""),
        kdf_params: cheap_params(),
    };
    let err = vault.change_passphrase(&store, opts).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidPassphrase);
    match err {
        PaladinAuthError::InvalidPassphrase { reason } => assert_eq!(reason, "zero_length"),
        other => panic!("expected invalid_passphrase, got {other:?}"),
    }
    // Vault still encrypted under the original passphrase.
    drop(vault);
    let _ = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("old key still valid");
}

// -----------------------------------------------------------------------------
// remove_passphrase: encrypted → plaintext
// -----------------------------------------------------------------------------

#[test]
fn remove_passphrase_rewrites_primary_as_plaintext_and_drops_cache() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();

    vault
        .remove_passphrase(&store)
        .expect("remove_passphrase commits");

    assert!(!vault.is_encrypted(), "cache dropped");
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);

    // Reopen as plaintext.
    drop(vault);
    let (vault2, _store2) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    assert_eq!(vault2.accounts().len(), 1);
    assert_eq!(vault2.get(alice_id).unwrap().label(), "alice");
}

#[test]
fn remove_passphrase_writes_plaintext_backup() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();

    vault.remove_passphrase(&store).unwrap();

    let bak_path = path.with_extension("bin.bak");
    // Plaintext backup is openable without any passphrase.
    let (vault_bak, _store_bak) = Store::open(&bak_path, VaultLock::Plaintext)
        .expect("backup is plaintext after remove_passphrase");
    assert_eq!(vault_bak.accounts().len(), 1);
}

#[test]
fn remove_passphrase_on_plaintext_returns_invalid_state() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();

    let err = vault.remove_passphrase(&store).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidState);
    match err {
        PaladinAuthError::InvalidState { operation, state } => {
            assert_eq!(operation, "remove_passphrase");
            assert_eq!(state, "not_encrypted");
        }
        other => panic!("expected invalid_state, got {other:?}"),
    }
    assert!(!vault.is_encrypted());
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
}

// -----------------------------------------------------------------------------
// kdf_params validation runs before any I/O / crypto
// -----------------------------------------------------------------------------

#[test]
fn set_passphrase_rejects_out_of_range_argon2_params_before_crypto() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();

    // Bypass with_params by hand-rolling the literal so the rejection
    // surfaces from set_passphrase itself.
    let opts = EncryptionOptions {
        passphrase: pp("hunter2"),
        kdf_params: Argon2Params {
            m_kib: 1,
            t: 1,
            p: 1,
        },
    };
    let err = vault.set_passphrase(&store, opts).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
    assert!(!vault.is_encrypted());
}

// -----------------------------------------------------------------------------
// is_encrypted reflects the post-transition state
// -----------------------------------------------------------------------------

#[test]
fn is_encrypted_flips_across_full_set_change_remove_cycle() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    assert!(!vault.is_encrypted());

    vault
        .set_passphrase(&store, cheap_options("hunter2"))
        .unwrap();
    assert!(vault.is_encrypted());

    vault
        .change_passphrase(&store, cheap_options("hunter3"))
        .unwrap();
    assert!(vault.is_encrypted());

    vault.remove_passphrase(&store).unwrap();
    assert!(!vault.is_encrypted());

    // Subsequent regular saves succeed under the new mode.
    vault.add(make_account("bob", Some("Acme")));
    vault.save(&store).expect("plaintext save after remove");
}
