// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration tests for the encrypted-mode `Store::open` /
// `Store::create` / `Store::create_force` / `Vault::save` round-trip
// (DESIGN.md §4.3 + §4.4).
//
// Tests use the cheapest in-bounds Argon2 params (`m_kib=8192 / t=1 /
// p=1`) so the suite stays under a few seconds. The §4.4 acceptance
// floor enforces `m_kib >= 8192`.

mod common;

use common::test_tempdir;

use std::fs;
use std::io::Write;
use std::os::unix::fs as unix_fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    inspect, parse_otpauth, Account, Argon2Params, EncryptionOptions, ErrorKind, PaladinError,
    PermissionSubject, SettingPatch, Store, VaultInit, VaultLock, VaultMode, VaultStatus,
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

/// Cheap in-bounds Argon2 params so the test suite finishes quickly.
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

#[test]
fn encrypted_create_writes_64_byte_encrypted_header_with_payload() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (_v, _store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).expect("create");
    let bytes = fs::read(&path).expect("read on-disk vault");
    // Header magic + format_ver + mode + KDF/AEAD trailer.
    assert!(bytes.len() > 64);
    assert_eq!(&bytes[0..8], b"PALADIN\0");
    assert_eq!(bytes[8], 1, "format_ver");
    assert_eq!(bytes[9], 1, "encrypted-mode discriminator");
    // The payload region is at least the 16-byte AEAD tag.
    assert!(bytes.len() >= 64 + 16);
}

#[test]
fn encrypted_create_marks_inspect_as_encrypted() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let _ = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
}

#[test]
fn encrypted_open_round_trips_empty_vault() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    drop(vault);
    let (vault2, _store2) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
    assert!(vault2.accounts().is_empty());
    assert!(vault2.is_encrypted());
}

#[test]
fn non_default_vault_settings_survive_encrypted_save_and_reopen() {
    // Encrypted-path complement to
    // `non_default_vault_settings_survive_plaintext_save_and_reopen`
    // in `tests/vault_lifecycle.rs`. The encrypted save path encodes
    // the settings inside the AEAD plaintext payload; this pins that
    // a regression dropping a settings field from `VaultPayload` would
    // be caught for the encrypted mode too, not only plaintext.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault
        .apply_setting_patch(SettingPatch::AutoLockEnabled(true))
        .unwrap();
    vault
        .apply_setting_patch(SettingPatch::AutoLockTimeoutSecs(900))
        .unwrap();
    vault
        .apply_setting_patch(SettingPatch::ClipboardClearEnabled(true))
        .unwrap();
    vault
        .apply_setting_patch(SettingPatch::ClipboardClearSecs(45))
        .unwrap();
    vault.save(&store).expect("encrypted save");
    drop(vault);
    drop(store);

    let (reopened, _store) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
    assert!(reopened.is_encrypted());
    assert!(reopened.settings().auto_lock_enabled());
    assert_eq!(reopened.settings().auto_lock_timeout_secs(), 900);
    assert!(reopened.settings().clipboard_clear_enabled());
    assert_eq!(reopened.settings().clipboard_clear_secs(), 45);
}

#[test]
fn encrypted_save_reopen_preserves_account_insertion_order() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.add(make_account("alice", Some("Acme")));
    vault.add(make_account("bob", Some("Acme")));
    vault.add(make_account("carol", None));
    vault.save(&store).expect("encrypted save");
    drop(vault);
    drop(store);

    let (reopened, _store2) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
    assert_eq!(reopened.accounts().len(), 3);
    assert_eq!(reopened.accounts()[0].label(), "alice");
    assert_eq!(reopened.accounts()[1].label(), "bob");
    assert_eq!(reopened.accounts()[2].label(), "carol");
}

#[test]
fn encrypted_reopen_with_wrong_passphrase_returns_decrypt_failed() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let _ = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let err = Store::open(&path, VaultLock::Encrypted(pp("WRONG"))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed);
}

#[test]
fn encrypted_file_opened_with_plaintext_lock_returns_wrong_vault_lock() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let _ = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::WrongVaultLock { expected, actual } => {
            assert_eq!(expected, VaultMode::Plaintext);
            assert_eq!(actual, VaultMode::Encrypted);
        }
        other => panic!("expected WrongVaultLock, got {other:?}"),
    }
}

#[test]
fn plaintext_file_opened_with_encrypted_lock_returns_wrong_vault_lock() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).expect("plaintext save");
    drop(vault);
    drop(store);

    let err = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap_err();
    match err {
        PaladinError::WrongVaultLock { expected, actual } => {
            assert_eq!(expected, VaultMode::Encrypted);
            assert_eq!(actual, VaultMode::Plaintext);
        }
        other => panic!("expected WrongVaultLock, got {other:?}"),
    }
}

#[test]
fn encrypted_create_rejects_when_primary_already_exists() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let _ = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let err = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultExists);
}

#[test]
fn encrypted_create_force_overwrites_existing_plaintext_primary() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    {
        let (v, s) = Store::create(&path, VaultInit::Plaintext).unwrap();
        v.save(&s).expect("plaintext save");
    }
    // Clobber with encrypted vault.
    let _ = Store::create_force(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
    let (vault2, _) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
    assert!(vault2.accounts().is_empty());
}

#[test]
fn encrypted_open_rejects_oversized_file_before_aead_work() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    // Manually write a "vault" larger than the 64-byte encrypted
    // header + 16 MiB max payload + 16 byte AEAD tag cap. The bytes
    // after the header cannot decrypt to anything (no key was used);
    // the size cap must reject before any AEAD/KDF work.
    let mut bytes = Vec::with_capacity(64 + 17 * 1024 * 1024);
    bytes.extend_from_slice(b"PALADIN\0");
    bytes.push(1); // format_ver
    bytes.push(1); // mode = encrypted
    bytes.push(1); // kdf_id = Argon2id
    bytes.extend_from_slice(&8_192u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&[0xAB; 16]); // salt
    bytes.push(1); // aead_id
    bytes.extend_from_slice(&[0xCD; 24]); // nonce
    assert_eq!(bytes.len(), 64);
    bytes.resize(64 + 17 * 1024 * 1024, 0); // 17 MiB body — over the cap.
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(&bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let err = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);
    match err {
        PaladinError::InvalidPayload { reason } => assert_eq!(reason, "exceeds_size_limit"),
        other => panic!("expected InvalidPayload, got {other:?}"),
    }
}

#[test]
fn encrypted_save_reuses_argon2_key_without_re_deriving() {
    // We cannot directly observe re-derivation, but the Phase F.3
    // contract is that save uses the cached key. Asserting that two
    // back-to-back saves succeed without a passphrase prompt — and
    // that the on-disk file remains decryptable — is the closest
    // black-box check available at this layer.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();
    vault.add(make_account("bob", Some("Acme")));
    vault.save(&store).unwrap();
    drop(vault);
    let (reopened, _) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
    assert_eq!(reopened.accounts().len(), 2);
}

// ──────────────────────────────────────────────────────────────────
// Phase G.11 — `Vault::is_encrypted()` matrix.
//
// Four explicit rows cover the §4.7 axis cross-product so a refactor
// that breaks the cache-presence projection cannot pass quietly:
//   * `VaultInit::Plaintext`              via `Store::create`  → false
//   * `VaultInit::Encrypted`              via `Store::create`  → true
//   * `VaultLock::Plaintext`              via `Store::open`    → false
//   * `VaultLock::Encrypted(passphrase)`  via `Store::open`    → true
//
// Phase H exercises the `set_passphrase` / `change_passphrase` /
// `remove_passphrase` transition cases (unchanged on
// `save_not_committed`, flipped on success or
// `save_durability_unconfirmed`) against this same getter.
// ──────────────────────────────────────────────────────────────────

#[test]
fn plaintext_create_reports_is_encrypted_false() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _) = Store::create(&path, VaultInit::Plaintext).unwrap();
    assert!(!vault.is_encrypted());
}

#[test]
fn encrypted_create_reports_is_encrypted_true() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _) = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    assert!(vault.is_encrypted());
}

#[test]
fn plaintext_open_reports_is_encrypted_false() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);

    let (reopened, _) = Store::open(&path, VaultLock::Plaintext).unwrap();
    assert!(!reopened.is_encrypted());
}

#[test]
fn encrypted_open_reports_is_encrypted_true() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.save(&store).unwrap();
    drop(vault);

    let (reopened, _) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
    assert!(reopened.is_encrypted());
}

// ──────────────────────────────────────────────────────────────────
// Phase F.17 — encrypted `create` / `create_force` semantic parity
// with plaintext storage. Each row mirrors a plaintext bullet from
// Phase E (precondition, parent-permission, staged-clobber). The
// commit-point and durability-error rows live in
// `tests/fault_injection.rs` because they require the
// `test-fault-injection` cargo feature.
// ──────────────────────────────────────────────────────────────────

#[test]
fn encrypted_create_rejects_when_parent_directory_grants_group_or_other() {
    let dir = vault_test_dir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("vault.bin");
    let err = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap_err();
    match err {
        PaladinError::UnsafePermissions {
            subject,
            actual_mode,
            expected_mode,
            ..
        } => {
            assert_eq!(subject, PermissionSubject::VaultDir);
            assert_eq!(actual_mode, "0755");
            assert_eq!(expected_mode, "0700");
        }
        other => panic!("expected UnsafePermissions, got {other:?}"),
    }
    assert!(
        !path.exists(),
        "encrypted create must reject before writing"
    );
}

#[test]
fn encrypted_create_succeeds_when_parent_directory_is_0700() {
    let dir = vault_test_dir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("vault.bin");
    let _ = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    assert!(path.exists());
}

#[test]
fn encrypted_create_rejects_when_parent_directory_is_symlink() {
    let real_dir = vault_test_dir();
    let link_root = vault_test_dir();
    let link_path = link_root.path().join("link");
    unix_fs::symlink(real_dir.path(), &link_path).unwrap();

    let path = link_path.join("vault.bin");
    let err = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "vault_dir_is_symlink"),
        other => panic!("expected vault_dir_is_symlink io_error, got {other:?}"),
    }
    assert!(!real_dir.path().join("vault.bin").exists());
}

#[test]
fn encrypted_create_force_rejects_when_parent_directory_grants_group_or_other() {
    let dir = vault_test_dir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("vault.bin");
    let err =
        Store::create_force(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap_err();
    match err {
        PaladinError::UnsafePermissions {
            subject,
            actual_mode,
            expected_mode,
            ..
        } => {
            assert_eq!(subject, PermissionSubject::VaultDir);
            assert_eq!(actual_mode, "0755");
            assert_eq!(expected_mode, "0700");
        }
        other => panic!("expected UnsafePermissions, got {other:?}"),
    }
    assert!(
        !path.exists(),
        "encrypted create_force must reject before writing"
    );
    assert!(!dir.path().join("vault.bin.tmp").exists());
}

#[test]
fn encrypted_create_force_writes_primary_with_0600_permissions() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let _ = Store::create_force(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "encrypted create_force must write the primary 0600",
    );
}

#[test]
fn encrypted_create_force_with_no_existing_primary_writes_fresh_vault() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) =
        Store::create_force(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    assert!(
        path.exists(),
        "encrypted create_force must write the primary"
    );
    assert!(
        !dir.path().join("vault.bin.bak").exists(),
        "no prior primary → no rotation → no .bak"
    );
    assert!(!dir.path().join("vault.bin.tmp").exists());
    drop(vault);
    drop(store);

    let (reopened, _) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap();
    assert!(reopened.accounts().is_empty());
    assert!(reopened.is_encrypted());
}

#[test]
fn encrypted_create_force_rotates_existing_encrypted_primary_to_bak_verbatim() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.add(make_account("alice", None));
    vault.add(make_account("bob", None));
    vault.save(&store).unwrap();
    let pre_clobber_primary = fs::read(&path).unwrap();
    drop(vault);
    drop(store);

    // Clobber with a fresh encrypted vault under a different passphrase
    // so the new ciphertext cannot collide with the old by accident.
    let (clobbered, _) =
        Store::create_force(&path, VaultInit::Encrypted(cheap_options("rotated"))).unwrap();
    let bak = dir.path().join("vault.bin.bak");
    assert!(
        bak.exists(),
        "encrypted create_force must rotate prior primary → .bak",
    );
    assert_eq!(
        fs::read(&bak).unwrap(),
        pre_clobber_primary,
        ".bak must hold the pre-clobber encrypted primary verbatim (no re-encryption)",
    );
    // The new primary differs from the old (fresh salt + nonce + key).
    assert_ne!(fs::read(&path).unwrap(), pre_clobber_primary);
    assert!(clobbered.accounts().is_empty());
    assert!(clobbered.is_encrypted());
    assert!(!dir.path().join("vault.bin.tmp").exists());
    assert!(!dir.path().join("vault.bin.bak.tmp").exists());
}

#[test]
fn encrypted_create_force_overwrites_existing_backup_during_rotation() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.save(&store).unwrap();
    vault.save(&store).unwrap(); // produces a real .bak from the regular-save path
    drop(vault);
    drop(store);

    let bak = dir.path().join("vault.bin.bak");
    let pre_primary = fs::read(&path).unwrap();
    fs::write(&bak, b"poisoned previous backup").unwrap();
    fs::set_permissions(&bak, fs::Permissions::from_mode(0o600)).unwrap();

    let _ = Store::create_force(&path, VaultInit::Encrypted(cheap_options("rotated"))).unwrap();
    let new_bak = fs::read(&bak).unwrap();
    assert_eq!(
        new_bak, pre_primary,
        ".bak must be the rotated pre-clobber primary, overwriting any prior backup",
    );
    assert_ne!(new_bak, b"poisoned previous backup".to_vec());
}

#[test]
fn encrypted_create_force_rejects_when_existing_primary_is_symlink() {
    let dir = vault_test_dir();
    let victim = dir.path().join("victim.bin");
    fs::write(&victim, b"victim contents").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();

    let path = dir.path().join("vault.bin");
    unix_fs::symlink(&victim, &path).unwrap();

    let err =
        Store::create_force(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "vault_file_is_symlink"),
        other => panic!("expected vault_file_is_symlink io_error, got {other:?}"),
    }

    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
    assert!(!dir.path().join("vault.bin.tmp").exists());
    assert!(!dir.path().join("vault.bin.bak").exists());
}
