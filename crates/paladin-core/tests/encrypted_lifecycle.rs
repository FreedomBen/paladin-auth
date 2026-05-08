// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration tests for the encrypted-mode `Store::open` /
// `Store::create` / `Store::create_force` / `Vault::save` round-trip
// (DESIGN.md §4.3 + §4.4).
//
// Tests use the cheapest in-bounds Argon2 params (`m_kib=8192 / t=1 /
// p=1`) so the suite stays under a few seconds. The §4.4 acceptance
// floor enforces `m_kib >= 8192`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    inspect, parse_otpauth, Account, Argon2Params, EncryptionOptions, ErrorKind, PaladinError,
    Store, VaultInit, VaultLock, VaultMode, VaultStatus,
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
    let dir = TempDir::new().expect("create tempdir");
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

#[test]
fn plaintext_vault_reports_is_encrypted_false() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _) = Store::create(&path, VaultInit::Plaintext).unwrap();
    assert!(!vault.is_encrypted());
}

#[test]
fn encrypted_vault_reports_is_encrypted_true() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _) = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    assert!(vault.is_encrypted());
}
