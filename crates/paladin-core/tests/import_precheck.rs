// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.7 — `classify_paladin_import_precheck` (docs/DESIGN.md §4.6 / §4.7).

#![cfg(unix)]

mod common;

use common::test_tempdir;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    classify_paladin_import_precheck, parse_otpauth, Account, Argon2Params, EncryptionOptions,
    ImportFormat, PaladinError, PaladinImportPrecheck, Store, VaultInit,
};
use secrecy::SecretString;
use tempfile::TempDir;

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(
        pp(passphrase),
        Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        },
    )
    .unwrap()
}

fn vault_test_dir() -> TempDir {
    let dir = test_tempdir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn make_account(uri: &str) -> Account {
    parse_otpauth(uri, import_time()).unwrap().account
}

fn write_encrypted_paladin(dir: &TempDir, name: &str, passphrase: &str) -> PathBuf {
    let path = dir.path().join(name);
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options(passphrase))).unwrap();
    let _ = vault.add(make_account("otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP"));
    vault.save(&store).unwrap();
    path
}

fn write_plaintext_paladin(dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account("otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP"));
    vault.save(&store).unwrap();
    path
}

// ---------- Forced non-paladin formats ----------

#[test]
fn forced_otpauth_returns_no_prompt_without_probing() {
    // Even on a path that doesn't exist — forced non-paladin formats
    // never read the file, so missing paths are fine.
    let dir = test_tempdir();
    let path = dir.path().join("does-not-exist");
    let result = classify_paladin_import_precheck(&path, Some(ImportFormat::Otpauth));
    assert!(matches!(result, PaladinImportPrecheck::NoPrompt));
}

#[test]
fn forced_aegis_returns_no_prompt() {
    let dir = test_tempdir();
    let path = dir.path().join("does-not-exist");
    let result = classify_paladin_import_precheck(&path, Some(ImportFormat::Aegis));
    assert!(matches!(result, PaladinImportPrecheck::NoPrompt));
}

#[test]
fn forced_qr_returns_no_prompt() {
    let dir = test_tempdir();
    let path = dir.path().join("does-not-exist");
    let result = classify_paladin_import_precheck(&path, Some(ImportFormat::QrImage));
    assert!(matches!(result, PaladinImportPrecheck::NoPrompt));
}

// ---------- Auto-detect ----------

#[test]
fn auto_detect_encrypted_paladin_returns_prompt_for_passphrase() {
    let dir = vault_test_dir();
    let path = write_encrypted_paladin(&dir, "vault.bin", "hunter2");
    let result = classify_paladin_import_precheck(&path, None);
    assert!(matches!(result, PaladinImportPrecheck::PromptForPassphrase));
}

#[test]
fn forced_paladin_encrypted_header_returns_prompt_for_passphrase() {
    let dir = vault_test_dir();
    let path = write_encrypted_paladin(&dir, "vault.bin", "hunter2");
    let result = classify_paladin_import_precheck(&path, Some(ImportFormat::Paladin));
    assert!(matches!(result, PaladinImportPrecheck::PromptForPassphrase));
}

#[test]
fn auto_detect_plaintext_paladin_returns_reject_unsupported_plaintext_vault() {
    let dir = vault_test_dir();
    let path = write_plaintext_paladin(&dir, "vault.bin");
    let result = classify_paladin_import_precheck(&path, None);
    let PaladinImportPrecheck::Reject(err) = result else {
        panic!("expected Reject");
    };
    assert!(matches!(err, PaladinError::UnsupportedPlaintextVault));
}

#[test]
fn forced_paladin_plaintext_returns_reject_unsupported_plaintext_vault() {
    let dir = vault_test_dir();
    let path = write_plaintext_paladin(&dir, "vault.bin");
    let result = classify_paladin_import_precheck(&path, Some(ImportFormat::Paladin));
    let PaladinImportPrecheck::Reject(err) = result else {
        panic!("expected Reject");
    };
    assert!(matches!(err, PaladinError::UnsupportedPlaintextVault));
}

// ---------- Malformed Paladin magic ----------

#[test]
fn paladin_magic_with_unsupported_format_version_returns_reject() {
    let dir = test_tempdir();
    let path = dir.path().join("malformed.bin");
    let mut bytes = b"PALADIN\0".to_vec();
    bytes.push(99); // bogus format_ver
    bytes.push(1); // mode encrypted
    bytes.extend_from_slice(&[0; 100]);
    fs::write(&path, &bytes).unwrap();
    let result = classify_paladin_import_precheck(&path, None);
    let PaladinImportPrecheck::Reject(err) = result else {
        panic!("expected Reject");
    };
    assert!(matches!(
        err,
        PaladinError::UnsupportedFormatVersion { format_ver: 99 }
    ));
}

#[test]
fn paladin_magic_with_unknown_mode_returns_reject_invalid_header() {
    let dir = test_tempdir();
    let path = dir.path().join("malformed.bin");
    let mut bytes = b"PALADIN\0".to_vec();
    bytes.push(1); // valid format_ver
    bytes.push(99); // bogus mode
    bytes.extend_from_slice(&[0; 100]);
    fs::write(&path, &bytes).unwrap();
    let result = classify_paladin_import_precheck(&path, None);
    let PaladinImportPrecheck::Reject(err) = result else {
        panic!("expected Reject");
    };
    assert!(matches!(err, PaladinError::InvalidHeader));
}

#[test]
fn paladin_magic_truncated_below_header_length_returns_reject_invalid_header() {
    let dir = test_tempdir();
    let path = dir.path().join("trunc.bin");
    fs::write(&path, b"PALADIN\0").unwrap(); // exactly 8 bytes — magic only
    let result = classify_paladin_import_precheck(&path, None);
    let PaladinImportPrecheck::Reject(err) = result else {
        panic!("expected Reject");
    };
    assert!(matches!(err, PaladinError::InvalidHeader));
}

// ---------- Non-paladin / missing / unreadable ----------

#[test]
fn missing_file_returns_no_prompt() {
    let dir = test_tempdir();
    let path = dir.path().join("nope.bin");
    let result = classify_paladin_import_precheck(&path, None);
    assert!(matches!(result, PaladinImportPrecheck::NoPrompt));
}

#[test]
fn non_paladin_magic_returns_no_prompt() {
    let dir = test_tempdir();
    let path = dir.path().join("not_paladin.bin");
    fs::write(&path, b"otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP").unwrap();
    let result = classify_paladin_import_precheck(&path, None);
    assert!(matches!(result, PaladinImportPrecheck::NoPrompt));
}

#[test]
fn empty_file_returns_no_prompt() {
    let dir = test_tempdir();
    let path = dir.path().join("empty.bin");
    fs::write(&path, b"").unwrap();
    let result = classify_paladin_import_precheck(&path, None);
    assert!(matches!(result, PaladinImportPrecheck::NoPrompt));
}

#[test]
fn unreadable_file_returns_no_prompt() {
    let dir = test_tempdir();
    let path = dir.path().join("unreadable.bin");
    fs::write(&path, b"PALADIN\0\x01\x01").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let result = classify_paladin_import_precheck(&path, None);
    // Restore perms for cleanup before any assert can fail.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(result, PaladinImportPrecheck::NoPrompt));
}
