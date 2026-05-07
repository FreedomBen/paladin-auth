// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration tests for `default_vault_path`, `inspect`, and the
// `classify_init_precheck` truth table (DESIGN.md §4.3 / §4.7 / §5).
//
// Subsequent Phase E commits will extend this file with `Store::open`,
// `Store::create`, `create_force`, and `mutate_and_save` coverage.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    classify_init_precheck, default_vault_path, inspect, parse_otpauth, Account, ErrorKind,
    InitPrecheck, PaladinError, PermissionSubject, Store, VaultInit, VaultLock, VaultStatus,
};
use tempfile::TempDir;

/// Fixed import-time timestamp used for round-trip tests so accounts
/// with identical labels still have stable `created_at` / `updated_at`
/// values.
fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// Build an `Account` via the public otpauth parser. The label and
/// (optional) issuer are caller-controlled; secret / algorithm /
/// digits are fixed because Phase E only exercises the storage
/// round-trip — the §4.1 validation matrix lives in Phase B / D.
fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

/// Allocate a temp directory and force its mode to `0700` so the
/// §4.3 perms check passes regardless of the host's `mkdtemp`
/// default (sandbox/test runners sometimes hand back `0770`).
fn vault_test_dir() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod tempdir 0700");
    dir
}

/// Bytes of a valid 10-byte plaintext header.
fn plaintext_header_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    // PALADIN\0 + format_ver=1 + mode=0
    v.extend_from_slice(b"PALADIN\0");
    v.push(1);
    v.push(0);
    v
}

/// Bytes of a valid 64-byte encrypted header (sample params: defaults).
fn encrypted_header_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"PALADIN\0");
    v.push(1); // format_ver
    v.push(1); // mode = encrypted
    v.push(1); // kdf_id = Argon2id
    v.extend_from_slice(&65_536u32.to_le_bytes());
    v.extend_from_slice(&3u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&[0u8; 16]); // salt
    v.push(1); // aead_id = XChaCha20-Poly1305
    v.extend_from_slice(&[0u8; 24]); // nonce
    v
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.path().join(name);
    let mut f = fs::File::create(&p).expect("create test file");
    f.write_all(bytes).expect("write test bytes");
    p
}

#[test]
fn default_vault_path_resolves_under_paladin_with_vault_bin_filename() {
    let path = default_vault_path().expect("default_vault_path resolves on this platform");
    assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("vault.bin"));
    assert!(path.to_string_lossy().contains("paladin"));
}

#[test]
fn inspect_missing_returns_status_missing() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Missing);
}

#[test]
fn inspect_plaintext_returns_plaintext() {
    let dir = vault_test_dir();
    let path = write(&dir, "vault.bin", &plaintext_header_bytes());
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
}

#[test]
fn inspect_encrypted_returns_encrypted() {
    let dir = vault_test_dir();
    let path = write(&dir, "vault.bin", &encrypted_header_bytes());
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
}

#[test]
fn inspect_does_not_enforce_permissions() {
    // §4.7: inspect deliberately skips the §4.3 permissions check so
    // callers can probe vault mode before fixing perms.
    let dir = vault_test_dir();
    let path = write(&dir, "vault.bin", &plaintext_header_bytes());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
}

#[test]
fn inspect_unrecognized_magic_is_invalid_header() {
    let dir = vault_test_dir();
    let path = write(&dir, "vault.bin", b"NOTPALADIN\0\x01\x00");
    assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
}

#[test]
fn inspect_unsupported_format_version_propagates() {
    let dir = vault_test_dir();
    let mut bytes = plaintext_header_bytes();
    bytes[8] = 99;
    let path = write(&dir, "vault.bin", &bytes);
    assert_eq!(
        inspect(&path).unwrap_err().kind(),
        ErrorKind::UnsupportedFormatVersion
    );
}

#[test]
fn classify_init_precheck_truth_table() {
    // Missing → Clear
    assert!(matches!(
        classify_init_precheck(Ok(VaultStatus::Missing)),
        InitPrecheck::Clear
    ));
    // Plaintext → Existing
    assert!(matches!(
        classify_init_precheck(Ok(VaultStatus::Plaintext)),
        InitPrecheck::Existing
    ));
    // Encrypted → Existing
    assert!(matches!(
        classify_init_precheck(Ok(VaultStatus::Encrypted)),
        InitPrecheck::Existing
    ));
    // InvalidHeader → Existing
    assert!(matches!(
        classify_init_precheck(Err(PaladinError::InvalidHeader)),
        InitPrecheck::Existing
    ));
    // UnsupportedFormatVersion → Existing
    assert!(matches!(
        classify_init_precheck(Err(PaladinError::UnsupportedFormatVersion)),
        InitPrecheck::Existing
    ));
    // Other Err → Propagate
    match classify_init_precheck(Err(PaladinError::VaultMissing)) {
        InitPrecheck::Propagate(PaladinError::VaultMissing) => {}
        other => panic!("expected Propagate(VaultMissing), got {other:?}"),
    }
}

// ---------- Store::open / Store::create / Vault::save (plaintext) ----------

#[test]
fn store_open_returns_vault_missing_when_path_absent() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultMissing);
}

#[test]
fn store_create_returns_vault_exists_when_primary_already_present() {
    let dir = vault_test_dir();
    let path = write(&dir, "vault.bin", &plaintext_header_bytes());
    let err = Store::create(&path, VaultInit::Plaintext).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultExists);
}

#[test]
fn first_save_writes_primary_and_creates_no_backup() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    assert!(path.exists(), "primary should be written");
    assert!(
        !dir.path().join("vault.bin.bak").exists(),
        "first-ever save must not produce a backup"
    );
    assert!(!dir.path().join("vault.bin.tmp").exists());
    assert!(!dir.path().join("vault.bin.bak.tmp").exists());
}

#[test]
fn second_save_rotates_backup_to_pre_save_primary_bytes() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    let primary_v1 = fs::read(&path).unwrap();
    // No mutations between saves, but the §4.3 atomic-write pipeline
    // still rotates `.bak` from the soon-to-be-replaced primary.
    vault.save(&store).unwrap();
    let bak = dir.path().join("vault.bin.bak");
    assert!(bak.exists(), "second save should rotate .bak");
    assert_eq!(
        fs::read(&bak).unwrap(),
        primary_v1,
        ".bak must hold the pre-save primary bytes verbatim"
    );
    assert!(!dir.path().join("vault.bin.tmp").exists());
    assert!(!dir.path().join("vault.bin.bak.tmp").exists());
}

#[test]
fn save_reopen_round_trip_preserves_account_insertion_order() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.add(make_account("alice", None));
    vault.add(make_account("bob", None));
    vault.add(make_account("carol", None));
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).unwrap();
    let labels: Vec<&str> = reopened.accounts().iter().map(Account::label).collect();
    assert_eq!(labels, ["alice", "bob", "carol"]);
}

#[test]
fn empty_vault_round_trips_through_save_reopen() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);

    let (reopened, _) = Store::open(&path, VaultLock::Plaintext).unwrap();
    assert!(reopened.accounts().is_empty());
    // Default settings round-trip too.
    assert!(!reopened.settings().auto_lock_enabled());
    assert_eq!(reopened.settings().auto_lock_timeout_secs(), 300);
    assert!(!reopened.settings().clipboard_clear_enabled());
    assert_eq!(reopened.settings().clipboard_clear_secs(), 20);
}

#[test]
fn open_with_plaintext_lock_against_encrypted_file_returns_wrong_vault_lock() {
    let dir = vault_test_dir();
    let path = write(&dir, "vault.bin", &encrypted_header_bytes());
    // §4.3 perms enforcement runs before mode classification, so make
    // sure the on-disk file passes the permission check; the
    // encrypted-shape rejection is what we are pinning here.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WrongVaultLock);
}

// ---------- §4.3 permissions enforcement ----------

#[test]
fn open_rejects_when_parent_directory_grants_group_or_other() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
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
}

#[test]
fn open_rejects_when_primary_grants_group_or_other() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::UnsafePermissions {
            subject,
            actual_mode,
            expected_mode,
            ..
        } => {
            assert_eq!(subject, PermissionSubject::VaultFile);
            assert_eq!(actual_mode, "0644");
            assert_eq!(expected_mode, "0600");
        }
        other => panic!("expected UnsafePermissions, got {other:?}"),
    }
}

#[test]
fn open_rejects_when_backup_grants_group_or_other() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    // Second save rotates a .bak that we then loosen on disk.
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);
    let bak = dir.path().join("vault.bin.bak");
    assert!(bak.exists(), "second save should produce vault.bin.bak");
    fs::set_permissions(&bak, fs::Permissions::from_mode(0o640)).unwrap();
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::UnsafePermissions {
            subject,
            actual_mode,
            expected_mode,
            path: bad_path,
        } => {
            assert_eq!(subject, PermissionSubject::BackupFile);
            assert_eq!(actual_mode, "0640");
            assert_eq!(expected_mode, "0600");
            assert_eq!(bad_path, bak);
        }
        other => panic!("expected UnsafePermissions, got {other:?}"),
    }
}

#[test]
fn create_rejects_when_parent_directory_grants_group_or_other() {
    let dir = vault_test_dir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("vault.bin");
    let err = Store::create(&path, VaultInit::Plaintext).unwrap_err();
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
}

#[test]
fn create_succeeds_when_parent_directory_is_0700() {
    let dir = vault_test_dir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("vault.bin");
    let _ = Store::create(&path, VaultInit::Plaintext).unwrap();
}

#[test]
fn unsafe_permissions_actual_mode_is_four_digit_octal() {
    // Even when the failing mode is e.g. 0700 with a stray sticky bit
    // (0701, encoded as four digits), the actual_mode field is exactly
    // four octal digits — the CLI / TUI / GUI helpers depend on the
    // `0NNN` shape to render the §5 "chmod NNN" repair hint.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o604)).unwrap();
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::UnsafePermissions {
            actual_mode,
            expected_mode,
            ..
        } => {
            assert_eq!(actual_mode.len(), 4);
            assert!(actual_mode.starts_with('0'));
            assert_eq!(actual_mode, "0604");
            assert_eq!(expected_mode.len(), 4);
            assert!(expected_mode.starts_with('0'));
        }
        other => panic!("expected UnsafePermissions, got {other:?}"),
    }
}

#[test]
fn open_unlinks_leftover_temp_files_from_prior_partial_save() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);

    // Stage stale tmp siblings as if a prior save crashed before
    // committing.
    fs::write(dir.path().join("vault.bin.tmp"), b"stale primary tmp").unwrap();
    fs::write(dir.path().join("vault.bin.bak.tmp"), b"stale backup tmp").unwrap();

    let _ = Store::open(&path, VaultLock::Plaintext).unwrap();
    assert!(
        !dir.path().join("vault.bin.tmp").exists(),
        "open must unlink leftover vault.bin.tmp"
    );
    assert!(
        !dir.path().join("vault.bin.bak.tmp").exists(),
        "open must unlink leftover vault.bin.bak.tmp"
    );
}

#[test]
fn saved_primary_starts_with_plaintext_header_bytes() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() >= 10);
    assert_eq!(&bytes[0..8], b"PALADIN\0");
    assert_eq!(bytes[8], 1, "format_ver should be 1");
    assert_eq!(bytes[9], 0, "mode should be 0 (plaintext)");
}

#[test]
fn saved_primary_file_has_0600_permissions() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "primary file must be written 0600");
}
