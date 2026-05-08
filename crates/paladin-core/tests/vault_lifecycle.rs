// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration tests for `default_vault_path`, `inspect`, and the
// `classify_init_precheck` truth table (DESIGN.md §4.3 / §4.7 / §5).
//
// Subsequent Phase E commits will extend this file with `Store::open`,
// `Store::create`, `create_force`, and `mutate_and_save` coverage.

use std::fs;
use std::io::Write;
use std::os::unix::fs as unix_fs;
use std::os::unix::fs::PermissionsExt;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    classify_init_precheck, default_vault_path, inspect, parse_otpauth, write_secret_file_atomic,
    Account, ErrorKind, InitPrecheck, PaladinError, PermissionSubject, Store, VaultInit, VaultLock,
    VaultStatus,
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
        classify_init_precheck(Err(PaladinError::UnsupportedFormatVersion {
            format_ver: 99
        })),
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

// ---------- §4.3 symbolic-link rejection (defense in depth) ----------

#[test]
fn open_rejects_when_parent_directory_is_symlink() {
    // Path layout:
    //   real_dir/vault.bin  (the actual file)
    //   link_root/link → real_dir
    // Open(link_root/link/vault.bin) — parent ("link_root/link") is a
    // symlink. §4.3 rejects with `vault_dir_is_symlink` before reading.
    let real_dir = vault_test_dir();
    let link_root = vault_test_dir();
    let link_path = link_root.path().join("link");
    unix_fs::symlink(real_dir.path(), &link_path).unwrap();

    let real_vault = real_dir.path().join("vault.bin");
    fs::write(&real_vault, plaintext_header_bytes()).unwrap();
    fs::set_permissions(&real_vault, fs::Permissions::from_mode(0o600)).unwrap();

    let opened_path = link_path.join("vault.bin");
    let err = Store::open(&opened_path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "vault_dir_is_symlink"),
        other => panic!("expected vault_dir_is_symlink io_error, got {other:?}"),
    }
}

#[test]
fn open_rejects_when_primary_file_is_symlink() {
    let dir = vault_test_dir();
    let real_target = dir.path().join("real_vault.bin");
    fs::write(&real_target, plaintext_header_bytes()).unwrap();
    fs::set_permissions(&real_target, fs::Permissions::from_mode(0o600)).unwrap();

    let path = dir.path().join("vault.bin");
    unix_fs::symlink(&real_target, &path).unwrap();

    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "vault_file_is_symlink"),
        other => panic!("expected vault_file_is_symlink io_error, got {other:?}"),
    }
}

#[test]
fn open_rejects_when_backup_file_is_symlink() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);

    // Plant a symlink at vault.bin.bak pointing to a sibling file.
    let real_bak_target = dir.path().join("real_bak_target.bin");
    fs::write(&real_bak_target, plaintext_header_bytes()).unwrap();
    fs::set_permissions(&real_bak_target, fs::Permissions::from_mode(0o600)).unwrap();
    let bak = dir.path().join("vault.bin.bak");
    unix_fs::symlink(&real_bak_target, &bak).unwrap();

    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "backup_file_is_symlink"),
        other => panic!("expected backup_file_is_symlink io_error, got {other:?}"),
    }
}

#[test]
fn create_rejects_when_parent_directory_is_symlink() {
    let real_dir = vault_test_dir();
    let link_root = vault_test_dir();
    let link_path = link_root.path().join("link");
    unix_fs::symlink(real_dir.path(), &link_path).unwrap();

    let path = link_path.join("vault.bin");
    let err = Store::create(&path, VaultInit::Plaintext).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "vault_dir_is_symlink"),
        other => panic!("expected vault_dir_is_symlink io_error, got {other:?}"),
    }
}

#[test]
fn create_force_rejects_when_existing_primary_is_symlink() {
    // A hostile symlink at vault.bin must not capture the rename target
    // during the §5 staged-clobber sequence. The symlink is rejected
    // before any read, write, or staged tempfile.
    let dir = vault_test_dir();
    let victim = dir.path().join("victim.bin");
    fs::write(&victim, b"victim contents").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();

    let path = dir.path().join("vault.bin");
    unix_fs::symlink(&victim, &path).unwrap();

    let err = Store::create_force(&path, VaultInit::Plaintext).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "vault_file_is_symlink"),
        other => panic!("expected vault_file_is_symlink io_error, got {other:?}"),
    }

    // The symlink itself should still be in place — we rejected before
    // writing — and the victim contents must be untouched.
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
    assert!(!dir.path().join("vault.bin.tmp").exists());
    assert!(!dir.path().join("vault.bin.bak").exists());
}

#[test]
fn symlink_rejection_fires_before_perms_check() {
    // The symlink itself has the typical lrwxrwxrwx (0o777) mode, so
    // the perms check would also reject it. But the symlink rejection
    // must surface as the more specific `vault_dir_is_symlink` error,
    // not as `unsafe_permissions { actual_mode: "0777" }`.
    //
    // The link target is a clean 0700 directory — defense in depth says
    // we still reject the symlink even when the resolved dir would pass.
    let real_dir = vault_test_dir();
    fs::set_permissions(real_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let link_root = vault_test_dir();
    let link_path = link_root.path().join("link");
    unix_fs::symlink(real_dir.path(), &link_path).unwrap();

    let real_vault = real_dir.path().join("vault.bin");
    fs::write(&real_vault, plaintext_header_bytes()).unwrap();
    fs::set_permissions(&real_vault, fs::Permissions::from_mode(0o600)).unwrap();

    let opened_path = link_path.join("vault.bin");
    let err = Store::open(&opened_path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "vault_dir_is_symlink"),
        PaladinError::UnsafePermissions { .. } => {
            panic!("symlink check must win over the perms check")
        }
        other => panic!("expected vault_dir_is_symlink io_error, got {other:?}"),
    }
}

// ---------- §5 `init --force` clobber semantics (`create_force`) ----------

#[test]
fn create_force_with_no_existing_primary_writes_fresh_vault() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create_force(&path, VaultInit::Plaintext).unwrap();
    // Per §4.7, create_force itself stages and commits the new vault.
    assert!(path.exists(), "create_force must write the primary");
    assert!(
        !dir.path().join("vault.bin.bak").exists(),
        "no prior primary → no rotation → no .bak"
    );
    assert!(!dir.path().join("vault.bin.tmp").exists());
    drop(vault);
    drop(store);

    let (reopened, _) = Store::open(&path, VaultLock::Plaintext).unwrap();
    assert!(reopened.accounts().is_empty());
}

#[test]
fn create_force_rotates_existing_primary_to_bak_verbatim() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.add(make_account("alice", None));
    vault.add(make_account("bob", None));
    vault.save(&store).unwrap();
    let pre_clobber_primary = fs::read(&path).unwrap();
    drop(vault);
    drop(store);

    let (clobbered, _) = Store::create_force(&path, VaultInit::Plaintext).unwrap();
    let bak = dir.path().join("vault.bin.bak");
    assert!(
        bak.exists(),
        "create_force must rotate prior primary → .bak"
    );
    assert_eq!(
        fs::read(&bak).unwrap(),
        pre_clobber_primary,
        ".bak must hold the pre-clobber primary verbatim (no re-encryption)"
    );
    // The new primary differs from the old (it's an empty vault).
    assert_ne!(fs::read(&path).unwrap(), pre_clobber_primary);
    assert!(clobbered.accounts().is_empty());
    assert!(!dir.path().join("vault.bin.tmp").exists());
    assert!(!dir.path().join("vault.bin.bak.tmp").exists());
}

#[test]
fn create_force_overwrites_existing_backup_during_rotation() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    vault.save(&store).unwrap(); // produces a real .bak
    drop(vault);
    drop(store);

    let bak = dir.path().join("vault.bin.bak");
    let pre_primary = fs::read(&path).unwrap();
    // Replace .bak with poisoned bytes so we can detect rotation.
    fs::write(&bak, b"poisoned previous backup").unwrap();
    fs::set_permissions(&bak, fs::Permissions::from_mode(0o600)).unwrap();

    let _ = Store::create_force(&path, VaultInit::Plaintext).unwrap();
    let new_bak = fs::read(&bak).unwrap();
    assert_eq!(
        new_bak, pre_primary,
        ".bak must be the rotated pre-clobber primary, overwriting any prior backup"
    );
    assert_ne!(new_bak, b"poisoned previous backup".to_vec());
}

#[test]
fn create_force_rejects_when_parent_directory_grants_group_or_other() {
    let dir = vault_test_dir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("vault.bin");
    let err = Store::create_force(&path, VaultInit::Plaintext).unwrap_err();
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
    assert!(!path.exists(), "create_force must reject before writing");
    assert!(!dir.path().join("vault.bin.tmp").exists());
}

#[test]
fn create_force_writes_primary_with_0600_permissions() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let _ = Store::create_force(&path, VaultInit::Plaintext).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "create_force must write the primary 0600");
}

// ---------- §4.3 leftover-`.tmp` cleanup edge cases ----------

#[test]
fn open_cleanup_surfaces_io_error_when_leftover_tmp_is_directory() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);

    // Plant a *directory* at vault.bin.tmp. fs::remove_file would error
    // with EISDIR; the cleanup helper must surface this as
    // io_error/cleanup_temp_file rather than silently swallowing it.
    let stale_dir = dir.path().join("vault.bin.tmp");
    fs::create_dir(&stale_dir).unwrap();
    fs::set_permissions(&stale_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    match err {
        PaladinError::IoError { operation, .. } => assert_eq!(operation, "cleanup_temp_file"),
        other => panic!("expected cleanup_temp_file io_error, got {other:?}"),
    }
    // The leftover dir must still be there — the cleanup didn't recurse.
    assert!(stale_dir.exists());
    assert!(stale_dir.is_dir());
}

#[test]
fn open_does_not_read_bak_on_success_path() {
    // The §4.3 backup is recovery-only — `open` reads only the primary.
    // Corrupting the .bak to garbage must not affect a clean open.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.add(make_account("alice", None));
    vault.save(&store).unwrap();
    vault.save(&store).unwrap(); // second save rotates a real .bak
    drop(vault);
    drop(store);

    let bak = dir.path().join("vault.bin.bak");
    assert!(bak.exists(), "second save should produce vault.bin.bak");
    // Replace .bak with bytes that would fail every layer of decode if
    // anyone ever tried to read them — header parse, payload size cap,
    // bincode decode would all reject. The clean open must not even
    // try.
    fs::write(&bak, b"NOTPALADIN garbage bytes that are not a vault").unwrap();
    fs::set_permissions(&bak, fs::Permissions::from_mode(0o600)).unwrap();

    let (reopened, _) = Store::open(&path, VaultLock::Plaintext).unwrap();
    let labels: Vec<&str> = reopened.accounts().iter().map(Account::label).collect();
    assert_eq!(
        labels,
        ["alice"],
        "open must read only the primary; .bak is recovery-only"
    );
}

#[test]
fn open_cleanup_unlinks_leftover_symlink_without_following_target() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);

    // Plant a symlink at vault.bin.tmp pointing to an external file we
    // must NOT delete during cleanup.
    let preserve_target = dir.path().join("important_target_data");
    fs::write(&preserve_target, b"do not delete this").unwrap();
    let stale_link = dir.path().join("vault.bin.tmp");
    unix_fs::symlink(&preserve_target, &stale_link).unwrap();

    let _ = Store::open(&path, VaultLock::Plaintext).unwrap();

    // The symlink itself was unlinked.
    assert!(
        fs::symlink_metadata(&stale_link).is_err(),
        "leftover symlink must be unlinked"
    );
    // The symlink target is preserved (we unlinked the link, not the
    // file the link pointed to).
    assert_eq!(fs::read(&preserve_target).unwrap(), b"do not delete this");
}

// -----------------------------------------------------------------
// E.6 — `write_secret_file_atomic` shared export writer.
// -----------------------------------------------------------------

#[test]
fn write_secret_file_atomic_creates_destination_with_zero_six_zero_zero_mode_and_content() {
    let dir = vault_test_dir();
    let path = dir.path().join("export.bin");
    let bytes = b"PALADIN-EXPORT-PAYLOAD-FIXTURE";

    write_secret_file_atomic(&path, bytes).expect("export write should succeed");

    assert_eq!(fs::read(&path).unwrap(), bytes);
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "export must be created 0600, got {mode:o}");
}

#[test]
fn write_secret_file_atomic_overwrites_existing_destination_in_place() {
    let dir = vault_test_dir();
    let path = dir.path().join("export.bin");

    write_secret_file_atomic(&path, b"v1-bytes").unwrap();
    write_secret_file_atomic(&path, b"v2-replaced-content").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"v2-replaced-content");
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn write_secret_file_atomic_never_creates_bak_or_leaves_tmp_residue() {
    // The export writer is intentionally `.bak`-free — callers own
    // the keep-or-discard policy on the prior file. A successful
    // commit also leaves no `.tmp` siblings around: the rename
    // consumes the staged tempfile.
    let dir = vault_test_dir();
    let path = dir.path().join("export.bin");
    fs::write(&path, b"original").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    write_secret_file_atomic(&path, b"replacement").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    assert!(
        !dir.path().join("export.bin.bak").exists(),
        "export writer must never rotate a .bak"
    );
    assert!(
        !dir.path().join("export.bin.tmp").exists(),
        "staged tempfile must be consumed by the rename"
    );
}

#[test]
fn write_secret_file_atomic_returns_io_error_for_path_with_no_parent() {
    // A bare basename has parent component `""` — treated as no
    // parent so the helper does not silently fall back to the
    // current working directory, which would surprise callers and
    // hide configuration mistakes.
    let err = write_secret_file_atomic(std::path::Path::new("export.bin"), b"x").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::IoError);
    match err {
        PaladinError::IoError { operation, .. } => {
            assert_eq!(operation, "resolve_secret_file_parent");
        }
        other => panic!("expected io_error, got {other:?}"),
    }
}

#[test]
fn write_secret_file_atomic_returns_save_not_committed_when_parent_is_read_only() {
    // chmod 0500 on the parent dir denies the tempfile creation. The
    // stage failure collapses into `save_not_committed` (committed
    // false, no backup) so callers can rely on the typed error to
    // know the destination was untouched, regardless of which
    // pre-rename step actually failed.
    let dir = vault_test_dir();
    let path = dir.path().join("export.bin");
    fs::write(&path, b"original-content-must-survive").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();

    let err = write_secret_file_atomic(&path, b"new-content-must-not-land").unwrap_err();

    // Restore perms before any further filesystem assertions so the
    // tempdir cleanup at the end of the test can succeed regardless
    // of how the read-only window was exercised.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(err.kind(), ErrorKind::SaveNotCommitted);
    match err {
        PaladinError::SaveNotCommitted {
            committed,
            backup_path,
        } => {
            assert!(!committed, "stage failures must report committed=false");
            assert!(
                backup_path.is_none(),
                "export writer must never claim a .bak rotation"
            );
        }
        other => panic!("expected SaveNotCommitted, got {other:?}"),
    }

    // Pre-existing destination content is preserved.
    assert_eq!(fs::read(&path).unwrap(), b"original-content-must-survive");
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // No tempfile was committed and no .bak was created as a side effect.
    assert!(!dir.path().join("export.bin.bak").exists());
    assert!(!dir.path().join("export.bin.tmp").exists());
}

#[test]
fn write_secret_file_atomic_does_not_enforce_directory_perms_on_caller_dir() {
    // Unlike `Store::open` / `Store::create`, the export writer does
    // not enforce the §4.3 0700-or-better directory check. Each
    // front-end gates its own warning surface (the GUI / TUI export
    // dialogs). Verify a 0750 parent — which `Store::create` would
    // reject — accepts an export write here.
    let dir = vault_test_dir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
    let path = dir.path().join("export.bin");

    write_secret_file_atomic(&path, b"loose-perms-ok").expect("export must succeed at 0750 parent");

    // Restore perms so TempDir cleanup is unconstrained.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"loose-perms-ok");
}
