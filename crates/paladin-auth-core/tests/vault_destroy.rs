// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration tests for `destroy_vault` and `DestroyReport`
// (docs/DESIGN.md §4.3). Every branch except the parent-directory
// `fsync` failure is exercised here without fault injection — the
// `fsync_vault_dir` path is pinned in `tests/fault_injection.rs` since
// it needs the `test-fault-injection` hook.

mod common;

use common::test_tempdir;

use std::fs;
use std::os::unix::fs as unix_fs;

use paladin_auth_core::{destroy_vault, DestroyReport, ErrorKind, PaladinAuthError};

/// Write a placeholder primary vault file at `dir/vault.bin`.
///
/// `destroy_vault` operates purely at the file level — it never parses
/// the payload and deliberately skips the §4.3 permissions gate — so a
/// byte blob is a faithful stand-in for a real vault and keeps these
/// tests independent of directory-permission setup.
fn make_vault(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("vault.bin");
    fs::write(&path, b"palauth vault bytes").expect("write placeholder vault");
    path
}

#[test]
fn destroy_missing_vault_returns_vault_missing() {
    let dir = test_tempdir();
    let path = dir.path().join("vault.bin");
    let err = destroy_vault(&path).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultMissing);
    assert!(matches!(err, PaladinAuthError::VaultMissing));
}

#[test]
fn destroy_missing_vault_does_not_touch_existing_backup() {
    // §4.3 step 1: a `vault_missing` short-circuit must not unlink a
    // stray sibling `.bak` — the primary is the authority for whether a
    // vault exists.
    let dir = test_tempdir();
    let path = dir.path().join("vault.bin");
    let bak = dir.path().join("vault.bin.bak");
    fs::write(&bak, b"orphan backup").unwrap();

    let err = destroy_vault(&path).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultMissing);
    assert!(
        bak.exists(),
        "orphan .bak must survive a vault_missing destroy"
    );
}

#[test]
fn destroy_primary_only_reports_primary_deleted() {
    let dir = test_tempdir();
    let path = make_vault(dir.path());

    let report = destroy_vault(&path).unwrap();
    assert_eq!(
        report,
        DestroyReport {
            primary_deleted: true,
            backup_deleted: false,
        }
    );
    assert!(!path.exists(), "primary must be gone after destroy");
}

#[test]
fn destroy_primary_and_backup_reports_both_deleted() {
    let dir = test_tempdir();
    let path = make_vault(dir.path());
    let bak = dir.path().join("vault.bin.bak");
    fs::write(&bak, b"previous generation").unwrap();

    let report = destroy_vault(&path).unwrap();
    assert_eq!(
        report,
        DestroyReport {
            primary_deleted: true,
            backup_deleted: true,
        }
    );
    assert!(!path.exists(), "primary must be gone");
    assert!(!bak.exists(), "backup must be gone");
}

#[test]
fn destroy_rejects_symlinked_primary_before_unlinking() {
    // §4.3 step 2: a symlinked primary is rejected before anything is
    // unlinked, so a hostile link cannot redirect the delete to its
    // target.
    let dir = test_tempdir();
    let target = dir.path().join("real_secret");
    fs::write(&target, b"do not delete me").unwrap();
    let path = dir.path().join("vault.bin");
    unix_fs::symlink(&target, &path).unwrap();

    let err = destroy_vault(&path).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::IoError);
    match err {
        PaladinAuthError::IoError { operation, .. } => {
            assert_eq!(operation, "vault_file_is_symlink");
        }
        other => panic!("expected IoError, got {other:?}"),
    }
    assert!(target.exists(), "symlink target must be untouched");
    assert!(path.exists(), "the symlink itself must be untouched");
}

#[test]
fn destroy_rejects_symlinked_backup_before_unlinking_primary() {
    // §4.3 step 2 checks both files up front, so a symlinked `.bak`
    // aborts the destroy with the primary still on disk.
    let dir = test_tempdir();
    let path = make_vault(dir.path());
    let target = dir.path().join("real_backup_target");
    fs::write(&target, b"do not delete me").unwrap();
    let bak = dir.path().join("vault.bin.bak");
    unix_fs::symlink(&target, &bak).unwrap();

    let err = destroy_vault(&path).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::IoError);
    match err {
        PaladinAuthError::IoError { operation, .. } => {
            assert_eq!(operation, "backup_file_is_symlink");
        }
        other => panic!("expected IoError, got {other:?}"),
    }
    assert!(
        path.exists(),
        "primary must NOT be unlinked when backup is a symlink"
    );
    assert!(target.exists(), "symlink target must be untouched");
}

#[test]
fn destroy_primary_unlink_failure_is_plain_io_error() {
    // A directory at `vault.bin` is not a symlink, so it passes the
    // gate; `remove_file` then fails (EISDIR) and the primary is still
    // authoritative — a plain `io_error`, no partial-completion
    // envelope.
    let dir = test_tempdir();
    let path = dir.path().join("vault.bin");
    fs::create_dir(&path).unwrap();

    let err = destroy_vault(&path).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::IoError);
    match err {
        PaladinAuthError::IoError { operation, .. } => assert_eq!(operation, "unlink_vault_file"),
        PaladinAuthError::DestroyIoError { .. } => {
            panic!("a pre-primary failure must not carry the destroy envelope")
        }
        other => panic!("expected IoError, got {other:?}"),
    }
    assert!(
        path.exists(),
        "the directory must remain after a failed unlink"
    );
}

#[test]
fn destroy_backup_unlink_failure_reports_partial_state() {
    // §4.3 step 4: the primary is gone but the backup unlink fails (a
    // directory at `vault.bin.bak`), so the error carries
    // `primary_deleted: true, backup_deleted: false`.
    let dir = test_tempdir();
    let path = make_vault(dir.path());
    let bak = dir.path().join("vault.bin.bak");
    fs::create_dir(&bak).unwrap();

    let err = destroy_vault(&path).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::IoError);
    match err {
        PaladinAuthError::DestroyIoError {
            operation,
            primary_deleted,
            backup_deleted,
            ..
        } => {
            assert_eq!(operation, "unlink_backup_file");
            assert!(
                primary_deleted,
                "primary was unlinked before the backup failed"
            );
            assert!(!backup_deleted, "backup unlink did not complete");
        }
        other => panic!("expected DestroyIoError, got {other:?}"),
    }
    assert!(!path.exists(), "primary must already be gone");
    assert!(bak.exists(), "the backup directory must remain");
}

#[test]
fn destroy_best_effort_removes_leftover_temp_files() {
    // §4.3: a crashed prior save can leave `.tmp` / `.bak.tmp`; destroy
    // unlinks them best-effort so the data directory is left clean.
    let dir = test_tempdir();
    let path = make_vault(dir.path());
    let tmp = dir.path().join("vault.bin.tmp");
    let bak_tmp = dir.path().join("vault.bin.bak.tmp");
    fs::write(&tmp, b"staged primary").unwrap();
    fs::write(&bak_tmp, b"staged backup").unwrap();

    let report = destroy_vault(&path).unwrap();
    assert!(report.primary_deleted);
    assert!(!tmp.exists(), "leftover .tmp should be cleaned up");
    assert!(!bak_tmp.exists(), "leftover .bak.tmp should be cleaned up");
}

#[test]
fn destroy_swallows_leftover_temp_unlink_failure() {
    // A `.tmp` that cannot be unlinked (here a directory) must not block
    // the destroy or appear in the report — §4.3 tracks only the primary
    // and the one-generation backup.
    let dir = test_tempdir();
    let path = make_vault(dir.path());
    let tmp = dir.path().join("vault.bin.tmp");
    fs::create_dir(&tmp).unwrap();

    let report = destroy_vault(&path).unwrap();
    assert_eq!(
        report,
        DestroyReport {
            primary_deleted: true,
            backup_deleted: false,
        }
    );
    assert!(!path.exists(), "primary must be gone");
    assert!(
        tmp.exists(),
        "the undeletable .tmp directory is left in place"
    );
}

#[test]
fn destroy_is_idempotent_across_reruns() {
    // §4.3: re-running destroy after a successful wipe returns
    // `vault_missing`, so a `paladin-auth destroy || true` script pattern is
    // safe.
    let dir = test_tempdir();
    let path = make_vault(dir.path());

    assert!(destroy_vault(&path).is_ok());
    let err = destroy_vault(&path).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultMissing);
}

#[test]
fn destroy_dangling_symlink_primary_is_rejected_not_missing() {
    // A symlink whose target is gone still "exists" via
    // `symlink_metadata`, so destroy rejects it as a symlink rather than
    // reporting `vault_missing` (which would let a hostile dangling link
    // mask a real file swap).
    let dir = test_tempdir();
    let path = dir.path().join("vault.bin");
    unix_fs::symlink(dir.path().join("nonexistent-target"), &path).unwrap();

    let err = destroy_vault(&path).unwrap_err();
    match err {
        PaladinAuthError::IoError { operation, .. } => {
            assert_eq!(operation, "vault_file_is_symlink");
        }
        other => panic!("expected IoError, got {other:?}"),
    }
}
