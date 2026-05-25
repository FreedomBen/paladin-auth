// SPDX-License-Identifier: AGPL-3.0-or-later
//
// §4.3 permissions enforcement (non-Unix stub).
//
// v0.1 ships Linux-only; this stub keeps the storage module's
// platform-agnostic call sites compiling on hypothetical non-Unix
// targets without silently weakening the Unix-side guarantees.

// Compiled under `cfg(any(not(unix), test))` so Unix test builds can
// exercise the stub directly. In that configuration the items aren't
// referenced from `storage::mod` (the Unix `use perms_unix::…` wins),
// so blanket-allow `dead_code` to keep `-D warnings` happy.
#![allow(dead_code)]

use std::fs::Metadata;
use std::io;
use std::path::Path;

use crate::error::{PaladinError, PermissionSubject, Result};

// Signature must match `perms_unix::enforce_dir_perms` (which can
// fail). The stub is infallible, but the wrapping `Result<()>` is
// load-bearing for the platform-agnostic call sites in `storage::mod`.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn enforce_dir_perms(_path: &Path) -> Result<()> {
    Ok(())
}

/// Non-Unix stub for the create-side parent-dir helper. Mode bits are
/// unenforceable on these targets, so this only `mkdir -p`s a missing
/// parent and surfaces failures as `create_vault_dir` for parity with
/// the Unix implementation; existing dirs are accepted unconditionally.
pub(crate) fn ensure_vault_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|err| PaladinError::IoError {
                operation: "create_vault_dir",
                source: err,
            })
        }
        Err(err) => Err(PaladinError::IoError {
            operation: "stat_vault_dir",
            source: err,
        }),
    }
}

// Signature must match `perms_unix::enforce_file_perms_from_meta`.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn enforce_file_perms_from_meta(
    _path: &Path,
    _meta: &Metadata,
    _subject: PermissionSubject,
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn test_tempdir() -> TempDir {
        // Mirror tests/common/mod.rs: prefer Cargo's per-target scratch
        // root so a misconfigured $TMPDIR cannot leak files into the
        // workspace.
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        tempfile::Builder::new()
            .prefix(".tmp")
            .tempdir_in(root)
            .expect("create test tempdir")
    }

    #[test]
    fn enforce_dir_perms_is_unconditional_ok_stub() {
        // The non-Unix stub deliberately performs no validation. The
        // path may not exist; the call must still succeed.
        let nonexistent = PathBuf::from("/definitely/does/not/exist/paladin-perms-other");
        assert!(enforce_dir_perms(&nonexistent).is_ok());
    }

    #[test]
    fn enforce_file_perms_from_meta_is_unconditional_ok_stub_for_every_subject() {
        // Synthesize a real Metadata via a tempfile so we don't have
        // to fake the Metadata type. Every PermissionSubject variant
        // must short-circuit to Ok on this platform.
        let dir = test_tempdir();
        let file = dir.path().join("probe");
        fs::write(&file, b"x").unwrap();
        let meta = fs::metadata(&file).unwrap();

        for subject in [
            PermissionSubject::VaultDir,
            PermissionSubject::VaultFile,
            PermissionSubject::BackupFile,
        ] {
            assert!(
                enforce_file_perms_from_meta(&file, &meta, subject).is_ok(),
                "stub must accept {subject:?}"
            );
        }
    }

    #[test]
    fn ensure_vault_dir_returns_ok_when_path_already_exists() {
        let dir = test_tempdir();
        // `dir.path()` is already created and present.
        assert!(ensure_vault_dir(dir.path()).is_ok());
    }

    #[test]
    fn ensure_vault_dir_creates_missing_directory_chain() {
        let dir = test_tempdir();
        let nested = dir.path().join("a").join("b").join("c");
        assert!(!nested.exists());

        ensure_vault_dir(&nested).expect("mkdir -p chain");
        assert!(nested.is_dir(), "ensure_vault_dir should mkdir -p");
    }

    #[test]
    fn ensure_vault_dir_stat_failure_surfaces_stat_vault_dir_io_error() {
        // `symlink_metadata` against a path whose prefix is a regular
        // file fails with `NotADirectory` (not `NotFound`), so the
        // stub takes the `Err(other)` branch and remaps it to
        // `io_error{operation:"stat_vault_dir"}`. This covers the
        // "stat error other than NotFound" arm.
        let dir = test_tempdir();
        let regular_file = dir.path().join("not-a-dir");
        fs::write(&regular_file, b"blocker").unwrap();
        let blocked = regular_file.join("child");

        let err = ensure_vault_dir(&blocked).expect_err("stat should fail under a regular file");
        match err {
            PaladinError::IoError { operation, .. } => {
                assert_eq!(operation, "stat_vault_dir");
                assert_eq!(err.kind(), ErrorKind::IoError);
            }
            other => panic!("expected IoError{{operation:stat_vault_dir}}, got {other:?}"),
        }
    }

    // The `create_vault_dir` arm only fires when `symlink_metadata`
    // returns `NotFound` *and* `create_dir_all` then fails. The
    // reliable cross-Unix way to force that is to chmod a parent
    // dir read-only so mkdir is denied. Gate this test on `unix`
    // so the file still compiles on a hypothetical non-Unix test
    // build (where the module is also visible).
    #[cfg(unix)]
    #[test]
    fn ensure_vault_dir_create_failure_under_readonly_parent_surfaces_create_vault_dir_io_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_tempdir();
        let readonly_parent = dir.path().join("locked");
        fs::create_dir(&readonly_parent).unwrap();
        // Strip write/exec so create_dir_all underneath fails. Root
        // (uid 0) bypasses these bits — skip the assertion in that
        // case rather than fail a CI runner that happens to be root.
        fs::set_permissions(&readonly_parent, fs::Permissions::from_mode(0o500)).unwrap();
        if nix_can_write_into_readonly_dir(&readonly_parent) {
            // Restore so the tempdir Drop can clean up either way.
            fs::set_permissions(&readonly_parent, fs::Permissions::from_mode(0o700)).ok();
            return;
        }

        let blocked = readonly_parent.join("child");
        let err =
            ensure_vault_dir(&blocked).expect_err("mkdir should be denied under a 0500 parent");

        // Restore write so TempDir cleanup can proceed.
        fs::set_permissions(&readonly_parent, fs::Permissions::from_mode(0o700)).ok();

        match err {
            PaladinError::IoError { operation, .. } => {
                assert_eq!(operation, "create_vault_dir");
                assert_eq!(err.kind(), ErrorKind::IoError);
            }
            other => panic!("expected IoError{{operation:create_vault_dir}}, got {other:?}"),
        }
    }

    #[cfg(unix)]
    fn nix_can_write_into_readonly_dir(parent: &std::path::Path) -> bool {
        // Probe empirically: if creating a child under a 0500 parent
        // succeeds, the caller bypasses DAC bits (root, or has
        // CAP_DAC_OVERRIDE). $USER/$UID aren't reliable inside CI
        // containers, so attempt the operation and observe.
        let probe = parent.join(".paladin-root-probe");
        match fs::create_dir(&probe) {
            Ok(()) => {
                let _ = fs::remove_dir(&probe);
                true
            }
            Err(_) => false,
        }
    }
}
