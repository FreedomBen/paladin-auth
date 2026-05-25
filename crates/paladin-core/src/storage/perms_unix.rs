// SPDX-License-Identifier: AGPL-3.0-or-later
//
// §4.3 permissions enforcement (Unix targets).
//
// In plaintext mode the on-disk file is the only protection on the
// secrets, so before decoding `open` rejects a vault whose parent
// directory or whose primary / backup file grants any group / other
// permissions. In encrypted mode the same checks still run as
// defense in depth alongside the AEAD tag.
//
// Each helper also rejects the path being a symbolic link before the
// mode check. The symlink check is the more specific surface
// (`vault_dir_is_symlink` / `vault_file_is_symlink` /
// `backup_file_is_symlink`), and a hostile symlink whose own mode
// happens to be `0700` would otherwise slip past the perms check —
// rejecting the symlink first closes that gap. Per §4.3 the probe
// uses `symlink_metadata` so the link is never followed.
//
// Mode strings on the typed `unsafe_permissions` error are exactly
// four octal digits ("0644" / "0700") so the CLI / TUI / GUI
// `format_unsafe_permissions` helper (Phase G) can render the
// `chmod NNN` repair hint without re-implementing the format.
//
// `inspect()` deliberately bypasses these checks (see §4.7) so a
// caller can probe the on-disk mode before fixing perms.

use std::fs::{DirBuilder, Metadata, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use crate::error::{PaladinError, PermissionSubject, Result};

/// Required mode for vault directories per §4.3 (`0700`).
const REQUIRED_DIR_MODE: u32 = 0o700;
/// Required mode for vault files per §4.3 (`0600`).
const REQUIRED_FILE_MODE: u32 = 0o600;
/// Mask catching any group / other permission bit; if any of these
/// bits are set the path is unsafe regardless of owner perms.
const FORBIDDEN_BITS: u32 = 0o077;

/// Reject the directory at `path` if it is a symbolic link or its
/// mode grants any group or other permissions. Stat errors propagate
/// as `io_error { operation: "stat_vault_dir" }`.
///
/// This is the `open`-side check: it never creates the directory. The
/// `create`-side call sites use [`ensure_vault_dir`] instead, which
/// `mkdir`s a missing parent at `0700` before applying the same
/// rejection rules to an existing one.
pub(crate) fn enforce_dir_perms(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|err| PaladinError::IoError {
        operation: "stat_vault_dir",
        source: err,
    })?;
    enforce_dir_perms_from_meta(path, &meta)
}

/// Enforce §4.3 vault-directory rules against an already-stat'd
/// `Metadata`. Shared by [`enforce_dir_perms`] and the existing-path
/// branch of [`ensure_vault_dir`] so a single stat covers both.
fn enforce_dir_perms_from_meta(path: &Path, meta: &Metadata) -> Result<()> {
    if meta.file_type().is_symlink() {
        return Err(symlink_io_error("vault_dir_is_symlink"));
    }
    let actual = meta.permissions().mode() & 0o7777;
    if actual & FORBIDDEN_BITS != 0 {
        return Err(unsafe_permissions(
            path,
            PermissionSubject::VaultDir,
            actual,
            REQUIRED_DIR_MODE,
        ));
    }
    Ok(())
}

/// Ensure the vault parent directory at `path` exists and satisfies
/// §4.3. The `create`-side counterpart to [`enforce_dir_perms`].
///
/// Behaviour:
///
/// * Path exists → identical to [`enforce_dir_perms`] (symlink + perms
///   rejection). Existing directories are never silently tightened.
/// * Path missing (`ENOENT`) → `mkdir -p` with mode `0700`, then
///   `chmod 0700` on the leaf so a permissive umask cannot widen the
///   final mode beyond what §4.3 requires. Failure surfaces as
///   `io_error { operation: "create_vault_dir" }`.
/// * Other stat failure → `io_error { operation: "stat_vault_dir" }`,
///   matching [`enforce_dir_perms`] so callers see one operation
///   string for "stat failed" regardless of which side triggered it.
///
/// Per §4.3 the directory mode is fixed on creation (`0o700`) — only
/// dirs that this call brings into existence get that mode; ancestors
/// that already existed are left as-is.
pub(crate) fn ensure_vault_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => enforce_dir_perms_from_meta(path, &meta),
        Err(err) if err.kind() == io::ErrorKind::NotFound => create_vault_dir(path),
        Err(err) => Err(PaladinError::IoError {
            operation: "stat_vault_dir",
            source: err,
        }),
    }
}

/// `mkdir -p` the parent directory at mode `0700`, then explicitly
/// `chmod 0700` on the leaf to neutralize a permissive umask. Both
/// failures surface as `io_error { operation: "create_vault_dir" }`
/// per the §5 error matrix.
fn create_vault_dir(path: &Path) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(REQUIRED_DIR_MODE)
        .create(path)
        .map_err(|err| PaladinError::IoError {
            operation: "create_vault_dir",
            source: err,
        })?;
    std::fs::set_permissions(path, Permissions::from_mode(REQUIRED_DIR_MODE)).map_err(|err| {
        PaladinError::IoError {
            operation: "create_vault_dir",
            source: err,
        }
    })
}

/// Reject the file whose `meta` was already stat'd by the caller when
/// it is a symbolic link or its mode grants any group or other
/// permissions.
///
/// The caller is responsible for stat'ing the path so this helper
/// can be reused for both `vault_file` and `backup_file` subjects
/// without re-stat'ing each one (the open path stats both anyway).
/// `subject` selects the matching `*_is_symlink` operation string.
pub(crate) fn enforce_file_perms_from_meta(
    path: &Path,
    meta: &Metadata,
    subject: PermissionSubject,
) -> Result<()> {
    if meta.file_type().is_symlink() {
        return Err(symlink_io_error(symlink_op_for_subject(subject)));
    }
    let actual = meta.permissions().mode() & 0o7777;
    if actual & FORBIDDEN_BITS != 0 {
        return Err(unsafe_permissions(
            path,
            subject,
            actual,
            REQUIRED_FILE_MODE,
        ));
    }
    Ok(())
}

fn symlink_op_for_subject(subject: PermissionSubject) -> &'static str {
    match subject {
        PermissionSubject::VaultDir => "vault_dir_is_symlink",
        PermissionSubject::VaultFile => "vault_file_is_symlink",
        PermissionSubject::BackupFile => "backup_file_is_symlink",
    }
}

fn symlink_io_error(operation: &'static str) -> PaladinError {
    PaladinError::IoError {
        operation,
        source: io::Error::new(io::ErrorKind::InvalidInput, "path is a symbolic link"),
    }
}

fn unsafe_permissions(
    path: &Path,
    subject: PermissionSubject,
    actual: u32,
    expected: u32,
) -> PaladinError {
    PaladinError::UnsafePermissions {
        path: path.to_path_buf(),
        subject,
        actual_mode: format_mode(actual),
        expected_mode: format_mode(expected),
    }
}

/// Render `mode` as a four-digit octal string ("0644", "0700"). Bits
/// above the standard 12-bit permission range are masked off so a
/// stray high bit cannot escape the four-digit shape the §5 error
/// surface promises.
fn format_mode(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn format_mode_produces_four_digit_octal() {
        assert_eq!(format_mode(0o600), "0600");
        assert_eq!(format_mode(0o700), "0700");
        assert_eq!(format_mode(0o644), "0644");
        assert_eq!(format_mode(0o755), "0755");
        // Sticky / setuid / setgid bits are kept in the rendered form
        // — they do not by themselves trip the FORBIDDEN_BITS mask, so
        // their presence in `actual_mode` is informational only.
        assert_eq!(format_mode(0o1700), "1700");
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn ensure_vault_dir_existing_clean_dir_is_ok() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("vault");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o700)).unwrap();
        ensure_vault_dir(&dir).expect("clean 0700 dir accepted");
    }

    #[test]
    fn ensure_vault_dir_creates_missing_single_level_parent_at_0700() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("paladin");
        assert!(!dir.exists());
        ensure_vault_dir(&dir).expect("missing parent created");
        assert!(dir.is_dir());
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn ensure_vault_dir_creates_missing_multi_level_parent_at_0700() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("a").join("b").join("paladin");
        assert!(!dir.exists());
        ensure_vault_dir(&dir).expect("missing nested parent created");
        assert!(dir.is_dir());
        // §4.3: the leaf the call brought into existence must be 0700.
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn ensure_vault_dir_existing_loose_dir_is_rejected() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("loose");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();
        let err = ensure_vault_dir(&dir).expect_err("0755 parent rejected");
        assert!(matches!(
            err,
            PaladinError::UnsafePermissions {
                subject: PermissionSubject::VaultDir,
                ..
            }
        ));
    }

    #[test]
    fn ensure_vault_dir_when_mkdir_eacces_surfaces_create_vault_dir() {
        let tmp = tempdir().unwrap();
        // Grandparent is `r-x------` (0o500): traversable + statable but
        // not writable. `mkdir(grandparent/leaf)` then fails with EACCES,
        // exercising the §5 `create_vault_dir` surface.
        let grandparent = tmp.path().join("ro");
        fs::create_dir(&grandparent).unwrap();
        fs::set_permissions(&grandparent, Permissions::from_mode(0o500)).unwrap();

        // Root (or CAP_DAC_OVERRIDE) bypasses DAC bits; CI containers
        // commonly run as root. Probe by attempting a write under the
        // 0500 parent — if it succeeds, skip the negative assertion.
        let probe = grandparent.join(".paladin-root-probe");
        if fs::create_dir(&probe).is_ok() {
            let _ = fs::remove_dir(&probe);
            fs::set_permissions(&grandparent, Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let target = grandparent.join("paladin");

        let err = ensure_vault_dir(&target).expect_err("mkdir into 0500 parent fails");

        // Restore so TempDir cleanup is unconstrained on drop.
        fs::set_permissions(&grandparent, Permissions::from_mode(0o700)).unwrap();

        match err {
            PaladinError::IoError { operation, source } => {
                assert_eq!(operation, "create_vault_dir");
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected create_vault_dir IO error, got {other:?}"),
        }
    }

    #[test]
    fn ensure_vault_dir_when_intermediate_is_a_file_surfaces_stat_vault_dir() {
        // When an intermediate component of the target path is a regular
        // file, `symlink_metadata` returns ENOTDIR. That's a stat failure
        // (per §5 mapping), not a mkdir failure, so it surfaces as
        // `stat_vault_dir` — `create_vault_dir` is reserved for failures
        // of the mkdir step itself.
        let tmp = tempdir().unwrap();
        let parent = tmp.path().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
        let blocking_file = parent.join("paladin");
        fs::write(&blocking_file, b"not a dir").unwrap();
        let target = blocking_file.join("inner");

        let err = ensure_vault_dir(&target).expect_err("stat through a file fails");
        match err {
            PaladinError::IoError { operation, .. } => {
                assert_eq!(operation, "stat_vault_dir");
            }
            other => panic!("expected stat_vault_dir IO error, got {other:?}"),
        }
    }

    #[test]
    fn ensure_vault_dir_symlink_is_rejected_without_following() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, Permissions::from_mode(0o700)).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = ensure_vault_dir(&link).expect_err("symlink rejected");
        match err {
            PaladinError::IoError { operation, .. } => {
                assert_eq!(operation, "vault_dir_is_symlink");
            }
            other => panic!("expected symlink IO error, got {other:?}"),
        }
    }
}
