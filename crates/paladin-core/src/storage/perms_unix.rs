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
// Mode strings on the typed `unsafe_permissions` error are exactly
// four octal digits ("0644" / "0700") so the CLI / TUI / GUI
// `format_unsafe_permissions` helper (Phase G) can render the
// `chmod NNN` repair hint without re-implementing the format.
//
// `inspect()` deliberately bypasses these checks (see §4.7) so a
// caller can probe the on-disk mode before fixing perms.

use std::fs::Metadata;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::error::{PaladinError, PermissionSubject, Result};

/// Required mode for vault directories per §4.3 (`0700`).
const REQUIRED_DIR_MODE: u32 = 0o700;
/// Required mode for vault files per §4.3 (`0600`).
const REQUIRED_FILE_MODE: u32 = 0o600;
/// Mask catching any group / other permission bit; if any of these
/// bits are set the path is unsafe regardless of owner perms.
const FORBIDDEN_BITS: u32 = 0o077;

/// Reject the directory at `path` if its mode grants any group or
/// other permissions. Stat errors propagate as
/// `io_error { operation: "stat_vault_dir" }`.
pub(crate) fn enforce_dir_perms(path: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|err| PaladinError::IoError {
        operation: "stat_vault_dir",
        source: err,
    })?;
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

/// Reject the file whose `meta` was already stat'd by the caller
/// when its mode grants any group or other permissions.
///
/// The caller is responsible for stat'ing the path so this helper
/// can be reused for both `vault_file` and `backup_file` subjects
/// without re-stat'ing each one (the open path stats both anyway).
pub(crate) fn enforce_file_perms_from_meta(
    path: &Path,
    meta: &Metadata,
    subject: PermissionSubject,
) -> Result<()> {
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
}
