// SPDX-License-Identifier: AGPL-3.0-or-later
//
// §4.3 permissions enforcement (non-Unix stub).
//
// v0.1 ships Linux-only; this stub keeps the storage module's
// platform-agnostic call sites compiling on hypothetical non-Unix
// targets without silently weakening the Unix-side guarantees.

use std::fs::Metadata;
use std::io;
use std::path::Path;

use crate::error::{PaladinError, PermissionSubject, Result};

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

pub(crate) fn enforce_file_perms_from_meta(
    _path: &Path,
    _meta: &Metadata,
    _subject: PermissionSubject,
) -> Result<()> {
    Ok(())
}
