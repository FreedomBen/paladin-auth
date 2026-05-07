// SPDX-License-Identifier: AGPL-3.0-or-later
//
// §4.3 permissions enforcement (non-Unix stub).
//
// v0.1 ships Linux-only; this stub keeps the storage module's
// platform-agnostic call sites compiling on hypothetical non-Unix
// targets without silently weakening the Unix-side guarantees.

use std::fs::Metadata;
use std::path::Path;

use crate::error::{PermissionSubject, Result};

pub(crate) fn enforce_dir_perms(_path: &Path) -> Result<()> {
    Ok(())
}

pub(crate) fn enforce_file_perms_from_meta(
    _path: &Path,
    _meta: &Metadata,
    _subject: PermissionSubject,
) -> Result<()> {
    Ok(())
}
