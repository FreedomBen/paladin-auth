// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared test helpers for the `paladin-tui` integration suite.
//!
//! [`test_tempdir`] pins tempdir creation to a path that ignores
//! `$TMPDIR`, so a misconfigured shell (e.g. `TMPDIR=$(pwd)`) cannot
//! make tests deposit scratch dirs inside the workspace.
//!
//! [`secure_test_tempdir`] returns the same kind of tempdir but
//! explicitly `chmod`s it to `0700` so the §4.3 `unsafe_permissions`
//! check passes when the host's tempdir-root has looser bits.

#![allow(dead_code)]

use std::path::PathBuf;

use tempfile::TempDir;

/// See [`super::test_tempdir`] in `paladin-core`'s common module.
/// Duplicated here because each test crate is its own compilation
/// unit; the helper is tiny enough that a shared dependency would
/// cost more than it saves.
pub fn test_tempdir() -> TempDir {
    tempfile::Builder::new()
        .prefix(".tmp")
        .tempdir_in(safe_test_tmp_root())
        .expect("create test tempdir")
}

/// `test_tempdir()` followed by `chmod 0700` so `unsafe_permissions`
/// checks pass when the host's tempdir-root inherits looser bits.
pub fn secure_test_tempdir() -> TempDir {
    let dir = test_tempdir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

fn safe_test_tmp_root() -> PathBuf {
    std::env::var_os("CARGO_TARGET_TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
}
