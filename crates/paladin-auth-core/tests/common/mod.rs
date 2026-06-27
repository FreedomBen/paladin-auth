// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared test helpers for the `paladin-auth-core` integration suite.
//!
//! The only function here today is [`test_tempdir`], which exists to
//! pin tempdir creation to a known-good location so a misconfigured
//! `TMPDIR` (e.g. pointing at the workspace root) can never make
//! tests deposit scratch files inside the source tree.

#![allow(dead_code)]

use std::path::PathBuf;

use tempfile::TempDir;

/// Create a fresh `0700` tempdir under a path that **ignores `$TMPDIR`**.
///
/// Prefers Cargo's `CARGO_TARGET_TMPDIR` (set automatically for
/// integration tests, scoped to `target/`) and falls back to `/tmp`.
/// The default `tempfile::TempDir::new()` would honor `$TMPDIR` —
/// if a developer has `TMPDIR=$(pwd)` exported, scratch dirs leak
/// into the workspace.
pub fn test_tempdir() -> TempDir {
    tempfile::Builder::new()
        .prefix(".tmp")
        .tempdir_in(safe_test_tmp_root())
        .expect("create test tempdir")
}

fn safe_test_tmp_root() -> PathBuf {
    std::env::var_os("CARGO_TARGET_TMPDIR").map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
}
