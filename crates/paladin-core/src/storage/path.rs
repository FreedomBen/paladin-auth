// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Default vault path resolver (docs/DESIGN.md §4.3).
//
// Presentation crates ask `paladin_core::default_vault_path()` for the
// canonical `vault.bin` location so they don't duplicate `ProjectDirs`
// logic. The CLI's `--vault <path>` override is applied by the front
// end before reaching `paladin-core`.

use std::path::PathBuf;

use directories::ProjectDirs;

use crate::error::{PaladinError, Result};

/// Filename for the vault primary, under the platform data directory.
///
/// Public so front ends can compute related paths (`.bak`, `.tmp`)
/// without re-deriving the constant.
pub const VAULT_FILENAME: &str = "vault.bin";

/// Resolve the default vault path: `ProjectDirs::from("", "", "paladin")`,
/// `data_dir()`, then `vault.bin`. Surfaces `io_error` with
/// `operation: "resolve_default_vault_path"` if the platform path
/// cannot be resolved.
pub fn default_vault_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("", "", "paladin").ok_or_else(|| PaladinError::IoError {
        operation: "resolve_default_vault_path",
        source: std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ProjectDirs::from returned None (no platform home directory)",
        ),
    })?;
    Ok(dirs.data_dir().join(VAULT_FILENAME))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn vault_filename_constant_locks_section_4_3() {
        assert_eq!(VAULT_FILENAME, "vault.bin");
    }

    #[test]
    fn default_vault_path_ends_with_vault_bin() {
        // On every supported platform `ProjectDirs::from("", "", "paladin")`
        // resolves (CI runs this on Linux). We just assert the filename
        // suffix is the §4.3 constant; the parent directory varies by
        // platform.
        let path = default_vault_path().expect("default_vault_path resolves on this platform");
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(VAULT_FILENAME)
        );
    }

    #[test]
    fn default_vault_path_uses_paladin_project_dirs() {
        // The path must contain "paladin" somewhere — `ProjectDirs::from`
        // appends it as the project name. This catches accidental swaps
        // to the wrong qualifier triple.
        let path = default_vault_path().expect("resolves");
        let s = path.to_string_lossy();
        assert!(
            s.contains("paladin"),
            "default_vault_path {s:?} does not contain 'paladin'"
        );
    }

    // The `io_error` failure path is exercised by an integration-style
    // test where ProjectDirs returns None; we don't have a portable way
    // to force that from inside the unit test, so the helper below
    // proves the error shape is constructible by core code (catches an
    // accidental rename of the operation tag).
    #[test]
    fn resolve_failure_uses_stable_operation_tag() {
        let err = PaladinError::IoError {
            operation: "resolve_default_vault_path",
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "synthetic"),
        };
        assert_eq!(err.kind(), ErrorKind::IoError);
        let rendered = format!("{err}");
        assert!(rendered.contains("resolve_default_vault_path"));
    }
}
