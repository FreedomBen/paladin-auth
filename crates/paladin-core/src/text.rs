// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared front-end text helpers (docs/DESIGN.md §4.7).
//
// CLI, TUI, and GUI all render the messages below through these
// helpers so wording never drifts between front ends. Strings are
// pinned by fixture tests at the bottom of the file — change wording
// only by changing the fixtures here, never by re-implementing it in a
// presentation crate.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{PaladinError, PermissionSubject};
use crate::ValidationWarning;

/// Render an `unsafe_permissions` error (§4.3) as a human-readable
/// message with a `chmod` repair hint. Returns `None` for any other
/// error kind so callers can fall through to their default error path.
///
/// All wording is sourced from the typed error fields (`path`,
/// `subject`, `actual_mode`, `expected_mode`) so the helper does not
/// need to know which call surfaced the error. The `expected_mode`
/// string on the error is already four-digit octal (`"0700"` for
/// directories, `"0600"` for files), which matches the `chmod` hint
/// verbatim.
#[must_use]
pub fn format_unsafe_permissions(err: &PaladinError) -> Option<String> {
    match err {
        PaladinError::UnsafePermissions {
            path,
            subject,
            actual_mode,
            expected_mode,
        } => Some(format!(
            "unsafe permissions on {path}: {subject_label} mode {actual_mode}, expected {expected_mode}.\nRun: chmod {expected_mode} {path}",
            path = path.display(),
            subject_label = subject_label(*subject),
        )),
        _ => None,
    }
}

/// Render a `create_vault_dir` `IoError` (§4.3 mkdir failure) as a
/// human-readable message naming the directory that paladin was trying
/// to create and the underlying OS error. Returns `None` for any other
/// error kind so callers can fall through to their default error path.
///
/// `PaladinError::IoError` doesn't carry a path, so the caller supplies
/// `attempted_dir` — typically `vault_path.parent()` from the
/// `Store::create` / `Store::create_force` call site. The returned
/// string ends with a hint pointing the user at the most common cause
/// (no write permission on the parent directory).
///
/// CLI, TUI, and GUI all route their create-vault-dir error rendering
/// through this helper so wording never drifts between front ends.
#[must_use]
pub fn format_create_vault_dir_error(err: &PaladinError, attempted_dir: &Path) -> Option<String> {
    match err {
        PaladinError::IoError {
            operation: "create_vault_dir",
            source,
        } => Some(format!(
            "Could not create the paladin data directory at {dir}: {source}.\nCheck that you have write permission to the parent directory.",
            dir = attempted_dir.display(),
        )),
        _ => None,
    }
}

fn subject_label(subject: PermissionSubject) -> &'static str {
    match subject {
        PermissionSubject::VaultDir => "vault directory",
        PermissionSubject::VaultFile => "vault file",
        PermissionSubject::BackupFile => "backup file",
    }
}

/// Format the `init --force` clobber warning shown by CLI `init` and
/// the GUI `InitDialog` destructive gate. Names the existing vault
/// path, derives the matching `.bak` path, and warns that any prior
/// backup at that location will be overwritten verbatim.
///
/// The derived `.bak` path appends a `.bak` suffix to the file name
/// component so paths whose basename is not literally `vault.bin` —
/// e.g. a non-default `--vault` argument — render the actual rotation
/// target rather than a generic placeholder.
#[must_use]
pub fn format_init_force_warning(existing_vault: &Path) -> String {
    let bak = backup_path_for(existing_vault);
    format!(
        "This will overwrite the existing vault at {}. The previous vault will be rotated to {}; any prior backup at that location will be overwritten.",
        existing_vault.display(),
        bak.display(),
    )
}

fn backup_path_for(primary: &Path) -> PathBuf {
    let mut name: OsString = primary.file_name().map_or_else(
        || OsString::from("vault.bin"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(".bak");
    primary.with_file_name(name)
}

/// Static warning shown before a plaintext-mode vault is created
/// (CLI `init`, GUI `InitDialog`) or before a passphrase is removed
/// (CLI `passphrase remove`, TUI Passphrase modal, GUI
/// `PassphraseDialog`).
///
/// The text is intentionally parameter-free so every caller renders
/// byte-identical wording.
#[must_use]
pub fn format_plaintext_storage_warning() -> String {
    "WARNING: Plaintext storage keeps account secrets unencrypted on disk. \
     The vault file is restricted to your user account (mode 0600), but \
     anyone with read access to that file or its backups can recover every \
     secret. Use an encrypted vault unless you fully accept this risk."
        .to_string()
}

/// Static warning shown before a plaintext export writes unencrypted
/// secrets to disk (CLI `export --plaintext`, TUI Export modal
/// plaintext path, GUI `ExportDialog` plaintext path).
#[must_use]
pub fn format_plaintext_export_warning() -> String {
    "WARNING: Plaintext export writes account secrets unencrypted to disk. \
     Anyone with access to the export file can recover every secret. Use an \
     encrypted export instead, and delete the plaintext file once it has \
     served its purpose."
        .to_string()
}

/// Stable human-readable message for a `ValidationWarning`. Used as
/// the JSON `message` field, by text-mode CLI stderr output, and by
/// TUI / GUI inline warnings so wording never drifts.
#[must_use]
pub fn format_validation_warning(warning: &ValidationWarning) -> String {
    match warning {
        ValidationWarning::ShortSecret {
            decoded_len,
            recommended_min,
        } => format!(
            "secret is shorter than recommended (decoded length {decoded_len} bytes; recommended minimum {recommended_min} bytes)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AccountId, AccountKindSummary, AccountSummary, Algorithm};
    use crate::error::{PaladinError, PermissionSubject, TimeRangeKind};
    use std::path::PathBuf;

    fn perms_err(
        path: &str,
        subject: PermissionSubject,
        actual: &str,
        expected: &str,
    ) -> PaladinError {
        PaladinError::UnsafePermissions {
            path: PathBuf::from(path),
            subject,
            actual_mode: actual.to_string(),
            expected_mode: expected.to_string(),
        }
    }

    #[test]
    fn format_unsafe_permissions_vault_file_fixture() {
        let err = perms_err(
            "/home/u/.local/share/paladin/vault.bin",
            PermissionSubject::VaultFile,
            "0644",
            "0600",
        );
        assert_eq!(
            format_unsafe_permissions(&err).unwrap(),
            "unsafe permissions on /home/u/.local/share/paladin/vault.bin: vault file mode 0644, expected 0600.\n\
             Run: chmod 0600 /home/u/.local/share/paladin/vault.bin"
        );
    }

    #[test]
    fn format_unsafe_permissions_vault_dir_fixture() {
        let err = perms_err(
            "/home/u/.local/share/paladin",
            PermissionSubject::VaultDir,
            "0755",
            "0700",
        );
        assert_eq!(
            format_unsafe_permissions(&err).unwrap(),
            "unsafe permissions on /home/u/.local/share/paladin: vault directory mode 0755, expected 0700.\n\
             Run: chmod 0700 /home/u/.local/share/paladin"
        );
    }

    #[test]
    fn format_unsafe_permissions_backup_file_fixture() {
        let err = perms_err(
            "/home/u/.local/share/paladin/vault.bin.bak",
            PermissionSubject::BackupFile,
            "0660",
            "0600",
        );
        assert_eq!(
            format_unsafe_permissions(&err).unwrap(),
            "unsafe permissions on /home/u/.local/share/paladin/vault.bin.bak: backup file mode 0660, expected 0600.\n\
             Run: chmod 0600 /home/u/.local/share/paladin/vault.bin.bak"
        );
    }

    #[test]
    fn format_unsafe_permissions_returns_none_for_other_kinds() {
        // Sample of other variants — the helper must return None for
        // anything that is not `unsafe_permissions`, so the CLI / TUI /
        // GUI can fall through to their default error renderer.
        let cases = [
            PaladinError::VaultMissing,
            PaladinError::VaultExists,
            PaladinError::DecryptFailed,
            PaladinError::InvalidHeader,
            PaladinError::UnsupportedFormatVersion { format_ver: 99 },
            PaladinError::CounterOverflow {
                account: AccountSummary {
                    id: AccountId::new(),
                    issuer: None,
                    label: "x".to_string(),
                    kind: AccountKindSummary::Hotp,
                    algorithm: Algorithm::Sha1,
                    digits: 6,
                    period: None,
                    counter: Some(u64::MAX),
                    icon_hint: None,
                    created_at: 0,
                    updated_at: 0,
                },
            },
            PaladinError::SaveDurabilityUnconfirmed,
            PaladinError::TimeRange {
                operation: "totp_code",
                kind: TimeRangeKind::PreEpoch,
            },
            PaladinError::IoError {
                operation: "read_vault_file",
                source: std::io::Error::other("x"),
            },
        ];
        for err in &cases {
            assert!(
                format_unsafe_permissions(err).is_none(),
                "expected None for {err:?}"
            );
        }
    }

    #[test]
    fn format_unsafe_permissions_uses_expected_mode_in_chmod_for_files() {
        // The chmod hint must always echo `expected_mode` verbatim, so
        // file subjects render `chmod 0600` and directory subjects
        // render `chmod 0700` — nothing else may appear there. This
        // pins the rule independent of the per-subject fixtures above.
        let file = perms_err("/v", PermissionSubject::VaultFile, "0666", "0600");
        assert!(format_unsafe_permissions(&file)
            .unwrap()
            .contains("chmod 0600 /v"));

        let dir = perms_err("/d", PermissionSubject::VaultDir, "0777", "0700");
        assert!(format_unsafe_permissions(&dir)
            .unwrap()
            .contains("chmod 0700 /d"));
    }

    #[test]
    fn format_create_vault_dir_error_renders_path_source_and_hint() {
        let err = PaladinError::IoError {
            operation: "create_vault_dir",
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        let dir = Path::new("/home/u/.local/share/paladin");
        assert_eq!(
            format_create_vault_dir_error(&err, dir).unwrap(),
            "Could not create the paladin data directory at /home/u/.local/share/paladin: permission denied.\n\
             Check that you have write permission to the parent directory."
        );
    }

    #[test]
    fn format_create_vault_dir_error_returns_none_for_other_ops_and_kinds() {
        // The helper must only fire for io_error { operation = "create_vault_dir" };
        // every other variant (and every other operation string) falls
        // through to the caller's default renderer.
        let dir = Path::new("/somewhere");
        let cases: [PaladinError; 4] = [
            PaladinError::VaultMissing,
            PaladinError::UnsafePermissions {
                path: std::path::PathBuf::from("/x"),
                subject: PermissionSubject::VaultDir,
                actual_mode: "0755".to_string(),
                expected_mode: "0700".to_string(),
            },
            PaladinError::IoError {
                operation: "stat_vault_dir",
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            PaladinError::IoError {
                operation: "read_vault_file",
                source: std::io::Error::other("x"),
            },
        ];
        for err in &cases {
            assert!(
                format_create_vault_dir_error(err, dir).is_none(),
                "expected None for {err:?}"
            );
        }
    }

    #[test]
    fn format_init_force_warning_default_basename_fixture() {
        assert_eq!(
            format_init_force_warning(Path::new("/home/u/.local/share/paladin/vault.bin")),
            "This will overwrite the existing vault at /home/u/.local/share/paladin/vault.bin. \
             The previous vault will be rotated to /home/u/.local/share/paladin/vault.bin.bak; \
             any prior backup at that location will be overwritten."
        );
    }

    #[test]
    fn format_init_force_warning_custom_basename_renders_real_bak_path() {
        // A `--vault` override may name the file something other than
        // `vault.bin`; the rotation target must reflect the actual
        // basename rather than a generic placeholder, so the user sees
        // the file that will actually be overwritten.
        assert_eq!(
            format_init_force_warning(Path::new("/tmp/work/secrets.dat")),
            "This will overwrite the existing vault at /tmp/work/secrets.dat. \
             The previous vault will be rotated to /tmp/work/secrets.dat.bak; \
             any prior backup at that location will be overwritten."
        );
    }

    #[test]
    fn format_plaintext_storage_warning_fixture() {
        assert_eq!(
            format_plaintext_storage_warning(),
            "WARNING: Plaintext storage keeps account secrets unencrypted on disk. \
             The vault file is restricted to your user account (mode 0600), but \
             anyone with read access to that file or its backups can recover every \
             secret. Use an encrypted vault unless you fully accept this risk."
        );
    }

    #[test]
    fn format_plaintext_export_warning_fixture() {
        assert_eq!(
            format_plaintext_export_warning(),
            "WARNING: Plaintext export writes account secrets unencrypted to disk. \
             Anyone with access to the export file can recover every secret. Use an \
             encrypted export instead, and delete the plaintext file once it has \
             served its purpose."
        );
    }

    #[test]
    fn format_plaintext_warnings_are_distinct_strings() {
        // Storage and export warnings cover different surfaces (vault
        // creation vs export-to-disk), so the two helpers must not
        // alias to the same text — divergence here would silently
        // collapse the two confirmation flows into one wording.
        assert_ne!(
            format_plaintext_storage_warning(),
            format_plaintext_export_warning()
        );
    }

    #[test]
    fn format_validation_warning_short_secret_fixture() {
        let warning = ValidationWarning::ShortSecret {
            decoded_len: 10,
            recommended_min: 16,
        };
        assert_eq!(
            format_validation_warning(&warning),
            "secret is shorter than recommended (decoded length 10 bytes; recommended minimum 16 bytes)"
        );
    }

    #[test]
    fn format_validation_warning_short_secret_uses_supplied_values() {
        // Distinct values are interpolated verbatim, so a future
        // `recommended_min` change in the validator surfaces correctly
        // through the helper without re-implementing the wording.
        let warning = ValidationWarning::ShortSecret {
            decoded_len: 5,
            recommended_min: 20,
        };
        let text = format_validation_warning(&warning);
        assert!(text.contains("decoded length 5 bytes"), "got {text}");
        assert!(text.contains("recommended minimum 20 bytes"), "got {text}");
    }
}
