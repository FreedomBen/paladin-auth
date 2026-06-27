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

use crate::error::{PaladinAuthError, PermissionSubject};
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
pub fn format_unsafe_permissions(err: &PaladinAuthError) -> Option<String> {
    match err {
        PaladinAuthError::UnsafePermissions {
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
/// human-readable message naming the directory that paladin-auth was trying
/// to create and the underlying OS error. Returns `None` for any other
/// error kind so callers can fall through to their default error path.
///
/// `PaladinAuthError::IoError` doesn't carry a path, so the caller supplies
/// `attempted_dir` — typically `vault_path.parent()` from the
/// `Store::create` / `Store::create_force` call site. The returned
/// string ends with a hint pointing the user at the most common cause
/// (no write permission on the parent directory).
///
/// CLI, TUI, and GUI all route their create-vault-dir error rendering
/// through this helper so wording never drifts between front ends.
#[must_use]
pub fn format_create_vault_dir_error(
    err: &PaladinAuthError,
    attempted_dir: &Path,
) -> Option<String> {
    match err {
        PaladinAuthError::IoError {
            operation: "create_vault_dir",
            source,
        } => Some(format!(
            "Could not create the paladin-auth data directory at {dir}: {source}.\nCheck that you have write permission to the parent directory.",
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

/// Format the destructive-confirmation text shown by CLI `destroy`
/// (§5 text mode), the TUI Destroy modal (§6), and the GTK
/// `DestroyDialog` (§7) before a vault is wiped from disk.
///
/// Names the resolved primary path and — when `backup_present` is
/// `true` — the derived `vault.bin.bak` path, states the operation is
/// irreversible, and notes the file is unlinked rather than
/// securely erased so an encrypted vault (§4.4) is the only reliable
/// protection for secrets already on disk.
///
/// Callers compute `backup_present` from `try_exists` on the sibling
/// `.bak`; passing `false` when no backup is on disk keeps the wording
/// honest. The derived `.bak` path appends a `.bak` suffix to the file
/// name component, matching [`format_init_force_warning`], so a
/// non-default `--vault` path renders the real rotation target.
#[must_use]
pub fn format_destroy_warning(vault_path: &Path, backup_present: bool) -> String {
    if backup_present {
        let bak = backup_path_for(vault_path);
        format!(
            "This will permanently delete the vault at {} and its backup at {}. This cannot be undone. The files are unlinked, not securely erased, so an encrypted vault is the only reliable protection for secrets already written to disk.",
            vault_path.display(),
            bak.display(),
        )
    } else {
        format!(
            "This will permanently delete the vault at {}. This cannot be undone. The file is unlinked, not securely erased, so an encrypted vault is the only reliable protection for secrets already written to disk.",
            vault_path.display(),
        )
    }
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

/// Static warning shown before a per-account QR code is rendered or
/// written to disk (CLI `qr` command, TUI per-account QR modal, GUI
/// per-account QR dialog). The text calls out that the QR encodes the
/// account secret, that anyone who sees or photographs it can clone the
/// OTP, that saved QR files should be treated like a plaintext export,
/// and that HOTP exports encode the *current* counter and do not
/// advance — the user's existing device retains code parity with a
/// second device that scans the QR.
#[must_use]
pub fn format_plaintext_qr_export_warning() -> String {
    "WARNING: A QR code encodes the account secret. Anyone who sees or \
     photographs it can clone the OTP, so treat the displayed code and any \
     saved QR file like a plaintext export. HOTP exports encode the current \
     counter and do not advance it; scanning the QR into a second device \
     keeps both devices in sync."
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
    use crate::error::{PaladinAuthError, PermissionSubject, TimeRangeKind};
    use std::path::PathBuf;

    fn perms_err(
        path: &str,
        subject: PermissionSubject,
        actual: &str,
        expected: &str,
    ) -> PaladinAuthError {
        PaladinAuthError::UnsafePermissions {
            path: PathBuf::from(path),
            subject,
            actual_mode: actual.to_string(),
            expected_mode: expected.to_string(),
        }
    }

    #[test]
    fn format_unsafe_permissions_vault_file_fixture() {
        let err = perms_err(
            "/home/u/.local/share/paladin-auth/vault.bin",
            PermissionSubject::VaultFile,
            "0644",
            "0600",
        );
        assert_eq!(
            format_unsafe_permissions(&err).unwrap(),
            "unsafe permissions on /home/u/.local/share/paladin-auth/vault.bin: vault file mode 0644, expected 0600.\n\
             Run: chmod 0600 /home/u/.local/share/paladin-auth/vault.bin"
        );
    }

    #[test]
    fn format_unsafe_permissions_vault_dir_fixture() {
        let err = perms_err(
            "/home/u/.local/share/paladin-auth",
            PermissionSubject::VaultDir,
            "0755",
            "0700",
        );
        assert_eq!(
            format_unsafe_permissions(&err).unwrap(),
            "unsafe permissions on /home/u/.local/share/paladin-auth: vault directory mode 0755, expected 0700.\n\
             Run: chmod 0700 /home/u/.local/share/paladin-auth"
        );
    }

    #[test]
    fn format_unsafe_permissions_backup_file_fixture() {
        let err = perms_err(
            "/home/u/.local/share/paladin-auth/vault.bin.bak",
            PermissionSubject::BackupFile,
            "0660",
            "0600",
        );
        assert_eq!(
            format_unsafe_permissions(&err).unwrap(),
            "unsafe permissions on /home/u/.local/share/paladin-auth/vault.bin.bak: backup file mode 0660, expected 0600.\n\
             Run: chmod 0600 /home/u/.local/share/paladin-auth/vault.bin.bak"
        );
    }

    #[test]
    fn format_unsafe_permissions_returns_none_for_other_kinds() {
        // Sample of other variants — the helper must return None for
        // anything that is not `unsafe_permissions`, so the CLI / TUI /
        // GUI can fall through to their default error renderer.
        let cases = [
            PaladinAuthError::VaultMissing,
            PaladinAuthError::VaultExists,
            PaladinAuthError::DecryptFailed,
            PaladinAuthError::InvalidHeader,
            PaladinAuthError::UnsupportedFormatVersion { format_ver: 99 },
            PaladinAuthError::CounterOverflow {
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
            PaladinAuthError::SaveDurabilityUnconfirmed,
            PaladinAuthError::TimeRange {
                operation: "totp_code",
                kind: TimeRangeKind::PreEpoch,
            },
            PaladinAuthError::IoError {
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
        let err = PaladinAuthError::IoError {
            operation: "create_vault_dir",
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        let dir = Path::new("/home/u/.local/share/paladin-auth");
        assert_eq!(
            format_create_vault_dir_error(&err, dir).unwrap(),
            "Could not create the paladin-auth data directory at /home/u/.local/share/paladin-auth: permission denied.\n\
             Check that you have write permission to the parent directory."
        );
    }

    #[test]
    fn format_create_vault_dir_error_returns_none_for_other_ops_and_kinds() {
        // The helper must only fire for io_error { operation = "create_vault_dir" };
        // every other variant (and every other operation string) falls
        // through to the caller's default renderer.
        let dir = Path::new("/somewhere");
        let cases: [PaladinAuthError; 4] = [
            PaladinAuthError::VaultMissing,
            PaladinAuthError::UnsafePermissions {
                path: std::path::PathBuf::from("/x"),
                subject: PermissionSubject::VaultDir,
                actual_mode: "0755".to_string(),
                expected_mode: "0700".to_string(),
            },
            PaladinAuthError::IoError {
                operation: "stat_vault_dir",
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            PaladinAuthError::IoError {
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
            format_init_force_warning(Path::new("/home/u/.local/share/paladin-auth/vault.bin")),
            "This will overwrite the existing vault at /home/u/.local/share/paladin-auth/vault.bin. \
             The previous vault will be rotated to /home/u/.local/share/paladin-auth/vault.bin.bak; \
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
    fn format_destroy_warning_without_backup_names_only_primary() {
        assert_eq!(
            format_destroy_warning(Path::new("/home/u/.local/share/paladin-auth/vault.bin"), false,),
            "This will permanently delete the vault at /home/u/.local/share/paladin-auth/vault.bin. \
             This cannot be undone. The file is unlinked, not securely erased, so an encrypted \
             vault is the only reliable protection for secrets already written to disk."
        );
    }

    #[test]
    fn format_destroy_warning_with_backup_names_primary_and_bak() {
        assert_eq!(
            format_destroy_warning(Path::new("/home/u/.local/share/paladin-auth/vault.bin"), true,),
            "This will permanently delete the vault at /home/u/.local/share/paladin-auth/vault.bin \
             and its backup at /home/u/.local/share/paladin-auth/vault.bin.bak. This cannot be \
             undone. The files are unlinked, not securely erased, so an encrypted vault is the \
             only reliable protection for secrets already written to disk."
        );
    }

    #[test]
    fn format_destroy_warning_custom_basename_renders_real_bak_path() {
        // A `--vault` override may name the file something other than
        // `vault.bin`; the named backup must reflect the actual basename
        // so the user sees the files that will actually be deleted.
        assert_eq!(
            format_destroy_warning(Path::new("/tmp/work/secrets.dat"), true),
            "This will permanently delete the vault at /tmp/work/secrets.dat and its backup at \
             /tmp/work/secrets.dat.bak. This cannot be undone. The files are unlinked, not \
             securely erased, so an encrypted vault is the only reliable protection for secrets \
             already written to disk."
        );
    }

    #[test]
    fn format_destroy_warning_backup_flag_changes_wording() {
        // The `backup_present` flag must change the rendered text — the
        // with-backup branch names a second file and pluralizes, so the
        // two branches can never collapse to the same string.
        let primary = Path::new("/tmp/work/vault.bin");
        assert_ne!(
            format_destroy_warning(primary, true),
            format_destroy_warning(primary, false)
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
    fn format_plaintext_qr_export_warning_fixture() {
        assert_eq!(
            format_plaintext_qr_export_warning(),
            "WARNING: A QR code encodes the account secret. Anyone who sees or \
             photographs it can clone the OTP, so treat the displayed code and any \
             saved QR file like a plaintext export. HOTP exports encode the current \
             counter and do not advance it; scanning the QR into a second device \
             keeps both devices in sync."
        );
    }

    #[test]
    fn format_plaintext_qr_export_warning_is_distinct_from_storage_and_export() {
        // The QR warning covers a different surface (per-account QR
        // render / save) than the vault-creation / export-to-disk
        // warnings, so the three helpers must not collapse to the same
        // wording at any of the three call sites that consume them.
        let qr = format_plaintext_qr_export_warning();
        assert_ne!(qr, format_plaintext_storage_warning());
        assert_ne!(qr, format_plaintext_export_warning());
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
