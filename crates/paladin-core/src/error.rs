// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `PaladinError` carries the §5 `error_kind` values verbatim so the
// CLI's `--json` output can serialize them without renaming or remapping.
// Only the *core-returnable* kinds appear here; the presentation-only
// kinds (`clipboard_write_failed`, `no_match`, `multiple_matches`,
// `duplicate_account`) live in front-end crates.

use std::fmt;
use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, PaladinError>;

/// Stable §5 `error_kind` discriminator. Each variant maps 1:1 to a
/// JSON `error_kind` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    ValidationError,
    InvalidPassphrase,
    InvalidState,
    VaultMissing,
    VaultExists,
    UnsafePermissions,
    WrongVaultLock,
    DecryptFailed,
    InvalidHeader,
    InvalidPayload,
    UnsupportedFormatVersion,
    KdfParamsOutOfBounds,
    UnsupportedImportFormat,
    UnsupportedPlaintextVault,
    UnsupportedEncryptedAegis,
    UnsupportedAegisEntryType,
    NoEntriesToImport,
    CounterOverflow,
    TimeRange,
    SaveNotCommitted,
    SaveDurabilityUnconfirmed,
    IoError,
}

impl ErrorKind {
    /// The `error_kind` JSON string for this variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidationError => "validation_error",
            Self::InvalidPassphrase => "invalid_passphrase",
            Self::InvalidState => "invalid_state",
            Self::VaultMissing => "vault_missing",
            Self::VaultExists => "vault_exists",
            Self::UnsafePermissions => "unsafe_permissions",
            Self::WrongVaultLock => "wrong_vault_lock",
            Self::DecryptFailed => "decrypt_failed",
            Self::InvalidHeader => "invalid_header",
            Self::InvalidPayload => "invalid_payload",
            Self::UnsupportedFormatVersion => "unsupported_format_version",
            Self::KdfParamsOutOfBounds => "kdf_params_out_of_bounds",
            Self::UnsupportedImportFormat => "unsupported_import_format",
            Self::UnsupportedPlaintextVault => "unsupported_plaintext_vault",
            Self::UnsupportedEncryptedAegis => "unsupported_encrypted_aegis",
            Self::UnsupportedAegisEntryType => "unsupported_aegis_entry_type",
            Self::NoEntriesToImport => "no_entries_to_import",
            Self::CounterOverflow => "counter_overflow",
            Self::TimeRange => "time_range",
            Self::SaveNotCommitted => "save_not_committed",
            Self::SaveDurabilityUnconfirmed => "save_durability_unconfirmed",
            Self::IoError => "io_error",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Vault-mode discriminator surfaced in `wrong_vault_lock` errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultMode {
    Plaintext,
    Encrypted,
}

impl VaultMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Encrypted => "encrypted",
        }
    }
}

impl fmt::Display for VaultMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Core-returnable §5 errors. The variants intentionally carry their
/// extra fields so the JSON serializer (`error-serde` cargo feature)
/// can lift them into the `error_kind` payload without an extra mapping
/// layer.
#[derive(Debug, Error)]
pub enum PaladinError {
    #[error("validation error: {field}: {reason}")]
    ValidationError {
        field: &'static str,
        reason: String,
        /// Optional 0-based index into a batch input (otpauth list, Aegis,
        /// QR), present only when the error is attributable to one row.
        source_index: Option<usize>,
        /// Optional decoded secret length for `short_secret` /
        /// `secret_too_long` rejections; otherwise `None`.
        decoded_len: Option<usize>,
        /// Optional minimum recommended secret length for
        /// `short_secret` warnings.
        recommended_min: Option<usize>,
        /// Optional Aegis entry type for `unsupported_aegis_entry_type`
        /// when surfaced as a validation error.
        entry_type: Option<String>,
    },

    #[error("invalid passphrase: {reason}")]
    InvalidPassphrase { reason: &'static str },

    #[error("invalid state: {operation}: {state}")]
    InvalidState {
        operation: &'static str,
        state: &'static str,
    },

    #[error("vault file is missing")]
    VaultMissing,

    #[error("vault file already exists")]
    VaultExists,

    #[error(
        "unsafe permissions on {path}: {subject} mode {actual_mode}, expected {expected_mode}"
    )]
    UnsafePermissions {
        path: PathBuf,
        /// One of `vault_dir`, `vault_file`, `backup_file`.
        subject: PermissionSubject,
        /// Four-digit octal mode string ("0644").
        actual_mode: String,
        /// Four-digit octal mode string ("0700" for dirs, "0600" for files).
        expected_mode: String,
    },

    #[error("wrong vault lock: expected {expected}, supplied {actual}")]
    WrongVaultLock {
        expected: VaultMode,
        actual: VaultMode,
    },

    #[error("decryption failed")]
    DecryptFailed,

    #[error("invalid vault header")]
    InvalidHeader,

    #[error("invalid vault payload: {reason}")]
    InvalidPayload { reason: &'static str },

    #[error("unsupported vault format version")]
    UnsupportedFormatVersion,

    #[error("Argon2 KDF parameters out of bounds: m_kib={m_kib} t={t} p={p}")]
    KdfParamsOutOfBounds { m_kib: u32, t: u32, p: u32 },

    #[error("unsupported import format: {format}")]
    UnsupportedImportFormat { format: String },

    #[error("Paladin import bundle is plaintext; v0.1 imports require encrypted bundles")]
    UnsupportedPlaintextVault,

    #[error("Aegis encrypted backups are not supported in v0.1")]
    UnsupportedEncryptedAegis,

    #[error("Aegis entry type {entry_type:?} is not supported (only totp/hotp)")]
    UnsupportedAegisEntryType {
        source_index: usize,
        entry_type: String,
    },

    #[error("no entries to import")]
    NoEntriesToImport,

    #[error("HOTP counter overflow")]
    CounterOverflow,

    #[error("time out of range: {operation}: {kind}")]
    TimeRange {
        operation: &'static str,
        kind: TimeRangeKind,
    },

    #[error("save not committed (committed={committed})")]
    SaveNotCommitted {
        committed: bool,
        backup_path: Option<PathBuf>,
    },

    #[error("save durability unconfirmed")]
    SaveDurabilityUnconfirmed,

    #[error("I/O error during {operation}: {source}")]
    IoError {
        /// Stable, core-owned operation string from §5.
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

impl PaladinError {
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::ValidationError { .. } => ErrorKind::ValidationError,
            Self::InvalidPassphrase { .. } => ErrorKind::InvalidPassphrase,
            Self::InvalidState { .. } => ErrorKind::InvalidState,
            Self::VaultMissing => ErrorKind::VaultMissing,
            Self::VaultExists => ErrorKind::VaultExists,
            Self::UnsafePermissions { .. } => ErrorKind::UnsafePermissions,
            Self::WrongVaultLock { .. } => ErrorKind::WrongVaultLock,
            Self::DecryptFailed => ErrorKind::DecryptFailed,
            Self::InvalidHeader => ErrorKind::InvalidHeader,
            Self::InvalidPayload { .. } => ErrorKind::InvalidPayload,
            Self::UnsupportedFormatVersion => ErrorKind::UnsupportedFormatVersion,
            Self::KdfParamsOutOfBounds { .. } => ErrorKind::KdfParamsOutOfBounds,
            Self::UnsupportedImportFormat { .. } => ErrorKind::UnsupportedImportFormat,
            Self::UnsupportedPlaintextVault => ErrorKind::UnsupportedPlaintextVault,
            Self::UnsupportedEncryptedAegis => ErrorKind::UnsupportedEncryptedAegis,
            Self::UnsupportedAegisEntryType { .. } => ErrorKind::UnsupportedAegisEntryType,
            Self::NoEntriesToImport => ErrorKind::NoEntriesToImport,
            Self::CounterOverflow => ErrorKind::CounterOverflow,
            Self::TimeRange { .. } => ErrorKind::TimeRange,
            Self::SaveNotCommitted { .. } => ErrorKind::SaveNotCommitted,
            Self::SaveDurabilityUnconfirmed => ErrorKind::SaveDurabilityUnconfirmed,
            Self::IoError { .. } => ErrorKind::IoError,
        }
    }

    pub(crate) fn validation(field: &'static str, reason: impl Into<String>) -> Self {
        Self::ValidationError {
            field,
            reason: reason.into(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionSubject {
    VaultDir,
    VaultFile,
    BackupFile,
}

impl PermissionSubject {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultDir => "vault_dir",
            Self::VaultFile => "vault_file",
            Self::BackupFile => "backup_file",
        }
    }
}

impl fmt::Display for PermissionSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Discriminator for `time_range` errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRangeKind {
    PreEpoch,
    Overflow,
    OutOfRange,
}

impl TimeRangeKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreEpoch => "pre_epoch",
            Self::Overflow => "overflow",
            Self::OutOfRange => "out_of_range",
        }
    }
}

impl fmt::Display for TimeRangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_strings_match_section_5() {
        assert_eq!(ErrorKind::ValidationError.as_str(), "validation_error");
        assert_eq!(ErrorKind::IoError.as_str(), "io_error");
        assert_eq!(ErrorKind::CounterOverflow.as_str(), "counter_overflow");
        assert_eq!(ErrorKind::SaveNotCommitted.as_str(), "save_not_committed");
        assert_eq!(
            ErrorKind::SaveDurabilityUnconfirmed.as_str(),
            "save_durability_unconfirmed"
        );
    }

    #[test]
    fn vault_mode_strings_match_section_5() {
        assert_eq!(VaultMode::Plaintext.as_str(), "plaintext");
        assert_eq!(VaultMode::Encrypted.as_str(), "encrypted");
    }

    #[test]
    fn permission_subject_strings_match_section_5() {
        assert_eq!(PermissionSubject::VaultDir.as_str(), "vault_dir");
        assert_eq!(PermissionSubject::VaultFile.as_str(), "vault_file");
        assert_eq!(PermissionSubject::BackupFile.as_str(), "backup_file");
    }

    #[test]
    fn validation_helper_populates_field_and_reason() {
        let err = PaladinError::validation("digits", "out_of_range");
        assert_eq!(err.kind(), ErrorKind::ValidationError);
        match err {
            PaladinError::ValidationError {
                field,
                reason,
                source_index,
                decoded_len,
                recommended_min,
                entry_type,
            } => {
                assert_eq!(field, "digits");
                assert_eq!(reason, "out_of_range");
                assert!(source_index.is_none());
                assert!(decoded_len.is_none());
                assert!(recommended_min.is_none());
                assert!(entry_type.is_none());
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn kind_round_trips_for_every_variant() {
        // Ensures `kind()` returns the right discriminant for every
        // variant it knows about. New variants must be added here.
        let cases = [
            (
                PaladinError::validation("x", "y"),
                ErrorKind::ValidationError,
            ),
            (
                PaladinError::InvalidPassphrase {
                    reason: "zero_length",
                },
                ErrorKind::InvalidPassphrase,
            ),
            (PaladinError::VaultMissing, ErrorKind::VaultMissing),
            (PaladinError::VaultExists, ErrorKind::VaultExists),
            (PaladinError::DecryptFailed, ErrorKind::DecryptFailed),
            (PaladinError::InvalidHeader, ErrorKind::InvalidHeader),
            (
                PaladinError::UnsupportedFormatVersion,
                ErrorKind::UnsupportedFormatVersion,
            ),
            (
                PaladinError::UnsupportedPlaintextVault,
                ErrorKind::UnsupportedPlaintextVault,
            ),
            (
                PaladinError::UnsupportedEncryptedAegis,
                ErrorKind::UnsupportedEncryptedAegis,
            ),
            (
                PaladinError::NoEntriesToImport,
                ErrorKind::NoEntriesToImport,
            ),
            (PaladinError::CounterOverflow, ErrorKind::CounterOverflow),
            (
                PaladinError::SaveDurabilityUnconfirmed,
                ErrorKind::SaveDurabilityUnconfirmed,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.kind(), expected, "kind mismatch for {err}");
        }
    }
}
