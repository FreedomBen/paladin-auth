// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `PaladinAuthError` carries the §5 `error_kind` values verbatim so the
// CLI's `--json` output can serialize them without renaming or remapping.
// Only the *core-returnable* kinds appear here; the presentation-only
// kinds (`clipboard_write_failed`, `no_match`, `multiple_matches`,
// `duplicate_account`) live in front-end crates.

use std::fmt;
use std::path::PathBuf;

use thiserror::Error;

use crate::domain::AccountSummary;

/// Convenience [`std::result::Result`] alias whose error type is [`PaladinAuthError`].
pub type Result<T> = std::result::Result<T, PaladinAuthError>;

/// Stable §5 `error_kind` discriminator. Each variant maps 1:1 to a
/// JSON `error_kind` string. See docs/DESIGN.md §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "error-serde", serde(rename_all = "snake_case"))]
pub enum ErrorKind {
    /// `validation_error` — input failed §4.1 / §4.6 validation.
    ValidationError,
    /// `invalid_passphrase` — passphrase is empty or otherwise rejected pre-KDF.
    InvalidPassphrase,
    /// `invalid_state` — operation not allowed in the current vault state (§4.7).
    InvalidState,
    /// `vault_missing` — primary vault file does not exist on `open` (§4.3).
    VaultMissing,
    /// `vault_exists` — primary vault file already present on `create` (§4.3).
    VaultExists,
    /// `unsafe_permissions` — file or parent directory mode does not match the §4.3 contract.
    UnsafePermissions,
    /// `wrong_vault_lock` — supplied [`VaultLock`](crate::VaultLock) does not match the on-disk mode.
    WrongVaultLock,
    /// `decrypt_failed` — AEAD authentication failed (§4.4).
    DecryptFailed,
    /// `invalid_header` — vault header magic, mode, KDF id, or AEAD id is unrecognized (§4.4).
    InvalidHeader,
    /// `invalid_payload` — bincode payload failed shape / size validation (§4.4).
    InvalidPayload,
    /// `unsupported_format_version` — header `format_ver` newer than this build supports (§4.4).
    UnsupportedFormatVersion,
    /// `kdf_params_out_of_bounds` — Argon2 `(m_kib, t, p)` outside §4.4 ranges.
    KdfParamsOutOfBounds,
    /// `unsupported_import_format` — auto-detect failed or forced format is unknown (§4.6).
    UnsupportedImportFormat,
    /// `unsupported_plaintext_vault` — Paladin Auth import bundle is plaintext (§4.6 v0.1).
    UnsupportedPlaintextVault,
    /// `unsupported_encrypted_aegis` — Aegis backup is encrypted (§4.6 v0.1).
    UnsupportedEncryptedAegis,
    /// `unsupported_aegis_entry_type` — Aegis entry is neither `totp` nor `hotp` (§4.6).
    UnsupportedAegisEntryType,
    /// `no_entries_to_import` — import resolved to zero accounts (§4.6).
    NoEntriesToImport,
    /// `counter_overflow` — HOTP advance from `u64::MAX` (§4.7).
    CounterOverflow,
    /// `time_range` — supplied or system timestamp is pre-epoch / overflow / out-of-range (§4.7).
    TimeRange,
    /// `save_not_committed` — atomic save failed before the primary rename (§4.3).
    SaveNotCommitted,
    /// `save_durability_unconfirmed` — primary rename succeeded but parent `fsync` failed (§4.3).
    SaveDurabilityUnconfirmed,
    /// `io_error` — underlying [`std::io::Error`] surfaced with a stable §5 operation tag.
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

/// Vault-mode discriminator surfaced in `wrong_vault_lock` errors. See docs/DESIGN.md §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "error-serde", serde(rename_all = "lowercase"))]
pub enum VaultMode {
    /// Plaintext vault file (no header crypto, `0600` permissions only).
    Plaintext,
    /// Encrypted vault file (Argon2id + XChaCha20-Poly1305, §4.4).
    Encrypted,
}

impl VaultMode {
    /// Returns the §5 wire string for this mode (`"plaintext"` or `"encrypted"`).
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
/// layer. See docs/DESIGN.md §5.
#[derive(Debug, Error)]
pub enum PaladinAuthError {
    /// Input failed §4.1 / §4.6 validation. See docs/DESIGN.md §5 `validation_error`.
    #[error("validation error: {field}: {reason}")]
    ValidationError {
        /// Stable §5 field name (e.g. `"digits"`, `"secret"`, `"label"`).
        field: &'static str,
        /// Stable §5 reason code (e.g. `"out_of_range"`, `"too_short"`).
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

    /// Passphrase rejected pre-KDF. See docs/DESIGN.md §5 `invalid_passphrase`.
    #[error("invalid passphrase: {reason}")]
    InvalidPassphrase {
        /// Stable §5 reason code (currently `"zero_length"`).
        reason: &'static str,
    },

    /// Operation not allowed in the current vault state. See docs/DESIGN.md §4.7 / §5 `invalid_state`.
    #[error("invalid state: {operation}: {state}")]
    InvalidState {
        /// Stable §4.7 operation name (e.g. `"set_passphrase"`, `"hotp_advance"`).
        operation: &'static str,
        /// Stable §4.7 state code (e.g. `"already_encrypted"`, `"account_not_found"`).
        state: &'static str,
    },

    /// Primary vault file does not exist on `open`. See docs/DESIGN.md §4.3 / §5 `vault_missing`.
    #[error("vault file is missing")]
    VaultMissing,

    /// Primary vault file already present on `create`. See docs/DESIGN.md §4.3 / §5 `vault_exists`.
    #[error("vault file already exists")]
    VaultExists,

    /// File or directory mode does not match the §4.3 contract. See docs/DESIGN.md §5 `unsafe_permissions`.
    #[error(
        "unsafe permissions on {path}: {subject} mode {actual_mode}, expected {expected_mode}"
    )]
    UnsafePermissions {
        /// Filesystem path of the offending entry.
        path: PathBuf,
        /// One of `vault_dir`, `vault_file`, `backup_file`.
        subject: PermissionSubject,
        /// Four-digit octal mode string ("0644").
        actual_mode: String,
        /// Four-digit octal mode string ("0700" for dirs, "0600" for files).
        expected_mode: String,
    },

    /// Supplied [`VaultLock`](crate::VaultLock) did not match the on-disk vault mode.
    /// See docs/DESIGN.md §4.3 / §5 `wrong_vault_lock`.
    #[error("wrong vault lock: expected {expected}, supplied {actual}")]
    WrongVaultLock {
        /// Mode actually present on disk.
        expected: VaultMode,
        /// Mode supplied by the caller's [`VaultLock`](crate::VaultLock).
        actual: VaultMode,
    },

    /// AEAD authentication failed. See docs/DESIGN.md §4.4 / §5 `decrypt_failed`.
    #[error("decryption failed")]
    DecryptFailed,

    /// Vault header magic / mode / KDF / AEAD id was unrecognized. See docs/DESIGN.md §4.4 / §5 `invalid_header`.
    #[error("invalid vault header")]
    InvalidHeader,

    /// Bincode payload failed shape or size validation. See docs/DESIGN.md §4.4 / §5 `invalid_payload`.
    #[error("invalid vault payload: {reason}")]
    InvalidPayload {
        /// Stable §5 reason code (`"too_large"`, `"trailing_bytes"`, `"decode_failed"`, `"ciphertext_too_short"`).
        reason: &'static str,
    },

    /// Header `format_ver` is newer than this build supports. See docs/DESIGN.md §4.4 / §5 `unsupported_format_version`.
    #[error("unsupported vault format version: {format_ver}")]
    UnsupportedFormatVersion {
        /// On-disk header format-version byte that was rejected.
        format_ver: u8,
    },

    /// Argon2 `(m_kib, t, p)` outside the §4.4 accepted range. See docs/DESIGN.md §5 `kdf_params_out_of_bounds`.
    #[error("Argon2 KDF parameters out of bounds: m_kib={m_kib} t={t} p={p}")]
    KdfParamsOutOfBounds {
        /// Memory cost in KiB (out-of-range value as supplied).
        m_kib: u32,
        /// Time cost / number of passes (out-of-range value as supplied).
        t: u32,
        /// Parallelism / lanes (out-of-range value as supplied).
        p: u32,
    },

    /// Auto-detect failed or forced format is unknown. See docs/DESIGN.md §4.6 / §5 `unsupported_import_format`.
    #[error("unsupported import format: {format}")]
    UnsupportedImportFormat {
        /// Format token (`"unknown"` for auto-detect failure, or the requested format string).
        format: String,
    },

    /// Paladin Auth import bundle is plaintext, which v0.1 imports do not accept.
    /// See docs/DESIGN.md §4.6 / §5 `unsupported_plaintext_vault`.
    #[error("Paladin Auth import bundle is plaintext; v0.1 imports require encrypted bundles")]
    UnsupportedPlaintextVault,

    /// Aegis backup is encrypted, which v0.1 imports do not accept.
    /// See docs/DESIGN.md §4.6 / §5 `unsupported_encrypted_aegis`.
    #[error("Aegis encrypted backups are not supported in v0.1")]
    UnsupportedEncryptedAegis,

    /// Aegis entry was neither `totp` nor `hotp`. See docs/DESIGN.md §4.6 / §5 `unsupported_aegis_entry_type`.
    #[error("Aegis entry type {entry_type:?} is not supported (only totp/hotp)")]
    UnsupportedAegisEntryType {
        /// 0-based index of the offending entry in the Aegis batch.
        source_index: usize,
        /// Verbatim entry type token from the Aegis JSON.
        entry_type: String,
    },

    /// Import resolved to zero accounts. See docs/DESIGN.md §4.6 / §5 `no_entries_to_import`.
    #[error("no entries to import")]
    NoEntriesToImport,

    /// HOTP advance from `u64::MAX`. See docs/DESIGN.md §4.7 / §5 `counter_overflow`.
    #[error("HOTP counter overflow")]
    CounterOverflow {
        /// Non-secret §5 `account` summary for the entry whose
        /// counter is at `u64::MAX`. Carried so callers can render
        /// the offending account without re-fetching by ID.
        account: AccountSummary,
    },

    /// Supplied or system timestamp out of range. See docs/DESIGN.md §4.7 / §5 `time_range`.
    #[error("time out of range: {operation}: {kind}")]
    TimeRange {
        /// Stable §4.7 operation name (`"totp_code"`, `"hotp_advance"`, `"rename"`).
        operation: &'static str,
        /// Discriminator distinguishing pre-epoch / overflow / out-of-range.
        kind: TimeRangeKind,
    },

    /// Atomic save failed before the primary rename. See docs/DESIGN.md §4.3 / §5 `save_not_committed`.
    #[error("save not committed (committed={committed})")]
    SaveNotCommitted {
        /// `true` if the staging file reached `fsync` before the rename failed; `false` otherwise.
        committed: bool,
        /// Path to the rotated `.bak` if backup rotation had already run, otherwise `None`.
        backup_path: Option<PathBuf>,
    },

    /// Primary rename succeeded but the parent-directory `fsync` failed.
    /// See docs/DESIGN.md §4.3 / §5 `save_durability_unconfirmed`.
    #[error("save durability unconfirmed")]
    SaveDurabilityUnconfirmed,

    /// Underlying [`std::io::Error`] surfaced with a stable §5 operation tag.
    /// See docs/DESIGN.md §5 `io_error`.
    #[error("I/O error during {operation}: {source}")]
    IoError {
        /// Stable, core-owned operation string from §5.
        operation: &'static str,
        /// Underlying I/O failure that triggered the error.
        #[source]
        source: std::io::Error,
    },

    /// `destroy_vault` (§4.3) step failed *after* the primary `vault.bin`
    /// was already unlinked, so the partial-completion state must travel
    /// with the error. Shares the §5 `io_error` `error_kind` with
    /// [`PaladinAuthError::IoError`] (so `kind()` is identical) but carries
    /// the extra `primary_deleted` / `backup_deleted` envelope fields the
    /// §5 `--json` output and the GUI inline-error renderer need to show
    /// an accurate "primary wiped, backup remained on disk" message.
    /// Only the `unlink_backup_file` and `fsync_vault_dir` operations use
    /// this variant; pre-primary failures (`vault_file_is_symlink`,
    /// `backup_file_is_symlink`, `unlink_vault_file`) stay plain
    /// [`PaladinAuthError::IoError`]. See docs/DESIGN.md §4.3.
    #[error("I/O error during {operation}: {source}")]
    DestroyIoError {
        /// Stable, core-owned operation string from §5 (one of
        /// `"unlink_backup_file"` / `"fsync_vault_dir"`).
        operation: &'static str,
        /// Underlying I/O failure that triggered the error.
        #[source]
        source: std::io::Error,
        /// `true` once the primary `vault.bin` has been unlinked — always
        /// `true` for this variant since it only fires post-primary.
        primary_deleted: bool,
        /// `true` if the sibling `vault.bin.bak` was unlinked before the
        /// failing step (only possible for `fsync_vault_dir`).
        backup_deleted: bool,
    },
}

impl PaladinAuthError {
    /// Returns the stable §5 [`ErrorKind`] discriminator for this error.
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
            Self::UnsupportedFormatVersion { .. } => ErrorKind::UnsupportedFormatVersion,
            Self::KdfParamsOutOfBounds { .. } => ErrorKind::KdfParamsOutOfBounds,
            Self::UnsupportedImportFormat { .. } => ErrorKind::UnsupportedImportFormat,
            Self::UnsupportedPlaintextVault => ErrorKind::UnsupportedPlaintextVault,
            Self::UnsupportedEncryptedAegis => ErrorKind::UnsupportedEncryptedAegis,
            Self::UnsupportedAegisEntryType { .. } => ErrorKind::UnsupportedAegisEntryType,
            Self::NoEntriesToImport => ErrorKind::NoEntriesToImport,
            Self::CounterOverflow { .. } => ErrorKind::CounterOverflow,
            Self::TimeRange { .. } => ErrorKind::TimeRange,
            Self::SaveNotCommitted { .. } => ErrorKind::SaveNotCommitted,
            Self::SaveDurabilityUnconfirmed => ErrorKind::SaveDurabilityUnconfirmed,
            // §4.3: a destroy partial-failure is still an `io_error` on
            // the wire — the extra envelope fields ride along, so it
            // shares `IoError`'s discriminant.
            Self::IoError { .. } | Self::DestroyIoError { .. } => ErrorKind::IoError,
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

    /// Attach a zero-based `source_index` to a [`PaladinAuthError::ValidationError`]
    /// raised by a batch importer (otpauth list, Aegis entries, decoded
    /// QR list). Non-validation variants pass through unchanged.
    #[must_use]
    pub(crate) fn tag_source_index(mut self, idx: usize) -> Self {
        if let Self::ValidationError { source_index, .. } = &mut self {
            *source_index = Some(idx);
        }
        self
    }
}

/// Hand-rolled serializer for the §5 error envelope. Behind the
/// `error-serde` feature only; production builds never link this.
///
/// Wire shape: `{ "error_kind": "<snake_case>", ...variant_fields }`.
/// Optional fields are omitted when `None`; the inner [`std::io::Error`]
/// of [`PaladinAuthError::IoError`] is *not* serialized — §5 carries
/// `operation` (and an optional `path` not yet modeled here) but not
/// the platform-specific message.
#[cfg(feature = "error-serde")]
impl serde::Serialize for PaladinAuthError {
    #[allow(clippy::too_many_lines)] // mechanical: one match arm per variant
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("error_kind", self.kind().as_str())?;
        match self {
            Self::ValidationError {
                field,
                reason,
                source_index,
                decoded_len,
                recommended_min,
                entry_type,
            } => {
                map.serialize_entry("field", field)?;
                map.serialize_entry("reason", reason)?;
                if let Some(v) = source_index {
                    map.serialize_entry("source_index", v)?;
                }
                if let Some(v) = decoded_len {
                    map.serialize_entry("decoded_len", v)?;
                }
                if let Some(v) = recommended_min {
                    map.serialize_entry("recommended_min", v)?;
                }
                if let Some(v) = entry_type {
                    map.serialize_entry("entry_type", v)?;
                }
            }
            Self::InvalidPassphrase { reason } | Self::InvalidPayload { reason } => {
                map.serialize_entry("reason", reason)?;
            }
            Self::InvalidState { operation, state } => {
                map.serialize_entry("operation", operation)?;
                map.serialize_entry("state", state)?;
            }
            Self::VaultMissing
            | Self::VaultExists
            | Self::DecryptFailed
            | Self::InvalidHeader
            | Self::UnsupportedPlaintextVault
            | Self::UnsupportedEncryptedAegis
            | Self::NoEntriesToImport
            | Self::SaveDurabilityUnconfirmed => {}
            Self::UnsafePermissions {
                path,
                subject,
                actual_mode,
                expected_mode,
            } => {
                map.serialize_entry("path", path)?;
                map.serialize_entry("subject", subject)?;
                map.serialize_entry("actual_mode", actual_mode)?;
                map.serialize_entry("expected_mode", expected_mode)?;
            }
            Self::WrongVaultLock { expected, actual } => {
                map.serialize_entry("expected", expected)?;
                map.serialize_entry("actual", actual)?;
            }
            Self::UnsupportedFormatVersion { format_ver } => {
                map.serialize_entry("format_ver", format_ver)?;
            }
            Self::KdfParamsOutOfBounds { m_kib, t, p } => {
                map.serialize_entry("m_kib", m_kib)?;
                map.serialize_entry("t", t)?;
                map.serialize_entry("p", p)?;
            }
            Self::UnsupportedImportFormat { format } => {
                map.serialize_entry("format", format)?;
            }
            Self::UnsupportedAegisEntryType {
                source_index,
                entry_type,
            } => {
                map.serialize_entry("source_index", source_index)?;
                map.serialize_entry("entry_type", entry_type)?;
            }
            Self::CounterOverflow { account } => {
                map.serialize_entry("account", account)?;
            }
            Self::TimeRange { operation, kind } => {
                map.serialize_entry("operation", operation)?;
                map.serialize_entry("kind", kind)?;
            }
            Self::SaveNotCommitted {
                committed,
                backup_path,
            } => {
                map.serialize_entry("committed", committed)?;
                if let Some(path) = backup_path {
                    map.serialize_entry("backup_path", path)?;
                }
            }
            Self::IoError { operation, .. } => {
                map.serialize_entry("operation", operation)?;
            }
            Self::DestroyIoError {
                operation,
                primary_deleted,
                backup_deleted,
                ..
            } => {
                map.serialize_entry("operation", operation)?;
                map.serialize_entry("primary_deleted", primary_deleted)?;
                map.serialize_entry("backup_deleted", backup_deleted)?;
            }
        }
        map.end()
    }
}

/// Discriminator naming which path a §5 `unsafe_permissions` error refers to. See docs/DESIGN.md §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "error-serde", serde(rename_all = "snake_case"))]
pub enum PermissionSubject {
    /// Parent vault directory (expected mode `0700`).
    VaultDir,
    /// Primary vault file (expected mode `0600`).
    VaultFile,
    /// One-generation `.bak` backup file (expected mode `0600`).
    BackupFile,
}

impl PermissionSubject {
    /// Returns the §5 wire string for this subject (`"vault_dir"`, `"vault_file"`, `"backup_file"`).
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

/// Discriminator for `time_range` errors. See docs/DESIGN.md §4.7 / §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "error-serde", serde(rename_all = "snake_case"))]
pub enum TimeRangeKind {
    /// Timestamp is before the Unix epoch.
    PreEpoch,
    /// Timestamp arithmetic overflowed the supported range.
    Overflow,
    /// Timestamp is outside the operation-specific accepted window.
    OutOfRange,
}

impl TimeRangeKind {
    /// Returns the §5 wire string for this kind (`"pre_epoch"`, `"overflow"`, `"out_of_range"`).
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

    use crate::domain::{AccountId, AccountKindSummary, Algorithm};

    fn fixture_account_summary() -> AccountSummary {
        AccountSummary {
            id: AccountId::new(),
            issuer: Some("issuer".to_string()),
            label: "label".to_string(),
            kind: AccountKindSummary::Hotp,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: None,
            counter: Some(u64::MAX),
            icon_hint: None,
            created_at: 0,
            updated_at: 0,
        }
    }

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
        let err = PaladinAuthError::validation("digits", "out_of_range");
        assert_eq!(err.kind(), ErrorKind::ValidationError);
        match err {
            PaladinAuthError::ValidationError {
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
                PaladinAuthError::validation("x", "y"),
                ErrorKind::ValidationError,
            ),
            (
                PaladinAuthError::InvalidPassphrase {
                    reason: "zero_length",
                },
                ErrorKind::InvalidPassphrase,
            ),
            (PaladinAuthError::VaultMissing, ErrorKind::VaultMissing),
            (PaladinAuthError::VaultExists, ErrorKind::VaultExists),
            (PaladinAuthError::DecryptFailed, ErrorKind::DecryptFailed),
            (PaladinAuthError::InvalidHeader, ErrorKind::InvalidHeader),
            (
                PaladinAuthError::UnsupportedFormatVersion { format_ver: 99 },
                ErrorKind::UnsupportedFormatVersion,
            ),
            (
                PaladinAuthError::UnsupportedPlaintextVault,
                ErrorKind::UnsupportedPlaintextVault,
            ),
            (
                PaladinAuthError::UnsupportedEncryptedAegis,
                ErrorKind::UnsupportedEncryptedAegis,
            ),
            (
                PaladinAuthError::NoEntriesToImport,
                ErrorKind::NoEntriesToImport,
            ),
            (
                PaladinAuthError::CounterOverflow {
                    account: fixture_account_summary(),
                },
                ErrorKind::CounterOverflow,
            ),
            (
                PaladinAuthError::SaveDurabilityUnconfirmed,
                ErrorKind::SaveDurabilityUnconfirmed,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.kind(), expected, "kind mismatch for {err}");
        }
    }

    #[test]
    fn destroy_io_error_shares_io_error_kind() {
        // §4.3: the destroy partial-failure variant must serialize as
        // `io_error` on the wire — same `ErrorKind` as `IoError` — so
        // front ends key off `operation` plus the envelope bools.
        let err = PaladinAuthError::DestroyIoError {
            operation: "unlink_backup_file",
            source: std::io::Error::other("backup is a directory"),
            primary_deleted: true,
            backup_deleted: false,
        };
        assert_eq!(err.kind(), ErrorKind::IoError);
        // Display matches the plain IoError wording so callers that print
        // the error see no destroy-specific phrasing.
        assert!(err
            .to_string()
            .starts_with("I/O error during unlink_backup_file: "));
    }
}
