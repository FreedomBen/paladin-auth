// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `ExportDialog` and §"Tests > Pure-logic unit tests >
//! `tests/export_dialog_logic.rs`", the dialog hosts a
//! [`gtk::FileDialog`] for the destination path, a format selector
//! ([`ExportFormatChoice::PlaintextOtpauth`] or
//! [`ExportFormatChoice::EncryptedPaladin`]), an overwrite-confirm
//! gate that arms only when the chosen destination already exists, a
//! plaintext-export warning gate that arms only on the plaintext
//! path, and an encrypted twice-confirm passphrase row that appears
//! only on the encrypted path. The widget layer drives this module's
//! helpers to:
//!
//! * Decide which gates the current format requires
//!   ([`ExportFormatChoice::requires_plaintext_warning`] /
//!   [`ExportFormatChoice::requires_passphrase`]).
//! * Reset the overwrite-acknowledgement gate
//!   ([`overwrite_gate_needs_reset`]), the plaintext-warning gate
//!   ([`plaintext_warning_needs_reset`]), and the passphrase row
//!   ([`passphrase_needs_reset`]) when the destination path or
//!   format selector changes — a stale acknowledgement / passphrase
//!   must never carry across to a different file or mode.
//! * Render the plaintext-export warning body verbatim through
//!   [`paladin_core::format_plaintext_export_warning`]
//!   ([`plaintext_warning_body`]).
//! * Build a validated [`paladin_core::EncryptionOptions`] from the
//!   twice-confirm passphrase pair ([`prepare_encrypted_export`]).
//!   Mismatches reject as
//!   [`SubmitRejection::ConfirmationMismatch`]; both-empty pairs
//!   reject as [`SubmitRejection::ZeroLength`]. Both rejections
//!   surface as the §5 `invalid_passphrase` error kind with the
//!   matching `reason` wire code.
//! * Classify the writer outcome of
//!   [`paladin_core::write_secret_file_atomic`] wrapping either
//!   [`paladin_core::export::otpauth_list`] or
//!   [`paladin_core::export::encrypted`] ([`classify_export_result`])
//!   into one of three outcomes:
//!     - [`ExportOutcome::Success`] on `Ok(())`.
//!     - [`ExportOutcome::DurabilityWarning`] for
//!       `save_durability_unconfirmed` — the export file is on disk
//!       but the parent-directory `fsync` failed; the dialog
//!       surfaces the warning so the user can decide whether to
//!       retry.
//!     - [`ExportOutcome::Inline`] for every other typed error
//!       (`io_error`, `save_not_committed`, …). Export does not
//!       mutate the vault, so no rollback path runs.
//!
//! The module owns no widgets. The encrypted-passphrase rows live in
//! [`crate::secret_fields::SecretEntry`] so the typed bytes zeroize
//! on drop / clear; the [`paladin_core::EncryptionOptions`] returned
//! by [`prepare_encrypted_export`] wraps the passphrase in a
//! `secrecy::SecretString` that zeroizes on drop. Inline-error /
//! inline-warning bodies render through [`PaladinError::Display`] so
//! wording stays in lock-step with the CLI / TUI verbatim.

use std::path::Path;

use paladin_core::{format_plaintext_export_warning, EncryptionOptions, ErrorKind, PaladinError};
use secrecy::SecretString;

/// Format-selector choice surfaced by the `ExportDialog`'s segmented
/// control.
///
/// The two formats correspond to
/// [`paladin_core::export::otpauth_list`] (plaintext JSON list of
/// `otpauth://` URIs) and [`paladin_core::export::encrypted`]
/// (encrypted Paladin bundle). They drive distinct dialog gates: the
/// plaintext path arms the plaintext-warning checkbox; the encrypted
/// path arms the twice-confirm passphrase row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormatChoice {
    /// Plaintext otpauth JSON list. Requires the plaintext-export
    /// warning to be acknowledged before the writer runs.
    PlaintextOtpauth,
    /// Encrypted Paladin bundle. Requires the twice-confirm
    /// passphrase row to be filled with a matching, non-empty pair.
    EncryptedPaladin,
}

impl ExportFormatChoice {
    /// `true` for the plaintext path that needs the warning gate.
    #[must_use]
    pub fn requires_plaintext_warning(self) -> bool {
        matches!(self, Self::PlaintextOtpauth)
    }

    /// `true` for the encrypted path that needs the twice-confirm
    /// passphrase row.
    #[must_use]
    pub fn requires_passphrase(self) -> bool {
        matches!(self, Self::EncryptedPaladin)
    }
}

/// Body text for the plaintext-export warning rendered above the
/// confirmation checkbox. Wording matches
/// [`paladin_core::format_plaintext_export_warning`] verbatim so it
/// stays in sync with the CLI / TUI.
#[must_use]
pub fn plaintext_warning_body() -> String {
    format_plaintext_export_warning()
}

/// Return `true` iff a change of destination path or format selector
/// requires clearing the overwrite-acknowledgement gate.
///
/// The dialog re-arms the gate (and re-checks
/// `Path::try_exists`) on every change so a stale acknowledgement
/// cannot apply to a different file or to a fresh attempt. The
/// helper takes raw [`Path`] equality and format equality — it does
/// not attempt to canonicalize paths, so `./vault.json` and
/// `vault.json` reset the gate even when they may resolve
/// identically. Canonicalization belongs to the file picker.
#[must_use]
pub fn overwrite_gate_needs_reset(
    prev_dest: &Path,
    prev_format: ExportFormatChoice,
    new_dest: &Path,
    new_format: ExportFormatChoice,
) -> bool {
    destination_or_format_changed(prev_dest, prev_format, new_dest, new_format)
}

/// Return `true` iff a change of destination path or format selector
/// requires clearing the plaintext-warning acknowledgement gate.
///
/// Same shape and rationale as [`overwrite_gate_needs_reset`]: a
/// stale tick must never apply to a different file or to a fresh
/// attempt. The widget layer also hides the gate entirely on the
/// encrypted path ([`ExportFormatChoice::requires_plaintext_warning`]
/// returns `false`); resetting it on every relevant change keeps the
/// hidden state from leaking into a later plaintext attempt.
#[must_use]
pub fn plaintext_warning_needs_reset(
    prev_dest: &Path,
    prev_format: ExportFormatChoice,
    new_dest: &Path,
    new_format: ExportFormatChoice,
) -> bool {
    destination_or_format_changed(prev_dest, prev_format, new_dest, new_format)
}

/// Return `true` iff a change of destination path or format selector
/// requires clearing the encrypted-passphrase rows.
///
/// Same shape and rationale as [`overwrite_gate_needs_reset`]. The
/// widget layer holds the typed bytes in
/// [`crate::secret_fields::SecretEntry`] so a reset zeroizes the
/// underlying buffer; the dialog re-prompts before the next encrypted
/// attempt. Switching to or away from
/// [`ExportFormatChoice::EncryptedPaladin`] both reset the row: any
/// content held while the row was hidden is invalid for the new
/// mode.
#[must_use]
pub fn passphrase_needs_reset(
    prev_dest: &Path,
    prev_format: ExportFormatChoice,
    new_dest: &Path,
    new_format: ExportFormatChoice,
) -> bool {
    destination_or_format_changed(prev_dest, prev_format, new_dest, new_format)
}

fn destination_or_format_changed(
    prev_dest: &Path,
    prev_format: ExportFormatChoice,
    new_dest: &Path,
    new_format: ExportFormatChoice,
) -> bool {
    prev_dest != new_dest || prev_format != new_format
}

/// Inline rejection produced by [`prepare_encrypted_export`] before
/// any writer work runs.
///
/// Both variants surface as the §5 `invalid_passphrase` error kind
/// with distinct `reason` wire codes so the dialog can attach the
/// rejection to the correct row and so telemetry / JSON
/// instrumentation match the CLI / TUI verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitRejection {
    /// Passphrase and confirm rows differ. Mirrors
    /// [`paladin_core::PaladinError::InvalidPassphrase`] with
    /// `reason: "confirmation_mismatch"`.
    ConfirmationMismatch,
    /// Both passphrase rows empty. Mirrors
    /// [`paladin_core::PaladinError::InvalidPassphrase`] with
    /// `reason: "zero_length"` — the same reason
    /// [`paladin_core::EncryptionOptions::new`] returns for an empty
    /// passphrase.
    ZeroLength,
}

impl SubmitRejection {
    /// Stable §5 [`ErrorKind`] discriminator for this rejection.
    /// Always [`ErrorKind::InvalidPassphrase`].
    #[must_use]
    pub fn error_kind(&self) -> ErrorKind {
        ErrorKind::InvalidPassphrase
    }

    /// Stable §5 `invalid_passphrase.reason` wire code for this
    /// rejection.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::ConfirmationMismatch => "confirmation_mismatch",
            Self::ZeroLength => "zero_length",
        }
    }
}

/// Validate the encrypted-export twice-confirm passphrase pair and
/// build the [`EncryptionOptions`] for the encrypted bundle.
///
/// * Pass / confirm pair differs → [`SubmitRejection::ConfirmationMismatch`].
/// * Both rows empty → [`SubmitRejection::ZeroLength`].
/// * Otherwise: build [`EncryptionOptions::new`] with the default
///   §4.4 Argon2id cost (m=64 MiB, t=3, p=1).
///
/// `EncryptionOptions::new` itself rejects empty passphrases with
/// `invalid_passphrase { reason: "zero_length" }`; the explicit
/// pre-check here lets the dialog distinguish the empty case from a
/// mismatch without depending on the constructor's typed error
/// surface.
pub fn prepare_encrypted_export(
    passphrase: &str,
    confirm: &str,
) -> Result<EncryptionOptions, SubmitRejection> {
    if passphrase != confirm {
        return Err(SubmitRejection::ConfirmationMismatch);
    }
    if passphrase.is_empty() {
        return Err(SubmitRejection::ZeroLength);
    }
    EncryptionOptions::new(SecretString::from(passphrase.to_string()))
        .map_err(|_| SubmitRejection::ZeroLength)
}

/// Outcome of the export writer
/// ([`paladin_core::write_secret_file_atomic`] wrapping the chosen
/// payload).
///
/// See [`classify_export_result`].
#[derive(Debug)]
pub enum ExportOutcome {
    /// `Ok(())` — the export bytes were written and the
    /// parent-directory `fsync` succeeded. The dialog closes with a
    /// success toast.
    Success,
    /// `save_durability_unconfirmed` — the primary rename succeeded
    /// (the file exists on disk) but the parent-directory `fsync`
    /// failed. The dialog surfaces the warning so the user can decide
    /// whether to retry; the file itself is not removed.
    DurabilityWarning(InlineWarning),
    /// Any other typed error (`io_error`, `save_not_committed`, …).
    /// The dialog stays open with the inline error. Export does not
    /// mutate the vault, so no rollback path runs.
    Inline(InlineError),
}

/// Classify the export-writer result into an [`ExportOutcome`].
///
/// `save_durability_unconfirmed` splits out as
/// [`ExportOutcome::DurabilityWarning`] so the dialog can render
/// warning-class wording for the "file exists, fsync failed" case;
/// every other typed variant falls through to
/// [`ExportOutcome::Inline`].
#[must_use]
pub fn classify_export_result(result: Result<(), PaladinError>) -> ExportOutcome {
    match result {
        Ok(()) => ExportOutcome::Success,
        Err(err) => match err.kind() {
            ErrorKind::SaveDurabilityUnconfirmed => {
                ExportOutcome::DurabilityWarning(InlineWarning::from_error(&err))
            }
            _ => ExportOutcome::Inline(InlineError::from_error(&err)),
        },
    }
}

/// Inline-error projection for the `ExportDialog` body.
///
/// Carries the stable §5 [`ErrorKind`] for instrumentation and the
/// rendered body for display. No source-error reference is kept so
/// the model can be cloned freely into the dialog's reactive state.
#[derive(Debug, Clone)]
pub struct InlineError {
    /// Stable §5 [`ErrorKind`] discriminator copied from
    /// [`PaladinError::kind`].
    pub kind: ErrorKind,
    /// Display body. Renders through [`std::fmt::Display`] so the
    /// wording stays in sync with the CLI / TUI verbatim.
    pub rendered: String,
}

impl InlineError {
    /// Build an [`InlineError`] from a [`PaladinError`].
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}

/// Durability-warning projection for the `ExportDialog` body.
///
/// Returned by [`classify_export_result`] on
/// `save_durability_unconfirmed`: the export file is on disk, but
/// the parent-directory `fsync` failed, so the dialog surfaces the
/// warning so the user can decide whether to retry.
#[derive(Debug, Clone)]
pub struct InlineWarning {
    /// Stable §5 [`ErrorKind`] discriminator — always
    /// [`ErrorKind::SaveDurabilityUnconfirmed`] in current code.
    pub kind: ErrorKind,
    /// Display body. Renders through [`std::fmt::Display`] so the
    /// wording stays in sync with the CLI / TUI verbatim.
    pub rendered: String,
}

impl InlineWarning {
    /// Build an [`InlineWarning`] from a [`PaladinError`].
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}
