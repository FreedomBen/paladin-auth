// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
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

use std::path::{Path, PathBuf};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use paladin_core::{
    format_plaintext_export_warning, write_secret_file_atomic, EncryptionOptions, ErrorKind,
    PaladinError, Store, Vault,
};
use secrecy::SecretString;

use crate::secret_fields::SecretEntry;

/// Format-selector choice surfaced by the `ExportDialog`'s segmented
/// control.
///
/// The two formats correspond to
/// [`paladin_core::export::otpauth_list`] (plaintext, newline-separated
/// list of `otpauth://` URIs — the same shape Gnome Authenticator's
/// "Backup → Save in plain text" produces) and
/// [`paladin_core::export::encrypted`] (encrypted Paladin bundle).
/// They drive distinct dialog gates: the plaintext path arms the
/// plaintext-warning checkbox; the encrypted path arms the
/// twice-confirm passphrase row.
///
/// [`Default`] returns [`ExportFormatChoice::PlaintextOtpauth`] for
/// CLI parity: `paladin export <DEST>` with no `--format` flag writes
/// the plaintext `otpauth://` URI list, and the dialog opens on the
/// same format so the user's first interaction matches the CLI
/// documentation. Switching to the encrypted path is one click on
/// the format-selector `adw::ComboRow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportFormatChoice {
    /// Plaintext otpauth URI list (one URI per line). Requires the
    /// plaintext-export warning to be acknowledged before the writer
    /// runs.
    #[default]
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

    /// `AdwComboRow` selection index for this choice.
    ///
    /// Inverse of [`format_choice_from_index`]: the widget binds
    /// `set_selected:` to this value so the active row matches the
    /// state machine after every refresh. The order mirrors
    /// [`format_export_dialog_format_labels`]:
    /// `[PlaintextOtpauth, EncryptedPaladin]`.
    #[must_use]
    pub fn index(self) -> u32 {
        match self {
            Self::PlaintextOtpauth => 0,
            Self::EncryptedPaladin => 1,
        }
    }
}

/// `AdwComboRow` `selected` index → [`ExportFormatChoice`].
///
/// Out-of-range selections route as `None` so the dispatch arm
/// leaves the draft untouched, mirroring the
/// `format_choice_from_index` pattern in [`crate::import_dialog`].
#[must_use]
pub fn format_choice_from_index(selected: u32) -> Option<ExportFormatChoice> {
    match selected {
        0 => Some(ExportFormatChoice::PlaintextOtpauth),
        1 => Some(ExportFormatChoice::EncryptedPaladin),
        _ => None,
    }
}

/// Format-selector display labels for the `AdwComboRow` model.
///
/// The order matches [`format_choice_from_index`] /
/// [`ExportFormatChoice::index`]:
/// `[PlaintextOtpauth, EncryptedPaladin]`.
#[must_use]
pub fn format_export_dialog_format_labels() -> &'static [&'static str] {
    &["Plaintext otpauth:// URI list", "Encrypted Paladin bundle"]
}

// ---------------------------------------------------------------------------
// Dialog title / row label helpers
// ---------------------------------------------------------------------------
//
// All wording lives in pure-logic helpers so `tests/export_dialog_logic.rs`
// can pin the strings without touching the GTK runtime, and so a
// future localization pass can swap the bodies in one place.

/// Title bar text for the `ExportDialog` `adw::Dialog`.
#[must_use]
pub fn format_export_dialog_title() -> &'static str {
    "Export"
}

/// Subtitle text rendered beneath the dialog title.
#[must_use]
pub fn format_export_dialog_subtitle() -> &'static str {
    "Write the visible accounts to a file."
}

/// `adw::PreferencesGroup` title for the destination chooser row.
#[must_use]
pub fn format_export_dialog_destination_group_title() -> &'static str {
    "Destination"
}

/// `adw::ActionRow` title for the destination chooser row.
#[must_use]
pub fn format_export_dialog_destination_row_title() -> &'static str {
    "File"
}

/// `adw::ActionRow` placeholder subtitle when no destination is
/// selected yet.
#[must_use]
pub fn format_export_dialog_destination_row_placeholder() -> &'static str {
    "No file selected"
}

/// `gtk::Button` label for the "Choose file…" affordance that opens
/// the [`gtk::FileDialog`] destination picker.
#[must_use]
pub fn format_export_dialog_choose_destination_label() -> &'static str {
    "Choose file…"
}

/// `adw::PreferencesGroup` title for the options group hosting the
/// format selector (and, in subsequent sub-items, the overwrite
/// gate, plaintext-warning gate, and twice-confirm passphrase row).
#[must_use]
pub fn format_export_dialog_options_group_title() -> &'static str {
    "Options"
}

/// `adw::ComboRow` title for the format selector.
#[must_use]
pub fn format_export_dialog_format_row_title() -> &'static str {
    "Format"
}

/// `AdwSwitchRow` title for the inline overwrite-acknowledgement
/// gate. The widget reveals the row only when the destination
/// already exists per [`compose_overwrite_gate_visible`]; the
/// wording mirrors the CLI's `--force` semantics.
#[must_use]
pub fn format_export_dialog_overwrite_gate_title() -> &'static str {
    "Overwrite existing file"
}

/// `AdwSwitchRow` subtitle for the inline overwrite-acknowledgement
/// gate. Explains that the file already exists and that toggling the
/// switch on replaces it on Export.
#[must_use]
pub fn format_export_dialog_overwrite_gate_subtitle() -> &'static str {
    "The selected file already exists. Toggle on to replace it on Export."
}

/// `adw::PreferencesGroup` title for the plaintext-warning group
/// hosting the warning body + ack row.
#[must_use]
pub fn format_export_dialog_plaintext_warning_group_title() -> &'static str {
    "Plaintext warning"
}

/// `AdwSwitchRow` title for the plaintext-warning acknowledgement
/// toggle. Keeping the wording short so the row body remains the
/// primary affordance.
#[must_use]
pub fn format_export_dialog_plaintext_warning_ack_title() -> &'static str {
    "I understand the risks"
}

/// `AdwSwitchRow` subtitle for the plaintext-warning acknowledgement
/// toggle. Restates that the user must explicitly confirm before the
/// plaintext write proceeds.
#[must_use]
pub fn format_export_dialog_plaintext_warning_ack_subtitle() -> &'static str {
    "Toggle on to confirm and enable Export."
}

/// `adw::PreferencesGroup` title for the encrypted-bundle twice-
/// confirm passphrase group. Only revealed when the active format
/// requires a passphrase per [`compose_passphrase_rows_visible`].
#[must_use]
pub fn format_export_dialog_passphrase_group_title() -> &'static str {
    "Bundle passphrase"
}

/// Pinned `AdwPasswordEntryRow` title for the bundle-passphrase entry.
#[must_use]
pub fn format_export_dialog_passphrase_row_title() -> &'static str {
    "Passphrase"
}

/// Pinned `AdwPasswordEntryRow` title for the confirm-passphrase
/// entry. The widget mounts it directly below the passphrase row;
/// the submit button stays dim until both rows are non-empty and
/// match.
#[must_use]
pub fn format_export_dialog_confirm_passphrase_row_title() -> &'static str {
    "Confirm passphrase"
}

/// Footer Cancel button label.
#[must_use]
pub fn format_export_dialog_cancel_label() -> &'static str {
    "Cancel"
}

/// Footer Export button label (the `suggested-action` affordance).
#[must_use]
pub fn format_export_dialog_export_label() -> &'static str {
    "Export"
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Build an [`InlineError`] from a pre-flight [`SubmitRejection`].
    ///
    /// Both [`SubmitRejection::ConfirmationMismatch`] and
    /// [`SubmitRejection::ZeroLength`] are §5 `invalid_passphrase`
    /// rejections — the [`ErrorKind`] is always
    /// [`ErrorKind::InvalidPassphrase`], and the rendered body comes
    /// from the matching [`PaladinError::InvalidPassphrase`] variant so
    /// wording stays in lock-step with the CLI / TUI verbatim. The
    /// `reason` wire code is preserved through
    /// [`SubmitRejection::reason`].
    #[must_use]
    pub fn from_rejection(rejection: SubmitRejection) -> Self {
        Self::from_error(&PaladinError::InvalidPassphrase {
            reason: rejection.reason(),
        })
    }
}

/// Durability-warning projection for the `ExportDialog` body.
///
/// Returned by [`classify_export_result`] on
/// `save_durability_unconfirmed`: the export file is on disk, but
/// the parent-directory `fsync` failed, so the dialog surfaces the
/// warning so the user can decide whether to retry.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Validated payload emitted by [`ExportDialogOutput::Submit`].
///
/// `AppModel` hands this to its `gio::spawn_blocking` worker that runs
/// either [`paladin_core::export::otpauth_list`] (plaintext) or
/// [`paladin_core::export::encrypted`] (encrypted) and writes the
/// resulting bytes via [`paladin_core::write_secret_file_atomic`].
/// Export does not mutate the vault, so this payload carries no
/// `(Vault, Store)` references — those move from `AppModel::vault`
/// into the matching [`ExportWorkerInput`].
///
/// Not `Clone` because [`EncryptionOptions`] wraps a
/// [`secrecy::SecretString`] that is intentionally non-`Clone`: the
/// bundle passphrase moves once into the worker and zeroizes on drop.
#[derive(Debug)]
pub struct ExportSubmitPayload {
    /// Destination path the writer commits to. Stored verbatim from
    /// the picker; canonicalization belongs to the picker.
    pub destination: PathBuf,
    /// Format choice. Drives the worker's branch between
    /// [`paladin_core::export::otpauth_list`] and
    /// [`paladin_core::export::encrypted`].
    pub format: ExportFormatChoice,
    /// `Some(options)` on the encrypted path; `None` on the
    /// plaintext path. The worker treats this field as authoritative
    /// — it does not re-check the format-passphrase invariant.
    pub encryption_options: Option<EncryptionOptions>,
}

/// Routing decision after a Submit click against the current
/// [`ExportDialogState`].
///
/// The dispatch arm in [`apply_msg`] runs [`compose_submit_outcome`]
/// to decide:
/// * [`Self::Proceed`] — every gate is acknowledged and the
///   twice-confirm passphrase pair (encrypted path) is valid. The
///   widget forwards the payload through
///   [`ExportDialogOutput::Submit`].
/// * [`Self::Rejected`] — the encrypted twice-confirm pair is empty
///   or mismatched. The dialog stages the inline `invalid_passphrase`
///   body and stays open.
/// * [`Self::NotReady`] — a non-passphrase gate is unmet (no
///   destination, overwrite-gate visible-and-unacked, plaintext-
///   warning unacked). The submit button should have been dimmed in
///   the first place; this variant is the defense-in-depth no-op for
///   stray clicks.
#[derive(Debug)]
pub enum SubmitOutcome {
    /// Submission is ready. The carried [`ExportSubmitPayload`] is
    /// the value the widget forwards through
    /// [`ExportDialogOutput::Submit`].
    Proceed(ExportSubmitPayload),
    /// The encrypted twice-confirm pre-flight rejected the typed
    /// pair. The widget keeps the inline error visible and does not
    /// dispatch the worker.
    Rejected(InlineError),
    /// One or more non-passphrase gates were unmet. The widget does
    /// not stage an inline error (the submit button was dimmed; the
    /// click should not have reached the dispatch path).
    NotReady,
}

/// Decide what to do with a Submit click against the current state.
///
/// Reads the gate predicates ([`compose_overwrite_gate_visible`] /
/// [`compose_plaintext_warning_visible`] /
/// [`compose_passphrase_rows_visible`]) and the matching acks, runs
/// the encrypted twice-confirm pre-flight via
/// [`prepare_encrypted_export`] for the encrypted path, and bundles a
/// validated [`ExportSubmitPayload`] on success. The destination path
/// is cloned (`PathBuf::clone`) so the state still carries it for the
/// post-success dialog flow; the encrypted passphrase moves into the
/// payload's [`EncryptionOptions`].
///
/// Symmetric to [`crate::import_dialog::compose_submit_outcome`] for
/// the export path: keeps the routing pure-logic so
/// `tests/export_dialog_logic.rs` can drive the dispatch without
/// mounting a GTK widget.
#[must_use]
pub fn compose_submit_outcome(state: &ExportDialogState) -> SubmitOutcome {
    let Some(destination) = state.destination_path().map(Path::to_path_buf) else {
        return SubmitOutcome::NotReady;
    };
    if compose_overwrite_gate_visible(state) && !state.is_overwrite_acknowledged() {
        return SubmitOutcome::NotReady;
    }
    if compose_plaintext_warning_visible(state) && !state.is_plaintext_warning_acknowledged() {
        return SubmitOutcome::NotReady;
    }
    let format = state.format();
    let encryption_options = if format.requires_passphrase() {
        match prepare_encrypted_export(state.passphrase_text(), state.confirm_passphrase_text()) {
            Ok(opts) => Some(opts),
            Err(rejection) => {
                return SubmitOutcome::Rejected(InlineError::from_rejection(rejection));
            }
        }
    } else {
        None
    };
    SubmitOutcome::Proceed(ExportSubmitPayload {
        destination,
        format,
        encryption_options,
    })
}

/// Input bundle moved into the `gio::spawn_blocking` worker.
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `ExportDialog`: the live `(Vault, Store)` pair is moved into the
/// worker so the export read happens off the main loop (the
/// encrypted-bundle path runs the §4.4 Argon2id KDF and a fresh AEAD
/// derivation), and returned on every branch through
/// [`ExportWorkerCompletion`] so `AppModel` can reinstall it. Export
/// does not mutate the vault — `Vault::mutate_and_save` is not on this
/// path — but the pair still round-trips so `AppModel::vault` is never
/// orphaned across the spawn boundary.
///
/// Not `Clone` / not `PartialEq`: [`Store`] holds non-`Clone`
/// filesystem state and [`EncryptionOptions::passphrase`] is a
/// [`secrecy::SecretString`] that zeroizes on drop. `AppModel::update`
/// consumes the input exactly once when it moves it into the closure.
#[derive(Debug)]
pub struct ExportWorkerInput {
    /// Live vault from the `Unlocked` `(Vault, Store)` pair.
    pub vault: Vault,
    /// Live store moved through unchanged.
    pub store: Store,
    /// Destination path the writer commits to.
    pub destination: PathBuf,
    /// Format choice — selects between
    /// [`paladin_core::export::otpauth_list`] and
    /// [`paladin_core::export::encrypted`].
    pub format: ExportFormatChoice,
    /// `Some(options)` on the encrypted path; `None` on plaintext.
    /// The worker treats this as authoritative.
    pub encryption_options: Option<EncryptionOptions>,
}

/// Bundle returned by [`run_export_worker`].
///
/// Carries the `(Vault, Store)` pair on every branch so
/// `AppModel::update` reinstalls it before applying the UI outcome.
/// Export does not mutate the vault, so the returned pair is the same
/// as the input pair byte-for-byte. The destination path is round-
/// tripped so the success-toast surface can render it without
/// reaching back into the dialog state.
#[derive(Debug)]
pub struct ExportWorkerCompletion {
    /// Routed outcome — `Success`, `DurabilityWarning`, or `Inline`.
    pub outcome: ExportOutcome,
    /// Live vault moved through unchanged.
    pub vault: Vault,
    /// Live store moved through unchanged.
    pub store: Store,
    /// Destination path the worker committed (or attempted to commit)
    /// to. Carried through so the post-success toast can render it.
    pub destination: PathBuf,
}

/// Synchronous body of the `gio::spawn_blocking` export worker.
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `ExportDialog`:
///
/// 1. Render the export bytes:
///    * [`ExportFormatChoice::PlaintextOtpauth`] →
///      [`paladin_core::export::otpauth_list`] (a newline-separated
///      list of `otpauth://` URIs, one per line, terminated by a
///      trailing newline; same shape as Gnome Authenticator's
///      "Backup → Save in plain text" file).
///    * [`ExportFormatChoice::EncryptedPaladin`] →
///      [`paladin_core::export::encrypted`] with the worker-supplied
///      [`EncryptionOptions`], which runs the §4.4 Argon2id KDF and
///      a fresh AEAD key derivation.
/// 2. Hand the bytes to
///    [`paladin_core::write_secret_file_atomic`], which writes
///    through a tmpfile + rename and enforces mode `0600` on the
///    final file (DESIGN §4.3 staged-clobber pipeline).
/// 3. Bundle the typed result into an [`ExportWorkerCompletion`] via
///    [`classify_export_result`].
///
/// Export does not mutate the vault, so `Vault::mutate_and_save` is
/// not on this path. The `(Vault, Store)` pair is moved through
/// unchanged on every branch so `AppModel::vault` is never orphaned
/// across the `gio::spawn_blocking` boundary.
#[must_use]
pub fn run_export_worker(input: ExportWorkerInput) -> ExportWorkerCompletion {
    let ExportWorkerInput {
        vault,
        store,
        destination,
        format,
        encryption_options,
    } = input;
    let bytes_result: Result<Vec<u8>, PaladinError> = match format {
        ExportFormatChoice::PlaintextOtpauth => {
            Ok(paladin_core::export::otpauth_list(&vault).into_bytes())
        }
        ExportFormatChoice::EncryptedPaladin => {
            // The widget gate (`compose_submit_outcome`) guarantees
            // `encryption_options` is `Some` on the encrypted path.
            // Matches the TUI's `execute_export` precedent: a `None`
            // here is a dispatch-site bug.
            let opts = encryption_options
                .expect("EncryptedPaladin format requires EncryptionOptions from the dispatch");
            paladin_core::export::encrypted(&vault, opts)
        }
    };
    let result = bytes_result.and_then(|bytes| write_secret_file_atomic(&destination, &bytes));
    ExportWorkerCompletion {
        outcome: classify_export_result(result),
        vault,
        store,
        destination,
    }
}

/// Construction parameters for [`ExportDialogComponent`].
///
/// The dialog opens against the live vault so the export worker that
/// lands in follow-up commits can call
/// [`paladin_core::export::otpauth_list`] /
/// [`paladin_core::export::encrypted`] against the same in-memory
/// accounts `AppModel` resolved at startup. Cloned from
/// `AppModel::state` at mount time so a mid-flight passphrase-
/// transition or lock cannot retarget the dialog.
#[derive(Debug, Clone)]
pub struct ExportDialogInit {
    /// Vault path the export source reads from; carried so the
    /// follow-up worker can resolve writes relative to a stable
    /// vault identity even if the live `AppState` retargets.
    pub vault_path: PathBuf,
}

/// Messages handled by [`ExportDialogComponent`].
///
/// The set covers the format-selector + destination-picker +
/// overwrite-gate sub-items from `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Milestone 7 checklist" > `ExportDialogComponent` plus the
/// explicit Cancel / Close dismissal paths. Subsequent sub-items
/// extend the enum with the plaintext-warning toggle, the
/// twice-confirm passphrase entries, the submit click, and the
/// worker-completion dispatch.
#[derive(Debug)]
pub enum ExportDialogMsg {
    /// User picked a destination file via the [`gtk::FileDialog`]
    /// callback. The path is stored verbatim — canonicalization
    /// belongs to the picker, and the gate-reset helpers
    /// ([`overwrite_gate_needs_reset`] /
    /// [`plaintext_warning_needs_reset`] / [`passphrase_needs_reset`])
    /// compare raw paths so a switch between two equivalent forms
    /// still rearms the gates. `exists` carries the result of the
    /// widget's `Path::try_exists` probe run synchronously after
    /// the picker returns; the state machine arms the inline
    /// overwrite gate iff `exists == true`. On `try_exists` I/O
    /// errors the widget passes `true` (assume the file exists, force
    /// the user to ack) — silent overwrites are always the worse
    /// failure mode.
    DestinationPicked {
        /// Picked destination file path. Stored verbatim.
        path: PathBuf,
        /// Result of `Path::try_exists` against `path`. Drives the
        /// inline overwrite-gate visibility.
        exists: bool,
    },
    /// User changed the active format on the [`adw::ComboRow`]
    /// selector. Carries the [`ExportFormatChoice`] decoded by
    /// [`format_choice_from_index`]; an out-of-range selection is
    /// dropped by the widget rather than dispatched.
    FormatChanged(ExportFormatChoice),
    /// User toggled the inline overwrite-acknowledgement gate on
    /// the destination `AdwSwitchRow`. The dispatch arm forwards the
    /// new boolean into [`ExportDialogState::set_overwrite_acknowledged`].
    /// When the gate is rearmed (false), the submit button dims again;
    /// when it is acknowledged (true), the submit button enables
    /// (subject to the plaintext-warning and twice-confirm passphrase
    /// gates).
    OverwriteAcknowledged(bool),
    /// User toggled the inline plaintext-warning acknowledgement on
    /// the warning-group `AdwSwitchRow`. The dispatch arm forwards
    /// the new boolean into
    /// [`ExportDialogState::set_plaintext_warning_acknowledged`].
    /// Mirror semantics to [`Self::OverwriteAcknowledged`]: rearming
    /// the gate dims the submit button until the user re-acks.
    PlaintextWarningAcknowledged(bool),
    /// Per-keystroke shadow of the encrypted-bundle passphrase entry.
    /// The widget's `AdwPasswordEntryRow.connect_changed` handler
    /// fires this so the Paladin-owned [`SecretEntry`] shadow tracks
    /// the GTK buffer verbatim; the dispatch arm routes through
    /// [`ExportDialogState::set_passphrase`], which zeroizes the
    /// prior buffer contents in place.
    PassphraseChanged(String),
    /// Per-keystroke shadow of the confirm-passphrase entry. Same
    /// dispatch shape as [`Self::PassphraseChanged`].
    ConfirmPassphraseChanged(String),
    /// User clicked the footer Export button. [`apply_msg`] runs the
    /// twice-confirm pre-flight ([`prepare_encrypted_export`]) on the
    /// encrypted path and stages an [`InlineError`] when the pair is
    /// mismatched ([`SubmitRejection::ConfirmationMismatch`] →
    /// `invalid_passphrase { reason: "confirmation_mismatch" }`) or
    /// both rows are empty ([`SubmitRejection::ZeroLength`] →
    /// `invalid_passphrase { reason: "zero_length" }`). The actual
    /// writer dispatch (an `ExportDialogOutput::Submit` payload routed
    /// through `gio::spawn_blocking` into
    /// [`paladin_core::write_secret_file_atomic`] wrapping the chosen
    /// payload) lands in the subsequent sub-item. Until then this
    /// arm emits no output for the accepted path either.
    SubmitClicked,
    /// User clicked the explicit Cancel button. The dispatch arm
    /// emits [`ExportDialogOutput::Cancel`] so `AppModel` drops the
    /// live controller and the form draft is discarded. Passphrase
    /// buffers are zeroized before the output is emitted per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Secret entry handling".
    Cancel,
    /// User dismissed the dialog via the parent close path (Escape /
    /// window close). The dispatch arm emits
    /// [`ExportDialogOutput::Close`]; the variant stays distinct
    /// from [`ExportDialogMsg::Cancel`] so a future "Discard draft?"
    /// prompt can attach to one path without affecting the other.
    /// Passphrase buffers are zeroized before the output is emitted.
    Close,
    /// `AppModel` pushes the busy latch back to the dialog after it
    /// has moved the `(Vault, Store)` pair into the
    /// `gio::spawn_blocking` worker. The dialog dims the Export
    /// button until [`Self::WorkerCompleted`] resets the latch via
    /// [`ExportDialogState::set_busy`].
    SetBusy(bool),
    /// `AppModel` pushes the typed [`ExportOutcome`] back to the
    /// dialog after the worker reports completion. [`apply_msg`]
    /// routes the variant through:
    /// * [`ExportOutcome::Success`] → clear the form, clear the busy
    ///   latch, emit [`ExportDialogOutput::Close`]. `AppModel` raises
    ///   the success [`AdwToast`] on the main overlay (see the
    ///   `compose_export_dispatch` helper in
    ///   `crate::app::state`).
    /// * [`ExportOutcome::DurabilityWarning`] → stage the inline
    ///   warning, clear the busy latch, emit no output. The dialog
    ///   stays open so the user dismisses the warning explicitly.
    /// * [`ExportOutcome::Inline`] → stage the inline error, clear
    ///   the busy latch, emit no output. The dialog stays open so
    ///   the user can retry.
    WorkerCompleted(ExportOutcome),
}

/// Messages emitted by [`ExportDialogComponent`] for `AppModel` to consume.
///
/// `AppModel` forwards these into `AppMsg::ExportDialogAction(...)`;
/// the dispatch arm drops the live `Controller<ExportDialogComponent>`
/// so the underlying `adw::Dialog` is torn down. Submit / export-
/// result outputs that propagate the typed
/// [`classify_export_result`] verdict to `AppModel` land in the same
/// follow-up commits that add the submit and worker-completion
/// transitions.
#[derive(Debug)]
pub enum ExportDialogOutput {
    /// User clicked the explicit Cancel button. `AppModel` drops the
    /// live controller so the dialog disappears and any in-flight
    /// pending form draft is discarded. Kept distinct from
    /// [`ExportDialogOutput::Close`] so future "Discard draft?"
    /// behavior can attach to one variant without affecting the
    /// other.
    Cancel,
    /// User dismissed the dialog via the parent close path (Escape /
    /// window close), or the worker reported
    /// [`ExportOutcome::Success`] and `apply_msg` closed the dialog.
    /// `AppModel` responds by dropping the live controller so the
    /// dialog disappears and any in-flight pending form draft
    /// (selected destination path, format choice, overwrite
    /// acknowledgement, plaintext-warning acknowledgement, twice-
    /// confirm passphrase entries) is discarded.
    Close,
    /// Submit button activation with a validated
    /// [`ExportSubmitPayload`]. `AppModel` hands the payload to its
    /// `gio::spawn_blocking` worker that runs
    /// [`paladin_core::export::otpauth_list`] or
    /// [`paladin_core::export::encrypted`] then
    /// [`paladin_core::write_secret_file_atomic`] (the encrypted
    /// variant runs Argon2id; keep it off the main loop).
    ///
    /// Not `Clone` because [`EncryptionOptions`] wraps a
    /// [`secrecy::SecretString`] that is intentionally non-`Clone`:
    /// the bundle passphrase moves once into the worker and zeroizes
    /// on drop.
    Submit(ExportSubmitPayload),
}

/// Pure-logic state machine for [`ExportDialogComponent`].
///
/// Owns the destination-path + format form draft plus the inline
/// overwrite-acknowledgement gate (arms when the picked destination
/// already exists on disk), the plaintext-export-warning ack
/// (arms on the [`ExportFormatChoice::PlaintextOtpauth`] path), and
/// the twice-confirm passphrase [`SecretEntry`] buffers used on the
/// [`ExportFormatChoice::EncryptedPaladin`] path. Subsequent sub-items
/// extend the struct with the busy latch and the post-worker
/// rendering slots. The widget layer drives this via [`apply_msg`] and
/// reads it via the `compose_*` helpers so the state stays unit-
/// testable in `tests/export_dialog_logic.rs`.
///
/// Not `Debug` because [`SecretEntry`] deliberately opts out of
/// `Debug` so a stray `dbg!` cannot leak the bundle passphrase
/// through the error log; not `Clone` for the same reason — the
/// zeroizing buffers must not be duplicated.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
pub struct ExportDialogState {
    destination_path: Option<PathBuf>,
    destination_exists: bool,
    format: ExportFormatChoice,
    overwrite_acknowledged: bool,
    plaintext_warning_acknowledged: bool,
    /// Bundle passphrase entry buffer. Inner [`zeroize::Zeroizing`]
    /// wipes on drop / clear; cleared whenever the destination or
    /// format changes per [`passphrase_needs_reset`].
    passphrase: SecretEntry,
    /// Confirm-passphrase entry buffer. Same lifecycle as
    /// [`Self::passphrase`].
    confirm_passphrase: SecretEntry,
    /// Inline error staged by the dialog body. Producers are the
    /// `SubmitClicked` twice-confirm pre-flight (`invalid_passphrase`)
    /// and the post-worker `WorkerCompleted` dispatch for
    /// [`ExportOutcome::Inline`] (`io_error`, `save_not_committed`,
    /// other writer errors). Cleared on edits to the passphrase rows,
    /// destination / format changes, the next accepted
    /// `SubmitClicked`, and `WorkerCompleted(Success)` so a dismissed
    /// failure never lingers beside the freshly accepted input.
    inline_error: Option<InlineError>,
    /// Inline warning staged after a `save_durability_unconfirmed`
    /// writer outcome. Carries the typed [`InlineWarning`] so the
    /// dialog body can render the committed-but-uncertain warning per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Effect errors". Cleared on
    /// `WorkerCompleted(Success)` and on subsequent successful
    /// submissions.
    inline_warning: Option<InlineWarning>,
    /// Busy latch toggled by [`ExportDialogMsg::SetBusy`]. `true`
    /// while a `gio::spawn_blocking` export worker is in flight; the
    /// view dims the Export / Cancel buttons via
    /// [`compose_submit_button_sensitive`] so the user cannot dispatch
    /// a second worker over the first.
    busy: bool,
}

impl ExportDialogState {
    /// Construct a fresh state — equivalent to `Self::default()`.
    /// `format` defaults to [`ExportFormatChoice::default`] (the
    /// plaintext newline-separated `otpauth://` URI list, mirroring
    /// the CLI's no-`--format` behavior).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Currently selected destination path, if any.
    #[must_use]
    pub fn destination_path(&self) -> Option<&Path> {
        self.destination_path.as_deref()
    }

    /// Whether the currently selected destination already exists on
    /// disk per the widget's `Path::try_exists` probe. Returns
    /// `false` when no destination has been picked yet, or when the
    /// probe returned `Ok(false)`. The widget treats
    /// `try_exists` I/O errors as `true` (assume it exists, arm the
    /// gate) — silent overwrites are always the worse failure mode.
    #[must_use]
    pub fn destination_exists(&self) -> bool {
        self.destination_exists
    }

    /// Currently selected format.
    #[must_use]
    pub fn format(&self) -> ExportFormatChoice {
        self.format
    }

    /// Whether the user has ack'd the inline overwrite gate for the
    /// current `(destination, format)` pair. Resets to `false`
    /// whenever the destination or format changes per
    /// [`overwrite_gate_needs_reset`].
    #[must_use]
    pub fn is_overwrite_acknowledged(&self) -> bool {
        self.overwrite_acknowledged
    }

    /// Whether the user has ack'd the plaintext-export warning for
    /// the current `(destination, format)` pair. Resets to `false`
    /// whenever the destination or format changes per
    /// [`plaintext_warning_needs_reset`].
    #[must_use]
    pub fn is_plaintext_warning_acknowledged(&self) -> bool {
        self.plaintext_warning_acknowledged
    }

    /// Update the destination path and the cached existence probe.
    /// The widget calls this from the [`gtk::FileDialog`] callback
    /// after the user picks a file and runs `Path::try_exists`.
    ///
    /// Resets the overwrite-acknowledgement, the plaintext-warning
    /// acknowledgement, and the twice-confirm passphrase entries when
    /// the path or format has changed per
    /// [`overwrite_gate_needs_reset`] /
    /// [`plaintext_warning_needs_reset`] / [`passphrase_needs_reset`]:
    /// a stale ack or typed passphrase must never carry across to a
    /// different file. Re-picking the exact same path is idempotent
    /// — the typed passphrase survives so a probe-only refresh does
    /// not erase the user's input.
    pub fn set_destination(&mut self, path: PathBuf, exists: bool) {
        let format = self.format;
        let (reset_overwrite, reset_plaintext, reset_passphrase) =
            match self.destination_path.as_deref() {
                Some(prev) => (
                    overwrite_gate_needs_reset(prev, format, &path, format),
                    plaintext_warning_needs_reset(prev, format, &path, format),
                    passphrase_needs_reset(prev, format, &path, format),
                ),
                None => (true, true, false),
            };
        if reset_overwrite {
            self.overwrite_acknowledged = false;
        }
        if reset_plaintext {
            self.plaintext_warning_acknowledged = false;
        }
        if reset_passphrase {
            self.passphrase.clear();
            self.confirm_passphrase.clear();
            // A stale `invalid_passphrase` body must not linger beside
            // the freshly emptied passphrase rows.
            self.inline_error = None;
        }
        self.destination_path = Some(path);
        self.destination_exists = exists;
    }

    /// Update the active format. The widget calls this from the
    /// `adw::ComboRow` `connect_selected_notify` handler when
    /// [`format_choice_from_index`] decodes the selection.
    ///
    /// Resets the overwrite-acknowledgement, the plaintext-warning
    /// acknowledgement, and the twice-confirm passphrase entries when
    /// the format changes per [`overwrite_gate_needs_reset`] /
    /// [`plaintext_warning_needs_reset`] / [`passphrase_needs_reset`]:
    /// all three are keyed to `(path, format)` because the two formats
    /// write distinct payloads even at the same path. The plaintext-
    /// warning ack and passphrase rows also reset on a same-path
    /// format hop (regardless of destination) so any value that
    /// survived the hop is invalidated and the user re-prompts from a
    /// clean slate.
    pub fn set_format(&mut self, format: ExportFormatChoice) {
        let prev_format = self.format;
        let (reset_overwrite, reset_plaintext, reset_passphrase) =
            match self.destination_path.as_deref() {
                Some(prev_dest) => (
                    overwrite_gate_needs_reset(prev_dest, prev_format, prev_dest, format),
                    plaintext_warning_needs_reset(prev_dest, prev_format, prev_dest, format),
                    passphrase_needs_reset(prev_dest, prev_format, prev_dest, format),
                ),
                // No destination yet. The overwrite ack tracks the
                // (path, format) pair against an actual file, so a
                // format-only change cannot invalidate an ack against
                // nothing. The plaintext ack and the passphrase rows,
                // by contrast, are keyed to the format selector
                // regardless of destination — the widget reveals the
                // warning whenever the plaintext format is active and
                // the passphrase rows whenever the encrypted format
                // is active. A format-only switch must clear any
                // pre-destination ack / typed passphrase so the next
                // entry is re-prompted from a clean slate.
                None => (false, prev_format != format, prev_format != format),
            };
        if reset_overwrite {
            self.overwrite_acknowledged = false;
        }
        if reset_plaintext {
            self.plaintext_warning_acknowledged = false;
        }
        if reset_passphrase {
            self.passphrase.clear();
            self.confirm_passphrase.clear();
            // A stale `invalid_passphrase` body must not linger beside
            // the freshly emptied passphrase rows.
            self.inline_error = None;
        }
        self.format = format;
    }

    /// Toggle the inline overwrite-acknowledgement gate. The widget
    /// binds this to the `AdwSwitchRow` `connect_active_notify`
    /// handler; flipping the switch off rearms the gate so a future
    /// careful user can step back from an ack they regret.
    pub fn set_overwrite_acknowledged(&mut self, acknowledged: bool) {
        self.overwrite_acknowledged = acknowledged;
    }

    /// Toggle the plaintext-warning acknowledgement. The widget binds
    /// this to the `AdwSwitchRow` `connect_active_notify` handler
    /// underneath the warning body; flipping the switch off rearms
    /// the gate so the user can step back from an ack they regret.
    pub fn set_plaintext_warning_acknowledged(&mut self, acknowledged: bool) {
        self.plaintext_warning_acknowledged = acknowledged;
    }

    /// Current bundle-passphrase entry text. Empty when no passphrase
    /// is required (plaintext format) or the user has not yet typed.
    #[must_use]
    pub fn passphrase_text(&self) -> &str {
        self.passphrase.text()
    }

    /// Current confirm-passphrase entry text. Empty when no passphrase
    /// is required (plaintext format) or the user has not yet typed.
    #[must_use]
    pub fn confirm_passphrase_text(&self) -> &str {
        self.confirm_passphrase.text()
    }

    /// Replace the bundle-passphrase entry buffer. The widget calls
    /// this from the `AdwPasswordEntryRow` `connect_changed` handler
    /// per keystroke so the Paladin-owned shadow tracks the GTK
    /// `gtk::EntryBuffer` verbatim; the prior buffer contents are
    /// zeroized in place via [`SecretEntry::set`].
    ///
    /// Also clears any staged inline error so the user is not stuck
    /// staring at a dismissed `invalid_passphrase` body while typing
    /// the fix.
    pub fn set_passphrase(&mut self, text: &str) {
        self.passphrase.set(text);
        self.inline_error = None;
    }

    /// Replace the confirm-passphrase entry buffer. Same per-keystroke
    /// semantics as [`Self::set_passphrase`], including the inline-
    /// error clearing.
    pub fn set_confirm_passphrase(&mut self, text: &str) {
        self.confirm_passphrase.set(text);
        self.inline_error = None;
    }

    /// Currently staged inline error, if any. The `compose_inline_error_*`
    /// view-layer helpers read this; widgets bind via
    /// [`compose_inline_error_revealed`] and [`compose_inline_error_body`].
    #[must_use]
    pub fn inline_error(&self) -> Option<&InlineError> {
        self.inline_error.as_ref()
    }

    /// Replace the staged inline error. Internal callers stage a
    /// [`SubmitRejection`]-derived error via [`apply_msg`]; tests use
    /// this to seed prior-state fixtures.
    pub fn set_inline_error(&mut self, err: Option<InlineError>) {
        self.inline_error = err;
    }

    /// Currently staged inline warning, if any. The
    /// `compose_inline_warning_*` view-layer helpers read this; the
    /// only producer is `WorkerCompleted(DurabilityWarning)`.
    #[must_use]
    pub fn inline_warning(&self) -> Option<&InlineWarning> {
        self.inline_warning.as_ref()
    }

    /// Replace the staged inline warning. Internal callers stage a
    /// [`classify_export_result`]-derived warning via [`apply_msg`];
    /// tests use this to seed prior-state fixtures.
    pub fn set_inline_warning(&mut self, warning: Option<InlineWarning>) {
        self.inline_warning = warning;
    }

    /// Whether a vault-touching export worker is currently in flight.
    /// The view binds this through [`compose_submit_button_sensitive`]
    /// so the user cannot dispatch a second worker over the first.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Toggle the busy latch. `AppModel` pushes `true` when it spawns
    /// the export worker (via [`ExportDialogMsg::SetBusy(true)`]) and
    /// `false` once the worker reports completion. The plumbing
    /// mirrors `ImportDialogState::set_busy` so the two dialogs stay
    /// in lock-step.
    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
    }
}

/// Subtitle binding for the destination `adw::ActionRow`.
///
/// Returns the picked path's full display string when a destination
/// is selected, or
/// [`format_export_dialog_destination_row_placeholder`] otherwise.
#[must_use]
pub fn compose_destination_row_subtitle(state: &ExportDialogState) -> String {
    match state.destination_path() {
        Some(path) => path.display().to_string(),
        None => format_export_dialog_destination_row_placeholder().to_string(),
    }
}

/// `gtk::Revealer::set_reveal_child` binding for the inline overwrite
/// gate row.
///
/// Returns `true` iff the destination has been picked AND the
/// widget's `Path::try_exists` probe reported the file already
/// existed. The widget mounts an `AdwSwitchRow` underneath the
/// destination row and reveals it through this predicate so the user
/// only sees the gate when an actual overwrite is at stake. The CLI
/// `--force` flag is the same idea inverted: refuse silently in the
/// default case, accept on explicit acknowledgement.
#[must_use]
pub fn compose_overwrite_gate_visible(state: &ExportDialogState) -> bool {
    state.destination_path().is_some() && state.destination_exists()
}

/// `gtk::Widget::set_visible` binding for the inline plaintext-warning
/// group.
///
/// Returns `true` iff the active format is the plaintext
/// `otpauth://` URI list ([`ExportFormatChoice::requires_plaintext_warning`]).
/// The widget mounts the warning body + ack row inside an
/// `adw::PreferencesGroup` and reveals it through this predicate so
/// the user only sees the warning when an actual plaintext write is
/// at stake. Destination presence is intentionally not part of the
/// predicate — the warning is keyed to the format selector so the
/// user sees the risk before committing to a destination.
#[must_use]
pub fn compose_plaintext_warning_visible(state: &ExportDialogState) -> bool {
    state.format().requires_plaintext_warning()
}

/// `gtk::Label::set_label` binding for the inline plaintext-warning
/// body.
///
/// Returns the verbatim core wording through
/// [`paladin_core::format_plaintext_export_warning`] so the GUI,
/// CLI, and TUI all surface the same text. Wrapping it as a
/// `compose_*` projection mirrors the rest of the dialog's view-
/// layer plumbing and gives the widget one consistent binding shape
/// across every body / label / subtitle in the dialog.
#[must_use]
pub fn compose_plaintext_warning_body() -> String {
    plaintext_warning_body()
}

/// `gtk::Widget::set_visible` binding for the encrypted-bundle
/// twice-confirm passphrase rows.
///
/// Returns `true` iff the active format is the encrypted Paladin
/// bundle ([`ExportFormatChoice::requires_passphrase`]). The widget
/// mounts the two `AdwPasswordEntryRow` rows inside an
/// `adw::PreferencesGroup` and reveals it through this predicate so
/// the rows are only visible when an encrypted write is at stake.
/// Destination presence is intentionally not part of the predicate
/// — the rows are keyed to the format selector so the user can type
/// a passphrase before committing to a destination; the
/// destination-change reset rule ([`passphrase_needs_reset`]) wipes
/// any typed value once the destination is set and then changes.
#[must_use]
pub fn compose_passphrase_rows_visible(state: &ExportDialogState) -> bool {
    state.format().requires_passphrase()
}

/// `gtk::Button::set_sensitive` binding for the footer Export button.
///
/// Returns `true` only when:
/// * The user has picked a destination path, and
/// * Either the destination does not already exist, or the user has
///   ack'd the inline overwrite gate, and
/// * Either the active format does not require the plaintext
///   warning, or the user has ack'd the plaintext-warning gate, and
/// * Either the active format does not require the twice-confirm
///   passphrase rows (plaintext path), or both rows are non-empty
///   AND match (so the worker dispatch never hands an empty or
///   mismatched pair to [`prepare_encrypted_export`]).
#[must_use]
pub fn compose_submit_button_sensitive(state: &ExportDialogState) -> bool {
    if state.is_busy() {
        return false;
    }
    if state.destination_path().is_none() {
        return false;
    }
    if compose_overwrite_gate_visible(state) && !state.is_overwrite_acknowledged() {
        return false;
    }
    if compose_plaintext_warning_visible(state) && !state.is_plaintext_warning_acknowledged() {
        return false;
    }
    if compose_passphrase_rows_visible(state) {
        let passphrase = state.passphrase_text();
        let confirm = state.confirm_passphrase_text();
        if passphrase.is_empty() || passphrase != confirm {
            return false;
        }
    }
    true
}

/// Apply an [`ExportDialogMsg`] to the [`ExportDialogState`] and
/// return the optional [`ExportDialogOutput`] the widget should
/// forward to `AppModel`.
///
/// Mirrors the [`crate::import_dialog::apply_msg`] shape so the two
/// dialogs stay in lock-step. The widget calls this from
/// [`relm4::SimpleComponent::update`]; `AppModel` consumes the
/// returned output through the existing
/// [`crate::app::model::AppMsg::ExportDialogAction`] dispatch arm.
pub fn apply_msg(
    state: &mut ExportDialogState,
    msg: ExportDialogMsg,
) -> Option<ExportDialogOutput> {
    match msg {
        ExportDialogMsg::DestinationPicked { path, exists } => {
            state.set_destination(path, exists);
            None
        }
        ExportDialogMsg::FormatChanged(format) => {
            state.set_format(format);
            None
        }
        ExportDialogMsg::OverwriteAcknowledged(acknowledged) => {
            state.set_overwrite_acknowledged(acknowledged);
            None
        }
        ExportDialogMsg::PlaintextWarningAcknowledged(acknowledged) => {
            state.set_plaintext_warning_acknowledged(acknowledged);
            None
        }
        ExportDialogMsg::PassphraseChanged(text) => {
            state.set_passphrase(&text);
            None
        }
        ExportDialogMsg::ConfirmPassphraseChanged(text) => {
            state.set_confirm_passphrase(&text);
            None
        }
        ExportDialogMsg::SubmitClicked => {
            // Defense-in-depth: a stray click while busy or with
            // unmet gates emits no output. `compose_submit_outcome`
            // owns the routing decision so the dispatch matches
            // `compose_submit_button_sensitive` exactly.
            if state.is_busy() {
                return None;
            }
            match compose_submit_outcome(state) {
                SubmitOutcome::Proceed(payload) => {
                    // The accepted twice-confirm pair has moved into
                    // the payload's `EncryptionOptions`; the state-
                    // side buffers must be zeroized so the secret
                    // does not linger in the dialog while the worker
                    // runs. `SecretEntry::clear` wipes the inner
                    // `Zeroizing<String>` in place.
                    state.passphrase.clear();
                    state.confirm_passphrase.clear();
                    state.set_inline_error(None);
                    Some(ExportDialogOutput::Submit(payload))
                }
                SubmitOutcome::Rejected(inline) => {
                    state.set_inline_error(Some(inline));
                    None
                }
                SubmitOutcome::NotReady => None,
            }
        }
        ExportDialogMsg::SetBusy(busy) => {
            state.set_busy(busy);
            None
        }
        ExportDialogMsg::WorkerCompleted(outcome) => {
            // The worker always releases the busy latch; the dialog
            // body re-evaluates `compose_submit_button_sensitive` so
            // the Export button re-enables (or stays dim if a gate is
            // unmet).
            state.set_busy(false);
            match outcome {
                ExportOutcome::Success => {
                    // Defense-in-depth: clear any lingering
                    // passphrase buffer (should already be empty
                    // because `SubmitClicked` zeroized them on
                    // dispatch, but the worker outcome is the
                    // authoritative success surface).
                    state.passphrase.clear();
                    state.confirm_passphrase.clear();
                    state.set_inline_error(None);
                    state.set_inline_warning(None);
                    Some(ExportDialogOutput::Close)
                }
                ExportOutcome::DurabilityWarning(warning) => {
                    state.set_inline_warning(Some(warning));
                    state.set_inline_error(None);
                    None
                }
                ExportOutcome::Inline(err) => {
                    state.set_inline_error(Some(err));
                    state.set_inline_warning(None);
                    None
                }
            }
        }
        ExportDialogMsg::Cancel => {
            // §"Secret entry handling": zeroize the passphrase
            // buffers before the dialog tears down so the secret
            // does not linger in memory while `AppModel` drops the
            // controller.
            state.passphrase.clear();
            state.confirm_passphrase.clear();
            Some(ExportDialogOutput::Cancel)
        }
        ExportDialogMsg::Close => {
            state.passphrase.clear();
            state.confirm_passphrase.clear();
            Some(ExportDialogOutput::Close)
        }
    }
}

/// `gtk::Revealer::set_reveal_child` binding for the inline-error row.
///
/// Returns `true` iff the state has a staged [`InlineError`] — currently
/// only the `SubmitClicked` twice-confirm pre-flight stages one. The
/// dialog body wraps the rendered text in a `gtk::Revealer` so the slot
/// collapses cleanly when no error is staged.
#[must_use]
pub fn compose_inline_error_revealed(state: &ExportDialogState) -> bool {
    state.inline_error().is_some()
}

/// `gtk::Label::set_label` binding for the inline-error body. Returns
/// the rendered `invalid_passphrase` body when an error is staged, or
/// `None` when the slot is collapsed.
#[must_use]
pub fn compose_inline_error_body(state: &ExportDialogState) -> Option<&str> {
    state.inline_error().map(|e| e.rendered.as_str())
}

/// `gtk::Revealer::set_reveal_child` binding for the inline-warning row.
///
/// Returns `true` iff the state has a staged [`InlineWarning`] —
/// currently only `WorkerCompleted(DurabilityWarning)` stages one.
/// The dialog body wraps the rendered text in a `gtk::Revealer` so
/// the slot collapses cleanly when no warning is staged.
#[must_use]
pub fn compose_inline_warning_revealed(state: &ExportDialogState) -> bool {
    state.inline_warning().is_some()
}

/// `gtk::Label::set_label` binding for the inline-warning body.
/// Returns the rendered `save_durability_unconfirmed` body when a
/// warning is staged, or `None` when the slot is collapsed.
#[must_use]
pub fn compose_inline_warning_body(state: &ExportDialogState) -> Option<&str> {
    state.inline_warning().map(|w| w.rendered.as_str())
}

/// Pinned text rendered on the success [`AdwToast`]. Mirrors the CLI's
/// "Exported N entries to <path>" stdout line, but the dialog flow
/// has no entry count to surface (the user picks the destination,
/// not the row set), so the toast names the destination only. The
/// toast surface in `AppModel` builds this string from
/// [`ExportWorkerCompletion::destination`].
#[must_use]
pub fn format_export_success_toast(destination: &Path) -> String {
    format!("Exported to {}", destination.display())
}

/// Widget-bearing `adw::Dialog` for the application menu's Export… entry.
///
/// Mounts the libadwaita dialog described in docs/DESIGN.md §7
/// (`ExportDialog`) and `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component
/// tree" > `ExportDialog`. The widget body now exposes the
/// destination picker (an `adw::ActionRow` with a "Choose file…"
/// `gtk::Button` that opens a [`gtk::FileDialog`]) and the format
/// selector (an `adw::ComboRow` driven by
/// [`format_export_dialog_format_labels`]). Subsequent sub-items
/// attach the overwrite-gate, the plaintext-warning gate, the
/// twice-confirm passphrase row, and the export worker that drives
/// [`classify_export_result`].
pub struct ExportDialogComponent {
    /// Vault path the dialog mounts against, kept on `self` so the
    /// follow-up export worker can reach it without re-plumbing
    /// through every signal. The pure-logic round-trip is asserted
    /// by `tests/export_dialog_logic.rs`.
    #[allow(dead_code)]
    vault_path: PathBuf,
    /// Form-draft state machine driven by [`apply_msg`]. Holds the
    /// destination path + format choice + gate / passphrase / busy /
    /// post-worker slots. The widget view reads this via the
    /// `compose_*` helpers.
    state: ExportDialogState,
    /// Stashed reference to the bundle-passphrase
    /// `AdwPasswordEntryRow` so [`Self::update`] can call
    /// [`adw::PasswordEntryRow::set_text("")`] to wipe the GTK
    /// `gtk::EntryBuffer` on Submit / Cancel / Close per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Secret entry handling". A
    /// `#[watch]` binding on `set_text:` would loop indefinitely
    /// because `gtk_editable_set_text` is implemented as `delete +
    /// insert` and always emits `changed`; the explicit call here
    /// fires once per zeroize event with no feedback loop. Set
    /// inside [`Self::init`] after `view_output!`.
    passphrase_row: Option<adw::PasswordEntryRow>,
    /// Stashed reference to the confirm-passphrase
    /// `AdwPasswordEntryRow`. Same lifecycle / clear semantics as
    /// [`Self::passphrase_row`].
    confirm_passphrase_row: Option<adw::PasswordEntryRow>,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for ExportDialogComponent {
    type Init = ExportDialogInit;
    type Input = ExportDialogMsg;
    type Output = ExportDialogOutput;

    view! {
        #[root]
        adw::Dialog {
            set_title: format_export_dialog_title(),

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {},

                #[wrap(Some)]
                set_content = &gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 12,
                    set_margin_top: 12,
                    set_margin_bottom: 12,
                    set_margin_start: 12,
                    set_margin_end: 12,

                    gtk::Label {
                        set_label: format_export_dialog_subtitle(),
                        set_xalign: 0.0,
                        set_wrap: true,
                        add_css_class: "dim-label",
                    },

                    #[name = "destination_group"]
                    adw::PreferencesGroup {
                        set_title: format_export_dialog_destination_group_title(),

                        #[name = "destination_row"]
                        add = &adw::ActionRow {
                            set_title: format_export_dialog_destination_row_title(),
                            #[watch]
                            set_subtitle: &compose_destination_row_subtitle(&model.state),

                            #[name = "choose_destination_button"]
                            add_suffix = &gtk::Button {
                                set_label: format_export_dialog_choose_destination_label(),
                                set_valign: gtk::Align::Center,
                            },
                        },

                        #[name = "overwrite_gate_row"]
                        add = &adw::SwitchRow {
                            set_title: format_export_dialog_overwrite_gate_title(),
                            set_subtitle: format_export_dialog_overwrite_gate_subtitle(),
                            #[watch]
                            set_visible: compose_overwrite_gate_visible(&model.state),
                            #[watch]
                            set_active: model.state.is_overwrite_acknowledged(),
                            // `Sender::send` is used instead of
                            // `ComponentSender::input` (which
                            // `.expect`s on a closed channel) so a
                            // stray callback after the controller
                            // is dropped is a benign no-op rather
                            // than a process abort. See
                            // `import_dialog`'s Cancel button for
                            // the canonical comment.
                            connect_active_notify[sender] => move |row| {
                                let _ = sender.input_sender().send(
                                    ExportDialogMsg::OverwriteAcknowledged(row.is_active()),
                                );
                            },
                        },
                    },

                    #[name = "options_group"]
                    adw::PreferencesGroup {
                        set_title: format_export_dialog_options_group_title(),

                        #[name = "format_row"]
                        add = &adw::ComboRow {
                            set_title: format_export_dialog_format_row_title(),
                            set_model: Some(&gtk::StringList::new(
                                format_export_dialog_format_labels(),
                            )),
                            #[watch]
                            set_selected: model.state.format().index(),
                            // See the overwrite-gate `connect_active_notify` comment.
                            connect_selected_notify[sender] => move |row| {
                                if let Some(choice) =
                                    format_choice_from_index(row.selected())
                                {
                                    let _ = sender
                                        .input_sender()
                                        .send(ExportDialogMsg::FormatChanged(choice));
                                }
                            },
                        },
                    },

                    #[name = "plaintext_warning_group"]
                    adw::PreferencesGroup {
                        set_title: format_export_dialog_plaintext_warning_group_title(),
                        #[watch]
                        set_visible: compose_plaintext_warning_visible(&model.state),

                        #[name = "plaintext_warning_body_row"]
                        add = &adw::ActionRow {
                            // Mount the verbatim warning as the row's
                            // title via `compose_plaintext_warning_body`
                            // so the wording stays in lock-step with
                            // `paladin_core::format_plaintext_export_warning`.
                            // Title is `set_use_markup: false` by
                            // default, so the body renders as plain
                            // text identically to the CLI / TUI.
                            #[watch]
                            set_title: &compose_plaintext_warning_body(),
                            set_title_lines: 0,
                            set_subtitle_lines: 0,
                            add_css_class: "warning",
                        },

                        #[name = "plaintext_warning_ack_row"]
                        add = &adw::SwitchRow {
                            set_title: format_export_dialog_plaintext_warning_ack_title(),
                            set_subtitle: format_export_dialog_plaintext_warning_ack_subtitle(),
                            #[watch]
                            set_active: model.state.is_plaintext_warning_acknowledged(),
                            // See the overwrite-gate `connect_active_notify` comment.
                            connect_active_notify[sender] => move |row| {
                                let _ = sender.input_sender().send(
                                    ExportDialogMsg::PlaintextWarningAcknowledged(
                                        row.is_active(),
                                    ),
                                );
                            },
                        },
                    },

                    #[name = "passphrase_group"]
                    adw::PreferencesGroup {
                        set_title: format_export_dialog_passphrase_group_title(),
                        #[watch]
                        set_visible: compose_passphrase_rows_visible(&model.state),

                        #[name = "passphrase_row"]
                        add = &adw::PasswordEntryRow {
                            set_title: format_export_dialog_passphrase_row_title(),
                            // See the overwrite-gate `connect_active_notify` comment.
                            connect_changed[sender] => move |entry| {
                                let _ = sender.input_sender().send(
                                    ExportDialogMsg::PassphraseChanged(
                                        entry.text().to_string(),
                                    ),
                                );
                            },
                        },

                        #[name = "confirm_passphrase_row"]
                        add = &adw::PasswordEntryRow {
                            set_title: format_export_dialog_confirm_passphrase_row_title(),
                            // See the overwrite-gate `connect_active_notify` comment.
                            connect_changed[sender] => move |entry| {
                                let _ = sender.input_sender().send(
                                    ExportDialogMsg::ConfirmPassphraseChanged(
                                        entry.text().to_string(),
                                    ),
                                );
                            },
                        },
                    },

                    // Inline error revealer. Producers: the
                    // SubmitClicked twice-confirm pre-flight
                    // (`invalid_passphrase`) and `WorkerCompleted`'s
                    // `ExportOutcome::Inline` arm (`io_error`,
                    // `save_not_committed`, other writer errors).
                    #[name = "inline_error_revealer"]
                    gtk::Revealer {
                        #[watch]
                        set_reveal_child: compose_inline_error_revealed(&model.state),
                        set_transition_type: gtk::RevealerTransitionType::SlideDown,
                        set_transition_duration: 150,

                        #[name = "inline_error_label"]
                        gtk::Label {
                            #[watch]
                            set_label: compose_inline_error_body(&model.state)
                                .unwrap_or(""),
                            set_xalign: 0.0,
                            set_wrap: true,
                            add_css_class: "error",
                        },
                    },

                    // Inline warning revealer. Producer:
                    // `WorkerCompleted`'s
                    // `ExportOutcome::DurabilityWarning` arm
                    // (`save_durability_unconfirmed`) — the export
                    // file is on disk but the parent-directory
                    // `fsync` failed. The dialog stays open so the
                    // user explicitly dismisses the warning.
                    #[name = "inline_warning_revealer"]
                    gtk::Revealer {
                        #[watch]
                        set_reveal_child: compose_inline_warning_revealed(&model.state),
                        set_transition_type: gtk::RevealerTransitionType::SlideDown,
                        set_transition_duration: 150,

                        #[name = "inline_warning_label"]
                        gtk::Label {
                            #[watch]
                            set_label: compose_inline_warning_body(&model.state)
                                .unwrap_or(""),
                            set_xalign: 0.0,
                            set_wrap: true,
                            add_css_class: "warning",
                        },
                    },

                    // Footer: Cancel / Export (subsequent sub-items
                    // attach a busy spinner and post-success Dismiss
                    // button alongside the existing affordances).
                    gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_spacing: 8,
                        set_halign: gtk::Align::End,
                        set_margin_top: 6,

                        #[name = "cancel_button"]
                        gtk::Button {
                            set_label: format_export_dialog_cancel_label(),
                            // See the overwrite-gate `connect_active_notify` comment.
                            connect_clicked[sender] => move |_| {
                                let _ = sender.input_sender().send(ExportDialogMsg::Cancel);
                            },
                        },

                        #[name = "export_button"]
                        gtk::Button {
                            set_label: format_export_dialog_export_label(),
                            add_css_class: "suggested-action",
                            #[watch]
                            set_sensitive: compose_submit_button_sensitive(&model.state),
                            // See the overwrite-gate `connect_active_notify` comment.
                            connect_clicked[sender] => move |_| {
                                let _ = sender
                                    .input_sender()
                                    .send(ExportDialogMsg::SubmitClicked);
                            },
                        },
                    },
                },
            },

            // `connect_closed` fires on Escape / window-close /
            // parent-navigation close. `AppModel` drops the
            // controller on both Cancel and Close; the variants stay
            // distinct so a future Close-only behavior (e.g. a
            // "Discard draft?" prompt) can attach to one dispatch arm
            // without affecting Cancel.
            // See the overwrite-gate `connect_active_notify` comment.
            connect_closed[sender] => move |_| {
                let _ = sender.input_sender().send(ExportDialogMsg::Close);
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut model = ExportDialogComponent {
            vault_path: init.vault_path,
            state: ExportDialogState::new(),
            passphrase_row: None,
            confirm_passphrase_row: None,
        };
        let widgets = view_output!();
        // Stash widget refs for the SecretEntry-widget zeroize hook
        // in `update()`. `adw::PasswordEntryRow` is a `GObject`;
        // `clone()` just bumps the refcount.
        model.passphrase_row = Some(widgets.passphrase_row.clone());
        model.confirm_passphrase_row = Some(widgets.confirm_passphrase_row.clone());

        // Wire the "Choose file…" button to `gtk::FileDialog::save`.
        // The async result feeds back as
        // `ExportDialogMsg::DestinationPicked { path, exists }` with
        // the user's selection. The picker's choice is stored
        // verbatim per §"`ExportDialog`" raw-path semantics; the
        // `exists` flag arms the inline overwrite gate. On
        // `Path::try_exists` I/O errors we pass `true` (assume the
        // file exists, force the user to ack) — silent overwrites
        // are always the worse failure mode.
        let dialog_root = root.clone();
        let sender_clone = sender.clone();
        widgets.choose_destination_button.connect_clicked(move |_| {
            let file_dialog = gtk::FileDialog::builder()
                .title("Choose export destination")
                .modal(true)
                .build();
            let sender_inner = sender_clone.clone();
            let parent = dialog_root.clone();
            file_dialog.save(
                parent.root().and_downcast_ref::<gtk::Window>(),
                None::<&relm4::gtk::gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result {
                        if let Some(path) = file.path() {
                            let exists = path.try_exists().unwrap_or(true);
                            // The `FileDialog::save` callback is
                            // long-lived (it survives across the
                            // whole open dialog session) and may
                            // fire after the parent controller has
                            // been dropped. Route through
                            // `Sender::send` so a stray completion
                            // is a benign no-op rather than a
                            // process abort.
                            let _ = sender_inner
                                .input_sender()
                                .send(ExportDialogMsg::DestinationPicked { path, exists });
                        }
                    }
                },
            );
        });

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        // Inspect the msg discriminant before consuming it so the
        // post-`apply_msg` widget-zeroize hook below knows which paths
        // require wiping the `gtk::EntryBuffer`. The matching
        // `SecretEntry` shadows are cleared inside `apply_msg`; the
        // explicit `set_text("")` here wipes the widget buffer (the
        // unavoidable UI-side copy of the typed passphrase) per
        // `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Secret entry handling".
        // `WorkerCompleted(Success)` also triggers a wipe because the
        // dialog tears down on the emitted `Close` output, and the
        // widget should not hold the typed passphrase between the
        // Submit dispatch and the controller drop.
        let wipe_secret_widgets = matches!(
            msg,
            ExportDialogMsg::SubmitClicked
                | ExportDialogMsg::Cancel
                | ExportDialogMsg::Close
                | ExportDialogMsg::WorkerCompleted(ExportOutcome::Success)
        );
        let output = apply_msg(&mut self.state, msg);
        if wipe_secret_widgets {
            if let Some(row) = self.passphrase_row.as_ref() {
                row.set_text("");
            }
            if let Some(row) = self.confirm_passphrase_row.as_ref() {
                row.set_text("");
            }
        }
        if let Some(output) = output {
            // Forward to `AppModel`. A closed output channel only happens
            // if `AppModel` already dropped the controller, in which case
            // the dialog is about to be torn down — drop the output.
            let _ = sender.output(output);
        }
    }
}
