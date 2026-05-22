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

use std::path::{Path, PathBuf};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

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
///
/// [`Default`] returns [`ExportFormatChoice::PlaintextOtpauth`] for
/// CLI parity: `paladin export <DEST>` with no `--format` flag writes
/// the plaintext `otpauth://` JSON list, and the dialog opens on the
/// same format so the user's first interaction matches the CLI
/// documentation. Switching to the encrypted path is one click on
/// the format-selector `adw::ComboRow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportFormatChoice {
    /// Plaintext otpauth JSON list. Requires the plaintext-export
    /// warning to be acknowledged before the writer runs.
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
    &["Plaintext otpauth:// JSON list", "Encrypted Paladin bundle"]
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
/// overwrite-gate sub-items from `IMPLEMENTATION_PLAN_04_GTK.md`
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
    /// (subject to subsequent sub-items' plaintext-warning and
    /// twice-confirm passphrase gates).
    OverwriteAcknowledged(bool),
    /// User clicked the explicit Cancel button. The dispatch arm
    /// emits [`ExportDialogOutput::Cancel`] so `AppModel` drops the
    /// live controller and the form draft is discarded.
    Cancel,
    /// User dismissed the dialog via the parent close path (Escape /
    /// window close). The dispatch arm emits
    /// [`ExportDialogOutput::Close`]; the variant stays distinct
    /// from [`ExportDialogMsg::Cancel`] so a future "Discard draft?"
    /// prompt can attach to one path without affecting the other.
    Close,
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
#[derive(Debug, Clone)]
pub enum ExportDialogOutput {
    /// User clicked the explicit Cancel button. `AppModel` drops the
    /// live controller so the dialog disappears and any in-flight
    /// pending form draft is discarded. Kept distinct from
    /// [`ExportDialogOutput::Close`] so future "Discard draft?"
    /// behavior can attach to one variant without affecting the
    /// other.
    Cancel,
    /// User dismissed the dialog via the parent close path (Escape /
    /// window close). `AppModel` responds by dropping the live
    /// controller so the dialog disappears and any in-flight pending
    /// form draft (selected destination path, format choice,
    /// overwrite acknowledgement, plaintext-warning acknowledgement,
    /// twice-confirm passphrase entries) is discarded.
    Close,
}

/// Pure-logic state machine for [`ExportDialogComponent`].
///
/// Owns the destination-path + format form draft plus the inline
/// overwrite-acknowledgement gate that arms when the picked
/// destination already exists on disk. Subsequent sub-items extend
/// the struct with the plaintext-warning gate, the twice-confirm
/// passphrase [`crate::secret_fields::SecretEntry`] buffer, the busy
/// latch, and the post-worker rendering slots. The widget layer
/// drives this via [`apply_msg`] and reads it via the `compose_*`
/// helpers so the state stays unit-testable in
/// `tests/export_dialog_logic.rs`.
#[derive(Debug, Default)]
pub struct ExportDialogState {
    destination_path: Option<PathBuf>,
    destination_exists: bool,
    format: ExportFormatChoice,
    overwrite_acknowledged: bool,
}

impl ExportDialogState {
    /// Construct a fresh state — equivalent to `Self::default()`.
    /// `format` defaults to [`ExportFormatChoice::default`] (the
    /// plaintext `otpauth://` JSON list, mirroring the CLI's
    /// no-`--format` behavior).
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

    /// Update the destination path and the cached existence probe.
    /// The widget calls this from the [`gtk::FileDialog`] callback
    /// after the user picks a file and runs `Path::try_exists`.
    ///
    /// Resets the overwrite acknowledgement when the path or format
    /// has changed per [`overwrite_gate_needs_reset`]: a stale ack
    /// must never carry across to a different file. Subsequent
    /// sub-items extend this setter to clear the plaintext-warning
    /// gate and the twice-confirm passphrase entries via
    /// [`plaintext_warning_needs_reset`] / [`passphrase_needs_reset`].
    pub fn set_destination(&mut self, path: PathBuf, exists: bool) {
        let format = self.format;
        let needs_reset = match self.destination_path.as_deref() {
            Some(prev) => overwrite_gate_needs_reset(prev, format, &path, format),
            None => true,
        };
        if needs_reset {
            self.overwrite_acknowledged = false;
        }
        self.destination_path = Some(path);
        self.destination_exists = exists;
    }

    /// Update the active format. The widget calls this from the
    /// `adw::ComboRow` `connect_selected_notify` handler when
    /// [`format_choice_from_index`] decodes the selection.
    ///
    /// Resets the overwrite acknowledgement when the format changes
    /// per [`overwrite_gate_needs_reset`]: the gate is keyed to
    /// `(path, format)` because the two formats write distinct
    /// payloads even at the same path. Subsequent sub-items extend
    /// this setter to clear plaintext-warning / passphrase state when
    /// the format changes, mirroring the existing reset helpers.
    pub fn set_format(&mut self, format: ExportFormatChoice) {
        let prev_format = self.format;
        let needs_reset = match self.destination_path.as_deref() {
            Some(prev_dest) => {
                overwrite_gate_needs_reset(prev_dest, prev_format, prev_dest, format)
            }
            // No destination yet — a format change cannot invalidate
            // an ack against nothing. Setting the field is a no-op
            // for the gate.
            None => false,
        };
        if needs_reset {
            self.overwrite_acknowledged = false;
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

/// `gtk::Button::set_sensitive` binding for the footer Export button.
///
/// Returns `true` only when:
/// * The user has picked a destination path, and
/// * Either the destination does not already exist, or the user has
///   ack'd the inline overwrite gate.
///
/// Subsequent sub-items extend the predicate with the
/// plaintext-warning and twice-confirm passphrase gates so the
/// Export button enables only when every required gate is satisfied.
#[must_use]
pub fn compose_submit_button_sensitive(state: &ExportDialogState) -> bool {
    if state.destination_path().is_none() {
        return false;
    }
    if compose_overwrite_gate_visible(state) && !state.is_overwrite_acknowledged() {
        return false;
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
        ExportDialogMsg::Cancel => Some(ExportDialogOutput::Cancel),
        ExportDialogMsg::Close => Some(ExportDialogOutput::Close),
    }
}

/// Widget-bearing `adw::Dialog` for the application menu's Export… entry.
///
/// Mounts the libadwaita dialog described in DESIGN.md §7
/// (`ExportDialog`) and `IMPLEMENTATION_PLAN_04_GTK.md` §"Component
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
    /// destination path + format choice; subsequent sub-items extend
    /// the struct with the gate / passphrase / busy / post-worker
    /// slots. The widget view reads this via the `compose_*` helpers.
    state: ExportDialogState,
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
                            connect_active_notify[sender] => move |row| {
                                sender.input(ExportDialogMsg::OverwriteAcknowledged(
                                    row.is_active(),
                                ));
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
                            connect_selected_notify[sender] => move |row| {
                                if let Some(choice) =
                                    format_choice_from_index(row.selected())
                                {
                                    sender.input(ExportDialogMsg::FormatChanged(choice));
                                }
                            },
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
                            connect_clicked[sender] => move |_| {
                                sender.input(ExportDialogMsg::Cancel);
                            },
                        },

                        #[name = "export_button"]
                        gtk::Button {
                            set_label: format_export_dialog_export_label(),
                            add_css_class: "suggested-action",
                            #[watch]
                            set_sensitive: compose_submit_button_sensitive(&model.state),
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
            connect_closed[sender] => move |_| {
                sender.input(ExportDialogMsg::Close);
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = ExportDialogComponent {
            vault_path: init.vault_path,
            state: ExportDialogState::new(),
        };
        let widgets = view_output!();

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
                            sender_inner.input(ExportDialogMsg::DestinationPicked { path, exists });
                        }
                    }
                },
            );
        });

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_msg(&mut self.state, msg) {
            // Forward to `AppModel`. A closed output channel only happens
            // if `AppModel` already dropped the controller, in which case
            // the dialog is about to be torn down — drop the output.
            let _ = sender.output(output);
        }
    }
}
