// SPDX-License-Identifier: AGPL-3.0-or-later

//! Import-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `ImportDialog` and §"Tests > Pure-logic unit tests >
//! `tests/import_dialog_logic.rs`", the dialog hosts a
//! [`gtk::FileDialog`] for the source path, a format selector
//! (auto-detect or explicit `otpauth` / `aegis` / `paladin` / `qr`),
//! an on-conflict selector (`skip` / `replace` / `append`), and an
//! optional bundle-passphrase row that appears only when the
//! Paladin-header probe returns
//! [`paladin_core::PaladinImportPrecheck::PromptForPassphrase`]. The
//! widget layer drives this module's helpers to:
//!
//! * Translate the format selector into the
//!   [`paladin_core::ImportFormat`] that
//!   [`paladin_core::ImportOptions::format`] consumes
//!   ([`FormatChoice::forced_format`] /
//!   [`build_import_options`]).
//! * Translate the conflict selector into the
//!   [`paladin_core::ImportConflict`] passed to
//!   [`paladin_core::Vault::import_accounts`]
//!   ([`ConflictChoice::into_policy`]).
//! * Route the Paladin-header probe via
//!   [`paladin_core::classify_paladin_import_precheck`] →
//!   [`classify_precheck`] into one of three decisions:
//!     - [`PrecheckOutcome::Proceed`] continues into
//!       [`paladin_core::import::from_file`] so the importer facade
//!       owns the typed format / I/O errors.
//!     - [`PrecheckOutcome::PromptForPassphrase`] reveals the bundle-
//!       passphrase row.
//!     - [`PrecheckOutcome::InlineError`] surfaces the typed core
//!       error inline (`unsupported_plaintext_vault`,
//!       `invalid_header`, `unsupported_format_version`, …) without
//!       prompting and without touching the vault.
//! * Decide whether the bundle-passphrase row needs clearing on a
//!   source-path or forced-format change ([`passphrase_needs_reset`]).
//! * Classify the [`paladin_core::Vault::mutate_and_save`] result
//!   ([`classify_merge_result`]) into one of four outcomes:
//!     - [`MergeOutcome::Success`] carries the post-merge
//!       [`MergeSummary`] for the counts panel.
//!     - [`MergeOutcome::DurabilityWarning`] surfaces the §5
//!       `save_durability_unconfirmed` warning inline; the merged
//!       accounts stay in memory because core kept the mutated state.
//!     - [`MergeOutcome::NotCommitted`] surfaces the §5
//!       `save_not_committed` typed error inline; core has already
//!       restored its pre-attempt snapshot, so no UI rollback is
//!       needed beyond clearing any optimistic counts.
//!     - [`MergeOutcome::Inline`] covers every other typed error the
//!       closure can return — importer errors
//!       (`unsupported_import_format`, `unsupported_plaintext_vault`,
//!       `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
//!       `validation_error`, `no_entries_to_import`, `decrypt_failed`,
//!       `invalid_header`, `invalid_payload`,
//!       `unsupported_format_version`, `kdf_params_out_of_bounds`,
//!       `io_error`) and the defensive
//!       [`paladin_core::Vault::import_accounts`] errors. All stay
//!       inline; none mutate vault state.
//!
//! The module owns no widgets. The bundle-passphrase row lives in
//! [`crate::secret_fields::SecretEntry`] so the typed bytes zeroize
//! on drop / clear; the wrapper [`SecretString`] used by
//! [`paladin_core::ImportOptions::paladin_passphrase`] zeroizes on
//! drop in turn. Inline-error / inline-warning bodies are rendered
//! through [`PaladinError::Display`], so wording stays in lock-step
//! with the CLI / TUI verbatim.

use std::path::{Path, PathBuf};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::prelude::*;

use paladin_core::{
    ErrorKind, ImportConflict, ImportFormat, ImportOptions, ImportReport, PaladinError,
    PaladinImportPrecheck,
};
use secrecy::SecretString;

/// Format-selector choice surfaced by the `ImportDialog`'s segmented
/// control.
///
/// Maps to the [`paladin_core::ImportFormat`] consumed by
/// [`paladin_core::ImportOptions::format`] via
/// [`FormatChoice::forced_format`] — `None` for auto-detect, `Some(_)`
/// for the explicit choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatChoice {
    /// Auto-detect via [`paladin_core::import::detect`].
    AutoDetect,
    /// Force the [`ImportFormat::Otpauth`] path.
    Otpauth,
    /// Force the [`ImportFormat::Aegis`] (plaintext) path.
    Aegis,
    /// Force the [`ImportFormat::Paladin`] (encrypted bundle) path.
    Paladin,
    /// Force the [`ImportFormat::QrImage`] path.
    Qr,
}

impl FormatChoice {
    /// Translate the dialog selector into the optional forced
    /// [`ImportFormat`].
    ///
    /// [`FormatChoice::AutoDetect`] returns `None`; every other
    /// variant returns `Some(_)`.
    #[must_use]
    pub fn forced_format(self) -> Option<ImportFormat> {
        match self {
            Self::AutoDetect => None,
            Self::Otpauth => Some(ImportFormat::Otpauth),
            Self::Aegis => Some(ImportFormat::Aegis),
            Self::Paladin => Some(ImportFormat::Paladin),
            Self::Qr => Some(ImportFormat::QrImage),
        }
    }
}

/// On-conflict selector surfaced by the dialog.
///
/// Maps to [`paladin_core::ImportConflict`] via
/// [`ConflictChoice::into_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    /// Keep the existing entry on collision; counts under `skipped`.
    Skip,
    /// Overwrite the existing entry on collision; counts under `replaced`.
    Replace,
    /// Insert the colliding row as a fresh account; counts under `appended`.
    Append,
}

impl ConflictChoice {
    /// Translate the dialog selector into the
    /// [`ImportConflict`] policy that
    /// [`paladin_core::Vault::import_accounts`] consumes.
    #[must_use]
    pub fn into_policy(self) -> ImportConflict {
        match self {
            Self::Skip => ImportConflict::Skip,
            Self::Replace => ImportConflict::Replace,
            Self::Append => ImportConflict::Append,
        }
    }
}

/// Build an [`ImportOptions`] from the dialog state.
///
/// `paladin_passphrase` is taken verbatim; the helper does not
/// pre-filter on `format` because the importer facade itself ignores
/// the field for non-Paladin formats. Passing the
/// [`SecretString`] through unchanged means the caller's zeroize-on-
/// drop semantics survive across the move.
#[must_use]
pub fn build_import_options(
    format: FormatChoice,
    paladin_passphrase: Option<SecretString>,
) -> ImportOptions {
    ImportOptions {
        format: format.forced_format(),
        paladin_passphrase,
    }
}

/// Routing decision after the Paladin-header probe.
///
/// See [`classify_precheck`].
#[derive(Debug)]
pub enum PrecheckOutcome {
    /// `NoPrompt` — no Paladin-bundle passphrase needed. The dialog
    /// continues into [`paladin_core::import::from_file`] (the
    /// importer facade owns the typed format / I/O errors).
    Proceed,
    /// `PromptForPassphrase` — encrypted Paladin header detected.
    /// The dialog reveals the bundle-passphrase row before invoking
    /// the importer.
    PromptForPassphrase,
    /// `Reject(_)` — the typed core error surfaces inline; the
    /// dialog never invokes the importer or mutates the vault.
    InlineError(InlineError),
}

/// Map a [`paladin_core::classify_paladin_import_precheck`] result
/// onto the dialog's three-way routing decision.
#[must_use]
pub fn classify_precheck(probe: PaladinImportPrecheck) -> PrecheckOutcome {
    match probe {
        PaladinImportPrecheck::NoPrompt => PrecheckOutcome::Proceed,
        PaladinImportPrecheck::PromptForPassphrase => PrecheckOutcome::PromptForPassphrase,
        PaladinImportPrecheck::Reject(err) => {
            PrecheckOutcome::InlineError(InlineError::from_error(&err))
        }
    }
}

/// Return `true` iff a change of source path or forced format
/// requires clearing the bundle-passphrase row.
///
/// Per the plan §"ImportDialog": "If the source path or forced
/// format changes after a bundle passphrase has been entered, the
/// passphrase row is cleared and the probe / prompt flow starts
/// over." The helper takes raw [`Path`] equality and forced-format
/// equality — it does not attempt to canonicalize paths or pre-detect
/// formats, so a switch from auto-detect to an explicit format that
/// happens to match still resets the row (the probe must re-run).
#[must_use]
pub fn passphrase_needs_reset(
    prev_path: &Path,
    prev_forced: Option<ImportFormat>,
    new_path: &Path,
    new_forced: Option<ImportFormat>,
) -> bool {
    prev_path != new_path || prev_forced != new_forced
}

/// Post-merge counts projected from an [`ImportReport`].
///
/// The dialog renders the four merge totals plus the warning count
/// in its counts panel. Each [`paladin_core::ImportWarning`] is
/// formatted by the widget layer (the GTK label hosts the rendered
/// strings); the pure-logic projection carries the count so callers
/// can decide how many slots the panel needs without re-walking the
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeSummary {
    /// `imported` — source rows added as new accounts.
    pub imported: usize,
    /// `skipped` — source rows that collided under
    /// [`ImportConflict::Skip`].
    pub skipped: usize,
    /// `replaced` — source rows that overwrote an existing account
    /// under [`ImportConflict::Replace`].
    pub replaced: usize,
    /// `appended` — source rows appended as fresh accounts under
    /// [`ImportConflict::Append`].
    pub appended: usize,
    /// Count of [`paladin_core::ImportWarning`] entries collected
    /// before the merge policy was applied.
    pub warnings: usize,
}

impl MergeSummary {
    /// Project an [`ImportReport`] into a [`MergeSummary`].
    #[must_use]
    pub fn from_report(report: &ImportReport) -> Self {
        Self {
            imported: report.imported,
            skipped: report.skipped,
            replaced: report.replaced,
            appended: report.appended,
            warnings: report.warnings.len(),
        }
    }
}

/// Outcome of a [`paladin_core::Vault::mutate_and_save`] call wrapping
/// the importer + [`paladin_core::Vault::import_accounts`] closure.
///
/// See [`classify_merge_result`].
#[derive(Debug)]
pub enum MergeOutcome {
    /// `Ok(report)` — the merge committed to disk fully. The dialog
    /// renders the [`MergeSummary`] in its counts panel and clears
    /// any prior inline error.
    Success(MergeSummary),
    /// `save_not_committed` — the closure ran but the staging
    /// rename failed. Core already restored its pre-attempt
    /// snapshot, so no UI rollback is required; the dialog stays
    /// open with the typed inline error.
    NotCommitted(InlineError),
    /// `save_durability_unconfirmed` — the primary rename succeeded
    /// but the parent-directory `fsync` failed. Core kept the
    /// mutated state in memory, so the merged accounts are
    /// available; the dialog surfaces the warning inline so the user
    /// knows durability is unconfirmed.
    DurabilityWarning(InlineWarning),
    /// Any other typed error returned by the closure — importer
    /// errors (`unsupported_import_format`, `unsupported_plaintext_vault`,
    /// `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
    /// `validation_error`, `no_entries_to_import`, `decrypt_failed`,
    /// `invalid_header`, `invalid_payload`, `unsupported_format_version`,
    /// `kdf_params_out_of_bounds`, `io_error`) and defensive
    /// [`paladin_core::Vault::import_accounts`] errors. Vault state is
    /// unchanged because the error fired before the save path; the
    /// dialog stays inline.
    Inline(InlineError),
}

/// Classify the [`paladin_core::Vault::mutate_and_save`] result into
/// a [`MergeOutcome`].
///
/// The save-pipeline discriminators (`save_not_committed` →
/// [`MergeOutcome::NotCommitted`], `save_durability_unconfirmed` →
/// [`MergeOutcome::DurabilityWarning`]) are split out so the dialog
/// can label them appropriately for telemetry and wording; every
/// other typed variant falls through to [`MergeOutcome::Inline`].
#[must_use]
pub fn classify_merge_result(result: Result<ImportReport, PaladinError>) -> MergeOutcome {
    match result {
        Ok(report) => MergeOutcome::Success(MergeSummary::from_report(&report)),
        Err(err) => match err.kind() {
            ErrorKind::SaveNotCommitted => {
                MergeOutcome::NotCommitted(InlineError::from_error(&err))
            }
            ErrorKind::SaveDurabilityUnconfirmed => {
                MergeOutcome::DurabilityWarning(InlineWarning::from_error(&err))
            }
            _ => MergeOutcome::Inline(InlineError::from_error(&err)),
        },
    }
}

/// Inline-error projection for the `ImportDialog` body.
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

/// Durability-warning projection for the `ImportDialog` body.
///
/// Returned by [`classify_merge_result`] on
/// `save_durability_unconfirmed`: the merge committed to disk but
/// the parent-directory `fsync` failed, so the merged accounts stay
/// in memory while the warning sits beneath the counts panel.
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

/// Construction parameters for [`ImportDialogComponent`].
///
/// The dialog opens against the live vault so the merge worker that
/// lands in follow-up commits can call
/// `Vault::mutate_and_save(|v| { from_file(...) → v.import_accounts(...) })`
/// against the same on-disk file `AppModel` resolved at startup.
/// Cloned from `AppModel::state` at mount time so a mid-flight
/// passphrase-transition or lock cannot retarget the dialog.
#[derive(Debug, Clone)]
pub struct ImportDialogInit {
    /// Vault path the merge worker will target.
    pub vault_path: PathBuf,
}

/// Messages handled by [`ImportDialogComponent`].
///
/// This milestone scaffolds the read-only `adw::Dialog` mount; the
/// file-picker / format-selector / conflict-selector / bundle-
/// passphrase / submit / worker-result transitions described in
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" > `ImportDialog`
/// land in follow-up commits alongside the live-apply behavior. The
/// empty enum is the deliberate v0.2 starting point — relm4 requires
/// the associated `Input` type to exist even when no inbound messages
/// are wired yet.
#[derive(Debug)]
pub enum ImportDialogMsg {}

/// Messages emitted by [`ImportDialogComponent`] for `AppModel` to consume.
///
/// `AppModel` forwards these into `AppMsg::ImportDialogAction(...)`;
/// the dispatch arm drops the live `Controller<ImportDialogComponent>`
/// so the underlying `adw::Dialog` is torn down. Submit / merge-result
/// outputs that propagate the post-merge [`ImportReport`] (or typed
/// failure) to `AppModel` land in the same follow-up commits that add
/// the matching [`ImportDialogMsg`] variants.
#[derive(Debug, Clone)]
pub enum ImportDialogOutput {
    /// User dismissed the dialog (Close button / Escape / window
    /// close). `AppModel` responds by dropping the live controller
    /// so the dialog disappears and any in-flight pending form draft
    /// (selected source path, format / conflict choice, bundle
    /// passphrase entry) is discarded.
    Close,
}

/// Widget-bearing `adw::Dialog` for the application menu's Import… entry.
///
/// Mounts the libadwaita dialog described in DESIGN.md §7
/// (`ImportDialog`) and `IMPLEMENTATION_PLAN_04_GTK.md` §"Component
/// tree" > `ImportDialog`. The widget body is a read-only scaffold at
/// this milestone (an empty `adw::ToolbarView` wrapped in `adw::Dialog`
/// with the dialog title set), so the controller mounts cleanly under
/// `xvfb-run` without yet exposing the file picker, format / conflict
/// selectors, or bundle-passphrase row. Follow-up commits attach the
/// real form widgets and the
/// `Vault::mutate_and_save(|v| { from_file(...) → v.import_accounts(...) })`
/// worker that drives [`classify_merge_result`].
pub struct ImportDialogComponent {
    /// Vault path the dialog mounts against, kept on `self` so the
    /// follow-up merge worker can reach it without re-plumbing
    /// through every signal. The pure-logic round-trip is asserted
    /// by `tests/import_dialog_logic.rs`.
    #[allow(dead_code)]
    vault_path: PathBuf,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for ImportDialogComponent {
    type Init = ImportDialogInit;
    type Input = ImportDialogMsg;
    type Output = ImportDialogOutput;

    view! {
        #[root]
        adw::Dialog {
            set_title: "Import",

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {},
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        _sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = ImportDialogComponent {
            vault_path: init.vault_path,
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, _msg: Self::Input, _sender: ComponentSender<Self>) {
        // No inbound messages handled at this milestone — see
        // `ImportDialogMsg` doc comment for the upcoming file-picker /
        // format / conflict / passphrase / submit / worker-result
        // transitions.
    }
}
