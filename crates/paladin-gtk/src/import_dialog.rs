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
use std::time::SystemTime;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::prelude::*;

use paladin_core::{
    ErrorKind, ImportConflict, ImportFormat, ImportOptions, ImportReport, PaladinError,
    PaladinImportPrecheck, Store, Vault,
};
use secrecy::SecretString;

use crate::secret_fields::SecretEntry;

/// Format-selector choice surfaced by the `ImportDialog`'s segmented
/// control.
///
/// Maps to the [`paladin_core::ImportFormat`] consumed by
/// [`paladin_core::ImportOptions::format`] via
/// [`FormatChoice::forced_format`] — `None` for auto-detect, `Some(_)`
/// for the explicit choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FormatChoice {
    /// Auto-detect via [`paladin_core::import::detect`]. The
    /// [`Default`] of [`FormatChoice`] so the initial
    /// [`ImportDialogState`] opens on auto-detect, matching the CLI
    /// `paladin import` default.
    #[default]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictChoice {
    /// Keep the existing entry on collision; counts under `skipped`.
    /// The [`Default`] of [`ConflictChoice`] so the initial
    /// [`ImportDialogState`] opens on `Skip`, matching the CLI
    /// `paladin import --on-conflict=skip` default.
    #[default]
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
/// The dialog drives a small state machine through [`apply_msg`]:
/// file-picker selection ([`Self::SourcePathPicked`]) and format /
/// conflict / passphrase changes update [`ImportDialogState`]; the
/// Submit button ([`Self::SubmitClicked`]) emits an
/// [`ImportDialogOutput::Submit`] for `AppModel` to dispatch on
/// `gio::spawn_blocking`; the worker reports completion via
/// [`Self::SetBusy`] / [`Self::WorkerCompleted`] which renders the
/// counts panel, durability warning, or inline error per the §"Effect
/// errors" rules in `IMPLEMENTATION_PLAN_04_GTK.md`.
///
/// The `String` payload of [`Self::PassphraseChanged`] is the
/// unavoidable §8 UI boundary: the bytes arrive as a `GString` from
/// [`gtk::Editable::text`] and live transiently in the relm4 channel
/// before the handler shadows them into the [`SecretEntry`] inside
/// [`ImportDialogState`] (which zeroizes on drop).
#[derive(Debug)]
pub enum ImportDialogMsg {
    /// Cancel button activation. [`apply_msg`] forwards
    /// [`ImportDialogOutput::Cancel`] so `AppModel` can drop the live
    /// [`ImportDialogComponent`] controller.
    Cancel,
    /// Window-close / Escape / parent-navigation pathway distinct from
    /// the explicit Cancel button. `AppModel` drops the controller the
    /// same way it does on [`Self::Cancel`]; the variant stays distinct
    /// so `AppMsg::ImportDialogAction(...)` can keep an explicit
    /// per-source arm rather than relying on a `_` catch-all that
    /// would silently swallow a future Close-only behavior.
    Close,
    /// User picked a source file via [`gtk::FileDialog`]. The widget
    /// captures the chosen [`PathBuf`] and runs
    /// [`paladin_core::classify_paladin_import_precheck`] inline (cheap,
    /// no Argon2) so the dialog can route through [`classify_precheck`]
    /// on the same message.
    SourcePathPicked {
        /// Selected file path. Stored verbatim on
        /// [`ImportDialogState::source_path`].
        path: PathBuf,
        /// Paladin-header probe against `path` under the current
        /// forced format. Drives the [`PrecheckOutcome::PromptForPassphrase`]
        /// reveal and the [`PrecheckOutcome::InlineError`] inline-error
        /// surface.
        precheck: PaladinImportPrecheck,
    },
    /// User changed the format selector. The widget re-runs
    /// [`paladin_core::classify_paladin_import_precheck`] against the
    /// current source path so the dialog can refresh the precheck
    /// outcome under the new forced format.
    FormatChanged {
        /// New format choice.
        format: FormatChoice,
        /// Paladin-header probe against the current source path under
        /// the new forced format. `PaladinImportPrecheck::NoPrompt` is
        /// used when no source path is selected yet.
        precheck: PaladinImportPrecheck,
    },
    /// User changed the on-conflict selector. Pure state update — the
    /// conflict policy threads through [`paladin_core::Vault::import_accounts`]
    /// at submit time, not at selection time.
    ConflictChanged(ConflictChoice),
    /// Per-keystroke shadow of the bundle-passphrase entry. The widget's
    /// `connect_changed` signal forwards the live entry text. [`apply_msg`]
    /// routes through [`ImportDialogState::set_passphrase`], which both
    /// shadows the buffer into the zeroizing [`SecretEntry`] and dismisses
    /// any prior inline error so the next attempt starts clean.
    PassphraseChanged(String),
    /// Submit button activation. [`apply_msg`] runs
    /// [`compose_submit_outcome`] against the current state and emits
    /// [`ImportDialogOutput::Submit`] iff the outcome is
    /// [`SubmitOutcome::Proceed`]. Other outcomes either leave the
    /// dialog untouched (button should not have been enabled) or
    /// stage an inline error.
    SubmitClicked,
    /// `AppModel` pushes the busy latch back to the dialog after it
    /// has moved the `(Vault, Store)` pair into the
    /// `gio::spawn_blocking` worker. The dialog disables the submit
    /// button and shows a spinner until [`Self::WorkerCompleted`]
    /// resets the latch.
    SetBusy(bool),
    /// `AppModel` pushes the typed [`MergeOutcome`] back to the dialog
    /// after the worker reports completion. [`apply_msg`] routes
    /// through [`ImportDialogState::apply_merge_outcome`], which lifts
    /// busy, populates the merge summary (on success), or stages the
    /// inline error / warning per the §"Effect errors" rules.
    WorkerCompleted(MergeOutcome),
    /// User dismissed the post-success counts panel. [`apply_msg`]
    /// forwards [`ImportDialogOutput::Close`] so `AppModel` drops the
    /// controller.
    DismissCounts,
}

/// Messages emitted by [`ImportDialogComponent`] for `AppModel` to consume.
///
/// `AppModel` forwards these into `AppMsg::ImportDialogAction(...)`;
/// [`Self::Cancel`] and [`Self::Close`] drop the live
/// `Controller<ImportDialogComponent>` so the underlying `adw::Dialog`
/// is torn down; [`Self::Submit`] hands the
/// validated payload to the `gio::spawn_blocking` worker without
/// closing the dialog (the dialog stays mounted until the worker
/// returns and the user dismisses the counts panel or cancels the
/// inline-error retry).
///
/// `Submit` is not `Clone` because [`ImportSubmitPayload::options`]
/// carries a [`secrecy::SecretString`] that is intentionally non-
/// `Clone`: the bundle passphrase moves once into the worker and is
/// zeroized on drop.
#[derive(Debug)]
pub enum ImportDialogOutput {
    /// Explicit Cancel button activation. `AppModel` responds by
    /// dropping the live controller so the dialog disappears and any
    /// in-flight pending form draft (selected source path, format /
    /// conflict choice, bundle passphrase entry) is discarded.
    Cancel,
    /// User dismissed the dialog (Close / Escape / window-close /
    /// post-success Dismiss). `AppModel` drops the controller the
    /// same way it does on [`Self::Cancel`]; the variant stays
    /// distinct so future Close-only behavior (e.g. a "Discard
    /// draft?" prompt) can attach to one dispatch arm without
    /// affecting Cancel.
    Close,
    /// Submit button activation with a validated [`ImportSubmitPayload`].
    /// `AppModel` hands the payload to its `gio::spawn_blocking`
    /// worker that runs
    /// `Vault::mutate_and_save(|v| { from_file(...) -> v.import_accounts(...) })`
    /// (the encrypted-Paladin variant runs Argon2id; keep it off the
    /// main loop).
    Submit(ImportSubmitPayload),
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
    /// Form-draft state machine driven by [`apply_msg`]. Holds the
    /// selected source path, format / conflict choices, latest
    /// precheck outcome, the zeroizing bundle-passphrase
    /// [`SecretEntry`], busy latch, and post-worker rendering slots
    /// (merge summary, inline error, inline warning). The widget
    /// view (lands in a follow-up commit) reads this via
    /// `compose_*` helpers.
    #[allow(dead_code)]
    state: ImportDialogState,
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
            state: ImportDialogState::new(),
        };
        let widgets = view_output!();
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

/// Validated submit payload forwarded to `AppModel` via
/// [`ImportDialogOutput::Submit`].
///
/// `AppModel` consumes the payload exactly once: it moves
/// `(source_path, options, conflict, import_time)` into the
/// `gio::spawn_blocking` worker built around
/// `Vault::mutate_and_save(|v| { from_file(...) -> v.import_accounts(...) })`.
/// The dialog stays mounted during the worker round trip — the
/// payload is consumed but the [`ImportDialogState`] still owns the
/// form draft so the user can see what was submitted while the
/// worker runs.
///
/// `Clone` is deliberately not derived: [`ImportOptions::paladin_passphrase`]
/// is a [`secrecy::SecretString`] which is intentionally non-`Clone`
/// — the cleartext bytes must move once into the worker and zeroize
/// on drop.
#[derive(Debug)]
pub struct ImportSubmitPayload {
    /// User-selected source file path. The worker passes it to
    /// [`paladin_core::import::from_file`] which handles format
    /// detection via [`paladin_core::import::detect`] when
    /// [`ImportOptions::format`] is `None`.
    pub source_path: PathBuf,
    /// Format + bundle-passphrase bundle ready for
    /// [`paladin_core::import::from_file`]. The widget builds it
    /// through [`build_import_options`] so the format-selector
    /// routing stays in one helper.
    pub options: ImportOptions,
    /// On-conflict policy threaded into
    /// [`paladin_core::Vault::import_accounts`]. Built via
    /// [`ConflictChoice::into_policy`].
    pub conflict: ImportConflict,
}

/// Routing decision after a Submit click against the current
/// [`ImportDialogState`].
///
/// See [`compose_submit_outcome`]. The widget consumes a
/// [`SubmitOutcome::Proceed`] by forwarding [`ImportDialogOutput::Submit`]
/// to `AppModel`; the other variants either no-op (button should
/// have been disabled) or stage an inline error.
#[derive(Debug)]
pub enum SubmitOutcome {
    /// No source file selected yet. The Submit button should have
    /// been disabled by [`compose_submit_button_sensitive`].
    NeedsSourcePath,
    /// Latest [`PrecheckOutcome`] is missing — the widget has not
    /// completed the Paladin-header probe for the current
    /// `(source_path, forced_format)` pair yet.
    AwaitingPrecheck,
    /// Bundle passphrase is required but the entry buffer is empty.
    AwaitingPassphrase,
    /// Submission is ready. The carried [`ImportSubmitPayload`] is
    /// the same value the widget should forward through
    /// [`ImportDialogOutput::Submit`].
    Proceed(ImportSubmitPayload),
    /// The precheck staged an inline error (e.g. malformed Paladin
    /// header under explicit `format = Paladin`). The widget should
    /// keep the inline error visible and not start a worker.
    Rejected(InlineError),
}

/// Pure-logic state machine for `ImportDialogComponent`.
///
/// Owns the source-path / format / conflict / passphrase form draft,
/// the latest [`PrecheckOutcome`] from
/// [`paladin_core::classify_paladin_import_precheck`], the busy
/// latch, and the post-worker rendering slots (merge summary,
/// inline error, inline warning). The widget layer drives this via
/// [`apply_msg`] and reads it via the `compose_*` helpers — the
/// state owns no widgets so it stays unit-testable in
/// `tests/import_dialog_logic.rs`.
///
/// Not `Debug` because [`SecretEntry`] deliberately opts out of
/// `Debug` so a stray `dbg!` cannot leak the bundle passphrase
/// through the error log. Not `Clone` for the same reason — the
/// zeroizing buffer must not be duplicated.
#[derive(Default)]
pub struct ImportDialogState {
    source_path: Option<PathBuf>,
    format: FormatChoice,
    conflict: ConflictChoice,
    /// Latest [`classify_precheck`] result. `None` until the user
    /// picks a source path. Refreshed on every
    /// [`ImportDialogMsg::SourcePathPicked`] and
    /// [`ImportDialogMsg::FormatChanged`] so the passphrase row
    /// visibility tracks the current `(source_path, forced_format)`
    /// pair.
    precheck_outcome: Option<PrecheckOutcome>,
    /// Bundle passphrase entry buffer. Inner [`Zeroizing<String>`]
    /// zeroes on drop / clear; the buffer is cleared whenever the
    /// source path or forced format changes per the §"`ImportDialog`"
    /// reset rule.
    passphrase: SecretEntry,
    inline_error: Option<InlineError>,
    inline_warning: Option<InlineWarning>,
    merge_summary: Option<MergeSummary>,
    busy: bool,
}

impl ImportDialogState {
    /// Construct a fresh state — equivalent to `Self::default()`.
    /// `format` defaults to [`FormatChoice::AutoDetect`] and
    /// `conflict` defaults to [`ConflictChoice::Skip`] per the CLI /
    /// TUI add-modal defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Currently selected source-file path, if any.
    #[must_use]
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    /// Currently selected format choice.
    #[must_use]
    pub fn format(&self) -> FormatChoice {
        self.format
    }

    /// Currently selected on-conflict policy.
    #[must_use]
    pub fn conflict(&self) -> ConflictChoice {
        self.conflict
    }

    /// Most recent precheck routing decision.
    #[must_use]
    pub fn precheck_outcome(&self) -> Option<&PrecheckOutcome> {
        self.precheck_outcome.as_ref()
    }

    /// Current bundle-passphrase entry text. Empty when no passphrase
    /// is required or the user has not yet typed.
    #[must_use]
    pub fn passphrase_text(&self) -> &str {
        self.passphrase.text()
    }

    /// `true` iff [`Self::precheck_outcome`] is
    /// [`PrecheckOutcome::PromptForPassphrase`]. The widget binds the
    /// bundle-passphrase row visibility to this getter.
    #[must_use]
    pub fn passphrase_visible(&self) -> bool {
        matches!(
            self.precheck_outcome,
            Some(PrecheckOutcome::PromptForPassphrase)
        )
    }

    /// `true` iff a worker is in flight against this dialog. Mirrors
    /// the `Unlocked → UnlockedBusy` window owned by `AppModel`.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Latest staged inline error, if any.
    #[must_use]
    pub fn inline_error(&self) -> Option<&InlineError> {
        self.inline_error.as_ref()
    }

    /// Latest staged durability warning, if any.
    #[must_use]
    pub fn inline_warning(&self) -> Option<&InlineWarning> {
        self.inline_warning.as_ref()
    }

    /// Latest post-success counts panel, if any.
    #[must_use]
    pub fn merge_summary(&self) -> Option<&MergeSummary> {
        self.merge_summary.as_ref()
    }

    /// Update the source path and refresh the precheck routing. If
    /// the path differs from the prior value, the bundle-passphrase
    /// entry is cleared per the §"`ImportDialog`" reset rule and any
    /// prior inline error is dismissed so the user starts the new
    /// `(path, forced_format)` probe with a clean slate.
    pub fn set_source_path(&mut self, path: PathBuf, precheck: PaladinImportPrecheck) {
        let needs_reset = match self.source_path.as_deref() {
            Some(prev) => passphrase_needs_reset(
                prev,
                self.format.forced_format(),
                &path,
                self.format.forced_format(),
            ),
            None => true,
        };
        if needs_reset {
            self.passphrase = SecretEntry::new();
        }
        self.source_path = Some(path);
        self.precheck_outcome = Some(classify_precheck(precheck));
        self.refresh_inline_error_from_precheck();
    }

    /// Update the forced-format choice and refresh the precheck
    /// routing under the new format. The bundle-passphrase entry is
    /// cleared when the forced format changes (the probe must re-run
    /// even if the new format happens to match the prior one's
    /// auto-detect result). Any prior inline error from a previous
    /// precheck is dismissed.
    pub fn set_format(&mut self, format: FormatChoice, precheck: PaladinImportPrecheck) {
        let prev_forced = self.format.forced_format();
        let new_forced = format.forced_format();
        let path_for_reset: &Path = self.source_path.as_deref().unwrap_or(Path::new(""));
        if passphrase_needs_reset(path_for_reset, prev_forced, path_for_reset, new_forced) {
            self.passphrase = SecretEntry::new();
        }
        self.format = format;
        self.precheck_outcome = Some(classify_precheck(precheck));
        self.refresh_inline_error_from_precheck();
    }

    /// Update the on-conflict policy. No precheck or passphrase reset
    /// needed — conflict policy only threads through
    /// [`paladin_core::Vault::import_accounts`] at submit time.
    pub fn set_conflict(&mut self, conflict: ConflictChoice) {
        self.conflict = conflict;
    }

    /// Shadow the bundle-passphrase entry buffer with `text`. The
    /// prior buffer zeroes in place when the temporary
    /// [`Zeroizing<String>`] inside [`SecretEntry`] drops. The first
    /// keystroke after a worker error dismisses the inline error so
    /// the entry never carries a stale error into the next attempt.
    pub fn set_passphrase(&mut self, text: &str) {
        self.passphrase.set(text);
        self.inline_error = None;
    }

    /// Toggle the busy latch. Flipped to `true` by `AppModel` when it
    /// moves the `(Vault, Store)` pair into the worker and to `false`
    /// by [`ImportDialogMsg::WorkerCompleted`] (`apply_merge_outcome`
    /// does the same internally).
    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
    }

    /// Apply a [`MergeOutcome`] from the worker. Lifts busy, then
    /// populates the matching rendering slot:
    ///
    /// * `Success(summary)` → stage `merge_summary`, clear any
    ///   prior inline error / warning so the counts panel is
    ///   uncluttered.
    /// * `DurabilityWarning(warning)` → stage `inline_warning`,
    ///   clear merge summary and any prior inline error. The merged
    ///   accounts stay in memory per §4.3 — `mutate_and_save` kept
    ///   the post-mutation state.
    /// * `NotCommitted(err)` → stage `inline_error`, clear merge
    ///   summary and inline warning. Core has already restored its
    ///   pre-attempt snapshot, so no in-UI rollback is needed.
    /// * `Inline(err)` → stage `inline_error`, clear merge summary
    ///   and inline warning. Vault state is unchanged (the error
    ///   fired before the save path).
    pub fn apply_merge_outcome(&mut self, outcome: MergeOutcome) {
        self.busy = false;
        match outcome {
            MergeOutcome::Success(summary) => {
                self.merge_summary = Some(summary);
                self.inline_error = None;
                self.inline_warning = None;
            }
            MergeOutcome::DurabilityWarning(warning) => {
                self.inline_warning = Some(warning);
                self.merge_summary = None;
                self.inline_error = None;
            }
            MergeOutcome::NotCommitted(err) | MergeOutcome::Inline(err) => {
                self.inline_error = Some(err);
                self.merge_summary = None;
                self.inline_warning = None;
            }
        }
    }

    /// Drain the post-success counts panel. Called from
    /// [`ImportDialogMsg::DismissCounts`] before the dialog forwards
    /// [`ImportDialogOutput::Close`].
    pub fn dismiss_counts(&mut self) {
        self.merge_summary = None;
    }

    /// Internal helper: lift the inline error from the current
    /// precheck outcome (`PrecheckOutcome::InlineError`) into
    /// `self.inline_error`. Non-error precheck outcomes do not
    /// auto-clear `inline_error` here, since a prior worker failure
    /// may have staged an inline error that should survive a benign
    /// format / path refresh.
    fn refresh_inline_error_from_precheck(&mut self) {
        if let Some(PrecheckOutcome::InlineError(err)) = self.precheck_outcome.as_ref() {
            self.inline_error = Some(err.clone());
        }
    }
}

/// Apply an inbound [`ImportDialogMsg`] to `state` and return the
/// optional [`ImportDialogOutput`] the widget layer should forward
/// to `AppModel`.
///
/// Pulled out of [`ImportDialogComponent::update`] so the routing
/// stays unit-testable in `tests/import_dialog_logic.rs` without
/// spinning up GTK.
pub fn apply_msg(
    state: &mut ImportDialogState,
    msg: ImportDialogMsg,
) -> Option<ImportDialogOutput> {
    match msg {
        ImportDialogMsg::Cancel => Some(ImportDialogOutput::Cancel),
        ImportDialogMsg::Close => Some(ImportDialogOutput::Close),
        ImportDialogMsg::SourcePathPicked { path, precheck } => {
            state.set_source_path(path, precheck);
            None
        }
        ImportDialogMsg::FormatChanged { format, precheck } => {
            state.set_format(format, precheck);
            None
        }
        ImportDialogMsg::ConflictChanged(conflict) => {
            state.set_conflict(conflict);
            None
        }
        ImportDialogMsg::PassphraseChanged(text) => {
            state.set_passphrase(&text);
            None
        }
        ImportDialogMsg::SubmitClicked => match compose_submit_outcome(state) {
            SubmitOutcome::Proceed(payload) => {
                state.set_busy(true);
                state.inline_error = None;
                state.inline_warning = None;
                state.merge_summary = None;
                Some(ImportDialogOutput::Submit(payload))
            }
            SubmitOutcome::Rejected(err) => {
                state.inline_error = Some(err);
                None
            }
            SubmitOutcome::NeedsSourcePath
            | SubmitOutcome::AwaitingPrecheck
            | SubmitOutcome::AwaitingPassphrase => {
                // Defensive: the Submit button should have been
                // disabled by `compose_submit_button_sensitive`.
                None
            }
        },
        ImportDialogMsg::SetBusy(busy) => {
            state.set_busy(busy);
            None
        }
        ImportDialogMsg::WorkerCompleted(outcome) => {
            state.apply_merge_outcome(outcome);
            None
        }
        ImportDialogMsg::DismissCounts => {
            state.dismiss_counts();
            Some(ImportDialogOutput::Close)
        }
    }
}

/// Classify the current [`ImportDialogState`] into a Submit-button
/// routing decision.
///
/// The widget's Submit handler calls this on click. The decision
/// table:
///
/// * `source_path = None` → [`SubmitOutcome::NeedsSourcePath`].
/// * `precheck_outcome = None` → [`SubmitOutcome::AwaitingPrecheck`]
///   (the widget has not finished the probe; rare in practice
///   because the widget runs the precheck inline on `SourcePathPicked`).
/// * `precheck_outcome = InlineError(err)` →
///   [`SubmitOutcome::Rejected`] carrying the same `err` so the
///   dialog can re-stage it inline.
/// * `precheck_outcome = PromptForPassphrase` and the entry buffer
///   is empty → [`SubmitOutcome::AwaitingPassphrase`].
/// * Otherwise → [`SubmitOutcome::Proceed`] carrying the built
///   [`ImportSubmitPayload`].
#[must_use]
pub fn compose_submit_outcome(state: &ImportDialogState) -> SubmitOutcome {
    let Some(path) = state.source_path.clone() else {
        return SubmitOutcome::NeedsSourcePath;
    };
    let Some(outcome) = state.precheck_outcome.as_ref() else {
        return SubmitOutcome::AwaitingPrecheck;
    };
    match outcome {
        PrecheckOutcome::InlineError(err) => SubmitOutcome::Rejected(err.clone()),
        PrecheckOutcome::PromptForPassphrase if state.passphrase.text().is_empty() => {
            SubmitOutcome::AwaitingPassphrase
        }
        PrecheckOutcome::PromptForPassphrase => {
            let secret = SecretString::from(state.passphrase.text().to_string());
            let options = build_import_options(state.format, Some(secret));
            SubmitOutcome::Proceed(ImportSubmitPayload {
                source_path: path,
                options,
                conflict: state.conflict.into_policy(),
            })
        }
        PrecheckOutcome::Proceed => {
            let options = build_import_options(state.format, None);
            SubmitOutcome::Proceed(ImportSubmitPayload {
                source_path: path,
                options,
                conflict: state.conflict.into_policy(),
            })
        }
    }
}

/// Submit-button sensitivity binding. Disabled while busy and when
/// the form is not ready ([`compose_submit_outcome`] would not
/// return `Proceed`).
#[must_use]
pub fn compose_submit_button_sensitive(state: &ImportDialogState) -> bool {
    if state.is_busy() {
        return false;
    }
    matches!(compose_submit_outcome(state), SubmitOutcome::Proceed(_))
}

/// Visibility binding for the bundle-passphrase row. The widget
/// reveals the row iff the precheck routing requested a prompt.
#[must_use]
pub fn compose_passphrase_row_visible(state: &ImportDialogState) -> bool {
    state.passphrase_visible()
}

/// Visibility binding for the post-success counts panel.
#[must_use]
pub fn compose_counts_panel_visible(state: &ImportDialogState) -> bool {
    state.merge_summary().is_some()
}

/// Imported-count label for the counts panel; `None` when the panel
/// is hidden.
#[must_use]
pub fn compose_counts_panel_imported_label(state: &ImportDialogState) -> Option<String> {
    state
        .merge_summary()
        .map(|s| format!("Imported: {}", s.imported))
}

/// Skipped-count label for the counts panel; `None` when the panel
/// is hidden.
#[must_use]
pub fn compose_counts_panel_skipped_label(state: &ImportDialogState) -> Option<String> {
    state
        .merge_summary()
        .map(|s| format!("Skipped: {}", s.skipped))
}

/// Replaced-count label for the counts panel; `None` when the panel
/// is hidden.
#[must_use]
pub fn compose_counts_panel_replaced_label(state: &ImportDialogState) -> Option<String> {
    state
        .merge_summary()
        .map(|s| format!("Replaced: {}", s.replaced))
}

/// Appended-count label for the counts panel; `None` when the panel
/// is hidden.
#[must_use]
pub fn compose_counts_panel_appended_label(state: &ImportDialogState) -> Option<String> {
    state
        .merge_summary()
        .map(|s| format!("Appended: {}", s.appended))
}

/// Warning-count label for the counts panel; `None` when the panel
/// is hidden.
#[must_use]
pub fn compose_counts_panel_warnings_label(state: &ImportDialogState) -> Option<String> {
    state
        .merge_summary()
        .map(|s| format!("Warnings: {}", s.warnings))
}

/// Visibility binding for the inline-error revealer.
#[must_use]
pub fn compose_inline_error_revealed(state: &ImportDialogState) -> bool {
    state.inline_error().is_some()
}

/// Inline-error body for the revealer; `None` when no error is staged.
#[must_use]
pub fn compose_inline_error_body(state: &ImportDialogState) -> Option<&str> {
    state.inline_error().map(|e| e.rendered.as_str())
}

/// Visibility binding for the inline-warning revealer.
#[must_use]
pub fn compose_inline_warning_revealed(state: &ImportDialogState) -> bool {
    state.inline_warning().is_some()
}

/// Inline-warning body for the revealer; `None` when no warning is
/// staged.
#[must_use]
pub fn compose_inline_warning_body(state: &ImportDialogState) -> Option<&str> {
    state.inline_warning().map(|w| w.rendered.as_str())
}

/// Input bundle for [`run_import_worker`].
///
/// Built by `AppModel` from
/// [`ImportDialogOutput::Submit`] (or
/// [`crate::app::state::compose_import_worker_input`] once the
/// dispatch site lands) and consumed exactly once by the
/// `gio::spawn_blocking` worker. The live `(Vault, Store)` pair is
/// moved into the worker so `mutate_and_save` can borrow it mutably
/// without keeping `AppModel` in `Unlocked` for the duration of the
/// save call; the pair is returned through
/// [`ImportWorkerCompletion`] regardless of typed outcome.
///
/// `Clone` / `PartialEq` are deliberately not derived: [`Store`]
/// holds non-`Clone` filesystem state, [`ImportOptions::paladin_passphrase`]
/// is a [`secrecy::SecretString`] that zeroizes on drop, and
/// `AppModel::update` consumes the input exactly once when it moves
/// it into the closure.
#[derive(Debug)]
pub struct ImportWorkerInput {
    /// Live vault from the `Unlocked` `(Vault, Store)` pair.
    pub vault: Vault,
    /// Live store from the `Unlocked` `(Vault, Store)` pair.
    pub store: Store,
    /// User-selected source file path.
    pub source_path: PathBuf,
    /// Format + bundle-passphrase bundle for
    /// [`paladin_core::import::from_file`].
    pub options: ImportOptions,
    /// On-conflict policy threaded into
    /// [`paladin_core::Vault::import_accounts`].
    pub conflict: ImportConflict,
    /// `import_time` stamp captured at submit time. Passes through
    /// to both [`paladin_core::import::from_file`] (for
    /// `created_at` / `updated_at` on the per-row
    /// [`paladin_core::ValidatedAccount`]) and
    /// [`paladin_core::Vault::import_accounts`] (for the merge-time
    /// `updated_at` bump on the replaced rows).
    pub import_time: SystemTime,
}

/// Bundle returned by [`run_import_worker`].
///
/// Carries the live `(Vault, Store)` pair on every branch so
/// `AppModel::update` can reinstall it before applying the UI
/// outcome — [`paladin_core::Vault::mutate_and_save`] already
/// restores the snapshot on `save_not_committed`, so the returned
/// vault is the authoritative post-effect state regardless of the
/// [`MergeOutcome`] variant. Per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction" > "Every
/// worker returns `(Vault, Store, EffectOutcome)`".
#[derive(Debug)]
pub struct ImportWorkerCompletion {
    /// Routed outcome for `AppModel::update` to push back through
    /// [`ImportDialogMsg::WorkerCompleted`].
    pub outcome: MergeOutcome,
    /// Live vault after the `mutate_and_save` call. On success the
    /// merged accounts are present; on `save_not_committed` the
    /// vault is the pre-attempt snapshot; on
    /// `save_durability_unconfirmed` the post-merge state is
    /// preserved.
    pub vault: Vault,
    /// Live store moved through unchanged.
    pub store: Store,
}

/// Synchronous body of the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| { from_file(...) -> v.import_accounts(...) })`
/// import worker fired by `AppModel::update` from
/// `AppMsg::ImportDialogAction(ImportDialogOutput::Submit(payload))`.
///
/// Consumes the [`ImportWorkerInput`] by value, runs the importer +
/// merge inside [`paladin_core::Vault::mutate_and_save`], and
/// bundles the outcome into an [`ImportWorkerCompletion`] via
/// [`classify_merge_result`]. The live `(Vault, Store)` pair is
/// always returned so `AppModel` reinstalls it regardless of the
/// typed outcome — `mutate_and_save` is authoritative for the
/// rollback / durability-unconfirmed semantics per DESIGN.md §4.3.
pub fn run_import_worker(input: ImportWorkerInput) -> ImportWorkerCompletion {
    let ImportWorkerInput {
        mut vault,
        store,
        source_path,
        options,
        conflict,
        import_time,
    } = input;
    let result: Result<ImportReport, PaladinError> = vault.mutate_and_save(&store, move |v| {
        let accounts = paladin_core::import::from_file(&source_path, options, import_time)?;
        v.import_accounts(accounts, conflict, import_time)
    });
    ImportWorkerCompletion {
        outcome: classify_merge_result(result),
        vault,
        store,
    }
}
