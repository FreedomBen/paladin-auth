// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rename-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" > Rename
//! dialog and §"Effect errors" > "Add / remove / rename / settings
//! saves", `RenameDialog` edits the label of an existing account
//! and routes the worker outcome of
//! `Vault::mutate_and_save(|v| v.rename(id, label, now))` back into
//! either a successful commit, a pre-commit rollback, or a durability-
//! warning surface. The widget layer hosts an [`adw::EntryRow`] for
//! the label and a non-editable issuer display (CLI parity with
//! `paladin rename <new-label>`); the pure-logic helpers here own
//! the validation and post-effect routing decisions so they can be
//! unit-tested in `tests/rename_dialog_logic.rs` without spinning up
//! GTK / libadwaita.
//!
//! # Pre-submit validation
//!
//! [`classify_submit`] re-runs [`paladin_core::validate_label`] on
//! the draft text. Empty / overlong inputs surface as inline errors
//! with the §5 `validation_error` discriminator and the typed body
//! text; the dialog stays open until the user fixes the input.
//!
//! # Same-label submission
//!
//! [`classify_submit`] takes only the draft label. There is no
//! prior-label comparison and therefore no silent short-circuit, so
//! re-submitting an unchanged label still goes through
//! `Vault::rename` inside `Vault::mutate_and_save` and bumps
//! `updated_at`, matching the CLI `paladin rename` contract.
//!
//! # Post-effect routing
//!
//! [`classify_rename_error`] maps the [`PaladinError`] from a failed
//! `mutate_and_save` onto the dialog's three-way routing decision:
//!
//! * `save_not_committed` → [`RenameErrorOutcome::RestorePrior`]
//!   (commit never landed; the dialog rolls the visible label back to
//!   the pre-submit value and shows the typed inline error).
//! * `save_durability_unconfirmed` →
//!   [`RenameErrorOutcome::KeepNewWithWarning`] (commit landed but
//!   parent-fsync failed; the visible label stays on the new value
//!   and a warning attaches to the dialog body).
//! * Anything else (defensive: `validation_error`, `invalid_state`,
//!   …) → [`RenameErrorOutcome::InlineError`] without transitioning
//!   out of the dialog.

use std::time::SystemTime;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use paladin_core::{validate_label, AccountId, ErrorKind, PaladinError, Store, Vault};

use crate::account_row::display_label;

/// Pre-submit validation outcome.
///
/// See [`classify_submit`].
#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    /// Validated, trimmed label ready for the rename worker. The
    /// dialog hands this through `Vault::mutate_and_save` so
    /// `updated_at` always bumps — see the same-label note in the
    /// module docs.
    Proceed(String),
    /// §4.1 validation failed. The dialog stays open and renders the
    /// inline error in the label-field error area.
    InlineError(InlineError),
}

/// Pre-submit validate the raw label entry. Trims whitespace,
/// rejects empty / overlong (§4.1 / §5 `validation_error`) inline.
///
/// The helper takes only the draft — there is no prior-label
/// comparison and therefore no silent short-circuit. The widget
/// layer always emits the rename effect on [`SubmitOutcome::Proceed`]
/// so `Vault::rename` bumps `updated_at` even on a no-op rename.
#[must_use]
pub fn classify_submit(raw_label: &str) -> SubmitOutcome {
    match validate_label(raw_label) {
        Ok(trimmed) => SubmitOutcome::Proceed(trimmed),
        Err(err) => SubmitOutcome::InlineError(InlineError::from_error(&err)),
    }
}

/// Post-effect routing decision for a failed
/// `Vault::mutate_and_save(|v| v.rename(...))`.
///
/// See [`classify_rename_error`].
#[derive(Debug, Clone)]
pub enum RenameErrorOutcome {
    /// `save_not_committed` — the rename never committed to disk.
    /// The dialog rolls the visible label back to the pre-submit
    /// value and shows the typed inline error.
    RestorePrior(InlineError),
    /// `save_durability_unconfirmed` — primary rename succeeded but
    /// parent-fsync failed. The visible label stays on the new value
    /// and the warning attaches to the dialog body.
    KeepNewWithWarning(InlineWarning),
    /// Defensive: any other typed error stays inline and does not
    /// transition the dialog out. Hits `validation_error` only if
    /// the widget layer bypasses [`classify_submit`], and
    /// `invalid_state { state: "account_not_found" }` only if the
    /// targeted account is removed mid-flight.
    InlineError(InlineError),
}

/// Classify a [`Vault::mutate_and_save`] failure into a
/// [`RenameErrorOutcome`].
///
/// Routes the §5 save-pipeline discriminators (`save_not_committed`
/// → [`RenameErrorOutcome::RestorePrior`],
/// `save_durability_unconfirmed` →
/// [`RenameErrorOutcome::KeepNewWithWarning`]) and falls back to an
/// inline error for every other typed variant so the dialog never
/// silently transitions out.
#[must_use]
pub fn classify_rename_error(err: &PaladinError) -> RenameErrorOutcome {
    match err.kind() {
        ErrorKind::SaveNotCommitted => {
            RenameErrorOutcome::RestorePrior(InlineError::from_error(err))
        }
        ErrorKind::SaveDurabilityUnconfirmed => {
            RenameErrorOutcome::KeepNewWithWarning(InlineWarning::from_error(err))
        }
        _ => RenameErrorOutcome::InlineError(InlineError::from_error(err)),
    }
}

/// Inputs consumed by [`run_rename_worker`] when `AppModel::update`
/// fires the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.rename(...))` worker.
///
/// The live `(Vault, Store)` pair is moved by value into the worker
/// closure so the busy gate can re-install whichever pair the worker
/// returns — success, durability-unconfirmed, or pre-commit
/// rollback. The targeted [`AccountId`] and the trimmed label come
/// off [`RenameDialogOutput::SubmitLabel`]; `now` is captured at the
/// dispatch site so the test surface can pin a deterministic
/// timestamp.
///
/// `Clone` / `PartialEq` are deliberately not derived: [`Store`]
/// holds non-`Clone` filesystem state, and `AppModel::update`
/// consumes the input exactly once when it moves it into the
/// `gio::spawn_blocking` closure.
#[derive(Debug)]
pub struct RenameWorkerInput {
    /// Live vault from the `Unlocked` `(Vault, Store)` pair. Moved
    /// into the worker so `mutate_and_save` can borrow it mutably
    /// without keeping `AppModel` in `Unlocked` for the duration of
    /// the open call.
    pub vault: Vault,
    /// Live store from the `Unlocked` `(Vault, Store)` pair. Moved
    /// alongside `vault` so the same `(Vault, Store)` pair returns
    /// from the worker even on typed failure.
    pub store: Store,
    /// Stable account id from
    /// [`RenameDialogOutput::SubmitLabel::account_id`]. Forwarded to
    /// `Vault::rename` so the worker targets the same account the
    /// dialog seeded.
    pub account_id: AccountId,
    /// Canonical trimmed label from
    /// [`RenameDialogOutput::SubmitLabel::label`]. Passed to
    /// `Vault::rename` which re-runs `validate_label` — a defensive
    /// validation failure here is treated as
    /// [`RenameErrorOutcome::InlineError`] so the dialog stays open.
    pub label: String,
    /// Wall-clock the worker hands to `Vault::rename` as the new
    /// `updated_at`. `AppModel::update` captures `SystemTime::now()`
    /// at the dispatch site so the worker thread does not race
    /// against later wall-clock drift.
    pub now: SystemTime,
}

/// Outcome of [`run_rename_worker`] for `AppModel::update` to apply.
///
/// `Success` indicates the rename committed and the visible label
/// stays on the new value. `Failure` wraps the [`RenameErrorOutcome`]
/// from [`classify_rename_error`] so the dialog can re-render the
/// matching inline error / durability warning without re-deriving
/// the routing decision off the [`PaladinError`].
#[derive(Debug, Clone)]
pub enum RenameWorkerEffect {
    /// `Vault::mutate_and_save(|v| v.rename(...))` returned `Ok(())`.
    /// The dialog dismisses itself and the visible row label updates
    /// to the new value.
    Success,
    /// `Vault::mutate_and_save(|v| v.rename(...))` returned a typed
    /// failure. The carried [`RenameErrorOutcome`] tells the dialog
    /// whether to restore the prior label (`save_not_committed`),
    /// keep the new label with a warning attached
    /// (`save_durability_unconfirmed`), or stay inline with the typed
    /// error (defensive `validation_error` / `invalid_state` / …).
    Failure(RenameErrorOutcome),
}

/// Bundle returned by [`run_rename_worker`].
///
/// Carries the live `(Vault, Store)` pair on every branch so
/// `AppModel::update` can reinstall it before applying the UI
/// outcome — `Vault::mutate_and_save` already restores the snapshot
/// on `save_not_committed`, so the returned vault is the
/// authoritative post-effect state regardless of the
/// [`RenameWorkerEffect`] variant. Per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Vault interaction" > "Every worker returns `(Vault, Store,
/// EffectOutcome)`".
///
/// `Clone` / `PartialEq` are deliberately not derived for the same
/// reason as on [`RenameWorkerInput`].
#[derive(Debug)]
pub struct RenameWorkerCompletion {
    /// Routed effect for `AppModel::update` to apply to the dialog.
    pub effect: RenameWorkerEffect,
    /// Live vault after the `mutate_and_save` call. On
    /// [`RenameWorkerEffect::Success`] the targeted account's label
    /// reflects the new value and `updated_at` has bumped; on
    /// [`RenameWorkerEffect::Failure`] the vault is whatever
    /// `mutate_and_save` rolled back to (pre-commit snapshot for
    /// `save_not_committed`; post-commit state with the new label for
    /// `save_durability_unconfirmed`; pre-call state for defensive
    /// `validation_error` / `invalid_state` cases).
    pub vault: Vault,
    /// Live store moved through unchanged so `AppModel::update` can
    /// reinstall the `(Vault, Store)` pair after the worker returns.
    pub store: Store,
}

/// Synchronous body of the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.rename(...))` rename worker fired by
/// `AppModel::update` from
/// `AppMsg::RenameDialogAction(RenameDialogOutput::SubmitLabel)`.
///
/// Consumes the [`RenameWorkerInput`] by value, runs
/// `vault.mutate_and_save(&store, |v| v.rename(account_id, &label,
/// now))`, and bundles the outcome into a
/// [`RenameWorkerCompletion`] via [`classify_rename_error`]. The
/// live `(Vault, Store)` pair is always returned so `AppModel`
/// reinstalls it regardless of the typed effect — `mutate_and_save`
/// is authoritative for the rollback / durability-unconfirmed
/// semantics per DESIGN.md §4.3.
///
/// Extracting the worker body as a pure function lets
/// `AppModel::update`'s closure stay a thin
/// `gio::spawn_blocking(move || run_rename_worker(input))` while the
/// real `mutate_and_save` call stays unit-testable in
/// `tests/rename_dialog_logic.rs` against tempfile-backed plaintext
/// vaults — no GTK / libadwaita main loop required. The
/// `AppModel::update` wire-up and the `apply_rename_*` reinstall
/// helpers land in follow-up commits alongside the `UnlockedBusy`
/// worker infrastructure.
#[must_use]
pub fn run_rename_worker(input: RenameWorkerInput) -> RenameWorkerCompletion {
    let RenameWorkerInput {
        mut vault,
        store,
        account_id,
        label,
        now,
    } = input;
    let effect = match vault.mutate_and_save(&store, |v| v.rename(account_id, &label, now)) {
        Ok(()) => RenameWorkerEffect::Success,
        Err(err) => RenameWorkerEffect::Failure(classify_rename_error(&err)),
    };
    RenameWorkerCompletion {
        effect,
        vault,
        store,
    }
}

/// Inline-error projection for the `RenameDialog` body.
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

/// Durability-warning projection for the `RenameDialog` body.
///
/// Returned by [`classify_rename_error`] on
/// `save_durability_unconfirmed`: the rename committed to disk, but
/// the parent-directory `fsync` failed, so the visible label stays
/// on the new value while the warning sits beneath it.
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

/// Stdout marker prefix emitted under `--exit-after-startup` once
/// the [`RenameDialogComponent`] has mounted in response to a kebab
/// `Rename…` activation.
///
/// The smoke test in `tests/gtk_smoke.rs` greps for this prefix to
/// prove the widget actually mounted rather than inferring the
/// render from the kebab dispatch alone (which fires before the
/// dialog widget exists).
pub const RENAME_DIALOG_MARKER_PREFIX: &str = "paladin-gtk: rename_dialog_account=";

/// Format the smoke-test stdout marker line for a mounted
/// [`RenameDialogComponent`].
///
/// The marker is `paladin-gtk: rename_dialog_account=<id> label=<display>`
/// where `<id>` is the [`AccountId`] the dialog targets and
/// `<display>` is the row's pre-formatted `<issuer>:<label>` heading.
#[must_use]
pub fn format_rename_dialog_marker(account_id: AccountId, display_label: &str) -> String {
    format!("{RENAME_DIALOG_MARKER_PREFIX}{account_id} label={display_label}")
}

/// Fixed `set_label` attribute the widget hands to the Rename
/// account dialog's header `gtk::Label`.
///
/// Returns the static title string the dialog renders at the top
/// of its body. The wording (`"Rename account"`) mirrors the TUI
/// rename view's `" Rename account "` block title built by `render`
/// (see `crates/paladin-tui/src/view/rename.rs`) — the TUI's
/// surrounding spaces are its block-padding convention and drop
/// out because `gtk::Label` renders the bare text without padding.
/// Pinning the title through a helper keeps the GTK / TUI wording
/// aligned against a single source of truth so a future copy
/// change cannot diverge silently.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::add_account::format_add_dialog_title`] on the
/// dialog-header-title side; together they pin the dialog header
/// label for both account-mutating dialogs.
#[must_use]
pub fn format_rename_dialog_title() -> &'static str {
    "Rename account"
}

/// Fixed `title` attribute the widget hands to the rename dialog's
/// label `AdwEntryRow::set_title`.
///
/// Returns the static title string `AdwEntryRow` renders as the
/// floating label above the entry. The wording (`"Label"`) is the
/// GNOME convention for an `AdwEntryRow` editing the account's
/// `label` field — sibling of [`crate::add_account::format_manual_label_title`]
/// on the row-title side; both return `"Label"` so the same field
/// reads the same way across the Add and Rename surfaces.
///
/// Intentionally distinct from the TUI rename view's `"New label:"`
/// row wording (see `crates/paladin-tui/src/view/rename.rs`): the
/// GTK dialog renders a separate `"Renaming X."` sub-title above
/// the row that names which account is being renamed, making
/// `"New label"` redundant; the TUI omits that sub-title and uses
/// `"New label:"` to disambiguate from the displayed current-label
/// prompt. Pinning the title through a helper keeps the wording in
/// one place shared by the widget binding and the pure-logic tests.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_rename_dialog_title`] on the dialog-chrome side;
/// together they pin every static label region of the rename
/// dialog above the (currently still-literal) cancel button.
#[must_use]
pub fn format_rename_dialog_label_title() -> &'static str {
    "Label"
}

/// Fixed `"Cancel"` label the widget hands to the Rename account
/// dialog's footer Cancel `gtk::Button::set_label`.
///
/// The label is the non-destructive affordance the user clicks to
/// dismiss the dialog without committing a new label via
/// `Vault::rename`. Wording is the fixed GNOME-convention
/// `"Cancel"` — surfaced through a helper so the string lives in
/// one place shared by the widget binding and the pure-logic
/// tests in `tests/rename_dialog_logic.rs`. Sibling of
/// [`crate::add_account::format_add_dialog_cancel_label`] on the
/// dialog-footer-cancel side; both return the same
/// GNOME-convention wording so a future copy change can land
/// through whichever helper's surface it applies to without
/// silently moving the other.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_rename_dialog_title`] and
/// [`format_rename_dialog_label_title`] on the dialog-chrome side.
#[must_use]
pub fn format_rename_dialog_cancel_label() -> &'static str {
    "Cancel"
}

/// Render the rename dialog's display-label-bearing sub-title
/// line — the `gtk::Label` beneath the
/// [`format_rename_dialog_title`] header that names which account
/// the user is renaming.
///
/// Returns `"Renaming <display>."` where `<display>` is the
/// pre-formatted `<issuer>:<label>` heading the rest of the
/// dialog uses (see [`format_rename_dialog_marker`]). The helper
/// takes the display label by `&str` so the widget can pass
/// `&model.init.display_label` without cloning, and uses
/// [`format!`] (returning an owned `String`) because the
/// `display` parameter is borrowed from
/// [`RenameDialogInit::display_label`] which the dialog owns for
/// the lifetime of the controller.
///
/// No TUI parity: the TUI renders a two-line prompt
/// (`"Renaming the following account:"` followed by the
/// current-label line) instead of the GTK's single-line
/// `"Renaming X."` form — the GTK condenses the two TUI lines
/// into a single sub-title so the dialog stays compact. Pinning
/// the format string through a helper keeps the GTK wording in
/// one place shared by the widget binding and the pure-logic
/// tests in `tests/rename_dialog_logic.rs`.
///
/// Sibling of [`format_rename_dialog_title`] (the header label),
/// [`format_rename_dialog_label_title`] (the `AdwEntryRow` title),
/// and [`format_rename_dialog_cancel_label`] (the footer cancel
/// button) on the rename-dialog-chrome side.
#[must_use]
pub fn format_rename_dialog_subtitle(display_label: &str) -> String {
    format!("Renaming {display_label}.")
}

/// Construction parameters for [`RenameDialogComponent`].
///
/// `AppModel` builds this from the live vault when a kebab
/// `AccountListOutput::OpenRenameDialog(id)` arrives — see
/// [`decide_rename_target`].
#[derive(Debug, Clone)]
pub struct RenameDialogInit {
    /// Stable account identifier. The widget passes this to
    /// `Vault::rename` inside `Vault::mutate_and_save` on submit so
    /// the worker targets the same account the kebab dispatched.
    pub account_id: AccountId,
    /// Current account label. The dialog's `adw::EntryRow` is seeded
    /// with this value so re-submitting an unchanged label still goes
    /// through `Vault::rename` and bumps `updated_at` (see the
    /// module-level "Same-label submission" note).
    pub current_label: String,
    /// Pre-formatted `<issuer>:<label>` heading mirroring
    /// `account_row::display_label`. Used as the dialog title chip so
    /// the user can confirm which row they are renaming. Empty
    /// issuer collapses to the bare label (parity with the row
    /// projection).
    pub display_label: String,
}

/// Look up an [`AccountSummary`] by id and project it into the
/// [`RenameDialogInit`] the widget binds.
///
/// Returns `None` if no account with the given id exists in
/// `vault` — the caller (`AppModel`) treats that as a benign race
/// (the account was removed between the kebab activation and the
/// dispatch) and does not mount the dialog.
///
/// The display label uses the same `account_row::display_label`
/// projection the list-row factory binds, so the dialog heading and
/// the row's heading never drift.
#[must_use]
pub fn decide_rename_target(vault: &Vault, id: AccountId) -> Option<RenameDialogInit> {
    vault
        .summaries()
        .find(|summary| summary.id == id)
        .map(|summary| RenameDialogInit {
            account_id: summary.id,
            current_label: summary.label.clone(),
            display_label: display_label(&summary),
        })
}

/// Live draft + validation state for [`RenameDialogComponent`].
///
/// The widget binds an [`adw::EntryRow`] to [`Self::draft`] and
/// re-runs [`classify_submit`] on every keystroke so the dialog
/// surfaces inline label errors as the user types. The widget never
/// trims the draft itself — trimming happens inside [`classify_submit`],
/// so [`Self::draft`] keeps the exact raw characters in the row and
/// the canonical trimmed value lives inside the [`SubmitOutcome`].
///
/// The targeted [`AccountId`] is copied off the [`RenameDialogInit`]
/// at construction so the future
/// `RenameDialogMsg::SubmitClicked` → `RenameDialogOutput::SubmitLabel`
/// routing can run through [`apply_msg`] without an extra
/// `account_id` argument. Mirrors the `UnlockDialogState` pattern
/// where the state owns everything the worker input needs.
#[derive(Debug, Clone)]
pub struct RenameDialogState {
    account_id: AccountId,
    /// Persisted label at dialog open. `save_not_committed` rolls
    /// the in-memory vault back to this value, so [`apply_msg`]
    /// rolls the visible draft back to match.
    prior_label: String,
    draft: String,
    last_validation: SubmitOutcome,
    /// Latest worker outcome from a completed `mutate_and_save`
    /// rename, surfaced via [`Self::worker_outcome`] so the widget
    /// view can render the inline error / durability warning
    /// attached to the dialog body. `None` between an open and the
    /// first worker completion, and re-cleared by any subsequent
    /// [`RenameDialogMsg::DraftChanged`] or
    /// [`RenameDialogMsg::SubmitClicked`] so a retry does not
    /// render stale text alongside the live attempt.
    worker_outcome: Option<RenameErrorOutcome>,
}

impl RenameDialogState {
    /// Seed the state from a freshly-projected [`RenameDialogInit`].
    ///
    /// The dialog opens with the entry row pre-filled with the
    /// account's current label so the user can edit-in-place; the
    /// initial validation always proceeds because labels persisted
    /// by `Vault::add` / `Vault::rename` have already passed §4.1.
    #[must_use]
    pub fn new(init: &RenameDialogInit) -> Self {
        let draft = init.current_label.clone();
        let last_validation = classify_submit(&draft);
        Self {
            account_id: init.account_id,
            prior_label: init.current_label.clone(),
            draft,
            last_validation,
            worker_outcome: None,
        }
    }

    /// Stable account identifier the dialog targets.
    ///
    /// Copied off the [`RenameDialogInit`] in [`Self::new`] so the
    /// future submit routing can build a
    /// `RenameDialogOutput::SubmitLabel { account_id, label }`
    /// payload directly from the state. A mid-flight keystroke
    /// never retargets the rename: [`set_draft`] mutates only the
    /// visible draft and cached validation.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Current raw draft text from the entry row.
    ///
    /// The widget binds this directly to `adw::EntryRow::text`. No
    /// trimming is applied here — see the struct doc comment.
    #[must_use]
    pub fn draft(&self) -> &str {
        &self.draft
    }

    /// Latest [`classify_submit`] outcome for the current draft.
    ///
    /// Cached on `self` so the widget can re-render the inline-error
    /// area without re-running validation on every redraw.
    #[must_use]
    pub fn last_validation(&self) -> &SubmitOutcome {
        &self.last_validation
    }

    /// Replace the draft and re-classify.
    ///
    /// Called from the entry row's text-change signal. The cached
    /// [`SubmitOutcome`] updates atomically alongside the draft so
    /// the widget never observes the two fields out of sync.
    /// Any prior worker outcome clears as part of the same update
    /// so a retry never renders stale post-effect text alongside
    /// the live draft.
    pub fn set_draft(&mut self, draft: String) {
        self.last_validation = classify_submit(&draft);
        self.draft = draft;
        self.worker_outcome = None;
    }

    /// Latest [`RenameErrorOutcome`] from a completed
    /// `Vault::mutate_and_save` rename worker.
    ///
    /// The widget view matches on this so the body can route
    /// `RestorePrior` (inline error, draft already rolled back),
    /// `KeepNewWithWarning` (warning attached, draft kept on the
    /// new value), or the defensive `InlineError` (inline error,
    /// draft kept) without re-deriving the typed routing decision.
    /// Cleared by [`Self::set_draft`] and [`RenameDialogMsg::SubmitClicked`]
    /// so a retry never renders stale text.
    #[must_use]
    pub fn worker_outcome(&self) -> Option<&RenameErrorOutcome> {
        self.worker_outcome.as_ref()
    }

    /// Inline-error projection for the body of the dialog.
    ///
    /// Returns `Some(&InlineError)` while the draft is invalid,
    /// `None` otherwise. The widget uses this to attach the `error`
    /// CSS class to the row and render the status-line label below
    /// it.
    #[must_use]
    pub fn inline_error(&self) -> Option<&InlineError> {
        match &self.last_validation {
            SubmitOutcome::InlineError(err) => Some(err),
            SubmitOutcome::Proceed(_) => None,
        }
    }

    /// On-demand classification of the current draft for the Save
    /// button / entry `entry-activated` routing branch.
    ///
    /// Re-runs [`classify_submit`] against the live draft so the
    /// returned [`SubmitOutcome`] reflects the same value the entry
    /// row currently shows. Pure — does not mutate the draft or the
    /// cached `last_validation`, so the visible value survives the
    /// `gio::spawn_blocking Vault::mutate_and_save` round trip and
    /// the routing decision is exercisable in
    /// `tests/rename_dialog_logic.rs` without GTK.
    ///
    /// The `RenameDialogMsg::SubmitClicked` variant, the
    /// `RenameDialogOutput::SubmitLabel` projection, and the
    /// `Vault::mutate_and_save` worker that consume this outcome
    /// land in follow-up commits alongside the `UnlockedBusy` worker
    /// infrastructure.
    #[must_use]
    pub fn submit(&self) -> SubmitOutcome {
        classify_submit(&self.draft)
    }
}

/// Messages handled by [`RenameDialogComponent`].
///
/// `DraftChanged(text)` arrives from the entry row's text-change
/// signal and runs [`RenameDialogState::set_draft`] so the cached
/// validation outcome stays in sync with what the user typed.
/// `Cancel` arrives from the dialog's Cancel button and dismisses
/// the dialog via [`RenameDialogOutput::Cancel`] without touching
/// the draft or the vault. `SubmitClicked` arrives from the dialog's
/// Save button and routes through [`RenameDialogState::submit`]:
/// a [`SubmitOutcome::Proceed`] forwards
/// [`RenameDialogOutput::SubmitLabel`] with the stable account id
/// and the canonical trimmed label; a [`SubmitOutcome::InlineError`]
/// emits no output so the dialog stays open with the cached inline
/// error visible. The `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.rename(...))` worker that consumes
/// the forwarded [`RenameDialogOutput::SubmitLabel`] lands in a
/// follow-up commit alongside the `UnlockedBusy` worker
/// infrastructure.
#[derive(Debug, Clone)]
pub enum RenameDialogMsg {
    /// Raw text from the [`adw::EntryRow`] after a keystroke. The
    /// handler re-runs [`classify_submit`] via
    /// [`RenameDialogState::set_draft`] so the inline-error area
    /// reflects the live draft.
    DraftChanged(String),
    /// Cancel button pressed. The handler forwards
    /// [`RenameDialogOutput::Cancel`] so `AppModel` can drop the
    /// controller and remove the dialog widget from the content
    /// tree.
    Cancel,
    /// Save button pressed. The handler routes through
    /// [`RenameDialogState::submit`]: a [`SubmitOutcome::Proceed`]
    /// forwards [`RenameDialogOutput::SubmitLabel`] with the stable
    /// account id and trimmed label; a [`SubmitOutcome::InlineError`]
    /// keeps the dialog open with the cached inline error visible.
    SubmitClicked,
    /// `AppModel` pushes the typed [`RenameErrorOutcome`] back to
    /// the dialog after the `gio::spawn_blocking
    /// Vault::mutate_and_save(|v| v.rename(...))` worker reports a
    /// failure. Symmetric partner of
    /// [`crate::unlock_dialog::UnlockDialogMsg::OpenFailedInline`]
    /// on the rename path: where the unlock variant carries an
    /// already-projected [`crate::unlock_dialog::InlineError`], the
    /// rename variant carries the typed [`RenameErrorOutcome`] so
    /// the dialog's handler can route `RestorePrior` (roll the
    /// visible label back and render the inline error),
    /// `KeepNewWithWarning` (keep the new label and attach the
    /// warning to the body), or the defensive `InlineError`
    /// (render the typed error without touching the label) in one
    /// `apply_msg` arm.
    ///
    /// The state-side handler for this variant — the
    /// [`RenameDialogState`] storage and the `apply_msg` routing —
    /// is wired in a follow-up commit alongside the dialog body
    /// re-render. For now [`apply_msg`] accepts the variant as a
    /// no-op so the dispatch path can build cleanly while the
    /// rendering side catches up.
    WorkerFailed(RenameErrorOutcome),
}

/// Outputs forwarded from [`RenameDialogComponent`] up to
/// `AppModel`.
///
/// Pinned as a typed enum (rather than the `()` unit used by the
/// initial render-only milestone) so future Save / worker
/// transitions can be added as additional variants without an
/// `_` catch-all in `AppModel` swallowing them silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameDialogOutput {
    /// User dismissed the dialog without saving. `AppModel` drops
    /// the live [`RenameDialogComponent`] controller and removes
    /// its widget from the content tree.
    Cancel,
    /// Save button pressed with a validated label. Carries the
    /// stable [`AccountId`] the dialog was seeded with so the
    /// `AppModel` worker dispatch targets the same account the
    /// kebab activation resolved, and the canonical trimmed label
    /// [`classify_submit`] produced from the live draft. `AppModel`
    /// hands the pair to the future `gio::spawn_blocking
    /// Vault::mutate_and_save(|v| v.rename(account_id, label, now))`
    /// worker.
    SubmitLabel {
        /// Stable identifier of the account whose label is being
        /// changed. Copied off [`RenameDialogState::account_id`] so
        /// a mid-flight keystroke never retargets the rename.
        account_id: AccountId,
        /// Canonical trimmed label from [`classify_submit`]. The
        /// visible draft on the dialog preserves the user's
        /// whitespace; the forwarded value is the trimmed string
        /// `Vault::rename` will persist.
        label: String,
    },
}

/// Apply an inbound [`RenameDialogMsg`] to `state` and return the
/// optional [`RenameDialogOutput`] the widget layer should forward
/// to `AppModel`.
///
/// Pulled out of [`RenameDialogComponent::update`] so the routing
/// decision — [`RenameDialogMsg::DraftChanged`] mutates the cached
/// validation and emits no output; [`RenameDialogMsg::Cancel`]
/// emits [`RenameDialogOutput::Cancel`] without touching the draft;
/// [`RenameDialogMsg::SubmitClicked`] routes through
/// [`RenameDialogState::submit`] and forwards
/// [`RenameDialogOutput::SubmitLabel`] on
/// [`SubmitOutcome::Proceed`] or emits no output on
/// [`SubmitOutcome::InlineError`] so the dialog stays open with the
/// cached inline error visible — stays unit-testable in
/// `tests/rename_dialog_logic.rs` without spinning up GTK.
pub fn apply_msg(
    state: &mut RenameDialogState,
    msg: RenameDialogMsg,
) -> Option<RenameDialogOutput> {
    match msg {
        RenameDialogMsg::DraftChanged(text) => {
            state.set_draft(text);
            None
        }
        RenameDialogMsg::Cancel => Some(RenameDialogOutput::Cancel),
        RenameDialogMsg::SubmitClicked => {
            // Clear any prior worker outcome so the body does not
            // render stale post-effect text alongside the live
            // attempt. A defensive `InlineError` from
            // `state.submit()` only fires if the widget bypassed
            // the entry-row validation gate, and in that case the
            // dialog stays open with the validation inline error
            // (not the stale worker outcome).
            state.worker_outcome = None;
            match state.submit() {
                SubmitOutcome::Proceed(label) => Some(RenameDialogOutput::SubmitLabel {
                    account_id: state.account_id(),
                    label,
                }),
                SubmitOutcome::InlineError(_) => None,
            }
        }
        RenameDialogMsg::WorkerFailed(outcome) => {
            if matches!(outcome, RenameErrorOutcome::RestorePrior(_)) {
                // `save_not_committed` rolled the in-memory vault
                // back to the pre-rename snapshot; roll the
                // visible draft back to the same persisted label
                // so the dialog and the vault stay in agreement.
                // `set_draft` also clears `worker_outcome`, so the
                // assignment below re-sets it to the actual
                // routing decision.
                let prior = state.prior_label.clone();
                state.set_draft(prior);
            }
            state.worker_outcome = Some(outcome);
            None
        }
    }
}

/// Widget-bearing dialog for the
/// [`crate::account_list::AccountListOutput::OpenRenameDialog`]
/// branch.
///
/// Mounts a vertical layout with a heading naming the targeted
/// `<issuer>:<label>` row, an editable [`adw::EntryRow`] pre-filled
/// with the account's current label, an inline-error label that
/// reflects [`RenameDialogState::inline_error`] as the user types,
/// and a Cancel button that forwards
/// [`RenameDialogOutput::Cancel`] so `AppModel` can dismiss the
/// dialog. The Save button and the
/// `Vault::mutate_and_save(|v| v.rename(...))` worker land in a
/// follow-up commit alongside the `UnlockedBusy` worker
/// infrastructure.
pub struct RenameDialogComponent {
    /// Construction parameters retained on `self` so future message
    /// handlers can read the targeted account id and reset the draft
    /// back to the pre-submit label on `save_not_committed`.
    init: RenameDialogInit,
    /// Live draft + validation state driven from the entry row's
    /// `changed` signal. The view watches
    /// [`RenameDialogState::inline_error`] so the error label
    /// surfaces inline as the user types.
    state: RenameDialogState,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for RenameDialogComponent {
    type Init = RenameDialogInit;
    type Input = RenameDialogMsg;
    type Output = RenameDialogOutput;

    view! {
        #[root]
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 12,
            set_hexpand: true,
            set_vexpand: true,

            gtk::Label {
                set_label: format_rename_dialog_title(),
                set_xalign: 0.0,
                add_css_class: "title-2",
            },
            gtk::Label {
                set_label: &format_rename_dialog_subtitle(&model.init.display_label),
                set_xalign: 0.0,
                set_wrap: true,
            },

            adw::PreferencesGroup {
                #[name = "label_row"]
                add = &adw::EntryRow {
                    set_title: format_rename_dialog_label_title(),
                    // `connect_changed` fires on every keystroke so
                    // the cached `RenameDialogState::last_validation`
                    // tracks the live draft.
                    connect_changed[sender] => move |entry| {
                        sender.input(RenameDialogMsg::DraftChanged(entry.text().to_string()));
                    },
                },
            },

            #[name = "error_label"]
            gtk::Label {
                set_xalign: 0.0,
                set_wrap: true,
                add_css_class: "error",
                #[watch]
                set_label: model
                    .state
                    .inline_error()
                    .map_or("", |err| err.rendered.as_str()),
                #[watch]
                set_visible: model.state.inline_error().is_some(),
            },

            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 6,
                set_halign: gtk::Align::End,

                #[name = "cancel_button"]
                gtk::Button {
                    set_label: format_rename_dialog_cancel_label(),
                    connect_clicked[sender] => move |_| {
                        sender.input(RenameDialogMsg::Cancel);
                    },
                },
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let state = RenameDialogState::new(&init);
        let model = RenameDialogComponent { init, state };
        let widgets = view_output!();
        // Seed the entry row imperatively so the initial `set_text`
        // does not run through the `connect_changed` round-trip on
        // every redraw — keeping the cursor where the user expects
        // it across state changes that do not reset the draft.
        widgets.label_row.set_text(model.state.draft());
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_msg(&mut self.state, msg) {
            // Ignore send failures: if `AppModel` has already dropped
            // the controller (e.g. window closed mid-click), there's
            // nothing left to dismiss.
            let _ = sender.output(output);
        }
    }
}
