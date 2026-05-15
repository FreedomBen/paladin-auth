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

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::prelude::*;

use paladin_core::{validate_label, AccountId, ErrorKind, PaladinError, Vault};

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

/// Messages handled by [`RenameDialogComponent`].
///
/// This milestone scaffolds the read-only render path — the
/// `submit` / `cancel` transitions and the
/// `Vault::mutate_and_save(|v| v.rename(...))` worker described in
/// §"Component tree" > Rename dialog and §"Effect errors" land in
/// follow-up commits alongside the `UnlockedBusy` worker
/// infrastructure. The empty enum is the deliberate starting point
/// — relm4 requires the associated `Input` type to exist even when
/// no inbound messages are wired yet.
#[derive(Debug)]
pub enum RenameDialogMsg {}

/// Widget-bearing dialog for the
/// [`crate::account_list::AccountListOutput::OpenRenameDialog`]
/// branch.
///
/// Mounts a libadwaita [`adw::StatusPage`] that surfaces the
/// targeted account's `<issuer>:<label>` heading alongside the
/// current label that the entry field will prefill in the next
/// commit. Subsequent commits replace the placeholder body with the
/// editable [`adw::EntryRow`], the submit button, and the
/// `Vault::mutate_and_save` worker; until then, keeping the widget
/// read-only mirrors the [`crate::init_dialog::InitDialogComponent`]
/// pattern (every dialog branch landed as a status page first and
/// grew inbound actions later).
pub struct RenameDialogComponent {
    /// Construction parameters retained on `self` so a future
    /// message handler can read the targeted account id and the
    /// pre-submit label without re-plumbing the values through every
    /// signal.
    #[allow(dead_code)]
    init: RenameDialogInit,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for RenameDialogComponent {
    type Init = RenameDialogInit;
    type Input = RenameDialogMsg;
    type Output = ();

    view! {
        #[root]
        adw::StatusPage {
            // `document-edit-symbolic` is the freedesktop-standard
            // glyph for "edit this thing"; resolves through the
            // system icon theme so the wordless icon matches the
            // platform's other rename surfaces.
            set_icon_name: Some("document-edit-symbolic"),
            set_title: "Rename account",
            set_description: Some(&format!(
                "Renaming {display}.\n\nCurrent label: {current}",
                display = model.init.display_label,
                current = model.init.current_label,
            )),
            set_hexpand: true,
            set_vexpand: true,
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        _sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = RenameDialogComponent { init };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, _msg: Self::Input, _sender: ComponentSender<Self>) {
        // No inbound messages handled at this milestone — see
        // `RenameDialogMsg` doc comment for the upcoming submit /
        // cancel / worker actions.
    }
}
