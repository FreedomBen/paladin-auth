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
use relm4::gtk;
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

/// Live draft + validation state for [`RenameDialogComponent`].
///
/// The widget binds an [`adw::EntryRow`] to [`Self::draft`] and
/// re-runs [`classify_submit`] on every keystroke so the dialog
/// surfaces inline label errors as the user types. The widget never
/// trims the draft itself — trimming happens inside [`classify_submit`],
/// so [`Self::draft`] keeps the exact raw characters in the row and
/// the canonical trimmed value lives inside the [`SubmitOutcome`].
#[derive(Debug, Clone)]
pub struct RenameDialogState {
    draft: String,
    last_validation: SubmitOutcome,
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
            draft,
            last_validation,
        }
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
    pub fn set_draft(&mut self, draft: String) {
        self.last_validation = classify_submit(&draft);
        self.draft = draft;
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
/// the draft or the vault. The `submit` transition and the
/// `Vault::mutate_and_save(|v| v.rename(...))` worker described in
/// §"Component tree" > Rename dialog and §"Effect errors" land in
/// a follow-up commit alongside the `UnlockedBusy` worker
/// infrastructure.
#[derive(Debug)]
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
}

/// Apply an inbound [`RenameDialogMsg`] to `state` and return the
/// optional [`RenameDialogOutput`] the widget layer should forward
/// to `AppModel`.
///
/// Pulled out of [`RenameDialogComponent::update`] so the routing
/// decision — [`RenameDialogMsg::DraftChanged`] mutates the cached
/// validation and emits no output; [`RenameDialogMsg::Cancel`]
/// emits [`RenameDialogOutput::Cancel`] without touching the draft
/// — stays unit-testable in `tests/rename_dialog_logic.rs` without
/// spinning up GTK.
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
                set_label: "Rename account",
                set_xalign: 0.0,
                add_css_class: "title-2",
            },
            gtk::Label {
                set_label: &format!("Renaming {}.", model.init.display_label),
                set_xalign: 0.0,
                set_wrap: true,
            },

            adw::PreferencesGroup {
                #[name = "label_row"]
                add = &adw::EntryRow {
                    set_title: "Label",
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
                    set_label: "Cancel",
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
