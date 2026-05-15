// SPDX-License-Identifier: AGPL-3.0-or-later

//! Remove-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `RemoveDialog` and §"Effect errors" > "Add / remove / rename /
//! settings saves", `RemoveDialog` is the confirmation gate before
//! calling `Vault::remove` inside `Vault::mutate_and_save`. The
//! widget layer hosts the destructive `AdwAlertDialog` chrome; the
//! pure-logic helpers here own the display-label formatting, the
//! defensive `account_not_found` error builder, and the post-effect
//! routing decision so they can be unit-tested in
//! `tests/remove_dialog_logic.rs` without spinning up GTK /
//! libadwaita.
//!
//! # Confirmation body
//!
//! [`summary_display_label`] renders the `<issuer>:<label>` body
//! shape the CLI and TUI both use (with `Some("")` collapsing to the
//! no-issuer form so the body never renders a dangling `:label`
//! colon). The dialog reads the result directly into its
//! confirmation prompt so wording matches the CLI / TUI verbatim.
//!
//! # Closure-side defensive error
//!
//! `Vault::remove(id)` returns `Option<Account>` — `None` for stale
//! ids. The `Vault::mutate_and_save` closure maps that `None` to
//! [`account_not_found_error`], which builds the §5 `invalid_state
//! { operation: "remove", state: "account_not_found" }` shape used
//! by the CLI / TUI for the same defensive path.
//!
//! # Post-effect routing
//!
//! [`classify_remove_error`] maps the [`PaladinError`] from a failed
//! `mutate_and_save` onto the dialog's three-way routing decision:
//!
//! * `save_not_committed` → [`RemoveErrorOutcome::RestorePrior`]
//!   (the commit never landed; `mutate_and_save` already restored
//!   the account at its previous position, and the dialog stays
//!   open with the inline error so the user can retry).
//! * `save_durability_unconfirmed` →
//!   [`RemoveErrorOutcome::KeepRemovedWithWarning`] (the remove
//!   committed to disk but parent-fsync failed; the account stays
//!   gone and the warning attaches to the dialog body).
//! * Anything else (defensive: `invalid_state { state:
//!   "account_not_found" }`, `io_error`, `validation_error`, …) →
//!   [`RemoveErrorOutcome::InlineError`] without transitioning the
//!   dialog out.

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use paladin_core::{AccountId, AccountSummary, ErrorKind, PaladinError, Vault};

/// Render the dialog's confirmation body label.
///
/// Returns `<issuer>:<label>` when `issuer` is `Some(non_empty)` and
/// the bare `label` otherwise. CLI / TUI parity: `Some("")` collapses
/// to the no-issuer form so the body never renders a dangling
/// `:label` colon for accounts imported / created without an issuer.
#[must_use]
pub fn summary_display_label(summary: &AccountSummary) -> String {
    match summary.issuer.as_deref().filter(|i| !i.is_empty()) {
        Some(issuer) => format!("{issuer}:{}", summary.label),
        None => summary.label.clone(),
    }
}

/// Build the defensive `account_not_found` error used inside the
/// `Vault::mutate_and_save` closure when `Vault::remove` returns
/// `None`.
///
/// Matches the CLI / TUI not-found shape exactly: `invalid_state
/// { operation: "remove", state: "account_not_found" }`.
#[must_use]
pub fn account_not_found_error() -> PaladinError {
    PaladinError::InvalidState {
        operation: "remove",
        state: "account_not_found",
    }
}

/// Post-effect routing decision for a failed
/// `Vault::mutate_and_save(|v| v.remove(...))`.
///
/// See [`classify_remove_error`].
#[derive(Debug, Clone)]
pub enum RemoveErrorOutcome {
    /// `save_not_committed` — the remove never committed to disk.
    /// `mutate_and_save` already restored the account at its previous
    /// position; the dialog stays open and shows the typed inline
    /// error.
    RestorePrior(InlineError),
    /// `save_durability_unconfirmed` — primary save succeeded but
    /// parent-fsync failed. The account stays removed in memory and
    /// the warning attaches to the dialog body.
    KeepRemovedWithWarning(InlineWarning),
    /// Defensive: any other typed error stays inline and does not
    /// transition the dialog out. Hits `invalid_state { state:
    /// "account_not_found" }` when the targeted account is removed
    /// mid-flight.
    InlineError(InlineError),
}

/// Classify a [`Vault::mutate_and_save`] failure into a
/// [`RemoveErrorOutcome`].
///
/// Routes the §5 save-pipeline discriminators (`save_not_committed`
/// → [`RemoveErrorOutcome::RestorePrior`],
/// `save_durability_unconfirmed` →
/// [`RemoveErrorOutcome::KeepRemovedWithWarning`]) and falls back to
/// an inline error for every other typed variant so the dialog
/// never silently transitions out.
#[must_use]
pub fn classify_remove_error(err: &PaladinError) -> RemoveErrorOutcome {
    match err.kind() {
        ErrorKind::SaveNotCommitted => {
            RemoveErrorOutcome::RestorePrior(InlineError::from_error(err))
        }
        ErrorKind::SaveDurabilityUnconfirmed => {
            RemoveErrorOutcome::KeepRemovedWithWarning(InlineWarning::from_error(err))
        }
        _ => RemoveErrorOutcome::InlineError(InlineError::from_error(err)),
    }
}

/// Inline-error projection for the `RemoveDialog` body.
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

/// Durability-warning projection for the `RemoveDialog` body.
///
/// Returned by [`classify_remove_error`] on
/// `save_durability_unconfirmed`: the remove committed to disk, but
/// the parent-directory `fsync` failed, so the account stays gone
/// from in-memory state while the warning sits beneath the
/// confirmation body.
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

/// Stdout marker prefix emitted under `--exit-after-startup` once the
/// [`RemoveDialogComponent`] has mounted in response to a kebab
/// `Remove…` activation.
///
/// The smoke test in `tests/gtk_smoke.rs` greps for this prefix to
/// prove the widget actually mounted rather than inferring the render
/// from the kebab dispatch alone (which fires before the dialog
/// widget exists).
pub const REMOVE_DIALOG_MARKER_PREFIX: &str = "paladin-gtk: remove_dialog_account=";

/// Format the smoke-test stdout marker line for a mounted
/// [`RemoveDialogComponent`].
///
/// The marker is `paladin-gtk: remove_dialog_account=<id> label=<display>`
/// where `<id>` is the [`AccountId`] the dialog targets and
/// `<display>` is the row's pre-formatted `<issuer>:<label>` heading.
#[must_use]
pub fn format_remove_dialog_marker(account_id: AccountId, display_label: &str) -> String {
    format!("{REMOVE_DIALOG_MARKER_PREFIX}{account_id} label={display_label}")
}

/// Construction parameters for [`RemoveDialogComponent`].
///
/// `AppModel` builds this from the live vault when a kebab
/// `AccountListOutput::OpenRemoveDialog(id)` arrives — see
/// [`decide_remove_target`].
#[derive(Debug, Clone)]
pub struct RemoveDialogInit {
    /// Stable account identifier. The widget passes this to
    /// `Vault::remove` inside `Vault::mutate_and_save` on confirm so
    /// the worker targets the same account the kebab dispatched.
    pub account_id: AccountId,
    /// Pre-formatted `<issuer>:<label>` heading mirroring
    /// `account_row::display_label` (and identical to
    /// [`summary_display_label`]). Used as the dialog body so the
    /// user can confirm which row they are removing. Empty issuer
    /// collapses to the bare label (parity with the row projection).
    pub display_label: String,
}

/// Look up an [`AccountSummary`] by id and project it into the
/// [`RemoveDialogInit`] the widget binds.
///
/// Returns `None` if no account with the given id exists in `vault`
/// — the caller (`AppModel`) treats that as a benign race (the
/// account was removed between the kebab activation and the
/// dispatch) and does not mount the dialog.
///
/// The display label uses [`summary_display_label`] so the dialog
/// body and the row's heading never drift.
#[must_use]
pub fn decide_remove_target(vault: &Vault, id: AccountId) -> Option<RemoveDialogInit> {
    vault
        .summaries()
        .find(|summary| summary.id == id)
        .map(|summary| RemoveDialogInit {
            account_id: summary.id,
            display_label: summary_display_label(&summary),
        })
}

/// Messages handled by [`RemoveDialogComponent`].
///
/// `Cancel` arrives from the dialog's Cancel button and dismisses
/// the dialog via [`RemoveDialogOutput::Cancel`] without touching
/// the vault. The `Confirm` / Remove transition and the
/// `Vault::mutate_and_save(|v| v.remove(...))` worker described in
/// §"Component tree" > `RemoveDialog` and §"Effect errors" land in
/// a follow-up commit alongside the `UnlockedBusy` worker
/// infrastructure.
#[derive(Debug)]
pub enum RemoveDialogMsg {
    /// Cancel button pressed. The handler forwards
    /// [`RemoveDialogOutput::Cancel`] so `AppModel` can drop the
    /// controller and remove the dialog widget from the content
    /// tree.
    Cancel,
}

/// Outputs forwarded from [`RemoveDialogComponent`] up to
/// `AppModel`.
///
/// Pinned as a typed enum (rather than the `()` unit used by the
/// initial render-only milestone) so future Confirm / worker
/// transitions can be added as additional variants without an
/// `_` catch-all in `AppModel` swallowing them silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveDialogOutput {
    /// User dismissed the dialog without removing. `AppModel` drops
    /// the live [`RemoveDialogComponent`] controller and removes its
    /// widget from the content tree.
    Cancel,
}

/// Apply an inbound [`RemoveDialogMsg`] and return the optional
/// [`RemoveDialogOutput`] the widget layer should forward to
/// `AppModel`.
///
/// Pulled out of [`RemoveDialogComponent::update`] so the routing
/// decision — [`RemoveDialogMsg::Cancel`] emits
/// [`RemoveDialogOutput::Cancel`] — stays unit-testable in
/// `tests/remove_dialog_logic.rs` without spinning up GTK. The
/// helper takes the message by value (rather than `&mut state, msg`
/// like the rename variant) because `RemoveDialog` carries no
/// editable draft — every transition is a pure dismissal /
/// confirmation today. The follow-up commits that add `Confirm` /
/// worker-outcome variants will move owned payloads out of the
/// message, so the by-value signature stays forward-compatible.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn apply_msg(msg: RemoveDialogMsg) -> Option<RemoveDialogOutput> {
    match msg {
        RemoveDialogMsg::Cancel => Some(RemoveDialogOutput::Cancel),
    }
}

/// Widget-bearing dialog for the
/// [`crate::account_list::AccountListOutput::OpenRemoveDialog`]
/// branch.
///
/// Mounts a libadwaita [`adw::StatusPage`] that surfaces the
/// targeted account's `<issuer>:<label>` heading so the user can
/// confirm which row will be removed, plus a Cancel button that
/// forwards [`RemoveDialogOutput::Cancel`] so `AppModel` can dismiss
/// the dialog. The destructive `AdwAlertDialog` chrome, the
/// Remove button, and the `Vault::mutate_and_save` worker land in
/// follow-up commits alongside the `UnlockedBusy` worker
/// infrastructure; the Cancel-only staging mirrors the
/// [`crate::rename_dialog::RenameDialogComponent`] rollout pattern.
pub struct RemoveDialogComponent {
    /// Construction parameters retained on `self` so a future
    /// message handler can read the targeted account id and the
    /// confirmation body without re-plumbing the values through every
    /// signal.
    #[allow(dead_code)]
    init: RemoveDialogInit,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for RemoveDialogComponent {
    type Init = RemoveDialogInit;
    type Input = RemoveDialogMsg;
    type Output = RemoveDialogOutput;

    view! {
        #[root]
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 12,
            set_hexpand: true,
            set_vexpand: true,

            adw::StatusPage {
                // `user-trash-symbolic` is the freedesktop-standard glyph
                // for destructive removal; resolves through the system
                // icon theme so the wordless icon matches the platform's
                // other delete surfaces.
                set_icon_name: Some("user-trash-symbolic"),
                set_title: "Remove account",
                set_description: Some(&format!(
                    "Removing {display}.",
                    display = model.init.display_label,
                )),
                set_hexpand: true,
                set_vexpand: true,
            },

            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 6,
                set_halign: gtk::Align::End,

                #[name = "cancel_button"]
                gtk::Button {
                    set_label: "Cancel",
                    connect_clicked[sender] => move |_| {
                        sender.input(RemoveDialogMsg::Cancel);
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
        let model = RemoveDialogComponent { init };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_msg(msg) {
            // Ignore send failures: if `AppModel` has already dropped
            // the controller (e.g. window closed mid-click), there's
            // nothing left to dismiss.
            let _ = sender.output(output);
        }
    }
}
