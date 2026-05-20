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

use paladin_core::{AccountId, ErrorKind, PaladinError, Store, Vault};

/// Render the dialog's confirmation body label.
///
/// Re-exports [`crate::account_row::summary_display_label`] so the
/// `RemoveDialog` confirmation body and the `AccountListComponent`
/// row factory share a single source of truth for the
/// `<issuer>:<label>` body shape. CLI / TUI parity: `Some("")`
/// collapses to the no-issuer form so the body never renders a
/// dangling `:label` colon for accounts imported / created without an
/// issuer.
pub use crate::account_row::summary_display_label;

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

/// Fixed `"Remove"` label the widget hands to the
/// [`RemoveDialogComponent`]'s footer destructive
/// `gtk::Button::set_label`.
///
/// The label is the action-specific GNOME-HIG verb for the
/// surface — matching the dialog's
/// [`format_remove_dialog_title`] (`"Remove account"`) so the
/// primary button reads as the noun-stripped imperative of the
/// dialog's stated action. The button binds `add_css_class:
/// "destructive-action"` so libadwaita paints the affordance in
/// the platform's destructive red against the Cancel button. No
/// TUI parity: the TUI's `remove` command is CLI-shaped and
/// prompts on stdin rather than rendering a dialog footer, so
/// the wording is GTK-specific. Pinning the wording through a
/// helper keeps the string in one place shared by the widget
/// binding and the pure-logic tests.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_remove_dialog_cancel_label`] on the dialog-footer
/// side; together they pin both halves of the dialog's footer
/// action affordances against a single source of truth.
#[must_use]
pub fn format_remove_dialog_remove_label() -> &'static str {
    "Remove"
}

/// Fixed `"Cancel"` label the widget hands to the
/// [`RemoveDialogComponent`]'s footer Cancel `gtk::Button::set_label`.
///
/// The label is the action-specific GNOME-HIG verb for the
/// surface — matching the rename / add dialog cancel affordance
/// so the dialog footer wording stays uniform across every per-
/// account surface. No TUI parity: the TUI's `remove` command is
/// CLI-shaped and prompts on stdin rather than rendering a
/// dialog footer, so the wording is GTK-specific. Pinning the
/// wording through a helper keeps the string in one place shared
/// by the widget binding and the pure-logic tests in
/// `tests/remove_dialog_logic.rs`.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::rename_dialog::format_rename_dialog_cancel_label`]
/// and [`crate::add_account::format_add_dialog_cancel_label`] on
/// the dialog-footer-cancel side; together they pin every
/// dialog's cancel affordance against a single source of truth.
#[must_use]
pub fn format_remove_dialog_cancel_label() -> &'static str {
    "Cancel"
}

/// Body the widget hands to the [`RemoveDialogComponent`]'s
/// `adw::StatusPage::set_description` attribute.
///
/// Renders `"Removing <display>."` where `<display>` is the
/// pre-formatted display label (`<issuer>:<label>` or `<label>`)
/// surfaced by [`RemoveDialogState::display_label`]. Pinning the
/// format string through a helper keeps the wording in one place
/// shared by the widget binding and the pure-logic tests, and
/// matches the parallel single-line "Verb-ing {display}." form
/// used by
/// [`crate::rename_dialog::format_rename_dialog_subtitle`] so the
/// rename and remove dialogs read in parallel against the same
/// display-label format.
///
/// Takes the display label by `&str` so the widget can pass
/// `model.state.display_label()` without cloning, and uses
/// [`format!`] (returning an owned `String`) because the rendered
/// text needs to outlive the borrowed argument once the view!
/// macro hands it to `set_description`. No TUI parity: the TUI's
/// `remove` command is CLI-shaped and prompts on stdin rather
/// than rendering a dialog sub-title, so the wording is GTK-
/// specific.
#[must_use]
pub fn format_remove_dialog_subtitle(display_label: &str) -> String {
    format!("Removing {display_label}.")
}

/// Freedesktop icon name the widget hands to the
/// [`RemoveDialogComponent`]'s `adw::StatusPage::set_icon_name`.
///
/// Returns the static icon name `"user-trash-symbolic"` — the
/// freedesktop-standard glyph for destructive removal that
/// resolves through the system icon theme so the wordless icon
/// matches every other GNOME app's delete surface. The
/// `-symbolic` suffix is required by the libadwaita HIG for
/// `AdwStatusPage` icons so the glyph recolors with the theme.
/// No TUI parity: the TUI is text-only and has no icon to mirror.
/// Pinning the icon name through a helper keeps the string in
/// one place shared by the widget binding and the pure-logic
/// tests.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_icon_name`],
/// [`crate::init_dialog::format_init_dialog_icon_name`], and
/// [`crate::startup_error::format_startup_error_icon_name`] on
/// the dialog-status-icon side; together they pin every first-
/// mount dialog's freedesktop glyph against a single source of
/// truth.
#[must_use]
pub fn format_remove_dialog_icon_name() -> &'static str {
    "user-trash-symbolic"
}

/// Fixed `title` attribute the widget hands to the
/// [`RemoveDialogComponent`]'s `adw::StatusPage::set_title`.
///
/// Returns the static title string the dialog renders at the top
/// of its body. The wording (`"Remove account"`) is the GNOME-HIG
/// verb-led phrasing for the destructive action, naming the
/// surface without restating the specific account — the per-
/// target display label lives in the `StatusPage`'s description
/// body. No TUI parity: the TUI's `remove` command is CLI-shaped
/// and prompts on stdin rather than mounting a dialog header, so
/// the wording is GTK-specific. Pinning the title through a
/// helper keeps the wording in one place shared by the widget
/// binding and the pure-logic tests in
/// `tests/remove_dialog_logic.rs`.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_title`],
/// [`crate::init_dialog::format_init_dialog_title`],
/// [`crate::rename_dialog::format_rename_dialog_title`],
/// [`crate::add_account::format_add_dialog_title`], and
/// [`crate::startup_error::format_startup_error_title`] on the
/// dialog-header-title side; together they pin every dialog's
/// titled surface against a single source of truth.
#[must_use]
pub fn format_remove_dialog_title() -> &'static str {
    "Remove account"
}

/// Worker input bundled by
/// `AppMsg::RemoveDialogAction(RemoveDialogOutput::SubmitConfirm)`
/// for the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.remove(...))` worker.
///
/// Symmetric partner of [`crate::rename_dialog::RenameWorkerInput`] on
/// the remove path. Carries the live `(Vault, Store)` pair plus the
/// stable account id from the dialog so the worker thread can call
/// `mutate_and_save` without re-fetching from `AppModel`. `Clone` /
/// `PartialEq` are deliberately not derived — [`Vault`] and [`Store`]
/// are non-`Clone` and `AppModel::update` consumes the input exactly
/// once when it moves it into the worker closure.
#[derive(Debug)]
pub struct RemoveWorkerInput {
    /// Live vault from the `Unlocked` `(Vault, Store)` pair. Moved
    /// into the worker so `mutate_and_save` can borrow it mutably
    /// without keeping `AppModel` in `Unlocked` for the duration of
    /// the save call.
    pub vault: Vault,
    /// Live store from the `Unlocked` `(Vault, Store)` pair. Moved
    /// alongside `vault` so the same `(Vault, Store)` pair returns
    /// from the worker even on typed failure.
    pub store: Store,
    /// Stable account id from
    /// [`RemoveDialogOutput::SubmitConfirm::account_id`]. Forwarded to
    /// `Vault::remove` so the worker targets the same account the
    /// dialog seeded.
    pub account_id: AccountId,
}

/// Outcome of [`run_remove_worker`] for `AppModel::update` to apply.
///
/// `Success` indicates the remove committed and the row drops out of
/// the visible account list. `Failure` wraps the
/// [`RemoveErrorOutcome`] from [`classify_remove_error`] so the
/// dialog can re-render the matching inline error / durability
/// warning without re-deriving the routing decision off the
/// [`PaladinError`].
#[derive(Debug, Clone)]
pub enum RemoveWorkerEffect {
    /// `Vault::mutate_and_save(|v| v.remove(...))` returned `Ok(())`.
    /// The dialog dismisses itself and the targeted row drops out of
    /// the visible account list.
    Success,
    /// `Vault::mutate_and_save(|v| v.remove(...))` returned a typed
    /// failure. The carried [`RemoveErrorOutcome`] tells the dialog
    /// whether to restore the prior account (`save_not_committed`),
    /// keep the removed state with a warning attached
    /// (`save_durability_unconfirmed`), or stay inline with the typed
    /// error (defensive `invalid_state { state: "account_not_found" }`
    /// / `io_error` / `validation_error` / …).
    Failure(RemoveErrorOutcome),
}

/// Bundle returned by [`run_remove_worker`].
///
/// Carries the live `(Vault, Store)` pair on every branch so
/// `AppModel::update` can reinstall it before applying the UI
/// outcome — `Vault::mutate_and_save` already restores the snapshot
/// on `save_not_committed`, so the returned vault is the
/// authoritative post-effect state regardless of the
/// [`RemoveWorkerEffect`] variant. Per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Vault interaction" > "Every worker returns `(Vault, Store,
/// EffectOutcome)`".
///
/// `Clone` / `PartialEq` are deliberately not derived for the same
/// reason as on [`RemoveWorkerInput`].
#[derive(Debug)]
pub struct RemoveWorkerCompletion {
    /// Routed effect for `AppModel::update` to apply to the dialog.
    pub effect: RemoveWorkerEffect,
    /// Live vault after the `mutate_and_save` call. On
    /// [`RemoveWorkerEffect::Success`] the targeted account is gone;
    /// on [`RemoveWorkerEffect::Failure`] the vault is whatever
    /// `mutate_and_save` rolled back to (pre-commit snapshot for
    /// `save_not_committed`; post-commit state with the account
    /// removed for `save_durability_unconfirmed`; pre-call state for
    /// defensive `invalid_state` / `io_error` / `validation_error`
    /// cases).
    pub vault: Vault,
    /// Live store moved through unchanged so `AppModel::update` can
    /// reinstall the `(Vault, Store)` pair after the worker returns.
    pub store: Store,
}

/// Synchronous body of the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.remove(...))` remove worker fired by
/// `AppModel::update` from
/// `AppMsg::RemoveDialogAction(RemoveDialogOutput::SubmitConfirm)`.
///
/// Consumes the [`RemoveWorkerInput`] by value, runs
/// `vault.mutate_and_save(&store, |v| v.remove(account_id))`, and
/// bundles the outcome into a [`RemoveWorkerCompletion`] via
/// [`classify_remove_error`]. The live `(Vault, Store)` pair is
/// always returned so `AppModel` reinstalls it regardless of the
/// typed effect — `mutate_and_save` is authoritative for the
/// rollback / durability-unconfirmed semantics per DESIGN.md §4.3.
///
/// The closure inside `mutate_and_save` maps `Vault::remove`'s
/// `Option<Account>` `None` (the targeted account was removed
/// mid-flight) to [`account_not_found_error`] so the defensive shape
/// matches the CLI / TUI verbatim.
///
/// Extracting the worker body as a pure function lets
/// `AppModel::update`'s closure stay a thin
/// `gio::spawn_blocking(move || run_remove_worker(input))` while the
/// real `mutate_and_save` call stays unit-testable in
/// `tests/remove_dialog_logic.rs` against tempfile-backed plaintext
/// vaults — no GTK / libadwaita main loop required.
#[must_use]
pub fn run_remove_worker(input: RemoveWorkerInput) -> RemoveWorkerCompletion {
    let RemoveWorkerInput {
        mut vault,
        store,
        account_id,
    } = input;
    let effect = match vault.mutate_and_save(&store, |v| {
        if v.remove(account_id).is_none() {
            return Err(account_not_found_error());
        }
        Ok(())
    }) {
        Ok(()) => RemoveWorkerEffect::Success,
        Err(err) => RemoveWorkerEffect::Failure(classify_remove_error(&err)),
    };
    RemoveWorkerCompletion {
        effect,
        vault,
        store,
    }
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
    /// Pre-formatted `<issuer>:<label>` heading from
    /// [`summary_display_label`] (re-exported from
    /// `account_row::summary_display_label`). Used as the dialog body
    /// so the user can confirm which row they are removing. Empty
    /// issuer collapses to the bare label (parity with the row
    /// projection).
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

/// Pure-logic state machine the [`RemoveDialogComponent`] shadows.
///
/// `RemoveDialog` has no editable draft — it is a confirmation gate —
/// so the state only needs to retain the construction parameters
/// (account id + display label) for the lifetime of the widget plus
/// the last typed [`RemoveErrorOutcome`] from the worker so the
/// dialog body can re-render the inline error / warning across
/// re-renders.
///
/// Symmetric partner of [`crate::rename_dialog::RenameDialogState`]
/// on the remove path. Where the rename state carries a live draft,
/// the remove state only carries the stable seeded values plus the
/// worker outcome — `Confirm` does not mutate the state, it only
/// fires the worker through `AppModel`.
#[derive(Debug, Clone)]
pub struct RemoveDialogState {
    /// Stable construction parameters from [`decide_remove_target`].
    /// Retained on `self` so [`RemoveDialogState::account_id`] and
    /// [`RemoveDialogState::display_label`] stay stable across
    /// re-renders even if `AppModel` mutates the underlying vault.
    init: RemoveDialogInit,
    /// Last typed worker outcome from the
    /// `Vault::mutate_and_save(|v| v.remove(...))` worker, set by
    /// [`apply_msg`] on the [`RemoveDialogMsg::WorkerFailed`] branch.
    /// Lets the dialog body render the matching inline error /
    /// warning across re-renders without re-routing the typed
    /// [`PaladinError`]. Stays public to the crate so the dispatch
    /// glue in `AppModel` can read it during a re-render after the
    /// dialog mounts.
    pub(crate) worker_outcome: Option<RemoveErrorOutcome>,
}

impl RemoveDialogState {
    /// Build a fresh state from the dialog's construction
    /// parameters. `worker_outcome` starts as `None` — the worker
    /// has not been fired yet, so there is no post-effect routing
    /// to render.
    #[must_use]
    pub fn new(init: &RemoveDialogInit) -> Self {
        Self {
            init: init.clone(),
            worker_outcome: None,
        }
    }

    /// Stable account id from the seeded [`RemoveDialogInit`].
    /// Forwarded as [`RemoveDialogOutput::SubmitConfirm::account_id`]
    /// when the user activates the Remove button.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.init.account_id
    }

    /// Pre-formatted `<issuer>:<label>` heading the dialog body
    /// renders so the user can confirm which row is being removed.
    /// Stable for the lifetime of the dialog — the widget reads
    /// straight off this accessor.
    #[must_use]
    pub fn display_label(&self) -> &str {
        &self.init.display_label
    }

    /// Last typed worker outcome, if any. Returns `None` until the
    /// worker has reported a `Failure` branch; `Success` drops the
    /// dialog and never reaches this accessor.
    #[must_use]
    pub fn worker_outcome(&self) -> Option<&RemoveErrorOutcome> {
        self.worker_outcome.as_ref()
    }

    /// Inline-error projection of [`Self::worker_outcome`]. Returns
    /// `Some` for the `RestorePrior` and defensive `InlineError`
    /// branches so the dialog body can render the typed message.
    /// Returns `None` for `KeepRemovedWithWarning` (rendered via
    /// [`Self::inline_warning`]) and for the pre-failure state.
    #[must_use]
    pub fn inline_error(&self) -> Option<&InlineError> {
        match self.worker_outcome.as_ref()? {
            RemoveErrorOutcome::RestorePrior(err) | RemoveErrorOutcome::InlineError(err) => {
                Some(err)
            }
            RemoveErrorOutcome::KeepRemovedWithWarning(_) => None,
        }
    }

    /// Durability-warning projection of [`Self::worker_outcome`].
    /// Returns `Some` only for the `KeepRemovedWithWarning` branch
    /// so the dialog body can render the parent-fsync warning
    /// beneath the confirmation prompt.
    #[must_use]
    pub fn inline_warning(&self) -> Option<&InlineWarning> {
        match self.worker_outcome.as_ref()? {
            RemoveErrorOutcome::KeepRemovedWithWarning(warning) => Some(warning),
            RemoveErrorOutcome::RestorePrior(_) | RemoveErrorOutcome::InlineError(_) => None,
        }
    }
}

/// Messages handled by [`RemoveDialogComponent`].
///
/// `Cancel` and `Confirm` arrive from the dialog's Cancel / Remove
/// buttons. `WorkerFailed` is pushed back from `AppModel` after the
/// `gio::spawn_blocking Vault::mutate_and_save(|v| v.remove(...))`
/// worker reports a failure so the dialog can re-render the matching
/// inline error / durability warning.
///
/// `Clone` is derived so the bundled [`crate::app::state::RemoveDispatch`]
/// (which carries an `Option<RemoveDialogMsg>` field) can be cloned
/// in the dispatch trio aggregator. The `WorkerFailed` payload is
/// already `Clone` because [`RemoveErrorOutcome`] only holds
/// `String` / [`ErrorKind`] values.
#[derive(Debug, Clone)]
pub enum RemoveDialogMsg {
    /// Cancel button pressed. The handler forwards
    /// [`RemoveDialogOutput::Cancel`] so `AppModel` can drop the
    /// controller and remove the dialog widget from the content
    /// tree.
    Cancel,
    /// Remove button pressed. The handler clears any prior worker
    /// outcome (so a re-render after a defensive
    /// `KeepRemovedWithWarning` does not show stale text alongside a
    /// fresh attempt) and forwards
    /// [`RemoveDialogOutput::SubmitConfirm`] with the stable
    /// [`AccountId`] from the seeded init so `AppModel` can fire the
    /// `Vault::mutate_and_save(|v| v.remove(...))` worker.
    Confirm,
    /// `AppModel` pushes the typed [`RemoveErrorOutcome`] back to
    /// the dialog after the `gio::spawn_blocking
    /// Vault::mutate_and_save(|v| v.remove(...))` worker reports a
    /// failure. Symmetric partner of
    /// [`crate::rename_dialog::RenameDialogMsg::WorkerFailed`] on
    /// the remove path: the dialog stores the typed outcome on
    /// [`RemoveDialogState::worker_outcome`] so the body can route
    /// `RestorePrior` (render the inline error), `KeepRemovedWithWarning`
    /// (render the warning beneath the confirmation), or the
    /// defensive `InlineError` (render the typed error) without
    /// re-deriving the routing off the [`PaladinError`].
    ///
    /// Unlike the rename variant, there is no draft to roll back —
    /// the confirmation body is immutable, so `apply_msg` only
    /// stores the outcome.
    WorkerFailed(RemoveErrorOutcome),
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
    /// Remove button pressed. Carries the stable [`AccountId`] the
    /// dialog was seeded with so the `AppModel` worker dispatch
    /// targets the same account the kebab activation resolved.
    /// `AppModel` hands the id to the `gio::spawn_blocking
    /// Vault::mutate_and_save(|v| v.remove(account_id))` worker.
    SubmitConfirm {
        /// Stable identifier of the account being removed. Copied
        /// off [`RemoveDialogState::account_id`] so a mid-flight
        /// click never retargets the remove.
        account_id: AccountId,
    },
}

/// Apply an inbound [`RemoveDialogMsg`] to `state` and return the
/// optional [`RemoveDialogOutput`] the widget layer should forward
/// to `AppModel`.
///
/// Pulled out of [`RemoveDialogComponent::update`] so the routing
/// decisions — [`RemoveDialogMsg::Cancel`] emits
/// [`RemoveDialogOutput::Cancel`] without touching state;
/// [`RemoveDialogMsg::Confirm`] clears the cached worker outcome
/// and forwards [`RemoveDialogOutput::SubmitConfirm`] with the
/// state's stable account id; [`RemoveDialogMsg::WorkerFailed`]
/// stores the typed [`RemoveErrorOutcome`] on
/// [`RemoveDialogState::worker_outcome`] so the dialog body
/// re-renders it on the next view pass — stay unit-testable in
/// `tests/remove_dialog_logic.rs` without spinning up GTK.
pub fn apply_msg(
    state: &mut RemoveDialogState,
    msg: RemoveDialogMsg,
) -> Option<RemoveDialogOutput> {
    match msg {
        RemoveDialogMsg::Cancel => Some(RemoveDialogOutput::Cancel),
        RemoveDialogMsg::Confirm => {
            // Clear any prior worker outcome so the body does not
            // render stale post-effect text alongside the live
            // attempt — the worker will refresh `worker_outcome` on
            // failure via `WorkerFailed`, and on success the dialog
            // is dropped before the next view pass.
            state.worker_outcome = None;
            Some(RemoveDialogOutput::SubmitConfirm {
                account_id: state.account_id(),
            })
        }
        RemoveDialogMsg::WorkerFailed(outcome) => {
            // `RemoveDialog` has no editable draft to roll back —
            // `mutate_and_save` already restored the in-memory
            // account on `save_not_committed`, so the dialog body
            // only needs the typed outcome to re-render. Symmetric
            // partner of `RenameDialogMsg::WorkerFailed` minus the
            // `set_draft(prior_label)` rollback step.
            state.worker_outcome = Some(outcome);
            None
        }
    }
}

/// Widget-bearing dialog for the
/// [`crate::account_list::AccountListOutput::OpenRemoveDialog`]
/// branch.
///
/// Mounts a libadwaita [`adw::StatusPage`] that surfaces the
/// targeted account's `<issuer>:<label>` heading so the user can
/// confirm which row will be removed, plus Cancel / Remove buttons
/// that drive the `Vault::mutate_and_save(|v| v.remove(...))` worker
/// in `AppModel` via [`RemoveDialogOutput`]. Mirrors the
/// [`crate::rename_dialog::RenameDialogComponent`] pattern.
pub struct RemoveDialogComponent {
    /// Pure-logic state machine. `apply_msg` mutates this in place;
    /// the widget reads back through accessors for re-renders.
    state: RemoveDialogState,
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
                set_icon_name: Some(format_remove_dialog_icon_name()),
                set_title: format_remove_dialog_title(),
                set_description: Some(&format_remove_dialog_subtitle(
                    model.state.display_label(),
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
                    set_label: format_remove_dialog_cancel_label(),
                    connect_clicked[sender] => move |_| {
                        sender.input(RemoveDialogMsg::Cancel);
                    },
                },

                // `destructive-action` CSS class renders the button in the
                // platform's destructive red so the irreversible operation
                // is visually distinct from the Cancel affordance.
                #[name = "remove_button"]
                gtk::Button {
                    set_label: format_remove_dialog_remove_label(),
                    add_css_class: "destructive-action",
                    connect_clicked[sender] => move |_| {
                        sender.input(RemoveDialogMsg::Confirm);
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
        let model = RemoveDialogComponent {
            state: RemoveDialogState::new(&init),
        };
        let widgets = view_output!();
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
