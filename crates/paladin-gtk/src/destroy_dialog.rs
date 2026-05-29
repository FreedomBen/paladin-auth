// SPDX-License-Identifier: AGPL-3.0-or-later

//! Destroy-dialog pure-logic state machine and widget for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"`DestroyDialog`
//! (Milestone 10 ...)" and `docs/DESIGN.md` §4.3 / §7,
//! `DestroyDialog` is the irreversible-action confirmation gate
//! before calling [`paladin_core::destroy_vault`]. The widget layer
//! hosts the destructive `AdwAlertDialog` chrome; the pure-logic
//! helpers here own the warning-body sourcing (a single call to
//! [`paladin_core::format_destroy_warning`] so the wording matches
//! the CLI / TUI verbatim), the `vault.bin.bak` probe, the
//! `yes`-confirmation gating, the worker body, and the post-effect
//! routing so they can be unit-tested in
//! `tests/destroy_dialog_logic.rs` without spinning up GTK /
//! libadwaita.
//!
//! # Warning body
//!
//! [`format_destroy_dialog_body`] returns
//! `paladin_core::format_destroy_warning(path, backup_present)`
//! verbatim — the GTK side never re-implements the wording. The
//! `backup_present` flag is populated on mount by
//! [`probe_backup_present`], which probes the sibling
//! `vault.bin.bak` via [`Path::try_exists`] and falls back to the
//! cautious `false` on any I/O error so the dialog never claims a
//! backup it cannot confirm.
//!
//! # Confirmation gating
//!
//! [`format_destroy_dialog_destructive_response_enabled`] enables the
//! destructive `destroy` response only when the confirmation buffer
//! reads exactly `yes` after a Unicode-whitespace trim and the busy
//! latch is clear — the same `yes` gate the CLI `destroy` command
//! enforces on stdin.
//!
//! # Post-effect routing
//!
//! [`classify_destroy_error`] maps a non-`VaultMissing`
//! [`PaladinError`] from a failed [`paladin_core::destroy_vault`]
//! onto the inline-error renderer so the dialog stays open and the
//! user can retry. `VaultMissing` is routed as its own
//! [`DestroyWorkerEffect::VaultMissing`] at the worker layer (the
//! destroy is idempotent — an absent primary is "already gone", not
//! an error). The success / vault-gone projections are aggregated
//! into a [`crate::app::state::DestroyDispatch`] by
//! [`crate::app::state::compose_destroy_dispatch`].

use std::path::{Path, PathBuf};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use paladin_core::{destroy_vault, format_destroy_warning, DestroyReport, ErrorKind, PaladinError};

// ---------------------------------------------------------------------------
// Backup probe
// ---------------------------------------------------------------------------

/// Sibling backup suffix appended to the vault path. Mirrors the
/// `paladin_core` storage layer's `.bak` rotation convention so the
/// probe checks the same file `destroy_vault` will unlink.
const BACKUP_SUFFIX: &str = ".bak";

/// Resolve the sibling backup path for a vault path by appending the
/// [`BACKUP_SUFFIX`].
///
/// Pure — mirrors the `paladin_core` storage `backup_path_for`
/// convention (`vault.bin` → `vault.bin.bak`) without reaching into
/// the core crate's private helper.
#[must_use]
pub fn backup_path_for(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.as_os_str().to_os_string();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

/// Probe whether `vault.bin.bak` exists alongside `vault_path`.
///
/// Returns `true` when the sibling backup is present, `false` when it
/// is absent, and the cautious `false` on any [`Path::try_exists`]
/// I/O error (e.g. an unreadable parent directory) so the dialog
/// never claims a backup it cannot confirm. The widget calls this on
/// mount to populate [`DestroyDialogInit::backup_present`]; the
/// pure-logic tests call it against tempfile-backed fixtures.
#[must_use]
pub fn probe_backup_present(vault_path: &Path) -> bool {
    let bak = backup_path_for(vault_path);
    bak.try_exists().unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Inline error projection
// ---------------------------------------------------------------------------

/// Inline-error projection for the `DestroyDialog` body.
///
/// Carries the stable §5 [`ErrorKind`] for instrumentation and the
/// rendered body for display. No source-error reference is kept so
/// the model can be cloned freely into the dialog's reactive state.
/// Mirrors [`crate::remove_dialog::InlineError`].
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
}

/// Post-effect routing decision for a failed
/// [`paladin_core::destroy_vault`].
///
/// `DestroyDialog` has a single failure shape — every typed error
/// other than `VaultMissing` (which the worker routes as its own
/// [`DestroyWorkerEffect::VaultMissing`]) stays inline and keeps the
/// dialog open. The single-variant enum is kept (rather than a bare
/// [`InlineError`]) so a future routing refinement can add a variant
/// without an `_` catch-all silently swallowing it, paralleling
/// [`crate::remove_dialog::RemoveErrorOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestroyErrorOutcome {
    /// The destroy failed with a typed error
    /// (`vault_file_is_symlink`, `backup_file_is_symlink`,
    /// `unlink_vault_file`, `unlink_backup_file`, `fsync_vault_dir`,
    /// or any other defensive typed variant). The dialog stays open
    /// and renders the inline error; the user can retype `yes` to
    /// retry.
    InlineError(InlineError),
}

/// Classify a [`paladin_core::destroy_vault`] failure into a
/// [`DestroyErrorOutcome`].
///
/// Every typed error renders inline — the symlink / unlink / fsync
/// `io_error` and `DestroyIoError` variants all surface the same way
/// (an inline error row beneath the warning body), and any other
/// typed variant falls through to the same inline rendering so the
/// dialog never silently transitions out. `VaultMissing` is handled
/// at the worker layer ([`run_destroy_worker`]) and never reaches
/// this classifier in practice, but the function is total so a
/// defensive caller still gets an inline projection.
#[must_use]
pub fn classify_destroy_error(err: &PaladinError) -> DestroyErrorOutcome {
    DestroyErrorOutcome::InlineError(InlineError::from_error(err))
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// Outcome of [`run_destroy_worker`] for `AppModel::update` to apply.
///
/// Unlike the mutating dialogs (add / edit / remove / settings /
/// passphrase), the destroy worker does **not** return a
/// `(Vault, Store)` pair — the destroy is terminal, so the held pair
/// is dropped by the model on success. The worker returns one of the
/// three terminal projections so `AppModel::update` can dispatch on
/// the unified outcome without re-deriving the routing off the
/// [`PaladinError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestroyWorkerEffect {
    /// [`paladin_core::destroy_vault`] returned `Ok(report)`. The
    /// dialog dismisses, the held vault drops, and the app
    /// transitions to `Missing` with a backup-aware success toast.
    Success(DestroyReport),
    /// [`paladin_core::destroy_vault`] returned
    /// [`PaladinError::VaultMissing`] — the primary was already
    /// absent (idempotent; no `.bak` touched). Treated as
    /// "already gone": the app still transitions to `Missing` with
    /// the `Vault already gone.` toast.
    VaultMissing,
    /// [`paladin_core::destroy_vault`] returned any other typed
    /// failure. The carried [`DestroyErrorOutcome`] tells the dialog
    /// to render the inline error and stay open.
    Failure(DestroyErrorOutcome),
}

/// Synchronous body of the `gio::spawn_blocking
/// paladin_core::destroy_vault(path)` worker fired by
/// `AppModel::update` from
/// `AppMsg::DestroyVault { path }`.
///
/// Consumes the resolved vault `path` by value, calls
/// [`paladin_core::destroy_vault`], and maps the result into a
/// [`DestroyWorkerEffect`]: `Ok(report)` →
/// [`DestroyWorkerEffect::Success`]; [`PaladinError::VaultMissing`]
/// → [`DestroyWorkerEffect::VaultMissing`]; any other error →
/// [`DestroyWorkerEffect::Failure`] via [`classify_destroy_error`].
///
/// Extracting the worker body as a pure function lets
/// `AppModel::update`'s closure stay a thin
/// `gio::spawn_blocking(move || run_destroy_worker(path))` while the
/// real `destroy_vault` call stays unit-testable in
/// `tests/destroy_dialog_logic.rs` against tempfile-backed vaults —
/// no GTK / libadwaita main loop required.
///
/// Takes the path by value (rather than `&Path`) so the
/// `gio::spawn_blocking(move || run_destroy_worker(path))` closure can
/// own it across the blocking-pool hop; `destroy_vault` only borrows
/// it internally.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn run_destroy_worker(path: PathBuf) -> DestroyWorkerEffect {
    match destroy_vault(&path) {
        Ok(report) => DestroyWorkerEffect::Success(report),
        Err(PaladinError::VaultMissing) => DestroyWorkerEffect::VaultMissing,
        Err(err) => DestroyWorkerEffect::Failure(classify_destroy_error(&err)),
    }
}

// ---------------------------------------------------------------------------
// Static wording / response-id pins
// ---------------------------------------------------------------------------

/// Smoke-test stdout marker prefix for a mounted
/// [`DestroyDialogComponent`].
pub const DESTROY_DIALOG_MARKER_PREFIX: &str = "paladin-gtk: destroy_dialog_path=";

/// Format the smoke-test stdout marker line for a mounted
/// [`DestroyDialogComponent`].
///
/// The marker is
/// `paladin-gtk: destroy_dialog_path=<path> backup_present=<bool>`.
#[must_use]
pub fn format_destroy_dialog_marker(path: &Path, backup_present: bool) -> String {
    format!(
        "{DESTROY_DIALOG_MARKER_PREFIX}{} backup_present={backup_present}",
        path.display(),
    )
}

/// Heading for the destroy `AdwAlertDialog` (`set_heading`).
///
/// Matches the GNOME-HIG irreversible-action phrasing. Pure —
/// returns a `'static str`.
#[must_use]
pub fn format_destroy_dialog_heading() -> &'static str {
    "Delete vault?"
}

/// Label for the destructive `destroy` response (`add_response`).
///
/// Pure — returns a `'static str`.
#[must_use]
pub fn format_destroy_dialog_destroy_label() -> &'static str {
    "Delete"
}

/// Label for the `cancel` response (`add_response`).
///
/// Pure — returns a `'static str`.
#[must_use]
pub fn format_destroy_dialog_cancel_label() -> &'static str {
    "Cancel"
}

/// Title for the `AdwEntryRow` confirmation field.
///
/// Pure — returns a `'static str`.
#[must_use]
pub fn format_destroy_dialog_confirmation_title() -> &'static str {
    "Type 'yes' to confirm"
}

/// Response id for the destructive `destroy` response.
///
/// Pure — returns a `'static str`. Sibling of
/// [`format_destroy_dialog_cancel_response_id`].
#[must_use]
pub fn format_destroy_dialog_destructive_response_id() -> &'static str {
    "destroy"
}

/// Response id for the `cancel` response (default + close response).
///
/// Pure — returns a `'static str`.
#[must_use]
pub fn format_destroy_dialog_cancel_response_id() -> &'static str {
    "cancel"
}

/// Body text for the `AdwToast` raised on the success branch.
///
/// Backup-aware: `"Vault deleted."` when the backup was deleted (or
/// there was no backup), and `"Vault deleted (backup remained on
/// disk)."` when the primary was deleted but the `.bak` survived
/// ([`DestroyReport::backup_deleted`] is `false`). Pure — returns a
/// `'static str`.
#[must_use]
pub fn format_destroy_dialog_success_toast(backup_deleted: bool) -> &'static str {
    if backup_deleted {
        "Vault deleted."
    } else {
        "Vault deleted (backup remained on disk)."
    }
}

/// Body text for the `AdwToast` raised on the `VaultMissing` branch.
///
/// Pure — returns a `'static str`.
#[must_use]
pub fn format_destroy_dialog_vault_gone_toast() -> &'static str {
    "Vault already gone."
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Construction parameters for [`DestroyDialogComponent`].
///
/// `AppModel` builds this from the resolved vault path when the
/// `app.delete-vault` action activates; `backup_present` is the
/// result of [`probe_backup_present`] on the same path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestroyDialogInit {
    /// Resolved vault path to destroy. Carried through to the worker
    /// so a mid-flight retarget is impossible.
    pub path: PathBuf,
    /// Whether `vault.bin.bak` exists alongside [`Self::path`].
    /// Drives whether the warning body mentions the backup.
    pub backup_present: bool,
}

/// Pure-logic state machine the [`DestroyDialogComponent`] shadows.
///
/// Retains the construction parameters plus the (non-secret)
/// confirmation buffer, the busy latch, and the last typed worker
/// outcome so the dialog body re-renders the inline error across
/// re-displays. Mirrors [`crate::remove_dialog::RemoveDialogState`].
#[derive(Debug, Clone)]
pub struct DestroyDialogState {
    /// Stable construction parameters.
    init: DestroyDialogInit,
    /// Shadow of the `AdwEntryRow` confirmation buffer. Non-secret
    /// (the literal string `yes`), but zeroized on lock /
    /// cancel through [`clear_for_lock`] to keep the surrounding
    /// state pattern uniform with the secret-bearing dialogs.
    confirmation: String,
    /// `true` while the destroy worker is in flight. The destructive
    /// response dims so the user cannot kick off a second worker.
    busy: bool,
    /// Last typed worker outcome. `Some` only on the inline-error
    /// branch so the dialog body re-renders it.
    worker_outcome: Option<DestroyErrorOutcome>,
}

impl DestroyDialogState {
    /// Build a fresh state from the dialog's construction parameters.
    #[must_use]
    pub fn new(init: &DestroyDialogInit) -> Self {
        Self {
            init: init.clone(),
            confirmation: String::new(),
            busy: false,
            worker_outcome: None,
        }
    }

    /// Resolved vault path the dialog targets.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.init.path
    }

    /// Whether `vault.bin.bak` is present alongside the vault.
    #[must_use]
    pub fn backup_present(&self) -> bool {
        self.init.backup_present
    }

    /// Current confirmation-buffer contents (non-secret).
    #[must_use]
    pub fn confirmation(&self) -> &str {
        &self.confirmation
    }

    /// `true` while the destroy worker is in flight.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// `true` iff the confirmation buffer reads exactly `yes` after a
    /// Unicode-whitespace trim.
    #[must_use]
    pub fn confirmation_accepted(&self) -> bool {
        self.confirmation.trim() == "yes"
    }

    /// Last typed inline error, if any.
    #[must_use]
    pub fn inline_error(&self) -> Option<&InlineError> {
        match self.worker_outcome.as_ref()? {
            DestroyErrorOutcome::InlineError(err) => Some(err),
        }
    }
}

/// Messages handled by [`DestroyDialogComponent`].
///
/// `ConfirmationChanged` arrives from the `AdwEntryRow` buffer's
/// `changed` signal; `Confirm` / `Cancel` from the dialog's
/// responses. `SetBusy` is driven by `AppModel` around the worker
/// dispatch. `WorkerFailed` is pushed back from `AppModel` after a
/// typed destroy failure so the dialog re-renders the inline error.
#[derive(Debug, Clone)]
pub enum DestroyDialogMsg {
    /// The confirmation buffer changed; shadow the new contents.
    ConfirmationChanged(String),
    /// The destructive `destroy` response fired. Clears any prior
    /// worker outcome and forwards [`DestroyDialogOutput::SubmitConfirm`]
    /// with the seeded vault path.
    Confirm,
    /// The `cancel` response (or Escape / outside-click / window
    /// close) fired. Forwards [`DestroyDialogOutput::Cancel`].
    Cancel,
    /// `AppModel` flips the busy latch around the worker dispatch.
    SetBusy(bool),
    /// `AppModel` pushes the typed [`DestroyErrorOutcome`] back after
    /// a failed destroy so the dialog re-renders the inline error.
    WorkerFailed(DestroyErrorOutcome),
}

/// Outputs forwarded from [`DestroyDialogComponent`] up to
/// `AppModel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestroyDialogOutput {
    /// User dismissed the dialog without destroying. `AppModel` drops
    /// the live controller and removes the dialog.
    Cancel,
    /// Destroy confirmed. Carries the seeded vault path so the
    /// `AppModel` worker dispatch targets the same path the dialog
    /// was constructed with.
    SubmitConfirm {
        /// Resolved vault path to destroy.
        path: PathBuf,
    },
}

/// Apply an inbound [`DestroyDialogMsg`] to `state` and return the
/// optional [`DestroyDialogOutput`] the widget layer should forward
/// to `AppModel`.
///
/// Pulled out of [`DestroyDialogComponent::update`] so the routing
/// decisions stay unit-testable in `tests/destroy_dialog_logic.rs`
/// without spinning up GTK.
pub fn apply_msg(
    state: &mut DestroyDialogState,
    msg: DestroyDialogMsg,
) -> Option<DestroyDialogOutput> {
    match msg {
        DestroyDialogMsg::ConfirmationChanged(text) => {
            state.confirmation = text;
            None
        }
        DestroyDialogMsg::Confirm => {
            // Clear any prior worker outcome so the body does not
            // render stale error text alongside a fresh attempt.
            state.worker_outcome = None;
            Some(DestroyDialogOutput::SubmitConfirm {
                path: state.init.path.clone(),
            })
        }
        DestroyDialogMsg::Cancel => Some(DestroyDialogOutput::Cancel),
        DestroyDialogMsg::SetBusy(busy) => {
            state.busy = busy;
            None
        }
        DestroyDialogMsg::WorkerFailed(outcome) => {
            state.worker_outcome = Some(outcome);
            None
        }
    }
}

/// Wipe the confirmation buffer and cached worker outcome at the
/// lock / cancel boundary.
///
/// Called by `AppModel` before dropping the live controller on
/// auto-lock or destroy teardown, mirroring
/// [`crate::edit_dialog::clear_for_lock`] /
/// [`crate::export_qr_dialog::clear_for_lock`]. The confirmation
/// string is non-secret, but zeroizing it keeps the surrounding
/// state pattern uniform.
pub fn clear_for_lock(state: &mut DestroyDialogState) {
    use zeroize::Zeroize;
    state.confirmation.zeroize();
    state.confirmation = String::new();
    state.worker_outcome = None;
    state.busy = false;
}

// ---------------------------------------------------------------------------
// Widget-facing projections
// ---------------------------------------------------------------------------

/// Warning body the widget hands to the dialog's body
/// `gtk::Label::set_label` / `AdwActionRow` rows.
///
/// Sourced verbatim from [`paladin_core::format_destroy_warning`] —
/// the GTK side never re-implements the wording, so the body is
/// byte-equal to the CLI / TUI warning for the same
/// `(path, backup_present)`.
#[must_use]
pub fn format_destroy_dialog_body(state: &DestroyDialogState) -> String {
    format_destroy_warning(state.path(), state.backup_present())
}

/// Decide whether the destructive `destroy` `AdwAlertDialog`
/// response should be enabled.
///
/// Returns `true` only when the confirmation buffer reads exactly
/// `yes` after a Unicode-whitespace trim **and** the busy latch is
/// clear. The widget drives
/// `AdwAlertDialog::set_response_enabled("destroy", …)` through this
/// projector. Pure — inspects only the confirmation buffer and the
/// busy latch.
#[must_use]
pub fn format_destroy_dialog_destructive_response_enabled(state: &DestroyDialogState) -> bool {
    !state.is_busy() && state.confirmation_accepted()
}

/// `set_label` body for the inline error row.
///
/// Returns the rendered error string when [`DestroyDialogState::inline_error`]
/// is `Some`, otherwise the empty string. Pairs with
/// [`format_destroy_dialog_inline_error_visible`].
#[must_use]
pub fn format_destroy_dialog_inline_error_text(state: &DestroyDialogState) -> &str {
    state.inline_error().map_or("", |err| err.rendered.as_str())
}

/// `set_visible` flag for the inline error row.
///
/// Returns `true` when [`DestroyDialogState::inline_error`] resolves
/// to `Some(_)` so the error row appears in the layout flow.
#[must_use]
pub fn format_destroy_dialog_inline_error_visible(state: &DestroyDialogState) -> bool {
    state.inline_error().is_some()
}

// ---------------------------------------------------------------------------
// Widget
// ---------------------------------------------------------------------------

/// Live GTK component for the destroy `AdwAlertDialog`.
///
/// Hosts the destructive `AdwAlertDialog` chrome around the pure-logic
/// [`DestroyDialogState`]. The body renders
/// [`format_destroy_dialog_body`]; an `AdwEntryRow` gates the `destroy`
/// response until the buffer reads `yes`. Routes Cancel / Confirm /
/// busy decisions through [`apply_msg`] and re-drives the destructive
/// response's enabled flag after every message.
pub struct DestroyDialogComponent {
    /// Pure-logic state machine.
    state: DestroyDialogState,
    /// Cloned root handle so [`SimpleComponent::update`] can drive
    /// `set_response_enabled` after each message.
    root: Option<adw::AlertDialog>,
}

impl DestroyDialogComponent {
    /// Borrow the pure-logic state (read-only) for the lock-transition
    /// path, mirroring the other dialogs' `state` accessor.
    #[must_use]
    pub fn state(&self) -> &DestroyDialogState {
        &self.state
    }

    /// Borrow the pure-logic state mutably so the lock-transition path
    /// can call [`clear_for_lock`] before the controller is dropped.
    pub fn state_mut(&mut self) -> &mut DestroyDialogState {
        &mut self.state
    }
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for DestroyDialogComponent {
    type Init = DestroyDialogInit;
    type Input = DestroyDialogMsg;
    type Output = DestroyDialogOutput;

    view! {
        #[root]
        adw::AlertDialog {
            set_heading: Some(format_destroy_dialog_heading()),
            #[watch]
            set_body: &format_destroy_dialog_body(&model.state),

            #[wrap(Some)]
            set_extra_child = &gtk::Box {
                set_orientation: gtk::Orientation::Vertical,
                set_spacing: 12,
                set_hexpand: true,

                adw::PreferencesGroup {
                    #[name = "confirmation_row"]
                    add = &adw::EntryRow {
                        set_title: format_destroy_dialog_confirmation_title(),
                        // `Sender::send` (not `ComponentSender::input`,
                        // which `.expect`s on a closed channel) so a
                        // stray keystroke after the controller drops is
                        // a benign no-op. See `import_dialog`'s Cancel
                        // button for the canonical comment.
                        connect_changed[sender] => move |entry| {
                            let _ = sender.input_sender().send(
                                DestroyDialogMsg::ConfirmationChanged(entry.text().to_string()),
                            );
                        },
                    },
                },

                #[name = "error_row"]
                adw::ActionRow {
                    add_css_class: "error",
                    #[watch]
                    set_visible: format_destroy_dialog_inline_error_visible(&model.state),
                    #[watch]
                    set_title: format_destroy_dialog_inline_error_text(&model.state),
                },
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut model = DestroyDialogComponent {
            state: DestroyDialogState::new(&init),
            root: None,
        };
        let widgets = view_output!();
        model.root = Some(root.clone());

        // Register the two responses imperatively after `view_output!`.
        // `add_response` must run before `set_response_appearance` /
        // `set_default_response` / `set_close_response`, which key on
        // the response id.
        let cancel_id = format_destroy_dialog_cancel_response_id();
        let destroy_id = format_destroy_dialog_destructive_response_id();
        root.add_response(cancel_id, format_destroy_dialog_cancel_label());
        root.add_response(destroy_id, format_destroy_dialog_destroy_label());
        root.set_response_appearance(destroy_id, adw::ResponseAppearance::Destructive);
        // Cancel is the default and close response so Escape /
        // outside-click / window-close dismiss without destroying.
        root.set_default_response(Some(cancel_id));
        root.set_close_response(cancel_id);
        // Destructive response starts disabled; the confirmation
        // signal re-drives it through the pure-logic projector.
        root.set_response_enabled(destroy_id, false);

        let response_sender = sender.clone();
        root.connect_response(None, move |_dialog, response| {
            if response == format_destroy_dialog_destructive_response_id() {
                let _ = response_sender
                    .input_sender()
                    .send(DestroyDialogMsg::Confirm);
            } else {
                let _ = response_sender
                    .input_sender()
                    .send(DestroyDialogMsg::Cancel);
            }
        });

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_msg(&mut self.state, msg) {
            // Ignore send failures: if `AppModel` already dropped the
            // controller there is nothing left to dismiss.
            let _ = sender.output(output);
        }
        // Re-drive the destructive response's enabled flag from the
        // pure-logic projector after every message (cheap, idempotent).
        if let Some(root) = self.root.as_ref() {
            root.set_response_enabled(
                format_destroy_dialog_destructive_response_id(),
                format_destroy_dialog_destructive_response_enabled(&self.state),
            );
        }
    }
}
