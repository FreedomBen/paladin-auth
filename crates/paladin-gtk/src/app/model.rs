// SPDX-License-Identifier: AGPL-3.0-or-later

//! Widget-bearing `AppModel` for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree", `AppModel`
//! is the relm4 root component that mounts the libadwaita
//! application window and routes the active child view by
//! [`crate::app::state::AppState`].
//!
//! This commit wires the §"Vault interaction" startup probes into
//! the model: `init` runs [`run_startup_probes`] to resolve the
//! vault path, call `paladin_core::inspect`, and (for plaintext
//! vaults) `paladin_core::Store::open` on the GTK main loop, then
//! seeds [`AppModel::state`] / [`AppModel::vault`] from the result.
//! The `AccountListComponent`, `StartupErrorComponent`,
//! `InitDialogComponent`, and `UnlockDialogComponent` branches are
//! all wired here as read-only mounts: `AccountListComponent`
//! renders the unlocked vault list, `StartupErrorComponent` renders
//! a non-mutating `AdwStatusPage` whose body text is the typed
//! [`crate::startup_error::StartupError`] projection,
//! `InitDialogComponent` renders the first-run / missing-vault
//! surface seeded with the resolved vault path, and
//! `UnlockDialogComponent` renders the encrypted-vault passphrase-
//! entry surface seeded with the resolved vault path.
//!
//! Unlock-worker dispatch is wired here: `AppMsg::UnlockDialogAction(
//! SubmitLock)` opens the busy gate via `apply_submit_unlock_inplace`,
//! and `AppMsg::UnlockWorkerCompleted(UnlockWorkerEffect)` runs the
//! bundled `compose_unlock_dispatch` projection over the cached
//! `AppState`. The composer's three side-effects — state replacement
//! via `apply_unlock_dispatch_inplace`, optional inline
//! `UnlockDialogMsg` forwarded to the live `UnlockDialogComponent`,
//! and the `drop_dialog` flag that detaches the dialog widget on
//! replacement branches (per `IMPLEMENTATION_PLAN_04_GTK.md`
//! §"Vault interaction") — fan out from a single handler. The
//! `gio::spawn_blocking paladin_core::open` worker that consumes the
//! forwarded `VaultLock` and posts `AppMsg::UnlockWorkerCompleted` on
//! completion lands in a follow-up commit.
//!
//! `AppMsg::AccountListAction(OpenRenameDialog(id))` mounts a
//! [`RenameDialogComponent`] seeded from
//! [`crate::rename_dialog::decide_rename_target`] so the kebab
//! `Rename…` action is now reachable end-to-end (kebab activation →
//! `AccountListOutput` → `AppMsg` → live dialog widget). The
//! dialog's Cancel button bubbles back here as
//! `AppMsg::RenameDialogAction(RenameDialogOutput::Cancel)`, which
//! drops the controller and removes its widget from the content
//! tree. The submit button / `Vault::mutate_and_save` worker land
//! in a follow-up commit. `OpenRemoveDialog(id)` mirrors the same
//! shape: it mounts a [`RemoveDialogComponent`] seeded from
//! [`crate::remove_dialog::decide_remove_target`] and routes its
//! Cancel button back as
//! `AppMsg::RemoveDialogAction(RemoveDialogOutput::Cancel)` so
//! `AppModel` can drop the controller and remove the dialog widget
//! from the content tree. The destructive `AdwAlertDialog` chrome,
//! the Remove button, and the `Vault::mutate_and_save` worker land
//! in follow-up commits alongside the `UnlockedBusy` worker
//! infrastructure.
//!
//! Under the hidden `--exit-after-startup` flag, the model prints
//! [`startup_state_marker`] to stdout and enqueues [`AppMsg::Quit`]
//! so `tests/gtk_smoke.rs` can assert which startup state was
//! reached under `xvfb-run` without driving widgets.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::gtk::glib;
use relm4::prelude::*;

use crate::account_list::{
    filtered_row_models_from_vault, format_rendered_marker, format_widget_states_marker,
    hidden_row_display, row_models_from_vault, selected_row_after_refresh, AccountListComponent,
    AccountListInit, AccountListMsg, AccountListOutput, AccountRowModel,
};
use crate::add_account::{
    route_qr_clipboard_loaded, run_add_worker, run_qr_worker, AddAccountComponent, AddAccountInit,
    AddAccountMsg, AddAccountOutput, AddWorkerCompletion, QrClipboardLoadedDispatch,
    QrWorkerCompletion,
};
use crate::app::state::{
    apply_add_dispatch_inplace, apply_add_vault_install_inplace, apply_export_dispatch_inplace,
    apply_export_vault_install_inplace, apply_import_dispatch_inplace,
    apply_import_vault_install_inplace, apply_qr_dispatch_inplace, apply_remove_dispatch_inplace,
    apply_remove_vault_install_inplace, apply_rename_dispatch_inplace,
    apply_rename_vault_install_inplace, apply_submit_add_inplace, apply_submit_export_inplace,
    apply_submit_import_inplace, apply_submit_remove_inplace, apply_submit_rename_inplace,
    apply_submit_unlock_inplace, apply_unlock_dispatch_inplace, apply_unlock_vault_install_inplace,
    compose_add_dispatch, compose_add_worker_input, compose_export_dispatch,
    compose_export_worker_input, compose_import_dispatch, compose_import_worker_input,
    compose_qr_dispatch, compose_qr_worker_input, compose_remove_dispatch,
    compose_remove_worker_input, compose_rename_dispatch, compose_rename_worker_input,
    compose_unlock_dispatch, compose_unlock_worker_input, decide_state_from_inspect,
    decide_state_from_open_error, run_unlock_worker, AppState, OpenErrorOutcome,
    UnlockWorkerCompletion,
};
use crate::clipboard_clear::{
    evaluate_wake, prepare_copy_bytes, schedule_copy, PendingClipboardClear, WakeDecision,
};
use crate::export_dialog::{
    run_export_worker, ExportDialogComponent, ExportDialogInit, ExportDialogMsg,
    ExportDialogOutput, ExportWorkerCompletion,
};
use crate::hotp_reveal::{
    apply_advance_decision, apply_advance_outcome, expired_reveals,
    format_hotp_advance_failed_toast, format_hotp_durability_unconfirmed_toast,
    row_display_for_reveal, run_hotp_advance_worker, HotpAdvanceWorkerCompletion,
    HotpAdvanceWorkerInput, RevealEffect, RevealWindow,
};
use crate::import_dialog::{
    run_import_worker, ImportDialogComponent, ImportDialogInit, ImportDialogOutput,
    ImportWorkerCompletion,
};
use crate::init_dialog::{
    format_init_dialog_marker, run_init_worker, InitDialogComponent, InitDialogInit, InitDialogMsg,
    InitDialogOutput, InitWorkerCompletion, InitWorkerEffect, InitWorkerInput, InitWorkerMode,
};
use crate::passphrase_dialog::{
    PassphraseDialogComponent, PassphraseDialogInit, PassphraseDialogOutput,
};
use crate::remove_dialog::{
    decide_remove_target, run_remove_worker, RemoveDialogComponent, RemoveDialogOutput,
    RemoveWorkerCompletion,
};
use crate::rename_dialog::{
    decide_rename_target, run_rename_worker, RenameDialogComponent, RenameDialogOutput,
    RenameWorkerCompletion,
};
use crate::settings::{
    CommittedSettings, SettingsComponent, SettingsDialogInit, SettingsDialogOutput,
};
use crate::startup_error::{
    format_startup_error_marker, StartupError, StartupErrorComponent, StartupErrorInit,
    StartupErrorOutput,
};
use crate::ticker::{tick, tick_interval, ticker_transition, TickerTransition};
use crate::unlock_dialog::{
    format_unlock_dialog_marker, UnlockDialogComponent, UnlockDialogInit, UnlockDialogOutput,
};

/// Construction parameters for [`AppModel`].
///
/// The fields are plumbed through so the next commit can run the
/// startup probes inside [`SimpleComponent::init`] without changing
/// the call site in `lib.rs::run`.
#[derive(Debug, Clone)]
pub struct AppInit {
    /// Vault path override from `--vault <PATH>`. `None` means the
    /// app falls back to `paladin_core::default_vault_path()` on
    /// startup.
    pub vault_path: Option<PathBuf>,
    /// Hidden smoke-test flag: when `true`, `AppMsg::Quit` is
    /// enqueued after the first widget mount so
    /// `tests/gtk_smoke.rs` can exit cleanly under `xvfb-run`.
    /// Production launches always pass `false`.
    pub exit_after_startup: bool,
}

/// Outcome of [`run_startup_probes`].
///
/// `state` is always populated. `vault` carries the live
/// `(Vault, Store)` pair only when the plaintext-open branch
/// succeeded — every other branch (`Missing` / `Locked` / `StartupError`)
/// owns no vault and leaves it `None`.
pub struct StartupOutcome {
    /// Resolved initial [`AppState`].
    pub state: AppState,
    /// Live `(Vault, Store)` pair when a plaintext vault was opened.
    pub vault: Option<(paladin_core::Vault, paladin_core::Store)>,
}

/// Top-level relm4 component for `paladin-gtk`.
///
/// Owns the resolved vault path override plus the [`AppState`] that
/// drives which child view is rendered. The live `(Vault, Store)`
/// pair lives in [`AppModel::vault`] alongside the state machine
/// per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree".
pub struct AppModel {
    /// Vault path override from [`AppInit`]. Preserved for the
    /// `StartupErrorComponent` retry action wired by a follow-up
    /// commit; an override given via `--vault` should win on retry.
    #[allow(dead_code)]
    vault_path: Option<PathBuf>,
    /// Cached `AppState` seeded by [`run_startup_probes`] in `init`.
    #[allow(dead_code)]
    state: Option<AppState>,
    /// Live `(Vault, Store)` pair when [`AppModel::state`] is
    /// `Unlocked` / `UnlockedBusy`; `None` for every other state.
    /// `Vault` does not implement `Debug` (its secrets would leak),
    /// so [`AppModel`]'s manual `Debug` impl below redacts it.
    #[allow(dead_code)]
    vault: Option<(paladin_core::Vault, paladin_core::Store)>,
    /// Live [`AccountListComponent`] controller when the unlocked
    /// list view is mounted. `None` for every non-`Unlocked` state.
    /// Held on `self` so the controller (and therefore the rendered
    /// `gtk::ListView` / its backing `gio::ListStore`) is not
    /// dropped at the end of `init`.
    #[allow(dead_code)]
    account_list: Option<Controller<AccountListComponent>>,
    /// Live [`StartupErrorComponent`] controller when `AppModel`
    /// routed to [`AppState::StartupError`]. `None` for every
    /// non-error state. Held on `self` so the rendered
    /// `AdwStatusPage` is not dropped at the end of `init`.
    #[allow(dead_code)]
    startup_error: Option<Controller<StartupErrorComponent>>,
    /// Live [`InitDialogComponent`] controller when `AppModel`
    /// routed to [`AppState::Missing`]. `None` for every
    /// non-missing state. Held on `self` so the rendered widget is
    /// not dropped at the end of `init`.
    #[allow(dead_code)]
    init_dialog: Option<Controller<InitDialogComponent>>,
    /// Live [`UnlockDialogComponent`] controller when `AppModel`
    /// routed to [`AppState::Locked`]. `None` for every
    /// non-locked state. Held on `self` so the rendered widget is
    /// not dropped at the end of `init`.
    #[allow(dead_code)]
    unlock_dialog: Option<Controller<UnlockDialogComponent>>,
    /// Live [`RenameDialogComponent`] controller when the user has
    /// activated a row's kebab `Rename…` action. `None` between
    /// activations. Held on `self` so the rendered widget is not
    /// dropped at the end of the [`AppMsg::AccountListAction`]
    /// handler.
    #[allow(dead_code)]
    rename_dialog: Option<Controller<RenameDialogComponent>>,
    /// Live [`RemoveDialogComponent`] controller when the user has
    /// activated a row's kebab `Remove…` action. `None` between
    /// activations. Held on `self` so the rendered widget is not
    /// dropped at the end of the [`AppMsg::AccountListAction`]
    /// handler.
    #[allow(dead_code)]
    remove_dialog: Option<Controller<RemoveDialogComponent>>,
    /// Live [`AddAccountComponent`] controller when the user has
    /// activated the header-bar `+` button. `None` between
    /// activations. Held on `self` so the rendered widget is not
    /// dropped at the end of the [`AppMsg::OpenAddDialog`] handler.
    #[allow(dead_code)]
    add_dialog: Option<Controller<AddAccountComponent>>,
    /// Live [`SettingsComponent`] controller when the user has
    /// activated the application menu's Preferences entry. `None`
    /// between activations. Held on `self` so the rendered
    /// `AdwPreferencesDialog` is not dropped at the end of the
    /// [`AppMsg::OpenPreferencesDialog`] handler.
    #[allow(dead_code)]
    settings_dialog: Option<Controller<SettingsComponent>>,
    /// Live [`ImportDialogComponent`] controller when the user has
    /// activated the application menu's Import… entry. `None`
    /// between activations. Held on `self` so the rendered
    /// `adw::Dialog` is not dropped at the end of the
    /// [`AppMsg::OpenImportDialog`] handler.
    #[allow(dead_code)]
    import_dialog: Option<Controller<ImportDialogComponent>>,
    /// Live [`ExportDialogComponent`] controller when the user has
    /// activated the application menu's Export… entry. `None`
    /// between activations. Held on `self` so the rendered
    /// `adw::Dialog` is not dropped at the end of the
    /// [`AppMsg::OpenExportDialog`] handler.
    #[allow(dead_code)]
    export_dialog: Option<Controller<ExportDialogComponent>>,
    /// Live [`PassphraseDialogComponent`] controller when the user
    /// has activated the application menu's Passphrase… entry.
    /// `None` between activations. Held on `self` so the rendered
    /// `adw::Dialog` is not dropped at the end of the
    /// [`AppMsg::OpenPassphraseDialog`] handler.
    #[allow(dead_code)]
    passphrase_dialog: Option<Controller<PassphraseDialogComponent>>,
    /// Reference-counted handle to the window's content box.
    ///
    /// `gtk::Box` is a `GObject`, so cloning it just bumps the
    /// reference count rather than duplicating the widget. The clone
    /// lets [`AppMsg::AccountListAction`] reach the content tree from
    /// `update` so kebab-driven dialog mounts
    /// (`RenameDialogComponent` / `RemoveDialogComponent`) can append
    /// themselves to the active view.
    #[allow(dead_code)]
    content: gtk::Box,
    /// Cached search query mirroring [`AccountListComponent`]'s
    /// `current_query`. Updated when
    /// [`crate::account_list::AccountListOutput::QueryChanged`]
    /// bubbles up so the post-mutation refresh path
    /// ([`AppModel::refresh_account_list`]) can re-filter the live
    /// vault through `paladin_core::account_matches_search` without
    /// asking the controller for its current entry text. The
    /// `AccountListComponent` controller is dropped (and the cache
    /// reset to the empty string in the next mount) when the vault
    /// locks, so there is no observable cross-vault query leak.
    search_query: String,
    /// Live `glib::timeout_add_local` source for the TOTP ticker.
    ///
    /// Installed by [`AppModel::apply_ticker_transition`] when the
    /// app enters `Unlocked` / `UnlockedBusy` with at least one
    /// visible TOTP row; torn down on transitions back to `Locked`,
    /// `Missing`, or `StartupError`, and on `Quit`. The source ID
    /// is stored as an [`Option`] because `glib::SourceId::remove`
    /// takes the source by value (the consumed `SourceId` cannot
    /// be re-removed). See `IMPLEMENTATION_PLAN_04_GTK.md`
    /// §"Milestone 7 checklist" > TOTP ticker.
    ticker_source: Option<glib::SourceId>,
    /// Open HOTP reveal windows keyed by [`paladin_core::AccountId`].
    ///
    /// Each entry's `code` field is wrapped in `Zeroizing<String>` so
    /// dropping a window (replace on a re-press, expiry on the
    /// ticker, or full map clear on `Locked` / `Quit`) zeroes the
    /// visible digits in place. `AppModel::update` mutates the map
    /// via [`apply_advance_decision`] on `HotpAdvanceWorkerCompleted`
    /// and via [`expired_reveals`] on every `Tick`. See
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
    /// "HOTP reveal window behavior".
    reveal_windows: HashMap<paladin_core::AccountId, RevealWindow>,
    /// Reference-counted handle to the window's `adw::ToastOverlay`.
    ///
    /// `adw::ToastOverlay` is a `GObject`, so cloning it just bumps
    /// the reference count rather than duplicating the widget. The
    /// clone lets `AppModel::update` raise toasts (HOTP durability-
    /// unconfirmed warning, HOTP advance failure) from the worker-
    /// completion arms without rebuilding the overlay reference.
    #[allow(dead_code)]
    toast_overlay: adw::ToastOverlay,
    /// Pending wipe-after-copy slot for the clipboard auto-clear
    /// policy.
    ///
    /// Set by [`AppMsg::AccountListAction(AccountListOutput::CopyCode)`]
    /// when the user has opted in via
    /// `VaultSettings::clipboard_clear_enabled` and the live
    /// `gdk::Clipboard::set_text` write succeeded; cleared on
    /// [`crate::clipboard_clear::WakeDecision::Clear`] /
    /// [`crate::clipboard_clear::WakeDecision::Mismatch`] outcomes
    /// from the per-tick wake (the captured bytes are zeroized via
    /// `Zeroizing<Vec<u8>>` on drop) and on `Locked` / `Quit`
    /// transitions for parity with [`Self::reveal_windows`]. See
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
    /// `AccountRowComponent` copy button.
    pending_clipboard: Option<PendingClipboardClear>,
    /// Last `AppState::is_busy()` value dispatched to the live
    /// [`AccountListComponent`] via [`AccountListMsg::SetBusy`].
    ///
    /// Tracked here so [`AppModel::sync_account_list_busy`] can
    /// debounce — the per-dispatch reconcile only emits the message
    /// when the busy flag actually flips, avoiding a redundant
    /// row-store splice on every steady-state update. Initialized to
    /// `false` because every startup path ([`AppState::Missing`],
    /// [`AppState::Locked`], [`AppState::Unlocked`],
    /// [`AppState::StartupError`]) yields `is_busy() == false`.
    last_account_list_busy: bool,
    /// Last `AppState::is_busy()` value dispatched to the live
    /// [`AddAccountComponent`] via [`AddAccountMsg::SetBusy`].
    ///
    /// Tracked here so [`AppModel::sync_add_dialog_busy`] can
    /// debounce — the per-dispatch reconcile only emits the message
    /// when the busy flag actually flips. The
    /// `Unlocked → UnlockedBusy` transition that brackets the
    /// `gio::spawn_blocking Vault::mutate_and_save(|v| v.add(...))`
    /// worker drives the dialog's Save-button gate per
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership";
    /// the debounce avoids a redundant view tick on every
    /// steady-state dispatch (e.g. search-query changes while the
    /// Add dialog is not mounted). Initialized to `false` for the
    /// same reason as [`Self::last_account_list_busy`].
    last_add_dialog_busy: bool,
}

impl std::fmt::Debug for AppModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppModel")
            .field("vault_path", &self.vault_path)
            .field("state", &self.state)
            .field("vault", &self.vault.as_ref().map(|_| "<redacted>"))
            .field(
                "account_list",
                &self.account_list.as_ref().map(|_| "<mounted>"),
            )
            .field(
                "startup_error",
                &self.startup_error.as_ref().map(|_| "<mounted>"),
            )
            .field(
                "init_dialog",
                &self.init_dialog.as_ref().map(|_| "<mounted>"),
            )
            .field(
                "unlock_dialog",
                &self.unlock_dialog.as_ref().map(|_| "<mounted>"),
            )
            .field(
                "rename_dialog",
                &self.rename_dialog.as_ref().map(|_| "<mounted>"),
            )
            .field(
                "remove_dialog",
                &self.remove_dialog.as_ref().map(|_| "<mounted>"),
            )
            .field("add_dialog", &self.add_dialog.as_ref().map(|_| "<mounted>"))
            .field(
                "settings_dialog",
                &self.settings_dialog.as_ref().map(|_| "<mounted>"),
            )
            .field(
                "import_dialog",
                &self.import_dialog.as_ref().map(|_| "<mounted>"),
            )
            .field(
                "export_dialog",
                &self.export_dialog.as_ref().map(|_| "<mounted>"),
            )
            .field(
                "passphrase_dialog",
                &self.passphrase_dialog.as_ref().map(|_| "<mounted>"),
            )
            .field("content", &"<gtk::Box>")
            .field("search_query", &self.search_query)
            .field(
                "ticker_source",
                &self.ticker_source.as_ref().map(|_| "<installed>"),
            )
            .field(
                "reveal_windows",
                &format!("<{} open>", self.reveal_windows.len()),
            )
            .field("toast_overlay", &"<adw::ToastOverlay>")
            .field(
                "pending_clipboard",
                &self.pending_clipboard.as_ref().map(|_| "<armed>"),
            )
            .field("last_account_list_busy", &self.last_account_list_busy)
            .field("last_add_dialog_busy", &self.last_add_dialog_busy)
            .finish()
    }
}

/// Messages handled by [`AppModel`].
#[derive(Debug)]
pub enum AppMsg {
    /// Tear down the GTK main loop. Routed through
    /// `relm4::main_application().quit()` so any pending `GLib`
    /// idle callbacks see the shutdown rather than being dropped
    /// mid-flight.
    Quit,
    /// Forwarded from [`AccountListComponent`] when the user
    /// activates a row's kebab Rename… / Remove… action.
    ///
    /// `AppModel` is the owner of the dialog widget tree per
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree", so the
    /// per-row actions bubble the row's [`paladin_core::AccountId`]
    /// up here for the dialog mount to consume.
    /// `OpenRenameDialog(id)` and `OpenRemoveDialog(id)` each mount
    /// their widget-bearing controller (`RenameDialogComponent` /
    /// `RemoveDialogComponent`) seeded from the live vault via
    /// [`decide_rename_target`] / [`decide_remove_target`]; the
    /// editable / destructive chrome and the `Vault::mutate_and_save`
    /// workers land in follow-up commits.
    AccountListAction(AccountListOutput),
    /// Posted by the header-bar search-toggle `gtk::ToggleButton`'s
    /// `connect_toggled` handler with the toggle's new `is_active`
    /// state. The handler routes through [`format_app_search_toggle_msg`]
    /// to emit [`AccountListMsg::SetSearchModeEnabled`] on the live
    /// [`AccountListComponent`] controller so the `gtk::SearchBar`
    /// reveals / hides in lockstep with the toggle. The search-toggle
    /// button is only visible per [`format_app_search_button_visible`]
    /// when the vault is open, so this message arriving in any other
    /// state is a benign no-op — `AppModel` drops it when
    /// [`AppModel::account_list`] is `None`.
    SearchToggled(bool),
    /// Forwarded from the live [`RenameDialogComponent`] when the
    /// user interacts with the dialog. Today only
    /// [`RenameDialogOutput::Cancel`] is emitted — `AppModel`
    /// responds by dropping the controller and removing the dialog
    /// widget from the content tree. Save / worker outputs are
    /// added in the follow-up commit that wires
    /// `Vault::mutate_and_save` through the `UnlockedBusy` worker.
    RenameDialogAction(RenameDialogOutput),
    /// Forwarded from the live [`RemoveDialogComponent`] when the
    /// user interacts with the dialog. Today only
    /// [`RemoveDialogOutput::Cancel`] is emitted — `AppModel`
    /// responds by dropping the controller and removing the dialog
    /// widget from the content tree. Confirm / worker outputs are
    /// added in the follow-up commit that wires
    /// `Vault::mutate_and_save` through the `UnlockedBusy` worker.
    RemoveDialogAction(RemoveDialogOutput),
    /// Posted by the header-bar `+` button click handler. Mounts a
    /// fresh [`AddAccountComponent`] seeded with the resolved vault
    /// path so the manual / URI / QR sub-paths can commit a new
    /// account via `Vault::mutate_and_save(|v| v.add(...))` on
    /// submit. Today only the Cancel button is wired — the editable
    /// form widgets and the worker spawn land in follow-up commits.
    ///
    /// Defensive: dispatched only when [`AppState::is_unlocked`] is
    /// `true` and a live `(Vault, Store)` pair is present. A click
    /// arriving in any other state (the `+` button is hidden, but a
    /// stray dispatch from a future keyboard shortcut would still
    /// land here) is a benign no-op.
    OpenAddDialog,
    /// Posted by the application menu's "About Paladin" entry's
    /// `connect_activate` handler. Mounts the
    /// [`adw::AboutDialog`] built by [`build_app_about_dialog`]
    /// parented at the active [`adw::ApplicationWindow`] so the
    /// dialog overlays the main window per §"libadwaita usage".
    ///
    /// About is always enabled — `format_app_menu_about_action`'s
    /// sensitivity rule is `true` in every state — so this
    /// dispatch can arrive in `Missing` / `Locked` /
    /// `Unlocked` / `UnlockedBusy` / `StartupError`. The
    /// handler is non-mutating: it does not touch the vault,
    /// the cached `AppState`, or any dialog controller, so the
    /// dispatch is benign in every state.
    OpenAboutDialog,
    /// Posted by the application menu's Preferences entry's
    /// `connect_activate` handler. Mounts the
    /// [`SettingsComponent`](crate::settings) — an
    /// [`adw::PreferencesDialog`] exposing the §4.7
    /// [`paladin_core::VaultSettings`] toggles + spinners with
    /// live-apply — parented at the active
    /// [`adw::ApplicationWindow`] so the dialog overlays the
    /// main window per §"libadwaita usage".
    ///
    /// Preferences is gated by
    /// [`format_app_primary_menu_action_sensitivities`]'s
    /// mutating-menu rule
    /// ([`crate::app::state::AppState::allows_mutating_menu`])
    /// so the action is disabled outside
    /// [`AppState::Unlocked`]. A stray dispatch in any other
    /// state (the action is disabled, but a stray dispatch from
    /// a future keyboard accelerator would still land here) is
    /// defensively guarded in the handler so the dialog never
    /// mounts over a `Missing` / `Locked` / `UnlockedBusy` /
    /// `StartupError` window.
    ///
    /// The fully wired [`SettingsComponent`](crate::settings)
    /// (the editable form widgets, the
    /// [`paladin_core::Vault::mutate_and_save`] live-apply
    /// worker, and the inline error / warning surfaces) lands
    /// in follow-up commits; this commit only wires the dispatch
    /// edge so the menu activation reaches `AppModel`.
    OpenPreferencesDialog,
    /// Posted by the application menu's Import entry's
    /// `connect_activate` handler. Mounts the
    /// [`ImportDialogComponent`](crate::import_dialog) — a
    /// libadwaita file picker + format selector +
    /// on-conflict + bundle passphrase row — parented at the
    /// active [`adw::ApplicationWindow`] so the dialog overlays
    /// the main window per §"libadwaita usage".
    ///
    /// Import is gated by
    /// [`format_app_primary_menu_action_sensitivities`]'s
    /// mutating-menu rule
    /// ([`crate::app::state::AppState::allows_mutating_menu`])
    /// so the action is disabled outside
    /// [`AppState::Unlocked`]. A stray dispatch in any other
    /// state (the action is disabled, but a stray dispatch from
    /// a future keyboard accelerator would still land here) is
    /// defensively guarded in the handler so the dialog never
    /// mounts over a `Missing` / `Locked` / `UnlockedBusy` /
    /// `StartupError` window.
    ///
    /// The fully wired
    /// [`ImportDialogComponent`](crate::import_dialog) (the
    /// editable form widgets, the
    /// [`paladin_core::Vault::mutate_and_save`] merge worker,
    /// and the inline error / warning surfaces) lands in
    /// follow-up commits; this commit only wires the dispatch
    /// edge so the menu activation reaches `AppModel`.
    OpenImportDialog,
    /// Posted by the application menu's Export entry's
    /// `connect_activate` handler. Mounts the
    /// [`ExportDialogComponent`](crate::export_dialog) — a
    /// libadwaita file picker + format selector + overwrite
    /// gate + encrypted-passphrase row — parented at the
    /// active [`adw::ApplicationWindow`] so the dialog overlays
    /// the main window per §"libadwaita usage".
    ///
    /// Export is gated by
    /// [`format_app_primary_menu_action_sensitivities`]'s
    /// mutating-menu rule
    /// ([`crate::app::state::AppState::allows_mutating_menu`])
    /// so the action is disabled outside
    /// [`AppState::Unlocked`]. A stray dispatch in any other
    /// state (the action is disabled, but a stray dispatch from
    /// a future keyboard accelerator would still land here) is
    /// defensively guarded in the handler so the dialog never
    /// mounts over a `Missing` / `Locked` / `UnlockedBusy` /
    /// `StartupError` window.
    ///
    /// The fully wired
    /// [`ExportDialogComponent`](crate::export_dialog) (the
    /// editable form widgets, the
    /// [`paladin_core::Vault::export`] worker, and the inline
    /// error / warning surfaces) lands in follow-up commits;
    /// this commit only wires the dispatch edge so the menu
    /// activation reaches `AppModel`.
    OpenExportDialog,
    /// Posted by the application menu's Passphrase entry's
    /// `connect_activate` handler. Mounts the
    /// [`PassphraseDialogComponent`](crate::passphrase_dialog)
    /// — a libadwaita-styled set / change / remove passphrase
    /// dialog — parented at the active
    /// [`adw::ApplicationWindow`] so the dialog overlays the
    /// main window per §"libadwaita usage".
    ///
    /// Passphrase is gated by
    /// [`format_app_primary_menu_action_sensitivities`]'s
    /// mutating-menu rule
    /// ([`crate::app::state::AppState::allows_mutating_menu`])
    /// so the action is disabled outside
    /// [`AppState::Unlocked`]. A stray dispatch in any other
    /// state (the action is disabled, but a stray dispatch from
    /// a future keyboard accelerator would still land here) is
    /// defensively guarded in the handler so the dialog never
    /// mounts over a `Missing` / `Locked` / `UnlockedBusy` /
    /// `StartupError` window.
    ///
    /// The fully wired
    /// [`PassphraseDialogComponent`](crate::passphrase_dialog)
    /// (the sub-flow router, the editable passphrase entries,
    /// the [`paladin_core::Vault::change_passphrase`] worker,
    /// and the inline error / warning surfaces) lands in
    /// follow-up commits; this commit only wires the dispatch
    /// edge so the menu activation reaches `AppModel`.
    OpenPassphraseDialog,
    /// Forwarded from the live [`AddAccountComponent`] when the
    /// user interacts with the dialog. Today only
    /// [`AddAccountOutput::Cancel`] is emitted — `AppModel`
    /// responds by dropping the controller and removing the dialog
    /// widget from the content tree. Submit / worker outputs land
    /// in follow-up commits alongside the editable form widgets.
    AddAccountAction(AddAccountOutput),
    /// Forwarded from the live [`SettingsComponent`] when the user
    /// interacts with the `AdwPreferencesDialog`. Today only
    /// [`SettingsDialogOutput::Close`] is emitted — `AppModel`
    /// responds by dropping the controller so the dialog disappears
    /// and any in-flight pending spinner draft is discarded. Toggle
    /// / spinner / debounce outputs that propagate
    /// [`paladin_core::SettingPatch`] values to
    /// `Vault::mutate_and_save` land in follow-up commits alongside
    /// the editable rows in the dialog body.
    SettingsDialogAction(SettingsDialogOutput),
    /// Forwarded from the live [`ImportDialogComponent`] when the
    /// user interacts with the `adw::Dialog`. Today only
    /// [`ImportDialogOutput::Close`] is emitted — `AppModel`
    /// responds by dropping the controller so the dialog disappears
    /// and any in-flight pending form draft (selected source path,
    /// format / conflict choice, bundle passphrase entry) is
    /// discarded. Submit / merge-result outputs that propagate the
    /// post-merge [`paladin_core::ImportReport`] (or typed failure
    /// via [`crate::import_dialog::classify_merge_result`]) to
    /// `AppModel` land in follow-up commits alongside the editable
    /// form widgets in the dialog body.
    ImportDialogAction(ImportDialogOutput),
    /// Forwarded from the live [`ExportDialogComponent`] when the
    /// user interacts with the `adw::Dialog`.
    /// [`ExportDialogOutput::Cancel`] / [`ExportDialogOutput::Close`]
    /// drop the controller so the dialog disappears and any
    /// in-flight pending form draft (selected destination path,
    /// format choice, overwrite acknowledgement, plaintext-warning
    /// acknowledgement, twice-confirm passphrase entries) is
    /// discarded. [`ExportDialogOutput::Submit`] hands the validated
    /// [`crate::export_dialog::ExportSubmitPayload`] to the
    /// `gio::spawn_blocking
    /// paladin_core::write_secret_file_atomic(.., otpauth_list /
    /// encrypted)` worker that posts back via
    /// [`AppMsg::ExportWorkerCompleted`].
    ExportDialogAction(ExportDialogOutput),
    /// Worker-completion message for the `gio::spawn_blocking` export
    /// path. `AppModel` reinstalls the returned `(Vault, Store)` pair
    /// (export does not mutate the vault, so it is the same pair
    /// passed in, but the round-trip keeps the busy-gate semantics in
    /// lock-step with the other vault-touching workers), rolls the
    /// `UnlockedBusy → Unlocked` transition, and dispatches the typed
    /// [`crate::export_dialog::ExportOutcome`] via
    /// [`crate::app::state::compose_export_dispatch`]:
    /// * `Success` → drop the dialog controller and raise an
    ///   [`AdwToast`](adw::Toast) naming the written path on the main
    ///   overlay.
    /// * `DurabilityWarning` → forward
    ///   [`ExportDialogMsg::WorkerCompleted`] so the dialog renders
    ///   the `save_durability_unconfirmed` warning inline; the
    ///   controller stays mounted.
    /// * `Inline` → forward the typed error so the dialog renders it
    ///   inline; the controller stays mounted.
    ExportWorkerCompleted(ExportWorkerCompletion),
    /// Forwarded from the live [`PassphraseDialogComponent`] when
    /// the user interacts with the `adw::Dialog`. Today only
    /// [`PassphraseDialogOutput::Close`] is emitted — `AppModel`
    /// responds by dropping the controller so the dialog disappears
    /// and any in-flight pending form draft (selected sub-flow,
    /// current / new / confirm passphrase entries, pending
    /// destructive acknowledgement) is discarded. Submit / worker-
    /// result outputs that propagate the typed
    /// [`paladin_core::Vault::set_passphrase`] /
    /// [`paladin_core::Vault::change_passphrase`] /
    /// [`paladin_core::Vault::remove_passphrase`] outcomes to
    /// `AppModel` land in follow-up commits alongside the
    /// editable form widgets in the dialog body.
    PassphraseDialogAction(PassphraseDialogOutput),
    /// Forwarded from the live [`UnlockDialogComponent`] when the
    /// user submits a non-empty passphrase. Today only
    /// [`UnlockDialogOutput::SubmitLock`] is emitted — the
    /// `gio::spawn_blocking paladin_core::open` worker that consumes
    /// the forwarded [`paladin_core::VaultLock`] and transitions
    /// [`AppState::Locked`] → [`AppState::UnlockedBusy`] →
    /// [`AppState::Unlocked`] (or routes the open failure inline
    /// for `decrypt_failed` / `invalid_passphrase` and to
    /// [`StartupErrorComponent`] for every other open failure per
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Effect errors") lands in a
    /// follow-up commit alongside the `UnlockedBusy` worker
    /// infrastructure.
    UnlockDialogAction(UnlockDialogOutput),
    /// Posted by the `gio::spawn_blocking paladin_core::open` worker
    /// after it consumes the forwarded [`paladin_core::VaultLock`]
    /// and reports its routed outcome as an
    /// [`UnlockWorkerCompletion`] — the typed
    /// [`crate::app::state::UnlockWorkerEffect`] bundled with the live
    /// `Option<(Vault, Store)>` pair returned by
    /// `paladin_core::Store::open` on the success branch.
    ///
    /// The handler bundles the worker effect over the cached
    /// [`AppState`] through
    /// [`crate::app::state::compose_unlock_dispatch`] into a single
    /// [`crate::app::state::UnlockDispatch`]: a state replacement
    /// (success → [`AppState::Unlocked`], startup-routed failure →
    /// [`AppState::StartupError`], inline rollback →
    /// [`AppState::Locked`]) applied via
    /// [`crate::app::state::apply_unlock_dispatch_inplace`], an
    /// optional [`crate::unlock_dialog::UnlockDialogMsg::OpenFailedInline`]
    /// forwarded to the live [`UnlockDialogComponent`] on the inline branch, and
    /// a `drop_dialog` flag that detaches the dialog widget from
    /// the content tree on the two replacement branches.
    ///
    /// In parallel, the carried pair is installed into
    /// [`AppModel::vault`] via
    /// [`crate::app::state::apply_unlock_vault_install_inplace`]:
    /// `Some(pair)` writes through on the success branch, `None`
    /// leaves the slot byte-for-byte intact on every failure branch
    /// (both inline-passphrase rollback and startup-routed failures)
    /// so a stray completion can never clobber a live unlocked pair.
    /// See `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction" and
    /// §"Effect errors".
    ///
    /// The `gio::spawn_blocking paladin_core::open` worker that
    /// produces this message lands in a follow-up commit; this
    /// commit only wires the consumer so the full dispatch + vault
    /// install path is in place before the worker spawn.
    UnlockWorkerCompleted(UnlockWorkerCompletion),
    /// Posted by the `gio::spawn_blocking
    /// Vault::mutate_and_save(|v| v.rename(...))` worker after it
    /// consumes a [`crate::rename_dialog::RenameWorkerInput`] and
    /// reports its routed outcome as a
    /// [`RenameWorkerCompletion`] — the typed
    /// [`crate::rename_dialog::RenameWorkerEffect`] bundled with the
    /// live `(Vault, Store)` pair returned by `mutate_and_save`
    /// regardless of typed outcome (the rename worker always returns
    /// the pair per `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault
    /// interaction").
    ///
    /// The handler bundles the worker effect over the cached
    /// [`AppState`] through
    /// [`crate::app::state::compose_rename_dispatch`] into a single
    /// [`crate::app::state::RenameDispatch`]: a state replacement
    /// (`UnlockedBusy → Unlocked` for every typed effect, since the
    /// busy gate always releases), applied via
    /// [`crate::app::state::apply_rename_dispatch_inplace`], an
    /// optional [`crate::rename_dialog::RenameDialogMsg::WorkerFailed`]
    /// forwarded to the live [`RenameDialogComponent`] on every
    /// failure branch, and a `drop_dialog` flag that detaches the
    /// dialog widget from the content tree on the
    /// [`crate::rename_dialog::RenameWorkerEffect::Success`] branch.
    ///
    /// In parallel, the carried `(Vault, Store)` pair is reinstalled
    /// into [`AppModel::vault`] via
    /// [`crate::app::state::apply_rename_vault_install_inplace`]
    /// unconditionally — `mutate_and_save` is authoritative for the
    /// post-rename / rollback state, so reinstalling the pair is the
    /// right behavior across `Success`, `save_durability_unconfirmed`
    /// warnings, and `save_not_committed` rollbacks alike.
    RenameWorkerCompleted(RenameWorkerCompletion),
    /// Posted by the `gio::spawn_blocking
    /// Vault::mutate_and_save(|v| v.remove(...))` worker after it
    /// consumes a [`crate::remove_dialog::RemoveWorkerInput`] and
    /// reports its routed outcome as a
    /// [`RemoveWorkerCompletion`] — the typed
    /// [`crate::remove_dialog::RemoveWorkerEffect`] bundled with the
    /// live `(Vault, Store)` pair returned by `mutate_and_save`
    /// regardless of typed outcome (the remove worker always returns
    /// the pair per `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault
    /// interaction").
    ///
    /// Mirrors the [`Self::RenameWorkerCompleted`] dispatch path
    /// exactly — `compose_remove_dispatch` bundles the typed
    /// [`crate::remove_dialog::RemoveWorkerEffect`] over the cached
    /// [`AppState`] into a [`crate::app::state::RemoveDispatch`]
    /// (state replacement `UnlockedBusy → Unlocked`, optional
    /// [`crate::remove_dialog::RemoveDialogMsg::WorkerFailed`] on
    /// every failure branch, drop-dialog flag on `Success`). The
    /// carried pair is reinstalled into [`AppModel::vault`] via
    /// [`crate::app::state::apply_remove_vault_install_inplace`]
    /// unconditionally.
    RemoveWorkerCompleted(RemoveWorkerCompletion),
    /// Posted by the `gio::spawn_blocking
    /// Vault::mutate_and_save(|v| v.add(account))` worker after it
    /// consumes a [`crate::add_account::AddWorkerInput`] and reports
    /// its routed outcome as an [`AddWorkerCompletion`] — the typed
    /// [`crate::add_account::AddWorkerEffect`] bundled with the live
    /// `(Vault, Store)` pair returned by `mutate_and_save`
    /// regardless of typed outcome (the add worker always returns
    /// the pair per `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault
    /// interaction").
    ///
    /// Mirrors the [`Self::RenameWorkerCompleted`] and
    /// [`Self::RemoveWorkerCompleted`] dispatch paths exactly —
    /// [`crate::app::state::compose_add_dispatch`] bundles the typed
    /// [`crate::add_account::AddWorkerEffect`] over the cached
    /// [`AppState`] into a [`crate::app::state::AddDispatch`] (state
    /// replacement `UnlockedBusy → Unlocked`, optional
    /// [`crate::add_account::AddAccountMsg::WorkerFailed`] on every
    /// failure branch, drop-dialog flag on `Success`). The carried
    /// pair is reinstalled into [`AppModel::vault`] via
    /// [`crate::app::state::apply_add_vault_install_inplace`]
    /// unconditionally.
    AddWorkerCompleted(AddWorkerCompletion),
    /// Posted by the `gio::spawn_blocking` worker that runs
    /// `Vault::mutate_and_save(|v| { from_file(...) -> v.import_accounts(...) })`
    /// for the application menu's Import… entry after it consumes a
    /// [`crate::import_dialog::ImportWorkerInput`] and reports its
    /// routed outcome as an
    /// [`crate::import_dialog::ImportWorkerCompletion`] — the typed
    /// [`crate::import_dialog::MergeOutcome`] bundled with the live
    /// `(Vault, Store)` pair returned by `mutate_and_save` regardless
    /// of typed outcome.
    ///
    /// Mirrors the [`Self::RemoveWorkerCompleted`] /
    /// [`Self::AddWorkerCompleted`] dispatch paths with one
    /// divergence pinned by
    /// [`crate::app::state::compose_import_dispatch`]:
    /// `drop_dialog` is always `false` — the import dialog keeps the
    /// post-merge counts panel mounted (on `Success`) or the inline
    /// error / warning visible (on every failure branch) until the
    /// user clicks Dismiss or Cancel per
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    /// `ImportDialog` ("keep the dialog on a post-success counts
    /// panel until the user dismisses it"). `dialog_msg` is always
    /// `Some(ImportDialogMsg::WorkerCompleted(outcome))` so the
    /// dialog populates the counts panel / inline warning / inline
    /// error per the typed outcome.
    ///
    /// The carried pair is reinstalled into [`AppModel::vault`] via
    /// [`crate::app::state::apply_import_vault_install_inplace`]
    /// unconditionally — `mutate_and_save` is authoritative for the
    /// post-merge / rollback state across every outcome branch.
    ImportWorkerCompleted(ImportWorkerCompletion),
    /// Posted by the `gio::spawn_blocking` worker that runs
    /// `Vault::mutate_and_save(|v| v.import_accounts(...))` for the
    /// clipboard-QR add path after it consumes a
    /// [`crate::add_account::QrWorkerInput`] and reports its routed
    /// outcome as a [`QrWorkerCompletion`] — the typed
    /// [`crate::add_account::QrWorkerEffect`] bundled with the live
    /// `(Vault, Store)` pair returned by `mutate_and_save` regardless
    /// of typed outcome (the QR worker always returns the pair per
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction" >
    /// "Every worker returns `(Vault, Store, EffectOutcome)`").
    ///
    /// Mirrors the [`Self::AddWorkerCompleted`] dispatch path with
    /// two divergences pinned by `compose_qr_dispatch`:
    ///
    /// * `drop_dialog` is always `false` — the QR sub-path keeps the
    ///   Add dialog mounted on every effect so the post-success
    ///   counts panel can render the
    ///   `imported`/`skipped`/`warning` numbers parked by
    ///   [`crate::add_account::AddAccountMsg::QrSuccess`].
    /// * `dialog_msg` is `Some(_)` on every effect:
    ///   `QrSuccess(QrImportSummary)` on `Success` (so the counts
    ///   panel actually surfaces the post-merge counts inline,
    ///   parity with §6) and `WorkerFailed(outcome)` on every
    ///   failure branch (typed
    ///   [`crate::add_account::AddPostEffectOutcome`] so the inline
    ///   error / durability warning re-renders).
    ///
    /// The carried pair is reinstalled into [`AppModel::vault`] via
    /// [`crate::app::state::apply_add_vault_install_inplace`]
    /// unconditionally — the QR sub-path reuses the add path's
    /// installer because both workers consume and return the live
    /// `(Vault, Store)` pair through `Vault::mutate_and_save`.
    QrWorkerCompleted(QrWorkerCompletion),
    /// Posted by the `gdk::Clipboard::read_texture_async` callback
    /// that the [`Self::AddAccountAction(AddAccountOutput::RequestScanClipboard)`]
    /// arm fires after the user clicks the "Scan clipboard" button
    /// on the QR sub-path of [`crate::add_account::AddAccountComponent`].
    ///
    /// The asynchronous read callback runs the four-step pure-logic
    /// preflight pipeline before posting the typed result back to
    /// `AppModel`:
    ///
    /// 1. `Option<gdk::Texture>` from the GDK clipboard read —
    ///    `None` (or any `glib::Error`) projects to
    ///    [`crate::qr_clipboard::QrPreflightError::NoClipboardImage`].
    /// 2. [`crate::qr_clipboard::classify_layout_preflight`] on the
    ///    texture's `(width, height)` — the §5
    ///    [`paladin_core::QR_RGBA_MAX_BYTES`] gate rejects oversized
    ///    images *before* allocation / download.
    /// 3. [`crate::qr_clipboard::allocate_rgba_buffer`] plus a
    ///    `gdk::TextureDownloader` configured with
    ///    [`crate::qr_clipboard::clipboard_qr_memory_format`]
    ///    (straight `R8g8b8a8`, never premultiplied — the QR
    ///    decoder upstream requires it).
    /// 4. [`crate::qr_clipboard::classify_qr_outcome`] on the
    ///    [`crate::qr_clipboard::compose_qr_decode_outcome`] result
    ///    — `verify_download_layout` rejects GDK stride / length
    ///    drift, then `decode_clipboard_qr` forwards the buffer to
    ///    [`paladin_core::import::qr_image_bytes`] which returns
    ///    `Vec<ValidatedAccount>` regardless of QR count.
    ///
    /// The handler in `AppModel::update` routes the payload through
    /// [`route_qr_clipboard_loaded`]:
    ///
    /// * [`QrClipboardLoadedDispatch::InlineError`] →
    ///   `controller.emit(AddAccountMsg::RenderInlineError(inline))`
    ///   so the Add dialog renders the typed body via
    ///   [`crate::add_account::compose_inline_error_body`].
    /// * [`QrClipboardLoadedDispatch::SpawnWorker`] → mirror of the
    ///   manual / URI [`Self::AddAccountAction(AddAccountOutput::Submit { account })`]
    ///   spawn pattern, using
    ///   [`crate::app::state::compose_qr_worker_input`] +
    ///   [`crate::app::state::apply_submit_add_inplace`] +
    ///   [`gtk::gio::spawn_blocking`] [`crate::add_account::run_qr_worker`].
    ///   The worker completion lands back as
    ///   [`Self::QrWorkerCompleted`].
    QrClipboardLoaded(
        std::result::Result<
            Vec<paladin_core::ValidatedAccount>,
            crate::qr_clipboard::QrPreflightError,
        >,
    ),
    /// Posted by the `gio::spawn_blocking` worker that runs
    /// `Vault::hotp_peek` + `Vault::hotp_advance` after it consumes
    /// the bundled [`HotpAdvanceWorkerInput`] and reports its routed
    /// outcome as a [`HotpAdvanceWorkerCompletion`] — the typed
    /// [`crate::hotp_reveal::AdvanceOutcome`] bundled with the
    /// `(Vault, Store)` pair returned by the worker.
    ///
    /// The handler reinstalls the pair into [`AppModel::vault`],
    /// transitions `UnlockedBusy → Unlocked` via `state.leave_busy()`,
    /// then routes the outcome through
    /// [`crate::hotp_reveal::apply_advance_outcome`] +
    /// [`crate::hotp_reveal::apply_advance_decision`] so the reveal-
    /// window map gains (or replaces) the entry for the affected
    /// account. The widget side-effect (cache rebind via
    /// [`AccountListMsg::Tick`], optional `AdwToast` raised on the
    /// `AdwToastOverlay`) follows the [`RevealEffect`] returned by
    /// the reducer. See `IMPLEMENTATION_PLAN_04_GTK.md`
    /// §"Milestone 7 checklist" > "HOTP reveal window behavior".
    HotpAdvanceWorkerCompleted(HotpAdvanceWorkerCompletion),
    /// Forwarded from the live [`InitDialogComponent`] when the user
    /// submits the "Create vault" button
    /// ([`InitDialogOutput::SubmitCreate`]) or confirms the destructive
    /// `vault_exists` race gate
    /// ([`InitDialogOutput::SubmitForceCreate`]). The handler stages
    /// the [`paladin_core::VaultInit`] plus the resolved vault path
    /// into an [`InitWorkerInput`] (with
    /// [`InitWorkerMode::Create`] / [`InitWorkerMode::CreateForce`]),
    /// spawns [`run_init_worker`] on `gtk::gio::spawn_blocking` so the
    /// §4.4 Argon2id KDF stays off the main loop, and posts the
    /// resulting [`InitWorkerCompletion`] back as
    /// [`Self::InitWorkerCompleted`].
    InitDialogAction(InitDialogOutput),
    /// Posted by the `gio::spawn_blocking
    /// paladin_core::Store::create` / `Store::create_force` init
    /// worker after it consumes the bundled [`InitWorkerInput`] and
    /// reports its routed outcome as an [`InitWorkerCompletion`].
    ///
    /// On [`InitWorkerEffect::Success`] the handler installs the
    /// returned `(Vault, Store)` pair into [`AppModel::vault`],
    /// transitions [`AppModel::state`] to
    /// [`crate::app::state::AppState::Unlocked`], and remounts the
    /// content tree via [`AppModel::remount_for_state`] so the
    /// `AccountListComponent` is the only visible chrome.
    ///
    /// On [`InitWorkerEffect::DestructiveGate`] the handler forwards
    /// [`InitDialogMsg::WorkerCompletedDestructive`] to the live
    /// `InitDialogComponent` so the dialog rebuilds the pending
    /// `VaultInit` from the preserved buffers and presents the
    /// destructive [`adw::AlertDialog`].
    ///
    /// On [`InitWorkerEffect::InlineError`] the handler forwards
    /// [`InitDialogMsg::WorkerCompletedInline`] carrying the typed
    /// [`crate::init_dialog::InlineError`] so the dialog renders the
    /// rendering verbatim alongside the still-populated entries —
    /// `unsafe_permissions`, `save_not_committed`,
    /// `save_durability_unconfirmed`, and any other typed error
    /// returned by `classify_create_error` / `classify_create_force_error`
    /// stay inline and never transition the dialog out.
    InitWorkerCompleted(InitWorkerCompletion),
    /// Posted by [`dispatch_startup_error_output`] when
    /// [`StartupErrorComponent`](crate::startup_error::StartupErrorComponent)
    /// emits [`StartupErrorOutput::Retry`].
    ///
    /// The handler re-runs the startup probe via
    /// [`run_startup_probes`] against the cached
    /// [`AppModel::vault_path`] override (so an explicit
    /// `--vault` flag still wins on retry), replaces
    /// [`AppModel::state`] and [`AppModel::vault`] with the
    /// fresh outcome, tears down the currently-mounted screen
    /// controller, and remounts the per-state controller that
    /// matches the new [`AppState`] — mirroring `init`'s
    /// per-state mount sequence so the retry path produces a
    /// content tree byte-for-byte equivalent to a fresh
    /// process start.
    ///
    /// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction"
    /// the handler is non-mutating: it does not create,
    /// overwrite, repair, chmod, or select a different vault
    /// path. The only side effects are the re-run probe (which
    /// is itself read-only — `paladin_core::default_vault_path`,
    /// `inspect`, and the plaintext-`open` already in the
    /// startup sequence are all non-mutating) and the
    /// controller swap in the content tree.
    StartupErrorRetry,
    /// Fired by the live `glib::timeout_add_local` ticker source
    /// installed via [`AppModel::apply_ticker_transition`].
    ///
    /// The handler projects the live `(Vault, Store)` pair plus
    /// the rendered row set through [`crate::ticker::tick`] and
    /// forwards the resulting display updates to the live
    /// [`AccountListComponent`] via [`AccountListMsg::Tick`] so
    /// the TOTP gauge / code labels refresh in lockstep with the
    /// shared `paladin_core::TICK_INTERVAL_MS` cadence (parity with
    /// the TUI). The `clipboard_wake_due` hint is reserved for the
    /// follow-up commit that wires the copy button and the
    /// `gdk::Clipboard` only-if-unchanged check.
    ///
    /// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist"
    /// TOTP ticker. A stray tick that lands after `Vault` has
    /// been dropped (e.g. between a `Locked` transition and the
    /// matching `ticker_transition` teardown) is a benign no-op:
    /// the handler returns early when [`AppModel::vault`] is `None`.
    Tick {
        /// Wall-clock at the tick firing. Used by TOTP code
        /// generation (`paladin_core::totp_code` is
        /// [`SystemTime`]-driven so the codes follow the user's
        /// wall clock rather than the monotonic timer).
        wall_clock: SystemTime,
        /// Monotonic timestamp at the tick firing. Used by the
        /// clipboard auto-clear policy's deadline check
        /// ([`PendingClipboardClear::deadline`] is monotonic so
        /// the wipe survives wall-clock adjustments).
        ///
        /// [`PendingClipboardClear::deadline`]: crate::clipboard_clear::PendingClipboardClear::deadline
        monotonic: Instant,
    },
    /// Outcome of an asynchronous `gdk::Clipboard::read_text_async`
    /// issued from [`AppModel::handle_tick`] when the per-tick
    /// `clipboard_wake_due` hint fires.
    ///
    /// The handler feeds `(token, current)` through
    /// [`crate::clipboard_clear::evaluate_wake`] and acts on the
    /// returned [`WakeDecision`]:
    ///
    /// * [`WakeDecision::Clear`] — write empty text through
    ///   `gdk::Clipboard::set_text` and drop
    ///   [`AppModel::pending_clipboard`] (the
    ///   `Zeroizing<Vec<u8>>` wipes on drop).
    /// * [`WakeDecision::Mismatch`] — the user replaced the
    ///   clipboard contents in the interim; drop
    ///   [`AppModel::pending_clipboard`] without touching the
    ///   clipboard so the user's new copy is preserved.
    /// * [`WakeDecision::Stale`] — a fresher copy has superseded
    ///   the issued token; the in-flight pending entry stays in
    ///   place and the wake is a benign no-op.
    ///
    /// A read failure (`read_text_async` errored or returned no
    /// text) forwards an empty `current` slice. The policy treats
    /// empty as non-equal to any non-empty pending value, so the
    /// captured `Zeroizing<Vec<u8>>` is dropped and the clipboard
    /// is left alone — the safe non-leaky default.
    ClipboardWakeRead {
        /// Token issued by `ClipboardClearPolicy::schedule` when
        /// the pending entry was armed. A wake that arrives after
        /// the user re-copied (which issued a fresher token)
        /// resolves to [`WakeDecision::Stale`] via the token gate.
        token: paladin_core::ClipboardClearToken,
        /// Current `gdk::Clipboard` text at the time the async read
        /// resolved, as raw bytes wrapped in [`Zeroizing`] so the
        /// buffer wipes on drop (the clipboard text may itself be
        /// an OTP). Empty when the read failed or the clipboard
        /// had no text. Compared byte-equal against
        /// [`PendingClipboardClear::value`] inside
        /// [`crate::clipboard_clear::evaluate_wake`].
        current: zeroize::Zeroizing<Vec<u8>>,
    },
}

// `relm4::component(pub)` generates a public `AppModelWidgets` struct so the
// `SimpleComponent::Widgets` associated type does not leak a private type out
// of `pub AppModel`. The macro does not attach a doc comment to that struct,
// so silence the workspace-wide `missing_docs` lint just for this impl block.
#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for AppModel {
    type Init = AppInit;
    type Input = AppMsg;
    type Output = ();

    view! {
        #[root]
        adw::ApplicationWindow {
            set_title: Some(format_app_window_title()),
            set_default_size: (
                format_app_window_default_size().0,
                format_app_window_default_size().1,
            ),

            #[wrap(Some)]
            set_content = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[name = "add_button"]
                    pack_start = &gtk::Button {
                        set_icon_name: format_app_add_button_icon_name(),
                        set_tooltip_text: Some(format_app_add_button_tooltip()),
                        // Initial visibility tracks the resolved
                        // startup state through the pinned
                        // `format_app_add_button_visible` helper.
                        // Subsequent state changes (Unlocked →
                        // UnlockedBusy → Unlocked, auto-lock,
                        // etc.) toggle visibility via
                        // `apply_app_add_button_visibility` wired
                        // in the post-init dispatch handlers. The
                        // `+` is hidden outside the vault-open
                        // states so users cannot trigger an
                        // `OpenAddDialog` race against a missing /
                        // locked / errored vault. Sensitivity and
                        // click dispatch are both inherited from
                        // the `"app.add"` SimpleAction registered
                        // on the bundled action group via
                        // `build_app_window_action_group`: the
                        // action's enabled state (pinned through
                        // `format_app_add_button_sensitive`)
                        // propagates to the button automatically
                        // through `set_action_name`, and clicking
                        // the button activates the action — which
                        // routes through `dispatch_app_window_action`
                        // to `AppMsg::OpenAddDialog`.
                        set_visible: format_app_add_button_visible(&state),
                        set_action_name: Some(format_app_add_button_action()),
                    },

                    #[name = "menu_button"]
                    pack_end = &gtk::MenuButton {
                        set_icon_name: format_app_menu_button_icon_name(),
                        set_tooltip_text: Some(format_app_menu_button_tooltip()),
                    },

                    #[name = "search_button"]
                    pack_end = &gtk::ToggleButton {
                        set_icon_name: format_app_search_button_icon_name(),
                        set_tooltip_text: Some(format_app_search_button_tooltip()),
                        // Initial visibility tracks the resolved
                        // startup state through the pinned
                        // `format_app_search_button_visible`
                        // helper — mirrors the `+` button rule so
                        // both header-bar affordances appear / hide
                        // together with the vault-open state.
                        // `connect_toggled` posts
                        // `AppMsg::SearchToggled(active)` so the
                        // update handler emits
                        // `AccountListMsg::SetSearchModeEnabled` to
                        // the live `AccountListComponent` controller
                        // (and silently drops the message in states
                        // where the controller is not mounted).
                        set_visible: format_app_search_button_visible(&state),
                        connect_toggled[sender] => move |btn| {
                            sender.input(AppMsg::SearchToggled(btn.is_active()));
                        },
                    },
                },

                // Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Window
                // shell and toast surface", every active screen
                // (`InitDialog`, `UnlockComponent`,
                // `StartupErrorComponent`, `AccountListComponent`)
                // renders inside a single `adw::ToastOverlay` so
                // copy confirmations, settings-saved notices,
                // clipboard-clear-fired notices, HOTP
                // `save_durability_unconfirmed` warnings, and
                // export-success toasts survive state transitions.
                // The overlay's child is the same `content`
                // `gtk::Box` the per-state controllers append into,
                // so the post-init mount sites stay unchanged from
                // before the overlay landed.
                #[wrap(Some)]
                #[name = "toast_overlay"]
                set_content = &adw::ToastOverlay {
                    set_widget_name: format_app_toast_overlay_widget_name(),

                    #[wrap(Some)]
                    #[name = "content"]
                    set_child = &gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_hexpand: true,
                        set_vexpand: true,
                    },
                },
            },
        }
    }

    // `init` walks startup probes, mounts every per-state child
    // controller, and wires the header-bar action group — the
    // sequence reads top-to-bottom and each block has a unique
    // role, so splitting it would obscure the dispatch table
    // without isolating reusable logic.
    #[allow(clippy::too_many_lines)]
    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let exit_after_startup = init.exit_after_startup;
        let vault_path_override = init.vault_path.clone();
        let StartupOutcome { state, vault } = run_startup_probes(init.vault_path);

        let rows: Vec<AccountRowModel> = vault
            .as_ref()
            .map(|(v, _)| row_models_from_vault(v))
            .unwrap_or_default();

        if exit_after_startup {
            // Stable stdout contract consumed by `tests/gtk_smoke.rs`.
            println!("{}", startup_state_marker(&state));
            // Per-state body markers are only meaningful when the
            // matching child component actually mounts; emit each
            // one exclusively from its own branch so callers do not
            // infer a render from a non-rendering state.
            if state.is_unlocked() {
                println!("{}", format_rendered_marker(&rows));
                let displays: Vec<_> = rows.iter().map(hidden_row_display).collect();
                println!("{}", format_widget_states_marker(&displays));
            }
            if let AppState::StartupError { error, .. } = &state {
                println!("{}", format_startup_error_marker(error));
            }
            if let AppState::Missing { path } = &state {
                println!("{}", format_init_dialog_marker(path));
            }
            if let AppState::Locked { path } = &state {
                println!("{}", format_unlock_dialog_marker(path));
            }
        }

        let widgets = view_output!();

        // Attach the primary menu model to the header-bar
        // `gtk::MenuButton` after `view_output!()` so the
        // model is built once via `build_app_primary_menu_model`
        // and the widget binding never hand-spells the
        // `set_menu_model` call site.
        wire_app_menu_button_menu_model(&widgets.menu_button);

        // Build the bundled application action group and
        // wire per-action `connect_activate` handlers before
        // inserting the group on the root
        // `adw::ApplicationWindow` so the menu targets
        // spelled by `format_app_primary_menu_entries`
        // (`"app.import"`, `"app.export"`, …, `"app.quit"`)
        // and the header-bar `+` button's `"app.add"` target
        // all resolve through one `gio::SimpleActionGroup`.
        let action_group = build_app_window_action_group(&state);
        wire_app_window_action_activations(&action_group, sender.input_sender());
        wire_app_window_action_group(&root, &action_group);

        // Register the pinned `<Control>n` / `<Control>q` /
        // `<Control>comma` accelerators on the shared application
        // so the Add, Quit, and Preferences `gio::SimpleAction`s
        // inserted on the bundled action group resolve through
        // their keyboard shortcuts in addition to the visible
        // menu / button click paths. Sourced from
        // `format_app_window_accelerator_bindings` so the wiring
        // stays a single iteration over the pinned source of truth.
        wire_app_window_accelerators(&relm4::main_application());

        let account_list = if state.is_unlocked() {
            let controller = AccountListComponent::builder()
                .launch(AccountListInit {
                    rows,
                    initial_query: String::new(),
                    initial_selection: None,
                })
                .forward(sender.input_sender(), AppMsg::AccountListAction);
            widgets.content.append(controller.widget());
            Some(controller)
        } else {
            None
        };

        let startup_error = if let AppState::StartupError { error, .. } = &state {
            let controller = StartupErrorComponent::builder()
                .launch(StartupErrorInit {
                    error: error.clone(),
                })
                .forward(sender.input_sender(), dispatch_startup_error_output);
            widgets.content.append(controller.widget());
            Some(controller)
        } else {
            None
        };

        let init_dialog = if let AppState::Missing { path } = &state {
            let controller = InitDialogComponent::builder()
                .launch(InitDialogInit {
                    vault_path: path.clone(),
                })
                .forward(sender.input_sender(), AppMsg::InitDialogAction);
            widgets.content.append(controller.widget());
            Some(controller)
        } else {
            None
        };

        let unlock_dialog = if let AppState::Locked { path } = &state {
            let controller = UnlockDialogComponent::builder()
                .launch(UnlockDialogInit {
                    vault_path: path.clone(),
                })
                .forward(sender.input_sender(), AppMsg::UnlockDialogAction);
            widgets.content.append(controller.widget());
            Some(controller)
        } else {
            None
        };

        let model = AppModel {
            vault_path: vault_path_override,
            state: Some(state),
            vault,
            account_list,
            startup_error,
            init_dialog,
            unlock_dialog,
            rename_dialog: None,
            remove_dialog: None,
            add_dialog: None,
            settings_dialog: None,
            import_dialog: None,
            export_dialog: None,
            passphrase_dialog: None,
            content: widgets.content.clone(),
            search_query: String::new(),
            ticker_source: None,
            reveal_windows: HashMap::new(),
            toast_overlay: widgets.toast_overlay.clone(),
            pending_clipboard: None,
            last_account_list_busy: false,
            last_add_dialog_busy: false,
        };

        // Install the TOTP ticker if the resolved startup state is
        // `Unlocked` and the projected row set contains at least one
        // TOTP row. `ticker_transition(was_installed: false, ...)`
        // collapses to `NoChange` in every other case so the call is
        // a benign no-op for `Missing` / `Locked` / `StartupError`
        // startups and for unlocked vaults that are HOTP-only / empty.
        let mut model = model;
        model.apply_ticker_transition(&sender);

        if exit_after_startup {
            sender.input(AppMsg::Quit);
        }

        ComponentParts { model, widgets }
    }

    // `update` aggregates every `AppMsg` dispatch arm; splitting it
    // would obscure the dispatch table without isolating reusable
    // logic (each branch already delegates to a unit-tested helper
    // in `crate::app::state`).
    #[allow(clippy::too_many_lines)]
    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        match msg {
            AppMsg::Quit => {
                if let Some(source_id) = self.ticker_source.take() {
                    source_id.remove();
                }
                // Drop every open reveal so the `Zeroizing<String>`
                // wrappers wipe the visible digits before the
                // process exits. Drop the pending clipboard slot
                // too so the captured `Zeroizing<Vec<u8>>` wipes in
                // lockstep — the clipboard contents themselves are
                // not touched here.
                self.reveal_windows.clear();
                self.pending_clipboard = None;
                relm4::main_application().quit();
            }
            AppMsg::Tick {
                wall_clock,
                monotonic,
            } => {
                if let Some(token) = self.handle_tick(wall_clock, monotonic) {
                    // The per-tick clipboard wake deadline elapsed
                    // and the pending entry is still armed. Issue an
                    // async `gdk::Clipboard::read_text` and route
                    // the byte-equality decision through
                    // `evaluate_wake` on completion — keeping the
                    // sync part of the tick handler free of the
                    // round trip so a slow clipboard read never
                    // blocks the next TOTP gauge refresh.
                    let clipboard = WidgetExt::display(&self.content).clipboard();
                    let dispatch = sender.clone();
                    clipboard.read_text_async(None::<&gtk::gio::Cancellable>, move |result| {
                        let current = zeroize::Zeroizing::new(
                            result
                                .ok()
                                .flatten()
                                .map(|s| s.as_bytes().to_vec())
                                .unwrap_or_default(),
                        );
                        dispatch.input(AppMsg::ClipboardWakeRead { token, current });
                    });
                }
            }
            AppMsg::ClipboardWakeRead { token, current } => {
                // Resolve the token against the live pending slot.
                // `evaluate_wake` gates on token first so a wake
                // that arrives after a fresher copy supersedes the
                // pending entry is a benign no-op; on `Clear` /
                // `Mismatch` we drop the pending entry (zeroizing
                // its captured bytes via `Zeroizing<Vec<u8>>`) and
                // on `Clear` we additionally wipe the clipboard.
                let decision = self
                    .pending_clipboard
                    .as_ref()
                    .map(|p| evaluate_wake(p, token, &current));
                match decision {
                    Some(WakeDecision::Clear) => {
                        let clipboard = WidgetExt::display(&self.content).clipboard();
                        clipboard.set_text("");
                        self.pending_clipboard = None;
                    }
                    Some(WakeDecision::Mismatch) => {
                        self.pending_clipboard = None;
                    }
                    Some(WakeDecision::Stale) | None => {}
                }
            }
            AppMsg::StartupErrorRetry => {
                // User clicked the StartupErrorComponent Retry
                // button. Re-run the same probe sequence
                // `run_startup_probes` walks at process start
                // (path resolution → `inspect` → plaintext
                // `open`) against the cached `vault_path`
                // override so an explicit `--vault` flag still
                // wins on retry. The probe is non-mutating per
                // `IMPLEMENTATION_PLAN_04_GTK.md`
                // §"Vault interaction"; the retry path
                // similarly never creates / overwrites /
                // repairs / chmods / selects a different vault
                // path.
                let StartupOutcome { state, vault } = run_startup_probes(self.vault_path.clone());
                self.vault = vault;
                self.remount_for_state(&state, &sender);
                self.state = Some(state);
            }
            AppMsg::AccountListAction(AccountListOutput::OpenRenameDialog(id)) => {
                // Look up the targeted account in the live vault and
                // mount the rename dialog. A `None` projection means
                // the account was removed between the kebab
                // activation and this dispatch — treat that as a
                // benign race and drop the action.
                if let Some((vault, _store)) = self.vault.as_ref() {
                    if let Some(init) = decide_rename_target(vault, id) {
                        let controller = RenameDialogComponent::builder()
                            .launch(init)
                            .forward(sender.input_sender(), AppMsg::RenameDialogAction);
                        self.content.append(controller.widget());
                        self.rename_dialog = Some(controller);
                    }
                }
            }
            AppMsg::AccountListAction(AccountListOutput::OpenRemoveDialog(id)) => {
                // Look up the targeted account in the live vault and
                // mount the remove dialog. A `None` projection means
                // the account was removed between the kebab
                // activation and this dispatch — treat that as a
                // benign race and drop the action. The widget is an
                // `adw::AlertDialog` with the destructive Remove
                // response styled `adw::ResponseAppearance::Destructive`,
                // so `present(parent)` raises the modal chrome and
                // self-detaches on close — no `self.content.append`
                // / `self.content.remove` plumbing needed.
                if let Some((vault, _store)) = self.vault.as_ref() {
                    if let Some(init) = decide_remove_target(vault, id) {
                        let controller = RemoveDialogComponent::builder()
                            .launch(init)
                            .forward(sender.input_sender(), AppMsg::RemoveDialogAction);
                        controller.widget().present(Some(&self.content));
                        self.remove_dialog = Some(controller);
                    }
                }
            }
            AppMsg::AccountListAction(AccountListOutput::AdvanceHotp(id)) => {
                // HOTP row "next" button → `Vault::hotp_peek` +
                // `Vault::hotp_advance` worker per
                // `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7
                // checklist" > "HOTP reveal window behavior". The
                // worker takes the live `(Vault, Store)` pair by
                // value, stages the pre-advance code via `hotp_peek`,
                // then commits via `hotp_advance` + `mutate_and_save`
                // and posts the outcome back as
                // `AppMsg::HotpAdvanceWorkerCompleted`. The busy gate
                // transitions `Unlocked → UnlockedBusy` before the
                // spawn so a second click on any row is no-op until
                // the worker returns and rolls the gate back.
                let now = SystemTime::now();
                let in_progress = match (self.state.as_ref(), self.vault.take()) {
                    (Some(state), Some(pair)) => {
                        if let Some(busy_state) = state.clone().enter_busy() {
                            let (vault, store) = pair;
                            Some((
                                HotpAdvanceWorkerInput {
                                    vault,
                                    store,
                                    account_id: id,
                                    now,
                                },
                                busy_state,
                            ))
                        } else {
                            // Stray dispatch from a non-`Unlocked`
                            // state — reinstall the pair untouched so
                            // `AppModel.vault` is not lost.
                            self.vault = Some(pair);
                            None
                        }
                    }
                    (_, pair) => {
                        if let Some(pair) = pair {
                            self.vault = Some(pair);
                        }
                        None
                    }
                };
                if let Some((input, busy_state)) = in_progress {
                    self.state = Some(busy_state);
                    let sender = sender.clone();
                    gtk::glib::spawn_future_local(async move {
                        let completion =
                            gtk::gio::spawn_blocking(move || run_hotp_advance_worker(input))
                                .await
                                .expect("Vault::hotp_advance worker panicked");
                        sender.input(AppMsg::HotpAdvanceWorkerCompleted(completion));
                    });
                }
            }
            AppMsg::AccountListAction(AccountListOutput::CopyCode(id)) => {
                // Per-row copy button → resolve the visible code via
                // `prepare_copy_bytes`, write to the default
                // `gdk::Clipboard` via `set_text`, and (when the
                // user has opted in via
                // `clipboard.clear_enabled`) arm the auto-clear
                // policy through `schedule_copy` per
                // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
                // `AccountRowComponent`. Hidden HOTP rows return
                // `None` from `prepare_copy_bytes` so a stray click
                // through the action group is a benign no-op even
                // though the row's copy `gtk::Button` is also
                // desensitized via `RowDisplay::copy_enabled`.
                if let Some((vault, _)) = self.vault.as_ref() {
                    let wall_clock = SystemTime::now();
                    if let Some(bytes) =
                        prepare_copy_bytes(vault, &self.reveal_windows, id, wall_clock)
                    {
                        let display = WidgetExt::display(&self.content);
                        let clipboard = display.clipboard();
                        let text = String::from_utf8_lossy(&bytes);
                        clipboard.set_text(&text);
                        if let Some(pending) =
                            schedule_copy(Instant::now(), vault.settings(), bytes)
                        {
                            self.pending_clipboard = Some(pending);
                        }
                    }
                }
            }
            AppMsg::AccountListAction(AccountListOutput::QueryChanged(query)) => {
                // The user typed into the search bar. Cache the query
                // on `self.search_query` so the post-mutation refresh
                // path (`refresh_account_list`) can re-filter the live
                // vault without asking the controller for its current
                // entry text, then filter through
                // `paladin_core::account_matches_search` (via
                // `filtered_row_models_from_vault`) and re-feed the
                // projected rows back to the live
                // `AccountListComponent`. The selection-preservation
                // rule is deferred to the component: passing `None`
                // for the `selection` slot lets
                // `selected_row_after_refresh` resolve against the
                // component's own `current_selection`, so the user's
                // cursor follows the §6 / §7 contract (preserve when
                // still visible, else first match).
                self.search_query = query;
                if let (Some((vault, _)), Some(controller)) =
                    (self.vault.as_ref(), self.account_list.as_ref())
                {
                    let rows = filtered_row_models_from_vault(vault, &self.search_query);
                    let selection = selected_row_after_refresh(None, &rows);
                    controller.emit(AccountListMsg::Refresh { rows, selection });
                }
            }
            AppMsg::SearchToggled(active) => {
                // The header-bar search-toggle `gtk::ToggleButton`
                // fired `connect_toggled`. Forward the new active
                // state to the live `AccountListComponent` through
                // the pinned `format_app_search_toggle_msg` mapping
                // so the `gtk::SearchBar` reveals / hides in
                // lockstep with the toggle. If the controller is
                // not mounted (e.g. the user managed to fire the
                // signal through a keyboard shortcut while the
                // button was hidden), this is a benign no-op.
                if let Some(controller) = self.account_list.as_ref() {
                    controller.emit(format_app_search_toggle_msg(active));
                }
            }
            AppMsg::RenameDialogAction(RenameDialogOutput::Cancel) => {
                // Detach the dialog widget from the content tree and
                // drop the controller. Defensive: if the field is
                // already `None` (controller swapped under us by a
                // future race), this is a benign no-op.
                if let Some(controller) = self.rename_dialog.take() {
                    self.content.remove(controller.widget());
                }
            }
            AppMsg::RenameDialogAction(RenameDialogOutput::SubmitLabel { account_id, label }) => {
                // Save-button entry side of the `gio::spawn_blocking
                // Vault::mutate_and_save(|v| v.rename(account_id,
                // label, now))` worker. Four steps run in order per
                // `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction":
                //
                // 1. Take the live `(Vault, Store)` pair from
                //    `self.vault` and bundle it with the dispatch
                //    payload into a `RenameWorkerInput` via
                //    `compose_rename_worker_input`. The composer
                //    inspects the cached `AppState`: only `Unlocked`
                //    returns `Ok(input)`; every other variant returns
                //    `Err(pair)` so the wrapper can reinstall the
                //    pair via `apply_rename_vault_install_inplace`.
                //    A `None` state or a `None` vault slot is the
                //    defensive no-op (a stray `SubmitLabel` from a
                //    locked / missing / busy state).
                // 2. Apply the `Unlocked → UnlockedBusy` busy-gate
                //    transition via `apply_submit_rename_inplace` so
                //    `is_busy()` / `allows_mutating_menu()` cover the
                //    worker's lifetime. The dialog stays mounted —
                //    `should_drop_rename_dialog_after` keeps it on
                //    every failure branch and the worker's success
                //    dispatch drops it once the worker returns.
                // 3. Capture `SystemTime::now()` at the dispatch site
                //    so the worker thread does not race against later
                //    wall-clock drift; `Vault::rename` uses this for
                //    the new `updated_at`.
                // 4. Spawn `run_rename_worker` on
                //    `gtk::gio::spawn_blocking` so the
                //    `mutate_and_save` durability fsync hop does not
                //    block the GTK main loop. The wrapping
                //    `gtk::glib::spawn_future_local` awaits the
                //    blocking handle and posts the bundled
                //    `RenameWorkerCompletion` back to `AppModel` via
                //    `AppMsg::RenameWorkerCompleted`, which is
                //    consumed by the dispatch branch wired below.
                let now = SystemTime::now();
                let worker_input = match (self.state.as_ref(), self.vault.take()) {
                    (Some(state), Some(pair)) => {
                        match compose_rename_worker_input(state, pair, account_id, label, now) {
                            Ok(input) => Some(input),
                            Err(pair) => {
                                apply_rename_vault_install_inplace(&mut self.vault, pair);
                                None
                            }
                        }
                    }
                    (None, Some(pair)) => {
                        apply_rename_vault_install_inplace(&mut self.vault, pair);
                        None
                    }
                    (_, None) => None,
                };
                if let Some(state) = self.state.as_mut() {
                    apply_submit_rename_inplace(state);
                }
                if let Some(input) = worker_input {
                    let sender = sender.clone();
                    gtk::glib::spawn_future_local(async move {
                        let completion = gtk::gio::spawn_blocking(move || run_rename_worker(input))
                            .await
                            .expect("Vault::mutate_and_save rename worker panicked");
                        sender.input(AppMsg::RenameWorkerCompleted(completion));
                    });
                }
            }
            AppMsg::RemoveDialogAction(RemoveDialogOutput::Cancel) => {
                // Drop the controller so the `adw::AlertDialog` widget
                // tears itself down. `adw::AlertDialog` self-detaches
                // from its toplevel parent on close (the
                // `connect_response` close-response wiring fires when
                // Escape / outside-click / window-close runs), so no
                // `self.content.remove` is needed. Defensive: if the
                // field is already `None` (controller swapped under us
                // by a future race), this is a benign no-op.
                self.remove_dialog = None;
            }
            AppMsg::OpenAboutDialog => {
                // Application menu "About Paladin" activation.
                // Build a fresh `adw::AboutDialog` via the
                // pinned `build_app_about_dialog` helper and
                // present it parented at the content tree's
                // toplevel. `AdwDialog::present` walks up to
                // the active `adw::ApplicationWindow`
                // automatically when given any descendant.
                build_app_about_dialog().present(Some(&self.content));
            }
            AppMsg::OpenPreferencesDialog => {
                // Application menu "Preferences" activation. Mount a
                // fresh `SettingsComponent` seeded with a snapshot of
                // the live vault's `paladin_core::VaultSettings` and
                // present the `AdwPreferencesDialog` parented at the
                // content tree's toplevel. The dispatch edge is gated
                // to [`AppState::Unlocked`] by
                // `format_app_primary_menu_action_sensitivities`'s
                // mutating-menu rule, but a stray dispatch from a
                // future keyboard accelerator could still arrive in a
                // non-unlocked state — defend against that here so
                // the dialog never mounts over a `Missing` / `Locked`
                // / `UnlockedBusy` / `StartupError` window.
                if let Some(state) = self.state.as_ref() {
                    if state.is_unlocked() {
                        if let Some((vault, _)) = self.vault.as_ref() {
                            let init = SettingsDialogInit {
                                settings: CommittedSettings::from_vault_settings(vault.settings()),
                            };
                            let controller = SettingsComponent::builder()
                                .launch(init)
                                .forward(sender.input_sender(), AppMsg::SettingsDialogAction);
                            controller.widget().present(Some(&self.content));
                            self.settings_dialog = Some(controller);
                        }
                    }
                }
            }
            AppMsg::SettingsDialogAction(SettingsDialogOutput::Close) => {
                // User dismissed the `AdwPreferencesDialog`. Drop the
                // live controller so the widget is released and any
                // in-flight pending spinner draft is discarded.
                // `adw::PreferencesDialog` self-detaches from its
                // toplevel parent on close, so no `self.content.remove`
                // is needed — unlike `AddAccountComponent` /
                // `RenameDialogComponent` / `RemoveDialogComponent`
                // which are appended into the content tree directly.
                // Defensive: if the field is already `None`
                // (controller swapped under us by a future race),
                // this is a benign no-op.
                self.settings_dialog = None;
            }
            AppMsg::OpenImportDialog => {
                // Application menu "Import…" activation. Mount a fresh
                // `ImportDialogComponent` seeded with the resolved
                // vault path and present the `adw::Dialog` modally.
                // The menu entry's sensitivity is gated against
                // `AppState::allows_mutating_menu` (`Unlocked` only),
                // but a stray dispatch from a future keyboard
                // accelerator could still arrive in a non-unlocked
                // state — defend against that here so the dialog
                // never mounts over a `Missing` / `Locked` /
                // `UnlockedBusy` / `StartupError` window.
                if let Some(state) = self.state.as_ref() {
                    if state.is_unlocked() {
                        if let Some(path) = state.path() {
                            let init = ImportDialogInit {
                                vault_path: path.to_path_buf(),
                            };
                            let controller = ImportDialogComponent::builder()
                                .launch(init)
                                .forward(sender.input_sender(), AppMsg::ImportDialogAction);
                            controller.widget().present(Some(&self.content));
                            self.import_dialog = Some(controller);
                        }
                    }
                }
            }
            AppMsg::ImportDialogAction(ImportDialogOutput::Close) => {
                // User dismissed the `adw::Dialog`. Drop the live
                // controller so the widget is released and any
                // in-flight pending form draft (selected source
                // path, format / conflict choice, bundle passphrase
                // entry) is discarded. `adw::Dialog` self-detaches
                // from its toplevel parent on close, so no
                // `self.content.remove` is needed — unlike
                // `AddAccountComponent` / `RenameDialogComponent` /
                // `RemoveDialogComponent` which are appended into
                // the content tree directly. Defensive: if the field
                // is already `None` (controller swapped under us by
                // a future race), this is a benign no-op.
                self.import_dialog = None;
            }
            AppMsg::ImportDialogAction(ImportDialogOutput::Cancel) => {
                // Explicit Cancel button activation. Treated the same
                // as `Close`: drop the live controller so the widget
                // tears down and any pending form draft / bundle-
                // passphrase entry is discarded (the
                // `crate::secret_fields::SecretEntry` inside
                // `ImportDialogState` zeroes on drop).
                self.import_dialog = None;
            }
            AppMsg::ImportDialogAction(ImportDialogOutput::Submit(payload)) => {
                // Entry side of the `gio::spawn_blocking
                // Vault::mutate_and_save(|v| { from_file(...) ->
                // v.import_accounts(...) })` worker. Mirrors the
                // rename / remove / add submit handlers
                // step-for-step:
                //
                // 1. Take the live `(Vault, Store)` pair from
                //    `self.vault` and bundle it with the dispatch
                //    payload (source path, importer options including
                //    the bundle passphrase, on-conflict policy) plus
                //    the dispatch-site `import_time` into an
                //    `ImportWorkerInput` via
                //    `compose_import_worker_input`. Only `Unlocked`
                //    returns `Ok(input)`; every other variant returns
                //    `Err(pair)` so the wrapper can reinstall the
                //    pair via `apply_import_vault_install_inplace`.
                //    A `None` state or a `None` vault slot is the
                //    defensive no-op (a stray `Submit` from a locked
                //    / missing / busy state).
                // 2. Apply the `Unlocked → UnlockedBusy` busy-gate
                //    transition via `apply_submit_import_inplace`.
                //    The dialog stays mounted —
                //    `should_drop_import_dialog_after` keeps it on
                //    every outcome so the post-success counts panel
                //    or post-failure inline error / warning surfaces
                //    inline (the dialog itself is the success
                //    surface per
                //    `IMPLEMENTATION_PLAN_04_GTK.md` §"Component
                //    tree" > `ImportDialog`).
                // 3. Spawn `run_import_worker` on
                //    `gtk::gio::spawn_blocking` so the encrypted-
                //    Paladin variant's §4.4 Argon2id KDF and the
                //    `mutate_and_save` durability fsync hop do not
                //    block the GTK main loop. The wrapping
                //    `gtk::glib::spawn_future_local` awaits the
                //    blocking handle and posts the bundled
                //    `ImportWorkerCompletion` back to `AppModel` via
                //    `AppMsg::ImportWorkerCompleted`, which is
                //    consumed by the dispatch branch wired below.
                let import_time = SystemTime::now();
                let worker_input = match (self.state.as_ref(), self.vault.take()) {
                    (Some(state), Some(pair)) => {
                        match compose_import_worker_input(state, pair, payload, import_time) {
                            Ok(input) => Some(input),
                            Err(pair) => {
                                apply_import_vault_install_inplace(&mut self.vault, pair);
                                None
                            }
                        }
                    }
                    (None, Some(pair)) => {
                        apply_import_vault_install_inplace(&mut self.vault, pair);
                        None
                    }
                    (_, None) => None,
                };
                if let Some(state) = self.state.as_mut() {
                    apply_submit_import_inplace(state);
                }
                if let Some(input) = worker_input {
                    let sender = sender.clone();
                    gtk::glib::spawn_future_local(async move {
                        let completion = gtk::gio::spawn_blocking(move || run_import_worker(input))
                            .await
                            .expect("Vault::mutate_and_save import worker panicked");
                        sender.input(AppMsg::ImportWorkerCompleted(completion));
                    });
                }
            }
            AppMsg::ImportWorkerCompleted(completion) => {
                // Worker-outcome dispatch. Mirrors `RemoveWorkerCompleted`
                // / `RenameWorkerCompleted` / `AddWorkerCompleted` with
                // one divergence pinned by `compose_import_dispatch`:
                // `drop_dialog` is always `false` because the import
                // dialog keeps the post-merge counts panel mounted
                // until the user clicks Dismiss (per
                // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
                // `ImportDialog`). The dispatch bundles the worker
                // outcome over the cached `AppState` into an
                // `ImportDispatch`:
                //
                // * `app_state` — `UnlockedBusy → Unlocked` rollback
                //   regardless of typed outcome
                //   (`Vault::mutate_and_save` is authoritative for
                //   the rollback / durability-unconfirmed semantics).
                //   The `None` defensive case (worker outcome arrived
                //   but the cached state was not `UnlockedBusy`)
                //   leaves `AppModel::state` intact.
                // * `dialog_msg` — always
                //   `Some(WorkerCompleted(outcome))` so the dialog
                //   can populate the counts panel (on `Success`),
                //   the inline warning (on `DurabilityWarning`), or
                //   the inline error (on `NotCommitted` / `Inline`).
                // * `drop_dialog` — always `false`.
                // * `refresh_list` — `true` on `Success` and
                //   `DurabilityWarning` so the merged accounts appear
                //   in the visible row set; `false` on `NotCommitted`
                //   (rollback restored snapshot) and `Inline` (error
                //   fired before save path).
                //
                // The carried `(vault, store)` pair is reinstalled
                // into `AppModel::vault` via
                // `apply_import_vault_install_inplace`
                // unconditionally — `mutate_and_save` is
                // authoritative for the post-merge / rollback state
                // across every outcome branch.
                let ImportWorkerCompletion {
                    outcome,
                    vault,
                    store,
                } = completion;
                apply_import_vault_install_inplace(&mut self.vault, (vault, store));
                let dispatch = self.state.as_mut().map(|state| {
                    let dispatch = compose_import_dispatch(state, &outcome);
                    apply_import_dispatch_inplace(state, &dispatch);
                    dispatch
                });
                if let Some(dispatch) = dispatch {
                    if let Some(msg) = dispatch.dialog_msg {
                        if let Some(controller) = self.import_dialog.as_ref() {
                            controller.emit(msg);
                        }
                    }
                    if dispatch.drop_dialog {
                        // Defensive only — `should_drop_import_dialog_after`
                        // always returns `false`. Kept as a hook so a
                        // future `IMPLEMENTATION_PLAN_04_GTK.md`
                        // policy change can attach to this arm
                        // without modifying every call site.
                        if let Some(controller) = self.import_dialog.take() {
                            controller.widget().force_close();
                        }
                    }
                    if dispatch.refresh_list {
                        self.refresh_account_list();
                    }
                }
            }
            AppMsg::OpenExportDialog => {
                // Application menu "Export…" activation. Mount a fresh
                // `ExportDialogComponent` seeded with the resolved
                // vault path and present the `adw::Dialog` modally.
                // The menu entry's sensitivity is gated against
                // `AppState::allows_mutating_menu` (`Unlocked` only),
                // but a stray dispatch from a future keyboard
                // accelerator could still arrive in a non-unlocked
                // state — defend against that here so the dialog
                // never mounts over a `Missing` / `Locked` /
                // `UnlockedBusy` / `StartupError` window.
                if let Some(state) = self.state.as_ref() {
                    if state.is_unlocked() {
                        if let Some(path) = state.path() {
                            let init = ExportDialogInit {
                                vault_path: path.to_path_buf(),
                            };
                            let controller = ExportDialogComponent::builder()
                                .launch(init)
                                .forward(sender.input_sender(), AppMsg::ExportDialogAction);
                            controller.widget().present(Some(&self.content));
                            self.export_dialog = Some(controller);
                        }
                    }
                }
            }
            AppMsg::ExportDialogAction(ExportDialogOutput::Cancel | ExportDialogOutput::Close) => {
                // User dismissed the `adw::Dialog` — either by the
                // explicit Cancel button (`ExportDialogOutput::Cancel`),
                // by Escape / window close (`ExportDialogOutput::Close`),
                // or by the dialog's own post-success `Close` emitted
                // from `WorkerCompleted(Success)`. All three drop the
                // live controller so the widget is released and any
                // in-flight pending form draft (selected destination
                // path, format choice, overwrite acknowledgement,
                // plaintext-warning acknowledgement, twice-confirm
                // passphrase entries) is discarded; the variants stay
                // distinct in
                // [`crate::export_dialog::ExportDialogOutput`] so a
                // future "Discard draft?" prompt can attach to one
                // path without affecting the other. `adw::Dialog`
                // self-detaches from its toplevel parent on close,
                // so no `self.content.remove` is needed — unlike
                // `AddAccountComponent` / `RenameDialogComponent` /
                // `RemoveDialogComponent` which are appended into
                // the content tree directly. Defensive: if the field
                // is already `None` (controller swapped under us by
                // a future race), this is a benign no-op.
                self.export_dialog = None;
            }
            AppMsg::ExportDialogAction(ExportDialogOutput::Submit(payload)) => {
                // Entry side of the `gio::spawn_blocking
                // write_secret_file_atomic(otpauth_list | encrypted)`
                // worker. Mirrors the import-dialog submit handler
                // step-for-step:
                //
                // 1. Take the live `(Vault, Store)` pair from
                //    `self.vault` and bundle it with the dispatch
                //    payload (destination, format, encryption
                //    options) into an `ExportWorkerInput` via
                //    `compose_export_worker_input`. Only `Unlocked`
                //    returns `Ok(input)`; every other variant returns
                //    `Err(pair)` so the wrapper can reinstall the
                //    pair via `apply_export_vault_install_inplace`.
                //    A `None` state or a `None` vault slot is the
                //    defensive no-op (a stray `Submit` from a locked
                //    / missing / busy state).
                // 2. Apply the `Unlocked → UnlockedBusy` busy-gate
                //    transition via `apply_submit_export_inplace`,
                //    then push `SetBusy(true)` to the dialog so the
                //    Export button dims.
                // 3. Spawn `run_export_worker` on
                //    `gtk::gio::spawn_blocking` so the encrypted-
                //    bundle path's fresh-AEAD-key derivation and the
                //    multi-fsync `write_secret_file_atomic` pipeline
                //    do not block the GTK main loop. The wrapping
                //    `gtk::glib::spawn_future_local` awaits the
                //    blocking handle and posts the bundled
                //    `ExportWorkerCompletion` back to `AppModel` via
                //    `AppMsg::ExportWorkerCompleted`.
                let worker_input = match (self.state.as_ref(), self.vault.take()) {
                    (Some(state), Some(pair)) => {
                        match compose_export_worker_input(state, pair, payload) {
                            Ok(input) => Some(input),
                            Err(pair) => {
                                apply_export_vault_install_inplace(&mut self.vault, pair);
                                None
                            }
                        }
                    }
                    (None, Some(pair)) => {
                        apply_export_vault_install_inplace(&mut self.vault, pair);
                        None
                    }
                    (_, None) => None,
                };
                if let Some(state) = self.state.as_mut() {
                    apply_submit_export_inplace(state);
                }
                if let Some(input) = worker_input {
                    if let Some(controller) = self.export_dialog.as_ref() {
                        controller.emit(ExportDialogMsg::SetBusy(true));
                    }
                    let sender = sender.clone();
                    gtk::glib::spawn_future_local(async move {
                        let completion = gtk::gio::spawn_blocking(move || run_export_worker(input))
                            .await
                            .expect("write_secret_file_atomic export worker panicked");
                        sender.input(AppMsg::ExportWorkerCompleted(completion));
                    });
                }
            }
            AppMsg::ExportWorkerCompleted(completion) => {
                // Worker-outcome dispatch. `compose_export_dispatch`
                // bundles the typed `ExportOutcome` over the cached
                // `AppState` and the worker's destination path into:
                //
                // * `app_state` — `UnlockedBusy → Unlocked` rollback
                //   regardless of typed outcome (export does not
                //   mutate the vault, but the busy gate releases on
                //   every branch).
                // * `dialog_msg` — `Some(WorkerCompleted(outcome))`
                //   on every branch so the dialog renders the typed
                //   success / warning / inline error inline (on
                //   `Success` the dialog itself emits
                //   `ExportDialogOutput::Close`, which drops the
                //   controller via the `Cancel | Close` arm above).
                // * `drop_dialog` — `true` on Success so `AppModel`
                //   force-closes the dialog widget immediately;
                //   `false` on `DurabilityWarning` / `Inline` so the
                //   inline body stays visible.
                // * `success_toast` — `Some(body)` only on Success
                //   (names the written destination); `None`
                //   otherwise.
                //
                // The carried `(vault, store)` pair is reinstalled
                // into `AppModel::vault` via
                // `apply_export_vault_install_inplace`
                // unconditionally — export does not mutate the
                // vault, so the returned pair is the same one we
                // moved into the worker; the round-trip keeps the
                // ownership model identical to the import / rename /
                // remove paths.
                let ExportWorkerCompletion {
                    outcome,
                    vault,
                    store,
                    destination,
                } = completion;
                apply_export_vault_install_inplace(&mut self.vault, (vault, store));
                let dispatch = self.state.as_mut().map(|state| {
                    let dispatch = compose_export_dispatch(state, &outcome, &destination);
                    apply_export_dispatch_inplace(state, &dispatch);
                    dispatch
                });
                if let Some(dispatch) = dispatch {
                    if let Some(msg) = dispatch.dialog_msg {
                        if let Some(controller) = self.export_dialog.as_ref() {
                            controller.emit(msg);
                        }
                    }
                    if dispatch.drop_dialog {
                        if let Some(controller) = self.export_dialog.take() {
                            controller.widget().force_close();
                        }
                    }
                    if let Some(body) = dispatch.success_toast {
                        self.toast_overlay.add_toast(adw::Toast::new(&body));
                    }
                }
            }
            AppMsg::OpenPassphraseDialog => {
                // Application menu "Passphrase…" activation. Mount a
                // fresh `PassphraseDialogComponent` seeded with the
                // resolved vault path and the encryption snapshot the
                // sub-flow gating
                // ([`crate::passphrase_dialog::available_sub_flows`])
                // depends on, then present the `adw::Dialog` modally.
                // The menu entry's sensitivity is gated against
                // `AppState::allows_mutating_menu` (`Unlocked` only),
                // but a stray dispatch from a future keyboard
                // accelerator could still arrive in a non-unlocked
                // state — defend against that here so the dialog
                // never mounts over a `Missing` / `Locked` /
                // `UnlockedBusy` / `StartupError` window.
                if let Some(state) = self.state.as_ref() {
                    if state.is_unlocked() {
                        if let Some((vault, _)) = self.vault.as_ref() {
                            if let Some(path) = state.path() {
                                let init = PassphraseDialogInit {
                                    vault_path: path.to_path_buf(),
                                    is_encrypted: vault.is_encrypted(),
                                };
                                let controller = PassphraseDialogComponent::builder()
                                    .launch(init)
                                    .forward(sender.input_sender(), AppMsg::PassphraseDialogAction);
                                controller.widget().present(Some(&self.content));
                                self.passphrase_dialog = Some(controller);
                            }
                        }
                    }
                }
            }
            AppMsg::PassphraseDialogAction(PassphraseDialogOutput::Close) => {
                // User dismissed the `adw::Dialog`. Drop the live
                // controller so the widget is released and any
                // in-flight pending form draft (selected sub-flow,
                // current / new / confirm passphrase entries, pending
                // destructive acknowledgement) is discarded.
                // `adw::Dialog` self-detaches from its toplevel
                // parent on close, so no `self.content.remove` is
                // needed — unlike `AddAccountComponent` /
                // `RenameDialogComponent` / `RemoveDialogComponent`
                // which are appended into the content tree directly.
                // Defensive: if the field is already `None`
                // (controller swapped under us by a future race),
                // this is a benign no-op.
                self.passphrase_dialog = None;
            }
            AppMsg::OpenAddDialog => {
                // Header-bar `+` button activation. Mount a fresh
                // `AddAccountComponent` seeded with the resolved
                // vault path. The button visibility is `#[watch]`'d
                // against `AppState::is_unlocked`, but a stray
                // dispatch from a future keyboard shortcut could
                // still arrive in a non-unlocked state — defend
                // against that here so the dialog never mounts over
                // a `Missing` / `Locked` / `StartupError` window.
                if let Some(state) = self.state.as_ref() {
                    if state.is_unlocked() {
                        if let Some(path) = state.path() {
                            let init = AddAccountInit {
                                vault_path: path.to_path_buf(),
                            };
                            let controller = AddAccountComponent::builder()
                                .launch(init)
                                .forward(sender.input_sender(), AppMsg::AddAccountAction);
                            self.content.append(controller.widget());
                            self.add_dialog = Some(controller);
                        }
                    }
                }
            }
            AppMsg::AddAccountAction(AddAccountOutput::Cancel | AddAccountOutput::Close) => {
                // Detach the dialog widget from the content tree and
                // drop the controller. Both arms behave identically
                // today — `AddAccountOutput::Cancel` (explicit Cancel
                // button) and `AddAccountOutput::Close` (window-close
                // / modal-dismissal) flow through the same dismissal
                // path because the dialog already wiped its
                // path-local secret state in `apply_msg` before
                // forwarding the output (see the centralized
                // `ClearReason::Cancel` / `ClearReason::Close`
                // handlers). The variants stay distinct so a future
                // Close-only behavior (e.g. surfacing a "Discard
                // draft?" prompt) can split the arm without a `_`
                // catch-all silently swallowing the new behavior.
                // Defensive: if the field is already `None`
                // (controller swapped under us by a future race),
                // this is a benign no-op.
                if let Some(controller) = self.add_dialog.take() {
                    self.content.remove(controller.widget());
                }
            }
            AppMsg::AddAccountAction(AddAccountOutput::Submit { account }) => {
                // Save-button entry side of the `gio::spawn_blocking
                // Vault::mutate_and_save(|v| v.add(account))` worker.
                // Mirrors the `RenameDialogOutput::SubmitLabel` and
                // `RemoveDialogOutput::SubmitConfirm` handlers step-
                // for-step:
                //
                // 1. Take the live `(Vault, Store)` pair from
                //    `self.vault` and bundle it with the validated
                //    `Account` into an `AddWorkerInput` via
                //    `compose_add_worker_input`. The composer
                //    inspects the cached `AppState`: only `Unlocked`
                //    returns `Ok(input)`; every other variant returns
                //    `Err(pair)` so the wrapper can reinstall the
                //    pair via `apply_add_vault_install_inplace`. A
                //    `None` state or a `None` vault slot is the
                //    defensive no-op (a stray `Submit` from a locked
                //    / missing / busy state).
                // 2. Apply the `Unlocked → UnlockedBusy` busy-gate
                //    transition via `apply_submit_add_inplace` so
                //    `is_busy()` / `allows_mutating_menu()` cover the
                //    worker's lifetime. The dialog stays mounted —
                //    `should_drop_add_dialog_after` keeps it on every
                //    failure branch and the worker's success dispatch
                //    drops it once the worker returns.
                // 3. Spawn `run_add_worker` on
                //    `gtk::gio::spawn_blocking` so the
                //    `mutate_and_save` durability fsync hop does not
                //    block the GTK main loop. The wrapping
                //    `gtk::glib::spawn_future_local` awaits the
                //    blocking handle and posts the bundled
                //    `AddWorkerCompletion` back to `AppModel` via
                //    `AppMsg::AddWorkerCompleted`, consumed by the
                //    dispatch branch wired above.
                //
                // Unlike `RenameDialogOutput::SubmitLabel`, the add
                // path does not need to capture `SystemTime::now()`
                // at the dispatch site — the validated `Account`
                // already carries the `created_at` / `updated_at`
                // stamps from the widget's earlier
                // `validate_manual` / `parse_otpauth` call.
                let worker_input = match (self.state.as_ref(), self.vault.take()) {
                    (Some(state), Some(pair)) => {
                        match compose_add_worker_input(state, pair, account) {
                            Ok(input) => Some(input),
                            Err(pair) => {
                                apply_add_vault_install_inplace(&mut self.vault, pair);
                                None
                            }
                        }
                    }
                    (None, Some(pair)) => {
                        apply_add_vault_install_inplace(&mut self.vault, pair);
                        None
                    }
                    (_, None) => None,
                };
                if let Some(state) = self.state.as_mut() {
                    apply_submit_add_inplace(state);
                }
                if let Some(input) = worker_input {
                    let sender = sender.clone();
                    gtk::glib::spawn_future_local(async move {
                        let completion = gtk::gio::spawn_blocking(move || run_add_worker(input))
                            .await
                            .expect("Vault::mutate_and_save add worker panicked");
                        sender.input(AppMsg::AddWorkerCompleted(completion));
                    });
                }
            }
            AppMsg::AddAccountAction(AddAccountOutput::RequestSaveClick) => {
                // Shared Save-button compose request. The dialog
                // cannot run `compose_save_click_outcome` itself
                // because the duplicate-detection pre-flight
                // borrows `&Vault` and the dialog never owns the
                // live `(Vault, Store)` pair. `AppModel` borrows
                // the cached dialog state via
                // `ComponentController::model`, borrows the live
                // vault from `self.vault`, runs the composer with
                // `SystemTime::now()` captured here so a long
                // worker queue cannot stamp a stale
                // `Code.timestamp`, and dispatches the resulting
                // `AddAccountMsg` back via
                // `controller.emit(save_click_outcome_to_msg(outcome))`.
                //
                // Defensive: a `None` controller, a `None` vault
                // slot, or a non-`Unlocked` cached state all
                // short-circuit to a benign no-op. The shared
                // pipeline keeps the manual / URI submit paths
                // converging on a single
                // `AddAccountOutput::Submit { account }` boundary
                // per `IMPLEMENTATION_PLAN_04_GTK.md`
                // §"Component tree" > `AddAccountComponent`
                // shared shell L2161 — the `SubmitProceed` arm
                // emitted by `save_click_outcome_to_msg` flows
                // through the same `AddAccountOutput::Submit`
                // handler above.
                if let (Some(controller), Some((vault, _store)), Some(app_state)) = (
                    self.add_dialog.as_ref(),
                    self.vault.as_ref(),
                    self.state.as_ref(),
                ) {
                    if matches!(app_state, AppState::Unlocked { .. }) {
                        let now = SystemTime::now();
                        let outcome = {
                            let model_ref = controller.model();
                            crate::add_account::compose_save_click_outcome(
                                &model_ref.state,
                                vault,
                                now,
                            )
                        };
                        controller.emit(crate::add_account::save_click_outcome_to_msg(outcome));
                    }
                }
            }
            AppMsg::AddAccountAction(AddAccountOutput::RequestScanClipboard) => {
                // Clipboard-QR activation entry point. Symmetric
                // with `RequestSaveClick`: the dialog forwards the
                // page-local Scan button click up to `AppModel`
                // because the live `gdk::Display` / `gdk::Clipboard`
                // / `gdk::TextureDownloader` round-trip and the
                // `Vault::mutate_and_save(|v|
                // v.import_accounts(...))` worker both live on the
                // parent.
                //
                // Defensive: a `None` controller, a `None` vault
                // slot, or a non-`Unlocked` cached state all
                // short-circuit to a benign no-op so a stray click
                // during a worker round trip cannot punch through
                // (mirror of `RequestSaveClick`).
                let ready = matches!(
                    (
                        self.add_dialog.as_ref(),
                        self.vault.as_ref(),
                        self.state.as_ref(),
                    ),
                    (Some(_), Some(_), Some(AppState::Unlocked { .. })),
                );
                if ready {
                    // Capture the import-time stamp at the dispatch
                    // site so a long async clipboard read cannot
                    // stamp a stale `updated_at` for any replaced
                    // row (parity with `RequestSaveClick`'s
                    // `SystemTime::now()` capture).
                    let import_time = SystemTime::now();
                    let clipboard = WidgetExt::display(&self.content).clipboard();
                    let dispatch = sender.clone();
                    clipboard.read_texture_async(None::<&gtk::gio::Cancellable>, move |result| {
                        let outcome = load_clipboard_qr_capture(result, import_time);
                        dispatch.input(AppMsg::QrClipboardLoaded(outcome));
                    });
                }
            }
            AppMsg::QrClipboardLoaded(result) => {
                // Wake-up after the asynchronous
                // `gdk::Clipboard::read_texture_async` callback
                // resolves. The callback runs the pre-worker
                // preflight pipeline (`classify_layout_preflight`
                // → `gdk::TextureDownloader::download_bytes` →
                // `compose_qr_decode_outcome` →
                // `classify_qr_outcome`) before posting back so the
                // dispatch decision below is shape-only.
                //
                // `route_qr_clipboard_loaded` projects the typed
                // result into two arms: an `InlineError` for any of
                // the four preflight failure categories (no
                // clipboard image, oversized layout, GDK download
                // mismatch, decoder failure) and a `SpawnWorker` for
                // the success path. The dialog stays mounted on
                // every branch (parity with the QR sub-path's
                // `compose_qr_dispatch` keep-mounted invariant).
                match route_qr_clipboard_loaded(result) {
                    QrClipboardLoadedDispatch::InlineError(inline) => {
                        if let Some(controller) = self.add_dialog.as_ref() {
                            controller.emit(AddAccountMsg::RenderInlineError(inline));
                        }
                    }
                    QrClipboardLoadedDispatch::SpawnWorker(accounts) => {
                        // Mirror of the `Submit { account }` Add-
                        // worker dispatch — `compose_qr_worker_input`
                        // gates on `Unlocked` (every other variant
                        // refuses and returns the live pair so
                        // `apply_add_vault_install_inplace` can put
                        // it back); `apply_submit_add_inplace` flips
                        // the busy gate; `gtk::gio::spawn_blocking`
                        // runs `run_qr_worker` so the
                        // `mutate_and_save` durability fsync hop
                        // does not block the GTK main loop.
                        //
                        // Re-uses the captured `SystemTime::now()`
                        // from the dispatch site that fired the
                        // clipboard read so the import_time threads
                        // through the entire pipeline (the read may
                        // resolve seconds later but the decode time
                        // the user saw is the wake-up time).
                        let worker_input = match (self.state.as_ref(), self.vault.take()) {
                            (Some(state), Some(pair)) => {
                                match compose_qr_worker_input(
                                    state,
                                    pair,
                                    accounts,
                                    SystemTime::now(),
                                ) {
                                    Ok(input) => Some(input),
                                    Err(pair) => {
                                        apply_add_vault_install_inplace(&mut self.vault, pair);
                                        None
                                    }
                                }
                            }
                            (None, Some(pair)) => {
                                apply_add_vault_install_inplace(&mut self.vault, pair);
                                None
                            }
                            (_, None) => None,
                        };
                        if let Some(state) = self.state.as_mut() {
                            apply_submit_add_inplace(state);
                        }
                        if let Some(input) = worker_input {
                            let sender = sender.clone();
                            gtk::glib::spawn_future_local(async move {
                                let completion =
                                    gtk::gio::spawn_blocking(move || run_qr_worker(input))
                                        .await
                                        .expect("Vault::mutate_and_save QR worker panicked");
                                sender.input(AppMsg::QrWorkerCompleted(completion));
                            });
                        }
                    }
                }
            }
            AppMsg::RemoveDialogAction(RemoveDialogOutput::SubmitConfirm { account_id }) => {
                // Entry side of the `gio::spawn_blocking
                // Vault::mutate_and_save(|v| v.remove(account_id))`
                // worker. Mirrors the rename `SubmitLabel` handler
                // step-for-step:
                //
                // 1. Take the live `(Vault, Store)` pair from
                //    `self.vault` and bundle it with the dispatch
                //    payload into a `RemoveWorkerInput` via
                //    `compose_remove_worker_input`. Only `Unlocked`
                //    returns `Ok(input)`; every other variant returns
                //    `Err(pair)` so the wrapper can reinstall the
                //    pair via `apply_remove_vault_install_inplace`.
                //    A `None` state or a `None` vault slot is the
                //    defensive no-op (a stray `SubmitConfirm` from a
                //    locked / missing / busy state).
                // 2. Apply the `Unlocked → UnlockedBusy` busy-gate
                //    transition via `apply_submit_remove_inplace` so
                //    `is_busy()` / `allows_mutating_menu()` cover the
                //    worker's lifetime. The dialog stays mounted —
                //    `should_drop_remove_dialog_after` keeps it on
                //    every failure branch and the worker's success
                //    dispatch drops it once the worker returns.
                // 3. Spawn `run_remove_worker` on
                //    `gtk::gio::spawn_blocking` so the
                //    `mutate_and_save` durability fsync hop does not
                //    block the GTK main loop. The wrapping
                //    `gtk::glib::spawn_future_local` awaits the
                //    blocking handle and posts the bundled
                //    `RemoveWorkerCompletion` back to `AppModel` via
                //    `AppMsg::RemoveWorkerCompleted`, which is
                //    consumed by the dispatch branch wired below.
                let worker_input = match (self.state.as_ref(), self.vault.take()) {
                    (Some(state), Some(pair)) => {
                        match compose_remove_worker_input(state, pair, account_id) {
                            Ok(input) => Some(input),
                            Err(pair) => {
                                apply_remove_vault_install_inplace(&mut self.vault, pair);
                                None
                            }
                        }
                    }
                    (None, Some(pair)) => {
                        apply_remove_vault_install_inplace(&mut self.vault, pair);
                        None
                    }
                    (_, None) => None,
                };
                if let Some(state) = self.state.as_mut() {
                    apply_submit_remove_inplace(state);
                }
                if let Some(input) = worker_input {
                    let sender = sender.clone();
                    gtk::glib::spawn_future_local(async move {
                        let completion = gtk::gio::spawn_blocking(move || run_remove_worker(input))
                            .await
                            .expect("Vault::mutate_and_save remove worker panicked");
                        sender.input(AppMsg::RemoveWorkerCompleted(completion));
                    });
                }
            }
            AppMsg::UnlockDialogAction(UnlockDialogOutput::SubmitLock(lock)) => {
                // Entry side of the `gio::spawn_blocking
                // paladin_core::open` worker. Three steps run in
                // order per `IMPLEMENTATION_PLAN_04_GTK.md`
                // §"Vault interaction":
                //
                // 1. Capture `(path, VaultLock)` into an
                //    `UnlockWorkerInput` via
                //    `compose_unlock_worker_input` while the cached
                //    `AppState` is still `Locked` — the composer
                //    inspects the variant and clones the path out
                //    before the busy-gate transition would consume
                //    it. `VaultLock` moves into the bundle by value
                //    so the `secrecy::SecretString` carried by
                //    `VaultLock::Encrypted` zeroes on drop after the
                //    Argon2 KDF step.
                // 2. Apply the `Locked → UnlockedBusy` busy-gate
                //    transition via `apply_submit_unlock_inplace`
                //    so `is_busy()` / `allows_mutating_menu()`
                //    cover the worker's lifetime. The dialog stays
                //    mounted — `should_drop_unlock_dialog_after`
                //    keeps it on the inline branch and the
                //    worker's success / startup-failure dispatch
                //    drops it once the worker returns.
                // 3. Spawn `run_unlock_worker` on
                //    `gtk::gio::spawn_blocking` so the §4.4
                //    Argon2 KDF (m=64 MiB defaults) does not
                //    block the GTK main loop. The wrapping
                //    `gtk::glib::spawn_future_local` awaits the
                //    blocking handle and posts the bundled
                //    `UnlockWorkerCompletion` back to `AppModel`
                //    via `AppMsg::UnlockWorkerCompleted`, which is
                //    consumed by the dispatch branch wired below.
                //
                // A `None` capture from `compose_unlock_worker_input`
                // means `SubmitLock` arrived from a non-`Locked`
                // state — a benign no-op for the worker spawn just
                // as `apply_submit_unlock_inplace` is a no-op for
                // the same source variants.
                let worker_input = self
                    .state
                    .as_ref()
                    .and_then(|state| compose_unlock_worker_input(state, lock));
                if let Some(state) = self.state.as_mut() {
                    apply_submit_unlock_inplace(state);
                }
                if let Some(input) = worker_input {
                    let sender = sender.clone();
                    gtk::glib::spawn_future_local(async move {
                        let completion = gtk::gio::spawn_blocking(move || run_unlock_worker(input))
                            .await
                            .expect("paladin_core::Store::open unlock worker panicked");
                        sender.input(AppMsg::UnlockWorkerCompleted(completion));
                    });
                }
            }
            AppMsg::UnlockWorkerCompleted(completion) => {
                // Worker-outcome dispatch. `compose_unlock_dispatch`
                // bundles the typed `UnlockWorkerEffect` over the
                // cached `AppState` into the three projections
                // pinned in `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault
                // interaction":
                //
                // * `app_state` — the state replacement
                //   (`UnlockedBusy` → `Unlocked` on success, →
                //   `StartupError` on a non-passphrase failure, or
                //   rollback to `Locked` on the inline branch),
                //   applied in-place via
                //   `apply_unlock_dispatch_inplace`. The `None`
                //   defensive case (inline branch from a non-
                //   `UnlockedBusy` source — a stray dispatch) leaves
                //   `AppModel::state` byte-for-byte intact.
                // * `dialog_msg` — `Some(OpenFailedInline(_))` on
                //   the inline branch, forwarded to the live
                //   `UnlockDialogComponent` so the typed
                //   passphrase-failure error re-renders inline.
                // * `drop_dialog` — `true` on the two replacement
                //   branches, detaching the dialog widget from the
                //   content tree and dropping the controller so the
                //   replacement view (`AccountListComponent` /
                //   `StartupErrorComponent`) is the only visible
                //   chrome. The two side-effects are mutually
                //   exclusive: replacement branches carry
                //   `dialog_msg = None` and inline branches carry
                //   `drop_dialog = false`.
                //
                // The carried `pair` is installed into
                // `AppModel::vault` via
                // `apply_unlock_vault_install_inplace`: `Some(pair)`
                // writes through on the success branch (the only
                // outcome of `route_unlock_open_completion` that
                // carries a live `(Vault, Store)`), `None` leaves
                // the slot byte-for-byte intact on every failure
                // branch so a stray completion can never clobber a
                // live unlocked pair.
                let UnlockWorkerCompletion { effect, pair } = completion;
                apply_unlock_vault_install_inplace(&mut self.vault, pair);
                let dispatch = self.state.as_mut().map(|state| {
                    let dispatch = compose_unlock_dispatch(state, &effect);
                    apply_unlock_dispatch_inplace(state, &dispatch);
                    dispatch
                });
                if let Some(dispatch) = dispatch {
                    if let Some(msg) = dispatch.dialog_msg {
                        if let Some(controller) = self.unlock_dialog.as_ref() {
                            controller.emit(msg);
                        }
                    }
                    if dispatch.drop_dialog {
                        if let Some(controller) = self.unlock_dialog.take() {
                            self.content.remove(controller.widget());
                        }
                    }
                }
            }
            AppMsg::InitDialogAction(output) => {
                // Spawn the `paladin_core::Store::create` /
                // `Store::create_force` worker once the dialog hands
                // back a [`VaultInit`]. The `Missing` state owns no
                // live `(Vault, Store)` pair — the worker returns one
                // on success and we install it via the
                // `InitWorkerCompleted` arm below. The vault path
                // comes from the cached `AppState::Missing` variant
                // (the dialog's local copy is the same path).
                //
                // The widget's submit-button sensitivity gate
                // (`InitDialogState::submit_button_sensitive`) and
                // `apply_msg`'s rejection routing keep buffer-empty
                // and confirmation-mismatch submissions from reaching
                // here, so the worker spawn is unconditional once we
                // have the path.
                let (mode, init) = match output {
                    InitDialogOutput::SubmitCreate(init) => (InitWorkerMode::Create, init),
                    InitDialogOutput::SubmitForceCreate(init) => {
                        (InitWorkerMode::CreateForce, init)
                    }
                };
                let vault_path = self
                    .state
                    .as_ref()
                    .and_then(AppState::path)
                    .map(Path::to_path_buf);
                if let Some(vault_path) = vault_path {
                    let input = InitWorkerInput {
                        init,
                        vault_path,
                        mode,
                    };
                    let sender = sender.clone();
                    gtk::glib::spawn_future_local(async move {
                        let completion = gtk::gio::spawn_blocking(move || run_init_worker(input))
                            .await
                            .expect("paladin_core::Store::create init worker panicked");
                        sender.input(AppMsg::InitWorkerCompleted(completion));
                    });
                }
            }
            AppMsg::InitWorkerCompleted(completion) => {
                // Worker-outcome dispatch per
                // `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction":
                //
                // * `Success { vault, store }` — install the returned
                //   pair into `AppModel::vault`, transition
                //   `AppModel::state` from `Missing` to `Unlocked`
                //   (preserving the resolved path) via
                //   `remount_for_state`, which also drops the init
                //   dialog and mounts the AccountListComponent.
                // * `DestructiveGate` — forward
                //   `InitDialogMsg::WorkerCompletedDestructive` to the
                //   live dialog so it rebuilds the pending VaultInit
                //   and presents the destructive AdwAlertDialog.
                // * `InlineError(err)` — forward
                //   `InitDialogMsg::WorkerCompletedInline(err)` so the
                //   dialog stages the inline projection.
                let InitWorkerCompletion { effect } = completion;
                match effect {
                    InitWorkerEffect::Success { vault, store } => {
                        let path = self
                            .state
                            .as_ref()
                            .and_then(AppState::path)
                            .map(Path::to_path_buf);
                        if let Some(path) = path {
                            self.vault = Some((vault, store));
                            let new_state = AppState::Unlocked { path };
                            self.remount_for_state(&new_state, &sender);
                            self.state = Some(new_state);
                        }
                    }
                    InitWorkerEffect::DestructiveGate => {
                        if let Some(controller) = self.init_dialog.as_ref() {
                            controller.emit(InitDialogMsg::WorkerCompletedDestructive);
                        }
                    }
                    InitWorkerEffect::InlineError(inline) => {
                        if let Some(controller) = self.init_dialog.as_ref() {
                            controller.emit(InitDialogMsg::WorkerCompletedInline(inline));
                        }
                    }
                }
            }
            AppMsg::RemoveWorkerCompleted(completion) => {
                // Worker-outcome dispatch. Mirrors
                // `RenameWorkerCompleted` exactly: `compose_remove_dispatch`
                // bundles the typed `RemoveWorkerEffect` over the
                // cached `AppState` into a `RemoveDispatch`:
                //
                // * `app_state` — `UnlockedBusy → Unlocked` rollback
                //   regardless of typed effect (`mutate_and_save` is
                //   authoritative for the rollback / durability-
                //   unconfirmed semantics, so the busy gate always
                //   releases). The `None` defensive case (worker
                //   outcome arrived but the cached state was not
                //   `UnlockedBusy`) leaves `AppModel::state` intact.
                // * `dialog_msg` — `Some(WorkerFailed(outcome))` on
                //   every failure branch, forwarded to the live
                //   `RemoveDialogComponent` so the typed
                //   `save_not_committed` / `save_durability_unconfirmed`
                //   / defensive error re-renders inline.
                // * `drop_dialog` — `true` on the success branch
                //   only, detaching the dialog widget so the
                //   `AccountListComponent` re-renders with the
                //   targeted row gone.
                //
                // The carried `(vault, store)` pair is reinstalled
                // into `AppModel::vault` via
                // `apply_remove_vault_install_inplace`
                // unconditionally — `mutate_and_save` is authoritative
                // for the post-remove / rollback state across every
                // effect branch.
                let RemoveWorkerCompletion {
                    effect,
                    vault,
                    store,
                } = completion;
                apply_remove_vault_install_inplace(&mut self.vault, (vault, store));
                let dispatch = self.state.as_mut().map(|state| {
                    let dispatch = compose_remove_dispatch(state, &effect);
                    apply_remove_dispatch_inplace(state, &dispatch);
                    dispatch
                });
                if let Some(dispatch) = dispatch {
                    if let Some(msg) = dispatch.dialog_msg {
                        if let Some(controller) = self.remove_dialog.as_ref() {
                            controller.emit(msg);
                        }
                    }
                    if dispatch.drop_dialog {
                        // `adw::AlertDialog` auto-dismisses on the
                        // response click that triggered the worker, so
                        // explicitly `force_close` here covers the
                        // race where the worker returns before the
                        // dismissal completes, then drop the
                        // controller. No `self.content.remove` —
                        // `adw::AlertDialog` self-detaches from its
                        // toplevel parent on close.
                        if let Some(controller) = self.remove_dialog.take() {
                            controller.widget().force_close();
                        }
                    }
                    if dispatch.refresh_list {
                        self.refresh_account_list();
                    }
                    if let Some(body) = dispatch.success_toast {
                        self.toast_overlay.add_toast(adw::Toast::new(&body));
                    }
                }
            }
            AppMsg::RenameWorkerCompleted(completion) => {
                // Worker-outcome dispatch. `compose_rename_dispatch`
                // bundles the typed `RenameWorkerEffect` over the
                // cached `AppState` into the three projections
                // pinned in `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault
                // interaction":
                //
                // * `app_state` — `UnlockedBusy → Unlocked` rollback
                //   regardless of typed effect (`mutate_and_save` is
                //   authoritative for the rollback / durability-
                //   unconfirmed semantics, so the busy gate always
                //   releases). The `None` defensive case (worker
                //   outcome arrived but the cached state was not
                //   `UnlockedBusy` — a stray dispatch) leaves
                //   `AppModel::state` byte-for-byte intact.
                // * `dialog_msg` — `Some(WorkerFailed(outcome))` on
                //   every failure branch, forwarded to the live
                //   `RenameDialogComponent` so the typed `save_not_
                //   committed` / `save_durability_unconfirmed` /
                //   defensive error re-renders inline.
                // * `drop_dialog` — `true` on the success branch
                //   only, detaching the dialog widget from the
                //   content tree and dropping the controller so the
                //   `AccountListComponent` row re-renders with the
                //   new label. The two side-effects are mutually
                //   exclusive: success carries
                //   `dialog_msg = None`, failure carries
                //   `drop_dialog = false`.
                //
                // The carried `(vault, store)` pair is reinstalled
                // into `AppModel::vault` via
                // `apply_rename_vault_install_inplace`
                // unconditionally — `mutate_and_save` is
                // authoritative for the post-rename / rollback
                // state, so reinstalling the pair is the right
                // behavior across every effect branch.
                let RenameWorkerCompletion {
                    effect,
                    vault,
                    store,
                } = completion;
                apply_rename_vault_install_inplace(&mut self.vault, (vault, store));
                let dispatch = self.state.as_mut().map(|state| {
                    let dispatch = compose_rename_dispatch(state, &effect);
                    apply_rename_dispatch_inplace(state, &dispatch);
                    dispatch
                });
                if let Some(dispatch) = dispatch {
                    if let Some(msg) = dispatch.dialog_msg {
                        if let Some(controller) = self.rename_dialog.as_ref() {
                            controller.emit(msg);
                        }
                    }
                    if dispatch.drop_dialog {
                        if let Some(controller) = self.rename_dialog.take() {
                            self.content.remove(controller.widget());
                        }
                    }
                    if dispatch.refresh_list {
                        self.refresh_account_list();
                    }
                    if let Some(body) = dispatch.success_toast {
                        self.toast_overlay.add_toast(adw::Toast::new(&body));
                    }
                }
            }
            AppMsg::HotpAdvanceWorkerCompleted(completion) => {
                // Worker-outcome dispatch per `IMPLEMENTATION_PLAN_04_GTK.md`
                // §"Milestone 7 checklist" > "HOTP reveal window
                // behavior":
                //
                // * Reinstall the `(Vault, Store)` pair unconditionally
                //   (the worker is authoritative for the post-advance
                //   state — `mutate_and_save` already rolled back on
                //   pre-commit failures).
                // * Roll `UnlockedBusy → Unlocked` so the busy gate
                //   releases. A non-busy source state is a benign
                //   defensive case (a stray completion from a future
                //   race); we leave the state untouched.
                // * Route the typed `AdvanceOutcome` through the pure-
                //   logic state machine (`apply_advance_outcome` +
                //   `apply_advance_decision`) so the reveal-window map
                //   gains / replaces the entry for the affected account
                //   on success and on `save_durability_unconfirmed`,
                //   and stays put on every other typed error.
                // * Publish the visible code into the
                //   `AccountListComponent` cache via
                //   `AccountListMsg::Tick` so the row binds through
                //   the freshly inserted `RowDisplay`.
                // * Raise an `AdwToast` on the durability-unconfirmed
                //   path (warning) and on every other failure (status
                //   error) per the bullets in the plan.
                let HotpAdvanceWorkerCompletion {
                    outcome,
                    vault,
                    store,
                } = completion;
                self.vault = Some((vault, store));
                if let Some(state) = self.state.take() {
                    let new_state = state.clone().leave_busy().unwrap_or(state);
                    self.state = Some(new_state);
                }
                let account_id = outcome.account_id;
                let decision = apply_advance_outcome(outcome);
                let effect = apply_advance_decision(&mut self.reveal_windows, decision);
                self.publish_reveal_for(account_id, effect);
            }
            AppMsg::AddWorkerCompleted(completion) => {
                // Worker-outcome dispatch. Mirrors
                // `RenameWorkerCompleted` / `RemoveWorkerCompleted`
                // exactly: `compose_add_dispatch` bundles the typed
                // `AddWorkerEffect` over the cached `AppState` into
                // an `AddDispatch`:
                //
                // * `app_state` — `UnlockedBusy → Unlocked` rollback
                //   regardless of typed effect (`mutate_and_save` is
                //   authoritative for the rollback / durability-
                //   unconfirmed semantics, so the busy gate always
                //   releases). The `None` defensive case (worker
                //   outcome arrived but the cached state was not
                //   `UnlockedBusy`) leaves `AppModel::state` intact.
                // * `dialog_msg` — `Some(WorkerFailed(outcome))` on
                //   every failure branch, forwarded to the live
                //   `AddAccountComponent` so the typed
                //   `save_not_committed` /
                //   `save_durability_unconfirmed` / defensive error
                //   re-renders inline.
                // * `drop_dialog` — `true` on the success branch
                //   only, detaching the dialog widget so the
                //   `AccountListComponent` re-renders with the new
                //   row.
                //
                // The carried `(vault, store)` pair is reinstalled
                // into `AppModel::vault` via
                // `apply_add_vault_install_inplace`
                // unconditionally — `mutate_and_save` is
                // authoritative for the post-add / rollback state
                // across every effect branch.
                let AddWorkerCompletion {
                    effect,
                    vault,
                    store,
                } = completion;
                apply_add_vault_install_inplace(&mut self.vault, (vault, store));
                let dispatch = self.state.as_mut().map(|state| {
                    let dispatch = compose_add_dispatch(state, &effect);
                    apply_add_dispatch_inplace(state, &dispatch);
                    dispatch
                });
                if let Some(dispatch) = dispatch {
                    if let Some(msg) = dispatch.dialog_msg {
                        if let Some(controller) = self.add_dialog.as_ref() {
                            controller.emit(msg);
                        }
                    }
                    if dispatch.drop_dialog {
                        if let Some(controller) = self.add_dialog.take() {
                            self.content.remove(controller.widget());
                        }
                    }
                    if dispatch.refresh_list {
                        self.refresh_account_list();
                    }
                    if let Some(body) = dispatch.success_toast {
                        self.toast_overlay.add_toast(adw::Toast::new(&body));
                    }
                }
            }
            AppMsg::QrWorkerCompleted(completion) => {
                // Clipboard-QR worker-outcome dispatch. Symmetric
                // partner of `AddWorkerCompleted` on the QR sub-path
                // with two divergences pinned by `compose_qr_dispatch`
                // and exercised in
                // `tests/app_state_logic.rs::qr_pipeline_*`:
                //
                // * `drop_dialog` is always `false` — the dialog
                //   stays mounted on every effect so the counts panel
                //   (success) or inline error / durability warning
                //   (failure) can render against the still-mounted
                //   Add dialog.
                // * `dialog_msg` is `Some(_)` on every effect:
                //   `QrSuccess(QrImportSummary)` on Success so the
                //   counts panel surfaces `imported`/`skipped`/
                //   `warning` inline (parity with §6), and
                //   `WorkerFailed(outcome)` on every failure branch.
                //
                // `compose_qr_dispatch` bundles the four worker-
                // completion decisions (`app_state`, `dialog_msg`,
                // `drop_dialog`, `refresh_list`); the handler reuses
                // `apply_add_vault_install_inplace` for the
                // `(Vault, Store)` reinstallation because the QR
                // worker consumes and returns the same live pair the
                // add path does, then routes the dispatch through
                // `apply_qr_dispatch_inplace` for the busy-gate
                // rollback.
                let QrWorkerCompletion {
                    effect,
                    vault,
                    store,
                } = completion;
                apply_add_vault_install_inplace(&mut self.vault, (vault, store));
                let dispatch = self.state.as_mut().map(|state| {
                    let dispatch = compose_qr_dispatch(state, &effect);
                    apply_qr_dispatch_inplace(state, &dispatch);
                    dispatch
                });
                if let Some(dispatch) = dispatch {
                    if let Some(msg) = dispatch.dialog_msg {
                        if let Some(controller) = self.add_dialog.as_ref() {
                            controller.emit(msg);
                        }
                    }
                    if dispatch.drop_dialog {
                        if let Some(controller) = self.add_dialog.take() {
                            self.content.remove(controller.widget());
                        }
                    }
                    if dispatch.refresh_list {
                        self.refresh_account_list();
                    }
                }
            }
        }

        // Re-evaluate the TOTP ticker after every dispatch. The
        // `(state, rows)` snapshot may have transitioned through
        // `Locked → Unlocked` (unlock success), `Unlocked → Locked`
        // (auto-lock), `Missing → Unlocked` (init success), or
        // `has_visible_totp_row` may have flipped (Add / Remove
        // worker completions). `ticker_transition(was_installed,
        // ...)` collapses to `NoChange` for steady-state dispatches
        // (search query change, settings save with no TOTP delta,
        // dialog cancel) so this call is a benign no-op in the
        // common case.
        self.apply_ticker_transition(&sender);
        self.prune_reveals_if_locked();
        self.sync_account_list_busy();
        self.sync_add_dialog_busy();
    }
}

impl AppModel {
    /// Reconcile the live [`AccountListComponent`]'s busy flag against
    /// the current [`AppState::is_busy()`] reading.
    ///
    /// Called once per `AppModel::update` dispatch (alongside
    /// [`Self::apply_ticker_transition`] /
    /// [`Self::prune_reveals_if_locked`]) so every state transition
    /// that flips `is_busy` propagates to the row factory's
    /// `connect_bind` callback. Per `IMPLEMENTATION_PLAN_04_GTK.md`
    /// §"In-flight effect ownership" / §"Component tree" >
    /// `AccountRowComponent` ("Disable mutating row controls (copy,
    /// 'next', kebab) while `AppModel` is `UnlockedBusy`"), each
    /// flip re-splices the `gio::ListStore` so every visible row
    /// rebinds through [`crate::account_list::bind_display_for_row`]
    /// with the freshly masked [`crate::account_row::RowDisplay`].
    ///
    /// Debounced through [`Self::last_account_list_busy`] — when the
    /// dispatched value matches the last seen value, no message is
    /// emitted and the row store is not re-spliced. `Missing` /
    /// `Locked` / `StartupError` and the pre-init window all
    /// project to `is_busy() == false`, matching the initial cache
    /// value, so the first dispatch is also a benign no-op.
    fn sync_account_list_busy(&mut self) {
        let busy = self.state.as_ref().is_some_and(AppState::is_busy);
        if busy == self.last_account_list_busy {
            return;
        }
        self.last_account_list_busy = busy;
        if let Some(controller) = self.account_list.as_ref() {
            controller.emit(AccountListMsg::SetBusy(busy));
        }
    }

    /// Reconcile the live [`crate::add_account::AddAccountComponent`]'s
    /// busy flag against the current [`AppState::is_busy()`] reading.
    ///
    /// Peer of [`Self::sync_account_list_busy`] on the Add dialog
    /// side. Per `IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect
    /// ownership" the `Unlocked → UnlockedBusy` transition that
    /// brackets the `gio::spawn_blocking Vault::mutate_and_save(|v|
    /// v.add(...))` worker disables the dialog's submit (and
    /// dismissal) affordances; centralizing the dispatch here means
    /// every flip — including the `UnlockedBusy → Unlocked` rollback
    /// applied by [`apply_add_dispatch_inplace`] on worker
    /// completion — propagates through the same path that the row
    /// factory uses for its busy mask.
    ///
    /// Debounced through [`Self::last_add_dialog_busy`]. A
    /// flip-without-dialog-mounted is still recorded so a later
    /// dialog mount can pick up the current busy reading from the
    /// component's initial state rather than from a stale message;
    /// the message itself is only emitted when a controller is live.
    fn sync_add_dialog_busy(&mut self) {
        let busy = self.state.as_ref().is_some_and(AppState::is_busy);
        if busy == self.last_add_dialog_busy {
            return;
        }
        self.last_add_dialog_busy = busy;
        if let Some(controller) = self.add_dialog.as_ref() {
            controller.emit(AddAccountMsg::SetBusy(busy));
        }
    }
}

impl AppModel {
    /// Drop every open HOTP reveal window and any pending
    /// clipboard auto-clear entry when the app is no longer in
    /// `Unlocked` / `UnlockedBusy`.
    ///
    /// The reveal-window map holds `Zeroizing<String>` codes and
    /// the pending clipboard slot holds `Zeroizing<Vec<u8>>` bytes
    /// that must not outlive the unlocked session — clearing here
    /// on the `Locked` / `Missing` / `StartupError` transitions
    /// ensures the secret bytes are wiped in lockstep with the
    /// vault lock per DESIGN.md §4.5 / §"Memory hygiene". The
    /// clipboard itself is NOT wiped here; the in-flight pending
    /// entry simply forgets its byte capture so a follow-up wake
    /// has nothing to match against (only-if-unchanged).
    fn prune_reveals_if_locked(&mut self) {
        let unlocked = self.state.as_ref().is_some_and(AppState::is_unlocked);
        if !unlocked {
            self.reveal_windows.clear();
            self.pending_clipboard = None;
        }
    }
}

impl AppModel {
    /// Re-evaluate the TOTP ticker against the current
    /// `(state, rows)` pair and install / teardown the live
    /// `glib::timeout_add_local` source as needed.
    ///
    /// Routes through [`ticker_transition`] so the four-outcome
    /// truth table (`NoChange` / `Install` / `Teardown`) is the same
    /// pure-logic decision exercised by `tests/ticker_logic.rs`.
    /// The current row set is re-projected through
    /// [`filtered_row_models_from_vault`] using
    /// [`Self::search_query`] (the same source the post-mutation
    /// refresh path consumes) so the install decision sees exactly
    /// what the live [`AccountListComponent`] is rendering.
    ///
    /// Called after every state transition: process startup
    /// ([`SimpleComponent::init`]), unlock success
    /// ([`AppMsg::UnlockWorkerCompleted`]), init success
    /// ([`AppMsg::InitWorkerCompleted`]), retry
    /// ([`AppMsg::StartupErrorRetry`]), and the Add / Remove
    /// worker completions (rows changing kind can transition
    /// `has_visible_totp_row`). The TUI parity contract pins this
    /// to the §"Milestone 7 checklist" > TOTP ticker bullet "Tear
    /// down the ticker on `Locked` / `StartupError` transitions
    /// and reinstall on `Unlocked`".
    fn apply_ticker_transition(&mut self, sender: &ComponentSender<Self>) {
        let Some(state) = self.state.as_ref() else {
            // Pre-init or post-Quit; tear down any source so a
            // dangling timer doesn't outlive `AppModel`.
            if let Some(source_id) = self.ticker_source.take() {
                source_id.remove();
            }
            return;
        };
        let rows: Vec<AccountRowModel> = match self.vault.as_ref() {
            Some((vault, _)) => filtered_row_models_from_vault(vault, &self.search_query),
            None => Vec::new(),
        };
        let was_installed = self.ticker_source.is_some();
        match ticker_transition(was_installed, state, &rows) {
            TickerTransition::NoChange => {}
            TickerTransition::Install => {
                let send = sender.input_sender().clone();
                let source_id = glib::timeout_add_local(tick_interval(), move || {
                    // Per-tick callback: emit AppMsg::Tick with the
                    // wall-clock + monotonic timestamps captured at
                    // fire time so the handler does not race against
                    // the time it took to be dispatched through the
                    // GLib main loop.
                    let _ = send.send(AppMsg::Tick {
                        wall_clock: SystemTime::now(),
                        monotonic: Instant::now(),
                    });
                    glib::ControlFlow::Continue
                });
                self.ticker_source = Some(source_id);
            }
            TickerTransition::Teardown => {
                if let Some(source_id) = self.ticker_source.take() {
                    source_id.remove();
                }
            }
        }
    }

    /// Handle one [`AppMsg::Tick`] firing.
    ///
    /// Projects the live `(Vault, Store)` pair plus the rendered
    /// row set through [`tick`] and forwards the resulting display
    /// updates to the live [`AccountListComponent`] via
    /// [`AccountListMsg::Tick`]. Returns
    /// `Some(token)` when the per-tick `clipboard_wake_due` hint
    /// fires against a live pending entry so the caller can issue
    /// the asynchronous `gdk::Clipboard::read_text_async` round
    /// trip whose result lands as [`AppMsg::ClipboardWakeRead`];
    /// otherwise `None`.
    ///
    /// Defensive: a tick that lands after [`Self::vault`] has been
    /// dropped (e.g. between a `Locked` transition and the matching
    /// `ticker_transition` teardown) is a benign no-op.
    fn handle_tick(
        &mut self,
        wall_clock: SystemTime,
        monotonic: Instant,
    ) -> Option<paladin_core::ClipboardClearToken> {
        let (vault, _) = self.vault.as_ref()?;
        let controller = self.account_list.as_ref()?;
        let rows = filtered_row_models_from_vault(vault, &self.search_query);
        let outcome = tick(
            vault,
            &rows,
            wall_clock,
            monotonic,
            self.pending_clipboard.as_ref(),
        );
        let mut updates = outcome.display_updates;

        // HOTP reveal expiry: drop windows past their deadline and
        // emit hidden RowDisplays so the row reverts to the stored
        // next counter per `IMPLEMENTATION_PLAN_04_GTK.md`
        // §"Milestone 7 checklist" > "Hide the code and revert to
        // the stored next counter when the reveal deadline elapses."
        let expired = expired_reveals(&self.reveal_windows, monotonic);
        for id in &expired {
            self.reveal_windows.remove(id);
        }
        for id in &expired {
            if let Some(row) = rows.iter().find(|r| r.id == *id) {
                updates.push((*id, hidden_row_display(row)));
            }
        }

        if !updates.is_empty() {
            controller.emit(AccountListMsg::Tick(updates));
        }

        if outcome.clipboard_wake_due {
            self.pending_clipboard.as_ref().map(|p| p.token)
        } else {
            None
        }
    }

    /// Publish the per-row [`RowDisplay`] for the affected HOTP row
    /// after [`apply_advance_decision`] mutated the reveal-window
    /// map, plus the matching `AdwToast` surface.
    ///
    /// On [`RevealEffect::Refreshed`] the row's cache entry is
    /// replaced with [`row_display_for_reveal`] so the live
    /// `gtk::ListView` re-binds through the freshly inserted
    /// [`RevealWindow`]. On [`RevealEffect::Refreshed`] with
    /// `show_toast = true` the durability-unconfirmed toast also
    /// fires. On [`RevealEffect::Retained`] no cache mutation is
    /// needed; the row keeps its prior display and the generic
    /// HOTP-advance-failed toast surfaces so the user sees the
    /// failure surface per `IMPLEMENTATION_PLAN_04_GTK.md`
    /// §"Milestone 7 checklist" > "surface the inline / status
    /// error".
    fn publish_reveal_for(&self, account_id: paladin_core::AccountId, effect: RevealEffect) {
        match effect {
            RevealEffect::Refreshed { show_toast } => {
                if let (Some((vault, _)), Some(controller), Some(window)) = (
                    self.vault.as_ref(),
                    self.account_list.as_ref(),
                    self.reveal_windows.get(&account_id),
                ) {
                    if let Some(summary) = vault.summaries().find(|s| s.id == account_id) {
                        let display = row_display_for_reveal(&summary, window);
                        controller.emit(AccountListMsg::Tick(vec![(account_id, display)]));
                    }
                }
                if show_toast {
                    self.toast_overlay
                        .add_toast(adw::Toast::new(format_hotp_durability_unconfirmed_toast()));
                }
            }
            RevealEffect::Retained => {
                self.toast_overlay
                    .add_toast(adw::Toast::new(format_hotp_advance_failed_toast()));
            }
        }
    }

    /// Re-project rows off the live `(Vault, Store)` pair and emit
    /// [`AccountListMsg::Refresh`] so the visible row set matches
    /// the post-mutation vault state per
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    /// `AccountListComponent` ("Refresh the store after every vault
    /// mutation … without reordering surviving rows"). Used by the
    /// rename / add / remove worker-completion handlers when the
    /// dispatch's `refresh_list` flag is set.
    ///
    /// Filters through [`filtered_row_models_from_vault`] using
    /// [`Self::search_query`] so an active search filter survives
    /// the post-mutation refresh. The `selection: None` argument
    /// lets the [`AccountListComponent`] resolve the new selection
    /// against its own `current_selection` via
    /// [`selected_row_after_refresh`] (preserve the prior selection
    /// when still present, else first match).
    ///
    /// Defensive: if the vault slot or the controller is `None`
    /// (the worker outcome arrived after auto-lock dropped the
    /// vault, or before the `AccountListComponent` was mounted),
    /// this is a benign no-op.
    fn refresh_account_list(&self) {
        if let (Some((vault, _)), Some(controller)) =
            (self.vault.as_ref(), self.account_list.as_ref())
        {
            let rows = filtered_row_models_from_vault(vault, &self.search_query);
            controller.emit(AccountListMsg::Refresh {
                rows,
                selection: None,
            });
        }
    }

    /// Tear down the currently-mounted screen controller and mount
    /// the per-state controller matching `state`, mirroring `init`'s
    /// per-state mount sequence.
    ///
    /// Called from the [`AppMsg::StartupErrorRetry`] handler after
    /// [`run_startup_probes`] has produced a fresh
    /// [`StartupOutcome`]; together they form the
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction" retry
    /// path: re-resolve the vault path, re-`inspect`, and remount
    /// the matching child controller without creating, overwriting,
    /// repairing, chmod'ing, or selecting a different vault path.
    /// The screen controller currently mounted on
    /// [`AppModel::content`] is whichever of
    /// [`AppModel::startup_error`], [`AppModel::init_dialog`],
    /// [`AppModel::unlock_dialog`], or [`AppModel::account_list`]
    /// is `Some`; this helper takes each in turn (so the
    /// `GtkWidget` reference held by relm4 is released back to GTK)
    /// before mounting the new per-state controller through the
    /// same builder calls `init` uses.
    fn remount_for_state(&mut self, state: &AppState, sender: &ComponentSender<Self>) {
        if let Some(controller) = self.startup_error.take() {
            self.content.remove(controller.widget());
        }
        if let Some(controller) = self.init_dialog.take() {
            self.content.remove(controller.widget());
        }
        if let Some(controller) = self.unlock_dialog.take() {
            self.content.remove(controller.widget());
        }
        if let Some(controller) = self.account_list.take() {
            self.content.remove(controller.widget());
        }

        match state {
            AppState::Unlocked { .. } | AppState::UnlockedBusy { .. } => {
                let rows: Vec<AccountRowModel> = self
                    .vault
                    .as_ref()
                    .map(|(v, _)| row_models_from_vault(v))
                    .unwrap_or_default();
                let controller = AccountListComponent::builder()
                    .launch(AccountListInit {
                        rows,
                        initial_query: String::new(),
                        initial_selection: None,
                    })
                    .forward(sender.input_sender(), AppMsg::AccountListAction);
                self.content.append(controller.widget());
                self.account_list = Some(controller);
            }
            AppState::StartupError { error, .. } => {
                let controller = StartupErrorComponent::builder()
                    .launch(StartupErrorInit {
                        error: error.clone(),
                    })
                    .forward(sender.input_sender(), dispatch_startup_error_output);
                self.content.append(controller.widget());
                self.startup_error = Some(controller);
            }
            AppState::Missing { path } => {
                let controller = InitDialogComponent::builder()
                    .launch(InitDialogInit {
                        vault_path: path.clone(),
                    })
                    .forward(sender.input_sender(), AppMsg::InitDialogAction);
                self.content.append(controller.widget());
                self.init_dialog = Some(controller);
            }
            AppState::Locked { path } => {
                let controller = UnlockDialogComponent::builder()
                    .launch(UnlockDialogInit {
                        vault_path: path.clone(),
                    })
                    .forward(sender.input_sender(), AppMsg::UnlockDialogAction);
                self.content.append(controller.widget());
                self.unlock_dialog = Some(controller);
            }
        }
    }
}

/// Run the §"Vault interaction" startup sequence.
///
/// 1. Resolve the vault path: `vault_path_override` (from `--vault`)
///    if `Some`, otherwise `paladin_core::default_vault_path()`. A
///    failure on the latter routes directly to
///    [`AppState::StartupError`] tagged
///    [`crate::startup_error::StartupErrorSource::PathResolution`].
/// 2. `paladin_core::inspect(path)` resolves the mode. Missing
///    routes to [`AppState::Missing`], Encrypted routes to
///    [`AppState::Locked`] (the `UnlockComponent` runs Argon2 off
///    the main loop later), and an `Err` routes to
///    [`AppState::StartupError`] tagged
///    [`crate::startup_error::StartupErrorSource::Inspect`].
/// 3. Plaintext only: `paladin_core::Store::open(path,
///    VaultLock::Plaintext)` directly on the GTK main loop. Per the
///    plan, "no Argon2; just bincode decode and the §4.3 perm check,
///    fast enough that the spawn-blocking thread hop costs more than
///    the call itself". A successful open returns the live
///    `(Vault, Store)` pair alongside [`AppState::Unlocked`]; a non-
///    passphrase failure routes through
///    [`decide_state_from_open_error`].
///
/// Inline-passphrase classification cannot arise on a plaintext
/// open in practice — the function still funnels it through
/// `StartupError` so a future divergence in `paladin_core` cannot
/// silently surface a passphrase dialog from the plaintext branch.
#[must_use]
pub fn run_startup_probes(vault_path_override: Option<PathBuf>) -> StartupOutcome {
    let path = match vault_path_override {
        Some(p) => p,
        None => match paladin_core::default_vault_path() {
            Ok(p) => p,
            Err(err) => {
                return StartupOutcome {
                    state: AppState::StartupError {
                        path: None,
                        error: StartupError::from_path_resolution(&err),
                    },
                    vault: None,
                };
            }
        },
    };

    if let Some(state) = decide_state_from_inspect(&path, paladin_core::inspect(&path)) {
        return StartupOutcome { state, vault: None };
    }

    match paladin_core::Store::open(&path, paladin_core::VaultLock::Plaintext) {
        Ok(pair) => StartupOutcome {
            state: AppState::Unlocked { path },
            vault: Some(pair),
        },
        Err(err) => {
            let state = match decide_state_from_open_error(&path, &err) {
                OpenErrorOutcome::Startup(state) => state,
                OpenErrorOutcome::InlinePassphrase => AppState::StartupError {
                    path: Some(path),
                    error: StartupError::from_open(&err),
                },
            };
            StartupOutcome { state, vault: None }
        }
    }
}

/// Render the stdout marker emitted under `--exit-after-startup`.
///
/// Format: `paladin-gtk: startup_state=<Variant> path=<path>`. For
/// `AppState::StartupError { path: None, .. }` (path-resolution
/// failures), `path` renders as `(unresolved)`. `tests/gtk_smoke.rs`
/// greps this line to verify which startup state the binary reached
/// without driving widgets under `xvfb-run`.
#[must_use]
pub fn startup_state_marker(state: &AppState) -> String {
    let variant = match state {
        AppState::Missing { .. } => "Missing",
        AppState::Locked { .. } => "Locked",
        AppState::Unlocked { .. } => "Unlocked",
        AppState::UnlockedBusy { .. } => "UnlockedBusy",
        AppState::StartupError { .. } => "StartupError",
    };
    let path_repr = match state.path() {
        Some(p) => p.display().to_string(),
        None => "(unresolved)".to_string(),
    };
    format!("paladin-gtk: startup_state={variant} path={path_repr}")
}

/// Initial `(width, height)` tuple the widget hands to the
/// [`AppModel`]'s `adw::ApplicationWindow::set_default_size`.
///
/// Returns the static `(640, 480)` pair — the libadwaita HIG's
/// narrow-window initial size: wide enough for the
/// [`crate::account_list::AccountListComponent`]'s
/// `<issuer>:<label>` lines without forcing an
/// [`adw::Squeezer`], tall enough to expose the header bar and a
/// useful run of accounts without dominating a smaller display.
/// Per the libadwaita HIG, the `ApplicationWindow` then becomes
/// user-resizable so the initial dimensions are a starting size,
/// not a clamp. No TUI parity: the TUI inherits the terminal's
/// dimensions and has no initial-size contract to mirror.
/// Pinning the dimensions through a helper keeps the values in
/// one place shared by the widget binding and the pure-logic
/// tests.
///
/// Pure — returns an `(i32, i32)` tuple without allocating.
/// Sibling of [`format_app_window_title`] on the
/// `ApplicationWindow`-chrome side; together they pin the
/// window's title and starting dimensions against a single
/// source of truth.
#[must_use]
pub fn format_app_window_default_size() -> (i32, i32) {
    (640, 480)
}

/// Freedesktop icon name the widget hands to the [`AppModel`]'s
/// header-bar add `gtk::Button::set_icon_name`.
///
/// Returns the static icon name `"list-add-symbolic"` — the
/// freedesktop-standard glyph for "add to list" that resolves
/// through the system icon theme so the wordless icon matches
/// every other GNOME app's `+` header-bar affordance. The
/// `-symbolic` suffix is required by the libadwaita HIG for
/// header-bar icons so the glyph recolors with the theme. No TUI
/// parity: the TUI is text-only and has no icon to mirror.
/// Pinning the icon name through a helper keeps the string in
/// one place shared by the widget binding and the pure-logic
/// tests.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from the dialog-status-icon siblings
/// ([`crate::unlock_dialog::format_unlock_dialog_icon_name`],
/// [`crate::init_dialog::format_init_dialog_icon_name`],
/// [`crate::startup_error::format_startup_error_icon_name`],
/// [`crate::remove_dialog::format_remove_dialog_icon_name`])
/// which pin `AdwStatusPage` icons rather than header-bar button
/// icons; pairing this helper with the existing app-level
/// [`format_app_add_button_tooltip`] keeps both halves of the
/// icon-only button's accessibility surface against a single
/// source of truth.
#[must_use]
pub fn format_app_add_button_icon_name() -> &'static str {
    "list-add-symbolic"
}

/// Fixed `tooltip_text` attribute the widget hands to the
/// [`AppModel`]'s header-bar add `gtk::Button::set_tooltip_text`.
///
/// Returns the static tooltip string (`"Add account"`) the user
/// sees when hovering or focusing the `+` header-bar affordance.
/// The wording names the action the button dispatches
/// ([`AppMsg::OpenAddDialog`]) and matches the GNOME-HIG verb-led
/// tooltip convention used by every other GNOME app's header-bar
/// `+` button. The tooltip is the user-visible label for an icon-
/// only button that otherwise shows only `list-add-symbolic`, so
/// pinning the wording through a helper guards the accessibility
/// surface (screen-readers read tooltips) against silent copy
/// drift.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from [`crate::add_account::format_add_dialog_title`]
/// (`"Add account"`), which names the surface the tooltip opens:
/// the two strings happen to match today but live on different
/// surfaces — a future copy change should land on one without
/// silently moving the other. No TUI parity: the TUI is text-
/// only and surfaces actions through command names rather than
/// tooltips.
#[must_use]
pub fn format_app_add_button_tooltip() -> &'static str {
    "Add account"
}

/// Fixed `title` attribute the widget hands to the [`AppModel`]'s
/// `adw::ApplicationWindow::set_title`.
///
/// Returns the static title string the window-list / chrome
/// renders for the running binary. The wording (`"Paladin"`) names
/// the application — surfaced verbatim through libadwaita's
/// window chrome and (on Wayland / X11) by the desktop's window
/// list, so the bare application name is the right wording (no
/// state-specific suffixes like `" — Locked"` / `" — Unlocked"`,
/// which would otherwise leak the live vault state into the
/// window-list across application switches). Matches the GNOME
/// app-id naming used by the `.desktop` / `AppStream` metadata
/// referenced by `IMPLEMENTATION_PLAN_04_GTK.md` §"Linux desktop
/// integration". No TUI parity: the TUI is a single-process
/// terminal app and has no window-list entry to mirror. Pinning
/// the title through a helper keeps the wording in one place
/// shared by the widget binding and the pure-logic tests in
/// `tests/startup_probes.rs`.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from the in-window dialog titles
/// ([`crate::unlock_dialog::format_unlock_dialog_title`],
/// [`crate::init_dialog::format_init_dialog_title`],
/// [`crate::rename_dialog::format_rename_dialog_title`],
/// [`crate::add_account::format_add_dialog_title`],
/// [`crate::startup_error::format_startup_error_title`],
/// [`crate::remove_dialog::format_remove_dialog_title`]), which
/// name surfaces inside the window rather than the window itself.
#[must_use]
pub fn format_app_window_title() -> &'static str {
    "Paladin"
}

/// Freedesktop icon name the widget hands to the [`AppModel`]'s
/// header-bar search-toggle `gtk::ToggleButton::set_icon_name`.
///
/// Returns the static icon name `"system-search-symbolic"` — the
/// freedesktop-standard glyph for "search" that resolves through
/// the system icon theme so the wordless icon matches every other
/// GNOME app's search-toggle header-bar affordance. The
/// `-symbolic` suffix is required by the libadwaita HIG for
/// header-bar icons so the glyph recolors with the theme. No TUI
/// parity: the TUI is text-only and exposes search through the
/// existing `/` keybinding rather than an icon. Pinning the icon
/// name through a helper keeps the string in one place shared by
/// the widget binding and the pure-logic tests.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_app_add_button_icon_name`] on the header-bar-icon
/// side; together they pin the wordless affordances against a
/// single source of truth.
#[must_use]
pub fn format_app_search_button_icon_name() -> &'static str {
    "system-search-symbolic"
}

/// Fixed `tooltip_text` attribute the widget hands to the
/// [`AppModel`]'s header-bar search-toggle
/// `gtk::ToggleButton::set_tooltip_text`.
///
/// Returns the static tooltip string (`"Search accounts"`) the
/// user sees when hovering or focusing the search-toggle
/// header-bar affordance. The wording names the action the toggle
/// dispatches (revealing the `gtk::SearchBar` in
/// `AccountListComponent`) and matches the GNOME-HIG verb-led
/// tooltip convention used by every other GNOME app's
/// search-toggle header-bar affordance. The tooltip is the user-
/// visible label for an icon-only button that otherwise shows
/// only `system-search-symbolic`, so pinning the wording through
/// a helper guards the accessibility surface (screen-readers read
/// tooltips) against silent copy drift.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_app_add_button_tooltip`] on the header-bar-tooltip
/// side; together they pin both icon-only-button labels against
/// a single source of truth. No TUI parity: the TUI is text-only
/// and surfaces search through the `/` keybinding rather than
/// tooltips.
#[must_use]
pub fn format_app_search_button_tooltip() -> &'static str {
    "Search accounts"
}

/// Freedesktop icon name the widget hands to the [`AppModel`]'s
/// header-bar primary `gtk::MenuButton::set_icon_name`.
///
/// Returns the static icon name `"open-menu-symbolic"` — the
/// freedesktop-standard glyph for a hamburger / primary-menu
/// button that resolves through the system icon theme so the
/// wordless icon matches every other GNOME app's primary-menu
/// header-bar affordance. The `-symbolic` suffix is required by
/// the libadwaita HIG for header-bar icons so the glyph recolors
/// with the theme. No TUI parity: the TUI is text-only and
/// exposes the same actions through `:` command-mode rather than
/// a menu icon. Pinning the icon name through a helper keeps the
/// string in one place shared by the widget binding and the
/// pure-logic tests.
///
/// Pure — returns a `'static str` without allocating. Third
/// sibling of [`format_app_add_button_icon_name`] and
/// [`format_app_search_button_icon_name`] on the header-bar-icon
/// side; together they pin all three wordless header-bar
/// affordances against a single source of truth.
#[must_use]
pub fn format_app_menu_button_icon_name() -> &'static str {
    "open-menu-symbolic"
}

/// Fixed `tooltip_text` attribute the widget hands to the
/// [`AppModel`]'s header-bar primary
/// `gtk::MenuButton::set_tooltip_text`.
///
/// Returns the static tooltip string (`"Main menu"`) the user
/// sees when hovering or focusing the primary-menu header-bar
/// affordance. The wording names the surface the button opens
/// (the primary `gio::Menu` with Import…, Export…, Passphrase…,
/// Preferences, About Paladin, Quit) and matches the GNOME-HIG
/// convention used by every other GNOME app's hamburger
/// header-bar affordance. The tooltip is the user-visible label
/// for an icon-only button that otherwise shows only
/// `open-menu-symbolic`, so pinning the wording through a helper
/// guards the accessibility surface (screen-readers read
/// tooltips) against silent copy drift.
///
/// Pure — returns a `'static str` without allocating. Third
/// sibling of [`format_app_add_button_tooltip`] and
/// [`format_app_search_button_tooltip`] on the header-bar-
/// tooltip side; together they pin all three icon-only-button
/// labels against a single source of truth. No TUI parity: the
/// TUI exposes the same actions through `:` command-mode rather
/// than tooltips.
#[must_use]
pub fn format_app_menu_button_tooltip() -> &'static str {
    "Main menu"
}

/// Fixed label the widget hands to the primary `gio::Menu`'s
/// "Import…" entry.
///
/// Returns the static label `"Import\u{2026}"` — the wording for
/// the menu entry that opens `ImportDialog`. Uses the GNOME-HIG
/// horizontal-ellipsis character (U+2026) — not three ASCII
/// periods — to indicate the action opens a sub-dialog requiring
/// further input before committing. The trailing ellipsis is the
/// GNOME-HIG convention for any menu entry that opens a dialog
/// rather than completing the action immediately. The Import
/// entry is gated to `Unlocked` per §"libadwaita usage" but the
/// label wording is identical across states so the menu does not
/// need to re-render when re-opened.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// the other primary-menu entries (Export…, Passphrase…,
/// Preferences, About Paladin, Quit) which will land in follow-up
/// commits with the same `format_app_menu_*_label` naming.
#[must_use]
pub fn format_app_menu_import_label() -> &'static str {
    "Import\u{2026}"
}

/// Fixed label the widget hands to the primary `gio::Menu`'s
/// "Export…" entry.
///
/// Returns the static label `"Export\u{2026}"` — the wording for
/// the menu entry that opens `ExportDialog`. Uses the GNOME-HIG
/// horizontal-ellipsis character (U+2026) — not three ASCII
/// periods — to indicate the action opens a sub-dialog requiring
/// further input before committing. The Export entry is gated to
/// `Unlocked` per §"libadwaita usage" but the label wording is
/// identical across states so the menu does not need to re-render
/// when re-opened.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_app_menu_import_label`] on the import/export menu-
/// entry side; together they pin the two file-IO entries against
/// a single source of truth.
#[must_use]
pub fn format_app_menu_export_label() -> &'static str {
    "Export\u{2026}"
}

/// Fixed label the widget hands to the primary `gio::Menu`'s
/// "Passphrase…" entry.
///
/// Returns the static label `"Passphrase\u{2026}"` — the wording
/// for the menu entry that opens `PassphraseDialog` with the
/// sub-flow gated by `Vault::is_encrypted()`. Uses the GNOME-HIG
/// horizontal-ellipsis character (U+2026) — not three ASCII
/// periods — to indicate the action opens a sub-dialog requiring
/// further input before committing. The Passphrase entry is
/// gated to `Unlocked` per §"libadwaita usage" but the label
/// wording is identical across the set / change / remove sub-
/// flows so the menu does not need to re-render when re-opened;
/// `PassphraseDialog` does the sub-flow routing internally.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// the other primary-menu entries
/// ([`format_app_menu_import_label`], [`format_app_menu_export_label`]).
#[must_use]
pub fn format_app_menu_passphrase_label() -> &'static str {
    "Passphrase\u{2026}"
}

/// Fixed label the widget hands to the primary `gio::Menu`'s
/// "Preferences" entry.
///
/// Returns the static label `"Preferences"` — the wording for the
/// menu entry that opens `SettingsComponent`'s
/// `AdwPreferencesDialog`. Uses the bare label (no trailing
/// horizontal-ellipsis) because the modern GNOME HIG drops the
/// ellipsis from preferences entries: the dialog is live-apply
/// (each toggle / spinner change drives a `Vault::mutate_and_save`
/// per `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage") rather
/// than collecting input behind an Apply / Cancel button, so the
/// affordance is not a request for further input before
/// committing. The dialog-opening entries (Import, Export,
/// Passphrase) keep the ellipsis because they collect input before
/// committing; Preferences does not.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from the dialog-opening primary-menu entries
/// ([`format_app_menu_import_label`], [`format_app_menu_export_label`],
/// [`format_app_menu_passphrase_label`]) which carry the ellipsis;
/// matches the ellipsis-less convention used by every other
/// modern GNOME app's Preferences entry.
#[must_use]
pub fn format_app_menu_preferences_label() -> &'static str {
    "Preferences"
}

/// Fixed label the widget hands to the primary `gio::Menu`'s
/// "About Paladin" entry.
///
/// Returns the static label `"About Paladin"` — the wording for
/// the menu entry that opens `AdwAboutDialog` (per §"libadwaita
/// usage", populated from Cargo package metadata embedded at
/// compile time). The application name is included verbatim so
/// the user can confirm the running binary's identity before
/// opening the dialog — same wording convention as every other
/// GNOME app's primary-menu About entry. The trailing "Paladin"
/// matches the bare application name pinned by
/// [`format_app_window_title`]; if either renames in a future
/// version, both should move together so the menu entry and
/// window-list entry stay in lockstep.
///
/// Pure — returns a `'static str` without allocating. No
/// trailing ellipsis: the About dialog is an informational
/// surface (program metadata + license) rather than a request
/// for input, so the GNOME-HIG ellipsis convention does not
/// apply — same reasoning as [`format_app_menu_preferences_label`].
#[must_use]
pub fn format_app_menu_about_label() -> &'static str {
    "About Paladin"
}

/// Fixed label the widget hands to the primary `gio::Menu`'s
/// "Quit" entry.
///
/// Returns the static label `"Quit"` — the wording for the menu
/// entry that dispatches the standard `Quit` action triggering
/// application shutdown after any in-flight vault worker returns
/// (per §"In-flight effect ownership"). Matches the GNOME-HIG
/// convention used by every other GNOME app's primary-menu Quit
/// entry. No trailing ellipsis: Quit is a commit-now action that
/// does not collect further input (the destructive-confirmation-
/// on-pending-work gate, if any, lives in the §"In-flight effect
/// ownership" worker-deferral logic, not in this label). The
/// Quit entry stays enabled in every `AppState` per §"libadwaita
/// usage" — unlike Import / Export / Passphrase / Preferences
/// which are gated to `Unlocked` — so the label wording does not
/// need to change across state transitions.
///
/// Pure — returns a `'static str` without allocating. Final
/// sibling of the primary-menu-label set
/// ([`format_app_menu_import_label`], [`format_app_menu_export_label`],
/// [`format_app_menu_passphrase_label`], [`format_app_menu_preferences_label`],
/// [`format_app_menu_about_label`]); together they pin all six
/// primary-menu entry labels against a single source of truth.
#[must_use]
pub fn format_app_menu_quit_label() -> &'static str {
    "Quit"
}

/// Fully-qualified `detailed_action_name` the widget hands to the
/// primary `gio::Menu`'s "Import…" entry.
///
/// Returns the static action target `"app.import"` — the
/// fully-qualified target the `gio::Menu` resolves against the
/// `gio::ApplicationWindow`'s `app` action group. The matching
/// `gio::SimpleAction` (`"import"`) is registered on the
/// application's action group; the menu's
/// `detailed_action_name` argument expects a
/// `<group>.<action>` target — a bare action name silently
/// no-ops at activation time. The `"app."` prefix names the
/// group; `"import"` names the action. Same pattern
/// `account_list.rs` uses with its `row.rename` / `row.remove`
/// targets resolved against the per-row
/// `gio::SimpleActionGroup`.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of the other primary-menu action-target helpers
/// ([`format_app_menu_import_label`] names the visible label;
/// this helper names the action target). Together they pin both
/// halves of the menu-entry contract against a single source of
/// truth.
#[must_use]
pub fn format_app_menu_import_action() -> &'static str {
    "app.import"
}

/// Fully-qualified `detailed_action_name` the widget hands to the
/// primary `gio::Menu`'s "Export…" entry.
///
/// Returns the static action target `"app.export"` — the
/// fully-qualified target the `gio::Menu` resolves against the
/// `gio::ApplicationWindow`'s `app` action group. The matching
/// `gio::SimpleAction` (`"export"`) is registered on the
/// application's action group. The `"app."` prefix names the
/// group; `"export"` names the action.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_export_label`] on the menu-entry-contract
/// side; together they pin both halves (visible label + action
/// target) against a single source of truth.
#[must_use]
pub fn format_app_menu_export_action() -> &'static str {
    "app.export"
}

/// Fully-qualified `detailed_action_name` the widget hands to the
/// primary `gio::Menu`'s "Passphrase…" entry.
///
/// Returns the static action target `"app.passphrase"` — the
/// fully-qualified target the `gio::Menu` resolves against the
/// `gio::ApplicationWindow`'s `app` action group. The matching
/// `gio::SimpleAction` (`"passphrase"`) is registered on the
/// application's action group. The `"app."` prefix names the
/// group; `"passphrase"` names the action. The single
/// `passphrase` action dispatches the set / change / remove
/// sub-flow gating internally per `Vault::is_encrypted()` rather
/// than carrying three distinct menu entries.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_passphrase_label`] on the menu-entry-
/// contract side; together they pin both halves (visible label +
/// action target) against a single source of truth.
#[must_use]
pub fn format_app_menu_passphrase_action() -> &'static str {
    "app.passphrase"
}

/// Fully-qualified `detailed_action_name` the widget hands to the
/// primary `gio::Menu`'s "Preferences" entry.
///
/// Returns the static action target `"app.preferences"` — the
/// fully-qualified target the `gio::Menu` resolves against the
/// `gio::ApplicationWindow`'s `app` action group. The matching
/// `gio::SimpleAction` (`"preferences"`) is registered on the
/// application's action group. The `"app."` prefix names the
/// group; `"preferences"` names the action.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_preferences_label`] on the menu-entry-
/// contract side; together they pin both halves (visible label +
/// action target) against a single source of truth.
#[must_use]
pub fn format_app_menu_preferences_action() -> &'static str {
    "app.preferences"
}

/// Fully-qualified `detailed_action_name` the widget hands to the
/// primary `gio::Menu`'s "About Paladin" entry.
///
/// Returns the static action target `"app.about"` — the
/// fully-qualified target the `gio::Menu` resolves against the
/// `gio::ApplicationWindow`'s `app` action group. The matching
/// `gio::SimpleAction` (`"about"`) is registered on the
/// application's action group. The `"app."` prefix names the
/// group; `"about"` names the action — bare `"about"` rather
/// than `"about_paladin"` so the action name does not need to
/// track an application rename if one ever lands.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_about_label`] on the menu-entry-contract
/// side; together they pin both halves (visible label + action
/// target) against a single source of truth.
#[must_use]
pub fn format_app_menu_about_action() -> &'static str {
    "app.about"
}

/// Fully-qualified `detailed_action_name` the widget hands to the
/// primary `gio::Menu`'s "Quit" entry.
///
/// Returns the static action target `"app.quit"` — the
/// fully-qualified target the `gio::Menu` resolves against the
/// `gio::ApplicationWindow`'s `app` action group. The matching
/// `gio::SimpleAction` (`"quit"`) is registered on the
/// application's action group and dispatches the standard
/// `Quit` shutdown path, deferring the close until any in-flight
/// vault worker returns per §"In-flight effect ownership". The
/// `"app."` prefix names the group; `"quit"` names the action.
///
/// Pure — returns a `'static str` without allocating. Final
/// sibling of the primary-menu action-target set
/// ([`format_app_menu_import_action`], [`format_app_menu_export_action`],
/// [`format_app_menu_passphrase_action`], [`format_app_menu_preferences_action`],
/// [`format_app_menu_about_action`]); together they pin all six
/// primary-menu entries' action targets against a single source
/// of truth, paired with the matching `_label` helpers.
#[must_use]
pub fn format_app_menu_quit_action() -> &'static str {
    "app.quit"
}

/// Bare `GLib` action name the primary `gio::Menu`'s "Import…"
/// entry binds via [`format_app_menu_import_action`].
///
/// Returns the static action name `"import"` — the name passed
/// to `gio::SimpleAction::new(..., None)` when the matching
/// action is registered on the application's `app` action group.
/// The fully-qualified `detailed_action_name` `"app.import"`
/// spelled by [`format_app_menu_import_action`] is the
/// [`format_app_action_group_name`] group prefix joined to this
/// bare name via the `<group>.<action>` separator, so the
/// `gio::Menu` and the matching `gio::SimpleAction` stay in
/// lockstep when wired separately.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_import_action`] on the fully-qualified
/// target side and [`format_app_menu_import_label`] on the
/// visible-label side; together they pin all three halves of
/// the menu-entry contract against a single source of truth.
#[must_use]
pub fn format_app_menu_import_action_name() -> &'static str {
    "import"
}

/// Bare `GLib` action name the primary `gio::Menu`'s "Export…"
/// entry binds via [`format_app_menu_export_action`].
///
/// Returns the static action name `"export"` — the name passed
/// to `gio::SimpleAction::new(..., None)` when the matching
/// action is registered on the application's `app` action group.
/// The fully-qualified `detailed_action_name` `"app.export"`
/// spelled by [`format_app_menu_export_action`] is the
/// [`format_app_action_group_name`] group prefix joined to this
/// bare name via the `<group>.<action>` separator.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_export_action`] on the fully-qualified
/// target side and [`format_app_menu_export_label`] on the
/// visible-label side; together they pin all three halves of
/// the menu-entry contract against a single source of truth.
#[must_use]
pub fn format_app_menu_export_action_name() -> &'static str {
    "export"
}

/// Bare `GLib` action name the primary `gio::Menu`'s "Passphrase…"
/// entry binds via [`format_app_menu_passphrase_action`].
///
/// Returns the static action name `"passphrase"` — the name
/// passed to `gio::SimpleAction::new(..., None)` when the matching
/// action is registered on the application's `app` action group.
/// The fully-qualified `detailed_action_name` `"app.passphrase"`
/// spelled by [`format_app_menu_passphrase_action`] is the
/// [`format_app_action_group_name`] group prefix joined to this
/// bare name via the `<group>.<action>` separator. The single
/// `passphrase` action dispatches the set / change / remove
/// sub-flow gating internally per `Vault::is_encrypted()` rather
/// than carrying three distinct menu entries.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_passphrase_action`] on the fully-
/// qualified target side and [`format_app_menu_passphrase_label`]
/// on the visible-label side; together they pin all three halves
/// of the menu-entry contract against a single source of truth.
#[must_use]
pub fn format_app_menu_passphrase_action_name() -> &'static str {
    "passphrase"
}

/// Bare `GLib` action name the primary `gio::Menu`'s
/// "Preferences" entry binds via
/// [`format_app_menu_preferences_action`].
///
/// Returns the static action name `"preferences"` — the name
/// passed to `gio::SimpleAction::new(..., None)` when the
/// matching action is registered on the application's `app`
/// action group. The fully-qualified `detailed_action_name`
/// `"app.preferences"` spelled by
/// [`format_app_menu_preferences_action`] is the
/// [`format_app_action_group_name`] group prefix joined to this
/// bare name via the `<group>.<action>` separator.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_preferences_action`] on the fully-
/// qualified target side and [`format_app_menu_preferences_label`]
/// on the visible-label side; together they pin all three halves
/// of the menu-entry contract against a single source of truth.
#[must_use]
pub fn format_app_menu_preferences_action_name() -> &'static str {
    "preferences"
}

/// Keyboard accelerator the primary menu's "Preferences" entry
/// is wired to per `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita
/// usage" > "Primary menu" and the GNOME HIG keyboard
/// conventions.
///
/// Returns the gtk-rs accelerator spelling `"<Control>comma"` —
/// the canonical Preferences shortcut GNOME applications register
/// via `gio::Application::set_accels_for_action("app.preferences",
/// &["<Control>comma"])`. The widget binding hands this
/// accelerator string to that registration so the menu and any
/// future keyboard activation paths share one shortcut surface
/// against a single source of truth.
///
/// The `comma` keysym (lowercase, gtk's bare key name for `,`)
/// matches gtk-rs `accels_for_action`'s recognised spelling;
/// `<Control>,` (with the literal `,`) is also accepted by
/// `gtk::accelerator_parse` but `comma` is the canonical key-name
/// form so the helper stays grounded in the gtk key-symbol table.
/// Mirrors the [`format_app_add_button_accelerator`] /
/// [`format_app_menu_quit_accelerator`] siblings on the other
/// pinned-accelerator surfaces.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_app_menu_preferences_action`] (fully-qualified action
/// target) and [`format_app_menu_preferences_action_name`] (bare
/// action name); together they pin the action target, its bare
/// name, and its keyboard accelerator against a single source of
/// truth.
#[must_use]
pub fn format_app_menu_preferences_accelerator() -> &'static str {
    "<Control>comma"
}

/// Bare `GLib` action name the primary `gio::Menu`'s "About
/// Paladin" entry binds via [`format_app_menu_about_action`].
///
/// Returns the static action name `"about"` — the name passed
/// to `gio::SimpleAction::new(..., None)` when the matching
/// action is registered on the application's `app` action group.
/// The fully-qualified `detailed_action_name` `"app.about"`
/// spelled by [`format_app_menu_about_action`] is the
/// [`format_app_action_group_name`] group prefix joined to this
/// bare name via the `<group>.<action>` separator. The bare
/// name is `"about"` rather than `"about_paladin"` so the
/// action does not need to track an application rename if one
/// ever lands.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_menu_about_action`] on the fully-qualified
/// target side and [`format_app_menu_about_label`] on the
/// visible-label side; together they pin all three halves of
/// the menu-entry contract against a single source of truth.
#[must_use]
pub fn format_app_menu_about_action_name() -> &'static str {
    "about"
}

/// Bare `GLib` action name the primary `gio::Menu`'s "Quit"
/// entry binds via [`format_app_menu_quit_action`].
///
/// Returns the static action name `"quit"` — the name passed
/// to `gio::SimpleAction::new(..., None)` when the matching
/// action is registered on the application's `app` action group.
/// The fully-qualified `detailed_action_name` `"app.quit"`
/// spelled by [`format_app_menu_quit_action`] is the
/// [`format_app_action_group_name`] group prefix joined to this
/// bare name via the `<group>.<action>` separator. The matching
/// action dispatches the standard `Quit` shutdown path,
/// deferring the close until any in-flight vault worker returns
/// per §"In-flight effect ownership".
///
/// Pure — returns a `'static str` without allocating. Final
/// sibling of the bare-action-name set
/// ([`format_app_menu_import_action_name`],
/// [`format_app_menu_export_action_name`],
/// [`format_app_menu_passphrase_action_name`],
/// [`format_app_menu_preferences_action_name`],
/// [`format_app_menu_about_action_name`]); together they pin
/// all six primary-menu entries' bare `SimpleAction` names
/// against a single source of truth, paired with the matching
/// `_action` and `_label` helpers.
#[must_use]
pub fn format_app_menu_quit_action_name() -> &'static str {
    "quit"
}

/// Keyboard accelerator the primary menu's "Quit" entry is wired
/// to per `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Primary menu".
///
/// Returns the gtk-rs accelerator spelling `"<Control>q"` — the
/// canonical Quit shortcut GNOME applications register via
/// `gio::Application::set_accels_for_action("app.quit",
/// &["<Control>q"])`. Pinning the accelerator here keeps the
/// widget-side wiring helper aligned with the documented Quit
/// shortcut against a single source of truth, mirroring
/// [`format_app_add_button_accelerator`] on the header-bar `+`
/// button side so both primary keyboard surfaces share the same
/// helper shape.
///
/// The `<Control>q` form (uppercase modifier in angle brackets,
/// lowercase key letter) matches gtk-rs `accels_for_action`'s
/// recognised spelling; `<Primary>` would also resolve on Linux
/// but `<Control>` keeps the helper consistent with the existing
/// [`format_app_add_button_accelerator`] sibling.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_app_menu_quit_action`] (fully-qualified action target)
/// and [`format_app_menu_quit_action_name`] (bare action name);
/// together they pin the action target, its bare name, and its
/// keyboard accelerator against a single source of truth.
#[must_use]
pub fn format_app_menu_quit_accelerator() -> &'static str {
    "<Control>q"
}

/// Fully-qualified `detailed_action_name` the header-bar `+`
/// button binds via `gtk::Button::set_action_name`.
///
/// Returns the static action target `"app.add"` — the fully-
/// qualified target the application's `app` action group resolves
/// against. The matching `gio::SimpleAction` (`"add"`) is
/// registered on the application's action group and dispatches
/// `AddAccountComponent`. The `"app."` prefix names the group;
/// `"add"` names the action. The `+` button shares the
/// `Unlocked` / `UnlockedBusy` gating with the four mutating
/// primary-menu entries per §"libadwaita usage".
///
/// Pure — returns a `'static str` without allocating. Companion
/// of [`format_app_add_button_icon_name`] (header-bar glyph) and
/// [`format_app_add_button_tooltip`] (header-bar tooltip);
/// together they pin the visible button surface and its action
/// wiring against a single source of truth.
#[must_use]
pub fn format_app_add_button_action() -> &'static str {
    "app.add"
}

/// Bare `GLib` action name the header-bar `+` button binds via
/// [`format_app_add_button_action`].
///
/// Returns the static action name `"add"` — the name passed
/// to `gio::SimpleAction::new(..., None)` when the matching
/// action is registered on the application's `app` action group.
/// The fully-qualified `detailed_action_name` `"app.add"`
/// spelled by [`format_app_add_button_action`] is the
/// [`format_app_action_group_name`] group prefix joined to this
/// bare name via the `<group>.<action>` separator. The matching
/// action dispatches `AddAccountComponent` and shares the
/// `Unlocked` / `UnlockedBusy` gating with the four mutating
/// primary-menu entries per §"libadwaita usage".
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_add_button_action`] on the fully-qualified
/// target side and [`format_app_add_button_icon_name`] /
/// [`format_app_add_button_tooltip`] on the header-bar visible
/// surface side; together they pin the bare action name and
/// its action wiring against a single source of truth.
#[must_use]
pub fn format_app_add_button_action_name() -> &'static str {
    "add"
}

/// Keyboard accelerator the header-bar `+` button's
/// `gio::SimpleAction` is wired to per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Header bar > Add".
///
/// Returns the gtk-rs accelerator spelling `"<Control>n"` —
/// the same `<Ctrl>N` shortcut referenced verbatim on
/// [`build_app_add_action`] and [`build_app_window_action_group`]
/// docstrings. The widget binding consumes this via
/// `gio::Application::set_accels_for_action(format_app_add_button_action(),
/// &[format_app_add_button_accelerator()])` so the menu and
/// button-driven activation paths share one shortcut surface
/// against a single source of truth, instead of re-spelling
/// `"<Control>n"` at the wiring site (which would silently
/// drift away from the documented shortcut on a future rename).
///
/// The `<Control>n` form (uppercase modifier in angle brackets,
/// lowercase key letter) matches gtk-rs `accels_for_action`'s
/// recognised spelling; `<Primary>` would also resolve on Linux
/// but `<Control>` keeps the helper aligned with the existing
/// in-source documentation references.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`format_app_add_button_action`] (the fully-qualified
/// action target) and [`format_app_add_button_action_name`]
/// (the bare action name); together they pin the action target,
/// its bare name, and its keyboard accelerator against a single
/// source of truth.
#[must_use]
pub fn format_app_add_button_accelerator() -> &'static str {
    "<Control>n"
}

/// Ordered `(accelerator, fully-qualified action target)` pairs
/// the application-window wiring hands to
/// `gio::Application::set_accels_for_action(target, &[accel])`
/// per `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Primary menu" / "Header bar > Add".
///
/// Returns the three pinned accelerator surfaces in pinned
/// order: Add (`<Control>n` → `app.add`), Quit (`<Control>q` →
/// `app.quit`), and Preferences (`<Control>comma` →
/// `app.preferences`). Each pair sources its accelerator from
/// the matching `format_app_*_accelerator` helper and its action
/// target from the matching `format_app_*_action` helper so the
/// table cannot drift away from either source of truth on a
/// future rename. The widget binding consumes this array via
/// `for (accel, target) in format_app_window_accelerator_bindings()
/// { app.set_accels_for_action(target, &[accel]); }` so the
/// accelerator wiring stays a single iteration over the pinned
/// source of truth instead of three hand-spelled calls that
/// could silently drift in order or coverage.
///
/// Pure — returns a small fixed-size array of `'static` string
/// pairs without allocating. Sibling of
/// [`format_app_primary_menu_entries`] on the menu-model side;
/// together they pin the (label / target / accelerator) triple
/// for every keyboard-reachable surface in the application
/// window against a single source of truth.
#[must_use]
pub fn format_app_window_accelerator_bindings() -> [(&'static str, &'static str); 3] {
    [
        (
            format_app_add_button_accelerator(),
            format_app_add_button_action(),
        ),
        (
            format_app_menu_quit_accelerator(),
            format_app_menu_quit_action(),
        ),
        (
            format_app_menu_preferences_accelerator(),
            format_app_menu_preferences_action(),
        ),
    ]
}

/// Register every pinned keyboard accelerator on `app` per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Primary menu" / "Header bar > Add".
///
/// Iterates [`format_app_window_accelerator_bindings`] (the
/// `(accelerator, fully-qualified action target)` pairs for
/// Add, Quit, and Preferences) and calls
/// `gio::Application::set_accels_for_action(target, &[accel])`
/// per pair so the menu and button activations share their
/// keyboard surfaces against a single source of truth instead
/// of three hand-spelled `set_accels_for_action` calls that
/// could silently drift in order or coverage.
///
/// The widget binding calls this helper inside `init` once the
/// shared application reference is available
/// (`relm4::main_application()`, which returns a
/// [`gtk::Application`] — `adw::Application` inherits from it
/// and would also resolve via `.upcast_ref()` if the project
/// ever migrates to an explicit `adw::Application::new` path);
/// the registrations stay live for the lifetime of the
/// application. Sibling of [`wire_app_window_action_group`]
/// (action-group insertion) and
/// [`wire_app_window_action_activations`] (per-action
/// `connect_activate` wiring); together the three helpers cover
/// the full keyboard-and-menu wiring for the application window
/// against the pinned source of truth.
///
/// Pure side-effect helper (no return value). Each
/// `set_accels_for_action` call overrides any prior binding for
/// the same target, so a repeat invocation is idempotent and
/// safe under hot-reload scenarios where the application
/// already has a partial accelerator surface.
pub fn wire_app_window_accelerators(app: &gtk::Application) {
    for (accel, target) in format_app_window_accelerator_bindings() {
        app.set_accels_for_action(target, &[accel]);
    }
}

/// Ordered `(label, detailed_action_name)` pairs the `AppModel`'s
/// primary `gio::Menu` appends in the §"libadwaita usage"
/// sequence (Import, Export, Passphrase, Preferences, About,
/// Quit).
///
/// Returns the same six pairs the per-entry helpers
/// ([`format_app_menu_import_label`] / [`format_app_menu_import_action`]
/// through [`format_app_menu_quit_label`] / [`format_app_menu_quit_action`])
/// already spell individually. The widget binding consumes this
/// array via `gio::Menu::append(Some(label), Some(action))` so
/// the menu construction stays a single `for`-loop over a
/// pinned source of truth instead of six hand-spelled
/// `menu.append(...)` calls that could silently drift in order
/// or coverage.
///
/// Pure — returns a small fixed-size array of `'static` string
/// pairs without allocating.
#[must_use]
pub fn format_app_primary_menu_entries() -> [(&'static str, &'static str); 6] {
    [
        (
            format_app_menu_import_label(),
            format_app_menu_import_action(),
        ),
        (
            format_app_menu_export_label(),
            format_app_menu_export_action(),
        ),
        (
            format_app_menu_passphrase_label(),
            format_app_menu_passphrase_action(),
        ),
        (
            format_app_menu_preferences_label(),
            format_app_menu_preferences_action(),
        ),
        (
            format_app_menu_about_label(),
            format_app_menu_about_action(),
        ),
        (format_app_menu_quit_label(), format_app_menu_quit_action()),
    ]
}

/// Build the application's primary `gio::Menu` model from the
/// pinned [`format_app_primary_menu_entries`] data.
///
/// Walks the six (label, detailed-action-name) pairs in the
/// §"libadwaita usage" sequence (Import…, Export…, Passphrase…,
/// Preferences, About Paladin, Quit) and `menu.append(...)`s
/// each one. The widget binding hands the returned model to the
/// header-bar `gtk::MenuButton::set_menu_model` so the kebab
/// popover renders the entries in the documented order, and the
/// action targets resolve against the `app` group registered on
/// the [`adw::ApplicationWindow`].
///
/// Centralizing the menu construction in one helper means the
/// labels and action targets stay sourced exclusively from the
/// pinned helpers — a drift between the widget binding and the
/// `format_app_menu_*` helpers cannot survive because the
/// widget reads the model through this single entry point and
/// the model walks the pinned array. Mirrors the
/// [`crate::account_list`]'s `build_kebab_menu_model` pattern for
/// the per-row kebab `gio::Menu`; both surfaces share the same
/// "iterate a pinned entry array and `menu.append`" shape so the
/// menu wiring is uniform across the crate.
///
/// Returns an owned [`gtk::gio::Menu`]. Construction allocates
/// the underlying `GMenu`; the caller is expected to hand the
/// model to `set_menu_model` and let the widget take ownership
/// of the model's `GObject` reference.
#[must_use]
pub fn build_app_primary_menu_model() -> gtk::gio::Menu {
    let menu = gtk::gio::Menu::new();
    for (label, action) in format_app_primary_menu_entries() {
        menu.append(Some(label), Some(action));
    }
    menu
}

/// Ordered bare `gio::SimpleAction` names the application's `app`
/// action group registers for the primary menu entries.
///
/// Returns the six bare action names in the §"libadwaita usage"
/// sequence (Import, Export, Passphrase, Preferences, About,
/// Quit) — parallel to [`format_app_primary_menu_entries`] —
/// so the widget binding can iterate this array to call
/// `gio::SimpleAction::new(name, None)` alongside the
/// matching `gio::Menu::append` loop. Both arrays share a
/// pinned source of truth, and the parallel coverage tests in
/// `tests/startup_probes.rs` cross-check that joining each name
/// with the shared [`format_app_action_group_name`] prefix
/// reproduces the fully-qualified action target in the matching
/// slot of [`format_app_primary_menu_entries`].
///
/// Pure — returns a small fixed-size array of `'static` strings
/// without allocating.
#[must_use]
pub fn format_app_primary_menu_action_names() -> [&'static str; 6] {
    [
        format_app_menu_import_action_name(),
        format_app_menu_export_action_name(),
        format_app_menu_passphrase_action_name(),
        format_app_menu_preferences_action_name(),
        format_app_menu_about_action_name(),
        format_app_menu_quit_action_name(),
    ]
}

/// Per-entry enabled state for the primary menu, parallel to
/// [`format_app_primary_menu_entries`] and
/// [`format_app_primary_menu_action_names`].
///
/// Returns a `[bool; 6]` array whose slots match the §"libadwaita
/// usage" sequence (Import, Export, Passphrase, Preferences,
/// About, Quit). The four mutating entries
/// (Import / Export / Passphrase / Preferences) read their
/// sensitivity from [`AppState::allows_mutating_menu`] so they
/// are enabled only when `AppModel` is in
/// [`AppState::Unlocked`] (disabled in `Missing` / `Locked` /
/// `UnlockedBusy` / `StartupError`). About and Quit stay enabled
/// in every state per §"libadwaita usage".
///
/// The widget binding consumes this array alongside
/// [`format_app_primary_menu_action_names`] to keep each
/// `gio::SimpleAction::set_enabled(...)` call against the same
/// pinned source of truth, so a future change to the mutating-
/// menu rule reverberates through every consumer instead of
/// silently drifting per entry.
///
/// Pure — returns a small fixed-size array of `bool` without
/// allocating.
#[must_use]
pub fn format_app_primary_menu_action_sensitivities(state: &AppState) -> [bool; 6] {
    let mutating = state.allows_mutating_menu();
    [
        mutating, // Import
        mutating, // Export
        mutating, // Passphrase
        mutating, // Preferences
        true,     // About
        true,     // Quit
    ]
}

/// Build the application's primary
/// [`gtk::gio::SimpleActionGroup`] from the pinned
/// [`format_app_primary_menu_action_names`] data, applying the
/// per-entry sensitivity returned by
/// [`format_app_primary_menu_action_sensitivities`] for the
/// supplied `state`.
///
/// Walks the six bare action names in the §"libadwaita usage"
/// sequence (Import, Export, Passphrase, Preferences, About,
/// Quit) and registers one parameter-less
/// [`gtk::gio::SimpleAction`] per name with the matching
/// `set_enabled` flag. The widget binding inserts the returned
/// group into the [`adw::ApplicationWindow`] via
/// `insert_action_group(format_app_action_group_name(), Some(&group))`
/// so the menu targets spelled by
/// [`format_app_primary_menu_entries`] (`"app.import"`,
/// `"app.export"`, …, `"app.quit"`) resolve through the group's
/// actions.
///
/// Centralizing the action-group construction in one helper
/// means the bare action names, their parameter shape (no
/// parameter), and their sensitivity rule stay sourced
/// exclusively from the pinned helpers — a drift between the
/// widget binding and the `format_app_menu_*_action_name` /
/// `format_app_primary_menu_action_sensitivities` helpers cannot
/// survive because the widget reads the group through this
/// single entry point. Mirrors
/// [`build_app_primary_menu_model`] on the menu side; together
/// they pin both halves of the primary-menu wiring (the
/// `gio::Menu` model and its companion `gio::SimpleActionGroup`)
/// against a single source of truth.
///
/// The per-action `connect_activate` handler that forwards each
/// activation to the matching [`AppMsg`] is wired by the widget
/// binding (the closure needs the [`relm4::ComponentSender`]
/// that lives on the widget side); this helper only registers
/// the action surface so the test suite can prove the names and
/// sensitivities are pinned.
///
/// Returns an owned [`gtk::gio::SimpleActionGroup`].
/// Construction allocates the underlying `GSimpleActionGroup`
/// and each `GSimpleAction`; the caller is expected to hand the
/// group to `insert_action_group` and let the widget take
/// ownership of the group's `GObject` reference.
#[must_use]
pub fn build_app_primary_action_group(state: &AppState) -> gtk::gio::SimpleActionGroup {
    let group = gtk::gio::SimpleActionGroup::new();
    let names = format_app_primary_menu_action_names();
    let enabled = format_app_primary_menu_action_sensitivities(state);
    for (name, sensitive) in names.iter().zip(enabled.iter()) {
        let action = gtk::gio::SimpleAction::new(name, None);
        action.set_enabled(*sensitive);
        group.add_action(&action);
    }
    group
}

/// Apply the per-state sensitivities returned by
/// [`format_app_primary_menu_action_sensitivities`] to an
/// existing primary [`gtk::gio::SimpleActionGroup`].
///
/// Walks the six bare action names in the §"libadwaita usage"
/// sequence (Import, Export, Passphrase, Preferences, About,
/// Quit) and applies
/// [`gtk::gio::SimpleAction::set_enabled`] to each matching
/// action looked up against `group`. The widget binding calls
/// this helper from [`AppMsg`] state-transition arms
/// ([`AppState::Missing`] / [`AppState::Locked`] /
/// [`AppState::Unlocked`] / [`AppState::UnlockedBusy`] /
/// [`AppState::StartupError`]) so the mutating affordances
/// (Import, Export, Passphrase, Preferences) toggle off
/// whenever `AppModel` leaves [`AppState::Unlocked`] without
/// re-creating the group. About and Quit stay enabled
/// everywhere per §"libadwaita usage".
///
/// Mirrors [`build_app_primary_action_group`] on the runtime-
/// update side; together they pin every primary-menu
/// sensitivity transition against
/// [`format_app_primary_menu_action_sensitivities`] so a future
/// change to the mutating-menu rule reverberates through both
/// the initial group construction and every subsequent state
/// transition without per-call drift.
///
/// If an action is missing from `group` (e.g. the widget
/// binding constructed the group via something other than
/// [`build_app_primary_action_group`]) the corresponding
/// sensitivity update is silently skipped — the assertion that
/// the group has every action lives on
/// [`build_app_primary_action_group`]'s test surface so this
/// helper stays a no-op-on-missing-action runtime path that
/// the smoke test can call without setup gymnastics. Pure side-
/// effect helper (no return value).
pub fn apply_app_primary_menu_sensitivities(group: &gtk::gio::SimpleActionGroup, state: &AppState) {
    let names = format_app_primary_menu_action_names();
    let enabled = format_app_primary_menu_action_sensitivities(state);
    for (name, sensitive) in names.iter().zip(enabled.iter()) {
        if let Some(action) = group.lookup_action(name) {
            if let Ok(simple) = action.downcast::<gtk::gio::SimpleAction>() {
                simple.set_enabled(*sensitive);
            }
        }
    }
}

/// Sensitive (enabled) state for the header-bar `+` button bound
/// via [`format_app_add_button_action`].
///
/// Returns the value of [`AppState::allows_mutating_menu`] —
/// `true` only when `AppModel` is in [`AppState::Unlocked`],
/// `false` everywhere else (`Missing` / `Locked` /
/// `UnlockedBusy` / `StartupError`) — matching the four mutating
/// primary-menu entries per §"libadwaita usage". Reading the
/// rule from `allows_mutating_menu` directly keeps the + button
/// and the menu entries on the same gate so a future change to
/// the mutating-menu rule reverberates through every consumer
/// instead of silently drifting per surface.
///
/// Companion of
/// [`format_app_primary_menu_action_sensitivities`] on the
/// per-entry sensitivity side; the four mutating slots of that
/// array carry the same value this helper returns.
///
/// Pure — returns a `bool` without allocating.
#[must_use]
pub fn format_app_add_button_sensitive(state: &AppState) -> bool {
    state.allows_mutating_menu()
}

/// Visibility for the header-bar `+` button bound via
/// [`format_app_add_button_action`].
///
/// Returns the value of [`AppState::is_unlocked`] — `true`
/// when `AppModel` is in [`AppState::Unlocked`] or
/// [`AppState::UnlockedBusy`] (the vault is open in either
/// case), `false` otherwise (`Missing` / `Locked` /
/// `StartupError`). The widget binding consumes the value
/// through `set_visible` so the `+` button is hidden entirely
/// before a vault is open — a relaxation of
/// [`format_app_add_button_sensitive`] (which also gates on
/// [`AppState::UnlockedBusy`] via
/// [`AppState::allows_mutating_menu`], so the button stays
/// visible-but-disabled during `UnlockedBusy`). The split
/// matches §"libadwaita usage": the `+` remains visible during
/// `UnlockedBusy` so the user can see the affordance is
/// momentarily unavailable rather than seeing the surface
/// re-flow when a vault worker spawns; it is disabled rather
/// than hidden so a follow-up keystroke does not race against
/// the running worker.
///
/// Pinning the rule through a helper keeps the widget binding
/// free of bare `state.is_unlocked()` reads shared between
/// `view!` and any future runtime visibility update. Sibling
/// of [`format_app_add_button_sensitive`] on the header-bar-
/// `+`-button state-projection side; together they pin both
/// the visibility and the (separate) sensitivity rule against
/// a single source of truth.
///
/// Pure — returns a `bool` without allocating.
#[must_use]
pub fn format_app_add_button_visible(state: &AppState) -> bool {
    state.is_unlocked()
}

/// Build the header-bar `+` button's
/// [`gtk::gio::SimpleAction`] from the pinned
/// [`format_app_add_button_action_name`] (the bare action name
/// `"add"`) with the sensitivity returned by
/// [`format_app_add_button_sensitive`] for the supplied
/// `state`.
///
/// Registers a parameter-less [`gtk::gio::SimpleAction`] named
/// `"add"` so the `+` button's
/// [`gtk::Button::set_action_name`] target `"app.add"` resolves
/// through the `app` action group registered on the
/// [`adw::ApplicationWindow`]. The widget binding adds the
/// returned action to the same group built by
/// [`build_app_primary_action_group`] (or registers a separate
/// extension group, depending on how the binding chooses to
/// scope action ownership); either path keeps the `+` button's
/// affordance and the primary menu's affordances on the same
/// `app` group prefix so the `<Ctrl>N` accelerator wired via
/// `gio::Application::set_accels_for_action("app.add",
/// &["<Control>n"])` resolves through this action.
///
/// Centralizing the construction in one helper means the bare
/// action name (`"add"`), its parameter shape (no parameter),
/// and its sensitivity rule stay sourced exclusively from the
/// pinned helpers — a drift between the widget binding and the
/// `format_app_add_button_action_name` /
/// `format_app_add_button_sensitive` helpers cannot survive
/// because the widget reads the action through this single
/// entry point. Sibling of [`build_app_primary_action_group`]
/// on the action-construction side; together they pin both the
/// header-bar `+` button and the primary menu against a single
/// source of truth.
///
/// The `connect_activate` handler that forwards activation to
/// [`AppMsg::OpenAddDialog`] is wired by the widget binding
/// (the closure needs the [`relm4::ComponentSender`] that lives
/// on the widget side); this helper only registers the action
/// surface so the test suite can prove the name and
/// sensitivity are pinned.
///
/// Returns an owned [`gtk::gio::SimpleAction`].
#[must_use]
pub fn build_app_add_action(state: &AppState) -> gtk::gio::SimpleAction {
    let action = gtk::gio::SimpleAction::new(format_app_add_button_action_name(), None);
    action.set_enabled(format_app_add_button_sensitive(state));
    action
}

/// Apply the per-state sensitivity returned by
/// [`format_app_add_button_sensitive`] to an existing
/// header-bar `+` button
/// [`gtk::gio::SimpleAction`].
///
/// Calls [`gtk::gio::SimpleAction::set_enabled`] on `action`
/// with [`format_app_add_button_sensitive`]'s value for the
/// supplied `state`. The widget binding calls this helper from
/// [`AppMsg`] state-transition arms ([`AppState::Missing`] /
/// [`AppState::Locked`] / [`AppState::Unlocked`] /
/// [`AppState::UnlockedBusy`] / [`AppState::StartupError`]) so
/// the Add affordance toggles disabled whenever `AppModel`
/// leaves [`AppState::Unlocked`] without re-creating the
/// action — mirrors
/// [`apply_app_primary_menu_sensitivities`] on the runtime-
/// update side for the primary menu's mutating entries.
///
/// Centralizing the runtime sensitivity application in one
/// helper means the Add button and the primary menu share one
/// rule sourced exclusively from
/// [`format_app_add_button_sensitive`] /
/// [`format_app_primary_menu_action_sensitivities`] — a future
/// change to the mutating-affordance rule reverberates through
/// both consumers without per-call drift. Sibling of
/// [`apply_app_primary_menu_sensitivities`] on the runtime-
/// transition side; together they pin every state-change
/// sensitivity update against the pinned format helpers.
///
/// Pure side-effect helper (no return value).
pub fn apply_app_add_action_sensitivity(action: &gtk::gio::SimpleAction, state: &AppState) {
    action.set_enabled(format_app_add_button_sensitive(state));
}

/// Apply the per-state visibility returned by
/// [`format_app_add_button_visible`] to an existing
/// header-bar `+` button [`gtk::Button`].
///
/// Calls [`gtk::prelude::WidgetExt::set_visible`] on `button`
/// with [`format_app_add_button_visible`]'s value for the
/// supplied `state`. The widget binding calls this helper from
/// [`AppMsg`] state-transition arms ([`AppState::Missing`] /
/// [`AppState::Locked`] / [`AppState::Unlocked`] /
/// [`AppState::UnlockedBusy`] / [`AppState::StartupError`]) so
/// the `+` button is hidden entirely whenever `AppModel`
/// leaves a vault-open state and re-appears when a vault is
/// open again — mirrors [`apply_app_add_action_sensitivity`]
/// on the sensitivity-update side and
/// [`apply_app_primary_menu_sensitivities`] on the
/// runtime-update side for the primary menu's mutating
/// entries.
///
/// Centralizing the runtime visibility application in one
/// helper means the `+` button's `set_visible` call site stays
/// sourced exclusively from [`format_app_add_button_visible`]
/// — the widget binding never hand-spells a bare
/// `state.is_unlocked()` read inline. Sibling of
/// [`apply_app_add_action_sensitivity`] on the runtime-
/// transition side; together they pin every state-change
/// visibility and sensitivity update for the `+` button
/// against the pinned format helpers.
///
/// Pure side-effect helper (no return value).
pub fn apply_app_add_button_visibility(button: &gtk::Button, state: &AppState) {
    button.set_visible(format_app_add_button_visible(state));
}

/// Per-state visibility flag the widget binding hands to the
/// header-bar search-toggle `gtk::ToggleButton::set_visible`.
///
/// Returns the value of [`AppState::is_unlocked`] — `true`
/// when `AppModel` is in [`AppState::Unlocked`] or
/// [`AppState::UnlockedBusy`] (the vault is open and
/// `AccountListComponent` is mounted in either case), `false`
/// otherwise (`Missing` / `Locked` / `StartupError`). The
/// search-toggle is hidden entirely before a vault is open
/// because the `gtk::SearchBar` it controls only exists inside
/// `AccountListComponent` — the user cannot search what is not
/// mounted. Stays visible during `UnlockedBusy` so the
/// affordance does not disappear when a vault worker spawns;
/// the search filter itself is non-mutating and remains
/// available regardless of the worker. Mirrors the
/// [`format_app_add_button_visible`] split on the `+` button
/// side so both header-bar affordances follow one rule.
///
/// Pinning the rule through a helper keeps the widget binding
/// free of bare `state.is_unlocked()` reads shared between
/// `view!` and any future runtime visibility update. Sibling
/// of [`format_app_add_button_visible`] on the header-bar-
/// visibility side; together they pin both header-bar
/// affordances' visibility against a single source of truth.
///
/// Pure — returns a `bool` without allocating.
#[must_use]
pub fn format_app_search_button_visible(state: &AppState) -> bool {
    state.is_unlocked()
}

/// Apply the per-state visibility returned by
/// [`format_app_search_button_visible`] to an existing
/// header-bar search-toggle [`gtk::ToggleButton`].
///
/// Calls [`gtk::prelude::WidgetExt::set_visible`] on `button`
/// with [`format_app_search_button_visible`]'s value for the
/// supplied `state`. The widget binding calls this helper from
/// [`AppMsg`] state-transition arms ([`AppState::Missing`] /
/// [`AppState::Locked`] / [`AppState::Unlocked`] /
/// [`AppState::UnlockedBusy`] / [`AppState::StartupError`]) so
/// the search-toggle is hidden entirely whenever `AppModel`
/// leaves a vault-open state and re-appears when a vault is
/// open again — mirrors [`apply_app_add_button_visibility`] on
/// the `+`-button side so both header-bar affordances toggle
/// together.
///
/// Centralizing the runtime visibility application in one
/// helper means the search-toggle's `set_visible` call site
/// stays sourced exclusively from
/// [`format_app_search_button_visible`] — the widget binding
/// never hand-spells a bare `state.is_unlocked()` read inline.
/// Sibling of [`apply_app_add_button_visibility`] on the
/// runtime-update side; together they pin every state-change
/// visibility update for both header-bar affordances against
/// the pinned format helpers.
///
/// Pure side-effect helper (no return value).
pub fn apply_app_search_button_visibility(button: &gtk::ToggleButton, state: &AppState) {
    button.set_visible(format_app_search_button_visible(state));
}

/// Map the header-bar search-toggle `gtk::ToggleButton`'s
/// `is_active` flag onto the [`AccountListMsg`] the live
/// [`AccountListComponent`] consumes.
///
/// The `connect_toggled` handler in `view!` posts
/// [`AppMsg::SearchToggled`] with the toggle's new `is_active`
/// state; the update arm calls this helper to derive the
/// matching [`AccountListMsg::SetSearchModeEnabled`] payload
/// before emitting it on the controller. Pinning the mapping
/// in a pure helper means the widget binding never hand-spells
/// the `active → AccountListMsg::SetSearchModeEnabled`
/// projection inline, and a future change (e.g. a guard
/// preventing the bar from opening during an in-flight
/// passphrase transition) reverberates through one call site.
///
/// Returns [`AccountListMsg::SetSearchModeEnabled(active)`]:
/// `true` reveals the `gtk::SearchBar` inside
/// `AccountListComponent`, `false` hides it. Sibling of the
/// [`AccountListOutput::QueryChanged`] dispatch on the
/// search-bar text side; together they cover both halves of
/// the user-driven search-bar surface.
///
/// Pure — `active` is consumed by value, no I/O, no
/// allocation.
#[must_use]
pub fn format_app_search_toggle_msg(active: bool) -> AccountListMsg {
    AccountListMsg::SetSearchModeEnabled(active)
}

/// Apply the per-state sensitivity returned by
/// [`format_app_add_button_sensitive`] to an existing
/// header-bar `+` button [`gtk::Button`].
///
/// Calls [`gtk::prelude::WidgetExt::set_sensitive`] on
/// `button` with [`format_app_add_button_sensitive`]'s value
/// for the supplied `state`. The widget binding calls this
/// helper from [`AppMsg`] state-transition arms
/// ([`AppState::Missing`] / [`AppState::Locked`] /
/// [`AppState::Unlocked`] / [`AppState::UnlockedBusy`] /
/// [`AppState::StartupError`]) so the `+` button is disabled
/// in every non-`Unlocked` state — sibling of
/// [`apply_app_add_button_visibility`] on the visibility-
/// update side and [`apply_app_add_action_sensitivity`] on
/// the [`gtk::gio::SimpleAction`] companion side. The
/// widget-level helper is what the binding calls when the
/// button is wired through [`gtk::Button::connect_clicked`]
/// directly; the action-level helper is what the binding
/// calls when the button is wired through
/// [`gtk::Button::set_action_name`] against the
/// [`build_app_add_action`] action.
///
/// Centralizing the runtime sensitivity application in one
/// helper means the `+` button's `set_sensitive` call site
/// stays sourced exclusively from
/// [`format_app_add_button_sensitive`] — the widget binding
/// never hand-spells a bare `state.allows_mutating_menu()`
/// read inline. Together with
/// [`apply_app_add_button_visibility`] they pin every
/// state-change visibility and sensitivity update for the
/// `+` button against the pinned format helpers.
///
/// Pure side-effect helper (no return value).
pub fn apply_app_add_button_sensitive(button: &gtk::Button, state: &AppState) {
    button.set_sensitive(format_app_add_button_sensitive(state));
}

/// Wire the primary-menu [`gtk::gio::Menu`] model returned by
/// [`build_app_primary_menu_model`] onto an existing
/// header-bar [`gtk::MenuButton`].
///
/// Calls [`gtk::MenuButton::set_menu_model`] on `menu_button`
/// with the [`gtk::gio::Menu`] built by
/// [`build_app_primary_menu_model`] (the six pinned entries
/// Import, Export, Passphrase, Preferences, About, Quit). The
/// widget binding calls this helper from `init` after
/// `view_output!()` so the primary menu surface is attached
/// once, alongside the [`build_app_window_action_group`]
/// insert that wires the matching `app.<bare>` action targets.
///
/// Centralizing the wiring in one helper means the widget
/// binding never hand-spells the
/// `menu_button.set_menu_model(Some(&build_app_primary_menu_model()))`
/// call site — a future change to the menu construction (e.g.
/// adding a separator or a sub-section) reverberates through
/// [`build_app_primary_menu_model`] alone. Sibling of
/// [`build_app_window_action_group`] on the action-group
/// wiring side; together they pin both halves of the primary-
/// menu surface (the `gio::Menu` model and its companion
/// `gio::SimpleActionGroup`) against a single source of truth.
///
/// Pure side-effect helper (no return value).
pub fn wire_app_menu_button_menu_model(menu_button: &gtk::MenuButton) {
    menu_button.set_menu_model(Some(&build_app_primary_menu_model()));
}

/// Insert a prebuilt application action group on the root
/// [`adw::ApplicationWindow`] with the pinned
/// [`format_app_action_group_name`] prefix.
///
/// Calls
/// [`gtk::prelude::WidgetExt::insert_action_group`] on
/// `window` with `group` and the bare group name returned by
/// [`format_app_action_group_name`] so the `"app.<bare>"`
/// action targets spelled by
/// [`format_app_primary_menu_entries`] (`"app.import"`,
/// `"app.export"`, …, `"app.quit"`) and the header-bar `+`
/// button's `"app.add"` target all resolve through the single
/// group inserted on the window. The caller is responsible
/// for constructing `group` via
/// [`build_app_window_action_group`] and wiring each action's
/// `connect_activate` handler against the
/// [`relm4::ComponentSender`] for `AppModel` before insert —
/// splitting build / wire-activate / insert into three steps
/// lets the widget binding attach the activation closures on
/// the same [`gtk::gio::SimpleActionGroup`] reference without
/// re-walking the group after the insert.
///
/// Centralizing the wiring in one helper means the widget
/// binding never hand-spells the
/// `window.insert_action_group(format_app_action_group_name(),
/// Some(&group))` call site — the group name stays sourced
/// exclusively from the pinned helper. Sibling of
/// [`wire_app_menu_button_menu_model`] on the menu-button
/// surface side; together they pin both halves of the primary-
/// menu wiring (the `gio::Menu` model attached to the
/// `MenuButton` and the `gio::SimpleActionGroup` inserted on
/// the window) against a single source of truth.
///
/// Pure side-effect helper (no return value).
pub fn wire_app_window_action_group(
    window: &adw::ApplicationWindow,
    group: &gtk::gio::SimpleActionGroup,
) {
    window.insert_action_group(format_app_action_group_name(), Some(group));
}

/// Install `connect_activate` closures on every
/// [`gtk::gio::SimpleAction`] registered on the bundled
/// application action group built by
/// [`build_app_window_action_group`].
///
/// Walks the seven bare action names returned by
/// [`format_app_window_action_names`] (the six primary-menu
/// entries plus the header-bar `+` Add action), looks each
/// one up on `group`, and wires a `connect_activate` closure
/// that posts the [`AppMsg`] variant returned by
/// [`dispatch_app_window_action`] through `input_sender`. The
/// widget binding calls this helper from `init` between the
/// [`build_app_window_action_group`] construction and the
/// [`wire_app_window_action_group`] insertion so every
/// action's activation flows through one shared dispatch
/// path.
///
/// Centralizing the wiring in one helper means the widget
/// binding never hand-spells per-action `connect_activate`
/// closures — a future addition to
/// [`format_app_window_action_names`] (e.g. a new menu entry)
/// automatically picks up its `connect_activate` closure
/// here, and the dispatch table coverage test
/// (`dispatch_app_window_action_covers_every_bundled_action_name`)
/// keeps the two helpers in lockstep. Mirrors
/// [`crate::account_list::install_row_action_group`] on the
/// per-row kebab menu side.
///
/// If an action name is missing from `group` (e.g. a future
/// refactor that split the actions across two groups) the
/// corresponding closure is silently skipped — the assertion
/// that the bundled group has every action lives on
/// [`build_app_window_action_group`]'s test surface so this
/// helper stays a no-op-on-missing-action runtime path.
///
/// Pure side-effect helper (no return value).
pub fn wire_app_window_action_activations(
    group: &gtk::gio::SimpleActionGroup,
    input_sender: &relm4::Sender<AppMsg>,
) {
    for name in format_app_window_action_names() {
        if let Some(simple) = group
            .lookup_action(name)
            .and_then(|a| a.downcast::<gtk::gio::SimpleAction>().ok())
        {
            let action_sender = input_sender.clone();
            let action_name = name;
            simple.connect_activate(move |_, _| {
                if let Some(msg) = dispatch_app_window_action(action_name) {
                    let _ = action_sender.send(msg);
                }
            });
        }
    }
}

/// Return every bare action name registered on the
/// application's `app` action group built by
/// [`build_app_window_action_group`].
///
/// Bundles the six primary-menu bare action names returned by
/// [`format_app_primary_menu_action_names`] (Import, Export,
/// Passphrase, Preferences, About, Quit) with the header-bar
/// `+` button's bare action name returned by
/// [`format_app_add_button_action_name`] into a fixed-size
/// array so the widget binding can iterate every action on
/// the bundled group without allocating a `Vec` per `init`
/// call.
///
/// The pinned order keeps the menu entries first (matching
/// the §"libadwaita usage" sequence) and appends Add at the
/// end so callers that only care about the menu can take
/// `&names[..6]` while the full array covers the entire
/// action surface for `connect_activate` wiring and runtime
/// sensitivity updates.
///
/// Pure — returns an owned array of `&'static str` without
/// allocating.
#[must_use]
pub fn format_app_window_action_names() -> [&'static str; 7] {
    let menu = format_app_primary_menu_action_names();
    [
        menu[0],
        menu[1],
        menu[2],
        menu[3],
        menu[4],
        menu[5],
        format_app_add_button_action_name(),
    ]
}

/// Map a bare application action name to the matching
/// [`AppMsg`] dispatch variant.
///
/// Mirrors [`crate::account_list::dispatch_row_action`] on the
/// per-row kebab menu side: a single dispatch table routes the
/// `gio::SimpleAction` activations registered through
/// [`build_app_window_action_group`] to their matching
/// [`AppMsg`] variants so the widget binding's
/// `connect_activate` handlers share one source of truth.
///
/// The mapping today covers the header-bar `+` button's Add
/// action and the always-enabled menu entries (About, Quit);
/// the mutating menu entries (Import, Export, Passphrase,
/// Preferences) land in follow-up commits alongside their
/// widget-bearing dialog components. Returns `None` for any
/// unknown action name so a stray activation from a future
/// refactor that introduced an action name not yet covered
/// here stays a benign no-op rather than a panic — the
/// [`crate::account_list::dispatch_row_action`] sibling uses
/// the same `Option` shape so both consumers can fold
/// `if let Some(msg) = …` into their `connect_activate`
/// closures.
///
/// Pure — `name` is borrowed for the duration of the lookup
/// only.
#[must_use]
pub fn dispatch_app_window_action(name: &str) -> Option<AppMsg> {
    if name == format_app_add_button_action_name() {
        return Some(AppMsg::OpenAddDialog);
    }
    if name == format_app_menu_about_action_name() {
        return Some(AppMsg::OpenAboutDialog);
    }
    if name == format_app_menu_export_action_name() {
        return Some(AppMsg::OpenExportDialog);
    }
    if name == format_app_menu_import_action_name() {
        return Some(AppMsg::OpenImportDialog);
    }
    if name == format_app_menu_passphrase_action_name() {
        return Some(AppMsg::OpenPassphraseDialog);
    }
    if name == format_app_menu_preferences_action_name() {
        return Some(AppMsg::OpenPreferencesDialog);
    }
    if name == format_app_menu_quit_action_name() {
        return Some(AppMsg::Quit);
    }
    None
}

/// Map a [`StartupErrorOutput`] emitted by
/// [`crate::startup_error::StartupErrorComponent`] to the matching
/// [`AppMsg`] dispatch variant.
///
/// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction" the
/// [`crate::startup_error::StartupErrorComponent`] is display-only:
/// Retry and Quit are the only actions. The two arms of this
/// match lock that contract on the dispatch side:
///
/// * [`StartupErrorOutput::Quit`] → [`AppMsg::Quit`]. The
///   primary menu's "Quit" entry routes through the same
///   `AppMsg::Quit` variant via [`dispatch_app_window_action`]
///   so the application has one shutdown path through
///   `relm4::main_application().quit()` regardless of which
///   surface initiates Quit. A cross-check test in
///   `tests/startup_error_logic.rs` asserts both surfaces
///   resolve to the same variant so a future drift surfaces
///   as a failing test rather than a silent alternate quit
///   path.
/// * [`StartupErrorOutput::Retry`] → [`AppMsg::StartupErrorRetry`].
///   The dedicated retry arm in `update` re-runs the
///   path-resolution + `inspect` probe and remounts the
///   per-state child controller; routing through a distinct
///   `AppMsg` variant (rather than reusing the Unlock-/Add-/…
///   dispatch arms) keeps the retry handler clearly
///   separable from the mutating dispatch arms and lets the
///   exhaustive match in the test surface guarantee no
///   mutating variant slips in without an explicit design
///   revisit.
///
/// Mirrors [`dispatch_app_window_action`] on the menu-action
/// dispatch side. Pure — `out` is moved into the match by
/// value; no I/O, no allocation.
#[must_use]
pub fn dispatch_startup_error_output(out: StartupErrorOutput) -> AppMsg {
    match out {
        StartupErrorOutput::Quit => AppMsg::Quit,
        StartupErrorOutput::Retry => AppMsg::StartupErrorRetry,
    }
}

/// Build the single application-window
/// [`gtk::gio::SimpleActionGroup`] bundling every primary-menu
/// action and the header-bar `+` button's Add action.
///
/// Builds the primary-menu group via
/// [`build_app_primary_action_group`] (registering the six
/// entries Import, Export, Passphrase, Preferences, About,
/// Quit with their per-state sensitivities) and adds the Add
/// action constructed by [`build_app_add_action`] under the
/// same group so the menu targets spelled by
/// [`format_app_primary_menu_entries`] (`"app.import"`,
/// `"app.export"`, …, `"app.quit"`) and the header-bar `+`
/// button's `"app.add"` target all resolve through one
/// [`gtk::gio::SimpleActionGroup`] inserted on the
/// [`adw::ApplicationWindow`] via
/// `insert_action_group(format_app_action_group_name(),
/// Some(&group))`.
///
/// Centralizing the construction in one helper means the
/// widget binding inserts a single group rather than two — the
/// `<Ctrl>N` accelerator wired via
/// `gio::Application::set_accels_for_action("app.add",
/// &["<Control>n"])` resolves through this group along with
/// every menu accelerator. Sibling of
/// [`build_app_primary_menu_model`] on the menu side and
/// [`build_app_primary_action_group`] /
/// [`build_app_add_action`] on the per-half construction side;
/// together they pin both halves of the menu wiring (`gio::Menu`
/// model plus its companion `gio::SimpleActionGroup`) and the
/// `+` button against a single source of truth.
///
/// The per-action `connect_activate` handler that forwards
/// each activation to the matching [`AppMsg`] is wired by the
/// widget binding (the closure needs the
/// [`relm4::ComponentSender`] that lives on the widget side);
/// this helper only registers the action surface so the test
/// suite can prove the names and sensitivities are pinned.
///
/// Returns an owned [`gtk::gio::SimpleActionGroup`].
/// Construction allocates the underlying `GSimpleActionGroup`
/// and each `GSimpleAction`; the caller is expected to hand
/// the group to `insert_action_group` and let the widget take
/// ownership of the group's `GObject` reference.
#[must_use]
pub fn build_app_window_action_group(state: &AppState) -> gtk::gio::SimpleActionGroup {
    let group = build_app_primary_action_group(state);
    group.add_action(&build_app_add_action(state));
    group
}

/// Apply the per-state sensitivities returned by
/// [`format_app_primary_menu_action_sensitivities`] and
/// [`format_app_add_button_sensitive`] to every action on an
/// existing application-window
/// [`gtk::gio::SimpleActionGroup`].
///
/// Bundles [`apply_app_primary_menu_sensitivities`] (which
/// walks the six primary-menu bare action names) with an
/// [`apply_app_add_action_sensitivity`]-equivalent update for
/// the Add action looked up by
/// [`format_app_add_button_action_name`] on `group`. The
/// widget binding calls this helper from [`AppMsg`]
/// state-transition arms ([`AppState::Missing`] /
/// [`AppState::Locked`] / [`AppState::Unlocked`] /
/// [`AppState::UnlockedBusy`] / [`AppState::StartupError`]) so
/// every gated affordance toggles in one call without the
/// widget binding hand-spelling the per-action sensitivity
/// applications.
///
/// Mirrors [`build_app_window_action_group`] on the
/// runtime-update side; together they pin both the
/// initial construction and every subsequent sensitivity
/// transition for the bundled action group against the pinned
/// `format_app_primary_menu_action_sensitivities` /
/// `format_app_add_button_sensitive` rules so a future change
/// to either rule reverberates through both consumers without
/// per-call drift.
///
/// If an action is missing from `group` (e.g. the widget
/// binding constructed the group via something other than
/// [`build_app_window_action_group`]) the corresponding
/// sensitivity update is silently skipped — the assertion that
/// the group has every action lives on
/// [`build_app_window_action_group`]'s test surface so this
/// helper stays a no-op-on-missing-action runtime path that
/// the smoke test can call without setup gymnastics. Pure side-
/// effect helper (no return value).
pub fn apply_app_window_action_group_sensitivities(
    group: &gtk::gio::SimpleActionGroup,
    state: &AppState,
) {
    apply_app_primary_menu_sensitivities(group, state);
    if let Some(action) = group.lookup_action(format_app_add_button_action_name()) {
        if let Ok(simple) = action.downcast::<gtk::gio::SimpleAction>() {
            apply_app_add_action_sensitivity(&simple, state);
        }
    }
}

/// Build the application menu's "About Paladin" entry's
/// [`adw::AboutDialog`] from the pinned `format_app_about_dialog_*`
/// helpers.
///
/// Walks every `format_app_about_dialog_*` helper and threads
/// the returned value through the matching setter on the
/// [`adw::AboutDialog`]:
///
/// * [`format_app_about_dialog_program_name`] →
///   `set_application_name`
/// * [`format_app_about_dialog_version`] → `set_version`
/// * [`format_app_about_dialog_application_icon_name`] →
///   `set_application_icon`
/// * [`format_app_about_dialog_developer_name`] →
///   `set_developer_name`
/// * [`format_app_about_dialog_copyright`] → `set_copyright`
/// * [`format_app_about_dialog_license_type`] →
///   `set_license_type`
/// * [`format_app_about_dialog_website`] → `set_website`
/// * [`format_app_about_dialog_issue_url`] → `set_issue_url`
/// * [`format_app_about_dialog_support_url`] →
///   `set_support_url`
/// * [`format_app_about_dialog_comments`] → `set_comments`
/// * [`format_app_about_dialog_developers`] →
///   `set_developers`
/// * [`format_app_about_dialog_designers`] →
///   `set_designers`
/// * [`format_app_about_dialog_artists`] →
///   `set_artists`
/// * [`format_app_about_dialog_documenters`] →
///   `set_documenters`
/// * [`format_app_about_dialog_translator_credits`] →
///   `set_translator_credits`
/// * [`format_app_about_dialog_release_notes_version`] →
///   `set_release_notes_version`
/// * [`format_app_about_dialog_release_notes`] →
///   `set_release_notes`
/// * [`format_app_about_dialog_debug_info`] →
///   `set_debug_info`
/// * [`format_app_about_dialog_debug_info_filename`] →
///   `set_debug_info_filename`
///
/// Centralizing the construction in one helper means every
/// `AdwAboutDialog` property is sourced exclusively from a
/// pinned `format_app_about_dialog_*` helper — a drift between
/// the widget binding and the format helpers cannot survive
/// because the widget reads the dialog through this single
/// entry point. The widget binding calls
/// `build_app_about_dialog().present(Some(parent))` on the
/// `"about"` action's `connect_activate` handler so the dialog
/// pops up rooted at the active `adw::ApplicationWindow`.
///
/// Mirrors [`build_app_primary_menu_model`] and
/// [`build_app_primary_action_group`] on the construction side;
/// together they pin the menu's model, action group, and the
/// "About Paladin" dialog content against a single source of
/// truth.
///
/// Returns an owned [`adw::AboutDialog`].
#[must_use]
pub fn build_app_about_dialog() -> adw::AboutDialog {
    let dialog = adw::AboutDialog::new();
    dialog.set_application_name(format_app_about_dialog_program_name());
    dialog.set_version(format_app_about_dialog_version());
    dialog.set_application_icon(format_app_about_dialog_application_icon_name());
    dialog.set_developer_name(format_app_about_dialog_developer_name());
    dialog.set_copyright(format_app_about_dialog_copyright());
    dialog.set_license_type(format_app_about_dialog_license_type());
    dialog.set_website(format_app_about_dialog_website());
    dialog.set_issue_url(format_app_about_dialog_issue_url());
    dialog.set_support_url(format_app_about_dialog_support_url());
    dialog.set_comments(format_app_about_dialog_comments());
    dialog.set_developers(&format_app_about_dialog_developers());
    dialog.set_designers(&format_app_about_dialog_designers());
    dialog.set_artists(&format_app_about_dialog_artists());
    dialog.set_documenters(&format_app_about_dialog_documenters());
    dialog.set_translator_credits(format_app_about_dialog_translator_credits());
    dialog.set_release_notes_version(format_app_about_dialog_release_notes_version());
    dialog.set_release_notes(format_app_about_dialog_release_notes());
    dialog.set_debug_info(format_app_about_dialog_debug_info());
    dialog.set_debug_info_filename(format_app_about_dialog_debug_info_filename());
    dialog
}

/// Human-readable program name the application menu's "About
/// Paladin" entry's `AdwAboutDialog` displays in its header.
///
/// Returns the static program name `"Paladin"` — the canonical
/// display string that matches the §11.3 desktop entry's
/// `Name=Paladin` field so the launcher caption and the about
/// dialog header stay in lockstep.
///
/// Distinct from [`crate::APP_ID`] (`"org.tamx.Paladin.Gui"`),
/// the reverse-DNS Flatpak / system identifier consumed by
/// `RelmApp::new(...)`, `StartupWMClass`, the icon-theme key,
/// and the `AppStream` `<id>`; this helper is for human display
/// and never appears in those system-identifier slots.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_app_about_dialog_program_name() -> &'static str {
    "Paladin"
}

/// Version string the application menu's "About Paladin"
/// entry's `AdwAboutDialog` displays.
///
/// Sources from `env!("CARGO_PKG_VERSION")` so the dialog
/// header version line and the release-tag version stay in
/// lockstep without manual updates — the `crates/paladin-gtk`
/// package inherits its `version` from the workspace
/// `[workspace.package]` table, so a workspace-wide version
/// bump propagates here for free.
///
/// Pure — returns a `'static str` resolved at compile time.
/// Companion of [`format_app_about_dialog_program_name`] on
/// the `AdwAboutDialog` metadata side; together they pin the
/// program-name and version slots against a single source of
/// truth.
#[must_use]
pub fn format_app_about_dialog_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Icon-theme key the application menu's "About Paladin" entry's
/// `AdwAboutDialog` hands to `set_application_icon`.
///
/// Returns the reverse-DNS [`crate::APP_ID`]
/// (`"org.tamx.Paladin.Gui"`) — the same key consumed by
/// `RelmApp::new(APP_ID)`, the §11.3 desktop entry's
/// `Icon=org.tamx.Paladin.Gui` field, and the §11 hicolor icon
/// install layout (`/usr/share/icons/hicolor/<size>/apps/org.tamx.Paladin.Gui.*`).
/// Sharing the key with `APP_ID` keeps the launcher icon, the
/// desktop entry icon, the `AppStream` `<id>` icon, and the about
/// dialog header glyph resolving identically across native and
/// Flatpak builds.
///
/// Pure — returns a `'static str` without allocating.
/// Distinct from [`format_app_about_dialog_program_name`] (the
/// human "Paladin" display name); the icon key is the
/// reverse-DNS identifier, not the bare display name.
#[must_use]
pub fn format_app_about_dialog_application_icon_name() -> &'static str {
    crate::APP_ID
}

/// Attribution string the application menu's "About Paladin"
/// entry's `AdwAboutDialog` shows in its developer-name slot.
///
/// Returns the canonical collective attribution
/// `"The Paladin contributors"`. The workspace `Cargo.toml`
/// deliberately omits the `authors` field — Paladin is an
/// AGPL-3.0-or-later project with an open contributor pool, so
/// `env!("CARGO_PKG_AUTHORS")` would resolve to an empty string
/// and leave the about-dialog attribution row blank. Pinning
/// the literal here keeps the dialog header attribution row
/// stable across releases and across native vs. Flatpak builds.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from [`format_app_about_dialog_program_name`] (the bare
/// `"Paladin"` display string) and from
/// [`format_app_about_dialog_application_icon_name`] (the
/// reverse-DNS `org.tamx.Paladin.Gui` icon-theme key).
#[must_use]
pub fn format_app_about_dialog_developer_name() -> &'static str {
    "The Paladin contributors"
}

/// Copyright notice the application menu's "About Paladin"
/// entry's `AdwAboutDialog` renders in its footer slot.
///
/// Returns the canonical AGPL-3.0-or-later collective notice
/// `"© The Paladin contributors"`. Pinning the literal keeps
/// the dialog footer copyright row stable across releases — a
/// year-derived value would silently drift on every release
/// without a matching update to a year constant — and the `©`
/// glyph (U+00A9) renders the proper legal mark rather than the
/// ASCII `(C)` fallback.
///
/// The attribution string is the same one returned by
/// [`format_app_about_dialog_developer_name`] so the dialog
/// header attribution row and footer copyright row reference a
/// single source of truth. Per DESIGN.md §14 the project ships
/// under AGPL-3.0-or-later; the matching license-type spelling
/// is provided as a companion helper.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_app_about_dialog_copyright() -> &'static str {
    "\u{00A9} The Paladin contributors"
}

/// Typed GTK license enum the application menu's "About
/// Paladin" entry's `AdwAboutDialog` hands to
/// `set_license_type` so the dialog footer renders the
/// canonical AGPL-3.0-or-later text shipped with the toolkit.
///
/// Returns [`gtk::License::Agpl30`] — the `GTK_LICENSE_AGPL_3_0`
/// variant, i.e. the "or later" form per DESIGN.md §14 and the
/// workspace-wide `license = "AGPL-3.0-or-later"` contract.
/// Distinct from the strict [`gtk::License::Agpl30Only`] variant
/// (which would mis-state the license boundary as "AGPL-3.0
/// only"), and from the sibling `Gpl30` / `Lgpl30` variants
/// (which would silently misrepresent the project license).
///
/// Returning the typed enum (rather than an SPDX `&'static str`)
/// keeps the `AdwAboutDialog::set_license_type` call site free
/// of string-to-enum translation logic and lets the toolkit
/// drive both the footer license link and the human-readable
/// license name from a single source of truth.
///
/// Pure — returns a `Copy` enum value without allocating.
#[must_use]
pub fn format_app_about_dialog_license_type() -> gtk::License {
    gtk::License::Agpl30
}

/// Website URL the application menu's "About Paladin" entry's
/// `AdwAboutDialog` links to from its footer slot.
///
/// Sources from `env!("CARGO_PKG_HOMEPAGE")` so the dialog
/// footer website link and the workspace
/// `[workspace.package].homepage` field stay in lockstep —
/// `crates/paladin-gtk` inherits its `homepage` from the
/// workspace `homepage.workspace = true` declaration, so a
/// workspace-wide homepage bump propagates here for free.
///
/// Pure — returns a `'static str` resolved at compile time.
/// Companion of [`format_app_about_dialog_program_name`] /
/// [`format_app_about_dialog_version`] /
/// [`format_app_about_dialog_developer_name`] /
/// [`format_app_about_dialog_copyright`] /
/// [`format_app_about_dialog_license_type`] on the
/// `AdwAboutDialog` metadata side.
#[must_use]
pub fn format_app_about_dialog_website() -> &'static str {
    env!("CARGO_PKG_HOMEPAGE")
}

/// Issue-tracker URL the application menu's "About Paladin"
/// entry's `AdwAboutDialog` links to from its footer
/// "Report an issue" slot.
///
/// Returns `concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")` so
/// the dialog footer issue link and the workspace
/// `[workspace.package].repository` field stay in lockstep —
/// `crates/paladin-gtk` inherits its `repository` from
/// `repository.workspace = true`, so a workspace-wide
/// repository change propagates here for free. Appends the
/// standard `/issues` suffix to follow the GitHub
/// `<repo>/issues` URL convention without a duplicate constant
/// in this crate.
///
/// Pure — returns a `'static str` resolved at compile time.
/// Distinct from [`format_app_about_dialog_website`] (the
/// project homepage) so the dialog renders two separate footer
/// links rather than collapsing them.
#[must_use]
pub fn format_app_about_dialog_issue_url() -> &'static str {
    concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")
}

/// Support URL the application menu's "About Paladin" entry's
/// `AdwAboutDialog` links to from its footer "Get support" slot.
///
/// Returns `concat!(env!("CARGO_PKG_REPOSITORY"),
/// "/discussions")` — the GitHub Discussions tab is the
/// canonical "Where to find help" surface for the project (the
/// community Q&A side, distinct from the bug-reporting
/// `issue_url` side and from the homepage `website` link).
/// Sourcing from the workspace repository field keeps the
/// dialog footer support link in lockstep with a workspace-wide
/// repository move.
///
/// Pure — returns a `'static str` resolved at compile time.
/// Distinct from [`format_app_about_dialog_issue_url`] (the
/// bug-tracker URL) and [`format_app_about_dialog_website`]
/// (the project homepage) so the dialog renders three separate
/// footer links rather than collapsing the support entry into
/// either neighbour.
#[must_use]
pub fn format_app_about_dialog_support_url() -> &'static str {
    concat!(env!("CARGO_PKG_REPOSITORY"), "/discussions")
}

/// Short description the application menu's "About Paladin"
/// entry's `AdwAboutDialog` renders directly under the
/// program-name header in its comments slot.
///
/// Sources from `env!("CARGO_PKG_DESCRIPTION")` so the dialog
/// comments row and the workspace
/// `[workspace.package].description` field stay in lockstep —
/// `crates/paladin-gtk` inherits its `description` from
/// `description.workspace = true`, so a workspace-wide
/// description bump propagates here for free without a manual
/// duplicate constant in this crate.
///
/// Pure — returns a `'static str` resolved at compile time.
/// Distinct from [`format_app_about_dialog_program_name`] (the
/// bare `"Paladin"` display string) so the dialog header
/// renders two separate rows rather than collapsing the
/// comments slot into the title.
#[must_use]
pub fn format_app_about_dialog_comments() -> &'static str {
    env!("CARGO_PKG_DESCRIPTION")
}

/// Ordered contributor list the application menu's "About
/// Paladin" entry's `AdwAboutDialog` hands to
/// `set_developers` for its credits-page "Developers" section.
///
/// Returns the pinned credits-page contributor list. The
/// current contributor pool for the v0.2 release per `git log`
/// is the single founding developer; pinning the literal here
/// keeps the credits list stable across releases until a
/// contributor is explicitly added.
///
/// Distinct from [`format_app_about_dialog_developer_name`]
/// which returns the single header-attribution collective
/// string (`"The Paladin contributors"`) used in the dialog's
/// program-name header — the credits-page list spells out
/// individual contributors so attribution remains accurate
/// even though the workspace `Cargo.toml` deliberately omits
/// the `authors` field.
///
/// Pure — returns a fixed-size array of `'static` strings
/// without allocating.
#[must_use]
pub fn format_app_about_dialog_developers() -> [&'static str; 1] {
    ["Benjamin Porter"]
}

/// Ordered designer-credit list the application menu's "About
/// Paladin" entry's `AdwAboutDialog` hands to
/// `set_designers` for its credits-page "Designers" section.
///
/// Returns the empty array for the v0.2 release. Paladin does
/// not yet have a separately-credited designer — the founding
/// contributor in [`format_app_about_dialog_developers`] also
/// owns the GTK / HIG layout choices — so the designers slot
/// stays empty until a credited designer joins. `AdwAboutDialog`
/// follows the libadwaita convention of suppressing the
/// credits-page "Designers" row when the slice is empty, which
/// is the correct rendering for an app with no credited
/// designer.
///
/// Pinning the empty slice through a helper rather than passing
/// `&[]` inline at the call site keeps the credits-page wiring
/// uniform: every credits-page list is sourced from a
/// `format_app_about_dialog_<role>` helper so a future
/// contributor change updates one helper without touching the
/// widget binding. Sibling of
/// [`format_app_about_dialog_developers`] on the credits-page-
/// contributor side; together they pin the dialog's "Developers"
/// and "Designers" rows against a single source of truth.
///
/// Pure — returns a fixed-size empty array of `'static` strings
/// without allocating.
#[must_use]
pub fn format_app_about_dialog_designers() -> [&'static str; 0] {
    []
}

/// Ordered artist-credit list the application menu's "About
/// Paladin" entry's `AdwAboutDialog` hands to `set_artists` for
/// its credits-page "Artists" section.
///
/// Returns the empty array for the v0.2 release. Paladin does
/// not yet have a separately-credited artist — the application
/// icon and any auxiliary glyphs ship with the standard
/// freedesktop / Adwaita symbolic icon set, which carries its
/// own upstream credits, and the founding contributor in
/// [`format_app_about_dialog_developers`] owns the Paladin-
/// specific visual choices — so the artists slot stays empty
/// until a credited artist joins. `AdwAboutDialog` follows the
/// libadwaita convention of suppressing the credits-page
/// "Artists" row when the slice is empty, which is the correct
/// rendering for an app with no credited artist.
///
/// Pinning the empty slice through a helper rather than passing
/// `&[]` inline at the call site keeps the credits-page wiring
/// uniform: every credits-page list is sourced from a
/// `format_app_about_dialog_<role>` helper so a future
/// contributor change updates one helper without touching the
/// widget binding. Companion of
/// [`format_app_about_dialog_developers`],
/// [`format_app_about_dialog_designers`], and
/// [`format_app_about_dialog_translator_credits`] on the
/// credits-page-contributor side; together they pin every
/// credits-page row against a single source of truth.
///
/// Pure — returns a fixed-size empty array of `'static` strings
/// without allocating.
#[must_use]
pub fn format_app_about_dialog_artists() -> [&'static str; 0] {
    []
}

/// Ordered documenter-credit list the application menu's "About
/// Paladin" entry's `AdwAboutDialog` hands to `set_documenters`
/// for its credits-page "Documentation" section.
///
/// Returns the empty array for the v0.2 release. Paladin does
/// not yet have a separately-credited documenter — the project
/// `README.md`, `DESIGN.md`, and inline rustdoc are written by
/// the founding contributor in
/// [`format_app_about_dialog_developers`] — so the documenters
/// slot stays empty until a credited documenter joins.
/// `AdwAboutDialog` follows the libadwaita convention of
/// suppressing the credits-page "Documentation" row when the
/// slice is empty, which is the correct rendering for an app
/// with no credited documenter.
///
/// Pinning the empty slice through a helper rather than passing
/// `&[]` inline at the call site keeps the credits-page wiring
/// uniform: every credits-page list is sourced from a
/// `format_app_about_dialog_<role>` helper so a future
/// contributor change updates one helper without touching the
/// widget binding. Completes the credits-page contributor row
/// surface alongside [`format_app_about_dialog_developers`],
/// [`format_app_about_dialog_designers`],
/// [`format_app_about_dialog_artists`], and
/// [`format_app_about_dialog_translator_credits`]; together they
/// pin every credits-page row against a single source of truth.
///
/// Pure — returns a fixed-size empty array of `'static` strings
/// without allocating.
#[must_use]
pub fn format_app_about_dialog_documenters() -> [&'static str; 0] {
    []
}

/// Translator-credits string the application menu's "About
/// Paladin" entry's `AdwAboutDialog` hands to
/// `set_translator_credits` for its credits-page "Translators"
/// section.
///
/// Returns the empty string for the v0.2 English-only release.
/// Paladin does not yet ship a gettext catalog (no `LINGUAS` /
/// `.po` files), and `AdwAboutDialog` follows the libadwaita
/// convention of skipping the credits-page Translators row when
/// this value is empty — which is the correct rendering for an
/// app with no translations.
///
/// Once a gettext catalog lands the body should call
/// `gettext("translator-credits")` so translators populate the
/// row via `.po` entries (the conventional message key for this
/// slot across the GNOME stack); the test-suite assertion in
/// `tests/startup_probes.rs` is wired to flag that swap so the
/// helper is not silently re-routed without updating the
/// translation pipeline.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_app_about_dialog_translator_credits() -> &'static str {
    ""
}

/// Version string scoping the application menu's "About
/// Paladin" entry's `AdwAboutDialog` release-notes-version slot
/// (the "What's New" section surfaced after an update).
///
/// Sources from `env!("CARGO_PKG_VERSION")` so a workspace-wide
/// version bump propagates here for free — the same source of
/// truth as [`format_app_about_dialog_version`]. Pinning both
/// labels to a single source keeps the dialog's release-notes
/// header and the dialog's version label in lockstep; a
/// mismatch would surface stale release notes to users who
/// just upgraded.
///
/// Pure — returns a `'static str` resolved at compile time.
#[must_use]
pub fn format_app_about_dialog_release_notes_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Markup body the application menu's "About Paladin" entry's
/// `AdwAboutDialog` hands to `set_release_notes` for its
/// "What's New" section, paired with the version returned by
/// [`format_app_about_dialog_release_notes_version`].
///
/// Returns the empty string for the v0.0.1 / pre-v0.2 workspace
/// because Paladin has not yet shipped a tagged release.
/// `AdwAboutDialog` follows the libadwaita convention of
/// suppressing the "What's New" section when the body is empty,
/// which is the correct rendering for an app that has no
/// release-notes copy to surface yet.
///
/// Once v0.2 is tagged the body should swap to the matching
/// release-notes markup (the libadwaita `release-notes` slot
/// accepts a restricted subset of Pango markup); the assertion
/// in `tests/startup_probes.rs` will be the canary that flags
/// the swap so the helper is not silently re-routed without
/// also updating
/// [`format_app_about_dialog_release_notes_version`] in
/// lockstep.
///
/// Pinning the markup through a helper keeps the wording in one
/// place shared by the widget binding and the pure-logic tests.
/// Sibling of [`format_app_about_dialog_release_notes_version`]
/// on the release-notes-surface side; together they pin the
/// "What's New" section's body and the version label against a
/// single source of truth.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_app_about_dialog_release_notes() -> &'static str {
    ""
}

/// Plain-text payload the application menu's "About Paladin"
/// entry's `AdwAboutDialog` hands to `set_debug_info` for its
/// "Copy debug info" button — the text users paste into bug
/// reports.
///
/// Returns a two-line `\n`-separated payload built at compile
/// time via `concat!`:
///
/// ```text
/// Paladin <version>
/// App ID: org.tamx.Paladin.Gui
/// ```
///
/// The program name, version, and app-ID lines are the minimum
/// fields that let a maintainer identify the running release
/// and the install variant (native vs. Flatpak) from a pasted
/// bug report. The `tests/startup_probes.rs` coverage cross-
/// checks each line against the matching helper
/// ([`format_app_about_dialog_program_name`],
/// [`format_app_about_dialog_version`],
/// [`format_app_about_dialog_application_icon_name`]) so the
/// inlined literals stay in lockstep with the rest of the
/// about-dialog metadata.
///
/// Pure — returns a `'static str` resolved at compile time.
#[must_use]
pub fn format_app_about_dialog_debug_info() -> &'static str {
    concat!(
        "Paladin ",
        env!("CARGO_PKG_VERSION"),
        "\nApp ID: ",
        "org.tamx.Paladin.Gui",
    )
}

/// Suggested filename the application menu's "About Paladin"
/// entry's `AdwAboutDialog` hands to `set_debug_info_filename`
/// for the "Save debug info" file-save dialog.
///
/// Returns the static filename `"paladin-debug-info.txt"` —
/// `<app-slug>-debug-info.txt` matches the GNOME convention for
/// the debug-info save target (the libadwaita default is
/// `<application-name>-debug-info.txt`; pinning the slug here
/// keeps the suggested filename stable even if a future
/// `application-name` change drifts away from the `paladin`
/// slug used by the CLI / executable name). The `.txt`
/// extension matches the debug-info payload built by
/// [`format_app_about_dialog_debug_info`] which is plain text,
/// not Markdown or JSON.
///
/// Pinning the filename through a helper keeps the call site
/// free of bare string literals shared between the widget
/// binding and the pure-logic tests in
/// `tests/startup_probes.rs`. Sibling of
/// [`format_app_about_dialog_debug_info`] on the debug-info
/// surface; together they pin both the payload and its file-
/// save dialog's suggested name against a single source of
/// truth.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_app_about_dialog_debug_info_filename() -> &'static str {
    "paladin-debug-info.txt"
}

/// Bare `GLib` action-group name the primary `gio::Menu` resolves
/// every entry target against.
///
/// Returns the static group name `"app"` — the name passed to
/// `gio::ApplicationWindow::insert_action_group(...)` so the six
/// `gio::SimpleAction`s registered for the primary menu (`import`
/// / `export` / `passphrase` / `preferences` / `about` / `quit`)
/// are reachable via the `app.<action>` `detailed_action_name`
/// form spelled by [`format_app_menu_import_action`] and its
/// siblings. The bare group name omits the `.` separator that
/// joins the group prefix to each action's bare name; the
/// fully-qualified target is `{format_app_action_group_name()}.{action}`.
///
/// Pure — returns a `'static str` without allocating. Companion
/// of the six primary-menu action-target helpers
/// ([`format_app_menu_import_action`], [`format_app_menu_export_action`],
/// [`format_app_menu_passphrase_action`], [`format_app_menu_preferences_action`],
/// [`format_app_menu_about_action`], [`format_app_menu_quit_action`]);
/// together they pin the group prefix and every entry's action
/// target against a single source of truth.
#[must_use]
pub fn format_app_action_group_name() -> &'static str {
    "app"
}

/// gresource path the bundled `data/style.css` payload mounts at
/// inside the application's gresource pool.
///
/// Returns the static absolute resource path
/// `"/org/tamx/Paladin/Gui/style.css"`. The prefix segments
/// (`org` / `tamx` / `Paladin` / `Gui`) mirror [`crate::APP_ID`]
/// (`"org.tamx.Paladin.Gui"`) split on `.` so the resource pool
/// namespaces by reverse-DNS app ID and never collides with other
/// gresource-shipping apps loaded in the same process. The
/// terminal `style.css` matches the `<file>` entry declared in
/// `data/paladin-gtk.gresource.xml`, so the bundle compiled by
/// `build.rs` and the runtime [`wire_app_css_provider`] `CssProvider`
/// load resolve to the same payload.
///
/// Pinning the resource path through a helper keeps the call site
/// in [`wire_app_css_provider`] free of bare string literals and
/// lets the pure-logic tests in `tests/startup_probes.rs` assert
/// the prefix/suffix shape without spinning up GTK.
///
/// Pure — returns a `'static str` without allocating. Companion of
/// [`register_app_gresource_bundle`] (which hands the compiled
/// gresource bytes to `gio::resources_register` so this path
/// resolves at runtime) and [`wire_app_css_provider`] (which calls
/// `gtk::CssProvider::load_from_resource` against this path);
/// together they pin the gresource side of the Paladin CSS layer
/// against a single source of truth.
#[must_use]
pub fn format_app_style_css_resource_path() -> &'static str {
    "/org/tamx/Paladin/Gui/style.css"
}

/// Bare widget binding name the view! macro assigns to the
/// `adw::ToastOverlay` wrapping every active screen.
///
/// Returns the static widget name `"toast_overlay"` — used both as
/// the relm4 `#[name = "…"]` binding inside [`AppModel`]'s view!
/// macro and as the GTK widget name (via `set_widget_name`) so
/// future selectors / accessibility queries can resolve the overlay
/// through a single source of truth. The overlay's child is the
/// `content` `gtk::Box` per-state controllers append into, so
/// state transitions (`InitDialog` → `AccountListComponent`,
/// `UnlockComponent` → `AccountListComponent`, etc.) never lose
/// pending toasts — the overlay is mounted once and survives every
/// child swap.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from the `content` binding the per-state controllers append
/// into; the toast overlay is the parent of `content`, never the
/// child.
#[must_use]
pub fn format_app_toast_overlay_widget_name() -> &'static str {
    "toast_overlay"
}

/// Compiled gresource bundle bytes embedded at build time.
///
/// `build.rs` invokes `glib_build_tools::compile_resources` to pack
/// `data/paladin-gtk.gresource.xml` (which references
/// `data/style.css` and, in subsequent commits, the placeholder
/// icon and any `*.ui` templates) into
/// `OUT_DIR/paladin-gtk.gresource`. The `include_bytes!` macro
/// pulls the resulting binary blob into the crate so
/// [`register_app_gresource_bundle`] can register it without
/// depending on the gresource file existing on disk at runtime —
/// crucial for the Flatpak / `AppImage` builds where the binary is
/// the only artifact shipped.
const APP_GRESOURCE_BUNDLE_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/paladin-gtk.gresource"));

/// Hand the compiled gresource bundle to the process-wide `gio`
/// resource pool so subsequent `gtk::CssProvider::load_from_resource`
/// / `gio::resources_lookup_data` calls resolve the bundled
/// `data/style.css` payload (and, in subsequent commits, the
/// placeholder icon and `*.ui` templates).
///
/// Called once from [`crate::run`] at startup, before
/// [`wire_app_css_provider`] attaches the `CssProvider` to the
/// default display. Internally builds a `glib::Bytes` view over
/// [`APP_GRESOURCE_BUNDLE_BYTES`] (no copy), constructs a
/// `gio::Resource` from those bytes, and calls
/// `gio::resources_register`. A double-registration would be a
/// programming error (the bundle is only registered from `run`),
/// but `gio` tolerates duplicate registrations so the function
/// stays idempotent in practice.
///
/// Sibling of [`wire_app_css_provider`] on the CSS-attach side and
/// [`format_app_style_css_resource_path`] on the gresource-path
/// side; together they pin the three halves of the Paladin CSS
/// layer (bundle bytes, resource path, `CssProvider` attach) against
/// a single source of truth.
///
/// # Panics
///
/// Panics if `gio::Resource::from_data` rejects the embedded
/// bytes. The bytes are produced deterministically by
/// `glib_build_tools::compile_resources` at build time, so any
/// rejection indicates a tooling regression rather than a runtime
/// failure mode.
pub fn register_app_gresource_bundle() {
    use gtk::gio;
    use gtk::glib;

    let bytes = glib::Bytes::from_static(APP_GRESOURCE_BUNDLE_BYTES);
    let resource = gio::Resource::from_data(&bytes)
        .expect("paladin-gtk gresource bundle bytes must be valid GResource format");
    gio::resources_register(&resource);
}

/// Layer Paladin's CSS on top of the Adwaita stylesheet for
/// `display`.
///
/// Builds a fresh `gtk::CssProvider`, loads
/// `data/style.css` from the registered gresource bundle via
/// [`format_app_style_css_resource_path`], and attaches it to
/// `display` at
/// `gtk::STYLE_PROVIDER_PRIORITY_APPLICATION` so the application-
/// specific tweaks override generic theme rules without re-skinning
/// the Adwaita palette per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Window shell and toast surface".
///
/// [`register_app_gresource_bundle`] must run before this helper so
/// the gresource pool can resolve the CSS path; otherwise the
/// `CssProvider` load is a silent no-op and the Adwaita defaults
/// stand alone. [`crate::run`] orders the two calls correctly at
/// startup.
///
/// Sibling of [`register_app_gresource_bundle`] on the gresource
/// side and [`format_app_style_css_resource_path`] on the path
/// side; together they pin the three halves of the Paladin CSS
/// layer (bundle bytes, resource path, `CssProvider` attach) against
/// a single source of truth.
pub fn wire_app_css_provider(display: &gtk::gdk::Display) {
    let provider = gtk::CssProvider::new();
    provider.load_from_resource(format_app_style_css_resource_path());
    gtk::style_context_add_provider_for_display(
        display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

/// Absolute gresource path to the Paladin-bundled icon-theme root.
///
/// Returns the static absolute resource path
/// `"/org/tamx/Paladin/Gui/icons"`. The prefix segments
/// (`org` / `tamx` / `Paladin` / `Gui`) mirror [`crate::APP_ID`]
/// (`"org.tamx.Paladin.Gui"`) split on `.` so the resource pool
/// namespaces by reverse-DNS app ID and never collides with other
/// gresource-shipping apps in the same process. The terminal
/// `icons` segment plays the role of the icon-theme root the
/// freedesktop spec / `gtk::IconTheme::add_resource_path` consume,
/// with `<root>/scalable/actions/<name>.svg` and the matching
/// pixel-size paths discovered beneath it.
///
/// Pure — returns a `'static str` without allocating. Companion of
/// [`register_app_gresource_bundle`] (which hands the compiled
/// gresource bytes to `gio::resources_register` so this root
/// resolves at runtime),
/// [`format_app_placeholder_icon_resource_path`] (which spells the
/// full path of the bundled placeholder symbolic), and
/// [`wire_app_icon_theme_resource_path`] (which adds this root to
/// the `gtk::IconTheme` for a given display); together they pin
/// the gresource side of the Paladin icon-theme layer against a
/// single source of truth.
#[must_use]
pub fn format_app_icon_theme_resource_path() -> &'static str {
    "/org/tamx/Paladin/Gui/icons"
}

/// Absolute gresource path to the bundled placeholder symbolic icon.
///
/// Returns the static absolute resource path
/// `"/org/tamx/Paladin/Gui/icons/scalable/actions/dialog-password-symbolic.svg"`.
/// The filename matches
/// [`crate::icon_resolution::PLACEHOLDER_ICON_NAME`] so the
/// `gtk::IconTheme` lookup the row factory performs by that
/// constant resolves to this bundled payload instead of the
/// (potentially missing) system symbolic. The directory shape
/// (`scalable/actions/<name>.svg`) is the freedesktop icon-theme
/// layout consumed by `gtk::IconTheme::add_resource_path`.
///
/// Pure — returns a `'static str` without allocating. Companion of
/// [`format_app_icon_theme_resource_path`] (which is the prefix
/// `wire_app_icon_theme_resource_path` registers) and the bundled
/// `data/icons/scalable/actions/dialog-password-symbolic.svg`
/// payload itself.
#[must_use]
pub fn format_app_placeholder_icon_resource_path() -> &'static str {
    "/org/tamx/Paladin/Gui/icons/scalable/actions/dialog-password-symbolic.svg"
}

/// Add the gresource-bundled icon-theme root to `display`'s
/// `gtk::IconTheme`.
///
/// Resolves the `gtk::IconTheme` for `display` and calls
/// `add_resource_path` with [`format_app_icon_theme_resource_path`]
/// so subsequent lookups by name (notably the `bind_row_icon`
/// fallback to [`crate::icon_resolution::PLACEHOLDER_ICON_NAME`])
/// discover the bundled SVGs through the standard freedesktop
/// directory layout. Distributions whose icon theme omits
/// `dialog-password-symbolic` — Flatpak sandboxes in particular —
/// then resolve the placeholder against the embedded copy rather
/// than rendering an empty `gtk::Image`.
///
/// [`register_app_gresource_bundle`] must run before this helper so
/// the `gio::Resource` carrying
/// `format_app_placeholder_icon_resource_path()` is live in the
/// process-wide pool; otherwise the icon-theme path attach
/// succeeds but the icon lookup silently falls back to the system
/// theme. [`crate::run`] orders the two calls correctly at
/// startup.
///
/// Sibling of [`register_app_gresource_bundle`] on the gresource
/// side and [`format_app_icon_theme_resource_path`] on the path
/// side; together they pin the three halves of the Paladin
/// icon-theme layer (bundle bytes, resource path, `IconTheme`
/// attach) against a single source of truth.
pub fn wire_app_icon_theme_resource_path(display: &gtk::gdk::Display) {
    let theme = gtk::IconTheme::for_display(display);
    theme.add_resource_path(format_app_icon_theme_resource_path());
}

/// Convert the result of `gdk::Clipboard::read_texture_async` into
/// the typed payload for [`AppMsg::QrClipboardLoaded`].
///
/// Runs the four-step clipboard-QR preflight pipeline so the
/// `QrClipboardLoaded` arm in [`AppModel::update`] can route the
/// result through [`route_qr_clipboard_loaded`] without
/// re-implementing the GDK round trip:
///
/// 1. `Ok(None)` and any `glib::Error` project to
///    [`crate::qr_clipboard::QrPreflightError::NoClipboardImage`]
///    — the clipboard either has nothing on it or holds a
///    non-image payload that GDK could not decode.
/// 2. The texture's `(width, height)` are passed through
///    [`crate::qr_clipboard::classify_layout_preflight`] which
///    gates against the §5 [`paladin_core::QR_RGBA_MAX_BYTES`]
///    ceiling *before* allocation / download. Negative dimensions
///    (defensive: GDK contract forbids it) project to
///    [`crate::qr_clipboard::QrLayoutError::ZeroDimensions`].
/// 3. A `gdk::TextureDownloader` is configured with the
///    [`crate::qr_clipboard::clipboard_qr_memory_format`]
///    (`R8g8b8a8`, straight / non-premultiplied — the QR decoder
///    upstream requires it) and the bytes are pulled via
///    `download_bytes()`.
/// 4. [`crate::qr_clipboard::compose_qr_decode_outcome`] runs
///    `verify_download_layout` against the validated `RgbaLayout`
///    (rejecting GDK stride / length drift) before forwarding the
///    buffer to [`paladin_core::import::qr_image_bytes`];
///    [`crate::qr_clipboard::classify_qr_outcome`] filters the
///    empty-decoded-batch defensive case.
///
/// The helper touches `gdk::TextureDownloader` so it is not unit-
/// tested without a display; every preflight step it composes is
/// pinned by pure-logic tests in `tests/qr_clipboard_logic.rs`.
fn load_clipboard_qr_capture(
    result: Result<Option<gtk::gdk::Texture>, glib::Error>,
    import_time: SystemTime,
) -> std::result::Result<Vec<paladin_core::ValidatedAccount>, crate::qr_clipboard::QrPreflightError>
{
    use crate::qr_clipboard::{
        classify_layout_preflight, classify_qr_outcome, clipboard_qr_memory_format,
        compose_qr_decode_outcome, QrLayoutError, QrPreflightError,
    };

    let Ok(Some(texture)) = result else {
        return Err(QrPreflightError::NoClipboardImage);
    };
    let width = u32::try_from(texture.width())
        .map_err(|_| QrPreflightError::LayoutRejected(QrLayoutError::ZeroDimensions))?;
    let height = u32::try_from(texture.height())
        .map_err(|_| QrPreflightError::LayoutRejected(QrLayoutError::ZeroDimensions))?;
    let layout = classify_layout_preflight(width, height)?;
    let mut downloader = gtk::gdk::TextureDownloader::new(&texture);
    downloader.set_format(clipboard_qr_memory_format());
    let (bytes, stride) = downloader.download_bytes();
    classify_qr_outcome(compose_qr_decode_outcome(
        &layout,
        bytes.as_ref(),
        stride,
        import_time,
    ))
}
