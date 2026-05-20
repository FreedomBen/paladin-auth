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

use std::path::PathBuf;
use std::time::SystemTime;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use crate::account_list::{
    format_rendered_marker, format_widget_states_marker, hidden_row_display, row_models_from_vault,
    AccountListComponent, AccountListInit, AccountListOutput, AccountRowModel,
};
use crate::add_account::{
    run_add_worker, AddAccountComponent, AddAccountInit, AddAccountOutput, AddWorkerCompletion,
};
use crate::app::state::{
    apply_add_dispatch_inplace, apply_add_vault_install_inplace, apply_remove_dispatch_inplace,
    apply_remove_vault_install_inplace, apply_rename_dispatch_inplace,
    apply_rename_vault_install_inplace, apply_submit_add_inplace, apply_submit_remove_inplace,
    apply_submit_rename_inplace, apply_submit_unlock_inplace, apply_unlock_dispatch_inplace,
    apply_unlock_vault_install_inplace, compose_add_dispatch, compose_add_worker_input,
    compose_remove_dispatch, compose_remove_worker_input, compose_rename_dispatch,
    compose_rename_worker_input, compose_unlock_dispatch, compose_unlock_worker_input,
    decide_state_from_inspect, decide_state_from_open_error, run_unlock_worker, AppState,
    OpenErrorOutcome, UnlockWorkerCompletion,
};
use crate::init_dialog::{format_init_dialog_marker, InitDialogComponent, InitDialogInit};
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
};
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
            .field("content", &"<gtk::Box>")
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
                    },
                },

                #[wrap(Some)]
                set_content = &gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,

                    #[name = "content"]
                    append = &gtk::Box {
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
                .launch(AccountListInit { rows })
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
                .detach();
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
                .detach();
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
            content: widgets.content.clone(),
        };

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
            AppMsg::Quit => relm4::main_application().quit(),
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
                // benign race and drop the action.
                if let Some((vault, _store)) = self.vault.as_ref() {
                    if let Some(init) = decide_remove_target(vault, id) {
                        let controller = RemoveDialogComponent::builder()
                            .launch(init)
                            .forward(sender.input_sender(), AppMsg::RemoveDialogAction);
                        self.content.append(controller.widget());
                        self.remove_dialog = Some(controller);
                    }
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
                // Detach the dialog widget from the content tree and
                // drop the controller. Defensive: if the field is
                // already `None` (controller swapped under us by a
                // future race), this is a benign no-op.
                if let Some(controller) = self.remove_dialog.take() {
                    self.content.remove(controller.widget());
                }
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
            AppMsg::OpenImportDialog | AppMsg::OpenExportDialog | AppMsg::OpenPassphraseDialog => {
                // Mutating menu activations whose dispatch
                // edges (action → AppMsg) have landed but
                // whose widget-bearing dialog components have
                // not yet. Each variant becomes its own arm
                // with a distinct handler when the matching
                // `ImportDialogComponent` / `ExportDialogComponent`
                // / `PassphraseDialogComponent` mount lands in
                // follow-up commits.
                //
                // Defense in depth: every variant in the
                // combined arm is gated by
                // `format_app_primary_menu_action_sensitivities`'s
                // mutating-menu rule
                // (`AppState::allows_mutating_menu` →
                // `Unlocked` only); a stray dispatch from a
                // future keyboard accelerator that lands in
                // any other state is the benign no-op below.
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
            AppMsg::AddAccountAction(AddAccountOutput::Cancel) => {
                // Detach the dialog widget from the content tree and
                // drop the controller. Defensive: if the field is
                // already `None` (controller swapped under us by a
                // future race), this is a benign no-op.
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
                        if let Some(controller) = self.remove_dialog.take() {
                            self.content.remove(controller.widget());
                        }
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
                }
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
                }
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
