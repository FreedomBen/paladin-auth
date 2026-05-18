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
    /// Forwarded from the live [`AddAccountComponent`] when the
    /// user interacts with the dialog. Today only
    /// [`AddAccountOutput::Cancel`] is emitted — `AppModel`
    /// responds by dropping the controller and removing the dialog
    /// widget from the content tree. Submit / worker outputs land
    /// in follow-up commits alongside the editable form widgets.
    AddAccountAction(AddAccountOutput),
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
            set_default_size: (640, 480),

            #[wrap(Some)]
            set_content = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[name = "add_button"]
                    pack_start = &gtk::Button {
                        set_icon_name: format_app_add_button_icon_name(),
                        set_tooltip_text: Some(format_app_add_button_tooltip()),
                        // Initial visibility tracks the resolved
                        // startup state. Subsequent state changes
                        // (Unlocked → UnlockedBusy → Unlocked,
                        // auto-lock, etc.) toggle visibility via
                        // `apply_add_button_visibility_inplace`
                        // wired in the post-init dispatch
                        // handlers. The `+` is hidden outside
                        // `Unlocked` so users cannot trigger an
                        // `OpenAddDialog` race against a missing /
                        // locked / busy vault.
                        set_visible: state.is_unlocked(),
                        connect_clicked[sender] => move |_| {
                            sender.input(AppMsg::OpenAddDialog);
                        },
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
