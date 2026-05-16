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
//! entry surface seeded with the resolved vault path. The full
//! passphrase-entry / `gio::spawn_blocking` `paladin_core::open`
//! worker wiring for `UnlockDialogComponent` lands in follow-up
//! commits.
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

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use crate::account_list::{
    format_rendered_marker, format_widget_states_marker, hidden_row_display, row_models_from_vault,
    AccountListComponent, AccountListInit, AccountListOutput, AccountRowModel,
};
use crate::app::state::{
    apply_submit_unlock_inplace, decide_state_from_inspect, decide_state_from_open_error, AppState,
    OpenErrorOutcome,
};
use crate::init_dialog::{format_init_dialog_marker, InitDialogComponent, InitDialogInit};
use crate::remove_dialog::{decide_remove_target, RemoveDialogComponent, RemoveDialogOutput};
use crate::rename_dialog::{decide_rename_target, RenameDialogComponent, RenameDialogOutput};
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
            set_title: Some("Paladin"),
            set_default_size: (640, 480),

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
            content: widgets.content.clone(),
        };

        if exit_after_startup {
            sender.input(AppMsg::Quit);
        }

        ComponentParts { model, widgets }
    }

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
            AppMsg::RemoveDialogAction(RemoveDialogOutput::Cancel) => {
                // Detach the dialog widget from the content tree and
                // drop the controller. Defensive: if the field is
                // already `None` (controller swapped under us by a
                // future race), this is a benign no-op.
                if let Some(controller) = self.remove_dialog.take() {
                    self.content.remove(controller.widget());
                }
            }
            AppMsg::UnlockDialogAction(UnlockDialogOutput::SubmitLock(_lock)) => {
                // Pre-worker state transition: `Locked → UnlockedBusy`.
                // `apply_submit_unlock_inplace` runs the typed entry-
                // side composer over `AppModel::state`, opening the
                // busy gate so `is_busy()` /
                // `allows_mutating_menu()` cover the open worker's
                // lifetime per `IMPLEMENTATION_PLAN_04_GTK.md`
                // §"Vault interaction". The dialog stays mounted —
                // `should_drop_unlock_dialog_after` keeps it on the
                // inline branch and the worker's success / startup-
                // failure dispatch drops it once the worker returns.
                //
                // The `gio::spawn_blocking paladin_core::open` worker
                // that consumes the forwarded `VaultLock` and the
                // `AppMsg::UnlockWorkerCompleted(UnlockWorkerEffect)`
                // dispatch that calls `compose_unlock_dispatch` on the
                // worker outcome land in follow-up commits.
                if let Some(state) = self.state.as_mut() {
                    apply_submit_unlock_inplace(state);
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
