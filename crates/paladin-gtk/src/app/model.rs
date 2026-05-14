// SPDX-License-Identifier: AGPL-3.0-or-later

//! Widget-bearing `AppModel` for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree", `AppModel`
//! is the relm4 root component that mounts the libadwaita
//! application window and routes the active child view by
//! [`crate::app::state::AppState`].
//!
//! This commit lands the skeleton only: an
//! `adw::ApplicationWindow` with an empty content slot plus an
//! `AppMsg::Quit` handler that calls
//! `relm4::main_application().quit()`. Subsequent commits will
//!
//! * run the startup probes
//!   (`paladin_core::default_vault_path` → `paladin_core::inspect`
//!   → optional plaintext `paladin_core::open`) and seed
//!   [`AppModel::state`] from them, and
//! * mount the per-`AppState` child components (`InitDialog`,
//!   `UnlockComponent`, `AccountListComponent`,
//!   `StartupErrorComponent`).
//!
//! The skeleton respects the hidden `--exit-after-startup` flag by
//! enqueueing [`AppMsg::Quit`] right after the widgets mount, so
//! `tests/gtk_smoke.rs` can exercise the libadwaita / relm4
//! bootstrap under `xvfb-run` and still return cleanly without a
//! real desktop session to dismiss the window.

use std::path::PathBuf;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use crate::app::state::AppState;

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

/// Top-level relm4 component for `paladin-gtk`.
///
/// Owns the resolved vault path plus the [`AppState`] that drives
/// which child view is rendered. The skeleton leaves both fields
/// inert; the follow-up commit that adds the startup-routing probes
/// will populate them.
#[derive(Debug)]
pub struct AppModel {
    /// Vault path override from [`AppInit`]. Consumed by the
    /// startup-routing probes in a follow-up commit.
    #[allow(dead_code)]
    vault_path: Option<PathBuf>,
    /// Cached `AppState` for the routed view. The skeleton leaves
    /// it `None`; the follow-up startup-routing commit seeds it.
    #[allow(dead_code)]
    state: Option<AppState>,
}

/// Messages handled by [`AppModel`].
#[derive(Debug)]
pub enum AppMsg {
    /// Tear down the GTK main loop. Routed through
    /// `relm4::main_application().quit()` so any pending `GLib`
    /// idle callbacks see the shutdown rather than being dropped
    /// mid-flight.
    Quit,
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
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let exit_after_startup = init.exit_after_startup;
        let model = AppModel {
            vault_path: init.vault_path,
            state: None,
        };
        let widgets = view_output!();

        if exit_after_startup {
            sender.input(AppMsg::Quit);
        }

        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _sender: ComponentSender<Self>) {
        match msg {
            AppMsg::Quit => relm4::main_application().quit(),
        }
    }
}
