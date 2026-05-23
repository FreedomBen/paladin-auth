// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-gtk` library surface.
//!
//! See `docs/IMPLEMENTATION_PLAN_04_GTK.md` and `docs/DESIGN.md` §7. The binary
//! at `src/main.rs` is a thin shim that hands off to [`run`]; all
//! presentation logic lives in submodules so the pure-logic helpers
//! (search, icon resolution, auto-lock, clipboard wiring, clipboard-clear
//! policy, HOTP reveal, dialog state machines, …) can be exercised by
//! integration tests in `tests/` without spinning up GTK or libadwaita.
//!
//! The crate intentionally re-exports nothing from `paladin_core`;
//! callers go through `paladin_core::*` directly. The §"Thinness
//! contract" of the plan forbids re-implementing crypto, storage,
//! import/export, or OTP primitives here.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::process::ExitCode;

pub mod account_list;
pub mod account_row;
pub mod add_account;
pub mod app;
pub mod auto_lock;
pub mod cli;
pub mod clipboard;
pub mod clipboard_clear;
pub mod column_view;
pub mod effect_ownership;
pub mod export_dialog;
pub mod gsettings;
pub mod hotp_reveal;
pub mod icon_resolution;
pub mod import_dialog;
pub mod init_dialog;
pub mod otpauth_uri_paste;
pub mod passphrase_dialog;
pub mod qr_clipboard;
pub mod remove_dialog;
pub mod rename_dialog;
pub mod row_item;
pub mod search;
pub mod secret_fields;
pub mod settings;
pub mod shortcuts_window;
pub mod startup_error;
pub mod ticker;
pub mod unlock_dialog;

/// Stable application identifier per §"Linux desktop integration" /
/// §"Packaging". Must stay in lockstep with the desktop file's
/// `StartupWMClass`, the `AppStream` `<id>`, the icon-theme key,
/// and the §11.4 Flatpak `app-id`, so a window opened by this
/// binary is correctly grouped with its launcher entry across
/// native packages, Flatpak, and `AppImage`.
pub const APP_ID: &str = "org.tamx.Paladin.Gui";

/// Run the `paladin-gtk` binary.
///
/// Milestone 7 foundation per `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
/// parse [`cli::GlobalArgs`], initialize libadwaita, construct the
/// relm4 [`RelmApp`](relm4::RelmApp) around [`app::model::AppModel`],
/// and run the main loop. The hidden `--exit-after-startup` flag
/// (wired by `tests/gtk_smoke.rs`) enqueues `AppMsg::Quit` on the
/// first frame so the smoke test can exercise the libadwaita /
/// relm4 bootstrap under `xvfb-run` without a real desktop session
/// to dismiss the window. Subsequent commits expand `AppModel`
/// with startup-routing probes (`default_vault_path` → `inspect`
/// → optional plaintext `open`) and the per-`AppState` child
/// components.
#[must_use]
pub fn run() -> ExitCode {
    use clap::Parser;
    use relm4::RelmApp;

    let args = match cli::GlobalArgs::try_parse() {
        Ok(args) => args,
        // `Error::exit` writes clap's text diagnostic / help / version
        // output and exits with the appropriate code (`2` for usage
        // errors, `0` for `--help` / `--version`). Never returns.
        Err(err) => err.exit(),
    };

    // `libadwaita::init` internally drives `gtk::init` plus the
    // Adwaita stylesheet bootstrap. It needs a live display server;
    // the §"Smoke test" `xvfb-run` wrapper supplies one in CI, and
    // graphical sessions supply one for normal launches. Propagate
    // failure as a clean exit code rather than a panic so packagers
    // and users see a readable diagnostic.
    if let Err(err) = libadwaita::init() {
        eprintln!("paladin-gtk: failed to initialize libadwaita: {err}");
        return ExitCode::FAILURE;
    }

    // Register the build-time gresource bundle on the process-wide
    // `gio` resource pool before any consumer (`wire_app_css_provider`
    // here; future widget `gtk::Builder::from_resource` /
    // `gtk::Image::from_resource` call sites) looks up a payload at
    // `/org/tamx/Paladin/Gui/...` per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Window shell and toast surface".
    app::model::register_app_gresource_bundle();

    // Layer Paladin's `data/style.css` on top of the Adwaita
    // stylesheet via `gtk::CssProvider` against the default display,
    // and register the bundled icon-theme root with `gtk::IconTheme`
    // so the row-factory placeholder symbolic
    // (`icon_resolution::PLACEHOLDER_ICON_NAME`) resolves identically
    // in native and Flatpak builds per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Icon resolution". Adwaita owns the base palette / colors /
    // widget styles; the CSS layer only adds the Paladin-specific
    // tweaks the v0.2 GUI needs and never re-skins the Adwaita
    // palette.
    if let Some(display) = relm4::gtk::gdk::Display::default() {
        app::model::wire_app_css_provider(&display);
        app::model::wire_app_icon_theme_resource_path(&display);
    } else {
        eprintln!(
            "paladin-gtk: no default GDK display available; skipping Paladin CSS layer and bundled icon-theme attach (Adwaita defaults still apply)",
        );
    }

    let init = app::model::AppInit {
        vault_path: args.vault,
        exit_after_startup: args.exit_after_startup,
    };

    RelmApp::new(APP_ID).run::<app::model::AppModel>(init);

    ExitCode::SUCCESS
}
