// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-gtk` library surface.
//!
//! See `IMPLEMENTATION_PLAN_04_GTK.md` and `DESIGN.md` §7. The binary
//! at `src/main.rs` is a thin shim that hands off to [`run`]; all
//! presentation logic lives in submodules so the pure-logic helpers
//! (search, icon resolution, auto-lock, clipboard-clear, HOTP reveal,
//! dialog state machines, …) can be exercised by integration tests in
//! `tests/` without spinning up GTK or libadwaita.
//!
//! The crate intentionally re-exports nothing from `paladin_core`;
//! callers go through `paladin_core::*` directly. The §"Thinness
//! contract" of the plan forbids re-implementing crypto, storage,
//! import/export, or OTP primitives here.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::process::ExitCode;

pub mod auto_lock;
pub mod clipboard_clear;
pub mod export_dialog;
pub mod hotp_reveal;
pub mod icon_resolution;
pub mod import_dialog;
pub mod init_dialog;
pub mod otpauth_uri_paste;
pub mod qr_clipboard;
pub mod rename_dialog;
pub mod search;
pub mod secret_fields;
pub mod startup_error;

/// Run the `paladin-gtk` binary.
///
/// Milestone 7 scaffold per `IMPLEMENTATION_PLAN_04_GTK.md`: returns
/// success without launching a GTK application yet. The real entry
/// (`adw::init`, gresource registration, `RelmApp::new` with the
/// `org.tamx.Paladin.Gui` app ID) is wired in subsequent commits.
#[must_use]
pub fn run() -> ExitCode {
    ExitCode::SUCCESS
}
