// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clap argument tree for the `paladin-gtk` binary.
//!
//! See `DESIGN.md` §5 and `IMPLEMENTATION_PLAN_04_GTK.md` "Global
//! flags". Parity with the CLI and TUI siblings is limited to
//! `--vault <PATH>` (overrides the default vault location) and
//! `--no-color` (accepted for parity; a parser-level no-op in the
//! GUI because theming is delegated to Adwaita / the system theme
//! and there is no ANSI palette to disable).
//!
//! `paladin-gtk` has no JSON output mode: `--json` is intentionally
//! not a defined flag, so clap surfaces its standard "unexpected
//! argument" text diagnostic and the GUI never emits a JSON
//! envelope. There is no positional file or URI argument either —
//! imports start from `ImportDialog`, never from argv.
//!
//! The hidden `--exit-after-startup` flag exists solely for
//! `tests/gtk_smoke.rs`: it lets the smoke test exercise the
//! libadwaita / relm4 bootstrap under `xvfb-run` and still return
//! cleanly without a real desktop session to dismiss the window.
//! It is not documented in `--help` (`hide = true`) so end users do
//! not see it.

use std::path::PathBuf;

use clap::Parser;

/// Top-level arguments accepted by `paladin-gtk`.
#[derive(Debug, Parser)]
#[command(
    name = "paladin-gtk",
    version,
    about = "Paladin GTK: Rust OTP authenticator (TOTP + HOTP)"
)]
pub struct GlobalArgs {
    /// Path to vault file (overrides the default location).
    #[arg(long, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Accepted for parity with the CLI / TUI; a parser-level no-op.
    #[arg(long)]
    pub no_color: bool,

    /// Hidden smoke-test flag: enqueue `AppMsg::Quit` on first
    /// frame so the relm4 main loop exits without a desktop
    /// session to dismiss the window. Wired by
    /// `tests/gtk_smoke.rs`; suppressed from `--help`.
    #[arg(long, hide = true)]
    pub exit_after_startup: bool,
}
