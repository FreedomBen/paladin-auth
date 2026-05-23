// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clap argument tree for the `paladin-tui` binary.
//!
//! See `docs/DESIGN.md` §6 and `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Global flags".
//! `paladin-tui` has no JSON mode: `--json` is rejected at parse time
//! with clap's text diagnostic — the flag is intentionally not defined,
//! so clap surfaces its standard "unexpected argument" error and never
//! emits a JSON envelope.

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Parser;

/// Top-level arguments accepted by `paladin-tui`.
#[derive(Debug, Parser)]
#[command(
    name = "paladin-tui",
    version,
    about = "Paladin TUI: Rust OTP authenticator (TOTP + HOTP)"
)]
pub struct GlobalArgs {
    /// Path to vault file (overrides the default location).
    #[arg(long, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Disable ANSI color styling.
    #[arg(long)]
    pub no_color: bool,
}

/// Decide whether color styling should be disabled.
///
/// Disabled if either the explicit `--no-color` flag is set or the
/// `NO_COLOR` environment variable is present. Per
/// <https://no-color.org/>, presence alone disables — value (including
/// the empty string) is ignored.
#[must_use]
pub fn should_disable_color(no_color_flag: bool, no_color_env: Option<&OsStr>) -> bool {
    no_color_flag || no_color_env.is_some()
}
