// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-tui` binary entry point. See
//! `docs/IMPLEMENTATION_PLAN_03_TUI.md` and `docs/DESIGN.md` §6.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    paladin_tui::run()
}
