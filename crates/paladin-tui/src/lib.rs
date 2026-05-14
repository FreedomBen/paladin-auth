// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-tui` library surface.
//!
//! See `IMPLEMENTATION_PLAN_03_TUI.md` and `DESIGN.md` §6. The binary
//! at `src/main.rs` is a thin shim that hands off to [`run`]; everything
//! else lives in submodules so the reducer / state-machine and helpers
//! can be exercised by integration tests in `tests/` without going
//! through a terminal.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::process::ExitCode;

pub mod app;
pub mod cli;
pub mod clipboard;
pub mod prompt;
pub mod search;
pub mod terminal;

/// Run the `paladin-tui` binary.
///
/// Phase 1 scaffold: parses [`cli::GlobalArgs`] and exits. The full
/// terminal lifecycle, reducer, and event loop are wired in subsequent
/// implementation phases per `IMPLEMENTATION_PLAN_03_TUI.md`.
#[must_use]
pub fn run() -> ExitCode {
    use clap::Parser;

    match cli::GlobalArgs::try_parse() {
        Ok(_args) => ExitCode::SUCCESS,
        // `Error::exit` writes clap's text diagnostic / help / version
        // output and exits with the appropriate code (`2` for usage
        // errors, `0` for `--help` / `--version`). Never returns.
        Err(err) => err.exit(),
    }
}
