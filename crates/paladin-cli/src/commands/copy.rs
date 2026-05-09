// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin copy <query>` — copy the current code to the clipboard via
//! `arboard`. Advances HOTP and persists *before* writing to the clipboard
//! (DESIGN.md §5 "deliberate HOTP side-effect order"). No auto-clear; the
//! CLI ignores `clipboard.clear_enabled`. Stub.

use crate::cli::{GlobalArgs, QueryArgs};
use crate::output::error::CliError;

pub fn run(_global: &GlobalArgs, _args: &QueryArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("copy"))
}
