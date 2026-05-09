// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin tui` exec wrapper: resolves `paladin-tui` on `PATH` and `execvp`s
//! it, forwarding `--vault` and `--no-color` verbatim. See
//! `IMPLEMENTATION_PLAN_02_CLI.md` "`paladin tui` exec wrapper". Stub; the
//! real exec wiring lands with the matching command body.

use crate::cli::GlobalArgs;
use crate::output::error::CliError;

pub fn run(_global: &GlobalArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("tui"))
}
