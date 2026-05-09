// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin add` — add an account interactively, from `--uri`, manual flags,
//! or `--qr`. See DESIGN.md §5 and `IMPLEMENTATION_PLAN_02_CLI.md` "Add modes".
//! Stub.

use crate::cli::{AddArgs, GlobalArgs};
use crate::output::error::CliError;

pub fn run(_global: &GlobalArgs, _args: &AddArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("add"))
}
