// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin remove <query>` — remove an account; confirmation prompt unless
//! `--yes`. See DESIGN.md §5. Stub.

use crate::cli::{GlobalArgs, RemoveArgs};
use crate::output::error::CliError;

pub fn run(_global: &GlobalArgs, _args: &RemoveArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("remove"))
}
