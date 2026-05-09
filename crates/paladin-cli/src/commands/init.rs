// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin init` — create a new vault. See DESIGN.md §5 and
//! `IMPLEMENTATION_PLAN_02_CLI.md`. Stub.

use crate::cli::{GlobalArgs, InitArgs};
use crate::CliError;

pub fn run(_global: &GlobalArgs, _args: &InitArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("init"))
}
