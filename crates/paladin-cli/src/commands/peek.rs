// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin peek <query>` — print the current code without advancing HOTP.
//! See DESIGN.md §5. Stub.

use crate::cli::{GlobalArgs, QueryArgs};
use crate::output::error::CliError;

pub fn run(_global: &GlobalArgs, _args: &QueryArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("peek"))
}
