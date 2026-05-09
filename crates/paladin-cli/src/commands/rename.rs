// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin rename <query> <new-label>` — rename an account; updates
//! `updated_at`. See DESIGN.md §5. Stub.

use crate::cli::{GlobalArgs, RenameArgs};
use crate::output::error::CliError;

pub fn run(_global: &GlobalArgs, _args: &RenameArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("rename"))
}
