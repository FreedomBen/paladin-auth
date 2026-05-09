// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin list` — print account metadata (no codes). See DESIGN.md §5. Stub.

use crate::cli::GlobalArgs;
use crate::CliError;

pub fn run(_global: &GlobalArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("list"))
}
