// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin import` — import accounts from a file. Auto-detects format when
//! `--format` is omitted; conflict policies are `skip` (default), `replace`,
//! `append`. See DESIGN.md §5. Stub.

use crate::cli::{GlobalArgs, ImportArgs};
use crate::output::error::CliError;

pub fn run(_global: &GlobalArgs, _args: &ImportArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("import"))
}
