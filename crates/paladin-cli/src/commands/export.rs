// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin export` — write the vault to a file (`--plaintext` or
//! `--encrypted`). Refuses overwrite without `--force`; output is always
//! mode 0600. See DESIGN.md §5. Stub.

use crate::cli::{ExportArgs, GlobalArgs};
use crate::CliError;

pub fn run(_global: &GlobalArgs, _args: &ExportArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("export"))
}
