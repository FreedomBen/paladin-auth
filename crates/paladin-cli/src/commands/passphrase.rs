// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin passphrase {set,change,remove}` — vault passphrase transitions.
//! See DESIGN.md §5. Stubs.

use crate::cli::{GlobalArgs, KdfArgs};
use crate::output::error::CliError;

pub fn set(_global: &GlobalArgs, _kdf: &KdfArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("passphrase set"))
}

pub fn change(_global: &GlobalArgs, _kdf: &KdfArgs) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("passphrase change"))
}

pub fn remove(_global: &GlobalArgs, _yes: bool) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("passphrase remove"))
}
