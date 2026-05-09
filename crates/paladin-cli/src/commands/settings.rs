// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin settings {get,set}` — read or modify vault settings. Settings
//! keys and bounds come from `paladin_core::parse_setting_patch` /
//! `parse_setting_key` (DESIGN.md §5). Stubs.

use crate::cli::GlobalArgs;
use crate::CliError;

pub fn get(_global: &GlobalArgs, _key: Option<&str>) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("settings get"))
}

pub fn set(_global: &GlobalArgs, _key: &str, _value: &str) -> Result<(), CliError> {
    Err(CliError::NotYetImplemented("settings set"))
}
