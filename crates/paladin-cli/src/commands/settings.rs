// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin settings {get,set}` — read or modify vault settings. See
//! DESIGN.md §5 and `IMPLEMENTATION_PLAN_02_CLI.md` "Settings keys" /
//! "Vault interaction pattern".
//!
//! Order of operations:
//!
//! 1. Resolve the output mode and vault path.
//! 2. Open the vault through the shared pipeline (no prompt for
//!    plaintext, single passphrase prompt for encrypted).
//! 3. For `get`: parse the optional dotted key through
//!    `paladin_core::parse_setting_key` so an unknown key rejects with
//!    the same `validation_error` shape as `set`. Render the current
//!    settings — full `VaultSettings` under `--json` (dotted key names
//!    never appear on the JSON wire), filtered or full text-mode
//!    output otherwise.
//! 4. For `set`: parse the dotted key/value pair through
//!    `paladin_core::parse_setting_patch`, then apply the result through
//!    `Vault::apply_setting_patch` inside `Vault::mutate_and_save` so
//!    the post-mutation state is persisted before rendering. Render
//!    the post-mutation `VaultSettings` (same JSON shape as `get`) so
//!    callers can confirm the value landed.

use paladin_core::{parse_setting_key, parse_setting_patch, PaladinError};

use crate::cli::GlobalArgs;
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::vault_open;

pub fn get(global: &GlobalArgs, key: Option<&str>) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    // Validate the optional dotted key *before* opening the vault so
    // an unknown key never triggers a passphrase prompt. The parsed
    // value is only used in text mode for filtered output; under
    // `--json` the full nested settings object is always returned.
    let parsed_key = match key {
        Some(k) => Some(parse_setting_key(k)?),
        None => None,
    };

    let path = vault_open::resolve_vault_path(global)?;
    let opened = vault_open::open(&path)?;
    let settings = opened.vault.settings();

    match mode {
        Mode::Json => {
            output::json::write_settings(settings, std::io::stdout().lock()).map_err(io_err)?;
        }
        Mode::Text { .. } => match parsed_key {
            Some(k) => {
                output::text::write_settings_one(k, settings, std::io::stdout().lock())
                    .map_err(io_err)?;
            }
            None => {
                output::text::write_settings_all(settings, std::io::stdout().lock())
                    .map_err(io_err)?;
            }
        },
    }
    Ok(())
}

pub fn set(global: &GlobalArgs, key: &str, value: &str) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    // Parse + validate the patch *before* opening the vault: unknown
    // keys, malformed values, and out-of-range numbers should reject
    // before any passphrase prompt fires.
    let patch = parse_setting_patch(key, value)?;

    let vault_path = vault_open::resolve_vault_path(global)?;
    let mut opened = vault_open::open(&vault_path)?;

    opened
        .vault
        .mutate_and_save(&opened.store, |vault| vault.apply_setting_patch(patch))?;

    let settings = opened.vault.settings();
    match mode {
        Mode::Json => {
            output::json::write_settings(settings, std::io::stdout().lock()).map_err(io_err)?;
        }
        Mode::Text { .. } => {
            output::text::write_settings_all(settings, std::io::stdout().lock()).map_err(io_err)?;
        }
    }
    Ok(())
}

fn io_err(source: std::io::Error) -> CliError {
    CliError::Paladin(PaladinError::IoError {
        operation: "write_stdout",
        source,
    })
}
