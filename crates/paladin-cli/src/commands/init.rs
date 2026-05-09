// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin init` — create a new vault. See DESIGN.md §5 and
//! `IMPLEMENTATION_PLAN_02_CLI.md` "Vault interaction pattern" /
//! "Passphrase prompts".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Resolve the vault path (`--vault` or `default_vault_path()`).
//! 2. Parse + validate KDF flags. Errors here win over `vault_exists`,
//!    `unsafe_permissions`, and the new-passphrase prompt.
//! 3. `inspect(path)` → `classify_init_precheck`. Without `--force`,
//!    `Existing` returns `vault_exists` *before* prompting. With
//!    `--force`, text mode prints `format_init_force_warning(path)`
//!    before any prompt.
//! 4. Prompt once for the new vault passphrase. An empty first entry
//!    selects plaintext storage and prints
//!    `format_plaintext_storage_warning()` in text mode; otherwise the
//!    second confirmation entry must match byte-for-byte.
//! 5. Build the [`paladin_core::VaultInit`] and call [`Store::create`]
//!    (Clear) or [`Store::create_force`] (Existing-with-force).
//!    `Store::create` does not write to disk, so a follow-up
//!    [`Vault::save`] commits the empty vault. `Store::create_force`
//!    runs the §5 staged-clobber pipeline itself and needs no follow-up.
//! 6. Render the §5 success envelope: `{ "ok": true, "status": ... }`
//!    under `--json`, a "Created … vault at …." line in text mode.

use std::io::Write;
use std::path::Path;

use paladin_core::{
    classify_init_precheck, format_init_force_warning, format_plaintext_storage_warning, inspect,
    EncryptionOptions, InitPrecheck, PaladinError, Store, Vault, VaultInit, VaultMode,
};

use crate::cli::{GlobalArgs, InitArgs};
use crate::kdf;
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::prompt::{self, NewPassphraseEmptyPolicy};
use crate::vault_open;

/// Entry point invoked from `main::dispatch`.
pub fn run(global: &GlobalArgs, args: &InitArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;

    // KDF validation runs before *any* disk inspection or prompt so an
    // invalid flag wins over `vault_exists`, `unsafe_permissions`, and
    // the new-passphrase prompt.
    let argon = kdf::parse_argon2_params(&args.kdf)?;

    let pre = classify_init_precheck(inspect(&path));
    match pre {
        InitPrecheck::Clear => {}
        InitPrecheck::Existing if !args.force => {
            return Err(CliError::Paladin(PaladinError::VaultExists));
        }
        InitPrecheck::Existing => {
            if matches!(mode, Mode::Text { .. }) {
                let warning = format_init_force_warning(&path);
                let _ = writeln!(std::io::stderr().lock(), "{warning}");
            }
        }
        InitPrecheck::Propagate(err) => return Err(err.into()),
    }

    let passphrase = prompt::prompt_new_passphrase(
        "New passphrase (empty for plaintext): ",
        "Confirm passphrase: ",
        NewPassphraseEmptyPolicy::AllowAsPlaintext,
    )?;

    let init = match passphrase {
        None => {
            if matches!(mode, Mode::Text { .. }) {
                let warning = format_plaintext_storage_warning();
                let _ = writeln!(std::io::stderr().lock(), "{warning}");
            }
            VaultInit::Plaintext
        }
        Some(pp) => VaultInit::Encrypted(EncryptionOptions::with_params(pp, argon)?),
    };

    let vault = if args.force {
        let (vault, _store) = Store::create_force(&path, init)?;
        vault
    } else {
        let (vault, store) = Store::create(&path, init)?;
        vault.save(&store)?;
        vault
    };

    render_success(mode, &vault, &path)
}

fn render_success(mode: Mode, vault: &Vault, path: &Path) -> Result<(), CliError> {
    let final_mode = if vault.is_encrypted() {
        VaultMode::Encrypted
    } else {
        VaultMode::Plaintext
    };
    match mode {
        Mode::Json => {
            output::json::write_ok_status(final_mode, std::io::stdout().lock()).map_err(io_err)?;
        }
        Mode::Text { .. } => {
            output::text::write_init_success(final_mode, path, std::io::stdout().lock())
                .map_err(io_err)?;
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
