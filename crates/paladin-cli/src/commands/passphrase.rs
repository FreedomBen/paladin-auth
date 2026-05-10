// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin passphrase {set,change,remove}` — vault passphrase
//! transitions (DESIGN.md §4.5 / §5). See `IMPLEMENTATION_PLAN_02_CLI.md`
//! "Passphrase prompts" / "Vault interaction pattern".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Resolve the output mode and vault path.
//! 2. (`remove` only) Reject `--json` without `--yes` *before* touching
//!    disk so the JSON wire never blocks on a destructive
//!    confirmation prompt. The rejection is a `validation_error` with
//!    `field: "argv"`, `reason: "yes_required_under_json"`, mirroring
//!    `paladin remove --json`.
//! 3. (`set` / `change` only) Parse + validate KDF flags. Errors here
//!    win over `vault_missing`, `invalid_state`, the unlock prompt, and
//!    the new-passphrase prompt — locked by `IMPLEMENTATION_PLAN_02_CLI.md`
//!    "Encrypted-write KDF flags".
//! 4. `inspect(path)`. The result also serves as the wrong-state gate
//!    *before* any prompt: `set` on `Encrypted` returns `invalid_state`
//!    `already_encrypted`; `change` / `remove` on `Plaintext` returns
//!    `invalid_state` `not_encrypted`. `Missing` short-circuits to
//!    `vault_missing`. Other `inspect` errors propagate verbatim.
//! 5. (`remove` only, text mode) Print
//!    `format_plaintext_storage_warning()` to stderr; if `--yes` is not
//!    passed, prompt destructive confirmation **before** the unlock
//!    prompt. A declined / no-`/dev/tty` confirmation surfaces
//!    `validation_error` `confirmation` `declined` or `io_error`
//!    `operation: "confirmation_prompt"` without ever asking for the
//!    unlock passphrase. Under `--json` the advisory is suppressed
//!    because the caller already opted in via `--yes`.
//! 6. Open the vault via [`vault_open::open`] (encrypted vaults prompt
//!    once for the existing passphrase via `/dev/tty`).
//! 7. (`set` / `change` only) Prompt for the new passphrase plus a
//!    matching confirmation. The
//!    [`NewPassphraseEmptyPolicy::Reject`] branch surfaces
//!    `invalid_passphrase` `zero_length` for an empty entry and
//!    `confirmation_mismatch` for any byte-level divergence.
//! 8. Apply the transition through the matching
//!    [`paladin_core::Vault`] method (`set_passphrase` /
//!    `change_passphrase` / `remove_passphrase`), each of which saves
//!    atomically through `&Store`.
//! 9. Render `{ "ok": true, "status": ... }` under `--json`, the
//!    matching success line in text mode.

use std::io::Write;

use paladin_core::{
    format_plaintext_storage_warning, inspect, EncryptionOptions, PaladinError, VaultMode,
    VaultStatus,
};

use crate::cli::{GlobalArgs, KdfArgs};
use crate::kdf;
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::prompt::{self, NewPassphraseEmptyPolicy};
use crate::vault_open;

/// `paladin passphrase set`: encrypt a plaintext vault under a new
/// passphrase. Wrong-state on an already-encrypted vault returns
/// `invalid_state` `already_encrypted` before any prompt.
pub fn set(global: &GlobalArgs, kdf_args: &KdfArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;

    // KDF parsing wins over `vault_missing`, `invalid_state`, and
    // every prompt — locked by the §5 ordering rule.
    let argon = kdf::parse_argon2_params(kdf_args)?;

    // Wrong-state gate: refuse to encrypt an already-encrypted vault
    // before unlocking it.
    match inspect(&path)? {
        VaultStatus::Missing => return Err(CliError::Paladin(PaladinError::VaultMissing)),
        VaultStatus::Encrypted => {
            return Err(CliError::Paladin(PaladinError::InvalidState {
                operation: "set_passphrase",
                state: "already_encrypted",
            }));
        }
        VaultStatus::Plaintext => {}
    }

    let mut opened = vault_open::open(&path)?;

    let pp = prompt::prompt_new_passphrase(
        "New passphrase: ",
        "Confirm passphrase: ",
        NewPassphraseEmptyPolicy::Reject,
    )?
    .expect("Reject policy never returns Ok(None)");

    let options = EncryptionOptions::with_params(pp, argon)?;
    opened.vault.set_passphrase(&opened.store, options)?;

    render(mode, VaultMode::Encrypted, SuccessKind::Set)
}

/// `paladin passphrase change`: re-encrypt an encrypted vault under a
/// new passphrase. Wrong-state on a plaintext vault returns
/// `invalid_state` `not_encrypted` before any prompt.
pub fn change(global: &GlobalArgs, kdf_args: &KdfArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;

    let argon = kdf::parse_argon2_params(kdf_args)?;

    match inspect(&path)? {
        VaultStatus::Missing => return Err(CliError::Paladin(PaladinError::VaultMissing)),
        VaultStatus::Plaintext => {
            return Err(CliError::Paladin(PaladinError::InvalidState {
                operation: "change_passphrase",
                state: "not_encrypted",
            }));
        }
        VaultStatus::Encrypted => {}
    }

    let mut opened = vault_open::open(&path)?;

    let pp = prompt::prompt_new_passphrase(
        "New passphrase: ",
        "Confirm passphrase: ",
        NewPassphraseEmptyPolicy::Reject,
    )?
    .expect("Reject policy never returns Ok(None)");

    let options = EncryptionOptions::with_params(pp, argon)?;
    opened.vault.change_passphrase(&opened.store, options)?;

    render(mode, VaultMode::Encrypted, SuccessKind::Change)
}

/// `paladin passphrase remove`: decrypt an encrypted vault to plaintext.
/// `--json` requires `--yes`. Text mode prints the plaintext-storage
/// warning and prompts for destructive confirmation **before** the
/// unlock prompt — a declined or no-`/dev/tty` confirmation surfaces
/// `validation_error` / `io_error` `operation: "confirmation_prompt"`
/// without ever asking for the unlock passphrase. `--yes` skips only
/// the confirmation; the unlock prompt still fires. Wrong-state on a
/// plaintext vault returns `invalid_state` `not_encrypted` before any
/// prompt.
pub fn remove(global: &GlobalArgs, yes: bool) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;

    // `--json` without `--yes` is rejected before any disk I/O so the
    // strict-mode contract holds (no prompt strings reach the JSON
    // streams). Mirrors the parse-time pattern used by `paladin remove
    // --json`.
    if matches!(mode, Mode::Json) && !yes {
        return Err(CliError::Paladin(PaladinError::ValidationError {
            field: "argv",
            reason: "yes_required_under_json".into(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
    }

    match inspect(&path)? {
        VaultStatus::Missing => return Err(CliError::Paladin(PaladinError::VaultMissing)),
        VaultStatus::Plaintext => {
            return Err(CliError::Paladin(PaladinError::InvalidState {
                operation: "remove_passphrase",
                state: "not_encrypted",
            }));
        }
        VaultStatus::Encrypted => {}
    }

    if matches!(mode, Mode::Text { .. }) {
        let warning = format_plaintext_storage_warning();
        let _ = writeln!(std::io::stderr().lock(), "{warning}");
        if !yes {
            prompt::prompt_destructive_confirmation(
                "Decrypt vault to plaintext? Type 'yes' to confirm: ",
            )?;
        }
    }

    let mut opened = vault_open::open(&path)?;

    opened.vault.remove_passphrase(&opened.store)?;

    render(mode, VaultMode::Plaintext, SuccessKind::Remove)
}

/// Which subcommand fired, so the text renderer can pick the matching
/// human-readable success line. The JSON envelope is identical across
/// all three subcommands (`{ "ok": true, "status": ... }`).
#[derive(Copy, Clone, Debug)]
enum SuccessKind {
    Set,
    Change,
    Remove,
}

fn render(mode: Mode, status: VaultMode, kind: SuccessKind) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_ok_status(status, std::io::stdout().lock()).map_err(io_err)?;
        }
        Mode::Text { .. } => {
            let line = match kind {
                SuccessKind::Set => "Encrypted vault.",
                SuccessKind::Change => "Re-encrypted vault.",
                SuccessKind::Remove => "Decrypted vault to plaintext.",
            };
            output::text::write_passphrase_success(line, std::io::stdout().lock())
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
