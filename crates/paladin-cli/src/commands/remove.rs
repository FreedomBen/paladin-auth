// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin remove <query>` — remove a single account. See docs/DESIGN.md §5
//! and `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Vault interaction pattern" /
//! "Non-passphrase TTY prompts".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Resolve the output mode and reject `--json` without `--yes` *before*
//!    touching disk so a script never blocks on a destructive
//!    confirmation prompt. The rejection is a `validation_error` with
//!    `field: "argv"`, `reason: "yes_required_under_json"`, mirroring
//!    the parse-time pattern used by `add --json` interactive mode.
//! 2. Resolve the vault path and run the shared open pipeline.
//! 3. Resolve the query through `select::resolve_unique` — `remove`
//!    always requires a single match so a substring like `alice` cannot
//!    silently delete several rows.
//! 4. Capture the resolved account's summary up front. The destructive
//!    confirmation prompt (or `--yes` bypass) runs *after* selection so
//!    a `no_match` / `multiple_matches` failure does not pop a confirm
//!    for nothing.
//! 5. In text mode, prompt the user via `/dev/tty` unless `--yes` is
//!    set. Confirmation requires the exact string `yes` after trimming
//!    Unicode whitespace; anything else exits before mutation with
//!    `validation_error` `field: "confirmation"`, `reason: "declined"`.
//! 6. Mutate through `Vault::mutate_and_save` so a pre-commit save
//!    failure restores the account to the in-memory vault (and surfaces
//!    `save_not_committed`) before the command renders its error.
//! 7. Render `{ "removed": AccountSummary }` under `--json`, "Removed
//!    Acme:alice." in text mode.

use paladin_core::{AccountId, AccountSummary, PaladinError};

use crate::cli::{GlobalArgs, RemoveArgs};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::prompt;
use crate::select;
use crate::vault_open;

pub fn run(global: &GlobalArgs, args: &RemoveArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);

    // `--json` without `--yes` is rejected before any disk I/O so the
    // strict-mode contract holds (no prompt strings reach the JSON
    // streams).
    if matches!(mode, Mode::Json) && !args.yes {
        return Err(CliError::Paladin(PaladinError::ValidationError {
            field: "argv",
            reason: "yes_required_under_json".into(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
    }

    let path = vault_open::resolve_vault_path(global)?;
    let mut opened = vault_open::open(&path)?;

    // Resolve the unique target *before* any destructive prompt. A
    // failed selection (no_match / multiple_matches) must not surface
    // a "are you sure?" dialog for nothing.
    let (id, removed_summary): (AccountId, AccountSummary) = {
        let account = select::resolve_unique(&opened.vault, &args.query)?;
        (account.id(), account.summary())
    };

    // Destructive confirmation gate. `--yes` skips both text-mode
    // confirmation and (by virtue of the parse-time check above) is
    // already required under `--json`.
    if !args.yes {
        prompt::prompt_destructive_confirmation(&format!(
            "Remove {}? Type 'yes' to confirm: ",
            display_label(&removed_summary),
        ))?;
    }

    // Mutate through mutate_and_save so a pre-commit save failure
    // restores the removed account before the command renders its
    // error envelope.
    opened.vault.mutate_and_save(&opened.store, |vault| {
        vault.remove(id).ok_or(PaladinError::InvalidState {
            operation: "remove",
            state: "account_not_found",
        })?;
        Ok(())
    })?;

    render(mode, &removed_summary)
}

/// Render `<issuer>:<label>` when the issuer is set and non-empty,
/// otherwise the bare label. Mirrors the helper in
/// [`crate::output::text`] so confirmation prompts and success lines
/// match.
fn display_label(s: &AccountSummary) -> String {
    match s.issuer.as_deref().filter(|i| !i.is_empty()) {
        Some(issuer) => format!("{issuer}:{}", s.label),
        None => s.label.clone(),
    }
}

fn render(mode: Mode, removed: &AccountSummary) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_remove_success(removed, std::io::stdout().lock())
                .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            output::text::write_remove_success(removed, std::io::stdout().lock())
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
