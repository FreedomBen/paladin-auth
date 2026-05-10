// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin rename <query> <new-label>` — rename an account. See
//! DESIGN.md §5 and `IMPLEMENTATION_PLAN_02_CLI.md` "Vault interaction
//! pattern".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Resolve the output mode and vault path.
//! 2. Open the vault through the shared pipeline.
//! 3. Resolve the query through `select::resolve_unique` — `rename`
//!    always requires a single match so a substring like `alice`
//!    cannot silently rename several rows in one call.
//! 4. Mutate through `Vault::mutate_and_save`. The closure invokes
//!    [`paladin_core::Vault::rename`] which performs label validation
//!    via the §4.1 path (returning `validation_error` for invalid
//!    labels and `invalid_state` `account_not_found` for stale ids)
//!    and bumps `updated_at` on success. A pre-commit save failure
//!    rolls the in-memory rename back before the command renders.
//! 5. Render `{ "account": AccountSummary }` under `--json`, "Renamed
//!    to Acme:newname." in text mode. The summary is the post-rename
//!    state so JSON consumers see the bumped `updated_at` without a
//!    follow-up `list`.

use std::time::SystemTime;

use paladin_core::{AccountId, AccountSummary, PaladinError, Vault};

use crate::cli::{GlobalArgs, RenameArgs};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::select;
use crate::vault_open;

pub fn run(global: &GlobalArgs, args: &RenameArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;
    let mut opened = vault_open::open(&path)?;

    let now = SystemTime::now();

    // Pull the id out of the borrow so the mutate_and_save closure
    // below can take `&mut Vault`.
    let id: AccountId = {
        let account = select::resolve_unique(&opened.vault, &args.query)?;
        account.id()
    };

    let new_label = args.new_label.as_str();

    opened
        .vault
        .mutate_and_save(&opened.store, |vault| vault.rename(id, new_label, now))?;

    let summary = post_summary(&opened.vault, id);
    render(mode, &summary)
}

/// Look up the persisted summary for `id` after the rename has been
/// committed. The id was just resolved against this vault and the
/// only intervening mutation preserves account ids, so a missing id
/// here would be a core invariant break.
fn post_summary(vault: &Vault, id: AccountId) -> AccountSummary {
    vault
        .summaries()
        .find(|s| s.id == id)
        .expect("renamed account id must persist after mutate_and_save")
}

fn render(mode: Mode, account: &AccountSummary) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_rename_success(account, std::io::stdout().lock())
                .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            output::text::write_rename_success(account, std::io::stdout().lock())
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
