// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin peek <query>` — print the current code without advancing
//! HOTP. See docs/DESIGN.md §5 and `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Vault
//! interaction pattern" / "Query resolution".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Resolve the vault path and run the shared open pipeline. The
//!    pipeline routes `Missing` to `vault_missing` and propagates other
//!    `inspect` errors verbatim before any prompt; encrypted vaults
//!    prompt once via `/dev/tty`.
//! 2. Resolve the query through `paladin_core::parse_account_query` /
//!    `Vault::matching_accounts`. `peek` allows multi-match
//!    unconditionally — it only rejects empty match sets — because it
//!    never mutates state.
//! 3. Generate codes:
//!    - TOTP via `Vault::totp_code(id, now)` — read-only, no save.
//!    - HOTP via `Vault::hotp_peek(id)` — read-only; reports the code
//!      for the **stored** counter without advancing it. The
//!      `Code::counter_used` field carries that stored counter.
//! 4. Render `{ "codes": [CodeResult] }` under `--json`, tab-separated
//!    rows in text mode. Account summaries reflect the unchanged
//!    persisted state — `peek` performs no writes.

use std::time::SystemTime;

use paladin_core::{AccountId, AccountKindSummary, AccountSummary, Code, PaladinError, Vault};

use crate::cli::{GlobalArgs, QueryArgs};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::select;
use crate::vault_open;

pub fn run(global: &GlobalArgs, args: &QueryArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;
    let opened = vault_open::open(&path)?;

    let now = SystemTime::now();

    // Collect (id, kind) pairs first so the &Vault borrow held by
    // the matched account list is released before we call the
    // read-only generators below.
    let plan: Vec<(AccountId, AccountKindSummary)> =
        select::resolve_all(&opened.vault, &args.query)?
            .into_iter()
            .map(|a| (a.id(), a.summary().kind))
            .collect();

    let mut pairs: Vec<(AccountSummary, Code)> = Vec::with_capacity(plan.len());
    for (id, kind) in plan {
        let code = match kind {
            AccountKindSummary::Totp => opened.vault.totp_code(id, now)?,
            AccountKindSummary::Hotp => opened.vault.hotp_peek(id)?,
        };
        pairs.push((current_summary(&opened.vault, id), code));
    }

    render(mode, &opened.vault, &pairs)
}

/// Look up the current persisted summary for `id` in `vault`. `peek`
/// never mutates the vault, so the summary matches the pre-call state
/// exactly; missing here would be a core invariant break.
fn current_summary(vault: &Vault, id: AccountId) -> AccountSummary {
    vault
        .summaries()
        .find(|s| s.id == id)
        .expect("resolved account id must exist in the live vault")
}

fn render(mode: Mode, vault: &Vault, pairs: &[(AccountSummary, Code)]) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            let rows: Vec<output::json::CodeRow<'_>> = pairs
                .iter()
                .map(|(summary, code)| output::json::CodeRow {
                    account: summary,
                    code,
                })
                .collect();
            output::json::write_show_codes(&rows, std::io::stdout().lock()).map_err(io_err)?;
        }
        Mode::Text { .. } => {
            let disambiguators: Vec<String> = pairs
                .iter()
                .map(|(summary, _)| {
                    let hex = vault
                        .shortest_unique_id_prefix(summary.id)
                        .expect("peeked account ID must be present in the live vault");
                    format!("id:{hex}")
                })
                .collect();
            let rows: Vec<output::text::CodeRow<'_>> = pairs
                .iter()
                .zip(disambiguators.iter())
                .map(|((summary, code), d)| output::text::CodeRow {
                    disambiguator: d.as_str(),
                    account: summary,
                    code,
                })
                .collect();
            output::text::write_code_rows(&rows, std::io::stdout().lock()).map_err(io_err)?;
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
