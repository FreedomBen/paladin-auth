// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin show <query>` — print the current code; advances HOTP and
//! persists before printing. See DESIGN.md §5 and
//! `IMPLEMENTATION_PLAN_02_CLI.md` "Vault interaction pattern" /
//! "Query resolution".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Resolve the vault path and run the shared open pipeline. The
//!    pipeline routes `Missing` to `vault_missing` and propagates other
//!    `inspect` errors verbatim before any prompt; encrypted vaults
//!    prompt once via `/dev/tty`.
//! 2. Resolve the query through `paladin_core::parse_account_query` /
//!    `Vault::matching_accounts`. The CLI applies the §5 cardinality
//!    policy: a single match always works; multi-match is allowed only
//!    when every match is TOTP, so one command cannot silently advance
//!    multiple HOTP counters.
//! 3. Generate codes:
//!    - TOTP via `Vault::totp_code(id, now)` — read-only, no save.
//!    - HOTP via `Vault::hotp_advance(&store, id, now)` — advances the
//!      counter and persists to disk before returning. Single-match
//!      only on this branch by construction.
//! 4. Render `{ "codes": [CodeResult] }` under `--json`, tab-separated
//!    rows in text mode. The `account` summary in each row reflects
//!    persisted state after the command, so HOTP `account.counter` is
//!    the post-advance value while `counter_used` is the pre-advance
//!    counter that produced the visible code.

use std::time::SystemTime;

use paladin_core::{AccountId, AccountKindSummary, AccountSummary, Code, PaladinError, Vault};

use crate::cli::{GlobalArgs, QueryArgs};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::select::{self, ShowSelection};
use crate::vault_open;

pub fn run(global: &GlobalArgs, args: &QueryArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;
    let mut opened = vault_open::open(&path)?;

    let now = SystemTime::now();

    // Resolve the query first so the cardinality decision lands before
    // any code generation. Borrows of `&opened.vault` are released by
    // dropping `selection` into a list of `(id, kind)` plans below.
    let plan = match select::resolve_for_show(&opened.vault, &args.query)? {
        ShowSelection::Single(account) => Plan::Single(account.id(), account.summary().kind),
        ShowSelection::AllTotp(accounts) => {
            Plan::AllTotp(accounts.iter().map(|a| a.id()).collect())
        }
    };

    let mut pairs: Vec<(AccountSummary, Code)> = Vec::new();
    match plan {
        Plan::Single(id, AccountKindSummary::Totp) => {
            let code = opened.vault.totp_code(id, now)?;
            pairs.push((post_summary(&opened.vault, id), code));
        }
        Plan::Single(id, AccountKindSummary::Hotp) => {
            // hotp_advance persists before returning, so the post-call
            // `summaries()` lookup reflects the on-disk counter.
            let code = opened.vault.hotp_advance(&opened.store, id, now)?;
            pairs.push((post_summary(&opened.vault, id), code));
        }
        Plan::AllTotp(ids) => {
            for id in ids {
                let code = opened.vault.totp_code(id, now)?;
                pairs.push((post_summary(&opened.vault, id), code));
            }
        }
    }

    render(mode, &opened.vault, &pairs)
}

/// Internal projection of [`ShowSelection`]. Holding plain ids and
/// kinds (rather than `&Account`) lets us drop the immutable borrow of
/// the vault before calling `hotp_advance`, which needs `&mut Vault`.
enum Plan {
    Single(AccountId, AccountKindSummary),
    AllTotp(Vec<AccountId>),
}

/// Look up the persisted summary for `id` in `vault`. Each id was
/// resolved from `matching_accounts` against the same vault and the
/// only mutation we run between resolution and lookup is
/// `hotp_advance`, which preserves the id; missing here would be a
/// core invariant break.
fn post_summary(vault: &Vault, id: AccountId) -> AccountSummary {
    vault
        .summaries()
        .find(|s| s.id == id)
        .expect("resolved account id must persist after code generation")
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
                        .expect("shown account ID must be present in the live vault");
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
