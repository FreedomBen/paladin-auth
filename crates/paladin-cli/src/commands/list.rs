// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin list` — print account metadata (no codes). See docs/DESIGN.md §5
//! and `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Vault interaction pattern".
//!
//! Order of operations:
//!
//! 1. Resolve the vault path.
//! 2. Run the shared open pipeline (`vault_open::open`) which routes
//!    `Missing` to `vault_missing`, propagates other `inspect` errors
//!    verbatim, and prompts once for an encrypted vault's passphrase.
//! 3. Iterate `Vault::summaries()` and render via the §5 envelopes —
//!    `{ "accounts": [AccountSummary] }` under `--json`, tab-separated
//!    rows in text mode (empty vault → no rows).

use paladin_core::{AccountSummary, PaladinError};

use crate::cli::GlobalArgs;
use crate::output::error::CliError;
use crate::output::text::ListRow;
use crate::output::{self, Mode};
use crate::vault_open;

/// Entry point invoked from `main::dispatch`.
pub fn run(global: &GlobalArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;
    let opened = vault_open::open(&path)?;

    let summaries: Vec<AccountSummary> = opened.vault.summaries().collect();

    match mode {
        Mode::Json => {
            output::json::write_account_list(&summaries, std::io::stdout().lock())
                .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            // Pre-compute disambiguators so the renderer borrows
            // `&str`. `shortest_unique_id_prefix` returns the lowercase
            // hex prefix (≥ 8 chars); prepending `id:` here keeps list
            // output and `multiple_matches` candidate lines on the
            // same disambiguator shape.
            let disambiguators: Vec<String> = summaries
                .iter()
                .map(|s| {
                    let hex = opened
                        .vault
                        .shortest_unique_id_prefix(s.id)
                        .expect("listed account ID must be present in the live vault");
                    format!("id:{hex}")
                })
                .collect();
            let rows: Vec<ListRow<'_>> = summaries
                .iter()
                .zip(disambiguators.iter())
                .map(|(s, d)| ListRow {
                    disambiguator: d.as_str(),
                    summary: s,
                })
                .collect();
            output::text::write_account_list(&rows, std::io::stdout().lock()).map_err(io_err)?;
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
