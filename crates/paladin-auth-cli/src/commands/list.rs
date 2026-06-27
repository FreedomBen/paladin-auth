// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-auth list` — print account metadata plus, for TOTP rows, the
//! current code, seconds remaining in the current TOTP window, and
//! the next TOTP code. See docs/DESIGN.md §5 and
//! `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Vault interaction pattern".
//!
//! Order of operations:
//!
//! 1. Resolve the vault path.
//! 2. Run the shared open pipeline (`vault_open::open`) which routes
//!    `Missing` to `vault_missing`, propagates other `inspect` errors
//!    verbatim, and prompts once for an encrypted vault's passphrase.
//! 3. Sample `SystemTime::now()` once and reuse it for every TOTP row
//!    so all rows share the same window.
//! 4. Iterate `Vault::summaries()` and render via the §5 envelopes —
//!    `{ "accounts": [AccountSummary + code/seconds_remaining/next_code] }`
//!    under `--json`, tab-separated rows in text mode (empty vault →
//!    no rows). HOTP rows leave the code columns empty (`-` in text,
//!    `null` under `--json`) because `list` never advances or peeks
//!    an HOTP counter.

use std::time::SystemTime;

use paladin_auth_core::{AccountKindSummary, AccountSummary, PaladinAuthError};

use crate::cli::GlobalArgs;
use crate::output::error::CliError;
use crate::output::json::ListAccountRow;
use crate::output::text::ListRow;
use crate::output::{self, Mode};
use crate::vault_open;

/// Computed TOTP codes for one account. HOTP rows leave every field
/// `None`; TOTP rows fill all three. Held outside the row structs so
/// the strings can be borrowed by both the text and JSON renderers.
struct ComputedCodes {
    current: Option<String>,
    seconds_remaining: Option<u32>,
    next: Option<String>,
}

/// Entry point invoked from `main::dispatch`.
pub fn run(global: &GlobalArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;
    let opened = vault_open::open(&path)?;

    let summaries: Vec<AccountSummary> = opened.vault.summaries().collect();
    let now = SystemTime::now();
    let computed: Vec<ComputedCodes> = summaries
        .iter()
        .map(|s| compute_codes(&opened.vault, s, now))
        .collect();

    match mode {
        Mode::Json => {
            let rows: Vec<ListAccountRow<'_>> = summaries
                .iter()
                .zip(computed.iter())
                .map(|(s, c)| ListAccountRow {
                    account: s,
                    code: c.current.as_deref(),
                    seconds_remaining: c.seconds_remaining,
                    next_code: c.next.as_deref(),
                })
                .collect();
            output::json::write_account_list(&rows, std::io::stdout().lock()).map_err(io_err)?;
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
                .zip(computed.iter())
                .map(|((s, d), c)| ListRow {
                    disambiguator: d.as_str(),
                    summary: s,
                    current_code: c.current.as_deref(),
                    seconds_remaining: c.seconds_remaining,
                    next_code: c.next.as_deref(),
                })
                .collect();
            output::text::write_account_list(&rows, std::io::stdout().lock()).map_err(io_err)?;
        }
    }
    Ok(())
}

/// Compute the current and next TOTP code for a row. HOTP rows return
/// all-`None`. If `Vault::totp_code` / `totp_next_code` ever fails
/// (e.g. a `time_range` overflow on a far-future clock), fall back to
/// `None` so the row still renders — `list` is read-only and should
/// not abort the whole command for one bad clock value.
fn compute_codes(
    vault: &paladin_auth_core::Vault,
    s: &AccountSummary,
    now: SystemTime,
) -> ComputedCodes {
    match s.kind {
        AccountKindSummary::Hotp => ComputedCodes {
            current: None,
            seconds_remaining: None,
            next: None,
        },
        AccountKindSummary::Totp => {
            let current = vault.totp_code(s.id, now).ok();
            let next = vault.totp_next_code(s.id, now).ok();
            ComputedCodes {
                seconds_remaining: current.as_ref().and_then(|c| c.seconds_remaining),
                current: current.map(|c| c.code),
                next: next.map(|c| c.code),
            }
        }
    }
}

fn io_err(source: std::io::Error) -> CliError {
    CliError::PaladinAuth(PaladinAuthError::IoError {
        operation: "write_stdout",
        source,
    })
}
