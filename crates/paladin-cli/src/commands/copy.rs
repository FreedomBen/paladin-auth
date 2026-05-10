// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin copy <query>` — copy the current code to the clipboard via
//! `arboard`. See DESIGN.md §5 "Clipboard copy side effects" and
//! `IMPLEMENTATION_PLAN_02_CLI.md` "Clipboard copy side effects".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Resolve the vault path and run the shared open pipeline.
//! 2. Resolve the query through `select::resolve_unique` — `copy`
//!    always requires a single match.
//! 3. Generate the code:
//!    - TOTP via `Vault::totp_code(id, now)` — read-only.
//!    - HOTP via `Vault::hotp_advance(&store, id, now)` — advances the
//!      counter and **persists to disk before** the clipboard write
//!      attempt. If the save returns `save_not_committed`, propagate it
//!      verbatim and skip the clipboard write entirely (counter is
//!      unchanged on disk and in memory after the rollback inside
//!      `mutate_and_save`).
//! 4. Attempt the clipboard write through the [`crate::clipboard`]
//!    adapter. A failure after a *committed* HOTP advance does **not**
//!    roll the counter back — the code may already have been exposed
//!    to the clipboard provider. Surface
//!    [`CliError::ClipboardWriteFailed`] with the post-advance summary
//!    and the pre-advance counter so the §5 envelope is intact.
//! 5. CLI is stateless per DESIGN.md §8 — never schedule an auto-clear,
//!    regardless of the vault's `clipboard.clear_enabled` setting.
//! 6. Render `{ "copied": true, "account": ..., "counter_used": ... }`
//!    under `--json`, "Copied … code to clipboard." in text mode.

use std::time::SystemTime;

use paladin_core::{AccountId, AccountKindSummary, AccountSummary, PaladinError, Vault};

use crate::cli::{GlobalArgs, QueryArgs};
use crate::clipboard;
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::select;
use crate::vault_open;

pub fn run(global: &GlobalArgs, args: &QueryArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let path = vault_open::resolve_vault_path(global)?;
    let mut opened = vault_open::open(&path)?;

    let now = SystemTime::now();

    // Pull the id and kind out of the borrow before any mutation.
    let (id, kind) = {
        let account = select::resolve_unique(&opened.vault, &args.query)?;
        (account.id(), account.summary().kind)
    };

    // Generate the code. For HOTP, hotp_advance persists before
    // returning so any save failure surfaces here without ever
    // attempting a clipboard write.
    let (code_str, counter_used): (String, Option<u64>) = match kind {
        AccountKindSummary::Totp => {
            let code = opened.vault.totp_code(id, now)?;
            (code.code, None)
        }
        AccountKindSummary::Hotp => {
            let code = opened.vault.hotp_advance(&opened.store, id, now)?;
            let pre = code.counter_used;
            (code.code, pre)
        }
    };

    // Account summary at this point reflects persisted post-advance
    // state for HOTP (hotp_advance has already saved) and the
    // unchanged stored state for TOTP.
    let summary = post_summary(&opened.vault, id);

    // Attempt the clipboard write. Failure surfaces
    // ClipboardWriteFailed; we deliberately do not roll the counter
    // back per §5. The CLI never schedules an auto-clear.
    clipboard::copy(&code_str, summary.clone(), counter_used)?;

    render(mode, &summary, counter_used)
}

/// Look up the persisted summary for `id` after any HOTP advance has
/// been committed. The id was just resolved against this vault and the
/// only intervening mutation preserves account ids, so a missing id
/// here would be a core invariant break.
fn post_summary(vault: &Vault, id: AccountId) -> AccountSummary {
    vault
        .summaries()
        .find(|s| s.id == id)
        .expect("copied account id must persist after code generation")
}

fn render(mode: Mode, summary: &AccountSummary, counter_used: Option<u64>) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_copy_success(summary, counter_used, std::io::stdout().lock())
                .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            output::text::write_copy_success(summary, std::io::stdout().lock()).map_err(io_err)?;
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
