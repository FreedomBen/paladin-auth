// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin edit <query>` — multi-field non-cryptographic metadata
//! edit. See docs/DESIGN.md §5 and `docs/IMPLEMENTATION_PLAN_02_CLI.md`
//! "Edit command (v0.2)".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Validate argv parse-time. The "at least one editable flag"
//!    requirement is enforced **before** any disk I/O so the
//!    `no_edit_fields` rejection beats `vault_missing` and the
//!    encrypted-mode passphrase prompt. The clap-side `conflicts_with`
//!    pairs (`--issuer` ↔ `--no-issuer`, `--icon-hint` ↔
//!    `--no-icon-hint`) are picked up by `argv_has_json_flag` →
//!    `handle_parse_err` and rendered as
//!    `validation_error` (`field: "argv"`, `reason: "usage"` via
//!    `CliError::Usage`); a follow-up landing may upgrade these to
//!    `reason: "mutually_exclusive"`, but the rejection itself
//!    already fires at parse time.
//! 2. Resolve the vault path and run the shared open pipeline.
//! 3. Resolve the query through `select::resolve_unique` so a single
//!    match is required (matching `copy` / `remove` / `rename` /
//!    `qr`).
//! 4. Build an `AccountEdit` from the argv flags. Icon-hint values
//!    flow through `paladin_core::parse_icon_hint_token` so the
//!    `add`-grammar (`empty -> Default`, `none -> Clear`,
//!    `slug -> Slug`) is shared.
//! 5. Run `paladin_core::validate_account_edit(&edit, prior, now)`
//!    explicitly. A typed `validation_error` wins precedence over
//!    `duplicate_account` (locked rule in DESIGN §5 / Plan §"Edit
//!    command (v0.2)").
//! 6. Unless `--allow-duplicate`, call
//!    `Vault::find_duplicate_after_edit(id, &edit)` and reject a
//!    non-`None` result with `duplicate_account` carrying the
//!    existing collision's `AccountSummary`.
//! 7. For `--dry-run`: apply `edit_account_metadata` in memory
//!    against `opened.vault` to project the post-edit summary, then
//!    render `{ "account": AccountSummary, "committed": false }`
//!    under `--json` (text mode stays silent). `mutate_and_save` is
//!    **never** invoked so the vault file is byte-identical.
//! 8. Otherwise: mutate through `Vault::mutate_and_save` so a
//!    pre-commit save failure restores the in-memory pre-edit state
//!    and surfaces `save_not_committed`. Render
//!    `{ "account": AccountSummary }` under `--json` (text mode
//!    stays silent — parity with `rename` / `remove --yes`).
//!
//! The CLI is read-only on secret bytes: it never decodes the stored
//! secret, never advances HOTP counters, and never re-derives a slug
//! from secret content.

use std::time::SystemTime;

use paladin_core::{
    parse_icon_hint_token, validate_account_edit, AccountEdit, AccountId, AccountSummary,
    IconHintInput, PaladinError, Vault,
};

use crate::cli::{EditArgs, GlobalArgs};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::select;
use crate::vault_open;

/// Entry point invoked from `main::dispatch`.
pub fn run(global: &GlobalArgs, args: &EditArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);

    // Step 1: parse-time "at least one editable flag" check. Fire
    // before any disk I/O so the rejection beats `vault_missing` and
    // the encrypted-mode passphrase prompt.
    if !has_any_editable_flag(args) {
        return Err(no_edit_fields_error());
    }

    let path = vault_open::resolve_vault_path(global)?;
    let mut opened = vault_open::open(&path)?;

    let now = SystemTime::now();

    // Step 3: single-match cardinality. Pull the id out so the
    // `mutate_and_save` closure can take `&mut Vault`.
    let id: AccountId = {
        let account = select::resolve_unique(&opened.vault, &args.query)?;
        account.id()
    };

    // Step 4: build the AccountEdit from argv values.
    let edit = build_account_edit(args)?;

    // Step 5: explicit per-field validation. Runs before the duplicate
    // check so a typed `validation_error` wins precedence over
    // `duplicate_account` regardless of `--allow-duplicate`.
    {
        let prior = opened
            .vault
            .get(id)
            .expect("resolved id must still be present in the open vault");
        validate_account_edit(&edit, prior, now)?;
    }

    // Step 6: duplicate-account gate.
    if !args.allow_duplicate {
        if let Some(existing) = opened.vault.find_duplicate_after_edit(id, &edit) {
            return Err(CliError::DuplicateAccount {
                account: existing.summary(),
            });
        }
    }

    if args.dry_run {
        // Step 7: project the post-edit summary by running the
        // canonical core mutator against the in-memory `Vault` only.
        // `mutate_and_save` is never invoked so the on-disk vault is
        // byte-identical.
        opened.vault.edit_account_metadata(id, edit, now)?;
        let summary = post_summary(&opened.vault, id);
        return render_dry_run(mode, &summary);
    }

    // Step 8: persist through mutate_and_save so a pre-commit save
    // failure rolls back the in-memory edit before the renderer fires.
    opened.vault.mutate_and_save(&opened.store, |vault| {
        vault.edit_account_metadata(id, edit.clone(), now)
    })?;

    let summary = post_summary(&opened.vault, id);
    render_success(mode, &summary)
}

/// True iff at least one of the editable flags is set.
/// `--allow-duplicate` is a collision override and does **not**
/// satisfy this requirement on its own.
fn has_any_editable_flag(args: &EditArgs) -> bool {
    args.label.is_some()
        || args.issuer.is_some()
        || args.no_issuer
        || args.icon_hint.is_some()
        || args.no_icon_hint
}

fn no_edit_fields_error() -> CliError {
    CliError::Paladin(PaladinError::ValidationError {
        field: "argv",
        reason: "no_edit_fields".into(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    })
}

/// Map argv onto a `paladin_core::AccountEdit`. Issuer / icon-hint
/// tri-states follow DESIGN.md §5 and §4.7 verbatim.
fn build_account_edit(args: &EditArgs) -> Result<AccountEdit, CliError> {
    let issuer: Option<Option<String>> = if args.no_issuer {
        Some(None)
    } else {
        args.issuer.clone().map(Some)
    };

    let icon_hint: Option<IconHintInput> = if args.no_icon_hint {
        Some(IconHintInput::Clear)
    } else if let Some(raw) = args.icon_hint.as_deref() {
        // Route through `parse_icon_hint_token` so the
        // empty / case-insensitive `none` / slug grammar matches the
        // `add` command. Any per-field validation failure surfaces as
        // `validation_error` with `field: "icon_hint"`.
        Some(parse_icon_hint_token(raw)?)
    } else {
        None
    };

    Ok(AccountEdit {
        label: args.label.clone(),
        issuer,
        icon_hint,
    })
}

/// Look up the persisted summary for `id` after the edit has been
/// applied. The id was resolved against this vault and the only
/// intervening mutation preserves account ids, so a missing id here
/// would be a core invariant break.
fn post_summary(vault: &Vault, id: AccountId) -> AccountSummary {
    vault
        .summaries()
        .find(|s| s.id == id)
        .expect("edited account id must persist after edit_account_metadata")
}

fn render_success(mode: Mode, account: &AccountSummary) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_edit_success(account, std::io::stdout().lock()).map_err(io_err)?;
        }
        Mode::Text { .. } => {
            // Parity with `rename` text mode: print nothing on
            // success. (`rename` prints a one-liner but `edit` is
            // multi-field; the plan locks "text mode prints nothing
            // on success".)
        }
    }
    Ok(())
}

fn render_dry_run(mode: Mode, account: &AccountSummary) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_edit_dry_run(account, std::io::stdout().lock()).map_err(io_err)?;
        }
        Mode::Text { .. } => {
            // Plan: "text mode stays silent" on dry-run.
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
