// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin import` — import accounts from a file (docs/DESIGN.md §5).
//! Auto-detects format when `--format` is omitted; conflict policies
//! are `skip` (default), `replace`, `append`.
//!
//! Order of operations (locked by `docs/IMPLEMENTATION_PLAN_02_CLI.md`):
//!
//! 1. Resolve output mode and vault path.
//! 2. Open the vault via the shared open pipeline (prompts once for an
//!    encrypted *vault* unlock — distinct from any bundle passphrase).
//! 3. Call [`paladin_core::classify_paladin_import_precheck`] with the
//!    resolved import path and forced format. `PromptForPassphrase`
//!    triggers a separate bundle-passphrase prompt before calling
//!    `import::from_file`; `Reject(err)` exits with that error
//!    verbatim *without* prompting; `NoPrompt` continues with no
//!    bundle passphrase so the import facade owns auto-detect /
//!    fallthrough.
//! 4. Run [`paladin_core::import::from_file`] to materialise the
//!    `Vec<ValidatedAccount>` batch.
//! 5. Apply the merge inside [`paladin_core::Vault::mutate_and_save`]
//!    so a pre-commit save failure restores the in-memory state
//!    before the command renders its error.
//! 6. Render the §5 success envelope (`{ imported, skipped, replaced,
//!    appended, accounts, warnings }`) and, in text mode only, write
//!    each warning advisory plus a one-line skip-collision advisory
//!    when at least one row was skipped.

use std::io::Write;
use std::time::SystemTime;

use paladin_core::{
    import as core_import, AccountSummary, ImportConflict, ImportFormat, PaladinImportPrecheck,
};
use secrecy::SecretString;

use crate::cli::{GlobalArgs, ImportArgs, ImportFormatArg, OnConflictArg};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::prompt;
use crate::vault_open;

/// Entry point invoked from `main::dispatch`.
pub fn run(global: &GlobalArgs, args: &ImportArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let vault_path = vault_open::resolve_vault_path(global)?;

    let forced_format = args.format.map(map_format);
    let policy = args.on_conflict.map_or(ImportConflict::Skip, map_policy);

    let mut opened = vault_open::open(&vault_path)?;

    // Classify the import source before prompting. The precheck owns
    // the decision tree (encrypted bundle → prompt; plaintext / bad
    // header → reject; everything else → no prompt) so the CLI can
    // never drift from the TUI / GUI.
    let bundle_passphrase: Option<SecretString> =
        match core_import::classify_paladin_import_precheck(&args.path, forced_format) {
            PaladinImportPrecheck::NoPrompt => None,
            PaladinImportPrecheck::PromptForPassphrase => {
                Some(prompt::prompt_passphrase("Bundle passphrase: ")?)
            }
            PaladinImportPrecheck::Reject(err) => return Err(err.into()),
        };

    let now = SystemTime::now();
    let options = core_import::ImportOptions {
        format: forced_format,
        paladin_passphrase: bundle_passphrase,
    };
    let validated = core_import::from_file(&args.path, options, now)?;

    let report = opened
        .vault
        .mutate_and_save(&opened.store, |v| v.import_accounts(validated, policy, now))?;

    let summaries: Vec<AccountSummary> = report
        .accounts
        .iter()
        .filter_map(|id| opened.vault.get(*id).map(paladin_core::Account::summary))
        .collect();

    render_success(mode, &report, &summaries)
}

fn map_format(arg: ImportFormatArg) -> ImportFormat {
    match arg {
        ImportFormatArg::Otpauth => ImportFormat::Otpauth,
        ImportFormatArg::Aegis => ImportFormat::Aegis,
        ImportFormatArg::Paladin => ImportFormat::Paladin,
        ImportFormatArg::Qr => ImportFormat::QrImage,
    }
}

fn map_policy(arg: OnConflictArg) -> ImportConflict {
    match arg {
        OnConflictArg::Skip => ImportConflict::Skip,
        OnConflictArg::Replace => ImportConflict::Replace,
        OnConflictArg::Append => ImportConflict::Append,
    }
}

fn render_success(
    mode: Mode,
    report: &paladin_core::ImportReport,
    summaries: &[AccountSummary],
) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_qr_import_success(report, summaries, std::io::stdout().lock())
                .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            // Text mode: per-row validation warnings (e.g. short_secret)
            // first, then the optional skip-collision advisory, then
            // the stdout summary.
            for w in &report.warnings {
                let _ =
                    output::text::write_validation_warning(&w.warning, std::io::stderr().lock());
            }
            if report.skipped > 0 {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "paladin: warning: skipped {} duplicate account(s) (use --on-conflict to change behavior)",
                    report.skipped,
                );
            }
            output::text::write_qr_import_success(report, std::io::stdout().lock())
                .map_err(io_err)?;
        }
    }
    Ok(())
}

fn io_err(source: std::io::Error) -> CliError {
    CliError::Paladin(paladin_core::PaladinError::IoError {
        operation: "write_stdout",
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_format_round_trips() {
        assert_eq!(map_format(ImportFormatArg::Otpauth), ImportFormat::Otpauth);
        assert_eq!(map_format(ImportFormatArg::Aegis), ImportFormat::Aegis);
        assert_eq!(map_format(ImportFormatArg::Paladin), ImportFormat::Paladin);
        assert_eq!(map_format(ImportFormatArg::Qr), ImportFormat::QrImage);
    }

    #[test]
    fn map_policy_round_trips() {
        assert_eq!(map_policy(OnConflictArg::Skip), ImportConflict::Skip);
        assert_eq!(map_policy(OnConflictArg::Replace), ImportConflict::Replace);
        assert_eq!(map_policy(OnConflictArg::Append), ImportConflict::Append);
    }
}
