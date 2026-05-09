// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin add` — add an account interactively, from `--uri`, manual
//! flags, or `--qr`. See DESIGN.md §5 and `IMPLEMENTATION_PLAN_02_CLI.md`
//! "Add modes".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Resolve mode from flags. Combining `--uri`, `--qr`, and manual
//!    flags is rejected at parse time by clap; `--allow-duplicate` is
//!    rejected at parse time when paired with `--qr`. Under `--json`,
//!    interactive mode (no input flags at all) is additionally rejected
//!    here as `validation_error` before any prompt or vault open.
//! 2. Build a [`paladin_core::ValidatedAccount`] from the chosen input
//!    mode. `--uri` calls [`paladin_core::parse_otpauth`]; manual flags
//!    and interactive prompts build an
//!    [`paladin_core::AccountInput`] and route it through
//!    [`paladin_core::validate_manual`] so §4.1 validation lives in
//!    core. `--qr` defers to [`paladin_core::import::from_file`] with a
//!    fixed `ImportConflict::Skip` policy and is multi-entry.
//! 3. Open the vault via the shared open pipeline.
//! 4. For single-entry modes, call [`paladin_core::Vault::find_duplicate`]
//!    against the running vault. A collision without `--allow-duplicate`
//!    rejects with [`CliError::DuplicateAccount`] before any save.
//! 5. Mutate via [`paladin_core::Vault::mutate_and_save`] so a
//!    pre-commit `save_not_committed` failure restores the in-memory
//!    state before the command renders its error.
//! 6. Render the §5 success envelope and, in text mode only, write
//!    `short_secret` validation warnings to stderr.

use std::io::Write;
use std::time::SystemTime;

use paladin_core::{
    format_validation_warning, import as core_import, parse_otpauth, validate_manual, AccountId,
    AccountInput, AccountKindInput, AccountSummary, Algorithm, IconHintInput, ImportConflict,
    PaladinError, ValidatedAccount, Vault,
};
use secrecy::SecretString;

use crate::cli::{AddArgs, AlgorithmArg, GlobalArgs, KindArg};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::prompt;
use crate::vault_open;

/// Entry point invoked from `main::dispatch`.
pub fn run(global: &GlobalArgs, args: &AddArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let input_mode = classify_input_mode(args);

    // Under `--json`, interactive mode is rejected before any I/O so
    // prompt strings cannot leak onto stdout/stderr (per §5).
    if matches!(mode, Mode::Json) && matches!(input_mode, InputMode::Interactive) {
        return Err(CliError::Paladin(PaladinError::ValidationError {
            field: "argv",
            reason: "interactive_add_requires_input_flags_under_json".into(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
    }

    let path = vault_open::resolve_vault_path(global)?;

    match input_mode {
        InputMode::Qr => add_qr(mode, &path, args),
        InputMode::Uri => {
            let uri = args
                .uri
                .as_deref()
                .expect("classified Uri implies --uri set");
            let now = SystemTime::now();
            let validated = parse_otpauth(uri, now)?;
            add_single(mode, &path, args, validated)
        }
        InputMode::Manual => {
            let input = build_manual_input(args)?;
            let validated = validate_manual(input, SystemTime::now())?;
            add_single(mode, &path, args, validated)
        }
        InputMode::Interactive => {
            let input = collect_interactive_input(args)?;
            let validated = validate_manual(input, SystemTime::now())?;
            add_single(mode, &path, args, validated)
        }
    }
}

/// Which add mode the user chose. Mode-combination conflicts are
/// rejected at parse time by clap (`AddArgs` `conflicts_with_*`); this
/// classifier just picks the single live mode.
#[derive(Debug, Clone, Copy)]
enum InputMode {
    Uri,
    Qr,
    Manual,
    Interactive,
}

fn classify_input_mode(args: &AddArgs) -> InputMode {
    if args.uri.is_some() {
        return InputMode::Uri;
    }
    if args.qr.is_some() {
        return InputMode::Qr;
    }
    if has_any_manual_field(args) {
        return InputMode::Manual;
    }
    InputMode::Interactive
}

fn has_any_manual_field(args: &AddArgs) -> bool {
    args.label.is_some()
        || args.secret.is_some()
        || args.issuer.is_some()
        || args.algorithm.is_some()
        || args.digits.is_some()
        || args.kind.is_some()
        || args.period.is_some()
        || args.counter.is_some()
        || args.icon_hint.is_some()
        || args.no_icon_hint
}

fn add_single(
    mode: Mode,
    path: &std::path::Path,
    args: &AddArgs,
    validated: ValidatedAccount,
) -> Result<(), CliError> {
    let mut opened = vault_open::open(path)?;

    if !args.allow_duplicate {
        if let Some(existing) = opened.vault.find_duplicate(&validated) {
            return Err(CliError::DuplicateAccount {
                account: existing.summary(),
            });
        }
    }

    let warnings = validated.warnings.clone();
    let account = validated.account;
    let summary = account.summary();

    let id: AccountId = opened
        .vault
        .mutate_and_save(&opened.store, move |v| Ok(v.add(account)))?;

    render_single_success(mode, &opened.vault, id, &summary, &warnings)
}

fn add_qr(mode: Mode, path: &std::path::Path, args: &AddArgs) -> Result<(), CliError> {
    let qr_path = args.qr.as_ref().expect("classified Qr implies --qr set");
    let now = SystemTime::now();

    let mut opened = vault_open::open(path)?;

    let options = core_import::ImportOptions {
        format: None,
        paladin_passphrase: None,
    };
    let validated = core_import::from_file(qr_path, options, now)?;

    let report = opened.vault.mutate_and_save(&opened.store, |v| {
        v.import_accounts(validated, ImportConflict::Skip, now)
    })?;

    let summaries: Vec<AccountSummary> = report
        .accounts
        .iter()
        .filter_map(|id| opened.vault.get(*id).map(paladin_core::Account::summary))
        .collect();

    match mode {
        Mode::Json => {
            output::json::write_qr_import_success(&report, &summaries, std::io::stdout().lock())
                .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            for warning in &report.warnings {
                let _ = output::text::write_validation_warning(
                    &warning.warning,
                    std::io::stderr().lock(),
                );
            }
            output::text::write_qr_import_success(&report, std::io::stdout().lock())
                .map_err(io_err)?;
        }
    }
    Ok(())
}

fn render_single_success(
    mode: Mode,
    vault: &Vault,
    id: AccountId,
    summary: &AccountSummary,
    warnings: &[paladin_core::ValidationWarning],
) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_add_success(summary, warnings, std::io::stdout().lock())
                .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            // Stderr advisories first so the success line on stdout is
            // the last byte the user sees.
            for warning in warnings {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "paladin: warning: {}",
                    format_validation_warning(warning),
                );
            }
            let disambiguator = vault
                .shortest_unique_id_prefix(id)
                .map_or_else(|| "id:?".to_string(), |hex| format!("id:{hex}"));
            output::text::write_add_success(summary, &disambiguator, std::io::stdout().lock())
                .map_err(io_err)?;
        }
    }
    Ok(())
}

// --- Manual input construction --------------------------------------------

fn build_manual_input(args: &AddArgs) -> Result<AccountInput, CliError> {
    let label = args
        .label
        .clone()
        .ok_or_else(|| validation_err("label", "missing"))?;
    let secret = args
        .secret
        .clone()
        .ok_or_else(|| validation_err("secret", "missing"))?;

    let kind = match args.kind {
        Some(KindArg::Hotp) => AccountKindInput::Hotp,
        Some(KindArg::Totp) | None => AccountKindInput::Totp,
    };
    let algorithm = match args.algorithm {
        Some(AlgorithmArg::Sha256) => Algorithm::Sha256,
        Some(AlgorithmArg::Sha512) => Algorithm::Sha512,
        Some(AlgorithmArg::Sha1) | None => Algorithm::Sha1,
    };
    let digits = u8::try_from(args.digits.unwrap_or(6))
        .map_err(|_| validation_err("digits", "out_of_range"))?;
    let icon_hint = if args.no_icon_hint {
        IconHintInput::Clear
    } else if let Some(slug) = args.icon_hint.clone() {
        IconHintInput::Slug(slug)
    } else {
        IconHintInput::Default
    };

    Ok(AccountInput {
        label,
        issuer: args.issuer.clone(),
        secret: SecretString::from(secret),
        algorithm,
        digits,
        kind,
        period_secs: args.period,
        counter: args.counter,
        icon_hint,
    })
}

// --- Interactive input collection -----------------------------------------

fn collect_interactive_input(args: &AddArgs) -> Result<AccountInput, CliError> {
    let label = prompt::prompt_account_line("Label: ")?;
    let issuer_line = prompt::prompt_account_line("Issuer (optional): ")?;
    let issuer = if issuer_line.is_empty() {
        None
    } else {
        Some(issuer_line)
    };
    let secret = prompt::prompt_account_secret("Secret (Base32): ")?;

    let algorithm = match args.algorithm {
        Some(AlgorithmArg::Sha256) => Algorithm::Sha256,
        Some(AlgorithmArg::Sha512) => Algorithm::Sha512,
        Some(AlgorithmArg::Sha1) | None => Algorithm::Sha1,
    };
    let digits_line = prompt::prompt_account_line("Digits [6]: ")?;
    let digits: u8 = if digits_line.is_empty() {
        6
    } else {
        digits_line
            .parse()
            .map_err(|_| validation_err("digits", "invalid_integer"))?
    };
    let kind_line = prompt::prompt_account_line("Kind [totp/hotp, default totp]: ")?;
    let kind = match kind_line.trim().to_ascii_lowercase().as_str() {
        "" | "totp" => AccountKindInput::Totp,
        "hotp" => AccountKindInput::Hotp,
        _ => return Err(validation_err("kind", "unknown")),
    };

    let (period_secs, counter) = match kind {
        AccountKindInput::Totp => {
            let period_line = prompt::prompt_account_line("Period seconds [30]: ")?;
            let period_secs = if period_line.is_empty() {
                None
            } else {
                Some(
                    period_line
                        .parse()
                        .map_err(|_| validation_err("period", "invalid_integer"))?,
                )
            };
            (period_secs, None)
        }
        AccountKindInput::Hotp => {
            let counter_line = prompt::prompt_account_line("Counter [0]: ")?;
            let counter = if counter_line.is_empty() {
                None
            } else {
                Some(
                    counter_line
                        .parse()
                        .map_err(|_| validation_err("counter", "invalid_integer"))?,
                )
            };
            (None, counter)
        }
    };

    let icon_hint_line =
        prompt::prompt_account_line("Icon hint (slug, blank for default, 'none' to clear): ")?;
    let icon_hint = paladin_core::parse_icon_hint_token(&icon_hint_line)?;

    Ok(AccountInput {
        label,
        issuer,
        secret,
        algorithm,
        digits,
        kind,
        period_secs,
        counter,
        icon_hint,
    })
}

fn validation_err(field: &'static str, reason: &str) -> CliError {
    CliError::Paladin(PaladinError::ValidationError {
        field,
        reason: reason.to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    })
}

fn io_err(source: std::io::Error) -> CliError {
    CliError::Paladin(PaladinError::IoError {
        operation: "write_stdout",
        source,
    })
}
