// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin destroy [--yes]` — permanently delete the vault file (and
//! its `.bak`) from disk. See docs/DESIGN.md §4.3 / §5 and
//! `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Destroy command (Milestone 10)".
//!
//! Order of operations (locked by the plan):
//!
//! 1. Parse-time rejections, before any disk I/O so an invalid
//!    invocation never touches the filesystem. (a) Any KDF flag set →
//!    `validation_error` (`field: "argv"`,
//!    `reason: "kdf_flags_not_supported"`); destroy runs no Argon2id
//!    work, so surfacing the flags as supported would be a lie, and
//!    this rejection wins precedence over `vault_missing` and the
//!    confirmation prompt. (b) `--json` without `--yes` →
//!    `validation_error` (`field: "argv"`,
//!    `reason: "confirmation_required"`), parallel to `remove` /
//!    `passphrase remove`.
//! 2. Resolve the vault path through the same `--vault` /
//!    `default_vault_path()` pipeline every command uses.
//! 3. Probe the sibling `vault.bin.bak` with `Path::try_exists` to
//!    populate `backup_present` for the warning helper. A probe error
//!    surfaces as `io_error` (`operation: "stat_backup_file"`) with the
//!    resolved `path`. The CLI never calls `Store::open` / `inspect` —
//!    destroy must work on a corrupted or perms-drifted vault.
//! 4. Text mode: print `format_destroy_warning(path, backup_present)`
//!    to stderr; unless `--yes`, confirm on `/dev/tty` (decline →
//!    `validation_error` `field: "confirmation"` / `reason: "declined"`;
//!    no `/dev/tty` → `io_error` `confirmation_prompt`). Under `--json`
//!    the warning is suppressed (strict-mode: the JSON envelope owns
//!    stdout).
//! 5. Call `paladin_core::destroy_vault(path)` and render the result.

use std::io::Write;

use paladin_core::{format_destroy_warning, PaladinError};

use crate::cli::{DestroyArgs, GlobalArgs, KdfArgs};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::prompt;
use crate::vault_open;

pub fn run(global: &GlobalArgs, args: &DestroyArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);

    // (1a) KDF flags are never honored by destroy; reject before any
    // I/O. Wins precedence over vault_missing and the confirmation
    // prompt.
    if kdf_flags_present(&args.kdf) {
        return Err(argv_validation("kdf_flags_not_supported"));
    }

    // (1b) Strict-mode: `--json` without `--yes` is rejected before any
    // disk I/O so no prompt strings reach the JSON streams.
    if matches!(mode, Mode::Json) && !args.yes {
        return Err(argv_validation("confirmation_required"));
    }

    // (2) Resolve the path the same way every other command does.
    let path = vault_open::resolve_vault_path(global)?;

    // (3) Probe the sibling `.bak` for the warning helper. A probe error
    // (e.g. parent dir unreadable) is an `io_error` carrying the path.
    let backup_path = path.with_file_name("vault.bin.bak");
    let backup_present = backup_path
        .try_exists()
        .map_err(|source| CliError::DestroyIo {
            path: path.clone(),
            source: PaladinError::IoError {
                operation: "stat_backup_file",
                source,
            },
        })?;

    // (4) Destructive confirmation. The warning prints to stderr in text
    // mode (even under `--yes`); under `--json` it is suppressed.
    if let Mode::Text { .. } = mode {
        let warning = format_destroy_warning(&path, backup_present);
        // Best-effort: a stderr write failure must not abort the
        // destroy the user already confirmed via flags. Mirrors the
        // other commands' advisory writes.
        let _ = writeln!(std::io::stderr().lock(), "{warning}");
    }
    if !args.yes {
        prompt::prompt_destructive_confirmation(&format!(
            "{} Type 'yes' to confirm: ",
            format_destroy_warning(&path, backup_present),
        ))?;
    }

    // (5) Dispatch to core and render. destroy_vault owns the symlink
    // probe, unlink sequence, and parent fsync.
    let report = paladin_core::destroy_vault(&path).map_err(|err| map_destroy_err(&path, err))?;

    render(mode, &path, report)
}

/// `true` if any Argon2id KDF flag was supplied on the argv.
fn kdf_flags_present(kdf: &KdfArgs) -> bool {
    kdf.kdf_memory_mib.is_some() || kdf.kdf_time.is_some() || kdf.kdf_parallelism.is_some()
}

/// Build an `argv` `validation_error` with the given stable reason.
fn argv_validation(reason: &str) -> CliError {
    CliError::Paladin(PaladinError::ValidationError {
        field: "argv",
        reason: reason.to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    })
}

/// Map a `destroy_vault` error onto the path-aware CLI envelope. The
/// `vault_missing` and `io_error` envelopes both carry the resolved
/// `path`; post-primary `DestroyIoError`s additionally carry
/// `primary_deleted` / `backup_deleted` (preserved by `DestroyIo`).
fn map_destroy_err(path: &std::path::Path, err: PaladinError) -> CliError {
    match err {
        PaladinError::VaultMissing => CliError::DestroyVaultMissing {
            path: path.to_path_buf(),
        },
        source @ (PaladinError::IoError { .. } | PaladinError::DestroyIoError { .. }) => {
            CliError::DestroyIo {
                path: path.to_path_buf(),
                source,
            }
        }
        // destroy_vault only returns the variants above; pass anything
        // else through verbatim rather than masking an unexpected kind.
        other => CliError::Paladin(other),
    }
}

fn render(
    mode: Mode,
    path: &std::path::Path,
    report: paladin_core::DestroyReport,
) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_destroy_success(
                path,
                report.primary_deleted,
                report.backup_deleted,
                std::io::stdout().lock(),
            )
            .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            output::text::write_destroy_success(report.backup_deleted, std::io::stdout().lock())
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
