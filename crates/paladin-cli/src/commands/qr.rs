// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin qr <query>` — render an account's `otpauth://` URI as a QR
//! code (docs/DESIGN.md §4.6 / `docs/IMPLEMENTATION_PLAN_02_CLI.md`
//! "QR export command (v0.2)").
//!
//! Read-only — the vault is opened immutably, HOTP counters are not
//! advanced, and `updated_at` is never bumped. Single-match cardinality
//! (parity with `copy` / `remove` / `rename`).
//!
//! Order of operations:
//!
//! 1. Parse-time validation of `--out` / `--format` / `--module-size-px`
//!    / `--json` combinations. Fires before any vault inspection or
//!    unlock prompt so an invalid invocation never asks for a
//!    passphrase.
//! 2. Resolve the output mode and source vault path.
//! 3. Refuse to overwrite an existing `--out` target without `--force`.
//! 4. Open the source vault (`vault_open::open`) — prompts once for
//!    an encrypted vault's passphrase.
//! 5. Resolve the query through `select::resolve_unique` — `qr`
//!    always requires a single match.
//! 6. Text-mode only: print the plaintext-qr-export warning to stderr.
//! 7. Render PNG / SVG / ANSI bytes via `Vault::export_qr_*` and
//!    either persist with `write_secret_file_atomic` (`--out` set) or
//!    stream the ANSI body to stdout.
//! 8. Render the §5 success envelope (text or JSON).

use std::io::Write;
use std::path::Path;

use paladin_core::{
    format_plaintext_qr_export_warning, write_secret_file_atomic, AccountSummary, PaladinError,
    QrRenderOptions, QR_MODULE_SIZE_PX_DEFAULT, QR_MODULE_SIZE_PX_MAX, QR_MODULE_SIZE_PX_MIN,
};

use crate::cli::{GlobalArgs, QrArgs, QrFormatArg};
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::select;
use crate::vault_open;

/// Stable §5 `format` value for a PNG QR file.
const FORMAT_QR_PNG: &str = "qr_png";
/// Stable §5 `format` value for an SVG QR file.
const FORMAT_QR_SVG: &str = "qr_svg";

/// Resolved render target after parse-time validation.
#[derive(Copy, Clone, Debug)]
enum Target {
    Png,
    Svg,
    Ansi,
}

impl Target {
    fn format_label(self) -> &'static str {
        match self {
            Self::Png => FORMAT_QR_PNG,
            Self::Svg => FORMAT_QR_SVG,
            // Ansi is unreachable via `--out`; included for completeness.
            Self::Ansi => "qr_ansi",
        }
    }
}

/// Entry point invoked from `main::dispatch`.
pub fn run(global: &GlobalArgs, args: &QrArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);

    // 1. Parse-time validation (fires before vault inspection / unlock).
    //    Empty / whitespace-only `<query>` rejects with the same
    //    `validation_error { field: "query" }` shape `parse_account_query`
    //    uses for malformed `id:` prefixes — so JSON consumers see one
    //    rejection family for every bad-query case.
    if args.query.trim().is_empty() {
        return Err(validation_err("query", "empty"));
    }
    let target = resolve_target(args, mode)?;
    let module_size_px = parse_module_size_px(args.module_size_px.as_deref())?;
    let opts = QrRenderOptions {
        module_size_px,
        quiet_zone: true,
    };

    // 2. Resolve the source vault path.
    let vault_path = vault_open::resolve_vault_path(global)?;

    // 3. Overwrite gate fires before vault unlock, but only for --out.
    if let Some(out) = args.out.as_deref() {
        refuse_existing_overwrite(out, args.force)?;
    }

    // 4. Open the vault.
    let opened = vault_open::open(&vault_path)?;

    // 5. Resolve the query (single match required).
    let (id, summary) = {
        let account = select::resolve_unique(&opened.vault, &args.query)?;
        (account.id(), account.summary())
    };

    // 6. Print the warning to stderr in text mode only.
    if matches!(mode, Mode::Text { .. }) {
        let warning = format_plaintext_qr_export_warning();
        let _ = writeln!(std::io::stderr().lock(), "{warning}");
    }

    // 7. Render + persist / stream.
    match (target, args.out.as_deref()) {
        (Target::Png, Some(out)) => {
            let bytes = opened.vault.export_qr_png(id, &opts)?;
            write_secret_file_atomic(out, &bytes)?;
            render_file_success(mode, out, target.format_label(), &summary)
        }
        (Target::Svg, Some(out)) => {
            let body = opened.vault.export_qr_svg(id, &opts)?;
            write_secret_file_atomic(out, body.as_bytes())?;
            render_file_success(mode, out, target.format_label(), &summary)
        }
        (Target::Ansi, None) => {
            let body = opened.vault.export_qr_ansi(id)?;
            // ANSI body already includes the half-block glyphs and a
            // trailing newline (per the `Dense1x2` renderer); just
            // stream the bytes verbatim. No success envelope follows
            // — the rendering IS the success output in text mode, and
            // --json is rejected at parse time so ANSI never lands
            // there.
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(body.as_bytes()).map_err(io_err)?;
            Ok(())
        }
        // Unreachable: every (target, --out) pair that survives
        // `resolve_target` is one of the three above.
        _ => unreachable!("resolve_target prevents this combination"),
    }
}

/// Resolve the `(--format, --out)` pair into the rendered target, or
/// reject the invocation with the matching parse-time
/// `validation_error` envelope.
///
/// Fires before vault inspection so invalid combinations never trigger
/// a passphrase prompt.
fn resolve_target(args: &QrArgs, mode: Mode) -> Result<Target, CliError> {
    // Order: more specific (explicit --format / --out compatibility)
    // wins over the general --json contract so a user who passed
    // `--format=png --json` without `--out` gets the precise
    // `required_for_binary_format` reason rather than the catch-all
    // `required_under_json`.
    match (args.format, args.out.is_some()) {
        (Some(QrFormatArg::Ansi), true) => {
            return Err(validation_err("format", "ansi_requires_no_out"));
        }
        (Some(QrFormatArg::Png | QrFormatArg::Svg), false) => {
            return Err(validation_err("out", "required_for_binary_format"));
        }
        _ => {}
    }
    // `--json` requires `--out` — the JSON envelope owns stdout, so
    // streaming an ANSI render there would corrupt it. Only fires when
    // no explicit `--format` already disambiguated the rejection.
    if matches!(mode, Mode::Json) && args.out.is_none() {
        return Err(validation_err("out", "required_under_json"));
    }
    match (args.format, args.out.is_some()) {
        (Some(QrFormatArg::Png) | None, true) => Ok(Target::Png),
        (Some(QrFormatArg::Svg), true) => Ok(Target::Svg),
        (Some(QrFormatArg::Ansi) | None, false) => Ok(Target::Ansi),
        // The two-arm filter above eliminated every other shape.
        _ => unreachable!("resolve_target rejected these combinations above"),
    }
}

/// Parse the optional `--module-size-px` raw string into a validated
/// `u32`. Missing → `QR_MODULE_SIZE_PX_DEFAULT`. Failure modes mirror
/// the KDF flag pattern:
///
/// - Non-base-10 / negative input → `validation_error` (`field:
///   "module_size_px"`, `reason: "invalid_integer"`).
/// - In-bounds parse but outside `[QR_MODULE_SIZE_PX_MIN,
///   QR_MODULE_SIZE_PX_MAX]` → `validation_error` (`field:
///   "module_size_px"`, `reason: "out_of_bounds"`).
fn parse_module_size_px(raw: Option<&str>) -> Result<u32, CliError> {
    let Some(text) = raw else {
        return Ok(QR_MODULE_SIZE_PX_DEFAULT);
    };
    let value: u32 = text
        .parse::<u32>()
        .map_err(|_| validation_err("module_size_px", "invalid_integer"))?;
    if !(QR_MODULE_SIZE_PX_MIN..=QR_MODULE_SIZE_PX_MAX).contains(&value) {
        return Err(validation_err("module_size_px", "out_of_bounds"));
    }
    Ok(value)
}

/// Build a `validation_error` `CliError` with the §5 field / reason
/// pair. Other slots (`source_index`, `decoded_len`, `recommended_min`,
/// `entry_type`) stay `None` since this is a flag-level parse rejection.
fn validation_err(field: &'static str, reason: &'static str) -> CliError {
    CliError::Paladin(PaladinError::ValidationError {
        field,
        reason: reason.to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    })
}

/// Same `output_exists` shape that `paladin export` returns. The
/// stat-error fallback also matches: `io_error` with `operation:
/// "stat_export_path"`. Defaulting `try_exists` failures to "exists"
/// would silently overwrite, which is the worse failure mode (see
/// `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Overwrite gate").
fn refuse_existing_overwrite(path: &Path, force: bool) -> Result<(), CliError> {
    if force {
        return Ok(());
    }
    let exists = path.try_exists().map_err(|source| {
        CliError::Paladin(PaladinError::IoError {
            operation: "stat_export_path",
            source,
        })
    })?;
    if exists {
        return Err(CliError::Paladin(PaladinError::ValidationError {
            field: "out",
            reason: "exists".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
    }
    Ok(())
}

fn render_file_success(
    mode: Mode,
    path: &Path,
    format_label: &str,
    summary: &AccountSummary,
) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_qr_export_success(
                path,
                format_label,
                summary,
                std::io::stdout().lock(),
            )
            .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            output::text::write_qr_export_success(path, format_label, std::io::stdout().lock())
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
