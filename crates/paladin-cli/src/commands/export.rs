// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin export` — write the vault to a file (DESIGN.md §5).
//!
//! Two modes selected via the (clap-required) mutually-exclusive flags
//! `--plaintext <path>` (JSON `otpauth://` array) and `--encrypted
//! <path>` (Paladin-format encrypted bundle). Both modes refuse to
//! overwrite without `--force`, both write through
//! [`paladin_core::write_secret_file_atomic`] so the destination ends up
//! `0600`, and both render the §5 stable success envelope (`{ "written":
//! ..., "format": "otpauth"|"paladin" }`) on completion.
//!
//! Order of operations (locked by `IMPLEMENTATION_PLAN_02_CLI.md`
//! "Vault interaction pattern" / "Encrypted-write KDF flags"):
//!
//! 1. Resolve the output mode and source vault path.
//! 2. (`--encrypted` only) Parse + validate the KDF flags. Errors here
//!    win over `vault_missing`, the source-vault unlock prompt, the
//!    overwrite-existing-file check, and the bundle-passphrase prompt.
//! 3. Refuse overwrite when the destination path already exists and
//!    `--force` is absent (`validation_error`, `field: "path"`,
//!    `reason: "output_exists"`). Pre-empts the unlock prompt so the
//!    user is never asked for a passphrase only to find the write
//!    blocked.
//! 4. Open the source vault via [`vault_open::open`] (prompts once for
//!    an encrypted *vault* unlock — distinct from any export-bundle
//!    passphrase).
//! 5. (`--plaintext` only, text mode) Print
//!    [`paladin_core::format_plaintext_export_warning`] to stderr.
//!    Suppressed under `--json` because the caller opted in via
//!    `--plaintext`.
//! 6. (`--encrypted` only) Prompt for a fresh export-bundle passphrase
//!    plus a matching confirmation (Reject empty-entry policy). The
//!    bundle passphrase is independent of the source vault's own
//!    passphrase per DESIGN §4.6.
//! 7. Render bytes via [`paladin_core::export::otpauth_list`] /
//!    [`paladin_core::export::encrypted`].
//! 8. Persist via [`paladin_core::write_secret_file_atomic`] (output is
//!    always `0600`).
//! 9. Render the §5 success envelope.

use std::io::Write;
use std::path::Path;

use paladin_core::{
    export, format_plaintext_export_warning, write_secret_file_atomic, EncryptionOptions,
    PaladinError,
};

use crate::cli::{ExportArgs, GlobalArgs};
use crate::kdf;
use crate::output::error::CliError;
use crate::output::{self, Mode};
use crate::prompt::{self, NewPassphraseEmptyPolicy};
use crate::vault_open;

/// Stable §5 `format` value for plaintext export (JSON `otpauth://` array).
const FORMAT_OTPAUTH: &str = "otpauth";
/// Stable §5 `format` value for an encrypted Paladin-bundle export.
const FORMAT_PALADIN: &str = "paladin";

/// Selected export target after disambiguating the (clap-enforced)
/// mutually-exclusive `--plaintext` / `--encrypted` flags.
enum Target<'a> {
    Plaintext(&'a Path),
    Encrypted(&'a Path),
}

impl Target<'_> {
    fn output_path(&self) -> &Path {
        match self {
            Self::Plaintext(p) | Self::Encrypted(p) => p,
        }
    }

    fn format_label(&self) -> &'static str {
        match self {
            Self::Plaintext(_) => FORMAT_OTPAUTH,
            Self::Encrypted(_) => FORMAT_PALADIN,
        }
    }
}

/// Entry point invoked from `main::dispatch`.
pub fn run(global: &GlobalArgs, args: &ExportArgs) -> Result<(), CliError> {
    let mode = Mode::resolve(global.json, global.no_color);
    let vault_path = vault_open::resolve_vault_path(global)?;

    let target = match (args.plaintext.as_deref(), args.encrypted.as_deref()) {
        (Some(p), None) => Target::Plaintext(p),
        (None, Some(p)) => Target::Encrypted(p),
        // The `export_target` ArgGroup is `required(true)` and the
        // two flags conflict, so clap rejects both-None and both-Some
        // before dispatch.
        _ => unreachable!("clap ArgGroup enforces exactly-one-of plaintext/encrypted"),
    };
    let output_path = target.output_path();

    // KDF parsing wins over `vault_missing`, the unlock prompt, the
    // overwrite check, and the bundle-passphrase prompt — locked by
    // the §5 ordering rule. Only the encrypted branch consumes the
    // result; for `--plaintext` the flags carry no semantic meaning,
    // so we skip the parse there entirely.
    let argon = match &target {
        Target::Encrypted(_) => Some(kdf::parse_argon2_params(&args.kdf)?),
        Target::Plaintext(_) => None,
    };

    refuse_existing_overwrite(output_path, args.force)?;

    let opened = vault_open::open(&vault_path)?;

    let bytes = match &target {
        Target::Plaintext(_) => {
            if matches!(mode, Mode::Text { .. }) {
                let warning = format_plaintext_export_warning();
                let _ = writeln!(std::io::stderr().lock(), "{warning}");
            }
            export::otpauth_list(&opened.vault).into_bytes()
        }
        Target::Encrypted(_) => {
            let pp = prompt::prompt_new_passphrase(
                "Export passphrase: ",
                "Confirm passphrase: ",
                NewPassphraseEmptyPolicy::Reject,
            )?
            .expect("Reject policy never returns Ok(None)");

            // `argon` is `Some` for the encrypted branch by construction.
            let params = argon.expect("encrypted branch parses KDF params above");
            let options = EncryptionOptions::with_params(pp, params)?;
            export::encrypted(&opened.vault, options)?
        }
    };

    write_secret_file_atomic(output_path, &bytes)?;

    render_success(mode, output_path, target.format_label())
}

/// Return `validation_error { field: "path", reason: "output_exists" }`
/// when the destination already exists and `--force` was not supplied.
/// `try_exists` failures (e.g. permission-denied stat on a parent
/// directory) propagate as `io_error` with `operation:
/// "stat_export_path"` so the user sees the underlying cause rather
/// than a misleading "exists" / "doesn't exist" answer.
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
            field: "path",
            reason: "output_exists".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
    }
    Ok(())
}

fn render_success(mode: Mode, path: &Path, format_label: &str) -> Result<(), CliError> {
    match mode {
        Mode::Json => {
            output::json::write_export_success(path, format_label, std::io::stdout().lock())
                .map_err(io_err)?;
        }
        Mode::Text { .. } => {
            output::text::write_export_success(path, format_label, std::io::stdout().lock())
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
