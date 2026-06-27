// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-auth tui` exec wrapper: resolves `paladin-auth-tui` on `PATH` and
//! `execvp`s it, forwarding `--vault` and `--no-color` verbatim. See
//! `docs/IMPLEMENTATION_PLAN_02_CLI.md` "`paladin-auth tui` exec wrapper" and
//! docs/DESIGN.md §5.
//!
//! `--json` is rejected here (rather than during clap parsing) so the
//! wrapper participates in the same `validation_error` `field: "argv"`
//! pattern used by `add --json` interactive mode and `remove --json`
//! without `--yes`. The success-terminal `--help` path is intercepted
//! upstream in `main::handle_parse_err`, so this function is never
//! reached for `paladin-auth --json tui --help` and the empty-PATH branch
//! does not need to special-case it.

use std::os::unix::process::CommandExt;
use std::process::Command;

use paladin_auth_core::PaladinAuthError;

use crate::cli::GlobalArgs;
use crate::output::error::CliError;

/// Reject `--json` (the TUI has no JSON mode), forward `--vault` and
/// `--no-color` to `paladin-auth-tui`, and `execvp` it. On success the
/// caller process is replaced by `paladin-auth-tui` and this function does
/// not return; on `exec` failure (most commonly `paladin-auth-tui` not on
/// `PATH`) the underlying `io::Error` is wrapped in
/// `PaladinAuthError::IoError` with the §5 stable operation tag
/// `"exec_paladin_auth_tui"`.
pub fn run(global: &GlobalArgs) -> Result<(), CliError> {
    if global.json {
        return Err(CliError::PaladinAuth(PaladinAuthError::ValidationError {
            field: "argv",
            reason: "tui_unsupported_under_json".into(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
    }

    let mut cmd = Command::new("paladin-auth-tui");
    if let Some(vault) = &global.vault {
        cmd.arg("--vault").arg(vault);
    }
    if global.no_color {
        cmd.arg("--no-color");
    }

    // `exec` only returns on failure (e.g. `paladin-auth-tui` not on `PATH`,
    // or the located file is not executable). On success the kernel
    // replaces the running paladin-auth process and the function never
    // returns to the caller.
    let err = cmd.exec();
    Err(CliError::PaladinAuth(PaladinAuthError::IoError {
        operation: "exec_paladin_auth_tui",
        source: err,
    }))
}
