// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-cli` library surface.
//!
//! Intentionally minimal — the binary lives in `src/main.rs` and owns
//! the full argv pre-scan, parse, dispatch, and exit-code mapping
//! per `docs/IMPLEMENTATION_PLAN_02_CLI.md` and `docs/DESIGN.md` §5.
//! This library exists solely so the workspace `xtask` crate can
//! recover the live clap `Command` for man-page rendering via
//! [`clap_command`] without duplicating the argument tree definition.
//!
//! Mirrors the lib+bin layout `paladin-tui` and `paladin-gtk` already
//! use. The `cli` module compiles into both the binary and the
//! library targets — that is intentional: `cli.rs` has no internal
//! dependencies (only `std::path::PathBuf` and `clap`), so the
//! double-compile is a no-op in practice and avoids reshaping
//! `main.rs`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cli;

use clap::CommandFactory;

/// Return the live clap `Command` for the `paladin` binary.
///
/// Consumed by `xtask::man` (via `clap_mangen`) so `paladin.1`
/// always tracks the live argument tree per
/// `docs/IMPLEMENTATION_PLAN_02_CLI.md` §"Packaging (per §11)".
#[must_use]
pub fn clap_command() -> clap::Command {
    <cli::Cli as CommandFactory>::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_command_reports_paladin_binary_name() {
        let cmd = clap_command();
        assert_eq!(
            cmd.get_name(),
            "paladin",
            "clap_command() must return the `paladin` binary's Command — \
             man-page rendering reads the name from here",
        );
    }

    #[test]
    fn clap_command_advertises_workspace_version() {
        let cmd = clap_command();
        assert_eq!(
            cmd.get_version(),
            Some(env!("CARGO_PKG_VERSION")),
            "clap_command() must surface the crate version so the rendered \
             man page header matches the workspace `[workspace.package].version`",
        );
    }

    #[test]
    fn clap_command_exposes_top_level_subcommands() {
        let cmd = clap_command();
        let names: Vec<&str> = cmd.get_subcommands().map(clap::Command::get_name).collect();
        for required in [
            "init",
            "add",
            "list",
            "show",
            "peek",
            "copy",
            "remove",
            "rename",
            "passphrase",
            "import",
            "export",
            "settings",
            "tui",
        ] {
            assert!(
                names.contains(&required),
                "clap_command() must expose `paladin {required}` — got {names:?}",
            );
        }
    }
}
