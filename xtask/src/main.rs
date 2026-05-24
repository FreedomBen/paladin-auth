// SPDX-License-Identifier: AGPL-3.0-or-later

//! Workspace orchestrator. See `docs/DESIGN.md` §11.2.
//!
//! Subcommands implemented in v0.2 Milestone 7:
//!
//! * `cargo xtask man` — render clap-derived man pages for `paladin`
//!   and `paladin-tui` into `target/man/`. The packaging pipeline
//!   sources the gzipped output from there.
//! * `cargo xtask package --frontend <name> --format rpm` — build the
//!   release binary, render + gzip the man page when applicable, and
//!   produce a `.rpm` via `nfpm` running inside the
//!   `docker.io/goreleaser/nfpm` image under rootless podman. Output
//!   lands in `target/dist/`.
//!
//! `.deb`, Flatpak, and `AppImage` formats land alongside the matching
//! pipelines in follow-up Milestone 7 commits per
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod man;
mod package;

#[derive(Debug, Parser)]
#[command(
    name = "xtask",
    version,
    about = "Paladin workspace orchestrator (see docs/DESIGN.md §11.2)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Render clap-derived man pages for `paladin` and `paladin-tui`.
    Man(man::Args),

    /// Build a distributable artifact for one front-end.
    Package(package::Args),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Man(args) => man::run(&args),
        Command::Package(args) => package::run(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err}");
            ExitCode::FAILURE
        }
    }
}
