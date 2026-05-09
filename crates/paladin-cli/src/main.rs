// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin` binary entry point: parses argv, dispatches to command modules,
//! and maps results to process exit codes per `IMPLEMENTATION_PLAN_02_CLI.md`.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod exec_tui;
mod output;
mod prompt;
mod select;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, PassphraseCommand, SettingsCommand};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("paladin: {err}");
            ExitCode::from(1)
        }
    }
}

/// Routes a parsed [`Cli`] to the matching command module.
fn dispatch(cli: &Cli) -> Result<(), CliError> {
    let global = &cli.global;
    match &cli.command {
        Command::Init(args) => commands::init::run(global, args),
        Command::Add(args) => commands::add::run(global, args),
        Command::List => commands::list::run(global),
        Command::Show(args) => commands::show::run(global, args),
        Command::Peek(args) => commands::peek::run(global, args),
        Command::Copy(args) => commands::copy::run(global, args),
        Command::Remove(args) => commands::remove::run(global, args),
        Command::Rename(args) => commands::rename::run(global, args),
        Command::Passphrase { action } => match action {
            PassphraseCommand::Set { kdf } => commands::passphrase::set(global, kdf),
            PassphraseCommand::Change { kdf } => commands::passphrase::change(global, kdf),
            PassphraseCommand::Remove { yes } => commands::passphrase::remove(global, *yes),
        },
        Command::Import(args) => commands::import::run(global, args),
        Command::Export(args) => commands::export::run(global, args),
        Command::Settings { action } => match action {
            SettingsCommand::Get { key } => commands::settings::get(global, key.as_deref()),
            SettingsCommand::Set { key, value } => commands::settings::set(global, key, value),
        },
        Command::Tui => exec_tui::run(global),
    }
}

/// CLI-internal error surface used while command bodies are stubbed. Once
/// each command lands, it will return [`paladin_core::PaladinError`] directly
/// and this enum will shrink accordingly.
#[derive(Debug)]
pub enum CliError {
    /// The command's body has not yet been implemented in this scaffold.
    NotYetImplemented(&'static str),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotYetImplemented(name) => {
                write!(f, "command '{name}' is not yet implemented")
            }
        }
    }
}

impl std::error::Error for CliError {}
