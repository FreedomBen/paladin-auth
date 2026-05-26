// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin` binary entry point: argv pre-scan, parse, dispatch, and
//! exit-code mapping per `docs/IMPLEMENTATION_PLAN_02_CLI.md` and docs/DESIGN.md
//! §5.
//!
//! Syntax errors and `--help` / `--version` requests are intercepted
//! upstream of `dispatch` so the JSON wire contract holds even when
//! clap would otherwise write text diagnostics.

#![forbid(unsafe_code)]

mod cli;
mod clipboard;
mod commands;
mod exec_tui;
mod kdf;
mod output;
mod prompt;
mod select;
mod vault_open;

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command, PassphraseCommand, SettingsCommand};
use crate::output::error::CliError;
use crate::output::Mode;

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let json_flag = output::argv_has_json_flag(&argv);

    match Cli::try_parse_from(&argv) {
        Ok(cli) => run(&cli),
        Err(err) => handle_parse_err(&err, &argv, json_flag),
    }
}

/// Dispatch a successfully parsed `Cli`. The mode is resolved here so
/// every command body inherits a single, consistent renderer choice.
fn run(cli: &Cli) -> ExitCode {
    let mode = Mode::resolve(cli.global.json, cli.global.no_color);
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = output::error::render(&err, mode, std::io::stderr().lock());
            ExitCode::from(1)
        }
    }
}

/// Routes a parsed `Cli` to the matching command module.
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
        Command::Qr(args) => commands::qr::run(global, args),
        Command::Settings { action } => match action {
            SettingsCommand::Get { key } => commands::settings::get(global, key.as_deref()),
            SettingsCommand::Set { key, value } => commands::settings::set(global, key, value),
        },
        Command::Tui => exec_tui::run(global),
    }
}

/// Map a clap parse error onto the right exit code and renderer:
/// success-terminal `--help` / `--version` are wrapped under `--json`,
/// while syntax / usage failures are routed through the §5
/// `validation_error` / `argv` / `usage` envelope.
fn handle_parse_err(err: &clap::Error, argv: &[OsString], json_flag: bool) -> ExitCode {
    use clap::error::ErrorKind as Ck;
    let kind = err.kind();
    let is_help = matches!(
        kind,
        Ck::DisplayHelp | Ck::DisplayHelpOnMissingArgumentOrSubcommand
    );
    let is_version = matches!(kind, Ck::DisplayVersion);

    if json_flag && is_help {
        let root = Cli::command();
        let argv_strs: Vec<&str> = argv.iter().filter_map(|a| a.to_str()).collect();
        let path = output::help::resolve_command_path(argv_strs.iter().copied(), &root);
        let text = render_help_text_for_path(&path, root);
        let _ = output::help::render_json(&path, &text, std::io::stdout().lock());
        let _ = std::io::stdout().flush();
        return ExitCode::SUCCESS;
    }

    if json_flag && is_version {
        let _ = output::version::render_json(std::io::stdout().lock());
        let _ = std::io::stdout().flush();
        return ExitCode::SUCCESS;
    }

    if is_help || is_version {
        // Text mode: clap renders help / version to stdout normally.
        let _ = err.print();
        return ExitCode::SUCCESS;
    }

    // Syntax / usage error.
    if json_flag {
        let usage = CliError::Usage {
            text_message: err.render().to_string(),
        };
        let _ = output::error::render(&usage, Mode::Json, std::io::stderr().lock());
    } else {
        let _ = err.print();
    }
    let code = err.exit_code().clamp(0, i32::from(u8::MAX));
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// Look up the resolved help text for a `paladin <subcommand...>` path.
/// Takes the root by value so we can walk by re-binding `current`
/// without fighting the borrow checker on `find_subcommand_mut`.
fn render_help_text_for_path(path: &str, root: clap::Command) -> String {
    let mut current = root;
    for token in path.split_whitespace().skip(1) {
        match current.find_subcommand(token).cloned() {
            Some(sub) => current = sub,
            None => break,
        }
    }
    current.render_help().to_string()
}
