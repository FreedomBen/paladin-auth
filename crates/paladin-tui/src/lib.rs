// SPDX-License-Identifier: AGPL-3.0-or-later

//! `paladin-tui` library surface.
//!
//! See `IMPLEMENTATION_PLAN_03_TUI.md` and `DESIGN.md` §6. The binary
//! at `src/main.rs` is a thin shim that hands off to [`run`]; everything
//! else lives in submodules so the reducer / state-machine and helpers
//! can be exercised by integration tests in `tests/` without going
//! through a terminal.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::cell::RefCell;
use std::io;
use std::process::ExitCode;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::SystemTime;

use ratatui::backend::Backend;
use ratatui::Terminal;

pub mod app;
pub mod cli;
pub mod clipboard;
pub mod keybindings;
pub mod prompt;
pub mod search;
pub mod terminal;
pub mod view;

use crate::app::event::AppEvent;
use crate::app::state::AppState;
use crate::terminal::TerminalBackend;

/// Run the `paladin-tui` binary.
///
/// Parses [`cli::GlobalArgs`] from `std::env::args_os` and hands the
/// production composition off to [`run_with_components`] with the real
/// stdout/stderr writers, the real
/// [`crate::terminal::CrosstermBackend`] lifecycle backend, a
/// [`ratatui::Terminal`] over [`ratatui::backend::CrosstermBackend`],
/// the wall-clock seed sampled at entry, and the production
/// [`crate::app::input::spawn`] / [`crate::app::ticker::spawn`]
/// producers.
///
/// A clap parse error short-circuits through [`clap::Error::exit`],
/// which writes the standard usage / `--help` / `--version` text and
/// exits the process with clap's own code; we never return on that
/// branch.
#[must_use]
pub fn run() -> ExitCode {
    use clap::Parser;

    let args = match cli::GlobalArgs::try_parse() {
        Ok(args) => args,
        // `Error::exit` writes clap's text diagnostic / help / version
        // output and exits with the appropriate code (`2` for usage
        // errors, `0` for `--help` / `--version`). Never returns.
        Err(err) => err.exit(),
    };

    run_with_components(
        args,
        terminal::CrosstermBackend::stdout(),
        || Terminal::new(ratatui::backend::CrosstermBackend::new(io::stdout())),
        app::input::spawn,
        app::ticker::spawn,
        SystemTime::now(),
        io::stderr().lock(),
    )
}

/// Top-level composer that ties together the parsed CLI args, the
/// initial-state builder, the ratatui [`Terminal`] construction, the
/// lifecycle [`TerminalBackend`], the render-error sink, and the
/// `ExitCode` mapper into a single call.
///
/// This is the testable surface beneath [`run`]: production wires the
/// real backends + producers + writers, while integration tests in
/// `tests/run_tests.rs` pass fakes (a recording lifecycle backend, a
/// `ratatui::backend::TestBackend`, a one-shot Ctrl-C input spawner,
/// a vector stderr sink) so the contract that [`run`] depends on is
/// pinned without a TTY.
///
/// Order of operations:
///
/// 1. Build the initial [`AppState`] from `args.vault` via
///    [`crate::app::build_initial_state`] (which resolves the default
///    vault path through `paladin_core::default_vault_path` when the
///    override is `None`).
/// 2. Invoke `make_terminal` to construct the ratatui [`Terminal`].
///    If this fails, the composer short-circuits with
///    [`ExitCode::FAILURE`] and the same `paladin-tui: <err>` stderr
///    advisory that a [`crate::terminal::TerminalGuard::setup`]
///    failure would emit — without touching `lifecycle_backend` or
///    invoking either spawner. Sequencing the terminal construction
///    BEFORE the guard means a `Terminal::new` failure cannot leak
///    raw-mode escape sequences onto the user's primary screen.
/// 3. Allocate the render-error sink and build the render closure
///    via [`crate::app::build_render_closure`].
/// 4. Run the event loop under
///    [`crate::app::run_with_terminal_guard`].
/// 5. Merge any render failure captured by the sink into the loop
///    result via [`crate::app::merge_render_failure_into_run_result`]
///    so a draw failure surfaces on the same advisory path as a
///    setup failure.
/// 6. Map the merged result onto an [`ExitCode`] via
///    [`crate::app::exit_code_from_run_result`].
#[must_use]
pub fn run_with_components<B, TB, MT, I, T, W>(
    args: cli::GlobalArgs,
    lifecycle_backend: TB,
    make_terminal: MT,
    spawn_input: I,
    spawn_ticker: T,
    initial_wall_clock: SystemTime,
    mut stderr: W,
) -> ExitCode
where
    B: Backend,
    TB: TerminalBackend,
    MT: FnOnce() -> io::Result<Terminal<B>>,
    I: FnOnce(Sender<AppEvent>) -> JoinHandle<()>,
    T: FnOnce(Sender<AppEvent>) -> JoinHandle<()>,
    W: io::Write,
{
    let initial_state = app::build_initial_state(args.vault);

    let mut terminal = match make_terminal() {
        Ok(t) => t,
        Err(err) => {
            // Short-circuit before any lifecycle work or spawner
            // runs. Funnel through the same `exit_code_from_run_result`
            // path used by `TerminalGuard::setup` failures so users
            // see one stderr-advisory shape regardless of which side
            // failed.
            let result: io::Result<AppState> = Err(err);
            return app::exit_code_from_run_result(result, &mut stderr);
        }
    };

    let error_sink: RefCell<Option<io::Error>> = RefCell::new(None);
    let render = app::build_render_closure(&mut terminal, &error_sink);

    let run_result = app::run_with_terminal_guard(
        initial_state,
        lifecycle_backend,
        render,
        spawn_input,
        spawn_ticker,
        initial_wall_clock,
    );

    // `render` (and its borrow of the sink + terminal) was dropped
    // when `run_with_terminal_guard` returned; the sink is now
    // moveable.
    let merged = app::merge_render_failure_into_run_result(run_result, error_sink.into_inner());

    app::exit_code_from_run_result(merged, &mut stderr)
}
