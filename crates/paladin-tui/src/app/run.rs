// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production composers for the TUI event loop.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//!
//! > Effects are executed by `app::run`, which is the only boundary
//! > that may call impure core / clipboard / writer functions.
//!
//! Two composers live here, layered from inside out:
//!
//! * [`run_event_loop`] is the inner, terminal-free composer that
//!   owns the `mpsc<AppEvent>` channel + producer spawning + the
//!   [`crate::app::dispatch::dispatch`] call. Production callers pass
//!   [`crate::app::input::spawn`] and [`crate::app::ticker::spawn`]
//!   as the producer spawners; tests in
//!   `crates/paladin-tui/tests/run_tests.rs` pass fake spawners that
//!   drive the channel synchronously so the sender-clone + dispatch
//!   completion contract is exercised without a TTY. Keeping this
//!   composer terminal-free is what makes it unit-testable against
//!   `dispatch`.
//!
//! * [`run_with_terminal_guard`] is the outer composer that wraps a
//!   [`crate::terminal::TerminalGuard`] around `run_event_loop` so
//!   the production path enables raw mode + the alternate screen
//!   before the first render and restores both on normal exit,
//!   `Ctrl-C` (which funnels through the reducer as
//!   `Effect::Quit`), setup failure, and panic unwind. The guard's
//!   own rollback / drop / panic semantics are pinned in
//!   `crates/paladin-tui/tests/terminal_tests.rs`; the tests in
//!   `run_tests.rs` cover the additional contract this composer
//!   adds (setup-before-first-render, teardown-after-quit,
//!   panic-unwind survival, setup-failure short-circuit).

use std::cell::RefCell;
use std::io;
use std::io::Write;
use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::SystemTime;

use ratatui::backend::Backend;
use ratatui::Terminal;

use crate::app::dispatch::dispatch;
use crate::app::event::AppEvent;
use crate::app::render::draw_frame;
use crate::app::state::AppState;
use crate::terminal::{TerminalBackend, TerminalGuard};

/// Run the event loop with the supplied producer spawners.
///
/// Creates the `mpsc<AppEvent>` channel that backs the loop, hands a
/// freshly cloned sender to each producer spawner, then runs
/// [`dispatch`] against `render` until an effect returns
/// [`crate::app::EffectOutcome::Quit`] or every sender is dropped.
/// Returns the final [`AppState`] for the caller to inspect.
///
/// Production callers pass [`crate::app::input::spawn`] as
/// `spawn_input` and [`crate::app::ticker::spawn`] as `spawn_ticker`.
/// Each spawn function consumes the sender clone into a named OS
/// thread; the returned [`JoinHandle`] is held by `run_event_loop`
/// for the duration of the call and detached on drop — joining is
/// intentionally deferred to each thread's own shutdown path
/// (`Sender::send` failure on receiver hangup, or
/// `crossterm::event::read` failure on terminal disconnect). The
/// receiver is dropped as `run_event_loop` returns, which is the
/// signal both producers watch for.
///
/// `initial_wall_clock` seeds the renderer's first frame; subsequent
/// frames see the most recent `AppEvent::Tick.wall_clock` per
/// [`dispatch`].
pub fn run_event_loop<R, I, T>(
    initial_state: AppState,
    render: R,
    spawn_input: I,
    spawn_ticker: T,
    initial_wall_clock: SystemTime,
) -> AppState
where
    R: FnMut(&AppState, SystemTime),
    I: FnOnce(Sender<AppEvent>) -> JoinHandle<()>,
    T: FnOnce(Sender<AppEvent>) -> JoinHandle<()>,
{
    let (tx, rx) = mpsc::channel::<AppEvent>();
    // Hand each producer its own clone; the production
    // `input::spawn` / `ticker::spawn` move the sender into their
    // named OS thread. We hold the handles only so the threads stay
    // alive for at least the lifetime of this scope — joining is
    // intentionally deferred to the per-producer shutdown paths
    // (see the module-level docs).
    let _input = spawn_input(tx.clone());
    let _ticker = spawn_ticker(tx.clone());
    // `dispatch` borrows the original sender to route effect
    // results back through the same channel; the receiver is
    // consumed as we return.
    dispatch(initial_state, &rx, &tx, render, initial_wall_clock)
}

/// Run the event loop under a [`TerminalGuard`] that owns raw mode
/// and the alternate-screen state for the duration of the call.
///
/// This is the production composer the binary entry uses: it enables
/// raw mode + the alternate screen before the first render, runs the
/// event loop with the supplied producer spawners and render
/// callback, and restores the terminal in reverse setup order when
/// the loop returns. The restoration is RAII via [`TerminalGuard`]'s
/// `Drop`, so it also runs during panic unwind — a panicking
/// renderer still leaves the user's terminal usable.
///
/// Production callers pair this with [`crate::app::render::draw_frame`]
/// inside `render` so each loop iteration paints
/// [`crate::view::render`] onto a real `ratatui::Terminal`. The
/// ratatui terminal is intentionally kept out of this composer's
/// signature: it is captured by the `render` closure the caller
/// constructs, so tests can substitute a noop or a recording closure
/// and skip the ratatui machinery entirely.
///
/// `Ctrl-C` is handled by the reducer as `Effect::Quit` on every
/// screen, so it shares the normal-exit code path here — no special
/// teardown branch is needed for it.
///
/// # Errors
///
/// Returns the [`io::Error`] [`TerminalGuard::setup`] raised when
/// raw mode or alternate-screen entry fails. In that case the event
/// loop never starts: neither producer spawner is invoked and the
/// render callback is never called. On success, returns the final
/// [`AppState`] from [`dispatch`].
pub fn run_with_terminal_guard<B, R, I, T>(
    initial_state: AppState,
    backend: B,
    render: R,
    spawn_input: I,
    spawn_ticker: T,
    initial_wall_clock: SystemTime,
) -> io::Result<AppState>
where
    B: TerminalBackend,
    R: FnMut(&AppState, SystemTime),
    I: FnOnce(Sender<AppEvent>) -> JoinHandle<()>,
    T: FnOnce(Sender<AppEvent>) -> JoinHandle<()>,
{
    // Install the guard before any producer is spawned or any frame
    // is drawn so the first render lands on the alternate screen.
    // `?` short-circuits when setup itself fails (`TerminalGuard`
    // owns rollback of any partially-enabled state in that case),
    // which keeps the spawners and render callback unreachable on
    // the failure path.
    let _guard = TerminalGuard::setup(backend)?;
    let final_state = run_event_loop(
        initial_state,
        render,
        spawn_input,
        spawn_ticker,
        initial_wall_clock,
    );
    // `_guard` drops here, leaving the alternate screen and
    // disabling raw mode in reverse setup order. The same Drop runs
    // during panic unwind out of `run_event_loop`, so the user's
    // terminal is always restored.
    Ok(final_state)
}

/// Map the `io::Result<AppState>` returned by
/// [`run_with_terminal_guard`] onto the [`ExitCode`] the binary's
/// `main` must return, writing a single-line `paladin-tui: <err>`
/// advisory to `stderr` on the failure path.
///
/// Production callers in [`crate::run`] hand `std::io::stderr().lock()`
/// as the writer; tests inject a `Vec<u8>` so they can pin the
/// wording without capturing the per-test stderr stream. A writer
/// that itself errors mid-write is swallowed silently — losing the
/// advisory is strictly worse than the binary exiting with a
/// misleading success code.
///
/// `AppState` carried by the `Ok(_)` variant is intentionally
/// ignored: [`dispatch`] only returns through `Effect::Quit`, so any
/// final state arriving here means a clean exit.
pub fn exit_code_from_run_result<W: Write>(
    result: io::Result<AppState>,
    mut stderr: W,
) -> ExitCode {
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(stderr, "paladin-tui: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Build the production render closure that wraps a
/// [`ratatui::Terminal`] into the infallible
/// `FnMut(&AppState, SystemTime)` slot [`run_event_loop`] and
/// [`run_with_terminal_guard`] consume.
///
/// On each call the closure routes `state`, `now`, and the captured
/// `no_color` through [`crate::app::render::draw_frame`] (which
/// itself drives [`crate::view::render`]). `no_color` is captured
/// at composer-construction time so the closure does not re-read
/// the flag on every frame; production [`crate::run`] computes it
/// once from [`crate::cli::should_disable_color`] and threads it
/// through [`crate::run_with_components`]. If `draw_frame` returns
/// an [`io::Error`], the error is recorded into `error_sink` and
/// the closure becomes a no-op for every subsequent invocation — a
/// single transient terminal failure must not pile up follow-on
/// errors across every remaining frame, and the alternate-screen
/// teardown that runs after the loop exits should not race a doomed
/// re-draw.
///
/// Production [`crate::run`] owns both the terminal and the sink;
/// after [`run_with_terminal_guard`] returns it inspects the sink
/// and merges any captured error into the result it hands to
/// [`exit_code_from_run_result`], so a draw failure surfaces on the
/// same `paladin-tui: <err>` stderr path as a terminal-setup
/// failure. The captured error is owned by the sink (it is never
/// re-emitted into the dispatch loop), which matches the
/// [`crate::app::dispatch::dispatch`] contract of consuming an
/// infallible render closure.
pub fn build_render_closure<'a, B: Backend>(
    terminal: &'a mut Terminal<B>,
    error_sink: &'a RefCell<Option<io::Error>>,
    no_color: bool,
) -> impl FnMut(&AppState, SystemTime) + 'a {
    move |state: &AppState, now: SystemTime| {
        if error_sink.borrow().is_some() {
            return;
        }
        if let Err(err) = draw_frame(terminal, state, now, no_color) {
            *error_sink.borrow_mut() = Some(err);
        }
    }
}

/// Merge the [`io::Result`] returned by [`run_with_terminal_guard`]
/// with the [`io::Error`] captured by the render-closure error sink
/// built by [`build_render_closure`].
///
/// Production [`crate::run`] holds both halves: `run_result` is what
/// [`run_with_terminal_guard`] returned, and `captured_render_error`
/// is the `Option<io::Error>` extracted from the sink (typically via
/// `RefCell::into_inner`) after the loop exited. Either side may
/// carry a failure, and the caller needs a single
/// [`io::Result<AppState>`] to hand to [`exit_code_from_run_result`]
/// so a draw failure surfaces on the same `paladin-tui: <err>`
/// stderr path as a terminal-setup failure.
///
/// Merge policy:
///
/// * `(Ok(state), None)` → `Ok(state)`. Clean exit through
///   [`crate::app::EffectOutcome::Quit`] with no captured render
///   failure.
/// * `(Ok(_), Some(render_err))` → `Err(render_err)`. The dispatch
///   loop exited cleanly (the reducer's `Effect::Quit` path runs
///   regardless of earlier per-frame failures since
///   [`build_render_closure`] short-circuits subsequent frames after
///   capturing) but at least one frame failed; promote that failure
///   so the binary exits with FAILURE rather than swallowing a draw
///   error under `ExitCode::SUCCESS`. The final `AppState` is
///   discarded because [`exit_code_from_run_result`] ignores it.
/// * `(Err(setup_err), None)` → `Err(setup_err)`. Terminal setup
///   failed before any render ran; preserve the setup error
///   unchanged.
/// * `(Err(setup_err), Some(_))` → `Err(setup_err)`. Defensive
///   quadrant. In production [`run_with_terminal_guard`] short-
///   circuits before constructing the render closure when setup
///   fails, so the sink should be empty here. We still need to
///   define behavior for every input; the setup error wins because
///   it is the proximate cause of the failure the user saw, and a
///   stale or unrelated sink entry must not displace it.
///
/// `AppState` is moved through unchanged on the success path —
/// [`exit_code_from_run_result`] discards it, but a future caller
/// that wants the final state retains the option.
pub fn merge_render_failure_into_run_result(
    run_result: io::Result<AppState>,
    captured_render_error: Option<io::Error>,
) -> io::Result<AppState> {
    match (run_result, captured_render_error) {
        (Ok(state), None) => Ok(state),
        (Ok(_), Some(render_err)) => Err(render_err),
        (Err(setup_err), _) => Err(setup_err),
    }
}
