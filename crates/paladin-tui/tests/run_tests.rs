// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the `app::run` production composers.
//!
//! Tracks `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//! *"Effects are executed by `app::run`, which is the only boundary
//! that may call impure core / clipboard / writer functions."*
//!
//! [`paladin_tui::app::run::run_event_loop`] is the inner testable
//! composer that owns the `mpsc<AppEvent>` channel + producer
//! spawning + the `dispatch` call. Production callers pass
//! [`paladin_tui::app::input::spawn`] / [`paladin_tui::app::ticker::spawn`];
//! these tests pass fake spawners so the sender-clone + dispatch
//! completion contract can be exercised without a TTY.
//!
//! [`paladin_tui::app::run::run_with_terminal_guard`] layers
//! [`paladin_tui::terminal::TerminalGuard`] above `run_event_loop` so
//! the production path enables raw mode + the alternate screen
//! before the first render and restores both on normal exit,
//! `Ctrl-C` (funnels through `Effect::Quit`), setup failure, and
//! panic unwind. The tests below pass a recording
//! [`paladin_tui::terminal::TerminalBackend`] so the setup / teardown
//! ordering can be asserted without an actual terminal.
//!
//! `dispatch` itself remains terminal-free so it stays
//! unit-testable; `run_with_terminal_guard` is the thin layer that
//! ties the two together.

mod common;

use common::secure_test_tempdir;

use std::cell::{Cell, RefCell};
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use std::process::ExitCode;

use ratatui::backend::{Backend, TestBackend, WindowSize};
use ratatui::buffer::Cell as BufferCell;
use ratatui::layout::{Position, Size};
use ratatui::Terminal;

use paladin_tui::app::event::AppEvent;
use paladin_tui::app::render::draw_frame;
use paladin_tui::app::run::{
    build_render_closure, exit_code_from_run_result, merge_render_failure_into_run_result,
    run_event_loop, run_with_terminal_guard,
};
use paladin_tui::app::state::AppState;
use paladin_tui::terminal::TerminalBackend;

/// Construct an `AppEvent::Input` carrying `Ctrl-c`. Ctrl-C funnels
/// through the reducer as `Effect::Quit` on every screen — the only
/// terminal-independent way to drive a clean dispatch-loop exit, so
/// every test injects it through one of the fake spawners.
fn ctrl_c() -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        at: Instant::now(),
    }
}

/// `CreateVault` is reducer-stable under `Ctrl-C` (it Quits without
/// mutating state) so the final `AppState` returned by dispatch is
/// trivially predictable for the "returns final state" assertion.
fn missing(path: &str) -> AppState {
    AppState::create_vault_initial(PathBuf::from(path))
}

/// Spawn a one-shot thread that delivers a single Ctrl-C through the
/// supplied sender and then exits. The handle is detached on drop.
fn one_shot_ctrl_c(tx: Sender<AppEvent>) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = tx.send(ctrl_c());
    })
}

/// Spawn a thread that exits immediately. Used as the no-op fake
/// ticker / no-op fake input partner when the *other* spawner is
/// providing the Ctrl-C that drives the dispatch exit.
fn noop_thread(_tx: Sender<AppEvent>) -> JoinHandle<()> {
    thread::spawn(|| {})
}

#[test]
fn run_event_loop_invokes_each_producer_spawner_with_a_sender() {
    // Pin the composer's wiring: both spawners must be invoked, so
    // the production path threads `input::spawn(tx.clone())` and
    // `ticker::spawn(tx.clone())` exactly once each.
    let input_invoked = Rc::new(RefCell::new(false));
    let ticker_invoked = Rc::new(RefCell::new(false));
    let input_invoked_clone = input_invoked.clone();
    let ticker_invoked_clone = ticker_invoked.clone();

    let _final_state = run_event_loop(
        missing("/tmp/v.bin"),
        |_state, _wc| {},
        move |tx: Sender<AppEvent>| {
            *input_invoked_clone.borrow_mut() = true;
            one_shot_ctrl_c(tx)
        },
        move |tx: Sender<AppEvent>| {
            *ticker_invoked_clone.borrow_mut() = true;
            noop_thread(tx)
        },
        SystemTime::UNIX_EPOCH,
    );

    assert!(*input_invoked.borrow(), "input spawner must be invoked");
    assert!(*ticker_invoked.borrow(), "ticker spawner must be invoked");
}

#[test]
fn run_event_loop_threads_a_sender_clone_through_each_spawner() {
    // Pin: the senders handed to the two spawners are clones of the
    // same underlying channel. A regression that ever hands one
    // spawner an unrelated sender would silently route that
    // producer's events away from dispatch — confirm both senders
    // reach `dispatch` by having only the ticker-side fake send the
    // Ctrl-C and having the input-side fake be a no-op. If the
    // ticker's sender is not on the dispatch channel, Ctrl-C never
    // arrives and the loop hangs (the suite's per-test timeout would
    // surface this).
    let final_state = run_event_loop(
        missing("/tmp/v.bin"),
        |_state, _wc| {},
        |tx: Sender<AppEvent>| noop_thread(tx),
        |tx: Sender<AppEvent>| one_shot_ctrl_c(tx),
        SystemTime::UNIX_EPOCH,
    );

    assert!(matches!(final_state, AppState::CreateVault { .. }));
}

#[test]
fn run_event_loop_returns_final_state_from_dispatch_on_quit() {
    // Pin: when an effect returns Quit, run_event_loop returns the
    // final state that dispatch returned. Ctrl-C is reducer-handled
    // as a Quit without state mutation on CreateVault, so the
    // returned state must still be CreateVault.
    let final_state = run_event_loop(
        missing("/tmp/v.bin"),
        |_state, _wc| {},
        one_shot_ctrl_c,
        noop_thread,
        SystemTime::UNIX_EPOCH,
    );

    match final_state {
        AppState::CreateVault { path, .. } => {
            assert_eq!(path, PathBuf::from("/tmp/v.bin"));
        }
        other => panic!("expected CreateVault, got {other:?}"),
    }
}

#[test]
fn run_event_loop_renders_initial_state_before_processing_events() {
    // Pin: the first render happens with the initial state — the
    // composer must preserve dispatch's "paint the initial state
    // before the first event" contract so the screen is up at
    // startup, not blank-until-first-tick.
    let renders: Rc<RefCell<Vec<&'static str>>> = Rc::default();
    let renders_clone = renders.clone();

    let _final_state = run_event_loop(
        missing("/tmp/v.bin"),
        move |state, _wc| {
            renders_clone.borrow_mut().push(match state {
                AppState::CreateVault { .. } => "CreateVault",
                AppState::Unlock { .. } => "Unlock",
                AppState::Locked { .. } => "Locked",
                AppState::Unlocked { .. } => "Unlocked",
                AppState::StartupError { .. } => "StartupError",
            });
        },
        one_shot_ctrl_c,
        noop_thread,
        SystemTime::UNIX_EPOCH,
    );

    let r = renders.borrow();
    assert!(!r.is_empty(), "at least one render expected");
    assert_eq!(r[0], "CreateVault", "first render must be initial state");
}

#[test]
fn run_event_loop_seeds_first_render_with_initial_wall_clock() {
    // Pin: the `initial_wall_clock` arg is the wall-clock the
    // renderer sees on its first call (before any `Tick` has been
    // produced). The composer must forward it straight into
    // `dispatch`.
    let renders: Rc<RefCell<Vec<SystemTime>>> = Rc::default();
    let renders_clone = renders.clone();
    let seed = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let _final_state = run_event_loop(
        missing("/tmp/v.bin"),
        move |_state, wc| {
            renders_clone.borrow_mut().push(wc);
        },
        one_shot_ctrl_c,
        noop_thread,
        seed,
    );

    let r = renders.borrow();
    assert!(!r.is_empty(), "at least one render expected");
    assert_eq!(
        r[0], seed,
        "first render's wall-clock must equal initial_wall_clock"
    );
}

// ---------------------------------------------------------------------------
// run_with_terminal_guard (IMPLEMENTATION_PLAN_03_TUI.md > Implementation
// checklist: "Implement terminal raw-mode / alternate-screen lifecycle with
// guarded restoration on exit, error, Ctrl-C, and panic unwind")
//
// `run_with_terminal_guard` is the production composer that wraps
// `TerminalGuard::setup` around `run_event_loop`. The fine-grained guard
// semantics (rollback on setup failure, drop-order on teardown, panic-unwind
// survival) are already pinned in `tests/terminal_tests.rs`; the tests below
// pin the composer's contract: setup runs before the first render, teardown
// runs after dispatch returns, and the guard's restoration survives a
// panicking renderer.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Recorder {
    calls: Vec<&'static str>,
}

type SharedRecorder = Rc<RefCell<Recorder>>;

/// Recording backend whose lifecycle methods all succeed and append a
/// fixed marker to a shared call log so the test can assert the
/// composer's setup → render → teardown ordering.
struct RecordingBackend(SharedRecorder);

impl TerminalBackend for RecordingBackend {
    fn enable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enable_raw_mode");
        Ok(())
    }
    fn enter_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enter_alt_screen");
        Ok(())
    }
    fn disable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("disable_raw_mode");
        Ok(())
    }
    fn leave_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("leave_alt_screen");
        Ok(())
    }
}

/// Backend whose `enable_raw_mode` returns an `io::Error` so the
/// composer's setup-failure path can be exercised without disturbing
/// the host terminal.
struct EnableRawModeFailureBackend(SharedRecorder);

impl TerminalBackend for EnableRawModeFailureBackend {
    fn enable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enable_raw_mode:fail");
        Err(io::Error::other("simulated raw-mode failure"))
    }
    fn enter_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enter_alt_screen");
        Ok(())
    }
    fn disable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("disable_raw_mode");
        Ok(())
    }
    fn leave_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("leave_alt_screen");
        Ok(())
    }
}

#[test]
fn run_with_terminal_guard_enters_raw_mode_and_alt_screen_before_first_render() {
    // Pin: the production composer must put the terminal into raw
    // mode + alternate screen BEFORE dispatch paints the initial
    // state. A regression that ever ordered the first render before
    // setup would leak ratatui escape sequences into the primary
    // screen buffer.
    let log: SharedRecorder = Rc::default();
    let log_in_render = log.clone();
    let render = move |_state: &AppState, _wc: SystemTime| {
        log_in_render.borrow_mut().calls.push("render");
    };

    let _final_state = run_with_terminal_guard(
        missing("/tmp/v.bin"),
        RecordingBackend(log.clone()),
        render,
        one_shot_ctrl_c,
        noop_thread,
        SystemTime::UNIX_EPOCH,
    )
    .expect("setup succeeds");

    let calls = log.borrow().calls.clone();
    assert!(
        calls.len() >= 3,
        "expected setup pair + at least one render, got {calls:?}"
    );
    assert_eq!(
        &calls[..2],
        &["enable_raw_mode", "enter_alt_screen"],
        "terminal setup must complete before first render"
    );
    assert!(
        calls[2..].contains(&"render"),
        "at least one render must run after setup, got {calls:?}",
    );
}

#[test]
fn run_with_terminal_guard_restores_terminal_in_reverse_order_after_quit() {
    // Pin: on a normal Quit-driven exit, the guard drops as the
    // composer returns, restoring alt-screen then raw-mode in
    // reverse setup order. Tail of the call log must be
    // leave_alt_screen → disable_raw_mode regardless of how many
    // renders fired in between.
    let log: SharedRecorder = Rc::default();

    let _final_state = run_with_terminal_guard(
        missing("/tmp/v.bin"),
        RecordingBackend(log.clone()),
        |_state, _wc| {},
        one_shot_ctrl_c,
        noop_thread,
        SystemTime::UNIX_EPOCH,
    )
    .expect("setup succeeds");

    let calls = log.borrow().calls.clone();
    assert!(
        calls.len() >= 4,
        "expected at least setup pair + teardown pair, got {calls:?}"
    );
    let tail = &calls[calls.len() - 2..];
    assert_eq!(
        tail,
        &["leave_alt_screen", "disable_raw_mode"],
        "guard drop must restore terminal in reverse setup order"
    );
}

#[test]
fn run_with_terminal_guard_returns_final_state_from_dispatch_on_quit() {
    // Pin: on a successful run, the composer returns
    // `Ok(final_state)` — mirrors the `run_event_loop` final-state
    // contract above, but now wrapped in the terminal-lifecycle
    // boundary.
    let log: SharedRecorder = Rc::default();

    let final_state = run_with_terminal_guard(
        missing("/tmp/v.bin"),
        RecordingBackend(log),
        |_state, _wc| {},
        one_shot_ctrl_c,
        noop_thread,
        SystemTime::UNIX_EPOCH,
    )
    .expect("setup succeeds");

    match final_state {
        AppState::CreateVault { path, .. } => {
            assert_eq!(path, PathBuf::from("/tmp/v.bin"));
        }
        other => panic!("expected CreateVault, got {other:?}"),
    }
}

#[test]
fn run_with_terminal_guard_returns_setup_error_without_invoking_spawners_or_render() {
    // Pin: if `TerminalGuard::setup` fails, no spawners are invoked
    // and no renders fire — the loop never starts. The propagated
    // error must be the one `TerminalGuard::setup` raised.
    let log: SharedRecorder = Rc::default();
    let input_invoked = Rc::new(RefCell::new(false));
    let input_invoked_clone = input_invoked.clone();
    let ticker_invoked = Rc::new(RefCell::new(false));
    let ticker_invoked_clone = ticker_invoked.clone();

    let result = run_with_terminal_guard(
        missing("/tmp/v.bin"),
        EnableRawModeFailureBackend(log.clone()),
        |_state, _wc| panic!("render must not run on setup failure"),
        move |tx: Sender<AppEvent>| {
            *input_invoked_clone.borrow_mut() = true;
            one_shot_ctrl_c(tx)
        },
        move |tx: Sender<AppEvent>| {
            *ticker_invoked_clone.borrow_mut() = true;
            noop_thread(tx)
        },
        SystemTime::UNIX_EPOCH,
    );

    let err = result.expect_err("expected setup-failure error to propagate");
    assert_eq!(
        err.to_string(),
        "simulated raw-mode failure",
        "the propagated error must come from TerminalGuard::setup"
    );
    assert!(
        !*input_invoked.borrow(),
        "input spawner must not run when setup fails",
    );
    assert!(
        !*ticker_invoked.borrow(),
        "ticker spawner must not run when setup fails",
    );
    assert_eq!(
        log.borrow().calls.as_slice(),
        &["enable_raw_mode:fail"],
        "only the failing setup call should appear in the recorder",
    );
}

#[test]
fn run_with_terminal_guard_restores_terminal_when_render_panics() {
    // Pin: a panicking render unwinds through `dispatch` →
    // `run_event_loop` → `run_with_terminal_guard`. The
    // `TerminalGuard`'s Drop runs during the unwind, so the
    // recorder still ends with leave_alt_screen → disable_raw_mode.
    // `tests/terminal_tests.rs::guard_restores_terminal_during_panic_unwind`
    // pins the guard's own behavior; this test pins that the
    // composer preserves it.
    let log: SharedRecorder = Rc::default();
    let log_in_render = log.clone();
    let log_for_panic = log.clone();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _ = run_with_terminal_guard(
            missing("/tmp/v.bin"),
            RecordingBackend(log_in_render),
            |_state, _wc| {
                log_for_panic.borrow_mut().calls.push("render:panic");
                panic!("simulated panic during render");
            },
            one_shot_ctrl_c,
            noop_thread,
            SystemTime::UNIX_EPOCH,
        );
    }));

    assert!(result.is_err(), "expected the simulated panic to surface");
    let calls = log.borrow().calls.clone();
    assert!(
        calls.contains(&"render:panic"),
        "render must have run before panic, got {calls:?}"
    );
    let tail = &calls[calls.len() - 2..];
    assert_eq!(
        tail,
        &["leave_alt_screen", "disable_raw_mode"],
        "guard drop must restore terminal during panic unwind"
    );
}

// ---------------------------------------------------------------------------
// exit_code_from_run_result (IMPLEMENTATION_PLAN_03_TUI.md > Implementation
// checklist: "Implement terminal raw-mode / alternate-screen lifecycle with
// guarded restoration on exit, error, Ctrl-C, and panic unwind")
//
// `exit_code_from_run_result` is the last small composer between
// `run_with_terminal_guard` and the binary's `main()`: it maps the
// composer's `io::Result<AppState>` into the `ExitCode` `main` must return,
// and writes the `io::Error` advisory to the supplied stderr sink on the
// failure path. Keeping the writer injectable is what lets these tests pin
// the wording without driving a real `process::exit` or capturing the
// per-test stderr stream.
//
// `ExitCode` does not implement `PartialEq` (rust-lang/rust#67939) so the
// tests compare via the stable `Debug` representation.
// ---------------------------------------------------------------------------

/// Stable `Debug` rendering of an `ExitCode` for equality assertions —
/// rust-lang/rust#67939 deliberately keeps `ExitCode` non-`Eq` so the
/// stable surface is `Debug` + `From<u8>` + `Termination`. The Debug
/// strings for `SUCCESS` and `FAILURE` are well-defined and stable.
fn debug_exit_code(code: ExitCode) -> String {
    format!("{code:?}")
}

#[test]
fn exit_code_from_run_result_success_returns_exit_code_success_and_writes_nothing() {
    // Pin: on `Ok(_)`, the helper returns `ExitCode::SUCCESS` and
    // writes nothing to the stderr sink. The `AppState` value carried
    // by the `Ok` variant is intentionally ignored — dispatch only
    // returns through the Quit path, so any final state means a clean
    // exit.
    let mut stderr: Vec<u8> = Vec::new();
    let code = exit_code_from_run_result(Ok(missing("/tmp/v.bin")), &mut stderr);

    assert_eq!(
        debug_exit_code(code),
        debug_exit_code(ExitCode::SUCCESS),
        "Ok(_) must map to ExitCode::SUCCESS",
    );
    assert!(
        stderr.is_empty(),
        "no stderr advisory should be written on the success path, got {:?}",
        String::from_utf8_lossy(&stderr),
    );
}

#[test]
fn exit_code_from_run_result_io_error_returns_exit_code_failure_and_writes_advisory() {
    // Pin: on `Err(io_error)`, the helper returns `ExitCode::FAILURE`
    // and writes a single-line `paladin-tui: <err>\n` advisory to the
    // stderr sink. The wording matches the CLI's `paladin: <err>`
    // pattern so users see a consistent prefix across the two
    // binaries.
    let mut stderr: Vec<u8> = Vec::new();
    let err = io::Error::other("simulated terminal setup failure");
    let code = exit_code_from_run_result(Err(err), &mut stderr);

    assert_eq!(
        debug_exit_code(code),
        debug_exit_code(ExitCode::FAILURE),
        "Err(_) must map to ExitCode::FAILURE",
    );
    let written = String::from_utf8(stderr).expect("stderr advisory is UTF-8");
    assert_eq!(
        written, "paladin-tui: simulated terminal setup failure\n",
        "the failure advisory must be the binary-prefixed io::Error wording with a trailing newline",
    );
}

#[test]
fn exit_code_from_run_result_writer_failure_does_not_change_exit_code() {
    // Pin: if the stderr sink itself errors mid-write, the helper
    // must still return `ExitCode::FAILURE` — losing the advisory is
    // strictly worse than the binary exiting with a misleading
    // success code. Drives a `Write` impl whose `write_all` always
    // returns an error so the helper has to swallow it.
    struct FailingWriter;
    impl io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("simulated stderr write failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("simulated stderr flush failure"))
        }
    }

    let err = io::Error::other("simulated terminal setup failure");
    let code = exit_code_from_run_result(Err(err), FailingWriter);

    assert_eq!(
        debug_exit_code(code),
        debug_exit_code(ExitCode::FAILURE),
        "writer failure must not downgrade ExitCode::FAILURE to SUCCESS",
    );
}

#[test]
fn run_with_terminal_guard_seeds_first_render_with_initial_wall_clock() {
    // Pin: the `initial_wall_clock` arg is forwarded to dispatch so
    // the first render sees the seed, before any `Tick` has
    // arrived. Mirrors
    // `run_event_loop_seeds_first_render_with_initial_wall_clock`
    // above so a regression that drops the forwarding inside the
    // terminal-guard composer surfaces here.
    let log: SharedRecorder = Rc::default();
    let renders: Rc<RefCell<Vec<SystemTime>>> = Rc::default();
    let renders_clone = renders.clone();
    let seed = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let _final_state = run_with_terminal_guard(
        missing("/tmp/v.bin"),
        RecordingBackend(log),
        move |_state, wc| {
            renders_clone.borrow_mut().push(wc);
        },
        one_shot_ctrl_c,
        noop_thread,
        seed,
    )
    .expect("setup succeeds");

    let r = renders.borrow();
    assert!(!r.is_empty(), "at least one render expected");
    assert_eq!(
        r[0], seed,
        "first render's wall-clock must equal initial_wall_clock"
    );
}

// ---------------------------------------------------------------------------
// build_render_closure (IMPLEMENTATION_PLAN_03_TUI.md > Implementation
// checklist: "Implement terminal raw-mode / alternate-screen lifecycle with
// guarded restoration on exit, error, Ctrl-C, and panic unwind")
//
// `build_render_closure` is the small composer that wraps a
// `ratatui::Terminal` and an error-capture sink into the infallible
// `FnMut(&AppState, SystemTime)` slot that `run_event_loop` /
// `run_with_terminal_guard` consume. On each call it routes the state +
// wall-clock through `draw_frame` (which itself drives `view::render`);
// any `io::Error` returned by the draw is recorded into the sink and the
// closure becomes a no-op for subsequent invocations so additional
// failures don't pile up after the terminal has already gone bad. The
// production `paladin-tui::run` reads the sink after
// `run_with_terminal_guard` returns and merges any captured error into
// the result it hands to `exit_code_from_run_result`.
// ---------------------------------------------------------------------------

/// `Backend` impl whose `draw` always errors and counts invocations.
/// Lets the error-capture tests below pin both the capture and the
/// short-circuit behavior without disturbing the host terminal or
/// relying on the production `CrosstermBackend`. All non-draw methods
/// succeed trivially so `Terminal::new` and `Terminal::draw`'s
/// surrounding scaffolding (cursor query, resize accounting) stay out
/// of the failure path being asserted.
struct DrawFailureBackend {
    draw_calls: Rc<Cell<u32>>,
    width: u16,
    height: u16,
}

impl Backend for DrawFailureBackend {
    fn draw<'a, I>(&mut self, _content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a BufferCell)>,
    {
        self.draw_calls.set(self.draw_calls.get() + 1);
        Err(io::Error::other("simulated draw failure"))
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Ok(Position::ORIGIN)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, _position: P) -> io::Result<()> {
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn size(&self) -> io::Result<Size> {
        Ok(Size::new(self.width, self.height))
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: Size::new(self.width, self.height),
            pixels: Size::ZERO,
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Build a fresh `Terminal<TestBackend>` of the given dimensions for
/// the happy-path tests.
fn fresh_test_terminal(width: u16, height: u16) -> Terminal<TestBackend> {
    Terminal::new(TestBackend::new(width, height)).expect("create TestBackend terminal")
}

#[test]
fn build_render_closure_routes_state_through_draw_frame_into_terminal_buffer() {
    // Pin: a single closure call paints the terminal buffer
    // identically to a direct `draw_frame` invocation with the same
    // state and wall-clock. The composer is meant to be a thin
    // wrapper around `draw_frame`; a regression that ever short-
    // circuits before reaching the renderer, or substitutes a
    // different draw call, surfaces as a buffer diff against the
    // baseline.
    let state = missing("/tmp/v.bin");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_012);

    let mut terminal = fresh_test_terminal(80, 12);
    let sink: RefCell<Option<io::Error>> = RefCell::new(None);
    {
        let mut render = build_render_closure(&mut terminal, &sink, false);
        render(&state, now);
    }
    let adapter_buf = terminal.backend().buffer().clone();

    let mut baseline_term = fresh_test_terminal(80, 12);
    draw_frame(&mut baseline_term, &state, now, false)
        .expect("baseline draw_frame should succeed against TestBackend");
    let baseline_buf = baseline_term.backend().buffer().clone();

    assert_eq!(
        adapter_buf, baseline_buf,
        "build_render_closure must route through draw_frame; buffers should match",
    );
    assert!(
        sink.borrow().is_none(),
        "no draw failure should be recorded on the success path, got {:?}",
        sink.borrow().as_ref().map(io::Error::to_string),
    );
}

#[test]
fn build_render_closure_is_a_noop_when_error_sink_already_holds_an_error() {
    // Pin: once the sink has captured a draw failure, subsequent
    // closure calls must short-circuit before touching the terminal.
    // The test seeds the sink with a sentinel error and asserts both
    // that the terminal buffer is unchanged from its initial blank
    // state and that the sink still holds the sentinel (not an
    // overwritten / wrapped variant).
    let state = missing("/tmp/v.bin");
    let now = SystemTime::UNIX_EPOCH;

    let mut terminal = fresh_test_terminal(80, 12);
    let blank_buf = terminal.backend().buffer().clone();

    let sink: RefCell<Option<io::Error>> = RefCell::new(Some(io::Error::other("sentinel")));
    {
        let mut render = build_render_closure(&mut terminal, &sink, false);
        render(&state, now);
    }

    assert_eq!(
        terminal.backend().buffer(),
        &blank_buf,
        "closure must not touch the terminal once the sink holds an error",
    );
    let captured = sink.into_inner().expect("sink still holds an error");
    assert_eq!(
        captured.to_string(),
        "sentinel",
        "closure must not overwrite an already-captured error",
    );
}

#[test]
fn build_render_closure_captures_draw_failure_and_short_circuits_subsequent_calls() {
    // Pin: when `terminal.draw()` returns an `io::Error`, the
    // closure records it into the sink. On the *next* call the
    // closure must short-circuit before invoking `draw` again, so a
    // single transient terminal failure does not pile up follow-on
    // errors across every subsequent frame. Asserted by counting
    // `Backend::draw` invocations on a backend whose draw always
    // errors — the count must reach 1 (first call hit the failure
    // path) and stay at 1 across additional closure calls.
    let state = missing("/tmp/v.bin");
    let now = SystemTime::UNIX_EPOCH;

    let draw_calls: Rc<Cell<u32>> = Rc::new(Cell::new(0));
    let backend = DrawFailureBackend {
        draw_calls: draw_calls.clone(),
        width: 80,
        height: 12,
    };
    let mut terminal = Terminal::new(backend).expect("construct terminal over DrawFailureBackend");
    let sink: RefCell<Option<io::Error>> = RefCell::new(None);

    {
        let mut render = build_render_closure(&mut terminal, &sink, false);
        render(&state, now);
        let captured_after_first = sink
            .borrow()
            .as_ref()
            .map(io::Error::to_string)
            .expect("first call should capture the simulated draw failure");
        assert!(
            captured_after_first.contains("simulated draw failure"),
            "captured error must carry the backend's failure wording, got {captured_after_first:?}",
        );
        assert_eq!(
            draw_calls.get(),
            1,
            "the first closure call must reach the failing draw exactly once",
        );

        // Subsequent calls must short-circuit — neither the draw
        // method nor the sink should observe any further activity.
        render(&state, now);
        render(&state, now);
    }

    assert_eq!(
        draw_calls.get(),
        1,
        "subsequent closure calls must short-circuit before invoking Backend::draw",
    );
    let final_err = sink
        .into_inner()
        .expect("sink retains the first captured error");
    assert!(
        final_err.to_string().contains("simulated draw failure"),
        "subsequent calls must not overwrite the first captured error, got {final_err}",
    );
}

// ---------------------------------------------------------------------------
// merge_render_failure_into_run_result
//
// Production `crate::run` owns both the `io::Result<AppState>` returned by
// `run_with_terminal_guard` *and* the `Option<io::Error>` extracted from the
// render-closure error sink built by `build_render_closure`. Those two
// failure sources must be merged into a single `io::Result<AppState>` so
// `exit_code_from_run_result` sees one combined outcome and a draw failure
// reaches the user on the same `paladin-tui: <err>` stderr path as a
// terminal-setup failure. Pinning the four quadrants here keeps that
// merge policy stable.
// ---------------------------------------------------------------------------

#[test]
fn merge_render_failure_into_run_result_returns_ok_when_loop_clean_and_sink_empty() {
    // Pin: with no setup failure and no captured render error, the
    // helper threads the final `AppState` through unchanged so the
    // success path is byte-identical to the un-merged result.
    let result: io::Result<AppState> = Ok(missing("/tmp/v.bin"));
    let merged = merge_render_failure_into_run_result(result, None);

    let final_state = merged.expect("clean run with empty sink must stay Ok");
    // AppState is `Debug`-only at the enum level (variants carry
    // non-`Clone` fields such as `Vault`), so compare via the
    // stable `Debug` rendering — mirrors the `debug_exit_code`
    // approach used for the `ExitCode` comparisons above.
    assert_eq!(
        format!("{final_state:?}"),
        format!("{:?}", missing("/tmp/v.bin")),
        "the merger must preserve the AppState carried by Ok(_) when no render failure is captured",
    );
}

#[test]
fn merge_render_failure_into_run_result_surfaces_render_failure_when_loop_exited_cleanly() {
    // Pin: dispatch returned `Ok(_)` via `Effect::Quit` but the render
    // sink captured an `io::Error` along the way. The helper promotes
    // that captured error to the merged result so the binary exits
    // with FAILURE and a `paladin-tui: <render-err>` advisory rather
    // than swallowing a draw failure under a SUCCESS exit code.
    let result: io::Result<AppState> = Ok(missing("/tmp/v.bin"));
    let render_err = io::Error::other("simulated draw failure");
    let merged = merge_render_failure_into_run_result(result, Some(render_err));

    let err = merged.expect_err("captured render failure must surface as Err");
    assert_eq!(
        err.to_string(),
        "simulated draw failure",
        "the merger must preserve the render error's wording so the stderr advisory matches the captured failure",
    );
}

#[test]
fn merge_render_failure_into_run_result_returns_setup_error_when_sink_is_empty() {
    // Pin: terminal setup failed; `run_with_terminal_guard` short-
    // circuited before the render closure was constructed, so the
    // sink is empty. The merger must return the setup error
    // unchanged.
    let setup_err = io::Error::other("simulated terminal setup failure");
    let result: io::Result<AppState> = Err(setup_err);
    let merged = merge_render_failure_into_run_result(result, None);

    let err = merged.expect_err("setup failure must stay Err");
    assert_eq!(
        err.to_string(),
        "simulated terminal setup failure",
        "the merger must preserve the setup error's wording when no render failure was captured",
    );
}

#[test]
fn merge_render_failure_into_run_result_prefers_setup_error_when_both_sources_failed() {
    // Pin: defensive case. In production a setup failure short-
    // circuits before any render runs, so the sink should always be
    // empty here. But the helper is a pure function that must define
    // behavior for every input; we preserve the setup error because
    // it is the more proximate cause — a stale or unrelated entry in
    // the sink must not displace the real failure the loop already
    // surfaced.
    let setup_err = io::Error::other("simulated terminal setup failure");
    let result: io::Result<AppState> = Err(setup_err);
    let render_err = io::Error::other("stale render entry");
    let merged = merge_render_failure_into_run_result(result, Some(render_err));

    let err = merged.expect_err("setup failure must stay Err");
    assert_eq!(
        err.to_string(),
        "simulated terminal setup failure",
        "the setup error must win when both sources report failure so the stderr advisory points at the real cause",
    );
}

// ---------------------------------------------------------------------------
// run_with_components (IMPLEMENTATION_PLAN_03_TUI.md > Implementation
// checklist) — top-level composer the `paladin_tui::run()` binary entry uses
// to tie `build_initial_state`, the ratatui `Terminal` construction, the
// lifecycle `TerminalGuard`, the render-error sink, and the exit-code mapper
// into a single call. The fine-grained pieces are each pinned above; the
// tests below pin the *integration* the binary's entry depends on without
// exercising a real TTY: the success path returns `ExitCode::SUCCESS` after
// dispatch quits cleanly, and a failed ratatui-Terminal construction short-
// circuits to `ExitCode::FAILURE` BEFORE either spawner or the lifecycle
// backend is touched, with the underlying error surfaced through the same
// `paladin-tui: <err>` stderr advisory as a setup failure.
// ---------------------------------------------------------------------------

#[test]
fn run_with_components_returns_success_after_dispatch_quits_cleanly() {
    // Pin: the binary's top-level composer ties `build_initial_state` +
    // the supplied lifecycle backend + a successful `Terminal::new` into
    // a clean `ExitCode::SUCCESS` exit when dispatch returns through
    // `Effect::Quit` (here driven by the one-shot Ctrl-C spawner).
    // Asserts no stderr advisory is written on the happy path and the
    // lifecycle guard's setup pair was driven so the production
    // "raw mode + alt screen active during dispatch" contract is
    // observable from this top layer.
    //
    // The vault path lives inside a `secure_test_tempdir()` so the
    // path is guaranteed non-existent (→ `CreateVault` initial state,
    // which is reducer-stable under Ctrl-C) and the parent dir's
    // `0700` mode keeps `paladin_core::inspect` from tripping
    // `unsafe_permissions`. The exact initial state does not matter
    // to the assertions — every `AppState` variant funnels Ctrl-C
    // through `Effect::Quit` — but pinning the path-class keeps the
    // test deterministic across machines whose `/tmp` permissions
    // differ.
    let tmp = secure_test_tempdir();
    let vault_path = tmp
        .path()
        .join("paladin-tui-run-with-components-success.bin");
    let args = paladin_tui::cli::GlobalArgs {
        vault: Some(vault_path),
        no_color: false,
    };
    let log: SharedRecorder = Rc::default();
    let mut stderr = Vec::<u8>::new();

    let exit_code = paladin_tui::run_with_components(
        args,
        false,
        RecordingBackend(log.clone()),
        || Terminal::new(TestBackend::new(80, 24)),
        one_shot_ctrl_c,
        noop_thread,
        SystemTime::UNIX_EPOCH,
        &mut stderr,
    );

    assert_eq!(
        debug_exit_code(exit_code),
        debug_exit_code(ExitCode::SUCCESS),
        "clean dispatch quit must map to ExitCode::SUCCESS",
    );
    assert!(
        stderr.is_empty(),
        "no stderr advisory should be written on success, got {:?}",
        String::from_utf8_lossy(&stderr),
    );
    let calls = log.borrow().calls.clone();
    assert!(
        calls.starts_with(&["enable_raw_mode", "enter_alt_screen"]),
        "guard must enable raw mode + alt screen before dispatch begins, got {calls:?}",
    );
    assert!(
        calls
            .iter()
            .any(|c| *c == "leave_alt_screen" || *c == "disable_raw_mode"),
        "guard must run teardown after dispatch returns, got {calls:?}",
    );
}

#[test]
fn run_with_components_returns_failure_with_stderr_advisory_on_terminal_construction_failure() {
    // Pin: when the ratatui `Terminal` cannot be constructed, the
    // composer short-circuits to `ExitCode::FAILURE` WITHOUT touching
    // either the lifecycle backend or the input/ticker spawners. A
    // regression that ever ordered `Terminal::new` after raw-mode
    // setup could silently leak ratatui escape sequences onto the
    // user's primary screen on the failure path; pinning "lifecycle
    // backend untouched" + "spawners must not run" catches that
    // class. The underlying `io::Error` surfaces through the same
    // `paladin-tui: <err>` stderr advisory as a
    // `TerminalGuard::setup` failure, so the user sees one
    // consistent failure shape regardless of which side failed.
    let tmp = secure_test_tempdir();
    let vault_path = tmp
        .path()
        .join("paladin-tui-run-with-components-failure.bin");
    let args = paladin_tui::cli::GlobalArgs {
        vault: Some(vault_path),
        no_color: false,
    };
    let log: SharedRecorder = Rc::default();
    let mut stderr = Vec::<u8>::new();

    let exit_code = paladin_tui::run_with_components::<TestBackend, _, _, _, _, _>(
        args,
        false,
        RecordingBackend(log.clone()),
        || Err(io::Error::other("synthetic terminal construction failure")),
        |_tx| panic!("input spawner must not be invoked when Terminal::new fails"),
        |_tx| panic!("ticker spawner must not be invoked when Terminal::new fails"),
        SystemTime::UNIX_EPOCH,
        &mut stderr,
    );

    assert_eq!(
        debug_exit_code(exit_code),
        debug_exit_code(ExitCode::FAILURE),
        "Terminal::new failure must map to ExitCode::FAILURE",
    );
    assert!(
        log.borrow().calls.is_empty(),
        "lifecycle backend must not be touched when Terminal::new fails, got {:?}",
        log.borrow().calls,
    );
    let stderr_str = String::from_utf8(stderr).expect("stderr advisory is UTF-8");
    assert_eq!(
        stderr_str, "paladin-tui: synthetic terminal construction failure\n",
        "stderr must carry the binary-prefixed advisory verbatim",
    );
}
