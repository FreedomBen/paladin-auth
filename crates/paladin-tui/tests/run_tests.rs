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

use std::cell::RefCell;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use std::process::ExitCode;

use paladin_tui::app::event::AppEvent;
use paladin_tui::app::run::{exit_code_from_run_result, run_event_loop, run_with_terminal_guard};
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

/// `MissingVault` is reducer-stable under `Ctrl-C` (it Quits without
/// mutating state) so the final `AppState` returned by dispatch is
/// trivially predictable for the "returns final state" assertion.
fn missing(path: &str) -> AppState {
    AppState::MissingVault {
        path: PathBuf::from(path),
    }
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

    assert!(matches!(final_state, AppState::MissingVault { .. }));
}

#[test]
fn run_event_loop_returns_final_state_from_dispatch_on_quit() {
    // Pin: when an effect returns Quit, run_event_loop returns the
    // final state that dispatch returned. Ctrl-C is reducer-handled
    // as a Quit without state mutation on MissingVault, so the
    // returned state must still be MissingVault.
    let final_state = run_event_loop(
        missing("/tmp/v.bin"),
        |_state, _wc| {},
        one_shot_ctrl_c,
        noop_thread,
        SystemTime::UNIX_EPOCH,
    );

    match final_state {
        AppState::MissingVault { path } => {
            assert_eq!(path, PathBuf::from("/tmp/v.bin"));
        }
        other => panic!("expected MissingVault, got {other:?}"),
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
                AppState::MissingVault { .. } => "MissingVault",
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
    assert_eq!(r[0], "MissingVault", "first render must be initial state");
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
        AppState::MissingVault { path } => {
            assert_eq!(path, PathBuf::from("/tmp/v.bin"));
        }
        other => panic!("expected MissingVault, got {other:?}"),
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
