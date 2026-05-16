// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the `app::run` production composer.
//!
//! Tracks `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//! *"Effects are executed by `app::run`, which is the only boundary
//! that may call impure core / clipboard / writer functions."*
//!
//! [`paladin_tui::app::run::run_event_loop`] is the testable composer
//! that owns the `mpsc<AppEvent>` channel + producer spawning + the
//! `dispatch` call. Production callers pass
//! [`paladin_tui::app::input::spawn`] / [`paladin_tui::app::ticker::spawn`];
//! these tests pass fake spawners so the sender-clone + dispatch
//! completion contract can be exercised without a TTY.
//!
//! Terminal lifecycle setup is intentionally *not* part of this
//! composer — it lands in a separate slice. Keeping the event-loop
//! composer terminal-free is what makes it unit-testable against the
//! `dispatch` contract here.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use paladin_tui::app::event::AppEvent;
use paladin_tui::app::run::run_event_loop;
use paladin_tui::app::state::AppState;

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
