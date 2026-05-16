// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dispatch-loop tests for `paladin-tui`.
//!
//! Tracks `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//! *"Single thread runs the reducer. ... The reducer is a pure
//! function over `(state, event) → (state, Vec<Effect>)` so it is
//! unit-testable without a terminal. Effects are executed by
//! `app::run`, which is the only boundary that may call impure core
//! / clipboard / writer functions."*
//!
//! [`paladin_tui::app::dispatch::dispatch`] is the pure event-loop
//! glue: it consumes events off an `mpsc<AppEvent>`, drives
//! `reduce → execute` for each event, threads the latest `Tick`
//! `wall_clock` into the render callback, and exits when an effect
//! returns [`paladin_tui::app::EffectOutcome::Quit`] or the producer
//! channel disconnects. Production `app::run` wraps it with the
//! terminal lifecycle + real input/ticker producer threads; these
//! tests drive the loop with a synchronous `mpsc::channel` so the
//! contract is exercised without a TTY.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use paladin_tui::app::dispatch::dispatch;
use paladin_tui::app::event::AppEvent;
use paladin_tui::app::state::AppState;

/// Construct an `AppEvent::Input` carrying `Ctrl-c`. Ctrl-C funnels
/// through the reducer as `Effect::Quit` on every screen — the only
/// terminal-independent way to drive a clean dispatch-loop exit.
fn ctrl_c() -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        at: Instant::now(),
    }
}

/// Construct an `AppEvent::Tick` with the given wall-clock and a
/// freshly sampled monotonic instant. Ticks on `MissingVault` are
/// passthrough per the reducer's terminal-screen contract, so they
/// drive the latest-`Tick`-wall-clock plumbing without state churn.
fn tick(wall_clock: SystemTime) -> AppEvent {
    AppEvent::Tick {
        wall_clock,
        monotonic: Instant::now(),
    }
}

fn missing(path: &str) -> AppState {
    AppState::MissingVault {
        path: PathBuf::from(path),
    }
}

/// Discriminant-only state tag — the test only cares whether the
/// renderer sees the same variant it was passed, not the inner data.
fn tag(state: &AppState) -> &'static str {
    match state {
        AppState::MissingVault { .. } => "MissingVault",
        AppState::Unlock { .. } => "Unlock",
        AppState::Locked { .. } => "Locked",
        AppState::Unlocked { .. } => "Unlocked",
        AppState::StartupError { .. } => "StartupError",
    }
}

// ---------------------------------------------------------------------------
// Dispatch loop (IMPLEMENTATION_PLAN_03_TUI.md > Event loop (per §6))
// ---------------------------------------------------------------------------

#[test]
fn dispatch_renders_initial_state_before_processing_events() {
    // Plan: *"`app::run` ... install a drop guard before the first
    // draw"*. The first draw paints the initial state — the user
    // expects the screen up at startup, not blank-until-first-tick.
    // Pin that by sending a single Ctrl-C (which Quits immediately
    // after one event) and asserting the renderer was called with
    // the initial state + initial wall-clock *before* the post-event
    // path would have run.
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let initial = missing("/tmp/v.bin");
    let initial_wc = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    tx.send(ctrl_c()).expect("send ctrl-c");

    let renders: Rc<RefCell<Vec<(&'static str, SystemTime)>>> = Rc::default();
    let renders_clone = renders.clone();

    let _final_state = dispatch(
        initial,
        &rx,
        &tx,
        move |state, wc| {
            renders_clone.borrow_mut().push((tag(state), wc));
        },
        initial_wc,
    );

    let r = renders.borrow();
    assert!(
        !r.is_empty(),
        "dispatch must render at least once before exiting",
    );
    assert_eq!(
        r[0],
        ("MissingVault", initial_wc),
        "first render must be the initial state with the initial wall-clock",
    );
}

#[test]
fn dispatch_returns_when_reducer_emits_effect_quit() {
    // Plan: *"`Quit` is special: it carries no `AppEvent` because the
    // run loop uses the return value to break out of its dispatch
    // loop"*. Pin that by sending Ctrl-C — the reducer maps it to
    // `Effect::Quit`, and the dispatch loop must return so the caller
    // can run terminal teardown.
    let (tx, rx) = mpsc::channel::<AppEvent>();
    tx.send(ctrl_c()).expect("send ctrl-c");

    // If `dispatch` doesn't return, this test hangs the suite. A
    // watchdog isn't necessary — the channel has exactly one event
    // and an immediate-Quit reducer path, so a regression that fails
    // to exit shows up as a CI timeout. The next regression test
    // (channel hangup) is the watchdog-protected variant.
    let _final_state = dispatch(
        missing("/tmp/v.bin"),
        &rx,
        &tx,
        |_, _| {},
        SystemTime::UNIX_EPOCH,
    );
}

#[test]
fn dispatch_returns_when_producer_channel_disconnects() {
    // The production input + ticker threads exit on their own when
    // the dispatch loop drops the receiver. The mirror contract:
    // if every sender on the receiver's end has been dropped, the
    // dispatch loop's `recv()` returns `Err(_)` and the loop must
    // exit cleanly so terminal teardown can run.
    //
    // Drop every sender on the production channel before calling
    // dispatch; pass a separate dummy `Sender` so the executor still
    // has somewhere to send effect results (none will be emitted on
    // this path, but the API still needs the handle).
    let (tx, rx) = mpsc::channel::<AppEvent>();
    drop(tx);
    let (dummy_tx, _dummy_rx) = mpsc::channel::<AppEvent>();

    // Watchdog the call so a hung loop surfaces as a test failure
    // rather than a stalled suite.
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = dispatch(
            missing("/tmp/v.bin"),
            &rx,
            &dummy_tx,
            |_, _| {},
            SystemTime::UNIX_EPOCH,
        );
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("dispatch must return when the producer channel disconnects");
}

#[test]
fn dispatch_threads_latest_tick_wall_clock_into_render() {
    // Plan: *"`now` is the wall-clock instant the renderer should use
    // for TOTP-window math ... The event loop feeds it the
    // `wall_clock` from the latest `Tick`."* Pin the seam: a Tick
    // arriving before a Ctrl-C must surface as the wall-clock of the
    // render call that paints the post-Tick state. The initial
    // render still uses `initial_wall_clock` because no Tick has
    // arrived yet.
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let initial_wc = SystemTime::UNIX_EPOCH;
    let tick_wc = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    tx.send(tick(tick_wc)).expect("send tick");
    tx.send(ctrl_c()).expect("send ctrl-c");

    let renders: Rc<RefCell<Vec<SystemTime>>> = Rc::default();
    let renders_clone = renders.clone();

    let _final_state = dispatch(
        missing("/tmp/v.bin"),
        &rx,
        &tx,
        move |_, wc| {
            renders_clone.borrow_mut().push(wc);
        },
        initial_wc,
    );

    let r = renders.borrow();
    assert!(
        r.len() >= 2,
        "expected initial render + post-Tick render, got {} renders",
        r.len(),
    );
    assert_eq!(r[0], initial_wc, "initial render uses initial_wall_clock");
    assert_eq!(
        r[1], tick_wc,
        "post-Tick render uses the latest Tick's wall_clock",
    );
}

#[test]
fn dispatch_renders_once_per_non_quit_event_then_exits_without_post_quit_render() {
    // Cadence contract: one initial render, then one render after
    // each event whose effects do not Quit. The event that emits
    // `Effect::Quit` does *not* produce a trailing render — the loop
    // breaks before the render call so terminal teardown can run
    // promptly. Drive two passthrough Ticks followed by a Ctrl-C and
    // count: initial + 2 ticks = 3 renders, no fourth render.
    let (tx, rx) = mpsc::channel::<AppEvent>();
    tx.send(tick(SystemTime::UNIX_EPOCH)).expect("send tick 1");
    tx.send(tick(SystemTime::UNIX_EPOCH)).expect("send tick 2");
    tx.send(ctrl_c()).expect("send ctrl-c");

    let count: Rc<RefCell<usize>> = Rc::default();
    let count_clone = count.clone();

    let _final_state = dispatch(
        missing("/tmp/v.bin"),
        &rx,
        &tx,
        move |_, _| {
            *count_clone.borrow_mut() += 1;
        },
        SystemTime::UNIX_EPOCH,
    );

    assert_eq!(
        *count.borrow(),
        3,
        "expected 1 initial render + 2 post-tick renders, no post-Quit render",
    );
}

#[test]
fn dispatch_renders_state_after_reducer_applies_event() {
    // The render after each event must observe the state the reducer
    // produced for *that* event, not the prior state. A Tick on
    // `MissingVault` is a passthrough so the variant tag stays
    // `MissingVault`, but the render must still be called after the
    // reducer ran — pin that by counting renders. (State-content
    // assertions live in the reducer tests; this slice asserts the
    // *cadence* of reduce → render.)
    let (tx, rx) = mpsc::channel::<AppEvent>();
    tx.send(tick(SystemTime::UNIX_EPOCH)).expect("send tick");
    tx.send(ctrl_c()).expect("send ctrl-c");

    let last_tag: Rc<RefCell<Option<&'static str>>> = Rc::default();
    let last_tag_clone = last_tag.clone();

    let _final_state = dispatch(
        missing("/tmp/v.bin"),
        &rx,
        &tx,
        move |state, _| {
            *last_tag_clone.borrow_mut() = Some(tag(state));
        },
        SystemTime::UNIX_EPOCH,
    );

    assert_eq!(
        *last_tag.borrow(),
        Some("MissingVault"),
        "render observes the reducer-produced state",
    );
}
