// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ticker thread tests for `paladin-auth-tui`.
//!
//! Tracks `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//! *"Ticker thread — sleeps `paladin_auth_core::TICK_INTERVAL_MS`, emits
//! `AppEvent::Tick { wall_clock, monotonic }`."* The producer is a
//! long-lived thread that the reducer drives off; the only impure
//! observable it owns is the channel send. These tests pin the cadence,
//! the clock-sampling contract (both `wall_clock` and `monotonic`
//! advance), and the receiver-hangup shutdown so the production event
//! loop can drop the receiver to bring the ticker down on quit /
//! auto-lock-to-locked / panic.

use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use paladin_auth_core::TICK_INTERVAL_MS;
use paladin_auth_tui::app::event::AppEvent;
use paladin_auth_tui::app::ticker;

/// Nominal sleep between ticks.
const TICK: Duration = Duration::from_millis(TICK_INTERVAL_MS);

/// Generous slack for scheduler jitter on busy CI hosts. Used as the
/// receive timeout so flakes do not surface from a host that is
/// momentarily slow; the cadence assertion still uses
/// `TICK_INTERVAL_MS` directly with its own (smaller) slack.
const RECV_SLACK: Duration = Duration::from_secs(2);

fn unwrap_tick(evt: AppEvent) -> (SystemTime, Instant) {
    match evt {
        AppEvent::Tick {
            wall_clock,
            monotonic,
        } => (wall_clock, monotonic),
        other => panic!("expected AppEvent::Tick, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Ticker thread (docs/IMPLEMENTATION_PLAN_03_TUI.md > Event loop > Ticker thread)
// ---------------------------------------------------------------------------

#[test]
fn spawn_emits_tick_events_with_advancing_wall_and_monotonic_clocks() {
    // Two consecutive ticks must arrive on the channel, both as
    // `AppEvent::Tick` (not `Input` / `EffectResult` / `ClipboardClear`),
    // with both their wall-clock and monotonic samples strictly
    // advancing — the plan calls out *both* clocks specifically because
    // wall-clock drives TOTP counter math (`SystemTime`) and the
    // monotonic clock drives UI deadlines (`Instant`).
    let (tx, rx) = mpsc::channel();
    let _handle = ticker::spawn(tx);

    let first = rx
        .recv_timeout(TICK + RECV_SLACK)
        .expect("ticker emits a first Tick within TICK_INTERVAL_MS + slack");
    let second = rx
        .recv_timeout(TICK + RECV_SLACK)
        .expect("ticker emits a second Tick within TICK_INTERVAL_MS + slack");

    let (wall1, mono1) = unwrap_tick(first);
    let (wall2, mono2) = unwrap_tick(second);

    assert!(
        mono2 > mono1,
        "monotonic clock must advance strictly between consecutive ticks (mono1={mono1:?}, mono2={mono2:?})",
    );
    let dt = wall2
        .duration_since(wall1)
        .expect("wall_clock advances forwards across consecutive ticks");
    // Cadence floor: the second tick should be at least one
    // `TICK_INTERVAL_MS` after the first, modulo small scheduler slack.
    // Use 50 ms of slack so the assertion does not flake on a busy CI
    // host whose `thread::sleep` undershoots the requested interval.
    let cadence_slack = Duration::from_millis(50);
    let cadence_floor = TICK.saturating_sub(cadence_slack);
    assert!(
        dt >= cadence_floor,
        "wall_clock gap should be >= TICK_INTERVAL_MS - 50ms ({cadence_floor:?}), got {dt:?}",
    );
}

#[test]
fn spawn_thread_exits_when_receiver_is_dropped() {
    // The reducer brings the ticker down by dropping the receiver
    // (channel hangup); the ticker thread observes the failed
    // `Sender::send` and returns from its loop. This is the production
    // shutdown path on `Effect::Quit`, on `Ctrl-C`, and on panic
    // unwind — `Sender::send` is the only way the ticker learns the
    // reducer has gone away because it does not poll any other
    // shutdown signal.
    let (tx, rx) = mpsc::channel();
    let handle = ticker::spawn(tx);

    // Wait for the first tick so we know the thread is running before
    // we drop the receiver — otherwise we'd race the spawn.
    let _evt = rx
        .recv_timeout(TICK + RECV_SLACK)
        .expect("ticker emits a Tick before we drop the receiver");
    drop(rx);

    // Watchdog: hand the join off to a helper thread that signals on a
    // bounded channel so the test cannot hang the suite if the ticker
    // never notices the hangup. The ticker is asleep for at most one
    // `TICK_INTERVAL_MS`, so it must terminate within ~one interval
    // after the hangup; allow generous slack for scheduler jitter.
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = handle.join();
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(TICK + RECV_SLACK)
        .expect("ticker thread terminates within TICK_INTERVAL_MS + slack after receiver drop");
}

#[test]
fn spawn_first_tick_is_not_emitted_synchronously() {
    // The plan's wording — *"sleeps `TICK_INTERVAL_MS`, emits"* — fixes
    // the order: sleep first, then emit. Pin that so a future
    // refactor cannot accidentally turn the loop into "emit immediately
    // then sleep" (which would burn one frame's worth of wall-clock
    // budget on a tick that arrived before the renderer was ready and
    // would shorten the auto-lock idle accounting on startup).
    let (tx, rx) = mpsc::channel();
    let _handle = ticker::spawn(tx);

    // Strictly less than one full interval — the floor is generous
    // enough that scheduler jitter does not flake this assertion, but
    // tight enough that an immediate-emit regression surfaces. 50 ms
    // is well under TICK_INTERVAL_MS (250 ms).
    let too_soon = Duration::from_millis(50);
    let err = rx
        .recv_timeout(too_soon)
        .expect_err("first Tick must not arrive within 50ms of spawn");
    assert!(
        matches!(err, mpsc::RecvTimeoutError::Timeout),
        "expected a Timeout error, got {err:?}",
    );
}
