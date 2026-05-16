// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production composer for the TUI event loop.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//!
//! > Effects are executed by `app::run`, which is the only boundary
//! > that may call impure core / clipboard / writer functions.
//!
//! [`run_event_loop`] is the testable composer that owns the
//! `mpsc<AppEvent>` channel + producer spawning + the
//! [`crate::app::dispatch::dispatch`] call. Production callers pass
//! [`crate::app::input::spawn`] and [`crate::app::ticker::spawn`] as
//! the producer spawners; tests in
//! `crates/paladin-tui/tests/run_tests.rs` pass fake spawners that
//! drive the channel synchronously so the sender-clone + dispatch
//! completion contract is exercised without a TTY.
//!
//! Terminal lifecycle (raw mode / alternate screen / drop guard) is
//! intentionally *not* part of this composer — it is layered above in
//! a separate slice. Keeping the event-loop composer terminal-free is
//! what makes it unit-testable against `dispatch` here.

use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::SystemTime;

use crate::app::dispatch::dispatch;
use crate::app::event::AppEvent;
use crate::app::state::AppState;

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
