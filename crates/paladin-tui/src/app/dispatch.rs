// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure event-loop glue between the reducer, the effect executor, and
//! the renderer.
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//!
//! > Single thread runs the reducer. ... The reducer is a pure
//! > function over `(state, event) → (state, Vec<Effect>)` so it is
//! > unit-testable without a terminal. Effects are executed by
//! > `app::run`, which is the only boundary that may call impure
//! > core / clipboard / writer functions.
//!
//! [`dispatch`] is the testable inner loop: it consumes events off
//! the supplied `mpsc<AppEvent>` receiver, drives
//! [`crate::app::reducer::reduce`] → [`crate::app::effect::execute`]
//! for each one, threads the latest `Tick` `wall_clock` into the
//! render callback, and exits when an effect returns
//! [`EffectOutcome::Quit`] or the producer channel disconnects. The
//! production `app::run` wraps this with terminal-lifecycle setup
//! and the long-lived input / ticker producer threads, and supplies
//! a render closure that drives `ratatui::Terminal::draw` against
//! [`crate::view::render`].

use std::sync::mpsc::{Receiver, Sender};
use std::time::SystemTime;

use crate::app::effect::{execute, EffectOutcome};
use crate::app::event::AppEvent;
use crate::app::reducer::reduce;
use crate::app::state::AppState;
use crate::clipboard::ClipboardSession;

/// Run the event dispatch loop until an effect returns
/// [`EffectOutcome::Quit`] or the producer side of `rx` disconnects.
///
/// The loop paints the initial state once (so the screen is up
/// before the first event arrives), then on every event runs
/// `reduce(state, event) → (new_state, Vec<Effect>)`, executes each
/// effect against the new state, and re-renders. Effects that emit
/// an [`AppEvent::EffectResult`] route the result back through
/// `tx`; the next `rx.recv()` picks it up and the reducer applies
/// it.
///
/// `tx` is the sender end of the same channel `rx` reads from — the
/// effect executor needs it to deliver effect results back to the
/// reducer. The loop holds its own clone-by-reference (it never
/// clones the sender), so the producer side stays owned by the
/// caller's input / ticker threads.
///
/// `initial_wall_clock` seeds the wall-clock the renderer sees on
/// its first call (no `Tick` has arrived yet). Subsequent renders
/// use the most recent `Tick`'s `wall_clock`. Per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)" and
/// `crate::view::render`: *"The event loop feeds it the `wall_clock`
/// from the latest `Tick`."* The renderer ignores the value for
/// states that do not surface TOTP codes.
///
/// The post-Quit render is intentionally skipped — the run boundary
/// uses the loop's return to tear down the terminal promptly, and a
/// trailing draw call would race the alternate-screen restoration.
///
/// `clipboard` is the long-lived [`ClipboardSession`] owned by
/// [`crate::app::run::run_event_loop`]; effects that touch the OS
/// clipboard borrow it as `&mut` for the duration of the call so
/// the cached `arboard::Clipboard` is reused across the app's
/// lifetime (see `crate::clipboard` module docs).
///
/// The function consumes `initial_state` and returns the final
/// `AppState` so callers can observe what the loop terminated on.
/// Production callers discard it; tests inspect it.
pub fn dispatch<R>(
    initial_state: AppState,
    rx: &Receiver<AppEvent>,
    tx: &Sender<AppEvent>,
    clipboard: &mut ClipboardSession,
    mut render: R,
    initial_wall_clock: SystemTime,
) -> AppState
where
    R: FnMut(&AppState, SystemTime),
{
    let mut state = initial_state;
    let mut wall_clock = initial_wall_clock;
    render(&state, wall_clock);
    while let Ok(event) = rx.recv() {
        // Track the latest Tick's wall-clock so subsequent renders
        // see real time advancing inside the same TOTP window. Match
        // by reference so we can still hand `event` to the reducer.
        if let AppEvent::Tick { wall_clock: wc, .. } = &event {
            wall_clock = *wc;
        }
        let (new_state, effects) = reduce(state, event);
        state = new_state;
        let mut quit = false;
        for effect in effects {
            if execute(effect, &mut state, tx, clipboard) == EffectOutcome::Quit {
                quit = true;
            }
        }
        if quit {
            return state;
        }
        render(&state, wall_clock);
    }
    state
}
