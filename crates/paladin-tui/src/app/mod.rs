// SPDX-License-Identifier: AGPL-3.0-or-later

//! TUI application state machine, event union, side-effect set, and
//! pure reducer.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)" the
//! reducer is a pure function over `(state, event) → (state, Vec<Effect>)`
//! so it can be unit-tested without a terminal. Impure side effects
//! (core calls, clipboard writes, terminal I/O) are confined to
//! the `run` boundary, which is wired in subsequent slices.

pub mod dispatch;
pub mod effect;
pub mod event;
pub mod input;
pub mod reducer;
pub mod render;
pub mod run;
pub mod state;
pub mod ticker;

pub use dispatch::dispatch;
pub use effect::{execute, EffectOutcome};
pub use event::{AppEvent, Effect, EffectResult};
pub use reducer::reduce;
pub use render::draw_frame;
pub use run::{run_event_loop, run_with_terminal_guard};
pub use state::{
    build_initial_state, build_initial_state_with_resolver, decide_state_from_inspect,
    decide_state_from_open, render_error_message, AppState, StatusLine, CLIPBOARD_WRITE_FAILED,
    NO_ACCOUNT_SELECTED,
};
