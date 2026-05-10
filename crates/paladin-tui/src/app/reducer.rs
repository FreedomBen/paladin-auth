// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure reducer: `(state, event) → (state, Vec<Effect>)`.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)" this
//! function is the only place the TUI's state transitions live, so
//! every transition is unit-testable without a terminal. Impure
//! side effects are returned as [`Effect`] values and executed by
//! the `run` boundary; the reducer itself never touches the
//! filesystem, clipboard, or core save paths.

use crate::app::event::{AppEvent, Effect};
use crate::app::state::AppState;

/// Apply one event to the current state and return the new state plus
/// any side effects.
///
/// Phase 1 spine: returns the state unchanged with no effects.
/// Per-event handling (input keys, ticks, effect results, clipboard
/// timers) is added in subsequent implementation slices.
#[must_use]
pub fn reduce(state: AppState, _event: AppEvent) -> (AppState, Vec<Effect>) {
    (state, Vec::new())
}
