// SPDX-License-Identifier: AGPL-3.0-or-later

//! ratatui rendering for `paladin-tui`.
//!
//! Each [`crate::app::state::AppState`] variant routes through one
//! `render_*` sub-module. The functions write to the supplied
//! [`ratatui::Frame`] only — no I/O, no `AppState` mutation — so
//! `tests/view_snapshots.rs` can drive each screen through
//! [`ratatui::backend::TestBackend`] and snapshot the rendered text
//! grid via `insta::assert_snapshot!`.
//!
//! Screen renderers land slice-by-slice per
//! `IMPLEMENTATION_PLAN_03_TUI.md` "Tests > Insta snapshots":
//! missing-vault / startup-error / unlock first (read-only
//! dead-end screens), list view next (with TOTP gauges,
//! HOTP reveal labels, status-line states, and search highlighting),
//! then modals and overlays.

pub mod list;
pub mod missing_vault;
pub mod startup_error;
pub mod unlock;

use ratatui::Frame;

use crate::app::state::AppState;

/// Render the given [`AppState`] onto `frame`.
///
/// Variants whose renderers have not yet landed in this slice draw
/// nothing — the screen is left at the backend's default fill cell.
/// Subsequent slices fill those branches in order; the per-variant
/// fan-out matches the plan's "Tests > Insta snapshots" ordering.
pub fn render(frame: &mut Frame<'_>, state: &AppState) {
    match state {
        AppState::MissingVault { path } => missing_vault::render(frame, path),
        AppState::StartupError { path, message } => {
            startup_error::render(frame, path.as_deref(), message);
        }
        AppState::Unlock {
            path,
            error,
            passphrase,
        } => {
            unlock::render(frame, path, error.as_deref(), passphrase);
        }
        AppState::Unlocked { .. } => list::render(frame, state),
        AppState::Locked { .. } => {
            // Renderer lands alongside the auto-lock re-unlock slice:
            // `Locked` re-uses the unlock screen with an empty
            // passphrase on the next unlock attempt, and the
            // in-state-machine `Locked → Unlock` handoff on the first
            // keystroke is reducer territory.
        }
    }
}
