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

pub mod add;
pub mod import;
pub mod list;
pub mod missing_vault;
pub mod remove;
pub mod rename;
pub mod startup_error;
pub mod unlock;

use std::time::SystemTime;

use ratatui::layout::Rect;
use ratatui::Frame;

use paladin_core::Vault;

use crate::app::state::{AppState, Modal};

/// Compute a `width × height` rect centered inside `outer`,
/// saturating at `outer` if the requested size is larger than the
/// frame in either dimension. Shared by every modal renderer so the
/// modals all overlay the underlying screen with consistent centering.
pub(super) fn centered_rect(outer: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(outer.width);
    let height = height.min(outer.height);
    let x = outer.x + (outer.width - width) / 2;
    let y = outer.y + (outer.height - height) / 2;
    Rect::new(x, y, width, height)
}

/// Render the given [`AppState`] onto `frame`.
///
/// `now` is the wall-clock instant the renderer should use for
/// TOTP-window math (code / `seconds_remaining` / progress gauge).
/// The event loop feeds it the `wall_clock` from the latest
/// [`crate::app::event::AppEvent::Tick`] so two consecutive frames
/// inside the same TOTP window render identically. Variants that do
/// not surface TOTP codes ignore the parameter.
///
/// Variants whose renderers have not yet landed in this slice draw
/// nothing — the screen is left at the backend's default fill cell.
/// Subsequent slices fill those branches in order; the per-variant
/// fan-out matches the plan's "Tests > Insta snapshots" ordering.
pub fn render(frame: &mut Frame<'_>, state: &AppState, now: SystemTime) {
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
        AppState::Unlocked { modal, vault, .. } => {
            list::render(frame, state, now);
            if let Some(open) = modal {
                render_modal(frame, open, vault);
            }
        }
        AppState::Locked { .. } => {
            // Renderer lands alongside the auto-lock re-unlock slice:
            // `Locked` re-uses the unlock screen with an empty
            // passphrase on the next unlock attempt, and the
            // in-state-machine `Locked → Unlock` handoff on the first
            // keystroke is reducer territory.
        }
    }
}

/// Dispatch an open [`Modal`] to its per-variant renderer. Each
/// modal's renderer is responsible for the [`ratatui::widgets::Clear`]
/// pass on its own rect before painting; this helper is a pure
/// dispatch table. Variants whose renderers have not yet landed in
/// this slice draw nothing — the list view alone shows underneath
/// until their slice ticks the corresponding plan checkbox.
///
/// The active [`Vault`] is threaded through so per-variant renderers
/// that need to surface account metadata (e.g. the Remove
/// confirmation prompt naming the selected account) can resolve their
/// `AccountId` against the same in-memory vault the list view paints,
/// rather than caching projection state on the modal struct.
fn render_modal(frame: &mut Frame<'_>, modal: &Modal, vault: &Vault) {
    match modal {
        Modal::Add(add_modal) => add::render(frame, add_modal),
        Modal::Remove(remove_modal) => remove::render(frame, remove_modal, vault),
        Modal::Rename(rename_modal) => rename::render(frame, rename_modal, vault),
        Modal::Import(import_modal) => import::render(frame, import_modal),
        Modal::Export(_) | Modal::Passphrase(_) | Modal::Settings(_) => {
            // Per-variant renderers land alongside each modal's
            // own "Tests > Insta snapshots > Modals and overlays"
            // checklist row in `IMPLEMENTATION_PLAN_03_TUI.md`.
        }
    }
}
