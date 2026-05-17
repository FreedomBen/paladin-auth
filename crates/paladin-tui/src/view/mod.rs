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
//! create-vault / startup-error / unlock first (the boundary
//! screens), list view next (with TOTP gauges, HOTP reveal labels,
//! status-line states, and search highlighting), then modals and
//! overlays.

pub mod add;
pub mod create_vault;
pub mod export;
pub mod help;
pub mod import;
pub mod list;
pub mod passphrase;
pub mod remove;
pub mod rename;
pub mod settings;
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
/// `no_color` suppresses ratatui foreground / background color
/// attributes on styled cells — the `--no-color` CLI flag and the
/// `NO_COLOR` environment variable both flow here via
/// [`crate::cli::should_disable_color`], wired through
/// [`crate::app::render::draw_frame`] and
/// [`crate::app::build_render_closure`]. For this slice the flag
/// only gates the list-view's bottom-line status row; the modal
/// renderers grow the same gating in their own slices per
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Global flags".
///
/// Variants whose renderers have not yet landed in this slice draw
/// nothing — the screen is left at the backend's default fill cell.
/// Subsequent slices fill those branches in order; the per-variant
/// fan-out matches the plan's "Tests > Insta snapshots" ordering.
pub fn render(frame: &mut Frame<'_>, state: &AppState, now: SystemTime, no_color: bool) {
    match state {
        AppState::CreateVault { path, step, error } => {
            create_vault::render(frame, path, step, error.as_deref());
        }
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
        AppState::Unlocked {
            modal,
            vault,
            help_open,
            ..
        } => {
            list::render(frame, state, now, no_color);
            if let Some(open) = modal {
                render_modal(frame, open, vault);
            }
            // The read-only Help overlay paints last so it sits on
            // top of any modal that might also be open. The reducer
            // suppresses `?` while a modal is open (per
            // `IMPLEMENTATION_PLAN_03_TUI.md` "Help overlay"), so in
            // practice the two are mutually exclusive — drawing the
            // overlay last is a defensive layer that keeps the
            // dismiss-hint visible if the invariant were ever
            // violated by a future event-source bug.
            if *help_open {
                help::render(frame);
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
        Modal::Export(export_modal) => export::render(frame, export_modal),
        Modal::Passphrase(passphrase_modal) => passphrase::render(frame, passphrase_modal),
        Modal::Settings(settings_modal) => settings::render(frame, settings_modal),
    }
}
