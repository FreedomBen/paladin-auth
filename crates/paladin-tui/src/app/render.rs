// SPDX-License-Identifier: AGPL-3.0-or-later

//! Adapter that bridges the pure event-loop glue
//! ([`crate::app::dispatch::dispatch`]'s
//! `render: FnMut(&AppState, SystemTime)` closure) to a real
//! [`ratatui::Terminal::draw`] call against [`crate::view::render`].
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)" and the
//! `dispatch` module docs: *"The production `app::run` … supplies a
//! render closure that drives `ratatui::Terminal::draw` against
//! `crate::view::render`."* This module holds that one-liner so the
//! production `app::run` and the integration tests share a single
//! adapter — a regression that ever rewires the closure to call
//! something other than [`crate::view::render`] surfaces in
//! `tests/render_tests.rs::draw_frame_*_matches_view_render_baseline`.
//!
//! The adapter intentionally returns the underlying
//! [`io::Result`] rather than swallowing it: the production caller
//! lifts a `draw` failure to the same teardown path as any other
//! terminal-I/O failure so the [`crate::terminal::TerminalGuard`]
//! drop still runs and the user's terminal is restored. The
//! [`crate::app::dispatch::dispatch`] loop itself takes an
//! infallible closure, so production code wraps `draw_frame` in a
//! closure that handles the failure mode (the dispatch loop never
//! sees the `Result`).

use std::io;
use std::time::SystemTime;

use ratatui::backend::Backend;
use ratatui::Terminal;

use crate::app::state::AppState;
use crate::view::render;

/// Drive one frame of [`crate::view::render`] through `terminal`.
///
/// Forwards `state`, `now`, and `no_color` straight into the
/// renderer; `now` is the wall-clock the TOTP-window math should
/// use and `no_color` suppresses foreground / background color
/// attributes on styled cells (see [`crate::view::render`]).
///
/// # Errors
///
/// Returns the [`io::Error`] from [`ratatui::Terminal::draw`] if the
/// underlying backend reports a write failure. Production callers
/// surface this through the terminal-guard teardown path so the
/// alternate-screen / raw-mode restoration still runs.
pub fn draw_frame<B: Backend>(
    terminal: &mut Terminal<B>,
    state: &AppState,
    now: SystemTime,
    no_color: bool,
) -> io::Result<()> {
    terminal.draw(|frame| render(frame, state, now, no_color))?;
    Ok(())
}
