// SPDX-License-Identifier: AGPL-3.0-or-later

//! List-view renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Insta snapshots > Layout / list views": once the vault is open
//! the TUI shows a single-screen list view — a bordered `Paladin`
//! block containing a search bar, a separator, the account-row pane,
//! a second separator, and a bottom keybinding hint.
//!
//! This slice lands the empty-vault branch: when `vault.iter()`
//! yields nothing, the rows pane shows a single centered
//! "No accounts. Press `a` to add one." line. The populated branches
//! (single-TOTP, mixed TOTP/HOTP with hidden + revealed rows,
//! search-active filtering, `zz`-recentered viewport) land in
//! subsequent slices alongside their own snapshot tests.
//!
//! The renderer never mutates application state and never performs
//! I/O — every value it reads comes from the supplied [`AppState`].

use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;

use crate::app::state::AppState;

/// Render the list-view screen for the given Unlocked `state`.
///
/// Caller is responsible for matching `AppState::Unlocked` before
/// dispatching here; non-Unlocked variants are a no-op so a future
/// stray call leaves the backend at its default fill rather than
/// panicking.
pub fn render(frame: &mut Frame<'_>, state: &AppState) {
    let AppState::Unlocked {
        vault,
        search_query,
        ..
    } = state
    else {
        return;
    };

    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Paladin ")
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Top-to-bottom: search line, divider, rows pane, divider, hint.
    // Fixed-height rows hug the borders so the rows pane is the only
    // flexible region, matching the §6 mock where the keybinding hint
    // sits flush with the bottom border.
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(inner);

    let search_line = Line::from(vec![
        Span::raw("Search: "),
        Span::raw(search_query.as_str()),
    ]);
    frame.render_widget(Paragraph::new(search_line), chunks[0]);

    let divider = "─".repeat(inner.width as usize);
    frame.render_widget(Paragraph::new(divider.clone()), chunks[1]);

    if vault.iter().next().is_none() {
        // Empty-state guidance: the centered single-line prompt
        // mirrors the §6 / DESIGN.md add-flow keybinding (`a`) so a
        // user who lands on an empty vault sees what to press next.
        let lines = vec![
            Line::from(""),
            Line::from(Span::raw("No accounts. Press `a` to add one.")),
        ];
        let paragraph = Paragraph::new(lines).alignment(Alignment::Center);
        frame.render_widget(paragraph, chunks[2]);
    }
    // Populated branches land in the next slice (single-TOTP, then
    // mixed TOTP / HOTP with hidden + revealed rows, then search and
    // `zz` recenter). They share `chunks[2]` as the rows pane.

    frame.render_widget(Paragraph::new(divider), chunks[3]);

    let hint = "[↑↓] move  [enter] copy  [n] next-HOTP  [a] add  [/] find";
    frame.render_widget(Paragraph::new(hint), chunks[4]);
}
