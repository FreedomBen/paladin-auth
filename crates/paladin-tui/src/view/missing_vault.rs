// SPDX-License-Identifier: AGPL-3.0-or-later

//! Missing-vault screen renderer.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Startup / vault modes" and
//! `DESIGN.md` §6: when `inspect(path)` returns
//! [`paladin_core::VaultStatus::Missing`], the TUI shows a
//! non-mutating message telling the user to run `paladin init`.
//! v0.1 TUI does not create vaults.
//!
//! The screen is read-only: `Esc`, `q`, and `Ctrl-C` all quit.

use std::path::Path;

use ratatui::layout::Alignment;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Wrap};
use ratatui::Frame;

/// Render the missing-vault guidance screen for the given vault
/// `path`. The renderer never mutates application state and never
/// performs I/O.
pub fn render(frame: &mut Frame<'_>, path: &Path) {
    let area = frame.area();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Paladin ")
        .padding(Padding::symmetric(2, 1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let path_display = path.display().to_string();
    let lines = vec![
        Line::from("No vault found at:"),
        Line::from(Span::styled(
            path_display,
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Run `paladin init` to create one."),
        Line::from(""),
        Line::from("Press Esc, q, or Ctrl-C to quit."),
    ];

    // Wrap so long vault paths stay visible at narrow terminal widths
    // instead of being truncated at the right border.
    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}
