// SPDX-License-Identifier: AGPL-3.0-or-later

//! Startup-error screen renderer.
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Startup / vault modes" #6
//! and `docs/DESIGN.md` §6: when vault-path resolution fails, or
//! `inspect` / `open` returns any error other than `decrypt_failed`,
//! the TUI shows a non-mutating screen with the error text and quits
//! on `Esc`, `q`, or `Ctrl-C`. `unsafe_permissions` errors render the
//! `Some(text)` from [`paladin_core::format_unsafe_permissions`]
//! verbatim — the pre-rendered string lives on
//! [`crate::app::state::AppState::StartupError::message`] so this
//! renderer just splits on `\n` and writes each line.
//!
//! The screen is read-only: it never mutates state, never performs
//! I/O, and never creates or rotates files.

use std::path::Path;

use ratatui::layout::Alignment;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph, Wrap};
use ratatui::Frame;

use crate::view::theme;

/// Render the startup-error screen.
///
/// `path` is `None` only when `default_vault_path()` itself failed
/// (per the deferred-test note in `docs/IMPLEMENTATION_PLAN_03_TUI.md`
/// "Tests > Vault modes and startup"). `message` is the pre-rendered
/// error text — `unsafe_permissions` errors carry the multi-line
/// `Some(text)` from [`paladin_core::format_unsafe_permissions`]
/// verbatim; every other variant carries the error's `Display`.
pub fn render(frame: &mut Frame<'_>, path: Option<&Path>, message: &str, no_color: bool) {
    let area = frame.area();

    let block = theme::destructive_titled_block(
        " Paladin — startup error ",
        no_color,
        Padding::symmetric(2, 1),
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line<'_>> = Vec::new();
    if let Some(p) = path {
        lines.push(Line::from(vec![
            Span::raw("Vault path: "),
            Span::styled(
                p.display().to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(""));
    }
    for raw in message.lines() {
        lines.push(Line::from(raw.to_string()));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Press Esc, q, or Ctrl-C to quit."));

    // Wrap long lines so verbatim `format_unsafe_permissions` text and
    // long vault paths stay visible at narrow terminal widths instead of
    // being truncated at the right border. `trim: false` preserves any
    // intentional leading whitespace inside the pre-rendered message.
    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}
