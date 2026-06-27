// SPDX-License-Identifier: AGPL-3.0-or-later

//! Startup-error screen renderer.
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Startup / vault modes" #6
//! and `docs/DESIGN.md` §6: when vault-path resolution fails, or
//! `inspect` / `open` returns any error other than `decrypt_failed`,
//! the TUI shows a non-mutating screen with the error text and quits
//! on `Esc`, `q`, or `Ctrl-C`. `unsafe_permissions` errors render the
//! `Some(text)` from [`paladin_auth_core::format_unsafe_permissions`]
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
/// `Some(text)` from [`paladin_auth_core::format_unsafe_permissions`]
/// verbatim; every other variant carries the error's `Display`.
pub fn render(frame: &mut Frame<'_>, path: Option<&Path>, message: &str, no_color: bool) {
    let area = frame.area();

    let block = theme::destructive_titled_block(
        " Paladin Auth — startup error ",
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
    // Forgot-passphrase escape hatch (DESIGN §6 / Milestone 10): a
    // startup error often means a vault the user can no longer open
    // (corrupt header, unsafe perms). The destroy chord lets them wipe
    // it without a shell. Only shown when a path was resolved — a
    // `default_vault_path` failure (`path: None`) has nothing to
    // destroy. Sourced from the shared keybindings table.
    if path.is_some() {
        lines.push(Line::from(Span::styled(
            crate::keybindings::destroy_footer_hint(),
            theme::fg(theme::WARN, no_color),
        )));
    }

    // Wrap long lines so verbatim `format_unsafe_permissions` text and
    // long vault paths stay visible at narrow terminal widths instead of
    // being truncated at the right border. `trim: false` preserves any
    // intentional leading whitespace inside the pre-rendered message.
    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}
