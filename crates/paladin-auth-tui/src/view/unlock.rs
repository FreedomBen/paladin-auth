// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unlock screen renderer.
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Startup / vault modes" #5
//! and `docs/DESIGN.md` §6: when `inspect(path)` returns
//! [`paladin_auth_core::VaultStatus::Encrypted`], the TUI shows the
//! unlock screen and prompts for the passphrase inside the terminal;
//! wrong passphrases (`decrypt_failed`) keep the user on this screen
//! with an inline error per `decide_state_from_open`.
//!
//! The renderer masks the typed passphrase so onlookers see one
//! `•` glyph per typed character but never the bytes themselves. It
//! never reads or logs the buffer beyond [`char_count`] above, and
//! never performs I/O.
//!
//! [`char_count`]: <https://doc.rust-lang.org/std/primitive.str.html#method.chars>

use std::path::Path;

use ratatui::layout::Alignment;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph, Wrap};
use ratatui::Frame;

use crate::prompt::PassphraseBuffer;
use crate::view::theme;

/// Render the unlock screen for the given vault `path`.
///
/// `error` carries the inline `decrypt_failed` from a previous wrong
/// attempt (per the L1791 snapshot); when `None`, the error line is
/// omitted entirely. `passphrase` is rendered as a row of `•`
/// glyphs — one per typed character — so the secret bytes never reach
/// the rendered grid.
pub fn render(
    frame: &mut Frame<'_>,
    path: &Path,
    error: Option<&str>,
    passphrase: &PassphraseBuffer,
    no_color: bool,
) {
    let area = frame.area();

    let block = theme::titled_block(
        " Paladin Auth — unlock ",
        no_color,
        Padding::symmetric(2, 1),
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mask: String = "•".repeat(passphrase.as_str().chars().count());

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::raw("Vault: "),
            Span::styled(
                path.display().to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::raw("Passphrase: "), Span::raw(mask)]),
    ];

    if let Some(msg) = error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            msg.to_string(),
            theme::fg(theme::ERROR, no_color),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from("Press Enter to unlock; Esc or Ctrl-C to quit."));
    // Forgot-passphrase escape hatch (DESIGN §6 / Milestone 10): the
    // destroy chord is advertised here so a locked-out user can wipe
    // the vault without dropping to a shell. Sourced from the shared
    // keybindings table so the hint and the Help-overlay row cannot
    // drift.
    lines.push(Line::from(Span::styled(
        crate::keybindings::destroy_footer_hint(),
        theme::fg(theme::WARN, no_color),
    )));

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}
