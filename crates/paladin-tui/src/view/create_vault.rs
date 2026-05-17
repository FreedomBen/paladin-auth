// SPDX-License-Identifier: AGPL-3.0-or-later

//! Create-vault wizard renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Startup / vault modes": when [`paladin_core::inspect`] returns
//! [`paladin_core::VaultStatus::Missing`], the TUI walks the user
//! through creating a new vault in-app via the two-step wizard
//! ([`AppState::CreateVault`](crate::app::state::AppState::CreateVault)
//! / [`CreateVaultStep`]).
//!
//! The renderer is pure — it never mutates state or performs I/O —
//! so `tests/view_snapshots.rs` can drive each step through a
//! [`ratatui::backend::TestBackend`] and lock the rendered grid via
//! `insta::assert_snapshot!`.

use std::path::Path;

use ratatui::layout::Alignment;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Wrap};
use ratatui::Frame;

use paladin_core::format_plaintext_storage_warning;

use crate::app::state::{CreateVaultMode, CreateVaultStep, PassphraseFieldFocus};
use crate::prompt::PassphraseBuffer;

/// Render the create-vault wizard for the given vault `path` at the
/// given `step`. `error`, when `Some`, is rendered as an inline red
/// error line beneath the step body.
pub fn render(frame: &mut Frame<'_>, path: &Path, step: &CreateVaultStep, error: Option<&str>) {
    let area = frame.area();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Paladin — create vault ")
        .padding(Padding::symmetric(2, 1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::raw("Vault: "),
            Span::styled(
                path.display().to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
    ];

    match step {
        CreateVaultStep::ChooseMode { selection } => render_choose_mode(&mut lines, *selection),
        CreateVaultStep::ConfirmPlaintext => render_confirm_plaintext(&mut lines),
        CreateVaultStep::EnterPassphrase {
            passphrase,
            confirmation,
            focus,
        } => render_enter_passphrase(&mut lines, passphrase, confirmation, *focus),
    }

    if let Some(msg) = error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            msg.to_string(),
            Style::default().fg(Color::Red),
        )));
    }

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

fn render_choose_mode(lines: &mut Vec<Line<'_>>, selection: CreateVaultMode) {
    lines.push(Line::from("Choose vault protection:"));
    lines.push(Line::from(""));
    lines.push(option_line(
        selection == CreateVaultMode::Encrypted,
        "Encrypted (recommended) — protect this vault with a passphrase.",
    ));
    lines.push(option_line(
        selection == CreateVaultMode::Plaintext,
        "Plaintext (insecure) — store secrets unencrypted on disk.",
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(
        "↑/↓ or j/k to select; Enter to continue; q or Esc to quit.",
    ));
}

fn render_confirm_plaintext(lines: &mut Vec<Line<'_>>) {
    lines.push(Line::from(Span::styled(
        "Plaintext vault confirmation",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));
    for warning_line in format_plaintext_storage_warning().lines() {
        lines.push(Line::from(warning_line.to_string()));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Press Enter to create a plaintext vault."));
    lines.push(Line::from("Press Esc to go back; q or Ctrl-C to quit."));
}

fn render_enter_passphrase(
    lines: &mut Vec<Line<'_>>,
    passphrase: &PassphraseBuffer,
    confirmation: &PassphraseBuffer,
    focus: PassphraseFieldFocus,
) {
    lines.push(Line::from(
        "Enter a passphrase to protect this vault. It cannot be recovered if lost.",
    ));
    lines.push(Line::from(""));
    lines.push(field_line(
        "Passphrase:   ",
        passphrase,
        focus == PassphraseFieldFocus::Passphrase,
    ));
    lines.push(field_line(
        "Confirmation: ",
        confirmation,
        focus == PassphraseFieldFocus::Confirmation,
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Tab or ↑/↓ switches fields; Enter advances or submits; Esc returns; Ctrl-C quits.",
    ));
}

fn option_line(selected: bool, label: &str) -> Line<'_> {
    let marker = if selected { "▶ " } else { "  " };
    let style = if selected {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(marker.to_string(), style),
        Span::styled(label.to_string(), style),
    ])
}

fn field_line<'a>(prefix: &'a str, buffer: &PassphraseBuffer, focused: bool) -> Line<'a> {
    let mask: String = "•".repeat(buffer.as_str().chars().count());
    let caret = if focused { "█" } else { "" };
    let style = if focused {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(prefix, style),
        Span::raw(mask),
        Span::styled(caret.to_string(), style),
    ])
}
