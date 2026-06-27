// SPDX-License-Identifier: AGPL-3.0-or-later

//! Create-vault wizard renderer.
//!
//! Per `docs/DESIGN.md` §6 and `docs/IMPLEMENTATION_PLAN_03_TUI.md`
//! "Startup / vault modes": when [`paladin_auth_core::inspect`] returns
//! [`paladin_auth_core::VaultStatus::Missing`], the TUI walks the user
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
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph, Wrap};
use ratatui::Frame;

use paladin_auth_core::format_plaintext_storage_warning;

use crate::app::state::{AppState, CreateVaultMode, CreateVaultStep, PassphraseFieldFocus};
use crate::prompt::PassphraseBuffer;
use crate::view::theme;

/// Render the create-vault wizard for the given vault `path` at the
/// given `step`. `error`, when `Some`, is rendered as an inline red
/// error line beneath the step body.
pub fn render(
    frame: &mut Frame<'_>,
    path: &Path,
    step: &CreateVaultStep,
    error: Option<&str>,
    no_color: bool,
) {
    let area = frame.area();

    let block = theme::titled_block(
        " Paladin Auth — create vault ",
        no_color,
        Padding::symmetric(2, 1),
    );
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
        CreateVaultStep::ConfirmPlaintext => render_confirm_plaintext(&mut lines, no_color),
        CreateVaultStep::EnterPassphrase {
            passphrase,
            confirmation,
            focus,
        } => render_enter_passphrase(&mut lines, passphrase, confirmation, *focus),
    }

    if let Some(msg) = error {
        // The Destroy modal's success / `vault_missing` paths land here
        // carrying a neutral post-destroy confirmation (Milestone 10),
        // which renders in the confirmation palette rather than the
        // red error palette; every other message is a genuine error.
        let style = if AppState::is_destroy_notice(msg) {
            theme::fg(theme::SUCCESS, no_color)
        } else {
            theme::fg(theme::ERROR, no_color)
        };
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(msg.to_string(), style)));
    }

    // Forgot-passphrase escape hatch (DESIGN §6 / Milestone 10): the
    // destroy chord is advertised on the create-vault screen too so a
    // user who landed here wanting to wipe + recreate a vault discovers
    // the binding. Sourced from the shared keybindings table.
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        crate::keybindings::destroy_footer_hint(),
        theme::fg(theme::WARN, no_color),
    )));

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

fn render_confirm_plaintext(lines: &mut Vec<Line<'_>>, no_color: bool) {
    lines.push(Line::from(Span::styled(
        "Plaintext vault confirmation",
        theme::fg_bold(theme::WARN, no_color),
    )));
    lines.push(Line::from(""));
    for warning_line in format_plaintext_storage_warning().lines() {
        lines.push(Line::from(Span::styled(
            warning_line.to_string(),
            theme::fg(theme::WARN, no_color),
        )));
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
