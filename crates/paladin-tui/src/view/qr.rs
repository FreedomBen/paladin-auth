// SPDX-License-Identifier: AGPL-3.0-or-later

//! QR Export modal renderer (v0.2; DESIGN §4.6 / §6).
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > QR
//! Export: *"single-account QR modal opened with `Q` (Shift-q) on
//! the focused list row. The modal is a small two-page state
//! machine"*. Page 1 (`WarningAck`) renders the warning body from
//! [`paladin_core::format_plaintext_qr_export_warning`] plus an ack
//! checkbox and Cancel button; Page 2 (`QrAndActions`) renders the
//! cached ANSI half-block QR body with the account's
//! `summary_display_label` caption and Save as PNG / Save as SVG /
//! Done buttons below.
//!
//! The Page 2 ANSI body is **cached on modal state**
//! ([`QrExportModal::staged_ansi`]) rather than re-rendered every
//! frame; the reducer populates the slot when the user acks the
//! warning on Page 1 and drops it (zeroizing) when the user toggles
//! the ack back off, closes the modal, or the auto-lock fires. The
//! renderer pulls from that cache so a missing slot falls back to a
//! defensive "no body" line rather than calling
//! [`paladin_core::Vault::export_qr_ansi`] from the view layer (the
//! view never touches core state).
//!
//! The modal is overlaid on top of the list view by
//! [`super::render`] and is responsible for the
//! [`ratatui::widgets::Clear`] pass on its own rect before painting
//! — otherwise list-view content would bleed through transparent
//! cells. Mirrors the overlay pattern used by every other modal
//! renderer.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Padding, Paragraph, Wrap};
use ratatui::Frame;

use paladin_core::{format_plaintext_qr_export_warning, summary_display_label, Vault};

use super::centered_rect;
use crate::app::state::{QrExportFocus, QrExportModal, QrExportPage};
use crate::view::theme;

/// Render the QR Export modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 72×24 bordered block centered inside the frame's
/// rect — wider than the other modals because Page 2 needs to fit
/// the half-block QR grid (a v10 QR with quiet zone is about 53
/// modules wide; at half-block density that is 27 columns, plus
/// caption + footer hint). The 72-cell width matches the Export
/// modal so the two surfaces line up visually when the user moves
/// between them.
pub fn render(frame: &mut Frame<'_>, modal: &QrExportModal, vault: &Vault, no_color: bool) {
    let modal_area = centered_rect(frame.area(), 72, 24);
    frame.render_widget(Clear, modal_area);

    let block = theme::titled_block(" QR Export ", no_color, Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    match modal.page {
        QrExportPage::WarningAck => render_warning_ack(frame, inner, modal, no_color),
        QrExportPage::QrAndActions => render_qr_and_actions(frame, inner, modal, vault, no_color),
    }
}

/// Render Page 1: the verbatim warning body, the ack checkbox, and
/// the Cancel button.
///
/// The ANSI QR body is **never** rendered here so a closing-terminal
/// glimpse cannot expose the secret per DESIGN §4.6.
fn render_warning_ack(frame: &mut Frame<'_>, inner: Rect, modal: &QrExportModal, no_color: bool) {
    let chunks = Layout::vertical([
        Constraint::Min(0),    // warning body (wraps)
        Constraint::Length(1), // blank
        Constraint::Length(1), // ack checkbox row
        Constraint::Length(1), // blank
        Constraint::Length(1), // Cancel button row
        Constraint::Length(1), // blank
        Constraint::Length(1), // error
        Constraint::Length(1), // hint
    ])
    .split(inner);

    let warning = format_plaintext_qr_export_warning();
    let warning_para = Paragraph::new(Span::styled(warning, theme::fg(theme::WARN, no_color)))
        .wrap(Wrap { trim: false });
    frame.render_widget(warning_para, chunks[0]);

    frame.render_widget(
        Paragraph::new(ack_checkbox_line(modal, no_color)),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(button_line(
            "Cancel",
            modal.focus == QrExportFocus::CancelButton,
        )),
        chunks[4],
    );

    if let Some(error) = &modal.error {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                error.clone(),
                theme::fg(theme::ERROR, no_color),
            ))),
            chunks[6],
        );
    }

    let hint = "Space / Enter toggles ack  ·  Tab cycles  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[7]);
}

/// Render Page 2: the account caption above the cached ANSI QR
/// body, followed by the Save PNG / Save SVG / Done button row.
///
/// The caption uses [`paladin_core::summary_display_label`] for
/// CLI / GUI parity. The ANSI body is pulled from
/// [`QrExportModal::staged_ansi`] (populated by the reducer on
/// ack-toggle-on); a missing slot renders a defensive placeholder.
fn render_qr_and_actions(
    frame: &mut Frame<'_>,
    inner: Rect,
    modal: &QrExportModal,
    vault: &Vault,
    no_color: bool,
) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // caption
        Constraint::Min(0),    // ANSI QR body
        Constraint::Length(1), // blank
        Constraint::Length(1), // button row
        Constraint::Length(1), // blank
        Constraint::Length(1), // last-save / error
        Constraint::Length(1), // hint
    ])
    .split(inner);

    let caption = vault
        .get(modal.account_id)
        .map(|a| summary_display_label(&a.summary()))
        .unwrap_or_default();
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            caption,
            theme::fg_bold(theme::ACCENT, no_color),
        )))
        .alignment(Alignment::Center),
        chunks[0],
    );

    let body = modal
        .staged_ansi
        .as_ref()
        .map(|rendered| rendered.as_str().to_owned())
        .unwrap_or_default();
    frame.render_widget(
        Paragraph::new(body)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    let buttons = Line::from(format!(
        "{}   {}   {}",
        button_label("Save as PNG…", modal.focus == QrExportFocus::SavePngButton),
        button_label("Save as SVG…", modal.focus == QrExportFocus::SaveSvgButton),
        button_label("Done", modal.focus == QrExportFocus::DoneButton),
    ));
    frame.render_widget(
        Paragraph::new(buttons).alignment(Alignment::Center),
        chunks[3],
    );

    if let Some(error) = &modal.error {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                error.clone(),
                theme::fg(theme::ERROR, no_color),
            )))
            .alignment(Alignment::Center),
            chunks[5],
        );
    } else if let Some(path) = &modal.last_save_path {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("Saved to {}", path.display()),
                theme::fg(theme::SUCCESS, no_color),
            )))
            .alignment(Alignment::Center),
            chunks[5],
        );
    }

    let hint = "Tab cycles buttons  ·  Enter activates  ·  Esc close";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[6]);
}

/// Render the ack checkbox row: `[ ] I understand the warning` or
/// `[x] I understand the warning`, with the focused checkbox
/// painted in the accent color.
fn ack_checkbox_line(modal: &QrExportModal, no_color: bool) -> Line<'static> {
    let mark = if modal.ack { "[x]" } else { "[ ]" };
    let mark_span = if modal.focus == QrExportFocus::AckCheckbox {
        Span::styled(
            format!("▶ {mark} "),
            theme::fg_bold(theme::ACCENT, no_color),
        )
    } else {
        Span::raw(format!("  {mark} "))
    };
    Line::from(vec![mark_span, Span::raw("I understand the warning")])
}

/// Centered single-button line — used for the Page-1 Cancel button.
fn button_line(label: &str, active: bool) -> Line<'static> {
    Line::from(button_label(label, active)).alignment(Alignment::Center)
}

/// Render a button label with focus brackets: `▶ Label ◀` when
/// focused, `  Label  ` otherwise.
fn button_label(label: &str, active: bool) -> String {
    if active {
        format!("▶ {label} ◀")
    } else {
        format!("  {label}  ")
    }
}
