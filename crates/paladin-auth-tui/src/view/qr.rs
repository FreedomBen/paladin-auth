// SPDX-License-Identifier: AGPL-3.0-or-later

//! QR Export modal renderer (v0.2; DESIGN §4.6 / §6).
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > QR
//! Export: *"single-account QR modal opened with `Q` (Shift-q) on
//! the focused list row. The modal is a single page that opens
//! directly on the rendered QR (no acknowledgment gate)"*. The body
//! renders the account's `summary_display_label` caption above the
//! cached ANSI half-block QR, the Save as PNG / Save as SVG / Done
//! buttons (or the active save sub-flow), and the verbatim
//! [`paladin_auth_core::format_plaintext_qr_export_warning`] text as an
//! informational footer beneath the actions.
//!
//! The ANSI body is **cached on modal state**
//! ([`QrExportModal::staged_ansi`]) rather than re-rendered every
//! frame; the reducer populates the slot when the modal opens and
//! drops it (zeroizing) when the modal closes or the auto-lock fires.
//! The renderer pulls from that cache so a missing slot falls back to
//! a defensive "no body" line rather than calling
//! [`paladin_auth_core::Vault::export_qr_ansi`] from the view layer (the
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

use paladin_auth_core::{format_plaintext_qr_export_warning, summary_display_label, Vault};

use super::centered_rect;
use crate::app::state::{QrExportFocus, QrExportModal, QrSaveFocus, QrSaveStep, QrSaveSubFlow};
use crate::view::theme;

/// Height (in rows) reserved for the informational warning footer.
/// The verbatim [`paladin_auth_core::format_plaintext_qr_export_warning`]
/// text wraps to roughly five lines at the modal's inner width; six
/// rows leaves a margin so the wording cannot clip.
const WARNING_FOOTER_HEIGHT: u16 = 6;

/// Render the QR Export modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 72×30 bordered block centered inside the frame's
/// rect — wider than the other modals because it must fit the
/// half-block QR grid (a v10 QR with quiet zone is about 53 modules
/// wide; at half-block density that is 27 columns) and taller so the
/// QR stays fully scannable above the informational warning footer.
/// [`centered_rect`] clamps to the frame, so short terminals degrade
/// gracefully. The 72-cell width matches the Export modal so the two
/// surfaces line up visually when the user moves between them.
pub fn render(frame: &mut Frame<'_>, modal: &QrExportModal, vault: &Vault, no_color: bool) {
    let modal_area = centered_rect(frame.area(), 72, 30);
    frame.render_widget(Clear, modal_area);

    let block = theme::titled_block(" QR Export ", no_color, Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    render_qr_and_actions(frame, inner, modal, vault, no_color);
}

/// Render the single-page QR Export body: the account caption above
/// the cached ANSI QR body, followed by either the Save PNG / Save
/// SVG / Done button row (when no save sub-flow is active) or the
/// destination-prompt sub-flow body (when
/// [`QrExportModal::save_sub_flow`] is `Some`), and the verbatim
/// [`paladin_auth_core::format_plaintext_qr_export_warning`] text as an
/// informational footer beneath the actions.
///
/// The caption uses [`paladin_auth_core::summary_display_label`] for
/// CLI / GUI parity. The ANSI body is pulled from
/// [`QrExportModal::staged_ansi`] (populated by the reducer when the
/// modal opens); a missing slot renders a defensive placeholder so an
/// encoder error still leaves the warning footer and inline error
/// visible. The QR body stays painted while the save sub-flow is
/// active so the user can still see the QR while picking a
/// destination.
fn render_qr_and_actions(
    frame: &mut Frame<'_>,
    inner: Rect,
    modal: &QrExportModal,
    vault: &Vault,
    no_color: bool,
) {
    let chunks = Layout::vertical([
        Constraint::Length(1),                     // caption
        Constraint::Min(0),                        // ANSI QR body
        Constraint::Length(1),                     // blank
        Constraint::Length(1),                     // button row / sub-flow destination row
        Constraint::Length(1),                     // sub-flow overwrite-ack row (blank otherwise)
        Constraint::Length(1),                     // sub-flow confirm/cancel row (blank otherwise)
        Constraint::Length(1),                     // last-save / error / sub-flow error
        Constraint::Length(WARNING_FOOTER_HEIGHT), // informational warning footer
        Constraint::Length(1),                     // hint
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

    if let Some(sub) = &modal.save_sub_flow {
        render_save_sub_flow(frame, &chunks, sub, no_color);
    } else {
        render_idle_button_row(frame, &chunks, modal, no_color);
    }

    // Informational warning footer (DESIGN §4.6 / §6): the verbatim
    // core warning rendered beneath the actions so the user is
    // reminded the QR encodes the account secret. It never gates the
    // QR behind a click.
    let warning = format_plaintext_qr_export_warning();
    frame.render_widget(
        Paragraph::new(Span::styled(warning, theme::fg(theme::WARN, no_color)))
            .wrap(Wrap { trim: false }),
        chunks[7],
    );

    let hint = match modal.save_sub_flow.as_ref().map(|s| s.step) {
        Some(QrSaveStep::EnterPath) => "Tab cycles fields  ·  Enter confirm  ·  Esc cancel save",
        Some(QrSaveStep::OverwriteGate) => {
            "Tab cycles fields  ·  Space toggles ack  ·  Esc cancel save"
        }
        None => "Tab cycles buttons  ·  Enter activates  ·  Esc close",
    };
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[8]);
}

/// Paint the idle layout's Save as PNG / Save as SVG / Done button
/// row plus the inline error or `Saved to …` success path slot.
///
/// The success path renders only when [`QrExportModal::error`] is
/// empty and [`QrExportModal::last_save_path`] is populated —
/// mirrors the Export modal's inline success styling so a green
/// `Saved to /path/file.png` line confirms the latest save.
fn render_idle_button_row(
    frame: &mut Frame<'_>,
    chunks: &[Rect],
    modal: &QrExportModal,
    no_color: bool,
) {
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
            chunks[6],
        );
    } else if let Some(path) = &modal.last_save_path {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("Saved to {}", path.display()),
                theme::fg(theme::SUCCESS, no_color),
            )))
            .alignment(Alignment::Center),
            chunks[6],
        );
    }
}

/// Paint the Save sub-flow body: destination text input, optional
/// overwrite-ack row on [`QrSaveStep::OverwriteGate`], Confirm /
/// Cancel button row, and any inline error from the most recent
/// Confirm attempt.
///
/// The path input mirrors the Export / Import modals' bracketed
/// `[ value ]` slot but appends a trailing `_` cursor indicator
/// when [`QrSaveSubFlow::focus`] is [`QrSaveFocus::PathField`] so
/// the snapshot makes the active text-entry slot visible.
fn render_save_sub_flow(
    frame: &mut Frame<'_>,
    chunks: &[Rect],
    sub: &QrSaveSubFlow,
    no_color: bool,
) {
    let path_focused = sub.focus == QrSaveFocus::PathField;
    let path_label = if path_focused { "▶ " } else { "  " };
    let cursor = if path_focused { "_" } else { "" };
    let path_line = Line::from(format!(
        "{path_label}Destination: [ {path}{cursor} ]",
        path = sub.path_text,
    ));
    frame.render_widget(Paragraph::new(path_line), chunks[3]);

    if sub.step == QrSaveStep::OverwriteGate {
        let ack_focused = sub.focus == QrSaveFocus::OverwriteAck;
        let mark = if sub.overwrite_ack { "[x]" } else { "[ ]" };
        let mark_span = if ack_focused {
            Span::styled(
                format!("▶ {mark} "),
                theme::fg_bold(theme::ACCENT, no_color),
            )
        } else {
            Span::raw(format!("  {mark} "))
        };
        let ack_line = Line::from(vec![mark_span, Span::raw("Overwrite existing file")]);
        frame.render_widget(Paragraph::new(ack_line), chunks[4]);
    }

    let confirm_cancel = Line::from(format!(
        "{}   {}",
        button_label("Confirm", sub.focus == QrSaveFocus::Confirm),
        button_label("Cancel", sub.focus == QrSaveFocus::Cancel),
    ));
    frame.render_widget(
        Paragraph::new(confirm_cancel).alignment(Alignment::Center),
        chunks[5],
    );

    if let Some(error) = &sub.error {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                error.clone(),
                theme::fg(theme::ERROR, no_color),
            )))
            .alignment(Alignment::Center),
            chunks[6],
        );
    } else if sub.step == QrSaveStep::OverwriteGate {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "File exists — toggle the overwrite ack to confirm.".to_string(),
                theme::fg(theme::WARN, no_color),
            )))
            .alignment(Alignment::Center),
            chunks[6],
        );
    }
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
