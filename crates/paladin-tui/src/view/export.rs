// SPDX-License-Identifier: AGPL-3.0-or-later

//! Export-modal renderer.
//!
//! Per `docs/DESIGN.md` §6 and `docs/IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6) > Export": *"Export writes either the plaintext
//! `otpauth://` JSON list (with an explicit unencrypted-secrets
//! warning before the write) or an encrypted Paladin bundle
//! (passphrase prompted twice and matched), refuses overwrite
//! without explicit confirmation, and surfaces the resulting `0600`
//! output path inline."* This slice paints the freshly-opened
//! baseline — the destination-path text-input row and the segmented
//! [`ExportFormat`] selector — with the footer keybinding hint flush
//! near the bottom of the modal.
//!
//! The renderer is overlaid on top of the list view by
//! [`super::render`], so the Export modal call site is responsible
//! for [`Clear`]-ing the modal's rect before painting — otherwise
//! list-view content would bleed through transparent cells.
//!
//! The plaintext-export warning rendering and the
//! `plaintext_confirmed` acknowledgement gate, the encrypted
//! twice-confirm passphrase prompts, and the
//! `confirmation_mismatch` / `zero_length` validation gates,
//! writer-failure / `save_not_committed` / `save_durability_unconfirmed`
//! inline errors land alongside their own reducer or effect slices.
//!
//! The [`ExportModal::error`] slot surfaces inline in the spacer
//! between the segmented `Format:` selector row and the footer hint,
//! painted in red and routed through
//! [`render_error_message`](crate::app::state::render_error_message)
//! so the refused-overwrite gate / `confirmation_mismatch` /
//! `zero_length` / writer-failure / `save_not_committed` /
//! `save_durability_unconfirmed` reads identically to the unlock
//! screen's `decrypt_failed` line and the Add / Remove / Rename
//! modals' inline-error slots.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{ExportFormat, ExportModal};
use crate::view::theme;

/// Width of the left-hand label column inside the modal. Long
/// enough for the widest field name (`Destination:`) so the value
/// column lines up across every row.
const LABEL_COL_WIDTH: usize = 13;

/// Render the Export modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 72×10 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells don't show through. Mirrors the
/// overlay pattern used by the Add / Remove / Rename / Import modal
/// renderers; the 72-cell width matches the Import modal so the
/// segmented selectors line up across the two import / export
/// flows.
pub fn render(frame: &mut Frame<'_>, modal: &ExportModal, no_color: bool) {
    let modal_area = centered_rect(frame.area(), 72, 10);
    frame.render_widget(Clear, modal_area);

    let block = theme::titled_block(" Export accounts ", no_color, Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    // Top-to-bottom: destination, blank, format selector, spacer,
    // hint.
    let chunks = Layout::vertical([
        Constraint::Length(1), // destination
        Constraint::Length(1), // blank
        Constraint::Length(1), // format selector
        Constraint::Min(0),    // spacer
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(text_field_line("Destination:", &modal.path_text)),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(format_selector_line(modal.format)),
        chunks[2],
    );

    if let Some(error) = &modal.error {
        render_inline_error(frame, chunks[3], error, no_color);
    }

    let hint = "Tab cycles fields  ·  Enter submit  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[4]);
}

/// Paint the inline error message inside the spacer area between the
/// segmented `Format:` selector row and the footer hint. The error
/// sits one blank row below the selector, foreground red, mirroring
/// the unlock screen's `decrypt_failed` styling and the Add / Remove
/// / Rename modals' inline errors so every inline-error surface in
/// the TUI reads the same way.
fn render_inline_error(frame: &mut Frame<'_>, spacer: Rect, message: &str, no_color: bool) {
    let spacer_chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(spacer);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            message.to_string(),
            theme::fg(theme::ERROR, no_color),
        ))),
        spacer_chunks[1],
    );
}

/// Render a labeled text-input row. Editable fields show their
/// current contents inside `[ ... ]` brackets so an empty value
/// renders as `[ ]` rather than blank and the field is visibly
/// "an input slot" in the snapshot — matches the Add / Rename /
/// Import modals' `text_field_line` so the TUI's editable rows
/// look the same across modals.
fn text_field_line(label: &str, value: &str) -> Line<'static> {
    Line::from(format!("{label:<LABEL_COL_WIDTH$}[ {value} ]"))
}

/// Build the segmented format-selector line. The active selector is
/// wrapped in `▶ ◀` braces so a regression that ever stops painting
/// the segmented selector or wires the wrong variant surfaces as a
/// diff — mirrors the Add / Import modals' segmented selectors.
fn format_selector_line(format: ExportFormat) -> Line<'static> {
    let plaintext = segment_label("Plaintext", format == ExportFormat::Plaintext);
    let encrypted = segment_label("Encrypted", format == ExportFormat::Encrypted);
    Line::from(format!(
        "{:<LABEL_COL_WIDTH$}{plaintext}  {encrypted}",
        "Format:"
    ))
}

fn segment_label(label: &str, active: bool) -> String {
    if active {
        format!("▶ {label} ◀")
    } else {
        format!("  {label}  ")
    }
}
