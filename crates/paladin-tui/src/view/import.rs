// SPDX-License-Identifier: AGPL-3.0-or-later

//! Import-modal renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6) > Import": *"Import takes a file path and
//! optional explicit format, calls `classify_paladin_import_precheck`
//! before any Paladin bundle passphrase prompt, prompts only for
//! encrypted-Paladin sources, applies a user-selected on-conflict
//! policy (`skip` / `replace` / `append`), and reports
//! imported/skipped/replaced/appended/warning counts."* This slice
//! paints the freshly-opened (path-entry phase, no inline error, no
//! counts panel) baseline: the source-path text-input row, the
//! segmented format selector, the segmented on-conflict selector,
//! and the footer keybinding hint.
//!
//! The renderer is overlaid on top of the list view by
//! [`super::render`], so the Import modal call site is responsible
//! for [`Clear`]-ing the modal's rect before painting — otherwise
//! list-view content would bleed through transparent cells.
//!
//! The [`ImportModal::error`] slot surfaces inline in the spacer
//! between the conflict-selector row and the footer hint, painted in
//! red and routed through
//! [`render_error_message`](crate::app::state::render_error_message)
//! so `save_not_committed` / `save_durability_unconfirmed` reads
//! identically to the unlock screen's `decrypt_failed` line and the
//! Add / Remove / Rename modals' inline-error slots.
//!
//! Encrypted-Paladin passphrase sub-phase / counts-panel rendering
//! land alongside their own reducer or effect slices.

use paladin_core::ImportConflict;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{ImportFormatSelector, ImportModal};

/// Width of the left-hand label column inside the modal. Long
/// enough for the widest field name (`On conflict:`) so the value
/// column lines up across every row.
const LABEL_COL_WIDTH: usize = 13;

/// Render the Import modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 72×12 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells don't show through. Mirrors the
/// overlay pattern used by the Add / Remove / Rename modal renderers.
/// The 8-cell width bump over the 64-wide Remove / Rename overlays
/// gives the segmented `Format:` selector enough room for all five
/// [`ImportFormatSelector`] variants (`Auto` / `Otpauth` / `Aegis` /
/// `Paladin` / `QR`) without truncating the last segment under the
/// `▶ … ◀` active-variant markers.
pub fn render(frame: &mut Frame<'_>, modal: &ImportModal) {
    let modal_area = centered_rect(frame.area(), 72, 12);
    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Import accounts ")
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    // Top-to-bottom: source path, blank, format selector, blank,
    // conflict selector, spacer, hint.
    let chunks = Layout::vertical([
        Constraint::Length(1), // source path
        Constraint::Length(1), // blank
        Constraint::Length(1), // format selector
        Constraint::Length(1), // blank
        Constraint::Length(1), // conflict selector
        Constraint::Min(0),    // spacer
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(text_field_line("Source:", &modal.path_text)),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(format_selector_line(modal.format)),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(conflict_selector_line(modal.conflict)),
        chunks[4],
    );

    if let Some(error) = &modal.error {
        render_inline_error(frame, chunks[5], error);
    }

    let hint = "Tab cycles fields  ·  Enter submit  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[6]);
}

/// Paint the inline error message inside the spacer area between the
/// conflict-selector row and the footer hint. The error sits one
/// blank row below the conflict selector, foreground red, mirroring
/// the unlock screen's `decrypt_failed` styling and the Add / Remove
/// / Rename modals' inline errors so every inline-error surface in
/// the TUI reads the same way.
fn render_inline_error(frame: &mut Frame<'_>, spacer: Rect, message: &str) {
    let spacer_chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
    ])
    .split(spacer);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            message.to_string(),
            Style::default().fg(Color::Red),
        ))),
        spacer_chunks[1],
    );
}

/// Render a labeled text-input row. Editable fields show their
/// current contents inside `[ ... ]` brackets so an empty value
/// renders as `[ ]` rather than blank and the field is visibly
/// "an input slot" in the snapshot — matches the Add / Rename
/// modals' `text_field_line` so the TUI's editable rows look the
/// same across modals.
fn text_field_line(label: &str, value: &str) -> Line<'static> {
    Line::from(format!("{label:<LABEL_COL_WIDTH$}[ {value} ]"))
}

/// Build the segmented format-selector line. The active selector is
/// wrapped in `▶ ◀` braces so a regression that ever stops painting
/// the segmented selector or wires the wrong variant surfaces as a
/// diff — mirrors the Add modal's `mode_selector_line`.
fn format_selector_line(selector: ImportFormatSelector) -> Line<'static> {
    let auto = segment_label("Auto", selector == ImportFormatSelector::Auto);
    let otpauth = segment_label("Otpauth", selector == ImportFormatSelector::Otpauth);
    let aegis = segment_label("Aegis", selector == ImportFormatSelector::Aegis);
    let paladin = segment_label("Paladin", selector == ImportFormatSelector::Paladin);
    let qr = segment_label("QR", selector == ImportFormatSelector::Qr);
    Line::from(format!(
        "{:<LABEL_COL_WIDTH$}{auto}  {otpauth}  {aegis}  {paladin}  {qr}",
        "Format:"
    ))
}

/// Build the segmented on-conflict-policy selector line. Mirrors the
/// format selector so the snapshot pins the three `ImportConflict`
/// variants in the CLI's documented order (`skip` / `replace` /
/// `append`).
fn conflict_selector_line(conflict: ImportConflict) -> Line<'static> {
    let skip = segment_label("Skip", conflict == ImportConflict::Skip);
    let replace = segment_label("Replace", conflict == ImportConflict::Replace);
    let append = segment_label("Append", conflict == ImportConflict::Append);
    Line::from(format!(
        "{:<LABEL_COL_WIDTH$}{skip}  {replace}  {append}",
        "On conflict:"
    ))
}

fn segment_label(label: &str, active: bool) -> String {
    if active {
        format!("▶ {label} ◀")
    } else {
        format!("  {label}  ")
    }
}
