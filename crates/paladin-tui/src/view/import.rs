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
//! When [`ImportModal::counts_panel`] is `Some`, the modal switches to
//! the post-success summary view: the input rows (Source / Format /
//! On conflict / footer hint) are replaced with the four
//! `paladin_core::ImportReport` merge totals
//! (`imported`/`skipped`/`replaced`/`appended`) plus an `Enter or Esc
//! to close` hint. Per `DESIGN.md` §6's "The modal reports
//! imported/skipped/replaced/appended/warning counts plus
//! validation-warning messages rendered through
//! `paladin_core::format_validation_warning()` in a post-success
//! counts panel" contract. The reducer pre-renders each
//! [`paladin_core::ImportWarning`] through
//! [`paladin_core::format_validation_warning`] so this renderer only
//! has to lay out the already-formatted strings: each warning becomes
//! one [`Line`] in a wrapped [`Paragraph`] painted into a dedicated
//! row band between the count rows and the footer hint. The modal
//! grows vertically to fit the wrapped warnings so long advisory
//! text stays fully visible at the standard 80-column terminal width
//! instead of being truncated at the right border.
//!
//! Encrypted-Paladin passphrase sub-phase rendering lands alongside
//! its own reducer or effect slice.

use paladin_core::ImportConflict;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{CountsPanel, ImportFormatSelector, ImportModal};

/// Width of the left-hand label column inside the modal. Long
/// enough for the widest field name (`On conflict:`) so the value
/// column lines up across every row.
const LABEL_COL_WIDTH: usize = 13;

/// Outer modal width in cells. Pinned so the segmented `Format:`
/// selector fits all five [`ImportFormatSelector`] variants without
/// truncating the last segment under the `▶ … ◀` active-variant
/// markers, and so the counts panel's `Enter or Esc to close` footer
/// hint sits inside a wide enough rect to render centered.
const MODAL_WIDTH: u16 = 72;

/// Inner content width inside the modal block.
/// `MODAL_WIDTH - 2 borders - 2 horizontal padding (Padding::symmetric(1, 0))`.
/// Used to predict the wrapped row count of the counts panel's
/// warnings paragraph before allocating the modal rect.
const MODAL_INNER_WIDTH: u16 = MODAL_WIDTH - 4;

/// Base modal height when no counts panel is open and when the
/// counts panel carries no validation warnings. Holds the
/// `header(1) + blank(1) + 4 count rows + Min(0) spacer + hint(1)`
/// inner layout plus the top/bottom border rows.
const MODAL_BASE_HEIGHT: u16 = 12;

/// Inner rows used by the counts panel's fixed regions
/// (`header(1) + blank(1) + 4 count rows + hint(1)`).
/// Anything beyond this — the blank separator and the wrapped
/// warnings band — is what grows the modal vertically.
const COUNTS_FIXED_ROWS: u16 = 7;

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
    let modal_height = modal_height_for(modal);
    let modal_area = centered_rect(frame.area(), MODAL_WIDTH, modal_height);
    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Import accounts ")
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    if let Some(panel) = &modal.counts_panel {
        render_counts_panel(frame, inner, panel);
        return;
    }

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

/// Paint the post-success summary view inside the modal's inner area.
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Import":
/// *"The modal reports imported/skipped/replaced/appended/warning
/// counts plus validation-warning messages rendered through
/// `paladin_core::format_validation_warning()` in a post-success
/// counts panel."* The reducer seeds [`CountsPanel`] from the
/// carried [`paladin_core::ImportReport`], so each of the four
/// totals (`imported` / `skipped` / `replaced` / `appended`) flows
/// through verbatim. The footer hint switches to
/// `Enter or Esc to close` so the user sees that the modal is now
/// in summary mode rather than the editable path-entry phase.
///
/// Each carried [`CountsPanel::warnings`] string was already rendered
/// through [`paladin_core::format_validation_warning`] by the reducer,
/// so the renderer only needs to lay the strings out. They are stacked
/// in a dedicated row band between the count rows and the footer hint:
/// one [`Line`] per warning, joined into a single wrapped
/// [`Paragraph`] (`Wrap { trim: false }`) so long advisory text stays
/// fully visible at the standard 80-column terminal width instead of
/// being truncated at the right border. A blank separator row sits
/// above the warnings band so the count rows and the warnings region
/// read as two distinct sections of the same panel. The Add modal's
/// QR-import counts panel reuses the same layout — sharing the
/// `Imported:` / `Skipped:` / `Replaced:` / `Appended:` label column
/// with the import counts panel so the two surfaces read identically.
fn render_counts_panel(frame: &mut Frame<'_>, inner: Rect, panel: &CountsPanel) {
    let warnings_rows = u16::try_from(total_wrapped_rows(
        &panel.warnings,
        usize::from(inner.width),
    ))
    .unwrap_or(u16::MAX);

    // Top-to-bottom: header, blank, imported, skipped, replaced,
    // appended; if warnings exist, blank separator + warnings band;
    // Min(0) absorbs any leftover; hint.
    let mut constraints: Vec<Constraint> = vec![
        Constraint::Length(1), // header
        Constraint::Length(1), // blank
        Constraint::Length(1), // imported
        Constraint::Length(1), // skipped
        Constraint::Length(1), // replaced
        Constraint::Length(1), // appended
    ];
    let warnings_slot = if warnings_rows > 0 {
        constraints.push(Constraint::Length(1)); // blank separator
        constraints.push(Constraint::Length(warnings_rows));
        Some(constraints.len() - 1)
    } else {
        None
    };
    constraints.push(Constraint::Min(0)); // leftover spacer
    constraints.push(Constraint::Length(1)); // hint
    let hint_idx = constraints.len() - 1;

    let chunks = Layout::vertical(constraints).split(inner);

    frame.render_widget(Paragraph::new("Import complete."), chunks[0]);
    frame.render_widget(
        Paragraph::new(count_row_line("Imported:", panel.imported)),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(count_row_line("Skipped:", panel.skipped)),
        chunks[3],
    );
    frame.render_widget(
        Paragraph::new(count_row_line("Replaced:", panel.replaced)),
        chunks[4],
    );
    frame.render_widget(
        Paragraph::new(count_row_line("Appended:", panel.appended)),
        chunks[5],
    );

    if let Some(idx) = warnings_slot {
        let lines: Vec<Line<'_>> = panel
            .warnings
            .iter()
            .map(|s| Line::from(s.clone()))
            .collect();
        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            chunks[idx],
        );
    }

    let hint = "Enter or Esc to close";
    frame.render_widget(
        Paragraph::new(hint).alignment(Alignment::Center),
        chunks[hint_idx],
    );
}

/// Compute the rendered modal height so the warnings band fits
/// fully on screen when the counts panel is open. Returns
/// [`MODAL_BASE_HEIGHT`] for the no-counts-panel and the
/// counts-panel-with-no-warnings cases — both of which already fit
/// inside the base layout's 3-row `Min(0)` spacer — so existing
/// snapshots stay locked at 12 cells tall.
fn modal_height_for(modal: &ImportModal) -> u16 {
    let Some(panel) = &modal.counts_panel else {
        return MODAL_BASE_HEIGHT;
    };
    let wrap_rows = u16::try_from(total_wrapped_rows(
        &panel.warnings,
        usize::from(MODAL_INNER_WIDTH),
    ))
    .unwrap_or(u16::MAX);
    if wrap_rows == 0 {
        return MODAL_BASE_HEIGHT;
    }
    // Inner rows needed = COUNTS_FIXED_ROWS + 1 blank separator + wrap_rows.
    // Modal height = inner rows + 2 borders.
    let inner = COUNTS_FIXED_ROWS
        .saturating_add(1)
        .saturating_add(wrap_rows);
    inner.saturating_add(2).max(MODAL_BASE_HEIGHT)
}

/// Total wrapped-row count across all warnings for a given inner
/// width. Each warning gets its own [`Line`] in the rendered
/// [`Paragraph`], so the per-warning row counts sum to the band's
/// row count. The algorithm mirrors ratatui's word wrapper for the
/// ASCII output of [`paladin_core::format_validation_warning`]: words
/// are separated by single spaces and broken at the last whitespace
/// boundary that still fits the line.
fn total_wrapped_rows(warnings: &[String], width: usize) -> usize {
    warnings.iter().map(|s| wrapped_row_count(s, width)).sum()
}

/// How many rendered rows a single warning takes at the given width.
/// Returns `1` for an empty string (an empty `Line` still occupies
/// one display row), `0` if `width == 0`. Greedy word wrap on ASCII
/// whitespace boundaries; matches ratatui's
/// [`Wrap { trim: false }`](Wrap) behavior for the ASCII strings
/// emitted by [`paladin_core::format_validation_warning`].
fn wrapped_row_count(text: &str, width: usize) -> usize {
    if width == 0 {
        return 0;
    }
    if text.is_empty() {
        return 1;
    }
    let mut rows = 1usize;
    let mut col = 0usize;
    let mut first_word = true;
    for word in text.split(' ') {
        let word_len = word.chars().count();
        let needed = if first_word { word_len } else { 1 + word_len };
        if col + needed <= width {
            col += needed;
        } else {
            rows += 1;
            col = word_len;
        }
        first_word = false;
    }
    rows
}

/// Build a single labeled count row (`"Imported:       3"`). The
/// label sits in the same `LABEL_COL_WIDTH` left-hand column as the
/// path-entry rows so the count row reads as a delta from the
/// pre-success layout rather than a separate visual region.
fn count_row_line(label: &str, count: usize) -> Line<'static> {
    Line::from(format!("{label:<LABEL_COL_WIDTH$}{count}"))
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
