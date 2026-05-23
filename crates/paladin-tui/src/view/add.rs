// SPDX-License-Identifier: AGPL-3.0-or-later

//! Add-modal renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6) > Add": the Add modal carries three input
//! modes (Manual / URI / QR) selected via a segmented header inside
//! the modal. This slice paints the freshly-opened (Manual-mode, no
//! error, no pending duplicate-add, no counts panel) baseline: the
//! mode selector, the Manual-mode field stack, and the footer
//! keybinding hint.
//!
//! The renderer is overlaid on top of the list view by
//! [`super::render`], so the Add modal call site is responsible for
//! [`Clear`]-ing the modal's rect before painting — otherwise list-
//! view content would bleed through transparent cells.
//!
//! The [`AddModal::error`] slot surfaces inline in the spacer above
//! the footer hint so `duplicate_account`, pre-commit
//! `save_not_committed`, and durability-unconfirmed save failures all
//! read at the same place. Pending-duplicate / URI / QR / per-field
//! focus highlighting all land alongside their own reducer or effect
//! slices; this slice keeps the field column plain text so the
//! snapshot pins only the layout contract.
//!
//! When [`AddModal::pending_duplicate_add`] is `Some` — the
//! follow-up "add anyway" confirmation form of the duplicate
//! rejection — the footer hint switches to
//! `Enter add anyway  ·  Esc cancel` so the user sees that the next
//! Enter commits the stashed pending account rather than re-running
//! the editable submit path. The inline rejection message stays
//! visible alongside it.
//!
//! When [`AddModal::counts_panel`] is `Some`, the modal switches to
//! the post-success summary view: the field stack is replaced with
//! the four `paladin_core::ImportReport` merge totals
//! (`imported`/`skipped`/`replaced`/`appended`) plus an `Enter or Esc
//! to close` hint per `DESIGN.md` §6's "The modal reports
//! imported/skipped/replaced/appended/warning counts plus
//! validation-warning messages rendered through
//! `paladin_core::format_validation_warning()` in a post-success
//! counts panel" contract. The clipboard-QR flow always uses
//! [`paladin_core::ImportConflict::Skip`] per the plan so
//! `replaced` and `appended` are always `0` on this path; the rows
//! still render so the surface reads identically to the Import
//! modal's counts panel.

use paladin_core::{AccountKindInput, Algorithm};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Padding, Paragraph, Wrap};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{AddModal, AddMode, CountsPanel};
use crate::view::theme;

/// Width of the left-hand label column inside the modal. Long
/// enough for the widest field name (`Period (s):`) so the value
/// column lines up across every row.
const LABEL_COL_WIDTH: usize = 12;

/// Width of the left-hand label column inside the counts panel.
/// Pinned to 13 to match `view::import`'s `LABEL_COL_WIDTH` so the
/// QR-add and file-import post-success surfaces line up at the
/// same column — a regression that ever drifts the two columns
/// surfaces as a diff across the matched snapshot pair.
const COUNTS_LABEL_COL_WIDTH: usize = 13;

/// Outer modal width in cells. The 64-cell width carries the
/// Manual-mode field stack and the segmented mode selector; the
/// counts panel reuses it (no `Format:` / `On conflict:` row
/// forces the import modal's 72-cell width).
const MODAL_WIDTH: u16 = 64;

/// Base modal height when no counts panel is open and when the
/// counts panel carries no validation warnings.
const MODAL_BASE_HEIGHT: u16 = 16;

/// Inner content width inside the modal block.
/// `MODAL_WIDTH - 2 borders - 2 horizontal padding (Padding::symmetric(1, 0))`.
/// Used to predict the wrapped row count of the counts panel's
/// warnings paragraph before allocating the modal rect.
const MODAL_INNER_WIDTH: u16 = MODAL_WIDTH - 4;

/// Inner rows used by the counts panel's fixed regions
/// (`header(1) + blank(1) + 4 count rows + hint(1)`). Anything
/// beyond this — the blank separator and the wrapped warnings
/// band — is what grows the modal vertically.
const COUNTS_FIXED_ROWS: u16 = 7;

/// Render the Add modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 64×16 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells don't show through. Renderers for the
/// other modal variants will follow the same overlay pattern.
///
/// When [`AddModal::counts_panel`] is `Some` the modal switches to
/// the post-success summary layout, growing vertically if warnings
/// would otherwise be truncated.
pub fn render(frame: &mut Frame<'_>, modal: &AddModal, no_color: bool) {
    let modal_height = modal_height_for(modal);
    let modal_area = centered_rect(frame.area(), MODAL_WIDTH, modal_height);
    frame.render_widget(Clear, modal_area);

    let block = theme::titled_block(" Add account ", no_color, Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    if let Some(panel) = &modal.counts_panel {
        render_counts_panel(frame, inner, panel);
        return;
    }

    // Top-to-bottom: mode selector, blank, eight Manual-mode
    // fields, blank, keybinding hint.
    let chunks = Layout::vertical([
        Constraint::Length(1), // mode selector
        Constraint::Length(1), // blank
        Constraint::Length(1), // label
        Constraint::Length(1), // issuer
        Constraint::Length(1), // secret
        Constraint::Length(1), // algorithm
        Constraint::Length(1), // digits
        Constraint::Length(1), // kind
        Constraint::Length(1), // period / counter
        Constraint::Length(1), // icon hint
        Constraint::Min(0),    // spacer
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(Paragraph::new(mode_selector_line(modal.mode)), chunks[0]);
    frame.render_widget(
        Paragraph::new(text_field_line("Label:", &modal.label)),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(text_field_line("Issuer:", &modal.issuer)),
        chunks[3],
    );
    frame.render_widget(
        Paragraph::new(masked_field_line(
            "Secret:",
            modal.manual_secret.as_str().chars().count(),
        )),
        chunks[4],
    );
    frame.render_widget(
        Paragraph::new(value_field_line(
            "Algorithm:",
            algorithm_label(modal.algorithm),
        )),
        chunks[5],
    );
    frame.render_widget(
        Paragraph::new(value_field_line("Digits:", &modal.digits.to_string())),
        chunks[6],
    );
    frame.render_widget(
        Paragraph::new(value_field_line("Kind:", kind_label(modal.kind))),
        chunks[7],
    );
    frame.render_widget(Paragraph::new(period_or_counter_line(modal)), chunks[8]);
    frame.render_widget(
        Paragraph::new(text_field_line("Icon hint:", &modal.icon_hint_text)),
        chunks[9],
    );

    if let Some(error) = &modal.error {
        render_inline_error(frame, chunks[10], error, no_color);
    }

    let hint = if modal.pending_duplicate_add.is_some() {
        "Enter add anyway  ·  Esc cancel"
    } else {
        "Tab cycles fields  ·  Enter submit  ·  Esc cancel"
    };
    frame.render_widget(
        Paragraph::new(hint).alignment(Alignment::Center),
        chunks[11],
    );
}

/// Paint the inline error message inside the spacer area between the
/// icon-hint row and the footer hint. The error sits one blank row
/// below the icon-hint row for breathing room, mirroring the unlock
/// screen's spacing convention; foreground red matches the unlock
/// screen's inline `decrypt_failed` styling so all inline error
/// surfaces in the TUI read the same way.
fn render_inline_error(
    frame: &mut Frame<'_>,
    spacer: ratatui::layout::Rect,
    message: &str,
    no_color: bool,
) {
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

/// Build the segmented mode-selector line. The active mode is wrapped
/// in `▶ ◀` braces so a regression that ever stops painting the
/// segmented selector or wires the wrong mode surfaces as a diff.
fn mode_selector_line(mode: AddMode) -> Line<'static> {
    let manual = mode_label("Manual", mode == AddMode::Manual);
    let uri = mode_label("URI", mode == AddMode::Uri);
    let qr = mode_label("QR", mode == AddMode::Qr);
    Line::from(format!("Mode: {manual}   {uri}   {qr}"))
}

fn mode_label(label: &str, active: bool) -> String {
    if active {
        format!("▶ {label} ◀")
    } else {
        format!("  {label}  ")
    }
}

/// Render a labeled text-input row. Editable fields show their
/// current contents inside `[ ... ]` brackets so an empty value
/// renders as `[ ]` rather than blank and the field is visibly
/// "an input slot" in the snapshot.
fn text_field_line(label: &str, value: &str) -> Line<'static> {
    Line::from(format!("{label:<LABEL_COL_WIDTH$}[ {value} ]"))
}

/// Render the masked secret-entry row. The typed character count is
/// rendered as bullets so the snapshot pins that the renderer never
/// paints the secret bytes; an empty buffer renders as `[ ]`.
fn masked_field_line(label: &str, char_count: usize) -> Line<'static> {
    let masked: String = "•".repeat(char_count);
    Line::from(format!("{label:<LABEL_COL_WIDTH$}[ {masked} ]"))
}

/// Render a labeled read-only value row (selectors / spinners). The
/// value is painted bare without brackets so it visually separates
/// from the editable text fields above.
fn value_field_line(label: &str, value: &str) -> Line<'static> {
    Line::from(format!("{label:<LABEL_COL_WIDTH$}{value}"))
}

/// Build the "Period (s)" (TOTP) or "Counter" (HOTP) row depending
/// on the modal's `kind`. Mirrors the
/// [`crate::app::state::AddManualFocus::PeriodOrCounter`] shared
/// focus slot so only one of the two fields ever appears at a time.
fn period_or_counter_line(modal: &AddModal) -> Line<'static> {
    match modal.kind {
        AccountKindInput::Totp => value_field_line("Period (s):", &modal.period_secs.to_string()),
        AccountKindInput::Hotp => value_field_line("Counter:", &modal.counter.to_string()),
    }
}

fn algorithm_label(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
    }
}

fn kind_label(kind: AccountKindInput) -> &'static str {
    match kind {
        AccountKindInput::Totp => "TOTP",
        AccountKindInput::Hotp => "HOTP",
    }
}

/// Paint the post-success summary view inside the modal's inner area.
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Add":
/// *"Clipboard QR import uses `ImportConflict::Skip` and reports
/// imported / skipped counts."* and *"QR-add validation warnings are
/// rendered through `paladin_core::format_validation_warning()` in the
/// post-success counts panel."* The reducer seeds [`CountsPanel`] from
/// the carried [`paladin_core::ImportReport`], so each of the four
/// totals (`imported` / `skipped` / `replaced` / `appended`) flows
/// through verbatim. The footer hint switches to
/// `Enter or Esc to close` so the user sees that the modal is now in
/// summary mode rather than the editable field-entry phase.
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
/// read as two distinct sections of the same panel.
///
/// The layout mirrors [`super::import`]'s `render_counts_panel` so the
/// QR-add and file-import surfaces line up at the same column — only
/// the modal width (64 vs 72) differs, since the Add modal does not
/// carry a `Format:` / `On conflict:` row.
fn render_counts_panel(frame: &mut Frame<'_>, inner: Rect, panel: &CountsPanel) {
    let warnings_rows = u16::try_from(total_wrapped_rows(
        &panel.warnings,
        usize::from(inner.width),
    ))
    .unwrap_or(u16::MAX);

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

/// Compute the rendered modal height so the warnings band fits fully
/// on screen when the counts panel is open. Returns
/// [`MODAL_BASE_HEIGHT`] for the no-counts-panel and the
/// counts-panel-with-no-warnings cases — both of which already fit
/// inside the base 16-row layout — so existing snapshots stay locked
/// at 16 cells tall.
fn modal_height_for(modal: &AddModal) -> u16 {
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
/// row count. Mirrors `view::import`'s wrapper for the ASCII output
/// of [`paladin_core::format_validation_warning`].
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

/// Build a single labeled count row (`"Imported:    3"`). Mirrors
/// `view::import`'s `count_row_line` so the QR-add and file-import
/// counts panels paint identical text at the same column.
fn count_row_line(label: &str, count: usize) -> Line<'static> {
    Line::from(format!("{label:<COUNTS_LABEL_COL_WIDTH$}{count}"))
}
