// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only Help-overlay renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Help overlay": *"`?` from list focus opens a read-only Help
//! overlay listing every keybinding from the table below; `Esc`
//! closes the overlay and restores list focus. The overlay has no
//! inputs and never mutates vault state. … The overlay's content is
//! generated from the same keybindings table that the workspace
//! `cargo xtask man` target appends into the man page (after the
//! clap-derived synopsis) so the two cannot drift."*
//!
//! The renderer paints the overlay as a bordered block titled
//! `Help — keybindings` over a centered rect inside the frame. Each
//! row from [`crate::keybindings::KEYBINDINGS`] becomes one or more
//! body lines — the key column on the left padded to a fixed width,
//! then a two-space gutter, then the action text. Actions longer
//! than the action column wrap to continuation lines indented under
//! the action column so the key column stays a clean strip on the
//! left. A single intro line sits above the table and a centered
//! hint (`Esc closes`) sits flush near the bottom of the overlay so
//! the user always sees how to dismiss it.
//!
//! Like every other modal overlay in `paladin-tui`, the rendered
//! rect is [`Clear`]-ed before the bordered block is drawn so list
//! cells under the overlay don't bleed through transparent cells.

use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::keybindings::{Keybinding, KEYBINDINGS};

/// Overlay width in terminal cells. Wide enough that the longest
/// documented `keys` string (`PgUp PgDn / Ctrl-B Ctrl-F`, 25 cells)
/// plus the two-space gutter plus the action column fits inside the
/// bordered block at the standard 80-column terminal width while
/// leaving room for word-wrapping long actions onto continuation
/// rows.
const OVERLAY_WIDTH: u16 = 78;

/// Width of the left-hand `keys` column inside the body, padded to
/// fit the longest `keys` string in [`KEYBINDINGS`] plus a small
/// breathing-room margin.
const KEY_COL_WIDTH: usize = 27;

/// Width of the gutter that separates the key column from the
/// action column. Two cells matches the spacing the modal renderers
/// use between labels and values.
const GUTTER_WIDTH: usize = 2;

/// Render the Help overlay onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The overlay is a bordered block whose width is fixed at
/// [`OVERLAY_WIDTH`] and whose height grows with the number of
/// rendered body lines — single-line rows render in one row,
/// long-action rows wrap onto continuation rows indented under the
/// action column. The rect is [`Clear`]-ed before the block is
/// drawn so underlying list-view cells don't show through. Mirrors
/// the overlay pattern used by the Add / Remove / Rename / Import /
/// Export / Passphrase / Settings modal renderers, with the
/// difference that the Help overlay has no per-state shape — its
/// content is fully determined by the `KEYBINDINGS` constant.
pub fn render(frame: &mut Frame<'_>) {
    let action_col_width = action_col_width(OVERLAY_WIDTH);
    let body_lines: Vec<Line<'_>> = KEYBINDINGS
        .iter()
        .flat_map(|kb| keybinding_lines(kb, action_col_width))
        .collect();
    let body_rows = u16::try_from(body_lines.len()).unwrap_or(u16::MAX);

    // intro + blank + body + spacer + hint + two borders
    let height = body_rows.saturating_add(5);

    let area = centered_rect(frame.area(), OVERLAY_WIDTH, height);
    frame.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help — keybindings ")
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::vertical([
        Constraint::Length(1),         // intro
        Constraint::Length(1),         // blank
        Constraint::Length(body_rows), // keybinding rows
        Constraint::Min(0),            // flexible spacer
        Constraint::Length(1),         // hint
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new("Read-only — keys are listed for reference."),
        chunks[0],
    );

    frame.render_widget(Paragraph::new(body_lines), chunks[2]);

    frame.render_widget(
        Paragraph::new("Esc closes").alignment(Alignment::Center),
        chunks[4],
    );
}

/// Compute the action-column width given the overlay's outer width.
/// Subtracts the bordered block's left/right borders, the
/// [`Padding::symmetric`] horizontal padding (one cell per side),
/// the key column, and the gutter. Saturates at zero if the overlay
/// is too narrow to fit any action text — the wrap helper degrades
/// gracefully (one word per line) so the overlay still renders
/// rather than panicking.
fn action_col_width(overlay_width: u16) -> usize {
    let inner = (overlay_width as usize).saturating_sub(2 /* borders */ + 2 /* padding */);
    inner.saturating_sub(KEY_COL_WIDTH + GUTTER_WIDTH).max(1)
}

/// Render one [`Keybinding`] as one or more text lines: the first
/// line carries the keys (padded to [`KEY_COL_WIDTH`]) and the
/// first chunk of wrapped action text; subsequent lines indent
/// under the action column so the key column stays a clean strip
/// on the left edge of the body.
fn keybinding_lines(kb: &Keybinding, action_col_width: usize) -> Vec<Line<'static>> {
    let chunks = wrap_action(kb.action, action_col_width);
    let key_pad = " ".repeat(KEY_COL_WIDTH.saturating_sub(display_width(kb.keys)));
    let blank_keys = " ".repeat(KEY_COL_WIDTH);
    let gutter = " ".repeat(GUTTER_WIDTH);

    chunks
        .into_iter()
        .enumerate()
        .map(|(idx, chunk)| {
            let prefix = if idx == 0 {
                format!("{keys}{key_pad}", keys = kb.keys)
            } else {
                blank_keys.clone()
            };
            Line::from(format!("{prefix}{gutter}{chunk}"))
        })
        .collect()
}

/// Word-wrap `action` to a list of strings, each no wider than
/// `width` display cells, splitting on ASCII whitespace. Falls back
/// to a single chunk when `width` is too small to fit any word
/// (e.g. an extremely narrow terminal); the chunk is intentionally
/// not byte-truncated so the action stays readable even when it
/// exceeds the visible column — the overlay would already have
/// other rendering problems at that width.
fn wrap_action(action: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in action.split_whitespace() {
        let word_width = display_width(word);
        if current.is_empty() {
            current.push_str(word);
        } else if display_width(&current) + 1 + word_width <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        // `action` was empty — render a single empty line so the
        // row layout stays self-consistent. The table-validation
        // tests in `keybindings.rs` reject empty actions, so in
        // practice this branch only fires if the data invariant is
        // ever violated by a future patch.
        lines.push(String::new());
    }
    lines
}

/// Compute the display width of `s` in terminal cells. The
/// documented keybindings table uses arrow glyphs (`↑`, `↓`) and
/// ASCII; both occupy one cell each in a monospace terminal, so a
/// straight character count suffices and avoids pulling in a
/// `unicode-width` dependency for one call site.
fn display_width(s: &str) -> usize {
    s.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_action_returns_one_chunk_when_short() {
        let chunks = wrap_action("Open Add modal", 47);
        assert_eq!(chunks, vec!["Open Add modal".to_string()]);
    }

    #[test]
    fn wrap_action_wraps_on_word_boundaries() {
        let chunks = wrap_action("Close modal / overlay / search; quit dead-end screens", 20);
        assert!(chunks.len() >= 2, "expected wrapping, got {chunks:?}");
        for chunk in &chunks {
            assert!(
                chunk.chars().count() <= 20,
                "chunk {chunk:?} exceeded width 20"
            );
        }
        let rejoined = chunks.join(" ");
        assert_eq!(
            rejoined,
            "Close modal / overlay / search; quit dead-end screens"
        );
    }

    #[test]
    fn action_col_width_matches_overlay_geometry() {
        // 78 outer − 2 borders − 2 padding = 74 inner.
        // 74 − 27 keys − 2 gutter = 45 action.
        assert_eq!(action_col_width(78), 45);
    }
}
