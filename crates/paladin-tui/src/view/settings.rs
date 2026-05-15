// SPDX-License-Identifier: AGPL-3.0-or-later

//! Settings-modal renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6) > Settings": *"toggles for `auto_lock.enabled`
//! and `clipboard.clear_enabled`, spinners for
//! `auto_lock.timeout_secs` and `clipboard.clear_secs`. The spinners
//! clamp to the shared core bounds … The modal accumulates pending
//! edits in modal-local state and only commits on Confirm: pending
//! values are applied through the same setters
//! (`set_auto_lock_*`, `set_clipboard_clear_*`) inside a single
//! `Vault::mutate_and_save` transaction."*
//!
//! The renderer paints the modal as a bordered block titled
//! `Settings`, with four labeled value rows in reading order — the
//! `auto_lock.enabled` toggle, the `auto_lock.timeout_secs` spinner
//! (indented under its parent toggle), a blank spacer, the
//! `clipboard.clear_enabled` toggle, and the `clipboard.clear_secs`
//! spinner (indented). Toggles render as `[✓]` / `[ ]` so the
//! enabled state is legible in a no-color snapshot; spinners render
//! their pending integer value inside `[ ... ]` brackets so the
//! field stays visibly editable. The footer keybinding hint sits
//! flush near the bottom of the modal.
//!
//! The renderer is overlaid on top of the list view by
//! [`super::render`], so the Settings modal call site is
//! responsible for [`Clear`]-ing the modal's rect before painting —
//! otherwise list-view content would bleed through transparent
//! cells.
//!
//! The [`SettingsModal::error`](crate::app::state::SettingsModal::error)
//! slot surfaces inline in the spacer between the
//! clipboard-spinner row and the footer hint, painted in red and
//! routed through
//! [`render_error_message`](crate::app::state::render_error_message)
//! so `save_not_committed` / `save_durability_unconfirmed` reads
//! identically to the unlock screen's `decrypt_failed` line and the
//! Add / Remove / Rename / Import / Passphrase modals' inline-error
//! slots. Per-field focus painting fans out in its own slice
//! (matching the Add modal's deferred focus-highlighting precedent).

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::SettingsModal;

/// Width of the left-hand label column inside the modal. Long
/// enough for the widest field name (`Clipboard-clear:`) so the
/// value column lines up across every row.
const LABEL_COL_WIDTH: usize = 18;

/// Render the Settings modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 64×12 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells don't show through. Mirrors the
/// overlay pattern used by the Add / Remove / Rename / Import /
/// Export / Passphrase modal renderers.
pub fn render(frame: &mut Frame<'_>, modal: &SettingsModal) {
    let modal_area = centered_rect(frame.area(), 64, 12);
    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Settings ")
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let chunks = Layout::vertical([
        Constraint::Length(1), // auto-lock toggle
        Constraint::Length(1), // auto-lock timeout
        Constraint::Length(1), // blank
        Constraint::Length(1), // clipboard toggle
        Constraint::Length(1), // clipboard timeout
        Constraint::Min(0),    // spacer
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(toggle_field_line("Auto-lock:", modal.auto_lock_enabled)),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(spinner_field_line(
            "  Timeout (s):",
            modal.auto_lock_timeout_secs,
        )),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(toggle_field_line(
            "Clipboard-clear:",
            modal.clipboard_clear_enabled,
        )),
        chunks[3],
    );
    frame.render_widget(
        Paragraph::new(spinner_field_line(
            "  Timeout (s):",
            modal.clipboard_clear_secs,
        )),
        chunks[4],
    );

    if let Some(error) = &modal.error {
        render_inline_error(frame, chunks[5], error);
    }

    let hint = "Tab cycles fields  ·  Enter submit  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[6]);
}

/// Paint the inline error message inside the spacer area between the
/// clipboard-spinner row and the footer hint. The error sits one
/// blank row below the clipboard-spinner row, foreground red,
/// mirroring the unlock screen's `decrypt_failed` styling and the
/// Add / Remove / Rename / Import / Passphrase modals' inline errors
/// so every inline-error surface in the TUI reads the same way.
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

/// Render a labeled toggle row. `[✓]` for the enabled state, `[ ]`
/// for the disabled state — the bracketed mark mirrors the Add /
/// Rename / Export modals' `[ value ]` editable-field convention so
/// the toggle stays visibly "a control" in the snapshot.
fn toggle_field_line(label: &str, on: bool) -> Line<'static> {
    let mark = if on { "✓" } else { " " };
    Line::from(format!("{label:<LABEL_COL_WIDTH$}[ {mark} ]"))
}

/// Render a labeled spinner row. The pending integer value is
/// rendered inside `[ ... ]` brackets so the row stays visibly "a
/// control" in the snapshot.
fn spinner_field_line(label: &str, value: u32) -> Line<'static> {
    Line::from(format!("{label:<LABEL_COL_WIDTH$}[ {value} ]"))
}
