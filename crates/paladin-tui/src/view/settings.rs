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
//! Per-field focus painting fans out in its own slice (matching the
//! Add modal's deferred focus-highlighting precedent), as do the
//! inline `save_not_committed` / `save_durability_unconfirmed`
//! variants of this modal's
//! [`SettingsModal::error`](crate::app::state::SettingsModal::error)
//! slot. This baseline keeps the body to the four labeled value
//! rows plus the hint so the snapshot pins only the layout contract.

use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::text::Line;
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

    let hint = "Tab cycles fields  ·  Enter submit  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[6]);
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
