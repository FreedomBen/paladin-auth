// SPDX-License-Identifier: AGPL-3.0-or-later

//! Destroy-modal renderer (Milestone 10; DESIGN §4.3 / §6).
//!
//! The Destroy modal is the loudest action in the app: a path-targeted
//! vault wipe reachable from every screen via `Ctrl+Shift+D`. The body
//! renders the warning text from
//! [`paladin_auth_core::format_destroy_warning`] verbatim — the same helper
//! the CLI text mode prints and the GTK `DestroyDialog` shows — so the
//! wording cannot drift between front ends. A single confirmation
//! field gates the destructive *Delete vault* action behind the literal
//! `yes` (matching the CLI's destructive-confirmation grammar); *Cancel*
//! holds the default focus on open so the commit always takes a
//! deliberate focus move plus `Enter`.
//!
//! The renderer is overlaid on top of whatever the caller state painted
//! (the unlocked list, the unlock screen, the startup-error screen,
//! etc.), so it [`Clear`]s its rect before painting — otherwise the
//! underlying cells would bleed through.

use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Padding, Paragraph, Wrap};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{DestroyAction, DestroyModal};
use crate::view::theme;

/// Render the Destroy modal onto `frame`, on top of whatever the caller
/// already painted underneath.
///
/// The modal is a bordered, red-chromed block centered in the frame.
/// Top-to-bottom it stacks: the multi-line warning body (sourced once
/// at open time from [`paladin_auth_core::format_destroy_warning`]), the
/// confirmation field labelled with the `yes` gate, an optional inline
/// error (partial-failure / symlink rejection), the two action buttons
/// with the focused one highlighted, and a keybinding hint.
pub fn render(frame: &mut Frame<'_>, modal: &DestroyModal, no_color: bool) {
    // Fixed modal width; the inner text width is the modal width minus
    // the two border columns and the symmetric horizontal padding (1
    // each side).
    const MODAL_WIDTH: u16 = 72;
    let inner_width = MODAL_WIDTH.saturating_sub(4).max(1);

    // The §4.3 warning is a single long sentence; size the body to its
    // word-wrapped height so the whole text is visible without
    // scrolling. `wrapped_line_count` mirrors ratatui's word wrap
    // closely enough for layout sizing.
    let body_height = wrapped_line_count(&modal.warning, inner_width).max(1);
    // Fixed rows: confirm field (1) + error (1) + blank spacer (1) +
    // actions (1) + hint (1) = 5, plus 2 border rows.
    let height = body_height.saturating_add(5).saturating_add(2);
    let modal_area = centered_rect(frame.area(), MODAL_WIDTH, height);
    frame.render_widget(Clear, modal_area);

    let block =
        theme::destructive_titled_block(" Destroy vault ", no_color, Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let chunks = Layout::vertical([
        Constraint::Length(body_height), // warning body (wrapped)
        Constraint::Length(1),           // confirmation field
        Constraint::Length(1),           // inline error (or blank)
        Constraint::Min(0),              // spacer
        Constraint::Length(1),           // actions
        Constraint::Length(1),           // hint
    ])
    .split(inner);

    // Warning body — rendered verbatim (word-wrapped) in the warning
    // palette so the severity reads without re-wording.
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            modal.warning.clone(),
            theme::fg(theme::WARN, no_color),
        )))
        .wrap(Wrap { trim: false }),
        chunks[0],
    );

    // Confirmation field: prompt + the typed buffer.
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("Type "),
            Span::styled("yes", theme::fg_bold(theme::WARN, no_color)),
            Span::raw(" to confirm: "),
            Span::raw(modal.confirmation.clone()),
        ])),
        chunks[1],
    );

    // Inline error (partial failure / symlink rejection), if any.
    if let Some(error) = &modal.error {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                error.clone(),
                theme::fg(theme::ERROR, no_color),
            ))),
            chunks[2],
        );
    }

    // Action row: Cancel + Delete vault. The focused action is
    // reverse-video; the Delete action is dimmed until the confirmation
    // reads `yes` so the gate is visible.
    let confirmed = modal.confirmed();
    let cancel = action_span(
        "[ Cancel ]",
        modal.focus == DestroyAction::Cancel,
        true,
        no_color,
    );
    let delete = action_span(
        "[ Delete vault ]",
        modal.focus == DestroyAction::Delete,
        confirmed,
        no_color,
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![cancel, Span::raw("    "), delete]))
            .alignment(Alignment::Center),
        chunks[4],
    );

    let hint = "Tab switches  ·  Enter confirms  ·  Esc cancels";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[5]);
}

/// Estimate the number of rows `text` occupies when word-wrapped to
/// `width` columns, mirroring ratatui's greedy word wrap closely enough
/// to size the modal body. Words longer than `width` still consume one
/// row (ratatui hard-breaks them, but the §4.3 warning has no such
/// word). Empty input is one row.
fn wrapped_line_count(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let mut rows: u16 = 0;
    for paragraph in text.split('\n') {
        let mut col = 0usize;
        let mut row_started = false;
        for word in paragraph.split_whitespace() {
            let w = word.chars().count();
            if !row_started {
                col = w;
                row_started = true;
                rows = rows.saturating_add(1);
            } else if col + 1 + w <= width {
                col += 1 + w;
            } else {
                rows = rows.saturating_add(1);
                col = w;
            }
        }
        if !row_started {
            // Blank line still occupies a row.
            rows = rows.saturating_add(1);
        }
    }
    rows.max(1)
}

/// Build a styled action-button span. `focused` reverse-videos the
/// label; `enabled` controls whether the *Delete vault* action reads as
/// active (it stays dimmed until the confirmation field reads `yes`).
fn action_span(label: &str, focused: bool, enabled: bool, no_color: bool) -> Span<'static> {
    use ratatui::style::{Modifier, Style};

    let mut style = Style::default();
    if !no_color {
        if !enabled {
            style = style.add_modifier(Modifier::DIM);
        } else if focused {
            style = style.add_modifier(Modifier::REVERSED);
        }
    }
    // In no-color mode the focus cue still needs to survive, so use a
    // bracketed reverse-video that does not depend on color.
    if no_color && focused {
        style = style.add_modifier(Modifier::REVERSED);
    }
    Span::styled(label.to_string(), style)
}
