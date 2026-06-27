// SPDX-License-Identifier: AGPL-3.0-or-later

//! v0.2 Edit-modal renderer (Shift+E).
//!
//! Per `docs/DESIGN.md` §6 and `docs/IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6) > Edit": the modal exposes three controls —
//! label text input, issuer text input, and a four-option segmented
//! icon-hint selector (Leave unchanged / Default from issuer / No
//! icon / Slug:). The *Slug:* option exposes a sibling slug input
//! row as a fourth focus stop; the other three positions skip it.
//!
//! Rendered as a centered bordered block on top of the list view;
//! the call site is responsible for the [`Clear`] pass on the
//! modal's rect before painting so list-view cells do not bleed
//! through.
//!
//! The active `▶ ... ◀` markers on the icon-hint selector are
//! character-only (no color or style differentiation) so the modal
//! renders identically under `NO_COLOR`, monochrome terminals, and
//! high-contrast color schemes per §13.

use std::fmt::Write as _;

use paladin_auth_core::Vault;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{format_account_display_label, EditFocus, EditIconHintSelector, EditModal};
use crate::view::theme;

/// Width of the left-hand label column inside the modal. Matches the
/// Rename modal's column so the input rows align visually.
const LABEL_COL_WIDTH: usize = 12;

/// Render the Edit modal onto `frame`, on top of whatever the caller
/// already painted underneath.
///
/// The modal is a 64×14 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells do not show through. The targeted
/// account is resolved against `vault` via `modal.account_id`; if
/// the account has been removed out from under the modal (defensive
/// branch — production flow closes the modal on
/// `EffectResult::EditAccountMetadata`) the renderer falls back to a
/// generic prompt rather than panicking.
pub fn render(frame: &mut Frame<'_>, modal: &EditModal, vault: &Vault, no_color: bool) {
    let modal_area = centered_rect(frame.area(), 64, 14);
    frame.render_widget(Clear, modal_area);

    let block = theme::titled_block(" Edit account ", no_color, Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    // Top-to-bottom: prompt, account label, blank, label row, issuer
    // row, icon-hint selector, slug row (always reserved so the
    // modal does not jump when toggling *Slug:*), spacer, hint.
    let chunks = Layout::vertical([
        Constraint::Length(1), // prompt
        Constraint::Length(1), // account label
        Constraint::Length(1), // blank
        Constraint::Length(1), // label row
        Constraint::Length(1), // issuer row
        Constraint::Length(1), // icon-hint selector
        Constraint::Length(1), // slug row
        Constraint::Min(0),    // spacer (and error if any)
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from("Editing the following account:")),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(account_label_line(modal, vault)), chunks[1]);

    frame.render_widget(
        Paragraph::new(text_field_line(
            "Label:",
            &modal.label_buffer,
            modal.focus == EditFocus::Label,
        )),
        chunks[3],
    );
    frame.render_widget(
        Paragraph::new(text_field_line(
            "Issuer:",
            &modal.issuer_buffer,
            modal.focus == EditFocus::Issuer,
        )),
        chunks[4],
    );
    frame.render_widget(
        Paragraph::new(icon_hint_selector_line(
            modal.icon_hint_selector,
            modal.focus == EditFocus::IconHint,
        )),
        chunks[5],
    );
    frame.render_widget(
        Paragraph::new(slug_row_line(
            &modal.icon_hint_slug,
            modal.icon_hint_selector == EditIconHintSelector::Slug,
            modal.focus == EditFocus::Slug,
        )),
        chunks[6],
    );

    if let Some(error) = &modal.error {
        render_inline_error(frame, chunks[7], error, no_color);
    }

    let hint = "Tab/Shift-Tab cycle  ·  Enter submit  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[8]);
}

/// Paint the inline error message inside the spacer area between the
/// rows and the footer hint.
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

fn account_label_line(modal: &EditModal, vault: &Vault) -> Line<'static> {
    match vault.summaries().find(|s| s.id == modal.account_id) {
        Some(summary) => Line::from(format_account_display_label(&summary)),
        None => Line::from("(account no longer present)"),
    }
}

/// Render a labeled text-input row. The focused row gets a bolded
/// label so callers running under monochrome terminals can still
/// distinguish active focus.
fn text_field_line(label: &str, value: &str, focused: bool) -> Line<'static> {
    let label_span = if focused {
        Span::styled(
            format!("{label:<LABEL_COL_WIDTH$}"),
            ratatui::style::Style::default().add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw(format!("{label:<LABEL_COL_WIDTH$}"))
    };
    let body_span = Span::raw(format!("[ {value} ]"));
    Line::from(vec![label_span, body_span])
}

/// Render the segmented icon-hint selector line. The active option
/// is bracketed by `▶ ... ◀` glyphs (character-only so the row
/// renders identically under `NO_COLOR` per §13).
fn icon_hint_selector_line(selector: EditIconHintSelector, focused: bool) -> Line<'static> {
    let label_span = if focused {
        Span::styled(
            format!("{:<LABEL_COL_WIDTH$}", "Icon hint:"),
            ratatui::style::Style::default().add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw(format!("{:<LABEL_COL_WIDTH$}", "Icon hint:"))
    };
    let options = [
        (EditIconHintSelector::LeaveUnchanged, "Leave unchanged"),
        (EditIconHintSelector::Default, "Default from issuer"),
        (EditIconHintSelector::Clear, "No icon"),
        (EditIconHintSelector::Slug, "Slug:"),
    ];
    let mut body = String::new();
    for (i, (variant, label)) in options.iter().enumerate() {
        if i > 0 {
            body.push_str("  ");
        }
        if *variant == selector {
            let _ = write!(body, "\u{25B6} {label} \u{25C0}");
        } else {
            let _ = write!(body, "  {label}  ");
        }
    }
    Line::from(vec![label_span, Span::raw(body)])
}

/// Render the sibling slug input row. Always reserved so the modal
/// does not jump when the selector toggles between *Slug:* and the
/// other three options. Renders dimmed text when the row is disabled
/// (selector not on *Slug:*).
fn slug_row_line(value: &str, enabled: bool, focused: bool) -> Line<'static> {
    let style = if !enabled {
        ratatui::style::Style::default().add_modifier(Modifier::DIM)
    } else if focused {
        ratatui::style::Style::default().add_modifier(Modifier::BOLD)
    } else {
        ratatui::style::Style::default()
    };
    Line::from(Span::styled(
        format!("{:<LABEL_COL_WIDTH$}[ {value} ]", "Slug:"),
        style,
    ))
}
