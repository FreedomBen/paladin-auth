// SPDX-License-Identifier: AGPL-3.0-or-later

//! Remove-modal renderer.
//!
//! Per `docs/DESIGN.md` §6 and `docs/IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6) > Remove": *"confirmation modal. On confirm,
//! wraps `Vault::remove` in `Vault::mutate_and_save`."* This slice
//! paints the freshly-opened baseline — the centered confirmation
//! prompt naming the targeted account, framed by the standard
//! ratatui block borders, with the Enter / Esc keybinding hint flush
//! near the bottom of the modal.
//!
//! The renderer is overlaid on top of the list view by
//! [`super::render`], so the Remove modal call site is responsible
//! for [`Clear`]-ing the modal's rect before painting — otherwise
//! list-view content would bleed through transparent cells.
//!
//! The [`RemoveModal::error`] slot surfaces inline in the spacer
//! between the account-label row and the footer hint, painted in
//! red and routed through
//! [`render_error_message`](crate::app::state::render_error_message)
//! so `save_not_committed` / `save_durability_unconfirmed` reads
//! identically to the unlock screen's `decrypt_failed` line and the
//! Add modal's inline-error slot.

use paladin_core::Vault;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{format_account_display_label, RemoveModal};
use crate::view::theme;

/// Render the Remove modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 64×10 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells don't show through. The targeted
/// account is resolved against `vault` via `modal.account_id`; if
/// the account has been removed out from under the modal (defensive
/// branch — production flow closes the modal on `EffectResult::Remove`)
/// the renderer falls back to a generic prompt rather than panicking.
pub fn render(frame: &mut Frame<'_>, modal: &RemoveModal, vault: &Vault, no_color: bool) {
    let modal_area = centered_rect(frame.area(), 64, 10);
    frame.render_widget(Clear, modal_area);

    let block =
        theme::destructive_titled_block(" Remove account ", no_color, Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    // Top-to-bottom: prompt, blank, account label, spacer, hint.
    let chunks = Layout::vertical([
        Constraint::Length(1), // prompt
        Constraint::Length(1), // blank
        Constraint::Length(1), // account label
        Constraint::Min(0),    // spacer
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from("Remove the following account?")),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(account_label_line(modal, vault)), chunks[2]);

    if let Some(error) = &modal.error {
        render_inline_error(frame, chunks[3], error, no_color);
    }

    let hint = "Enter confirms  ·  Esc cancels";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[4]);
}

/// Resolve the targeted account against `vault` and format its
/// display label via [`format_account_display_label`] so the modal
/// names accounts identically to the duplicate-account inline error
/// and the CLI's `display_label`. Falls back to a generic prompt if
/// the account has been removed out from under the modal — the
/// reducer's `EffectResult::Remove` handler closes the modal on
/// success, so this branch only fires as a defensive guard against
/// future refactors.
fn account_label_line(modal: &RemoveModal, vault: &Vault) -> Line<'static> {
    match vault.summaries().find(|s| s.id == modal.account_id) {
        Some(summary) => Line::from(format_account_display_label(&summary)),
        None => Line::from("(account no longer present)"),
    }
}

/// Paint the inline error message inside the spacer area between the
/// account-label row and the footer hint. The error sits one blank
/// row below the account label, foreground red, mirroring the unlock
/// screen's `decrypt_failed` styling and the Add modal's inline error
/// so every inline-error surface in the TUI reads the same way.
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
