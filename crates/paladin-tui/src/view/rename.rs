// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rename-modal renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6) > Rename": *"single text field pre-populated
//! with the selected account's current label."* This slice paints
//! the freshly-opened baseline — the targeted account's display
//! label above an editable `New label:` text-input row carrying the
//! `RenameModal::draft` buffer, framed by the standard ratatui block
//! borders, with the Enter / Esc keybinding hint flush near the
//! bottom of the modal.
//!
//! The renderer is overlaid on top of the list view by
//! [`super::render`], so the Rename modal call site is responsible
//! for [`Clear`]-ing the modal's rect before painting — otherwise
//! list-view content would bleed through transparent cells.
//!
//! Inline `save_not_committed` / `save_durability_unconfirmed`
//! variants of this modal land alongside their own
//! [`RenameModal::error`](crate::app::state::RenameModal::error)
//! rendering slice; this baseline keeps the body to the prompt /
//! account-label / draft-field / hint quartet so the snapshot pins
//! only the layout contract.

use paladin_core::Vault;
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{format_account_display_label, RenameModal};

/// Width of the left-hand label column inside the modal. Matches the
/// Add modal's column so the `New label:` field aligns with the rest
/// of the TUI's editable-field rows.
const LABEL_COL_WIDTH: usize = 12;

/// Render the Rename modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 64×10 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells don't show through. The targeted
/// account is resolved against `vault` via `modal.account_id`; if
/// the account has been removed out from under the modal (defensive
/// branch — production flow closes the modal on `EffectResult::Rename`)
/// the renderer falls back to a generic prompt rather than panicking.
pub fn render(frame: &mut Frame<'_>, modal: &RenameModal, vault: &Vault) {
    let modal_area = centered_rect(frame.area(), 64, 10);
    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Rename account ")
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    // Top-to-bottom: prompt, account label, blank, draft field,
    // spacer, hint.
    let chunks = Layout::vertical([
        Constraint::Length(1), // prompt
        Constraint::Length(1), // account label
        Constraint::Length(1), // blank
        Constraint::Length(1), // draft field
        Constraint::Min(0),    // spacer
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from("Renaming the following account:")),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(account_label_line(modal, vault)), chunks[1]);
    frame.render_widget(
        Paragraph::new(text_field_line("New label:", &modal.draft)),
        chunks[3],
    );

    let hint = "Enter submit  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[5]);
}

/// Resolve the targeted account against `vault` and format its
/// display label via [`format_account_display_label`] so the modal
/// names accounts identically to the duplicate-account inline error
/// and the CLI's `display_label`. Falls back to a generic prompt if
/// the account has been removed out from under the modal — the
/// reducer's `EffectResult::Rename` handler closes the modal on
/// success, so this branch only fires as a defensive guard against
/// future refactors.
fn account_label_line(modal: &RenameModal, vault: &Vault) -> Line<'static> {
    match vault.summaries().find(|s| s.id == modal.account_id) {
        Some(summary) => Line::from(format_account_display_label(&summary)),
        None => Line::from("(account no longer present)"),
    }
}

/// Render a labeled text-input row. Editable fields show their
/// current contents inside `[ ... ]` brackets so an empty value
/// renders as `[ ]` rather than blank and the field is visibly
/// "an input slot" in the snapshot — matches the Add modal's
/// `text_field_line` so the TUI's editable rows look the same
/// across modals.
fn text_field_line(label: &str, value: &str) -> Line<'static> {
    Line::from(format!("{label:<LABEL_COL_WIDTH$}[ {value} ]"))
}
