// SPDX-License-Identifier: AGPL-3.0-or-later

//! Passphrase-modal renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Modals (per §6) > Passphrase": *"three sub-flows mirroring
//! CLI's `passphrase set / change / remove`. The available sub-flow
//! is gated by [`Vault::is_encrypted()`](paladin_core::Vault::is_encrypted):
//! `set` is offered only on plaintext vaults (plaintext → encrypted),
//! and `change` / `remove` are offered only on encrypted vaults.
//! New passphrases (`set`, `change`) are prompted twice and
//! confirmed; mismatch returns to the modal with an inline
//! `invalid_passphrase` (`reason: "confirmation_mismatch"`) error.
//! Empty new passphrases are rejected with `invalid_passphrase`
//! (`reason: "zero_length"`)."*
//!
//! The modal title spells out which transition the user picked
//! (`Set passphrase` / `Change passphrase` / `Remove passphrase`),
//! the body fans out per sub-flow — `set` / `change` show a one-line
//! intent description plus the twice-confirm passphrase prompts,
//! and `remove` swaps the twice-confirm rows for a wrapped
//! plaintext-storage warning sourced verbatim from
//! [`paladin_core::format_plaintext_storage_warning`] so the TUI
//! wording stays byte-identical to the CLI `passphrase remove` /
//! GTK `PassphraseDialog::remove_warning_body` paths. The footer
//! keybinding hint sits flush near the bottom of the modal in every
//! sub-flow — `Enter submit  ·  Esc cancel` for the twice-confirm
//! sub-flows, `Enter confirm  ·  Esc cancel` for `remove` to flag
//! its destructive mutation. The `remove` modal is taller than the
//! twice-confirm sub-flows because the wrapped warning consumes
//! more rows than the masked input pair it replaces.
//!
//! The renderer is overlaid on top of the list view by
//! [`super::render`], so the Passphrase modal call site is
//! responsible for [`Clear`]-ing the modal's rect before painting —
//! otherwise list-view content would bleed through transparent
//! cells.
//!
//! The [`PassphraseModal::error`](crate::app::state::PassphraseModal::error)
//! slot surfaces inline near the bottom of the modal, painted in
//! red and routed through
//! [`render_error_message`](crate::app::state::render_error_message)
//! so `save_not_committed` / `save_durability_unconfirmed` reads
//! identically to the unlock screen's `decrypt_failed` line and the
//! Add / Remove / Rename / Import / Export modals' inline-error
//! slots. In the twice-confirm sub-flows (`set` / `change`) the
//! error sits inside the spacer between the `Confirm:` row and the
//! footer hint; in the `remove` sub-flow it sits between the
//! wrapped plaintext-storage warning and the footer hint so the
//! destructive-mutation verb (`Enter confirm  ·  Esc cancel`)
//! remains visible alongside the save failure. Inline
//! `confirmation_mismatch` / `zero_length` validation gates flow
//! through the same slot, populated by the reducer when the user
//! submits.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap};
use ratatui::Frame;

use paladin_core::format_plaintext_storage_warning;

use super::centered_rect;
use crate::app::state::{PassphraseModal, PassphraseSubFlow};

/// Width of the left-hand label column inside the modal. Long
/// enough for the widest field name (`Passphrase:`) so the value
/// column lines up across every row.
const LABEL_COL_WIDTH: usize = 13;

/// Render the Passphrase modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 64-wide bordered block centered inside the
/// frame's rect; the rect is [`Clear`]-ed before the block is drawn
/// so underlying list-view cells don't show through. Mirrors the
/// overlay pattern used by the Add / Remove / Rename / Import /
/// Export modal renderers. The title spells out the active sub-flow
/// so the user always knows which transition is being performed.
/// The block grows taller for the `remove` sub-flow because its
/// wrapped plaintext-storage warning consumes more rows than the
/// twice-confirm input pair used by `set` / `change`.
pub fn render(frame: &mut Frame<'_>, modal: &PassphraseModal) {
    let modal_area = centered_rect(frame.area(), 64, modal_height(modal.sub_flow));
    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title_for(modal.sub_flow))
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    match modal.sub_flow {
        PassphraseSubFlow::Set | PassphraseSubFlow::Change => {
            render_twice_confirm(frame, inner, modal);
        }
        PassphraseSubFlow::Remove => render_remove_warning(frame, inner, modal),
    }
}

/// Modal height for the bordered block, per sub-flow. `set` and
/// `change` share the compact twice-confirm layout; `remove` grows
/// taller to fit the wrapped plaintext-storage warning. The widths
/// (`64` cells) are equal across sub-flows so the user's eye lands
/// on the same screen region regardless of which transition is
/// being performed.
fn modal_height(sub_flow: PassphraseSubFlow) -> u16 {
    match sub_flow {
        PassphraseSubFlow::Set | PassphraseSubFlow::Change => 10,
        PassphraseSubFlow::Remove => 14,
    }
}

/// Render the twice-confirm body shared by the `set` and `change`
/// sub-flows: one-line intent, a blank spacer, the two masked
/// passphrase input rows, a flexible spacer (carries the inline
/// error when [`PassphraseModal::error`] is populated), and the
/// centered `Enter submit  ·  Esc cancel` hint.
fn render_twice_confirm(frame: &mut Frame<'_>, inner: Rect, modal: &PassphraseModal) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // intent
        Constraint::Length(1), // blank
        Constraint::Length(1), // new passphrase
        Constraint::Length(1), // confirm
        Constraint::Min(0),    // spacer (carries inline error if any)
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(Paragraph::new(intent_line(modal.sub_flow)), chunks[0]);
    frame.render_widget(
        Paragraph::new(masked_field_line(
            "Passphrase:",
            modal.new_passphrase.as_str().chars().count(),
        )),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(masked_field_line(
            "Confirm:",
            modal.confirm_passphrase.as_str().chars().count(),
        )),
        chunks[3],
    );

    if let Some(error) = &modal.error {
        render_inline_error(frame, chunks[4], error);
    }

    let hint = "Enter submit  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[5]);
}

/// Render the `remove` sub-flow body: one-line intent, a blank
/// spacer, the wrapped plaintext-storage warning sourced from
/// [`paladin_core::format_plaintext_storage_warning`], a flexible
/// spacer (carries the inline error when [`PassphraseModal::error`]
/// is populated), and the centered `Enter confirm  ·  Esc cancel`
/// hint (the verb shifts to `confirm` to flag the destructive
/// mutation).
fn render_remove_warning(frame: &mut Frame<'_>, inner: Rect, modal: &PassphraseModal) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // intent
        Constraint::Length(1), // blank
        Constraint::Min(1),    // wrapped warning
        Constraint::Length(1), // spacer (carries inline error if any)
        Constraint::Length(1), // hint
    ])
    .split(inner);

    frame.render_widget(Paragraph::new(intent_line(modal.sub_flow)), chunks[0]);
    frame.render_widget(
        Paragraph::new(format_plaintext_storage_warning()).wrap(Wrap { trim: true }),
        chunks[2],
    );

    if let Some(error) = &modal.error {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                error.clone(),
                Style::default().fg(Color::Red),
            ))),
            chunks[3],
        );
    }

    let hint = "Enter confirm  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[4]);
}

/// Paint the inline error message inside the spacer area between the
/// `Confirm:` row and the footer hint. The error sits one blank row
/// below the `Confirm:` row, foreground red, mirroring the unlock
/// screen's `decrypt_failed` styling and the Add / Remove / Rename /
/// Import modals' inline errors so every inline-error surface in the
/// TUI reads the same way.
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

/// Title text for the modal's bordered block. The active sub-flow
/// is named verbatim so a regression that ever swaps the title
/// (e.g. opens the wrong sub-flow on an encrypted vault) surfaces
/// as a diff.
fn title_for(sub_flow: PassphraseSubFlow) -> &'static str {
    match sub_flow {
        PassphraseSubFlow::Set => " Set passphrase ",
        PassphraseSubFlow::Change => " Change passphrase ",
        PassphraseSubFlow::Remove => " Remove passphrase ",
    }
}

/// One-line intent description painted just below the title border
/// so the user sees what the modal is about to do before typing
/// any bytes into the masked prompts. Wording mirrors the CLI
/// `paladin passphrase set / change / remove` command help.
fn intent_line(sub_flow: PassphraseSubFlow) -> Line<'static> {
    match sub_flow {
        PassphraseSubFlow::Set => Line::from("Encrypts this vault under a new passphrase."),
        PassphraseSubFlow::Change => Line::from("Re-encrypts this vault under a new passphrase."),
        PassphraseSubFlow::Remove => Line::from("Removes the passphrase and stores plaintext."),
    }
}

/// Render a masked passphrase-entry row. The typed character count
/// is rendered as bullets so the snapshot pins that the renderer
/// never paints the secret bytes; an empty buffer renders as `[ ]`.
/// Mirrors the Add modal's `masked_field_line` so the TUI's
/// secret-input rows look the same across modals.
fn masked_field_line(label: &str, char_count: usize) -> Line<'static> {
    let masked: String = "•".repeat(char_count);
    Line::from(format!("{label:<LABEL_COL_WIDTH$}[ {masked} ]"))
}
