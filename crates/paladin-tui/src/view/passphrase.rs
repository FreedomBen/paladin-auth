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
//! This slice paints the freshly-opened `set` sub-flow baseline —
//! the modal title spells out which transition the user picked
//! (`Set passphrase` / `Change passphrase` / `Remove passphrase`),
//! the body shows a one-line intent description plus the
//! twice-confirm passphrase prompts for the `set` / `change`
//! sub-flows, and the footer keybinding hint sits flush near the
//! bottom of the modal. The `remove` sub-flow's plaintext-storage
//! warning body lands in its own snapshot slice (plan L1970); for
//! now the renderer falls through to the same twice-confirm body
//! shape so the layout contract stays consistent until the
//! sub-flow-specific bodies fan out.
//!
//! The renderer is overlaid on top of the list view by
//! [`super::render`], so the Passphrase modal call site is
//! responsible for [`Clear`]-ing the modal's rect before painting —
//! otherwise list-view content would bleed through transparent
//! cells.
//!
//! Inline `confirmation_mismatch` / `zero_length` validation gates
//! and `save_not_committed` / `save_durability_unconfirmed` variants
//! of this modal land alongside their own
//! [`PassphraseModal::error`](crate::app::state::PassphraseModal::error)
//! rendering slices (plan L1990 / L1991 / L2002 / L2003 / L2004 /
//! L2005 / L2006 / L2007); this baseline keeps the body to the
//! intent / twice-prompt / hint quartet so the snapshot pins only
//! the layout contract.

use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{PassphraseModal, PassphraseSubFlow};

/// Width of the left-hand label column inside the modal. Long
/// enough for the widest field name (`Passphrase:`) so the value
/// column lines up across every row.
const LABEL_COL_WIDTH: usize = 13;

/// Render the Passphrase modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 64×10 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells don't show through. Mirrors the
/// overlay pattern used by the Add / Remove / Rename / Import /
/// Export modal renderers. The title spells out the active
/// sub-flow so the user always knows which transition is being
/// performed.
pub fn render(frame: &mut Frame<'_>, modal: &PassphraseModal) {
    let modal_area = centered_rect(frame.area(), 64, 10);
    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title_for(modal.sub_flow))
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    // Top-to-bottom: intent, blank, passphrase, confirm, spacer,
    // hint.
    let chunks = Layout::vertical([
        Constraint::Length(1), // intent
        Constraint::Length(1), // blank
        Constraint::Length(1), // new passphrase
        Constraint::Length(1), // confirm
        Constraint::Min(0),    // spacer
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

    let hint = "Enter submit  ·  Esc cancel";
    frame.render_widget(Paragraph::new(hint).alignment(Alignment::Center), chunks[5]);
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
