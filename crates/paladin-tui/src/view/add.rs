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
//! Inline-error / pending-duplicate / counts-panel / URI / QR /
//! per-field focus highlighting all land alongside their own
//! reducer or effect slices; this slice keeps the field column
//! plain text so the snapshot pins only the layout contract.

use paladin_core::{AccountKindInput, Algorithm};
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Padding, Paragraph};
use ratatui::Frame;

use super::centered_rect;
use crate::app::state::{AddModal, AddMode};

/// Width of the left-hand label column inside the modal. Long
/// enough for the widest field name (`Period (s):`) so the value
/// column lines up across every row.
const LABEL_COL_WIDTH: usize = 12;

/// Render the Add modal onto `frame`, on top of whatever the
/// caller already painted underneath.
///
/// The modal is a 64×16 bordered block centered inside the frame's
/// rect; the rect is [`Clear`]-ed before the block is drawn so
/// underlying list-view cells don't show through. Renderers for the
/// other modal variants will follow the same overlay pattern.
pub fn render(frame: &mut Frame<'_>, modal: &AddModal) {
    let modal_area = centered_rect(frame.area(), 64, 16);
    frame.render_widget(Clear, modal_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Add account ")
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

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

    let hint = "Tab cycles fields  ·  Enter submit  ·  Esc cancel";
    frame.render_widget(
        Paragraph::new(hint).alignment(Alignment::Center),
        chunks[11],
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
