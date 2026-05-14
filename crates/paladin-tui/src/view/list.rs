// SPDX-License-Identifier: AGPL-3.0-or-later

//! List-view renderer.
//!
//! Per `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Insta snapshots > Layout / list views": once the vault is open
//! the TUI shows a single-screen list view — a bordered `Paladin`
//! block containing a search bar, a separator, the account-row pane,
//! a second separator, and a bottom keybinding hint.
//!
//! Empty branch: when `vault.iter()` yields nothing, the rows pane
//! shows a single centered "No accounts. Press `a` to add one." line.
//!
//! Populated branch (this slice's TOTP fan-out): each `AccountSummary`
//! becomes one row — a selection marker, the issuer/label pair, the
//! `Code.code` digits split on the width midpoint, a 10-cell
//! period-progress gauge, and the `Code.seconds_remaining` suffix.
//!
//! HOTP rows are hidden by default: the title carries a `(#N)`
//! counter suffix and the right-side column shows the
//! `▸ press n to advance` prompt instead of digits — the renderer
//! never calls into the OTP layer for a hidden HOTP row, so the
//! next-counter code cannot leak. Once
//! `HotpAdvance` opens a [`HotpReveal`] for the row, the title
//! switches to the pre-advance counter (`Code.counter_used`) and the
//! visible code from the reveal replaces the prompt until the
//! reveal's deadline fires (per `DESIGN.md` §6).
//!
//! Search-active filtering and `zz`-recentered viewports land in
//! subsequent slices.
//!
//! The renderer never mutates application state and never performs
//! I/O — every value it reads comes from the supplied [`AppState`].

use std::time::SystemTime;

use paladin_core::{AccountId, AccountKindSummary, AccountSummary, Code, Vault};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};
use ratatui::Frame;
use secrecy::ExposeSecret;

use crate::app::state::{AppState, HotpReveal};

/// Width of the issuer/label column inside an account row. Truncated
/// titles end with `…` so the column never bleeds into the code
/// column at smaller terminal widths.
const TITLE_COL_WIDTH: usize = 32;

/// Width of the OTP-code column. Fits a 6-digit code with a
/// mid-string space (`"123 456"` is 7 chars); the field is
/// right-aligned in a 9-cell box so 7-/8-digit codes stay
/// column-aligned with their 6-digit siblings.
const CODE_COL_WIDTH: usize = 9;

/// Number of cells in the TOTP period-progress gauge.
const GAUGE_WIDTH: usize = 10;

/// Filled cell used by the TOTP progress gauge.
const GAUGE_FILLED: char = '█';

/// Empty cell used by the TOTP progress gauge.
const GAUGE_EMPTY: char = '░';

/// Render the list-view screen for the given Unlocked `state`.
///
/// `now` is the wall-clock instant fed to [`Vault::totp_code`] so
/// TOTP windows / `seconds_remaining` / gauge math are deterministic
/// across renders within the same tick. Caller is responsible for
/// matching `AppState::Unlocked` before dispatching here;
/// non-Unlocked variants are a no-op so a future stray call leaves
/// the backend at its default fill rather than panicking.
pub fn render(frame: &mut Frame<'_>, state: &AppState, now: SystemTime) {
    let AppState::Unlocked {
        vault,
        search_query,
        selected,
        hotp_reveal,
        ..
    } = state
    else {
        return;
    };

    let area = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Paladin ")
        .padding(Padding::symmetric(1, 0));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Top-to-bottom: search line, divider, rows pane, divider, hint.
    // Fixed-height rows hug the borders so the rows pane is the only
    // flexible region, matching the §6 mock where the keybinding hint
    // sits flush with the bottom border.
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(inner);

    let search_line = Line::from(vec![
        Span::raw("Search: "),
        Span::raw(search_query.as_str()),
    ]);
    frame.render_widget(Paragraph::new(search_line), chunks[0]);

    let divider = "─".repeat(inner.width as usize);
    frame.render_widget(Paragraph::new(divider.clone()), chunks[1]);

    if vault.iter().next().is_none() {
        // Empty-state guidance: the centered single-line prompt
        // mirrors the §6 / DESIGN.md add-flow keybinding (`a`) so a
        // user who lands on an empty vault sees what to press next.
        let lines = vec![
            Line::from(""),
            Line::from(Span::raw("No accounts. Press `a` to add one.")),
        ];
        let paragraph = Paragraph::new(lines).alignment(Alignment::Center);
        frame.render_widget(paragraph, chunks[2]);
    } else {
        render_rows(
            frame,
            chunks[2],
            vault,
            selected.as_ref(),
            hotp_reveal.as_ref(),
            now,
        );
    }

    frame.render_widget(Paragraph::new(divider), chunks[3]);

    let hint = "[↑↓] move  [enter] copy  [n] next-HOTP  [a] add  [/] find";
    frame.render_widget(Paragraph::new(hint), chunks[4]);
}

/// Render one account row per visible vault entry into `area`. Rows
/// past the bottom of `area` are clipped — viewport scrolling for
/// long lists lands alongside the `Ctrl-F` / `Ctrl-B` slice.
fn render_rows(
    frame: &mut Frame<'_>,
    area: Rect,
    vault: &Vault,
    selected: Option<&AccountId>,
    hotp_reveal: Option<&HotpReveal>,
    now: SystemTime,
) {
    let capacity = area.height as usize;
    for (idx, account) in vault.iter().take(capacity).enumerate() {
        // `idx < capacity == area.height` (a `u16`), so the cast is
        // lossless — the row offset cannot exceed the row pane's own
        // height.
        let row_offset = u16::try_from(idx).expect("row index ≤ area.height (u16)");
        let row = Rect::new(area.x, area.y + row_offset, area.width, 1);
        let summary = account.summary();
        let is_selected = selected.is_some_and(|sel| *sel == summary.id);
        let line = match summary.kind {
            AccountKindSummary::Totp => render_totp_row(vault, &summary, is_selected, now),
            AccountKindSummary::Hotp => {
                let reveal = hotp_reveal.filter(|r| r.account_id == summary.id);
                render_hotp_row(&summary, is_selected, reveal)
            }
        };
        frame.render_widget(Paragraph::new(line), row);
    }
}

/// Render a single TOTP row: marker, title column, code, gauge, and
/// remaining-seconds suffix. A code-compute failure (e.g.
/// pre-Unix-epoch `now`) falls back to `------` so the row stays
/// the same shape as a healthy row and never panics on a transient
/// `now` argument.
fn render_totp_row(
    vault: &Vault,
    summary: &AccountSummary,
    is_selected: bool,
    now: SystemTime,
) -> String {
    let prefix = format_row_prefix(summary, is_selected, None);
    let period = summary.period.unwrap_or(30);
    let (code_text, secs_remaining) = match vault.totp_code(summary.id, now) {
        Ok(Code {
            code,
            seconds_remaining,
            ..
        }) => (format_code_digits(&code), seconds_remaining.unwrap_or(0)),
        Err(_) => ("------".to_string(), 0),
    };
    let gauge = render_gauge(secs_remaining, period);
    format!("{prefix}  {code_text:>CODE_COL_WIDTH$}   {gauge}  {secs_remaining:>3}s")
}

/// Render a single HOTP row.
///
/// * Hidden (`reveal` is `None`): title gets a `(#N)` suffix using
///   `summary.counter` — the *stored next counter*, which is the
///   value `hotp_advance` would consume on the next press of `n` —
///   and the right-side column shows the `▸ press n to advance`
///   prompt. The renderer never touches the OTP layer on this path,
///   so the next-counter code cannot leak.
/// * Revealed (`reveal` is the active [`HotpReveal`] for this
///   account): title gets a `(#N)` suffix using
///   `reveal.counter_used` — the *pre-advance* counter that
///   produced the visible code — and the right-side column shows
///   the visible code (formatted by [`format_code_digits`] for
///   parity with TOTP rows).
///
/// The caller is responsible for filtering `reveal` to the row's
/// account; passing the reveal slot for a different account would
/// silently desync the displayed counter from the displayed code.
fn render_hotp_row(
    summary: &AccountSummary,
    is_selected: bool,
    reveal: Option<&HotpReveal>,
) -> String {
    let stored_counter = summary.counter.unwrap_or(0);
    let (counter_label, right_col) = match reveal {
        Some(r) => {
            let code = format_code_digits(r.code.expose_secret());
            (r.counter_used, format!("{code:>CODE_COL_WIDTH$}"))
        }
        None => (stored_counter, "▸ press n to advance".to_string()),
    };
    let prefix = format_row_prefix(summary, is_selected, Some(counter_label));
    format!("{prefix}  {right_col}")
}

/// Build the `{marker} {title-padded-to-32}` prefix shared by TOTP
/// and HOTP rows. The marker is a right-pointing wedge for the
/// selected row and a space otherwise so unselected rows stay
/// left-aligned with the marker column rather than shifting one cell
/// when the selection changes.
///
/// When `counter` is `Some(n)`, a ` (#n)` suffix is appended to the
/// title before truncation so HOTP rows carry either the stored next
/// counter (hidden) or `Code.counter_used` (revealed) per
/// `DESIGN.md` §6.
fn format_row_prefix(summary: &AccountSummary, is_selected: bool, counter: Option<u64>) -> String {
    let marker = if is_selected { '▶' } else { ' ' };
    let title = title_for(summary, counter);
    let title = truncate_to_chars(&title, TITLE_COL_WIDTH);
    let pad = TITLE_COL_WIDTH.saturating_sub(title.chars().count());
    format!("{marker} {title}{}", " ".repeat(pad))
}

/// Render the visible label for an account row.
///
/// Per `DESIGN.md` §6's mock, an account with an issuer renders as
/// `{issuer} ({label})`; a label-only account renders bare. HOTP
/// rows append a ` (#N)` counter suffix (`counter` is `Some`) so the
/// row carries the stored next counter (hidden) or
/// `Code.counter_used` (revealed) inside the title column. The
/// composed string is then passed through [`truncate_to_chars`] so
/// it fits the column.
fn title_for(summary: &AccountSummary, counter: Option<u64>) -> String {
    let base = match &summary.issuer {
        Some(issuer) => format!("{issuer} ({label})", issuer = issuer, label = summary.label),
        None => summary.label.clone(),
    };
    match counter {
        Some(n) => format!("{base} (#{n})"),
        None => base,
    }
}

/// Truncate `s` to at most `max_chars` Unicode scalar values,
/// replacing the trailing character with `…` when truncation
/// happens. Char-based (not byte-based) so multi-byte issuers do not
/// produce mid-codepoint truncation.
fn truncate_to_chars(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_string();
    }
    let take = max_chars.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('…');
    out
}

/// Insert a space at the digit-width midpoint of a TOTP code so it
/// reads as two groups (`"123456"` → `"123 456"`). Codes whose width
/// is below 2 (cannot happen for valid TOTP outputs) are returned
/// verbatim; odd widths split with the larger group on the left.
fn format_code_digits(code: &str) -> String {
    let chars: Vec<char> = code.chars().collect();
    if chars.len() < 2 {
        return code.to_string();
    }
    let mid = chars.len().div_ceil(2);
    let mut out = String::with_capacity(chars.len() + 1);
    out.extend(&chars[..mid]);
    out.push(' ');
    out.extend(&chars[mid..]);
    out
}

/// Render the [`GAUGE_WIDTH`]-cell period-progress gauge for a TOTP
/// row. The filled-cell count is `ceil(seconds_remaining / period *
/// GAUGE_WIDTH)` so a single second remaining still shows one filled
/// cell rather than rounding down to an all-empty bar.
fn render_gauge(seconds_remaining: u32, period: u32) -> String {
    if period == 0 {
        return GAUGE_EMPTY.to_string().repeat(GAUGE_WIDTH);
    }
    let secs = seconds_remaining.min(period);
    let filled = (secs as usize * GAUGE_WIDTH).div_ceil(period as usize);
    let filled = filled.min(GAUGE_WIDTH);
    let empty = GAUGE_WIDTH - filled;
    let mut bar = String::with_capacity(GAUGE_WIDTH);
    for _ in 0..filled {
        bar.push(GAUGE_FILLED);
    }
    for _ in 0..empty {
        bar.push(GAUGE_EMPTY);
    }
    bar
}
