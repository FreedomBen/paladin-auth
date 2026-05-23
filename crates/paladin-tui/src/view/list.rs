// SPDX-License-Identifier: AGPL-3.0-or-later

//! List-view renderer.
//!
//! Per `docs/DESIGN.md` §6 and `docs/IMPLEMENTATION_PLAN_03_TUI.md`
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
//! reveal's deadline fires (per `docs/DESIGN.md` §6).
//!
//! Search-active filtering: when `state.search_query` is non-empty,
//! `render_rows` walks the [`crate::search::filtered_account_ids`]
//! subset of [`Vault::iter`] in insertion order — same predicate
//! the reducer uses for incremental search — so the rows pane only
//! paints accounts whose `"{issuer}:{label}"` match key contains the
//! query case-insensitively. An empty query matches every account
//! (per [`paladin_core::account_matches_search`]'s "empty needle
//! matches everything" contract), keeping the no-search list view
//! byte-for-byte identical to the pre-filter rendering.
//!
//! Viewport scrolling: `render_rows` skips the first
//! `state.viewport_offset` rows of the (post-filter) insertion-order
//! list before painting, so the `zz` recenter chord and the page /
//! half-page bindings can shift the visible window without changing
//! row layout. A `viewport_offset` of `0` (the default) keeps the
//! window pinned to the top of the list.
//!
//! The renderer never mutates application state and never performs
//! I/O — every value it reads comes from the supplied [`AppState`].

use std::collections::HashSet;
use std::time::SystemTime;

use paladin_core::{AccountId, AccountKindSummary, AccountSummary, Code, Vault};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Padding, Paragraph};
use ratatui::Frame;
use secrecy::ExposeSecret;

use crate::app::state::{AppState, HotpReveal, StatusLine};
use crate::search::filtered_account_ids;
use crate::view::theme;

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
///
/// `no_color` suppresses foreground / background color attributes
/// on styled cells (the `--no-color` flag and the `NO_COLOR`
/// environment variable both flow here through
/// [`crate::cli::should_disable_color`]). It gates the accent-colored
/// border / title, the TOTP-code / period-gauge color tier
/// (green / yellow / red as the rotation window drains), the
/// search-match highlight, the HOTP `▸ press n to advance` tint,
/// the plaintext-mode title chip, and the bottom-line status tints.
/// Modifiers like bold / dim / reversed survive the gating so the
/// hierarchy remains legible in monochrome terminals.
pub fn render(frame: &mut Frame<'_>, state: &AppState, now: SystemTime, no_color: bool) {
    let AppState::Unlocked {
        vault,
        search_query,
        selected,
        hotp_reveal,
        viewport_offset,
        status_line,
        ..
    } = state
    else {
        return;
    };

    let area = frame.area();
    let title = list_title_line(vault, no_color);
    let block = theme::bordered_block(no_color)
        .title(title)
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
        // mirrors the §6 / docs/DESIGN.md add-flow keybinding (`a`) so a
        // user who lands on an empty vault sees what to press next.
        // The check is against the unfiltered vault — a populated
        // vault whose search-bar filter happens to yield zero rows
        // is still "not empty" and keeps the rows pane blank rather
        // than redirecting to the add-account prompt.
        let lines = vec![
            Line::from(""),
            Line::from(Span::raw("No accounts. Press `a` to add one.")),
        ];
        let paragraph = Paragraph::new(lines).alignment(Alignment::Center);
        frame.render_widget(paragraph, chunks[2]);
    } else {
        let visible_ids: HashSet<AccountId> = filtered_account_ids(vault, search_query)
            .into_iter()
            .collect();
        render_rows(
            frame,
            chunks[2],
            vault,
            &visible_ids,
            selected.as_ref(),
            hotp_reveal.as_ref(),
            *viewport_offset,
            now,
            search_query,
            no_color,
        );
    }

    frame.render_widget(Paragraph::new(divider), chunks[3]);

    frame.render_widget(
        Paragraph::new(bottom_line(status_line.as_ref(), no_color)),
        chunks[4],
    );
}

/// Build the bottom-row [`Line`] for the list view.
///
/// When `status_line` is `None`, returns the default keybinding hint
/// that documents the §6 mock's bottom bar. When `status_line` is
/// `Some`, the published prose takes over the slot — per
/// `docs/DESIGN.md` §6's *"errors surface inline in the active modal or
/// in the status line"* and the
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Status-line states" snapshot
/// fan-out, the carried text from `StatusLine::Error` /
/// `StatusLine::Confirmation` replaces the hint until the next event
/// either clears it (a follow-up successful effect re-publishes
/// `None` per the reducer's last-write-wins contract) or overwrites
/// it. `Error` is tinted red and `Confirmation` is tinted green so a
/// live terminal distinguishes them; `no_color = true` drops the
/// foreground attribute via [`fg_unless_no_color`] so the cells
/// render with the terminal's default color (matching the
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Global flags" wording that
/// `--no-color` disables ratatui styling).
fn bottom_line(status_line: Option<&StatusLine>, no_color: bool) -> Line<'_> {
    match status_line {
        Some(StatusLine::Error(msg)) => Line::from(Span::styled(
            msg.as_str(),
            theme::fg(theme::ERROR, no_color),
        )),
        Some(StatusLine::Confirmation(msg)) => Line::from(Span::styled(
            msg.as_str(),
            theme::fg(theme::SUCCESS, no_color),
        )),
        None => Line::from("[↑↓] move  [enter] copy  [n] next-HOTP  [a] add  [/] find"),
    }
}

/// Render one account row per visible vault entry into `area`. The
/// first `viewport_offset` post-filter rows are skipped so the `zz`
/// recenter chord and page / half-page bindings can shift the
/// visible window; rows past the bottom of `area` are clipped.
///
/// `visible_ids` is the search-bar filter's matching set in vault
/// insertion order (provided as a [`HashSet`] for O(1) membership
/// while [`Vault::iter`] continues to drive the rendering order, so
/// rows still paint in insertion order rather than the filter's
/// return order — relevant once the filter ever switches away from
/// insertion-order preservation).
// Private single-call helper that ferries the row-relevant slices
// of `AppState::Unlocked` into the painting loop; the alternative
// (one bag-of-state struct per renderer helper) buys nothing here.
#[allow(clippy::too_many_arguments)]
fn render_rows(
    frame: &mut Frame<'_>,
    area: Rect,
    vault: &Vault,
    visible_ids: &HashSet<AccountId>,
    selected: Option<&AccountId>,
    hotp_reveal: Option<&HotpReveal>,
    viewport_offset: u16,
    now: SystemTime,
    search_query: &str,
    no_color: bool,
) {
    let capacity = area.height as usize;
    for (idx, account) in vault
        .iter()
        .filter(|account| visible_ids.contains(&account.id()))
        .skip(viewport_offset as usize)
        .take(capacity)
        .enumerate()
    {
        // `idx < capacity == area.height` (a `u16`), so the cast is
        // lossless — the row offset cannot exceed the row pane's own
        // height.
        let row_offset = u16::try_from(idx).expect("row index ≤ area.height (u16)");
        let row = Rect::new(area.x, area.y + row_offset, area.width, 1);
        let summary = account.summary();
        let is_selected = selected.is_some_and(|sel| *sel == summary.id);
        let line = match summary.kind {
            AccountKindSummary::Totp => {
                render_totp_row(vault, &summary, is_selected, now, search_query, no_color)
            }
            AccountKindSummary::Hotp => {
                let reveal = hotp_reveal.filter(|r| r.account_id == summary.id);
                render_hotp_row(&summary, is_selected, reveal, search_query, no_color)
            }
        };
        let paragraph = if is_selected {
            Paragraph::new(line).style(theme::selected_row_style())
        } else {
            Paragraph::new(line)
        };
        frame.render_widget(paragraph, row);
    }
}

/// Render a single TOTP row: marker, title column, code, gauge, and
/// remaining-seconds suffix. A code-compute failure (e.g.
/// pre-Unix-epoch `now`) falls back to `------` so the row stays
/// the same shape as a healthy row and never panics on a transient
/// `now` argument.
///
/// `search_query`, when non-empty, drives an ASCII case-insensitive
/// highlight on matching substrings inside the title column so the
/// user can see at a glance which characters survived the search
/// predicate. `no_color` drops the foreground attributes while
/// keeping the bold modifier on the code digits so the visual
/// hierarchy survives in monochrome terminals.
fn render_totp_row(
    vault: &Vault,
    summary: &AccountSummary,
    is_selected: bool,
    now: SystemTime,
    search_query: &str,
    no_color: bool,
) -> Line<'static> {
    let prefix_text = format_row_prefix(summary, is_selected, None);
    let period = summary.period.unwrap_or(30);
    let (code_text, secs_remaining) = match vault.totp_code(summary.id, now) {
        Ok(Code {
            code,
            seconds_remaining,
            ..
        }) => (format_code_digits(&code), seconds_remaining.unwrap_or(0)),
        Err(_) => ("------".to_string(), 0),
    };
    let gauge_text = render_gauge(secs_remaining, period);
    let gauge = theme::gauge_color(secs_remaining, period);
    let code_padded = format!("{code_text:>CODE_COL_WIDTH$}");

    let mut spans = highlight_prefix_with_search(&prefix_text, search_query, no_color);
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        code_padded,
        theme::fg_bold(theme::CODE, no_color),
    ));
    spans.push(Span::raw("   "));
    spans.push(Span::styled(gauge_text, theme::fg(gauge, no_color)));
    spans.push(Span::raw(format!("  {secs_remaining:>3}s")));
    Line::from(spans)
}

/// Render a single HOTP row.
///
/// * Hidden (`reveal` is `None`): title gets a `(#N)` suffix using
///   `summary.counter` — the *stored next counter*, which is the
///   value `hotp_advance` would consume on the next press of `n` —
///   and the right-side column shows the `▸ press n to advance`
///   prompt rendered in dim yellow so the row reads as
///   "action required". The renderer never touches the OTP layer on
///   this path, so the next-counter code cannot leak.
/// * Revealed (`reveal` is the active [`HotpReveal`] for this
///   account): title gets a `(#N)` suffix using
///   `reveal.counter_used` — the *pre-advance* counter that
///   produced the visible code — and the right-side column shows
///   the visible code rendered in bold cyan (formatted by
///   [`format_code_digits`] for parity with TOTP rows). HOTP codes
///   render in the same [`theme::CODE`] hue as TOTP rows; they have
///   no rotation window so there is no urgency tier to encode.
///
/// The caller is responsible for filtering `reveal` to the row's
/// account; passing the reveal slot for a different account would
/// silently desync the displayed counter from the displayed code.
fn render_hotp_row(
    summary: &AccountSummary,
    is_selected: bool,
    reveal: Option<&HotpReveal>,
    search_query: &str,
    no_color: bool,
) -> Line<'static> {
    let stored_counter = summary.counter.unwrap_or(0);
    let (counter_label, right_spans): (u64, Vec<Span<'static>>) = match reveal {
        Some(r) => {
            let code = format_code_digits(r.code.expose_secret());
            let code_padded = format!("{code:>CODE_COL_WIDTH$}");
            (
                r.counter_used,
                vec![Span::styled(
                    code_padded,
                    theme::fg_bold(theme::CODE, no_color),
                )],
            )
        }
        None => (
            stored_counter,
            vec![Span::styled(
                "▸ press n to advance".to_string(),
                theme::fg_dim(theme::WARN, no_color),
            )],
        ),
    };
    let prefix_text = format_row_prefix(summary, is_selected, Some(counter_label));
    let mut spans = highlight_prefix_with_search(&prefix_text, search_query, no_color);
    spans.push(Span::raw("  "));
    spans.extend(right_spans);
    Line::from(spans)
}

/// Split the row prefix (`marker` + space + padded title) into spans
/// that highlight ASCII case-insensitive matches of `query` in
/// yellow-bold so the user sees which characters survived the search
/// predicate. Non-ASCII titles or queries fall through to a single
/// unstyled span so a stray UTF-8 character cannot mid-codepoint
/// split the row.
///
/// The prefix layout is `{marker}{space}{title_padded_to_TITLE_COL_WIDTH}`
/// — the marker and gutter never contain query characters, so the
/// match search is anchored to the title portion only.
fn highlight_prefix_with_search(prefix: &str, query: &str, no_color: bool) -> Vec<Span<'static>> {
    let leader_chars = 2; // marker + gutter space
    let chars: Vec<char> = prefix.chars().collect();
    if query.is_empty() || chars.len() <= leader_chars {
        return vec![Span::raw(prefix.to_string())];
    }
    let leader: String = chars[..leader_chars].iter().collect();
    let title: String = chars[leader_chars..].iter().collect();
    if !title.is_ascii() || !query.is_ascii() {
        return vec![Span::raw(prefix.to_string())];
    }
    let lower_title = title.to_ascii_lowercase();
    let lower_query = query.to_ascii_lowercase();
    let mut spans: Vec<Span<'static>> = vec![Span::raw(leader)];
    let hit_style = Style::default()
        .add_modifier(Modifier::BOLD)
        .add_modifier(Modifier::UNDERLINED);
    let hit_style = if no_color {
        hit_style
    } else {
        hit_style.fg(theme::WARN)
    };
    let mut cursor = 0;
    for (idx, _) in lower_title.match_indices(&lower_query) {
        if idx > cursor {
            spans.push(Span::raw(title[cursor..idx].to_string()));
        }
        let end = idx + lower_query.len();
        spans.push(Span::styled(title[idx..end].to_string(), hit_style));
        cursor = end;
    }
    if cursor < title.len() {
        spans.push(Span::raw(title[cursor..].to_string()));
    }
    spans
}

/// Build the bordered block's title line. The base " Paladin "
/// segment is rendered in bold accent; a plaintext-mode vault gets a
/// `[plaintext]` warning chip appended in yellow so the user always
/// sees that the vault is unencrypted, regardless of which screen
/// they are on.
fn list_title_line(vault: &Vault, no_color: bool) -> Line<'static> {
    let mut spans = vec![Span::styled(
        " Paladin ",
        theme::fg_bold(theme::ACCENT, no_color),
    )];
    if !vault.is_encrypted() {
        spans.push(Span::styled(
            "[plaintext] ",
            theme::fg_bold(theme::WARN, no_color),
        ));
    }
    Line::from(spans)
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
/// `docs/DESIGN.md` §6.
fn format_row_prefix(summary: &AccountSummary, is_selected: bool, counter: Option<u64>) -> String {
    let marker = if is_selected { '▶' } else { ' ' };
    let title = title_for(summary, counter);
    let title = truncate_to_chars(&title, TITLE_COL_WIDTH);
    let pad = TITLE_COL_WIDTH.saturating_sub(title.chars().count());
    format!("{marker} {title}{}", " ".repeat(pad))
}

/// Render the visible label for an account row.
///
/// Per `docs/DESIGN.md` §6's mock, an account with an issuer renders as
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
