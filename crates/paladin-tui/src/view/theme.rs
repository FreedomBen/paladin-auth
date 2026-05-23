// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared color palette and style helpers for `paladin-tui`.
//!
//! Every styled cell in the view layer routes through this module so
//! the `--no-color` flag (and the `NO_COLOR` environment variable,
//! per [`crate::cli::should_disable_color`]) has a single chokepoint:
//! when `no_color` is `true` the helpers return styles with no
//! foreground / background attributes, but still preserve modifiers
//! like `BOLD`, `DIM`, and `REVERSED` so the visual hierarchy degrades
//! to a monochrome-but-still-legible rendering rather than a flat
//! wall of text.
//!
//! The palette intentionally uses ratatui's named ANSI colors
//! ([`Color::Blue`], [`Color::Cyan`], etc.) rather than fixed RGB
//! triples so the user's terminal theme decides the exact hues — a
//! Solarized-Dark terminal renders Blue as muted teal, a default
//! xterm renders it as bright blue, and a light terminal still gets a
//! readable accent.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Padding};

/// Primary accent color used for window borders, titles, and the
/// keybinding column inside the Help overlay.
pub const ACCENT: Color = Color::Blue;

/// Color reserved for destructive surfaces — the Remove modal title,
/// inline error lines, and the `StatusLine::Error` bottom-row tint.
pub const ERROR: Color = Color::Red;

/// Color reserved for successful outcomes — the `StatusLine::Confirmation`
/// bottom-row tint.
pub const SUCCESS: Color = Color::Green;

/// Color used to render TOTP code digits when the rotation window
/// has plenty of time left. Switches to [`WARN`] then [`URGENT`] as
/// the window drains (see [`code_color`]).
pub const CODE_CALM: Color = Color::Green;

/// Color used for the warning tier — TOTP digits and gauge cells in
/// the second half of the rotation window, the plaintext-mode chip,
/// the HOTP `▸ press n to advance` prompt.
pub const WARN: Color = Color::Yellow;

/// Color used for the urgent tier — TOTP digits and gauge cells in
/// the final 5 seconds of the rotation window.
pub const URGENT: Color = Color::Red;

/// Color used for the Help overlay's key column. Cyan reads as a
/// distinct "interactive control" hue against the blue accents used
/// for structural chrome.
pub const KEY_HINT: Color = Color::Cyan;

/// Foreground-only [`Style`] honoring the `--no-color` policy:
/// returns `Style::default().fg(color)` in styled mode and a bare
/// `Style::default()` (no fg attribute) when `no_color` is set.
#[must_use]
pub fn fg(color: Color, no_color: bool) -> Style {
    if no_color {
        Style::default()
    } else {
        Style::default().fg(color)
    }
}

/// Bold + foreground-color [`Style`] honoring `--no-color`. The bold
/// modifier survives in both modes so a no-color terminal still gets
/// the typographic hierarchy.
#[must_use]
pub fn fg_bold(color: Color, no_color: bool) -> Style {
    fg(color, no_color).add_modifier(Modifier::BOLD)
}

/// Dim + foreground-color [`Style`] honoring `--no-color`. Used for
/// secondary text (labels under bolded issuers, advisory prompts).
#[must_use]
pub fn fg_dim(color: Color, no_color: bool) -> Style {
    fg(color, no_color).add_modifier(Modifier::DIM)
}

/// Bordered [`Block`] with the accent-colored border that anchors
/// every full-screen view and modal.
#[must_use]
pub fn bordered_block(no_color: bool) -> Block<'static> {
    let block = Block::default().borders(Borders::ALL);
    if no_color {
        block
    } else {
        block.border_style(Style::default().fg(ACCENT))
    }
}

/// Bordered [`Block`] with a destructive (red) border, used by the
/// Remove modal so the severity reads at the chrome level.
#[must_use]
pub fn destructive_block(no_color: bool) -> Block<'static> {
    let block = Block::default().borders(Borders::ALL);
    if no_color {
        block
    } else {
        block.border_style(Style::default().fg(ERROR))
    }
}

/// Convenience: an accent-bordered [`Block`] carrying the given
/// `title` rendered in bold-accent (or just bold in no-color mode),
/// with the supplied [`Padding`].
#[must_use]
pub fn titled_block(title: &str, no_color: bool, padding: Padding) -> Block<'_> {
    bordered_block(no_color)
        .title(Span::styled(title, fg_bold(ACCENT, no_color)))
        .padding(padding)
}

/// Same as [`titled_block`] but uses the destructive palette so the
/// border and title both render in red.
#[must_use]
pub fn destructive_titled_block(title: &str, no_color: bool, padding: Padding) -> Block<'_> {
    destructive_block(no_color)
        .title(Span::styled(title, fg_bold(ERROR, no_color)))
        .padding(padding)
}

/// Style applied to the currently selected row in the account list.
/// Reverse video plus bold so the highlight works regardless of the
/// user's terminal theme and survives `--no-color`.
#[must_use]
pub fn selected_row_style() -> Style {
    Style::default()
        .add_modifier(Modifier::REVERSED)
        .add_modifier(Modifier::BOLD)
}

/// Pick a foreground color for TOTP code digits and the period
/// progress gauge based on how many seconds remain in the rotation
/// window.
///
/// Thresholds are absolute seconds remaining (matching the GTK
/// frontend's `progress_urgency` bands in `paladin-gtk`):
/// `> 15 s` → [`CODE_CALM`], `6..=15 s` → [`WARN`], `<= 5 s` →
/// [`URGENT`]. A zero `period` falls through to [`CODE_CALM`]
/// defensively — `paladin_core::validation` rejects a zero period
/// upstream, so this path never fires in practice.
#[must_use]
pub fn code_color(seconds_remaining: u32, period: u32) -> Color {
    if period == 0 {
        return CODE_CALM;
    }
    let secs = seconds_remaining.min(period);
    if secs <= 5 {
        URGENT
    } else if secs <= 15 {
        WARN
    } else {
        CODE_CALM
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_color_calm_above_fifteen_seconds() {
        assert_eq!(code_color(30, 30), CODE_CALM);
        assert_eq!(code_color(16, 30), CODE_CALM);
        assert_eq!(code_color(60, 60), CODE_CALM);
        assert_eq!(code_color(16, 60), CODE_CALM);
    }

    #[test]
    fn code_color_warn_between_six_and_fifteen_seconds() {
        assert_eq!(code_color(15, 30), WARN);
        assert_eq!(code_color(10, 30), WARN);
        assert_eq!(code_color(6, 30), WARN);
        assert_eq!(code_color(15, 60), WARN);
        assert_eq!(code_color(6, 60), WARN);
    }

    #[test]
    fn code_color_urgent_at_or_below_five_seconds() {
        assert_eq!(code_color(5, 30), URGENT);
        assert_eq!(code_color(2, 30), URGENT);
        assert_eq!(code_color(1, 30), URGENT);
        assert_eq!(code_color(0, 30), URGENT);
        assert_eq!(code_color(5, 60), URGENT);
        assert_eq!(code_color(0, 60), URGENT);
    }

    #[test]
    fn code_color_clamps_remaining_to_period() {
        // A defensively over-large remaining should clamp into the
        // calm band when the period itself exceeds 15 s.
        assert_eq!(code_color(120, 30), CODE_CALM);
        // When the period is small enough that the clamped value
        // lands in the urgent band, urgent wins.
        assert_eq!(code_color(99, 5), URGENT);
    }

    #[test]
    fn code_color_zero_period_returns_calm() {
        assert_eq!(code_color(0, 0), CODE_CALM);
        assert_eq!(code_color(30, 0), CODE_CALM);
    }
}
