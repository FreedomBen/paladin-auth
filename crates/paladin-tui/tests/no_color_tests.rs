// SPDX-License-Identifier: AGPL-3.0-or-later

//! `--no-color` / `NO_COLOR` runtime gating for the renderer.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Global flags":
//!
//! > `--no-color` disables ratatui styling; the `NO_COLOR`
//! > environment variable does the same when `--no-color` is
//! > absent, matching CLI text-output behavior.
//!
//! `paladin_tui::cli::should_disable_color` already pinned the
//! flag-vs-env precedence in [`tests/reducer_tests.rs`]; this suite
//! pins the *renderer-side* contract — that when the resolved
//! `no_color: bool` flows down through `view::render` →
//! `list::render` → `bottom_line`, the foreground attribute on the
//! status-line cells disappears, while the default (`no_color =
//! false`) path keeps `Color::Red` (Error) / `Color::Green`
//! (Confirmation).
//!
//! The existing `tests/view_snapshots.rs` harness intentionally
//! drops style attributes from its text snapshots (so the
//! symbol-only diffs stay readable), which is why the
//! `--no-color` × styled-color matrix needs a separate harness:
//! [`render_to_buffer`] returns the full ratatui [`Buffer`] and
//! the assertions inspect cell `fg` directly.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::Color;
use ratatui::Terminal;

use paladin_core::{Store, Vault, VaultInit, VaultLock};
use paladin_tui::app::state::{AppState, Focus, StatusLine};
use paladin_tui::view;

mod common;
use common::test_tempdir;

/// Fixed wall-clock instant so any TOTP math is deterministic.
/// Matches `view_snapshots.rs::SNAPSHOT_NOW_SECS` to keep
/// cross-suite reasoning simple, though the bottom-line cells under
/// test do not depend on `now`.
const RENDER_NOW_SECS: u64 = 1_500_000_012;

fn render_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(RENDER_NOW_SECS)
}

/// Tempdir that ignores `$TMPDIR` and is chmod'd to `0700` so
/// `paladin_core::Store::create` does not reject it via the §4.3
/// `unsafe_permissions` check on hosts with looser tempdir bits.
fn secure_tempdir() -> tempfile::TempDir {
    let dir = test_tempdir();
    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

/// Create a fresh plaintext vault on disk and return the unlocked
/// `(Vault, Store)` pair.
fn open_plaintext_pair(path: &Path) -> (Vault, Store) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(path, VaultLock::Plaintext).expect("reopen plaintext")
}

/// Build an `Unlocked` state on a fresh plaintext vault with the
/// supplied `status_line` published; every other slot is set to its
/// neutral default so the rendered frame is fully deterministic.
fn unlocked_with_status_line(path: PathBuf, status_line: StatusLine) -> AppState {
    let (vault, store) = open_plaintext_pair(&path);
    AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(status_line),
        help_open: false,
    }
}

/// Render `state` into an `width × height` [`TestBackend`] and
/// return the full ratatui [`Buffer`] (including per-cell style
/// attributes). The companion `view_snapshots.rs::render_to_text`
/// helper deliberately strips those attributes for symbol-only
/// snapshots; this helper preserves them so the `--no-color` tests
/// can assert against cell `fg`.
fn render_to_buffer(state: &AppState, no_color: bool, width: u16, height: u16) -> Buffer {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create TestBackend terminal");
    terminal
        .draw(|frame| view::render(frame, state, render_now(), no_color))
        .expect("draw frame");
    terminal.backend().buffer().clone()
}

/// X coordinate of the bottom-line message's first character.
///
/// The Paladin block draws a 1-cell border + 1-cell horizontal
/// padding (`Padding::symmetric(1, 0)`), so the bordered block's
/// inner content starts at `x = 2`. The bottom-line `Paragraph`
/// fills that inner row left-aligned, so the message's first byte
/// always lands at `x = 2`.
const BOTTOM_LINE_MSG_X: u16 = 2;

/// Y coordinate of the bottom-line row for an 80×12 frame.
///
/// Outer frame is `(0, 0, 80, 12)`. Borders take 1 cell on each
/// side (vertical padding is 0), so the bordered block's inner
/// rect is `(2, 1, 76, 10)`. The list-view's vertical layout is
/// `[Length(1), Length(1), Min(0), Length(1), Length(1)]`, so the
/// bottom-line `chunks[4]` sits at the inner's last row →
/// `y = 1 + 10 - 1 = 10`.
const BOTTOM_LINE_Y_AT_HEIGHT_12: u16 = 10;

// ---------------------------------------------------------------------------
// Error tint
// ---------------------------------------------------------------------------

#[test]
fn bottom_line_status_line_error_strips_fg_when_no_color_is_true() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("plaintext.bin");
    let state = unlocked_with_status_line(path, StatusLine::Error("Failed: example".into()));
    let buf = render_to_buffer(&state, true, 80, 12);

    let cell = &buf[(BOTTOM_LINE_MSG_X, BOTTOM_LINE_Y_AT_HEIGHT_12)];
    assert_eq!(
        cell.symbol(),
        "F",
        "test setup: bottom-line cell at (x={BOTTOM_LINE_MSG_X}, y={BOTTOM_LINE_Y_AT_HEIGHT_12}) \
         should be the message's first char `F` for `Failed:` — got {:?}",
        cell.symbol(),
    );
    assert_eq!(
        cell.fg,
        Color::Reset,
        "no_color = true must drop the Color::Red foreground from the Error status-line; \
         cell.fg = {:?}",
        cell.fg,
    );
}

#[test]
fn bottom_line_status_line_error_keeps_red_fg_when_no_color_is_false() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("plaintext.bin");
    let state = unlocked_with_status_line(path, StatusLine::Error("Failed: example".into()));
    let buf = render_to_buffer(&state, false, 80, 12);

    let cell = &buf[(BOTTOM_LINE_MSG_X, BOTTOM_LINE_Y_AT_HEIGHT_12)];
    assert_eq!(cell.symbol(), "F");
    assert_eq!(
        cell.fg,
        Color::Red,
        "default (color enabled) must keep Color::Red on the Error status-line; \
         cell.fg = {:?}",
        cell.fg,
    );
}

// ---------------------------------------------------------------------------
// Confirmation tint
// ---------------------------------------------------------------------------

#[test]
fn bottom_line_status_line_confirmation_strips_fg_when_no_color_is_true() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("plaintext.bin");
    let state = unlocked_with_status_line(path, StatusLine::Confirmation("Saved".into()));
    let buf = render_to_buffer(&state, true, 80, 12);

    let cell = &buf[(BOTTOM_LINE_MSG_X, BOTTOM_LINE_Y_AT_HEIGHT_12)];
    assert_eq!(
        cell.symbol(),
        "S",
        "test setup: bottom-line cell at (x={BOTTOM_LINE_MSG_X}, y={BOTTOM_LINE_Y_AT_HEIGHT_12}) \
         should be `S` for `Saved` — got {:?}",
        cell.symbol(),
    );
    assert_eq!(
        cell.fg,
        Color::Reset,
        "no_color = true must drop the Color::Green foreground from the Confirmation \
         status-line; cell.fg = {:?}",
        cell.fg,
    );
}

#[test]
fn bottom_line_status_line_confirmation_keeps_green_fg_when_no_color_is_false() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("plaintext.bin");
    let state = unlocked_with_status_line(path, StatusLine::Confirmation("Saved".into()));
    let buf = render_to_buffer(&state, false, 80, 12);

    let cell = &buf[(BOTTOM_LINE_MSG_X, BOTTOM_LINE_Y_AT_HEIGHT_12)];
    assert_eq!(cell.symbol(), "S");
    assert_eq!(
        cell.fg,
        Color::Green,
        "default (color enabled) must keep Color::Green on the Confirmation status-line; \
         cell.fg = {:?}",
        cell.fg,
    );
}

// ---------------------------------------------------------------------------
// build_render_closure plumbing
// ---------------------------------------------------------------------------

#[test]
fn build_render_closure_propagates_no_color_into_draw_frame() {
    // End-to-end plumbing: build_render_closure captures the
    // no_color bool at construction time and threads it through
    // draw_frame → view::render → list::render → bottom_line on
    // every frame. Regressions that ever short-circuit the
    // threading (e.g. hard-coding `false` inside the closure)
    // would surface as `cell.fg = Color::Red` here.
    use std::cell::RefCell;
    use std::io;

    use paladin_tui::app::build_render_closure;

    let tmp = secure_tempdir();
    let path = tmp.path().join("plaintext.bin");
    let state = unlocked_with_status_line(path, StatusLine::Error("Boom".into()));

    let backend = TestBackend::new(80, 12);
    let mut terminal = Terminal::new(backend).expect("create TestBackend terminal");
    let sink: RefCell<Option<io::Error>> = RefCell::new(None);
    {
        let mut render = build_render_closure(&mut terminal, &sink, true);
        render(&state, render_now());
    }
    assert!(
        sink.borrow().is_none(),
        "no draw failure should be recorded on the success path: {:?}",
        sink.borrow().as_ref().map(io::Error::to_string),
    );

    let buf = terminal.backend().buffer().clone();
    let cell = &buf[(BOTTOM_LINE_MSG_X, BOTTOM_LINE_Y_AT_HEIGHT_12)];
    assert_eq!(cell.symbol(), "B", "test setup: first char of `Boom`");
    assert_eq!(
        cell.fg,
        Color::Reset,
        "build_render_closure must thread no_color = true all the way to bottom_line; \
         cell.fg = {:?}",
        cell.fg,
    );
}
