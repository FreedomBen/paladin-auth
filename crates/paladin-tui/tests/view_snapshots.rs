// SPDX-License-Identifier: AGPL-3.0-or-later

//! ratatui rendering snapshots for `paladin-tui`.
//!
//! Each test drives one [`AppState`] variant through the view
//! pipeline using [`ratatui::backend::TestBackend`] (no real
//! terminal, no I/O), then converts the resulting [`Buffer`] into a
//! deterministic text grid and asserts it via `insta::assert_snapshot!`.
//! Insta stores accepted output in `tests/snapshots/` so any
//! regression shows up as a `git diff`-readable text change.
//!
//! Tracks the "Tests > Insta snapshots" checklist in
//! `IMPLEMENTATION_PLAN_03_TUI.md`. The harness deliberately drops
//! styling (foreground / background / modifiers) from the snapshot
//! body — only the cell symbols are serialized — so the snapshot
//! file stays diff-readable and the `--no-color` variants share a
//! single text body. A styled-grid harness for the eventual
//! `--no-color` × styled-color matrix lands when the list view's
//! search highlighting needs it.

use std::path::PathBuf;

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

use paladin_tui::app::state::AppState;
use paladin_tui::view::render;

/// Draw `state` into an `width × height` [`TestBackend`] and return
/// the resulting text grid (one line per row, cell symbols only).
fn render_to_text(state: &AppState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create TestBackend terminal");
    terminal
        .draw(|frame| render(frame, state))
        .expect("draw frame");
    buffer_to_text(terminal.backend().buffer())
}

/// Serialize a ratatui [`Buffer`] as one line per terminal row.
///
/// Cell symbols are joined verbatim (multi-codepoint graphemes like
/// box-drawing characters are preserved); styling is intentionally
/// dropped so the snapshot diffs stay readable.
fn buffer_to_text(buffer: &Buffer) -> String {
    let area = buffer.area();
    let width = area.width;
    let height = area.height;
    let mut out = String::with_capacity((width as usize + 1) * height as usize);
    for y in 0..height {
        for x in 0..width {
            out.push_str(buffer[(x, y)].symbol());
        }
        // Trim trailing spaces so the snapshot file is friendlier to
        // diff and to editors with "strip-trailing-whitespace" hooks.
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('\n');
    }
    out
}

#[test]
fn snapshot_missing_vault_screen() {
    let state = AppState::MissingVault {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
    };
    insta::assert_snapshot!(render_to_text(&state, 80, 12));
}
