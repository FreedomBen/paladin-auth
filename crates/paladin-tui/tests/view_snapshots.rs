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

use paladin_core::{format_unsafe_permissions, PaladinError, PermissionSubject};
use paladin_tui::app::state::AppState;
use paladin_tui::prompt::PassphraseBuffer;
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

#[test]
fn snapshot_unlock_screen() {
    // Plan L1731: "Unlock screen." — encrypted-vault first-attempt
    // state with no inline error and no typed bytes.
    let state = AppState::Unlock {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    insta::assert_snapshot!(render_to_text(&state, 80, 12));
}

#[test]
fn snapshot_unlock_screen_with_wrong_passphrase_error() {
    // Plan L1791: "Unlock screen with inline wrong-passphrase error."
    // The reducer surfaces the `decrypt_failed` text via
    // `render_error_message(&PaladinError::DecryptFailed)`, which
    // falls back to `Display` for non-`unsafe_permissions` errors —
    // that path is exercised here so the snapshot is bound to the
    // core Display wording rather than a hand-typed string.
    let state = AppState::Unlock {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        error: Some(PaladinError::DecryptFailed.to_string()),
        passphrase: PassphraseBuffer::new(),
    };
    insta::assert_snapshot!(render_to_text(&state, 80, 12));
}

#[test]
fn snapshot_startup_error_unsafe_permissions() {
    // Plan L1806: "Startup-error screen rendered with `unsafe_permissions`
    // (the `Some(text)` from `format_unsafe_permissions`)." Build the error
    // through the public core API so the snapshot binds the verbatim
    // wording from `paladin_core::format_unsafe_permissions`; any future
    // wording change in core is then surfaced as a diff in this snapshot.
    let path = PathBuf::from("/var/lib/paladin/vault.bin");
    let err = PaladinError::UnsafePermissions {
        path: path.clone(),
        subject: PermissionSubject::VaultDir,
        actual_mode: "0755".to_string(),
        expected_mode: "0700".to_string(),
    };
    let message = format_unsafe_permissions(&err).expect("unsafe_permissions text");
    let state = AppState::StartupError {
        path: Some(path),
        message,
    };
    insta::assert_snapshot!(render_to_text(&state, 80, 12));
}
