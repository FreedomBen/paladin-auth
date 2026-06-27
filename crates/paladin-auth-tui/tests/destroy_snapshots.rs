// SPDX-License-Identifier: AGPL-3.0-or-later

//! ratatui rendering snapshots for the Destroy modal and its footer
//! hints / post-destroy create-vault notice (Milestone 10; DESIGN
//! §4.3 / §6, `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Destroy modal").
//!
//! Kept in a dedicated file (rather than `view_snapshots.rs`) so the
//! `destroy_snapshots__*` snapshot namespace is self-contained — the
//! `.snap` fixtures cannot collide with the `view_snapshots__*` set,
//! and the file can be developed independently of the broader
//! view-snapshot suite. Mirrors that suite's symbol-only serializer so
//! a regression shows up as a `git diff`-readable text change.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

use paladin_auth_tui::app::state::{
    AppState, DestroyAction, DestroyModal, VAULT_DELETED, VAULT_DELETED_BACKUP_REMAINED,
};
use paladin_auth_tui::view::render;

/// Fixed wall-clock so any underlay that computes TOTP stays
/// deterministic. Unused by the destroy modal itself (it shows no
/// codes) but threaded for parity with the view-snapshot suite.
fn snapshot_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_500_000_012)
}

/// Render `state` into a `width × height` [`TestBackend`] and return the
/// symbol-only text grid (one line per row), matching
/// `view_snapshots.rs::render_to_text`.
fn render_to_text(state: &AppState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create TestBackend terminal");
    terminal
        .draw(|frame| render(frame, state, snapshot_now(), false))
        .expect("draw frame");
    buffer_to_text(terminal.backend().buffer())
}

/// Serialize a [`Buffer`] to a newline-joined symbol grid with trailing
/// whitespace trimmed per row (matches the view-snapshot serializer).
fn buffer_to_text(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut out = String::new();
    for y in 0..area.height {
        let mut row = String::new();
        for x in 0..area.width {
            row.push_str(buffer[(x, y)].symbol());
        }
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out
}

/// Build a `Destroy` state from a fixed-path prior so the warning body
/// is deterministic. `prior` is a `Missing` create-vault state (no
/// underlay codes), keeping the snapshot focused on the modal chrome.
fn destroy_state(modal: DestroyModal) -> AppState {
    AppState::Destroy {
        path: PathBuf::from("/home/u/.local/share/paladin-auth/vault.bin"),
        prior: Box::new(AppState::create_vault_initial(PathBuf::from(
            "/home/u/.local/share/paladin-auth/vault.bin",
        ))),
        modal,
    }
}

/// A modal with a deterministic warning body (backup present) so the
/// snapshots don't depend on a real filesystem probe.
fn warning_with_backup() -> String {
    paladin_auth_core::format_destroy_warning(
        std::path::Path::new("/home/u/.local/share/paladin-auth/vault.bin"),
        true,
    )
}

fn warning_no_backup() -> String {
    paladin_auth_core::format_destroy_warning(
        std::path::Path::new("/home/u/.local/share/paladin-auth/vault.bin"),
        false,
    )
}

#[test]
fn snapshot_destroy_modal_default() {
    let modal = DestroyModal {
        backup_present: true,
        warning: warning_with_backup(),
        confirmation: String::new(),
        focus: DestroyAction::Cancel,
        error: None,
    };
    insta::assert_snapshot!(render_to_text(&destroy_state(modal), 80, 24));
}

#[test]
fn snapshot_destroy_modal_confirmation_filled() {
    let modal = DestroyModal {
        backup_present: true,
        warning: warning_with_backup(),
        confirmation: "yes".to_string(),
        focus: DestroyAction::Delete,
        error: None,
    };
    insta::assert_snapshot!(render_to_text(&destroy_state(modal), 80, 24));
}

#[test]
fn snapshot_destroy_modal_no_backup() {
    let modal = DestroyModal {
        backup_present: false,
        warning: warning_no_backup(),
        confirmation: String::new(),
        focus: DestroyAction::Cancel,
        error: None,
    };
    insta::assert_snapshot!(render_to_text(&destroy_state(modal), 80, 24));
}

#[test]
fn snapshot_destroy_modal_partial_failure_backup() {
    let modal = DestroyModal {
        backup_present: true,
        warning: warning_with_backup(),
        confirmation: "yes".to_string(),
        focus: DestroyAction::Delete,
        error: Some(
            "Primary deleted; backup unlink failed: \
             /home/u/.local/share/paladin-auth/vault.bin.bak"
                .to_string(),
        ),
    };
    insta::assert_snapshot!(render_to_text(&destroy_state(modal), 80, 24));
}

#[test]
fn snapshot_destroy_modal_partial_failure_fsync() {
    let modal = DestroyModal {
        backup_present: true,
        warning: warning_with_backup(),
        confirmation: "yes".to_string(),
        focus: DestroyAction::Delete,
        error: Some(
            "Vault unlinked but durability unconfirmed: \
             /home/u/.local/share/paladin-auth"
                .to_string(),
        ),
    };
    insta::assert_snapshot!(render_to_text(&destroy_state(modal), 80, 24));
}

#[test]
fn snapshot_destroy_modal_symlink_rejection() {
    let modal = DestroyModal {
        backup_present: false,
        warning: warning_no_backup(),
        confirmation: String::new(),
        focus: DestroyAction::Cancel,
        error: Some(
            "Vault file is a symlink, refusing to follow: \
             /home/u/.local/share/paladin-auth/vault.bin"
                .to_string(),
        ),
    };
    insta::assert_snapshot!(render_to_text(&destroy_state(modal), 80, 24));
}

#[test]
fn snapshot_unlock_footer_hint() {
    // The unlock screen advertises the destroy escape hatch in its
    // footer (DESIGN §6 / Milestone 10).
    let state = AppState::Unlock {
        path: PathBuf::from("/home/u/.local/share/paladin-auth/vault.bin"),
        error: None,
        passphrase: paladin_auth_tui::prompt::PassphraseBuffer::new(),
    };
    insta::assert_snapshot!(render_to_text(&state, 80, 12));
}

#[test]
fn snapshot_startup_error_footer_hint() {
    // A resolved-path startup error shows the destroy footer hint.
    let state = AppState::StartupError {
        path: Some(PathBuf::from("/home/u/.local/share/paladin-auth/vault.bin")),
        message: "vault header is corrupt".to_string(),
    };
    insta::assert_snapshot!(render_to_text(&state, 80, 12));
}

#[test]
fn snapshot_status_line_vault_deleted() {
    // Post-destroy: the create-vault screen carries the neutral
    // `Vault deleted.` notice.
    let state = AppState::create_vault_with_notice(
        PathBuf::from("/home/u/.local/share/paladin-auth/vault.bin"),
        VAULT_DELETED,
    );
    insta::assert_snapshot!(render_to_text(&state, 80, 16));
}

#[test]
fn snapshot_status_line_vault_deleted_backup_remained() {
    let state = AppState::create_vault_with_notice(
        PathBuf::from("/home/u/.local/share/paladin-auth/vault.bin"),
        VAULT_DELETED_BACKUP_REMAINED,
    );
    insta::assert_snapshot!(render_to_text(&state, 80, 16));
}
