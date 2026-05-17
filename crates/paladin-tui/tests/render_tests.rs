// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the `paladin_tui::app::render::draw_frame` adapter that
//! bridges the pure event-loop glue (`app::dispatch`'s
//! `FnMut(&AppState, SystemTime)` render closure) to a real
//! `ratatui::Terminal::draw` call against [`crate::view::render`].
//!
//! The adapter is a thin pass-through, so each test asserts that the
//! buffer produced by [`paladin_tui::app::render::draw_frame`] matches,
//! cell for cell, the buffer produced by a direct
//! `terminal.draw(|f| view::render(f, state, now))` call. Coverage:
//!
//! * `MissingVault` (dead-end screen).
//! * `StartupError` (dead-end screen).
//! * `Unlock` (dead-end screen, exercises the typed-passphrase branch).
//! * `Unlocked` with a single TOTP account — pins the `now`
//!   forwarding so a regression that ever stops threading the
//!   wall-clock through to the renderer surfaces as a diff.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

use paladin_core::{
    format_unsafe_permissions, validate_manual, AccountInput, AccountKindInput, Algorithm,
    IconHintInput, PaladinError, PermissionSubject, Store, VaultInit,
};
use paladin_tui::app::render::draw_frame;
use paladin_tui::app::state::{decide_state_from_open, AppState};
use paladin_tui::prompt::PassphraseBuffer;
use paladin_tui::view::render as view_render;
use secrecy::SecretString;

mod common;
use common::secure_test_tempdir;

/// `1_500_000_012 mod 30 == 12`, mirroring `view_snapshots.rs` so any
/// TOTP-bearing comparison falls on a deterministic window cursor.
const SNAPSHOT_NOW_SECS: u64 = 1_500_000_012;

fn snapshot_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(SNAPSHOT_NOW_SECS)
}

/// Build a `Terminal<TestBackend>` of the given dimensions.
fn fresh_terminal(width: u16, height: u16) -> Terminal<TestBackend> {
    Terminal::new(TestBackend::new(width, height)).expect("create TestBackend terminal")
}

/// Render `state` via the adapter and return the resulting buffer.
///
/// `no_color = false` is threaded into both `draw_frame` and the
/// `render_via_view` baseline so the adapter-vs-baseline diff is
/// invariant under the `--no-color` gating that landed alongside
/// the `paladin_tui::cli::should_disable_color` wiring; the
/// `no_color = true` branch is exercised in `tests/no_color_tests.rs`.
fn render_via_adapter(state: &AppState, now: SystemTime, width: u16, height: u16) -> Buffer {
    let mut terminal = fresh_terminal(width, height);
    draw_frame(&mut terminal, state, now, false)
        .expect("draw_frame should succeed against TestBackend");
    terminal.backend().buffer().clone()
}

/// Render `state` by driving `view::render` directly. Baseline that
/// the adapter must match to qualify as a thin pass-through.
fn render_via_view(state: &AppState, now: SystemTime, width: u16, height: u16) -> Buffer {
    let mut terminal = fresh_terminal(width, height);
    terminal
        .draw(|frame| view_render(frame, state, now, false))
        .expect("baseline draw");
    terminal.backend().buffer().clone()
}

#[test]
fn draw_frame_missing_vault_matches_view_render_baseline() {
    let state = AppState::MissingVault {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
    };
    let now = snapshot_now();

    let adapter = render_via_adapter(&state, now, 80, 12);
    let baseline = render_via_view(&state, now, 80, 12);

    assert_eq!(adapter, baseline);
}

#[test]
fn draw_frame_startup_error_matches_view_render_baseline() {
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
    let now = snapshot_now();

    let adapter = render_via_adapter(&state, now, 80, 12);
    let baseline = render_via_view(&state, now, 80, 12);

    assert_eq!(adapter, baseline);
}

#[test]
fn draw_frame_unlock_screen_matches_view_render_baseline() {
    let state = AppState::Unlock {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        error: Some(PaladinError::DecryptFailed.to_string()),
        passphrase: PassphraseBuffer::new(),
    };
    let now = snapshot_now();

    let adapter = render_via_adapter(&state, now, 80, 12);
    let baseline = render_via_view(&state, now, 80, 12);

    assert_eq!(adapter, baseline);
}

#[test]
fn draw_frame_threads_wall_clock_into_view_render() {
    // Drive the adapter against the same Unlocked state at two
    // different `now` values and confirm each output matches the
    // matching `view::render` baseline. The state holds one TOTP
    // account using the same Base32 secret /
    // algorithm / digits / 30-s window the existing
    // `snapshot_list_view_single_totp` view test pins, so at
    // `SNAPSHOT_NOW_SECS = 1_500_000_012` the renderer is 12 s
    // into the window; rendering again at `now + 5s` shifts the
    // gauge and seconds-remaining cells. A regression that ever
    // stops threading the wall-clock through the closure renders
    // both calls identically and fails this test.
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Plaintext).expect("create plaintext vault");
    let input = AccountInput {
        label: "ben@example.com".to_string(),
        issuer: Some("GitHub".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, snapshot_now()).expect("valid manual input");
    vault.add(validated.account);
    vault.save(&store).expect("commit added account");

    let state = decide_state_from_open(Instant::now(), path, Ok((vault, store)));

    let now_a = snapshot_now();
    let now_b = snapshot_now() + Duration::from_secs(5);

    let adapter_a = render_via_adapter(&state, now_a, 80, 12);
    let adapter_b = render_via_adapter(&state, now_b, 80, 12);
    let baseline_a = render_via_view(&state, now_a, 80, 12);
    let baseline_b = render_via_view(&state, now_b, 80, 12);

    assert_eq!(adapter_a, baseline_a, "adapter at now_a must match view");
    assert_eq!(adapter_b, baseline_b, "adapter at now_b must match view");
    assert_ne!(
        adapter_a, adapter_b,
        "advancing `now` by 5s must shift the TOTP gauge / seconds cell"
    );
}
