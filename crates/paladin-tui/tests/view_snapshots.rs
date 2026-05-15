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

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

use paladin_core::{
    format_unsafe_permissions, hotp_reveal_deadline, validate_manual, AccountInput,
    AccountKindInput, Algorithm, IconHintInput, PaladinError, PermissionSubject, Store, Vault,
    VaultInit, VaultLock,
};
use paladin_tui::app::state::{AppState, Focus, HotpReveal};
use paladin_tui::prompt::PassphraseBuffer;
use paladin_tui::view::render;
use secrecy::SecretString;

mod common;
use common::secure_test_tempdir;

/// Fixed wall-clock time threaded through every list-view snapshot so the
/// TOTP code / gauge / `seconds_remaining` cells stay deterministic across
/// hosts. `1_500_000_012 mod 30 == 12`, so for a 30-second TOTP window
/// the cursor sits 12 s in and 18 s remain — matching the
/// `DESIGN.md` §6 mock's `18s` and yielding a 6-of-10-cell gauge.
const SNAPSHOT_NOW_SECS: u64 = 1_500_000_012;

fn snapshot_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(SNAPSHOT_NOW_SECS)
}

/// Draw `state` into an `width × height` [`TestBackend`] and return
/// the resulting text grid (one line per row, cell symbols only). The
/// `now` parameter is forwarded to the list-view renderer so TOTP
/// rows compute against a deterministic wall-clock instead of the
/// host's real time.
fn render_to_text(state: &AppState, now: SystemTime, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create TestBackend terminal");
    terminal
        .draw(|frame| render(frame, state, now))
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
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
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
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
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
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

/// Create an empty plaintext vault at `path` and commit it to disk so a
/// subsequent `Store::open(_, VaultLock::Plaintext)` reopens an
/// `Unlocked`-able vault. Mirrors the helper in
/// `crates/paladin-tui/tests/effect_tests.rs` — duplicated locally
/// because integration-test crates do not share helper code.
fn create_plaintext_vault(path: &Path) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create vault");
    vault.save(&store).expect("commit initial vault");
}

#[test]
fn snapshot_list_view_empty() {
    // Plan L1711: "Empty vault list view." Construct an `Unlocked`
    // AppState backed by a freshly-created empty plaintext vault so
    // the renderer exercises the no-accounts branch (an empty rows
    // pane) while still drawing the surrounding chrome — title bar,
    // search line, separators, bottom keybinding hint — per
    // `DESIGN.md` §6's list-view layout.
    //
    // The vault path itself does not appear in the list view (per the
    // §6 mock), so the tempdir-backed path stays out of the rendered
    // snapshot grid and keeps the snapshot deterministic across hosts.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
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
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

/// Insert a single TOTP account into `vault` and commit it to `store`.
/// The Base32 secret, algorithm, digits, and 30-second window mirror the
/// CLI manual-add defaults so the rendered code/gauge/seconds tuple is a
/// pure function of [`SNAPSHOT_NOW_SECS`].
fn push_totp_account(
    vault: &mut Vault,
    store: &Store,
    issuer: Option<&str>,
    label: &str,
) -> paladin_core::AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, snapshot_now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

#[test]
fn snapshot_list_view_single_totp() {
    // Plan L1727: "Single-TOTP list view." Construct an `Unlocked`
    // AppState backed by a plaintext vault holding one TOTP account
    // (`GitHub (ben@example.com)`) so the renderer exercises the
    // populated-row branch: the selection marker, the issuer/label
    // pair, the formatted TOTP code, the period-progress gauge, and
    // the remaining-seconds suffix per `DESIGN.md` §6's list-view
    // mock.
    //
    // `snapshot_now()` is 12 s into a 30-s TOTP window so 18 s remain
    // and the gauge ends up 60% full — both values are encoded into
    // the snapshot, so a regression that mishandles the
    // `Code::seconds_remaining` math or the gauge ratio surfaces as
    // a diff in this file.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

/// Insert a single HOTP account at `counter` into `vault` and commit
/// it to `store`. Mirrors [`push_totp_account`] for the HOTP fan-out
/// of the list-view snapshots: the secret/algorithm/digits are
/// identical so the only behavioral delta is the kind discriminant
/// and the stored next counter.
fn push_hotp_account(
    vault: &mut Vault,
    store: &Store,
    issuer: Option<&str>,
    label: &str,
    counter: u64,
) -> paladin_core::AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Hotp,
        period_secs: None,
        counter: Some(counter),
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, snapshot_now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

#[test]
fn snapshot_list_view_mixed_totp_hotp_hidden_and_revealed() {
    // Plan L1762: "Mixed TOTP / HOTP list view with hidden + revealed
    // rows." Drive `view::list` against a vault whose insertion order
    // (TOTP, hidden HOTP, revealed HOTP) places one row of each
    // distinct shape onto the screen so the snapshot exercises every
    // branch of `render_rows` in a single grid:
    //
    //   * TOTP row: marker / title / code / progress gauge / remaining
    //     seconds (the same shape as `snapshot_list_view_single_totp`,
    //     but unselected so the marker column is blank).
    //   * Hidden HOTP row: title carries the *stored next* counter
    //     (`(#0)` here) and the right-side column shows the
    //     `▸ press n to advance` prompt. The renderer must not call
    //     into the OTP layer on this path — the snapshot would diff
    //     if a regression ever made it leak the next-counter code.
    //   * Revealed HOTP row: title carries `HotpReveal.counter_used`
    //     (the *pre-advance* counter that produced the visible code,
    //     `41` here while the stored next counter is `42`) and the
    //     right-side column shows the visible code from the reveal
    //     formatted by `format_code_digits` for parity with TOTP rows.
    //
    // The revealed HOTP is the selected row so the `▶` marker lands
    // on a HOTP row and a regression that ever stops painting
    // selection on HOTP rows surfaces as a diff in this snapshot.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let _totp_id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let _hidden_hotp_id = push_hotp_account(&mut vault, &store, Some("Bank"), "savings", 0);
    let revealed_hotp_id = push_hotp_account(&mut vault, &store, Some("VPN"), "work", 42);

    let reveal = HotpReveal {
        account_id: revealed_hotp_id,
        counter_used: 41,
        code: SecretString::from("654321".to_string()),
        // The reveal deadline is monotonic and only consulted by the
        // reducer's expiry tick — the renderer never reads it, so the
        // host-clock-derived `Instant::now()` cannot leak into the
        // rendered grid and the snapshot stays deterministic.
        deadline: hotp_reveal_deadline(Instant::now()),
    };

    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: Some(reveal),
        modal: None,
        selected: Some(revealed_hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

#[test]
fn snapshot_list_view_search_active() {
    // Plan L1781: "Search-active list view." Drive `view::list` against a
    // vault holding three accounts where only two match a non-empty
    // search query (`"git"`) so the snapshot pins two contracts:
    //
    //   * The `Search:` line carries the active query bytes verbatim
    //     so a regression that ever stops painting the query into the
    //     search bar surfaces as a diff.
    //   * `render_rows` honors the search-bar filter — only the
    //     matching accounts (`GitHub`, `GitLab`) appear in the rows
    //     pane; `Bank (savings)` is filtered out via
    //     [`paladin_core::account_matches_search`] (case-insensitive
    //     `"{issuer}:{label}"` substring match, the same predicate
    //     used by the reducer's incremental-search slice).
    //
    // The selected row is the first match (`GitHub`) so the `▶` marker
    // lands on a visible row — a regression that ever paints the
    // marker on a filtered-out row would surface as a diff. The
    // snapshot stays deterministic across hosts: the vault path itself
    // is not rendered on the list view, and TOTP codes/gauges/seconds
    // are pinned by `SNAPSHOT_NOW_SECS`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let github_id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let _gitlab_id = push_totp_account(&mut vault, &store, Some("GitLab"), "ben@example.com");
    let _bank_id = push_hotp_account(&mut vault, &store, Some("Bank"), "savings", 0);

    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: "git".to_string(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(github_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

#[test]
fn snapshot_list_view_after_zz_recenter() {
    // Plan L1806: "List view after a `zz` recenter (selected row in
    // viewport middle)." Drive `view::list` against a vault holding
    // twelve TOTP accounts (more than the 6-row rows pane in an
    // 80x12 terminal) with the selected row deep enough into the
    // list that a centered viewport requires a non-zero
    // `viewport_offset` — pinning that the renderer honors
    // `viewport_offset` to slice the visible window.
    //
    // `viewport_height = 6` matches the rows pane height with a
    // terminal height of 12; the 9th account (`Acct09 (u09)`,
    // insertion-order index 8) is selected; and `viewport_offset = 5`
    // is the value `recenter_viewport` would compute from
    // `sel_pos.saturating_sub(viewport_height / 2)` (`8 - 3 = 5`).
    // The snapshot therefore pins:
    //   * Only insertion-order indices `[5..=10]`
    //     (`Acct06`..`Acct11`) appear in the rows pane —
    //     `Acct01`..`Acct05` are scrolled past the top, `Acct12` is
    //     scrolled past the bottom.
    //   * The selected row (`Acct09`) lands at viewport row position
    //     3 (the 4th of 6 visible rows) so the `▶` marker sits in
    //     the middle of the viewport, matching vim's `zz` semantics.
    //
    // A regression that ever stops applying `viewport_offset` would
    // shift the visible window back to indices `[0..=5]`, leaving
    // the selected row off-screen and the marker absent — surfacing
    // as a diff in this snapshot.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let mut ids = Vec::with_capacity(12);
    for i in 1..=12u8 {
        let issuer = format!("Acct{i:02}");
        let label = format!("u{i:02}");
        ids.push(push_totp_account(
            &mut vault,
            &store,
            Some(issuer.as_str()),
            &label,
        ));
    }
    let selected_index: usize = 8;
    let viewport_height: u16 = 6;
    let viewport_offset: u16 =
        u16::try_from(selected_index).expect("index fits u16") - viewport_height / 2;
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(ids[selected_index]),
        pending_chord_leader: None,
        viewport_height,
        viewport_offset,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
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
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}
