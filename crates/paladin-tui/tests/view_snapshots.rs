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
    format_plaintext_export_warning, format_unsafe_permissions, format_validation_warning,
    hotp_reveal_deadline, validate_manual, AccountInput, AccountKindInput, Algorithm,
    IconHintInput, PaladinError, PermissionSubject, Store, ValidationWarning, Vault, VaultInit,
    VaultLock,
};
use paladin_tui::app::event::QrImportFailure;
use paladin_tui::app::state::{
    format_duplicate_account_message, format_qr_import_failure, render_error_message, AddModal,
    AddMode, AppState, CountsPanel, ExportFormat, ExportModal, Focus, HotpReveal, ImportModal,
    Modal, PassphraseModal, PassphraseSubFlow, RemoveModal, RenameModal, SettingsModal,
};
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
fn snapshot_add_modal_default() {
    // Plan L1835: "Add modal." Drive `view::render` against an
    // `Unlocked` state holding `Modal::Add(AddModal::default())` so
    // the snapshot pins the freshly-opened (Manual-mode, no inline
    // error, no pending duplicate-add, no counts panel) baseline of
    // the Add modal overlay rendered on top of the list view per
    // `DESIGN.md` §6's "modal dialogs for add / remove / rename /
    // import / export / passphrase / settings" call-out and the
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Add"
    // contract.
    //
    // The background vault is empty so the underlying list view
    // settles into its `No accounts. Press `a` to add one.`
    // prompt — the modal overlay's Clear-region then erases that
    // prompt where it would otherwise show through, and the
    // snapshot captures only the bordered list chrome
    // (top border + search + divider above, divider + hint + bottom
    // border below) framing the modal. Future slices land the URI /
    // QR modes, duplicate "add anyway" gate, and post-import counts
    // panel as their own snapshots.
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
        modal: Some(Modal::Add(AddModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_add_modal_save_not_committed() {
    // Plan L2121: "Add modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Add(AddModal { error: Some(render_error_message(
    // &PaladinError::SaveNotCommitted { .. })), .. })` so the snapshot
    // pins the inline-error row populated from a pre-commit save
    // failure per `DESIGN.md` §5's `save_not_committed` discriminator
    // and the `IMPLEMENTATION_PLAN_03_TUI.md` "Pre-commit effect
    // failures leave visible state unchanged and surface the typed
    // error through `render_error_message`" contract. Routing the
    // wording through the shared helper means the inline text matches
    // the rest of the TUI's error surface.
    //
    // The rest of the modal is at its default state (Manual mode,
    // empty fields) so the snapshot reads as a delta from the
    // `snapshot_add_modal_default` baseline: the inline error line
    // appears inside the spacer area between the icon-hint row and
    // the footer hint.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        error: Some(render_error_message(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // inline error field must fail this test even before the
    // human reads the snapshot diff.
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_save_durability_unconfirmed() {
    // Plan L2122: "Add modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        error: Some(render_error_message(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_no_clipboard_image() {
    // Plan L2447: "Add modal QR-import inline error: no clipboard
    // image." Drive `view::render` against an `Unlocked` state
    // holding `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::NoClipboardImage)),
    // .. })` so the snapshot pins the inline-error row populated
    // when `arboard::Clipboard::get_image()` reports the clipboard
    // does not hold an image — the no-image clipboard branch per
    // `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
    // §6) > Add": *"Scan a QR code from clipboard image bytes;
    // imported via the shared QR-decode path"*. The reducer's Err
    // arm (`reduce_qr_import_result` in `src/app/reducer.rs`) routes
    // the failure through `format_qr_import_failure` and parks the
    // wording on `AddModal::error` per the matching contract in
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Tests > Add modal": *"QR-
    // import inline errors (no clipboard image, image decode
    // failure, zero decoded QRs, oversized RGBA buffer, invalid QR
    // payload) surface inline and the modal stays open in
    // `AddMode::Qr`."*  The view-snapshot pins the post-reduce
    // rendering 1:1 with the reducer-side coverage from
    // `effect_result_qr_import_no_clipboard_image_sets_inline_error_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    //
    // Routing the wording through `format_qr_import_failure` binds
    // the snapshot to the shared TUI helper rather than a hand-typed
    // string so any future rewording of the "QR import failed:
    // clipboard does not contain an image …" prompt surfaces here as
    // a diff. The `AddMode::Qr` selector also pins the segmented
    // mode-selector row — a regression that ever wires the QR
    // failure result against the wrong `AddMode` surfaces as a diff
    // of the active mode wrapper (`▶ … ◀`).
    //
    // The rest of the modal is at its default state (empty Manual
    // field stack — the Add view currently paints the Manual field
    // column regardless of `AddMode`, with mode-specific rendering
    // landing alongside its own slice) so the snapshot reads as a
    // delta from `snapshot_add_modal_default` on two cells: the
    // active mode selector wraps `QR` instead of `Manual`, and the
    // inline-error row appears inside the spacer above the footer
    // hint via the same `render_inline_error` branch the Add modal's
    // `save_not_committed` / `save_durability_unconfirmed` slices
    // exercise.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(format_qr_import_failure(&QrImportFailure::NoClipboardImage)),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // QR-import failure must fail this test even before the human
    // reads the snapshot diff. Bind the assertion to the leading
    // `QR import failed: clipboard does not contain an image`
    // substring — the full message (with the `(copy a QR image
    // first).` parenthetical hint) exceeds the inline-error slot's
    // ~60-col width and is truncated by `Paragraph::new(Line::from(...))`
    // in `view/add.rs::render_inline_error`, mirroring the
    // truncation pin the plaintext-export-warning snapshot exercises.
    assert!(
        rendered.contains("QR import failed: clipboard does not contain an image"),
        "expected inline no-clipboard-image wording prefix to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_image_decode_failure() {
    // Plan L2448: "Add modal QR-import inline error: image decode
    // failure." Drive `view::render` against an `Unlocked` state
    // holding `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::ImageDecodeFailure)),
    // .. })` so the snapshot pins the inline-error row populated
    // when `arboard` returned an image but the bytes could not be
    // decoded as a usable raster — the malformed-raster branch per
    // the `QrImportFailure::ImageDecodeFailure` discriminator
    // documented in `crates/paladin-tui/src/app/event.rs`. The
    // reducer's Err arm (`reduce_qr_import_result` in
    // `src/app/reducer.rs`) routes the failure through
    // `format_qr_import_failure` and parks the wording on
    // `AddModal::error`. The view-snapshot pins the post-reduce
    // rendering 1:1 with the reducer-side coverage from
    // `effect_result_qr_import_image_decode_failure_sets_inline_error_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    //
    // Routing the wording through `format_qr_import_failure` binds
    // the snapshot to the shared TUI helper rather than a hand-typed
    // string so any future rewording of the "QR import failed:
    // clipboard image could not be decoded." prompt surfaces here as
    // a diff. The `ImageDecodeFailure` arm of
    // `format_qr_import_failure` returns a 56-char message that
    // fits the ~60-col inline-error slot without truncation, unlike
    // the longer `NoClipboardImage` companion slice — so this
    // snapshot doubles as a regression guard that the renderer
    // surfaces the full single-line message when it does fit.
    //
    // The rest of the modal is at its default state (Manual field
    // stack; `AddMode::Qr` selector) so the snapshot reads as a
    // delta from `snapshot_add_modal_qr_no_clipboard_image` on a
    // single cell: the inline-error wording.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(format_qr_import_failure(
            &QrImportFailure::ImageDecodeFailure,
        )),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = format_qr_import_failure(&QrImportFailure::ImageDecodeFailure);
    assert!(
        rendered.contains(&expected),
        "expected inline image-decode-failure wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_no_qrs_decoded() {
    // Plan L2449: "Add modal QR-import inline error: zero decoded
    // QRs." Drive `view::render` against an `Unlocked` state holding
    // `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::Import(
    //     PaladinError::NoEntriesToImport))), .. })` so the snapshot
    // pins the inline-error row populated when
    // `paladin_core::import::qr_image_bytes` decodes the clipboard
    // raster but finds zero QR payloads in it — the
    // `no_entries_to_import` discriminator per `DESIGN.md` §4.6 / §5.
    // The reducer's Err arm (`reduce_qr_import_result` in
    // `src/app/reducer.rs`) routes the failure through
    // `format_qr_import_failure`, whose `Import(err)` arm delegates
    // to `render_error_message` and binds the wording to the core
    // `Display` impl (`no entries to import`). The view-snapshot
    // pins the post-reduce rendering 1:1 with the reducer-side
    // coverage from
    // `effect_result_qr_import_no_qrs_decoded_sets_inline_error_via_render_error_message`
    // in `tests/reducer_tests.rs`.
    //
    // Routing through `format_qr_import_failure` (rather than
    // `render_error_message` directly) pins that the QR-failure
    // pipeline's `Import` arm continues to forward `PaladinError`
    // wording verbatim — a regression that ever wraps the core
    // wording in a "QR import failed:" prefix on this arm surfaces
    // here as a diff, distinguishing it from the bespoke
    // `NoClipboardImage` and `ImageDecodeFailure` arms above. The
    // 20-char core wording fits the ~60-col inline-error slot
    // without truncation.
    //
    // The rest of the modal is at its default state (Manual field
    // stack; `AddMode::Qr` selector) so the snapshot reads as a
    // delta from `snapshot_add_modal_qr_image_decode_failure` on a
    // single cell: the inline-error wording.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(format_qr_import_failure(&QrImportFailure::Import(
            PaladinError::NoEntriesToImport,
        ))),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected =
        format_qr_import_failure(&QrImportFailure::Import(PaladinError::NoEntriesToImport));
    assert!(
        rendered.contains(&expected),
        "expected inline no-entries-to-import wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_oversized_rgba_buffer() {
    // Plan L2450: "Add modal QR-import inline error: oversized raw
    // RGBA buffer." Drive `view::render` against an `Unlocked` state
    // holding `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::Import(
    //     paladin_core::import::qr_image_bytes(5000, 5000, &[], _)
    //         .expect_err(...)))), .. })` so the snapshot pins the
    // inline-error row populated when
    // `paladin_core::import::qr_image_bytes` rejects oversized RGBA
    // buffers (dimensions whose `width * height * 4` exceeds
    // `paladin_core::QR_RGBA_MAX_BYTES`) with `validation_error
    // { field: "qr_image", reason: "image_too_large" }` per
    // `DESIGN.md` §4.6. Routing through the real `qr_image_bytes`
    // call rather than constructing the error directly binds the
    // snapshot to the public API contract — the reducer-side
    // fixture
    // (`effect_result_qr_import_oversized_rgba_buffer_sets_inline_error_via_render_error_message`
    // in `tests/reducer_tests.rs`) uses the same trigger so the
    // view-snapshot matrix stays 1:1 with the reducer matrix.
    //
    // Routing the wording through `format_qr_import_failure`'s
    // `Import(err)` arm — which delegates to `render_error_message`
    // and binds to the core `Display` impl (`validation error:
    // qr_image: image_too_large`) — pins that this arm forwards
    // `PaladinError` wording verbatim without a "QR import failed:"
    // prefix, matching the `NoEntriesToImport` companion slice. The
    // 43-char core wording fits the ~60-col inline-error slot
    // without truncation.
    //
    // The rest of the modal is at its default state (Manual field
    // stack; `AddMode::Qr` selector) so the snapshot reads as a
    // delta from `snapshot_add_modal_qr_no_qrs_decoded` on a single
    // cell: the inline-error wording.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let oversized_side: u32 = 5000;
    let core_err =
        paladin_core::import::qr_image_bytes(oversized_side, oversized_side, &[], snapshot_now())
            .expect_err("oversized RGBA dimensions must reject");
    let expected = format_qr_import_failure(&QrImportFailure::Import(core_err));
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(expected.clone()),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains(&expected),
        "expected inline oversized-rgba wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_invalid_qr_payload() {
    // Plan L2615: "Add modal QR-import inline error: invalid QR
    // payload." Drive `view::render` against an `Unlocked` state
    // holding `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::Import(
    //     PaladinError::ValidationError { field: "qr_image", reason:
    //     "non_otpauth_payload", source_index: Some(0), .. }))), .. })`
    // so the snapshot pins the inline-error row populated when
    // `paladin_core::import::qr_image_bytes` decodes a QR whose
    // payload is not an `otpauth://` URI — the `non_otpauth_payload`
    // discriminator emitted by `payloads_to_accounts` per `DESIGN.md`
    // §4.6 / §5 (see `crates/paladin-core/src/import/qr.rs:87`).
    // The reducer's Err arm (`reduce_qr_import_result` in
    // `src/app/reducer.rs`) routes the failure through
    // `format_qr_import_failure`, whose `Import(err)` arm delegates
    // to `render_error_message` and binds the wording to the core
    // `Display` impl (`validation error: qr_image: non_otpauth_payload`).
    // The view-snapshot pins the post-reduce rendering 1:1 with the
    // reducer-side coverage from
    // `effect_result_qr_import_invalid_qr_payload_sets_inline_error_via_render_error_message`
    // in `tests/reducer_tests.rs`.
    //
    // Routing the wording through `format_qr_import_failure`'s
    // `Import(err)` arm — which delegates to `render_error_message`
    // and binds to the core `Display` impl — pins that this arm
    // forwards `PaladinError` wording verbatim without a "QR import
    // failed:" prefix, matching the `NoEntriesToImport` and
    // oversized-RGBA companion slices. Constructing the
    // `ValidationError` variant directly (rather than driving a real
    // non-otpauth QR through `qr_image_bytes`) keeps the snapshot
    // self-contained — the field / reason codes are stable per
    // `DESIGN.md` §5, and `crates/paladin-core/tests/import_qr.rs`'s
    // `qr_image_bytes_with_non_otpauth_payload_rejects_with_source_index`
    // already binds the real-API path. The 47-char core wording fits
    // the ~60-col inline-error slot without truncation.
    //
    // `source_index: Some(0)` mirrors the value `payloads_to_accounts`
    // tags on the first offending payload; the `Display` impl ignores
    // the field, so this slot is locked here to document the
    // attribution rather than influence the rendered text.
    //
    // The rest of the modal is at its default state (Manual field
    // stack; `AddMode::Qr` selector) so the snapshot reads as a
    // delta from `snapshot_add_modal_qr_oversized_rgba_buffer` on a
    // single cell: the inline-error wording.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let core_err = PaladinError::ValidationError {
        field: "qr_image",
        reason: "non_otpauth_payload".to_string(),
        source_index: Some(0),
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    };
    let expected = format_qr_import_failure(&QrImportFailure::Import(core_err));
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(expected.clone()),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains(&expected),
        "expected inline non-otpauth-payload wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_counts_panel() {
    // Plan L2616: "Add modal post-QR-import counts panel." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Add(AddModal { mode: AddMode::Qr, counts_panel:
    // Some(CountsPanel { imported, skipped, replaced: 0, appended: 0,
    // warnings: vec![] }), .. })` so the snapshot pins the post-success
    // summary panel — the four `ImportReport` merge totals the reducer
    // seeds from `paladin_core::ImportReport` per `DESIGN.md` §6's
    // "The modal reports imported/skipped/replaced/appended/warning
    // counts plus validation-warning messages rendered through
    // `paladin_core::format_validation_warning()` in a post-success
    // counts panel" contract and the `IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Add" checklist row: *"Clipboard QR import
    // uses `ImportConflict::Skip` and reports imported / skipped
    // counts."*
    //
    // Per `AddModal::counts_panel` and the [`CountsPanel`] doc, the
    // clipboard-QR flow always runs with [`ImportConflict::Skip`], so
    // `replaced` and `appended` are always `0` on this path; only
    // `imported` and `skipped` carry meaningful counts. The snapshot
    // still pins all four rows so the layout matches the Import modal's
    // counts panel — which means a regression that ever hides the
    // always-zero rows for the QR-add path (or paints a different
    // label) surfaces as a diff. The `warnings` slot is empty here; the
    // warnings-included variant lands in its own snapshot per the
    // plan's "QR-add counts panel with validation-warning messages"
    // checklist row at L2619.
    //
    // The carried counts (imported: 2, skipped: 1) are distinct from
    // the Import modal's no-warnings (3 / 1 / 2 / 4) and warnings
    // (2 / 0 / 0 / 0) snapshots so the three counts-panel snapshots
    // read as deltas across the three flows; a regression that ever
    // swaps two counts surfaces as a diff rather than staying silent
    // under identical values.
    //
    // Background vault is empty so the underlying list view paints
    // its `(no accounts yet)` empty-state row through the modal's
    // clipped border, mirroring the other Add modal snapshots.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        counts_panel: Some(CountsPanel {
            imported: 2,
            skipped: 1,
            replaced: 0,
            appended: 0,
            warnings: Vec::new(),
        }),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("Imported:") && rendered.contains('2'),
        "expected 'Imported:' row with count 2 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Skipped:") && rendered.contains('1'),
        "expected 'Skipped:' row with count 1 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Replaced:") && rendered.contains('0'),
        "expected 'Replaced:' row with count 0 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Appended:"),
        "expected 'Appended:' row to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Enter or Esc to close"),
        "expected post-success hint to appear in counts panel:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_duplicate_account() {
    // Plan L2702: "Add modal `duplicate_account`." Drive `view::render`
    // against an `Unlocked` state holding
    // `Modal::Add(AddModal { error: Some(format_duplicate_account_message(
    // &existing_summary)), .. })` so the snapshot pins the inline-error
    // row populated when `paladin_core::Vault::find_duplicate` matches
    // an existing entry on the `(secret, issuer, label)` triple. Per
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Add":
    // *"manual and URI duplicate collisions call
    // `Vault::find_duplicate(&validated)` before mutation. A collision
    // initially rejects with the existing account in the modal and
    // offers an 'add anyway' confirmation."*
    //
    // Routing the wording through `format_duplicate_account_message`
    // pins the shared TUI renderer — the same one the reducer's
    // `AddFailure::Duplicate` arm wires into `AddModal::error` per
    // `effect_result_add_duplicate_stashes_pending_and_sets_inline_error`
    // in `tests/reducer_tests.rs` — and binds the snapshot to the
    // function's `"account already exists with the same (secret,
    // issuer, label): {} (press Enter to add anyway)"` template. Any
    // future wording change in the shared formatter surfaces as a
    // diff here.
    //
    // The vault holds a single TOTP account labelled `github` (no
    // issuer) so `format_account_display_label` returns the bare
    // `github` form — the same shape exercised by the reducer-side
    // test cited above — keeping the snapshot self-contained and
    // independent of any specific `Vault::find_duplicate` invocation.
    // `pending_duplicate_add` is intentionally left `None`: only the
    // `error` slot reaches the renderer (see
    // `crates/paladin-tui/src/view/add.rs:167`), and a follow-up "add
    // anyway" confirmation snapshot lands as its own plan checklist
    // row.
    //
    // The Manual mode keeps this as a sibling delta to
    // `snapshot_add_modal_save_not_committed` /
    // `snapshot_add_modal_save_durability_unconfirmed`: same field
    // stack, same footer hint, only the inline-error row changes —
    // a regression that ever swaps the duplicate wording for one of
    // the save-failure templates surfaces as a diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let existing_id = push_totp_account(&mut vault, &store, None, "github");
    let existing_summary = vault
        .iter()
        .find(|a| a.id() == existing_id)
        .expect("existing account must be present in vault")
        .summary();
    let expected = format_duplicate_account_message(&existing_summary);
    let modal = AddModal {
        error: Some(expected.clone()),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: Some(existing_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // duplicate rejection must fail this test even before the human
    // reads the snapshot diff. Bind the assertion to the leading
    // `account already exists with the same (secret, issuer, label)`
    // substring — the full message (with the `: github (press Enter
    // to add anyway)` tail) exceeds the inline-error slot's ~60-col
    // width and is truncated by `Paragraph::new(Line::from(...))` in
    // `view/add.rs::render_inline_error`, mirroring the truncation
    // pin the `snapshot_add_modal_qr_no_clipboard_image` snapshot
    // exercises.
    assert!(
        rendered.contains("account already exists with the same (secret, issuer, label)"),
        "expected leading duplicate_account wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_remove_modal_default() {
    // Plan L1856: "Remove modal." Drive `view::render` against an
    // `Unlocked` state with one TOTP account and
    // `Modal::Remove(RemoveModal { account_id, error: None })` open
    // so the snapshot pins the freshly-opened (no inline save-error,
    // populated `account_id`) baseline of the Remove confirmation
    // modal overlay rendered on top of the list view per `DESIGN.md`
    // §6's "modal dialogs for add / remove / rename / import /
    // export / passphrase / settings" call-out and the
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Remove"
    // contract — *"confirmation modal. On confirm, wraps
    // `Vault::remove` in `Vault::mutate_and_save`."*
    //
    // The single account uses the same `GitHub` / `ben@example.com`
    // issuer/label pair the single-TOTP list-view snapshot uses, so
    // the `issuer:label` line painted inside the modal exercises the
    // shared `format_account_display_label` rendering (identical
    // wording to the duplicate-account inline error and the CLI's
    // `display_label`). A future slice that re-wires the modal to a
    // different display format then surfaces as a diff in this file.
    // The inline `error` slot stays `None`; the
    // `save_not_committed` / `save_durability_unconfirmed` variants
    // land as their own snapshots per the plan's later checkboxes.
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
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_remove_modal_save_not_committed() {
    // Plan L2140: "Remove modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Remove(RemoveModal { account_id, error: Some(
    // render_error_message(&PaladinError::SaveNotCommitted { .. })) })`
    // so the snapshot pins the inline-error row populated from a
    // pre-commit save failure per `DESIGN.md` §5's
    // `save_not_committed` discriminator and the
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Pre-commit save rollback >
    // Remove modal: same coverage as Add, asserted on `Vault::iter()`"
    // contract. Routing the wording through the shared
    // `render_error_message` helper means the inline text matches
    // the rest of the TUI's error surface.
    //
    // The rest of the modal is at its default state (single TOTP
    // account, `GitHub` / `ben@example.com`) so the snapshot reads
    // as a delta from the `snapshot_remove_modal_default` baseline:
    // the inline error line appears inside the spacer area between
    // the account-label row and the footer hint.
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
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // inline error field must fail this test even before the
    // human reads the snapshot diff.
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_remove_modal_save_durability_unconfirmed() {
    // Plan L2141: "Remove modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
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
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_rename_modal_default() {
    // Plan L1885: "Rename modal." Drive `view::render` against an
    // `Unlocked` state with one TOTP account and
    // `Modal::Rename(RenameModal { account_id, draft, error: None })`
    // open so the snapshot pins the freshly-opened (draft pre-populated
    // with the selected account's current label, no inline save / validation
    // error) baseline of the Rename modal overlay rendered on top of the
    // list view per `DESIGN.md` §6's "modal dialogs for add / remove /
    // rename / import / export / passphrase / settings" call-out and the
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Rename"
    // contract — *"single text field pre-populated with the selected
    // account's current label."*
    //
    // The single account uses the same `GitHub` / `ben@example.com`
    // issuer/label pair the Remove modal snapshot uses, so the
    // `issuer:label` line painted inside the modal exercises the
    // shared `format_account_display_label` rendering (identical
    // wording to the duplicate-account inline error and the CLI's
    // `display_label`). The `draft` is seeded with the account's
    // current label so the snapshot pins that the renderer prefills
    // the editable text-input from the reducer's modal-open path.
    // The inline `error` slot stays `None`; the `save_not_committed`
    // / `save_durability_unconfirmed` variants land as their own
    // snapshots per the plan's later checkboxes.
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
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: "ben@example.com".to_string(),
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_rename_modal_save_not_committed() {
    // Plan L2159: "Rename modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Rename(RenameModal { account_id, draft, error: Some(
    // render_error_message(&PaladinError::SaveNotCommitted { .. })) })`
    // so the snapshot pins the inline-error row populated from a
    // pre-commit save failure per `DESIGN.md` §5's
    // `save_not_committed` discriminator. Routing the wording
    // through the shared `render_error_message` helper means the
    // inline text matches the rest of the TUI's error surface — the
    // unlock screen's `decrypt_failed` line, the Add modal's
    // inline-error slot, and the Remove modal's inline-error slot.
    //
    // The rest of the modal is at its default state (single TOTP
    // account, `GitHub` / `ben@example.com`, draft prefilled with
    // the current label) so the snapshot reads as a delta from the
    // `snapshot_rename_modal_default` baseline: the inline error
    // line appears inside the spacer area between the draft field
    // and the footer hint.
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
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: "ben@example.com".to_string(),
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // inline error field must fail this test even before the
    // human reads the snapshot diff.
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_rename_modal_save_durability_unconfirmed() {
    // Plan L2160: "Rename modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
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
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: "ben@example.com".to_string(),
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_default() {
    // Plan L1886: "Import modal." Drive `view::render` against an
    // `Unlocked` state with `Modal::Import(ImportModal::default())`
    // open so the snapshot pins the freshly-opened (empty
    // `path_text`, `Auto` format selector, `Skip` on-conflict policy,
    // no inline error, no encrypted-Paladin passphrase sub-phase, no
    // post-success counts panel) baseline of the Import modal overlay
    // rendered on top of the list view per `DESIGN.md` §6's "Import
    // takes a file path and optional explicit format … applies a
    // user-selected on-conflict policy (skip / replace / append), and
    // reports imported/skipped/replaced/appended/warning counts"
    // contract and the `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
    // §6) > Import" checklist row.
    //
    // The background vault is empty so the underlying list view
    // settles into its `No accounts. Press `a` to add one.` prompt
    // — the modal overlay's Clear-region then erases that prompt
    // where it would otherwise show through, and the snapshot
    // captures only the bordered list chrome (top border + search +
    // divider above, divider + hint + bottom border below) framing
    // the modal. The `Source:` field renders as the editable
    // `[ ... ]` text-input style mirroring the Add / Rename modals'
    // editable rows; the `Format:` selector renders as the segmented
    // `▶ Auto ◀  Otpauth  Aegis  Paladin  QR` line mirroring the Add
    // modal's mode selector so a regression that ever swaps the
    // active variant or stops painting the segmented selector
    // surfaces as a diff; the `On conflict:` selector renders the
    // same way over the three `ImportConflict` variants. Future
    // slices land the inline-error / passphrase sub-phase / counts
    // panel variants as their own snapshots per the plan's later
    // checkboxes.
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
        modal: Some(Modal::Import(ImportModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_import_modal_save_not_committed() {
    // Plan L2161: "Import modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Import(ImportModal { error: Some(render_error_message(
    // &PaladinError::SaveNotCommitted { .. })), .. })` so the
    // snapshot pins the inline-error row populated from a pre-commit
    // save failure per `DESIGN.md` §5's `save_not_committed`
    // discriminator. Routing the wording through the shared
    // `render_error_message` helper means the inline text matches
    // the rest of the TUI's error surface — the unlock screen's
    // `decrypt_failed` line and the Add / Remove / Rename modals'
    // inline-error slots.
    //
    // Every other ImportModal field stays at its default
    // (empty `path_text`, `Auto` format, `Skip` conflict, no
    // passphrase sub-phase, no counts panel) so the snapshot reads
    // as a delta from the `snapshot_import_modal_default` baseline:
    // the inline error line appears inside the spacer area between
    // the conflict-selector row and the footer hint.
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
        modal: Some(Modal::Import(ImportModal {
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_save_durability_unconfirmed() {
    // Plan L2162: "Import modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
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
        modal: Some(Modal::Import(ImportModal {
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

/// Render the Import modal overlay against a fresh `Unlocked` state
/// with the supplied `PaladinError` pre-rendered into
/// `ImportModal::error` via `render_error_message`, and return the
/// resulting text grid.
///
/// Mirrors the `snapshot_import_modal_save_not_committed` /
/// `snapshot_import_modal_save_durability_unconfirmed` setups so the
/// per-importer-error-kind snapshots below read as deltas from the
/// `snapshot_import_modal_default` baseline. The `expected_substring`
/// argument doubles as a guard that the rendered grid does carry the
/// rendered error wording before the snapshot lands — a regression
/// that ever drops the inline error or strips the rendered wording
/// surfaces as the assertion message rather than a silent snapshot
/// diff.
fn render_import_modal_with_inline_error(err: &PaladinError, expected_substring: &str) -> String {
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
        modal: Some(Modal::Import(ImportModal {
            error: Some(render_error_message(err)),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains(expected_substring),
        "expected inline error substring {expected_substring:?} to appear in modal:\n{rendered}"
    );
    rendered
}

// ---------------------------------------------------------------------------
// Import modal — per-importer-error-kind inline rendering
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Insta snapshots:
//  *"Import modal with each importer error kind."*)
//
// One snapshot per `PaladinError` variant the reducer's
// `reduce_import_result` Err arm surfaces. Each pins the
// `render_error_message`-formatted wording inside the spacer area
// between the conflict-selector row and the footer hint, mirroring
// the pre-commit / durability-unconfirmed snapshots above. The set
// of variants matches the plan's "Importer errors" list (L1079–1084)
// and the reducer tests'
// `effect_result_import_err_*_renders_inline` coverage in
// `tests/reducer_tests.rs` — keeping the view-snapshot matrix
// 1:1 with the reducer matrix so a regression that ever changes
// the rendered wording for one kind surfaces here as a diff.
// ---------------------------------------------------------------------------

#[test]
fn snapshot_import_modal_unsupported_import_format() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedImportFormat {
            format: "unknown".to_string(),
        },
        "unsupported import format",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_unsupported_plaintext_vault() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedPlaintextVault,
        "Paladin import bundle is plaintext",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_unsupported_encrypted_aegis() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedEncryptedAegis,
        "Aegis encrypted backups are not supported",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_unsupported_aegis_entry_type() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedAegisEntryType {
            source_index: 2,
            entry_type: "steam".to_string(),
        },
        "Aegis entry type",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_validation_error() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::ValidationError {
            field: "secret",
            reason: "bad_base32".to_string(),
            source_index: Some(0),
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        },
        "validation error",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_no_entries_to_import() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::NoEntriesToImport,
        "no entries to import",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_decrypt_failed() {
    let rendered =
        render_import_modal_with_inline_error(&PaladinError::DecryptFailed, "decryption failed");
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_invalid_header() {
    let rendered =
        render_import_modal_with_inline_error(&PaladinError::InvalidHeader, "invalid vault header");
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_invalid_payload() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::InvalidPayload {
            reason: "decode_failed",
        },
        "invalid vault payload",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_unsupported_format_version() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedFormatVersion { format_ver: 99 },
        "unsupported vault format version",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_kdf_params_out_of_bounds() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::KdfParamsOutOfBounds {
            m_kib: 1,
            t: 0,
            p: 0,
        },
        "Argon2 KDF parameters out of bounds",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_io_error() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::IoError {
            operation: "read_import_file",
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        },
        "I/O error during read_import_file",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_counts_panel() {
    // Plan L2300: "Import modal post-import counts panel." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Import(ImportModal { counts_panel: Some(CountsPanel {
    // imported, skipped, replaced, appended, warnings: vec![] }), .. })`
    // so the snapshot pins the post-success summary panel — the four
    // `ImportReport` merge totals (`imported`/`skipped`/`replaced`/
    // `appended`) the reducer seeds from
    // `paladin_core::ImportReport` per `DESIGN.md` §6's "The modal
    // reports imported/skipped/replaced/appended/warning counts plus
    // validation-warning messages rendered through
    // `paladin_core::format_validation_warning()` in a post-success
    // counts panel" contract and the `IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Import" checklist row.
    //
    // Every other ImportModal field stays at its default (empty
    // `path_text`, `Auto` format, `Skip` conflict, no inline error,
    // no passphrase sub-phase) so the snapshot reads as a delta from
    // the `snapshot_import_modal_default` baseline: the input rows
    // (Source / Format / On conflict / hint) are replaced with the
    // counts summary panel. The `warnings` slot is empty here; the
    // warnings-included variant lands in its own snapshot per the
    // plan's next checklist row.
    //
    // The carried counts are deliberately distinct (3 / 1 / 2 / 4)
    // so the snapshot pins each field to its slot — a regression
    // that ever swaps two counts surfaces as a diff rather than
    // staying silent under identical values.
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
        modal: Some(Modal::Import(ImportModal {
            counts_panel: Some(CountsPanel {
                imported: 3,
                skipped: 1,
                replaced: 2,
                appended: 4,
                warnings: Vec::new(),
            }),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("Imported:") && rendered.contains('3'),
        "expected 'Imported:' row with count 3 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Skipped:") && rendered.contains('1'),
        "expected 'Skipped:' row with count 1 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Replaced:") && rendered.contains('2'),
        "expected 'Replaced:' row with count 2 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Appended:") && rendered.contains('4'),
        "expected 'Appended:' row with count 4 to appear in counts panel:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_counts_panel_with_validation_warnings() {
    // Plan L2323: "Import counts panel with validation-warning messages."
    // Drive `view::render` against an `Unlocked` state holding
    // `Modal::Import(ImportModal { counts_panel: Some(CountsPanel {
    // ..., warnings: vec![...] }), .. })` so the snapshot pins the
    // post-success counts panel rendering each
    // `paladin_core::ImportWarning` through
    // `paladin_core::format_validation_warning()` per `DESIGN.md` §6's
    // "The modal reports imported/skipped/replaced/appended/warning
    // counts plus validation-warning messages rendered through
    // `paladin_core::format_validation_warning()` in a post-success
    // counts panel" contract. The reducer's `reduce_import_result` Ok
    // arm seeds `CountsPanel::warnings` from
    // `ImportReport::warnings.iter().map(format_validation_warning)`,
    // so the warnings strings flow through the same helper here —
    // binding the snapshot to the core wording rather than a
    // hand-typed string keeps the rendered text in sync with the core
    // library if the warning phrasing is ever revised.
    //
    // Two warnings with distinct `decoded_len` values (5, 1) so a
    // regression that ever swaps two warnings or collapses them onto
    // a single line surfaces as a diff rather than staying silent
    // under identical values. The remaining counts (`imported: 2`) are
    // distinct from the no-warnings snapshot so the two snapshots read
    // as deltas of the same panel and a future renderer change that
    // hides the counts in the presence of warnings is caught.
    let warning_short = format_validation_warning(&ValidationWarning::ShortSecret {
        decoded_len: 5,
        recommended_min: 16,
    });
    let warning_shortest = format_validation_warning(&ValidationWarning::ShortSecret {
        decoded_len: 1,
        recommended_min: 16,
    });

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
        modal: Some(Modal::Import(ImportModal {
            counts_panel: Some(CountsPanel {
                imported: 2,
                skipped: 0,
                replaced: 0,
                appended: 0,
                warnings: vec![warning_short.clone(), warning_shortest.clone()],
            }),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 22);
    assert!(
        rendered.contains("decoded length 5 bytes"),
        "expected first warning's decoded_len text in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("decoded length 1 bytes"),
        "expected second warning's decoded_len text in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Imported:") && rendered.contains('2'),
        "expected 'Imported:' row with count 2 to remain visible above warnings:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_default() {
    // Plan L1887: "Export modal." Drive `view::render` against an
    // `Unlocked` state with `Modal::Export(ExportModal::default())`
    // open so the snapshot pins the freshly-opened (empty
    // `path_text`, `ExportFormat::Plaintext` format selector, empty
    // twice-confirm passphrase buffers, `plaintext_confirmed: false`
    // acknowledgement gate, no inline error) baseline of the Export
    // modal overlay rendered on top of the list view per `DESIGN.md`
    // §6's "Export writes either the plaintext `otpauth://` JSON list
    // (with an explicit unencrypted-secrets warning before the write)
    // or an encrypted Paladin bundle (passphrase prompted twice and
    // matched), refuses overwrite without explicit confirmation"
    // contract and the `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
    // §6) > Export" checklist row.
    //
    // The background vault is empty so the underlying list view
    // settles into its `No accounts. Press `a` to add one.` prompt
    // — the modal overlay's Clear-region then erases that prompt
    // where it would otherwise show through. The `Destination:` field
    // renders as the editable `[ ... ]` text-input style mirroring
    // the Add / Rename / Import modals' editable rows; the `Format:`
    // selector renders as the segmented `▶ Plaintext ◀  Encrypted`
    // line mirroring the Add / Import modals' segmented selectors so
    // a regression that ever swaps the active variant or stops
    // painting the segmented selector surfaces as a diff; the
    // plaintext-export warning rendering and the `[ ]` /
    // `[x]` acknowledgement gate land in their own dedicated
    // snapshot slices below (plan L1996 "Export modal plaintext-
    // export warning."). Inline `confirmation_mismatch` /
    // `zero_length` / refused-overwrite / writer-failure /
    // `save_not_committed` / `save_durability_unconfirmed` variants
    // land as their own snapshots per the plan's later checkboxes.
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
        modal: Some(Modal::Export(ExportModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_export_modal_refused_overwrite_gate() {
    // Plan L2360: "Export modal refused overwrite gate." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { error: Some(render_error_message(
    // &PaladinError::ValidationError { field: "path",
    // reason: "output_exists".to_string(), .. })), .. })` open so the
    // snapshot pins the inline-error row populated from the
    // refused-overwrite gate per `IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Export": *"Overwriting an existing file is
    // rejected unless the user confirms an inline overwrite gate
    // (parity with CLI `--force`)."* Routing the wording through
    // `render_error_message` binds the snapshot to the core
    // `PaladinError::ValidationError` `Display` impl
    // (`validation error: path: output_exists`) rather than a
    // hand-typed string so any future wording change in core surfaces
    // here as a diff.
    //
    // The rest of the modal is at its default state (empty
    // `path_text`, `ExportFormat::Plaintext`, empty passphrase
    // buffers, `plaintext_confirmed: false`) so the snapshot reads as
    // a delta from the `snapshot_export_modal_default` baseline: the
    // inline error line appears inside the spacer area between the
    // segmented `Format:` selector row and the footer hint, mirroring
    // the Add / Remove / Rename modals' inline-error slots and the
    // unlock screen's `decrypt_failed` styling so every inline-error
    // surface in the TUI reads the same way.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = ExportModal {
        error: Some(render_error_message(&PaladinError::ValidationError {
            field: "path",
            reason: "output_exists".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        })),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // refused-overwrite gate's inline error must fail this test even
    // before the human reads the snapshot diff. Binds the assertion
    // to the core `Display` wording rather than a hand-typed string.
    let expected = render_error_message(&PaladinError::ValidationError {
        field: "path",
        reason: "output_exists".to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    });
    assert!(
        rendered.contains(&expected),
        "expected inline refused-overwrite wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_confirmation_mismatch() {
    // Plan L2361: "Export modal `confirmation_mismatch`." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { format: ExportFormat::Encrypted,
    // error: Some(render_error_message(&PaladinError::InvalidPassphrase
    // { reason: "confirmation_mismatch" })), .. })` open so the
    // snapshot pins the inline-error row populated from the encrypted
    // twice-confirm passphrase mismatch gate per
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Export":
    // *"Encrypted exports prompt twice for the bundle passphrase ..."*
    // Mismatch surfaces a rendered `PaladinError::InvalidPassphrase`
    // with `reason: "confirmation_mismatch"` per DESIGN.md §5,
    // matching the CLI's `prompt_new_passphrase` and the GTK
    // `SubmitRejection::ConfirmationMismatch` wire code. Routing the
    // wording through `render_error_message` binds the snapshot to the
    // core `Display` impl (`invalid passphrase: confirmation_mismatch`)
    // rather than a hand-typed string so any future wording change in
    // core surfaces here as a diff.
    //
    // The format selector reads `Encrypted` so the snapshot reads as
    // an encrypted-path delta from the `snapshot_export_modal_default`
    // baseline — the inline error line appears inside the spacer area
    // between the segmented `Format:` selector row and the footer
    // hint, mirroring the unlock screen's `decrypt_failed` styling and
    // the Add / Remove / Rename modals' inline-error slots. The
    // refused-overwrite gate's snapshot above already exercises the
    // `Plaintext` selector with the same renderer.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = ExportModal {
        format: ExportFormat::Encrypted,
        error: Some(render_error_message(&PaladinError::InvalidPassphrase {
            reason: "confirmation_mismatch",
        })),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::InvalidPassphrase {
        reason: "confirmation_mismatch",
    });
    assert!(
        rendered.contains(&expected),
        "expected inline confirmation_mismatch wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_zero_length() {
    // Plan L2388: "Export modal `zero_length`." Drive `view::render`
    // against an `Unlocked` state with
    // `Modal::Export(ExportModal { format: ExportFormat::Encrypted,
    // error: Some(render_error_message(&PaladinError::InvalidPassphrase
    // { reason: "zero_length" })), .. })` open so the snapshot pins the
    // inline-error row populated from the encrypted twice-confirm
    // empty-passphrase gate per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals
    // (per §6) > Export": *"Encrypted exports prompt twice for the
    // bundle passphrase and reject mismatch with inline
    // `invalid_passphrase` (`reason: "confirmation_mismatch"`) or
    // empty entry with `reason: "zero_length"`."*. When the encrypted
    // path is selected and both prompts are blank (so the mismatch
    // gate passes by both buffers being equal), the reducer surfaces
    // a rendered `PaladinError::InvalidPassphrase` with
    // `reason: "zero_length"` per DESIGN.md §5, matching the CLI's
    // `prompt_new_passphrase` (mismatch first, then `zero_length`) and
    // the GTK `SubmitRejection::ZeroLength` wire code so the
    // user-facing reason stays stable across all three front-ends.
    // Routing the wording through `render_error_message` binds the
    // snapshot to the core `Display` impl
    // (`invalid passphrase: zero_length`) rather than a hand-typed
    // string so any future wording change in core surfaces here as a
    // diff.
    //
    // The format selector reads `Encrypted` so the snapshot reads as
    // an encrypted-path delta from the `snapshot_export_modal_default`
    // baseline — the inline error line appears inside the spacer area
    // between the segmented `Format:` selector row and the footer
    // hint, sharing the same renderer branch the
    // `confirmation_mismatch` snapshot above exercises. The
    // refused-overwrite gate's snapshot already exercises the
    // `Plaintext` selector with the same renderer.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = ExportModal {
        format: ExportFormat::Encrypted,
        error: Some(render_error_message(&PaladinError::InvalidPassphrase {
            reason: "zero_length",
        })),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::InvalidPassphrase {
        reason: "zero_length",
    });
    assert!(
        rendered.contains(&expected),
        "expected inline zero_length wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_plaintext_export_warning() {
    // Plan L2389: "Export modal plaintext-export warning." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { format: ExportFormat::Plaintext,
    // error: Some(format_plaintext_export_warning()),
    // plaintext_confirmed: false, .. })` open so the snapshot pins the
    // inline-error row populated from the plaintext unencrypted-secrets
    // acknowledgement gate per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals
    // (per §6) > Export": *"Plaintext exports render
    // `paladin_core::format_plaintext_export_warning()` verbatim and
    // the user must confirm before the write proceeds."*. Routing the
    // wording through `paladin_core::format_plaintext_export_warning`
    // binds the snapshot to the core helper rather than a hand-typed
    // string so wording stays in lockstep with the CLI's stderr
    // advisory (`paladin-cli/src/commands/export.rs`, DESIGN.md §4.6 /
    // §6) and the GTK `ExportDialog`'s `plaintext_warning_body()`
    // checkbox label — any future wording change in core surfaces here
    // as a diff.
    //
    // The format selector reads `Plaintext` so the snapshot reads as a
    // plaintext-path delta from the `snapshot_export_modal_default`
    // baseline — the warning appears inside the spacer area between
    // the segmented `Format:` selector row and the footer hint via the
    // same `render_inline_error` branch the refused-overwrite,
    // `confirmation_mismatch`, and `zero_length` snapshots exercise.
    // The renderer paints a single line per `view/export.rs`'s
    // `render_inline_error` (no `Wrap`), so the snapshot also pins the
    // truncation behavior — a regression that ever swaps the slot for
    // a multi-line `Wrap` widget surfaces here as a diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = ExportModal {
        format: ExportFormat::Plaintext,
        error: Some(format_plaintext_export_warning()),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // plaintext-export warning must fail this test even before the
    // human reads the snapshot diff. Bind the assertion to the leading
    // `WARNING: Plaintext export` substring (the full ~270-char
    // warning exceeds the inline-error slot's width and is truncated
    // by `Paragraph::new(Line::from(...))` per `view/export.rs`).
    assert!(
        rendered.contains("WARNING: Plaintext export"),
        "expected plaintext-export warning prefix to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_io_error() {
    // Plan L2390: "Export modal `io_error` writer failure." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { error:
    // Some(render_error_message(&PaladinError::IoError { ... })), .. })`
    // open so the snapshot pins the inline-error row populated when
    // `paladin_core::write_secret_file_atomic` fails anywhere along
    // the staging / rename / parent-dir-fsync chain. The reducer's Err
    // arm (`reduce_export_result` in `src/app/reducer.rs`) routes the
    // error through `render_error_message` and parks the wording on
    // `ExportModal::error` per `IMPLEMENTATION_PLAN_03_TUI.md` "Tests
    // > Export modal": *"Writer `io_error`, `save_not_committed`, and
    // `save_durability_unconfirmed` surface inline and the modal stays
    // open."* The view-snapshot pins the post-reduce rendering 1:1
    // with the reducer-side coverage from
    // `effect_result_export_err_io_error_surfaces_inline_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    //
    // Routing the wording through `render_error_message` binds the
    // snapshot to the core `Display` impl (`I/O error during
    // write_secret_file_atomic`) rather than a hand-typed string so
    // any future wording change in core's `io_error` `Display` surfaces
    // here as a diff. The operation tag mirrors the writer the export
    // executor invokes; the underlying `std::io::ErrorKind` is
    // deliberately `PermissionDenied` to match the reducer-side
    // fixture and bind both surfaces to the same `Debug`-stable kind.
    //
    // The format selector stays at the `Plaintext` default so the
    // snapshot reads as a plaintext-path delta from
    // `snapshot_export_modal_default` — the inline error appears
    // inside the spacer area between the segmented `Format:` selector
    // row and the footer hint via the same `render_inline_error`
    // branch the refused-overwrite, `confirmation_mismatch`,
    // `zero_length`, and plaintext-export-warning snapshots exercise.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let err = PaladinError::IoError {
        operation: "write_secret_file_atomic",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic-denied"),
    };
    let modal = ExportModal {
        error: Some(render_error_message(&err)),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::IoError {
        operation: "write_secret_file_atomic",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic-denied"),
    });
    assert!(
        rendered.contains(&expected),
        "expected inline io_error wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_save_not_committed() {
    // Plan L2442: "Export modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { error:
    // Some(render_error_message(&PaladinError::SaveNotCommitted { .. })), .. })`
    // open so the snapshot pins the inline-error row populated when
    // `paladin_core::write_secret_file_atomic` fails before the
    // primary rename — the staging-file fsync / rename failure mode
    // per `DESIGN.md` §4.3 / §5 `save_not_committed`. The reducer's
    // Err arm (`reduce_export_result` in `src/app/reducer.rs`) routes
    // the error through `render_error_message` and parks the wording
    // on `ExportModal::error` per `IMPLEMENTATION_PLAN_03_TUI.md`
    // "Tests > Export modal": *"Writer `io_error`,
    // `save_not_committed`, and `save_durability_unconfirmed` surface
    // inline and the modal stays open."* The view-snapshot pins the
    // post-reduce rendering 1:1 with the reducer-side coverage from
    // `effect_result_export_err_save_not_committed_surfaces_inline_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    //
    // Routing the wording through `render_error_message` binds the
    // snapshot to the core `Display` impl (`save not committed
    // (committed=false)`) rather than a hand-typed string so any
    // future wording change in core's `save_not_committed` `Display`
    // surfaces here as a diff. The `committed: false, backup_path:
    // None` shape mirrors the reducer-side fixture and the
    // pre-rename failure path documented in §4.3 (the staging file
    // never reached the destination, no `.bak` rotation ran).
    //
    // The format selector stays at the `Plaintext` default so the
    // snapshot reads as a plaintext-path delta from
    // `snapshot_export_modal_default` — the inline error appears
    // inside the spacer area between the segmented `Format:`
    // selector row and the footer hint via the same
    // `render_inline_error` branch the refused-overwrite,
    // `confirmation_mismatch`, `zero_length`, plaintext-export-
    // warning, and `io_error` snapshots exercise.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let modal = ExportModal {
        error: Some(render_error_message(&err)),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    assert!(
        rendered.contains(&expected),
        "expected inline save_not_committed wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_save_durability_unconfirmed() {
    // Plan L2443: "Export modal `save_durability_unconfirmed`." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { error:
    // Some(render_error_message(&PaladinError::SaveDurabilityUnconfirmed)), .. })`
    // open so the snapshot pins the inline-error row populated when
    // `paladin_core::write_secret_file_atomic`'s primary rename
    // succeeded but the parent-directory `fsync` failed — the
    // durability-unconfirmed failure mode per `DESIGN.md` §4.3 / §5
    // `save_durability_unconfirmed`. The reducer's Err arm
    // (`reduce_export_result` in `src/app/reducer.rs`) routes the
    // error through `render_error_message` and parks the wording on
    // `ExportModal::error` per `IMPLEMENTATION_PLAN_03_TUI.md`
    // "Tests > Export modal": *"Writer `io_error`,
    // `save_not_committed`, and `save_durability_unconfirmed`
    // surface inline and the modal stays open."* The view-snapshot
    // pins the post-reduce rendering 1:1 with the reducer-side
    // coverage from
    // `effect_result_export_err_save_durability_unconfirmed_surfaces_inline_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    //
    // Routing the wording through `render_error_message` binds the
    // snapshot to the core `Display` impl (`save durability
    // unconfirmed`) rather than a hand-typed string so any future
    // wording change in core's `save_durability_unconfirmed`
    // `Display` surfaces here as a diff. The variant is a unit
    // (`PaladinError::SaveDurabilityUnconfirmed` carries no fields),
    // mirroring the §4.3 contract — the destination file is in
    // place on disk; only the parent-directory metadata sync is
    // unconfirmed — so this slice deliberately differs from
    // `save_not_committed` (pre-rename failure with `committed` /
    // `backup_path` discriminators) in the rendered wording even
    // though both surface inline through the same modal slot.
    //
    // The format selector stays at the `Plaintext` default so the
    // snapshot reads as a plaintext-path delta from
    // `snapshot_export_modal_default` — the inline error appears
    // inside the spacer area between the segmented `Format:`
    // selector row and the footer hint via the same
    // `render_inline_error` branch the refused-overwrite,
    // `confirmation_mismatch`, `zero_length`, plaintext-export-
    // warning, `io_error`, and `save_not_committed` snapshots
    // exercise.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let modal = ExportModal {
        error: Some(render_error_message(&err)),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(
        rendered.contains(&expected),
        "expected inline save_durability_unconfirmed wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_set_default() {
    // Plan L1968: "Passphrase modal — `set` sub-flow." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Passphrase(PassphraseModal::default())` open so the
    // snapshot pins the freshly-opened (`PassphraseSubFlow::Set`,
    // empty `new_passphrase` / `confirm_passphrase` buffers, no
    // inline error) baseline of the Passphrase modal's `set`
    // sub-flow overlay rendered on top of the list view per
    // `DESIGN.md` §6's "modal dialogs for add / remove / rename /
    // import / export / passphrase / settings" call-out and the
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) >
    // Passphrase" contract — *"three sub-flows mirroring CLI's
    // `passphrase set / change / remove`. … New passphrases (`set`,
    // `change`) are prompted twice and confirmed; mismatch returns
    // to the modal with an inline `invalid_passphrase`
    // (`reason: "confirmation_mismatch"`) error."*
    //
    // The background vault is empty (plaintext) so the underlying
    // list view settles into its `No accounts. Press `a` to add
    // one.` prompt — the modal overlay's Clear-region then erases
    // that prompt where it would otherwise show through. The
    // `Passphrase:` and `Confirm:` rows render as masked input
    // slots mirroring the Add modal's `Secret:` field — `[ ]`
    // empty, `[ ••• ]` non-empty — so the snapshot pins that the
    // renderer never paints typed bytes (the buffers are zeroizing
    // and the `Debug` impl is redacted, but the renderer is the
    // last line of defense against onlookers reading the screen).
    // Inline `confirmation_mismatch` / `zero_length` validation
    // gates and `save_not_committed` / `save_durability_unconfirmed`
    // variants land as their own snapshots per the plan's later
    // checkboxes (L2002 / L2003), as do the `change` and `remove`
    // sub-flow snapshots (L1969 / L1970).
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Set,
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_passphrase_modal_change_default() {
    // Plan L2002: "Passphrase modal — `change` sub-flow." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Passphrase` open and `sub_flow: PassphraseSubFlow::Change`
    // so the snapshot pins the freshly-opened (empty `new_passphrase`
    // / `confirm_passphrase` buffers, no inline error) baseline of
    // the Passphrase modal's `change` sub-flow overlay. The `change`
    // sub-flow is the encrypted → encrypted re-key transition per
    // `DESIGN.md` §6's "modal dialogs for add / remove / rename /
    // import / export / passphrase / settings" call-out and the
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Passphrase"
    // contract — *"three sub-flows mirroring CLI's `passphrase set /
    // change / remove`. … New passphrases (`set`, `change`) are
    // prompted twice and confirmed; mismatch returns to the modal
    // with an inline `invalid_passphrase` (`reason:
    // "confirmation_mismatch"`) error."*
    //
    // Compared to the `set` snapshot above, this snapshot's
    // bordered-block title flips to ` Change passphrase ` and the
    // one-line intent reads `Re-encrypts this vault under a new
    // passphrase.` — so a regression that ever swaps the sub-flow
    // wording (or paints the `set` intent on a `change` modal)
    // surfaces as a diff in this snapshot rather than in a unit
    // test against private helpers. The masked `Passphrase:` /
    // `Confirm:` rows, the centered `Enter submit  ·  Esc cancel`
    // hint, and the surrounding list-view chrome all match the
    // `set` baseline so the snapshot pins that the body shape
    // stays identical between the twice-confirm sub-flows.
    //
    // The renderer doesn't gate on vault state (the gate is enforced
    // upstream by the modal-open reducer per the design's "available
    // sub-flow is gated by `Vault::is_encrypted()`" rule); a
    // plaintext-vault background therefore matches the `set` test
    // and keeps this test focused on the renderer's contract. The
    // `remove` sub-flow snapshot lands in its own slice below
    // (plan L2003).
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Change,
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_passphrase_modal_remove_default() {
    // Plan L2003: "Passphrase modal — `remove` sub-flow." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Passphrase` open and `sub_flow: PassphraseSubFlow::Remove`
    // so the snapshot pins the freshly-opened (no inline error,
    // unused `new_passphrase` / `confirm_passphrase` buffers)
    // baseline of the Passphrase modal's `remove` sub-flow overlay.
    // The `remove` sub-flow is the encrypted → plaintext transition
    // per `DESIGN.md` §6 and the `IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Passphrase" contract — *"`remove` shows the
    // plaintext-storage warning and requires explicit confirmation
    // before mutation. Source the `passphrase remove` warning from
    // `paladin_core::format_plaintext_storage_warning()`."*
    //
    // Compared to the `set` / `change` twice-confirm sub-flow
    // snapshots above, the `remove` body fans out into its own
    // shape — the bordered block grows taller to fit the wrapped
    // plaintext-storage warning sourced verbatim from
    // [`paladin_core::format_plaintext_storage_warning`] (so the
    // TUI wording stays byte-identical to the CLI `passphrase
    // remove` / GTK `PassphraseDialog::remove_warning_body` paths),
    // the masked `Passphrase:` / `Confirm:` input rows drop away
    // entirely (the sub-flow takes no new secret), and the hint
    // reads `Enter confirm  ·  Esc cancel` to flag the destructive
    // mutation. A regression that ever paints the twice-confirm
    // body on a `remove` modal (or drifts the warning wording from
    // core) surfaces as a diff in this snapshot rather than in a
    // unit test against private helpers.
    //
    // The renderer doesn't gate on vault state (the gate is
    // enforced upstream by the modal-open reducer per the design's
    // "available sub-flow is gated by `Vault::is_encrypted()`"
    // rule); a plaintext-vault background therefore matches the
    // `set` / `change` tests and keeps this snapshot focused on
    // the renderer's contract.
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Remove,
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_passphrase_modal_set_save_not_committed() {
    // Plan L2198: "Passphrase set `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Passphrase(PassphraseModal { sub_flow: Set, error:
    // Some(render_error_message(&PaladinError::SaveNotCommitted {
    // committed: false, backup_path: None })), .. })` so the
    // snapshot pins the inline-error row populated from a pre-commit
    // save failure per `DESIGN.md` §5's `save_not_committed`
    // discriminator. Routing the wording through the shared
    // `render_error_message` helper means the inline text matches
    // the rest of the TUI's error surface — the unlock screen's
    // `decrypt_failed` line and the Add / Remove / Rename / Import
    // modals' inline-error slots.
    //
    // Every other PassphraseModal field stays at its default (empty
    // `new_passphrase` / `confirm_passphrase` buffers) so the
    // snapshot reads as a delta from the
    // `snapshot_passphrase_modal_set_default` baseline: the inline
    // error line appears inside the spacer area between the
    // `Confirm:` row and the footer hint.
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Set,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_set_save_durability_unconfirmed() {
    // Plan L2199: "Passphrase set `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Set,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_change_save_not_committed() {
    // Plan L2200: "Passphrase change `save_not_committed`." Mirrors
    // the `set` save_not_committed test above with
    // `sub_flow: PassphraseSubFlow::Change` so the snapshot pins
    // that the inline-error slot lights up identically in the
    // encrypted → encrypted re-key transition. The bordered-block
    // title flips to ` Change passphrase ` and the intent line
    // reads `Re-encrypts this vault under a new passphrase.`; the
    // body shape, the error row placement, and the surrounding
    // list-view chrome all match the `set` baseline.
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Change,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording in change modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_change_save_durability_unconfirmed() {
    // Plan L2201: "Passphrase change `save_durability_unconfirmed`."
    // Same rendering path as the `change` save_not_committed snapshot
    // above; typed against `PaladinError::SaveDurabilityUnconfirmed`
    // per the plan's "Durability-unconfirmed failures follow the
    // committed-state path" contract.
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Change,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording in change modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_remove_save_not_committed() {
    // Plan L2202: "Passphrase remove `save_not_committed`." Mirrors
    // the `set` / `change` save_not_committed tests but for the
    // encrypted → plaintext transition. The `remove` sub-flow's
    // body — wrapped plaintext-storage warning sourced verbatim
    // from [`paladin_core::format_plaintext_storage_warning`] — stays
    // intact above the inline error, and the inline error is painted
    // between the warning and the `Enter confirm  ·  Esc cancel`
    // hint so the destructive-mutation verb remains visible while
    // surfacing the save failure.
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Remove,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording in remove modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_remove_save_durability_unconfirmed() {
    // Plan L2203: "Passphrase remove `save_durability_unconfirmed`."
    // Same rendering path as the `remove` save_not_committed
    // snapshot above; typed against
    // `PaladinError::SaveDurabilityUnconfirmed` per the plan's
    // "Durability-unconfirmed failures follow the committed-state
    // path" contract.
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
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Remove,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording in remove modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_settings_modal_default() {
    // Plan L2004: "Settings modal." Drive `view::render` against an
    // `Unlocked` state with `Modal::Settings(SettingsModal { .. })`
    // open so the snapshot pins the freshly-opened (no inline error)
    // baseline of the Settings modal overlay rendered on top of the
    // list view per `DESIGN.md` §6 and the
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Settings"
    // contract — *"toggles for `auto_lock.enabled` and
    // `clipboard.clear_enabled`, spinners for `auto_lock.timeout_secs`
    // and `clipboard.clear_secs`. … The modal accumulates pending
    // edits in modal-local state and only commits on Confirm."*
    //
    // The modal's four pending-edit fields are seeded with the
    // `paladin_core::VaultSettings::default()` values — both toggles
    // off, `auto_lock.timeout_secs = 300`, `clipboard.clear_secs =
    // 20` — so the snapshot mirrors what the production modal-open
    // path produces against a freshly initialized vault rather than
    // the doc-only `SettingsModal::default()` placeholder (which
    // exists for reducer-test ergonomics and underflows the spinner
    // bounds with `0`). A regression that ever drifts the toggle
    // glyphs, the spinner formatting, or the row order from the
    // documented "auto-lock toggle / auto-lock timeout / clipboard
    // toggle / clipboard timeout" reading order surfaces as a diff
    // in this snapshot rather than in a unit test against private
    // helpers.
    //
    // Inline `save_not_committed` / `save_durability_unconfirmed`
    // variants of this modal land alongside their own
    // [`SettingsModal::error`](crate::app::state::SettingsModal::error)
    // rendering slices per the plan's later checklist rows; the
    // per-field focus marker fans out alongside the focus-paint
    // slice (matching the Add modal's deferred focus-highlighting
    // precedent), so this baseline keeps the body to the four
    // labeled value rows plus the hint and pins only the layout
    // contract.
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
        modal: Some(Modal::Settings(SettingsModal {
            auto_lock_enabled: false,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
            ..SettingsModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_settings_modal_save_not_committed() {
    // Plan L2255: "Settings modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Settings(SettingsModal { error: Some(render_error_message(
    // &PaladinError::SaveNotCommitted { committed: false, backup_path:
    // None })), .. })` so the snapshot pins the inline-error row
    // populated from a pre-commit save failure per `DESIGN.md` §5's
    // `save_not_committed` discriminator. Routing the wording through
    // the shared `render_error_message` helper means the inline text
    // matches the rest of the TUI's error surface — the unlock
    // screen's `decrypt_failed` line and the Add / Remove / Rename /
    // Import / Passphrase modals' inline-error slots.
    //
    // Every other SettingsModal field stays at its default-snapshot
    // baseline (toggles off, `auto_lock.timeout_secs = 300`,
    // `clipboard.clear_secs = 20`) so the snapshot reads as a delta
    // from the `snapshot_settings_modal_default` baseline: the inline
    // error line appears inside the spacer area between the
    // clipboard-spinner row and the footer hint.
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
        modal: Some(Modal::Settings(SettingsModal {
            auto_lock_enabled: false,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..SettingsModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording in settings modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_settings_modal_save_durability_unconfirmed() {
    // Plan L2256: "Settings modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
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
        modal: Some(Modal::Settings(SettingsModal {
            auto_lock_enabled: false,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..SettingsModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording in settings modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_help_overlay() {
    // Plan L2071: "Help overlay." Drive `view::render` against an
    // `Unlocked` state with `help_open: true` so the snapshot pins
    // the read-only Help overlay rendered on top of the list view
    // per `DESIGN.md` §6 and the `IMPLEMENTATION_PLAN_03_TUI.md`
    // "Help overlay" contract — *"`?` from list focus opens a
    // read-only Help overlay listing every keybinding from the
    // table below; `Esc` closes the overlay and restores list
    // focus. The overlay has no inputs and never mutates vault
    // state."*
    //
    // The overlay's content is sourced from the workspace-wide
    // `paladin_tui::keybindings::KEYBINDINGS` table — the same
    // table the future `cargo xtask man` target will append into
    // the man page after the clap-derived synopsis. Pinning the
    // snapshot to that public table means any drift between the
    // help-overlay wording and the man-page keybindings section
    // surfaces as a diff here (and in the man-page golden test
    // when that lands) rather than being silently introduced.
    //
    // A plaintext vault keeps the underlying list-view background
    // deterministic and matches the modal-default snapshots above;
    // the renderer doesn't gate on vault state (the gate is
    // enforced upstream by the reducer's "list-focus only,
    // no-modal" rule, per the design's "list-focus-only" line).
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
        help_open: true,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 30));
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
