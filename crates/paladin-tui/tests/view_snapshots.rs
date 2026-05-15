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
use paladin_tui::app::state::{
    render_error_message, AddModal, AppState, ExportModal, Focus, HotpReveal, ImportModal, Modal,
    PassphraseModal, PassphraseSubFlow, RemoveModal, RenameModal, SettingsModal,
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
