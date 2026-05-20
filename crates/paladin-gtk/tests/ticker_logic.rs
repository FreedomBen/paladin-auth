// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic `ticker` tests for `paladin-gtk`.
//!
//! Tracks `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist"
//! TOTP ticker section:
//!
//! * `tick_interval()` mirrors `paladin_core::TICK_INTERVAL_MS`.
//! * `has_visible_totp_row(rows)` returns `true` iff at least one
//!   visible row is TOTP — HOTP-only and empty row sets return
//!   `false` because HOTP rows pull their codes from the reveal slot
//!   on demand and do not need a per-tick refresh.
//! * `should_install(state, rows)` returns `true` iff the vault is
//!   open (`Unlocked` / `UnlockedBusy` — both share the responsive
//!   list-display contract from §"In-flight effect ownership") AND
//!   `has_visible_totp_row(rows)` is `true`; every other state
//!   (`Missing` / `Locked` / `StartupError`) tears the ticker down
//!   per the plan's "Tear down the ticker on `Locked` /
//!   `StartupError` transitions" rule.
//! * `ticker_transition(was_installed, state, rows)` collapses the
//!   `(was, should)` matrix into the four canonical
//!   [`TickerTransition`] outcomes the widget layer applies — the
//!   `glib::timeout_add_local` source is installed exactly when the
//!   prior tick had no source and `should_install` returns `true`,
//!   torn down exactly when the prior tick had a source and
//!   `should_install` returns `false`, and otherwise the transition
//!   is a no-op so callers never thrash the source.
//!
//! The module under test (`paladin_gtk::ticker`) is widget-free and
//! `(Vault, Store)`-free, so these tests run without spinning up GTK
//! / libadwaita.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use secrecy::SecretString;
use zeroize::Zeroizing;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, AccountKindSummary, Algorithm,
    IconHintInput, PaladinError, Store, Vault, VaultInit, VaultLock, TICK_INTERVAL_MS,
};

use paladin_gtk::account_list::AccountRowModel;
use paladin_gtk::account_row::{CodeDisplay, RowDisplay};
use paladin_gtk::app::state::AppState;
use paladin_gtk::clipboard_clear::PendingClipboardClear;
use paladin_gtk::startup_error::StartupError;
use paladin_gtk::ticker::{
    compute_tick_displays, has_visible_totp_row, should_install, tick, tick_interval,
    ticker_transition, TickOutcome, TickerTransition,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn totp_row(label: &str) -> AccountRowModel {
    AccountRowModel {
        id: AccountId::new(),
        display_label: label.to_string(),
        kind: AccountKindSummary::Totp,
        counter: None,
    }
}

fn hotp_row(label: &str, counter: u64) -> AccountRowModel {
    AccountRowModel {
        id: AccountId::new(),
        display_label: label.to_string(),
        kind: AccountKindSummary::Hotp,
        counter: Some(counter),
    }
}

fn vault_path() -> PathBuf {
    PathBuf::from("/tmp/paladin-ticker-fixture.bin")
}

fn unlocked() -> AppState {
    AppState::Unlocked { path: vault_path() }
}

fn unlocked_busy() -> AppState {
    AppState::UnlockedBusy { path: vault_path() }
}

fn locked() -> AppState {
    AppState::Locked { path: vault_path() }
}

fn missing() -> AppState {
    AppState::Missing { path: vault_path() }
}

fn startup_error() -> AppState {
    let err = PaladinError::IoError {
        operation: "ticker_logic_fixture",
        source: io::Error::new(io::ErrorKind::NotFound, "fixture"),
    };
    AppState::StartupError {
        path: Some(vault_path()),
        error: StartupError::from_inspect(&err),
    }
}

// ---------------------------------------------------------------------------
// `tick_interval`
// ---------------------------------------------------------------------------

#[test]
fn tick_interval_matches_paladin_core_constant() {
    // Routing the per-tick interval through `paladin_core` keeps the
    // GUI ticker in lockstep with the TUI ticker and with the §5
    // `ui_contract` source of truth. A future bump to
    // `TICK_INTERVAL_MS` must propagate automatically.
    assert_eq!(tick_interval(), Duration::from_millis(TICK_INTERVAL_MS));
}

#[test]
fn tick_interval_is_nonzero() {
    // Defensive: a zero interval would burn CPU on a tight loop and
    // would also fail the "sleeps before emitting" contract the TUI
    // ticker pins. `paladin_core::TICK_INTERVAL_MS` is 250 ms today;
    // any future change must keep the value strictly positive.
    assert!(
        tick_interval() > Duration::ZERO,
        "tick interval must be strictly positive (got {:?})",
        tick_interval(),
    );
}

// ---------------------------------------------------------------------------
// `has_visible_totp_row`
// ---------------------------------------------------------------------------

#[test]
fn has_visible_totp_row_empty_returns_false() {
    let rows: Vec<AccountRowModel> = Vec::new();
    assert!(!has_visible_totp_row(&rows));
}

#[test]
fn has_visible_totp_row_only_hotp_returns_false() {
    // HOTP-only row sets never need the per-tick refresh: HOTP codes
    // come from the reveal slot, which the row factory binds on
    // demand, not from a periodic timer.
    let rows = vec![hotp_row("solo", 7), hotp_row("other", 9)];
    assert!(!has_visible_totp_row(&rows));
}

#[test]
fn has_visible_totp_row_single_totp_returns_true() {
    let rows = vec![totp_row("Acme:alice")];
    assert!(has_visible_totp_row(&rows));
}

#[test]
fn has_visible_totp_row_mixed_with_any_totp_returns_true() {
    // The decision is "at least one" — order, position, and HOTP
    // siblings do not gate the TOTP refresh.
    let rows = vec![
        hotp_row("solo", 7),
        totp_row("Acme:alice"),
        hotp_row("other", 9),
    ];
    assert!(has_visible_totp_row(&rows));
}

// ---------------------------------------------------------------------------
// `should_install`
// ---------------------------------------------------------------------------

#[test]
fn should_install_unlocked_with_totp_returns_true() {
    let rows = vec![totp_row("Acme:alice")];
    assert!(should_install(&unlocked(), &rows));
}

#[test]
fn should_install_unlocked_busy_with_totp_returns_true() {
    // §"In-flight effect ownership": the already-rendered list
    // display stays responsive while a worker holds the vault, so
    // the ticker keeps firing during a brief mutation.
    let rows = vec![totp_row("Acme:alice")];
    assert!(should_install(&unlocked_busy(), &rows));
}

#[test]
fn should_install_unlocked_without_totp_returns_false() {
    // An unlocked vault whose visible row set is HOTP-only (or
    // empty) has nothing to refresh; the ticker is torn down to
    // avoid burning timer wakeups on a no-op.
    let rows = vec![hotp_row("solo", 7)];
    assert!(!should_install(&unlocked(), &rows));

    let empty: Vec<AccountRowModel> = Vec::new();
    assert!(!should_install(&unlocked(), &empty));
}

#[test]
fn should_install_unlocked_busy_without_totp_returns_false() {
    // Mirrors the `Unlocked` case for symmetry: the "open" gate is
    // shared, but `has_visible_totp_row` independently rules out the
    // install.
    let rows = vec![hotp_row("solo", 7)];
    assert!(!should_install(&unlocked_busy(), &rows));
}

#[test]
fn should_install_locked_with_totp_returns_false() {
    // `Locked` is the plan's teardown trigger — the user is staring
    // at `UnlockComponent`, no vault is open, and nothing in the
    // list-view surface is visible.
    let rows = vec![totp_row("Acme:alice")];
    assert!(!should_install(&locked(), &rows));
}

#[test]
fn should_install_missing_returns_false() {
    // `Missing` mounts `InitDialog` — there is no list view yet, so
    // there can be no TOTP rows. Defensive: even if a caller passes
    // a non-empty row set (a stale snapshot), `should_install`
    // refuses to arm the ticker.
    let rows = vec![totp_row("Acme:alice")];
    assert!(!should_install(&missing(), &rows));
}

#[test]
fn should_install_startup_error_returns_false() {
    // `StartupError` is non-mutating chrome — same teardown rule as
    // `Locked` per the plan.
    let rows = vec![totp_row("Acme:alice")];
    assert!(!should_install(&startup_error(), &rows));
}

// ---------------------------------------------------------------------------
// `ticker_transition`
// ---------------------------------------------------------------------------

#[test]
fn ticker_transition_install_when_not_installed_and_should_install() {
    let rows = vec![totp_row("Acme:alice")];
    assert_eq!(
        ticker_transition(false, &unlocked(), &rows),
        TickerTransition::Install,
    );
}

#[test]
fn ticker_transition_teardown_when_installed_and_should_not_install() {
    // Common teardown path: the user just locked the vault, or the
    // last TOTP row was removed.
    let rows = vec![totp_row("Acme:alice")];
    assert_eq!(
        ticker_transition(true, &locked(), &rows),
        TickerTransition::Teardown,
    );

    let hotp_only = vec![hotp_row("solo", 7)];
    assert_eq!(
        ticker_transition(true, &unlocked(), &hotp_only),
        TickerTransition::Teardown,
    );
}

#[test]
fn ticker_transition_nochange_when_installed_and_should_stay() {
    // Steady-state during normal operation: the ticker is running,
    // the user is unlocked, and at least one TOTP row is visible.
    let rows = vec![totp_row("Acme:alice")];
    assert_eq!(
        ticker_transition(true, &unlocked(), &rows),
        TickerTransition::NoChange,
    );

    // Busy keeps the ticker alive — the transient mutation must not
    // tear down the gauge.
    assert_eq!(
        ticker_transition(true, &unlocked_busy(), &rows),
        TickerTransition::NoChange,
    );
}

#[test]
fn ticker_transition_nochange_when_not_installed_and_should_not_install() {
    // The other steady state: the user is locked / missing / in a
    // startup error and there's no ticker to install.
    let rows = vec![totp_row("Acme:alice")];
    assert_eq!(
        ticker_transition(false, &locked(), &rows),
        TickerTransition::NoChange,
    );
    assert_eq!(
        ticker_transition(false, &missing(), &rows),
        TickerTransition::NoChange,
    );
    assert_eq!(
        ticker_transition(false, &startup_error(), &rows),
        TickerTransition::NoChange,
    );

    // And the unlocked-but-no-TOTP-rows steady state.
    let hotp_only = vec![hotp_row("solo", 7)];
    assert_eq!(
        ticker_transition(false, &unlocked(), &hotp_only),
        TickerTransition::NoChange,
    );
}

#[test]
fn ticker_transition_install_on_locked_to_unlocked_with_totp() {
    // Unlock flow: was torn down (Locked), now is Unlocked with at
    // least one TOTP row — install fires exactly once.
    let rows = vec![totp_row("Acme:alice")];
    assert_eq!(
        ticker_transition(false, &unlocked(), &rows),
        TickerTransition::Install,
    );
}

#[test]
fn ticker_transition_teardown_on_unlocked_to_locked_with_totp() {
    // Auto-lock flow: was installed (Unlocked with TOTP), now is
    // Locked — teardown fires exactly once even though `rows` still
    // contains the TOTP entry (the caller hands the prior snapshot).
    let rows = vec![totp_row("Acme:alice")];
    assert_eq!(
        ticker_transition(true, &locked(), &rows),
        TickerTransition::Teardown,
    );
}

// ---------------------------------------------------------------------------
// `compute_tick_displays` — per-tick TOTP row refresh
//
// The plan's "On each tick, recompute the TOTP gauge value and the
// visible code from `paladin_core::totp_code(account, now)` for every
// TOTP row in the current list view" bullet binds to this projection.
// HOTP rows pull from the reveal slot on demand, so they are not in
// the per-tick refresh set. Missing account ids (a race between a
// vault mutation and the tick firing) and `totp_code` errors
// (pre-Unix-epoch `now`, `valid_until` overflow) drop silently — the
// widget layer leaves the prior display in place rather than blanking
// the row on a transient failure.
// ---------------------------------------------------------------------------

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

fn open_plaintext_pair(path: &Path) -> (Vault, Store) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(path, VaultLock::Plaintext).expect("reopen plaintext")
}

fn add_totp(vault: &mut Vault, store: &Store, issuer: Option<&str>, label: &str) -> AccountId {
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
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

fn add_hotp(
    vault: &mut Vault,
    store: &Store,
    issuer: Option<&str>,
    label: &str,
    counter: u64,
) -> AccountId {
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
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

fn totp_row_for(id: AccountId, label: &str) -> AccountRowModel {
    AccountRowModel {
        id,
        display_label: label.to_string(),
        kind: AccountKindSummary::Totp,
        counter: None,
    }
}

fn hotp_row_for(id: AccountId, label: &str, counter: u64) -> AccountRowModel {
    AccountRowModel {
        id,
        display_label: label.to_string(),
        kind: AccountKindSummary::Hotp,
        counter: Some(counter),
    }
}

#[test]
fn compute_tick_displays_empty_rows_returns_empty() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let displays = compute_tick_displays(&vault, &[], SystemTime::now());
    assert!(
        displays.is_empty(),
        "an empty row set produces an empty refresh: {displays:?}",
    );
}

#[test]
fn compute_tick_displays_hotp_only_rows_returns_empty() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_hotp(&mut vault, &store, Some("Acme"), "alice", 7);
    let rows = vec![hotp_row_for(id, "Acme:alice", 7)];

    let displays = compute_tick_displays(&vault, &rows, SystemTime::now());
    assert!(
        displays.is_empty(),
        "HOTP rows are not in the per-tick refresh set; got: {displays:?}",
    );
}

#[test]
fn compute_tick_displays_single_totp_row_returns_visible_code() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let rows = vec![totp_row_for(id, "Acme:alice")];

    // Pin `now` so the expected code is stable across test runs;
    // re-derive the expected digits from `Vault::totp_code` so the
    // assertion stays independent of the test secret.
    let now = UNIX_EPOCH + Duration::from_secs(59);
    let expected_code = vault
        .totp_code(id, now)
        .expect("totp_code at t=59 is well-defined");
    let displays = compute_tick_displays(&vault, &rows, now);
    assert_eq!(
        displays.len(),
        1,
        "one TOTP row → one display: {displays:?}"
    );
    let (out_id, display) = &displays[0];
    assert_eq!(*out_id, id);
    assert_eq!(display.label, "Acme:alice");
    assert_eq!(display.kind, AccountKindSummary::Totp);
    match &display.code {
        CodeDisplay::Visible(text) => {
            assert_eq!(*text, expected_code.code);
            assert_eq!(text.len(), 6, "default digits = 6: {text}");
            assert!(
                text.chars().all(|c| c.is_ascii_digit()),
                "TOTP code is all ASCII digits: {text}",
            );
        }
        CodeDisplay::Hidden => panic!("per-tick refresh must publish a visible code"),
    }
    assert_eq!(display.counter, None, "TOTP rows carry no counter widget");
    assert!(display.copy_enabled, "TOTP rows always allow copy");
    assert!(
        !display.next_button_visible,
        "TOTP rows never expose the HOTP next button",
    );
    assert!(
        display.progress_visible,
        "TOTP rows expose the progress gauge",
    );
    assert!(display.kebab_visible, "every row exposes the kebab menu");
}

#[test]
fn compute_tick_displays_skips_hotp_rows_in_mixed_set() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let totp_id = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let hotp_id = add_hotp(&mut vault, &store, Some("Acme"), "bob", 3);

    let rows = vec![
        totp_row_for(totp_id, "Acme:alice"),
        hotp_row_for(hotp_id, "Acme:bob", 3),
    ];

    let displays = compute_tick_displays(&vault, &rows, SystemTime::now());
    assert_eq!(displays.len(), 1, "only TOTP rows refresh: {displays:?}");
    assert_eq!(displays[0].0, totp_id);
    let ids: Vec<AccountId> = displays.iter().map(|(id, _)| *id).collect();
    assert!(
        !ids.contains(&hotp_id),
        "HOTP id must not appear in tick displays",
    );
}

#[test]
fn compute_tick_displays_preserves_row_order_for_totp_rows() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let a = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let b = add_totp(&mut vault, &store, Some("Acme"), "bob");
    let c = add_totp(&mut vault, &store, Some("Acme"), "carol");

    // Pass rows in non-vault-insertion order — the projection must
    // preserve the caller's order, not re-sort by vault.
    let rows = vec![
        totp_row_for(c, "Acme:carol"),
        totp_row_for(a, "Acme:alice"),
        totp_row_for(b, "Acme:bob"),
    ];

    let displays = compute_tick_displays(&vault, &rows, SystemTime::now());
    let ids: Vec<AccountId> = displays.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        ids,
        vec![c, a, b],
        "order matches `rows`, not vault insertion order",
    );
}

#[test]
fn compute_tick_displays_skips_rows_missing_from_vault() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let real = add_totp(&mut vault, &store, Some("Acme"), "alice");
    // A stale id that does not exist in the vault — simulates a
    // race where the row set lags one tick behind a remove.
    let stale = AccountId::new();

    let rows = vec![
        totp_row_for(stale, "Stale:row"),
        totp_row_for(real, "Acme:alice"),
    ];

    let displays = compute_tick_displays(&vault, &rows, SystemTime::now());
    assert_eq!(displays.len(), 1, "stale id is skipped: {displays:?}");
    assert_eq!(displays[0].0, real, "only the live id projects");
}

#[test]
fn compute_tick_displays_skips_rows_when_totp_code_fails() {
    // `Vault::totp_code` surfaces `time_range` from the underlying
    // TOTP primitive when `now` precedes the Unix epoch. A transient
    // clock failure must not blank an otherwise valid row — the
    // projection skips the row and the widget layer leaves its prior
    // display in place.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let rows = vec![totp_row_for(id, "Acme:alice")];

    let pre_epoch = UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .expect("UNIX_EPOCH supports a 1-second rewind on this platform");
    let displays = compute_tick_displays(&vault, &rows, pre_epoch);
    assert!(
        displays.is_empty(),
        "TOTP errors drop silently: {displays:?}",
    );
}

#[test]
fn compute_tick_displays_publishes_each_row_independently() {
    // Two TOTP rows with distinct labels — each must produce its own
    // display, both with `progress_visible = true` so the gauge ticks
    // on every TOTP row.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let alice = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let bob = add_totp(&mut vault, &store, Some("Acme"), "bob");
    let rows = vec![
        totp_row_for(alice, "Acme:alice"),
        totp_row_for(bob, "Acme:bob"),
    ];

    let displays = compute_tick_displays(&vault, &rows, SystemTime::now());
    assert_eq!(displays.len(), 2);
    for (_, display) in &displays {
        assert!(display.progress_visible);
        assert!(matches!(display.code, CodeDisplay::Visible(_)));
        assert!(display.copy_enabled);
        assert!(!display.next_button_visible);
    }
    let labels: Vec<&str> = displays.iter().map(|(_, d)| d.label.as_str()).collect();
    assert_eq!(labels, vec!["Acme:alice", "Acme:bob"]);
}

#[test]
fn compute_tick_displays_carries_full_row_display_shape() {
    // Defensive: confirm the returned `RowDisplay` shape is identical
    // to what `account_row::project_row` would emit, so the widget
    // layer can swap the per-tick path in without conditional binds.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let rows = vec![totp_row_for(id, "Acme:alice")];

    let now = UNIX_EPOCH + Duration::from_secs(30);
    let displays = compute_tick_displays(&vault, &rows, now);
    assert_eq!(displays.len(), 1);
    let (_, display) = &displays[0];

    let expected = RowDisplay {
        label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        code: display.code.clone(),
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        kebab_visible: true,
    };
    assert_eq!(display, &expected);
}

// ---------------------------------------------------------------------------
// `tick` — joint TOTP-refresh + clipboard-wake decision
//
// The plan's "On each tick, give the clipboard auto-clear policy a chance
// to wake against the current `gdk::Clipboard` text" bullet routes through
// this helper: the GTK call site fires the tick callback, this function
// returns the typed [`TickOutcome`], and the widget layer applies the
// display updates and (only when `clipboard_wake_due == true`) reads the
// live `gdk::Clipboard` and routes the bytes through `evaluate_wake`.
//
// The wake decision is `pending.deadline <= now`. Future deadlines stay
// dormant; the deadline boundary itself fires (matching the TUI's
// `wake_due` rule and the `glib::timeout_add_local` semantics on the
// fallback timer source).
// ---------------------------------------------------------------------------

fn pending_with_deadline(
    vault: &mut Vault,
    store: &Store,
    deadline: Instant,
) -> PendingClipboardClear {
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clipboard_clear_secs within bounds");
    vault.save(store).expect("save vault settings");
    let mut pending = paladin_gtk::clipboard_clear::schedule_copy(
        Instant::now(),
        vault.settings(),
        Zeroizing::new(b"123456".to_vec()),
    )
    .expect("schedule_copy returned Some once clipboard_clear is enabled");
    pending.deadline = deadline;
    pending
}

#[test]
fn tick_returns_empty_displays_when_no_totp_rows() {
    // Empty row set → empty display projection; clipboard wake is
    // independently `false` because no pending was supplied.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let outcome = tick(&vault, &[], SystemTime::now(), Instant::now(), None);
    assert!(outcome.display_updates.is_empty());
    assert!(!outcome.clipboard_wake_due);
}

#[test]
fn tick_returns_display_updates_for_totp_rows() {
    // TOTP row → display projection includes a visible code; with
    // no pending the clipboard wake stays dormant.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let rows = vec![totp_row_for(id, "Acme:alice")];

    let outcome = tick(
        &vault,
        &rows,
        UNIX_EPOCH + Duration::from_secs(30),
        Instant::now(),
        None,
    );
    assert_eq!(outcome.display_updates.len(), 1);
    let (out_id, out_display) = &outcome.display_updates[0];
    assert_eq!(*out_id, id);
    assert!(matches!(out_display.code, CodeDisplay::Visible(_)));
    assert!(out_display.progress_visible);
    assert!(!outcome.clipboard_wake_due);
}

#[test]
fn tick_returns_no_wake_when_pending_deadline_is_in_the_future() {
    // The pending wipe is still in the future at the tick instant —
    // wake stays dormant, no `gdk::Clipboard` round trip is needed.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let monotonic_now = Instant::now();
    let pending =
        pending_with_deadline(&mut vault, &store, monotonic_now + Duration::from_secs(10));

    let outcome = tick(
        &vault,
        &[],
        SystemTime::now(),
        monotonic_now,
        Some(&pending),
    );
    assert!(!outcome.clipboard_wake_due);
}

#[test]
fn tick_returns_wake_due_when_pending_deadline_already_elapsed() {
    // The pending wipe's deadline has already passed at the tick
    // instant — the widget layer should now read the clipboard and
    // route through `evaluate_wake`.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let monotonic_now = Instant::now();
    let pending = pending_with_deadline(
        &mut vault,
        &store,
        monotonic_now
            .checked_sub(Duration::from_millis(1))
            .expect("monotonic_now is past Instant epoch"),
    );

    let outcome = tick(
        &vault,
        &[],
        SystemTime::now(),
        monotonic_now,
        Some(&pending),
    );
    assert!(outcome.clipboard_wake_due);
}

#[test]
fn tick_returns_wake_due_when_pending_deadline_lands_exactly_on_tick() {
    // Boundary case: the deadline lands exactly on the tick instant.
    // The `<=` comparison fires (matching TUI / `timeout_add_local`
    // semantics: a timer scheduled for `now` is considered ready).
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let monotonic_now = Instant::now();
    let pending = pending_with_deadline(&mut vault, &store, monotonic_now);

    let outcome = tick(
        &vault,
        &[],
        SystemTime::now(),
        monotonic_now,
        Some(&pending),
    );
    assert!(outcome.clipboard_wake_due);
}

#[test]
fn tick_combines_displays_and_clipboard_wake_independently() {
    // Both fields populate independently: a TOTP row produces display
    // updates AND a due pending wipe sets `clipboard_wake_due = true`.
    // The widget driver applies both effects in the same callback.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let rows = vec![totp_row_for(id, "Acme:alice")];
    let monotonic_now = Instant::now();
    let pending = pending_with_deadline(
        &mut vault,
        &store,
        monotonic_now
            .checked_sub(Duration::from_secs(1))
            .expect("monotonic_now is past Instant epoch"),
    );

    let outcome = tick(
        &vault,
        &rows,
        SystemTime::now(),
        monotonic_now,
        Some(&pending),
    );
    assert_eq!(outcome.display_updates.len(), 1);
    assert!(outcome.clipboard_wake_due);
}

#[test]
fn tick_display_updates_match_compute_tick_displays_for_same_inputs() {
    // Defensive: the `tick` wrapper must not re-derive the display
    // projection — it forwards the same `compute_tick_displays`
    // output so the widget layer sees one consistent shape regardless
    // of which entry point it calls.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id_a = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let id_b = add_totp(&mut vault, &store, Some("Acme"), "bob");
    let rows = vec![
        totp_row_for(id_a, "Acme:alice"),
        totp_row_for(id_b, "Acme:bob"),
    ];

    let now = UNIX_EPOCH + Duration::from_secs(60);
    let outcome = tick(&vault, &rows, now, Instant::now(), None);
    let direct = compute_tick_displays(&vault, &rows, now);
    assert_eq!(outcome.display_updates, direct);
}

#[test]
fn tick_outcome_struct_carries_named_fields() {
    // Pin the public field names so the widget call site doesn't
    // shift onto positional destructuring.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let TickOutcome {
        display_updates,
        clipboard_wake_due,
    } = tick(&vault, &[], SystemTime::now(), Instant::now(), None);
    assert!(display_updates.is_empty());
    assert!(!clipboard_wake_due);
}
