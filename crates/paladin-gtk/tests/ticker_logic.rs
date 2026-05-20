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
use std::path::PathBuf;
use std::time::Duration;

use paladin_core::{AccountId, AccountKindSummary, PaladinError, TICK_INTERVAL_MS};

use paladin_gtk::account_list::AccountRowModel;
use paladin_gtk::app::state::AppState;
use paladin_gtk::startup_error::StartupError;
use paladin_gtk::ticker::{
    has_visible_totp_row, should_install, tick_interval, ticker_transition, TickerTransition,
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
