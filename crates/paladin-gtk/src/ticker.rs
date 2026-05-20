// SPDX-License-Identifier: AGPL-3.0-or-later

//! TOTP ticker pure-logic glue for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" TOTP
//! ticker section, the GUI owns the `glib::timeout_add_local`
//! timeout source and the per-tick widget refresh, but every
//! lifecycle decision (install / teardown based on app state plus
//! TOTP row presence) and the per-tick interval pin route through
//! this module so the widget layer never re-derives the rule. The
//! TUI's `paladin-tui/src/app/ticker.rs` drives the same
//! [`paladin_core::TICK_INTERVAL_MS`] (250 ms today) so the two GUIs
//! tick at the same cadence.
//!
//! The module is widget-free: the helpers here take
//! [`crate::app::state::AppState`] plus the already-projected
//! [`crate::account_list::AccountRowModel`] slice and return typed
//! decisions. `tests/ticker_logic.rs` exercises the helpers without
//! spinning up GTK or libadwaita.

use std::time::Duration;

use paladin_core::{AccountKindSummary, TICK_INTERVAL_MS};

use crate::account_list::AccountRowModel;
use crate::app::state::AppState;

/// Per-tick interval for the TOTP ticker.
///
/// Sourced from [`paladin_core::TICK_INTERVAL_MS`] (250 ms today, pinned
/// by `crates/paladin-core/src/ui_contract.rs` and asserted by
/// `crates/paladin-core/tests/ui_contract.rs`). Centralizing the
/// `Duration` conversion here keeps the
/// `glib::timeout_add_local(tick_interval(), ...)` call site short
/// and prevents drift from the TUI ticker (`paladin-tui` uses the
/// same constant). The plan's "Install a single
/// `glib::timeout_add_local` source ticking at
/// `paladin_core::TICK_INTERVAL_MS`" bullet binds to this single
/// helper.
#[must_use]
pub fn tick_interval() -> Duration {
    Duration::from_millis(TICK_INTERVAL_MS)
}

/// `true` iff at least one of the rendered `rows` is a TOTP row.
///
/// HOTP rows pull their codes from the reveal slot on demand and do
/// not need a per-tick refresh, so a HOTP-only (or empty) row set
/// makes the ticker pointless. The plan's "Install a single
/// `glib::timeout_add_local` source … while at least one TOTP row
/// is visible" bullet binds to this predicate.
#[must_use]
pub fn has_visible_totp_row(rows: &[AccountRowModel]) -> bool {
    rows.iter()
        .any(|row| matches!(row.kind, AccountKindSummary::Totp))
}

/// `true` iff the ticker should be running for the current
/// `(state, rows)` pair.
///
/// Two conditions, both required:
///
/// 1. The vault is open ([`AppState::is_unlocked`] — i.e.
///    `Unlocked` or `UnlockedBusy`). `UnlockedBusy` keeps the
///    ticker alive because §"In-flight effect ownership" pins the
///    already-rendered list display as responsive while a worker
///    holds the vault; a transient mutation must not tear down the
///    gauge.
/// 2. At least one TOTP row is visible
///    ([`has_visible_totp_row`]).
///
/// Every other state (`Missing` / `Locked` / `StartupError`) tears
/// the ticker down — the plan's "Tear down the ticker on `Locked`
/// / `StartupError` transitions and reinstall on `Unlocked`" bullet
/// binds to this rule.
#[must_use]
pub fn should_install(state: &AppState, rows: &[AccountRowModel]) -> bool {
    state.is_unlocked() && has_visible_totp_row(rows)
}

/// Lifecycle transition the ticker driver should apply when the
/// `(state, rows)` pair changes.
///
/// `was_installed` is the live state of the
/// `glib::timeout_add_local` source the caller installed (or did
/// not install) on the prior tick / state change. The decision is
/// expressed as a typed enum so the install / teardown call sites
/// in the widget layer are exhaustive against [`TickerTransition`]
/// and cannot thrash the source by ignoring a no-op transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickerTransition {
    /// No change — the source is already in the right state for
    /// the current `(state, rows)` pair. The widget layer makes no
    /// `glib::timeout_add_local` / `glib::source_remove` calls.
    NoChange,
    /// Install a fresh `glib::timeout_add_local` source at
    /// [`tick_interval`].
    Install,
    /// Tear down the existing `glib::timeout_add_local` source.
    Teardown,
}

/// Collapse the `(was_installed, should_install(state, rows))`
/// matrix into a single [`TickerTransition`] outcome.
///
/// The four outcomes:
///
/// | `was_installed` | `should_install` | result    |
/// |-----------------|------------------|-----------|
/// | `false`         | `true`           | `Install` |
/// | `true`          | `false`          | `Teardown`|
/// | `true`          | `true`           | `NoChange`|
/// | `false`         | `false`          | `NoChange`|
///
/// Driver call sites that compute this transition on every relevant
/// state change (state mounted, vault list refresh, search filter
/// rebuild) never double-install and never tear down a source that
/// is not there.
#[must_use]
pub fn ticker_transition(
    was_installed: bool,
    state: &AppState,
    rows: &[AccountRowModel],
) -> TickerTransition {
    match (was_installed, should_install(state, rows)) {
        (false, true) => TickerTransition::Install,
        (true, false) => TickerTransition::Teardown,
        _ => TickerTransition::NoChange,
    }
}
