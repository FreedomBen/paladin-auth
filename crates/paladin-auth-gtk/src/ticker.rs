// SPDX-License-Identifier: AGPL-3.0-or-later

//! TOTP ticker pure-logic glue for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" TOTP
//! ticker section, the GUI owns the `glib::timeout_add_local`
//! timeout source and the per-tick widget refresh, but every
//! lifecycle decision (install / teardown based on app state plus
//! TOTP row presence) and the per-tick interval pin route through
//! this module so the widget layer never re-derives the rule. The
//! TUI's `paladin-auth-tui/src/app/ticker.rs` drives the same
//! [`paladin_auth_core::TICK_INTERVAL_MS`] (250 ms today) so the two GUIs
//! tick at the same cadence.
//!
//! The module is widget-free: the helpers here take
//! [`crate::app::state::AppState`] plus the already-projected
//! [`crate::account_list::AccountRowModel`] slice and return typed
//! decisions. `tests/ticker_logic.rs` exercises the helpers without
//! spinning up GTK or libadwaita.

use std::time::{Duration, Instant, SystemTime};

use paladin_auth_core::{AccountId, AccountKindSummary, Vault, TICK_INTERVAL_MS};

use crate::account_list::AccountRowModel;
use crate::account_row::{project_row, RowDisplay};
use crate::app::state::AppState;
use crate::clipboard_clear::PendingClipboardClear;

/// Per-tick interval for the TOTP ticker.
///
/// Sourced from [`paladin_auth_core::TICK_INTERVAL_MS`] (250 ms today, pinned
/// by `crates/paladin-auth-core/src/ui_contract.rs` and asserted by
/// `crates/paladin-auth-core/tests/ui_contract.rs`). Centralizing the
/// `Duration` conversion here keeps the
/// `glib::timeout_add_local(tick_interval(), ...)` call site short
/// and prevents drift from the TUI ticker (`paladin-auth-tui` uses the
/// same constant). The plan's "Install a single
/// `glib::timeout_add_local` source ticking at
/// `paladin_auth_core::TICK_INTERVAL_MS`" bullet binds to this single
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

/// Compute refreshed [`RowDisplay`] projections for every TOTP row
/// in `rows` against the live `vault` at `now`.
///
/// HOTP rows are skipped because their codes come from the reveal
/// slot on demand (see `paladin_auth_core::policy::hotp_reveal`); a HOTP
/// row never participates in the per-tick refresh set. Output order
/// matches `rows`, not vault insertion order, so the widget layer
/// can index back into the rendered list without re-sorting.
///
/// Two transient-failure paths drop silently rather than blanking
/// the row:
///
/// 1. `row.id` is not present in `vault.summaries()` — a race
///    between a vault mutation (remove / replace) and the timer
///    firing. The widget layer leaves the prior display in place
///    until the next refresh after `AccountListMsg::Refresh`.
/// 2. `vault.totp_code(row.id, now)` returns an error — clock-skew
///    edge cases like a pre-Unix-epoch `now` or `valid_until`
///    overflow. Same rule: the row's prior display stays put.
///
/// The plan's "On each tick, recompute the TOTP gauge value and the
/// visible code from `paladin_auth_core::totp_code(account, now)` for
/// every TOTP row in the current list view" bullet binds to this
/// function. The widget driver fans the returned `(AccountId,
/// RowDisplay)` pairs out to the live row factory under
/// `AccountListMsg::Tick`; the lifecycle (Install / Teardown) is
/// already gated by [`ticker_transition`].
#[must_use]
pub fn compute_tick_displays(
    vault: &Vault,
    rows: &[AccountRowModel],
    now: SystemTime,
) -> Vec<(AccountId, RowDisplay)> {
    rows.iter()
        .filter(|row| matches!(row.kind, AccountKindSummary::Totp))
        .filter_map(|row| {
            let summary = vault.summaries().find(|s| s.id == row.id)?;
            let code = vault.totp_code(row.id, now).ok()?;
            // `Vault::totp_next_code` is a single HMAC — sub-ms —
            // and runs on the same `now` sample as `totp_code` so the
            // projected next-code digits and the current row's
            // gauge `seconds_remaining` stay aligned within the
            // same tick.  `.ok()` so a per-row resolution failure
            // (e.g. the row's account vanished between summary
            // lookup and this call) projects `None` for the Next
            // cell rather than dropping the entire row.
            let next_code = vault.totp_next_code(row.id, now).ok();
            Some((
                row.id,
                project_row(&summary, Some(&code), next_code.as_ref()),
            ))
        })
        .collect()
}

/// Outcome of one ticker firing.
///
/// The widget-layer tick handler in `AppModel` runs three side
/// effects per tick — the TOTP gauge / code refresh ([`compute_tick_displays`]),
/// the clipboard auto-clear policy wake against the live
/// `gdk::Clipboard` text, and (in follow-up commits) the HOTP reveal
/// expiry check — but the decisions for the first two route through
/// [`tick`] so the GTK call sites stay free of timing logic and the
/// pure-logic tests in `tests/ticker_logic.rs` exercise the full
/// per-tick contract without spinning up GTK / libadwaita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickOutcome {
    /// Refreshed [`RowDisplay`] projections for every visible TOTP
    /// row, in caller-supplied row order. The widget driver dispatches
    /// these to [`crate::account_list::AccountListMsg::Tick`] so the
    /// row factory rebinds the affected positions without rebuilding
    /// the `gio::ListStore`.
    pub display_updates: Vec<(AccountId, RowDisplay)>,
    /// `true` iff there is a [`PendingClipboardClear`] entry whose
    /// monotonic `deadline` is `<= monotonic_now`. The widget driver
    /// pairs this hint with a live `gdk::Clipboard::read_text` and
    /// routes the byte-equality decision through
    /// [`crate::clipboard_clear::evaluate_wake`]; `false` means the
    /// pending wipe is still in the future (or there is no pending
    /// wipe at all) and the per-tick wake is a no-op.
    pub clipboard_wake_due: bool,
}

/// Compute the per-tick widget driver effect for `(vault, rows)` at
/// the given wall-clock / monotonic instants.
///
/// Combines [`compute_tick_displays`] with the clipboard auto-clear
/// deadline check so the widget layer makes one call per tick and
/// applies the typed [`TickOutcome`] to the live `gtk::ListView`
/// (display updates) plus the live `gdk::Clipboard` (wake on
/// `clipboard_wake_due`). The two decisions are bundled here rather
/// than split because the call site that drives one always drives
/// the other — keeping them together lets the pure-logic tests pin
/// the joint contract.
///
/// `pending_clipboard` is the live pending-clear slot from the
/// `AppModel`; `None` means the user has not opted in (or no copy
/// is outstanding) and the wake is a no-op. The deadline is checked
/// with `<=` so a wake that lands exactly on the deadline fires
/// (matching the TUI `wake_due` rule); future deadlines stay
/// dormant until the next tick.
#[must_use]
pub fn tick(
    vault: &Vault,
    rows: &[AccountRowModel],
    wall_clock: SystemTime,
    monotonic_now: Instant,
    pending_clipboard: Option<&PendingClipboardClear>,
) -> TickOutcome {
    TickOutcome {
        display_updates: compute_tick_displays(vault, rows, wall_clock),
        clipboard_wake_due: pending_clipboard.is_some_and(|p| p.deadline <= monotonic_now),
    }
}
