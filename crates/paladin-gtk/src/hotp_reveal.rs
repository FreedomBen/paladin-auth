// SPDX-License-Identifier: AGPL-3.0-or-later

//! HOTP reveal-window pure-logic glue for `paladin-gtk`.
//!
//! Per the `docs/IMPLEMENTATION_PLAN_04_GTK.md` checklist under
//! `tests/hotp_reveal_logic.rs` (§"Tests", "Pure-logic unit tests"),
//! the GUI owns the reveal-panel widgetry (label, countdown, "next"
//! button) but every reveal-window timing decision routes through
//! [`paladin_core::hotp_reveal_deadline`], which sources
//! [`paladin_core::HOTP_REVEAL_SECS`] from the shared `ui_contract`.
//!
//! The module also owns the *staged-code* state machine that the
//! reducer applies to the outcome of a `Vault::hotp_advance` worker:
//!
//! * On `Ok(code)` the worker's `Code` is published as the visible
//!   reveal window and any [`StagedCode`] from the pre-advance
//!   `hotp_peek` is dropped (zeroizing its bytes via
//!   [`Zeroizing<String>`]).
//! * On `Err(SaveDurabilityUnconfirmed)` with a [`StagedCode`], the
//!   staged code is published as the visible reveal *and* the caller
//!   surfaces an `AdwToast` durability-unconfirmed warning — DESIGN
//!   §4.3 / §5 `save_durability_unconfirmed`: the user has the new
//!   code in hand even though durability is in question.
//! * On any other `Err(...)` (including pre-commit `SaveNotCommitted`,
//!   which core has already rolled back) the prior reveal window
//!   (if any) is retained and the [`StagedCode`] is dropped, zeroizing
//!   its bytes.
//!
//! The pure-logic helper does **not** drop the prior reveal — the
//! reducer / component layer owns the model state and is responsible
//! for the move that triggers the [`Zeroizing`] wipe on replace.

use std::collections::HashMap;
use std::fmt;
use std::hash::BuildHasher;
use std::time::{Instant, SystemTime};

use zeroize::Zeroizing;

use paladin_core::{
    hotp_reveal_deadline, AccountId, AccountSummary, Code, PaladinError, Store, Vault,
};

use crate::account_row::{project_row, RowDisplay};

/// Compute the HOTP reveal-window deadline relative to `now`.
///
/// Routes through [`paladin_core::hotp_reveal_deadline`]; equivalent
/// to `now + Duration::from_secs(paladin_core::HOTP_REVEAL_SECS)`.
#[must_use]
pub fn deadline(now: Instant) -> Instant {
    hotp_reveal_deadline(now)
}

/// An open HOTP reveal window held on `AppModel::Unlocked`.
///
/// `code` is wrapped in [`Zeroizing<String>`] so dropping the window
/// zeros the displayed digits in place — required by the §"Tests" bullet
/// *"Staged code is zeroized and prior reveal state is retained on
/// `save_not_committed` and other failures"* and parity with the TUI's
/// `HotpReveal::code: SecretString`.
pub struct RevealWindow {
    /// The account whose code is being revealed.
    pub account_id: AccountId,
    /// HOTP counter that produced the visible `code`; the GUI row
    /// renders this in place of the next-counter prompt until the
    /// reveal expires.
    pub counter_used: u64,
    /// Displayed code, zero-padded to the account's digit width.
    /// Wrapped in [`Zeroizing`] so the bytes are wiped on drop.
    pub code: Zeroizing<String>,
    /// Monotonic reveal-window expiry returned by [`deadline`]. On
    /// each timer tick the reducer compares this against the
    /// monotonic clock and closes the reveal when expired.
    pub deadline: Instant,
}

/// Pre-advance code computed by `Vault::hotp_peek` and held by the
/// vault worker until `Vault::hotp_advance` returns.
///
/// Published as the visible reveal only on the
/// `Err(SaveDurabilityUnconfirmed)` path; dropped on every other
/// `Err(...)` and on `Ok(...)`. The `code` field is
/// [`Zeroizing<String>`] so dropping the staged value zeros its bytes
/// in place.
pub struct StagedCode {
    /// The HOTP counter the staged code corresponds to.
    pub counter_used: u64,
    /// The staged code's digits, wrapped in [`Zeroizing`] so the
    /// bytes are wiped on drop.
    pub code: Zeroizing<String>,
}

impl StagedCode {
    /// Construct a [`StagedCode`] from a `Code` returned by
    /// `Vault::hotp_peek`. Returns `None` when `counter_used` is
    /// `None` (a TOTP projection); the caller MUST NOT stage a TOTP
    /// projection as an HOTP reveal.
    #[must_use]
    pub fn from_code(code: Code) -> Option<Self> {
        Some(Self {
            counter_used: code.counter_used?,
            code: Zeroizing::new(code.code),
        })
    }
}

/// Outcome of a `Vault::hotp_advance` worker, posted back to the
/// reducer with the pre-advance staged code (if any).
pub struct AdvanceOutcome {
    /// The account whose counter the worker tried to advance.
    pub account_id: AccountId,
    /// The `Vault::hotp_advance` outcome.
    pub result: Result<Code, PaladinError>,
    /// Pre-advance code computed by `Vault::hotp_peek`. Published as
    /// the visible reveal only on `Err(SaveDurabilityUnconfirmed)`;
    /// dropped (zeroizing its bytes) on every other path.
    pub staged_code: Option<StagedCode>,
    /// Monotonic clock sampled immediately after the advance
    /// returned; the reducer feeds this into [`deadline`] to compute
    /// the reveal-window expiry.
    pub completed_at: Instant,
}

/// Decision returned by [`apply_advance_outcome`].
///
/// The reducer applies one of three outcomes:
///
/// * [`AdvanceDecision::Replace`] — open or replace the visible
///   reveal window with the freshly returned code. The reducer drops
///   any prior reveal (which zeros its bytes via [`Zeroizing`]).
/// * [`AdvanceDecision::ReplaceWithDurabilityWarning`] — same, but
///   built from the [`StagedCode`] and accompanied by a durability-
///   unconfirmed `AdwToast` warning. Use this only on the
///   `Err(SaveDurabilityUnconfirmed)` path.
/// * [`AdvanceDecision::Retain`] — leave the prior reveal in place;
///   the staged code (if any) has been moved into the decision and
///   dropped, zeroizing its bytes.
pub enum AdvanceDecision {
    /// Open or replace the visible reveal window with the carried
    /// [`RevealWindow`]. The reducer drops the prior reveal (if any),
    /// zeroizing its bytes.
    Replace(RevealWindow),
    /// Open or replace the visible reveal window with the carried
    /// [`RevealWindow`] and surface an `AdwToast` durability-
    /// unconfirmed warning.
    ReplaceWithDurabilityWarning(RevealWindow),
    /// Retain the prior reveal window. The staged code (if any) has
    /// been dropped, zeroizing its bytes.
    Retain,
}

/// Apply an HOTP advance outcome to decide what to do with the
/// visible reveal window.
///
/// See [`AdvanceDecision`] for the routing table. The function takes
/// `outcome` by value so the staged code (and the `Err(...)` payload)
/// drop here on the `Retain` paths — zeroizing the staged bytes via
/// [`Zeroizing<String>`].
#[must_use]
pub fn apply_advance_outcome(outcome: AdvanceOutcome) -> AdvanceDecision {
    let AdvanceOutcome {
        account_id,
        result,
        staged_code,
        completed_at,
    } = outcome;
    let expiry = deadline(completed_at);
    match result {
        Ok(code) => {
            // Defensive: a TOTP projection has `counter_used: None`;
            // the worker should never deliver one on the HOTP path,
            // but if it does, retain the prior reveal rather than
            // staging garbage. `staged_code` drops here either way.
            let Some(counter_used) = code.counter_used else {
                drop(staged_code);
                return AdvanceDecision::Retain;
            };
            drop(staged_code);
            AdvanceDecision::Replace(RevealWindow {
                account_id,
                counter_used,
                code: Zeroizing::new(code.code),
                deadline: expiry,
            })
        }
        Err(PaladinError::SaveDurabilityUnconfirmed) => match staged_code {
            Some(staged) => AdvanceDecision::ReplaceWithDurabilityWarning(RevealWindow {
                account_id,
                counter_used: staged.counter_used,
                code: staged.code,
                deadline: expiry,
            }),
            None => AdvanceDecision::Retain,
        },
        Err(_) => {
            drop(staged_code);
            AdvanceDecision::Retain
        }
    }
}

// Manual `Debug` impls for the worker types — Vault / Store redact
// their secrets via their own `Debug` impls in `paladin_core`, but
// `Zeroizing<String>` would print the code bytes via `Deref`, so we
// redact the code fields here per docs/DESIGN.md §"Memory hygiene".

impl fmt::Debug for RevealWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevealWindow")
            .field("account_id", &self.account_id)
            .field("counter_used", &self.counter_used)
            .field("code", &"<redacted>")
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl fmt::Debug for StagedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedCode")
            .field("counter_used", &self.counter_used)
            .field("code", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for AdvanceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdvanceOutcome")
            .field("account_id", &self.account_id)
            .field("result", &self.result.as_ref().map(|_| "<redacted>"))
            .field("staged_code", &self.staged_code)
            .field("completed_at", &self.completed_at)
            .finish()
    }
}

impl fmt::Debug for AdvanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replace(w) => f.debug_tuple("Replace").field(w).finish(),
            Self::ReplaceWithDurabilityWarning(w) => f
                .debug_tuple("ReplaceWithDurabilityWarning")
                .field(w)
                .finish(),
            Self::Retain => f.debug_struct("Retain").finish(),
        }
    }
}

impl fmt::Debug for HotpAdvanceWorkerInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HotpAdvanceWorkerInput")
            .field("vault", &"<redacted>")
            .field("store", &self.store)
            .field("account_id", &self.account_id)
            .field("now", &self.now)
            .finish()
    }
}

impl fmt::Debug for HotpAdvanceWorkerCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HotpAdvanceWorkerCompletion")
            .field("outcome", &self.outcome)
            .field("vault", &"<redacted>")
            .field("store", &self.store)
            .finish()
    }
}

/// Inputs consumed by [`run_hotp_advance_worker`] when
/// `AppModel::update` fires the `gio::spawn_blocking
/// Vault::hotp_advance` worker from the row's "next" button
/// activation per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7
/// checklist" > HOTP reveal window behavior.
///
/// The live `(Vault, Store)` pair is moved into the worker so
/// `mutate_and_save` can borrow `vault` mutably without keeping
/// `AppModel` in `Unlocked` for the duration of the call. The pair
/// returns inside [`HotpAdvanceWorkerCompletion`] for reinstall on
/// every outcome.
pub struct HotpAdvanceWorkerInput {
    /// Live vault from the `Unlocked` `(Vault, Store)` pair. Moved
    /// into the worker so `hotp_advance` can take `&mut self`
    /// without keeping `AppModel` in `Unlocked` for the duration.
    pub vault: Vault,
    /// Live store from the `Unlocked` `(Vault, Store)` pair. Moved
    /// alongside `vault` so the same `(Vault, Store)` pair returns
    /// from the worker even on typed failure.
    pub store: Store,
    /// Account whose counter the worker advances. Forwarded to both
    /// `Vault::hotp_peek` (for the pre-advance staged code) and
    /// `Vault::hotp_advance`.
    pub account_id: AccountId,
    /// Wall-clock the worker hands to `Vault::hotp_advance` as the
    /// new `updated_at`. `AppModel::update` captures
    /// `SystemTime::now()` at the dispatch site so the worker
    /// thread does not race against later wall-clock drift.
    pub now: SystemTime,
}

/// Bundle returned by [`run_hotp_advance_worker`] for
/// `AppModel::update` to apply.
///
/// The `outcome` field plugs straight into [`apply_advance_outcome`]
/// to drive the reveal-window state machine; `vault` / `store`
/// reinstall the `(Vault, Store)` pair on `AppModel::vault`
/// regardless of typed outcome (mirroring the
/// `rename_dialog::RenameWorkerCompletion` shape — the busy gate
/// always releases because `mutate_and_save` is authoritative for
/// the rollback / durability-unconfirmed semantics).
pub struct HotpAdvanceWorkerCompletion {
    /// Typed `AdvanceOutcome` carrying the pre-advance staged code
    /// and the `Vault::hotp_advance` `Result`. Consumed by
    /// [`apply_advance_outcome`].
    pub outcome: AdvanceOutcome,
    /// Live vault returned from the worker so `AppModel::update` can
    /// reinstall the `(Vault, Store)` pair on every effect branch.
    pub vault: Vault,
    /// Live store returned alongside `vault`.
    pub store: Store,
}

/// Body text for the `AdwToast` raised on the
/// `Err(SaveDurabilityUnconfirmed)` HOTP-advance path.
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist"
/// bullet *"On `save_durability_unconfirmed`, additionally post an
/// `AdwToast` carrying the committed-but-uncertain warning so the
/// row stays usable with the new code in hand."* Sibling of the
/// `format_settings_dialog_saved_toast` helper for toast bodies that
/// stay reachable from tests without spinning up libadwaita.
#[must_use]
pub fn format_hotp_durability_unconfirmed_toast() -> &'static str {
    "Counter advanced, but durability could not be confirmed."
}

/// Body text for the `AdwToast` raised on every non-durability
/// HOTP-advance failure (pre-commit `SaveNotCommitted` and any other
/// typed error).
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist"
/// bullet *"On worker pre-commit failure (`save_not_committed`) or
/// any other typed error, leave the previous reveal state unchanged
/// …, zeroize the staged code, and surface the inline / status
/// error."*
#[must_use]
pub fn format_hotp_advance_failed_toast() -> &'static str {
    "Could not advance HOTP counter."
}

/// Side-effect summary returned by [`apply_advance_decision`].
///
/// The widget layer uses this to decide whether to:
///
/// * Re-bind the affected row through the live display cache
///   ([`RevealEffect::Refreshed`] — a new reveal window is in place).
/// * Surface an `AdwToast` durability-unconfirmed warning
///   ([`show_toast = true`](RevealEffect::Refreshed) on the
///   `Err(SaveDurabilityUnconfirmed)` path).
/// * Leave the live display cache alone ([`RevealEffect::Retained`]
///   — the prior reveal stays in place and the staged code (if any)
///   has been zeroized inside the decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealEffect {
    /// The reveal-window map gained a fresh entry for the affected
    /// account (or replaced the prior entry, zeroizing its bytes via
    /// [`Zeroizing`]).
    Refreshed {
        /// `true` iff the caller should also raise the
        /// durability-unconfirmed `AdwToast` (the
        /// `Err(SaveDurabilityUnconfirmed)` branch of
        /// [`apply_advance_outcome`]).
        show_toast: bool,
    },
    /// The reveal-window map is unchanged — the staged code (if any)
    /// has been dropped inside the decision.
    Retained,
}

/// Insert / replace the reveal window in `windows` per the
/// `AdvanceDecision` returned by [`apply_advance_outcome`].
///
/// Replacing a prior entry for the same `AccountId` drops the old
/// [`RevealWindow`], which zeroes its `code` bytes via
/// [`Zeroizing<String>`]. The [`AdvanceDecision::Retain`] branch
/// leaves the map untouched.
///
/// Returns a [`RevealEffect`] so the caller knows which side-effects
/// (cache rebind, durability-warning toast) to apply.
pub fn apply_advance_decision<S: BuildHasher>(
    windows: &mut HashMap<AccountId, RevealWindow, S>,
    decision: AdvanceDecision,
) -> RevealEffect {
    match decision {
        AdvanceDecision::Replace(window) => {
            windows.insert(window.account_id, window);
            RevealEffect::Refreshed { show_toast: false }
        }
        AdvanceDecision::ReplaceWithDurabilityWarning(window) => {
            windows.insert(window.account_id, window);
            RevealEffect::Refreshed { show_toast: true }
        }
        AdvanceDecision::Retain => RevealEffect::Retained,
    }
}

/// Return the [`AccountId`]s of every reveal window whose deadline
/// has elapsed at `now`.
///
/// The widget driver passes the result to the live row factory under
/// [`crate::account_list::AccountListMsg::Tick`] (paired with hidden
/// [`RowDisplay`] projections) and removes the matching windows from
/// the [`AppModel`] state so the displayed code clears.
///
/// Deadlines compare with `>=` so a tick that lands exactly on the
/// deadline closes the reveal — matching the TUI's `wake_due` rule.
#[must_use]
pub fn expired_reveals<S: BuildHasher>(
    windows: &HashMap<AccountId, RevealWindow, S>,
    now: Instant,
) -> Vec<AccountId> {
    windows
        .iter()
        .filter_map(|(id, w)| (now >= w.deadline).then_some(*id))
        .collect()
}

/// Project an [`AccountSummary`] + open [`RevealWindow`] into the
/// [`RowDisplay`] the live cache stores.
///
/// Builds a synthetic [`Code`] from the reveal window's
/// `counter_used` / `code` so the widget layer can blindly re-bind
/// through [`crate::account_list::bind_display_for_row`] without
/// re-projecting the live `Vault`. The `Code.code` clone leaks the
/// reveal bytes into a non-zeroizing string — by the time the row
/// is rendered the visible digits are already in widget memory, so
/// the leak is bounded to the lifetime of the live display cache
/// entry (which is replaced on the next reveal or hidden when the
/// reveal expires).
#[must_use]
pub fn row_display_for_reveal(summary: &AccountSummary, window: &RevealWindow) -> RowDisplay {
    let code = Code {
        code: window.code.to_string(),
        valid_from: None,
        valid_until: None,
        seconds_remaining: None,
        counter_used: Some(window.counter_used),
    };
    project_row(summary, Some(&code))
}

/// Synchronous body of the `gio::spawn_blocking Vault::hotp_advance`
/// worker fired by `AppModel::update` on a row "next" press.
///
/// Per the `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist"
/// HOTP reveal-window bullet *"On row activation of 'next', stage
/// the would-be visible Code from `Vault::hotp_peek` into a
/// zeroizing pending slot before calling `Vault::hotp_advance`
/// inside the spawn-blocking worker"*, the worker:
///
/// 1. Calls `Vault::hotp_peek(account_id)` to compute the code at
///    the *current* next counter. Failure (e.g. `account_not_found`
///    on a mid-flight removal, or a TOTP projection) leaves
///    `staged_code` as `None` — `apply_advance_outcome` routes the
///    subsequent `Err(...)` to [`AdvanceDecision::Retain`].
/// 2. Calls `Vault::hotp_advance(&store, account_id, now)` which
///    advances the counter and persists via `mutate_and_save`.
/// 3. Captures `Instant::now()` as `completed_at` so the reducer
///    can rebase the reveal-window expiry through [`deadline`].
///
/// Extracting the worker body as a pure function lets
/// `AppModel::update`'s closure stay a thin
/// `gio::spawn_blocking(move || run_hotp_advance_worker(input))`
/// while the real `mutate_and_save` call stays unit-testable in
/// `tests/hotp_reveal_logic.rs` against tempfile-backed plaintext
/// vaults.
#[must_use]
pub fn run_hotp_advance_worker(input: HotpAdvanceWorkerInput) -> HotpAdvanceWorkerCompletion {
    let HotpAdvanceWorkerInput {
        mut vault,
        store,
        account_id,
        now,
    } = input;
    let staged_code = vault
        .hotp_peek(account_id)
        .ok()
        .and_then(StagedCode::from_code);
    let result = vault.hotp_advance(&store, account_id, now);
    let completed_at = Instant::now();
    HotpAdvanceWorkerCompletion {
        outcome: AdvanceOutcome {
            account_id,
            result,
            staged_code,
            completed_at,
        },
        vault,
        store,
    }
}
