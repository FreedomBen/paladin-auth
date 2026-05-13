// SPDX-License-Identifier: AGPL-3.0-or-later

//! HOTP reveal-window pure-logic glue for `paladin-gtk`.
//!
//! Per the `IMPLEMENTATION_PLAN_04_GTK.md` checklist under
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

use std::time::Instant;

use zeroize::Zeroizing;

use paladin_core::{hotp_reveal_deadline, AccountId, Code, PaladinError};

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
