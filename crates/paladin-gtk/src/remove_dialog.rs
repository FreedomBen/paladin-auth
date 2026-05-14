// SPDX-License-Identifier: AGPL-3.0-or-later

//! Remove-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `RemoveDialog` and §"Effect errors" > "Add / remove / rename /
//! settings saves", `RemoveDialog` is the confirmation gate before
//! calling `Vault::remove` inside `Vault::mutate_and_save`. The
//! widget layer hosts the destructive `AdwAlertDialog` chrome; the
//! pure-logic helpers here own the display-label formatting, the
//! defensive `account_not_found` error builder, and the post-effect
//! routing decision so they can be unit-tested in
//! `tests/remove_dialog_logic.rs` without spinning up GTK /
//! libadwaita.
//!
//! # Confirmation body
//!
//! [`summary_display_label`] renders the `<issuer>:<label>` body
//! shape the CLI and TUI both use (with `Some("")` collapsing to the
//! no-issuer form so the body never renders a dangling `:label`
//! colon). The dialog reads the result directly into its
//! confirmation prompt so wording matches the CLI / TUI verbatim.
//!
//! # Closure-side defensive error
//!
//! `Vault::remove(id)` returns `Option<Account>` — `None` for stale
//! ids. The `Vault::mutate_and_save` closure maps that `None` to
//! [`account_not_found_error`], which builds the §5 `invalid_state
//! { operation: "remove", state: "account_not_found" }` shape used
//! by the CLI / TUI for the same defensive path.
//!
//! # Post-effect routing
//!
//! [`classify_remove_error`] maps the [`PaladinError`] from a failed
//! `mutate_and_save` onto the dialog's three-way routing decision:
//!
//! * `save_not_committed` → [`RemoveErrorOutcome::RestorePrior`]
//!   (the commit never landed; `mutate_and_save` already restored
//!   the account at its previous position, and the dialog stays
//!   open with the inline error so the user can retry).
//! * `save_durability_unconfirmed` →
//!   [`RemoveErrorOutcome::KeepRemovedWithWarning`] (the remove
//!   committed to disk but parent-fsync failed; the account stays
//!   gone and the warning attaches to the dialog body).
//! * Anything else (defensive: `invalid_state { state:
//!   "account_not_found" }`, `io_error`, `validation_error`, …) →
//!   [`RemoveErrorOutcome::InlineError`] without transitioning the
//!   dialog out.

use paladin_core::{AccountSummary, ErrorKind, PaladinError};

/// Render the dialog's confirmation body label.
///
/// Returns `<issuer>:<label>` when `issuer` is `Some(non_empty)` and
/// the bare `label` otherwise. CLI / TUI parity: `Some("")` collapses
/// to the no-issuer form so the body never renders a dangling
/// `:label` colon for accounts imported / created without an issuer.
#[must_use]
pub fn summary_display_label(summary: &AccountSummary) -> String {
    match summary.issuer.as_deref().filter(|i| !i.is_empty()) {
        Some(issuer) => format!("{issuer}:{}", summary.label),
        None => summary.label.clone(),
    }
}

/// Build the defensive `account_not_found` error used inside the
/// `Vault::mutate_and_save` closure when `Vault::remove` returns
/// `None`.
///
/// Matches the CLI / TUI not-found shape exactly: `invalid_state
/// { operation: "remove", state: "account_not_found" }`.
#[must_use]
pub fn account_not_found_error() -> PaladinError {
    PaladinError::InvalidState {
        operation: "remove",
        state: "account_not_found",
    }
}

/// Post-effect routing decision for a failed
/// `Vault::mutate_and_save(|v| v.remove(...))`.
///
/// See [`classify_remove_error`].
#[derive(Debug, Clone)]
pub enum RemoveErrorOutcome {
    /// `save_not_committed` — the remove never committed to disk.
    /// `mutate_and_save` already restored the account at its previous
    /// position; the dialog stays open and shows the typed inline
    /// error.
    RestorePrior(InlineError),
    /// `save_durability_unconfirmed` — primary save succeeded but
    /// parent-fsync failed. The account stays removed in memory and
    /// the warning attaches to the dialog body.
    KeepRemovedWithWarning(InlineWarning),
    /// Defensive: any other typed error stays inline and does not
    /// transition the dialog out. Hits `invalid_state { state:
    /// "account_not_found" }` when the targeted account is removed
    /// mid-flight.
    InlineError(InlineError),
}

/// Classify a [`Vault::mutate_and_save`] failure into a
/// [`RemoveErrorOutcome`].
///
/// Routes the §5 save-pipeline discriminators (`save_not_committed`
/// → [`RemoveErrorOutcome::RestorePrior`],
/// `save_durability_unconfirmed` →
/// [`RemoveErrorOutcome::KeepRemovedWithWarning`]) and falls back to
/// an inline error for every other typed variant so the dialog
/// never silently transitions out.
#[must_use]
pub fn classify_remove_error(err: &PaladinError) -> RemoveErrorOutcome {
    match err.kind() {
        ErrorKind::SaveNotCommitted => {
            RemoveErrorOutcome::RestorePrior(InlineError::from_error(err))
        }
        ErrorKind::SaveDurabilityUnconfirmed => {
            RemoveErrorOutcome::KeepRemovedWithWarning(InlineWarning::from_error(err))
        }
        _ => RemoveErrorOutcome::InlineError(InlineError::from_error(err)),
    }
}

/// Inline-error projection for the `RemoveDialog` body.
///
/// Carries the stable §5 [`ErrorKind`] for instrumentation and the
/// rendered body for display. No source-error reference is kept so
/// the model can be cloned freely into the dialog's reactive state.
#[derive(Debug, Clone)]
pub struct InlineError {
    /// Stable §5 [`ErrorKind`] discriminator copied from
    /// [`PaladinError::kind`].
    pub kind: ErrorKind,
    /// Display body. Renders through [`std::fmt::Display`] so the
    /// wording stays in sync with the CLI / TUI verbatim.
    pub rendered: String,
}

impl InlineError {
    /// Build an [`InlineError`] from a [`PaladinError`].
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}

/// Durability-warning projection for the `RemoveDialog` body.
///
/// Returned by [`classify_remove_error`] on
/// `save_durability_unconfirmed`: the remove committed to disk, but
/// the parent-directory `fsync` failed, so the account stays gone
/// from in-memory state while the warning sits beneath the
/// confirmation body.
#[derive(Debug, Clone)]
pub struct InlineWarning {
    /// Stable §5 [`ErrorKind`] discriminator — always
    /// [`ErrorKind::SaveDurabilityUnconfirmed`] in current code.
    pub kind: ErrorKind,
    /// Display body. Renders through [`std::fmt::Display`] so the
    /// wording stays in sync with the CLI / TUI verbatim.
    pub rendered: String,
}

impl InlineWarning {
    /// Build an [`InlineWarning`] from a [`PaladinError`].
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}
