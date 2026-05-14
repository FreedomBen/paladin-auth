// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rename-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" > Rename
//! dialog and §"Effect errors" > "Add / remove / rename / settings
//! saves", `RenameDialog` edits the label of an existing account
//! and routes the worker outcome of
//! `Vault::mutate_and_save(|v| v.rename(id, label, now))` back into
//! either a successful commit, a pre-commit rollback, or a durability-
//! warning surface. The widget layer hosts an [`adw::EntryRow`] for
//! the label and a non-editable issuer display (CLI parity with
//! `paladin rename <new-label>`); the pure-logic helpers here own
//! the validation and post-effect routing decisions so they can be
//! unit-tested in `tests/rename_dialog_logic.rs` without spinning up
//! GTK / libadwaita.
//!
//! # Pre-submit validation
//!
//! [`classify_submit`] re-runs [`paladin_core::validate_label`] on
//! the draft text. Empty / overlong inputs surface as inline errors
//! with the §5 `validation_error` discriminator and the typed body
//! text; the dialog stays open until the user fixes the input.
//!
//! # Same-label submission
//!
//! [`classify_submit`] takes only the draft label. There is no
//! prior-label comparison and therefore no silent short-circuit, so
//! re-submitting an unchanged label still goes through
//! `Vault::rename` inside `Vault::mutate_and_save` and bumps
//! `updated_at`, matching the CLI `paladin rename` contract.
//!
//! # Post-effect routing
//!
//! [`classify_rename_error`] maps the [`PaladinError`] from a failed
//! `mutate_and_save` onto the dialog's three-way routing decision:
//!
//! * `save_not_committed` → [`RenameErrorOutcome::RestorePrior`]
//!   (commit never landed; the dialog rolls the visible label back to
//!   the pre-submit value and shows the typed inline error).
//! * `save_durability_unconfirmed` →
//!   [`RenameErrorOutcome::KeepNewWithWarning`] (commit landed but
//!   parent-fsync failed; the visible label stays on the new value
//!   and a warning attaches to the dialog body).
//! * Anything else (defensive: `validation_error`, `invalid_state`,
//!   …) → [`RenameErrorOutcome::InlineError`] without transitioning
//!   out of the dialog.

use paladin_core::{validate_label, ErrorKind, PaladinError};

/// Pre-submit validation outcome.
///
/// See [`classify_submit`].
#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    /// Validated, trimmed label ready for the rename worker. The
    /// dialog hands this through `Vault::mutate_and_save` so
    /// `updated_at` always bumps — see the same-label note in the
    /// module docs.
    Proceed(String),
    /// §4.1 validation failed. The dialog stays open and renders the
    /// inline error in the label-field error area.
    InlineError(InlineError),
}

/// Pre-submit validate the raw label entry. Trims whitespace,
/// rejects empty / overlong (§4.1 / §5 `validation_error`) inline.
///
/// The helper takes only the draft — there is no prior-label
/// comparison and therefore no silent short-circuit. The widget
/// layer always emits the rename effect on [`SubmitOutcome::Proceed`]
/// so `Vault::rename` bumps `updated_at` even on a no-op rename.
#[must_use]
pub fn classify_submit(raw_label: &str) -> SubmitOutcome {
    match validate_label(raw_label) {
        Ok(trimmed) => SubmitOutcome::Proceed(trimmed),
        Err(err) => SubmitOutcome::InlineError(InlineError::from_error(&err)),
    }
}

/// Post-effect routing decision for a failed
/// `Vault::mutate_and_save(|v| v.rename(...))`.
///
/// See [`classify_rename_error`].
#[derive(Debug, Clone)]
pub enum RenameErrorOutcome {
    /// `save_not_committed` — the rename never committed to disk.
    /// The dialog rolls the visible label back to the pre-submit
    /// value and shows the typed inline error.
    RestorePrior(InlineError),
    /// `save_durability_unconfirmed` — primary rename succeeded but
    /// parent-fsync failed. The visible label stays on the new value
    /// and the warning attaches to the dialog body.
    KeepNewWithWarning(InlineWarning),
    /// Defensive: any other typed error stays inline and does not
    /// transition the dialog out. Hits `validation_error` only if
    /// the widget layer bypasses [`classify_submit`], and
    /// `invalid_state { state: "account_not_found" }` only if the
    /// targeted account is removed mid-flight.
    InlineError(InlineError),
}

/// Classify a [`Vault::mutate_and_save`] failure into a
/// [`RenameErrorOutcome`].
///
/// Routes the §5 save-pipeline discriminators (`save_not_committed`
/// → [`RenameErrorOutcome::RestorePrior`],
/// `save_durability_unconfirmed` →
/// [`RenameErrorOutcome::KeepNewWithWarning`]) and falls back to an
/// inline error for every other typed variant so the dialog never
/// silently transitions out.
#[must_use]
pub fn classify_rename_error(err: &PaladinError) -> RenameErrorOutcome {
    match err.kind() {
        ErrorKind::SaveNotCommitted => {
            RenameErrorOutcome::RestorePrior(InlineError::from_error(err))
        }
        ErrorKind::SaveDurabilityUnconfirmed => {
            RenameErrorOutcome::KeepNewWithWarning(InlineWarning::from_error(err))
        }
        _ => RenameErrorOutcome::InlineError(InlineError::from_error(err)),
    }
}

/// Inline-error projection for the `RenameDialog` body.
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

/// Durability-warning projection for the `RenameDialog` body.
///
/// Returned by [`classify_rename_error`] on
/// `save_durability_unconfirmed`: the rename committed to disk, but
/// the parent-directory `fsync` failed, so the visible label stays
/// on the new value while the warning sits beneath it.
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
