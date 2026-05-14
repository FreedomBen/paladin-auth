// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic remove-dialog tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests >
//! `tests/remove_dialog_logic.rs`" checklist in
//! `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * `summary_display_label` matches the CLI / TUI body shape
//!   (`issuer:label` when the issuer is set and non-empty, otherwise
//!   the bare label; `Some("")` collapses to the no-issuer form).
//! * `account_not_found_error` builds the §5 `invalid_state` shape
//!   the `Vault::mutate_and_save` closure passes through when
//!   `Vault::remove` returns `None`.
//! * `save_not_committed` (with and without a rotated `.bak` path)
//!   restores the prior in-memory account (which `mutate_and_save`
//!   does for us) and keeps the dialog open with the inline error.
//! * `save_durability_unconfirmed` keeps the removed-state in memory
//!   and surfaces the warning attached to the dialog body — the
//!   account stays gone, the parent-fsync uncertainty is what
//!   surfaces.
//! * Every other typed error (`invalid_state { state:
//!   "account_not_found" }`, `io_error`, defensive `validation_error`)
//!   stays inline and does not transition the dialog out.
//!
//! The module under test (`paladin_gtk::remove_dialog`) is the pure-
//! logic state machine the GTK `RemoveDialog` shadows. It owns no
//! widgets; the widget layer renders [`summary_display_label`] into
//! the confirmation body, hands [`account_not_found_error`] to the
//! `Vault::mutate_and_save` closure when `Vault::remove` returns
//! `None`, and drives [`classify_remove_error`] on the worker
//! outcome.

use std::io;
use std::path::PathBuf;

use paladin_core::{
    AccountId, AccountKindSummary, AccountSummary, Algorithm, ErrorKind, PaladinError,
};

use paladin_gtk::remove_dialog::{
    account_not_found_error, classify_remove_error, summary_display_label, InlineError,
    InlineWarning, RemoveErrorOutcome,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fixture_summary(label: &str, issuer: Option<&str>) -> AccountSummary {
    AccountSummary {
        id: AccountId::new(),
        issuer: issuer.map(str::to_string),
        label: label.to_string(),
        kind: AccountKindSummary::Totp,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: Some(30),
        counter: None,
        icon_hint: None,
        created_at: 0,
        updated_at: 0,
    }
}

fn save_not_committed_no_backup() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    }
}

fn save_not_committed_with_backup() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: true,
        backup_path: Some(PathBuf::from("/tmp/vault.bin.bak")),
    }
}

// ---------------------------------------------------------------------------
// summary_display_label — CLI / TUI parity for the confirmation body
// ---------------------------------------------------------------------------

#[test]
fn summary_display_label_with_issuer_returns_issuer_colon_label() {
    let summary = fixture_summary("alice@example.com", Some("Example"));
    assert_eq!(summary_display_label(&summary), "Example:alice@example.com");
}

#[test]
fn summary_display_label_without_issuer_returns_bare_label() {
    let summary = fixture_summary("alice@example.com", None);
    assert_eq!(summary_display_label(&summary), "alice@example.com");
}

#[test]
fn summary_display_label_with_empty_issuer_collapses_to_bare_label() {
    // CLI / TUI parity: `Some("")` is treated as "no issuer" so the
    // body never renders a dangling `:label` colon. The §6 import /
    // §4.1 validation paths allow empty issuer strings, so the
    // dialog must tolerate them.
    let summary = fixture_summary("alice@example.com", Some(""));
    assert_eq!(summary_display_label(&summary), "alice@example.com");
}

#[test]
fn summary_display_label_preserves_unicode_issuer_and_label() {
    // §4.1 labels and issuers are unrestricted UTF-8 up to the byte
    // limit; the display helper must not strip / normalize.
    let summary = fixture_summary("café", Some("Société"));
    assert_eq!(summary_display_label(&summary), "Société:café");
}

// ---------------------------------------------------------------------------
// account_not_found_error — defensive closure-side error builder
// ---------------------------------------------------------------------------

#[test]
fn account_not_found_error_uses_remove_operation_tag() {
    // CLI / TUI parity: `Vault::remove` returns `None` for stale
    // ids; the closure inside `Vault::mutate_and_save` maps that to
    // `invalid_state { operation: "remove", state: "account_not_found" }`.
    let err = account_not_found_error();
    let PaladinError::InvalidState { operation, state } = err else {
        panic!("expected InvalidState, got {err:?}");
    };
    assert_eq!(operation, "remove");
    assert_eq!(state, "account_not_found");
}

#[test]
fn account_not_found_error_kind_is_invalid_state() {
    let err = account_not_found_error();
    assert_eq!(err.kind(), ErrorKind::InvalidState);
}

// ---------------------------------------------------------------------------
// classify_remove_error — save-pipeline routing
// ---------------------------------------------------------------------------

#[test]
fn classify_remove_error_save_not_committed_restores_prior() {
    // Per §"Effect errors" > "Add / remove / rename / settings
    // saves": `save_not_committed` rolls back the in-memory removal
    // (mutate_and_save restores the account at its previous position)
    // and the dialog stays open with the inline error so the user
    // can retry.
    let err = save_not_committed_no_backup();
    let outcome = classify_remove_error(&err);
    let RemoveErrorOutcome::RestorePrior(inline) = outcome else {
        panic!("expected RestorePrior, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert!(!inline.rendered.is_empty());
}

#[test]
fn classify_remove_error_save_not_committed_with_backup_restores_prior() {
    // A `save_not_committed` after the backup rotation has run still
    // routes to RestorePrior — the rotated `.bak` is not material to
    // the visible-state rollback for remove, but the routing decision
    // must not depend on whether the backup ran.
    let err = save_not_committed_with_backup();
    let outcome = classify_remove_error(&err);
    let RemoveErrorOutcome::RestorePrior(inline) = outcome else {
        panic!("expected RestorePrior, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
}

#[test]
fn classify_remove_error_save_durability_unconfirmed_keeps_removed_with_warning() {
    // `save_durability_unconfirmed` means the primary rename
    // (rotating the staged file into place) succeeded but the
    // parent-directory fsync failed. The account is gone from disk
    // and from in-memory state; the warning attaches to the dialog
    // body so the user can dismiss it explicitly.
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_remove_error(&err);
    let RemoveErrorOutcome::KeepRemovedWithWarning(warning) = outcome else {
        panic!("expected KeepRemovedWithWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert!(!warning.rendered.is_empty());
}

#[test]
fn classify_remove_error_invalid_state_account_not_found_stays_inline() {
    // Defensive: a stale `AccountId` (the row was removed by another
    // surface between modal-open and submit) surfaces as
    // `invalid_state { operation: "remove", state: "account_not_found" }`
    // from the `Vault::mutate_and_save` closure. The dialog must stay
    // open and render the typed inline error rather than rolling
    // anything back (there is no prior state to restore) or
    // transitioning out.
    let err = account_not_found_error();
    let outcome = classify_remove_error(&err);
    let RemoveErrorOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::InvalidState);
}

#[test]
fn classify_remove_error_io_error_stays_inline() {
    // `io_error` from the save pipeline (e.g. ENOSPC on the staging
    // write) is not a §5 save-pipeline discriminator, so it stays
    // inline. The dialog keeps showing the confirmation gate so the
    // user can retry once disk is freed.
    let err = PaladinError::IoError {
        operation: "save_vault",
        source: io::Error::other("disk full"),
    };
    let outcome = classify_remove_error(&err);
    let RemoveErrorOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::IoError);
    assert!(!inline.rendered.is_empty());
}

#[test]
fn classify_remove_error_validation_error_stays_inline() {
    // Defensive: `Vault::remove` does not re-validate so this only
    // fires if the closure body is changed to validate something
    // before the `remove` call. The dialog must still surface it
    // inline rather than rolling back.
    let err = PaladinError::ValidationError {
        field: "label",
        reason: "too_long".into(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    };
    let outcome = classify_remove_error(&err);
    let RemoveErrorOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

// ---------------------------------------------------------------------------
// InlineError / InlineWarning — projection invariants
// ---------------------------------------------------------------------------

#[test]
fn inline_error_from_error_preserves_kind_and_render() {
    let err = save_not_committed_no_backup();
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, err.kind());
    assert_eq!(inline.rendered, err.to_string());
}

#[test]
fn inline_error_clones_freely_for_reactive_state() {
    // The dialog stores the inline error in its reactive state and
    // re-uses it across re-renders; the type must implement `Clone`
    // without dropping any data.
    let err = save_not_committed_with_backup();
    let inline = InlineError::from_error(&err);
    let cloned = inline.clone();
    assert_eq!(cloned.kind, inline.kind);
    assert_eq!(cloned.rendered, inline.rendered);
}

#[test]
fn inline_warning_from_error_preserves_kind_and_render() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let warning = InlineWarning::from_error(&err);
    assert_eq!(warning.kind, err.kind());
    assert_eq!(warning.rendered, err.to_string());
}

#[test]
fn inline_warning_clones_freely_for_reactive_state() {
    let warning = InlineWarning::from_error(&PaladinError::SaveDurabilityUnconfirmed);
    let cloned = warning.clone();
    assert_eq!(cloned.kind, warning.kind);
    assert_eq!(cloned.rendered, warning.rendered);
}
