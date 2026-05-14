// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic rename-dialog tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/rename_dialog_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Label validation (non-empty, §4.1 length limits) blocks submit
//!   inline.
//! * Issuer is not editable (CLI parity with `rename <new-label>`).
//! * Submitting with the new label equal to the current label still
//!   calls `Vault::rename` inside `Vault::mutate_and_save` (no silent
//!   short-circuit, so `updated_at` always bumps).
//! * `save_not_committed` restores the prior label in memory and
//!   keeps the dialog open with the inline error.
//! * `save_durability_unconfirmed` keeps the new label in memory and
//!   surfaces the warning attached to the dialog body.
//!
//! The module under test (`paladin_gtk::rename_dialog`) is the pure-
//! logic state machine the GTK `RenameDialog` shadows. It owns no
//! widgets; the widget layer drives `classify_submit` on the typed
//! draft and `classify_rename_error` on the worker outcome, then
//! reacts to the [`RenameErrorOutcome`] routing decision.

use std::path::PathBuf;

use paladin_core::{ErrorKind, PaladinError};

use paladin_gtk::rename_dialog::{
    classify_rename_error, classify_submit, InlineError, InlineWarning, RenameErrorOutcome,
    SubmitOutcome,
};

/// §4.1 label length cap. The constant is internal to
/// `paladin_core::domain::validation`; mirrored here so the tests
/// exercise the boundary in terms a reader can verify directly
/// against §4.1.
const LABEL_MAX_BYTES: usize = 128;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
// classify_submit — §4.1 label validation gates submission inline
// ---------------------------------------------------------------------------

#[test]
fn classify_submit_empty_label_rejects_inline() {
    let outcome = classify_submit("");
    let SubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

#[test]
fn classify_submit_whitespace_only_label_rejects_inline_as_empty() {
    // §4.1: validate_label trims Unicode whitespace then rejects
    // empty results. The dialog must surface the typed empty-label
    // rejection, not "too_long" or a generic fallback.
    let outcome = classify_submit("   \t  ");
    let SubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    // The inline body must reference the field/reason wire codes so
    // the dialog wording matches the CLI / TUI verbatim.
    assert!(inline.rendered.contains("label"));
    assert!(inline.rendered.contains("empty"));
}

#[test]
fn classify_submit_overlong_label_rejects_inline() {
    let raw = "x".repeat(LABEL_MAX_BYTES + 1);
    let outcome = classify_submit(&raw);
    let SubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("label"));
    assert!(inline.rendered.contains("too_long"));
}

#[test]
fn classify_submit_at_max_length_proceeds() {
    // Exactly LABEL_MAX_BYTES bytes after trim is allowed by §4.1.
    let raw = "y".repeat(LABEL_MAX_BYTES);
    let outcome = classify_submit(&raw);
    let SubmitOutcome::Proceed(trimmed) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    assert_eq!(trimmed.len(), LABEL_MAX_BYTES);
}

#[test]
fn classify_submit_trims_surrounding_whitespace() {
    let outcome = classify_submit("   Acme:user   ");
    let SubmitOutcome::Proceed(trimmed) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    assert_eq!(trimmed, "Acme:user");
}

#[test]
fn classify_submit_valid_label_proceeds() {
    let outcome = classify_submit("Acme:user");
    let SubmitOutcome::Proceed(trimmed) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    assert_eq!(trimmed, "Acme:user");
}

// ---------------------------------------------------------------------------
// Issuer not editable — CLI parity with `rename <new-label>`
// ---------------------------------------------------------------------------

#[test]
fn submit_signature_only_takes_label_no_issuer_field() {
    // CLI parity per `paladin rename <query> <new-label>`: the
    // dialog edits the label only; issuer is read-only and never
    // threaded through this helper. Assigning `classify_submit` to a
    // single-argument function pointer makes that signature contract
    // explicit at compile time — adding an issuer parameter would
    // break the type-check below.
    const _SUBMIT_API: fn(&str) -> SubmitOutcome = classify_submit;
}

// ---------------------------------------------------------------------------
// Same-as-prior submission still proceeds (no silent short-circuit)
// ---------------------------------------------------------------------------

#[test]
fn classify_submit_with_label_matching_prior_still_proceeds() {
    // The helper takes only the new draft — there is no prior-label
    // comparison and therefore no short-circuit. The dialog still
    // emits the rename effect, and `Vault::mutate_and_save` bumps
    // `updated_at` on every commit, matching the CLI
    // `paladin rename` contract.
    let prior = "Acme:user";
    let outcome = classify_submit(prior);
    let SubmitOutcome::Proceed(trimmed) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    assert_eq!(trimmed, prior);
}

#[test]
fn classify_submit_with_label_matching_prior_after_trim_still_proceeds() {
    // Same-as-prior including extra whitespace still resolves to the
    // same trimmed value the prior label was stored as, but the
    // dialog must still go through `Vault::rename` so `updated_at`
    // bumps even when the visible label is unchanged.
    let outcome = classify_submit("  Acme:user  ");
    let SubmitOutcome::Proceed(trimmed) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    assert_eq!(trimmed, "Acme:user");
}

// ---------------------------------------------------------------------------
// classify_rename_error — save_not_committed restores prior label
// ---------------------------------------------------------------------------

#[test]
fn classify_rename_error_save_not_committed_restores_prior() {
    let err = save_not_committed_no_backup();
    let outcome = classify_rename_error(&err);
    let RenameErrorOutcome::RestorePrior(inline) = outcome else {
        panic!("expected RestorePrior, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
}

#[test]
fn classify_rename_error_save_not_committed_with_backup_restores_prior() {
    // A `save_not_committed` after the backup rotation has run still
    // routes to RestorePrior — the dialog rolls the visible label
    // back. The rotated `.bak` path is not material to the
    // visible-state rollback for rename, but the routing decision
    // must not depend on whether the backup ran.
    let err = save_not_committed_with_backup();
    let outcome = classify_rename_error(&err);
    let RenameErrorOutcome::RestorePrior(inline) = outcome else {
        panic!("expected RestorePrior, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
}

// ---------------------------------------------------------------------------
// classify_rename_error — save_durability_unconfirmed keeps new label
// ---------------------------------------------------------------------------

#[test]
fn classify_rename_error_save_durability_unconfirmed_keeps_new_label() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_rename_error(&err);
    let RenameErrorOutcome::KeepNewWithWarning(warning) = outcome else {
        panic!("expected KeepNewWithWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    // Body must surface non-empty text so the dialog can show it.
    assert!(!warning.rendered.is_empty());
}

// ---------------------------------------------------------------------------
// classify_rename_error — defensive: other errors stay inline
// ---------------------------------------------------------------------------

#[test]
fn classify_rename_error_invalid_state_stays_inline() {
    // Defensive: a missing-account race after the modal opened would
    // surface `invalid_state { operation: "rename", state:
    // "account_not_found" }`. The dialog stays open and shows the
    // typed inline error rather than transitioning out.
    let err = PaladinError::InvalidState {
        operation: "rename",
        state: "account_not_found",
    };
    let outcome = classify_rename_error(&err);
    let RenameErrorOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::InvalidState);
}

#[test]
fn classify_rename_error_validation_error_stays_inline() {
    // Defensive: `Vault::rename` re-validates the label so this only
    // fires if the dialog's pre-submit check is bypassed. The dialog
    // must still show it inline rather than rolling back.
    let err = PaladinError::ValidationError {
        field: "label",
        reason: "too_long".into(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    };
    let outcome = classify_rename_error(&err);
    let RenameErrorOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

// ---------------------------------------------------------------------------
// InlineError / InlineWarning rendering
// ---------------------------------------------------------------------------

#[test]
fn inline_error_renders_non_empty_for_save_not_committed() {
    let err = save_not_committed_no_backup();
    let outcome = classify_rename_error(&err);
    let RenameErrorOutcome::RestorePrior(inline) = outcome else {
        panic!("expected RestorePrior");
    };
    assert!(!inline.rendered.is_empty());
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
fn inline_warning_clones_freely_for_reactive_state() {
    let warning = InlineWarning::from_error(&PaladinError::SaveDurabilityUnconfirmed);
    let cloned = warning.clone();
    assert_eq!(cloned.kind, warning.kind);
    assert_eq!(cloned.rendered, warning.rendered);
}
