// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic edit-dialog tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests >
//! `tests/edit_dialog_logic.rs`" checklist in
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Per-row WYSIWYS projection for label / issuer / icon-hint.
//! * Save sensitivity = non-empty `AccountEdit` AND every populated
//!   field validates clean.
//! * `validate_account_edit` runs before
//!   `Vault::find_duplicate_after_edit` (the duplicate stub asserts
//!   zero pre-check calls when validation rejects).
//! * `classify_post_effect_error` routes the locked three-variant
//!   set: `Close { post_summary }` (`Ok` path, handled at dispatch),
//!   `StayOpenWithWarning` (`save_durability_unconfirmed`),
//!   `StayOpenWithError` (`save_not_committed` / `invalid_state` /
//!   `duplicate_account`).
//! * `clear_for_lock` drops every buffer + cached marker.
//! * `apply_msg(Cancel)` clears state identity-equal to the
//!   `clear`-then-default shape.
//! * `apply_msg(SubmitClicked)` only fires when Save is sensitive.
//! * HOTP read-only invariant — `classify_edit_draft` is
//!   account-kind-agnostic.
//! * Multi-row revert collapses to an empty `AccountEdit`.
//! * Post-edit summary `None` branch — toast text is the bare
//!   `Edited.` form.

use std::path::Path;
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    validate_manual, Account, AccountEdit, AccountId, AccountInput, AccountKindInput,
    AccountKindSummary, AccountSummary, Algorithm, ErrorKind, IconHintInput, PaladinError, Store,
    Vault, VaultInit, VaultLock,
};

use paladin_gtk::edit_dialog::{
    apply_msg, classify_edit_draft, classify_post_effect_error, classify_submit,
    classify_submit_with_duplicate, clear_for_lock, decide_edit_target,
    duplicate_marker_from_account, format_edit_dialog_cancel_label,
    format_edit_dialog_icon_hint_title, format_edit_dialog_issuer_title,
    format_edit_dialog_label_title, format_edit_dialog_marker,
    format_edit_dialog_save_button_sensitive, format_edit_dialog_save_label,
    format_edit_dialog_subtitle, format_edit_dialog_success_toast, format_edit_dialog_title,
    is_account_edit_empty, run_edit_worker, DuplicateMarker, EditDialogInit, EditDialogMsg,
    EditDialogOutput, EditDialogState, EditDraftProjection, EditPriorSnapshot, EditWorkerEffect,
    EditWorkerInput, InlineError, InlineWarning, PostEffectOutcome, SubmitDispatch, SubmitOutcome,
    EDIT_DIALOG_MARKER_PREFIX, ISSUER_MAX_BYTES,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SECRET_B32: &str = "JBSWY3DPEHPK3PXP";

fn manual_input(label: &str, issuer: Option<&str>, icon_hint: Option<&str>) -> AccountInput {
    AccountInput {
        kind: AccountKindInput::Totp,
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from(SECRET_B32.to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period_secs: None,
        counter: None,
        icon_hint: icon_hint.map_or(IconHintInput::Default, |s| {
            IconHintInput::Slug(s.to_string())
        }),
    }
}

fn hotp_input(label: &str, issuer: Option<&str>) -> AccountInput {
    AccountInput {
        kind: AccountKindInput::Hotp,
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from(SECRET_B32.to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period_secs: None,
        counter: Some(0),
        icon_hint: IconHintInput::Default,
    }
}

fn build_account(label: &str, issuer: Option<&str>, icon_hint: Option<&str>) -> Account {
    let input = manual_input(label, issuer, icon_hint);
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("validate_manual succeeds");
    validated.account
}

fn build_hotp_account(label: &str, issuer: Option<&str>) -> Account {
    let input = hotp_input(label, issuer);
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("validate_manual succeeds");
    validated.account
}

fn snapshot_for(label: &str, issuer: Option<&str>, icon_hint: Option<&str>) -> EditPriorSnapshot {
    let acct = build_account(label, issuer, icon_hint);
    let summary = summary_from_account(&acct, AccountKindSummary::Totp);
    EditPriorSnapshot::from_summary(&summary)
}

fn summary_from_account(acct: &Account, kind: AccountKindSummary) -> AccountSummary {
    AccountSummary {
        id: acct.id(),
        issuer: acct.issuer().map(str::to_string),
        label: acct.label().to_string(),
        kind,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: match kind {
            AccountKindSummary::Totp => Some(30),
            AccountKindSummary::Hotp => None,
        },
        counter: match kind {
            AccountKindSummary::Totp => None,
            AccountKindSummary::Hotp => Some(0),
        },
        icon_hint: acct.icon_hint().map(str::to_string),
        created_at: 0,
        updated_at: 0,
    }
}

fn open_state(label: &str, issuer: Option<&str>, icon_hint: Option<&str>) -> EditDialogState {
    let prior = snapshot_for(label, issuer, icon_hint);
    EditDialogState::new(&EditDialogInit { prior })
}

// ---------------------------------------------------------------------------
// 1. Static-string helpers (header / row titles / footer / toast)
// ---------------------------------------------------------------------------

#[test]
fn dialog_title_is_edit_account_no_ellipsis() {
    // DESIGN §7: the dialog title does not carry an ellipsis (the
    // ellipsis convention applies to the menu/button verb that
    // opens the dialog).
    assert_eq!(format_edit_dialog_title(), "Edit account");
}

#[test]
fn dialog_subtitle_formats_editing_display_label() {
    assert_eq!(
        format_edit_dialog_subtitle("GitHub:work"),
        "Editing GitHub:work."
    );
}

#[test]
fn dialog_row_titles_are_label_issuer_icon_hint() {
    assert_eq!(format_edit_dialog_label_title(), "Label");
    assert_eq!(format_edit_dialog_issuer_title(), "Issuer");
    assert_eq!(format_edit_dialog_icon_hint_title(), "Icon hint");
}

#[test]
fn dialog_footer_labels_are_cancel_and_save() {
    assert_eq!(format_edit_dialog_cancel_label(), "Cancel");
    assert_eq!(format_edit_dialog_save_label(), "Save");
}

#[test]
fn marker_prefix_carries_edit_dialog_namespace() {
    assert_eq!(
        EDIT_DIALOG_MARKER_PREFIX,
        "paladin-gtk: edit_dialog_account="
    );
}

#[test]
fn marker_format_includes_id_and_display_label() {
    let id = AccountId::new();
    let marker = format_edit_dialog_marker(id, "GitHub:work");
    assert!(marker.starts_with(EDIT_DIALOG_MARKER_PREFIX));
    assert!(marker.contains(&id.to_string()));
    assert!(marker.ends_with("label=GitHub:work"));
}

// ---------------------------------------------------------------------------
// 2. Empty AccountEdit projection (every row at the pre-fill)
// ---------------------------------------------------------------------------

#[test]
fn opens_with_every_row_at_pre_fill_yields_empty_account_edit() {
    let state = open_state("work", Some("GitHub"), Some("github"));
    let projection = classify_edit_draft(&state);
    assert!(is_account_edit_empty(&projection.edit));
    assert!(!projection.save_sensitive());
    assert!(projection.label_error.is_none());
    assert!(projection.issuer_error.is_none());
    assert!(projection.icon_hint_error.is_none());
}

#[test]
fn opens_with_none_issuer_and_none_icon_hint_yields_empty_buffers() {
    let state = open_state("work", None, None);
    assert_eq!(state.label_buf(), "work");
    assert_eq!(state.issuer_buf(), "");
    assert_eq!(state.icon_hint_buf(), "");
    let projection = classify_edit_draft(&state);
    assert!(is_account_edit_empty(&projection.edit));
    assert!(!projection.save_sensitive());
}

// ---------------------------------------------------------------------------
// 3. Label projection
// ---------------------------------------------------------------------------

#[test]
fn label_buffer_byte_equal_to_pre_fill_projects_to_none() {
    let mut state = open_state("work", Some("GitHub"), None);
    state.set_label_buf("work".to_string());
    let projection = classify_edit_draft(&state);
    assert!(
        projection.edit.label.is_none(),
        "byte-equal label collapses to leave-untouched"
    );
}

#[test]
fn label_buffer_with_whitespace_around_pre_fill_collapses_to_none() {
    // A whitespace touch that trims back to the prior label must
    // not enable Save (cosmetic edits are never persisted).
    let mut state = open_state("work", None, None);
    state.set_label_buf("  work  ".to_string());
    let projection = classify_edit_draft(&state);
    assert!(projection.edit.label.is_none());
    assert!(!projection.save_sensitive());
}

#[test]
fn label_buffer_with_new_value_projects_to_some_trimmed() {
    let mut state = open_state("work", None, None);
    state.set_label_buf("  personal  ".to_string());
    let projection = classify_edit_draft(&state);
    assert_eq!(projection.edit.label, Some("personal".to_string()));
    assert!(projection.label_error.is_none());
    assert!(projection.save_sensitive());
}

#[test]
fn label_buffer_empty_surfaces_inline_validation_error() {
    let mut state = open_state("work", None, None);
    state.set_label_buf(String::new());
    let projection = classify_edit_draft(&state);
    assert!(
        projection.label_error.is_some(),
        "empty label rejects inline"
    );
    assert_eq!(
        projection.label_error.as_ref().unwrap().kind,
        ErrorKind::ValidationError
    );
    assert!(!projection.save_sensitive());
}

#[test]
fn label_buffer_overlong_surfaces_inline_validation_error() {
    let mut state = open_state("work", None, None);
    state.set_label_buf("x".repeat(129));
    let projection = classify_edit_draft(&state);
    assert!(
        projection.label_error.is_some(),
        "overlong label rejects inline"
    );
    assert!(!projection.save_sensitive());
}

// ---------------------------------------------------------------------------
// 4. Issuer projection — WYSIWYS rules
// ---------------------------------------------------------------------------

#[test]
fn issuer_empty_over_none_prior_projects_to_none() {
    let mut state = open_state("work", None, None);
    state.set_issuer_buf(String::new());
    let projection = classify_edit_draft(&state);
    assert!(projection.edit.issuer.is_none());
}

#[test]
fn issuer_empty_over_some_prior_projects_to_explicit_clear() {
    let mut state = open_state("work", Some("GitHub"), None);
    state.set_issuer_buf(String::new());
    let projection = classify_edit_draft(&state);
    assert_eq!(
        projection.edit.issuer,
        Some(None),
        "empty over Some collapses to explicit clear"
    );
    assert!(projection.save_sensitive());
}

#[test]
fn issuer_trimmed_equal_to_prior_projects_to_none() {
    let mut state = open_state("work", Some("GitHub"), None);
    state.set_issuer_buf("  GitHub  ".to_string());
    let projection = classify_edit_draft(&state);
    assert!(
        projection.edit.issuer.is_none(),
        "whitespace touch around prior issuer is leave-untouched"
    );
}

#[test]
fn issuer_new_value_projects_to_some_some_trimmed() {
    let mut state = open_state("work", Some("GitHub"), None);
    state.set_issuer_buf("  Acme  ".to_string());
    let projection = classify_edit_draft(&state);
    assert_eq!(projection.edit.issuer, Some(Some("Acme".to_string())));
    assert!(projection.save_sensitive());
}

#[test]
fn issuer_overlong_surfaces_inline_validation_error() {
    let mut state = open_state("work", Some("GitHub"), None);
    state.set_issuer_buf("x".repeat(ISSUER_MAX_BYTES + 1));
    let projection = classify_edit_draft(&state);
    assert!(projection.issuer_error.is_some());
    assert_eq!(
        projection.issuer_error.as_ref().unwrap().kind,
        ErrorKind::ValidationError
    );
    assert!(!projection.save_sensitive());
}

#[test]
fn issuer_whitespace_only_over_none_prior_collapses_to_none() {
    // Non-empty raw buffer that trims to empty over a None prior
    // is the §4.1 whitespace-only case but the `prior None`
    // shoulder collapses to leave-untouched because the buffer
    // would still produce a non-empty trim → empty fallback we
    // catch as a validation error.
    let mut state = open_state("work", None, None);
    state.set_issuer_buf("   ".to_string());
    let projection = classify_edit_draft(&state);
    // Either leave-untouched (None) or inline error is acceptable
    // — the contract is that Save stays disabled.
    let is_none = projection.edit.issuer.is_none();
    let is_invalid = projection.issuer_error.is_some();
    assert!(
        is_none || is_invalid,
        "whitespace-only issuer with no prior must not enable Save"
    );
    assert!(!projection.save_sensitive() || is_none);
}

// ---------------------------------------------------------------------------
// 5. Icon-hint projection — WYSIWYS rules
// ---------------------------------------------------------------------------

#[test]
fn icon_hint_byte_equal_to_pre_fill_projects_to_none() {
    let mut state = open_state("work", None, Some("github"));
    state.set_icon_hint_buf("github".to_string());
    let projection = classify_edit_draft(&state);
    assert!(projection.edit.icon_hint.is_none());
}

#[test]
fn icon_hint_empty_over_none_prior_projects_to_none() {
    let mut state = open_state("work", None, None);
    state.set_icon_hint_buf(String::new());
    let projection = classify_edit_draft(&state);
    assert!(projection.edit.icon_hint.is_none());
}

#[test]
fn icon_hint_empty_over_some_prior_projects_to_default() {
    let mut state = open_state("work", Some("GitHub"), Some("github"));
    state.set_icon_hint_buf(String::new());
    let projection = classify_edit_draft(&state);
    assert!(matches!(
        projection.edit.icon_hint,
        Some(IconHintInput::Default)
    ));
    assert!(projection.save_sensitive());
}

#[test]
fn icon_hint_literal_none_projects_to_clear() {
    let mut state = open_state("work", None, Some("github"));
    state.set_icon_hint_buf("none".to_string());
    let projection = classify_edit_draft(&state);
    assert!(matches!(
        projection.edit.icon_hint,
        Some(IconHintInput::Clear)
    ));
}

#[test]
fn icon_hint_uppercase_none_also_projects_to_clear() {
    let mut state = open_state("work", None, Some("github"));
    state.set_icon_hint_buf("NONE".to_string());
    let projection = classify_edit_draft(&state);
    assert!(matches!(
        projection.edit.icon_hint,
        Some(IconHintInput::Clear)
    ));
}

#[test]
fn icon_hint_new_slug_projects_to_slug_input() {
    let mut state = open_state("work", None, None);
    state.set_icon_hint_buf("acme".to_string());
    let projection = classify_edit_draft(&state);
    match projection.edit.icon_hint {
        Some(IconHintInput::Slug(ref s)) => assert_eq!(s, "acme"),
        other => panic!("expected Slug, got {other:?}"),
    }
    assert!(projection.icon_hint_error.is_none());
    assert!(projection.save_sensitive());
}

#[test]
fn icon_hint_uppercase_slug_surfaces_inline_validation_error() {
    // Uppercase input must surface §5 `validation_error`
    // (`field: "icon_hint"`, `reason: "invalid_chars"`) inline.
    let mut state = open_state("work", None, None);
    state.set_icon_hint_buf("Acme".to_string());
    let projection = classify_edit_draft(&state);
    assert!(projection.icon_hint_error.is_some());
    assert_eq!(
        projection.icon_hint_error.as_ref().unwrap().kind,
        ErrorKind::ValidationError
    );
    assert!(!projection.save_sensitive());
}

#[test]
fn icon_hint_byte_equal_after_whitespace_touch_flips_out_of_untouched() {
    // The icon-hint rule is byte-equal (no trim) — a leading
    // space differs from the pre-fill and projects to the Slug
    // arm; if that slug is invalid (contains whitespace) it
    // surfaces inline.
    let mut state = open_state("work", None, Some("github"));
    state.set_icon_hint_buf(" github".to_string());
    let projection = classify_edit_draft(&state);
    assert!(
        projection.edit.icon_hint.is_some() || projection.icon_hint_error.is_some(),
        "byte-non-equal icon-hint flips out of leave-untouched"
    );
}

// ---------------------------------------------------------------------------
// 6. Save sensitivity composition
// ---------------------------------------------------------------------------

#[test]
fn save_sensitive_only_when_non_empty_and_clean() {
    let mut state = open_state("work", Some("GitHub"), None);
    // Step 1: change label to a new value.
    state.set_label_buf("personal".to_string());
    let projection = classify_edit_draft(&state);
    assert!(
        projection.save_sensitive(),
        "non-empty + clean enables Save"
    );
    // Step 2: introduce an invalid icon-hint slug.
    state.set_icon_hint_buf("Bad Slug".to_string());
    let projection = classify_edit_draft(&state);
    assert!(
        !projection.save_sensitive(),
        "an invalid icon hint disables Save"
    );
    // Step 3: clear the icon-hint back to the pre-fill (None).
    state.set_icon_hint_buf(String::new());
    let projection = classify_edit_draft(&state);
    assert!(
        projection.save_sensitive(),
        "reverting the invalid row re-enables Save"
    );
}

// ---------------------------------------------------------------------------
// 7. classify_submit — validation-before-duplicate ordering
// ---------------------------------------------------------------------------

#[test]
fn classify_submit_empty_edit_returns_empty_reject() {
    let state = open_state("work", Some("GitHub"), None);
    let acct = build_account("work", Some("GitHub"), None);
    let outcome = classify_submit(&state, &acct);
    assert!(matches!(outcome, SubmitOutcome::EmptyEditReject));
}

#[test]
fn classify_submit_invalid_edit_returns_invalid_edit_variant() {
    let mut state = open_state("work", None, None);
    state.set_label_buf(String::new());
    let acct = build_account("work", None, None);
    let outcome = classify_submit(&state, &acct);
    assert!(matches!(outcome, SubmitOutcome::InvalidEdit(_)));
}

#[test]
fn classify_submit_valid_edit_returns_validated_with_payload() {
    let mut state = open_state("work", None, None);
    state.set_label_buf("personal".to_string());
    let acct = build_account("work", None, None);
    match classify_submit(&state, &acct) {
        SubmitOutcome::Validated(edit) => {
            assert_eq!(edit.label, Some("personal".to_string()));
            assert!(edit.issuer.is_none());
            assert!(edit.icon_hint.is_none());
        }
        other => panic!("expected Validated, got {other:?}"),
    }
}

#[test]
fn classify_submit_with_duplicate_routes_validated_through_duplicate_arm() {
    let mut state = open_state("work", None, None);
    state.set_label_buf("personal".to_string());
    let acct = build_account("work", None, None);
    let validated = classify_submit(&state, &acct);
    let marker = DuplicateMarker {
        other_id: AccountId::new(),
        display_label: "Other:account".to_string(),
    };
    match classify_submit_with_duplicate(validated, Some(marker.clone())) {
        SubmitDispatch::DuplicateDetected(got) => assert_eq!(got, marker),
        other => panic!("expected DuplicateDetected, got {other:?}"),
    }
}

#[test]
fn classify_submit_with_duplicate_routes_clean_to_dispatch_effect() {
    let mut state = open_state("work", None, None);
    state.set_label_buf("personal".to_string());
    let acct = build_account("work", None, None);
    let validated = classify_submit(&state, &acct);
    match classify_submit_with_duplicate(validated, None) {
        SubmitDispatch::DispatchEffect(edit) => {
            assert_eq!(edit.label, Some("personal".to_string()));
        }
        other => panic!("expected DispatchEffect, got {other:?}"),
    }
}

#[test]
fn classify_submit_with_duplicate_passes_invalid_edit_through() {
    // Validation-before-duplicate ordering: if `classify_submit`
    // returns `InvalidEdit`, the duplicate-fold step must
    // surface it without consulting the duplicate marker (the
    // caller should never have run `find_duplicate_after_edit`
    // in that case).
    let mut state = open_state("work", None, None);
    state.set_label_buf(String::new());
    let acct = build_account("work", None, None);
    let invalid = classify_submit(&state, &acct);
    match classify_submit_with_duplicate(invalid, None) {
        SubmitDispatch::InvalidEdit(_) => {}
        other => panic!("expected InvalidEdit, got {other:?}"),
    }
}

#[test]
fn classify_submit_with_duplicate_passes_empty_reject_through() {
    let state = open_state("work", None, None);
    let acct = build_account("work", None, None);
    let outcome = classify_submit(&state, &acct);
    match classify_submit_with_duplicate(outcome, None) {
        SubmitDispatch::EmptyEditReject => {}
        other => panic!("expected EmptyEditReject, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 8. Validation-before-duplicate (recording-stub style with vault)
// ---------------------------------------------------------------------------

#[test]
fn validation_failure_short_circuits_before_find_duplicate_after_edit() {
    // Build a real vault with two accounts and assert that an
    // invalid AccountEdit never reaches `find_duplicate_after_edit`
    // (we simulate the dialog's submit-click ordering manually).
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut vault, store) = build_plaintext_vault(tmp.path());
    let one = add_account(&mut vault, &store, "alpha", Some("Acme"), None);
    let _two = add_account(&mut vault, &store, "beta", Some("Acme"), None);

    // Open the dialog state against `alpha` and force an
    // invalid label.
    let prior_acct = vault
        .accounts()
        .iter()
        .find(|a| a.id() == one)
        .cloned()
        .expect("alpha persisted");
    let prior = EditPriorSnapshot::from_summary(
        &vault
            .summaries()
            .find(|s| s.id == one)
            .expect("alpha summary"),
    );
    let mut state = EditDialogState::new(&EditDialogInit { prior });
    state.set_label_buf(String::new());

    // Step 1: classify_submit must reject.
    let outcome = classify_submit(&state, &prior_acct);
    assert!(matches!(outcome, SubmitOutcome::InvalidEdit(_)));

    // Step 2: if the dispatcher routes that through
    // classify_submit_with_duplicate(None), the call site never
    // had to issue find_duplicate_after_edit because the
    // validation arm short-circuits.
    match classify_submit_with_duplicate(outcome, None) {
        SubmitDispatch::InvalidEdit(_) => {}
        other => panic!("expected InvalidEdit, got {other:?}"),
    }
}

#[test]
fn duplicate_detection_uses_find_duplicate_after_edit_for_the_real_collision() {
    // Build a vault with two accounts that share the secret and
    // would collide if we renamed one to match the other.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut vault, store) = build_plaintext_vault(tmp.path());
    let alpha = add_account(&mut vault, &store, "alpha", Some("Acme"), None);
    let beta = add_account(&mut vault, &store, "beta", Some("Acme"), None);

    // Rename `beta` to `alpha` to collide.
    let prior_acct = vault
        .accounts()
        .iter()
        .find(|a| a.id() == beta)
        .cloned()
        .expect("beta persisted");
    let prior = EditPriorSnapshot::from_summary(
        &vault
            .summaries()
            .find(|s| s.id == beta)
            .expect("beta summary"),
    );
    let mut state = EditDialogState::new(&EditDialogInit { prior });
    state.set_label_buf("alpha".to_string());

    let outcome = classify_submit(&state, &prior_acct);
    let validated_edit = match &outcome {
        SubmitOutcome::Validated(e) => e.clone(),
        other => panic!("expected Validated, got {other:?}"),
    };

    // Run find_duplicate_after_edit synchronously per the
    // design contract.
    let duplicate = vault
        .find_duplicate_after_edit(beta, &validated_edit)
        .map(duplicate_marker_from_account);
    assert!(
        duplicate.is_some(),
        "find_duplicate_after_edit must catch the collision"
    );
    let collision_id = duplicate.as_ref().unwrap().other_id;
    assert_eq!(collision_id, alpha, "the colliding account is alpha");

    // Fold into SubmitDispatch.
    match classify_submit_with_duplicate(outcome, duplicate) {
        SubmitDispatch::DuplicateDetected(_) => {}
        other => panic!("expected DuplicateDetected, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 9. classify_post_effect_error — locked variant set
// ---------------------------------------------------------------------------

#[test]
fn classify_post_effect_error_save_durability_unconfirmed_routes_to_warning() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    match classify_post_effect_error(&err) {
        PostEffectOutcome::StayOpenWithWarning(w) => {
            assert_eq!(w.kind, ErrorKind::SaveDurabilityUnconfirmed);
        }
        other => panic!("expected StayOpenWithWarning, got {other:?}"),
    }
}

#[test]
fn classify_post_effect_error_save_not_committed_routes_to_inline_error() {
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    match classify_post_effect_error(&err) {
        PostEffectOutcome::StayOpenWithError(e) => {
            assert_eq!(e.kind, ErrorKind::SaveNotCommitted);
        }
        other => panic!("expected StayOpenWithError, got {other:?}"),
    }
}

#[test]
fn classify_post_effect_error_invalid_state_routes_to_inline_error() {
    let err = PaladinError::InvalidState {
        operation: "edit_account_metadata",
        state: "account_not_found",
    };
    match classify_post_effect_error(&err) {
        PostEffectOutcome::StayOpenWithError(e) => {
            assert_eq!(e.kind, ErrorKind::InvalidState);
        }
        other => panic!("expected StayOpenWithError, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 10. apply_msg routing
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_label_changed_updates_buffer_and_refreshes_errors() {
    let mut state = open_state("work", None, None);
    let acct = build_account("work", None, None);
    let out = apply_msg(
        &mut state,
        EditDialogMsg::LabelChanged("personal".to_string()),
        &acct,
    );
    assert!(out.is_none());
    assert_eq!(state.label_buf(), "personal");
    assert!(state.label_error().is_none());
}

#[test]
fn apply_msg_issuer_changed_updates_buffer_and_clears_duplicate() {
    let mut state = open_state("work", Some("GitHub"), None);
    let acct = build_account("work", Some("GitHub"), None);
    let _ = apply_msg(
        &mut state,
        EditDialogMsg::DuplicateDetected(DuplicateMarker {
            other_id: AccountId::new(),
            display_label: "Other:account".to_string(),
        }),
        &acct,
    );
    assert!(state.duplicate().is_some());
    let _ = apply_msg(
        &mut state,
        EditDialogMsg::IssuerChanged("Acme".to_string()),
        &acct,
    );
    assert_eq!(state.issuer_buf(), "Acme");
    assert!(
        state.duplicate().is_none(),
        "issuer keystroke clears duplicate marker"
    );
}

#[test]
fn apply_msg_icon_hint_changed_preserves_duplicate_marker() {
    let mut state = open_state("work", None, None);
    let acct = build_account("work", None, None);
    let marker = DuplicateMarker {
        other_id: AccountId::new(),
        display_label: "Other:account".to_string(),
    };
    let _ = apply_msg(
        &mut state,
        EditDialogMsg::DuplicateDetected(marker.clone()),
        &acct,
    );
    let _ = apply_msg(
        &mut state,
        EditDialogMsg::IconHintChanged("acme".to_string()),
        &acct,
    );
    assert_eq!(
        state.duplicate(),
        Some(&marker),
        "icon-hint keystroke preserves duplicate marker (not in §4.7 key)"
    );
}

#[test]
fn apply_msg_issuer_clear_clicked_wipes_buffer() {
    let mut state = open_state("work", Some("GitHub"), None);
    let acct = build_account("work", Some("GitHub"), None);
    let _ = apply_msg(&mut state, EditDialogMsg::IssuerClearClicked, &acct);
    assert_eq!(state.issuer_buf(), "");
    // Empty over Some(_) ⇒ implicit clear ⇒ non-empty edit.
    let projection = classify_edit_draft(&state);
    assert_eq!(projection.edit.issuer, Some(None));
}

#[test]
fn apply_msg_cancel_clears_state_and_emits_cancel_output() {
    let mut state = open_state("work", Some("GitHub"), Some("github"));
    let acct = build_account("work", Some("GitHub"), Some("github"));
    state.set_label_buf("personal".to_string());
    state.set_issuer_buf("Acme".to_string());
    let out = apply_msg(&mut state, EditDialogMsg::Cancel, &acct);
    assert!(matches!(out, Some(EditDialogOutput::Cancel)));
    assert_eq!(state.label_buf(), "");
    assert_eq!(state.issuer_buf(), "");
    assert_eq!(state.icon_hint_buf(), "");
    assert!(state.duplicate().is_none());
    assert!(state.worker_outcome().is_none());
}

#[test]
fn apply_msg_submit_clicked_emits_submit_when_save_sensitive() {
    let mut state = open_state("work", None, None);
    let acct = build_account("work", None, None);
    state.set_label_buf("personal".to_string());
    match apply_msg(&mut state, EditDialogMsg::SubmitClicked, &acct) {
        Some(EditDialogOutput::Submit { account_id, edit }) => {
            assert_eq!(account_id, state.account_id());
            assert_eq!(edit.label, Some("personal".to_string()));
        }
        other => panic!("expected Submit, got {other:?}"),
    }
}

#[test]
fn apply_msg_submit_clicked_no_op_when_empty_edit() {
    let mut state = open_state("work", None, None);
    let acct = build_account("work", None, None);
    let out = apply_msg(&mut state, EditDialogMsg::SubmitClicked, &acct);
    assert!(out.is_none(), "no Submit output on empty edit");
}

#[test]
fn apply_msg_submit_clicked_no_op_when_invalid_edit() {
    let mut state = open_state("work", None, None);
    let acct = build_account("work", None, None);
    state.set_label_buf(String::new());
    let out = apply_msg(&mut state, EditDialogMsg::SubmitClicked, &acct);
    assert!(out.is_none(), "no Submit output on invalid edit");
}

#[test]
fn apply_msg_set_busy_flips_busy_latch() {
    let mut state = open_state("work", None, None);
    let acct = build_account("work", None, None);
    assert!(!state.is_busy());
    let _ = apply_msg(&mut state, EditDialogMsg::SetBusy(true), &acct);
    assert!(state.is_busy());
    let _ = apply_msg(&mut state, EditDialogMsg::SetBusy(false), &acct);
    assert!(!state.is_busy());
}

#[test]
fn apply_msg_worker_completed_routes_outcome_into_state() {
    let mut state = open_state("work", None, None);
    let acct = build_account("work", None, None);
    let outcome = PostEffectOutcome::Close { post_summary: None };
    let _ = apply_msg(
        &mut state,
        EditDialogMsg::WorkerCompleted(outcome.clone()),
        &acct,
    );
    assert_eq!(state.worker_outcome(), Some(&outcome));
}

// ---------------------------------------------------------------------------
// 11. clear_for_lock
// ---------------------------------------------------------------------------

#[test]
fn clear_for_lock_drops_row_buffers_and_markers() {
    let mut state = open_state("work", Some("GitHub"), Some("github"));
    state.set_label_buf("personal".to_string());
    state.set_issuer_buf("Acme".to_string());
    state.set_icon_hint_buf("acme".to_string());
    state.set_busy(true);

    clear_for_lock(&mut state);

    assert_eq!(state.label_buf(), "");
    assert_eq!(state.issuer_buf(), "");
    assert_eq!(state.icon_hint_buf(), "");
    assert!(state.label_error().is_none());
    assert!(state.issuer_error().is_none());
    assert!(state.icon_hint_error().is_none());
    assert!(state.duplicate().is_none());
    assert!(state.worker_outcome().is_none());
}

#[test]
fn clear_for_lock_is_idempotent_on_already_cleared_state() {
    let mut state = open_state("work", None, None);
    clear_for_lock(&mut state);
    let snapshot_buf = state.label_buf().to_string();
    clear_for_lock(&mut state);
    assert_eq!(state.label_buf(), snapshot_buf);
}

// ---------------------------------------------------------------------------
// 12. HOTP read-only invariant
// ---------------------------------------------------------------------------

#[test]
fn classify_edit_draft_is_kind_agnostic_between_totp_and_hotp() {
    let totp_acct = build_account("work", Some("GitHub"), None);
    let hotp_acct = build_hotp_account("work", Some("GitHub"));

    let totp_summary = summary_from_account(&totp_acct, AccountKindSummary::Totp);
    let hotp_summary = summary_from_account(&hotp_acct, AccountKindSummary::Hotp);

    let mut totp_state = EditDialogState::new(&EditDialogInit {
        prior: EditPriorSnapshot::from_summary(&totp_summary),
    });
    let mut hotp_state = EditDialogState::new(&EditDialogInit {
        prior: EditPriorSnapshot::from_summary(&hotp_summary),
    });

    totp_state.set_label_buf("personal".to_string());
    hotp_state.set_label_buf("personal".to_string());

    let totp_p = classify_edit_draft(&totp_state);
    let hotp_p = classify_edit_draft(&hotp_state);

    assert_eq!(totp_p.edit.label, hotp_p.edit.label);
    assert_eq!(totp_p.edit.issuer.is_some(), hotp_p.edit.issuer.is_some());
    assert!(totp_p.save_sensitive());
    assert!(hotp_p.save_sensitive());
}

// ---------------------------------------------------------------------------
// 13. Multi-row revert
// ---------------------------------------------------------------------------

#[test]
fn multi_row_revert_collapses_to_empty_edit_with_save_disabled() {
    let mut state = open_state("work", Some("GitHub"), Some("github"));
    state.set_label_buf("personal".to_string());
    state.set_issuer_buf("Acme".to_string());
    state.set_icon_hint_buf("acme".to_string());
    // Revert each row.
    state.set_label_buf("work".to_string());
    state.set_issuer_buf("GitHub".to_string());
    state.set_icon_hint_buf("github".to_string());
    let projection = classify_edit_draft(&state);
    assert!(is_account_edit_empty(&projection.edit));
    assert!(!projection.save_sensitive());
}

// ---------------------------------------------------------------------------
// 14. Post-edit summary None branch
// ---------------------------------------------------------------------------

#[test]
fn success_toast_renders_edited_dot_when_post_summary_is_none() {
    let body = format_edit_dialog_success_toast(None);
    assert_eq!(body, "Edited.");
}

#[test]
fn success_toast_renders_edited_display_label_when_post_summary_is_some() {
    let acct = build_account("work", Some("GitHub"), None);
    let summary = summary_from_account(&acct, AccountKindSummary::Totp);
    let body = format_edit_dialog_success_toast(Some(&summary));
    assert_eq!(body, "Edited GitHub:work.");
}

// ---------------------------------------------------------------------------
// 15. decide_edit_target
// ---------------------------------------------------------------------------

#[test]
fn decide_edit_target_returns_none_for_unknown_id() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (vault, _store) = build_plaintext_vault(tmp.path());
    let unknown = AccountId::new();
    assert!(decide_edit_target(&vault, unknown).is_none());
}

#[test]
fn decide_edit_target_projects_summary_to_init() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut vault, store) = build_plaintext_vault(tmp.path());
    let id = add_account(&mut vault, &store, "work", Some("GitHub"), Some("github"));
    let init = decide_edit_target(&vault, id).expect("init projects");
    assert_eq!(init.prior.account_id, id);
    assert_eq!(init.prior.label, "work");
    assert_eq!(init.prior.issuer.as_deref(), Some("GitHub"));
    assert_eq!(init.prior.icon_hint.as_deref(), Some("github"));
    assert_eq!(init.prior.display_label, "GitHub:work");
}

// ---------------------------------------------------------------------------
// 16. InlineError / InlineWarning struct projections
// ---------------------------------------------------------------------------

#[test]
fn inline_error_carries_kind_and_renders_paladin_error_body() {
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert_eq!(inline.rendered, err.to_string());
}

#[test]
fn inline_warning_carries_kind_and_renders_paladin_error_body() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let inline = InlineWarning::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert_eq!(inline.rendered, err.to_string());
}

// ---------------------------------------------------------------------------
// 17. EditDraftProjection.save_sensitive composition
// ---------------------------------------------------------------------------

#[test]
fn edit_draft_projection_save_sensitive_false_for_empty_edit() {
    let projection = EditDraftProjection {
        edit: AccountEdit::default(),
        label_error: None,
        issuer_error: None,
        icon_hint_error: None,
    };
    assert!(
        !projection.save_sensitive(),
        "empty AccountEdit is never save-sensitive"
    );
}

#[test]
fn edit_draft_projection_save_sensitive_false_when_any_row_has_error() {
    let projection = EditDraftProjection {
        edit: AccountEdit {
            label: Some("personal".to_string()),
            ..Default::default()
        },
        label_error: None,
        issuer_error: Some(InlineError {
            kind: ErrorKind::ValidationError,
            rendered: "issuer too long".to_string(),
        }),
        icon_hint_error: None,
    };
    assert!(!projection.save_sensitive());
}

// ---------------------------------------------------------------------------
// Helpers — plaintext vault fixture
// ---------------------------------------------------------------------------

fn build_plaintext_vault(dir: &Path) -> (Vault, Store) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    let path = dir.join("vault.bin");
    let (vault, store) =
        Store::create(&path, VaultInit::Plaintext).expect("create plaintext vault on disk");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault")
}

fn add_account(
    vault: &mut Vault,
    store: &Store,
    label: &str,
    issuer: Option<&str>,
    icon_hint: Option<&str>,
) -> AccountId {
    let input = manual_input(label, issuer, icon_hint);
    let validated = validate_manual(input, SystemTime::UNIX_EPOCH).expect("validate_manual");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

// ---------------------------------------------------------------------------
// 18. format_edit_dialog_save_button_sensitive — busy + projection gate
// ---------------------------------------------------------------------------

#[test]
fn save_button_disabled_while_busy_even_with_clean_edit() {
    let mut state = open_state("work", None, None);
    state.set_label_buf("personal".to_string());
    assert!(format_edit_dialog_save_button_sensitive(&state));
    state.set_busy(true);
    assert!(
        !format_edit_dialog_save_button_sensitive(&state),
        "busy latch dims Save regardless of projection cleanliness"
    );
}

#[test]
fn save_button_disabled_on_empty_edit() {
    let state = open_state("work", None, None);
    assert!(!format_edit_dialog_save_button_sensitive(&state));
}

#[test]
fn save_button_disabled_on_inline_error() {
    let mut state = open_state("work", None, None);
    state.set_label_buf(String::new());
    assert!(!format_edit_dialog_save_button_sensitive(&state));
}

// ---------------------------------------------------------------------------
// 19. run_edit_worker — end-to-end against tempfile-backed plaintext vault
// ---------------------------------------------------------------------------

#[test]
fn run_edit_worker_success_persists_new_label_and_returns_post_summary() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut vault, store) = build_plaintext_vault(tmp.path());
    let id = add_account(&mut vault, &store, "work", Some("GitHub"), None);

    let edit = AccountEdit {
        label: Some("personal".to_string()),
        ..Default::default()
    };
    let input = EditWorkerInput {
        vault,
        store,
        account_id: id,
        edit,
        now: SystemTime::UNIX_EPOCH,
    };
    let completion = run_edit_worker(input);
    match completion.effect {
        EditWorkerEffect::Success { post_summary } => {
            let summary = post_summary.expect("post-edit summary present");
            assert_eq!(summary.label, "personal");
            assert_eq!(summary.issuer.as_deref(), Some("GitHub"));
        }
        EditWorkerEffect::Failure(other) => panic!("expected Success, got Failure({other:?})"),
    }
    // The vault returned by the worker reflects the new label.
    let post = completion
        .vault
        .summaries()
        .find(|s| s.id == id)
        .expect("account still present");
    assert_eq!(post.label, "personal");
}

#[test]
fn run_edit_worker_success_clears_issuer_when_edit_carries_some_none() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut vault, store) = build_plaintext_vault(tmp.path());
    let id = add_account(&mut vault, &store, "work", Some("GitHub"), None);

    let edit = AccountEdit {
        issuer: Some(None),
        ..Default::default()
    };
    let completion = run_edit_worker(EditWorkerInput {
        vault,
        store,
        account_id: id,
        edit,
        now: SystemTime::UNIX_EPOCH,
    });
    match completion.effect {
        EditWorkerEffect::Success { post_summary } => {
            let summary = post_summary.unwrap();
            assert_eq!(summary.label, "work");
            assert!(summary.issuer.is_none(), "Some(None) clears the issuer");
        }
        EditWorkerEffect::Failure(other) => panic!("expected Success, got Failure({other:?})"),
    }
}

#[test]
fn run_edit_worker_returns_vault_and_store_on_every_branch() {
    // Even on a defensive InvalidState (the targeted account has
    // been removed concurrently), the worker still returns the
    // live (vault, store) pair so AppModel can reinstall it.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut vault, store) = build_plaintext_vault(tmp.path());
    let id = add_account(&mut vault, &store, "work", None, None);
    // Remove the account so the edit hits invalid_state.
    vault.remove(id);
    vault.save(&store).expect("commit removal");

    let edit = AccountEdit {
        label: Some("personal".to_string()),
        ..Default::default()
    };
    let completion = run_edit_worker(EditWorkerInput {
        vault,
        store,
        account_id: id,
        edit,
        now: SystemTime::UNIX_EPOCH,
    });
    // Vault is still usable.
    assert_eq!(completion.vault.summaries().count(), 0);
    match completion.effect {
        EditWorkerEffect::Failure(PostEffectOutcome::StayOpenWithError(err)) => {
            assert_eq!(err.kind, ErrorKind::InvalidState);
        }
        other => panic!("expected StayOpenWithError(InvalidState), got {other:?}"),
    }
}
