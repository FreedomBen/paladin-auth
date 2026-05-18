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
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, AccountKindSummary, AccountSummary,
    Algorithm, ErrorKind, IconHintInput, PaladinError, Store, Vault, VaultInit, VaultLock,
};

use paladin_gtk::remove_dialog::{
    account_not_found_error, apply_msg, classify_remove_error, decide_remove_target,
    format_remove_dialog_marker, run_remove_worker, summary_display_label, InlineError,
    InlineWarning, RemoveDialogInit, RemoveDialogMsg, RemoveDialogOutput, RemoveDialogState,
    RemoveErrorOutcome, RemoveWorkerCompletion, RemoveWorkerEffect, RemoveWorkerInput,
    REMOVE_DIALOG_MARKER_PREFIX,
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

fn save_durability_unconfirmed() -> PaladinError {
    PaladinError::SaveDurabilityUnconfirmed
}

/// Seed `state.worker_outcome` by routing through the public
/// `apply_msg(state, WorkerFailed(...))` entry point. The field is
/// `pub(crate)` on the source type so it stays out of the
/// integration-test API; this helper lets tests stage a "post-
/// failure" state without bypassing the routing helper.
fn seed_worker_outcome(state: &mut RemoveDialogState, err: &PaladinError) {
    let outcome = classify_remove_error(err);
    let out = apply_msg(state, RemoveDialogMsg::WorkerFailed(outcome));
    assert!(out.is_none(), "WorkerFailed never forwards an output");
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

// ---------------------------------------------------------------------------
// `decide_remove_target` + `format_remove_dialog_marker`
//
// The dialog mount lives behind `AccountListOutput::OpenRemoveDialog(id)`.
// `AppModel` calls `decide_remove_target` with the active `Vault` and the
// dispatched `AccountId` to project the row into the [`RemoveDialogInit`]
// the widget binds (id + heading label). The marker is emitted under
// `--exit-after-startup` once the dialog has mounted so a future
// `tests/gtk_smoke.rs` bullet can prove the widget reached the screen.
// ---------------------------------------------------------------------------

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir for remove-target fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    dir
}

fn open_plaintext_pair(path: &Path) -> (Vault, Store) {
    let (vault, store) =
        Store::create(path, VaultInit::Plaintext).expect("create plaintext vault on disk");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(path, VaultLock::Plaintext).expect("reopen plaintext vault")
}

fn add_totp(vault: &mut Vault, store: &Store, issuer: Option<&str>, label: &str) -> AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::now()).expect("totp account input validates");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

#[test]
fn remove_dialog_marker_prefix_is_stable_grep_anchor() {
    // The smoke test in `tests/gtk_smoke.rs` will grep for this prefix
    // to prove the dialog mounted; locking the literal here keeps the
    // pure-logic projection and the smoke marker aligned.
    assert_eq!(
        REMOVE_DIALOG_MARKER_PREFIX,
        "paladin-gtk: remove_dialog_account="
    );
}

#[test]
fn format_remove_dialog_marker_renders_id_and_display_label() {
    let id = AccountId::new();
    let marker = format_remove_dialog_marker(id, "GitHub:ben");
    assert!(
        marker.starts_with(REMOVE_DIALOG_MARKER_PREFIX),
        "marker `{marker}` should start with `{REMOVE_DIALOG_MARKER_PREFIX}`",
    );
    assert!(
        marker.contains(&id.to_string()),
        "marker `{marker}` should contain the account id",
    );
    assert!(
        marker.contains("GitHub:ben"),
        "marker `{marker}` should contain the display label",
    );
}

#[test]
fn decide_remove_target_finds_known_account() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("GitHub"), "ben");

    let init = decide_remove_target(&vault, id).expect("known account id resolves");
    assert_eq!(init.account_id, id);
    assert_eq!(init.display_label, "GitHub:ben");
}

#[test]
fn decide_remove_target_drops_empty_issuer_in_display_label() {
    // `summary_display_label` collapses to the bare label when issuer
    // is empty or `None`, matching `account_row::display_label`. The
    // remove dialog body shares that projection so the confirmation
    // prompt never reads `:label`.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, None, "alice");

    let init = decide_remove_target(&vault, id).expect("known account id resolves");
    assert_eq!(init.display_label, "alice");
}

#[test]
fn decide_remove_target_returns_none_for_unknown_id() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let stray = AccountId::new();

    assert!(decide_remove_target(&vault, stray).is_none());
}

#[test]
fn remove_dialog_init_clones_for_reactive_state() {
    // The widget layer stores the init on `self` and clones it across
    // re-renders; the type must implement `Clone` without losing
    // fields.
    let init = RemoveDialogInit {
        account_id: AccountId::new(),
        display_label: "GitHub:ben".to_string(),
    };
    let cloned = init.clone();
    assert_eq!(cloned.account_id, init.account_id);
    assert_eq!(cloned.display_label, init.display_label);
}

// ---------------------------------------------------------------------------
// apply_msg — Cancel routing
//
// The widget's `update` delegates here so the routing decision (Cancel
// emits `RemoveDialogOutput::Cancel`) stays a pure function that does
// not require spinning up GTK to verify. The Confirm / Remove worker
// path lands in a follow-up commit alongside the `UnlockedBusy` worker
// infrastructure.
// ---------------------------------------------------------------------------

fn dummy_init() -> RemoveDialogInit {
    RemoveDialogInit {
        account_id: AccountId::new(),
        display_label: "GitHub:ben".to_string(),
    }
}

#[test]
fn apply_msg_cancel_emits_cancel_output() {
    // Cancel button must bubble back to `AppModel` as
    // `RemoveDialogOutput::Cancel` so the controller can be dropped
    // and the dialog widget removed from the content tree. Mirrors
    // the `RenameDialogComponent` Cancel staging.
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    let out = apply_msg(&mut state, RemoveDialogMsg::Cancel);
    assert_eq!(out, Some(RemoveDialogOutput::Cancel));
}

#[test]
fn apply_msg_cancel_does_not_mutate_worker_outcome() {
    // Cancel must not clobber `worker_outcome` — a user that opened
    // the dialog after a `KeepRemovedWithWarning` warning, saw the
    // warning, and then pressed Cancel should still see no surprise
    // mutation of the state from the Cancel handler.
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    seed_worker_outcome(&mut state, &save_durability_unconfirmed());
    let _ = apply_msg(&mut state, RemoveDialogMsg::Cancel);
    assert!(state.worker_outcome().is_some());
}

#[test]
fn remove_dialog_output_cancel_is_distinct_variant() {
    // Defensive: the variant exists and is comparable, so the
    // AppModel can pattern-match on `RemoveDialogOutput::Cancel`
    // without an `_` catch-all swallowing future variants (Confirm /
    // typed worker outcomes ship in follow-up commits).
    let out = RemoveDialogOutput::Cancel;
    assert!(matches!(out, RemoveDialogOutput::Cancel));
    assert_eq!(out.clone(), RemoveDialogOutput::Cancel);
}

// ---------------------------------------------------------------------------
// `RemoveDialogState` accessors
// ---------------------------------------------------------------------------

#[test]
fn remove_dialog_state_new_seeds_account_id_from_init() {
    let init = dummy_init();
    let state = RemoveDialogState::new(&init);
    assert_eq!(state.account_id(), init.account_id);
}

#[test]
fn remove_dialog_state_new_seeds_display_label_from_init() {
    let init = dummy_init();
    let state = RemoveDialogState::new(&init);
    assert_eq!(state.display_label(), "GitHub:ben");
}

#[test]
fn remove_dialog_state_new_initializes_worker_outcome_to_none() {
    let init = dummy_init();
    let state = RemoveDialogState::new(&init);
    assert!(state.worker_outcome().is_none());
    assert!(state.inline_error().is_none());
    assert!(state.inline_warning().is_none());
}

#[test]
fn remove_dialog_state_clones_for_reactive_state() {
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    seed_worker_outcome(&mut state, &save_not_committed_no_backup());
    let cloned = state.clone();
    assert_eq!(cloned.account_id(), state.account_id());
    assert_eq!(cloned.display_label(), state.display_label());
    assert!(cloned.worker_outcome().is_some());
}

#[test]
fn remove_dialog_state_inline_error_projects_restore_prior() {
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    seed_worker_outcome(&mut state, &save_not_committed_no_backup());
    assert!(state.inline_error().is_some());
    assert!(state.inline_warning().is_none());
}

#[test]
fn remove_dialog_state_inline_warning_projects_keep_removed() {
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    seed_worker_outcome(&mut state, &save_durability_unconfirmed());
    assert!(state.inline_error().is_none());
    assert!(state.inline_warning().is_some());
}

#[test]
fn remove_dialog_state_inline_error_projects_defensive_inline_error() {
    // Defensive: `invalid_state { state: "account_not_found" }`
    // (target removed mid-flight) routes through the
    // `RemoveErrorOutcome::InlineError` arm. `inline_error` must
    // surface it so the dialog body re-renders the typed message.
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    seed_worker_outcome(&mut state, &account_not_found_error());
    assert!(state.inline_error().is_some());
    assert!(state.inline_warning().is_none());
}

// ---------------------------------------------------------------------------
// `apply_msg(Confirm)` and `RemoveDialogOutput::SubmitConfirm`
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_confirm_emits_submit_confirm_with_state_account_id() {
    // Confirm must bubble back as `RemoveDialogOutput::SubmitConfirm`
    // carrying the seeded account id so `AppModel`'s worker dispatch
    // targets the same account the kebab activation resolved.
    let init = dummy_init();
    let expected_id = init.account_id;
    let mut state = RemoveDialogState::new(&init);
    let out = apply_msg(&mut state, RemoveDialogMsg::Confirm);
    assert_eq!(
        out,
        Some(RemoveDialogOutput::SubmitConfirm {
            account_id: expected_id,
        }),
    );
}

#[test]
fn apply_msg_confirm_clears_prior_worker_outcome() {
    // Confirm must clear the cached worker outcome so a re-render
    // after a defensive `KeepRemovedWithWarning` does not show
    // stale text alongside a fresh attempt.
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    seed_worker_outcome(&mut state, &save_durability_unconfirmed());
    let _ = apply_msg(&mut state, RemoveDialogMsg::Confirm);
    assert!(state.worker_outcome().is_none());
}

#[test]
fn remove_dialog_output_submit_confirm_distinct_from_cancel() {
    let id = AccountId::new();
    let submit = RemoveDialogOutput::SubmitConfirm { account_id: id };
    assert!(matches!(submit, RemoveDialogOutput::SubmitConfirm { .. }));
    assert_ne!(submit, RemoveDialogOutput::Cancel);
}

#[test]
fn remove_dialog_output_submit_confirm_clones_and_equals() {
    let id = AccountId::new();
    let submit = RemoveDialogOutput::SubmitConfirm { account_id: id };
    let cloned = submit.clone();
    assert_eq!(submit, cloned);
}

// ---------------------------------------------------------------------------
// `apply_msg(WorkerFailed(...))`
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_worker_failed_restore_prior_stores_outcome() {
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    let outcome = classify_remove_error(&save_not_committed_no_backup());
    let out = apply_msg(&mut state, RemoveDialogMsg::WorkerFailed(outcome));
    assert!(out.is_none(), "WorkerFailed never forwards an output");
    let stored = state.worker_outcome().expect("outcome stored on state");
    assert!(matches!(stored, RemoveErrorOutcome::RestorePrior(_)));
}

#[test]
fn apply_msg_worker_failed_keep_removed_with_warning_stores_outcome() {
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    let outcome = classify_remove_error(&save_durability_unconfirmed());
    let out = apply_msg(&mut state, RemoveDialogMsg::WorkerFailed(outcome));
    assert!(out.is_none());
    let stored = state.worker_outcome().expect("outcome stored on state");
    assert!(matches!(
        stored,
        RemoveErrorOutcome::KeepRemovedWithWarning(_)
    ));
}

#[test]
fn apply_msg_worker_failed_defensive_inline_error_stores_outcome() {
    let init = dummy_init();
    let mut state = RemoveDialogState::new(&init);
    let outcome = classify_remove_error(&account_not_found_error());
    let out = apply_msg(&mut state, RemoveDialogMsg::WorkerFailed(outcome));
    assert!(out.is_none());
    let stored = state.worker_outcome().expect("outcome stored on state");
    assert!(matches!(stored, RemoveErrorOutcome::InlineError(_)));
}

#[test]
fn apply_msg_worker_failed_does_not_change_account_id_or_display() {
    // Defensive: the outcome stash must not retarget the dialog by
    // mutating the seeded init.
    let init = dummy_init();
    let original_id = init.account_id;
    let original_label = init.display_label.clone();
    let mut state = RemoveDialogState::new(&init);
    let outcome = classify_remove_error(&save_not_committed_no_backup());
    let _ = apply_msg(&mut state, RemoveDialogMsg::WorkerFailed(outcome));
    assert_eq!(state.account_id(), original_id);
    assert_eq!(state.display_label(), original_label);
}

// ---------------------------------------------------------------------------
// `run_remove_worker`
//
// Exercises the synchronous worker body that `AppModel::update` hands
// to `gio::spawn_blocking` against tempfile-backed plaintext vaults so
// the `Vault::mutate_and_save` save-pipeline routing stays unit-
// testable without the GTK loop.
// ---------------------------------------------------------------------------

#[test]
fn run_remove_worker_plaintext_remove_succeeds_and_returns_live_pair() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let target = add_totp(&mut vault, &store, Some("Acme"), "alice");
    let surviving = add_totp(&mut vault, &store, Some("Acme"), "bob");

    let completion = run_remove_worker(RemoveWorkerInput {
        vault,
        store,
        account_id: target,
    });

    let RemoveWorkerCompletion {
        effect,
        vault,
        store: _,
    } = completion;
    assert!(
        matches!(effect, RemoveWorkerEffect::Success),
        "plaintext remove success must surface as RemoveWorkerEffect::Success, got {effect:?}",
    );
    assert!(
        vault.summaries().all(|s| s.id != target),
        "targeted account is gone from the returned vault",
    );
    assert!(
        vault.summaries().any(|s| s.id == surviving),
        "non-targeted account survives the remove",
    );
}

#[test]
fn run_remove_worker_unknown_account_routes_inline_error_and_returns_pair() {
    // Defensive: a mid-flight removal between the kebab activation
    // and the worker dispatch leaves the worker targeting an unknown
    // id. The closure inside `mutate_and_save` maps the `None` to
    // `account_not_found_error`, which `classify_remove_error`
    // routes to `RemoveErrorOutcome::InlineError`. The vault is
    // unchanged so `AppModel::update` reinstalls it without losing
    // other accounts.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let surviving = add_totp(&mut vault, &store, None, "alice");
    let stray = AccountId::new();

    let completion = run_remove_worker(RemoveWorkerInput {
        vault,
        store,
        account_id: stray,
    });

    match completion.effect {
        RemoveWorkerEffect::Failure(RemoveErrorOutcome::InlineError(inline)) => {
            assert_eq!(inline.kind, ErrorKind::InvalidState);
        }
        other => panic!("expected Failure(InlineError) for unknown id, got {other:?}"),
    }
    let summary = completion
        .vault
        .summaries()
        .find(|s| s.id == surviving)
        .expect("surviving account stays in the returned vault");
    assert_eq!(summary.label, "alice");
}

#[test]
fn run_remove_worker_persists_removal_to_disk() {
    // The worker must not just mutate the in-memory vault — it goes
    // through `mutate_and_save` so the removal survives a reopen.
    // This pins the round trip through the §4.3 atomic-write pipeline
    // without exercising the GTK loop.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let target = add_totp(&mut vault, &store, Some("Acme"), "alice");

    let completion = run_remove_worker(RemoveWorkerInput {
        vault,
        store,
        account_id: target,
    });
    assert!(matches!(completion.effect, RemoveWorkerEffect::Success));
    drop(completion);

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    assert!(
        reopened.summaries().all(|s| s.id != target),
        "removed account stays gone after reopen",
    );
}

#[test]
fn format_remove_dialog_cancel_label_returns_cancel() {
    // The RemoveDialog's footer Cancel `gtk::Button`'s
    // `set_label` attribute is populated from this helper. The
    // wording (`"Cancel"`) is the action-specific GNOME-HIG verb
    // for the surface — matching the rename / add dialog cancel
    // affordance so the dialog footer wording stays uniform
    // across every per-account surface. Pinning the wording
    // through a helper keeps the string in one place shared by
    // the widget binding and the pure-logic tests.
    //
    // No TUI parity: the TUI's `remove` command is CLI-shaped
    // and prompts on stdin rather than rendering a dialog
    // footer, so the wording is GTK-specific. Sibling of
    // `paladin_gtk::rename_dialog::format_rename_dialog_cancel_label`
    // and
    // `paladin_gtk::add_account::format_add_dialog_cancel_label`
    // on the dialog-footer-cancel side; together they pin every
    // dialog's cancel affordance against a single source of
    // truth.
    use paladin_gtk::remove_dialog::format_remove_dialog_cancel_label;

    assert_eq!(
        format_remove_dialog_cancel_label(),
        "Cancel",
        "cancel button label uses the action-specific GNOME-HIG verb",
    );
}

#[test]
fn format_remove_dialog_subtitle_renders_display_label() {
    // The RemoveDialog's `adw::StatusPage::set_description`
    // attribute is populated from this helper. The wording
    // (`"Removing {display}."`) names the destructive action
    // verbatim against the row's pre-formatted display label, so
    // the user can confirm the specific account before
    // submitting. Pinning the format string through a helper
    // keeps the wording in one place shared by the widget binding
    // and the pure-logic tests in `tests/remove_dialog_logic.rs`.
    //
    // Sibling of
    // `paladin_gtk::rename_dialog::format_rename_dialog_subtitle`
    // on the dialog-sub-title side: the two surfaces use the same
    // single-line "Verb-ing {display}." form so the rename and
    // remove dialogs read in parallel against the same display
    // label format. No TUI parity: the TUI's `remove` command is
    // CLI-shaped and prompts on stdin rather than rendering a
    // dialog sub-title, so the wording is GTK-specific.
    use paladin_gtk::remove_dialog::format_remove_dialog_subtitle;

    assert_eq!(
        format_remove_dialog_subtitle("Acme:alice"),
        "Removing Acme:alice.",
        "subtitle names the destructive action against the display label verbatim",
    );
}

#[test]
fn format_remove_dialog_subtitle_starts_with_removing_prefix() {
    // The prefix `"Removing "` is the stable wording the dialog
    // leads with — pinning a prefix assertion alongside the full-
    // string assertion guards against an accidental rewording
    // that still happens to keep the label intact.
    use paladin_gtk::remove_dialog::format_remove_dialog_subtitle;

    let rendered = format_remove_dialog_subtitle("X");
    assert!(
        rendered.starts_with("Removing "),
        "subtitle begins with the stable `Removing ` prefix; got {rendered:?}",
    );
}

#[test]
fn format_remove_dialog_subtitle_renders_empty_display_label() {
    // Defense-in-depth against an empty display label: the helper
    // should not panic or drop the trailing period, matching the
    // `format_rename_dialog_subtitle` contract. `AppModel` should
    // never hand an empty label in practice, but pinning the
    // edge case keeps the formatter total.
    use paladin_gtk::remove_dialog::format_remove_dialog_subtitle;

    assert_eq!(format_remove_dialog_subtitle(""), "Removing .");
}

#[test]
fn format_remove_dialog_icon_name_returns_user_trash_symbolic() {
    // The RemoveDialog's `adw::StatusPage::set_icon_name`
    // attribute is populated from this helper. The icon
    // (`"user-trash-symbolic"`) is the freedesktop-standard glyph
    // for destructive removal — resolving through the system icon
    // theme so the wordless icon matches every other GNOME app's
    // delete surface. The `-symbolic` suffix is required by the
    // libadwaita HIG for `AdwStatusPage` icons so the glyph
    // recolors with the theme. Pinning the icon name through a
    // helper keeps the string in one place shared by the widget
    // binding and the pure-logic tests.
    //
    // No TUI parity: the TUI is text-only and has no icon to
    // mirror. Sibling of
    // `paladin_gtk::unlock_dialog::format_unlock_dialog_icon_name`,
    // `paladin_gtk::init_dialog::format_init_dialog_icon_name`,
    // and
    // `paladin_gtk::startup_error::format_startup_error_icon_name`
    // on the dialog-status-icon side; together they pin every
    // first-mount dialog's freedesktop glyph against a single
    // source of truth.
    use paladin_gtk::remove_dialog::format_remove_dialog_icon_name;

    assert_eq!(
        format_remove_dialog_icon_name(),
        "user-trash-symbolic",
        "AdwStatusPage icon uses the freedesktop-standard destructive-removal glyph",
    );
}

#[test]
fn format_remove_dialog_icon_name_ends_with_symbolic_suffix() {
    // The libadwaita HIG requires `AdwStatusPage` icons to be
    // symbolic so they recolor with the theme; the icon-name
    // contract is to end with `-symbolic`. Pinning a suffix
    // assertion alongside the full-string assertion guards
    // against an accidental rename to a non-symbolic glyph.
    use paladin_gtk::remove_dialog::format_remove_dialog_icon_name;

    let icon = format_remove_dialog_icon_name();
    assert!(
        icon.ends_with("-symbolic"),
        "AdwStatusPage icon name must end with `-symbolic` for HIG-conformant theming; got {icon:?}",
    );
}

#[test]
fn format_remove_dialog_title_returns_remove_account() {
    // The RemoveDialog's `adw::StatusPage::set_title` attribute
    // is populated from this helper. The wording (`"Remove
    // account"`) names the destructive action without restating
    // the specific account — the per-target display label lives
    // in the StatusPage's description body (sourced from
    // `model.state.display_label()`). Pinning the title through
    // a helper keeps the wording in one place shared by the
    // widget binding and the pure-logic tests in
    // `tests/remove_dialog_logic.rs`.
    //
    // No TUI parity: the TUI's `remove` command is CLI-shaped
    // and prompts on stdin (see `crates/paladin-tui/src/view`)
    // rather than mounting a dialog header, so the wording is
    // GTK-specific. Sibling of
    // `paladin_gtk::unlock_dialog::format_unlock_dialog_title`,
    // `paladin_gtk::init_dialog::format_init_dialog_title`,
    // `paladin_gtk::rename_dialog::format_rename_dialog_title`,
    // `paladin_gtk::add_account::format_add_dialog_title`, and
    // `paladin_gtk::startup_error::format_startup_error_title`
    // on the dialog-header-title side; together they pin every
    // dialog's titled surface against a single source of truth.
    use paladin_gtk::remove_dialog::format_remove_dialog_title;

    assert_eq!(
        format_remove_dialog_title(),
        "Remove account",
        "AdwStatusPage title uses the GNOME-HIG verb-led wording for the destructive action",
    );
}
