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
//!
//! The widget layer also routes the `Cancel` button click through
//! [`apply_msg`] so the dialog dismissal contract — Cancel resets
//! the entry buffer's shadow state (`L1789` in
//! `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `RenameDialog`) and emits [`RenameDialogOutput::Cancel`] — lives
//! in pure logic alongside the validation / error-routing helpers
//! and stays unit-testable here.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, ErrorKind,
    IconHintInput, PaladinError, Store, Vault, VaultInit, VaultLock,
};

use paladin_gtk::rename_dialog::{
    apply_msg, classify_rename_error, classify_submit, decide_rename_target,
    format_rename_dialog_marker, run_rename_worker, InlineError, InlineWarning, RenameDialogInit,
    RenameDialogMsg, RenameDialogOutput, RenameDialogState, RenameErrorOutcome,
    RenameWorkerCompletion, RenameWorkerEffect, RenameWorkerInput, SubmitOutcome,
    RENAME_DIALOG_MARKER_PREFIX,
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

// ---------------------------------------------------------------------------
// `decide_rename_target` + `format_rename_dialog_marker`
//
// The dialog mount lives behind `AccountListOutput::OpenRenameDialog(id)`.
// `AppModel` calls `decide_rename_target` with the active `Vault` and the
// dispatched `AccountId` to project the row into the [`RenameDialogInit`]
// the widget binds (id + current label + heading label). The marker is
// emitted under `--exit-after-startup` once the dialog has mounted so
// `tests/gtk_smoke.rs` can prove the widget reached the screen.
// ---------------------------------------------------------------------------

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir for rename-target fixture");
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
fn rename_dialog_marker_prefix_is_stable_grep_anchor() {
    // The smoke test in `tests/gtk_smoke.rs` greps for this prefix to
    // prove the dialog mounted; locking the literal here keeps the
    // pure-logic projection and the smoke marker aligned.
    assert_eq!(
        RENAME_DIALOG_MARKER_PREFIX,
        "paladin-gtk: rename_dialog_account="
    );
}

#[test]
fn format_rename_dialog_marker_renders_id_and_display_label() {
    let id = AccountId::new();
    let marker = format_rename_dialog_marker(id, "GitHub:ben");
    assert!(
        marker.starts_with(RENAME_DIALOG_MARKER_PREFIX),
        "marker `{marker}` should start with `{RENAME_DIALOG_MARKER_PREFIX}`",
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
fn decide_rename_target_finds_known_account() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("GitHub"), "ben");

    let init = decide_rename_target(&vault, id).expect("known account id resolves");
    assert_eq!(init.account_id, id);
    assert_eq!(init.current_label, "ben");
    assert_eq!(init.display_label, "GitHub:ben");
}

#[test]
fn decide_rename_target_drops_empty_issuer_in_display_label() {
    // `display_label` collapses to the bare label when issuer is empty
    // or `None`, matching `account_row::display_label`. The rename
    // dialog heading shares that projection so the dialog never reads
    // `:label`.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, None, "alice");

    let init = decide_rename_target(&vault, id).expect("known account id resolves");
    assert_eq!(init.current_label, "alice");
    assert_eq!(init.display_label, "alice");
}

#[test]
fn decide_rename_target_returns_none_for_unknown_id() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let stray = AccountId::new();

    assert!(decide_rename_target(&vault, stray).is_none());
}

#[test]
fn rename_dialog_init_clones_for_reactive_state() {
    // The widget layer stores the init on `self` and clones it across
    // re-renders; the type must implement `Clone` without losing
    // fields.
    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "ben".to_string(),
        display_label: "GitHub:ben".to_string(),
    };
    let cloned = init.clone();
    assert_eq!(cloned.account_id, init.account_id);
    assert_eq!(cloned.current_label, init.current_label);
    assert_eq!(cloned.display_label, init.display_label);
}

// ---------------------------------------------------------------------------
// `RenameDialogState` — live draft + validation state machine
//
// The widget layer drives an `adw::EntryRow` pre-filled with the account's
// current label. Every keystroke runs `classify_submit` so the dialog can
// surface inline errors as the user types. This block tests the pure-logic
// state machine; the widget binding is exercised separately via the smoke
// test.
// ---------------------------------------------------------------------------

fn dummy_init(current_label: &str) -> RenameDialogInit {
    RenameDialogInit {
        account_id: AccountId::new(),
        current_label: current_label.to_string(),
        display_label: format!("Acme:{current_label}"),
    }
}

#[test]
fn rename_dialog_state_new_seeds_draft_from_current_label() {
    let state = RenameDialogState::new(&dummy_init("ben"));
    assert_eq!(state.draft(), "ben");
}

#[test]
fn rename_dialog_state_new_stores_account_id_from_init() {
    // `RenameDialogState` carries the targeted account id alongside
    // the draft so the future `RenameDialogMsg::SubmitClicked` →
    // `RenameDialogOutput::SubmitLabel { account_id, label }`
    // routing can run through `apply_msg(state, msg)` without an
    // extra `account_id` argument. Mirrors the `UnlockDialogState`
    // pattern where the state owns the entire data needed to build
    // the worker input.
    let init = dummy_init("ben");
    let expected = init.account_id;
    let state = RenameDialogState::new(&init);
    assert_eq!(state.account_id(), expected);
}

#[test]
fn rename_dialog_state_account_id_survives_draft_mutations() {
    // `set_draft` only mutates the visible draft and cached
    // validation outcome — the stable account-id projection used
    // by the worker must remain the original target so a mid-flight
    // keystroke does not retarget the rename.
    let init = dummy_init("ben");
    let expected = init.account_id;
    let mut state = RenameDialogState::new(&init);
    state.set_draft("draft-in-progress".to_string());
    assert_eq!(state.account_id(), expected);
}

#[test]
fn rename_dialog_state_new_validates_seeded_draft_positively() {
    // The current label was stored in the vault by `Vault::add` /
    // `Vault::rename`, which both validate, so a freshly-seeded
    // draft must classify as Proceed and the inline-error helper
    // must return None.
    let state = RenameDialogState::new(&dummy_init("ben"));
    let SubmitOutcome::Proceed(trimmed) = state.last_validation().clone() else {
        panic!(
            "expected Proceed on freshly-seeded state, got {:?}",
            state.last_validation()
        );
    };
    assert_eq!(trimmed, "ben");
    assert!(state.inline_error().is_none());
}

#[test]
fn rename_dialog_state_set_draft_to_empty_surfaces_inline_error() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft(String::new());
    assert_eq!(state.draft(), "");
    let inline = state
        .inline_error()
        .expect("empty draft should surface inline error");
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("label"));
    assert!(inline.rendered.contains("empty"));
}

#[test]
fn rename_dialog_state_set_draft_to_whitespace_only_surfaces_inline_error() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("   \t  ".to_string());
    let inline = state
        .inline_error()
        .expect("whitespace-only draft should surface inline error");
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("empty"));
}

#[test]
fn rename_dialog_state_set_draft_to_overlong_surfaces_inline_error() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("x".repeat(LABEL_MAX_BYTES + 1));
    let inline = state
        .inline_error()
        .expect("overlong draft should surface inline error");
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("too_long"));
}

#[test]
fn rename_dialog_state_set_draft_back_to_valid_clears_inline_error() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft(String::new());
    assert!(state.inline_error().is_some());
    state.set_draft("alice".to_string());
    assert!(state.inline_error().is_none());
    let SubmitOutcome::Proceed(trimmed) = state.last_validation().clone() else {
        panic!("expected Proceed after switching back to valid draft");
    };
    assert_eq!(trimmed, "alice");
}

#[test]
fn rename_dialog_state_preserves_untrimmed_draft_for_round_trip() {
    // The visible entry value is the raw draft; trimming happens
    // inside `classify_submit` so the user keeps the whitespace they
    // typed until they commit. Re-classifying the same string later
    // must therefore still trim to the same canonical value.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("  Acme:user  ".to_string());
    assert_eq!(state.draft(), "  Acme:user  ");
    let SubmitOutcome::Proceed(trimmed) = state.last_validation().clone() else {
        panic!("expected Proceed");
    };
    assert_eq!(trimmed, "Acme:user");
}

#[test]
fn rename_dialog_state_clones_for_reactive_state() {
    // The widget stores the state on `self` and may clone it across
    // re-renders or into messages; the type must implement Clone.
    let state = RenameDialogState::new(&dummy_init("ben"));
    let cloned = state.clone();
    assert_eq!(cloned.draft(), state.draft());
}

// ---------------------------------------------------------------------------
// apply_msg — Cancel routing and DraftChanged state mutation
//
// The widget's `update` delegates here so the routing decision (Cancel
// emits `RenameDialogOutput::Cancel`; DraftChanged mutates the draft
// in-place and emits no output) stays a pure function that does not
// require spinning up GTK to verify.
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_cancel_emits_cancel_output() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    let out = apply_msg(&mut state, RenameDialogMsg::Cancel);
    assert_eq!(out, Some(RenameDialogOutput::Cancel));
}

// ---------------------------------------------------------------------------
// L1789 — Reset the entry buffer on cancel / submit / dialog close
//
// The rename dialog's `adw::EntryRow` carries a non-secret label,
// so the L1789 reset obligation is the standard widget-buffer
// reset (not the zeroize-on-drop the URI / passphrase / manual-
// secret buffers require in §"Secret entry handling"). Three
// dismissal paths converge on resetting the underlying
// `gtk::EntryBuffer`:
//
// * Cancel — `apply_msg(Cancel)` calls `state.clear()` to wipe the
//   shadow draft / cached validation / worker outcome and emits
//   [`RenameDialogOutput::Cancel`]; `AppModel` then drops the live
//   [`RenameDialogComponent`] controller, releasing the widget
//   tree (and its `gtk::EntryBuffer`) with it.
// * Submit success — the worker reports
//   [`RenameWorkerEffect::Success`], the dispatch composer flips
//   `drop_dialog = true`
//   (pinned by
//   `should_drop_rename_dialog_after_success_returns_true` in
//   `tests/app_state_logic.rs`), and the same `AppModel` drop
//   path runs.
// * Dialog close (auto-lock / parent navigation) — `AppModel`
//   drops the controller as part of the lock transition,
//   releasing the widget tree with it.
//
// The state-level `clear` API is exercised here so a future
// refactor that decouples the dialog state from the widget
// controller cannot silently drop the L1789 obligation.
// ---------------------------------------------------------------------------

#[test]
fn rename_dialog_state_clear_resets_draft_per_l1789() {
    // The visible draft is the shadow of the `adw::EntryRow`'s
    // text; clearing it pre-drop ensures a defensive re-render
    // against an undropped state cannot leak the cancelled draft.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("draft-in-progress".to_string());
    state.clear();
    assert!(
        state.draft().is_empty(),
        "clear must reset the draft per L1789, got {:?}",
        state.draft()
    );
}

#[test]
fn rename_dialog_state_clear_resets_worker_outcome_per_l1789() {
    // A pending `KeepNewWithWarning` / `RestorePrior` outcome from
    // a prior worker completion must not survive the reset so a
    // future re-mount cannot inherit a stale body warning.
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    state.set_draft("alicia".to_string());
    let outcome = classify_rename_error(&PaladinError::SaveDurabilityUnconfirmed);
    let _ = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    assert!(
        state.worker_outcome().is_some(),
        "precondition: outcome stored before clear",
    );
    state.clear();
    assert!(
        state.worker_outcome().is_none(),
        "clear must reset the worker outcome per L1789",
    );
}

#[test]
fn rename_dialog_state_clear_resets_last_validation_per_l1789() {
    // The cached `SubmitOutcome` must reflect the cleared draft;
    // an empty draft fails §4.1 validation, so `last_validation`
    // routes to `SubmitOutcome::InlineError` after `clear`. This
    // pins the invariant `last_validation == classify_submit(draft)`
    // even across a reset.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("benji".to_string());
    state.clear();
    let inline = state
        .inline_error()
        .expect("cleared draft must surface the empty-label inline error");
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

#[test]
fn rename_dialog_state_clear_preserves_account_id_per_l1789() {
    // The reset is scoped to the visible draft / worker outcome —
    // the stable `AccountId` stays on the state so a defensive
    // re-render against the cleared state still targets the same
    // row.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    let id = state.account_id();
    state.set_draft("benji".to_string());
    state.clear();
    assert_eq!(state.account_id(), id);
}

#[test]
fn rename_dialog_state_clear_is_idempotent_per_l1789() {
    // A second `clear` on an already-empty state is a no-op so the
    // dismissal path is safe to call from multiple AppModel hooks
    // (e.g. Cancel button click race with parent navigation) without
    // re-classifying or re-routing the validation outcome twice.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("benji".to_string());
    state.clear();
    let after_first = state.draft().to_string();
    state.clear();
    assert_eq!(state.draft(), after_first);
    assert!(state.worker_outcome().is_none());
}

#[test]
fn apply_msg_cancel_clears_state_per_l1789() {
    // Cancel is the primary dismissal hook for L1789. `apply_msg`
    // calls `state.clear()` before emitting Cancel so the
    // controller-drop path that follows runs against an already-
    // reset state. Asserting the full reset here pins the
    // dismissal contract end-to-end without a separate widget
    // probe.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("draft-in-progress".to_string());
    let outcome = classify_rename_error(&PaladinError::SaveDurabilityUnconfirmed);
    let _ = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    let _ = apply_msg(&mut state, RenameDialogMsg::Cancel);
    assert!(state.draft().is_empty(), "Cancel must reset the draft");
    assert!(
        state.worker_outcome().is_none(),
        "Cancel must reset the worker outcome",
    );
}

#[test]
fn apply_msg_cancel_still_emits_cancel_output_after_clear_per_l1789() {
    // The clear step must not swallow the Cancel output: `AppModel`
    // relies on the output to drop the controller (and with it the
    // widget tree) so the underlying `gtk::EntryBuffer` is released.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("draft-in-progress".to_string());
    let out = apply_msg(&mut state, RenameDialogMsg::Cancel);
    assert_eq!(out, Some(RenameDialogOutput::Cancel));
}

#[test]
fn apply_msg_draft_changed_updates_draft_and_emits_no_output() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    let out = apply_msg(
        &mut state,
        RenameDialogMsg::DraftChanged("new-label".to_string()),
    );
    assert_eq!(out, None);
    assert_eq!(state.draft(), "new-label");
}

#[test]
fn apply_msg_draft_changed_to_invalid_surfaces_inline_error() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    let out = apply_msg(&mut state, RenameDialogMsg::DraftChanged(String::new()));
    assert_eq!(out, None);
    let inline = state
        .inline_error()
        .expect("empty draft should surface inline error after apply_msg");
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

#[test]
fn rename_dialog_output_cancel_is_distinct_variant() {
    // Defensive: the variant exists and is comparable, so the
    // AppModel can pattern-match on `RenameDialogOutput::Cancel`
    // without an `_` catch-all swallowing future variants.
    let out = RenameDialogOutput::Cancel;
    assert!(matches!(out, RenameDialogOutput::Cancel));
    assert_eq!(out.clone(), RenameDialogOutput::Cancel);
}

// ---------------------------------------------------------------------------
// apply_msg — WorkerFailed routing
//
// Implements the §"Component tree" > RenameDialog contract that
// pre-commit save failures (`save_not_committed`) restore the prior
// label in memory and keep the dialog open with the inline error,
// while durability-unconfirmed failures (`save_durability_unconfirmed`)
// leave the new label in memory and surface the warning. Routing
// lives in `apply_msg` so the per-message decisions stay
// unit-testable here without spinning up the relm4 widget tree.
// ---------------------------------------------------------------------------

#[test]
fn rename_dialog_state_new_initializes_worker_outcome_to_none() {
    // No worker has run yet on a freshly-opened dialog, so the
    // body should not render any prior outcome.
    let state = RenameDialogState::new(&dummy_init("ben"));
    assert!(state.worker_outcome().is_none());
}

#[test]
fn apply_msg_worker_failed_restore_prior_stores_outcome() {
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    state.set_draft("alicia".to_string());
    let outcome = classify_rename_error(&save_not_committed_no_backup());
    let returned = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    assert!(returned.is_none(), "WorkerFailed must not emit an Output");
    let stored = state
        .worker_outcome()
        .expect("RestorePrior outcome should be stored on the state");
    assert!(matches!(stored, RenameErrorOutcome::RestorePrior(_)));
}

#[test]
fn apply_msg_worker_failed_restore_prior_resets_draft_to_init_label() {
    // `save_not_committed` rolls the in-memory vault back, so the
    // dialog must roll the visible draft back to the label the user
    // saw before they started typing — i.e. `init.current_label`.
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    state.set_draft("alicia".to_string());
    let outcome = classify_rename_error(&save_not_committed_no_backup());
    let _ = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    assert_eq!(state.draft(), "alice");
}

#[test]
fn apply_msg_worker_failed_restore_prior_with_backup_resets_draft_to_init_label() {
    // The presence of a rotated `.bak` path does not change the
    // visible-state rollback — `mutate_and_save` restored the
    // in-memory vault to the pre-rename snapshot, so the draft
    // returns to the dialog's seeded label either way.
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    state.set_draft("alicia".to_string());
    let outcome = classify_rename_error(&save_not_committed_with_backup());
    let _ = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    assert_eq!(state.draft(), "alice");
    let stored = state
        .worker_outcome()
        .expect("RestorePrior outcome should be stored");
    assert!(matches!(stored, RenameErrorOutcome::RestorePrior(_)));
}

#[test]
fn apply_msg_worker_failed_keep_new_with_warning_keeps_draft() {
    // `save_durability_unconfirmed` means the rename committed but
    // the parent fsync failed. The visible draft stays on the new
    // value while the warning attaches to the dialog body.
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    state.set_draft("alicia".to_string());
    let outcome = classify_rename_error(&PaladinError::SaveDurabilityUnconfirmed);
    let returned = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    assert!(returned.is_none(), "WorkerFailed must not emit an Output");
    assert_eq!(state.draft(), "alicia");
    let stored = state
        .worker_outcome()
        .expect("KeepNewWithWarning outcome should be stored");
    assert!(matches!(stored, RenameErrorOutcome::KeepNewWithWarning(_)));
}

#[test]
fn apply_msg_worker_failed_defensive_inline_error_keeps_draft() {
    // Defensive: a `validation_error` only fires if the dialog's
    // pre-submit check is bypassed, but if it does, the visible
    // draft stays untouched so the user can edit and retry.
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    state.set_draft("alicia".to_string());
    let err = PaladinError::ValidationError {
        field: "label",
        reason: "too_long".into(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    };
    let outcome = classify_rename_error(&err);
    let _ = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    assert_eq!(state.draft(), "alicia");
    let stored = state
        .worker_outcome()
        .expect("defensive InlineError outcome should be stored");
    assert!(matches!(stored, RenameErrorOutcome::InlineError(_)));
}

#[test]
fn apply_msg_draft_changed_clears_prior_worker_outcome() {
    // After a `save_not_committed` rollback, the user types again
    // to retry. The stored worker outcome must clear so a fresh
    // submit does not re-render a stale error from a previous
    // worker attempt.
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    state.set_draft("alicia".to_string());
    let outcome = classify_rename_error(&save_not_committed_no_backup());
    let _ = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    assert!(state.worker_outcome().is_some());

    let _ = apply_msg(
        &mut state,
        RenameDialogMsg::DraftChanged("alicia-2".to_string()),
    );
    assert!(
        state.worker_outcome().is_none(),
        "DraftChanged must clear the stored worker outcome on retry"
    );
}

#[test]
fn apply_msg_submit_clicked_clears_prior_worker_outcome() {
    // Re-submitting after a stored failure must clear the stale
    // outcome so the body does not render two layers of error
    // while the worker runs.
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    state.set_draft("alicia".to_string());
    let outcome = classify_rename_error(&save_not_committed_no_backup());
    let _ = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    assert!(state.worker_outcome().is_some());

    let _ = apply_msg(&mut state, RenameDialogMsg::SubmitClicked);
    assert!(
        state.worker_outcome().is_none(),
        "SubmitClicked must clear the stored worker outcome before the worker re-runs"
    );
}

#[test]
fn rename_dialog_state_clone_preserves_worker_outcome() {
    // The widget stores the state on `self` and may clone it across
    // re-renders; the worker outcome must survive the clone so the
    // body keeps rendering after the next redraw.
    let mut state = RenameDialogState::new(&dummy_init("alice"));
    let outcome = classify_rename_error(&PaladinError::SaveDurabilityUnconfirmed);
    let _ = apply_msg(&mut state, RenameDialogMsg::WorkerFailed(outcome));
    let cloned = state.clone();
    let stored = cloned
        .worker_outcome()
        .expect("worker outcome should clone through");
    assert!(matches!(stored, RenameErrorOutcome::KeepNewWithWarning(_)));
}

// ---------------------------------------------------------------------------
// RenameDialogState::submit — on-demand classification for the Save
// button / entry `entry-activated` routing branch
//
// Mirrors `UnlockDialogState::submit` so the widget layer can call
// `state.submit()` from the Save click handler and either forward
// the validated label up to `AppModel` or render the inline error
// without touching the entry row. Pure-logic so the routing decision
// is exercisable here without spinning up GTK. The `RenameDialogMsg`
// `SubmitClicked` variant, the `RenameDialogOutput::SubmitLabel`
// projection, and the `Vault::mutate_and_save` worker land in
// follow-up commits alongside the `UnlockedBusy` worker
// infrastructure.
// ---------------------------------------------------------------------------

#[test]
fn rename_dialog_state_submit_returns_proceed_for_valid_draft() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("renamed".to_string());
    let outcome = state.submit();
    let SubmitOutcome::Proceed(trimmed) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    assert_eq!(trimmed, "renamed");
}

#[test]
fn rename_dialog_state_submit_trims_surrounding_whitespace() {
    // The visible draft preserves the user's spacing while the
    // forwarded label is the canonical trimmed value `classify_submit`
    // produces. See `rename_dialog_state_preserves_untrimmed_draft_for_round_trip`
    // for the round-trip side of the same invariant.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("  Acme:user  ".to_string());
    let outcome = state.submit();
    let SubmitOutcome::Proceed(trimmed) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    assert_eq!(trimmed, "Acme:user");
}

#[test]
fn rename_dialog_state_submit_rejects_empty_draft_inline() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft(String::new());
    let outcome = state.submit();
    let SubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

#[test]
fn rename_dialog_state_submit_rejects_whitespace_only_draft_inline() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("   ".to_string());
    let outcome = state.submit();
    let SubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

#[test]
fn rename_dialog_state_submit_rejects_overlong_draft_inline() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("x".repeat(LABEL_MAX_BYTES + 1));
    let outcome = state.submit();
    let SubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

#[test]
fn rename_dialog_state_submit_does_not_mutate_draft() {
    // Submit is a pure read of the draft. The visible value stays
    // until the worker callback applies the success / restore-prior
    // routing decision — otherwise the entry row would flash blank
    // mid-flight.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("  Acme:user  ".to_string());
    let before = state.draft().to_string();
    let _ = state.submit();
    assert_eq!(state.draft(), before);
}

#[test]
fn rename_dialog_state_submit_matches_last_validation_for_valid_draft() {
    // The two read paths must agree so the widget can render the
    // pre-submit inline-error projection from `last_validation()`
    // and still forward the same `SubmitOutcome` on click without a
    // reclassify race.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("renamed".to_string());
    let from_submit = state.submit();
    let from_cache = state.last_validation().clone();
    let (SubmitOutcome::Proceed(a), SubmitOutcome::Proceed(b)) = (from_submit, from_cache) else {
        panic!("expected both outcomes to be Proceed");
    };
    assert_eq!(a, b);
}

#[test]
fn rename_dialog_state_submit_matches_last_validation_for_invalid_draft() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft(String::new());
    let from_submit = state.submit();
    let from_cache = state.last_validation().clone();
    assert!(matches!(from_submit, SubmitOutcome::InlineError(_)));
    assert!(matches!(from_cache, SubmitOutcome::InlineError(_)));
}

// ---------------------------------------------------------------------------
// SubmitClicked → SubmitLabel routing through apply_msg
//
// Mirrors `UnlockDialogMsg::SubmitClicked` → `UnlockDialogOutput::SubmitLock`
// so the widget's Save click goes through the same pure-logic dispatch the
// inline `DraftChanged` / `Cancel` messages already use. `Proceed` produces
// `SubmitLabel { account_id, label }` carrying the canonical trimmed value
// and the stable account id seeded by `RenameDialogState::new`. `InlineError`
// emits `None` so the dialog stays open with the cached inline error
// visible — the worker spawn and the `Vault::mutate_and_save(|v| v.rename(...))`
// invocation land in follow-up commits.
// ---------------------------------------------------------------------------

#[test]
fn rename_dialog_output_submit_label_carries_account_id_and_label() {
    let account_id = AccountId::new();
    let out = RenameDialogOutput::SubmitLabel {
        account_id,
        label: "renamed".to_string(),
    };
    let RenameDialogOutput::SubmitLabel {
        account_id: out_id,
        label,
    } = out
    else {
        panic!("expected SubmitLabel variant");
    };
    assert_eq!(out_id, account_id);
    assert_eq!(label, "renamed");
}

#[test]
fn rename_dialog_output_submit_label_distinct_from_cancel() {
    // `AppModel` pattern-matches on the typed enum; the variants must
    // stay distinct under `PartialEq` so a future Cancel match arm
    // cannot accidentally consume a SubmitLabel and silently drop the
    // rename.
    let cancel = RenameDialogOutput::Cancel;
    let submit = RenameDialogOutput::SubmitLabel {
        account_id: AccountId::new(),
        label: "x".to_string(),
    };
    assert_ne!(cancel, submit);
}

#[test]
fn apply_msg_submit_clicked_with_valid_draft_emits_submit_label() {
    let init = dummy_init("ben");
    let expected_id = init.account_id;
    let mut state = RenameDialogState::new(&init);
    state.set_draft("renamed".to_string());
    let out = apply_msg(&mut state, RenameDialogMsg::SubmitClicked);
    let Some(RenameDialogOutput::SubmitLabel { account_id, label }) = out else {
        panic!("expected SubmitLabel output, got {out:?}");
    };
    assert_eq!(account_id, expected_id);
    assert_eq!(label, "renamed");
}

#[test]
fn apply_msg_submit_clicked_trims_whitespace_in_emitted_label() {
    // The visible draft preserves the user's spacing; the forwarded
    // label is the canonical trimmed value `classify_submit` produces.
    // Mirrors `rename_dialog_state_submit_trims_surrounding_whitespace`
    // but exercised through the `apply_msg` routing the widget uses.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("  Acme:user  ".to_string());
    let out = apply_msg(&mut state, RenameDialogMsg::SubmitClicked);
    let Some(RenameDialogOutput::SubmitLabel { label, .. }) = out else {
        panic!("expected SubmitLabel output, got {out:?}");
    };
    assert_eq!(label, "Acme:user");
}

#[test]
fn apply_msg_submit_clicked_uses_state_account_id() {
    // Defensive: the routing reads the stable account id off the
    // state (seeded by `RenameDialogState::new`), never from the
    // message payload. A keystroke between mount and click must not
    // be able to retarget the rename.
    let init = dummy_init("ben");
    let expected_id = init.account_id;
    let mut state = RenameDialogState::new(&init);
    state.set_draft("renamed".to_string());
    let _ = apply_msg(
        &mut state,
        RenameDialogMsg::DraftChanged("renamed-again".to_string()),
    );
    let out = apply_msg(&mut state, RenameDialogMsg::SubmitClicked);
    let Some(RenameDialogOutput::SubmitLabel { account_id, .. }) = out else {
        panic!("expected SubmitLabel output");
    };
    assert_eq!(account_id, expected_id);
}

#[test]
fn apply_msg_submit_clicked_with_empty_draft_emits_no_output() {
    // The Save button binds `set_sensitive` to a future
    // `state.submit_button_sensitive()` accessor that disables it
    // while the cached validation is `InlineError`; defense-in-depth
    // here verifies that a keyboard accelerator or reactive race
    // still routes safely (no output, no transition out of the
    // dialog).
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft(String::new());
    let out = apply_msg(&mut state, RenameDialogMsg::SubmitClicked);
    assert_eq!(out, None);
}

#[test]
fn apply_msg_submit_clicked_with_overlong_draft_emits_no_output() {
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("x".repeat(LABEL_MAX_BYTES + 1));
    let out = apply_msg(&mut state, RenameDialogMsg::SubmitClicked);
    assert_eq!(out, None);
}

#[test]
fn apply_msg_submit_clicked_with_invalid_draft_keeps_inline_error_visible() {
    // `SubmitClicked` on an invalid draft must keep the inline error
    // visible so the user sees why submission was refused. The cached
    // `last_validation` already tracks the live draft (via
    // `set_draft`); the routing must not blank it out.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft(String::new());
    let _ = apply_msg(&mut state, RenameDialogMsg::SubmitClicked);
    let inline = state
        .inline_error()
        .expect("invalid draft inline error must survive SubmitClicked routing");
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

#[test]
fn apply_msg_submit_clicked_does_not_mutate_draft() {
    // The visible draft must survive the round trip so the user's
    // typed value is not silently dropped before the worker callback
    // applies the success / restore-prior routing decision. Mirrors
    // `rename_dialog_state_submit_does_not_mutate_draft` but at the
    // routing layer.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("  Acme:user  ".to_string());
    let before = state.draft().to_string();
    let _ = apply_msg(&mut state, RenameDialogMsg::SubmitClicked);
    assert_eq!(state.draft(), before);
}

#[test]
fn rename_dialog_msg_submit_clicked_is_distinct_variant() {
    // Defensive: the variant exists so the widget can dispatch it
    // from the Save button click signal. Pattern-matching round-
    // trips through the enum.
    let msg = RenameDialogMsg::SubmitClicked;
    assert!(matches!(msg, RenameDialogMsg::SubmitClicked));
}

// ---------------------------------------------------------------------------
// run_rename_worker — synchronous body of the spawn_blocking rename worker
//
// `run_rename_worker` is the body of the `gio::spawn_blocking
// Vault::mutate_and_save(|v| v.rename(...))` worker fired by
// `AppModel::update` from
// `AppMsg::RenameDialogAction(RenameDialogOutput::SubmitLabel)`. The
// helper consumes the live `(Vault, Store)` pair by value so the busy
// gate reinstalls whichever pair the worker returns — success,
// `save_durability_unconfirmed`, or pre-commit rollback. Extracting
// the worker body as a pure function lets `AppModel::update`'s
// closure stay a thin `gio::spawn_blocking(move || run_rename_worker(
// input))` while the real `mutate_and_save` call stays unit-testable
// here against tempfile-backed plaintext vaults — no GTK /
// libadwaita main loop required.
// ---------------------------------------------------------------------------

#[test]
fn run_rename_worker_plaintext_rename_succeeds_and_returns_live_pair() {
    // Happy path: rename a TOTP account on a plaintext vault and
    // verify the worker reports Success, the renamed account carries
    // the new label, and the `(Vault, Store)` pair survives the
    // worker so `AppModel::update` can reinstall it.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let id = add_totp(&mut vault, &store, Some("Acme"), "alice");

    let completion = run_rename_worker(RenameWorkerInput {
        vault,
        store,
        account_id: id,
        label: "bob".to_string(),
        now: SystemTime::now(),
    });

    let RenameWorkerCompletion {
        effect,
        vault,
        store: _,
    } = completion;
    assert!(
        matches!(effect, RenameWorkerEffect::Success),
        "plaintext rename success must surface as RenameWorkerEffect::Success, got {effect:?}",
    );
    let summary = vault
        .summaries()
        .find(|s| s.id == id)
        .expect("renamed account still exists in the returned vault");
    assert_eq!(summary.label, "bob");
}

#[test]
fn run_rename_worker_unknown_account_routes_inline_error_and_returns_pair() {
    // Defensive: a mid-flight removal between the kebab activation
    // and the worker dispatch leaves the worker targeting an unknown
    // id. `Vault::rename` surfaces `invalid_state { state:
    // "account_not_found" }` which `classify_rename_error` routes to
    // `RenameErrorOutcome::InlineError`. The vault returned by the
    // worker must be unchanged so `AppModel::update` reinstalls it
    // without losing other accounts.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let surviving = add_totp(&mut vault, &store, None, "alice");
    let stray = AccountId::new();

    let completion = run_rename_worker(RenameWorkerInput {
        vault,
        store,
        account_id: stray,
        label: "bob".to_string(),
        now: SystemTime::now(),
    });

    match completion.effect {
        RenameWorkerEffect::Failure(RenameErrorOutcome::InlineError(inline)) => {
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
fn run_rename_worker_validation_error_routes_inline_error() {
    // Defensive: a widget that bypasses `classify_submit` and sends
    // an empty label is still caught by `Vault::rename`'s
    // `validate_label` call. `classify_rename_error` routes the typed
    // `validation_error` to `RenameErrorOutcome::InlineError` so the
    // dialog stays open with the inline error visible. The
    // `mutate_and_save` snapshot rollback keeps the prior label in
    // place on the returned vault.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let id = add_totp(&mut vault, &store, None, "alice");

    let completion = run_rename_worker(RenameWorkerInput {
        vault,
        store,
        account_id: id,
        label: String::new(),
        now: SystemTime::now(),
    });

    match completion.effect {
        RenameWorkerEffect::Failure(RenameErrorOutcome::InlineError(inline)) => {
            assert_eq!(inline.kind, ErrorKind::ValidationError);
        }
        other => panic!("expected Failure(InlineError) for empty label, got {other:?}"),
    }
    let summary = completion
        .vault
        .summaries()
        .find(|s| s.id == id)
        .expect("account survives validation failure");
    assert_eq!(
        summary.label, "alice",
        "validation failure must not mutate the visible label",
    );
}

#[test]
fn run_rename_worker_same_label_still_bumps_updated_at() {
    // CLI parity: `Vault::rename` always bumps `updated_at`, even
    // when the new label matches the prior one. The worker must not
    // short-circuit on a same-label rename — `classify_submit` and
    // the dialog already refuse to short-circuit, and the worker is
    // the final gate before persistence.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let id = add_totp(&mut vault, &store, None, "alice");
    let before = vault
        .summaries()
        .find(|s| s.id == id)
        .expect("account exists pre-rename")
        .updated_at;

    // Pin `now` to a value strictly later than the original
    // `updated_at` so the bump is observable regardless of the
    // wall-clock resolution between the `add_totp` call and here.
    let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(before + 5);
    let completion = run_rename_worker(RenameWorkerInput {
        vault,
        store,
        account_id: id,
        label: "alice".to_string(),
        now,
    });

    assert!(matches!(completion.effect, RenameWorkerEffect::Success));
    let after = completion
        .vault
        .summaries()
        .find(|s| s.id == id)
        .expect("account survives same-label rename")
        .updated_at;
    assert!(
        after > before,
        "same-label rename must bump updated_at ({before} → {after})",
    );
}

#[test]
fn run_rename_worker_persists_label_to_disk() {
    // The worker must not just mutate the in-memory vault — it goes
    // through `mutate_and_save` so the new label survives a reopen.
    // This pins the round trip through the §4.3 atomic-write pipeline
    // without exercising the GTK loop.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let id = add_totp(&mut vault, &store, Some("Acme"), "alice");

    let completion = run_rename_worker(RenameWorkerInput {
        vault,
        store,
        account_id: id,
        label: "bob".to_string(),
        now: SystemTime::now(),
    });
    assert!(matches!(completion.effect, RenameWorkerEffect::Success));
    drop(completion);

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let summary = reopened
        .summaries()
        .find(|s| s.id == id)
        .expect("renamed account survives reopen");
    assert_eq!(summary.label, "bob");
}

#[test]
fn format_rename_dialog_title_matches_tui_wording() {
    // The Rename account dialog's header `gtk::Label` `set_label`
    // attribute is populated from this helper, so the wording must
    // match what the TUI's rename view shows (the
    // `" Rename account "` block title built by `render` in
    // `crates/paladin-tui/src/view/rename.rs` — the surrounding
    // spaces are the TUI block-padding convention and drop out
    // because `gtk::Label` renders the bare text without them).
    // Pinning the title through a helper keeps the GTK / TUI
    // wording aligned against a single source of truth so a future
    // copy change cannot diverge silently. Sibling of
    // `paladin_gtk::add_account::format_add_dialog_title` on the
    // dialog-header-title side.
    use paladin_gtk::rename_dialog::format_rename_dialog_title;

    assert_eq!(
        format_rename_dialog_title(),
        "Rename account",
        "dialog header mirrors the TUI rename view's \" Rename account \" block title",
    );
}

#[test]
fn format_rename_dialog_label_title_returns_label() {
    // The label `AdwEntryRow`'s `set_title` attribute is populated
    // from this helper. The wording is the static `"Label"` —
    // intentionally distinct from the TUI rename view's
    // `"New label:"` row built by `text_field_line` in
    // `crates/paladin-tui/src/view/rename.rs`, because the GTK
    // dialog already renders a separate `"Renaming X."` sub-title
    // above the row that names which account is being renamed,
    // making `"New label"` redundant; the TUI omits that sub-title
    // and uses `"New label:"` to disambiguate from the displayed
    // current-label prompt. Pinning the title through a helper
    // keeps the wording in one place shared by the widget binding
    // and the pure-logic test, in lockstep with the partner
    // `format_rename_dialog_title` helper on the dialog-chrome
    // side. Sibling of `paladin_gtk::add_account::format_manual_label_title`
    // on the row-title side: both return `"Label"` because the
    // shared GNOME convention for an `AdwEntryRow` editing an
    // account's `label` field is the bare field-name title.
    use paladin_gtk::rename_dialog::format_rename_dialog_label_title;

    assert_eq!(
        format_rename_dialog_label_title(),
        "Label",
        "row title matches the GNOME convention for an AdwEntryRow editing the account label",
    );
}

#[test]
fn format_rename_dialog_cancel_label_returns_cancel() {
    // The Rename account dialog's footer Cancel `gtk::Button`'s
    // `set_label` attribute is populated from this helper. The
    // label wording is the fixed GNOME-convention `"Cancel"` —
    // surfaced through a helper so the string lives in one place
    // shared by the widget binding and the snapshot tests. Sibling
    // of `paladin_gtk::add_account::format_add_dialog_cancel_label`
    // on the dialog-footer-cancel side; both return the same
    // GNOME-convention wording, so a future copy change can land
    // through whichever helper's surface it applies to without
    // silently moving the other.
    use paladin_gtk::rename_dialog::format_rename_dialog_cancel_label;

    assert_eq!(
        format_rename_dialog_cancel_label(),
        "Cancel",
        "dialog cancel button label is the fixed GNOME-convention wording",
    );
}

#[test]
fn format_rename_dialog_subtitle_renders_renaming_display_label() {
    // The Rename account dialog renders a second `gtk::Label`
    // beneath the header whose `set_label` attribute is populated
    // from this helper. The body names which account the user is
    // editing in the form `"Renaming <display>."` where `<display>`
    // is the pre-formatted `<issuer>:<label>` heading the rest of
    // the dialog uses (see `format_rename_dialog_marker`). Pinning
    // the format string through a helper keeps the GTK wording in
    // one place shared by the widget binding and the pure-logic
    // tests; the helper takes the display label by `&str` so the
    // widget can pass `&model.init.display_label` without cloning.
    //
    // No TUI parity: the TUI renders a two-line prompt
    // (`"Renaming the following account:"` followed by the
    // current-label line) instead of the GTK's single-line
    // `"Renaming X."` form — the GTK condenses the two TUI lines
    // into a single sub-title so the dialog stays compact.
    use paladin_gtk::rename_dialog::format_rename_dialog_subtitle;

    assert_eq!(
        format_rename_dialog_subtitle("GitHub:alice"),
        "Renaming GitHub:alice.",
        "subtitle names the account being renamed inline with the display heading",
    );
    assert_eq!(
        format_rename_dialog_subtitle(""),
        "Renaming .",
        "empty display label degrades to the literal trailing period without panicking",
    );
}

#[test]
fn format_rename_dialog_save_label_returns_save() {
    // The Rename account dialog's footer Save `gtk::Button`'s
    // `set_label` attribute is populated from this helper. The
    // label wording is the GNOME-convention `"Save"` — surfaced
    // through a helper so the string lives in one place shared by
    // the widget binding and the snapshot tests, mirroring the
    // partner `format_rename_dialog_cancel_label` helper on the
    // dialog-footer-cancel side.
    use paladin_gtk::rename_dialog::format_rename_dialog_save_label;

    assert_eq!(
        format_rename_dialog_save_label(),
        "Save",
        "dialog save button label is the fixed GNOME-convention wording",
    );
}

#[test]
fn format_rename_dialog_save_button_sensitive_proceeds_when_validation_succeeds() {
    // The Save `gtk::Button`'s `set_sensitive` attribute is
    // bound through this helper so the dialog reads off the
    // cached `RenameDialogState::last_validation` rather than
    // re-running `classify_submit` on every redraw. A
    // `SubmitOutcome::Proceed` outcome enables the button so the
    // user can commit the validated label.
    use paladin_gtk::rename_dialog::format_rename_dialog_save_button_sensitive;

    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let state = RenameDialogState::new(&init);
    assert!(
        matches!(state.last_validation(), SubmitOutcome::Proceed(_)),
        "seeded label passes §4.1 validation",
    );

    assert!(
        format_rename_dialog_save_button_sensitive(&state),
        "Save button must be sensitive when the live draft validates",
    );
}

#[test]
fn format_rename_dialog_save_button_sensitive_dimmed_when_validation_fails() {
    // The Save button must dim when the draft fails §4.1
    // validation so the user cannot bypass the inline error to
    // submit an empty / overlong label. The helper inspects the
    // cached [`RenameDialogState::last_validation`] and returns
    // `false` on `SubmitOutcome::InlineError` so the widget
    // disables the button until the user fixes the draft.
    use paladin_gtk::rename_dialog::format_rename_dialog_save_button_sensitive;

    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let mut state = RenameDialogState::new(&init);
    state.set_draft(String::new());
    assert!(
        matches!(state.last_validation(), SubmitOutcome::InlineError(_)),
        "empty draft fails §4.1 validation",
    );

    assert!(
        !format_rename_dialog_save_button_sensitive(&state),
        "Save button must be dimmed when the live draft fails validation",
    );
}

#[test]
fn format_rename_dialog_success_toast_returns_renamed() {
    // `AppMsg::RenameWorkerCompleted` raises an `AdwToast` on the
    // success branch per `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone
    // 7 checklist" > "In-app account rename" ("On success, refresh
    // `AccountListComponent` from the returned vault, close the
    // dialog, and surface a status / toast confirmation."). The body
    // is pinned through this helper so the wording stays in one place
    // shared by the widget binding and the pure-logic tests; sibling
    // of `format_hotp_durability_unconfirmed_toast` on the
    // toast-body-text side.
    use paladin_gtk::rename_dialog::format_rename_dialog_success_toast;

    assert_eq!(
        format_rename_dialog_success_toast(),
        "Account renamed.",
        "wording must stay stable so the success toast does not drift silently",
    );
}

// ---------------------------------------------------------------------------
// Busy gating — `IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership":
// while the AppModel is in `UnlockedBusy`, every mutating control surface
// disables. The rename dialog's Save button is one such surface; while a
// `Vault::mutate_and_save` worker is in flight, the dialog dims its Save
// button so the user cannot kick off a second rename worker before the
// first one returns the `(Vault, Store)` pair.
// ---------------------------------------------------------------------------

#[test]
fn fresh_rename_dialog_state_is_not_busy() {
    // A freshly opened dialog has not dispatched any worker yet, so the
    // busy latch must start cleared. `AppModel::sync_rename_dialog_busy`
    // would otherwise emit an immediate `SetBusy(false)` on mount,
    // which is harmless but wastes a view tick.
    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let state = RenameDialogState::new(&init);

    assert!(
        !state.is_busy(),
        "fresh state must not be busy — no worker has been dispatched",
    );
}

#[test]
fn apply_msg_set_busy_true_marks_state_busy() {
    // `AppModel` brackets the `gio::spawn_blocking
    // Vault::mutate_and_save(|v| v.rename(...))` call with
    // `SetBusy(true)` / `SetBusy(false)` so the dialog can dim its
    // Save button while the worker owns the `(Vault, Store)` pair.
    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let mut state = RenameDialogState::new(&init);
    let out = apply_msg(&mut state, RenameDialogMsg::SetBusy(true));

    assert!(out.is_none(), "SetBusy must not emit a dialog output");
    assert!(state.is_busy(), "SetBusy(true) must flip the busy latch on");
}

#[test]
fn apply_msg_set_busy_false_clears_busy_state() {
    // On worker return `AppModel` emits `SetBusy(false)` so the Save
    // button re-enables alongside the reinstalled `(Vault, Store)`
    // pair.
    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let mut state = RenameDialogState::new(&init);
    apply_msg(&mut state, RenameDialogMsg::SetBusy(true));
    let out = apply_msg(&mut state, RenameDialogMsg::SetBusy(false));

    assert!(out.is_none(), "SetBusy must not emit a dialog output");
    assert!(
        !state.is_busy(),
        "SetBusy(false) must flip the busy latch off",
    );
}

#[test]
fn apply_msg_set_busy_same_value_is_idempotent() {
    // The reconciler in `AppModel::sync_rename_dialog_busy`
    // debounces same-value flips, but the dialog itself must also be
    // idempotent so a stray duplicate emit does not corrupt the
    // latch.
    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let mut state = RenameDialogState::new(&init);
    apply_msg(&mut state, RenameDialogMsg::SetBusy(true));
    apply_msg(&mut state, RenameDialogMsg::SetBusy(true));
    assert!(state.is_busy(), "two SetBusy(true) calls leave busy on");

    apply_msg(&mut state, RenameDialogMsg::SetBusy(false));
    apply_msg(&mut state, RenameDialogMsg::SetBusy(false));
    assert!(!state.is_busy(), "two SetBusy(false) calls leave busy off");
}

#[test]
fn apply_msg_set_busy_does_not_disturb_draft_or_validation() {
    // The busy latch is orthogonal to the draft / validation state
    // — flipping it must not clear the user-typed draft or the
    // cached `last_validation`, otherwise a worker round trip would
    // reset the entry row mid-edit.
    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let mut state = RenameDialogState::new(&init);
    state.set_draft("alice-renamed".to_string());
    let draft_before = state.draft().to_string();
    let validation_before = matches!(state.last_validation(), SubmitOutcome::Proceed(_));

    apply_msg(&mut state, RenameDialogMsg::SetBusy(true));

    assert_eq!(state.draft(), draft_before, "draft survives SetBusy");
    assert_eq!(
        matches!(state.last_validation(), SubmitOutcome::Proceed(_)),
        validation_before,
        "cached validation survives SetBusy",
    );
}

#[test]
fn format_rename_dialog_save_button_sensitive_dimmed_when_busy() {
    // Even with a fully validated draft, the Save button must dim
    // while a `Vault::mutate_and_save` worker is in flight so the
    // user cannot kick off a second rename worker before the first
    // returns the `(Vault, Store)` pair.
    use paladin_gtk::rename_dialog::format_rename_dialog_save_button_sensitive;

    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let mut state = RenameDialogState::new(&init);
    assert!(
        matches!(state.last_validation(), SubmitOutcome::Proceed(_)),
        "seeded label passes §4.1 validation",
    );
    assert!(
        format_rename_dialog_save_button_sensitive(&state),
        "Save button sensitive while idle and validation succeeds",
    );

    apply_msg(&mut state, RenameDialogMsg::SetBusy(true));

    assert!(
        !format_rename_dialog_save_button_sensitive(&state),
        "Save button dims while the AppModel is busy",
    );
}

#[test]
fn format_rename_dialog_save_button_sensitive_re_enables_after_busy_clears() {
    // After the worker returns `AppModel` emits `SetBusy(false)`;
    // the Save button must re-enable so the user can retry / edit
    // again.
    use paladin_gtk::rename_dialog::format_rename_dialog_save_button_sensitive;

    let init = RenameDialogInit {
        account_id: AccountId::new(),
        current_label: "alice".to_string(),
        display_label: "GitHub:alice".to_string(),
    };
    let mut state = RenameDialogState::new(&init);
    apply_msg(&mut state, RenameDialogMsg::SetBusy(true));
    assert!(!format_rename_dialog_save_button_sensitive(&state));

    apply_msg(&mut state, RenameDialogMsg::SetBusy(false));

    assert!(
        format_rename_dialog_save_button_sensitive(&state),
        "Save button re-enables after busy clears",
    );
}
