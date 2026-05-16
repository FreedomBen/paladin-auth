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
//! [`apply_msg`] so the dialog dismissal contract — Cancel emits
//! [`RenameDialogOutput::Cancel`] without touching the draft —
//! lives in pure logic alongside the validation / error-routing
//! helpers and stays unit-testable here.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, ErrorKind,
    IconHintInput, PaladinError, Store, Vault, VaultInit, VaultLock,
};

use paladin_gtk::rename_dialog::{
    apply_msg, classify_rename_error, classify_submit, decide_rename_target,
    format_rename_dialog_marker, InlineError, InlineWarning, RenameDialogInit, RenameDialogMsg,
    RenameDialogOutput, RenameDialogState, RenameErrorOutcome, SubmitOutcome,
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

#[test]
fn apply_msg_cancel_does_not_mutate_draft() {
    // Cancel is a pure dismissal — the draft must round-trip
    // unchanged so the user's typed value is not silently dropped
    // before a future `save_not_committed` rollback that re-opens
    // the same dialog instance can re-seed the prior label.
    let mut state = RenameDialogState::new(&dummy_init("ben"));
    state.set_draft("draft-in-progress".to_string());
    let before = state.draft().to_string();
    let _ = apply_msg(&mut state, RenameDialogMsg::Cancel);
    assert_eq!(state.draft(), before);
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
