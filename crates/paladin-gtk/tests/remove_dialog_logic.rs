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
    format_remove_dialog_marker, summary_display_label, InlineError, InlineWarning,
    RemoveDialogInit, RemoveDialogMsg, RemoveDialogOutput, RemoveErrorOutcome,
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

#[test]
fn apply_msg_cancel_emits_cancel_output() {
    // Cancel button must bubble back to `AppModel` as
    // `RemoveDialogOutput::Cancel` so the controller can be dropped
    // and the dialog widget removed from the content tree. Mirrors
    // the `RenameDialogComponent` Cancel staging.
    let out = apply_msg(RemoveDialogMsg::Cancel);
    assert_eq!(out, Some(RemoveDialogOutput::Cancel));
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
