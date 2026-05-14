// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic init-dialog tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/init_dialog_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Plaintext vs encrypted routing: both passphrase fields empty
//!   selects plaintext; non-empty selects encrypted.
//! * Twice-confirm match accepts encrypted submission.
//! * One-empty / mismatched encrypted entries reject inline with
//!   `invalid_passphrase` (`reason: "confirmation_mismatch"`).
//! * Plaintext-warning gate must be ticked before submission is
//!   enabled; the rendered text matches
//!   `paladin_core::format_plaintext_storage_warning()` verbatim.
//! * `paladin_core::classify_init_precheck` routing:
//!   `InitPrecheck::Clear` opens the normal create path,
//!   `InitPrecheck::Existing` opens the destructive-confirmation gate,
//!   `InitPrecheck::Propagate` shows an inline error.
//! * `vault_exists` returned by `create` after a `Clear` precheck
//!   (race) opens the destructive-confirmation gate worded by
//!   `paladin_core::format_init_force_warning(existing_path)`.
//! * Confirming the destructive gate routes through
//!   `paladin_core::create_force` and consumes the pending
//!   `VaultInit`.
//! * Cancelling the destructive gate leaves the existing vault
//!   intact and zeroizes the pending `VaultInit`.
//! * `unsafe_permissions` from `create` / `create_force` routes
//!   back to inline errors (does not transition out of the dialog).
//! * `save_not_committed` and `save_durability_unconfirmed` from
//!   `create` / `create_force` stay inline; `save_not_committed`
//!   carries the `backup_path` field on the `create_force` path
//!   when the failure occurs after backup rotation.
//!
//! The module under test (`paladin_gtk::init_dialog`) is the pure-
//! logic state machine the GTK `InitDialog` shadows. It owns no
//! widgets; the `InitSecretState` from
//! [`paladin_gtk::secret_fields`] holds the secret-bearing
//! passphrase buffers and the pending [`paladin_core::VaultInit`]
//! across the destructive gate (DESIGN §8 / plan §"Secret entry
//! handling").

use std::path::{Path, PathBuf};

use paladin_core::{
    format_init_force_warning, format_plaintext_storage_warning, ErrorKind, PaladinError,
    PermissionSubject, VaultInit, VaultStatus,
};

use paladin_gtk::init_dialog::{
    classify_create_error, classify_create_force_error, classify_mode, classify_precheck,
    destructive_gate_body, plaintext_warning_body, prepare_vault_init, CreateOutcome, InitMode,
    InlineError, PrecheckOutcome, SubmitRejection,
};
use paladin_gtk::secret_fields::{ClearReason, InitSecretState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn existing_vault_path() -> PathBuf {
    PathBuf::from("/home/u/.local/share/paladin/vault.bin")
}

fn unsafe_permissions_err() -> PaladinError {
    PaladinError::UnsafePermissions {
        path: PathBuf::from("/tmp/vault.bin"),
        subject: PermissionSubject::VaultFile,
        actual_mode: "0644".to_string(),
        expected_mode: "0600".to_string(),
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
        committed: false,
        backup_path: Some(PathBuf::from("/tmp/vault.bin.bak")),
    }
}

// ---------------------------------------------------------------------------
// classify_mode — both empty → plaintext; otherwise → encrypted
// ---------------------------------------------------------------------------

#[test]
fn classify_mode_both_empty_selects_plaintext() {
    assert_eq!(classify_mode("", ""), InitMode::Plaintext);
}

#[test]
fn classify_mode_passphrase_only_selects_encrypted() {
    assert_eq!(classify_mode("hunter2", ""), InitMode::Encrypted);
}

#[test]
fn classify_mode_confirm_only_selects_encrypted() {
    assert_eq!(classify_mode("", "hunter2"), InitMode::Encrypted);
}

#[test]
fn classify_mode_both_non_empty_selects_encrypted() {
    assert_eq!(classify_mode("hunter2", "hunter2"), InitMode::Encrypted);
}

// ---------------------------------------------------------------------------
// prepare_vault_init — plaintext requires the warning gate
// ---------------------------------------------------------------------------

#[test]
fn prepare_vault_init_plaintext_requires_warning_acknowledged() {
    let err = prepare_vault_init("", "", false).expect_err("warning not ticked must reject");
    assert_eq!(err, SubmitRejection::PlaintextWarningRequired);
}

#[test]
fn prepare_vault_init_plaintext_warning_ticked_returns_plaintext() {
    let init =
        prepare_vault_init("", "", true).expect("plaintext init accepted with warning ticked");
    assert!(matches!(init, VaultInit::Plaintext));
}

// ---------------------------------------------------------------------------
// prepare_vault_init — encrypted requires both fields filled and matching
// ---------------------------------------------------------------------------

#[test]
fn prepare_vault_init_encrypted_match_returns_encrypted() {
    let init = prepare_vault_init("hunter2", "hunter2", false).expect("matching pair accepted");
    assert!(matches!(init, VaultInit::Encrypted(_)));
}

#[test]
fn prepare_vault_init_encrypted_warning_flag_ignored_when_passphrase_set() {
    // The plaintext warning gate is plaintext-mode only; toggling it
    // should not change encrypted submission outcomes.
    let init = prepare_vault_init("hunter2", "hunter2", true)
        .expect("matching pair accepted regardless of warning flag");
    assert!(matches!(init, VaultInit::Encrypted(_)));
}

#[test]
fn prepare_vault_init_encrypted_one_empty_rejects_with_confirmation_mismatch() {
    // Passphrase set, confirm empty.
    let err =
        prepare_vault_init("hunter2", "", false).expect_err("one-empty encrypted pair must reject");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);
    // Passphrase empty, confirm set.
    let err =
        prepare_vault_init("", "hunter2", false).expect_err("one-empty encrypted pair must reject");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);
}

#[test]
fn prepare_vault_init_encrypted_mismatched_rejects_with_confirmation_mismatch() {
    let err = prepare_vault_init("hunter2", "hunter3", false)
        .expect_err("mismatched encrypted pair must reject");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);
}

#[test]
fn submit_rejection_confirmation_mismatch_renders_invalid_passphrase_reason() {
    // §5 contract: encrypted-mode rejection uses
    // `invalid_passphrase` with `reason: "confirmation_mismatch"`.
    let rej = SubmitRejection::ConfirmationMismatch;
    assert_eq!(rej.error_kind(), Some(ErrorKind::InvalidPassphrase));
    assert_eq!(rej.reason(), Some("confirmation_mismatch"));
}

#[test]
fn submit_rejection_plaintext_warning_required_has_no_paladin_error_kind() {
    // The plaintext-warning gate is a UI-only precondition — it
    // never surfaces as a §5 PaladinError.
    let rej = SubmitRejection::PlaintextWarningRequired;
    assert_eq!(rej.error_kind(), None);
    assert_eq!(rej.reason(), None);
}

// ---------------------------------------------------------------------------
// plaintext_warning_body / destructive_gate_body wording matches core
// ---------------------------------------------------------------------------

#[test]
fn plaintext_warning_body_matches_core_format() {
    assert_eq!(plaintext_warning_body(), format_plaintext_storage_warning());
}

#[test]
fn destructive_gate_body_matches_core_format_for_existing_vault() {
    let path = existing_vault_path();
    assert_eq!(
        destructive_gate_body(&path),
        format_init_force_warning(&path)
    );
}

#[test]
fn destructive_gate_body_uses_supplied_path_for_non_default_basename() {
    let path = Path::new("/tmp/work/secrets.dat");
    assert_eq!(destructive_gate_body(path), format_init_force_warning(path));
    // Sanity: the rendered body must reference the actual basename,
    // not a hardcoded `vault.bin` placeholder.
    assert!(destructive_gate_body(path).contains("secrets.dat"));
}

// ---------------------------------------------------------------------------
// classify_precheck — routes Missing / Existing / Propagate
// ---------------------------------------------------------------------------

#[test]
fn classify_precheck_missing_proceeds_to_create() {
    let outcome = classify_precheck(Ok(VaultStatus::Missing));
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn classify_precheck_plaintext_existing_opens_destructive_gate() {
    let outcome = classify_precheck(Ok(VaultStatus::Plaintext));
    assert!(matches!(outcome, PrecheckOutcome::DestructiveGate));
}

#[test]
fn classify_precheck_encrypted_existing_opens_destructive_gate() {
    let outcome = classify_precheck(Ok(VaultStatus::Encrypted));
    assert!(matches!(outcome, PrecheckOutcome::DestructiveGate));
}

#[test]
fn classify_precheck_invalid_header_opens_destructive_gate() {
    // `classify_init_precheck` treats decode-side errors as Existing
    // (a non-empty file is on disk; force will overwrite it).
    let outcome = classify_precheck(Err(PaladinError::InvalidHeader));
    assert!(matches!(outcome, PrecheckOutcome::DestructiveGate));
}

#[test]
fn classify_precheck_unsafe_permissions_propagates_inline_error() {
    let err = unsafe_permissions_err();
    let outcome = classify_precheck(Err(err));
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::UnsafePermissions);
    // UnsafePermissions renders through format_unsafe_permissions —
    // the rendered body must mention the offending path verbatim.
    assert!(inline.rendered.contains("/tmp/vault.bin"));
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_precheck_vault_missing_propagates_inline_error() {
    // VaultMissing is the only `Err` variant `classify_init_precheck`
    // currently routes to Propagate.
    let outcome = classify_precheck(Err(PaladinError::VaultMissing));
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::VaultMissing);
}

// ---------------------------------------------------------------------------
// classify_create_error — `vault_exists` race opens destructive gate;
// other errors stay inline
// ---------------------------------------------------------------------------

#[test]
fn classify_create_error_vault_exists_opens_destructive_gate() {
    let outcome = classify_create_error(&PaladinError::VaultExists);
    assert!(matches!(outcome, CreateOutcome::DestructiveGate));
}

#[test]
fn classify_create_error_unsafe_permissions_stays_inline() {
    let err = unsafe_permissions_err();
    let outcome = classify_create_error(&err);
    let CreateOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::UnsafePermissions);
    assert!(inline.rendered.contains("/tmp/vault.bin"));
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_create_error_save_not_committed_stays_inline_without_backup() {
    // `create` never rotates a backup (only `create_force` does), so
    // the `backup_path` field is always `None` on this path.
    let err = save_not_committed_no_backup();
    let outcome = classify_create_error(&err);
    let CreateOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_create_error_save_durability_unconfirmed_stays_inline() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_create_error(&err);
    let CreateOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_create_error_invalid_passphrase_stays_inline() {
    // Defensive: zero-length passphrases are rejected at
    // `prepare_vault_init`, but if `EncryptionOptions::new` returns
    // `InvalidPassphrase` the dialog still surfaces it inline.
    let err = PaladinError::InvalidPassphrase {
        reason: "zero_length",
    };
    let outcome = classify_create_error(&err);
    let CreateOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
}

// ---------------------------------------------------------------------------
// classify_create_force_error — `vault_exists` does not occur; backup
// path threads through `save_not_committed`
// ---------------------------------------------------------------------------

#[test]
fn classify_create_force_error_unsafe_permissions_stays_inline() {
    let err = unsafe_permissions_err();
    let inline = classify_create_force_error(&err);
    assert_eq!(inline.kind, ErrorKind::UnsafePermissions);
    assert!(inline.rendered.contains("/tmp/vault.bin"));
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_create_force_error_save_not_committed_threads_backup_path() {
    // `create_force` rotates an existing vault to `.bak` before the
    // new write; if the post-rotation save fails, the §5
    // `save_not_committed` carries the rotated path so the dialog
    // can show it inline.
    let err = save_not_committed_with_backup();
    let inline = classify_create_force_error(&err);
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert_eq!(
        inline.backup_path.as_deref(),
        Some(Path::new("/tmp/vault.bin.bak"))
    );
}

#[test]
fn classify_create_force_error_save_not_committed_without_backup_threads_none() {
    // Failure before the backup rotation runs leaves `backup_path`
    // unset — the dialog must not invent a path.
    let err = save_not_committed_no_backup();
    let inline = classify_create_force_error(&err);
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_create_force_error_save_durability_unconfirmed_stays_inline() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let inline = classify_create_force_error(&err);
    assert_eq!(inline.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert!(inline.backup_path.is_none());
}

// ---------------------------------------------------------------------------
// InlineError rendering — UnsafePermissions uses
// format_unsafe_permissions, others fall back to typed Display
// ---------------------------------------------------------------------------

#[test]
fn inline_error_unsafe_permissions_renders_via_core_formatter() {
    let err = unsafe_permissions_err();
    let inline = InlineError::from_error(&err);
    // The core formatter returns Some(_) for UnsafePermissions; the
    // dialog must not invent its own wording.
    let expected = paladin_core::format_unsafe_permissions(&err)
        .expect("format_unsafe_permissions returns Some for UnsafePermissions");
    assert_eq!(inline.rendered, expected);
}

#[test]
fn inline_error_other_variant_falls_back_to_display() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.rendered, err.to_string());
}

#[test]
fn inline_error_save_not_committed_with_backup_threads_path_into_field() {
    let err = save_not_committed_with_backup();
    let inline = InlineError::from_error(&err);
    assert_eq!(
        inline.backup_path.as_deref(),
        Some(Path::new("/tmp/vault.bin.bak"))
    );
}

// ---------------------------------------------------------------------------
// Destructive gate confirm / cancel flow with InitSecretState
// ---------------------------------------------------------------------------

#[test]
fn destructive_gate_confirm_consumes_pending_vault_init() {
    // Setup: the user filled an encrypted passphrase pair, the dialog
    // built a `VaultInit::Encrypted`, the create call returned
    // `vault_exists`, and we staged the pending init for re-use on
    // the create_force re-run.
    let mut state = InitSecretState::new();
    state.passphrase.set("hunter2");
    state.confirm.set("hunter2");
    let init = prepare_vault_init("hunter2", "hunter2", false).expect("matching pair accepted");
    let prior = state.replace_pending(init);
    assert!(prior.is_none());

    // Confirm: pending is consumed; passphrase fields are wiped.
    let taken = state
        .consume_pending()
        .expect("pending consumed on confirm");
    assert!(matches!(taken, VaultInit::Encrypted(_)));
    assert!(state.pending.is_none());
    assert!(state.passphrase.is_empty());
    assert!(state.confirm.is_empty());
    drop(taken);
}

#[test]
fn destructive_gate_cancel_drops_pending_and_wipes_passphrases() {
    // Setup: same as confirm, but the user cancels the destructive
    // gate. The existing vault is left intact (no create_force
    // call); the pending init is dropped (zeroizing the
    // EncryptionOptions' SecretString) and both passphrase fields
    // are wiped per DESIGN §8.
    let mut state = InitSecretState::new();
    state.passphrase.set("hunter2");
    state.confirm.set("hunter2");
    let init = prepare_vault_init("hunter2", "hunter2", false).expect("matching pair accepted");
    let _ = state.replace_pending(init);

    let prior = state.clear_for(ClearReason::Cancel);
    assert!(matches!(prior, Some(VaultInit::Encrypted(_))));
    assert!(state.pending.is_none());
    assert!(state.passphrase.is_empty());
    assert!(state.confirm.is_empty());
    drop(prior);
}

#[test]
fn destructive_gate_plaintext_pending_round_trips_through_init_state() {
    // The plaintext path also stages a pending VaultInit (a zero-
    // byte enum variant). Confirm consumes it; cancel drops it.
    let mut state = InitSecretState::new();
    let init = prepare_vault_init("", "", true).expect("plaintext accepted with warning");
    let prior = state.replace_pending(init);
    assert!(prior.is_none());

    let taken = state.consume_pending().expect("pending consumed");
    assert!(matches!(taken, VaultInit::Plaintext));
    assert!(state.pending.is_none());
}
