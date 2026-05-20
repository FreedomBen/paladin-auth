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
    format_init_force_warning, format_plaintext_storage_warning, Argon2Params, EncryptionOptions,
    ErrorKind, PaladinError, PermissionSubject, Store, VaultInit, VaultLock, VaultStatus,
};
use secrecy::SecretString;

use paladin_gtk::init_dialog::{
    apply_msg, classify_create_error, classify_create_force_error, classify_mode,
    classify_precheck, destructive_gate_body, plaintext_warning_body, prepare_vault_init,
    run_init_worker, CreateOutcome, InitDialogMsg, InitDialogOutput, InitDialogState, InitMode,
    InitWorkerCompletion, InitWorkerEffect, InitWorkerInput, InitWorkerMode, InlineError,
    PrecheckOutcome, SubmitRejection,
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

/// Representative attempted-mkdir directory for create classifier
/// tests. Matches the `unsafe_permissions_err()` vault file's parent
/// so a fixture sees a coherent (path, parent) pair.
fn attempted_dir() -> &'static Path {
    Path::new("/tmp")
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
    let outcome = classify_create_error(&PaladinError::VaultExists, attempted_dir());
    assert!(matches!(outcome, CreateOutcome::DestructiveGate));
}

#[test]
fn classify_create_error_unsafe_permissions_stays_inline() {
    let err = unsafe_permissions_err();
    let outcome = classify_create_error(&err, attempted_dir());
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
    let outcome = classify_create_error(&err, attempted_dir());
    let CreateOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_create_error_save_durability_unconfirmed_stays_inline() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_create_error(&err, attempted_dir());
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
    let outcome = classify_create_error(&err, attempted_dir());
    let CreateOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
}

#[test]
fn classify_create_error_create_vault_dir_renders_friendly_message_with_path() {
    // §4.3 mkdir failure on a fresh `Store::create` surfaces as the
    // friendly path-aware wording from
    // `paladin_core::format_create_vault_dir_error`, naming the
    // directory paladin tried to `mkdir -p`.
    let err = PaladinError::IoError {
        operation: "create_vault_dir",
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    };
    let outcome = classify_create_error(&err, Path::new("/home/u/.local/share/paladin"));
    let CreateOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::IoError);
    assert!(
        inline.rendered.contains("/home/u/.local/share/paladin"),
        "rendered text should name the attempted dir, got {:?}",
        inline.rendered
    );
    assert!(
        inline
            .rendered
            .contains("Check that you have write permission"),
        "rendered text should include the friendly hint, got {:?}",
        inline.rendered
    );
}

// ---------------------------------------------------------------------------
// classify_create_force_error — `vault_exists` does not occur; backup
// path threads through `save_not_committed`
// ---------------------------------------------------------------------------

#[test]
fn classify_create_force_error_unsafe_permissions_stays_inline() {
    let err = unsafe_permissions_err();
    let inline = classify_create_force_error(&err, attempted_dir());
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
    let inline = classify_create_force_error(&err, attempted_dir());
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
    let inline = classify_create_force_error(&err, attempted_dir());
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_create_force_error_save_durability_unconfirmed_stays_inline() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let inline = classify_create_force_error(&err, attempted_dir());
    assert_eq!(inline.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert!(inline.backup_path.is_none());
}

#[test]
fn classify_create_force_error_create_vault_dir_renders_friendly_message_with_path() {
    let err = PaladinError::IoError {
        operation: "create_vault_dir",
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    };
    let inline = classify_create_force_error(&err, Path::new("/home/u/.local/share/paladin"));
    assert_eq!(inline.kind, ErrorKind::IoError);
    assert!(
        inline.rendered.contains("/home/u/.local/share/paladin"),
        "rendered text should name the attempted dir, got {:?}",
        inline.rendered
    );
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

// `format_init_dialog_marker` / `INIT_DIALOG_MARKER_PREFIX` pin the
// `--exit-after-startup` stdout contract consumed by `tests/gtk_smoke.rs`
// for the `Missing` branch. Pure-logic tests live here so the
// contract is verified without spinning up a display server.

#[test]
fn init_dialog_marker_prefix_is_stable() {
    assert_eq!(
        paladin_gtk::init_dialog::INIT_DIALOG_MARKER_PREFIX,
        "paladin-gtk: init_dialog_path=",
    );
}

#[test]
fn format_init_dialog_marker_renders_resolved_path() {
    let path = Path::new("/tmp/example/vault.bin");
    assert_eq!(
        paladin_gtk::init_dialog::format_init_dialog_marker(path),
        "paladin-gtk: init_dialog_path=/tmp/example/vault.bin",
    );
}

#[test]
fn format_init_dialog_marker_starts_with_prefix() {
    // Every rendered marker begins with `INIT_DIALOG_MARKER_PREFIX`
    // so the smoke test can grep by prefix when the path varies.
    let marker = paladin_gtk::init_dialog::format_init_dialog_marker(Path::new("/x"));
    assert!(marker.starts_with(paladin_gtk::init_dialog::INIT_DIALOG_MARKER_PREFIX));
}

// ---------------------------------------------------------------------------
// run_init_worker — synchronous body of the spawn_blocking Store::create
// worker fired by `AppModel::update` from the InitDialog submit dispatch.
//
// Mirrors the `rename_dialog::run_rename_worker` pattern: the
// `InitWorkerInput` is consumed once and routed through the matching
// `Store::create` / `Store::create_force` call. The worker returns a
// `(Vault, Store)` pair on success; on failure it routes the typed
// `PaladinError` through `classify_create_error` /
// `classify_create_force_error` so AppModel reopens the destructive
// gate or surfaces an inline error without re-deriving the routing
// off the raw error.
//
// Extracting the worker body as a pure function lets `AppModel::update`
// stay a thin `gio::spawn_blocking(move || run_init_worker(input))`
// while keeping the real `Store::create` round-trip unit-testable
// against tempfile-backed plaintext vaults — no GTK / libadwaita main
// loop required.
// ---------------------------------------------------------------------------

fn secure_tempdir_for_worker() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir for init worker fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    dir
}

#[test]
fn run_init_worker_plaintext_create_succeeds_and_returns_live_pair() {
    // Happy path: a `Plaintext` `VaultInit` against a fresh path is
    // routed through `Store::create` and the worker returns the live
    // `(Vault, Store)` pair the `Unlocked` transition needs.
    let dir = secure_tempdir_for_worker();
    let path = dir.path().join("vault.bin");

    let completion = run_init_worker(InitWorkerInput {
        init: VaultInit::Plaintext,
        vault_path: path.clone(),
        mode: InitWorkerMode::Create,
    });

    let InitWorkerCompletion { effect } = completion;
    match effect {
        InitWorkerEffect::Success { vault, store: _ } => {
            assert!(
                vault.summaries().next().is_none(),
                "freshly created vault must be empty",
            );
        }
        other => panic!("expected Success for plaintext create, got {other:?}"),
    }
    assert!(path.exists(), "vault file must be created on disk");
}

#[test]
fn run_init_worker_encrypted_create_succeeds_with_light_params() {
    // Encrypted path exercises `Store::create` via the
    // `VaultInit::Encrypted` arm. Light Argon2 params keep the test
    // fast — the production defaults (m_kib=65_536, t=3) are
    // unsuitable for unit tests.
    let dir = secure_tempdir_for_worker();
    let path = dir.path().join("vault.bin");

    let cheap = Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    };
    let opts = EncryptionOptions::with_params(SecretString::from("hunter2".to_string()), cheap)
        .expect("cheap params + non-empty passphrase accepted");

    let completion = run_init_worker(InitWorkerInput {
        init: VaultInit::Encrypted(opts),
        vault_path: path.clone(),
        mode: InitWorkerMode::Create,
    });

    assert!(
        matches!(completion.effect, InitWorkerEffect::Success { .. }),
        "encrypted create must surface as Success, got {effect:?}",
        effect = completion.effect,
    );
    assert!(
        path.exists(),
        "encrypted vault file must be created on disk"
    );
}

/// Seed an on-disk plaintext vault so subsequent `Store::create`
/// calls land on `vault_exists` (the destructive-gate trigger) and
/// `Store::create_force` calls see a primary to rotate to `.bak`.
/// Mirrors the CLI / TUI `init` flow: `Store::create` only builds
/// the in-memory pair, so the seed must commit via `Vault::save`.
fn seed_plaintext_vault_on_disk(path: &Path) {
    let (vault, store) =
        Store::create(path, VaultInit::Plaintext).expect("seed Store::create plaintext");
    vault.save(&store).expect("commit seed vault to disk");
}

#[test]
fn run_init_worker_create_existing_vault_routes_destructive_gate() {
    // `Store::create` against a path that already holds a vault
    // surfaces `vault_exists`. `classify_create_error` maps that onto
    // `CreateOutcome::DestructiveGate`, and the worker hoists it to
    // `InitWorkerEffect::DestructiveGate` so AppModel reopens the
    // destructive-confirmation gate worded by
    // `paladin_core::format_init_force_warning`. The pending
    // `VaultInit` lives in `InitSecretState::pending` for the
    // create-force re-run.
    let dir = secure_tempdir_for_worker();
    let path = dir.path().join("vault.bin");
    seed_plaintext_vault_on_disk(&path);

    let completion = run_init_worker(InitWorkerInput {
        init: VaultInit::Plaintext,
        vault_path: path.clone(),
        mode: InitWorkerMode::Create,
    });

    assert!(
        matches!(completion.effect, InitWorkerEffect::DestructiveGate),
        "vault_exists on Create must route to DestructiveGate, got {effect:?}",
        effect = completion.effect,
    );
    assert!(path.exists(), "seeded vault file must remain on disk");
}

#[test]
fn run_init_worker_create_force_overwrites_existing_vault() {
    // `Store::create_force` always overwrites — `vault_exists` cannot
    // surface on this path. The worker therefore routes the
    // existing-vault scenario to `Success` and rotates the prior file
    // to `vault.bin.bak`.
    let dir = secure_tempdir_for_worker();
    let path = dir.path().join("vault.bin");
    let backup = dir.path().join("vault.bin.bak");
    seed_plaintext_vault_on_disk(&path);

    let completion = run_init_worker(InitWorkerInput {
        init: VaultInit::Plaintext,
        vault_path: path.clone(),
        mode: InitWorkerMode::CreateForce,
    });

    assert!(
        matches!(completion.effect, InitWorkerEffect::Success { .. }),
        "create_force must succeed against an existing vault, got {effect:?}",
        effect = completion.effect,
    );
    assert!(path.exists(), "primary vault file must remain on disk");
    assert!(
        backup.exists(),
        "prior vault must rotate to vault.bin.bak (§5 backup rotation)",
    );
}

#[test]
fn run_init_worker_persists_plaintext_to_disk() {
    // Worker goes through the §4.3 atomic-write pipeline; the freshly
    // created vault must survive a reopen via `Store::open`. This
    // pins the round-trip without exercising the GTK loop.
    let dir = secure_tempdir_for_worker();
    let path = dir.path().join("vault.bin");

    let completion = run_init_worker(InitWorkerInput {
        init: VaultInit::Plaintext,
        vault_path: path.clone(),
        mode: InitWorkerMode::Create,
    });
    assert!(matches!(
        completion.effect,
        InitWorkerEffect::Success { .. }
    ));
    drop(completion);

    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen newly created plaintext vault");
    assert!(
        reopened.summaries().next().is_none(),
        "freshly created vault stays empty after reopen",
    );
}

#[test]
fn format_init_dialog_description_renders_resolved_path_then_plaintext_warning() {
    // The InitDialog's `adw::StatusPage::set_description` attribute
    // is populated from this helper. The rendered body leads with
    // the resolved vault path (`"No vault found at {path}."`) so
    // the user can confirm the destination before submitting, then
    // surfaces the standard plaintext-storage warning verbatim
    // through `paladin_core::format_plaintext_storage_warning()`.
    // The two sections are separated by a blank line (`\n\n`) so
    // the warning reads as its own paragraph. Pinning the format
    // string through a helper keeps the wording in one place
    // shared by the widget binding and the pure-logic tests, and
    // routes the warning text through the shared paladin-core
    // projection so the GUI cannot drift from the CLI / TUI copy.
    //
    // Sibling of
    // `paladin_gtk::unlock_dialog::format_unlock_dialog_description`
    // on the dialog-status-description side; together they pin
    // every first-mount dialog's body against a single source of
    // truth.
    use paladin_core::format_plaintext_storage_warning;
    use paladin_gtk::init_dialog::format_init_dialog_description;

    let path = Path::new("/tmp/example/vault.bin");
    let rendered = format_init_dialog_description(path);
    assert_eq!(
        rendered,
        format!(
            "No vault found at /tmp/example/vault.bin.\n\n{warning}",
            warning = format_plaintext_storage_warning(),
        ),
        "description leads with the resolved path and routes the warning through paladin-core",
    );
}

#[test]
fn format_init_dialog_description_starts_with_no_vault_found_at() {
    // The prefix `"No vault found at "` is the stable wording the
    // dialog leads with — pinning a prefix assertion alongside the
    // full-string assertion guards against an accidental rewording
    // that still happens to keep the path intact.
    use paladin_gtk::init_dialog::format_init_dialog_description;

    let rendered = format_init_dialog_description(Path::new("/x"));
    assert!(
        rendered.starts_with("No vault found at "),
        "description begins with the stable `No vault found at ` prefix; got {rendered:?}",
    );
}

#[test]
fn format_init_dialog_description_contains_paladin_core_plaintext_warning_verbatim() {
    // The plaintext-storage warning body is sourced through
    // `paladin_core::format_plaintext_storage_warning()` so the
    // GUI cannot drift from the CLI / TUI copy. Pinning a
    // `contains` assertion alongside the full-string assertion
    // guards against an accidental refactor that re-renders the
    // warning locally.
    use paladin_core::format_plaintext_storage_warning;
    use paladin_gtk::init_dialog::format_init_dialog_description;

    let rendered = format_init_dialog_description(Path::new("/x"));
    assert!(
        rendered.contains(&format_plaintext_storage_warning()),
        "description must embed the paladin-core plaintext warning verbatim; got {rendered:?}",
    );
}

#[test]
fn format_init_dialog_icon_name_returns_document_new_symbolic() {
    // The InitDialog's `adw::StatusPage::set_icon_name` attribute
    // is populated from this helper. The icon
    // (`"document-new-symbolic"`) is the freedesktop-standard
    // glyph for "create a new document" — resolving through the
    // system icon theme so the wordless icon matches every other
    // GNOME app's first-run / missing-resource surface. The
    // `-symbolic` suffix is required by the libadwaita HIG for
    // `AdwStatusPage` icons so the glyph recolors with the theme.
    // Pinning the icon name through a helper keeps the string in
    // one place shared by the widget binding and the pure-logic
    // tests.
    //
    // No TUI parity: the TUI is text-only and has no icon to
    // mirror. Sibling of
    // `paladin_gtk::unlock_dialog::format_unlock_dialog_icon_name`
    // on the dialog-status-icon side; together they pin every
    // first-mount dialog's freedesktop glyph against a single
    // source of truth.
    use paladin_gtk::init_dialog::format_init_dialog_icon_name;

    assert_eq!(
        format_init_dialog_icon_name(),
        "document-new-symbolic",
        "AdwStatusPage icon uses the freedesktop-standard new-document glyph",
    );
}

#[test]
fn format_init_dialog_icon_name_ends_with_symbolic_suffix() {
    // The libadwaita HIG requires `AdwStatusPage` icons to be
    // symbolic so they recolor with the theme; the icon-name
    // contract is to end with `-symbolic`. Pinning a suffix
    // assertion alongside the full-string assertion guards
    // against an accidental rename to a non-symbolic glyph.
    use paladin_gtk::init_dialog::format_init_dialog_icon_name;

    let icon = format_init_dialog_icon_name();
    assert!(
        icon.ends_with("-symbolic"),
        "AdwStatusPage icon name must end with `-symbolic` for HIG-conformant theming; got {icon:?}",
    );
}

#[test]
fn format_init_dialog_title_returns_create_a_new_vault() {
    // The InitDialog's `adw::StatusPage::set_title` attribute is
    // populated from this helper. The wording is the action-
    // oriented `"Create a new vault"` — the GNOME-HIG verb-led
    // phrasing for a first-run / missing-vault surface, matching
    // the dialog's freedesktop icon (`document-new-symbolic`) and
    // the §"Component tree" > `InitDialog` description
    // ("first-run / missing-vault flow"). Pinning the title
    // through a helper keeps the wording in one place shared by
    // the widget binding and the pure-logic tests.
    //
    // No TUI parity: the TUI does not surface a first-run
    // creation dialog (its `init` command is CLI-shaped only), so
    // the wording is GTK-specific. Sibling of
    // `paladin_gtk::unlock_dialog::format_unlock_dialog_title`,
    // `paladin_gtk::rename_dialog::format_rename_dialog_title`,
    // and `paladin_gtk::add_account::format_add_dialog_title` on
    // the dialog-header-title side; together they pin every
    // dialog's titled surface against a single source of truth.
    use paladin_gtk::init_dialog::format_init_dialog_title;

    assert_eq!(
        format_init_dialog_title(),
        "Create a new vault",
        "AdwStatusPage title uses the action-oriented GNOME-HIG wording",
    );
}

#[test]
fn format_init_dialog_create_label_returns_create_vault() {
    // Per §"Component tree" > `InitDialog`: the dialog's
    // primary action button calls `Store::create` (plaintext
    // path) or `Store::create` with `EncryptionOptions` (the
    // encrypted path) — the user-visible verb is the same on
    // both sub-flows, so the button label reads `"Create vault"`.
    // The wording matches the dialog title verb (`"Create a new
    // vault"`) while keeping the button caption short. Pinning
    // the wording through a helper keeps the label in one place
    // shared by the widget binding and the pure-logic tests in
    // `tests/init_dialog_logic.rs`.
    use paladin_gtk::init_dialog::format_init_dialog_create_label;

    assert_eq!(
        format_init_dialog_create_label(),
        "Create vault",
        "InitDialog create button label uses the short action-oriented wording matching the dialog title verb",
    );
}

#[test]
fn format_init_dialog_create_label_is_non_empty_single_line_distinct_from_title() {
    // Defense-in-depth: the create button label must be
    // non-empty (an empty label would render a blank button),
    // must be a single line (the action button caption is
    // rendered inline), and must be distinct from the dialog
    // title so the action button caption and the title are
    // visually separable rather than rendering the same string
    // twice.
    use paladin_gtk::init_dialog::{format_init_dialog_create_label, format_init_dialog_title};

    let label = format_init_dialog_create_label();
    assert!(
        !label.is_empty(),
        "InitDialog create button label must be non-empty; got {label:?}",
    );
    assert!(
        !label.contains('\n'),
        "InitDialog create button label must be a single line (no embedded newlines); got {label:?}",
    );
    assert!(
        !label.starts_with(char::is_whitespace),
        "InitDialog create button label must not start with whitespace; got {label:?}",
    );
    assert!(
        !label.ends_with(char::is_whitespace),
        "InitDialog create button label must not end with whitespace; got {label:?}",
    );
    assert_ne!(
        label,
        format_init_dialog_title(),
        "InitDialog create button label must be distinct from the dialog title so the action button caption and the title are visually separable",
    );
}

#[test]
fn format_init_dialog_create_label_starts_with_capital_letter_for_button_caption() {
    // Defense-in-depth: HIG-aligned button captions start with
    // a capital letter ("Create vault", not "create vault" or
    // "CREATE VAULT"). Catches an accidental lower-cased typo
    // that would render a non-HIG button caption.
    use paladin_gtk::init_dialog::format_init_dialog_create_label;

    let label = format_init_dialog_create_label();
    let first = label
        .chars()
        .next()
        .expect("InitDialog create button label must be non-empty");
    assert!(
        first.is_ascii_uppercase(),
        "InitDialog create button label must start with a capital ASCII letter per the GNOME HIG button-caption convention; got {label:?}",
    );
}

#[test]
fn format_init_dialog_force_confirm_label_returns_replace() {
    // Per §"Component tree" > `InitDialog`: when a vault appears
    // between `inspect` and `create` (precheck reported `Clear`
    // but the race resolved to `Existing`), the dialog opens an
    // in-dialog `AdwAlertDialog` with `destructive-action`
    // styling. The destructive confirm button calls
    // `Store::create_force(path, init)` — replacing the existing
    // vault. The GNOME-HIG verb for a "vault appears, confirm
    // to replace" affordance is the bare `"Replace"` — not
    // "Overwrite" (used by the file-overwrite gate in ExportDialog
    // for a different surface), not "Create" (which would
    // overlap with the primary submit-button caption returned by
    // `format_init_dialog_create_label`), and not "Confirm" (too
    // generic for a destructive-action button caption). Pinning
    // the wording through a helper keeps the destructive button
    // label in one place shared by the widget binding and the
    // pure-logic tests in `tests/init_dialog_logic.rs`.
    use paladin_gtk::init_dialog::format_init_dialog_force_confirm_label;

    assert_eq!(
        format_init_dialog_force_confirm_label(),
        "Replace",
        "InitDialog force-replace destructive confirm button label uses the HIG-aligned `Replace` verb",
    );
}

#[test]
fn format_init_dialog_force_confirm_label_is_distinct_from_create_label_and_non_empty() {
    // Defense-in-depth: the destructive confirm label must be
    // distinct from the primary create button label so the two
    // captions read as different actions (`Create vault` for
    // the normal path, `Replace` for the destructive force-
    // replace path) rather than collapsing onto the same word.
    // It must also be non-empty, single-line, and HIG-cased.
    use paladin_gtk::init_dialog::{
        format_init_dialog_create_label, format_init_dialog_force_confirm_label,
    };

    let label = format_init_dialog_force_confirm_label();
    assert!(
        !label.is_empty(),
        "InitDialog force-replace destructive confirm label must be non-empty; got {label:?}",
    );
    assert!(
        !label.contains('\n'),
        "InitDialog force-replace destructive confirm label must be a single line; got {label:?}",
    );
    assert!(
        !label.starts_with(char::is_whitespace),
        "InitDialog force-replace destructive confirm label must not start with whitespace; got {label:?}",
    );
    assert!(
        !label.ends_with(char::is_whitespace),
        "InitDialog force-replace destructive confirm label must not end with whitespace; got {label:?}",
    );
    let first = label
        .chars()
        .next()
        .expect("InitDialog force-replace destructive confirm label must be non-empty");
    assert!(
        first.is_ascii_uppercase(),
        "InitDialog force-replace destructive confirm label must start with a capital ASCII letter per the GNOME HIG button-caption convention; got {label:?}",
    );
    assert_ne!(
        label,
        format_init_dialog_create_label(),
        "InitDialog force-replace destructive confirm label must be distinct from the primary create button caption so the two action surfaces stay visually separable",
    );
}

#[test]
fn format_init_dialog_force_cancel_label_returns_cancel() {
    // Per §"Component tree" > `InitDialog`: when the destructive
    // `vault_exists` gate opens, the user can either confirm
    // (routes through `create_force`) or cancel (closes the
    // alert dialog and leaves the existing vault untouched —
    // explicitly required by the §10 routing test "Cancelling
    // the destructive gate leaves the existing vault"). The
    // GNOME-HIG verb for that affordance is the bare `"Cancel"`
    // — the same wording every other dialog footer cancel
    // affordance in this crate uses. Pinning the wording
    // through a helper keeps the destructive-gate cancel label
    // in one place shared by the widget binding and the pure-
    // logic tests in `tests/init_dialog_logic.rs`.
    use paladin_gtk::init_dialog::format_init_dialog_force_cancel_label;

    assert_eq!(
        format_init_dialog_force_cancel_label(),
        "Cancel",
        "InitDialog force-replace destructive cancel button label uses the standard `Cancel` HIG verb",
    );
}

#[test]
fn format_init_dialog_force_cancel_label_matches_other_dialog_cancel_labels() {
    // Cross-check: every dialog cancel affordance across the
    // crate should render the exact same `"Cancel"` wording so
    // the application's cancel-action vocabulary stays uniform.
    // A drift between any two would surface as a confusing
    // "Cancel" vs "Dismiss" vs "Close" inconsistency when the
    // user reaches the same cancel action from two different
    // dialogs.
    use paladin_gtk::add_account::format_add_dialog_cancel_label;
    use paladin_gtk::init_dialog::format_init_dialog_force_cancel_label;
    use paladin_gtk::remove_dialog::format_remove_dialog_cancel_label;
    use paladin_gtk::rename_dialog::format_rename_dialog_cancel_label;

    let cancel = format_init_dialog_force_cancel_label();
    assert_eq!(
        cancel,
        format_remove_dialog_cancel_label(),
        "InitDialog destructive cancel label must match the remove dialog cancel label so the cancel-action vocabulary stays uniform",
    );
    assert_eq!(
        cancel,
        format_rename_dialog_cancel_label(),
        "InitDialog destructive cancel label must match the rename dialog cancel label so the cancel-action vocabulary stays uniform",
    );
    assert_eq!(
        cancel,
        format_add_dialog_cancel_label(),
        "InitDialog destructive cancel label must match the add dialog cancel label so the cancel-action vocabulary stays uniform",
    );
}

#[test]
fn format_init_dialog_force_cancel_label_is_distinct_from_force_confirm() {
    // Defense-in-depth: the destructive-gate cancel and confirm
    // buttons must render distinct captions so the two
    // affordances read as different actions rather than
    // collapsing onto the same word.
    use paladin_gtk::init_dialog::{
        format_init_dialog_force_cancel_label, format_init_dialog_force_confirm_label,
    };

    let cancel = format_init_dialog_force_cancel_label();
    assert!(
        !cancel.is_empty(),
        "InitDialog destructive cancel label must be non-empty; got {cancel:?}",
    );
    assert!(
        !cancel.contains('\n'),
        "InitDialog destructive cancel label must be a single line; got {cancel:?}",
    );
    assert_ne!(
        cancel,
        format_init_dialog_force_confirm_label(),
        "InitDialog destructive cancel label must be distinct from the destructive confirm label so the two affordances read as different actions",
    );
}

#[test]
fn format_init_dialog_passphrase_title_returns_passphrase() {
    // Per §"Component tree" > `InitDialog`: the encrypted path
    // surfaces a passphrase `AdwPasswordEntryRow` whose floating
    // `set_title` label is populated from this helper. The wording
    // (`"Passphrase"`) matches the sibling
    // `format_unlock_dialog_passphrase_title` so the GTK init and
    // unlock surfaces render the same passphrase-row caption — a
    // drift would surface as a confusing "Passphrase" vs
    // "Password" vs "Passcode" inconsistency when the user reaches
    // both surfaces from the same launch. Pinning the title through
    // a helper keeps the GTK wording aligned against a single
    // source of truth so a future copy change cannot diverge
    // silently.
    use paladin_gtk::init_dialog::format_init_dialog_passphrase_title;

    assert_eq!(
        format_init_dialog_passphrase_title(),
        "Passphrase",
        "InitDialog passphrase row title uses the standard \"Passphrase\" HIG wording",
    );
}

#[test]
fn format_init_dialog_passphrase_title_matches_unlock_dialog_passphrase_title() {
    // Cross-check: every passphrase entry row in this crate
    // should render the exact same `"Passphrase"` wording so the
    // application's passphrase-row vocabulary stays uniform across
    // the init and unlock surfaces. A drift between the two would
    // surface as a confusing copy inconsistency when the user
    // reaches both dialogs from the same launch (Missing → Init,
    // then Locked → Unlock after a passphrase set).
    use paladin_gtk::init_dialog::format_init_dialog_passphrase_title;
    use paladin_gtk::unlock_dialog::format_unlock_dialog_passphrase_title;

    assert_eq!(
        format_init_dialog_passphrase_title(),
        format_unlock_dialog_passphrase_title(),
        "InitDialog passphrase row title must match the UnlockDialog passphrase row title so the passphrase-row vocabulary stays uniform",
    );
}

#[test]
fn format_init_dialog_force_heading_returns_replace_existing_vault_question() {
    // Per §"Component tree" > `InitDialog`: when the precheck
    // reports `Clear` but `Store::create` returns `vault_exists`
    // (a vault appeared between `inspect` and `create`), the
    // dialog opens an `AdwAlertDialog` whose heading is populated
    // from this helper. The wording (`"Replace existing vault?"`)
    // is the question-form GNOME-HIG heading for the destructive
    // gate — pairing with the `format_init_dialog_force_confirm_label`
    // (`"Replace"`) button caption so the heading reads as the
    // question and the button reads as the affirmative answer.
    // Pinning the heading through a helper keeps the wording in
    // one place shared by the widget binding and the pure-logic
    // tests.
    use paladin_gtk::init_dialog::format_init_dialog_force_heading;

    assert_eq!(
        format_init_dialog_force_heading(),
        "Replace existing vault?",
        "InitDialog force-replace destructive gate heading reads as the question paired with the `Replace` confirm button",
    );
}

#[test]
fn format_init_dialog_force_heading_is_non_empty_single_line_question() {
    // Defense-in-depth: the AlertDialog heading must be a non-
    // empty single-line question caption so `AdwAlertDialog::set_heading`
    // can render it as the dialog header without wrapping or
    // truncation artifacts, and the trailing `?` keeps the
    // heading framed as a question (matching the destructive
    // `format_duplicate_alert_heading` "Add anyway?" convention).
    use paladin_gtk::init_dialog::format_init_dialog_force_heading;

    let heading = format_init_dialog_force_heading();
    assert!(
        !heading.is_empty(),
        "InitDialog destructive gate heading must be non-empty; got {heading:?}",
    );
    assert!(
        !heading.contains('\n'),
        "InitDialog destructive gate heading must be a single line; got {heading:?}",
    );
    assert!(
        heading.ends_with('?'),
        "InitDialog destructive gate heading must end with `?` so it reads as a question; got {heading:?}",
    );
}

#[test]
fn format_init_dialog_force_heading_pairs_with_force_confirm_label() {
    // Cross-check: the heading must mention the destructive verb
    // (`"Replace"`) so the heading-question and the
    // confirm-button label read as a matched question/answer
    // pair. A drift where the heading said `"Overwrite"` but the
    // button said `"Replace"` would surface as a confusing
    // mismatch in the destructive affordance copy.
    use paladin_gtk::init_dialog::{
        format_init_dialog_force_confirm_label, format_init_dialog_force_heading,
    };

    let heading = format_init_dialog_force_heading();
    let confirm = format_init_dialog_force_confirm_label();
    assert!(
        heading.contains(confirm),
        "InitDialog destructive gate heading {heading:?} must contain the confirm-button verb {confirm:?} so the two surfaces read as a matched question/answer pair",
    );
}

#[test]
fn format_init_dialog_plaintext_warning_label_returns_accept_risk() {
    // Per §"Component tree" > `InitDialog`: when the user submits
    // the plaintext path (both passphrase fields empty), the
    // dialog renders an explicit acknowledgement checkbox whose
    // label is populated from this helper. The wording (`"I
    // accept this risk"`) mirrors the closing line of
    // `paladin_core::format_plaintext_storage_warning()` —
    // "Use an encrypted vault unless you fully accept this risk." —
    // so the checkbox caption reads as the affirmative of the
    // advisory text rendered directly beside it. Pinning the
    // wording through a helper keeps the label in one place
    // shared by the widget binding and the pure-logic tests in
    // `tests/init_dialog_logic.rs`.
    use paladin_gtk::init_dialog::format_init_dialog_plaintext_warning_label;

    assert_eq!(
        format_init_dialog_plaintext_warning_label(),
        "I accept this risk",
        "InitDialog plaintext-warning acknowledgement checkbox label is the affirmative of the format_plaintext_storage_warning closing line",
    );
}

#[test]
fn format_init_dialog_plaintext_warning_label_is_non_empty_single_line() {
    // Defense-in-depth: the checkbox label must be a non-empty
    // single-line caption so `gtk::CheckButton::set_label` can
    // render it inline beside the checkbox without wrapping or
    // truncation artifacts. The longer warning body lives in
    // `paladin_core::format_plaintext_storage_warning()` and is
    // rendered separately above the checkbox; this helper only
    // covers the short affirmative caption attached to the
    // checkbox itself.
    use paladin_gtk::init_dialog::format_init_dialog_plaintext_warning_label;

    let label = format_init_dialog_plaintext_warning_label();
    assert!(
        !label.is_empty(),
        "InitDialog plaintext-warning checkbox label must be non-empty; got {label:?}",
    );
    assert!(
        !label.contains('\n'),
        "InitDialog plaintext-warning checkbox label must be a single line; got {label:?}",
    );
}

#[test]
fn format_init_dialog_plaintext_warning_label_is_distinct_from_warning_body() {
    // Defense-in-depth: the checkbox label and the longer
    // warning body must render distinct strings so the
    // affirmative caption beside the checkbox cannot collapse
    // onto the same wording as the standalone advisory shown
    // above it. The warning body comes from
    // `paladin_core::format_plaintext_storage_warning()`; the
    // checkbox label is the short affirmative this helper
    // returns.
    use paladin_core::format_plaintext_storage_warning;
    use paladin_gtk::init_dialog::format_init_dialog_plaintext_warning_label;

    assert_ne!(
        format_init_dialog_plaintext_warning_label(),
        format_plaintext_storage_warning(),
        "InitDialog plaintext-warning checkbox label must be distinct from the standalone warning body so the two surfaces read as separate captions",
    );
}

#[test]
fn format_init_dialog_confirm_passphrase_title_returns_confirm_passphrase() {
    // Per §"Component tree" > `InitDialog`: the encrypted path
    // surfaces a second `AdwPasswordEntryRow` whose floating
    // `set_title` label is populated from this helper. The wording
    // (`"Confirm passphrase"`) mirrors the CLI `init`'s
    // `"Confirm passphrase: "` rprompt (see
    // `crates/paladin-cli/src/commands/init.rs`) — the CLI's
    // trailing colon and space are its prompt separator and drop
    // out because `AdwPasswordEntryRow` renders the title as a
    // floating label above the entry rather than as a prefix.
    // Pinning the title through a helper keeps the GTK / CLI
    // wording aligned against a single source of truth so a
    // future copy change cannot diverge silently.
    use paladin_gtk::init_dialog::format_init_dialog_confirm_passphrase_title;

    assert_eq!(
        format_init_dialog_confirm_passphrase_title(),
        "Confirm passphrase",
        "InitDialog confirm-passphrase row title mirrors the CLI `init` confirm prompt without the prompt separator",
    );
}

#[test]
fn format_init_dialog_confirm_passphrase_title_is_distinct_from_passphrase_title() {
    // Defense-in-depth: the two AdwPasswordEntryRow titles in the
    // InitDialog encrypted path must render distinct captions so
    // the user can tell which row is which. A drift where both
    // resolved to `"Passphrase"` would surface as a confusing
    // ambiguity when the user types into the second row expecting
    // a different prompt.
    use paladin_gtk::init_dialog::{
        format_init_dialog_confirm_passphrase_title, format_init_dialog_passphrase_title,
    };

    assert_ne!(
        format_init_dialog_confirm_passphrase_title(),
        format_init_dialog_passphrase_title(),
        "InitDialog confirm-passphrase row title must be distinct from the passphrase row title so the two rows read as different prompts",
    );
}

#[test]
fn format_init_dialog_confirm_passphrase_title_is_non_empty_single_line() {
    // Defense-in-depth: the confirm-passphrase row title must be
    // a non-empty single-line caption so `AdwPasswordEntryRow`
    // can render it as the floating label above the entry field
    // without truncation or wrapping artifacts.
    use paladin_gtk::init_dialog::format_init_dialog_confirm_passphrase_title;

    let title = format_init_dialog_confirm_passphrase_title();
    assert!(
        !title.is_empty(),
        "InitDialog confirm-passphrase row title must be non-empty; got {title:?}",
    );
    assert!(
        !title.contains('\n'),
        "InitDialog confirm-passphrase row title must be a single line; got {title:?}",
    );
}

#[test]
fn format_init_dialog_passphrase_title_is_non_empty_single_line() {
    // Defense-in-depth: the passphrase row title must be a non-
    // empty single-line caption so `AdwPasswordEntryRow` can
    // render it as the floating label above the entry field
    // without truncation or wrapping artifacts.
    use paladin_gtk::init_dialog::format_init_dialog_passphrase_title;

    let title = format_init_dialog_passphrase_title();
    assert!(
        !title.is_empty(),
        "InitDialog passphrase row title must be non-empty; got {title:?}",
    );
    assert!(
        !title.contains('\n'),
        "InitDialog passphrase row title must be a single line; got {title:?}",
    );
}

// ---------------------------------------------------------------------------
// InlineError::from_rejection — confirmation_mismatch maps to invalid_passphrase
// ---------------------------------------------------------------------------

#[test]
fn inline_error_from_rejection_confirmation_mismatch_carries_invalid_passphrase_kind() {
    // The two-field encrypted submission rejection lifts to the
    // §5 `invalid_passphrase` projection so the GUI surfaces the
    // same stable `error_kind` the CLI / TUI do.
    let inline = InlineError::from_rejection(SubmitRejection::ConfirmationMismatch)
        .expect("ConfirmationMismatch maps to an InlineError");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
}

#[test]
fn inline_error_from_rejection_confirmation_mismatch_renders_invalid_passphrase_reason() {
    // Rendered body uses the typed `PaladinError::Display` so the
    // stable `reason: "confirmation_mismatch"` discriminator
    // surfaces in the inline label verbatim.
    let inline = InlineError::from_rejection(SubmitRejection::ConfirmationMismatch)
        .expect("ConfirmationMismatch maps to an InlineError");
    let expected = PaladinError::InvalidPassphrase {
        reason: "confirmation_mismatch",
    }
    .to_string();
    assert_eq!(inline.rendered, expected);
}

#[test]
fn inline_error_from_rejection_plaintext_warning_required_returns_none() {
    // The plaintext-warning gate is a UI-only precondition (it
    // returns `None` from `SubmitRejection::error_kind`), so the
    // inline-error projection collapses to `None` — the widget
    // surfaces the warning body separately, not as an inline error.
    assert!(InlineError::from_rejection(SubmitRejection::PlaintextWarningRequired).is_none());
}

#[test]
fn submit_confirmation_mismatch_inline_error_does_not_echo_passphrase_or_confirm() {
    // Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" →
    // "Secret-entry ownership and zeroization guardrails": validation
    // messages can name fields / reasons but must never echo
    // secret-bearing input values. Type a distinctive passphrase and
    // a distinctive different confirm, trigger the mismatch
    // rejection, and assert the rendered inline error contains
    // neither marker.
    const PASSPHRASE_MARKER: &str = "ZZ-init-passphrase-marker-ZZ";
    const CONFIRM_MARKER: &str = "QQ-init-confirm-marker-QQ";
    let mut state = InitDialogState::new();
    state.set_passphrase(PASSPHRASE_MARKER);
    state.set_confirm(CONFIRM_MARKER);
    let rejection = state
        .submit()
        .expect_err("non-empty mismatched pair must reject");
    assert_eq!(rejection, SubmitRejection::ConfirmationMismatch);
    let inline = state
        .inline_error()
        .cloned()
        .expect("ConfirmationMismatch stages the inline error");
    assert!(
        !inline.rendered.contains(PASSPHRASE_MARKER),
        "inline body must not echo the passphrase, got {:?}",
        inline.rendered,
    );
    assert!(
        !inline.rendered.contains(CONFIRM_MARKER),
        "inline body must not echo the confirm passphrase, got {:?}",
        inline.rendered,
    );
}

// ---------------------------------------------------------------------------
// InitDialogState — basic getters / setters
// ---------------------------------------------------------------------------

#[test]
fn init_dialog_state_new_is_empty_with_unticked_warning() {
    let state = InitDialogState::new();
    assert!(state.passphrase_text().is_empty());
    assert!(state.confirm_text().is_empty());
    assert!(!state.plaintext_warning_acknowledged());
    assert!(state.inline_error().is_none());
}

#[test]
fn init_dialog_state_default_matches_new() {
    let lhs = InitDialogState::default();
    let rhs = InitDialogState::new();
    assert_eq!(lhs.passphrase_text(), rhs.passphrase_text());
    assert_eq!(lhs.confirm_text(), rhs.confirm_text());
    assert_eq!(
        lhs.plaintext_warning_acknowledged(),
        rhs.plaintext_warning_acknowledged()
    );
    assert!(lhs.inline_error().is_none() && rhs.inline_error().is_none());
}

#[test]
fn init_dialog_state_set_passphrase_shadows_typed_bytes() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    assert_eq!(state.passphrase_text(), "hunter2");
}

#[test]
fn init_dialog_state_set_confirm_shadows_typed_bytes() {
    let mut state = InitDialogState::new();
    state.set_confirm("hunter2");
    assert_eq!(state.confirm_text(), "hunter2");
}

#[test]
fn init_dialog_state_set_plaintext_warning_flips_flag() {
    let mut state = InitDialogState::new();
    assert!(!state.plaintext_warning_acknowledged());
    state.set_plaintext_warning(true);
    assert!(state.plaintext_warning_acknowledged());
    state.set_plaintext_warning(false);
    assert!(!state.plaintext_warning_acknowledged());
}

#[test]
fn init_dialog_state_set_passphrase_clears_inline_error() {
    // Typing dismisses any stale rejection / worker error so the
    // dialog never carries a stale message into the next attempt.
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter3");
    let _ = state.submit(); // stages the mismatch inline error
    assert!(state.inline_error().is_some());
    state.set_passphrase("hunter4");
    assert!(state.inline_error().is_none());
}

#[test]
fn init_dialog_state_set_confirm_clears_inline_error() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter3");
    let _ = state.submit();
    assert!(state.inline_error().is_some());
    state.set_confirm("hunter2");
    assert!(state.inline_error().is_none());
}

#[test]
fn init_dialog_state_set_plaintext_warning_clears_inline_error() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter3");
    let _ = state.submit();
    assert!(state.inline_error().is_some());
    state.set_plaintext_warning(true);
    assert!(state.inline_error().is_none());
}

#[test]
fn init_dialog_state_mode_tracks_field_emptiness() {
    let mut state = InitDialogState::new();
    assert_eq!(state.mode(), InitMode::Plaintext);
    state.set_passphrase("hunter2");
    assert_eq!(state.mode(), InitMode::Encrypted);
    state.set_passphrase("");
    state.set_confirm("hunter2");
    assert_eq!(state.mode(), InitMode::Encrypted);
    state.set_confirm("");
    assert_eq!(state.mode(), InitMode::Plaintext);
}

// ---------------------------------------------------------------------------
// InitDialogState::submit_button_sensitive — gates the primary action
// ---------------------------------------------------------------------------

#[test]
fn submit_button_sensitive_plaintext_without_warning_is_disabled() {
    // Plaintext mode requires the warning checkbox ticked. Empty
    // fields without the tick must leave the button disabled.
    let state = InitDialogState::new();
    assert!(!state.submit_button_sensitive());
}

#[test]
fn submit_button_sensitive_plaintext_with_warning_is_enabled() {
    let mut state = InitDialogState::new();
    state.set_plaintext_warning(true);
    assert!(state.submit_button_sensitive());
}

#[test]
fn submit_button_sensitive_encrypted_one_empty_is_disabled() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    assert!(!state.submit_button_sensitive());
    state.set_passphrase("");
    state.set_confirm("hunter2");
    assert!(!state.submit_button_sensitive());
}

#[test]
fn submit_button_sensitive_encrypted_mismatched_is_disabled() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter3");
    assert!(!state.submit_button_sensitive());
}

#[test]
fn submit_button_sensitive_encrypted_matching_is_enabled() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    assert!(state.submit_button_sensitive());
}

// ---------------------------------------------------------------------------
// InitDialogState::submit — accepts / rejects per prepare_vault_init
// ---------------------------------------------------------------------------

#[test]
fn submit_plaintext_with_warning_returns_plaintext_init() {
    let mut state = InitDialogState::new();
    state.set_plaintext_warning(true);
    let init = state
        .submit()
        .expect("plaintext init accepted with warning");
    assert!(matches!(init, VaultInit::Plaintext));
    // Plaintext buffers are already empty (the user never typed any
    // passphrase). The submit path preserves whatever buffers exist,
    // so the empty state is unchanged.
    assert!(state.passphrase_text().is_empty());
    assert!(state.confirm_text().is_empty());
    assert!(state.inline_error().is_none());
}

#[test]
fn submit_encrypted_match_returns_encrypted_init_and_preserves_buffers() {
    // The destructive-gate retry path requires the buffers to survive
    // the first-pass submit so `stage_pending_for_force` can rebuild a
    // second `VaultInit` on a `vault_exists` race. `VaultInit` is
    // non-`Clone`, so we cannot keep a duplicate alongside the one
    // consumed by the first worker call — instead we rebuild from the
    // preserved buffers when `WorkerCompletedDestructive` arrives.
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init = state.submit().expect("matching pair accepted");
    assert!(matches!(init, VaultInit::Encrypted(_)));
    assert_eq!(state.passphrase_text(), "hunter2");
    assert_eq!(state.confirm_text(), "hunter2");
    assert!(state.inline_error().is_none());
    drop(init);
}

#[test]
fn submit_plaintext_without_warning_returns_rejection_and_preserves_buffers() {
    let mut state = InitDialogState::new();
    let rej = state
        .submit()
        .expect_err("plaintext requires warning ticked");
    assert_eq!(rej, SubmitRejection::PlaintextWarningRequired);
    // PlaintextWarningRequired collapses to `None` in
    // `InlineError::from_rejection`, so no inline error is staged.
    assert!(state.inline_error().is_none());
}

#[test]
fn submit_encrypted_mismatch_stages_inline_error_and_preserves_buffers() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter3");
    let rej = state.submit().expect_err("mismatched pair rejects");
    assert_eq!(rej, SubmitRejection::ConfirmationMismatch);
    let inline = state.inline_error().expect("inline error staged");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    // Buffers stay so the user can correct without retyping.
    assert_eq!(state.passphrase_text(), "hunter2");
    assert_eq!(state.confirm_text(), "hunter3");
}

#[test]
fn submit_encrypted_one_empty_stages_inline_error() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    let rej = state.submit().expect_err("one-empty pair rejects");
    assert_eq!(rej, SubmitRejection::ConfirmationMismatch);
    assert!(state.inline_error().is_some());
}

// ---------------------------------------------------------------------------
// InitDialogState — inline-error slot setter
// ---------------------------------------------------------------------------

#[test]
fn set_inline_error_stores_some_and_none_clears() {
    let mut state = InitDialogState::new();
    let inline = InlineError::from_error(&unsafe_permissions_err());
    state.set_inline_error(Some(inline));
    assert!(state.inline_error().is_some());
    state.set_inline_error(None);
    assert!(state.inline_error().is_none());
}

// ---------------------------------------------------------------------------
// InitDialogState — clear_for wipes buffers and pending
// ---------------------------------------------------------------------------

#[test]
fn clear_for_cancel_wipes_buffers_and_returns_pending() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init = state.submit().expect("matching pair accepted");
    state.stage_pending(init);
    let prior = state.clear_for(ClearReason::Cancel);
    assert!(matches!(prior, Some(VaultInit::Encrypted(_))));
    assert!(state.passphrase_text().is_empty());
    assert!(state.confirm_text().is_empty());
    drop(prior);
}

#[test]
fn clear_for_submit_wipes_buffers_returns_no_pending_when_already_consumed() {
    // After a successful submit, the worker dispatch site consumes
    // the pending via `consume_pending` (which clears the buffers
    // as a side effect). A subsequent `clear_for(Submit)` finds the
    // pending slot already empty.
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init = state.submit().expect("matching pair accepted");
    state.stage_pending(init);
    let _ = state.consume_pending();
    let prior = state.clear_for(ClearReason::Submit);
    assert!(prior.is_none());
}

// ---------------------------------------------------------------------------
// InitDialogMsg::PassphraseChanged / ConfirmChanged / WarningToggled
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_passphrase_changed_updates_buffer_and_emits_no_output() {
    let mut state = InitDialogState::new();
    let out = apply_msg(&mut state, InitDialogMsg::PassphraseChanged("h".into()));
    assert!(out.is_none());
    assert_eq!(state.passphrase_text(), "h");
}

#[test]
fn apply_msg_confirm_changed_updates_buffer_and_emits_no_output() {
    let mut state = InitDialogState::new();
    let out = apply_msg(&mut state, InitDialogMsg::ConfirmChanged("c".into()));
    assert!(out.is_none());
    assert_eq!(state.confirm_text(), "c");
}

#[test]
fn apply_msg_warning_toggled_updates_flag_and_emits_no_output() {
    let mut state = InitDialogState::new();
    let out = apply_msg(&mut state, InitDialogMsg::WarningToggled(true));
    assert!(out.is_none());
    assert!(state.plaintext_warning_acknowledged());
}

// ---------------------------------------------------------------------------
// InitDialogMsg::SubmitClicked — routes via state.submit
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_submit_clicked_plaintext_with_warning_emits_submit_create() {
    let mut state = InitDialogState::new();
    state.set_plaintext_warning(true);
    let out = apply_msg(&mut state, InitDialogMsg::SubmitClicked);
    match out {
        Some(InitDialogOutput::SubmitCreate(init)) => {
            assert!(matches!(init, VaultInit::Plaintext));
        }
        other => panic!("expected SubmitCreate(Plaintext), got {other:?}"),
    }
}

#[test]
fn apply_msg_submit_clicked_encrypted_match_emits_submit_create_encrypted() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let out = apply_msg(&mut state, InitDialogMsg::SubmitClicked);
    match out {
        Some(InitDialogOutput::SubmitCreate(VaultInit::Encrypted(_))) => {}
        other => panic!("expected SubmitCreate(Encrypted), got {other:?}"),
    }
}

#[test]
fn apply_msg_submit_clicked_plaintext_without_warning_returns_none() {
    // The plaintext-warning gate is the only pre-submit gate that
    // collapses to `None` (no inline error staged) — the button is
    // already disabled by `submit_button_sensitive`, but a stray
    // dispatch from a keyboard accelerator must not produce an
    // output either.
    let mut state = InitDialogState::new();
    let out = apply_msg(&mut state, InitDialogMsg::SubmitClicked);
    assert!(out.is_none());
}

#[test]
fn apply_msg_submit_clicked_encrypted_mismatch_returns_none_and_stages_inline_error() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter3");
    let out = apply_msg(&mut state, InitDialogMsg::SubmitClicked);
    assert!(out.is_none());
    let inline = state.inline_error().expect("inline error staged");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
}

// ---------------------------------------------------------------------------
// InitDialogMsg::WorkerCompletedInline — staging projection
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_worker_completed_inline_stages_inline_error_and_emits_no_output() {
    let mut state = InitDialogState::new();
    let inline = InlineError::from_error(&unsafe_permissions_err());
    let out = apply_msg(&mut state, InitDialogMsg::WorkerCompletedInline(inline));
    assert!(out.is_none());
    assert!(state.inline_error().is_some());
    assert_eq!(
        state.inline_error().unwrap().kind,
        ErrorKind::UnsafePermissions
    );
}

// ---------------------------------------------------------------------------
// InitDialogMsg::ForceConfirmClicked / ForceCancelClicked — destructive gate
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_force_confirm_consumes_pending_and_emits_submit_force_create() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    // First submit stages the pending VaultInit (the dispatch site
    // calls `stage_pending` before spawning the worker).
    let init = state.submit().expect("matching pair accepted");
    state.stage_pending(init);
    let out = apply_msg(&mut state, InitDialogMsg::ForceConfirmClicked);
    match out {
        Some(InitDialogOutput::SubmitForceCreate(VaultInit::Encrypted(_))) => {}
        other => panic!("expected SubmitForceCreate(Encrypted), got {other:?}"),
    }
    // Pending consumed.
    assert!(state.consume_pending().is_none());
}

#[test]
fn apply_msg_force_confirm_without_pending_returns_none() {
    // Defensive: no pending means the user reached the destructive
    // confirm button without an active first-pass submit — the
    // dispatch is a no-op.
    let mut state = InitDialogState::new();
    let out = apply_msg(&mut state, InitDialogMsg::ForceConfirmClicked);
    assert!(out.is_none());
}

#[test]
fn apply_msg_force_cancel_drops_pending_and_wipes_passphrases() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init = state.submit().expect("matching pair accepted");
    state.stage_pending(init);
    let out = apply_msg(&mut state, InitDialogMsg::ForceCancelClicked);
    assert!(out.is_none());
    // After force-cancel, pending is dropped and buffers wiped.
    assert!(state.consume_pending().is_none());
    assert!(state.passphrase_text().is_empty());
    assert!(state.confirm_text().is_empty());
}

// ---------------------------------------------------------------------------
// stage_pending — replaces prior pending and clears buffers
// ---------------------------------------------------------------------------

#[test]
fn stage_pending_replaces_prior_pending() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init1 = state.submit().expect("matching pair accepted");
    let prior = state.stage_pending(init1);
    assert!(prior.is_none());
    // Subsequent re-submit (different passphrase) replaces the pending.
    state.set_passphrase("hunter3");
    state.set_confirm("hunter3");
    let init2 = state.submit().expect("matching pair accepted");
    let prior = state.stage_pending(init2);
    assert!(matches!(prior, Some(VaultInit::Encrypted(_))));
    drop(prior);
}

// ---------------------------------------------------------------------------
// stage_pending_for_force — re-derives VaultInit from preserved buffers
// ---------------------------------------------------------------------------

#[test]
fn stage_pending_for_force_with_encrypted_buffers_stages_pending() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    // Simulate the first-pass submit that preserves the buffers.
    let init = state.submit().expect("matching pair accepted");
    drop(init);
    // The worker reports DestructiveGate; the dialog rebuilds from
    // buffers.
    let prior = state
        .stage_pending_for_force()
        .expect("rebuild succeeds with preserved buffers");
    assert!(prior.is_none());
    assert!(state.has_pending_force());
}

#[test]
fn stage_pending_for_force_with_plaintext_warning_stages_plaintext() {
    let mut state = InitDialogState::new();
    state.set_plaintext_warning(true);
    let _ = state
        .submit()
        .expect("plaintext init accepted with warning");
    let prior = state
        .stage_pending_for_force()
        .expect("rebuild succeeds for plaintext path");
    assert!(prior.is_none());
    assert!(state.has_pending_force());
    // Confirming consumes the staged plaintext init.
    let taken = state
        .consume_pending()
        .expect("pending consumed on confirm");
    assert!(matches!(taken, VaultInit::Plaintext));
}

#[test]
fn stage_pending_for_force_rebuild_failure_returns_rejection() {
    // Defensive: if the buffers were modified between submit and
    // worker return (the dialog should be disabled during this
    // window, so this is a safety net), the rebuild fails with the
    // typed §5 rejection.
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter3"); // mismatched
    let rej = state
        .stage_pending_for_force()
        .expect_err("mismatched rebuild rejects");
    assert_eq!(rej, SubmitRejection::ConfirmationMismatch);
    assert!(!state.has_pending_force());
}

// ---------------------------------------------------------------------------
// has_pending_force — destructive AlertDialog visibility watch
// ---------------------------------------------------------------------------

#[test]
fn has_pending_force_false_when_no_pending_staged() {
    let state = InitDialogState::new();
    assert!(!state.has_pending_force());
}

#[test]
fn has_pending_force_true_after_stage_pending() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init = state.submit().expect("matching pair accepted");
    let _ = state.stage_pending(init);
    assert!(state.has_pending_force());
}

#[test]
fn has_pending_force_false_after_consume_pending() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init = state.submit().expect("matching pair accepted");
    let _ = state.stage_pending(init);
    let _ = state.consume_pending();
    assert!(!state.has_pending_force());
}

#[test]
fn has_pending_force_false_after_force_cancel() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init = state.submit().expect("matching pair accepted");
    let _ = state.stage_pending(init);
    let _ = apply_msg(&mut state, InitDialogMsg::ForceCancelClicked);
    assert!(!state.has_pending_force());
}

// ---------------------------------------------------------------------------
// InitDialogMsg::WorkerCompletedDestructive — stages pending via rebuild
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_worker_completed_destructive_stages_pending_from_buffers() {
    let mut state = InitDialogState::new();
    state.set_passphrase("hunter2");
    state.set_confirm("hunter2");
    let init = state.submit().expect("matching pair accepted");
    drop(init);
    let out = apply_msg(&mut state, InitDialogMsg::WorkerCompletedDestructive);
    assert!(out.is_none());
    assert!(state.has_pending_force());
    // Force-confirm then consumes the staged init and emits
    // SubmitForceCreate.
    let out = apply_msg(&mut state, InitDialogMsg::ForceConfirmClicked);
    match out {
        Some(InitDialogOutput::SubmitForceCreate(VaultInit::Encrypted(_))) => {}
        other => panic!("expected SubmitForceCreate(Encrypted), got {other:?}"),
    }
}

#[test]
fn apply_msg_worker_completed_destructive_plaintext_round_trip() {
    let mut state = InitDialogState::new();
    state.set_plaintext_warning(true);
    let _ = state.submit().expect("plaintext init accepted");
    let _ = apply_msg(&mut state, InitDialogMsg::WorkerCompletedDestructive);
    assert!(state.has_pending_force());
    let out = apply_msg(&mut state, InitDialogMsg::ForceConfirmClicked);
    match out {
        Some(InitDialogOutput::SubmitForceCreate(VaultInit::Plaintext)) => {}
        other => panic!("expected SubmitForceCreate(Plaintext), got {other:?}"),
    }
}
