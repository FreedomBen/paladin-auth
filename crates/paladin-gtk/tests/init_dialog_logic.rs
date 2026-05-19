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
    classify_create_error, classify_create_force_error, classify_mode, classify_precheck,
    destructive_gate_body, plaintext_warning_body, prepare_vault_init, run_init_worker,
    CreateOutcome, InitMode, InitWorkerCompletion, InitWorkerEffect, InitWorkerInput,
    InitWorkerMode, InlineError, PrecheckOutcome, SubmitRejection,
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
