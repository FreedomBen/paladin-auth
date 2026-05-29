// SPDX-License-Identifier: AGPL-3.0-or-later

//! Destroy modal reducer + executor coverage (Milestone 10; DESIGN
//! §4.3 / §6, `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) >
//! Destroy" + "Destroy modal" test inventory).
//!
//! Covers: the universal `Ctrl+Shift+D` opener from every `AppState`
//! (and over an open modal, with secret-buffer zeroization), the
//! `yes`-literal confirmation gate, the `Effect::DestroyVault` emit on
//! submit, and the `EffectResult::DestroyVault` result routing for the
//! success (backup deleted / remained), `vault_missing`, and
//! `DestroyIoError` / symlink-rejection branches. The executor side
//! drives the real `paladin_core::destroy_vault` (no mocks) against
//! on-disk fixtures so the unlink actually happens.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use paladin_core::{DestroyReport, PaladinError, Store, VaultInit};

use paladin_tui::app::effect::{execute, EffectOutcome};
use paladin_tui::app::event::{AppEvent, Effect, EffectResult};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{
    AddModal, AddMode, AppState, CreateVaultMode, CreateVaultStep, DestroyAction, DestroyModal,
    Focus, Modal, PassphraseModal, PassphraseSubFlow, VAULT_ALREADY_GONE, VAULT_DELETED,
    VAULT_DELETED_BACKUP_REMAINED,
};
use paladin_tui::prompt::PassphraseBuffer;

mod common;
use common::secure_test_tempdir;

// ---------------------------------------------------------------------------
// Input / event helpers (mirroring tests/reducer_tests.rs).
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        at: Instant::now(),
    }
}

fn typed(c: char) -> AppEvent {
    key(KeyCode::Char(c))
}

/// The `Ctrl+Shift+D` destroy chord as a `KeyEvent`-bearing `AppEvent`.
fn destroy_chord() -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(
            KeyCode::Char('d'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        )),
        at: Instant::now(),
    }
}

fn destroy_vault_result(result: Result<DestroyReport, PaladinError>) -> AppEvent {
    AppEvent::EffectResult(EffectResult::DestroyVault(result))
}

// ---------------------------------------------------------------------------
// State builders.
// ---------------------------------------------------------------------------

fn missing(path: &str) -> AppState {
    AppState::create_vault_initial(PathBuf::from(path))
}

fn startup_err(path: Option<&str>) -> AppState {
    AppState::StartupError {
        path: path.map(PathBuf::from),
        message: "boom".into(),
    }
}

fn locked(path: &str) -> AppState {
    AppState::Locked {
        path: PathBuf::from(path),
        pending_clipboard_clear: None,
    }
}

/// Build a real `Unlocked` state backed by an on-disk plaintext vault
/// in a `0700` tempdir so the `unsafe_permissions` gate stays quiet.
fn unlocked_at(path: &Path) -> AppState {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create plaintext vault");
    vault.save(&store).expect("commit empty vault");
    AppState::Unlocked {
        path: path.to_path_buf(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    }
}

/// Open the Destroy modal from `state` via the chord and assert the
/// transition succeeded, returning the `Destroy` state.
fn open_destroy(state: AppState) -> AppState {
    let (next, effects) = reduce(state, destroy_chord());
    assert!(
        effects.is_empty(),
        "opening the Destroy modal emits no effect, got {effects:?}"
    );
    assert!(
        matches!(next, AppState::Destroy { .. }),
        "chord must transition to AppState::Destroy"
    );
    next
}

// ---------------------------------------------------------------------------
// Opening the modal from every AppState.
// ---------------------------------------------------------------------------

#[test]
fn chord_from_missing_opens_destroy_with_cancel_focus_and_empty_buffer() {
    let next = open_destroy(missing("/tmp/v.bin"));
    let AppState::Destroy { path, modal, .. } = next else {
        unreachable!();
    };
    assert_eq!(path, PathBuf::from("/tmp/v.bin"));
    assert_eq!(
        modal.focus,
        DestroyAction::Cancel,
        "default focus is Cancel"
    );
    assert!(modal.confirmation.is_empty());
    assert!(modal.error.is_none());
    assert!(
        !modal.warning.is_empty(),
        "warning body is sourced from format_destroy_warning"
    );
}

#[test]
fn chord_warning_body_matches_core_format_destroy_warning() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    std::fs::write(&path, b"x").expect("write primary");
    let next = open_destroy(missing(path.to_str().unwrap()));
    let AppState::Destroy { modal, .. } = next else {
        unreachable!();
    };
    // No `.bak` on disk → backup_present false → warning names only the
    // primary, byte-for-byte equal to the core helper.
    assert!(!modal.backup_present);
    assert_eq!(
        modal.warning,
        paladin_core::format_destroy_warning(&path, false)
    );
}

#[test]
fn chord_backup_present_probe_reflects_on_disk_bak() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    std::fs::write(&path, b"primary").expect("write primary");
    std::fs::write(dir.path().join("vault.bin.bak"), b"backup").expect("write bak");
    let next = open_destroy(missing(path.to_str().unwrap()));
    let AppState::Destroy { modal, .. } = next else {
        unreachable!();
    };
    assert!(modal.backup_present, "the on-disk .bak must be probed");
    assert_eq!(
        modal.warning,
        paladin_core::format_destroy_warning(&path, true)
    );
}

#[test]
fn chord_from_locked_opens_without_unlocking() {
    let next = open_destroy(locked("/tmp/v.bin"));
    let AppState::Destroy { prior, .. } = next else {
        unreachable!();
    };
    assert!(
        matches!(*prior, AppState::Locked { .. }),
        "prior must stay Locked so cancel restores the locked screen"
    );
}

#[test]
fn chord_from_startup_error_keeps_error_underneath() {
    let next = open_destroy(startup_err(Some("/tmp/v.bin")));
    let AppState::Destroy { prior, .. } = next else {
        unreachable!();
    };
    assert!(
        matches!(*prior, AppState::StartupError { .. }),
        "cancel returns to the same startup-error view"
    );
}

#[test]
fn chord_from_unlock_screen_zeroizes_passphrase_and_keeps_prior() {
    // Typed passphrase on the unlock screen; the chord opens destroy.
    let mut buf = PassphraseBuffer::new();
    for c in "hunter2".chars() {
        buf.push(c);
    }
    let state = AppState::Unlock {
        path: PathBuf::from("/tmp/v.bin"),
        error: None,
        passphrase: buf,
    };
    let next = open_destroy(state);
    let AppState::Destroy { prior, .. } = next else {
        unreachable!();
    };
    assert!(matches!(*prior, AppState::Unlock { .. }));
}

#[test]
fn chord_from_startup_error_without_path_is_noop() {
    // A `default_vault_path` failure leaves no path to destroy; the
    // chord must be a silent no-op.
    let (next, effects) = reduce(startup_err(None), destroy_chord());
    assert!(effects.is_empty());
    assert!(
        matches!(next, AppState::StartupError { path: None, .. }),
        "no path → chord is a no-op, state unchanged"
    );
}

#[test]
fn chord_while_destroy_open_is_silent_noop() {
    let state = open_destroy(missing("/tmp/v.bin"));
    // Fill the confirmation so we can detect any state churn.
    let (state, _) = reduce(state, typed('y'));
    let (next, effects) = reduce(state, destroy_chord());
    assert!(effects.is_empty(), "second chord emits no effect");
    let AppState::Destroy { modal, .. } = next else {
        panic!("second chord must leave the Destroy modal open");
    };
    assert_eq!(
        modal.confirmation, "y",
        "second chord is a no-op; the buffer is unchanged"
    );
}

#[test]
fn chord_over_open_passphrase_modal_zeroizes_and_opens_destroy() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let mut state = unlocked_at(&path);
    if let AppState::Unlocked { modal, .. } = &mut state {
        let mut pmodal = PassphraseModal {
            sub_flow: PassphraseSubFlow::Set,
            ..PassphraseModal::default()
        };
        for c in "topsecret".chars() {
            pmodal.new_passphrase.push(c);
        }
        *modal = Some(Modal::Passphrase(pmodal));
    }
    let next = open_destroy(state);
    let AppState::Destroy { prior, .. } = next else {
        unreachable!();
    };
    // The active modal is closed before the prior is boxed so its
    // secret buffers zeroize on drop.
    assert!(
        matches!(*prior, AppState::Unlocked { modal: None, .. }),
        "the active modal is closed before the prior Unlocked is boxed"
    );
}

#[test]
fn chord_over_open_add_modal_closes_it_before_boxing_prior() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let mut state = unlocked_at(&path);
    if let AppState::Unlocked { modal, .. } = &mut state {
        let mut add = AddModal {
            mode: AddMode::Uri,
            ..AddModal::default()
        };
        for c in "otpauth://totp/x?secret=ABCDEFGH".chars() {
            add.uri_text.push(c);
        }
        for c in "JBSWY3DPEHPK3PXP".chars() {
            add.manual_secret.push(c);
        }
        *modal = Some(Modal::Add(add));
    }
    let next = open_destroy(state);
    let AppState::Destroy { prior, .. } = next else {
        unreachable!();
    };
    assert!(matches!(*prior, AppState::Unlocked { modal: None, .. }));
}

// ---------------------------------------------------------------------------
// Confirmation gating + submit.
// ---------------------------------------------------------------------------

#[test]
fn confirmed_gate_accepts_exact_yes_and_rejects_partial() {
    let cases = [
        ("", false),
        ("y", false),
        ("ye", false),
        ("yes", true),
        ("  yes  ", true), // whitespace-trimmed
        ("yes ", true),
        ("yess", false),
        ("no", false),
        ("YES", false), // case-sensitive: only lowercase `yes`
    ];
    for (input, expected) in cases {
        let modal = DestroyModal {
            confirmation: input.to_string(),
            ..DestroyModal::default()
        };
        assert_eq!(
            modal.confirmed(),
            expected,
            "confirmation gate for {input:?}"
        );
    }
}

#[test]
fn typing_builds_confirmation_and_clears_inline_error() {
    let mut state = open_destroy(missing("/tmp/v.bin"));
    if let AppState::Destroy { modal, .. } = &mut state {
        modal.error = Some("stale".into());
    }
    let (state, _) = reduce(state, typed('y'));
    let (state, _) = reduce(state, typed('e'));
    let (state, effects) = reduce(state, typed('s'));
    assert!(effects.is_empty(), "typing emits no effect");
    let AppState::Destroy { modal, .. } = state else {
        unreachable!();
    };
    assert_eq!(modal.confirmation, "yes");
    assert!(modal.confirmed());
    assert!(
        modal.error.is_none(),
        "typing clears any stale inline error"
    );
}

#[test]
fn backspace_pops_confirmation() {
    let state = open_destroy(missing("/tmp/v.bin"));
    let (state, _) = reduce(state, typed('y'));
    let (state, _) = reduce(state, typed('e'));
    let (state, _) = reduce(state, key(KeyCode::Backspace));
    let AppState::Destroy { modal, .. } = state else {
        unreachable!();
    };
    assert_eq!(modal.confirmation, "y");
}

#[test]
fn tab_toggles_focus_between_cancel_and_delete() {
    let state = open_destroy(missing("/tmp/v.bin"));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let AppState::Destroy { modal, .. } = &state else {
        unreachable!();
    };
    assert_eq!(modal.focus, DestroyAction::Delete);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let AppState::Destroy { modal, .. } = &state else {
        unreachable!();
    };
    assert_eq!(modal.focus, DestroyAction::Cancel);
}

#[test]
fn enter_on_delete_without_yes_is_noop_no_effect() {
    let state = open_destroy(missing("/tmp/v.bin"));
    // Focus Delete but leave the buffer empty.
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (next, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "unconfirmed Delete emits no effect, got {effects:?}"
    );
    assert!(
        matches!(next, AppState::Destroy { .. }),
        "unconfirmed Delete keeps the modal open"
    );
}

#[test]
fn enter_on_delete_with_yes_emits_destroy_effect_with_path() {
    let state = open_destroy(missing("/tmp/secret-vault.bin"));
    // Type `yes` then move focus to Delete and submit.
    let (state, _) = reduce(state, typed('y'));
    let (state, _) = reduce(state, typed('e'));
    let (state, _) = reduce(state, typed('s'));
    let (state, _) = reduce(state, key(KeyCode::Tab)); // focus Delete
    let (next, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        matches!(
            effects.as_slice(),
            [Effect::DestroyVault { path }] if path == Path::new("/tmp/secret-vault.bin")
        ),
        "submit emits Effect::DestroyVault with the resolved path, got {effects:?}"
    );
    // No state mutation until the executor result returns.
    assert!(matches!(next, AppState::Destroy { .. }));
}

#[test]
fn esc_cancels_and_restores_prior_state() {
    let state = open_destroy(startup_err(Some("/tmp/v.bin")));
    let (next, effects) = reduce(state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    assert!(
        matches!(next, AppState::StartupError { .. }),
        "Esc restores the boxed prior state verbatim"
    );
}

#[test]
fn enter_on_cancel_restores_prior_state() {
    let state = open_destroy(locked("/tmp/v.bin"));
    // Cancel is the default focus; Enter on it cancels.
    let (next, effects) = reduce(state, key(KeyCode::Enter));
    assert!(effects.is_empty());
    assert!(matches!(next, AppState::Locked { .. }));
}

// ---------------------------------------------------------------------------
// Result routing.
// ---------------------------------------------------------------------------

#[test]
fn result_ok_backup_deleted_transitions_to_create_vault_with_deleted_note() {
    let state = open_destroy(missing("/tmp/v.bin"));
    let (next, effects) = reduce(
        state,
        destroy_vault_result(Ok(DestroyReport {
            primary_deleted: true,
            backup_deleted: true,
        })),
    );
    assert!(effects.is_empty());
    let AppState::CreateVault { path, step, error } = next else {
        panic!("success transitions to create-vault");
    };
    assert_eq!(path, PathBuf::from("/tmp/v.bin"));
    assert!(matches!(
        step,
        CreateVaultStep::ChooseMode {
            selection: CreateVaultMode::Encrypted
        }
    ));
    assert_eq!(error.as_deref(), Some(VAULT_DELETED));
}

#[test]
fn result_ok_backup_remained_uses_backup_remained_note() {
    let state = open_destroy(missing("/tmp/v.bin"));
    let (next, _) = reduce(
        state,
        destroy_vault_result(Ok(DestroyReport {
            primary_deleted: true,
            backup_deleted: false,
        })),
    );
    let AppState::CreateVault { error, .. } = next else {
        panic!("success transitions to create-vault");
    };
    assert_eq!(error.as_deref(), Some(VAULT_DELETED_BACKUP_REMAINED));
}

#[test]
fn result_ok_drops_held_vault_and_store() {
    // From a real Unlocked state: success must drop the (Vault, Store)
    // and land on create-vault (no held vault remains).
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let state = open_destroy(unlocked_at(&path));
    let (next, _) = reduce(
        state,
        destroy_vault_result(Ok(DestroyReport {
            primary_deleted: true,
            backup_deleted: false,
        })),
    );
    assert!(
        matches!(next, AppState::CreateVault { .. }),
        "the held (Vault, Store) is dropped and we land on create-vault"
    );
}

#[test]
fn result_vault_missing_transitions_with_already_gone_note() {
    let state = open_destroy(missing("/tmp/v.bin"));
    let (next, effects) = reduce(state, destroy_vault_result(Err(PaladinError::VaultMissing)));
    assert!(effects.is_empty());
    let AppState::CreateVault { error, .. } = next else {
        panic!("vault_missing transitions to create-vault");
    };
    assert_eq!(error.as_deref(), Some(VAULT_ALREADY_GONE));
}

#[test]
fn result_destroy_io_error_backup_keeps_modal_open_with_partial_inline_error() {
    let state = open_destroy(missing("/tmp/data/vault.bin"));
    let err = PaladinError::DestroyIoError {
        operation: "unlink_backup_file",
        source: std::io::Error::other("boom"),
        primary_deleted: true,
        backup_deleted: false,
    };
    let (next, effects) = reduce(state, destroy_vault_result(Err(err)));
    assert!(effects.is_empty());
    let AppState::Destroy { modal, .. } = next else {
        panic!("DestroyIoError keeps the modal open");
    };
    let msg = modal.error.expect("inline error is set");
    assert!(
        msg.contains("backup unlink failed") && msg.contains("vault.bin.bak"),
        "inline error names the failing .bak path: {msg:?}"
    );
}

#[test]
fn result_destroy_io_error_fsync_keeps_modal_open_with_durability_inline_error() {
    let state = open_destroy(missing("/tmp/data/vault.bin"));
    let err = PaladinError::DestroyIoError {
        operation: "fsync_vault_dir",
        source: std::io::Error::other("boom"),
        primary_deleted: true,
        backup_deleted: true,
    };
    let (next, _) = reduce(state, destroy_vault_result(Err(err)));
    let AppState::Destroy { modal, .. } = next else {
        panic!("DestroyIoError keeps the modal open");
    };
    let msg = modal.error.expect("inline error is set");
    assert!(
        msg.contains("durability unconfirmed"),
        "fsync failure names the durability condition: {msg:?}"
    );
}

#[test]
fn result_symlink_rejection_keeps_modal_open_naming_path() {
    let state = open_destroy(missing("/tmp/v.bin"));
    let err = PaladinError::IoError {
        operation: "vault_file_is_symlink",
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "symlink"),
    };
    let (next, _) = reduce(state, destroy_vault_result(Err(err)));
    let AppState::Destroy { modal, .. } = next else {
        panic!("symlink rejection keeps the modal open");
    };
    let msg = modal.error.expect("inline error is set");
    assert!(
        msg.contains("symlink") && msg.contains("/tmp/v.bin"),
        "inline error names the symlinked primary path: {msg:?}"
    );
}

#[test]
fn result_delivered_off_destroy_state_is_discarded() {
    // A late result that arrives after the modal closed / auto-locked
    // must not mutate the live state.
    let (next, effects) = reduce(
        locked("/tmp/v.bin"),
        destroy_vault_result(Ok(DestroyReport {
            primary_deleted: true,
            backup_deleted: true,
        })),
    );
    assert!(effects.is_empty());
    assert!(
        matches!(next, AppState::Locked { .. }),
        "a result delivered off the Destroy state is discarded"
    );
}

// ---------------------------------------------------------------------------
// Auto-lock interaction.
// ---------------------------------------------------------------------------

#[test]
fn auto_lock_while_destroy_open_over_unlocked_locks_and_closes_modal() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let mut prior = unlocked_at(&path);
    // Arm an already-expired idle deadline on the prior Unlocked state.
    if let AppState::Unlocked { idle_deadline, .. } = &mut prior {
        *idle_deadline = Some(
            Instant::now()
                .checked_sub(std::time::Duration::from_secs(60))
                .expect("monotonic clock is >60s past boot in test environments"),
        );
    }
    let destroy = open_destroy(prior);
    // Type a partial confirmation so we can confirm it does not survive.
    let (destroy, _) = reduce(destroy, typed('y'));

    let tick = AppEvent::Tick {
        wall_clock: std::time::SystemTime::now(),
        monotonic: Instant::now(),
    };
    let (next, effects) = reduce(destroy, tick);
    assert!(effects.is_empty());
    assert!(
        matches!(next, AppState::Locked { .. }),
        "an idle expiry while the Destroy modal is open over Unlocked locks the vault, got a non-Locked state"
    );
}

#[test]
fn auto_lock_unexpired_deadline_keeps_destroy_modal_open() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let mut prior = unlocked_at(&path);
    if let AppState::Unlocked { idle_deadline, .. } = &mut prior {
        // Far-future deadline: not expired.
        *idle_deadline = Some(Instant::now() + std::time::Duration::from_secs(3600));
    }
    let destroy = open_destroy(prior);
    let tick = AppEvent::Tick {
        wall_clock: std::time::SystemTime::now(),
        monotonic: Instant::now(),
    };
    let (next, _) = reduce(destroy, tick);
    assert!(
        matches!(next, AppState::Destroy { .. }),
        "an unexpired deadline leaves the Destroy modal open"
    );
}

// ---------------------------------------------------------------------------
// Executor — drives the real paladin_core::destroy_vault.
// ---------------------------------------------------------------------------

fn run_destroy(path: &Path) -> (EffectOutcome, Result<DestroyReport, PaladinError>) {
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let mut clipboard = paladin_tui::clipboard::ClipboardSession::new();
    // The executor ignores `state` on the destroy arm; a cheap
    // placeholder is fine.
    let mut state = AppState::StartupError {
        path: None,
        message: String::new(),
    };
    let outcome = execute(
        Effect::DestroyVault {
            path: path.to_path_buf(),
        },
        &mut state,
        &tx,
        &mut clipboard,
    );
    let event = rx.try_recv().expect("executor posts a DestroyVault result");
    let AppEvent::EffectResult(EffectResult::DestroyVault(result)) = event else {
        panic!("expected EffectResult::DestroyVault, got {event:?}");
    };
    (outcome, result)
}

#[test]
fn execute_destroy_vault_deletes_primary_and_backup() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create");
    vault.save(&store).expect("commit");
    // Force a `.bak` by re-creating with force-rotate semantics: just
    // copy the primary to the sibling `.bak`.
    std::fs::copy(&path, dir.path().join("vault.bin.bak")).expect("seed bak");

    let (outcome, result) = run_destroy(&path);
    assert_eq!(outcome, EffectOutcome::Continue);
    let report = result.expect("destroy succeeds");
    assert!(report.primary_deleted);
    assert!(report.backup_deleted, "the sibling .bak is unlinked too");
    assert!(!path.exists(), "primary is gone");
    assert!(!dir.path().join("vault.bin.bak").exists(), "bak is gone");
}

#[test]
fn execute_destroy_vault_no_backup_reports_backup_deleted_false() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create");
    vault.save(&store).expect("commit");

    let (_, result) = run_destroy(&path);
    let report = result.expect("destroy succeeds");
    assert!(report.primary_deleted);
    assert!(!report.backup_deleted, "no .bak was present");
    assert!(!path.exists());
}

#[test]
fn execute_destroy_vault_missing_reports_vault_missing_idempotently() {
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    // Never created.
    let (_, result) = run_destroy(&path);
    assert!(
        matches!(result, Err(PaladinError::VaultMissing)),
        "an absent primary is vault_missing"
    );
}

#[test]
fn execute_destroy_vault_partial_failure_when_bak_is_a_directory() {
    // Mirrors the CLI test: a `.bak` directory passes the symlink probe
    // but `remove_file` fails → DestroyIoError(unlink_backup_file) with
    // primary_deleted=true, backup_deleted=false.
    let dir = secure_test_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create");
    vault.save(&store).expect("commit");
    std::fs::create_dir(dir.path().join("vault.bin.bak")).expect("mkdir bak dir");

    let (_, result) = run_destroy(&path);
    match result {
        Err(PaladinError::DestroyIoError {
            operation,
            primary_deleted,
            backup_deleted,
            ..
        }) => {
            assert_eq!(operation, "unlink_backup_file");
            assert!(primary_deleted, "primary is unlinked before the bak fails");
            assert!(!backup_deleted);
        }
        other => panic!("expected DestroyIoError, got {other:?}"),
    }
    assert!(!path.exists(), "primary should be gone on partial failure");
}

#[test]
#[cfg(unix)]
fn execute_destroy_vault_symlinked_primary_is_rejected() {
    let dir = secure_test_tempdir();
    let target = dir.path().join("real.bin");
    let path = dir.path().join("vault.bin");
    std::fs::write(&target, b"real").expect("write target");
    std::os::unix::fs::symlink(&target, &path).expect("symlink primary");

    let (_, result) = run_destroy(&path);
    assert!(
        matches!(
            result,
            Err(PaladinError::IoError { operation, .. }) if operation == "vault_file_is_symlink"
        ),
        "a symlinked primary is rejected before any unlink"
    );
    assert!(
        target.exists(),
        "the symlink target survives byte-identical"
    );
}
