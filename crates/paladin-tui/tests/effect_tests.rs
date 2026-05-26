// SPDX-License-Identifier: AGPL-3.0-or-later

//! Effect-executor tests for `paladin-tui`.
//!
//! Tracks `docs/IMPLEMENTATION_PLAN_03_TUI.md` > "Implementation checklist":
//! "Implement reducer, event producers, effect execution, ...".
//!
//! The executor is the only impure boundary between the pure reducer
//! and `paladin-core` / OS resources. Each [`Effect`] dispatches to the
//! matching core call, sends back the expected [`AppEvent`], and
//! returns the right [`EffectOutcome`]; `Effect::Quit` short-circuits
//! the run loop without emitting an `AppEvent`.

mod common;

use common::test_tempdir;

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Instant, SystemTime};

use secrecy::SecretString;
use tempfile::TempDir;

use paladin_core::{
    export as core_export, validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm,
    Argon2Params, EncryptionOptions, IconHintInput, ImportConflict, ImportFormat, PaladinError,
    SettingPatch, Store, Vault, VaultInit, VaultLock,
};

use paladin_tui::app::effect::{execute, EffectOutcome};
use paladin_tui::app::event::{
    AddFailure, AddSuccess, AppEvent, Effect, EffectResult, ImportFailure, ImportSuccess,
};
use paladin_tui::app::state::{AppState, ExportFormat, Focus};

/// Light Argon2 params for fast tests; mirrors the CLI test fixtures.
fn light_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    }
}

/// Create a tempdir whose own mode is `0700`, so vault-dir permission
/// checks (`unsafe_permissions`) pass even when the system `TMPDIR`
/// inherits looser bits.
fn secure_tempdir() -> TempDir {
    let dir = test_tempdir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

fn create_encrypted_vault(path: &Path, passphrase: &str) {
    let pp = SecretString::from(passphrase.to_string());
    let opts = EncryptionOptions::with_params(pp, light_params()).expect("encryption opts");
    let (vault, store) = Store::create(path, VaultInit::Encrypted(opts)).expect("create vault");
    vault.save(&store).expect("commit initial vault");
}

fn create_plaintext_vault(path: &Path) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create vault");
    vault.save(&store).expect("commit initial vault");
}

/// A throwaway state for effects that do not read it (`Quit`,
/// `Unlock`, `ClearClipboard`). `CreateVault` is the cheapest
/// variant to construct.
fn dummy_state() -> AppState {
    AppState::create_vault_initial(PathBuf::from("/dev/null/dummy-vault.bin"))
}

/// Build an [`AppState::Unlocked`] backed by a real plaintext vault at
/// `path` containing a single TOTP account labeled `label`. Returns the
/// state and the account's `AccountId` so callers can target it.
fn unlocked_with_one_totp(path: &Path, label: &str) -> (AppState, AccountId) {
    let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create vault");
    vault.save(&store).expect("commit empty vault");
    let id = add_totp_account(&mut vault, &store, label);
    let state = AppState::Unlocked {
        path: path.to_path_buf(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    (state, id)
}

fn add_totp_account(vault: &mut Vault, store: &Store, label: &str) -> AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: None,
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

// ---------------------------------------------------------------------------
// Effect::Quit
// ---------------------------------------------------------------------------

#[test]
fn execute_quit_returns_quit_and_sends_no_event() {
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let mut state = dummy_state();
    let outcome = execute(
        Effect::Quit,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Quit);
    assert!(
        rx.try_recv().is_err(),
        "Effect::Quit must not emit an AppEvent"
    );
}

// ---------------------------------------------------------------------------
// Effect::Unlock — happy path
// ---------------------------------------------------------------------------

#[test]
fn execute_unlock_with_correct_passphrase_sends_unlock_ok() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let passphrase = "the-right-passphrase";
    create_encrypted_vault(&path, passphrase);

    let (tx, rx) = mpsc::channel();
    let effect = Effect::Unlock {
        path: path.clone(),
        passphrase: SecretString::from(passphrase.to_string()),
    };

    // Bound the executor's `opened_at` sample inside a window we
    // control so we can assert the executor used a real monotonic
    // sample rather than some default-constructed instant.
    let before = Instant::now();
    let mut state = dummy_state();
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    let after = Instant::now();
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Unlock {
            result: Ok(_pair),
            opened_at,
        }) => {
            assert!(
                opened_at >= before && opened_at <= after,
                "opened_at must be sampled inside [before, after] of execute()"
            );
        }
        other => panic!("expected EffectResult::Unlock {{ Ok, .. }}, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Unlock"
    );
}

// ---------------------------------------------------------------------------
// Effect::Unlock — decrypt_failed surfaces as Err for the reducer to
// route inline on the unlock screen.
// ---------------------------------------------------------------------------

#[test]
fn execute_unlock_with_wrong_passphrase_sends_decrypt_failed() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    create_encrypted_vault(&path, "right");

    let (tx, rx) = mpsc::channel();
    let effect = Effect::Unlock {
        path: path.clone(),
        passphrase: SecretString::from("wrong".to_string()),
    };

    let mut state = dummy_state();
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("event should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Unlock {
            result: Err(PaladinError::DecryptFailed),
            ..
        }) => {}
        other => {
            panic!("expected EffectResult::Unlock {{ Err(DecryptFailed), .. }}, got {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// Effect::Unlock — non-decrypt errors flow through unchanged. The
// reducer turns these into the startup-error screen.
// ---------------------------------------------------------------------------

#[test]
fn execute_unlock_against_create_vault_sends_vault_missing() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("does-not-exist.bin");

    let (tx, rx) = mpsc::channel();
    let effect = Effect::Unlock {
        path: path.clone(),
        passphrase: SecretString::from("any".to_string()),
    };

    let mut state = dummy_state();
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("event should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Unlock {
            result: Err(PaladinError::VaultMissing),
            ..
        }) => {}
        other => panic!("expected EffectResult::Unlock {{ Err(VaultMissing), .. }}, got {other:?}"),
    }
}

#[test]
fn execute_unlock_against_plaintext_vault_sends_wrong_vault_lock() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    create_plaintext_vault(&path);

    let (tx, rx) = mpsc::channel();
    let effect = Effect::Unlock {
        path: path.clone(),
        passphrase: SecretString::from("any".to_string()),
    };

    let mut state = dummy_state();
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("event should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Unlock {
            result: Err(PaladinError::WrongVaultLock { .. }),
            ..
        }) => {}
        other => {
            panic!("expected EffectResult::Unlock {{ Err(WrongVaultLock), .. }}, got {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// Channel resilience — a dropped receiver (e.g. the run loop quit
// in-flight) must not panic the executor. The result drops cleanly
// and zeroizes the carried passphrase / pair.
// ---------------------------------------------------------------------------

#[test]
fn execute_unlock_with_dropped_receiver_does_not_panic() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    create_encrypted_vault(&path, "pass");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    drop(rx);

    let effect = Effect::Unlock {
        path: path.clone(),
        passphrase: SecretString::from("pass".to_string()),
    };

    let mut state = dummy_state();
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(
        outcome,
        EffectOutcome::Continue,
        "executor must continue even when the receiver is gone"
    );
}

// ---------------------------------------------------------------------------
// Effect::Rename
// ---------------------------------------------------------------------------

/// `Effect::Rename` against an `AppState::Unlocked` whose live `Vault`
/// owns the target account routes through `Vault::mutate_and_save` →
/// `Vault::rename`. The post-rename label lives on the live vault, the
/// on-disk primary carries the same payload after commit, and the
/// executor posts back `EffectResult::Rename` with `Ok(())` so the
/// reducer can close the modal and publish the status confirmation.
#[test]
fn execute_rename_with_valid_label_renames_account_and_sends_ok() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Rename {
        path: path.clone(),
        account_id: id,
        new_label: "github-personal".to_string(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Rename {
            account_id,
            result: Ok(()),
        }) => {
            assert_eq!(account_id, id, "result must carry the source account_id");
        }
        other => panic!("expected EffectResult::Rename {{ Ok }}, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Rename"
    );

    // The live vault now carries the new label.
    let live_label = match &state {
        AppState::Unlocked { vault, .. } => vault
            .iter()
            .find(|a| a.id() == id)
            .expect("account should exist")
            .label()
            .to_string(),
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(live_label, "github-personal");

    // Re-open the on-disk primary and assert the commit landed.
    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    let on_disk_label = reopened
        .iter()
        .find(|a| a.id() == id)
        .expect("account on disk")
        .label()
        .to_string();
    assert_eq!(
        on_disk_label, "github-personal",
        "Vault::mutate_and_save must commit the new label to the on-disk primary"
    );
}

/// Per `docs/DESIGN.md` §6 (Rename) the trimmed draft is passed through to
/// `Vault::rename` even when it equals the current label so
/// `updated_at` advances and matches CLI behavior.
#[test]
fn execute_rename_with_same_label_still_bumps_updated_at() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, id) = unlocked_with_one_totp(&path, "github");

    let prior_updated_at = match &state {
        AppState::Unlocked { vault, .. } => vault
            .iter()
            .find(|a| a.id() == id)
            .expect("account exists")
            .updated_at(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    // Wall-clock must advance by at least one second between the
    // initial save (`add_totp_account`) and the rename so the
    // post-rename `updated_at` (stored in whole seconds) is strictly
    // greater. The reducer / executor never sleeps in production —
    // this is a test-only synchronization to make the bump observable.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Rename {
        path: path.clone(),
        account_id: id,
        new_label: "github".to_string(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    assert!(matches!(
        evt,
        AppEvent::EffectResult(EffectResult::Rename { result: Ok(()), .. })
    ));

    let new_updated_at = match &state {
        AppState::Unlocked { vault, .. } => vault
            .iter()
            .find(|a| a.id() == id)
            .expect("account exists")
            .updated_at(),
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert!(
        new_updated_at > prior_updated_at,
        "same-label rename must still bump updated_at ({prior_updated_at} -> {new_updated_at})"
    );
}

/// `Effect::Rename` carrying an `account_id` that does not exist in
/// the live vault surfaces an `account_not_found` `Err` for the
/// reducer to discard (mismatched-account_id results are dropped
/// alongside the carried error per the reducer's `EffectResult::Rename`
/// arm). The live vault is unchanged.
#[test]
fn execute_rename_with_unknown_account_id_sends_account_not_found_err() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, _id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let bogus = AccountId::new();
    let effect = Effect::Rename {
        path: path.clone(),
        account_id: bogus,
        new_label: "whatever".to_string(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Rename {
            account_id,
            result:
                Err(PaladinError::InvalidState {
                    operation: "rename",
                    state: "account_not_found",
                }),
        }) => {
            assert_eq!(account_id, bogus);
        }
        other => panic!(
            "expected EffectResult::Rename {{ Err(InvalidState account_not_found) }}, got {other:?}"
        ),
    }

    // The unrelated account in the live vault is untouched.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(vault.iter().count(), 1);
            assert_eq!(vault.iter().next().unwrap().label(), "github");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

/// A stale `Effect::Rename` (emitted under an `Unlocked` state that
/// has since transitioned to `Locked` / `CreateVault` / etc.) is
/// dropped silently so the executor cannot synthesize a rename
/// attempt against an unrelated vault.
#[test]
fn execute_rename_on_non_unlocked_state_is_silently_dropped() {
    let mut state = AppState::create_vault_initial(PathBuf::from("/tmp/dummy-vault.bin"));
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Rename {
        path: PathBuf::from("/tmp/dummy-vault.bin"),
        account_id: AccountId::new(),
        new_label: "anything".to_string(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    assert!(
        rx.try_recv().is_err(),
        "off-Unlocked Effect::Rename must not emit an AppEvent"
    );
}

/// Path mismatch (e.g. the user `--vault`-switched between the
/// reducer-side emit and the run loop draining the effect queue) is
/// treated like a stale effect: dropped silently with no mutation.
#[test]
fn execute_rename_with_mismatched_path_is_silently_dropped() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("real-vault.bin");
    let (mut state, id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Rename {
        path: PathBuf::from("/tmp/some-other-vault.bin"),
        account_id: id,
        new_label: "renamed".to_string(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    assert!(
        rx.try_recv().is_err(),
        "path-mismatched Effect::Rename must not emit an AppEvent"
    );

    // The live vault is untouched.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(vault.iter().next().unwrap().label(), "github");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

/// A dropped receiver during a Rename does not panic the executor,
/// mirroring the Unlock channel-resilience contract.
#[test]
fn execute_rename_with_dropped_receiver_does_not_panic() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    drop(rx);

    let effect = Effect::Rename {
        path: path.clone(),
        account_id: id,
        new_label: "renamed".to_string(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    // The rename still took effect in memory (the executor does not
    // pre-check the channel before mutating) and on disk.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(vault.iter().next().unwrap().label(), "renamed");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Effect::Remove
// ---------------------------------------------------------------------------

/// `Effect::Remove` against an `AppState::Unlocked` whose live `Vault`
/// owns the target account routes through `Vault::mutate_and_save` →
/// `Vault::remove`. The account is gone from the live vault, the
/// on-disk primary no longer carries it after commit, and the
/// executor posts back `EffectResult::Remove` with `Ok(display_label)`
/// so the reducer can close the modal and publish the status
/// confirmation.
#[test]
fn execute_remove_with_existing_account_removes_and_sends_ok_with_label() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Remove {
        path: path.clone(),
        account_id: id,
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Remove {
            account_id,
            result: Ok(label),
        }) => {
            assert_eq!(account_id, id, "result must carry the source account_id");
            assert_eq!(
                label, "github",
                "Ok carries the removed account's display label"
            );
        }
        other => panic!("expected EffectResult::Remove {{ Ok }}, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Remove"
    );

    // The live vault no longer carries the account.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert!(
                vault.iter().find(|a| a.id() == id).is_none(),
                "Vault::remove must drop the account from the live vault"
            );
            assert_eq!(
                vault.iter().count(),
                0,
                "the one-account fixture is empty after remove"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }

    // Re-open the on-disk primary and assert the commit landed.
    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert_eq!(
        reopened.iter().count(),
        0,
        "Vault::mutate_and_save must commit the remove to the on-disk primary"
    );
}

/// `Effect::Remove` carrying an `account_id` that does not exist in
/// the live vault surfaces an `account_not_found` `Err` for the
/// reducer to discard. The live vault is unchanged.
#[test]
fn execute_remove_with_unknown_account_id_sends_account_not_found_err() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, _id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let bogus = AccountId::new();
    let effect = Effect::Remove {
        path: path.clone(),
        account_id: bogus,
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Remove {
            account_id,
            result:
                Err(PaladinError::InvalidState {
                    operation: "remove",
                    state: "account_not_found",
                }),
        }) => {
            assert_eq!(account_id, bogus);
        }
        other => panic!(
            "expected EffectResult::Remove {{ Err(InvalidState account_not_found) }}, got {other:?}"
        ),
    }

    // The unrelated account in the live vault is untouched.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(vault.iter().count(), 1);
            assert_eq!(vault.iter().next().unwrap().label(), "github");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

/// A stale `Effect::Remove` (emitted under an `Unlocked` state that
/// has since transitioned to `Locked` / `CreateVault` / etc.) is
/// dropped silently so the executor cannot synthesize a remove
/// attempt against an unrelated vault.
#[test]
fn execute_remove_on_non_unlocked_state_is_silently_dropped() {
    let mut state = AppState::create_vault_initial(PathBuf::from("/tmp/dummy-vault.bin"));
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Remove {
        path: PathBuf::from("/tmp/dummy-vault.bin"),
        account_id: AccountId::new(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    assert!(
        rx.try_recv().is_err(),
        "off-Unlocked Effect::Remove must not emit an AppEvent"
    );
}

/// Path mismatch (e.g. the user `--vault`-switched between the
/// reducer-side emit and the run loop draining the effect queue) is
/// treated like a stale effect: dropped silently with no mutation.
#[test]
fn execute_remove_with_mismatched_path_is_silently_dropped() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("real-vault.bin");
    let (mut state, id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Remove {
        path: PathBuf::from("/tmp/some-other-vault.bin"),
        account_id: id,
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    assert!(
        rx.try_recv().is_err(),
        "path-mismatched Effect::Remove must not emit an AppEvent"
    );

    // The live vault is untouched.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(vault.iter().next().unwrap().label(), "github");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

/// A dropped receiver during a Remove does not panic the executor,
/// mirroring the Unlock channel-resilience contract.
#[test]
fn execute_remove_with_dropped_receiver_does_not_panic() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    drop(rx);

    let effect = Effect::Remove {
        path: path.clone(),
        account_id: id,
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    // The remove still took effect in memory (the executor does not
    // pre-check the channel before mutating) and on disk.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(vault.iter().count(), 0);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

/// When the removed account has an issuer, the carried display label
/// formats as `issuer:label` to match the CLI's "Removed Acme:alice."
/// text-output idiom (see paladin-cli's `display_label`).
#[test]
fn execute_remove_carries_issuer_joined_display_label() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");

    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create vault");
    let input = AccountInput {
        label: "alice".to_string(),
        issuer: Some("Acme".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(&store).expect("save vault");

    let mut state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Remove {
        path: path.clone(),
        account_id: id,
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Remove {
            account_id,
            result: Ok(label),
        }) => {
            assert_eq!(account_id, id);
            assert_eq!(
                label, "Acme:alice",
                "issuer-prefixed display label must be carried back verbatim"
            );
        }
        other => panic!("expected EffectResult::Remove {{ Ok }}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Effect::ApplySettings
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Settings modal: "Confirm
//  runs every changed setter inside one Vault::mutate_and_save
//  transaction.")
// ---------------------------------------------------------------------------

#[test]
fn execute_apply_settings_with_single_patch_applies_and_sends_ok() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, _id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::ApplySettings {
        path: path.clone(),
        patches: vec![SettingPatch::AutoLockEnabled(true)],
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Settings { result: Ok(()) }) => {}
        other => panic!("expected EffectResult::Settings {{ Ok }}, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::ApplySettings"
    );

    // The live vault carries the new value.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert!(
                vault.settings().auto_lock_enabled(),
                "single patch must update the live vault"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }

    // Re-open the on-disk primary and assert the commit landed.
    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert!(
        reopened.settings().auto_lock_enabled(),
        "Vault::mutate_and_save must commit the new setting to the on-disk primary"
    );
}

#[test]
fn execute_apply_settings_with_multiple_patches_applies_atomically_and_sends_ok() {
    // Per docs/IMPLEMENTATION_PLAN_03_TUI.md > Settings modal: "Confirm
    // runs every changed setter inside one `Vault::mutate_and_save`
    // transaction." A four-patch list lands as one commit and every
    // field reflects the new value in the live vault and on disk.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, _id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::ApplySettings {
        path: path.clone(),
        patches: vec![
            SettingPatch::AutoLockEnabled(true),
            SettingPatch::AutoLockTimeoutSecs(120),
            SettingPatch::ClipboardClearEnabled(true),
            SettingPatch::ClipboardClearSecs(45),
        ],
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    assert!(matches!(
        evt,
        AppEvent::EffectResult(EffectResult::Settings { result: Ok(()) })
    ));

    match &state {
        AppState::Unlocked { vault, .. } => {
            let s = vault.settings();
            assert!(s.auto_lock_enabled());
            assert_eq!(s.auto_lock_timeout_secs(), 120);
            assert!(s.clipboard_clear_enabled());
            assert_eq!(s.clipboard_clear_secs(), 45);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }

    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    let s = reopened.settings();
    assert!(s.auto_lock_enabled());
    assert_eq!(s.auto_lock_timeout_secs(), 120);
    assert!(s.clipboard_clear_enabled());
    assert_eq!(s.clipboard_clear_secs(), 45);
}

#[test]
fn execute_apply_settings_with_out_of_range_patch_returns_validation_error() {
    // Defensive: the reducer clamps spinner values before submit, so
    // this path is observable only when a future code path bypasses
    // the modal clamp. `apply_setting_patch` enforces the §4.7
    // bounds (`auto_lock.timeout_secs` ∈ 30..=86_400), so an
    // out-of-range patch rejects with `validation_error` and
    // `Vault::mutate_and_save` rolls back. The live vault stays at
    // its pre-attempt values.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, _id) = unlocked_with_one_totp(&path, "github");

    let pre = match &state {
        AppState::Unlocked { vault, .. } => vault.settings().auto_lock_timeout_secs(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::ApplySettings {
        path: path.clone(),
        patches: vec![SettingPatch::AutoLockTimeoutSecs(0)],
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Settings { result: Err(err) }) => {
            assert!(
                matches!(err, PaladinError::ValidationError { field, .. } if field == "auto_lock.timeout_secs"),
                "expected validation_error for auto_lock.timeout_secs, got {err:?}"
            );
        }
        other => panic!("expected EffectResult::Settings {{ Err }}, got {other:?}"),
    }

    // mutate_and_save rolls back: the live vault still has the
    // pre-attempt value.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(vault.settings().auto_lock_timeout_secs(), pre);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn execute_apply_settings_on_non_unlocked_state_is_silently_dropped() {
    let mut state = AppState::create_vault_initial(PathBuf::from("/tmp/dummy-vault.bin"));
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::ApplySettings {
        path: PathBuf::from("/tmp/dummy-vault.bin"),
        patches: vec![SettingPatch::AutoLockEnabled(true)],
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    assert!(
        rx.try_recv().is_err(),
        "off-Unlocked Effect::ApplySettings must not emit an AppEvent"
    );
}

#[test]
fn execute_apply_settings_with_mismatched_path_is_silently_dropped() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("real-vault.bin");
    let (mut state, _id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::ApplySettings {
        path: PathBuf::from("/tmp/some-other-vault.bin"),
        patches: vec![SettingPatch::AutoLockEnabled(true)],
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    assert!(
        rx.try_recv().is_err(),
        "path-mismatched Effect::ApplySettings must not emit an AppEvent"
    );

    // The live vault settings are untouched.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert!(!vault.settings().auto_lock_enabled());
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn execute_apply_settings_with_dropped_receiver_does_not_panic() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, _id) = unlocked_with_one_totp(&path, "github");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    drop(rx);
    let effect = Effect::ApplySettings {
        path,
        patches: vec![SettingPatch::AutoLockEnabled(true)],
    };

    // The mutate-and-save still ran (vault carries the new value);
    // the send into a dropped channel is swallowed without panic.
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert!(vault.settings().auto_lock_enabled());
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Effect::Add — duplicate detection (validate_manual + find_duplicate)
// ---------------------------------------------------------------------------

/// `Effect::Add` whose carried Manual-mode fields produce a
/// `ValidatedAccount` that exactly matches an existing
/// `(secret, issuer, label)` triple in the vault must:
///
/// 1. Build the `AccountInput` and call `paladin_core::validate_manual`.
/// 2. Call `Vault::find_duplicate(&validated)`.
/// 3. Emit `EffectResult::Add { Err(AddFailure::Duplicate { existing, pending }) }`
///    carrying the existing account's `AccountSummary` and the
///    validated pending account so the reducer can stash it for the
///    follow-up "add anyway" confirmation.
/// 4. Leave the on-disk vault unchanged (the duplicate gate runs
///    before `Vault::mutate_and_save`).
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
/// *"manual and URI duplicate collisions call
/// `Vault::find_duplicate(&validated)` before mutation. A collision
/// initially rejects with the existing account in the modal and
/// offers an 'add anyway' confirmation."*
#[test]
fn execute_add_with_duplicate_emits_duplicate_failure_and_does_not_mutate_vault() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, existing_id) = unlocked_with_one_totp(&path, "github");

    // Capture the pre-attempt account count and the existing account's
    // summary so the assertions can verify the executor neither
    // mutated the vault nor invented a fresh summary.
    let (initial_count, existing_summary) = match &state {
        AppState::Unlocked { vault, .. } => (
            vault.iter().count(),
            vault
                .iter()
                .find(|a| a.id() == existing_id)
                .expect("existing account in vault")
                .summary(),
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    // Mirror `unlocked_with_one_totp`'s seed: same secret, same label,
    // no issuer, TOTP/SHA1/6 digits. `validate_manual` will produce
    // an account whose (secret, issuer, label) triple matches the
    // stored one verbatim.
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Add {
        path: path.clone(),
        label: "github".to_string(),
        issuer: String::new(),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: 30,
        counter: 0,
        icon_hint_text: String::new(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Add {
            result:
                Err(AddFailure::Duplicate {
                    existing,
                    pending: _,
                }),
        }) => {
            assert_eq!(
                existing, existing_summary,
                "executor must carry the existing account's AccountSummary"
            );
        }
        other => panic!("expected EffectResult::Add Duplicate, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Add"
    );

    // The live vault still carries exactly the pre-attempt accounts.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "duplicate detection must run before any mutation"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }

    // Re-open the on-disk primary and assert no commit happened.
    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert_eq!(
        reopened.iter().count(),
        initial_count,
        "duplicate detection must not commit to the on-disk primary"
    );
}

// ---------------------------------------------------------------------------
// Effect::AddFromUri — duplicate detection (parse_otpauth + find_duplicate)
// ---------------------------------------------------------------------------

/// `Effect::AddFromUri` whose carried `otpauth://` URI parses to a
/// `ValidatedAccount` that exactly matches an existing
/// `(secret, issuer, label)` triple in the vault must:
///
/// 1. Call [`paladin_core::parse_otpauth`] over the carried URI bytes.
/// 2. Call `Vault::find_duplicate(&validated)`.
/// 3. Emit `EffectResult::Add { Err(AddFailure::Duplicate { existing, pending }) }`
///    carrying the existing account's `AccountSummary` and the
///    parsed pending account so the reducer can stash it for the
///    follow-up "add anyway" confirmation. The result is delivered
///    on the shared [`EffectResult::Add`] channel so the reducer's
///    Manual-mode duplicate handling covers URI-mode too.
/// 4. Leave the on-disk vault unchanged (the duplicate gate runs
///    before `Vault::mutate_and_save`).
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
/// *"URI mode is a single text field; on submit the entered string is
/// passed to `paladin_core::parse_otpauth(uri, submit_time)`, and on
/// success the resulting `ValidatedAccount` shares the manual path's
/// duplicate-detection, 'add anyway' override, and
/// `Vault::mutate_and_save` insertion."*
#[test]
fn execute_add_from_uri_with_duplicate_emits_duplicate_failure_and_does_not_mutate_vault() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, existing_id) = unlocked_with_one_totp(&path, "github");

    let (initial_count, existing_summary) = match &state {
        AppState::Unlocked { vault, .. } => (
            vault.iter().count(),
            vault
                .iter()
                .find(|a| a.id() == existing_id)
                .expect("existing account in vault")
                .summary(),
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    // `unlocked_with_one_totp` seeds: secret `JBSWY3DPEHPK3PXP`,
    // no issuer, label "github", SHA1, 6 digits, TOTP, period 30.
    // The URI below parses to the same triple so `find_duplicate`
    // matches verbatim.
    let uri = SecretString::from(
        "otpauth://totp/github?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"
            .to_string(),
    );
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::AddFromUri {
        path: path.clone(),
        uri,
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Add {
            result:
                Err(AddFailure::Duplicate {
                    existing,
                    pending: _,
                }),
        }) => {
            assert_eq!(
                existing, existing_summary,
                "executor must carry the existing account's AccountSummary"
            );
        }
        other => panic!("expected EffectResult::Add Duplicate, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::AddFromUri"
    );

    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "duplicate detection must run before any mutation"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }

    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert_eq!(
        reopened.iter().count(),
        initial_count,
        "duplicate detection must not commit to the on-disk primary"
    );
}

/// An `Effect::AddFromUri` whose carried bytes do not parse as a
/// valid `otpauth://` URI must emit
/// `EffectResult::Add { Err(AddFailure::Validation(...)) }` carrying
/// the `parse_otpauth` error verbatim — per `docs/IMPLEMENTATION_PLAN_03_TUI.md`
/// "Modals (per §6)" > Add: *"Parser errors
/// (`unsupported_import_format`, `validation_error`) stay in the
/// modal as inline errors and never mutate the vault."*
#[test]
fn execute_add_from_uri_with_invalid_uri_emits_validation_failure() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, _) = unlocked_with_one_totp(&path, "github");
    let initial_count = match &state {
        AppState::Unlocked { vault, .. } => vault.iter().count(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    let uri = SecretString::from("not-a-real-otpauth-uri".to_string());
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::AddFromUri {
        path: path.clone(),
        uri,
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Add {
            result: Err(AddFailure::Validation(_)),
        }) => {}
        other => panic!("expected EffectResult::Add Validation, got {other:?}"),
    }
    assert!(rx.try_recv().is_err());

    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "parse failure must not mutate the vault"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Effect::AddAnyway — duplicate-allowed insertion path
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > "Add modal" > "The follow-up
//  'add anyway' confirmation inserts the pending validated account on
//  the duplicate-allowed path with a fresh ID.")
// ---------------------------------------------------------------------------

/// `Effect::AddAnyway` carries a `ValidatedAccount` previously stashed
/// in [`AddModal::pending_duplicate_add`] after the duplicate-rejection
/// slice. On the user's follow-up "add anyway" confirmation, the
/// executor wraps `Vault::add` in `Vault::mutate_and_save` so the
/// pending account is inserted with a fresh `AccountId`, persisted to
/// the on-disk primary, and surfaced through
/// `EffectResult::Add { Ok(AddSuccess { summary, warnings }) }`.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add: *"A
/// collision initially rejects with the existing account in the modal
/// and offers an 'add anyway' confirmation that inserts the pending
/// validated account on the duplicate-allowed path (CLI parity with
/// `--allow-duplicate`, appending a new account that shares the
/// `(secret, issuer, label)` triple)."*
#[test]
fn execute_add_anyway_inserts_validated_account_with_fresh_id_and_persists() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, existing_id) = unlocked_with_one_totp(&path, "github");
    let initial_count = match &state {
        AppState::Unlocked { vault, .. } => vault.iter().count(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    // Build a validated account whose (secret, issuer, label) triple
    // matches the existing entry; the executor must insert it without
    // re-running duplicate detection.
    let input = AccountInput {
        label: "github".to_string(),
        issuer: None,
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, SystemTime::now())
        .expect("validation should succeed on golden duplicate input");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::AddAnyway {
        path: path.clone(),
        validated: Box::new(validated),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    let new_id = match evt {
        AppEvent::EffectResult(EffectResult::Add {
            result: Ok(success),
        }) => {
            assert_ne!(
                success.summary.id, existing_id,
                "add-anyway insertion must assign a fresh AccountId distinct from the colliding one"
            );
            assert_eq!(success.summary.label, "github");
            assert_eq!(success.summary.issuer, None);
            // `success.warnings` rides the validation outcome (e.g.
            // `ShortSecret` on a 16-character Base32 secret); the
            // status-line confirmation slice asserts on warning
            // rendering — this slice only checks the insertion path.
            success.summary.id
        }
        other => panic!("expected EffectResult::Add Ok, got {other:?}"),
    };
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::AddAnyway"
    );

    // Live in-memory vault gained the duplicate alongside the existing entry.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count + 1,
                "add-anyway must insert the pending validated account"
            );
            assert!(
                vault.iter().any(|a| a.id() == new_id),
                "vault must carry the freshly inserted account"
            );
            assert!(
                vault.iter().any(|a| a.id() == existing_id),
                "existing colliding account must survive add-anyway"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }

    // On-disk primary committed.
    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert_eq!(
        reopened.iter().count(),
        initial_count + 1,
        "add-anyway must commit to the on-disk primary"
    );
    assert!(
        reopened.iter().any(|a| a.id() == new_id),
        "on-disk vault must carry the freshly inserted account"
    );
}

/// Path-mismatch / non-`Unlocked` deliveries drop the effect silently
/// — the dispatcher only mutates the live vault when the carried path
/// still matches `Unlocked.path`, mirroring the path-guard the Remove /
/// Rename / Add / `AddFromUri` arms already enforce.
#[test]
fn execute_add_anyway_with_mismatched_path_is_silently_dropped() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let other_path = tmp.path().join("other.bin");
    let (mut state, _) = unlocked_with_one_totp(&path, "github");
    let initial_count = match &state {
        AppState::Unlocked { vault, .. } => vault.iter().count(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    let input = AccountInput {
        label: "github".to_string(),
        issuer: None,
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, SystemTime::now()).expect("validation should succeed");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::AddAnyway {
        path: other_path,
        validated: Box::new(validated),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    assert!(
        rx.try_recv().is_err(),
        "mismatched path must drop the effect without emitting"
    );
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "mismatched-path must not mutate the live vault"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Effect::Add — non-duplicate happy-path insertion
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > "Add modal" — covers the
//  `Vault::add` inside `Vault::mutate_and_save` insertion referenced by
//  `effect_result_add_ok_closes_modal`'s "later slice" comment.)
// ---------------------------------------------------------------------------

/// `Effect::Add` whose validated `(secret, issuer, label)` triple does
/// **not** match any existing account must:
///
/// 1. Run `validate_manual` over the carried form fields.
/// 2. Call `Vault::find_duplicate(&validated)` and see no match.
/// 3. Wrap `Vault::add` in `Vault::mutate_and_save` so the insertion
///    commits atomically to the on-disk primary alongside the live
///    in-memory vault.
/// 4. Emit `EffectResult::Add { Ok(AddSuccess { summary, warnings }) }`
///    carrying the newly assigned account's `AccountSummary` and the
///    validation warnings.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add: *"Manual
/// entries route through `paladin_core::validate_manual(input,
/// submit_time)` ... Successful additions are wrapped in
/// `Vault::mutate_and_save`, which runs the `Vault::add` ... mutation
/// and save under core-owned rollback."*
#[test]
fn execute_add_with_no_duplicate_inserts_validated_account_and_persists() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, existing_id) = unlocked_with_one_totp(&path, "github");
    let initial_count = match &state {
        AppState::Unlocked { vault, .. } => vault.iter().count(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    // Distinct label keeps the `(secret, issuer, label)` triple unique
    // even though the secret is shared with the seeded account —
    // `Vault::find_duplicate` matches on the full triple, so a label
    // difference alone is enough to bypass the duplicate gate.
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Add {
        path: path.clone(),
        label: "aws".to_string(),
        issuer: String::new(),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: 30,
        counter: 0,
        icon_hint_text: String::new(),
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    let new_id = match evt {
        AppEvent::EffectResult(EffectResult::Add {
            result: Ok(AddSuccess { summary, .. }),
        }) => {
            assert_ne!(
                summary.id, existing_id,
                "fresh insertion must assign a distinct AccountId"
            );
            assert_eq!(summary.label, "aws");
            assert_eq!(summary.issuer, None);
            summary.id
        }
        other => panic!("expected EffectResult::Add Ok, got {other:?}"),
    };
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Add"
    );

    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count + 1,
                "non-duplicate Add must insert into the live vault"
            );
            assert!(
                vault.iter().any(|a| a.id() == new_id),
                "vault must carry the freshly inserted account"
            );
            assert!(
                vault.iter().any(|a| a.id() == existing_id),
                "existing account must survive the Add"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }

    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert_eq!(
        reopened.iter().count(),
        initial_count + 1,
        "non-duplicate Add must commit to the on-disk primary"
    );
    assert!(
        reopened.iter().any(|a| a.id() == new_id),
        "on-disk vault must carry the freshly inserted account"
    );
}

/// `Effect::AddFromUri` whose parsed `(secret, issuer, label)` triple
/// does **not** match any existing account shares the Manual-mode
/// success path: `parse_otpauth` → `Vault::find_duplicate` → wrap
/// `Vault::add` in `Vault::mutate_and_save` → emit
/// `EffectResult::Add { Ok(AddSuccess { summary, warnings }) }`. The
/// reducer's Manual-mode `Ok` handling covers URI-mode too.
#[test]
fn execute_add_from_uri_with_no_duplicate_inserts_validated_account_and_persists() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut state, existing_id) = unlocked_with_one_totp(&path, "github");
    let initial_count = match &state {
        AppState::Unlocked { vault, .. } => vault.iter().count(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    // Distinct label ("aws" vs seeded "github") keeps the
    // `(secret, issuer, label)` triple unique even though the URI
    // encodes the same secret as the seeded account.
    let uri = SecretString::from(
        "otpauth://totp/aws?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30".to_string(),
    );
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::AddFromUri {
        path: path.clone(),
        uri,
    };

    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    let new_id = match evt {
        AppEvent::EffectResult(EffectResult::Add {
            result: Ok(AddSuccess { summary, .. }),
        }) => {
            assert_ne!(
                summary.id, existing_id,
                "fresh insertion must assign a distinct AccountId"
            );
            assert_eq!(summary.label, "aws");
            summary.id
        }
        other => panic!("expected EffectResult::Add Ok, got {other:?}"),
    };
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::AddFromUri"
    );

    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count + 1,
                "non-duplicate URI Add must insert into the live vault"
            );
            assert!(
                vault.iter().any(|a| a.id() == new_id),
                "vault must carry the freshly inserted account"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }

    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert_eq!(
        reopened.iter().count(),
        initial_count + 1,
        "non-duplicate URI Add must commit to the on-disk primary"
    );
}

// ---------------------------------------------------------------------------
// Effect::Import — auto-detect path
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Import modal" >
// *"Format auto-detect routes through `paladin_core::import::from_file`."*
// With `format: None` the executor must build
// `paladin_core::ImportOptions { format: None, .. }`, call
// `paladin_core::import::from_file`, and commit the resulting
// `Vec<ValidatedAccount>` through `Vault::import_accounts` wrapped in
// `Vault::mutate_and_save`. A plain `otpauth://` URI in the source file
// is detected as `ImportFormat::Otpauth` by the core facade, so the
// happy-path executor test only needs to verify the imported count and
// the in-memory / on-disk persistence parity.

#[test]
fn execute_import_with_auto_format_routes_through_import_from_file_for_otpauth_payload_and_persists_via_mutate_and_save(
) {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);

    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let initial_count = vault.iter().count();
    let state = AppState::Unlocked {
        path: path.clone(),
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
    };

    // Write a single otpauth URI so the facade's `detect` returns
    // `ImportFormat::Otpauth` and dispatches to the otpauth importer.
    let source_path = tmp.path().join("import.txt");
    std::fs::write(
        &source_path,
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    )
    .expect("write otpauth source file");

    let mut state = state;
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Import {
        path: path.clone(),
        source_path: source_path.clone(),
        format: None,
        conflict: ImportConflict::Skip,
        paladin_passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    let new_id = match evt {
        AppEvent::EffectResult(EffectResult::Import {
            result: Ok(ImportSuccess { report }),
        }) => {
            assert_eq!(
                report.imported, 1,
                "single-URI otpauth payload must produce exactly one imported account"
            );
            assert_eq!(report.skipped, 0, "no skip path on an empty starting vault");
            assert_eq!(report.replaced, 0, "Skip policy never replaces");
            assert_eq!(report.appended, 0, "Skip policy never appends");
            assert_eq!(
                report.accounts.len(),
                1,
                "imported IDs list must reflect the new account"
            );
            report.accounts[0]
        }
        other => panic!("expected EffectResult::Import Ok, got {other:?}"),
    };
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Import"
    );

    // Live in-memory vault grew by one.
    vault = match state {
        AppState::Unlocked { vault, .. } => vault,
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        vault.iter().count(),
        initial_count + 1,
        "successful import must grow the live vault"
    );
    assert!(
        vault.iter().any(|a| a.id() == new_id),
        "live vault must carry the imported account ID"
    );

    // On-disk primary committed (mutate_and_save persists the merge).
    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    assert_eq!(
        reopened.iter().count(),
        initial_count + 1,
        "successful import must commit to the on-disk primary"
    );
    assert!(
        reopened.iter().any(|a| a.id() == new_id),
        "on-disk vault must carry the imported account ID"
    );
}

#[test]
fn execute_import_with_missing_source_file_emits_io_error_failure_and_leaves_vault_untouched() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let initial_count = vault.iter().count();
    let mut state = AppState::Unlocked {
        path: path.clone(),
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
    };

    let missing = tmp.path().join("does-not-exist.txt");
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Import {
        path: path.clone(),
        source_path: missing,
        format: None,
        conflict: ImportConflict::Skip,
        paladin_passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Import {
            result: Err(ImportFailure(err)),
        }) => match err {
            PaladinError::IoError { operation, .. } => assert_eq!(
                operation, "read_import_file",
                "missing source file must surface the facade's `read_import_file` io_error"
            ),
            other => panic!("expected IoError, got {other:?}"),
        },
        other => panic!("expected EffectResult::Import Err, got {other:?}"),
    }

    // Vault state was not mutated.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "io_error during import must not mutate the live vault"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn execute_import_with_mismatched_path_is_silently_dropped() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let other_path = tmp.path().join("other.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let initial_count = vault.iter().count();
    let mut state = AppState::Unlocked {
        path: path.clone(),
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
    };

    // Write a valid source file so the facade would otherwise succeed —
    // the path guard must reject this effect before the read.
    let source_path = tmp.path().join("import.txt");
    std::fs::write(
        &source_path,
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    )
    .expect("write otpauth source file");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Import {
        path: other_path,
        source_path,
        format: None,
        conflict: ImportConflict::Skip,
        paladin_passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);
    assert!(
        rx.try_recv().is_err(),
        "mismatched path must drop the effect without emitting an AppEvent"
    );

    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "mismatched path must not mutate the live vault"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Explicit-format-override executor coverage —
// docs/IMPLEMENTATION_PLAN_03_TUI.md > "Import modal" >
// "Explicit format overrides (`otpauth` / `aegis` / `paladin` / `qr`)
//  route through `paladin_core::import::from_file`."
// ---------------------------------------------------------------------------

/// Minimal valid Aegis plaintext export with a single TOTP entry.
fn aegis_plaintext_single_totp() -> String {
    r#"{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[{"type":"totp","name":"alice","issuer":"Acme","info":{"secret":"JBSWY3DPEHPK3PXP"}}]}}"#
        .to_string()
}

#[test]
fn execute_import_with_forced_aegis_format_routes_through_import_from_file_for_aegis_payload_and_persists_via_mutate_and_save(
) {
    // Forced `Some(ImportFormat::Aegis)` over Aegis-shaped JSON must
    // dispatch through `from_file` → `aegis_plaintext` (not the
    // otpauth path), parse the entry, and commit via
    // `Vault::mutate_and_save`.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);

    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let initial_count = vault.iter().count();
    let mut state = AppState::Unlocked {
        path: path.clone(),
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
    };

    let source_path = tmp.path().join("aegis.json");
    std::fs::write(&source_path, aegis_plaintext_single_totp()).expect("write aegis source file");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Import {
        path: path.clone(),
        source_path: source_path.clone(),
        format: Some(ImportFormat::Aegis),
        conflict: ImportConflict::Skip,
        paladin_passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    let new_id = match evt {
        AppEvent::EffectResult(EffectResult::Import {
            result: Ok(ImportSuccess { report }),
        }) => {
            assert_eq!(
                report.imported, 1,
                "single-entry Aegis payload must produce exactly one imported account"
            );
            assert_eq!(
                report.accounts.len(),
                1,
                "imported IDs list must reflect the new account"
            );
            report.accounts[0]
        }
        other => panic!("expected EffectResult::Import Ok via forced Aegis, got {other:?}"),
    };

    let live_vault = match &state {
        AppState::Unlocked { vault, .. } => vault,
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        live_vault.iter().count(),
        initial_count + 1,
        "forced-Aegis success must grow the live vault by one"
    );
    assert!(
        live_vault.iter().any(|a| a.id() == new_id),
        "live vault must carry the imported Aegis account ID"
    );

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    assert_eq!(
        reopened.iter().count(),
        initial_count + 1,
        "forced-Aegis success must commit to the on-disk primary"
    );
    assert!(
        reopened.iter().any(|a| a.id() == new_id),
        "on-disk vault must carry the imported Aegis account ID"
    );
}

#[test]
fn execute_import_with_forced_format_mismatch_returns_unsupported_import_format_without_mutation() {
    // Forced `Some(ImportFormat::Aegis)` over an otpauth URI text body
    // must surface `unsupported_import_format` (the facade's
    // `resolve_format` rejects forced/detected disagreement when the
    // detected concrete format is *not* `Unknown`). No mutation reaches
    // the vault.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let initial_count = vault.iter().count();
    let mut state = AppState::Unlocked {
        path: path.clone(),
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
    };

    // Write an otpauth URI: `detect` returns `ImportFormat::Otpauth`,
    // so a forced `Aegis` triggers the mismatch rejection branch.
    let source_path = tmp.path().join("import.txt");
    std::fs::write(
        &source_path,
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    )
    .expect("write otpauth source file");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Import {
        path: path.clone(),
        source_path,
        format: Some(ImportFormat::Aegis),
        conflict: ImportConflict::Skip,
        paladin_passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Import {
            result: Err(ImportFailure(err)),
        }) => match err {
            PaladinError::UnsupportedImportFormat { format } => assert_eq!(
                format, "aegis",
                "the facade must echo the forced format token on mismatch"
            ),
            other => panic!("expected UnsupportedImportFormat, got {other:?}"),
        },
        other => panic!("expected EffectResult::Import Err, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Import"
    );

    let live_vault = match &state {
        AppState::Unlocked { vault, .. } => vault,
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        live_vault.iter().count(),
        initial_count,
        "forced-format mismatch must not mutate the live vault"
    );

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    assert_eq!(
        reopened.iter().count(),
        initial_count,
        "forced-format mismatch must not touch the on-disk primary"
    );
}

// Effect::Import — on-conflict policy is threaded into
// `Vault::import_accounts` and the report counts reflect the chosen
// merge action.
//
// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Import modal" >
// *"On-conflict policy (`skip` / `replace` / `append`) is forwarded to
// `Vault::import_accounts` and reflected in the report counts."*
// The three tests below seed a vault with a single TOTP row whose
// `(secret, issuer=None, label)` triple is identical to the candidate
// produced by the source otpauth URI, then run the executor under
// each `ImportConflict` variant. They lock:
//
//   - Skip: `skipped += 1`, no live-vault size change, existing ID
//     untouched, no entry in `ImportReport.accounts`.
//   - Replace: `replaced += 1`, vault size unchanged, existing
//     `AccountId` preserved in `ImportReport.accounts`.
//   - Append: `appended += 1`, vault grows by one, a fresh
//     `AccountId` distinct from the existing one lands in
//     `ImportReport.accounts`.

fn unlocked_state_with_seeded_collision_target(
    tmp: &TempDir,
    label: &str,
) -> (AppState, std::path::PathBuf, AccountId) {
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let existing_id = add_totp_account(&mut vault, &store, label);
    let state = AppState::Unlocked {
        path: path.clone(),
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
    };
    (state, path, existing_id)
}

#[test]
fn execute_import_with_skip_conflict_over_colliding_account_records_skip_and_leaves_vault_unchanged(
) {
    let tmp = secure_tempdir();
    let label = "duplicate-target";
    let (mut state, path, existing_id) = unlocked_state_with_seeded_collision_target(&tmp, label);
    let initial_count = match &state {
        AppState::Unlocked { vault, .. } => vault.iter().count(),
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        initial_count, 1,
        "fixture must seed exactly one collision-target account"
    );

    let source_path = tmp.path().join("import.txt");
    std::fs::write(
        &source_path,
        format!("otpauth://totp/{label}?secret=JBSWY3DPEHPK3PXP"),
    )
    .expect("write otpauth source file");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Import {
        path: path.clone(),
        source_path,
        format: None,
        conflict: ImportConflict::Skip,
        paladin_passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Import {
            result: Ok(ImportSuccess { report }),
        }) => {
            assert_eq!(
                report.skipped, 1,
                "Skip policy must record the colliding row under `skipped`"
            );
            assert_eq!(
                report.imported, 0,
                "Skip on a collision must not also count under `imported`"
            );
            assert_eq!(report.replaced, 0, "Skip never replaces");
            assert_eq!(report.appended, 0, "Skip never appends");
            assert!(
                report.accounts.is_empty(),
                "Skip leaves `ImportReport.accounts` empty per DESIGN §4.7"
            );
        }
        other => panic!("expected EffectResult::Import Ok with Skip counts, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Import"
    );

    let live_vault = match &state {
        AppState::Unlocked { vault, .. } => vault,
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        live_vault.iter().count(),
        initial_count,
        "Skip must not change live-vault size on a collision"
    );
    assert!(
        live_vault.iter().any(|a| a.id() == existing_id),
        "Skip must leave the existing account intact"
    );

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    assert_eq!(
        reopened.iter().count(),
        initial_count,
        "Skip must not change on-disk vault size on a collision"
    );
    assert!(
        reopened.iter().any(|a| a.id() == existing_id),
        "Skip must leave the existing account intact on disk"
    );
}

#[test]
fn execute_import_with_replace_conflict_over_colliding_account_preserves_id_and_persists() {
    let tmp = secure_tempdir();
    let label = "duplicate-target";
    let (mut state, path, existing_id) = unlocked_state_with_seeded_collision_target(&tmp, label);
    let initial_count = match &state {
        AppState::Unlocked { vault, .. } => vault.iter().count(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    let source_path = tmp.path().join("import.txt");
    std::fs::write(
        &source_path,
        format!("otpauth://totp/{label}?secret=JBSWY3DPEHPK3PXP"),
    )
    .expect("write otpauth source file");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Import {
        path: path.clone(),
        source_path,
        format: None,
        conflict: ImportConflict::Replace,
        paladin_passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Import {
            result: Ok(ImportSuccess { report }),
        }) => {
            assert_eq!(
                report.replaced, 1,
                "Replace policy must record the colliding row under `replaced`"
            );
            assert_eq!(
                report.imported, 0,
                "Replace on a collision must not also count under `imported`"
            );
            assert_eq!(report.skipped, 0, "Replace never skips");
            assert_eq!(report.appended, 0, "Replace never appends");
            assert_eq!(
                report.accounts,
                vec![existing_id],
                "Replace preserves the existing AccountId; ImportReport.accounts echoes it"
            );
        }
        other => panic!("expected EffectResult::Import Ok with Replace counts, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Import"
    );

    let live_vault = match &state {
        AppState::Unlocked { vault, .. } => vault,
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        live_vault.iter().count(),
        initial_count,
        "Replace keeps vault size constant on a collision"
    );
    assert!(
        live_vault.iter().any(|a| a.id() == existing_id),
        "Replace preserves the existing AccountId in the live vault"
    );

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    assert_eq!(
        reopened.iter().count(),
        initial_count,
        "Replace keeps on-disk vault size constant on a collision"
    );
    assert!(
        reopened.iter().any(|a| a.id() == existing_id),
        "Replace persists the same AccountId on disk"
    );
}

#[test]
fn execute_import_with_append_conflict_over_colliding_account_inserts_fresh_id_and_persists() {
    let tmp = secure_tempdir();
    let label = "duplicate-target";
    let (mut state, path, existing_id) = unlocked_state_with_seeded_collision_target(&tmp, label);
    let initial_count = match &state {
        AppState::Unlocked { vault, .. } => vault.iter().count(),
        other => panic!("expected Unlocked, got {other:?}"),
    };

    let source_path = tmp.path().join("import.txt");
    std::fs::write(
        &source_path,
        format!("otpauth://totp/{label}?secret=JBSWY3DPEHPK3PXP"),
    )
    .expect("write otpauth source file");

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Import {
        path: path.clone(),
        source_path,
        format: None,
        conflict: ImportConflict::Append,
        paladin_passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    let appended_id = match evt {
        AppEvent::EffectResult(EffectResult::Import {
            result: Ok(ImportSuccess { report }),
        }) => {
            assert_eq!(
                report.appended, 1,
                "Append policy must record the colliding row under `appended`"
            );
            assert_eq!(
                report.imported, 0,
                "Append on a collision must not also count under `imported`"
            );
            assert_eq!(report.skipped, 0, "Append never skips");
            assert_eq!(report.replaced, 0, "Append never replaces");
            assert_eq!(
                report.accounts.len(),
                1,
                "Append produces exactly one new entry in ImportReport.accounts"
            );
            assert_ne!(
                report.accounts[0], existing_id,
                "Append must assign a fresh AccountId distinct from the existing one"
            );
            report.accounts[0]
        }
        other => panic!("expected EffectResult::Import Ok with Append counts, got {other:?}"),
    };
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Import"
    );

    let live_vault = match &state {
        AppState::Unlocked { vault, .. } => vault,
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        live_vault.iter().count(),
        initial_count + 1,
        "Append must grow the live vault by one on a collision"
    );
    assert!(
        live_vault.iter().any(|a| a.id() == existing_id),
        "Append must leave the original account in place"
    );
    assert!(
        live_vault.iter().any(|a| a.id() == appended_id),
        "Append must add the new account into the live vault"
    );

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    assert_eq!(
        reopened.iter().count(),
        initial_count + 1,
        "Append must grow the on-disk vault by one on a collision"
    );
    assert!(
        reopened.iter().any(|a| a.id() == existing_id),
        "Append must persist the original account"
    );
    assert!(
        reopened.iter().any(|a| a.id() == appended_id),
        "Append must persist the new account"
    );
}

#[cfg(feature = "test-hooks")]
mod import_save_not_committed {
    //! Effect-executor coverage for the "`save_not_committed` restores
    //! the core snapshot" bullet in `docs/IMPLEMENTATION_PLAN_03_TUI.md` >
    //! "Import modal". Gated behind the `test-hooks` cargo feature so
    //! the `PALADIN_FAULT_INJECT=pre_commit` hook is compiled into
    //! `paladin-core::storage::fault`. The process-wide env var
    //! serializes through a local mutex so concurrent tests in the
    //! `cargo test` thread pool don't trip each other.
    use super::*;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const ENV: &str = "PALADIN_FAULT_INJECT";

    fn with_pre_commit_fault<R>(f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::set_var(ENV, "pre_commit");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        std::env::remove_var(ENV);
        match result {
            Ok(v) => v,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    #[test]
    fn execute_import_with_save_not_committed_failure_rolls_back_live_vault_to_pre_attempt_snapshot(
    ) {
        // Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Import modal" >
        //   "A `save_not_committed` failure restores the core snapshot
        //    so `Vault::iter()` matches its pre-attempt state."
        //
        // `Vault::mutate_and_save` calls the mutator (here:
        // `Vault::import_accounts`) against the live vault, then attempts
        // to commit through `Store::save`. The fault hook fires at the
        // pre-rename injection point so the surrounding save site bails
        // out with `save_not_committed { committed: false, backup_path:
        // None }`. `mutate_and_save` restores the pre-mutation snapshot
        // in place so the live vault matches the (untouched) on-disk
        // state. The executor reports the error through
        // `EffectResult::Import { Err(ImportFailure(...)) }`.
        let tmp = secure_tempdir();
        let path = tmp.path().join("vault.bin");
        create_plaintext_vault(&path);

        let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
        let initial_count = vault.iter().count();
        let initial_ids: Vec<AccountId> = vault.iter().map(paladin_core::Account::id).collect();
        let mut state = AppState::Unlocked {
            path: path.clone(),
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
        };

        let source_path = tmp.path().join("import.txt");
        std::fs::write(
            &source_path,
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .expect("write otpauth source file");

        let (tx, rx) = mpsc::channel::<AppEvent>();
        let effect = Effect::Import {
            path: path.clone(),
            source_path: source_path.clone(),
            format: None,
            conflict: ImportConflict::Skip,
            paladin_passphrase: None,
        };
        let outcome = with_pre_commit_fault(|| {
            execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            )
        });

        assert_eq!(outcome, EffectOutcome::Continue);
        let evt = rx.try_recv().expect("an AppEvent should be sent");
        match evt {
            AppEvent::EffectResult(EffectResult::Import {
                result: Err(ImportFailure(err)),
            }) => match err {
                PaladinError::SaveNotCommitted {
                    committed,
                    backup_path,
                } => {
                    assert!(!committed, "pre-commit fault must report committed=false");
                    assert!(
                        backup_path.is_none(),
                        "regular save sites must not claim a .bak rotation"
                    );
                }
                other => panic!("expected SaveNotCommitted, got {other:?}"),
            },
            other => panic!("expected EffectResult::Import Err, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "executor must emit exactly one AppEvent per Effect::Import"
        );

        // Live vault rolled back to the pre-attempt snapshot.
        match &state {
            AppState::Unlocked { vault, .. } => {
                assert_eq!(
                    vault.iter().count(),
                    initial_count,
                    "save_not_committed must restore the in-memory snapshot"
                );
                let post_ids: Vec<AccountId> =
                    vault.iter().map(paladin_core::Account::id).collect();
                assert_eq!(
                    post_ids, initial_ids,
                    "post-rollback iteration order must match the pre-attempt snapshot"
                );
            }
            other => panic!("expected Unlocked, got {other:?}"),
        }

        // On-disk vault is untouched (no tmpfile was renamed in).
        let (reopened, _store) =
            Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
        assert_eq!(
            reopened.iter().count(),
            initial_count,
            "save_not_committed must leave the on-disk vault untouched"
        );
    }
}

// ---------------------------------------------------------------------------
// Effect::Export — plaintext format routes through
// `paladin_core::export::otpauth_list` and persists via
// `paladin_core::write_secret_file_atomic`.
//
// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests" > "Export modal": *"Plaintext
// format selector routes to `paladin_core::export::otpauth_list`"* and
// *"Output is written through `paladin_core::write_secret_file_atomic`
// with mode `0600`"*. The executor must render the live vault through
// `core_export::otpauth_list`, hand the bytes to `write_secret_file_atomic`,
// and post back `EffectResult::Export { result: Ok(()) }`. The vault
// state (in-memory and on disk) must be unchanged — Export does not
// mutate the vault per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors" >
// Export: *"Export does not mutate the vault, so there is no rollback
// path."*
// ---------------------------------------------------------------------------

#[test]
fn execute_export_with_plaintext_format_routes_through_otpauth_list_and_writes_via_write_secret_file_atomic(
) {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);

    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    add_totp_account(&mut vault, &store, "github");
    add_totp_account(&mut vault, &store, "azure");

    let expected_bytes = core_export::otpauth_list(&vault).into_bytes();
    let initial_accounts: Vec<AccountId> = vault.iter().map(paladin_core::Account::id).collect();

    let mut state = AppState::Unlocked {
        path: path.clone(),
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
    };

    let target_path = tmp.path().join("export.json");
    assert!(
        !target_path.exists(),
        "target path must not exist before the executor writes it"
    );

    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Export {
        path: path.clone(),
        target_path: target_path.clone(),
        format: ExportFormat::Plaintext,
        passphrase: None,
    };
    let outcome = execute(
        effect,
        &mut state,
        &tx,
        &mut paladin_tui::clipboard::ClipboardSession::new(),
    );
    assert_eq!(outcome, EffectOutcome::Continue);

    let evt = rx.try_recv().expect("an AppEvent should be sent");
    match evt {
        AppEvent::EffectResult(EffectResult::Export { result: Ok(()) }) => {}
        other => panic!("expected EffectResult::Export Ok, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Export"
    );

    // The file on disk must match `core_export::otpauth_list` byte-for-byte:
    // this pins down the routing axis — that plaintext export goes through
    // `otpauth_list`, not through any other serializer.
    let written = std::fs::read(&target_path).expect("read written export");
    assert_eq!(
        written, expected_bytes,
        "plaintext export must contain exactly the bytes returned by core_export::otpauth_list"
    );

    // `write_secret_file_atomic` enforces mode `0600` on the final file
    // per `docs/DESIGN.md` §4.2 / §4.6 (mirrors the vault-file permission rule).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target_path)
            .expect("stat export file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "plaintext export file must be written with mode 0600 via write_secret_file_atomic"
        );
    }

    // Export must not mutate the vault — in-memory iteration order /
    // count is unchanged, and the on-disk vault file is byte-identical.
    let vault = match &state {
        AppState::Unlocked { vault, .. } => vault,
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let after_accounts: Vec<AccountId> = vault.iter().map(paladin_core::Account::id).collect();
    assert_eq!(
        after_accounts, initial_accounts,
        "Export must leave the in-memory vault iteration order unchanged"
    );

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    let reopened_accounts: Vec<AccountId> =
        reopened.iter().map(paladin_core::Account::id).collect();
    assert_eq!(
        reopened_accounts, initial_accounts,
        "Export must leave the on-disk vault untouched (no Vault::save was issued)"
    );
}

// ---------------------------------------------------------------------------
// Effect::Export — encrypted format routes through
// `paladin_core::export::encrypted` and persists via
// `paladin_core::write_secret_file_atomic`.
//
// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests" > "Export modal":
// *"Encrypted format selector routes to `paladin_core::export::encrypted`."*
// The executor must render the live vault through `core_export::encrypted`
// with `EncryptionOptions::new(secret)` (default §4.4 Argon2 params per
// the plan's "Encrypted-bundle Export" / `EncryptionOptions::new` rule),
// hand the bundle bytes to `write_secret_file_atomic`, and post back
// `EffectResult::Export { result: Ok(()) }`. The vault state (in-memory
// and on disk) must be unchanged — Export does not mutate the vault.
//
// Routing axis: byte-equality is not available because each
// `export::encrypted` call mints a fresh salt + nonce. Instead we pin
// routing by (a) magic + header bytes that only `export::encrypted`
// emits (`PALADIN\0`, format_ver=1, mode=1) and (b) a successful
// round-trip through `import::paladin` with the same passphrase that
// recovers the original account set. That combination is impossible
// to satisfy from `otpauth_list` or any other writer.
// ---------------------------------------------------------------------------

#[test]
fn execute_export_with_encrypted_format_routes_through_export_encrypted_and_writes_via_write_secret_file_atomic(
) {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);

    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let _ = add_totp_account(&mut vault, &store, "github");
    let _ = add_totp_account(&mut vault, &store, "azure");

    let initial_accounts: Vec<AccountId> = vault.iter().map(paladin_core::Account::id).collect();
    let initial_labels: Vec<String> = vault.iter().map(|a| a.label().to_string()).collect();

    let mut state = AppState::Unlocked {
        path: path.clone(),
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
    };

    let target_path = tmp.path().join("export.paladin");
    assert!(!target_path.exists(), "target must not pre-exist");

    let bundle_passphrase = "bundle-hunter2";
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Export {
        path: path.clone(),
        target_path: target_path.clone(),
        format: ExportFormat::Encrypted,
        passphrase: Some(SecretString::from(bundle_passphrase.to_string())),
    };
    assert_eq!(
        execute(
            effect,
            &mut state,
            &tx,
            &mut paladin_tui::clipboard::ClipboardSession::new()
        ),
        EffectOutcome::Continue
    );

    match rx.try_recv().expect("an AppEvent should be sent") {
        AppEvent::EffectResult(EffectResult::Export { result: Ok(()) }) => {}
        other => panic!("expected EffectResult::Export Ok, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "executor must emit exactly one AppEvent per Effect::Export"
    );

    // Header-routing axis: §4.3 magic + format_ver=1 + mode=1 are emitted
    // only by `export::encrypted`. `otpauth_list` writes JSON, which
    // could never satisfy this header check.
    let written = std::fs::read(&target_path).expect("read written export");
    assert!(
        written.starts_with(b"PALADIN\0"),
        "encrypted export must begin with the §4.3 PALADIN magic; got first 16 = {:?}",
        &written[..written.len().min(16)]
    );
    assert_eq!(written[8], 1, "header byte 8 must be format_ver = 1");
    assert_eq!(written[9], 1, "header byte 9 must be mode = 1 (encrypted)");

    // Round-trip-routing axis: `import::paladin` with the same passphrase
    // must recover exactly the source vault's labels in order. Any other
    // routing would either fail to decrypt or yield a different set.
    let imported =
        paladin_core::import::paladin(&written, SecretString::from(bundle_passphrase.to_string()))
            .expect("encrypted export must round-trip through import::paladin");
    let imported_labels: Vec<String> = imported
        .iter()
        .map(|v| v.account.label().to_string())
        .collect();
    assert_eq!(
        imported_labels, initial_labels,
        "encrypted bundle must round-trip the source vault's labels in order"
    );

    // Write-path-routing axis: mode `0600` is enforced only by
    // `write_secret_file_atomic` (per `docs/DESIGN.md` §4.2 / §4.6); a bare
    // `fs::write` would inherit the umask instead.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target_path)
            .expect("stat export file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "encrypted export file must land at 0600");
    }

    // Non-mutation invariant: Export issues no `Vault::save`, so both
    // the in-memory iteration order and the on-disk source vault must
    // be byte-identical to the pre-export snapshot.
    let vault = match &state {
        AppState::Unlocked { vault, .. } => vault,
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let after_accounts: Vec<AccountId> = vault.iter().map(paladin_core::Account::id).collect();
    assert_eq!(
        after_accounts, initial_accounts,
        "in-memory vault unchanged"
    );

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    let reopened_accounts: Vec<AccountId> =
        reopened.iter().map(paladin_core::Account::id).collect();
    assert_eq!(
        reopened_accounts, initial_accounts,
        "on-disk vault unchanged"
    );
}

// ---------------------------------------------------------------------------
// Effect::AddFromClipboardQr — live clipboard image + QR decode + import
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Implementation checklist:
//   * "Implement clipboard wrapper (arboard reads/writes), QR image
//     import from clipboard bytes, ...")
//
// The executor:
//   1. Reads the live clipboard image via `paladin_tui::clipboard::read_image`.
//      `ImageReadError::NoImage` → `QrImportFailure::NoClipboardImage`;
//      `ImageReadError::DecodeFailure` → `QrImportFailure::ImageDecodeFailure`.
//   2. Calls `paladin_core::import::qr_image_bytes(width, height, &rgba, now)`
//      which re-validates dimensions, rejects oversized buffers
//      (`image_too_large`), and decodes every QR as `otpauth://`.
//   3. Wraps `Vault::import_accounts(_, ImportConflict::Skip, now)` in
//      `Vault::mutate_and_save`; pre-commit save failures roll back
//      and `save_durability_unconfirmed` commits in-memory.
//   4. Posts the outcome through `EffectResult::QrImport { result: ... }`.
//
// Tests use the `paladin-tui/test-hooks` clipboard DRYRUN seam to feed
// in synthetic clipboard images without a system clipboard server.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-hooks")]
mod add_from_clipboard_qr {
    use super::*;

    use image::Luma;
    use qrcode::QrCode;

    use paladin_core::ErrorKind;
    use paladin_tui::app::event::{QrImportFailure, QrImportSuccess};
    use paladin_tui::clipboard::{
        clear_test_clipboard_image, seed_test_clipboard_image, test_clipboard_lock,
    };

    /// Render `payload` as a QR code into an RGBA8 buffer of
    /// `(width, height, rgba)`. Mirrors `paladin-core`'s
    /// `tests/import_qr.rs::make_qr_rgba` so the two suites render QRs
    /// through the same encoder.
    fn make_qr_rgba(payload: &str) -> (u32, u32, Vec<u8>) {
        let code = QrCode::new(payload.as_bytes()).expect("encode QR");
        let luma = code
            .render::<Luma<u8>>()
            .min_dimensions(160, 160)
            .quiet_zone(true)
            .build();
        let (w, h) = luma.dimensions();
        let raw = luma.into_raw();
        let mut rgba = Vec::with_capacity(raw.len() * 4);
        for v in raw {
            rgba.extend_from_slice(&[v, v, v, 0xFF]);
        }
        (w, h, rgba)
    }

    /// Run `body` with `PALADIN_CLIPBOARD_DRYRUN=mode` and the
    /// process-wide test-clipboard lock held; clear the fake image
    /// on exit so no test leaks state into the next.
    fn with_dryrun<R>(mode: &str, body: impl FnOnce() -> R) -> R {
        let _guard = test_clipboard_lock();
        std::env::set_var("PALADIN_CLIPBOARD_DRYRUN", mode);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        std::env::remove_var("PALADIN_CLIPBOARD_DRYRUN");
        clear_test_clipboard_image();
        match result {
            Ok(v) => v,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    const URI_TOTP_A: &str = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme";

    #[test]
    fn execute_add_from_clipboard_qr_with_valid_otpauth_qr_imports_and_persists_via_mutate_and_save(
    ) {
        // Happy path: clipboard holds a valid `otpauth://` QR. The
        // executor decodes via `qr_image_bytes`, commits through
        // `Vault::import_accounts(_, ImportConflict::Skip, _)` wrapped
        // in `mutate_and_save`, and posts back `EffectResult::QrImport`
        // with a `QrImportSuccess { report }` whose `imported == 1`.
        with_dryrun("1", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            create_plaintext_vault(&path);
            let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
            let initial_count = vault.iter().count();
            let mut state = AppState::Unlocked {
                path: path.clone(),
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
            };

            let (w, h, rgba) = make_qr_rgba(URI_TOTP_A);
            seed_test_clipboard_image(w, h, rgba);

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let outcome = execute(
                Effect::AddFromClipboardQr { path: path.clone() },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::QrImport {
                    result: Ok(QrImportSuccess { report }),
                }) => {
                    assert_eq!(
                        report.imported, 1,
                        "single-QR otpauth payload must produce exactly one imported account"
                    );
                    assert_eq!(report.skipped, 0, "no skip path on an empty starting vault");
                    assert_eq!(report.replaced, 0, "Skip policy never replaces");
                    assert_eq!(report.appended, 0, "Skip policy never appends");
                }
                other => panic!("expected EffectResult::QrImport Ok, got {other:?}"),
            }
            assert!(
                rx.try_recv().is_err(),
                "executor must emit exactly one AppEvent per Effect::AddFromClipboardQr"
            );

            // Live in-memory vault grew by one.
            let vault = match state {
                AppState::Unlocked { vault, .. } => vault,
                other => panic!("expected Unlocked, got {other:?}"),
            };
            assert_eq!(
                vault.iter().count(),
                initial_count + 1,
                "successful QR import must grow the live vault"
            );

            // On-disk primary committed (mutate_and_save persists the merge).
            let (reopened, _store) =
                Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
            assert_eq!(
                reopened.iter().count(),
                initial_count + 1,
                "successful QR import must commit to the on-disk primary"
            );
        });
    }

    #[test]
    fn execute_add_from_clipboard_qr_with_no_image_on_clipboard_sends_no_clipboard_image_failure() {
        // Clipboard has no image (text-only target, or platform reports
        // `ContentNotAvailable`). The executor must surface the inline
        // `QrImportFailure::NoClipboardImage` variant — the reducer
        // renders a distinct user-facing wording for this case.
        with_dryrun("1", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            create_plaintext_vault(&path);
            let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
            let initial_count = vault.iter().count();
            let mut state = AppState::Unlocked {
                path: path.clone(),
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
            };

            clear_test_clipboard_image();

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let outcome = execute(
                Effect::AddFromClipboardQr { path: path.clone() },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::QrImport {
                    result: Err(QrImportFailure::NoClipboardImage),
                }) => {}
                other => {
                    panic!("expected EffectResult::QrImport Err(NoClipboardImage), got {other:?}")
                }
            }

            // Vault untouched on both sides.
            let vault = match state {
                AppState::Unlocked { vault, .. } => vault,
                other => panic!("expected Unlocked, got {other:?}"),
            };
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "no-image failure must leave the live vault untouched"
            );
            let (reopened, _store) =
                Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
            assert_eq!(
                reopened.iter().count(),
                initial_count,
                "no-image failure must leave the on-disk vault untouched"
            );
        });
    }

    #[test]
    fn execute_add_from_clipboard_qr_with_decode_failure_sends_image_decode_failure() {
        // `arboard` reported an image but the bytes could not be
        // converted to a usable raster (or the backend itself failed
        // to init). Modeled in tests through `PALADIN_CLIPBOARD_DRYRUN=fail`.
        with_dryrun("fail", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            create_plaintext_vault(&path);
            let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
            let initial_count = vault.iter().count();
            let mut state = AppState::Unlocked {
                path: path.clone(),
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
            };

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let outcome = execute(
                Effect::AddFromClipboardQr { path: path.clone() },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::QrImport {
                    result: Err(QrImportFailure::ImageDecodeFailure),
                }) => {}
                other => {
                    panic!("expected EffectResult::QrImport Err(ImageDecodeFailure), got {other:?}")
                }
            }

            let vault = match state {
                AppState::Unlocked { vault, .. } => vault,
                other => panic!("expected Unlocked, got {other:?}"),
            };
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "decode-failure must leave the live vault untouched"
            );
        });
    }

    #[test]
    fn execute_add_from_clipboard_qr_with_image_containing_no_qrs_sends_no_entries_to_import_failure(
    ) {
        // Clipboard holds an image but the QR decoder finds no codes.
        // `qr_image_bytes` rejects with `PaladinError::NoEntriesToImport`
        // per `docs/DESIGN.md` §4.6, which the executor wraps in
        // `QrImportFailure::Import(_)` for the reducer to render through
        // `render_error_message`.
        with_dryrun("1", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            create_plaintext_vault(&path);
            let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
            let initial_count = vault.iter().count();
            let mut state = AppState::Unlocked {
                path: path.clone(),
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
            };

            // Solid-white 32x32 RGBA8 buffer — no QR code present, so
            // `read_qr_image_bytes` returns an empty vec which
            // `qr_image_bytes` converts to NoEntriesToImport.
            let blank: Vec<u8> = std::iter::repeat_n([0xFFu8, 0xFF, 0xFF, 0xFF], 32 * 32)
                .flatten()
                .collect();
            seed_test_clipboard_image(32, 32, blank);

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let outcome = execute(
                Effect::AddFromClipboardQr { path: path.clone() },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::QrImport {
                    result: Err(QrImportFailure::Import(err)),
                }) => {
                    assert_eq!(
                        err.kind(),
                        ErrorKind::NoEntriesToImport,
                        "blank image must surface no_entries_to_import"
                    );
                }
                other => panic!(
                    "expected EffectResult::QrImport Err(Import(NoEntriesToImport)), got {other:?}"
                ),
            }

            let vault = match state {
                AppState::Unlocked { vault, .. } => vault,
                other => panic!("expected Unlocked, got {other:?}"),
            };
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "no-QRs-decoded failure must leave the live vault untouched"
            );
        });
    }

    #[test]
    fn execute_add_from_clipboard_qr_with_oversized_rgba_buffer_sends_validation_image_too_large() {
        // `qr_image_bytes` rejects RGBA buffers above `QR_RGBA_MAX_BYTES`
        // (64 MiB) with `validation_error { field: "qr_image",
        // reason: "image_too_large" }`. Use 4097x4097 → ~67.1 MiB to
        // trip the guard. The executor pre-screens dimensions so the
        // backing buffer length never has to match — a zero-byte rgba
        // is passed for memory-frugal CI.
        with_dryrun("1", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            create_plaintext_vault(&path);
            let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
            let initial_count = vault.iter().count();
            let mut state = AppState::Unlocked {
                path: path.clone(),
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
            };

            // Dimensions whose `w*h*4` exceeds `QR_RGBA_MAX_BYTES`
            // (64 MiB). 5000*5000*4 = 100 MB > 64 MiB. Use a 0-byte
            // payload — the executor's pre-screen catches the
            // dimension-derived overflow before reaching
            // `qr_image_bytes`'s buffer-length check.
            seed_test_clipboard_image(5000, 5000, Vec::new());

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let outcome = execute(
                Effect::AddFromClipboardQr { path: path.clone() },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::QrImport {
                    result: Err(QrImportFailure::Import(err)),
                }) => match err.kind() {
                    ErrorKind::ValidationError => {
                        // Wording is owned by the core; the executor
                        // only needs to confirm the routed `kind`.
                    }
                    other => {
                        panic!("expected ValidationError (image_too_large), got kind={other:?}")
                    }
                },
                other => panic!(
                    "expected EffectResult::QrImport Err(Import(ValidationError)), got {other:?}"
                ),
            }

            let vault = match state {
                AppState::Unlocked { vault, .. } => vault,
                other => panic!("expected Unlocked, got {other:?}"),
            };
            assert_eq!(
                vault.iter().count(),
                initial_count,
                "oversized-buffer failure must leave the live vault untouched"
            );
        });
    }

    #[test]
    fn execute_add_from_clipboard_qr_with_mismatched_path_is_silently_dropped() {
        // Stale effect emitted before a vault switch must drop without
        // touching the clipboard or sending an AppEvent — mirrors the
        // `execute_import_with_mismatched_path_is_silently_dropped`
        // contract.
        with_dryrun("1", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            create_plaintext_vault(&path);
            let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
            let mut state = AppState::Unlocked {
                path: path.clone(),
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
            };

            let (w, h, rgba) = make_qr_rgba(URI_TOTP_A);
            seed_test_clipboard_image(w, h, rgba);

            let other_path = tmp.path().join("other.bin");
            let (tx, rx) = mpsc::channel::<AppEvent>();
            let outcome = execute(
                Effect::AddFromClipboardQr { path: other_path },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "mismatched-path effect must drop without emitting an AppEvent"
            );
        });
    }

    #[test]
    fn execute_add_from_clipboard_qr_on_locked_state_is_silently_dropped() {
        // Same drop rule on a non-Unlocked state — the reducer would
        // discard a corresponding `EffectResult::QrImport` anyway, and
        // posting back would just synthesize a mutation attempt
        // against unrelated state.
        with_dryrun("1", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            create_plaintext_vault(&path);

            let mut state = AppState::Locked {
                path: path.clone(),
                pending_clipboard_clear: None,
            };

            let (w, h, rgba) = make_qr_rgba(URI_TOTP_A);
            seed_test_clipboard_image(w, h, rgba);

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let outcome = execute(
                Effect::AddFromClipboardQr { path: path.clone() },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "Locked-state effect must drop without emitting an AppEvent"
            );
        });
    }

    #[test]
    fn execute_add_from_clipboard_qr_with_skip_conflict_over_existing_account_records_skip() {
        // Re-importing a QR for an account that already exists with
        // matching `(secret, issuer, label)` produces 0 imports +
        // 1 skip under `ImportConflict::Skip`. Asserts the executor
        // wires `Vault::import_accounts` with the Skip policy as the
        // event docstring requires.
        with_dryrun("1", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            create_plaintext_vault(&path);
            let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
            let mut state = AppState::Unlocked {
                path: path.clone(),
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
            };

            let (w, h, rgba) = make_qr_rgba(URI_TOTP_A);
            seed_test_clipboard_image(w, h, rgba.clone());

            // First import: lands.
            let (tx, rx) = mpsc::channel::<AppEvent>();
            let _ = execute(
                Effect::AddFromClipboardQr { path: path.clone() },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            let evt = rx.try_recv().expect("first AppEvent");
            match evt {
                AppEvent::EffectResult(EffectResult::QrImport {
                    result: Ok(QrImportSuccess { report }),
                }) => assert_eq!(report.imported, 1, "first import must add the account"),
                other => panic!("expected Ok first time, got {other:?}"),
            }
            let count_after_first = match &state {
                AppState::Unlocked { vault, .. } => vault.iter().count(),
                other => panic!("expected Unlocked, got {other:?}"),
            };

            // Second import: same QR, same `(secret, issuer, label)` —
            // Skip policy records 1 skip and 0 imports.
            seed_test_clipboard_image(w, h, rgba);
            let (tx2, rx2) = mpsc::channel::<AppEvent>();
            let _ = execute(
                Effect::AddFromClipboardQr { path: path.clone() },
                &mut state,
                &tx2,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            let evt2 = rx2.try_recv().expect("second AppEvent");
            match evt2 {
                AppEvent::EffectResult(EffectResult::QrImport {
                    result: Ok(QrImportSuccess { report }),
                }) => {
                    assert_eq!(
                        report.imported, 0,
                        "second import with Skip conflict must not insert"
                    );
                    assert_eq!(
                        report.skipped, 1,
                        "second import with Skip conflict must record one skip"
                    );
                    assert_eq!(report.replaced, 0, "Skip policy does not replace");
                    assert_eq!(report.appended, 0, "Skip policy does not append");
                }
                other => panic!("expected Ok with skip on second import, got {other:?}"),
            }
            let count_after_second = match &state {
                AppState::Unlocked { vault, .. } => vault.iter().count(),
                other => panic!("expected Unlocked, got {other:?}"),
            };
            assert_eq!(
                count_after_second, count_after_first,
                "Skip conflict must not grow the live vault"
            );
        });
    }
}

// ---------------------------------------------------------------------------
// Effect::CopyCode
//
// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings":
// *"`Enter` — Copy selected code (TOTP: current; HOTP: visible only)."*
//
// The executor:
//   1. Confirms the live `AppState::Unlocked` still points at the same
//      vault path the effect carries (silent drop on mismatch / non-
//      Unlocked, mirroring `Effect::Remove` / `Effect::Rename`).
//   2. Resolves the code bytes — TOTP via `Vault::totp_code(id, now)`
//      on the live wall clock; HOTP via the `hotp_reveal` slot
//      (defensively re-gated on `account_id` match).
//   3. Writes via `paladin_tui::clipboard::write_text` and samples
//      `Instant::now()` after the write returns.
//   4. Posts back `EffectResult::CopyCode { account_id, result,
//      completed_at }` so the reducer can route the Ok path through
//      `ClipboardClearPolicy::schedule` or surface
//      `clipboard_write_failed` on `Err(())`.
//
// Tests use the `paladin-tui/test-hooks` clipboard DRYRUN seam so
// the suite runs without a system clipboard server.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-hooks")]
mod copy_code {
    use super::*;

    use paladin_core::{hotp_reveal_deadline, IconHintInput};
    use paladin_tui::app::state::HotpReveal;
    use paladin_tui::clipboard::{read_test_clipboard, seed_test_clipboard, test_clipboard_lock};

    /// Run `body` with `PALADIN_CLIPBOARD_DRYRUN=mode` and the
    /// process-wide test-clipboard lock held; clear the fake text
    /// clipboard on exit so no test leaks state into the next.
    fn with_dryrun<R>(mode: &str, body: impl FnOnce() -> R) -> R {
        let _guard = test_clipboard_lock();
        std::env::set_var("PALADIN_CLIPBOARD_DRYRUN", mode);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        std::env::remove_var("PALADIN_CLIPBOARD_DRYRUN");
        seed_test_clipboard("");
        match result {
            Ok(v) => v,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn add_hotp_account(vault: &mut Vault, store: &Store, label: &str) -> AccountId {
        let input = AccountInput {
            label: label.to_string(),
            issuer: None,
            secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: AccountKindInput::Hotp,
            period_secs: None,
            counter: Some(0),
            icon_hint: IconHintInput::Default,
        };
        let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
        let id = vault.add(validated.account);
        vault.save(store).expect("commit added hotp account");
        id
    }

    fn unlocked_with_hotp_and_reveal(
        path: &Path,
        label: &str,
        visible_code: &str,
    ) -> (AppState, AccountId) {
        let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create vault");
        vault.save(&store).expect("commit empty vault");
        let id = add_hotp_account(&mut vault, &store, label);
        let reveal = HotpReveal {
            account_id: id,
            counter_used: 0,
            code: SecretString::from(visible_code.to_string()),
            deadline: hotp_reveal_deadline(Instant::now()),
        };
        let state = AppState::Unlocked {
            path: path.to_path_buf(),
            vault,
            store,
            search_query: String::new(),
            idle_deadline: None,
            pending_clipboard_clear: None,
            hotp_reveal: Some(reveal),
            modal: None,
            selected: Some(id),
            pending_chord_leader: None,
            viewport_height: 0,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        };
        (state, id)
    }

    fn unlocked_with_hotp_no_reveal(path: &Path, label: &str) -> (AppState, AccountId) {
        let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create vault");
        vault.save(&store).expect("commit empty vault");
        let id = add_hotp_account(&mut vault, &store, label);
        let state = AppState::Unlocked {
            path: path.to_path_buf(),
            vault,
            store,
            search_query: String::new(),
            idle_deadline: None,
            pending_clipboard_clear: None,
            hotp_reveal: None,
            modal: None,
            selected: Some(id),
            pending_chord_leader: None,
            viewport_height: 0,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        };
        (state, id)
    }

    /// Happy path: `Effect::CopyCode` against an `Unlocked` TOTP
    /// account writes a freshly generated code to the clipboard and
    /// posts `EffectResult::CopyCode { Ok(value) }` whose `value`
    /// matches what landed on the clipboard. `completed_at` is sampled
    /// inside `execute()`'s window.
    #[test]
    fn execute_copy_code_totp_writes_code_to_clipboard_and_sends_ok() {
        with_dryrun("1", || {
            seed_test_clipboard("");
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, id) = unlocked_with_one_totp(&path, "github");

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyCode {
                path: path.clone(),
                account_id: id,
            };

            let before = Instant::now();
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            let after = Instant::now();
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::CopyCode {
                    account_id,
                    result: Ok(value),
                    completed_at,
                }) => {
                    assert_eq!(account_id, id, "result must carry the source account_id");
                    let code_str = std::str::from_utf8(&value).expect("OTP digits are ASCII");
                    assert_eq!(code_str.len(), 6, "default TOTP account is 6 digits");
                    assert!(
                        code_str.chars().all(|c| c.is_ascii_digit()),
                        "TOTP code must be ASCII digits, got {code_str:?}"
                    );
                    assert_eq!(
                        read_test_clipboard().as_bytes(),
                        value.as_slice(),
                        "clipboard must hold exactly the code bytes the executor wrote back"
                    );
                    assert!(
                        completed_at >= before && completed_at <= after,
                        "completed_at must be sampled inside [before, after] of execute()"
                    );
                }
                other => panic!("expected EffectResult::CopyCode {{ Ok }}, got {other:?}"),
            }
            assert!(
                rx.try_recv().is_err(),
                "executor must emit exactly one AppEvent per Effect::CopyCode"
            );
        });
    }

    /// HOTP happy path: with a `hotp_reveal` slot matching the target
    /// account, the executor reads the visible code straight out of
    /// the slot's `SecretString` and writes it to the clipboard.
    /// Mirrors the reducer-side "TOTP: current; HOTP: visible only"
    /// gating.
    #[test]
    fn execute_copy_code_hotp_with_matching_reveal_writes_visible_code_and_sends_ok() {
        with_dryrun("1", || {
            seed_test_clipboard("");
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, id) = unlocked_with_hotp_and_reveal(&path, "github", "123456");

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyCode {
                path: path.clone(),
                account_id: id,
            };
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::CopyCode {
                    account_id,
                    result: Ok(value),
                    ..
                }) => {
                    assert_eq!(account_id, id);
                    assert_eq!(
                        value.as_slice(),
                        b"123456",
                        "HOTP code must come from the live `hotp_reveal` slot, not a fresh generation"
                    );
                    assert_eq!(
                        read_test_clipboard(),
                        "123456",
                        "clipboard must hold the visible HOTP code"
                    );
                }
                other => panic!(
                    "expected EffectResult::CopyCode {{ Ok }} for HOTP visible-reveal, got {other:?}"
                ),
            }
        });
    }

    /// Clipboard write failure (`PALADIN_CLIPBOARD_DRYRUN=fail`) maps
    /// to `EffectResult::CopyCode { Err(()) }` so the reducer can
    /// surface the `clipboard_write_failed` status-line error per
    /// "Effect errors": *"Copy: show a status-line error if clipboard
    /// write fails; do not schedule auto-clear."*
    #[test]
    fn execute_copy_code_clipboard_write_failure_sends_err() {
        with_dryrun("fail", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, id) = unlocked_with_one_totp(&path, "github");

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyCode {
                path: path.clone(),
                account_id: id,
            };
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::CopyCode {
                    account_id,
                    result: Err(()),
                    ..
                }) => assert_eq!(account_id, id),
                other => panic!(
                    "expected EffectResult::CopyCode {{ Err }} under DRYRUN=fail, got {other:?}"
                ),
            }
        });
    }

    /// Stale effect aimed at a path the live state no longer owns
    /// must not touch the clipboard and must not emit a result —
    /// follows the `Effect::Remove` / `Effect::Rename` silent-drop
    /// precedent.
    #[test]
    fn execute_copy_code_with_mismatched_path_is_silently_dropped() {
        with_dryrun("1", || {
            seed_test_clipboard("PRIOR");
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, id) = unlocked_with_one_totp(&path, "github");

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyCode {
                path: PathBuf::from("/some/other/vault.bin"),
                account_id: id,
            };
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "path-mismatched Effect::CopyCode must not emit an AppEvent"
            );
            assert_eq!(
                read_test_clipboard(),
                "PRIOR",
                "path-mismatched Effect::CopyCode must not touch the clipboard"
            );
        });
    }

    /// Stale effect arriving while the app is no longer `Unlocked`
    /// (auto-lock fired, quit in flight, …) is silently dropped.
    #[test]
    fn execute_copy_code_on_non_unlocked_state_is_silently_dropped() {
        with_dryrun("1", || {
            seed_test_clipboard("PRIOR");
            let mut state = dummy_state();

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyCode {
                path: PathBuf::from("/dev/null/dummy-vault.bin"),
                account_id: AccountId::new(),
            };
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "non-Unlocked Effect::CopyCode must not emit an AppEvent"
            );
            assert_eq!(
                read_test_clipboard(),
                "PRIOR",
                "non-Unlocked Effect::CopyCode must not touch the clipboard"
            );
        });
    }

    /// Defensive: HOTP target with no matching `hotp_reveal` slot is a
    /// silent drop. The reducer-side gating means we never reach this
    /// path in normal flow; surfacing `clipboard_write_failed` for a
    /// reducer-side bug would be misleading.
    #[test]
    fn execute_copy_code_hotp_without_matching_reveal_is_silently_dropped() {
        with_dryrun("1", || {
            seed_test_clipboard("PRIOR");
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, id) = unlocked_with_hotp_no_reveal(&path, "github");

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyCode {
                path: path.clone(),
                account_id: id,
            };
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "HOTP without matching reveal must be a silent drop"
            );
            assert_eq!(
                read_test_clipboard(),
                "PRIOR",
                "HOTP without matching reveal must not touch the clipboard"
            );
        });
    }

    /// Defensive: a `CopyCode` for an `account_id` that is no longer
    /// in the live vault (a reducer-side bug — the reducer captures
    /// the id from the live `selected` slot which is kept in sync) is
    /// a silent drop.
    #[test]
    fn execute_copy_code_with_unknown_account_id_is_silently_dropped() {
        with_dryrun("1", || {
            seed_test_clipboard("PRIOR");
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, _id) = unlocked_with_one_totp(&path, "github");

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyCode {
                path: path.clone(),
                account_id: AccountId::new(),
            };
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "unknown account_id must be a silent drop"
            );
            assert_eq!(
                read_test_clipboard(),
                "PRIOR",
                "unknown account_id must not touch the clipboard"
            );
        });
    }

    /// Dropped receiver (run loop tearing down between effect emit and
    /// dispatch) must not panic the executor. Mirrors
    /// `execute_rename_with_dropped_receiver_does_not_panic`.
    #[test]
    fn execute_copy_code_with_dropped_receiver_does_not_panic() {
        with_dryrun("1", || {
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, id) = unlocked_with_one_totp(&path, "github");

            let (tx, rx) = mpsc::channel::<AppEvent>();
            drop(rx);
            let effect = Effect::CopyCode {
                path: path.clone(),
                account_id: id,
            };
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
        });
    }

    /// Happy path: `Effect::CopyNextCode` against an `Unlocked` TOTP
    /// account writes the *next* 30-second-window code to the
    /// clipboard, posts `EffectResult::CopyNextCode { Ok(value),
    /// seconds_until_valid: Some(_) }`, and the value matches what
    /// landed on the clipboard. The next-code digits must differ
    /// from the current-code digits the existing `CopyCode` arm
    /// would have produced — same selection, different window.
    #[test]
    fn execute_copy_next_code_totp_writes_next_code_and_sends_ok_with_seconds() {
        with_dryrun("1", || {
            seed_test_clipboard("");
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, id) = unlocked_with_one_totp(&path, "github");

            // Compute what the current code would be so we can prove
            // the next code is different. The `now` snapshot the
            // executor uses is `SystemTime::now()` so two
            // back-to-back calls land in the same 30 s window for a
            // 30 s period — `totp_next_code` advances the counter by
            // exactly one regardless.
            let current_code = match &state {
                AppState::Unlocked { vault, .. } => {
                    vault
                        .totp_code(id, std::time::SystemTime::now())
                        .expect("totp_code happy path")
                        .code
                }
                other => panic!("expected Unlocked, got {other:?}"),
            };

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyNextCode {
                path: path.clone(),
                account_id: id,
            };

            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);

            let evt = rx.try_recv().expect("an AppEvent should be sent");
            match evt {
                AppEvent::EffectResult(EffectResult::CopyNextCode {
                    account_id,
                    result: Ok(value),
                    completed_at: _,
                    seconds_until_valid,
                }) => {
                    assert_eq!(account_id, id, "result must carry the source account_id");
                    let next_str = std::str::from_utf8(&value).expect("OTP digits are ASCII");
                    assert_eq!(next_str.len(), 6, "default TOTP account is 6 digits");
                    assert!(
                        next_str.chars().all(|c| c.is_ascii_digit()),
                        "next code must be ASCII digits, got {next_str:?}"
                    );
                    assert_ne!(
                        next_str, current_code,
                        "next code must differ from current code (counters differ by 1)"
                    );
                    assert_eq!(
                        read_test_clipboard().as_bytes(),
                        value.as_slice(),
                        "clipboard must hold exactly the next-code bytes the executor wrote"
                    );
                    // DESIGN §6: `seconds_until_valid` is the
                    // remainder of the current window in 1..=period.
                    let secs = seconds_until_valid.expect("Ok path must carry seconds_until_valid");
                    assert!(
                        (1..=30).contains(&secs),
                        "seconds_until_valid must be in 1..=period for the default 30 s TOTP, got {secs}",
                    );
                }
                other => panic!("expected EffectResult::CopyNextCode {{ Ok }}, got {other:?}"),
            }
            assert!(
                rx.try_recv().is_err(),
                "executor must emit exactly one AppEvent per Effect::CopyNextCode"
            );
        });
    }

    /// Defensive silent drop: `Effect::CopyNextCode` aimed at an
    /// HOTP account would only arrive via a reducer-side bug
    /// (the §6 reducer gate rejects HOTP with a status-line message
    /// before emitting). The executor must not touch the clipboard
    /// and must not send a result envelope — surfacing
    /// `clipboard_write_failed` for a routing bug would be
    /// misleading. Mirrors the `Effect::CopyCode` silent-drop
    /// precedent.
    #[test]
    fn execute_copy_next_code_silently_drops_on_hotp_account() {
        with_dryrun("1", || {
            seed_test_clipboard("sentinel");
            let tmp = secure_tempdir();
            let path = tmp.path().join("vault.bin");
            let (mut state, id) = unlocked_with_hotp_and_reveal(&path, "github", "123456");

            let (tx, rx) = mpsc::channel::<AppEvent>();
            let effect = Effect::CopyNextCode {
                path: path.clone(),
                account_id: id,
            };
            let outcome = execute(
                effect,
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "HOTP CopyNextCode must be silent-dropped: no EffectResult"
            );
            assert_eq!(
                read_test_clipboard(),
                "sentinel",
                "HOTP CopyNextCode must not write to the clipboard"
            );
        });
    }
}

// ---------------------------------------------------------------------------
// Effect::QrExport — QR Export modal Save-as-PNG / Save-as-SVG executor
//
// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
// QR Export and `docs/DESIGN.md` §4.6 / §6:
//   1. Build an `Unlocked` state with the target account.
//   2. Dispatch `Effect::QrExport { format, .. }` through `execute(...)`.
//   3. Assert `EffectResult::QrExport(Ok(target_path))` (or the right
//      `Err(PaladinError::...)`).
//   4. Read the file and assert bytes match `Vault::export_qr_{png,svg}`
//      byte-for-byte, with mode `0600` on Unix.
//
// The executor is read-only on the vault — HOTP counters / `updated_at`
// must be unchanged across modal open / close / save. The PNG /
// SVG round-trip tests use `rqrr` (added as a `dev-dependency` for
// this purpose; mirrors `paladin-core`'s `tests/export_qr.rs`).
// ---------------------------------------------------------------------------

mod qr_export {
    use super::*;

    use image::Luma;
    use paladin_core::QrRenderOptions;
    use paladin_tui::app::state::QrSaveFormat;
    use paladin_tui::prompt::PassphraseBuffer;

    /// Build an [`AppState::Unlocked`] backed by a real plaintext
    /// vault at `path` containing a single HOTP account with the
    /// given starting `counter`. Returns the state and the account's
    /// [`AccountId`] so callers can target it.
    fn unlocked_with_one_hotp(path: &Path, label: &str, counter: u64) -> (AppState, AccountId) {
        let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create vault");
        vault.save(&store).expect("commit empty vault");
        let input = AccountInput {
            label: label.to_string(),
            issuer: None,
            secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: AccountKindInput::Hotp,
            period_secs: None,
            counter: Some(counter),
            icon_hint: IconHintInput::Default,
        };
        let validated = validate_manual(input, SystemTime::now()).expect("valid HOTP manual input");
        let id = vault.add(validated.account);
        vault.save(&store).expect("commit hotp account");
        let state = AppState::Unlocked {
            path: path.to_path_buf(),
            vault,
            store,
            search_query: String::new(),
            idle_deadline: None,
            pending_clipboard_clear: None,
            hotp_reveal: None,
            modal: None,
            selected: Some(id),
            pending_chord_leader: None,
            viewport_height: 0,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        };
        (state, id)
    }

    /// Decode a PNG QR image back to the encoded `otpauth://` URI.
    /// Mirrors `paladin-core`'s `tests/export_qr.rs::decode_png_to_payload`
    /// so the two suites use the same decoder.
    fn decode_png_to_payload(png_bytes: &[u8]) -> String {
        let img = image::load_from_memory(png_bytes).expect("decode PNG");
        let luma = img.to_luma8();
        let (w, h) = luma.dimensions();
        let raw = luma.into_raw();
        let img =
            image::ImageBuffer::<Luma<u8>, _>::from_raw(w, h, raw).expect("rebuild luma buffer");
        let mut decoder = rqrr::PreparedImage::prepare(img);
        let grids = decoder.detect_grids();
        assert_eq!(grids.len(), 1, "QR image must contain exactly one code");
        let (_meta, content) = grids[0].decode().expect("decode QR grid");
        content
    }

    /// Read mode bits (`0o777` mask) off `path`. Unix-only.
    #[cfg(unix)]
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("stat exported QR file")
            .permissions()
            .mode()
            & 0o777
    }

    /// Happy-path PNG save: the executor writes the bytes that
    /// `Vault::export_qr_png` returns to the requested target path with
    /// mode `0600`. The pre-seeded garbage at `target_path` exercises
    /// the overwrite path (the executor itself does not gate; the
    /// reducer's `OverwriteGate` ack handles that side of the contract).
    #[test]
    fn execute_qr_export_png_with_overwrite_ack_writes_bytes_matching_export_qr_png_at_0600() {
        let tmp = secure_tempdir();
        let path = tmp.path().join("vault.bin");
        let (mut state, id) = unlocked_with_one_totp(&path, "github");
        let target_path = tmp.path().join("github.png");

        // Pre-seed the target with garbage so the assertion below
        // proves the executor *replaced* the file (not just refused
        // to write because the file existed). The overwrite gate
        // is reducer-side; the executor must blindly write.
        std::fs::write(&target_path, b"GARBAGE-NOT-A-PNG").expect("seed target");

        let expected_bytes = match &state {
            AppState::Unlocked { vault, .. } => vault
                .export_qr_png(id, &QrRenderOptions::default())
                .expect("PNG render")
                .to_vec(),
            other => panic!("expected Unlocked, got {other:?}"),
        };

        let (tx, rx) = mpsc::channel::<AppEvent>();
        let effect = Effect::QrExport {
            path: path.clone(),
            target_path: target_path.clone(),
            account_id: id,
            format: QrSaveFormat::Png,
        };
        let outcome = execute(
            effect,
            &mut state,
            &tx,
            &mut paladin_tui::clipboard::ClipboardSession::new(),
        );
        assert_eq!(outcome, EffectOutcome::Continue);

        match rx.try_recv() {
            Ok(AppEvent::EffectResult(EffectResult::QrExport { result })) => match result {
                Ok(p) => assert_eq!(
                    p, target_path,
                    "EffectResult::QrExport(Ok) must carry the target_path"
                ),
                other => panic!("expected EffectResult::QrExport(Ok), got {other:?}"),
            },
            other => panic!("expected EffectResult::QrExport, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "executor must emit exactly one AppEvent per Effect::QrExport"
        );

        let written = std::fs::read(&target_path).expect("read written PNG");
        assert_eq!(
            written, expected_bytes,
            "PNG bytes on disk must equal Vault::export_qr_png(id, QrRenderOptions::default())"
        );

        #[cfg(unix)]
        assert_eq!(
            file_mode(&target_path),
            0o600,
            "QR PNG export file must land at mode 0600 via write_secret_file_atomic"
        );
    }

    /// SVG save mirrors the PNG path: bytes on disk match
    /// `Vault::export_qr_svg`, mode is `0600`, and the document
    /// starts with the expected SVG / XML preamble.
    #[test]
    fn execute_qr_export_svg_writes_bytes_matching_export_qr_svg_at_0600() {
        let tmp = secure_tempdir();
        let path = tmp.path().join("vault.bin");
        let (mut state, id) = unlocked_with_one_totp(&path, "github");
        let target_path = tmp.path().join("github.svg");

        let expected_bytes = match &state {
            AppState::Unlocked { vault, .. } => vault
                .export_qr_svg(id, &QrRenderOptions::default())
                .expect("SVG render")
                .as_bytes()
                .to_vec(),
            other => panic!("expected Unlocked, got {other:?}"),
        };

        let (tx, rx) = mpsc::channel::<AppEvent>();
        let effect = Effect::QrExport {
            path: path.clone(),
            target_path: target_path.clone(),
            account_id: id,
            format: QrSaveFormat::Svg,
        };
        let outcome = execute(
            effect,
            &mut state,
            &tx,
            &mut paladin_tui::clipboard::ClipboardSession::new(),
        );
        assert_eq!(outcome, EffectOutcome::Continue);

        match rx.try_recv() {
            Ok(AppEvent::EffectResult(EffectResult::QrExport { result })) => match result {
                Ok(p) => assert_eq!(p, target_path),
                other => panic!("expected EffectResult::QrExport(Ok), got {other:?}"),
            },
            other => panic!("expected EffectResult::QrExport, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "executor must emit exactly one AppEvent per Effect::QrExport"
        );

        let written = std::fs::read(&target_path).expect("read written SVG");
        assert_eq!(
            written, expected_bytes,
            "SVG bytes on disk must equal Vault::export_qr_svg(id, QrRenderOptions::default())"
        );

        // Format sanity: the SVG document must begin with the
        // XML / SVG preamble so a downstream renderer can parse it.
        let head =
            std::str::from_utf8(&written[..written.len().min(120)]).expect("SVG must be UTF-8");
        assert!(
            head.starts_with("<?xml") || head.starts_with("<svg"),
            "SVG export must start with `<?xml` or `<svg`; got: {head:?}"
        );

        #[cfg(unix)]
        assert_eq!(
            file_mode(&target_path),
            0o600,
            "QR SVG export file must land at mode 0600 via write_secret_file_atomic"
        );
    }

    /// When `write_secret_file_atomic` cannot resolve a parent
    /// directory (the path has no usable parent component), the
    /// executor surfaces `PaladinError::IoError` with the
    /// `resolve_secret_file_parent` op tag from §5. (A path whose
    /// parent exists as a string but is missing on disk surfaces
    /// `save_not_committed` instead — `write_secret_file_atomic`
    /// collapses pre-commit open / write / fsync failures into that
    /// typed discriminator per the §4.7 commit-state contract; the
    /// `io_error` channel only fires on path-shape rejection.)
    #[test]
    fn execute_qr_export_png_with_missing_parent_dir_returns_io_error() {
        let tmp = secure_tempdir();
        let path = tmp.path().join("vault.bin");
        let (mut state, id) = unlocked_with_one_totp(&path, "github");
        // Empty-parent path: `Path::new("github.png").parent()` is
        // `Some("")`, which `write_secret_file_atomic` rejects with
        // `IoError { operation: "resolve_secret_file_parent", .. }`.
        let target_path = PathBuf::from("github.png");

        let (tx, rx) = mpsc::channel::<AppEvent>();
        let effect = Effect::QrExport {
            path: path.clone(),
            target_path: target_path.clone(),
            account_id: id,
            format: QrSaveFormat::Png,
        };
        let outcome = execute(
            effect,
            &mut state,
            &tx,
            &mut paladin_tui::clipboard::ClipboardSession::new(),
        );
        assert_eq!(outcome, EffectOutcome::Continue);

        match rx.try_recv() {
            Ok(AppEvent::EffectResult(EffectResult::QrExport { result })) => match result {
                Err(PaladinError::IoError { operation, .. }) => assert_eq!(
                    operation, "resolve_secret_file_parent",
                    "missing-parent path must surface the `resolve_secret_file_parent` io_error"
                ),
                other => panic!("expected EffectResult::QrExport(Err(IoError)), got {other:?}"),
            },
            other => panic!("expected EffectResult::QrExport, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "executor must emit exactly one AppEvent per Effect::QrExport"
        );
    }

    /// A `QrExport` effect that arrives while the live state is not
    /// `Unlocked` (e.g. auto-lock fired between submit and execute)
    /// must be silently dropped: no `EffectResult::QrExport` is
    /// posted, so the reducer cannot synthesize a fake mutation
    /// attempt against unrelated state.
    #[test]
    fn execute_qr_export_drops_silently_when_state_is_not_unlocked() {
        let tmp = secure_tempdir();
        let path = tmp.path().join("vault.bin");
        let target_path = tmp.path().join("github.png");
        let mut state = AppState::Unlock {
            path: path.clone(),
            error: None,
            passphrase: PassphraseBuffer::new(),
        };

        let (tx, rx) = mpsc::channel::<AppEvent>();
        let effect = Effect::QrExport {
            path: path.clone(),
            target_path,
            account_id: AccountId::new(),
            format: QrSaveFormat::Png,
        };
        let outcome = execute(
            effect,
            &mut state,
            &tx,
            &mut paladin_tui::clipboard::ClipboardSession::new(),
        );
        assert_eq!(outcome, EffectOutcome::Continue);
        assert!(
            rx.try_recv().is_err(),
            "QrExport against non-Unlocked state must not emit an AppEvent"
        );
    }

    /// A `QrExport` effect whose `path` does not match the live
    /// `Unlocked` state's path (e.g. the user switched vaults) must
    /// also be silently dropped, mirroring the same path-mismatch
    /// guard `Effect::Rename` / `Effect::Remove` apply.
    #[test]
    fn execute_qr_export_drops_silently_when_path_mismatch() {
        let tmp = secure_tempdir();
        let path = tmp.path().join("vault.bin");
        let (mut state, id) = unlocked_with_one_totp(&path, "github");
        let target_path = tmp.path().join("github.png");

        let (tx, rx) = mpsc::channel::<AppEvent>();
        let effect = Effect::QrExport {
            path: PathBuf::from("/tmp/some-other-vault.bin"),
            target_path: target_path.clone(),
            account_id: id,
            format: QrSaveFormat::Png,
        };
        let outcome = execute(
            effect,
            &mut state,
            &tx,
            &mut paladin_tui::clipboard::ClipboardSession::new(),
        );
        assert_eq!(outcome, EffectOutcome::Continue);
        assert!(
            rx.try_recv().is_err(),
            "path-mismatched Effect::QrExport must not emit an AppEvent"
        );
        // No file was written either — the executor short-circuits
        // before touching the renderer or the writer.
        assert!(
            !target_path.exists(),
            "path-mismatched QrExport must not write the destination file"
        );
    }

    /// HOTP read-only contract: the QR PNG that the Save sub-flow
    /// writes for an HOTP account must decode back through `rqrr`
    /// to an `otpauth://hotp/...&counter=N` URI whose `counter`
    /// equals the *current stored counter*. The save path is
    /// read-only — `Vault::export_qr_png` takes `&self`, the
    /// executor never calls `Vault::save`, and the in-memory
    /// counter is unchanged across submit. This pins the rule
    /// down at the executor boundary.
    #[test]
    fn qr_export_modal_png_save_for_hotp_row_decodes_to_otpauth_uri_with_current_counter() {
        const STARTING_COUNTER: u64 = 7;
        let tmp = secure_tempdir();
        let path = tmp.path().join("vault.bin");
        let (mut state, id) = unlocked_with_one_hotp(&path, "github", STARTING_COUNTER);
        let target_path = tmp.path().join("github.png");

        let (tx, rx) = mpsc::channel::<AppEvent>();
        let effect = Effect::QrExport {
            path: path.clone(),
            target_path: target_path.clone(),
            account_id: id,
            format: QrSaveFormat::Png,
        };
        let outcome = execute(
            effect,
            &mut state,
            &tx,
            &mut paladin_tui::clipboard::ClipboardSession::new(),
        );
        assert_eq!(outcome, EffectOutcome::Continue);
        match rx.try_recv() {
            Ok(AppEvent::EffectResult(EffectResult::QrExport { result })) => {
                assert!(result.is_ok(), "expected Ok, got {result:?}");
            }
            other => panic!("expected EffectResult::QrExport, got {other:?}"),
        }

        // Round-trip: decode the PNG bytes back to the encoded URI
        // and assert HOTP scheme + counter equal the *current*
        // stored counter.
        let png_bytes = std::fs::read(&target_path).expect("read written PNG");
        let decoded = decode_png_to_payload(&png_bytes);
        assert!(
            decoded.starts_with("otpauth://hotp/"),
            "HOTP QR must encode as otpauth://hotp/...; got: {decoded:?}"
        );
        let expected_counter = format!("counter={STARTING_COUNTER}");
        assert!(
            decoded.contains(&expected_counter),
            "HOTP QR must carry `counter={STARTING_COUNTER}`; got: {decoded:?}"
        );

        // Read-only contract: the live in-memory counter must NOT
        // have advanced across the save.
        match &state {
            AppState::Unlocked { vault, .. } => {
                let account = vault
                    .iter()
                    .find(|a| a.id() == id)
                    .expect("HOTP account still present");
                assert_eq!(
                    account.counter(),
                    Some(STARTING_COUNTER),
                    "QR Export PNG save must not advance the HOTP counter"
                );
            }
            other => panic!("expected Unlocked, got {other:?}"),
        }
    }

    /// TOTP round-trip: the PNG that the Save sub-flow writes for a
    /// TOTP row must decode back through `rqrr` to an
    /// `otpauth://totp/...` URI carrying the matching algo, digits,
    /// period, and secret. Mirrors the HOTP case at the executor
    /// boundary so the QR payload is pinned to the live account
    /// snapshot, not a stale projection.
    #[test]
    fn qr_export_modal_png_save_for_totp_row_decodes_to_otpauth_uri_with_matching_params() {
        let tmp = secure_tempdir();
        let path = tmp.path().join("vault.bin");
        let (mut state, id) = unlocked_with_one_totp(&path, "github");
        let target_path = tmp.path().join("github.png");

        let (tx, rx) = mpsc::channel::<AppEvent>();
        let effect = Effect::QrExport {
            path: path.clone(),
            target_path: target_path.clone(),
            account_id: id,
            format: QrSaveFormat::Png,
        };
        let outcome = execute(
            effect,
            &mut state,
            &tx,
            &mut paladin_tui::clipboard::ClipboardSession::new(),
        );
        assert_eq!(outcome, EffectOutcome::Continue);
        match rx.try_recv() {
            Ok(AppEvent::EffectResult(EffectResult::QrExport { result })) => {
                assert!(result.is_ok(), "expected Ok, got {result:?}");
            }
            other => panic!("expected EffectResult::QrExport, got {other:?}"),
        }

        let png_bytes = std::fs::read(&target_path).expect("read written PNG");
        let decoded = decode_png_to_payload(&png_bytes);
        // Scheme: TOTP.
        assert!(
            decoded.starts_with("otpauth://totp/"),
            "TOTP QR must encode as otpauth://totp/...; got: {decoded:?}"
        );
        // OTP params from `unlocked_with_one_totp` / `add_totp_account`:
        // secret `JBSWY3DPEHPK3PXP`, SHA1, 6 digits, 30s period.
        assert!(
            decoded.contains("secret=JBSWY3DPEHPK3PXP"),
            "TOTP QR must carry the matching base32 secret; got: {decoded:?}"
        );
        assert!(
            decoded.contains("algorithm=SHA1"),
            "TOTP QR must carry algorithm=SHA1; got: {decoded:?}"
        );
        assert!(
            decoded.contains("digits=6"),
            "TOTP QR must carry digits=6; got: {decoded:?}"
        );
        assert!(
            decoded.contains("period=30"),
            "TOTP QR must carry period=30; got: {decoded:?}"
        );
    }
}
