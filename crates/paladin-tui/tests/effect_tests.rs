// SPDX-License-Identifier: AGPL-3.0-or-later

//! Effect-executor tests for `paladin-tui`.
//!
//! Tracks `IMPLEMENTATION_PLAN_03_TUI.md` > "Implementation checklist":
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
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, Argon2Params,
    EncryptionOptions, IconHintInput, PaladinError, Store, Vault, VaultInit, VaultLock,
};

use paladin_tui::app::effect::{execute, EffectOutcome};
use paladin_tui::app::event::{AppEvent, Effect, EffectResult};
use paladin_tui::app::state::{AppState, Focus};

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
/// `Unlock`, `ClearClipboard`). `MissingVault` is the cheapest
/// variant to construct.
fn dummy_state() -> AppState {
    AppState::MissingVault {
        path: PathBuf::from("/dev/null/dummy-vault.bin"),
    }
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
    let outcome = execute(Effect::Quit, &mut state, &tx);
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
    let outcome = execute(effect, &mut state, &tx);
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
    let outcome = execute(effect, &mut state, &tx);
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
fn execute_unlock_against_missing_vault_sends_vault_missing() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("does-not-exist.bin");

    let (tx, rx) = mpsc::channel();
    let effect = Effect::Unlock {
        path: path.clone(),
        passphrase: SecretString::from("any".to_string()),
    };

    let mut state = dummy_state();
    let outcome = execute(effect, &mut state, &tx);
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
    let outcome = execute(effect, &mut state, &tx);
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
    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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

/// Per `DESIGN.md` §6 (Rename) the trimmed draft is passed through to
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

    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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
/// has since transitioned to `Locked` / `MissingVault` / etc.) is
/// dropped silently so the executor cannot synthesize a rename
/// attempt against an unrelated vault.
#[test]
fn execute_rename_on_non_unlocked_state_is_silently_dropped() {
    let mut state = AppState::MissingVault {
        path: PathBuf::from("/tmp/dummy-vault.bin"),
    };
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Rename {
        path: PathBuf::from("/tmp/dummy-vault.bin"),
        account_id: AccountId::new(),
        new_label: "anything".to_string(),
    };

    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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
/// has since transitioned to `Locked` / `MissingVault` / etc.) is
/// dropped silently so the executor cannot synthesize a remove
/// attempt against an unrelated vault.
#[test]
fn execute_remove_on_non_unlocked_state_is_silently_dropped() {
    let mut state = AppState::MissingVault {
        path: PathBuf::from("/tmp/dummy-vault.bin"),
    };
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let effect = Effect::Remove {
        path: PathBuf::from("/tmp/dummy-vault.bin"),
        account_id: AccountId::new(),
    };

    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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

    let outcome = execute(effect, &mut state, &tx);
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
