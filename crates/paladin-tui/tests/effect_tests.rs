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

use std::path::Path;
use std::sync::mpsc;
use std::time::Instant;

use secrecy::SecretString;
use tempfile::TempDir;

use paladin_core::{Argon2Params, EncryptionOptions, PaladinError, Store, VaultInit};

use paladin_tui::app::effect::{execute, EffectOutcome};
use paladin_tui::app::event::{AppEvent, Effect, EffectResult};

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

// ---------------------------------------------------------------------------
// Effect::Quit
// ---------------------------------------------------------------------------

#[test]
fn execute_quit_returns_quit_and_sends_no_event() {
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let outcome = execute(Effect::Quit, &tx);
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
    let outcome = execute(effect, &tx);
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

    let outcome = execute(effect, &tx);
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

    let outcome = execute(effect, &tx);
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

    let outcome = execute(effect, &tx);
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

    let outcome = execute(effect, &tx);
    assert_eq!(
        outcome,
        EffectOutcome::Continue,
        "executor must continue even when the receiver is gone"
    );
}
