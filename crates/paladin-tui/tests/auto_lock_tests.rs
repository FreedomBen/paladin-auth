// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto-lock idle-deadline and lock-transition tests for `paladin-tui`.
//!
//! Tracks the "Tests > Auto-lock (`tests/auto_lock_tests.rs`)" checklist
//! in `IMPLEMENTATION_PLAN_03_TUI.md`.

use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::SecretString;

use paladin_core::{Argon2Params, EncryptionOptions, Store, Vault, VaultInit};
use paladin_tui::app::event::AppEvent;
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::AppState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn light_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    }
}

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

fn create_encrypted_pair(path: &Path, passphrase: &str) -> (Vault, Store) {
    let pp = SecretString::from(passphrase.to_string());
    let opts = EncryptionOptions::with_params(pp, light_params()).expect("encryption opts");
    let (vault, store) = Store::create(path, VaultInit::Encrypted(opts)).expect("create vault");
    vault.save(&store).expect("commit initial vault");
    (vault, store)
}

fn enable_auto_lock(vault: &mut Vault, store: &Store, timeout_secs: u32) {
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(timeout_secs)
        .expect("timeout within bounds");
    vault.save(store).expect("commit settings");
}

fn key_input_at(code: KeyCode, at: Instant) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        at,
    }
}

// ---------------------------------------------------------------------------
// `idle_deadline` resets on any `AppEvent::Input`
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 2)
//
// Slice covered: every `AppEvent::Input` that lands while the state is
// `Unlocked` refreshes the auto-lock idle deadline via
// `paladin_core::IdlePolicy::next_deadline(at, is_encrypted, settings)`,
// rebased on the event's `at` instant. Plaintext vaults and encrypted
// vaults with `auto_lock_enabled = false` stay `None` because
// `IdlePolicy::should_arm` is `false` — the TUI must not paper over the
// core rule.
// ---------------------------------------------------------------------------

#[test]
fn input_in_encrypted_unlocked_with_auto_lock_rebases_idle_deadline_on_event_at() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        idle_deadline: Some(t0 + Duration::from_secs(600)),
    };

    let t1 = t0 + Duration::from_secs(123);
    let (next, effects) = reduce(state, key_input_at(KeyCode::Down, t1));
    assert!(
        effects.is_empty(),
        "Down on Unlocked is a no-op for effects"
    );
    match next {
        AppState::Unlocked { idle_deadline, .. } => {
            assert_eq!(
                idle_deadline,
                Some(t1 + Duration::from_secs(600)),
                "idle_deadline must rebase on the event's `at` timestamp"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn input_in_plaintext_unlocked_keeps_idle_deadline_none_even_if_auto_lock_enabled() {
    // The plaintext-no-op rule (`IdlePolicy::should_arm`) must hold even
    // after the user toggled `auto_lock_enabled = true` on the
    // (plaintext) vault. Input must not arm the deadline.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(600)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit settings");

    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        idle_deadline: None,
    };

    let (next, effects) = reduce(state, key_input_at(KeyCode::Char('x'), Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { idle_deadline, .. } => assert_eq!(idle_deadline, None),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn input_in_encrypted_unlocked_with_auto_lock_disabled_keeps_idle_deadline_none() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, store) = create_encrypted_pair(&path, "pp");
    assert!(
        !vault.settings().auto_lock_enabled(),
        "fixture default must be auto_lock_enabled = false"
    );

    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        idle_deadline: None,
    };

    let (next, effects) = reduce(state, key_input_at(KeyCode::Char('x'), Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { idle_deadline, .. } => assert_eq!(idle_deadline, None),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn non_key_input_in_encrypted_unlocked_also_rebases_idle_deadline() {
    // "Idle is reset by any `AppEvent::Input`." — resize, focus, paste,
    // mouse events all reset the deadline. Resize stands in for the
    // non-Key variants here.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        idle_deadline: Some(t0 + Duration::from_secs(600)),
    };

    let t1 = t0 + Duration::from_secs(45);
    let evt = AppEvent::Input {
        event: Event::Resize(80, 24),
        at: t1,
    };
    let (next, effects) = reduce(state, evt);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { idle_deadline, .. } => {
            assert_eq!(idle_deadline, Some(t1 + Duration::from_secs(600)));
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}
