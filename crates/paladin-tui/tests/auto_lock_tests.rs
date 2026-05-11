// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto-lock idle-deadline and lock-transition tests for `paladin-tui`.
//!
//! Tracks the "Tests > Auto-lock (`tests/auto_lock_tests.rs`)" checklist
//! in `IMPLEMENTATION_PLAN_03_TUI.md`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::SecretString;

use paladin_core::{Argon2Params, EncryptionOptions, Store, Vault, VaultInit, VaultLock};
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

fn tick_at(monotonic: Instant) -> AppEvent {
    AppEvent::Tick {
        wall_clock: SystemTime::now(),
        monotonic,
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

// ---------------------------------------------------------------------------
// Tick-driven `Unlocked → Locked` transition
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 3)
//
// Slice covered: on each `paladin_core::TICK_INTERVAL_MS` `Tick` the
// reducer asks `IdlePolicy::is_expired(deadline, monotonic)` and, if
// true, transitions `Unlocked → Locked { path }` so the in-memory
// `Vault` / `Store` drop in place. Pre-deadline Ticks, `None`-deadline
// Unlocked states (plaintext / disabled), and Ticks on non-`Unlocked`
// screens are passthrough. Boundary case: `monotonic == deadline`
// fires the lock because `IdlePolicy::is_expired` uses `now >= deadline`.
//
// The "discard HOTP reveal / search / modal" coverage rides on a
// later slice once those state slots exist. Here we only assert the
// state-variant transition and the `path` carry-over.
// ---------------------------------------------------------------------------

#[test]
fn tick_after_deadline_locks_unlocked_state() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        idle_deadline: Some(deadline),
    };

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked { path: p } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_exactly_at_deadline_locks_unlocked_state() {
    // `IdlePolicy::is_expired` uses `now >= deadline`, so a Tick that
    // lands exactly on the deadline must fire the lock — this protects
    // the TUI from re-deriving its own (looser) comparison.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        idle_deadline: Some(deadline),
    };

    let (next, effects) = reduce(state, tick_at(deadline));
    assert!(effects.is_empty());
    match next {
        AppState::Locked { path: p } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_before_deadline_keeps_unlocked_state() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        idle_deadline: Some(deadline),
    };

    let now = deadline
        .checked_sub(Duration::from_millis(1))
        .expect("pre-deadline instant in monotonic range");
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            idle_deadline,
            path: p,
            ..
        } => {
            assert_eq!(p, path);
            assert_eq!(
                idle_deadline,
                Some(deadline),
                "pre-deadline Tick must not rebase the deadline"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn tick_with_no_deadline_keeps_unlocked_state() {
    // Plaintext / auto-lock-disabled vaults have `idle_deadline = None`.
    // A Tick must never fabricate a `Locked` transition from `None`.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");

    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        idle_deadline: None,
    };

    let (next, effects) = reduce(state, tick_at(Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            idle_deadline,
            path: p,
            ..
        } => {
            assert_eq!(p, path);
            assert_eq!(idle_deadline, None);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn tick_on_locked_state_is_passthrough() {
    // A Tick that arrives while the state is already `Locked` is a
    // no-op (no re-lock churn, no path drift).
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Locked { path: path.clone() };

    let (next, effects) = reduce(state, tick_at(Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Locked { path: p } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_on_unlock_screen_is_passthrough() {
    use paladin_tui::prompt::PassphraseBuffer;
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Unlock {
        path: path.clone(),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };

    let (next, effects) = reduce(state, tick_at(Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Unlock { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Unlock, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Setting persists across saves
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 5)
//
// Slice covered: `auto_lock_enabled` and `auto_lock_timeout_secs`
// survive a `Vault::save` + `Store::open` round-trip on both vault
// modes. For plaintext vaults the values are inert at runtime (the
// `IdlePolicy::should_arm` plaintext-no-op rule), but the setting
// itself is still persisted so it takes effect if the vault is later
// encrypted via `passphrase set`. Foundational guarantee for the
// Settings modal slice (still ahead): once that modal lands and
// commits settings via `Vault::mutate_and_save`, the persisted state
// must come back identically after reopen.
// ---------------------------------------------------------------------------

#[test]
fn auto_lock_setting_persists_across_save_reopen_encrypted() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(900)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit settings");
    drop(vault);
    drop(store);

    let (reopened, _store) = Store::open(
        &path,
        VaultLock::Encrypted(SecretString::from("pp".to_string())),
    )
    .expect("reopen encrypted vault");
    assert!(
        reopened.settings().auto_lock_enabled(),
        "auto_lock_enabled must survive encrypted save + reopen"
    );
    assert_eq!(
        reopened.settings().auto_lock_timeout_secs(),
        900,
        "auto_lock_timeout_secs must survive encrypted save + reopen"
    );
}

#[test]
fn auto_lock_setting_persists_across_save_reopen_plaintext() {
    // Plaintext-no-op rule (§6 / §7): the setting is inert at
    // runtime but must still be persisted so it activates if the
    // vault is later encrypted via `passphrase set`.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(900)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit settings");
    drop(vault);
    drop(store);

    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert!(
        reopened.settings().auto_lock_enabled(),
        "auto_lock_enabled must survive plaintext save + reopen even though inert"
    );
    assert_eq!(
        reopened.settings().auto_lock_timeout_secs(),
        900,
        "auto_lock_timeout_secs must survive plaintext save + reopen"
    );
}
