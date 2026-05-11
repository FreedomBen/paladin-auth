// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto-lock idle-deadline and lock-transition tests for `paladin-tui`.
//!
//! Tracks the "Tests > Auto-lock (`tests/auto_lock_tests.rs`)" checklist
//! in `IMPLEMENTATION_PLAN_03_TUI.md`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::SecretString;

use paladin_core::{
    hotp_reveal_deadline, AccountId, Argon2Params, ClipboardClearPolicy, ClipboardClearToken,
    EncryptionOptions, Store, Vault, VaultInit, VaultLock,
};
use paladin_tui::app::event::{AppEvent, Effect};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{AppState, HotpReveal, Modal, PendingClipboardClear};

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
        search_query: String::new(),
        idle_deadline: Some(t0 + Duration::from_secs(600)),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
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
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
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
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
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
        search_query: String::new(),
        idle_deadline: Some(t0 + Duration::from_secs(600)),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
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
// The search-query discard slice is covered by
// `tick_after_deadline_lock_discards_unlocked_search_query`, the
// HOTP-reveal slice by
// `tick_after_deadline_lock_discards_unlocked_hotp_reveal`, and the
// modal-discard slice by
// `tick_after_deadline_lock_discards_unlocked_modal` below. The
// remaining tests here only assert the state-variant transition and
// the `path` carry-over.
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
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
    };

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_after_deadline_lock_discards_unlocked_search_query() {
    // IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 6:
    // "Locking discards the Vault / Store, open HOTP reveal windows,
    // the search query, and any modal while retaining the resolved
    // vault path for the next unlock attempt." This test covers the
    // search-query slice: a non-empty filter buffer present at the
    // moment of lock must be gone from the resulting `Locked` state,
    // which by construction carries only `path`. The Vault and Store
    // are likewise gone because the variant change drops them.
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
        search_query: "github".to_string(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
    };

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked { path: p, .. } => {
            assert_eq!(p, path, "Locked must carry the original vault path");
        }
        other => panic!("expected Locked (search query and vault must be gone), got {other:?}"),
    }
}

#[test]
fn tick_after_deadline_lock_discards_unlocked_hotp_reveal() {
    // IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 6:
    // "Locking discards the Vault / Store, open HOTP reveal windows,
    // the search query, and any modal while retaining the resolved
    // vault path for the next unlock attempt." This test covers the
    // HOTP-reveal slice: an open reveal window (the account being
    // revealed, the `counter_used` that produced the visible code,
    // the displayed code bytes, and the monotonic reveal deadline)
    // present at the moment of lock must be gone from the resulting
    // `Locked` state, which by construction carries only `path` (plus
    // any pending clipboard clear). The Vault and Store are likewise
    // gone because the variant change drops them.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let idle_deadline = t0 + Duration::from_secs(600);
    let reveal = HotpReveal {
        account_id: AccountId::new(),
        counter_used: 7,
        code: SecretString::from("123456".to_string()),
        deadline: hotp_reveal_deadline(t0),
    };
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(idle_deadline),
        pending_clipboard_clear: None,
        hotp_reveal: Some(reveal),
        modal: None,
    };

    let now = idle_deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "Locked must carry the original vault path");
            assert!(
                pending_clipboard_clear.is_none(),
                "pending clipboard clear was None on entry; lock must not fabricate one"
            );
        }
        other => panic!("expected Locked (HOTP reveal and vault must be gone), got {other:?}"),
    }
}

#[test]
fn tick_after_deadline_lock_discards_unlocked_modal() {
    // IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 6:
    // "Locking discards the Vault / Store, open HOTP reveal windows,
    // the search query, and any modal while retaining the resolved
    // vault path for the next unlock attempt." This test covers the
    // modal slice: an open modal present at the moment of lock must
    // be gone from the resulting `Locked` state, which by
    // construction carries only `path` (plus any pending clipboard
    // clear). `Modal::Passphrase` is chosen as the representative
    // case because, once its payload lands, it owns the most
    // secret-bearing modal-local buffer (the typed passphrase) —
    // making the discard-on-lock contract most consequential.
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
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase),
    };

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "Locked must carry the original vault path");
            assert!(
                pending_clipboard_clear.is_none(),
                "pending clipboard clear was None on entry; lock must not fabricate one"
            );
        }
        other => panic!("expected Locked (modal and vault must be gone), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Clipboard auto-clear survives lock
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 7)
//
// State-carry-across-lock slice: a `PendingClipboardClear` present on
// `Unlocked` at the moment of the idle-expiry tick is carried
// unchanged through to the resulting `Locked` state — token,
// captured bytes, and the scheduled wake-deadline all survive the
// variant change.
//
// Wake-on-`Locked` slice (the "still fires only-if-unchanged" half):
// covered by `clipboard_clear_event_on_locked_*` further down. A
// matching-token `AppEvent::ClipboardClear` arriving on `Locked`
// emits `Effect::ClearClipboard { value }` and clears
// `pending_clipboard_clear`; a stale token or absent pending state
// is a no-op. The executor-side "read the live clipboard, apply
// `ClipboardClearPolicy::should_clear`, write empty if `true`"
// decision is covered separately by `tests/clipboard_tests.rs` once
// the clipboard adapter lands.
// ---------------------------------------------------------------------------

#[test]
fn tick_after_deadline_lock_carries_pending_clipboard_clear() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clear secs within bounds");

    let t0 = Instant::now();
    let (token, clear_deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("clipboard clear scheduled");
    let pending = PendingClipboardClear {
        token,
        value: vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36],
        deadline: clear_deadline,
    };

    let idle_deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(idle_deadline),
        pending_clipboard_clear: Some(pending),
        hotp_reveal: None,
        modal: None,
    };

    let now = idle_deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path);
            let p_clear =
                pending_clipboard_clear.expect("pending clear survives the lock transition");
            assert_eq!(p_clear.token, token, "token survives unchanged");
            assert_eq!(
                p_clear.value.as_slice(),
                &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36],
                "captured bytes survive unchanged"
            );
            assert_eq!(
                p_clear.deadline, clear_deadline,
                "wake-deadline survives unchanged"
            );
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_after_deadline_lock_with_no_pending_clipboard_clear_yields_none() {
    // The default Unlocked has no pending clear; the post-lock state
    // must reflect that — i.e. `pending_clipboard_clear == None` on
    // `Locked` — so a stale `Some(...)` cannot be fabricated by the
    // transition path.
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
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
    };

    let now = deadline + Duration::from_millis(1);
    let (next, _effects) = reduce(state, tick_at(now));
    match next {
        AppState::Locked {
            pending_clipboard_clear,
            ..
        } => {
            assert!(
                pending_clipboard_clear.is_none(),
                "no pending clear must remain `None` after lock"
            );
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `AppEvent::ClipboardClear` wake handler on `Locked`
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 7, second half)
//
// Slice covered: when the clipboard auto-clear timer that survived the
// `Unlocked → Locked` lock fires its delayed
// `AppEvent::ClipboardClear { token, value }`, the reducer:
//
// * with a matching token on `pending_clipboard_clear`, emits a single
//   [`Effect::ClearClipboard { value }`] carrying the captured bytes
//   from state and clears `pending_clipboard_clear` to `None`. The
//   actual live-clipboard read / `should_clear` / wipe lives in the
//   effect executor (covered by `tests/clipboard_tests.rs` once the
//   adapter lands);
// * with a stale token (a fresher copy has issued a new token and
//   replaced the pending state), drops the wake event with no state
//   change and no effect;
// * with no pending clear (the wake arrived after a clear had already
//   fired or been superseded out), is a no-op.
//
// The pre-lock (`Unlocked`) wake path is covered by
// `tests/clipboard_tests.rs`; the `Locked` path is here because it is
// the path that directly enforces bullet 7's lock-survival contract.
// ---------------------------------------------------------------------------

fn clipboard_clear_event(token: ClipboardClearToken, value: Vec<u8>) -> AppEvent {
    AppEvent::ClipboardClear { token, value }
}

#[test]
fn clipboard_clear_event_on_locked_with_matching_token_fires_wipe_and_clears_pending() {
    let path = PathBuf::from("/tmp/v.bin");
    let captured = vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
    // A schedule done from a real `VaultSettings` issues a real
    // `ClipboardClearToken`; the test mirrors that to avoid hand-rolling
    // tokens (which the policy module doesn't expose as a public ctor).
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted_pair(&tmp.path().join("issuer.bin"), "pp");
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clear secs within bounds");
    let t0 = Instant::now();
    let (token, deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("clipboard clear scheduled");
    drop(vault);
    drop(store);

    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token,
            value: captured.clone(),
            deadline,
        }),
    };

    let (next, effects) = reduce(state, clipboard_clear_event(token, captured.clone()));

    match &effects[..] {
        [Effect::ClearClipboard { value }] => {
            assert_eq!(
                value, &captured,
                "wipe effect must carry the captured bytes from pending state"
            );
        }
        other => panic!("expected exactly one Effect::ClearClipboard, got {other:?}"),
    }
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "Locked path must carry over");
            assert!(
                pending_clipboard_clear.is_none(),
                "matching-token wake hands the wipe to the executor; pending state clears"
            );
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn clipboard_clear_event_on_locked_with_stale_token_is_noop() {
    // A second copy after the first issues a fresh, strictly-greater
    // token via `ClipboardClearPolicy::schedule`. The first timer's
    // delayed `AppEvent::ClipboardClear` then arrives with the *old*
    // token; the reducer must drop it without state change and
    // without emitting a wipe effect — the newer pending state owns
    // the only valid clear.
    let path = PathBuf::from("/tmp/v.bin");
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted_pair(&tmp.path().join("issuer.bin"), "pp");
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clear secs within bounds");
    let t0 = Instant::now();
    let (stale_token, _stale_deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("first schedule");
    let (fresh_token, fresh_deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("second schedule");
    assert_ne!(
        stale_token, fresh_token,
        "successive schedule calls must issue distinct tokens"
    );
    drop(vault);
    drop(store);

    let fresh_value = vec![0x39, 0x39, 0x39, 0x39, 0x39, 0x39];
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token: fresh_token,
            value: fresh_value.clone(),
            deadline: fresh_deadline,
        }),
    };

    let (next, effects) = reduce(
        state,
        clipboard_clear_event(stale_token, vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36]),
    );

    assert!(
        effects.is_empty(),
        "stale-token wake must not emit a wipe effect"
    );
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path);
            let p_clear =
                pending_clipboard_clear.expect("fresher pending state must survive a stale wake");
            assert_eq!(p_clear.token, fresh_token);
            assert_eq!(p_clear.value.as_slice(), fresh_value.as_slice());
            assert_eq!(p_clear.deadline, fresh_deadline);
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn clipboard_clear_event_on_locked_with_no_pending_is_noop() {
    // If the wake arrives after the pending clear has already fired
    // (or been dropped some other way), the reducer must not
    // fabricate a wipe — there is nothing to wipe a token against.
    let path = PathBuf::from("/tmp/v.bin");
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted_pair(&tmp.path().join("issuer.bin"), "pp");
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clear secs within bounds");
    let (token, _deadline) = ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
        .expect("schedule for token");
    drop(vault);
    drop(store);

    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: None,
    };

    let (next, effects) = reduce(state, clipboard_clear_event(token, Vec::new()));
    assert!(
        effects.is_empty(),
        "wake with no pending state must not emit a wipe effect"
    );
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path);
            assert!(pending_clipboard_clear.is_none());
        }
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
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
    };

    let (next, effects) = reduce(state, tick_at(deadline));
    assert!(effects.is_empty());
    match next {
        AppState::Locked { path: p, .. } => assert_eq!(p, path),
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
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
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
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
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
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: None,
    };

    let (next, effects) = reduce(state, tick_at(Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Locked { path: p, .. } => assert_eq!(p, path),
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
