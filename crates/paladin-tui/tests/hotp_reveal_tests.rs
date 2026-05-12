// SPDX-License-Identifier: AGPL-3.0-or-later

//! HOTP reveal-window lifecycle tests for `paladin-tui`.
//!
//! Tracks the "Tests > HOTP reveal window (`tests/hotp_reveal_tests.rs`)"
//! checklist in `IMPLEMENTATION_PLAN_03_TUI.md`. The reveal panel opens
//! when `Effect::HotpAdvance` returns a generated `Code`; it closes
//! when the `paladin_core::policy::hotp_reveal::deadline(now)` deadline
//! is crossed by a `Tick`, when `n` is pressed again (which advances
//! the counter and opens a fresh reveal), or when the
//! `Unlocked → Locked` auto-lock transition discards the entire
//! `Unlocked` payload. This slice covers the deadline-expiry and
//! 'n'-during-open-reveal sub-clauses; the rendering bullets (hidden
//! row shows next counter, revealed row shows `counter_used`) ride
//! with the view-layer slice.

mod common;

use common::test_tempdir;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::{ExposeSecret, SecretString};

use paladin_core::{
    hotp_reveal_deadline, validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm,
    Argon2Params, Code, EncryptionOptions, IconHintInput, PaladinError, Store, Vault, VaultInit,
};
use paladin_tui::app::event::{AppEvent, Effect, EffectResult};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{render_error_message, AppState, Focus, HotpReveal, StatusLine};

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
    let dir = test_tempdir();
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
    let validated = validate_manual(input, SystemTime::now()).expect("valid HOTP manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit hotp account");
    id
}

fn tick_at(monotonic: Instant) -> AppEvent {
    AppEvent::Tick {
        wall_clock: SystemTime::now(),
        monotonic,
    }
}

fn key_input_at(code: KeyCode, at: Instant) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        at,
    }
}

fn open_reveal(account_id: AccountId, counter_used: u64, code: &str, t0: Instant) -> HotpReveal {
    HotpReveal {
        account_id,
        counter_used,
        code: SecretString::from(code.to_string()),
        deadline: hotp_reveal_deadline(t0),
    }
}

/// Build an `Unlocked` state with the given reveal already open and no
/// auto-lock deadline armed, so Tick-driven behaviour is observed in
/// isolation from auto-lock.
fn unlocked_with_reveal(
    path: PathBuf,
    vault: Vault,
    store: Store,
    selected: Option<AccountId>,
    reveal: Option<HotpReveal>,
) -> AppState {
    AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: reveal,
        modal: None,
        selected,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    }
}

// ---------------------------------------------------------------------------
// Reveal-expiry on Tick
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > HOTP reveal window — bullet 1)
//
// "Reveal closes after the deadline returned by
// `paladin_core::policy::hotp_reveal::deadline(now)`
// (`paladin_core::HOTP_REVEAL_SECS` measured on a monotonic clock)."
// ---------------------------------------------------------------------------

#[test]
fn tick_after_reveal_deadline_clears_reveal_and_emits_no_effects() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let reveal = open_reveal(hotp_id, 7, "123456", t0);
    let state = unlocked_with_reveal(path.clone(), vault, store, Some(hotp_id), Some(reveal));

    let now = hotp_reveal_deadline(t0) + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(
        effects.is_empty(),
        "reveal expiry emits no effects (purely state-internal)"
    );
    match next {
        AppState::Unlocked {
            hotp_reveal,
            path: p,
            ..
        } => {
            assert!(
                hotp_reveal.is_none(),
                "Tick past the reveal deadline must close the reveal window"
            );
            assert_eq!(p, path, "expiry must not alter the vault path");
        }
        other => panic!("expected Unlocked (no auto-lock deadline armed), got {other:?}"),
    }
}

#[test]
fn tick_exactly_at_reveal_deadline_clears_reveal() {
    // Boundary case: `policy::hotp_reveal::deadline(t0)` returns the
    // last instant the code remains visible. Per the policy's
    // monotonic semantics any `Tick` at-or-past the deadline closes
    // the reveal; the boundary is `>=`, mirroring `IdlePolicy`.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let reveal = open_reveal(hotp_id, 7, "123456", t0);
    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), Some(reveal));

    let now = hotp_reveal_deadline(t0);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { hotp_reveal, .. } => assert!(
            hotp_reveal.is_none(),
            "Tick at the reveal deadline must close the reveal"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn tick_before_reveal_deadline_preserves_reveal() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let reveal = open_reveal(hotp_id, 7, "123456", t0);
    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), Some(reveal));

    let now = t0 + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            ..
        } => {
            assert_eq!(r.account_id, hotp_id);
            assert_eq!(r.counter_used, 7);
            assert_eq!(
                r.code.expose_secret(),
                "123456",
                "code bytes must survive an inert tick"
            );
            assert_eq!(
                r.deadline,
                hotp_reveal_deadline(t0),
                "deadline must not be mutated by an inert tick"
            );
        }
        other => panic!("expected Unlocked with reveal still open, got {other:?}"),
    }
}

#[test]
fn tick_after_reveal_deadline_leaves_unrelated_state_untouched() {
    // Reveal expiry must be surgical: every other slot on Unlocked
    // (selected, focus, search, viewport, modal, idle deadline,
    // pending clipboard clear) is preserved verbatim.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let reveal = open_reveal(hotp_id, 7, "123456", t0);
    let mut state = unlocked_with_reveal(path, vault, store, Some(hotp_id), Some(reveal));
    if let AppState::Unlocked {
        search_query,
        viewport_height,
        viewport_offset,
        focus,
        ..
    } = &mut state
    {
        *search_query = "h".to_string();
        *viewport_height = 12;
        *viewport_offset = 3;
        *focus = Focus::Search;
    }

    let now = hotp_reveal_deadline(t0) + Duration::from_millis(1);
    let (next, _effects) = reduce(state, tick_at(now));
    match next {
        AppState::Unlocked {
            hotp_reveal,
            selected,
            focus,
            search_query,
            viewport_height,
            viewport_offset,
            modal,
            idle_deadline,
            pending_clipboard_clear,
            ..
        } => {
            assert!(hotp_reveal.is_none(), "reveal closed");
            assert_eq!(selected, Some(hotp_id));
            assert_eq!(focus, Focus::Search);
            assert_eq!(search_query, "h");
            assert_eq!(viewport_height, 12);
            assert_eq!(viewport_offset, 3);
            assert!(modal.is_none());
            assert!(idle_deadline.is_none());
            assert!(pending_clipboard_clear.is_none());
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn tick_with_no_reveal_is_a_passthrough() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");
    let state = unlocked_with_reveal(path.clone(), vault, store, Some(hotp_id), None);

    let now = Instant::now() + Duration::from_secs(3600);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            hotp_reveal,
            path: p,
            ..
        } => {
            assert!(hotp_reveal.is_none());
            assert_eq!(p, path);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn auto_lock_takes_precedence_over_reveal_expiry_when_both_fire() {
    // If the same `Tick` is both past the auto-lock idle deadline
    // and past the reveal deadline, the lock transition wins and
    // the resulting `Locked` state inherently has no `hotp_reveal`
    // slot. The reveal-expiry handler must not run after the
    // variant change.
    use paladin_core::Argon2Params;
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let _ = Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(60)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit settings");

    let t0 = Instant::now();
    let idle_deadline = t0 + Duration::from_secs(60);
    let reveal = open_reveal(hotp_id, 7, "123456", t0);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(idle_deadline),
        pending_clipboard_clear: None,
        hotp_reveal: Some(reveal),
        modal: None,
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };

    // Tick is past both deadlines.
    let now = idle_deadline.max(hotp_reveal_deadline(t0)) + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty());
    match next {
        AppState::Locked { path: p, .. } => {
            assert_eq!(p, path, "lock transition retains the vault path");
        }
        other => panic!("expected Locked (auto-lock wins), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `n` during an open reveal advances again
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > HOTP reveal window — bullet 2)
//
// "`n` during an open reveal advances again (does not no-op)."
//
// The reducer's `n` handler dispatches `Effect::HotpAdvance` whenever
// a HOTP account is selected and no modal traps focus. The presence
// of an open `hotp_reveal` must not gate the advance — the executor
// owns the counter mutation, and the reveal slot is replaced by the
// next `EffectResult::HotpAdvance` carrying the freshly generated
// code.
// ---------------------------------------------------------------------------

#[test]
fn pressing_n_with_open_reveal_still_emits_hotp_advance_effect() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let reveal = open_reveal(hotp_id, 7, "123456", t0);
    let state = unlocked_with_reveal(path.clone(), vault, store, Some(hotp_id), Some(reveal));

    let (next, effects) = reduce(state, key_input_at(KeyCode::Char('n'), t0));
    assert_eq!(
        effects.len(),
        1,
        "`n` with an open reveal must still emit a HotpAdvance effect (not no-op)"
    );
    match &effects[0] {
        Effect::HotpAdvance {
            account_id,
            path: effect_path,
        } => {
            assert_eq!(*account_id, hotp_id);
            assert_eq!(*effect_path, path);
        }
        other => panic!("expected Effect::HotpAdvance, got {other:?}"),
    }
    // The reveal window itself is unchanged by the reducer at this
    // slice — the executor's `EffectResult::HotpAdvance` will
    // replace it. Until that variant lands, the old reveal stays
    // open in the post-dispatch state.
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            ..
        } => assert_eq!(r.counter_used, 7),
        other => panic!("expected Unlocked with reveal still set, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// EffectResult::HotpAdvance opens / replaces the reveal window
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer)
//
// "AppEvent::EffectResult(...) is the only path by which effect outcomes
// change non-core UI state (status text, reveal windows, modal
// close / counts panels, inline errors)."
//
// The reducer must:
//   * On `Ok(code)` while Unlocked: open a fresh `HotpReveal` slot keyed
//     by `account_id`, with `counter_used` and `code` from the carried
//     `Code` and `deadline = hotp_reveal_deadline(completed_at)`. Any
//     previous reveal slot is dropped (its `SecretString` zeroizes).
//   * On any non-`Unlocked` state: drop the result (and the carried
//     `Code`'s OTP digits) without changing the state.
// ---------------------------------------------------------------------------

fn hotp_code(digits: &str, counter: u64) -> Code {
    Code {
        code: digits.to_string(),
        valid_from: None,
        valid_until: None,
        seconds_remaining: None,
        counter_used: Some(counter),
    }
}

#[test]
fn effect_result_hotp_advance_ok_opens_reveal_window_on_unlocked() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), None);
    let completed_at = Instant::now();
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Ok(hotp_code("123456", 7)),
        staged_code: None,
        completed_at,
    });

    let (next, effects) = reduce(state, event);
    assert!(
        effects.is_empty(),
        "EffectResult::HotpAdvance emits no follow-up effects"
    );
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            ..
        } => {
            assert_eq!(r.account_id, hotp_id);
            assert_eq!(r.counter_used, 7);
            assert_eq!(r.code.expose_secret(), "123456");
            assert_eq!(
                r.deadline,
                hotp_reveal_deadline(completed_at),
                "reveal deadline must be computed from `completed_at`"
            );
        }
        other => panic!("expected Unlocked with reveal open, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_ok_replaces_existing_reveal() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let prior = open_reveal(hotp_id, 7, "111111", t0);
    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), Some(prior));

    let completed_at = t0 + Duration::from_millis(500);
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Ok(hotp_code("222222", 8)),
        staged_code: None,
        completed_at,
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            ..
        } => {
            assert_eq!(
                r.counter_used, 8,
                "fresh reveal must replace the prior one (counter 7 → 8)"
            );
            assert_eq!(r.code.expose_secret(), "222222");
            assert_eq!(r.deadline, hotp_reveal_deadline(completed_at));
        }
        other => panic!("expected Unlocked with replaced reveal, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_drops_when_locked() {
    // The user auto-locked between `Effect::HotpAdvance` emission and
    // the executor's result delivery. The late result is dropped and
    // the carried `Code` zeroizes on drop without mutating Locked
    // state.
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: None,
    };
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: AccountId::new(),
        result: Ok(hotp_code("999999", 1)),
        staged_code: None,
        completed_at: Instant::now(),
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty(), "discarding a late result emits nothing");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear: None,
        } => assert_eq!(p, path),
        other => panic!("expected Locked unchanged, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_err_save_not_committed_leaves_reveal_unchanged() {
    // Pre-commit save failure: the core has already reverted the
    // in-memory counter, so the reducer must not open a reveal. Any
    // previous reveal stays in place (the failure does not retroact-
    // ively invalidate an unrelated earlier successful advance).
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let prior = open_reveal(hotp_id, 7, "111111", t0);
    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), Some(prior));

    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        }),
        staged_code: None,
        completed_at: t0,
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            ..
        } => {
            assert_eq!(
                r.counter_used, 7,
                "pre-commit failure must not replace the prior reveal"
            );
            assert_eq!(r.code.expose_secret(), "111111");
        }
        other => panic!("expected Unlocked with prior reveal preserved, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_drops_when_on_unlock_screen() {
    // Defensive case: a result arriving while the app is back on the
    // Unlock screen (e.g. the user locked then attempted to unlock
    // again) is discarded without mutating the unlock screen.
    use paladin_tui::prompt::PassphraseBuffer;
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Unlock {
        path: path.clone(),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: AccountId::new(),
        result: Ok(hotp_code("999999", 1)),
        staged_code: None,
        completed_at: Instant::now(),
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlock { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Unlock unchanged, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_err_invalid_state_leaves_reveal_unchanged() {
    // Defensive coverage: any non-`Ok` result (here `InvalidState`,
    // matching the `account_not_found` / `not_hotp` paths inside
    // `Vault::hotp_advance`) must not open a reveal. Any prior reveal
    // is preserved verbatim until a successful `Ok(code)` replaces it.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let prior = open_reveal(hotp_id, 7, "111111", t0);
    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), Some(prior));

    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(PaladinError::InvalidState {
            operation: "hotp_advance",
            state: "account_not_found",
        }),
        staged_code: None,
        completed_at: t0,
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            ..
        } => {
            assert_eq!(r.counter_used, 7);
            assert_eq!(r.code.expose_secret(), "111111");
        }
        other => panic!("expected Unlocked with prior reveal preserved, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_err_with_no_prior_reveal_does_not_open_one() {
    // No prior reveal + error result + `staged_code: None` must leave
    // `hotp_reveal` as `None`. Symmetric with the prior-reveal-
    // preserved case, and the fail-safe for the
    // `Err(SaveDurabilityUnconfirmed)` path when the executor did not
    // (or could not) stage a `Code` via `Vault::hotp_peek` —
    // `staged_code: Some(_)` opens a reveal per the dedicated
    // staged-code tests below.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), None);

    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(PaladinError::SaveDurabilityUnconfirmed),
        staged_code: None,
        completed_at: Instant::now(),
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { hotp_reveal, .. } => assert!(
            hotp_reveal.is_none(),
            "error result without a staged code must not fabricate a reveal"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn hotp_reveal_debug_redacts_displayed_code_bytes() {
    // The displayed code is held in `SecretString` and must not leak
    // through the derived `Debug` impl. Same rule as
    // `passphrase_buffer_debug_redacts_typed_bytes` for the unlock
    // buffer — anyone reading a panic trace or `dbg!(&state)` output
    // must not see the active OTP digits.
    let reveal = HotpReveal {
        account_id: AccountId::new(),
        counter_used: 7,
        code: SecretString::from("424242".to_string()),
        deadline: Instant::now(),
    };
    let rendered = format!("{reveal:?}");
    assert!(
        !rendered.contains("424242"),
        "HotpReveal Debug must not leak the OTP digits, got: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// EffectResult::HotpAdvance Err — status-line surfacing.
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` Tests > Reducer:
//   "Pre-commit effect failures leave visible state unchanged and surface
//    inline / status-line errors."
//
// And the Effect errors body:
//   "Pre-commit save failures (`save_not_committed`) leave the in-memory
//    counter and reveal state unchanged ... and surface a status-line error.
//    Durability-unconfirmed failures (`save_durability_unconfirmed`) reveal
//    the new code and `Code.counter_used` label and report the
//    committed-but-uncertain status in the status line — the user has the
//    new code in hand even though durability is in question. All other
//    failures show a status-line error and leave the previous reveal state
//    unchanged."
//
// The companion `_leaves_reveal_unchanged` tests above lock in the
// visible-state-unchanged half for pre-commit and other errors. The
// `save_durability_unconfirmed` row's reveals-on-failure behavior uses
// the staged-code mechanism on `EffectResult::HotpAdvance` and is
// covered by the dedicated `_with_staged_code_*` tests below. The
// status-line tests below lock in the shared status-line surface for
// every error kind the executor surfaces today (`save_not_committed`
// from `Vault::hotp_advance`'s pre-rename failure, `invalid_state`
// defensively, `save_durability_unconfirmed`).
// ---------------------------------------------------------------------------

#[test]
fn effect_result_hotp_advance_err_save_not_committed_sets_status_line() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), None);

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let expected = render_error_message(&err);
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(err),
        staged_code: None,
        completed_at: Instant::now(),
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { status_line, .. } => assert_eq!(
            status_line,
            Some(StatusLine::Error(expected)),
            "save_not_committed must surface a status-line error"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_err_invalid_state_sets_status_line() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), None);

    let err = PaladinError::InvalidState {
        operation: "hotp_advance",
        state: "account_not_found",
    };
    let expected = render_error_message(&err);
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(err),
        staged_code: None,
        completed_at: Instant::now(),
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { status_line, .. } => assert_eq!(
            status_line,
            Some(StatusLine::Error(expected)),
            "non-save errors must surface a status-line error"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_err_save_durability_unconfirmed_sets_status_line() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), None);

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let expected = render_error_message(&err);
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(err),
        staged_code: None,
        completed_at: Instant::now(),
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { status_line, .. } => assert_eq!(
            status_line,
            Some(StatusLine::Error(expected)),
            "save_durability_unconfirmed must surface a status-line note \
             reporting the committed-but-uncertain status; the companion \
             reveal-opening behavior lives in the staged-code tests below"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_ok_clears_prior_status_line() {
    // Symmetric: a successful advance closes the loop and the status
    // line should be cleared so the prior failure note does not stick.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let mut state = unlocked_with_reveal(path, vault, store, Some(hotp_id), None);
    if let AppState::Unlocked {
        ref mut status_line,
        ..
    } = state
    {
        *status_line = Some(StatusLine::Error("prior failure".to_string()));
    }

    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Ok(hotp_code("999999", 1)),
        staged_code: None,
        completed_at: Instant::now(),
    });
    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            status_line,
            hotp_reveal,
            ..
        } => {
            assert_eq!(
                status_line, None,
                "successful advance must clear the prior status-line error"
            );
            assert!(hotp_reveal.is_some(), "Ok must open the reveal window");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// EffectResult::HotpAdvance Err(SaveDurabilityUnconfirmed) with a staged
// code — the durability-unconfirmed reveal-on-failure path.
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` Tests > Reducer:
//   "Durability-unconfirmed failures follow the committed-state behavior
//    in 'Effect errors'."
//
// And the Effect errors body for HOTP `n`:
//   "Durability-unconfirmed failures (`save_durability_unconfirmed`)
//    reveal the new code and `Code.counter_used` label and report the
//    committed-but-uncertain status in the status line — the user has
//    the new code in hand even though durability is in question."
//
// The executor stages the would-be visible `Code` via `Vault::hotp_peek`
// before calling `Vault::hotp_advance`, and publishes the staged code on
// `EffectResult::HotpAdvance.staged_code` only when the advance succeeded
// or returned `save_durability_unconfirmed`. On every other `Err(...)`
// path the executor zeroizes the staged code and sets `staged_code` to
// `None`, which the reducer treats as "status-line only" (covered by
// the `_sets_status_line` and `_with_no_prior_reveal_does_not_open_one`
// tests above).
// ---------------------------------------------------------------------------

#[test]
fn effect_result_hotp_advance_err_save_durability_unconfirmed_with_staged_code_opens_reveal() {
    // No prior reveal + Err(SaveDurabilityUnconfirmed) + staged_code:
    // Some(_) must open the reveal slot using the staged code AND set
    // the status-line to the rendered durability-unconfirmed note.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), None);

    let completed_at = Instant::now();
    let expected_status = render_error_message(&PaladinError::SaveDurabilityUnconfirmed);
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(PaladinError::SaveDurabilityUnconfirmed),
        staged_code: Some(Box::new(hotp_code("424242", 9))),
        completed_at,
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            status_line,
            ..
        } => {
            assert_eq!(
                r.account_id, hotp_id,
                "reveal must be keyed by the advanced account"
            );
            assert_eq!(
                r.counter_used, 9,
                "reveal must carry the staged code's pre-advance counter"
            );
            assert_eq!(
                r.code.expose_secret(),
                "424242",
                "reveal must show the staged code"
            );
            assert_eq!(
                r.deadline,
                hotp_reveal_deadline(completed_at),
                "reveal deadline must be computed from `completed_at`"
            );
            assert_eq!(
                status_line,
                Some(StatusLine::Error(expected_status)),
                "save_durability_unconfirmed must also surface a status-line note"
            );
        }
        other => panic!("expected Unlocked with reveal opened from staged code, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_err_save_durability_unconfirmed_with_staged_code_replaces_prior_reveal(
) {
    // Prior reveal at counter=7 + Err(SaveDurabilityUnconfirmed) +
    // staged_code: Some(counter=8) must REPLACE the prior reveal with
    // the new staged code — the user just advanced and the on-disk
    // counter is at the new value even though durability is uncertain.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let prior = open_reveal(hotp_id, 7, "111111", t0);
    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), Some(prior));

    let completed_at = t0 + Duration::from_millis(500);
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(PaladinError::SaveDurabilityUnconfirmed),
        staged_code: Some(Box::new(hotp_code("222222", 8))),
        completed_at,
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            ..
        } => {
            assert_eq!(
                r.counter_used, 8,
                "staged code must replace the prior reveal"
            );
            assert_eq!(
                r.code.expose_secret(),
                "222222",
                "reveal must show the staged code, not the prior code"
            );
            assert_eq!(
                r.deadline,
                hotp_reveal_deadline(completed_at),
                "reveal deadline must rebase off the latest `completed_at`"
            );
        }
        other => panic!("expected Unlocked with replaced reveal, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_err_save_not_committed_with_staged_code_does_not_open_reveal() {
    // Defensive guard: only `Err(SaveDurabilityUnconfirmed)` may publish
    // the staged code to the reveal slot. A pre-commit failure
    // (`SaveNotCommitted`) with a staged code attached (which the
    // executor should not produce, but the reducer must not trust)
    // leaves the reveal unchanged — the in-memory counter has been
    // rolled back inside `Vault::hotp_advance` and the user must not
    // see a code that is no longer the on-disk state.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");

    let t0 = Instant::now();
    let prior = open_reveal(hotp_id, 7, "111111", t0);
    let state = unlocked_with_reveal(path, vault, store, Some(hotp_id), Some(prior));

    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: hotp_id,
        result: Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        }),
        staged_code: Some(Box::new(hotp_code("999999", 8))),
        completed_at: t0,
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            hotp_reveal: Some(r),
            ..
        } => {
            assert_eq!(
                r.counter_used, 7,
                "pre-commit failure must not replace the prior reveal even if a staged code is attached"
            );
            assert_eq!(
                r.code.expose_secret(),
                "111111",
                "prior reveal's code must remain visible"
            );
        }
        other => panic!("expected Unlocked with prior reveal preserved, got {other:?}"),
    }
}

#[test]
fn effect_result_hotp_advance_err_save_durability_unconfirmed_with_staged_code_on_non_unlocked_drops(
) {
    // Defensive case: a result arriving while the app is no longer
    // `Unlocked` must drop the staged code (and its OTP digits) without
    // mutating the current state. Matches the existing drop-on-Unlock
    // test for `Ok(code)`.
    use paladin_tui::prompt::PassphraseBuffer;
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Unlock {
        path: path.clone(),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    let event = AppEvent::EffectResult(EffectResult::HotpAdvance {
        account_id: AccountId::new(),
        result: Err(PaladinError::SaveDurabilityUnconfirmed),
        staged_code: Some(Box::new(hotp_code("424242", 9))),
        completed_at: Instant::now(),
    });

    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlock { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Unlock unchanged, got {other:?}"),
    }
}
