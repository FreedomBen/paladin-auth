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
    Argon2Params, EncryptionOptions, IconHintInput, Store, Vault, VaultInit,
};
use paladin_tui::app::event::{AppEvent, Effect};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{AppState, Focus, HotpReveal};

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
