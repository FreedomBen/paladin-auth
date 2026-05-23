// SPDX-License-Identifier: AGPL-3.0-or-later

//! Help-overlay reducer tests for `paladin-tui`.
//!
//! Tracks `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Help overlay" and the
//! "Implementation checklist" item *"Implement the read-only Help
//! overlay (`?` from list focus, `Esc` to close); … suppress `?` on
//! the unlock, create-vault, and startup-error screens."*
//!
//! The overlay is a single boolean slot on
//! [`paladin_tui::app::state::AppState::Unlocked`]; `?` opens it from
//! list focus when no modal is open, `Esc` closes it (highest
//! precedence on Unlocked), and every other key is a silent no-op
//! while it is visible — so the overlay is genuinely read-only and
//! cannot bleed actions into the underlying list view. View-level
//! rendering of the keybinding table rides with the view slice.

mod common;

use common::test_tempdir;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, Argon2Params,
    EncryptionOptions, IconHintInput, Store, Vault, VaultInit, VaultLock,
};
use paladin_tui::app::event::AppEvent;
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{AppState, Focus, Modal, SettingsModal};
use paladin_tui::prompt::PassphraseBuffer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        at: Instant::now(),
    }
}

fn key_with_mods(code: KeyCode, mods: KeyModifiers) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, mods)),
        at: Instant::now(),
    }
}

fn tick_at(now: Instant) -> AppEvent {
    AppEvent::Tick {
        wall_clock: SystemTime::now(),
        monotonic: now,
    }
}

fn secure_tempdir() -> tempfile::TempDir {
    let dir = test_tempdir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

fn open_plaintext_pair(path: &Path) -> (Vault, Store) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(path, VaultLock::Plaintext).expect("reopen plaintext")
}

fn light_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    }
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
    vault.save(store).expect("commit account");
    id
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

/// Build an `Unlocked` state with sane defaults. Callers can mutate
/// individual fields on the returned state for the specific
/// behaviour under test (e.g. set `help_open = true`, switch focus,
/// open a modal).
fn unlocked_default(path: PathBuf, vault: Vault, store: Store) -> AppState {
    AppState::Unlocked {
        path,
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

/// Build an `Unlocked` state pre-opened against a fresh plaintext
/// vault with `help_open = true`. Each call gets its own tempdir so
/// callers can iterate independently in a single test.
fn unlocked_with_help_open(tmp: &tempfile::TempDir, name: &str) -> AppState {
    let path = tmp.path().join(format!("{name}.bin"));
    let (vault, store) = open_plaintext_pair(&path);
    let mut state = unlocked_default(path, vault, store);
    if let AppState::Unlocked { help_open, .. } = &mut state {
        *help_open = true;
    }
    state
}

fn assert_help_open(state: &AppState, expected: bool, msg: &str) {
    match state {
        AppState::Unlocked { help_open, .. } => assert_eq!(*help_open, expected, "{msg}"),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Opening: `?` from list focus
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Help overlay)
// ---------------------------------------------------------------------------

#[test]
fn question_mark_on_unlocked_with_list_focus_and_no_modal_opens_help() {
    // Base case: `?` opens the read-only Help overlay when the user
    // is on the list view (`focus = List`, no modal open) and the
    // overlay is not already visible. The overlay opens entirely in
    // state — no effects emitted.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let state = unlocked_default(path, vault, store);

    let (next, effects) = reduce(state, key(KeyCode::Char('?')));
    assert!(effects.is_empty(), "opening Help must not emit effects");
    assert_help_open(&next, true, "`?` from list focus must open Help");
}

#[test]
fn question_mark_with_shift_modifier_still_opens_help() {
    // Some terminals report `Shift+?` (since `?` is the shifted form
    // of `/` on US keyboards) — the reducer must accept either
    // shape, mirroring the `R` / `r` modal-opener convention. CONTROL
    // and ALT remain filtered out by the existing modifier guard.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let state = unlocked_default(path, vault, store);

    let (next, effects) = reduce(
        state,
        key_with_mods(KeyCode::Char('?'), KeyModifiers::SHIFT),
    );
    assert!(effects.is_empty());
    assert_help_open(&next, true, "Shift+`?` must still open Help");
}

#[test]
fn question_mark_with_ctrl_modifier_does_not_open_help() {
    // `Ctrl-?` is unbound — the existing Ctrl/Alt guard short-circuits
    // before any bare-letter handler can fire, so the overlay stays
    // closed.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let state = unlocked_default(path, vault, store);

    let (next, effects) = reduce(
        state,
        key_with_mods(KeyCode::Char('?'), KeyModifiers::CONTROL),
    );
    assert!(effects.is_empty());
    assert_help_open(&next, false, "Ctrl-`?` must not open Help");
}

#[test]
fn question_mark_with_search_focus_routes_to_search_query() {
    // Per the spec: "While the search bar is focused or any modal is
    // open, `?` is consumed as character input by text fields (parity
    // with the other action keys)." The Focus::Search routing
    // pushes the literal `?` into the query and the overlay stays
    // closed.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    add_totp_account(&mut vault, &store, "alice");
    let mut state = unlocked_default(path, vault, store);
    if let AppState::Unlocked {
        focus,
        search_query,
        ..
    } = &mut state
    {
        *focus = Focus::Search;
        search_query.clear();
    }

    let (next, effects) = reduce(state, key(KeyCode::Char('?')));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            help_open,
            focus,
            search_query,
            ..
        } => {
            assert!(!help_open, "`?` on Focus::Search must not open Help");
            assert_eq!(focus, Focus::Search, "focus must stay on the search bar");
            assert_eq!(
                search_query, "?",
                "`?` on Focus::Search must be typed into the search query"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn question_mark_with_modal_open_does_not_open_help() {
    // With a modal open, bare-letter keys (including `?`) are
    // consumed by the modal-local input path (text fields when the
    // modal payloads land). The Help overlay is list-focus-only.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let mut state = unlocked_default(path, vault, store);
    if let AppState::Unlocked { modal, .. } = &mut state {
        *modal = Some(Modal::Settings(SettingsModal::default()));
    }

    let (next, effects) = reduce(state, key(KeyCode::Char('?')));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            help_open, modal, ..
        } => {
            assert!(!help_open, "`?` with a modal open must not open Help");
            assert!(
                matches!(modal, Some(Modal::Settings(_))),
                "modal must be preserved unchanged, got {modal:?}"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn question_mark_when_help_already_open_is_idempotent() {
    // Re-pressing `?` while the overlay is already visible leaves
    // it visible — `help_open` is a boolean, so re-asserting `true`
    // is a no-op observably.
    let tmp = secure_tempdir();
    let state = unlocked_with_help_open(&tmp, "plain");

    let (next, effects) = reduce(state, key(KeyCode::Char('?')));
    assert!(effects.is_empty());
    assert_help_open(&next, true, "re-pressing `?` must leave Help open");
}

// ---------------------------------------------------------------------------
// Closing: `Esc` closes Help (highest precedence on Unlocked)
// ---------------------------------------------------------------------------

#[test]
fn esc_with_help_open_closes_help_and_leaves_other_state_untouched() {
    // `Esc` has the highest dismissable-affordance precedence on
    // Unlocked: Help-close > modal-close > search-clear. When the
    // overlay is open the modal slot is `None` by construction
    // (the opener guard refuses to fire with a modal open) and the
    // focus is `List` (the opener guard refuses to fire on
    // `Focus::Search`), so this test pins the no-op-on-sibling
    // contract: search query and modal slot are preserved by
    // construction. Pending chord-leader state must still be
    // cleared, mirroring the existing Esc contract.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let mut state = unlocked_default(path, vault, store);
    if let AppState::Unlocked {
        help_open,
        search_query,
        ..
    } = &mut state
    {
        *help_open = true;
        // A non-empty search query from before `/` was pressed and
        // Esc'd back to list focus, preserved verbatim through the
        // Help-open → Esc round trip.
        *search_query = "go".to_string();
    }

    let (next, effects) = reduce(state, key(KeyCode::Esc));
    assert!(effects.is_empty(), "Esc closing Help must not emit effects");
    match next {
        AppState::Unlocked {
            help_open,
            modal,
            focus,
            search_query,
            pending_chord_leader,
            ..
        } => {
            assert!(!help_open, "Esc must close Help");
            assert!(modal.is_none(), "Esc must not touch the modal slot");
            assert_eq!(focus, Focus::List, "focus stays on the list");
            assert_eq!(search_query, "go", "search query is preserved");
            assert!(pending_chord_leader.is_none(), "Esc clears chord leader");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn esc_with_help_closed_falls_back_to_existing_esc_handling() {
    // `Esc` with no Help open must still respect the existing
    // precedence: modal-close > search-clear > silent no-op on
    // Focus::List. The Help slice introduces a *new* highest tier
    // but must not regress the lower tiers. Cover the modal-close
    // half (the search-clear half is exercised in reducer_tests.rs).
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let mut state = unlocked_default(path, vault, store);
    if let AppState::Unlocked { modal, .. } = &mut state {
        *modal = Some(Modal::Settings(SettingsModal::default()));
    }

    let (next, effects) = reduce(state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            help_open, modal, ..
        } => {
            assert!(!help_open, "Help stays closed when it was already closed");
            assert!(modal.is_none(), "Esc closes the open modal");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Read-only: other keys are silent no-ops while Help is open
// (Spec: "The overlay has no inputs and never mutates vault state.")
// ---------------------------------------------------------------------------

#[test]
fn modal_opener_keys_are_silent_no_op_while_help_is_open() {
    // While Help is open, the bare-letter modal-opener keys
    // (`a`/`i`/`e`/`r`/`R`/`p`/`s`) must not open a modal underneath
    // the overlay — that would let the overlay's "read-only"
    // contract leak vault-mutating affordances.
    let tmp = secure_tempdir();
    for c in ['a', 'i', 'e', 'r', 'R', 'p', 's'] {
        let state = unlocked_with_help_open(&tmp, &format!("v_{c}"));
        let (next, effects) = reduce(state, key(KeyCode::Char(c)));
        assert!(
            effects.is_empty(),
            "key `{c}` while Help is open must not emit effects"
        );
        match next {
            AppState::Unlocked {
                help_open, modal, ..
            } => {
                assert!(help_open, "Help stays open after `{c}`");
                assert!(modal.is_none(), "`{c}` must not open a modal under Help");
            }
            other => panic!("expected Unlocked, got {other:?}"),
        }
    }
}

#[test]
fn navigation_keys_are_silent_no_op_while_help_is_open() {
    // Selection must not move while Help is open — neither arrow
    // keys nor the vim mirrors should walk the list under the
    // overlay.
    let tmp = secure_tempdir();
    for (idx, code) in [
        KeyCode::Down,
        KeyCode::Up,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::PageDown,
        KeyCode::PageUp,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Char('G'),
    ]
    .into_iter()
    .enumerate()
    {
        let path = tmp.path().join(format!("nav_{idx}.bin"));
        let (mut vault, store) = open_plaintext_pair(&path);
        let first = add_totp_account(&mut vault, &store, "alice");
        let _second = add_totp_account(&mut vault, &store, "bob");
        let mut state = unlocked_default(path, vault, store);
        if let AppState::Unlocked {
            help_open,
            selected,
            ..
        } = &mut state
        {
            *help_open = true;
            *selected = Some(first);
        }

        let (next, effects) = reduce(state, key(code));
        assert!(
            effects.is_empty(),
            "navigation key {code:?} while Help is open must not emit effects"
        );
        match next {
            AppState::Unlocked {
                help_open,
                selected,
                ..
            } => {
                assert!(help_open, "Help stays open after {code:?}");
                assert_eq!(
                    selected,
                    Some(first),
                    "{code:?} must not move selection under Help"
                );
            }
            other => panic!("expected Unlocked, got {other:?}"),
        }
    }
}

#[test]
fn hotp_n_does_not_advance_while_help_is_open() {
    // `n` must not emit `Effect::HotpAdvance` while Help is open —
    // the overlay's read-only contract covers HOTP advancement too.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let hotp_id = add_hotp_account(&mut vault, &store, "hotp");
    let mut state = unlocked_default(path, vault, store);
    if let AppState::Unlocked {
        help_open,
        selected,
        ..
    } = &mut state
    {
        *help_open = true;
        *selected = Some(hotp_id);
    }

    let (next, effects) = reduce(state, key(KeyCode::Char('n')));
    assert!(
        effects.is_empty(),
        "`n` while Help is open must not emit HotpAdvance"
    );
    assert_help_open(&next, true, "Help stays open after suppressed `n`");
}

#[test]
fn q_does_not_quit_while_help_is_open() {
    // `q` is the list-view quit key. While Help is open it is
    // suppressed alongside the other action keys — `Esc` is the
    // sole exit from the overlay. Re-pressing `q` after Esc closes
    // Help still quits (covered in reducer_tests.rs); this test
    // pins only the "no quit through Help" half of the contract.
    let tmp = secure_tempdir();
    let state = unlocked_with_help_open(&tmp, "plain");

    let (next, effects) = reduce(state, key(KeyCode::Char('q')));
    assert!(
        effects.is_empty(),
        "`q` while Help is open must not quit (overlay swallows it)"
    );
    assert_help_open(&next, true, "Help stays open after suppressed `q`");
}

#[test]
fn slash_does_not_focus_search_while_help_is_open() {
    // `/` is the search-bar focus key. While Help is open the
    // overlay swallows it; the user must Esc the overlay first.
    let tmp = secure_tempdir();
    let state = unlocked_with_help_open(&tmp, "plain");

    let (next, _effects) = reduce(state, key(KeyCode::Char('/')));
    match next {
        AppState::Unlocked {
            help_open, focus, ..
        } => {
            assert!(help_open, "Help stays open after suppressed `/`");
            assert_eq!(
                focus,
                Focus::List,
                "`/` must not flip focus to Search through Help"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn ctrl_c_still_quits_while_help_is_open() {
    // `Ctrl-C` is the universal quit chord and must work on every
    // screen — including with the Help overlay open. The reducer
    // dispatches `Ctrl-C` before reaching the Unlocked-specific
    // dispatch, so this test pins that order against a regression
    // where the Help-open guard might be hoisted ahead of it.
    use paladin_tui::app::event::Effect;

    let tmp = secure_tempdir();
    let state = unlocked_with_help_open(&tmp, "plain");

    let (_next, effects) = reduce(
        state,
        key_with_mods(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(
        matches!(effects.as_slice(), [Effect::Quit]),
        "Ctrl-C must always quit, got {effects:?}"
    );
}

// ---------------------------------------------------------------------------
// `?` is suppressed on non-Unlocked screens
// ---------------------------------------------------------------------------

#[test]
fn question_mark_on_create_vault_is_silent_no_op() {
    let state = AppState::create_vault_initial(PathBuf::from("/tmp/missing.bin"));
    let (next, effects) = reduce(state, key(KeyCode::Char('?')));
    assert!(effects.is_empty(), "`?` on CreateVault must emit nothing");
    assert!(
        matches!(next, AppState::CreateVault { .. }),
        "`?` on CreateVault must leave the state unchanged, got {next:?}"
    );
}

#[test]
fn question_mark_on_startup_error_is_silent_no_op() {
    let state = AppState::StartupError {
        path: Some(PathBuf::from("/tmp/err.bin")),
        message: "boom".into(),
    };
    let (next, effects) = reduce(state, key(KeyCode::Char('?')));
    assert!(effects.is_empty(), "`?` on StartupError must emit nothing");
    assert!(
        matches!(next, AppState::StartupError { .. }),
        "`?` on StartupError must leave the state unchanged, got {next:?}"
    );
}

#[test]
fn question_mark_on_unlock_screen_is_consumed_as_passphrase_text() {
    // Per the spec: "The unlock, create-vault, and startup-error
    // screens do not bind `?`." On Unlock the screen is a
    // passphrase-input field — `?` falls through to that text-input
    // path (appended to the typed buffer). The overlay does not
    // open because Help is an Unlocked-only construct.
    use secrecy::ExposeSecret;

    let state = AppState::Unlock {
        path: PathBuf::from("/tmp/v.bin"),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    let (next, effects) = reduce(state, key(KeyCode::Char('?')));
    assert!(effects.is_empty());
    match next {
        AppState::Unlock { mut passphrase, .. } => {
            let secret = passphrase.take();
            assert_eq!(
                secret.expose_secret(),
                "?",
                "`?` on Unlock must be appended to the passphrase buffer"
            );
        }
        other => panic!("expected Unlock, got {other:?}"),
    }
}

#[test]
fn question_mark_on_locked_screen_is_silent_no_op() {
    let state = AppState::Locked {
        path: PathBuf::from("/tmp/v.bin"),
        pending_clipboard_clear: None,
    };
    let (next, effects) = reduce(state, key(KeyCode::Char('?')));
    assert!(effects.is_empty(), "`?` on Locked must emit nothing");
    assert!(
        matches!(next, AppState::Locked { .. }),
        "`?` on Locked must leave the state unchanged, got {next:?}"
    );
}

// ---------------------------------------------------------------------------
// Auto-lock drops `help_open` (Locked has no slot, by variant change)
// ---------------------------------------------------------------------------

#[test]
fn auto_lock_with_help_open_drops_help_state_into_locked() {
    // An auto-lock idle-expiry Tick that fires while the Help
    // overlay is visible must transition to `Locked` (which has no
    // help slot) — the overlay disappears along with the rest of
    // the Unlocked payload. Pins the discard-on-lock contract for
    // future view code that might keep its own copy of `help_open`.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let mut state = unlocked_default(path.clone(), vault, store);
    if let AppState::Unlocked {
        help_open,
        idle_deadline,
        ..
    } = &mut state
    {
        *help_open = true;
        *idle_deadline = Some(deadline);
    }

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "auto-lock transition emits no effects");
    match next {
        AppState::Locked { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}
