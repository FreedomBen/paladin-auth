// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reducer tests for the in-app create-vault wizard.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Startup / vault modes" and
//! `DESIGN.md` §6: when the vault is missing the TUI walks the user
//! through creation in-app. These tests pin every transition of the
//! [`CreateVaultStep`] state machine plus the executor-result reducer
//! (`Ok(...)` lands on `Unlocked` with an empty list; `Err(...)`
//! stays on `CreateVault` with an inline error).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use paladin_core::{EncryptionOptions, PaladinError, Store, Vault, VaultInit};
use secrecy::SecretString;

use paladin_tui::app::event::{AppEvent, CreateVaultInit, Effect, EffectResult};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{AppState, CreateVaultMode, CreateVaultStep, PassphraseFieldFocus};

fn key(code: KeyCode) -> AppEvent {
    key_with(code, KeyModifiers::NONE)
}

fn key_with(code: KeyCode, modifiers: KeyModifiers) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }),
        at: Instant::now(),
    }
}

fn p(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn initial(path: &str) -> AppState {
    AppState::create_vault_initial(PathBuf::from(path))
}

fn assert_choose_mode(state: &AppState, expected: CreateVaultMode) {
    match state {
        AppState::CreateVault {
            step: CreateVaultStep::ChooseMode { selection },
            error: None,
            ..
        } => assert_eq!(*selection, expected, "selection mismatch"),
        other => panic!("expected CreateVault ChooseMode, got {other:?}"),
    }
}

// ---------- ChooseMode ----------

#[test]
fn create_vault_choose_mode_defaults_to_encrypted() {
    let state = initial("/tmp/missing.bin");
    assert_choose_mode(&state, CreateVaultMode::Encrypted);
}

#[test]
fn create_vault_choose_mode_j_toggles_to_plaintext() {
    let (state, fx) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Char('j')));
    assert!(fx.is_empty());
    assert_choose_mode(&state, CreateVaultMode::Plaintext);
}

#[test]
fn create_vault_choose_mode_k_toggles_back_to_encrypted() {
    let (state, _) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Char('j')));
    let (state, fx) = reduce(state, key(KeyCode::Char('k')));
    assert!(fx.is_empty());
    assert_choose_mode(&state, CreateVaultMode::Encrypted);
}

#[test]
fn create_vault_choose_mode_down_arrow_toggles() {
    let (state, _) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Down));
    assert_choose_mode(&state, CreateVaultMode::Plaintext);
}

#[test]
fn create_vault_choose_mode_up_arrow_toggles_back() {
    let (state, _) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Down));
    let (state, _) = reduce(state, key(KeyCode::Up));
    assert_choose_mode(&state, CreateVaultMode::Encrypted);
}

#[test]
fn create_vault_choose_mode_enter_on_encrypted_advances_to_enter_passphrase() {
    let (state, fx) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Enter));
    assert!(fx.is_empty());
    match state {
        AppState::CreateVault {
            step:
                CreateVaultStep::EnterPassphrase {
                    passphrase,
                    confirmation,
                    focus,
                },
            error,
            ..
        } => {
            assert!(passphrase.is_empty());
            assert!(confirmation.is_empty());
            assert_eq!(focus, PassphraseFieldFocus::Passphrase);
            assert_eq!(error, None);
        }
        other => panic!("expected CreateVault EnterPassphrase, got {other:?}"),
    }
}

#[test]
fn create_vault_choose_mode_enter_on_plaintext_advances_to_confirm_plaintext() {
    let (state, _) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Char('j')));
    let (state, fx) = reduce(state, key(KeyCode::Enter));
    assert!(fx.is_empty());
    assert!(matches!(
        state,
        AppState::CreateVault {
            step: CreateVaultStep::ConfirmPlaintext,
            error: None,
            ..
        }
    ));
}

#[test]
fn create_vault_choose_mode_esc_quits() {
    let (state, fx) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Esc));
    assert!(matches!(fx[..], [Effect::Quit]));
    assert!(matches!(state, AppState::CreateVault { .. }));
}

#[test]
fn create_vault_choose_mode_q_quits() {
    let (state, fx) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Char('q')));
    assert!(matches!(fx[..], [Effect::Quit]));
    assert!(matches!(state, AppState::CreateVault { .. }));
}

#[test]
fn create_vault_choose_mode_ctrl_c_quits() {
    let (_state, fx) = reduce(
        initial("/tmp/missing.bin"),
        key_with(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(matches!(fx[..], [Effect::Quit]));
}

// ---------- ConfirmPlaintext ----------

fn at_confirm_plaintext() -> AppState {
    let (state, _) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Char('j')));
    let (state, _) = reduce(state, key(KeyCode::Enter));
    state
}

#[test]
fn create_vault_confirm_plaintext_enter_emits_create_effect() {
    let (state, fx) = reduce(at_confirm_plaintext(), key(KeyCode::Enter));
    match &fx[..] {
        [Effect::CreateVault {
            path,
            init: CreateVaultInit::Plaintext,
        }] => assert_eq!(path, &PathBuf::from("/tmp/missing.bin")),
        other => panic!("expected single CreateVault Plaintext effect, got {other:?}"),
    }
    // State is unchanged until the executor's EffectResult arrives.
    assert!(matches!(
        state,
        AppState::CreateVault {
            step: CreateVaultStep::ConfirmPlaintext,
            ..
        }
    ));
}

#[test]
fn create_vault_confirm_plaintext_esc_returns_to_choose_mode_plaintext_selected() {
    let (state, fx) = reduce(at_confirm_plaintext(), key(KeyCode::Esc));
    assert!(fx.is_empty(), "Esc on ConfirmPlaintext must NOT quit");
    assert_choose_mode(&state, CreateVaultMode::Plaintext);
}

#[test]
fn create_vault_confirm_plaintext_q_quits() {
    let (_state, fx) = reduce(at_confirm_plaintext(), key(KeyCode::Char('q')));
    assert!(matches!(fx[..], [Effect::Quit]));
}

#[test]
fn create_vault_confirm_plaintext_ctrl_c_quits() {
    let (_state, fx) = reduce(
        at_confirm_plaintext(),
        key_with(KeyCode::Char('c'), KeyModifiers::CONTROL),
    );
    assert!(matches!(fx[..], [Effect::Quit]));
}

// ---------- EnterPassphrase ----------

fn at_enter_passphrase() -> AppState {
    let (state, _) = reduce(initial("/tmp/missing.bin"), key(KeyCode::Enter));
    state
}

fn passphrase_focus(state: &AppState) -> PassphraseFieldFocus {
    match state {
        AppState::CreateVault {
            step: CreateVaultStep::EnterPassphrase { focus, .. },
            ..
        } => *focus,
        other => panic!("expected EnterPassphrase, got {other:?}"),
    }
}

fn passphrase_buffer(state: &AppState) -> String {
    match state {
        AppState::CreateVault {
            step: CreateVaultStep::EnterPassphrase { passphrase, .. },
            ..
        } => passphrase.as_str().to_owned(),
        other => panic!("expected EnterPassphrase, got {other:?}"),
    }
}

fn confirmation_buffer(state: &AppState) -> String {
    match state {
        AppState::CreateVault {
            step: CreateVaultStep::EnterPassphrase { confirmation, .. },
            ..
        } => confirmation.as_str().to_owned(),
        other => panic!("expected EnterPassphrase, got {other:?}"),
    }
}

#[test]
fn create_vault_enter_passphrase_typed_chars_append_to_focused_field() {
    let mut state = at_enter_passphrase();
    for c in "secret".chars() {
        let (next, fx) = reduce(state, key(KeyCode::Char(c)));
        assert!(fx.is_empty());
        state = next;
    }
    assert_eq!(passphrase_buffer(&state), "secret");
    assert_eq!(confirmation_buffer(&state), "");
}

#[test]
fn create_vault_enter_passphrase_q_is_a_typed_char_in_passphrase_field() {
    let (state, fx) = reduce(at_enter_passphrase(), key(KeyCode::Char('q')));
    assert!(fx.is_empty(), "q in EnterPassphrase must NOT quit");
    assert_eq!(passphrase_buffer(&state), "q");
}

#[test]
fn create_vault_enter_passphrase_backspace_pops_from_focused_field() {
    let (state, _) = reduce(at_enter_passphrase(), key(KeyCode::Char('a')));
    let (state, _) = reduce(state, key(KeyCode::Char('b')));
    let (state, _) = reduce(state, key(KeyCode::Backspace));
    assert_eq!(passphrase_buffer(&state), "a");
}

#[test]
fn create_vault_enter_passphrase_tab_toggles_focus() {
    let state = at_enter_passphrase();
    assert_eq!(passphrase_focus(&state), PassphraseFieldFocus::Passphrase);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(passphrase_focus(&state), PassphraseFieldFocus::Confirmation);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(passphrase_focus(&state), PassphraseFieldFocus::Passphrase);
}

#[test]
fn create_vault_enter_passphrase_down_arrow_toggles_focus() {
    let (state, _) = reduce(at_enter_passphrase(), key(KeyCode::Down));
    assert_eq!(passphrase_focus(&state), PassphraseFieldFocus::Confirmation);
}

#[test]
fn create_vault_enter_passphrase_up_arrow_toggles_focus() {
    let (state, _) = reduce(at_enter_passphrase(), key(KeyCode::Down));
    let (state, _) = reduce(state, key(KeyCode::Up));
    assert_eq!(passphrase_focus(&state), PassphraseFieldFocus::Passphrase);
}

#[test]
fn create_vault_enter_passphrase_enter_on_passphrase_moves_focus_to_confirmation() {
    let (state, _) = reduce(at_enter_passphrase(), key(KeyCode::Char('a')));
    let (state, fx) = reduce(state, key(KeyCode::Enter));
    assert!(fx.is_empty());
    assert_eq!(passphrase_focus(&state), PassphraseFieldFocus::Confirmation);
}

#[test]
fn create_vault_enter_passphrase_enter_on_empty_passphrase_sets_inline_error() {
    let (state, fx) = reduce(at_enter_passphrase(), key(KeyCode::Enter));
    assert!(fx.is_empty(), "empty passphrase must NOT dispatch effect");
    match state {
        AppState::CreateVault {
            step: CreateVaultStep::EnterPassphrase { .. },
            error: Some(msg),
            ..
        } => assert!(
            msg.to_lowercase().contains("passphrase"),
            "error should mention passphrase, got {msg:?}"
        ),
        other => panic!("expected EnterPassphrase with error, got {other:?}"),
    }
}

#[test]
fn create_vault_enter_passphrase_matching_confirmation_emits_encrypted_effect() {
    let mut state = at_enter_passphrase();
    for c in "hunter2".chars() {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    let (mut state, _) = reduce(state, key(KeyCode::Tab));
    for c in "hunter2".chars() {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    let (state, fx) = reduce(state, key(KeyCode::Enter));
    match &fx[..] {
        [Effect::CreateVault {
            path,
            init: CreateVaultInit::Encrypted(secret),
        }] => {
            use secrecy::ExposeSecret;
            assert_eq!(path, &PathBuf::from("/tmp/missing.bin"));
            assert_eq!(secret.expose_secret(), "hunter2");
        }
        other => panic!("expected single CreateVault Encrypted effect, got {other:?}"),
    }
    // State stays in CreateVault until the executor's EffectResult arrives,
    // but the passphrase buffer should be drained (taken into the SecretString).
    assert_eq!(passphrase_buffer(&state), "");
    assert_eq!(confirmation_buffer(&state), "");
}

#[test]
fn create_vault_enter_passphrase_mismatch_clears_confirmation_and_focuses_it() {
    let mut state = at_enter_passphrase();
    for c in "right".chars() {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    let (mut state, _) = reduce(state, key(KeyCode::Tab));
    for c in "wrong".chars() {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    let (state, fx) = reduce(state, key(KeyCode::Enter));
    assert!(fx.is_empty(), "mismatch must NOT dispatch effect");
    match state {
        AppState::CreateVault {
            step:
                CreateVaultStep::EnterPassphrase {
                    passphrase,
                    confirmation,
                    focus,
                },
            error: Some(msg),
            ..
        } => {
            assert_eq!(
                passphrase.as_str(),
                "right",
                "passphrase buffer must be preserved on mismatch"
            );
            assert_eq!(
                confirmation.as_str(),
                "",
                "confirmation buffer must be zeroized on mismatch"
            );
            assert_eq!(focus, PassphraseFieldFocus::Confirmation);
            assert!(
                msg.to_lowercase().contains("match"),
                "error should mention match, got {msg:?}"
            );
        }
        other => panic!("expected EnterPassphrase with inline error, got {other:?}"),
    }
}

#[test]
fn create_vault_enter_passphrase_esc_returns_to_choose_mode_and_zeroizes() {
    let (state, _) = reduce(at_enter_passphrase(), key(KeyCode::Char('a')));
    let (state, fx) = reduce(state, key(KeyCode::Esc));
    assert!(fx.is_empty(), "Esc on EnterPassphrase must NOT quit");
    assert_choose_mode(&state, CreateVaultMode::Encrypted);
}

#[test]
fn create_vault_enter_passphrase_ctrl_c_quits() {
    let (state, _) = reduce(at_enter_passphrase(), key(KeyCode::Char('a')));
    let (_state, fx) = reduce(state, key_with(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(matches!(fx[..], [Effect::Quit]));
}

// ---------- EffectResult::CreateVault ----------

fn create_actual_vault(dir: &tempfile::TempDir, encrypted: bool) -> (Vault, Store) {
    // `Store::create` enforces a 0700 parent-dir mode per DESIGN.md §4.3.
    // The system umask in test environments often produces 0770 dirs, so
    // tighten it explicitly before the create call.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let path = dir.path().join("vault.bin");
    let init = if encrypted {
        VaultInit::Encrypted(EncryptionOptions::new(p("hunter2")).unwrap())
    } else {
        VaultInit::Plaintext
    };
    let (vault, store) = Store::create(&path, init).unwrap();
    vault.save(&store).unwrap();
    Store::open(
        &path,
        if encrypted {
            paladin_core::VaultLock::Encrypted(p("hunter2"))
        } else {
            paladin_core::VaultLock::Plaintext
        },
    )
    .unwrap()
}

#[test]
fn create_vault_effect_result_ok_transitions_to_unlocked_with_empty_list() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, store) = create_actual_vault(&dir, false);
    let state = AppState::create_vault_initial(dir.path().join("vault.bin"));
    let result_event = AppEvent::EffectResult(EffectResult::CreateVault {
        result: Ok((vault, store)),
        opened_at: Instant::now()
            .checked_sub(Duration::from_millis(10))
            .unwrap(),
    });
    let (next, fx) = reduce(state, result_event);
    assert!(fx.is_empty());
    match next {
        AppState::Unlocked {
            search_query,
            selected,
            modal,
            help_open,
            ..
        } => {
            assert_eq!(search_query, "");
            assert_eq!(selected, None, "fresh vault has no accounts to select");
            assert!(modal.is_none());
            assert!(!help_open);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn create_vault_effect_result_err_keeps_create_vault_with_inline_error() {
    // Simulate an unsafe_permissions failure by constructing the error.
    let state = at_enter_passphrase();
    let result_event = AppEvent::EffectResult(EffectResult::CreateVault {
        result: Err(PaladinError::IoError {
            operation: "save_vault",
            source: std::io::Error::other("disk full"),
        }),
        opened_at: Instant::now(),
    });
    let (next, fx) = reduce(state, result_event);
    assert!(fx.is_empty());
    match next {
        AppState::CreateVault {
            step:
                CreateVaultStep::EnterPassphrase {
                    passphrase,
                    confirmation,
                    ..
                },
            error: Some(msg),
            ..
        } => {
            assert_eq!(
                passphrase.as_str(),
                "",
                "passphrase buffer must be zeroized on error"
            );
            assert_eq!(
                confirmation.as_str(),
                "",
                "confirmation buffer must be zeroized on error"
            );
            assert!(msg.to_lowercase().contains("disk"), "got {msg:?}");
        }
        other => panic!("expected CreateVault EnterPassphrase with inline error, got {other:?}"),
    }
}
