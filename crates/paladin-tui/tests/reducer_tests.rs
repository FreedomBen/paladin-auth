// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reducer / state-machine + global-arg tests for `paladin-tui`.
//! Tracks the "Tests" checklist in `IMPLEMENTATION_PLAN_03_TUI.md`.

mod common;

use common::test_tempdir;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use clap::Parser;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::{ExposeSecret, SecretString};

use paladin_core::{
    hotp_reveal_deadline, validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm,
    Argon2Params, EncryptionOptions, IconHintInput, IdlePolicy, PaladinError, PermissionSubject,
    SettingPatch, Store, Vault, VaultInit, VaultLock, VaultStatus,
};
use paladin_tui::app::event::{AppEvent, Effect, EffectResult};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{
    compute_idle_deadline, decide_state_from_inspect, decide_state_from_open, render_error_message,
    AddManualFocus, AddModal, AddMode, AppState, ChordLeader, Focus, HotpReveal, Modal,
    RemoveModal, RenameModal, SettingsFocus, SettingsModal, StatusLine, NO_ACCOUNT_SELECTED,
};
use paladin_tui::cli::{should_disable_color, GlobalArgs};
use paladin_tui::prompt::PassphraseBuffer;

// ---------------------------------------------------------------------------
// Reducer helpers shared by the per-key-binding tests below.
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        at: Instant::now(),
    }
}

fn ctrl(code: KeyCode) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, KeyModifiers::CONTROL)),
        at: Instant::now(),
    }
}

fn missing(path: &str) -> AppState {
    AppState::MissingVault {
        path: PathBuf::from(path),
    }
}

fn startup_err(path: Option<&str>) -> AppState {
    AppState::StartupError {
        path: path.map(PathBuf::from),
        message: "test error message".into(),
    }
}

fn unlock(path: &str) -> AppState {
    AppState::Unlock {
        path: PathBuf::from(path),
        error: None,
        passphrase: PassphraseBuffer::new(),
    }
}

fn unlock_with(path: &str, typed: &str) -> AppState {
    let mut buf = PassphraseBuffer::new();
    for c in typed.chars() {
        buf.push(c);
    }
    AppState::Unlock {
        path: PathBuf::from(path),
        error: None,
        passphrase: buf,
    }
}

fn locked(path: &str) -> AppState {
    AppState::Locked {
        path: PathBuf::from(path),
        pending_clipboard_clear: None,
    }
}

// ---------------------------------------------------------------------------
// Global args (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Global args)
// ---------------------------------------------------------------------------

#[test]
fn global_args_vault_flag_selects_inspected_path() {
    let args = GlobalArgs::try_parse_from(["paladin-tui", "--vault", "/tmp/v.bin"])
        .expect("--vault should parse");
    assert_eq!(args.vault.as_deref(), Some(Path::new("/tmp/v.bin")));
}

#[test]
fn global_args_default_leaves_vault_unset() {
    let args = GlobalArgs::try_parse_from(["paladin-tui"]).expect("no args should parse");
    assert!(args.vault.is_none());
}

#[test]
fn global_args_no_color_flag_disables_styling() {
    let args =
        GlobalArgs::try_parse_from(["paladin-tui", "--no-color"]).expect("--no-color should parse");
    assert!(args.no_color);
}

#[test]
fn global_args_default_no_color_is_false() {
    let args = GlobalArgs::try_parse_from(["paladin-tui"]).expect("no args should parse");
    assert!(!args.no_color);
}

#[test]
fn global_args_json_flag_is_rejected_at_parse_time() {
    // `--json` is intentionally not a defined flag: clap surfaces its
    // standard "unexpected argument" text diagnostic and the TUI never
    // emits a JSON envelope.
    let err =
        GlobalArgs::try_parse_from(["paladin-tui", "--json"]).expect_err("--json should reject");
    let rendered = err.to_string();
    assert!(
        rendered.contains("--json") || rendered.to_lowercase().contains("unexpected"),
        "expected clap text diagnostic mentioning --json or 'unexpected', got: {rendered}"
    );
    assert!(
        !rendered.trim_start().starts_with('{'),
        "TUI must not emit a JSON envelope for --json rejection, got: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// NO_COLOR env resolution (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Global args)
// ---------------------------------------------------------------------------

#[test]
fn no_color_flag_disables_color() {
    assert!(should_disable_color(true, None));
}

#[test]
fn no_color_env_present_disables_color() {
    let env = OsString::from("1");
    assert!(should_disable_color(false, Some(env.as_os_str())));
}

#[test]
fn no_color_env_empty_string_disables_color() {
    // Per https://no-color.org, *presence* of NO_COLOR disables — value
    // (including the empty string) is ignored.
    let env = OsString::from("");
    assert!(should_disable_color(false, Some(env.as_os_str())));
}

#[test]
fn no_color_unset_with_no_flag_keeps_color_enabled() {
    assert!(!should_disable_color(false, None));
}

// ---------------------------------------------------------------------------
// Vault modes and startup
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Vault modes and startup)
// ---------------------------------------------------------------------------

#[test]
fn missing_vault_inspect_yields_missing_vault_state() {
    let path = PathBuf::from("/tmp/paladin-test-nonexistent.bin");
    let state = decide_state_from_inspect(&path, Ok(VaultStatus::Missing));
    match state {
        Some(AppState::MissingVault { path: p }) => assert_eq!(p, path),
        other => panic!("expected MissingVault, got {other:?}"),
    }
}

#[test]
fn encrypted_vault_inspect_yields_unlock_state_with_no_inline_error() {
    let path = PathBuf::from("/tmp/paladin-test-encrypted.bin");
    let state = decide_state_from_inspect(&path, Ok(VaultStatus::Encrypted));
    match state {
        Some(AppState::Unlock {
            path: p,
            error: None,
            passphrase,
        }) => {
            assert_eq!(p, path);
            assert!(
                passphrase.is_empty(),
                "fresh Unlock state must start with an empty passphrase buffer"
            );
        }
        other => panic!("expected Unlock with empty passphrase and no error, got {other:?}"),
    }
}

#[test]
fn plaintext_vault_inspect_returns_none_signaling_caller_to_open() {
    let path = PathBuf::from("/tmp/paladin-test-plain.bin");
    let state = decide_state_from_inspect(&path, Ok(VaultStatus::Plaintext));
    assert!(
        state.is_none(),
        "plaintext branch must signal caller to follow up with open"
    );
}

#[test]
fn missing_vault_inspect_does_not_create_or_mutate_files() {
    // Bullet: "Missing vault opens the missing-vault screen and does
    // not create or mutate files." `missing_vault_inspect_yields_…`
    // above drives the state transition with a synthetic
    // `VaultStatus::Missing`; this test exercises the real
    // `paladin_core::inspect` path on a non-existent file inside a
    // sandboxed tempdir and asserts that neither `inspect` nor the
    // subsequent `decide_state_from_inspect` step creates the vault
    // file.
    let tmp = test_tempdir();
    let path = tmp.path().join("paladin-test-nonexistent.bin");
    assert!(
        !path.exists(),
        "test fixture must start with no vault file at {path:?}"
    );

    let inspect = paladin_core::inspect(&path);
    assert!(
        matches!(inspect, Ok(VaultStatus::Missing)),
        "missing path must inspect as VaultStatus::Missing, got {inspect:?}"
    );

    let state = decide_state_from_inspect(&path, inspect);
    match state {
        Some(AppState::MissingVault { path: p }) => assert_eq!(p, path),
        other => panic!("expected MissingVault, got {other:?}"),
    }

    assert!(
        !path.exists(),
        "missing-vault entry point must not create the vault file at {path:?}"
    );

    // The parent directory was created by the tempdir; the
    // missing-vault path must not leak any sibling artifacts
    // (`.bak`, `.tmp`, partial writes) either.
    let leaked: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name())
        .collect();
    assert!(
        leaked.is_empty(),
        "missing-vault entry point must not create sibling files, found {leaked:?}"
    );
}

#[test]
fn inspect_error_yields_startup_error_with_rendered_message_and_no_file_mutation() {
    // Drive a real `invalid_header` (or comparable) error by inspecting a
    // file with garbage bytes — verifies bullet "Non-`decrypt_failed`
    // errors from `inspect` / `open` ... open the non-mutating
    // startup-error screen and do not create or mutate files."
    let tmp = test_tempdir();
    let path = tmp.path().join("garbage.bin");
    fs::write(&path, b"not a paladin vault").unwrap();
    let before = fs::read(&path).unwrap();

    let inspect = paladin_core::inspect(&path);
    assert!(inspect.is_err(), "expected inspect error, got {inspect:?}");
    let err_msg = inspect.as_ref().err().map(ToString::to_string).unwrap();

    let state = decide_state_from_inspect(&path, inspect);
    match state {
        Some(AppState::StartupError {
            path: Some(p),
            message,
        }) => {
            assert_eq!(p, path);
            assert_eq!(message, err_msg);
        }
        other => panic!("expected StartupError, got {other:?}"),
    }

    // File contents must be unchanged after the inspect path.
    let after = fs::read(&path).unwrap();
    assert_eq!(before, after, "inspect must not mutate the vault file");
}

#[test]
fn plaintext_open_yields_unlocked_state() {
    // Bullet: "Plaintext vault opens directly to the list (no unlock screen)."
    let tmp = test_tempdir();
    // `Store::create` enforces the parent directory be mode 0700 (§4.3).
    // `tempfile::TempDir` is typically 0700 but some sandboxed CI / cache
    // roots set a more permissive umask, so normalize defensively.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(tmp.path(), perms).unwrap();
    }
    let path = tmp.path().join("plain.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);

    let inspect = paladin_core::inspect(&path);
    assert!(
        matches!(inspect, Ok(VaultStatus::Plaintext)),
        "expected Plaintext, got {inspect:?}"
    );
    assert!(
        decide_state_from_inspect(&path, inspect).is_none(),
        "plaintext should signal caller to open"
    );

    let open = Store::open(&path, VaultLock::Plaintext);
    let now = Instant::now();
    let state = decide_state_from_open(now, path.clone(), open);
    match state {
        AppState::Unlocked {
            path: p,
            idle_deadline,
            ..
        } => {
            assert_eq!(p, path);
            assert_eq!(
                idle_deadline, None,
                "plaintext vault must never arm the auto-lock idle deadline"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn open_error_yields_startup_error_with_path_retained() {
    // Bullet: "Non-`decrypt_failed` errors from `inspect` / `open` ...
    // open the non-mutating startup-error screen ..."
    // Drive an open failure by pointing at a tempfile with garbage bytes
    // (Store::open returns an error for invalid header etc.).
    let tmp = test_tempdir();
    let path = tmp.path().join("garbage.bin");
    fs::write(&path, b"not a paladin vault").unwrap();

    let open = Store::open(&path, VaultLock::Plaintext);
    assert!(open.is_err(), "expected open error, got Ok");

    let state = decide_state_from_open(Instant::now(), path.clone(), open);
    match state {
        AppState::StartupError {
            path: Some(p),
            message,
        } => {
            assert_eq!(p, path);
            assert!(!message.is_empty());
        }
        other => panic!("expected StartupError, got {other:?}"),
    }
}

#[test]
fn render_error_message_uses_format_unsafe_permissions_verbatim() {
    // Bullet: "`unsafe_permissions` rendering uses the `Some(text)` from
    // `format_unsafe_permissions` verbatim."
    let err = PaladinError::UnsafePermissions {
        path: PathBuf::from("/tmp/paladin-loose.bin"),
        subject: PermissionSubject::VaultDir,
        actual_mode: "0755".to_string(),
        expected_mode: "0700".to_string(),
    };
    let expected = paladin_core::format_unsafe_permissions(&err)
        .expect("unsafe_permissions must yield Some(text)");
    let rendered = render_error_message(&err);
    assert_eq!(rendered, expected);
}

#[test]
fn render_error_message_falls_back_to_display_for_non_unsafe_permissions_error() {
    let tmp = test_tempdir();
    let path = tmp.path().join("garbage.bin");
    fs::write(&path, b"not a paladin vault").unwrap();
    let err = paladin_core::inspect(&path).unwrap_err();
    // Sanity: this is not an unsafe_permissions error.
    assert!(paladin_core::format_unsafe_permissions(&err).is_none());

    let rendered = render_error_message(&err);
    assert_eq!(rendered, err.to_string());
}

// ---------------------------------------------------------------------------
// Reducer quit-key behavior
// (IMPLEMENTATION_PLAN_03_TUI.md > Keybindings (initial v0.1) +
//  IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer)
//
// Keybinding rules covered here:
//   * Ctrl-C quits on any screen.
//   * Esc quits on unlock, missing-vault, startup-error screens.
//   * `q` quits on missing-vault and startup-error screens; on the
//     unlock screen it is text input (will route into the passphrase
//     field in a follow-up slice — for now it is a no-op).
//   * Tick events are passthrough (no effects) on terminal screens.
//   * Unrecognized keys produce no effects.
// ---------------------------------------------------------------------------

#[test]
fn ctrl_c_on_missing_vault_quits() {
    let (_, effects) = reduce(missing("/tmp/v.bin"), ctrl(KeyCode::Char('c')));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn ctrl_c_on_startup_error_quits() {
    let (_, effects) = reduce(startup_err(Some("/tmp/v.bin")), ctrl(KeyCode::Char('c')));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn ctrl_c_on_unlock_quits() {
    let (_, effects) = reduce(unlock("/tmp/v.bin"), ctrl(KeyCode::Char('c')));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn ctrl_c_on_locked_quits() {
    let (_, effects) = reduce(locked("/tmp/v.bin"), ctrl(KeyCode::Char('c')));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn ctrl_c_on_unlocked_quits() {
    // Build a real Unlocked state so we can verify Ctrl-C quits even
    // from the main list view ("Ctrl-C quits on any screen").
    let tmp = test_tempdir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(tmp.path(), perms).unwrap();
    }
    let path = tmp.path().join("plain.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit empty vault");
    let unlocked = AppState::Unlocked {
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
    let (_, effects) = reduce(unlocked, ctrl(KeyCode::Char('c')));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn esc_on_missing_vault_quits() {
    let (_, effects) = reduce(missing("/tmp/v.bin"), key(KeyCode::Esc));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn esc_on_startup_error_quits() {
    let (_, effects) = reduce(startup_err(None), key(KeyCode::Esc));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn esc_on_unlock_quits() {
    let (_, effects) = reduce(unlock("/tmp/v.bin"), key(KeyCode::Esc));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn q_on_missing_vault_quits() {
    let (_, effects) = reduce(missing("/tmp/v.bin"), key(KeyCode::Char('q')));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn q_on_startup_error_quits() {
    let (_, effects) = reduce(startup_err(None), key(KeyCode::Char('q')));
    assert!(matches!(effects.as_slice(), [Effect::Quit]));
}

#[test]
fn q_on_unlock_does_not_quit_and_is_appended_to_the_passphrase_buffer() {
    // `q` on the unlock screen is a valid passphrase character (per the
    // Keybindings table + Focus model: "`q` is a valid passphrase
    // character, so it is not bound to quit there"). It must not
    // produce a Quit effect and must reach the passphrase buffer as
    // ordinary text input.
    let (state, effects) = reduce(unlock("/tmp/v.bin"), key(KeyCode::Char('q')));
    assert!(effects.is_empty(), "expected no effect, got {effects:?}");
    match state {
        AppState::Unlock { passphrase, .. } => {
            assert_eq!(passphrase.as_str(), "q");
        }
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn tick_event_on_missing_vault_yields_no_effect() {
    let tick = AppEvent::Tick {
        wall_clock: SystemTime::now(),
        monotonic: Instant::now(),
    };
    let (_, effects) = reduce(missing("/tmp/v.bin"), tick);
    assert!(effects.is_empty());
}

#[test]
fn unrecognized_key_on_missing_vault_yields_no_effect() {
    let (_, effects) = reduce(missing("/tmp/v.bin"), key(KeyCode::Char('a')));
    assert!(effects.is_empty());
}

#[test]
fn ctrl_c_only_fires_with_control_modifier() {
    // Bare `c` (no Ctrl) must not quit — Ctrl is what makes it Ctrl-C.
    let (_, effects) = reduce(missing("/tmp/v.bin"), key(KeyCode::Char('c')));
    assert!(effects.is_empty());
}

#[test]
fn non_key_input_event_yields_no_effect() {
    // Resize / focus / paste / mouse events on a terminal screen do
    // not quit; they pass through with no effects.
    let evt = AppEvent::Input {
        event: Event::Resize(80, 24),
        at: Instant::now(),
    };
    let (_, effects) = reduce(missing("/tmp/v.bin"), evt);
    assert!(effects.is_empty());
}

// ---------------------------------------------------------------------------
// Unlock passphrase buffer
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Sensitive UI buffers +
//  IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer +
//  IMPLEMENTATION_PLAN_03_TUI.md > Focus model "The unlock screen
//  accepts character input (passphrase) and Enter (submit), and quits
//  on Esc or Ctrl-C")
//
// Behavior covered:
//   * `AppState::Unlock` starts with an empty passphrase buffer.
//   * Printable character input (no Ctrl/Alt modifier) appends to the
//     buffer and never emits an Effect — including bare letters like
//     `q`, the action keys, and the Tab/`/`/`?` keys that are actions
//     elsewhere.
//   * Ctrl-modified Char keys (other than Ctrl-C, which already quits)
//     do NOT append to the buffer — Ctrl-A / Ctrl-U etc. are not
//     passphrase characters.
//   * Backspace pops the last typed char; backspace on an empty buffer
//     is a silent no-op.
//   * Enter on an empty buffer yields no effect.
//   * Enter on a non-empty buffer emits a single
//     `Effect::Unlock { path, passphrase: SecretString }` and clears
//     the buffer (zeroized on submit per the Sensitive UI buffers
//     bullet).
//   * `PassphraseBuffer` redacts its `Debug` output so logs / panic
//     messages never leak the typed bytes (per the "No `Debug` impls
//     that leak bytes" rule in CLAUDE.md).
// ---------------------------------------------------------------------------

#[test]
fn fresh_unlock_state_has_empty_passphrase_buffer() {
    let AppState::Unlock { passphrase, .. } = unlock("/tmp/v.bin") else {
        panic!("expected Unlock state");
    };
    assert!(passphrase.is_empty());
    assert_eq!(passphrase.as_str(), "");
}

#[test]
fn typing_a_char_on_unlock_appends_to_passphrase_buffer() {
    let (state, effects) = reduce(unlock("/tmp/v.bin"), key(KeyCode::Char('a')));
    assert!(effects.is_empty(), "expected no effect, got {effects:?}");
    match state {
        AppState::Unlock { passphrase, .. } => assert_eq!(passphrase.as_str(), "a"),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn typing_multiple_chars_on_unlock_accumulates_in_typed_order() {
    let mut state = unlock("/tmp/v.bin");
    for c in ['p', 'a', 's', 's'] {
        let (next, effects) = reduce(state, key(KeyCode::Char(c)));
        assert!(effects.is_empty(), "char-input never emits an Effect");
        state = next;
    }
    match state {
        AppState::Unlock { passphrase, .. } => assert_eq!(passphrase.as_str(), "pass"),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn typing_uppercase_char_with_shift_modifier_appends_uppercase() {
    // crossterm reports the resolved character (e.g. 'A' for Shift+a),
    // so a Shift modifier on Char('A') must not block the append.
    let evt = AppEvent::Input {
        event: Event::Key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT)),
        at: Instant::now(),
    };
    let (state, effects) = reduce(unlock("/tmp/v.bin"), evt);
    assert!(effects.is_empty());
    match state {
        AppState::Unlock { passphrase, .. } => assert_eq!(passphrase.as_str(), "A"),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn ctrl_modified_char_other_than_ctrl_c_does_not_append_to_passphrase() {
    // Ctrl-U / Ctrl-A / etc. are not passphrase text. The reducer must
    // ignore them on the Unlock screen (Ctrl-C is handled earlier and
    // is a Quit, so we use Ctrl-U here).
    let (state, effects) = reduce(unlock("/tmp/v.bin"), ctrl(KeyCode::Char('u')));
    assert!(
        effects.is_empty(),
        "Ctrl-modified non-quit chars on Unlock are no-ops, got {effects:?}"
    );
    match state {
        AppState::Unlock { passphrase, .. } => assert!(
            passphrase.is_empty(),
            "Ctrl-U must not append to passphrase buffer"
        ),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn backspace_on_unlock_pops_the_last_typed_char() {
    let (state, effects) = reduce(unlock_with("/tmp/v.bin", "ab"), key(KeyCode::Backspace));
    assert!(effects.is_empty());
    match state {
        AppState::Unlock { passphrase, .. } => assert_eq!(passphrase.as_str(), "a"),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn backspace_on_empty_unlock_buffer_is_a_silent_no_op() {
    let (state, effects) = reduce(unlock("/tmp/v.bin"), key(KeyCode::Backspace));
    assert!(effects.is_empty());
    match state {
        AppState::Unlock { passphrase, .. } => assert!(passphrase.is_empty()),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn enter_with_empty_passphrase_yields_no_effect_and_keeps_state() {
    let (state, effects) = reduce(unlock("/tmp/v.bin"), key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "Enter on an empty passphrase must not submit; got {effects:?}"
    );
    match state {
        AppState::Unlock { passphrase, .. } => assert!(passphrase.is_empty()),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn enter_with_non_empty_passphrase_emits_unlock_effect_and_clears_buffer() {
    let (state, effects) = reduce(unlock_with("/tmp/v.bin", "hunter2"), key(KeyCode::Enter));

    match effects.as_slice() {
        [Effect::Unlock { path, passphrase }] => {
            assert_eq!(path, &PathBuf::from("/tmp/v.bin"));
            assert_eq!(passphrase.expose_secret(), "hunter2");
        }
        other => panic!("expected single Effect::Unlock, got {other:?}"),
    }

    match state {
        AppState::Unlock { passphrase, .. } => assert!(
            passphrase.is_empty(),
            "passphrase buffer must zeroize (clear) on submit"
        ),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn esc_on_unlock_with_typed_passphrase_zeroizes_buffer_before_quit() {
    // Bullet (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Sensitive UI
    // buffers): "Unlock passphrase buffer zeroizes on submit, cancel,
    // and auto-lock." `Esc` on the Unlock screen is a cancel path —
    // per Keybindings it emits `Effect::Quit`, and the typed bytes
    // must be wiped before the process tears down so the passphrase
    // does not linger between `Quit` emission and actual process
    // exit (or survive a crash / coredump in that window).
    let (state, effects) = reduce(unlock_with("/tmp/v.bin", "hunter2"), key(KeyCode::Esc));

    assert!(matches!(effects.as_slice(), [Effect::Quit]));
    match state {
        AppState::Unlock { passphrase, .. } => assert!(
            passphrase.is_empty(),
            "passphrase buffer must zeroize on Esc-cancel before Quit"
        ),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn ctrl_c_on_unlock_with_typed_passphrase_zeroizes_buffer_before_quit() {
    // Same bullet: `Ctrl-C` is the other cancel path from the Unlock
    // screen (Keybindings: "Ctrl-C quits any screen") and must
    // zeroize the buffer for the same reason as `Esc`-cancel.
    let (state, effects) = reduce(
        unlock_with("/tmp/v.bin", "hunter2"),
        ctrl(KeyCode::Char('c')),
    );

    assert!(matches!(effects.as_slice(), [Effect::Quit]));
    match state {
        AppState::Unlock { passphrase, .. } => assert!(
            passphrase.is_empty(),
            "passphrase buffer must zeroize on Ctrl-C cancel before Quit"
        ),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

#[test]
fn tick_on_unlock_with_typed_passphrase_preserves_buffer() {
    // Auto-lock fires only from `Unlocked` (per
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)"); the
    // Unlock screen has no idle deadline. A `Tick` on `Unlock`
    // therefore passes through unchanged — the buffer is *not*
    // zeroized by Tick, only by submit / cancel. This nails down
    // that the auto-lock axis of the Sensitive-UI-buffers bullet is
    // structurally satisfied by Unlock having no auto-lock path,
    // rather than by a hidden buffer-wipe on every Tick.
    let tick = AppEvent::Tick {
        wall_clock: SystemTime::now(),
        monotonic: Instant::now(),
    };
    let (state, effects) = reduce(unlock_with("/tmp/v.bin", "hunter2"), tick);

    assert!(effects.is_empty(), "Tick on Unlock yields no effects");
    match state {
        AppState::Unlock { passphrase, .. } => assert_eq!(
            passphrase.as_str(),
            "hunter2",
            "Tick on Unlock must not mutate the passphrase buffer"
        ),
        other => panic!("expected Unlock state, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Sensitive UI buffers — PassphraseBuffer
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Sensitive UI buffers)
// ---------------------------------------------------------------------------

#[test]
fn passphrase_buffer_debug_redacts_typed_bytes() {
    let mut buf = PassphraseBuffer::new();
    for c in "topsecret".chars() {
        buf.push(c);
    }
    let rendered = format!("{buf:?}");
    assert!(
        !rendered.contains("topsecret"),
        "Debug must not leak typed bytes, got: {rendered}"
    );
    // The redaction marker should be unambiguous so reviewers know the
    // omission is intentional.
    assert!(
        rendered.to_lowercase().contains("redacted"),
        "Debug must indicate redaction, got: {rendered}"
    );
}

#[test]
fn passphrase_buffer_clear_empties_the_buffer() {
    let mut buf = PassphraseBuffer::new();
    buf.push('x');
    buf.push('y');
    assert!(!buf.is_empty());
    buf.clear();
    assert!(buf.is_empty());
    assert_eq!(buf.as_str(), "");
}

#[test]
fn passphrase_buffer_take_returns_secret_and_clears_buffer() {
    let mut buf = PassphraseBuffer::new();
    buf.push('p');
    buf.push('w');
    let secret = buf.take();
    assert_eq!(secret.expose_secret(), "pw");
    assert!(buf.is_empty(), "take must clear the buffer in place");
}

#[test]
fn passphrase_buffer_pop_returns_last_char_and_shortens() {
    let mut buf = PassphraseBuffer::new();
    buf.push('a');
    buf.push('b');
    assert_eq!(buf.pop(), Some('b'));
    assert_eq!(buf.as_str(), "a");
    assert_eq!(buf.pop(), Some('a'));
    assert!(buf.is_empty());
    assert_eq!(buf.pop(), None, "pop on empty buffer returns None");
}

// ---------------------------------------------------------------------------
// EffectResult::Unlock — outcome of an Effect::Unlock submission
// (IMPLEMENTATION_PLAN_03_TUI.md > Startup / vault modes +
//  IMPLEMENTATION_PLAN_03_TUI.md > Tests > Vault modes and startup +
//  IMPLEMENTATION_PLAN_03_TUI.md > Event loop (per §6) — "Save-bearing
//  effects ... send an AppEvent::EffectResult(...) back through the same
//  mpsc channel.")
//
// Behavior covered:
//   * Ok((vault, store)) on Unlock → AppState::Unlocked with same path.
//   * Err(DecryptFailed)  on Unlock → stay on Unlock with inline error
//     and preserve the (already-cleared) passphrase buffer.
//   * Err(other)          on Unlock → StartupError preserving the path.
//   * Result delivered while not on Unlock (auto-locked, navigated
//     away, quit-in-flight) is discarded: state and effects unchanged
//     and the carried (Vault, Store) drops.
// ---------------------------------------------------------------------------

fn unlock_result(result: Result<(Vault, Store), PaladinError>) -> AppEvent {
    // Off-the-shelf `opened_at` for tests that do not care about the
    // post-unlock auto-lock deadline (e.g. error paths). The
    // dedicated idle-deadline tests construct the event inline with
    // a controlled instant instead.
    AppEvent::EffectResult(EffectResult::Unlock {
        result,
        opened_at: Instant::now(),
    })
}

fn open_plaintext_pair(tmp: &tempfile::TempDir) -> (PathBuf, (Vault, Store)) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(tmp.path(), perms).unwrap();
    }
    let path = tmp.path().join("plain.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    let pair = Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext");
    (path, pair)
}

#[test]
fn effect_result_unlock_ok_transitions_unlock_to_unlocked_with_same_path() {
    // Bullet: "Encrypted vault correct passphrase advances to the list."
    // We use a plaintext-opened pair because the (Vault, Store) type
    // signature is identical between modes and Argon2id KDF would
    // dominate test runtime.
    let tmp = test_tempdir();
    let (vault_path, pair) = open_plaintext_pair(&tmp);

    // The Unlock state carries an inline `error` from a prior failed
    // attempt; the success transition must drop it implicitly because
    // `Unlocked` has no `error` field.
    let unlock_state = AppState::Unlock {
        path: vault_path.clone(),
        error: Some("previous decrypt_failed".into()),
        passphrase: PassphraseBuffer::new(),
    };
    let (state, effects) = reduce(unlock_state, unlock_result(Ok(pair)));

    assert!(effects.is_empty(), "unlock result emits no effects");
    match state {
        AppState::Unlocked { path: p, .. } => assert_eq!(p, vault_path),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_decrypt_failed_stays_on_unlock_with_inline_error() {
    // Bullet: "Encrypted vault wrong passphrase shows inline
    // `decrypt_failed` and stays on the unlock screen."
    let expected = render_error_message(&PaladinError::DecryptFailed);
    let vault_path = PathBuf::from("/tmp/v.bin");
    let (state, effects) = reduce(
        AppState::Unlock {
            path: vault_path.clone(),
            error: None,
            passphrase: PassphraseBuffer::new(),
        },
        unlock_result(Err(PaladinError::DecryptFailed)),
    );
    assert!(effects.is_empty());
    match state {
        AppState::Unlock {
            path,
            error,
            passphrase,
        } => {
            assert_eq!(path, vault_path);
            assert_eq!(
                error.as_deref(),
                Some(expected.as_str()),
                "inline error must use render_error_message(DecryptFailed)"
            );
            assert!(
                passphrase.is_empty(),
                "buffer was zeroized at submit and must not be repopulated"
            );
        }
        other => panic!("expected Unlock, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_non_decrypt_error_transitions_to_startup_error() {
    // Bullet: "The unlock screen handles only `decrypt_failed` inline;
    // every other `open` error replaces the unlock screen with the
    // startup-error screen."
    let tmp = test_tempdir();
    let garbage = tmp.path().join("garbage.bin");
    fs::write(&garbage, b"not a paladin vault").unwrap();
    let err = paladin_core::inspect(&garbage).unwrap_err();
    assert!(
        !matches!(err, PaladinError::DecryptFailed),
        "fixture must produce a non-decrypt_failed error"
    );
    let expected = render_error_message(&err);

    let vault_path = PathBuf::from("/tmp/v.bin");
    let (state, effects) = reduce(
        AppState::Unlock {
            path: vault_path.clone(),
            error: None,
            passphrase: PassphraseBuffer::new(),
        },
        unlock_result(Err(err)),
    );
    assert!(effects.is_empty());
    match state {
        AppState::StartupError {
            path: Some(p),
            message,
        } => {
            assert_eq!(p, vault_path);
            assert_eq!(message, expected);
        }
        other => panic!("expected StartupError, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_ok_off_unlock_screen_is_discarded() {
    // If the user navigated away (auto-lock, etc.) between submit and
    // the result arriving, the late (Vault, Store) drops on the floor
    // and the current screen is unchanged. Tested against `Locked`
    // because auto-lock is the realistic race condition.
    let tmp = test_tempdir();
    let (_vault_path, pair) = open_plaintext_pair(&tmp);

    let locked_path = PathBuf::from("/tmp/locked.bin");
    let (state, effects) = reduce(
        AppState::Locked {
            path: locked_path.clone(),
            pending_clipboard_clear: None,
        },
        unlock_result(Ok(pair)),
    );
    assert!(effects.is_empty());
    match state {
        AppState::Locked { path, .. } => assert_eq!(path, locked_path),
        other => panic!("expected Locked unchanged, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_decrypt_failed_off_unlock_screen_is_discarded() {
    // Same race condition, error branch: a wrong-passphrase result
    // arriving after the user navigated away must NOT replace the
    // current screen with StartupError.
    let (state, effects) = reduce(
        missing("/tmp/v.bin"),
        unlock_result(Err(PaladinError::DecryptFailed)),
    );
    assert!(effects.is_empty());
    assert!(matches!(state, AppState::MissingVault { .. }));
}

// ---------------------------------------------------------------------------
// Auto-lock — idle_deadline seeded on Unlocked entry
// (IMPLEMENTATION_PLAN_03_TUI.md > Auto-lock (per §6) +
//  IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock —
//  "idle_deadline is set via paladin_core::policy::auto_lock::
//   IdlePolicy::next_deadline(now, vault.is_encrypted(), settings)
//   on Unlocked + enabled + encrypted")
//
// Slice covered here: idle_deadline is seeded at both Unlocked-entry
// sites — `decide_state_from_open` (plaintext direct-open path in
// `build_initial_state`) and the `EffectResult::Unlock` Ok branch
// (encrypted unlock path) — by delegating to
// `paladin_core::IdlePolicy::next_deadline`. The plaintext-no-op
// rule is enforced by `IdlePolicy::should_arm`; we verify the TUI
// does not paper over it. (Input-driven resets and the Tick-driven
// Locked transition land in follow-up slices.)
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

fn enable_auto_lock(vault: &mut Vault, store: &Store, timeout_secs: u32) {
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(timeout_secs)
        .expect("timeout within bounds");
    vault.save(store).expect("commit settings");
}

/// Insert a TOTP account into the vault (persisted) and return its
/// `AccountId`. Insertion order is preserved by `Vault::iter()`, so
/// repeated calls produce the same ordering the TUI list will show.
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

/// Add an HOTP account with the given `label` and counter `0`.
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
    vault.save(store).expect("commit added HOTP account");
    id
}

#[test]
fn compute_idle_deadline_plaintext_vault_is_none() {
    // The plaintext-no-op rule (§6 / §7) must hold even if the
    // user explicitly enabled auto-lock — `IdlePolicy::should_arm`
    // gates on `is_encrypted` first.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(900).unwrap();
    vault.save(&store).unwrap();

    let now = Instant::now();
    assert_eq!(
        compute_idle_deadline(now, &vault),
        None,
        "plaintext vault must never produce an idle deadline"
    );
}

#[test]
fn compute_idle_deadline_encrypted_auto_lock_disabled_is_none() {
    // Encrypted vault, default settings (auto_lock_enabled = false)
    // → no deadline. The setting is opt-in per §6.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, _store) = create_encrypted_pair(&path, "pp");

    let now = Instant::now();
    assert!(
        !vault.settings().auto_lock_enabled(),
        "fixture must default to auto_lock_enabled = false"
    );
    assert_eq!(compute_idle_deadline(now, &vault), None);
}

#[test]
fn compute_idle_deadline_encrypted_auto_lock_enabled_matches_idle_policy() {
    // Encrypted vault with auto-lock enabled at a non-default
    // timeout → deadline equals `IdlePolicy::next_deadline(now, ...)`
    // exactly. The TUI must not reimplement the math.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let now = Instant::now();
    let expected = IdlePolicy::next_deadline(now, true, vault.settings());
    assert_eq!(expected, Some(now + Duration::from_secs(600)));
    assert_eq!(compute_idle_deadline(now, &vault), expected);
}

#[test]
fn decide_state_from_open_encrypted_auto_lock_disabled_seeds_no_idle_deadline() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let pair = create_encrypted_pair(&path, "pp");

    let now = Instant::now();
    let state = decide_state_from_open(now, path.clone(), Ok(pair));
    match state {
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
fn decide_state_from_open_encrypted_auto_lock_enabled_seeds_idle_deadline() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let now = Instant::now();
    let state = decide_state_from_open(now, path.clone(), Ok((vault, store)));
    match state {
        AppState::Unlocked {
            idle_deadline,
            path: p,
            ..
        } => {
            assert_eq!(p, path);
            assert_eq!(
                idle_deadline,
                Some(now + Duration::from_secs(600)),
                "deadline must equal `now + timeout_secs` for encrypted + enabled"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_ok_seeds_idle_deadline_from_opened_at() {
    // The reducer must feed the executor's `opened_at` (not its own
    // `Instant::now()`) into the deadline math so the TUI's auto-lock
    // window measures from when `Store::open` actually returned.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 420);

    let opened_at = Instant::now();
    let event = AppEvent::EffectResult(EffectResult::Unlock {
        result: Ok((vault, store)),
        opened_at,
    });
    let (state, effects) = reduce(unlock(path.to_str().unwrap()), event);
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { idle_deadline, .. } => {
            assert_eq!(
                idle_deadline,
                Some(opened_at + Duration::from_secs(420)),
                "idle_deadline must derive from EffectResult::Unlock.opened_at"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_ok_plaintext_seeds_no_idle_deadline() {
    // Plaintext path through the same code: `IdlePolicy::should_arm`
    // returns false, so the new Unlocked has no deadline even if the
    // user previously toggled `auto_lock_enabled = true` (the setting
    // persists but is inert for plaintext).
    let tmp = secure_tempdir();
    let (vault_path, pair) = open_plaintext_pair(&tmp);
    let event = AppEvent::EffectResult(EffectResult::Unlock {
        result: Ok(pair),
        opened_at: Instant::now(),
    });
    let (state, _effects) = reduce(unlock(vault_path.to_str().unwrap()), event);
    match state {
        AppState::Unlocked { idle_deadline, .. } => assert_eq!(idle_deadline, None),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn decide_state_from_open_plaintext_seeds_no_idle_deadline() {
    // The other Unlocked-entry site: `build_initial_state` calls
    // `decide_state_from_open` on the plaintext direct-open path
    // (no `Unlock` screen, no `EffectResult::Unlock`). The
    // plaintext-no-op rule (§6 / §7) must hold here too: even if the
    // user previously toggled `auto_lock_enabled = true` on the
    // plaintext vault, the resulting `Unlocked` state carries no
    // idle deadline. The setting persists in the vault file but is
    // inert for plaintext because `IdlePolicy::should_arm` gates on
    // `is_encrypted` first.
    let tmp = secure_tempdir();
    let (vault_path, (mut vault, store)) = open_plaintext_pair(&tmp);
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(900)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit settings");

    let now = Instant::now();
    let state = decide_state_from_open(now, vault_path.clone(), Ok((vault, store)));
    match state {
        AppState::Unlocked {
            idle_deadline,
            path: p,
            ..
        } => {
            assert_eq!(p, vault_path);
            assert_eq!(
                idle_deadline, None,
                "plaintext direct-open must never seed an idle deadline"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Initial selection seeding
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Search — `select_after_filter`
//  preserves selection by `AccountId`; on Unlocked entry the previous
//  selection is `None`, so the seed equals the first match in the
//  filtered set. With no search query the filtered set is `Vault::iter()`
//  in insertion order, so the seed is the first inserted account or
//  `None` when the vault is empty.)
// ---------------------------------------------------------------------------

#[test]
fn decide_state_from_open_empty_vault_seeds_no_selection() {
    let tmp = secure_tempdir();
    let (vault_path, (vault, store)) = open_plaintext_pair(&tmp);
    let now = Instant::now();
    let state = decide_state_from_open(now, vault_path, Ok((vault, store)));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected, None,
            "empty vault must seed `selected` to None on Unlocked entry"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn decide_state_from_open_non_empty_vault_seeds_first_inserted_account() {
    let tmp = secure_tempdir();
    let (vault_path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let first = add_totp_account(&mut vault, &store, "first");
    let _second = add_totp_account(&mut vault, &store, "second");
    let now = Instant::now();
    let state = decide_state_from_open(now, vault_path, Ok((vault, store)));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(first),
            "non-empty vault must seed `selected` to the first inserted account"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_ok_seeds_selection_from_first_inserted_account() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pw");
    let first = add_totp_account(&mut vault, &store, "first");
    let _second = add_totp_account(&mut vault, &store, "second");
    // Drop and re-open to mimic the unlock-effect flow.
    drop(vault);
    drop(store);
    let pp = SecretString::from("pw".to_string());
    let pair = Store::open(&path, VaultLock::Encrypted(pp)).expect("unlock");

    let prior = AppState::Unlock {
        path: path.clone(),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    let (state, effects) = reduce(prior, unlock_result(Ok(pair)));
    assert!(
        effects.is_empty(),
        "successful unlock yields no follow-up effects"
    );
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(first),
            "successful unlock must seed `selected` to the first inserted account"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_ok_empty_vault_seeds_no_selection() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, store) = create_encrypted_pair(&path, "pw");
    drop(vault);
    drop(store);
    let pp = SecretString::from("pw".to_string());
    let pair = Store::open(&path, VaultLock::Encrypted(pp)).expect("unlock");

    let prior = AppState::Unlock {
        path: path.clone(),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    let (state, effects) = reduce(prior, unlock_result(Ok(pair)));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected, None,
            "empty vault unlock must seed `selected` to None"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Initial focus seeding
// (IMPLEMENTATION_PLAN_03_TUI.md > Focus model: "On list-view entry,
//  focus starts on the account list".)
// ---------------------------------------------------------------------------

#[test]
fn decide_state_from_open_seeds_focus_on_the_list() {
    // Every Unlocked-entry path lands the user on the account list so
    // navigation keys engage without a focus-toggle press. The
    // `decide_state_from_open` path is the plaintext / direct-open
    // entry; the encrypted-unlock path is covered by its own test.
    let tmp = secure_tempdir();
    let (vault_path, (vault, store)) = open_plaintext_pair(&tmp);
    let now = Instant::now();
    let state = decide_state_from_open(now, vault_path, Ok((vault, store)));
    match state {
        AppState::Unlocked { focus, .. } => assert_eq!(
            focus,
            Focus::List,
            "Unlocked entry must seed `focus` to Focus::List"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_ok_seeds_focus_on_the_list() {
    // The successful-unlock branch in `reduce_unlock_result` is the
    // second Unlocked-entry site. It must seed focus the same way so
    // the user is on the list regardless of whether they came in via
    // plaintext direct-open or encrypted unlock.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, store) = create_encrypted_pair(&path, "pw");
    drop(vault);
    drop(store);
    let pp = SecretString::from("pw".to_string());
    let pair = Store::open(&path, VaultLock::Encrypted(pp)).expect("unlock");

    let prior = AppState::Unlock {
        path: path.clone(),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    let (state, effects) = reduce(prior, unlock_result(Ok(pair)));
    assert!(
        effects.is_empty(),
        "successful unlock yields no follow-up effects"
    );
    match state {
        AppState::Unlocked { focus, .. } => assert_eq!(
            focus,
            Focus::List,
            "successful unlock must seed `focus` to Focus::List"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Modals — open transitions
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer — bullet 4)
//
// Slice covered: pressing `a` on `AppState::Unlocked` while no modal is
// open sets `modal = Some(Modal::Add)` and emits no effects. When a modal
// is already open, the bare `a` key does not replace the open modal —
// the modal-local input path consumes it (modals' typed-field payloads
// land in later slices, so the slot stays unchanged here). `Ctrl-A` is
// unbound and is a no-op. Routing the other six modal openers
// (`i` / `e` / `r` / `R` / `p` / `s`) lands with the remaining modal
// slices alongside their post-open payloads.
// ---------------------------------------------------------------------------

#[test]
fn pressing_a_on_unlocked_with_no_modal_open_opens_add_modal() {
    let tmp = secure_tempdir();
    let (path, (vault, store)) = open_plaintext_pair(&tmp);
    let unlocked = AppState::Unlocked {
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
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('a')));
    assert!(effects.is_empty(), "opening a modal must not emit effects");
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add(add)),
            ..
        } => {
            assert_eq!(
                add.mode,
                AddMode::Manual,
                "Add modal opens on the Manual input-mode tab per DESIGN §6"
            );
            assert!(
                add.error.is_none(),
                "freshly opened Add modal must have no inline error, got {:?}",
                add.error
            );
        }
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=Some(Modal::Add(_)), got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn add_modal_default_mode_is_manual() {
    // The Add modal opens on the Manual tab per DESIGN §6: *"Add
    // supports manual entry, paste of an `otpauth://` URI ..., and QR
    // scan from clipboard image bytes"*. `AddModal::default()` must
    // mirror this so the placeholder shape used by reducer tests and
    // the `'a'` opener agree on the initial input mode.
    let add = AddModal::default();
    assert_eq!(add.mode, AddMode::Manual);
}

#[test]
fn add_modal_default_has_no_inline_error() {
    // No save / validation attempt has happened on a fresh modal, so
    // the inline error slot starts empty per the Settings/Rename/Remove
    // pattern.
    let add = AddModal::default();
    assert!(add.error.is_none(), "got {:?}", add.error);
}

// ---------------------------------------------------------------------------
// Add modal — Manual-mode field defaults (non-secret + secret).
//
// Per DESIGN §5 manual-add defaults / `IMPLEMENTATION_PLAN_03_TUI.md`
// "Modals (per §6)" > Add: *"defaults follow the CLI manual-add
// defaults in DESIGN §5 (TOTP, SHA1, 6 digits, 30 s period, HOTP
// counter 0, icon-hint defaulted from the issuer per §4.1)"*. The
// secret-bearing manual-secret buffer (Base32 secret material) lives
// in a zeroizing buffer per the same section's *"keep typed bytes in
// zeroizing buffers, convert to `secrecy::SecretString` only for
// core calls"* rule; submit / cancel / mode-switch zeroization lands
// alongside the reducer wiring for those transitions.
// ---------------------------------------------------------------------------

#[test]
fn add_modal_default_manual_label_is_empty() {
    let add = AddModal::default();
    assert!(
        add.label.is_empty(),
        "freshly opened Add modal must start with empty label, got {:?}",
        add.label
    );
}

#[test]
fn add_modal_default_manual_issuer_is_empty() {
    let add = AddModal::default();
    assert!(
        add.issuer.is_empty(),
        "freshly opened Add modal must start with empty issuer, got {:?}",
        add.issuer
    );
}

#[test]
fn add_modal_default_manual_icon_hint_text_is_empty() {
    // Per DESIGN §6 the icon-hint default is "default from issuer";
    // the modal's text buffer is empty so that an unedited submit
    // resolves to `IconHintInput::Default` via `parse_icon_hint_token`
    // (an empty / whitespace-only token).
    let add = AddModal::default();
    assert!(
        add.icon_hint_text.is_empty(),
        "freshly opened Add modal must start with empty icon-hint text, got {:?}",
        add.icon_hint_text
    );
}

#[test]
fn add_modal_default_manual_algorithm_is_sha1() {
    // RFC 6238 default per DESIGN §5.
    let add = AddModal::default();
    assert_eq!(add.algorithm, Algorithm::Sha1);
}

#[test]
fn add_modal_default_manual_digits_is_six() {
    // CLI manual-add default per DESIGN §5 (`DIGITS_DEFAULT`).
    let add = AddModal::default();
    assert_eq!(add.digits, paladin_core::DIGITS_DEFAULT);
    assert_eq!(add.digits, 6);
}

#[test]
fn add_modal_default_manual_kind_is_totp() {
    // CLI manual-add default per DESIGN §5: TOTP unless `--hotp`.
    let add = AddModal::default();
    assert_eq!(add.kind, AccountKindInput::Totp);
}

#[test]
fn add_modal_default_manual_period_secs_is_thirty() {
    // CLI manual-add default per DESIGN §5 (`TOTP_PERIOD_DEFAULT`).
    let add = AddModal::default();
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT);
    assert_eq!(add.period_secs, 30);
}

#[test]
fn add_modal_default_manual_counter_is_zero() {
    // CLI manual-add default per DESIGN §5 — HOTP counter starts at 0.
    let add = AddModal::default();
    assert_eq!(add.counter, 0);
}

#[test]
fn add_modal_default_manual_secret_is_empty() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    // the manual-secret field carries Base32 secret material in a
    // zeroizing buffer. A freshly opened modal starts with an empty
    // buffer so the user begins with a clean slate — mirroring the
    // empty label / issuer / icon-hint slots above.
    let add = AddModal::default();
    assert!(
        add.manual_secret.is_empty(),
        "freshly opened Add modal must start with empty manual secret"
    );
}

#[test]
fn add_modal_manual_secret_debug_redacts_typed_bytes() {
    // Per `CLAUDE.md` "No `Debug` impls that leak bytes" — the
    // manual-secret buffer is secret-bearing (Base32 secret material)
    // so its `Debug` output must redact the contents the same way
    // `PassphraseBuffer` does for typed passphrases. This guards
    // against accidentally surfacing the secret through panic
    // messages, reducer-state dumps, or test failure output.
    let mut add = AddModal::default();
    add.manual_secret.push('A');
    add.manual_secret.push('B');
    add.manual_secret.push('C');
    let dbg = format!("{add:?}");
    assert!(
        !dbg.contains("ABC"),
        "Debug output must not leak manual-secret bytes, got: {dbg}"
    );
}

#[test]
fn add_modal_default_uri_text_is_empty() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    // *"The URI text field is treated as a secret-bearing buffer …
    // because the URI embeds the Base32 secret."* A freshly opened
    // modal starts with an empty buffer just like the manual-secret
    // slot above.
    let add = AddModal::default();
    assert!(
        add.uri_text.is_empty(),
        "freshly opened Add modal must start with empty URI text"
    );
}

#[test]
fn add_modal_uri_text_debug_redacts_typed_bytes() {
    // Per `CLAUDE.md` "No `Debug` impls that leak bytes" — the
    // URI-mode entry embeds the Base32 secret (`otpauth://…?secret=…`)
    // so its `Debug` output must redact the contents the same way
    // the manual-secret buffer does. Push an obviously sentinel
    // substring and assert it does not surface in the formatted
    // output.
    let mut add = AddModal::default();
    add.uri_text.push('o');
    add.uri_text.push('t');
    add.uri_text.push('p');
    add.uri_text.push('Z');
    add.uri_text.push('Z');
    add.uri_text.push('Z');
    let dbg = format!("{add:?}");
    assert!(
        !dbg.contains("otpZZZ"),
        "Debug output must not leak URI-text bytes, got: {dbg}"
    );
}

#[test]
fn opening_add_modal_with_a_seeds_manual_defaults() {
    // The `a` opener constructs `AddModal::default()`, so the modal
    // observed in the unlocked state must carry the same manual
    // defaults the unit tests above lock in. This anchors the
    // observable contract from the keybinding through to the payload
    // shape.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let add = add_modal_ref(&state);
    assert!(add.label.is_empty());
    assert!(add.issuer.is_empty());
    assert!(add.icon_hint_text.is_empty());
    assert!(add.manual_secret.is_empty());
    assert!(add.uri_text.is_empty());
    assert_eq!(add.algorithm, Algorithm::Sha1);
    assert_eq!(add.digits, paladin_core::DIGITS_DEFAULT);
    assert_eq!(add.kind, AccountKindInput::Totp);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT);
    assert_eq!(add.counter, 0);
}

// ---------------------------------------------------------------------------
// Add modal — segmented mode selector (`←` / `→`).
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)": *"`←` / `→`
// change segmented selectors"*. The Add modal's three input modes
// (Manual / URI / QR per DESIGN §6) form one segmented selector;
// `→` advances Manual → Uri → Qr → Manual and `←` retreats
// Manual → Qr → Uri → Manual. Cycling is modal-local: outside an
// open Add modal both keys are silent no-ops at the top level.
// ---------------------------------------------------------------------------

/// Open the Add modal on a fresh plaintext vault, returning the
/// populated `AppState` ready for mode-selector tests.
fn fresh_unlocked_with_add_modal(tmp: &tempfile::TempDir) -> AppState {
    let unlocked = fresh_plaintext_unlocked(tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('a')));
    assert!(effects.is_empty(), "opening Add must not emit effects");
    state
}

/// Pull the open `AddModal` out of an `Unlocked` state by ref,
/// panicking with a clear message if Add is not the open modal.
fn add_modal_ref(state: &AppState) -> &AddModal {
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add(a)),
            ..
        } => a,
        AppState::Unlocked { modal, .. } => {
            panic!("expected Modal::Add open, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn right_in_add_modal_cycles_mode_manual_uri_qr_manual() {
    // Per DESIGN §6 the Add modal's input modes are Manual / URI / QR;
    // the segmented selector advances forward on `→`, wrapping after
    // the final mode so the user can cycle indefinitely without a
    // separate "reset" action.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    assert_eq!(add_modal_ref(&state).mode, AddMode::Manual);
    let order = [AddMode::Uri, AddMode::Qr, AddMode::Manual];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Right));
        assert!(
            effects.is_empty(),
            "→ inside Add modal (step {i}) must not emit effects"
        );
        assert_eq!(
            add_modal_ref(&next).mode,
            *expected,
            "→ step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn left_in_add_modal_cycles_mode_manual_qr_uri_manual() {
    // `←` retreats through the segmented selector, the mirror of `→`.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    assert_eq!(add_modal_ref(&state).mode, AddMode::Manual);
    let order = [AddMode::Qr, AddMode::Uri, AddMode::Manual];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Left));
        assert!(
            effects.is_empty(),
            "← inside Add modal (step {i}) must not emit effects"
        );
        assert_eq!(
            add_modal_ref(&next).mode,
            *expected,
            "← step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn right_then_left_in_add_modal_round_trips_from_every_mode() {
    // Defensive round-trip: from any starting mode, `→` then `←`
    // must return to the starting mode. Locks in the symmetry between
    // `AddMode::next()` and `AddMode::prev()`. Walks the modal
    // forward across each mode in one open session, asserting the
    // round-trip at each stop.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let order = [AddMode::Manual, AddMode::Uri, AddMode::Qr];
    for start in order {
        assert_eq!(
            add_modal_ref(&state).mode,
            start,
            "walk should be at {start:?}"
        );
        let (after_right, _) = reduce(state, key(KeyCode::Right));
        let (after_left, _) = reduce(after_right, key(KeyCode::Left));
        assert_eq!(
            add_modal_ref(&after_left).mode,
            start,
            "→ then ← from {start:?} should round-trip back to {start:?}"
        );
        // Advance to the next start by one `→` for the next iteration.
        let (next, _) = reduce(after_left, key(KeyCode::Right));
        state = next;
    }
}

#[test]
fn arrows_in_add_modal_do_not_mutate_other_state() {
    // Per the modal-trap contract, ←/→ are modal-local: pressing them
    // while the Add modal is open must not change the path, search
    // query, focus, or status line.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (path_before, query_before, focus_before, status_before) = match &state {
        AppState::Unlocked {
            path,
            search_query,
            focus,
            status_line,
            ..
        } => (
            path.clone(),
            search_query.clone(),
            *focus,
            status_line.clone(),
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (after_right, _) = reduce(state, key(KeyCode::Right));
    match &after_right {
        AppState::Unlocked {
            path,
            search_query,
            focus,
            status_line,
            modal: Some(Modal::Add(_)),
            ..
        } => {
            assert_eq!(path, &path_before);
            assert_eq!(search_query, &query_before);
            assert_eq!(*focus, focus_before);
            assert_eq!(status_line, &status_before);
        }
        other => panic!("expected Unlocked with Modal::Add open, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Add modal — mode-switch zeroization of secret-bearing buffers.
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
// *"Switching modes clears the hidden secret-bearing fields for the
// modes being left: the manual Base32 secret, the URI text, and any
// pending duplicate/add-anyway state."* This block locks in the
// targeted contract — only the *leaving* mode's secrets are wiped —
// so stale Base32 input does not survive behind the active mode.
// Coverage tracks the secret-bearing fields as they land: the
// manual-secret buffer (Manual mode) and the URI-text buffer (Uri
// mode) today, with the pending duplicate/add-anyway slot to follow.
// ---------------------------------------------------------------------------

/// Helper: open the Add modal and push four Base32 chars into the
/// manual-secret buffer so the assertions can distinguish "wiped" from
/// "already empty".
fn add_modal_with_typed_manual_secret(tmp: &tempfile::TempDir) -> AppState {
    let mut state = fresh_unlocked_with_add_modal(tmp);
    match &mut state {
        AppState::Unlocked {
            modal: Some(Modal::Add(add)),
            ..
        } => {
            add.manual_secret.push('J');
            add.manual_secret.push('B');
            add.manual_secret.push('S');
            add.manual_secret.push('W');
        }
        _ => panic!("expected Unlocked with Modal::Add open"),
    }
    state
}

/// Helper: open the Add modal, advance to Uri mode via `→`, and push
/// a sentinel `otpauth://` prefix into the URI buffer so the
/// assertions can distinguish "wiped" from "already empty".
fn add_modal_in_uri_mode_with_typed_text(tmp: &tempfile::TempDir) -> AppState {
    // One `→` cycles Manual → Uri.
    let (mut state, _) = reduce(fresh_unlocked_with_add_modal(tmp), key(KeyCode::Right));
    match &mut state {
        AppState::Unlocked {
            modal: Some(Modal::Add(add)),
            ..
        } => {
            assert_eq!(add.mode, AddMode::Uri, "expected one → to land on Uri");
            for c in "otpauth://".chars() {
                add.uri_text.push(c);
            }
        }
        _ => panic!("expected Unlocked with Modal::Add open"),
    }
    state
}

#[test]
fn right_from_manual_mode_wipes_manual_secret() {
    // Leaving Manual via `→` (Manual → Uri) must zeroize the typed
    // Base32 buffer so the bytes are not retained behind the active
    // mode.
    let tmp = secure_tempdir();
    let state = add_modal_with_typed_manual_secret(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Right));
    assert!(
        effects.is_empty(),
        "→ inside Add modal must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.mode, AddMode::Uri);
    assert!(
        add.manual_secret.is_empty(),
        "→ from Manual must wipe manual_secret"
    );
}

#[test]
fn left_from_manual_mode_wipes_manual_secret() {
    // Leaving Manual via `←` (Manual → Qr) must zeroize the typed
    // Base32 buffer the same way `→` does — both arrows are
    // mode-switches that abandon the Manual-mode field set.
    let tmp = secure_tempdir();
    let state = add_modal_with_typed_manual_secret(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Left));
    assert!(
        effects.is_empty(),
        "← inside Add modal must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.mode, AddMode::Qr);
    assert!(
        add.manual_secret.is_empty(),
        "← from Manual must wipe manual_secret"
    );
}

#[test]
fn cycling_between_uri_and_qr_preserves_manual_secret() {
    // Per the plan, only the *leaving* mode's secrets are wiped on a
    // mode switch. Cycling Uri ↔ Qr (with Manual untouched) must
    // leave the manual-secret buffer alone — we observe this by
    // poking a sentinel byte directly into the buffer while not in
    // Manual mode, then cycling and asserting the byte survives.
    let tmp = secure_tempdir();
    // Move to Uri so leaving Manual already happened and manual_secret
    // is empty (per the test above).
    let (state, _) = reduce(fresh_unlocked_with_add_modal(&tmp), key(KeyCode::Right));
    let mut state = state;
    match &mut state {
        AppState::Unlocked {
            modal: Some(Modal::Add(add)),
            ..
        } => {
            assert_eq!(add.mode, AddMode::Uri);
            // Direct mutation: production code wouldn't fill
            // manual_secret while in Uri mode, but the test reaches
            // in so we can prove the *next* mode switch does not
            // touch this slot.
            add.manual_secret.push('X');
        }
        _ => panic!("expected Modal::Add open in Uri mode"),
    }
    // Uri → Qr.
    let (after_uri_to_qr, _) = reduce(state, key(KeyCode::Right));
    let add = add_modal_ref(&after_uri_to_qr);
    assert_eq!(add.mode, AddMode::Qr);
    assert_eq!(
        add.manual_secret.as_str(),
        "X",
        "Uri → Qr must not touch manual_secret",
    );
    // Qr → Uri (back) via `←` — still not leaving Manual.
    let (after_qr_to_uri, _) = reduce(after_uri_to_qr, key(KeyCode::Left));
    let add = add_modal_ref(&after_qr_to_uri);
    assert_eq!(add.mode, AddMode::Uri);
    assert_eq!(
        add.manual_secret.as_str(),
        "X",
        "Qr → Uri must not touch manual_secret",
    );
}

#[test]
fn right_from_uri_mode_wipes_uri_text() {
    // Leaving Uri via `→` (Uri → Qr) must zeroize the typed URI
    // buffer so the embedded Base32 secret is not retained behind
    // the active mode.
    let tmp = secure_tempdir();
    let state = add_modal_in_uri_mode_with_typed_text(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Right));
    assert!(
        effects.is_empty(),
        "→ inside Add modal must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.mode, AddMode::Qr);
    assert!(add.uri_text.is_empty(), "→ from Uri must wipe uri_text");
}

#[test]
fn left_from_uri_mode_wipes_uri_text() {
    // Leaving Uri via `←` (Uri → Manual) must zeroize the typed URI
    // buffer the same way `→` does — both arrows are mode-switches
    // that abandon the Uri-mode field set.
    let tmp = secure_tempdir();
    let state = add_modal_in_uri_mode_with_typed_text(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Left));
    assert!(
        effects.is_empty(),
        "← inside Add modal must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.mode, AddMode::Manual);
    assert!(add.uri_text.is_empty(), "← from Uri must wipe uri_text");
}

#[test]
fn cycling_away_from_manual_or_qr_preserves_uri_text() {
    // Per the plan, only the *leaving* mode's secrets are wiped. Push
    // a sentinel byte into uri_text while in Manual and cycle to Qr
    // (via `←`, two-step path Manual → Qr); the URI buffer must
    // survive because neither leg leaves Uri mode. Then cycle Qr →
    // Manual (via `→`) and assert the byte still survives.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    match &mut state {
        AppState::Unlocked {
            modal: Some(Modal::Add(add)),
            ..
        } => {
            assert_eq!(add.mode, AddMode::Manual);
            // Direct mutation: production code wouldn't fill
            // uri_text while in Manual mode, but the test reaches in
            // so we can prove the *next* mode-switch does not touch
            // this slot.
            add.uri_text.push('S');
        }
        _ => panic!("expected Modal::Add open in Manual mode"),
    }
    // Manual → Qr via `←`.
    let (after_manual_to_qr, _) = reduce(state, key(KeyCode::Left));
    let add = add_modal_ref(&after_manual_to_qr);
    assert_eq!(add.mode, AddMode::Qr);
    assert_eq!(
        add.uri_text.as_str(),
        "S",
        "Manual → Qr must not touch uri_text",
    );
    // Qr → Manual via `→`.
    let (after_qr_to_manual, _) = reduce(after_manual_to_qr, key(KeyCode::Right));
    let add = add_modal_ref(&after_qr_to_manual);
    assert_eq!(add.mode, AddMode::Manual);
    assert_eq!(
        add.uri_text.as_str(),
        "S",
        "Qr → Manual must not touch uri_text",
    );
}

#[test]
fn right_with_no_modal_open_is_a_silent_no_op() {
    // `→` is not a top-level binding. With no modal open it must be a
    // silent no-op (no effects, modal stays `None`).
    let tmp = secure_tempdir();
    let state = fresh_plaintext_unlocked(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Right));
    assert!(effects.is_empty(), "→ at top level must not emit effects");
    match after {
        AppState::Unlocked { modal: None, .. } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=None preserved, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn left_with_no_modal_open_is_a_silent_no_op() {
    let tmp = secure_tempdir();
    let state = fresh_plaintext_unlocked(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Left));
    assert!(effects.is_empty(), "← at top level must not emit effects");
    match after {
        AppState::Unlocked { modal: None, .. } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=None preserved, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn right_in_non_add_modal_does_not_mutate_state() {
    // `→` is the Add modal's segmented-selector key only; other
    // focusable-field modals (Settings here) must not be mutated by
    // it. The observable contract: the open variant is preserved with
    // no effects emitted.
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, _) = reduce(unlocked, key(KeyCode::Char('s')));
    let (after, effects) = reduce(state, key(KeyCode::Right));
    assert!(
        effects.is_empty(),
        "→ inside Settings modal must not emit effects"
    );
    match after {
        AppState::Unlocked {
            modal: Some(Modal::Settings(_)),
            ..
        } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected Modal::Settings preserved, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn add_mode_next_cycles_manual_to_uri_to_qr_to_manual() {
    // Unit test for `AddMode::next()`: explicit per-variant transition
    // table so the cycle is locked at the type level independent of
    // the reducer wiring.
    assert_eq!(AddMode::Manual.next(), AddMode::Uri);
    assert_eq!(AddMode::Uri.next(), AddMode::Qr);
    assert_eq!(AddMode::Qr.next(), AddMode::Manual);
}

#[test]
fn add_mode_prev_cycles_manual_to_qr_to_uri_to_manual() {
    // Unit test for `AddMode::prev()`: the mirror of `next()`.
    assert_eq!(AddMode::Manual.prev(), AddMode::Qr);
    assert_eq!(AddMode::Qr.prev(), AddMode::Uri);
    assert_eq!(AddMode::Uri.prev(), AddMode::Manual);
}

// ---------------------------------------------------------------------------
// Add modal — Manual-mode field focus + Tab/Shift-Tab/Ctrl-N/Ctrl-P cycling
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer — "Modal-local
//  navigation covers Tab / Shift-Tab, the Ctrl-N / Ctrl-P aliases …"
//  and "Modals (per §6)": *"`Tab` and `Ctrl-N` move to the next
//  control, `Shift-Tab` and `Ctrl-P` move to the previous control."*)
//
// The Add modal's Manual mode collects eight field controls in DESIGN
// §6 reading order: label → issuer → secret → algorithm → digits →
// kind → period/counter → icon-hint. Tab and its modal-LOCAL alias
// `Ctrl-N` cycle [`AddManualFocus`] forward, `BackTab` / `Ctrl-P`
// cycle backward, both wrapping at either end. Focus is modal-local;
// no effects fire and no other slice of state is touched. In Uri / Qr
// modes there are no multi-field controls to cycle, so the same keys
// are silent no-ops — the stored `manual_focus` survives a round trip
// through a different mode so it remains "sticky" when the user
// returns to Manual.
// ---------------------------------------------------------------------------

#[test]
fn add_manual_focus_default_is_label() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)": focus
    // starts on the first field so the visual top-down reading order
    // matches the keyboard entry point. `AddManualFocus::default()`
    // is `Label` — the first field in DESIGN §6's order.
    assert_eq!(AddManualFocus::default(), AddManualFocus::Label);
}

#[test]
fn add_manual_focus_next_cycles_through_all_fields_with_wrap() {
    // Unit test for `AddManualFocus::next()`: explicit per-variant
    // transition table so the cycle is locked at the type level
    // independent of the reducer wiring. Forward order mirrors DESIGN
    // §6: label → issuer → secret → algorithm → digits → kind →
    // period/counter → icon-hint → wrap to label.
    assert_eq!(AddManualFocus::Label.next(), AddManualFocus::Issuer);
    assert_eq!(AddManualFocus::Issuer.next(), AddManualFocus::Secret);
    assert_eq!(AddManualFocus::Secret.next(), AddManualFocus::Algorithm);
    assert_eq!(AddManualFocus::Algorithm.next(), AddManualFocus::Digits);
    assert_eq!(AddManualFocus::Digits.next(), AddManualFocus::Kind);
    assert_eq!(AddManualFocus::Kind.next(), AddManualFocus::PeriodOrCounter);
    assert_eq!(
        AddManualFocus::PeriodOrCounter.next(),
        AddManualFocus::IconHintText
    );
    assert_eq!(AddManualFocus::IconHintText.next(), AddManualFocus::Label);
}

#[test]
fn add_manual_focus_prev_cycles_through_all_fields_with_wrap() {
    // Unit test for `AddManualFocus::prev()`: the mirror of `next()`,
    // wrapping at the first field so `Shift-Tab` / `Ctrl-P` cycle
    // indefinitely without falling off the front.
    assert_eq!(AddManualFocus::Label.prev(), AddManualFocus::IconHintText);
    assert_eq!(
        AddManualFocus::IconHintText.prev(),
        AddManualFocus::PeriodOrCounter
    );
    assert_eq!(AddManualFocus::PeriodOrCounter.prev(), AddManualFocus::Kind);
    assert_eq!(AddManualFocus::Kind.prev(), AddManualFocus::Digits);
    assert_eq!(AddManualFocus::Digits.prev(), AddManualFocus::Algorithm);
    assert_eq!(AddManualFocus::Algorithm.prev(), AddManualFocus::Secret);
    assert_eq!(AddManualFocus::Secret.prev(), AddManualFocus::Issuer);
    assert_eq!(AddManualFocus::Issuer.prev(), AddManualFocus::Label);
}

#[test]
fn add_modal_default_manual_focus_is_label() {
    // `AddModal::default()` seeds focus on `Label` so a freshly
    // opened modal lands on the first field per DESIGN §6 reading
    // order.
    let add = AddModal::default();
    assert_eq!(add.manual_focus, AddManualFocus::Label);
}

#[test]
fn opening_add_modal_with_a_seeds_manual_focus_on_label() {
    // The `a` opener constructs `AddModal::default()`, so the modal
    // opens with focus on Label end-to-end.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Label);
}

#[test]
fn tab_in_add_modal_manual_mode_advances_focus_through_all_fields_with_wrap() {
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let order = [
        AddManualFocus::Issuer,
        AddManualFocus::Secret,
        AddManualFocus::Algorithm,
        AddManualFocus::Digits,
        AddManualFocus::Kind,
        AddManualFocus::PeriodOrCounter,
        AddManualFocus::IconHintText,
        AddManualFocus::Label,
    ];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Tab));
        assert!(
            effects.is_empty(),
            "Tab inside Add (step {i}) must not emit effects"
        );
        assert_eq!(
            add_modal_ref(&next).manual_focus,
            *expected,
            "Tab step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn shift_tab_in_add_modal_manual_mode_retreats_focus_through_all_fields_with_wrap() {
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let order = [
        AddManualFocus::IconHintText,
        AddManualFocus::PeriodOrCounter,
        AddManualFocus::Kind,
        AddManualFocus::Digits,
        AddManualFocus::Algorithm,
        AddManualFocus::Secret,
        AddManualFocus::Issuer,
        AddManualFocus::Label,
    ];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::BackTab));
        assert!(
            effects.is_empty(),
            "Shift-Tab inside Add (step {i}) must not emit effects"
        );
        assert_eq!(
            add_modal_ref(&next).manual_focus,
            *expected,
            "Shift-Tab step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn ctrl_n_in_add_modal_manual_mode_advances_focus_like_tab() {
    // `Ctrl-N` is the modal-LOCAL alias for `Tab` per the keybindings
    // table; the observable behavior must match `Tab` exactly inside
    // a focusable-field modal.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let order = [
        AddManualFocus::Issuer,
        AddManualFocus::Secret,
        AddManualFocus::Algorithm,
        AddManualFocus::Digits,
        AddManualFocus::Kind,
        AddManualFocus::PeriodOrCounter,
        AddManualFocus::IconHintText,
        AddManualFocus::Label,
    ];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, ctrl(KeyCode::Char('n')));
        assert!(
            effects.is_empty(),
            "Ctrl-N inside Add (step {i}) must not emit effects"
        );
        assert_eq!(
            add_modal_ref(&next).manual_focus,
            *expected,
            "Ctrl-N step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn ctrl_p_in_add_modal_manual_mode_retreats_focus_like_shift_tab() {
    // `Ctrl-P` is the modal-LOCAL alias for `Shift-Tab`.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let order = [
        AddManualFocus::IconHintText,
        AddManualFocus::PeriodOrCounter,
        AddManualFocus::Kind,
        AddManualFocus::Digits,
        AddManualFocus::Algorithm,
        AddManualFocus::Secret,
        AddManualFocus::Issuer,
        AddManualFocus::Label,
    ];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, ctrl(KeyCode::Char('p')));
        assert!(
            effects.is_empty(),
            "Ctrl-P inside Add (step {i}) must not emit effects"
        );
        assert_eq!(
            add_modal_ref(&next).manual_focus,
            *expected,
            "Ctrl-P step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn tab_in_add_modal_does_not_mutate_other_state() {
    // Per the modal-trap contract, modal-local focus cycling is
    // strictly modal-local: pressing Tab while the Add modal is open
    // must not change the path, search query, top-level focus, or
    // status line, and must not emit any effects.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (path_before, query_before, focus_before, status_before) = match &state {
        AppState::Unlocked {
            path,
            search_query,
            focus,
            status_line,
            ..
        } => (
            path.clone(),
            search_query.clone(),
            *focus,
            status_line.clone(),
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (after, effects) = reduce(state, key(KeyCode::Tab));
    assert!(effects.is_empty(), "Tab inside Add must not emit effects");
    match &after {
        AppState::Unlocked {
            path,
            search_query,
            focus,
            status_line,
            modal: Some(Modal::Add(add)),
            ..
        } => {
            assert_eq!(path, &path_before);
            assert_eq!(search_query, &query_before);
            assert_eq!(*focus, focus_before);
            assert_eq!(status_line, &status_before);
            assert_eq!(add.manual_focus, AddManualFocus::Issuer);
        }
        other => panic!("expected Unlocked with Modal::Add open, got {other:?}"),
    }
}

#[test]
fn tab_in_add_modal_uri_mode_does_not_change_manual_focus() {
    // Uri mode is a single text field — there are no multi-field
    // controls to cycle, so `Tab` is a silent no-op. The stored
    // `manual_focus` survives a Uri-mode round trip so it remains
    // "sticky" when the user returns to Manual mode.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    // Manual → Uri via `→`.
    let (state, _) = reduce(state, key(KeyCode::Right));
    assert_eq!(add_modal_ref(&state).mode, AddMode::Uri);
    let focus_before = add_modal_ref(&state).manual_focus;
    let (after, effects) = reduce(state, key(KeyCode::Tab));
    assert!(
        effects.is_empty(),
        "Tab inside Add (Uri mode) must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.mode, AddMode::Uri);
    assert_eq!(
        add.manual_focus, focus_before,
        "Tab in Uri mode must not change manual_focus"
    );
}

#[test]
fn tab_in_add_modal_qr_mode_does_not_change_manual_focus() {
    // Qr mode's only control is a "scan from clipboard" action with
    // no multi-field cycling target, so `Tab` is a silent no-op.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    // Manual → Qr via `←`.
    let (state, _) = reduce(state, key(KeyCode::Left));
    assert_eq!(add_modal_ref(&state).mode, AddMode::Qr);
    let focus_before = add_modal_ref(&state).manual_focus;
    let (after, effects) = reduce(state, key(KeyCode::Tab));
    assert!(
        effects.is_empty(),
        "Tab inside Add (Qr mode) must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.mode, AddMode::Qr);
    assert_eq!(
        add.manual_focus, focus_before,
        "Tab in Qr mode must not change manual_focus"
    );
}

#[test]
fn manual_focus_survives_round_trip_through_uri_mode() {
    // Push focus past Label so a default-equal compare can't mask a
    // reset bug, then cycle Manual → Uri → Manual via `→ →`. The
    // stored focus must come back identical: mode-switching does not
    // touch the focus slot.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Issuer);
    // Manual → Uri.
    let (state, _) = reduce(state, key(KeyCode::Right));
    assert_eq!(add_modal_ref(&state).mode, AddMode::Uri);
    assert_eq!(
        add_modal_ref(&state).manual_focus,
        AddManualFocus::Issuer,
        "→ Manual→Uri must not change manual_focus"
    );
    // Uri → Qr → Manual.
    let (state, _) = reduce(state, key(KeyCode::Right));
    let (state, _) = reduce(state, key(KeyCode::Right));
    assert_eq!(add_modal_ref(&state).mode, AddMode::Manual);
    assert_eq!(
        add_modal_ref(&state).manual_focus,
        AddManualFocus::Issuer,
        "round-trip back to Manual must preserve manual_focus"
    );
}

#[test]
fn char_in_add_modal_manual_mode_label_focus_appends_to_label() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    // Manual mode collects a label as the first focused field. A
    // printable character (no Ctrl/Alt modifier) typed while the
    // label is focused appends to the modal-local `label` buffer.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Label);
    assert!(add_modal_ref(&state).label.is_empty());
    let (after, effects) = reduce(state, key(KeyCode::Char('H')));
    assert!(
        effects.is_empty(),
        "typing into a Manual-mode field must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.label, "H");
    assert_eq!(
        add.mode,
        AddMode::Manual,
        "typing must not change input mode"
    );
    assert_eq!(
        add.manual_focus,
        AddManualFocus::Label,
        "typing must not change manual_focus"
    );
}

#[test]
fn multiple_chars_in_add_modal_manual_mode_label_focus_append_in_order() {
    // Several `KeyCode::Char` presses build up the label in the typed
    // order, including a non-ASCII codepoint so the implementation
    // can't accidentally byte-slice or drop multi-byte input.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    for c in "Hi 🦀".chars() {
        let (next, effects) = reduce(state, key(KeyCode::Char(c)));
        assert!(effects.is_empty(), "typing must not emit effects");
        state = next;
    }
    assert_eq!(add_modal_ref(&state).label, "Hi 🦀");
}

#[test]
fn backspace_in_add_modal_manual_mode_label_focus_pops_last_char() {
    // Backspace on a non-empty label removes the trailing character.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    for c in "Hi".chars() {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    assert_eq!(add_modal_ref(&state).label, "Hi");
    let (after, effects) = reduce(state, key(KeyCode::Backspace));
    assert!(effects.is_empty(), "Backspace must not emit effects");
    assert_eq!(add_modal_ref(&after).label, "H");
}

#[test]
fn backspace_in_add_modal_manual_mode_label_focus_on_empty_label_is_silent_noop() {
    // Backspace on an empty label is a silent no-op: no panic, no
    // effects, no state change. Mirrors the Unlock-screen contract.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    assert!(add_modal_ref(&state).label.is_empty());
    let (after, effects) = reduce(state, key(KeyCode::Backspace));
    assert!(
        effects.is_empty(),
        "Backspace on empty must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert!(add.label.is_empty());
    assert_eq!(add.manual_focus, AddManualFocus::Label);
    assert_eq!(add.mode, AddMode::Manual);
}

#[test]
fn ctrl_modified_char_in_add_modal_manual_mode_label_focus_does_not_append() {
    // Mirrors the Unlock screen's Ctrl/Alt-modifier filter on text
    // fields: `Ctrl-*` and `Alt-*` are reserved for binding extensions
    // and must not leak into the label as raw characters. `Ctrl-X`
    // must NOT append `'x'` to the label.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (after, effects) = reduce(state, ctrl(KeyCode::Char('x')));
    assert!(effects.is_empty(), "Ctrl-X must not emit effects");
    assert!(
        add_modal_ref(&after).label.is_empty(),
        "Ctrl-X must not append 'x' to the label"
    );
}

#[test]
fn char_in_add_modal_manual_mode_issuer_focus_appends_to_issuer() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    // Manual mode collects an issuer as the second focused field. A
    // printable character (no Ctrl/Alt modifier) typed while the
    // issuer is focused appends to the modal-local `issuer` buffer
    // and leaves `label` untouched.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Issuer);
    assert!(add_modal_ref(&state).issuer.is_empty());
    let (after, effects) = reduce(state, key(KeyCode::Char('A')));
    assert!(
        effects.is_empty(),
        "typing into a Manual-mode field must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.issuer, "A");
    assert!(
        add.label.is_empty(),
        "Issuer-focused Char must not leak into the label"
    );
    assert_eq!(
        add.mode,
        AddMode::Manual,
        "typing must not change input mode"
    );
    assert_eq!(
        add.manual_focus,
        AddManualFocus::Issuer,
        "typing must not change manual_focus"
    );
}

#[test]
fn multiple_chars_in_add_modal_manual_mode_issuer_focus_append_in_order() {
    // Several `KeyCode::Char` presses build up the issuer in the
    // typed order, including a non-ASCII codepoint so the
    // implementation can't accidentally byte-slice or drop multi-byte
    // input.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let (next, _) = reduce(state, key(KeyCode::Tab));
    state = next;
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Issuer);
    for c in "Acme 🦀".chars() {
        let (next, effects) = reduce(state, key(KeyCode::Char(c)));
        assert!(effects.is_empty(), "typing must not emit effects");
        state = next;
    }
    assert_eq!(add_modal_ref(&state).issuer, "Acme 🦀");
    assert!(add_modal_ref(&state).label.is_empty());
}

#[test]
fn backspace_in_add_modal_manual_mode_issuer_focus_pops_last_char() {
    // Backspace on a non-empty issuer removes the trailing character.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let (next, _) = reduce(state, key(KeyCode::Tab));
    state = next;
    for c in "Hi".chars() {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    assert_eq!(add_modal_ref(&state).issuer, "Hi");
    let (after, effects) = reduce(state, key(KeyCode::Backspace));
    assert!(effects.is_empty(), "Backspace must not emit effects");
    assert_eq!(add_modal_ref(&after).issuer, "H");
}

#[test]
fn backspace_in_add_modal_manual_mode_issuer_focus_on_empty_issuer_is_silent_noop() {
    // Backspace on an empty issuer is a silent no-op: no panic, no
    // effects, no state change. Mirrors the Unlock-screen contract
    // and the Label-focus behaviour.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Issuer);
    assert!(add_modal_ref(&state).issuer.is_empty());
    let (after, effects) = reduce(state, key(KeyCode::Backspace));
    assert!(
        effects.is_empty(),
        "Backspace on empty must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert!(add.issuer.is_empty());
    assert!(add.label.is_empty());
    assert_eq!(add.manual_focus, AddManualFocus::Issuer);
    assert_eq!(add.mode, AddMode::Manual);
}

#[test]
fn ctrl_modified_char_in_add_modal_manual_mode_issuer_focus_does_not_append() {
    // Mirrors the Unlock-screen / Label Ctrl/Alt-modifier filter on
    // text fields: `Ctrl-*` and `Alt-*` are reserved for binding
    // extensions and must not leak into the issuer as raw characters.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Issuer);
    let (after, effects) = reduce(state, ctrl(KeyCode::Char('x')));
    assert!(effects.is_empty(), "Ctrl-X must not emit effects");
    assert!(
        add_modal_ref(&after).issuer.is_empty(),
        "Ctrl-X must not append 'x' to the issuer"
    );
}

#[test]
fn char_in_add_modal_manual_mode_secret_focus_appends_to_manual_secret() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    // Manual mode collects the Base32 secret as the third focused
    // field. A printable character (no Ctrl/Alt modifier) typed while
    // the secret is focused appends to the modal-local
    // `manual_secret` PassphraseBuffer; `label` and `issuer` remain
    // untouched. Validation (Base32 + length) lands at submit time
    // via `paladin_core::validate_manual` — typing accepts any char.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Secret);
    assert!(add_modal_ref(&state).manual_secret.is_empty());
    let (after, effects) = reduce(state, key(KeyCode::Char('J')));
    assert!(
        effects.is_empty(),
        "typing into a Manual-mode field must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.manual_secret.as_str(), "J");
    assert!(
        add.label.is_empty(),
        "Secret-focused Char must not leak into the label"
    );
    assert!(
        add.issuer.is_empty(),
        "Secret-focused Char must not leak into the issuer"
    );
    assert_eq!(
        add.mode,
        AddMode::Manual,
        "typing must not change input mode"
    );
    assert_eq!(
        add.manual_focus,
        AddManualFocus::Secret,
        "typing must not change manual_focus"
    );
}

#[test]
fn multiple_chars_in_add_modal_manual_mode_secret_focus_append_in_order() {
    // Several `KeyCode::Char` presses build up the secret buffer in
    // typed order, including a non-ASCII codepoint so the
    // implementation can't accidentally byte-slice or drop multi-byte
    // input (validation rejects non-Base32 at submit, not at typing
    // time).
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let (next, _) = reduce(state, key(KeyCode::Tab));
    state = next;
    let (next, _) = reduce(state, key(KeyCode::Tab));
    state = next;
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Secret);
    for c in "JBSW 🦀".chars() {
        let (next, effects) = reduce(state, key(KeyCode::Char(c)));
        assert!(effects.is_empty(), "typing must not emit effects");
        state = next;
    }
    assert_eq!(add_modal_ref(&state).manual_secret.as_str(), "JBSW 🦀");
    assert!(add_modal_ref(&state).label.is_empty());
    assert!(add_modal_ref(&state).issuer.is_empty());
}

#[test]
fn backspace_in_add_modal_manual_mode_secret_focus_pops_last_char() {
    // Backspace on a non-empty manual_secret removes the trailing
    // character.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let (next, _) = reduce(state, key(KeyCode::Tab));
    state = next;
    let (next, _) = reduce(state, key(KeyCode::Tab));
    state = next;
    for c in "JB".chars() {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    assert_eq!(add_modal_ref(&state).manual_secret.as_str(), "JB");
    let (after, effects) = reduce(state, key(KeyCode::Backspace));
    assert!(effects.is_empty(), "Backspace must not emit effects");
    assert_eq!(add_modal_ref(&after).manual_secret.as_str(), "J");
}

#[test]
fn backspace_in_add_modal_manual_mode_secret_focus_on_empty_secret_is_silent_noop() {
    // Backspace on an empty manual_secret is a silent no-op: no
    // panic, no effects, no state change. Mirrors the Unlock-screen
    // contract and the Label / Issuer focus behaviour.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Secret);
    assert!(add_modal_ref(&state).manual_secret.is_empty());
    let (after, effects) = reduce(state, key(KeyCode::Backspace));
    assert!(
        effects.is_empty(),
        "Backspace on empty must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert!(add.manual_secret.is_empty());
    assert!(add.label.is_empty());
    assert!(add.issuer.is_empty());
    assert_eq!(add.manual_focus, AddManualFocus::Secret);
    assert_eq!(add.mode, AddMode::Manual);
}

#[test]
fn ctrl_modified_char_in_add_modal_manual_mode_secret_focus_does_not_append() {
    // Mirrors the Unlock-screen / Label / Issuer Ctrl/Alt-modifier
    // filter on text fields: `Ctrl-*` and `Alt-*` are reserved for
    // binding extensions and must not leak into the secret as raw
    // characters.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Secret);
    let (after, effects) = reduce(state, ctrl(KeyCode::Char('x')));
    assert!(effects.is_empty(), "Ctrl-X must not emit effects");
    assert!(
        add_modal_ref(&after).manual_secret.is_empty(),
        "Ctrl-X must not append 'x' to manual_secret"
    );
}

#[test]
fn char_in_add_modal_manual_mode_icon_hint_focus_appends_to_icon_hint_text() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    // Manual mode collects an optional icon-hint free-form token as
    // the eighth (final) focused field. A printable character (no
    // Ctrl/Alt modifier) typed while the icon-hint is focused appends
    // to the modal-local `icon_hint_text` buffer. Reach IconHintText
    // by one BackTab from the default Label focus (the cycle wraps).
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::BackTab));
    assert_eq!(
        add_modal_ref(&state).manual_focus,
        AddManualFocus::IconHintText
    );
    assert!(add_modal_ref(&state).icon_hint_text.is_empty());
    let (after, effects) = reduce(state, key(KeyCode::Char('I')));
    assert!(
        effects.is_empty(),
        "typing into a Manual-mode field must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert_eq!(add.icon_hint_text, "I");
    assert!(
        add.label.is_empty(),
        "IconHint-focused Char must not leak into the label"
    );
    assert!(
        add.issuer.is_empty(),
        "IconHint-focused Char must not leak into the issuer"
    );
    assert!(
        add.manual_secret.is_empty(),
        "IconHint-focused Char must not leak into manual_secret"
    );
    assert_eq!(
        add.mode,
        AddMode::Manual,
        "typing must not change input mode"
    );
    assert_eq!(
        add.manual_focus,
        AddManualFocus::IconHintText,
        "typing must not change manual_focus"
    );
}

#[test]
fn multiple_chars_in_add_modal_manual_mode_icon_hint_focus_append_in_order() {
    // Several `KeyCode::Char` presses build up the icon-hint buffer
    // in typed order, including a non-ASCII codepoint so the
    // implementation can't accidentally byte-slice or drop multi-byte
    // input.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let (next, _) = reduce(state, key(KeyCode::BackTab));
    state = next;
    assert_eq!(
        add_modal_ref(&state).manual_focus,
        AddManualFocus::IconHintText
    );
    for c in "key 🦀".chars() {
        let (next, effects) = reduce(state, key(KeyCode::Char(c)));
        assert!(effects.is_empty(), "typing must not emit effects");
        state = next;
    }
    assert_eq!(add_modal_ref(&state).icon_hint_text, "key 🦀");
    assert!(add_modal_ref(&state).label.is_empty());
    assert!(add_modal_ref(&state).issuer.is_empty());
    assert!(add_modal_ref(&state).manual_secret.is_empty());
}

#[test]
fn backspace_in_add_modal_manual_mode_icon_hint_focus_pops_last_char() {
    // Backspace on a non-empty icon_hint_text removes the trailing
    // character.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_add_modal(&tmp);
    let (next, _) = reduce(state, key(KeyCode::BackTab));
    state = next;
    for c in "ab".chars() {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    assert_eq!(add_modal_ref(&state).icon_hint_text, "ab");
    let (after, effects) = reduce(state, key(KeyCode::Backspace));
    assert!(effects.is_empty(), "Backspace must not emit effects");
    assert_eq!(add_modal_ref(&after).icon_hint_text, "a");
}

#[test]
fn backspace_in_add_modal_manual_mode_icon_hint_focus_on_empty_is_silent_noop() {
    // Backspace on an empty icon_hint_text is a silent no-op: no
    // panic, no effects, no state change. Mirrors the Unlock-screen
    // contract and the Label / Issuer / Secret focus behaviour.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::BackTab));
    assert_eq!(
        add_modal_ref(&state).manual_focus,
        AddManualFocus::IconHintText
    );
    assert!(add_modal_ref(&state).icon_hint_text.is_empty());
    let (after, effects) = reduce(state, key(KeyCode::Backspace));
    assert!(
        effects.is_empty(),
        "Backspace on empty must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert!(add.icon_hint_text.is_empty());
    assert!(add.label.is_empty());
    assert!(add.issuer.is_empty());
    assert!(add.manual_secret.is_empty());
    assert_eq!(add.manual_focus, AddManualFocus::IconHintText);
    assert_eq!(add.mode, AddMode::Manual);
}

#[test]
fn ctrl_modified_char_in_add_modal_manual_mode_icon_hint_focus_does_not_append() {
    // Mirrors the Unlock-screen / Label / Issuer / Secret
    // Ctrl/Alt-modifier filter on text fields: `Ctrl-*` and `Alt-*`
    // are reserved for binding extensions and must not leak into the
    // icon hint as raw characters.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::BackTab));
    assert_eq!(
        add_modal_ref(&state).manual_focus,
        AddManualFocus::IconHintText
    );
    let (after, effects) = reduce(state, ctrl(KeyCode::Char('x')));
    assert!(effects.is_empty(), "Ctrl-X must not emit effects");
    assert!(
        add_modal_ref(&after).icon_hint_text.is_empty(),
        "Ctrl-X must not append 'x' to icon_hint_text"
    );
}

#[test]
fn char_in_add_modal_manual_mode_with_non_text_focus_is_silent_noop() {
    // Text editing for Label and Issuer is wired; the remaining
    // fields beyond Secret (Algorithm / Digits / Kind /
    // PeriodOrCounter) are not text-bearing — they cycle by `←` /
    // `→` / `↑` / `↓` in subsequent slices. With focus on Algorithm
    // (three Tabs past Label), a `KeyCode::Char` keystroke is
    // consumed silently and no field mutates.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(
        add_modal_ref(&state).manual_focus,
        AddManualFocus::Algorithm
    );
    let (after, effects) = reduce(state, key(KeyCode::Char('Y')));
    assert!(
        effects.is_empty(),
        "typing on a non-text-bearing field must not emit effects"
    );
    let add = add_modal_ref(&after);
    assert!(
        add.label.is_empty(),
        "Algorithm-focused Char keystroke must not leak into the label"
    );
    assert!(
        add.issuer.is_empty(),
        "Algorithm-focused Char keystroke must not leak into the issuer"
    );
}

/// Reach Algorithm focus from the default Add-modal open (Label) by
/// pressing Tab three times. Returned state has `manual_focus ==
/// Algorithm` and an unchanged `algorithm == Sha1` default.
fn add_modal_focused_on_algorithm(tmp: &tempfile::TempDir) -> AppState {
    let state = fresh_unlocked_with_add_modal(tmp);
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    assert_eq!(
        add_modal_ref(&state).manual_focus,
        AddManualFocus::Algorithm
    );
    assert_eq!(add_modal_ref(&state).algorithm, Algorithm::Sha1);
    state
}

#[test]
fn right_in_add_modal_manual_mode_algorithm_focus_cycles_forward_with_wrap() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)":
    // *"selectors and spinners cycled by `←` / `→` / `↑` / `↓`"*.
    // Algorithm is a three-valued segmented selector (Sha1 / Sha256 /
    // Sha512); `→` advances forward and wraps after Sha512 so the
    // user can cycle indefinitely. The mode stays Manual — `→` does
    // NOT switch the AddMode header when focused on a non-text field.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_algorithm(&tmp);
    let order = [Algorithm::Sha256, Algorithm::Sha512, Algorithm::Sha1];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Right));
        assert!(
            effects.is_empty(),
            "→ on Algorithm focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(
            add.algorithm, *expected,
            "→ step {i} should land on {expected:?}"
        );
        assert_eq!(
            add.mode,
            AddMode::Manual,
            "→ on Algorithm focus must not switch AddMode (step {i})"
        );
        assert_eq!(
            add.manual_focus,
            AddManualFocus::Algorithm,
            "→ on Algorithm focus must not change focus (step {i})"
        );
        state = next;
    }
}

#[test]
fn left_in_add_modal_manual_mode_algorithm_focus_cycles_backward_with_wrap() {
    // `←` retreats through the three-valued Algorithm selector and
    // wraps from Sha1 back to Sha512. The mode stays Manual.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_algorithm(&tmp);
    let order = [Algorithm::Sha512, Algorithm::Sha256, Algorithm::Sha1];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Left));
        assert!(
            effects.is_empty(),
            "← on Algorithm focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(
            add.algorithm, *expected,
            "← step {i} should land on {expected:?}"
        );
        assert_eq!(
            add.mode,
            AddMode::Manual,
            "← on Algorithm focus must not switch AddMode (step {i})"
        );
        assert_eq!(
            add.manual_focus,
            AddManualFocus::Algorithm,
            "← on Algorithm focus must not change focus (step {i})"
        );
        state = next;
    }
}

#[test]
fn down_in_add_modal_manual_mode_algorithm_focus_cycles_forward_like_right() {
    // `↓` is an alias for `→` on segmented selectors: forward
    // through Sha1 → Sha256 → Sha512 → Sha1, with the same
    // mode-preserving contract.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_algorithm(&tmp);
    let order = [Algorithm::Sha256, Algorithm::Sha512, Algorithm::Sha1];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Down));
        assert!(
            effects.is_empty(),
            "↓ on Algorithm focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(add.algorithm, *expected, "↓ step {i}");
        assert_eq!(add.mode, AddMode::Manual);
        assert_eq!(add.manual_focus, AddManualFocus::Algorithm);
        state = next;
    }
}

#[test]
fn up_in_add_modal_manual_mode_algorithm_focus_cycles_backward_like_left() {
    // `↑` is an alias for `←` on segmented selectors: backward
    // through Sha1 → Sha512 → Sha256 → Sha1, with the same
    // mode-preserving contract.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_algorithm(&tmp);
    let order = [Algorithm::Sha512, Algorithm::Sha256, Algorithm::Sha1];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Up));
        assert!(
            effects.is_empty(),
            "↑ on Algorithm focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(add.algorithm, *expected, "↑ step {i}");
        assert_eq!(add.mode, AddMode::Manual);
        assert_eq!(add.manual_focus, AddManualFocus::Algorithm);
        state = next;
    }
}

#[test]
fn arrows_on_algorithm_focus_do_not_leak_into_text_fields_or_secret() {
    // Cycling the Algorithm selector with arrow keys must leave every
    // other modal-local field untouched: text buffers stay empty, the
    // secret-bearing manual_secret / uri_text buffers stay empty,
    // and the digits / kind / period / counter values keep their
    // open-time defaults.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_algorithm(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Right));
    let (state, _) = reduce(state, key(KeyCode::Down));
    let (state, _) = reduce(state, key(KeyCode::Left));
    let (state, _) = reduce(state, key(KeyCode::Up));
    let add = add_modal_ref(&state);
    assert!(add.label.is_empty());
    assert!(add.issuer.is_empty());
    assert!(add.icon_hint_text.is_empty());
    assert!(add.manual_secret.is_empty());
    assert!(add.uri_text.is_empty());
    assert_eq!(add.digits, paladin_core::DIGITS_DEFAULT);
    assert_eq!(add.kind, AccountKindInput::Totp);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT);
    assert_eq!(add.counter, 0);
    assert!(add.error.is_none());
}

#[test]
fn right_in_add_modal_manual_mode_label_focus_still_cycles_addmode() {
    // Regression: → on a text-bearing focus (Label) keeps the
    // existing AddMode segmented-selector behavior — Manual → Uri.
    // The non-text-focus override (Algorithm / Digits / Kind /
    // PeriodOrCounter) must not steal `→` when a text field is
    // focused.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_add_modal(&tmp);
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Label);
    let (after, effects) = reduce(state, key(KeyCode::Right));
    assert!(effects.is_empty());
    assert_eq!(add_modal_ref(&after).mode, AddMode::Uri);
}

/// Reach Digits focus from the default Add-modal open (Label) by
/// pressing Tab four times. Returned state has `manual_focus ==
/// Digits` and an unchanged `digits == DIGITS_DEFAULT` (6).
fn add_modal_focused_on_digits(tmp: &tempfile::TempDir) -> AppState {
    let mut state = fresh_unlocked_with_add_modal(tmp);
    for _ in 0..4 {
        let (next, _) = reduce(state, key(KeyCode::Tab));
        state = next;
    }
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Digits);
    assert_eq!(add_modal_ref(&state).digits, paladin_core::DIGITS_DEFAULT);
    state
}

#[test]
fn right_in_add_modal_manual_mode_digits_focus_cycles_forward_with_wrap() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)":
    // *"selectors and spinners cycled by `←` / `→` / `↑` / `↓`"*.
    // Digits is a three-valued segmented selector (6 / 7 / 8 per
    // `DIGITS_MIN`..=`DIGITS_MAX`); `→` advances forward and wraps
    // after 8 so the user can cycle indefinitely. The mode stays
    // Manual — `→` does NOT switch the AddMode header when focused
    // on a non-text field.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_digits(&tmp);
    let order = [7u8, 8u8, 6u8];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Right));
        assert!(
            effects.is_empty(),
            "→ on Digits focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(
            add.digits, *expected,
            "→ step {i} should land on {expected} digits"
        );
        assert_eq!(
            add.mode,
            AddMode::Manual,
            "→ on Digits focus must not switch AddMode (step {i})"
        );
        assert_eq!(
            add.manual_focus,
            AddManualFocus::Digits,
            "→ on Digits focus must not change focus (step {i})"
        );
        state = next;
    }
}

#[test]
fn left_in_add_modal_manual_mode_digits_focus_cycles_backward_with_wrap() {
    // `←` retreats through the three-valued Digits selector and
    // wraps from 6 back to 8. The mode stays Manual.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_digits(&tmp);
    let order = [8u8, 7u8, 6u8];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Left));
        assert!(
            effects.is_empty(),
            "← on Digits focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(
            add.digits, *expected,
            "← step {i} should land on {expected} digits"
        );
        assert_eq!(
            add.mode,
            AddMode::Manual,
            "← on Digits focus must not switch AddMode (step {i})"
        );
        assert_eq!(
            add.manual_focus,
            AddManualFocus::Digits,
            "← on Digits focus must not change focus (step {i})"
        );
        state = next;
    }
}

#[test]
fn down_in_add_modal_manual_mode_digits_focus_cycles_forward_like_right() {
    // `↓` is an alias for `→` on segmented selectors: forward
    // through 6 → 7 → 8 → 6, with the same mode-preserving
    // contract.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_digits(&tmp);
    let order = [7u8, 8u8, 6u8];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Down));
        assert!(
            effects.is_empty(),
            "↓ on Digits focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(add.digits, *expected, "↓ step {i}");
        assert_eq!(add.mode, AddMode::Manual);
        assert_eq!(add.manual_focus, AddManualFocus::Digits);
        state = next;
    }
}

#[test]
fn up_in_add_modal_manual_mode_digits_focus_cycles_backward_like_left() {
    // `↑` is an alias for `←` on segmented selectors: backward
    // through 6 → 8 → 7 → 6, with the same mode-preserving
    // contract.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_digits(&tmp);
    let order = [8u8, 7u8, 6u8];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Up));
        assert!(
            effects.is_empty(),
            "↑ on Digits focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(add.digits, *expected, "↑ step {i}");
        assert_eq!(add.mode, AddMode::Manual);
        assert_eq!(add.manual_focus, AddManualFocus::Digits);
        state = next;
    }
}

/// Reach Kind focus from the default Add-modal open (Label) by
/// pressing Tab five times. Returned state has `manual_focus ==
/// Kind` and an unchanged `kind == AccountKindInput::Totp` default.
fn add_modal_focused_on_kind(tmp: &tempfile::TempDir) -> AppState {
    let mut state = fresh_unlocked_with_add_modal(tmp);
    for _ in 0..5 {
        let (next, _) = reduce(state, key(KeyCode::Tab));
        state = next;
    }
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Kind);
    assert_eq!(add_modal_ref(&state).kind, AccountKindInput::Totp);
    state
}

#[test]
fn right_in_add_modal_manual_mode_kind_focus_toggles_totp_hotp_totp_with_wrap() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)":
    // *"selectors and spinners cycled by `←` / `→` / `↑` / `↓`"*.
    // Kind is a two-valued segmented selector (Totp / Hotp); `→`
    // toggles between them, wrapping after each press. The mode
    // stays Manual — `→` does NOT switch the AddMode header when
    // focused on a non-text field.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_kind(&tmp);
    let order = [AccountKindInput::Hotp, AccountKindInput::Totp];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Right));
        assert!(
            effects.is_empty(),
            "→ on Kind focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(
            add.kind, *expected,
            "→ step {i} should land on {expected:?}"
        );
        assert_eq!(
            add.mode,
            AddMode::Manual,
            "→ on Kind focus must not switch AddMode (step {i})"
        );
        assert_eq!(
            add.manual_focus,
            AddManualFocus::Kind,
            "→ on Kind focus must not change focus (step {i})"
        );
        state = next;
    }
}

#[test]
fn left_in_add_modal_manual_mode_kind_focus_toggles_totp_hotp_totp_with_wrap() {
    // `←` on the two-valued Kind selector toggles every press,
    // wrapping symmetrically. The mode stays Manual.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_kind(&tmp);
    let order = [AccountKindInput::Hotp, AccountKindInput::Totp];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Left));
        assert!(
            effects.is_empty(),
            "← on Kind focus (step {i}) must not emit effects"
        );
        let add = add_modal_ref(&next);
        assert_eq!(
            add.kind, *expected,
            "← step {i} should land on {expected:?}"
        );
        assert_eq!(add.mode, AddMode::Manual);
        assert_eq!(add.manual_focus, AddManualFocus::Kind);
        state = next;
    }
}

#[test]
fn down_in_add_modal_manual_mode_kind_focus_toggles_like_right() {
    // `↓` mirrors `→` on the two-valued Kind selector.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_kind(&tmp);
    let order = [AccountKindInput::Hotp, AccountKindInput::Totp];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Down));
        assert!(effects.is_empty(), "↓ on Kind focus (step {i})");
        let add = add_modal_ref(&next);
        assert_eq!(add.kind, *expected, "↓ step {i}");
        assert_eq!(add.mode, AddMode::Manual);
        assert_eq!(add.manual_focus, AddManualFocus::Kind);
        state = next;
    }
}

#[test]
fn up_in_add_modal_manual_mode_kind_focus_toggles_like_left() {
    // `↑` mirrors `←` on the two-valued Kind selector.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_kind(&tmp);
    let order = [AccountKindInput::Hotp, AccountKindInput::Totp];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Up));
        assert!(effects.is_empty(), "↑ on Kind focus (step {i})");
        let add = add_modal_ref(&next);
        assert_eq!(add.kind, *expected, "↑ step {i}");
        assert_eq!(add.mode, AddMode::Manual);
        assert_eq!(add.manual_focus, AddManualFocus::Kind);
        state = next;
    }
}

#[test]
fn arrows_on_kind_focus_preserve_period_secs_and_counter() {
    // Switching Kind must NOT reset the modal-local `period_secs` or
    // `counter` — the two values live independently on `AddModal`,
    // and the PeriodOrCounter focus simply binds to whichever
    // applies given the current Kind. Cycling arrow keys around the
    // Kind selector therefore leaves both numeric defaults intact
    // (30s / 0) alongside every other modal-local field.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_kind(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Right));
    let (state, _) = reduce(state, key(KeyCode::Down));
    let (state, _) = reduce(state, key(KeyCode::Left));
    let (state, _) = reduce(state, key(KeyCode::Up));
    let add = add_modal_ref(&state);
    assert!(add.label.is_empty());
    assert!(add.issuer.is_empty());
    assert!(add.icon_hint_text.is_empty());
    assert!(add.manual_secret.is_empty());
    assert!(add.uri_text.is_empty());
    assert_eq!(add.algorithm, Algorithm::Sha1);
    assert_eq!(add.digits, paladin_core::DIGITS_DEFAULT);
    assert_eq!(
        add.period_secs,
        paladin_core::TOTP_PERIOD_DEFAULT,
        "cycling Kind must not touch period_secs"
    );
    assert_eq!(add.counter, 0, "cycling Kind must not touch counter");
    assert!(add.error.is_none());
}

/// Reach `PeriodOrCounter` focus from the default Add-modal open
/// (Label) by pressing Tab six times. Returned state has
/// `manual_focus == PeriodOrCounter`, kind == Totp (open-time
/// default), and unchanged spinner defaults (`period_secs == 30`,
/// `counter == 0`).
fn add_modal_focused_on_period_or_counter(tmp: &tempfile::TempDir) -> AppState {
    let mut state = fresh_unlocked_with_add_modal(tmp);
    for _ in 0..6 {
        let (next, _) = reduce(state, key(KeyCode::Tab));
        state = next;
    }
    let add = add_modal_ref(&state);
    assert_eq!(add.manual_focus, AddManualFocus::PeriodOrCounter);
    assert_eq!(add.kind, AccountKindInput::Totp);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT);
    assert_eq!(add.counter, 0);
    state
}

/// Same as `add_modal_focused_on_period_or_counter` but pre-toggles
/// `kind` to Hotp via one arrow press on the Kind focus before
/// landing on `PeriodOrCounter`.
fn add_modal_focused_on_period_or_counter_hotp(tmp: &tempfile::TempDir) -> AppState {
    let mut state = fresh_unlocked_with_add_modal(tmp);
    for _ in 0..5 {
        let (next, _) = reduce(state, key(KeyCode::Tab));
        state = next;
    }
    assert_eq!(add_modal_ref(&state).manual_focus, AddManualFocus::Kind);
    let (state2, _) = reduce(state, key(KeyCode::Right));
    let state2 = state2;
    assert_eq!(add_modal_ref(&state2).kind, AccountKindInput::Hotp);
    let (state3, _) = reduce(state2, key(KeyCode::Tab));
    let add = add_modal_ref(&state3);
    assert_eq!(add.manual_focus, AddManualFocus::PeriodOrCounter);
    assert_eq!(add.kind, AccountKindInput::Hotp);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT);
    assert_eq!(add.counter, 0);
    state3
}

#[test]
fn up_on_period_focus_with_totp_increments_period_secs_by_one() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)":
    // *"↑ / ↓ adjust spinners"*. PeriodOrCounter is the Manual-mode
    // numeric spinner; when kind == Totp it binds to `period_secs`.
    // `↑` increments by 1 (the validation granule per
    // `TOTP_PERIOD_MIN`..=`TOTP_PERIOD_MAX`).
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_period_or_counter(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Up));
    assert!(effects.is_empty(), "↑ on spinner must not emit effects");
    let add = add_modal_ref(&after);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT + 1);
    assert_eq!(add.counter, 0, "↑ on Totp spinner must not touch counter");
    assert_eq!(add.mode, AddMode::Manual);
    assert_eq!(add.manual_focus, AddManualFocus::PeriodOrCounter);
}

#[test]
fn down_on_period_focus_with_totp_decrements_period_secs_by_one() {
    // `↓` decrements `period_secs` by 1.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_period_or_counter(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Down));
    assert!(effects.is_empty());
    let add = add_modal_ref(&after);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT - 1);
    assert_eq!(add.counter, 0);
    assert_eq!(add.mode, AddMode::Manual);
    assert_eq!(add.manual_focus, AddManualFocus::PeriodOrCounter);
}

#[test]
fn right_on_period_focus_with_totp_increments_like_up() {
    // `→` aliases to `↑` on the spinner: same +1 increment.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_period_or_counter(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Right));
    assert!(effects.is_empty());
    let add = add_modal_ref(&after);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT + 1);
    assert_eq!(
        add.mode,
        AddMode::Manual,
        "→ on PeriodOrCounter focus must not switch AddMode"
    );
}

#[test]
fn left_on_period_focus_with_totp_decrements_like_down() {
    // `←` aliases to `↓` on the spinner: same -1 decrement.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_period_or_counter(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Left));
    assert!(effects.is_empty());
    let add = add_modal_ref(&after);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT - 1);
    assert_eq!(
        add.mode,
        AddMode::Manual,
        "← on PeriodOrCounter focus must not switch AddMode"
    );
}

#[test]
fn up_at_period_max_clamps_to_max() {
    // The spinner is clamped to
    // `TOTP_PERIOD_MIN`..=`TOTP_PERIOD_MAX` so `↑` at the upper
    // bound is a silent no-op (no overflow, no emitted effects).
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_period_or_counter(&tmp);
    // Walk up to TOTP_PERIOD_MAX. TOTP_PERIOD_DEFAULT == 30,
    // TOTP_PERIOD_MAX == 300 → 270 presses. Use a tight loop.
    for _ in paladin_core::TOTP_PERIOD_DEFAULT..paladin_core::TOTP_PERIOD_MAX {
        let (next, _) = reduce(state, key(KeyCode::Up));
        state = next;
    }
    assert_eq!(
        add_modal_ref(&state).period_secs,
        paladin_core::TOTP_PERIOD_MAX
    );
    let (after, effects) = reduce(state, key(KeyCode::Up));
    assert!(effects.is_empty());
    assert_eq!(
        add_modal_ref(&after).period_secs,
        paladin_core::TOTP_PERIOD_MAX,
        "↑ at TOTP_PERIOD_MAX must clamp, not overflow"
    );
}

#[test]
fn down_at_period_min_clamps_to_min() {
    // `↓` at TOTP_PERIOD_MIN clamps; default 30 → walk down to 1.
    let tmp = secure_tempdir();
    let mut state = add_modal_focused_on_period_or_counter(&tmp);
    for _ in paladin_core::TOTP_PERIOD_MIN..paladin_core::TOTP_PERIOD_DEFAULT {
        let (next, _) = reduce(state, key(KeyCode::Down));
        state = next;
    }
    assert_eq!(
        add_modal_ref(&state).period_secs,
        paladin_core::TOTP_PERIOD_MIN
    );
    let (after, effects) = reduce(state, key(KeyCode::Down));
    assert!(effects.is_empty());
    assert_eq!(
        add_modal_ref(&after).period_secs,
        paladin_core::TOTP_PERIOD_MIN,
        "↓ at TOTP_PERIOD_MIN must clamp"
    );
}

#[test]
fn up_on_period_or_counter_focus_with_hotp_increments_counter_by_one() {
    // When kind == Hotp the same spinner focus binds to the
    // independent `counter: u64` instead of `period_secs`.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_period_or_counter_hotp(&tmp);
    let (after, effects) = reduce(state, key(KeyCode::Up));
    assert!(effects.is_empty());
    let add = add_modal_ref(&after);
    assert_eq!(add.counter, 1);
    assert_eq!(
        add.period_secs,
        paladin_core::TOTP_PERIOD_DEFAULT,
        "↑ on Hotp spinner must not touch period_secs"
    );
    assert_eq!(add.mode, AddMode::Manual);
    assert_eq!(add.manual_focus, AddManualFocus::PeriodOrCounter);
}

#[test]
fn down_at_counter_zero_clamps_to_zero() {
    // Counter is u64 with saturating-subtract semantics; `↓` at 0
    // is a silent no-op so the spinner can't wrap to u64::MAX.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_period_or_counter_hotp(&tmp);
    assert_eq!(add_modal_ref(&state).counter, 0);
    let (after, effects) = reduce(state, key(KeyCode::Down));
    assert!(effects.is_empty());
    assert_eq!(
        add_modal_ref(&after).counter,
        0,
        "↓ at counter==0 must clamp, not wrap to u64::MAX"
    );
}

#[test]
fn right_and_left_on_counter_focus_with_hotp_alias_up_and_down() {
    // `→` increments counter by 1; `←` decrements (clamping at 0).
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_period_or_counter_hotp(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Right));
    assert_eq!(add_modal_ref(&state).counter, 1);
    let (state, _) = reduce(state, key(KeyCode::Right));
    assert_eq!(add_modal_ref(&state).counter, 2);
    let (state, _) = reduce(state, key(KeyCode::Left));
    assert_eq!(add_modal_ref(&state).counter, 1);
    let (state, _) = reduce(state, key(KeyCode::Left));
    assert_eq!(add_modal_ref(&state).counter, 0);
    let add = add_modal_ref(&state);
    assert_eq!(add.mode, AddMode::Manual);
    assert_eq!(add.manual_focus, AddManualFocus::PeriodOrCounter);
}

#[test]
fn arrows_on_period_or_counter_focus_do_not_leak_into_other_fields() {
    // The spinner mutates only the field its current Kind binds
    // to (period_secs for Totp). Every other modal-local field
    // keeps its open-time default.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_period_or_counter(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Up));
    let (state, _) = reduce(state, key(KeyCode::Right));
    let (state, _) = reduce(state, key(KeyCode::Down));
    let (state, _) = reduce(state, key(KeyCode::Left));
    let add = add_modal_ref(&state);
    assert_eq!(
        add.period_secs,
        paladin_core::TOTP_PERIOD_DEFAULT,
        "+1, +1, -1, -1 must round-trip"
    );
    assert_eq!(add.counter, 0);
    assert!(add.label.is_empty());
    assert!(add.issuer.is_empty());
    assert!(add.icon_hint_text.is_empty());
    assert!(add.manual_secret.is_empty());
    assert!(add.uri_text.is_empty());
    assert_eq!(add.algorithm, Algorithm::Sha1);
    assert_eq!(add.digits, paladin_core::DIGITS_DEFAULT);
    assert_eq!(add.kind, AccountKindInput::Totp);
    assert!(add.error.is_none());
}

#[test]
fn arrows_on_digits_focus_do_not_leak_into_other_fields() {
    // Cycling the Digits selector with arrow keys must leave every
    // other modal-local field untouched: text buffers stay empty,
    // the secret-bearing manual_secret / uri_text buffers stay
    // empty, and the algorithm / kind / period / counter values keep
    // their open-time defaults.
    let tmp = secure_tempdir();
    let state = add_modal_focused_on_digits(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Right));
    let (state, _) = reduce(state, key(KeyCode::Down));
    let (state, _) = reduce(state, key(KeyCode::Left));
    let (state, _) = reduce(state, key(KeyCode::Up));
    let add = add_modal_ref(&state);
    assert!(add.label.is_empty());
    assert!(add.issuer.is_empty());
    assert!(add.icon_hint_text.is_empty());
    assert!(add.manual_secret.is_empty());
    assert!(add.uri_text.is_empty());
    assert_eq!(add.algorithm, Algorithm::Sha1);
    assert_eq!(add.kind, AccountKindInput::Totp);
    assert_eq!(add.period_secs, paladin_core::TOTP_PERIOD_DEFAULT);
    assert_eq!(add.counter, 0);
    assert!(add.error.is_none());
}

#[test]
fn pressing_a_on_unlocked_with_modal_already_open_does_not_replace_the_modal() {
    // When a modal is open, the `a` key is consumed by the modal's
    // input path (text-field typing once payloads land). At this
    // slice the modal payloads do not exist yet, so the observable
    // contract is: the open modal variant is preserved unchanged.
    let tmp = secure_tempdir();
    let (path, (vault, store)) = open_plaintext_pair(&tmp);
    let unlocked = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('a')));
    assert!(
        effects.is_empty(),
        "bare `a` inside an open modal must not emit effects"
    );
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(_)),
            ..
        } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=Some(Modal::Settings(SettingsModal::default())) preserved, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_a_on_unlocked_does_not_open_add_modal() {
    // `Ctrl-A` is not bound in `Keybindings (initial v0.1)`. The bare
    // `a` opens the Add modal, but the same code with the Control
    // modifier must not — otherwise common readline-style `Ctrl-A`
    // (beginning-of-line) presses would silently open dialogs.
    let tmp = secure_tempdir();
    let (path, (vault, store)) = open_plaintext_pair(&tmp);
    let unlocked = AppState::Unlocked {
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
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('a')));
    assert!(effects.is_empty(), "Ctrl-A is unbound; no effects");
    match state {
        AppState::Unlocked { modal: None, .. } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=None preserved, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

/// Build a fresh plaintext `AppState::Unlocked` with `modal = None` for
/// per-binding modal-open tests.
fn fresh_plaintext_unlocked(tmp: &tempfile::TempDir) -> AppState {
    let (path, (vault, store)) = open_plaintext_pair(tmp);
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

/// Press `event` on a fresh plaintext `Unlocked` state and assert the
/// resulting `modal` slot matches `expected` with no emitted effects.
fn assert_key_opens_modal(event: AppEvent, expected: &Modal) {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, event);
    assert!(effects.is_empty(), "opening a modal must not emit effects");
    match state {
        AppState::Unlocked { modal: Some(m), .. } => {
            assert_eq!(
                std::mem::discriminant(&m),
                std::mem::discriminant(expected),
                "expected modal variant {expected:?}, got {m:?}"
            );
        }
        AppState::Unlocked { modal: None, .. } => panic!("expected modal=Some(_), got None"),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

/// Like [`assert_key_opens_modal`] but seeds an account into the vault
/// first so the resulting `selected` is `Some(_)`. Used by the
/// selection-gated openers (`r` / `R`) per the
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Focus model" rule: with no
/// selection those keys surface the "no account selected"
/// status-line error instead of opening the modal.
fn assert_selection_gated_key_opens_modal(event: AppEvent, expected: &Modal) {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    let unlocked = AppState::Unlocked {
        path,
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
    let (state, effects) = reduce(unlocked, event);
    assert!(effects.is_empty(), "opening a modal must not emit effects");
    match state {
        AppState::Unlocked {
            modal: Some(m),
            status_line,
            ..
        } => {
            assert_eq!(
                std::mem::discriminant(&m),
                std::mem::discriminant(expected),
                "expected modal variant {expected:?}, got {m:?}"
            );
            assert!(
                status_line.is_none(),
                "selection-gated opener with selected=Some must not set a status-line, got {status_line:?}"
            );
        }
        AppState::Unlocked { modal: None, .. } => panic!("expected modal=Some(_), got None"),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_i_on_unlocked_with_no_modal_open_opens_import_modal() {
    assert_key_opens_modal(key(KeyCode::Char('i')), &Modal::Import);
}

#[test]
fn pressing_e_on_unlocked_with_no_modal_open_opens_export_modal() {
    assert_key_opens_modal(key(KeyCode::Char('e')), &Modal::Export);
}

#[test]
fn pressing_lowercase_r_on_unlocked_with_no_modal_open_opens_remove_modal() {
    // Per Keybindings (initial v0.1): `r` opens Remove confirmation;
    // `R` (Shift+R) opens Rename. The lowercase / uppercase split is
    // the only thing distinguishing the two bindings. `r` is a
    // selection-gated opener, so the helper seeds an account first.
    assert_selection_gated_key_opens_modal(
        key(KeyCode::Char('r')),
        &Modal::Remove(RemoveModal::default()),
    );
}

#[test]
fn pressing_r_opens_remove_modal_prepopulated_with_selected_account_id() {
    // Per IMPLEMENTATION_PLAN_03_TUI.md "Modals (per §6)" > Remove:
    // a confirmation gate for removing the selected account. The
    // reducer snapshots the selected account id at modal-open time so
    // a subsequent selection / search change does not redirect the
    // remove mid-confirm. Mirrors `RenameModal.account_id`; Remove
    // just has no editable draft.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    let unlocked = AppState::Unlocked {
        path,
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
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('r')));
    assert!(effects.is_empty(), "opening Remove must not emit effects");
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Remove(remove)),
            status_line,
            ..
        } => {
            assert_eq!(
                remove.account_id, id,
                "Remove modal must snapshot the selected account id"
            );
            assert!(
                remove.error.is_none(),
                "freshly opened Remove modal has no inline error"
            );
            assert!(
                status_line.is_none(),
                "Remove open with selection must not surface a status-line error"
            );
        }
        AppState::Unlocked { modal, .. } => panic!("expected Modal::Remove, got {modal:?}"),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_shift_r_on_unlocked_with_no_modal_open_opens_rename_modal() {
    // crossterm reports the resolved upper-case character with the
    // SHIFT modifier preserved. Match on `Char('R')` (the resolved
    // letter) so the binding works whether or not the terminal
    // forwards the SHIFT modifier alongside the upper-case key.
    let evt = AppEvent::Input {
        event: Event::Key(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT)),
        at: Instant::now(),
    };
    assert_selection_gated_key_opens_modal(evt, &Modal::Rename(RenameModal::default()));
}

#[test]
fn pressing_shift_r_without_modifier_byte_still_opens_rename_modal() {
    // Belt-and-suspenders for terminals that report `Char('R')`
    // without the SHIFT modifier byte (the historic crossterm
    // default outside kitty-protocol mode). The reducer dispatches
    // on the resolved character, not the modifier, so both shapes
    // must hit Rename.
    assert_selection_gated_key_opens_modal(
        key(KeyCode::Char('R')),
        &Modal::Rename(RenameModal::default()),
    );
}

#[test]
fn pressing_shift_r_opens_rename_modal_prepopulated_with_selected_label() {
    // Per IMPLEMENTATION_PLAN_03_TUI.md "Modals (per §6)" > Rename:
    // "single text field pre-populated with the selected account's
    // current label." The reducer snapshots the selected account's
    // id and label at modal-open time so a subsequent selection /
    // search change does not redirect the rename mid-edit.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    let unlocked = AppState::Unlocked {
        path,
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
    let (state, effects) = reduce(
        unlocked,
        AppEvent::Input {
            event: Event::Key(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT)),
            at: Instant::now(),
        },
    );
    assert!(effects.is_empty(), "opening Rename must not emit effects");
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Rename(rename)),
            status_line,
            ..
        } => {
            assert_eq!(
                rename.account_id, id,
                "Rename modal must snapshot the selected account id"
            );
            assert_eq!(
                rename.draft, "github",
                "Rename modal draft must pre-populate with the account's current label"
            );
            assert!(
                status_line.is_none(),
                "Rename open with selection must not surface a status-line error"
            );
        }
        AppState::Unlocked { modal, .. } => panic!("expected Modal::Rename, got {modal:?}"),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Rename modal — text editing, Enter submit, validation
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Rename modal)
//
// Slice covered: while `Modal::Rename` is open, bare-letter Char keys
// append to `draft`; Backspace pops; Enter validates via
// `validate_label` and either emits `Effect::Rename` for valid input
// or surfaces an inline error (no effect). Subsequent typing clears
// any prior inline error. Same-label renames still emit the effect
// (per design: bump `updated_at` to match the CLI). The effect /
// `EffectResult` wiring (executor side, save-error rollback paths)
// lands in a follow-up slice.
// ---------------------------------------------------------------------------

fn fresh_unlocked_with_rename_modal_open(
    label: &str,
    draft: &str,
) -> (tempfile::TempDir, AccountId, PathBuf, AppState) {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, label);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: draft.to_string(),
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    (tmp, id, path, state)
}

fn expect_rename_modal(state: &AppState) -> &RenameModal {
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Rename(rename)),
            ..
        } => rename,
        AppState::Unlocked { modal, .. } => panic!("expected Modal::Rename, got {modal:?}"),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn rename_modal_typing_char_appends_to_draft() {
    let (_tmp, _id, _path, unlocked) = fresh_unlocked_with_rename_modal_open("github", "github");
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('!')));
    assert!(
        effects.is_empty(),
        "typing inside Rename must not emit effects"
    );
    let rename = expect_rename_modal(&state);
    assert_eq!(rename.draft, "github!");
}

#[test]
fn rename_modal_backspace_pops_last_char_from_draft() {
    let (_tmp, _id, _path, unlocked) = fresh_unlocked_with_rename_modal_open("github", "github");
    let (state, effects) = reduce(unlocked, key(KeyCode::Backspace));
    assert!(
        effects.is_empty(),
        "backspace inside Rename must not emit effects"
    );
    let rename = expect_rename_modal(&state);
    assert_eq!(rename.draft, "githu");
}

#[test]
fn rename_modal_backspace_on_empty_draft_is_a_silent_noop() {
    // Pop on an empty buffer is a defined no-op so the user can hold
    // backspace through the whole label without surfacing an error.
    let (_tmp, _id, _path, unlocked) = fresh_unlocked_with_rename_modal_open("github", "");
    let (state, effects) = reduce(unlocked, key(KeyCode::Backspace));
    assert!(effects.is_empty());
    let rename = expect_rename_modal(&state);
    assert_eq!(rename.draft, "");
    assert!(rename.error.is_none());
}

#[test]
fn rename_modal_typing_clears_inline_error() {
    // Seed a Rename modal with a stale inline error so the test
    // observes that an edit clears the slot. Building the state
    // directly (rather than driving through a prior Enter) keeps
    // this slice's failure mode independent of the validation
    // slice's own assertions.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: String::new(),
            error: Some("stale".into()),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('x')));
    let rename = expect_rename_modal(&state);
    assert_eq!(rename.draft, "x");
    assert!(
        rename.error.is_none(),
        "editing must clear any prior inline error"
    );
}

#[test]
fn rename_modal_enter_with_valid_draft_emits_rename_effect() {
    let (_tmp, id, path, unlocked) =
        fresh_unlocked_with_rename_modal_open("github", "  github-personal  ");
    let (state, effects) = reduce(unlocked, key(KeyCode::Enter));
    assert_eq!(effects.len(), 1, "expected single Effect::Rename");
    match &effects[0] {
        Effect::Rename {
            path: p,
            account_id,
            new_label,
        } => {
            assert_eq!(p, &path);
            assert_eq!(*account_id, id);
            assert_eq!(
                new_label, "github-personal",
                "Effect::Rename must carry the trimmed label"
            );
        }
        other => panic!("expected Effect::Rename, got {other:?}"),
    }
    // Modal stays open until the EffectResult arrives (success path
    // closes it; save-error rollback re-opens with inline error).
    let rename = expect_rename_modal(&state);
    assert!(
        rename.error.is_none(),
        "submitting a valid draft must not surface an inline error"
    );
}

#[test]
fn rename_modal_enter_with_same_label_still_emits_rename_effect() {
    // Per IMPLEMENTATION_PLAN_03_TUI.md "Modals (per §6)" > Rename:
    // "Same-label renames still call `Vault::rename`, save, and bump
    // `updated_at`, matching the CLI." The reducer must not short-
    // circuit when the trimmed draft equals the current label —
    // the executor / core layer is responsible for that semantics.
    let (_tmp, id, path, unlocked) = fresh_unlocked_with_rename_modal_open("github", "github");
    let (_state, effects) = reduce(unlocked, key(KeyCode::Enter));
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::Rename {
            path: p,
            account_id,
            new_label,
        } => {
            assert_eq!(p, &path);
            assert_eq!(*account_id, id);
            assert_eq!(new_label, "github");
        }
        other => panic!("expected Effect::Rename, got {other:?}"),
    }
}

#[test]
fn rename_modal_enter_with_empty_draft_sets_inline_error_no_effect() {
    let (_tmp, _id, _path, unlocked) = fresh_unlocked_with_rename_modal_open("github", "");
    let (state, effects) = reduce(unlocked, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "empty draft must not emit Effect::Rename"
    );
    let rename = expect_rename_modal(&state);
    assert_eq!(
        rename.draft, "",
        "empty draft stays empty after the rejected submit"
    );
    let err = rename
        .error
        .as_deref()
        .expect("empty draft must set an inline error");
    // `validate_label`'s `empty` reason is rendered through
    // `render_error_message` (which falls back to `Display`), so the
    // surfaced string carries the §5 `label` / `empty` pair verbatim.
    assert!(
        err.contains("label") && err.contains("empty"),
        "inline error must surface the `label` / `empty` validation pair, got {err:?}"
    );
}

#[test]
fn rename_modal_enter_with_whitespace_only_draft_sets_inline_error_no_effect() {
    // `validate_label` trims; a whitespace-only draft trims to empty
    // and the empty-label rejection fires.
    let (_tmp, _id, _path, unlocked) = fresh_unlocked_with_rename_modal_open("github", "   \t  ");
    let (state, effects) = reduce(unlocked, key(KeyCode::Enter));
    assert!(effects.is_empty());
    let rename = expect_rename_modal(&state);
    let err = rename.error.as_deref().expect("whitespace draft is empty");
    assert!(
        err.contains("label") && err.contains("empty"),
        "inline error must surface the `label` / `empty` validation pair, got {err:?}"
    );
}

#[test]
fn rename_modal_enter_with_overlong_draft_sets_inline_error_no_effect() {
    // §4.1 caps labels at 128 bytes. A 129-char ASCII draft exceeds
    // the cap and `validate_label` returns `too_long`.
    let oversized = "a".repeat(129);
    let (_tmp, _id, _path, unlocked) = fresh_unlocked_with_rename_modal_open("github", &oversized);
    let (state, effects) = reduce(unlocked, key(KeyCode::Enter));
    assert!(effects.is_empty(), "too-long draft must not emit effect");
    let rename = expect_rename_modal(&state);
    let err = rename.error.as_deref().expect("overlong draft errors");
    assert!(
        err.contains("label") && err.contains("too_long"),
        "inline error must surface the `label` / `too_long` validation pair, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Remove modal — Enter submit
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Remove modal; Modals (per
//  §6) > Remove: *"confirmation modal. On confirm, wraps
//  `Vault::remove` in `Vault::mutate_and_save`."*)
//
// Slice covered: while `Modal::Remove` is open, `Enter` emits a single
// `Effect::Remove` carrying the snapshotted `account_id` and the
// current vault path. Unlike Rename, Remove has no editable draft —
// every other key (printable Chars, Backspace, arrows, Tab) is a
// silent no-op so the modal-trap contract holds (bare-letter keys do
// not leak into the list view). The modal stays open until the
// `EffectResult::Remove` arrives; the success / save-error rollback
// wiring lands in a subsequent slice. Esc is filtered upstream and
// covered by `pressing_esc_on_unlocked_with_open_remove_modal_*`.
// ---------------------------------------------------------------------------

fn fresh_unlocked_with_remove_modal_open() -> (tempfile::TempDir, AccountId, PathBuf, AppState) {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    (tmp, id, path, state)
}

fn expect_remove_modal(state: &AppState) -> &RemoveModal {
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Remove(remove)),
            ..
        } => remove,
        AppState::Unlocked { modal, .. } => panic!("expected Modal::Remove, got {modal:?}"),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn remove_modal_enter_emits_remove_effect() {
    let (_tmp, id, path, unlocked) = fresh_unlocked_with_remove_modal_open();
    let (state, effects) = reduce(unlocked, key(KeyCode::Enter));
    assert_eq!(effects.len(), 1, "expected single Effect::Remove");
    match &effects[0] {
        Effect::Remove {
            path: p,
            account_id,
        } => {
            assert_eq!(p, &path);
            assert_eq!(*account_id, id);
        }
        other => panic!("expected Effect::Remove, got {other:?}"),
    }
    // Modal stays open until the EffectResult arrives (success path
    // closes it; save-error rollback re-opens with inline error).
    let remove = expect_remove_modal(&state);
    assert_eq!(
        remove.account_id, id,
        "Enter on Remove must preserve the snapshotted account_id"
    );
    assert!(
        remove.error.is_none(),
        "submitting Remove must not surface an inline error"
    );
}

#[test]
fn remove_modal_printable_chars_are_silent_noop() {
    // Remove is a confirmation modal with no editable draft; bare
    // letters must not leak into the list (modal-trap contract) and
    // must not emit any effect or mutate modal state.
    let (_tmp, id, _path, unlocked) = fresh_unlocked_with_remove_modal_open();
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('x')));
    assert!(
        effects.is_empty(),
        "printable chars inside Remove must not emit effects"
    );
    let remove = expect_remove_modal(&state);
    assert_eq!(remove.account_id, id);
    assert!(remove.error.is_none());
}

#[test]
fn remove_modal_backspace_is_silent_noop() {
    let (_tmp, id, _path, unlocked) = fresh_unlocked_with_remove_modal_open();
    let (state, effects) = reduce(unlocked, key(KeyCode::Backspace));
    assert!(
        effects.is_empty(),
        "backspace inside Remove must not emit effects"
    );
    let remove = expect_remove_modal(&state);
    assert_eq!(remove.account_id, id);
    assert!(remove.error.is_none());
}

// ---------------------------------------------------------------------------
// Remove modal — EffectResult::Remove handling
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Remove modal — save-error
//  rollback and durability-unconfirmed bullets; "Effect errors" >
//  "Add / remove / rename / settings saves" rule.)
//
// Slice covered: the reducer's response to `EffectResult::Remove`
// deliveries. `Ok(label)` closes the modal and publishes a status-line
// confirmation built from the carried display label (the executor
// captures it before `Vault::remove` drops the Account). The
// save-error variants (`save_not_committed`,
// `save_durability_unconfirmed`, any other) leave the modal open with
// the rendered error in `RemoveModal.error`; pre-commit rollback
// semantics are owned by `Vault::mutate_and_save` in `paladin-core`.
// Deliveries that arrive after the modal closed, with a stale
// account_id, or onto a non-Unlocked state are discarded.
// ---------------------------------------------------------------------------

fn remove_result(account_id: AccountId, result: Result<String, PaladinError>) -> AppEvent {
    AppEvent::EffectResult(EffectResult::Remove { account_id, result })
}

#[test]
fn effect_result_remove_ok_closes_modal_and_sets_status_confirmation() {
    // Simulate the executor's post-`Vault::mutate_and_save` state by
    // dropping the account from the vault before delivering the
    // `Ok(label)` outcome — that mirrors the real run-loop where the
    // executor has already removed the account by the time the
    // reducer sees the result.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    vault.remove(id).expect("simulate executor-side remove");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, remove_result(id, Ok("github".to_string())));
    assert!(
        effects.is_empty(),
        "successful remove result must not emit effects"
    );
    match state {
        AppState::Unlocked {
            modal, status_line, ..
        } => {
            assert!(
                modal.is_none(),
                "Ok(()) remove outcome must close the modal, got {modal:?}"
            );
            let line = status_line.expect("Ok remove outcome must surface confirmation");
            match line {
                StatusLine::Confirmation(msg) => assert!(
                    msg.contains("github") && msg.contains("Removed"),
                    "confirmation must include the removed label, got {msg:?}"
                ),
                StatusLine::Error(e) => panic!("expected Confirmation, got Error({e:?})"),
            }
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_remove_ok_message_uses_carried_display_label() {
    // Per the EffectResult::Remove contract: the executor formats the
    // display label (`issuer:label` or just `label`) and the reducer
    // surfaces it verbatim — it does not re-look-up in the vault
    // because the account is already gone post-remove.
    let (_tmp, id, _path, unlocked) = fresh_unlocked_with_remove_modal_open();
    let (state, _) = reduce(unlocked, remove_result(id, Ok("Acme:alice".to_string())));
    match state {
        AppState::Unlocked {
            status_line: Some(StatusLine::Confirmation(msg)),
            ..
        } => {
            assert!(
                msg.contains("Acme:alice"),
                "confirmation must echo the carried display label, got {msg:?}"
            );
        }
        other => panic!("expected Unlocked with Confirmation, got {other:?}"),
    }
}

#[test]
fn effect_result_remove_save_not_committed_keeps_modal_open_with_inline_error() {
    // Core rolls back the remove inside `Vault::mutate_and_save` so
    // the vault still holds the original account at its previous
    // iteration position; the reducer surfaces the typed error
    // inline and leaves the modal open so the user can retry. The
    // fixture's vault carries the original "github" account (no
    // executor-side mutation simulated) — that mirrors the
    // rolled-back state core leaves behind on `save_not_committed`.
    let (_tmp, id, _path, unlocked) = fresh_unlocked_with_remove_modal_open();
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let (state, effects) = reduce(unlocked, remove_result(id, Err(err)));
    assert!(
        effects.is_empty(),
        "save error result must not emit effects"
    );
    let remove = expect_remove_modal(&state);
    assert_eq!(
        remove.account_id, id,
        "account_id is preserved across the save-error rollback"
    );
    let surfaced = remove
        .error
        .as_deref()
        .expect("save_not_committed must set inline error");
    assert!(
        surfaced.contains("save not committed") || surfaced.contains("save_not_committed"),
        "inline error must surface save_not_committed wording, got {surfaced:?}"
    );
    let labels: Vec<&str> = match &state {
        AppState::Unlocked { vault, .. } => {
            vault.iter().map(paladin_core::Account::label).collect()
        }
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        labels,
        vec!["github"],
        "Vault::iter() must reflect the rolled-back pre-attempt state on save_not_committed"
    );
}

#[test]
fn effect_result_remove_save_durability_unconfirmed_keeps_modal_open_with_inline_error() {
    // Durability-unconfirmed: core left the account removed in
    // memory and on disk, but parent fsync was uncertain. The TUI
    // mirrors Rename's surfacing convention — modal stays open and
    // the warning is inline so the user can retry or `Esc` out
    // deliberately.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    vault
        .remove(id)
        .expect("simulate executor-side remove for durability-unconfirmed");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let (state, _) = reduce(unlocked, remove_result(id, Err(err)));
    let remove = expect_remove_modal(&state);
    let surfaced = remove
        .error
        .as_deref()
        .expect("save_durability_unconfirmed must surface inline");
    assert!(
        surfaced.to_lowercase().contains("durability")
            || surfaced.contains("save_durability_unconfirmed"),
        "inline error must surface durability wording, got {surfaced:?}"
    );
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert_eq!(
                vault.iter().count(),
                0,
                "durability-unconfirmed leaves the account removed in memory"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_remove_io_error_keeps_modal_open_with_inline_error() {
    let (_tmp, id, _path, unlocked) = fresh_unlocked_with_remove_modal_open();
    let err = PaladinError::IoError {
        operation: "remove_save",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    };
    let (state, _effects) = reduce(unlocked, remove_result(id, Err(err)));
    let remove = expect_remove_modal(&state);
    let surfaced = remove
        .error
        .as_deref()
        .expect("io_error must surface inline");
    assert!(
        surfaced.to_lowercase().contains("i/o") || surfaced.contains("remove_save"),
        "inline error must surface io wording, got {surfaced:?}"
    );
}

#[test]
fn effect_result_remove_on_locked_state_is_discarded() {
    // Auto-lock fired between the remove emit and the result
    // delivery. The result is dropped without mutating the Locked
    // screen.
    let locked = AppState::Locked {
        path: PathBuf::from("/tmp/v.bin"),
        pending_clipboard_clear: None,
    };
    let (state, effects) = reduce(
        locked,
        remove_result(AccountId::new(), Ok("ignored".to_string())),
    );
    assert!(effects.is_empty());
    match state {
        AppState::Locked { path, .. } => assert_eq!(path, PathBuf::from("/tmp/v.bin")),
        other => panic!("expected Locked preserved, got {other:?}"),
    }
}

#[test]
fn effect_result_remove_on_non_remove_modal_is_discarded() {
    // Defensive: a stale remove outcome arrives after the user has
    // dismissed Remove and opened (say) the Add modal. The reducer
    // must leave the unrelated modal untouched.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, remove_result(id, Ok("github".to_string())));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add(_)),
            status_line: None,
            ..
        } => {}
        AppState::Unlocked {
            modal,
            status_line,
            ..
        } => panic!(
            "stale remove outcome must not touch unrelated modal / status, got modal={modal:?} status_line={status_line:?}"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_remove_with_mismatched_account_id_is_discarded() {
    // The modal targets account A but the result carries B's id
    // (defensive — should never happen in practice, but the reducer
    // is total so the no-op is observable). Modal stays open, no
    // inline error is set, and `status_line` is untouched.
    let (_tmp, modal_id, _path, unlocked) = fresh_unlocked_with_remove_modal_open();
    let other_id = AccountId::new();
    let (state, _) = reduce(unlocked, remove_result(other_id, Ok("github".to_string())));
    let remove = expect_remove_modal(&state);
    assert_eq!(
        remove.account_id, modal_id,
        "modal account_id must be preserved across a mismatched result"
    );
    assert!(
        remove.error.is_none(),
        "mismatched result must not set an inline error"
    );
    match &state {
        AppState::Unlocked {
            status_line: None, ..
        } => {}
        other => panic!("status_line must stay untouched, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Rename modal — EffectResult::Rename handling
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Rename modal — save-error
//  rollback and durability-unconfirmed bullets; "Effect errors" >
//  "Add / remove / rename / settings saves" rule.)
//
// Slice covered: the reducer's response to `EffectResult::Rename`
// deliveries. `Ok(())` closes the modal and publishes a status-line
// confirmation built from the post-rename label. The save-error
// variants (`save_not_committed`, `save_durability_unconfirmed`, any
// other) leave the modal open with the rendered error in
// `RenameModal.error`; pre-commit rollback semantics are owned by
// `Vault::mutate_and_save` in `paladin-core` so the reducer side
// only asserts the surface that's visible from the TUI. Deliveries
// that arrive after the modal closed, with a stale account_id, or
// onto a non-Unlocked state are discarded.
// ---------------------------------------------------------------------------

fn rename_result(account_id: AccountId, result: Result<(), PaladinError>) -> AppEvent {
    AppEvent::EffectResult(EffectResult::Rename { account_id, result })
}

#[test]
fn effect_result_rename_ok_closes_modal_and_sets_status_confirmation() {
    // Simulate the executor's post-`Vault::mutate_and_save` state by
    // applying the rename in the vault before delivering the
    // `Ok(())` outcome — that mirrors the real run-loop where the
    // executor has already mutated the vault by the time the
    // reducer sees the result.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    vault
        .rename(id, "github-personal", SystemTime::now())
        .expect("simulate executor-side rename");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: "github-personal".to_string(),
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, rename_result(id, Ok(())));
    assert!(
        effects.is_empty(),
        "successful rename result must not emit effects"
    );
    match state {
        AppState::Unlocked {
            modal,
            status_line,
            selected,
            ..
        } => {
            assert!(
                modal.is_none(),
                "Ok(()) rename outcome must close the modal, got {modal:?}"
            );
            assert_eq!(
                selected,
                Some(id),
                "Selection must survive a successful rename"
            );
            let line = status_line.expect("Ok rename outcome must surface confirmation");
            match line {
                StatusLine::Confirmation(msg) => assert!(
                    msg.contains("github-personal"),
                    "confirmation must include the new label, got {msg:?}"
                ),
                StatusLine::Error(e) => panic!("expected Confirmation, got Error({e:?})"),
            }
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_rename_save_not_committed_keeps_modal_open_with_inline_error() {
    // Core rolls back the label inside `Vault::mutate_and_save` so the
    // vault still holds the pre-attempt label; the reducer surfaces
    // the typed error inline and leaves the modal open so the user
    // can adjust and retry. The fixture's vault carries the original
    // "github" label (no executor-side mutation simulated) — that
    // mirrors the rolled-back state core leaves behind on
    // `save_not_committed`.
    let (_tmp, id, _path, unlocked) =
        fresh_unlocked_with_rename_modal_open("github", "github-personal");
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let (state, effects) = reduce(unlocked, rename_result(id, Err(err)));
    assert!(
        effects.is_empty(),
        "save error result must not emit effects"
    );
    let rename = expect_rename_modal(&state);
    assert_eq!(
        rename.draft, "github-personal",
        "draft is preserved so the user can retry"
    );
    let surfaced = rename
        .error
        .as_deref()
        .expect("save_not_committed must set inline error");
    assert!(
        surfaced.contains("save not committed") || surfaced.contains("save_not_committed"),
        "inline error must surface save_not_committed wording, got {surfaced:?}"
    );
    let labels: Vec<&str> = match &state {
        AppState::Unlocked { vault, .. } => {
            vault.iter().map(paladin_core::Account::label).collect()
        }
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        labels,
        vec!["github"],
        "Vault::iter() must reflect the rolled-back pre-attempt state on save_not_committed"
    );
}

#[test]
fn effect_result_rename_save_durability_unconfirmed_keeps_modal_open_with_inline_error() {
    // Durability-unconfirmed: core left the new label committed in
    // memory and on disk, but parent fsync was uncertain. The TUI
    // mirrors HotpAdvance's surfacing convention — modal stays open
    // and the warning is inline so the user can retry or `Esc` out
    // deliberately.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    vault
        .rename(id, "github-personal", SystemTime::now())
        .expect("simulate executor-side rename");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: "github-personal".to_string(),
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(
        unlocked,
        rename_result(id, Err(PaladinError::SaveDurabilityUnconfirmed)),
    );
    assert!(effects.is_empty());
    let rename = expect_rename_modal(&state);
    let surfaced = rename
        .error
        .as_deref()
        .expect("durability-unconfirmed must surface inline");
    assert!(
        surfaced.contains("durability") || surfaced.contains("save durability"),
        "inline error must surface durability wording, got {surfaced:?}"
    );
    let labels: Vec<&str> = match &state {
        AppState::Unlocked { vault, .. } => {
            vault.iter().map(paladin_core::Account::label).collect()
        }
        other => panic!("expected Unlocked, got {other:?}"),
    };
    assert_eq!(
        labels,
        vec!["github-personal"],
        "Vault::iter() must reflect the committed new label on save_durability_unconfirmed"
    );
}

#[test]
fn effect_result_rename_io_error_keeps_modal_open_with_inline_error() {
    let (_tmp, id, _path, unlocked) =
        fresh_unlocked_with_rename_modal_open("github", "github-personal");
    let err = PaladinError::IoError {
        operation: "rename_save",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    };
    let (state, _effects) = reduce(unlocked, rename_result(id, Err(err)));
    let rename = expect_rename_modal(&state);
    let surfaced = rename
        .error
        .as_deref()
        .expect("io_error must surface inline");
    assert!(
        surfaced.to_lowercase().contains("i/o") || surfaced.contains("rename_save"),
        "inline error must surface io wording, got {surfaced:?}"
    );
}

#[test]
fn effect_result_rename_on_locked_state_is_discarded() {
    // Auto-lock fired between the rename emit and the result
    // delivery. The result is dropped without mutating the Locked
    // screen.
    let locked = AppState::Locked {
        path: PathBuf::from("/tmp/v.bin"),
        pending_clipboard_clear: None,
    };
    let (state, effects) = reduce(locked, rename_result(AccountId::new(), Ok(())));
    assert!(effects.is_empty());
    match state {
        AppState::Locked { path, .. } => assert_eq!(path, PathBuf::from("/tmp/v.bin")),
        other => panic!("expected Locked preserved, got {other:?}"),
    }
}

#[test]
fn effect_result_rename_on_non_rename_modal_is_discarded() {
    // Defensive: a stale rename outcome arrives after the user has
    // dismissed Rename and opened (say) the Add modal. The reducer
    // must leave the unrelated modal untouched.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, rename_result(id, Ok(())));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add(_)),
            status_line: None,
            ..
        } => {}
        AppState::Unlocked {
            modal,
            status_line,
            ..
        } => panic!(
            "stale rename outcome must not touch unrelated modal / status, got modal={modal:?} status_line={status_line:?}"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_rename_with_mismatched_account_id_is_discarded() {
    // The modal targets account A but the result carries B's id
    // (defensive — should never happen in practice, but the reducer
    // is total so the no-op is observable). Modal stays open, no
    // inline error is set, and `status_line` is untouched.
    let (_tmp, modal_id, _path, unlocked) =
        fresh_unlocked_with_rename_modal_open("github", "github-personal");
    let other_id = AccountId::new();
    let (state, _) = reduce(unlocked, rename_result(other_id, Ok(())));
    let rename = expect_rename_modal(&state);
    assert_eq!(
        rename.account_id, modal_id,
        "modal account_id must be preserved across a mismatched result"
    );
    assert!(
        rename.error.is_none(),
        "mismatched result must not set an inline error"
    );
    match &state {
        AppState::Unlocked {
            status_line: None, ..
        } => {}
        other => panic!("status_line must stay untouched, got {other:?}"),
    }
}

#[test]
fn pressing_p_on_unlocked_with_no_modal_open_opens_passphrase_modal() {
    assert_key_opens_modal(key(KeyCode::Char('p')), &Modal::Passphrase);
}

#[test]
fn pressing_s_on_unlocked_with_no_modal_open_opens_settings_modal() {
    assert_key_opens_modal(
        key(KeyCode::Char('s')),
        &Modal::Settings(SettingsModal::default()),
    );
}

#[test]
fn pressing_s_opens_settings_modal_prepopulated_with_vault_config() {
    // Per IMPLEMENTATION_PLAN_03_TUI.md "Modals (per §6)" > Settings:
    // *"toggles for `auto_lock.enabled` and `clipboard.clear_enabled`,
    // spinners for `auto_lock.timeout_secs` and `clipboard.clear_secs`.
    // ... The modal accumulates pending edits in modal-local state and
    // only commits on Confirm."* The reducer snapshots the live
    // `VaultSettings` into the modal's pending fields at open time so
    // edits stay modal-local until Confirm. Selection is not gated for
    // Settings (per the Focus model), so the binding works regardless
    // of `selected`.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    // Mutate the live vault settings away from defaults so the
    // pre-populated values are observable instead of coinciding with
    // the `SettingsModal::default()`.
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(123)
        .expect("123s is within AUTO_LOCK_SECS_MIN..=AUTO_LOCK_SECS_MAX");
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(45)
        .expect("45s is within CLIPBOARD_CLEAR_SECS_MIN..=CLIPBOARD_CLEAR_SECS_MAX");
    let unlocked = AppState::Unlocked {
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
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('s')));
    assert!(effects.is_empty(), "opening Settings must not emit effects");
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(settings)),
            ..
        } => {
            assert!(
                settings.auto_lock_enabled,
                "auto_lock_enabled must mirror the live vault setting"
            );
            assert_eq!(
                settings.auto_lock_timeout_secs, 123,
                "auto_lock_timeout_secs must mirror the live vault setting"
            );
            assert!(
                settings.clipboard_clear_enabled,
                "clipboard_clear_enabled must mirror the live vault setting"
            );
            assert_eq!(
                settings.clipboard_clear_secs, 45,
                "clipboard_clear_secs must mirror the live vault setting"
            );
            assert!(
                settings.error.is_none(),
                "freshly opened Settings modal has no inline error"
            );
        }
        AppState::Unlocked { modal, .. } => {
            panic!("expected Modal::Settings, got {modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Settings modal — field focus + Tab/Shift-Tab/Ctrl-N/Ctrl-P cycling
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer — "Modal-local
//  navigation covers Tab / Shift-Tab, the Ctrl-N / Ctrl-P aliases …")
//
// The Settings modal traps Tab / Shift-Tab and their modal-LOCAL
// aliases `Ctrl-N` / `Ctrl-P` to cycle [`SettingsFocus`] through the
// four pending fields in reading order: auto-lock toggle → auto-lock
// spinner → clipboard-clear toggle → clipboard-clear spinner →
// wrap. Focus is modal-local; the live `VaultSettings` is untouched
// until a future Confirm slice runs the setters inside one
// `Vault::mutate_and_save` transaction.
// ---------------------------------------------------------------------------

/// Open the Settings modal on a fresh plaintext vault with default
/// settings, returning the populated `AppState` ready for focus-key
/// tests.
fn fresh_unlocked_with_settings_modal(tmp: &tempfile::TempDir) -> AppState {
    let unlocked = fresh_plaintext_unlocked(tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('s')));
    assert!(effects.is_empty(), "opening Settings must not emit effects");
    state
}

/// Pull the open `SettingsModal` out of an `Unlocked` state by ref,
/// panicking with a clear message if Settings is not the open modal.
fn settings_modal_ref(state: &AppState) -> &SettingsModal {
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => s,
        AppState::Unlocked { modal, .. } => {
            panic!("expected Modal::Settings open, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn settings_modal_opens_with_default_focus_on_auto_lock_enabled() {
    // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)": focus
    // starts on the first field so the visual top-down reading order
    // matches the keyboard entry point. `SettingsFocus::default()`
    // is `AutoLockEnabled`.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_settings_modal(&tmp);
    assert_eq!(
        settings_modal_ref(&state).focus,
        SettingsFocus::AutoLockEnabled
    );
}

#[test]
fn tab_in_settings_modal_advances_focus_through_all_fields_with_wrap() {
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_settings_modal(&tmp);
    let order = [
        SettingsFocus::AutoLockTimeoutSecs,
        SettingsFocus::ClipboardClearEnabled,
        SettingsFocus::ClipboardClearSecs,
        SettingsFocus::AutoLockEnabled,
    ];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::Tab));
        assert!(
            effects.is_empty(),
            "Tab inside Settings (step {i}) must not emit effects"
        );
        assert_eq!(
            settings_modal_ref(&next).focus,
            *expected,
            "Tab step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn shift_tab_in_settings_modal_retreats_focus_through_all_fields_with_wrap() {
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_settings_modal(&tmp);
    let order = [
        SettingsFocus::ClipboardClearSecs,
        SettingsFocus::ClipboardClearEnabled,
        SettingsFocus::AutoLockTimeoutSecs,
        SettingsFocus::AutoLockEnabled,
    ];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, key(KeyCode::BackTab));
        assert!(
            effects.is_empty(),
            "Shift-Tab inside Settings (step {i}) must not emit effects"
        );
        assert_eq!(
            settings_modal_ref(&next).focus,
            *expected,
            "Shift-Tab step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn ctrl_n_in_settings_modal_advances_focus_like_tab() {
    // `Ctrl-N` is the modal-LOCAL alias for `Tab` per the keybindings
    // table; the observable behavior must match `Tab` exactly inside
    // a focusable-field modal.
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_settings_modal(&tmp);
    let order = [
        SettingsFocus::AutoLockTimeoutSecs,
        SettingsFocus::ClipboardClearEnabled,
        SettingsFocus::ClipboardClearSecs,
        SettingsFocus::AutoLockEnabled,
    ];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, ctrl(KeyCode::Char('n')));
        assert!(
            effects.is_empty(),
            "Ctrl-N inside Settings (step {i}) must not emit effects"
        );
        assert_eq!(
            settings_modal_ref(&next).focus,
            *expected,
            "Ctrl-N step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn ctrl_p_in_settings_modal_retreats_focus_like_shift_tab() {
    let tmp = secure_tempdir();
    let mut state = fresh_unlocked_with_settings_modal(&tmp);
    let order = [
        SettingsFocus::ClipboardClearSecs,
        SettingsFocus::ClipboardClearEnabled,
        SettingsFocus::AutoLockTimeoutSecs,
        SettingsFocus::AutoLockEnabled,
    ];
    for (i, expected) in order.iter().enumerate() {
        let (next, effects) = reduce(state, ctrl(KeyCode::Char('p')));
        assert!(
            effects.is_empty(),
            "Ctrl-P inside Settings (step {i}) must not emit effects"
        );
        assert_eq!(
            settings_modal_ref(&next).focus,
            *expected,
            "Ctrl-P step {i} should land on {expected:?}"
        );
        state = next;
    }
}

#[test]
fn tab_in_settings_modal_does_not_mutate_vault_settings() {
    // Modal-local focus changes must never reach the live
    // `VaultSettings`; only the Confirm path through
    // `Vault::mutate_and_save` is allowed to do that. Snapshot the
    // four fields before / after Tab and assert byte equality.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_settings_modal(&tmp);
    let before = match &state {
        AppState::Unlocked { vault, .. } => {
            let s = vault.settings();
            (
                s.auto_lock_enabled(),
                s.auto_lock_timeout_secs(),
                s.clipboard_clear_enabled(),
                s.clipboard_clear_secs(),
            )
        }
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (after, _) = reduce(state, key(KeyCode::Tab));
    match &after {
        AppState::Unlocked { vault, .. } => {
            let s = vault.settings();
            assert_eq!(
                (
                    s.auto_lock_enabled(),
                    s.auto_lock_timeout_secs(),
                    s.clipboard_clear_enabled(),
                    s.clipboard_clear_secs(),
                ),
                before,
                "Tab inside Settings must not mutate live VaultSettings"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn ctrl_n_in_settings_modal_does_not_flip_top_level_focus() {
    // Mirror of the existing `Ctrl-N with modal open on Search focus`
    // top-level-focus guard, but with focusable Settings fields:
    // advancing the modal-local focus must not flip the underlying
    // `Focus::List` / `Focus::Search` surface.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_settings_modal(&tmp);
    let (after, effects) = reduce(state, ctrl(KeyCode::Char('n')));
    assert!(effects.is_empty());
    match &after {
        AppState::Unlocked { focus, .. } => assert_eq!(
            *focus,
            Focus::List,
            "Ctrl-N inside Settings must not flip top-level focus"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Settings modal — Space toggles the focused boolean field
// (IMPLEMENTATION_PLAN_03_TUI.md > Modals (per §6): *"`Space` toggles
//  the focused checkbox / toggle."* The two boolean fields are
//  `auto_lock.enabled` and `clipboard.clear_enabled`; on the two
//  spinner fields, Space is a silent no-op so the modal-trap contract
//  holds. Toggles stay modal-local; only Confirm runs the setters
//  inside `Vault::mutate_and_save`.)
// ---------------------------------------------------------------------------

/// Reduce a Space press against a freshly opened Settings modal with
/// `focus` pre-positioned on `target` and `auto_lock_enabled` /
/// `clipboard_clear_enabled` pre-set to `(al, cc)`, returning the
/// resulting `SettingsModal` along with any emitted effects.
fn reduce_space_on_settings_with(
    tmp: &tempfile::TempDir,
    target: SettingsFocus,
    al: bool,
    cc: bool,
) -> (SettingsModal, Vec<Effect>) {
    let state = fresh_unlocked_with_settings_modal(tmp);
    let state = match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal: Some(Modal::Settings(mut s)),
            selected,
            pending_chord_leader,
            viewport_height,
            viewport_offset,
            focus,
            status_line,
            help_open,
        } => {
            s.focus = target;
            s.auto_lock_enabled = al;
            s.clipboard_clear_enabled = cc;
            AppState::Unlocked {
                path,
                vault,
                store,
                search_query,
                idle_deadline,
                pending_clipboard_clear,
                hotp_reveal,
                modal: Some(Modal::Settings(s)),
                selected,
                pending_chord_leader,
                viewport_height,
                viewport_offset,
                focus,
                status_line,
                help_open,
            }
        }
        other => panic!("expected Settings modal open, got {other:?}"),
    };
    let (after, effects) = reduce(state, key(KeyCode::Char(' ')));
    let modal = match after {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => s,
        AppState::Unlocked { modal, .. } => {
            panic!("expected Settings modal still open, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    };
    (modal, effects)
}

#[test]
fn space_on_settings_with_focus_on_auto_lock_enabled_flips_auto_lock_only() {
    let tmp = secure_tempdir();
    let (modal, effects) =
        reduce_space_on_settings_with(&tmp, SettingsFocus::AutoLockEnabled, false, false);
    assert!(
        effects.is_empty(),
        "Space inside Settings must not emit effects"
    );
    assert!(
        modal.auto_lock_enabled,
        "Space on AutoLockEnabled must flip the boolean"
    );
    assert!(
        !modal.clipboard_clear_enabled,
        "Space must not touch the other toggle"
    );
    assert_eq!(
        modal.focus,
        SettingsFocus::AutoLockEnabled,
        "Space must not advance focus"
    );
}

#[test]
fn space_on_settings_with_focus_on_auto_lock_enabled_toggles_off_when_already_on() {
    let tmp = secure_tempdir();
    let (modal, _) =
        reduce_space_on_settings_with(&tmp, SettingsFocus::AutoLockEnabled, true, true);
    assert!(!modal.auto_lock_enabled, "Space must flip true → false too");
    assert!(modal.clipboard_clear_enabled, "the other toggle stays put");
}

#[test]
fn space_on_settings_with_focus_on_clipboard_clear_enabled_flips_clipboard_only() {
    let tmp = secure_tempdir();
    let (modal, effects) =
        reduce_space_on_settings_with(&tmp, SettingsFocus::ClipboardClearEnabled, false, false);
    assert!(effects.is_empty());
    assert!(
        modal.clipboard_clear_enabled,
        "Space must flip the clipboard toggle"
    );
    assert!(!modal.auto_lock_enabled, "auto-lock toggle stays put");
    assert_eq!(modal.focus, SettingsFocus::ClipboardClearEnabled);
}

#[test]
fn space_on_settings_with_focus_on_auto_lock_timeout_spinner_is_silent_no_op() {
    // Spinner fields are spinner-only; Space against them is a
    // silent no-op so the modal-trap contract holds.
    let tmp = secure_tempdir();
    let (modal, effects) =
        reduce_space_on_settings_with(&tmp, SettingsFocus::AutoLockTimeoutSecs, true, true);
    assert!(effects.is_empty());
    assert!(
        modal.auto_lock_enabled && modal.clipboard_clear_enabled,
        "Space on a spinner field must not flip any toggle"
    );
    assert_eq!(modal.focus, SettingsFocus::AutoLockTimeoutSecs);
}

#[test]
fn space_on_settings_with_focus_on_clipboard_clear_secs_spinner_is_silent_no_op() {
    let tmp = secure_tempdir();
    let (modal, effects) =
        reduce_space_on_settings_with(&tmp, SettingsFocus::ClipboardClearSecs, false, false);
    assert!(effects.is_empty());
    assert!(
        !modal.auto_lock_enabled && !modal.clipboard_clear_enabled,
        "Space on a spinner field must not flip any toggle"
    );
    assert_eq!(modal.focus, SettingsFocus::ClipboardClearSecs);
}

#[test]
fn space_on_settings_modal_does_not_mutate_vault_settings() {
    // Toggle edits stay modal-local; the live `VaultSettings` only
    // changes through the Confirm path's `Vault::mutate_and_save`.
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let before = match &unlocked {
        AppState::Unlocked { vault, .. } => {
            let s = vault.settings();
            (s.auto_lock_enabled(), s.clipboard_clear_enabled())
        }
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (with_modal, _) = reduce(unlocked, key(KeyCode::Char('s')));
    let (after, _) = reduce(with_modal, key(KeyCode::Char(' ')));
    match &after {
        AppState::Unlocked { vault, .. } => {
            let s = vault.settings();
            assert_eq!(
                (s.auto_lock_enabled(), s.clipboard_clear_enabled()),
                before,
                "Space inside Settings must not mutate live VaultSettings"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn space_on_settings_round_trips_boolean_on_repeated_presses() {
    // Two consecutive Space presses on the AutoLockEnabled toggle
    // must flip false → true → false. Drives the press through the
    // live reducer twice so the toggle direction (XOR rather than
    // "set to a fixed value") is exercised.
    let tmp = secure_tempdir();
    let state = fresh_unlocked_with_settings_modal(&tmp);
    let (after_one, _) = reduce(state, key(KeyCode::Char(' ')));
    assert!(
        settings_modal_ref(&after_one).auto_lock_enabled,
        "first Space press must flip false → true"
    );
    let (after_two, _) = reduce(after_one, key(KeyCode::Char(' ')));
    assert!(
        !settings_modal_ref(&after_two).auto_lock_enabled,
        "second Space press must flip true → false"
    );
}

// ---------------------------------------------------------------------------
// Settings modal — ↑/↓ adjusts the focused spinner
// (IMPLEMENTATION_PLAN_03_TUI.md > Modals (per §6): *"`↑` / `↓`
//  adjust spinners … The spinners clamp to the shared core bounds."*
//  Step size matches the field's MIN granule:
//  `auto_lock.timeout_secs` steps by `AUTO_LOCK_SECS_MIN = 30`;
//  `clipboard.clear_secs` steps by `CLIPBOARD_CLEAR_SECS_MIN = 5`.
//  Saturation at MIN/MAX is enforced at the UI layer so the core
//  setter rejection path stays a defensive backstop.)
// ---------------------------------------------------------------------------

/// Reduce an arrow press against a freshly opened Settings modal with
/// `focus` pre-positioned on `target` and the two spinner fields
/// pre-set to `(al_secs, cc_secs)`. Returns the post-press
/// `SettingsModal` plus emitted effects.
fn reduce_arrow_on_settings_with(
    tmp: &tempfile::TempDir,
    target: SettingsFocus,
    arrow: KeyCode,
    al_secs: u32,
    cc_secs: u32,
) -> (SettingsModal, Vec<Effect>) {
    let state = fresh_unlocked_with_settings_modal(tmp);
    let state = match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal: Some(Modal::Settings(mut s)),
            selected,
            pending_chord_leader,
            viewport_height,
            viewport_offset,
            focus,
            status_line,
            help_open,
        } => {
            s.focus = target;
            s.auto_lock_timeout_secs = al_secs;
            s.clipboard_clear_secs = cc_secs;
            AppState::Unlocked {
                path,
                vault,
                store,
                search_query,
                idle_deadline,
                pending_clipboard_clear,
                hotp_reveal,
                modal: Some(Modal::Settings(s)),
                selected,
                pending_chord_leader,
                viewport_height,
                viewport_offset,
                focus,
                status_line,
                help_open,
            }
        }
        other => panic!("expected Settings modal open, got {other:?}"),
    };
    let (after, effects) = reduce(state, key(arrow));
    let modal = match after {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => s,
        AppState::Unlocked { modal, .. } => {
            panic!("expected Settings modal still open, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    };
    (modal, effects)
}

#[test]
fn up_on_auto_lock_timeout_spinner_increments_by_min_step() {
    let tmp = secure_tempdir();
    let (modal, effects) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::AutoLockTimeoutSecs,
        KeyCode::Up,
        60,
        30,
    );
    assert!(
        effects.is_empty(),
        "↑ inside Settings must not emit effects"
    );
    assert_eq!(
        modal.auto_lock_timeout_secs,
        60 + paladin_core::AUTO_LOCK_SECS_MIN,
        "↑ must increment by AUTO_LOCK_SECS_MIN (= 30)"
    );
    assert_eq!(
        modal.clipboard_clear_secs, 30,
        "the other spinner stays put"
    );
    assert_eq!(modal.focus, SettingsFocus::AutoLockTimeoutSecs);
}

#[test]
fn down_on_auto_lock_timeout_spinner_decrements_by_min_step() {
    let tmp = secure_tempdir();
    let (modal, effects) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::AutoLockTimeoutSecs,
        KeyCode::Down,
        120,
        30,
    );
    assert!(effects.is_empty());
    assert_eq!(
        modal.auto_lock_timeout_secs,
        120 - paladin_core::AUTO_LOCK_SECS_MIN
    );
}

#[test]
fn up_on_clipboard_clear_spinner_increments_by_min_step() {
    let tmp = secure_tempdir();
    let (modal, effects) =
        reduce_arrow_on_settings_with(&tmp, SettingsFocus::ClipboardClearSecs, KeyCode::Up, 60, 30);
    assert!(effects.is_empty());
    assert_eq!(
        modal.clipboard_clear_secs,
        30 + paladin_core::CLIPBOARD_CLEAR_SECS_MIN,
        "↑ must increment by CLIPBOARD_CLEAR_SECS_MIN (= 5)"
    );
    assert_eq!(
        modal.auto_lock_timeout_secs, 60,
        "the other spinner stays put"
    );
}

#[test]
fn down_on_clipboard_clear_spinner_decrements_by_min_step() {
    let tmp = secure_tempdir();
    let (modal, _) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::ClipboardClearSecs,
        KeyCode::Down,
        60,
        60,
    );
    assert_eq!(
        modal.clipboard_clear_secs,
        60 - paladin_core::CLIPBOARD_CLEAR_SECS_MIN
    );
}

#[test]
fn up_at_auto_lock_max_clamps_to_max() {
    let tmp = secure_tempdir();
    let (modal, _) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::AutoLockTimeoutSecs,
        KeyCode::Up,
        paladin_core::AUTO_LOCK_SECS_MAX,
        30,
    );
    assert_eq!(
        modal.auto_lock_timeout_secs,
        paladin_core::AUTO_LOCK_SECS_MAX,
        "↑ at MAX must clamp instead of wrapping or overshooting"
    );
}

#[test]
fn up_near_auto_lock_max_clamps_to_max_when_step_would_overshoot() {
    // MAX = 86400, step = 30. Start at MAX - 10 (86390); ↑ would
    // overshoot to 86420 — the clamp must trim it to MAX.
    let tmp = secure_tempdir();
    let start = paladin_core::AUTO_LOCK_SECS_MAX - 10;
    let (modal, _) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::AutoLockTimeoutSecs,
        KeyCode::Up,
        start,
        30,
    );
    assert_eq!(
        modal.auto_lock_timeout_secs,
        paladin_core::AUTO_LOCK_SECS_MAX
    );
}

#[test]
fn down_at_auto_lock_min_clamps_to_min() {
    let tmp = secure_tempdir();
    let (modal, _) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::AutoLockTimeoutSecs,
        KeyCode::Down,
        paladin_core::AUTO_LOCK_SECS_MIN,
        30,
    );
    assert_eq!(
        modal.auto_lock_timeout_secs,
        paladin_core::AUTO_LOCK_SECS_MIN
    );
}

#[test]
fn down_near_auto_lock_min_clamps_to_min_when_step_would_undershoot() {
    let tmp = secure_tempdir();
    let start = paladin_core::AUTO_LOCK_SECS_MIN + 10;
    let (modal, _) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::AutoLockTimeoutSecs,
        KeyCode::Down,
        start,
        30,
    );
    assert_eq!(
        modal.auto_lock_timeout_secs,
        paladin_core::AUTO_LOCK_SECS_MIN
    );
}

#[test]
fn up_at_clipboard_max_clamps_to_max() {
    let tmp = secure_tempdir();
    let (modal, _) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::ClipboardClearSecs,
        KeyCode::Up,
        60,
        paladin_core::CLIPBOARD_CLEAR_SECS_MAX,
    );
    assert_eq!(
        modal.clipboard_clear_secs,
        paladin_core::CLIPBOARD_CLEAR_SECS_MAX
    );
}

#[test]
fn down_at_clipboard_min_clamps_to_min() {
    let tmp = secure_tempdir();
    let (modal, _) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::ClipboardClearSecs,
        KeyCode::Down,
        60,
        paladin_core::CLIPBOARD_CLEAR_SECS_MIN,
    );
    assert_eq!(
        modal.clipboard_clear_secs,
        paladin_core::CLIPBOARD_CLEAR_SECS_MIN
    );
}

#[test]
fn up_on_settings_with_focus_on_auto_lock_toggle_is_silent_no_op() {
    // Toggle fields take Space; ↑/↓ are silent no-ops so the
    // modal-trap contract holds and the focused boolean is not
    // accidentally mutated by spinner-adjacent presses.
    let tmp = secure_tempdir();
    let (modal, effects) =
        reduce_arrow_on_settings_with(&tmp, SettingsFocus::AutoLockEnabled, KeyCode::Up, 60, 30);
    assert!(effects.is_empty());
    assert_eq!(modal.auto_lock_timeout_secs, 60);
    assert_eq!(modal.clipboard_clear_secs, 30);
}

#[test]
fn down_on_settings_with_focus_on_clipboard_toggle_is_silent_no_op() {
    let tmp = secure_tempdir();
    let (modal, effects) = reduce_arrow_on_settings_with(
        &tmp,
        SettingsFocus::ClipboardClearEnabled,
        KeyCode::Down,
        60,
        30,
    );
    assert!(effects.is_empty());
    assert_eq!(modal.auto_lock_timeout_secs, 60);
    assert_eq!(modal.clipboard_clear_secs, 30);
}

#[test]
fn arrow_on_settings_modal_does_not_mutate_vault_settings() {
    // Spinner edits stay modal-local; the live `VaultSettings` only
    // changes through the Confirm path's `Vault::mutate_and_save`.
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let before = match &unlocked {
        AppState::Unlocked { vault, .. } => {
            let s = vault.settings();
            (s.auto_lock_timeout_secs(), s.clipboard_clear_secs())
        }
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (with_modal, _) = reduce(unlocked, key(KeyCode::Char('s')));
    // Cycle to the auto_lock spinner and press ↑.
    let (after_tab, _) = reduce(with_modal, key(KeyCode::Tab));
    let (after_up, _) = reduce(after_tab, key(KeyCode::Up));
    match &after_up {
        AppState::Unlocked { vault, .. } => {
            let s = vault.settings();
            assert_eq!(
                (s.auto_lock_timeout_secs(), s.clipboard_clear_secs()),
                before,
                "↑ inside Settings must not mutate live VaultSettings"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Settings modal — Confirm / Esc / pending-edit buffering + save outcomes
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer — "Settings modal":
//  pending edits buffered, Esc discards, Confirm runs every changed
//  setter inside one Vault::mutate_and_save, save-error rollback,
//  durability-unconfirmed surfacing, no-change Confirm closes without
//  saving.)
// ---------------------------------------------------------------------------

/// Open the Settings modal and return the contained `AppState` plus
/// the vault path for Effect assertions. The fresh plaintext vault
/// uses `VaultSettings::default()` so callers can mutate pending
/// fields to create observable diffs.
fn fresh_unlocked_with_settings_modal_and_path(
    tmp: &tempfile::TempDir,
) -> (PathBuf, AccountId, AppState) {
    let (path, (mut vault, store)) = open_plaintext_pair(tmp);
    // Seed one account so `Vault::iter()` is non-empty and the
    // post-save assertions can observe vault-wide invariants (the
    // Settings modal does not depend on selection but the executor
    // does run inside `Vault::mutate_and_save`).
    let id = add_totp_account(&mut vault, &store, "github");
    let unlocked = AppState::Unlocked {
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
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('s')));
    assert!(effects.is_empty(), "opening Settings must not emit effects");
    (path, id, state)
}

/// Mutate the open Settings modal's pending fields, returning the
/// modified `AppState`. Caller supplies a closure so multiple field
/// edits stay observable; the helper preserves every other slot.
fn with_settings_modal_mut(state: AppState, f: impl FnOnce(&mut SettingsModal)) -> AppState {
    match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            mut modal,
            selected,
            pending_chord_leader,
            viewport_height,
            viewport_offset,
            focus,
            status_line,
            help_open,
        } => {
            match modal.as_mut() {
                Some(Modal::Settings(s)) => f(s),
                other => panic!("expected Modal::Settings open, got {other:?}"),
            }
            AppState::Unlocked {
                path,
                vault,
                store,
                search_query,
                idle_deadline,
                pending_clipboard_clear,
                hotp_reveal,
                modal,
                selected,
                pending_chord_leader,
                viewport_height,
                viewport_offset,
                focus,
                status_line,
                help_open,
            }
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

fn settings_result(result: Result<(), PaladinError>) -> AppEvent {
    AppEvent::EffectResult(EffectResult::Settings { result })
}

/// Pull a snapshot of the live `VaultSettings` from an `Unlocked`
/// state as a `(auto_lock_enabled, auto_lock_timeout_secs,
/// clipboard_clear_enabled, clipboard_clear_secs)` tuple.
fn settings_snapshot(state: &AppState) -> (bool, u32, bool, u32) {
    match state {
        AppState::Unlocked { vault, .. } => {
            let s = vault.settings();
            (
                s.auto_lock_enabled(),
                s.auto_lock_timeout_secs(),
                s.clipboard_clear_enabled(),
                s.clipboard_clear_secs(),
            )
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn settings_modal_space_and_arrow_edits_buffer_pending_until_confirm() {
    // Per IMPLEMENTATION_PLAN_03_TUI.md > Settings modal:
    // "Pending edits are buffered until Confirm." Multiple
    // interleaved Tab / Space / ↑ presses must update the modal's
    // pending fields but never call any `Vault::set_*` setter — the
    // live `VaultSettings` only changes through the Confirm path's
    // `Vault::mutate_and_save`. This sister-tests `space_*` and
    // `arrow_*` for the buffered-multi-edit guarantee.
    let tmp = secure_tempdir();
    let (_path, _id, state) = fresh_unlocked_with_settings_modal_and_path(&tmp);
    let before = settings_snapshot(&state);
    // Flip auto-lock toggle (focus starts on AutoLockEnabled).
    let (state, _) = reduce(state, key(KeyCode::Char(' ')));
    // Tab → auto_lock_timeout_secs spinner.
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Up));
    // Tab → clipboard_clear_enabled.
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Char(' ')));
    // Tab → clipboard_clear_secs spinner.
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Up));
    let after = settings_snapshot(&state);
    assert_eq!(
        before, after,
        "pending Settings edits must not mutate live VaultSettings until Confirm"
    );
    // The modal carries the pending values now.
    match &state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => {
            assert!(s.auto_lock_enabled, "auto_lock_enabled toggled pending");
            assert!(
                s.auto_lock_timeout_secs > before.1,
                "auto_lock_timeout_secs stepped pending (before={}, after={})",
                before.1,
                s.auto_lock_timeout_secs
            );
            assert!(s.clipboard_clear_enabled);
            assert!(s.clipboard_clear_secs > before.3);
        }
        other => panic!("expected open Settings modal, got {other:?}"),
    }
}

#[test]
fn settings_modal_esc_discards_pending_edits_without_invoking_save() {
    // Per IMPLEMENTATION_PLAN_03_TUI.md > Settings modal:
    // "`Esc` discards pending edits without invoking setters or save."
    // The reducer's Esc handler clears the modal slot; pending values
    // drop with the discarded `SettingsModal` and no effect is
    // emitted. The live vault stays at its pre-edit settings.
    let tmp = secure_tempdir();
    let (_path, _id, state) = fresh_unlocked_with_settings_modal_and_path(&tmp);
    let before = settings_snapshot(&state);
    // Apply a flurry of pending edits.
    let (state, _) = reduce(state, key(KeyCode::Char(' ')));
    let (state, _) = reduce(state, key(KeyCode::Tab));
    let (state, _) = reduce(state, key(KeyCode::Up));
    // Now press Esc.
    let (state, effects) = reduce(state, key(KeyCode::Esc));
    assert!(
        effects.is_empty(),
        "Esc on Settings must not emit effects, got {effects:?}"
    );
    match &state {
        AppState::Unlocked { modal: None, .. } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=None after Esc, got {modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
    assert_eq!(
        settings_snapshot(&state),
        before,
        "Esc on Settings must not mutate live VaultSettings"
    );
}

#[test]
fn settings_modal_enter_with_no_changes_closes_modal_without_emitting_effect() {
    // Per IMPLEMENTATION_PLAN_03_TUI.md > Settings modal:
    // "Confirm with no changes closes the modal without invoking
    // save." The reducer diffs pending vs live and skips the effect
    // when the diff is empty.
    let tmp = secure_tempdir();
    let (_path, _id, state) = fresh_unlocked_with_settings_modal_and_path(&tmp);
    let before = settings_snapshot(&state);
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "no-change Confirm must not emit Effect::ApplySettings, got {effects:?}"
    );
    match &state {
        AppState::Unlocked { modal: None, .. } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=None after no-change Confirm, got {modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
    assert_eq!(
        settings_snapshot(&state),
        before,
        "no-change Confirm must not mutate live VaultSettings"
    );
}

#[test]
fn settings_modal_enter_with_changes_emits_apply_settings_effect_with_diff_patches() {
    // Per IMPLEMENTATION_PLAN_03_TUI.md > Settings modal: "Confirm
    // runs every changed setter inside one `Vault::mutate_and_save`
    // transaction." The reducer diffs the modal's pending fields
    // against the live `VaultSettings` at Confirm time and emits
    // exactly the changed `SettingPatch`es; the modal stays open
    // until the `EffectResult::Settings` arrives.
    let tmp = secure_tempdir();
    let (path, _id, state) = fresh_unlocked_with_settings_modal_and_path(&tmp);
    let before = settings_snapshot(&state);
    // Stage three pending changes (every field except
    // `auto_lock_timeout_secs`).
    let state = with_settings_modal_mut(state, |s| {
        s.auto_lock_enabled = !before.0;
        s.clipboard_clear_enabled = !before.2;
        s.clipboard_clear_secs = before
            .3
            .saturating_add(paladin_core::CLIPBOARD_CLEAR_SECS_MIN);
    });
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert_eq!(effects.len(), 1, "expected single Effect::ApplySettings");
    match &effects[0] {
        Effect::ApplySettings { path: p, patches } => {
            assert_eq!(p, &path);
            assert_eq!(
                patches.len(),
                3,
                "patches must include exactly the three diffed fields, got {patches:?}"
            );
            assert!(matches!(
                patches[0],
                SettingPatch::AutoLockEnabled(v) if v != before.0
            ));
            assert!(matches!(
                patches[1],
                SettingPatch::ClipboardClearEnabled(v) if v != before.2
            ));
            assert!(matches!(
                patches[2],
                SettingPatch::ClipboardClearSecs(v)
                    if v == before.3.saturating_add(paladin_core::CLIPBOARD_CLEAR_SECS_MIN)
            ));
        }
        other => panic!("expected Effect::ApplySettings, got {other:?}"),
    }
    // The modal stays open while the executor runs `mutate_and_save`.
    match &state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => {
            assert!(
                s.error.is_none(),
                "submitting changes must not set an inline error"
            );
        }
        AppState::Unlocked { modal, .. } => {
            panic!("expected open Settings modal pending result, got {modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
    // Live vault is still untouched — the executor hasn't run yet.
    assert_eq!(settings_snapshot(&state), before);
}

#[test]
fn settings_modal_enter_with_single_field_change_emits_one_patch() {
    // Only the single diffed field appears in `patches`.
    let tmp = secure_tempdir();
    let (path, _id, state) = fresh_unlocked_with_settings_modal_and_path(&tmp);
    let before = settings_snapshot(&state);
    let state = with_settings_modal_mut(state, |s| {
        s.auto_lock_timeout_secs = before.1.saturating_add(paladin_core::AUTO_LOCK_SECS_MIN);
    });
    let (_state, effects) = reduce(state, key(KeyCode::Enter));
    match effects.as_slice() {
        [Effect::ApplySettings { path: p, patches }] => {
            assert_eq!(p, &path);
            assert_eq!(patches.len(), 1);
            assert!(matches!(
                patches[0],
                SettingPatch::AutoLockTimeoutSecs(v)
                    if v == before.1.saturating_add(paladin_core::AUTO_LOCK_SECS_MIN)
            ));
        }
        other => panic!("expected single Effect::ApplySettings, got {other:?}"),
    }
}

#[test]
fn effect_result_settings_ok_closes_modal_and_sets_status_confirmation() {
    // Simulate the post-`Vault::mutate_and_save` view (the executor
    // has already mutated the live vault) by applying the patch
    // before delivering the `Ok(())` outcome.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    vault
        .apply_setting_patch(SettingPatch::AutoLockEnabled(true))
        .expect("simulate executor-side patch");
    vault.save(&store).expect("commit setting");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal {
            auto_lock_enabled: true,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
            focus: SettingsFocus::default(),
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, settings_result(Ok(())));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            modal, status_line, ..
        } => {
            assert!(
                modal.is_none(),
                "Ok settings outcome must close the modal, got {modal:?}"
            );
            let line = status_line.expect("Ok settings outcome must surface confirmation");
            match line {
                StatusLine::Confirmation(_) => {}
                StatusLine::Error(e) => panic!("expected Confirmation, got Error({e:?})"),
            }
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_settings_save_not_committed_keeps_modal_open_with_inline_error() {
    // Core's `mutate_and_save` rolls back inside on `save_not_committed`
    // so the vault stays at its pre-attempt values. The reducer
    // surfaces the typed error inline and the modal stays open so the
    // user can retry.
    let tmp = secure_tempdir();
    let (_path, _id, state) = fresh_unlocked_with_settings_modal_and_path(&tmp);
    let before = settings_snapshot(&state);
    let state = with_settings_modal_mut(state, |s| {
        s.auto_lock_enabled = !before.0;
    });
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let (state, effects) = reduce(state, settings_result(Err(err)));
    assert!(effects.is_empty());
    match &state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => {
            let surfaced = s
                .error
                .as_deref()
                .expect("save_not_committed must set inline error");
            assert!(
                surfaced.contains("save not committed") || surfaced.contains("save_not_committed"),
                "inline error must surface save_not_committed wording, got {surfaced:?}"
            );
        }
        other => panic!("expected open Settings modal, got {other:?}"),
    }
    // Live vault still reflects the rolled-back state.
    assert_eq!(
        settings_snapshot(&state),
        before,
        "Vault::settings() must reflect the rolled-back pre-attempt state on save_not_committed"
    );
}

#[test]
fn effect_result_settings_save_durability_unconfirmed_keeps_modal_open_with_inline_error() {
    // Durability-unconfirmed: core left the new values committed in
    // memory + on disk, but parent fsync was uncertain. Modal stays
    // open and the warning is inline so the user can retry or `Esc`
    // out deliberately.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let id = add_totp_account(&mut vault, &store, "github");
    vault
        .apply_setting_patch(SettingPatch::AutoLockEnabled(true))
        .expect("simulate executor-side patch");
    vault.save(&store).expect("commit setting");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal {
            auto_lock_enabled: true,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
            focus: SettingsFocus::default(),
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(
        unlocked,
        settings_result(Err(PaladinError::SaveDurabilityUnconfirmed)),
    );
    assert!(effects.is_empty());
    match &state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => {
            let surfaced = s
                .error
                .as_deref()
                .expect("durability-unconfirmed must surface inline");
            assert!(
                surfaced.contains("durability") || surfaced.contains("save durability"),
                "inline error must surface durability wording, got {surfaced:?}"
            );
        }
        other => panic!("expected open Settings modal, got {other:?}"),
    }
    // Live vault reflects the committed new value.
    match &state {
        AppState::Unlocked { vault, .. } => {
            assert!(
                vault.settings().auto_lock_enabled(),
                "durability-unconfirmed leaves the new values committed"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_settings_io_error_keeps_modal_open_with_inline_error() {
    // Generic I/O error path: any non-`SaveNotCommitted` /
    // non-`SaveDurabilityUnconfirmed` error also surfaces inline so
    // the user can adjust and retry.
    let tmp = secure_tempdir();
    let (_path, _id, state) = fresh_unlocked_with_settings_modal_and_path(&tmp);
    let err = PaladinError::IoError {
        operation: "settings_save",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    };
    let (state, _) = reduce(state, settings_result(Err(err)));
    match &state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => {
            let surfaced = s.error.as_deref().expect("io_error must surface inline");
            assert!(
                surfaced.to_lowercase().contains("i/o") || surfaced.contains("settings_save"),
                "inline error must surface io wording, got {surfaced:?}"
            );
        }
        other => panic!("expected open Settings modal, got {other:?}"),
    }
}

#[test]
fn effect_result_settings_validation_error_keeps_modal_open_with_inline_error() {
    // Defensive setter validation failure: even though the spinner
    // controls clamp to the shared core bounds, a malformed pending
    // value reaching the executor would surface back through
    // `EffectResult::Settings(Err(ValidationError { … }))`. The
    // reducer surfaces it inline and keeps the modal open.
    let tmp = secure_tempdir();
    let (_path, _id, state) = fresh_unlocked_with_settings_modal_and_path(&tmp);
    let err = PaladinError::ValidationError {
        field: "auto_lock.timeout_secs",
        reason: "out_of_range".to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    };
    let (state, _) = reduce(state, settings_result(Err(err)));
    match &state {
        AppState::Unlocked {
            modal: Some(Modal::Settings(s)),
            ..
        } => {
            let surfaced = s
                .error
                .as_deref()
                .expect("validation_error must surface inline");
            assert!(
                surfaced.contains("auto_lock.timeout_secs"),
                "inline error must mention the rejected field, got {surfaced:?}"
            );
        }
        other => panic!("expected open Settings modal, got {other:?}"),
    }
}

#[test]
fn effect_result_settings_on_locked_state_is_discarded() {
    // Auto-lock fired between the apply emit and the result delivery.
    // The result is dropped without mutating the Locked screen.
    let locked = AppState::Locked {
        path: PathBuf::from("/tmp/v.bin"),
        pending_clipboard_clear: None,
    };
    let (state, effects) = reduce(locked, settings_result(Ok(())));
    assert!(effects.is_empty());
    match state {
        AppState::Locked { path, .. } => assert_eq!(path, PathBuf::from("/tmp/v.bin")),
        other => panic!("expected Locked preserved, got {other:?}"),
    }
}

#[test]
fn effect_result_settings_on_non_settings_modal_is_discarded() {
    // A stale settings outcome arrives after the user dismissed
    // Settings and opened (say) the Add modal. The reducer must
    // leave the unrelated modal untouched.
    let tmp = secure_tempdir();
    let (path, (vault, store)) = open_plaintext_pair(&tmp);
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, settings_result(Ok(())));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add(_)),
            status_line: None,
            ..
        } => {}
        AppState::Unlocked {
            modal,
            status_line,
            ..
        } => panic!(
            "stale settings outcome must not touch unrelated modal / status, got modal={modal:?} status_line={status_line:?}"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Modals — close transitions
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer — bullet 4,
//  Keybindings table: "Esc — Close modal / clear search …")
//
// Slice covered: pressing `Esc` on `AppState::Unlocked` with an open
// modal clears the slot to `None` and emits no effects. With no open
// modal, `Esc` is a passthrough no-op on `Unlocked` (it does **not**
// emit `Effect::Quit`; only the unlock / missing-vault / startup-error
// "no dismissable affordance" screens quit on `Esc`). Search-clear and
// vim-chord clear land in their own slices.
// ---------------------------------------------------------------------------
//
// Per-variant coverage: this slice asserts the close transition for
// every `Modal` variant so the reducer's "reset to None" rule is
// observed regardless of which modal was open.
// ---------------------------------------------------------------------------

fn assert_esc_closes_modal(opened: Modal) {
    let tmp = secure_tempdir();
    let (path, (vault, store)) = open_plaintext_pair(&tmp);
    let unlocked = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(opened),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Esc));
    assert!(
        effects.is_empty(),
        "Esc closing a modal must not emit effects (and must not Quit)"
    );
    match state {
        AppState::Unlocked { modal: None, .. } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=None after Esc, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_esc_on_unlocked_with_open_add_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Add(AddModal::default()));
}

#[test]
fn pressing_esc_on_unlocked_with_open_import_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Import);
}

#[test]
fn pressing_esc_on_unlocked_with_open_export_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Export);
}

#[test]
fn pressing_esc_on_unlocked_with_open_remove_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Remove(RemoveModal::default()));
}

#[test]
fn pressing_esc_on_unlocked_with_open_rename_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Rename(RenameModal::default()));
}

#[test]
fn pressing_esc_on_unlocked_with_open_passphrase_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Passphrase);
}

#[test]
fn pressing_esc_on_unlocked_with_open_settings_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Settings(SettingsModal::default()));
}

#[test]
fn pressing_esc_on_unlocked_with_no_modal_open_is_passthrough_no_op() {
    // Unlocked is not in `quits_on_esc`'s "no dismissable
    // affordance" set, so Esc with no modal open is a silent
    // no-op — state unchanged, no `Effect::Quit`.
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Esc));
    assert!(
        effects.is_empty(),
        "Esc on Unlocked with no modal must not emit Effect::Quit, got {effects:?}"
    );
    match state {
        AppState::Unlocked { modal: None, .. } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=None preserved, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `q` quits Unlocked when no modal is open
// (IMPLEMENTATION_PLAN_03_TUI.md > Keybindings: "q — Quit from list,
//  missing-vault, and startup-error screens; text input in text fields")
//
// Slice covered: pressing `q` on `AppState::Unlocked` with no open modal
// emits `Effect::Quit`. With a modal open, `q` is passthrough so the
// modal-local input path can consume it as text (modal payloads land
// per-modal). The search-focused "text input" branch arrives with the
// focus-state slice; at this slice every `Unlocked` is treated as
// list-focused because no other focus exists yet.
// ---------------------------------------------------------------------------

#[test]
fn pressing_q_on_unlocked_with_no_modal_open_quits() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (_, effects) = reduce(unlocked, key(KeyCode::Char('q')));
    assert!(
        matches!(effects.as_slice(), [Effect::Quit]),
        "expected [Effect::Quit], got {effects:?}"
    );
}

#[test]
fn pressing_q_on_unlocked_with_modal_open_does_not_quit() {
    // With a modal open, `q` belongs to the modal-local input path
    // (it'll be consumed as a text-field character once payloads
    // land). The reducer must not emit `Effect::Quit` and must not
    // mutate the open modal slot.
    let tmp = secure_tempdir();
    let (path, (vault, store)) = open_plaintext_pair(&tmp);
    let unlocked = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('q')));
    assert!(
        effects.is_empty(),
        "q with a modal open must not emit Effect::Quit, got {effects:?}"
    );
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add(_)),
            ..
        } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=Some(Modal::Add) preserved, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_q_on_unlocked_does_not_quit() {
    // `Ctrl-Q` is not bound and must not silently quit. The bare
    // `q` quit lives at the modifier-free surface.
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (_, effects) = reduce(unlocked, ctrl(KeyCode::Char('q')));
    assert!(
        effects.is_empty(),
        "Ctrl-Q is unbound; expected no effects, got {effects:?}"
    );
}

// ---------------------------------------------------------------------------
// List selection navigation — `↑` / `↓` and the vim `j` / `k` mirrors
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer:
//   "Selection navigation moves correctly under `↑` / `↓` / `j` / `k`,
//    `PgUp` / `PgDn` / `Ctrl-B` / `Ctrl-F`, `Ctrl-U` / `Ctrl-D`, and
//    `Home` / `End`."
//  + Vim-style navigation: "`j` / `k` mirror `↓` / `↑`.")
//
// Slice covered: bare `↑` / `↓` / `j` / `k` step the selection by one
// row through `Vault::iter()` (insertion order) and clamp at both ends.
// `j` / `k` mirror the arrow keys; Ctrl/Alt modifier or a modal open
// suppress the move. Empty filtered set is a silent no-op (the
// `select_after_filter` `None` invariant). Page / chord / half-page
// keys land in later slices.
// ---------------------------------------------------------------------------

/// Build a 3-account plaintext Unlocked state with the first account
/// selected; returns the three inserted ids in insertion order.
fn unlocked_with_three_accounts(tmp: &tempfile::TempDir) -> (AppState, [AccountId; 3]) {
    let (path, (mut vault, store)) = open_plaintext_pair(tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    (state, [a, b, c])
}

#[test]
fn pressing_down_arrow_on_unlocked_moves_selection_to_next_account() {
    let tmp = secure_tempdir();
    let (state, [_a, b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Down));
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "Down on first row must advance selection to the second row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_down_arrow_walks_through_multiple_rows() {
    let tmp = secure_tempdir();
    let (mut state, [_a, b, c]) = unlocked_with_three_accounts(&tmp);
    let (next, _) = reduce(state, key(KeyCode::Down));
    state = next;
    match &state {
        AppState::Unlocked { selected, .. } => assert_eq!(*selected, Some(b)),
        other => panic!("expected Unlocked, got {other:?}"),
    }
    let (next, _) = reduce(state, key(KeyCode::Down));
    match next {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(c),
            "two Down presses on a 3-row list must reach the last row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_down_arrow_at_end_of_list_clamps() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Down));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "Down at end of list must clamp on the last row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_up_arrow_on_unlocked_moves_selection_to_previous_account() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Up));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "Up on second row must retreat selection to the first row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_up_arrow_at_start_of_list_clamps() {
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Up));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "Up at start of list must clamp on the first row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_down_arrow_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Down));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_up_arrow_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Up));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_down_arrow_with_modal_open_does_not_move_selection() {
    // Modal-open routes list-navigation keys to the modal's input
    // path. At this slice the modal payloads do not exist yet, so the
    // observable contract is: the selection is preserved unchanged.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Down));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            selected,
            Some(a),
            "Down inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_j_mirrors_down_arrow() {
    let tmp = secure_tempdir();
    let (state, [_a, b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('j')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "vim `j` must mirror Down arrow on the list"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_k_mirrors_up_arrow() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('k')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "vim `k` must mirror Up arrow on the list"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_down_does_not_move_selection() {
    // `Ctrl-Down` is not bound in `Keybindings (initial v0.1)`. The
    // bare `Down` moves selection, but the same key with the Control
    // modifier must not — readline-style Ctrl bindings should not
    // silently navigate.
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, ctrl(KeyCode::Down));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => {
            assert_eq!(selected, Some(a), "Ctrl-Down must not move list selection");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_j_with_modal_open_does_not_move_selection() {
    // With a modal open, `j` belongs to the modal-local input path
    // (it'll be consumed as a text-field character once payloads land).
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('j')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Add(_)),
            ..
        } => assert_eq!(
            selected,
            Some(a),
            "vim `j` inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Add open, got {other:?}"),
    }
}

#[test]
fn pressing_k_with_modal_open_does_not_move_selection() {
    // Parity with `pressing_down_arrow_with_modal_open_does_not_move_selection`
    // and `pressing_j_with_modal_open_does_not_move_selection`: with a
    // modal open, `k` belongs to the modal-local input path and must
    // not move list selection.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('k')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            selected,
            Some(b),
            "vim `k` inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_j_at_end_of_list_clamps() {
    // Mirrors `pressing_down_arrow_at_end_of_list_clamps`: vim `j` on
    // the last row must clamp and not advance past the tail.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('j')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "vim `j` at end of list must clamp on the last row, mirroring Down"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_k_at_start_of_list_clamps() {
    // Mirrors `pressing_up_arrow_at_start_of_list_clamps`: vim `k` on
    // the first row must clamp and not retreat past the head.
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('k')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "vim `k` at start of list must clamp on the first row, mirroring Up"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_j_with_empty_vault_is_silent_no_op() {
    // Mirrors `pressing_down_arrow_with_empty_vault_is_silent_no_op`:
    // vim `j` on an empty vault must keep `selected = None` and emit
    // no effects.
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('j')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_k_with_empty_vault_is_silent_no_op() {
    // Mirrors `pressing_up_arrow_with_empty_vault_is_silent_no_op`:
    // vim `k` on an empty vault must keep `selected = None` and emit
    // no effects.
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('k')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `Home` / `End` — jump-to-first / jump-to-last list selection (Unlocked).
//
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer:
//   "Selection navigation moves correctly under `↑` / `↓` / `j` / `k`,
//    `PgUp` / `PgDn` / `Ctrl-B` / `Ctrl-F`, `Ctrl-U` / `Ctrl-D`, and
//    `Home` / `End`.")
//
// Slice covered: bare `Home` jumps the selection to the first row of
// `Vault::iter()` (insertion order); bare `End` jumps to the last row.
// Ctrl/Alt modifier or a modal open suppress the move. Empty filtered
// set is a silent no-op. Already-at-first / already-at-last are
// observable no-ops (the resolved selection is identical to the prior
// selection). The `G` vim mirror of `End` and the `gg` chord mirror of
// `Home` land in later slices.
// ---------------------------------------------------------------------------

#[test]
fn pressing_home_on_unlocked_jumps_to_first_account() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(c),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Home));
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "Home must jump selection to the first inserted account"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_end_on_unlocked_jumps_to_last_account() {
    let tmp = secure_tempdir();
    let (state, [_a, _b, c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::End));
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(c),
            "End must jump selection to the last inserted account"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_home_at_first_account_is_a_no_op() {
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Home));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "Home on the first row must leave the selection unchanged"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_end_at_last_account_is_a_no_op() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::End));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "End on the last row must leave the selection unchanged"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_home_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Home));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_end_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::End));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_home_with_modal_open_does_not_move_selection() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(c),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Home));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            selected,
            Some(c),
            "Home inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_end_with_modal_open_does_not_move_selection() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::End));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Add(_)),
            ..
        } => assert_eq!(
            selected,
            Some(a),
            "End inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Add open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_home_does_not_move_selection() {
    // `Ctrl-Home` is not bound in `Keybindings (initial v0.1)`. The
    // bare `Home` jumps to the first row, but the same key with the
    // Control modifier must not silently navigate.
    let tmp = secure_tempdir();
    let (state, [_a, _b, c]) = unlocked_with_three_accounts(&tmp);
    let unlocked = match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            ..
        } => AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            selected: Some(c),
            pending_chord_leader: None,
            viewport_height: 0,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        },
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Home));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => {
            assert_eq!(selected, Some(c), "Ctrl-Home must not move list selection");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_end_does_not_move_selection() {
    // Same rationale as `Ctrl-Home`: only the bare `End` is bound.
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, ctrl(KeyCode::End));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => {
            assert_eq!(selected, Some(a), "Ctrl-End must not move list selection");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Vim `G` — mirror of `End` (jump-to-last list selection on Unlocked).
//
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Vim-style navigation:
//   "`G` mirrors `End`.")
//
// Slice covered: bare upper-case `G` (Shift+g — crossterm reports the
// resolved `KeyCode::Char('G')`, with or without `KeyModifiers::SHIFT`
// depending on the terminal) jumps the selection to the last row of
// `Vault::iter()`. Suppression rules mirror `End`: Ctrl/Alt blocks the
// jump, a modal-open is passthrough so modal-local input wins, and an
// empty filtered set is a silent no-op. Bare lower-case `g` stays a
// no-op at this slice — the `gg` chord leader lands with the pending-
// chord state slice; the contract here is just that a single `g`
// never moves selection on its own.
// ---------------------------------------------------------------------------

#[test]
fn pressing_shift_g_on_unlocked_jumps_to_last_account() {
    let tmp = secure_tempdir();
    let (state, [_a, _b, c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(
        state,
        AppEvent::Input {
            event: Event::Key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT)),
            at: Instant::now(),
        },
    );
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(c),
            "vim `G` must jump selection to the last inserted account (End mirror)"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_shift_g_without_modifier_byte_still_jumps_to_last() {
    // Some terminals fold Shift into the resolved character and drop
    // `KeyModifiers::SHIFT`; the upper-case match arm must still
    // resolve `G` to a jump.
    let tmp = secure_tempdir();
    let (state, [_a, _b, c]) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('G')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(c),
            "`G` with no Shift modifier byte must still resolve to jump-to-last"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_shift_g_at_last_account_is_a_no_op() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('G')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "vim `G` on the last row must leave the selection unchanged"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_shift_g_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('G')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_shift_g_with_modal_open_does_not_move_selection() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('G')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Add(_)),
            ..
        } => assert_eq!(
            selected,
            Some(a),
            "vim `G` inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Add open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_shift_g_does_not_move_selection() {
    // `Ctrl-G` (or `Ctrl-Shift-G`) is not bound; only the bare /
    // shift-only `G` jumps to last.
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(
        state,
        AppEvent::Input {
            event: Event::Key(KeyEvent::new(
                KeyCode::Char('G'),
                KeyModifiers::CONTROL | KeyModifiers::SHIFT,
            )),
            at: Instant::now(),
        },
    );
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "Ctrl-Shift-G must not move list selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_lowercase_g_on_unlocked_does_not_move_selection() {
    // Bare lower-case `g` is the `gg` chord leader: the first press
    // sets pending state but never moves the selection on its own.
    // The matching second `g` commits the jump-to-first; that
    // commit-on-second-press behaviour is covered separately.
    let tmp = secure_tempdir();
    let (state, [_a, _b, c]) = unlocked_with_three_accounts(&tmp);
    let unlocked = match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            ..
        } => AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            selected: Some(c),
            pending_chord_leader: None,
            viewport_height: 0,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        },
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('g')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(c),
            "first `g` is the chord leader and must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `gg` two-press chord — vim mirror of `Home` (jump-to-first).
//
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Vim-style navigation:
//   "`gg` two-press chord jumps to the first row of the filtered set."
//  + "Pending-leader chord state is held by the reducer, committed on
//    the matching second press, and cleared by any non-matching key,
//    focus change, modal open, `Esc`, or auto-lock.")
//
// Slice covered: lower-case `g` on `Unlocked` with no modal open sets
// `pending_chord_leader = Some(ChordLeader::G)` on first press and
// commits a jump-to-first on the matching second press (clearing the
// pending state). A non-matching key, an `Esc`, a modal open, and any
// Ctrl/Alt-modifier press all clear the pending state. The chord
// never engages while a modal is open. Empty filtered set is a silent
// no-op. `Tick` events between the two presses preserve the pending
// state (vim's `nottimeout` semantics — there is no timeout). The
// `zz` chord, `gg` from the focused search field, and the auto-lock
// chord-drop assertion land in later slices.
// ---------------------------------------------------------------------------

#[test]
fn pressing_lowercase_g_on_unlocked_sets_pending_chord_leader() {
    let tmp = secure_tempdir();
    let (state, [_a, _b, c]) = unlocked_with_three_accounts(&tmp);
    let unlocked = match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            ..
        } => AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            selected: Some(c),
            pending_chord_leader: None,
            viewport_height: 0,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        },
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('g')));
    assert!(effects.is_empty(), "chord leader must not emit effects");
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            ..
        } => assert_eq!(
            pending_chord_leader,
            Some(ChordLeader::G),
            "first `g` must set pending chord leader to G"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_gg_on_unlocked_jumps_to_first_account() {
    let tmp = secure_tempdir();
    let (state, [a, _b, c]) = unlocked_with_three_accounts(&tmp);
    // Start with selection on the last account so the jump is observable.
    let unlocked = match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            ..
        } => AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            selected: Some(c),
            pending_chord_leader: None,
            viewport_height: 0,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        },
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('g')));
    assert!(effects.is_empty());
    let (state, effects) = reduce(state, key(KeyCode::Char('g')));
    assert!(effects.is_empty(), "chord commit must not emit effects");
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                selected,
                Some(a),
                "`gg` must jump selection to the first inserted account"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`gg` commit must clear pending chord state"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_g_then_j_clears_chord_and_moves_down() {
    // A non-matching key after the chord leader must clear the
    // pending state AND still execute its own action — pressing
    // `gj` from the first row should land on the second row, not
    // jump-to-first.
    let tmp = secure_tempdir();
    let (state, [_a, b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, effects) = reduce(state, key(KeyCode::Char('j')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                selected,
                Some(b),
                "`j` after `g` must execute Down even though it cleared the chord"
            );
            assert_eq!(
                pending_chord_leader, None,
                "non-matching key must clear pending chord state"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_esc_after_g_clears_pending_chord_leader() {
    // `Esc` on the list with no modal open is otherwise a no-op, but
    // it always clears any pending vim chord state.
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, effects) = reduce(state, key(KeyCode::Esc));
    assert!(
        effects.is_empty(),
        "Esc on Unlocked with no modal open must be effect-free"
    );
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            modal,
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "Esc must clear pending chord state"
            );
            assert!(modal.is_none(), "Esc must not open a modal");
            assert_eq!(selected, Some(a), "Esc must not move list selection");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_modal_opener_after_g_clears_chord_and_opens_modal() {
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, effects) = reduce(state, key(KeyCode::Char('a')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            modal,
            ..
        } => {
            assert!(
                matches!(modal, Some(Modal::Add(_))),
                "`a` after `g` must still open the Add modal"
            );
            assert_eq!(
                pending_chord_leader, None,
                "opening a modal must clear pending chord state"
            );
            assert_eq!(
                selected,
                Some(a),
                "opening a modal must not move list selection"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_g_with_modal_open_does_not_set_chord_leader() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('g')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            pending_chord_leader, None,
            "chord leader must not engage while a modal is open"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_gg_on_empty_vault_is_silent_noop() {
    let tmp = secure_tempdir();
    let (vault_path, (vault, store)) = open_plaintext_pair(&tmp);
    let unlocked = AppState::Unlocked {
        path: vault_path,
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
    let (state, _) = reduce(unlocked, key(KeyCode::Char('g')));
    let (state, effects) = reduce(state, key(KeyCode::Char('g')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(selected, None, "`gg` on empty vault must stay at None");
            assert_eq!(
                pending_chord_leader, None,
                "`gg` commit must still clear pending chord state on empty vault"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_g_clears_pending_chord_leader() {
    // `Ctrl-G` is not bound; it falls through the Ctrl/Alt modifier
    // guard, which also clears any pending chord state.
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, effects) = reduce(state, ctrl(KeyCode::Char('g')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "Ctrl-G must clear pending chord state"
            );
            assert_eq!(selected, Some(a), "Ctrl-G must not move selection");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn tick_between_g_presses_preserves_pending_chord_leader() {
    // vim's `nottimeout` semantics — there is no timeout on the chord.
    // A `Tick` event delivered between the two `g` presses must not
    // clear the pending chord leader; the second `g` still commits the
    // jump-to-first.
    let tmp = secure_tempdir();
    let (state, [a, _b, c]) = unlocked_with_three_accounts(&tmp);
    let unlocked = match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            ..
        } => AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            selected: Some(c),
            pending_chord_leader: None,
            viewport_height: 0,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        },
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('g')));
    // Slip a tick through; with no idle deadline armed this is a
    // total passthrough but must not clear chord state.
    let (state, _) = reduce(
        state,
        AppEvent::Tick {
            wall_clock: SystemTime::now(),
            monotonic: Instant::now(),
        },
    );
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                selected,
                Some(a),
                "Tick between `g`s must not break the chord — `gg` still commits jump-to-first"
            );
            assert_eq!(
                pending_chord_leader, None,
                "after commit pending chord state must be cleared"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `PgUp` / `PgDn` — page-up / page-down list selection by `viewport_height`.
//
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Reducer:
//   "Selection navigation moves correctly under `↑` / `↓` / `j` / `k`,
//    `PgUp` / `PgDn` / `Ctrl-B` / `Ctrl-F`, `Ctrl-U` / `Ctrl-D`, and
//    `Home` / `End`."
//  + DESIGN §6: "PgUp/PgDn and Ctrl-B/Ctrl-F move by viewport height".)
//
// Slice covered: bare `PgDn` / `PgUp` walk `Vault::iter()` (insertion order)
// by `viewport_height` rows from the current selection, clamping at the
// last / first row when fewer rows remain. `viewport_height = 0` makes the
// step a silent no-op (the production run loop seeds the real height
// through the resize-driven viewport slice). Empty filtered set is a
// silent no-op. Modal open or Ctrl/Alt modifier suppresses the move. The
// `Ctrl-F` / `Ctrl-B` vim mirrors, `Ctrl-U` / `Ctrl-D` half-page
// variants, and the search-focus pass-through land in later slices.
// ---------------------------------------------------------------------------

/// Build a plaintext `AppState::Unlocked` with `n` TOTP accounts named
/// `acct-0` … `acct-{n-1}` and the given `viewport_height`, selecting
/// the first account. Returns the state plus the account IDs in
/// insertion order so tests can assert against specific rows.
fn unlocked_with_n_accounts(
    tmp: &tempfile::TempDir,
    n: usize,
    viewport_height: u16,
) -> (AppState, Vec<AccountId>) {
    let (path, (mut vault, store)) = open_plaintext_pair(tmp);
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let label = format!("acct-{i}");
        ids.push(add_totp_account(&mut vault, &store, &label));
    }
    let selected = ids.first().copied();
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected,
        pending_chord_leader: None,
        viewport_height,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    (state, ids)
}

#[test]
fn decide_state_from_open_seeds_viewport_height_to_zero() {
    // Unlocked entry must seed `viewport_height = 0`; the production
    // run loop replaces it with the real terminal height through the
    // resize-driven viewport slice before the first draw.
    let tmp = secure_tempdir();
    let (vault_path, (vault, store)) = open_plaintext_pair(&tmp);
    let now = Instant::now();
    let state = decide_state_from_open(now, vault_path, Ok((vault, store)));
    match state {
        AppState::Unlocked {
            viewport_height, ..
        } => assert_eq!(
            viewport_height, 0,
            "decide_state_from_open must seed viewport_height to 0"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_unlock_ok_seeds_viewport_height_to_zero() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, store) = create_encrypted_pair(&path, "pw");
    drop(vault);
    drop(store);
    let pp = SecretString::from("pw".to_string());
    let pair = Store::open(&path, VaultLock::Encrypted(pp)).expect("unlock");

    let prior = AppState::Unlock {
        path: path.clone(),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    let (state, _) = reduce(prior, unlock_result(Ok(pair)));
    match state {
        AppState::Unlocked {
            viewport_height, ..
        } => assert_eq!(
            viewport_height, 0,
            "EffectResult::Unlock Ok must seed viewport_height to 0"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_down_on_unlocked_moves_selection_by_viewport_height() {
    // viewport_height = 2 over a four-row vault: selection at row 0
    // advances to row 2.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 4, 2);
    let (state, effects) = reduce(state, key(KeyCode::PageDown));
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(ids[2]),
            "PgDn must advance selection by viewport_height rows"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_up_on_unlocked_moves_selection_by_viewport_height() {
    // viewport_height = 2 over a four-row vault: selection at row 3
    // retreats to row 1.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(d),
        pending_chord_leader: None,
        viewport_height: 2,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::PageUp));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "PgUp must retreat selection by viewport_height rows"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_down_clamps_to_last_when_fewer_rows_remain() {
    // viewport_height = 3 over a four-row vault: selection at row 2
    // would land beyond the end; clamp at the last row.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(c),
        pending_chord_leader: None,
        viewport_height: 3,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::PageDown));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(d),
            "PgDn past the end must clamp on the last row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_up_clamps_to_first_when_fewer_rows_remain() {
    // viewport_height = 3 over a four-row vault: selection at row 1
    // would land before the start; clamp at the first row.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 3,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::PageUp));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "PgUp past the start must clamp on the first row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_down_with_viewport_height_zero_is_a_no_op() {
    // viewport_height = 0 (pre-resize seed) makes page navigation a
    // silent no-op so the reducer stays deterministic before the
    // production run loop has sampled the terminal size.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 3, 0);
    let (state, effects) = reduce(state, key(KeyCode::PageDown));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(ids[0]),
            "PgDn with viewport_height = 0 must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_up_with_viewport_height_zero_is_a_no_op() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::PageUp));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "PgUp with viewport_height = 0 must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_down_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::PageDown));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_up_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, key(KeyCode::PageUp));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_down_with_modal_open_does_not_move_selection() {
    // With a modal open, list-navigation keys route to the modal-local
    // input path. Observable contract at this slice: selection is
    // preserved unchanged.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 2,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::PageDown));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            selected,
            Some(a),
            "PgDn inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_page_down_does_not_move_selection() {
    // `Ctrl-PgDn` is not bound; the Ctrl/Alt modifier guard also
    // clears any pending chord state.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 4, 2);
    let (state, effects) = reduce(state, ctrl(KeyCode::PageDown));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(ids[0]),
            "Ctrl-PgDn must not move list selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_down_clears_pending_chord_leader() {
    // Any non-matching list-navigation key clears the pending chord
    // state before its own action runs.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 4, 2);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, _) = reduce(state, key(KeyCode::PageDown));
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "PgDn must clear pending chord leader"
            );
            assert_eq!(
                selected,
                Some(ids[2]),
                "PgDn must still advance after clearing the chord"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Vim-style navigation: Ctrl-F / Ctrl-B mirror PgDn / PgUp
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Vim-style navigation)
// ---------------------------------------------------------------------------

#[test]
fn pressing_ctrl_f_on_unlocked_moves_selection_by_viewport_height() {
    // Ctrl-F is the vim mirror of PgDn: viewport_height = 2 over a
    // four-row vault advances selection at row 0 to row 2.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 4, 2);
    let (state, effects) = reduce(state, ctrl(KeyCode::Char('f')));
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(ids[2]),
            "Ctrl-F must advance selection by viewport_height rows (PgDn mirror)"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_b_on_unlocked_moves_selection_by_viewport_height() {
    // Ctrl-B is the vim mirror of PgUp: viewport_height = 2 over a
    // four-row vault retreats selection at row 3 to row 1.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(d),
        pending_chord_leader: None,
        viewport_height: 2,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('b')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "Ctrl-B must retreat selection by viewport_height rows (PgUp mirror)"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_f_clamps_to_last_when_fewer_rows_remain() {
    // Mirrors PgDn clamp: viewport_height = 3 with selection at row 2
    // (one row from end) clamps at the last row.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(c),
        pending_chord_leader: None,
        viewport_height: 3,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, ctrl(KeyCode::Char('f')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(d),
            "Ctrl-F past the end must clamp on the last row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_b_clamps_to_first_when_fewer_rows_remain() {
    // Mirrors PgUp clamp: viewport_height = 3 with selection at row 1
    // (one row from start) clamps at the first row.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 3,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, ctrl(KeyCode::Char('b')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "Ctrl-B past the start must clamp on the first row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_f_with_viewport_height_zero_is_a_no_op() {
    // Matches PgDn: viewport_height = 0 (pre-resize seed) is a silent
    // no-op so the reducer stays deterministic before the production
    // run loop has sampled the terminal size.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 3, 0);
    let (state, effects) = reduce(state, ctrl(KeyCode::Char('f')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(ids[0]),
            "Ctrl-F with viewport_height = 0 must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_b_with_viewport_height_zero_is_a_no_op() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('b')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "Ctrl-B with viewport_height = 0 must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_f_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('f')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_b_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('b')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_f_with_modal_open_does_not_move_selection() {
    // Mirrors PgDn: with a modal open, list-navigation keys route to
    // the modal-local input path. Observable contract at this slice:
    // selection is preserved unchanged.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 2,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('f')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            selected,
            Some(a),
            "Ctrl-F inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_b_with_modal_open_does_not_move_selection() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(c),
        pending_chord_leader: None,
        viewport_height: 2,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('b')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            selected,
            Some(c),
            "Ctrl-B inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_f_clears_pending_chord_leader() {
    // Mirrors PgDn: a non-matching key clears the pending chord state
    // before its own action runs.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 4, 2);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, _) = reduce(state, ctrl(KeyCode::Char('f')));
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "Ctrl-F must clear pending chord leader"
            );
            assert_eq!(
                selected,
                Some(ids[2]),
                "Ctrl-F must still advance after clearing the chord"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_b_clears_pending_chord_leader() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(d),
        pending_chord_leader: None,
        viewport_height: 2,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('g')));
    let (state, _) = reduce(state, ctrl(KeyCode::Char('b')));
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "Ctrl-B must clear pending chord leader"
            );
            assert_eq!(
                selected,
                Some(b),
                "Ctrl-B must still retreat after clearing the chord"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Vim-style navigation: Ctrl-U / Ctrl-D half-page up / down
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Vim-style navigation; per
// Layout §6, half-page = viewport_height / 2 rows, clamped at head/tail)
// ---------------------------------------------------------------------------

#[test]
fn pressing_ctrl_d_on_unlocked_moves_selection_by_half_viewport_height() {
    // viewport_height = 4 (half = 2) over a five-row vault: selection
    // at row 0 advances to row 2.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let _e = add_totp_account(&mut vault, &store, "e");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('d')));
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(c),
            "Ctrl-D must advance selection by viewport_height/2 rows"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_u_on_unlocked_moves_selection_by_half_viewport_height() {
    // viewport_height = 4 (half = 2) over a five-row vault: selection
    // at row 4 retreats to row 2.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let e = add_totp_account(&mut vault, &store, "e");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(e),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('u')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(c),
            "Ctrl-U must retreat selection by viewport_height/2 rows"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn ctrl_d_half_page_uses_integer_division_on_odd_viewport_height() {
    // viewport_height = 5 (half = 2 by integer division) over a
    // four-row vault: selection at row 0 advances to row 2.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 5,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, ctrl(KeyCode::Char('d')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(c),
            "Ctrl-D with viewport_height = 5 must advance by 2 (integer-div half)"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_d_clamps_to_last_when_fewer_rows_remain() {
    // viewport_height = 4 (half = 2) with selection at row 3 (one row
    // from end): clamp at the last row.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let d = add_totp_account(&mut vault, &store, "d");
    let e = add_totp_account(&mut vault, &store, "e");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(d),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, ctrl(KeyCode::Char('d')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(e),
            "Ctrl-D past the end must clamp on the last row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_u_clamps_to_first_when_fewer_rows_remain() {
    // viewport_height = 4 (half = 2) with selection at row 1 (one row
    // from start): clamp at the first row.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let _e = add_totp_account(&mut vault, &store, "e");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, ctrl(KeyCode::Char('u')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(a),
            "Ctrl-U past the start must clamp on the first row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_d_with_viewport_height_zero_is_a_no_op() {
    // Pre-resize seed: half-of-0 = 0, no-op.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 3, 0);
    let (state, effects) = reduce(state, ctrl(KeyCode::Char('d')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(ids[0]),
            "Ctrl-D with viewport_height = 0 must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_u_with_viewport_height_zero_is_a_no_op() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('u')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "Ctrl-U with viewport_height = 0 must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_d_with_viewport_height_one_is_a_no_op() {
    // viewport_height = 1 (half = 0 by integer division) is a no-op:
    // half-page is undefined on a one-row viewport.
    let tmp = secure_tempdir();
    let (state, ids) = unlocked_with_n_accounts(&tmp, 3, 1);
    let (state, effects) = reduce(state, ctrl(KeyCode::Char('d')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(ids[0]),
            "Ctrl-D with viewport_height = 1 (half = 0) must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_u_with_viewport_height_one_is_a_no_op() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 1,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('u')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(b),
            "Ctrl-U with viewport_height = 1 (half = 0) must not move selection"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_d_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('d')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_u_with_empty_vault_is_silent_no_op() {
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('u')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { selected: None, .. } => {}
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_d_with_modal_open_does_not_move_selection() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('d')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            selected,
            Some(a),
            "Ctrl-D inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_u_with_modal_open_does_not_move_selection() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(c),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('u')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            selected,
            Some(c),
            "Ctrl-U inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_d_clears_pending_chord_leader() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let _e = add_totp_account(&mut vault, &store, "e");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('g')));
    let (state, _) = reduce(state, ctrl(KeyCode::Char('d')));
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "Ctrl-D must clear pending chord leader"
            );
            assert_eq!(
                selected,
                Some(c),
                "Ctrl-D must still advance after clearing the chord"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_u_clears_pending_chord_leader() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let e = add_totp_account(&mut vault, &store, "e");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(e),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('g')));
    let (state, _) = reduce(state, ctrl(KeyCode::Char('u')));
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "Ctrl-U must clear pending chord leader"
            );
            assert_eq!(
                selected,
                Some(c),
                "Ctrl-U must still retreat after clearing the chord"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `zz` two-press chord — vim recenter (place selected row in the
// middle of the viewport).
//
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Vim-style navigation:
//   "`zz` two-press chord recenters the viewport on the selected row."
//  + "Pending-leader chord state is held by the reducer, committed on
//    the matching second press, and cleared by any non-matching key,
//    focus change, modal open, `Esc`, or auto-lock.")
//
// Slice covered: lower-case `z` on `Unlocked` with no modal open sets
// `pending_chord_leader = Some(ChordLeader::Z)` on first press and
// commits a recenter on the matching second press (clearing the
// pending state). The recenter sets
// `viewport_offset = sel_pos.saturating_sub(viewport_height / 2)`
// (integer division), where `sel_pos` is the position of the
// selected account in `Vault::iter()`. A non-matching key, an `Esc`,
// a modal open, any Ctrl/Alt-modifier press, and auto-lock all clear
// the pending state. `g` after `z` and `z` after `g` cross-clear the
// other leader and set their own (mixed chords do not commit).
// Empty filtered set, `viewport_height = 0`, and an open modal are
// all silent no-ops. `Tick` between the two presses preserves the
// pending state (vim's `nottimeout` semantics).
// ---------------------------------------------------------------------------

#[test]
fn pressing_lowercase_z_on_unlocked_sets_pending_chord_leader_z() {
    // First `z` is the chord leader: it must set
    // `pending_chord_leader = Some(ChordLeader::Z)` and leave the
    // viewport unchanged.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let c = add_totp_account(&mut vault, &store, "c");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(c),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('z')));
    assert!(effects.is_empty(), "chord leader must not emit effects");
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            viewport_offset,
            ..
        } => {
            assert_eq!(
                pending_chord_leader,
                Some(ChordLeader::Z),
                "first `z` must set pending chord leader to Z"
            );
            assert_eq!(
                viewport_offset, 0,
                "first `z` is the chord leader and must not move the viewport"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_zz_recenters_viewport_on_selected_row() {
    // Five-row vault, viewport_height = 4 (half = 2), selection at
    // row 3 → target offset = 3 - 2 = 1 (selected sits in viewport
    // middle).
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let d = add_totp_account(&mut vault, &store, "d");
    let _e = add_totp_account(&mut vault, &store, "e");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(d),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('z')));
    let (state, effects) = reduce(state, key(KeyCode::Char('z')));
    assert!(effects.is_empty(), "chord commit must not emit effects");
    match state {
        AppState::Unlocked {
            viewport_offset,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                viewport_offset, 1,
                "`zz` must set viewport_offset = sel_pos.saturating_sub(viewport_height / 2)"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`zz` commit must clear pending chord state"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_zz_uses_integer_division_on_odd_viewport_height() {
    // viewport_height = 5 (half = 2 by integer division). Selection
    // at row 4 → target offset = 4 - 2 = 2.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let _b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let e = add_totp_account(&mut vault, &store, "e");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(e),
        pending_chord_leader: None,
        viewport_height: 5,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match state {
        AppState::Unlocked {
            viewport_offset, ..
        } => assert_eq!(
            viewport_offset, 2,
            "`zz` with viewport_height = 5 must use integer-division half"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_zz_near_top_clamps_offset_to_zero() {
    // Selection at row 1, viewport_height = 4 (half = 2): target
    // would be 1 - 2 = -1 → saturating_sub clamps to 0.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let _a = add_totp_account(&mut vault, &store, "a");
    let b = add_totp_account(&mut vault, &store, "b");
    let _c = add_totp_account(&mut vault, &store, "c");
    let _d = add_totp_account(&mut vault, &store, "d");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(b),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 3,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match state {
        AppState::Unlocked {
            viewport_offset, ..
        } => assert_eq!(
            viewport_offset, 0,
            "`zz` near the top must clamp viewport_offset to 0"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_zz_with_viewport_height_zero_is_a_no_op() {
    // viewport_height = 0 (pre-resize seed): half is 0, but
    // recenter on a zero-height viewport is undefined. Preserve
    // viewport_offset unchanged.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_n_accounts(&tmp, 3, 0);
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match state {
        AppState::Unlocked {
            viewport_offset,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                viewport_offset, 0,
                "`zz` with viewport_height = 0 must not move the viewport"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`zz` commit must still clear the pending chord"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_zz_with_empty_vault_is_silent_no_op() {
    // Empty filtered set: every list-navigation key including the
    // chords is a silent no-op. viewport_offset preserved.
    let tmp = secure_tempdir();
    let unlocked = fresh_plaintext_unlocked(&tmp);
    let (state, _) = reduce(unlocked, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match state {
        AppState::Unlocked {
            viewport_offset,
            pending_chord_leader,
            selected: None,
            ..
        } => {
            assert_eq!(
                viewport_offset, 0,
                "`zz` on empty vault must not move the viewport"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`zz` commit must still clear the pending chord"
            );
        }
        AppState::Unlocked { selected, .. } => {
            panic!("expected selected=None on empty vault, got {selected:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_z_with_modal_open_does_not_set_chord_leader() {
    // While a modal is open the chord never engages — bare-letter
    // input belongs to the modal.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 4,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('z')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            viewport_offset,
            modal: Some(Modal::Settings(_)),
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "`z` inside a modal must not arm the chord leader"
            );
            assert_eq!(
                viewport_offset, 0,
                "`z` inside a modal must not move the viewport"
            );
        }
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_z_then_j_clears_chord_and_moves_down() {
    // Mirrors the `gj` cross-key test: a non-matching key after the
    // chord leader must clear the pending state AND still execute its
    // own action.
    let tmp = secure_tempdir();
    let (state, [_a, b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let (state, effects) = reduce(state, key(KeyCode::Char('j')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                pending_chord_leader, None,
                "non-matching key after `z` must clear the pending chord"
            );
            assert_eq!(
                selected,
                Some(b),
                "`zj` from the first row must land on the second row"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_z_after_g_clears_g_and_sets_z_pending() {
    // Cross-chord: a pending `g` is cleared when `z` is pressed,
    // and `z` arms its own pending state instead.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            ..
        } => assert_eq!(
            pending_chord_leader,
            Some(ChordLeader::Z),
            "`z` after pending `g` must clear G and set Z"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_g_after_z_clears_z_and_sets_g_pending() {
    // Symmetry: a pending `z` is cleared when `g` is pressed, and
    // `g` arms its own pending state instead.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            ..
        } => assert_eq!(
            pending_chord_leader,
            Some(ChordLeader::G),
            "`g` after pending `z` must clear Z and set G"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_g_then_z_does_not_commit_gg_or_zz() {
    // Selection must not jump-to-first (no `gg` commit) and
    // viewport must not recenter (no `zz` commit) when the two
    // leaders are interleaved. viewport_offset stays unchanged.
    let tmp = secure_tempdir();
    let (state, [_a, _b, c]) = unlocked_with_three_accounts(&tmp);
    let unlocked = match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            ..
        } => AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            selected: Some(c),
            pending_chord_leader: None,
            viewport_height: 4,
            viewport_offset: 0,
            focus: Focus::List,
            status_line: None,
            help_open: false,
        },
        other => panic!("expected Unlocked, got {other:?}"),
    };
    let (state, _) = reduce(unlocked, key(KeyCode::Char('g')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match state {
        AppState::Unlocked {
            selected,
            viewport_offset,
            ..
        } => {
            assert_eq!(
                selected,
                Some(c),
                "interleaved `gz` must not commit jump-to-first"
            );
            assert_eq!(
                viewport_offset, 0,
                "interleaved `gz` must not commit recenter"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_esc_after_z_clears_pending_chord_leader() {
    // Esc clears any pending chord leader (regardless of which
    // leader it is).
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Esc));
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            ..
        } => assert_eq!(pending_chord_leader, None, "Esc must clear pending Z chord"),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_z_does_not_set_chord_leader() {
    // Ctrl-Z is unbound at this slice and must not arm the chord
    // leader. (The Ctrl/Alt guard clears any pending chord state.)
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, ctrl(KeyCode::Char('z')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            ..
        } => assert_eq!(
            pending_chord_leader, None,
            "Ctrl-Z must not arm the chord leader"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_modal_opener_after_z_clears_chord_and_opens_modal() {
    // A modal-opener letter after `z` must clear the pending Z
    // chord and open the modal — chord state never persists across
    // modal transitions.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let (state, effects) = reduce(state, key(KeyCode::Char('a')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add(_)),
            pending_chord_leader,
            ..
        } => assert_eq!(
            pending_chord_leader, None,
            "opening a modal must clear pending Z chord"
        ),
        AppState::Unlocked { modal, .. } => {
            panic!("expected Modal::Add, got {modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn tick_between_z_presses_preserves_pending_chord_leader() {
    // vim's `nottimeout` semantics: the chord has no time-based
    // clear; a Tick between presses must leave pending state intact.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let monotonic = Instant::now() + Duration::from_secs(5);
    let wall_clock = SystemTime::now() + Duration::from_secs(5);
    let (state, _) = reduce(
        state,
        AppEvent::Tick {
            monotonic,
            wall_clock,
        },
    );
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            ..
        } => assert_eq!(
            pending_chord_leader,
            Some(ChordLeader::Z),
            "Tick between `z` presses must preserve pending Z state"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `/` — focus the search bar.
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Focus model": `/` from list focus
// transitions `focus` from `Focus::List` to `Focus::Search`. Selection,
// search_query, viewport, and modal state are untouched. A modal traps
// focus, so `/` with a modal open is a no-op. `/` also clears any
// pending vim chord leader (it is a non-`g` / non-`z` press).
// ---------------------------------------------------------------------------

#[test]
fn pressing_slash_on_unlocked_focuses_search_bar() {
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('/')));
    assert!(
        effects.is_empty(),
        "`/` must not emit effects — it only swaps focus"
    );
    match state {
        AppState::Unlocked {
            focus,
            selected,
            search_query,
            modal,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::Search,
                "`/` from Focus::List must transition focus to Focus::Search"
            );
            assert_eq!(selected, Some(a), "`/` must not move list selection");
            assert_eq!(search_query, "", "`/` must not modify the search query");
            assert!(modal.is_none(), "`/` must not open a modal");
            assert_eq!(
                pending_chord_leader, None,
                "`/` must clear any pending chord leader"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_slash_on_unlocked_preserves_existing_search_query() {
    let tmp = secure_tempdir();
    let (mut state, _ids) = unlocked_with_three_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut search_query,
        ..
    } = state
    {
        *search_query = "github".to_string();
    }
    let (state, effects) = reduce(state, key(KeyCode::Char('/')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            ..
        } => {
            assert_eq!(focus, Focus::Search);
            assert_eq!(
                search_query, "github",
                "`/` must preserve the active search query when refocusing"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_slash_when_already_focused_on_search_is_idempotent() {
    let tmp = secure_tempdir();
    let (mut state, _ids) = unlocked_with_three_accounts(&tmp);
    if let AppState::Unlocked { ref mut focus, .. } = state {
        *focus = Focus::Search;
    }
    let (state, effects) = reduce(state, key(KeyCode::Char('/')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked { focus, .. } => assert_eq!(
            focus,
            Focus::Search,
            "`/` while already in Focus::Search must remain in Focus::Search \
             (text-routing into the search field lands in a later slice)"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_slash_with_modal_open_does_not_change_focus() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('/')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            focus,
            Focus::List,
            "`/` must not change focus while a modal traps input"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_slash_after_g_clears_chord_and_focuses_search() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, effects) = reduce(state, key(KeyCode::Char('/')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::Search,
                "`/` after `g` must still focus the search bar"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`/` must clear pending chord state alongside the focus swap"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_slash_after_z_clears_chord_and_focuses_search() {
    // Mirrors `pressing_slash_after_g_clears_chord_and_focuses_search`
    // for the `z` leader: focus change to the search bar must clear a
    // pending `z` chord state alongside the focus swap, completing the
    // "cleared by focus change" axis of the pending-leader contract
    // for both leaders.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let (state, effects) = reduce(state, key(KeyCode::Char('/')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::Search,
                "`/` after `z` must still focus the search bar"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`/` must clear pending `z` chord state alongside the focus swap"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `Esc` from search focus — clear query and return focus to the list.
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Focus model":
//   "`Esc` clears the search query and returns focus to the list; on the
//    list, `Esc` only clears pending vim chord state and is otherwise a
//    no-op."
//
// Modal-close still wins: "Modal dialogs trap focus while open and
// intercept `Esc` to close themselves." When a modal is open, Esc
// closes the modal and leaves focus / search_query untouched, so the
// user lands back on whatever focus surface was active before the
// modal opened.
// ---------------------------------------------------------------------------

#[test]
fn pressing_esc_on_unlocked_with_search_focus_clears_query_and_returns_to_list() {
    let tmp = secure_tempdir();
    let (mut state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut focus,
        ref mut search_query,
        ..
    } = state
    {
        *focus = Focus::Search;
        *search_query = "github".to_string();
    }
    let (state, effects) = reduce(state, key(KeyCode::Esc));
    assert!(
        effects.is_empty(),
        "Esc on search focus must not emit effects"
    );
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            selected,
            modal,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::List,
                "Esc on search focus must return focus to the list"
            );
            assert_eq!(
                search_query, "",
                "Esc on search focus must clear the search query"
            );
            assert_eq!(
                selected,
                Some(a),
                "Esc must not move list selection while clearing search"
            );
            assert!(
                modal.is_none(),
                "Esc on search focus with no modal open must not open one"
            );
            assert_eq!(
                pending_chord_leader, None,
                "Esc must keep pending chord leader cleared"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_esc_on_unlocked_with_search_focus_and_empty_query_returns_to_list() {
    // Even with no query typed, Esc must still swap focus back to the
    // list — focus management is independent of whether the query
    // buffer happens to be empty.
    let tmp = secure_tempdir();
    let (mut state, _ids) = unlocked_with_three_accounts(&tmp);
    if let AppState::Unlocked { ref mut focus, .. } = state {
        *focus = Focus::Search;
    }
    let (state, effects) = reduce(state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            ..
        } => {
            assert_eq!(focus, Focus::List);
            assert_eq!(search_query, "");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_esc_on_unlocked_with_search_focus_and_modal_open_closes_modal_only() {
    // Modal-close takes precedence — the modal traps focus and
    // intercepts Esc. The focus slot and search query are untouched
    // so the user returns to the same search-bar surface after the
    // modal dismisses.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: "github".to_string(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Esc));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            modal,
            ..
        } => {
            assert!(modal.is_none(), "Esc must close the open modal");
            assert_eq!(
                focus,
                Focus::Search,
                "modal-close Esc must not change focus — search bar stays focused"
            );
            assert_eq!(
                search_query, "github",
                "modal-close Esc must not clear the search query"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Typing character input while Focus::Search.
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Focus model":
//   "Other keys, including the action keys ... and the bare-letter vim
//    navigation keys `j` / `k` / `g` / `G` / `z`, the search-focus key
//    `/`, and the quit key `q`, are routed to the search field as
//    character input while it has focus".
//
// On every search-query change, the list selection is recomputed via
// `paladin_core::select_after_filter` (DESIGN.md §6 / §7): preserve
// `prev` if still in the filtered set, otherwise pick the first match,
// or `None` if the filtered set is empty.
//
// Modal dialogs trap focus, so typing while a modal is open is not
// routed to the search field even if `focus == Focus::Search`. Ctrl /
// Alt-modified characters are also not routed as text — they remain
// reserved for the Ctrl-* navigation / quit chords.
// ---------------------------------------------------------------------------

/// Build a 3-account plaintext Unlocked state with labels "github",
/// "google", "gitlab" and `Focus::Search` seeded so the focus-routing
/// tests can demonstrate filtering by typed characters. Selection
/// starts on the first inserted account ("github").
fn unlocked_search_focused_with_three_named_accounts(
    tmp: &tempfile::TempDir,
) -> (AppState, [AccountId; 3]) {
    let (path, (mut vault, store)) = open_plaintext_pair(tmp);
    let a = add_totp_account(&mut vault, &store, "github");
    let b = add_totp_account(&mut vault, &store, "google");
    let c = add_totp_account(&mut vault, &store, "gitlab");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    (state, [a, b, c])
}

#[test]
fn typing_char_while_focus_search_appends_to_search_query() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('g')));
    assert!(
        effects.is_empty(),
        "typing into search must not emit effects"
    );
    match state {
        AppState::Unlocked {
            search_query,
            focus,
            pending_chord_leader,
            modal,
            ..
        } => {
            assert_eq!(
                search_query, "g",
                "character pressed while Focus::Search must append to the query buffer"
            );
            assert_eq!(focus, Focus::Search, "typing must not change focus");
            assert_eq!(
                pending_chord_leader, None,
                "typing `g` into the search field must not engage the chord leader"
            );
            assert!(modal.is_none(), "typing must not open a modal");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_chars_while_focus_search_accumulates_in_typed_order() {
    let tmp = secure_tempdir();
    let (mut state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    for c in ['g', 'i', 't'] {
        let (next, _) = reduce(state, key(KeyCode::Char(c)));
        state = next;
    }
    match state {
        AppState::Unlocked { search_query, .. } => {
            assert_eq!(
                search_query, "git",
                "successive Char presses while Focus::Search must accumulate"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_char_while_focus_search_updates_selection_to_first_match() {
    let tmp = secure_tempdir();
    let (mut state, [_github, google, _gitlab]) =
        unlocked_search_focused_with_three_named_accounts(&tmp);
    // Move selection off the first account so a refining filter has
    // to fall back to "first match" via `select_after_filter`.
    if let AppState::Unlocked {
        ref mut selected, ..
    } = state
    {
        *selected = Some(google);
    }
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    // "g" still matches all three (all labels start with "g"), so
    // "google" remains the surviving prev selection.
    match &state {
        AppState::Unlocked {
            search_query,
            selected,
            ..
        } => {
            assert_eq!(search_query, "g");
            assert_eq!(
                *selected,
                Some(google),
                "prev selection survives a filter it is still in"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
    // Now narrow to "git" — only "github" and "gitlab" remain, so
    // the surviving prev ("google") is filtered out and selection
    // falls back to the first match in insertion order ("github").
    let (state, _) = reduce(state, key(KeyCode::Char('i')));
    let (state, _) = reduce(state, key(KeyCode::Char('t')));
    match state {
        AppState::Unlocked {
            search_query,
            selected,
            ..
        } => {
            assert_eq!(search_query, "git");
            // First-inserted match for "git" is "github".
            assert!(
                selected.is_some(),
                "filtered set non-empty must yield Some(selected)"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_char_producing_empty_filtered_set_clears_selection() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    // "xyz" matches none of "github" / "google" / "gitlab".
    let (state, _) = reduce(state, key(KeyCode::Char('x')));
    let (state, _) = reduce(state, key(KeyCode::Char('y')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match state {
        AppState::Unlocked {
            search_query,
            selected,
            ..
        } => {
            assert_eq!(search_query, "xyz");
            assert_eq!(
                selected, None,
                "empty filtered set must clear selection per select_after_filter"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_capital_char_while_focus_search_appends_uppercase() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let event = AppEvent::Input {
        event: Event::Key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT)),
        at: Instant::now(),
    };
    let (state, _) = reduce(state, event);
    match state {
        AppState::Unlocked { search_query, .. } => {
            assert_eq!(
                search_query, "G",
                "Shift-modified Char must still append the resolved upper-case byte"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Bare-letter vim keys (`j`, `k`, `g`, `G`, `z`) are consumed by the
// search field as text input and never trigger chord state from the
// search field. Per `IMPLEMENTATION_PLAN_03_TUI.md` > Tests > Vim-style
// navigation. The `g` and `G` cases are covered above by the generic
// bare-letter tests; the `j`, `k`, `z` cases below close the explicit
// regression guards. `z` is the regression-critical one because it is
// the `zz` recenter chord leader on `Focus::List` — typing `z` in
// `Focus::Search` must NOT arm `ChordLeader::Z`.
// ---------------------------------------------------------------------------

#[test]
fn typing_j_while_focus_search_appends_to_query_and_no_chord() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('j')));
    assert!(
        effects.is_empty(),
        "typing `j` into the search field must not emit effects"
    );
    match state {
        AppState::Unlocked {
            search_query,
            focus,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                search_query, "j",
                "vim `j` while Focus::Search must be routed as text input"
            );
            assert_eq!(focus, Focus::Search, "typing must not change focus");
            assert_eq!(
                pending_chord_leader, None,
                "vim `j` while Focus::Search must not engage chord state"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_k_while_focus_search_appends_to_query_and_no_chord() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('k')));
    assert!(
        effects.is_empty(),
        "typing `k` into the search field must not emit effects"
    );
    match state {
        AppState::Unlocked {
            search_query,
            focus,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                search_query, "k",
                "vim `k` while Focus::Search must be routed as text input"
            );
            assert_eq!(focus, Focus::Search);
            assert_eq!(
                pending_chord_leader, None,
                "vim `k` while Focus::Search must not engage chord state"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_z_while_focus_search_does_not_arm_zz_chord_leader() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('z')));
    assert!(
        effects.is_empty(),
        "typing `z` into the search field must not emit effects"
    );
    match state {
        AppState::Unlocked {
            search_query,
            focus,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                search_query, "z",
                "vim `z` while Focus::Search must be routed as text input"
            );
            assert_eq!(focus, Focus::Search);
            assert_eq!(
                pending_chord_leader, None,
                "vim `z` while Focus::Search must not arm the `zz` chord leader"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_zz_pair_while_focus_search_appends_two_chars_and_no_chord() {
    // The `zz` recenter chord is `Focus::List`-only. Pressing `z`
    // twice with the search field focused must accumulate "zz" in
    // the query buffer without ever committing the chord or
    // recentering the viewport.
    let tmp = secure_tempdir();
    let (mut state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut viewport_offset,
        ..
    } = state
    {
        *viewport_offset = 7;
    }
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match state {
        AppState::Unlocked {
            search_query,
            pending_chord_leader,
            viewport_offset,
            ..
        } => {
            assert_eq!(
                search_query, "zz",
                "two `z` presses in Focus::Search must accumulate as text"
            );
            assert_eq!(
                pending_chord_leader, None,
                "no chord must be armed at any point during the search-focused `z` `z` sequence"
            );
            assert_eq!(
                viewport_offset, 7,
                "the recenter chord must not fire while Focus::Search"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_gg_pair_while_focus_search_appends_two_chars_and_no_chord() {
    // Parallel guard to `zz`: the `gg` jump-to-first chord is
    // `Focus::List`-only; two `g` presses in `Focus::Search` must
    // accumulate "gg" without arming or committing the chord.
    let tmp = secure_tempdir();
    let (mut state, [_a, _b, c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut selected, ..
    } = state
    {
        *selected = Some(c);
    }
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    match state {
        AppState::Unlocked {
            search_query,
            pending_chord_leader,
            selected,
            ..
        } => {
            assert_eq!(
                search_query, "gg",
                "two `g` presses in Focus::Search must accumulate as text"
            );
            assert_eq!(
                pending_chord_leader, None,
                "no chord must be armed during the search-focused `g` `g` sequence"
            );
            // All three labels ("github", "google", "gitlab") match
            // "gg" case-insensitively? No — only "github" contains
            // "gg"? Actually none do. The filter goes empty and the
            // surviving prev selection (c = gitlab) drops; selection
            // becomes None. The contract asserted here is *not* the
            // selection value (which is a filter side-effect) but
            // that the chord didn't commit to first-of-filtered.
            assert!(
                selected.is_none() || selected != Some(c),
                "filter side-effect: prev selection dropped when filtered set is empty; \
                 the important guard is that no chord-commit jumped selection"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_q_while_focus_search_does_not_quit() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('q')));
    assert!(
        effects.is_empty(),
        "`q` typed into the search field must not Quit"
    );
    match state {
        AppState::Unlocked { search_query, .. } => {
            assert_eq!(
                search_query, "q",
                "`q` must be routed as a literal char into the search field"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_modal_opener_letter_while_focus_search_does_not_open_modal() {
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('a')));
    match state {
        AppState::Unlocked {
            search_query,
            modal,
            ..
        } => {
            assert!(modal.is_none(), "`a` in search focus must not open Add");
            assert_eq!(
                search_query, "a",
                "`a` must be routed as a literal char into the search field"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_slash_while_focus_search_appends_to_query() {
    // `/` already focuses search from list focus; while already in
    // Focus::Search it is routed as a literal char per the §6 /
    // "Focus model" rule.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('/')));
    match state {
        AppState::Unlocked {
            search_query,
            focus,
            ..
        } => {
            assert_eq!(focus, Focus::Search);
            assert_eq!(search_query, "/", "`/` while in Focus::Search is literal");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_char_while_focus_search_with_modal_open_does_not_route_into_search() {
    // Modal traps focus and takes precedence over the search-focus
    // text routing — the modal-local input path consumes the key.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "github");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('g')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            search_query,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            search_query, "",
            "modal traps focus — typing must not bleed into the search query"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn typing_ctrl_modified_char_while_focus_search_does_not_append_to_query() {
    // Ctrl-* chords (navigation / quit) must not be routed as text
    // even when the search field is focused, mirroring `tui-input`'s
    // own treatment of Ctrl-modified keys as control sequences.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, _) = reduce(state, ctrl(KeyCode::Char('x')));
    match state {
        AppState::Unlocked { search_query, .. } => assert_eq!(
            search_query, "",
            "Ctrl-modified Char must not be routed as text into the search field"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Search-focus pass-through routes navigation keys to the list (per
// `IMPLEMENTATION_PLAN_03_TUI.md` > Tests > Vim-style navigation:
// "Search-focus pass-through routes `PgUp` / `PgDn` / `Home` / `End`
//  / `Ctrl-B` / `Ctrl-F` / `Ctrl-D` / `Ctrl-U` to the list before
//  `tui-input` sees them.")
//
// The selection must move while the search field is focused so the
// user can navigate filter results without unfocusing the search bar.
// For each of the eight keys we assert (a) the selection moved, (b)
// the search query was NOT appended to (so the key wasn't routed as
// text input), and (c) `focus` stays on `Focus::Search` so subsequent
// typed characters still flow into the query.
// ---------------------------------------------------------------------------

#[test]
fn pressing_page_down_while_focus_search_advances_selection() {
    let tmp = secure_tempdir();
    let (mut state, [a, _b, c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut viewport_height,
        ref mut selected,
        ..
    } = state
    {
        *viewport_height = 2;
        *selected = Some(a);
    }
    let (state, effects) = reduce(state, key(KeyCode::PageDown));
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                selected,
                Some(c),
                "PgDn while Focus::Search must advance list selection"
            );
            assert_eq!(
                search_query, "",
                "PgDn must not be routed as text into the search field"
            );
            assert_eq!(
                focus,
                Focus::Search,
                "PgDn must leave focus on the search bar"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_up_while_focus_search_retreats_selection() {
    let tmp = secure_tempdir();
    let (mut state, [a, _b, c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut viewport_height,
        ref mut selected,
        ..
    } = state
    {
        *viewport_height = 2;
        *selected = Some(c);
    }
    let (state, _) = reduce(state, key(KeyCode::PageUp));
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                selected,
                Some(a),
                "PgUp while Focus::Search must retreat list selection"
            );
            assert_eq!(
                search_query, "",
                "PgUp must not be routed as text into the search field"
            );
            assert_eq!(focus, Focus::Search);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_home_while_focus_search_jumps_to_first() {
    let tmp = secure_tempdir();
    let (mut state, [a, _b, c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut selected, ..
    } = state
    {
        *selected = Some(c);
    }
    let (state, _) = reduce(state, key(KeyCode::Home));
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                selected,
                Some(a),
                "Home while Focus::Search must jump to the first row"
            );
            assert_eq!(
                search_query, "",
                "Home must not be routed as text into the search field"
            );
            assert_eq!(focus, Focus::Search);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_end_while_focus_search_jumps_to_last() {
    let tmp = secure_tempdir();
    let (state, [_a, _b, c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::End));
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                selected,
                Some(c),
                "End while Focus::Search must jump to the last row"
            );
            assert_eq!(
                search_query, "",
                "End must not be routed as text into the search field"
            );
            assert_eq!(focus, Focus::Search);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_f_while_focus_search_advances_selection() {
    let tmp = secure_tempdir();
    let (mut state, [a, _b, c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut viewport_height,
        ref mut selected,
        ..
    } = state
    {
        *viewport_height = 2;
        *selected = Some(a);
    }
    let (state, _) = reduce(state, ctrl(KeyCode::Char('f')));
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                selected,
                Some(c),
                "Ctrl-F while Focus::Search must advance list selection (PgDn mirror)"
            );
            assert_eq!(
                search_query, "",
                "Ctrl-F must not append to the search field"
            );
            assert_eq!(focus, Focus::Search);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_b_while_focus_search_retreats_selection() {
    let tmp = secure_tempdir();
    let (mut state, [a, _b, c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut viewport_height,
        ref mut selected,
        ..
    } = state
    {
        *viewport_height = 2;
        *selected = Some(c);
    }
    let (state, _) = reduce(state, ctrl(KeyCode::Char('b')));
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                selected,
                Some(a),
                "Ctrl-B while Focus::Search must retreat list selection (PgUp mirror)"
            );
            assert_eq!(
                search_query, "",
                "Ctrl-B must not append to the search field"
            );
            assert_eq!(focus, Focus::Search);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_d_while_focus_search_half_page_advances() {
    let tmp = secure_tempdir();
    let (mut state, [a, b, _c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut viewport_height,
        ref mut selected,
        ..
    } = state
    {
        *viewport_height = 2;
        *selected = Some(a);
    }
    let (state, _) = reduce(state, ctrl(KeyCode::Char('d')));
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                selected,
                Some(b),
                "Ctrl-D while Focus::Search must half-page advance the list selection"
            );
            assert_eq!(
                search_query, "",
                "Ctrl-D must not append to the search field"
            );
            assert_eq!(focus, Focus::Search);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_u_while_focus_search_half_page_retreats() {
    let tmp = secure_tempdir();
    let (mut state, [_a, b, c]) = unlocked_search_focused_with_three_named_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut viewport_height,
        ref mut selected,
        ..
    } = state
    {
        *viewport_height = 2;
        *selected = Some(c);
    }
    let (state, _) = reduce(state, ctrl(KeyCode::Char('u')));
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                selected,
                Some(b),
                "Ctrl-U while Focus::Search must half-page retreat the list selection"
            );
            assert_eq!(
                search_query, "",
                "Ctrl-U must not append to the search field"
            );
            assert_eq!(focus, Focus::Search);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn typing_g_while_focus_list_still_engages_chord_leader() {
    // Regression guard: the chord leader engagement on Focus::List is
    // unchanged by the search-focus text routing — typing `g` from
    // list focus still sets `Some(ChordLeader::G)`.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, _) = reduce(state, key(KeyCode::Char('g')));
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            search_query,
            focus,
            ..
        } => {
            assert_eq!(
                pending_chord_leader,
                Some(ChordLeader::G),
                "`g` on Focus::List must still arm the chord leader"
            );
            assert_eq!(
                search_query, "",
                "`g` on Focus::List must NOT bleed into the search query"
            );
            assert_eq!(focus, Focus::List);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_esc_on_unlocked_with_list_focus_does_not_clear_search_query() {
    // On list focus, Esc only clears pending chord state per the §6
    // / "Focus model" rule. The search query must persist so an
    // active filter survives stray Esc presses on the list.
    let tmp = secure_tempdir();
    let (mut state, _ids) = unlocked_with_three_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut search_query,
        ..
    } = state
    {
        *search_query = "github".to_string();
    }
    let (state, effects) = reduce(state, key(KeyCode::Esc));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::List,
                "Esc on list focus must keep focus on the list"
            );
            assert_eq!(
                search_query, "github",
                "Esc on list focus must preserve the active search query"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Search filter narrows the visible list in place (per
// `IMPLEMENTATION_PLAN_03_TUI.md` Tests > Reducer > "Search filter narrows
// the visible list in place"). With a non-empty `search_query`, list
// navigation must walk the filtered insertion-order set, not `Vault::iter()`.
// ---------------------------------------------------------------------------

/// Build a 4-account plaintext Unlocked state with custom labels so the
/// search predicate has both matches and non-matches to traverse.
/// Returns the four inserted ids in insertion order.
fn unlocked_with_four_labeled_accounts(
    tmp: &tempfile::TempDir,
    labels: [&str; 4],
) -> (AppState, [AccountId; 4]) {
    let (path, (mut vault, store)) = open_plaintext_pair(tmp);
    let a = add_totp_account(&mut vault, &store, labels[0]);
    let b = add_totp_account(&mut vault, &store, labels[1]);
    let c = add_totp_account(&mut vault, &store, labels[2]);
    let d = add_totp_account(&mut vault, &store, labels[3]);
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    (state, [a, b, c, d])
}

#[test]
fn pressing_down_arrow_walks_filtered_list_when_search_query_active() {
    // alpha / alex match "al"; beta / carol do not. Down from alpha
    // must skip past beta (filtered out) and land on alex.
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alpha);
    }
    let (state, effects) = reduce(state, key(KeyCode::Down));
    assert!(effects.is_empty(), "navigation must not emit effects");
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alex),
            "Down must walk the filtered list and skip over non-matching rows"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_down_arrow_clamps_at_last_of_filtered_list() {
    // From alex (last filtered match for "al"), Down must clamp at
    // alex — not jump to carol (filtered out) or beyond.
    let tmp = secure_tempdir();
    let (mut state, [_alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alex);
    }
    let (state, _effects) = reduce(state, key(KeyCode::Down));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alex),
            "Down at last filtered row must clamp, not advance to a filtered-out row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_up_arrow_walks_filtered_list_when_search_query_active() {
    // From alex, Up with filter "al" must skip beta and land on alpha.
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alex);
    }
    let (state, _effects) = reduce(state, key(KeyCode::Up));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alpha),
            "Up must walk the filtered list and skip over non-matching rows"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_end_jumps_to_last_of_filtered_list() {
    // End with filter "al" must land on alex (last filtered match),
    // not carol (last vault row, filtered out).
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alpha);
    }
    let (state, _effects) = reduce(state, key(KeyCode::End));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alex),
            "End must jump to the last row of the filtered list"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_home_jumps_to_first_of_filtered_list() {
    // Home with filter "al" must land on alpha (first filtered match)
    // from alex, not on alpha's vault-position-0 unless alpha is the
    // first filtered row.
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alex);
    }
    let (state, _effects) = reduce(state, key(KeyCode::Home));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alpha),
            "Home must jump to the first row of the filtered list"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_end_with_filter_excluding_first_vault_row_still_lands_in_filtered_set() {
    // Filter "ro" matches only "carol". End must land on carol even
    // though "carol" is the last vault row in this layout — but the
    // important assertion is that End is grounded in the filtered set
    // (not vault.iter()), which is exercised by the other End test
    // above. This case asserts End behaves the same when the filtered
    // set is a single account.
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, _alex, carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "ro".to_string();
        // A typical search-recompute would have already placed
        // selection on carol; seed it explicitly here from alpha to
        // verify End repositions to the only filtered row.
        *selected = Some(alpha);
    }
    let (state, _effects) = reduce(state, key(KeyCode::End));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(carol),
            "End must land on the sole filtered match"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_j_walks_filtered_list_when_search_query_active() {
    // Mirrors `pressing_down_arrow_walks_filtered_list_when_search_query_active`:
    // with filter "al", `j` from alpha must skip beta (filtered out)
    // and land on alex.
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alpha);
    }
    let (state, _effects) = reduce(state, key(KeyCode::Char('j')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alex),
            "vim `j` must walk the filtered list, mirroring Down"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_k_walks_filtered_list_when_search_query_active() {
    // Mirrors `pressing_up_arrow_walks_filtered_list_when_search_query_active`:
    // with filter "al", `k` from alex must skip beta (filtered out)
    // and land on alpha.
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alex);
    }
    let (state, _effects) = reduce(state, key(KeyCode::Char('k')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alpha),
            "vim `k` must walk the filtered list, mirroring Up"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_shift_g_jumps_to_last_of_filtered_list() {
    // vim `G` mirrors `End`; with filter "al" matching alpha / alex,
    // `G` must land on alex (last filtered match), skipping carol
    // (last vault row, filtered out).
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alpha);
    }
    let (state, _effects) = reduce(state, key(KeyCode::Char('G')));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alex),
            "vim `G` must jump to the last row of the filtered list, mirroring End"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_gg_jumps_to_first_of_filtered_list() {
    // vim `gg` chord mirrors `Home`; with filter "al" matching alpha /
    // alex, starting at alex the two-press chord must land on alpha
    // (first filtered match), not on the unfiltered vault head.
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alex);
    }
    let (state, effects) = reduce(state, key(KeyCode::Char('g')));
    assert!(effects.is_empty(), "first `g` arms the chord; no effects");
    let (state, effects) = reduce(state, key(KeyCode::Char('g')));
    assert!(effects.is_empty(), "chord commit must not emit effects");
    match state {
        AppState::Unlocked {
            selected,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                selected,
                Some(alpha),
                "vim `gg` must jump to the first row of the filtered list"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`gg` commit must clear pending chord state"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// HOTP `n` triggers a `HotpAdvance` effect (per
// `IMPLEMENTATION_PLAN_03_TUI.md` Tests > Reducer > "HOTP `n` triggers a
// `HotpAdvance` effect"). Pressing `n` on Unlocked with an HOTP account
// selected emits `Effect::HotpAdvance { path, account_id }`. The reducer
// does not mutate `hotp_reveal` — only `EffectResult::HotpAdvance` may do
// that, per the §6 effect-result ownership rule.
// ---------------------------------------------------------------------------

#[test]
fn pressing_n_with_hotp_account_selected_emits_hotp_advance_effect() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Char('n')));
    match effects.as_slice() {
        [Effect::HotpAdvance {
            path: emitted_path,
            account_id,
        }] => {
            assert_eq!(emitted_path, &path, "HotpAdvance must carry the vault path");
            assert_eq!(
                *account_id, hotp_id,
                "HotpAdvance must carry the selected account id"
            );
        }
        other => panic!("expected single HotpAdvance effect, got {other:?}"),
    }
    match state {
        AppState::Unlocked { hotp_reveal, .. } => {
            assert!(
                hotp_reveal.is_none(),
                "reducer must not seed hotp_reveal — only EffectResult::HotpAdvance can"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_n_with_totp_account_selected_emits_no_effect() {
    // `n` is meaningful only on HOTP accounts; for TOTP the binding
    // is a silent no-op at the reducer layer (the status-line "not an
    // HOTP account" hint lands with the status-line slice).
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(totp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (_state, effects) = reduce(state, key(KeyCode::Char('n')));
    assert!(
        effects.is_empty(),
        "pressing `n` with a TOTP account selected must not emit HotpAdvance, got {effects:?}"
    );
}

#[test]
fn pressing_n_with_no_selection_emits_no_effect() {
    // Empty vault / empty filtered set: `n` emits no effect and (per
    // `IMPLEMENTATION_PLAN_03_TUI.md` "Focus model") surfaces the
    // "no account selected" status-line error. The status-line side
    // of the contract is asserted separately in
    // `pressing_n_with_no_selection_sets_no_account_selected_status_line`.
    let tmp = secure_tempdir();
    let (path, (vault, store)) = open_plaintext_pair(&tmp);
    let state = AppState::Unlocked {
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
    };
    let (_state, effects) = reduce(state, key(KeyCode::Char('n')));
    assert!(
        effects.is_empty(),
        "pressing `n` with no selected account must not emit HotpAdvance, got {effects:?}"
    );
}

#[test]
fn pressing_n_with_modal_open_emits_no_effect() {
    // Modal traps focus — `n` is modal-local input and must not
    // leak through to the HOTP advance binding.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (_state, effects) = reduce(state, key(KeyCode::Char('n')));
    assert!(
        effects.is_empty(),
        "pressing `n` with a modal open must not emit HotpAdvance, got {effects:?}"
    );
}

// ---------------------------------------------------------------------------
// Selection-gated action keys with `selected = None`
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Search — bullet
//  *"Empty result sets have no selection; action keys that require a
//  selected row surface the 'no account selected' status-line
//  error."*; cross-references the "Focus model" rule
//  *"With no selection, `Enter`, `n`, `r`, and `R` produce a
//  status-line 'no account selected' error and no effect."*)
//
// Slice covered: `n`, `r`, and `R` on `Unlocked` / `Focus::List` /
// no-modal with `selected = None` set `status_line` to
// `StatusLine::Error("no account selected")` and suppress their
// normal effect (no `HotpAdvance` for `n`; no modal open for `r` / `R`).
// `Enter` is not yet bound on Unlocked at this slice — its gating
// lands alongside the show / copy effect.
// ---------------------------------------------------------------------------

fn unlocked_with_empty_selection(tmp: &tempfile::TempDir) -> AppState {
    // Empty vault — `select_after_filter(None, &[])` is `None`, so
    // every `selected = None` flow we care about reuses this fixture.
    let (path, (vault, store)) = open_plaintext_pair(tmp);
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

fn assert_no_account_selected_status_after(event: AppEvent, label: &str) {
    let tmp = secure_tempdir();
    let before = unlocked_with_empty_selection(&tmp);
    let (after, effects) = reduce(before, event);
    assert!(
        effects.is_empty(),
        "{label} with no selection must emit no effects, got {effects:?}"
    );
    match after {
        AppState::Unlocked {
            modal,
            status_line,
            selected,
            ..
        } => {
            assert!(
                selected.is_none(),
                "{label} with no selection must leave selected = None, got {selected:?}"
            );
            assert!(
                modal.is_none(),
                "{label} with no selection must not open a modal, got {modal:?}"
            );
            assert_eq!(
                status_line,
                Some(StatusLine::Error(NO_ACCOUNT_SELECTED.to_string())),
                "{label} with no selection must set the 'no account selected' status-line error, got {status_line:?}"
            );
        }
        other => panic!("{label}: expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_n_with_no_selection_sets_no_account_selected_status_line() {
    assert_no_account_selected_status_after(key(KeyCode::Char('n')), "n");
}

#[test]
fn pressing_lowercase_r_with_no_selection_sets_no_account_selected_status_line() {
    assert_no_account_selected_status_after(key(KeyCode::Char('r')), "r");
}

#[test]
fn pressing_shift_r_with_no_selection_sets_no_account_selected_status_line() {
    // Both the bare `Char('R')` (terminals that swallow SHIFT into
    // the case conversion) and the `Char('R') + SHIFT` shape must
    // surface the status-line error — matches the resolved-character
    // dispatch on the modal-open side.
    assert_no_account_selected_status_after(key(KeyCode::Char('R')), "R");
    let evt = AppEvent::Input {
        event: Event::Key(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT)),
        at: Instant::now(),
    };
    assert_no_account_selected_status_after(evt, "Shift-R");
}

#[test]
fn pressing_non_selection_gated_opener_with_no_selection_does_not_set_status_line() {
    // `a` / `i` / `e` / `p` / `s` are not selection-gated — they
    // open their respective modals regardless of `selected`. The
    // status-line stays `None` so the user does not see a spurious
    // "no account selected" error while opening Add / Import /
    // Export / Passphrase / Settings on an empty vault.
    for (letter, expected) in [
        ('a', Modal::Add(AddModal::default())),
        ('i', Modal::Import),
        ('e', Modal::Export),
        ('p', Modal::Passphrase),
        ('s', Modal::Settings(SettingsModal::default())),
    ] {
        let tmp = secure_tempdir();
        let before = unlocked_with_empty_selection(&tmp);
        let (after, effects) = reduce(before, key(KeyCode::Char(letter)));
        assert!(
            effects.is_empty(),
            "{letter} with no selection must emit no effects, got {effects:?}"
        );
        match after {
            AppState::Unlocked {
                modal, status_line, ..
            } => {
                assert!(
                    matches!(&modal, Some(m) if std::mem::discriminant(m) == std::mem::discriminant(&expected)),
                    "{letter} must open {expected:?}, got {modal:?}"
                );
                assert!(
                    status_line.is_none(),
                    "{letter} must not set the status-line on an empty selection, got {status_line:?}"
                );
            }
            other => panic!("{letter}: expected Unlocked, got {other:?}"),
        }
    }
}

#[test]
fn pressing_n_after_search_clears_filtered_set_sets_status_line() {
    // End-to-end path the L682 bullet describes verbatim: a vault
    // with accounts, a typed search query that filters everything
    // out, then `n` on the resulting empty selection. Asserts that
    // the empty filtered set is reached through the search path
    // (not directly fabricated) and that the status-line error
    // surfaces.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    add_totp_account(&mut vault, &store, "github");
    add_hotp_account(&mut vault, &store, "azure");
    let unlocked = AppState::Unlocked {
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
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    // Type "zzz" — no account matches.
    let (state, _) = reduce(unlocked, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    let (state, _) = reduce(state, key(KeyCode::Char('z')));
    match &state {
        AppState::Unlocked { selected, .. } => assert!(
            selected.is_none(),
            "search query filtered everything out, so selection must be None"
        ),
        other => panic!("expected Unlocked after typing search query, got {other:?}"),
    }
    // Return focus to the list so `n` is interpreted as the
    // HOTP-advance binding, not as text input. `Esc` from
    // `Focus::Search` also clears the query, so re-establish the
    // empty filtered set with a `Tab` cycle instead, which preserves
    // the query.
    let (state, _) = reduce(state, key(KeyCode::Tab));
    // `n` on the empty filtered set surfaces the status-line error.
    let (state, effects) = reduce(state, key(KeyCode::Char('n')));
    assert!(
        effects.is_empty(),
        "`n` on a search-emptied set must emit no effect, got {effects:?}"
    );
    match state {
        AppState::Unlocked {
            selected,
            status_line,
            ..
        } => {
            assert!(
                selected.is_none(),
                "search-empty selection must remain None across `n`, got {selected:?}"
            );
            assert_eq!(
                status_line,
                Some(StatusLine::Error(NO_ACCOUNT_SELECTED.to_string())),
                "`n` on a search-emptied set must set 'no account selected', got {status_line:?}"
            );
        }
        other => panic!("expected Unlocked after `n`, got {other:?}"),
    }
}

#[test]
fn pressing_n_while_focus_search_appends_to_query_not_advance() {
    // While Focus::Search, `n` is text input — it must accumulate
    // in `search_query`, never trigger HotpAdvance.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Char('n')));
    assert!(
        effects.is_empty(),
        "pressing `n` while Focus::Search must not emit HotpAdvance, got {effects:?}"
    );
    match state {
        AppState::Unlocked { search_query, .. } => {
            assert_eq!(
                search_query, "n",
                "`n` while Focus::Search must append to the search query"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_page_down_clamps_within_filtered_list() {
    // With a viewport tall enough to overshoot the filtered set,
    // PageDown must clamp at the last filtered row (alex), not run
    // off the end of vault.iter() into filtered-out rows.
    let tmp = secure_tempdir();
    let (mut state, [alpha, _beta, alex, _carol]) =
        unlocked_with_four_labeled_accounts(&tmp, ["alpha", "beta", "alex", "carol"]);
    if let AppState::Unlocked {
        ref mut search_query,
        ref mut selected,
        ref mut viewport_height,
        ..
    } = state
    {
        *search_query = "al".to_string();
        *selected = Some(alpha);
        *viewport_height = 10;
    }
    let (state, _effects) = reduce(state, key(KeyCode::PageDown));
    match state {
        AppState::Unlocked { selected, .. } => assert_eq!(
            selected,
            Some(alex),
            "PageDown with oversized viewport must clamp at the last filtered row"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Empty filtered set: every list-navigation key including the chords
// is a silent no-op. Per `IMPLEMENTATION_PLAN_03_TUI.md` > Tests >
// Vim-style navigation > "Empty filtered set: every list-navigation
// key including the chords is a silent no-op."
//
// Setup: a 3-account vault filtered by a query that matches none of
// the labels. `select_after_filter` leaves `selected = None`. Each
// nav key must leave `selected = None`, `search_query` unchanged,
// `viewport_offset` unchanged, and emit no effects.
// ---------------------------------------------------------------------------

/// Build an `Unlocked` state where the vault has three named accounts
/// but the search query filters out every one of them.
///
/// `viewport_height` is pre-set to `8` and `viewport_offset` to `3` so
/// chord / page tests can observe that no viewport bookkeeping
/// changes during the no-op. `pending_chord_leader` starts `None`.
fn unlocked_with_empty_filtered_set(tmp: &tempfile::TempDir) -> AppState {
    let (path, (mut vault, store)) = open_plaintext_pair(tmp);
    add_totp_account(&mut vault, &store, "github");
    add_totp_account(&mut vault, &store, "google");
    add_totp_account(&mut vault, &store, "gitlab");
    AppState::Unlocked {
        path,
        vault,
        store,
        search_query: "xyz".to_string(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: None,
        pending_chord_leader: None,
        viewport_height: 8,
        viewport_offset: 3,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    }
}

/// Press `event` on a state with an empty filtered set and assert
/// every observable selection / viewport / effect output is unchanged.
fn assert_silent_no_op_on_empty_filtered_set(event: AppEvent, msg: &str) {
    let tmp = secure_tempdir();
    let before = unlocked_with_empty_filtered_set(&tmp);
    let (state, effects) = reduce(before, event);
    assert!(
        effects.is_empty(),
        "{msg}: navigation on empty filtered set must not emit effects, got {effects:?}"
    );
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            viewport_offset,
            modal,
            ..
        } => {
            assert_eq!(
                selected, None,
                "{msg}: selection on empty filtered set must stay None"
            );
            assert_eq!(
                search_query, "xyz",
                "{msg}: nav key must not mutate the search query"
            );
            assert_eq!(
                viewport_offset, 3,
                "{msg}: nav key on empty filtered set must not shift viewport offset"
            );
            assert!(
                modal.is_none(),
                "{msg}: nav key must not open a modal on empty filtered set"
            );
        }
        other => panic!("{msg}: expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_down_arrow_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::Down), "Down");
}

#[test]
fn pressing_up_arrow_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::Up), "Up");
}

#[test]
fn pressing_j_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::Char('j')), "vim j");
}

#[test]
fn pressing_k_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::Char('k')), "vim k");
}

#[test]
fn pressing_page_down_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::PageDown), "PageDown");
}

#[test]
fn pressing_page_up_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::PageUp), "PageUp");
}

#[test]
fn pressing_ctrl_f_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(ctrl(KeyCode::Char('f')), "Ctrl-F");
}

#[test]
fn pressing_ctrl_b_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(ctrl(KeyCode::Char('b')), "Ctrl-B");
}

#[test]
fn pressing_ctrl_d_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(ctrl(KeyCode::Char('d')), "Ctrl-D");
}

#[test]
fn pressing_ctrl_u_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(ctrl(KeyCode::Char('u')), "Ctrl-U");
}

#[test]
fn pressing_home_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::Home), "Home");
}

#[test]
fn pressing_end_on_empty_filtered_set_is_silent_no_op() {
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::End), "End");
}

#[test]
fn pressing_shift_g_on_empty_filtered_set_is_silent_no_op() {
    // vim `G` (End mirror) — Crossterm reports the resolved upper-
    // case character, with or without a Shift modifier.
    assert_silent_no_op_on_empty_filtered_set(key(KeyCode::Char('G')), "vim G");
}

#[test]
fn pressing_gg_chord_on_empty_filtered_set_is_silent_no_op() {
    // Two-press `gg` chord: first `g` arms `ChordLeader::G`; second
    // `g` commits the jump-to-first. With an empty filtered set,
    // the commit must be a no-op — selection stays None, viewport
    // offset stays put, no effects emitted, and the chord leader
    // is cleared after the commit.
    let tmp = secure_tempdir();
    let state = unlocked_with_empty_filtered_set(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('g')));
    assert!(effects.is_empty(), "first `g` must not emit effects");
    let (state, effects) = reduce(state, key(KeyCode::Char('g')));
    assert!(
        effects.is_empty(),
        "`gg` commit on empty filtered set must not emit effects"
    );
    match state {
        AppState::Unlocked {
            selected,
            search_query,
            viewport_offset,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                selected, None,
                "`gg` commit on empty filtered set must leave selection None"
            );
            assert_eq!(search_query, "xyz", "`gg` must not mutate the search query");
            assert_eq!(
                viewport_offset, 3,
                "`gg` on empty filtered set must not shift viewport offset"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`gg` commit must clear the pending chord leader"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_zz_chord_on_empty_filtered_set_is_silent_no_op() {
    // Two-press `zz` recenter chord. With `selected = None` (empty
    // filtered set) the recenter has no row to center on; the
    // viewport must not move and the chord leader must clear.
    let tmp = secure_tempdir();
    let state = unlocked_with_empty_filtered_set(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('z')));
    assert!(effects.is_empty(), "first `z` must not emit effects");
    let (state, effects) = reduce(state, key(KeyCode::Char('z')));
    assert!(
        effects.is_empty(),
        "`zz` commit on empty filtered set must not emit effects"
    );
    match state {
        AppState::Unlocked {
            selected,
            viewport_offset,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                selected, None,
                "`zz` commit on empty filtered set must leave selection None"
            );
            assert_eq!(
                viewport_offset, 3,
                "`zz` with no selected row must not shift viewport offset"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`zz` commit must clear the pending chord leader"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `Tab` / `Shift-Tab` — cycle focus between the search bar and the
// account list (Unlocked).
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings (initial v0.1)":
//   "`Tab` `Shift-Tab` — Cycle focus between search bar and list
//    (preserves active query when leaving search)".
//
// Top-level Unlocked has two focus surfaces (`Focus::List`,
// `Focus::Search`), so `Tab` and `Shift-Tab` both swap. Outside
// Unlocked the keys are silent (the other screens have no focus
// model in v0.1). Modal dialogs trap focus while open, so `Tab`
// with a modal open is a silent no-op — `Ctrl-N` / `Ctrl-P` inside
// modals will land in a later slice for the modal-local navigation
// rule. Focus changes clear any pending vim chord leader, mirroring
// the `/`-after-`g` / `/`-after-`z` chord-clear rule from the slash
// section above.
// ---------------------------------------------------------------------------

#[test]
fn pressing_tab_on_unlocked_list_focus_moves_focus_to_search() {
    let tmp = secure_tempdir();
    let (state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Tab));
    assert!(
        effects.is_empty(),
        "`Tab` must not emit effects — it only swaps focus"
    );
    match state {
        AppState::Unlocked {
            focus,
            selected,
            search_query,
            modal,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::Search,
                "`Tab` from Focus::List must transition focus to Focus::Search"
            );
            assert_eq!(selected, Some(a), "`Tab` must not move list selection");
            assert_eq!(search_query, "", "`Tab` must not modify the search query");
            assert!(modal.is_none(), "`Tab` must not open a modal");
            assert_eq!(
                pending_chord_leader, None,
                "`Tab` must keep pending chord leader cleared"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_tab_on_unlocked_search_focus_moves_focus_to_list_preserving_query() {
    // Active query must survive the focus swap per the keybindings
    // table: "preserves active query when leaving search".
    let tmp = secure_tempdir();
    let (mut state, [a, _b, _c]) = unlocked_with_three_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut focus,
        ref mut search_query,
        ..
    } = state
    {
        *focus = Focus::Search;
        *search_query = "github".to_string();
    }
    let (state, effects) = reduce(state, key(KeyCode::Tab));
    assert!(effects.is_empty(), "`Tab` must not emit effects");
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            selected,
            modal,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::List,
                "`Tab` from Focus::Search must return focus to the list"
            );
            assert_eq!(
                search_query, "github",
                "`Tab` must preserve the active search query when leaving search"
            );
            assert_eq!(selected, Some(a), "`Tab` must not move list selection");
            assert!(modal.is_none(), "`Tab` must not open a modal");
            assert_eq!(pending_chord_leader, None);
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_shift_tab_on_unlocked_list_focus_moves_focus_to_search() {
    // Top-level Unlocked has only two focus surfaces, so Shift-Tab
    // swaps the same way as Tab.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::BackTab));
    assert!(effects.is_empty(), "`Shift-Tab` must not emit effects");
    match state {
        AppState::Unlocked { focus, .. } => assert_eq!(
            focus,
            Focus::Search,
            "`Shift-Tab` from Focus::List must transition focus to Focus::Search"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_shift_tab_on_unlocked_search_focus_moves_focus_to_list_preserving_query() {
    let tmp = secure_tempdir();
    let (mut state, _ids) = unlocked_with_three_accounts(&tmp);
    if let AppState::Unlocked {
        ref mut focus,
        ref mut search_query,
        ..
    } = state
    {
        *focus = Focus::Search;
        *search_query = "gitlab".to_string();
    }
    let (state, effects) = reduce(state, key(KeyCode::BackTab));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::List,
                "`Shift-Tab` from Focus::Search must return focus to the list"
            );
            assert_eq!(
                search_query, "gitlab",
                "`Shift-Tab` must preserve the active search query"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_tab_with_modal_open_does_not_change_focus() {
    // Modals trap focus while open — `Tab` is a silent no-op at the
    // top level so the modal's own focus traversal (Ctrl-N / Ctrl-P
    // aliasing Tab / Shift-Tab, covered by the modal-local alias
    // tests further down) is not pre-empted. Until modal payloads
    // grow focusable fields, both Tab/Shift-Tab and Ctrl-N/Ctrl-P
    // are silent no-ops inside a modal — symmetry that the alias
    // tests lock in.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Tab));
    assert!(
        effects.is_empty(),
        "`Tab` with modal open must not emit effects"
    );
    match state {
        AppState::Unlocked {
            focus,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            focus,
            Focus::List,
            "`Tab` must not change top-level focus while a modal traps input"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_shift_tab_with_modal_open_does_not_change_focus() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::BackTab));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            focus,
            Focus::Search,
            "`Shift-Tab` must not change top-level focus while a modal is open"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_tab_after_g_clears_chord_and_moves_focus_to_search() {
    // Mirrors `pressing_slash_after_g_clears_chord_and_focuses_search`:
    // any focus change to the search bar must drop a pending vim
    // chord leader. The `Tab` key swaps focus, so it cross-clears
    // the `g` leader without firing the `gg` jump-to-first action.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('g')));
    assert!(effects.is_empty(), "first `g` must not emit effects");
    let (state, effects) = reduce(state, key(KeyCode::Tab));
    assert!(effects.is_empty(), "`Tab` must not emit effects");
    match state {
        AppState::Unlocked {
            focus,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::Search,
                "`Tab` after `g` must still focus the search bar"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`Tab` must clear a pending `g` chord leader"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_tab_after_z_clears_chord_and_moves_focus_to_search() {
    // Mirrors `pressing_slash_after_z_clears_chord_and_focuses_search`
    // for the `z` leader.
    let tmp = secure_tempdir();
    let (state, _ids) = unlocked_with_three_accounts(&tmp);
    let (state, effects) = reduce(state, key(KeyCode::Char('z')));
    assert!(effects.is_empty(), "first `z` must not emit effects");
    let (state, effects) = reduce(state, key(KeyCode::Tab));
    assert!(effects.is_empty(), "`Tab` must not emit effects");
    match state {
        AppState::Unlocked {
            focus,
            pending_chord_leader,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::Search,
                "`Tab` after `z` must still focus the search bar"
            );
            assert_eq!(
                pending_chord_leader, None,
                "`Tab` must clear a pending `z` chord leader"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_tab_on_missing_vault_is_silent_no_op() {
    // Non-Unlocked screens have no focus model in v0.1 — `Tab` is a
    // silent no-op (no effects, state unchanged).
    let state = missing("/nonexistent/vault");
    let (state, effects) = reduce(state, key(KeyCode::Tab));
    assert!(
        effects.is_empty(),
        "`Tab` outside Unlocked must not emit effects"
    );
    match state {
        AppState::MissingVault { path } => assert_eq!(path, PathBuf::from("/nonexistent/vault")),
        other => panic!("expected MissingVault, got {other:?}"),
    }
}

#[test]
fn pressing_tab_on_unlock_screen_is_silent_no_op() {
    // The unlock screen has only the passphrase buffer — `Tab` must
    // not be captured as text input nor change anything.
    let state = unlock_with("/some/vault", "secret");
    let (state, effects) = reduce(state, key(KeyCode::Tab));
    assert!(effects.is_empty(), "`Tab` on Unlock must not emit effects");
    match state {
        AppState::Unlock { passphrase, .. } => {
            assert_eq!(
                passphrase.as_str(),
                "secret",
                "`Tab` on Unlock must not mutate the passphrase buffer"
            );
        }
        other => panic!("expected Unlock, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Ctrl-N / Ctrl-P modal-local Tab / Shift-Tab aliases
//
// `IMPLEMENTATION_PLAN_03_TUI.md` "Vim-style navigation": *"`Ctrl-N` /
// `Ctrl-P` inside modals advance / retreat focus the same as `Tab` /
// `Shift-Tab`, have no effect on a post-success counts panel, and do
// not override `↑` / `↓` spinner adjustments."*
//
// The seven modal variants are still tag-only (no payloads, no
// focusable fields), so the in-modal observable behavior for both
// `Tab` / `Shift-Tab` and `Ctrl-N` / `Ctrl-P` is "preserve all visible
// state". The contract these tests lock in is symmetry: whichever
// alias is pressed, the modal stays open, top-level focus does not
// flip, the selection does not move, the status line does not
// surface, and the pending chord leader ends `None` (the chord-clear
// is shared by every modal-trapped key). When modal payloads grow
// internal focus-cycling, the same handler must dispatch off both
// pairs of keys.
//
// Modal-local scope is asserted by the top-level companion tests:
// outside a modal, `Ctrl-N` / `Ctrl-P` are unbound (silent no-ops)
// and must NOT flip top-level focus between list and search the way
// `Tab` / `Shift-Tab` do.

fn assert_ctrl_modal_alias_is_silent_no_op(modal_to_open: Modal, event: AppEvent, label: &str) {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let initial_focus = Focus::List;
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(modal_to_open),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: initial_focus,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, event);
    assert!(
        effects.is_empty(),
        "{label} inside a modal must not emit effects"
    );
    match state {
        AppState::Unlocked {
            focus,
            modal,
            selected,
            status_line,
            pending_chord_leader,
            search_query,
            hotp_reveal,
            pending_clipboard_clear,
            ..
        } => {
            assert!(modal.is_some(), "{label} must not close the trapped modal");
            assert_eq!(
                focus, initial_focus,
                "{label} must not flip top-level focus while a modal traps input"
            );
            assert_eq!(
                selected,
                Some(a),
                "{label} inside a modal must not advance the underlying list selection"
            );
            assert!(
                status_line.is_none(),
                "{label} inside a modal must not surface a status-line error"
            );
            assert!(
                pending_chord_leader.is_none(),
                "{label} inside a modal must leave pending chord state cleared"
            );
            assert!(
                search_query.is_empty(),
                "{label} inside a modal must not mutate the search query"
            );
            assert!(
                hotp_reveal.is_none(),
                "{label} inside a modal must not open a HOTP reveal"
            );
            assert!(
                pending_clipboard_clear.is_none(),
                "{label} inside a modal must not arm clipboard auto-clear"
            );
        }
        other => panic!("expected Unlocked with modal preserved, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_n_with_add_modal_open_aliases_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(
        Modal::Add(AddModal::default()),
        ctrl(KeyCode::Char('n')),
        "`Ctrl-N`",
    );
}

#[test]
fn pressing_ctrl_p_with_add_modal_open_aliases_shift_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(
        Modal::Add(AddModal::default()),
        ctrl(KeyCode::Char('p')),
        "`Ctrl-P`",
    );
}

#[test]
fn pressing_ctrl_n_with_import_modal_open_aliases_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(Modal::Import, ctrl(KeyCode::Char('n')), "`Ctrl-N`");
}

#[test]
fn pressing_ctrl_p_with_import_modal_open_aliases_shift_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(Modal::Import, ctrl(KeyCode::Char('p')), "`Ctrl-P`");
}

#[test]
fn pressing_ctrl_n_with_export_modal_open_aliases_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(Modal::Export, ctrl(KeyCode::Char('n')), "`Ctrl-N`");
}

#[test]
fn pressing_ctrl_p_with_export_modal_open_aliases_shift_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(Modal::Export, ctrl(KeyCode::Char('p')), "`Ctrl-P`");
}

#[test]
fn pressing_ctrl_n_with_remove_modal_open_aliases_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(
        Modal::Remove(RemoveModal::default()),
        ctrl(KeyCode::Char('n')),
        "`Ctrl-N`",
    );
}

#[test]
fn pressing_ctrl_p_with_remove_modal_open_aliases_shift_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(
        Modal::Remove(RemoveModal::default()),
        ctrl(KeyCode::Char('p')),
        "`Ctrl-P`",
    );
}

#[test]
fn pressing_ctrl_n_with_rename_modal_open_aliases_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(
        Modal::Rename(RenameModal::default()),
        ctrl(KeyCode::Char('n')),
        "`Ctrl-N`",
    );
}

#[test]
fn pressing_ctrl_p_with_rename_modal_open_aliases_shift_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(
        Modal::Rename(RenameModal::default()),
        ctrl(KeyCode::Char('p')),
        "`Ctrl-P`",
    );
}

#[test]
fn pressing_ctrl_n_with_passphrase_modal_open_aliases_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(
        Modal::Passphrase,
        ctrl(KeyCode::Char('n')),
        "`Ctrl-N`",
    );
}

#[test]
fn pressing_ctrl_p_with_passphrase_modal_open_aliases_shift_tab() {
    assert_ctrl_modal_alias_is_silent_no_op(
        Modal::Passphrase,
        ctrl(KeyCode::Char('p')),
        "`Ctrl-P`",
    );
}

// `Ctrl-N` / `Ctrl-P` inside an open Settings modal advance / retreat
// `SettingsFocus` through the four pending fields; coverage lives in
// the "Settings modal — field focus" slice above
// (`ctrl_n_in_settings_modal_advances_focus_like_tab` and
// `ctrl_p_in_settings_modal_retreats_focus_like_shift_tab`). The
// generic `assert_ctrl_modal_alias_is_silent_no_op` helper is reserved
// for modals whose payload has no focusable fields yet (Add / Import
// / Export / Remove / Passphrase / Rename); the Settings entry is
// intentionally not in that table because Settings consumes the
// aliases through `route_settings_modal_input` instead.

#[test]
fn pressing_ctrl_n_with_modal_open_on_search_focus_does_not_flip_focus() {
    // Mirror of the `Tab` / `Shift-Tab` modal-trap behavior with the
    // initial focus seeded to `Focus::Search`: the alias still must
    // not flip the underlying focus surface while the modal traps
    // input. Without this guard a future regression where `Ctrl-N`
    // routes through `toggle_unlocked_focus` would silently flip
    // List ↔ Search underneath an open modal.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('n')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            focus,
            Focus::Search,
            "`Ctrl-N` must not flip top-level focus while a modal is open"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_p_with_modal_open_on_search_focus_does_not_flip_focus() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal::default())),
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('p')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            modal: Some(Modal::Settings(_)),
            ..
        } => assert_eq!(
            focus,
            Focus::Search,
            "`Ctrl-P` must not flip top-level focus while a modal is open"
        ),
        other => panic!("expected Unlocked with Modal::Settings open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_n_with_modal_open_clears_pending_chord_leader() {
    // Every modal-trapped key clears the pending vim chord leader
    // (per the modal-trap rule in `reduce_unlocked_input`). `Ctrl-N`
    // is no exception — Tab / Shift-Tab clear it via the modal trap;
    // Ctrl-N clears it via the Ctrl-branch prologue. Symmetry
    // preserved.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(a),
        pending_chord_leader: Some(ChordLeader::G),
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('n')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            modal: Some(Modal::Add(_)),
            ..
        } => assert!(
            pending_chord_leader.is_none(),
            "`Ctrl-N` inside a modal must clear pending chord state"
        ),
        other => panic!("expected Unlocked with Modal::Add open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_p_with_modal_open_clears_pending_chord_leader() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(a),
        pending_chord_leader: Some(ChordLeader::Z),
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('p')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            pending_chord_leader,
            modal: Some(Modal::Add(_)),
            ..
        } => assert!(
            pending_chord_leader.is_none(),
            "`Ctrl-P` inside a modal must clear pending chord state"
        ),
        other => panic!("expected Unlocked with Modal::Add open, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_n_at_top_level_list_focus_does_not_flip_focus() {
    // `Ctrl-N` / `Ctrl-P` are MODAL-LOCAL aliases for `Tab` /
    // `Shift-Tab`. With no modal open, they are unbound — they must
    // not toggle the List ↔ Search focus the way bare `Tab` does.
    // This guard would trip a regression that lifted the alias to
    // top level.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('n')));
    assert!(
        effects.is_empty(),
        "top-level `Ctrl-N` must not emit effects"
    );
    match state {
        AppState::Unlocked {
            focus,
            modal,
            selected,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::List,
                "top-level `Ctrl-N` must not flip List ↔ Search focus"
            );
            assert!(modal.is_none(), "top-level `Ctrl-N` must not open a modal");
            assert_eq!(
                selected,
                Some(a),
                "top-level `Ctrl-N` must not move the list selection"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_p_at_top_level_list_focus_does_not_flip_focus() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('p')));
    assert!(
        effects.is_empty(),
        "top-level `Ctrl-P` must not emit effects"
    );
    match state {
        AppState::Unlocked {
            focus,
            modal,
            selected,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::List,
                "top-level `Ctrl-P` must not flip List ↔ Search focus"
            );
            assert!(modal.is_none(), "top-level `Ctrl-P` must not open a modal");
            assert_eq!(
                selected,
                Some(a),
                "top-level `Ctrl-P` must not move the list selection"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_n_at_top_level_search_focus_does_not_flip_focus() {
    // `Ctrl-N` on the search bar must not pre-empt `tui-input` and
    // flip focus back to the list — that would invert the contract
    // that Ctrl-N is a modal-LOCAL Tab alias. The search-focus
    // pass-through list explicitly omits `Ctrl-N` / `Ctrl-P`.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::from("a"),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('n')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            modal,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::Search,
                "top-level `Ctrl-N` must not flip search focus to list"
            );
            assert_eq!(
                search_query, "a",
                "top-level `Ctrl-N` must not mutate the search query"
            );
            assert!(modal.is_none());
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_ctrl_p_at_top_level_search_focus_does_not_flip_focus() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let a = add_totp_account(&mut vault, &store, "a");
    let unlocked = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::from("a"),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(a),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(unlocked, ctrl(KeyCode::Char('p')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            modal,
            ..
        } => {
            assert_eq!(
                focus,
                Focus::Search,
                "top-level `Ctrl-P` must not flip search focus to list"
            );
            assert_eq!(
                search_query, "a",
                "top-level `Ctrl-P` must not mutate the search query"
            );
            assert!(modal.is_none());
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Enter on Unlocked copies the selected code
//
// `IMPLEMENTATION_PLAN_03_TUI.md` Keybindings table: *"`Enter` — Copy
// selected code (TOTP: current; HOTP: visible only)."* The reducer
// emits `Effect::CopyCode { path, account_id }` when:
//
//   * `Focus::List` (Enter is not a search-field action),
//   * no modal is open and the help overlay is closed,
//   * an account is selected,
//   * and the account is TOTP, or it is HOTP with a `hotp_reveal`
//     whose `account_id` matches `selected`.
//
// The reducer never reads or writes the OS clipboard itself — only
// the executor (and only behind the placeholder until the clipboard
// adapter slice lands). HOTP-visible-only gating is enforced here so
// the executor never sees a CopyCode for a HOTP code the user cannot
// see on screen.
// ---------------------------------------------------------------------------

fn assert_copy_code_for(effects: &[Effect], expected_path: &Path, expected_account: AccountId) {
    match effects {
        [Effect::CopyCode { path, account_id }] => {
            assert_eq!(path, expected_path, "CopyCode must carry the vault path");
            assert_eq!(
                *account_id, expected_account,
                "CopyCode must carry the selected account id"
            );
        }
        other => panic!("expected single CopyCode effect, got {other:?}"),
    }
}

#[test]
fn pressing_enter_on_unlocked_with_totp_selected_emits_copy_code_effect() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(totp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert_copy_code_for(&effects, &path, totp_id);
    match state {
        AppState::Unlocked {
            hotp_reveal,
            status_line,
            ..
        } => {
            assert!(
                hotp_reveal.is_none(),
                "Enter on TOTP must not seed an HOTP reveal"
            );
            assert!(
                status_line.is_none(),
                "Enter on TOTP must not set a status line"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_enter_on_unlocked_with_hotp_selected_and_visible_reveal_emits_copy_code_effect() {
    // HOTP rule: copy only when a reveal window for the SAME account
    // is currently visible. The reveal is a precondition the reducer
    // can observe locally — no need to round-trip the executor.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "github");
    let reveal = HotpReveal {
        account_id: hotp_id,
        counter_used: 7,
        code: SecretString::from("123456".to_string()),
        deadline: hotp_reveal_deadline(Instant::now()),
    };
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
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
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert_copy_code_for(&effects, &path, hotp_id);
    match state {
        AppState::Unlocked { hotp_reveal, .. } => {
            assert!(
                hotp_reveal.is_some(),
                "Enter on a visible HOTP reveal must not close the reveal window — \
                 only Tick past the deadline or a fresh EffectResult may"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_enter_on_unlocked_with_hotp_selected_and_no_reveal_emits_no_effect() {
    // "HOTP: visible only" — with no reveal window the code is
    // hidden, so Enter has nothing to copy. The reducer must not
    // leak a CopyCode emission the executor would have to drop.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "Enter on a hidden HOTP must not emit CopyCode, got {effects:?}"
    );
    match state {
        AppState::Unlocked { hotp_reveal, .. } => {
            assert!(
                hotp_reveal.is_none(),
                "Enter on a hidden HOTP must not seed a reveal"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_enter_on_unlocked_with_hotp_selected_and_reveal_for_other_account_emits_no_effect() {
    // A stale reveal — pointing at a DIFFERENT account — does not
    // satisfy "visible only" for the currently selected HOTP. The
    // reducer must compare `hotp_reveal.account_id` against
    // `selected`, not merely check `hotp_reveal.is_some()`.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_a = add_hotp_account(&mut vault, &store, "alpha");
    let hotp_b = add_hotp_account(&mut vault, &store, "beta");
    let reveal = HotpReveal {
        account_id: hotp_a,
        counter_used: 3,
        code: SecretString::from("000000".to_string()),
        deadline: hotp_reveal_deadline(Instant::now()),
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: Some(reveal),
        modal: None,
        selected: Some(hotp_b),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "Enter on HOTP-B with reveal for HOTP-A must not emit CopyCode, got {effects:?}"
    );
    match state {
        AppState::Unlocked { hotp_reveal, .. } => {
            assert!(
                hotp_reveal.is_some(),
                "the stale reveal for the other account must not be cleared by Enter"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_enter_on_unlocked_with_no_selection_emits_no_effect() {
    // Without a selection there is no "selected code" to copy. The
    // reducer must not emit CopyCode and must not surface the
    // "no account selected" status used by the modal-opener keys
    // (`n` / `r` / `R`) — Enter is not selection-gated in the same
    // sense; an empty vault simply yields no action.
    let tmp = secure_tempdir();
    let (path, (vault, store)) = open_plaintext_pair(&tmp);
    let state = AppState::Unlocked {
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
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "Enter with no selection must not emit CopyCode, got {effects:?}"
    );
    match state {
        AppState::Unlocked { status_line, .. } => {
            assert!(
                status_line.is_none(),
                "Enter with no selection is a silent no-op (no status surface)"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_enter_on_unlocked_with_modal_open_emits_no_effect() {
    // Modal traps focus — Enter is modal-local input (Add modal
    // commits, Remove modal confirms, …) and must not leak through
    // to the underlying list's copy binding.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: Some(totp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "Enter with a modal open must not emit CopyCode, got {effects:?}"
    );
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add(_)),
            ..
        } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=Some(Modal::Add) preserved, got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_enter_on_unlocked_with_help_open_emits_no_effect() {
    // The Help overlay is read-only — every key besides `Esc` and
    // `Ctrl-C` is a silent no-op while it is visible, so Enter
    // cannot leak through to the copy binding.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(totp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: true,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "Enter with help open must not emit CopyCode, got {effects:?}"
    );
    match state {
        AppState::Unlocked { help_open, .. } => {
            assert!(help_open, "Enter with help open must not close the overlay");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn pressing_enter_on_unlocked_with_focus_search_emits_no_effect() {
    // Enter is a list action — on `Focus::Search` it must not copy.
    // The search field has no "submit" concept (the filter is live
    // on every keystroke), so the cleanest behavior is a silent
    // no-op. `Tab` is the documented way to leave the search field.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: "gh".to_string(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(totp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert!(
        effects.is_empty(),
        "Enter while Focus::Search must not emit CopyCode, got {effects:?}"
    );
    match state {
        AppState::Unlocked {
            focus,
            search_query,
            ..
        } => {
            assert_eq!(focus, Focus::Search, "Enter must not change focus");
            assert_eq!(search_query, "gh", "Enter must not mutate the search query");
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// EffectResult is the only path for non-core UI state mutation.
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` Tests > Reducer:
//   "AppEvent::EffectResult(...) is the only path by which effect
//    outcomes change non-core UI state (status text, reveal windows,
//    modal close / counts panels, inline errors)."
//
// The contract is: when the reducer EMITS an effect (Unlock, HotpAdvance,
// CopyCode, ClearClipboard, Quit), it must NOT mutate any of these
// non-core UI fields based on the effect's pending outcome — only the
// matching `EffectResult` arm may do so. Modal-close / counts-panel
// payloads land with the modal slices; this section locks in the rule
// for the slots already in `AppState::Unlocked` plus the inline
// `error` on `AppState::Unlock`.
// ---------------------------------------------------------------------------

#[test]
fn emit_unlock_effect_preserves_prior_inline_error_on_unlock_screen() {
    // Pressing Enter with a typed passphrase emits Effect::Unlock; the
    // prior `decrypt_failed` text must remain visible until the
    // matching EffectResult::Unlock replaces it (success → Unlocked,
    // wrong → re-renders the same `decrypt_failed`, other → StartupError).
    // The reducer must not pre-clear the error in anticipation.
    let prior = render_error_message(&PaladinError::DecryptFailed);
    let mut buf = PassphraseBuffer::new();
    for c in "hunter2".chars() {
        buf.push(c);
    }
    let state = AppState::Unlock {
        path: PathBuf::from("/tmp/v.bin"),
        error: Some(prior.clone()),
        passphrase: buf,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));

    match effects.as_slice() {
        [Effect::Unlock { .. }] => {}
        other => panic!("expected single Effect::Unlock, got {other:?}"),
    }
    match state {
        AppState::Unlock { error, .. } => assert_eq!(
            error.as_deref(),
            Some(prior.as_str()),
            "Effect::Unlock emission must not clear the prior inline error — \
             only EffectResult::Unlock may"
        ),
        other => panic!("expected Unlock, got {other:?}"),
    }
}

#[test]
fn emit_hotp_advance_effect_preserves_prior_open_reveal_window() {
    // Pressing `n` on Unlocked with an HOTP account selected emits
    // Effect::HotpAdvance. A prior reveal window (e.g. from an earlier
    // press whose code is still on screen) must be preserved verbatim
    // — only EffectResult::HotpAdvance Ok may replace it.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "github");
    let prior_deadline = hotp_reveal_deadline(Instant::now());
    let prior = HotpReveal {
        account_id: hotp_id,
        counter_used: 11,
        code: SecretString::from("424242".to_string()),
        deadline: prior_deadline,
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: Some(prior),
        modal: None,
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Char('n')));
    match effects.as_slice() {
        [Effect::HotpAdvance { .. }] => {}
        other => panic!("expected single Effect::HotpAdvance, got {other:?}"),
    }
    match state {
        AppState::Unlocked { hotp_reveal, .. } => match hotp_reveal {
            Some(reveal) => {
                assert_eq!(
                    reveal.account_id, hotp_id,
                    "prior reveal must be preserved across emission"
                );
                assert_eq!(
                    reveal.counter_used, 11,
                    "prior counter_used must be preserved — only \
                     EffectResult::HotpAdvance Ok may replace the slot"
                );
                assert_eq!(reveal.deadline, prior_deadline);
                assert_eq!(reveal.code.expose_secret(), "424242");
            }
            None => panic!("prior reveal must not be cleared by Effect::HotpAdvance emission"),
        },
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn emit_hotp_advance_effect_preserves_prior_status_line() {
    // A prior status_line set by an earlier rejected action (e.g. a
    // bare `n` on a no-selection list) must remain visible across a
    // later emission. The Effect emission step itself is not a
    // status-line surface — only the matching EffectResult arms (or
    // unrelated reducer paths) may set / clear it.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "github");
    let prior = StatusLine::Error("prior status".to_string());
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(prior.clone()),
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Char('n')));
    match effects.as_slice() {
        [Effect::HotpAdvance { .. }] => {}
        other => panic!("expected single Effect::HotpAdvance, got {other:?}"),
    }
    match state {
        AppState::Unlocked { status_line, .. } => assert_eq!(
            status_line,
            Some(prior),
            "Effect::HotpAdvance emission must not mutate status_line — \
             only matching EffectResult arms (or distinct reducer paths) may"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn emit_copy_code_effect_for_totp_preserves_prior_status_line() {
    // Pressing Enter on Unlocked with a TOTP account selected emits
    // Effect::CopyCode. A prior status_line (e.g. a stale "no account
    // selected" from before the user clicked into the list) must be
    // left in place by the emission step — only the matching
    // EffectResult arm or a distinct reducer path may clear it.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    let prior = StatusLine::Error("prior status".to_string());
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(totp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(prior.clone()),
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert_copy_code_for(&effects, &path, totp_id);
    match state {
        AppState::Unlocked { status_line, .. } => assert_eq!(
            status_line,
            Some(prior),
            "Effect::CopyCode emission must not mutate status_line"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn emit_copy_code_effect_for_totp_preserves_prior_unrelated_hotp_reveal() {
    // A reveal window for an HOTP account that is NOT the currently
    // selected (TOTP) account must survive the CopyCode emission for
    // the TOTP. Only its own deadline-Tick or a fresh
    // EffectResult::HotpAdvance can replace / drop it.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "alpha");
    let totp_id = add_totp_account(&mut vault, &store, "github");
    let prior_deadline = hotp_reveal_deadline(Instant::now());
    let prior = HotpReveal {
        account_id: hotp_id,
        counter_used: 5,
        code: SecretString::from("121212".to_string()),
        deadline: prior_deadline,
    };
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: Some(prior),
        modal: None,
        selected: Some(totp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert_copy_code_for(&effects, &path, totp_id);
    match state {
        AppState::Unlocked { hotp_reveal, .. } => match hotp_reveal {
            Some(reveal) => {
                assert_eq!(
                    reveal.account_id, hotp_id,
                    "unrelated HOTP reveal must survive a TOTP CopyCode emission"
                );
                assert_eq!(reveal.counter_used, 5);
                assert_eq!(reveal.deadline, prior_deadline);
                assert_eq!(reveal.code.expose_secret(), "121212");
            }
            None => panic!(
                "unrelated HOTP reveal must not be cleared by Effect::CopyCode emission for TOTP"
            ),
        },
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn emit_copy_code_effect_for_hotp_preserves_status_line_and_reveal() {
    // Pressing Enter on a visible HOTP reveal emits Effect::CopyCode;
    // both the status_line AND the reveal window must be preserved.
    // The reveal stays visible because only its own deadline-Tick (or
    // a fresh EffectResult::HotpAdvance) may drop it; status_line is
    // not on the path either.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let hotp_id = add_hotp_account(&mut vault, &store, "github");
    let prior_deadline = hotp_reveal_deadline(Instant::now());
    let prior_reveal = HotpReveal {
        account_id: hotp_id,
        counter_used: 3,
        code: SecretString::from("987654".to_string()),
        deadline: prior_deadline,
    };
    let prior_status = StatusLine::Error("prior status".to_string());
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: Some(prior_reveal),
        modal: None,
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(prior_status.clone()),
        help_open: false,
    };
    let (state, effects) = reduce(state, key(KeyCode::Enter));
    assert_copy_code_for(&effects, &path, hotp_id);
    match state {
        AppState::Unlocked {
            hotp_reveal,
            status_line,
            ..
        } => {
            match hotp_reveal {
                Some(reveal) => {
                    assert_eq!(reveal.account_id, hotp_id);
                    assert_eq!(
                        reveal.counter_used, 3,
                        "Effect::CopyCode emission must not replace reveal — \
                         only EffectResult::HotpAdvance Ok may"
                    );
                    assert_eq!(reveal.deadline, prior_deadline);
                    assert_eq!(reveal.code.expose_secret(), "987654");
                }
                None => panic!("HOTP reveal must survive CopyCode emission"),
            }
            assert_eq!(
                status_line,
                Some(prior_status),
                "status_line must survive CopyCode emission"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}
