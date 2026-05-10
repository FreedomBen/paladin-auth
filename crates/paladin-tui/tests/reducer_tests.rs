// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reducer / state-machine + global-arg tests for `paladin-tui`.
//! Tracks the "Tests" checklist in `IMPLEMENTATION_PLAN_03_TUI.md`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use clap::Parser;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::ExposeSecret;

use paladin_core::{PaladinError, PermissionSubject, Store, VaultInit, VaultLock, VaultStatus};
use paladin_tui::app::event::{AppEvent, Effect};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{
    decide_state_from_inspect, decide_state_from_open, render_error_message, AppState,
};
use paladin_tui::cli::{should_disable_color, GlobalArgs};
use paladin_tui::prompt::PassphraseBuffer;

// ---------------------------------------------------------------------------
// Reducer helpers shared by the per-key-binding tests below.
// ---------------------------------------------------------------------------

fn key(code: KeyCode) -> AppEvent {
    AppEvent::Input(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)))
}

fn ctrl(code: KeyCode) -> AppEvent {
    AppEvent::Input(Event::Key(KeyEvent::new(code, KeyModifiers::CONTROL)))
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
fn inspect_error_yields_startup_error_with_rendered_message_and_no_file_mutation() {
    // Drive a real `invalid_header` (or comparable) error by inspecting a
    // file with garbage bytes — verifies bullet "Non-`decrypt_failed`
    // errors from `inspect` / `open` ... open the non-mutating
    // startup-error screen and do not create or mutate files."
    let tmp = tempfile::TempDir::new().unwrap();
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
    let tmp = tempfile::TempDir::new().unwrap();
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
    let state = decide_state_from_open(path.clone(), open);
    match state {
        AppState::Unlocked { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn open_error_yields_startup_error_with_path_retained() {
    // Bullet: "Non-`decrypt_failed` errors from `inspect` / `open` ...
    // open the non-mutating startup-error screen ..."
    // Drive an open failure by pointing at a tempfile with garbage bytes
    // (Store::open returns an error for invalid header etc.).
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("garbage.bin");
    fs::write(&path, b"not a paladin vault").unwrap();

    let open = Store::open(&path, VaultLock::Plaintext);
    assert!(open.is_err(), "expected open error, got Ok");

    let state = decide_state_from_open(path.clone(), open);
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
    let tmp = tempfile::TempDir::new().unwrap();
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
    let tmp = tempfile::TempDir::new().unwrap();
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
    let evt = AppEvent::Input(Event::Resize(80, 24));
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
    let evt = AppEvent::Input(Event::Key(KeyEvent::new(
        KeyCode::Char('A'),
        KeyModifiers::SHIFT,
    )));
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
