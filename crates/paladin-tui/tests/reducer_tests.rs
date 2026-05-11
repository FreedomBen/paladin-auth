// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reducer / state-machine + global-arg tests for `paladin-tui`.
//! Tracks the "Tests" checklist in `IMPLEMENTATION_PLAN_03_TUI.md`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use clap::Parser;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::{ExposeSecret, SecretString};

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, Argon2Params,
    EncryptionOptions, IconHintInput, IdlePolicy, PaladinError, PermissionSubject, Store, Vault,
    VaultInit, VaultLock, VaultStatus,
};
use paladin_tui::app::event::{AppEvent, Effect, EffectResult};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{
    compute_idle_deadline, decide_state_from_inspect, decide_state_from_open, render_error_message,
    AppState, Modal,
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
    let tmp = tempfile::TempDir::new().unwrap();
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
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: None,
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
    let tmp = tempfile::TempDir::new().unwrap();
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
    let tmp = tempfile::TempDir::new().unwrap();
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
    let tmp = tempfile::TempDir::new().unwrap();
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
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('a')));
    assert!(effects.is_empty(), "opening a modal must not emit effects");
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add),
            ..
        } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=Some(Modal::Add), got modal={modal:?}")
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
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
        modal: Some(Modal::Settings),
        selected: None,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('a')));
    assert!(
        effects.is_empty(),
        "bare `a` inside an open modal must not emit effects"
    );
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Settings),
            ..
        } => {}
        AppState::Unlocked { modal, .. } => {
            panic!("expected modal=Some(Modal::Settings) preserved, got modal={modal:?}")
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
    // the only thing distinguishing the two bindings.
    assert_key_opens_modal(key(KeyCode::Char('r')), &Modal::Remove);
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
    assert_key_opens_modal(evt, &Modal::Rename);
}

#[test]
fn pressing_shift_r_without_modifier_byte_still_opens_rename_modal() {
    // Belt-and-suspenders for terminals that report `Char('R')`
    // without the SHIFT modifier byte (the historic crossterm
    // default outside kitty-protocol mode). The reducer dispatches
    // on the resolved character, not the modifier, so both shapes
    // must hit Rename.
    assert_key_opens_modal(key(KeyCode::Char('R')), &Modal::Rename);
}

#[test]
fn pressing_p_on_unlocked_with_no_modal_open_opens_passphrase_modal() {
    assert_key_opens_modal(key(KeyCode::Char('p')), &Modal::Passphrase);
}

#[test]
fn pressing_s_on_unlocked_with_no_modal_open_opens_settings_modal() {
    assert_key_opens_modal(key(KeyCode::Char('s')), &Modal::Settings);
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
    assert_esc_closes_modal(Modal::Add);
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
    assert_esc_closes_modal(Modal::Remove);
}

#[test]
fn pressing_esc_on_unlocked_with_open_rename_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Rename);
}

#[test]
fn pressing_esc_on_unlocked_with_open_passphrase_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Passphrase);
}

#[test]
fn pressing_esc_on_unlocked_with_open_settings_modal_closes_the_modal() {
    assert_esc_closes_modal(Modal::Settings);
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
        modal: Some(Modal::Add),
        selected: None,
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('q')));
    assert!(
        effects.is_empty(),
        "q with a modal open must not emit Effect::Quit, got {effects:?}"
    );
    match state {
        AppState::Unlocked {
            modal: Some(Modal::Add),
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
        modal: Some(Modal::Settings),
        selected: Some(a),
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Down));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Settings),
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
        modal: Some(Modal::Add),
        selected: Some(a),
    };
    let (state, effects) = reduce(unlocked, key(KeyCode::Char('j')));
    assert!(effects.is_empty());
    match state {
        AppState::Unlocked {
            selected,
            modal: Some(Modal::Add),
            ..
        } => assert_eq!(
            selected,
            Some(a),
            "vim `j` inside an open modal must not move list selection"
        ),
        other => panic!("expected Unlocked with Modal::Add open, got {other:?}"),
    }
}
