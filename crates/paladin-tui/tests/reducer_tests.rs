// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reducer / state-machine + global-arg tests for `paladin-tui`.
//! Tracks the "Tests" checklist in `IMPLEMENTATION_PLAN_03_TUI.md`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;

use paladin_core::{PaladinError, PermissionSubject, Store, VaultInit, VaultLock, VaultStatus};
use paladin_tui::app::state::{
    decide_state_from_inspect, decide_state_from_open, render_error_message, AppState,
};
use paladin_tui::cli::{should_disable_color, GlobalArgs};

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
        }) => assert_eq!(p, path),
        other => panic!("expected Unlock with no error, got {other:?}"),
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
