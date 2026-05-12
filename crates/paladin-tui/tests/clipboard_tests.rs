// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clipboard auto-clear reducer tests for `paladin-tui`.
//!
//! Tracks the "Tests > Clipboard auto-clear (`tests/clipboard_tests.rs`)"
//! checklist in `IMPLEMENTATION_PLAN_03_TUI.md`. This slice covers the
//! reducer-level scheduling decision: when an
//! `EffectResult::CopyCode` lands on `Unlocked` with
//! `clipboard.clear_enabled = true`, the reducer routes through
//! `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule`
//! to seed `pending_clipboard_clear` with the captured bytes, the
//! issued monotonic token, and the policy-returned deadline. With
//! the setting disabled, `schedule` returns `None` and the reducer
//! must not arm a pending clear. The error path leaves
//! `pending_clipboard_clear` untouched and surfaces a status-line
//! error per the §6 / "Effect errors" rule: *"Copy: show a
//! status-line error if clipboard write fails; do not schedule
//! auto-clear."*
//!
//! The executor-side live-clipboard read / `should_clear` / wipe and
//! the `PALADIN_CLIPBOARD_DRYRUN=1` adapter hook ride with later
//! bullets in the same checklist (clipboard adapter slice).

mod common;

use common::test_tempdir;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, Argon2Params,
    ClipboardClearPolicy, EncryptionOptions, IconHintInput, Store, Vault, VaultInit, VaultLock,
};
use paladin_tui::app::event::{AppEvent, EffectResult};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{
    AppState, Focus, PendingClipboardClear, StatusLine, CLIPBOARD_WRITE_FAILED,
};

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

fn create_encrypted_pair(path: &Path, passphrase: &str) -> (Vault, Store) {
    let pp = SecretString::from(passphrase.to_string());
    let opts = EncryptionOptions::with_params(pp, light_params()).expect("encryption opts");
    let (vault, store) = Store::create(path, VaultInit::Encrypted(opts)).expect("create vault");
    vault.save(&store).expect("commit initial vault");
    (vault, store)
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
    vault.save(store).expect("commit added account");
    id
}

fn enable_clipboard_clear(vault: &mut Vault, store: &Store, secs: u32) {
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(secs)
        .expect("clear secs within bounds");
    vault.save(store).expect("commit clipboard-clear settings");
}

fn build_unlocked(
    path: PathBuf,
    vault: Vault,
    store: Store,
    selected: Option<AccountId>,
) -> AppState {
    AppState::Unlocked {
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
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    }
}

fn copy_bytes() -> Vec<u8> {
    b"123456".to_vec()
}

// ---------------------------------------------------------------------------
// Copy schedules a clear via `ClipboardClearPolicy::schedule`
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Clipboard auto-clear — bullet 1)
//
// The reducer side of "at copy time it stores the latest
// ClipboardClearToken plus the captured bytes in UI state". On
// `Unlocked` with `clipboard.clear_enabled = true`, an
// `EffectResult::CopyCode { account_id, result: Ok(bytes),
// completed_at }` routes through
// `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule(completed_at, vault.settings())`
// and seeds `pending_clipboard_clear` with the returned token, the
// captured bytes, and the returned deadline.
// ---------------------------------------------------------------------------

#[test]
fn effect_result_copy_code_ok_with_clipboard_clear_enabled_schedules_pending_clear() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    enable_clipboard_clear(&mut vault, &store, 30);
    let state = build_unlocked(path, vault, store, Some(totp_id));

    let completed_at = Instant::now();
    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Ok(copy_bytes()),
        completed_at,
    });

    let (next, effects) = reduce(state, event);
    assert!(
        effects.is_empty(),
        "EffectResult::CopyCode emits no follow-up effects at the reducer layer"
    );
    match next {
        AppState::Unlocked {
            pending_clipboard_clear: Some(pending),
            status_line,
            ..
        } => {
            assert_eq!(
                pending.value.as_slice(),
                copy_bytes().as_slice(),
                "scheduled pending clear must carry the bytes from the EffectResult"
            );
            assert_eq!(
                pending.deadline,
                completed_at + Duration::from_secs(30),
                "deadline must equal completed_at + clipboard_clear_secs"
            );
            assert!(
                status_line.is_none(),
                "successful copy must not surface a status-line error"
            );
        }
        other => panic!("expected Unlocked with pending clipboard clear, got {other:?}"),
    }
}

#[test]
fn effect_result_copy_code_ok_uses_monotonic_schedule_token() {
    // The token must come from `ClipboardClearPolicy::schedule` (a
    // monotonic counter). A token issued before the reducer's call
    // must compare strictly less than the token the reducer stored.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    enable_clipboard_clear(&mut vault, &store, 30);

    let pre_token = ClipboardClearPolicy::schedule(Instant::now(), vault.settings()).map(|t| t.0);

    let state = build_unlocked(path, vault, store, Some(totp_id));
    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Ok(copy_bytes()),
        completed_at: Instant::now(),
    });
    let (next, _) = reduce(state, event);
    match next {
        AppState::Unlocked {
            pending_clipboard_clear: Some(pending),
            ..
        } => {
            let pre = pre_token.expect("schedule must yield Some when clipboard_clear_enabled");
            assert!(
                pending.token > pre,
                "reducer-issued token must be strictly greater than a token issued earlier ({pre:?} vs {:?})",
                pending.token
            );
        }
        other => panic!("expected Unlocked with pending clipboard clear, got {other:?}"),
    }
}

#[test]
fn effect_result_copy_code_ok_with_clipboard_clear_disabled_does_not_arm_pending() {
    // The default `VaultSettings` has `clipboard_clear_enabled =
    // false`; `ClipboardClearPolicy::schedule` returns `None`, and
    // the reducer must not fabricate a pending clear.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    // Confirm the setting is OFF by default — the test would silently
    // pass if a future default flipped it on.
    assert!(
        !vault.settings().clipboard_clear_enabled(),
        "test precondition: clipboard_clear_enabled must default to false"
    );
    let state = build_unlocked(path, vault, store, Some(totp_id));

    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Ok(copy_bytes()),
        completed_at: Instant::now(),
    });
    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            pending_clipboard_clear,
            status_line,
            ..
        } => {
            assert!(
                pending_clipboard_clear.is_none(),
                "schedule returned None — reducer must not arm a pending clear, got {pending_clipboard_clear:?}"
            );
            assert!(
                status_line.is_none(),
                "successful copy must not surface a status-line error even with auto-clear disabled"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_copy_code_ok_replaces_prior_pending_clear_when_enabled() {
    // A later schedule on the same vault settings supersedes the
    // earlier one (per `PendingClipboardClear` doc comment: "A later
    // schedule on the same vault settings supersedes this one.").
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    enable_clipboard_clear(&mut vault, &store, 30);

    let earlier =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings()).expect("first schedule");
    let prior = PendingClipboardClear {
        token: earlier.0,
        value: b"prev".to_vec(),
        deadline: earlier.1,
    };
    let mut state = build_unlocked(path, vault, store, Some(totp_id));
    if let AppState::Unlocked {
        ref mut pending_clipboard_clear,
        ..
    } = state
    {
        *pending_clipboard_clear = Some(prior);
    }

    let completed_at = Instant::now();
    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Ok(copy_bytes()),
        completed_at,
    });
    let (next, _) = reduce(state, event);
    match next {
        AppState::Unlocked {
            pending_clipboard_clear: Some(pending),
            ..
        } => {
            assert!(
                pending.token > earlier.0,
                "fresh schedule must yield a token strictly greater than the prior pending one"
            );
            assert_eq!(
                pending.value.as_slice(),
                copy_bytes().as_slice(),
                "replacement must carry the fresh copy's bytes (not the prior bytes)"
            );
            assert_eq!(pending.deadline, completed_at + Duration::from_secs(30));
        }
        other => panic!("expected Unlocked with replaced pending clear, got {other:?}"),
    }
}

#[test]
fn effect_result_copy_code_ok_clears_prior_status_line() {
    // Last-write-wins: a successful copy dismisses any prior failure
    // note on the status line (mirrors the HotpAdvance Ok contract).
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    enable_clipboard_clear(&mut vault, &store, 30);
    let mut state = build_unlocked(path, vault, store, Some(totp_id));
    if let AppState::Unlocked {
        ref mut status_line,
        ..
    } = state
    {
        *status_line = Some(StatusLine::Error("prior failure".to_string()));
    }

    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Ok(copy_bytes()),
        completed_at: Instant::now(),
    });
    let (next, _) = reduce(state, event);
    match next {
        AppState::Unlocked { status_line, .. } => assert!(
            status_line.is_none(),
            "successful copy must clear the prior status-line note, got {status_line:?}"
        ),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Copy failure: status-line error, no schedule
// (IMPLEMENTATION_PLAN_03_TUI.md > Effect errors)
//
// "Copy: show a status-line error if clipboard write fails; do not
// schedule auto-clear."
// ---------------------------------------------------------------------------

#[test]
fn effect_result_copy_code_err_sets_status_line_clipboard_write_failed() {
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    enable_clipboard_clear(&mut vault, &store, 30);
    let state = build_unlocked(path, vault, store, Some(totp_id));

    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Err(()),
        completed_at: Instant::now(),
    });
    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            status_line,
            pending_clipboard_clear,
            ..
        } => {
            assert_eq!(
                status_line,
                Some(StatusLine::Error(CLIPBOARD_WRITE_FAILED.to_string())),
                "clipboard write failure must surface the clipboard_write_failed status-line error"
            );
            assert!(
                pending_clipboard_clear.is_none(),
                "failed copy must not schedule an auto-clear, got {pending_clipboard_clear:?}"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn effect_result_copy_code_err_leaves_prior_pending_clear_unchanged() {
    // A failed second copy must not wipe the still-valid pending
    // clear from a prior successful copy.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    enable_clipboard_clear(&mut vault, &store, 30);

    let earlier =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings()).expect("schedule");
    let prior = PendingClipboardClear {
        token: earlier.0,
        value: b"prev".to_vec(),
        deadline: earlier.1,
    };
    let mut state = build_unlocked(path, vault, store, Some(totp_id));
    if let AppState::Unlocked {
        ref mut pending_clipboard_clear,
        ..
    } = state
    {
        *pending_clipboard_clear = Some(prior);
    }

    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Err(()),
        completed_at: Instant::now(),
    });
    let (next, _) = reduce(state, event);
    match next {
        AppState::Unlocked {
            pending_clipboard_clear: Some(pending),
            status_line,
            ..
        } => {
            assert_eq!(
                pending.token, earlier.0,
                "prior pending clear must survive a failed follow-up copy"
            );
            assert_eq!(
                pending.value, b"prev",
                "prior captured bytes must survive a failed follow-up copy"
            );
            assert_eq!(
                status_line,
                Some(StatusLine::Error(CLIPBOARD_WRITE_FAILED.to_string()))
            );
        }
        other => panic!("expected Unlocked with prior pending clear, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Non-Unlocked state: discard
//
// `EffectResult::CopyCode` results arriving on `Locked` (auto-lock
// fired between the copy effect and its result), `MissingVault`, or
// `StartupError` are dropped without mutating state. The carried
// bytes are not stored anywhere — they drop with the `Vec<u8>`.
// ---------------------------------------------------------------------------

#[test]
fn effect_result_copy_code_drops_when_locked() {
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: None,
    };
    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: AccountId::new(),
        result: Ok(copy_bytes()),
        completed_at: Instant::now(),
    });
    let (next, effects) = reduce(state, event);
    assert!(effects.is_empty(), "discarding a late result emits nothing");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear: None,
        } => assert_eq!(p, path, "Locked path must be preserved"),
        other => panic!("expected Locked unchanged, got {other:?}"),
    }
}

#[test]
fn effect_result_copy_code_err_drops_when_locked_without_surfacing_error() {
    // The error path is `Unlocked`-only too — once the vault is
    // locked, there's no list view to anchor the status-line error
    // against. Discarding cleanly matches the HotpAdvance Err
    // discard rule.
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: None,
    };
    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: AccountId::new(),
        result: Err(()),
        completed_at: Instant::now(),
    });
    let (next, _) = reduce(state, event);
    match next {
        AppState::Locked { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Encrypted vault parity
//
// The schedule contract is identical for plaintext and encrypted
// vaults: `ClipboardClearPolicy::schedule` does not gate on
// `is_encrypted` (unlike `IdlePolicy::should_arm`). One encrypted
// case locks the rule in.
// ---------------------------------------------------------------------------

#[test]
fn effect_result_copy_code_ok_schedules_on_encrypted_vault_when_enabled() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    let totp_id = add_totp_account(&mut vault, &store, "github");
    enable_clipboard_clear(&mut vault, &store, 60);
    let state = build_unlocked(path, vault, store, Some(totp_id));

    let completed_at = Instant::now();
    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Ok(copy_bytes()),
        completed_at,
    });
    let (next, _) = reduce(state, event);
    match next {
        AppState::Unlocked {
            pending_clipboard_clear: Some(pending),
            ..
        } => {
            assert_eq!(pending.value.as_slice(), copy_bytes().as_slice());
            assert_eq!(pending.deadline, completed_at + Duration::from_secs(60));
        }
        other => panic!("expected Unlocked with pending clear, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Stale tokens are ignored on wake
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Clipboard auto-clear — bullet 2)
//
// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear (per §6)":
// *"on wake, it ignores stale tokens, …"*. The reducer-side guard
// short-circuits the wake on `AppState::Locked` when the event token
// does not match the pending token (a fresher copy has issued a new
// token and replaced the pending state) and when the pending slot is
// `None` (the matching-token branch already fired or auto-lock
// arrived with no pending clear in flight). Both no-op branches must
// leave state untouched and emit no effects.
// ---------------------------------------------------------------------------

#[test]
fn clipboard_clear_wake_with_stale_token_on_locked_is_noop() {
    // Stale token: a fresher copy has replaced `pending_clipboard_clear`
    // with a strictly greater token; the older timer thread's wake
    // arrives carrying its now-superseded token. The reducer must
    // preserve the fresher pending slot byte-for-byte and emit no
    // `Effect::ClearClipboard`.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    enable_clipboard_clear(&mut vault, &store, 60);

    let (stale_token, _stale_deadline) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
            .expect("first schedule yields Some when clipboard_clear_enabled");
    let (fresh_token, fresh_deadline) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
            .expect("second schedule yields Some when clipboard_clear_enabled");
    assert!(
        fresh_token > stale_token,
        "schedule must issue strictly monotonic tokens ({stale_token:?} vs {fresh_token:?})"
    );

    let fresh_value: Vec<u8> = b"654321".to_vec();
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token: fresh_token,
            value: fresh_value.clone(),
            deadline: fresh_deadline,
        }),
    };
    let event = AppEvent::ClipboardClear {
        token: stale_token,
        value: b"123456".to_vec(),
    };
    let (next, effects) = reduce(state, event);
    assert!(
        effects.is_empty(),
        "stale-token wake must not dispatch any effect, got {effects:?}"
    );
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear: Some(pending),
        } => {
            assert_eq!(p, path);
            assert_eq!(
                pending.token, fresh_token,
                "fresher pending token must be preserved verbatim"
            );
            assert_eq!(
                pending.value.as_slice(),
                fresh_value.as_slice(),
                "fresher pending bytes must be preserved verbatim"
            );
            assert_eq!(
                pending.deadline, fresh_deadline,
                "fresher pending deadline must be preserved verbatim"
            );
        }
        other => panic!("expected Locked with the fresher pending clear intact, got {other:?}"),
    }
}

#[test]
fn clipboard_clear_wake_with_no_pending_on_locked_is_noop() {
    // The matching-token branch already cleared `pending_clipboard_clear`
    // (so a duplicate wake is a no-op), or auto-lock landed without a
    // copy in flight. Either way the reducer must drop the wake
    // silently — no effect, state unchanged.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    enable_clipboard_clear(&mut vault, &store, 60);

    let (token, _deadline) = ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
        .expect("schedule yields Some when clipboard_clear_enabled");
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: None,
    };
    let event = AppEvent::ClipboardClear {
        token,
        value: b"123456".to_vec(),
    };
    let (next, effects) = reduce(state, event);
    assert!(
        effects.is_empty(),
        "wake with no pending clear must not dispatch any effect, got {effects:?}"
    );
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear: None,
        } => assert_eq!(p, path),
        other => panic!("expected Locked with no pending clear preserved, got {other:?}"),
    }
}
