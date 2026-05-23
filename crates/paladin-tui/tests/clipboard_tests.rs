// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clipboard auto-clear reducer tests for `paladin-tui`.
//!
//! Tracks the "Tests > Clipboard auto-clear (`tests/clipboard_tests.rs`)"
//! checklist in `docs/IMPLEMENTATION_PLAN_03_TUI.md`. This slice covers the
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
use zeroize::Zeroizing;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, Argon2Params,
    ClipboardClearPolicy, EncryptionOptions, IconHintInput, Store, Vault, VaultInit, VaultLock,
};
use paladin_tui::app::event::{AppEvent, Effect, EffectResult};
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
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Clipboard auto-clear — bullet 1)
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
        result: Ok(Zeroizing::new(copy_bytes())),
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
        result: Ok(Zeroizing::new(copy_bytes())),
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
        result: Ok(Zeroizing::new(copy_bytes())),
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
        value: Zeroizing::new(b"prev".to_vec()),
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
        result: Ok(Zeroizing::new(copy_bytes())),
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
        result: Ok(Zeroizing::new(copy_bytes())),
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
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Effect errors)
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
        value: Zeroizing::new(b"prev".to_vec()),
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
                pending.value.as_slice(),
                b"prev",
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
// fired between the copy effect and its result), `CreateVault`, or
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
        result: Ok(Zeroizing::new(copy_bytes())),
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
        result: Ok(Zeroizing::new(copy_bytes())),
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
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Clipboard auto-clear — bullet 2)
//
// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear (per §6)":
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
            value: Zeroizing::new(fresh_value.clone()),
            deadline: fresh_deadline,
        }),
    };
    let event = AppEvent::ClipboardClear {
        token: stale_token,
        value: Zeroizing::new(b"123456".to_vec()),
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
        value: Zeroizing::new(b"123456".to_vec()),
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

// ---------------------------------------------------------------------------
// Pending copied values are zeroized
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Clipboard auto-clear — bullet 4)
//
// Captured clipboard bytes flow through four lifetime points:
//   * the reducer's `pending_clipboard_clear.value` slot,
//   * the `AppEvent::ClipboardClear.value` carried by the wake event
//     (which the reducer drops verbatim on a stale-token wake),
//   * the `Effect::ClearClipboard.value` payload handed to the
//     executor on a matching-token wake, and
//   * the `EffectResult::CopyCode.result` `Ok` payload carried back
//     from the executor.
//
// Each is wrapped in `Zeroizing<Vec<u8>>` so `Drop` zeroizes the bytes
// before the underlying allocation is freed — covering both the
// "after the clear attempt" path (executor drops the effect after
// running the wipe) and the "stale-token drop" path (reducer drops
// the rejected event without dispatching an effect).
// ---------------------------------------------------------------------------

#[test]
fn pending_clipboard_clear_value_field_is_zeroizing_vec() {
    // Compile-time gate: building a `PendingClipboardClear` whose
    // `value` is `Zeroizing<Vec<u8>>` only typechecks when the field
    // accepts that exact type. A plain `Vec<u8>` field would fail
    // to compile here.
    let tmp = secure_tempdir();
    let (_path, (mut vault, store)) = open_plaintext_pair(&tmp);
    enable_clipboard_clear(&mut vault, &store, 30);
    let (token, deadline) = ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
        .expect("schedule yields Some when clipboard_clear_enabled");

    let pending = PendingClipboardClear {
        token,
        value: Zeroizing::new(copy_bytes()),
        deadline,
    };

    // The `value` deref'd as a slice must still expose the bytes for
    // the only-if-unchanged comparison.
    assert_eq!(pending.value.as_slice(), copy_bytes().as_slice());
    // Explicit type binding locks the wrapper in.
    let _: &Zeroizing<Vec<u8>> = &pending.value;
}

#[test]
fn app_event_clipboard_clear_value_field_is_zeroizing_vec() {
    let tmp = secure_tempdir();
    let (_path, (mut vault, store)) = open_plaintext_pair(&tmp);
    enable_clipboard_clear(&mut vault, &store, 30);
    let (token, _deadline) = ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
        .expect("schedule yields Some when clipboard_clear_enabled");

    let event = AppEvent::ClipboardClear {
        token,
        value: Zeroizing::new(copy_bytes()),
    };

    match event {
        AppEvent::ClipboardClear { value, .. } => {
            assert_eq!(value.as_slice(), copy_bytes().as_slice());
            let _: &Zeroizing<Vec<u8>> = &value;
        }
        other => panic!("expected ClipboardClear, got {other:?}"),
    }
}

#[test]
fn effect_clear_clipboard_value_field_is_zeroizing_vec() {
    let effect = Effect::ClearClipboard {
        value: Zeroizing::new(copy_bytes()),
    };
    match effect {
        Effect::ClearClipboard { value } => {
            assert_eq!(value.as_slice(), copy_bytes().as_slice());
            let _: &Zeroizing<Vec<u8>> = &value;
        }
        other => panic!("expected ClearClipboard, got {other:?}"),
    }
}

#[test]
fn effect_result_copy_code_ok_value_is_zeroizing_vec() {
    let result = EffectResult::CopyCode {
        account_id: AccountId::new(),
        result: Ok(Zeroizing::new(copy_bytes())),
        completed_at: Instant::now(),
    };
    match result {
        EffectResult::CopyCode {
            result: Ok(value), ..
        } => {
            assert_eq!(value.as_slice(), copy_bytes().as_slice());
            let _: &Zeroizing<Vec<u8>> = &value;
        }
        other => panic!("expected CopyCode Ok, got {other:?}"),
    }
}

#[test]
fn matching_token_wake_hands_clear_clipboard_effect_zeroizing_bytes() {
    // End-to-end check: after the matching-token wake on `Locked`,
    // the dispatched `Effect::ClearClipboard.value` is a
    // `Zeroizing<Vec<u8>>` carrying the previously captured bytes.
    // The executor drops this payload after the wipe; the zeroizing
    // wrapper's Drop guarantees the bytes are wiped before the
    // backing allocation is freed.
    let tmp = secure_tempdir();
    let (_path, (mut vault, store)) = open_plaintext_pair(&tmp);
    enable_clipboard_clear(&mut vault, &store, 30);
    let (token, deadline) = ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
        .expect("schedule yields Some when clipboard_clear_enabled");

    let path = PathBuf::from("/tmp/v.bin");
    let captured = copy_bytes();
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token,
            value: Zeroizing::new(captured.clone()),
            deadline,
        }),
    };

    let (_next, effects) = reduce(
        state,
        AppEvent::ClipboardClear {
            token,
            value: Zeroizing::new(captured.clone()),
        },
    );

    match &effects[..] {
        [Effect::ClearClipboard { value }] => {
            assert_eq!(
                value.as_slice(),
                captured.as_slice(),
                "wipe effect must carry the captured bytes from pending state"
            );
            let _: &Zeroizing<Vec<u8>> = value;
        }
        other => panic!("expected exactly one Effect::ClearClipboard, got {other:?}"),
    }
}

#[test]
fn zeroizing_vec_zeroize_empties_buffer() {
    // The `Zeroize::zeroize` contract for `Vec<u8>` — both the
    // explicit call exercised here and the implicit one in
    // `Zeroizing::<Vec<u8>>::drop` — zeros every byte of the
    // backing buffer and resets the `Vec`'s length to 0. The
    // `is_empty()` check is the safe-Rust observable side of that
    // contract; the wrapper is the contract bearer for the
    // `Pending` / `Effect` / `EffectResult` payloads above.
    let mut value: Zeroizing<Vec<u8>> = Zeroizing::new(copy_bytes());
    assert!(!value.is_empty(), "precondition: buffer is non-empty");

    zeroize::Zeroize::zeroize(&mut *value);

    assert!(
        value.is_empty(),
        "Zeroize::zeroize must reset the buffer to empty"
    );
}

// ---------------------------------------------------------------------------
// Pending clipboard-clear buffer: survives lock; zeroizes on
// scheduled clear attempt, stale-token drop, replacement, and app
// shutdown
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Sensitive UI buffers —
//  bullet "Pending clipboard-clear buffers survive lock until the
//  scheduled clear attempt, stale-token drop, replacement, or app
//  shutdown, then zeroize.")
//
// The `PendingClipboardClear.value` field is a `Zeroizing<Vec<u8>>`,
// so the captured bytes wipe on drop via the wrapper's `Drop` impl.
// The four termination axes below each exercise a code path that
// drops the buffer (`Drop::drop` on `Zeroizing<Vec<u8>>` runs
// `Zeroize::zeroize` on the inner `Vec<u8>`, see
// `zeroizing_vec_zeroize_empties_buffer`). The lock-survival axis
// confirms the buffer is *not* dropped on the `Unlocked → Locked`
// transition: it must ride through verbatim so the timer thread's
// wake can still find pending state.
// ---------------------------------------------------------------------------

#[test]
fn auto_lock_carries_pending_clipboard_clear_into_locked_preserving_zeroizing_bytes() {
    // Lock-survival axis. A `Tick` past `idle_deadline` transitions
    // `Unlocked → Locked` via `maybe_auto_lock`; per
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
    // *"A clipboard auto-clear timer scheduled before lock survives
    // lock and still fires only-if-unchanged."* The bytes must
    // arrive on `Locked` byte-equal to the captured value, the token
    // must be unchanged so a later matching wake still finds them,
    // and the wrapper type must remain `Zeroizing<Vec<u8>>` so the
    // remaining termination axes can still rely on `Drop` for the
    // wipe.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_clipboard_clear(&mut vault, &store, 30);
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(60)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit auto-lock settings");

    let t0 = Instant::now();
    let idle_deadline = t0 + Duration::from_secs(60);
    let (token, wake_deadline) = ClipboardClearPolicy::schedule(t0, vault.settings())
        .expect("schedule yields Some when clipboard_clear_enabled");
    let captured = copy_bytes();
    let mut state = build_unlocked(path.clone(), vault, store, None);
    match &mut state {
        AppState::Unlocked {
            idle_deadline: id_slot,
            pending_clipboard_clear,
            ..
        } => {
            *id_slot = Some(idle_deadline);
            *pending_clipboard_clear = Some(PendingClipboardClear {
                token,
                value: Zeroizing::new(captured.clone()),
                deadline: wake_deadline,
            });
        }
        other => panic!("build_unlocked must yield Unlocked, got {other:?}"),
    }

    let now = idle_deadline + Duration::from_millis(1);
    let tick = AppEvent::Tick {
        wall_clock: SystemTime::now(),
        monotonic: now,
    };
    let (next, effects) = reduce(state, tick);
    assert!(
        effects.is_empty(),
        "auto-lock transition must not emit effects; got {effects:?}",
    );
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear: Some(pending),
        } => {
            assert_eq!(p, path, "Locked must retain the vault path");
            assert_eq!(
                pending.token, token,
                "pending token must survive the Unlocked → Locked transition unchanged",
            );
            assert_eq!(
                pending.deadline, wake_deadline,
                "pending wake-deadline must survive the transition unchanged",
            );
            assert_eq!(
                pending.value.as_slice(),
                captured.as_slice(),
                "pending captured bytes must survive the transition byte-for-byte",
            );
            // Wrapper-type binding: locks the lock-survived value in
            // as a `Zeroizing<Vec<u8>>` so the matching-token wake
            // and app-shutdown axes can still rely on `Drop` for
            // the wipe.
            let _: &Zeroizing<Vec<u8>> = &pending.value;
        }
        other => panic!("expected Locked carrying the pending clipboard clear, got {other:?}",),
    }
}

#[test]
fn matching_token_wake_on_locked_clears_pending_slot_post_state() {
    // Scheduled-clear-attempt axis. A wake whose token matches the
    // pending slot is handed off as `Effect::ClearClipboard` (carrying
    // the bytes — see
    // `matching_token_wake_hands_clear_clipboard_effect_zeroizing_bytes`).
    // The reducer must clear `pending_clipboard_clear` to `None` on the
    // post-state so the buffer drops out of `AppState` and the
    // `Zeroizing<Vec<u8>>` carried by the dispatched effect is the
    // sole remaining owner — its `Drop` (run by the executor after
    // the wipe) wipes the bytes. A duplicate wake then no-ops.
    let tmp = secure_tempdir();
    let (_p, (mut vault, store)) = open_plaintext_pair(&tmp);
    enable_clipboard_clear(&mut vault, &store, 30);
    let (token, deadline) = ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
        .expect("schedule yields Some when clipboard_clear_enabled");
    drop((vault, store));

    let path = PathBuf::from("/tmp/v.bin");
    let captured = copy_bytes();
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token,
            value: Zeroizing::new(captured.clone()),
            deadline,
        }),
    };
    let (next, effects) = reduce(
        state,
        AppEvent::ClipboardClear {
            token,
            value: Zeroizing::new(captured.clone()),
        },
    );

    match &effects[..] {
        [Effect::ClearClipboard { value }] => {
            let _: &Zeroizing<Vec<u8>> = value;
            assert_eq!(value.as_slice(), captured.as_slice());
        }
        other => panic!("expected one Effect::ClearClipboard, got {other:?}"),
    }
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path);
            assert!(
                pending_clipboard_clear.is_none(),
                "matching-token wake must consume the pending slot so the buffer drops out of state, got {pending_clipboard_clear:?}",
            );
        }
        other => panic!("expected Locked with cleared pending slot, got {other:?}"),
    }
}

#[test]
fn stale_token_wake_drops_event_zeroizing_bytes_and_preserves_pending() {
    // Stale-token-drop axis. The reducer rejects a wake whose token
    // does not match the (fresher) pending slot. The wake event's
    // `value: Zeroizing<Vec<u8>>` is consumed by `reduce` (moved in
    // by value) and dropped on the rejection path — its `Drop` wipes
    // the bytes before the backing allocation is freed. The pending
    // slot itself stays intact so the *fresher* timer thread's later
    // wake can still find it.
    let tmp = secure_tempdir();
    let (_p, (mut vault, store)) = open_plaintext_pair(&tmp);
    enable_clipboard_clear(&mut vault, &store, 60);
    let (stale_token, _stale_deadline) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
            .expect("stale schedule yields Some");
    let (fresh_token, fresh_deadline) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
            .expect("fresh schedule yields Some");
    drop((vault, store));
    assert!(
        fresh_token > stale_token,
        "monotonic token precondition: fresh > stale",
    );

    let path = PathBuf::from("/tmp/v.bin");
    let fresh_value: Vec<u8> = b"fresh!".to_vec();
    let stale_value: Vec<u8> = b"stale!".to_vec();
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token: fresh_token,
            value: Zeroizing::new(fresh_value.clone()),
            deadline: fresh_deadline,
        }),
    };

    // Type binding: the event we hand to `reduce` owns a
    // `Zeroizing<Vec<u8>>`. The reducer's stale-token branch drops
    // the event (no field destructure carries the bytes out), so the
    // wrapper's `Drop` runs and wipes the bytes here.
    let event = AppEvent::ClipboardClear {
        token: stale_token,
        value: Zeroizing::new(stale_value.clone()),
    };
    match &event {
        AppEvent::ClipboardClear { value, .. } => {
            let _: &Zeroizing<Vec<u8>> = value;
        }
        _ => unreachable!(),
    }

    let (next, effects) = reduce(state, event);
    assert!(
        effects.is_empty(),
        "stale-token wake must not dispatch any effect, got {effects:?}",
    );
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear: Some(pending),
        } => {
            assert_eq!(p, path);
            assert_eq!(
                pending.token, fresh_token,
                "fresher pending must survive a stale wake",
            );
            assert_eq!(
                pending.value.as_slice(),
                fresh_value.as_slice(),
                "fresher pending bytes must survive a stale wake byte-for-byte",
            );
            let _: &Zeroizing<Vec<u8>> = &pending.value;
        }
        other => panic!("expected Locked with fresher pending preserved, got {other:?}",),
    }
}

#[test]
fn replacement_copy_drops_prior_pending_value_via_zeroizing_drop() {
    // Replacement axis. A second successful `EffectResult::CopyCode`
    // on `Unlocked` issues a fresh `(token, deadline)` from
    // `ClipboardClearPolicy::schedule` and overwrites the prior
    // `pending_clipboard_clear` slot. The prior `PendingClipboardClear`
    // (and its `Zeroizing<Vec<u8>>`) is dropped in place by the
    // assignment, so the captured bytes wipe before the backing
    // allocation is freed. The replacement carries the *fresh* copy's
    // bytes — not residue from the prior pending — so a snapshot of
    // the post-state shows the prior bytes are gone.
    let tmp = secure_tempdir();
    let (path, (mut vault, store)) = open_plaintext_pair(&tmp);
    let totp_id = add_totp_account(&mut vault, &store, "github");
    enable_clipboard_clear(&mut vault, &store, 30);
    let (earlier_token, earlier_deadline) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
            .expect("prior schedule yields Some");
    let prior_value: Vec<u8> = b"old".to_vec();
    let prior = PendingClipboardClear {
        token: earlier_token,
        value: Zeroizing::new(prior_value.clone()),
        deadline: earlier_deadline,
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
    let fresh_bytes = copy_bytes();
    let event = AppEvent::EffectResult(EffectResult::CopyCode {
        account_id: totp_id,
        result: Ok(Zeroizing::new(fresh_bytes.clone())),
        completed_at,
    });
    let (next, _) = reduce(state, event);
    match next {
        AppState::Unlocked {
            pending_clipboard_clear: Some(pending),
            ..
        } => {
            assert!(
                pending.token > earlier_token,
                "replacement must issue a strictly-greater monotonic token",
            );
            assert_eq!(
                pending.value.as_slice(),
                fresh_bytes.as_slice(),
                "replacement slot must carry the fresh bytes (not residue from the prior pending)",
            );
            assert_ne!(
                pending.value.as_slice(),
                prior_value.as_slice(),
                "post-replacement value must not equal the prior captured bytes",
            );
            let _: &Zeroizing<Vec<u8>> = &pending.value;
        }
        other => panic!("expected Unlocked with replaced pending clipboard clear, got {other:?}",),
    }
}

#[test]
fn pending_clipboard_clear_drop_chain_zeroizes_value_via_zeroizing_drop() {
    // App-shutdown axis (regression sentinel). A direct
    // construct-and-`drop` exercises the wrapper's `Drop` chain
    // end-to-end so future refactors that swap `value` away from a
    // zeroizing wrapper fail this test. Concretely: at process exit
    // the runtime drops the `AppState`, which drops the
    // `PendingClipboardClear`, which drops its
    // `Zeroizing<Vec<u8>>`, whose `Drop` calls `Zeroize::zeroize` on
    // the inner `Vec<u8>` (covered as a contract by
    // `zeroizing_vec_zeroize_empties_buffer`). The shutdown path
    // has no observable side effect after the wipe (the memory is
    // freed), so this test functions as a compile-and-drop
    // sentinel: the type binding on `value` and the `drop(pending)`
    // call together pin the discipline in place.
    let tmp = secure_tempdir();
    let (_p, (mut vault, store)) = open_plaintext_pair(&tmp);
    enable_clipboard_clear(&mut vault, &store, 30);
    let (token, deadline) = ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
        .expect("schedule yields Some when clipboard_clear_enabled");

    let pending = PendingClipboardClear {
        token,
        value: Zeroizing::new(copy_bytes()),
        deadline,
    };
    // Type binding: refactoring `PendingClipboardClear.value` to
    // anything other than `Zeroizing<Vec<u8>>` would fail to compile
    // here, breaking the app-shutdown zeroize contract loudly.
    let _: &Zeroizing<Vec<u8>> = &pending.value;
    assert_eq!(
        pending.value.as_slice(),
        copy_bytes().as_slice(),
        "precondition: pending carries the sentinel bytes before drop",
    );

    // Explicit drop exercises the `Drop` chain (PendingClipboardClear
    // → Zeroizing<Vec<u8>> → Zeroize::zeroize on Vec<u8>) at a
    // well-defined point — the same chain runs implicitly when the
    // `AppState` drops at process exit.
    drop(pending);
}

// ---------------------------------------------------------------------------
// Executor (`paladin_tui::app::effect::execute`) — only-if-unchanged
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Clipboard auto-clear)
//
//   * Bullet 4: *"\"Only-if-unchanged\" honored when an external copy
//     mutates the clipboard between copy and wake."*
//   * Bullet 6: *"Clipboard flows are exercised through the
//     `PALADIN_CLIPBOARD_DRYRUN=1` adapter hook so they run without a
//     clipboard server."*
//
// On `Effect::ClearClipboard`, the executor reads the live clipboard,
// calls `ClipboardClearPolicy::should_clear(captured, current)`, and
// writes empty only when the comparison returns `true`. The test
// hooks below replace the production `arboard` backend with an
// in-process fake addressable through `seed_test_clipboard` /
// `read_test_clipboard`, gated on `PALADIN_CLIPBOARD_DRYRUN=1` so the
// production path stays untouched outside
// `cargo test … --features test-hooks`. The `fail` mode forces both
// read and write to return `Err(())` so the executor's failure
// branches stay covered without a live system clipboard. A
// process-wide `test_clipboard_lock` mutex serializes the env-var
// manipulation across the `cargo test` thread pool.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-hooks")]
mod executor_only_if_unchanged {
    use super::*;

    use std::sync::mpsc;

    use paladin_tui::app::effect::{execute, EffectOutcome};
    use paladin_tui::clipboard::{read_test_clipboard, seed_test_clipboard, test_clipboard_lock};

    /// Run `body` with `PALADIN_CLIPBOARD_DRYRUN=mode` and the
    /// process-wide test-clipboard lock held. The env var is removed
    /// on the way out so a panicking test cannot leak state into the
    /// next; the mutex guard runs first to flush poisoning before the
    /// env var cleanup.
    fn with_dryrun<R>(mode: &str, body: impl FnOnce() -> R) -> R {
        let _guard = test_clipboard_lock();
        std::env::set_var("PALADIN_CLIPBOARD_DRYRUN", mode);
        let out = body();
        std::env::remove_var("PALADIN_CLIPBOARD_DRYRUN");
        out
    }

    #[test]
    fn dryrun_adapter_round_trip_writes_and_reads_in_process_fake() {
        with_dryrun("1", || {
            seed_test_clipboard("");
            assert!(
                paladin_tui::clipboard::ClipboardSession::new()
                    .write_text("abc123")
                    .is_ok(),
                "PALADIN_CLIPBOARD_DRYRUN=1 must accept writes via the fake"
            );
            assert_eq!(
                read_test_clipboard(),
                "abc123",
                "DRYRUN write must land in the in-process fake clipboard"
            );
            assert_eq!(
                paladin_tui::clipboard::ClipboardSession::new().read_text(),
                Ok("abc123".to_string()),
                "DRYRUN read must return the same bytes the fake holds"
            );
        });
    }

    #[test]
    fn dryrun_adapter_fail_mode_returns_err_for_both_read_and_write() {
        with_dryrun("fail", || {
            assert_eq!(
                paladin_tui::clipboard::ClipboardSession::new().write_text("ignored"),
                Err(()),
                "PALADIN_CLIPBOARD_DRYRUN=fail must surface a write error"
            );
            assert_eq!(
                paladin_tui::clipboard::ClipboardSession::new().read_text(),
                Err(()),
                "PALADIN_CLIPBOARD_DRYRUN=fail must surface a read error"
            );
        });
    }

    #[test]
    fn execute_clear_clipboard_writes_empty_when_live_clipboard_still_matches() {
        with_dryrun("1", || {
            seed_test_clipboard("123456");
            let mut state = AppState::Locked {
                path: PathBuf::from("/tmp/v.bin"),
                pending_clipboard_clear: None,
            };
            let (tx, rx) = mpsc::channel();
            let outcome = execute(
                Effect::ClearClipboard {
                    value: Zeroizing::new(b"123456".to_vec()),
                },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "Effect::ClearClipboard emits no AppEvent at this layer"
            );
            assert_eq!(
                read_test_clipboard(),
                "",
                "live clipboard byte-equals captured: executor must write empty"
            );
        });
    }

    #[test]
    fn execute_clear_clipboard_preserves_clipboard_when_external_copy_intervenes() {
        // The headline only-if-unchanged contract: a user (or another
        // app) copied something else between the copy effect and the
        // wake; the captured-vs-current byte comparison must fail and
        // the executor must keep its hands off the live clipboard so
        // the user's later selection survives.
        with_dryrun("1", || {
            seed_test_clipboard("user-pasted-other-content");
            let mut state = AppState::Locked {
                path: PathBuf::from("/tmp/v.bin"),
                pending_clipboard_clear: None,
            };
            let (tx, rx) = mpsc::channel();
            let outcome = execute(
                Effect::ClearClipboard {
                    value: Zeroizing::new(b"123456".to_vec()),
                },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(
                rx.try_recv().is_err(),
                "Effect::ClearClipboard emits no AppEvent at this layer"
            );
            assert_eq!(
                read_test_clipboard(),
                "user-pasted-other-content",
                "captured bytes differ from live clipboard: executor must not write"
            );
        });
    }

    #[test]
    fn execute_clear_clipboard_preserves_clipboard_when_live_is_empty() {
        // Edge case of the same rule: another app cleared the
        // clipboard after the copy. The captured non-empty bytes do
        // not byte-equal an empty live clipboard, so the executor
        // must leave it alone (writing empty would be a no-op in
        // outcome but still violates the "only-if-unchanged" rule
        // when the policy returns `false`).
        with_dryrun("1", || {
            seed_test_clipboard("");
            let mut state = AppState::Locked {
                path: PathBuf::from("/tmp/v.bin"),
                pending_clipboard_clear: None,
            };
            let (tx, _rx) = mpsc::channel();
            let outcome = execute(
                Effect::ClearClipboard {
                    value: Zeroizing::new(b"123456".to_vec()),
                },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert_eq!(
                read_test_clipboard(),
                "",
                "empty-but-different live clipboard: executor must not write"
            );
        });
    }

    #[test]
    fn execute_clear_clipboard_noop_when_clipboard_read_fails() {
        // When the backend rejects the read (DRYRUN=fail or a real
        // arboard error), the executor must not call write — it
        // cannot know whether the live clipboard matches captured.
        // The effect drops cleanly and the run loop continues.
        with_dryrun("fail", || {
            let mut state = AppState::Locked {
                path: PathBuf::from("/tmp/v.bin"),
                pending_clipboard_clear: None,
            };
            let (tx, rx) = mpsc::channel();
            let outcome = execute(
                Effect::ClearClipboard {
                    value: Zeroizing::new(b"123456".to_vec()),
                },
                &mut state,
                &tx,
                &mut paladin_tui::clipboard::ClipboardSession::new(),
            );
            assert_eq!(outcome, EffectOutcome::Continue);
            assert!(rx.try_recv().is_err());
        });
    }
}

// ---------------------------------------------------------------------------
// Clipboard image adapter — `read_image` (docs/IMPLEMENTATION_PLAN_03_TUI.md >
// Implementation checklist: "Implement clipboard wrapper (arboard
// reads/writes), QR image import from clipboard bytes, ...").
//
// `read_image` is the third adapter primitive (alongside `read_text` /
// `write_text`). Production calls `arboard::Clipboard::get_image()` and
// re-shapes the returned bytes into a stable `ClipboardImage { width,
// height, rgba }` shape that does not leak the `arboard` type into
// `paladin-tui`'s public surface. Errors collapse to two variants the
// executor maps onto `QrImportFailure::{NoClipboardImage,
// ImageDecodeFailure}` — distinct user-facing wording per
// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Add modal" QR-import bullets:
// *"No-image, no-QR, and invalid-QR cases reject inline."*
//
// Under `paladin-tui/test-hooks` the same env-var protocol used for
// `read_text` / `write_text` covers images: `PALADIN_CLIPBOARD_DRYRUN=1`
// returns an in-process seeded image (or `NoImage` when not seeded);
// `=fail` returns `DecodeFailure` so both inline-error wordings are
// reachable from CI.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-hooks")]
mod adapter_read_image {
    use paladin_tui::clipboard::{
        clear_test_clipboard_image, seed_test_clipboard_image, test_clipboard_lock, ClipboardImage,
        ImageReadError,
    };

    /// Run `body` with `PALADIN_CLIPBOARD_DRYRUN=mode`, the process-wide
    /// test-clipboard lock held, and the fake image cleared on exit so
    /// the next test cannot see leaked state.
    fn with_dryrun_image<R>(mode: &str, body: impl FnOnce() -> R) -> R {
        let _guard = test_clipboard_lock();
        std::env::set_var("PALADIN_CLIPBOARD_DRYRUN", mode);
        let out = body();
        std::env::remove_var("PALADIN_CLIPBOARD_DRYRUN");
        clear_test_clipboard_image();
        out
    }

    #[test]
    fn dryrun_image_round_trip_returns_seeded_dimensions_and_bytes() {
        with_dryrun_image("1", || {
            // 2x1 RGBA8 image — 8 bytes — opaque red then opaque blue.
            let rgba: Vec<u8> = vec![255, 0, 0, 255, 0, 0, 255, 255];
            seed_test_clipboard_image(2, 1, rgba.clone());
            match paladin_tui::clipboard::ClipboardSession::new().read_image() {
                Ok(ClipboardImage {
                    width,
                    height,
                    rgba: out,
                }) => {
                    assert_eq!(width, 2, "seeded width must round-trip");
                    assert_eq!(height, 1, "seeded height must round-trip");
                    assert_eq!(out, rgba, "seeded RGBA bytes must round-trip");
                }
                other => panic!("expected Ok(ClipboardImage), got {other:?}"),
            }
        });
    }

    #[test]
    fn dryrun_image_returns_no_image_when_clipboard_unseeded() {
        with_dryrun_image("1", || {
            clear_test_clipboard_image();
            assert_eq!(
                paladin_tui::clipboard::ClipboardSession::new().read_image(),
                Err(ImageReadError::NoImage),
                "DRYRUN=1 without a seeded image must surface NoImage"
            );
        });
    }

    #[test]
    fn dryrun_image_fail_mode_returns_decode_failure() {
        with_dryrun_image("fail", || {
            assert_eq!(
                paladin_tui::clipboard::ClipboardSession::new().read_image(),
                Err(ImageReadError::DecodeFailure),
                "DRYRUN=fail must surface DecodeFailure so the executor \
                 reaches the QrImportFailure::ImageDecodeFailure branch"
            );
        });
    }

    #[test]
    fn dryrun_image_seed_overwrites_prior_seed() {
        // Each `seed_test_clipboard_image` replaces any prior seed so
        // tests do not accumulate stale image state across calls
        // within the same `with_dryrun_image` block.
        with_dryrun_image("1", || {
            seed_test_clipboard_image(2, 1, vec![1, 2, 3, 4, 5, 6, 7, 8]);
            seed_test_clipboard_image(1, 1, vec![9, 9, 9, 9]);
            match paladin_tui::clipboard::ClipboardSession::new().read_image() {
                Ok(ClipboardImage {
                    width,
                    height,
                    rgba,
                }) => {
                    assert_eq!(width, 1);
                    assert_eq!(height, 1);
                    assert_eq!(rgba, vec![9, 9, 9, 9]);
                }
                other => panic!("expected Ok(ClipboardImage), got {other:?}"),
            }
        });
    }

    #[test]
    fn dryrun_image_clear_seed_returns_no_image_on_subsequent_read() {
        with_dryrun_image("1", || {
            seed_test_clipboard_image(1, 1, vec![1, 2, 3, 4]);
            assert!(
                paladin_tui::clipboard::ClipboardSession::new()
                    .read_image()
                    .is_ok(),
                "sanity: seed should succeed"
            );
            clear_test_clipboard_image();
            assert_eq!(
                paladin_tui::clipboard::ClipboardSession::new().read_image(),
                Err(ImageReadError::NoImage),
                "after clear, the fake clipboard image must report NoImage"
            );
        });
    }
}
