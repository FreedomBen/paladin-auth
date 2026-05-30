// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto-lock idle-deadline and lock-transition tests for `paladin-tui`.
//!
//! Tracks the "Tests > Auto-lock (`tests/auto_lock_tests.rs`)" checklist
//! in `docs/IMPLEMENTATION_PLAN_03_TUI.md`.

mod common;

use common::test_tempdir;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use secrecy::SecretString;
use zeroize::Zeroizing;

use paladin_core::{
    hotp_reveal_deadline, validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm,
    Argon2Params, ClipboardClearPolicy, ClipboardClearToken, EncryptionOptions, IconHintInput,
    Store, Vault, VaultInit, VaultLock,
};
use paladin_tui::app::event::{AppEvent, Effect};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{
    AppState, ChordLeader, EditFocus, EditIconHintSelector, EditModal, EditPrior, Focus,
    HotpReveal, Modal, PassphraseModal, PendingClipboardClear, QrExportFocus, QrSaveFocus,
    QrSaveFormat, QrSaveStep,
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

fn key_input_at(code: KeyCode, at: Instant) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        at,
    }
}

fn tick_at(monotonic: Instant) -> AppEvent {
    AppEvent::Tick {
        wall_clock: SystemTime::now(),
        monotonic,
    }
}

// ---------------------------------------------------------------------------
// `idle_deadline` resets on any `AppEvent::Input`
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 2)
//
// Slice covered: every `AppEvent::Input` that lands while the state is
// `Unlocked` refreshes the auto-lock idle deadline via
// `paladin_core::IdlePolicy::next_deadline(at, is_encrypted, settings)`,
// rebased on the event's `at` instant. Plaintext vaults and encrypted
// vaults with `auto_lock_enabled = false` stay `None` because
// `IdlePolicy::should_arm` is `false` — the TUI must not paper over the
// core rule.
// ---------------------------------------------------------------------------

#[test]
fn input_in_encrypted_unlocked_with_auto_lock_rebases_idle_deadline_on_event_at() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(t0 + Duration::from_secs(600)),
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

    let t1 = t0 + Duration::from_secs(123);
    let (next, effects) = reduce(state, key_input_at(KeyCode::Down, t1));
    assert!(
        effects.is_empty(),
        "Down on Unlocked is a no-op for effects"
    );
    match next {
        AppState::Unlocked { idle_deadline, .. } => {
            assert_eq!(
                idle_deadline,
                Some(t1 + Duration::from_secs(600)),
                "idle_deadline must rebase on the event's `at` timestamp"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn input_in_plaintext_unlocked_keeps_idle_deadline_none_even_if_auto_lock_enabled() {
    // The plaintext-no-op rule (`IdlePolicy::should_arm`) must hold even
    // after the user toggled `auto_lock_enabled = true` on the
    // (plaintext) vault. Input must not arm the deadline.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(600)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit settings");

    let state = AppState::Unlocked {
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

    let (next, effects) = reduce(state, key_input_at(KeyCode::Char('x'), Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { idle_deadline, .. } => assert_eq!(idle_deadline, None),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn input_in_encrypted_unlocked_with_auto_lock_disabled_keeps_idle_deadline_none() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (vault, store) = create_encrypted_pair(&path, "pp");
    assert!(
        !vault.settings().auto_lock_enabled(),
        "fixture default must be auto_lock_enabled = false"
    );

    let state = AppState::Unlocked {
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

    let (next, effects) = reduce(state, key_input_at(KeyCode::Char('x'), Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { idle_deadline, .. } => assert_eq!(idle_deadline, None),
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn non_key_input_in_encrypted_unlocked_also_rebases_idle_deadline() {
    // "Idle is reset by any `AppEvent::Input`." — resize, focus, paste,
    // mouse events all reset the deadline. Resize stands in for the
    // non-Key variants here.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(t0 + Duration::from_secs(600)),
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

    let t1 = t0 + Duration::from_secs(45);
    let evt = AppEvent::Input {
        event: Event::Resize(80, 24),
        at: t1,
    };
    let (next, effects) = reduce(state, evt);
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked { idle_deadline, .. } => {
            assert_eq!(idle_deadline, Some(t1 + Duration::from_secs(600)));
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tick-driven `Unlocked → Locked` transition
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 3)
//
// On each `paladin_core::TICK_INTERVAL_MS` `Tick` the reducer asks
// `IdlePolicy::is_expired(deadline, monotonic)` and, if true, transitions
// `Unlocked → Locked { path }` so the in-memory `Vault` / `Store` drop in
// place. Pre-deadline Ticks, `None`-deadline Unlocked states (plaintext /
// disabled), and Ticks on non-`Unlocked` screens are passthrough. Boundary
// case: `monotonic == deadline` fires the lock because
// `IdlePolicy::is_expired` uses `now >= deadline`.
// ---------------------------------------------------------------------------

#[test]
fn tick_after_deadline_locks_unlocked_state() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(deadline),
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

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_after_deadline_lock_discards_unlocked_search_query() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 6:
    // "Locking discards the Vault / Store, open HOTP reveal windows,
    // the search query, and any modal while retaining the resolved
    // vault path for the next unlock attempt." This test covers the
    // search-query slice: a non-empty filter buffer present at the
    // moment of lock must be gone from the resulting `Locked` state,
    // which by construction carries only `path`. The Vault and Store
    // are likewise gone because the variant change drops them.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: "github".to_string(),
        idle_deadline: Some(deadline),
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

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked { path: p, .. } => {
            assert_eq!(p, path, "Locked must carry the original vault path");
        }
        other => panic!("expected Locked (search query and vault must be gone), got {other:?}"),
    }
}

#[test]
fn tick_after_deadline_lock_discards_unlocked_hotp_reveal() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 6:
    // "Locking discards the Vault / Store, open HOTP reveal windows,
    // the search query, and any modal while retaining the resolved
    // vault path for the next unlock attempt." This test covers the
    // HOTP-reveal slice: an open reveal window (the account being
    // revealed, the `counter_used` that produced the visible code,
    // the displayed code bytes, and the monotonic reveal deadline)
    // present at the moment of lock must be gone from the resulting
    // `Locked` state, which by construction carries only `path` (plus
    // any pending clipboard clear). The Vault and Store are likewise
    // gone because the variant change drops them.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let idle_deadline = t0 + Duration::from_secs(600);
    let reveal = HotpReveal {
        account_id: AccountId::new(),
        counter_used: 7,
        code: SecretString::from("123456".to_string()),
        deadline: hotp_reveal_deadline(t0),
    };
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(idle_deadline),
        pending_clipboard_clear: None,
        hotp_reveal: Some(reveal),
        modal: None,
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };

    let now = idle_deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "Locked must carry the original vault path");
            assert!(
                pending_clipboard_clear.is_none(),
                "pending clipboard clear was None on entry; lock must not fabricate one"
            );
        }
        other => panic!("expected Locked (HOTP reveal and vault must be gone), got {other:?}"),
    }
}

#[test]
fn tick_after_deadline_lock_discards_unlocked_modal() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 6:
    // "Locking discards the Vault / Store, open HOTP reveal windows,
    // the search query, and any modal while retaining the resolved
    // vault path for the next unlock attempt." This test covers the
    // modal slice: an open modal present at the moment of lock must
    // be gone from the resulting `Locked` state, which by
    // construction carries only `path` (plus any pending clipboard
    // clear). `Modal::Passphrase` is chosen as the representative
    // case because, once its payload lands, it owns the most
    // secret-bearing modal-local buffer (the typed passphrase) —
    // making the discard-on-lock contract most consequential.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "Locked must carry the original vault path");
            assert!(
                pending_clipboard_clear.is_none(),
                "pending clipboard clear was None on entry; lock must not fabricate one"
            );
        }
        other => panic!("expected Locked (modal and vault must be gone), got {other:?}"),
    }
}

/// Add a TOTP account named `label` to `vault` and commit. Returns
/// the new `AccountId`.
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
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual TOTP input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added TOTP account");
    id
}

/// Assert preconditions for the QR-Export auto-lock test: the modal
/// must have `staged_ansi` populated, the Save PNG sub-flow open on
/// the path field with `path_text == expected_path`, and the idle
/// deadline rebased to `expected_deadline`.
fn assert_qr_export_modal_loaded(
    state: &AppState,
    expected_path: &str,
    expected_deadline: Instant,
) {
    match state {
        AppState::Unlocked {
            modal: Some(Modal::QrExport(qr)),
            idle_deadline,
            ..
        } => {
            assert!(qr.staged_ansi.is_some(), "the modal must have ANSI staged");
            assert_eq!(qr.focus, QrExportFocus::SavePngButton);
            let sub = qr
                .save_sub_flow
                .as_ref()
                .expect("Enter on Save PNG opens the sub-flow");
            assert_eq!(sub.format, QrSaveFormat::Png);
            assert_eq!(sub.step, QrSaveStep::EnterPath);
            assert_eq!(sub.focus, QrSaveFocus::PathField);
            assert_eq!(
                sub.path_text, expected_path,
                "typed path must populate the sub-flow's path buffer",
            );
            assert_eq!(
                *idle_deadline,
                Some(expected_deadline),
                "each input rebased to t0 + 600s so the Tick boundary is deterministic",
            );
        }
        other => panic!("expected Unlocked with QR Export modal + sub-flow, got {other:?}",),
    }
}

#[test]
fn auto_lock_with_qr_export_modal_open_drops_modal_and_rendered_buffers() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Modals (per §6) >
    // QR Export: "Auto-lock (encrypted vaults only, per
    // `IdlePolicy::should_arm`) with the QR Export modal open drops
    // the modal, the rendered ANSI / any in-flight PNG / SVG
    // buffers, **and** the in-memory vault, then re-presents the
    // unlock screen."
    //
    // Slice covered: a fully-loaded QR Export modal — `staged_ansi`
    // populated, the Save PNG sub-flow open with a typed destination
    // path — must be discarded alongside the `Vault` / `Store` on the
    // idle-expiry Tick. The resulting `Locked` carries only the
    // resolved vault path so the UI can re-present the unlock screen
    // on the next render pass.
    //
    // The modal is driven through the reducer (Q → Enter → typed
    // path) so `staged_ansi` is populated by the real open path
    // rather than fabricated; that wires the zeroizing buffer drop
    // through the same code path the runtime uses. Each input event
    // passes `t0` as its `at` instant so
    // every reducer call rebases `idle_deadline` to `t0 + 600s` —
    // the lock Tick is then `t0 + 600s + 1ms`, guaranteed past the
    // deadline.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);
    let account_id = add_totp_account(&mut vault, &store, "alice");

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(account_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };

    // Q → open QR Export modal directly on the QR view; `staged_ansi`
    // is populated and focus lands on `SavePngButton`.
    let (state, _) = reduce(state, key_input_at(KeyCode::Char('Q'), t0));
    // Enter on Save PNG button → open the destination-path sub-flow.
    let (state, _) = reduce(state, key_input_at(KeyCode::Enter, t0));
    // Type a destination path so `save_sub_flow.path_text` is non-empty.
    let dest_path = tmp.path().join("alice.png");
    let dest_text = dest_path.to_str().expect("utf-8 path");
    let mut state = state;
    for ch in dest_text.chars() {
        let (next, _) = reduce(state, key_input_at(KeyCode::Char(ch), t0));
        state = next;
    }

    assert_qr_export_modal_loaded(&state, dest_text, deadline);

    // Tick past the idle deadline — auto-lock must fire even with a
    // fully loaded QR Export modal open. The `Modal::QrExport(_)`
    // payload (with its `Zeroizing<String>` ANSI buffer) and the
    // `QrSaveSubFlow` (carrying the typed destination path) are
    // dropped alongside the `Vault` / `Store`; the resulting
    // `Locked` carries only the vault path so the UI re-presents the
    // unlock screen on the next render.
    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(
        effects.is_empty(),
        "auto-lock Tick must not emit effects; got {effects:?}",
    );
    match next {
        AppState::Locked {
            path: locked_path,
            pending_clipboard_clear,
        } => {
            assert_eq!(
                locked_path, path,
                "Locked must carry the resolved vault path for the next unlock attempt",
            );
            assert!(
                pending_clipboard_clear.is_none(),
                "pending clipboard clear was None on entry; lock must not fabricate one",
            );
        }
        other => panic!(
            "expected Locked (QR Export modal, staged ANSI, save sub-flow, and vault must be gone), got {other:?}",
        ),
    }
}

#[test]
fn tick_after_deadline_lock_discards_unlocked_pending_chord_leader() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Vim-style navigation
    // bullet: "Pending-leader chord state is held by the reducer,
    // committed on the matching second press, and cleared by any
    // non-matching key, focus change, modal open, `Esc`, or
    // auto-lock." This test covers the auto-lock half of that
    // clear-pending contract: an in-flight chord leader present at
    // the moment of the idle-expiry tick must be dropped alongside
    // the `Vault` / `Store` rather than carried into `Locked` (the
    // `Locked` variant has no chord-leader field, so the contract is
    // structural — this test locks it in against a future refactor
    // that might introduce one). `ChordLeader::G` is the
    // representative case; `Z` rides on the same destructure.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: None,
        pending_chord_leader: Some(ChordLeader::G),
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "Locked must carry the original vault path");
            assert!(
                pending_clipboard_clear.is_none(),
                "pending clipboard clear was None on entry; lock must not fabricate one"
            );
        }
        other => {
            panic!("expected Locked (pending chord leader and vault must be gone), got {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// Clipboard auto-clear survives lock
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 7)
//
// State-carry-across-lock slice: a `PendingClipboardClear` present on
// `Unlocked` at the moment of the idle-expiry tick is carried
// unchanged through to the resulting `Locked` state — token,
// captured bytes, and the scheduled wake-deadline all survive the
// variant change.
// ---------------------------------------------------------------------------

#[test]
fn tick_after_deadline_lock_carries_pending_clipboard_clear() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clear secs within bounds");

    let t0 = Instant::now();
    let (token, clear_deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("clipboard clear scheduled");
    let pending = PendingClipboardClear {
        token,
        value: Zeroizing::new(vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36]),
        deadline: clear_deadline,
    };

    let idle_deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(idle_deadline),
        pending_clipboard_clear: Some(pending),
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

    let now = idle_deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path);
            let p_clear =
                pending_clipboard_clear.expect("pending clear survives the lock transition");
            assert_eq!(p_clear.token, token, "token survives unchanged");
            assert_eq!(
                p_clear.value.as_slice(),
                &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36],
                "captured bytes survive unchanged"
            );
            assert_eq!(
                p_clear.deadline, clear_deadline,
                "wake-deadline survives unchanged"
            );
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_after_deadline_lock_with_no_pending_clipboard_clear_yields_none() {
    // The default Unlocked has no pending clear; the post-lock state
    // must reflect that — i.e. `pending_clipboard_clear == None` on
    // `Locked` — so a stale `Some(...)` cannot be fabricated by the
    // transition path.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(deadline),
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

    let now = deadline + Duration::from_millis(1);
    let (next, _effects) = reduce(state, tick_at(now));
    match next {
        AppState::Locked {
            pending_clipboard_clear,
            ..
        } => {
            assert!(
                pending_clipboard_clear.is_none(),
                "no pending clear must remain `None` after lock"
            );
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `AppEvent::ClipboardClear` wake handler on `Locked`
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 7, second half)
//
// When the clipboard auto-clear timer that survived the
// `Unlocked → Locked` lock fires its delayed
// `AppEvent::ClipboardClear { token, value }`, the reducer:
//
// * with a matching token on `pending_clipboard_clear`, emits a single
//   [`Effect::ClearClipboard { value }`] carrying the captured bytes
//   from state and clears `pending_clipboard_clear` to `None`;
// * with a stale token (a fresher copy issued a new token and replaced
//   the pending state), drops the wake event with no state change and
//   no effect;
// * with no pending clear, is a no-op.
// ---------------------------------------------------------------------------

fn clipboard_clear_event(token: ClipboardClearToken, value: Vec<u8>) -> AppEvent {
    AppEvent::ClipboardClear {
        token,
        value: Zeroizing::new(value),
    }
}

#[test]
fn clipboard_clear_event_on_locked_with_matching_token_fires_wipe_and_clears_pending() {
    let path = PathBuf::from("/tmp/v.bin");
    let captured = vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
    // A schedule done from a real `VaultSettings` issues a real
    // `ClipboardClearToken`; the test mirrors that to avoid hand-rolling
    // tokens (which the policy module doesn't expose as a public ctor).
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted_pair(&tmp.path().join("issuer.bin"), "pp");
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clear secs within bounds");
    let t0 = Instant::now();
    let (token, deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("clipboard clear scheduled");
    drop(vault);
    drop(store);

    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token,
            value: Zeroizing::new(captured.clone()),
            deadline,
        }),
    };

    let (next, effects) = reduce(state, clipboard_clear_event(token, captured.clone()));

    match &effects[..] {
        [Effect::ClearClipboard { value }] => {
            assert_eq!(
                value.as_slice(),
                captured.as_slice(),
                "wipe effect must carry the captured bytes from pending state"
            );
        }
        other => panic!("expected exactly one Effect::ClearClipboard, got {other:?}"),
    }
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "Locked path must carry over");
            assert!(
                pending_clipboard_clear.is_none(),
                "matching-token wake hands the wipe to the executor; pending state clears"
            );
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn clipboard_clear_event_on_locked_with_stale_token_is_noop() {
    // A second copy after the first issues a fresh, strictly-greater
    // token via `ClipboardClearPolicy::schedule`. The first timer's
    // delayed `AppEvent::ClipboardClear` then arrives with the *old*
    // token; the reducer must drop it without state change and
    // without emitting a wipe effect — the newer pending state owns
    // the only valid clear.
    let path = PathBuf::from("/tmp/v.bin");
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted_pair(&tmp.path().join("issuer.bin"), "pp");
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clear secs within bounds");
    let t0 = Instant::now();
    let (stale_token, _stale_deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("first schedule");
    let (fresh_token, fresh_deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("second schedule");
    assert_ne!(
        stale_token, fresh_token,
        "successive schedule calls must issue distinct tokens"
    );
    drop(vault);
    drop(store);

    let fresh_value = vec![0x39, 0x39, 0x39, 0x39, 0x39, 0x39];
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token: fresh_token,
            value: Zeroizing::new(fresh_value.clone()),
            deadline: fresh_deadline,
        }),
    };

    let (next, effects) = reduce(
        state,
        clipboard_clear_event(stale_token, vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36]),
    );

    assert!(
        effects.is_empty(),
        "stale-token wake must not emit a wipe effect"
    );
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path);
            let p_clear =
                pending_clipboard_clear.expect("fresher pending state must survive a stale wake");
            assert_eq!(p_clear.token, fresh_token);
            assert_eq!(p_clear.value.as_slice(), fresh_value.as_slice());
            assert_eq!(p_clear.deadline, fresh_deadline);
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn clipboard_clear_event_on_locked_with_no_pending_is_noop() {
    // If the wake arrives after the pending clear has already fired
    // (or been dropped some other way), the reducer must not
    // fabricate a wipe — there is nothing to wipe a token against.
    let path = PathBuf::from("/tmp/v.bin");
    let tmp = secure_tempdir();
    let (mut vault, store) = create_encrypted_pair(&tmp.path().join("issuer.bin"), "pp");
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(30)
        .expect("clear secs within bounds");
    let (token, _deadline) = ClipboardClearPolicy::schedule(Instant::now(), vault.settings())
        .expect("schedule for token");
    drop(vault);
    drop(store);

    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: None,
    };

    let (next, effects) = reduce(state, clipboard_clear_event(token, Vec::new()));
    assert!(
        effects.is_empty(),
        "wake with no pending state must not emit a wipe effect"
    );
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path);
            assert!(pending_clipboard_clear.is_none());
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_exactly_at_deadline_locks_unlocked_state() {
    // `IdlePolicy::is_expired` uses `now >= deadline`, so a Tick that
    // lands exactly on the deadline must fire the lock — this protects
    // the TUI from re-deriving its own (looser) comparison.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(deadline),
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

    let (next, effects) = reduce(state, tick_at(deadline));
    assert!(effects.is_empty());
    match next {
        AppState::Locked { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_before_deadline_keeps_unlocked_state() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(deadline),
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

    let now = deadline
        .checked_sub(Duration::from_millis(1))
        .expect("pre-deadline instant in monotonic range");
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty());
    match next {
        AppState::Unlocked {
            idle_deadline,
            path: p,
            ..
        } => {
            assert_eq!(p, path);
            assert_eq!(
                idle_deadline,
                Some(deadline),
                "pre-deadline Tick must not rebase the deadline"
            );
        }
        other => panic!("expected Unlocked, got {other:?}"),
    }
}

#[test]
fn tick_with_no_deadline_keeps_unlocked_state() {
    // Plaintext / auto-lock-disabled vaults have `idle_deadline = None`.
    // A Tick must never fabricate a `Locked` transition from `None`.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");

    let state = AppState::Unlocked {
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

    let (next, effects) = reduce(state, tick_at(Instant::now()));
    assert!(effects.is_empty());
    match next {
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
fn tick_on_locked_state_is_passthrough() {
    // A Tick that arrives while the state is already `Locked` is a
    // no-op (no re-lock churn, no path drift).
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Locked {
        path: path.clone(),
        pending_clipboard_clear: None,
    };

    let (next, effects) = reduce(state, tick_at(Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Locked { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn tick_on_unlock_screen_is_passthrough() {
    use paladin_tui::prompt::PassphraseBuffer;
    let path = PathBuf::from("/tmp/v.bin");
    let state = AppState::Unlock {
        path: path.clone(),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };

    let (next, effects) = reduce(state, tick_at(Instant::now()));
    assert!(effects.is_empty());
    match next {
        AppState::Unlock { path: p, .. } => assert_eq!(p, path),
        other => panic!("expected Unlock, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Setting persists across saves
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — bullet 5)
//
// Slice covered: `auto_lock_enabled` and `auto_lock_timeout_secs`
// survive a `Vault::save` + `Store::open` round-trip on both vault
// modes. For plaintext vaults the values are inert at runtime (the
// `IdlePolicy::should_arm` plaintext-no-op rule), but the setting
// itself is still persisted so it takes effect if the vault is later
// encrypted via `passphrase set`. Foundational guarantee for the
// Settings modal slice (still ahead): once that modal lands and
// commits settings via `Vault::mutate_and_save`, the persisted state
// must come back identically after reopen.
// ---------------------------------------------------------------------------

#[test]
fn auto_lock_setting_persists_across_save_reopen_encrypted() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(900)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit settings");
    drop(vault);
    drop(store);

    let (reopened, _store) = Store::open(
        &path,
        VaultLock::Encrypted(SecretString::from("pp".to_string())),
    )
    .expect("reopen encrypted vault");
    assert!(
        reopened.settings().auto_lock_enabled(),
        "auto_lock_enabled must survive encrypted save + reopen"
    );
    assert_eq!(
        reopened.settings().auto_lock_timeout_secs(),
        900,
        "auto_lock_timeout_secs must survive encrypted save + reopen"
    );
}

#[test]
fn auto_lock_setting_persists_across_save_reopen_plaintext() {
    // Plaintext-no-op rule (§6 / §7): the setting is inert at
    // runtime but must still be persisted so it activates if the
    // vault is later encrypted via `passphrase set`.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.set_auto_lock_enabled(true);
    vault
        .set_auto_lock_timeout_secs(900)
        .expect("timeout within bounds");
    vault.save(&store).expect("commit settings");
    drop(vault);
    drop(store);

    let (reopened, _store) =
        Store::open(&path, VaultLock::Plaintext).expect("reopen plaintext vault");
    assert!(
        reopened.settings().auto_lock_enabled(),
        "auto_lock_enabled must survive plaintext save + reopen even though inert"
    );
    assert_eq!(
        reopened.settings().auto_lock_timeout_secs(),
        900,
        "auto_lock_timeout_secs must survive plaintext save + reopen"
    );
}

// ---------------------------------------------------------------------------
// Clipboard auto-clear timer scheduled before lock survives lock and still
// fires only-if-unchanged
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Auto-lock — last bullet)
//
// End-to-end shape: schedule a clipboard clear on `Unlocked`, let a `Tick`
// past the idle deadline lock the state (the lock window comes before the
// clear-deadline), and verify `pending_clipboard_clear` survives the variant
// change verbatim. The deferred `AppEvent::ClipboardClear { token, value }`
// on `Locked` must emit exactly one `Effect::ClearClipboard { value }`
// carrying the captured bytes — the input the executor needs to apply
// `ClipboardClearPolicy::should_clear` ("only-if-unchanged").
// ---------------------------------------------------------------------------

#[test]
fn clipboard_clear_timer_scheduled_before_lock_survives_and_fires_after_lock() {
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    // Auto-lock fires well before the clipboard clear timer, so the
    // wake event arrives on `Locked`, not `Unlocked`. The minimum
    // `auto_lock_timeout_secs` is 30 and the maximum
    // `clipboard_clear_secs` is 600 (per `ui_contract`), so the lock
    // is guaranteed to land before the clipboard clear deadline.
    enable_auto_lock(&mut vault, &store, 30);
    vault.set_clipboard_clear_enabled(true);
    vault
        .set_clipboard_clear_secs(600)
        .expect("clear secs within bounds");

    let t0 = Instant::now();
    let (token, clear_deadline) =
        ClipboardClearPolicy::schedule(t0, vault.settings()).expect("clipboard clear scheduled");
    let captured: Vec<u8> = vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36];

    // Idle deadline comes from the 30s auto-lock timeout; the clear
    // deadline is 600s out — guaranteed to be after the lock.
    let idle_deadline = t0 + Duration::from_secs(30);
    assert!(
        clear_deadline > idle_deadline,
        "test invariant: clear must be scheduled after the lock window"
    );

    let unlocked = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(idle_deadline),
        pending_clipboard_clear: Some(PendingClipboardClear {
            token,
            value: Zeroizing::new(captured.clone()),
            deadline: clear_deadline,
        }),
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

    // Step 1: a tick past the idle deadline locks the vault; the
    // pending clear must ride the variant change verbatim.
    let lock_at = idle_deadline + Duration::from_millis(1);
    let (locked, lock_effects) = reduce(unlocked, tick_at(lock_at));
    assert!(
        lock_effects.is_empty(),
        "lock transition emits no effects; got {lock_effects:?}"
    );
    match &locked {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, &path, "Locked path matches the original Unlocked path");
            let p_clear = pending_clipboard_clear
                .as_ref()
                .expect("pending clear must survive lock");
            assert_eq!(
                p_clear.token, token,
                "token survives the Unlocked → Locked transition unchanged"
            );
            assert_eq!(
                p_clear.value.as_slice(),
                captured.as_slice(),
                "captured bytes survive the lock unchanged"
            );
            assert_eq!(
                p_clear.deadline, clear_deadline,
                "wake-deadline survives the lock unchanged"
            );
        }
        other => panic!("expected Locked after tick past idle deadline, got {other:?}"),
    }

    // Step 2: the delayed wake fires on the locked state. The reducer
    // emits exactly one `Effect::ClearClipboard` carrying the captured
    // bytes (the input to executor-side `should_clear`) and the
    // pending state drops to `None`.
    let (final_state, wake_effects) = reduce(
        locked,
        AppEvent::ClipboardClear {
            token,
            value: Zeroizing::new(captured.clone()),
        },
    );
    match &wake_effects[..] {
        [Effect::ClearClipboard { value }] => {
            assert_eq!(
                value.as_slice(),
                captured.as_slice(),
                "Effect::ClearClipboard must carry the captured bytes verbatim — the executor checks only-if-unchanged against this value"
            );
        }
        other => panic!("expected exactly one Effect::ClearClipboard, got {other:?}"),
    }
    match final_state {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "still Locked after firing");
            assert!(
                pending_clipboard_clear.is_none(),
                "pending clear is consumed once handed to the executor"
            );
        }
        other => panic!("expected Locked after wake, got {other:?}"),
    }
}

#[test]
fn auto_lock_with_edit_modal_open_drops_modal_and_buffers() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Edit modal bullet
    // (auto-lock): "Auto-lock with the Edit modal open drops the
    // modal and every modal-local buffer (label, issuer, icon-hint
    // slug) and resets the selector to *Leave unchanged* before
    // re-presenting the unlock screen. The dismissal is silent: no
    // toast fires, no status-line message is posted, and no other
    // user-visible feedback surfaces — matching Add and Rename
    // auto-lock behavior."
    //
    // The modal drop is structural (the resulting `Locked` carries
    // only `path` plus pending clipboard clear), so this test
    // mirrors the QR Export auto-lock shape: build an Unlocked with
    // a fully-loaded Edit modal (custom buffers, slug-mode selector,
    // populated slug buffer), fire a tick past the idle deadline,
    // and assert the resulting state is `Locked` with no
    // status-line, modal, or vault state surviving.
    let tmp = secure_tempdir();
    let path = tmp.path().join("vault.bin");
    let (mut vault, store) = create_encrypted_pair(&path, "pp");
    enable_auto_lock(&mut vault, &store, 600);
    let account_id = add_totp_account(&mut vault, &store, "alice");

    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(600);
    let modal = EditModal {
        account_id,
        prior: EditPrior {
            label: "alice".to_string(),
            issuer: Some("Acme".to_string()),
            icon_hint: Some("acme".to_string()),
        },
        label_buffer: "alice-edited".to_string(),
        issuer_buffer: "Acme".to_string(),
        icon_hint_selector: EditIconHintSelector::Slug,
        icon_hint_slug: "custom-slug".to_string(),
        focus: EditFocus::Slug,
        error: None,
    };
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: Some(deadline),
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Edit(modal)),
        selected: Some(account_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };

    let now = deadline + Duration::from_millis(1);
    let (next, effects) = reduce(state, tick_at(now));
    assert!(effects.is_empty(), "lock transition emits no effects");
    match next {
        AppState::Locked {
            path: p,
            pending_clipboard_clear,
        } => {
            assert_eq!(p, path, "Locked must carry the original vault path");
            assert!(
                pending_clipboard_clear.is_none(),
                "pending clipboard clear was None on entry; lock must not fabricate one",
            );
            // Modal / vault / buffers are gone by construction (the
            // `Locked` variant has no slots for them); the typed
            // buffers + selector wiped alongside the variant change.
        }
        other => {
            panic!("expected Locked (Edit modal, buffers, and vault must be gone), got {other:?}",)
        }
    }
}
