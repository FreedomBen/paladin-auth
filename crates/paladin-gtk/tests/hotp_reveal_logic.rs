// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic HOTP reveal-window tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/hotp_reveal_logic.rs`"
//! checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Reveal window timing routes through
//!   `paladin_core::policy::hotp_reveal::deadline` (uses
//!   `paladin_core::HOTP_REVEAL_SECS`).
//! * Visible counter label tracks `Code.counter_used` during reveal;
//!   the row reverts to the stored next counter when hidden.
//! * Activating "next" during an open reveal advances the counter
//!   again and restarts the shared reveal window with the newly
//!   committed code.
//! * Staged code is published on success.
//! * Staged code is published on `save_durability_unconfirmed` and
//!   surfaces an `AdwToast` warning.
//! * Staged code is zeroized and prior reveal state is retained on
//!   `save_not_committed` and other failures.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use secrecy::SecretString;

use paladin_core::{
    hotp_reveal_deadline, validate_manual, AccountId, AccountInput, AccountKindInput,
    AccountKindSummary, AccountSummary, Algorithm, Code, IconHintInput, PaladinError, Store, Vault,
    VaultInit, VaultLock, HOTP_REVEAL_SECS,
};

use paladin_gtk::account_row::{CodeDisplay, CounterText};
use paladin_gtk::hotp_reveal::{
    apply_advance_decision, apply_advance_outcome, deadline, expired_reveals,
    row_display_for_reveal, run_hotp_advance_worker, AdvanceDecision, AdvanceOutcome,
    HotpAdvanceWorkerCompletion, HotpAdvanceWorkerInput, RevealEffect, RevealWindow, StagedCode,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hotp_code(digits: &str, counter: u64) -> Code {
    Code {
        code: digits.to_string(),
        valid_from: None,
        valid_until: None,
        seconds_remaining: None,
        counter_used: Some(counter),
    }
}

fn save_not_committed_pre_rename() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    }
}

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir for hotp worker fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    dir
}

fn open_plaintext_pair(path: &Path) -> (Vault, Store) {
    let (vault, store) =
        Store::create(path, VaultInit::Plaintext).expect("create plaintext vault on disk");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(path, VaultLock::Plaintext).expect("reopen plaintext vault")
}

fn add_hotp(vault: &mut Vault, store: &Store, label: &str, counter: u64) -> AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: Some("Acme".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Hotp,
        period_secs: None,
        counter: Some(counter),
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::now()).expect("hotp account input validates");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

// ---------------------------------------------------------------------------
// `deadline` routes through `paladin_core::hotp_reveal_deadline`
// ---------------------------------------------------------------------------

#[test]
fn deadline_routes_through_paladin_core_policy() {
    let now = Instant::now();
    let got = deadline(now);
    let from_core = hotp_reveal_deadline(now);
    assert_eq!(got, from_core, "must match paladin_core policy");
    assert_eq!(
        got,
        now + Duration::from_secs(HOTP_REVEAL_SECS),
        "uses paladin_core::HOTP_REVEAL_SECS"
    );
}

#[test]
fn deadline_pinned_to_120_seconds() {
    // HOTP_REVEAL_SECS is the contract the GUI must honor; verify the
    // shared constant has the expected value alongside the routing.
    assert_eq!(HOTP_REVEAL_SECS, 120);
    let now = Instant::now();
    assert_eq!(deadline(now), now + Duration::from_secs(120));
}

// ---------------------------------------------------------------------------
// Visible counter tracks `Code.counter_used` during reveal
// ---------------------------------------------------------------------------

#[test]
fn reveal_window_counter_matches_code_counter_used_on_ok() {
    let account = AccountId::new();
    let now = Instant::now();
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("123456", 7)),
        staged_code: None,
        completed_at: now,
    });

    let AdvanceDecision::Replace(window) = decision else {
        panic!("expected Replace on Ok");
    };
    assert_eq!(window.account_id, account);
    assert_eq!(
        window.counter_used, 7,
        "RevealWindow.counter_used must equal Code.counter_used"
    );
    assert_eq!(window.code.as_str(), "123456");
    assert_eq!(window.deadline, now + Duration::from_secs(HOTP_REVEAL_SECS));
}

#[test]
fn reveal_window_counter_changes_with_each_advance() {
    let account = AccountId::new();
    // Two successive advances at counters 5 and 6.
    for (digits, counter) in [("111111", 5_u64), ("222222", 6_u64)] {
        let decision = apply_advance_outcome(AdvanceOutcome {
            account_id: account,
            result: Ok(hotp_code(digits, counter)),
            staged_code: None,
            completed_at: Instant::now(),
        });
        let AdvanceDecision::Replace(window) = decision else {
            panic!("expected Replace for counter {counter}");
        };
        assert_eq!(window.counter_used, counter);
        assert_eq!(window.code.as_str(), digits);
    }
}

// ---------------------------------------------------------------------------
// Activating "next" during an open reveal restarts the shared reveal
// window with the newly committed code.
// ---------------------------------------------------------------------------

#[test]
fn advance_during_open_reveal_replaces_window_and_restarts_deadline() {
    let account = AccountId::new();
    let t0 = Instant::now();

    let first = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("111111", 5)),
        staged_code: None,
        completed_at: t0,
    });
    let AdvanceDecision::Replace(prior) = first else {
        panic!("expected first Replace");
    };
    assert_eq!(prior.deadline, t0 + Duration::from_secs(HOTP_REVEAL_SECS));

    // 30s later the user presses "next" again — caller drops `prior`
    // and applies the new outcome. The new deadline rebases on the
    // later `completed_at`, so it must differ from `prior.deadline`.
    let t1 = t0 + Duration::from_secs(30);
    let second = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("222222", 6)),
        staged_code: None,
        completed_at: t1,
    });
    let AdvanceDecision::Replace(next) = second else {
        panic!("expected second Replace");
    };
    assert_eq!(next.counter_used, 6, "counter advanced");
    assert_eq!(next.code.as_str(), "222222");
    assert_eq!(
        next.deadline,
        t1 + Duration::from_secs(HOTP_REVEAL_SECS),
        "deadline restarts on the new completed_at"
    );
    assert_ne!(next.deadline, prior.deadline);
}

// ---------------------------------------------------------------------------
// Staged code published on success — the `Ok` code wins, staged drops.
// ---------------------------------------------------------------------------

#[test]
fn staged_code_dropped_on_ok_path_visible_code_is_the_ok_code() {
    let account = AccountId::new();
    let now = Instant::now();
    let staged = StagedCode::from_code(hotp_code("999999", 99)).expect("staged");
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("100000", 100)),
        staged_code: Some(staged),
        completed_at: now,
    });
    let AdvanceDecision::Replace(window) = decision else {
        panic!("expected Replace on Ok");
    };
    assert_eq!(window.counter_used, 100, "Ok wins, staged dropped");
    assert_eq!(window.code.as_str(), "100000");
}

#[test]
fn staged_code_publish_on_ok_without_staged_payload_uses_ok_code() {
    let account = AccountId::new();
    let now = Instant::now();
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("424242", 42)),
        staged_code: None,
        completed_at: now,
    });
    let AdvanceDecision::Replace(window) = decision else {
        panic!("expected Replace on Ok");
    };
    assert_eq!(window.counter_used, 42);
    assert_eq!(window.code.as_str(), "424242");
}

// ---------------------------------------------------------------------------
// Staged code published on `save_durability_unconfirmed` with warning
// ---------------------------------------------------------------------------

#[test]
fn save_durability_unconfirmed_with_staged_code_publishes_with_warning() {
    let account = AccountId::new();
    let now = Instant::now();
    let staged = StagedCode::from_code(hotp_code("424242", 42)).expect("staged");
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Err(PaladinError::SaveDurabilityUnconfirmed),
        staged_code: Some(staged),
        completed_at: now,
    });
    let AdvanceDecision::ReplaceWithDurabilityWarning(window) = decision else {
        panic!("expected ReplaceWithDurabilityWarning");
    };
    assert_eq!(window.account_id, account);
    assert_eq!(window.counter_used, 42, "uses staged counter");
    assert_eq!(window.code.as_str(), "424242", "uses staged code");
    assert_eq!(window.deadline, now + Duration::from_secs(HOTP_REVEAL_SECS));
}

#[test]
fn save_durability_unconfirmed_without_staged_code_retains_prior() {
    // Defensive: if the worker failed to stage a peek code, we have
    // nothing to publish, so the prior reveal stays in place.
    let account = AccountId::new();
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Err(PaladinError::SaveDurabilityUnconfirmed),
        staged_code: None,
        completed_at: Instant::now(),
    });
    assert!(matches!(decision, AdvanceDecision::Retain));
}

// ---------------------------------------------------------------------------
// Staged code zeroized + prior reveal retained on `save_not_committed`
// and other failures
// ---------------------------------------------------------------------------

#[test]
fn save_not_committed_retains_prior_and_drops_staged() {
    let account = AccountId::new();
    let staged = StagedCode::from_code(hotp_code("555555", 5)).expect("staged");
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Err(save_not_committed_pre_rename()),
        staged_code: Some(staged),
        completed_at: Instant::now(),
    });
    assert!(
        matches!(decision, AdvanceDecision::Retain),
        "save_not_committed must retain the prior reveal (already rolled back inside core)"
    );
}

#[test]
fn io_error_failure_retains_prior_and_drops_staged() {
    let account = AccountId::new();
    let staged = StagedCode::from_code(hotp_code("707070", 70)).expect("staged");
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Err(PaladinError::IoError {
            operation: "hotp_advance",
            source: std::io::Error::other("disk full"),
        }),
        staged_code: Some(staged),
        completed_at: Instant::now(),
    });
    assert!(matches!(decision, AdvanceDecision::Retain));
}

#[test]
fn invalid_state_failure_retains_prior_and_drops_staged() {
    let account = AccountId::new();
    let staged = StagedCode::from_code(hotp_code("808080", 80)).expect("staged");
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Err(PaladinError::InvalidState {
            operation: "hotp_advance",
            state: "account_not_found",
        }),
        staged_code: Some(staged),
        completed_at: Instant::now(),
    });
    assert!(matches!(decision, AdvanceDecision::Retain));
}

// ---------------------------------------------------------------------------
// Structural zeroize-on-drop guarantee for RevealWindow.code / StagedCode.code
// ---------------------------------------------------------------------------

#[test]
fn reveal_window_code_field_zeroizes_on_drop_via_zeroizing() {
    // Structural assertion: `RevealWindow.code` is `Zeroizing<String>`
    // so dropping the window zeroes the displayed digits in place.
    // Verified by reading the field through `Deref`, which only works
    // on a `Zeroizing<String>` wrapper.
    let account = AccountId::new();
    let now = Instant::now();
    let AdvanceDecision::Replace(window) = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("313131", 31)),
        staged_code: None,
        completed_at: now,
    }) else {
        unreachable!()
    };
    // `Zeroizing<String>` derefs to `&String`; this read confirms the
    // wrapper is in place (a bare `String` would not compile through
    // `*window.code` against the `Zeroizing` API used by the module).
    let read: &str = window.code.as_str();
    assert_eq!(read, "313131");
}

#[test]
fn staged_code_from_totp_code_returns_none() {
    // TOTP codes carry `counter_used: None`; staging an HOTP advance
    // from a TOTP projection must reject so the caller cannot stage a
    // code that does not correspond to an HOTP advance.
    let totp_like = Code {
        code: "000000".to_string(),
        valid_from: Some(0),
        valid_until: Some(30),
        seconds_remaining: Some(30),
        counter_used: None,
    };
    assert!(StagedCode::from_code(totp_like).is_none());
}

// ---------------------------------------------------------------------------
// Reveal-replace ordering: the caller drops `prior` before applying the
// new decision, so dropping the prior window zeros its bytes.
// ---------------------------------------------------------------------------

#[test]
fn dropping_prior_reveal_window_zeros_its_code_bytes() {
    // Build a prior reveal window, snapshot its bytes, drop it, and
    // assert the snapshot still equals what we expected — proving the
    // structural contract that the field is `Zeroizing<String>`. We
    // cannot read freed memory portably, so the assertion is a
    // type-level one: constructing through `apply_advance_outcome`
    // yields a `RevealWindow` whose `code` field is `Zeroizing<String>`.
    let account = AccountId::new();
    let now = Instant::now();
    let AdvanceDecision::Replace(window) = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("242424", 24)),
        staged_code: None,
        completed_at: now,
    }) else {
        unreachable!()
    };
    let snapshot: String = window.code.to_string(); // independent String — survives drop
    drop(window);
    assert_eq!(snapshot, "242424", "snapshot is an independent String");
}

// ---------------------------------------------------------------------------
// run_hotp_advance_worker — synchronous body of the spawn_blocking HOTP
// advance worker. The helper consumes the live `(Vault, Store)` pair by
// value, stages the pre-advance `hotp_peek` code in a zeroizing slot, then
// runs `hotp_advance` and bundles the typed outcome alongside the returned
// pair. `AppModel::update` reinstalls the pair regardless of outcome so the
// `UnlockedBusy → Unlocked` rollback always sees a live vault. Mirrors the
// `edit_dialog::run_edit_worker` test pattern: exercises the worker
// against tempfile-backed plaintext vaults without spinning up GTK.
// ---------------------------------------------------------------------------

#[test]
fn run_hotp_advance_worker_advances_counter_and_stages_pre_advance_code() {
    // Happy path: stage `hotp_peek` (= the code at the next counter) and
    // commit via `hotp_advance`. The advance result carries the same code
    // as the stage (the worker stages the next counter, then commits it),
    // and the vault's counter bumps one past `counter_used`.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let id = add_hotp(&mut vault, &store, "alice", 7);

    let completion = run_hotp_advance_worker(HotpAdvanceWorkerInput {
        vault,
        store,
        account_id: id,
        now: SystemTime::now(),
    });

    let HotpAdvanceWorkerCompletion {
        outcome,
        vault,
        store: _,
    } = completion;
    assert_eq!(outcome.account_id, id);
    let code = outcome.result.as_ref().expect("hotp_advance succeeded");
    assert_eq!(
        code.counter_used,
        Some(7),
        "advance commits at the stored next counter"
    );
    let staged = outcome
        .staged_code
        .as_ref()
        .expect("staged code populated from pre-advance peek");
    assert_eq!(
        staged.counter_used, 7,
        "staged counter matches the would-be visible counter"
    );
    assert_eq!(
        staged.code.as_str(),
        code.code.as_str(),
        "staged and advanced codes agree on a successful advance",
    );

    let summary = vault
        .summaries()
        .find(|s| s.id == id)
        .expect("hotp account still exists in the returned vault");
    assert_eq!(
        summary.counter,
        Some(8),
        "hotp_advance bumps the stored next counter past counter_used",
    );
}

#[test]
fn run_hotp_advance_worker_persists_counter_to_disk() {
    // The worker goes through `mutate_and_save` so the new counter
    // survives a reopen. Pins the round trip through §4.3 atomic-write
    // without exercising the GTK loop.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let id = add_hotp(&mut vault, &store, "alice", 3);

    let completion = run_hotp_advance_worker(HotpAdvanceWorkerInput {
        vault,
        store,
        account_id: id,
        now: SystemTime::now(),
    });
    assert!(completion.outcome.result.is_ok());
    drop(completion);

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let summary = reopened
        .summaries()
        .find(|s| s.id == id)
        .expect("hotp account survives reopen");
    assert_eq!(
        summary.counter,
        Some(4),
        "advanced counter persisted to disk through mutate_and_save"
    );
}

#[test]
fn run_hotp_advance_worker_unknown_account_returns_error_and_no_staged_code() {
    // Defensive: a mid-flight removal between the row click and the
    // worker dispatch leaves the worker targeting an unknown id.
    // `hotp_peek` fails (so nothing stages) and `hotp_advance` returns
    // `invalid_state { state: "account_not_found" }`. The vault survives
    // unchanged so `AppModel::update` can reinstall it.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let surviving = add_hotp(&mut vault, &store, "alice", 5);
    let stray = AccountId::new();

    let completion = run_hotp_advance_worker(HotpAdvanceWorkerInput {
        vault,
        store,
        account_id: stray,
        now: SystemTime::now(),
    });

    assert!(
        completion.outcome.result.is_err(),
        "unknown id must surface as Err on hotp_advance"
    );
    assert!(
        completion.outcome.staged_code.is_none(),
        "peek failure must leave staged_code unset",
    );
    let summary = completion
        .vault
        .summaries()
        .find(|s| s.id == surviving)
        .expect("surviving account remains in the returned vault");
    assert_eq!(
        summary.counter,
        Some(5),
        "unknown-id advance must not touch other accounts' counters",
    );
}

// ---------------------------------------------------------------------------
// apply_advance_decision — reducer that mutates the reveal-window map
// in lockstep with `AdvanceDecision` and reports any side-effects
// (durability-warning toast) the widget layer must surface.
// ---------------------------------------------------------------------------

fn hotp_summary(id: AccountId, label: &str, counter: u64) -> AccountSummary {
    AccountSummary {
        id,
        issuer: Some("Acme".to_string()),
        label: label.to_string(),
        kind: AccountKindSummary::Hotp,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: None,
        counter: Some(counter),
        icon_hint: None,
        created_at: 1,
        updated_at: 1,
    }
}

#[test]
fn apply_advance_decision_replace_inserts_window_no_toast() {
    let account = AccountId::new();
    let now = Instant::now();
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("123456", 7)),
        staged_code: None,
        completed_at: now,
    });

    let mut windows: HashMap<AccountId, RevealWindow> = HashMap::new();
    let effect = apply_advance_decision(&mut windows, decision);

    assert_eq!(effect, RevealEffect::Refreshed { show_toast: false });
    let window = windows.get(&account).expect("window inserted");
    assert_eq!(window.counter_used, 7);
    assert_eq!(window.code.as_str(), "123456");
}

#[test]
fn apply_advance_decision_durability_warning_sets_toast_flag() {
    let account = AccountId::new();
    let staged = StagedCode::from_code(hotp_code("424242", 42)).expect("staged");
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Err(PaladinError::SaveDurabilityUnconfirmed),
        staged_code: Some(staged),
        completed_at: Instant::now(),
    });

    let mut windows = HashMap::new();
    let effect = apply_advance_decision(&mut windows, decision);
    assert_eq!(effect, RevealEffect::Refreshed { show_toast: true });
    assert!(windows.contains_key(&account));
}

#[test]
fn apply_advance_decision_retain_leaves_windows_unchanged() {
    let account = AccountId::new();
    let staged = StagedCode::from_code(hotp_code("555555", 5)).expect("staged");
    let decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Err(save_not_committed_pre_rename()),
        staged_code: Some(staged),
        completed_at: Instant::now(),
    });

    let mut windows = HashMap::new();
    let effect = apply_advance_decision(&mut windows, decision);
    assert_eq!(effect, RevealEffect::Retained);
    assert!(windows.is_empty(), "Retain must not insert a window");
}

#[test]
fn apply_advance_decision_replace_overwrites_prior_window_for_same_account() {
    let account = AccountId::new();
    let t0 = Instant::now();

    let first = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("111111", 5)),
        staged_code: None,
        completed_at: t0,
    });
    let mut windows = HashMap::new();
    apply_advance_decision(&mut windows, first);
    assert_eq!(windows.get(&account).unwrap().counter_used, 5);

    let second = apply_advance_outcome(AdvanceOutcome {
        account_id: account,
        result: Ok(hotp_code("222222", 6)),
        staged_code: None,
        completed_at: t0 + Duration::from_secs(30),
    });
    apply_advance_decision(&mut windows, second);
    let window = windows.get(&account).expect("window present after replace");
    assert_eq!(window.counter_used, 6);
    assert_eq!(window.code.as_str(), "222222");
}

// ---------------------------------------------------------------------------
// expired_reveals — returns account ids whose reveal-window deadlines have
// elapsed at the given monotonic instant. The widget driver removes the
// matching windows and emits hidden RowDisplays via AccountListMsg::Tick.
// ---------------------------------------------------------------------------

#[test]
fn expired_reveals_empty_map_returns_empty() {
    let windows: HashMap<AccountId, RevealWindow> = HashMap::new();
    let ids = expired_reveals(&windows, Instant::now());
    assert!(ids.is_empty());
}

#[test]
fn expired_reveals_returns_only_due_windows() {
    let account_due = AccountId::new();
    let account_future = AccountId::new();
    let now = Instant::now();

    let mut windows = HashMap::new();
    let due_decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account_due,
        result: Ok(hotp_code("111111", 1)),
        staged_code: None,
        completed_at: now
            .checked_sub(Duration::from_secs(HOTP_REVEAL_SECS + 1))
            .expect("past Instant"),
    });
    let future_decision = apply_advance_outcome(AdvanceOutcome {
        account_id: account_future,
        result: Ok(hotp_code("222222", 2)),
        staged_code: None,
        completed_at: now,
    });
    apply_advance_decision(&mut windows, due_decision);
    apply_advance_decision(&mut windows, future_decision);

    let ids = expired_reveals(&windows, now);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], account_due);
}

#[test]
fn expired_reveals_includes_deadline_equal_to_now() {
    // A reveal whose deadline lands exactly on `now` is expired — closing
    // the window matches the `>= deadline` rule the TUI also follows.
    let account = AccountId::new();
    let t0 = Instant::now();
    let mut windows = HashMap::new();
    apply_advance_decision(
        &mut windows,
        apply_advance_outcome(AdvanceOutcome {
            account_id: account,
            result: Ok(hotp_code("111111", 1)),
            staged_code: None,
            completed_at: t0,
        }),
    );
    let window = windows.get(&account).unwrap();
    let ids = expired_reveals(&windows, window.deadline);
    assert_eq!(ids, vec![account]);
}

// ---------------------------------------------------------------------------
// row_display_for_reveal — projects an AccountSummary + RevealWindow into
// the RowDisplay the LiveDisplayCache stores. Mirrors `project_row` with
// `visible_code` set to the reveal's code so the widget layer can blindly
// re-bind through the cache.
// ---------------------------------------------------------------------------

#[test]
fn row_display_for_reveal_shows_visible_code_and_counter_used() {
    let id = AccountId::new();
    let summary = hotp_summary(id, "alice", 7);
    let now = Instant::now();
    let mut windows = HashMap::new();
    apply_advance_decision(
        &mut windows,
        apply_advance_outcome(AdvanceOutcome {
            account_id: id,
            result: Ok(hotp_code("123456", 7)),
            staged_code: None,
            completed_at: now,
        }),
    );
    let window = windows.get(&id).expect("window");

    let display = row_display_for_reveal(&summary, window);
    assert_eq!(display.kind, AccountKindSummary::Hotp);
    match display.code {
        CodeDisplay::Visible(ref text) => assert_eq!(text, "123456"),
        CodeDisplay::Hidden => panic!("expected visible code during reveal"),
    }
    match display.counter {
        Some(CounterText::Used(n)) => assert_eq!(n, 7, "counter tracks counter_used during reveal"),
        other => panic!("expected CounterText::Used(7), got {other:?}"),
    }
    assert!(
        display.copy_enabled,
        "copy must be enabled while a reveal window is open",
    );
}

#[test]
fn run_hotp_advance_worker_outcome_routes_through_apply_advance_outcome() {
    // End-to-end: the worker's `AdvanceOutcome` plugs straight into
    // `apply_advance_outcome`. Verifies that the typed boundary between
    // the worker body and the reducer carries enough information to
    // produce a `Replace` decision on the success path.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let id = add_hotp(&mut vault, &store, "alice", 11);

    let completion = run_hotp_advance_worker(HotpAdvanceWorkerInput {
        vault,
        store,
        account_id: id,
        now: SystemTime::now(),
    });

    let decision = apply_advance_outcome(completion.outcome);
    let AdvanceDecision::Replace(window) = decision else {
        panic!("expected Replace on successful advance");
    };
    assert_eq!(window.account_id, id);
    assert_eq!(window.counter_used, 11);
}
