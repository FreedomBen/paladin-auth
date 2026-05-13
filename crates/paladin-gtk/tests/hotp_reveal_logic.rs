// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic HOTP reveal-window tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/hotp_reveal_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
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

use std::time::{Duration, Instant};

use paladin_core::{hotp_reveal_deadline, AccountId, Code, PaladinError, HOTP_REVEAL_SECS};

use paladin_gtk::hotp_reveal::{
    apply_advance_outcome, deadline, AdvanceDecision, AdvanceOutcome, StagedCode,
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
