// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic in-flight-effect ownership tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests >
//! `tests/effect_ownership_logic.rs`" checklist in
//! `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Only one vault-touching worker is in flight at a time.
//! * Mutating controls (row `next`, dialog submit buttons,
//!   passphrase actions, import / export, settings) are disabled
//!   while `UnlockedBusy` is active.
//! * Quit / window-close requests are deferred until the worker
//!   returns.
//! * Auto-lock expiry while `UnlockedBusy` is active records a
//!   lock-after-effect request and only locks if the returned vault
//!   is still encrypted; if the operation changed the vault to
//!   plaintext, the pending lock is discarded.
//! * `(Vault, Store)` is reinstalled before UI outcome handling on
//!   both success and typed failure.
//! * Settings spinner debounce coalesces to the latest pre-save
//!   value when an effect is in flight.
//! * Toggle changes that would overlap an active vault effect are
//!   not accepted until the control is re-enabled.
//! * Worker that fails before returning the `(Vault, Store)` pair
//!   routes the app to `StartupErrorComponent` without trying to
//!   reconstruct in-memory vault state.
//!
//! The module under test (`paladin_gtk::effect_ownership`) is the
//! pure-logic state machine that the GTK `AppModel` shadows. It
//! owns no `(Vault, Store)` itself — the `AppModel` keeps that pair
//! in an `Option<(Vault, Store)>` and `take`s it for the worker on
//! `start_effect`, restoring it on `complete_effect`. The state
//! machine here records *which effect is in flight* and the
//! deferred quit / lock flags so widget controls can be gated and
//! lifecycle requests resolved without the test harness needing a
//! real `(Vault, Store)`.

use paladin_gtk::effect_ownership::{
    AppState, CompleteOutcome, ControlGating, EffectKind, EffectOwnership, EffectStart,
    LockDecision, QuitDecision,
};
use paladin_gtk::settings::{AcceptedChange, DebounceOutcome, SettingsField, SettingsState};
// CommittedSettings constructor takes 4 plain args — pull in directly so the
// settings interaction tests stay self-contained.
use paladin_core::SettingPatch;
use paladin_gtk::settings::CommittedSettings;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unlocked() -> EffectOwnership {
    EffectOwnership::unlocked()
}

// ---------------------------------------------------------------------------
// Only one vault-touching worker is in flight at a time
// ---------------------------------------------------------------------------

#[test]
fn fresh_unlocked_state_is_idle() {
    let model = unlocked();
    assert_eq!(model.state(), AppState::Unlocked);
    assert!(!model.is_busy());
    assert_eq!(model.current_effect(), None);
    assert!(!model.pending_lock());
    assert!(!model.pending_quit());
}

#[test]
fn start_effect_from_idle_is_accepted_and_transitions_to_unlocked_busy() {
    let mut model = unlocked();
    let outcome = model.start_effect(EffectKind::HotpAdvance);
    assert_eq!(outcome, EffectStart::Accepted);
    assert!(model.is_busy());
    assert_eq!(model.current_effect(), Some(EffectKind::HotpAdvance));
    assert_eq!(
        model.state(),
        AppState::UnlockedBusy(EffectKind::HotpAdvance)
    );
}

#[test]
fn second_start_effect_while_busy_is_rejected_and_does_not_swap_in_flight() {
    let mut model = unlocked();
    assert_eq!(
        model.start_effect(EffectKind::Import),
        EffectStart::Accepted
    );
    let outcome = model.start_effect(EffectKind::Export);
    assert_eq!(outcome, EffectStart::Rejected);
    // The original in-flight effect is unchanged — Rejected does
    // not stomp the current worker.
    assert_eq!(model.current_effect(), Some(EffectKind::Import));
}

#[test]
fn start_effect_from_startup_error_is_rejected() {
    // Once the AppModel routes to StartupError (worker_lost), the
    // (V, S) pair is gone — no further vault effects can be started.
    let mut model = unlocked();
    assert_eq!(
        model.start_effect(EffectKind::HotpAdvance),
        EffectStart::Accepted
    );
    model.worker_lost();
    assert_eq!(model.state(), AppState::StartupError);
    let outcome = model.start_effect(EffectKind::HotpAdvance);
    assert_eq!(outcome, EffectStart::Rejected);
}

#[test]
fn complete_effect_releases_busy_and_allows_next_effect() {
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    let outcome = model.complete_effect(true);
    assert!(matches!(outcome, CompleteOutcome::Ready));
    assert_eq!(model.state(), AppState::Unlocked);
    assert!(!model.is_busy());

    let next = model.start_effect(EffectKind::RemoveAccount);
    assert_eq!(next, EffectStart::Accepted);
    assert_eq!(model.current_effect(), Some(EffectKind::RemoveAccount));
}

// ---------------------------------------------------------------------------
// Mutating controls are disabled while UnlockedBusy
// ---------------------------------------------------------------------------

#[test]
fn control_gating_idle_unlocked_all_enabled() {
    let model = unlocked();
    let gating = model.control_gating();
    assert_eq!(gating, ControlGating::all_enabled());
    assert!(!gating.row_next);
    assert!(!gating.dialog_submit);
    assert!(!gating.passphrase_actions);
    assert!(!gating.import_export);
    assert!(!gating.settings);
}

#[test]
fn control_gating_unlocked_busy_disables_all_mutating_controls() {
    // The plan checklist names: row `next`, dialog submit buttons,
    // passphrase actions, import / export, settings. All five
    // surface flags must go disabled while a vault-touching worker
    // is in flight.
    for effect in [
        EffectKind::HotpAdvance,
        EffectKind::AddAccount,
        EffectKind::RemoveAccount,
        EffectKind::RenameAccount,
        EffectKind::Import,
        EffectKind::Export,
        EffectKind::Settings,
        EffectKind::PassphraseSet,
        EffectKind::PassphraseChange,
        EffectKind::PassphraseRemove,
    ] {
        let mut model = unlocked();
        model.start_effect(effect);
        let gating = model.control_gating();
        assert!(gating.row_next, "row_next disabled for {effect:?}");
        assert!(
            gating.dialog_submit,
            "dialog_submit disabled for {effect:?}"
        );
        assert!(
            gating.passphrase_actions,
            "passphrase_actions disabled for {effect:?}"
        );
        assert!(
            gating.import_export,
            "import_export disabled for {effect:?}"
        );
        assert!(gating.settings, "settings disabled for {effect:?}");
    }
}

#[test]
fn control_gating_startup_error_disables_all_mutating_controls() {
    let mut model = unlocked();
    model.start_effect(EffectKind::HotpAdvance);
    model.worker_lost();
    let gating = model.control_gating();
    // StartupErrorComponent offers only retry/quit — every mutating
    // surface is off.
    assert!(gating.row_next);
    assert!(gating.dialog_submit);
    assert!(gating.passphrase_actions);
    assert!(gating.import_export);
    assert!(gating.settings);
}

// ---------------------------------------------------------------------------
// Quit / window-close deferred until the worker returns
// ---------------------------------------------------------------------------

#[test]
fn request_quit_while_idle_fires_now() {
    let mut model = unlocked();
    let outcome = model.request_quit();
    assert_eq!(outcome, QuitDecision::Now);
    assert!(!model.pending_quit());
}

#[test]
fn request_quit_while_busy_is_deferred_and_records_pending_quit() {
    let mut model = unlocked();
    model.start_effect(EffectKind::Export);
    let outcome = model.request_quit();
    assert_eq!(outcome, QuitDecision::Deferred);
    assert!(model.pending_quit());
}

#[test]
fn complete_effect_with_pending_quit_fires_quit_now() {
    let mut model = unlocked();
    model.start_effect(EffectKind::Export);
    model.request_quit();
    let outcome = model.complete_effect(true);
    assert!(matches!(outcome, CompleteOutcome::QuitNow));
    // After firing, the pending_quit flag clears.
    assert!(!model.pending_quit());
}

#[test]
fn complete_effect_with_no_pending_quit_fires_ready() {
    let mut model = unlocked();
    model.start_effect(EffectKind::Export);
    let outcome = model.complete_effect(true);
    assert!(matches!(outcome, CompleteOutcome::Ready));
}

// ---------------------------------------------------------------------------
// Auto-lock expiry during UnlockedBusy: deferred lock-after-effect; only
// fires if the returned vault is still encrypted
// ---------------------------------------------------------------------------

#[test]
fn auto_lock_expired_while_idle_and_encrypted_fires_now() {
    let mut model = unlocked();
    let outcome = model.auto_lock_expired(true);
    assert_eq!(outcome, LockDecision::Now);
    assert!(!model.pending_lock());
}

#[test]
fn auto_lock_expired_while_idle_and_plaintext_is_ignored() {
    // Per the plan §"Auto-lock and clipboard auto-clear" /
    // IdlePolicy gating, plaintext vaults are no-op for auto-lock.
    // An expiry signal that reaches the state machine when the
    // vault is plaintext (e.g., post-PassphraseRemove transition
    // before disarm) is silently dropped.
    let mut model = unlocked();
    let outcome = model.auto_lock_expired(false);
    assert_eq!(outcome, LockDecision::Ignored);
    assert!(!model.pending_lock());
}

#[test]
fn auto_lock_expired_while_busy_is_deferred_and_records_pending_lock() {
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    // `vault_is_encrypted` here is the pre-effect mode; the
    // gating at completion time is what decides whether the lock
    // actually fires.
    let outcome = model.auto_lock_expired(true);
    assert_eq!(outcome, LockDecision::Deferred);
    assert!(model.pending_lock());
}

#[test]
fn complete_effect_with_pending_lock_on_still_encrypted_vault_fires_lock_now() {
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    model.auto_lock_expired(true);
    // Worker returned a vault that is still encrypted — the
    // deferred lock fires.
    let outcome = model.complete_effect(true);
    assert!(matches!(outcome, CompleteOutcome::LockNow));
    assert!(!model.pending_lock());
}

#[test]
fn complete_effect_with_pending_lock_on_plaintext_converted_vault_discards_lock() {
    // PassphraseRemove transitions the vault to plaintext. A lock
    // expiry that landed mid-flight is discarded because auto-lock
    // is a no-op on plaintext vaults.
    let mut model = unlocked();
    model.start_effect(EffectKind::PassphraseRemove);
    model.auto_lock_expired(true);
    let outcome = model.complete_effect(false);
    assert!(matches!(outcome, CompleteOutcome::LockDiscarded));
    assert!(!model.pending_lock());
}

#[test]
fn complete_effect_with_no_pending_lock_and_still_encrypted_is_ready() {
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    let outcome = model.complete_effect(true);
    assert!(matches!(outcome, CompleteOutcome::Ready));
}

#[test]
fn pending_lock_does_not_arm_a_second_time_when_idle_expiry_follows_completion() {
    // A deferred lock fires exactly once — the completion clears the
    // flag, so a fresh idle expiry has to be re-armed by the timer.
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    model.auto_lock_expired(true);
    assert!(matches!(
        model.complete_effect(true),
        CompleteOutcome::LockNow
    ));
    assert!(!model.pending_lock());
}

#[test]
fn pending_lock_and_pending_quit_both_set_completes_with_quit_now() {
    // When both lock-after-effect and quit are deferred, the app
    // exits via quit; the lock would be moot. The state machine
    // surfaces the quit decision and clears both flags.
    let mut model = unlocked();
    model.start_effect(EffectKind::Export);
    model.auto_lock_expired(true);
    model.request_quit();
    let outcome = model.complete_effect(true);
    assert!(matches!(outcome, CompleteOutcome::QuitNow));
    assert!(!model.pending_lock());
    assert!(!model.pending_quit());
}

// ---------------------------------------------------------------------------
// (Vault, Store) reinstalled before UI outcome handling on both success and
// typed failure
// ---------------------------------------------------------------------------

#[test]
fn complete_effect_transitions_to_unlocked_before_caller_handles_typed_result() {
    // The state machine has no notion of the worker's typed Result
    // (Ok / Err PaladinError) — that's handled by the dialog-
    // specific apply_save_result. The contract is: when the worker
    // returns the (V, S) pair, `complete_effect` transitions to
    // `Unlocked` so the caller can read the typed result with the
    // vault available again. This invariant holds regardless of
    // success / failure of the underlying operation.
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    let outcome = model.complete_effect(true);
    // State is now Unlocked. The caller now reads the typed result
    // and pipes it to e.g. AddAccountComponent::apply_result. By
    // that point, (Vault, Store) is reinstalled (the AppModel has
    // restored its Option<(V, S)> from the worker return).
    assert_eq!(model.state(), AppState::Unlocked);
    assert!(matches!(outcome, CompleteOutcome::Ready));
}

#[test]
fn complete_effect_releases_busy_for_both_simulated_success_and_failure() {
    // Both success and typed failure follow the same state-machine
    // path: the worker returned (V, S) so we leave UnlockedBusy.
    // The state machine cannot distinguish — the typed Result lives
    // in the dialog's apply_save_result downstream.
    for vault_still_encrypted in [true, false] {
        let mut model = unlocked();
        model.start_effect(EffectKind::Settings);
        let outcome = model.complete_effect(vault_still_encrypted);
        assert!(matches!(outcome, CompleteOutcome::Ready));
        assert_eq!(model.state(), AppState::Unlocked);
    }
}

// ---------------------------------------------------------------------------
// Settings spinner debounce coalesces to the latest pre-save value when an
// effect is in flight
// ---------------------------------------------------------------------------

#[test]
fn settings_debounce_accumulates_during_settings_effect_and_fires_after_completion() {
    // The state machine here gates whether a new vault save can
    // *start*; it does not consult the settings module. The
    // SettingsState keeps buffering across a busy window. After
    // complete_effect releases the busy flag, the next debounce
    // tick fires the coalesced latest value through one save.
    let mut model = unlocked();
    let mut settings = SettingsState::new(CommittedSettings::new(false, 300, false, 30));

    // First save fires for value 60.
    settings.stage_auto_lock_secs(60);
    let DebounceOutcome::Save { patch, field } = settings.resolve_debounce() else {
        panic!("expected first Save");
    };
    assert!(matches!(patch, SettingPatch::AutoLockTimeoutSecs(60)));
    assert_eq!(field, SettingsField::AutoLockSecs);

    assert_eq!(
        model.start_effect(EffectKind::Settings),
        EffectStart::Accepted
    );

    // While the worker is running, the user keeps typing. The
    // pending buffer accumulates — these stages are not rejected
    // by the state machine because settings_logic owns its own
    // buffer.
    settings.stage_auto_lock_secs(90);
    settings.stage_auto_lock_secs(120);

    // Worker returns with success.
    let _ = settings.apply_save_result(AcceptedChange::AutoLockSecs(60), Ok(()));
    assert!(matches!(
        model.complete_effect(true),
        CompleteOutcome::Ready
    ));

    // Next debounce fires the *latest* buffered value once.
    let outcome = settings.resolve_debounce();
    let DebounceOutcome::Save { patch, field } = outcome else {
        panic!("expected coalesced Save, got {outcome:?}");
    };
    assert!(matches!(patch, SettingPatch::AutoLockTimeoutSecs(120)));
    assert_eq!(field, SettingsField::AutoLockSecs);
}

// ---------------------------------------------------------------------------
// Toggle changes that would overlap an active vault effect are not accepted
// until the control is re-enabled
// ---------------------------------------------------------------------------

#[test]
fn toggle_attempt_during_busy_is_blocked_by_control_gating() {
    // Toggle controls are disabled by control_gating while busy.
    // The widget layer drives the AdwSwitchRow's `sensitive`
    // property from this flag; a flipped switch cannot reach the
    // state machine while disabled. We verify the gating signal
    // here and assert that a second vault-effect start (the only
    // path a toggle-driven save could take) is rejected during
    // busy.
    let mut model = unlocked();
    model.start_effect(EffectKind::Import);
    assert!(model.control_gating().settings);
    assert_eq!(
        model.start_effect(EffectKind::Settings),
        EffectStart::Rejected
    );
}

#[test]
fn toggle_control_re_enables_after_complete_effect() {
    let mut model = unlocked();
    model.start_effect(EffectKind::Import);
    assert!(model.control_gating().settings);
    model.complete_effect(true);
    assert!(!model.control_gating().settings);
    // And a settings effect can now start.
    assert_eq!(
        model.start_effect(EffectKind::Settings),
        EffectStart::Accepted
    );
}

// ---------------------------------------------------------------------------
// Worker that fails before returning (V, S) routes to StartupError without
// reconstructing in-memory vault state
// ---------------------------------------------------------------------------

#[test]
fn worker_lost_transitions_to_startup_error() {
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    model.worker_lost();
    assert_eq!(model.state(), AppState::StartupError);
    assert!(!model.is_busy());
    assert_eq!(model.current_effect(), None);
}

#[test]
fn worker_lost_clears_pending_lock_and_quit_flags() {
    // The (V, S) pair is gone; there is nothing left to lock and the
    // app is already routing to StartupError. The AppModel surfaces
    // the StartupErrorComponent which offers retry / quit on its
    // own. Carrying the pending flags forward would risk firing
    // either against an Unlocked state we no longer have.
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    model.auto_lock_expired(true);
    model.request_quit();
    assert!(model.pending_lock());
    assert!(model.pending_quit());
    model.worker_lost();
    assert!(!model.pending_lock());
    assert!(!model.pending_quit());
}

#[test]
fn complete_effect_after_worker_lost_does_not_resurrect_unlocked() {
    // Defense in depth: even if a stale `complete_effect` were
    // dispatched after `worker_lost`, the state must not flip back
    // to Unlocked. The in-memory (V, S) is gone — only the
    // StartupErrorComponent's retry path can rebuild it.
    let mut model = unlocked();
    model.start_effect(EffectKind::AddAccount);
    model.worker_lost();
    let outcome = model.complete_effect(true);
    assert!(matches!(outcome, CompleteOutcome::Ready));
    assert_eq!(model.state(), AppState::StartupError);
}
