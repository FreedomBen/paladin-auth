// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic settings tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests >
//! `tests/settings_logic.rs`" checklist in
//! `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Live-apply path runs `Vault::mutate_and_save` once per accepted
//!   change (modeled here as `ToggleOutcome::Save` /
//!   `DebounceOutcome::Save` returning exactly one
//!   [`paladin_core::SettingPatch`] per accepted transition).
//! * Spinners clamp to
//!   `paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`
//!   and
//!   `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`.
//! * 500 ms debounce coalesces repeated spinner changes so only the
//!   most recent buffered value reaches `mutate_and_save`.
//! * `save_not_committed` reverts the visible widget value to the
//!   last committed state.
//! * `save_durability_unconfirmed` keeps the new value visible and
//!   attaches the warning to the changed `AdwPreferencesGroup` row
//!   inside the `AdwPreferencesDialog`.
//!
//! The module under test (`paladin_gtk::settings`) is the pure-logic
//! state machine the GTK `SettingsComponent` shadows. It owns no
//! widgets and never starts a timer of its own — the widget layer
//! arms a `glib::timeout_add_local(500ms, ...)` after each
//! `stage_*` call and calls `resolve_debounce` on tick. The "500 ms
//! debounce" cited in the plan checklist is enforced by that timer;
//! the state-machine bullet here is the *coalescing* contract: only
//! the most recent buffered value reaches `apply_setting_patch`.

use std::path::PathBuf;

use paladin_core::{
    ErrorKind, PaladinError, SettingPatch, AUTO_LOCK_SECS_MAX, AUTO_LOCK_SECS_MIN,
    CLIPBOARD_CLEAR_SECS_MAX, CLIPBOARD_CLEAR_SECS_MIN,
};

use paladin_gtk::settings::{
    clamp_auto_lock_secs, clamp_clipboard_clear_secs, AcceptedChange, CommittedSettings,
    DebounceOutcome, InlineError, InlineWarning, SaveOutcome, SettingsField, SettingsState,
    ToggleOutcome,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn defaults() -> CommittedSettings {
    // Mirrors `VaultSettings::default()` (DESIGN §4.7): auto-lock
    // off, 300s; clipboard-clear off, 30s. The numbers are the §4.7
    // defaults — the state machine carries them across the dialog
    // round trip but never depends on `VaultSettings::default()`
    // directly so the tests stay grounded in observable values.
    CommittedSettings::new(false, 300, false, 30)
}

fn save_not_committed_no_backup() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    }
}

fn save_not_committed_with_backup() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: true,
        backup_path: Some(PathBuf::from("/tmp/vault.bin.bak")),
    }
}

// ---------------------------------------------------------------------------
// Spinners clamp to AUTO_LOCK / CLIPBOARD_CLEAR bounds
// ---------------------------------------------------------------------------

#[test]
fn clamp_auto_lock_secs_below_min_returns_min() {
    assert_eq!(clamp_auto_lock_secs(0), AUTO_LOCK_SECS_MIN);
    assert_eq!(
        clamp_auto_lock_secs(AUTO_LOCK_SECS_MIN - 1),
        AUTO_LOCK_SECS_MIN
    );
}

#[test]
fn clamp_auto_lock_secs_above_max_returns_max() {
    assert_eq!(clamp_auto_lock_secs(u32::MAX), AUTO_LOCK_SECS_MAX);
    assert_eq!(
        clamp_auto_lock_secs(AUTO_LOCK_SECS_MAX + 1),
        AUTO_LOCK_SECS_MAX
    );
}

#[test]
fn clamp_auto_lock_secs_in_range_unchanged() {
    assert_eq!(clamp_auto_lock_secs(AUTO_LOCK_SECS_MIN), AUTO_LOCK_SECS_MIN);
    assert_eq!(clamp_auto_lock_secs(AUTO_LOCK_SECS_MAX), AUTO_LOCK_SECS_MAX);
    assert_eq!(clamp_auto_lock_secs(300), 300);
}

#[test]
fn clamp_clipboard_clear_secs_below_min_returns_min() {
    assert_eq!(clamp_clipboard_clear_secs(0), CLIPBOARD_CLEAR_SECS_MIN);
    assert_eq!(
        clamp_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MIN - 1),
        CLIPBOARD_CLEAR_SECS_MIN
    );
}

#[test]
fn clamp_clipboard_clear_secs_above_max_returns_max() {
    assert_eq!(
        clamp_clipboard_clear_secs(u32::MAX),
        CLIPBOARD_CLEAR_SECS_MAX
    );
    assert_eq!(
        clamp_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MAX + 1),
        CLIPBOARD_CLEAR_SECS_MAX
    );
}

#[test]
fn clamp_clipboard_clear_secs_in_range_unchanged() {
    assert_eq!(
        clamp_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MIN),
        CLIPBOARD_CLEAR_SECS_MIN
    );
    assert_eq!(
        clamp_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MAX),
        CLIPBOARD_CLEAR_SECS_MAX
    );
    assert_eq!(clamp_clipboard_clear_secs(30), 30);
}

#[test]
fn stage_auto_lock_secs_clamps_to_min() {
    let mut state = SettingsState::new(defaults());
    let returned = state.stage_auto_lock_secs(0);
    assert_eq!(returned, AUTO_LOCK_SECS_MIN);
    assert_eq!(state.visible_auto_lock_secs(), AUTO_LOCK_SECS_MIN);
}

#[test]
fn stage_auto_lock_secs_clamps_to_max() {
    let mut state = SettingsState::new(defaults());
    let returned = state.stage_auto_lock_secs(u32::MAX);
    assert_eq!(returned, AUTO_LOCK_SECS_MAX);
    assert_eq!(state.visible_auto_lock_secs(), AUTO_LOCK_SECS_MAX);
}

#[test]
fn stage_clipboard_clear_secs_clamps_to_min() {
    let mut state = SettingsState::new(defaults());
    let returned = state.stage_clipboard_clear_secs(0);
    assert_eq!(returned, CLIPBOARD_CLEAR_SECS_MIN);
    assert_eq!(
        state.visible_clipboard_clear_secs(),
        CLIPBOARD_CLEAR_SECS_MIN
    );
}

#[test]
fn stage_clipboard_clear_secs_clamps_to_max() {
    let mut state = SettingsState::new(defaults());
    let returned = state.stage_clipboard_clear_secs(u32::MAX);
    assert_eq!(returned, CLIPBOARD_CLEAR_SECS_MAX);
    assert_eq!(
        state.visible_clipboard_clear_secs(),
        CLIPBOARD_CLEAR_SECS_MAX
    );
}

// ---------------------------------------------------------------------------
// Live-apply path runs `Vault::mutate_and_save` once per accepted change
// (toggles fire immediately; spinners fire on debounce resolution)
// ---------------------------------------------------------------------------

#[test]
fn toggle_auto_lock_enabled_returns_save_request_when_value_changes() {
    let mut state = SettingsState::new(defaults());
    let outcome = state.toggle_auto_lock_enabled(true);

    let ToggleOutcome::Save { patch, field } = outcome else {
        panic!("expected Save, got {outcome:?}");
    };
    assert!(matches!(patch, SettingPatch::AutoLockEnabled(true)));
    assert_eq!(field, SettingsField::AutoLockEnabled);
}

#[test]
fn toggle_auto_lock_enabled_returns_noop_when_value_unchanged() {
    let mut state = SettingsState::new(defaults());
    // `defaults()` has auto-lock disabled.
    let outcome = state.toggle_auto_lock_enabled(false);
    assert!(matches!(outcome, ToggleOutcome::Noop));
}

#[test]
fn toggle_clipboard_clear_enabled_returns_save_request_when_value_changes() {
    let mut state = SettingsState::new(defaults());
    let outcome = state.toggle_clipboard_clear_enabled(true);

    let ToggleOutcome::Save { patch, field } = outcome else {
        panic!("expected Save, got {outcome:?}");
    };
    assert!(matches!(patch, SettingPatch::ClipboardClearEnabled(true)));
    assert_eq!(field, SettingsField::ClipboardClearEnabled);
}

#[test]
fn toggle_clipboard_clear_enabled_returns_noop_when_value_unchanged() {
    let mut state = SettingsState::new(defaults());
    let outcome = state.toggle_clipboard_clear_enabled(false);
    assert!(matches!(outcome, ToggleOutcome::Noop));
}

#[test]
fn stage_spinner_does_not_fire_save_immediately() {
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    // The state machine never starts the timer; the only way for a
    // spinner to reach `mutate_and_save` is through
    // `resolve_debounce` returning `Save`. So immediately after
    // staging, the dialog has buffered a value but has not asked
    // for a save.
    let outcome = state.resolve_debounce();
    let DebounceOutcome::Save { patch, field } = outcome else {
        panic!("expected Save after debounce, got {outcome:?}");
    };
    assert!(matches!(patch, SettingPatch::AutoLockTimeoutSecs(60)));
    assert_eq!(field, SettingsField::AutoLockSecs);
}

#[test]
fn resolve_debounce_returns_idle_when_no_pending() {
    let mut state = SettingsState::new(defaults());
    assert!(matches!(state.resolve_debounce(), DebounceOutcome::Idle));
}

#[test]
fn resolve_debounce_returns_idle_when_pending_matches_committed() {
    let mut state = SettingsState::new(defaults());
    // `defaults()` has auto_lock_secs = 300.
    state.stage_auto_lock_secs(300);
    assert!(matches!(state.resolve_debounce(), DebounceOutcome::Idle));
}

#[test]
fn resolve_debounce_clears_pending_after_firing() {
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    assert!(matches!(
        state.resolve_debounce(),
        DebounceOutcome::Save { .. }
    ));
    // A second tick with no further changes is idle.
    assert!(matches!(state.resolve_debounce(), DebounceOutcome::Idle));
}

// ---------------------------------------------------------------------------
// 500 ms debounce coalesces repeated spinner changes — only the most recent
// buffered value reaches `mutate_and_save`
// ---------------------------------------------------------------------------

#[test]
fn multiple_auto_lock_spinner_changes_coalesce_to_latest_on_debounce() {
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    state.stage_auto_lock_secs(90);
    state.stage_auto_lock_secs(120);

    let outcome = state.resolve_debounce();
    let DebounceOutcome::Save { patch, field } = outcome else {
        panic!("expected Save, got {outcome:?}");
    };
    assert!(matches!(patch, SettingPatch::AutoLockTimeoutSecs(120)));
    assert_eq!(field, SettingsField::AutoLockSecs);
}

#[test]
fn multiple_clipboard_clear_spinner_changes_coalesce_to_latest_on_debounce() {
    let mut state = SettingsState::new(defaults());
    state.stage_clipboard_clear_secs(10);
    state.stage_clipboard_clear_secs(15);
    state.stage_clipboard_clear_secs(60);

    let outcome = state.resolve_debounce();
    let DebounceOutcome::Save { patch, field } = outcome else {
        panic!("expected Save, got {outcome:?}");
    };
    assert!(matches!(patch, SettingPatch::ClipboardClearSecs(60)));
    assert_eq!(field, SettingsField::ClipboardClearSecs);
}

#[test]
fn switching_spinner_fields_during_debounce_replaces_pending() {
    // The dialog only ever debounces a single pending spinner — the
    // SettingsField changes when the user moves focus to the other
    // row, and the prior pending is dropped (no orphaned save
    // request for the previous row).
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    state.stage_clipboard_clear_secs(60);

    let outcome = state.resolve_debounce();
    let DebounceOutcome::Save { patch, field } = outcome else {
        panic!("expected Save, got {outcome:?}");
    };
    assert!(matches!(patch, SettingPatch::ClipboardClearSecs(60)));
    assert_eq!(field, SettingsField::ClipboardClearSecs);
}

#[test]
fn debounce_during_inflight_save_accumulates_for_next_tick() {
    // Per the effect_ownership checklist bullet "Settings spinner
    // debounce coalesces to the latest pre-save value when an
    // effect is in flight." The state machine itself does not gate
    // on in-flight effects (that's the AppModel's job); but the
    // *coalescing* contract — that pending entries survive across
    // an apply_save_result cycle and fire on the next debounce —
    // is enforced here.
    let mut state = SettingsState::new(defaults());

    // First save fires for value 60.
    state.stage_auto_lock_secs(60);
    let DebounceOutcome::Save { .. } = state.resolve_debounce() else {
        panic!("expected first Save");
    };
    state.apply_save_result(AcceptedChange::AutoLockSecs(60), Ok(()));

    // User keeps typing during the save — pending accumulates.
    state.stage_auto_lock_secs(90);
    state.stage_auto_lock_secs(120);

    // Next debounce fires the latest value once.
    let outcome = state.resolve_debounce();
    let DebounceOutcome::Save { patch, field } = outcome else {
        panic!("expected Save, got {outcome:?}");
    };
    assert!(matches!(patch, SettingPatch::AutoLockTimeoutSecs(120)));
    assert_eq!(field, SettingsField::AutoLockSecs);
}

// ---------------------------------------------------------------------------
// `save_not_committed` reverts the visible widget value to the last committed
// state
// ---------------------------------------------------------------------------

#[test]
fn apply_save_not_committed_reverts_auto_lock_secs_to_committed() {
    let mut state = SettingsState::new(defaults());

    state.stage_auto_lock_secs(60);
    let _ = state.resolve_debounce();

    let outcome = state.apply_save_result(
        AcceptedChange::AutoLockSecs(60),
        Err(save_not_committed_no_backup()),
    );

    let SaveOutcome::Rollback { error, field } = outcome else {
        panic!("expected Rollback, got {outcome:?}");
    };
    assert_eq!(error.kind, ErrorKind::SaveNotCommitted);
    assert_eq!(field, SettingsField::AutoLockSecs);

    // The visible value reverts to the last committed state (300s).
    assert_eq!(state.visible_auto_lock_secs(), 300);
    assert_eq!(state.committed().auto_lock_secs(), 300);
}

#[test]
fn apply_save_not_committed_reverts_auto_lock_enabled_to_committed() {
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);

    let outcome = state.apply_save_result(
        AcceptedChange::AutoLockEnabled(true),
        Err(save_not_committed_with_backup()),
    );

    let SaveOutcome::Rollback { error, field } = outcome else {
        panic!("expected Rollback, got {outcome:?}");
    };
    assert_eq!(error.kind, ErrorKind::SaveNotCommitted);
    assert_eq!(field, SettingsField::AutoLockEnabled);

    // Committed remains disabled (false) — toggle reverts.
    assert!(!state.committed().auto_lock_enabled());
}

#[test]
fn apply_save_not_committed_reverts_clipboard_clear_secs_to_committed() {
    let mut state = SettingsState::new(defaults());
    state.stage_clipboard_clear_secs(60);
    let _ = state.resolve_debounce();

    let outcome = state.apply_save_result(
        AcceptedChange::ClipboardClearSecs(60),
        Err(save_not_committed_no_backup()),
    );

    let SaveOutcome::Rollback { error, field } = outcome else {
        panic!("expected Rollback, got {outcome:?}");
    };
    assert_eq!(error.kind, ErrorKind::SaveNotCommitted);
    assert_eq!(field, SettingsField::ClipboardClearSecs);

    assert_eq!(state.committed().clipboard_clear_secs(), 30);
}

#[test]
fn apply_save_not_committed_reverts_clipboard_clear_enabled_to_committed() {
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_clipboard_clear_enabled(true);

    let outcome = state.apply_save_result(
        AcceptedChange::ClipboardClearEnabled(true),
        Err(save_not_committed_no_backup()),
    );

    let SaveOutcome::Rollback { error, field } = outcome else {
        panic!("expected Rollback, got {outcome:?}");
    };
    assert_eq!(error.kind, ErrorKind::SaveNotCommitted);
    assert_eq!(field, SettingsField::ClipboardClearEnabled);

    assert!(!state.committed().clipboard_clear_enabled());
}

// ---------------------------------------------------------------------------
// `save_durability_unconfirmed` keeps the new value visible and attaches the
// warning to the changed row
// ---------------------------------------------------------------------------

#[test]
fn apply_save_durability_unconfirmed_keeps_auto_lock_secs_visible_with_warning() {
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    let _ = state.resolve_debounce();

    let outcome = state.apply_save_result(
        AcceptedChange::AutoLockSecs(60),
        Err(PaladinError::SaveDurabilityUnconfirmed),
    );

    let SaveOutcome::DurabilityWarning { warning, field } = outcome else {
        panic!("expected DurabilityWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    // The warning attaches to the row whose value was just saved.
    assert_eq!(field, SettingsField::AutoLockSecs);
    // File is on disk — committed reflects the new value.
    assert_eq!(state.committed().auto_lock_secs(), 60);
    assert_eq!(state.visible_auto_lock_secs(), 60);
}

#[test]
fn apply_save_durability_unconfirmed_keeps_clipboard_clear_secs_visible_with_warning() {
    let mut state = SettingsState::new(defaults());
    state.stage_clipboard_clear_secs(60);
    let _ = state.resolve_debounce();

    let outcome = state.apply_save_result(
        AcceptedChange::ClipboardClearSecs(60),
        Err(PaladinError::SaveDurabilityUnconfirmed),
    );

    let SaveOutcome::DurabilityWarning { warning, field } = outcome else {
        panic!("expected DurabilityWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert_eq!(field, SettingsField::ClipboardClearSecs);
    assert_eq!(state.committed().clipboard_clear_secs(), 60);
}

#[test]
fn apply_save_durability_unconfirmed_keeps_auto_lock_enabled_visible_with_warning() {
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);

    let outcome = state.apply_save_result(
        AcceptedChange::AutoLockEnabled(true),
        Err(PaladinError::SaveDurabilityUnconfirmed),
    );

    let SaveOutcome::DurabilityWarning { warning, field } = outcome else {
        panic!("expected DurabilityWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert_eq!(field, SettingsField::AutoLockEnabled);
    assert!(state.committed().auto_lock_enabled());
}

#[test]
fn apply_save_durability_unconfirmed_keeps_clipboard_clear_enabled_visible_with_warning() {
    // Mirrors `apply_save_durability_unconfirmed_keeps_auto_lock_enabled_visible_with_warning`
    // for the second toggle. The three existing durability tests cover
    // `AutoLockSecs`, `ClipboardClearSecs`, and `AutoLockEnabled`;
    // without this test the `ClipboardClearEnabled` toggle would have
    // no durability-warning assertion, so a regression that swapped
    // the `commit_attempted` arm for `ClipboardClearEnabled` inside the
    // `SaveDurabilityUnconfirmed` branch against, say,
    // `AutoLockEnabled` would land undetected. Pairs with
    // `apply_save_success_promotes_clipboard_clear_enabled_to_committed`
    // on the field-coverage side so every `SettingsField` variant now
    // has both a success-path and a durability-warning-path assertion,
    // matching the §"Tests > Pure-logic unit tests >
    // `tests/settings_logic.rs`" checklist entry that the
    // `save_durability_unconfirmed` warning attaches to "the changed
    // `AdwPreferencesGroup` row" — for every row, not just three of
    // the four.
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_clipboard_clear_enabled(true);

    let outcome = state.apply_save_result(
        AcceptedChange::ClipboardClearEnabled(true),
        Err(PaladinError::SaveDurabilityUnconfirmed),
    );

    let SaveOutcome::DurabilityWarning { warning, field } = outcome else {
        panic!("expected DurabilityWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert_eq!(field, SettingsField::ClipboardClearEnabled);
    assert!(state.committed().clipboard_clear_enabled());
}

// ---------------------------------------------------------------------------
// Apply save success — committed promotes to the attempted value
// ---------------------------------------------------------------------------

#[test]
fn apply_save_success_promotes_auto_lock_secs_to_committed() {
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    let _ = state.resolve_debounce();

    let outcome = state.apply_save_result(AcceptedChange::AutoLockSecs(60), Ok(()));
    assert!(matches!(outcome, SaveOutcome::Success));
    assert_eq!(state.committed().auto_lock_secs(), 60);
    assert_eq!(state.visible_auto_lock_secs(), 60);
}

#[test]
fn apply_save_success_promotes_clipboard_clear_enabled_to_committed() {
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_clipboard_clear_enabled(true);

    let outcome = state.apply_save_result(AcceptedChange::ClipboardClearEnabled(true), Ok(()));
    assert!(matches!(outcome, SaveOutcome::Success));
    assert!(state.committed().clipboard_clear_enabled());
}

#[test]
fn apply_save_success_promotes_auto_lock_enabled_to_committed() {
    // Mirrors `apply_save_success_promotes_clipboard_clear_enabled_to_committed`
    // for the second toggle. The two existing success-path tests cover
    // `AutoLockSecs` (spinner field) and `ClipboardClearEnabled`
    // (toggle field); without this test the `AutoLockEnabled` toggle
    // would have no success-path assertion, so a regression that swapped
    // the `commit_attempted` arm for `AutoLockEnabled` against, say,
    // `ClipboardClearEnabled` would land undetected. Pairs with
    // `apply_save_durability_unconfirmed_keeps_auto_lock_enabled_visible_with_warning`
    // on the field-coverage side so every `SettingsField` variant has
    // both a success-path and a durability-warning-path assertion.
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);

    let outcome = state.apply_save_result(AcceptedChange::AutoLockEnabled(true), Ok(()));
    assert!(matches!(outcome, SaveOutcome::Success));
    assert!(state.committed().auto_lock_enabled());
}

#[test]
fn apply_save_success_promotes_clipboard_clear_secs_to_committed() {
    // Mirrors `apply_save_success_promotes_auto_lock_secs_to_committed`
    // for the second spinner. The two existing success-path tests cover
    // `AutoLockSecs` (spinner field) and `ClipboardClearEnabled`
    // (toggle field); without this test the `ClipboardClearSecs`
    // spinner would have no success-path assertion, so a regression
    // that swapped the `commit_attempted` arm for `ClipboardClearSecs`
    // against, say, `AutoLockSecs` would land undetected. Pairs with
    // `apply_save_durability_unconfirmed_keeps_clipboard_clear_secs_visible_with_warning`
    // on the field-coverage side so every `SettingsField` variant has
    // both a success-path and a durability-warning-path assertion. The
    // visible-value assertion below also pins the
    // `visible_clipboard_clear_secs` projection promoting to the
    // committed value once the pending buffer is consumed by the
    // resolve_debounce + apply_save_result round trip.
    let mut state = SettingsState::new(defaults());
    state.stage_clipboard_clear_secs(60);
    let _ = state.resolve_debounce();

    let outcome = state.apply_save_result(AcceptedChange::ClipboardClearSecs(60), Ok(()));
    assert!(matches!(outcome, SaveOutcome::Success));
    assert_eq!(state.committed().clipboard_clear_secs(), 60);
    assert_eq!(state.visible_clipboard_clear_secs(), 60);
}

// ---------------------------------------------------------------------------
// Apply other typed errors — visible value rolls back, inline error attached
// ---------------------------------------------------------------------------

#[test]
fn apply_save_io_error_routes_to_inline_and_rolls_back_visible_value() {
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    let _ = state.resolve_debounce();

    let err = PaladinError::IoError {
        operation: "vault_save",
        source: std::io::Error::other("disk full"),
    };
    let outcome = state.apply_save_result(AcceptedChange::AutoLockSecs(60), Err(err));

    let SaveOutcome::Inline { error, field } = outcome else {
        panic!("expected Inline, got {outcome:?}");
    };
    assert_eq!(error.kind, ErrorKind::IoError);
    assert_eq!(field, SettingsField::AutoLockSecs);

    // Inline errors are non-mutating from the dialog's perspective —
    // the on-disk file did not change, so the committed reverts.
    assert_eq!(state.committed().auto_lock_secs(), 300);
}

#[test]
fn apply_save_io_error_for_toggle_routes_to_inline_and_keeps_committed_unchanged() {
    // Sibling of `apply_save_io_error_routes_to_inline_and_rolls_back_visible_value`
    // on the toggle side. The existing test exercises the spinner
    // path (`AutoLockSecs` with a pending buffer); this test
    // exercises the toggle path (`AutoLockEnabled`, no pending
    // buffer — toggles bypass debounce). Both must route a
    // non-`SaveNotCommitted` / non-`SaveDurabilityUnconfirmed`
    // failure (here `IoError`, the §5 catchall arm) to
    // `SaveOutcome::Inline` so the matching `AdwSwitchRow` shows
    // the red error subtitle, and both must leave `committed`
    // unchanged so the visible toggle (which mirrors
    // `committed.auto_lock_enabled` because toggles have no
    // pending buffer) rolls back to the pre-toggle state.
    //
    // Without this assertion a regression that special-cased
    // `commit_attempted` for toggle fields (e.g. promoting the
    // value even on `Inline`) would land undetected — the dialog
    // would then show a red error subtitle but the toggle position
    // would silently match the failed save, masking the failure.
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);

    let err = PaladinError::IoError {
        operation: "vault_save",
        source: std::io::Error::other("disk full"),
    };
    let outcome = state.apply_save_result(AcceptedChange::AutoLockEnabled(true), Err(err));

    let SaveOutcome::Inline { error, field } = outcome else {
        panic!("expected Inline, got {outcome:?}");
    };
    assert_eq!(error.kind, ErrorKind::IoError);
    assert_eq!(field, SettingsField::AutoLockEnabled);

    // The on-disk file did not change, so the committed toggle
    // reverts to its pre-toggle state. `defaults()` returns
    // `auto_lock_enabled = false`.
    assert!(!state.committed().auto_lock_enabled());
}

#[test]
fn apply_save_io_error_for_clipboard_clear_secs_routes_to_inline_and_rolls_back_visible_value() {
    // Mirrors `apply_save_io_error_routes_to_inline_and_rolls_back_visible_value`
    // for the `ClipboardClearSecs` spinner. The original test
    // pinned the spinner-path rollback for `AutoLockSecs`; this
    // test pins the same behavior for the clipboard-clear-secs
    // spinner so every `SettingsField` spinner variant has an
    // io-error-path assertion that the visible value (driven by
    // the pending buffer) snaps back to `committed` once the save
    // fails inline.
    //
    // Without this companion test a regression that special-cased
    // `commit_attempted` for `ClipboardClearSecs` on the `Inline`
    // arm could land undetected on the clipboard-clear spinner
    // even though the auto-lock spinner stayed correct.
    let mut state = SettingsState::new(defaults());
    state.stage_clipboard_clear_secs(45);
    let _ = state.resolve_debounce();

    let err = PaladinError::IoError {
        operation: "vault_save",
        source: std::io::Error::other("disk full"),
    };
    let outcome = state.apply_save_result(AcceptedChange::ClipboardClearSecs(45), Err(err));

    let SaveOutcome::Inline { error, field } = outcome else {
        panic!("expected Inline, got {outcome:?}");
    };
    assert_eq!(error.kind, ErrorKind::IoError);
    assert_eq!(field, SettingsField::ClipboardClearSecs);

    // Inline errors are non-mutating from the dialog's perspective —
    // the on-disk file did not change, so the committed value
    // stays at the pre-stage default (`clipboard_clear_secs = 30`).
    assert_eq!(state.committed().clipboard_clear_secs(), 30);
}

#[test]
fn apply_save_io_error_for_clipboard_clear_enabled_routes_to_inline_and_keeps_committed_unchanged()
{
    // Mirrors `apply_save_io_error_for_toggle_routes_to_inline_and_keeps_committed_unchanged`
    // for the `ClipboardClearEnabled` toggle. The original test
    // pinned the toggle-path inline rollback for `AutoLockEnabled`;
    // this test pins the same behavior for the clipboard-clear
    // toggle so every `SettingsField` toggle variant has an
    // io-error-path assertion that `commit_attempted` does **not**
    // promote on the `Inline` arm, so the visible toggle (which
    // mirrors `committed.clipboard_clear_enabled` because toggles
    // have no pending buffer) reverts to its pre-toggle state.
    //
    // Without this companion test a regression that special-cased
    // `commit_attempted` for `ClipboardClearEnabled` could land
    // undetected on the clipboard-clear toggle even though the
    // auto-lock toggle stayed correct.
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_clipboard_clear_enabled(true);

    let err = PaladinError::IoError {
        operation: "vault_save",
        source: std::io::Error::other("disk full"),
    };
    let outcome = state.apply_save_result(AcceptedChange::ClipboardClearEnabled(true), Err(err));

    let SaveOutcome::Inline { error, field } = outcome else {
        panic!("expected Inline, got {outcome:?}");
    };
    assert_eq!(error.kind, ErrorKind::IoError);
    assert_eq!(field, SettingsField::ClipboardClearEnabled);

    // The on-disk file did not change, so the committed toggle
    // reverts to its pre-toggle state. `defaults()` returns
    // `clipboard_clear_enabled = false`.
    assert!(!state.committed().clipboard_clear_enabled());
}

// ---------------------------------------------------------------------------
// SettingsComponent format helpers — `AdwPreferencesDialog` chrome
// ---------------------------------------------------------------------------

#[test]
fn format_settings_dialog_auto_lock_group_title_returns_auto_lock() {
    // The SettingsComponent organizes the dialog into two
    // `AdwPreferencesGroup`s per `IMPLEMENTATION_PLAN_04_GTK.md`
    // §"libadwaita usage" > "Preferences": one for auto-lock,
    // one for clipboard-clear. This helper pins the title for
    // the auto-lock group so the wording appears in one place
    // shared by the widget binding and the pure-logic tests in
    // `tests/settings_logic.rs`.
    //
    // The wording (`"Auto-lock"`) names the concept the §4.7
    // `paladin_core::VaultSettings::auto_lock_enabled` /
    // `paladin_core::VaultSettings::auto_lock_secs` fields
    // control without restating what the toggle does — the
    // `AdwSwitchRow` / `AdwSpinRow` row labels (added in
    // follow-up commits) carry the per-control wording.
    use paladin_gtk::settings::format_settings_dialog_auto_lock_group_title;

    assert_eq!(
        format_settings_dialog_auto_lock_group_title(),
        "Auto-lock",
        "AdwPreferencesGroup title names the auto-lock concept",
    );
}

#[test]
fn format_settings_dialog_clipboard_clear_enabled_row_title_returns_clear_after_copy() {
    // The clipboard-clear `AdwSwitchRow` carries the toggle
    // that controls
    // `paladin_core::VaultSettings::clipboard_clear_enabled`.
    // Sibling of `format_settings_dialog_auto_lock_enabled_row_title`
    // on the clipboard side per `IMPLEMENTATION_PLAN_04_GTK.md`
    // §"libadwaita usage" > "Preferences".
    //
    // The wording (`"Clear clipboard after copy"`) names the
    // behavior the user is enabling — the clipboard contents
    // are zeroed after the matching timeout elapses — without
    // restating `"enabled"` or `"clipboard"` (the group title
    // already names that concept). Verb-led wording per the
    // GNOME HIG.
    use paladin_gtk::settings::format_settings_dialog_clipboard_clear_enabled_row_title;

    assert_eq!(
        format_settings_dialog_clipboard_clear_enabled_row_title(),
        "Clear clipboard after copy",
        "AdwSwitchRow title is verb-led and HIG-conformant",
    );
}

#[test]
fn format_settings_dialog_auto_lock_secs_row_title_returns_inactivity_timeout() {
    // The auto-lock `AdwSpinRow` carries the spinner that
    // controls `paladin_core::VaultSettings::auto_lock_secs`.
    // Per `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Preferences" and §"Component tree" > `SettingsComponent`,
    // the spinner clamps to
    // `paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`
    // and is debounced 500 ms so holding the +/- buttons does
    // not fire one `Vault::mutate_and_save` per click.
    //
    // The wording (`"Inactivity timeout (seconds)"`) names the
    // dimension the spinner adjusts and units the value uses
    // without restating "auto-lock" (the group title already
    // names that concept) or "lock" (the sibling
    // `AdwSwitchRow` title already names that).
    use paladin_gtk::settings::format_settings_dialog_auto_lock_secs_row_title;

    assert_eq!(
        format_settings_dialog_auto_lock_secs_row_title(),
        "Inactivity timeout (seconds)",
        "AdwSpinRow title names the dimension and units",
    );
}

#[test]
fn format_settings_dialog_auto_lock_enabled_row_title_returns_lock_after_inactivity() {
    // The auto-lock `AdwSwitchRow` carries the toggle that
    // controls `paladin_core::VaultSettings::auto_lock_enabled`.
    // Per `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Preferences", the SettingsComponent uses idiomatic
    // libadwaita rows — `AdwSwitchRow` for toggles, `AdwSpinRow`
    // for timeouts.
    //
    // The wording (`"Lock after inactivity"`) names the
    // behavior the user is enabling — the dialog locks the
    // vault after the matching idle window expires — without
    // restating "enabled" or "auto-lock" (the group title
    // already names that concept). Verb-led wording per the
    // GNOME HIG.
    use paladin_gtk::settings::format_settings_dialog_auto_lock_enabled_row_title;

    assert_eq!(
        format_settings_dialog_auto_lock_enabled_row_title(),
        "Lock after inactivity",
        "AdwSwitchRow title is verb-led and HIG-conformant",
    );
}

#[test]
fn format_settings_dialog_clipboard_clear_group_title_returns_clipboard() {
    // Sibling of `format_settings_dialog_auto_lock_group_title`
    // on the clipboard-clear `AdwPreferencesGroup` side. This
    // helper pins the title for the clipboard-clear group so the
    // wording appears in one place shared by the widget binding
    // and the pure-logic tests in `tests/settings_logic.rs`.
    //
    // The wording (`"Clipboard"`) names the concept the §4.7
    // `paladin_core::VaultSettings::clipboard_clear_enabled` /
    // `paladin_core::VaultSettings::clipboard_clear_secs` fields
    // control. The shorter form (`"Clipboard"`) over
    // `"Clipboard auto-clear"` keeps the group-title surface lean
    // — the per-row labels (added in follow-up commits) carry
    // the verb-led wording on the `AdwSwitchRow` /
    // `AdwSpinRow` themselves.
    use paladin_gtk::settings::format_settings_dialog_clipboard_clear_group_title;

    assert_eq!(
        format_settings_dialog_clipboard_clear_group_title(),
        "Clipboard",
        "AdwPreferencesGroup title names the clipboard-clear concept",
    );
}

#[test]
fn compose_settings_dialog_clipboard_clear_secs_sensitive_follows_clipboard_clear_enabled() {
    // The clipboard-clear seconds `AdwSpinRow` binds its
    // `set_sensitive:` attribute to this composer per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `SettingsComponent`. Sibling of
    // `compose_settings_dialog_auto_lock_secs_sensitive` on the
    // clipboard side; together they cover both
    // `AdwSpinRow::set_sensitive:` bindings the
    // `SettingsComponent` mounts.
    use paladin_gtk::settings::{
        compose_settings_dialog_clipboard_clear_secs_sensitive, CommittedSettings, SettingsState,
    };

    let state_on = SettingsState::new(CommittedSettings::new(false, 60, true, 20));
    assert!(
        compose_settings_dialog_clipboard_clear_secs_sensitive(&state_on),
        "spinner row is sensitive when the toggle is on",
    );

    let state_off = SettingsState::new(CommittedSettings::new(false, 60, false, 20));
    assert!(
        !compose_settings_dialog_clipboard_clear_secs_sensitive(&state_off),
        "spinner row is insensitive when the toggle is off",
    );
}

#[test]
fn compose_settings_dialog_auto_lock_secs_sensitive_follows_auto_lock_enabled() {
    // The auto-lock seconds `AdwSpinRow` binds its
    // `set_sensitive:` attribute to this composer per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `SettingsComponent`. When the auto-lock toggle is off, the
    // seconds spinner has no effect — disabling it follows the
    // GNOME HIG ("disable controls whose effect is conditional on
    // a sibling") and visually signals the dependency. Threading
    // the bool through this composer keeps the widget binding
    // minimal: the widget's `#[watch] set_sensitive:` reads a
    // single `bool` instead of reaching into [`CommittedSettings`]
    // inline.
    //
    // Sibling of `compose_settings_dialog_auto_lock_enabled_active`
    // (the gating toggle) and of the clipboard-clear sensitivity
    // composer (added in a follow-up commit) on the spinner-row
    // sensitivity side.
    use paladin_gtk::settings::{
        compose_settings_dialog_auto_lock_secs_sensitive, CommittedSettings, SettingsState,
    };

    let state_on = SettingsState::new(CommittedSettings::new(true, 600, false, 30));
    assert!(
        compose_settings_dialog_auto_lock_secs_sensitive(&state_on),
        "spinner row is sensitive when the toggle is on",
    );

    let state_off = SettingsState::new(CommittedSettings::new(false, 600, false, 30));
    assert!(
        !compose_settings_dialog_auto_lock_secs_sensitive(&state_off),
        "spinner row is insensitive when the toggle is off",
    );
}

#[test]
fn compose_settings_dialog_clipboard_clear_enabled_active_mirrors_committed_clipboard_clear_enabled(
) {
    // The clipboard-clear `AdwSwitchRow` binds its `set_active:`
    // attribute to this composer per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `SettingsComponent`. Sibling of
    // `compose_settings_dialog_auto_lock_enabled_active` on the
    // clipboard side; together they cover both
    // `AdwSwitchRow::set_active:` bindings the
    // `SettingsComponent` mounts.
    use paladin_gtk::settings::{
        compose_settings_dialog_clipboard_clear_enabled_active, CommittedSettings, SettingsState,
    };

    let state_on = SettingsState::new(CommittedSettings::new(false, 60, true, 20));
    assert!(
        compose_settings_dialog_clipboard_clear_enabled_active(&state_on),
        "composer is `true` when committed.clipboard_clear_enabled is true",
    );

    let state_off = SettingsState::new(CommittedSettings::new(false, 60, false, 20));
    assert!(
        !compose_settings_dialog_clipboard_clear_enabled_active(&state_off),
        "composer is `false` when committed.clipboard_clear_enabled is false",
    );
}

#[test]
fn compose_settings_dialog_auto_lock_enabled_active_mirrors_committed_auto_lock_enabled() {
    // The auto-lock `AdwSwitchRow` binds its `set_active:`
    // attribute to this composer per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `SettingsComponent`. Toggle clicks bypass the spinner
    // debounce buffer because they reflect a discrete user
    // intent — the committed `CommittedSettings::auto_lock_enabled`
    // is therefore the single source of truth for the switch's
    // active state.
    //
    // Sibling of `compose_settings_dialog_auto_lock_secs_value`
    // on the auto-lock side and of the clipboard-clear toggle
    // composer (added in a follow-up commit) on the switch-row
    // side; together they cover every state-driven row binding
    // the `SettingsComponent` mounts.
    use paladin_gtk::settings::{
        compose_settings_dialog_auto_lock_enabled_active, CommittedSettings, SettingsState,
    };

    let state_on = SettingsState::new(CommittedSettings::new(true, 600, false, 30));
    assert!(
        compose_settings_dialog_auto_lock_enabled_active(&state_on),
        "composer is `true` when committed.auto_lock_enabled is true",
    );

    let state_off = SettingsState::new(CommittedSettings::new(false, 600, false, 30));
    assert!(
        !compose_settings_dialog_auto_lock_enabled_active(&state_off),
        "composer is `false` when committed.auto_lock_enabled is false",
    );
}

#[test]
fn compose_settings_dialog_auto_lock_secs_value_casts_visible_auto_lock_secs_to_f64() {
    // The auto-lock `AdwSpinRow` binds its `set_value:` attribute
    // to this composer per `IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Component tree" > `SettingsComponent`. The spinner
    // value is the buffered (pending) auto-lock seconds while a
    // 500 ms debounce is in flight and the committed value
    // otherwise — both surfaced by
    // `SettingsState::visible_auto_lock_secs`. Casting the `u32`
    // through this composer matches `AdwSpinRow::set_value`'s
    // `f64` signature without forcing the widget layer to cast
    // inline.
    //
    // Sibling of `paladin_gtk::add_account::compose_manual_period_secs_value`,
    // `compose_manual_counter_value`, and `compose_manual_digits_value`
    // on the spinner-value side; together they cover every
    // `AdwSpinRow::set_value:` binding the GTK front end mounts.
    use paladin_gtk::settings::{
        compose_settings_dialog_auto_lock_secs_value, CommittedSettings, SettingsState,
    };

    let committed = CommittedSettings::new(true, 600, false, 30);
    let state = SettingsState::new(committed);

    let value = compose_settings_dialog_auto_lock_secs_value(&state);
    assert!(
        (value - 600.0).abs() < f64::EPSILON,
        "composer surfaces the committed value as `f64` when no debounce is pending",
    );
}

#[test]
fn compose_settings_dialog_auto_lock_secs_value_reflects_pending_spinner_buffer() {
    // While a 500 ms debounce is in flight,
    // `SettingsState::visible_auto_lock_secs` returns the pending
    // (buffered) value rather than the committed one — this
    // composer mirrors that contract on the widget side so the
    // spinner shows the user's most recent typed value during the
    // debounce window.
    use paladin_gtk::settings::{
        compose_settings_dialog_auto_lock_secs_value, CommittedSettings, SettingsState,
    };

    let committed = CommittedSettings::new(true, 600, false, 30);
    let mut state = SettingsState::new(committed);
    state.stage_auto_lock_secs(900);

    let value = compose_settings_dialog_auto_lock_secs_value(&state);
    assert!(
        (value - 900.0).abs() < f64::EPSILON,
        "composer surfaces the pending buffered value during the debounce window",
    );
}

#[test]
fn compose_settings_dialog_clipboard_clear_secs_value_casts_visible_clipboard_clear_secs_to_f64() {
    // The clipboard-clear `AdwSpinRow` binds its `set_value:`
    // attribute to this composer per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `SettingsComponent`. Sibling of
    // `compose_settings_dialog_auto_lock_secs_value` on the
    // clipboard side; together they cover both
    // `AdwSpinRow::set_value:` bindings the `SettingsComponent`
    // mounts.
    use paladin_gtk::settings::{
        compose_settings_dialog_clipboard_clear_secs_value, CommittedSettings, SettingsState,
    };

    let committed = CommittedSettings::new(false, 60, true, 20);
    let state = SettingsState::new(committed);

    let value = compose_settings_dialog_clipboard_clear_secs_value(&state);
    assert!(
        (value - 20.0).abs() < f64::EPSILON,
        "composer surfaces the committed value as `f64` when no debounce is pending",
    );
}

#[test]
fn compose_settings_dialog_clipboard_clear_secs_value_reflects_pending_spinner_buffer() {
    // While a 500 ms debounce is in flight,
    // `SettingsState::visible_clipboard_clear_secs` returns the
    // pending (buffered) value rather than the committed one —
    // this composer mirrors that contract on the widget side so
    // the spinner shows the user's most recent typed value during
    // the debounce window.
    use paladin_gtk::settings::{
        compose_settings_dialog_clipboard_clear_secs_value, CommittedSettings, SettingsState,
    };

    let committed = CommittedSettings::new(false, 60, true, 20);
    let mut state = SettingsState::new(committed);
    state.stage_clipboard_clear_secs(45);

    let value = compose_settings_dialog_clipboard_clear_secs_value(&state);
    assert!(
        (value - 45.0).abs() < f64::EPSILON,
        "composer surfaces the pending buffered value during the debounce window",
    );
}

#[test]
fn format_settings_dialog_auto_lock_secs_adjustment_returns_paladin_core_bounds() {
    // The auto-lock `AdwSpinRow` consumes a `gtk::Adjustment`
    // built from this helper per `IMPLEMENTATION_PLAN_04_GTK.md`
    // §"libadwaita usage" > "Preferences" and §"Component tree"
    // > `SettingsComponent`. Returning the
    // `(lower, upper, step_increment)` tuple here keeps the
    // spinner bounds pinned against
    // `paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`
    // — the same range `clamp_auto_lock_secs` and
    // `SettingsState::stage_auto_lock_secs` enforce — without
    // duplicating the integer literals at the widget layer.
    //
    // Sibling of `paladin_gtk::add_account::format_manual_period_adjustment`,
    // `format_manual_counter_adjustment`, and
    // `format_manual_digits_adjustment` on the spinner-adjustment
    // side; together they cover every `AdwSpinRow` the GTK front
    // end mounts. Step `1.0` matches the integer-only seconds
    // domain.
    use paladin_gtk::settings::format_settings_dialog_auto_lock_secs_adjustment;

    let (lower, upper, step) = format_settings_dialog_auto_lock_secs_adjustment();
    assert!(
        (lower - f64::from(paladin_core::AUTO_LOCK_SECS_MIN)).abs() < f64::EPSILON,
        "AdwSpinRow lower bound mirrors paladin_core::AUTO_LOCK_SECS_MIN",
    );
    assert!(
        (upper - f64::from(paladin_core::AUTO_LOCK_SECS_MAX)).abs() < f64::EPSILON,
        "AdwSpinRow upper bound mirrors paladin_core::AUTO_LOCK_SECS_MAX",
    );
    assert!(
        (step - 1.0).abs() < f64::EPSILON,
        "AdwSpinRow step is 1 second per click for the integer-only seconds domain",
    );
}

#[test]
fn format_settings_dialog_clipboard_clear_secs_adjustment_returns_paladin_core_bounds() {
    // The clipboard-clear `AdwSpinRow` consumes a
    // `gtk::Adjustment` built from this helper per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Preferences" and §"Component tree" > `SettingsComponent`.
    // Returning the `(lower, upper, step_increment)` tuple here
    // keeps the spinner bounds pinned against
    // `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`
    // — the same range `clamp_clipboard_clear_secs` and
    // `SettingsState::stage_clipboard_clear_secs` enforce —
    // without duplicating the integer literals at the widget
    // layer.
    //
    // Sibling of `format_settings_dialog_auto_lock_secs_adjustment`
    // on the clipboard side; together they pin both `AdwSpinRow`
    // adjustments the `SettingsComponent` hosts. Step `1.0`
    // matches the integer-only seconds domain.
    use paladin_gtk::settings::format_settings_dialog_clipboard_clear_secs_adjustment;

    let (lower, upper, step) = format_settings_dialog_clipboard_clear_secs_adjustment();
    assert!(
        (lower - f64::from(paladin_core::CLIPBOARD_CLEAR_SECS_MIN)).abs() < f64::EPSILON,
        "AdwSpinRow lower bound mirrors paladin_core::CLIPBOARD_CLEAR_SECS_MIN",
    );
    assert!(
        (upper - f64::from(paladin_core::CLIPBOARD_CLEAR_SECS_MAX)).abs() < f64::EPSILON,
        "AdwSpinRow upper bound mirrors paladin_core::CLIPBOARD_CLEAR_SECS_MAX",
    );
    assert!(
        (step - 1.0).abs() < f64::EPSILON,
        "AdwSpinRow step is 1 second per click for the integer-only seconds domain",
    );
}

#[test]
fn format_settings_dialog_clipboard_clear_secs_row_title_returns_clear_delay() {
    // The clipboard-clear `AdwSpinRow` carries the spinner that
    // controls `paladin_core::VaultSettings::clipboard_clear_secs`.
    // Per `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Preferences" and §"Component tree" > `SettingsComponent`,
    // the spinner clamps to
    // `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`
    // and is debounced 500 ms so holding the +/- buttons does
    // not fire one `Vault::mutate_and_save` per click. Sibling
    // of `format_settings_dialog_auto_lock_secs_row_title` on
    // the clipboard side; together they pin both `AdwSpinRow`
    // titles the `SettingsComponent` hosts.
    //
    // The wording (`"Clear delay (seconds)"`) names the
    // dimension the spinner adjusts (the delay before the
    // clipboard is cleared) and the units the value uses,
    // threading naturally with the sibling `AdwSwitchRow`
    // title returned by
    // `format_settings_dialog_clipboard_clear_enabled_row_title`
    // (`"Clear clipboard after copy"`). Units inline
    // parenthesized per the GNOME HIG.
    use paladin_gtk::settings::format_settings_dialog_clipboard_clear_secs_row_title;

    assert_eq!(
        format_settings_dialog_clipboard_clear_secs_row_title(),
        "Clear delay (seconds)",
        "AdwSpinRow title names the dimension and units",
    );
}

#[test]
fn format_settings_dialog_saved_toast_returns_settings_saved() {
    // Per `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Toast surface", `SettingsComponent` confirms an accepted
    // change with an `AdwToast` carrying the "settings-saved
    // confirmation" body. Pinning the wording through a helper
    // keeps the text in one place shared by the widget binding
    // (`AdwToast::new(format_settings_dialog_saved_toast())`) and
    // the pure-logic tests in `tests/settings_logic.rs`.
    //
    // The wording (`"Settings saved"`) names the affirmative
    // outcome without restating which setting changed — the
    // dialog body still shows the visible value the user picked
    // — and reads identically whether the change came from a
    // switch click or a debounced spinner edit. Verb-led, HIG-
    // conformant, and brief enough for an `AdwToast` to fit the
    // default timeout.
    //
    // No TUI parity: the TUI's `settings` command is CLI-shaped
    // and emits a stdout confirmation instead of a transient
    // toast (see `crates/paladin-tui/src/view`), so the wording
    // is GTK-specific.
    use paladin_gtk::settings::format_settings_dialog_saved_toast;

    assert_eq!(
        format_settings_dialog_saved_toast(),
        "Settings saved",
        "AdwToast body confirms the accepted change",
    );
}

#[test]
fn format_settings_dialog_title_returns_preferences() {
    // The SettingsComponent's `adw::PreferencesDialog::set_title`
    // attribute is populated from this helper. The wording
    // (`"Preferences"`) matches the menu entry label returned by
    // `format_app_menu_preferences_label` so the dialog chrome
    // reads identically to the affordance the user activated.
    // Pinning the title through a helper keeps the wording in one
    // place shared by the widget binding and the pure-logic
    // tests in `tests/settings_logic.rs`.
    //
    // No TUI parity: the TUI's `settings` command is CLI-shaped
    // and runs in-place rather than mounting a dialog header
    // (see `crates/paladin-tui/src/view`), so the wording is
    // GTK-specific. Sibling of
    // `paladin_gtk::unlock_dialog::format_unlock_dialog_title`,
    // `paladin_gtk::init_dialog::format_init_dialog_title`,
    // `paladin_gtk::rename_dialog::format_rename_dialog_title`,
    // `paladin_gtk::remove_dialog::format_remove_dialog_title`,
    // `paladin_gtk::add_account::format_add_dialog_title`, and
    // `paladin_gtk::startup_error::format_startup_error_title`
    // on the dialog-header-title side; together they pin every
    // dialog's titled surface against a single source of truth.
    use paladin_gtk::settings::format_settings_dialog_title;

    assert_eq!(
        format_settings_dialog_title(),
        "Preferences",
        "AdwPreferencesDialog title matches the menu entry label",
    );
}

#[test]
fn compose_settings_dialog_inline_subtitle_for_field_returns_none_without_outcome() {
    // Before the first save attempt the widget has no
    // `SaveOutcome` to render — the per-row inline subtitle slot
    // (a sibling `gtk::Label` beneath each `AdwSwitchRow` /
    // `AdwSpinRow` carrying the `error` CSS class, mirroring the
    // `crate::rename_dialog::RenameDialogComponent` pattern) stays
    // hidden in that idle state. Pinning the `None` reply through
    // the same helper that handles the populated cases lets the
    // widget bind a single `#[watch] set_label:` /
    // `#[watch] set_visible:` pair against
    // `compose_settings_dialog_inline_subtitle_for_field(...)`
    // instead of pattern-matching against an `Option<SaveOutcome>`
    // inline.
    use paladin_gtk::settings::compose_settings_dialog_inline_subtitle_for_field;

    for field in [
        SettingsField::AutoLockEnabled,
        SettingsField::AutoLockSecs,
        SettingsField::ClipboardClearEnabled,
        SettingsField::ClipboardClearSecs,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_for_field(None, field),
            None,
            "no outcome yet → row {field:?} has no inline subtitle text",
        );
    }
}

#[test]
fn compose_settings_dialog_inline_subtitle_for_field_returns_none_on_success_for_every_field() {
    // `SaveOutcome::Success` does not carry a field discriminator
    // because the affirmative path is reported through the global
    // `AdwToast` (body returned by `format_settings_dialog_saved_toast`)
    // rather than a per-row subtitle. Every row's subtitle helper
    // therefore reports `None` while the last outcome is `Success`,
    // even though the outcome itself is `Some`.
    use paladin_gtk::settings::compose_settings_dialog_inline_subtitle_for_field;

    let outcome = SaveOutcome::Success;
    for field in [
        SettingsField::AutoLockEnabled,
        SettingsField::AutoLockSecs,
        SettingsField::ClipboardClearEnabled,
        SettingsField::ClipboardClearSecs,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_for_field(Some(&outcome), field),
            None,
            "SaveOutcome::Success → row {field:?} has no inline subtitle text",
        );
    }
}

#[test]
fn compose_settings_dialog_inline_subtitle_for_field_returns_inline_error_text_for_matching_field()
{
    // `SaveOutcome::Inline { error, field }` carries the rendered
    // `InlineError::rendered` (the §5 `Display` body shared verbatim
    // with the CLI / TUI) so the dialog can render the failure text
    // beneath the row that triggered the save without re-formatting
    // the error. Per the implementation plan §"libadwaita usage" >
    // "Preferences": status-line errors stay inline in the affected
    // dialog rather than firing a global toast, so each
    // `SettingsField` variant must address the matching row's
    // subtitle slot and only that one.
    use paladin_gtk::settings::compose_settings_dialog_inline_subtitle_for_field;

    let err = PaladinError::IoError {
        operation: "write",
        source: std::io::Error::other("disk full"),
    };
    let outcome = SaveOutcome::Inline {
        error: InlineError::from_error(&err),
        field: SettingsField::ClipboardClearSecs,
    };
    let rendered = err.to_string();

    // Matching row carries the rendered error body.
    assert_eq!(
        compose_settings_dialog_inline_subtitle_for_field(
            Some(&outcome),
            SettingsField::ClipboardClearSecs,
        ),
        Some(rendered.as_str()),
        "inline error attaches to the row whose save failed",
    );

    // Non-matching rows stay clear.
    for other in [
        SettingsField::AutoLockEnabled,
        SettingsField::AutoLockSecs,
        SettingsField::ClipboardClearEnabled,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_for_field(Some(&outcome), other),
            None,
            "row {other:?} stays clear when the inline error targets ClipboardClearSecs",
        );
    }
}

#[test]
fn compose_settings_dialog_inline_subtitle_for_field_returns_inline_error_text_for_rollback_target_only(
) {
    // `SaveOutcome::Rollback` is the `save_not_committed` branch:
    // the on-disk file did not change, the visible widget value
    // reverts to the last committed state, and the rendered error
    // attaches to the row that attempted the save. Same per-field
    // routing as the `Inline` arm.
    use paladin_gtk::settings::compose_settings_dialog_inline_subtitle_for_field;

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: Some(PathBuf::from("/tmp/vault.bak")),
    };
    let outcome = SaveOutcome::Rollback {
        error: InlineError::from_error(&err),
        field: SettingsField::AutoLockEnabled,
    };
    let rendered = err.to_string();

    assert_eq!(
        compose_settings_dialog_inline_subtitle_for_field(
            Some(&outcome),
            SettingsField::AutoLockEnabled,
        ),
        Some(rendered.as_str()),
        "rollback error attaches to the row whose save was reverted",
    );

    for other in [
        SettingsField::AutoLockSecs,
        SettingsField::ClipboardClearEnabled,
        SettingsField::ClipboardClearSecs,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_for_field(Some(&outcome), other),
            None,
            "row {other:?} stays clear when the rollback error targets AutoLockEnabled",
        );
    }
}

#[test]
fn compose_settings_dialog_inline_subtitle_for_field_returns_durability_warning_text_for_matching_field(
) {
    // `SaveOutcome::DurabilityWarning` is the
    // `save_durability_unconfirmed` branch: the primary rename
    // succeeded so the visible value sticks, but the parent
    // directory `fsync` failed so the rendered warning attaches
    // to the changed row. Same per-field routing as the error arms,
    // sourced from `InlineWarning::rendered` instead of
    // `InlineError::rendered`.
    use paladin_gtk::settings::compose_settings_dialog_inline_subtitle_for_field;

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = SaveOutcome::DurabilityWarning {
        warning: InlineWarning::from_error(&err),
        field: SettingsField::AutoLockSecs,
    };
    let rendered = err.to_string();

    assert_eq!(
        compose_settings_dialog_inline_subtitle_for_field(
            Some(&outcome),
            SettingsField::AutoLockSecs,
        ),
        Some(rendered.as_str()),
        "durability warning attaches to the row whose save raised it",
    );

    for other in [
        SettingsField::AutoLockEnabled,
        SettingsField::ClipboardClearEnabled,
        SettingsField::ClipboardClearSecs,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_for_field(Some(&outcome), other),
            None,
            "row {other:?} stays clear when the durability warning targets AutoLockSecs",
        );
    }
}

#[test]
fn compose_settings_dialog_inline_subtitle_revealed_for_field_mirrors_subtitle_text_for_field() {
    // Sibling of `compose_settings_dialog_inline_subtitle_for_field`
    // on the `set_visible:` side: the inline subtitle gtk::Label
    // (carrying the rendered `InlineError` / `InlineWarning` body)
    // must reveal exactly when the text helper returns `Some`, so
    // the widget can bind a single `#[watch] set_visible:` against
    // the helper instead of `.is_some()` on the text projection
    // inline.
    //
    // Per the implementation plan §"libadwaita usage" >
    // "Preferences", the inline-error / durability-warning surface
    // attaches to the matching `AdwPreferencesGroup` row; the two
    // projections (text + revealed) flip together on the same
    // `SaveOutcome` dispatch so the row chrome stays consistent.
    use paladin_gtk::settings::{
        compose_settings_dialog_inline_subtitle_for_field,
        compose_settings_dialog_inline_subtitle_revealed_for_field,
    };

    let io_err = PaladinError::IoError {
        operation: "write",
        source: std::io::Error::other("disk full"),
    };
    let scenarios: [(Option<SaveOutcome>, &'static str); 5] = [
        (None, "idle: no save attempted"),
        (Some(SaveOutcome::Success), "success: row stays clear"),
        (
            Some(SaveOutcome::Inline {
                error: InlineError::from_error(&io_err),
                field: SettingsField::ClipboardClearSecs,
            }),
            "inline error targets ClipboardClearSecs",
        ),
        (
            Some(SaveOutcome::Rollback {
                error: InlineError::from_error(&save_not_committed_with_backup()),
                field: SettingsField::AutoLockEnabled,
            }),
            "rollback targets AutoLockEnabled",
        ),
        (
            Some(SaveOutcome::DurabilityWarning {
                warning: InlineWarning::from_error(&PaladinError::SaveDurabilityUnconfirmed),
                field: SettingsField::AutoLockSecs,
            }),
            "durability warning targets AutoLockSecs",
        ),
    ];

    for (outcome, label) in &scenarios {
        for field in [
            SettingsField::AutoLockEnabled,
            SettingsField::AutoLockSecs,
            SettingsField::ClipboardClearEnabled,
            SettingsField::ClipboardClearSecs,
        ] {
            let text = compose_settings_dialog_inline_subtitle_for_field(outcome.as_ref(), field);
            let revealed =
                compose_settings_dialog_inline_subtitle_revealed_for_field(outcome.as_ref(), field);
            assert_eq!(
                revealed,
                text.is_some(),
                "{label}: row {field:?} revealed flag must mirror text helper's Some/None",
            );
        }
    }
}

#[test]
fn compose_settings_dialog_inline_subtitle_css_class_for_field_routes_error_and_warning_by_variant()
{
    // The inline-subtitle `gtk::Label` styles itself by CSS class:
    // "error" for `SaveOutcome::Inline` / `SaveOutcome::Rollback`
    // (red foreground, matching the
    // `crate::rename_dialog::RenameDialogComponent` error label
    // styling), "warning" for `SaveOutcome::DurabilityWarning`
    // (amber, distinguishing the post-commit-but-fsync-failed case
    // from the pre-commit rollback path), and `None` for both the
    // idle state and `SaveOutcome::Success` (no CSS class
    // attached). Pinning the class through this helper lets the
    // widget bind `add_css_class:` and `remove_css_class:`
    // declaratively instead of re-routing on `SaveOutcome` inline.
    //
    // Mirrors the partitioning of
    // `compose_settings_dialog_inline_subtitle_for_field` (text) /
    // `compose_settings_dialog_inline_subtitle_revealed_for_field`
    // (visibility) on the styling side; the three projections flip
    // together on the same `SaveOutcome` dispatch.
    use paladin_gtk::settings::compose_settings_dialog_inline_subtitle_css_class_for_field;

    let io_err = PaladinError::IoError {
        operation: "write",
        source: std::io::Error::other("disk full"),
    };

    // Idle: no outcome → no class for any row.
    for field in [
        SettingsField::AutoLockEnabled,
        SettingsField::AutoLockSecs,
        SettingsField::ClipboardClearEnabled,
        SettingsField::ClipboardClearSecs,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_css_class_for_field(None, field),
            None,
            "idle: row {field:?} has no CSS class",
        );
    }

    // Success: outcome exists but every row stays unstyled.
    let success = SaveOutcome::Success;
    for field in [
        SettingsField::AutoLockEnabled,
        SettingsField::AutoLockSecs,
        SettingsField::ClipboardClearEnabled,
        SettingsField::ClipboardClearSecs,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_css_class_for_field(Some(&success), field),
            None,
            "Success: row {field:?} has no CSS class",
        );
    }

    // Inline error: matching row gets the "error" class.
    let inline = SaveOutcome::Inline {
        error: InlineError::from_error(&io_err),
        field: SettingsField::ClipboardClearSecs,
    };
    assert_eq!(
        compose_settings_dialog_inline_subtitle_css_class_for_field(
            Some(&inline),
            SettingsField::ClipboardClearSecs,
        ),
        Some("error"),
        "Inline error attaches the \"error\" CSS class to the matching row",
    );
    for other in [
        SettingsField::AutoLockEnabled,
        SettingsField::AutoLockSecs,
        SettingsField::ClipboardClearEnabled,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_css_class_for_field(Some(&inline), other),
            None,
            "Inline error: row {other:?} stays unstyled",
        );
    }

    // Rollback: matching row also gets the "error" class.
    let rollback = SaveOutcome::Rollback {
        error: InlineError::from_error(&save_not_committed_no_backup()),
        field: SettingsField::AutoLockEnabled,
    };
    assert_eq!(
        compose_settings_dialog_inline_subtitle_css_class_for_field(
            Some(&rollback),
            SettingsField::AutoLockEnabled,
        ),
        Some("error"),
        "Rollback error attaches the \"error\" CSS class to the reverted row",
    );

    // DurabilityWarning: matching row gets the "warning" class.
    let warning = SaveOutcome::DurabilityWarning {
        warning: InlineWarning::from_error(&PaladinError::SaveDurabilityUnconfirmed),
        field: SettingsField::AutoLockSecs,
    };
    assert_eq!(
        compose_settings_dialog_inline_subtitle_css_class_for_field(
            Some(&warning),
            SettingsField::AutoLockSecs,
        ),
        Some("warning"),
        "Durability warning attaches the \"warning\" CSS class to the changed row",
    );
    for other in [
        SettingsField::AutoLockEnabled,
        SettingsField::ClipboardClearEnabled,
        SettingsField::ClipboardClearSecs,
    ] {
        assert_eq!(
            compose_settings_dialog_inline_subtitle_css_class_for_field(Some(&warning), other),
            None,
            "Durability warning: row {other:?} stays unstyled",
        );
    }
}

#[test]
fn accepted_change_from_setting_patch_mirrors_setting_patch_enum_field_for_field() {
    // Bridge between the two parallel enums the dialog round trip
    // touches: `paladin_core::SettingPatch` (returned in
    // `ToggleOutcome::Save` / `DebounceOutcome::Save` and consumed
    // by `Vault::apply_setting_patch` inside
    // `Vault::mutate_and_save`) and `AcceptedChange` (handed to
    // `SettingsState::apply_save_result` so the state machine
    // promotes / rolls back the right field after the worker
    // returns). The widget layer keeps the patch and the change
    // side-by-side across the async hop so a fresh pending spinner
    // arriving during the save does not derail the rollback.
    //
    // Without this helper the widget has to re-match the four
    // variants by hand in two different call sites, drifting them
    // apart on every enum extension; with it the conversion lives
    // in one place that the test pins enum-variant-for-enum-variant.
    use paladin_gtk::settings::accepted_change_from_setting_patch;

    assert_eq!(
        accepted_change_from_setting_patch(&SettingPatch::AutoLockEnabled(true)),
        AcceptedChange::AutoLockEnabled(true),
    );
    assert_eq!(
        accepted_change_from_setting_patch(&SettingPatch::AutoLockEnabled(false)),
        AcceptedChange::AutoLockEnabled(false),
    );
    assert_eq!(
        accepted_change_from_setting_patch(&SettingPatch::AutoLockTimeoutSecs(AUTO_LOCK_SECS_MIN)),
        AcceptedChange::AutoLockSecs(AUTO_LOCK_SECS_MIN),
    );
    assert_eq!(
        accepted_change_from_setting_patch(&SettingPatch::AutoLockTimeoutSecs(AUTO_LOCK_SECS_MAX)),
        AcceptedChange::AutoLockSecs(AUTO_LOCK_SECS_MAX),
    );
    assert_eq!(
        accepted_change_from_setting_patch(&SettingPatch::ClipboardClearEnabled(true)),
        AcceptedChange::ClipboardClearEnabled(true),
    );
    assert_eq!(
        accepted_change_from_setting_patch(&SettingPatch::ClipboardClearEnabled(false)),
        AcceptedChange::ClipboardClearEnabled(false),
    );
    assert_eq!(
        accepted_change_from_setting_patch(&SettingPatch::ClipboardClearSecs(
            CLIPBOARD_CLEAR_SECS_MIN
        )),
        AcceptedChange::ClipboardClearSecs(CLIPBOARD_CLEAR_SECS_MIN),
    );
    assert_eq!(
        accepted_change_from_setting_patch(&SettingPatch::ClipboardClearSecs(
            CLIPBOARD_CLEAR_SECS_MAX
        )),
        AcceptedChange::ClipboardClearSecs(CLIPBOARD_CLEAR_SECS_MAX),
    );
}

// ---------------------------------------------------------------------------
// `SettingsState::last_outcome` — state-resident SaveOutcome slot
// ---------------------------------------------------------------------------

#[test]
fn settings_state_last_outcome_is_none_on_construction() {
    // A freshly opened settings dialog has no prior worker reply
    // to render — the inline-subtitle slot beneath every row must
    // stay clear until the first `apply_save_result` call.
    let state = SettingsState::new(defaults());
    assert!(
        state.last_outcome().is_none(),
        "freshly constructed SettingsState has no prior SaveOutcome",
    );
}

#[test]
fn settings_state_apply_save_result_stores_outcome_for_state_resident_lookup() {
    // The widget owns one `SettingsState` per dialog and binds the
    // inline-subtitle compose helpers
    // (`compose_settings_dialog_inline_subtitle_*_for_field`) through
    // `state.last_outcome()` so a single `#[watch]` over state covers
    // every row's body / visibility / CSS class. The state machine
    // therefore mirrors what `apply_save_result` returns into a
    // resident slot rather than forcing the widget to thread an
    // `Option<SaveOutcome>` alongside `&SettingsState` through every
    // binding.
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    let _ = state.resolve_debounce();

    // Success: the resident slot now reports the success arm so the
    // widget can decide whether to fire the saved-confirmation
    // `AdwToast` from `format_settings_dialog_saved_toast`.
    let outcome = state.apply_save_result(AcceptedChange::AutoLockSecs(60), Ok(()));
    assert!(matches!(outcome, SaveOutcome::Success));
    assert!(matches!(state.last_outcome(), Some(SaveOutcome::Success)));

    // Inline failure routes the same body verbatim into the slot so
    // the subtitle helpers (which take `Option<&SaveOutcome>`) read
    // it from the state alongside `committed()` /
    // `visible_auto_lock_secs()` without an extra widget-side cache.
    let err = PaladinError::IoError {
        operation: "vault_save",
        source: std::io::Error::other("disk full"),
    };
    let outcome = state.apply_save_result(AcceptedChange::AutoLockSecs(60), Err(err));
    let (stored_kind, stored_field) = match state.last_outcome() {
        Some(SaveOutcome::Inline { error, field }) => (error.kind, *field),
        other => panic!("expected Inline SaveOutcome in last_outcome, got {other:?}"),
    };
    assert_eq!(
        stored_kind,
        ErrorKind::IoError,
        "stored outcome carries the IoError discriminator the apply call received",
    );
    assert_eq!(
        stored_field,
        SettingsField::AutoLockSecs,
        "stored outcome targets the field that attempted the save",
    );
    // Same arm came back from `apply_save_result` directly — the
    // resident slot is a mirror, not a divergent rewrite.
    assert!(matches!(
        outcome,
        SaveOutcome::Inline {
            field: SettingsField::AutoLockSecs,
            ..
        }
    ));
}

#[test]
fn settings_state_toggle_clears_last_outcome_so_prior_inline_does_not_linger() {
    // Once the user starts a new change the prior inline error /
    // durability warning should clear — the user has acknowledged
    // it by acting again, and a stale subtitle beneath an unrelated
    // value would be visually noisy. Toggle clicks therefore reset
    // the resident slot before returning their own
    // `ToggleOutcome::Save` / `ToggleOutcome::Noop`.
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);
    let _ = state.apply_save_result(
        AcceptedChange::AutoLockEnabled(true),
        Err(PaladinError::SaveDurabilityUnconfirmed),
    );
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::DurabilityWarning { .. })
    ));

    // A fresh toggle (matching or differing) clears the slot before
    // the widget sees the new outcome.
    let _ = state.toggle_clipboard_clear_enabled(true);
    assert!(
        state.last_outcome().is_none(),
        "new toggle clears the prior outcome so the subtitle does not linger",
    );
}

#[test]
fn settings_state_stage_clears_last_outcome_so_prior_inline_does_not_linger() {
    // Spinner stage events (typed values pre-debounce) are also
    // a fresh user action — clear the resident outcome so the
    // previous error / warning does not stick to the row while the
    // user is typing a retry. Mirrors the toggle reset above.
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);
    let _ = state.apply_save_result(
        AcceptedChange::AutoLockEnabled(true),
        Err(save_not_committed_no_backup()),
    );
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::Rollback { .. })
    ));

    state.stage_auto_lock_secs(60);
    assert!(
        state.last_outcome().is_none(),
        "new spinner stage clears the prior outcome so the subtitle does not linger",
    );
}

#[test]
fn format_settings_dialog_spinner_page_increment_returns_ten() {
    // `gtk::Adjustment::new` takes a `page_increment` separately
    // from the `step_increment` returned by
    // `format_settings_dialog_auto_lock_secs_adjustment` /
    // `format_settings_dialog_clipboard_clear_secs_adjustment`.
    // The page increment governs the value the `AdwSpinRow` jumps
    // by on Page Up / Page Down keyboard navigation; both spinners
    // share the same seconds dimension and the same per-press +/-
    // step (`1.0`), so the page step is also shared.
    //
    // The wording (`10.0`) is the conventional 10× step factor:
    // small enough to feel responsive on the §4.7-bounded ranges
    // (auto-lock 30..=86400, clipboard 5..=600) without sliding
    // past the bounds in a single press, large enough that Page
    // Up / Down is meaningfully different from the +/- buttons.
    //
    // Pinning the page step through this helper keeps the spinner
    // keyboard navigation in one place shared by both
    // `gtk::Adjustment::new` calls the `SettingsComponent` makes;
    // the widget layer never duplicates the literal.
    //
    // Sibling of
    // `format_settings_dialog_auto_lock_secs_adjustment` and
    // `format_settings_dialog_clipboard_clear_secs_adjustment`
    // on the `gtk::Adjustment::new` argument side; together they
    // pin every value the constructor receives for both spinners
    // (the value itself comes from
    // `compose_settings_dialog_*_secs_value`, and `page_size`
    // stays `0.0` because `AdwSpinRow` has no slider area).
    use paladin_gtk::settings::format_settings_dialog_spinner_page_increment;

    assert!(
        (format_settings_dialog_spinner_page_increment() - 10.0).abs() < f64::EPSILON,
        "page increment is the conventional 10× step factor",
    );
}

#[test]
fn format_settings_dialog_spinner_page_size_returns_zero() {
    // The last argument `gtk::Adjustment::new` accepts is
    // `page_size`, which only matters for adjustments backing
    // sliders (`gtk::Scale`, `gtk::Scrollbar`). `AdwSpinRow`
    // surfaces a `gtk::SpinButton`-style numeric editor with no
    // slider area, so the `page_size` must be `0.0`: a non-zero
    // value would make the spinner's accepted upper bound become
    // `upper - page_size`, silently shrinking the range we already
    // pinned through
    // `format_settings_dialog_auto_lock_secs_adjustment` /
    // `format_settings_dialog_clipboard_clear_secs_adjustment`.
    //
    // Pinning the literal through this helper keeps the
    // `gtk::Adjustment::new` argument in one place shared by both
    // spinners so the slider-bound subtraction never accidentally
    // re-emerges, and rounds out the constructor's six positional
    // arguments together with the value compose helpers, the
    // bounds + step adjustment tuple, and
    // `format_settings_dialog_spinner_page_increment`.
    //
    // Pure — returns an `f64` without allocating.
    use paladin_gtk::settings::format_settings_dialog_spinner_page_size;

    assert!(
        format_settings_dialog_spinner_page_size().abs() < f64::EPSILON,
        "page size is 0.0 because AdwSpinRow has no slider area",
    );
}

#[test]
fn format_settings_dialog_spinner_climb_rate_returns_one() {
    // `adw::SpinRow::new` takes a `climb_rate` argument that
    // governs how fast the value accelerates when the user holds
    // the `+` / `-` button down. The §4.7 ranges are short enough
    // (auto-lock 30..=86400 seconds at 1.0 per step, clipboard
    // 5..=600 seconds at 1.0 per step) that a flat `1.0` climb
    // rate already feels responsive — additional acceleration
    // would skip past intended values faster than the eye can
    // track, especially on the clipboard-clear range. Pinning the
    // literal through this helper keeps the climb rate in one
    // place shared by both `adw::SpinRow::new` calls the
    // `SettingsComponent` makes; the widget layer never
    // duplicates the literal.
    //
    // Pure — returns an `f64` without allocating. Sibling of
    // `format_settings_dialog_spinner_page_increment` and
    // `format_settings_dialog_spinner_page_size` on the
    // `adw::SpinRow::new` argument side; together they pin every
    // numeric the constructor receives beyond the
    // `gtk::Adjustment` (which the value compose helpers, the
    // bounds adjustment tuple, page_increment, and page_size
    // already cover).
    use paladin_gtk::settings::format_settings_dialog_spinner_climb_rate;

    assert!(
        (format_settings_dialog_spinner_climb_rate() - 1.0).abs() < f64::EPSILON,
        "climb rate is the flat 1.0 acceleration the seconds ranges call for",
    );
}

#[test]
fn format_settings_dialog_spinner_digits_returns_zero() {
    // `adw::SpinRow::new` takes a `digits: u32` argument that
    // controls how many fractional places the spinner shows.
    // The §4.7 settings the spinners edit
    // (`auto_lock_timeout_secs`, `clipboard_clear_secs`) are
    // `u32` seconds — a whole-number dimension with no
    // fractional component — so the spinner must show `0`
    // decimal digits. A non-zero `digits` would render trailing
    // `.000` glyphs that misrepresent the underlying typed
    // values and could mislead the user into typing fractional
    // entries that the integer parser already drops.
    //
    // Pinning the literal through this helper keeps the digits
    // count in one place shared by both `adw::SpinRow::new`
    // calls the `SettingsComponent` makes; the widget layer
    // never duplicates the literal.
    //
    // Pure — returns a `u32` without allocating. Sibling of
    // `format_settings_dialog_spinner_climb_rate`,
    // `format_settings_dialog_spinner_page_increment`, and
    // `format_settings_dialog_spinner_page_size` on the
    // `adw::SpinRow::new` argument side; together with the
    // adjustment tuple they pin every value the constructor
    // receives.
    use paladin_gtk::settings::format_settings_dialog_spinner_digits;

    assert_eq!(
        format_settings_dialog_spinner_digits(),
        0,
        "digits is 0 because the §4.7 seconds settings are integer-valued",
    );
}

#[test]
fn settings_state_stage_clears_last_outcome_for_prior_durability_warning() {
    // Sibling of `settings_state_stage_clears_last_outcome_so_prior_inline_does_not_linger`
    // (which exercises the `Rollback` arm) on the
    // `DurabilityWarning` path. `stage_*` clears `last_outcome`
    // unconditionally, but without a test exercising the warning
    // variant a regression that special-cased the clear (e.g.
    // "leave warnings since the file is on disk anyway") would
    // land undetected — the amber subtitle would then linger under
    // a spinner row the user is actively editing, which violates
    // the §"Tests > Pure-logic unit tests >
    // `tests/settings_logic.rs`" checklist intent that the
    // subtitle disappears the moment the user acts again.
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    let _ = state.resolve_debounce();
    let _ = state.apply_save_result(
        AcceptedChange::AutoLockSecs(60),
        Err(PaladinError::SaveDurabilityUnconfirmed),
    );
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::DurabilityWarning { .. })
    ));

    state.stage_auto_lock_secs(120);
    assert!(
        state.last_outcome().is_none(),
        "new spinner stage clears the prior durability warning so the amber subtitle does not linger",
    );
}

#[test]
fn settings_state_toggle_clears_last_outcome_for_prior_durability_warning() {
    // Mirrors `settings_state_stage_clears_last_outcome_for_prior_durability_warning`
    // on the toggle side. `toggle_*` also clears `last_outcome`
    // unconditionally; the test covers a regression where the
    // toggle path special-cased warnings the same way a hypothetical
    // stage-side bug would. Pairs with
    // `settings_state_toggle_clears_last_outcome_so_prior_inline_does_not_linger`
    // (the `Rollback` arm) so the toggle clear contract is asserted
    // for both the error and warning variants the dialog can show.
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);
    let _ = state.apply_save_result(
        AcceptedChange::AutoLockEnabled(true),
        Err(PaladinError::SaveDurabilityUnconfirmed),
    );
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::DurabilityWarning { .. })
    ));

    let _ = state.toggle_auto_lock_enabled(false);
    assert!(
        state.last_outcome().is_none(),
        "new toggle clears the prior durability warning so the amber subtitle does not linger",
    );
}

#[test]
fn settings_state_stage_clears_last_outcome_for_prior_inline_io_error() {
    // Sibling of `settings_state_stage_clears_last_outcome_for_prior_durability_warning`
    // on the `Inline` arm. The existing `_for_prior_durability_warning`
    // pair pins the clear contract for the amber-subtitle path; this
    // pair pins the same contract for the red-subtitle inline-error
    // path that `apply_save_io_error_routes_to_inline_and_rolls_back_visible_value`
    // produces. Without an explicit assertion for the `Inline` variant a
    // regression that special-cased the clear ("leave errors so the user
    // notices") would land undetected — the red subtitle would then
    // linger under a spinner row the user is actively retyping, which
    // would visually contradict the §"Tests > Pure-logic unit tests >
    // `tests/settings_logic.rs`" checklist intent that the subtitle
    // disappears the moment the user acts again.
    let mut state = SettingsState::new(defaults());
    state.stage_auto_lock_secs(60);
    let _ = state.resolve_debounce();
    let _ = state.apply_save_result(
        AcceptedChange::AutoLockSecs(60),
        Err(PaladinError::IoError {
            operation: "vault_save",
            source: std::io::Error::other("disk full"),
        }),
    );
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::Inline { .. })
    ));

    state.stage_auto_lock_secs(120);
    assert!(
        state.last_outcome().is_none(),
        "new spinner stage clears the prior inline io_error so the red subtitle does not linger",
    );
}

#[test]
fn settings_state_toggle_clears_last_outcome_for_prior_rollback() {
    // Mirrors `settings_state_stage_clears_last_outcome_so_prior_inline_does_not_linger`
    // (which exercises the `Rollback` arm on the stage side, despite
    // its older "inline" name) on the toggle side. The sibling
    // `settings_state_toggle_clears_last_outcome_so_prior_inline_does_not_linger`
    // uses `SaveDurabilityUnconfirmed`, which lands in the
    // `DurabilityWarning` slot, so the toggle path's clear contract
    // for the `Rollback` variant was the last terminal-outcome gap.
    // Pairs with the existing `_for_prior_durability_warning` and
    // `_for_prior_inline_io_error` toggle tests so all three
    // terminal save outcomes have explicit toggle-side clear
    // coverage.
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);
    let _ = state.apply_save_result(
        AcceptedChange::AutoLockEnabled(true),
        Err(save_not_committed_no_backup()),
    );
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::Rollback { .. })
    ));

    let _ = state.toggle_auto_lock_enabled(false);
    assert!(
        state.last_outcome().is_none(),
        "new toggle clears the prior rollback so the red subtitle does not linger",
    );
}

#[test]
fn settings_state_toggle_clears_last_outcome_for_prior_inline_io_error() {
    // Mirrors `settings_state_stage_clears_last_outcome_for_prior_inline_io_error`
    // on the toggle side. The original sibling pair covers the
    // `DurabilityWarning` variant for both stage and toggle; this
    // pair extends that to the `Inline` variant so the toggle clear
    // contract is asserted for all three terminal save outcomes the
    // dialog can show (`Rollback`, `DurabilityWarning`, `Inline`).
    let mut state = SettingsState::new(defaults());
    let _ = state.toggle_auto_lock_enabled(true);
    let _ = state.apply_save_result(
        AcceptedChange::AutoLockEnabled(true),
        Err(PaladinError::IoError {
            operation: "vault_save",
            source: std::io::Error::other("disk full"),
        }),
    );
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::Inline { .. })
    ));

    let _ = state.toggle_auto_lock_enabled(false);
    assert!(
        state.last_outcome().is_none(),
        "new toggle clears the prior inline io_error so the red subtitle does not linger",
    );
}

#[test]
fn format_settings_dialog_spinner_wrap_returns_false() {
    // `gtk::SpinButton::wrap` (surfaced through `adw::SpinRow`)
    // defaults to `FALSE` — once the value reaches `upper` (or
    // `lower`), continued `+` (or `-`) presses keep the value
    // pinned at the boundary rather than wrapping to the opposite
    // end. The §4.7 ranges
    // (`auto_lock_timeout_secs` 30..=86400; `clipboard_clear_secs`
    // 5..=600) make wrap-around behavior actively user-hostile: a
    // user holding `-` on the clipboard-clear spinner expecting it
    // to drop toward 5 would suddenly find it at 600, a 12x jump
    // in the opposite direction. Pinning the flag to `false`
    // matches the default but makes the bounded-behavior contract
    // explicit so future contributors do not flip it on by mistake
    // (e.g. for a clock-face hour picker that genuinely benefits
    // from wrap).
    //
    // Pairs with the bounded `gtk::Adjustment` returned by
    // `format_settings_dialog_auto_lock_secs_adjustment` /
    // `format_settings_dialog_clipboard_clear_secs_adjustment` on
    // the value-range side; wrap controls the *traversal* across
    // those bounds while the adjustment pins the bounds themselves.
    //
    // Pinning the literal through this helper keeps the wrap flag
    // in one place shared by both `adw::SpinRow::set_wrap(
    // format_settings_dialog_spinner_wrap())` calls the
    // `SettingsComponent` makes; the widget layer never duplicates
    // the literal. Sibling of
    // `format_settings_dialog_spinner_climb_rate`,
    // `format_settings_dialog_spinner_digits`,
    // `format_settings_dialog_spinner_numeric`,
    // `format_settings_dialog_spinner_page_increment`,
    // `format_settings_dialog_spinner_page_size`, and
    // `format_settings_dialog_spinner_snap_to_ticks` on the
    // `adw::SpinRow` property side; together they pin every
    // spinner-property literal the `SettingsComponent` sets beyond
    // the `gtk::Adjustment` bounds.
    //
    // Pure — returns a `bool` without allocating.
    use paladin_gtk::settings::format_settings_dialog_spinner_wrap;

    assert!(
        !format_settings_dialog_spinner_wrap(),
        "wrap is pinned off so holding +/- pins to the boundary instead of jumping to the other end",
    );
}

#[test]
fn format_settings_dialog_spinner_numeric_returns_true() {
    // `adw::SpinRow::numeric` (the libadwaita-side override of the
    // `gtk::SpinButton` property of the same name) defaults to
    // `TRUE` — typed input is restricted to digits, the decimal
    // point, and the minus sign — while the underlying
    // `gtk::SpinButton::numeric` defaults to `FALSE`. Toggling it
    // back to `FALSE` would let a user paste arbitrary text into
    // the spinner entry (e.g. `"thirty seconds"`); the entry's
    // value parser then silently snaps the unparseable input to
    // the prior committed value without firing a `changed` signal,
    // leaving the visible text out of sync with the value the
    // `SettingsState` debounce eventually saves. Pinning the flag
    // to `true` makes the input restriction explicit so future
    // contributors do not regress the property to the
    // `gtk::SpinButton` default by mistake.
    //
    // Pairs with `format_settings_dialog_spinner_digits` returning
    // `0` (the entry shows no fractional places) and
    // `format_settings_dialog_spinner_snap_to_ticks` returning
    // `true` (off-grid values snap to whole seconds) so the
    // integer-seconds invariant is enforced at every entry point:
    // typed input (`numeric`), displayed digits (`digits`), and
    // programmatic / external setters (`snap_to_ticks`).
    //
    // Pinning the literal through this helper keeps the numeric
    // flag in one place shared by both `adw::SpinRow::set_numeric(
    // format_settings_dialog_spinner_numeric())` calls the
    // `SettingsComponent` makes; the widget layer never duplicates
    // the literal. Sibling of
    // `format_settings_dialog_spinner_climb_rate`,
    // `format_settings_dialog_spinner_digits`,
    // `format_settings_dialog_spinner_page_increment`,
    // `format_settings_dialog_spinner_page_size`, and
    // `format_settings_dialog_spinner_snap_to_ticks` on the
    // `adw::SpinRow` property side; together they pin every
    // spinner-property literal the `SettingsComponent` sets beyond
    // the `gtk::Adjustment` bounds.
    //
    // Pure — returns a `bool` without allocating.
    use paladin_gtk::settings::format_settings_dialog_spinner_numeric;

    assert!(
        format_settings_dialog_spinner_numeric(),
        "numeric input restriction is the AdwSpinRow default and is pinned defensively",
    );
}

#[test]
fn format_settings_dialog_spinner_snap_to_ticks_returns_true() {
    // `adw::SpinRow::snap-to-ticks` defaults to `FALSE` in
    // libadwaita: invalid intermediate values (typed entries that
    // do not land on a multiple of `step_increment`, or values set
    // programmatically by external setters / accessibility tooling)
    // are accepted as-is. The §4.7 settings the spinners edit
    // (`auto_lock_timeout_secs`, `clipboard_clear_secs`) are `u32`
    // seconds — every accepted value is an integer multiple of the
    // `1.0` step pinned by
    // `format_settings_dialog_auto_lock_secs_adjustment` /
    // `format_settings_dialog_clipboard_clear_secs_adjustment` — so
    // turning snap-to-ticks on enforces the integer-seconds grid at
    // the widget edge: any off-grid value (e.g. a programmatic
    // `set_value(30.5)` from a screen reader script, or a paste of
    // `30.5` into the entry buffer) snaps to the nearest whole
    // second before the spinner ever fires its `changed` signal.
    //
    // Pairs with `format_settings_dialog_spinner_digits` returning
    // `0`: digits controls *display* (no trailing `.0` glyphs),
    // snap-to-ticks controls *value* (no fractional component
    // entering the model). Together they enforce the same integer
    // invariant on both sides of the spinner.
    //
    // Pinning the literal through this helper keeps the
    // snap-to-ticks flag in one place shared by both
    // `adw::SpinRow::set_snap_to_ticks(
    // format_settings_dialog_spinner_snap_to_ticks())` calls the
    // `SettingsComponent` makes; the widget layer never duplicates
    // the literal.
    //
    // Pure — returns a `bool` without allocating. Sibling of
    // `format_settings_dialog_spinner_climb_rate`,
    // `format_settings_dialog_spinner_digits`,
    // `format_settings_dialog_spinner_page_increment`, and
    // `format_settings_dialog_spinner_page_size` on the
    // `adw::SpinRow` property side; together they pin every
    // spinner-property literal the `SettingsComponent` sets beyond
    // the `gtk::Adjustment` bounds.
    use paladin_gtk::settings::format_settings_dialog_spinner_snap_to_ticks;

    assert!(
        format_settings_dialog_spinner_snap_to_ticks(),
        "snap-to-ticks enforces the integer-seconds grid against off-grid programmatic values",
    );
}

#[test]
fn format_settings_dialog_spinner_debounce_returns_500_ms() {
    // The widget arms a `glib::timeout_add_local` after every
    // `stage_*` call; the timer's tick handler calls
    // `SettingsState::resolve_debounce` and fires
    // `Vault::mutate_and_save` on `DebounceOutcome::Save`. The
    // 500 ms duration is the §"Component tree" `SettingsComponent`
    // contract that "holding +/- does not fire one save per
    // click — the most recent buffered value is the one that
    // saves" — long enough that a multi-press burst coalesces
    // into a single `mutate_and_save`, short enough that a paused
    // user does not notice the save lag.
    //
    // Pinning the literal through this helper keeps the debounce
    // window in one place shared by the widget binding
    // (`glib::timeout_add_local(format_settings_dialog_spinner_debounce(), ...)`)
    // and the pure-logic tests; the widget layer never duplicates
    // the literal. Returning a `Duration` (not a `u64` ms value)
    // matches the `glib::timeout_add_local` argument type so the
    // widget call site does not need a conversion.
    //
    // Pure — returns a `std::time::Duration` without allocating.
    use std::time::Duration;

    use paladin_gtk::settings::format_settings_dialog_spinner_debounce;

    assert_eq!(
        format_settings_dialog_spinner_debounce(),
        Duration::from_millis(500),
        "debounce window is the 500 ms coalescing budget from the plan",
    );
}

#[test]
fn format_settings_dialog_search_enabled_returns_false() {
    // `AdwPreferencesDialog::search-enabled` defaults to `TRUE` in
    // libadwaita: the dialog grows a search bar that scans every
    // `AdwPreferencesGroup` row title / description. That affordance
    // is built for large dialogs hosting many `AdwPreferencesPage`s
    // (GNOME Settings, GNOME Tweaks); ours hosts exactly two groups
    // (auto-lock and clipboard, pinned by
    // `format_settings_dialog_auto_lock_group_title` /
    // `format_settings_dialog_clipboard_clear_group_title`) with
    // four rows total. The search bar would visually crowd the
    // chrome above the groups without surfacing any rows the user
    // could not already see at a glance.
    //
    // Pinning the literal through this helper keeps the
    // search-enabled flag in one place shared by the widget binding
    // (`AdwPreferencesDialog::set_search_enabled(
    // format_settings_dialog_search_enabled())`) and the pure-logic
    // tests; the widget layer never duplicates the literal.
    //
    // Sibling of `format_settings_dialog_title` (the header text)
    // on the `AdwPreferencesDialog` property side; together they
    // pin the dialog-level chrome above the `AdwPreferencesGroup`s
    // that the group-title / row-title helpers cover.
    //
    // Pure — returns a `bool` without allocating.
    use paladin_gtk::settings::format_settings_dialog_search_enabled;

    assert!(
        !format_settings_dialog_search_enabled(),
        "search bar is overkill for a two-group dialog and is suppressed",
    );
}

#[test]
fn format_settings_dialog_saved_toast_use_markup_returns_false() {
    // `adw::Toast::use-markup` toggles whether the body string is
    // interpreted as Pango markup. The default is `TRUE` —
    // `AdwToast::new(text)` initialises the inherited `title`
    // property with `use_markup: true`, so any `&` / `<` / `>` byte
    // in `text` gets parsed as markup unless the caller explicitly
    // sets the flag to `false`. The
    // `format_settings_dialog_saved_toast` body ("Settings saved")
    // is a static `&'static str` with no entity-quoted glyphs today,
    // but the helper's docstring leaves the door open to future
    // localisation — once translators get hold of the string, an
    // `&` in a translation ("Indstillinger gemt &c.") would silently
    // truncate the toast or surface a console warning. Pinning the
    // flag to `false` keeps the body as literal text regardless of
    // future wording, matching every other plain-text surface in
    // the dialog (the inline subtitle text helpers return raw
    // [`SaveOutcome`] error / warning `Display` bodies, not markup).
    //
    // Pinning the literal through this helper keeps the use-markup
    // flag in one place shared by the widget binding
    // (`AdwToast::set_use_markup(
    // format_settings_dialog_saved_toast_use_markup())`) and the
    // pure-logic tests; the widget layer never duplicates the
    // literal. Sibling of `format_settings_dialog_saved_toast` (the
    // body text) and `format_settings_dialog_saved_toast_timeout`
    // (the auto-dismiss window); together they pin every value the
    // success-toast constructor / setter chain receives.
    //
    // Pure — returns a `bool` without allocating.
    use paladin_gtk::settings::format_settings_dialog_saved_toast_use_markup;

    assert!(
        !format_settings_dialog_saved_toast_use_markup(),
        "toast body is plain text, never Pango markup",
    );
}

#[test]
fn format_settings_dialog_saved_toast_timeout_returns_five_seconds() {
    // `adw::Toast::set_timeout` takes a `u32` count of seconds the
    // toast remains visible (0 means the toast never auto-dismisses,
    // which would defeat the transient confirmation surface). The
    // `SettingsComponent` raises the toast via
    // `AdwToast::new(format_settings_dialog_saved_toast()).set_timeout(
    // format_settings_dialog_saved_toast_timeout())` after every
    // accepted change so the success confirmation surfaces without
    // blocking interaction. Pinning the literal through this helper
    // keeps the timeout in one place shared by the widget binding
    // and the pure-logic tests; the widget layer never duplicates
    // the literal.
    //
    // The value (`5` seconds) matches `AdwToast`'s default and the
    // wording the `format_settings_dialog_saved_toast` docstring
    // already cites ("brief enough for an `AdwToast` to fit the
    // default timeout"): long enough for the user to register the
    // confirmation, short enough that a rapid sequence of saves
    // does not stack overlapping toasts on the
    // `AdwToastOverlay`. Sibling of
    // `format_settings_dialog_saved_toast` (the body text); the two
    // together pin every value the success-toast constructor call
    // receives.
    //
    // Pure — returns a `u32` without allocating.
    use paladin_gtk::settings::format_settings_dialog_saved_toast_timeout;

    assert_eq!(
        format_settings_dialog_saved_toast_timeout(),
        5,
        "toast timeout matches the AdwToast default the body wording was sized for",
    );
}

// ---------------------------------------------------------------------------
// SettingsComponent scaffold (Milestone 7 component-tree wiring)
// ---------------------------------------------------------------------------
//
// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" entry
// "Relm4 component tree (Init / Unlock / List / Row / Add / Remove /
// Rename / Import / Export / Passphrase / Settings / StartupError)",
// `SettingsComponent` joins the seven already-mounted controllers
// (`AccountListComponent`, `StartupErrorComponent`,
// `InitDialogComponent`, `UnlockDialogComponent`,
// `RenameDialogComponent`, `RemoveDialogComponent`,
// `AddAccountComponent`) with the same scaffold shape:
// `<Name>Init` / `<Name>Msg` / `<Name>Output` plus a
// `relm4::SimpleComponent` impl. The widget body of the
// `AdwPreferencesDialog` (toggles + spinners + debounce) lands in
// follow-up commits alongside the live-apply behavior — this
// commit only adds the controller so the menu's Preferences entry
// can mount it.

#[test]
fn settings_dialog_init_round_trips_committed_settings() {
    use paladin_gtk::settings::SettingsDialogInit;

    let snapshot = defaults();
    let init = SettingsDialogInit { settings: snapshot };
    assert_eq!(init.settings, snapshot);
}

#[test]
fn settings_dialog_output_close_is_constructible() {
    use paladin_gtk::settings::SettingsDialogOutput;

    let output = SettingsDialogOutput::Close;
    assert!(matches!(output, SettingsDialogOutput::Close));
}

#[test]
fn settings_component_input_and_output_match_dispatch_edges() {
    use paladin_gtk::settings::{SettingsComponent, SettingsDialogMsg, SettingsDialogOutput};
    use relm4::SimpleComponent;

    // Compile-only assertion that ties `SettingsComponent` to its
    // associated `Input` / `Output` types so the AppModel dispatch
    // edges stay in lock-step with the component declaration. If a
    // future refactor renames `SettingsDialogMsg` or
    // `SettingsDialogOutput`, this test fails at compile time
    // before the AppModel build does.
    fn assert_types<C>()
    where
        C: SimpleComponent<Input = SettingsDialogMsg, Output = SettingsDialogOutput>,
    {
    }
    assert_types::<SettingsComponent>();
}

// ---------------------------------------------------------------------------
// classify_settings_save_result — shared kind-based routing for the
// in-process and worker paths. Mirrors the back-half of
// `SettingsState::apply_save_result` so the dialog and the
// `gio::spawn_blocking` worker stay lock-stepped on which typed error
// maps to which `SaveOutcome` variant.
// ---------------------------------------------------------------------------

#[test]
fn classify_settings_save_result_success_maps_to_save_outcome_success() {
    use paladin_gtk::settings::{classify_settings_save_result, AcceptedChange, SaveOutcome};
    let outcome = classify_settings_save_result(AcceptedChange::AutoLockEnabled(true), Ok(()));
    assert!(matches!(outcome, SaveOutcome::Success));
}

#[test]
fn classify_settings_save_result_save_not_committed_maps_to_rollback() {
    use paladin_gtk::settings::{
        classify_settings_save_result, AcceptedChange, SaveOutcome, SettingsField,
    };
    let outcome = classify_settings_save_result(
        AcceptedChange::AutoLockSecs(120),
        Err(save_not_committed_no_backup()),
    );
    match outcome {
        SaveOutcome::Rollback { field, .. } => {
            assert_eq!(field, SettingsField::AutoLockSecs);
        }
        other => panic!("expected Rollback, got {other:?}"),
    }
}

#[test]
fn classify_settings_save_result_save_durability_unconfirmed_maps_to_durability_warning() {
    use paladin_core::PaladinError;
    use paladin_gtk::settings::{
        classify_settings_save_result, AcceptedChange, SaveOutcome, SettingsField,
    };
    let outcome = classify_settings_save_result(
        AcceptedChange::ClipboardClearEnabled(true),
        Err(PaladinError::SaveDurabilityUnconfirmed),
    );
    match outcome {
        SaveOutcome::DurabilityWarning { field, .. } => {
            assert_eq!(field, SettingsField::ClipboardClearEnabled);
        }
        other => panic!("expected DurabilityWarning, got {other:?}"),
    }
}

#[test]
fn classify_settings_save_result_other_error_maps_to_inline() {
    use paladin_core::PaladinError;
    use paladin_gtk::settings::{
        classify_settings_save_result, AcceptedChange, SaveOutcome, SettingsField,
    };
    let err = PaladinError::IoError {
        operation: "rename",
        source: std::io::Error::other("synthetic"),
    };
    let outcome = classify_settings_save_result(AcceptedChange::ClipboardClearSecs(60), Err(err));
    match outcome {
        SaveOutcome::Inline { field, .. } => {
            assert_eq!(field, SettingsField::ClipboardClearSecs);
        }
        other => panic!("expected Inline, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// apply_save_outcome — back-half of apply_save_result, called by the
// worker dispatch path so the state machine can consume a typed
// SaveOutcome without re-classifying the error.
// ---------------------------------------------------------------------------

#[test]
fn apply_save_outcome_success_promotes_attempted_value_to_committed() {
    use paladin_gtk::settings::{AcceptedChange, SaveOutcome, SettingsState};
    let mut state = SettingsState::new(defaults());
    let prior = state.committed().auto_lock_enabled();
    state.apply_save_outcome(
        AcceptedChange::AutoLockEnabled(!prior),
        SaveOutcome::Success,
    );
    assert_eq!(state.committed().auto_lock_enabled(), !prior);
    assert!(matches!(state.last_outcome(), Some(SaveOutcome::Success)));
}

#[test]
fn apply_save_outcome_durability_warning_promotes_attempted_value_to_committed() {
    use paladin_core::PaladinError;
    use paladin_gtk::settings::{
        AcceptedChange, InlineWarning, SaveOutcome, SettingsField, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let target = paladin_core::CLIPBOARD_CLEAR_SECS_MAX;
    let warning = InlineWarning::from_error(&PaladinError::SaveDurabilityUnconfirmed);
    state.apply_save_outcome(
        AcceptedChange::ClipboardClearSecs(target),
        SaveOutcome::DurabilityWarning {
            warning,
            field: SettingsField::ClipboardClearSecs,
        },
    );
    assert_eq!(state.committed().clipboard_clear_secs(), target);
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::DurabilityWarning { .. })
    ));
}

#[test]
fn apply_save_outcome_rollback_leaves_committed_unchanged() {
    use paladin_gtk::settings::{
        AcceptedChange, InlineError, SaveOutcome, SettingsField, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let prior = state.committed().auto_lock_secs();
    let err = save_not_committed_no_backup();
    state.apply_save_outcome(
        AcceptedChange::AutoLockSecs(prior.wrapping_add(60)),
        SaveOutcome::Rollback {
            error: InlineError::from_error(&err),
            field: SettingsField::AutoLockSecs,
        },
    );
    assert_eq!(
        state.committed().auto_lock_secs(),
        prior,
        "Rollback must leave the committed value unchanged",
    );
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::Rollback { .. })
    ));
}

#[test]
fn apply_save_outcome_inline_leaves_committed_unchanged() {
    use paladin_core::PaladinError;
    use paladin_gtk::settings::{
        AcceptedChange, InlineError, SaveOutcome, SettingsField, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let prior = state.committed().clipboard_clear_enabled();
    let err = PaladinError::IoError {
        operation: "rename",
        source: std::io::Error::other("synthetic"),
    };
    state.apply_save_outcome(
        AcceptedChange::ClipboardClearEnabled(!prior),
        SaveOutcome::Inline {
            error: InlineError::from_error(&err),
            field: SettingsField::ClipboardClearEnabled,
        },
    );
    assert_eq!(
        state.committed().clipboard_clear_enabled(),
        prior,
        "Inline error must leave the committed value unchanged",
    );
}

// ---------------------------------------------------------------------------
// apply_settings_dialog_msg — message-routing dispatch tested without
// driving the real relm4 Component::update runtime.
// ---------------------------------------------------------------------------

#[test]
fn dispatch_settings_dialog_msg_worker_completed_promotes_on_success_and_returns_noop() {
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, AcceptedChange, SaveOutcome, SettingsDialogAction,
        SettingsDialogMsg, SettingsState, SettingsWorkerEffect,
    };
    let mut state = SettingsState::new(defaults());
    let prior = state.committed().auto_lock_enabled();
    let effect = SettingsWorkerEffect {
        change: AcceptedChange::AutoLockEnabled(!prior),
        outcome: SaveOutcome::Success,
    };
    let action =
        dispatch_settings_dialog_msg(&mut state, SettingsDialogMsg::WorkerCompleted(effect));
    assert_eq!(action, SettingsDialogAction::Noop);
    assert_eq!(state.committed().auto_lock_enabled(), !prior);
}

#[test]
fn dispatch_settings_dialog_msg_worker_completed_rolls_back_inline_error() {
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, AcceptedChange, InlineError, SaveOutcome,
        SettingsDialogAction, SettingsDialogMsg, SettingsField, SettingsState,
        SettingsWorkerEffect,
    };
    let mut state = SettingsState::new(defaults());
    let prior = state.committed().auto_lock_secs();
    let err = save_not_committed_no_backup();
    let effect = SettingsWorkerEffect {
        change: AcceptedChange::AutoLockSecs(prior.wrapping_add(60)),
        outcome: SaveOutcome::Rollback {
            error: InlineError::from_error(&err),
            field: SettingsField::AutoLockSecs,
        },
    };
    let action =
        dispatch_settings_dialog_msg(&mut state, SettingsDialogMsg::WorkerCompleted(effect));
    assert_eq!(action, SettingsDialogAction::Noop);
    assert_eq!(state.committed().auto_lock_secs(), prior);
    assert!(matches!(
        state.last_outcome(),
        Some(SaveOutcome::Rollback { .. })
    ));
}

// ---------------------------------------------------------------------------
// dispatch_settings_dialog_msg — toggle / spinner / debounce variants
// route into the existing `SettingsState::toggle_*` / `stage_*` /
// `resolve_debounce` so the widget layer only owns the side-effect
// decision (Noop / StageDebounce / Submit).
// ---------------------------------------------------------------------------

#[test]
fn dispatch_settings_dialog_msg_auto_lock_toggled_value_change_returns_submit() {
    use paladin_core::SettingPatch;
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, SettingsDialogAction, SettingsDialogMsg, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let new = !state.committed().auto_lock_enabled();
    let action = dispatch_settings_dialog_msg(&mut state, SettingsDialogMsg::AutoLockToggled(new));
    assert_eq!(
        action,
        SettingsDialogAction::Submit(SettingPatch::AutoLockEnabled(new))
    );
}

#[test]
fn dispatch_settings_dialog_msg_auto_lock_toggled_noop_returns_noop() {
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, SettingsDialogAction, SettingsDialogMsg, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let same = state.committed().auto_lock_enabled();
    let action = dispatch_settings_dialog_msg(&mut state, SettingsDialogMsg::AutoLockToggled(same));
    assert_eq!(action, SettingsDialogAction::Noop);
}

#[test]
fn dispatch_settings_dialog_msg_clipboard_clear_toggled_value_change_returns_submit() {
    use paladin_core::SettingPatch;
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, SettingsDialogAction, SettingsDialogMsg, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let new = !state.committed().clipboard_clear_enabled();
    let action =
        dispatch_settings_dialog_msg(&mut state, SettingsDialogMsg::ClipboardClearToggled(new));
    assert_eq!(
        action,
        SettingsDialogAction::Submit(SettingPatch::ClipboardClearEnabled(new))
    );
}

#[test]
fn dispatch_settings_dialog_msg_auto_lock_secs_spinner_change_returns_stage_debounce() {
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, SettingsDialogAction, SettingsDialogMsg, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let raw = state.committed().auto_lock_secs().wrapping_add(60);
    let action = dispatch_settings_dialog_msg(
        &mut state,
        SettingsDialogMsg::AutoLockSecsSpinnerChanged(raw),
    );
    assert_eq!(action, SettingsDialogAction::StageDebounce);
    assert_eq!(
        state.visible_auto_lock_secs(),
        raw.min(paladin_core::AUTO_LOCK_SECS_MAX)
    );
}

#[test]
fn dispatch_settings_dialog_msg_clipboard_clear_secs_spinner_change_returns_stage_debounce() {
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, SettingsDialogAction, SettingsDialogMsg, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let raw = state.committed().clipboard_clear_secs().wrapping_add(10);
    let action = dispatch_settings_dialog_msg(
        &mut state,
        SettingsDialogMsg::ClipboardClearSecsSpinnerChanged(raw),
    );
    assert_eq!(action, SettingsDialogAction::StageDebounce);
}

#[test]
fn dispatch_settings_dialog_msg_debounce_tick_with_pending_returns_submit() {
    use paladin_core::SettingPatch;
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, SettingsDialogAction, SettingsDialogMsg, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let raw = state.committed().auto_lock_secs().wrapping_add(60);
    let staged = state.stage_auto_lock_secs(raw);
    let action = dispatch_settings_dialog_msg(&mut state, SettingsDialogMsg::DebounceTick);
    assert_eq!(
        action,
        SettingsDialogAction::Submit(SettingPatch::AutoLockTimeoutSecs(staged))
    );
}

#[test]
fn dispatch_settings_dialog_msg_debounce_tick_idle_returns_noop() {
    use paladin_gtk::settings::{
        dispatch_settings_dialog_msg, SettingsDialogAction, SettingsDialogMsg, SettingsState,
    };
    let mut state = SettingsState::new(defaults());
    let action = dispatch_settings_dialog_msg(&mut state, SettingsDialogMsg::DebounceTick);
    assert_eq!(action, SettingsDialogAction::Noop);
}
