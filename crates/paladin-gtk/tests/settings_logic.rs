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
    DebounceOutcome, SaveOutcome, SettingsField, SettingsState, ToggleOutcome,
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
