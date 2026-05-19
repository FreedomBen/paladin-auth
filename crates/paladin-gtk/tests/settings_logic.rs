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
