// SPDX-License-Identifier: AGPL-3.0-or-later

//! Settings-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `SettingsComponent` and §"Tests > Pure-logic unit tests >
//! `tests/settings_logic.rs`", the `AdwPreferencesDialog` exposes
//! the §4.7 [`paladin_core::VaultSettings`] fields as toggles and
//! spinners with live-apply. The widget layer drives this module's
//! helpers to:
//!
//! * Clamp typed spinner values to the §"Global flags" /
//!   [`paladin_core::AUTO_LOCK_SECS_MIN`] /
//!   [`paladin_core::CLIPBOARD_CLEAR_SECS_MIN`] ranges
//!   ([`clamp_auto_lock_secs`] / [`clamp_clipboard_clear_secs`]).
//! * Coalesce repeated spinner activity into a single
//!   `mutate_and_save` per accepted change ([`SettingsState::stage_auto_lock_secs`] /
//!   [`SettingsState::stage_clipboard_clear_secs`] +
//!   [`SettingsState::resolve_debounce`]). The 500 ms debounce
//!   *timer* itself is owned by the widget
//!   (`glib::timeout_add_local(500ms, ...)`); this module owns the
//!   coalescing contract — only the most recent buffered value
//!   reaches the save call.
//! * Decide whether a toggle change should fire a save now
//!   ([`SettingsState::toggle_auto_lock_enabled`] /
//!   [`SettingsState::toggle_clipboard_clear_enabled`]). Toggle
//!   changes do not debounce; they hit `mutate_and_save` on the
//!   click that flips the value.
//! * Route the writer outcome of `Vault::mutate_and_save`
//!   ([`SettingsState::apply_save_result`]):
//!     - `Ok(())` → [`SaveOutcome::Success`]; committed promotes to
//!       the attempted value.
//!     - `save_not_committed` → [`SaveOutcome::Rollback`]; the on-
//!       disk file did not change and the visible widget value
//!       reverts to the last committed state.
//!     - `save_durability_unconfirmed` → [`SaveOutcome::DurabilityWarning`];
//!       the file *is* on disk (committed promotes) and a warning
//!       attaches to the changed `AdwPreferencesGroup` row.
//!     - Any other typed error → [`SaveOutcome::Inline`]; visible
//!       value rolls back to the last committed state and the
//!       inline error renders beneath the row.
//!
//! The module owns no widgets. The §"Thinness contract" forbids
//! re-implementing validation: clamp bounds and
//! [`paladin_core::SettingPatch`] construction are the only
//! re-exposed surface, and both route through `paladin-core`
//! constants / typed setters.

use paladin_core::{
    ErrorKind, PaladinError, SettingPatch, AUTO_LOCK_SECS_MAX, AUTO_LOCK_SECS_MIN,
    CLIPBOARD_CLEAR_SECS_MAX, CLIPBOARD_CLEAR_SECS_MIN,
};

/// Identifies the `AdwPreferencesGroup` row whose value is at issue
/// for a given save attempt — used to attach inline errors and
/// durability warnings to the correct row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    /// `auto_lock_enabled` toggle.
    AutoLockEnabled,
    /// `auto_lock_timeout_secs` spinner.
    AutoLockSecs,
    /// `clipboard_clear_enabled` toggle.
    ClipboardClearEnabled,
    /// `clipboard_clear_secs` spinner.
    ClipboardClearSecs,
}

/// Last-committed snapshot of the §4.7 settings the dialog is
/// editing.
///
/// Mirrors [`paladin_core::VaultSettings`] field-for-field. The
/// dialog keeps a plain-data copy so the state machine can be
/// exercised in pure-logic tests without instantiating a real
/// [`paladin_core::Vault`]. Construct from
/// [`paladin_core::VaultSettings`] with [`CommittedSettings::from_vault_settings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedSettings {
    auto_lock_enabled: bool,
    auto_lock_secs: u32,
    clipboard_clear_enabled: bool,
    clipboard_clear_secs: u32,
}

impl CommittedSettings {
    /// Build a snapshot from explicit field values.
    #[must_use]
    pub fn new(
        auto_lock_enabled: bool,
        auto_lock_secs: u32,
        clipboard_clear_enabled: bool,
        clipboard_clear_secs: u32,
    ) -> Self {
        Self {
            auto_lock_enabled,
            auto_lock_secs,
            clipboard_clear_enabled,
            clipboard_clear_secs,
        }
    }

    /// Capture the four §4.7 fields out of a
    /// [`paladin_core::VaultSettings`].
    #[must_use]
    pub fn from_vault_settings(settings: &paladin_core::VaultSettings) -> Self {
        Self {
            auto_lock_enabled: settings.auto_lock_enabled(),
            auto_lock_secs: settings.auto_lock_timeout_secs(),
            clipboard_clear_enabled: settings.clipboard_clear_enabled(),
            clipboard_clear_secs: settings.clipboard_clear_secs(),
        }
    }

    /// `auto_lock_enabled` toggle row value.
    #[must_use]
    pub fn auto_lock_enabled(&self) -> bool {
        self.auto_lock_enabled
    }

    /// `auto_lock_timeout_secs` spinner row value.
    #[must_use]
    pub fn auto_lock_secs(&self) -> u32 {
        self.auto_lock_secs
    }

    /// `clipboard_clear_enabled` toggle row value.
    #[must_use]
    pub fn clipboard_clear_enabled(&self) -> bool {
        self.clipboard_clear_enabled
    }

    /// `clipboard_clear_secs` spinner row value.
    #[must_use]
    pub fn clipboard_clear_secs(&self) -> u32 {
        self.clipboard_clear_secs
    }
}

/// A change the dialog has accepted and handed to the worker for
/// `Vault::mutate_and_save`. Carried back into
/// [`SettingsState::apply_save_result`] so the state machine can
/// promote / roll back the right field without remembering the
/// last pending in flight (a fresh pending may have accumulated
/// during the save).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptedChange {
    /// `auto_lock_enabled` flipped to this value.
    AutoLockEnabled(bool),
    /// `auto_lock_timeout_secs` set to this clamped value.
    AutoLockSecs(u32),
    /// `clipboard_clear_enabled` flipped to this value.
    ClipboardClearEnabled(bool),
    /// `clipboard_clear_secs` set to this clamped value.
    ClipboardClearSecs(u32),
}

impl AcceptedChange {
    fn field(self) -> SettingsField {
        match self {
            Self::AutoLockEnabled(_) => SettingsField::AutoLockEnabled,
            Self::AutoLockSecs(_) => SettingsField::AutoLockSecs,
            Self::ClipboardClearEnabled(_) => SettingsField::ClipboardClearEnabled,
            Self::ClipboardClearSecs(_) => SettingsField::ClipboardClearSecs,
        }
    }
}

/// Outcome of a 500 ms debounce tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebounceOutcome {
    /// Nothing buffered, or buffered value equals the committed
    /// value. The widget should leave the timer disarmed and not
    /// invoke the save worker.
    Idle,
    /// Buffered value differs from committed. The widget should
    /// invoke `Vault::mutate_and_save` with this
    /// [`SettingPatch`] and pass [`AcceptedChange`] back to
    /// [`SettingsState::apply_save_result`] on return.
    Save {
        /// Typed §5 patch the worker applies via
        /// [`paladin_core::Vault::apply_setting_patch`].
        patch: SettingPatch,
        /// Row this save targets — used to attach errors / warnings.
        field: SettingsField,
    },
}

/// Outcome of a toggle click.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToggleOutcome {
    /// Toggled value already equals the committed value. The widget
    /// does not invoke the save worker.
    Noop,
    /// Toggled value differs from committed. The widget should
    /// invoke `Vault::mutate_and_save` with this
    /// [`SettingPatch`] and pass [`AcceptedChange`] back to
    /// [`SettingsState::apply_save_result`] on return.
    Save {
        /// Typed §5 patch the worker applies via
        /// [`paladin_core::Vault::apply_setting_patch`].
        patch: SettingPatch,
        /// Row this save targets — used to attach errors / warnings.
        field: SettingsField,
    },
}

/// Outcome of the save worker's typed result.
#[derive(Debug, Clone)]
pub enum SaveOutcome {
    /// `Ok(())` — the attempted value is now committed. The visible
    /// widget value sticks.
    Success,
    /// `save_not_committed` — the on-disk file did not change. The
    /// visible widget value reverts to the last committed state.
    Rollback {
        /// Inline-error projection for the row.
        error: InlineError,
        /// Row this error attaches to.
        field: SettingsField,
    },
    /// `save_durability_unconfirmed` — the file is on disk (the
    /// primary rename succeeded) but the parent-directory `fsync`
    /// failed. The visible widget value sticks and the warning
    /// attaches to the changed row so the user can decide whether
    /// to retry.
    DurabilityWarning {
        /// Durability-warning projection for the row.
        warning: InlineWarning,
        /// Row this warning attaches to.
        field: SettingsField,
    },
    /// Any other typed error (`io_error`, `validation_error`, …).
    /// The visible widget value reverts to the last committed
    /// state and the inline error renders beneath the row.
    Inline {
        /// Inline-error projection for the row.
        error: InlineError,
        /// Row this error attaches to.
        field: SettingsField,
    },
}

/// Inline-error projection for a `SettingsComponent` row.
///
/// Carries the stable §5 [`ErrorKind`] for instrumentation and the
/// rendered body for display. Mirrors the
/// [`crate::rename_dialog::InlineError`] / [`crate::export_dialog::InlineError`]
/// shape so callers share one widget pattern across dialogs.
#[derive(Debug, Clone)]
pub struct InlineError {
    /// Stable §5 [`ErrorKind`] discriminator copied from
    /// [`PaladinError::kind`].
    pub kind: ErrorKind,
    /// Display body. Renders through [`std::fmt::Display`] so the
    /// wording stays in sync with the CLI / TUI verbatim.
    pub rendered: String,
}

impl InlineError {
    /// Build an [`InlineError`] from a [`PaladinError`].
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}

/// Durability-warning projection for a `SettingsComponent` row.
///
/// Returned by [`SettingsState::apply_save_result`] on
/// `save_durability_unconfirmed`: the save committed to disk, but
/// the parent-directory `fsync` failed, so the visible value stays
/// on the new value while the warning sits beneath it.
#[derive(Debug, Clone)]
pub struct InlineWarning {
    /// Stable §5 [`ErrorKind`] discriminator — always
    /// [`ErrorKind::SaveDurabilityUnconfirmed`] in current code.
    pub kind: ErrorKind,
    /// Display body. Renders through [`std::fmt::Display`] so the
    /// wording stays in sync with the CLI / TUI verbatim.
    pub rendered: String,
}

impl InlineWarning {
    /// Build an [`InlineWarning`] from a [`PaladinError`].
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}

/// Clamp a typed `auto_lock_timeout_secs` spinner value to
/// `[AUTO_LOCK_SECS_MIN, AUTO_LOCK_SECS_MAX]`.
///
/// The widget layer applies this on every spinner edit so a typed
/// value below the floor or above the ceiling is normalized before
/// it reaches the buffered pending entry.
#[must_use]
pub fn clamp_auto_lock_secs(value: u32) -> u32 {
    value.clamp(AUTO_LOCK_SECS_MIN, AUTO_LOCK_SECS_MAX)
}

/// Clamp a typed `clipboard_clear_secs` spinner value to
/// `[CLIPBOARD_CLEAR_SECS_MIN, CLIPBOARD_CLEAR_SECS_MAX]`.
#[must_use]
pub fn clamp_clipboard_clear_secs(value: u32) -> u32 {
    value.clamp(CLIPBOARD_CLEAR_SECS_MIN, CLIPBOARD_CLEAR_SECS_MAX)
}

/// Title rendered by `SettingsComponent`'s
/// [`adw::PreferencesDialog::set_title`] call.
///
/// The wording (`"Preferences"`) matches the menu entry label
/// returned by
/// [`crate::app::model::format_app_menu_preferences_label`] so the
/// dialog chrome reads identically to the affordance the user
/// activated. Pinning the title through this helper keeps the
/// wording in one place shared by the widget binding and the
/// pure-logic tests in `tests/settings_logic.rs`.
///
/// No TUI parity: the TUI's `settings` command is CLI-shaped
/// and runs in-place rather than mounting a dialog header (see
/// `crates/paladin-tui/src/view`), so the wording is
/// GTK-specific.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_title`],
/// [`crate::init_dialog::format_init_dialog_title`],
/// [`crate::rename_dialog::format_rename_dialog_title`],
/// [`crate::remove_dialog::format_remove_dialog_title`], and
/// [`crate::startup_error::format_startup_error_title`] on the
/// dialog-header-title side; together they pin every dialog's
/// titled surface against a single source of truth.
#[must_use]
pub fn format_settings_dialog_title() -> &'static str {
    "Preferences"
}

/// Title rendered on the `AdwPreferencesGroup` that hosts the
/// auto-lock toggle + spinner per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"libadwaita usage" > "Preferences".
///
/// The `SettingsComponent` organizes the
/// [`adw::PreferencesDialog`] into two `AdwPreferencesGroup`s:
/// one for auto-lock and one for clipboard-clear. This helper
/// pins the auto-lock group's title so the wording lives in one
/// place shared by the widget binding and the pure-logic tests
/// in `tests/settings_logic.rs`.
///
/// The wording (`"Auto-lock"`) names the concept the §4.7
/// [`paladin_core::VaultSettings::auto_lock_enabled`] /
/// [`paladin_core::VaultSettings::auto_lock_secs`] fields
/// control without restating what each individual control does
/// — the per-row labels (added in follow-up commits) carry the
/// `AdwSwitchRow` / `AdwSpinRow` wording.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_settings_dialog_auto_lock_group_title() -> &'static str {
    "Auto-lock"
}

/// Title rendered on the `AdwPreferencesGroup` that hosts the
/// clipboard-clear toggle + spinner per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences".
///
/// Sibling of [`format_settings_dialog_auto_lock_group_title`]
/// on the clipboard-clear side; together they pin both
/// `AdwPreferencesGroup` titles the `SettingsComponent` hosts
/// in its [`adw::PreferencesDialog`] against a single source of
/// truth shared by the widget binding and the pure-logic tests
/// in `tests/settings_logic.rs`.
///
/// The wording (`"Clipboard"`) names the concept the §4.7
/// [`paladin_core::VaultSettings::clipboard_clear_enabled`] /
/// [`paladin_core::VaultSettings::clipboard_clear_secs`] fields
/// control. The shorter form (`"Clipboard"`) over
/// `"Clipboard auto-clear"` keeps the group-title surface lean
/// — the per-row labels (added in follow-up commits) carry the
/// verb-led wording on the `AdwSwitchRow` / `AdwSpinRow`
/// themselves.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_settings_dialog_clipboard_clear_group_title() -> &'static str {
    "Clipboard"
}

/// Title rendered on the auto-lock `AdwSwitchRow` per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences". The `SettingsComponent` uses idiomatic
/// libadwaita rows — `AdwSwitchRow` for the toggle controlling
/// [`paladin_core::VaultSettings::auto_lock_enabled`] and
/// `AdwSpinRow` for the timeout
/// [`paladin_core::VaultSettings::auto_lock_secs`].
///
/// The wording (`"Lock after inactivity"`) names the behavior
/// the user is enabling — the dialog locks the vault after the
/// matching idle window expires — without restating
/// `"enabled"` or `"auto-lock"` (the group title returned by
/// [`format_settings_dialog_auto_lock_group_title`] already
/// names that concept). Verb-led wording per the GNOME HIG.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_settings_dialog_auto_lock_enabled_row_title() -> &'static str {
    "Lock after inactivity"
}

/// Title rendered on the auto-lock `AdwSpinRow` per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
/// The spinner controls
/// [`paladin_core::VaultSettings::auto_lock_secs`], clamps to
/// [`paladin_core::AUTO_LOCK_SECS_MIN`]
/// ..= [`paladin_core::AUTO_LOCK_SECS_MAX`] via
/// [`clamp_auto_lock_secs`], and is debounced 500 ms so holding
/// the +/- buttons does not fire one `Vault::mutate_and_save`
/// per click.
///
/// The wording (`"Inactivity timeout (seconds)"`) names the
/// dimension the spinner adjusts and the units the value uses
/// without restating `"auto-lock"` (the group title returned
/// by [`format_settings_dialog_auto_lock_group_title`] already
/// names that concept) or `"lock"` (the sibling
/// `AdwSwitchRow` title returned by
/// [`format_settings_dialog_auto_lock_enabled_row_title`]
/// already names that). Units inline parenthesized per the
/// GNOME HIG.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_settings_dialog_auto_lock_secs_row_title() -> &'static str {
    "Inactivity timeout (seconds)"
}

/// Title rendered on the clipboard-clear `AdwSwitchRow` per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences". Sibling of
/// [`format_settings_dialog_auto_lock_enabled_row_title`] on
/// the clipboard side; together they pin both `AdwSwitchRow`
/// titles the `SettingsComponent` hosts.
///
/// The wording (`"Clear clipboard after copy"`) names the
/// behavior the user is enabling — the clipboard contents are
/// zeroed after the matching timeout elapses — without
/// restating `"enabled"` or `"clipboard"` (the group title
/// returned by
/// [`format_settings_dialog_clipboard_clear_group_title`]
/// already names that concept). Verb-led wording per the GNOME
/// HIG.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_settings_dialog_clipboard_clear_enabled_row_title() -> &'static str {
    "Clear clipboard after copy"
}

/// Title rendered on the clipboard-clear `AdwSpinRow` per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
/// The spinner controls
/// [`paladin_core::VaultSettings::clipboard_clear_secs`], clamps
/// to [`paladin_core::CLIPBOARD_CLEAR_SECS_MIN`]
/// ..= [`paladin_core::CLIPBOARD_CLEAR_SECS_MAX`] via
/// [`clamp_clipboard_clear_secs`], and is debounced 500 ms so
/// holding the +/- buttons does not fire one
/// `Vault::mutate_and_save` per click. Sibling of
/// [`format_settings_dialog_auto_lock_secs_row_title`] on the
/// clipboard side; together they pin both `AdwSpinRow` titles
/// the `SettingsComponent` hosts.
///
/// The wording (`"Clear delay (seconds)"`) names the dimension
/// the spinner adjusts (the delay before the clipboard is
/// cleared) and the units the value uses, threading naturally
/// with the sibling `AdwSwitchRow` title returned by
/// [`format_settings_dialog_clipboard_clear_enabled_row_title`]
/// (`"Clear clipboard after copy"`). Units inline parenthesized
/// per the GNOME HIG.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_settings_dialog_clipboard_clear_secs_row_title() -> &'static str {
    "Clear delay (seconds)"
}

/// Fixed `(lower, upper, step_increment)` tuple the widget hands
/// to `gtk::Adjustment::new` for the auto-lock seconds
/// `AdwSpinRow` per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"libadwaita usage" > "Preferences" and §"Component tree" >
/// `SettingsComponent`.
///
/// Returns
/// `(f64::from(paladin_core::AUTO_LOCK_SECS_MIN), f64::from(paladin_core::AUTO_LOCK_SECS_MAX), 1.0)`
/// — the §4.7 auto-lock bounds (the same range
/// [`clamp_auto_lock_secs`] and
/// [`SettingsState::stage_auto_lock_secs`] enforce) plus a
/// `1.0` step because the seconds domain is integer-only.
/// Pinning the adjustment through this helper keeps the spinner
/// bounds in one place shared by the widget binding and the
/// pure-logic tests in `tests/settings_logic.rs`; the widget
/// layer never duplicates the integer literals.
///
/// Pure — returns a `(f64, f64, f64)` tuple without allocating.
/// Sibling of
/// [`crate::add_account::format_manual_period_adjustment`],
/// [`crate::add_account::format_manual_counter_adjustment`], and
/// [`crate::add_account::format_manual_digits_adjustment`] on
/// the spinner-adjustment side; together they cover every
/// `AdwSpinRow` the GTK front end mounts.
#[must_use]
pub fn format_settings_dialog_auto_lock_secs_adjustment() -> (f64, f64, f64) {
    (
        f64::from(paladin_core::AUTO_LOCK_SECS_MIN),
        f64::from(paladin_core::AUTO_LOCK_SECS_MAX),
        1.0,
    )
}

/// Fixed `(lower, upper, step_increment)` tuple the widget hands
/// to `gtk::Adjustment::new` for the clipboard-clear seconds
/// `AdwSpinRow` per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"libadwaita usage" > "Preferences" and §"Component tree" >
/// `SettingsComponent`.
///
/// Returns
/// `(f64::from(paladin_core::CLIPBOARD_CLEAR_SECS_MIN), f64::from(paladin_core::CLIPBOARD_CLEAR_SECS_MAX), 1.0)`
/// — the §4.7 clipboard-clear bounds (the same range
/// [`clamp_clipboard_clear_secs`] and
/// [`SettingsState::stage_clipboard_clear_secs`] enforce) plus
/// a `1.0` step because the seconds domain is integer-only.
/// Pinning the adjustment through this helper keeps the spinner
/// bounds in one place shared by the widget binding and the
/// pure-logic tests in `tests/settings_logic.rs`; the widget
/// layer never duplicates the integer literals.
///
/// Pure — returns a `(f64, f64, f64)` tuple without allocating.
/// Sibling of [`format_settings_dialog_auto_lock_secs_adjustment`]
/// on the clipboard side; together they pin both `AdwSpinRow`
/// adjustments the `SettingsComponent` hosts.
#[must_use]
pub fn format_settings_dialog_clipboard_clear_secs_adjustment() -> (f64, f64, f64) {
    (
        f64::from(paladin_core::CLIPBOARD_CLEAR_SECS_MIN),
        f64::from(paladin_core::CLIPBOARD_CLEAR_SECS_MAX),
        1.0,
    )
}

/// State-driven projection of the auto-lock seconds `AdwSpinRow`'s
/// visible value, surfaced as the `f64` that `AdwSpinRow::set_value`
/// expects, per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `SettingsComponent` and §"Tests > Pure-logic unit tests >
/// `tests/settings_logic.rs`".
///
/// Returns [`SettingsState::visible_auto_lock_secs`] cast to
/// `f64` — the buffered (pending) spinner value while a 500 ms
/// debounce is in flight, and the committed value otherwise.
/// Threading the cast through this composer keeps the widget
/// binding minimal: the widget's `#[watch] set_value:` reads a
/// single `f64` instead of pattern-matching against the pending
/// buffer or casting inline against the live state.
///
/// Pure — borrows the state and returns an `f64` without allocating.
/// Sibling of
/// [`crate::add_account::compose_manual_period_secs_value`],
/// [`crate::add_account::compose_manual_counter_value`], and
/// [`crate::add_account::compose_manual_digits_value`] on the
/// spinner-value side; together they cover every
/// `AdwSpinRow::set_value:` binding the GTK front end mounts.
#[must_use]
pub fn compose_settings_dialog_auto_lock_secs_value(state: &SettingsState) -> f64 {
    f64::from(state.visible_auto_lock_secs())
}

/// State-driven projection of the clipboard-clear seconds
/// `AdwSpinRow`'s visible value, surfaced as the `f64` that
/// `AdwSpinRow::set_value` expects, per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `SettingsComponent`.
///
/// Returns [`SettingsState::visible_clipboard_clear_secs`] cast
/// to `f64` — the buffered (pending) spinner value while a
/// 500 ms debounce is in flight, and the committed value
/// otherwise. Sibling of
/// [`compose_settings_dialog_auto_lock_secs_value`] on the
/// clipboard side; together they cover both
/// `AdwSpinRow::set_value:` bindings the `SettingsComponent`
/// mounts.
///
/// Pure — borrows the state and returns an `f64` without allocating.
#[must_use]
pub fn compose_settings_dialog_clipboard_clear_secs_value(state: &SettingsState) -> f64 {
    f64::from(state.visible_clipboard_clear_secs())
}

/// State-driven projection of the auto-lock `AdwSwitchRow`'s
/// active state, surfaced as the `bool` that `AdwSwitchRow::set_active`
/// expects, per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree"
/// > `SettingsComponent`.
///
/// Returns `state.committed().auto_lock_enabled()` — toggle
/// clicks bypass the spinner debounce buffer because they reflect
/// a discrete user intent (per
/// [`SettingsState::toggle_auto_lock_enabled`]), so the committed
/// snapshot is the single source of truth for the switch's
/// active state. Threading the bool through this composer keeps
/// the widget binding minimal: the widget's `#[watch] set_active:`
/// reads a single `bool` instead of reaching into
/// [`CommittedSettings`] inline.
///
/// Pure — borrows the state and returns a `bool` without allocating.
/// Sibling of [`compose_settings_dialog_auto_lock_secs_value`]
/// on the auto-lock side.
#[must_use]
pub fn compose_settings_dialog_auto_lock_enabled_active(state: &SettingsState) -> bool {
    state.committed().auto_lock_enabled()
}

/// Buffered spinner pending the 500 ms debounce.
#[derive(Debug, Clone, Copy)]
enum PendingSpinner {
    AutoLockSecs(u32),
    ClipboardClearSecs(u32),
}

/// Pure-logic settings-dialog state machine.
///
/// Tracks the last committed [`CommittedSettings`] snapshot and at
/// most one pending spinner draft. Toggle clicks bypass the pending
/// buffer because they reflect a discrete user intent.
///
/// The widget layer pairs this with a
/// `glib::timeout_add_local(500ms, ...)` after every `stage_*` call;
/// the timer's tick handler calls [`Self::resolve_debounce`] and
/// fires `Vault::mutate_and_save` on `Save`.
#[derive(Debug, Clone)]
pub struct SettingsState {
    committed: CommittedSettings,
    pending: Option<PendingSpinner>,
}

impl SettingsState {
    /// Open the dialog on `committed` (snapshot from
    /// `Vault::settings()` via [`CommittedSettings::from_vault_settings`]).
    #[must_use]
    pub fn new(committed: CommittedSettings) -> Self {
        Self {
            committed,
            pending: None,
        }
    }

    /// Committed (on-disk) snapshot.
    #[must_use]
    pub fn committed(&self) -> &CommittedSettings {
        &self.committed
    }

    /// Visible `auto_lock_timeout_secs` value — the pending draft if
    /// one is buffered for that field, otherwise the committed value.
    #[must_use]
    pub fn visible_auto_lock_secs(&self) -> u32 {
        match self.pending {
            Some(PendingSpinner::AutoLockSecs(v)) => v,
            _ => self.committed.auto_lock_secs,
        }
    }

    /// Visible `clipboard_clear_secs` value — the pending draft if
    /// one is buffered for that field, otherwise the committed value.
    #[must_use]
    pub fn visible_clipboard_clear_secs(&self) -> u32 {
        match self.pending {
            Some(PendingSpinner::ClipboardClearSecs(v)) => v,
            _ => self.committed.clipboard_clear_secs,
        }
    }

    /// Buffer a new `auto_lock_timeout_secs` spinner value. Replaces
    /// any prior pending entry (a spinner switch drops the previous
    /// row's pending). Returns the clamped value the widget should
    /// display.
    pub fn stage_auto_lock_secs(&mut self, raw: u32) -> u32 {
        let clamped = clamp_auto_lock_secs(raw);
        self.pending = Some(PendingSpinner::AutoLockSecs(clamped));
        clamped
    }

    /// Buffer a new `clipboard_clear_secs` spinner value. Replaces
    /// any prior pending entry. Returns the clamped value.
    pub fn stage_clipboard_clear_secs(&mut self, raw: u32) -> u32 {
        let clamped = clamp_clipboard_clear_secs(raw);
        self.pending = Some(PendingSpinner::ClipboardClearSecs(clamped));
        clamped
    }

    /// Resolve the 500 ms debounce tick. Returns
    /// [`DebounceOutcome::Save`] iff a pending draft differs from
    /// the committed value, and clears the pending buffer in that
    /// case so the next tick is idle unless new spinner activity
    /// arrives.
    pub fn resolve_debounce(&mut self) -> DebounceOutcome {
        let Some(pending) = self.pending else {
            return DebounceOutcome::Idle;
        };
        let (patch, field) = match pending {
            PendingSpinner::AutoLockSecs(v) => {
                if v == self.committed.auto_lock_secs {
                    self.pending = None;
                    return DebounceOutcome::Idle;
                }
                (
                    SettingPatch::AutoLockTimeoutSecs(v),
                    SettingsField::AutoLockSecs,
                )
            }
            PendingSpinner::ClipboardClearSecs(v) => {
                if v == self.committed.clipboard_clear_secs {
                    self.pending = None;
                    return DebounceOutcome::Idle;
                }
                (
                    SettingPatch::ClipboardClearSecs(v),
                    SettingsField::ClipboardClearSecs,
                )
            }
        };
        self.pending = None;
        DebounceOutcome::Save { patch, field }
    }

    /// Flip the `auto_lock_enabled` toggle. Toggles do not debounce.
    pub fn toggle_auto_lock_enabled(&mut self, enabled: bool) -> ToggleOutcome {
        if enabled == self.committed.auto_lock_enabled {
            return ToggleOutcome::Noop;
        }
        ToggleOutcome::Save {
            patch: SettingPatch::AutoLockEnabled(enabled),
            field: SettingsField::AutoLockEnabled,
        }
    }

    /// Flip the `clipboard_clear_enabled` toggle. Toggles do not
    /// debounce.
    pub fn toggle_clipboard_clear_enabled(&mut self, enabled: bool) -> ToggleOutcome {
        if enabled == self.committed.clipboard_clear_enabled {
            return ToggleOutcome::Noop;
        }
        ToggleOutcome::Save {
            patch: SettingPatch::ClipboardClearEnabled(enabled),
            field: SettingsField::ClipboardClearEnabled,
        }
    }

    /// Route the typed worker result back into the state machine.
    /// Updates the committed snapshot in the success /
    /// durability-unconfirmed cases (the file is on disk in both)
    /// and leaves it unchanged on rollback / inline failure.
    pub fn apply_save_result(
        &mut self,
        change: AcceptedChange,
        result: Result<(), PaladinError>,
    ) -> SaveOutcome {
        match result {
            Ok(()) => {
                self.commit_attempted(change);
                SaveOutcome::Success
            }
            Err(err) if err.kind() == ErrorKind::SaveDurabilityUnconfirmed => {
                self.commit_attempted(change);
                SaveOutcome::DurabilityWarning {
                    warning: InlineWarning::from_error(&err),
                    field: change.field(),
                }
            }
            Err(err) if err.kind() == ErrorKind::SaveNotCommitted => SaveOutcome::Rollback {
                error: InlineError::from_error(&err),
                field: change.field(),
            },
            Err(err) => SaveOutcome::Inline {
                error: InlineError::from_error(&err),
                field: change.field(),
            },
        }
    }

    fn commit_attempted(&mut self, change: AcceptedChange) {
        match change {
            AcceptedChange::AutoLockEnabled(v) => self.committed.auto_lock_enabled = v,
            AcceptedChange::AutoLockSecs(v) => self.committed.auto_lock_secs = v,
            AcceptedChange::ClipboardClearEnabled(v) => self.committed.clipboard_clear_enabled = v,
            AcceptedChange::ClipboardClearSecs(v) => self.committed.clipboard_clear_secs = v,
        }
    }
}
