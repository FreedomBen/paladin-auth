// SPDX-License-Identifier: AGPL-3.0-or-later

//! Settings-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
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

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::gtk::gio;
use relm4::gtk::glib;
use relm4::prelude::*;

use paladin_core::{
    ErrorKind, PaladinError, SettingPatch, Store, Vault, AUTO_LOCK_SECS_MAX, AUTO_LOCK_SECS_MIN,
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
    /// primary save succeeded) but the parent-directory `fsync`
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
/// [`crate::edit_dialog::InlineError`] / [`crate::export_dialog::InlineError`]
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
/// [`crate::edit_dialog::format_edit_dialog_title`],
/// [`crate::remove_dialog::format_remove_dialog_title`], and
/// [`crate::startup_error::format_startup_error_title`] on the
/// dialog-header-title side; together they pin every dialog's
/// titled surface against a single source of truth.
#[must_use]
pub fn format_settings_dialog_title() -> &'static str {
    "Preferences"
}

/// Title rendered on the `AdwPreferencesGroup` that hosts the
/// auto-lock toggle + spinner per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
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
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
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
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
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
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
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
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
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
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
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

/// Title rendered on the per-user "Display" `AdwPreferencesGroup`
/// that hosts the section-headers `AdwSwitchRow` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `SettingsComponent` > Display group.
///
/// Returned by a dedicated helper (vs.
/// [`format_settings_dialog_auto_lock_group_title`] /
/// [`format_settings_dialog_clipboard_clear_group_title`]) so the
/// three groups' titles stay aligned in the same module and so a
/// future locale pass updates them together.
#[must_use]
pub fn format_settings_dialog_display_group_title() -> &'static str {
    "Display"
}

/// Title rendered on the section-headers `AdwSwitchRow` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `SettingsComponent` > Display group.
///
/// Verb-led wording matches the auto-lock / clipboard rows.
#[must_use]
pub fn format_settings_dialog_section_headers_row_title() -> &'static str {
    "Show section headers"
}

/// Subtitle rendered on the section-headers `AdwSwitchRow` so the
/// user knows what flipping it does without having to consult the
/// docs.  Explains the issuer-grouping behavior and the
/// vault-insertion-order caveat in one sentence.
#[must_use]
pub fn format_settings_dialog_section_headers_row_subtitle() -> &'static str {
    "Group consecutive accounts by issuer with a small heading. Off by default."
}

/// Title rendered on the column-headers `AdwSwitchRow` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §A.4
/// "Column-header visibility preference".
///
/// Verb-led wording matches the auto-lock / clipboard / section-
/// headers rows for parallel structure inside the Display group.
#[must_use]
pub fn format_settings_dialog_column_headers_row_title() -> &'static str {
    "Show column headers"
}

/// Subtitle rendered on the column-headers `AdwSwitchRow` so the
/// user knows what flipping it does without having to consult the
/// docs.
#[must_use]
pub fn format_settings_dialog_column_headers_row_subtitle() -> &'static str {
    "Show the Account / Code / Time / Copy / Menu column titles above the list. On by default."
}

/// Title rendered on the next-code-column `AdwSwitchRow` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Next-code column
/// implementation" > "Build order" > "Preferences toggle".
///
/// Verb-led wording matches the auto-lock / clipboard / section-
/// headers / column-headers rows for parallel structure inside
/// the Display group.
#[must_use]
pub fn format_settings_dialog_next_code_column_row_title() -> &'static str {
    "Show next code"
}

/// Subtitle rendered on the next-code-column `AdwSwitchRow` so the
/// user knows what flipping it does without having to consult the
/// docs.  Explains the upcoming-TOTP-digits behavior and the
/// default-on stance in one sentence.
#[must_use]
pub fn format_settings_dialog_next_code_column_row_subtitle() -> &'static str {
    "Show the upcoming TOTP code in a Next column with a copy affordance. On by default."
}

/// Fixed `(lower, upper, step_increment)` tuple the widget hands
/// to `gtk::Adjustment::new` for the auto-lock seconds
/// `AdwSpinRow` per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
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
/// `AdwSpinRow` per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
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
/// expects, per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
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
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
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
/// expects, per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree"
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

/// State-driven projection of the clipboard-clear
/// `AdwSwitchRow`'s active state, surfaced as the `bool` that
/// `AdwSwitchRow::set_active` expects, per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `SettingsComponent`.
///
/// Returns `state.committed().clipboard_clear_enabled()` —
/// toggle clicks bypass the spinner debounce buffer because they
/// reflect a discrete user intent (per
/// [`SettingsState::toggle_clipboard_clear_enabled`]), so the
/// committed snapshot is the single source of truth for the
/// switch's active state. Sibling of
/// [`compose_settings_dialog_auto_lock_enabled_active`] on the
/// clipboard side; together they cover both
/// `AdwSwitchRow::set_active:` bindings the `SettingsComponent`
/// mounts.
///
/// Pure — borrows the state and returns a `bool` without allocating.
#[must_use]
pub fn compose_settings_dialog_clipboard_clear_enabled_active(state: &SettingsState) -> bool {
    state.committed().clipboard_clear_enabled()
}

/// State-driven projection of the auto-lock seconds
/// `AdwSpinRow`'s sensitivity, surfaced as the `bool` that
/// `AdwSpinRow::set_sensitive` expects, per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `SettingsComponent`.
///
/// Returns `state.committed().auto_lock_enabled()` — the seconds
/// spinner has no effect when the toggle is off, so disabling
/// the row follows the GNOME HIG ("disable controls whose effect
/// is conditional on a sibling") and visually signals the
/// dependency. Threading the bool through this composer keeps
/// the widget binding minimal: the widget's
/// `#[watch] set_sensitive:` reads a single `bool` instead of
/// reaching into [`CommittedSettings`] inline.
///
/// Pure — borrows the state and returns a `bool` without allocating.
/// Sibling of [`compose_settings_dialog_auto_lock_enabled_active`]
/// (the gating toggle) on the auto-lock side.
#[must_use]
pub fn compose_settings_dialog_auto_lock_secs_sensitive(state: &SettingsState) -> bool {
    if state.is_busy() {
        return false;
    }
    state.committed().auto_lock_enabled()
}

/// Whether the auto-lock `AdwSwitchRow` should be sensitive.
///
/// Returns `false` while [`SettingsState::is_busy`] so the toggle
/// dims alongside the spinner while a `Vault::mutate_and_save`
/// settings worker is in flight; `true` otherwise. The widget
/// binds `AdwSwitchRow::set_sensitive` to this through `#[watch]`.
///
/// Pure — sibling of
/// [`compose_settings_dialog_auto_lock_secs_sensitive`] on the
/// toggle-row side. Pinned by `tests/settings_logic.rs`.
#[must_use]
pub fn compose_settings_dialog_auto_lock_enabled_sensitive(state: &SettingsState) -> bool {
    !state.is_busy()
}

/// State-driven projection of the clipboard-clear seconds
/// `AdwSpinRow`'s sensitivity, surfaced as the `bool` that
/// `AdwSpinRow::set_sensitive` expects, per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `SettingsComponent`.
///
/// Returns `state.committed().clipboard_clear_enabled()` — the
/// seconds spinner has no effect when the toggle is off, so
/// disabling the row follows the GNOME HIG ("disable controls
/// whose effect is conditional on a sibling") and visually
/// signals the dependency. Sibling of
/// [`compose_settings_dialog_auto_lock_secs_sensitive`] on the
/// clipboard side; together they cover both
/// `AdwSpinRow::set_sensitive:` bindings the
/// `SettingsComponent` mounts.
///
/// Pure — borrows the state and returns a `bool` without allocating.
#[must_use]
pub fn compose_settings_dialog_clipboard_clear_secs_sensitive(state: &SettingsState) -> bool {
    if state.is_busy() {
        return false;
    }
    state.committed().clipboard_clear_enabled()
}

/// Whether the clipboard-clear `AdwSwitchRow` should be sensitive.
///
/// Returns `false` while [`SettingsState::is_busy`]; `true`
/// otherwise. Sibling of
/// [`compose_settings_dialog_auto_lock_enabled_sensitive`] on the
/// other toggle. Pure — pinned by `tests/settings_logic.rs`.
#[must_use]
pub fn compose_settings_dialog_clipboard_clear_enabled_sensitive(state: &SettingsState) -> bool {
    !state.is_busy()
}

/// Toast body rendered by `SettingsComponent` on an accepted
/// change per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage"
/// > "Toast surface".
///
/// On a `SaveOutcome::Success` from [`SettingsState::apply_save_result`]
/// the widget layer threads this helper into
/// `AdwToast::new(format_settings_dialog_saved_toast())` and
/// dispatches it through the application's `AdwToastOverlay` so the
/// confirmation surfaces without blocking further interaction.
/// Pinning the wording through this helper keeps the text in one
/// place shared by the widget binding and the pure-logic tests in
/// `tests/settings_logic.rs`.
///
/// The wording (`"Settings saved"`) names the affirmative outcome
/// without restating which setting changed — the dialog body still
/// shows the visible value the user picked — and reads identically
/// whether the change came from a switch click or a debounced
/// spinner edit. Verb-led, HIG-conformant, and brief enough for an
/// `AdwToast` to fit the default timeout.
///
/// No TUI parity: the TUI's `settings` command is CLI-shaped and
/// emits a stdout confirmation rather than a transient toast (see
/// `crates/paladin-tui/src/view`), so the wording is GTK-specific.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_settings_dialog_saved_toast() -> &'static str {
    "Settings saved"
}

/// State-driven projection of the inline subtitle text the
/// `SettingsComponent` renders beneath the `AdwSwitchRow` /
/// `AdwSpinRow` identified by `field` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Tests > Pure-logic unit tests >
/// `tests/settings_logic.rs`".
///
/// Routes a [`SaveOutcome`] (the typed reply from
/// [`SettingsState::apply_save_result`]) into a per-row subtitle
/// projection so the widget can bind a single
/// `#[watch] set_label:` / `#[watch] set_visible:` pair against
/// the helper instead of pattern-matching against an
/// `Option<SaveOutcome>` inline. The projection covers every
/// failure / warning arm:
///
/// * [`SaveOutcome::Inline`] and [`SaveOutcome::Rollback`] → the
///   matching row carries the rendered [`InlineError::rendered`]
///   body verbatim (the §5 `Display` body shared with the CLI /
///   TUI). Other rows stay clear.
/// * [`SaveOutcome::DurabilityWarning`] → the matching row
///   carries the rendered [`InlineWarning::rendered`] body
///   verbatim. Other rows stay clear.
/// * [`SaveOutcome::Success`] → no per-row subtitle; the
///   affirmative outcome surfaces through
///   [`format_settings_dialog_saved_toast`] on the
///   `AdwToastOverlay` instead, per
///   `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
///   "Toast surface".
/// * `None` (no save attempted yet) → no subtitle for any row.
///
/// Pure — borrows the outcome and returns an `Option<&str>`
/// without allocating; the returned slice borrows from the
/// outcome's [`InlineError::rendered`] / [`InlineWarning::rendered`]
/// `String` so the widget can re-render the row subtitle in
/// lockstep with the `#[watch]` dispatch without re-deriving
/// the routing decision against [`SaveOutcome`] inline.
#[must_use]
pub fn compose_settings_dialog_inline_subtitle_for_field(
    outcome: Option<&SaveOutcome>,
    field: SettingsField,
) -> Option<&str> {
    match outcome? {
        SaveOutcome::Inline {
            error,
            field: target,
        }
        | SaveOutcome::Rollback {
            error,
            field: target,
        } if *target == field => Some(error.rendered.as_str()),
        SaveOutcome::DurabilityWarning {
            warning,
            field: target,
        } if *target == field => Some(warning.rendered.as_str()),
        SaveOutcome::Success
        | SaveOutcome::Inline { .. }
        | SaveOutcome::Rollback { .. }
        | SaveOutcome::DurabilityWarning { .. } => None,
    }
}

/// State-driven projection of whether the inline-subtitle
/// `gtk::Label` beneath the `AdwSwitchRow` / `AdwSpinRow`
/// identified by `field` is currently revealed per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Tests > Pure-logic unit tests >
/// `tests/settings_logic.rs`".
///
/// Sibling of
/// [`compose_settings_dialog_inline_subtitle_for_field`] on the
/// `set_visible:` side: returns `true` iff the text projection
/// returns `Some`, so the widget can bind a single
/// `#[watch] set_visible:` against the helper instead of
/// re-deriving the routing decision against [`SaveOutcome`] or
/// calling `.is_some()` on the text projection inline. Lets the
/// row chrome — body text and visibility — flip together on the
/// same `SaveOutcome` dispatch.
///
/// Pure — borrows the outcome and returns a `bool` without
/// allocating; mirrors the partitioning of [`SaveOutcome`] applied
/// by [`compose_settings_dialog_inline_subtitle_for_field`] so the
/// two projections stay in lockstep across every dispatch.
#[must_use]
pub fn compose_settings_dialog_inline_subtitle_revealed_for_field(
    outcome: Option<&SaveOutcome>,
    field: SettingsField,
) -> bool {
    compose_settings_dialog_inline_subtitle_for_field(outcome, field).is_some()
}

/// State-driven projection of the CSS class the inline-subtitle
/// `gtk::Label` beneath the `AdwSwitchRow` / `AdwSpinRow`
/// identified by `field` carries per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Tests > Pure-logic unit tests >
/// `tests/settings_logic.rs`".
///
/// Routes a [`SaveOutcome`] (the typed reply from
/// [`SettingsState::apply_save_result`]) into the styling class
/// the matching row's inline-subtitle label uses so the widget
/// can bind `add_css_class:` / `remove_css_class:` declaratively
/// rather than re-routing on [`SaveOutcome`] inline:
///
/// * [`SaveOutcome::Inline`] / [`SaveOutcome::Rollback`] → the
///   matching row carries the `"error"` class (red foreground,
///   matching the `crate::edit_dialog::EditDialogComponent`
///   inline-error label styling so failures across dialogs read
///   identically).
/// * [`SaveOutcome::DurabilityWarning`] → the matching row carries
///   the `"warning"` class (amber, distinguishing the
///   post-commit-but-fsync-failed case from the pre-commit
///   rollback path so the user can tell the value is on disk
///   even though the warning is showing).
/// * [`SaveOutcome::Success`] and `None` → no CSS class.
/// * Non-matching rows always return `None`.
///
/// Pure — borrows the outcome and returns an `Option<&'static str>`
/// without allocating; the returned slice is one of the two
/// libadwaita-recognized class names (`"error"` / `"warning"`).
/// Sibling of
/// [`compose_settings_dialog_inline_subtitle_for_field`] (the text
/// body) and
/// [`compose_settings_dialog_inline_subtitle_revealed_for_field`]
/// (the visibility flag); the three projections partition
/// [`SaveOutcome`] in lockstep so the row chrome — body, class,
/// and visibility — flips together on the same dispatch.
#[must_use]
pub fn compose_settings_dialog_inline_subtitle_css_class_for_field(
    outcome: Option<&SaveOutcome>,
    field: SettingsField,
) -> Option<&'static str> {
    match outcome? {
        SaveOutcome::Inline { field: target, .. } | SaveOutcome::Rollback { field: target, .. }
            if *target == field =>
        {
            Some("error")
        }
        SaveOutcome::DurabilityWarning { field: target, .. } if *target == field => Some("warning"),
        SaveOutcome::Success
        | SaveOutcome::Inline { .. }
        | SaveOutcome::Rollback { .. }
        | SaveOutcome::DurabilityWarning { .. } => None,
    }
}

/// Bridge between the two parallel enums the dialog round trip
/// touches: [`paladin_core::SettingPatch`] (returned in
/// [`ToggleOutcome::Save`] / [`DebounceOutcome::Save`] and consumed
/// by [`paladin_core::Vault::apply_setting_patch`] inside
/// `Vault::mutate_and_save`) and [`AcceptedChange`] (handed to
/// [`SettingsState::apply_save_result`] so the state machine
/// promotes / rolls back the right field after the worker
/// returns).
///
/// The widget layer keeps the patch and the change side-by-side
/// across the async hop: the patch is what mutates the vault, the
/// change is what the dialog remembers so a fresh pending spinner
/// arriving during the save does not derail the rollback (a fresh
/// pending may have accumulated by the time the worker returns,
/// per the [`AcceptedChange`] docstring). Pinning the conversion
/// through this helper keeps the two enum spellings aligned in one
/// place; without it the widget would re-match the four variants by
/// hand in two different call sites, drifting them apart on every
/// enum extension.
///
/// Pure — takes the patch by reference and returns an owned
/// [`AcceptedChange`] (`Copy`) without allocating. Sibling of
/// [`AcceptedChange::field`] (the change → field projection); the
/// two together let the widget take a `SettingPatch` and route it
/// to the matching row without ever pattern-matching on
/// [`SettingPatch`] directly.
#[must_use]
pub fn accepted_change_from_setting_patch(patch: &SettingPatch) -> AcceptedChange {
    match *patch {
        SettingPatch::AutoLockEnabled(v) => AcceptedChange::AutoLockEnabled(v),
        SettingPatch::AutoLockTimeoutSecs(v) => AcceptedChange::AutoLockSecs(v),
        SettingPatch::ClipboardClearEnabled(v) => AcceptedChange::ClipboardClearEnabled(v),
        SettingPatch::ClipboardClearSecs(v) => AcceptedChange::ClipboardClearSecs(v),
    }
}

/// Fixed `page_increment` value the widget hands to
/// [`gtk::Adjustment::new`] for both `AdwSpinRow` adjustments per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
///
/// Returns `10.0` — the conventional 10× step factor relative to
/// the `1.0` `step_increment` returned by
/// [`format_settings_dialog_auto_lock_secs_adjustment`] and
/// [`format_settings_dialog_clipboard_clear_secs_adjustment`].
/// Governs the value the `AdwSpinRow` jumps by on Page Up / Page
/// Down keyboard navigation: small enough to feel responsive on
/// the §4.7-bounded ranges (auto-lock 30..=86400, clipboard
/// 5..=600) without sliding past the bounds in a single press,
/// large enough that paging differs meaningfully from the per-
/// press +/- buttons.
///
/// Shared by both spinners — both edit a seconds dimension and
/// both use the same `1.0` per-press step, so the page step is
/// also shared. Pinning the literal through this helper keeps
/// the spinner keyboard navigation in one place; the widget layer
/// never duplicates the literal.
///
/// Pure — returns an `f64` without allocating. Sibling of
/// [`format_settings_dialog_auto_lock_secs_adjustment`] and
/// [`format_settings_dialog_clipboard_clear_secs_adjustment`] on
/// the [`gtk::Adjustment::new`] argument side; together they pin
/// every value the constructor receives for both spinners (the
/// `value` itself comes from
/// [`compose_settings_dialog_auto_lock_secs_value`] /
/// [`compose_settings_dialog_clipboard_clear_secs_value`], and
/// `page_size` stays `0.0` because `AdwSpinRow` has no slider
/// area).
#[must_use]
pub fn format_settings_dialog_spinner_page_increment() -> f64 {
    10.0
}

/// Fixed `page_size` value the widget hands to
/// [`gtk::Adjustment::new`] for both `AdwSpinRow` adjustments per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
///
/// Returns `0.0` because `AdwSpinRow` surfaces a
/// `gtk::SpinButton`-style numeric editor with no slider area; the
/// `page_size` parameter only matters for slider-backing
/// adjustments (`gtk::Scale`, `gtk::Scrollbar`). A non-zero value
/// would make the spinner's accepted upper bound become
/// `upper - page_size`, silently shrinking the range pinned
/// through [`format_settings_dialog_auto_lock_secs_adjustment`] /
/// [`format_settings_dialog_clipboard_clear_secs_adjustment`].
///
/// Pinning the literal through this helper keeps the
/// [`gtk::Adjustment::new`] argument in one place shared by both
/// spinners; the widget layer never duplicates the literal.
///
/// Pure — returns an `f64` without allocating. Sibling of
/// [`format_settings_dialog_spinner_page_increment`] and the two
/// `format_settings_dialog_*_secs_adjustment` helpers on the
/// [`gtk::Adjustment::new`] argument side; the four together pin
/// every positional argument the constructor receives beyond the
/// `value` (which comes from
/// [`compose_settings_dialog_auto_lock_secs_value`] /
/// [`compose_settings_dialog_clipboard_clear_secs_value`]).
#[must_use]
pub fn format_settings_dialog_spinner_page_size() -> f64 {
    0.0
}

/// Fixed `climb_rate` value the widget hands to
/// [`adw::SpinRow::new`] for both `AdwSpinRow` constructors per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
///
/// Returns `1.0` — a flat (non-accelerated) climb rate suited to
/// the §4.7 seconds ranges. Auto-lock spans `30..=86_400` and
/// clipboard-clear spans `5..=600` (both at the `1.0` step from
/// the matching `_secs_adjustment` tuple), so an accelerated
/// climb rate would skip past intended values faster than the eye
/// can track — especially on the short clipboard range. Pinning
/// the literal through this helper keeps the climb rate in one
/// place shared by both `adw::SpinRow::new` calls; the widget
/// layer never duplicates the literal.
///
/// Pure — returns an `f64` without allocating. Sibling of
/// [`format_settings_dialog_spinner_page_increment`] and
/// [`format_settings_dialog_spinner_page_size`] on the
/// [`adw::SpinRow::new`] argument side; together they pin every
/// numeric the constructor receives beyond the
/// [`gtk::Adjustment`] (which the value compose helpers, the
/// bounds adjustment tuple, `page_increment`, and `page_size`
/// already cover).
#[must_use]
pub fn format_settings_dialog_spinner_climb_rate() -> f64 {
    1.0
}

/// Fixed `digits` value the widget hands to
/// [`adw::SpinRow::new`] for both `AdwSpinRow` constructors per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
///
/// Returns `0` because the §4.7 spinner-edited settings
/// ([`paladin_core::VaultSettings::auto_lock_timeout_secs`] and
/// [`paladin_core::VaultSettings::clipboard_clear_secs`]) are
/// `u32` seconds — a whole-number dimension with no fractional
/// component. A non-zero `digits` would render trailing `.000`
/// glyphs that misrepresent the typed values and could mislead
/// the user into entering fractional values the integer parser
/// already drops on `Vault::apply_setting_patch`.
///
/// Pinning the literal through this helper keeps the digits
/// count in one place shared by both `adw::SpinRow::new` calls
/// the `SettingsComponent` makes; the widget layer never
/// duplicates the literal.
///
/// Pure — returns a `u32` without allocating. Sibling of
/// [`format_settings_dialog_spinner_climb_rate`],
/// [`format_settings_dialog_spinner_page_increment`], and
/// [`format_settings_dialog_spinner_page_size`] on the
/// [`adw::SpinRow::new`] argument side; together with the bounds
/// adjustment tuple and the value compose helpers they pin every
/// value the constructor receives.
#[must_use]
pub fn format_settings_dialog_spinner_digits() -> u32 {
    0
}

/// Fixed `bool` the widget passes to
/// `AdwPreferencesDialog::set_search_enabled` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
///
/// Returns `false` — libadwaita defaults this property to `TRUE`
/// (the dialog grows a search bar that scans every
/// `AdwPreferencesGroup` row title / description, built for large
/// dialogs hosting many `AdwPreferencesPage`s like GNOME Settings).
/// Our `SettingsComponent` hosts exactly two
/// `AdwPreferencesGroup`s — the auto-lock and clipboard panels
/// pinned by [`format_settings_dialog_auto_lock_group_title`] /
/// [`format_settings_dialog_clipboard_clear_group_title`] — with
/// four rows total. The search bar would visually crowd the chrome
/// above the groups without surfacing any rows the user could not
/// already see at a glance, so the `SettingsComponent` calls
/// `set_search_enabled(format_settings_dialog_search_enabled())`
/// once after construction to suppress it.
///
/// Pinning the literal through this helper keeps the
/// search-enabled flag in one place shared by the widget binding
/// and the pure-logic tests in `tests/settings_logic.rs`; the
/// widget layer never duplicates the literal. Sibling of
/// [`format_settings_dialog_title`] on the `AdwPreferencesDialog`
/// property side; together they pin the dialog-level chrome above
/// the `AdwPreferencesGroup`s that the group-title / row-title
/// helpers cover.
///
/// Pure — returns a `bool` without allocating.
#[must_use]
pub fn format_settings_dialog_search_enabled() -> bool {
    false
}

/// Fixed `bool` the widget passes to `AdwToast::set_use_markup` for
/// the [`format_settings_dialog_saved_toast`] body per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Toast surface" and §"Component tree" > `SettingsComponent`.
///
/// Returns `false` — `AdwToast::use-markup` defaults to `TRUE`
/// (the inherited `title` property is markup-aware), so any `&` /
/// `<` / `>` byte in the body would otherwise get parsed as Pango
/// markup. The [`format_settings_dialog_saved_toast`] body is a
/// static `&'static str` with no entity-quoted glyphs today, but
/// the helper's docstring leaves the door open to future
/// localisation; once translators get hold of the string, an `&`
/// in a translation would silently truncate the toast or surface a
/// console warning. Pinning the flag to `false` keeps the body as
/// literal text regardless of future wording, matching every other
/// plain-text surface in the dialog (the inline subtitle text
/// helpers return raw [`SaveOutcome`] error / warning `Display`
/// bodies, not markup).
///
/// Pinning the literal through this helper keeps the use-markup
/// flag in one place shared by the widget binding
/// (`AdwToast::set_use_markup(
/// format_settings_dialog_saved_toast_use_markup())`) and the
/// pure-logic tests in `tests/settings_logic.rs`; the widget layer
/// never duplicates the literal. Sibling of
/// [`format_settings_dialog_saved_toast`] (the body text) and
/// [`format_settings_dialog_saved_toast_timeout`] (the auto-dismiss
/// window); together they pin every value the success-toast
/// constructor / setter chain receives.
///
/// Pure — returns a `bool` without allocating.
#[must_use]
pub fn format_settings_dialog_saved_toast_use_markup() -> bool {
    false
}

/// Fixed `u32` count of seconds the
/// [`format_settings_dialog_saved_toast`] body stays visible on the
/// `AdwToastOverlay` per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"libadwaita usage" > "Toast surface" and §"Component tree" >
/// `SettingsComponent`.
///
/// Returns `5` — matches the `AdwToast` default timeout the
/// [`format_settings_dialog_saved_toast`] docstring was sized for
/// ("brief enough for an `AdwToast` to fit the default timeout").
/// Long enough for the user to register the confirmation, short
/// enough that a rapid sequence of saves does not stack overlapping
/// toasts on the `AdwToastOverlay`. The `SettingsComponent` raises
/// the success toast via
/// `AdwToast::new(format_settings_dialog_saved_toast())` and then
/// `set_timeout(format_settings_dialog_saved_toast_timeout())`, so
/// pinning the literal through this helper keeps the timeout in one
/// place shared by the widget binding and the pure-logic tests in
/// `tests/settings_logic.rs`; the widget layer never duplicates the
/// literal.
///
/// `0` would disable auto-dismissal entirely (defeating the
/// transient confirmation surface), so the helper returns a strictly
/// positive count. Sibling of [`format_settings_dialog_saved_toast`]
/// (the body text); the two together pin every value the
/// success-toast constructor call receives. The matching failure /
/// warning surfaces never use the toast — they route through
/// [`compose_settings_dialog_inline_subtitle_for_field`] and the
/// inline-subtitle helpers instead — so this timeout only governs
/// the affirmative path.
///
/// Pure — returns a `u32` without allocating.
#[must_use]
pub fn format_settings_dialog_saved_toast_timeout() -> u32 {
    5
}

/// Fixed `bool` the widget passes to
/// [`gtk::prelude::SpinButtonExt::set_wrap`] (via
/// `adw::SpinRow::set_wrap`) for both `SettingsComponent` spinners
/// per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
///
/// Returns `false` — `gtk::SpinButton::wrap` (surfaced through
/// `adw::SpinRow`) defaults to `FALSE`: once the value reaches
/// `upper` (or `lower`), continued `+` (or `-`) presses keep the
/// value pinned at the boundary rather than wrapping to the
/// opposite end. The §4.7 ranges
/// (`auto_lock_timeout_secs` 30..=86400; `clipboard_clear_secs`
/// 5..=600) make wrap-around behavior actively user-hostile: a
/// user holding `-` on the clipboard-clear spinner expecting it to
/// drop toward 5 would suddenly find it at 600, a 12x jump in the
/// opposite direction. Pinning the flag to `false` matches the
/// default but makes the bounded-behavior contract explicit so
/// future contributors do not flip it on by mistake (e.g. for a
/// clock-face hour picker that genuinely benefits from wrap).
///
/// Pairs with the bounded `gtk::Adjustment` returned by
/// [`format_settings_dialog_auto_lock_secs_adjustment`] /
/// [`format_settings_dialog_clipboard_clear_secs_adjustment`] on
/// the value-range side; wrap controls the *traversal* across
/// those bounds while the adjustment pins the bounds themselves.
///
/// Pinning the literal through this helper keeps the wrap flag in
/// one place shared by both `adw::SpinRow::set_wrap` calls the
/// `SettingsComponent` makes; the widget layer never duplicates the
/// literal. Sibling of
/// [`format_settings_dialog_spinner_climb_rate`],
/// [`format_settings_dialog_spinner_digits`],
/// [`format_settings_dialog_spinner_numeric`],
/// [`format_settings_dialog_spinner_page_increment`],
/// [`format_settings_dialog_spinner_page_size`], and
/// [`format_settings_dialog_spinner_snap_to_ticks`] on the
/// `adw::SpinRow` property side; together they pin every
/// spinner-property literal the `SettingsComponent` sets beyond the
/// `gtk::Adjustment` bounds.
///
/// Pure — returns a `bool` without allocating.
#[must_use]
pub fn format_settings_dialog_spinner_wrap() -> bool {
    false
}

/// Fixed `bool` the widget passes to
/// [`gtk::prelude::SpinButtonExt::set_numeric`] (via
/// `adw::SpinRow::set_numeric`) for both `SettingsComponent`
/// spinners per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"libadwaita usage" > "Preferences" and §"Component tree" >
/// `SettingsComponent`.
///
/// Returns `true` — `adw::SpinRow::numeric` (the libadwaita-side
/// override of the `gtk::SpinButton` property of the same name)
/// defaults to `TRUE` (typed input is restricted to digits, the
/// decimal point, and the minus sign), while the underlying
/// `gtk::SpinButton::numeric` defaults to `FALSE`. Toggling it back
/// to `FALSE` would let a user paste arbitrary text into the
/// spinner entry (e.g. `"thirty seconds"`); the entry's value
/// parser then silently snaps the unparseable input to the prior
/// committed value without firing a `changed` signal, leaving the
/// visible text out of sync with the value the [`SettingsState`]
/// debounce eventually saves. Pinning the flag to `true` makes the
/// input restriction explicit so future contributors do not regress
/// the property to the `gtk::SpinButton` default by mistake.
///
/// Pairs with [`format_settings_dialog_spinner_digits`] returning
/// `0` (the entry shows no fractional places) and
/// [`format_settings_dialog_spinner_snap_to_ticks`] returning
/// `true` (off-grid values snap to whole seconds) so the
/// integer-seconds invariant is enforced at every entry point:
/// typed input (`numeric`), displayed digits (`digits`), and
/// programmatic / external setters (`snap_to_ticks`).
///
/// Pinning the literal through this helper keeps the numeric flag
/// in one place shared by both `adw::SpinRow::set_numeric` calls
/// the `SettingsComponent` makes; the widget layer never duplicates
/// the literal. Sibling of
/// [`format_settings_dialog_spinner_climb_rate`],
/// [`format_settings_dialog_spinner_digits`],
/// [`format_settings_dialog_spinner_page_increment`],
/// [`format_settings_dialog_spinner_page_size`], and
/// [`format_settings_dialog_spinner_snap_to_ticks`] on the
/// `adw::SpinRow` property side; together they pin every
/// spinner-property literal the `SettingsComponent` sets beyond the
/// `gtk::Adjustment` bounds.
///
/// Pure — returns a `bool` without allocating.
#[must_use]
pub fn format_settings_dialog_spinner_numeric() -> bool {
    true
}

/// Fixed `bool` the widget passes to
/// [`adw::prelude::SpinRowExt::set_snap_to_ticks`] for both
/// `SettingsComponent` spinners per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
///
/// Returns `true` — `adw::SpinRow::snap-to-ticks` defaults to
/// `FALSE` in libadwaita: invalid intermediate values (typed
/// entries that do not land on a multiple of `step_increment`, or
/// values set programmatically by external setters / accessibility
/// tooling) are accepted as-is. The §4.7 settings the spinners
/// edit (`auto_lock_timeout_secs`, `clipboard_clear_secs`) are
/// `u32` seconds — every accepted value is an integer multiple of
/// the `1.0` step pinned by
/// [`format_settings_dialog_auto_lock_secs_adjustment`] /
/// [`format_settings_dialog_clipboard_clear_secs_adjustment`] — so
/// turning snap-to-ticks on enforces the integer-seconds grid at
/// the widget edge: any off-grid value (e.g. a programmatic
/// `set_value(30.5)` from a screen reader script, or a paste of
/// `30.5` into the entry buffer) snaps to the nearest whole second
/// before the spinner ever fires its `changed` signal.
///
/// Pairs with [`format_settings_dialog_spinner_digits`] returning
/// `0`: digits controls *display* (no trailing `.0` glyphs),
/// snap-to-ticks controls *value* (no fractional component
/// entering the model). Together they enforce the same integer
/// invariant on both sides of the spinner.
///
/// Pinning the literal through this helper keeps the snap-to-ticks
/// flag in one place shared by both `adw::SpinRow::set_snap_to_ticks`
/// calls the `SettingsComponent` makes; the widget layer never
/// duplicates the literal. Sibling of
/// [`format_settings_dialog_spinner_climb_rate`],
/// [`format_settings_dialog_spinner_digits`],
/// [`format_settings_dialog_spinner_page_increment`], and
/// [`format_settings_dialog_spinner_page_size`] on the
/// `adw::SpinRow` property side; together they pin every
/// spinner-property literal the `SettingsComponent` sets beyond the
/// `gtk::Adjustment` bounds.
///
/// Pure — returns a `bool` without allocating.
#[must_use]
pub fn format_settings_dialog_spinner_snap_to_ticks() -> bool {
    true
}

/// Fixed [`std::time::Duration`] the widget hands to
/// [`glib::timeout_add_local`] for the spinner debounce timer per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
/// "Preferences" and §"Component tree" > `SettingsComponent`.
///
/// Returns `Duration::from_millis(500)` — the §"Component tree"
/// `SettingsComponent` contract that "holding +/- does not fire
/// one save per click — the most recent buffered value is the one
/// that saves". Long enough that a multi-press burst coalesces
/// into a single `Vault::mutate_and_save`, short enough that a
/// paused user does not notice the save lag. The pure-logic
/// coalescing contract this duration arms is exercised by
/// [`SettingsState::stage_auto_lock_secs`] /
/// [`SettingsState::stage_clipboard_clear_secs`] +
/// [`SettingsState::resolve_debounce`]; this helper pins the
/// real-time interval the timer waits between the most recent
/// stage call and the resolve call.
///
/// Pinning the literal through this helper keeps the debounce
/// window in one place shared by the widget binding
/// (`glib::timeout_add_local(format_settings_dialog_spinner_debounce(), …)`)
/// and the pure-logic tests; the widget layer never duplicates
/// the literal. Returning a [`std::time::Duration`] (not a `u64`
/// millisecond count) matches the
/// [`glib::timeout_add_local`] argument type so the widget call
/// site does not need a conversion.
///
/// Pure — returns a [`std::time::Duration`] without allocating.
#[must_use]
pub fn format_settings_dialog_spinner_debounce() -> std::time::Duration {
    std::time::Duration::from_millis(500)
}

/// Classify the `Vault::mutate_and_save` typed result into the
/// [`SaveOutcome`] the `SettingsComponent` consumes.
///
/// Shared by [`SettingsState::apply_save_result`] (the in-process
/// path used in pure-logic tests) and [`run_settings_worker`] (the
/// `gio::spawn_blocking` path used by `AppModel`). Keeping the
/// `kind()`-based routing in one place per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Effect errors" ensures the dialog
/// and the worker stay in lock-step on which typed error maps to
/// `Rollback` vs `DurabilityWarning` vs `Inline`.
#[must_use]
pub fn classify_settings_save_result(
    change: AcceptedChange,
    result: Result<(), PaladinError>,
) -> SaveOutcome {
    match result {
        Ok(()) => SaveOutcome::Success,
        Err(err) if err.kind() == ErrorKind::SaveDurabilityUnconfirmed => {
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

/// Inputs consumed by [`run_settings_worker`].
///
/// Carries the live `(Vault, Store)` pair plus the typed
/// [`SettingPatch`] that triggered the dispatch. The worker
/// **always** returns the pair via
/// [`SettingsWorkerCompletion`] on every branch (success and typed
/// failure) so `AppModel::update` can reinstall it before applying
/// the UI outcome — `Vault::mutate_and_save` is authoritative for the
/// rollback / durability-unconfirmed semantics per docs/DESIGN.md §4.3.
///
/// `Clone` / `PartialEq` are deliberately not derived because
/// [`Vault`] and [`Store`] are non-`Clone`.
#[derive(Debug)]
pub struct SettingsWorkerInput {
    /// Live vault from the `Unlocked` `(Vault, Store)` pair. Moved
    /// into the worker so `mutate_and_save` can borrow it mutably
    /// without keeping `AppModel` in `Unlocked` for the duration of
    /// the save call.
    pub vault: Vault,
    /// Live store from the `Unlocked` `(Vault, Store)` pair. Moved
    /// alongside `vault` so the same `(Vault, Store)` pair returns
    /// from the worker even on typed failure.
    pub store: Store,
    /// Typed §5 patch forwarded from
    /// [`DebounceOutcome::Save`] / [`ToggleOutcome::Save`].
    /// `SettingPatch` derives `Copy`, so moving it through the worker
    /// closure does not consume the dispatch site's value.
    pub patch: SettingPatch,
}

/// Outcome of [`run_settings_worker`] for `AppModel::update` and the
/// live [`SettingsComponent`] controller to apply.
///
/// Routed to the dialog as [`SettingsDialogMsg::WorkerCompleted`] so
/// the typed [`SaveOutcome`] flows into
/// [`SettingsState::apply_save_outcome`]: success / durability-warning
/// promote the attempted value to the committed snapshot, rollback /
/// inline leave it unchanged. The [`AcceptedChange`] is carried
/// alongside the outcome because the worker no longer holds the
/// dialog's [`SettingsState`] and the dialog's
/// `apply_save_outcome` needs it to know which field to promote
/// (or which row to attach the error/warning to via [`SaveOutcome`]).
#[derive(Debug, Clone)]
pub struct SettingsWorkerEffect {
    /// The §5 setting that the worker attempted to commit, threaded
    /// through [`accepted_change_from_setting_patch`] off the input
    /// [`SettingPatch`].
    pub change: AcceptedChange,
    /// Typed routing for the dialog and the inline subtitle helpers.
    pub outcome: SaveOutcome,
}

/// Bundle returned by [`run_settings_worker`].
///
/// Carries the live `(Vault, Store)` pair on every branch so
/// `AppModel::update` can reinstall it via
/// `apply_settings_vault_install_inplace` before applying the UI
/// outcome — `Vault::mutate_and_save` already restores the snapshot
/// on `save_not_committed`, so the returned vault is the
/// authoritative post-effect state regardless of
/// [`SettingsWorkerEffect::outcome`]. Per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction" > "Every
/// worker returns `(Vault, Store, EffectOutcome)`".
///
/// `Clone` / `PartialEq` are deliberately not derived for the same
/// reason as on [`SettingsWorkerInput`].
#[derive(Debug)]
pub struct SettingsWorkerCompletion {
    /// Routed effect for `AppModel::update` and the live
    /// [`SettingsComponent`] controller to apply.
    pub effect: SettingsWorkerEffect,
    /// Live vault after the `mutate_and_save` call. On success the
    /// patch is applied; on rollback the snapshot is restored; on
    /// `save_durability_unconfirmed` the patch is applied but the
    /// parent-directory `fsync` failed.
    pub vault: Vault,
    /// Live store moved through unchanged so `AppModel::update` can
    /// reinstall the `(Vault, Store)` pair after the worker returns.
    pub store: Store,
}

/// Synchronous body of the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.apply_setting_patch(patch))` settings
/// worker fired by `AppModel::update` from
/// `AppMsg::SettingsDialogAction(SettingsDialogOutput::Submit)`.
///
/// Consumes the [`SettingsWorkerInput`] by value, runs
/// `vault.mutate_and_save(&store, |v| v.apply_setting_patch(patch))`,
/// and bundles the outcome into a [`SettingsWorkerCompletion`] via
/// [`classify_settings_save_result`]. The live `(Vault, Store)` pair
/// is always returned so `AppModel` reinstalls it regardless of the
/// typed effect — `mutate_and_save` is authoritative for the
/// rollback / durability-unconfirmed semantics per docs/DESIGN.md §4.3.
///
/// Extracting the worker body as a pure function lets
/// `AppModel::update`'s closure stay a thin
/// `gio::spawn_blocking(move || run_settings_worker(input))` while
/// the real `mutate_and_save` call stays unit-testable in
/// `tests/settings_logic.rs` against tempfile-backed plaintext
/// vaults — no GTK / libadwaita main loop required.
#[must_use]
pub fn run_settings_worker(input: SettingsWorkerInput) -> SettingsWorkerCompletion {
    let SettingsWorkerInput {
        mut vault,
        store,
        patch,
    } = input;
    let change = accepted_change_from_setting_patch(&patch);
    let result = vault.mutate_and_save(&store, |v| v.apply_setting_patch(patch));
    let outcome = classify_settings_save_result(change, result);
    SettingsWorkerCompletion {
        effect: SettingsWorkerEffect { change, outcome },
        vault,
        store,
    }
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
    last_outcome: Option<SaveOutcome>,
    /// Worker-in-flight latch flipped by
    /// [`SettingsDialogMsg::SetBusy`] from `AppModel` around the
    /// `gio::spawn_blocking Vault::mutate_and_save(|v|
    /// v.apply_setting_patch(...))` worker. While `true`, the
    /// toggle and spinner sensitivity helpers all return `false`
    /// so the user cannot kick off a second settings worker before
    /// the first returns the `(Vault, Store)` pair per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership".
    /// Independent of [`Self::pending`] (the staged spinner value)
    /// — `busy` is the pre-return latch.
    busy: bool,
}

impl SettingsState {
    /// Open the dialog on `committed` (snapshot from
    /// `Vault::settings()` via [`CommittedSettings::from_vault_settings`]).
    #[must_use]
    pub fn new(committed: CommittedSettings) -> Self {
        Self {
            committed,
            pending: None,
            last_outcome: None,
            busy: false,
        }
    }

    /// `true` while a `Vault::mutate_and_save` settings worker is
    /// in flight; flipped by [`SettingsDialogMsg::SetBusy`] from
    /// `AppModel`.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Parent-driven setter for the worker-in-flight latch.
    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
    }

    /// True iff a buffered spinner draft differs from the committed
    /// value — i.e., a save would actually fire if
    /// [`Self::resolve_debounce`] were called now.
    ///
    /// Used by [`dispatch_settings_dialog_msg`] on the
    /// `SetBusy(true → false)` edge so the dispatch can decide whether
    /// to re-arm the 500 ms debounce timer after a sibling vault
    /// effect returns. Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` line 4030
    /// ("Coalesce settings spinner debounce to the latest pre-save
    /// value when an effect is in flight"), the spinner draft must
    /// survive a busy window and eventually save — the post-busy
    /// re-arm is the path that wakes it.
    #[must_use]
    pub fn has_pending_save_due(&self) -> bool {
        match self.pending {
            Some(PendingSpinner::AutoLockSecs(v)) => v != self.committed.auto_lock_secs,
            Some(PendingSpinner::ClipboardClearSecs(v)) => v != self.committed.clipboard_clear_secs,
            None => false,
        }
    }

    /// Committed (on-disk) snapshot.
    #[must_use]
    pub fn committed(&self) -> &CommittedSettings {
        &self.committed
    }

    /// Last [`SaveOutcome`] reported by [`Self::apply_save_result`],
    /// or `None` if no worker reply has arrived yet for the open
    /// dialog (and `None` again after a fresh `stage_*` /
    /// `toggle_*` clears the slot — see those methods).
    ///
    /// The widget pairs this with the
    /// `compose_settings_dialog_inline_subtitle_*_for_field` family
    /// so a single `#[watch]` over [`SettingsState`] covers every
    /// row's body / visibility / CSS class. Sibling of
    /// [`Self::committed`] and [`Self::visible_auto_lock_secs`] /
    /// [`Self::visible_clipboard_clear_secs`] on the
    /// state-resident-projection side.
    #[must_use]
    pub fn last_outcome(&self) -> Option<&SaveOutcome> {
        self.last_outcome.as_ref()
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
    /// row's pending) and clears any resident
    /// [`Self::last_outcome`] so a prior inline error / durability
    /// warning does not linger beneath an unrelated typed retry.
    /// Returns the clamped value the widget should display.
    pub fn stage_auto_lock_secs(&mut self, raw: u32) -> u32 {
        let clamped = clamp_auto_lock_secs(raw);
        self.pending = Some(PendingSpinner::AutoLockSecs(clamped));
        self.last_outcome = None;
        clamped
    }

    /// Buffer a new `clipboard_clear_secs` spinner value. Replaces
    /// any prior pending entry and clears any resident
    /// [`Self::last_outcome`] (same reasoning as
    /// [`Self::stage_auto_lock_secs`]). Returns the clamped value.
    pub fn stage_clipboard_clear_secs(&mut self, raw: u32) -> u32 {
        let clamped = clamp_clipboard_clear_secs(raw);
        self.pending = Some(PendingSpinner::ClipboardClearSecs(clamped));
        self.last_outcome = None;
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
    /// Clears any resident [`Self::last_outcome`] before returning
    /// so a prior inline error / durability warning does not linger
    /// beneath the row while the user is acting again.
    pub fn toggle_auto_lock_enabled(&mut self, enabled: bool) -> ToggleOutcome {
        self.last_outcome = None;
        if enabled == self.committed.auto_lock_enabled {
            return ToggleOutcome::Noop;
        }
        ToggleOutcome::Save {
            patch: SettingPatch::AutoLockEnabled(enabled),
            field: SettingsField::AutoLockEnabled,
        }
    }

    /// Flip the `clipboard_clear_enabled` toggle. Toggles do not
    /// debounce. Clears any resident [`Self::last_outcome`] before
    /// returning (same reasoning as
    /// [`Self::toggle_auto_lock_enabled`]).
    pub fn toggle_clipboard_clear_enabled(&mut self, enabled: bool) -> ToggleOutcome {
        self.last_outcome = None;
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
    /// and leaves it unchanged on rollback / inline failure. Mirrors
    /// the typed outcome into [`Self::last_outcome`] so the inline-
    /// subtitle compose helpers
    /// (`compose_settings_dialog_inline_subtitle_*_for_field`) can
    /// read it back off `&SettingsState` without an extra widget-side
    /// cache.
    pub fn apply_save_result(
        &mut self,
        change: AcceptedChange,
        result: Result<(), PaladinError>,
    ) -> SaveOutcome {
        let outcome = classify_settings_save_result(change, result);
        self.apply_save_outcome(change, outcome.clone());
        outcome
    }

    /// Apply a [`SaveOutcome`] that was already classified by
    /// [`classify_settings_save_result`] — used by the
    /// `gio::spawn_blocking` worker dispatch path that ships the
    /// typed outcome back from `AppModel` via
    /// [`SettingsDialogMsg::WorkerCompleted`].
    ///
    /// Mirrors the back-half of [`Self::apply_save_result`]: promotes
    /// the attempted value to the committed snapshot for success /
    /// durability-warning branches, leaves it unchanged on rollback /
    /// inline branches, and stamps `last_outcome` so the
    /// `compose_settings_dialog_inline_subtitle_*_for_field` helpers
    /// can read the row-attached error / warning back off
    /// `&SettingsState` for the next `#[watch]` tick.
    pub fn apply_save_outcome(&mut self, change: AcceptedChange, outcome: SaveOutcome) {
        match outcome {
            SaveOutcome::Success | SaveOutcome::DurabilityWarning { .. } => {
                self.commit_attempted(change);
            }
            SaveOutcome::Rollback { .. } | SaveOutcome::Inline { .. } => {}
        }
        self.last_outcome = Some(outcome);
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

/// Construction parameters for [`SettingsComponent`].
///
/// The dialog opens on a snapshot of the current `paladin_core::VaultSettings`
/// (captured via [`CommittedSettings::from_vault_settings`] at the call site
/// in `AppModel`), so the component can seed its [`SettingsState`] without
/// holding a live `Vault` reference across the controller boundary.
#[derive(Debug, Clone)]
pub struct SettingsDialogInit {
    /// On-disk settings snapshot the dialog renders.
    pub settings: CommittedSettings,
    /// Per-user `gio::Settings` clone bound to
    /// [`crate::gsettings::SCHEMA_ID`].  Drives the "Display"
    /// `AdwPreferencesGroup`'s three `AdwSwitchRow`s
    /// (`Show section headers`, `Show column headers`,
    /// `Show next code`): the initial active state for each row is
    /// read from this instance, and each row's
    /// `connect_active_notify` writes back to it (firing the
    /// matching `changed::show-section-headers` /
    /// `changed::show-column-headers` /
    /// `changed::show-next-code-column` signal that `AppModel` has
    /// wired up to refresh the live `AccountListComponent`).
    pub app_settings: gio::Settings,
}

/// Messages handled by [`SettingsComponent`].
///
/// Toggle messages route through [`SettingsState::toggle_*`] and emit
/// `SettingsDialogOutput::Submit` immediately on a value change
/// (toggles never debounce). Spinner messages route through
/// [`SettingsState::stage_*`] and signal that the 500 ms debounce
/// timer should arm / re-arm. [`Self::DebounceTick`] fires when the
/// timer expires and routes through
/// [`SettingsState::resolve_debounce`] to either submit the pending
/// patch or stay idle. [`Self::WorkerCompleted`] consumes the typed
/// [`SettingsWorkerEffect`] from the AppModel-side worker dispatch.
#[derive(Debug, Clone)]
pub enum SettingsDialogMsg {
    /// Auto-lock toggle (`AdwSwitchRow`) flipped to `enabled`.
    AutoLockToggled(bool),
    /// Clipboard-clear toggle (`AdwSwitchRow`) flipped to `enabled`.
    ClipboardClearToggled(bool),
    /// Auto-lock timeout spinner (`AdwSpinRow`) was edited.
    AutoLockSecsSpinnerChanged(u32),
    /// Clipboard-clear timeout spinner (`AdwSpinRow`) was edited.
    ClipboardClearSecsSpinnerChanged(u32),
    /// 500 ms debounce timer fired. Routed through
    /// [`SettingsState::resolve_debounce`] to either consume the
    /// pending spinner draft (and submit it) or stay idle.
    DebounceTick,
    /// `gio::spawn_blocking` worker finished. Carries the typed
    /// [`SettingsWorkerEffect`] (the [`AcceptedChange`] the worker
    /// attempted to commit and the routed [`SaveOutcome`]) so the
    /// dialog promotes the visible value to committed on
    /// success / durability-warning, leaves it on rollback / inline,
    /// and stamps `last_outcome` so the inline-subtitle compose
    /// helpers can paint the row body / CSS class on the next
    /// `#[watch]` tick.
    WorkerCompleted(SettingsWorkerEffect),
    /// Parent-driven worker-in-flight latch.
    ///
    /// `AppModel::sync_settings_busy` emits `SetBusy(true)` when
    /// entering `AppState::UnlockedBusy` (with this dialog as the
    /// originating effect) and `SetBusy(false)` on the worker
    /// return, mirroring the add / edit / remove submit dimming
    /// pattern. The toggle and spinner sensitivity helpers consult
    /// the latch through [`SettingsState::is_busy`].
    SetBusy(bool),
}

/// Result of dispatching a [`SettingsDialogMsg`] through
/// [`dispatch_settings_dialog_msg`].
///
/// Extracted so the widget-side `update()` method stays a thin
/// `apply pure-logic transition + apply side effects` pair while the
/// pure-logic transition stays unit-testable in
/// `tests/settings_logic.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsDialogAction {
    /// Nothing further to do — the message has been absorbed into
    /// `SettingsState` (worker outcome promoted / no-op toggle / idle
    /// debounce tick / spinner staged but value unchanged).
    Noop,
    /// Spinner change buffered — the widget layer should arm or
    /// re-arm the 500 ms `glib::timeout_add_local` debounce timer so
    /// a [`SettingsDialogMsg::DebounceTick`] arrives in
    /// [`format_settings_dialog_spinner_debounce`].
    StageDebounce,
    /// A typed [`SettingPatch`] is ready to dispatch — the widget
    /// layer should emit
    /// [`SettingsDialogOutput::Submit`] to `AppModel` so the
    /// `gio::spawn_blocking` `Vault::mutate_and_save` worker fires.
    Submit(SettingPatch),
}

/// Pure-logic dispatch over [`SettingsDialogMsg`] for the
/// [`SettingsComponent`] update loop. Threads the state machine
/// (`stage_*` / `toggle_*` / `resolve_debounce` /
/// `apply_save_outcome`) under the message variants and returns the
/// side-effect decision the widget layer applies (timer arming,
/// `SettingsDialogOutput::Submit` emission, or noop).
pub fn dispatch_settings_dialog_msg(
    state: &mut SettingsState,
    msg: SettingsDialogMsg,
) -> SettingsDialogAction {
    match msg {
        SettingsDialogMsg::AutoLockToggled(enabled) => {
            // Refuse toggle changes that would overlap an active
            // vault effect (`docs/IMPLEMENTATION_PLAN_04_GTK.md` line 4030
            // and §"In-flight effect ownership"). The widget layer
            // dims the `AdwSwitchRow` via `set_sensitive: false` so
            // the user cannot reach this path under normal
            // interaction; this guard defends against a stray message
            // queued before the `#[watch]` dim tick takes effect.
            if state.is_busy() {
                return SettingsDialogAction::Noop;
            }
            match state.toggle_auto_lock_enabled(enabled) {
                ToggleOutcome::Noop => SettingsDialogAction::Noop,
                ToggleOutcome::Save { patch, .. } => SettingsDialogAction::Submit(patch),
            }
        }
        SettingsDialogMsg::ClipboardClearToggled(enabled) => {
            if state.is_busy() {
                return SettingsDialogAction::Noop;
            }
            match state.toggle_clipboard_clear_enabled(enabled) {
                ToggleOutcome::Noop => SettingsDialogAction::Noop,
                ToggleOutcome::Save { patch, .. } => SettingsDialogAction::Submit(patch),
            }
        }
        SettingsDialogMsg::AutoLockSecsSpinnerChanged(value) => {
            // Drop spinner edits arriving during a busy window so the
            // current save's committed-on-disk value is the latest
            // *pre-save* value, not a stray during-save value. The
            // widget is dimmed in this state; this guard catches the
            // pre-tick race.
            if state.is_busy() {
                return SettingsDialogAction::Noop;
            }
            state.stage_auto_lock_secs(value);
            SettingsDialogAction::StageDebounce
        }
        SettingsDialogMsg::ClipboardClearSecsSpinnerChanged(value) => {
            if state.is_busy() {
                return SettingsDialogAction::Noop;
            }
            state.stage_clipboard_clear_secs(value);
            SettingsDialogAction::StageDebounce
        }
        SettingsDialogMsg::DebounceTick => {
            // Coalesce the spinner debounce to the latest pre-save
            // value when a sibling vault effect is in flight: keep
            // the pending draft buffered and return Noop so the
            // widget neither submits nor re-arms a fresh timer. The
            // `SetBusy(true → false)` edge below re-arms when the
            // worker returns so the staged value eventually saves.
            if state.is_busy() {
                return SettingsDialogAction::Noop;
            }
            match state.resolve_debounce() {
                DebounceOutcome::Idle => SettingsDialogAction::Noop,
                DebounceOutcome::Save { patch, .. } => SettingsDialogAction::Submit(patch),
            }
        }
        SettingsDialogMsg::WorkerCompleted(SettingsWorkerEffect { change, outcome }) => {
            state.apply_save_outcome(change, outcome);
            SettingsDialogAction::Noop
        }
        SettingsDialogMsg::SetBusy(busy) => {
            // Parent-driven flag flip — `AppModel` brackets the
            // `gio::spawn_blocking
            // Vault::mutate_and_save(|v| v.apply_setting_patch(...))`
            // call with `SetBusy(true)` / `SetBusy(false)` so the
            // toggle / spinner sensitivity projectors dim the dialog
            // while the worker owns the live `(Vault, Store)` pair.
            //
            // On the `true → false` edge, if a spinner draft is still
            // buffered (a `DebounceTick` was dropped while busy, or a
            // pending value pre-dated the save), re-arm the 500 ms
            // debounce so the latest pre-save value eventually fires
            // a save — that is the coalescing path per
            // `docs/IMPLEMENTATION_PLAN_04_GTK.md` line 4030.
            let was_busy = state.is_busy();
            state.set_busy(busy);
            if was_busy && !busy && state.has_pending_save_due() {
                return SettingsDialogAction::StageDebounce;
            }
            SettingsDialogAction::Noop
        }
    }
}

/// Messages emitted by [`SettingsComponent`] for `AppModel` to consume.
///
/// `AppModel` forwards these into `AppMsg::SettingsDialogAction(...)`;
/// the `Close` arm drops the live `Controller<SettingsComponent>` so
/// the underlying `AdwPreferencesDialog` is torn down; the `Submit`
/// arm bundles a [`SettingsWorkerInput`] via
/// `compose_settings_worker_input` and dispatches the
/// `gio::spawn_blocking` `Vault::mutate_and_save` worker.
#[derive(Debug, Clone)]
pub enum SettingsDialogOutput {
    /// User dismissed the dialog (Close button / Escape / window
    /// close). `AppModel` responds by dropping the live controller
    /// so the dialog disappears and any in-flight pending spinner
    /// draft is discarded.
    Close,
    /// Toggle clicked or 500 ms debounce resolved with a pending
    /// spinner change. `AppModel` bundles this patch into a
    /// [`SettingsWorkerInput`] and spawns the
    /// `gio::spawn_blocking` `Vault::mutate_and_save` worker; the
    /// `AppMsg::SettingsWorkerCompleted` arm routes the typed
    /// [`SettingsWorkerEffect`] back through the dialog as
    /// [`SettingsDialogMsg::WorkerCompleted`].
    Submit(SettingPatch),
}

/// Widget-bearing `AdwPreferencesDialog` for the Preferences menu entry.
///
/// Mounts the libadwaita preferences surface described in docs/DESIGN.md §7
/// (`SettingsComponent`) and `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Component tree" > `SettingsComponent`. Two `AdwPreferencesGroup`
/// sections host an `AdwSwitchRow` toggle and an `AdwSpinRow` spinner
/// each (auto-lock + clipboard-clear); the values are driven by the
/// existing `compose_settings_dialog_*_active` /
/// `compose_settings_dialog_*_value` /
/// `compose_settings_dialog_*_sensitive` view helpers via `#[watch]`
/// bindings so a single source of truth ([`SettingsState`]) feeds the
/// widget surface.
///
/// The dialog stays mounted across every save — live-apply does not
/// close the surface on success — so the [`SettingsDialogOutput::Submit`]
/// arm runs through `AppModel`'s `gio::spawn_blocking` worker and the
/// returned [`SettingsWorkerEffect`] is forwarded back as
/// [`SettingsDialogMsg::WorkerCompleted`].
///
/// Spinner edits buffer through [`SettingsState::stage_auto_lock_secs`] /
/// [`SettingsState::stage_clipboard_clear_secs`] and arm the 500 ms
/// debounce timer via [`format_settings_dialog_spinner_debounce`].
/// Holding +/- coalesces to a single save with the most recent
/// buffered value per `docs/IMPLEMENTATION_PLAN_04_GTK.md` line 3456. A
/// `DebounceTick` that fires while a sibling vault effect is in
/// flight is absorbed by [`dispatch_settings_dialog_msg`] without
/// dropping the buffered draft, and the `SetBusy(true → false)` edge
/// re-arms the debounce so the latest pre-save value still reaches a
/// single `Vault::mutate_and_save` after the worker returns — the
/// "Coalesce settings spinner debounce to the latest pre-save value
/// when an effect is in flight" contract.
pub struct SettingsComponent {
    /// Live state machine seeded from [`SettingsDialogInit::settings`]
    /// in `init`. The pure-logic round-trip is asserted by
    /// `tests/settings_logic.rs`; the widget layer holds it behind
    /// the relm4 component so the `view!` macro's `#[watch]`
    /// bindings re-paint on every `dispatch_settings_dialog_msg`.
    state: SettingsState,
    /// Live `glib::timeout_add_local_once` source for the 500 ms
    /// spinner debounce. Stored as an `Option<SourceId>` so each
    /// fresh spinner change can drop the prior pending tick (via
    /// `SourceId::remove`) before scheduling a new one — keeping
    /// only the latest buffered value per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` line 3458.
    debounce_source: Option<glib::SourceId>,
    /// Per-user `gio::Settings` clone seeded from
    /// [`SettingsDialogInit::app_settings`].  Drives the
    /// "Display" group's three `AdwSwitchRow`s
    /// (section-headers, column-headers, and next-code-column):
    /// the initial active state for each row reads from this
    /// instance, and each row's `connect_active_notify` writes
    /// back through the matching
    /// [`crate::gsettings::set_show_section_headers`] /
    /// [`crate::gsettings::set_show_column_headers`] /
    /// [`crate::gsettings::set_show_next_code_column`] helper.
    app_settings: gio::Settings,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for SettingsComponent {
    type Init = SettingsDialogInit;
    type Input = SettingsDialogMsg;
    type Output = SettingsDialogOutput;

    view! {
        #[root]
        adw::PreferencesDialog {
            set_title: format_settings_dialog_title(),
            set_search_enabled: format_settings_dialog_search_enabled(),

            add = &adw::PreferencesPage {
                add = &adw::PreferencesGroup {
                    set_title: format_settings_dialog_auto_lock_group_title(),

                    #[name = "auto_lock_enabled_row"]
                    add = &adw::SwitchRow {
                        set_title: format_settings_dialog_auto_lock_enabled_row_title(),
                        #[watch]
                        set_active: compose_settings_dialog_auto_lock_enabled_active(&model.state),
                        #[watch]
                        set_sensitive: compose_settings_dialog_auto_lock_enabled_sensitive(
                            &model.state,
                        ),
                        // `Sender::send` is used instead of
                        // `ComponentSender::input` (which `.expect`s
                        // on a closed channel) so a stray callback
                        // after the controller is dropped — e.g.
                        // `lock_on_auto_lock_expiry` taking the
                        // dialog into `UnlockedDiscards.modal` — is
                        // a benign no-op rather than a process
                        // abort. See `import_dialog`'s Cancel
                        // button for the canonical comment.
                        connect_active_notify[sender] => move |row| {
                            let _ = sender
                                .input_sender()
                                .send(SettingsDialogMsg::AutoLockToggled(row.is_active()));
                        },
                    },

                    #[name = "auto_lock_secs_row"]
                    add = &adw::SpinRow {
                        set_title: format_settings_dialog_auto_lock_secs_row_title(),
                        set_adjustment: Some(&{
                            let (lower, upper, step) =
                                format_settings_dialog_auto_lock_secs_adjustment();
                            gtk::Adjustment::new(
                                compose_settings_dialog_auto_lock_secs_value(&model.state),
                                lower,
                                upper,
                                step,
                                format_settings_dialog_spinner_page_increment(),
                                format_settings_dialog_spinner_page_size(),
                            )
                        }),
                        set_climb_rate: format_settings_dialog_spinner_climb_rate(),
                        set_digits: format_settings_dialog_spinner_digits(),
                        set_wrap: format_settings_dialog_spinner_wrap(),
                        set_numeric: format_settings_dialog_spinner_numeric(),
                        set_snap_to_ticks: format_settings_dialog_spinner_snap_to_ticks(),
                        #[watch]
                        set_value: compose_settings_dialog_auto_lock_secs_value(&model.state),
                        #[watch]
                        set_sensitive: compose_settings_dialog_auto_lock_secs_sensitive(
                            &model.state,
                        ),
                        // See the auto-lock-enabled-row `connect_active_notify` comment.
                        connect_changed[sender] => move |spin| {
                            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                            let secs = spin.value() as u32;
                            let _ = sender
                                .input_sender()
                                .send(SettingsDialogMsg::AutoLockSecsSpinnerChanged(secs));
                        },
                    },
                },

                add = &adw::PreferencesGroup {
                    set_title: format_settings_dialog_display_group_title(),

                    #[name = "show_section_headers_row"]
                    add = &adw::SwitchRow {
                        set_title: format_settings_dialog_section_headers_row_title(),
                        set_subtitle: format_settings_dialog_section_headers_row_subtitle(),
                        set_active: crate::gsettings::show_section_headers(&model.app_settings),
                        connect_active_notify[app_settings_for_toggle] => move |row| {
                            let _ = crate::gsettings::set_show_section_headers(
                                &app_settings_for_toggle,
                                row.is_active(),
                            );
                        },
                    },

                    #[name = "show_column_headers_row"]
                    add = &adw::SwitchRow {
                        set_title: format_settings_dialog_column_headers_row_title(),
                        set_subtitle: format_settings_dialog_column_headers_row_subtitle(),
                        set_active: crate::gsettings::show_column_headers(&model.app_settings),
                        connect_active_notify[app_settings_for_column_toggle] => move |row| {
                            let _ = crate::gsettings::set_show_column_headers(
                                &app_settings_for_column_toggle,
                                row.is_active(),
                            );
                        },
                    },

                    #[name = "show_next_code_column_row"]
                    add = &adw::SwitchRow {
                        set_title: format_settings_dialog_next_code_column_row_title(),
                        set_subtitle: format_settings_dialog_next_code_column_row_subtitle(),
                        set_active:
                            crate::gsettings::show_next_code_column(&model.app_settings),
                        connect_active_notify[app_settings_for_next_code_column_toggle] =>
                            move |row| {
                                let _ = crate::gsettings::set_show_next_code_column(
                                    &app_settings_for_next_code_column_toggle,
                                    row.is_active(),
                                );
                            },
                    },
                },

                add = &adw::PreferencesGroup {
                    set_title: format_settings_dialog_clipboard_clear_group_title(),

                    #[name = "clipboard_clear_enabled_row"]
                    add = &adw::SwitchRow {
                        set_title:
                            format_settings_dialog_clipboard_clear_enabled_row_title(),
                        #[watch]
                        set_active: compose_settings_dialog_clipboard_clear_enabled_active(
                            &model.state,
                        ),
                        #[watch]
                        set_sensitive:
                            compose_settings_dialog_clipboard_clear_enabled_sensitive(
                                &model.state,
                            ),
                        // See the auto-lock-enabled-row `connect_active_notify` comment.
                        connect_active_notify[sender] => move |row| {
                            let _ = sender.input_sender().send(
                                SettingsDialogMsg::ClipboardClearToggled(row.is_active()),
                            );
                        },
                    },

                    #[name = "clipboard_clear_secs_row"]
                    add = &adw::SpinRow {
                        set_title: format_settings_dialog_clipboard_clear_secs_row_title(),
                        set_adjustment: Some(&{
                            let (lower, upper, step) =
                                format_settings_dialog_clipboard_clear_secs_adjustment();
                            gtk::Adjustment::new(
                                compose_settings_dialog_clipboard_clear_secs_value(&model.state),
                                lower,
                                upper,
                                step,
                                format_settings_dialog_spinner_page_increment(),
                                format_settings_dialog_spinner_page_size(),
                            )
                        }),
                        set_climb_rate: format_settings_dialog_spinner_climb_rate(),
                        set_digits: format_settings_dialog_spinner_digits(),
                        set_wrap: format_settings_dialog_spinner_wrap(),
                        set_numeric: format_settings_dialog_spinner_numeric(),
                        set_snap_to_ticks: format_settings_dialog_spinner_snap_to_ticks(),
                        #[watch]
                        set_value: compose_settings_dialog_clipboard_clear_secs_value(
                            &model.state,
                        ),
                        #[watch]
                        set_sensitive:
                            compose_settings_dialog_clipboard_clear_secs_sensitive(&model.state),
                        // See the auto-lock-enabled-row `connect_active_notify` comment.
                        connect_changed[sender] => move |spin| {
                            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                            let secs = spin.value() as u32;
                            let _ = sender.input_sender().send(
                                SettingsDialogMsg::ClipboardClearSecsSpinnerChanged(secs),
                            );
                        },
                    },
                },
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let state = SettingsState::new(init.settings);
        let model = SettingsComponent {
            state,
            debounce_source: None,
            app_settings: init.app_settings,
        };
        // Pre-clone the per-user `gio::Settings` so the `view!`
        // macro's `connect_active_notify[app_settings_for_toggle]`
        // capture has a sibling binding to clone into the closure.
        let app_settings_for_toggle = model.app_settings.clone();
        let app_settings_for_column_toggle = model.app_settings.clone();
        let app_settings_for_next_code_column_toggle = model.app_settings.clone();
        let widgets = view_output!();
        // Forward the dialog's intrinsic close signal (Escape /
        // window close button) as `SettingsDialogOutput::Close` so
        // `AppModel` drops the controller. `adw::Dialog` self-detaches
        // from its toplevel parent on close, so no explicit
        // `force_close` is needed.
        let close_sender = sender.output_sender().clone();
        root.connect_closed(move |_| {
            let _ = close_sender.send(SettingsDialogOutput::Close);
        });
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        let action = dispatch_settings_dialog_msg(&mut self.state, msg);
        match action {
            SettingsDialogAction::Noop => {}
            SettingsDialogAction::StageDebounce => {
                if let Some(source) = self.debounce_source.take() {
                    source.remove();
                }
                let send = sender.input_sender().clone();
                let source_id = glib::timeout_add_local_once(
                    format_settings_dialog_spinner_debounce(),
                    move || {
                        let _ = send.send(SettingsDialogMsg::DebounceTick);
                    },
                );
                self.debounce_source = Some(source_id);
            }
            SettingsDialogAction::Submit(patch) => {
                // A fresh save dispatch consumes the buffered spinner
                // draft; drop any pending debounce so a stale tick
                // does not double-fire after the worker returns.
                if let Some(source) = self.debounce_source.take() {
                    source.remove();
                }
                let _ = sender.output(SettingsDialogOutput::Submit(patch));
            }
        }
    }
}
