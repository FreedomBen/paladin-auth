// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-flight vault-effect ownership state machine for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership"
//! and §"Tests > Pure-logic unit tests >
//! `tests/effect_ownership_logic.rs`", the GTK `AppModel`
//! serializes every vault-touching blocking effect through one
//! `gio::spawn_blocking` worker at a time. While the worker holds
//! the `(Vault, Store)` pair, the model is in
//! [`AppState::UnlockedBusy`] and every mutating control surface
//! (row `next`, dialog submit buttons, passphrase actions, import
//! / export, settings) is disabled.
//!
//! This module owns the pure-logic shadow of that contract — it
//! tracks:
//!
//! * Which [`EffectKind`] is in flight, if any
//!   ([`EffectOwnership::current_effect`]).
//! * Whether quit / window-close requests have been deferred
//!   ([`EffectOwnership::pending_quit`]).
//! * Whether an auto-lock expiry landed while busy and is waiting
//!   on the worker return to decide if it actually fires
//!   ([`EffectOwnership::pending_lock`]).
//!
//! It deliberately does **not** own the `(Vault, Store)` pair
//! itself — the `AppModel` keeps that in an
//! `Option<(Vault, Store)>` and `take`s it for the worker on
//! [`EffectOwnership::start_effect`], restoring it on
//! [`EffectOwnership::complete_effect`]. The state machine here is
//! widget-free and `(Vault, Store)`-free so the integration tests
//! under `tests/effect_ownership_logic.rs` exercise the deferral /
//! gating / lock-after-effect rules without a real vault.

use crate::settings::SettingsField;

/// Identifies which vault-touching blocking effect is currently in
/// flight. Each variant corresponds to a worker the GTK `AppModel`
/// may dispatch via `gio::spawn_blocking`.
///
/// The state machine never inspects the variant beyond identifying
/// the *current* effect for telemetry / dialog routing — the
/// gating contract (all five mutating control surfaces off while
/// any effect is in flight) applies uniformly regardless of which
/// effect is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectKind {
    /// `Vault::hotp_advance` on a row `next` press.
    HotpAdvance,
    /// `AddAccountComponent` → `Vault::add` inside
    /// `Vault::mutate_and_save`.
    AddAccount,
    /// `RemoveDialog` → `Vault::remove` inside
    /// `Vault::mutate_and_save`.
    RemoveAccount,
    /// `RenameDialog` → `Vault::rename` inside
    /// `Vault::mutate_and_save`.
    RenameAccount,
    /// `ImportDialog` — `import` source ingest + atomic apply.
    Import,
    /// `ExportDialog` — `export` writer (vault read; no mutation
    /// post-write).
    Export,
    /// `SettingsComponent` — `apply_setting_patch` inside
    /// `Vault::mutate_and_save`.
    Settings,
    /// `PassphraseDialog` set sub-flow — `Vault::set_passphrase`.
    PassphraseSet,
    /// `PassphraseDialog` change sub-flow — `Vault::change_passphrase`.
    PassphraseChange,
    /// `PassphraseDialog` remove sub-flow — `Vault::remove_passphrase`.
    PassphraseRemove,
}

impl EffectKind {
    /// Short user-facing name for this effect, used by surfaces that
    /// render the effect in human-readable text (e.g. the
    /// `StartupErrorComponent` body when a worker panics or otherwise
    /// fails before returning the `(Vault, Store)` pair).
    ///
    /// Returns a `&'static str` without allocating. Pinned by
    /// `tests/effect_ownership_logic.rs::effect_kind_user_name_*` so
    /// the wording is grep-able and stable.
    #[must_use]
    pub fn user_name(&self) -> &'static str {
        match self {
            Self::HotpAdvance => "HOTP advance",
            Self::AddAccount => "add account",
            Self::RemoveAccount => "remove account",
            Self::RenameAccount => "rename account",
            Self::Import => "import",
            Self::Export => "export",
            Self::Settings => "settings save",
            Self::PassphraseSet => "passphrase set",
            Self::PassphraseChange => "passphrase change",
            Self::PassphraseRemove => "passphrase remove",
        }
    }
}

/// Top-level app state tracked by [`EffectOwnership`].
///
/// The state machine here only models the *unlocked* portion of
/// the `AppModel` lifecycle (idle / busy / lost-vault). The
/// `Locked` and `Missing` / `InitDialog` states are owned by other
/// surfaces and never share a vault-touching worker with this
/// state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Holds the `(Vault, Store)` pair; mutating controls enabled.
    Unlocked,
    /// Worker holds the `(Vault, Store)` pair; mutating controls
    /// disabled. Carries the in-flight [`EffectKind`] for
    /// telemetry / dialog routing.
    UnlockedBusy(EffectKind),
    /// Worker lost the `(Vault, Store)` pair before returning;
    /// `AppModel` routes to [`crate::startup_error::StartupErrorState`]
    /// which offers retry / quit. The in-memory vault state is not
    /// reconstructed here.
    StartupError,
}

/// Disabled / enabled flags for each mutating control surface.
///
/// `true` means *disabled* (greyed out, not accepting input);
/// `false` means *enabled*. The naming mirrors GTK's
/// `sensitive` property inverted — the widget binds
/// `!gating.<flag>` to `sensitive` so disabled surfaces also lose
/// keyboard focus.
// The plan checklist names exactly five mutating control surfaces
// (`row_next`, `dialog_submit`, `passphrase_actions`, `import_export`,
// `settings`). Each surface maps to a distinct `gtk::Widget::sensitive`
// binding, so a packed bitflag would obscure the binding sites and a
// nested struct would just rename the same five fields. Keep the
// per-surface bool fields as the plan documents them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlGating {
    /// `AccountRowComponent::next_button.sensitive = !row_next`.
    pub row_next: bool,
    /// `AdwDialog::submit_button.sensitive = !dialog_submit`
    /// across `AddAccountComponent`, `RemoveDialog`,
    /// `RenameDialog`, `ImportDialog`, `ExportDialog`.
    pub dialog_submit: bool,
    /// `PassphraseDialog::set/change/remove_button.sensitive =
    /// !passphrase_actions`.
    pub passphrase_actions: bool,
    /// Header-bar `Import…` / `Export…` menu entries' `enabled`
    /// state — both pinned to a single flag because they share
    /// the same effect-class (read + write the vault).
    pub import_export: bool,
    /// All [`SettingsField`] controls inside the
    /// `AdwPreferencesDialog` (`AdwSwitchRow` toggles + spinner
    /// rows). One flag covers the lot because settings live-apply
    /// always routes through a single worker class.
    pub settings: bool,
}

impl ControlGating {
    /// All five surfaces enabled (no flags set).
    #[must_use]
    pub fn all_enabled() -> Self {
        Self {
            row_next: false,
            dialog_submit: false,
            passphrase_actions: false,
            import_export: false,
            settings: false,
        }
    }

    /// All five surfaces disabled — the gating in effect during
    /// `UnlockedBusy` and `StartupError`.
    #[must_use]
    pub fn all_disabled_for_busy() -> Self {
        Self {
            row_next: true,
            dialog_submit: true,
            passphrase_actions: true,
            import_export: true,
            settings: true,
        }
    }

    /// `true` iff a [`SettingsField`] control should be greyed out
    /// right now. Pinned to [`Self::settings`]; exposed by name so
    /// the widget code reads intent over flag layout.
    #[must_use]
    pub fn settings_field_disabled(&self, _field: SettingsField) -> bool {
        self.settings
    }
}

/// Outcome of an attempted [`EffectOwnership::start_effect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectStart {
    /// State transitions from [`AppState::Unlocked`] to
    /// [`AppState::UnlockedBusy`]. Caller may move
    /// `(Vault, Store)` into the worker.
    Accepted,
    /// State was not [`AppState::Unlocked`] (another worker is in
    /// flight, or the app is in [`AppState::StartupError`]).
    /// Caller must not start a worker.
    Rejected,
}

/// Outcome of a [`EffectOwnership::complete_effect`] call.
///
/// In every variant the state machine has already transitioned
/// back to [`AppState::Unlocked`] before the variant is returned
/// — the plan §"In-flight effect ownership" requires that
/// `(Vault, Store)` be reinstalled *before* UI outcome handling on
/// both success and typed failure. The variant tells the `AppModel`
/// which lifecycle action to take next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteOutcome {
    /// No deferred actions. Caller resumes normal UI handling.
    Ready,
    /// A deferred lock fires now. The worker returned a vault that
    /// is still encrypted, so the pending auto-lock applies.
    LockNow,
    /// A deferred lock is silently discarded. The worker
    /// transitioned the vault to plaintext (e.g. `PassphraseRemove`)
    /// — auto-lock is a no-op on plaintext vaults so the pending
    /// expiry signal is dropped without firing.
    LockDiscarded,
    /// A deferred quit fires now. The app exits.
    QuitNow,
}

/// Outcome of an [`EffectOwnership::request_quit`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuitDecision {
    /// Quit immediately. The app was [`AppState::Unlocked`] (or
    /// [`AppState::StartupError`]; the `AppModel` still allows quit
    /// from the error surface).
    Now,
    /// Quit deferred until the worker returns. The flag is recorded
    /// on the state machine ([`EffectOwnership::pending_quit`]).
    Deferred,
}

/// Outcome of an [`EffectOwnership::auto_lock_expired`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockDecision {
    /// Lock now. The app was [`AppState::Unlocked`] and the vault
    /// was encrypted.
    Now,
    /// Lock deferred until the worker returns. The flag is recorded
    /// on the state machine ([`EffectOwnership::pending_lock`]); the
    /// completion-time gate decides whether it actually fires.
    Deferred,
    /// No-op. Auto-lock is a no-op on plaintext vaults (DESIGN §7),
    /// so an expiry signal arriving while the vault is plaintext is
    /// silently dropped.
    Ignored,
}

/// In-flight vault-effect ownership state machine.
///
/// See the module-level documentation for the full contract.
#[derive(Debug, Clone)]
pub struct EffectOwnership {
    state: AppState,
    pending_lock: bool,
    pending_quit: bool,
}

impl EffectOwnership {
    /// Construct a fresh `Unlocked` state machine. The `AppModel`
    /// creates one of these immediately after a successful
    /// `paladin_core::open` (plaintext path) or a successful
    /// `UnlockComponent` submit (encrypted path).
    #[must_use]
    pub fn unlocked() -> Self {
        Self {
            state: AppState::Unlocked,
            pending_lock: false,
            pending_quit: false,
        }
    }

    /// Current app state.
    #[must_use]
    pub fn state(&self) -> AppState {
        self.state
    }

    /// `true` while a vault-touching worker is in flight.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        matches!(self.state, AppState::UnlockedBusy(_))
    }

    /// The [`EffectKind`] currently in flight, or `None` when idle.
    #[must_use]
    pub fn current_effect(&self) -> Option<EffectKind> {
        match self.state {
            AppState::UnlockedBusy(kind) => Some(kind),
            _ => None,
        }
    }

    /// `true` iff an auto-lock expiry was deferred and is waiting
    /// on the worker return to fire.
    #[must_use]
    pub fn pending_lock(&self) -> bool {
        self.pending_lock
    }

    /// `true` iff a quit / window-close request was deferred and is
    /// waiting on the worker return to fire.
    #[must_use]
    pub fn pending_quit(&self) -> bool {
        self.pending_quit
    }

    /// Disabled / enabled flags for the five mutating control
    /// surfaces named in the plan checklist.
    ///
    /// All disabled while in [`AppState::UnlockedBusy`] or
    /// [`AppState::StartupError`]; all enabled while
    /// [`AppState::Unlocked`].
    #[must_use]
    pub fn control_gating(&self) -> ControlGating {
        match self.state {
            AppState::Unlocked => ControlGating::all_enabled(),
            AppState::UnlockedBusy(_) | AppState::StartupError => {
                ControlGating::all_disabled_for_busy()
            }
        }
    }

    /// Try to start a vault-touching worker. Accepted only when the
    /// state machine is in [`AppState::Unlocked`]; rejected if a
    /// worker is already in flight or the app has routed to
    /// [`AppState::StartupError`].
    ///
    /// On acceptance, the state machine transitions to
    /// [`AppState::UnlockedBusy`] carrying `effect`. The `AppModel`
    /// is responsible for actually moving the `(Vault, Store)`
    /// pair into the worker; the state machine does not own it.
    pub fn start_effect(&mut self, effect: EffectKind) -> EffectStart {
        if matches!(self.state, AppState::Unlocked) {
            self.state = AppState::UnlockedBusy(effect);
            EffectStart::Accepted
        } else {
            EffectStart::Rejected
        }
    }

    /// Worker returned with `(Vault, Store)` reinstalled.
    /// Transitions back to [`AppState::Unlocked`] (or stays in
    /// [`AppState::StartupError`] if a stale completion arrives
    /// after [`Self::worker_lost`]) and resolves deferred quit /
    /// lock flags.
    ///
    /// `vault_still_encrypted` is the on-return
    /// `Vault::is_encrypted()` reading — used to gate whether a
    /// deferred lock actually fires.
    pub fn complete_effect(&mut self, vault_still_encrypted: bool) -> CompleteOutcome {
        if matches!(self.state, AppState::StartupError) {
            // Defense in depth: a stale completion arriving after
            // worker_lost cannot resurrect Unlocked state. The
            // in-memory (V, S) is gone.
            self.pending_lock = false;
            self.pending_quit = false;
            return CompleteOutcome::Ready;
        }
        self.state = AppState::Unlocked;
        let quit = std::mem::take(&mut self.pending_quit);
        let lock = std::mem::take(&mut self.pending_lock);
        if quit {
            return CompleteOutcome::QuitNow;
        }
        if lock {
            return if vault_still_encrypted {
                CompleteOutcome::LockNow
            } else {
                CompleteOutcome::LockDiscarded
            };
        }
        CompleteOutcome::Ready
    }

    /// Worker failed to return the `(Vault, Store)` pair. Drops the
    /// in-memory vault state by routing to [`AppState::StartupError`]
    /// and clears the deferred quit / lock flags (the
    /// `StartupErrorComponent` offers its own retry / quit affordances
    /// that do not consult the prior pending flags).
    pub fn worker_lost(&mut self) {
        self.state = AppState::StartupError;
        self.pending_lock = false;
        self.pending_quit = false;
    }

    /// Quit / window-close request. Fires now when idle; deferred
    /// while busy.
    pub fn request_quit(&mut self) -> QuitDecision {
        if self.is_busy() {
            self.pending_quit = true;
            QuitDecision::Deferred
        } else {
            QuitDecision::Now
        }
    }

    /// Auto-lock expiry signal. `vault_is_encrypted` is the
    /// pre-effect on-disk mode (used to short-circuit a plaintext
    /// idle expiry to [`LockDecision::Ignored`]).
    ///
    /// While busy, the expiry is recorded as
    /// [`Self::pending_lock`] and resolved by
    /// [`Self::complete_effect`] against the post-worker mode.
    pub fn auto_lock_expired(&mut self, vault_is_encrypted: bool) -> LockDecision {
        if self.is_busy() {
            self.pending_lock = true;
            LockDecision::Deferred
        } else if vault_is_encrypted {
            LockDecision::Now
        } else {
            LockDecision::Ignored
        }
    }
}
