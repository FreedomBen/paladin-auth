// SPDX-License-Identifier: AGPL-3.0-or-later

//! Top-level `AppModel` state machine for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" and
//! §"Vault interaction", `AppModel` carries the resolved vault path
//! plus one of the lifecycle states tracked by [`AppState`]:
//!
//! * [`AppState::Missing`] — no vault file at the resolved path;
//!   `InitDialog` is shown.
//! * [`AppState::Locked`] — encrypted vault present; `UnlockComponent`
//!   is shown.
//! * [`AppState::Unlocked`] — vault is open and idle. The
//!   `AppModel` owns the `(Vault, Store)` pair next to this state
//!   machine in an `Option<(Vault, Store)>`.
//! * [`AppState::UnlockedBusy`] — a vault-touching worker holds the
//!   `(Vault, Store)` pair via `gio::spawn_blocking`. Mutating
//!   controls are disabled and quit / auto-lock requests are
//!   deferred per §"In-flight effect ownership".
//! * [`AppState::StartupError`] — `default_vault_path`, `inspect`,
//!   or a non-passphrase `open` failure routed `AppModel` to the
//!   non-mutating error surface (`StartupErrorComponent`).
//!
//! The state machine is widget-free and `(Vault, Store)`-free — the
//! `AppModel` keeps the live pair in a sibling `Option` and uses
//! these transition helpers to gate which dialog / screen is shown.
//! This split lets `tests/app_state_logic.rs` exercise the routing
//! and transition rules without spinning up GTK / libadwaita or
//! constructing a real vault file.
//!
//! # Startup routing
//!
//! Startup runs two probes in order. Each one returns an
//! `Option<AppState>` whose `Some` variant pins the state machine
//! directly and whose `None` variant tells the caller to proceed to
//! the next probe.
//!
//! * [`decide_state_from_path_resolution`] handles
//!   `paladin_auth_core::default_vault_path()`. `Ok(path)` returns `None`
//!   (proceed to inspect); `Err(_)` returns
//!   `Some(AppState::StartupError { path: None, .. })` because no
//!   path was resolved.
//! * [`decide_state_from_inspect`] handles
//!   `paladin_auth_core::inspect(path)`. The three `Ok` variants route to
//!   `Missing` / `Locked` / `None` (for `Plaintext`); `Err(_)`
//!   routes to `StartupError` tagged
//!   [`crate::startup_error::StartupErrorSource::Inspect`].
//!
//! Open failures arrive after `paladin_auth_core::open` returns; the
//! routing decision splits passphrase retries (which stay inline on
//! the `UnlockComponent` / `InitDialog` passphrase surface) from
//! every other failure (which transitions to `StartupError`).
//! [`decide_state_from_open_error`] returns an [`OpenErrorOutcome`]
//! the caller pattern-matches against.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use paladin_auth_core::{
    policy::auto_lock::IdlePolicy, Account, AccountEdit, AccountId, PaladinAuthError, Store,
    ValidatedAccount, Vault, VaultLock, VaultSettings, VaultStatus,
};

use crate::add_account::{
    AddAccountMsg, AddWorkerEffect, AddWorkerInput, QrWorkerEffect, QrWorkerInput,
};
use crate::destroy_dialog::{
    format_destroy_dialog_success_toast, format_destroy_dialog_vault_gone_toast, DestroyDialogMsg,
    DestroyWorkerEffect,
};
use crate::edit_dialog::{EditWorkerEffect, EditWorkerInput};
use crate::effect_ownership::{
    CompleteOutcome, EffectKind, EffectOwnership, EffectStart, LockDecision, QuitDecision,
};
use crate::export_dialog::{
    ExportDialogMsg, ExportOutcome, ExportSubmitPayload, ExportWorkerInput,
};
use crate::import_dialog::{ImportDialogMsg, ImportSubmitPayload, ImportWorkerInput, MergeOutcome};
use crate::passphrase_dialog::{
    format_passphrase_success_toast, PassphraseDialogMsg, PassphraseWorkerEffect,
    PassphraseWorkerInput, SubmitPayload as PassphraseSubmitPayload,
};
use crate::remove_dialog::{RemoveDialogMsg, RemoveWorkerEffect, RemoveWorkerInput};
use crate::settings::{
    AcceptedChange, SaveOutcome, SettingsDialogMsg, SettingsWorkerEffect, SettingsWorkerInput,
};
use crate::startup_error::{classify_open_error, OpenErrorRouting, StartupError};
use crate::unlock_dialog::{
    route_unlock_open_error, InlineError, UnlockDialogMsg, UnlockOpenRouting,
};

/// `AppModel` lifecycle state.
///
/// The five variants mirror the plan's §"Component tree" decision
/// tree. Each variant other than [`AppState::StartupError`] carries
/// the resolved vault path so the active surface (init / unlock /
/// list) can render its title bar and pass the path back to vault
/// effects. `StartupError` carries an `Option<PathBuf>` because
/// `default_vault_path` failures happen before any path is known.
#[derive(Debug, Clone)]
pub enum AppState {
    /// No vault file at `path`; `InitDialog` is the active surface.
    /// `InitDialog` is the only GTK surface that creates a vault —
    /// successful creation transitions to [`AppState::Unlocked`]
    /// carrying the same path.
    Missing {
        /// Resolved vault path.
        path: PathBuf,
    },
    /// Encrypted vault file at `path`; `UnlockComponent` is the
    /// active surface. A successful unlock transitions to
    /// [`AppState::Unlocked`].
    Locked {
        /// Resolved vault path.
        path: PathBuf,
    },
    /// Vault is open and idle. `AppModel` owns the `(Vault, Store)`
    /// pair in a sibling `Option`. Mutating controls are enabled.
    Unlocked {
        /// Resolved vault path.
        path: PathBuf,
    },
    /// A worker holds the `(Vault, Store)` pair on
    /// `gio::spawn_blocking` for the duration of a single
    /// vault-touching effect. Mutating controls are disabled per
    /// §"In-flight effect ownership"; quit / auto-lock requests are
    /// deferred until the worker returns and the pair is reinstalled.
    UnlockedBusy {
        /// Resolved vault path.
        path: PathBuf,
    },
    /// Non-mutating startup / open error surface
    /// (`StartupErrorComponent`). The `path` is `None` when the
    /// failure came from `default_vault_path` (before any path was
    /// resolved); otherwise it is the path that produced the
    /// failure so retry can re-run from the same target.
    StartupError {
        /// Path that produced the failure, or `None` when the
        /// failure came from path resolution itself.
        path: Option<PathBuf>,
        /// Rendered error projection (see
        /// [`crate::startup_error::StartupError`]).
        error: StartupError,
    },
}

impl AppState {
    /// Resolved vault path for the variants that carry one.
    ///
    /// Returns `None` only for [`AppState::StartupError`] variants
    /// whose `path` field is `None`. For every other variant — and
    /// for `StartupError { path: Some(_), .. }` — the resolved path
    /// is returned.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Missing { path }
            | Self::Locked { path }
            | Self::Unlocked { path }
            | Self::UnlockedBusy { path } => Some(path.as_path()),
            Self::StartupError { path, .. } => path.as_deref(),
        }
    }

    /// `true` only when the state holds a live `(Vault, Store)` pair
    /// or has just handed it to a worker — i.e.
    /// [`AppState::Unlocked`] and [`AppState::UnlockedBusy`].
    ///
    /// Other surfaces (`Missing` / `Locked` / `StartupError`) own
    /// no vault.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked { .. } | Self::UnlockedBusy { .. })
    }

    /// `true` only on [`AppState::UnlockedBusy`].
    ///
    /// Convenience predicate for control-gating sites that want to
    /// dim a button regardless of which effect is in flight.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::UnlockedBusy { .. })
    }

    /// `true` when mutating menu / header-bar entries are enabled.
    ///
    /// Per §"libadwaita usage": the `+` button and the Import /
    /// Export / Passphrase / Preferences entries are disabled when
    /// `AppModel` is not in `Unlocked` (so they are off in
    /// `Missing` / `Locked` / `StartupError`) and disabled while
    /// `UnlockedBusy` is active.
    #[must_use]
    pub fn allows_mutating_menu(&self) -> bool {
        matches!(self, Self::Unlocked { .. })
    }

    /// `true` when the *Delete Vault…* action / accelerator may fire.
    ///
    /// Per the `DestroyDialog` (Milestone 10) build order, vault
    /// deletion is reachable from every state that has a vault on
    /// disk to delete and no worker in flight: `Unlocked` (primary
    /// menu + `Ctrl+Shift+Delete`), `Locked` (the `UnlockComponent`
    /// footer link), and `StartupError` carrying a resolved path (the
    /// `StartupErrorView` footer link). It is disabled in `Missing`
    /// (no vault), in `UnlockedBusy` (a worker holds the pair), and in
    /// a path-less `StartupError` (the failure came from
    /// `default_vault_path`, so there is no target to destroy).
    #[must_use]
    pub fn allows_destroy_action(&self) -> bool {
        match self {
            Self::Unlocked { .. } | Self::Locked { .. } => true,
            Self::StartupError { path, .. } => path.is_some(),
            Self::Missing { .. } | Self::UnlockedBusy { .. } => false,
        }
    }

    /// Transition [`AppState::Unlocked`] → [`AppState::UnlockedBusy`]
    /// when a vault-touching worker takes the `(Vault, Store)` pair.
    ///
    /// Returns `None` from every other state — `Missing` / `Locked`
    /// / `StartupError` have no vault to hand off, and
    /// `UnlockedBusy` already serializes through one worker per
    /// §"In-flight effect ownership". The `Locked → UnlockedBusy`
    /// transition for the unlock open worker lives in the symmetric
    /// partner [`Self::enter_unlocking_busy`] so each typed
    /// transition documents its own source state.
    #[must_use]
    pub fn enter_busy(self) -> Option<Self> {
        match self {
            Self::Unlocked { path } => Some(Self::UnlockedBusy { path }),
            _ => None,
        }
    }

    /// Transition [`AppState::Locked`] → [`AppState::UnlockedBusy`]
    /// when the `gio::spawn_blocking paladin_auth_core::open` worker takes
    /// the submitted [`paladin_auth_core::VaultLock`].
    ///
    /// Symmetric partner of [`Self::enter_busy`] for the unlock path:
    /// where `enter_busy` covers the `Unlocked → UnlockedBusy`
    /// handoff for vault-touching mutations (which take the live
    /// `(Vault, Store)` pair), this method covers the
    /// `Locked → UnlockedBusy` handoff for the open worker (which is
    /// about to compute the pair). The two methods partition the
    /// idle source states — `enter_busy` only accepts `Unlocked`;
    /// this one only accepts `Locked` — so the `is_busy()` /
    /// `allows_mutating_menu()` gating already in place covers the
    /// open path alongside the post-unlock mutation path per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction".
    ///
    /// Returns `None` from every other state — `Missing` has no
    /// encrypted vault to open, `Unlocked` is owned by
    /// [`Self::enter_busy`], `UnlockedBusy` already serializes
    /// through one worker per §"In-flight effect ownership", and
    /// `StartupError` is the non-mutating surface.
    #[must_use]
    pub fn enter_unlocking_busy(self) -> Option<Self> {
        match self {
            Self::Locked { path } => Some(Self::UnlockedBusy { path }),
            _ => None,
        }
    }

    /// Transition [`AppState::UnlockedBusy`] → [`AppState::Unlocked`]
    /// when the worker returns the `(Vault, Store)` pair.
    ///
    /// Returns `None` from every other state. The plan §"In-flight
    /// effect ownership" requires that `(Vault, Store)` be
    /// reinstalled before UI outcome handling on both success and
    /// typed failure; the caller restores the pair onto its sibling
    /// `Option<(Vault, Store)>` immediately after this transition.
    #[must_use]
    pub fn leave_busy(self) -> Option<Self> {
        match self {
            Self::UnlockedBusy { path } => Some(Self::Unlocked { path }),
            _ => None,
        }
    }

    /// Transition [`AppState::UnlockedBusy`] → [`AppState::Locked`]
    /// when the `gio::spawn_blocking paladin_auth_core::open` worker
    /// returns a typed wrong-passphrase failure (`DecryptFailed`,
    /// `InvalidPassphrase`).
    ///
    /// Symmetric partner of [`Self::enter_unlocking_busy`] for the
    /// failure return path: the busy window that
    /// `enter_unlocking_busy` opens for the unlock worker is rolled
    /// back here so the dialog's passphrase entry becomes
    /// interactive again. Per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
    /// §"Effect errors", the live
    /// [`crate::unlock_dialog::UnlockDialogComponent`] stays mounted
    /// with the inline error so the user can retype without losing
    /// the surface; the dispatch trio
    /// ([`should_drop_unlock_dialog_after`],
    /// [`unlock_dialog_msg_after`], [`unlock_app_state_after`])
    /// reports the inline-message side, and this method owns the
    /// state-machine roll-back side so `is_busy()` /
    /// `allows_mutating_menu()` release the gate the moment the
    /// worker returns.
    ///
    /// Returns `None` from every other state — `Missing` has no
    /// encrypted vault to open, `Locked` has no busy window in
    /// flight, `Unlocked` has the live vault decrypted, and
    /// `StartupError` is the non-mutating surface. Sister method
    /// [`Self::leave_busy`] consumes the same `UnlockedBusy` source
    /// but lands on `Unlocked` for the success / mutation-completed
    /// path; the worker outcome picks which method `AppModel::update`
    /// calls.
    #[must_use]
    pub fn leave_unlocking_busy(self) -> Option<Self> {
        match self {
            Self::UnlockedBusy { path } => Some(Self::Locked { path }),
            _ => None,
        }
    }

    /// Transition [`AppState::Locked`] or [`AppState::Missing`] →
    /// [`AppState::Unlocked`] after a successful unlock / create.
    ///
    /// `Locked → Unlocked` is the post-`UnlockComponent` success
    /// path; `Missing → Unlocked` is the post-`InitDialog`
    /// success path (GTK is the only front end that creates a vault
    /// in-app). Returns `None` from every other state.
    #[must_use]
    pub fn into_unlocked(self) -> Option<Self> {
        match self {
            Self::Locked { path } | Self::Missing { path } => Some(Self::Unlocked { path }),
            _ => None,
        }
    }

    /// Transition [`AppState::Unlocked`] → [`AppState::Locked`] on
    /// an auto-lock expiry.
    ///
    /// Returns `None` from every other state. The plan
    /// §"In-flight effect ownership" requires that an auto-lock
    /// expiry arriving while `UnlockedBusy` is active be recorded
    /// as a lock-after-effect request rather than transitioning
    /// directly; this method enforces that by refusing the
    /// transition from `UnlockedBusy`.
    #[must_use]
    pub fn into_locked(self) -> Option<Self> {
        match self {
            Self::Unlocked { path } => Some(Self::Locked { path }),
            _ => None,
        }
    }
}

/// Routing decision for a `paladin_auth_core::open` failure.
///
/// Wrong-passphrase failures stay inline on the active passphrase
/// surface (`UnlockComponent` or the encrypted-create path of
/// `InitDialog`); every other failure transitions `AppModel` to
/// [`AppState::StartupError`].
#[derive(Debug, Clone)]
pub enum OpenErrorOutcome {
    /// Wrong / empty passphrase — surface inline at the active
    /// passphrase entry, do not transition state.
    InlinePassphrase,
    /// Non-authentication failure — transition `AppModel` to the
    /// non-mutating error surface.
    Startup(AppState),
}

/// Map a `paladin_auth_core::default_vault_path()` outcome onto an
/// optional initial [`AppState`].
///
/// * `Ok(path)` → `None` (proceed to `inspect`).
/// * `Err(_)` → `Some(AppState::StartupError { path: None, .. })`
///   tagged [`crate::startup_error::StartupErrorSource::PathResolution`].
#[must_use]
pub fn decide_state_from_path_resolution(
    resolution: Result<PathBuf, PaladinAuthError>,
) -> Option<AppState> {
    match resolution {
        Ok(_) => None,
        Err(err) => Some(AppState::StartupError {
            path: None,
            error: StartupError::from_path_resolution(&err),
        }),
    }
}

/// Map a `paladin_auth_core::inspect(path)` outcome onto an optional
/// initial [`AppState`].
///
/// * `Ok(VaultStatus::Missing)` → `Some(AppState::Missing)`.
/// * `Ok(VaultStatus::Encrypted)` → `Some(AppState::Locked)`.
/// * `Ok(VaultStatus::Plaintext)` → `None`. The caller follows up
///   with `paladin_auth_core::open(path, VaultLock::Plaintext)` on the
///   GTK main loop per §"Vault interaction".
/// * `Err(_)` → `Some(AppState::StartupError)` tagged
///   [`crate::startup_error::StartupErrorSource::Inspect`].
#[must_use]
pub fn decide_state_from_inspect(
    path: &Path,
    inspect: Result<VaultStatus, PaladinAuthError>,
) -> Option<AppState> {
    match inspect {
        Ok(VaultStatus::Missing) => Some(AppState::Missing {
            path: path.to_path_buf(),
        }),
        Ok(VaultStatus::Encrypted) => Some(AppState::Locked {
            path: path.to_path_buf(),
        }),
        Ok(VaultStatus::Plaintext) => None,
        Err(err) => Some(AppState::StartupError {
            path: Some(path.to_path_buf()),
            error: StartupError::from_inspect(&err),
        }),
    }
}

/// Classify a `paladin_auth_core::open` failure into an [`OpenErrorOutcome`].
///
/// Wrong passphrase (`DecryptFailed`, `InvalidPassphrase`) stays
/// inline on the active passphrase surface; every other failure
/// transitions `AppModel` to
/// `AppState::StartupError { path: Some(path), .. }` tagged
/// [`crate::startup_error::StartupErrorSource::Open`].
#[must_use]
pub fn decide_state_from_open_error(path: &Path, err: &PaladinAuthError) -> OpenErrorOutcome {
    match classify_open_error(err) {
        OpenErrorRouting::InlinePassphrase => OpenErrorOutcome::InlinePassphrase,
        OpenErrorRouting::Startup(startup) => OpenErrorOutcome::Startup(AppState::StartupError {
            path: Some(path.to_path_buf()),
            error: startup,
        }),
    }
}

/// Routing decision for a `paladin_auth_core::open` failure reported by
/// the future `gio::spawn_blocking` unlock worker fired by
/// [`crate::unlock_dialog::UnlockDialogComponent`].
///
/// Pairs with [`OpenErrorOutcome`] (used by `run_startup_probes` on
/// the plaintext-startup path) but carries the typed
/// [`crate::unlock_dialog::InlineError`] projection so `AppModel`'s
/// worker call site can dispatch
/// [`crate::unlock_dialog::UnlockDialogMsg::OpenFailedInline`]
/// directly without re-routing the typed `PaladinAuthError` here.
///
/// [`crate::unlock_dialog::route_unlock_open_error`] returns a unit
/// `Startup` variant because the resolved vault path is owned by
/// `AppModel`; this completion helper attaches the path to build
/// the full [`AppState::StartupError`] transition the caller can
/// install verbatim.
#[derive(Debug, Clone)]
pub enum UnlockFailureAction {
    /// Wrong / empty passphrase. Dispatch
    /// [`crate::unlock_dialog::UnlockDialogMsg::OpenFailedInline`]
    /// carrying the [`InlineError`] back to the live
    /// [`crate::unlock_dialog::UnlockDialogComponent`] so the user
    /// sees the inline error at the passphrase entry and re-types.
    /// `AppState` stays at [`AppState::Locked`] — the dialog
    /// surface itself remains mounted.
    SendInlineToDialog(InlineError),
    /// Non-passphrase open failure. Transition `AppModel` to the
    /// non-mutating [`AppState::StartupError`] surface, dropping
    /// the live [`crate::unlock_dialog::UnlockDialogComponent`].
    /// Carries the populated state with the resolved path attached
    /// and the error tagged
    /// [`crate::startup_error::StartupErrorSource::Open`].
    TransitionToStartup(AppState),
}

/// Complete the routing of an unlock-worker `paladin_auth_core::open`
/// failure by attaching the resolved vault path that `AppModel`
/// owns.
///
/// Combines [`crate::unlock_dialog::route_unlock_open_error`] with
/// the path so the worker call site stays a thin shell. Wrong-
/// passphrase failures (`DecryptFailed`, `InvalidPassphrase`)
/// return [`UnlockFailureAction::SendInlineToDialog`] carrying the
/// typed [`InlineError`] projection that
/// [`crate::unlock_dialog::route_unlock_open_error`] already built;
/// every other failure (`UnsafePermissions`, `WrongVaultLock`,
/// `InvalidHeader`, `InvalidPayload`, `UnsupportedFormatVersion`,
/// `KdfParamsOutOfBounds`, `IoError`) returns
/// [`UnlockFailureAction::TransitionToStartup`] carrying a fully-
/// constructed [`AppState::StartupError`] tagged
/// [`crate::startup_error::StartupErrorSource::Open`].
#[must_use]
pub fn decide_unlock_failure_action(path: &Path, err: &PaladinAuthError) -> UnlockFailureAction {
    match route_unlock_open_error(err) {
        UnlockOpenRouting::Inline(inline) => UnlockFailureAction::SendInlineToDialog(inline),
        UnlockOpenRouting::Startup => {
            UnlockFailureAction::TransitionToStartup(AppState::StartupError {
                path: Some(path.to_path_buf()),
                error: StartupError::from_open(err),
            })
        }
    }
}

/// Concrete effect `AppModel`'s update branch applies after
/// [`decide_unlock_failure_action`] returns a typed
/// [`UnlockFailureAction`].
///
/// Splits the typed action into the two side-effect shapes
/// `AppModel::update` needs to apply:
///
/// * [`UnlockFailureEffect::SendUnlockDialogMsg`] — forward a
///   [`crate::unlock_dialog::UnlockDialogMsg`] to the live
///   [`crate::unlock_dialog::UnlockDialogComponent`] controller via
///   its input channel. `AppState` stays at [`AppState::Locked`];
///   the dialog stays mounted; the inline error label flips on
///   through [`crate::unlock_dialog::apply_msg`]'s
///   [`crate::unlock_dialog::UnlockDialogMsg::OpenFailedInline`]
///   branch.
/// * [`UnlockFailureEffect::SetAppState`] — replace
///   `AppModel.state` with the carried state, drop the live
///   `UnlockDialogComponent` controller, and re-mount the active
///   surface (typically [`crate::startup_error::StartupErrorComponent`]
///   for the `AppState::StartupError` carried by
///   [`UnlockFailureAction::TransitionToStartup`]).
///
/// Pinned as a typed enum (rather than bubbling
/// [`UnlockFailureAction`] up to the update branch) so a future
/// effect — cancel, auto-lock, passphrase rotation — can be added
/// as an additional variant without an `_` catch-all in
/// `AppModel::update` swallowing it silently.
#[derive(Debug)]
pub enum UnlockFailureEffect {
    /// Forward this [`UnlockDialogMsg`] to the live
    /// [`crate::unlock_dialog::UnlockDialogComponent`] controller.
    /// `AppState` stays at [`AppState::Locked`].
    SendUnlockDialogMsg(UnlockDialogMsg),
    /// Replace `AppModel.state` with this new state and re-mount
    /// the active surface (drop the `UnlockDialogComponent`
    /// controller, mount [`crate::startup_error::StartupErrorComponent`]
    /// for the [`AppState::StartupError`] carried by
    /// [`UnlockFailureAction::TransitionToStartup`]).
    SetAppState(AppState),
}

/// Translate a typed [`UnlockFailureAction`] into the concrete
/// [`UnlockFailureEffect`] `AppModel`'s update branch applies.
///
/// Pulled out of `AppModel::update` so the per-variant decision —
/// [`UnlockFailureAction::SendInlineToDialog`] becomes a
/// [`UnlockDialogMsg::OpenFailedInline`] forward to the live
/// dialog; [`UnlockFailureAction::TransitionToStartup`] becomes an
/// [`AppState`] replacement — stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita
/// or constructing a real vault file. The typed `InlineError`
/// `decide_unlock_failure_action` already built survives the
/// translation byte-identical so the dialog renders the same §5
/// projection the router chose.
#[must_use]
pub fn apply_unlock_failure_action(action: UnlockFailureAction) -> UnlockFailureEffect {
    match action {
        UnlockFailureAction::SendInlineToDialog(inline) => {
            UnlockFailureEffect::SendUnlockDialogMsg(UnlockDialogMsg::OpenFailedInline(inline))
        }
        UnlockFailureAction::TransitionToStartup(state) => UnlockFailureEffect::SetAppState(state),
    }
}

/// Compose [`decide_unlock_failure_action`] and
/// [`apply_unlock_failure_action`] into the single entry point
/// `AppModel`'s future worker-error branch calls when the
/// `gio::spawn_blocking paladin_auth_core::open` worker returns an
/// `Err(PaladinAuthError)`.
///
/// Bypassing the intermediate [`UnlockFailureAction`] keeps
/// `AppModel::update` a thin shell: one call goes from the typed
/// `PaladinAuthError` directly to the concrete [`UnlockFailureEffect`]
/// the update path applies — forwarding a
/// [`UnlockDialogMsg::OpenFailedInline`] to the live
/// [`crate::unlock_dialog::UnlockDialogComponent`] for the wrong-
/// passphrase branch, or replacing `AppModel.state` with the
/// carried [`AppState::StartupError`] for every other open failure.
/// The intermediate helpers stay public so the pure-logic tests in
/// `tests/app_state_logic.rs` can pin the per-step decisions
/// independently.
#[must_use]
pub fn route_unlock_failure_effect(path: &Path, err: &PaladinAuthError) -> UnlockFailureEffect {
    apply_unlock_failure_action(decide_unlock_failure_action(path, err))
}

/// Decide the new [`AppState`] after the unlock worker reports an
/// `Ok((Vault, Store))` outcome.
///
/// The `gio::spawn_blocking paladin_auth_core::open` worker fired by
/// [`crate::unlock_dialog::UnlockDialogComponent`] on the encrypted
/// path returns the live `(Vault, Store)` pair on success.
/// `AppModel` installs the pair into its sibling
/// `Option<(Vault, Store)>` slot and replaces `AppModel.state` with
/// the value this helper returns. Mirrors
/// [`decide_unlock_failure_action`] on the failure branch so the
/// pure-logic transition rule stays pinned by
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita
/// or constructing a real vault file.
///
/// Returns [`AppState::Unlocked`] carrying the supplied vault path.
/// The unlock worker leaves [`AppState::Locked`] for
/// [`AppState::Unlocked`] directly — no [`AppState::UnlockedBusy`]
/// intermediate, because the worker is *producing* the
/// `(Vault, Store)` pair, not consuming an existing one. The
/// `UnlockedBusy` state is reserved for vault-touching effects fired
/// from the unlocked surface per §"In-flight effect ownership".
#[must_use]
pub fn decide_unlock_success_state(path: &Path) -> AppState {
    AppState::Unlocked {
        path: path.to_path_buf(),
    }
}

/// Concrete effect `AppModel`'s update branch applies after
/// [`decide_unlock_success_state`] decides the new [`AppState`].
///
/// Pinned as a typed enum (rather than bubbling a bare [`AppState`]
/// up to the update branch) so a future success-branch effect —
/// dropping the live [`crate::unlock_dialog::UnlockDialogComponent`]
/// controller, mounting the [`crate::account_list::AccountListComponent`]
/// controller, or installing the live `(Vault, Store)` pair into
/// `AppModel.vault` — can be added as an additional variant without
/// an `_` catch-all in `AppModel::update` swallowing it silently.
/// Mirrors [`UnlockFailureEffect`] on the failure branch so the two
/// sides of the unlock-worker dispatch present matching shapes to
/// the update path.
#[derive(Debug)]
pub enum UnlockSuccessEffect {
    /// Replace `AppModel.state` with this new state. `AppModel`'s
    /// update branch follows up by dropping the
    /// [`crate::unlock_dialog::UnlockDialogComponent`] controller
    /// and mounting the
    /// [`crate::account_list::AccountListComponent`] controller for
    /// the [`AppState::Unlocked`] carried here; the live
    /// `(Vault, Store)` pair returned by the worker is installed
    /// alongside this state into the sibling `AppModel.vault` slot.
    SetAppState(AppState),
}

/// Compose [`decide_unlock_success_state`] into the single entry
/// point `AppModel`'s future worker-success branch calls when the
/// `gio::spawn_blocking paladin_auth_core::open` worker returns an
/// `Ok((Vault, Store))`.
///
/// Mirrors [`route_unlock_failure_effect`] on the failure branch so
/// `AppModel::update` stays a thin shell on both worker outcomes:
/// one call goes from the resolved vault path directly to the
/// concrete [`UnlockSuccessEffect`] the update path applies —
/// replacing `AppModel.state` with the new [`AppState::Unlocked`].
/// The live `(Vault, Store)` pair the worker produced is installed
/// separately into the sibling `AppModel.vault` slot; this helper
/// owns only the state-machine transition so the routing rule stays
/// unit-testable in `tests/app_state_logic.rs` without spinning up
/// GTK / libadwaita or constructing a real vault file. The
/// intermediate [`decide_unlock_success_state`] helper stays public
/// so the per-step transition stays pinned independently.
#[must_use]
pub fn route_unlock_success_effect(path: &Path) -> UnlockSuccessEffect {
    UnlockSuccessEffect::SetAppState(decide_unlock_success_state(path))
}

/// Concrete effect `AppModel`'s update branch applies after the
/// `gio::spawn_blocking paladin_auth_core::open` unlock worker returns.
///
/// Wraps the success / failure halves into a single typed enum so the
/// worker callback in `AppModel::update` can dispatch on the unified
/// outcome with a single match. Mirrors the `Result<(Vault, Store),
/// PaladinAuthError>` shape the worker produces: `Success` carries the
/// existing [`UnlockSuccessEffect`] (state transition to
/// [`AppState::Unlocked`]); `Failure` carries the existing
/// [`UnlockFailureEffect`] (either an inline dialog message or a
/// transition to [`AppState::StartupError`]).
///
/// The variant boundary is explicit so a future success-branch effect
/// (drop dialog, mount account list, install `(Vault, Store)`) or
/// failure-branch effect (auto-lock cancellation, passphrase
/// rotation) can be added without an `_` catch-all in
/// `AppModel::update` swallowing the new dispatch silently.
#[derive(Debug)]
pub enum UnlockWorkerEffect {
    /// The worker returned `Ok((Vault, Store))`. `AppModel`'s update
    /// branch installs the live pair into the sibling
    /// `Option<(Vault, Store)>` slot separately; this variant only
    /// owns the state-machine transition piece.
    Success(UnlockSuccessEffect),
    /// The worker returned `Err(PaladinAuthError)`. The carried effect
    /// either keeps the dialog mounted with an inline error
    /// (wrong / empty passphrase) or transitions `AppModel` to the
    /// non-mutating [`AppState::StartupError`] surface.
    Failure(UnlockFailureEffect),
}

/// Unified dispatch for the `gio::spawn_blocking paladin_auth_core::open`
/// unlock worker outcome.
///
/// Wraps [`route_unlock_success_effect`] and
/// [`route_unlock_failure_effect`] so `AppModel::update` can fan out
/// from the worker's `Result` into the correct
/// [`UnlockWorkerEffect`] variant with a single call. The
/// `Ok(())` arm represents `Ok((Vault, Store))` from the worker — the
/// pure-logic dispatch only owns the state-machine transition, while
/// the live pair is installed separately into `AppModel.vault`. The
/// `Err(&PaladinAuthError)` arm forwards the typed error to
/// [`route_unlock_failure_effect`] so the inline-passphrase vs
/// startup-transition routing decision stays in one place.
///
/// The intermediate helpers stay public so the pure-logic tests in
/// `tests/app_state_logic.rs` can pin the per-step decisions
/// independently from this unified entry.
#[must_use]
pub fn route_unlock_worker_outcome(
    path: &Path,
    outcome: Result<(), &PaladinAuthError>,
) -> UnlockWorkerEffect {
    match outcome {
        Ok(()) => UnlockWorkerEffect::Success(route_unlock_success_effect(path)),
        Err(err) => UnlockWorkerEffect::Failure(route_unlock_failure_effect(path, err)),
    }
}

/// Bundled outcome of the `gio::spawn_blocking paladin_auth_core::open`
/// unlock worker.
///
/// The worker calls `paladin_auth_core::Store::open(path, lock)` which
/// returns `Result<(Vault, Store), PaladinAuthError>`. This struct fans
/// that out into the two pieces `AppModel::update` needs to apply
/// from a single [`crate::app::model::AppMsg`] dispatch:
///
/// * [`UnlockWorkerCompletion::effect`] drives the state-machine
///   transition (`UnlockedBusy` → `Unlocked` on success,
///   → `StartupError` on a non-passphrase failure, or the inline
///   rollback path that keeps the dialog mounted).
/// * [`UnlockWorkerCompletion::pair`] carries the live
///   `(Vault, Store)` pair on the `Ok` branch so `AppModel` can
///   install it into its sibling `Option<(Vault, Store)>` slot
///   before the success-side UI mounts the
///   [`crate::account_list::AccountListComponent`].
///
/// Both fields are owned values so the worker closure can `move`
/// them across the `gio::spawn_blocking` boundary without borrowing
/// into `AppModel`. `Clone` / `PartialEq` are deliberately *not*
/// derived: [`paladin_auth_core::Vault`] / [`paladin_auth_core::Store`] are
/// non-`Clone` (the live pair must move, not duplicate, to keep
/// zeroize-on-drop semantics intact), and the carried
/// [`UnlockWorkerEffect`] is consumed exactly once when
/// `AppModel::update` applies the dispatch.
#[derive(Debug)]
pub struct UnlockWorkerCompletion {
    /// Routed state-machine effect derived from the worker's open
    /// outcome by [`route_unlock_worker_outcome`].
    pub effect: UnlockWorkerEffect,
    /// Live `(Vault, Store)` pair on the success branch; `None` on
    /// every failure branch (both inline-passphrase rollback and
    /// startup-routed failures). `AppModel::update` installs the
    /// pair into its sibling `Option<(Vault, Store)>` slot when
    /// `Some(_)`.
    pub pair: Option<(Vault, Store)>,
}

/// Bundle the `Result<(Vault, Store), PaladinAuthError>` returned by
/// `paladin_auth_core::Store::open` into an [`UnlockWorkerCompletion`].
///
/// Symmetric partner of [`compose_unlock_worker_input`] on the exit
/// side of the open worker: that composer captures the
/// `(path, VaultLock)` the worker consumes, this composer bundles
/// the pair + routed effect the worker produces. Both keep the
/// worker closure thin — the closure does not need to hand-roll the
/// `Ok` / `Err` split or borrow into `AppModel` to translate the
/// open `Result` for [`route_unlock_worker_outcome`].
///
/// The routing rule itself is delegated to
/// [`route_unlock_worker_outcome`] so the per-error-kind decisions
/// stay in one place; this helper is shape-only over the worker
/// `Result`. The path is taken by reference so the caller (the
/// worker closure) keeps ownership for the dispatch message.
///
/// `outcome.Ok((vault, store))` is consumed by value because both
/// [`paladin_auth_core::Vault`] and [`paladin_auth_core::Store`] are non-
/// `Clone`; the live pair must move into the resulting
/// [`UnlockWorkerCompletion`] so zeroize-on-drop semantics survive
/// the `gio::spawn_blocking` boundary.
///
/// The composer stays shape-only — it inspects only the worker
/// `Result` discriminant — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` against real `(Vault, Store)` pairs
/// constructed via `paladin_auth_core::Store::create` over a tempfile
/// vault.
#[must_use]
pub fn route_unlock_open_completion(
    path: &Path,
    outcome: Result<(Vault, Store), PaladinAuthError>,
) -> UnlockWorkerCompletion {
    match outcome {
        Ok(pair) => UnlockWorkerCompletion {
            effect: route_unlock_worker_outcome(path, Ok(())),
            pair: Some(pair),
        },
        Err(err) => UnlockWorkerCompletion {
            effect: route_unlock_worker_outcome(path, Err(&err)),
            pair: None,
        },
    }
}

/// Decide whether `AppModel`'s update branch should drop the live
/// [`crate::unlock_dialog::UnlockDialogComponent`] controller after
/// applying the given [`UnlockWorkerEffect`].
///
/// The dispatch rule is shape-only — it inspects the typed
/// [`UnlockWorkerEffect`] variant without touching the carried path,
/// error projection, or state — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
///
/// The two outcomes that drop the dialog:
///
/// * [`UnlockWorkerEffect::Success`] — the worker decrypted the
///   vault. The dialog has done its job; `AppModel::update` follows
///   up by mounting the [`crate::account_list::AccountListComponent`]
///   controller and installing the live `(Vault, Store)` pair into
///   `AppModel.vault`.
/// * [`UnlockWorkerEffect::Failure`] carrying
///   [`UnlockFailureEffect::SetAppState`] — a non-passphrase open
///   failure (`UnsafePermissions`, `WrongVaultLock`, `InvalidHeader`,
///   `InvalidPayload`, `UnsupportedFormatVersion`,
///   `KdfParamsOutOfBounds`, `IoError`, …) routes to the
///   non-mutating [`crate::startup_error::StartupErrorComponent`]
///   surface per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Effect errors".
///   The dialog gets replaced by the startup-error component.
///
/// The one outcome that keeps the dialog mounted:
///
/// * [`UnlockWorkerEffect::Failure`] carrying
///   [`UnlockFailureEffect::SendUnlockDialogMsg`] — wrong
///   passphrase or empty passphrase. The user retypes without
///   losing the dialog surface, so `AppModel::update` forwards the
///   inline error to the still-mounted controller via
///   [`crate::unlock_dialog::UnlockDialogMsg::OpenFailedInline`].
#[must_use]
pub fn should_drop_unlock_dialog_after(effect: &UnlockWorkerEffect) -> bool {
    // Listed by explicit variant rather than `_` so a future
    // `UnlockWorkerEffect` / `UnlockFailureEffect` variant fails the
    // match exhaustively and forces an explicit drop decision here.
    match effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(_)) => false,
        UnlockWorkerEffect::Success(_)
        | UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(_)) => true,
    }
}

/// Extract the optional [`crate::unlock_dialog::UnlockDialogMsg`]
/// `AppModel`'s update branch should forward to the live
/// [`crate::unlock_dialog::UnlockDialogComponent`] controller after
/// applying the given [`UnlockWorkerEffect`].
///
/// Mirror of [`should_drop_unlock_dialog_after`]: the drop decision
/// reports whether the dialog goes away, this extractor reports
/// whether (and which) inline error message goes to the still-mounted
/// dialog. Across the full set of worker outcomes, the two are
/// inverses — a dialog message is available iff the dialog stays
/// mounted — so `AppModel::update` can apply both in lockstep without
/// re-deriving the partition.
///
/// The extraction is shape-only — it inspects the typed
/// [`UnlockWorkerEffect`] variant without touching the carried path,
/// error projection, or state — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
///
/// The one outcome that carries a dialog message:
///
/// * [`UnlockWorkerEffect::Failure`] carrying
///   [`UnlockFailureEffect::SendUnlockDialogMsg`] — wrong / empty
///   passphrase. The carried
///   [`crate::unlock_dialog::UnlockDialogMsg::OpenFailedInline`]
///   already wraps the [`crate::unlock_dialog::InlineError`]
///   projection built by [`crate::unlock_dialog::InlineError::from_error`],
///   so `AppModel::update` forwards it verbatim to the live controller.
///
/// The two outcomes that carry no dialog message:
///
/// * [`UnlockWorkerEffect::Success`] — the worker decrypted the
///   vault. The dialog is dropped, not messaged.
/// * [`UnlockWorkerEffect::Failure`] carrying
///   [`UnlockFailureEffect::SetAppState`] — a non-passphrase open
///   failure routes to the [`crate::startup_error::StartupErrorComponent`]
///   surface. The dialog is dropped, not messaged.
#[must_use]
pub fn unlock_dialog_msg_after(effect: &UnlockWorkerEffect) -> Option<&UnlockDialogMsg> {
    // Listed by explicit variant rather than `_` so a future
    // `UnlockWorkerEffect` / `UnlockFailureEffect` variant fails the
    // match exhaustively and forces an explicit extraction decision
    // here, in lockstep with `should_drop_unlock_dialog_after`.
    match effect {
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(msg)) => Some(msg),
        UnlockWorkerEffect::Success(_)
        | UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(_)) => None,
    }
}

/// Extract the optional [`AppState`] replacement `AppModel`'s update
/// branch should install after applying the given
/// [`UnlockWorkerEffect`].
///
/// Third leg of the unlock-worker dispatch trio alongside
/// [`should_drop_unlock_dialog_after`] (drop the dialog?) and
/// [`unlock_dialog_msg_after`] (forward an inline message?). Across
/// the full set of worker outcomes:
///
/// * [`UnlockWorkerEffect::Success`] — returns `Some(Unlocked)`. The
///   dialog is dropped and `AppModel` transitions from `Locked` /
///   `UnlockedBusy` to `Unlocked` carrying the resolved vault path.
///   The live `(Vault, Store)` pair is installed separately into
///   `AppModel.vault` by the worker callback.
/// * [`UnlockWorkerEffect::Failure`] carrying
///   [`UnlockFailureEffect::SetAppState`] — returns
///   `Some(StartupError)`. A non-passphrase open failure
///   (`UnsafePermissions`, `WrongVaultLock`, `InvalidHeader`,
///   `InvalidPayload`, `UnsupportedFormatVersion`,
///   `KdfParamsOutOfBounds`, `IoError`, …) replaces the dialog with
///   the non-mutating [`crate::startup_error::StartupErrorComponent`]
///   surface per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Effect errors".
/// * [`UnlockWorkerEffect::Failure`] carrying
///   [`UnlockFailureEffect::SendUnlockDialogMsg`] — returns `None`.
///   The dialog stays mounted with the inline error and `AppState`
///   is unchanged so the user can retype without losing the surface.
///
/// The extraction is shape-only — it inspects the typed
/// [`UnlockWorkerEffect`] variant without re-deriving the routing —
/// so the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita. The two invariants pinned by the cross-check tests
/// there:
///
/// * State-replacement presence equals
///   [`should_drop_unlock_dialog_after`] — the dialog is dropped iff
///   a new state is installed.
/// * State-replacement and inline dialog message are mutually
///   exclusive — every outcome carries one, the other, or neither,
///   but never both.
#[must_use]
pub fn unlock_app_state_after(effect: &UnlockWorkerEffect) -> Option<&AppState> {
    // Listed by explicit variant rather than `_` so a future
    // `UnlockWorkerEffect` / `UnlockFailureEffect` / `UnlockSuccessEffect`
    // variant fails the match exhaustively and forces an explicit
    // extraction decision here, in lockstep with the sibling
    // `should_drop_unlock_dialog_after` and `unlock_dialog_msg_after`
    // helpers.
    match effect {
        UnlockWorkerEffect::Success(UnlockSuccessEffect::SetAppState(state))
        | UnlockWorkerEffect::Failure(UnlockFailureEffect::SetAppState(state)) => Some(state),
        UnlockWorkerEffect::Failure(UnlockFailureEffect::SendUnlockDialogMsg(_)) => None,
    }
}

/// Decide the [`AppState`] transition when `AppModel::update`
/// receives [`crate::unlock_dialog::UnlockDialogOutput::SubmitLock`].
///
/// Symmetric partner of [`unlock_final_app_state`] for the entry
/// side of the open worker: where the final composer rolls
/// [`AppState::UnlockedBusy`] back to [`AppState::Locked`] (inline
/// branch) or installs `Unlocked` / `StartupError` (replacement
/// branches) after the worker returns, this composer covers the
/// `Locked → UnlockedBusy` handoff that opens the busy gate just
/// before the `gio::spawn_blocking paladin_auth_core::open` worker
/// spawns. Together the two composers bracket the busy window so
/// the [`AppState::is_busy`] / [`AppState::allows_mutating_menu`]
/// gating in [`AppState`] covers the full open worker lifetime per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction".
///
/// The helper is a name-the-entry-point wrapper over
/// [`AppState::enter_unlocking_busy`]: it returns
/// `Some(UnlockedBusy { path })` iff `current` is
/// `Locked { path }`, and `None` for every other source state
/// (`Missing`, `Unlocked`, `UnlockedBusy`, `StartupError`). The
/// `None` arm is the defensive case for a stray dispatch — a
/// `SubmitLock` that arrives from any other source state leaves
/// `AppModel` in place rather than installing a phantom
/// `UnlockedBusy` that would clobber the idle state.
///
/// The composer stays shape-only — it delegates the transition to
/// [`AppState::enter_unlocking_busy`] — so the side-effect decision
/// in `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
#[must_use]
pub fn submit_unlock_app_state(current: &AppState) -> Option<AppState> {
    current.clone().enter_unlocking_busy()
}

/// Decide the [`AppState`] transition when `AppModel::update`
/// receives the validated `AddAccountOutput::Submit{Manual,Uri}`
/// dispatch from `AddAccountComponent`.
///
/// Symmetric partner of [`submit_edit_app_state`] for the add
/// path: both helpers cover the `Unlocked → UnlockedBusy` handoff
/// for a `gio::spawn_blocking Vault::mutate_and_save(...)` worker
/// that consumes the already-decrypted `(Vault, Store)` pair. The
/// edit composer fires from
/// [`crate::edit_dialog::EditDialogOutput::Submit`]; this
/// one fires from the add dialog's manual / URI submit branch so
/// `AppModel::update` can serialize through one vault-touching
/// worker at a time per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Vault
/// interaction".
///
/// The helper is a name-the-entry-point wrapper over
/// [`AppState::enter_busy`]: it returns
/// `Some(UnlockedBusy { path })` iff `current` is
/// `Unlocked { path }`, and `None` for every other source state
/// (`Missing`, `Locked`, `UnlockedBusy`, `StartupError`). The
/// `None` arm is the defensive case for a stray dispatch — an add
/// submit that arrives from any other source state leaves
/// `AppModel` in place rather than installing a phantom
/// `UnlockedBusy` that would clobber the idle state.
///
/// The composer stays shape-only — it delegates the transition to
/// [`AppState::enter_busy`] — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
#[must_use]
pub fn submit_add_app_state(current: &AppState) -> Option<AppState> {
    current.clone().enter_busy()
}

/// Decide the [`AppState`] transition when `AppModel::update`
/// receives the validated [`crate::edit_dialog::EditDialogOutput::Submit`]
/// dispatch from [`crate::edit_dialog::EditDialogComponent`].
///
/// Symmetric partner of [`submit_add_app_state`] for the edit
/// path: both cover `Unlocked → UnlockedBusy` (the worker takes the
/// already-decrypted `(Vault, Store)` pair through
/// `Vault::mutate_and_save`), differing only in the dispatch origin
/// (`EditDialogOutput::Submit` vs `AddAccountOutput::Submit{Manual,Uri}`).
///
/// The helper is a name-the-entry-point wrapper over
/// [`AppState::enter_busy`]: it returns `Some(UnlockedBusy { path })`
/// iff `current` is `Unlocked { path }`, and `None` for every other
/// source state (`Missing`, `Locked`, `UnlockedBusy`,
/// `StartupError`). The `None` arm is the defensive case for a stray
/// dispatch — an edit submit that arrives from any other source
/// state leaves `AppModel` in place rather than installing a phantom
/// `UnlockedBusy`.
///
/// The composer stays shape-only — it delegates the transition to
/// [`AppState::enter_busy`] — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
#[must_use]
pub fn submit_edit_app_state(current: &AppState) -> Option<AppState> {
    current.clone().enter_busy()
}

/// Bundle the live `(Vault, Store)` pair and the
/// [`crate::edit_dialog::EditDialogOutput::Submit`] payload into an
/// [`EditWorkerInput`] for the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.edit_account_metadata(...))` worker.
///
/// Symmetric partner of [`compose_add_worker_input`] on the edit
/// path: where the add composer captures the live
/// `(Vault, Store)` pair plus the validated [`Account`], this
/// composer captures the live
/// `(Vault, Store)` pair plus the account id, the assembled
/// [`AccountEdit`], and the dispatch-site wall-clock. Both composers
/// inspect `current` before the busy-gate transition so the source
/// state is verified before [`submit_edit_app_state`] consumes the
/// variant per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Vault
/// interaction".
///
/// Returns `Ok(EditWorkerInput)` iff `current` is
/// [`AppState::Unlocked`]. The `Err((vault, store))` branch is the
/// defensive case for a stray dispatch from any other source state
/// (`Missing` / `Locked` / `UnlockedBusy` / `StartupError`): the
/// non-`Clone` live `(Vault, Store)` pair would be lost if the
/// composer dropped it, so it is handed back so the caller can
/// reinstall it into `AppModel.vault` rather than leaking the
/// unlocked state. The contract mirrors the `Some` / `None`
/// agreement with [`submit_edit_app_state`] — both helpers return
/// success iff the source is `Unlocked`.
///
/// The composer stays shape-only — it inspects only the variant
/// discriminant on `current` — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` against real `(Vault, Store)` pairs
/// constructed via `paladin_auth_core::Store::create` over a tempfile
/// vault.
pub fn compose_edit_worker_input(
    current: &AppState,
    pair: (Vault, Store),
    account_id: AccountId,
    edit: AccountEdit,
    now: SystemTime,
) -> Result<EditWorkerInput, (Vault, Store)> {
    match current {
        AppState::Unlocked { .. } => {
            let (vault, store) = pair;
            Ok(EditWorkerInput {
                vault,
                store,
                account_id,
                edit,
                now,
            })
        }
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => Err(pair),
    }
}

/// Bundle the live `(Vault, Store)` pair and the validated
/// [`paladin_auth_core::Account`] payload from
/// [`crate::add_account::classify_manual_submit`] /
/// [`crate::otpauth_uri_paste::classify_uri_submit`] into an
/// [`AddWorkerInput`] for the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.add(account))` worker.
///
/// Symmetric partner of [`compose_edit_worker_input`] on the add
/// path: where the edit composer captures the live
/// `(Vault, Store)` pair plus the
/// [`crate::edit_dialog::EditDialogOutput::Submit`] payload
/// (account id, assembled [`AccountEdit`], dispatch-site wall-clock)
/// for the edit worker, this composer captures the live `(Vault, Store)`
/// pair plus the validated `Account` extracted from the
/// `AddAccountOutput::Submit{Manual,Uri}` dispatch for the add
/// worker. Both composers inspect `current` before the busy-gate
/// transition so the source state is verified before
/// [`submit_add_app_state`] consumes the variant. Together they
/// bracket every typed dispatch with a documented source-state
/// contract per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction".
///
/// Returns `Ok(AddWorkerInput)` iff `current` is
/// [`AppState::Unlocked`]. The `Err((vault, store))` branch is the
/// defensive case for a stray dispatch from any other source state
/// (`Missing` / `Locked` / `UnlockedBusy` / `StartupError`): the
/// non-`Clone` live `(Vault, Store)` pair would be lost if the
/// composer dropped it, so it is handed back so the caller can
/// reinstall it into `AppModel.vault` rather than leaking the
/// unlocked state. The `Account` payload itself is dropped on the
/// `Err` branch — it carries no filesystem state and the dialog
/// still owns the reactive copy for re-rendering if the dispatch
/// was unexpected. The contract mirrors the `Ok` / `Err` agreement
/// with [`compose_edit_worker_input`] and the `Some` / `None`
/// agreement with [`submit_add_app_state`] — all three helpers
/// return success iff the source is `Unlocked`.
///
/// The composer stays shape-only — it inspects only the variant
/// discriminant on `current` — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` against real `(Vault, Store)` pairs
/// constructed via `paladin_auth_core::Store::create` over a tempfile
/// vault.
pub fn compose_add_worker_input(
    current: &AppState,
    pair: (Vault, Store),
    account: Account,
) -> Result<AddWorkerInput, (Vault, Store)> {
    match current {
        AppState::Unlocked { .. } => {
            let (vault, store) = pair;
            Ok(AddWorkerInput {
                vault,
                store,
                account,
            })
        }
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => Err(pair),
    }
}

/// Compose the [`QrWorkerInput`] payload for the clipboard-QR add
/// path's `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.import_accounts(...))` worker.
///
/// Symmetric partner of [`compose_add_worker_input`] on the QR sub-
/// path. Where the manual / URI add path submits a single
/// [`Account`] through [`AddWorkerInput`], the clipboard-QR sub-
/// path submits a batch — `paladin_auth_core::import::qr_image_bytes`
/// returns `Vec<ValidatedAccount>` regardless of QR count, and the
/// worker merges them under
/// [`crate::qr_clipboard::CLIPBOARD_QR_CONFLICT_POLICY`].
///
/// The composer captures the live `(Vault, Store)` pair plus the
/// decoded accounts and the `import_time` stamp the dialog read
/// when it requested the clipboard scan (so a long worker queue
/// cannot stamp a stale `updated_at` for any replaced row if a
/// future caller swaps the policy off `Skip`). It gates on the
/// pre-transition source state (`Unlocked` only — the QR worker
/// consumes the already-decrypted pair) so `AppModel::update` can
/// call this composer before `submit_add_app_state` consumes the
/// variant.
///
/// `compose_qr_worker_input` returns `Result<QrWorkerInput,
/// (Vault, Store)>` rather than `Option` because the
/// `(Vault, Store)` pair is non-`Clone` and represents live
/// unlocked state — dropping it on a stray dispatch would lose the
/// user's open vault. The `Err((vault, store))` branch returns the
/// pair so the caller can put it back in `AppModel.vault`. The
/// `Vec<ValidatedAccount>` payload is dropped on the refusal arm
/// (no filesystem state attached) and the secret bytes inside each
/// `Account` zeroize on drop via `Zeroize` so a refused dispatch
/// does not leak the decoded payloads.
///
/// Stays widget-free and `gio::spawn_blocking`-free — the
/// `(Vault, Store)` pair lives in `AppModel`'s sibling
/// `Option<(Vault, Store)>` slot and the `AppState` cache is just a
/// discriminant on `current` — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` against real `(Vault, Store)` pairs
/// constructed via `paladin_auth_core::Store::create` over a tempfile
/// vault.
pub fn compose_qr_worker_input(
    current: &AppState,
    pair: (Vault, Store),
    accounts: Vec<ValidatedAccount>,
    import_time: SystemTime,
) -> Result<QrWorkerInput, (Vault, Store)> {
    match current {
        AppState::Unlocked { .. } => {
            let (vault, store) = pair;
            Ok(QrWorkerInput {
                vault,
                store,
                accounts,
                import_time,
            })
        }
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => Err(pair),
    }
}

/// Unified state-transition composer for the clipboard-QR add worker
/// outcome.
///
/// Symmetric partner of [`add_final_app_state`] for the QR sub-path.
/// Both Add sub-paths share the same `Unlocked → UnlockedBusy →
/// Unlocked` busy-gate lifecycle because they both consume the live
/// `(Vault, Store)` pair through `Vault::mutate_and_save`. Every
/// [`QrWorkerEffect`] variant — `Success(ImportReport)` from a
/// successful `import_accounts` merge and `Failure(AddPostEffectOutcome)`
/// for the `save_not_committed` / `save_durability_unconfirmed` /
/// defensive `validation_error` / `invalid_state` projections —
/// lands on the same `UnlockedBusy → Unlocked` rollback via
/// [`AppState::leave_busy`]. The dialog-drop / inline-message
/// decisions split off the typed effect in sibling composers; this
/// composer owns only the state-machine roll-back.
///
/// `effect` is accepted for signature symmetry with
/// [`add_final_app_state`] (and so a future routing refinement can
/// branch on it without changing call sites) but is not inspected:
/// the QR worker reinstalls the live `(Vault, Store)` pair through
/// [`apply_add_vault_install_inplace`] regardless of effect, so the
/// state machine returns to `Unlocked` uniformly. The dialog drop /
/// inline-message / counts-panel routing handled elsewhere is what
/// differs across effects.
///
/// Returns `Some(Unlocked { path })` iff `current` is
/// [`AppState::UnlockedBusy`], and `None` from every other state.
/// The `None` arm is the defensive case for a stray completion: a
/// QR completion arriving while `current` is not `UnlockedBusy` must
/// not silently install a phantom `Unlocked` over another idle
/// state.
///
/// The composer is shape-only — it delegates to
/// [`AppState::leave_busy`] without re-deriving the transition — so
/// the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
#[must_use]
pub fn qr_final_app_state(current: &AppState, _effect: &QrWorkerEffect) -> Option<AppState> {
    current.clone().leave_busy()
}

/// Drop-decision projection for the [`crate::add_account::AddAccountComponent`]
/// after a clipboard-QR worker outcome.
///
/// Symmetric partner of [`should_drop_add_dialog_after`] for the QR
/// sub-path. Diverges from the manual / URI add path on `Success`:
/// where the manual / URI flow drops the dialog after a successful
/// add (the new row appears in the visible list and there is nothing
/// more to show), the QR sub-path keeps the dialog mounted so the
/// counts panel can render the `imported` / `skipped` / `warning`
/// numbers parked by
/// [`crate::qr_clipboard::QrImportSummary::from_report`]. The failure
/// projections (`AddPostEffectOutcome::Inline` for
/// `save_not_committed` / `io_error` / defensive `validation_error`
/// / `invalid_state` and `KeepWithWarning` for
/// `save_durability_unconfirmed`) also keep the dialog mounted so
/// the inline error / durability warning is visible and the user
/// can retry or acknowledge — same contract as the manual / URI
/// failure branches.
///
/// The projection therefore returns `false` for every typed
/// [`QrWorkerEffect`] variant. The "stay mounted" rule across
/// success and failure is what lets the dialog continue to serve as
/// the user's surface for both the counts panel and the inline
/// error / durability warning without needing a separate post-
/// success popup.
///
/// The projection inspects only the typed [`QrWorkerEffect`]
/// variant — it does not consult [`AppState`], the live
/// `(Vault, Store)` pair, or any
/// [`crate::add_account::AddAccountComponent`] state — so the
/// side-effect decision in `AppModel::update` stays unit-testable
/// in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
#[must_use]
pub fn should_drop_add_dialog_after_qr(_effect: &QrWorkerEffect) -> bool {
    false
}

/// List-refresh projection after a clipboard-QR worker outcome.
///
/// Symmetric partner of [`should_refresh_list_after_add`] for the QR
/// sub-path. Both pivot on whether the vault is committed-or-
/// uncertain (refresh) versus rolled-back (no refresh):
///
/// * [`QrWorkerEffect::Success`] → `true`. The import committed and
///   the merged accounts must surface in the list. Mirrors the
///   manual / URI add path's `Success` arm.
/// * [`QrWorkerEffect::Failure`] with
///   [`crate::add_account::AddPostEffectOutcome::Inline`] → `false`.
///   `Vault::mutate_and_save` rolled back to the pre-attempt
///   snapshot (or never mutated for the defensive
///   `validation_error` / `invalid_state` branches); the visible
///   rows already match the post-rollback state.
/// * [`QrWorkerEffect::Failure`] with
///   [`crate::add_account::AddPostEffectOutcome::KeepWithWarning`]
///   → `true`. Primary save succeeded so the merged accounts are
///   durable in memory; the list must surface them even though the
///   parent fsync was uncertain.
///
/// The projection inspects only the typed [`QrWorkerEffect`]
/// variant — it does not consult [`AppState`], the live
/// `(Vault, Store)` pair, or any
/// [`crate::add_account::AddAccountComponent`] state — so the
/// side-effect decision in `AppModel::update` stays unit-testable
/// in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
#[must_use]
pub fn should_refresh_list_after_qr(effect: &QrWorkerEffect) -> bool {
    match effect {
        QrWorkerEffect::Success(_) => true,
        QrWorkerEffect::Failure(outcome) => match outcome {
            crate::add_account::AddPostEffectOutcome::KeepWithWarning(_) => true,
            crate::add_account::AddPostEffectOutcome::Inline(_) => false,
        },
    }
}

/// Inline-message projection for the live
/// [`crate::add_account::AddAccountComponent`] after a clipboard-QR
/// worker outcome.
///
/// Symmetric partner of [`add_dialog_msg_after`] for the QR sub-
/// path. Diverges from the manual / URI add path on `Success`:
/// where the manual / URI flow returns `None` (the dialog is being
/// dropped, so there is no controller to forward to), the QR sub-
/// path returns `Some(AddAccountMsg::QrSuccess(summary))` so the
/// counts panel can render the post-merge counts inside the still-
/// mounted dialog. The carried [`crate::qr_clipboard::QrImportSummary`]
/// is the [`QrImportSummary::from_report`] projection of the worker's
/// [`paladin_auth_core::ImportReport`].
///
/// On every Failure branch the projection returns
/// `Some(AddAccountMsg::WorkerFailed(outcome.clone()))` so the
/// dialog can re-render the typed
/// [`crate::add_account::AddPostEffectOutcome`] (`Inline` for
/// `save_not_committed` / `io_error` / defensive `validation_error`
/// / `invalid_state` and `KeepWithWarning` for
/// `save_durability_unconfirmed`) — same contract as the manual /
/// URI failure branches because the dialog stays mounted on every
/// failure.
///
/// The projection returns an *owned* [`Option<AddAccountMsg>`]
/// rather than a borrow into the effect because [`QrWorkerEffect`]
/// carries the [`paladin_auth_core::ImportReport`] /
/// [`crate::add_account::AddPostEffectOutcome`] payloads rather
/// than a pre-built dialog message. The clone is cheap — the
/// summary is three `usize` counts and the outcome only holds an
/// [`crate::add_account::InlineError`] /
/// [`crate::add_account::InlineWarning`] of a stable
/// [`paladin_auth_core::ErrorKind`] and a `String` body.
///
/// `dialog_msg.is_some()` is always `true` for the QR sub-path
/// because the dialog stays mounted on every effect — pinned in
/// `tests/app_state_logic.rs` so the dispatch composer can rely on
/// the invariant without re-deriving it.
#[must_use]
pub fn qr_dialog_msg_after(effect: &QrWorkerEffect) -> Option<AddAccountMsg> {
    match effect {
        QrWorkerEffect::Success(report) => Some(AddAccountMsg::QrSuccess(
            crate::qr_clipboard::QrImportSummary::from_report(report),
        )),
        QrWorkerEffect::Failure(outcome) => Some(AddAccountMsg::WorkerFailed(outcome.clone())),
    }
}

/// Bundled `AppModel::update` instructions for a clipboard-QR
/// worker completion. Carries the four decisions the existing
/// sibling projections derive ([`qr_final_app_state`],
/// [`qr_dialog_msg_after`], [`should_drop_add_dialog_after_qr`], and
/// [`should_refresh_list_after_qr`]) so the dispatch site can apply
/// the worker outcome in a single shot without re-routing the
/// [`QrWorkerEffect`].
///
/// Symmetric partner of [`AddDispatch`] for the QR sub-path. The
/// shape diverges from [`AddDispatch`] on two points:
///
/// * `dialog_msg` is `Some(_)` on every typed effect (not just
///   `Failure`) because the QR sub-path keeps the dialog mounted on
///   `Success` to render the counts panel via
///   [`AddAccountMsg::QrSuccess`]. The manual / URI add path drops
///   the dialog on `Success` and therefore has no message to
///   forward; the QR sub-path always forwards a message.
/// * `success_toast` is intentionally absent. The counts panel
///   parked by `QrSuccess(summary)` inside the still-mounted dialog
///   is the surface for the post-merge counts (per
///   `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR
///   clipboard image path" > "Surface post-merge counts … inline
///   (parity with §6)"). A separate `AdwToast` would be redundant.
///
/// `app_state` keeps the same `Option<AppState>` shape as
/// [`AddDispatch`] (the busy gate always releases on
/// [`AppState::UnlockedBusy`] and is `None` from every other source
/// state to avoid installing a phantom rollback on a stray
/// dispatch). `drop_dialog` is always `false` for QR (the dialog
/// stays mounted on every effect) but the field is preserved for
/// shape parity with the sibling dispatches.
#[derive(Debug, Clone)]
pub struct QrDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some` for
    /// the `UnlockedBusy → Unlocked` rollback that
    /// [`qr_final_app_state`] returns regardless of typed effect
    /// (the QR worker always rolls the busy gate back because
    /// `Vault::mutate_and_save` is authoritative for the rollback /
    /// durability-unconfirmed semantics per docs/DESIGN.md §4.3).
    /// `None` is the defensive case where the worker outcome
    /// arrives but `current` is not [`AppState::UnlockedBusy`] —
    /// `AppModel::update` leaves the state untouched rather than
    /// installing a phantom `Unlocked` over another idle state.
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::add_account::AddAccountComponent`] controller.
    /// `Some(AddAccountMsg::QrSuccess(summary))` on `Success` so the
    /// counts panel renders the post-merge counts, and
    /// `Some(AddAccountMsg::WorkerFailed(outcome))` on every
    /// `Failure` branch (the dialog stays mounted and re-renders
    /// the typed outcome — `Inline` for `save_not_committed` /
    /// `io_error` / defensive `validation_error` / `invalid_state`
    /// and `KeepWithWarning` for `save_durability_unconfirmed`).
    pub dialog_msg: Option<AddAccountMsg>,
    /// Whether `AppModel::update` should drop the live
    /// [`crate::add_account::AddAccountComponent`] controller after
    /// applying [`Self::app_state`]. Always `false` for the QR sub-
    /// path because the dialog stays mounted on every effect; the
    /// field is kept for shape parity with [`AddDispatch`] /
    /// [`RemoveDispatch`] / [`AddDispatch`] and so a future
    /// routing refinement can flip it without changing the
    /// dispatch shape at the call site.
    pub drop_dialog: bool,
    /// Whether `AppModel::update` should re-project rows off the
    /// freshly reinstalled `(Vault, Store)` pair and emit
    /// [`crate::account_list::AccountListMsg::Refresh`] so newly
    /// merged accounts appear in the visible row set. Mirrors
    /// [`should_refresh_list_after_qr`] — `true` on `Success` and
    /// `KeepWithWarning` (both leave the merged accounts in
    /// memory), `false` on the `Inline` failure branches (where
    /// the vault is unchanged so the visible rows already match
    /// disk).
    pub refresh_list: bool,
}

/// Bundle the four QR-dispatch decisions into a single
/// [`QrDispatch`] result so `AppModel::update` can apply the worker
/// outcome in one shot.
///
/// Symmetric partner of [`compose_add_dispatch`] for the QR sub-
/// path. The composer is a pure aggregator over the existing
/// projections — it never re-derives the routing:
///
/// * `app_state` mirrors [`qr_final_app_state`], which is the
///   `UnlockedBusy → Unlocked` rollback for every typed effect
///   (the QR worker always rolls the busy gate back, regardless of
///   typed outcome).
/// * `dialog_msg` mirrors [`qr_dialog_msg_after`], which returns
///   `Some(AddAccountMsg::QrSuccess(summary))` on `Success` and
///   `Some(AddAccountMsg::WorkerFailed(outcome))` on every
///   `Failure` branch. The bundled message is owned so it outlives
///   the borrow on `effect`.
/// * `drop_dialog` mirrors [`should_drop_add_dialog_after_qr`]
///   (always `false`).
/// * `refresh_list` mirrors [`should_refresh_list_after_qr`].
///
/// The same invariants pinned at the projection level carry
/// through:
///
/// * `dialog_msg.is_some()` is always `true` because the dialog
///   stays mounted on every effect — diverges from
///   [`compose_add_dispatch`] which returns `None` on `Success`
///   (the manual / URI add path drops the dialog).
/// * `app_state.is_some()` iff `current` is
///   [`AppState::UnlockedBusy`]. For the defensive branch from a
///   non-`UnlockedBusy` source state (a stray dispatch),
///   `app_state` is `None` while the other three fields still
///   mirror the projections. `AppModel::update` leaves the source
///   state in place rather than installing a phantom rollback.
///
/// The composer stays shape-only — it delegates to the sibling
/// projections without inspecting the typed [`QrWorkerEffect`]
/// variant itself — so `tests/app_state_logic.rs` exercises the
/// dispatch contract without spinning up GTK / libadwaita.
#[must_use]
pub fn compose_qr_dispatch(current: &AppState, effect: &QrWorkerEffect) -> QrDispatch {
    QrDispatch {
        app_state: qr_final_app_state(current, effect),
        dialog_msg: qr_dialog_msg_after(effect),
        drop_dialog: should_drop_add_dialog_after_qr(effect),
        refresh_list: should_refresh_list_after_qr(effect),
    }
}

/// Apply [`submit_unlock_app_state`] in-place to `state`, leaving
/// it unchanged when the composer returns `None`.
///
/// `AppModel::update`'s
/// [`crate::unlock_dialog::UnlockDialogOutput::SubmitLock`] handler
/// holds the cached [`AppState`] behind `&mut AppState`; this
/// wrapper bridges the owned-`self` [`AppState::enter_unlocking_busy`]
/// contract underlying `submit_unlock_app_state` to the mut-reference
/// call site so the handler does not have to manage a take-and-
/// restore dance around `submit_unlock_app_state`'s
/// `Option<AppState>` return.
///
/// Returns `true` when the state actually transitioned (source was
/// `Locked` → destination is `UnlockedBusy`), `false` otherwise.
/// `AppModel::update` uses the `true` return to gate the
/// `gio::spawn_blocking paladin_auth_core::open` worker spawn — a `false`
/// return is the defensive no-op for a stray `SubmitLock` from any
/// non-`Locked` source state (`Missing`, `Unlocked`, `UnlockedBusy`,
/// `StartupError`).
///
/// The wrapper stays shape-only — it delegates to
/// `submit_unlock_app_state` without re-deriving the transition —
/// so the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
pub fn apply_submit_unlock_inplace(state: &mut AppState) -> bool {
    if let Some(new_state) = submit_unlock_app_state(state) {
        *state = new_state;
        true
    } else {
        false
    }
}

/// Apply [`submit_edit_app_state`] in-place to `state`, leaving it
/// unchanged when the composer returns `None`.
///
/// Symmetric partner of [`apply_submit_add_inplace`] for the edit
/// path: both cover `Unlocked → UnlockedBusy` (the worker takes the
/// already-decrypted `(Vault, Store)` pair through
/// `Vault::mutate_and_save`), but they bridge different dispatch
/// origins. `apply_submit_add_inplace` fires from
/// [`crate::add_account::AddAccountOutput::Submit{Manual,Uri}`]; this
/// wrapper fires from [`crate::edit_dialog::EditDialogOutput::Submit`].
/// Both bridge the owned-`self` [`AppState::enter_busy`] contract to
/// the mut-reference call site so `AppModel::update`'s
/// `EditDialogOutput::Submit` handler does not have to manage a
/// take-and-restore dance around `submit_edit_app_state`'s
/// `Option<AppState>` return.
///
/// Returns `true` when the state actually transitioned (source was
/// `Unlocked` → destination is `UnlockedBusy`), `false` otherwise.
/// `AppModel::update` uses the `true` return to gate the
/// `gio::spawn_blocking Vault::mutate_and_save(|v|
/// v.edit_account_metadata(...))` worker spawn — a `false` return is
/// the defensive no-op for a stray `Submit` from any non-`Unlocked`
/// source state (`Missing`, `Locked`, `UnlockedBusy`,
/// `StartupError`).
///
/// The wrapper stays shape-only — it delegates to
/// [`submit_edit_app_state`] without re-deriving the transition — so
/// the side-effect decision in `AppModel::update` stays unit-testable
/// in `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
pub fn apply_submit_edit_inplace(state: &mut AppState) -> bool {
    if let Some(new_state) = submit_edit_app_state(state) {
        *state = new_state;
        true
    } else {
        false
    }
}

/// Apply [`submit_add_app_state`] in-place to `state`, leaving it
/// unchanged when the composer returns `None`.
///
/// Symmetric partner of [`apply_submit_edit_inplace`] for the add
/// path: both cover `Unlocked → UnlockedBusy` (the worker takes the
/// already-decrypted `(Vault, Store)` pair through
/// `Vault::mutate_and_save`), but they bridge different dispatch
/// origins. `apply_submit_edit_inplace` fires from
/// [`crate::edit_dialog::EditDialogOutput::Submit`]; this
/// wrapper fires from
/// [`crate::add_account::AddAccountOutput::Submit{Manual,Uri}`]. Both
/// bridge the owned-`self` [`AppState::enter_busy`] contract to the
/// mut-reference call site so `AppModel::update`'s
/// `AddAccountOutput::Submit{Manual,Uri}` handler does not have to
/// manage a take-and-restore dance around `submit_add_app_state`'s
/// `Option<AppState>` return.
///
/// Returns `true` when the state actually transitioned (source was
/// `Unlocked` → destination is `UnlockedBusy`), `false` otherwise.
/// `AppModel::update` uses the `true` return to gate the
/// `gio::spawn_blocking Vault::mutate_and_save(|v| v.add(account))`
/// worker spawn — a `false` return is the defensive no-op for a
/// stray `Submit{Manual,Uri}` from any non-`Unlocked` source state
/// (`Missing`, `Locked`, `UnlockedBusy`, `StartupError`).
///
/// The wrapper stays shape-only — it delegates to
/// `submit_add_app_state` without re-deriving the transition — so
/// the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
pub fn apply_submit_add_inplace(state: &mut AppState) -> bool {
    if let Some(new_state) = submit_add_app_state(state) {
        *state = new_state;
        true
    } else {
        false
    }
}

/// Unified state-transition composer for the unlock worker outcome.
///
/// [`unlock_app_state_after`] reports the new [`AppState`] for the
/// two state-replacing branches (success → `Unlocked`,
/// startup-routed failure → `StartupError`) and `None` for the
/// inline-passphrase branch (the dialog stays mounted). The inline
/// branch leaves `AppModel` in [`AppState::UnlockedBusy`] — set by
/// [`AppState::enter_unlocking_busy`] before the worker spawned —
/// so `AppModel::update` must roll the busy window back to
/// [`AppState::Locked`] via [`AppState::leave_unlocking_busy`] to
/// release the busy gate and let the dialog's passphrase entry
/// become interactive again.
///
/// This composer hides that asymmetry behind a single call:
///
/// * For the two replacement branches, it returns
///   `Some(replacement.clone())` directly from
///   [`unlock_app_state_after`] — `current` is not consulted
///   because the new state replaces outright.
/// * For the inline branch, it delegates to
///   `current.clone().leave_unlocking_busy()` so the busy window
///   rolls back to `Locked(path)` while preserving the resolved
///   path.
///
/// The `Some` / `None` return matches the
/// [`AppState::leave_unlocking_busy`] contract: `None` is reserved
/// for the defensive case where the inline branch fires but
/// `current` is not [`AppState::UnlockedBusy`]. A stray call from
/// any other source state refuses to install a phantom `Locked`
/// transition that would clobber another idle state —
/// `AppModel::update` is expected to call this from the
/// worker-completion handler where `current` is always
/// [`AppState::UnlockedBusy`].
///
/// The composer is shape-only — it inspects the typed
/// [`UnlockWorkerEffect`] variant via [`unlock_app_state_after`]
/// without re-deriving the routing, and it delegates the rollback
/// to [`AppState::leave_unlocking_busy`] — so the side-effect
/// decision in `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
#[must_use]
pub fn unlock_final_app_state(current: &AppState, effect: &UnlockWorkerEffect) -> Option<AppState> {
    match unlock_app_state_after(effect) {
        Some(replacement) => Some(replacement.clone()),
        None => current.clone().leave_unlocking_busy(),
    }
}

/// Unified state-transition composer for the edit worker outcome.
///
/// Symmetric partner of [`add_final_app_state`] for the edit
/// path. Every [`EditWorkerEffect`] variant — `Success` and the
/// `Failure(PostEffectOutcome)` projection — lands on the same
/// `UnlockedBusy → Unlocked` rollback via [`AppState::leave_busy`]
/// because the edit worker reinstalls the live `(Vault, Store)` pair
/// through [`apply_edit_vault_install_inplace`] regardless of effect
/// (`Vault::mutate_and_save` is authoritative for the rollback /
/// durability-unconfirmed semantics per docs/DESIGN.md §4.3). The
/// dialog drop / inline-message routing handled at the dispatch site
/// is what differs across effects.
///
/// `effect` is accepted for signature symmetry with
/// [`add_final_app_state`] (and so a future routing refinement can
/// branch on it without changing call sites) but is not inspected.
///
/// Returns `Some(Unlocked { path })` iff `current` is
/// [`AppState::UnlockedBusy`], and `None` from every other state. The
/// `None` arm is the defensive case for a stray completion: an edit
/// completion arriving while `current` is not `UnlockedBusy` must not
/// silently install a phantom `Unlocked` over another idle state.
///
/// The composer is shape-only — it delegates to
/// [`AppState::leave_busy`] without re-deriving the transition — so
/// the side-effect decision in `AppModel::update` stays unit-testable
/// in `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
#[must_use]
pub fn edit_final_app_state(current: &AppState, _effect: &EditWorkerEffect) -> Option<AppState> {
    current.clone().leave_busy()
}

/// Bundled `AppModel::update` instructions for an unlock-worker
/// completion. Carries the three decisions the existing trio
/// projects ([`should_drop_unlock_dialog_after`],
/// [`unlock_dialog_msg_after`], and [`unlock_final_app_state`]) so
/// the dispatch site can apply the worker outcome in a single shot
/// without re-routing the [`UnlockWorkerEffect`].
///
/// Owning [`UnlockDialogMsg`] (rather than a borrow into the
/// effect) lets `AppModel::update` move the message straight into
/// the live [`crate::unlock_dialog::UnlockDialogComponent`] sender
/// after the borrow on the effect has ended.
#[derive(Debug, Clone)]
pub struct UnlockDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some` for
    /// the two replacement branches (success → `Unlocked`,
    /// startup-routed failure → `StartupError`) and the inline
    /// branch's `UnlockedBusy → Locked` rollback. `None` is the
    /// defensive case where the inline branch fires but `current`
    /// is not [`AppState::UnlockedBusy`] — `AppModel::update`
    /// leaves the state untouched rather than installing a phantom
    /// `Locked` over another idle state.
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::unlock_dialog::UnlockDialogComponent`] controller.
    /// `Some(UnlockDialogMsg::OpenFailedInline(_))` for the inline
    /// branch (the dialog stays mounted and re-renders the typed
    /// passphrase error); `None` for the replacement branches that
    /// drop the dialog.
    pub dialog_msg: Option<UnlockDialogMsg>,
    /// Whether `AppModel::update` should drop the live
    /// [`crate::unlock_dialog::UnlockDialogComponent`] controller
    /// after applying [`Self::app_state`]. Drops on the two
    /// replacement branches; stays mounted on the inline branch so
    /// the user can retype their passphrase.
    pub drop_dialog: bool,
}

/// Bundle the trio of unlock-dispatch decisions into a single
/// [`UnlockDispatch`] result so `AppModel::update` can apply the
/// worker outcome in one shot.
///
/// The composer is a pure aggregator over the existing trio — it
/// never re-derives the routing:
///
/// * `drop_dialog` mirrors [`should_drop_unlock_dialog_after`].
/// * `dialog_msg` is the cloned projection of
///   [`unlock_dialog_msg_after`]; `UnlockDialogMsg` derives `Clone`
///   so the bundled message outlives the borrow on `effect`.
/// * `app_state` mirrors [`unlock_final_app_state`], which itself
///   composes [`unlock_app_state_after`] (replacement branches)
///   with [`AppState::leave_unlocking_busy`] (inline rollback).
///
/// The same invariants pinned at the trio level carry through:
///
/// * `drop_dialog == true` iff the worker outcome routes through
///   one of the two replacement branches — the dialog is dropped
///   exactly when [`unlock_app_state_after`] reports `Some`. The
///   replacement branches set `dialog_msg = None`; the inline
///   branch leaves `app_state` as the `Locked` rollback alongside
///   the forwarded inline message.
/// * For the inline branch from a non-[`AppState::UnlockedBusy`]
///   source state (a stray dispatch), `app_state` is `None` while
///   `dialog_msg` and `drop_dialog` still mirror the trio.
///   `AppModel::update` leaves the source state in place rather
///   than installing a phantom rollback.
///
/// The composer stays shape-only — it delegates to the trio without
/// inspecting the typed [`UnlockWorkerEffect`] variant itself — so
/// `tests/app_state_logic.rs` exercises the dispatch contract
/// without spinning up GTK / libadwaita.
#[must_use]
pub fn compose_unlock_dispatch(current: &AppState, effect: &UnlockWorkerEffect) -> UnlockDispatch {
    UnlockDispatch {
        app_state: unlock_final_app_state(current, effect),
        dialog_msg: unlock_dialog_msg_after(effect).cloned(),
        drop_dialog: should_drop_unlock_dialog_after(effect),
    }
}

/// Apply [`compose_unlock_dispatch`]'s state field in-place to
/// `state`, leaving it unchanged when the dispatch carries
/// `app_state = None`.
///
/// `AppModel::update`'s `AppMsg::UnlockWorkerCompleted` handler
/// holds the cached [`AppState`] behind `&mut AppState`; this
/// wrapper bridges the `Option<AppState>` field of [`UnlockDispatch`]
/// to that mut-reference call site so the handler does not have to
/// manage a take-and-restore dance around `dispatch.app_state`. The
/// remaining [`UnlockDispatch::dialog_msg`] and
/// [`UnlockDispatch::drop_dialog`] projections drive widget-side
/// work in the handler (forwarding the inline message to the live
/// [`crate::unlock_dialog::UnlockDialogComponent`] controller and
/// dropping the controller on the two replacement branches) and
/// are not the wrapper's concern.
///
/// Returns `true` when the state actually transitioned
/// (`dispatch.app_state` was `Some(_)` and `*state` now mirrors the
/// composer's projection), `false` otherwise. `AppModel::update`
/// can use the `true` return to gate any state-installation-only
/// follow-up work — a `false` return is the defensive no-op for the
/// inline branch from a non-[`AppState::UnlockedBusy`] source state
/// (a stray dispatch).
///
/// The wrapper stays shape-only — it inspects only the
/// `dispatch.app_state` field and clones the replacement out — so
/// the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
pub fn apply_unlock_dispatch_inplace(state: &mut AppState, dispatch: &UnlockDispatch) -> bool {
    if let Some(new_state) = dispatch.app_state.as_ref() {
        *state = new_state.clone();
        true
    } else {
        false
    }
}

/// Install the worker's `(Vault, Store)` pair from
/// [`UnlockWorkerCompletion::pair`] into `AppModel::vault` in-place,
/// leaving the slot unchanged when the completion carries `None`.
///
/// `AppModel::update`'s `AppMsg::UnlockWorkerCompleted` handler holds
/// the live vault slot behind `&mut Option<(Vault, Store)>` next to
/// the state machine; this wrapper bridges the `Option<(Vault, Store)>`
/// field of [`UnlockWorkerCompletion`] to that mut-reference call
/// site so the handler can absorb the worker outcome without
/// spreading the unpack across the dispatch path. It is the sibling
/// of [`apply_unlock_dispatch_inplace`] on the vault-slot side: the
/// dispatch wrapper handles the `AppState` replacement, this wrapper
/// handles the vault-slot install.
///
/// Returns `true` when the slot was written to (`pair` was
/// `Some(_)`), `false` otherwise. `AppModel::update` does not need
/// the return value for the unlock flow today — the slot is always
/// `None` entering the flow and the dispatch decision drives the
/// follow-up `AccountListComponent` mount — but the return mirrors
/// [`apply_unlock_dispatch_inplace`]'s `true`-on-write contract so
/// the two wrappers stay symmetric for future call sites.
///
/// `pair` is consumed by value because [`Vault`] and [`Store`] are
/// non-`Clone`; an incoming `Some(_)` always overwrites the slot so
/// the wrapper is idempotent against a stray double-fire and so the
/// same shape can be reused by other vault-touching workers (HOTP
/// `next`, add / remove / edit, settings saves, import / export,
/// passphrase transitions) when they reinstall the pair after a
/// worker return.
///
/// The wrapper stays shape-only — it inspects only the `Option`
/// discriminant — so the side-effect decision in `AppModel::update`
/// stays unit-testable in `tests/app_state_logic.rs` against real
/// `(Vault, Store)` pairs constructed via `paladin_auth_core::Store::create`
/// over a tempfile vault.
pub fn apply_unlock_vault_install_inplace(
    vault_slot: &mut Option<(Vault, Store)>,
    pair: Option<(Vault, Store)>,
) -> bool {
    if let Some(pair) = pair {
        *vault_slot = Some(pair);
        true
    } else {
        false
    }
}

/// Install the worker's `(Vault, Store)` pair from
/// [`crate::edit_dialog::EditWorkerCompletion`] into
/// `AppModel::vault` in-place.
///
/// Symmetric partner of [`apply_add_vault_install_inplace`] for
/// the edit path. The shape is identical because the edit worker
/// also returns the pair on *every* effect branch — `Success`,
/// `save_durability_unconfirmed`, `save_not_committed`, and the
/// defensive `invalid_state` / `duplicate_account` projections all
/// come back with the same `(Vault, Store)`, because
/// `Vault::mutate_and_save` is the authoritative rollback /
/// durability source per docs/DESIGN.md §4.3. There is no `None` case
/// to dispatch on, so the helper takes the pair by value and always
/// installs.
///
/// `AppModel::update`'s `AppMsg::EditWorkerCompleted` handler holds
/// the live vault slot behind `&mut Option<(Vault, Store)>` next to
/// the state machine; this wrapper unconditionally writes through
/// `Some(pair)`. That keeps it idempotent against a stray double-fire
/// and safe against a stray completion arriving while the slot is
/// empty (reinstalling the worker's pair is still the right behavior
/// because it owns the authoritative post-`mutate_and_save` state).
///
/// `pair` is consumed by value because [`Vault`] and [`Store`] are
/// non-`Clone`. The wrapper stays shape-only — it does not inspect
/// the pair — so the side-effect decision in `AppModel::update` stays
/// unit-testable in `tests/app_state_logic.rs` against real
/// `(Vault, Store)` pairs constructed via `paladin_auth_core::Store::create`
/// over a tempfile vault.
pub fn apply_edit_vault_install_inplace(
    vault_slot: &mut Option<(Vault, Store)>,
    pair: (Vault, Store),
) {
    *vault_slot = Some(pair);
}

/// Install the worker's `(Vault, Store)` pair from
/// [`crate::add_account::AddWorkerCompletion`] into `AppModel::vault`
/// in-place.
///
/// Symmetric partner of [`apply_edit_vault_install_inplace`] for
/// the add path. The shape is identical because the add worker also
/// returns the pair on *every* effect branch — `Success`,
/// `save_durability_unconfirmed`, `save_not_committed`, and the
/// defensive `validation_error` / `invalid_state` / `io_error`
/// projections all come back with the same `(Vault, Store)`, because
/// `Vault::mutate_and_save` is the authoritative rollback /
/// durability source per docs/DESIGN.md §4.3. There is no `None` case to
/// dispatch on, so the helper takes the pair by value and always
/// installs.
///
/// `AppModel::update`'s `AppMsg::AddWorkerCompleted` handler holds
/// the live vault slot behind `&mut Option<(Vault, Store)>` next to
/// the state machine; this wrapper unconditionally writes through
/// `Some(pair)`. That keeps it idempotent against a stray double-fire
/// — the same call against a filled slot replaces the contents — and
/// safe against a stray completion arriving while the slot is empty
/// (which would happen only if a non-`Unlocked` dispatch slipped past
/// the [`compose_add_worker_input`] gate; reinstalling the worker's
/// pair is still the right behavior because it owns the authoritative
/// post-`mutate_and_save` state).
///
/// `pair` is consumed by value because [`Vault`] and [`Store`] are
/// non-`Clone`. The wrapper stays shape-only — it does not inspect
/// the pair — so the side-effect decision in `AppModel::update`
/// stays unit-testable in `tests/app_state_logic.rs` against real
/// `(Vault, Store)` pairs constructed via `paladin_auth_core::Store::create`
/// over a tempfile vault.
pub fn apply_add_vault_install_inplace(
    vault_slot: &mut Option<(Vault, Store)>,
    pair: (Vault, Store),
) {
    *vault_slot = Some(pair);
}

/// Unified state-transition composer for the add worker outcome.
///
/// Symmetric partner of [`edit_final_app_state`] for the add path.
/// Every [`AddWorkerEffect`] variant — `Success { account_id }` and
/// every `Failure(AddPostEffectOutcome)` projection
/// (`Inline(InlineError)` for `save_not_committed` / `io_error` /
/// defensive `validation_error` / `invalid_state`, and
/// `KeepWithWarning(InlineWarning)` for
/// `save_durability_unconfirmed`) — lands on the same
/// `UnlockedBusy → Unlocked` rollback via [`AppState::leave_busy`].
/// The dialog-drop / inline-message decisions split off the typed
/// effect in sibling composers (`should_drop_add_dialog_after`,
/// `add_dialog_msg_after`) added in follow-up commits; this composer
/// owns only the state-machine rollback.
///
/// `effect` is accepted for signature symmetry with
/// [`edit_final_app_state`] (and so a future routing refinement
/// can branch on it without changing call sites) but is not
/// inspected: the add worker's two failure projections both
/// reinstall the live `(Vault, Store)` pair through
/// [`apply_add_vault_install_inplace`] regardless of effect, so the
/// state machine returns to `Unlocked` uniformly. The dialog drop /
/// inline-message routing handled elsewhere is what differs across
/// effects.
///
/// Returns `Some(Unlocked { path })` iff `current` is
/// [`AppState::UnlockedBusy`], and `None` from every other state.
/// The `None` arm is the defensive case for a stray completion: an
/// add completion arriving while `current` is not `UnlockedBusy`
/// must not silently install a phantom `Unlocked` over another
/// idle state.
///
/// The composer is shape-only — it delegates to
/// [`AppState::leave_busy`] without re-deriving the transition — so
/// the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
#[must_use]
pub fn add_final_app_state(current: &AppState, _effect: &AddWorkerEffect) -> Option<AppState> {
    current.clone().leave_busy()
}

/// Drop-decision projection for the [`crate::add_account::AddAccountComponent`]
/// after an add worker outcome.
///
/// Symmetric partner of [`should_drop_remove_dialog_after`] for the
/// add path. `AppMsg::AddWorkerCompleted` consults this to decide
/// whether to detach the live `AddAccountComponent` from the
/// content tree after applying the worker outcome:
///
/// * [`AddWorkerEffect::Success`] → `true`. The dialog dismisses
///   itself and the new row appears in the visible account list,
///   in lockstep with the `AppState::UnlockedBusy → Unlocked`
///   rollback that [`add_final_app_state`] returns.
/// * [`AddWorkerEffect::Failure`] (every
///   [`crate::add_account::AddPostEffectOutcome`] variant —
///   `Inline` for `save_not_committed` / `io_error` / defensive
///   `validation_error` / `invalid_state`, and `KeepWithWarning`
///   for `save_durability_unconfirmed`) → `false`. The dialog
///   stays mounted so the inline error / durability warning is
///   visible and the user can retry or acknowledge, mirroring how
///   the edit dialog stays mounted on every failure branch.
///
/// The projection inspects only the typed [`AddWorkerEffect`]
/// variant — it does not consult [`AppState`], the live
/// `(Vault, Store)` pair, or any
/// [`crate::add_account::AddAccountComponent`] state — so the
/// side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up
/// GTK / libadwaita.
#[must_use]
pub fn should_drop_add_dialog_after(effect: &AddWorkerEffect) -> bool {
    match effect {
        AddWorkerEffect::Success { .. } => true,
        AddWorkerEffect::Failure(_) => false,
    }
}

/// List-refresh projection after an add worker outcome.
///
/// Symmetric partner of [`should_refresh_list_after_remove`] for the
/// add path. `AppMsg::AddWorkerCompleted` consults this to decide
/// whether to re-project rows off the freshly reinstalled
/// `(Vault, Store)` pair and emit
/// [`crate::account_list::AccountListMsg::Refresh`] so the new
/// account appears in the visible row set per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountListComponent` ("Refresh the store after every vault
/// mutation … without reordering surviving rows"):
///
/// * [`AddWorkerEffect::Success`] → `true`. The add committed and
///   the new row must surface in the list.
/// * [`AddWorkerEffect::Failure`] with
///   [`crate::add_account::AddPostEffectOutcome::Inline`] → `false`.
///   `Vault::mutate_and_save` rolled back to the pre-attempt
///   snapshot (or never mutated for the defensive
///   `validation_error` / `invalid_state` branches); the visible
///   rows already match the post-rollback state.
/// * [`AddWorkerEffect::Failure`] with
///   [`crate::add_account::AddPostEffectOutcome::KeepWithWarning`]
///   → `true`. Primary save succeeded so the new account is durable
///   in memory; the list must surface it even though the parent
///   fsync was uncertain.
#[must_use]
pub fn should_refresh_list_after_add(effect: &AddWorkerEffect) -> bool {
    match effect {
        AddWorkerEffect::Success { .. } => true,
        AddWorkerEffect::Failure(outcome) => match outcome {
            crate::add_account::AddPostEffectOutcome::KeepWithWarning(_) => true,
            crate::add_account::AddPostEffectOutcome::Inline(_) => false,
        },
    }
}

/// Toast-body projection after an add worker outcome.
///
/// `AppMsg::AddWorkerCompleted` consults this to decide whether to
/// raise an `AdwToast` on the `adw::ToastOverlay` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
/// `AddAccountComponent` shared shell ("Keep successful manual and
/// URI additions consistent with §7: refresh the list from the
/// returned vault, close the dialog, and surface a status / toast
/// confirmation."):
///
/// * [`AddWorkerEffect::Success`] → `Some(body)`. The dialog dismisses
///   and the new row appears; the toast confirms the save committed.
/// * [`AddWorkerEffect::Failure`] → `None`. The dialog stays mounted
///   with the inline error / body warning, which is the surface that
///   conveys the typed outcome — no toast layered on top.
///
/// The body comes from
/// [`crate::add_account::format_add_dialog_success_toast`] so the
/// wording stays in one place shared by the widget binding and the
/// pure-logic tests. Sibling of [`remove_success_toast_after`] /
/// [`remove_success_toast_after`].
///
/// The projection inspects only the typed [`AddWorkerEffect`] variant
/// so the side-effect decision in `AppModel::update` stays
/// unit-testable in `tests/app_state_logic.rs` without spinning up
/// GTK / libadwaita.
#[must_use]
pub fn add_success_toast_after(effect: &AddWorkerEffect) -> Option<String> {
    match effect {
        AddWorkerEffect::Success { .. } => {
            Some(crate::add_account::format_add_dialog_success_toast().to_string())
        }
        AddWorkerEffect::Failure(_) => None,
    }
}

/// Inline-message projection for the live
/// [`crate::add_account::AddAccountComponent`] after an add worker
/// outcome.
///
/// Symmetric partner of [`remove_dialog_msg_after`] for the add
/// path. `AppMsg::AddWorkerCompleted` consults this to decide what
/// message (if any) to forward into the live dialog after applying
/// the worker outcome:
///
/// * [`AddWorkerEffect::Success`] → `None`. The dialog is being
///   dropped (see [`should_drop_add_dialog_after`]), so there is
///   no live controller to forward to.
/// * [`AddWorkerEffect::Failure`] → `Some(AddAccountMsg::
///   WorkerFailed(outcome.clone()))`. The dialog stays mounted;
///   the message carries the typed
///   [`crate::add_account::AddPostEffectOutcome`] so the dialog
///   can route `Inline` (render the typed inline error and keep
///   the form populated for retry) or `KeepWithWarning` (attach
///   the durability warning to the body) without re-deriving the
///   routing off the [`paladin_auth_core::PaladinAuthError`].
///
/// The projection returns an *owned* [`Option<AddAccountMsg>`]
/// rather than a borrow into the effect because
/// [`AddWorkerEffect`] carries the typed
/// [`crate::add_account::AddPostEffectOutcome`] rather than a
/// pre-built dialog message (parity with the edit path; the
/// unlock effect carries its dialog message directly via
/// `UnlockFailureEffect::SendUnlockDialogMsg` so the unlock
/// variant can borrow). The clone is cheap — the outcome only
/// holds an [`crate::add_account::InlineError`] /
/// [`crate::add_account::InlineWarning`] of a stable
/// [`paladin_auth_core::ErrorKind`] and a `String` body.
///
/// The projection inspects only the typed [`AddWorkerEffect`]
/// variant — it does not consult [`AppState`], the live
/// `(Vault, Store)` pair, or any
/// [`crate::add_account::AddAccountComponent`] state — so the
/// side-effect decision in `AppModel::update` stays unit-testable
/// in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
///
/// The `Some` / `None` partition matches
/// [`should_drop_add_dialog_after`] exactly (a dropped dialog
/// receives no message; a mounted dialog receives a message) and
/// this contract is pinned in `tests/app_state_logic.rs` so the
/// two projections cannot drift apart silently.
#[must_use]
pub fn add_dialog_msg_after(effect: &AddWorkerEffect) -> Option<AddAccountMsg> {
    match effect {
        AddWorkerEffect::Success { .. } => None,
        AddWorkerEffect::Failure(outcome) => Some(AddAccountMsg::WorkerFailed(outcome.clone())),
    }
}

/// Bundled `AppModel::update` instructions for an add-worker
/// completion. Carries the three decisions the existing trio
/// projects ([`should_drop_add_dialog_after`],
/// [`add_dialog_msg_after`], and [`add_final_app_state`]) so the
/// dispatch site can apply the worker outcome in a single shot
/// without re-routing the [`AddWorkerEffect`].
///
/// Symmetric partner of [`RemoveDispatch`] for the add path. The
/// shape mirrors the remove variant: an optional state replacement,
/// an optional inline message, and a drop-dialog flag. `dialog_msg`
/// is owned rather than borrowed because [`add_dialog_msg_after`]
/// returns an owned [`Option<AddAccountMsg>`] — the add effect
/// carries the typed
/// [`crate::add_account::AddPostEffectOutcome`] and the message is
/// constructed at projection time.
#[derive(Debug, Clone)]
pub struct AddDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some` for
    /// the `UnlockedBusy → Unlocked` rollback that
    /// [`add_final_app_state`] returns regardless of typed effect
    /// (the add worker always rolls the busy gate back because
    /// `Vault::mutate_and_save` is authoritative for the rollback /
    /// durability-unconfirmed semantics per docs/DESIGN.md §4.3). `None`
    /// is the defensive case where the worker outcome arrives but
    /// `current` is not [`AppState::UnlockedBusy`] — `AppModel::update`
    /// leaves the state untouched rather than installing a phantom
    /// `Unlocked` over another idle state.
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::add_account::AddAccountComponent`] controller.
    /// `Some(AddAccountMsg::WorkerFailed(outcome))` for the failure
    /// branches (the dialog stays mounted and re-renders the typed
    /// outcome — `Inline` for `save_not_committed` / `io_error` /
    /// defensive `validation_error` / `invalid_state`, and
    /// `KeepWithWarning` for `save_durability_unconfirmed`); `None`
    /// for the success branch that drops the dialog.
    pub dialog_msg: Option<AddAccountMsg>,
    /// Whether `AppModel::update` should drop the live
    /// [`crate::add_account::AddAccountComponent`] controller after
    /// applying [`Self::app_state`]. Drops on the success branch;
    /// stays mounted on every failure branch so the inline error /
    /// body warning is visible and the user can retry or acknowledge.
    pub drop_dialog: bool,
    /// Whether `AppModel::update` should re-project rows off the
    /// freshly reinstalled `(Vault, Store)` pair and emit
    /// [`crate::account_list::AccountListMsg::Refresh`] so the new
    /// account appears in the visible row set. Mirrors
    /// [`should_refresh_list_after_add`] — `true` on `Success` and
    /// `KeepWithWarning` (both leave the new account in memory),
    /// `false` on the `Inline` failure branches (where the vault is
    /// unchanged so the visible rows already match disk).
    pub refresh_list: bool,
    /// Optional `AdwToast` body to raise on the `adw::ToastOverlay`
    /// after applying the add worker outcome. Mirrors
    /// [`add_success_toast_after`] — `Some(body)` on
    /// [`AddWorkerEffect::Success`] and `None` on every `Failure`
    /// variant so the dialog's inline error / body warning stays the
    /// only surface that conveys the typed outcome.
    pub success_toast: Option<String>,
}

/// Bundle the trio of add-dispatch decisions into a single
/// [`AddDispatch`] result so `AppModel::update` can apply the worker
/// outcome in one shot.
///
/// Symmetric partner of [`compose_remove_dispatch`] for the add
/// path. The composer is a pure aggregator over the existing trio —
/// it never re-derives the routing:
///
/// * `drop_dialog` mirrors [`should_drop_add_dialog_after`].
/// * `dialog_msg` mirrors [`add_dialog_msg_after`], which returns an
///   owned [`Option<AddAccountMsg>`] so the bundled message outlives
///   the borrow on `effect`.
/// * `app_state` mirrors [`add_final_app_state`], which is the
///   `UnlockedBusy → Unlocked` rollback for every typed effect (the
///   add worker always rolls the busy gate back, regardless of typed
///   outcome).
///
/// The same invariants pinned at the trio level carry through:
///
/// * `drop_dialog == true` iff the worker outcome is
///   [`AddWorkerEffect::Success`] — the dialog drops on success and
///   stays mounted on every `Failure(AddPostEffectOutcome)` variant.
/// * `dialog_msg.is_some() == !drop_dialog`: a dropped dialog gets no
///   inline message; a mounted dialog gets a `WorkerFailed(outcome)`.
/// * For the failure branches from a non-[`AppState::UnlockedBusy`]
///   source state (a stray dispatch), `app_state` is `None` while
///   `dialog_msg` and `drop_dialog` still mirror the trio.
///   `AppModel::update` leaves the source state in place rather than
///   installing a phantom rollback.
///
/// The composer stays shape-only — it delegates to the trio without
/// inspecting the typed [`AddWorkerEffect`] variant itself — so
/// `tests/app_state_logic.rs` exercises the dispatch contract
/// without spinning up GTK / libadwaita.
#[must_use]
pub fn compose_add_dispatch(current: &AppState, effect: &AddWorkerEffect) -> AddDispatch {
    AddDispatch {
        app_state: add_final_app_state(current, effect),
        dialog_msg: add_dialog_msg_after(effect),
        drop_dialog: should_drop_add_dialog_after(effect),
        refresh_list: should_refresh_list_after_add(effect),
        success_toast: add_success_toast_after(effect),
    }
}

/// Apply [`compose_add_dispatch`]'s state field in-place to `state`,
/// leaving it unchanged when the dispatch carries `app_state = None`.
///
/// Symmetric partner of [`apply_remove_dispatch_inplace`] for the
/// add path. `AppModel::update`'s `AppMsg::AddWorkerCompleted`
/// handler holds the cached [`AppState`] behind `&mut AppState`;
/// this wrapper bridges the `Option<AppState>` field of
/// [`AddDispatch`] to that mut-reference call site so the handler
/// does not have to manage a take-and-restore dance around
/// `dispatch.app_state`. The remaining [`AddDispatch::dialog_msg`]
/// and [`AddDispatch::drop_dialog`] projections drive widget-side
/// work in the handler (forwarding the inline message to the live
/// [`crate::add_account::AddAccountComponent`] controller and
/// dropping the controller on the success branch) and are not the
/// wrapper's concern.
///
/// Returns `true` when the state actually transitioned
/// (`dispatch.app_state` was `Some(_)` and `*state` now mirrors the
/// composer's projection), `false` otherwise. `AppModel::update`
/// can use the `true` return to gate any state-installation-only
/// follow-up work — a `false` return is the defensive no-op for the
/// case where the worker outcome arrived but the cached state was
/// not [`AppState::UnlockedBusy`] (a stray dispatch).
///
/// The wrapper stays shape-only — it inspects only the
/// `dispatch.app_state` field and clones the replacement out — so
/// the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
pub fn apply_add_dispatch_inplace(state: &mut AppState, dispatch: &AddDispatch) -> bool {
    if let Some(new_state) = dispatch.app_state.as_ref() {
        *state = new_state.clone();
        true
    } else {
        false
    }
}

/// Apply [`compose_qr_dispatch`]'s state field in-place to `state`,
/// leaving it unchanged when the dispatch carries `app_state = None`.
///
/// Symmetric partner of [`apply_add_dispatch_inplace`] for the
/// clipboard-QR sub-path. `AppModel::update`'s
/// `AppMsg::QrWorkerCompleted` handler holds the cached [`AppState`]
/// behind `&mut AppState`; this wrapper bridges the
/// `Option<AppState>` field of [`QrDispatch`] to that mut-reference
/// call site so the handler does not have to manage a take-and-
/// restore dance around `dispatch.app_state`. The remaining
/// [`QrDispatch::dialog_msg`], [`QrDispatch::drop_dialog`], and
/// [`QrDispatch::refresh_list`] projections drive widget-side work
/// in the handler (forwarding `QrSuccess(summary)` /
/// `WorkerFailed(outcome)` to the live
/// [`crate::add_account::AddAccountComponent`] controller, keeping
/// the dialog mounted on every effect, and refreshing the account
/// list when the merge committed) and are not the wrapper's concern.
///
/// Returns `true` when the state actually transitioned
/// (`dispatch.app_state` was `Some(_)` and `*state` now mirrors the
/// composer's projection), `false` otherwise. `AppModel::update` can
/// use the `true` return to gate any state-installation-only follow-
/// up work — a `false` return is the defensive no-op for the case
/// where the worker outcome arrived but the cached state was not
/// [`AppState::UnlockedBusy`] (a stray dispatch).
///
/// The wrapper stays shape-only — it inspects only the
/// `dispatch.app_state` field and clones the replacement out — so
/// the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
pub fn apply_qr_dispatch_inplace(state: &mut AppState, dispatch: &QrDispatch) -> bool {
    if let Some(new_state) = dispatch.app_state.as_ref() {
        *state = new_state.clone();
        true
    } else {
        false
    }
}

/// Compose the [`AppState`] transition for the
/// [`crate::remove_dialog::RemoveDialogOutput::SubmitConfirm`] dispatch.
///
/// Symmetric partner of [`submit_edit_app_state`] for the remove
/// path: both delegate to [`AppState::enter_busy`] so an `Unlocked →
/// UnlockedBusy` transition gates the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.remove(...))` worker.
///
/// Returns `Some(UnlockedBusy { path })` iff `current` is
/// [`AppState::Unlocked`], and `None` from every other state — the
/// defensive no-op for a stray `SubmitConfirm` from any non-
/// `Unlocked` source state (`Missing`, `Locked`, `UnlockedBusy`,
/// `StartupError`).
///
/// The composer stays shape-only — it delegates the transition to
/// [`AppState::enter_busy`] — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
#[must_use]
pub fn submit_remove_app_state(current: &AppState) -> Option<AppState> {
    current.clone().enter_busy()
}

/// Bundle the live `(Vault, Store)` pair and the
/// [`crate::remove_dialog::RemoveDialogOutput::SubmitConfirm`] payload
/// into a [`RemoveWorkerInput`] for the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.remove(...))` worker.
///
/// Symmetric partner of [`compose_edit_worker_input`] on the remove
/// path: where the edit composer captures the account id plus the
/// assembled [`AccountEdit`] and dispatch-site wall-clock, this composer only
/// needs the account id — `Vault::remove` has no wall-clock dependency
/// and no editable payload. The `(Vault, Store)` pair is otherwise
/// captured the same way so the worker thread can run
/// `mutate_and_save` without re-fetching from `AppModel`.
///
/// Returns `Ok(RemoveWorkerInput)` iff `current` is
/// [`AppState::Unlocked`]. The `Err((vault, store))` branch is the
/// defensive case for a stray dispatch from any other source state
/// (`Missing` / `Locked` / `UnlockedBusy` / `StartupError`): the
/// non-`Clone` live `(Vault, Store)` pair would be lost if the
/// composer dropped it, so it is handed back so the caller can
/// reinstall it into `AppModel.vault` rather than leaking the
/// unlocked state. The contract mirrors the `Some` / `None`
/// agreement with [`submit_remove_app_state`] — both helpers return
/// success iff the source is `Unlocked`.
///
/// The composer stays shape-only — it inspects only the variant
/// discriminant on `current` — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` against real `(Vault, Store)` pairs
/// constructed via `paladin_auth_core::Store::create` over a tempfile
/// vault.
pub fn compose_remove_worker_input(
    current: &AppState,
    pair: (Vault, Store),
    account_id: AccountId,
) -> Result<RemoveWorkerInput, (Vault, Store)> {
    match current {
        AppState::Unlocked { .. } => {
            let (vault, store) = pair;
            Ok(RemoveWorkerInput {
                vault,
                store,
                account_id,
            })
        }
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => Err(pair),
    }
}

/// Apply [`submit_remove_app_state`] in-place to `state`, leaving it
/// unchanged when the composer returns `None`.
///
/// Symmetric partner of [`apply_submit_edit_inplace`] for the
/// remove path. Both bridge the owned-`self` [`AppState::enter_busy`]
/// contract to the mut-reference call site so `AppModel::update`'s
/// [`crate::remove_dialog::RemoveDialogOutput::SubmitConfirm`] handler
/// does not have to manage a take-and-restore dance around
/// `submit_remove_app_state`'s `Option<AppState>` return.
///
/// Returns `true` when the state actually transitioned (source was
/// `Unlocked` → destination is `UnlockedBusy`), `false` otherwise.
/// `AppModel::update` uses the `true` return to gate the
/// `gio::spawn_blocking Vault::mutate_and_save(|v| v.remove(...))`
/// worker spawn — a `false` return is the defensive no-op for a
/// stray `SubmitConfirm` from any non-`Unlocked` source state
/// (`Missing`, `Locked`, `UnlockedBusy`, `StartupError`).
///
/// The wrapper stays shape-only — it delegates to
/// `submit_remove_app_state` without re-deriving the transition —
/// so the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
pub fn apply_submit_remove_inplace(state: &mut AppState) -> bool {
    if let Some(new_state) = submit_remove_app_state(state) {
        *state = new_state;
        true
    } else {
        false
    }
}

/// Unified state-transition composer for the remove worker outcome.
///
/// Symmetric partner of [`edit_final_app_state`] for the remove
/// path: both delegate to [`AppState::leave_busy`] so every
/// [`RemoveWorkerEffect`] variant — `Success` and every
/// `Failure(RemoveErrorOutcome)` projection — lands on the same
/// `UnlockedBusy → Unlocked` rollback. The dialog-drop / inline-
/// message decisions split off the typed effect in sibling composers;
/// this composer owns only the state-machine rollback.
///
/// `effect` is accepted for signature symmetry with
/// [`edit_final_app_state`] (and so a future routing refinement
/// can branch on it without changing call sites) but is not
/// inspected: the remove worker's three failure projections all
/// reinstall the live `(Vault, Store)` pair through
/// [`apply_remove_vault_install_inplace`] regardless of effect, so
/// the state machine returns to `Unlocked` uniformly. The dialog
/// drop / inline-message routing handled elsewhere is what differs
/// across effects.
///
/// Returns `Some(Unlocked { path })` iff `current` is
/// [`AppState::UnlockedBusy`], and `None` from every other state.
/// The `None` arm is the defensive case for a stray completion: a
/// remove completion arriving while `current` is not `UnlockedBusy`
/// must not silently install a phantom `Unlocked` over another
/// idle state.
///
/// The composer is shape-only — it delegates to
/// [`AppState::leave_busy`] without re-deriving the transition —
/// so the side-effect decision in `AppModel::update` stays unit-
/// testable in `tests/app_state_logic.rs` without spinning up GTK /
/// libadwaita.
#[must_use]
pub fn remove_final_app_state(
    current: &AppState,
    _effect: &RemoveWorkerEffect,
) -> Option<AppState> {
    current.clone().leave_busy()
}

/// Drop-decision projection for the
/// [`crate::remove_dialog::RemoveDialogComponent`] after a remove
/// worker outcome.
///
/// Symmetric partner of [`should_drop_add_dialog_after`] for the
/// remove path. `AppMsg::RemoveWorkerCompleted` consults this to
/// decide whether to detach the live `RemoveDialogComponent` from
/// the content tree after applying the worker outcome:
///
/// * [`RemoveWorkerEffect::Success`] → `true`. The dialog dismisses
///   itself and the targeted row drops out of the visible account
///   list, in lockstep with the `AppState::UnlockedBusy → Unlocked`
///   rollback that [`remove_final_app_state`] returns.
/// * [`RemoveWorkerEffect::Failure`] (every
///   [`crate::remove_dialog::RemoveErrorOutcome`] variant —
///   `RestorePrior`, `KeepRemovedWithWarning`, defensive `InlineError`)
///   → `false`. The dialog stays mounted so the inline error / body
///   warning is visible and the user can retry, mirroring how the
///   edit dialog stays mounted on every failure branch.
///
/// The projection inspects only the typed [`RemoveWorkerEffect`]
/// variant — it does not consult [`AppState`], the live
/// `(Vault, Store)` pair, or the
/// [`crate::remove_dialog::RemoveDialogState`] — so the side-effect
/// decision in `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
#[must_use]
pub fn should_drop_remove_dialog_after(effect: &RemoveWorkerEffect) -> bool {
    match effect {
        RemoveWorkerEffect::Success => true,
        RemoveWorkerEffect::Failure(_) => false,
    }
}

/// List-refresh projection after a remove worker outcome.
///
/// Symmetric partner of [`should_refresh_list_after_add`] for the
/// remove path. `AppMsg::RemoveWorkerCompleted` consults this to
/// decide whether to re-project rows off the freshly reinstalled
/// `(Vault, Store)` pair and emit
/// [`crate::account_list::AccountListMsg::Refresh`] so the removed
/// account disappears from the visible row set per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountListComponent` ("Refresh the store after every vault
/// mutation … without reordering surviving rows"):
///
/// * [`RemoveWorkerEffect::Success`] → `true`. The remove
///   committed and the row must disappear from the list.
/// * [`RemoveWorkerEffect::Failure`] with
///   [`crate::remove_dialog::RemoveErrorOutcome::RestorePrior`] →
///   `false`. `Vault::mutate_and_save` restored the removed
///   account at its previous position; the visible rows already
///   match the post-rollback state.
/// * [`RemoveWorkerEffect::Failure`] with
///   [`crate::remove_dialog::RemoveErrorOutcome::KeepRemovedWithWarning`]
///   → `true`. Primary save succeeded so the removal is durable
///   in memory; the list must surface it even though the parent
///   fsync was uncertain.
/// * [`RemoveWorkerEffect::Failure`] with
///   [`crate::remove_dialog::RemoveErrorOutcome::InlineError`] →
///   `false`. Defensive branch (`invalid_state` /
///   `account_not_found`) where the vault was not mutated.
#[must_use]
pub fn should_refresh_list_after_remove(effect: &RemoveWorkerEffect) -> bool {
    match effect {
        RemoveWorkerEffect::Success => true,
        RemoveWorkerEffect::Failure(outcome) => match outcome {
            crate::remove_dialog::RemoveErrorOutcome::KeepRemovedWithWarning(_) => true,
            crate::remove_dialog::RemoveErrorOutcome::RestorePrior(_)
            | crate::remove_dialog::RemoveErrorOutcome::InlineError(_) => false,
        },
    }
}

/// Inline-message projection for the live
/// [`crate::remove_dialog::RemoveDialogComponent`] after a remove
/// worker outcome.
///
/// Symmetric partner of [`add_dialog_msg_after`] for the remove
/// path. `AppMsg::RemoveWorkerCompleted` consults this to decide
/// what message (if any) to forward into the live dialog after
/// applying the worker outcome:
///
/// * [`RemoveWorkerEffect::Success`] → `None`. The dialog is being
///   dropped (see [`should_drop_remove_dialog_after`]), so there
///   is no live controller to forward to.
/// * [`RemoveWorkerEffect::Failure`] → `Some(RemoveDialogMsg::
///   WorkerFailed(outcome.clone()))`. The dialog stays mounted; the
///   message carries the typed
///   [`crate::remove_dialog::RemoveErrorOutcome`] so the dialog can
///   route `RestorePrior` (render the inline error),
///   `KeepRemovedWithWarning` (render the warning beneath the
///   confirmation), or the defensive `InlineError` (render the typed
///   error) without re-deriving the routing off the
///   [`paladin_auth_core::PaladinAuthError`].
///
/// The projection returns an *owned* [`Option<RemoveDialogMsg>`]
/// rather than a borrow into the effect because
/// [`RemoveWorkerEffect`] carries the typed
/// [`crate::remove_dialog::RemoveErrorOutcome`] rather than a
/// pre-built dialog message. The clone is cheap — the outcome only
/// holds an [`crate::remove_dialog::InlineError`] /
/// [`crate::remove_dialog::InlineWarning`] of a stable
/// [`paladin_auth_core::ErrorKind`] and a `String` body.
///
/// The `Some` / `None` partition matches
/// [`should_drop_remove_dialog_after`] exactly (a dropped dialog
/// receives no message; a mounted dialog receives a message) and
/// this contract is pinned in `tests/app_state_logic.rs` so the
/// two projections cannot drift apart silently.
#[must_use]
pub fn remove_dialog_msg_after(effect: &RemoveWorkerEffect) -> Option<RemoveDialogMsg> {
    match effect {
        RemoveWorkerEffect::Success => None,
        RemoveWorkerEffect::Failure(outcome) => {
            Some(RemoveDialogMsg::WorkerFailed(outcome.clone()))
        }
    }
}

/// Bundled `AppModel::update` instructions for a remove-worker
/// completion. Carries the three decisions the existing trio
/// projects ([`should_drop_remove_dialog_after`],
/// [`remove_dialog_msg_after`], and [`remove_final_app_state`]) so
/// the dispatch site can apply the worker outcome in a single shot
/// without re-routing the [`RemoveWorkerEffect`].
///
/// Symmetric partner of [`AddDispatch`] for the remove path. The
/// shape mirrors the edit variant: an optional state replacement,
/// an optional inline message, and a drop-dialog flag.
#[derive(Debug, Clone)]
pub struct RemoveDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some` for
    /// the `UnlockedBusy → Unlocked` rollback that
    /// [`remove_final_app_state`] returns regardless of typed effect
    /// (the remove worker always rolls the busy gate back because
    /// `Vault::mutate_and_save` is authoritative for the rollback /
    /// durability-unconfirmed semantics per docs/DESIGN.md §4.3). `None`
    /// is the defensive case where the worker outcome arrives but
    /// `current` is not [`AppState::UnlockedBusy`] — `AppModel::update`
    /// leaves the state untouched rather than installing a phantom
    /// `Unlocked` over another idle state.
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::remove_dialog::RemoveDialogComponent`] controller.
    /// `Some(RemoveDialogMsg::WorkerFailed(outcome))` for the failure
    /// branches (the dialog stays mounted and re-renders the typed
    /// outcome — `RestorePrior`, `KeepRemovedWithWarning`, or
    /// defensive `InlineError`); `None` for the success branch that
    /// drops the dialog.
    pub dialog_msg: Option<RemoveDialogMsg>,
    /// Whether `AppModel::update` should drop the live
    /// [`crate::remove_dialog::RemoveDialogComponent`] controller
    /// after applying [`Self::app_state`]. Drops on the success
    /// branch; stays mounted on every failure branch so the inline
    /// error / body warning is visible and the user can retry.
    pub drop_dialog: bool,
    /// Whether `AppModel::update` should re-project rows off the
    /// freshly reinstalled `(Vault, Store)` pair and emit
    /// [`crate::account_list::AccountListMsg::Refresh`] so the
    /// removed account disappears from the visible row set.
    /// Mirrors [`should_refresh_list_after_remove`] — `true` on
    /// `Success` and `KeepRemovedWithWarning` (both leave the
    /// removal in memory), `false` on `RestorePrior` and defensive
    /// `InlineError` (both leave the vault unchanged so the
    /// visible rows already match disk).
    pub refresh_list: bool,
    /// Optional `AdwToast` body to raise on the `adw::ToastOverlay`
    /// after applying the remove worker outcome. Mirrors
    /// [`remove_success_toast_after`] — `Some(body)` on
    /// [`RemoveWorkerEffect::Success`] and `None` on every
    /// `Failure` variant so the dialog's inline error / body
    /// warning stays the only surface that conveys the typed
    /// outcome.
    pub success_toast: Option<String>,
}

/// Bundle the trio of remove-dispatch decisions into a single
/// [`RemoveDispatch`] result so `AppModel::update` can apply the
/// worker outcome in one shot.
///
/// The composer is a pure aggregator over the existing trio — it
/// never re-derives the routing:
///
/// * `drop_dialog` mirrors [`should_drop_remove_dialog_after`].
/// * `dialog_msg` mirrors [`remove_dialog_msg_after`], which returns
///   an owned [`Option<RemoveDialogMsg>`] so the bundled message
///   outlives the borrow on `effect`.
/// * `app_state` mirrors [`remove_final_app_state`], which is the
///   `UnlockedBusy → Unlocked` rollback for every typed effect.
///
/// The same invariants pinned at the trio level carry through:
///
/// * `drop_dialog == true` iff the worker outcome is
///   [`RemoveWorkerEffect::Success`] — the dialog drops on success
///   and stays mounted on every `Failure(RemoveErrorOutcome)`
///   variant.
/// * `dialog_msg.is_some() == !drop_dialog`: a dropped dialog gets no
///   inline message; a mounted dialog gets a `WorkerFailed(outcome)`.
/// * For the failure branches from a non-[`AppState::UnlockedBusy`]
///   source state (a stray dispatch), `app_state` is `None` while
///   `dialog_msg` and `drop_dialog` still mirror the trio.
///   `AppModel::update` leaves the source state in place rather than
///   installing a phantom rollback.
///
/// The composer stays shape-only — it delegates to the trio without
/// inspecting the typed [`RemoveWorkerEffect`] variant itself — so
/// `tests/app_state_logic.rs` exercises the dispatch contract
/// without spinning up GTK / libadwaita.
#[must_use]
pub fn compose_remove_dispatch(current: &AppState, effect: &RemoveWorkerEffect) -> RemoveDispatch {
    RemoveDispatch {
        app_state: remove_final_app_state(current, effect),
        dialog_msg: remove_dialog_msg_after(effect),
        drop_dialog: should_drop_remove_dialog_after(effect),
        refresh_list: should_refresh_list_after_remove(effect),
        success_toast: remove_success_toast_after(effect),
    }
}

/// Toast-body projection for the remove worker outcome.
///
/// `AppMsg::RemoveWorkerCompleted` consults this to decide whether
/// to raise an `AdwToast` on the `adw::ToastOverlay` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
/// `RemoveDialog` confirmation flow ("On success, refresh
/// `AccountListComponent` from the returned vault, close the
/// dialog, and surface a status / toast confirmation."):
///
/// * [`RemoveWorkerEffect::Success`] → `Some(body)`. The dialog
///   dismisses and the row disappears from the list; the toast
///   confirms the save committed.
/// * [`RemoveWorkerEffect::Failure`] → `None`. The dialog stays
///   mounted with the inline error / body warning, which is the
///   surface that conveys the typed outcome — no toast layered on
///   top.
///
/// The body comes from
/// [`crate::remove_dialog::format_remove_dialog_success_toast`] so
/// the wording stays in one place shared by the widget binding and
/// the pure-logic tests. Sibling of [`add_success_toast_after`]
/// on the dispatch-side projection set.
///
/// The projection inspects only the typed [`RemoveWorkerEffect`]
/// variant so the side-effect decision in `AppModel::update` stays
/// unit-testable in `tests/app_state_logic.rs` without spinning up
/// GTK / libadwaita.
#[must_use]
pub fn remove_success_toast_after(effect: &RemoveWorkerEffect) -> Option<String> {
    match effect {
        RemoveWorkerEffect::Success => {
            Some(crate::remove_dialog::format_remove_dialog_success_toast().to_string())
        }
        RemoveWorkerEffect::Failure(_) => None,
    }
}

/// Apply [`compose_remove_dispatch`]'s state field in-place to
/// `state`, leaving it unchanged when the dispatch carries
/// `app_state = None`.
///
/// Symmetric partner of [`apply_add_dispatch_inplace`] for the
/// remove path. `AppModel::update`'s `AppMsg::RemoveWorkerCompleted`
/// handler holds the cached [`AppState`] behind `&mut AppState`; this
/// wrapper bridges the `Option<AppState>` field of [`RemoveDispatch`]
/// to that mut-reference call site so the handler does not have to
/// manage a take-and-restore dance around `dispatch.app_state`. The
/// remaining [`RemoveDispatch::dialog_msg`] and
/// [`RemoveDispatch::drop_dialog`] projections drive widget-side work
/// in the handler (forwarding the inline message to the live
/// [`crate::remove_dialog::RemoveDialogComponent`] controller and
/// dropping the controller on the success branch) and are not the
/// wrapper's concern.
///
/// Returns `true` when the state actually transitioned
/// (`dispatch.app_state` was `Some(_)` and `*state` now mirrors the
/// composer's projection), `false` otherwise. `AppModel::update` can
/// use the `true` return to gate any state-installation-only follow-
/// up work — a `false` return is the defensive no-op for the case
/// where the worker outcome arrived but the cached state was not
/// [`AppState::UnlockedBusy`] (a stray dispatch).
///
/// The wrapper stays shape-only — it inspects only the
/// `dispatch.app_state` field and clones the replacement out — so the
/// side-effect decision in `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita.
pub fn apply_remove_dispatch_inplace(state: &mut AppState, dispatch: &RemoveDispatch) -> bool {
    if let Some(new_state) = dispatch.app_state.as_ref() {
        *state = new_state.clone();
        true
    } else {
        false
    }
}

/// Install the worker's `(Vault, Store)` pair from
/// [`crate::remove_dialog::RemoveWorkerCompletion`] into
/// `AppModel::vault` in-place.
///
/// Symmetric partner of [`apply_edit_vault_install_inplace`] for
/// the remove path. The remove worker, like the edit worker,
/// returns the pair on *every* effect branch — `Success`,
/// `save_durability_unconfirmed`, `save_not_committed`, and the
/// defensive `account_not_found` / `io_error` / `validation_error`
/// projections all come back with the same `(Vault, Store)`, because
/// `Vault::mutate_and_save` is the authoritative rollback /
/// durability source per docs/DESIGN.md §4.3. There is no `None` case to
/// dispatch on, so the helper takes the pair by value and always
/// installs.
///
/// `AppModel::update`'s `AppMsg::RemoveWorkerCompleted` handler
/// holds the live vault slot behind `&mut Option<(Vault, Store)>`
/// next to the state machine; this wrapper unconditionally writes
/// through `Some(pair)`. That keeps it idempotent against a stray
/// double-fire and safe against a stray completion arriving while
/// the slot is empty (which would happen only if a non-`Unlocked`
/// dispatch slipped past the [`compose_remove_worker_input`] gate;
/// reinstalling the worker's pair is still the right behavior
/// because it owns the authoritative post-`mutate_and_save` state).
///
/// `pair` is consumed by value because [`Vault`] and [`Store`] are
/// non-`Clone`. The wrapper stays shape-only — it does not inspect
/// the pair — so the side-effect decision in `AppModel::update`
/// stays unit-testable in `tests/app_state_logic.rs` against real
/// `(Vault, Store)` pairs constructed via `paladin_auth_core::Store::create`
/// over a tempfile vault.
pub fn apply_remove_vault_install_inplace(
    vault_slot: &mut Option<(Vault, Store)>,
    pair: (Vault, Store),
) {
    *vault_slot = Some(pair);
}

/// Worker input bundled by `AppMsg::UnlockDialogAction(SubmitLock)`
/// for the `gio::spawn_blocking paladin_auth_core::open` worker.
///
/// Carries the resolved vault path captured from the current
/// [`AppState::Locked`] source state alongside the typed
/// [`paladin_auth_core::VaultLock`] forwarded from
/// [`crate::unlock_dialog::UnlockDialogOutput::SubmitLock`]. Both
/// fields are owned values so the worker closure can `move` them
/// across the `gio::spawn_blocking` boundary without borrowing into
/// `AppModel`.
///
/// `Debug` is derived — `VaultLock`'s own `Debug` impl redacts the
/// `Encrypted(SecretString)` payload via `secrecy`, so a debug print
/// shows `Encrypted([REDACTED])` rather than leaking the passphrase.
/// `Clone` / `PartialEq` are deliberately *not* derived:
/// `VaultLock::Encrypted` wraps a non-`Clone` `SecretString`, and
/// `AppModel::update` consumes the input exactly once when it moves
/// it into the worker closure.
#[derive(Debug)]
pub struct UnlockWorkerInput {
    /// Resolved vault path passed to `paladin_auth_core::open`.
    pub path: PathBuf,
    /// Typed lock (`VaultLock::Plaintext` or `VaultLock::Encrypted`)
    /// passed to `paladin_auth_core::open`.
    pub lock: VaultLock,
}

/// Bundle a [`VaultLock`] with the resolved vault path from `current`
/// so the `gio::spawn_blocking paladin_auth_core::open` worker can move
/// both into its closure.
///
/// Symmetric partner of [`submit_unlock_app_state`] for the entry
/// side of the open worker: that composer owns the
/// `Locked → UnlockedBusy` state transition, this composer owns the
/// `(path, VaultLock)` capture the worker closure consumes. Both
/// inspect `current` *before* the transition so the path is captured
/// before [`AppState::enter_unlocking_busy`] would consume the
/// [`AppState::Locked`] variant. Together the two composers bracket
/// the worker spawn: running the state transition without the input
/// bundle (or vice versa) would leave `AppModel` with a busy gate
/// but no worker (or a worker but no busy gate).
///
/// Returns `Some(UnlockWorkerInput { path, lock })` iff `current` is
/// [`AppState::Locked`]; returns `None` for every other source state
/// (`Missing`, `Unlocked`, `UnlockedBusy`, `StartupError`) so a stray
/// `SubmitLock` from a non-`Locked` source is a benign no-op for the
/// worker spawn just as it is for the state machine.
///
/// `lock` is consumed by value because [`VaultLock::Encrypted`] wraps
/// a [`secrecy::SecretString`] that must move (not clone) into the
/// worker closure to keep zeroize-on-drop semantics intact across
/// the `gio::spawn_blocking` boundary.
///
/// The composer stays shape-only — it inspects only the [`AppState`]
/// variant and clones the carried path out — so the side-effect
/// decision in `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` without spinning up GTK / libadwaita
/// or constructing a real vault file.
#[must_use]
pub fn compose_unlock_worker_input(
    current: &AppState,
    lock: VaultLock,
) -> Option<UnlockWorkerInput> {
    match current {
        AppState::Locked { path } => Some(UnlockWorkerInput {
            path: path.clone(),
            lock,
        }),
        AppState::Missing { .. }
        | AppState::Unlocked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => None,
    }
}

/// Synchronous body of the `gio::spawn_blocking paladin_auth_core::open`
/// unlock worker fired by `AppModel::update` from
/// `AppMsg::UnlockDialogAction(UnlockDialogOutput::SubmitLock)`.
///
/// Consumes the [`UnlockWorkerInput`] by value, calls
/// `paladin_auth_core::Store::open(&path, lock)`, and bundles the outcome
/// into an [`UnlockWorkerCompletion`] via
/// [`route_unlock_open_completion`]. The carried [`VaultLock`] is
/// moved into the open call so the [`secrecy::SecretString`] held by
/// [`VaultLock::Encrypted`] zeroes on drop after the Argon2 KDF step
/// per DESIGN §4.4.
///
/// Extracting the worker body as a pure function lets
/// `AppModel::update`'s closure stay a thin
/// `gio::spawn_blocking(move || run_unlock_worker(input))` while the
/// real `Store::open` call stays unit-testable in
/// `tests/app_state_logic.rs` against tempfile-backed plaintext and
/// encrypted vaults — no GTK / libadwaita main loop required.
///
/// The returned [`UnlockWorkerCompletion`] carries the live
/// `(Vault, Store)` pair on success and `None` on every failure so
/// `AppModel::update`'s `apply_unlock_vault_install_inplace` /
/// `apply_unlock_dispatch_inplace` pair can apply the outcome
/// uniformly per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction".
#[must_use]
pub fn run_unlock_worker(input: UnlockWorkerInput) -> UnlockWorkerCompletion {
    let UnlockWorkerInput { path, lock } = input;
    let outcome = Store::open(&path, lock);
    route_unlock_open_completion(&path, outcome)
}

// ---------------------------------------------------------------------------
// Import dispatch helpers
//
// Symmetric partners of the edit / remove / add dispatch trios:
// `submit_import_app_state` + `apply_submit_import_inplace` for the
// entry side, `compose_import_worker_input` for the worker-input
// capture, `import_final_app_state` + `should_drop_import_dialog_after`
// + `import_dialog_msg_after` + `should_refresh_list_after_import` for
// the worker-completion trio, and `ImportDispatch` +
// `compose_import_dispatch` + `apply_import_dispatch_inplace` +
// `apply_import_vault_install_inplace` for the bundled apply path.
//
// Every helper stays shape-only (`AppState` discriminant inspection
// plus carried-path cloning) so `tests/app_state_logic.rs` exercises
// the routing and transition rules without spinning up GTK /
// libadwaita or running the real `Vault::mutate_and_save` import
// merge.
// ---------------------------------------------------------------------------

/// Transition [`AppState::Unlocked`] → [`AppState::UnlockedBusy`]
/// when [`crate::import_dialog::ImportDialogOutput::Submit`] dispatches
/// the `gio::spawn_blocking`
/// `Vault::mutate_and_save(|v| { from_file(...) → v.import_accounts(...) })`
/// import worker.
///
/// Symmetric partner of [`submit_remove_app_state`] /
/// [`submit_edit_app_state`] / [`submit_add_app_state`] for the
/// import path. The composer stays shape-only — it delegates to
/// [`AppState::enter_busy`] without re-deriving the transition — so
/// `tests/app_state_logic.rs` exercises the entry-side handoff
/// without spinning up GTK / libadwaita.
///
/// Returns `Some(UnlockedBusy { path })` iff `current` is
/// [`AppState::Unlocked`]; returns `None` for every other source state
/// so a stray import dispatch from a non-`Unlocked` window is a
/// benign no-op for the worker spawn.
#[must_use]
pub fn submit_import_app_state(current: &AppState) -> Option<AppState> {
    current.clone().enter_busy()
}

/// Apply [`submit_import_app_state`] in-place to `state`, leaving it
/// unchanged when the composer returns `None`.
///
/// Symmetric partner of [`apply_submit_remove_inplace`] /
/// [`apply_submit_edit_inplace`] / [`apply_submit_add_inplace`].
/// Returns `true` iff the state transitioned (source was `Unlocked`
/// → destination is `UnlockedBusy`); `AppModel::update` uses the
/// `true` return to gate the `gio::spawn_blocking` worker spawn so
/// the busy gate and the worker open and close in lockstep.
pub fn apply_submit_import_inplace(state: &mut AppState) -> bool {
    if let Some(new_state) = submit_import_app_state(state) {
        *state = new_state;
        true
    } else {
        false
    }
}

/// Bundle the live `(Vault, Store)` pair plus the dialog's validated
/// [`ImportSubmitPayload`] and the dispatch-site `import_time` into
/// an [`ImportWorkerInput`] so the
/// `gio::spawn_blocking
/// Vault::mutate_and_save(|v| { from_file(...) → v.import_accounts(...) })`
/// worker can move both into its closure.
///
/// Symmetric partner of [`compose_remove_worker_input`] /
/// [`compose_add_worker_input`] / [`compose_qr_worker_input`] for the
/// import path: that family inspects the [`AppState`] variant before
/// taking the pair so a stray Submit from a non-`Unlocked` source
/// (`Missing`, `Locked`, `UnlockedBusy`, `StartupError`) returns the
/// pair back through the `Err` arm so the caller can reinstall it via
/// [`apply_import_vault_install_inplace`] rather than dropping it.
///
/// `payload.options.paladin_auth_passphrase` is consumed by value because
/// it wraps a [`secrecy::SecretString`] that must move (not clone)
/// into the worker closure to keep zeroize-on-drop semantics intact
/// across the `gio::spawn_blocking` boundary.
///
/// The composer stays shape-only — it inspects only the [`AppState`]
/// variant discriminant on `current` — so the side-effect decision
/// in `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` against real `(Vault, Store)` pairs
/// constructed via `paladin_auth_core::Store::create` over a tempfile
/// vault.
pub fn compose_import_worker_input(
    current: &AppState,
    pair: (Vault, Store),
    payload: ImportSubmitPayload,
    import_time: SystemTime,
) -> Result<ImportWorkerInput, (Vault, Store)> {
    match current {
        AppState::Unlocked { .. } => {
            let (vault, store) = pair;
            let ImportSubmitPayload {
                source_path,
                options,
                conflict,
            } = payload;
            Ok(ImportWorkerInput {
                vault,
                store,
                source_path,
                options,
                conflict,
                import_time,
            })
        }
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => Err(pair),
    }
}

/// Unified state-transition composer for the import worker outcome.
///
/// Symmetric partner of [`remove_final_app_state`] for the import
/// path: every [`MergeOutcome`] variant — `Success`,
/// `DurabilityWarning`, `NotCommitted`, defensive `Inline` — lands on
/// the same `UnlockedBusy → Unlocked` rollback via
/// [`AppState::leave_busy`] because `Vault::mutate_and_save` is
/// authoritative for the rollback / durability-unconfirmed semantics
/// per docs/DESIGN.md §4.3. The dialog-drop / inline-message decisions
/// split off the typed outcome in sibling composers; this composer
/// owns only the state-machine rollback.
///
/// `outcome` is accepted for signature symmetry with the edit /
/// remove / add composers but is not inspected: every variant rolls
/// the busy gate back.
///
/// Returns `Some(Unlocked { path })` iff `current` is
/// [`AppState::UnlockedBusy`], and `None` from every other state so
/// a stray completion arriving while the cached state has already
/// transitioned away from `UnlockedBusy` does not install a phantom
/// `Unlocked` over another idle state.
#[must_use]
pub fn import_final_app_state(current: &AppState, _outcome: &MergeOutcome) -> Option<AppState> {
    current.clone().leave_busy()
}

/// Drop-decision projection for the
/// [`crate::import_dialog::ImportDialogComponent`] after an import
/// worker outcome.
///
/// The import dialog stays mounted on every outcome: success keeps
/// the dialog open on the post-merge counts panel until the user
/// clicks Dismiss, and every failure / warning keeps it open with
/// the inline error / warning visible so the user can retry. This
/// diverges from the edit / remove / add path where success drops
/// the dialog — matching the `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Component tree" > `ImportDialog` rule "keep the dialog on a
/// post-success counts panel until the user dismisses it".
///
/// The projection inspects only the typed [`MergeOutcome`] variant
/// — it does not consult [`AppState`] or the live `(Vault, Store)`
/// pair — so the side-effect decision in `AppModel::update` stays
/// unit-testable in `tests/app_state_logic.rs` without spinning up
/// GTK / libadwaita.
#[must_use]
pub fn should_drop_import_dialog_after(_outcome: &MergeOutcome) -> bool {
    false
}

/// Inline-message projection for the live
/// [`crate::import_dialog::ImportDialogComponent`] after an import
/// worker outcome.
///
/// Every outcome forwards
/// [`ImportDialogMsg::WorkerCompleted`] carrying the typed
/// [`MergeOutcome`]: success populates the merge summary so the
/// counts panel surfaces the `imported`/`skipped`/`replaced`/
/// `appended`/`warnings` rows; `DurabilityWarning` stages the inline
/// warning beneath the counts panel; `NotCommitted` / `Inline` stage
/// the inline error and leave the form draft intact so the user can
/// retry without re-entering options.
///
/// The projection clones the carried outcome so the
/// `Option<ImportDialogMsg>` it returns owns the inner state
/// independently of the dispatch site's borrow on `outcome`. The
/// clone is cheap because [`MergeOutcome`]'s arms wrap `MergeSummary`,
/// [`crate::import_dialog::InlineError`], or
/// [`crate::import_dialog::InlineWarning`] — all `Clone`-derived
/// value types — and the dispatch site pays it exactly once per
/// worker completion.
#[must_use]
pub fn import_dialog_msg_after(outcome: &MergeOutcome) -> Option<ImportDialogMsg> {
    Some(ImportDialogMsg::WorkerCompleted(outcome.clone()))
}

/// List-refresh projection after an import worker outcome.
///
/// Mirrors `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountListComponent` ("Refresh the store after every vault
/// mutation … without reordering surviving rows"):
///
/// * [`MergeOutcome::Success`] → `true`. The merge committed and the
///   list must reflect the new accounts.
/// * [`MergeOutcome::DurabilityWarning`] → `true`. Primary save
///   succeeded so the merged accounts are durable in memory; the
///   list must surface them even though the parent `fsync` was
///   uncertain.
/// * [`MergeOutcome::NotCommitted`] → `false`. `Vault::mutate_and_save`
///   restored the pre-attempt snapshot; the visible rows already
///   match the post-rollback state.
/// * [`MergeOutcome::Inline`] → `false`. The error fired before the
///   save path; vault state is unchanged.
#[must_use]
pub fn should_refresh_list_after_import(outcome: &MergeOutcome) -> bool {
    match outcome {
        MergeOutcome::Success(_) | MergeOutcome::DurabilityWarning(_) => true,
        MergeOutcome::NotCommitted(_) | MergeOutcome::Inline(_) => false,
    }
}

/// Bundled `AppModel::update` instructions for an import-worker
/// completion. Carries the four decisions the existing trio projects
/// ([`should_drop_import_dialog_after`], [`import_dialog_msg_after`],
/// [`import_final_app_state`], and [`should_refresh_list_after_import`])
/// so the dispatch site can apply the worker outcome in a single
/// shot without re-routing the [`MergeOutcome`].
///
/// Symmetric partner of [`RemoveDispatch`] / [`AddDispatch`] /
/// [`AddDispatch`] for the import path. The shape mirrors the
/// remove variant: an optional state replacement, an optional inline
/// message, a drop-dialog flag, and a refresh-list flag. No
/// `success_toast` field because the import dialog renders the post-
/// merge counts panel inline — the dialog itself is the success
/// surface — and the manual test plan is the authority for the
/// "confirm via toast on every success" sibling decision.
///
/// Not `Clone` because [`ImportDialogMsg::WorkerCompleted`] carries a
/// [`MergeOutcome`] in `dialog_msg` and `ImportDialogMsg` is not
/// `Clone` (its `PassphraseChanged(String)` arm carries a transient
/// keystroke shadow that we deliberately do not duplicate). The
/// dispatch is consumed exactly once per worker completion — the
/// dispatch site moves the bundle by value into the handler.
#[derive(Debug)]
pub struct ImportDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some` for
    /// the `UnlockedBusy → Unlocked` rollback that
    /// [`import_final_app_state`] returns regardless of typed
    /// outcome. `None` is the defensive case where the worker
    /// outcome arrives but `current` is not [`AppState::UnlockedBusy`]
    /// — `AppModel::update` leaves the state untouched rather than
    /// installing a phantom `Unlocked` over another idle state.
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::import_dialog::ImportDialogComponent`] controller —
    /// always `Some(ImportDialogMsg::WorkerCompleted(outcome))` so
    /// the dialog can populate the counts panel (on `Success`),
    /// the inline warning (on `DurabilityWarning`), or the inline
    /// error (on `NotCommitted` / `Inline`).
    pub dialog_msg: Option<ImportDialogMsg>,
    /// Whether `AppModel::update` should drop the live
    /// [`crate::import_dialog::ImportDialogComponent`] controller
    /// after applying [`Self::app_state`]. Always `false` because
    /// the dialog stays mounted on every outcome per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    /// `ImportDialog` ("keep the dialog on a post-success counts
    /// panel until the user dismisses it").
    pub drop_dialog: bool,
    /// Whether `AppModel::update` should re-project rows off the
    /// freshly reinstalled `(Vault, Store)` pair and emit
    /// [`crate::account_list::AccountListMsg::Refresh`] so the merged
    /// accounts appear in the visible row set. Mirrors
    /// [`should_refresh_list_after_import`] — `true` on `Success`
    /// and `DurabilityWarning`, `false` on `NotCommitted` / `Inline`.
    pub refresh_list: bool,
}

/// Bundle the trio of import-dispatch decisions into a single
/// [`ImportDispatch`] result so `AppModel::update` can apply the
/// worker outcome in one shot.
///
/// The composer is a pure aggregator over the existing trio — it
/// never re-derives the routing:
///
/// * `drop_dialog` mirrors [`should_drop_import_dialog_after`] (always
///   `false`).
/// * `dialog_msg` mirrors [`import_dialog_msg_after`] (always
///   `Some(WorkerCompleted(outcome))`).
/// * `app_state` mirrors [`import_final_app_state`] (the
///   `UnlockedBusy → Unlocked` rollback).
/// * `refresh_list` mirrors [`should_refresh_list_after_import`]
///   (`true` on `Success` / `DurabilityWarning`, `false` on
///   `NotCommitted` / `Inline`).
#[must_use]
pub fn compose_import_dispatch(current: &AppState, outcome: &MergeOutcome) -> ImportDispatch {
    ImportDispatch {
        app_state: import_final_app_state(current, outcome),
        dialog_msg: import_dialog_msg_after(outcome),
        drop_dialog: should_drop_import_dialog_after(outcome),
        refresh_list: should_refresh_list_after_import(outcome),
    }
}

/// Apply [`compose_import_dispatch`]'s state field in-place to
/// `state`, leaving it unchanged when the dispatch carries
/// `app_state = None`.
///
/// Symmetric partner of [`apply_remove_dispatch_inplace`] /
/// [`apply_add_dispatch_inplace`] / [`apply_add_dispatch_inplace`]
/// for the import path. Returns `true` when the state actually
/// transitioned (`dispatch.app_state` was `Some(_)` and `*state` now
/// mirrors the composer's projection), `false` otherwise.
pub fn apply_import_dispatch_inplace(state: &mut AppState, dispatch: &ImportDispatch) -> bool {
    if let Some(new_state) = dispatch.app_state.as_ref() {
        *state = new_state.clone();
        true
    } else {
        false
    }
}

/// Install the worker's `(Vault, Store)` pair from
/// [`crate::import_dialog::ImportWorkerCompletion`] into
/// `AppModel::vault` in-place.
///
/// Symmetric partner of [`apply_remove_vault_install_inplace`] /
/// [`apply_edit_vault_install_inplace`] /
/// [`apply_add_vault_install_inplace`] for the import path. The
/// import worker always returns the pair on every branch (`Success`,
/// `DurabilityWarning`, `NotCommitted`, `Inline`) because
/// `Vault::mutate_and_save` is the authoritative rollback /
/// durability source per docs/DESIGN.md §4.3. There is no `None` case to
/// dispatch on, so the helper takes the pair by value and always
/// installs.
///
/// `pair` is consumed by value because [`Vault`] and [`Store`] are
/// non-`Clone`. The wrapper stays shape-only — it does not inspect
/// the pair — so the side-effect decision in `AppModel::update`
/// stays unit-testable in `tests/app_state_logic.rs` against real
/// `(Vault, Store)` pairs constructed via `paladin_auth_core::Store::create`
/// over a tempfile vault.
pub fn apply_import_vault_install_inplace(
    vault_slot: &mut Option<(Vault, Store)>,
    pair: (Vault, Store),
) {
    *vault_slot = Some(pair);
}

// ===========================================================================
// Export dispatch — entry / worker-input / final state / dialog-drop
// projections symmetric to the import family above.
// ===========================================================================

/// Bundled export-dispatch result returned by [`compose_export_dispatch`].
///
/// Bundles the worker-outcome → (state, dialog, drop, toast) projections
/// the import / edit / remove dispatchers expose individually. Export's
/// success path adds the [`Self::success_toast`] field because the
/// `ExportDialog` closes on success and surfaces the written path through
/// an [`AdwToast`](adw::Toast) on the main overlay rather than an inline
/// counts panel (per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `ExportDialog`).
///
/// `Clone` is intentionally not derived: the contained
/// [`ExportDialogMsg`] wraps an [`crate::export_dialog::InlineError`] /
/// [`crate::export_dialog::InlineWarning`] which carry stable §5
/// `ErrorKind` discriminators plus rendered bodies, and the dispatch
/// site moves the bundle by value into the handler.
#[derive(Debug)]
pub struct ExportDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some` for
    /// the `UnlockedBusy → Unlocked` rollback that
    /// [`export_final_app_state`] returns regardless of typed
    /// outcome. `None` is the defensive case where the worker
    /// outcome arrives but `current` is not [`AppState::UnlockedBusy`].
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::export_dialog::ExportDialogComponent`] controller —
    /// always `Some(ExportDialogMsg::WorkerCompleted(outcome))` so
    /// the dialog can clear its busy latch and (on `Success`) emit
    /// `ExportDialogOutput::Close`, on `DurabilityWarning` stage
    /// the inline warning, on `Inline` stage the inline error.
    pub dialog_msg: Option<ExportDialogMsg>,
    /// Whether `AppModel::update` should drop the live
    /// [`crate::export_dialog::ExportDialogComponent`] controller
    /// after applying [`Self::app_state`]. `true` on
    /// [`ExportOutcome::Success`] so the dialog tears down and the
    /// success toast is the only post-action surface; `false` on
    /// `DurabilityWarning` / `Inline` so the inline warning / error
    /// stays visible until the user dismisses it.
    pub drop_dialog: bool,
    /// Toast body for the main [`adw::ToastOverlay`]. `Some(body)`
    /// on [`ExportOutcome::Success`] (names the written destination
    /// path via [`crate::export_dialog::format_export_success_toast`]);
    /// `None` on every other branch — `DurabilityWarning` and
    /// `Inline` surface inline in the dialog, not as toasts.
    pub success_toast: Option<String>,
}

/// Entry-side `AppState` transition for an export submit click.
///
/// Symmetric partner of [`submit_import_app_state`] for the export
/// path: `Unlocked → UnlockedBusy` so the busy gate dims the Export
/// button until the worker reports completion. Export does not
/// mutate the vault, but the same `(Vault, Store)` ownership model
/// applies — the pair moves into the worker for the duration of the
/// read.
///
/// Returns `Some(UnlockedBusy { path })` iff `current` is
/// [`AppState::Unlocked`]; returns `None` for every other source
/// state so a stray export dispatch from a non-`Unlocked` window is
/// a benign no-op for the worker spawn.
#[must_use]
pub fn submit_export_app_state(current: &AppState) -> Option<AppState> {
    current.clone().enter_busy()
}

/// Apply [`submit_export_app_state`] in-place to `state`, leaving it
/// unchanged when the composer returns `None`.
///
/// Symmetric partner of [`apply_submit_import_inplace`]. Returns
/// `true` iff the state transitioned (source was `Unlocked` →
/// destination is `UnlockedBusy`); `AppModel::update` uses the
/// `true` return to gate the `gio::spawn_blocking` worker spawn so
/// the busy gate and the worker open and close in lockstep.
pub fn apply_submit_export_inplace(state: &mut AppState) -> bool {
    if let Some(new_state) = submit_export_app_state(state) {
        *state = new_state;
        true
    } else {
        false
    }
}

/// Bundle the live `(Vault, Store)` pair plus the dialog's validated
/// [`ExportSubmitPayload`] into an [`ExportWorkerInput`] so the
/// `gio::spawn_blocking
/// write_secret_file_atomic(otpauth_list | encrypted)` worker can
/// move both into its closure.
///
/// Symmetric partner of [`compose_import_worker_input`] for the
/// export path: inspects the [`AppState`] variant before taking the
/// pair so a stray Submit from a non-`Unlocked` source returns the
/// pair back through the `Err` arm so the caller can reinstall it
/// via [`apply_export_vault_install_inplace`] rather than dropping
/// it.
///
/// `payload.encryption_options` is consumed by value because
/// [`paladin_auth_core::EncryptionOptions`] holds a
/// [`secrecy::SecretString`] that must move (not clone) into the
/// worker closure to keep zeroize-on-drop semantics intact across
/// the `gio::spawn_blocking` boundary.
///
/// The composer stays shape-only — it inspects only the
/// [`AppState`] variant discriminant on `current` — so the
/// side-effect decision in `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` against real `(Vault, Store)` pairs
/// constructed via `paladin_auth_core::Store::create` over a tempfile
/// vault.
pub fn compose_export_worker_input(
    current: &AppState,
    pair: (Vault, Store),
    payload: ExportSubmitPayload,
) -> Result<ExportWorkerInput, (Vault, Store)> {
    match current {
        AppState::Unlocked { .. } => {
            let (vault, store) = pair;
            let ExportSubmitPayload {
                destination,
                format,
                encryption_options,
            } = payload;
            Ok(ExportWorkerInput {
                vault,
                store,
                destination,
                format,
                encryption_options,
            })
        }
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => Err(pair),
    }
}

/// Unified state-transition composer for the export worker outcome.
///
/// Symmetric partner of [`import_final_app_state`] for the export
/// path: every [`ExportOutcome`] variant rolls
/// `UnlockedBusy → Unlocked` via [`AppState::leave_busy`] because
/// export does not mutate the vault; the busy gate releases on every
/// branch.
///
/// `outcome` is accepted for signature symmetry with the edit /
/// remove / add composers but is not inspected: every variant rolls
/// the busy gate back.
///
/// Returns `Some(Unlocked { path })` iff `current` is
/// [`AppState::UnlockedBusy`], and `None` from every other state so
/// a stray completion arriving while the cached state has already
/// transitioned away from `UnlockedBusy` does not install a phantom
/// `Unlocked` over another idle state.
#[must_use]
pub fn export_final_app_state(current: &AppState, _outcome: &ExportOutcome) -> Option<AppState> {
    current.clone().leave_busy()
}

/// Drop-decision projection for the
/// [`crate::export_dialog::ExportDialogComponent`] after an export
/// worker outcome.
///
/// The export dialog tears down on [`ExportOutcome::Success`] (the
/// post-action surface is the [`adw::Toast`] naming the written
/// path, not an inline counts panel); it stays mounted on
/// `DurabilityWarning` and `Inline` so the inline warning / error
/// is visible until the user dismisses it.
#[must_use]
pub fn should_drop_export_dialog_after(outcome: &ExportOutcome) -> bool {
    matches!(outcome, ExportOutcome::Success)
}

/// Dialog-message projection for the
/// [`crate::export_dialog::ExportDialogComponent`] after an export
/// worker outcome.
///
/// Always `Some(ExportDialogMsg::WorkerCompleted(outcome))` so the
/// dialog routes the typed outcome through `apply_msg` (clears the
/// busy latch on every branch; stages the inline warning / error
/// for `DurabilityWarning` / `Inline`; emits `Close` on `Success`).
///
/// `outcome` is consumed by value because [`ExportOutcome`] is not
/// `Clone` — `InlineError` / `InlineWarning` carry rendered bodies
/// that move into the dialog's reactive state.
#[must_use]
pub fn export_dialog_msg_after(outcome: ExportOutcome) -> Option<ExportDialogMsg> {
    Some(ExportDialogMsg::WorkerCompleted(outcome))
}

/// Success-toast projection for the main
/// [`adw::ToastOverlay`] after an export worker outcome.
///
/// Returns `Some(body)` only on [`ExportOutcome::Success`]; the body
/// is built from
/// [`crate::export_dialog::format_export_success_toast`] so the
/// wording stays in one place. `DurabilityWarning` and `Inline`
/// surface inline in the dialog (which stays mounted), not as
/// toasts.
#[must_use]
pub fn export_success_toast_after(outcome: &ExportOutcome, destination: &Path) -> Option<String> {
    match outcome {
        ExportOutcome::Success => Some(crate::export_dialog::format_export_success_toast(
            destination,
        )),
        ExportOutcome::DurabilityWarning(_) | ExportOutcome::Inline(_) => None,
    }
}

/// Bundle the quartet of export-dispatch decisions into a single
/// [`ExportDispatch`] result so `AppModel::update` can apply the
/// worker outcome in one shot.
///
/// The composer is a pure aggregator over the existing quartet — it
/// never re-derives the routing:
///
/// * `app_state` mirrors [`export_final_app_state`] (the
///   `UnlockedBusy → Unlocked` rollback).
/// * `dialog_msg` mirrors [`export_dialog_msg_after`] (always
///   `Some(WorkerCompleted(outcome))`).
/// * `drop_dialog` mirrors [`should_drop_export_dialog_after`]
///   (`true` on `Success`, `false` otherwise).
/// * `success_toast` mirrors [`export_success_toast_after`]
///   (`Some(body)` on `Success`, `None` otherwise).
///
/// `outcome` is consumed by value because [`ExportOutcome`] is not
/// `Clone`. The `app_state` and `success_toast` branches inspect the
/// discriminant beforehand so the dispatch stays unit-testable in
/// `tests/app_state_logic.rs` without re-constructing the typed
/// outcome.
#[must_use]
pub fn compose_export_dispatch(
    current: &AppState,
    outcome: &ExportOutcome,
    destination: &Path,
) -> ExportDispatch {
    let app_state = export_final_app_state(current, outcome);
    let drop_dialog = should_drop_export_dialog_after(outcome);
    let success_toast = export_success_toast_after(outcome, destination);
    // `dialog_msg` is the last projection because it consumes the
    // outcome by value — the earlier projections all take `&outcome`.
    let dialog_msg = export_dialog_msg_after(clone_export_outcome(outcome));
    ExportDispatch {
        app_state,
        dialog_msg,
        drop_dialog,
        success_toast,
    }
}

// `ExportOutcome` is intentionally non-`Clone` (carries
// `InlineError` / `InlineWarning` rendered strings; the type
// stays out of `AppMsg` clone semantics). The dispatch composer
// needs the outcome twice — once by reference for the toast /
// state projections, once by value for the dialog message — so
// reconstitute a shallow copy by inspecting the discriminant.
fn clone_export_outcome(outcome: &ExportOutcome) -> ExportOutcome {
    match outcome {
        ExportOutcome::Success => ExportOutcome::Success,
        ExportOutcome::DurabilityWarning(w) => ExportOutcome::DurabilityWarning(w.clone()),
        ExportOutcome::Inline(e) => ExportOutcome::Inline(e.clone()),
    }
}

/// Apply [`compose_export_dispatch`]'s state field in-place to
/// `state`, leaving it unchanged when the dispatch carries
/// `app_state = None`.
///
/// Symmetric partner of [`apply_import_dispatch_inplace`] for the
/// export path. Returns `true` when the state actually transitioned
/// (`dispatch.app_state` was `Some(_)` and `*state` now mirrors the
/// composer's projection), `false` otherwise.
pub fn apply_export_dispatch_inplace(state: &mut AppState, dispatch: &ExportDispatch) -> bool {
    if let Some(new_state) = dispatch.app_state.as_ref() {
        *state = new_state.clone();
        true
    } else {
        false
    }
}

/// Install the worker's `(Vault, Store)` pair from
/// [`crate::export_dialog::ExportWorkerCompletion`] into
/// `AppModel::vault` in-place.
///
/// Symmetric partner of [`apply_import_vault_install_inplace`] for
/// the export path. Export does not mutate the vault, so the
/// returned pair is the same one we moved into the worker — but
/// the round-trip keeps the ownership model identical to the import
/// / edit / remove / add paths so `AppModel::vault` is never
/// orphaned across the `gio::spawn_blocking` boundary.
///
/// `pair` is consumed by value because [`Vault`] and [`Store`] are
/// non-`Clone`. The wrapper stays shape-only — it does not inspect
/// the pair — so the side-effect decision in `AppModel::update`
/// stays unit-testable in `tests/app_state_logic.rs` against real
/// `(Vault, Store)` pairs constructed via `paladin_auth_core::Store::create`
/// over a tempfile vault.
pub fn apply_export_vault_install_inplace(
    vault_slot: &mut Option<(Vault, Store)>,
    pair: (Vault, Store),
) {
    *vault_slot = Some(pair);
}

// ---------------------------------------------------------------------------
// PassphraseDialog — pre-worker / post-worker composers
//
// `PassphraseDialog` mirrors the `RemoveDialog` shape: a typed
// effect (`PassphraseWorkerEffect::{Success, Failure}`) routes
// through a `compose_passphrase_dispatch` aggregator into
// `(app_state, dialog_msg, drop_dialog, success_toast)`. The
// success branch drops the dialog and raises an `AdwToast`; every
// failure branch keeps the dialog mounted with
// `PassphraseDialogMsg::WorkerFailed(outcome)` so the dialog re-
// renders the typed `save_not_committed` /
// `save_durability_unconfirmed` / defensive inline error per
// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Effect errors".
// ---------------------------------------------------------------------------

/// Pre-worker `Unlocked → UnlockedBusy` transition for the
/// `gio::spawn_blocking` passphrase-transition worker dispatched
/// by `AppMsg::PassphraseDialogAction(PassphraseDialogOutput::Submit(_))`.
///
/// Returns `Some(UnlockedBusy { path })` iff `current` is
/// [`AppState::Unlocked`], and `None` from every other state
/// (`Missing`, `Locked`, `UnlockedBusy`, `StartupError`). The
/// `None` arm is the defensive case for a stray `Submit` reaching
/// `AppModel::update` from a non-`Unlocked` source — `AppModel`
/// must not silently install a phantom `UnlockedBusy` that would
/// clobber the idle state.
#[must_use]
pub fn submit_passphrase_app_state(current: &AppState) -> Option<AppState> {
    current.clone().enter_busy()
}

/// Apply [`submit_passphrase_app_state`]'s transition in-place to
/// `state`, leaving it unchanged when the transition would return
/// `None`.
///
/// Returns `true` when the state actually transitioned (source was
/// `Unlocked` → destination is `UnlockedBusy`), `false` otherwise.
/// `AppModel::update` uses the `true` return to gate the
/// `gio::spawn_blocking` worker spawn — a `false` return is the
/// defensive no-op for a stray `Submit` from any non-`Unlocked`
/// source state.
pub fn apply_submit_passphrase_inplace(state: &mut AppState) -> bool {
    if let Some(new_state) = submit_passphrase_app_state(state) {
        *state = new_state;
        true
    } else {
        false
    }
}

/// Compose the [`PassphraseWorkerInput`] payload for the
/// `gio::spawn_blocking` passphrase-transition worker.
///
/// Bundles the live `(Vault, Store)` pair and the validated
/// [`PassphraseSubmitPayload`] into a [`PassphraseWorkerInput`] for
/// [`crate::passphrase_dialog::run_passphrase_worker`]. Gates on
/// the pre-transition source state: only [`AppState::Unlocked`]
/// returns `Ok(input)`; every other variant returns
/// `Err((vault, store))` so the caller can reinstall the pair
/// without losing the live unlocked vault.
///
/// `Result` rather than `Option` because the `(Vault, Store)` pair
/// is non-`Clone` — dropping it on a stray dispatch would lose the
/// user's open vault. The `Err((vault, store))` branch hands the
/// pair back so `apply_passphrase_vault_install_inplace` can put
/// it back in `AppModel.vault`. The [`PassphraseSubmitPayload`] is
/// dropped on the refusal arm so the carried
/// [`paladin_auth_core::EncryptionOptions`] zeroizes its
/// `secrecy::SecretString` per `ZeroizeOnDrop`.
///
/// # Errors
///
/// Returns `Err((vault, store))` when `current` is not
/// [`AppState::Unlocked`]; the pair is unchanged.
pub fn compose_passphrase_worker_input(
    current: &AppState,
    pair: (Vault, Store),
    payload: PassphraseSubmitPayload,
) -> Result<PassphraseWorkerInput, (Vault, Store)> {
    match current {
        AppState::Unlocked { .. } => {
            let (vault, store) = pair;
            Ok(PassphraseWorkerInput {
                vault,
                store,
                payload,
            })
        }
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => Err(pair),
    }
}

/// Install the worker's `(Vault, Store)` pair from
/// [`crate::passphrase_dialog::PassphraseWorkerCompletion`] into
/// `AppModel::vault` in-place.
///
/// Symmetric partner of [`apply_remove_vault_install_inplace`] for
/// the passphrase path. The pair is always reinstalled — the §4.5
/// passphrase transitions are authoritative for the rollback
/// (`save_not_committed`) and durability-unconfirmed semantics, so
/// the returned vault reflects the committed state regardless of
/// effect branch.
pub fn apply_passphrase_vault_install_inplace(
    vault_slot: &mut Option<(Vault, Store)>,
    pair: (Vault, Store),
) {
    *vault_slot = Some(pair);
}

/// `UnlockedBusy → Unlocked` rollback projection for the passphrase
/// worker outcome.
///
/// Mirrors [`remove_final_app_state`]: every
/// [`PassphraseWorkerEffect`] variant — `Success` and every
/// `Failure(PassphraseErrorOutcome)` projection — lands on the same
/// `UnlockedBusy → Unlocked` rollback via [`AppState::leave_busy`].
/// `Vault::set_passphrase` / `change_passphrase` / `remove_passphrase`
/// own the §4.5 rollback / durability semantics, so the state
/// machine returns to `Unlocked` uniformly. The dialog-drop /
/// inline-message / toast routing splits off the typed effect in
/// sibling helpers in [`compose_passphrase_dispatch`].
///
/// Returns `Some(Unlocked { path })` iff `current` is
/// [`AppState::UnlockedBusy`], and `None` from every other state.
#[must_use]
pub fn passphrase_final_app_state(
    current: &AppState,
    _effect: &PassphraseWorkerEffect,
) -> Option<AppState> {
    current.clone().leave_busy()
}

/// Drop-decision projection for the
/// [`crate::passphrase_dialog::PassphraseDialogComponent`] after a
/// passphrase worker outcome.
///
/// `true` on [`PassphraseWorkerEffect::Success`] — the dialog
/// dismisses; `false` on every `Failure(_)` branch so the dialog
/// stays open and re-renders the typed
/// `save_not_committed` / `save_durability_unconfirmed` /
/// defensive inline error.
#[must_use]
pub fn should_drop_passphrase_dialog_after(effect: &PassphraseWorkerEffect) -> bool {
    matches!(effect, PassphraseWorkerEffect::Success { .. })
}

/// Inline-message projection for the passphrase worker outcome.
///
/// * [`PassphraseWorkerEffect::Success`] → `None`. The dialog
///   dismisses so no inline body needs to render.
/// * [`PassphraseWorkerEffect::Failure(outcome)`] →
///   `Some(PassphraseDialogMsg::WorkerFailed(outcome))`. The dialog
///   stays open and the typed
///   [`crate::passphrase_dialog::PassphraseErrorOutcome`]
///   re-renders inline (DESIGN §4.5 owns the in-memory rollback /
///   replacement).
#[must_use]
pub fn passphrase_dialog_msg_after(effect: &PassphraseWorkerEffect) -> Option<PassphraseDialogMsg> {
    match effect {
        PassphraseWorkerEffect::Success { .. } => None,
        PassphraseWorkerEffect::Failure(outcome) => {
            Some(PassphraseDialogMsg::WorkerFailed(outcome.clone()))
        }
    }
}

/// Toast-body projection for the passphrase worker outcome.
///
/// * [`PassphraseWorkerEffect::Success { sub_flow, .. }`] →
///   `Some(format_passphrase_success_toast(sub_flow).to_string())`.
/// * [`PassphraseWorkerEffect::Failure`] → `None`. The dialog
///   stays mounted with the inline error / warning, which is the
///   surface that conveys the typed outcome — no toast layered on
///   top.
#[must_use]
pub fn passphrase_success_toast_after(effect: &PassphraseWorkerEffect) -> Option<String> {
    match effect {
        PassphraseWorkerEffect::Success { sub_flow, .. } => {
            Some(format_passphrase_success_toast(*sub_flow).to_string())
        }
        PassphraseWorkerEffect::Failure(_) => None,
    }
}

/// Visible vault-mode-flag projection for the passphrase worker
/// outcome.
///
/// * [`PassphraseWorkerEffect::Success { new_is_encrypted, .. }`] →
///   `Some(new_is_encrypted)`. The worker carries the post-transition
///   [`Vault::is_encrypted`] value, so downstream consumers (menu
///   sub-flow gating, auto-lock arming) do not need to round-trip
///   through the live vault getter.
/// * [`PassphraseWorkerEffect::Failure`] → `None`. The dialog stays
///   open and DESIGN §4.5 owns the in-memory mode rollback /
///   replacement, so no flag flip propagates outside the dialog.
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"`PassphraseDialog` full
/// implementation" line 3403 ("On success, update the visible
/// vault-mode flag before closing the dialog, post a status / toast
/// confirmation, and re-ask `IdlePolicy::should_arm` so the auto-lock
/// timer state tracks the new on-disk mode").
#[must_use]
pub fn passphrase_new_is_encrypted_after(effect: &PassphraseWorkerEffect) -> Option<bool> {
    match effect {
        PassphraseWorkerEffect::Success {
            new_is_encrypted, ..
        } => Some(*new_is_encrypted),
        PassphraseWorkerEffect::Failure(_) => None,
    }
}

/// Re-ask
/// [`IdlePolicy::should_arm`][paladin_auth_core::policy::auto_lock::IdlePolicy::should_arm]
/// after a passphrase worker outcome.
///
/// * [`PassphraseWorkerEffect::Success { new_is_encrypted, .. }`] →
///   `Some(IdlePolicy::should_arm(new_is_encrypted, settings))`. The
///   encrypted-only gating lives in core, so a `Remove` that flips the
///   vault to plaintext returns `Some(false)` regardless of the user's
///   `auto_lock_enabled` setting (DESIGN §6 / §7 plaintext no-op).
/// * [`PassphraseWorkerEffect::Failure`] → `None`. Failures keep the
///   dialog open and the in-memory mode is the §4.5
///   rollback / replacement value, so no re-arm decision is taken.
///
/// `settings` comes from the reinstalled vault (the worker hands the
/// pair back via [`apply_passphrase_vault_install_inplace`]
/// before the dispatch projection runs, so by the time the caller
/// reaches this helper the `(Vault, Store)` slot already reflects the
/// post-transition state). Threads the projection from
/// [`passphrase_new_is_encrypted_after`] so the
/// `Success` / `Failure` discrimination stays in one place.
#[must_use]
pub fn passphrase_should_arm_idle_after(
    effect: &PassphraseWorkerEffect,
    settings: &VaultSettings,
) -> Option<bool> {
    passphrase_new_is_encrypted_after(effect)
        .map(|is_encrypted| IdlePolicy::should_arm(is_encrypted, settings))
}

/// Bundle of dispatch decisions for the passphrase worker outcome.
///
/// Mirrors [`RemoveDispatch`] for the passphrase path.
/// `AppMsg::PassphraseWorkerCompleted` runs this aggregator over
/// the typed effect so the call site applies all five decisions
/// (state rollback, inline message forward, dialog drop, success
/// toast, visible vault-mode flag) without re-deriving the routing.
#[derive(Debug, Clone)]
pub struct PassphraseDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some` for
    /// the `UnlockedBusy → Unlocked` rollback that
    /// [`passphrase_final_app_state`] returns regardless of typed
    /// effect; `None` is the defensive case where the worker
    /// outcome arrives but `current` is not
    /// [`AppState::UnlockedBusy`].
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::passphrase_dialog::PassphraseDialogComponent`]
    /// controller. `Some(WorkerFailed(outcome))` for the failure
    /// branches; `None` for the success branch that drops the
    /// dialog.
    pub dialog_msg: Option<PassphraseDialogMsg>,
    /// Whether `AppModel::update` should drop the live
    /// [`crate::passphrase_dialog::PassphraseDialogComponent`]
    /// controller after applying [`Self::app_state`]. Drops on the
    /// success branch; stays mounted on every failure branch.
    pub drop_dialog: bool,
    /// Optional `AdwToast` body to raise on the
    /// `adw::ToastOverlay` after applying the worker outcome.
    /// `Some(body)` on success, `None` on every failure.
    pub success_toast: Option<String>,
    /// Visible vault-mode flag after the transition: `Some(true)` if
    /// the vault is encrypted, `Some(false)` if plaintext. `None` on
    /// every failure branch (the dialog stays open and the in-memory
    /// mode is owned by §4.5 rollback / replacement).
    ///
    /// `AppModel::update` consults this projection (alongside the
    /// reinstalled `(Vault, Store)` pair) to re-evaluate auto-lock
    /// arming via
    /// [`paladin_auth_core::policy::auto_lock::IdlePolicy::should_arm`] —
    /// the hook from line 3403 of the plan that the auto-lock
    /// section (line 3499) builds on.
    pub new_is_encrypted: Option<bool>,
}

/// Aggregate the passphrase-dispatch projections into a single
/// [`PassphraseDispatch`].
#[must_use]
pub fn compose_passphrase_dispatch(
    current: &AppState,
    effect: &PassphraseWorkerEffect,
) -> PassphraseDispatch {
    PassphraseDispatch {
        app_state: passphrase_final_app_state(current, effect),
        dialog_msg: passphrase_dialog_msg_after(effect),
        drop_dialog: should_drop_passphrase_dialog_after(effect),
        success_toast: passphrase_success_toast_after(effect),
        new_is_encrypted: passphrase_new_is_encrypted_after(effect),
    }
}

/// Apply [`compose_passphrase_dispatch`]'s state field in-place to
/// `state`, leaving it unchanged when the dispatch carries
/// `app_state = None`.
///
/// Returns `true` when the state actually transitioned, `false`
/// otherwise.
pub fn apply_passphrase_dispatch_inplace(
    state: &mut AppState,
    dispatch: &PassphraseDispatch,
) -> bool {
    if let Some(new_state) = dispatch.app_state.as_ref() {
        *state = new_state.clone();
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// SettingsComponent — pre-worker / post-worker composers
//
// Mirrors the `RemoveDialog` / `EditDialog` shape: a typed
// [`SettingsWorkerEffect`] (carrying the [`AcceptedChange`] and the
// classified [`SaveOutcome`]) routes through `compose_settings_dispatch`
// into `(app_state, dialog_msg, success_toast, reask_idle)`. The
// dialog stays mounted on every branch (live-apply does not close the
// `AdwPreferencesDialog` after each save), so there is no
// `drop_dialog` field — `dialog_msg` is always
// `Some(WorkerCompleted(effect))` so the state machine in the live
// `SettingsComponent` can run `apply_save_outcome` on the carried
// `AcceptedChange` / `SaveOutcome`.
//
// `reask_idle` flips on for auto-lock changes whose `SaveOutcome` left
// the new value on disk (Success / DurabilityWarning) per
// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"SettingsComponent" line 3468:
// "Re-ask `IdlePolicy::should_arm` after auto-lock toggle or timeout
// changes so the timer state tracks the new policy without
// re-inspecting the file." Clipboard-clear changes never affect the
// auto-lock policy, so they always return `false`. Rollback / inline
// outcomes leave the on-disk policy unchanged, so they also return
// `false`.
// ---------------------------------------------------------------------------

/// Pre-worker `Unlocked → UnlockedBusy` transition for the
/// `gio::spawn_blocking` settings save worker dispatched by
/// `AppMsg::SettingsDialogAction(SettingsDialogOutput::Submit)`.
///
/// Mirrors [`submit_remove_app_state`] / [`submit_edit_app_state`]:
/// returns `Some(UnlockedBusy { path })` iff `current` is
/// [`AppState::Unlocked`], and `None` from every other state
/// (`Missing`, `Locked`, `UnlockedBusy`, `StartupError`). The `None`
/// arm is the defensive case for a stray dispatch — `AppModel` must
/// not silently install a phantom `UnlockedBusy` that would clobber
/// the idle state.
#[must_use]
pub fn submit_settings_app_state(current: &AppState) -> Option<AppState> {
    current.clone().enter_busy()
}

/// Apply [`submit_settings_app_state`]'s transition in-place to
/// `state`, leaving it unchanged when the transition would return
/// `None`.
///
/// Returns `true` when the state actually transitioned (source was
/// `Unlocked` → destination is `UnlockedBusy`), `false` otherwise.
/// `AppModel::update` uses the `true` return to gate the
/// `gio::spawn_blocking` worker spawn.
pub fn apply_submit_settings_inplace(state: &mut AppState) -> bool {
    if let Some(new_state) = submit_settings_app_state(state) {
        *state = new_state;
        true
    } else {
        false
    }
}

/// Compose the [`SettingsWorkerInput`] payload for the
/// `gio::spawn_blocking` settings save worker.
///
/// Bundles the live `(Vault, Store)` pair and the typed
/// [`paladin_auth_core::SettingPatch`] from the dialog's
/// `DebounceOutcome::Save` / `ToggleOutcome::Save` into a
/// [`SettingsWorkerInput`] for
/// [`crate::settings::run_settings_worker`]. Gates on the
/// pre-transition source state: only [`AppState::Unlocked`] returns
/// `Ok(input)`; every other variant returns `Err((vault, store))` so
/// the caller can reinstall the pair without losing the live unlocked
/// vault.
///
/// `Result` rather than `Option` because the `(Vault, Store)` pair is
/// non-`Clone` — dropping it on a stray dispatch would lose the
/// user's open vault. The `Err((vault, store))` branch hands the pair
/// back so [`apply_settings_vault_install_inplace`] can put it back
/// in `AppModel.vault`.
///
/// # Errors
///
/// Returns `Err((vault, store))` when `current` is not
/// [`AppState::Unlocked`]; the pair is unchanged.
pub fn compose_settings_worker_input(
    current: &AppState,
    pair: (Vault, Store),
    patch: paladin_auth_core::SettingPatch,
) -> Result<SettingsWorkerInput, (Vault, Store)> {
    match current {
        AppState::Unlocked { .. } => {
            let (vault, store) = pair;
            Ok(SettingsWorkerInput {
                vault,
                store,
                patch,
            })
        }
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => Err(pair),
    }
}

/// Install the worker's `(Vault, Store)` pair from
/// [`crate::settings::SettingsWorkerCompletion`] into
/// `AppModel::vault` in-place.
///
/// Symmetric partner of [`apply_edit_vault_install_inplace`] for
/// the settings path. The pair is always reinstalled —
/// `Vault::mutate_and_save` is authoritative for the rollback /
/// durability-unconfirmed semantics per docs/DESIGN.md §4.3, so the
/// returned vault reflects the committed state regardless of which
/// [`SaveOutcome`] the worker classified.
pub fn apply_settings_vault_install_inplace(
    vault_slot: &mut Option<(Vault, Store)>,
    pair: (Vault, Store),
) {
    *vault_slot = Some(pair);
}

/// `UnlockedBusy → Unlocked` rollback projection for the settings
/// worker outcome.
///
/// Mirrors [`edit_final_app_state`]: every [`SettingsWorkerEffect`]
/// branch lands on the same `UnlockedBusy → Unlocked` rollback via
/// [`AppState::leave_busy`]. `Vault::mutate_and_save` is
/// authoritative for the §4.3 rollback / durability-unconfirmed
/// semantics, so the state machine returns to `Unlocked` uniformly
/// across success / durability-warning / rollback / inline branches.
///
/// Returns `Some(Unlocked { path })` iff `current` is
/// [`AppState::UnlockedBusy`], and `None` from every other state.
#[must_use]
pub fn settings_final_app_state(
    current: &AppState,
    _effect: &SettingsWorkerEffect,
) -> Option<AppState> {
    current.clone().leave_busy()
}

/// Inline-message projection for the settings worker outcome.
///
/// Always `Some(SettingsDialogMsg::WorkerCompleted(effect))` — the
/// dialog stays mounted on every branch and routes the typed effect
/// through [`crate::settings::apply_settings_dialog_msg`] so
/// `SettingsState::apply_save_outcome` promotes / leaves the
/// committed value and stamps `last_outcome` for the inline-subtitle
/// helpers.
#[must_use]
pub fn settings_dialog_msg_after(effect: &SettingsWorkerEffect) -> Option<SettingsDialogMsg> {
    Some(SettingsDialogMsg::WorkerCompleted(effect.clone()))
}

/// Toast-body projection for the settings worker outcome.
///
/// * [`SaveOutcome::Success`] →
///   `Some(format_settings_dialog_saved_toast().to_string())` per the
///   plan checklist line 3465 ("On successful live-apply, keep the
///   committed value visible and post a non-blocking settings-saved
///   `AdwToast` through the shared toast overlay").
/// * Every other [`SaveOutcome`] (`DurabilityWarning`, `Rollback`,
///   `Inline`) → `None`. The dialog's inline-subtitle row body is
///   the surface that conveys the warning / error — no toast is
///   layered on top because the row already carries the typed
///   message.
#[must_use]
pub fn settings_success_toast_after(effect: &SettingsWorkerEffect) -> Option<String> {
    match effect.outcome {
        SaveOutcome::Success => {
            Some(crate::settings::format_settings_dialog_saved_toast().to_string())
        }
        SaveOutcome::DurabilityWarning { .. }
        | SaveOutcome::Rollback { .. }
        | SaveOutcome::Inline { .. } => None,
    }
}

/// Idle-policy re-ask projection for the settings worker outcome.
///
/// Returns `true` iff `AppModel::update` should consult
/// [`paladin_auth_core::policy::auto_lock::IdlePolicy::should_arm`] against
/// the reinstalled vault after applying this effect:
///
/// * Auto-lock change ([`AcceptedChange::AutoLockEnabled`] or
///   [`AcceptedChange::AutoLockSecs`]) **and** outcome left the new
///   value on disk ([`SaveOutcome::Success`] or
///   [`SaveOutcome::DurabilityWarning`]) → `true`. The committed
///   `auto_lock_enabled` / `auto_lock_timeout_secs` value drives
///   `IdlePolicy::should_arm`, so the timer state must re-evaluate.
/// * Auto-lock change but the on-disk policy did not move
///   ([`SaveOutcome::Rollback`] / [`SaveOutcome::Inline`]) → `false`.
///   `Vault::mutate_and_save` restored the snapshot, so the
///   committed policy is unchanged.
/// * Clipboard-clear change (either field) → `false` regardless of
///   outcome. `IdlePolicy::should_arm` reads only the auto-lock
///   inputs from `VaultSettings`; the clipboard-clear toggles /
///   spinners cannot affect it.
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` line 3468: "Re-ask
/// `IdlePolicy::should_arm` after auto-lock toggle or timeout changes
/// so the timer state tracks the new policy without re-inspecting the
/// file."
#[must_use]
pub fn settings_reask_idle_after(effect: &SettingsWorkerEffect) -> bool {
    let affects_idle = matches!(
        effect.change,
        AcceptedChange::AutoLockEnabled(_) | AcceptedChange::AutoLockSecs(_)
    );
    let committed = matches!(
        effect.outcome,
        SaveOutcome::Success | SaveOutcome::DurabilityWarning { .. }
    );
    affects_idle && committed
}

/// Bundle of dispatch decisions for the settings worker outcome.
///
/// Mirrors [`AddDispatch`] for the settings path, sans
/// `drop_dialog` because live-apply keeps the `AdwPreferencesDialog`
/// mounted across every save. The dispatch site applies the four
/// decisions in one shot:
///
/// * `app_state` → install via [`apply_settings_dispatch_inplace`].
/// * `dialog_msg` → forward to the live `SettingsComponent`
///   controller so it can run
///   [`crate::settings::apply_settings_dialog_msg`].
/// * `success_toast` → raise on the shared `adw::ToastOverlay` on
///   success only.
/// * `reask_idle` → consult `idle_should_arm(vault)` against the
///   reinstalled pair when `true`.
#[derive(Debug, Clone)]
pub struct SettingsDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some` for
    /// the `UnlockedBusy → Unlocked` rollback that
    /// [`settings_final_app_state`] returns regardless of typed
    /// effect; `None` is the defensive case where the worker outcome
    /// arrives but `current` is not [`AppState::UnlockedBusy`].
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::settings::SettingsComponent`] controller. Always
    /// `Some(WorkerCompleted(effect))` so the dialog's state machine
    /// runs [`crate::settings::SettingsState::apply_save_outcome`]
    /// over the typed [`SettingsWorkerEffect`].
    pub dialog_msg: Option<SettingsDialogMsg>,
    /// Optional `AdwToast` body to raise on the
    /// `adw::ToastOverlay` after applying the worker outcome.
    /// `Some(body)` on [`SaveOutcome::Success`]; `None` on every
    /// other outcome (the row's inline subtitle is the surface that
    /// conveys the warning / error).
    pub success_toast: Option<String>,
    /// Whether `AppModel::update` should consult
    /// [`paladin_auth_core::policy::auto_lock::IdlePolicy::should_arm`]
    /// against the reinstalled vault after applying this effect.
    /// `true` only when the change is an auto-lock field AND the
    /// outcome left the new value on disk
    /// ([`SaveOutcome::Success`] / [`SaveOutcome::DurabilityWarning`]).
    pub reask_idle: bool,
}

/// Aggregate the settings-dispatch projections into a single
/// [`SettingsDispatch`].
#[must_use]
pub fn compose_settings_dispatch(
    current: &AppState,
    effect: &SettingsWorkerEffect,
) -> SettingsDispatch {
    SettingsDispatch {
        app_state: settings_final_app_state(current, effect),
        dialog_msg: settings_dialog_msg_after(effect),
        success_toast: settings_success_toast_after(effect),
        reask_idle: settings_reask_idle_after(effect),
    }
}

/// Apply [`compose_settings_dispatch`]'s state field in-place to
/// `state`, leaving it unchanged when the dispatch carries
/// `app_state = None`.
///
/// Returns `true` when the state actually transitioned, `false`
/// otherwise. `AppModel::update` can use the `true` return to gate
/// any state-installation-only follow-up work.
pub fn apply_settings_dispatch_inplace(state: &mut AppState, dispatch: &SettingsDispatch) -> bool {
    if let Some(new_state) = dispatch.app_state.as_ref() {
        *state = new_state.clone();
        true
    } else {
        false
    }
}

/// Seed the [`EffectOwnership`] slot stored on
/// `AppModel.effects` from the resolved startup [`AppState`].
///
/// Returns `Some(EffectOwnership::unlocked())` iff `state` is
/// [`AppState::Unlocked`], and `None` from every other variant
/// (`Missing` / `Locked` / `UnlockedBusy` / `StartupError`).
///
/// The `UnlockedBusy` arm returns `None` because that variant is
/// only ever reached *from* an existing `EffectOwnership::unlocked()`
/// via [`EffectOwnership::start_effect`]; an `AppModel` constructor
/// that ran startup probes and ended up there would be reconstructing
/// a stale in-flight state without a live worker, which the plan's
/// §"In-flight effect ownership" forbids. The `StartupError` arm
/// returns `None` because that surface intentionally owns no
/// `(Vault, Store)` pair — every mutating control is disabled until
/// the user retries through `StartupErrorComponent`.
///
/// `AppModel::init` calls this once from the
/// [`crate::app::model::run_startup_probes`] result so the in-flight
/// effect machinery is wired up immediately on a plaintext-open
/// success and stays unallocated for every other startup branch.
#[must_use]
pub fn initial_effects_for(state: &AppState) -> Option<EffectOwnership> {
    match state {
        AppState::Unlocked { .. } => Some(EffectOwnership::unlocked()),
        AppState::Missing { .. }
        | AppState::Locked { .. }
        | AppState::UnlockedBusy { .. }
        | AppState::StartupError { .. } => None,
    }
}

/// Routing decision for `AppMsg::Quit`: dispatch the teardown-and-quit
/// path now, or defer until the in-flight worker returns.
///
/// Wraps [`EffectOwnership::request_quit`] over the
/// `Option<EffectOwnership>` slot stored on
/// [`crate::app::model::AppModel`]'s `effects` field. When the slot
/// is `None` (no vault open — `Missing` / `Locked` / `StartupError`
/// startups leave it unallocated per [`initial_effects_for`]), there
/// is no worker to defer behind, so the decision is unconditionally
/// [`QuitDecision::Now`]; otherwise the slot's `EffectOwnership`
/// drives the decision and records the `pending_quit` flag on
/// `Deferred`.
///
/// `AppModel::update`'s `AppMsg::Quit` branch calls this helper then
/// matches: `Now` runs the teardown +
/// `relm4::main_application().quit()`; `Deferred` records the
/// pending flag on the in-flight state machine (already done by
/// `request_quit` itself) and waits for the worker-completion path
/// to surface [`crate::effect_ownership::CompleteOutcome::QuitNow`]
/// per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership".
pub fn handle_quit_request(effects: Option<&mut EffectOwnership>) -> QuitDecision {
    match effects {
        Some(state) => state.request_quit(),
        None => QuitDecision::Now,
    }
}

/// Routing decision for a vault-touching dispatch attempt: open the
/// busy gate now (transitioning `Unlocked → UnlockedBusy` on the
/// effect-ownership state machine), or refuse the dispatch.
///
/// Wraps [`EffectOwnership::start_effect`] over the
/// `Option<EffectOwnership>` slot stored on
/// [`crate::app::model::AppModel`]'s `effects` field. When the slot
/// is `None` (no vault open — `Missing` / `Locked` / `StartupError`
/// startups leave it unallocated per [`initial_effects_for`]), there
/// is no machinery to drive a worker through, so the decision is
/// unconditionally [`EffectStart::Rejected`]: a stray vault-touching
/// dispatch on a non-vault surface must never run. When the slot is
/// `Some(_)`, the contained `EffectOwnership` decides — `Accepted`
/// while idle, `Rejected` while another worker is already in flight
/// or the machinery has routed to [`crate::effect_ownership::AppState::StartupError`].
///
/// `AppModel::update`'s vault-touching dispatch branches call this
/// helper before moving the `(Vault, Store)` pair into a
/// `gio::spawn_blocking` worker, per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"In-flight effect ownership". An `Accepted` return is the gate
/// the caller respects when transitioning `AppState` via
/// [`AppState::enter_busy`].
pub fn handle_effect_request(
    effects: Option<&mut EffectOwnership>,
    kind: EffectKind,
) -> EffectStart {
    match effects {
        Some(state) => state.start_effect(kind),
        None => EffectStart::Rejected,
    }
}

/// Resolution of a worker completion against the in-flight machinery:
/// release the busy gate and propagate any deferred quit / lock
/// decisions accumulated while the worker was running.
///
/// Wraps [`EffectOwnership::complete_effect`] over the
/// `Option<EffectOwnership>` slot. When the slot is `None`
/// (defensive — a stray completion arriving after the slot was
/// already dropped, e.g. after [`handle_worker_lost`] routed the app
/// to `StartupError`), there is no machinery to update and no
/// deferred state to drain, so the decision is unconditionally
/// [`CompleteOutcome::Ready`]. When the slot is `Some(_)`, the
/// contained `EffectOwnership` decides — `vault_still_encrypted` is
/// the on-return `Vault::is_encrypted()` reading and gates whether a
/// `pending_lock` actually fires.
///
/// `AppModel::update`'s `*WorkerCompleted` branches call this helper
/// after reinstalling the returned `(Vault, Store)` pair so the
/// dispatch epilogue's deferred-quit and deferred-lock handlers see
/// the post-worker state, per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"In-flight effect ownership".
pub fn handle_effect_completion(
    effects: Option<&mut EffectOwnership>,
    vault_still_encrypted: bool,
) -> CompleteOutcome {
    match effects {
        Some(state) => state.complete_effect(vault_still_encrypted),
        None => CompleteOutcome::Ready,
    }
}

/// Routing decision for an auto-lock expiry signal: fire the
/// lock-on-expiry teardown now, defer until the in-flight worker
/// returns, or drop the signal (the vault is plaintext or no vault
/// is open).
///
/// Wraps [`EffectOwnership::auto_lock_expired`] over the
/// `Option<EffectOwnership>` slot. When the slot is `None` (no vault
/// open — `Missing` / `Locked` / `StartupError` startups leave it
/// unallocated), there is nothing to lock, so the decision is
/// unconditionally [`LockDecision::Ignored`]. When the slot is
/// `Some(_)`, the contained `EffectOwnership` decides — `Now` from
/// the idle `Unlocked` state on an encrypted vault, `Deferred` from
/// `UnlockedBusy` (with `pending_lock` recorded so
/// [`handle_effect_completion`] can resolve it against the
/// post-worker mode), and `Ignored` from the idle `Unlocked` state on
/// a plaintext vault (DESIGN §7 plaintext auto-lock no-op).
///
/// `AppModel::update`'s `AppMsg::AutoLockTimerFired` handler calls
/// this helper to decide whether to lock now, drop the signal, or
/// just record the deferral, per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"In-flight effect ownership" and §"Auto-lock and clipboard
/// auto-clear".
pub fn handle_auto_lock_expiry(
    effects: Option<&mut EffectOwnership>,
    vault_is_encrypted: bool,
) -> LockDecision {
    match effects {
        Some(state) => state.auto_lock_expired(vault_is_encrypted),
        None => LockDecision::Ignored,
    }
}

/// Resolution of a worker that failed before returning the
/// `(Vault, Store)` pair: route the in-flight machinery to
/// [`crate::effect_ownership::AppState::StartupError`] and drop the
/// deferred quit / lock flags.
///
/// Wraps [`EffectOwnership::worker_lost`] over the
/// `Option<EffectOwnership>` slot. When the slot is `None`
/// (defensive — a stray completion arriving after a prior
/// `worker_lost` already dropped the slot), there is no machinery to
/// update and the call is a no-op. When the slot is `Some(_)`, the
/// contained `EffectOwnership` transitions to
/// [`crate::effect_ownership::AppState::StartupError`] so the
/// `control_gating()` projection returns `all_disabled_for_busy`
/// until the user retries through `StartupErrorComponent`.
///
/// `AppModel::update`'s `*WorkerCompleted` branches call this helper
/// on the failure-before-return paths, then route the surface to
/// `StartupErrorComponent` without trying to reconstruct in-memory
/// vault state, per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"In-flight effect ownership".
pub fn handle_worker_lost(effects: Option<&mut EffectOwnership>) {
    if let Some(state) = effects {
        state.worker_lost();
    }
}

// ---------------------------------------------------------------------------
// Destroy-dialog dispatch
// ---------------------------------------------------------------------------

/// Bundle of dispatch decisions for the destroy worker outcome.
///
/// Per the `DestroyDialog` (Milestone 10) "Result routing" build
/// step in `docs/IMPLEMENTATION_PLAN_04_GTK.md`,
/// `AppMsg::DestroyVaultCompleted` runs [`compose_destroy_dispatch`]
/// over the typed [`DestroyWorkerEffect`] so the call site applies
/// all decisions (state transition, dialog teardown, held-vault
/// drop, secret wipe, `InitDialog` mount, toast, inline-error
/// forward) without re-deriving the routing.
///
/// Unlike [`RemoveDispatch`], the destroy worker is terminal — the
/// success / vault-gone branches drop the held `(Vault, Store)` pair
/// and transition to [`AppState::Missing`] rather than reinstalling
/// the pair. The failure branch keeps the dialog open and rolls the
/// busy gate back to [`AppState::Unlocked`] so the user can retry.
// Four independent post-effect decisions (`drop_dialog`,
// `drop_vault`, `wipe_secrets`, `mount_init`) each map to a distinct
// `AppModel::update` side effect, mirroring the per-surface bool
// fields on `RemoveDispatch` / `ControlGating`; a packed flag set
// would obscure the call sites.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct DestroyDispatch {
    /// New [`AppState`] to install on `AppModel.state`. `Some(Missing
    /// { path })` for the success / vault-gone branches (the destroy
    /// is terminal); `Some(Unlocked { path })` for the failure branch
    /// (roll the busy gate back so controls re-enable). `None` only
    /// when the cached state carried no path (defensive — every
    /// `UnlockedBusy` / `Unlocked` carries one).
    pub app_state: Option<AppState>,
    /// Inline message to forward to the live
    /// [`crate::destroy_dialog::DestroyDialogComponent`] controller.
    /// `Some(WorkerFailed(outcome))` on the failure branch (the
    /// dialog stays mounted and re-renders the inline error); `None`
    /// on the success / vault-gone branches that drop the dialog.
    pub dialog_msg: Option<DestroyDialogMsg>,
    /// Whether `AppModel::update` should drop the live
    /// [`crate::destroy_dialog::DestroyDialogComponent`] controller.
    /// `true` on success / vault-gone; `false` on failure (stays
    /// mounted so the inline error is visible and the user can retry).
    pub drop_dialog: bool,
    /// Whether `AppModel::update` should drop the held
    /// `(Vault, Store)` pair. `true` on success / vault-gone (the
    /// vault is gone from disk); `false` on failure (the pair was
    /// never handed to the worker, so the model still owns it).
    pub drop_vault: bool,
    /// Whether `AppModel::update` should wipe every secret-bearing UI
    /// buffer via the [`crate::secret_fields::clear_all`] roll-call.
    /// `true` on success / vault-gone; `false` on failure.
    pub wipe_secrets: bool,
    /// Whether `AppModel::update` should mount the `InitDialog` after
    /// transitioning to `Missing`. `true` on success / vault-gone;
    /// `false` on failure.
    pub mount_init: bool,
    /// Optional `AdwToast` body to raise on the shared
    /// `adw::ToastOverlay`. `Some(Vault deleted[. | (backup remained
    /// on disk).])` on success (backup-aware); `Some(Vault already
    /// gone.)` on vault-gone; `None` on failure (the inline error is
    /// the only surface).
    pub toast: Option<String>,
}

/// Resolve the destroyed-vault path from the cached [`AppState`].
///
/// Every `Unlocked` / `UnlockedBusy` state carries the resolved vault
/// path; this returns it so the success / vault-gone branches can
/// build [`AppState::Missing`] carrying the same path (so a follow-up
/// `InitDialog` creates the vault at the same location).
fn destroy_target_path(current: &AppState) -> Option<PathBuf> {
    current.path().map(Path::to_path_buf)
}

/// Aggregate the destroy-dispatch projections into a single
/// [`DestroyDispatch`].
///
/// * [`DestroyWorkerEffect::Success`] — transition to
///   [`AppState::Missing`], drop the dialog + held vault, wipe
///   secrets, mount `InitDialog`, and raise the backup-aware success
///   toast (`Vault deleted.` / `Vault deleted (backup remained on
///   disk).`).
/// * [`DestroyWorkerEffect::VaultMissing`] — identical terminal
///   routing (the destroy is idempotent), with the `Vault already
///   gone.` toast.
/// * [`DestroyWorkerEffect::Failure`] — keep the dialog open, roll
///   the busy gate back to [`AppState::Unlocked`], forward the inline
///   error, and raise no toast.
#[must_use]
pub fn compose_destroy_dispatch(
    current: &AppState,
    effect: &DestroyWorkerEffect,
) -> DestroyDispatch {
    let path = destroy_target_path(current);
    match effect {
        DestroyWorkerEffect::Success(report) => DestroyDispatch {
            app_state: path.map(|path| AppState::Missing { path }),
            dialog_msg: None,
            drop_dialog: true,
            drop_vault: true,
            wipe_secrets: true,
            mount_init: true,
            toast: Some(format_destroy_dialog_success_toast(report.backup_deleted).to_string()),
        },
        DestroyWorkerEffect::VaultMissing => DestroyDispatch {
            app_state: path.map(|path| AppState::Missing { path }),
            dialog_msg: None,
            drop_dialog: true,
            drop_vault: true,
            wipe_secrets: true,
            mount_init: true,
            toast: Some(format_destroy_dialog_vault_gone_toast().to_string()),
        },
        DestroyWorkerEffect::Failure(outcome) => DestroyDispatch {
            // Roll the busy gate back so the mutating controls
            // re-enable; the dialog stays open with the inline error.
            app_state: path.map(|path| AppState::Unlocked { path }),
            dialog_msg: Some(DestroyDialogMsg::WorkerFailed(outcome.clone())),
            drop_dialog: false,
            drop_vault: false,
            wipe_secrets: false,
            mount_init: false,
            toast: None,
        },
    }
}
