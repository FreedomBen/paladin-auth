// SPDX-License-Identifier: AGPL-3.0-or-later

//! Top-level `AppModel` state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" and
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
//!   `paladin_core::default_vault_path()`. `Ok(path)` returns `None`
//!   (proceed to inspect); `Err(_)` returns
//!   `Some(AppState::StartupError { path: None, .. })` because no
//!   path was resolved.
//! * [`decide_state_from_inspect`] handles
//!   `paladin_core::inspect(path)`. The three `Ok` variants route to
//!   `Missing` / `Locked` / `None` (for `Plaintext`); `Err(_)`
//!   routes to `StartupError` tagged
//!   [`crate::startup_error::StartupErrorSource::Inspect`].
//!
//! Open failures arrive after `paladin_core::open` returns; the
//! routing decision splits passphrase retries (which stay inline on
//! the `UnlockComponent` / `InitDialog` passphrase surface) from
//! every other failure (which transitions to `StartupError`).
//! [`decide_state_from_open_error`] returns an [`OpenErrorOutcome`]
//! the caller pattern-matches against.

use std::path::{Path, PathBuf};

use paladin_core::{PaladinError, VaultStatus};

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

    /// Transition [`AppState::Unlocked`] → [`AppState::UnlockedBusy`]
    /// when a vault-touching worker takes the `(Vault, Store)` pair.
    ///
    /// Returns `None` from every other state — `Missing` / `Locked`
    /// / `StartupError` have no vault to hand off, and
    /// `UnlockedBusy` already serializes through one worker per
    /// §"In-flight effect ownership".
    #[must_use]
    pub fn enter_busy(self) -> Option<Self> {
        match self {
            Self::Unlocked { path } => Some(Self::UnlockedBusy { path }),
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

/// Routing decision for a `paladin_core::open` failure.
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

/// Map a `paladin_core::default_vault_path()` outcome onto an
/// optional initial [`AppState`].
///
/// * `Ok(path)` → `None` (proceed to `inspect`).
/// * `Err(_)` → `Some(AppState::StartupError { path: None, .. })`
///   tagged [`crate::startup_error::StartupErrorSource::PathResolution`].
#[must_use]
pub fn decide_state_from_path_resolution(
    resolution: Result<PathBuf, PaladinError>,
) -> Option<AppState> {
    match resolution {
        Ok(_) => None,
        Err(err) => Some(AppState::StartupError {
            path: None,
            error: StartupError::from_path_resolution(&err),
        }),
    }
}

/// Map a `paladin_core::inspect(path)` outcome onto an optional
/// initial [`AppState`].
///
/// * `Ok(VaultStatus::Missing)` → `Some(AppState::Missing)`.
/// * `Ok(VaultStatus::Encrypted)` → `Some(AppState::Locked)`.
/// * `Ok(VaultStatus::Plaintext)` → `None`. The caller follows up
///   with `paladin_core::open(path, VaultLock::Plaintext)` on the
///   GTK main loop per §"Vault interaction".
/// * `Err(_)` → `Some(AppState::StartupError)` tagged
///   [`crate::startup_error::StartupErrorSource::Inspect`].
#[must_use]
pub fn decide_state_from_inspect(
    path: &Path,
    inspect: Result<VaultStatus, PaladinError>,
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

/// Classify a `paladin_core::open` failure into an [`OpenErrorOutcome`].
///
/// Wrong passphrase (`DecryptFailed`, `InvalidPassphrase`) stays
/// inline on the active passphrase surface; every other failure
/// transitions `AppModel` to
/// `AppState::StartupError { path: Some(path), .. }` tagged
/// [`crate::startup_error::StartupErrorSource::Open`].
#[must_use]
pub fn decide_state_from_open_error(path: &Path, err: &PaladinError) -> OpenErrorOutcome {
    match classify_open_error(err) {
        OpenErrorRouting::InlinePassphrase => OpenErrorOutcome::InlinePassphrase,
        OpenErrorRouting::Startup(startup) => OpenErrorOutcome::Startup(AppState::StartupError {
            path: Some(path.to_path_buf()),
            error: startup,
        }),
    }
}

/// Routing decision for a `paladin_core::open` failure reported by
/// the future `gio::spawn_blocking` unlock worker fired by
/// [`crate::unlock_dialog::UnlockDialogComponent`].
///
/// Pairs with [`OpenErrorOutcome`] (used by `run_startup_probes` on
/// the plaintext-startup path) but carries the typed
/// [`crate::unlock_dialog::InlineError`] projection so `AppModel`'s
/// worker call site can dispatch
/// [`crate::unlock_dialog::UnlockDialogMsg::OpenFailedInline`]
/// directly without re-routing the typed `PaladinError` here.
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

/// Complete the routing of an unlock-worker `paladin_core::open`
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
pub fn decide_unlock_failure_action(path: &Path, err: &PaladinError) -> UnlockFailureAction {
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
