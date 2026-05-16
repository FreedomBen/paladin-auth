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

use paladin_core::{PaladinError, Store, Vault, VaultLock, VaultStatus};

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
    /// when the `gio::spawn_blocking paladin_core::open` worker takes
    /// the submitted [`paladin_core::VaultLock`].
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
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction".
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
    /// when the `gio::spawn_blocking paladin_core::open` worker
    /// returns a typed wrong-passphrase failure (`DecryptFailed`,
    /// `InvalidPassphrase`).
    ///
    /// Symmetric partner of [`Self::enter_unlocking_busy`] for the
    /// failure return path: the busy window that
    /// `enter_unlocking_busy` opens for the unlock worker is rolled
    /// back here so the dialog's passphrase entry becomes
    /// interactive again. Per `IMPLEMENTATION_PLAN_04_GTK.md`
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

/// Compose [`decide_unlock_failure_action`] and
/// [`apply_unlock_failure_action`] into the single entry point
/// `AppModel`'s future worker-error branch calls when the
/// `gio::spawn_blocking paladin_core::open` worker returns an
/// `Err(PaladinError)`.
///
/// Bypassing the intermediate [`UnlockFailureAction`] keeps
/// `AppModel::update` a thin shell: one call goes from the typed
/// `PaladinError` directly to the concrete [`UnlockFailureEffect`]
/// the update path applies — forwarding a
/// [`UnlockDialogMsg::OpenFailedInline`] to the live
/// [`crate::unlock_dialog::UnlockDialogComponent`] for the wrong-
/// passphrase branch, or replacing `AppModel.state` with the
/// carried [`AppState::StartupError`] for every other open failure.
/// The intermediate helpers stay public so the pure-logic tests in
/// `tests/app_state_logic.rs` can pin the per-step decisions
/// independently.
#[must_use]
pub fn route_unlock_failure_effect(path: &Path, err: &PaladinError) -> UnlockFailureEffect {
    apply_unlock_failure_action(decide_unlock_failure_action(path, err))
}

/// Decide the new [`AppState`] after the unlock worker reports an
/// `Ok((Vault, Store))` outcome.
///
/// The `gio::spawn_blocking paladin_core::open` worker fired by
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
/// `gio::spawn_blocking paladin_core::open` worker returns an
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
/// `gio::spawn_blocking paladin_core::open` unlock worker returns.
///
/// Wraps the success / failure halves into a single typed enum so the
/// worker callback in `AppModel::update` can dispatch on the unified
/// outcome with a single match. Mirrors the `Result<(Vault, Store),
/// PaladinError>` shape the worker produces: `Success` carries the
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
    /// The worker returned `Err(PaladinError)`. The carried effect
    /// either keeps the dialog mounted with an inline error
    /// (wrong / empty passphrase) or transitions `AppModel` to the
    /// non-mutating [`AppState::StartupError`] surface.
    Failure(UnlockFailureEffect),
}

/// Unified dispatch for the `gio::spawn_blocking paladin_core::open`
/// unlock worker outcome.
///
/// Wraps [`route_unlock_success_effect`] and
/// [`route_unlock_failure_effect`] so `AppModel::update` can fan out
/// from the worker's `Result` into the correct
/// [`UnlockWorkerEffect`] variant with a single call. The
/// `Ok(())` arm represents `Ok((Vault, Store))` from the worker — the
/// pure-logic dispatch only owns the state-machine transition, while
/// the live pair is installed separately into `AppModel.vault`. The
/// `Err(&PaladinError)` arm forwards the typed error to
/// [`route_unlock_failure_effect`] so the inline-passphrase vs
/// startup-transition routing decision stays in one place.
///
/// The intermediate helpers stay public so the pure-logic tests in
/// `tests/app_state_logic.rs` can pin the per-step decisions
/// independently from this unified entry.
#[must_use]
pub fn route_unlock_worker_outcome(
    path: &Path,
    outcome: Result<(), &PaladinError>,
) -> UnlockWorkerEffect {
    match outcome {
        Ok(()) => UnlockWorkerEffect::Success(route_unlock_success_effect(path)),
        Err(err) => UnlockWorkerEffect::Failure(route_unlock_failure_effect(path, err)),
    }
}

/// Bundled outcome of the `gio::spawn_blocking paladin_core::open`
/// unlock worker.
///
/// The worker calls `paladin_core::Store::open(path, lock)` which
/// returns `Result<(Vault, Store), PaladinError>`. This struct fans
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
/// derived: [`paladin_core::Vault`] / [`paladin_core::Store`] are
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

/// Bundle the `Result<(Vault, Store), PaladinError>` returned by
/// `paladin_core::Store::open` into an [`UnlockWorkerCompletion`].
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
/// [`paladin_core::Vault`] and [`paladin_core::Store`] are non-
/// `Clone`; the live pair must move into the resulting
/// [`UnlockWorkerCompletion`] so zeroize-on-drop semantics survive
/// the `gio::spawn_blocking` boundary.
///
/// The composer stays shape-only — it inspects only the worker
/// `Result` discriminant — so the side-effect decision in
/// `AppModel::update` stays unit-testable in
/// `tests/app_state_logic.rs` against real `(Vault, Store)` pairs
/// constructed via `paladin_core::Store::create` over a tempfile
/// vault.
#[must_use]
pub fn route_unlock_open_completion(
    path: &Path,
    outcome: Result<(Vault, Store), PaladinError>,
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
///   surface per `IMPLEMENTATION_PLAN_04_GTK.md` §"Effect errors".
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
///   surface per `IMPLEMENTATION_PLAN_04_GTK.md` §"Effect errors".
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
/// before the `gio::spawn_blocking paladin_core::open` worker
/// spawns. Together the two composers bracket the busy window so
/// the [`AppState::is_busy`] / [`AppState::allows_mutating_menu`]
/// gating in [`AppState`] covers the full open worker lifetime per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction".
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
/// `gio::spawn_blocking paladin_core::open` worker spawn — a `false`
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
/// `next`, add / remove / rename, settings saves, import / export,
/// passphrase transitions) when they reinstall the pair after a
/// worker return.
///
/// The wrapper stays shape-only — it inspects only the `Option`
/// discriminant — so the side-effect decision in `AppModel::update`
/// stays unit-testable in `tests/app_state_logic.rs` against real
/// `(Vault, Store)` pairs constructed via `paladin_core::Store::create`
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

/// Worker input bundled by `AppMsg::UnlockDialogAction(SubmitLock)`
/// for the `gio::spawn_blocking paladin_core::open` worker.
///
/// Carries the resolved vault path captured from the current
/// [`AppState::Locked`] source state alongside the typed
/// [`paladin_core::VaultLock`] forwarded from
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
    /// Resolved vault path passed to `paladin_core::open`.
    pub path: PathBuf,
    /// Typed lock (`VaultLock::Plaintext` or `VaultLock::Encrypted`)
    /// passed to `paladin_core::open`.
    pub lock: VaultLock,
}

/// Bundle a [`VaultLock`] with the resolved vault path from `current`
/// so the `gio::spawn_blocking paladin_core::open` worker can move
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
