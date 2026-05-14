// SPDX-License-Identifier: AGPL-3.0-or-later

//! Startup-error pure-logic glue for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" and
//! §"Vault interaction", `AppModel` runs `paladin_core::default_vault_path()`
//! and `paladin_core::inspect(path)` at startup, then opens the vault
//! through `paladin_core::open(path, lock)`. Three categories of
//! failure route to `StartupErrorComponent`, which never creates,
//! overwrites, or repairs vault files:
//!
//! * `default_vault_path` failure (no platform home).
//! * `inspect` failure (corrupted header, unsupported format, …).
//! * Open failure other than wrong passphrase
//!   (`unsafe_permissions`, `wrong_vault_lock`, `invalid_header`,
//!   `invalid_payload`, `unsupported_format_version`,
//!   `kdf_params_out_of_bounds`, `io_error`).
//!
//! "Wrong passphrase" — `DecryptFailed` (AEAD authentication failed)
//! and `InvalidPassphrase` (empty / pre-KDF rejection) — stays inline
//! on `UnlockComponent` (or `InitDialog` for the encrypted-create
//! path), matching the CLI / TUI which never escalate a passphrase
//! retry to a startup-error transition.
//!
//! `UnsafePermissions` is rendered through
//! [`paladin_core::format_unsafe_permissions`] so wording matches the
//! CLI and TUI verbatim. Every other variant falls back to the
//! typed `Display` text. The pure-logic split lets
//! `tests/startup_error_logic.rs` exercise the routing and rendering
//! without a display server; the `StartupErrorComponent` widgetry
//! reads `rendered` directly into its `AdwStatusPage` body.

use std::path::{Path, PathBuf};

use paladin_core::{format_unsafe_permissions, ErrorKind, PaladinError, VaultStatus};

/// Which startup step produced the error.
///
/// The `StartupErrorComponent` does not branch on the source for its
/// chrome (retry + quit only — per §"Vault interaction", picking a
/// different vault path is out of scope for v0.2), but the field is
/// carried so callers can log / instrument routing decisions and so
/// the retry handler knows which step to re-run from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupErrorSource {
    /// `paladin_core::default_vault_path()` returned `Err`.
    PathResolution,
    /// `paladin_core::inspect(path)` returned `Err`.
    Inspect,
    /// `paladin_core::open(path, lock)` returned a non-passphrase `Err`.
    Open,
}

/// Non-mutating startup / open error displayed by
/// `StartupErrorComponent`.
///
/// All fields are presentation-side projections of a [`PaladinError`]
/// — no source-error reference is kept so the model can be cloned and
/// stored in `AppModel::StartupError` without lifetime gymnastics.
#[derive(Debug, Clone)]
pub struct StartupError {
    /// Which step produced the error.
    pub source: StartupErrorSource,
    /// Stable §5 [`ErrorKind`] discriminator, copied from
    /// `PaladinError::kind`. Consumers read this to drive
    /// instrumentation / structured logging.
    pub kind: ErrorKind,
    /// Display body for the `AdwStatusPage`. Uses
    /// [`paladin_core::format_unsafe_permissions`] for the
    /// `UnsafePermissions` variant; otherwise the typed `Display`
    /// text.
    pub rendered: String,
}

impl StartupError {
    /// Build a [`StartupError`] for a `default_vault_path` failure.
    #[must_use]
    pub fn from_path_resolution(err: &PaladinError) -> Self {
        Self {
            source: StartupErrorSource::PathResolution,
            kind: err.kind(),
            rendered: render_startup_error(err),
        }
    }

    /// Build a [`StartupError`] for an `inspect` failure.
    #[must_use]
    pub fn from_inspect(err: &PaladinError) -> Self {
        Self {
            source: StartupErrorSource::Inspect,
            kind: err.kind(),
            rendered: render_startup_error(err),
        }
    }

    /// Build a [`StartupError`] for an `open` failure that has
    /// already been classified as non-passphrase.
    #[must_use]
    pub fn from_open(err: &PaladinError) -> Self {
        Self {
            source: StartupErrorSource::Open,
            kind: err.kind(),
            rendered: render_startup_error(err),
        }
    }
}

/// Decision tag for routing a [`PaladinError`] returned by
/// `paladin_core::open`.
///
/// The `UnlockComponent` / `InitDialog` keeps wrong-passphrase
/// retries inline so the user can re-type; every other failure mode
/// transitions `AppModel` to `StartupError`.
#[derive(Debug, Clone)]
pub enum OpenErrorRouting {
    /// Wrong passphrase or empty passphrase — surface inline at the
    /// passphrase entry component.
    InlinePassphrase,
    /// Non-authentication failure — transition `AppModel` to
    /// `StartupError(StartupErrorComponent)`.
    Startup(StartupError),
}

/// Classify a `paladin_core::open` failure into the routing decision
/// described in §"Vault interaction" of the plan.
#[must_use]
pub fn classify_open_error(err: &PaladinError) -> OpenErrorRouting {
    match err.kind() {
        ErrorKind::DecryptFailed | ErrorKind::InvalidPassphrase => {
            OpenErrorRouting::InlinePassphrase
        }
        _ => OpenErrorRouting::Startup(StartupError::from_open(err)),
    }
}

/// Render a [`PaladinError`] for the `StartupErrorComponent` body.
///
/// `UnsafePermissions` routes through
/// [`paladin_core::format_unsafe_permissions`] so the wording matches
/// the CLI and TUI exactly (path, subject, actual / expected modes,
/// chmod hint). Other variants fall back to the typed `Display`,
/// which already carries the stable §5 field values verbatim.
#[must_use]
pub fn render_startup_error(err: &PaladinError) -> String {
    format_unsafe_permissions(err).unwrap_or_else(|| err.to_string())
}

/// Re-run the startup probe: vault-path resolution followed by
/// `inspect`. Returns the resolved `(path, status)` tuple on success
/// or a [`StartupError`] tagged with the failing step on error.
///
/// The closures are taken by value (`FnOnce`) because retry is a
/// one-shot operation per `StartupErrorComponent` action — the
/// caller spawns a fresh retry handler on each click.
///
/// `inspect` is not invoked if `resolve` fails. This matches the
/// startup sequence in §"Vault interaction" where `inspect` always
/// runs against the resolved path; in particular, an `inspect`-
/// sourced error implies that path resolution succeeded.
pub fn retry<R, I>(resolve: R, inspect: I) -> Result<(PathBuf, VaultStatus), StartupError>
where
    R: FnOnce() -> Result<PathBuf, PaladinError>,
    I: FnOnce(&Path) -> Result<VaultStatus, PaladinError>,
{
    let path = resolve().map_err(|err| StartupError::from_path_resolution(&err))?;
    let status = inspect(&path).map_err(|err| StartupError::from_inspect(&err))?;
    Ok((path, status))
}
