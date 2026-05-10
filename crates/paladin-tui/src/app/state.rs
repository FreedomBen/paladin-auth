// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppState` — the TUI's top-level state machine — plus the pure
//! startup-decision functions that map `inspect` / `open` outcomes
//! onto initial states.
//!
//! See `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Startup / vault modes" + "Auto-lock (per §6)".

use std::path::{Path, PathBuf};

use paladin_core::{format_unsafe_permissions, PaladinError, Store, Vault, VaultLock, VaultStatus};

/// Top-level UI state.
///
/// Variants other than [`AppState::Unlocked`] are deliberately
/// `Vault`/`Store`-free so the TUI cannot mutate vault data from
/// non-unlocked screens (per the plan's "non-mutating missing-vault /
/// startup-error" guarantee).
#[derive(Debug)]
pub enum AppState {
    /// Vault file does not exist; the TUI shows a non-mutating
    /// guidance screen telling the user to run `paladin init`.
    /// v0.1 TUI does not create vaults.
    MissingVault {
        /// The vault path that was inspected.
        path: PathBuf,
    },

    /// Encrypted vault: the unlock screen is shown and the user is
    /// prompted for the passphrase inside the TUI. A
    /// `decrypt_failed` from a previous attempt is held in `error`
    /// for inline display; every other `open` error replaces this
    /// state with [`AppState::StartupError`].
    Unlock {
        /// The vault path being unlocked.
        path: PathBuf,
        /// Inline error (most recently `decrypt_failed`), if any.
        error: Option<String>,
    },

    /// Auto-locked: an encrypted vault that was previously unlocked
    /// but has timed out per the auto-lock idle policy. Keeps only
    /// the resolved path plus pending clipboard-clear state needed
    /// for re-unlock and scheduled clear; the previous `Vault`,
    /// `Store`, cached key, and any modal-local secret state are
    /// discarded.
    Locked {
        /// The vault path; same as the previously unlocked state's.
        path: PathBuf,
    },

    /// Unlocked: the main list view is active. Owns the `Vault` and
    /// `Store` so save-bearing effects can call
    /// `Vault::mutate_and_save`, `Vault::hotp_advance`, and
    /// passphrase-transition methods directly.
    Unlocked {
        /// The vault path the `Store` reads/writes.
        path: PathBuf,
        /// The decrypted in-memory vault.
        vault: Vault,
        /// Persistence handle for the vault file.
        store: Store,
    },

    /// Non-mutating startup-error screen. Used when vault-path
    /// resolution fails or `inspect` / `open` returns anything other
    /// than `decrypt_failed`. Quits on `Esc` / `q` / `Ctrl-C`.
    StartupError {
        /// Vault path, if it was resolved before the failure.
        /// `None` if `default_vault_path` itself failed.
        path: Option<PathBuf>,
        /// Pre-rendered error text. `unsafe_permissions` uses the
        /// `Some(text)` from
        /// [`paladin_core::format_unsafe_permissions`] verbatim so
        /// all front ends share identical wording.
        message: String,
    },
}

/// Map a `paladin_core::inspect` result onto the corresponding initial
/// [`AppState`].
///
/// Returns `None` for [`VaultStatus::Plaintext`]: the caller must
/// follow up with `Store::open(path, VaultLock::Plaintext)` and feed
/// the outcome into [`decide_state_from_open`]. This split keeps the
/// pure decision logic separate from the impure `open` call so each
/// branch is unit-testable without touching the filesystem.
#[must_use]
pub fn decide_state_from_inspect(
    path: &Path,
    inspect: Result<VaultStatus, PaladinError>,
) -> Option<AppState> {
    match inspect {
        Ok(VaultStatus::Missing) => Some(AppState::MissingVault {
            path: path.to_path_buf(),
        }),
        Ok(VaultStatus::Encrypted) => Some(AppState::Unlock {
            path: path.to_path_buf(),
            error: None,
        }),
        Ok(VaultStatus::Plaintext) => None,
        Err(err) => Some(AppState::StartupError {
            path: Some(path.to_path_buf()),
            message: render_error_message(&err),
        }),
    }
}

/// Map a `Store::open` result onto the corresponding initial
/// [`AppState`].
#[must_use]
pub fn decide_state_from_open(
    path: PathBuf,
    open: Result<(Vault, Store), PaladinError>,
) -> AppState {
    match open {
        Ok((vault, store)) => AppState::Unlocked { path, vault, store },
        Err(err) => AppState::StartupError {
            path: Some(path),
            message: render_error_message(&err),
        },
    }
}

/// Render an error for the startup-error screen.
///
/// `unsafe_permissions` errors use the `Some(text)` from
/// [`paladin_core::format_unsafe_permissions`] verbatim so the CLI,
/// TUI, and GUI surface identical wording; every other error falls
/// back to the error's `Display` implementation.
#[must_use]
pub fn render_error_message(error: &PaladinError) -> String {
    format_unsafe_permissions(error).unwrap_or_else(|| error.to_string())
}

/// Build the TUI's initial state from the optional `--vault`
/// command-line override.
///
/// Mirrors `IMPLEMENTATION_PLAN_03_TUI.md` "Startup / vault modes":
///
/// 1. Resolve the vault path (`--vault` overrides `default_vault_path`).
/// 2. Call [`paladin_core::inspect`].
/// 3. Branch on [`VaultStatus`]; plaintext vaults are opened
///    immediately, encrypted vaults defer to the unlock screen,
///    missing vaults open the guidance screen, and any error from
///    path resolution / `inspect` / plaintext `open` lands on the
///    non-mutating startup-error screen.
pub fn build_initial_state(vault: Option<PathBuf>) -> AppState {
    let path: PathBuf = match vault {
        Some(p) => p,
        None => match paladin_core::default_vault_path() {
            Ok(p) => p,
            Err(err) => {
                return AppState::StartupError {
                    path: None,
                    message: render_error_message(&err),
                };
            }
        },
    };

    let inspect = paladin_core::inspect(&path);
    if let Some(state) = decide_state_from_inspect(&path, inspect) {
        return state;
    }
    // `VaultStatus::Plaintext` — open immediately, no passphrase prompt.
    let open = Store::open(&path, VaultLock::Plaintext);
    decide_state_from_open(path, open)
}
