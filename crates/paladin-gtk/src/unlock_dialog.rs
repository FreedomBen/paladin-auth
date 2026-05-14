// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unlock-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `UnlockComponent` and §"Vault interaction", `UnlockComponent` is
//! the passphrase-entry view `AppModel` presents whenever
//! [`paladin_core::inspect`] reports
//! [`paladin_core::VaultStatus::Encrypted`]. Plaintext vaults skip
//! the view entirely and open directly into `AccountListComponent`;
//! a `Missing` vault routes to [`crate::init_dialog`] instead.
//!
//! The widget layer hosts a single [`adw::PasswordEntryRow`] whose
//! bytes shadow into a [`crate::secret_fields::SecretEntry`]. On
//! submit the dialog calls [`prepare_unlock_lock`] to gate the empty
//! passphrase short-circuit and to build the
//! [`paladin_core::VaultLock::Encrypted`] handed to
//! [`paladin_core::open`] inside a `gio::spawn_blocking` worker so
//! the §4.4 Argon2id KDF (m=64 MiB defaults) does not block the GTK
//! main loop. On worker return:
//!
//! * `Ok((Vault, Store))` swaps `AppModel` to `Unlocked`.
//! * `Err(PaladinError)` routes through [`classify_unlock_error`],
//!   which delegates to the shared
//!   [`crate::startup_error::classify_open_error`]:
//!   * `DecryptFailed` / `InvalidPassphrase` → inline error at the
//!     passphrase entry (the user can re-type without leaving the
//!     view).
//!   * Every other variant (`UnsafePermissions`, `WrongVaultLock`,
//!     `InvalidHeader`, `InvalidPayload`,
//!     `UnsupportedFormatVersion`, `KdfParamsOutOfBounds`,
//!     `IoError`) transitions `AppModel` to
//!     `StartupErrorComponent`, which is non-mutating per the plan.
//!
//! The module is a pure-logic shell — it owns no widgets and no
//! `gio::spawn_blocking` plumbing — so
//! `tests/unlock_dialog_logic.rs` can exercise every branch without
//! spinning up GTK or libadwaita.

use secrecy::SecretString;

use paladin_core::{ErrorKind, PaladinError, VaultLock, VaultStatus};

use crate::startup_error::{classify_open_error, OpenErrorRouting};

/// Whether `AppModel` should present the unlock view for `status`.
///
/// Encrypted vaults require the passphrase round trip; plaintext
/// vaults open directly into `AccountListComponent`, and a missing
/// vault routes to [`crate::init_dialog`] instead. Returns `true`
/// only for [`VaultStatus::Encrypted`].
#[must_use]
pub fn unlock_view_required(status: VaultStatus) -> bool {
    matches!(status, VaultStatus::Encrypted)
}

/// Pre-submit rejection surfaced by [`prepare_unlock_lock`].
///
/// The only pre-flight gate is the empty-passphrase short-circuit:
/// rejecting an empty entry in the GUI avoids spawning a worker just
/// to receive [`PaladinError::InvalidPassphrase`] with
/// `reason: "zero_length"`, while still returning the same stable §5
/// `error_kind` / `reason` pair so instrumentation matches the CLI / TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitRejection {
    /// Passphrase entry is empty. Mirrors
    /// [`paladin_core::PaladinError::InvalidPassphrase`] with
    /// `reason: "zero_length"`.
    EmptyPassphrase,
}

impl SubmitRejection {
    /// Stable §5 [`ErrorKind`] for this rejection.
    #[must_use]
    pub fn error_kind(self) -> ErrorKind {
        match self {
            Self::EmptyPassphrase => ErrorKind::InvalidPassphrase,
        }
    }

    /// Stable §5 `invalid_passphrase.reason` code for this rejection.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::EmptyPassphrase => "zero_length",
        }
    }
}

/// Build the [`VaultLock`] passed to [`paladin_core::open`] from the
/// typed passphrase, rejecting an empty entry pre-flight.
///
/// `passphrase` is borrowed by the GTK widget layer from the
/// `SecretEntry` shadow buffer; the caller is expected to clear /
/// `take` the buffer after handing the returned [`VaultLock`] to the
/// worker so the cleartext bytes do not outlive the submit.
///
/// # Errors
///
/// * [`SubmitRejection::EmptyPassphrase`] when `passphrase` is empty.
///   Whitespace-only passphrases are accepted (the §5 `zero_length`
///   contract only catches the empty string; further passphrase
///   policy lives in `paladin_core::open`).
pub fn prepare_unlock_lock(passphrase: &str) -> Result<VaultLock, SubmitRejection> {
    if passphrase.is_empty() {
        return Err(SubmitRejection::EmptyPassphrase);
    }
    Ok(VaultLock::Encrypted(SecretString::from(
        passphrase.to_owned(),
    )))
}

/// Route a [`paladin_core::open`] failure returned by the unlock
/// worker into the appropriate UI outcome.
///
/// Wraps [`classify_open_error`] from [`crate::startup_error`] so
/// callers do not need to reach across modules — the unlock dialog
/// shares the same `DecryptFailed` / `InvalidPassphrase` → inline,
/// everything-else → `StartupErrorComponent` table the plan pins for
/// every `paladin_core::open` call.
#[must_use]
pub fn classify_unlock_error(err: &PaladinError) -> OpenErrorRouting {
    classify_open_error(err)
}
