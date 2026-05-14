// SPDX-License-Identifier: AGPL-3.0-or-later

//! Passphrase-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `PassphraseDialog` and §"Vault interaction", the dialog wraps the
//! three §4.5 / Phase H passphrase transitions exposed by
//! `paladin_core`:
//!
//! * [`paladin_core::Vault::set_passphrase`] — encrypt a previously-
//!   plaintext vault.
//! * [`paladin_core::Vault::change_passphrase`] — re-encrypt an
//!   already-encrypted vault under a new passphrase.
//! * [`paladin_core::Vault::remove_passphrase`] — drop encryption
//!   and rewrite the vault as plaintext (the destructive direction;
//!   gated behind the same plaintext-storage warning the
//!   `InitDialog`'s plaintext path uses).
//!
//! The widget layer hosts a sub-flow segmented control, two
//! [`adw::PasswordEntryRow`] passphrase fields for the Set / Change
//! paths, and an in-dialog [`adw::AlertDialog`] for the Remove
//! destructive gate. The pure-logic helpers in this module own the
//! routing and rendering decisions so they can be unit-tested in
//! `tests/passphrase_dialog_logic.rs` without spinning up GTK /
//! libadwaita.
//!
//! # Sub-flow gating
//!
//! [`SubFlow::is_available`] and [`available_sub_flows`] gate which
//! sub-flows the dialog exposes against the live
//! [`paladin_core::Vault::is_encrypted`] state: a plaintext vault
//! can only `Set`; an encrypted vault can `Change` or `Remove`.
//! Mirrors the `paladin passphrase` CLI (`set` is rejected when the
//! vault is already encrypted; `change` / `remove` are rejected when
//! it is plaintext) verbatim, so the GUI cannot expose a sub-flow
//! the core would refuse with `invalid_state`.
//!
//! # Submission gates (Set / Change)
//!
//! [`prepare_new_passphrase`] is shared by the Set and Change paths:
//! both ask for a twice-confirm new passphrase pair, both reject
//! mismatches as [`SubmitRejection::ConfirmationMismatch`], and
//! both reject both-empty inputs as [`SubmitRejection::ZeroLength`].
//! Both rejections surface as the §5 `invalid_passphrase` error
//! kind with the matching `reason` wire code so telemetry / JSON
//! instrumentation match the CLI / TUI verbatim. On success, the
//! pair is wrapped in an [`EncryptionOptions`] built with the
//! default Argon2id cost (m=64 MiB, t=3, p=1); the GUI does not
//! expose KDF tuning per `DESIGN.md` §11 / §13.
//!
//! # Submission gate (Remove)
//!
//! [`remove_warning_body`] returns
//! [`paladin_core::format_plaintext_storage_warning`] verbatim so
//! the destructive-gate body matches the wording the CLI / TUI use
//! before any plaintext write. The dialog does not call
//! `remove_passphrase` until
//! [`crate::secret_fields::PassphraseSecretState::acknowledge_remove`]
//! has flipped the per-state confirmation flag, which is reset by
//! sub-flow switches and by every `clear_for` reason (so a stale
//! acknowledgement cannot survive a cancel / close / auto-lock and
//! re-arm a future attempt).

use paladin_core::{format_plaintext_storage_warning, EncryptionOptions, ErrorKind};
use secrecy::SecretString;

/// Three sub-flows the `PassphraseDialog` exposes.
///
/// Routing is gated against [`paladin_core::Vault::is_encrypted`] —
/// see [`SubFlow::is_available`] and [`available_sub_flows`] — so
/// the dialog cannot present a sub-flow the core would refuse with
/// `invalid_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFlow {
    /// Encrypt a previously-plaintext vault. Calls
    /// [`paladin_core::Vault::set_passphrase`].
    Set,
    /// Re-encrypt an encrypted vault under a new passphrase. Calls
    /// [`paladin_core::Vault::change_passphrase`].
    Change,
    /// Drop encryption from an encrypted vault and rewrite as
    /// plaintext. Calls [`paladin_core::Vault::remove_passphrase`].
    /// Gated behind the [`remove_warning_body`] destructive
    /// confirmation.
    Remove,
}

impl SubFlow {
    /// Whether this sub-flow is available given the vault's current
    /// [`paladin_core::Vault::is_encrypted`] state.
    ///
    /// `Set` is available only when `is_encrypted == false`;
    /// `Change` and `Remove` only when `is_encrypted == true`.
    /// Mirrors the `paladin_core::Vault` wrong-state guards verbatim
    /// (see `set_passphrase` / `change_passphrase` /
    /// `remove_passphrase` doc comments).
    #[must_use]
    pub fn is_available(self, is_encrypted: bool) -> bool {
        match self {
            Self::Set => !is_encrypted,
            Self::Change | Self::Remove => is_encrypted,
        }
    }
}

/// Static slice of sub-flows available for the supplied vault
/// encryption state.
///
/// Returns `[Set]` when the vault is plaintext and
/// `[Change, Remove]` when it is encrypted. Used by the widget
/// layer to populate the dialog's sub-flow selector with exactly
/// the choices the core will accept.
#[must_use]
pub fn available_sub_flows(is_encrypted: bool) -> &'static [SubFlow] {
    if is_encrypted {
        &[SubFlow::Change, SubFlow::Remove]
    } else {
        &[SubFlow::Set]
    }
}

/// Inline rejection produced by [`prepare_new_passphrase`] before
/// any vault work runs.
///
/// Both variants surface as the §5 `invalid_passphrase` error kind
/// with distinct `reason` wire codes so the dialog can attach the
/// rejection to the correct row and so telemetry / JSON
/// instrumentation match the CLI / TUI verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitRejection {
    /// Passphrase and confirm rows differ. Mirrors
    /// [`paladin_core::PaladinError::InvalidPassphrase`] with
    /// `reason: "confirmation_mismatch"`.
    ConfirmationMismatch,
    /// Both passphrase rows empty. Mirrors
    /// [`paladin_core::PaladinError::InvalidPassphrase`] with
    /// `reason: "zero_length"` — the same reason
    /// [`paladin_core::EncryptionOptions::new`] returns for an empty
    /// passphrase.
    ZeroLength,
}

impl SubmitRejection {
    /// Stable §5 [`ErrorKind`] discriminator for this rejection.
    /// Always [`ErrorKind::InvalidPassphrase`].
    #[must_use]
    pub fn error_kind(&self) -> ErrorKind {
        ErrorKind::InvalidPassphrase
    }

    /// Stable §5 `invalid_passphrase.reason` wire code for this
    /// rejection.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::ConfirmationMismatch => "confirmation_mismatch",
            Self::ZeroLength => "zero_length",
        }
    }
}

/// Validate the twice-confirm new-passphrase pair shared by the
/// [`SubFlow::Set`] and [`SubFlow::Change`] paths and build the
/// [`EncryptionOptions`] for the upcoming
/// [`paladin_core::Vault::set_passphrase`] /
/// [`paladin_core::Vault::change_passphrase`] call.
///
/// * Pass / confirm pair differs → [`SubmitRejection::ConfirmationMismatch`].
/// * Both rows empty → [`SubmitRejection::ZeroLength`].
/// * Otherwise: build [`EncryptionOptions::new`] with the default
///   §4.4 Argon2id cost (m=64 MiB, t=3, p=1).
///
/// `EncryptionOptions::new` itself rejects empty passphrases with
/// `invalid_passphrase { reason: "zero_length" }`; the explicit
/// pre-check here lets the dialog distinguish the empty case from a
/// mismatch without depending on the constructor's typed error
/// surface.
///
/// # Errors
///
/// Returns [`SubmitRejection`] for either pre-vault gate failure.
pub fn prepare_new_passphrase(
    passphrase: &str,
    confirm: &str,
) -> Result<EncryptionOptions, SubmitRejection> {
    if passphrase != confirm {
        return Err(SubmitRejection::ConfirmationMismatch);
    }
    if passphrase.is_empty() {
        return Err(SubmitRejection::ZeroLength);
    }
    EncryptionOptions::new(SecretString::from(passphrase.to_string()))
        .map_err(|_| SubmitRejection::ZeroLength)
}

/// Body text for the destructive confirmation rendered before
/// [`paladin_core::Vault::remove_passphrase`] runs. Wording matches
/// [`paladin_core::format_plaintext_storage_warning`] verbatim so
/// the GUI never drifts from the CLI `passphrase remove` /
/// TUI Passphrase modal wording.
#[must_use]
pub fn remove_warning_body() -> String {
    format_plaintext_storage_warning()
}
