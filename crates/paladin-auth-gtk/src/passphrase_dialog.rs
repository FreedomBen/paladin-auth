// SPDX-License-Identifier: AGPL-3.0-or-later

//! Passphrase-dialog state machine and component for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `PassphraseDialog` and §"Vault interaction", the dialog wraps the
//! three §4.5 / Phase H passphrase transitions exposed by
//! `paladin_auth_core`:
//!
//! * [`paladin_auth_core::Vault::set_passphrase`] — encrypt a previously-
//!   plaintext vault.
//! * [`paladin_auth_core::Vault::change_passphrase`] — re-encrypt an
//!   already-encrypted vault under a new passphrase.
//! * [`paladin_auth_core::Vault::remove_passphrase`] — drop encryption
//!   and rewrite the vault as plaintext (the destructive direction;
//!   gated behind the same plaintext-storage warning the
//!   `InitDialog`'s plaintext path uses).
//!
//! The widget layer hosts a sub-flow segmented control, two
//! [`adw::PasswordEntryRow`] passphrase fields for the Set / Change
//! paths, and an inline plaintext-storage warning + acknowledgement
//! row for the Remove path. The pure-logic helpers in this module
//! own the routing and rendering decisions so they can be unit-tested
//! in `tests/passphrase_dialog_logic.rs` without spinning up GTK /
//! libadwaita.
//!
//! # Sub-flow gating
//!
//! [`SubFlow::is_available`] and [`available_sub_flows`] gate which
//! sub-flows the dialog exposes against the live
//! [`paladin_auth_core::Vault::is_encrypted`] state: a plaintext vault
//! can only `Set`; an encrypted vault can `Change` or `Remove`.
//! Mirrors the `paladin-auth passphrase` CLI (`set` is rejected when the
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
//! expose KDF tuning per `docs/DESIGN.md` §11 / §13.
//!
//! # Submission gate (Remove)
//!
//! [`remove_warning_body`] returns
//! [`paladin_auth_core::format_plaintext_storage_warning`] verbatim so
//! the destructive-gate body matches the wording the CLI / TUI use
//! before any plaintext write. The dialog does not call
//! `remove_passphrase` until
//! [`crate::secret_fields::PassphraseSecretState::acknowledge_remove`]
//! has flipped the per-state confirmation flag, which is reset by
//! sub-flow switches and by every `clear_for` reason (so a stale
//! acknowledgement cannot survive a cancel / close / auto-lock and
//! re-arm a future attempt).
//!
//! # Post-effect routing
//!
//! [`classify_passphrase_error`] maps the [`PaladinAuthError`] from a
//! failed `Vault::set_passphrase` / `change_passphrase` /
//! `remove_passphrase` onto the dialog's three-way routing decision:
//!
//! * `save_not_committed` → [`PassphraseErrorOutcome::RestorePrior`]
//!   (commit never landed; the dialog keeps the input the user typed
//!   and shows the typed inline error so they can retry).
//! * `save_durability_unconfirmed` →
//!   [`PassphraseErrorOutcome::KeepNewWithWarning`] (commit landed
//!   but parent-fsync failed; the dialog stays open with a warning
//!   attached to the body so the user explicitly dismisses).
//! * Anything else (defensive: `invalid_state`, `decrypt_failed`, …)
//!   → [`PassphraseErrorOutcome::InlineError`] without transitioning
//!   out of the dialog.

use std::path::PathBuf;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::prelude::*;

use paladin_auth_core::{
    format_plaintext_storage_warning, EncryptionOptions, ErrorKind, PaladinAuthError, Store, Vault,
};
use secrecy::SecretString;

use crate::secret_fields::{ClearReason, PassphraseSecretState};

/// Three sub-flows the `PassphraseDialog` exposes.
///
/// Routing is gated against [`paladin_auth_core::Vault::is_encrypted`] —
/// see [`SubFlow::is_available`] and [`available_sub_flows`] — so
/// the dialog cannot present a sub-flow the core would refuse with
/// `invalid_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFlow {
    /// Encrypt a previously-plaintext vault. Calls
    /// [`paladin_auth_core::Vault::set_passphrase`].
    Set,
    /// Re-encrypt an encrypted vault under a new passphrase. Calls
    /// [`paladin_auth_core::Vault::change_passphrase`].
    Change,
    /// Drop encryption from an encrypted vault and rewrite as
    /// plaintext. Calls [`paladin_auth_core::Vault::remove_passphrase`].
    /// Gated behind the [`remove_warning_body`] destructive
    /// confirmation.
    Remove,
}

impl SubFlow {
    /// Whether this sub-flow is available given the vault's current
    /// [`paladin_auth_core::Vault::is_encrypted`] state.
    ///
    /// `Set` is available only when `is_encrypted == false`;
    /// `Change` and `Remove` only when `is_encrypted == true`.
    /// Mirrors the `paladin_auth_core::Vault` wrong-state guards verbatim
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

/// Initial sub-flow to arm on the segmented control given the live
/// vault encryption state.
///
/// * Plaintext vault → [`SubFlow::Set`] (the only available option).
/// * Encrypted vault → [`SubFlow::Change`] (the non-destructive
///   default; [`SubFlow::Remove`] requires the additional
///   plaintext-storage acknowledgement so the user has to opt in
///   explicitly).
#[must_use]
pub fn default_sub_flow_for(is_encrypted: bool) -> SubFlow {
    if is_encrypted {
        SubFlow::Change
    } else {
        SubFlow::Set
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
    /// [`paladin_auth_core::PaladinAuthError::InvalidPassphrase`] with
    /// `reason: "confirmation_mismatch"`.
    ConfirmationMismatch,
    /// Both passphrase rows empty. Mirrors
    /// [`paladin_auth_core::PaladinAuthError::InvalidPassphrase`] with
    /// `reason: "zero_length"` — the same reason
    /// [`paladin_auth_core::EncryptionOptions::new`] returns for an empty
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

    /// Rendered display body — mirrors the §5 wording produced by
    /// [`PaladinAuthError::InvalidPassphrase`] for the same `reason`.
    #[must_use]
    pub fn rendered(&self) -> String {
        match self {
            Self::ConfirmationMismatch => "passphrase and confirmation do not match.".to_string(),
            Self::ZeroLength => "passphrase must not be empty.".to_string(),
        }
    }
}

/// Validate the twice-confirm new-passphrase pair shared by the
/// [`SubFlow::Set`] and [`SubFlow::Change`] paths and build the
/// [`EncryptionOptions`] for the upcoming
/// [`paladin_auth_core::Vault::set_passphrase`] /
/// [`paladin_auth_core::Vault::change_passphrase`] call.
///
/// * Pass / confirm pair differs → [`SubmitRejection::ConfirmationMismatch`].
/// * Both rows empty → [`SubmitRejection::ZeroLength`].
/// * Otherwise: build [`EncryptionOptions::new`] with the default
///   §4.4 Argon2id cost (m=64 MiB, t=3, p=1).
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
/// [`paladin_auth_core::Vault::remove_passphrase`] runs. Wording matches
/// [`paladin_auth_core::format_plaintext_storage_warning`] verbatim so
/// the GUI never drifts from the CLI `passphrase remove` /
/// TUI Passphrase modal wording.
#[must_use]
pub fn remove_warning_body() -> String {
    format_plaintext_storage_warning()
}

/// Post-effect routing decision for a failed passphrase transition.
///
/// See [`classify_passphrase_error`].
#[derive(Debug, Clone)]
pub enum PassphraseErrorOutcome {
    /// `save_not_committed` — the transition never committed to
    /// disk. The in-memory vault mode / key rolled back (DESIGN
    /// §4.5 owns this); the dialog keeps the user's input and shows
    /// the typed inline error so they can retry.
    RestorePrior(InlineError),
    /// `save_durability_unconfirmed` — primary rename succeeded but
    /// parent-fsync failed. The in-memory vault mode / key reflects
    /// the new state (DESIGN §4.5 already swapped it in); the dialog
    /// stays open with the warning attached to the body so the user
    /// explicitly dismisses.
    KeepNewWithWarning(InlineWarning),
    /// Defensive: any other typed error stays inline and does not
    /// transition the dialog out. Hits `invalid_state` only if the
    /// vault mode flipped under us (the segmented control's
    /// gating already rejects mismatched sub-flows), and
    /// `decrypt_failed` cannot arise on this surface (the dialog
    /// operates against the already-unlocked vault).
    InlineError(InlineError),
}

/// Classify a passphrase-transition failure into a
/// [`PassphraseErrorOutcome`].
///
/// Routes the §5 save-pipeline discriminators (`save_not_committed`
/// → [`PassphraseErrorOutcome::RestorePrior`],
/// `save_durability_unconfirmed` →
/// [`PassphraseErrorOutcome::KeepNewWithWarning`]) and falls back to
/// an inline error for every other typed variant so the dialog
/// never silently transitions out.
#[must_use]
pub fn classify_passphrase_error(err: &PaladinAuthError) -> PassphraseErrorOutcome {
    match err.kind() {
        ErrorKind::SaveNotCommitted => {
            PassphraseErrorOutcome::RestorePrior(InlineError::from_error(err))
        }
        ErrorKind::SaveDurabilityUnconfirmed => {
            PassphraseErrorOutcome::KeepNewWithWarning(InlineWarning::from_error(err))
        }
        _ => PassphraseErrorOutcome::InlineError(InlineError::from_error(err)),
    }
}

/// Inline-error projection for the `PassphraseDialog` body.
#[derive(Debug, Clone)]
pub struct InlineError {
    /// Stable §5 [`ErrorKind`] discriminator copied from
    /// [`PaladinAuthError::kind`].
    pub kind: ErrorKind,
    /// Display body. Renders through [`std::fmt::Display`] so the
    /// wording stays in sync with the CLI / TUI verbatim.
    pub rendered: String,
}

impl InlineError {
    /// Build an [`InlineError`] from a [`PaladinAuthError`].
    #[must_use]
    pub fn from_error(err: &PaladinAuthError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}

/// Durability-warning projection for the `PassphraseDialog` body.
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
    /// Build an [`InlineWarning`] from a [`PaladinAuthError`].
    #[must_use]
    pub fn from_error(err: &PaladinAuthError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}

/// Payload forwarded from [`PassphraseDialogOutput::Submit`] to
/// `AppModel` describing the chosen transition.
///
/// `EncryptionOptions` is not `Clone` (it owns a
/// [`secrecy::SecretString`]), so neither [`SubmitPayload`] nor
/// [`PassphraseDialogOutput`] derive `Clone`. `AppModel` moves the
/// payload into the worker exactly once.
#[derive(Debug)]
pub enum SubmitPayload {
    /// [`SubFlow::Set`]. Carries the validated [`EncryptionOptions`]
    /// that [`run_passphrase_worker`] passes to
    /// [`paladin_auth_core::Vault::set_passphrase`].
    Set(EncryptionOptions),
    /// [`SubFlow::Change`]. Carries the validated
    /// [`EncryptionOptions`] for
    /// [`paladin_auth_core::Vault::change_passphrase`].
    Change(EncryptionOptions),
    /// [`SubFlow::Remove`]. No secret payload; the dialog already
    /// gated the destructive acknowledgement before emitting this
    /// variant.
    Remove,
}

impl SubmitPayload {
    /// Which [`SubFlow`] this payload represents.
    #[must_use]
    pub fn sub_flow(&self) -> SubFlow {
        match self {
            Self::Set(_) => SubFlow::Set,
            Self::Change(_) => SubFlow::Change,
            Self::Remove => SubFlow::Remove,
        }
    }
}

/// Inputs consumed by [`run_passphrase_worker`].
///
/// `AppModel::update` moves the live `(Vault, Store)` pair plus the
/// [`SubmitPayload`] into the worker; the worker bundles the
/// `(Vault, Store)` back into [`PassphraseWorkerCompletion`] on every
/// branch so the dispatch site can reinstall the pair.
///
/// `Clone` / `PartialEq` are deliberately not derived: [`Store`]
/// holds non-`Clone` filesystem state, and `AppModel::update`
/// consumes the input exactly once.
#[derive(Debug)]
pub struct PassphraseWorkerInput {
    /// Live vault moved by value so the §4.5 transition can borrow
    /// it mutably without keeping `AppModel` in `Unlocked` for the
    /// duration of the KDF.
    pub vault: Vault,
    /// Live store moved alongside `vault`.
    pub store: Store,
    /// Which transition to apply, plus any required
    /// [`EncryptionOptions`].
    pub payload: SubmitPayload,
}

/// Outcome of [`run_passphrase_worker`] for `AppModel::update` to apply.
#[derive(Debug, Clone)]
pub enum PassphraseWorkerEffect {
    /// The selected `Vault::*_passphrase` call returned `Ok(())`.
    /// Carries the new vault encryption state and the sub-flow that
    /// transitioned so the dispatch site can update the visible
    /// mode flag and re-ask `IdlePolicy::should_arm` against the new
    /// `is_encrypted` value.
    Success {
        /// Sub-flow that was applied. Used by the dispatch site to
        /// pick the matching success toast / status line.
        sub_flow: SubFlow,
        /// Post-transition [`Vault::is_encrypted`] value. The
        /// dispatch site threads this into the auto-lock policy and
        /// any cached mode flag.
        new_is_encrypted: bool,
    },
    /// The selected `Vault::*_passphrase` call returned a typed
    /// failure. The carried [`PassphraseErrorOutcome`] tells the
    /// dialog whether to render the typed `save_not_committed` /
    /// `save_durability_unconfirmed` rollback / warning, or fall
    /// back to the defensive inline error.
    Failure(PassphraseErrorOutcome),
}

/// Bundle returned by [`run_passphrase_worker`]. Carries the live
/// `(Vault, Store)` pair on every branch so `AppModel::update` can
/// reinstall it before applying the UI outcome.
#[derive(Debug)]
pub struct PassphraseWorkerCompletion {
    /// Routed effect for `AppModel::update` to apply.
    pub effect: PassphraseWorkerEffect,
    /// Live vault after the transition (or after the §4.5 rollback
    /// for `save_not_committed`).
    pub vault: Vault,
    /// Live store moved through unchanged.
    pub store: Store,
}

/// Synchronous body of the `gio::spawn_blocking` passphrase-
/// transition worker fired by `AppModel::update` from
/// `AppMsg::PassphraseDialogAction(PassphraseDialogOutput::Submit)`.
///
/// Consumes the [`PassphraseWorkerInput`] by value, dispatches to
/// the matching `Vault::*_passphrase` call, and bundles the outcome
/// into a [`PassphraseWorkerCompletion`] via
/// [`classify_passphrase_error`]. The live `(Vault, Store)` pair is
/// always returned so `AppModel` reinstalls it regardless of the
/// typed effect — `Vault::*_passphrase` is authoritative for the
/// §4.5 rollback / durability semantics.
#[must_use]
pub fn run_passphrase_worker(input: PassphraseWorkerInput) -> PassphraseWorkerCompletion {
    let PassphraseWorkerInput {
        mut vault,
        store,
        payload,
    } = input;
    let sub_flow = payload.sub_flow();
    let result = match payload {
        SubmitPayload::Set(options) => vault.set_passphrase(&store, options),
        SubmitPayload::Change(options) => vault.change_passphrase(&store, options),
        SubmitPayload::Remove => vault.remove_passphrase(&store),
    };
    let effect = match result {
        Ok(()) => PassphraseWorkerEffect::Success {
            sub_flow,
            new_is_encrypted: vault.is_encrypted(),
        },
        Err(err) => PassphraseWorkerEffect::Failure(classify_passphrase_error(&err)),
    };
    PassphraseWorkerCompletion {
        effect,
        vault,
        store,
    }
}

/// Construction parameters for [`PassphraseDialogComponent`].
///
/// The dialog opens against the live vault so the worker can call
/// the matching `Vault::*_passphrase` against the same on-disk file
/// `AppModel` resolved at startup. Cloned from `AppModel::state` at
/// mount time so a mid-flight passphrase-transition or lock cannot
/// retarget the dialog.
#[derive(Debug, Clone)]
pub struct PassphraseDialogInit {
    /// Vault path the passphrase worker will target.
    pub vault_path: PathBuf,
    /// Snapshot of [`paladin_auth_core::Vault::is_encrypted`] at mount
    /// time. Threads into [`available_sub_flows`] and
    /// [`default_sub_flow_for`] so the dialog only presents
    /// sub-flows the core would not refuse with `invalid_state`.
    pub is_encrypted: bool,
}

/// Live state for [`PassphraseDialogComponent`].
///
/// Owns the active sub-flow, the two secret-bearing passphrase
/// buffers (via [`PassphraseSecretState`]), the pending plaintext-
/// removal acknowledgement, the latest pre-submit inline rejection,
/// and the latest worker outcome. The pure-logic helpers in this
/// module operate against this struct so the widget side can be
/// kept thin.
///
/// `Debug` is manually implemented to redact the secret-bearing
/// passphrase buffers — never derive `Debug` here, otherwise a
/// stray `dbg!` would leak the buffer through the error log.
pub struct PassphraseDialogState {
    /// Live vault encryption snapshot at dialog open. Threads into
    /// [`available_sub_flows`] so a mid-flight mode flip cannot
    /// expose an unavailable sub-flow.
    is_encrypted: bool,
    /// Secret-bearing widget shadows — passphrase buffers + pending
    /// remove acknowledgement. Owned here so [`apply_msg`] can wipe
    /// them on Submit / Cancel without leaking a borrow into the
    /// widget layer.
    secrets: PassphraseSecretState,
    /// Latest pre-submit rejection (mismatch / zero-length). Stamped
    /// on a failed [`PassphraseDialogMsg::SubmitClicked`] and cleared
    /// by the next [`PassphraseDialogMsg::NewPassphraseChanged`] /
    /// [`PassphraseDialogMsg::ConfirmPassphraseChanged`] so the
    /// inline error tracks the live input.
    inline_rejection: Option<SubmitRejection>,
    /// Latest worker outcome from a completed `Vault::*_passphrase`
    /// transition. The widget body matches on this so the inline
    /// error / durability warning surfaces.
    worker_outcome: Option<PassphraseErrorOutcome>,
    /// `true` while a `gio::spawn_blocking` passphrase-transition
    /// worker is in flight. Shadows the `AppState::UnlockedBusy`
    /// busy-gate `AppModel` mounts at the same instant the dialog
    /// emits [`PassphraseDialogOutput::Submit`]: the Save / Cancel
    /// buttons disable through [`Self::submit_button_sensitive`] /
    /// [`Self::cancel_button_sensitive`] and the footer spinner
    /// shows through [`Self::spinner_visible`] until the worker
    /// completes. Cleared by
    /// [`PassphraseDialogMsg::WorkerFailed`] (stay-open failure
    /// branches re-enable the dialog) and by
    /// [`PassphraseDialogMsg::Cancel`] (defensive: a stray Cancel
    /// arriving while busy must not deadlock the dialog). On
    /// success the controller is dropped by `AppModel` so the flag
    /// disappears with the state.
    dispatching: bool,
}

impl std::fmt::Debug for PassphraseDialogState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the secret-bearing passphrase buffers; surface only
        // their `is_empty` shadow plus the rest of the state.
        f.debug_struct("PassphraseDialogState")
            .field("is_encrypted", &self.is_encrypted)
            .field("sub_flow", &self.secrets.sub_flow)
            .field(
                "new_passphrase_empty",
                &self.secrets.new_passphrase.is_empty(),
            )
            .field(
                "confirm_passphrase_empty",
                &self.secrets.confirm_passphrase.is_empty(),
            )
            .field("remove_confirmed", &self.secrets.remove_confirmed)
            .field("inline_rejection", &self.inline_rejection)
            .field("worker_outcome", &self.worker_outcome)
            .field("dispatching", &self.dispatching)
            .finish()
    }
}

impl PassphraseDialogState {
    /// Seed the state from the live vault's encryption mode.
    ///
    /// Picks the default sub-flow via [`default_sub_flow_for`]:
    /// `Set` for plaintext vaults and `Change` for encrypted vaults
    /// (the non-destructive option for encrypted vaults; `Remove`
    /// requires the additional acknowledgement).
    #[must_use]
    pub fn new(is_encrypted: bool) -> Self {
        let sub_flow = default_sub_flow_for(is_encrypted);
        Self {
            is_encrypted,
            secrets: PassphraseSecretState::new(sub_flow),
            inline_rejection: None,
            worker_outcome: None,
            dispatching: false,
        }
    }

    /// Currently-active sub-flow on the segmented control.
    #[must_use]
    pub fn sub_flow(&self) -> SubFlow {
        self.secrets.sub_flow
    }

    /// Vault encryption snapshot captured at dialog open.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    /// Borrow the new-passphrase entry's shadow buffer.
    #[must_use]
    pub fn new_passphrase(&self) -> &str {
        self.secrets.new_passphrase.text()
    }

    /// Borrow the confirm-passphrase entry's shadow buffer.
    #[must_use]
    pub fn confirm_passphrase(&self) -> &str {
        self.secrets.confirm_passphrase.text()
    }

    /// Whether the Remove sub-flow's plaintext-storage
    /// acknowledgement is currently ticked.
    #[must_use]
    pub fn remove_confirmed(&self) -> bool {
        self.secrets.remove_confirmed
    }

    /// Borrow the latest pre-submit rejection, if any.
    #[must_use]
    pub fn inline_rejection(&self) -> Option<&SubmitRejection> {
        self.inline_rejection.as_ref()
    }

    /// Borrow the latest worker outcome, if any.
    #[must_use]
    pub fn worker_outcome(&self) -> Option<&PassphraseErrorOutcome> {
        self.worker_outcome.as_ref()
    }

    /// Whether the Save button should be sensitive given the current
    /// input.
    ///
    /// For Set / Change: both passphrase rows non-empty and equal.
    /// For Remove: the acknowledgement checkbox ticked.
    ///
    /// Always returns `false` while a passphrase-transition worker is
    /// in flight (see [`Self::is_dispatching`]) so a stray accelerator
    /// cannot fire a second Submit over the running worker.
    #[must_use]
    pub fn submit_button_sensitive(&self) -> bool {
        if self.dispatching {
            return false;
        }
        match self.sub_flow() {
            SubFlow::Set | SubFlow::Change => {
                !self.new_passphrase().is_empty()
                    && self.new_passphrase() == self.confirm_passphrase()
            }
            SubFlow::Remove => self.remove_confirmed(),
        }
    }

    /// Whether the Cancel button should be sensitive.
    ///
    /// Always `true` while idle; `false` while a passphrase-transition
    /// worker is in flight per the §"In-flight effect ownership" rule
    /// "Dialog close/cancel is disabled for the surface that owns the
    /// in-flight mutation until the worker returns".
    #[must_use]
    pub fn cancel_button_sensitive(&self) -> bool {
        !self.dispatching
    }

    /// Whether the busy spinner should be visible. Mirrors
    /// [`Self::is_dispatching`] so the widget can bind both
    /// `set_spinning` and `set_visible` directly.
    #[must_use]
    pub fn spinner_visible(&self) -> bool {
        self.dispatching
    }

    /// `true` while a `gio::spawn_blocking` passphrase-transition
    /// worker is in flight against this dialog.
    #[must_use]
    pub fn is_dispatching(&self) -> bool {
        self.dispatching
    }

    /// Toggle the dispatching busy gate. Flipped to `true` by the
    /// `apply_msg` arm that consumes a valid Submit; flipped to
    /// `false` by [`PassphraseDialogMsg::WorkerFailed`] or by
    /// [`PassphraseDialogMsg::Cancel`] (defensive). `AppModel` may
    /// also call this through the
    /// [`PassphraseDialogMsg::SetDispatching`] message to roll the
    /// gate back when a dispatch is refused before the worker
    /// spawns.
    pub fn set_dispatching(&mut self, dispatching: bool) {
        self.dispatching = dispatching;
    }
}

/// Messages handled by [`PassphraseDialogComponent`].
///
/// `Clone` is derived so [`crate::app::state::compose_passphrase_dispatch`]'s
/// `dialog_msg` field can carry an owned `PassphraseDialogMsg`
/// projection and `AppModel::update` can forward it to the live
/// controller without re-deriving the routing.
#[derive(Debug, Clone)]
pub enum PassphraseDialogMsg {
    /// User clicked a different sub-flow on the segmented control.
    /// If the target is available for the current encryption mode
    /// and differs from the active sub-flow, the buffers + pending
    /// acknowledgement clear (see
    /// [`PassphraseSecretState::switch_sub_flow`]). Unavailable
    /// targets are a no-op (defensive).
    SubFlowSelected(SubFlow),
    /// Raw text from the new-passphrase [`adw::PasswordEntryRow`]
    /// after a keystroke. Updates the secret-bearing shadow buffer
    /// and clears any prior inline rejection so the row no longer
    /// shows a stale error against the new input.
    NewPassphraseChanged(String),
    /// Raw text from the confirm-passphrase
    /// [`adw::PasswordEntryRow`] after a keystroke.
    ConfirmPassphraseChanged(String),
    /// User toggled the plaintext-storage acknowledgement checkbox
    /// on the Remove sub-flow.
    AcknowledgeRemove(bool),
    /// Save button pressed. Routes through
    /// [`prepare_new_passphrase`] (Set / Change) or the
    /// acknowledgement gate (Remove) and emits
    /// [`PassphraseDialogOutput::Submit`] on success or stamps an
    /// inline rejection on failure.
    SubmitClicked,
    /// Cancel button pressed. Wipes the secret-bearing state and
    /// emits [`PassphraseDialogOutput::Close`].
    Cancel,
    /// `AppModel` pushes the typed [`PassphraseErrorOutcome`] back
    /// to the dialog after the `gio::spawn_blocking` worker reports
    /// a failure. Releases the busy gate
    /// ([`PassphraseDialogState::is_dispatching`] → `false`) so the
    /// dialog re-enables; the typed outcome stages the inline
    /// error / durability warning rendered through
    /// [`inline_body_text`].
    WorkerFailed(PassphraseErrorOutcome),
    /// `AppModel` pushes the busy gate back to the dialog without
    /// staging a worker outcome — used when a dispatch is refused
    /// before the worker spawns (defensive: a stray Submit from a
    /// non-`Unlocked` state, or a `compose_passphrase_worker_input`
    /// refusal). Lets the dialog re-enable Save / Cancel without
    /// surfacing an inline error.
    SetDispatching(bool),
}

/// Messages emitted by [`PassphraseDialogComponent`] for `AppModel` to consume.
#[derive(Debug)]
pub enum PassphraseDialogOutput {
    /// User dismissed the dialog (Cancel button / Escape / window
    /// close). `AppModel` responds by dropping the live
    /// `Controller<PassphraseDialogComponent>` so the underlying
    /// `adw::Dialog` is torn down. Any in-flight pending form draft
    /// (selected sub-flow, current / new / confirm passphrase
    /// entries, pending destructive acknowledgement) has already
    /// been zeroized inside [`apply_msg`] before this is emitted.
    Close,
    /// Save button pressed with valid input. Carries the
    /// validated [`SubmitPayload`]; `AppModel` moves it into the
    /// `gio::spawn_blocking` passphrase worker.
    Submit(SubmitPayload),
}

/// Apply an inbound [`PassphraseDialogMsg`] to `state` and return
/// the optional [`PassphraseDialogOutput`] the widget layer should
/// forward to `AppModel`.
pub fn apply_msg(
    state: &mut PassphraseDialogState,
    msg: PassphraseDialogMsg,
) -> Option<PassphraseDialogOutput> {
    match msg {
        PassphraseDialogMsg::SubFlowSelected(target) => {
            if !target.is_available(state.is_encrypted) {
                return None;
            }
            if state.secrets.sub_flow != target {
                state.inline_rejection = None;
                state.worker_outcome = None;
            }
            state.secrets.switch_sub_flow(target);
            None
        }
        PassphraseDialogMsg::NewPassphraseChanged(text) => {
            state.secrets.new_passphrase.set(&text);
            state.inline_rejection = None;
            None
        }
        PassphraseDialogMsg::ConfirmPassphraseChanged(text) => {
            state.secrets.confirm_passphrase.set(&text);
            state.inline_rejection = None;
            None
        }
        PassphraseDialogMsg::AcknowledgeRemove(checked) => {
            if checked {
                state.secrets.acknowledge_remove();
            } else {
                state.secrets.remove_confirmed = false;
            }
            None
        }
        PassphraseDialogMsg::SubmitClicked => {
            // Clear any stale worker outcome so the body does not
            // render post-effect text alongside the live attempt.
            state.worker_outcome = None;
            match state.secrets.sub_flow {
                SubFlow::Set | SubFlow::Change => {
                    let new_pp = state.secrets.new_passphrase.text().to_string();
                    let confirm_pp = state.secrets.confirm_passphrase.text().to_string();
                    match prepare_new_passphrase(&new_pp, &confirm_pp) {
                        Ok(options) => {
                            // Take the validated secret out of the
                            // shadow buffers and emit the matching
                            // Submit variant; the GTK
                            // PasswordEntryRow widget buffers are
                            // cleared by the component's
                            // post-apply_msg hook.
                            state.inline_rejection = None;
                            state.secrets.clear_for(ClearReason::Submit);
                            state.dispatching = true;
                            let payload = match state.secrets.sub_flow {
                                SubFlow::Set => SubmitPayload::Set(options),
                                SubFlow::Change => SubmitPayload::Change(options),
                                SubFlow::Remove => unreachable!(),
                            };
                            Some(PassphraseDialogOutput::Submit(payload))
                        }
                        Err(rejection) => {
                            state.inline_rejection = Some(rejection);
                            None
                        }
                    }
                }
                SubFlow::Remove => {
                    if !state.secrets.remove_confirmed {
                        // Submit is gated by the acknowledgement —
                        // the widget binds submit_button_sensitive
                        // through #[watch] so this branch only
                        // fires if a future accelerator bypasses
                        // the visible gate. No inline rejection:
                        // the gate is the un-ticked checkbox, not a
                        // passphrase validation failure.
                        return None;
                    }
                    state.inline_rejection = None;
                    state.secrets.clear_for(ClearReason::Submit);
                    state.dispatching = true;
                    Some(PassphraseDialogOutput::Submit(SubmitPayload::Remove))
                }
            }
        }
        PassphraseDialogMsg::Cancel => {
            state.secrets.clear_for(ClearReason::Cancel);
            state.inline_rejection = None;
            state.worker_outcome = None;
            state.dispatching = false;
            Some(PassphraseDialogOutput::Close)
        }
        PassphraseDialogMsg::WorkerFailed(outcome) => {
            state.worker_outcome = Some(outcome);
            state.dispatching = false;
            None
        }
        PassphraseDialogMsg::SetDispatching(value) => {
            state.dispatching = value;
            None
        }
    }
}

/// Static label of the dialog title.
#[must_use]
pub fn format_passphrase_dialog_title() -> &'static str {
    "Passphrase"
}

/// Static label of the Cancel button.
#[must_use]
pub fn format_passphrase_dialog_cancel_label() -> &'static str {
    "Cancel"
}

/// Static label of the Save button.
#[must_use]
pub fn format_passphrase_dialog_save_label() -> &'static str {
    "Save"
}

/// Human-readable label for a sub-flow on the segmented control.
#[must_use]
pub fn format_sub_flow_label(sub_flow: SubFlow) -> &'static str {
    match sub_flow {
        SubFlow::Set => "Set",
        SubFlow::Change => "Change",
        SubFlow::Remove => "Remove",
    }
}

/// Success toast body posted after a successful passphrase
/// transition. Picks the matching wording per sub-flow.
#[must_use]
pub fn format_passphrase_success_toast(sub_flow: SubFlow) -> &'static str {
    match sub_flow {
        SubFlow::Set => "Encrypted vault.",
        SubFlow::Change => "Re-encrypted vault.",
        SubFlow::Remove => "Decrypted vault to plaintext.",
    }
}

/// Widget-bearing `adw::Dialog` for the application menu's Passphrase… entry.
///
/// Mounts the libadwaita dialog described in docs/DESIGN.md §7
/// (`PassphraseDialog`) and `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Component tree" > `PassphraseDialog`. The widget body contains:
///
/// * An [`adw::ViewSwitcher`]-driven segmented control that exposes
///   the sub-flows available for the current encryption mode
///   (`Set` for plaintext vaults; `Change` / `Remove` for
///   encrypted).
/// * An [`adw::PreferencesGroup`] with two
///   [`adw::PasswordEntryRow`] widgets for the Set / Change paths
///   (twice-confirm) and an inline plaintext-storage warning +
///   acknowledgement check row for the Remove path.
/// * Cancel / Save footer buttons. Save dims via
///   [`PassphraseDialogState::submit_button_sensitive`] when the
///   input is invalid.
pub struct PassphraseDialogComponent {
    /// Vault path the dialog mounts against, kept on `self` so the
    /// passphrase worker can reach it without re-plumbing through
    /// every signal.
    #[allow(dead_code)]
    vault_path: PathBuf,
    /// Live state owning the active sub-flow, secret-bearing
    /// shadow buffers, pending acknowledgement, inline rejection,
    /// and worker outcome.
    state: PassphraseDialogState,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for PassphraseDialogComponent {
    type Init = PassphraseDialogInit;
    type Input = PassphraseDialogMsg;
    type Output = PassphraseDialogOutput;

    view! {
        #[root]
        adw::Dialog {
            set_title: format_passphrase_dialog_title(),

            // `connect_closed` fires on Escape / window-close /
            // parent-navigation close, distinct from the explicit
            // Cancel button. Routed through the same
            // `PassphraseDialogMsg::Cancel` arm so secret-bearing
            // shadow buffers are wiped uniformly regardless of the
            // dismissal channel. The send goes through the bare
            // `Sender` (instead of `ComponentSender::input`, which
            // panics on a closed channel) so the closure is safe to
            // fire during teardown — `force_close` from the
            // `AppMsg::PassphraseDialogAction(Close)` handler emits
            // `closed` synchronously, and the runtime may have
            // already scheduled shutdown by then.
            connect_closed[sender] => move |_| {
                let _ = sender.input_sender().send(PassphraseDialogMsg::Cancel);
            },

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {},

                #[wrap(Some)]
                set_content = &gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 12,
                    set_margin_top: 12,
                    set_margin_bottom: 12,
                    set_margin_start: 12,
                    set_margin_end: 12,

                    // Sub-flow segmented control (gated by is_encrypted).
                    // We mount a horizontal box of toggle buttons (one
                    // per available SubFlow) so the test surface can
                    // assert sub-flow gating without depending on
                    // libadwaita's segmented-control widget version.
                    #[name = "sub_flow_box"]
                    gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_spacing: 0,
                        set_halign: gtk::Align::Center,
                        add_css_class: "linked",
                    },

                    // Set / Change passphrase rows.
                    #[name = "passphrase_group"]
                    adw::PreferencesGroup {
                        #[watch]
                        set_visible: matches!(model.state.sub_flow(), SubFlow::Set | SubFlow::Change),

                        #[name = "new_passphrase_row"]
                        add = &adw::PasswordEntryRow {
                            set_title: "New passphrase",
                            // See the Cancel button comment — route
                            // through `Sender::send` so a stray
                            // callback after the controller is
                            // dropped is a benign no-op.
                            connect_changed[sender] => move |entry| {
                                let _ = sender.input_sender().send(
                                    PassphraseDialogMsg::NewPassphraseChanged(
                                        entry.text().to_string(),
                                    ),
                                );
                            },
                        },

                        #[name = "confirm_passphrase_row"]
                        add = &adw::PasswordEntryRow {
                            set_title: "Confirm passphrase",
                            // See the Cancel button comment.
                            connect_changed[sender] => move |entry| {
                                let _ = sender.input_sender().send(
                                    PassphraseDialogMsg::ConfirmPassphraseChanged(
                                        entry.text().to_string(),
                                    ),
                                );
                            },
                        },
                    },

                    // Remove plaintext-storage warning label, shown
                    // only on the Remove sub-flow.
                    #[name = "remove_warning_label"]
                    gtk::Label {
                        set_label: &remove_warning_body(),
                        set_xalign: 0.0,
                        set_wrap: true,
                        add_css_class: "warning",
                        #[watch]
                        set_visible: matches!(model.state.sub_flow(), SubFlow::Remove),
                    },

                    // Remove acknowledgement check row.
                    #[name = "remove_group"]
                    adw::PreferencesGroup {
                        #[watch]
                        set_visible: matches!(model.state.sub_flow(), SubFlow::Remove),

                        #[name = "remove_ack_row"]
                        add = &adw::SwitchRow {
                            set_title: "I understand the risk.",
                            // See the Cancel button comment.
                            connect_active_notify[sender] => move |row| {
                                let _ = sender.input_sender().send(
                                    PassphraseDialogMsg::AcknowledgeRemove(row.is_active()),
                                );
                            },
                        },
                    },

                    // Inline pre-submit rejection / worker outcome
                    // body.
                    #[name = "inline_label"]
                    gtk::Label {
                        set_xalign: 0.0,
                        set_wrap: true,
                        add_css_class: "error",
                        #[watch]
                        set_label: &inline_body_text(&model.state),
                        #[watch]
                        set_visible: !inline_body_text(&model.state).is_empty(),
                    },

                    // Footer: spinner (while busy), Cancel / Save buttons.
                    gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_spacing: 6,
                        set_halign: gtk::Align::End,

                        #[name = "busy_spinner"]
                        gtk::Spinner {
                            #[watch]
                            set_spinning: model.state.spinner_visible(),
                            #[watch]
                            set_visible: model.state.spinner_visible(),
                        },

                        #[name = "cancel_button"]
                        gtk::Button {
                            set_label: format_passphrase_dialog_cancel_label(),
                            #[watch]
                            set_sensitive: model.state.cancel_button_sensitive(),
                            connect_clicked[sender] => move |_| {
                                // `Sender::send` is used in place of
                                // `ComponentSender::input` (which
                                // `.expect`s on a closed channel) so
                                // a stray click that arrives after
                                // `AppMsg::PassphraseDialogAction(Close)`
                                // has dropped the controller is a
                                // benign no-op instead of an abort.
                                let _ = sender.input_sender().send(PassphraseDialogMsg::Cancel);
                            },
                        },

                        #[name = "save_button"]
                        gtk::Button {
                            set_label: format_passphrase_dialog_save_label(),
                            add_css_class: "suggested-action",
                            #[watch]
                            set_sensitive: model.state.submit_button_sensitive(),
                            // See the Cancel button comment.
                            connect_clicked[sender] => move |_| {
                                let _ = sender
                                    .input_sender()
                                    .send(PassphraseDialogMsg::SubmitClicked);
                            },
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
        let state = PassphraseDialogState::new(init.is_encrypted);
        let model = PassphraseDialogComponent {
            vault_path: init.vault_path,
            state,
        };
        let widgets = view_output!();
        // Populate the sub-flow segmented control with the
        // available sub-flows for this encryption mode. Buttons
        // share a radio group so exactly one is active at a time.
        let mut group_leader: Option<gtk::ToggleButton> = None;
        for &flow in available_sub_flows(model.state.is_encrypted()) {
            let button = gtk::ToggleButton::builder()
                .label(format_sub_flow_label(flow))
                .build();
            if let Some(leader) = group_leader.as_ref() {
                button.set_group(Some(leader));
            } else {
                group_leader = Some(button.clone());
            }
            if model.state.sub_flow() == flow {
                button.set_active(true);
            }
            let sender_clone = sender.clone();
            button.connect_toggled(move |b| {
                if b.is_active() {
                    // See the Cancel button comment.
                    let _ = sender_clone
                        .input_sender()
                        .send(PassphraseDialogMsg::SubFlowSelected(flow));
                }
            });
            widgets.sub_flow_box.append(&button);
        }
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_msg(&mut self.state, msg) {
            let _ = sender.output(output);
        }
    }
}

/// Inline body text for the dialog status label.
///
/// Renders the worker outcome (`save_not_committed` rollback /
/// `save_durability_unconfirmed` warning / defensive inline error)
/// if present, otherwise the pre-submit rejection
/// (mismatch / zero-length). Returns an empty string when there is
/// nothing to render — the widget's `set_visible` binding hides the
/// label in that case.
#[must_use]
pub fn inline_body_text(state: &PassphraseDialogState) -> String {
    if let Some(outcome) = state.worker_outcome() {
        return match outcome {
            PassphraseErrorOutcome::KeepNewWithWarning(warn) => warn.rendered.clone(),
            PassphraseErrorOutcome::RestorePrior(err)
            | PassphraseErrorOutcome::InlineError(err) => err.rendered.clone(),
        };
    }
    if let Some(rejection) = state.inline_rejection() {
        return rejection.rendered();
    }
    String::new()
}
