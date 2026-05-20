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

use std::path::PathBuf;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::prelude::*;

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

/// Construction parameters for [`PassphraseDialogComponent`].
///
/// The dialog opens against the live vault so the worker that lands
/// in follow-up commits can call
/// [`paladin_core::Vault::set_passphrase`] /
/// [`paladin_core::Vault::change_passphrase`] /
/// [`paladin_core::Vault::remove_passphrase`] against the same on-
/// disk file `AppModel` resolved at startup. Cloned from
/// `AppModel::state` at mount time so a mid-flight passphrase-
/// transition or lock cannot retarget the dialog. The encryption
/// snapshot is also captured at mount time because sub-flow gating
/// (`available_sub_flows(is_encrypted)`) depends on it.
#[derive(Debug, Clone)]
pub struct PassphraseDialogInit {
    /// Vault path the passphrase worker will target.
    pub vault_path: PathBuf,
    /// Snapshot of [`paladin_core::Vault::is_encrypted`] at mount
    /// time. Threads into [`available_sub_flows`] so the dialog only
    /// presents sub-flows the core would not refuse with
    /// `invalid_state`.
    pub is_encrypted: bool,
}

/// Messages handled by [`PassphraseDialogComponent`].
///
/// This milestone scaffolds the read-only `adw::Dialog` mount; the
/// sub-flow-selector / Set / Change / Remove / destructive-gate /
/// submit / worker-result transitions described in
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `PassphraseDialog` land in follow-up commits alongside the
/// live-apply behavior. The empty enum is the deliberate v0.2
/// starting point — relm4 requires the associated `Input` type to
/// exist even when no inbound messages are wired yet.
#[derive(Debug)]
pub enum PassphraseDialogMsg {}

/// Messages emitted by [`PassphraseDialogComponent`] for `AppModel` to consume.
///
/// `AppModel` forwards these into `AppMsg::PassphraseDialogAction(...)`;
/// the dispatch arm drops the live
/// `Controller<PassphraseDialogComponent>` so the underlying
/// `adw::Dialog` is torn down. Submit / worker-result outputs that
/// propagate the typed [`paladin_core::PaladinError`] / vault-mode
/// transition signals to `AppModel` land in the same follow-up
/// commits that add the matching [`PassphraseDialogMsg`] variants.
#[derive(Debug, Clone)]
pub enum PassphraseDialogOutput {
    /// User dismissed the dialog (Close button / Escape / window
    /// close). `AppModel` responds by dropping the live controller
    /// so the dialog disappears and any in-flight pending form draft
    /// (selected sub-flow, current / new / confirm passphrase
    /// entries, pending destructive acknowledgement) is discarded.
    Close,
}

/// Widget-bearing `adw::Dialog` for the application menu's Passphrase… entry.
///
/// Mounts the libadwaita dialog described in DESIGN.md §7
/// (`PassphraseDialog`) and `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Component tree" > `PassphraseDialog`. The widget body is a
/// read-only scaffold at this milestone (an empty `adw::ToolbarView`
/// wrapped in `adw::Dialog` with the dialog title set), so the
/// controller mounts cleanly under `xvfb-run` without yet exposing
/// the sub-flow segmented control, Set / Change / Remove fields, or
/// destructive `adw::AlertDialog` gate. Follow-up commits attach the
/// real form widgets and the
/// `paladin_core::Vault::{set,change,remove}_passphrase` worker
/// alongside the wording sourced from [`remove_warning_body`].
pub struct PassphraseDialogComponent {
    /// Vault path the dialog mounts against, kept on `self` so the
    /// follow-up passphrase worker can reach it without re-plumbing
    /// through every signal. The pure-logic round-trip is asserted
    /// by `tests/passphrase_dialog_logic.rs`.
    #[allow(dead_code)]
    vault_path: PathBuf,
    /// Encryption snapshot captured at mount time. Used by the
    /// follow-up [`available_sub_flows`] wiring to gate the sub-
    /// flow selector against the live vault mode.
    #[allow(dead_code)]
    is_encrypted: bool,
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
            set_title: "Passphrase",

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {},
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        _sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = PassphraseDialogComponent {
            vault_path: init.vault_path,
            is_encrypted: init.is_encrypted,
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, _msg: Self::Input, _sender: ComponentSender<Self>) {
        // No inbound messages handled at this milestone — see
        // `PassphraseDialogMsg` doc comment for the upcoming sub-flow
        // / Set / Change / Remove / destructive-gate / submit /
        // worker-result transitions.
    }
}
