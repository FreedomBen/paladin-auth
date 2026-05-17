// SPDX-License-Identifier: AGPL-3.0-or-later

//! Init-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" and
//! §"Vault interaction", `InitDialog` is the only path that creates
//! a vault from the GUI (DESIGN §6, §7). The widget layer hosts two
//! [`adw::PasswordEntryRow`] passphrase fields, an explicit
//! plaintext-warning [`gtk::CheckButton`], and an in-dialog
//! [`adw::AlertDialog`] for the `vault_exists` destructive gate; the
//! pure-logic helpers in this module own the routing and rendering
//! decisions so they can be unit-tested in `tests/init_dialog_logic.rs`
//! without spinning up GTK / libadwaita.
//!
//! # Mode classification
//!
//! Per the plan, both passphrase fields empty selects plaintext;
//! any non-empty field selects encrypted. [`classify_mode`] returns
//! the [`InitMode`] used by [`prepare_vault_init`] to gate
//! submission.
//!
//! # Submission gates
//!
//! [`prepare_vault_init`] enforces the two pre-vault gates:
//!
//! * Plaintext requires the warning checkbox to be ticked. The
//!   rendered text comes from
//!   [`paladin_core::format_plaintext_storage_warning`] verbatim
//!   (see [`plaintext_warning_body`]).
//! * Encrypted requires both fields non-empty AND matching. The
//!   one-empty / mismatched pair rejection mirrors the §5
//!   `invalid_passphrase` error with `reason: "confirmation_mismatch"`.
//!
//! On success, [`prepare_vault_init`] returns a
//! [`paladin_core::VaultInit`] the caller hands to a worker calling
//! [`paladin_core::Store::create`] (or
//! [`paladin_core::Store::create_force`] after the destructive gate).
//!
//! # Precheck routing
//!
//! Before the `create` worker spawns, the dialog runs
//! [`paladin_core::classify_init_precheck`] against
//! [`paladin_core::inspect`]. [`classify_precheck`] maps the
//! [`paladin_core::InitPrecheck`] truth table onto the dialog's three
//! routing decisions: proceed to `create`, open the destructive
//! gate, or surface an inline error without touching disk.
//!
//! # Create result routing
//!
//! [`classify_create_error`] handles the post-`create` race: if the
//! precheck reported `Clear` but disk grew a vault between
//! `inspect` and `create`, the typed `vault_exists` error reopens
//! the destructive gate worded by
//! [`paladin_core::format_init_force_warning`] (see
//! [`destructive_gate_body`]). All other typed errors stay inline.
//!
//! [`classify_create_force_error`] is the same routing for the
//! create-force re-run; `vault_exists` cannot occur on that path
//! (force always overwrites), so the routing collapses to inline
//! errors only. The `save_not_committed` variant carries the
//! rotated `.bak` path through the [`InlineError::backup_path`]
//! field so the dialog can show it inline (DESIGN §5
//! `save_not_committed.backup_path`).
//!
//! # Inline error rendering
//!
//! [`InlineError::from_error`] renders `unsafe_permissions` through
//! [`paladin_core::format_unsafe_permissions`] so wording matches
//! the CLI / TUI verbatim; other variants fall back to the typed
//! [`std::fmt::Display`] text.
//!
//! # Pending `VaultInit` lifetime
//!
//! The destructive gate holds the pending [`VaultInit`] across the
//! confirmation round trip. Storage lives in
//! [`crate::secret_fields::InitSecretState::pending`] so its
//! [`paladin_core::EncryptionOptions`] passphrase wipes on drop via
//! `secrecy::SecretString` regardless of which arm of the
//! confirmation fires; this module concerns itself only with the
//! routing decisions that produce or consume that slot.

use std::path::{Path, PathBuf};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::prelude::*;

use paladin_core::{
    classify_init_precheck, format_create_vault_dir_error, format_init_force_warning,
    format_plaintext_storage_warning, format_unsafe_permissions, EncryptionOptions, ErrorKind,
    InitPrecheck, PaladinError, VaultInit, VaultStatus,
};
use secrecy::SecretString;

/// Vault mode selected by the current passphrase-field contents.
///
/// See [`classify_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitMode {
    /// Both passphrase fields empty.
    Plaintext,
    /// At least one passphrase field non-empty.
    Encrypted,
}

/// Classify the current passphrase-field contents into an
/// [`InitMode`].
///
/// Both fields empty selects [`InitMode::Plaintext`]; any non-empty
/// field selects [`InitMode::Encrypted`] (the actual two-field
/// validity check happens in [`prepare_vault_init`]).
#[must_use]
pub fn classify_mode(passphrase: &str, confirm: &str) -> InitMode {
    if passphrase.is_empty() && confirm.is_empty() {
        InitMode::Plaintext
    } else {
        InitMode::Encrypted
    }
}

/// Inline rejection produced by [`prepare_vault_init`] before any
/// vault work runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitRejection {
    /// Plaintext mode selected but the warning checkbox is unticked.
    /// The dialog must surface
    /// [`plaintext_warning_body`] beside the gate; submission stays
    /// disabled until the user ticks it.
    PlaintextWarningRequired,
    /// Encrypted mode selected with one-empty or mismatched
    /// passphrase fields. Mirrors
    /// [`paladin_core::PaladinError::InvalidPassphrase`] with
    /// `reason: "confirmation_mismatch"`.
    ConfirmationMismatch,
}

impl SubmitRejection {
    /// `Some(ErrorKind)` when the rejection corresponds to a §5
    /// [`PaladinError`] kind; `None` for the UI-only plaintext
    /// warning gate.
    #[must_use]
    pub fn error_kind(&self) -> Option<ErrorKind> {
        match self {
            Self::ConfirmationMismatch => Some(ErrorKind::InvalidPassphrase),
            Self::PlaintextWarningRequired => None,
        }
    }

    /// `Some(reason)` mirroring the §5 `invalid_passphrase.reason`
    /// field for [`Self::ConfirmationMismatch`]; `None` otherwise.
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::ConfirmationMismatch => Some("confirmation_mismatch"),
            Self::PlaintextWarningRequired => None,
        }
    }
}

/// Build a [`VaultInit`] from the current dialog state, gating on
/// the plaintext warning and the encrypted twice-confirm.
///
/// Returns:
///
/// * `Ok(VaultInit::Plaintext)` when both passphrase fields are
///   empty AND `plaintext_warning_acknowledged` is `true`.
/// * `Ok(VaultInit::Encrypted(_))` when both passphrase fields are
///   non-empty AND match. The encrypted variant carries an
///   [`EncryptionOptions`] built with the default Argon2 cost; the
///   GUI does not expose KDF tuning per `DESIGN.md` §11 / §13.
/// * `Err(SubmitRejection::PlaintextWarningRequired)` when plaintext
///   mode is selected but the warning is unticked.
/// * `Err(SubmitRejection::ConfirmationMismatch)` when encrypted
///   mode is selected with one-empty or mismatched fields.
///
/// # Errors
///
/// Returns [`SubmitRejection`] for either pre-vault gate failure.
pub fn prepare_vault_init(
    passphrase: &str,
    confirm: &str,
    plaintext_warning_acknowledged: bool,
) -> Result<VaultInit, SubmitRejection> {
    match classify_mode(passphrase, confirm) {
        InitMode::Plaintext => {
            if !plaintext_warning_acknowledged {
                return Err(SubmitRejection::PlaintextWarningRequired);
            }
            Ok(VaultInit::Plaintext)
        }
        InitMode::Encrypted => {
            if passphrase.is_empty() || confirm.is_empty() || passphrase != confirm {
                return Err(SubmitRejection::ConfirmationMismatch);
            }
            // `EncryptionOptions::new` only fails on zero-length, which
            // we already gated against above. Map a defensive error to
            // ConfirmationMismatch so the UI never has to surface a
            // distinct path here.
            let opts = EncryptionOptions::new(SecretString::from(passphrase.to_string()))
                .map_err(|_| SubmitRejection::ConfirmationMismatch)?;
            Ok(VaultInit::Encrypted(opts))
        }
    }
}

/// Body text for the plaintext storage warning rendered above the
/// confirmation checkbox. Wording matches
/// [`paladin_core::format_plaintext_storage_warning`] verbatim so it
/// stays in sync with the CLI / TUI.
#[must_use]
pub fn plaintext_warning_body() -> String {
    format_plaintext_storage_warning()
}

/// Body text for the destructive `vault_exists` confirmation gate.
/// Wording matches [`paladin_core::format_init_force_warning`]
/// verbatim so it stays in sync with the CLI `init --force` flow
/// and the TUI.
#[must_use]
pub fn destructive_gate_body(existing_vault: &Path) -> String {
    format_init_force_warning(existing_vault)
}

/// Routing decision after the precheck step.
///
/// See [`classify_precheck`].
#[derive(Debug)]
pub enum PrecheckOutcome {
    /// `InitPrecheck::Clear` — proceed to call
    /// [`paladin_core::Store::create`].
    Proceed,
    /// `InitPrecheck::Existing` — open the destructive-confirmation
    /// gate; on confirm, call [`paladin_core::Store::create_force`].
    DestructiveGate,
    /// `InitPrecheck::Propagate(_)` — render inline; do not touch
    /// disk.
    InlineError(InlineError),
}

/// Map a [`paladin_core::inspect`] result onto the dialog's
/// three-way routing decision via
/// [`paladin_core::classify_init_precheck`].
#[must_use]
pub fn classify_precheck(probe: Result<VaultStatus, PaladinError>) -> PrecheckOutcome {
    match classify_init_precheck(probe) {
        InitPrecheck::Clear => PrecheckOutcome::Proceed,
        InitPrecheck::Existing => PrecheckOutcome::DestructiveGate,
        InitPrecheck::Propagate(err) => PrecheckOutcome::InlineError(InlineError::from_error(&err)),
    }
}

/// Routing decision for a [`paladin_core::Store::create`] failure.
///
/// See [`classify_create_error`].
#[derive(Debug)]
pub enum CreateOutcome {
    /// `vault_exists` race after a `Clear` precheck — open the
    /// destructive-confirmation gate. The pending [`VaultInit`]
    /// stays in
    /// [`crate::secret_fields::InitSecretState::pending`] for the
    /// create-force re-run.
    DestructiveGate,
    /// Any other typed error stays inline; the dialog does not
    /// transition out.
    InlineError(InlineError),
}

/// Classify a [`paladin_core::Store::create`] failure into a
/// [`CreateOutcome`].
///
/// `vault_exists` is the only kind that opens the destructive gate;
/// every other variant — including `unsafe_permissions`,
/// `save_not_committed`, `save_durability_unconfirmed`,
/// `create_vault_dir`, and defensive `invalid_passphrase` — stays
/// inline.
///
/// `attempted_dir` is the parent directory the dialog passed to
/// `Store::create` (i.e. `vault_path.parent()`). It is threaded into
/// [`InlineError::from_create_error`] so a
/// `create_vault_dir` `IoError` renders the friendly
/// [`paladin_core::format_create_vault_dir_error`] wording naming the
/// directory paladin tried to `mkdir -p`.
#[must_use]
pub fn classify_create_error(err: &PaladinError, attempted_dir: &Path) -> CreateOutcome {
    match err.kind() {
        ErrorKind::VaultExists => CreateOutcome::DestructiveGate,
        _ => CreateOutcome::InlineError(InlineError::from_create_error(err, attempted_dir)),
    }
}

/// Classify a [`paladin_core::Store::create_force`] failure into an
/// [`InlineError`].
///
/// `vault_exists` cannot occur on the create-force path (force
/// always overwrites), so the routing collapses to inline errors
/// only — there is no destructive-gate re-entry to model. The
/// dialog never transitions out on a `create_force` failure.
/// `save_not_committed` threads through the optional `backup_path`
/// from the §5 error so the dialog can name the rotated `.bak`
/// path inline; `create_vault_dir` renders the friendly
/// [`paladin_core::format_create_vault_dir_error`] wording using
/// `attempted_dir`.
#[must_use]
pub fn classify_create_force_error(err: &PaladinError, attempted_dir: &Path) -> InlineError {
    InlineError::from_create_error(err, attempted_dir)
}

/// Inline-error projection for the `InitDialog` body.
///
/// Carries the stable §5 [`ErrorKind`] for instrumentation, the
/// rendered body for display, and the optional `backup_path`
/// surfaced by `save_not_committed` after a `create_force` backup
/// rotation. No source-error reference is kept so the model can be
/// cloned freely into the dialog's reactive state.
#[derive(Debug, Clone)]
pub struct InlineError {
    /// Stable §5 [`ErrorKind`] discriminator copied from
    /// [`PaladinError::kind`].
    pub kind: ErrorKind,
    /// Display body. `unsafe_permissions` renders through
    /// [`paladin_core::format_unsafe_permissions`]; other variants
    /// fall back to the typed [`std::fmt::Display`].
    pub rendered: String,
    /// Optional rotated-`.bak` path threaded through from
    /// [`PaladinError::SaveNotCommitted::backup_path`]. Always
    /// `None` for non-`save_not_committed` variants.
    pub backup_path: Option<PathBuf>,
}

impl InlineError {
    /// Build an [`InlineError`] from a [`PaladinError`]. Renders
    /// `unsafe_permissions` via the core formatter and threads the
    /// `save_not_committed.backup_path` field through unchanged.
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: render_inline(err),
            backup_path: backup_path_of(err),
        }
    }

    /// Build an [`InlineError`] for a `Store::create` / `create_force`
    /// failure. Identical to [`InlineError::from_error`] except that a
    /// `create_vault_dir` `IoError` renders via the path-aware
    /// [`paladin_core::format_create_vault_dir_error`] helper, so the
    /// dialog body names the directory paladin tried to `mkdir -p`.
    /// `attempted_dir` is typically the dialog's
    /// `InitDialogInit::vault_path.parent()`.
    #[must_use]
    pub fn from_create_error(err: &PaladinError, attempted_dir: &Path) -> Self {
        Self {
            kind: err.kind(),
            rendered: render_create_inline(err, attempted_dir),
            backup_path: backup_path_of(err),
        }
    }
}

fn render_inline(err: &PaladinError) -> String {
    format_unsafe_permissions(err).unwrap_or_else(|| err.to_string())
}

fn render_create_inline(err: &PaladinError, attempted_dir: &Path) -> String {
    format_create_vault_dir_error(err, attempted_dir).unwrap_or_else(|| render_inline(err))
}

fn backup_path_of(err: &PaladinError) -> Option<PathBuf> {
    match err {
        PaladinError::SaveNotCommitted { backup_path, .. } => backup_path.clone(),
        _ => None,
    }
}

/// Stdout marker prefix emitted under `--exit-after-startup` once
/// the [`InitDialogComponent`] has mounted on the
/// [`crate::app::state::AppState::Missing`] branch.
///
/// The smoke test in `tests/gtk_smoke.rs` greps for this prefix to
/// prove the widget actually mounted (rather than inferring the
/// render from the `startup_state=Missing` line, which is emitted
/// before any per-state widget is mounted).
pub const INIT_DIALOG_MARKER_PREFIX: &str = "paladin-gtk: init_dialog_path=";

/// Format the smoke-test stdout marker line for a mounted
/// [`InitDialogComponent`].
///
/// The marker is `paladin-gtk: init_dialog_path=<path>` where
/// `<path>` is the resolved vault path the dialog will pass to
/// `paladin_core::Store::create` on submit.
#[must_use]
pub fn format_init_dialog_marker(path: &Path) -> String {
    format!("{INIT_DIALOG_MARKER_PREFIX}{}", path.display())
}

/// Construction parameters for [`InitDialogComponent`].
#[derive(Debug, Clone)]
pub struct InitDialogInit {
    /// Resolved vault path the dialog targets on submit. Surfaced
    /// in the dialog body so the user can confirm the destination
    /// before creating a vault.
    pub vault_path: PathBuf,
}

/// Messages handled by [`InitDialogComponent`].
///
/// This milestone scaffolds the read-only render path — the
/// `submit` / `cancel` / destructive-gate transitions described in
/// §"Component tree" land in a follow-up commit alongside the
/// passphrase-field wiring on `AppModel`. The empty enum is the
/// deliberate v0.2 starting point — relm4 requires the associated
/// `Input` type to exist even when no inbound messages are wired
/// yet.
#[derive(Debug)]
pub enum InitDialogMsg {}

/// Widget-bearing dialog for the
/// [`crate::app::state::AppState::Missing`] branch.
///
/// Mounts a libadwaita [`adw::StatusPage`] that surfaces the
/// resolved vault path alongside the standard plaintext-storage
/// warning copy. Subsequent commits replace the placeholder body
/// with the two-field passphrase entry, the warning checkbox, and
/// the destructive-`create_force` confirmation gate; until then,
/// keeping the widget read-only mirrors the
/// [`crate::startup_error::StartupErrorComponent`] pattern (the
/// `StartupError` branch also mounted a status page first and grew
/// inbound actions later).
pub struct InitDialogComponent {
    /// Resolved vault path the dialog will hand to a
    /// `Store::create` worker on submit. Kept on `self` so a
    /// future message handler can read it without re-plumbing the
    /// value through every signal.
    #[allow(dead_code)]
    vault_path: PathBuf,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for InitDialogComponent {
    type Init = InitDialogInit;
    type Input = InitDialogMsg;
    type Output = ();

    view! {
        #[root]
        adw::StatusPage {
            // `document-new-symbolic` is the freedesktop-standard
            // glyph for "create a new document"; it resolves
            // through the system icon theme so the wordless icon
            // matches every other GNOME app's first-run surface.
            set_icon_name: Some("document-new-symbolic"),
            set_title: "Create a new vault",
            set_description: Some(&format!(
                "No vault found at {path}.\n\n{warning}",
                path = model.vault_path.display(),
                warning = plaintext_warning_body(),
            )),
            set_hexpand: true,
            set_vexpand: true,
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        _sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = InitDialogComponent {
            vault_path: init.vault_path,
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, _msg: Self::Input, _sender: ComponentSender<Self>) {
        // No inbound messages handled at this milestone — see
        // `InitDialogMsg` doc comment for the upcoming submit /
        // cancel / destructive-gate actions.
    }
}
