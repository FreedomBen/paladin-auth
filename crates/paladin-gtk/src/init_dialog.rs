// SPDX-License-Identifier: AGPL-3.0-or-later

//! Init-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" and
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
use relm4::gtk;
use relm4::prelude::*;

use paladin_core::{
    classify_init_precheck, format_create_vault_dir_error, format_init_force_warning,
    format_plaintext_storage_warning, format_unsafe_permissions, EncryptionOptions, ErrorKind,
    InitPrecheck, PaladinError, Store, Vault, VaultInit, VaultStatus,
};
use secrecy::SecretString;

use crate::secret_fields::{ClearReason, InitSecretState};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
///   GUI does not expose KDF tuning per `docs/DESIGN.md` §11 / §13.
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

/// Whether [`run_init_worker`] should route through
/// [`paladin_core::Store::create`] or
/// [`paladin_core::Store::create_force`].
///
/// The first-pass create submit lands as
/// [`InitWorkerMode::Create`]; the destructive-gate confirm re-run
/// lands as [`InitWorkerMode::CreateForce`]. The mode is the only
/// signal the worker uses to pick the underlying core call, so
/// the dialog state machine never needs to plumb two parallel
/// worker functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitWorkerMode {
    /// First-pass create. `vault_exists` routes to
    /// [`InitWorkerEffect::DestructiveGate`].
    Create,
    /// Post-confirmation force create. `vault_exists` cannot occur on
    /// this path (force always overwrites), so the destructive-gate
    /// arm is unreachable; every failure stays inline.
    CreateForce,
}

/// Input to [`run_init_worker`] consumed once.
///
/// `AppModel::update` builds this from the dialog state when the
/// user confirms a create submit (or the destructive-gate
/// confirmation). The [`VaultInit`] is the same value
/// [`prepare_vault_init`] returned — the worker does not re-derive
/// it from the passphrase fields so the
/// [`crate::secret_fields::InitSecretState::pending`] hand-off
/// stays the single source of truth across the destructive gate.
///
/// `Clone` / `PartialEq` are deliberately not derived: [`VaultInit`]
/// carries a [`EncryptionOptions`] whose passphrase is a
/// [`secrecy::SecretString`] (non-`Clone`), and `AppModel::update`
/// consumes the input exactly once when it moves it into the
/// `gio::spawn_blocking` closure.
#[derive(Debug)]
pub struct InitWorkerInput {
    /// Vault initialization parameters from [`prepare_vault_init`].
    /// Moved into the worker so the encrypted variant's
    /// [`EncryptionOptions`] passphrase travels into the
    /// `Store::create` call without being borrowed back into the UI
    /// thread.
    pub init: VaultInit,
    /// Resolved vault path the worker passes to
    /// [`paladin_core::Store::create`] or
    /// [`paladin_core::Store::create_force`]. Threaded through to
    /// [`classify_create_error`] / [`classify_create_force_error`]
    /// so a `create_vault_dir` `IoError` renders the friendly
    /// [`paladin_core::format_create_vault_dir_error`] wording
    /// naming the directory paladin tried to `mkdir -p`.
    pub vault_path: PathBuf,
    /// Toggle between [`paladin_core::Store::create`] and
    /// [`paladin_core::Store::create_force`].
    pub mode: InitWorkerMode,
}

/// Outcome of [`run_init_worker`] for `AppModel::update` to apply.
///
/// On [`Self::Success`] the dialog dismisses itself and `AppModel`
/// transitions `Missing → Unlocked` with the returned
/// `(Vault, Store)` pair. On [`Self::DestructiveGate`] the dialog
/// reopens the destructive-confirmation gate worded by
/// [`paladin_core::format_init_force_warning`]; the pending
/// [`VaultInit`] stays in
/// [`crate::secret_fields::InitSecretState::pending`] for the
/// create-force re-run. On [`Self::InlineError`] the dialog stays
/// open with the inline error attached.
///
/// `Clone` / `PartialEq` are deliberately not derived because the
/// `Success` arm carries non-`Clone` [`Vault`] / [`Store`] handles.
#[derive(Debug)]
pub enum InitWorkerEffect {
    /// `Store::create` / `create_force` returned a live
    /// `(Vault, Store)` pair. The dialog dismisses and `AppModel`
    /// transitions to `Unlocked` with this pair.
    Success {
        /// Live vault returned by the underlying `Store::create*`
        /// call. The `Missing → Unlocked` transition installs this
        /// into the `AppState::Unlocked` slot.
        vault: Vault,
        /// Live store returned alongside `vault`. Installed into the
        /// `Unlocked` slot so subsequent `Vault::mutate_and_save`
        /// calls reuse the same `(Vault, Store)` pair.
        store: Store,
    },
    /// `Store::create` reported `vault_exists` (the only error that
    /// can race past a `Clear` precheck). The dialog reopens the
    /// destructive-confirmation gate; the pending [`VaultInit`]
    /// stays in [`crate::secret_fields::InitSecretState::pending`]
    /// for the create-force re-run.
    ///
    /// Unreachable on the [`InitWorkerMode::CreateForce`] path —
    /// `create_force` always overwrites, so a `vault_exists`
    /// classification cannot occur there.
    DestructiveGate,
    /// Typed error stays inline; the dialog does not transition
    /// out. Carries the same [`InlineError`] projection
    /// [`classify_create_error`] / [`classify_create_force_error`]
    /// would have returned synchronously.
    InlineError(InlineError),
}

/// Bundle returned by [`run_init_worker`].
///
/// Currently a transparent wrapper around the [`InitWorkerEffect`]
/// — unlike [`crate::rename_dialog::RenameWorkerCompletion`], the
/// init worker has no live `(Vault, Store)` pair to reinstall on
/// the failure paths (the pair only exists once `Store::create`
/// succeeds). The struct shape is kept so the type evolves
/// uniformly with the rename worker if a future failure path grows
/// a live-pair return.
#[derive(Debug)]
pub struct InitWorkerCompletion {
    /// Routed effect for `AppModel::update` to apply to the dialog.
    pub effect: InitWorkerEffect,
}

/// Synchronous body of the `gio::spawn_blocking
/// Store::create` / `Store::create_force` init worker fired by
/// `AppModel::update` from the `InitDialog` submit dispatch.
///
/// Consumes the [`InitWorkerInput`] by value, dispatches to
/// [`paladin_core::Store::create`] or
/// [`paladin_core::Store::create_force`] per [`InitWorkerMode`],
/// and bundles the outcome into an [`InitWorkerCompletion`] via
/// [`classify_create_error`] / [`classify_create_force_error`].
///
/// # Commit semantics
///
/// On the [`InitWorkerMode::Create`] path the freshly minted
/// [`Vault`] is committed to disk via [`Vault::save`] before the
/// `(Vault, Store)` pair is handed back — mirrors the CLI's
/// `paladin init` flow (`Store::create` + `vault.save(&store)`) so
/// the on-disk vault survives an app restart even when the user
/// never adds an account. [`InitWorkerMode::CreateForce`] does not
/// need this hand-off because [`paladin_core::Store::create_force`]
/// runs the §5 staged-clobber pipeline inline — it has already
/// written the new primary by the time it returns. A `save`
/// failure on the [`Create`] path is classified through the same
/// [`classify_create_error`] table as the underlying
/// `Store::create` failure (`vault_exists` cannot arise after
/// save, so the routing collapses to inline errors there).
///
/// [`InitWorkerMode::Create`]: InitWorkerMode::Create
/// [`Create`]: InitWorkerMode::Create
///
/// Extracting the worker body as a pure function lets
/// `AppModel::update`'s closure stay a thin
/// `gio::spawn_blocking(move || run_init_worker(input))` while the
/// real `Store::create*` call stays unit-testable in
/// `tests/init_dialog_logic.rs` against tempfile-backed plaintext
/// vaults — no GTK / libadwaita main loop required. The
/// `AppModel::update` wire-up and the `apply_init_*` reinstall
/// helpers land in follow-up commits alongside the destructive-gate
/// dispatch routing.
#[must_use]
pub fn run_init_worker(input: InitWorkerInput) -> InitWorkerCompletion {
    let InitWorkerInput {
        init,
        vault_path,
        mode,
    } = input;
    // `Store::create*` always writes to a path with a parent (the GUI
    // resolves vaults under `$XDG_DATA_HOME/paladin/`). Falling back
    // to `.` keeps the typed `create_vault_dir` IoError message
    // sensible for the degenerate root-path case that should never
    // reach this worker in practice.
    let attempted_dir = vault_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let result = match mode {
        InitWorkerMode::Create => Store::create(&vault_path, init).and_then(|(vault, store)| {
            vault.save(&store)?;
            Ok((vault, store))
        }),
        InitWorkerMode::CreateForce => Store::create_force(&vault_path, init),
    };
    let effect = match result {
        Ok((vault, store)) => InitWorkerEffect::Success { vault, store },
        Err(err) => match mode {
            InitWorkerMode::Create => match classify_create_error(&err, &attempted_dir) {
                CreateOutcome::DestructiveGate => InitWorkerEffect::DestructiveGate,
                CreateOutcome::InlineError(inline) => InitWorkerEffect::InlineError(inline),
            },
            InitWorkerMode::CreateForce => {
                InitWorkerEffect::InlineError(classify_create_force_error(&err, &attempted_dir))
            }
        },
    };
    InitWorkerCompletion { effect }
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

    /// Build an [`InlineError`] from a pre-flight [`SubmitRejection`].
    ///
    /// Returns `Some` for [`SubmitRejection::ConfirmationMismatch`] —
    /// the §5 `invalid_passphrase` projection with
    /// `reason: "confirmation_mismatch"` so the GUI surfaces the same
    /// stable `error_kind` / `reason` the CLI / TUI do.
    ///
    /// Returns `None` for [`SubmitRejection::PlaintextWarningRequired`]
    /// — that gate is a UI-only precondition that never lifts to a §5
    /// [`PaladinError`] kind; the dialog surfaces the unticked warning
    /// body separately, not as an inline error. Mirroring the typed
    /// `SubmitRejection::error_kind() -> Option<ErrorKind>` contract,
    /// this constructor returns `Option<InlineError>` so the caller
    /// can distinguish "no inline error to stage" from "inline error
    /// staged" without re-deriving the routing.
    ///
    /// The rendered text and [`ErrorKind`] match the equivalent
    /// [`PaladinError`] variant so the GUI surfaces the same stable §5
    /// `error_kind` / `reason` pair the CLI / TUI do.
    #[must_use]
    pub fn from_rejection(rejection: SubmitRejection) -> Option<Self> {
        match rejection {
            SubmitRejection::ConfirmationMismatch => {
                Some(Self::from_error(&PaladinError::InvalidPassphrase {
                    reason: rejection.reason()?,
                }))
            }
            SubmitRejection::PlaintextWarningRequired => None,
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

/// Body the widget hands to the [`InitDialogComponent`]'s
/// `adw::StatusPage::set_description` attribute.
///
/// Renders `"No vault found at <path>.\n\n<plaintext warning>"`
/// where `<path>` is the resolved vault path the dialog will hand
/// to `Store::create` on submit and `<plaintext warning>` is the
/// `paladin_core::format_plaintext_storage_warning()` body.
/// Leading with the resolved path lets the user confirm the
/// destination before submitting; the warning is surfaced verbatim
/// so the GUI cannot drift from the CLI / TUI copy — see
/// [`plaintext_warning_body`].
///
/// Takes the path by `&Path` so the widget can pass
/// `&model.vault_path` without cloning, and uses [`format!`]
/// (returning an owned `String`) because the rendered text needs
/// to outlive the borrowed [`std::path::Path`] argument once the
/// view! macro hands it to `set_description`. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_description`] on
/// the dialog-status-description side; together they pin every
/// first-mount dialog's body against a single source of truth.
#[must_use]
pub fn format_init_dialog_description(path: &Path) -> String {
    format!(
        "No vault found at {path}.\n\n{warning}",
        path = path.display(),
        warning = plaintext_warning_body(),
    )
}

/// Freedesktop icon name the widget hands to the
/// [`InitDialogComponent`]'s `adw::StatusPage::set_icon_name`.
///
/// Returns the static icon name `"document-new-symbolic"` — the
/// freedesktop-standard glyph for "create a new document" that
/// resolves through the system icon theme so the wordless icon
/// matches every other GNOME app's first-run / missing-resource
/// surface. The `-symbolic` suffix is required by the libadwaita
/// HIG for `AdwStatusPage` icons so the glyph recolors with the
/// theme. No TUI parity: the TUI is text-only and has no icon to
/// mirror. Pinning the icon name through a helper keeps the
/// string in one place shared by the widget binding and the
/// pure-logic tests.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_icon_name`] on
/// the dialog-status-icon side; together they pin every first-
/// mount dialog's freedesktop glyph against a single source of
/// truth.
#[must_use]
pub fn format_init_dialog_icon_name() -> &'static str {
    "document-new-symbolic"
}

/// Fixed `title` attribute the widget hands to the
/// [`InitDialogComponent`]'s `adw::StatusPage::set_title`.
///
/// Returns the static title string the dialog renders at the top
/// of its body. The wording (`"Create a new vault"`) is the
/// action-oriented GNOME-HIG verb-led phrasing for a first-run /
/// missing-vault surface, matching the dialog's freedesktop icon
/// (`document-new-symbolic`) and the §"Component tree" >
/// `InitDialog` description ("first-run / missing-vault flow").
/// No TUI parity: the TUI does not surface a first-run creation
/// dialog (its `init` command is CLI-shaped only), so the wording
/// is GTK-specific. Pinning the title through a helper keeps the
/// wording in one place shared by the widget binding and the
/// pure-logic tests in `tests/init_dialog_logic.rs`.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_title`],
/// [`crate::rename_dialog::format_rename_dialog_title`], and
/// [`crate::add_account::format_add_dialog_title`] on the
/// dialog-header-title side; together they pin every dialog's
/// titled surface against a single source of truth.
#[must_use]
pub fn format_init_dialog_title() -> &'static str {
    "Create a new vault"
}

/// Action-button label the [`InitDialogComponent`]'s submit
/// button renders when the user is ready to call `Store::create`
/// (plaintext path) or `Store::create` with `EncryptionOptions`
/// (encrypted path).
///
/// Returns the short action-oriented caption `"Create vault"`.
/// The wording matches the verb in
/// [`format_init_dialog_title`] (`"Create a new vault"`) while
/// keeping the button caption short — the title sentence-case
/// form for the surface header, the button bare verb-noun form
/// for the action caption. Pinning the wording through a helper
/// keeps the button label in one place shared by the widget
/// binding and the pure-logic tests in
/// `tests/init_dialog_logic.rs`.
///
/// Pure — returns a `'static str` without allocating. Sibling
/// of [`crate::unlock_dialog::format_unlock_button_label`] on
/// the dialog-submit-action side; together they pin the first-
/// mount dialog action captions against a single source of
/// truth.
#[must_use]
pub fn format_init_dialog_create_label() -> &'static str {
    "Create vault"
}

/// Fixed `title` attribute the widget hands to the
/// [`InitDialogComponent`]'s passphrase
/// `AdwPasswordEntryRow::set_title`.
///
/// Returns the static title string the encrypted-path passphrase
/// `AdwPasswordEntryRow` renders as the floating label above the
/// entry. The wording (`"Passphrase"`) matches the sibling
/// [`crate::unlock_dialog::format_unlock_dialog_passphrase_title`]
/// so the GTK init and unlock surfaces render the same passphrase-
/// row caption — a drift would surface as a confusing
/// "Passphrase" vs "Password" vs "Passcode" inconsistency when the
/// user reaches both dialogs from the same launch (Missing → Init,
/// then Locked → Unlock after a passphrase set).
///
/// Pinning the title through a helper keeps the wording in one
/// place shared by the widget binding and the pure-logic tests in
/// `tests/init_dialog_logic.rs`. No TUI parity beyond the existing
/// `passphrase_line` prompt mirrored by
/// [`crate::unlock_dialog::format_unlock_dialog_passphrase_title`]
/// — the TUI's `init` command takes the passphrase via stdin and
/// has no labeled row to mirror.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_passphrase_title`]
/// on the dialog-passphrase-row side; together they pin every
/// passphrase-entry-row caption in this crate against a single
/// source of truth.
#[must_use]
pub fn format_init_dialog_passphrase_title() -> &'static str {
    "Passphrase"
}

/// Fixed `title` attribute the widget hands to the
/// [`InitDialogComponent`]'s confirm-passphrase
/// `AdwPasswordEntryRow::set_title`.
///
/// Returns the static title string the encrypted-path
/// confirm-passphrase `AdwPasswordEntryRow` renders as the
/// floating label above the entry. The wording
/// (`"Confirm passphrase"`) mirrors the CLI `init`'s
/// `"Confirm passphrase: "` rprompt (see
/// `crates/paladin-cli/src/commands/init.rs`) — the CLI's
/// trailing colon and space are its prompt separator and drop
/// out because `AdwPasswordEntryRow` renders its title as a
/// floating label above the entry rather than as a prefix.
/// Pinning the title through a helper keeps the GTK / CLI
/// wording aligned against a single source of truth so a future
/// copy change cannot diverge silently.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`format_init_dialog_passphrase_title`] on the dialog-
/// passphrase-row side; together they pin both passphrase-entry
/// captions in the encrypted-path `InitDialog` against a single
/// source of truth, and the cross-check test in
/// `tests/init_dialog_logic.rs` asserts the two helpers resolve
/// to distinct strings so the user can tell which row is which.
#[must_use]
pub fn format_init_dialog_confirm_passphrase_title() -> &'static str {
    "Confirm passphrase"
}

/// Caption rendered beside the
/// [`InitDialogComponent`]'s plaintext-warning acknowledgement
/// `gtk::CheckButton`.
///
/// Returns the short affirmative `"I accept this risk"`. The
/// wording mirrors the closing line of
/// [`paladin_core::format_plaintext_storage_warning()`] —
/// "Use an encrypted vault unless you fully accept this risk." —
/// so the checkbox caption reads as the affirmative of the
/// advisory text rendered directly beside it. The longer warning
/// body lives in [`paladin_core::format_plaintext_storage_warning`]
/// and is rendered separately above the checkbox; this helper
/// only covers the short affirmative caption attached to the
/// checkbox itself.
///
/// The gate is required by §"Component tree" > `InitDialog` —
/// the plaintext path stays disabled until the user ticks the
/// checkbox, matching the §10 routing test "Plaintext-warning
/// gate must be ticked before submission is allowed". Pinning
/// the label through a helper keeps the wording in one place
/// shared by the widget binding and the pure-logic tests in
/// `tests/init_dialog_logic.rs`.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`plaintext_warning_body`] on the plaintext-warning-surface
/// side; together they pin the standalone warning body and the
/// affirmative checkbox caption against a single source of
/// truth.
#[must_use]
pub fn format_init_dialog_plaintext_warning_label() -> &'static str {
    "I accept this risk"
}

/// Heading the widget hands to the
/// [`InitDialogComponent`]'s destructive `vault_exists` race
/// gate `AdwAlertDialog::set_heading`.
///
/// Returns the static heading string `"Replace existing vault?"`
/// — the question-form GNOME-HIG heading for the destructive
/// gate. The destructive gate opens when a vault appears between
/// `inspect` and `create` (precheck reported `Clear` but the
/// race resolved to `Existing`); the heading reads as the
/// question, paired with [`format_init_dialog_force_confirm_label`]
/// (`"Replace"`) so the affirmative button reads as the matched
/// answer. The body of the `AlertDialog` comes from
/// [`destructive_gate_body`] (which routes through
/// [`paladin_core::format_init_force_warning`]); this helper
/// only covers the short heading rendered above it.
///
/// Pinning the heading through a helper keeps the wording in one
/// place shared by the widget binding and the pure-logic tests
/// in `tests/init_dialog_logic.rs`. Sibling of
/// [`crate::add_account::format_duplicate_alert_heading`]
/// (`"Add anyway?"`) on the destructive-AlertDialog-heading side;
/// together they pin every `AdwAlertDialog` heading in this
/// crate as a question caption against a single source of truth.
///
/// Pure — returns a `'static str` without allocating.
#[must_use]
pub fn format_init_dialog_force_heading() -> &'static str {
    "Replace existing vault?"
}

/// Destructive action-button label the [`InitDialogComponent`]'s
/// `vault_exists` race gate renders on its in-dialog
/// `AdwAlertDialog` with `destructive-action` styling.
///
/// Returns the bare verb `"Replace"`. The destructive gate
/// opens when a vault appears between `inspect` and `create`
/// (precheck reported `Clear` but the race resolved to
/// `Existing`); confirming routes through `Store::create_force`,
/// which rotates the existing vault to `vault.bin.bak` and
/// writes the new one — i.e. **replaces** the existing file.
/// The GNOME-HIG verb for that affordance is the bare
/// `"Replace"` — not "Overwrite" (used by the file-overwrite
/// gate in [`crate::export_dialog`] for a different surface),
/// not "Create" (which would overlap the primary submit-button
/// caption returned by [`format_init_dialog_create_label`]),
/// and not "Confirm" (too generic for a destructive-action
/// button caption).
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from [`format_init_dialog_create_label`] so the two action
/// surfaces stay visually separable rather than collapsing onto
/// the same word.
#[must_use]
pub fn format_init_dialog_force_confirm_label() -> &'static str {
    "Replace"
}

/// Cancel-button label the [`InitDialogComponent`]'s
/// `vault_exists` race gate renders on its in-dialog
/// `AdwAlertDialog` with `destructive-action` styling.
///
/// Returns the bare verb `"Cancel"`. Pressing the button closes
/// the destructive gate and leaves the existing vault
/// untouched — explicitly required by the §10 routing test
/// "Cancelling the destructive gate leaves the existing vault".
/// Pinning the wording to `"Cancel"` keeps the destructive-gate
/// cancel affordance and every other dialog footer cancel
/// affordance in this crate rendering the same string so the
/// application's cancel-action vocabulary stays uniform — a
/// drift would surface as a confusing "Cancel" vs "Dismiss" vs
/// "Close" inconsistency when the user reaches the same cancel
/// action from two different dialogs.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from [`format_init_dialog_force_confirm_label`] so the two
/// affordances read as different actions. Companion of
/// [`crate::remove_dialog::format_remove_dialog_cancel_label`],
/// [`crate::rename_dialog::format_rename_dialog_cancel_label`],
/// and [`crate::add_account::format_add_dialog_cancel_label`]
/// on the dialog-footer-cancel side; the cross-check test in
/// `tests/init_dialog_logic.rs` asserts every cancel helper
/// resolves to the same wording.
#[must_use]
pub fn format_init_dialog_force_cancel_label() -> &'static str {
    "Cancel"
}

/// Construction parameters for [`InitDialogComponent`].
#[derive(Debug, Clone)]
pub struct InitDialogInit {
    /// Resolved vault path the dialog targets on submit. Surfaced
    /// in the dialog body so the user can confirm the destination
    /// before creating a vault.
    pub vault_path: PathBuf,
}

/// Live state owned by [`InitDialogComponent`].
///
/// Wraps the shared [`InitSecretState`] (passphrase + confirm
/// [`crate::secret_fields::SecretEntry`] shadow buffers plus the
/// destructive-gate pending [`VaultInit`]) and tracks the additional
/// dialog-local state: the plaintext-warning acknowledgement
/// checkbox and the [`InlineError`] slot the widget binds to its
/// inline-error label.
///
/// The struct deliberately does not derive `Debug` — `InitSecretState`
/// is the §8 boundary that keeps secret bytes inside `Zeroizing<String>`
/// and out of `Debug` output.
#[derive(Default)]
pub struct InitDialogState {
    secret: InitSecretState,
    plaintext_warning_acknowledged: bool,
    inline_error: Option<InlineError>,
}

impl InitDialogState {
    /// Construct an empty state — equivalent to `Self::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the passphrase shadow buffer with the entry row's
    /// current text.
    ///
    /// Called from the widget's `connect_changed` signal on every
    /// keystroke. Also dismisses any prior [`InlineError`] so the
    /// dialog never carries a stale message into the next attempt —
    /// mirrors the [`crate::unlock_dialog::UnlockDialogState`]
    /// affordance.
    pub fn set_passphrase(&mut self, text: &str) {
        self.secret.passphrase.set(text);
        self.inline_error = None;
    }

    /// Replace the confirm-passphrase shadow buffer with the entry
    /// row's current text. Also dismisses any prior [`InlineError`].
    pub fn set_confirm(&mut self, text: &str) {
        self.secret.confirm.set(text);
        self.inline_error = None;
    }

    /// Flip the plaintext-warning acknowledgement flag.
    ///
    /// Called from the warning checkbox's `connect_toggled` signal.
    /// Also dismisses any prior [`InlineError`] so toggling the
    /// checkbox after a stale rejection clears the message.
    pub fn set_plaintext_warning(&mut self, acknowledged: bool) {
        self.plaintext_warning_acknowledged = acknowledged;
        self.inline_error = None;
    }

    /// Borrow the passphrase shadow buffer.
    #[must_use]
    pub fn passphrase_text(&self) -> &str {
        self.secret.passphrase.text()
    }

    /// Borrow the confirm-passphrase shadow buffer.
    #[must_use]
    pub fn confirm_text(&self) -> &str {
        self.secret.confirm.text()
    }

    /// Whether the plaintext-warning checkbox is ticked.
    #[must_use]
    pub fn plaintext_warning_acknowledged(&self) -> bool {
        self.plaintext_warning_acknowledged
    }

    /// Borrow the inline-error slot for the widget's `gtk::Label`
    /// binding.
    #[must_use]
    pub fn inline_error(&self) -> Option<&InlineError> {
        self.inline_error.as_ref()
    }

    /// Replace the inline-error slot.
    ///
    /// `Some(_)` is staged by the worker dispatch site when
    /// [`run_init_worker`] returns [`InitWorkerEffect::InlineError`];
    /// `None` clears the slot on a successful destructive-gate
    /// cancel or after the user starts typing.
    pub fn set_inline_error(&mut self, err: Option<InlineError>) {
        self.inline_error = err;
    }

    /// Whether a destructive-gate `VaultInit` is staged in the
    /// pending slot.
    ///
    /// Used by the widget to flip the destructive
    /// [`adw::AlertDialog`] into visible state once
    /// `InitWorkerEffect::DestructiveGate` lands.
    #[must_use]
    pub fn has_pending_force(&self) -> bool {
        self.secret.pending.is_some()
    }

    /// Classify the dialog's current passphrase-field contents.
    #[must_use]
    pub fn mode(&self) -> InitMode {
        classify_mode(self.passphrase_text(), self.confirm_text())
    }

    /// Whether the primary "Create vault" button is currently
    /// sensitive.
    ///
    /// The widget's `#[watch] set_sensitive` binding reads this
    /// predicate so the per-mode gate in [`prepare_vault_init`]
    /// never fires through a normal click:
    ///
    /// * Plaintext mode requires the warning checkbox ticked.
    /// * Encrypted mode requires both fields non-empty and matching.
    ///
    /// Defense-in-depth: a stray keyboard accelerator that bypasses
    /// the sensitivity binding still goes through
    /// [`InitDialogState::submit`] which re-runs
    /// [`prepare_vault_init`] and stages the typed rejection.
    #[must_use]
    pub fn submit_button_sensitive(&self) -> bool {
        match self.mode() {
            InitMode::Plaintext => self.plaintext_warning_acknowledged,
            InitMode::Encrypted => {
                !self.passphrase_text().is_empty()
                    && !self.confirm_text().is_empty()
                    && self.passphrase_text() == self.confirm_text()
            }
        }
    }

    /// Run the pre-submit gate when the "Create vault" button fires.
    ///
    /// Delegates to [`prepare_vault_init`] on the current passphrase
    /// shadow buffers and the warning-acknowledgement flag.
    ///
    /// On success, the passphrase shadow buffers are **preserved** so
    /// the destructive-gate retry path can re-derive a second
    /// [`VaultInit`] (the type is non-`Clone`) when the worker
    /// returns [`InitWorkerEffect::DestructiveGate`]. The dialog
    /// stays in [`crate::app::state::AppState::UnlockedBusy`] while
    /// the worker is in flight so editing is disabled and the buffers
    /// cannot drift before the destructive-gate decision is made.
    /// `consume_pending` (the destructive-confirm path) and
    /// [`clear_for`](Self::clear_for) (cancel / close / auto-lock)
    /// wipe the buffers when they complete.
    ///
    /// On rejection, the buffers are left untouched so the user can
    /// correct without retyping. `ConfirmationMismatch` stages an
    /// inline error via [`InlineError::from_rejection`];
    /// `PlaintextWarningRequired` returns the rejection without
    /// staging an inline error (the unticked warning gate is rendered
    /// separately by the widget).
    ///
    /// # Errors
    ///
    /// Returns [`SubmitRejection`] when the §5 pre-vault gate fails.
    pub fn submit(&mut self) -> Result<VaultInit, SubmitRejection> {
        match prepare_vault_init(
            self.passphrase_text(),
            self.confirm_text(),
            self.plaintext_warning_acknowledged,
        ) {
            Ok(init) => {
                self.inline_error = None;
                Ok(init)
            }
            Err(rejection) => {
                self.inline_error = InlineError::from_rejection(rejection);
                Err(rejection)
            }
        }
    }

    /// Re-derive a fresh [`VaultInit`] from the current buffers and
    /// stage it in the pending slot, returning the prior pending (if
    /// any).
    ///
    /// Called from [`apply_msg`]'s
    /// [`InitDialogMsg::WorkerCompletedDestructive`] arm so the
    /// destructive-gate confirm path has a `VaultInit` to consume on
    /// the create-force re-run. `VaultInit` is non-`Clone`, so we
    /// cannot keep a copy alongside the one consumed by the first
    /// worker call — instead we rebuild a second value from the
    /// preserved buffers.
    ///
    /// Returns `Ok(prior_pending)` on success; the prior pending (if
    /// any) is returned for the caller to drop explicitly so its
    /// `SecretString` passphrase zeroes. Returns `Err(rejection)` if
    /// [`prepare_vault_init`] now refuses (e.g., the user managed to
    /// modify the buffers between Submit and the worker return — the
    /// dialog should be disabled during this window, so this branch
    /// is defensive).
    ///
    /// # Errors
    ///
    /// Returns [`SubmitRejection`] when the §5 pre-vault gate refuses
    /// the rebuild.
    pub fn stage_pending_for_force(&mut self) -> Result<Option<VaultInit>, SubmitRejection> {
        let init = prepare_vault_init(
            self.passphrase_text(),
            self.confirm_text(),
            self.plaintext_warning_acknowledged,
        )?;
        Ok(self.secret.replace_pending(init))
    }

    /// Stage a freshly built [`VaultInit`] in the pending slot,
    /// returning the prior pending (if any).
    ///
    /// Called by the worker dispatch site after [`InitDialogState::submit`]
    /// succeeds so the destructive-gate re-run path
    /// ([`InitWorkerEffect::DestructiveGate`] → user confirms force)
    /// can consume the same `VaultInit` without re-deriving it from
    /// the passphrase buffers — which by then have been wiped.
    /// Mirrors [`InitSecretState::replace_pending`].
    pub fn stage_pending(&mut self, init: VaultInit) -> Option<VaultInit> {
        self.secret.replace_pending(init)
    }

    /// Consume the pending [`VaultInit`] for a `create_force` re-run.
    ///
    /// Wipes both passphrase buffers as a side effect — mirrors
    /// [`InitSecretState::consume_pending`]. Returns `None` when no
    /// pending is staged (defensive: a stray force-confirm dispatch
    /// without an active first-pass submit).
    #[must_use]
    pub fn consume_pending(&mut self) -> Option<VaultInit> {
        self.secret.consume_pending()
    }

    /// Wipe both passphrase buffers and drop any pending
    /// [`VaultInit`].
    ///
    /// Mirrors [`InitSecretState::clear_for`] — covers Submit /
    /// Cancel / Close / `AutoLock` / Replace per DESIGN §8. Returns
    /// the prior pending so the caller can drop it explicitly.
    /// Also clears the inline-error slot so a re-mounted dialog
    /// does not flash a stale message.
    pub fn clear_for(&mut self, reason: ClearReason) -> Option<VaultInit> {
        let prior = self.secret.clear_for(reason);
        self.inline_error = None;
        prior
    }
}

/// Messages handled by [`InitDialogComponent`].
///
/// Live keystrokes from the two passphrase entries and toggles of
/// the plaintext-warning checkbox arrive as
/// [`Self::PassphraseChanged`] / [`Self::ConfirmChanged`] /
/// [`Self::WarningToggled`]; the handler shadows the typed bytes /
/// flag into the [`InitDialogState`] so the cleartext lives in
/// Paladin-owned memory rather than escaping through `AppMsg` /
/// `AppOutput`. [`Self::SubmitClicked`] arrives from the "Create
/// vault" button's `connect_clicked`; the handler runs
/// [`InitDialogState::submit`] so the typed rejection stages an
/// inline error and the `Ok` branch forwards as
/// [`InitDialogOutput::SubmitCreate`]. [`Self::ForceConfirmClicked`] /
/// [`Self::ForceCancelClicked`] arrive from the destructive
/// [`adw::AlertDialog`]'s two buttons after the worker reports
/// [`InitWorkerEffect::DestructiveGate`]. [`Self::WorkerCompletedInline`] is
/// pushed back from `AppModel` after the worker returns
/// [`InitWorkerEffect::InlineError`]; the handler stages the
/// pre-projected [`InlineError`] into [`InitDialogState`]'s inline
/// slot so the dialog body can render it.
///
/// `Clone` is unnecessary — the relm4 channel consumes the message
/// by value — and would conflict with the `VaultInit` carried by
/// [`InitDialogOutput`] (whose [`EncryptionOptions`] passphrase is a
/// non-`Clone` [`secrecy::SecretString`]).
#[derive(Debug)]
pub enum InitDialogMsg {
    /// Raw text from the passphrase [`adw::PasswordEntryRow`] after
    /// a keystroke. Carries `String` because the [`gtk::EntryBuffer`]
    /// is the unavoidable §8 UI boundary; the bytes transit the
    /// relm4 channel before the handler shadows them into the
    /// [`crate::secret_fields::SecretEntry`].
    PassphraseChanged(String),
    /// Raw text from the confirm-passphrase
    /// [`adw::PasswordEntryRow`] after a keystroke. Mirrors
    /// [`Self::PassphraseChanged`] for the second entry row.
    ConfirmChanged(String),
    /// New value of the plaintext-warning [`gtk::CheckButton`] after
    /// a toggle.
    WarningToggled(bool),
    /// The "Create vault" button was clicked. Routes through
    /// [`apply_msg`] / [`InitDialogState::submit`]; success forwards
    /// [`InitDialogOutput::SubmitCreate`].
    SubmitClicked,
    /// The destructive [`adw::AlertDialog`]'s confirm button (worded
    /// `"Replace"` per [`format_init_dialog_force_confirm_label`])
    /// was clicked. Routes through [`apply_msg`] /
    /// [`InitDialogState::consume_pending`] and forwards
    /// [`InitDialogOutput::SubmitForceCreate`].
    ForceConfirmClicked,
    /// The destructive [`adw::AlertDialog`]'s cancel button (worded
    /// `"Cancel"` per [`format_init_dialog_force_cancel_label`]) was
    /// clicked. The handler drops the pending [`VaultInit`] and
    /// wipes both passphrase buffers via
    /// [`InitDialogState::clear_for`] with [`ClearReason::Cancel`].
    ForceCancelClicked,
    /// `AppModel` pushes the [`InlineError`] branch of
    /// [`InitWorkerEffect::InlineError`] back to the dialog after
    /// the worker returns a typed failure. The handler stages the
    /// pre-projected error into the dialog's inline-error slot.
    WorkerCompletedInline(InlineError),
    /// `AppModel` pushes this after the worker returns
    /// [`InitWorkerEffect::DestructiveGate`]. The handler re-derives
    /// a fresh [`VaultInit`] from the preserved passphrase buffers
    /// via [`InitDialogState::stage_pending_for_force`] and stages it
    /// in the pending slot so the [`Self::ForceConfirmClicked`] path
    /// has a value to consume for the `create_force` worker call.
    /// The destructive [`adw::AlertDialog`]'s visibility is bound to
    /// [`InitDialogState::has_pending_force`] so staging the pending
    /// triggers the dialog to show itself.
    WorkerCompletedDestructive,
}

/// Outputs forwarded from [`InitDialogComponent`] up to `AppModel`.
///
/// Carries the [`VaultInit`] the GUI handed to
/// [`InitDialogState::submit`] (first-pass [`Self::SubmitCreate`]) or
/// to [`InitDialogState::consume_pending`] (destructive-gate re-run
/// [`Self::SubmitForceCreate`]) so `AppModel::update` can build the
/// matching [`InitWorkerInput`] and spawn the worker on
/// `gtk::gio::spawn_blocking` without re-deriving the value from the
/// dialog's now-wiped passphrase buffers.
///
/// Not `Clone` / `PartialEq` because [`VaultInit::Encrypted`] wraps a
/// [`paladin_core::EncryptionOptions`] whose `SecretString` passphrase
/// is intentionally non-`Clone` / non-`Eq`: the cleartext bytes must
/// move once into the worker and zeroize on drop. `AppModel`'s
/// handler consumes the variant by value and never observes the
/// cleartext again.
#[derive(Debug)]
pub enum InitDialogOutput {
    /// "Create vault" button pressed with a valid first-pass
    /// submission (plaintext + warning ticked, or encrypted +
    /// matching pair). Carries the [`VaultInit`] for
    /// [`InitWorkerMode::Create`] dispatch.
    SubmitCreate(VaultInit),
    /// Destructive [`adw::AlertDialog`] confirm button pressed after
    /// [`InitWorkerEffect::DestructiveGate`]. Carries the
    /// [`VaultInit`] previously staged via
    /// [`InitDialogState::stage_pending`] for
    /// [`InitWorkerMode::CreateForce`] dispatch.
    SubmitForceCreate(VaultInit),
}

/// Apply an inbound [`InitDialogMsg`] to `state` and return the
/// optional [`InitDialogOutput`] the widget layer should forward to
/// `AppModel`.
///
/// Pulled out of [`InitDialogComponent::update`] so the per-message
/// routing decisions stay unit-testable in
/// `tests/init_dialog_logic.rs` without spinning up GTK / libadwaita.
///
/// * [`InitDialogMsg::PassphraseChanged`] /
///   [`InitDialogMsg::ConfirmChanged`] /
///   [`InitDialogMsg::WarningToggled`] shadow the value into the
///   matching [`InitDialogState`] slot and emit no output.
/// * [`InitDialogMsg::SubmitClicked`] runs
///   [`InitDialogState::submit`]: rejection stages the inline
///   projection (or is silently ignored for the plaintext-warning
///   gate); the `Ok` branch is staged in the pending slot via
///   [`InitDialogState::stage_pending`] and forwarded as
///   [`InitDialogOutput::SubmitCreate`].
/// * [`InitDialogMsg::ForceConfirmClicked`] consumes the pending
///   [`VaultInit`] via [`InitDialogState::consume_pending`] and
///   forwards [`InitDialogOutput::SubmitForceCreate`]; a stray
///   dispatch without a pending value is a benign no-op.
/// * [`InitDialogMsg::ForceCancelClicked`] drops the pending value
///   and wipes both passphrase buffers via
///   [`InitDialogState::clear_for`] with [`ClearReason::Cancel`].
/// * [`InitDialogMsg::WorkerCompletedInline`] stages the
///   pre-projected error into [`InitDialogState`]'s inline slot.
pub fn apply_msg(state: &mut InitDialogState, msg: InitDialogMsg) -> Option<InitDialogOutput> {
    match msg {
        InitDialogMsg::PassphraseChanged(text) => {
            state.set_passphrase(&text);
            None
        }
        InitDialogMsg::ConfirmChanged(text) => {
            state.set_confirm(&text);
            None
        }
        InitDialogMsg::WarningToggled(value) => {
            state.set_plaintext_warning(value);
            None
        }
        InitDialogMsg::SubmitClicked => match state.submit() {
            Ok(init) => Some(InitDialogOutput::SubmitCreate(init)),
            Err(_rejection) => None,
        },
        InitDialogMsg::ForceConfirmClicked => state
            .consume_pending()
            .map(InitDialogOutput::SubmitForceCreate),
        InitDialogMsg::ForceCancelClicked => {
            let _ = state.clear_for(ClearReason::Cancel);
            None
        }
        InitDialogMsg::WorkerCompletedInline(inline) => {
            state.set_inline_error(Some(inline));
            None
        }
        InitDialogMsg::WorkerCompletedDestructive => {
            // Rebuild a fresh `VaultInit` from the preserved buffers
            // and stage it in pending. The destructive
            // `adw::AlertDialog`'s `set_visible` watch on
            // `has_pending_force()` flips to `true`, surfacing the
            // alert. A rebuild rejection here is defensive — the
            // dialog is in `UnlockedBusy` while the worker runs so
            // the buffers should be intact — but is silently dropped
            // because the prior submit succeeded by definition (the
            // worker would not have returned `DestructiveGate`
            // otherwise).
            let _ = state.stage_pending_for_force();
            None
        }
    }
}

/// Widget-bearing dialog for the
/// [`crate::app::state::AppState::Missing`] branch.
///
/// Mounts a libadwaita [`adw::StatusPage`] heading naming the
/// resolved vault path, two [`adw::PasswordEntryRow`] entries
/// (passphrase + confirmation) inside an
/// [`adw::PreferencesGroup`], a [`gtk::CheckButton`] for the
/// plaintext-storage warning acknowledgement, an inline-error
/// [`gtk::Label`] beneath the entries, and a "Create vault" submit
/// button whose sensitivity binds to
/// [`InitDialogState::submit_button_sensitive`] so the per-mode gate
/// in [`prepare_vault_init`] never fires through a normal click.
/// Keystrokes in the passphrase entries shadow into the model's
/// [`InitDialogState`] [`crate::secret_fields::SecretEntry`] buffers;
/// the warning checkbox feeds the same state's acknowledgement
/// flag. The button's `connect_clicked` signal routes through
/// [`apply_msg`] / [`InitDialogState::submit`]; success forwards
/// [`InitDialogOutput::SubmitCreate`] to `AppModel` for the
/// `Store::create` worker dispatch. The destructive
/// [`adw::AlertDialog`] for the `vault_exists` race is presented
/// from [`update`](SimpleComponent::update) on
/// [`InitDialogMsg::WorkerCompletedDestructive`] so the alert can be
/// constructed fresh each time with response callbacks dispatching
/// [`InitDialogMsg::ForceConfirmClicked`] /
/// [`InitDialogMsg::ForceCancelClicked`].
pub struct InitDialogComponent {
    /// Resolved vault path the dialog will hand to a
    /// `Store::create` worker on submit. Surfaced in the dialog body
    /// and in the destructive-gate [`adw::AlertDialog`] body.
    vault_path: PathBuf,
    /// Live state owned by the dialog: passphrase + confirm shadow
    /// buffers, the plaintext-warning acknowledgement flag, and the
    /// inline-error slot the widget binds to its error label.
    state: InitDialogState,
    /// Reference-counted handle to the root [`gtk::Box`] so the
    /// destructive [`adw::AlertDialog`] in [`update`] can use it as
    /// a presentation parent (`AdwDialog::present` walks up to the
    /// active [`adw::ApplicationWindow`] from any descendant).
    /// `gtk::Box` is a `GObject`, so cloning just bumps the
    /// reference count rather than duplicating the widget.
    root_box: gtk::Box,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for InitDialogComponent {
    type Init = InitDialogInit;
    type Input = InitDialogMsg;
    type Output = InitDialogOutput;

    view! {
        #[root]
        #[name = "root_box"]
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 12,
            set_hexpand: true,
            set_vexpand: true,

            adw::StatusPage {
                set_icon_name: Some(format_init_dialog_icon_name()),
                set_title: format_init_dialog_title(),
                set_description: Some(&format_init_dialog_description(&model.vault_path)),
                set_hexpand: true,
            },

            adw::PreferencesGroup {
                #[name = "passphrase_row"]
                add = &adw::PasswordEntryRow {
                    set_title: format_init_dialog_passphrase_title(),
                    // `connect_changed` fires on every keystroke so
                    // the `SecretEntry` shadow buffer tracks the live
                    // entry and Paladin-owned `Zeroizing<String>` is
                    // the only long-lived home for the cleartext
                    // bytes.
                    connect_changed[sender] => move |entry| {
                        sender.input(InitDialogMsg::PassphraseChanged(
                            entry.text().to_string(),
                        ));
                    },
                },
                #[name = "confirm_row"]
                add = &adw::PasswordEntryRow {
                    set_title: format_init_dialog_confirm_passphrase_title(),
                    connect_changed[sender] => move |entry| {
                        sender.input(InitDialogMsg::ConfirmChanged(
                            entry.text().to_string(),
                        ));
                    },
                },
            },

            // Plaintext-warning acknowledgement checkbox. The
            // standard warning body is already surfaced through the
            // `AdwStatusPage` `set_description` above
            // (`format_init_dialog_description`); this `gtk::CheckButton`
            // carries the short affirmative caption and gates the
            // plaintext path's `submit_button_sensitive` until the
            // user explicitly acknowledges.
            #[name = "warning_check"]
            gtk::CheckButton {
                set_label: Some(format_init_dialog_plaintext_warning_label()),
                connect_toggled[sender] => move |btn| {
                    sender.input(InitDialogMsg::WarningToggled(btn.is_active()));
                },
            },

            // Inline-error label. The post-submit / post-worker
            // `WorkerCompletedInline` arms populate
            // `state.inline_error`; typing in either entry or
            // toggling the warning checkbox dismisses the prior
            // message through the dedicated `set_*` clearers.
            #[name = "error_label"]
            gtk::Label {
                set_xalign: 0.0,
                set_wrap: true,
                add_css_class: "error",
                #[watch]
                set_label: model
                    .state
                    .inline_error()
                    .map_or("", |err| err.rendered.as_str()),
                #[watch]
                set_visible: model.state.inline_error().is_some(),
            },

            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 6,
                set_halign: gtk::Align::End,

                // "Create vault" submit button. The `suggested-action`
                // CSS class renders it as the primary affordance per
                // the libadwaita HIG. `set_sensitive` binds to
                // `submit_button_sensitive` so the per-mode gate in
                // `prepare_vault_init` never fires through a normal
                // click. `connect_clicked` dispatches `SubmitClicked`,
                // whose handler routes through `apply_msg`: rejection
                // stages the inline error inline beneath the entries;
                // the `Ok` branch is forwarded as
                // `InitDialogOutput::SubmitCreate`. The
                // `gio::spawn_blocking Store::create` worker that
                // consumes the forwarded `VaultInit` lands in the
                // follow-up `AppModel` dispatch commit.
                #[name = "create_button"]
                gtk::Button {
                    set_label: format_init_dialog_create_label(),
                    add_css_class: "suggested-action",
                    #[watch]
                    set_sensitive: model.state.submit_button_sensitive(),
                    connect_clicked[sender] => move |_| {
                        sender.input(InitDialogMsg::SubmitClicked);
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
        let root_box = root.clone();
        let model = InitDialogComponent {
            vault_path: init.vault_path,
            state: InitDialogState::new(),
            root_box,
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        // Capture whether this dispatch is the worker→destructive
        // signal *before* `apply_msg` consumes the message, so the
        // post-routing branch below can react after the pending
        // VaultInit has been staged.
        let was_worker_destructive = matches!(msg, InitDialogMsg::WorkerCompletedDestructive);

        if let Some(output) = apply_msg(&mut self.state, msg) {
            // Ignore send failures: if `AppModel` has already dropped
            // the controller (e.g. window closed mid-click), there's
            // nothing left to dismiss.
            let _ = sender.output(output);
        }

        // After `apply_msg` returns from `WorkerCompletedDestructive`,
        // the pending [`VaultInit`] is staged and `has_pending_force()`
        // is `true`. Present the destructive [`adw::AlertDialog`]
        // worded by [`destructive_gate_body`] (same wording as the
        // CLI `init --force` confirmation); response callbacks dispatch
        // back through the same sender so the AlertDialog stays
        // self-contained.
        if was_worker_destructive && self.state.has_pending_force() {
            self.present_destructive_alert(&sender);
        }
    }
}

impl InitDialogComponent {
    /// Construct and present the destructive `vault_exists`
    /// [`adw::AlertDialog`].
    ///
    /// The alert is built fresh each time so heading / body / button
    /// labels resolve through the pinned format helpers without
    /// re-binding stateful widgets across presentations. The
    /// `replace` response is styled `destructive-action`; the
    /// `cancel` response is the default and is invoked on Escape /
    /// outside-click via `set_close_response`. Both responses
    /// dispatch the matching [`InitDialogMsg`] through `sender` so
    /// `apply_msg` remains the single routing entry point.
    fn present_destructive_alert(&self, sender: &ComponentSender<Self>) {
        let alert = adw::AlertDialog::new(
            Some(format_init_dialog_force_heading()),
            Some(&destructive_gate_body(&self.vault_path)),
        );
        let cancel_id = "cancel";
        let confirm_id = "replace";
        alert.add_response(cancel_id, format_init_dialog_force_cancel_label());
        alert.add_response(confirm_id, format_init_dialog_force_confirm_label());
        alert.set_response_appearance(confirm_id, adw::ResponseAppearance::Destructive);
        alert.set_default_response(Some(cancel_id));
        alert.set_close_response(cancel_id);

        let confirm_id_owned = confirm_id.to_string();
        let sender = sender.clone();
        alert.connect_response(None, move |_dialog, response| {
            if response == confirm_id_owned {
                sender.input(InitDialogMsg::ForceConfirmClicked);
            } else {
                sender.input(InitDialogMsg::ForceCancelClicked);
            }
        });

        alert.present(Some(&self.root_box));
    }
}
