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
    InitPrecheck, PaladinError, Store, Vault, VaultInit, VaultStatus,
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
            set_icon_name: Some(format_init_dialog_icon_name()),
            set_title: format_init_dialog_title(),
            set_description: Some(&format_init_dialog_description(&model.vault_path)),
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
