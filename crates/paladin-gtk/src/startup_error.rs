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

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;
use relm4::ComponentSender;

use paladin_core::{format_unsafe_permissions, ErrorKind, PaladinError, VaultStatus};

use crate::effect_ownership::EffectKind;

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
    /// A `gio::spawn_blocking` worker panicked or otherwise failed
    /// to return its `(Vault, Store)` pair to the dispatch site.
    /// `AppModel` routes the surface to `StartupErrorComponent`
    /// rather than reconstructing in-memory vault state per
    /// `IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership".
    /// Carries the [`EffectKind`] of the failed worker for
    /// instrumentation and rendered-body wording.
    WorkerPanic(EffectKind),
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

    /// Build a [`StartupError`] for a `gio::spawn_blocking` worker
    /// that panicked / failed before returning its `(Vault, Store)`
    /// pair.
    ///
    /// The rendered body comes from [`format_worker_panic_message`]
    /// so the wording is grep-able and pinned by tests. `kind`
    /// resolves to [`ErrorKind::IoError`] — a worker panic interrupts
    /// the durability contract of the in-flight save, which is the
    /// closest match in the typed §5 error palette without leaking
    /// a GUI-specific kind into `paladin_core`.
    #[must_use]
    pub fn from_worker_panic(effect: EffectKind) -> Self {
        Self {
            source: StartupErrorSource::WorkerPanic(effect),
            kind: ErrorKind::IoError,
            rendered: format_worker_panic_message(effect),
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

/// Render the `StartupErrorComponent` body text for a worker-panic
/// transition.
///
/// Names the affected operation through [`EffectKind::user_name`] and
/// instructs the user to restart Paladin. The exact wording is
/// pinned by tests in `tests/startup_error_logic.rs` so a future
/// rewording does not silently break instrumentation that greps for
/// it. The leading sentence stays single-line so
/// [`format_startup_error_marker`]'s `'\n' → '|'` substitution does
/// not corrupt the smoke-test stdout marker.
///
/// No TUI parity: the TUI does not run vault work on a separate
/// thread, so it has no worker-panic surface.
#[must_use]
pub fn format_worker_panic_message(effect: EffectKind) -> String {
    format!(
        "A background task ({}) failed unexpectedly. Restart Paladin to continue.",
        effect.user_name(),
    )
}

/// Stdout marker prefix emitted under `--exit-after-startup` once
/// the `StartupErrorComponent` has mounted with a rendered body.
///
/// The smoke test in `tests/gtk_smoke.rs` greps for this prefix to
/// prove that the widget actually mounted on the
/// [`crate::app::state::AppState::StartupError`] branch (rather than
/// inferring the render from the `startup_state=StartupError` line,
/// which is emitted before any per-state widget is mounted).
pub const STARTUP_ERROR_MARKER_PREFIX: &str = "paladin-gtk: startup_error_body=";

/// Format the smoke-test stdout marker line for a mounted
/// [`StartupError`].
///
/// The marker is `paladin-gtk: startup_error_body=<rendered>` where
/// `<rendered>` is [`StartupError::rendered`] with any embedded
/// `'\n'` collapsed to `'|'` so the marker fits on a single line and
/// `tests/gtk_smoke.rs` can match it with `stdout.contains(...)`.
/// Newline collapse only matters for the multi-line
/// `UnsafePermissions` body (the chmod hint sits on its own line in
/// the CLI / TUI rendering); single-line bodies pass through
/// unchanged. The `'|'` separator is safe because no
/// `paladin_core::format_unsafe_permissions` or `PaladinError`
/// `Display` variant contains a pipe character.
#[must_use]
pub fn format_startup_error_marker(error: &StartupError) -> String {
    let single_line = error.rendered.replace('\n', "|");
    format!("{STARTUP_ERROR_MARKER_PREFIX}{single_line}")
}

/// Freedesktop icon name the widget hands to the
/// [`StartupErrorComponent`]'s `adw::StatusPage::set_icon_name`.
///
/// Returns the static icon name `"dialog-error-symbolic"` — the
/// freedesktop-standard glyph for an error surface shipped by
/// `adwaita-icon-theme` that resolves through the system icon
/// theme so the wordless glyph matches every other GNOME app's
/// error surface. The `-symbolic` suffix is required by the
/// libadwaita HIG for `AdwStatusPage` icons so the glyph
/// recolors with the theme. No TUI parity: the TUI is text-only
/// and has no icon to mirror. Pinning the icon name through a
/// helper keeps the string in one place shared by the widget
/// binding and the pure-logic tests.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_icon_name`] and
/// [`crate::init_dialog::format_init_dialog_icon_name`] on the
/// dialog-status-icon side; together they pin every first-mount
/// dialog's freedesktop glyph against a single source of truth.
#[must_use]
pub fn format_startup_error_icon_name() -> &'static str {
    "dialog-error-symbolic"
}

/// Fixed `title` attribute the widget hands to the
/// [`StartupErrorComponent`]'s `adw::StatusPage::set_title`.
///
/// Returns the static title string the surface renders at the
/// top of its body. The wording (`"Startup error"`) names the
/// error class without restating the specific failure — the
/// per-error rendered text lives in the `StatusPage`'s description
/// body, sourced from the typed [`paladin_core::PaladinError`]
/// `Display` impl through [`StartupError::rendered`]. Pinning
/// the title through a helper keeps the wording in one place
/// shared by the widget binding and the pure-logic tests in
/// `tests/startup_error_logic.rs`.
///
/// Pure — returns a `'static str` without allocating. Sibling of
/// [`crate::unlock_dialog::format_unlock_dialog_title`],
/// [`crate::init_dialog::format_init_dialog_title`],
/// [`crate::rename_dialog::format_rename_dialog_title`], and
/// [`crate::add_account::format_add_dialog_title`] on the
/// dialog-header-title side; together they pin every dialog's
/// titled surface against a single source of truth.
#[must_use]
pub fn format_startup_error_title() -> &'static str {
    "Startup error"
}

/// Action-button label the [`StartupErrorComponent`]'s
/// `adw::StatusPage` renders for the Retry action described
/// in §"Vault interaction".
///
/// Returns the bare verb `"Retry"`. Pressing the button re-runs
/// the path-resolution-then-inspect probe (the [`retry`] helper
/// in this module), and the HIG-aligned wording for that kind
/// of probe re-run on `AdwStatusPage` surfaces is the bare verb
/// form — not "Try again" or "Reload". Pinning the wording
/// through a helper keeps the button label in one place shared
/// by the widget binding and the pure-logic tests in
/// `tests/startup_error_logic.rs`.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from [`format_startup_error_title`] (the
/// `adw::StatusPage::set_title` wording) so the action button
/// caption and the surface title are visually separable rather
/// than rendering the same string twice.
#[must_use]
pub fn format_startup_error_retry_label() -> &'static str {
    "Retry"
}

/// Action-button label the [`StartupErrorComponent`]'s
/// `adw::StatusPage` renders for the Quit action described in
/// §"Vault interaction".
///
/// Returns the bare verb `"Quit"`. Pressing the button tears
/// the application down via the same primary `app.quit` action
/// the primary menu's Quit entry routes through; pinning the
/// wording to `"Quit"` keeps the startup-error secondary action
/// and the primary menu's Quit entry rendering the same string
/// so the application's quit-action vocabulary stays
/// consistent across surfaces — a drift would surface as a
/// confusing "Quit" vs "Exit" inconsistency when the same
/// action is reached from two different surfaces.
///
/// Pure — returns a `'static str` without allocating. Distinct
/// from [`format_startup_error_retry_label`] so the two action
/// buttons read as separate options rather than rendering the
/// same caption twice. Companion of
/// [`crate::app::model::format_app_menu_quit_label`] on the
/// quit-action-label side; the cross-check test in
/// `tests/startup_error_logic.rs` asserts the two helpers
/// resolve to the same wording.
#[must_use]
pub fn format_startup_error_quit_label() -> &'static str {
    "Quit"
}

/// Construction parameters for [`StartupErrorComponent`].
#[derive(Debug, Clone)]
pub struct StartupErrorInit {
    /// Rendered error projection to bind into the status page body.
    pub error: StartupError,
}

/// Messages handled by [`StartupErrorComponent`].
///
/// The two `*Clicked` variants are dispatched by the matching
/// `gtk::Button::connect_clicked` handlers on the
/// [`adw::StatusPage`] action-row buttons rendered for the
/// Retry and Quit actions described in §"Vault interaction".
/// Routing through `apply_startup_error_msg` (the pure-logic
/// shape consumed by the relm4 `update` closure) emits the
/// matching [`StartupErrorOutput`], which `AppModel` forwards
/// through `crate::app::model::dispatch_startup_error_output`
/// to either re-run the startup probe or tear the application
/// down through the primary-menu shutdown path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupErrorMsg {
    /// The Retry button was clicked. Routes through
    /// [`apply_startup_error_msg`] to
    /// [`StartupErrorOutput::Retry`].
    RetryClicked,
    /// The Quit button was clicked. Routes through
    /// [`apply_startup_error_msg`] to
    /// [`StartupErrorOutput::Quit`].
    QuitClicked,
}

/// Outputs emitted by [`StartupErrorComponent`].
///
/// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction"
/// the `StartupErrorComponent` is display-only: Retry and Quit
/// are the only actions, and the component never creates,
/// overwrites, repairs, chmods, or selects a different vault
/// path in v0.2. The two variants here lock that contract on
/// the Output surface — adding a mutating variant (e.g. a
/// "create vault here" affordance) would require an explicit
/// design revisit in `DESIGN.md` and `IMPLEMENTATION_PLAN_04_GTK.md`.
///
/// `AppModel` consumes both variants by forwarding them through
/// `crate::app::model::dispatch_startup_error_output`:
/// [`StartupErrorOutput::Quit`] dispatches the same `AppMsg::Quit`
/// shutdown path the primary menu's Quit entry uses, and
/// [`StartupErrorOutput::Retry`] dispatches a dedicated
/// `AppMsg::StartupErrorRetry` that re-runs the path-resolution
/// and `inspect` probe and re-routes to the matching per-state
/// child controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupErrorOutput {
    /// User asked to re-run the startup probe.
    Retry,
    /// User asked to tear the application down through the
    /// primary-menu shutdown path.
    Quit,
}

/// Translate a [`StartupErrorMsg`] into the optional
/// [`StartupErrorOutput`] the widget layer should forward.
///
/// Pure — no side effects, no I/O. The relm4 `update` closure
/// reads the returned `Option` and calls
/// [`ComponentSender::output`] only when `Some`, matching the
/// emit-on-success pattern used by every other relm4 component
/// in this crate (`apply_msg` on `UnlockDialogComponent`,
/// `apply_msg` on `RemoveDialogComponent`, …). The pure shape
/// lets `tests/startup_error_logic.rs` exercise the
/// click-to-Output mapping without a display server.
#[must_use]
pub fn apply_startup_error_msg(msg: StartupErrorMsg) -> Option<StartupErrorOutput> {
    match msg {
        StartupErrorMsg::RetryClicked => Some(StartupErrorOutput::Retry),
        StartupErrorMsg::QuitClicked => Some(StartupErrorOutput::Quit),
    }
}

/// Widget-bearing non-mutating error surface for the
/// [`crate::app::state::AppState::StartupError`] branch.
///
/// Mounts a libadwaita [`adw::StatusPage`] whose body renders
/// [`StartupError::rendered`] verbatim, so the wording the user
/// sees matches `paladin_core::format_unsafe_permissions` /
/// `PaladinError::Display` exactly (same text the CLI and TUI use).
/// The component never creates, overwrites, or repairs vault files
/// — per §"Vault interaction", a vault path entered the
/// `StartupError` branch precisely because the binary could not
/// safely operate on the underlying file.
pub struct StartupErrorComponent {
    /// Cloned projection of the typed [`PaladinError`] that routed
    /// `AppModel` to `StartupError`. Kept on `self` so a future
    /// message handler (retry action) can read the source / kind
    /// without re-plumbing the value through every signal.
    #[allow(dead_code)]
    error: StartupError,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for StartupErrorComponent {
    type Init = StartupErrorInit;
    type Input = StartupErrorMsg;
    type Output = StartupErrorOutput;

    view! {
        #[root]
        adw::StatusPage {
            set_icon_name: Some(format_startup_error_icon_name()),
            set_title: format_startup_error_title(),
            set_description: Some(model.error.rendered.as_str()),
            set_hexpand: true,
            set_vexpand: true,

            #[wrap(Some)]
            set_child = &gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_halign: gtk::Align::Center,
                set_spacing: 12,

                gtk::Button {
                    set_label: format_startup_error_retry_label(),
                    add_css_class: "suggested-action",
                    add_css_class: "pill",
                    connect_clicked[sender] => move |_| {
                        sender.input(StartupErrorMsg::RetryClicked);
                    },
                },

                gtk::Button {
                    set_label: format_startup_error_quit_label(),
                    add_css_class: "pill",
                    connect_clicked[sender] => move |_| {
                        sender.input(StartupErrorMsg::QuitClicked);
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
        let model = StartupErrorComponent { error: init.error };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_startup_error_msg(msg) {
            let _ = sender.output(output);
        }
    }
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
