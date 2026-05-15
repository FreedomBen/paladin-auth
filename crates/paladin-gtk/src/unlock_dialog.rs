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

use std::path::{Path, PathBuf};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::prelude::*;
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

/// Stdout marker prefix emitted under `--exit-after-startup` once
/// the [`UnlockDialogComponent`] has mounted on the
/// [`crate::app::state::AppState::Locked`] branch.
///
/// The smoke test in `tests/gtk_smoke.rs` greps for this prefix to
/// prove the widget actually mounted (rather than inferring the
/// render from the `startup_state=Locked` line, which is emitted
/// before any per-state widget is mounted).
pub const UNLOCK_DIALOG_MARKER_PREFIX: &str = "paladin-gtk: unlock_dialog_path=";

/// Format the smoke-test stdout marker line for a mounted
/// [`UnlockDialogComponent`].
///
/// The marker is `paladin-gtk: unlock_dialog_path=<path>` where
/// `<path>` is the resolved vault path the dialog will pass to
/// `paladin_core::open` (inside `gio::spawn_blocking`) on submit.
#[must_use]
pub fn format_unlock_dialog_marker(path: &Path) -> String {
    format!("{UNLOCK_DIALOG_MARKER_PREFIX}{}", path.display())
}

/// Construction parameters for [`UnlockDialogComponent`].
#[derive(Debug, Clone)]
pub struct UnlockDialogInit {
    /// Resolved vault path the dialog targets on submit. Surfaced
    /// in the dialog body so the user can confirm the destination
    /// before typing a passphrase.
    pub vault_path: PathBuf,
}

/// Messages handled by [`UnlockDialogComponent`].
///
/// This milestone scaffolds the read-only render path — the
/// `submit` / inline-decrypt-failure / `gio::spawn_blocking`
/// `paladin_core::open` wiring described in §"Component tree" lands
/// in a follow-up commit alongside the passphrase-field widget on
/// `AppModel`. The empty enum is the deliberate v0.2 starting point
/// — relm4 requires the associated `Input` type to exist even when
/// no inbound messages are wired yet.
#[derive(Debug)]
pub enum UnlockDialogMsg {}

/// Widget-bearing dialog for the
/// [`crate::app::state::AppState::Locked`] branch.
///
/// Mounts a libadwaita [`adw::StatusPage`] that surfaces the
/// resolved vault path so the user can confirm the destination
/// before typing a passphrase. Subsequent commits replace the
/// placeholder body with the [`adw::PasswordEntryRow`] passphrase
/// entry, the submit action wired to a `gio::spawn_blocking`
/// `paladin_core::open` worker, and the inline `DecryptFailed` /
/// `InvalidPassphrase` error surface; until then, keeping the
/// widget read-only mirrors the
/// [`crate::startup_error::StartupErrorComponent`] and
/// [`crate::init_dialog::InitDialogComponent`] pattern (those
/// branches also mounted a status page first and grew inbound
/// actions later).
pub struct UnlockDialogComponent {
    /// Resolved vault path the dialog will hand to a
    /// `paladin_core::open` worker on submit. Kept on `self` so a
    /// future message handler can read it without re-plumbing the
    /// value through every signal.
    #[allow(dead_code)]
    vault_path: PathBuf,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for UnlockDialogComponent {
    type Init = UnlockDialogInit;
    type Input = UnlockDialogMsg;
    type Output = ();

    view! {
        #[root]
        adw::StatusPage {
            // `dialog-password-symbolic` is the freedesktop-standard
            // glyph for "passphrase / unlock"; it resolves through
            // the system icon theme so the wordless icon matches
            // every other GNOME app's unlock surface.
            set_icon_name: Some("dialog-password-symbolic"),
            set_title: "Unlock vault",
            set_description: Some(&format!(
                "Enter the passphrase for {path}.",
                path = model.vault_path.display(),
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
        let model = UnlockDialogComponent {
            vault_path: init.vault_path,
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, _msg: Self::Input, _sender: ComponentSender<Self>) {
        // No inbound messages handled at this milestone — see
        // `UnlockDialogMsg` doc comment for the upcoming submit /
        // inline-error / worker actions.
    }
}
