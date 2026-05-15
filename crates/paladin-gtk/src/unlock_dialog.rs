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
//! bytes shadow into a [`crate::secret_fields::SecretEntry`]. The
//! "Unlock" button's `connect_clicked` signal dispatches
//! [`UnlockDialogMsg::SubmitClicked`]; the handler runs
//! [`UnlockDialogState::submit`], which calls [`prepare_unlock_lock`]
//! to gate the empty passphrase short-circuit (rejection stages the
//! inline projection) and to build the
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
//! The widget binds a `gtk::Label` to
//! [`UnlockDialogState::inline_error`] so the `InlinePassphrase`
//! outcome surfaces directly beneath the passphrase entry once the
//! worker populates the slot; typing dismisses the prior message.
//!
//! The module is a pure-logic shell — it owns no widgets and no
//! `gio::spawn_blocking` plumbing — so
//! `tests/unlock_dialog_logic.rs` can exercise every branch without
//! spinning up GTK or libadwaita.

use std::path::{Path, PathBuf};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;
use secrecy::SecretString;
use zeroize::Zeroizing;

use paladin_core::{ErrorKind, PaladinError, VaultLock, VaultStatus};

use crate::secret_fields::SecretEntry;
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

/// Inline-error projection rendered beneath the passphrase entry.
///
/// The widget binds a [`gtk::Label`] to
/// [`UnlockDialogState::inline_error`] and shows the [`Self::rendered`]
/// text while the option is `Some`. The slot is populated by the
/// `gio::spawn_blocking` [`paladin_core::open`] worker (deferred —
/// see the module-level doc comment) whenever
/// [`classify_unlock_error`] returns
/// [`OpenErrorRouting::InlinePassphrase`]
/// (`decrypt_failed` / `invalid_passphrase`); typing in the entry
/// dismisses the prior error so the dialog never carries a stale
/// "wrong passphrase" message into the next attempt.
#[derive(Debug, Clone)]
pub struct InlineError {
    /// Stable §5 [`ErrorKind`] discriminator copied from
    /// [`PaladinError::kind`]. Kept on the projection so the widget
    /// layer can inspect the cause without re-deriving it from the
    /// rendered text.
    pub kind: ErrorKind,
    /// Display body rendered inline beneath the passphrase entry.
    /// Uses the typed [`PaladinError::Display`] verbatim so the
    /// wording matches the CLI / TUI exactly.
    pub rendered: String,
}

impl InlineError {
    /// Build an [`InlineError`] from a [`PaladinError`].
    ///
    /// Renders through the typed [`std::fmt::Display`] impl which
    /// already carries the stable §5 field values (e.g. the
    /// `invalid_passphrase.reason` discriminator). Intended for
    /// [`PaladinError::DecryptFailed`] and
    /// [`PaladinError::InvalidPassphrase`] — the §5 errors
    /// [`classify_unlock_error`] routes to
    /// [`OpenErrorRouting::InlinePassphrase`] — but the constructor
    /// is variant-agnostic so the worker commit can hand any
    /// [`PaladinError`] through without re-routing here.
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }

    /// Build an [`InlineError`] from a pre-flight [`SubmitRejection`].
    ///
    /// The "Unlock" submit button's `#[watch] set_sensitive` binding
    /// gates the click on
    /// [`UnlockDialogState::submit_button_sensitive`]
    /// (== `!is_passphrase_empty()`) so the empty-passphrase short
    /// circuit in [`prepare_unlock_lock`] never fires through a normal
    /// click. Defense-in-depth: the future click handler will run
    /// `prepare_unlock_lock` regardless and stage this projection if
    /// the gate ever leaks (e.g. a keyboard accelerator firing before
    /// the property binding settles).
    ///
    /// The rendered text and [`ErrorKind`] match the equivalent
    /// [`PaladinError`] variant so the GUI surfaces the same stable §5
    /// `error_kind` / `reason` pair the CLI / TUI do.
    #[must_use]
    pub fn from_rejection(rejection: SubmitRejection) -> Self {
        match rejection {
            SubmitRejection::EmptyPassphrase => {
                Self::from_error(&PaladinError::InvalidPassphrase {
                    reason: rejection.reason(),
                })
            }
        }
    }
}

/// Live shadow buffer for the dialog's [`adw::PasswordEntryRow`].
///
/// The widget's `connect_changed` signal pushes every keystroke into
/// [`UnlockDialogState::set_passphrase`], which mirrors the typed
/// bytes into a Paladin-owned [`SecretEntry`]
/// ([`Zeroizing<String>`]). On submit, the widget reads
/// [`UnlockDialogState::passphrase_text`] and hands it to
/// [`prepare_unlock_lock`] to build the
/// [`paladin_core::VaultLock::Encrypted`] passed to
/// `paladin_core::open` inside `gio::spawn_blocking`. On submit /
/// cancel / auto-lock the widget calls [`Self::clear_passphrase`] or
/// [`Self::take_passphrase`] so the cleartext bytes do not outlive
/// the event.
///
/// The [`Self::inline_error`] slot renders the deferred
/// `decrypt_failed` / `invalid_passphrase` outcome from the future
/// `gio::spawn_blocking paladin_core::open` worker. Typing,
/// [`Self::clear_passphrase`], and [`Self::take_passphrase`] all
/// dismiss any prior inline error so the dialog never carries a
/// stale message into the next attempt.
///
/// The struct deliberately does not derive `Clone` or `Debug` —
/// [`SecretEntry`] is the §8 boundary that keeps secret bytes
/// inside `Zeroizing<String>` and out of `Debug` output.
#[derive(Default)]
pub struct UnlockDialogState {
    passphrase: SecretEntry,
    inline_error: Option<InlineError>,
}

impl UnlockDialogState {
    /// Construct an empty state — equivalent to `Self::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the shadow buffer with the entry row's current text.
    ///
    /// Called from the widget's `connect_changed` signal on every
    /// keystroke. The previous buffer's bytes are zeroized in place
    /// when the temporary [`Zeroizing<String>`] inside
    /// [`SecretEntry`] drops. The first keystroke after a worker
    /// error also dismisses any prior [`InlineError`] so the entry
    /// never carries a stale "wrong passphrase" message into the
    /// next attempt — matches the standard GNOME unlock-surface
    /// affordance.
    pub fn set_passphrase(&mut self, text: &str) {
        self.passphrase.set(text);
        self.inline_error = None;
    }

    /// Borrow the shadow buffer as a `&str` for
    /// [`prepare_unlock_lock`] and for the `is_empty` sensitivity
    /// gate on a future submit button.
    #[must_use]
    pub fn passphrase_text(&self) -> &str {
        self.passphrase.text()
    }

    /// True iff the shadow buffer is the empty string.
    ///
    /// The "Unlock" submit button binds its `sensitive` property to
    /// the [`Self::submit_button_sensitive`] predicate (which is the
    /// negation of this method) so the empty-passphrase pre-flight
    /// short-circuit in [`prepare_unlock_lock`] never fires through a
    /// click.
    #[must_use]
    pub fn is_passphrase_empty(&self) -> bool {
        self.passphrase.is_empty()
    }

    /// Whether the "Unlock" submit button is currently sensitive.
    ///
    /// The widget's `#[watch] set_sensitive` binding reads this
    /// predicate so the empty-passphrase pre-flight short-circuit in
    /// [`prepare_unlock_lock`] never fires through a click. Returns
    /// `true` exactly when the shadow buffer is non-empty. Pinned
    /// behind a dedicated accessor so future gating conditions
    /// (e.g. disabling the button while an
    /// [`crate::app::state::AppState::UnlockedBusy`] worker is in
    /// flight) can be added in one place without re-touching the
    /// widget binding.
    #[must_use]
    pub fn submit_button_sensitive(&self) -> bool {
        !self.is_passphrase_empty()
    }

    /// Wipe the shadow buffer in place without consuming it.
    ///
    /// The widget calls this on cancel / auto-lock so cleartext bytes
    /// do not survive the dismissal. Submit uses [`Self::take_passphrase`]
    /// instead so the bytes flow into the worker. Also clears any
    /// pending [`InlineError`] so a re-mounted dialog does not flash
    /// a stale `decrypt_failed` message.
    pub fn clear_passphrase(&mut self) {
        self.passphrase.clear();
        self.inline_error = None;
    }

    /// Move the shadow buffer out, leaving the state empty.
    ///
    /// The widget's submit path will call this and hand the returned
    /// [`Zeroizing<String>`] to `SecretString::from(...)` inside the
    /// [`paladin_core::VaultLock::Encrypted`], dropping the wrapper
    /// once `paladin_core::open` returns so the bytes zeroize. Any
    /// prior [`InlineError`] is dismissed in the same step so the
    /// worker result lands into clean state.
    #[must_use]
    pub fn take_passphrase(&mut self) -> Zeroizing<String> {
        self.inline_error = None;
        self.passphrase.take()
    }

    /// Borrow the inline-error slot for the widget's `gtk::Label`
    /// binding.
    ///
    /// `None` while no error is pending; `Some` after the future
    /// `gio::spawn_blocking paladin_core::open` worker reports a
    /// [`PaladinError::DecryptFailed`] or
    /// [`PaladinError::InvalidPassphrase`] result (per
    /// [`classify_unlock_error`]).
    #[must_use]
    pub fn inline_error(&self) -> Option<&InlineError> {
        self.inline_error.as_ref()
    }

    /// Replace the inline-error slot.
    ///
    /// Called by the future worker commit on
    /// [`OpenErrorRouting::InlinePassphrase`] results
    /// (`set_inline_error(Some(_))`) and on the successful unlock
    /// transition (`set_inline_error(None)`) so the dialog hands a
    /// clean state to whatever surface mounts next.
    pub fn set_inline_error(&mut self, err: Option<InlineError>) {
        self.inline_error = err;
    }

    /// Run the pre-flight submit gate when the "Unlock" button fires.
    ///
    /// Delegates to [`prepare_unlock_lock`] on the current shadow
    /// buffer. The two outcomes:
    ///
    /// * `Ok(VaultLock)` — the typed passphrase is non-empty. The
    ///   shadow buffer is consumed via [`Self::take_passphrase`]
    ///   (which zeroizes the bytes in place and dismisses any prior
    ///   [`InlineError`]) so cleartext does not outlive the submit.
    ///   The returned [`VaultLock::Encrypted`] is handed to the
    ///   (deferred) `gio::spawn_blocking paladin_core::open` worker.
    /// * `Err(SubmitRejection)` — the buffer was empty. The stable §5
    ///   `invalid_passphrase` / `zero_length` projection is staged
    ///   inline via [`InlineError::from_rejection`] so the user sees
    ///   the rejection without a worker spawn. The buffer is left
    ///   untouched.
    ///
    /// The "Unlock" button binds `set_sensitive` to
    /// [`Self::submit_button_sensitive`] so the empty path should not
    /// fire through a normal click. Defense-in-depth: a keyboard
    /// accelerator or a reactive race during an
    /// [`crate::app::state::AppState::UnlockedBusy`] window could
    /// still reach this branch, and the rendered §5 projection means
    /// instrumentation matches the CLI / TUI without an extra widget
    /// path.
    ///
    /// # Errors
    ///
    /// Returns [`SubmitRejection::EmptyPassphrase`] when the buffer is
    /// the empty string.
    pub fn submit(&mut self) -> Result<VaultLock, SubmitRejection> {
        match prepare_unlock_lock(self.passphrase.text()) {
            Ok(lock) => {
                let _ = self.take_passphrase();
                Ok(lock)
            }
            Err(rejection) => {
                self.inline_error = Some(InlineError::from_rejection(rejection));
                Err(rejection)
            }
        }
    }
}

/// Messages handled by [`UnlockDialogComponent`].
///
/// `PassphraseChanged(text)` arrives from the
/// [`adw::PasswordEntryRow`]'s `connect_changed` signal on every
/// keystroke. The handler shadows the typed bytes into the
/// [`UnlockDialogState`]'s [`SecretEntry`] so the cleartext lives in
/// Paladin-owned memory rather than escaping through `AppMsg` /
/// `AppOutput`. `SubmitClicked` arrives from the "Unlock" button's
/// `connect_clicked` signal; the handler runs
/// [`UnlockDialogState::submit`] so the pre-flight rejection stages
/// inline. The `gio::spawn_blocking paladin_core::open` worker
/// described in §"Component tree" > `UnlockComponent` lands in a
/// follow-up commit alongside the `UnlockedBusy` worker
/// infrastructure; for now the `Ok` branch of `submit` is intentionally
/// discarded by the widget's `update`.
#[derive(Debug)]
pub enum UnlockDialogMsg {
    /// Raw text from the [`adw::PasswordEntryRow`] after a keystroke.
    /// The widget's `update` runs [`UnlockDialogState::set_passphrase`]
    /// so the shadow buffer tracks the live entry.
    ///
    /// The variant carries `String` rather than [`SecretString`]
    /// because the GTK [`gtk::EntryBuffer`] is the unavoidable §8 UI
    /// boundary: the bytes arrive as a `GString` from
    /// [`gtk::Editable::text`] and live transiently in the relm4
    /// channel before the handler shadows them into the
    /// [`SecretEntry`]. Once the handler returns, the `String`
    /// drops and only the [`Zeroizing<String>`] copy in
    /// [`UnlockDialogState`] survives.
    PassphraseChanged(String),
    /// The "Unlock" submit button was clicked. The widget's `update`
    /// runs [`UnlockDialogState::submit`]: rejection stages the inline
    /// error projection; the `Ok` branch carrying the
    /// [`VaultLock::Encrypted`] is currently discarded — the
    /// `gio::spawn_blocking paladin_core::open` worker that consumes
    /// it lands in a follow-up commit alongside the `UnlockedBusy`
    /// worker infrastructure.
    SubmitClicked,
}

/// Widget-bearing dialog for the
/// [`crate::app::state::AppState::Locked`] branch.
///
/// Mounts a libadwaita [`adw::StatusPage`] heading that names the
/// resolved vault path so the user can confirm the destination, an
/// [`adw::PasswordEntryRow`] whose keystrokes shadow into the model's
/// [`UnlockDialogState`] [`SecretEntry`], an inline-error label
/// beneath the entry, and an "Unlock" submit button whose sensitivity
/// binds to [`UnlockDialogState::submit_button_sensitive`] so the
/// empty-passphrase pre-flight short-circuit in
/// [`prepare_unlock_lock`] never fires through a click. The button's
/// `connect_clicked` signal dispatches [`UnlockDialogMsg::SubmitClicked`],
/// whose handler runs [`UnlockDialogState::submit`]: rejection stages
/// the inline error projection; the `Ok` branch carrying the
/// [`VaultLock::Encrypted`] is currently discarded — the
/// `gio::spawn_blocking paladin_core::open` worker that consumes it
/// and the inline `DecryptFailed` / `InvalidPassphrase` error surface
/// flip land in follow-up commits alongside the `UnlockedBusy` worker
/// infrastructure.
pub struct UnlockDialogComponent {
    /// Resolved vault path the dialog will hand to a
    /// `paladin_core::open` worker on submit. Kept on `self` so a
    /// future message handler can read it without re-plumbing the
    /// value through every signal.
    #[allow(dead_code)]
    vault_path: PathBuf,
    /// Live passphrase shadow buffer driven from the
    /// [`adw::PasswordEntryRow`]'s `connect_changed` signal. Also
    /// hosts the [`InlineError`] slot the view's error label binds
    /// to. The view also `#[watch]`-binds the "Unlock" button's
    /// `set_sensitive` property to
    /// [`UnlockDialogState::submit_button_sensitive`] so the gate
    /// tracks the live buffer. The submit handler will read
    /// [`UnlockDialogState::passphrase_text`] (or
    /// [`UnlockDialogState::take_passphrase`]) once the
    /// `UnlockedBusy` worker lands.
    state: UnlockDialogState,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for UnlockDialogComponent {
    type Init = UnlockDialogInit;
    type Input = UnlockDialogMsg;
    type Output = ();

    view! {
        #[root]
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 12,
            set_hexpand: true,
            set_vexpand: true,

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
            },

            adw::PreferencesGroup {
                #[name = "passphrase_row"]
                add = &adw::PasswordEntryRow {
                    set_title: "Passphrase",
                    // `connect_changed` fires on every keystroke so the
                    // `SecretEntry` shadow buffer tracks the live entry
                    // and Paladin-owned `Zeroizing<String>` is the only
                    // long-lived home for the cleartext bytes.
                    connect_changed[sender] => move |entry| {
                        sender.input(UnlockDialogMsg::PassphraseChanged(
                            entry.text().to_string(),
                        ));
                    },
                },
            },

            // Inline-error surface beneath the passphrase entry. The
            // future `gio::spawn_blocking paladin_core::open` worker
            // populates `state.inline_error` from
            // `classify_unlock_error`'s `InlinePassphrase` outcome
            // (decrypt_failed / invalid_passphrase); typing a new
            // passphrase dismisses the prior message.
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

                // "Unlock" submit button. The `suggested-action` CSS
                // class renders it as the primary affordance per the
                // libadwaita HIG. `set_sensitive` binds to
                // `submit_button_sensitive` so the empty-passphrase
                // pre-flight short-circuit in `prepare_unlock_lock`
                // never fires through a click. `connect_clicked`
                // dispatches `SubmitClicked`, whose handler runs
                // `UnlockDialogState::submit` — rejection stages the
                // inline error inline beneath the entry. The
                // `gio::spawn_blocking paladin_core::open` worker that
                // consumes the `Ok(VaultLock)` lands in a follow-up
                // commit alongside the `UnlockedBusy` worker
                // infrastructure; until then the `Ok` branch is
                // intentionally discarded.
                #[name = "unlock_button"]
                gtk::Button {
                    set_label: "Unlock",
                    add_css_class: "suggested-action",
                    #[watch]
                    set_sensitive: model.state.submit_button_sensitive(),
                    connect_clicked[sender] => move |_| {
                        sender.input(UnlockDialogMsg::SubmitClicked);
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
        let model = UnlockDialogComponent {
            vault_path: init.vault_path,
            state: UnlockDialogState::new(),
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, _sender: ComponentSender<Self>) {
        match msg {
            UnlockDialogMsg::PassphraseChanged(text) => {
                self.state.set_passphrase(&text);
            }
            UnlockDialogMsg::SubmitClicked => {
                // Rejection stages the inline error projection inside
                // `submit`. The `Ok(VaultLock)` branch is intentionally
                // discarded here — the `gio::spawn_blocking
                // paladin_core::open` worker that consumes it lands in
                // a follow-up commit alongside the `UnlockedBusy`
                // worker infrastructure.
                let _ = self.state.submit();
            }
        }
    }
}
