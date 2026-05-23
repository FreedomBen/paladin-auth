// SPDX-License-Identifier: AGPL-3.0-or-later

//! `otpauth://`-paste pure-logic state machine for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AddAccountComponent` and §"Tests > Pure-logic unit tests >
//! `tests/otpauth_uri_paste_logic.rs`", the URI sub-path of the Add
//! dialog parses a typed `otpauth://` URI through
//! [`paladin_core::parse_otpauth`] and shares the manual path's
//! duplicate-detection logic, "add anyway" override, and
//! `Vault::mutate_and_save` insertion. The widget layer hosts a
//! single [`adw::EntryRow`] for the URI text whose bytes shadow into
//! [`crate::secret_fields::SecretEntry`]; the pure-logic helpers here
//! own the parse and post-effect routing decisions so they can be
//! unit-tested in `tests/otpauth_uri_paste_logic.rs` without spinning
//! up GTK / libadwaita.
//!
//! # URI parse
//!
//! [`classify_uri_submit`] runs [`paladin_core::parse_otpauth`] on
//! the typed text and surfaces either:
//!
//! * [`UriSubmitOutcome::Proceed`] carrying the validated account —
//!   the widget calls [`paladin_core::Vault::find_duplicate`] before
//!   committing, and on collision stages the validated account in
//!   [`crate::secret_fields::AddSecretState::pending`] (the same
//!   slot the manual path uses). The duplicate-allowed "add anyway"
//!   confirmation consumes it via
//!   [`crate::secret_fields::AddSecretState::consume_pending`].
//! * [`UriSubmitOutcome::InlineError`] carrying the typed §5
//!   discriminator and pre-rendered body. The dialog stays open and
//!   the vault is not mutated. Malformed URIs, unsupported scheme
//!   (`https://`, `mailto:`, …), unsupported `type=` (anything other
//!   than `totp` / `hotp`), and the full `validation_error` table all
//!   route here.
//!
//! # No URI text in error bodies
//!
//! The [`InlineError::rendered`] body is produced by
//! [`paladin_core::PaladinError::Display`], which by construction
//! includes only the stable §5 `field` / `reason` wire codes — never
//! the raw URI text. The pure-logic tests assert this invariant by
//! threading distinctive marker substrings through the URI and
//! verifying they never appear in the rendered body.
//!
//! # URI buffer ownership
//!
//! [`classify_uri_submit`] takes a borrowed `&str` so the caller's
//! [`crate::secret_fields::SecretEntry`] retains ownership of the
//! `Zeroizing<String>` and wipes it on drop. Neither the input
//! parameter nor the output types carry the URI bytes onward into
//! `AppMsg` / `AppOutput`.
//!
//! # Post-effect routing
//!
//! [`classify_uri_add_error`] maps the [`PaladinError`] from a failed
//! `Vault::mutate_and_save` onto the dialog's two-way routing
//! decision:
//!
//! * `save_durability_unconfirmed` →
//!   [`UriAddErrorOutcome::KeepWithWarning`] (commit landed but
//!   parent-fsync failed; the dialog reports success while surfacing
//!   the warning beneath it).
//! * Anything else (`save_not_committed`, `io_error`,
//!   `validation_error`, …) → [`UriAddErrorOutcome::Inline`]
//!   (commit never landed; the dialog stays open with the inline
//!   rejection so the user can retry without losing the typed
//!   buffer).

use std::time::SystemTime;

use paladin_core::{parse_otpauth, ErrorKind, PaladinError, ValidatedAccount};

/// Pre-add outcome of a typed `otpauth://` URI.
///
/// See [`classify_uri_submit`]. The widget layer hands the validated
/// account to [`paladin_core::Vault::find_duplicate`] before
/// committing; on a collision the account is staged in
/// [`crate::secret_fields::AddSecretState::pending`] for the "add
/// anyway" confirmation round trip.
#[derive(Debug)]
pub enum UriSubmitOutcome {
    /// `parse_otpauth` accepted the URI. The carried
    /// [`ValidatedAccount`] is the same shape the manual flow
    /// produces, so the dialog's downstream duplicate-detection,
    /// duplicate-confirm, and save wiring is shared.
    Proceed(ValidatedAccount),
    /// `parse_otpauth` rejected the URI. The dialog stays open and
    /// renders the inline error in the URI-field error area.
    InlineError(InlineError),
}

/// Parse the typed URI buffer and classify the outcome.
///
/// Takes a borrowed `&str` so the caller's
/// [`crate::secret_fields::SecretEntry`] retains ownership of the
/// `Zeroizing<String>` buffer; no `String` copy is allocated and the
/// helper does not store the bytes past return.
///
/// The carried [`InlineError`] never echoes the URI text — its body
/// comes from [`PaladinError::Display`] which surfaces only the
/// stable §5 `field` / `reason` codes.
#[must_use]
pub fn classify_uri_submit(uri: &str, import_time: SystemTime) -> UriSubmitOutcome {
    match parse_otpauth(uri, import_time) {
        Ok(validated) => UriSubmitOutcome::Proceed(validated),
        Err(err) => UriSubmitOutcome::InlineError(InlineError::from_error(&err)),
    }
}

/// Post-effect routing decision for a failed
/// `Vault::mutate_and_save(|v| { v.add(uri_validated.account); … })`.
///
/// See [`classify_uri_add_error`].
#[derive(Debug, Clone)]
pub enum UriAddErrorOutcome {
    /// `save_not_committed`, `io_error`, or any other typed error
    /// other than `save_durability_unconfirmed`. The vault was not
    /// mutated (or the rollback inside core has already restored
    /// it). The dialog stays open and surfaces the inline error.
    Inline(InlineError),
    /// `save_durability_unconfirmed` — the add committed to disk but
    /// the parent-directory fsync failed. The dialog can close the
    /// success path and surface the durability warning beneath the
    /// post-add counts panel.
    KeepWithWarning(InlineWarning),
}

/// Classify a [`Vault::mutate_and_save`] failure into a
/// [`UriAddErrorOutcome`].
///
/// Routes `save_durability_unconfirmed` to
/// [`UriAddErrorOutcome::KeepWithWarning`] and falls back to
/// [`UriAddErrorOutcome::Inline`] for every other typed variant so
/// the dialog never silently transitions out on a failure.
#[must_use]
pub fn classify_uri_add_error(err: &PaladinError) -> UriAddErrorOutcome {
    match err.kind() {
        ErrorKind::SaveDurabilityUnconfirmed => {
            UriAddErrorOutcome::KeepWithWarning(InlineWarning::from_error(err))
        }
        _ => UriAddErrorOutcome::Inline(InlineError::from_error(err)),
    }
}

/// Inline-error projection for the URI sub-path of
/// `AddAccountComponent`.
///
/// Carries the stable §5 [`ErrorKind`] for instrumentation and the
/// pre-rendered body for display. The body comes from
/// [`PaladinError::Display`], which surfaces only `field` / `reason`
/// wire codes — the URI text is never included.
#[derive(Debug, Clone)]
pub struct InlineError {
    /// Stable §5 [`ErrorKind`] discriminator copied from
    /// [`PaladinError::kind`].
    pub kind: ErrorKind,
    /// Display body. Renders through [`std::fmt::Display`] so the
    /// wording stays in sync with the CLI / TUI verbatim.
    pub rendered: String,
}

impl InlineError {
    /// Build an [`InlineError`] from a [`PaladinError`].
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}

/// Durability-warning projection for the URI sub-path of
/// `AddAccountComponent`.
///
/// Returned by [`classify_uri_add_error`] on
/// `save_durability_unconfirmed`: the add committed to disk, but the
/// parent-directory `fsync` failed, so the dialog reports the
/// success outcome while surfacing this warning beneath it.
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
    /// Build an [`InlineWarning`] from a [`PaladinError`].
    #[must_use]
    pub fn from_error(err: &PaladinError) -> Self {
        Self {
            kind: err.kind(),
            rendered: err.to_string(),
        }
    }
}
