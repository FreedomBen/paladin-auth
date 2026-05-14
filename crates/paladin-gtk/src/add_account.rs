// SPDX-License-Identifier: AGPL-3.0-or-later

//! Manual-path pure-logic state machine for `paladin-gtk`'s
//! `AddAccountComponent`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AddAccountComponent`, the dialog presents three input sub-paths
//! (manual fields, `otpauth://` URI paste, "scan from clipboard
//! image"). The URI sub-path lives in [`crate::otpauth_uri_paste`],
//! the QR sub-path lives in [`crate::qr_clipboard`], and the path-
//! switch / duplicate-pending state machine lives in
//! [`crate::secret_fields::AddSecretState`]. *This* module owns the
//! widget-free manual-input projection plus the post-validate
//! duplicate-detection and post-save-effect routing that the manual
//! and URI sub-paths share.
//!
//! # Manual submit
//!
//! [`classify_manual_submit`] takes the widget's [`ManualFields`]
//! bundle (label, issuer, secret, algorithm, digits, kind,
//! `period_secs`, counter, icon-hint free-form text), parses the
//! icon-hint token through [`paladin_core::parse_icon_hint_token`],
//! builds a [`paladin_core::AccountInput`] (collapsing empty issuer
//! to `None` and dropping the kind-irrelevant `period_secs` /
//! `counter` so [`paladin_core::validate_manual`]'s cross-checks
//! never fire on well-formed widget input), and routes the call
//! into:
//!
//! * [`ManualSubmitOutcome::Proceed`] carrying the validated account
//!   plus any non-fatal [`paladin_core::ValidationWarning`]s the
//!   widget renders alongside the success outcome via
//!   [`paladin_core::format_validation_warning`].
//! * [`ManualSubmitOutcome::InlineError`] carrying the typed §5
//!   discriminator and pre-rendered body. Field-level parse errors
//!   (invalid Base32, empty label, out-of-range digits / period,
//!   malformed icon-hint slug) and any other `validation_error`
//!   from core land here. The dialog stays open and the vault is
//!   not mutated.
//!
//! # No widget input echo in [`InlineError`] bodies
//!
//! The [`InlineError::rendered`] body is produced by
//! [`paladin_core::PaladinError::Display`], which by construction
//! emits only the stable §5 `field` / `reason` wire codes — never
//! the widget input (label, issuer, secret, slug, …). The pure-logic
//! tests assert this invariant by threading distinctive marker
//! substrings through widget input and verifying they never appear
//! in the rendered body.
//!
//! # Duplicate detection
//!
//! [`classify_duplicate`] takes the validated account plus the
//! `Option<AccountSummary>` from
//! [`paladin_core::Vault::find_duplicate`] and routes to:
//!
//! * [`DuplicateOutcome::Proceed`] when no collision exists; the
//!   caller commits with `Vault::add` inside
//!   `Vault::mutate_and_save`.
//! * [`DuplicateOutcome::AwaitConfirmation`] when a duplicate exists;
//!   the caller stages the validated account in
//!   [`crate::secret_fields::AddSecretState::pending`] (the same
//!   slot the URI sub-path uses), shows the existing
//!   [`AccountSummary`] in the dialog, and consumes the staged
//!   value via
//!   [`crate::secret_fields::AddSecretState::consume_pending`] on
//!   the "add anyway" confirmation.
//!
//! # Post-effect routing
//!
//! [`classify_add_post_effect_error`] maps the [`PaladinError`] from
//! a failed `Vault::mutate_and_save` onto the dialog's two-way
//! routing decision (parity with [`crate::otpauth_uri_paste`]):
//!
//! * `save_durability_unconfirmed` →
//!   [`AddPostEffectOutcome::KeepWithWarning`] (commit landed but
//!   parent-fsync failed; the dialog reports success while surfacing
//!   the warning beneath it).
//! * Anything else (`save_not_committed`, `io_error`,
//!   `validation_error`, …) → [`AddPostEffectOutcome::Inline`]
//!   (commit never landed; the dialog stays open with the inline
//!   rejection so the user can retry without losing the typed
//!   buffer).

use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    parse_icon_hint_token, validate_manual, AccountInput, AccountKindInput, AccountSummary,
    Algorithm, ErrorKind, PaladinError, ValidatedAccount,
};

/// Widget-side bundle of typed manual-add fields.
///
/// The widget shadows each entry into Paladin-owned zeroizing
/// buffers (see [`crate::secret_fields::AddSecretState`]) and copies
/// the relevant text into this struct only at submit time. The
/// Base32 secret travels as a [`SecretString`] so [`validate_manual`]
/// can hand it through to core without an extra allocation; the
/// caller drops the [`SecretString`] after the call returns,
/// zeroizing the bytes in place.
pub struct ManualFields {
    /// Label entry text (trimmed and rejected for empty / overlong
    /// by [`validate_manual`]).
    pub label: String,
    /// Issuer entry text. Empty maps to `None` before being passed
    /// to [`validate_manual`].
    pub issuer: String,
    /// Base32 secret. Zeroized on drop via the `SecretString`'s
    /// `ZeroizeOnDrop` impl.
    pub secret: SecretString,
    /// HMAC algorithm chosen by the algorithm selector.
    pub algorithm: Algorithm,
    /// OTP digit count chosen by the digits spinner (`6..=8`).
    pub digits: u8,
    /// TOTP / HOTP kind chosen by the kind selector.
    pub kind: AccountKindInput,
    /// TOTP period in seconds. Consulted only when `kind == Totp`;
    /// dropped before being passed to [`validate_manual`] when
    /// `kind == Hotp` so the cross-check never fires.
    pub period_secs: u32,
    /// HOTP starting counter. Consulted only when `kind == Hotp`;
    /// dropped before being passed to [`validate_manual`] when
    /// `kind == Totp`.
    pub counter: u64,
    /// Free-form icon-hint text. Empty / `"none"` (any case) /
    /// explicit slug parsing happens through
    /// [`parse_icon_hint_token`] (CLI / TUI parity).
    pub icon_hint_text: String,
}

/// Pre-add outcome of manual-field submission.
///
/// See [`classify_manual_submit`]. The widget hands the validated
/// account to [`paladin_core::Vault::find_duplicate`] before
/// committing; on a collision the account is staged in
/// [`crate::secret_fields::AddSecretState::pending`] via
/// [`classify_duplicate`].
#[derive(Debug)]
pub enum ManualSubmitOutcome {
    /// [`validate_manual`] (or the earlier
    /// [`parse_icon_hint_token`]) accepted the input. The carried
    /// [`ValidatedAccount`] is the same shape the URI sub-path
    /// produces, so the dialog's downstream duplicate-detection,
    /// duplicate-confirm, and save wiring is shared.
    Proceed(ValidatedAccount),
    /// [`validate_manual`] (or [`parse_icon_hint_token`]) rejected
    /// the input. The dialog stays open and renders the inline
    /// error against the failing field.
    InlineError(InlineError),
}

/// Parse the typed manual fields and classify the outcome.
///
/// 1. Normalize the icon-hint token through [`parse_icon_hint_token`];
///    a malformed slug short-circuits as [`InlineError`] before
///    [`validate_manual`] runs.
/// 2. Build an [`AccountInput`], collapsing empty issuer to `None`
///    and dropping `period_secs` / `counter` on the irrelevant kind
///    so the cross-check in [`validate_manual`] never fires.
/// 3. Run [`validate_manual`] over the input with the supplied
///    `import_time` (the widget passes `SystemTime::now()` at
///    submit time so the account's `created_at` / `updated_at`
///    match the user's submit moment).
///
/// The carried [`InlineError`] never echoes widget input — its body
/// comes from [`PaladinError::Display`] which surfaces only the
/// stable §5 `field` / `reason` codes.
#[must_use]
pub fn classify_manual_submit(
    fields: ManualFields,
    import_time: SystemTime,
) -> ManualSubmitOutcome {
    let icon_hint = match parse_icon_hint_token(&fields.icon_hint_text) {
        Ok(hint) => hint,
        Err(err) => return ManualSubmitOutcome::InlineError(InlineError::from_error(&err)),
    };

    let input = AccountInput {
        label: fields.label,
        issuer: if fields.issuer.is_empty() {
            None
        } else {
            Some(fields.issuer)
        },
        secret: fields.secret,
        algorithm: fields.algorithm,
        digits: fields.digits,
        kind: fields.kind,
        period_secs: match fields.kind {
            AccountKindInput::Totp => Some(fields.period_secs),
            AccountKindInput::Hotp => None,
        },
        counter: match fields.kind {
            AccountKindInput::Hotp => Some(fields.counter),
            AccountKindInput::Totp => None,
        },
        icon_hint,
    };

    match validate_manual(input, import_time) {
        Ok(validated) => ManualSubmitOutcome::Proceed(validated),
        Err(err) => ManualSubmitOutcome::InlineError(InlineError::from_error(&err)),
    }
}

/// Post-validate duplicate-detection routing decision.
///
/// See [`classify_duplicate`]. The carried `ValidatedAccount` on
/// [`AwaitConfirmation`](DuplicateOutcome::AwaitConfirmation) is the
/// pending validated account staged in
/// [`crate::secret_fields::AddSecretState::pending`] for the "add
/// anyway" confirmation round trip.
#[derive(Debug)]
pub enum DuplicateOutcome {
    /// No collision; commit with `Vault::add` inside
    /// `Vault::mutate_and_save`.
    Proceed(ValidatedAccount),
    /// Collision detected; show the existing summary in the dialog
    /// and stage the pending validated account in
    /// [`crate::secret_fields::AddSecretState::pending`] for the
    /// "add anyway" confirmation. The duplicate-allowed path
    /// consumes the staged value via
    /// [`crate::secret_fields::AddSecretState::consume_pending`]
    /// (CLI parity with `--allow-duplicate`, appending a new account
    /// that shares the `(secret, issuer, label)` triple).
    AwaitConfirmation {
        /// Existing account that collided. The widget renders its
        /// display label and metadata so the user can confirm the
        /// collision before electing "add anyway".
        existing: AccountSummary,
        /// Pending validated account staged in the
        /// [`crate::secret_fields::AddSecretState::pending`] slot.
        validated: ValidatedAccount,
    },
}

/// Classify the [`paladin_core::Vault::find_duplicate`] result for
/// the pre-mutation pre-flight.
///
/// `existing` is the return value of
/// [`paladin_core::Vault::find_duplicate`] (`Some(account.summary())`
/// on collision, `None` otherwise). Routing rule:
///
/// * `None` → [`DuplicateOutcome::Proceed`]: commit the validated
///   account.
/// * `Some(existing)` → [`DuplicateOutcome::AwaitConfirmation`]:
///   stage the validated account and prompt the user.
#[must_use]
pub fn classify_duplicate(
    validated: ValidatedAccount,
    existing: Option<AccountSummary>,
) -> DuplicateOutcome {
    match existing {
        None => DuplicateOutcome::Proceed(validated),
        Some(existing) => DuplicateOutcome::AwaitConfirmation {
            existing,
            validated,
        },
    }
}

/// Post-effect routing decision for a failed
/// `Vault::mutate_and_save(|v| { v.add(validated.account); … })`.
///
/// See [`classify_add_post_effect_error`].
#[derive(Debug, Clone)]
pub enum AddPostEffectOutcome {
    /// `save_not_committed`, `io_error`, or any other typed error
    /// other than `save_durability_unconfirmed`. The vault was not
    /// mutated (or the rollback inside core has already restored
    /// it). The dialog stays open and surfaces the inline error.
    Inline(InlineError),
    /// `save_durability_unconfirmed` — the add committed to disk but
    /// the parent-directory `fsync` failed. The dialog can close the
    /// success path and surface the durability warning beneath the
    /// post-add counts panel.
    KeepWithWarning(InlineWarning),
}

/// Classify a [`paladin_core::Vault::mutate_and_save`] failure into
/// an [`AddPostEffectOutcome`].
///
/// Routes `save_durability_unconfirmed` to
/// [`AddPostEffectOutcome::KeepWithWarning`] and falls back to
/// [`AddPostEffectOutcome::Inline`] for every other typed variant so
/// the dialog never silently transitions out on a failure (parity
/// with the URI sub-path's
/// [`crate::otpauth_uri_paste::classify_uri_add_error`]).
#[must_use]
pub fn classify_add_post_effect_error(err: &PaladinError) -> AddPostEffectOutcome {
    match err.kind() {
        ErrorKind::SaveDurabilityUnconfirmed => {
            AddPostEffectOutcome::KeepWithWarning(InlineWarning::from_error(err))
        }
        _ => AddPostEffectOutcome::Inline(InlineError::from_error(err)),
    }
}

/// Inline-error projection for `AddAccountComponent`'s manual /
/// duplicate-detection / save paths.
///
/// Carries the stable §5 [`ErrorKind`] for instrumentation and the
/// pre-rendered body for display. The body comes from
/// [`PaladinError::Display`], which surfaces only `field` / `reason`
/// wire codes — widget input (label, issuer, secret, slug, …) is
/// never included.
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

/// Durability-warning projection for the post-effect `Add` path.
///
/// Returned by [`classify_add_post_effect_error`] on
/// `save_durability_unconfirmed`: the add committed to disk, but the
/// parent-directory `fsync` failed, so the dialog reports the success
/// outcome while surfacing this warning beneath it.
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
