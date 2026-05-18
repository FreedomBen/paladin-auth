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

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;
use secrecy::SecretString;

use paladin_core::{
    parse_icon_hint_token, validate_manual, Account, AccountId, AccountInput, AccountKindInput,
    AccountSummary, Algorithm, ErrorKind, PaladinError, Store, ValidatedAccount, ValidationWarning,
    Vault,
};

use crate::secret_fields::{AddPath, AddSecretState, ClearReason};

/// Per-keystroke reactive state for the non-secret manual entries.
///
/// Holds the live label / issuer / algorithm / digits / kind / TOTP
/// period / HOTP counter / icon-hint text shadowed from the widget
/// `AdwEntryRow` and selector widgets. Defaults match the CLI
/// interactive `add` prompts (DESIGN §5 / `paladin-cli/src/commands/add.rs`):
/// TOTP, SHA1, 6 digits, 30 s period, HOTP counter 0, and empty
/// label / issuer / icon-hint (the empty icon-hint text collapses to
/// [`paladin_core::IconHintInput::Default`] through
/// [`paladin_core::parse_icon_hint_token`]).
///
/// Separate from [`ManualFields`] — which the widget builds *at
/// submit time* by combining this draft with the
/// [`crate::secret_fields::AddSecretState::manual_secret`] buffer —
/// so the secret stays inside the [`crate::secret_fields::SecretEntry`]
/// boundary until the user commits. Per-keystroke message routing
/// for each field lands as additional [`AddAccountMsg`] variants in
/// follow-up commits alongside the editable form widgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualDraftState {
    /// Live label entry text. Trimmed and length-validated by
    /// [`validate_manual`] at submit time; the draft preserves the
    /// user's whitespace so the cursor position does not jump.
    pub label: String,
    /// Live issuer entry text. Empty maps to `None` before being
    /// passed to [`validate_manual`].
    pub issuer: String,
    /// HMAC algorithm selected by the algorithm dropdown.
    pub algorithm: Algorithm,
    /// OTP digit count from the digits spinner (`6..=8`).
    pub digits: u8,
    /// TOTP / HOTP kind selected by the kind switcher.
    pub kind: AccountKindInput,
    /// TOTP period in seconds. Consulted only when
    /// `kind == AccountKindInput::Totp`; dropped before
    /// [`validate_manual`] runs on the HOTP path so the cross-check
    /// never fires.
    pub period_secs: u32,
    /// HOTP starting counter. Consulted only when
    /// `kind == AccountKindInput::Hotp`; dropped before
    /// [`validate_manual`] runs on the TOTP path.
    pub counter: u64,
    /// Free-form icon-hint entry text. Empty / `"none"` (any case) /
    /// explicit slug parsing happens through
    /// [`paladin_core::parse_icon_hint_token`] at submit time so the
    /// CLI / TUI add modals stay in parity.
    pub icon_hint_text: String,
}

impl Default for ManualDraftState {
    fn default() -> Self {
        Self {
            label: String::new(),
            issuer: String::new(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: AccountKindInput::Totp,
            period_secs: 30,
            counter: 0,
            icon_hint_text: String::new(),
        }
    }
}

impl ManualDraftState {
    /// Construct a fresh manual draft on the CLI defaults (TOTP,
    /// SHA1, 6 digits, 30 s period, HOTP counter 0, empty label /
    /// issuer / icon-hint).
    ///
    /// Named constructor for the widget mount path so the call site
    /// reads as `ManualDraftState::new()` alongside
    /// [`AddDialogState::new`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

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

/// Build a [`ManualFields`] bundle from the live non-secret draft
/// and the Paladin-owned manual secret text.
///
/// The widget calls this at submit time to combine the
/// [`ManualDraftState`] shadow (label / issuer / algorithm / digits /
/// kind / period / counter / icon-hint) with the
/// [`crate::secret_fields::SecretEntry::text`] of
/// [`crate::secret_fields::AddSecretState::manual_secret`]. The
/// draft is borrowed so a worker retry after `save_not_committed`
/// can re-compose against the same typed values without losing the
/// user's input; the non-secret fields are `Clone`d into the
/// returned bundle. The secret is borrowed too — the caller hands a
/// `&str` from the `SecretEntry`, and `compose_manual_fields` wraps
/// it in a [`SecretString`] whose `ZeroizeOnDrop` impl wipes the
/// bytes once the returned [`ManualFields`] drops.
///
/// Chain `compose_manual_fields(...).into()` into
/// [`classify_manual_submit`] so the widget keeps the submit
/// pipeline as `draft + secret → ManualFields → ManualSubmitOutcome`
/// without intermediate re-packing. Mirror of the URI sub-path,
/// where the widget reads `secret_state.uri_text.text()` straight
/// into [`crate::otpauth_uri_paste::classify_uri_submit`].
#[must_use]
pub fn compose_manual_fields(draft: &ManualDraftState, secret: &str) -> ManualFields {
    ManualFields {
        label: draft.label.clone(),
        issuer: draft.issuer.clone(),
        secret: SecretString::from(secret.to_string()),
        algorithm: draft.algorithm,
        digits: draft.digits,
        kind: draft.kind,
        period_secs: draft.period_secs,
        counter: draft.counter,
        icon_hint_text: draft.icon_hint_text.clone(),
    }
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

/// Chained `compose_manual_fields → classify_manual_submit` against
/// the live [`AddDialogState`].
///
/// The widget Save handler calls this on every click to drive the
/// manual sub-path's validation pipeline as a single boundary —
/// sourcing the non-secret fields from
/// [`AddDialogState::manual_draft`] and the secret text from
/// [`crate::secret_fields::AddSecretState::manual_secret`] via
/// [`crate::secret_fields::SecretEntry::text`]. The borrow keeps
/// the dialog state intact so a typed-but-rejected attempt can
/// retry against the same buffers without losing the user's
/// input.
///
/// The carried [`ManualSubmitOutcome`] is the same shape
/// [`classify_manual_submit`] produces on its own:
///
/// * [`ManualSubmitOutcome::Proceed`] — validated account; the
///   widget hands it to [`paladin_core::Vault::find_duplicate`]
///   plus [`classify_duplicate`] next to decide
///   [`AddAccountMsg::SubmitProceed`] vs
///   [`AddAccountMsg::StagePendingDuplicate`].
/// * [`ManualSubmitOutcome::InlineError`] — typed §5 error body;
///   the widget renders the rejection inline and leaves the form
///   populated for retry.
#[must_use]
pub fn compose_manual_submit_outcome(
    state: &AddDialogState,
    now: SystemTime,
) -> ManualSubmitOutcome {
    let fields = compose_manual_fields(
        state.manual_draft(),
        state.secret_state().manual_secret.text(),
    );
    classify_manual_submit(fields, now)
}

/// Chained
/// [`crate::otpauth_uri_paste::classify_uri_submit`] against the live
/// [`AddDialogState`].
///
/// Parallel of [`compose_manual_submit_outcome`] on the URI sub-
/// path. The widget Save handler calls this on every click to drive
/// the URI validation pipeline as a single boundary, sourcing the
/// URI text from
/// [`crate::secret_fields::AddSecretState::uri_text`] via
/// [`crate::secret_fields::SecretEntry::text`]. The borrow keeps
/// the dialog state intact so a typed-but-rejected attempt can
/// retry against the same buffer without losing the user's input.
///
/// The carried [`crate::otpauth_uri_paste::UriSubmitOutcome`] is
/// the same shape
/// [`crate::otpauth_uri_paste::classify_uri_submit`] produces on
/// its own:
///
/// * [`crate::otpauth_uri_paste::UriSubmitOutcome::Proceed`] —
///   validated account; the widget hands it to
///   [`paladin_core::Vault::find_duplicate`] plus
///   [`classify_duplicate`] next to decide
///   [`AddAccountMsg::SubmitProceed`] vs
///   [`AddAccountMsg::StagePendingDuplicate`].
/// * [`crate::otpauth_uri_paste::UriSubmitOutcome::InlineError`] —
///   typed §5 error body; the widget renders the rejection inline
///   and leaves the URI field populated for retry.
#[must_use]
pub fn compose_uri_submit_outcome(
    state: &AddDialogState,
    now: SystemTime,
) -> crate::otpauth_uri_paste::UriSubmitOutcome {
    crate::otpauth_uri_paste::classify_uri_submit(state.secret_state().uri_text.text(), now)
}

/// Unified validation outcome for the path-aware
/// [`compose_submit_outcome`].
///
/// Collapses the structurally-identical
/// [`ManualSubmitOutcome`] and
/// [`crate::otpauth_uri_paste::UriSubmitOutcome`] into a single
/// shape so the widget Save handler has one downstream branch
/// regardless of which sub-path is active. Both per-path composers
/// continue to return their own typed outcome — the unified enum
/// is built by `compose_submit_outcome` at the boundary the widget
/// consults.
///
/// Naming parallels [`crate::rename_dialog::SubmitOutcome`] on the
/// rename path; each dialog scopes its own `SubmitOutcome` to its
/// module so the variants stay narrow.
///
/// * [`SubmitOutcome::Proceed`] — validated account; the widget
///   hands it to [`paladin_core::Vault::find_duplicate`] plus
///   [`classify_duplicate`] next to decide
///   [`AddAccountMsg::SubmitProceed`] vs
///   [`AddAccountMsg::StagePendingDuplicate`].
/// * [`SubmitOutcome::InlineError`] — typed §5 error body; the
///   widget renders the rejection inline against the active sub-
///   path's failing field and leaves the form populated for retry.
#[derive(Debug)]
pub enum SubmitOutcome {
    /// Validated account ready for the duplicate-detection pre-
    /// flight, regardless of whether it was produced by the manual
    /// or URI sub-path.
    Proceed(ValidatedAccount),
    /// Typed §5 inline error; the widget renders the rejection
    /// against the active sub-path's failing field.
    InlineError(InlineError),
}

/// Path-aware state-driven submit composer.
///
/// Dispatches to [`compose_manual_submit_outcome`] or
/// [`compose_uri_submit_outcome`] based on
/// [`crate::secret_fields::AddSecretState::active_path`] and
/// rewraps the per-path outcome as the unified [`SubmitOutcome`]
/// so the widget Save handler has a single downstream branch.
/// Routing keys off `active_path` only — a populated buffer on
/// the inactive sub-path is ignored, so a stale URI typed before
/// the user switched back to the manual path cannot bypass the
/// manual fields' validation.
///
/// The borrow keeps the dialog state intact so a typed-but-
/// rejected attempt can retry against the same buffers without
/// losing the user's input on either sub-path.
#[must_use]
pub fn compose_submit_outcome(state: &AddDialogState, now: SystemTime) -> SubmitOutcome {
    match state.secret_state().active_path {
        crate::secret_fields::AddPath::Manual => match compose_manual_submit_outcome(state, now) {
            ManualSubmitOutcome::Proceed(validated) => SubmitOutcome::Proceed(validated),
            ManualSubmitOutcome::InlineError(err) => SubmitOutcome::InlineError(err),
        },
        crate::secret_fields::AddPath::Uri => match compose_uri_submit_outcome(state, now) {
            crate::otpauth_uri_paste::UriSubmitOutcome::Proceed(validated) => {
                SubmitOutcome::Proceed(validated)
            }
            // The URI sub-path's [`crate::otpauth_uri_paste::InlineError`]
            // is structurally identical to [`InlineError`] but a
            // distinct type, so copy the fields rather than handing
            // the value through directly.
            crate::otpauth_uri_paste::UriSubmitOutcome::InlineError(err) => {
                SubmitOutcome::InlineError(InlineError {
                    kind: err.kind,
                    rendered: err.rendered,
                })
            }
        },
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

/// Save-click outcome from the path-aware submit composer chained
/// through duplicate detection.
///
/// Collapses [`SubmitOutcome`] and [`DuplicateOutcome`] into a
/// single shape so the widget Save handler has one downstream
/// branch covering the full pre-mutation pipeline:
///
/// * [`SaveClickOutcome::Proceed`] — validated account ready for
///   insertion via `Vault::mutate_and_save(|v| v.add(account))`.
///   The widget dispatches [`AddAccountMsg::SubmitProceed`].
/// * [`SaveClickOutcome::AwaitConfirmation`] — `(secret, issuer,
///   label)` collision detected by [`Vault::find_duplicate`]. The
///   widget renders the existing summary alongside the "add
///   anyway?" prompt and dispatches
///   [`AddAccountMsg::StagePendingDuplicate`] to park the pending
///   in [`crate::secret_fields::AddSecretState::pending`].
/// * [`SaveClickOutcome::InlineError`] — typed §5 inline error
///   surfaced by [`compose_submit_outcome`] before the duplicate
///   check runs. The widget renders the rejection against the
///   active sub-path's failing field and leaves the form populated
///   for retry.
///
/// Naming parallels [`SubmitOutcome`] / [`DuplicateOutcome`] on
/// the per-stage layer; this enum is the unified projection the
/// widget consults once per Save click.
#[derive(Debug)]
pub enum SaveClickOutcome {
    /// Validated account ready for insertion via
    /// `Vault::mutate_and_save(|v| v.add(account))`.
    Proceed(ValidatedAccount),
    /// `Vault::find_duplicate` returned a collision. Threads the
    /// existing summary plus the pending validated account so the
    /// widget can render the "add anyway?" prompt and park the
    /// pending via
    /// [`crate::secret_fields::AddSecretState::replace_pending`].
    AwaitConfirmation {
        /// Existing account that collided. The widget renders its
        /// display label and metadata so the user can confirm the
        /// collision before electing "add anyway".
        existing: AccountSummary,
        /// Pending validated account staged in the
        /// [`crate::secret_fields::AddSecretState::pending`] slot.
        validated: ValidatedAccount,
    },
    /// Typed §5 inline error; the widget renders the rejection
    /// against the active sub-path's failing field. Surfaced
    /// before the duplicate check runs so a typed-but-rejected
    /// attempt never consults the vault.
    InlineError(InlineError),
}

/// Path-aware Save-click composer chaining [`compose_submit_outcome`]
/// with [`paladin_core::Vault::find_duplicate`] + [`classify_duplicate`].
///
/// The widget Save handler calls this once per click to drive the
/// full pre-mutation pipeline as a single boundary — the unified
/// [`SaveClickOutcome`] keeps the downstream dispatch
/// (`SubmitProceed` vs `StagePendingDuplicate` vs inline render) a
/// one-shot match without re-deriving the validation or
/// duplicate-detection decision elsewhere.
///
/// Routing rules:
///
/// * Typed inline error from [`compose_submit_outcome`] →
///   [`SaveClickOutcome::InlineError`]. The vault is **not**
///   consulted, so a typed-but-rejected attempt never runs the
///   duplicate check.
/// * `Proceed(validated)` from [`compose_submit_outcome`] →
///   [`paladin_core::Vault::find_duplicate`] is consulted; the
///   `Option<&Account>` collapses to `Option<AccountSummary>` for
///   [`classify_duplicate`], which routes to
///   [`SaveClickOutcome::Proceed`] (no collision) or
///   [`SaveClickOutcome::AwaitConfirmation`] (collision).
///
/// The borrow keeps the dialog state intact so a typed-but-
/// rejected attempt can retry against the same buffers without
/// losing the user's input on either sub-path. The vault is
/// borrowed shared because
/// [`paladin_core::Vault::find_duplicate`] is read-only — the
/// mutation lives later in the
/// `gio::spawn_blocking Vault::mutate_and_save(|v| v.add(account))`
/// worker once the widget dispatches `SubmitProceed`.
#[must_use]
pub fn compose_save_click_outcome(
    state: &AddDialogState,
    vault: &Vault,
    now: SystemTime,
) -> SaveClickOutcome {
    match compose_submit_outcome(state, now) {
        SubmitOutcome::InlineError(err) => SaveClickOutcome::InlineError(err),
        SubmitOutcome::Proceed(validated) => {
            let existing = vault.find_duplicate(&validated).map(Account::summary);
            match classify_duplicate(validated, existing) {
                DuplicateOutcome::Proceed(validated) => SaveClickOutcome::Proceed(validated),
                DuplicateOutcome::AwaitConfirmation {
                    existing,
                    validated,
                } => SaveClickOutcome::AwaitConfirmation {
                    existing,
                    validated,
                },
            }
        }
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

/// Bundle of inputs the GTK add worker consumes by value.
///
/// `AppModel::update` builds this from the live `Unlocked` `(Vault,
/// Store)` pair plus the [`ValidatedAccount::account`] extracted from
/// either [`classify_manual_submit`]'s `Proceed` arm or
/// [`crate::otpauth_uri_paste::classify_uri_submit`]'s `Proceed` arm
/// (the URI sub-path shares the same downstream commit path). The
/// dialog retains the [`ValidatedAccount::warnings`] in its own
/// reactive state so they can be rendered on the success path; the
/// worker is concerned only with the commit itself.
///
/// Consumed by value so `gio::spawn_blocking(move || run_add_worker(
/// input))` moves the live pair into the worker thread without
/// keeping `AppModel` in `Unlocked` for the duration of the save
/// call. The same pair returns from the worker on every branch so
/// `AppModel::update` can reinstall it before applying the UI
/// outcome.
///
/// `Clone` / `PartialEq` are deliberately not derived: [`Store`]
/// holds non-`Clone` filesystem state, [`Account`] holds zeroizing
/// secret bytes, and `AppModel::update` consumes the input exactly
/// once when it moves it into the `gio::spawn_blocking` closure.
#[derive(Debug)]
pub struct AddWorkerInput {
    /// Live vault from the `Unlocked` `(Vault, Store)` pair. Moved
    /// into the worker so `mutate_and_save` can borrow it mutably
    /// without keeping `AppModel` in `Unlocked` for the duration of
    /// the save call.
    pub vault: Vault,
    /// Live store from the `Unlocked` `(Vault, Store)` pair. Moved
    /// alongside `vault` so the same `(Vault, Store)` pair returns
    /// from the worker even on typed failure.
    pub store: Store,
    /// Validated account extracted from
    /// [`ValidatedAccount::account`]. The id stamped at validation
    /// time is preserved through [`Vault::add`] so the worker can
    /// surface it back to the dialog on
    /// [`AddWorkerEffect::Success`] without scanning the vault.
    pub account: Account,
}

/// Outcome of [`run_add_worker`] for `AppModel::update` to apply.
///
/// `Success` indicates the add committed and the row appears in the
/// visible account list (the carried [`AccountId`] lets the dialog /
/// list highlight or scroll to the new row without re-scanning the
/// vault). `Failure` wraps the [`AddPostEffectOutcome`] from
/// [`classify_add_post_effect_error`] so the dialog can re-render
/// the inline error / durability warning without re-deriving the
/// routing decision off the [`PaladinError`].
#[derive(Debug, Clone)]
pub enum AddWorkerEffect {
    /// `Vault::mutate_and_save(|v| { v.add(account); … })` returned
    /// `Ok(())`. The dialog dismisses itself and the new row appears
    /// in the visible account list. The carried [`AccountId`] is the
    /// id stamped on the [`Account`] at validation time (preserved
    /// by [`Vault::add`]).
    Success {
        /// Stable id of the just-inserted account.
        account_id: AccountId,
    },
    /// `Vault::mutate_and_save(|v| { v.add(account); … })` returned a
    /// typed failure. The carried [`AddPostEffectOutcome`] tells the
    /// dialog whether to stay open with an inline error
    /// (`save_not_committed`, `io_error`, defensive
    /// `validation_error` / `invalid_state` / …) or report success
    /// with an attached durability warning
    /// (`save_durability_unconfirmed`).
    Failure(AddPostEffectOutcome),
}

/// Bundle returned by [`run_add_worker`].
///
/// Carries the live `(Vault, Store)` pair on every branch so
/// `AppModel::update` can reinstall it before applying the UI
/// outcome — `Vault::mutate_and_save` already restores the snapshot
/// on `save_not_committed`, so the returned vault is the
/// authoritative post-effect state regardless of the
/// [`AddWorkerEffect`] variant. Per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Vault interaction" > "Every worker returns `(Vault, Store,
/// EffectOutcome)`".
///
/// `Clone` / `PartialEq` are deliberately not derived for the same
/// reason as on [`AddWorkerInput`].
#[derive(Debug)]
pub struct AddWorkerCompletion {
    /// Routed effect for `AppModel::update` to apply to the dialog.
    pub effect: AddWorkerEffect,
    /// Live vault after the `mutate_and_save` call. On
    /// [`AddWorkerEffect::Success`] the targeted account is present;
    /// on [`AddWorkerEffect::Failure`] the vault is whatever
    /// `mutate_and_save` rolled back to (pre-commit snapshot for
    /// `save_not_committed`; post-commit state with the new account
    /// for `save_durability_unconfirmed`; pre-call state for
    /// defensive `validation_error` / `invalid_state` cases).
    pub vault: Vault,
    /// Live store moved through unchanged so `AppModel::update` can
    /// reinstall the `(Vault, Store)` pair after the worker returns.
    pub store: Store,
}

/// Synchronous body of the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.add(...))` add worker fired by
/// `AppModel::update` from
/// `AppMsg::AddAccountAction(AddAccountOutput::Submit{Manual,Uri})`.
///
/// Consumes the [`AddWorkerInput`] by value, captures the
/// [`AccountId`] off the [`Account`] before it moves into the
/// closure, runs `vault.mutate_and_save(&store, |v| { v.add(account);
/// Ok(()) })`, and bundles the outcome into an
/// [`AddWorkerCompletion`] via [`classify_add_post_effect_error`].
/// The live `(Vault, Store)` pair is always returned so `AppModel`
/// reinstalls it regardless of the typed effect — `mutate_and_save`
/// is authoritative for the rollback / durability-unconfirmed
/// semantics per DESIGN.md §4.3.
///
/// The duplicate-detection pre-flight ([`classify_duplicate`]) runs
/// at the dialog layer before this worker is dispatched; an "add
/// anyway" confirmation consumes the staged validated account from
/// [`crate::secret_fields::AddSecretState::pending`] and the worker
/// commits it without re-checking. The worker therefore makes no
/// duplicate decisions — it commits whatever account the dialog
/// hands it, in lockstep with the CLI's `--allow-duplicate` /
/// "add anyway" semantics.
///
/// Extracting the worker body as a pure function lets
/// `AppModel::update`'s closure stay a thin
/// `gio::spawn_blocking(move || run_add_worker(input))` while the
/// real `mutate_and_save` call stays unit-testable in
/// `tests/add_account_logic.rs` against tempfile-backed plaintext
/// vaults — no GTK / libadwaita main loop required. The
/// `AppModel::update` wire-up and the `apply_add_*` reinstall
/// helpers land in follow-up commits alongside the `UnlockedBusy`
/// worker infrastructure.
#[must_use]
pub fn run_add_worker(input: AddWorkerInput) -> AddWorkerCompletion {
    let AddWorkerInput {
        mut vault,
        store,
        account,
    } = input;
    let account_id = account.id();
    let effect = match vault.mutate_and_save(&store, |v| {
        v.add(account);
        Ok(())
    }) {
        Ok(()) => AddWorkerEffect::Success { account_id },
        Err(err) => AddWorkerEffect::Failure(classify_add_post_effect_error(&err)),
    };
    AddWorkerCompletion {
        effect,
        vault,
        store,
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

/// Inbound messages handled by `AddAccountComponent`.
///
/// Symmetric partner of [`crate::rename_dialog::RenameDialogMsg`]
/// on the add path. Pinned as a typed enum so future Component
/// scaffolding (manual / URI / QR input plumbing, switching path,
/// duplicate prompt, etc.) can land as additional variants without
/// an `_` catch-all in the dispatch silently swallowing them.
///
/// Initial milestone defines only the
/// [`AddAccountMsg::WorkerFailed`] variant so
/// [`crate::app::state::add_dialog_msg_after`] has a typed message
/// to forward into the live `AddAccountComponent` after the
/// `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.add(account); … )` worker reports
/// a failure. The Component-side `apply_msg` routing for this
/// variant — the dialog-body re-render that attaches the inline
/// error / durability warning — lands in a follow-up commit
/// alongside the `AddAccountComponent` scaffold itself; for now
/// the variant exists so the dispatch path can build cleanly
/// while the rendering side catches up (parity with the rename
/// staged rollout in commit `ae8fd44`).
#[derive(Debug, Clone)]
pub enum AddAccountMsg {
    /// Cancel button activation. [`apply_msg`] forwards
    /// [`AddAccountOutput::Cancel`] so `AppModel` can drop the
    /// live [`AddAccountComponent`] controller and remove its
    /// widget from the content tree.
    Cancel,
    /// `AppModel` pushes the typed [`AddPostEffectOutcome`] back
    /// to the dialog after the
    /// `gio::spawn_blocking Vault::mutate_and_save(|v| v.add(...))`
    /// worker reports a failure. Symmetric partner of
    /// [`crate::rename_dialog::RenameDialogMsg::WorkerFailed`] on
    /// the add path: where the rename variant carries the typed
    /// [`crate::rename_dialog::RenameErrorOutcome`], the add
    /// variant carries the typed [`AddPostEffectOutcome`] so the
    /// dialog's handler can route `Inline` (render the typed
    /// inline error and keep the form populated for retry) or
    /// `KeepWithWarning` (attach the durability warning to the
    /// body) in one `apply_msg` arm.
    WorkerFailed(AddPostEffectOutcome),
    /// Internal Save-clicked routing produced by the widget once
    /// [`classify_manual_submit`] / [`crate::otpauth_uri_paste::classify_uri_submit`]
    /// returned `Proceed` and [`classify_duplicate`] reported a
    /// non-collision `Proceed(ValidatedAccount)`. Carries the
    /// validated [`Account`] so [`apply_msg`] can forward
    /// [`AddAccountOutput::Submit`] to `AppModel` without re-running
    /// the validation pipeline. The [`Account`]'s secret is wrapped
    /// in [`paladin_core::Secret`] (which is `ZeroizeOnDrop`) so the
    /// message stays compliant with §"Secret entry handling" when it
    /// crosses the Component boundary.
    ///
    /// The duplicate-collision "add anyway" path uses
    /// [`Self::ConfirmAddAnyway`] instead — that variant sources the
    /// account from
    /// [`crate::secret_fields::AddSecretState::pending`] (parked by
    /// [`Self::StagePendingDuplicate`]) rather than from the widget,
    /// so a stray Save click cannot bypass the parked-pending
    /// invariant.
    SubmitProceed {
        /// Validated account ready for insertion via
        /// `Vault::mutate_and_save(|v| v.add(account))`. The
        /// stable id stamped at validation time is preserved
        /// through [`Vault::add`] and surfaces on
        /// [`AddWorkerEffect::Success`].
        account: Account,
    },
    /// `AdwViewSwitcher` selection between the manual / URI sub-
    /// paths. [`apply_msg`] delegates to
    /// [`crate::secret_fields::AddSecretState::switch_path`], which
    /// is a no-op on same-path re-entry and otherwise wipes the
    /// leaving path's secret buffer and drops any pending duplicate-
    /// add staged for the prior path. The decision is dialog-local —
    /// no [`AddAccountOutput`] is emitted; `AppModel` only sees the
    /// path that was active when the user pressed Save.
    SwitchPath(AddPath),
    /// Per-keystroke shadow of the non-secret label entry into
    /// [`ManualDraftState::label`].
    ///
    /// Carries a plain `String` from the GTK [`gtk::EntryBuffer`] at
    /// the §8 UI boundary; the bytes are not secret-bearing (the
    /// `validate_manual` field-name `label` rule rejects empty /
    /// overlong but the label itself is rendered to the user as a
    /// row title once committed). [`apply_msg`] replaces (does not
    /// append) the prior shadow so the draft stays in lockstep with
    /// the visible entry text. Dialog-local — no [`AddAccountOutput`]
    /// is emitted.
    ManualLabelChanged(String),
    /// Per-keystroke shadow of the non-secret issuer entry into
    /// [`ManualDraftState::issuer`].
    ///
    /// Sibling of [`Self::ManualLabelChanged`] on the issuer field.
    /// Carries a plain `String` from the GTK [`gtk::EntryBuffer`] at
    /// the §8 UI boundary; the bytes are not secret-bearing — the
    /// issuer is rendered alongside the row label once committed and
    /// participates in the issuer / label match-key
    /// [`paladin_core::account_matches_search`] uses. Empty issuer
    /// maps to `None` at submit time inside
    /// [`classify_manual_submit`]; the draft preserves the user's
    /// whitespace so the cursor position does not jump. [`apply_msg`]
    /// replaces (does not append) the prior shadow. Dialog-local —
    /// no [`AddAccountOutput`] is emitted.
    ManualIssuerChanged(String),
    /// Algorithm dropdown selection shadowed into
    /// [`ManualDraftState::algorithm`].
    ///
    /// Sibling of [`Self::ManualLabelChanged`] on the algorithm
    /// dropdown. Carries the typed [`Algorithm`] enum rather than a
    /// raw string because the `AdwComboRow` model is built from the
    /// fixed `{Sha1, Sha256, Sha512}` set; the widget maps the
    /// selected index back to the enum before dispatching so
    /// [`apply_msg`] never has to re-parse a label. [`apply_msg`]
    /// replaces the prior shadow on every selection. Dialog-local —
    /// no [`AddAccountOutput`] is emitted.
    ManualAlgorithmChanged(Algorithm),
    /// OTP digit count from the digits spinner shadowed into
    /// [`ManualDraftState::digits`].
    ///
    /// Sibling of [`Self::ManualAlgorithmChanged`] on the digits
    /// spinner. The widget configures the `AdwSpinRow` adjustment to
    /// `6..=8` so dispatch normally only carries valid values, but
    /// [`apply_msg`] does **not** re-clamp — the draft preserves
    /// whatever value arrives so [`validate_manual`] at Save time can
    /// surface the typed `digits` inline error if a test driver or a
    /// future misuse path slips an out-of-range value through.
    /// Dialog-local — no [`AddAccountOutput`] is emitted.
    ManualDigitsChanged(u8),
    /// TOTP / HOTP switcher selection shadowed into
    /// [`ManualDraftState::kind`].
    ///
    /// Sibling of [`Self::ManualAlgorithmChanged`] on the kind
    /// switcher. The widget swaps the period spinner for the counter
    /// spinner (and vice versa) on every `#[watch]` re-render keyed
    /// off this field. [`apply_msg`] does **not** clear the sibling
    /// `period_secs` / `counter` buffers — [`classify_manual_submit`]
    /// at Save time already drops the irrelevant value based on
    /// `kind`, so a toggle-and-toggle-back preserves the user's prior
    /// typing in both fields. Dialog-local — no [`AddAccountOutput`]
    /// is emitted.
    ManualKindChanged(AccountKindInput),
    /// TOTP period (seconds) from the period spinner shadowed into
    /// [`ManualDraftState::period_secs`].
    ///
    /// Sibling of [`Self::ManualDigitsChanged`] on the period
    /// spinner. The widget configures the `AdwSpinRow` adjustment to
    /// the §5 valid range so dispatch normally only carries valid
    /// values, but [`apply_msg`] does **not** re-clamp — the draft
    /// preserves whatever value arrives so [`validate_manual`] at
    /// Save time can surface the typed `period_secs` inline error.
    /// The field is consulted only when `kind == AccountKindInput::Totp`
    /// (see [`classify_manual_submit`]) but the draft preserves it
    /// regardless so a kind round trip does not lose the user's
    /// typing. Dialog-local — no [`AddAccountOutput`] is emitted.
    ManualPeriodChanged(u32),
    /// HOTP starting counter from the counter spinner shadowed into
    /// [`ManualDraftState::counter`].
    ///
    /// Sibling of [`Self::ManualPeriodChanged`] on the counter
    /// spinner. The full `u64` range is accepted verbatim —
    /// [`validate_manual`] at Save time owns any range checks. The
    /// field is consulted only when `kind == AccountKindInput::Hotp`
    /// (see [`classify_manual_submit`]) but the draft preserves it
    /// regardless so a kind round trip does not lose the user's
    /// typing. Dialog-local — no [`AddAccountOutput`] is emitted.
    ManualCounterChanged(u64),
    /// Per-keystroke shadow of the non-secret icon-hint entry into
    /// [`ManualDraftState::icon_hint_text`].
    ///
    /// Sibling of [`Self::ManualLabelChanged`] on the icon-hint
    /// field. Carries a plain `String` from the GTK
    /// [`gtk::EntryBuffer`] at the §8 UI boundary; the bytes are not
    /// secret-bearing. Parsing of `"none"` (any case) / explicit
    /// slugs lives in [`paladin_core::parse_icon_hint_token`] at
    /// Save time inside [`classify_manual_submit`], so [`apply_msg`]
    /// preserves the typed text verbatim — including whitespace and
    /// arbitrary case — so the parse happens once at the boundary the
    /// CLI / TUI also use. [`apply_msg`] replaces (does not append)
    /// the prior shadow. Dialog-local — no [`AddAccountOutput`] is
    /// emitted.
    ManualIconHintChanged(String),
    /// Per-keystroke shadow of the manual Base32 secret entry into
    /// the Paladin-owned [`crate::secret_fields::SecretEntry`] inside
    /// [`crate::secret_fields::AddSecretState::manual_secret`].
    ///
    /// Carries a plain `String` rather than [`secrecy::SecretString`]
    /// because the GTK [`gtk::EntryBuffer`] is the unavoidable §8 UI
    /// boundary: the bytes arrive as a `GString` from
    /// [`gtk::Editable::text`] and live transiently in the relm4
    /// channel before [`apply_msg`] shadows them into the
    /// [`crate::secret_fields::SecretEntry`]. Once the handler
    /// returns, the `String` drops and only the `Zeroizing<String>`
    /// copy in [`AddDialogState::secret_state`] survives. Mirror of
    /// [`crate::unlock_dialog::UnlockDialogMsg::PassphraseChanged`]
    /// on the add path.
    ManualSecretChanged(String),
    /// Per-keystroke shadow of the `otpauth://` URI entry into the
    /// Paladin-owned [`crate::secret_fields::SecretEntry`] inside
    /// [`crate::secret_fields::AddSecretState::uri_text`].
    ///
    /// Secret-bearing because the URI embeds the Base32 secret per
    /// §"Secret entry handling": the same `String`-at-the-UI-boundary,
    /// `Zeroizing<String>`-in-the-canonical-home contract applies
    /// here as for [`Self::ManualSecretChanged`].
    UriTextChanged(String),
    /// The widget pre-ran [`classify_duplicate`] and observed
    /// [`DuplicateOutcome::AwaitConfirmation`]; the pending
    /// [`ValidatedAccount`] is staged in
    /// [`crate::secret_fields::AddSecretState::pending`] so the
    /// "add anyway?" confirmation prompt can render. The
    /// destructured `{ account, warnings }` shape sidesteps the
    /// missing `Clone` impl on [`ValidatedAccount`] — both fields
    /// are `Clone` individually so [`AddAccountMsg`]'s `Clone`
    /// derive stays intact. [`apply_msg`] reconstructs a
    /// [`ValidatedAccount`] from the carried fields before handing
    /// it to
    /// [`crate::secret_fields::AddSecretState::replace_pending`].
    ///
    /// Dialog-local — no [`AddAccountOutput`] is emitted. The
    /// duplicate-confirm round trip stays inside the dialog until
    /// the user confirms (via [`Self::ConfirmAddAnyway`], which
    /// consumes the pending and forwards
    /// [`AddAccountOutput::Submit`]) or cancels (via
    /// [`Self::Cancel`], which drops the pending).
    StagePendingDuplicate {
        /// Validated account ready for insertion via
        /// `Vault::mutate_and_save(|v| v.add(account))` once the
        /// user confirms "add anyway". Stored together with
        /// `warnings` in a reconstructed [`ValidatedAccount`]
        /// inside [`crate::secret_fields::AddSecretState::pending`].
        account: Account,
        /// Non-fatal warnings collected during validation (e.g.
        /// [`ValidationWarning::ShortSecret`]). Threaded through
        /// with `account` so the dialog can render them alongside
        /// the duplicate-confirm prompt without re-running
        /// [`validate_manual`].
        warnings: Vec<ValidationWarning>,
    },
    /// "Add anyway" confirmation from the duplicate-collision modal.
    /// [`apply_msg`] consumes the pending [`ValidatedAccount`] out of
    /// [`crate::secret_fields::AddSecretState::pending`] via
    /// [`crate::secret_fields::AddSecretState::consume_pending`] —
    /// which also wipes the manual / URI shadow buffers — and
    /// forwards the carried [`Account`] as
    /// [`AddAccountOutput::Submit`] so `AppModel::update` can spawn
    /// the `gio::spawn_blocking Vault::mutate_and_save(|v|
    /// v.add(account))` worker. CLI parity with `--allow-duplicate`
    /// and TUI parity with `Effect::AddAnyway`.
    ///
    /// Defensive: a dispatch with no pending parked is a no-op (no
    /// output, no state change) so a stray click cannot punch through
    /// to the worker without a validated account in hand.
    ConfirmAddAnyway,
    /// Typed §5 inline-error projection produced by the widget when
    /// [`compose_save_click_outcome`] returned
    /// [`SaveClickOutcome::InlineError`] — the active sub-path's
    /// pre-effect validation or duplicate-detection pipeline
    /// rejected the Save click. [`apply_msg`] stores the carried
    /// [`InlineError`] in [`AddDialogState::inline_error`] so the
    /// dialog body's `#[watch]` over [`AddDialogState::inline_error`]
    /// can render the typed body against the failing field.
    /// Dialog-local — no [`AddAccountOutput`] is emitted; the
    /// rejection stays inside the dialog until the user fixes the
    /// failing field and re-submits. Mirror of
    /// [`crate::unlock_dialog::UnlockDialogState::set_inline_error`]
    /// on the add path; pairs with [`Self::WorkerFailed`] which
    /// covers post-effect (`Vault::mutate_and_save`) failures
    /// instead.
    RenderInlineError(InlineError),
}

/// Outbound messages emitted by [`AddAccountComponent`] back to
/// `AppModel`.
///
/// Symmetric partner of [`crate::rename_dialog::RenameDialogOutput`]
/// on the add path. Pinned as a typed enum so future Component
/// scaffolding (manual / URI / QR submit variants) can land as
/// additional variants without an `_` catch-all in the dispatch
/// silently swallowing them.
///
/// `Cancel` dismisses the dialog; `Submit` ships the validated
/// [`Account`] to `AppModel` so the `gio::spawn_blocking
/// Vault::mutate_and_save(|v| v.add(account))` worker can run. The
/// QR sub-path (`Vec<ValidatedAccount>`) lands as a separate variant
/// alongside the QR widget body in a follow-up commit.
#[derive(Debug, Clone)]
pub enum AddAccountOutput {
    /// User dismissed the dialog without saving. `AppModel` drops
    /// the live [`AddAccountComponent`] controller and removes its
    /// widget from the content tree.
    Cancel,
    /// Save button pressed with a validated account from either the
    /// manual or URI sub-path. The widget pre-runs
    /// [`classify_manual_submit`] / [`crate::otpauth_uri_paste::classify_uri_submit`]
    /// and [`classify_duplicate`] on the main thread so this
    /// variant only fires once a `Proceed` outcome (or a consumed
    /// "add anyway" duplicate) is in hand. `AppModel` hands the
    /// pair to the `gio::spawn_blocking
    /// Vault::mutate_and_save(|v| v.add(account))` worker via
    /// [`crate::app::state::compose_add_worker_input`].
    Submit {
        /// Validated account ready for insertion. The id stamped
        /// at validation time is preserved through [`Vault::add`]
        /// so the worker can surface it back to the dialog on
        /// [`AddWorkerEffect::Success`] without scanning the
        /// vault.
        account: Account,
    },
}

/// Construction parameters for [`AddAccountComponent`].
///
/// Mirrors the shape of [`crate::rename_dialog::RenameDialogInit`]
/// but carries the vault path rather than a target account — the
/// add dialog creates a *new* account rather than mutating an
/// existing one. The path is retained on `self` so the smoke test
/// marker ([`format_add_dialog_marker`]) can render it for the
/// `xvfb-run` integration test that will land alongside the
/// header-bar `+` button wiring.
#[derive(Debug, Clone)]
pub struct AddAccountInit {
    /// Vault path the dialog will commit a new account into. Cloned
    /// from `AppModel::state` at mount time so a mid-flight
    /// passphrase-transition or lock cannot retarget the dialog.
    pub vault_path: PathBuf,
}

/// Stable stdout prefix the smoke test in `tests/gtk_smoke.rs`
/// greps for to prove [`AddAccountComponent`] mounted under
/// `xvfb-run`.
///
/// Symmetric partner of
/// [`crate::rename_dialog::RENAME_DIALOG_MARKER_PREFIX`]; the
/// literal is pinned by `tests/add_account_logic.rs` so the
/// pure-logic projection and the smoke marker never drift.
pub const ADD_DIALOG_MARKER_PREFIX: &str = "paladin-gtk: add_dialog_path=";

/// Render the stdout marker the smoke test greps for after the
/// header-bar `+` button mounts the [`AddAccountComponent`].
///
/// Symmetric partner of
/// [`crate::rename_dialog::format_rename_dialog_marker`]. The marker
/// carries the resolved vault path so a future
/// `tests/gtk_smoke.rs` variant can assert that the dialog mounted
/// against the same path the startup probes resolved.
#[must_use]
pub fn format_add_dialog_marker(path: &Path) -> String {
    format!("{ADD_DIALOG_MARKER_PREFIX}{}", path.display())
}

/// Apply an inbound [`AddAccountMsg`] and return the optional
/// [`AddAccountOutput`] the widget layer should forward to
/// `AppModel`.
///
/// Symmetric partner of [`crate::rename_dialog::apply_msg`] on the
/// add path. Pulled out of [`AddAccountComponent::update`] so the
/// routing decision stays unit-testable in
/// `tests/add_account_logic.rs` without spinning up GTK.
///
/// Initial milestone handles three variants:
///
/// * [`AddAccountMsg::Cancel`] → `Some(AddAccountOutput::Cancel)`.
///   The dialog dismisses; `AppModel` drops the controller.
/// * [`AddAccountMsg::WorkerFailed`] → `None`. The typed
///   [`AddPostEffectOutcome`] is consumed by the dialog to re-
///   render the inline error / durability warning; it never
///   bubbles back to `AppModel`. The rendering side lands in a
///   follow-up commit alongside the editable form widgets.
/// * [`AddAccountMsg::SubmitProceed`] →
///   `Some(AddAccountOutput::Submit { account })`. The widget pre-
///   runs [`classify_manual_submit`] /
///   [`crate::otpauth_uri_paste::classify_uri_submit`] and
///   [`classify_duplicate`] on the main thread; this arm only
///   forwards the validated [`Account`] once a `Proceed` outcome
///   is in hand, so `AppModel::update`'s submit handler does not
///   re-derive the validation pipeline.
/// * [`AddAccountMsg::ConfirmAddAnyway`] →
///   `Some(AddAccountOutput::Submit { account })` sourced from
///   the pending [`ValidatedAccount`] parked by
///   [`AddAccountMsg::StagePendingDuplicate`]. The arm consumes
///   the pending via
///   [`crate::secret_fields::AddSecretState::consume_pending`]
///   (which also wipes the manual / URI shadow buffers) and is a
///   defensive no-op when no pending is parked.
///
/// Reactive state owned by the live [`AddAccountComponent`].
///
/// Symmetric partner of
/// [`crate::rename_dialog::RenameDialogState`] on the add path: the
/// only field at present is `worker_outcome`, the typed
/// [`AddPostEffectOutcome`] from the most recent
/// `Vault::mutate_and_save` worker completion. The widget view
/// matches on [`Self::worker_outcome`] so the dialog body can route
/// `Inline` (render the typed inline error and keep the form
/// populated for retry) or `KeepWithWarning` (attach the durability
/// warning) without re-deriving the routing decision.
///
/// Cleared by [`apply_msg`] on every fresh
/// [`AddAccountMsg::SubmitProceed`] so a retry never renders stale
/// post-effect text alongside the live attempt. The
/// draft-text / manual-fields / URI / QR sub-path state lands as
/// additional fields in follow-up commits alongside the editable
/// form widgets.
#[derive(Default)]
pub struct AddDialogState {
    /// Latest [`AddPostEffectOutcome`] from a completed
    /// `Vault::mutate_and_save` add worker.
    ///
    /// `None` between a dialog open and the first worker
    /// completion, and re-cleared by every
    /// [`AddAccountMsg::SubmitProceed`] so a retry does not render
    /// stale text from a previous worker attempt.
    worker_outcome: Option<AddPostEffectOutcome>,
    /// Paladin-owned secret-bearing state for the manual / URI sub-
    /// paths plus the duplicate-collision pending slot.
    ///
    /// Embedded so the dialog's path selector, secret-buffer shadows,
    /// and "add anyway" confirmation share a single state machine
    /// with the rest of the component layer
    /// ([`crate::secret_fields::AddSecretState`]). The default
    /// construction opens on [`crate::secret_fields::AddPath::Manual`]
    /// with empty buffers and no pending duplicate — see
    /// [`crate::secret_fields::AddSecretState::new`].
    ///
    /// Not `Debug` because [`crate::secret_fields::SecretEntry`]
    /// deliberately opts out of `Debug` so a stray `dbg!` cannot leak
    /// the manual Base32 secret or the `otpauth://` URI text through
    /// the error log.
    secret_state: AddSecretState,
    /// Non-secret live state for the manual sub-path's editable
    /// fields. Holds the label / issuer / algorithm / digits / kind /
    /// TOTP period / HOTP counter / icon-hint text shadow that the
    /// widget combines with
    /// [`crate::secret_fields::AddSecretState::manual_secret`] to
    /// build a [`ManualFields`] bundle at submit time. Defaults to
    /// the CLI manual-add defaults (TOTP, SHA1, 6 digits, 30 s
    /// period, HOTP counter 0).
    manual_draft: ManualDraftState,
    /// Typed §5 inline-error projection from the most recent Save
    /// click that produced [`SaveClickOutcome::InlineError`].
    ///
    /// `None` between dialog open and the first rejected Save
    /// click. Mutated through
    /// [`AddAccountMsg::RenderInlineError`] so the widget view
    /// (a `#[watch]` over [`Self::inline_error`]) can attach the
    /// `error` CSS class to the failing sub-path's row and render
    /// the typed body verbatim. Mirror of
    /// [`crate::unlock_dialog::UnlockDialogState::inline_error`]
    /// on the add path; pairs with the post-effect
    /// [`Self::worker_outcome`] slot which handles `Vault::mutate_and_save`
    /// failures instead of the pre-effect validation pipeline.
    inline_error: Option<InlineError>,
}

impl AddDialogState {
    /// Construct an empty state for a freshly-opened dialog.
    ///
    /// No worker has run yet, so [`Self::worker_outcome`] returns
    /// `None`. Mirror of [`crate::rename_dialog::RenameDialogState::new`]
    /// on the add path; pre-populated dialog state lands as
    /// additional construction arguments when the editable manual /
    /// URI / QR sub-paths are wired in follow-up commits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Latest [`AddPostEffectOutcome`] from a completed
    /// `Vault::mutate_and_save` add worker, or `None` if no worker
    /// has reported back yet (or a fresh submit has cleared it).
    ///
    /// The widget view matches on this so the body can route
    /// `Inline` (render the typed inline error) or
    /// `KeepWithWarning` (attach the durability warning) without
    /// re-deriving the typed routing decision.
    #[must_use]
    pub fn worker_outcome(&self) -> Option<&AddPostEffectOutcome> {
        self.worker_outcome.as_ref()
    }

    /// Read-only view of the dialog's secret-bearing state.
    ///
    /// Exposes the active sub-path, the manual / URI secret-shadow
    /// buffers, and the duplicate-collision pending slot so the
    /// widget view and integration tests can observe the dialog's
    /// secret state without owning a mutable handle. Mutation lands
    /// through dedicated [`AddAccountMsg`] arms in follow-up
    /// commits.
    #[must_use]
    pub fn secret_state(&self) -> &AddSecretState {
        &self.secret_state
    }

    /// Read-only view of the manual sub-path's live draft state.
    ///
    /// Exposes the non-secret label / issuer / algorithm / digits /
    /// kind / period / counter / icon-hint shadow so the widget view
    /// and integration tests can observe the live form values
    /// without owning a mutable handle. Per-field mutation lands
    /// through dedicated [`AddAccountMsg`] arms in follow-up
    /// commits.
    #[must_use]
    pub fn manual_draft(&self) -> &ManualDraftState {
        &self.manual_draft
    }

    /// Typed §5 inline-error projection from the most recent Save
    /// click, or `None` if the dialog has not yet seen a rejected
    /// Save click (or a successor message has cleared it).
    ///
    /// The widget binds a `#[watch]` over this so the dialog body
    /// can render the typed error against the failing sub-path's
    /// row. Returns the same projection
    /// [`AddAccountMsg::RenderInlineError`] last stored.
    #[must_use]
    pub fn inline_error(&self) -> Option<&InlineError> {
        self.inline_error.as_ref()
    }
}

/// Per-message routing decisions for [`AddAccountComponent`].
///
/// Draft-changed / duplicate-confirm routing land in follow-up
/// commits as additional variants are added to [`AddAccountMsg`] /
/// [`AddAccountOutput`]. Mirror of
/// [`crate::rename_dialog::apply_msg`] on the add path: the per-
/// message decisions stay co-located with the state struct so a
/// future refactor cannot silently reorder them.
#[must_use]
pub fn apply_msg(state: &mut AddDialogState, msg: AddAccountMsg) -> Option<AddAccountOutput> {
    match msg {
        AddAccountMsg::Cancel => {
            // DESIGN §8: secret fields clear on cancel. Wipe the
            // manual / URI shadow buffers and drop any pending
            // duplicate-add before emitting the output so the
            // secrets are not live between this return and
            // `AppModel` dropping the controller. The let-binding
            // names the returned `Option<Box<ValidatedAccount>>`
            // so the prior pending (if any) drops at the end of
            // this arm — `paladin_core::Secret`'s `ZeroizeOnDrop`
            // wipes the carried bytes.
            let _dropped_pending = state.secret_state.clear_for(ClearReason::Cancel);
            Some(AddAccountOutput::Cancel)
        }
        AddAccountMsg::WorkerFailed(outcome) => {
            state.worker_outcome = Some(outcome);
            None
        }
        AddAccountMsg::SubmitProceed { account } => {
            // Clear any prior worker outcome so the body does not
            // render stale post-effect text alongside the live
            // retry. The fresh worker run is authoritative for the
            // next routing decision.
            state.worker_outcome = None;
            // DESIGN §8: secret fields clear on submit. The
            // validated `Account` already carries its `Secret` in
            // `ZeroizeOnDrop` form across the Component boundary,
            // but the manual / URI shadow buffers and any pending
            // duplicate slot in `secret_state` are *not* consumed
            // by the output — wipe them here so the buffers are
            // empty before the worker spawns.
            let _dropped_pending = state.secret_state.clear_for(ClearReason::Submit);
            Some(AddAccountOutput::Submit { account })
        }
        AddAccountMsg::SwitchPath(to) => {
            // Detect an actual sub-path transition (versus an
            // idempotent same-path re-entry) before calling
            // [`AddSecretState::switch_path`], which early-returns
            // on same-path entry. Mirror the early-return guard
            // here so the inline-error / pending-duplicate drop
            // both key off the same condition the secret-state
            // layer already uses.
            let path_changed = state.secret_state.active_path != to;
            // Let-binding the returned `Option<Box<ValidatedAccount>>`
            // so the prior pending duplicate (if any) drops at the
            // end of this arm — the secret bytes inside the
            // `ValidatedAccount` zero out via
            // `paladin_core::Secret`'s `ZeroizeOnDrop` impl.
            let _dropped_pending = state.secret_state.switch_path(to);
            if path_changed {
                // A typed §5 rejection from
                // [`SaveClickOutcome::InlineError`] is always
                // specific to the leaving sub-path's failing field
                // (manual label / secret / icon-hint, or URI text);
                // it is not applicable to the entering path. Drop
                // it so the new path starts fresh — symmetric with
                // the pending-duplicate drop above.
                state.inline_error = None;
            }
            None
        }
        AddAccountMsg::ManualLabelChanged(text) => {
            state.manual_draft.label = text;
            None
        }
        AddAccountMsg::ManualIssuerChanged(text) => {
            state.manual_draft.issuer = text;
            None
        }
        AddAccountMsg::ManualAlgorithmChanged(algorithm) => {
            state.manual_draft.algorithm = algorithm;
            None
        }
        AddAccountMsg::ManualDigitsChanged(digits) => {
            state.manual_draft.digits = digits;
            None
        }
        AddAccountMsg::ManualKindChanged(kind) => {
            state.manual_draft.kind = kind;
            None
        }
        AddAccountMsg::ManualPeriodChanged(period_secs) => {
            state.manual_draft.period_secs = period_secs;
            None
        }
        AddAccountMsg::ManualCounterChanged(counter) => {
            state.manual_draft.counter = counter;
            None
        }
        AddAccountMsg::ManualIconHintChanged(text) => {
            state.manual_draft.icon_hint_text = text;
            None
        }
        AddAccountMsg::ManualSecretChanged(text) => {
            state.secret_state.manual_secret.set(&text);
            // Retyping the failing secret invalidates the prior
            // Save-click rejection — drop the inline error so the
            // dialog body stops rendering stale text against the
            // live buffer. Mirror of
            // `UnlockDialogState::set_passphrase` clearing
            // `inline_error` on the encrypted-vault path.
            state.inline_error = None;
            None
        }
        AddAccountMsg::UriTextChanged(text) => {
            state.secret_state.uri_text.set(&text);
            // Retyping the failing URI invalidates the prior
            // Save-click rejection — drop the inline error so the
            // dialog body stops rendering stale text against the
            // live buffer. Mirror of
            // `Self::ManualSecretChanged` on the URI sub-path.
            state.inline_error = None;
            None
        }
        AddAccountMsg::StagePendingDuplicate { account, warnings } => {
            // Reconstruct the `ValidatedAccount` from its destructured
            // fields — the variant carries `{ account, warnings }`
            // rather than `(ValidatedAccount)` because
            // `ValidatedAccount` is intentionally not `Clone` while
            // `AddAccountMsg` derives `Clone`. The let-binding names
            // the returned `Option<Box<ValidatedAccount>>` so any
            // prior pending drops at the end of this arm — its
            // secret bytes zero out via `paladin_core::Secret`'s
            // `ZeroizeOnDrop` impl.
            let _dropped_prior = state
                .secret_state
                .replace_pending(ValidatedAccount { account, warnings });
            None
        }
        AddAccountMsg::ConfirmAddAnyway => {
            // Defensive: no pending → no output. The widget should
            // only dispatch this after `StagePendingDuplicate` parked
            // a value, but a stray click cannot punch through to the
            // `(Vault, Store)` worker without an account in hand.
            let validated = state.secret_state.consume_pending()?;
            // Clear any prior worker outcome so the body does not
            // render stale post-effect text alongside the live
            // worker attempt. Symmetric with the `SubmitProceed`
            // arm — both enter the worker through the same
            // `AddAccountOutput::Submit` boundary.
            state.worker_outcome = None;
            Some(AddAccountOutput::Submit {
                account: validated.account,
            })
        }
        AddAccountMsg::RenderInlineError(err) => {
            // Replace any prior projection so the dialog never
            // renders stale text from an earlier Save click. The
            // widget computes [`compose_save_click_outcome`] on
            // every click; the rejection stays inline so the user
            // can retry without losing the in-flight buffers.
            state.inline_error = Some(err);
            None
        }
    }
}

/// Widget-bearing dialog for the header-bar `+` button.
///
/// Mounts a vertical layout with a heading naming the add flow and
/// a Cancel button that forwards [`AddAccountOutput::Cancel`] so
/// `AppModel` can dismiss the dialog. The editable manual / URI /
/// QR sub-paths, the Save button, and the `Vault::mutate_and_save(
/// |v| v.add(...))` worker land in follow-up commits alongside the
/// header-bar wiring per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Component tree" > `AddAccountComponent`.
///
/// Symmetric partner of [`crate::rename_dialog::RenameDialogComponent`]
/// for the add path. The Component is `pub` so the future header-
/// bar wiring commit can mount it from `AppModel::update`'s
/// `AppMsg::OpenAddDialog` arm without re-declaring the widget
/// shape.
pub struct AddAccountComponent {
    /// Construction parameters retained on `self` so future message
    /// handlers can read the resolved vault path. Held by value so
    /// the dialog never re-resolves the path mid-flight.
    init: AddAccountInit,
    /// Reactive state owned by the dialog. Currently carries the
    /// latest [`AddPostEffectOutcome`] from the
    /// `Vault::mutate_and_save` add worker so the view can route
    /// inline-error / durability-warning rendering. The editable
    /// manual / URI / QR sub-path state lands as additional fields
    /// in follow-up commits.
    state: AddDialogState,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for AddAccountComponent {
    type Init = AddAccountInit;
    type Input = AddAccountMsg;
    type Output = AddAccountOutput;

    view! {
        #[root]
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 12,
            set_hexpand: true,
            set_vexpand: true,

            gtk::Label {
                set_label: "Add account",
                set_xalign: 0.0,
                add_css_class: "title-2",
            },

            adw::PreferencesGroup {
                set_title: "New account",
                set_description: Some(
                    "The editable manual / URI / QR sub-paths land in a follow-up commit.",
                ),
            },

            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 6,
                set_halign: gtk::Align::End,

                #[name = "cancel_button"]
                gtk::Button {
                    set_label: "Cancel",
                    connect_clicked[sender] => move |_| {
                        sender.input(AddAccountMsg::Cancel);
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
        let model = AddAccountComponent {
            init,
            state: AddDialogState::new(),
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_msg(&mut self.state, msg) {
            // Ignore send failures: if `AppModel` has already dropped
            // the controller (e.g. window closed mid-click), there's
            // nothing left to dismiss.
            let _ = sender.output(output);
        }
    }
}

impl AddAccountComponent {
    /// Resolved vault path the dialog was mounted against. Used by
    /// the smoke-test marker ([`format_add_dialog_marker`]) and by
    /// future submit handlers that need to thread the path into
    /// the `Vault::mutate_and_save(|v| v.add(...))` worker.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.init.vault_path
    }

    /// Read-only view of the dialog's reactive state.
    ///
    /// Lets the future widget view bind `#[watch]` projections
    /// against [`AddDialogState::worker_outcome`] without exposing
    /// the field directly. Integration tests can use this to assert
    /// post-worker state without driving the `gio::spawn_blocking`
    /// boundary.
    #[must_use]
    pub fn state(&self) -> &AddDialogState {
        &self.state
    }
}
