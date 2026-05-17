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
    parse_icon_hint_token, validate_manual, Account, AccountId, AccountInput, AccountKindInput,
    AccountSummary, Algorithm, ErrorKind, PaladinError, Store, ValidatedAccount, Vault,
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
