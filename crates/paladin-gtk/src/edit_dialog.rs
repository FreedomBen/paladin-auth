// SPDX-License-Identifier: AGPL-3.0-or-later

//! Edit-dialog pure-logic state machine for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Row context menu and
//! `EditDialog` implementation (per DESIGN §7 / Milestone 9)" and
//! `docs/DESIGN.md` §7, the GTK `EditDialog` edits three
//! non-cryptographic fields of an existing account — label, issuer,
//! and icon-hint — over a [`paladin_core::AccountEdit`] value and
//! calls [`paladin_core::Vault::edit_account_metadata`] inside
//! `Vault::mutate_and_save`. This module owns the pure-logic state
//! machine (state buffers, per-keystroke projection, classify-submit,
//! classify-post-effect-error, lock-transition pruning) so the
//! dialog's decisions stay unit-testable in
//! `tests/edit_dialog_logic.rs` without spinning up GTK / libadwaita.
//! The widget binding lands in slice 4.
//!
//! # Three editable rows
//!
//! Each row is an [`adw::EntryRow`] pre-populated from
//! [`paladin_core::AccountSummary`]:
//!
//! * *Label* — required; validated through
//!   [`paladin_core::validate_label`]. Whitespace touches that
//!   normalize back to the prior label project to `None`
//!   (leave-untouched) so cosmetic edits never enable Save.
//! * *Issuer* — optional. Implicit-clear semantics match
//!   `paladin edit --no-issuer`: an empty buffer over a `Some(_)`
//!   prior projects to `Some(None)`. Per-keystroke length is
//!   gated by the §4.1 128-byte cap mirrored here.
//! * *Icon-hint slug* — optional; parsed through
//!   [`paladin_core::parse_icon_hint_token`]. Byte-equal to the
//!   pre-fill ⇒ leave-untouched; empty over `Some(_)` ⇒
//!   re-derive from post-edit issuer
//!   ([`paladin_core::IconHintInput::Default`]); literal `none`
//!   (case-insensitive) ⇒ explicit clear
//!   ([`paladin_core::IconHintInput::Clear`]); anything else ⇒
//!   `Slug(s)` and routes through `parse_icon_hint_token` for
//!   `[a-z0-9_-]+` rejection.
//!
//! The same WYSIWYS projection drives Save sensitivity and the
//! submit payload — see [`classify_edit_draft`] /
//! [`classify_submit`] / [`classify_post_effect_error`].
//!
//! # Pre-check order
//!
//! Locked by DESIGN §4.7 and the Phase M plan: per-field
//! [`paladin_core::validate_account_edit`] runs first; only on
//! success does the dialog issue
//! `Vault::find_duplicate_after_edit`. Reversing would surface
//! `duplicate_account` against a partly-invalid edit.
//! [`classify_submit`] encodes the ordering directly: per-row
//! WYSIWYS rules collapse to the `AccountEdit`, then the
//! cross-field `validate_account_edit` runs, then the duplicate
//! pre-flight runs separately in
//! [`classify_submit_with_duplicate`].
//!
//! # Post-effect routing
//!
//! [`classify_post_effect_error`] maps the [`PaladinError`] from
//! a failed `mutate_and_save` onto a [`PostEffectOutcome`]: the
//! `save_durability_unconfirmed` arm bubbles a warning into
//! [`PostEffectOutcome::StayOpenWithWarning`]; every other typed
//! error (including `save_not_committed`, `invalid_state`,
//! `duplicate_account`) routes through
//! [`PostEffectOutcome::StayOpenWithError`]. The `Ok` path is
//! handled by the dispatch site as
//! [`PostEffectOutcome::Close`] alongside the post-edit
//! [`AccountSummary`] for the toast.

use std::time::SystemTime;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use paladin_core::{
    parse_icon_hint_token, validate_account_edit, validate_label, Account, AccountEdit, AccountId,
    AccountSummary, ErrorKind, IconHintInput, PaladinError, Vault,
};

/// §4.1 issuer length cap. Mirrors the constant `paladin_core`
/// applies inside `validate_issuer` (which is `pub(crate)`) so
/// the per-keystroke projection can surface a length rejection
/// inline without a round-trip through
/// `validate_account_edit`.
pub const ISSUER_MAX_BYTES: usize = 128;

/// Pre-edit snapshot used to drive every WYSIWYS projection in
/// [`EditDialogState`].
///
/// Captured from `AccountSummary` at mount time so the dialog can
/// compare each row buffer against the persisted values without
/// re-reading the vault on every keystroke. Holds owned strings so
/// the state machine never borrows from the live `Vault`; the
/// dialog drops it on close / lock alongside the row buffers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditPriorSnapshot {
    /// Stable account identifier copied from
    /// [`AccountSummary::id`]; the submit payload threads it
    /// through to `Vault::edit_account_metadata`.
    pub account_id: AccountId,
    /// Pre-edit label exactly as the persisted `Account` carries
    /// it (already §4.1-normalized by `Vault::add` /
    /// `Vault::edit_account_metadata` on the previous write).
    pub label: String,
    /// Pre-edit issuer (`None` ⇔ no issuer is persisted).
    pub issuer: Option<String>,
    /// Pre-edit icon-hint slug (`None` ⇔ no slug is persisted).
    /// Already canonical (`[a-z0-9_-]+`) so a byte-equal
    /// comparison against the row buffer is sound.
    pub icon_hint: Option<String>,
    /// Pre-formatted `<issuer>:<label>` heading mirroring
    /// `crate::account_row::summary_display_label`. Used by the
    /// widget for the dialog sub-title and by the smoke-test
    /// marker.
    pub display_label: String,
}

impl EditPriorSnapshot {
    /// Build a snapshot from an [`AccountSummary`] using the same
    /// `<issuer>:<label>` projection the row factory binds.
    #[must_use]
    pub fn from_summary(summary: &AccountSummary) -> Self {
        let display_label = crate::account_row::summary_display_label(summary);
        Self {
            account_id: summary.id,
            label: summary.label.clone(),
            issuer: summary.issuer.clone(),
            icon_hint: summary.icon_hint.clone(),
            display_label,
        }
    }
}

/// Construction parameters for the future `EditDialogComponent`.
///
/// `AppModel` builds this from the live vault when a kebab
/// `AccountListOutput::OpenEditDialog(id)` arrives — see
/// [`decide_edit_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditDialogInit {
    /// Pre-edit snapshot the state seeds from.
    pub prior: EditPriorSnapshot,
}

/// Look up an [`AccountSummary`] by id and project it into the
/// [`EditDialogInit`] the widget binds.
///
/// Returns `None` if no account with the given id exists in
/// `vault` — the caller (`AppModel`) treats that as a benign race
/// (the account was removed between the kebab activation and the
/// dispatch) and does not mount the dialog (parity with
/// `decide_rename_target`).
#[must_use]
pub fn decide_edit_target(vault: &Vault, id: AccountId) -> Option<EditDialogInit> {
    vault
        .summaries()
        .find(|summary| summary.id == id)
        .map(|summary| EditDialogInit {
            prior: EditPriorSnapshot::from_summary(&summary),
        })
}

/// Live draft + projection state for the future
/// `EditDialogComponent`.
///
/// Three row buffers (`label_buf`, `issuer_buf`, `icon_hint_buf`)
/// shadow the [`adw::EntryRow`] text; per-keystroke validation
/// caches sit in `label_error`, `issuer_error`, `icon_hint_error`
/// so the widget can dim Save and render inline errors without
/// re-running the validators on every redraw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditDialogState {
    /// Pre-edit snapshot; the WYSIWYS rules compare each row
    /// buffer back to these values.
    prior: EditPriorSnapshot,
    /// Raw `Label` row text — preserved byte-for-byte. The
    /// projection in [`classify_edit_draft`] normalizes a copy
    /// before comparing to `prior.label`.
    label_buf: String,
    /// Raw `Issuer` row text — preserved byte-for-byte.
    issuer_buf: String,
    /// Raw icon-hint row text — preserved byte-for-byte (no
    /// client-side lowercasing; uppercase input surfaces
    /// inline through `parse_icon_hint_token`).
    icon_hint_buf: String,
    /// Cached `validate_label` outcome on the assembled
    /// `AccountEdit.label` projection. `None` while the buffer
    /// is untouched-equivalent or the label projection
    /// validates clean.
    label_error: Option<InlineError>,
    /// Cached issuer-length-cap outcome on the assembled
    /// `AccountEdit.issuer` projection.
    issuer_error: Option<InlineError>,
    /// Cached `parse_icon_hint_token` outcome on the icon-hint
    /// projection — `None` while clean / untouched.
    icon_hint_error: Option<InlineError>,
    /// Pending duplicate from the last `find_duplicate_after_edit`
    /// pre-flight; cleared on any keystroke to label or issuer
    /// (either field can resolve the collision per the design
    /// contract).
    duplicate: Option<DuplicateMarker>,
    /// Latest post-effect routing decision from a completed
    /// `Vault::edit_account_metadata` worker. Cleared by any
    /// keystroke so the body never renders stale text alongside
    /// the live attempt.
    worker_outcome: Option<PostEffectOutcome>,
    /// Worker-in-flight latch flipped by the parent around the
    /// `gio::spawn_blocking Vault::mutate_and_save(|v|
    /// v.edit_account_metadata(...))` worker.
    busy: bool,
}

/// Duplicate marker carried in [`EditDialogState`] between a
/// pre-flight collision and the keystroke that resolves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateMarker {
    /// The colliding account's stable id.
    pub other_id: AccountId,
    /// Pre-formatted heading of the colliding account, mirroring
    /// `summary_display_label`.
    pub display_label: String,
}

impl EditDialogState {
    /// Seed the state from a freshly-projected [`EditDialogInit`].
    ///
    /// Each row buffer opens pre-filled from the persisted value
    /// (the issuer / icon-hint `None` arms project to the empty
    /// string so the entry rows render an empty buffer). The
    /// initial Save sensitivity is `false` because the WYSIWYS
    /// projection of "pre-fill exactly" collapses to an empty
    /// `AccountEdit`.
    #[must_use]
    pub fn new(init: &EditDialogInit) -> Self {
        Self {
            label_buf: init.prior.label.clone(),
            issuer_buf: init.prior.issuer.clone().unwrap_or_default(),
            icon_hint_buf: init.prior.icon_hint.clone().unwrap_or_default(),
            prior: init.prior.clone(),
            label_error: None,
            issuer_error: None,
            icon_hint_error: None,
            duplicate: None,
            worker_outcome: None,
            busy: false,
        }
    }

    /// Stable account identifier the dialog targets.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        self.prior.account_id
    }

    /// Pre-edit snapshot for the success-toast label and the
    /// row-revert paths.
    #[must_use]
    pub fn prior(&self) -> &EditPriorSnapshot {
        &self.prior
    }

    /// Current raw label buffer.
    #[must_use]
    pub fn label_buf(&self) -> &str {
        &self.label_buf
    }

    /// Current raw issuer buffer.
    #[must_use]
    pub fn issuer_buf(&self) -> &str {
        &self.issuer_buf
    }

    /// Current raw icon-hint buffer.
    #[must_use]
    pub fn icon_hint_buf(&self) -> &str {
        &self.icon_hint_buf
    }

    /// Cached inline-error projection for the label row.
    #[must_use]
    pub fn label_error(&self) -> Option<&InlineError> {
        self.label_error.as_ref()
    }

    /// Cached inline-error projection for the issuer row.
    #[must_use]
    pub fn issuer_error(&self) -> Option<&InlineError> {
        self.issuer_error.as_ref()
    }

    /// Cached inline-error projection for the icon-hint row.
    #[must_use]
    pub fn icon_hint_error(&self) -> Option<&InlineError> {
        self.icon_hint_error.as_ref()
    }

    /// Pending duplicate marker (`Some` between pre-flight
    /// detection and the next label / issuer keystroke).
    #[must_use]
    pub fn duplicate(&self) -> Option<&DuplicateMarker> {
        self.duplicate.as_ref()
    }

    /// Latest post-effect routing decision from a completed
    /// worker.
    #[must_use]
    pub fn worker_outcome(&self) -> Option<&PostEffectOutcome> {
        self.worker_outcome.as_ref()
    }

    /// Worker-in-flight latch.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Parent-driven setter for the worker-in-flight latch (same
    /// idempotency contract as `RenameDialogState::set_busy`).
    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
    }

    /// Replace the label buffer and refresh inline errors. Any
    /// keystroke on label or issuer also clears the duplicate
    /// marker (either field can resolve the §4.7 collision).
    pub fn set_label_buf(&mut self, buf: String) {
        self.label_buf = buf;
        self.refresh_inline_errors();
        self.duplicate = None;
        self.worker_outcome = None;
    }

    /// Replace the issuer buffer and refresh inline errors.
    pub fn set_issuer_buf(&mut self, buf: String) {
        self.issuer_buf = buf;
        self.refresh_inline_errors();
        self.duplicate = None;
        self.worker_outcome = None;
    }

    /// Replace the icon-hint buffer and refresh inline errors.
    /// Icon-hint keystrokes do **not** clear the duplicate
    /// marker — `icon_hint` is not part of the §4.7 duplicate
    /// key.
    pub fn set_icon_hint_buf(&mut self, buf: String) {
        self.icon_hint_buf = buf;
        self.refresh_inline_errors();
        self.worker_outcome = None;
    }

    /// Drop every row buffer + inline error + duplicate marker +
    /// pending worker outcome. The pre-edit `prior` snapshot is
    /// also cleared so the resulting state is
    /// identity-equal to the post-`clear_for_lock`-then-default
    /// shape.
    pub fn clear(&mut self) {
        self.label_buf.clear();
        self.issuer_buf.clear();
        self.icon_hint_buf.clear();
        self.label_error = None;
        self.issuer_error = None;
        self.icon_hint_error = None;
        self.duplicate = None;
        self.worker_outcome = None;
    }

    /// Refresh `label_error` / `issuer_error` / `icon_hint_error`
    /// against the current buffers.
    fn refresh_inline_errors(&mut self) {
        let projection = classify_edit_draft(self);
        self.label_error = projection.label_error;
        self.issuer_error = projection.issuer_error;
        self.icon_hint_error = projection.icon_hint_error;
    }
}

/// Inline-error projection for any of the three rows.
///
/// Carries the stable §5 [`ErrorKind`] for instrumentation and
/// the rendered body for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineError {
    /// Stable §5 discriminator copied from
    /// [`PaladinError::kind`].
    pub kind: ErrorKind,
    /// Rendered body for the inline-error `gtk::Label`.
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

/// Durability-warning projection for the dialog body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineWarning {
    /// Stable §5 discriminator — always
    /// [`ErrorKind::SaveDurabilityUnconfirmed`] in current code.
    pub kind: ErrorKind,
    /// Rendered body for the inline-warning `gtk::Label`.
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

/// Output of [`classify_edit_draft`]: the assembled
/// [`AccountEdit`] alongside the per-row inline-error caches.
///
/// `PartialEq` / `Eq` are intentionally not derived — `AccountEdit`
/// is `Clone + Debug + Default` but not `Eq`, and the dialog
/// state machine never compares two projections.
#[derive(Debug, Clone)]
pub struct EditDraftProjection {
    /// Assembled [`AccountEdit`] reflecting the WYSIWYS rules.
    pub edit: AccountEdit,
    /// Inline-error projection for the label row.
    pub label_error: Option<InlineError>,
    /// Inline-error projection for the issuer row.
    pub issuer_error: Option<InlineError>,
    /// Inline-error projection for the icon-hint row.
    pub icon_hint_error: Option<InlineError>,
}

impl EditDraftProjection {
    /// `true` iff every row validates clean **and** the assembled
    /// `AccountEdit` is non-empty. Drives Save sensitivity.
    #[must_use]
    pub fn save_sensitive(&self) -> bool {
        self.label_error.is_none()
            && self.issuer_error.is_none()
            && self.icon_hint_error.is_none()
            && !is_account_edit_empty(&self.edit)
    }
}

/// Per-keystroke projection of the three row buffers onto an
/// [`AccountEdit`].
///
/// Encodes the WYSIWYS rules from the design contract — see the
/// module docs for the table.
#[must_use]
pub fn classify_edit_draft(state: &EditDialogState) -> EditDraftProjection {
    let mut edit = AccountEdit::default();
    let mut label_error: Option<InlineError> = None;
    let mut issuer_error: Option<InlineError> = None;
    let mut icon_hint_error: Option<InlineError> = None;

    // ---- Label ----
    let label_trimmed = state.label_buf.trim();
    if label_trimmed == state.prior.label.trim() {
        // Whitespace-only / byte-equal-after-trim touches collapse
        // to leave-untouched (parity with the issuer rule).
        edit.label = None;
    } else {
        match validate_label(state.label_buf.as_str()) {
            Ok(trimmed) => {
                edit.label = Some(trimmed);
            }
            Err(err) => {
                label_error = Some(InlineError::from_error(&err));
                edit.label = Some(state.label_buf.clone());
            }
        }
    }

    // ---- Issuer ----
    let issuer_buf = state.issuer_buf.as_str();
    let issuer_trimmed = issuer_buf.trim();
    edit.issuer = match (issuer_buf.is_empty(), state.prior.issuer.as_deref()) {
        (true, None) => None,
        (true, Some(_)) => Some(None),
        (false, _) => {
            let prior_issuer = state.prior.issuer.as_deref().unwrap_or("");
            if issuer_trimmed == prior_issuer {
                None
            } else if issuer_trimmed.is_empty() {
                // Trimmed-empty buffer with non-empty raw is the
                // §4.1 "whitespace-only" case — surfaces a
                // validation_error rather than a leave-untouched.
                issuer_error = Some(make_validation_error(
                    "issuer",
                    "validation_error: issuer must not be empty",
                ));
                Some(Some(issuer_buf.to_string()))
            } else if issuer_trimmed.len() > ISSUER_MAX_BYTES {
                issuer_error = Some(make_validation_error(
                    "issuer",
                    "validation_error: issuer exceeds 128 bytes",
                ));
                Some(Some(issuer_buf.to_string()))
            } else {
                Some(Some(issuer_trimmed.to_string()))
            }
        }
    };

    // ---- Icon hint ----
    let prior_icon = state.prior.icon_hint.as_deref().unwrap_or("");
    let buf = state.icon_hint_buf.as_str();
    edit.icon_hint = if buf == prior_icon {
        // Byte-equal to the pre-fill ⇒ leave untouched. Also
        // covers the both-empty case (prior None / buf empty).
        None
    } else if buf.is_empty() {
        // Empty over Some(_) ⇒ implicit re-derive from issuer
        // (Default).
        Some(IconHintInput::Default)
    } else if buf.eq_ignore_ascii_case("none") {
        Some(IconHintInput::Clear)
    } else {
        match parse_icon_hint_token(buf) {
            Ok(input) => Some(input),
            Err(err) => {
                icon_hint_error = Some(InlineError::from_error(&err));
                Some(IconHintInput::Slug(buf.to_string()))
            }
        }
    };

    EditDraftProjection {
        edit,
        label_error,
        issuer_error,
        icon_hint_error,
    }
}

/// Build an [`InlineError`] for a synthesized `validation_error`
/// raised by the dialog (issuer length / empty-buffer arms that
/// the public surface does not let us reach through a
/// `PaladinError` ctor).
fn make_validation_error(field: &str, rendered: &str) -> InlineError {
    let _ = field;
    InlineError {
        kind: ErrorKind::ValidationError,
        rendered: rendered.to_string(),
    }
}

/// Whether the assembled `AccountEdit` carries any changes.
#[must_use]
pub fn is_account_edit_empty(edit: &AccountEdit) -> bool {
    edit.label.is_none() && edit.issuer.is_none() && edit.icon_hint.is_none()
}

/// Pre-submit routing outcome from [`classify_submit`].
///
/// * `EmptyEditReject` — every row at the pre-fill; Save disabled.
/// * `Validated` — per-field
///   [`paladin_core::validate_account_edit`] passed; the carried
///   `AccountEdit` is the payload the call site hands to
///   `Vault::find_duplicate_after_edit`.
/// * `InvalidEdit` — per-field validation rejected.
///
/// `PartialEq` / `Eq` are not derived because the carried
/// `AccountEdit` is not `Eq`.
#[derive(Debug, Clone)]
pub enum SubmitOutcome {
    /// Empty `AccountEdit`; no effect to dispatch.
    EmptyEditReject,
    /// Per-field validation passed; ready for the duplicate
    /// pre-flight.
    Validated(AccountEdit),
    /// Per-field validation rejected; the inline error lives on
    /// `EditDialogState` and is also surfaced here for the
    /// dispatch site that may toast a generic "invalid" hint.
    InvalidEdit(InlineError),
}

/// Final pre-effect routing — folds the
/// `find_duplicate_after_edit` result into the post-validator
/// state.
///
/// `PartialEq` / `Eq` are not derived because the carried
/// `AccountEdit` is not `Eq`.
#[derive(Debug, Clone)]
pub enum SubmitDispatch {
    /// Empty `AccountEdit`; no effect to dispatch.
    EmptyEditReject,
    /// Per-field validation rejected.
    InvalidEdit(InlineError),
    /// Pre-flight detected a collision; the dialog surfaces the
    /// inline error without mutating the vault.
    DuplicateDetected(DuplicateMarker),
    /// Cleared every pre-flight gate.
    DispatchEffect(AccountEdit),
}

/// Classify the live state into the pre-submit
/// [`SubmitOutcome`] without consulting the vault for the
/// duplicate pre-flight.
///
/// Internally:
/// 1. Runs [`classify_edit_draft`] to assemble the
///    `AccountEdit` per the WYSIWYS rules.
/// 2. Rejects the empty `AccountEdit` case.
/// 3. Surfaces any per-row inline error from the projection.
/// 4. Runs `validate_account_edit` against the assembled
///    `AccountEdit` for cross-field rules. `prior_account` is
///    the dialog's pre-fill `&Account` reference.
#[must_use]
pub fn classify_submit(state: &EditDialogState, prior_account: &Account) -> SubmitOutcome {
    let projection = classify_edit_draft(state);
    if is_account_edit_empty(&projection.edit) {
        return SubmitOutcome::EmptyEditReject;
    }
    if let Some(err) = projection
        .label_error
        .or(projection.issuer_error)
        .or(projection.icon_hint_error)
    {
        return SubmitOutcome::InvalidEdit(err);
    }
    match validate_account_edit(&projection.edit, prior_account, SystemTime::UNIX_EPOCH) {
        Ok(()) => SubmitOutcome::Validated(projection.edit),
        Err(err) => SubmitOutcome::InvalidEdit(InlineError::from_error(&err)),
    }
}

/// Final pre-effect routing — folds a resolved
/// `find_duplicate_after_edit` result into the post-validator
/// state. Reversing (duplicate before validate) would surface
/// `duplicate_account` against a partly-invalid edit — locked
/// by DESIGN.md / Phase M.
#[must_use]
pub fn classify_submit_with_duplicate(
    outcome: SubmitOutcome,
    duplicate: Option<DuplicateMarker>,
) -> SubmitDispatch {
    match outcome {
        SubmitOutcome::EmptyEditReject => SubmitDispatch::EmptyEditReject,
        SubmitOutcome::InvalidEdit(err) => SubmitDispatch::InvalidEdit(err),
        SubmitOutcome::Validated(edit) => match duplicate {
            Some(marker) => SubmitDispatch::DuplicateDetected(marker),
            None => SubmitDispatch::DispatchEffect(edit),
        },
    }
}

/// Build a [`DuplicateMarker`] from an [`Account`] returned by
/// `Vault::find_duplicate_after_edit`.
#[must_use]
pub fn duplicate_marker_from_account(other: &Account) -> DuplicateMarker {
    DuplicateMarker {
        other_id: other.id(),
        display_label: account_display_label(other),
    }
}

/// `<issuer>:<label>` projection against an [`Account`] — mirror
/// of `account_row::summary_display_label` for the duplicate
/// pre-flight result.
fn account_display_label(account: &Account) -> String {
    match account.issuer() {
        Some(issuer) if !issuer.is_empty() => format!("{issuer}:{label}", label = account.label()),
        _ => account.label().to_string(),
    }
}

/// Post-effect routing decision from a completed
/// `Vault::mutate_and_save(|v| v.edit_account_metadata(...))`
/// worker.
///
/// Locked variant set per the design contract / Phase M:
///
/// * `Close { post_summary }` — the `Ok` path. The dialog
///   dismisses; the dispatch site renders the
///   `Edited {summary_display_label}.` toast.
/// * `StayOpenWithWarning(InlineWarning)` — the
///   `save_durability_unconfirmed` path.
/// * `StayOpenWithError(InlineError)` — the
///   `save_not_committed` / `invalid_state` /
///   `duplicate_account` paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostEffectOutcome {
    /// `Ok` — close the dialog, render the toast.
    Close {
        /// Post-edit summary lookup (`None` defensively on a
        /// concurrent remove between mutate and read).
        post_summary: Option<AccountSummary>,
    },
    /// `save_durability_unconfirmed` — keep the dialog open and
    /// attach the warning.
    StayOpenWithWarning(InlineWarning),
    /// `save_not_committed` / `invalid_state` /
    /// `duplicate_account` — keep the dialog open and surface
    /// the inline error.
    StayOpenWithError(InlineError),
}

/// Map a [`PaladinError`] from the
/// `Vault::edit_account_metadata` worker into a typed
/// [`PostEffectOutcome`].
#[must_use]
pub fn classify_post_effect_error(err: &PaladinError) -> PostEffectOutcome {
    match err.kind() {
        ErrorKind::SaveDurabilityUnconfirmed => {
            PostEffectOutcome::StayOpenWithWarning(InlineWarning::from_error(err))
        }
        _ => PostEffectOutcome::StayOpenWithError(InlineError::from_error(err)),
    }
}

/// Drop every row buffer + cached inline error + duplicate
/// marker + pending worker outcome on auto-lock.
///
/// Registered with `AppModel`'s lock-transition pruning per the
/// design contract (locked three-step sequence: `force_close()`
/// on the controller → drop controller → `clear_for_lock` on
/// the captured state).
///
/// Idempotent: calling on already-cleared state is a benign
/// no-op.
pub fn clear_for_lock(state: &mut EditDialogState) {
    state.clear();
}

/// Format the smoke-test stdout marker line for a mounted
/// `EditDialogComponent`.
#[must_use]
pub fn format_edit_dialog_marker(account_id: AccountId, display_label: &str) -> String {
    format!("{EDIT_DIALOG_MARKER_PREFIX}{account_id} label={display_label}")
}

/// Stdout marker prefix emitted under `--exit-after-startup`
/// once `EditDialogComponent` mounts in response to a kebab
/// `Edit…` activation.
pub const EDIT_DIALOG_MARKER_PREFIX: &str = "paladin-gtk: edit_dialog_account=";

/// Fixed `Edit account` header text — the visible title at the
/// top of the dialog body. No ellipsis (the ellipsis applies to
/// the menu/button verb that opens the dialog).
#[must_use]
pub fn format_edit_dialog_title() -> &'static str {
    "Edit account"
}

/// Sub-title naming which account the user is editing —
/// `Editing <display>.` where `<display>` mirrors
/// `account_row::summary_display_label`.
#[must_use]
pub fn format_edit_dialog_subtitle(display_label: &str) -> String {
    format!("Editing {display_label}.")
}

/// `AdwEntryRow::set_title` for the Label row.
#[must_use]
pub fn format_edit_dialog_label_title() -> &'static str {
    "Label"
}

/// `AdwEntryRow::set_title` for the Issuer row.
#[must_use]
pub fn format_edit_dialog_issuer_title() -> &'static str {
    "Issuer"
}

/// `AdwEntryRow::set_title` for the Icon-hint row.
#[must_use]
pub fn format_edit_dialog_icon_hint_title() -> &'static str {
    "Icon hint"
}

/// Fixed Cancel button label (GNOME-convention `"Cancel"`).
#[must_use]
pub fn format_edit_dialog_cancel_label() -> &'static str {
    "Cancel"
}

/// Fixed Save button label (GNOME-convention `"Save"`).
#[must_use]
pub fn format_edit_dialog_save_label() -> &'static str {
    "Save"
}

/// Toast body for the [`PostEffectOutcome::Close`] arm.
#[must_use]
pub fn format_edit_dialog_success_toast(post_summary: Option<&AccountSummary>) -> String {
    match post_summary {
        Some(summary) => {
            let display = crate::account_row::summary_display_label(summary);
            format!("Edited {display}.")
        }
        None => "Edited.".to_string(),
    }
}

/// Messages handled by the future `EditDialogComponent`.
#[derive(Debug, Clone)]
pub enum EditDialogMsg {
    /// Label row text changed.
    LabelChanged(String),
    /// Issuer row text changed.
    IssuerChanged(String),
    /// Icon-hint row text changed.
    IconHintChanged(String),
    /// Inline Issuer-clear button pressed.
    IssuerClearClicked,
    /// Cancel button pressed.
    Cancel,
    /// Save button pressed.
    SubmitClicked,
    /// Parent broadcast: the synchronous pre-flight
    /// `find_duplicate_after_edit` resolved to a duplicate.
    DuplicateDetected(DuplicateMarker),
    /// Parent broadcast: the
    /// `gio::spawn_blocking Vault::mutate_and_save(|v|
    /// v.edit_account_metadata(...))` worker reported a typed
    /// failure or warning.
    WorkerCompleted(PostEffectOutcome),
    /// Parent-driven busy latch.
    SetBusy(bool),
}

/// Output variants the future `EditDialogComponent` emits back
/// to `AppModel`.
///
/// `PartialEq` / `Eq` are not derived because the carried
/// `AccountEdit` is not `Eq`.
#[derive(Debug, Clone)]
pub enum EditDialogOutput {
    /// User dismissed the dialog without saving.
    Cancel,
    /// Save pressed with a clean
    /// [`SubmitDispatch::DispatchEffect`] payload.
    Submit {
        /// Stable account identifier.
        account_id: AccountId,
        /// Assembled per-keystroke `AccountEdit`.
        edit: AccountEdit,
    },
}

/// Decide whether the Save button should be sensitive given the
/// dialog's cached state.
///
/// Save is sensitive iff:
/// 1. The dialog is not busy (no in-flight worker).
/// 2. The pre-edit `effect_ownership` slot is populated (the
///    dialog has the `(Vault, Store)` pair available — the
///    caller drives this through `SetBusy`).
/// 3. The assembled `AccountEdit` from
///    [`classify_edit_draft`] is non-empty.
/// 4. Every populated field validates clean (no inline
///    [`InlineError`] in the projection).
#[must_use]
pub fn format_edit_dialog_save_button_sensitive(state: &EditDialogState) -> bool {
    if state.is_busy() {
        return false;
    }
    let projection = classify_edit_draft(state);
    projection.save_sensitive()
}

/// Apply an inbound [`EditDialogMsg`] to `state` and return the
/// optional [`EditDialogOutput`] the widget layer forwards to
/// `AppModel`. `prior_account` is the dialog's pre-fill
/// `&Account` reference (only consulted by the `SubmitClicked`
/// arm for the cross-field validator).
pub fn apply_msg(
    state: &mut EditDialogState,
    msg: EditDialogMsg,
    prior_account: &Account,
) -> Option<EditDialogOutput> {
    match msg {
        EditDialogMsg::LabelChanged(text) => {
            state.set_label_buf(text);
            None
        }
        EditDialogMsg::IssuerChanged(text) => {
            state.set_issuer_buf(text);
            None
        }
        EditDialogMsg::IconHintChanged(text) => {
            state.set_icon_hint_buf(text);
            None
        }
        EditDialogMsg::IssuerClearClicked => {
            state.set_issuer_buf(String::new());
            None
        }
        EditDialogMsg::Cancel => {
            state.clear();
            Some(EditDialogOutput::Cancel)
        }
        EditDialogMsg::SubmitClicked => match classify_submit(state, prior_account) {
            SubmitOutcome::Validated(edit) => Some(EditDialogOutput::Submit {
                account_id: state.account_id(),
                edit,
            }),
            SubmitOutcome::EmptyEditReject | SubmitOutcome::InvalidEdit(_) => None,
        },
        EditDialogMsg::DuplicateDetected(marker) => {
            state.duplicate = Some(marker);
            None
        }
        EditDialogMsg::WorkerCompleted(outcome) => {
            state.worker_outcome = Some(outcome);
            None
        }
        EditDialogMsg::SetBusy(busy) => {
            state.set_busy(busy);
            None
        }
    }
}

/// Widget-bearing dialog for the upcoming
/// `AccountListOutput::OpenEditDialog` branch.
///
/// Mounts a vertical layout with the `Edit account` heading, a
/// `Editing <display>.` sub-title, three `AdwEntryRow` widgets
/// (Label / Issuer + inline clear button / Icon-hint slug)
/// inside an `AdwPreferencesGroup`, an inline-error label that
/// reflects the per-row validator outputs, a duplicate banner
/// (when set), a Cancel button, and a Save button gated by
/// [`format_edit_dialog_save_button_sensitive`].
///
/// The widget binding stops here for slice 4 — slice 5 wires
/// the `Vault::find_duplicate_after_edit` pre-flight and the
/// `gio::spawn_blocking Vault::mutate_and_save(|v|
/// v.edit_account_metadata(...))` worker dispatch in `AppModel`.
pub struct EditDialogComponent {
    /// Pre-fill snapshot retained on `self` so future message
    /// handlers can read the targeted account id and the
    /// display label.
    init: EditDialogInit,
    /// Live draft state.
    state: EditDialogState,
    /// Pre-edit `Account` reference required by
    /// [`apply_msg`]'s `SubmitClicked` arm. The widget mounting
    /// site clones the pre-fill `Account` off the live vault
    /// when launching the controller so the state machine can
    /// run `validate_account_edit` without holding a borrow on
    /// the vault.
    prior_account: Account,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for EditDialogComponent {
    type Init = (EditDialogInit, Account);
    type Input = EditDialogMsg;
    type Output = EditDialogOutput;

    view! {
        #[root]
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 12,
            set_hexpand: true,
            set_vexpand: true,

            gtk::Label {
                set_label: format_edit_dialog_title(),
                set_xalign: 0.0,
                add_css_class: "title-2",
            },
            gtk::Label {
                set_label: &format_edit_dialog_subtitle(&model.init.prior.display_label),
                set_xalign: 0.0,
                set_wrap: true,
            },

            adw::PreferencesGroup {
                #[name = "label_row"]
                add = &adw::EntryRow {
                    set_title: format_edit_dialog_label_title(),
                    // `Sender::send` is used instead of
                    // `ComponentSender::input` (which `.expect`s
                    // on a closed channel) so a stray callback
                    // after the controller is dropped — e.g.
                    // `lock_on_auto_lock_expiry` taking the
                    // dialog into `UnlockedDiscards.modal` while
                    // the widget still lives — is a benign no-op
                    // rather than a process abort. See
                    // `import_dialog`'s Cancel button for the
                    // canonical comment.
                    connect_changed[sender] => move |entry| {
                        let _ = sender
                            .input_sender()
                            .send(EditDialogMsg::LabelChanged(entry.text().to_string()));
                    },
                },

                #[name = "issuer_row"]
                add = &adw::EntryRow {
                    set_title: format_edit_dialog_issuer_title(),
                    connect_changed[sender] => move |entry| {
                        let _ = sender
                            .input_sender()
                            .send(EditDialogMsg::IssuerChanged(entry.text().to_string()));
                    },
                    // Inline issuer-clear button (parity with the
                    // TUI `Ctrl+U`).
                    add_suffix = &gtk::Button {
                        set_icon_name: "edit-clear-symbolic",
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        set_tooltip_text: Some("Clear issuer"),
                        connect_clicked[sender] => move |_| {
                            let _ = sender
                                .input_sender()
                                .send(EditDialogMsg::IssuerClearClicked);
                        },
                    },
                },

                #[name = "icon_hint_row"]
                add = &adw::EntryRow {
                    set_title: format_edit_dialog_icon_hint_title(),
                    connect_changed[sender] => move |entry| {
                        let _ = sender
                            .input_sender()
                            .send(EditDialogMsg::IconHintChanged(entry.text().to_string()));
                    },
                },
            },

            #[name = "label_error_label"]
            gtk::Label {
                set_xalign: 0.0,
                set_wrap: true,
                add_css_class: "error",
                #[watch]
                set_label: model
                    .state
                    .label_error()
                    .map_or("", |err| err.rendered.as_str()),
                #[watch]
                set_visible: model.state.label_error().is_some(),
            },

            #[name = "issuer_error_label"]
            gtk::Label {
                set_xalign: 0.0,
                set_wrap: true,
                add_css_class: "error",
                #[watch]
                set_label: model
                    .state
                    .issuer_error()
                    .map_or("", |err| err.rendered.as_str()),
                #[watch]
                set_visible: model.state.issuer_error().is_some(),
            },

            #[name = "icon_hint_error_label"]
            gtk::Label {
                set_xalign: 0.0,
                set_wrap: true,
                add_css_class: "error",
                #[watch]
                set_label: model
                    .state
                    .icon_hint_error()
                    .map_or("", |err| err.rendered.as_str()),
                #[watch]
                set_visible: model.state.icon_hint_error().is_some(),
            },

            #[name = "duplicate_banner"]
            gtk::Label {
                set_xalign: 0.0,
                set_wrap: true,
                add_css_class: "error",
                #[watch]
                set_label: &model
                    .state
                    .duplicate()
                    .map(|m| format!("duplicate_account: collides with {}.", m.display_label))
                    .unwrap_or_default(),
                #[watch]
                set_visible: model.state.duplicate().is_some(),
            },

            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 6,
                set_halign: gtk::Align::End,

                #[name = "cancel_button"]
                gtk::Button {
                    set_label: format_edit_dialog_cancel_label(),
                    connect_clicked[sender] => move |_| {
                        let _ = sender.input_sender().send(EditDialogMsg::Cancel);
                    },
                },

                #[name = "save_button"]
                gtk::Button {
                    set_label: format_edit_dialog_save_label(),
                    add_css_class: "suggested-action",
                    #[watch]
                    set_sensitive: format_edit_dialog_save_button_sensitive(&model.state),
                    connect_clicked[sender] => move |_| {
                        let _ = sender.input_sender().send(EditDialogMsg::SubmitClicked);
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
        let (init, prior_account) = init;
        let state = EditDialogState::new(&init);
        let model = EditDialogComponent {
            init,
            state,
            prior_account,
        };
        let widgets = view_output!();
        // Seed the three entry rows imperatively so the initial
        // `set_text` does not run through the `connect_changed`
        // round-trip on every redraw — keeping the cursor where
        // the user expects it across state changes that do not
        // reset the buffers (parity with `RenameDialogComponent`).
        widgets.label_row.set_text(model.state.label_buf());
        widgets.issuer_row.set_text(model.state.issuer_buf());
        widgets.icon_hint_row.set_text(model.state.icon_hint_buf());
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_msg(&mut self.state, msg, &self.prior_account) {
            // Ignore send failures: if `AppModel` has already
            // dropped the controller (e.g. window closed
            // mid-click), there's nothing left to dismiss.
            let _ = sender.output(output);
        }
    }
}
