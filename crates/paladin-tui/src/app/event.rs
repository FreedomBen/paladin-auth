// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppEvent` — union of every event the reducer can consume — and
//! `Effect` — the union of impure actions the reducer can request.
//!
//! See `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)".

use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use secrecy::SecretString;
use zeroize::Zeroizing;

use paladin_core::{
    AccountId, AccountKindInput, AccountSummary, Algorithm, ClipboardClearToken, Code,
    ImportConflict, ImportFormat, ImportReport, PaladinError, SettingPatch, Store,
    ValidatedAccount, ValidationWarning, Vault,
};

/// Events delivered to the reducer over the `mpsc<AppEvent>` channel.
///
/// `Input` and `Tick` arrive from long-lived producer threads;
/// `ClipboardClear` arrives from one-shot timer threads spawned by
/// clipboard auto-clear effects. `EffectResult` carries the outcome of
/// save-bearing effects (currently `Effect::Unlock`; more variants land
/// alongside their corresponding effects) back to the reducer so it can
/// update visible state.
#[derive(Debug)]
pub enum AppEvent {
    /// Terminal input (keystroke, resize, focus change, …) translated
    /// from a `crossterm` event.
    ///
    /// `at` is the monotonic instant the boundary sampled when the
    /// event was read from `crossterm`. The reducer feeds it into
    /// [`paladin_core::IdlePolicy::next_deadline`] to refresh the
    /// auto-lock idle deadline so the timer rebases on each keypress
    /// — per `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
    /// *"Idle is reset by any `AppEvent::Input`."*
    Input {
        /// The raw terminal event from `crossterm`.
        event: crossterm::event::Event,
        /// Monotonic clock sampled at input read time.
        at: Instant,
    },

    /// Wall-clock + monotonic tick.
    ///
    /// TOTP generation uses `wall_clock` (`SystemTime`); UI deadlines
    /// such as HOTP reveal expiry and the auto-lock idle deadline use
    /// `monotonic` (`Instant`).
    Tick {
        /// Real-world clock at tick time, for TOTP counter math.
        wall_clock: SystemTime,
        /// Monotonic clock for UI deadlines.
        monotonic: Instant,
    },

    /// Outcome of a side effect executed by the `run` boundary.
    EffectResult(EffectResult),

    /// Delayed clipboard auto-clear notification from a one-shot
    /// timer thread.
    ///
    /// The reducer asks
    /// `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::should_clear`
    /// whether the previously copied `value` still matches the current
    /// clipboard contents before issuing a clear.
    ClipboardClear {
        /// Token identifying which copy this clear is for.
        token: ClipboardClearToken,
        /// The previously copied bytes; checked against the current
        /// clipboard contents for the only-if-unchanged rule. Wrapped
        /// in [`Zeroizing`] so a stale-token reducer drop wipes the
        /// bytes before the backing allocation is freed.
        value: Zeroizing<Vec<u8>>,
    },
}

/// Outcome of an [`Effect`] executed by the `run` boundary, delivered
/// back to the reducer wrapped in [`AppEvent::EffectResult`].
///
/// Variants are added incrementally alongside the effects that produce
/// them; trust core rollback semantics for the carried `Vault` value
/// and let the reducer own non-core visible state (status text,
/// reveal windows, modal close/count panels, inline errors).
#[derive(Debug)]
pub enum EffectResult {
    /// Outcome of an [`Effect::Unlock`] attempt: either a fresh
    /// `(Vault, Store)` pair to install in [`crate::app::state::AppState::Unlocked`],
    /// or a [`PaladinError`]. `decrypt_failed` surfaces inline on the
    /// unlock screen; every other error replaces the unlock screen
    /// with [`crate::app::state::AppState::StartupError`].
    ///
    /// `opened_at` is the monotonic instant the executor sampled
    /// immediately after `Store::open` returned. On success the
    /// reducer feeds it into
    /// [`paladin_core::IdlePolicy::next_deadline`] to seed the new
    /// `Unlocked` state's auto-lock `idle_deadline`; on error it is
    /// unused.
    Unlock {
        /// The `Store::open` outcome carried back from the executor.
        result: Result<(Vault, Store), PaladinError>,
        /// Monotonic clock sampled immediately after `Store::open`.
        opened_at: Instant,
    },

    /// Outcome of an [`Effect::HotpAdvance`] attempt.
    ///
    /// On `Ok(code)` the reducer opens (or replaces) the
    /// [`crate::app::state::AppState::Unlocked::hotp_reveal`] slot keyed
    /// by `account_id`.
    ///
    /// On `Err(PaladinError::SaveDurabilityUnconfirmed)`, if the
    /// executor staged a code via `Vault::hotp_peek` before the advance
    /// (carried back as `staged_code: Some(_)`), the reducer opens (or
    /// replaces) the reveal slot with that staged code AND surfaces the
    /// committed-but-uncertain status in the status line — per
    /// `IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors":
    /// *"Durability-unconfirmed failures (`save_durability_unconfirmed`)
    /// reveal the new code and `Code.counter_used` label and report the
    /// committed-but-uncertain status in the status line — the user has
    /// the new code in hand even though durability is in question."*
    ///
    /// On any other `Err(...)` no reveal opens and the prior reveal
    /// slot (if any) is preserved — pre-commit failures
    /// (`save_not_committed`) have already been rolled back inside
    /// `Vault::hotp_advance` per `DESIGN.md` §4.3, and other error
    /// kinds are surfaced only through the status line.
    ///
    /// Results delivered while not on `Unlocked` (auto-lock, quit-in-
    /// flight, …) are discarded so the carried OTP digits drop without
    /// mutating non-`Unlocked` state.
    ///
    /// `completed_at` is the monotonic instant the executor sampled
    /// immediately after `Vault::hotp_advance` returned; the reducer
    /// feeds it into [`paladin_core::hotp_reveal_deadline`] to compute
    /// the reveal window's expiry instant.
    HotpAdvance {
        /// The account whose counter was advanced. Carried back on
        /// the result so the reveal slot stays keyed by the account
        /// the advance ran against, even if the user has since
        /// changed selection.
        account_id: AccountId,
        /// The `Vault::hotp_advance` outcome.
        result: Result<Code, PaladinError>,
        /// Pre-advance code computed by `Vault::hotp_peek` and held by
        /// the executor in zeroizing pending state. The executor
        /// publishes it back only on the two paths where the reveal
        /// should open: `result == Ok(_)` (redundant with the code
        /// inside `Ok`) and `result == Err(SaveDurabilityUnconfirmed)`
        /// (the staged-code mechanism that avoids requiring the error
        /// type to carry a `Code`). On every other `Err(...)` path the
        /// executor zeroizes the staged code and sets this to `None`.
        ///
        /// The reducer reads `staged_code` only on
        /// `Err(SaveDurabilityUnconfirmed)`; the `Ok` arm uses the
        /// code from `result` directly.
        ///
        /// Boxed so the rare durability-unconfirmed-with-staged-code
        /// path does not bloat every `EffectResult::HotpAdvance` —
        /// the common path (`None`) stays one pointer wide.
        staged_code: Option<Box<Code>>,
        /// Monotonic clock sampled immediately after the advance
        /// returned; used to derive the reveal-window deadline.
        completed_at: Instant,
    },

    /// Outcome of an [`Effect::CopyCode`] attempt.
    ///
    /// On `Ok(value)` (the executor's `arboard` write succeeded),
    /// while [`crate::app::state::AppState::Unlocked`] the reducer
    /// routes through
    /// [`paladin_core::ClipboardClearPolicy::schedule`] to seed
    /// `pending_clipboard_clear` with the issued token, the captured
    /// `value`, and the policy-returned deadline — per
    /// `IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear (per
    /// §6)": *"at copy time it stores the latest
    /// `ClipboardClearToken` plus the captured bytes in UI state."*
    /// When the vault's `clipboard_clear_enabled` is `false` the
    /// policy returns `None` and the reducer leaves
    /// `pending_clipboard_clear` untouched. A successful copy also
    /// clears any prior `status_line` (last-write-wins per the
    /// [`crate::app::state::StatusLine`] contract).
    ///
    /// On `Err(())` (the `arboard` backend failed) the reducer
    /// surfaces a [`crate::app::state::StatusLine::Error`] carrying
    /// [`crate::app::state::CLIPBOARD_WRITE_FAILED`] and leaves
    /// `pending_clipboard_clear` unchanged — per
    /// `IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors": *"Copy: show
    /// a status-line error if clipboard write fails; do not schedule
    /// auto-clear."* The `arboard` error is collapsed to `()` because
    /// the user-facing wording is fixed; the executor's failure
    /// envelope does not need to round-trip a typed error.
    ///
    /// Results delivered while not on `Unlocked` (auto-lock or quit
    /// in-flight) are discarded so the carried bytes drop without
    /// mutating non-`Unlocked` state.
    ///
    /// `completed_at` is the monotonic instant the executor sampled
    /// immediately after the clipboard write returned; the reducer
    /// feeds it into [`paladin_core::ClipboardClearPolicy::schedule`]
    /// so the auto-clear deadline rebases on the actual copy time.
    CopyCode {
        /// The account whose code was (or was meant to be) copied.
        /// Carried back so the reducer can correlate the result with
        /// the source account even if selection has since moved.
        account_id: AccountId,
        /// The clipboard-write outcome. `Ok(value)` carries the bytes
        /// the executor wrote to the OS clipboard, wrapped in
        /// [`Zeroizing`] so the bytes are wiped on drop (covers the
        /// non-`Unlocked` discard path where the carried result drops
        /// without seeding `pending_clipboard_clear`); `Err(())`
        /// indicates the `arboard` backend rejected the write.
        result: Result<Zeroizing<Vec<u8>>, ()>,
        /// Monotonic clock sampled immediately after the clipboard
        /// write returned; used to derive the auto-clear deadline via
        /// [`paladin_core::ClipboardClearPolicy::schedule`].
        completed_at: Instant,
    },

    /// Outcome of an [`Effect::Rename`] attempt.
    ///
    /// On `Ok(())` while [`crate::app::state::AppState::Unlocked`]
    /// with `Modal::Rename` open against `account_id`, the reducer
    /// closes the modal and publishes a
    /// [`crate::app::state::StatusLine::Confirmation`] derived from
    /// the post-rename label (looked up in the vault, which the
    /// executor has already mutated through
    /// `Vault::mutate_and_save`). On any `Err(...)` the modal stays
    /// open and the rendered error is stashed in
    /// [`crate::app::state::RenameModal::error`] — per
    /// `IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors" >
    /// "Add / remove / rename / settings saves": pre-commit failures
    /// (`save_not_committed`) are rolled back inside
    /// `Vault::mutate_and_save` so memory matches disk;
    /// durability-unconfirmed leaves the new label committed and
    /// surfaces the warning inline.
    ///
    /// Results delivered while not on `Unlocked`, while a different
    /// modal is open, or for an `account_id` that does not match the
    /// open rename modal are discarded so the carried error drops
    /// without mutating state.
    Rename {
        /// The account the rename targeted. Carried back so the
        /// reducer can correlate the result with the modal — the
        /// rename modal's `account_id` is the source of truth and
        /// the result is discarded on mismatch.
        account_id: AccountId,
        /// The `Vault::rename` + `Vault::save` outcome. `Ok(())`
        /// indicates the new label is persisted; the post-rename
        /// label lives on the `Vault::iter()` entry for `account_id`
        /// (the executor mutated the vault before posting back).
        result: Result<(), PaladinError>,
    },

    /// Outcome of an [`Effect::Remove`] attempt.
    ///
    /// On `Ok(display_label)` while [`crate::app::state::AppState::Unlocked`]
    /// with `Modal::Remove` open against `account_id`, the reducer
    /// closes the modal and publishes a
    /// [`crate::app::state::StatusLine::Confirmation`] derived from
    /// the carried display label — mirroring the CLI's "Removed
    /// {label}." idiom. The label is carried back because the
    /// executor has already removed the account from
    /// `Vault::iter()` by the time the reducer sees the result, so
    /// the reducer cannot look it up post-hoc.
    ///
    /// On any `Err(...)` the modal stays open and the rendered error
    /// is stashed in
    /// [`crate::app::state::RemoveModal::error`] — per
    /// `IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors" >
    /// "Add / remove / rename / settings saves": pre-commit failures
    /// (`save_not_committed`) are rolled back inside
    /// `Vault::mutate_and_save` so memory matches disk (the removed
    /// account is restored at its previous iteration position);
    /// durability-unconfirmed leaves the account removed in memory
    /// and surfaces the warning inline.
    ///
    /// Results delivered while not on `Unlocked`, while a different
    /// modal is open, or for an `account_id` that does not match the
    /// open remove modal are discarded so the carried error drops
    /// without mutating state.
    Remove {
        /// The account the remove targeted. Carried back so the
        /// reducer can correlate the result with the modal — the
        /// remove modal's `account_id` is the source of truth and
        /// the result is discarded on mismatch.
        account_id: AccountId,
        /// The `Vault::remove` + `Vault::save` outcome. `Ok(label)`
        /// indicates the account is gone from `Vault::iter()` and
        /// carries its pre-remove display label (`issuer:label` if
        /// the issuer was set, else just `label`) for the status-line
        /// confirmation; the executor captures it from the Account
        /// returned by `Vault::remove` before the value drops.
        result: Result<String, PaladinError>,
    },

    /// Outcome of an [`Effect::ApplySettings`] attempt.
    ///
    /// On `Ok(())` while [`crate::app::state::AppState::Unlocked`]
    /// with `Modal::Settings` open, the reducer closes the modal and
    /// publishes a [`crate::app::state::StatusLine::Confirmation`] —
    /// per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)":
    /// *"manual Add, URI Add, Remove, Rename, Export, Passphrase, and
    /// Settings close the modal and publish a status-line
    /// confirmation."*
    ///
    /// On any `Err(...)` the modal stays open and the rendered error
    /// is stashed in
    /// [`crate::app::state::SettingsModal::error`] — per the same
    /// plan's "Effect errors" > "Add / remove / rename / settings
    /// saves": pre-commit failures (`save_not_committed`) are rolled
    /// back inside `Vault::mutate_and_save` so memory matches disk;
    /// durability-unconfirmed leaves the new values committed and
    /// surfaces the warning inline; defensive setter validation
    /// failures (e.g. an out-of-range patch) also surface inline so
    /// the user can adjust and retry.
    ///
    /// Results delivered while not on `Unlocked`, while a different
    /// modal is open, or after the Settings modal closed are
    /// discarded so the carried error drops without mutating state.
    Settings {
        /// The `Vault::apply_setting_patch` + `Vault::save` outcome.
        /// `Ok(())` indicates every staged patch is persisted; on
        /// `Err(...)` core's `Vault::mutate_and_save` has already
        /// rolled back the in-memory snapshot on `save_not_committed`
        /// or left the new values committed on
        /// `save_durability_unconfirmed`.
        result: Result<(), PaladinError>,
    },

    /// Outcome of an [`Effect::Add`] attempt.
    ///
    /// The executor first runs
    /// [`paladin_core::validate_manual`] over the carried Manual-mode
    /// form fields; on validation failure the reducer surfaces the
    /// error inline in [`crate::app::state::AddModal::error`] and
    /// leaves the modal open. On a passing validation the executor
    /// calls [`paladin_core::Vault::find_duplicate`]; a collision
    /// returns the existing account's [`AccountSummary`] alongside
    /// the validated pending account so the reducer can render the
    /// `duplicate_account` rejection and stash the pending state for
    /// a follow-up "add anyway" confirmation — per
    /// `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    /// *"manual and URI duplicate collisions call
    /// `Vault::find_duplicate(&validated)` before mutation. A
    /// collision initially rejects with the existing account in the
    /// modal and offers an 'add anyway' confirmation."* When no
    /// duplicate is found the executor commits the new account
    /// through `Vault::mutate_and_save`; save errors map to
    /// [`AddFailure::Save`] and the modal stays open with the inline
    /// error per the plan's "Effect errors" >
    /// "Add / remove / rename / settings saves" rule.
    ///
    /// Results delivered while not on `Unlocked`, while a different
    /// modal is open, or after the Add modal closed are discarded so
    /// the carried [`ValidatedAccount`] / [`SecretString`] drop
    /// without mutating state.
    Add {
        /// The validation / duplicate-check / save outcome. `Ok` carries
        /// the inserted account's projection plus any non-fatal
        /// `ValidationWarning`s for the status-line confirmation; `Err`
        /// covers validation failure, duplicate collision, and save
        /// failure.
        result: Result<AddSuccess, AddFailure>,
    },

    /// Outcome of an [`Effect::AddFromClipboardQr`] attempt.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    /// *"QR imports call `Vault::import_accounts` with
    /// `ImportConflict::Skip` and report imported/skipped/warning
    /// counts plus any warning messages in the post-success counts
    /// panel."*
    ///
    /// On `Ok(QrImportSuccess)` the reducer renders the counts panel
    /// and any [`ImportWarning`](paladin_core::ImportWarning) messages
    /// inside the still-open Add modal — the success path lands with
    /// the counts-panel state slice.
    ///
    /// On `Err(QrImportFailure)` the reducer surfaces the rendered
    /// failure inline in [`crate::app::state::AddModal::error`] and
    /// leaves the modal open so the user can retry, per the plan's
    /// "Add modal" QR-import inline-error bullets:
    /// *"No-image, no-QR, and invalid-QR cases reject inline."*
    ///
    /// Results delivered while not on `Unlocked`, while a different
    /// modal is open, or after the Add modal closed are discarded so
    /// the carried `ImportReport` / [`PaladinError`] drops without
    /// mutating state.
    QrImport {
        /// The QR-import outcome. `Ok` carries the
        /// [`ImportReport`](paladin_core::ImportReport) for the counts
        /// panel; `Err` carries the inline-error reason.
        result: Result<QrImportSuccess, QrImportFailure>,
    },

    /// Outcome of an [`Effect::Import`] attempt.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Import:
    /// *"The modal reports imported/skipped/replaced/appended/warning
    /// counts plus validation-warning messages rendered through
    /// `paladin_core::format_validation_warning()` in a post-success
    /// counts panel."* and *"Importer errors … stay in the modal as
    /// inline errors and never mutate vault state."*
    ///
    /// On `Ok(ImportSuccess)` the reducer renders the counts panel
    /// (warnings + per-policy totals) inside the still-open Import
    /// modal — the counts-panel state slice lands alongside the success
    /// rendering.
    ///
    /// On `Err(ImportFailure)` the reducer surfaces the rendered
    /// failure inline in
    /// [`crate::app::state::ImportModal::error`] and leaves the modal
    /// open so the user can retry. Pre-commit save failures
    /// (`save_not_committed`) are rolled back inside
    /// `Vault::mutate_and_save`; durability-unconfirmed leaves the
    /// merge committed in memory and surfaces the warning inline. Both
    /// classes deliver here as [`ImportFailure`].
    ///
    /// Results delivered while not on
    /// [`crate::app::state::AppState::Unlocked`], while a different
    /// modal is open, or after the Import modal closed are discarded so
    /// the carried [`ImportReport`] / [`PaladinError`] drops without
    /// mutating state.
    Import {
        /// The import outcome. `Ok` carries the
        /// [`ImportReport`](paladin_core::ImportReport) for the counts
        /// panel; `Err` carries the rendered inline-error reason.
        result: Result<ImportSuccess, ImportFailure>,
    },

    /// Outcome of an [`Effect::Export`] attempt.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Export:
    /// *"On success the modal closes with a status-line confirmation
    /// showing the written path; `io_error`, `save_not_committed`,
    /// `save_durability_unconfirmed`, `invalid_passphrase`, and the
    /// refused overwrite gate stay in the modal as inline errors.
    /// Export does not mutate the vault, so there is no rollback path."*
    ///
    /// On `Ok(())` the reducer closes the modal and publishes a
    /// [`crate::app::state::StatusLine::Confirmation`] derived from the
    /// written destination path.
    ///
    /// On `Err(...)` the modal stays open and the rendered error is
    /// stashed in [`crate::app::state::ExportModal::error`]. Writer
    /// failures (`io_error`, `save_not_committed`,
    /// `save_durability_unconfirmed`) and encrypted-export passphrase
    /// validation (`invalid_passphrase`) all ride this channel.
    ///
    /// Results delivered while not on
    /// [`crate::app::state::AppState::Unlocked`], while a different
    /// modal is open, or after the Export modal closed are discarded —
    /// the carried [`PaladinError`] drops without mutating state.
    Export {
        /// The export outcome. `Ok(())` means the destination file is
        /// written; `Err` carries the writer / encryption error for
        /// inline rendering.
        result: Result<(), PaladinError>,
    },
}

/// Successful outcome of an [`Effect::Add`] attempt.
///
/// Carries the freshly inserted account's public projection plus any
/// non-fatal `ValidationWarning`s collected by
/// [`paladin_core::validate_manual`]. The reducer renders the
/// status-line confirmation from `summary` and includes any
/// `warnings` text per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
/// §6)" > Add: *"Validation warnings are rendered with
/// `paladin_core::format_validation_warning()` and do not block
/// creation: manual / URI additions include them in the status-line
/// confirmation."*
#[derive(Debug)]
pub struct AddSuccess {
    /// Non-secret projection of the inserted account.
    pub summary: AccountSummary,
    /// Non-fatal warnings captured at validation time (e.g.
    /// [`ValidationWarning::ShortSecret`]).
    pub warnings: Vec<ValidationWarning>,
}

/// Failure outcome of an [`Effect::Add`] attempt.
///
/// Distinguishes the three rejection paths the reducer must surface
/// differently:
///
/// - [`AddFailure::Validation`] — `validate_manual` returned an error
///   (label / issuer length, Base32 decode, digits / period bounds,
///   icon-hint slug). The reducer surfaces the rendered error inline
///   and leaves the modal open so the user can correct the field.
/// - [`AddFailure::Duplicate`] — validation passed but
///   `Vault::find_duplicate` matched an existing
///   `(secret, issuer, label)` triple. The reducer stashes the
///   `pending` validated account in
///   [`crate::app::state::AddModal::pending_duplicate_add`] and
///   surfaces a `duplicate_account` rejection naming the existing
///   account so a follow-up "add anyway" confirmation can insert the
///   pending account on the duplicate-allowed path.
/// - [`AddFailure::Save`] — `Vault::mutate_and_save` returned an
///   error (`save_not_committed` rolled back inside core,
///   `save_durability_unconfirmed` left committed in memory, or any
///   other `io_error`). Same inline-error surface as validation.
#[derive(Debug)]
pub enum AddFailure {
    /// `validate_manual` rejected the carried form fields.
    Validation(PaladinError),
    /// `Vault::find_duplicate` matched an existing account.
    Duplicate {
        /// Public projection of the colliding account already in the
        /// vault, used for the rejection message.
        existing: AccountSummary,
        /// Validated pending account stashed so a follow-up
        /// "add anyway" confirmation can insert it on the
        /// duplicate-allowed path. Carries the secret bytes which
        /// zeroize on drop if the user cancels.
        pending: Box<ValidatedAccount>,
    },
    /// `Vault::mutate_and_save` returned an error.
    Save(PaladinError),
}

/// Successful outcome of an [`Effect::AddFromClipboardQr`] attempt.
///
/// Carries the [`ImportReport`] returned by `Vault::import_accounts`
/// so the reducer can populate the post-success counts panel with the
/// `imported` / `skipped` / `warnings` totals and the rendered
/// warning messages (per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
/// §6)" > Add: *"QR imports call `Vault::import_accounts` with
/// `ImportConflict::Skip` and report imported/skipped/warning counts
/// plus any warning messages in the post-success counts panel."*).
#[derive(Debug)]
pub struct QrImportSuccess {
    /// Counts and warnings from `Vault::import_accounts`. The reducer
    /// reads the `imported` / `skipped` totals plus
    /// [`ImportReport::warnings`] for the counts-panel rendering;
    /// other fields (`replaced`, `appended`) are zero by construction
    /// because clipboard QR imports always use
    /// `ImportConflict::Skip`.
    pub report: ImportReport,
}

/// Failure outcome of an [`Effect::AddFromClipboardQr`] attempt.
///
/// Distinguishes the inline-error cases the reducer must render
/// differently in [`crate::app::state::AddModal::error`], per
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Add modal":
/// *"No-image, no-QR, and invalid-QR cases reject inline."*
///
/// - [`QrImportFailure::NoClipboardImage`] — `arboard` reported the
///   clipboard does not currently hold an image. The reducer surfaces
///   a stable user-facing string asking the user to copy a QR image
///   first.
/// - [`QrImportFailure::ImageDecodeFailure`] — `arboard` reported an
///   image is present but the bytes could not be decoded as a usable
///   raster. Same surface as `NoClipboardImage`, different wording.
/// - [`QrImportFailure::Import`] — wraps a [`PaladinError`] returned
///   by `paladin_core::import::qr_image_bytes` (oversized buffer
///   guard, zero decoded QRs, non-otpauth payload, validation /
///   parsing failures) or by `Vault::import_accounts` /
///   `Vault::mutate_and_save`. Rendered through
///   [`crate::app::state::render_error_message`] so the wording stays
///   in sync with the rest of the TUI's error surface.
#[derive(Debug)]
pub enum QrImportFailure {
    /// `arboard::Clipboard::get_image()` reported the clipboard does
    /// not hold an image (the user has not copied one, or the active
    /// clipboard target carries text-only data).
    NoClipboardImage,
    /// `arboard` returned an image but the bytes could not be decoded
    /// as a usable raster.
    ImageDecodeFailure,
    /// `paladin_core::import::qr_image_bytes` /
    /// `Vault::import_accounts` / `Vault::mutate_and_save` returned a
    /// [`PaladinError`] (oversized RGBA buffer, zero decoded QRs,
    /// non-otpauth payload, save-not-committed, etc.).
    Import(PaladinError),
}

/// Successful outcome of an [`Effect::Import`] attempt.
///
/// Carries the [`ImportReport`] returned by
/// [`paladin_core::Vault::import_accounts`] so the reducer can populate
/// the post-success counts panel with the `imported` / `skipped` /
/// `replaced` / `appended` totals plus the rendered validation
/// warnings — per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
/// Import: *"The modal reports imported/skipped/replaced/appended/
/// warning counts plus validation-warning messages rendered through
/// `paladin_core::format_validation_warning()` in a post-success
/// counts panel."*
#[derive(Debug)]
pub struct ImportSuccess {
    /// Counts and warnings from
    /// [`paladin_core::Vault::import_accounts`].
    pub report: ImportReport,
}

/// Failure outcome of an [`Effect::Import`] attempt.
///
/// Wraps the [`PaladinError`] returned by
/// [`paladin_core::import::from_file`] (importer / facade /
/// format-specific errors) or by
/// [`paladin_core::Vault::import_accounts`] /
/// [`paladin_core::Vault::mutate_and_save`] (merge / save / durability
/// errors). The reducer renders the failure through
/// [`crate::app::state::render_error_message`] so the wording matches
/// the rest of the TUI's error surface and stashes it in
/// [`crate::app::state::ImportModal::error`] per the plan's "Modals
/// (per §6)" > Import inline-error rule. Single-variant for now
/// (mirrors the CLI's `paladin: error: <text>` surface); subsequent
/// slices may introduce sub-variants if a class needs distinct UI
/// affordances.
#[derive(Debug)]
pub struct ImportFailure(pub PaladinError);

/// Side effects produced by the reducer.
///
/// Effects are executed by the `run` boundary (the only site allowed
/// to call impure core / clipboard / writer functions). Save-bearing
/// effects send an `AppEvent::EffectResult(…)` back through the same
/// `mpsc` channel; clipboard timer effects send a delayed
/// [`AppEvent::ClipboardClear`].
///
/// Variants are added incrementally as the reducer comes online.
#[derive(Debug)]
pub enum Effect {
    /// Tear down the terminal and exit the process cleanly.
    Quit,
    /// Attempt to unlock the encrypted vault at `path` with the
    /// supplied passphrase. The executor calls `Store::open(path,
    /// VaultLock::Encrypted(passphrase))` and sends the outcome back
    /// through an `AppEvent::EffectResult(...)` so the reducer can
    /// transition to `Unlocked` on success or surface `decrypt_failed`
    /// inline on failure. The passphrase zeroizes on drop because
    /// `SecretString` owns its bytes through `secrecy`.
    Unlock {
        /// The vault path to open.
        path: PathBuf,
        /// Typed passphrase, taken from the Unlock screen's zeroizing
        /// buffer.
        passphrase: SecretString,
    },
    /// Wipe the OS clipboard if it still holds the bytes the front
    /// end captured at copy time.
    ///
    /// Emitted by the reducer when an `AppEvent::ClipboardClear` wake
    /// arrives whose token matches the current
    /// `PendingClipboardClear` token (the stale-token / no-pending
    /// cases short-circuit in the reducer, never reaching the
    /// executor). The executor reads the live clipboard, asks
    /// [`paladin_core::ClipboardClearPolicy::should_clear`], and
    /// writes empty only when the comparison returns `true` — per
    /// `IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear (per
    /// §6)": *"on wake, it … reads the current clipboard, asks
    /// `ClipboardClearPolicy::should_clear`, and writes empty when
    /// the policy returns `true`."*
    ///
    /// The actual `arboard` read/write lands with the clipboard
    /// adapter slice; until then the executor consumes the bytes and
    /// returns `Continue`.
    ClearClipboard {
        /// The bytes the copy effect wrote to the clipboard; compared
        /// for byte-equality with the live clipboard contents inside
        /// the executor. Wrapped in [`Zeroizing`] so the bytes are
        /// wiped on drop once the executor finishes the
        /// only-if-unchanged comparison.
        value: Zeroizing<Vec<u8>>,
    },
    /// Advance the HOTP counter on the selected account, persist the
    /// new counter to disk, and surface the generated code through an
    /// `AppEvent::EffectResult(EffectResult::HotpAdvance(...))` so the
    /// reducer can open a reveal window.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` §6 and the reducer-tests
    /// "HOTP `n` triggers a `HotpAdvance` effect" rule: the reducer
    /// emits this effect when `Char('n')` is pressed on Unlocked with
    /// a HOTP-kind account selected and no modal open. The reducer
    /// itself never mutates `hotp_reveal` — only the matching
    /// `EffectResult::HotpAdvance` can. The executor delegates to
    /// `Vault::hotp_advance(store, account_id, SystemTime::now())`
    /// which advances the counter, persists via `Vault::save`, and
    /// returns the freshly generated `Code`.
    HotpAdvance {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
        /// The HOTP account whose counter should advance.
        account_id: AccountId,
    },
    /// Copy the currently selected account's code to the OS clipboard.
    ///
    /// Per the Keybindings table in `IMPLEMENTATION_PLAN_03_TUI.md`:
    /// *"`Enter` — Copy selected code (TOTP: current; HOTP: visible
    /// only)."* The reducer emits this effect when `KeyCode::Enter` is
    /// pressed on `Unlocked` with `Focus::List`, no modal open, no
    /// help overlay, and either a TOTP account selected or an HOTP
    /// account selected whose code is currently visible in
    /// `hotp_reveal`. The HOTP-visible-only gating is enforced at the
    /// reducer level so the executor only ever sees emissions for
    /// codes the user can actually see.
    ///
    /// The actual clipboard write, auto-clear scheduling, and
    /// `ClipboardClearPolicy::should_clear` wiring land with the
    /// clipboard adapter slice (see `IMPLEMENTATION_PLAN_03_TUI.md`
    /// "Clipboard auto-clear"); until then the executor consumes the
    /// variant and returns `Continue` without touching the
    /// clipboard.
    CopyCode {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
        /// The account whose code should be copied. For TOTP the
        /// executor generates a fresh code from the live wall clock;
        /// for HOTP the executor reads the most recently revealed
        /// code (guaranteed to exist by reducer-level gating).
        account_id: AccountId,
    },
    /// Rename the selected account's label and persist the change.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
    /// Rename: *"Confirm wraps `Vault::rename(id, new_label, now)`
    /// in `Vault::mutate_and_save` with the trimmed input regardless
    /// of whether it equals the current label."* The reducer emits
    /// this effect when `Enter` is pressed on `Modal::Rename` with a
    /// draft that passes [`paladin_core::validate_label`] — empty /
    /// out-of-range drafts surface inline inside the modal without
    /// reaching the executor.
    ///
    /// The executor wires the call to `Vault::rename` inside
    /// `Vault::mutate_and_save` and posts the outcome back through
    /// an `AppEvent::EffectResult(EffectResult::Rename { … })`
    /// in a subsequent slice; until then the executor consumes the
    /// variant and returns `Continue`.
    Rename {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
        /// The account whose label should be replaced. Snapshotted by
        /// the reducer at modal-open time so a later selection change
        /// does not redirect the rename mid-flight.
        account_id: AccountId,
        /// The trimmed, pre-validated new label. The executor re-runs
        /// `validate_label` through `Vault::rename` for defense in
        /// depth; the trim is idempotent so this string is the value
        /// that ends up persisted on success.
        new_label: String,
    },
    /// Remove the selected account and persist the change.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
    /// Remove: *"confirmation modal. On confirm, wraps `Vault::remove`
    /// in `Vault::mutate_and_save`."* The reducer emits this effect
    /// when `Enter` is pressed on `Modal::Remove`; the modal carries
    /// the snapshotted `account_id` so a subsequent selection /
    /// search-filter change does not redirect the remove mid-confirm.
    ///
    /// The executor wires the call to `Vault::remove` inside
    /// `Vault::mutate_and_save` and posts the outcome back through an
    /// `AppEvent::EffectResult(EffectResult::Remove { … })` in a
    /// subsequent slice; until then the executor consumes the variant
    /// and returns `Continue`.
    Remove {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
        /// The account to remove. Snapshotted by the reducer at
        /// modal-open time so a later selection change does not
        /// redirect the remove mid-flight.
        account_id: AccountId,
    },
    /// Apply Settings modal's pending changes to the live vault and
    /// persist them.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
    /// Settings: *"The modal accumulates pending edits in modal-local
    /// state and only commits on Confirm: pending values are applied
    /// through the same setters (`set_auto_lock_*`,
    /// `set_clipboard_clear_*`) inside a single
    /// `Vault::mutate_and_save` transaction."* The reducer diffs the
    /// modal's pending fields against the live
    /// [`paladin_core::VaultSettings`] at Confirm time and emits this
    /// effect carrying exactly the changed [`SettingPatch`]es (empty
    /// pending == no diff == no effect; the reducer closes the modal
    /// without invoking save in that case).
    ///
    /// The executor wires each patch through
    /// `Vault::apply_setting_patch` inside a single
    /// `Vault::mutate_and_save` so all changes commit atomically: a
    /// pre-commit failure (`save_not_committed`) snaps every staged
    /// value back to its pre-attempt state and a
    /// `save_durability_unconfirmed` leaves them committed in memory.
    /// The outcome is posted back through an
    /// `AppEvent::EffectResult(EffectResult::Settings { … })`.
    ApplySettings {
        /// The current vault path; the executor uses it to verify the
        /// path the effect was emitted against in case the user has
        /// navigated away.
        path: PathBuf,
        /// The diffed list of patches to apply, in declaration order
        /// of `SettingsFocus` (auto-lock toggle → auto-lock spinner →
        /// clipboard toggle → clipboard spinner). The reducer only
        /// emits this effect when `patches` is non-empty; the
        /// executor still tolerates an empty list as a defensive
        /// no-op that posts back `Ok(())`.
        patches: Vec<SettingPatch>,
    },
    /// Insert a Manual-mode account into the vault and persist it.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    /// *"Manual entries route through
    /// `paladin_core::validate_manual(input, submit_time)`. … Each
    /// submit captures one `submit_time` used for account
    /// validation/import timestamps."* The reducer emits this effect
    /// when `Enter` is pressed on `Modal::Add` with
    /// [`crate::app::state::AddMode::Manual`] active; the executor
    /// builds a `paladin_core::AccountInput` from the carried fields,
    /// samples one `SystemTime::now()` as `submit_time`, runs
    /// `validate_manual`, performs duplicate detection, and wraps the
    /// `Vault::add` call in `Vault::mutate_and_save`. The validation,
    /// duplicate-detect, and save wiring land with a subsequent slice;
    /// until then the executor consumes the variant without emitting
    /// an `AppEvent`.
    ///
    /// `secret` is the typed Base32 buffer taken from
    /// [`crate::app::state::AddModal::manual_secret`] via
    /// [`crate::prompt::PassphraseBuffer::take`]; the buffer zeroizes
    /// in the same step. `secret` then zeroizes on drop because
    /// `SecretString` owns its bytes through `secrecy`. `issuer` is
    /// carried as `String`; the executor turns an empty string into
    /// `Option::None` per `validate_manual`'s contract. The
    /// `period_secs` and `counter` fields ride together; the executor
    /// picks one based on `kind` per `DESIGN.md` §5
    /// (rejected-on-cross-kind is enforced inside `validate_manual`).
    Add {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
        /// Manual-mode label buffer at submit time. The executor
        /// passes this verbatim to `validate_manual`, which trims and
        /// enforces the §4.1 length rules.
        label: String,
        /// Manual-mode issuer buffer at submit time. Empty means
        /// "no issuer" — the executor maps empty to `None` before
        /// calling `validate_manual`.
        issuer: String,
        /// Base32 secret taken from the modal's
        /// [`crate::prompt::PassphraseBuffer`] at submit time;
        /// zeroizes on drop.
        secret: SecretString,
        /// HMAC algorithm at submit time.
        algorithm: Algorithm,
        /// OTP digit count at submit time (6 / 7 / 8 per the §4.1
        /// bounds).
        digits: u8,
        /// Account kind selector at submit time; selects
        /// `period_secs` (TOTP) or `counter` (HOTP) inside the
        /// executor.
        kind: AccountKindInput,
        /// TOTP period at submit time; consulted only when
        /// `kind == Totp`.
        period_secs: u32,
        /// HOTP starting counter at submit time; consulted only when
        /// `kind == Hotp`.
        counter: u64,
        /// Free-form icon-hint token at submit time; the executor
        /// runs it through
        /// [`paladin_core::parse_icon_hint_token`] before building
        /// the `AccountInput`.
        icon_hint_text: String,
    },
    /// Insert a URI-mode account into the vault and persist it.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    /// *"URI mode is a single text field; on submit the entered
    /// string is passed to `paladin_core::parse_otpauth(uri,
    /// submit_time)`, and on success the resulting `ValidatedAccount`
    /// shares the manual path's duplicate-detection, 'add anyway'
    /// override, and `Vault::mutate_and_save` insertion."* The
    /// reducer emits this effect when `Enter` is pressed on
    /// `Modal::Add` with [`crate::app::state::AddMode::Uri`] active;
    /// the executor calls
    /// [`paladin_core::parse_otpauth`] over the carried URI bytes,
    /// samples one `SystemTime::now()` as `submit_time`, performs
    /// duplicate detection, and wraps the `Vault::add` call in
    /// `Vault::mutate_and_save`. The result is delivered on the
    /// shared [`EffectResult::Add`] channel so the reducer's
    /// duplicate / validation / save handling covers Manual and URI
    /// alike — only the parsing front end differs.
    ///
    /// `uri` is the typed text buffer taken from
    /// [`crate::app::state::AddModal::uri_text`] via
    /// [`crate::prompt::PassphraseBuffer::take`]; the buffer zeroizes
    /// in the same step. `uri` then zeroizes on drop because
    /// `SecretString` owns its bytes through `secrecy` — the URI
    /// text is secret-bearing because the URI embeds the Base32
    /// secret.
    AddFromUri {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
        /// URI text buffer taken from the modal's
        /// [`crate::prompt::PassphraseBuffer`] at submit time;
        /// zeroizes on drop because `SecretString` owns its bytes
        /// through `secrecy`. Passed verbatim to
        /// [`paladin_core::parse_otpauth`] which trims and enforces
        /// the §4.4 URI grammar.
        uri: SecretString,
    },
    /// Insert a previously-validated account on the duplicate-allowed
    /// path and persist it.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    /// *"A collision initially rejects with the existing account in
    /// the modal and offers an 'add anyway' confirmation that inserts
    /// the pending validated account on the duplicate-allowed path
    /// (CLI parity with `--allow-duplicate`, appending a new account
    /// that shares the `(secret, issuer, label)` triple)."*
    ///
    /// The reducer emits this effect when `Enter` is pressed on
    /// `Modal::Add` while
    /// [`crate::app::state::AddModal::pending_duplicate_add`] is
    /// `Some`. The pending state was stashed by the prior
    /// [`EffectResult::Add`] `Err(AddFailure::Duplicate { .. })` and
    /// carries the already-validated account; the executor inserts it
    /// via `Vault::add` inside `Vault::mutate_and_save` without
    /// re-running `validate_manual` / `parse_otpauth` or
    /// `Vault::find_duplicate`. `Vault::add` assigns a fresh
    /// [`paladin_core::AccountId`] so the new account is distinct from
    /// the colliding existing account. The outcome is delivered on the
    /// shared [`EffectResult::Add`] channel so the success / save-error
    /// rendering covers Manual, URI, and "add anyway" alike.
    AddAnyway {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
        /// The validated account taken out of
        /// [`crate::app::state::AddModal::pending_duplicate_add`].
        /// Carries the secret bytes; zeroizes on drop if the closure
        /// rolls back or the executor is torn down before the call
        /// reaches `Vault::add`.
        validated: Box<ValidatedAccount>,
    },
    /// Read a QR code from the OS clipboard image, decode any encoded
    /// `otpauth://` URIs, and import the resulting accounts into the
    /// vault.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
    /// *"Clipboard images are read through
    /// `arboard::Clipboard::get_image()`, whose `ImageData` already
    /// carries raw RGBA8 bytes plus width/height; the TUI calls
    /// `paladin_core::import::qr_image_bytes(width, height, rgba_bytes,
    /// submit_time)` per the §4.7 signature, which takes `import_time`
    /// directly rather than the `ImportOptions` accepted by
    /// `import::from_file` / `import::from_bytes`. Per DESIGN §4.6, the
    /// Add modal checks `width * height * 4` against
    /// `paladin_core::QR_RGBA_MAX_BYTES` before allocating or copying
    /// the clipboard buffer and surfaces the same `validation_error`
    /// (`field: "qr_image"`, `reason: "image_too_large"`) inline that
    /// the core decoder would return for an oversized buffer."*
    ///
    /// The reducer emits this effect when `Enter` is pressed on
    /// `Modal::Add` with [`crate::app::state::AddMode::Qr`] active.
    /// QR import has no modal-local form fields — the executor reads
    /// the live clipboard image through `arboard`, performs the
    /// oversized-buffer guard, runs `qr_image_bytes`, and calls
    /// `Vault::import_accounts` with `ImportConflict::Skip` inside
    /// `Vault::mutate_and_save`.
    AddFromClipboardQr {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
    },
    /// Import accounts from a source file into the live vault.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Import:
    /// *"The selected `paladin_core::import::from_file` call returns
    /// `Vec<ValidatedAccount>`; on success,
    /// `Vault::import_accounts(accounts, conflict, import_time)` is
    /// called inside `Vault::mutate_and_save` with the user's policy
    /// and the same `import_time` passed to `ImportOptions`."*
    ///
    /// The reducer emits this effect when `Enter` is pressed on
    /// `Modal::Import` after the (optional)
    /// [`paladin_core::classify_paladin_import_precheck`] gate has
    /// returned `NoPrompt` (or after the encrypted-Paladin passphrase
    /// prompt resolved). The executor calls
    /// [`paladin_core::import::from_file`] over `source_path` with the
    /// carried [`paladin_core::ImportOptions`] and one
    /// `SystemTime::now()` sample as `import_time`; on success it
    /// commits the resulting [`paladin_core::ValidatedAccount`] batch
    /// through [`paladin_core::Vault::import_accounts`] wrapped in
    /// [`paladin_core::Vault::mutate_and_save`] so the merge and save
    /// are atomic. The outcome rides on [`EffectResult::Import`].
    ///
    /// `format` mirrors [`paladin_core::ImportOptions::format`]:
    /// [`None`] auto-detects via [`paladin_core::detect`] inside the
    /// facade, [`Some`] forces the matching format and lets the facade
    /// sanity-check the input shape.
    ///
    /// `paladin_passphrase` is consumed only when the facade dispatches
    /// to [`ImportFormat::Paladin`]; it lands in subsequent slices once
    /// the precheck wiring is in place. The auto-detect first slice
    /// passes [`None`].
    Import {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away.
        path: PathBuf,
        /// Source file path passed to
        /// [`paladin_core::import::from_file`].
        source_path: PathBuf,
        /// Forced format override (per
        /// [`paladin_core::ImportOptions::format`]). [`None`] means
        /// auto-detect via [`paladin_core::detect`].
        format: Option<ImportFormat>,
        /// Per-batch merge policy passed to
        /// [`paladin_core::Vault::import_accounts`].
        conflict: ImportConflict,
        /// Bundle passphrase for encrypted-Paladin imports; consumed
        /// only when the facade dispatches to
        /// [`ImportFormat::Paladin`]. The auto-detect first slice
        /// passes [`None`].
        paladin_passphrase: Option<SecretString>,
    },
    /// Write the live vault to `target_path` as a plaintext
    /// `otpauth://` JSON list or an encrypted Paladin bundle.
    ///
    /// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Export:
    /// *"format selector (plaintext `otpauth://` JSON list or encrypted
    /// Paladin bundle) and a destination path field. ... Writes go
    /// through `paladin_core::write_secret_file_atomic`. ... Export
    /// does not mutate the vault, so there is no rollback path."*
    ///
    /// The reducer emits this effect when `Enter` is pressed on
    /// `Modal::Export` after the (plaintext) unencrypted-secrets
    /// confirmation gate clears or the (encrypted) twice-prompt
    /// passphrase entry resolves and the overwrite-confirmation gate
    /// has cleared. The executor renders the bytes through
    /// [`paladin_core::export::otpauth_list`] (plaintext) or
    /// [`paladin_core::export::encrypted`] (encrypted) and hands them
    /// off to [`paladin_core::write_secret_file_atomic`].
    ///
    /// `format` selects which renderer is invoked. `passphrase` is
    /// consumed only when `format == ExportFormat::Encrypted`; the
    /// plaintext path passes [`None`].
    Export {
        /// The current vault path; the executor uses it for error
        /// reporting and to verify the path the effect was emitted
        /// against in case the user has navigated away. The vault is
        /// read-only on the export path — no `Vault::save` is issued.
        path: PathBuf,
        /// Destination file path passed to
        /// [`paladin_core::write_secret_file_atomic`].
        target_path: PathBuf,
        /// Output format. [`crate::app::state::ExportFormat::Plaintext`]
        /// routes through [`paladin_core::export::otpauth_list`];
        /// [`crate::app::state::ExportFormat::Encrypted`] routes through
        /// [`paladin_core::export::encrypted`].
        format: crate::app::state::ExportFormat,
        /// Bundle passphrase for encrypted exports, taken from the
        /// modal's zeroizing twice-prompt buffer at submit time; the
        /// buffer zeroizes in the same step. Consumed only when
        /// `format == ExportFormat::Encrypted`; the plaintext path
        /// passes [`None`].
        passphrase: Option<SecretString>,
    },
}
