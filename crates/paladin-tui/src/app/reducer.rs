// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure reducer: `(state, event) → (state, Vec<Effect>)`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)" this
//! function is the only place the TUI's state transitions live, so
//! every transition is unit-testable without a terminal. Impure
//! side effects are returned as [`Effect`] values and executed by
//! the `run` boundary; the reducer itself never touches the
//! filesystem, clipboard, or core save paths.

use std::time::Instant;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use paladin_core::{
    classify_paladin_import_precheck, format_plaintext_export_warning, format_validation_warning,
    hotp_reveal_deadline, summary_display_label, validate_account_edit, validate_icon_hint_slug,
    validate_label, AccountEdit, AccountId, AccountKindInput, AccountSummary, Algorithm,
    ClipboardClearPolicy, ClipboardClearToken, Code, IconHintInput, IdlePolicy, PaladinError,
    PaladinImportPrecheck, SettingPatch, Store, Vault,
};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::app::event::{
    AddFailure, AppEvent, EditFailure, Effect, EffectResult, ImportFailure, ImportSuccess,
    QrImportSuccess,
};
use crate::app::state::{
    compute_idle_deadline, format_account_display_label, format_duplicate_account_message,
    format_qr_import_failure, initial_selection, render_error_message, AddManualFocus, AddModal,
    AddMode, AppState, ChordLeader, CountsPanel, EditFocus, EditIconHintSelector, EditModal,
    EditPrior, ExportFormat, ExportModal, Focus, HotpReveal, ImportModal, Modal, PassphraseModal,
    PassphraseSubFlow, PendingClipboardClear, PendingDuplicateAdd, QrExportFocus, QrExportModal,
    QrExportPage, QrSaveFocus, QrSaveFormat, QrSaveStep, QrSaveSubFlow, RemoveModal, RenameModal,
    SettingsFocus, SettingsModal, StatusLine, CLIPBOARD_WRITE_FAILED, NO_ACCOUNT_SELECTED,
};
use crate::prompt::PassphraseBuffer;
use crate::search::{filtered_account_ids, select_after_search};

/// Apply one event to the current state and return the new state plus
/// any side effects.
///
/// This slice covers the global quit keybindings, the Unlock screen's
/// passphrase-input handling, and the [`EffectResult::Unlock`] outcome
/// from `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings (initial v0.1)",
/// "Focus model", and "Startup / vault modes":
///
/// * `Ctrl-C` quits on any screen.
/// * `Esc` quits on `StartupError`, `Unlock`, and `CreateVault` at
///   `ChooseMode` (per-step Esc behavior on `CreateVault` lives in
///   [`reduce_create_vault_input`]: `ConfirmPlaintext` /
///   `EnterPassphrase` return to `ChooseMode` rather than quitting).
/// * `q` quits on `StartupError`, and on `CreateVault` at
///   `ChooseMode` / `ConfirmPlaintext`. On `Unlock` and on
///   `CreateVault::EnterPassphrase` it is a valid passphrase
///   character and is appended to the focused buffer.
/// * On `Unlock`, printable characters (no Ctrl/Alt modifier) append
///   to the passphrase buffer, `Backspace` pops the last character,
///   and `Enter` with a non-empty buffer emits a single
///   [`Effect::Unlock`] and clears the buffer in place.
/// * [`EffectResult::Unlock`] on `Unlock` transitions to `Unlocked` on
///   success, surfaces `decrypt_failed` inline on `Err(DecryptFailed)`,
///   and transitions to `StartupError` for any other open error.
///   Results delivered while not on `Unlock` (e.g. auto-locked between
///   submit and result) are discarded and the carried `(Vault, Store)`
///   drops.
///
/// `AppEvent::Tick` additionally drives the auto-lock `Unlocked →
/// Locked` transition when the current `Unlocked` state carries an
/// `idle_deadline` and [`paladin_core::IdlePolicy::is_expired`]
/// returns `true` for the tick's `monotonic` instant — per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)". The carried
/// `Vault` / `Store` drop in place on the transition. Ticks with no
/// deadline, before the deadline, or on non-`Unlocked` screens are
/// passthrough.
///
/// [`AppEvent::ClipboardClear`] on [`AppState::Locked`] with a
/// matching-token `pending_clipboard_clear` hands the wipe off as an
/// [`Effect::ClearClipboard`] and clears the pending slot — per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
/// *"A clipboard auto-clear timer scheduled before lock survives
/// lock and still fires only-if-unchanged."* Stale-token wakes,
/// `None`-pending wakes, and wakes on non-`Locked` states are
/// passthrough at this slice; the `Unlocked` branch lands alongside
/// the clipboard adapter / copy slice.
///
/// `AppEvent::Input` additionally rebases the auto-lock idle deadline
/// on the event's `at` timestamp when the post-dispatch state is
/// `Unlocked`, per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
/// *"Idle is reset by any `AppEvent::Input`."* The rebase delegates to
/// [`compute_idle_deadline`] so the plaintext / disabled `None` cases
/// fall out of [`paladin_core::IdlePolicy::should_arm`] rather than a
/// local copy of the rule.
#[must_use]
pub fn reduce(state: AppState, event: AppEvent) -> (AppState, Vec<Effect>) {
    match event {
        AppEvent::Input { event: input, at } => {
            let (state, effects) = reduce_input(state, &input);
            (refresh_idle_deadline_on_input(state, at), effects)
        }
        AppEvent::EffectResult(result) => reduce_effect_result(state, result),
        AppEvent::Tick { monotonic, .. } => {
            let state = maybe_auto_lock(state, monotonic);
            (
                maybe_close_expired_hotp_reveal(state, monotonic),
                Vec::new(),
            )
        }
        AppEvent::ClipboardClear { token, .. } => reduce_clipboard_clear_wake(state, token),
    }
}

/// Transition `Unlocked → Locked` when the auto-lock idle deadline has
/// expired at `now`. Other states and `Unlocked` with no / unexpired
/// deadline pass through unchanged. The expiry decision delegates to
/// [`paladin_core::IdlePolicy::is_expired`] so the TUI shares
/// monotonic-clock comparison semantics with the GUI.
///
/// On lock the `Vault`, `Store`, search query, open HOTP reveal
/// window, open modal, and idle deadline drop in place through the
/// variant change; any pending clipboard auto-clear is carried onto
/// the resulting [`AppState::Locked`] so the timer thread's wake
/// event still finds pending state to act on. Per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
/// *"Locking discards the Vault / Store, open HOTP reveal windows,
/// the search query, and any modal while retaining the resolved
/// vault path…"* and *"A clipboard auto-clear timer scheduled before
/// lock survives lock and still fires only-if-unchanged."*
fn maybe_auto_lock(state: AppState, now: Instant) -> AppState {
    let AppState::Unlocked {
        idle_deadline: Some(deadline),
        ..
    } = &state
    else {
        return state;
    };
    if !IdlePolicy::is_expired(*deadline, now) {
        return state;
    }
    let AppState::Unlocked {
        path,
        pending_clipboard_clear,
        ..
    } = state
    else {
        unreachable!("variant checked immediately above");
    };
    AppState::Locked {
        path,
        pending_clipboard_clear,
    }
}

/// Close the HOTP reveal window on [`AppState::Unlocked`] when the
/// monotonic `now` has reached the reveal's deadline. Other states
/// and `Unlocked` with no reveal or an unexpired deadline pass
/// through unchanged.
///
/// Chained after [`maybe_auto_lock`] in the [`AppEvent::Tick`] arm of
/// [`reduce`], so a tick that fires both the auto-lock idle deadline
/// and the reveal deadline transitions to [`AppState::Locked`] (which
/// has no reveal slot) without this helper running — the variant
/// change is the source of truth for "lock discards open HOTP reveal
/// windows" (`docs/IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)").
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests > HOTP reveal window":
/// *"Reveal closes after the deadline returned by
/// `paladin_core::policy::hotp_reveal::deadline(now)`
/// (`paladin_core::HOTP_REVEAL_SECS` measured on a monotonic
/// clock)."* The boundary is `now >= deadline`, mirroring
/// [`paladin_core::IdlePolicy::is_expired`].
fn maybe_close_expired_hotp_reveal(mut state: AppState, now: Instant) -> AppState {
    if let AppState::Unlocked {
        hotp_reveal: slot @ Some(_),
        ..
    } = &mut state
    {
        let deadline = slot.as_ref().expect("matched Some above").deadline;
        if now >= deadline {
            *slot = None;
        }
    }
    state
}

/// Handle a delayed [`AppEvent::ClipboardClear`] wake from a one-shot
/// timer thread.
///
/// On [`AppState::Locked`] with a matching-token
/// `pending_clipboard_clear`, hands the wipe off to the executor as
/// [`Effect::ClearClipboard`] carrying the captured bytes from state
/// and clears `pending_clipboard_clear` so a duplicate wake is a
/// no-op. The live-clipboard read and
/// [`paladin_core::ClipboardClearPolicy::should_clear`] decision live
/// in the executor — per `docs/IMPLEMENTATION_PLAN_03_TUI.md`
/// "Clipboard auto-clear (per §6)": *"on wake, it ignores stale
/// tokens, reads the current clipboard, asks
/// `ClipboardClearPolicy::should_clear`, and writes empty when the
/// policy returns `true`."*
///
/// Stale tokens (a fresher copy has issued a new token and replaced
/// the pending state) and a `None` pending state are both no-ops:
/// state unchanged, no effect.
///
/// The pre-lock (`Unlocked`) branch lands alongside the clipboard
/// adapter / copy slice; this slice only covers the `Locked` path so
/// the lock-survival contract of bullet 7 holds end-to-end.
fn reduce_clipboard_clear_wake(
    state: AppState,
    event_token: ClipboardClearToken,
) -> (AppState, Vec<Effect>) {
    let AppState::Locked {
        path,
        pending_clipboard_clear: Some(pending),
    } = state
    else {
        return (state, Vec::new());
    };
    if pending.token != event_token {
        return (
            AppState::Locked {
                path,
                pending_clipboard_clear: Some(pending),
            },
            Vec::new(),
        );
    }
    (
        AppState::Locked {
            path,
            pending_clipboard_clear: None,
        },
        vec![Effect::ClearClipboard {
            value: pending.value,
        }],
    )
}

/// Rebase [`AppState::Unlocked::idle_deadline`] on `at` when the
/// post-Input state is `Unlocked`. No-op for every other variant —
/// non-`Unlocked` screens carry no idle deadline.
fn refresh_idle_deadline_on_input(mut state: AppState, at: Instant) -> AppState {
    if let AppState::Unlocked {
        ref mut idle_deadline,
        ref vault,
        ..
    } = state
    {
        *idle_deadline = compute_idle_deadline(at, vault);
    }
    state
}

/// Apply an `EffectResult` delivered by the `run` boundary.
fn reduce_effect_result(state: AppState, result: EffectResult) -> (AppState, Vec<Effect>) {
    match result {
        EffectResult::Unlock { result, opened_at } => {
            reduce_unlock_result(state, result, opened_at)
        }
        EffectResult::CreateVault { result, opened_at } => {
            reduce_create_vault_result(state, result, opened_at)
        }
        EffectResult::HotpAdvance {
            account_id,
            result,
            staged_code,
            completed_at,
        } => reduce_hotp_advance_result(state, account_id, result, staged_code, completed_at),
        EffectResult::CopyCode {
            account_id,
            result,
            completed_at,
        } => reduce_copy_code_result(state, account_id, result, completed_at),
        EffectResult::CopyNextCode {
            account_id,
            result,
            completed_at,
            seconds_until_valid,
        } => reduce_copy_next_code_result(
            state,
            account_id,
            result,
            completed_at,
            seconds_until_valid,
        ),
        EffectResult::Rename { account_id, result } => {
            reduce_rename_result(state, account_id, result)
        }
        EffectResult::EditAccountMetadata {
            path,
            account_id,
            result,
        } => reduce_edit_account_metadata_result(state, &path, account_id, result),
        EffectResult::Remove { account_id, result } => {
            reduce_remove_result(state, account_id, result)
        }
        EffectResult::Settings { result } => reduce_settings_result(state, result),
        EffectResult::Add { result } => reduce_add_result(state, result),
        EffectResult::QrImport { result } => reduce_qr_import_result(state, result),
        EffectResult::Import { result } => reduce_import_result(state, result),
        EffectResult::Export { result } => reduce_export_result(state, result),
        EffectResult::QrExport { result } => reduce_qr_export_result(state, result),
        EffectResult::Passphrase { result } => reduce_passphrase_result(state, result),
    }
}

/// Handle the outcome of an [`Effect::Export`].
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors" > Export:
/// *"writer errors (`io_error`, `save_not_committed`,
/// `save_durability_unconfirmed`, `invalid_passphrase`) and the refused
/// overwrite gate stay in the Export modal as inline errors. Export
/// does not mutate the vault, so save-error rollback does not apply."*
///
/// On `Err(...)` while `Modal::Export` is open the reducer renders the
/// typed error through [`render_error_message`] and stashes it on
/// [`crate::app::state::ExportModal::error`]; the modal stays open so
/// the user can fix the destination, passphrase, or filesystem
/// condition and retry. The status line is left untouched — every
/// writer / passphrase error stays inline on the modal. Because the
/// executor never calls [`paladin_core::Vault::save`] on the Export
/// path, the live vault and on-disk source bundle are byte-stable
/// across both Err and Ok arms.
///
/// Results delivered while not on `Unlocked` or while a different
/// modal is open are discarded.
///
/// On `Ok(())` while `Modal::Export` is open the reducer closes the
/// modal (`modal = None`) and publishes a
/// [`StatusLine::Confirmation`] referencing the written destination
/// path — per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
/// "Successful modal outcomes": *"manual Add, URI Add, Remove,
/// Rename, Export, Passphrase, and Settings close the modal and
/// publish a status-line confirmation."* Closing the modal drops the
/// `ExportModal` value, which runs `PassphraseBuffer::Drop` on the
/// (already drained) `new_passphrase` / `confirm_passphrase` buffers,
/// covering the "modal close" axis of the sensitive-buffer zeroize
/// contract.
fn reduce_export_result(
    mut state: AppState,
    result: Result<(), PaladinError>,
) -> (AppState, Vec<Effect>) {
    if let AppState::Unlocked {
        ref mut modal,
        ref mut status_line,
        ..
    } = state
    {
        if let Some(Modal::Export(export)) = modal.as_mut() {
            match result {
                Ok(()) => {
                    let display = export.path_text.trim().to_owned();
                    *modal = None;
                    *status_line =
                        Some(StatusLine::Confirmation(format!("Exported to {display}.")));
                }
                Err(err) => {
                    export.error = Some(render_error_message(&err));
                }
            }
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::QrExport`].
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
/// QR Export: *"Save-as-PNG / Save-as-SVG route through
/// `write_secret_file_atomic` (0600) ... pre-commit /
/// durability-unconfirmed save errors and writer failures stay in
/// the modal as inline errors."*
///
/// On `Ok(target_path)` while `Modal::QrExport` is open with an
/// active save sub-flow: the path replaces
/// [`QrExportModal::last_save_path`] (replace-only — a second
/// successful save overwrites this slot per the plan's
/// "Inline success-path slot is replace-only" rule), the sub-flow
/// closes, focus returns to the Page-2 button row, and no
/// status-line confirmation is published (the inline success path
/// surfaces in the modal body, not the status line).
///
/// On `Err(...)` the modal stays open with the sub-flow still
/// active and the rendered error is stashed in
/// [`QrSaveSubFlow::error`] so the user can fix the destination,
/// filesystem condition, or retry. Because the executor never calls
/// [`paladin_core::Vault::save`] on the QR export path, the live
/// vault is byte-stable across both arms.
///
/// Results delivered while not on `Unlocked` or while a different
/// modal is open are discarded.
fn reduce_qr_export_result(
    mut state: AppState,
    result: Result<std::path::PathBuf, PaladinError>,
) -> (AppState, Vec<Effect>) {
    if let AppState::Unlocked { ref mut modal, .. } = state {
        if let Some(Modal::QrExport(qr)) = modal.as_mut() {
            match result {
                Ok(target_path) => {
                    qr.last_save_path = Some(target_path);
                    qr.save_sub_flow = None;
                    qr.focus = QrExportFocus::SavePngButton;
                    qr.error = None;
                }
                Err(err) => {
                    let rendered = render_error_message(&err);
                    if let Some(sub) = qr.save_sub_flow.as_mut() {
                        sub.error = Some(rendered);
                    } else {
                        qr.error = Some(rendered);
                    }
                }
            }
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::CopyCode`].
///
/// On `Ok(value)` while [`AppState::Unlocked`], route through
/// [`paladin_core::ClipboardClearPolicy::schedule`] to obtain a
/// monotonic token and the policy-derived deadline; when
/// `clipboard.clear_enabled = true` the policy returns
/// `Some((token, deadline))` and the reducer seeds
/// `pending_clipboard_clear` with the captured bytes. When the
/// setting is disabled the policy returns `None` and
/// `pending_clipboard_clear` is left untouched — per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear (per §6)":
/// *"at copy time it stores the latest `ClipboardClearToken` plus the
/// captured bytes in UI state."* The successful arm also clears any
/// prior `status_line` (last-write-wins, matching
/// [`reduce_hotp_advance_result`]'s Ok contract).
///
/// On `Err(())` set a status-line error using
/// [`CLIPBOARD_WRITE_FAILED`] and leave `pending_clipboard_clear`
/// unchanged — per the same plan's "Effect errors" rule: *"Copy:
/// show a status-line error if clipboard write fails; do not
/// schedule auto-clear."*
///
/// On any non-`Unlocked` state (auto-lock fired between the copy
/// effect and the result, quit-in-flight, …) the result is dropped
/// so the carried bytes drop without mutating state.
///
/// `account_id` is carried back on the result for symmetry with
/// [`EffectResult::HotpAdvance`] and to keep future hooks
/// (per-account confirmations, focus moves) self-contained; the
/// scheduling decision itself does not depend on it.
fn reduce_copy_code_result(
    mut state: AppState,
    _account_id: AccountId,
    result: Result<Zeroizing<Vec<u8>>, ()>,
    completed_at: Instant,
) -> (AppState, Vec<Effect>) {
    if let AppState::Unlocked {
        ref vault,
        ref mut pending_clipboard_clear,
        ref mut status_line,
        ..
    } = state
    {
        match result {
            Ok(value) => {
                if let Some((token, deadline)) =
                    ClipboardClearPolicy::schedule(completed_at, vault.settings())
                {
                    *pending_clipboard_clear = Some(PendingClipboardClear {
                        token,
                        value,
                        deadline,
                    });
                }
                *status_line = None;
            }
            Err(()) => {
                *status_line = Some(StatusLine::Error(CLIPBOARD_WRITE_FAILED.to_string()));
            }
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::CopyNextCode`].
///
/// Mirrors [`reduce_copy_code_result`] for the clipboard-write
/// success / failure routing — `Ok(value)` arms
/// [`paladin_core::ClipboardClearPolicy`] identically so the
/// auto-clear deadline rebases on `completed_at`; `Err(())` surfaces
/// the same [`CLIPBOARD_WRITE_FAILED`] status-line error. The
/// distinguishing behavior is the success-path
/// [`StatusLine::Confirmation`]: per DESIGN §6 the reducer publishes
/// `next code copied, valid in {seconds_until_valid}s` so the user
/// sees both the action confirmation and the seconds remaining in
/// the current window — `None` falls through to a generic
/// confirmation (defensive: the executor only carries `None` when
/// its guards short-circuited before sampling the wall-clock, which
/// is unreachable for reducer-emitted effects).
fn reduce_copy_next_code_result(
    mut state: AppState,
    _account_id: AccountId,
    result: Result<Zeroizing<Vec<u8>>, ()>,
    completed_at: Instant,
    seconds_until_valid: Option<u32>,
) -> (AppState, Vec<Effect>) {
    if let AppState::Unlocked {
        ref vault,
        ref mut pending_clipboard_clear,
        ref mut status_line,
        ..
    } = state
    {
        match result {
            Ok(value) => {
                if let Some((token, deadline)) =
                    ClipboardClearPolicy::schedule(completed_at, vault.settings())
                {
                    *pending_clipboard_clear = Some(PendingClipboardClear {
                        token,
                        value,
                        deadline,
                    });
                }
                *status_line = Some(StatusLine::Confirmation(match seconds_until_valid {
                    Some(secs) => crate::app::state::format_next_code_copied(secs),
                    None => "next code copied".to_string(),
                }));
            }
            Err(()) => {
                *status_line = Some(StatusLine::Error(CLIPBOARD_WRITE_FAILED.to_string()));
            }
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::HotpAdvance`].
///
/// On `Ok(code)` while [`AppState::Unlocked`], open (or replace) the
/// `hotp_reveal` slot keyed by `account_id` and clear any prior
/// status-line note (last-write-wins per the [`StatusLine`] contract:
/// a successful advance dismisses the previous failure note). The
/// reveal deadline is computed from `completed_at` via
/// [`paladin_core::hotp_reveal_deadline`]. Any prior reveal slot is
/// dropped in place — its `SecretString` zeroizes on drop per the
/// "Sensitive UI buffers" guarantee.
///
/// On `Err(PaladinError::SaveDurabilityUnconfirmed)` with a
/// `staged_code: Some(_)`, open (or replace) the reveal slot using the
/// staged code AND surface a status-line note built from
/// [`render_error_message`] — per `docs/IMPLEMENTATION_PLAN_03_TUI.md`
/// "Effect errors":
/// *"Durability-unconfirmed failures (`save_durability_unconfirmed`)
/// reveal the new code and `Code.counter_used` label and report the
/// committed-but-uncertain status in the status line — the user has the
/// new code in hand even though durability is in question."*
///
/// On any other `Err(...)` (or `Err(SaveDurabilityUnconfirmed)` with
/// `staged_code: None`) no reveal opens; the prior reveal slot (if any)
/// is preserved and a status-line error is surfaced via
/// [`render_error_message`] — per the same "Effect errors" section:
/// *"Pre-commit save failures (`save_not_committed`) leave the
/// in-memory counter and reveal state unchanged ... and surface a
/// status-line error. ... All other failures show a status-line error
/// and leave the previous reveal state unchanged."* Pre-commit
/// failures have already been rolled back inside `Vault::hotp_advance`,
/// so the in-memory vault remains consistent with disk.
///
/// On any non-`Unlocked` state the result is discarded so the carried
/// OTP digits drop without mutating the current state.
fn reduce_hotp_advance_result(
    mut state: AppState,
    account_id: AccountId,
    result: Result<Code, PaladinError>,
    staged_code: Option<Box<Code>>,
    completed_at: Instant,
) -> (AppState, Vec<Effect>) {
    if let AppState::Unlocked {
        hotp_reveal: slot,
        status_line,
        ..
    } = &mut state
    {
        match result {
            Ok(code) => {
                *slot = Some(HotpReveal {
                    account_id,
                    counter_used: code.counter_used.unwrap_or(0),
                    code: SecretString::from(code.code),
                    deadline: hotp_reveal_deadline(completed_at),
                });
                *status_line = None;
            }
            Err(PaladinError::SaveDurabilityUnconfirmed) => {
                if let Some(code) = staged_code {
                    let code = *code;
                    *slot = Some(HotpReveal {
                        account_id,
                        counter_used: code.counter_used.unwrap_or(0),
                        code: SecretString::from(code.code),
                        deadline: hotp_reveal_deadline(completed_at),
                    });
                }
                *status_line = Some(StatusLine::Error(render_error_message(
                    &PaladinError::SaveDurabilityUnconfirmed,
                )));
            }
            Err(err) => {
                *status_line = Some(StatusLine::Error(render_error_message(&err)));
            }
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::Rename`].
///
/// On `Ok(())` while [`AppState::Unlocked`] with `Modal::Rename` open
/// against the result's `account_id`, close the modal and publish a
/// [`StatusLine::Confirmation`] derived from the post-rename label —
/// the executor has already mutated the vault via
/// `Vault::mutate_and_save`, so `vault.iter()` carries the new
/// label. Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)":
/// *"manual Add, URI Add, Remove, Rename, Export, Passphrase, and
/// Settings close the modal and publish a status-line confirmation."*
///
/// On `Err(...)` the modal stays open and the rendered error is
/// stashed in `RenameModal.error` — per the same plan's "Effect
/// errors" section: *"Pre-commit save failures (`save_not_committed`)
/// are rolled back by `Vault::mutate_and_save` so memory matches
/// disk ... and the modal stays open with the inline error so the
/// user can retry. Durability-unconfirmed save errors leave the new
/// state in memory ... and are shown as committed-but-uncertain."*
/// `save_not_committed`, `save_durability_unconfirmed`, and any
/// other error variant share this surfacing path; the specific
/// rollback semantics belong to `Vault::mutate_and_save`.
///
/// Deliveries that arrive after the user navigated away (auto-lock,
/// non-`Unlocked` state), after the modal closed or was replaced, or
/// whose `account_id` does not match the open rename modal are
/// discarded so the carried error drops without mutating state.
fn reduce_rename_result(
    mut state: AppState,
    account_id: AccountId,
    result: Result<(), PaladinError>,
) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref vault,
        ref mut modal,
        ref mut status_line,
        ..
    } = state
    else {
        return (state, Vec::new());
    };

    let Some(Modal::Rename(rename)) = modal.as_mut() else {
        return (state, Vec::new());
    };
    if rename.account_id != account_id {
        return (state, Vec::new());
    }

    match result {
        Ok(()) => {
            let label = vault
                .iter()
                .find(|a| a.id() == account_id)
                .map(|a| a.label().to_owned());
            // Defensive: if the account is no longer in the vault
            // (race with a remove, or a core invariant break), keep
            // the modal open without overwriting state so the user
            // can dismiss deliberately rather than silently losing
            // the buffer.
            let Some(label) = label else {
                return (state, Vec::new());
            };
            *modal = None;
            *status_line = Some(StatusLine::Confirmation(format!("Renamed to {label}")));
        }
        Err(err) => {
            rename.error = Some(render_error_message(&err));
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::EditAccountMetadata`].
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Edit"
/// `EffectResult::EditAccountMetadata` Ok-arm: when the executor
/// reports success, the reducer closes the Edit modal and publishes
/// `StatusLine::Confirmation(format!("Edited {}.",
/// summary_display_label(&summary)))` against the post-edit
/// [`paladin_core::AccountSummary`] carried in the Ok payload.
///
/// `Err(EditFailure::Duplicate { existing })` keeps the modal open
/// and surfaces the inline `duplicate_account` message via
/// [`format_duplicate_account_message`]; there is **no edit-anyway
/// override** per the locked spec — only revising the row buffers
/// can clear it.
///
/// `Err(EditFailure::Save(err))` keeps the modal open and surfaces
/// the rendered save error inline through [`render_error_message`]
/// — `save_not_committed` is rolled back inside
/// `Vault::mutate_and_save` so memory matches disk, while
/// `save_durability_unconfirmed` leaves the new state in memory and
/// surfaces the warning inline.
///
/// Deliveries that arrive after the user navigated away (off-
/// `Unlocked`), against a mismatched live vault path, with no Edit
/// modal open, or for a mismatched `account_id` are silently
/// discarded so the carried payload drops without mutating state.
fn reduce_edit_account_metadata_result(
    mut state: AppState,
    expected_path: &std::path::Path,
    account_id: AccountId,
    result: Result<AccountSummary, EditFailure>,
) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref path,
        ref mut modal,
        ref mut status_line,
        ..
    } = state
    else {
        return (state, Vec::new());
    };
    if path != expected_path {
        return (state, Vec::new());
    }
    let Some(Modal::Edit(edit)) = modal.as_mut() else {
        return (state, Vec::new());
    };
    if edit.account_id != account_id {
        return (state, Vec::new());
    }

    match result {
        Ok(summary) => {
            *modal = None;
            *status_line = Some(StatusLine::Confirmation(format!(
                "Edited {}.",
                summary_display_label(&summary),
            )));
        }
        Err(EditFailure::Duplicate { existing }) => {
            edit.error = Some(format_duplicate_account_message(&existing));
        }
        Err(EditFailure::Save(err)) => {
            edit.error = Some(render_error_message(&err));
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::Remove`].
///
/// On `Ok(display_label)` while [`AppState::Unlocked`] with
/// `Modal::Remove` open against the result's `account_id`, close the
/// modal and publish a [`StatusLine::Confirmation`] built from the
/// carried display label — mirroring the CLI's "Removed {label}."
/// idiom. The executor has already removed the account from
/// `Vault::iter()` through `Vault::mutate_and_save` by the time the
/// reducer sees the result, so the label must come back through the
/// `EffectResult` rather than from a post-hoc vault lookup. Per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)": *"manual Add,
/// URI Add, Remove, Rename, Export, Passphrase, and Settings close
/// the modal and publish a status-line confirmation."*
///
/// On `Err(...)` the modal stays open and the rendered error is
/// stashed in `RemoveModal.error` — per the same plan's "Effect
/// errors" section: *"Pre-commit save failures (`save_not_committed`)
/// are rolled back by `Vault::mutate_and_save` so memory matches
/// disk (Remove restores the removed account at its previous
/// position) ... and the modal stays open with the inline error so
/// the user can retry. Durability-unconfirmed save errors leave the
/// new state in memory ... and are shown as committed-but-uncertain."*
/// `save_not_committed`, `save_durability_unconfirmed`, and any
/// other error variant share this surfacing path; the specific
/// rollback semantics belong to `Vault::mutate_and_save`.
///
/// Deliveries that arrive after the user navigated away (auto-lock,
/// non-`Unlocked` state), after the modal closed or was replaced, or
/// whose `account_id` does not match the open remove modal are
/// discarded so the carried error drops without mutating state.
fn reduce_remove_result(
    mut state: AppState,
    account_id: AccountId,
    result: Result<String, PaladinError>,
) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref mut modal,
        ref mut status_line,
        ..
    } = state
    else {
        return (state, Vec::new());
    };

    let Some(Modal::Remove(remove)) = modal.as_mut() else {
        return (state, Vec::new());
    };
    if remove.account_id != account_id {
        return (state, Vec::new());
    }

    match result {
        Ok(label) => {
            *modal = None;
            *status_line = Some(StatusLine::Confirmation(format!("Removed {label}.")));
        }
        Err(err) => {
            remove.error = Some(render_error_message(&err));
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::ApplySettings`].
///
/// On `Ok(())` while [`AppState::Unlocked`] with `Modal::Settings`
/// open, close the modal and publish a [`StatusLine::Confirmation`]
/// — per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)": *"manual
/// Add, URI Add, Remove, Rename, Export, Passphrase, and Settings
/// close the modal and publish a status-line confirmation."*
///
/// On any `Err(...)` the modal stays open and the rendered error is
/// stashed in `SettingsModal.error` — per the same plan's "Effect
/// errors" > "Add / remove / rename / settings saves" section.
/// `save_not_committed`, `save_durability_unconfirmed`, and any
/// validation / I/O error variant share this surfacing path; the
/// specific rollback semantics belong to `Vault::mutate_and_save`.
///
/// Deliveries that arrive after the user navigated away (auto-lock,
/// non-`Unlocked` state) or after the Settings modal closed are
/// discarded so the carried error drops without mutating state.
fn reduce_settings_result(
    mut state: AppState,
    result: Result<(), PaladinError>,
) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref mut modal,
        ref mut status_line,
        ..
    } = state
    else {
        return (state, Vec::new());
    };

    let Some(Modal::Settings(settings)) = modal.as_mut() else {
        return (state, Vec::new());
    };

    match result {
        Ok(()) => {
            *modal = None;
            *status_line = Some(StatusLine::Confirmation("Settings updated.".to_string()));
        }
        Err(err) => {
            settings.error = Some(render_error_message(&err));
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an `Effect::PassphraseSet` /
/// `PassphraseChange` / `PassphraseRemove`.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Passphrase:
/// *"The transition methods (`set_passphrase` / `change_passphrase` /
/// `remove_passphrase`) save themselves through `&Store` and handle
/// their own pre-commit rollback per DESIGN §4.5 (the in-memory
/// mode/key reverts to its previous state on `save_not_committed` and
/// is replaced on `save_durability_unconfirmed`); the TUI surfaces
/// both failure classes inline, re-reads `Vault::is_encrypted()` to
/// refresh its visible vault-mode flag (unchanged on
/// `save_not_committed`, changed on `save_durability_unconfirmed`),
/// and otherwise leaves the in-memory vault as the core left it."*
///
/// On `Ok(())` the reducer closes the modal and publishes a
/// [`StatusLine::Confirmation`] — per the plan's "Successful modal
/// outcomes": *"manual Add, URI Add, Remove, Rename, Export,
/// Passphrase, and Settings close the modal and publish a status-line
/// confirmation."* Sub-flow-specific confirmation wording lands with
/// the dedicated Ok-arm slice.
///
/// On any `Err(...)` the modal stays open and the rendered error is
/// stashed in [`crate::app::state::PassphraseModal::error`]; the
/// reducer does **not** mutate the vault (core owns the rollback
/// semantics on the `save_not_committed` / `save_durability_unconfirmed`
/// classes) and does **not** inspect private key / cache material —
/// the visible vault-mode flag is read back through
/// [`paladin_core::Vault::is_encrypted`] alongside other view-only
/// projections. The status line is left untouched so every
/// transition / writer / save error stays inline on the modal.
///
/// Deliveries that arrive after the user navigated away (auto-lock,
/// non-`Unlocked` state) or after the Passphrase modal closed are
/// discarded so the carried error drops without mutating state.
fn reduce_passphrase_result(
    mut state: AppState,
    result: Result<(), PaladinError>,
) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref mut modal,
        ref mut status_line,
        ..
    } = state
    else {
        return (state, Vec::new());
    };

    let Some(Modal::Passphrase(passphrase)) = modal.as_mut() else {
        return (state, Vec::new());
    };

    match result {
        Ok(()) => {
            *modal = None;
            *status_line = Some(StatusLine::Confirmation("Passphrase updated.".to_string()));
        }
        Err(err) => {
            passphrase.error = Some(render_error_message(&err));
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::Add`] / [`Effect::AddFromUri`] /
/// [`Effect::AddAnyway`].
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
/// *"manual and URI duplicate collisions call
/// `Vault::find_duplicate(&validated)` before mutation. A collision
/// initially rejects with the existing account in the modal and
/// offers an 'add anyway' confirmation that inserts the pending
/// validated account on the duplicate-allowed path."* The
/// duplicate-rejection path stashes the pending validated account in
/// [`AddModal::pending_duplicate_add`] so the follow-up confirmation
/// can insert it without re-running validation; the inline error
/// names the existing account via [`format_duplicate_account_message`].
///
/// Validation and save failures (the other two [`AddFailure`]
/// variants) surface inline through [`render_error_message`] and
/// leave the modal open per the plan's "Effect errors" >
/// "Add / remove / rename / settings saves" rule.
///
/// The success path closes the modal so the user returns to the list
/// view; the status-line confirmation wording (with
/// [`paladin_core::format_validation_warning`] text) lands with the
/// dedicated "Manual / URI Add status-line confirmations include
/// validation warning text" slice.
///
/// Deliveries that arrive after the user navigated away
/// (non-`Unlocked` state) or after the Add modal closed are
/// discarded so the carried [`paladin_core::ValidatedAccount`] (with
/// its `SecretString`) drops without mutating state.
fn reduce_add_result(
    mut state: AppState,
    result: Result<crate::app::event::AddSuccess, AddFailure>,
) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref mut modal,
        ref mut status_line,
        ..
    } = state
    else {
        return (state, Vec::new());
    };

    let Some(Modal::Add(add)) = modal.as_mut() else {
        return (state, Vec::new());
    };

    match result {
        Ok(success) => {
            // Close the Add modal so the user returns to the list
            // view and publish the `Added <display>.` status-line
            // confirmation, mirroring the CLI's
            // `Added Acme:alice (id:abcdef01).` idiom (the TUI omits
            // the disambiguator because no `id:` selector is used in
            // the keyboard UI). Any
            // `paladin_core::ValidationWarning`s collected by
            // `validate_manual` are rendered through
            // `format_validation_warning` and appended after the
            // confirmation as `warning: <text>` — multiple warnings
            // are joined with `; ` so the status line stays single-
            // line per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
            // §6)" > Add.
            let display = format_account_display_label(&success.summary);
            let confirmation = if success.warnings.is_empty() {
                format!("Added {display}.")
            } else {
                let rendered = success
                    .warnings
                    .iter()
                    .map(format_validation_warning)
                    .collect::<Vec<_>>()
                    .join("; ");
                format!("Added {display}. warning: {rendered}")
            };
            *status_line = Some(StatusLine::Confirmation(confirmation));
            *modal = None;
        }
        Err(AddFailure::Duplicate { existing, pending }) => {
            add.error = Some(format_duplicate_account_message(&existing));
            add.pending_duplicate_add = Some(Box::new(PendingDuplicateAdd {
                existing,
                validated: pending,
            }));
        }
        Err(AddFailure::Validation(err) | AddFailure::Save(err)) => {
            add.error = Some(render_error_message(&err));
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::AddFromClipboardQr`].
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Add modal":
/// *"No-image, no-QR, and invalid-QR cases reject inline."* On any
/// `Err(...)` the Add modal stays open and the rendered failure is
/// stashed in [`AddModal::error`] via [`format_qr_import_failure`] so
/// the user can retry.
///
/// On `Ok(QrImportSuccess { report })` the modal stays open in
/// [`AddMode::Qr`] and the carried [`paladin_core::ImportReport`]
/// seeds the post-success counts panel: `imported` / `skipped` totals
/// flow through verbatim, and each [`paladin_core::ImportWarning`] is
/// rendered through [`paladin_core::format_validation_warning`] up
/// front so the view layer only needs to display the already-formatted
/// strings. Any prior inline error from a failed retry is cleared so
/// the user does not see a stale rejection alongside the success
/// panel. The status line is left untouched — counts panel owns
/// success rendering for QR-add per the plan's "Add modal" >
/// *"Clipboard QR import uses `ImportConflict::Skip` and reports
/// imported / skipped counts."* and *"QR-add validation warnings are
/// rendered through `paladin_core::format_validation_warning()` in the
/// post-success counts panel."*.
///
/// Results delivered while not on `Unlocked`, while a different modal
/// is open, or after the Add modal closed are discarded so the
/// carried [`paladin_core::ImportReport`] / [`PaladinError`] drops
/// without mutating state.
fn reduce_qr_import_result(
    mut state: AppState,
    result: Result<QrImportSuccess, crate::app::event::QrImportFailure>,
) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked { ref mut modal, .. } = state else {
        return (state, Vec::new());
    };

    let Some(Modal::Add(add)) = modal.as_mut() else {
        return (state, Vec::new());
    };

    match result {
        Ok(QrImportSuccess { report }) => {
            let warnings = report
                .warnings
                .iter()
                .map(|w| format_validation_warning(&w.warning))
                .collect();
            add.counts_panel = Some(CountsPanel {
                imported: report.imported,
                skipped: report.skipped,
                replaced: report.replaced,
                appended: report.appended,
                warnings,
            });
            add.error = None;
        }
        Err(failure) => {
            add.error = Some(format_qr_import_failure(&failure));
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::Import`].
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Import:
/// on success the modal renders a post-success counts panel populated
/// from the carried [`paladin_core::ImportReport`] — the four merge
/// totals (`imported` / `skipped` / `replaced` / `appended`) flow
/// through verbatim, and each [`paladin_core::ImportWarning`] is
/// rendered through [`paladin_core::format_validation_warning`] up
/// front so the view layer only needs to display the already-formatted
/// strings. Any prior inline error from a failed retry is cleared so
/// the user does not see stale rejection text alongside the success
/// panel.
///
/// On failure the rendered importer / save error stashes inline so the
/// user can adjust and retry. Pre-commit save failures are rolled
/// back inside [`paladin_core::Vault::mutate_and_save`] — the executor
/// reports them through the same [`ImportFailure`] channel as
/// importer-side errors, so this arm does not need a separate rollback
/// step on the in-memory vault.
///
/// Results delivered while not on
/// [`AppState::Unlocked`], while a different modal is open, or after
/// the Import modal closed are discarded so the carried
/// [`paladin_core::ImportReport`] / [`PaladinError`] drops without
/// mutating state.
fn reduce_import_result(
    mut state: AppState,
    result: Result<ImportSuccess, ImportFailure>,
) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked { ref mut modal, .. } = state else {
        return (state, Vec::new());
    };

    let Some(Modal::Import(import)) = modal.as_mut() else {
        return (state, Vec::new());
    };

    match result {
        Ok(ImportSuccess { report }) => {
            let warnings = report
                .warnings
                .iter()
                .map(|w| format_validation_warning(&w.warning))
                .collect();
            import.counts_panel = Some(CountsPanel {
                imported: report.imported,
                skipped: report.skipped,
                replaced: report.replaced,
                appended: report.appended,
                warnings,
            });
            import.error = None;
        }
        Err(ImportFailure(err)) => {
            import.error = Some(render_error_message(&err));
        }
    }
    (state, Vec::new())
}

/// Handle the outcome of an [`Effect::Unlock`].
///
/// Only `AppState::Unlock` accepts the result; any other state means
/// the user navigated away (auto-lock, quit-in-flight, …) and the
/// late result is dropped. The carried `(Vault, Store)` zeroizes on
/// drop, so discarding is safe.
///
/// On `Ok`, the auto-lock idle deadline is seeded from the executor's
/// `opened_at` instant via [`compute_idle_deadline`] (which delegates
/// to [`paladin_core::IdlePolicy::next_deadline`]).
fn reduce_unlock_result(
    state: AppState,
    open: Result<(Vault, Store), PaladinError>,
    opened_at: Instant,
) -> (AppState, Vec<Effect>) {
    match state {
        AppState::Unlock {
            path, passphrase, ..
        } => match open {
            Ok((vault, store)) => {
                let idle_deadline = compute_idle_deadline(opened_at, &vault);
                let selected = initial_selection(&vault);
                (
                    AppState::Unlocked {
                        path,
                        vault,
                        store,
                        search_query: String::new(),
                        idle_deadline,
                        pending_clipboard_clear: None,
                        hotp_reveal: None,
                        modal: None,
                        selected,
                        pending_chord_leader: None,
                        viewport_height: 0,
                        viewport_offset: 0,
                        focus: Focus::List,
                        status_line: None,
                        help_open: false,
                    },
                    Vec::new(),
                )
            }
            Err(PaladinError::DecryptFailed) => (
                AppState::Unlock {
                    path,
                    error: Some(render_error_message(&PaladinError::DecryptFailed)),
                    passphrase,
                },
                Vec::new(),
            ),
            Err(err) => (
                AppState::StartupError {
                    path: Some(path),
                    message: render_error_message(&err),
                },
                Vec::new(),
            ),
        },
        other => (other, Vec::new()),
    }
}

/// Apply an [`EffectResult::CreateVault`] outcome.
///
/// On `Ok((vault, store))` while [`AppState::CreateVault`] is still
/// the current state, transitions to [`AppState::Unlocked`] with an
/// empty account list — the same vault `paladin init` would produce.
/// The auto-lock idle deadline is seeded from the executor's
/// `opened_at` instant via [`compute_idle_deadline`].
///
/// On `Err(_)` the wizard stays open with the rendered error
/// surfaced inline and any in-flight passphrase buffer zeroized so
/// the user can correct the issue (e.g. fix permissions, choose a
/// different mode) and retry. The wizard step is preserved.
///
/// Results delivered while not on `CreateVault` (e.g., the user
/// navigated away or the app is tearing down between submit and
/// result) are discarded — the carried `(Vault, Store)` drops,
/// which zeroizes the derived AEAD key inside the `Store`.
fn reduce_create_vault_result(
    state: AppState,
    result: Result<(Vault, Store), PaladinError>,
    opened_at: Instant,
) -> (AppState, Vec<Effect>) {
    match state {
        AppState::CreateVault { path, mut step, .. } => match result {
            Ok((vault, store)) => {
                let idle_deadline = compute_idle_deadline(opened_at, &vault);
                let selected = initial_selection(&vault);
                (
                    AppState::Unlocked {
                        path,
                        vault,
                        store,
                        search_query: String::new(),
                        idle_deadline,
                        pending_clipboard_clear: None,
                        hotp_reveal: None,
                        modal: None,
                        selected,
                        pending_chord_leader: None,
                        viewport_height: 0,
                        viewport_offset: 0,
                        focus: Focus::List,
                        status_line: None,
                        help_open: false,
                    },
                    Vec::new(),
                )
            }
            Err(err) => {
                if let crate::app::state::CreateVaultStep::EnterPassphrase {
                    passphrase,
                    confirmation,
                    ..
                } = &mut step
                {
                    passphrase.clear();
                    confirmation.clear();
                }
                // Path-aware rendering: a `create_vault_dir` IoError
                // names the parent directory paladin tried to mkdir.
                let rendered = crate::app::state::render_create_vault_error_message(&err, &path);
                (
                    AppState::CreateVault {
                        path,
                        step,
                        error: Some(rendered),
                    },
                    Vec::new(),
                )
            }
        },
        other => (other, Vec::new()),
    }
}

/// Apply a `crossterm` input event.
fn reduce_input(state: AppState, event: &Event) -> (AppState, Vec<Effect>) {
    let Event::Key(key) = event else {
        // Resize / focus / paste / mouse events are passthrough at
        // this slice; specific handlers (e.g. resize-driven viewport
        // recompute) land with their state slices.
        return (state, Vec::new());
    };

    if is_ctrl_c(key) {
        return (zeroize_passphrase_buffers(state), vec![Effect::Quit]);
    }

    if matches!(key.code, KeyCode::Esc) && quits_on_esc(&state) {
        return (zeroize_passphrase_buffers(state), vec![Effect::Quit]);
    }

    if matches!(state, AppState::Unlock { .. }) {
        return reduce_unlock_input(state, key);
    }

    if matches!(state, AppState::Unlocked { .. }) {
        return reduce_unlocked_input(state, key);
    }

    if matches!(state, AppState::CreateVault { .. }) {
        return reduce_create_vault_input(state, key);
    }

    match key.code {
        KeyCode::Char('q') if quits_on_q(&state) => (state, vec![Effect::Quit]),
        _ => (state, Vec::new()),
    }
}

/// Per-step input handling for the in-app create-vault wizard.
///
/// Per `docs/DESIGN.md` §6 / `docs/IMPLEMENTATION_PLAN_03_TUI.md`
/// "Startup / vault modes":
///
/// * **`ChooseMode`**: `↑` / `↓` / `j` / `k` toggle between
///   [`CreateVaultMode::Encrypted`] (default) and
///   [`CreateVaultMode::Plaintext`]. `Enter` advances to
///   `EnterPassphrase` (encrypted) or `ConfirmPlaintext`
///   (plaintext). `Esc` / `q` / `Ctrl-C` quit at the
///   [`reduce_input`] layer via [`quits_on_esc`] / [`quits_on_q`] /
///   [`is_ctrl_c`].
/// * **`ConfirmPlaintext`**: `Enter` emits a single
///   [`Effect::CreateVault`] carrying
///   [`CreateVaultInit::Plaintext`]; state is unchanged until the
///   executor's [`EffectResult::CreateVault`] arrives. `Esc`
///   returns to `ChooseMode` with `selection = Plaintext` so the
///   user's prior mode choice is preserved.
/// * **`EnterPassphrase`**: characters append to the focused buffer
///   (the inline error, if any, clears on the next typed
///   character), `Backspace` pops, `Tab` / `↑` / `↓` toggle focus.
///   `Enter` on the `Passphrase` field moves focus to
///   `Confirmation`. `Enter` on the `Confirmation` field:
///     - empty passphrase → inline error "passphrase required",
///       confirmation cleared, focus moves to `Passphrase`;
///     - non-empty but `passphrase != confirmation` → inline error
///       "passphrases do not match", confirmation cleared, focus
///       stays on `Confirmation` so the user can retry the typo;
///     - matching → take the passphrase as a
///       [`SecretString`](secrecy::SecretString) and emit
///       [`Effect::CreateVault`] with
///       [`CreateVaultInit::Encrypted`]; both buffers are drained.
///
///   `Esc` returns to `ChooseMode` with `selection = Encrypted`,
///   dropping both `PassphraseBuffer`s (which zeroize on drop via
///   `Zeroizing`). `Ctrl-C` is handled by the [`reduce_input`]
///   wrapper, which calls [`zeroize_passphrase_buffers`] before
///   emitting [`Effect::Quit`].
#[allow(clippy::too_many_lines)]
fn reduce_create_vault_input(state: AppState, key: &KeyEvent) -> (AppState, Vec<Effect>) {
    use crate::app::event::CreateVaultInit;
    use crate::app::state::{CreateVaultMode, CreateVaultStep, PassphraseFieldFocus};

    let AppState::CreateVault {
        path,
        mut step,
        mut error,
    } = state
    else {
        // `reduce_input` only routes `AppState::CreateVault` here.
        unreachable!("reduce_create_vault_input called with non-CreateVault state");
    };

    match &mut step {
        CreateVaultStep::ChooseMode { selection } => {
            match key.code {
                KeyCode::Char('j' | 'J') | KeyCode::Down => {
                    *selection = CreateVaultMode::Plaintext;
                    error = None;
                }
                KeyCode::Char('k' | 'K') | KeyCode::Up => {
                    *selection = CreateVaultMode::Encrypted;
                    error = None;
                }
                KeyCode::Enter => {
                    let next_step = match *selection {
                        CreateVaultMode::Encrypted => CreateVaultStep::EnterPassphrase {
                            passphrase: PassphraseBuffer::new(),
                            confirmation: PassphraseBuffer::new(),
                            focus: PassphraseFieldFocus::Passphrase,
                        },
                        CreateVaultMode::Plaintext => CreateVaultStep::ConfirmPlaintext,
                    };
                    return (
                        AppState::CreateVault {
                            path,
                            step: next_step,
                            error: None,
                        },
                        Vec::new(),
                    );
                }
                KeyCode::Esc | KeyCode::Char('q' | 'Q') => {
                    return (
                        AppState::CreateVault { path, step, error },
                        vec![Effect::Quit],
                    );
                }
                _ => {}
            }
            (AppState::CreateVault { path, step, error }, Vec::new())
        }
        CreateVaultStep::ConfirmPlaintext => match key.code {
            KeyCode::Enter => {
                let effect = Effect::CreateVault {
                    path: path.clone(),
                    init: CreateVaultInit::Plaintext,
                };
                (
                    AppState::CreateVault {
                        path,
                        step: CreateVaultStep::ConfirmPlaintext,
                        error: None,
                    },
                    vec![effect],
                )
            }
            KeyCode::Esc => (
                AppState::CreateVault {
                    path,
                    step: CreateVaultStep::ChooseMode {
                        selection: CreateVaultMode::Plaintext,
                    },
                    error: None,
                },
                Vec::new(),
            ),
            KeyCode::Char('q' | 'Q') => (
                AppState::CreateVault { path, step, error },
                vec![Effect::Quit],
            ),
            _ => (AppState::CreateVault { path, step, error }, Vec::new()),
        },
        CreateVaultStep::EnterPassphrase {
            passphrase,
            confirmation,
            focus,
        } => {
            // Reject anything that explicitly carries a Ctrl modifier;
            // typed printable characters arrive with no modifier (or
            // Shift only for uppercase). Ctrl-C is intercepted by
            // `reduce_input`'s `is_ctrl_c` check before this handler
            // ever runs, so explicit Ctrl rejection here keeps other
            // accidental Ctrl- chords (e.g. Ctrl-A) from polluting the
            // passphrase buffer.
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && !matches!(key.code, KeyCode::Char('c'))
            {
                return (AppState::CreateVault { path, step, error }, Vec::new());
            }
            match key.code {
                KeyCode::Esc => (
                    AppState::CreateVault {
                        path,
                        step: CreateVaultStep::ChooseMode {
                            selection: CreateVaultMode::Encrypted,
                        },
                        error: None,
                    },
                    Vec::new(),
                ),
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                    *focus = match focus {
                        PassphraseFieldFocus::Passphrase => PassphraseFieldFocus::Confirmation,
                        PassphraseFieldFocus::Confirmation => PassphraseFieldFocus::Passphrase,
                    };
                    (AppState::CreateVault { path, step, error }, Vec::new())
                }
                KeyCode::Backspace => {
                    match focus {
                        PassphraseFieldFocus::Passphrase => {
                            passphrase.pop();
                        }
                        PassphraseFieldFocus::Confirmation => {
                            confirmation.pop();
                        }
                    }
                    (
                        AppState::CreateVault {
                            path,
                            step,
                            error: None,
                        },
                        Vec::new(),
                    )
                }
                KeyCode::Enter => match focus {
                    PassphraseFieldFocus::Passphrase => {
                        if passphrase.is_empty() {
                            return (
                                AppState::CreateVault {
                                    path,
                                    step,
                                    error: Some("passphrase required".to_string()),
                                },
                                Vec::new(),
                            );
                        }
                        *focus = PassphraseFieldFocus::Confirmation;
                        (
                            AppState::CreateVault {
                                path,
                                step,
                                error: None,
                            },
                            Vec::new(),
                        )
                    }
                    PassphraseFieldFocus::Confirmation => {
                        if passphrase.is_empty() {
                            confirmation.clear();
                            *focus = PassphraseFieldFocus::Passphrase;
                            return (
                                AppState::CreateVault {
                                    path,
                                    step,
                                    error: Some("passphrase required".to_string()),
                                },
                                Vec::new(),
                            );
                        }
                        if passphrase.as_str() != confirmation.as_str() {
                            confirmation.clear();
                            *focus = PassphraseFieldFocus::Confirmation;
                            return (
                                AppState::CreateVault {
                                    path,
                                    step,
                                    error: Some("passphrases do not match".to_string()),
                                },
                                Vec::new(),
                            );
                        }
                        let secret = passphrase.take();
                        confirmation.clear();
                        let effect = Effect::CreateVault {
                            path: path.clone(),
                            init: CreateVaultInit::Encrypted(secret),
                        };
                        (
                            AppState::CreateVault {
                                path,
                                step,
                                error: None,
                            },
                            vec![effect],
                        )
                    }
                },
                KeyCode::Char(c) => {
                    match focus {
                        PassphraseFieldFocus::Passphrase => passphrase.push(c),
                        PassphraseFieldFocus::Confirmation => confirmation.push(c),
                    }
                    (
                        AppState::CreateVault {
                            path,
                            step,
                            error: None,
                        },
                        Vec::new(),
                    )
                }
                _ => (AppState::CreateVault { path, step, error }, Vec::new()),
            }
        }
    }
}

/// Handle a key event on the Unlocked (main list) screen.
///
/// Three transitions land in this slice, all from
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings (initial v0.1)":
///
/// * **Modal openers** (seven bare-letter keys):
///
///   | Key | Modal              |
///   | --- | ------------------ |
///   | `a` | [`Modal::Add`]     |
///   | `i` | [`Modal::Import`]  |
///   | `e` | [`Modal::Export`]  |
///   | `r` | [`Modal::Remove`]  |
///   | `R` | [`Modal::Rename`]  |
///   | `p` | [`Modal::Passphrase`] |
///   | `s` | [`Modal::Settings`] |
///
///   All seven fire only when no Ctrl / Alt modifier is held — the
///   corresponding Ctrl- chords are unbound and must not silently
///   open dialogs. Shift is allowed through because the `r` / `R`
///   split relies on the resolved upper-case character. The modal
///   opens only when no modal is currently open; once a modal
///   payload exists, the bare letter inside an open modal is
///   consumed by the modal-local input path. Routing into
///   modal-local input lands alongside each modal's payload slice;
///   at this slice the open-modal case is a no-op so the slot stays
///   unchanged.
///
/// * **`Esc` close-modal / clear-search / clear-chord**: precedence
///   order is `modal-close > search-clear > chord-clear`. With a
///   modal open, `Esc` clears the modal slot to `None` and leaves
///   `focus` / `search_query` untouched — the modal traps focus, so
///   the user returns to the same focus surface that was active
///   before the modal opened. With no modal open and
///   `focus == Focus::Search`, `Esc` clears the search query buffer
///   and returns `focus` to `Focus::List`. With no modal open and
///   `focus == Focus::List`, `Esc` is otherwise a silent no-op —
///   `Unlocked` is intentionally not in `quits_on_esc`'s "no
///   dismissable affordance" set, so the user is never one stray
///   `Esc` away from losing the unlocked session. In every case,
///   any pending vim chord leader is cleared. `Esc` is accepted
///   regardless of modifier so terminals that report Ctrl-Esc or
///   kitty-style augmented Esc still dismiss the modal /
///   search-focus.
///
/// * **`gg` two-press chord** (vim mirror of `Home`): with no modal
///   open, lower-case `g` either sets
///   `pending_chord_leader = Some(ChordLeader::G)` on the first press
///   or commits a jump-to-first on the matching second press
///   (clearing the pending state). Any other key on `Unlocked`,
///   any Ctrl/Alt-modifier press, `Esc`, or a modal open also
///   clears the pending state. There is no time-based clear —
///   vim's `nottimeout` semantics. The chord never engages while
///   a modal is open. The `zz` recenter chord lands alongside the
///   viewport-tracking slice.
fn reduce_unlocked_input(mut state: AppState, key: &KeyEvent) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref path,
        ref mut modal,
        ref mut pending_chord_leader,
        ref mut focus,
        ref mut search_query,
        ref vault,
        ref mut selected,
        ref mut help_open,
        ref hotp_reveal,
        ..
    } = state
    else {
        // Caller ensures we're in Unlocked; defensive fall-through
        // keeps the reducer total.
        return (state, Vec::new());
    };

    if matches!(key.code, KeyCode::Esc) {
        apply_esc_dismiss(pending_chord_leader, help_open, modal, focus, search_query);
        return (state, Vec::new());
    }

    if *help_open {
        // The Help overlay is read-only: every key besides `Esc`
        // (handled above) and `Ctrl-C` (caught upstream in
        // [`reduce_input`]) is a silent no-op while it is visible
        // per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Help overlay": *"The
        // overlay has no inputs and never mutates vault state."*
        // Modal openers, navigation, `q`, `/`, `n`, and even
        // bare-letter Char presses are suppressed so they cannot
        // bleed actions into the underlying list view. Pending
        // chord-leader state stays as-is because the overlay
        // cannot have been opened with a chord in flight (the
        // `?` opener runs through `dispatch_unlocked_char` which
        // clears it on entry).
        return (state, Vec::new());
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        // `Ctrl-F` / `Ctrl-B` are the vim mirrors of `PgDn` / `PgUp`,
        // `Ctrl-D` / `Ctrl-U` are the vim half-page bindings (move
        // by `viewport_height / 2` rows, integer division), and
        // `Ctrl-N` / `Ctrl-P` are the readline-style next / previous
        // row aliases for `↓` / `↑` — all when no modal is open.
        // Every binding routes through the same [`move_selection`]
        // path, so `viewport_height = 0` and the empty filtered set
        // stay silent no-ops, and the chord leader is cleared before
        // the page step runs. The half-page variants additionally
        // no-op on `viewport_height = 1` (half = 0). Strict equality
        // on `KeyModifiers::CONTROL` keeps Ctrl-Shift-* /
        // Ctrl-Alt-* out (mirroring the existing `Ctrl-Shift-G is
        // unbound` convention) — only the bare Ctrl chord engages.
        // With a modal open, page / half-page chords mirror the
        // modal-routing no-op of `PgDn` / `PgUp`, while `Ctrl-N` /
        // `Ctrl-P` keep their modal-LOCAL meaning as `Tab` /
        // `Shift-Tab` aliases per
        // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Vim-style navigation":
        // they fall through to the modal-focus-routing branch
        // below — when modal payloads grow focusable fields, both
        // pairs dispatch through the same modal-local
        // focus-cycling handler. All other Ctrl/Alt-modifier
        // presses are unbound at this slice but still clear any
        // pending chord state — chord commitment requires a bare
        // second press.
        *pending_chord_leader = None;
        if let Some(step) = ctrl_chord_list_step(modal.is_some(), key) {
            return move_selection(state, step);
        }
        if modal.is_some() && (is_modal_focus_next(key) || is_modal_focus_prev(key)) {
            let effects = route_modal_input(path, modal, vault, key);
            return (state, effects);
        }
        return (state, Vec::new());
    }

    if modal.is_some() {
        *pending_chord_leader = None;
        let effects = route_modal_input(path, modal, vault, key);
        return (state, effects);
    }

    // Modal is None below here.

    if *focus == Focus::Search {
        *pending_chord_leader = None;
        if route_search_focus_char(search_query, selected, vault, key) {
            return (state, Vec::new());
        }
    }

    // `gg` chord: first press sets pending leader, matching second
    // press commits jump-to-first. Handled before list-step / modal
    // openers so the bare `g` is consumed by the chord path. `z` on a
    // pending `g` cross-clears `g` and arms `z` — handled below by
    // the symmetric `z` branch.
    if matches!(key.code, KeyCode::Char('g')) {
        let was_pending = matches!(*pending_chord_leader, Some(ChordLeader::G));
        *pending_chord_leader = None;
        if was_pending {
            return move_selection(state, ListStep::First);
        }
        if let AppState::Unlocked {
            pending_chord_leader,
            ..
        } = &mut state
        {
            *pending_chord_leader = Some(ChordLeader::G);
        }
        return (state, Vec::new());
    }

    // `zz` chord (vim recenter): first press sets pending leader,
    // matching second press commits a viewport recenter on the
    // selected row. A pending `z` followed by any non-`z` key
    // (including `g`) cross-clears the leader; `g` then re-arms its
    // own leader through the `g` branch above. The recenter
    // resolves `sel_pos = vault.iter().position(selected)` and sets
    // `viewport_offset = (sel_pos - viewport_height / 2)` with
    // `saturating_sub` so near-the-top selections clamp to `0`.
    // Empty filtered set, `selected = None`, and `viewport_height
    // = 0` are silent no-ops; the chord leader is still cleared.
    if matches!(key.code, KeyCode::Char('z')) {
        let was_pending = matches!(*pending_chord_leader, Some(ChordLeader::Z));
        *pending_chord_leader = None;
        if was_pending {
            return recenter_viewport(state);
        }
        if let AppState::Unlocked {
            pending_chord_leader,
            ..
        } = &mut state
        {
            *pending_chord_leader = Some(ChordLeader::Z);
        }
        return (state, Vec::new());
    }

    // Any other key on the list (matching or not) clears the
    // pending chord state before its own action runs.
    *pending_chord_leader = None;

    if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
        return toggle_unlocked_focus(state);
    }

    if let Some(step) = list_step_for_key(key.code) {
        return move_selection(state, step);
    }

    // `Enter` on Unlocked: copy the selected code (see [`enter_on_unlocked`]).
    if matches!(key.code, KeyCode::Enter) && *focus == Focus::List {
        let effects = enter_on_unlocked(path, vault, hotp_reveal.as_ref(), *selected);
        return (state, effects);
    }

    if let KeyCode::Char(c) = key.code {
        return route_unlocked_char_kbd(state, c);
    }

    (state, Vec::new())
}

/// Route the bare-letter Char `c` on `AppState::Unlocked` with no
/// modal open and no chord leader pending.
///
/// Pre-bundles the per-char modal-payload and effect-list inputs
/// (snapshotting the live `(Vault, &Path)` borrow before handing
/// `state` to [`dispatch_unlocked_char`]) and applies the
/// selection-gated status-line error from
/// [`selection_gated_status_error`] for `n` / `r` / `R` with no
/// selection. Extracted from [`reduce_unlocked_input`] so the parent
/// reducer stays within the 100-line clippy budget; the inputs are
/// what the previous inline implementation passed to
/// `dispatch_unlocked_char` plus the selection-gated error gate.
fn route_unlocked_char_kbd(mut state: AppState, c: char) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref path,
        ref vault,
        ref selected,
        ref mut status_line,
        ..
    } = state
    else {
        return (state, Vec::new());
    };
    if let Some(err) = selection_gated_status_error(c, *selected) {
        *status_line = Some(err);
        return (state, Vec::new());
    }
    let n_effects = n_effects_for_char(c, path, vault, *selected);
    let rename_modal = pending_rename_for_char(c, vault, *selected);
    let edit_modal = pending_edit_for_char(c, vault, *selected);
    let remove_modal = pending_remove_for_char(c, *selected);
    let settings_modal = pending_settings_for_char(c, vault);
    let qr_export_modal = pending_qr_export_for_char(c, vault, *selected);
    let copy_next = if c == 'C' {
        Some(copy_next_code_outcome(path, vault, *selected))
    } else {
        None
    };
    dispatch_unlocked_char(
        state,
        c,
        n_effects,
        rename_modal,
        edit_modal,
        remove_modal,
        settings_modal,
        qr_export_modal,
        copy_next,
    )
}

/// Build the effect list `dispatch_unlocked_char` should carry for
/// the bare-letter Char `c`. Currently only `n` produces a non-empty
/// list (the HOTP-advance effect when a HOTP account is selected);
/// every other letter is dispatched with an empty effect list. The
/// helper keeps the borrow of `path` / `vault` confined to a tight
/// pre-dispatch window so the parent reducer stays within its line
/// budget.
/// Resolve a bare-Ctrl chord into its list-navigation step, or `None`
/// when the chord is unbound at the current modal state.
///
/// `Ctrl-F` / `Ctrl-B` mirror `PgDn` / `PgUp`, `Ctrl-D` / `Ctrl-U`
/// are the vim half-page bindings, and `Ctrl-N` / `Ctrl-P` are the
/// readline-style next / previous row aliases for `↓` / `↑` per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Vim-style navigation". They only
/// fire when no modal is open (modals trap focus) and the modifier
/// set equals `KeyModifiers::CONTROL` exactly — Ctrl-Shift-* /
/// Ctrl-Alt-* stay unbound, matching the `Ctrl-Shift-G is unbound`
/// convention. With a modal open, `Ctrl-N` / `Ctrl-P` keep their
/// modal-LOCAL meaning as `Tab` / `Shift-Tab` aliases by falling
/// through to the modal-focus-routing branch in the caller.
fn ctrl_chord_list_step(modal_open: bool, key: &KeyEvent) -> Option<ListStep> {
    if modal_open || key.modifiers != KeyModifiers::CONTROL {
        return None;
    }
    match key.code {
        KeyCode::Char('f') => Some(ListStep::PageDown),
        KeyCode::Char('b') => Some(ListStep::PageUp),
        KeyCode::Char('d') => Some(ListStep::HalfPageDown),
        KeyCode::Char('u') => Some(ListStep::HalfPageUp),
        KeyCode::Char('n') => Some(ListStep::Down),
        KeyCode::Char('p') => Some(ListStep::Up),
        _ => None,
    }
}

fn n_effects_for_char(
    c: char,
    path: &std::path::Path,
    vault: &Vault,
    selected: Option<AccountId>,
) -> Vec<Effect> {
    if c == 'n' {
        hotp_advance_effect(path, vault, selected)
            .into_iter()
            .collect()
    } else {
        Vec::new()
    }
}

/// Construct the [`RenameModal`] payload for `R` from the still-borrowed
/// vault + selection, or `None` when the binding is not `R` or when the
/// selection cannot be resolved to a vault account.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Rename:
/// *"single text field pre-populated with the selected account's
/// current label."* Selection is gated upstream by
/// [`selection_gated_status_error`], so a `selected = None` here means
/// the caller bypassed the gate (defensive — yields `None` so no modal
/// opens). The lookup tolerates a stale selection (id no longer in
/// `Vault::iter`) by returning `None`; the dispatch arm leaves the
/// modal slot untouched in that case.
fn pending_rename_for_char(
    c: char,
    vault: &Vault,
    selected: Option<AccountId>,
) -> Option<RenameModal> {
    if c != 'R' {
        return None;
    }
    let id = selected?;
    let account = vault.iter().find(|a| a.id() == id)?;
    Some(RenameModal {
        account_id: id,
        draft: account.label().to_owned(),
        error: None,
    })
}

/// Construct the [`EditModal`] payload for `Shift+E` from the still-
/// borrowed vault + selection, or `None` when the binding is not
/// `'E'` or when the selection cannot be resolved to a vault account.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Edit"
/// and the "Edit modal" test inventory: opens with all three controls
/// pre-populated — label buffer = prior label, issuer buffer = prior
/// issuer (`None` rendered as empty), icon-hint selector defaulted to
/// *Leave unchanged* with the sibling slug buffer pre-populated from
/// the prior `icon_hint` slug (empty string when the prior was
/// `None`). Initial focus lands on the Label row.
fn pending_edit_for_char(c: char, vault: &Vault, selected: Option<AccountId>) -> Option<EditModal> {
    if c != 'E' {
        return None;
    }
    let id = selected?;
    let account = vault.iter().find(|a| a.id() == id)?;
    let prior_label = account.label().to_owned();
    let prior_issuer = account.issuer().map(str::to_owned);
    let prior_icon_hint = account.icon_hint().map(str::to_owned);
    let slug_buffer = prior_icon_hint.clone().unwrap_or_default();
    Some(EditModal {
        account_id: id,
        prior: EditPrior {
            label: prior_label.clone(),
            issuer: prior_issuer.clone(),
            icon_hint: prior_icon_hint,
        },
        label_buffer: prior_label,
        issuer_buffer: prior_issuer.unwrap_or_default(),
        icon_hint_selector: EditIconHintSelector::LeaveUnchanged,
        icon_hint_slug: slug_buffer,
        focus: EditFocus::Label,
        error: None,
    })
}

/// Construct the [`RemoveModal`] payload for `r` from the current
/// selection, or `None` when the binding is not `r` or when nothing
/// is selected.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Remove: a
/// confirmation gate keyed by the selected account. Selection is
/// gated upstream by [`selection_gated_status_error`], so a
/// `selected = None` here means the caller bypassed the gate
/// (defensive — yields `None` so no modal opens). Unlike Rename, no
/// vault lookup is needed at modal-open time: the executor resolves
/// `account_id` against the live `Vault` at submit and surfaces an
/// inline error if it has disappeared meanwhile.
fn pending_remove_for_char(c: char, selected: Option<AccountId>) -> Option<RemoveModal> {
    if c != 'r' {
        return None;
    }
    let id = selected?;
    Some(RemoveModal {
        account_id: id,
        error: None,
    })
}

/// Construct the [`SettingsModal`] payload for `s` from the live vault
/// settings, or `None` when the binding is not `s`.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Settings:
/// *"The modal accumulates pending edits in modal-local state and
/// only commits on Confirm."* The reducer snapshots the live
/// [`paladin_core::VaultSettings`] into the modal's pending fields at
/// open time so subsequent edits stay modal-local until Confirm and
/// `Esc` can discard them without invoking any setter or save.
/// Settings is not selection-gated (per the "Focus model" rule) and
/// the four field types are all `Copy`, so no vault-account lookup
/// or fallible read is required.
fn pending_settings_for_char(c: char, vault: &Vault) -> Option<SettingsModal> {
    if c != 's' {
        return None;
    }
    let settings = vault.settings();
    Some(SettingsModal {
        auto_lock_enabled: settings.auto_lock_enabled(),
        auto_lock_timeout_secs: settings.auto_lock_timeout_secs(),
        clipboard_clear_enabled: settings.clipboard_clear_enabled(),
        clipboard_clear_secs: settings.clipboard_clear_secs(),
        focus: SettingsFocus::default(),
        error: None,
    })
}

/// Construct the [`QrExportModal`] payload for `Q` (Shift-q) from the
/// current selection, or `None` when the binding is not `Q`, when
/// nothing is selected (empty filtered set), or when the selection
/// has dropped out of the vault.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > QR
/// Export: *"single-account QR modal opened with `Q` (Shift-q) on
/// the focused list row. ... is also a silent no-op when the
/// filtered set is empty so there is no focused row to render
/// (parity with `Enter` on an empty list)."* Unlike Remove / Rename,
/// the no-selection case does NOT set a status-line error — the
/// binding is a silent no-op (parity with `Enter` on an empty list).
/// The vault lookup tolerates a stale selection (id no longer in
/// `Vault::iter`) by returning `None`; the dispatch arm leaves the
/// modal slot untouched in that case.
fn pending_qr_export_for_char(
    c: char,
    vault: &Vault,
    selected: Option<AccountId>,
) -> Option<QrExportModal> {
    if c != 'Q' {
        return None;
    }
    let id = selected?;
    vault.iter().find(|a| a.id() == id)?;
    Some(QrExportModal::new(id))
}

/// Dispatch a key event to the open modal's modal-local input path.
///
/// At this slice [`Modal::Add`], [`Modal::Rename`], [`Modal::Remove`],
/// and [`Modal::Settings`] consume input; the other variants do not
/// yet carry an editable payload, so they fall through to a silent
/// no-op (the modal stays open and no effect is emitted, preserving
/// the modal-trap contract that bare-letter keys do not leak into
/// the list view). Each modal's input path lands alongside its
/// respective slice.
fn route_modal_input(
    path: &std::path::Path,
    modal: &mut Option<Modal>,
    vault: &Vault,
    key: &KeyEvent,
) -> Vec<Effect> {
    match modal.as_mut() {
        Some(Modal::Add(add)) => route_add_modal_input(path, add, key),
        Some(Modal::Rename(rename)) => route_rename_modal_input(path, rename, key),
        Some(Modal::Edit(edit)) => route_edit_modal_input(path, edit, vault, key),
        Some(Modal::Remove(remove)) => route_remove_modal_input(path, remove, key),
        Some(Modal::Import(import)) => route_import_modal_input(path, import, key),
        Some(Modal::Export(export)) => route_export_modal_input(path, export, key),
        Some(Modal::Passphrase(passphrase)) => route_passphrase_modal_input(path, passphrase, key),
        Some(Modal::Settings(settings)) => {
            let (effects, close) = route_settings_modal_input(path, settings, vault, key);
            if close {
                *modal = None;
            }
            effects
        }
        Some(Modal::QrExport(qr)) => {
            let (effects, close) = route_qr_export_modal_input(path, qr, vault, key);
            if close {
                *modal = None;
            }
            effects
        }
        _ => Vec::new(),
    }
}

/// Add modal's input path.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)":
/// *"`←` / `→` change segmented selectors"* and *"`Tab` and `Ctrl-N`
/// move to the next control, `Shift-Tab` and `Ctrl-P` move to the
/// previous control."*
///
/// The Add modal's three input modes (Manual / URI / QR per DESIGN
/// §6) form one segmented selector; `→` advances through
/// [`AddMode::next`] and `←` retreats through [`AddMode::prev`], both
/// wrapping so the user can cycle indefinitely. The mode-switch
/// routes through [`AddModal::switch_mode`] which zeroizes the
/// secret-bearing buffers belonging to the mode being left — per the
/// plan's *"switching modes clears the hidden secret-bearing fields
/// for the modes being left: the manual Base32 secret, the URI text,
/// and any pending duplicate/add-anyway state"*.
///
/// Inside Manual mode `Tab` / `Ctrl-N` advance
/// [`AddModal::manual_focus`] forward through DESIGN §6's eight
/// controls (label → issuer → secret → algorithm → digits → kind →
/// period/counter → icon-hint) and `Shift-Tab` / `Ctrl-P` retreat,
/// both wrapping at either end. In Uri / Qr mode there is no
/// multi-field control to cycle, so the same keys are silent no-ops;
/// `manual_focus` is intentionally sticky across mode switches so the
/// user's last Manual-mode focus is restored on return to Manual.
///
/// In Manual mode with one of the four text-bearing fields focused
/// — [`AddManualFocus::Label`], [`AddManualFocus::Issuer`],
/// [`AddManualFocus::Secret`], or [`AddManualFocus::IconHintText`] —
/// a printable `KeyCode::Char` keystroke (no `Ctrl` / `Alt` modifier
/// — mirroring the Unlock-screen filter) appends to the corresponding
/// modal-local buffer (`label`, `issuer`, `manual_secret`, or
/// `icon_hint_text`) and `KeyCode::Backspace` pops the trailing
/// character; backspace on an empty buffer is a silent no-op. The
/// `manual_secret` field is a
/// [`PassphraseBuffer`](crate::prompt::PassphraseBuffer) so typed
/// bytes are zeroized on drop / clear; Base32 + length validation
/// runs at submit time via `paladin_core::validate_manual`, so typing
/// accepts any character. `Char` keystrokes on the four
/// non-text-bearing focuses ([`AddManualFocus::Algorithm`],
/// [`AddManualFocus::Digits`], [`AddManualFocus::Kind`], and
/// [`AddManualFocus::PeriodOrCounter`] — selectors and spinners
/// cycled by `←` / `→` / `↑` / `↓`) are silently consumed.
///
/// In Manual mode with [`AddManualFocus::Algorithm`] focused,
/// `→` / `↓` advance the three-valued segmented selector forward
/// (Sha1 → Sha256 → Sha512 → Sha1) and `←` / `↑` retreat it backward
/// (Sha1 → Sha512 → Sha256 → Sha1); both wrap at either end. The
/// same four arrow keys with [`AddManualFocus::Digits`] cycle the
/// digit count through the three valid values per
/// [`paladin_core::DIGITS_MIN`]..=[`paladin_core::DIGITS_MAX`]
/// (6 → 7 → 8 → 6 forward; 6 → 8 → 7 → 6 backward), also wrapping.
/// With [`AddManualFocus::Kind`] focused, any of the four arrow
/// keys toggles the two-valued
/// [`paladin_core::AccountKindInput`] selector between `Totp` and
/// `Hotp`; the modal's independent `period_secs` and `counter`
/// scratch values are preserved across the toggle so the
/// `PeriodOrCounter` focus can bind to whichever applies to the
/// current Kind. With [`AddManualFocus::PeriodOrCounter`] focused,
/// `↑` / `→` increment and `↓` / `←` decrement the bound numeric
/// spinner by 1: `period_secs` when Kind is `Totp` (clamped to
/// [`paladin_core::TOTP_PERIOD_MIN`]..=[`paladin_core::TOTP_PERIOD_MAX`])
/// or `counter` when Kind is `Hotp` (saturating `u64`).
/// These arrow keys are intercepted before the mode-switch `←` /
/// `→` branch so they do not switch the [`AddMode`] header when a
/// non-text field has focus; the URI / QR modes and the four
/// text-bearing Manual focuses keep the existing
/// [`AddMode`]-cycling behavior.
/// URI-mode typing, the duplicate-gate pending state, and the
/// post-QR counts panel land in subsequent slices.
/// Every other key here is a silent no-op so the modal-trap contract
/// holds. `Esc` / Help / `Ctrl-C` are filtered upstream of the modal
/// trap.
/// Try to handle a `←` / `→` / `↑` / `↓` keystroke as a value cycle
/// on the Add modal's non-text Manual focuses (Algorithm / Digits /
/// Kind). Returns `true` if the key was consumed so the caller skips
/// the mode-switch `←` / `→` branch and the Tab / Char / Backspace
/// handlers. Caller guarantees [`AddMode::Manual`].
fn try_cycle_manual_selector(add: &mut AddModal, key: &KeyEvent) -> bool {
    match (add.manual_focus, key.code) {
        (AddManualFocus::Algorithm, KeyCode::Right | KeyCode::Down) => {
            add.algorithm = match add.algorithm {
                Algorithm::Sha1 => Algorithm::Sha256,
                Algorithm::Sha256 => Algorithm::Sha512,
                Algorithm::Sha512 => Algorithm::Sha1,
            };
            true
        }
        (AddManualFocus::Algorithm, KeyCode::Left | KeyCode::Up) => {
            add.algorithm = match add.algorithm {
                Algorithm::Sha1 => Algorithm::Sha512,
                Algorithm::Sha256 => Algorithm::Sha1,
                Algorithm::Sha512 => Algorithm::Sha256,
            };
            true
        }
        (AddManualFocus::Digits, KeyCode::Right | KeyCode::Down) => {
            add.digits = match add.digits {
                6 => 7,
                7 => 8,
                _ => 6,
            };
            true
        }
        (AddManualFocus::Digits, KeyCode::Left | KeyCode::Up) => {
            add.digits = match add.digits {
                6 => 8,
                7 => 6,
                _ => 7,
            };
            true
        }
        (AddManualFocus::Kind, KeyCode::Right | KeyCode::Down | KeyCode::Left | KeyCode::Up) => {
            add.kind = match add.kind {
                AccountKindInput::Totp => AccountKindInput::Hotp,
                AccountKindInput::Hotp => AccountKindInput::Totp,
            };
            true
        }
        (AddManualFocus::PeriodOrCounter, KeyCode::Up | KeyCode::Right) => {
            step_period_or_counter(add, true);
            true
        }
        (AddManualFocus::PeriodOrCounter, KeyCode::Down | KeyCode::Left) => {
            step_period_or_counter(add, false);
            true
        }
        _ => false,
    }
}

/// Increment / decrement the Add modal's
/// [`AddManualFocus::PeriodOrCounter`] spinner.
///
/// When the modal-local Kind is `Totp` the step adjusts `period_secs`
/// by 1 second, clamped to
/// [`paladin_core::TOTP_PERIOD_MIN`]..=[`paladin_core::TOTP_PERIOD_MAX`].
/// When Kind is `Hotp` the step adjusts `counter` by 1 with
/// saturating-add / saturating-sub semantics so the spinner cannot
/// wrap past `u64::MAX` or below 0.
fn step_period_or_counter(add: &mut AddModal, up: bool) {
    match add.kind {
        AccountKindInput::Totp => {
            if up {
                if add.period_secs < paladin_core::TOTP_PERIOD_MAX {
                    add.period_secs += 1;
                }
            } else if add.period_secs > paladin_core::TOTP_PERIOD_MIN {
                add.period_secs -= 1;
            }
        }
        AccountKindInput::Hotp => {
            if up {
                add.counter = add.counter.saturating_add(1);
            } else {
                add.counter = add.counter.saturating_sub(1);
            }
        }
    }
}

fn route_add_modal_input(
    path: &std::path::Path,
    add: &mut AddModal,
    key: &KeyEvent,
) -> Vec<Effect> {
    // Post-success counts panel owns the modal's visible region: the
    // underlying mode-specific controls are no longer reachable, so
    // the modal-local focus aliases `Ctrl-N` / `Ctrl-P` (and their
    // `Tab` / `Shift-Tab` siblings) must be silent no-ops rather
    // than cycle the now-hidden field set. Per
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Vim-style navigation":
    // *"`Ctrl-N` / `Ctrl-P` inside modals have no effect on a
    // post-success counts panel — lands alongside the counts panel
    // payload (Add / Import / Export)."*
    if add.counts_panel.is_some() && (is_modal_focus_next(key) || is_modal_focus_prev(key)) {
        return Vec::new();
    }
    // Pending duplicate-add state shortcircuits Enter on both Manual
    // and URI modes per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
    // §6)" > Add: *"A collision initially rejects with the existing
    // account in the modal and offers an 'add anyway' confirmation
    // that inserts the pending validated account on the
    // duplicate-allowed path."* The dispatch must run before the
    // mode-specific submit so a follow-up Enter in URI mode does not
    // re-run `parse_otpauth` against an empty buffer.
    if matches!(key.code, KeyCode::Enter) {
        if let Some(pending) = add.pending_duplicate_add.take() {
            add.error = None;
            return vec![Effect::AddAnyway {
                path: path.to_path_buf(),
                validated: pending.validated,
            }];
        }
    }
    if add.mode == AddMode::Manual && try_cycle_manual_selector(add, key) {
        return Vec::new();
    }
    match key.code {
        KeyCode::Right => {
            add.switch_mode(add.mode.next());
            return Vec::new();
        }
        KeyCode::Left => {
            add.switch_mode(add.mode.prev());
            return Vec::new();
        }
        _ => {}
    }
    if add.mode == AddMode::Manual {
        if is_modal_focus_next(key) {
            add.manual_focus = add.manual_focus.next();
            return Vec::new();
        }
        if is_modal_focus_prev(key) {
            add.manual_focus = add.manual_focus.prev();
            return Vec::new();
        }
        if matches!(key.code, KeyCode::Enter) {
            return vec![Effect::Add {
                path: path.to_path_buf(),
                label: add.label.clone(),
                issuer: add.issuer.clone(),
                secret: add.manual_secret.take(),
                algorithm: add.algorithm,
                digits: add.digits,
                kind: add.kind,
                period_secs: add.period_secs,
                counter: add.counter,
                icon_hint_text: add.icon_hint_text.clone(),
            }];
        }
        if let KeyCode::Char(c) = key.code {
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            {
                match add.manual_focus {
                    AddManualFocus::Label => add.label.push(c),
                    AddManualFocus::Issuer => add.issuer.push(c),
                    AddManualFocus::Secret => add.manual_secret.push(c),
                    AddManualFocus::IconHintText => add.icon_hint_text.push(c),
                    AddManualFocus::Algorithm
                    | AddManualFocus::Digits
                    | AddManualFocus::Kind
                    | AddManualFocus::PeriodOrCounter => {}
                }
            }
            return Vec::new();
        }
        if matches!(key.code, KeyCode::Backspace) {
            match add.manual_focus {
                AddManualFocus::Label => {
                    add.label.pop();
                }
                AddManualFocus::Issuer => {
                    add.issuer.pop();
                }
                AddManualFocus::Secret => {
                    add.manual_secret.pop();
                }
                AddManualFocus::IconHintText => {
                    add.icon_hint_text.pop();
                }
                AddManualFocus::Algorithm
                | AddManualFocus::Digits
                | AddManualFocus::Kind
                | AddManualFocus::PeriodOrCounter => {}
            }
            return Vec::new();
        }
    }
    if add.mode == AddMode::Uri {
        return route_add_uri_mode_input(path, add, key);
    }
    if add.mode == AddMode::Qr {
        return route_add_qr_mode_input(path, key);
    }
    Vec::new()
}

/// Qr-mode key dispatch: Enter dispatches an
/// [`Effect::AddFromClipboardQr`] so the executor can read the live
/// clipboard image through `arboard`, validate the RGBA buffer size
/// against [`paladin_core::QR_RGBA_MAX_BYTES`], decode any encoded
/// `otpauth://` URIs via `paladin_core::import::qr_image_bytes`, and
/// import them via `Vault::import_accounts` with
/// [`paladin_core::ImportConflict::Skip`] per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add. QR mode
/// has no modal-local form fields, so every other key is a silent
/// no-op so the modal-trap contract holds.
fn route_add_qr_mode_input(path: &std::path::Path, key: &KeyEvent) -> Vec<Effect> {
    if matches!(key.code, KeyCode::Enter) {
        return vec![Effect::AddFromClipboardQr {
            path: path.to_path_buf(),
        }];
    }
    Vec::new()
}

/// Uri-mode key dispatch: Enter submits the typed URI, printable
/// `KeyCode::Char` (without Ctrl/Alt) appends to `uri_text`, and
/// `KeyCode::Backspace` pops the trailing character. All other keys
/// are silent no-ops so the modal-trap contract holds.
fn route_add_uri_mode_input(
    path: &std::path::Path,
    add: &mut AddModal,
    key: &KeyEvent,
) -> Vec<Effect> {
    if matches!(key.code, KeyCode::Enter) {
        return vec![Effect::AddFromUri {
            path: path.to_path_buf(),
            uri: add.uri_text.take(),
        }];
    }
    if let KeyCode::Char(c) = key.code {
        if !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            add.uri_text.push(c);
        }
        return Vec::new();
    }
    if matches!(key.code, KeyCode::Backspace) {
        add.uri_text.pop();
    }
    Vec::new()
}

/// Settings modal's input path.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)": *"`Tab` and
/// `Ctrl-N` move to the next control, `Shift-Tab` and `Ctrl-P` move
/// to the previous control … `Space` toggles the focused checkbox /
/// toggle … `↑` / `↓` adjust spinners … The spinners clamp to the
/// shared core bounds."* The Settings modal cycles
/// [`SettingsFocus`], flips the focused boolean, and adjusts the
/// focused spinner by the field's MIN granule
/// (`AUTO_LOCK_SECS_MIN = 30` for `auto_lock.timeout_secs`;
/// `CLIPBOARD_CLEAR_SECS_MIN = 5` for `clipboard.clear_secs`),
/// clamping at both ends. `↑` / `↓` on a toggle-focused field and
/// Space on a spinner-focused field are silent no-ops so the
/// modal-trap contract holds.
///
/// `Enter` diffs the modal's pending fields against the live
/// [`paladin_core::VaultSettings`] and emits a single
/// [`Effect::ApplySettings`] carrying exactly the changed
/// [`SettingPatch`]es (declaration order of [`SettingsFocus`]). An
/// empty diff closes the modal in place without emitting any effect
/// — per `docs/IMPLEMENTATION_PLAN_03_TUI.md` > Settings modal: *"Confirm
/// with no changes closes the modal without invoking save."*
/// Every other key is a silent no-op; Esc / Help / Ctrl-C are
/// filtered upstream of the modal trap. The bool in the tuple return
/// signals the caller to clear the modal slot on the no-change Enter
/// path.
fn route_settings_modal_input(
    path: &std::path::Path,
    settings: &mut SettingsModal,
    vault: &Vault,
    key: &KeyEvent,
) -> (Vec<Effect>, bool) {
    if is_modal_focus_next(key) {
        settings.focus = settings.focus.next();
        return (Vec::new(), false);
    }
    if is_modal_focus_prev(key) {
        settings.focus = settings.focus.prev();
        return (Vec::new(), false);
    }
    if matches!(key.code, KeyCode::Char(' ')) {
        match settings.focus {
            SettingsFocus::AutoLockEnabled => {
                settings.auto_lock_enabled = !settings.auto_lock_enabled;
            }
            SettingsFocus::ClipboardClearEnabled => {
                settings.clipboard_clear_enabled = !settings.clipboard_clear_enabled;
            }
            SettingsFocus::AutoLockTimeoutSecs | SettingsFocus::ClipboardClearSecs => {
                // Spinner-only fields: Space is a silent no-op so the
                // modal-trap contract holds.
            }
        }
        return (Vec::new(), false);
    }
    if matches!(key.code, KeyCode::Up | KeyCode::Down) {
        let delta_up = matches!(key.code, KeyCode::Up);
        match settings.focus {
            SettingsFocus::AutoLockTimeoutSecs => {
                settings.auto_lock_timeout_secs = step_spinner(
                    settings.auto_lock_timeout_secs,
                    delta_up,
                    paladin_core::AUTO_LOCK_SECS_MIN,
                    paladin_core::AUTO_LOCK_SECS_MAX,
                );
            }
            SettingsFocus::ClipboardClearSecs => {
                settings.clipboard_clear_secs = step_spinner(
                    settings.clipboard_clear_secs,
                    delta_up,
                    paladin_core::CLIPBOARD_CLEAR_SECS_MIN,
                    paladin_core::CLIPBOARD_CLEAR_SECS_MAX,
                );
            }
            SettingsFocus::AutoLockEnabled | SettingsFocus::ClipboardClearEnabled => {
                // Toggle-only fields: ↑/↓ is a silent no-op so the
                // modal-trap contract holds.
            }
        }
        return (Vec::new(), false);
    }
    if matches!(key.code, KeyCode::Enter) {
        let patches = pending_settings_diff(settings, vault);
        if patches.is_empty() {
            return (Vec::new(), true);
        }
        return (
            vec![Effect::ApplySettings {
                path: path.to_path_buf(),
                patches,
            }],
            false,
        );
    }
    (Vec::new(), false)
}

/// Diff the [`SettingsModal`] modal-local pending fields against the
/// live [`paladin_core::VaultSettings`] and return one
/// [`SettingPatch`] per changed field. The patch list is emitted in
/// [`SettingsFocus`] declaration order (auto-lock toggle → auto-lock
/// spinner → clipboard toggle → clipboard spinner) so the
/// `EffectResult::Settings` round trip is deterministic and the
/// executor's per-patch error reporting picks the same field the user
/// last edited when bounds are violated.
///
/// An empty list means the user pressed Confirm without altering any
/// pending field; the reducer skips emitting an effect and closes
/// the modal in place.
fn pending_settings_diff(modal: &SettingsModal, vault: &Vault) -> Vec<SettingPatch> {
    let current = vault.settings();
    let mut patches = Vec::new();
    if modal.auto_lock_enabled != current.auto_lock_enabled() {
        patches.push(SettingPatch::AutoLockEnabled(modal.auto_lock_enabled));
    }
    if modal.auto_lock_timeout_secs != current.auto_lock_timeout_secs() {
        patches.push(SettingPatch::AutoLockTimeoutSecs(
            modal.auto_lock_timeout_secs,
        ));
    }
    if modal.clipboard_clear_enabled != current.clipboard_clear_enabled() {
        patches.push(SettingPatch::ClipboardClearEnabled(
            modal.clipboard_clear_enabled,
        ));
    }
    if modal.clipboard_clear_secs != current.clipboard_clear_secs() {
        patches.push(SettingPatch::ClipboardClearSecs(modal.clipboard_clear_secs));
    }
    patches
}

/// Apply one ↑/↓ press to a spinner field. The step granule is the
/// field's MIN bound (the natural unit for that range — 30 s for
/// auto-lock, 5 s for clipboard); the result is clamped to the
/// inclusive `min..=max` range so saturation at either end is a
/// silent no-op rather than wrapping or overshooting. Implements the
/// "spinners clamp to the shared core bounds" rule from
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)".
fn step_spinner(current: u32, up: bool, min: u32, max: u32) -> u32 {
    let step = min;
    if up {
        current.saturating_add(step).min(max)
    } else {
        current.saturating_sub(step).max(min)
    }
}

/// `true` when `key` is the modal-local "advance focus" trigger:
/// bare `Tab` or `Ctrl-N`. `Ctrl-N` requires exactly
/// `KeyModifiers::CONTROL` so `Ctrl-Shift-N` / `Ctrl-Alt-N` stay
/// unbound, matching the existing strict-modifier convention used by
/// [`ctrl_chord_list_step`].
fn is_modal_focus_next(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Tab)
        || (key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('n')))
}

/// `true` when `key` is the modal-local "retreat focus" trigger:
/// `BackTab` (crossterm's report for `Shift-Tab`) or `Ctrl-P`.
fn is_modal_focus_prev(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::BackTab)
        || (key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('p')))
}

/// Remove modal's input path.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Remove:
/// confirmation modal whose only affordance is `Enter` to confirm
/// removal. `Enter` emits [`Effect::Remove`] carrying the
/// snapshotted `account_id`. Every other key (printable Chars,
/// Backspace, arrows, Tab) is a silent no-op — Remove has no
/// editable draft, so the modal-trap contract holds (bare-letter
/// keys do not leak to the list view). Esc / Help / Ctrl-C are
/// filtered upstream of the modal trap.
fn route_remove_modal_input(
    path: &std::path::Path,
    remove: &mut RemoveModal,
    key: &KeyEvent,
) -> Vec<Effect> {
    match key.code {
        KeyCode::Enter => vec![Effect::Remove {
            path: path.to_path_buf(),
            account_id: remove.account_id,
        }],
        _ => Vec::new(),
    }
}

/// Rename modal's input path.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Rename:
/// printable Chars append to `draft`, Backspace pops, Enter validates
/// through [`paladin_core::validate_label`] and either emits
/// [`Effect::Rename`] (with the trimmed draft) or surfaces an inline
/// `error` (`empty` / `too_long`). Any edit clears the inline error
/// so the user sees their retry; the upstream Ctrl/Alt guard filters
/// modifier-bearing Chars before this routing runs. Tab / Shift-Tab
/// / arrows / other unbound keys are silent no-ops at this slice —
/// Rename has only one field, so modal-local focus traversal is
/// observable only as no-ops until additional fields land. Esc /
/// Help / Ctrl-C are filtered upstream of the modal trap.
fn route_rename_modal_input(
    path: &std::path::Path,
    rename: &mut RenameModal,
    key: &KeyEvent,
) -> Vec<Effect> {
    match key.code {
        KeyCode::Char(c) => {
            rename.draft.push(c);
            rename.error = None;
            Vec::new()
        }
        KeyCode::Backspace => {
            rename.draft.pop();
            rename.error = None;
            Vec::new()
        }
        KeyCode::Enter => match validate_label(&rename.draft) {
            Ok(trimmed) => vec![Effect::Rename {
                path: path.to_path_buf(),
                account_id: rename.account_id,
                new_label: trimmed,
            }],
            Err(err) => {
                rename.error = Some(render_error_message(&err));
                Vec::new()
            }
        },
        _ => Vec::new(),
    }
}

/// Apply a single text-editing keystroke to a modal text buffer.
///
/// This is the shared per-field text-edit routine the v0.2 Edit modal
/// rows (Label / Issuer / Slug) route through so the three rows cannot
/// drift in their editing semantics. It handles the printable-`Char`
/// append and `Backspace` pop. Returns `true` when the keystroke was a
/// recognized text-editing key (so the caller can clear any inline
/// error to surface the user's retry), `false` otherwise.
///
/// The shared `route_modal_input` Ctrl/Alt guard filters
/// modifier-bearing `Char`s before this routing runs, so a bare `Char`
/// is safe to append.
fn apply_modal_text_edit(buffer: &mut String, key: &KeyEvent) -> bool {
    match key.code {
        KeyCode::Char(c) => {
            buffer.push(c);
            true
        }
        KeyCode::Backspace => {
            buffer.pop();
            true
        }
        _ => false,
    }
}

/// v0.2 Edit modal's input path (`Shift+E`).
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Edit"
/// and the "Edit modal" test inventory:
///
/// - `Tab` / `Shift-Tab` (and `Ctrl-N` / `Ctrl-P`) cycle focus across
///   the focusable controls in document order. The cycle length is
///   three stops (Label → Issuer → Icon hint) by default and four
///   stops (Label → Issuer → Icon hint → Slug) when the icon-hint
///   selector is on *Slug:*. The pure-logic cycle lives on
///   [`EditModal::next_focus`] / [`EditModal::prev_focus`].
/// - Printable `KeyCode::Char` keystrokes route to the focused text
///   row: Label / Issuer / Slug (when *Slug:* is active and the slug
///   row is focused). Typing while the slug row is disabled is a
///   silent no-op so accidental focus state cannot mutate the
///   buffer.
/// - `Backspace` pops the trailing byte from the focused buffer
///   (Label / Issuer / Slug); no-op on the icon-hint selector row.
/// - `←` / `→` on the icon-hint selector cycles its four options;
///   `←` / `→` on text-input rows are silent no-ops.
/// - Typing into any row clears the modal's inline error so the user
///   sees their retry.
/// - `Enter` runs the three-step locked pre-check ordering: explicit
///   empty-edit guard → [`validate_account_edit`] → [`Vault::find_duplicate_after_edit`].
///   The first failure wins; subsequent checks are skipped. On a
///   passing draft the reducer emits [`Effect::EditAccountMetadata`].
fn route_edit_modal_input(
    path: &std::path::Path,
    edit: &mut EditModal,
    vault: &Vault,
    key: &KeyEvent,
) -> Vec<Effect> {
    // Focus-cycle triggers go first so Tab / Ctrl-N never reach the
    // per-row text handler.
    if is_modal_focus_next(key) {
        edit.focus = edit.next_focus();
        return Vec::new();
    }
    if is_modal_focus_prev(key) {
        edit.focus = edit.prev_focus();
        return Vec::new();
    }

    match key.code {
        KeyCode::Char(_) | KeyCode::Backspace => {
            match edit.focus {
                EditFocus::Label => {
                    apply_modal_text_edit(&mut edit.label_buffer, key);
                    edit.error = None;
                }
                EditFocus::Issuer => {
                    apply_modal_text_edit(&mut edit.issuer_buffer, key);
                    edit.error = None;
                }
                EditFocus::IconHint => {
                    // No text input on the selector row.
                }
                EditFocus::Slug => {
                    // Defensive: only mutate the slug buffer when the
                    // slug row is actually enabled (selector on
                    // *Slug:*). Focus state can only land on Slug
                    // when the selector is on *Slug:* per
                    // `next_focus` / `prev_focus`, so this is a
                    // belt-and-braces guard for future refactors.
                    if edit.icon_hint_selector == EditIconHintSelector::Slug {
                        apply_modal_text_edit(&mut edit.icon_hint_slug, key);
                        edit.error = None;
                    }
                }
            }
            Vec::new()
        }
        KeyCode::Left if edit.focus == EditFocus::IconHint => {
            edit.icon_hint_selector = edit.icon_hint_selector.prev();
            edit.error = None;
            Vec::new()
        }
        KeyCode::Right if edit.focus == EditFocus::IconHint => {
            edit.icon_hint_selector = edit.icon_hint_selector.next();
            edit.error = None;
            Vec::new()
        }
        KeyCode::Enter => classify_edit_submit(path, edit, vault),
        _ => Vec::new(),
    }
}

/// Run the three-step locked pre-check ordering (empty → validate →
/// `find_duplicate_after_edit`) on a submit and either emit
/// [`Effect::EditAccountMetadata`] or stash the inline error.
///
/// Pure-logic helper so reducer tests can exercise the ordering
/// without driving through the `KeyCode::Enter` arm.
fn classify_edit_submit(
    path: &std::path::Path,
    edit: &mut EditModal,
    vault: &Vault,
) -> Vec<Effect> {
    let projection = project_edit(edit);

    // Step 1: explicit reducer-side empty-edit guard. Mirrors the
    // mutator-side guard in `Vault::edit_account_metadata` so the
    // modal surfaces an inline error without ever reaching the
    // executor.
    if projection.label.is_none() && projection.issuer.is_none() && projection.icon_hint.is_none() {
        edit.error = Some(render_error_message(&PaladinError::ValidationError {
            field: "edit",
            reason: "empty".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
        return Vec::new();
    }

    // Step 2: per-field validation. First failure wins per the
    // locked order in `validate_account_edit`. The `prior` lookup is
    // best-effort; if the account has been removed out from under
    // the modal we surface the same `invalid_state` the executor
    // would.
    let Some(prior_account) = vault.iter().find(|a| a.id() == edit.account_id) else {
        edit.error = Some(render_error_message(&PaladinError::InvalidState {
            operation: "edit_account_metadata",
            state: "account_not_found",
        }));
        return Vec::new();
    };
    if let Err(err) =
        validate_account_edit(&projection, prior_account, std::time::SystemTime::now())
    {
        edit.error = Some(render_error_message(&err));
        return Vec::new();
    }

    // Step 3: pre-submit duplicate check against the live vault.
    if let Some(existing) = vault.find_duplicate_after_edit(edit.account_id, &projection) {
        let existing_summary = existing.summary();
        edit.error = Some(format_duplicate_account_message(&existing_summary));
        return Vec::new();
    }

    // All pre-checks passed; clear any stale inline error and emit
    // the effect.
    edit.error = None;
    vec![Effect::EditAccountMetadata {
        path: path.to_path_buf(),
        account_id: edit.account_id,
        edit: projection,
    }]
}

/// Project the in-flight modal buffers onto a
/// [`paladin_core::AccountEdit`].
///
/// WYSIWYS rules per `docs/IMPLEMENTATION_PLAN_03_TUI.md`:
/// - Label buffer byte-equal to the prior label → `label: None`.
/// - Issuer buffer byte-equal to the prior issuer's `Some(_)` arm
///   → `issuer: None` (leave untouched). An empty buffer when prior
///   was `Some(_)` → `Some(None)` (clear). An empty buffer when
///   prior was `None` → `None` (already cleared). A divergent non-
///   empty buffer → `Some(Some(buffer))`. Whitespace-only buffers
///   collapse to the same projection an empty buffer would produce
///   for the corresponding prior, mirroring the validator's
///   §4.1-trim contract.
/// - Icon-hint selector → tri-state per [`EditIconHintSelector`].
fn project_edit(edit: &EditModal) -> AccountEdit {
    let label = if edit.label_buffer == edit.prior.label {
        None
    } else {
        Some(edit.label_buffer.clone())
    };

    let trimmed_issuer = edit.issuer_buffer.trim();
    let issuer = match edit.prior.issuer.as_deref() {
        None => {
            // Prior was None.
            if trimmed_issuer.is_empty() {
                // Buffer is empty / whitespace-only and prior was
                // already None — projection is a no-op.
                None
            } else if edit.issuer_buffer == *edit.prior.issuer.as_deref().unwrap_or("") {
                // Defensive: byte-equal to prior empty is unreachable
                // here because we already checked `trimmed_issuer.is_empty`.
                None
            } else {
                Some(Some(edit.issuer_buffer.clone()))
            }
        }
        Some(prior_issuer) => {
            if edit.issuer_buffer == prior_issuer {
                // Buffer byte-equal to prior → leave untouched.
                None
            } else if trimmed_issuer.is_empty() {
                // Buffer empty / whitespace-only against a `Some(_)`
                // prior → clear.
                Some(None)
            } else {
                Some(Some(edit.issuer_buffer.clone()))
            }
        }
    };

    let icon_hint = match edit.icon_hint_selector {
        EditIconHintSelector::LeaveUnchanged => None,
        EditIconHintSelector::Default => Some(IconHintInput::Default),
        EditIconHintSelector::Clear => Some(IconHintInput::Clear),
        EditIconHintSelector::Slug => match validate_icon_hint_slug(&edit.icon_hint_slug) {
            Ok(input) => Some(input),
            // Defer the surfacing to the validator step; we still
            // emit a `Some(IconHintInput::Slug(...))` carrying the
            // raw buffer so `validate_account_edit` produces the
            // canonical `invalid_slug` / `invalid_chars` /
            // `too_long` error consistent with the rest of the
            // stack.
            Err(_) => Some(IconHintInput::Slug(edit.icon_hint_slug.clone())),
        },
    };

    AccountEdit {
        label,
        issuer,
        icon_hint,
    }
}

/// Import modal's input path.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Import:
/// the modal collects a source path, a format selector (auto-detect or
/// explicit `otpauth` / `aegis` / `paladin` / `qr`), and an
/// on-conflict selector.
///
/// The modal runs in one of two phases keyed off
/// [`ImportModal::paladin_passphrase`]:
///
/// - **Path-entry phase** (`paladin_passphrase.is_none()`, the
///   default). Printable `KeyCode::Char` keystrokes (no `Ctrl` /
///   `Alt` modifier — mirroring the Unlock-screen filter) append to
///   the `path_text` buffer; `KeyCode::Backspace` pops the trailing
///   character. Any edit clears the inline `error` so the user sees
///   their retry. `KeyCode::Enter` runs
///   [`paladin_core::classify_paladin_import_precheck`] over the
///   trimmed `source_path` + forced format selector:
///   - [`PaladinImportPrecheck::NoPrompt`] emits
///     [`Effect::Import`] with `paladin_passphrase: None`. This
///     covers missing files, non-Paladin payloads, and forced
///     non-Paladin formats — `import::from_file` owns the per-format
///     failure surfaces from there.
///   - [`PaladinImportPrecheck::Reject`] surfaces the carried
///     [`PaladinError`] inline through `import.error` and emits no
///     effect; the modal stays open in path-entry phase so the user
///     can retry / cancel.
///   - [`PaladinImportPrecheck::PromptForPassphrase`] transitions
///     the modal to the passphrase-entry phase by seeding
///     `import.paladin_passphrase = Some(PassphraseBuffer::new())`.
///     No effect is emitted; the next `Enter` submits with the
///     buffered passphrase.
/// - **Passphrase-entry phase** (`paladin_passphrase.is_some()`).
///   Printable `KeyCode::Char` keystrokes append to the
///   [`PassphraseBuffer`]; `KeyCode::Backspace` pops the trailing
///   character. Any edit clears the inline `error`.
///   `KeyCode::Enter` consumes the buffered passphrase through
///   [`PassphraseBuffer::take`] (zeroizing the buffer in place) and
///   emits [`Effect::Import`] with `paladin_passphrase: Some(_)`.
///   The buffer is dropped on modal close / auto-lock so leftover
///   bytes never outlive the modal.
///
/// Other keys (`Tab` / `Shift-Tab` / arrows / unbound chords) are
/// silent no-ops at this slice — the format / conflict selector
/// navigation lands alongside its slice.
///
/// Esc / Help / Ctrl-C are filtered upstream of the modal trap.
fn route_import_modal_input(
    path: &std::path::Path,
    import: &mut ImportModal,
    key: &KeyEvent,
) -> Vec<Effect> {
    let has_passphrase_phase = import.paladin_passphrase.is_some();
    match key.code {
        KeyCode::Char(c)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            if let Some(buf) = import.paladin_passphrase.as_mut() {
                buf.push(c);
            } else {
                import.path_text.push(c);
            }
            import.error = None;
            Vec::new()
        }
        KeyCode::Backspace => {
            if let Some(buf) = import.paladin_passphrase.as_mut() {
                buf.pop();
            } else {
                import.path_text.pop();
            }
            import.error = None;
            Vec::new()
        }
        KeyCode::Enter if has_passphrase_phase => {
            // SAFETY: `has_passphrase_phase` was sampled at the top
            // of the function; nothing between there and here mutates
            // `paladin_passphrase` away from `Some`.
            let buf = import
                .paladin_passphrase
                .as_mut()
                .expect("passphrase phase implies Some(buffer)");
            let secret = buf.take();
            let source_path = std::path::PathBuf::from(import.path_text.trim());
            vec![Effect::Import {
                path: path.to_path_buf(),
                source_path,
                format: import.format.forced(),
                conflict: import.conflict,
                paladin_passphrase: Some(secret),
            }]
        }
        KeyCode::Enter => {
            let source_path = std::path::PathBuf::from(import.path_text.trim());
            let forced_format = import.format.forced();
            match classify_paladin_import_precheck(&source_path, forced_format) {
                PaladinImportPrecheck::NoPrompt => {
                    vec![Effect::Import {
                        path: path.to_path_buf(),
                        source_path,
                        format: forced_format,
                        conflict: import.conflict,
                        paladin_passphrase: None,
                    }]
                }
                PaladinImportPrecheck::Reject(err) => {
                    import.error = Some(render_error_message(&err));
                    Vec::new()
                }
                PaladinImportPrecheck::PromptForPassphrase => {
                    import.paladin_passphrase = Some(PassphraseBuffer::new());
                    import.error = None;
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    }
}

/// Export modal's input path.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Export:
/// *"Overwriting an existing file is rejected unless the user
/// confirms an inline overwrite gate (parity with CLI `--force`)."*
/// The refused-overwrite gate is the first submit-time check: if the
/// trimmed `path_text` resolves to a path that already exists on
/// disk, the reducer rejects Enter inline — no [`Effect::Export`] is
/// emitted, the modal stays open, and the rendered
/// [`PaladinError::ValidationError`] with `field = "path"` /
/// `reason = "output_exists"` lands in
/// [`ExportModal::error`](crate::app::state::ExportModal::error) so
/// the wording matches `paladin-cli/src/commands/export.rs`'s
/// `refuse_existing_overwrite` (docs/DESIGN.md §5) and the GTK
/// `overwrite_gate_needs_reset` flow.
///
/// The second submit-time check is the encrypted twice-confirm
/// passphrase gate. Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals
/// (per §6)" > Export: *"Encrypted exports prompt twice for the
/// bundle passphrase ..."*. When `format = ExportFormat::Encrypted`
/// and the two typed buffers differ byte-for-byte, the reducer
/// surfaces a rendered
/// [`PaladinError::InvalidPassphrase`] with
/// `reason = "confirmation_mismatch"` inline on
/// [`ExportModal::error`](crate::app::state::ExportModal::error) so
/// the wording matches the CLI's `prompt_new_passphrase`
/// (`paladin-cli/src/prompt.rs`, docs/DESIGN.md §5) and the GTK
/// `SubmitRejection::ConfirmationMismatch` wire code.
///
/// The third submit-time check is the zero-length passphrase gate.
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests" > Export modal:
/// *"Encrypted export rejects empty new passphrase with
/// `zero_length`."*. When `format = ExportFormat::Encrypted` and the
/// twice-confirmed buffer is empty (both rows blank slip past the
/// equality check above), the reducer surfaces a rendered
/// [`PaladinError::InvalidPassphrase`] with `reason = "zero_length"`
/// inline on
/// [`ExportModal::error`](crate::app::state::ExportModal::error). Gate
/// order mirrors the CLI's `prompt_new_passphrase` (mismatch first,
/// then `zero_length`) and the GTK `SubmitRejection::ZeroLength` wire
/// code so the user-facing reason stays stable across all three
/// front-ends.
///
/// The plaintext path has its own submit-time check: the
/// unencrypted-secrets acknowledgement gate. Per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Export:
/// *"Plaintext exports render
/// `paladin_core::format_plaintext_export_warning()` verbatim and the
/// user must confirm before the write proceeds."*. When
/// `format = ExportFormat::Plaintext` and
/// [`ExportModal::plaintext_confirmed`](crate::app::state::ExportModal::plaintext_confirmed)
/// is still `false`, the reducer refuses the submit — no
/// [`Effect::Export`] is emitted and
/// [`paladin_core::format_plaintext_export_warning`] lands verbatim
/// on [`ExportModal::error`](crate::app::state::ExportModal::error) so
/// the wording matches the CLI's stderr advisory
/// (`paladin-cli/src/commands/export.rs`, docs/DESIGN.md §4.6 / §6) and
/// the GTK `ExportDialog`'s `plaintext_warning_body()` checkbox label.
///
/// Once every gate passes, the reducer emits a single
/// [`Effect::Export`] carrying the current vault path, the trimmed
/// destination path, the format selector, and — on the encrypted path
/// — the typed passphrase as a `SecretString` produced by
/// [`PassphraseBuffer::take`]. The companion `confirm_passphrase`
/// buffer is wiped via [`PassphraseBuffer::clear`] in the same step so
/// both halves of the twice-prompt zeroize on submit per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests > Sensitive UI buffers":
/// *"Encrypted export passphrase buffer zeroizes on submit, cancel,
/// modal close, and auto-lock."* The plaintext path emits the same
/// [`Effect::Export`] shape with `passphrase = None`.
///
/// The plaintext-confirmation toggle key handler lands alongside its
/// own checklist entry; until then this slice consumes Enter and
/// treats all other keys as a silent no-op so the modal-trap contract
/// holds.
fn route_export_modal_input(
    path: &std::path::Path,
    export: &mut ExportModal,
    key: &KeyEvent,
) -> Vec<Effect> {
    if matches!(key.code, KeyCode::Enter) {
        let target = std::path::PathBuf::from(export.path_text.trim());
        if matches!(target.try_exists(), Ok(true)) {
            export.error = Some(render_error_message(&PaladinError::ValidationError {
                field: "path",
                reason: "output_exists".to_string(),
                source_index: None,
                decoded_len: None,
                recommended_min: None,
                entry_type: None,
            }));
            return Vec::new();
        }
        if matches!(export.format, ExportFormat::Encrypted)
            && export.new_passphrase.as_str() != export.confirm_passphrase.as_str()
        {
            export.error = Some(render_error_message(&PaladinError::InvalidPassphrase {
                reason: "confirmation_mismatch",
            }));
            return Vec::new();
        }
        if matches!(export.format, ExportFormat::Encrypted) && export.new_passphrase.is_empty() {
            export.error = Some(render_error_message(&PaladinError::InvalidPassphrase {
                reason: "zero_length",
            }));
            return Vec::new();
        }
        if matches!(export.format, ExportFormat::Plaintext) && !export.plaintext_confirmed {
            export.error = Some(format_plaintext_export_warning());
            return Vec::new();
        }
        let passphrase = match export.format {
            ExportFormat::Encrypted => {
                let secret = export.new_passphrase.take();
                export.confirm_passphrase.clear();
                Some(secret)
            }
            ExportFormat::Plaintext => None,
        };
        return vec![Effect::Export {
            path: path.to_path_buf(),
            target_path: target,
            format: export.format,
            passphrase,
        }];
    }
    Vec::new()
}

/// QR Export modal's input path (v0.2; DESIGN §4.6 / §6).
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > QR Export
/// the modal is a small two-page state machine. The reducer arms here
/// cover the **read-only** axis (open / ack-toggle / focus-cycle /
/// Enter on Cancel or Done); the save sub-flow (destination prompt,
/// overwrite gate, PNG / SVG executors) lands in a follow-up slice.
///
/// Returns `true` if the modal should close (Enter on Cancel on
/// Page 1, Enter on Done on Page 2). `Esc` is handled by
/// [`apply_esc_dismiss`] upstream and never reaches this routine.
///
/// **Page 1 keys** — `Space` on the ack checkbox toggles `ack`. The
/// toggle-on path immediately advances to
/// [`QrExportPage::QrAndActions`] and populates `staged_ansi` via
/// [`paladin_core::Vault::export_qr_ansi`] (the
/// `account_not_found` path stores the rendered error inline rather
/// than crashing). The toggle-off path drops `staged_ansi` and
/// returns to [`QrExportPage::WarningAck`]. `Tab` / `Ctrl-N` advance
/// focus forward (Ack → Cancel → Ack) and `Shift-Tab` / `Ctrl-P`
/// retreat. `Enter` on [`QrExportFocus::CancelButton`] closes the
/// modal; `Enter` on [`QrExportFocus::AckCheckbox`] toggles the ack
/// (same wiring as `Space`).
///
/// **Page 2 keys** — `Tab` / `Ctrl-N` advance focus among
/// `SavePngButton` / `SaveSvgButton` / `DoneButton` (wrapping);
/// `Shift-Tab` / `Ctrl-P` retreat. `Enter` on
/// [`QrExportFocus::DoneButton`] closes the modal. `Enter` on the
/// Save buttons is reserved for the save sub-flow slice (currently a
/// silent no-op so the modal-trap contract holds).
fn route_qr_export_modal_input(
    path: &std::path::Path,
    qr: &mut QrExportModal,
    vault: &Vault,
    key: &KeyEvent,
) -> (Vec<Effect>, bool) {
    // Active sub-flow gets first crack at input — Tab/focus cycling
    // and Enter/Space land on the sub-flow's controls, not the
    // Page-2 button row.
    if qr.save_sub_flow.is_some() {
        return route_qr_save_sub_flow_input(path, qr, key);
    }

    if is_modal_focus_next(key) {
        qr.focus = qr_export_focus_next(qr.focus, qr.page);
        return (Vec::new(), false);
    }
    if is_modal_focus_prev(key) {
        qr.focus = qr_export_focus_prev(qr.focus, qr.page);
        return (Vec::new(), false);
    }
    match qr.page {
        QrExportPage::WarningAck => match key.code {
            KeyCode::Char(' ') if qr.focus == QrExportFocus::AckCheckbox => {
                toggle_qr_export_ack(qr, vault);
                (Vec::new(), false)
            }
            KeyCode::Enter => match qr.focus {
                QrExportFocus::AckCheckbox => {
                    toggle_qr_export_ack(qr, vault);
                    (Vec::new(), false)
                }
                QrExportFocus::CancelButton => (Vec::new(), true),
                _ => (Vec::new(), false),
            },
            _ => (Vec::new(), false),
        },
        QrExportPage::QrAndActions => match key.code {
            KeyCode::Char(' ') if qr.focus == QrExportFocus::AckCheckbox => {
                // The ack control still owns the toggle even when the
                // user has Tabbed back to it from Page 2's button row
                // (defensive — the focus enum is shared across pages,
                // and a future redesign that surfaces the ack on
                // Page 2 should not silently drop the bind).
                toggle_qr_export_ack(qr, vault);
                (Vec::new(), false)
            }
            KeyCode::Enter => match qr.focus {
                QrExportFocus::DoneButton => (Vec::new(), true),
                QrExportFocus::SavePngButton => {
                    qr.save_sub_flow = Some(QrSaveSubFlow::new(QrSaveFormat::Png));
                    qr.error = None;
                    (Vec::new(), false)
                }
                QrExportFocus::SaveSvgButton => {
                    qr.save_sub_flow = Some(QrSaveSubFlow::new(QrSaveFormat::Svg));
                    qr.error = None;
                    (Vec::new(), false)
                }
                _ => (Vec::new(), false),
            },
            _ => (Vec::new(), false),
        },
    }
}

/// QR Export modal save sub-flow input path.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
/// QR Export, the sub-flow is a two-step state machine:
///
/// * [`QrSaveStep::EnterPath`] — the user types a destination path.
///   `Enter` on [`QrSaveFocus::Confirm`] validates the path: empty
///   rejects inline; an existing path flips to
///   [`QrSaveStep::OverwriteGate`] (no effect emitted); otherwise
///   emits [`Effect::QrExport`].
/// * [`QrSaveStep::OverwriteGate`] — the destination exists. The
///   user toggles [`QrSaveSubFlow::overwrite_ack`] and re-confirms;
///   refused acks reject inline and the existing file stays
///   byte-stable. Editing the path returns the step to
///   [`QrSaveStep::EnterPath`] so a stale ack cannot apply to a
///   different destination.
///
/// `Esc` cancels the sub-flow back to Page 2 — handled upstream in
/// [`apply_esc_dismiss`] so the typed buffer drops before any
/// rendering pass. `Tab` / `Ctrl-N` advance focus and
/// `Shift-Tab` / `Ctrl-P` retreat within the active step's control
/// set.
fn route_qr_save_sub_flow_input(
    path: &std::path::Path,
    qr: &mut QrExportModal,
    key: &KeyEvent,
) -> (Vec<Effect>, bool) {
    let account_id = qr.account_id;
    let Some(sub) = qr.save_sub_flow.as_mut() else {
        return (Vec::new(), false);
    };

    if is_modal_focus_next(key) {
        sub.focus = qr_save_focus_next(sub.focus, sub.step);
        return (Vec::new(), false);
    }
    if is_modal_focus_prev(key) {
        sub.focus = qr_save_focus_prev(sub.focus, sub.step);
        return (Vec::new(), false);
    }

    match key.code {
        KeyCode::Char(c) if sub.focus == QrSaveFocus::PathField => {
            // Editing the path invalidates any prior overwrite ack
            // so a stale ack cannot apply to a different
            // destination.
            sub.path_text.push(c);
            sub.step = QrSaveStep::EnterPath;
            sub.overwrite_ack = false;
            sub.error = None;
            (Vec::new(), false)
        }
        KeyCode::Backspace if sub.focus == QrSaveFocus::PathField => {
            sub.path_text.pop();
            sub.step = QrSaveStep::EnterPath;
            sub.overwrite_ack = false;
            sub.error = None;
            (Vec::new(), false)
        }
        KeyCode::Char(' ') if sub.focus == QrSaveFocus::OverwriteAck => {
            sub.overwrite_ack = !sub.overwrite_ack;
            sub.error = None;
            (Vec::new(), false)
        }
        KeyCode::Enter => match sub.focus {
            QrSaveFocus::Cancel => {
                qr.save_sub_flow = None;
                qr.focus = QrExportFocus::SavePngButton;
                (Vec::new(), false)
            }
            QrSaveFocus::OverwriteAck => {
                sub.overwrite_ack = !sub.overwrite_ack;
                sub.error = None;
                (Vec::new(), false)
            }
            QrSaveFocus::PathField | QrSaveFocus::Confirm => {
                submit_qr_save_sub_flow(path, qr, account_id)
            }
        },
        _ => (Vec::new(), false),
    }
}

/// Validate the sub-flow's path + overwrite-ack state and either
/// emit [`Effect::QrExport`] or stash an inline error.
fn submit_qr_save_sub_flow(
    path: &std::path::Path,
    qr: &mut QrExportModal,
    account_id: AccountId,
) -> (Vec<Effect>, bool) {
    let Some(sub) = qr.save_sub_flow.as_mut() else {
        return (Vec::new(), false);
    };
    let trimmed = sub.path_text.trim();
    if trimmed.is_empty() {
        sub.error = Some(render_error_message(&PaladinError::ValidationError {
            field: "path",
            reason: "empty_path".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
        return (Vec::new(), false);
    }
    let target = std::path::PathBuf::from(trimmed);
    let exists = matches!(target.try_exists(), Ok(true));
    if exists && !sub.overwrite_ack {
        // First Confirm against an existing path flips the sub-flow
        // into the overwrite gate; a follow-up Confirm with the ack
        // off rejects inline with the refused-overwrite wording.
        if sub.step == QrSaveStep::EnterPath {
            sub.step = QrSaveStep::OverwriteGate;
            sub.focus = QrSaveFocus::OverwriteAck;
            sub.error = None;
            return (Vec::new(), false);
        }
        sub.error = Some(render_error_message(&PaladinError::ValidationError {
            field: "path",
            reason: "output_exists".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        }));
        return (Vec::new(), false);
    }

    let format = sub.format;
    (
        vec![Effect::QrExport {
            path: path.to_path_buf(),
            target_path: target,
            account_id,
            format,
        }],
        false,
    )
}

/// Advance focus within the save sub-flow, wrapping at either end of
/// the current step's control set.
fn qr_save_focus_next(focus: QrSaveFocus, step: QrSaveStep) -> QrSaveFocus {
    match step {
        QrSaveStep::EnterPath => match focus {
            QrSaveFocus::PathField => QrSaveFocus::Confirm,
            QrSaveFocus::Confirm => QrSaveFocus::Cancel,
            QrSaveFocus::Cancel | QrSaveFocus::OverwriteAck => QrSaveFocus::PathField,
        },
        QrSaveStep::OverwriteGate => match focus {
            QrSaveFocus::PathField => QrSaveFocus::OverwriteAck,
            QrSaveFocus::OverwriteAck => QrSaveFocus::Confirm,
            QrSaveFocus::Confirm => QrSaveFocus::Cancel,
            QrSaveFocus::Cancel => QrSaveFocus::PathField,
        },
    }
}

/// Retreat focus within the save sub-flow, wrapping at either end of
/// the current step's control set.
fn qr_save_focus_prev(focus: QrSaveFocus, step: QrSaveStep) -> QrSaveFocus {
    match step {
        QrSaveStep::EnterPath => match focus {
            QrSaveFocus::Cancel => QrSaveFocus::Confirm,
            QrSaveFocus::Confirm => QrSaveFocus::PathField,
            QrSaveFocus::PathField | QrSaveFocus::OverwriteAck => QrSaveFocus::Cancel,
        },
        QrSaveStep::OverwriteGate => match focus {
            QrSaveFocus::Cancel => QrSaveFocus::Confirm,
            QrSaveFocus::Confirm => QrSaveFocus::OverwriteAck,
            QrSaveFocus::OverwriteAck => QrSaveFocus::PathField,
            QrSaveFocus::PathField => QrSaveFocus::Cancel,
        },
    }
}

/// Toggle the QR Export modal's ack checkbox and apply the
/// page-mount side effects per DESIGN §4.6 / §6.
///
/// Toggling on advances to [`QrExportPage::QrAndActions`] and
/// populates [`QrExportModal::staged_ansi`] via
/// [`paladin_core::Vault::export_qr_ansi`]. Toggling off drops the
/// staged buffer (zeroizing on `Drop`) and returns to
/// [`QrExportPage::WarningAck`]. The page-1 focus snaps to
/// [`QrExportFocus::AckCheckbox`] on toggle-off so the user returns
/// to the same control that triggered the ack; the page-2 focus
/// snaps to [`QrExportFocus::SavePngButton`] on toggle-on so the
/// user's next Enter targets the canonical save path.
///
/// Encoder failures (the `qrcode` crate's `data_too_long` on a
/// payload past QR version 40, or the defensive
/// `account_not_found` path if the vault mutates while the modal is
/// open) render inline through [`render_error_message`] and leave
/// the modal on Page 1 with `ack = false`.
fn toggle_qr_export_ack(qr: &mut QrExportModal, vault: &Vault) {
    if qr.ack {
        // Toggle off: drop staged buffers (and any in-flight save
        // sub-flow) and return to Page 1.
        qr.ack = false;
        qr.staged_ansi = None;
        qr.save_sub_flow = None;
        qr.page = QrExportPage::WarningAck;
        qr.focus = QrExportFocus::AckCheckbox;
        return;
    }
    match vault.export_qr_ansi(qr.account_id) {
        Ok(rendered) => {
            qr.ack = true;
            qr.staged_ansi = Some(rendered);
            qr.page = QrExportPage::QrAndActions;
            qr.focus = QrExportFocus::SavePngButton;
            qr.error = None;
        }
        Err(err) => {
            qr.error = Some(render_error_message(&err));
        }
    }
}

/// Advance focus within the QR Export modal, wrapping at either end
/// of the current page's control set.
fn qr_export_focus_next(focus: QrExportFocus, page: QrExportPage) -> QrExportFocus {
    match page {
        QrExportPage::WarningAck => match focus {
            QrExportFocus::AckCheckbox => QrExportFocus::CancelButton,
            _ => QrExportFocus::AckCheckbox,
        },
        QrExportPage::QrAndActions => match focus {
            QrExportFocus::SavePngButton => QrExportFocus::SaveSvgButton,
            QrExportFocus::SaveSvgButton => QrExportFocus::DoneButton,
            _ => QrExportFocus::SavePngButton,
        },
    }
}

/// Retreat focus within the QR Export modal, wrapping at either end
/// of the current page's control set.
fn qr_export_focus_prev(focus: QrExportFocus, page: QrExportPage) -> QrExportFocus {
    match page {
        QrExportPage::WarningAck => match focus {
            QrExportFocus::CancelButton => QrExportFocus::AckCheckbox,
            _ => QrExportFocus::CancelButton,
        },
        QrExportPage::QrAndActions => match focus {
            QrExportFocus::DoneButton => QrExportFocus::SaveSvgButton,
            QrExportFocus::SaveSvgButton => QrExportFocus::SavePngButton,
            _ => QrExportFocus::DoneButton,
        },
    }
}

/// Passphrase modal's input path (submit axis).
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Passphrase:
/// *"three sub-flows mirroring CLI's `passphrase set / change /
/// remove`. ... New passphrases (`set`, `change`) are prompted twice
/// and confirmed; mismatch returns to the modal with an inline
/// `invalid_passphrase` (`reason: "confirmation_mismatch"`) error.
/// Empty new passphrases are rejected with `invalid_passphrase`
/// (`reason: "zero_length"`)."*
///
/// Validation order for [`PassphraseSubFlow::Set`] /
/// [`PassphraseSubFlow::Change`]: confirmation mismatch first
/// (`new_passphrase != confirm_passphrase` regardless of either
/// being empty), then zero-length (`new_passphrase` empty when the
/// two matched). Both gates render through [`render_error_message`]
/// so the surfaced wording matches the rest of the TUI's error
/// surface.
///
/// On a passing submit the `new_passphrase` buffer is moved through
/// [`crate::prompt::PassphraseBuffer::take`] into the `SecretString`
/// carried by the emitted [`Effect::PassphraseSet`] /
/// [`Effect::PassphraseChange`], and the `confirm_passphrase`
/// sibling is wiped via [`crate::prompt::PassphraseBuffer::clear`]
/// — both operations zeroize in place per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)": *"All
/// passphrase-entry fields ... keep typed bytes in zeroizing
/// buffers, convert to `secrecy::SecretString` only for core calls,
/// and zeroize on submit, cancel, modal close, and auto-lock."*
///
/// [`PassphraseSubFlow::Remove`] does not consume either buffer
/// (the cached key in core decrypts the existing payload before the
/// plaintext rewrite); Enter emits an [`Effect::PassphraseRemove`]
/// carrying only the vault path.
fn route_passphrase_modal_input(
    path: &std::path::Path,
    passphrase: &mut PassphraseModal,
    key: &KeyEvent,
) -> Vec<Effect> {
    if !matches!(key.code, KeyCode::Enter) {
        return Vec::new();
    }
    match passphrase.sub_flow {
        PassphraseSubFlow::Set | PassphraseSubFlow::Change => {
            if passphrase.new_passphrase.as_str() != passphrase.confirm_passphrase.as_str() {
                passphrase.error = Some(render_error_message(&PaladinError::InvalidPassphrase {
                    reason: "confirmation_mismatch",
                }));
                return Vec::new();
            }
            if passphrase.new_passphrase.is_empty() {
                passphrase.error = Some(render_error_message(&PaladinError::InvalidPassphrase {
                    reason: "zero_length",
                }));
                return Vec::new();
            }
            let secret = passphrase.new_passphrase.take();
            passphrase.confirm_passphrase.clear();
            passphrase.error = None;
            let effect = match passphrase.sub_flow {
                PassphraseSubFlow::Set => Effect::PassphraseSet {
                    path: path.to_path_buf(),
                    new_passphrase: secret,
                },
                PassphraseSubFlow::Change => Effect::PassphraseChange {
                    path: path.to_path_buf(),
                    new_passphrase: secret,
                },
                PassphraseSubFlow::Remove => unreachable!("guarded by outer match arm"),
            };
            vec![effect]
        }
        PassphraseSubFlow::Remove => {
            passphrase.error = None;
            vec![Effect::PassphraseRemove {
                path: path.to_path_buf(),
            }]
        }
    }
}

/// Map the (key character, current selection) pair to a status-line
/// error when a selection-gated action key fires without a selected
/// row. Returns `Some(StatusLine::Error(...))` for `n` / `r` / `R`
/// with `selected = None` and `None` for every other shape per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Focus model": *"With no
/// selection, `Enter`, `n`, `r`, and `R` produce a status-line 'no
/// account selected' error and no effect; Add / Import / Export /
/// Passphrase / Settings remain available from list focus."*
///
/// `C` (Shift-c, "copy next code") joins the same gate per
/// DESIGN §6: the selection-empty rejection is uniform with the
/// `n` / `r` / `R` bindings, even though the wrong-kind (HOTP
/// selected) rejection is handled separately by
/// [`copy_next_code_outcome`].
///
/// `Enter` is not bound on Unlocked at this slice — once it gains a
/// show / copy action it joins this gate.
fn selection_gated_status_error(c: char, selected: Option<AccountId>) -> Option<StatusLine> {
    if matches!(c, 'n' | 'r' | 'R' | 'E' | 'C') && selected.is_none() {
        Some(StatusLine::Error(NO_ACCOUNT_SELECTED.to_string()))
    } else {
        None
    }
}

/// Dispatch the post-chord-clear bare-letter Char handling on
/// Unlocked / `Focus::List` (modal-already-open is filtered out
/// upstream).
///
/// Owns the small terminal-letter table: `q` → quit, `/` → focus the
/// search bar, `n` → emit the precomputed HOTP-advance effects, `r`
/// → open the precomputed [`Modal::Remove`] payload, `R` → open the
/// precomputed [`Modal::Rename`] payload, `s` → open the
/// precomputed [`Modal::Settings`] payload, and the
/// `modal_opener_for_char` table (`a`/`i`/`e`/`p`) for the
/// payload-free modals.
///
/// `n_effects` carries the [`Effect::HotpAdvance`] list precomputed
/// by the caller (empty when the binding is a silent no-op — TOTP
/// selection, no selection, or selection missing from the vault).
/// `rename_modal` carries the [`RenameModal`] payload built from the
/// still-borrowed vault for `R` (or `None` for every other char).
/// `remove_modal` carries the [`RemoveModal`] payload for `r` (or
/// `None` otherwise). `settings_modal` carries the
/// [`SettingsModal`] payload snapshotted from the live vault
/// settings for `s` (or `None` otherwise). All are precomputed by
/// the caller so this helper does not borrow the vault.
#[allow(clippy::too_many_arguments)]
fn dispatch_unlocked_char(
    mut state: AppState,
    c: char,
    n_effects: Vec<Effect>,
    rename_modal: Option<RenameModal>,
    edit_modal: Option<EditModal>,
    remove_modal: Option<RemoveModal>,
    settings_modal: Option<SettingsModal>,
    qr_export_modal: Option<QrExportModal>,
    copy_next: Option<CopyNextCodeOutcome>,
) -> (AppState, Vec<Effect>) {
    // `q` quits Unlocked when no modal is open. (Once the search bar
    // can take focus, `q` is text input on the search surface too;
    // that gating lands with the focus-state slice.)
    if c == 'q' {
        return (state, vec![Effect::Quit]);
    }
    // `/` focuses the search bar from the list per the §6 "Focus
    // model" rule. The modal guard above already short-circuits when
    // a modal traps focus, and the chord leader was cleared just
    // above this Char block, so the only remaining work is the
    // `Focus::List -> Focus::Search` transition. Pressing `/` while
    // already in `Focus::Search` is a silent no-op at this slice —
    // character routing into the search field (which would type `/`
    // literally) lands alongside the search-focus typing pass-through.
    if c == '/' {
        if let AppState::Unlocked { focus, .. } = &mut state {
            *focus = Focus::Search;
        }
        return (state, Vec::new());
    }
    if c == 'n' {
        return (state, n_effects);
    }
    if c == '?' {
        // `?` opens the read-only Help overlay from list focus per
        // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Help overlay". This arm
        // is only reached when no modal is open (filtered upstream),
        // focus is `Focus::List` (Focus::Search consumes Char as
        // text input), no Ctrl/Alt modifier is held (filtered
        // upstream), and Help is not already open (the early
        // `*help_open` guard in `reduce_unlocked_input` would have
        // short-circuited). Re-pressing `?` while the overlay is
        // already visible is therefore not observable here — it
        // never reaches this dispatch.
        if let AppState::Unlocked { help_open, .. } = &mut state {
            *help_open = true;
        }
        return (state, Vec::new());
    }
    if c == 'r' {
        // Remove is selection-gated (filtered upstream) and carries a
        // pre-populated payload built by [`pending_remove_for_char`].
        // A `None` here means the gate was passed but the selection
        // was `None` — leave the modal slot untouched so the binding
        // observes as a silent no-op.
        if let Some(remove) = remove_modal {
            if let AppState::Unlocked { modal, .. } = &mut state {
                *modal = Some(Modal::Remove(remove));
            }
        }
        return (state, Vec::new());
    }
    if c == 'R' {
        // Rename is selection-gated (filtered upstream) and carries a
        // pre-populated payload built by [`pending_rename_for_char`].
        // A `None` here means the gate was passed but the selection
        // could not be resolved to a vault account — leave the modal
        // slot untouched so the binding observes as a silent no-op.
        if let Some(rename) = rename_modal {
            if let AppState::Unlocked { modal, .. } = &mut state {
                *modal = Some(Modal::Rename(rename));
            }
        }
        return (state, Vec::new());
    }
    if c == 'E' {
        // v0.2 Edit (`Shift+E`) is selection-gated (filtered
        // upstream) and carries a pre-populated payload built by
        // [`pending_edit_for_char`]. A `None` here means the gate
        // was passed but the selection could not be resolved to a
        // vault account — leave the modal slot untouched so the
        // binding observes as a silent no-op.
        if let Some(edit) = edit_modal {
            if let AppState::Unlocked { modal, .. } = &mut state {
                *modal = Some(Modal::Edit(edit));
            }
        }
        return (state, Vec::new());
    }
    if c == 'C' {
        // `C` (Shift-c) — copy next code. Selection-gated upstream
        // (`selection_gated_status_error` sets "no account selected"
        // when `selected = None`). TOTP selection emits an
        // [`Effect::CopyNextCode`]; HOTP selection surfaces the
        // [`crate::app::state::NO_NEXT_CODE_FOR_HOTP`] status-line
        // error and emits no effect. The pre-populated outcome is
        // computed by `copy_next_code_outcome`, mirroring the
        // `n_effects` / `rename_modal` / `remove_modal` /
        // `settings_modal` precomputation pattern so this arm does
        // not borrow the vault.
        match copy_next {
            Some(CopyNextCodeOutcome::Effect(effect)) => return (state, vec![effect]),
            Some(CopyNextCodeOutcome::Reject(err)) => {
                if let AppState::Unlocked { status_line, .. } = &mut state {
                    *status_line = Some(err);
                }
                return (state, Vec::new());
            }
            Some(CopyNextCodeOutcome::Noop) | None => return (state, Vec::new()),
        }
    }
    if c == 's' {
        // Settings is not selection-gated and carries a pre-populated
        // payload built by [`pending_settings_for_char`] from the
        // live `VaultSettings`. The helper always returns `Some(_)`
        // for `c == 's'` (the four fields are all `Copy` and the
        // settings borrow is infallible), so the inner `if let Some`
        // is purely defensive — a `None` here would leave the modal
        // slot untouched and observe as a silent no-op.
        if let Some(settings) = settings_modal {
            if let AppState::Unlocked { modal, .. } = &mut state {
                *modal = Some(Modal::Settings(settings));
            }
        }
        return (state, Vec::new());
    }
    if c == 'Q' {
        // QR Export is selection-gated and carries a pre-populated
        // payload built by [`pending_qr_export_for_char`]. The
        // no-selection / empty-filtered-set / stale-id cases yield
        // `None` so the binding observes as a silent no-op — parity
        // with `Enter` on an empty list. No status-line error is
        // surfaced (unlike `r` / `R` / `C` which set
        // [`crate::app::state::NO_ACCOUNT_SELECTED`]).
        if let Some(qr) = qr_export_modal {
            if let AppState::Unlocked { modal, .. } = &mut state {
                *modal = Some(Modal::QrExport(qr));
            }
        }
        return (state, Vec::new());
    }
    if let Some(opened) = modal_opener_for_char(c) {
        if let AppState::Unlocked { modal, .. } = &mut state {
            *modal = Some(opened);
        }
        return (state, Vec::new());
    }
    (state, Vec::new())
}

/// Build the [`Effect::HotpAdvance`] for the selected account, or
/// `None` when the binding is a silent no-op.
///
/// Returns `Some(Effect::HotpAdvance { path, account_id })` only when
/// (a) `selected` resolves to a vault account and (b) the account's
/// kind is [`AccountKindSummary::Hotp`]. TOTP accounts and a selected
/// id missing from the vault yield `None` so the reducer surfaces no
/// effect — the status-line "not an HOTP account" hint lands with a
/// later slice. The `selected = None` case is intercepted earlier by
/// [`selection_gated_status_error`] (which sets the
/// "no account selected" status-line error), so this helper sees
/// `None` for selection only when called from paths that have not
/// run the gate.
fn hotp_advance_effect(
    path: &std::path::Path,
    vault: &Vault,
    selected: Option<AccountId>,
) -> Option<Effect> {
    let id = selected?;
    let account = vault.iter().find(|a| a.id() == id)?;
    if account.kind() != paladin_core::AccountKindSummary::Hotp {
        return None;
    }
    Some(Effect::HotpAdvance {
        path: path.to_path_buf(),
        account_id: id,
    })
}

/// Handle `Enter` on Unlocked: return the effects for a `CopyCode`
/// emission when [`copy_code_effect`] resolves one, otherwise an empty
/// vec. Per the Keybindings table: *"`Enter` — Copy selected code
/// (TOTP: current; HOTP: visible only)."* Modal / help / `Ctrl-Enter`
/// short-circuit before reaching this helper; `Focus::List` is gated
/// by the caller.
fn enter_on_unlocked(
    path: &std::path::Path,
    vault: &Vault,
    hotp_reveal: Option<&crate::app::state::HotpReveal>,
    selected: Option<AccountId>,
) -> Vec<Effect> {
    copy_code_effect(path, vault, hotp_reveal, selected)
        .map(|e| vec![e])
        .unwrap_or_default()
}

/// Resolve whether `Enter` on Unlocked should emit a
/// [`Effect::CopyCode`] for the currently selected account.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` Keybindings: *"`Enter` — Copy
/// selected code (TOTP: current; HOTP: visible only)."* The rules:
///
/// * No selection → `None`.
/// * Selection points at an account no longer in the vault
///   (defensive — the search/selection slice keeps these in sync) →
///   `None`.
/// * TOTP → `Some(CopyCode)` — the executor generates a fresh code
///   from the live wall clock.
/// * HOTP with a `hotp_reveal` whose `account_id` matches the
///   selection → `Some(CopyCode)` — the executor reads the visible
///   code.
/// * HOTP without a matching reveal (no reveal at all, or one for a
///   different account) → `None`. The "visible only" rule is enforced
///   here so the executor never sees a `CopyCode` for a hidden code.
fn copy_code_effect(
    path: &std::path::Path,
    vault: &Vault,
    hotp_reveal: Option<&crate::app::state::HotpReveal>,
    selected: Option<AccountId>,
) -> Option<Effect> {
    let id = selected?;
    let account = vault.iter().find(|a| a.id() == id)?;
    let visible = match account.kind() {
        paladin_core::AccountKindSummary::Totp => true,
        paladin_core::AccountKindSummary::Hotp => hotp_reveal.is_some_and(|r| r.account_id == id),
    };
    if !visible {
        return None;
    }
    Some(Effect::CopyCode {
        path: path.to_path_buf(),
        account_id: id,
    })
}

/// Outcome of `C` (Shift-c, "copy next code") dispatch on Unlocked /
/// `Focus::List` with a selection set. Per DESIGN §6: TOTP rows emit
/// [`Effect::CopyNextCode`]; HOTP rows surface
/// [`crate::app::state::NO_NEXT_CODE_FOR_HOTP`] as a status-line
/// error and emit no effect; a selection that has dropped out of
/// the vault is a silent no-op (defensive — selection / vault are
/// kept in sync by the search slice).
///
/// The no-selection case is intercepted upstream by
/// [`selection_gated_status_error`] so this helper sees `selected
/// = Some(_)` in normal flow; callers that bypass the gate still
/// observe `None` and treat it as a silent no-op.
#[derive(Debug)]
enum CopyNextCodeOutcome {
    /// Emit this `Effect::CopyNextCode` and clear the status line.
    Effect(Effect),
    /// Reject the dispatch — set the status line to this error and
    /// emit no effect.
    Reject(StatusLine),
    /// Silent no-op (no selection, selection missing from vault).
    Noop,
}

fn copy_next_code_outcome(
    path: &std::path::Path,
    vault: &Vault,
    selected: Option<AccountId>,
) -> CopyNextCodeOutcome {
    let Some(id) = selected else {
        return CopyNextCodeOutcome::Noop;
    };
    let Some(account) = vault.iter().find(|a| a.id() == id) else {
        return CopyNextCodeOutcome::Noop;
    };
    match account.kind() {
        paladin_core::AccountKindSummary::Totp => {
            CopyNextCodeOutcome::Effect(Effect::CopyNextCode {
                path: path.to_path_buf(),
                account_id: id,
            })
        }
        paladin_core::AccountKindSummary::Hotp => CopyNextCodeOutcome::Reject(StatusLine::Error(
            crate::app::state::NO_NEXT_CODE_FOR_HOTP.to_string(),
        )),
    }
}

/// Step direction for list selection navigation.
///
/// `Up` / `Down` are single-row adjacency steps. `First` / `Last` are
/// absolute jumps to the head / tail of `Vault::iter()` (insertion
/// order), used by `Home` and `End`. `PageUp` / `PageDown` walk by
/// `AppState::Unlocked::viewport_height` rows (insertion order),
/// clamping at the head / tail when fewer rows remain — used by `PgUp`
/// / `PgDn` and their `Ctrl-B` / `Ctrl-F` vim mirrors.
/// `HalfPageUp` / `HalfPageDown` walk by
/// `AppState::Unlocked::viewport_height / 2` rows (integer division),
/// with the same clamp behavior — used by the vim-style `Ctrl-U` /
/// `Ctrl-D` half-page bindings. A `viewport_height` of `0` or `1`
/// (half = 0 by integer division) is a silent no-op for the half-page
/// variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListStep {
    Up,
    Down,
    First,
    Last,
    PageUp,
    PageDown,
    HalfPageUp,
    HalfPageDown,
}

/// Map a list-navigation key to its step direction.
///
/// `↑` / `↓` and the vim mirrors `k` / `j` step the selection by one
/// row. `Home` / `End` jump to the first / last row of `Vault::iter()`
/// (insertion order); upper-case `G` (Shift+g — crossterm reports the
/// resolved `KeyCode::Char('G')`, with or without `KeyModifiers::SHIFT`
/// depending on the terminal) is the vim mirror of `End`. `PgUp` /
/// `PgDn` walk by [`AppState::Unlocked::viewport_height`] rows,
/// clamping at the first / last row of the iteration. Returns `None`
/// for keys that are not list navigation; the `gg` chord leader
/// (lower-case `g`) is consumed before this dispatch and the
/// `Ctrl-B` / `Ctrl-F` page mirrors plus `Ctrl-U` / `Ctrl-D`
/// half-page bindings are routed through the Ctrl/Alt guard in
/// [`reduce_unlocked_input`] (so they reuse the
/// [`ListStep::PageDown`] / [`ListStep::PageUp`] /
/// [`ListStep::HalfPageDown`] / [`ListStep::HalfPageUp`] steps from
/// here). The `zz` recenter chord lands in a later slice.
fn list_step_for_key(code: KeyCode) -> Option<ListStep> {
    match code {
        KeyCode::Down | KeyCode::Char('j') => Some(ListStep::Down),
        KeyCode::Up | KeyCode::Char('k') => Some(ListStep::Up),
        KeyCode::Home => Some(ListStep::First),
        KeyCode::End | KeyCode::Char('G') => Some(ListStep::Last),
        KeyCode::PageDown => Some(ListStep::PageDown),
        KeyCode::PageUp => Some(ListStep::PageUp),
        _ => None,
    }
}

/// Move the Unlocked list selection per `step`.
///
/// All step variants walk the **filtered** insertion-order set derived
/// from `search_query` via [`filtered_account_ids`], not the unfiltered
/// `Vault::iter()`, so navigation honors the active search filter per
/// the §6 "Search filter narrows the visible list in place" rule. For
/// `Up` / `Down`, picks the row adjacent to the currently selected
/// `AccountId` within the filtered set; clamping at top / bottom leaves
/// the selection unchanged. For `First` / `Last`, assigns the head /
/// tail of the filtered set directly. For `PageUp` / `PageDown`, walks
/// the filtered set by `viewport_height` rows, clamping at head / tail
/// when fewer filtered rows remain. A `viewport_height` of `0`
/// (pre-resize seed) is a silent no-op. An empty filtered set
/// (`selected = None`, no rows match) is a silent no-op in every
/// direction. The reducer never emits effects for navigation — these
/// are pure state updates.
fn move_selection(mut state: AppState, step: ListStep) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref vault,
        ref search_query,
        ref mut selected,
        viewport_height,
        viewport_offset: 0,
        ..
    } = state
    else {
        return (state, Vec::new());
    };
    let ids = filtered_account_ids(vault, search_query);
    match step {
        ListStep::Up | ListStep::Down => {
            if let Some(current) = *selected {
                if let Some(next) = adjacent_in_filtered(&ids, current, step) {
                    *selected = Some(next);
                }
            }
        }
        ListStep::First => {
            *selected = ids.first().copied();
        }
        ListStep::Last => {
            *selected = ids.last().copied();
        }
        ListStep::PageDown | ListStep::PageUp => {
            if let Some(current) = *selected {
                if let Some(next) = step_n_rows(&ids, current, step, viewport_height as usize) {
                    *selected = Some(next);
                }
            }
        }
        ListStep::HalfPageDown | ListStep::HalfPageUp => {
            if let Some(current) = *selected {
                // Half-page uses integer division: viewport_height = 1
                // yields n = 0 (no-op) which matches vim's
                // behavior — half-page is undefined on a one-row
                // viewport.
                let n = (viewport_height as usize) / 2;
                if let Some(next) = step_n_rows(&ids, current, step, n) {
                    *selected = Some(next);
                }
            }
        }
    }
    (state, Vec::new())
}

/// Commit a `zz` recenter: set [`AppState::Unlocked::viewport_offset`]
/// so the selected row sits in the middle of the viewport.
///
/// Computes `sel_pos` as the position of the selection within the
/// **filtered** insertion-order set (`filtered_account_ids`) so the
/// offset matches the rendered list when a search query is active, then
/// assigns `viewport_offset = sel_pos.saturating_sub(viewport_height / 2)`.
/// The lower-bound saturation keeps near-the-top selections at offset
/// `0`; the renderer is responsible for any upper-bound clamping when
/// the resize-driven viewport slice lands. Silent no-op when
/// `selected = None`, the selected id is not present in the filtered
/// set, or `viewport_height = 0` — `viewport_offset` is unchanged in
/// every no-op case.
fn recenter_viewport(mut state: AppState) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref vault,
        ref search_query,
        selected,
        viewport_height,
        ref mut viewport_offset,
        ..
    } = state
    else {
        return (state, Vec::new());
    };
    if viewport_height == 0 {
        return (state, Vec::new());
    }
    let Some(current) = selected else {
        return (state, Vec::new());
    };
    let ids = filtered_account_ids(vault, search_query);
    let Some(pos) = ids.iter().position(|id| *id == current) else {
        return (state, Vec::new());
    };
    let half = viewport_height / 2;
    let sel_pos: u16 = u16::try_from(pos).unwrap_or(u16::MAX);
    *viewport_offset = sel_pos.saturating_sub(half);
    (state, Vec::new())
}

/// Swap [`AppState::Unlocked::focus`] between the two top-level
/// surfaces (`Focus::List` ↔ `Focus::Search`) for the `Tab` /
/// `Shift-Tab` keybinding.
///
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings" rule: *"Cycle focus
/// between search bar and list (preserves active query when leaving
/// search)"*. Top-level Unlocked has only two surfaces, so `Tab` and
/// `Shift-Tab` (which crossterm reports as `KeyCode::BackTab`) swap
/// the same direction. `search_query` is untouched so an active
/// query survives the swap. Modal-open is filtered out by the
/// modal-trap guard in [`reduce_unlocked_input`] before this helper
/// is reached — and `Ctrl-N` / `Ctrl-P` never reach this helper:
/// at the top level they bind to list navigation (`↓` / `↑`) via
/// [`ctrl_chord_list_step`], and with a modal open they cycle
/// modal-local focus as `Tab` / `Shift-Tab` aliases. Once modal
/// payloads grow focusable fields, both pairs must dispatch through
/// the same modal-local focus-cycling handler.
fn toggle_unlocked_focus(mut state: AppState) -> (AppState, Vec<Effect>) {
    if let AppState::Unlocked { focus, .. } = &mut state {
        *focus = match *focus {
            Focus::List => Focus::Search,
            Focus::Search => Focus::List,
        };
    }
    (state, Vec::new())
}

/// Return the account adjacent to `current` in the filtered
/// insertion-order set `ids`, or `None` when `current` is at the end
/// of the set in the requested direction (clamp signal) or is absent
/// from the filtered set entirely.
///
/// Only `ListStep::Up` and `ListStep::Down` are valid here; the
/// absolute-jump and page-step variants are handled directly in
/// [`move_selection`].
fn adjacent_in_filtered(
    ids: &[AccountId],
    current: AccountId,
    step: ListStep,
) -> Option<AccountId> {
    let pos = ids.iter().position(|id| *id == current)?;
    match step {
        ListStep::Down => ids.get(pos + 1).copied(),
        ListStep::Up => {
            if pos == 0 {
                None
            } else {
                Some(ids[pos - 1])
            }
        }
        ListStep::First
        | ListStep::Last
        | ListStep::PageDown
        | ListStep::PageUp
        | ListStep::HalfPageDown
        | ListStep::HalfPageUp => {
            unreachable!(
                "First/Last/PageUp/PageDown/HalfPageUp/HalfPageDown are absolute / page jumps handled in move_selection"
            )
        }
    }
}

/// Walk the filtered insertion-order set `ids` by `n` rows up or down
/// from `current`, clamping at the head / tail when fewer rows remain.
///
/// Returns the new `AccountId` when the selection moves, or `None` when
/// the walk would be a no-op (n == 0, `current` already at the
/// boundary in the requested direction, or `current` not found in the
/// filtered set). Used by `ListStep::PageUp` / `ListStep::PageDown`
/// with `n = viewport_height` and by `ListStep::HalfPageUp` /
/// `ListStep::HalfPageDown` with `n = viewport_height / 2`.
fn step_n_rows(
    ids: &[AccountId],
    current: AccountId,
    step: ListStep,
    n: usize,
) -> Option<AccountId> {
    if n == 0 {
        return None;
    }
    let pos = ids.iter().position(|id| *id == current)?;
    let target = match step {
        ListStep::PageDown | ListStep::HalfPageDown => (pos + n).min(ids.len().saturating_sub(1)),
        ListStep::PageUp | ListStep::HalfPageUp => pos.saturating_sub(n),
        ListStep::Up | ListStep::Down | ListStep::First | ListStep::Last => {
            unreachable!("step_n_rows only handles page steps")
        }
    };
    if target == pos {
        None
    } else {
        Some(ids[target])
    }
}

/// Append a typed character to the search-query buffer and recompute
/// the surviving list selection.
///
/// Returns `true` when the key was consumed (printable Char while
/// `Focus::Search`); `false` when the caller should fall through to
/// list-step dispatch — non-Char keys (`↑` / `↓` / `Home` / `End` /
/// `PgUp` / `PgDn`) pass through to the list per the §6 / "Focus
/// model" rule that *"the selection is always navigable so the user
/// does not need to unfocus the search to act on a result"*.
///
/// Ctrl / Alt-modified Chars are returned-early by the Ctrl/Alt
/// guard in [`reduce_unlocked_input`], so this helper only sees bare
/// or Shift-modified Chars (e.g. `KeyCode::Char('G')` with
/// `KeyModifiers::SHIFT`). The chord leader is **not** cleared here —
/// the caller clears it before invoking this routing, mirroring
/// the unconditional-clear pattern used by the Ctrl/Alt guard.
///
/// Selection is recomputed via [`select_after_search`] (composing
/// [`paladin_core::select_after_filter`] with the case-insensitive
/// issuer/label substring filter from
/// [`paladin_core::account_matches_search`]). The prev selection
/// survives if still in the filtered set; otherwise the first match
/// in [`Vault::iter`] insertion order; otherwise `None` when the
/// filtered set is empty.
fn route_search_focus_char(
    search_query: &mut String,
    selected: &mut Option<AccountId>,
    vault: &Vault,
    key: &KeyEvent,
) -> bool {
    if let KeyCode::Char(c) = key.code {
        search_query.push(c);
        *selected = select_after_search(vault, search_query, *selected);
        return true;
    }
    false
}

/// Map a bare-letter Unlocked-screen keybinding to the payload-free
/// modal it opens, or `None` if the character is not such a binding.
///
/// Mirrors `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings (initial v0.1)"
/// for the modals whose initial state does not depend on vault data:
/// Add / Import / Export / Passphrase. The `r` (Remove), `R`
/// (Rename), and `s` (Settings) bindings are handled separately by
/// [`dispatch_unlocked_char`] because their payloads pre-populate
/// from vault state — `account_id` (and, for Rename, the draft)
/// from the selected account, and the Settings pending values from
/// the live [`paladin_core::VaultSettings`].
fn modal_opener_for_char(c: char) -> Option<Modal> {
    Some(match c {
        'a' => Modal::Add(AddModal::default()),
        'i' => Modal::Import(ImportModal::default()),
        'e' => Modal::Export(ExportModal::default()),
        'p' => Modal::Passphrase(PassphraseModal::default()),
        _ => return None,
    })
}

/// Handle a key event on the Unlock screen.
///
/// Printable Char input (no Ctrl/Alt modifier) appends to the
/// passphrase buffer. Backspace pops the last char. Enter on a
/// non-empty buffer emits [`Effect::Unlock`] and clears the buffer in
/// place; Enter on an empty buffer is a no-op. Any other key is a
/// no-op.
fn reduce_unlock_input(mut state: AppState, key: &KeyEvent) -> (AppState, Vec<Effect>) {
    let AppState::Unlock {
        ref path,
        ref mut passphrase,
        ..
    } = state
    else {
        // Caller ensures we're in Unlock; defensive fall-through keeps
        // the reducer total.
        return (state, Vec::new());
    };

    match key.code {
        KeyCode::Char(c)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            passphrase.push(c);
            (state, Vec::new())
        }
        KeyCode::Backspace => {
            passphrase.pop();
            (state, Vec::new())
        }
        KeyCode::Enter if !passphrase.is_empty() => {
            let secret = passphrase.take();
            let effect = Effect::Unlock {
                path: path.clone(),
                passphrase: secret,
            };
            (state, vec![effect])
        }
        _ => (state, Vec::new()),
    }
}

/// Apply the Unlocked-screen `Esc` precedence chain: clear any
/// pending vim chord leader, then dismiss the highest-precedence
/// dismissable affordance (Help close > modal close > search clear).
///
/// The chord clear is always performed regardless of which (if any)
/// affordance fires, mirroring vim's `nottimeout` semantics. The
/// Help overlay opens only when `modal == None` and `focus ==
/// List`, so the sibling slots are no-ops by construction while
/// Help is open; the modal traps focus, so closing it leaves
/// `focus` / `search_query` intact; with no modal and
/// `Focus::Search`, Esc clears the query and returns focus to the
/// list. On `Focus::List` with no modal and no Help, Esc is
/// otherwise a silent no-op (chord clear above is the only state
/// change).
fn apply_esc_dismiss(
    pending_chord_leader: &mut Option<ChordLeader>,
    help_open: &mut bool,
    modal: &mut Option<Modal>,
    focus: &mut Focus,
    search_query: &mut String,
) {
    *pending_chord_leader = None;
    if *help_open {
        *help_open = false;
    } else if let Some(Modal::QrExport(qr)) = modal {
        // Esc inside the QR Export modal's save sub-flow only
        // cancels the sub-flow — the Page-2 QR body survives so
        // the user can re-attempt a save. Per
        // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
        // QR Export: *"`Esc` while focus is inside the Page-2
        // destination-path sub-flow ... cancels only the sub-flow:
        // the modal returns to the Page-2 QR body, the typed path
        // buffer is zeroized, and the rendered ANSI body
        // survives."*
        if qr.save_sub_flow.is_some() {
            qr.save_sub_flow = None;
            qr.focus = QrExportFocus::SavePngButton;
        } else {
            *modal = None;
        }
    } else if modal.is_some() {
        *modal = None;
    } else if *focus == Focus::Search {
        *focus = Focus::List;
        search_query.clear();
    }
}

/// `Ctrl-C` — quits on any screen.
fn is_ctrl_c(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('c')) && key.modifiers.contains(KeyModifiers::CONTROL)
}

/// `Esc` quits on `Unlock`, `StartupError`, and the `ChooseMode`
/// step of `CreateVault`.
///
/// `CreateVault::ConfirmPlaintext` and `CreateVault::EnterPassphrase`
/// handle `Esc` in [`reduce_create_vault_input`] so it returns to
/// `ChooseMode` (zeroizing passphrase buffers) rather than quitting.
/// `Unlocked` is intentionally excluded — modals / search / vim
/// chords own its `Esc` dismissal precedence, and the user must never
/// be one stray `Esc` away from losing the unlocked session.
fn quits_on_esc(state: &AppState) -> bool {
    matches!(
        state,
        AppState::StartupError { .. }
            | AppState::Unlock { .. }
            | AppState::CreateVault {
                step: crate::app::state::CreateVaultStep::ChooseMode { .. },
                ..
            }
    )
}

/// `q` quits on `StartupError`, and on `CreateVault` at `ChooseMode`
/// / `ConfirmPlaintext`. On `Unlock` and on
/// `CreateVault::EnterPassphrase` it is text input. On `Unlocked`
/// the quit fires from [`reduce_unlocked_input`] under its modal /
/// focus guards; this fallback predicate is only consulted for the
/// remaining "no dedicated handler" states.
fn quits_on_q(state: &AppState) -> bool {
    matches!(
        state,
        AppState::StartupError { .. }
            | AppState::CreateVault {
                step: crate::app::state::CreateVaultStep::ChooseMode { .. }
                    | crate::app::state::CreateVaultStep::ConfirmPlaintext,
                ..
            }
    )
}

/// Wipe the Unlock-screen passphrase buffer in place on a cancel-quit.
///
/// Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests > Sensitive UI buffers":
/// *"Unlock passphrase buffer zeroizes on submit, cancel, and
/// auto-lock."* The same guarantee covers
/// [`CreateVaultStep::EnterPassphrase`] (per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Startup / vault modes": *"Esc
/// returns to `ChooseMode` (both buffers zeroized); Ctrl-C quits and
/// zeroizes."*).
///
/// The submit path is covered by
/// [`crate::prompt::PassphraseBuffer::take`]; this helper covers the
/// cancel paths (`Esc` / `Ctrl-C` from the Unlock screen, `Ctrl-C`
/// from `CreateVault::EnterPassphrase`) so the typed bytes do not
/// linger between [`Effect::Quit`] emission and process tear-down.
/// Auto-lock does not apply on either screen — it fires from
/// `Unlocked` only — so no buffer exists to wipe at that boundary.
/// States other than `Unlock` and `CreateVault::EnterPassphrase`
/// pass through unchanged.
fn zeroize_passphrase_buffers(mut state: AppState) -> AppState {
    match state {
        AppState::Unlock {
            ref mut passphrase, ..
        } => {
            passphrase.clear();
        }
        AppState::CreateVault {
            step:
                crate::app::state::CreateVaultStep::EnterPassphrase {
                    ref mut passphrase,
                    ref mut confirmation,
                    ..
                },
            ..
        } => {
            passphrase.clear();
            confirmation.clear();
        }
        _ => {}
    }
    state
}
