// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppEvent` — union of every event the reducer can consume — and
//! `Effect` — the union of impure actions the reducer can request.
//!
//! See `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)".

use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use secrecy::SecretString;
use zeroize::Zeroizing;

use paladin_core::{AccountId, ClipboardClearToken, Code, PaladinError, Store, Vault};

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
}

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
}
