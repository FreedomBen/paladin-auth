// SPDX-License-Identifier: AGPL-3.0-or-later

//! Effect executor: the only impure boundary between the pure reducer
//! and `paladin-core` / OS resources.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//!
//! > The reducer is a pure function over
//! > `(state, event) → (state, Vec<Effect>)` so it is unit-testable
//! > without a terminal. Effects are executed by `app::run`, which is
//! > the only boundary that may call impure core / clipboard / writer
//! > functions. Save-bearing effects mutate the current `Vault` only
//! > through core APIs ... then send an `AppEvent::EffectResult(...)`
//! > back through the same `mpsc` channel.
//!
//! [`execute`] is the per-effect dispatcher: the run loop calls it for
//! each [`Effect`] the reducer returned. Variants land here in lockstep
//! with the corresponding [`Effect`] variants.

use std::sync::mpsc::Sender;
use std::time::{Instant, SystemTime};

use paladin_core::{Store, VaultLock};

use crate::app::event::{AppEvent, Effect, EffectResult};
use crate::app::state::AppState;

/// Outcome of executing a single [`Effect`].
///
/// `Quit` is special: it carries no `AppEvent` because the run loop
/// uses the return value to break out of its dispatch loop and drive
/// terminal teardown (raw mode + alternate-screen restoration via the
/// [`crate::terminal::TerminalGuard`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectOutcome {
    /// The run loop should keep dispatching events.
    Continue,
    /// The run loop should exit cleanly. The teardown path is shared
    /// with normal exit, startup failure, `Ctrl-C`, and panic unwind.
    Quit,
}

/// Execute a single effect.
///
/// Save-bearing effects send an [`AppEvent::EffectResult`] back to the
/// reducer through `sender`; [`Effect::Quit`] returns
/// [`EffectOutcome::Quit`] without emitting an `AppEvent`.
///
/// `state` is the run loop's live [`AppState`]. Effects whose target
/// requires the live `(Vault, Store)` — `Rename`, and later
/// `HotpAdvance` / `CopyCode` — read it from
/// [`AppState::Unlocked`]; effects whose target is independent of UI
/// state (`Quit`, `Unlock`, `ClearClipboard`) ignore it.
///
/// If the receiver has already been dropped (the run loop is tearing
/// down), the send is silently ignored. The carried result — including
/// any `(Vault, Store)` pair — drops cleanly, which zeroizes the
/// derived AEAD key inside the `Store` and frees the in-memory vault.
pub fn execute(effect: Effect, state: &mut AppState, sender: &Sender<AppEvent>) -> EffectOutcome {
    match effect {
        Effect::Quit => EffectOutcome::Quit,
        Effect::Unlock { path, passphrase } => {
            let result = Store::open(&path, VaultLock::Encrypted(passphrase));
            // Sample `opened_at` immediately after `Store::open`
            // so the reducer can seed the auto-lock idle deadline
            // off the same monotonic clock the `Tick` thread uses.
            let opened_at = Instant::now();
            // `send` only fails if the receiver is gone; in that case
            // the app is already tearing down, so dropping the result
            // is correct.
            let _ = sender.send(AppEvent::EffectResult(EffectResult::Unlock {
                result,
                opened_at,
            }));
            EffectOutcome::Continue
        }
        Effect::ClearClipboard { value: _ } => {
            // Placeholder: the live-clipboard read and
            // `ClipboardClearPolicy::should_clear` decision land with
            // the clipboard adapter slice (see
            // `IMPLEMENTATION_PLAN_03_TUI.md` "Implementation
            // checklist": *"Implement clipboard wrapper (arboard
            // reads/writes) … only-if-unchanged auto-clear via
            // `ClipboardClearPolicy::should_clear`."*). For now the
            // captured bytes are dropped here — the reducer has
            // already cleared `pending_clipboard_clear` before this
            // executor arm runs.
            //
            // No `AppEvent` is sent back: clipboard wipe is fire-and-
            // forget at this layer.
            let _ = sender;
            EffectOutcome::Continue
        }
        Effect::HotpAdvance {
            path: _,
            account_id: _,
        } => {
            // Placeholder: the `Vault::hotp_advance` call lands with
            // the run-loop slice that gives the executor access to the
            // live `(Vault, Store)` carried in `AppState::Unlocked`.
            // The reducer side of the round trip is already in place:
            // `EffectResult::HotpAdvance { account_id, result,
            // completed_at }` opens (or replaces) the
            // `AppState::Unlocked::hotp_reveal` slot on `Ok(code)`
            // and is a no-op on `Err(...)` / non-`Unlocked` states.
            // Until the executor wiring lands, the emit is exercised
            // by reducer-level tests
            // (`pressing_n_with_hotp_account_selected_emits_hotp_advance_effect`,
            // `effect_result_hotp_advance_*`) and the executor
            // consumes the variant without emitting an `AppEvent`.
            let _ = sender;
            EffectOutcome::Continue
        }
        Effect::CopyCode {
            path: _,
            account_id: _,
        } => {
            // Placeholder: the `arboard` clipboard write and
            // `ClipboardClearPolicy::schedule` wiring land with the
            // clipboard adapter slice (see
            // `IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear":
            // *"Copy schedules a clear via
            // `ClipboardClearPolicy::schedule`."*). The executor
            // needs access to the live `(Vault, Store)` carried in
            // `AppState::Unlocked` to compute the TOTP code or read
            // the HOTP reveal value. Until that wiring lands the
            // reducer emit is exercised by reducer-level tests
            // (`pressing_enter_*_emits_copy_code_effect`, etc.) and
            // the executor consumes the variant without emitting an
            // `AppEvent`.
            let _ = sender;
            EffectOutcome::Continue
        }
        Effect::Rename {
            path,
            account_id,
            new_label,
        } => {
            // Run `Vault::rename` inside `Vault::mutate_and_save` so a
            // pre-commit failure (`save_not_committed`) snaps the
            // in-memory label back to its pre-rename value while
            // post-commit `save_durability_unconfirmed` leaves the
            // new label in memory matching the on-disk primary, per
            // `IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors" >
            // "Add / remove / rename / settings saves".
            //
            // The path check protects against a stale effect emitted
            // before an auto-lock or vault switch: if the live state
            // is no longer `Unlocked` against the same path, drop the
            // effect silently — the reducer would discard the
            // corresponding `EffectResult::Rename` anyway, and posting
            // back would just synthesize an artificial mutation
            // attempt against unrelated state.
            if let AppState::Unlocked {
                path: state_path,
                vault,
                store,
                ..
            } = state
            {
                if *state_path == path {
                    let result = vault.mutate_and_save(store, |v| {
                        v.rename(account_id, &new_label, SystemTime::now())
                    });
                    let _ = sender.send(AppEvent::EffectResult(EffectResult::Rename {
                        account_id,
                        result,
                    }));
                }
            }
            EffectOutcome::Continue
        }
    }
}
