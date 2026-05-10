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

use paladin_core::{Store, VaultLock};

use crate::app::event::{AppEvent, Effect, EffectResult};

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
/// If the receiver has already been dropped (the run loop is tearing
/// down), the send is silently ignored. The carried result — including
/// any `(Vault, Store)` pair — drops cleanly, which zeroizes the
/// derived AEAD key inside the `Store` and frees the in-memory vault.
pub fn execute(effect: Effect, sender: &Sender<AppEvent>) -> EffectOutcome {
    match effect {
        Effect::Quit => EffectOutcome::Quit,
        Effect::Unlock { path, passphrase } => {
            let result = Store::open(&path, VaultLock::Encrypted(passphrase));
            // `send` only fails if the receiver is gone; in that case
            // the app is already tearing down, so dropping the result
            // is correct.
            let _ = sender.send(AppEvent::EffectResult(EffectResult::Unlock(result)));
            EffectOutcome::Continue
        }
    }
}
