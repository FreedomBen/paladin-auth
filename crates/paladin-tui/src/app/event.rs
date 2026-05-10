// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppEvent` — union of every event the reducer can consume — and
//! `Effect` — the union of impure actions the reducer can request.
//!
//! See `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)".

use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use secrecy::SecretString;

use paladin_core::{ClipboardClearToken, PaladinError, Store, Vault};

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
    Input(crossterm::event::Event),

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
        /// clipboard contents for the only-if-unchanged rule.
        value: Vec<u8>,
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
    Unlock(Result<(Vault, Store), PaladinError>),
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
}
