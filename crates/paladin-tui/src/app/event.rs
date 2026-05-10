// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppEvent` — union of every event the reducer can consume — and
//! `Effect` — the union of impure actions the reducer can request.
//!
//! See `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)".

use std::time::{Instant, SystemTime};

use paladin_core::ClipboardClearToken;

/// Events delivered to the reducer over the `mpsc<AppEvent>` channel.
///
/// `Input` and `Tick` arrive from long-lived producer threads;
/// `ClipboardClear` arrives from one-shot timer threads spawned by
/// clipboard auto-clear effects. `EffectResult` (added in subsequent
/// slices) carries the outcome of save-bearing effects back to the
/// reducer so it can update visible state.
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

/// Side effects produced by the reducer.
///
/// Effects are executed by the `run` boundary (the only site allowed
/// to call impure core / clipboard / writer functions). Save-bearing
/// effects send an `AppEvent::EffectResult(…)` back through the same
/// `mpsc` channel; clipboard timer effects send a delayed
/// [`AppEvent::ClipboardClear`].
///
/// Variants are added incrementally as the reducer comes online; this
/// initial spine carries only [`Effect::Quit`] so terminal screens
/// (missing-vault / startup-error / unlock) can request shutdown.
#[derive(Debug)]
pub enum Effect {
    /// Tear down the terminal and exit the process cleanly.
    Quit,
}
