// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wall-clock + monotonic ticker thread.
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//!
//! > **Ticker thread** — sleeps `paladin_auth_core::TICK_INTERVAL_MS`,
//! > emits `AppEvent::Tick { wall_clock, monotonic }`; TOTP generation
//! > uses `SystemTime` (`wall_clock`), while UI deadlines such as
//! > HOTP reveal expiry use monotonic `Instant` values.
//!
//! [`spawn`] is the only impure entry — production callers hand in
//! the `mpsc::Sender<AppEvent>` end of the same channel the reducer
//! reads from. The thread sleeps first, then emits, so a regression
//! that turns the loop into "emit immediately then sleep" surfaces in
//! the `spawn_first_tick_is_not_emitted_synchronously` test.
//!
//! The reducer brings the ticker down by dropping the receiver; the
//! thread's `Sender::send` fails on the next tick and the loop
//! returns. This is the production shutdown path on `Effect::Quit`,
//! `Ctrl-C`, and panic unwind — the ticker does not poll any other
//! shutdown signal.

use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use paladin_auth_core::TICK_INTERVAL_MS;

use crate::app::event::AppEvent;

/// Spawn the wall-clock + monotonic ticker thread.
///
/// The returned [`JoinHandle`] resolves once the thread exits, which
/// happens on the next tick after the matching receiver is dropped.
/// Callers who do not need to observe the join — production callers
/// running the event loop — may discard the handle; the
/// `drop`-on-receiver-hangup shutdown still applies.
#[must_use]
pub fn spawn(sender: Sender<AppEvent>) -> JoinHandle<()> {
    let interval = Duration::from_millis(TICK_INTERVAL_MS);
    thread::Builder::new()
        .name("paladin-auth-tui-ticker".into())
        .spawn(move || loop {
            thread::sleep(interval);
            let event = AppEvent::Tick {
                wall_clock: SystemTime::now(),
                monotonic: Instant::now(),
            };
            if sender.send(event).is_err() {
                // Receiver dropped — reducer is shutting down.
                return;
            }
        })
        .expect("OS thread spawn for ticker")
}
