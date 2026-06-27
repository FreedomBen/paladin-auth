// SPDX-License-Identifier: AGPL-3.0-or-later

//! Terminal input producer thread.
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//!
//! > **Input thread** — `crossterm::event::read()` in a loop, maps to
//! > `AppEvent::Input(KeyEvent | ResizeEvent | …)`.
//!
//! [`spawn`] is the production entry: it threads
//! [`crossterm::event::read`] in as the read source, returning a
//! `JoinHandle<()>` for a named OS thread `paladin-auth-tui-input`. The
//! thread blocks in `read()`, samples `Instant::now()` once the read
//! returns, wraps the event in [`AppEvent::Input`], and sends it down
//! the supplied `mpsc::Sender<AppEvent>` end of the channel the
//! reducer reads from.
//!
//! [`spawn_with`] is the same loop with an injected reader so the
//! integration tests in `crates/paladin-auth-tui/tests/input_tests.rs` can
//! drive it without a real terminal — `crossterm::event::read()`
//! requires a TTY, so the test seam is the only way to exercise the
//! event-to-`AppEvent` mapping and the two shutdown paths from CI.
//!
//! Two shutdown paths, mirroring the ticker's contract:
//!
//! * **Receiver hangup** — the reducer drops the receiver; the next
//!   `Sender::send` returns `Err` and the loop returns. This is the
//!   production shutdown on `Effect::Quit`, `Ctrl-C`, and panic
//!   unwind.
//! * **Read error** — `crossterm::event::read()` returns `Err` (closed
//!   terminal / disconnected TTY); the loop returns without panicking.
//!
//! The thread polls no other shutdown signal.

use std::io;
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crossterm::event::Event;

use crate::app::event::AppEvent;

/// Spawn the production input thread.
///
/// Reads `crossterm::event::Event` values via
/// [`crossterm::event::read`] in a loop and forwards each as
/// [`AppEvent::Input`] on `sender`. The returned [`JoinHandle`]
/// resolves once the thread exits — see the module-level docs for
/// the two shutdown paths. Callers running the event loop may
/// discard the handle; the drop-on-hangup shutdown still applies.
#[must_use]
pub fn spawn(sender: Sender<AppEvent>) -> JoinHandle<()> {
    spawn_with(sender, crossterm::event::read)
}

/// Spawn the input thread with a custom event reader.
///
/// Used by the integration tests in
/// `crates/paladin-auth-tui/tests/input_tests.rs` to drive the loop with
/// a fake reader so the event-to-`AppEvent` mapping and shutdown
/// paths can be exercised without a real terminal.
///
/// `read` is called in a loop; each `Ok(event)` is wrapped in
/// [`AppEvent::Input`] with `at = Instant::now()` sampled *after* the
/// read returned, then sent down `sender`. The loop exits when
/// `read` returns `Err` (terminal disconnect) or when `sender.send`
/// fails (receiver hangup) — both shutdown paths are tested.
///
/// # Panics
///
/// Panics only if the OS refuses to spawn the named thread; the loop
/// body never panics.
#[must_use]
pub fn spawn_with<F>(sender: Sender<AppEvent>, mut read: F) -> JoinHandle<()>
where
    F: FnMut() -> io::Result<Event> + Send + 'static,
{
    thread::Builder::new()
        .name("paladin-auth-tui-input".into())
        .spawn(move || loop {
            let Ok(event) = read() else { return };
            let at = Instant::now();
            if sender.send(AppEvent::Input { event, at }).is_err() {
                // Receiver dropped — reducer is shutting down.
                return;
            }
        })
        .expect("OS thread spawn for input")
}
