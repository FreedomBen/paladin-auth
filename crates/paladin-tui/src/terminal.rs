// SPDX-License-Identifier: AGPL-3.0-or-later

//! Terminal lifecycle: raw mode + alternate-screen guard with
//! restoration on normal exit, startup failure after setup, `Ctrl-C`,
//! and panic unwind.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)" the
//! guard is installed before the first draw and dropped after the
//! event loop terminates. `Ctrl-C` is delivered as a `crossterm`
//! key event and funnels through the reducer's `Effect::Quit` so its
//! teardown shares the normal-exit code path.
//!
//! The guard is generic over a [`TerminalBackend`] so the lifecycle
//! can be unit-tested with a recording fake; production wires it to
//! [`CrosstermBackend`] which drives the real terminal.

use std::io::{self, Write};

use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

/// Operations the guard issues against the underlying terminal.
///
/// Real backends drive `crossterm`; integration tests substitute a
/// recording implementation so the order and rollback semantics of
/// setup / teardown can be asserted without an actual terminal.
pub trait TerminalBackend {
    /// Put the terminal into raw mode.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the platform refuses to enable raw mode.
    fn enable_raw_mode(&mut self) -> io::Result<()>;

    /// Switch to the alternate screen buffer.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the write to the terminal fails.
    fn enter_alt_screen(&mut self) -> io::Result<()>;

    /// Restore cooked / canonical mode.
    ///
    /// Called during teardown and during setup rollback. Errors are
    /// surfaced to the caller; the guard's own `Drop` swallows them
    /// because we are tearing the terminal down regardless.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the platform refuses to disable raw mode.
    fn disable_raw_mode(&mut self) -> io::Result<()>;

    /// Switch back to the primary screen buffer.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the write to the terminal fails.
    fn leave_alt_screen(&mut self) -> io::Result<()>;
}

/// RAII guard that owns the terminal's raw-mode + alternate-screen
/// state for the lifetime of the event loop.
///
/// On normal `drop`, the guard leaves the alternate screen and
/// disables raw mode in reverse setup order. The same `drop` runs
/// during panic unwind, so a panicking renderer still leaves the
/// terminal usable. If [`Self::setup`] fails partway through, raw mode
/// is rolled back before the error is returned to the caller.
pub struct TerminalGuard<B: TerminalBackend> {
    backend: B,
    raw_enabled: bool,
    alt_entered: bool,
}

impl<B: TerminalBackend> TerminalGuard<B> {
    /// Enable raw mode and enter the alternate screen.
    ///
    /// # Errors
    ///
    /// If `enable_raw_mode` fails, no terminal state has been
    /// disturbed and the error is returned as-is. If
    /// `enter_alt_screen` fails after raw mode is enabled, raw mode
    /// is rolled back (best effort) before the error is returned, so
    /// the user's terminal is left in its original state.
    pub fn setup(mut backend: B) -> io::Result<Self> {
        backend.enable_raw_mode()?;
        if let Err(err) = backend.enter_alt_screen() {
            // Best-effort rollback: restore raw mode. We surface the
            // alt-screen error to the caller; the rollback error (if
            // any) is intentionally dropped because we cannot
            // meaningfully report two errors from one call.
            let _ = backend.disable_raw_mode();
            return Err(err);
        }
        Ok(Self {
            backend,
            raw_enabled: true,
            alt_entered: true,
        })
    }
}

impl<B: TerminalBackend> Drop for TerminalGuard<B> {
    fn drop(&mut self) {
        // Reverse setup order: leave alternate screen first, then
        // disable raw mode. Both errors are swallowed because we are
        // tearing the terminal down and have no caller to report to.
        if self.alt_entered {
            let _ = self.backend.leave_alt_screen();
            self.alt_entered = false;
        }
        if self.raw_enabled {
            let _ = self.backend.disable_raw_mode();
            self.raw_enabled = false;
        }
    }
}

/// Production [`TerminalBackend`] that drives `crossterm`.
///
/// `crossterm::terminal::enable_raw_mode` / `disable_raw_mode`
/// operate on the process-global terminal state; alternate-screen
/// commands are written to the supplied writer (`stdout` by default).
pub struct CrosstermBackend<W: Write> {
    out: W,
}

impl<W: Write> CrosstermBackend<W> {
    /// Wrap the given writer (typically `stdout`).
    pub const fn new(out: W) -> Self {
        Self { out }
    }
}

impl CrosstermBackend<io::Stdout> {
    /// Construct a backend that writes to the process's `stdout`.
    #[must_use]
    pub fn stdout() -> Self {
        Self::new(io::stdout())
    }
}

impl<W: Write> TerminalBackend for CrosstermBackend<W> {
    fn enable_raw_mode(&mut self) -> io::Result<()> {
        enable_raw_mode()
    }

    fn enter_alt_screen(&mut self) -> io::Result<()> {
        execute!(self.out, EnterAlternateScreen)
    }

    fn disable_raw_mode(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }

    fn leave_alt_screen(&mut self) -> io::Result<()> {
        execute!(self.out, LeaveAlternateScreen)
    }
}
