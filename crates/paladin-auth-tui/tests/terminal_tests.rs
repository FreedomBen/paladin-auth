// SPDX-License-Identifier: AGPL-3.0-or-later

//! Terminal lifecycle tests.
//!
//! Tracks `docs/IMPLEMENTATION_PLAN_03_TUI.md` > Tests > "Terminal lifecycle":
//! the guard restores raw mode and alternate-screen state on normal
//! exit, startup failure after raw-mode enable, `Ctrl-C`, and panic
//! unwind. `Ctrl-C` is funneled through the reducer as
//! `Effect::Quit`, so its teardown is the same code path as a normal
//! exit; this file therefore exercises normal exit, startup-failure
//! rollback, and panic unwind. The integration of `Ctrl-C` →
//! `Effect::Quit` lives in the reducer test slice.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use paladin_auth_tui::terminal::{TerminalBackend, TerminalGuard};

#[derive(Default)]
struct Recorder {
    calls: Vec<&'static str>,
}

type SharedRecorder = Rc<RefCell<Recorder>>;

/// Backend that records every call and always succeeds.
struct RecordingBackend(SharedRecorder);

impl TerminalBackend for RecordingBackend {
    fn enable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enable_raw_mode");
        Ok(())
    }
    fn enter_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enter_alt_screen");
        Ok(())
    }
    fn disable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("disable_raw_mode");
        Ok(())
    }
    fn leave_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("leave_alt_screen");
        Ok(())
    }
}

/// Backend whose `enter_alt_screen` always fails, mirroring a startup
/// failure after raw mode has been successfully enabled.
struct AltScreenFailureBackend(SharedRecorder);

impl TerminalBackend for AltScreenFailureBackend {
    fn enable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enable_raw_mode");
        Ok(())
    }
    fn enter_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enter_alt_screen:fail");
        Err(io::Error::other("simulated alt-screen failure"))
    }
    fn disable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("disable_raw_mode");
        Ok(())
    }
    fn leave_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("leave_alt_screen");
        Ok(())
    }
}

/// Backend whose `enable_raw_mode` itself fails, before any other
/// terminal state has been disturbed.
struct RawModeFailureBackend(SharedRecorder);

impl TerminalBackend for RawModeFailureBackend {
    fn enable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enable_raw_mode:fail");
        Err(io::Error::other("simulated raw-mode failure"))
    }
    fn enter_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("enter_alt_screen");
        Ok(())
    }
    fn disable_raw_mode(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("disable_raw_mode");
        Ok(())
    }
    fn leave_alt_screen(&mut self) -> io::Result<()> {
        self.0.borrow_mut().calls.push("leave_alt_screen");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Terminal lifecycle (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Terminal lifecycle)
// ---------------------------------------------------------------------------

#[test]
fn guard_setup_enables_raw_then_enters_alt_screen_in_order() {
    let rec: SharedRecorder = Rc::default();
    let guard = TerminalGuard::setup(RecordingBackend(rec.clone())).expect("setup succeeds");
    assert_eq!(
        rec.borrow().calls.as_slice(),
        &["enable_raw_mode", "enter_alt_screen"]
    );
    drop(guard);
}

#[test]
fn guard_normal_drop_restores_alt_screen_then_disables_raw_in_reverse_order() {
    let rec: SharedRecorder = Rc::default();
    {
        let _guard = TerminalGuard::setup(RecordingBackend(rec.clone())).expect("setup succeeds");
    }
    assert_eq!(
        rec.borrow().calls.as_slice(),
        &[
            "enable_raw_mode",
            "enter_alt_screen",
            "leave_alt_screen",
            "disable_raw_mode",
        ]
    );
}

#[test]
fn guard_restores_terminal_during_panic_unwind() {
    // Drop runs during unwind; the guard must restore the terminal even
    // when its owner panics mid-render. Panic-strategy = unwind is the
    // dev/test profile default; release builds use `panic = "abort"`
    // (workspace Cargo.toml), but Ctrl-C funnels through the reducer's
    // Effect::Quit code path in production anyway.
    let rec: SharedRecorder = Rc::default();
    let rec_in_panic = rec.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = TerminalGuard::setup(RecordingBackend(rec_in_panic)).expect("setup succeeds");
        panic!("simulated panic during render");
    }));
    assert!(result.is_err(), "expected the simulated panic to surface");
    assert_eq!(
        rec.borrow().calls.as_slice(),
        &[
            "enable_raw_mode",
            "enter_alt_screen",
            "leave_alt_screen",
            "disable_raw_mode",
        ]
    );
}

#[test]
fn guard_setup_rolls_back_raw_mode_when_enter_alt_fails() {
    // Bullet: "startup failure after setup" — raw mode is already
    // enabled when `enter_alt_screen` fails, so setup must roll it
    // back before returning the error.
    let rec: SharedRecorder = Rc::default();
    let result = TerminalGuard::setup(AltScreenFailureBackend(rec.clone()));
    assert!(
        result.is_err(),
        "expected setup to surface the alt-screen error"
    );
    assert_eq!(
        rec.borrow().calls.as_slice(),
        &[
            "enable_raw_mode",
            "enter_alt_screen:fail",
            "disable_raw_mode",
        ]
    );
}

#[test]
fn guard_setup_returns_error_without_touching_terminal_when_raw_mode_fails() {
    // If enable_raw_mode itself fails, no further terminal state has
    // been disturbed; setup must not attempt alt-screen or disable_raw
    // (nothing to disable).
    let rec: SharedRecorder = Rc::default();
    let result = TerminalGuard::setup(RawModeFailureBackend(rec.clone()));
    assert!(
        result.is_err(),
        "expected setup to surface the raw-mode error"
    );
    assert_eq!(rec.borrow().calls.as_slice(), &["enable_raw_mode:fail"]);
}
