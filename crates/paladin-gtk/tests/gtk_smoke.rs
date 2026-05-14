// SPDX-License-Identifier: AGPL-3.0-or-later

//! `xvfb-run` headless smoke test for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Smoke test" / §"Tests", this
//! suite drives the GTK binary through a virtual X server so that
//! `adw::init()` and the relm4 bootstrap are exercised without
//! requiring a real desktop session. This file holds the bullets
//! enumerated under §"Smoke test (`tests/gtk_smoke.rs`)".
//!
//! Local developers without `xvfb-run` installed see each test skip
//! with a printed instruction line; CI (which installs `xvfb` per
//! the §"Smoke test" entry of the Milestone 7 checklist) runs them
//! for real. Tests that cannot run still return `Ok(())` so they do
//! not mask other regressions.
//!
//! The binary path is resolved at compile time via
//! `CARGO_BIN_EXE_paladin-gtk`, which Cargo provides to integration
//! tests of crates that declare a `[[bin]]` of that name.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Path to the built `paladin-gtk` binary. Cargo populates this at
/// compile time per the §"Crate layout" `[[bin]]` declaration.
const PALADIN_GTK_BIN: &str = env!("CARGO_BIN_EXE_paladin-gtk");

/// Wall-clock ceiling for an `xvfb-run paladin-gtk` invocation that
/// is expected to exit. Generous to absorb cold-cache startup on CI.
const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns `true` when `xvfb-run` is on `$PATH` and reports a usable
/// `--help`. CI installs it; many local dev environments do not.
fn xvfb_run_available() -> bool {
    Command::new("xvfb-run")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `xvfb-run -a <bin> <args...>` with a fresh display, capture
/// stdout / stderr, and wait up to [`SMOKE_TIMEOUT`] for the child
/// to exit. Returns the exit-status output bundle.
fn run_under_xvfb(args: &[&str]) -> std::process::Output {
    assert!(
        Path::new(PALADIN_GTK_BIN).exists(),
        "CARGO_BIN_EXE_paladin-gtk does not point at an existing file: {PALADIN_GTK_BIN}",
    );

    let mut child = Command::new("xvfb-run")
        .arg("-a")
        .arg(PALADIN_GTK_BIN)
        .args(args)
        // Force a clean environment slice — no carried-over DISPLAY
        // from the host session, no XDG_RUNTIME_DIR from a logged-in
        // user that might steer GIO / libadwaita off the synthetic
        // server.
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn xvfb-run");

    let deadline = std::time::Instant::now() + SMOKE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "xvfb-run {PALADIN_GTK_BIN} did not exit within \
                         {SMOKE_TIMEOUT:?}; the smoke-test binary must \
                         terminate on its own.",
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("waiting on xvfb-run failed: {e}"),
        }
    }

    child.wait_with_output().expect("xvfb-run output read")
}

/// Plan bullet: "`xvfb-run` launches `paladin-gtk` and the process
/// exits". This is the lowest rung — it proves that the binary
/// links against the GTK / libadwaita / relm4 stack, initializes
/// libadwaita under a synthetic display, and returns without the
/// process getting stuck or panicking.
///
/// The binary is invoked with no arguments so the full `run()`
/// path is exercised — clap parsing succeeds, libadwaita is
/// initialized against the xvfb display, and the process exits on
/// its own. `clap`'s `--version` / `--help` short-circuit would
/// bypass `adw::init()` and so would not validate the foundation,
/// so they are intentionally not used here. Subsequent bullets
/// exercise the relm4 main loop with a prepared vault.
#[test]
fn xvfb_run_launches_paladin_gtk_and_process_exits() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let output = run_under_xvfb(&[]);
    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk exited with status {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
