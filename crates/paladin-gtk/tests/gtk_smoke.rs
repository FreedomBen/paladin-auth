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
/// libadwaita under a synthetic display, mounts the
/// `AppModel` relm4 component, and returns from the main loop
/// without the process getting stuck or panicking.
///
/// The hidden `--exit-after-startup` flag (see `cli.rs`) enqueues
/// `AppMsg::Quit` on the first frame so the relm4 main loop tears
/// down cleanly without a real desktop session to dismiss the
/// window. `clap`'s `--version` / `--help` short-circuit would
/// bypass `adw::init()` and `RelmApp::run` and so would not validate
/// the foundation, so they are intentionally not used here.
/// Subsequent bullets exercise the same path with a prepared vault.
#[test]
fn xvfb_run_launches_paladin_gtk_and_process_exits() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let output = run_under_xvfb(&["--exit-after-startup"]);
    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk exited with status {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Plan bullet: "App opens a prepared plaintext vault."
///
/// Pre-creates a plaintext vault at a temporary path via
/// `paladin_core::Store::create`, then launches `paladin-gtk` with
/// `--vault <path> --exit-after-startup` under `xvfb-run`. The binary
/// runs the §"Vault interaction" startup sequence — resolve path,
/// `paladin_core::inspect`, and `paladin_core::Store::open` with
/// `VaultLock::Plaintext` directly on the main loop — before the
/// hidden flag quits the main loop. Under `--exit-after-startup`,
/// `AppModel` emits a stable marker line to stdout naming the
/// resolved [`crate::app::state::AppState`] variant and the resolved
/// vault path; this test asserts on that marker so the foundation
/// the next bullet (`AccountListComponent` rendering) builds on is
/// observed rather than merely inferred from a clean exit.
#[test]
fn app_opens_prepared_plaintext_vault() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let tempdir = tempfile::tempdir().expect("create tempdir for prepared vault");
    // `paladin_core` enforces `0700` on the vault parent directory
    // (§4.3); pin it explicitly so a sandboxed test runner's umask
    // (commonly `0770`) does not trip `UnsafePermissions` before the
    // GTK binary even starts.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    let vault_path = tempdir.path().join("vault.bin");

    // `Store::create` stages the in-memory vault; the file is not
    // written until `Vault::save` runs the §4.3 atomic-write pipeline
    // (see `paladin_core::Store::create` docs). The pair is dropped at
    // the end of this scope so the file handle is closed before
    // `paladin-gtk`'s own `Store::open` re-opens it.
    {
        let (vault, store) =
            paladin_core::Store::create(&vault_path, paladin_core::VaultInit::Plaintext)
                .expect("create plaintext vault on disk");
        vault.save(&store).expect("persist plaintext vault to disk");
    }

    let path_str = vault_path
        .to_str()
        .expect("tempfile produced a non-UTF-8 vault path");
    let output = run_under_xvfb(&["--vault", path_str, "--exit-after-startup"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk --vault {path_str} --exit-after-startup exited with status {:?}\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        stdout,
        stderr,
    );

    // The marker format is fixed by `app::model::startup_state_marker`
    // and is documented next to that helper so test + implementation
    // share a single string contract.
    let expected = format!("paladin-gtk: startup_state=Unlocked path={path_str}");
    assert!(
        stdout.contains(&expected),
        "expected stdout to contain `{expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}
