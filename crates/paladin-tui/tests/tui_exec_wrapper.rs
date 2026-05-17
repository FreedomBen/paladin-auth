// SPDX-License-Identifier: AGPL-3.0-or-later

//! TUI-side smoke test for the `paladin tui` → `paladin-tui` exec
//! wrapper.
//!
//! Counterpart to `crates/paladin-cli/tests/cli_exec_tui.rs`, which
//! drives argv forwarding (`--vault`, `--no-color`, `--json` rejection)
//! against a stub `paladin-tui` script. This test pins the contract
//! from the TUI side: on a shared-`PATH` install (Debian / Fedora /
//! `AppImage`), when the real `paladin-tui` binary is reachable on
//! `PATH`, the wrapper finds it and execs into it. The Flatpak
//! `exec_paladin_tui` failure mode is exercised by the CLI plan's
//! tests.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Implementation checklist":
//! *"Add a TUI-side smoke test that spawns `paladin tui` (CLI) and
//! asserts it execs `paladin-tui` on shared-`PATH` installs; the
//! Flatpak `exec_paladin_tui` failure mode is exercised by the CLI
//! plan's tests."*
//!
//! The real `paladin-tui` binary's post-exec behavior is environment-
//! dependent: with a `/dev/tty` available it blocks in
//! `crossterm::event::read()`; without one (typical CI / sandboxed
//! test runs) it fails terminal setup and exits with a
//! `paladin-tui: <io error>` stderr advisory. Both outcomes are
//! valid proofs that the wrapper's `execvp` succeeded — the
//! `paladin-tui:` prefix in the second case comes from the inner
//! binary, not the wrapper. The only stderr fingerprint that
//! indicates a real wrapper regression is the wrapper's own
//! `exec_paladin_tui` advisory (see
//! `crates/paladin-cli/src/exec_tui.rs`), which the wrapper writes
//! only when `execvp` itself fails. These tests therefore give the
//! child a brief settle window, kill it if still running, and
//! assert that the captured stderr never carries `exec_paladin_tui`
//! — regardless of whether the inner binary exited cleanly or had
//! to be killed. Mirrors the wait-or-kill pattern in
//! `crates/paladin-gtk/tests/gtk_smoke.rs::run_under_xvfb`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;

/// How long to wait for the spawned child to either exit on its own
/// (the wrapper's `exec_paladin_tui` failure path, or `paladin-tui`'s
/// terminal-setup failure path on a CI host without a `/dev/tty`)
/// or settle into `crossterm::event::read()`. Generous enough to
/// absorb cold-cache process spawn on busy CI hosts; short enough
/// that a hung child surfaces within the test's per-suite budget
/// rather than the session-wide timeout.
const EXEC_SETTLE: Duration = Duration::from_millis(2_000);

/// Locate the `paladin` CLI binary built for this workspace.
///
/// `cargo_bin` resolves the absolute path the way `assert_cmd`
/// would, falling back to `<this_test_binary_parent>/paladin` when
/// the env var is unset. `cargo test --workspace` builds every
/// crate's binaries into the shared `target/<profile>/` directory,
/// so this resolves to the real `paladin` binary in CI and after
/// `cargo build --workspace` locally.
fn paladin_cli_path() -> PathBuf {
    let path = cargo_bin("paladin");
    assert!(
        path.is_file(),
        "paladin binary not found at {} \
         (run `cargo build --workspace` or `cargo test --workspace`)",
        path.display(),
    );
    path
}

/// Spawn `paladin <args>` with `PATH` constrained to `paladin_tui_dir`
/// and `NO_COLOR` removed. `stdin` is wired to `/dev/null` so the
/// child's `crossterm::event::read()` cannot accidentally consume
/// the parent test process's terminal.
fn spawn_paladin(paladin_tui_dir: &Path, args: &[&str]) -> Child {
    Command::new(paladin_cli_path())
        .env_remove("NO_COLOR")
        .env("PATH", paladin_tui_dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn paladin")
}

/// Wait up to [`EXEC_SETTLE`] for `child` to exit on its own; kill
/// and reap it if the deadline elapses first.
///
/// Both outcomes are part of the contract under test — see the
/// module-level docs for why the inner binary's post-exec behavior
/// is environment-dependent. The caller inspects the captured
/// stderr after this returns, regardless of which arm fired.
fn wait_for_settle_or_kill(child: &mut Child) {
    let deadline = Instant::now() + EXEC_SETTLE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("waiting on paladin failed: {e}"),
        }
    }
}

/// Drive a `paladin tui` invocation through its `execvp` handoff and
/// assert the wrapper never wrote its `exec_paladin_tui` advisory to
/// stderr. The inner binary may exit on its own (CI hosts without a
/// `/dev/tty` surface a `paladin-tui: <io error>` advisory and exit)
/// or block in `crossterm::event::read()` until killed — neither
/// stderr fingerprint contains `exec_paladin_tui`, which is unique
/// to the wrapper's exec-failure path.
fn assert_wrapper_exec_succeeded(child: &mut Child) {
    wait_for_settle_or_kill(child);
    let stderr = read_stderr(child);
    assert!(
        !stderr.contains("exec_paladin_tui"),
        "wrapper must not surface exec failure when paladin-tui is on PATH; \
         got stderr={stderr:?}",
    );
}

/// Drain whatever has accumulated on the child's stderr pipe so the
/// post-kill assertions can inspect it. The pipe is owned by `child`
/// after `wait_with_output` would normally consume it; we use
/// `Option::take` so the helper is reentrant across multiple reads.
fn read_stderr(child: &mut Child) -> String {
    use std::io::Read;

    let mut buf = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn paladin_tui_subcommand_execs_real_paladin_tui_on_shared_path() {
    // `CARGO_BIN_EXE_paladin-tui` is set by Cargo for this crate's
    // integration tests, pointing at the absolute path of the binary
    // built from `crates/paladin-tui/src/main.rs`. Using it lets the
    // test pin the exact binary the test crate compiled against.
    let paladin_tui_bin = PathBuf::from(env!("CARGO_BIN_EXE_paladin-tui"));
    assert!(
        paladin_tui_bin.is_file(),
        "paladin-tui binary not found at {paladin_tui_bin:?}",
    );
    let paladin_tui_dir = paladin_tui_bin
        .parent()
        .expect("paladin-tui binary path has a parent directory");

    let mut child = spawn_paladin(paladin_tui_dir, &["tui"]);
    assert_wrapper_exec_succeeded(&mut child);
}

#[test]
fn paladin_tui_subcommand_forwards_vault_to_real_paladin_tui_on_shared_path() {
    // Companion to the no-args smoke test: verify the wrapper still
    // execs into the real `paladin-tui` when `--vault` is supplied, so
    // the forwarded argv survives the chain. The CLI plan's stub-based
    // tests pin the exact forwarded bytes; this test only re-verifies
    // that the wrapper-to-binary handoff succeeds with the real
    // binary in play.
    let paladin_tui_bin = PathBuf::from(env!("CARGO_BIN_EXE_paladin-tui"));
    let paladin_tui_dir = paladin_tui_bin
        .parent()
        .expect("paladin-tui binary path has a parent directory");

    let mut child = spawn_paladin(
        paladin_tui_dir,
        &["--vault", "/tmp/paladin-smoke-vault.bin", "tui"],
    );
    assert_wrapper_exec_succeeded(&mut child);
}
