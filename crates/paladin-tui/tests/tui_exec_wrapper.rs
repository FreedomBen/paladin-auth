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

use std::path::PathBuf;

use assert_cmd::Command;

/// Locate the `paladin` CLI binary built for this workspace.
///
/// Falls back to `assert_cmd::Command::cargo_bin`'s sibling-dir
/// heuristic (`<this_test_binary_parent>/paladin`). `cargo test
/// --workspace` builds every crate's binaries into the shared
/// `target/<profile>/` directory, so the fallback resolves to the
/// real `paladin` binary in CI and after `cargo build --workspace`
/// locally.
fn paladin_cli_command() -> Command {
    Command::cargo_bin("paladin")
        .expect("paladin binary built (run `cargo build --workspace` or `cargo test --workspace`)")
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

    let mut cmd = paladin_cli_command();
    cmd.env_remove("NO_COLOR")
        .env("PATH", paladin_tui_dir)
        .args(["tui"]);

    let assert = cmd.assert().success();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    // The wrapper renders `exec_paladin_tui` on stderr only when
    // `execvp` fails. Its absence after `assert.success()` proves the
    // wrapper resolved `paladin-tui` on the controlled `PATH` and
    // exec'd into it.
    assert!(
        !stderr.contains("exec_paladin_tui"),
        "wrapper must not surface exec failure when paladin-tui is on PATH; got stderr={stderr:?}",
    );
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

    let mut cmd = paladin_cli_command();
    cmd.env_remove("NO_COLOR")
        .env("PATH", paladin_tui_dir)
        .args(["--vault", "/tmp/paladin-smoke-vault.bin", "tui"]);

    let assert = cmd.assert().success();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        !stderr.contains("exec_paladin_tui"),
        "wrapper must not surface exec failure when paladin-tui is on PATH; got stderr={stderr:?}",
    );
}
