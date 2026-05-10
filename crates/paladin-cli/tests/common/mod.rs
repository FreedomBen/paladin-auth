// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared test helpers for the `paladin` CLI integration suite.
//!
//! Provides:
//!
//! * `paladin()` / `paladin_command()` — `assert_cmd::Command` and
//!   `std::process::Command` factories that pin the cargo-built
//!   `paladin` binary and clear `NO_COLOR` so test output is
//!   deterministic regardless of the host's terminal preferences.
//! * `fresh_vault_path()` / `write_existing_plaintext_vault()` —
//!   on-disk fixtures duplicated across the no-prompt test files;
//!   centralized here so the PTY tests don't need to copy them again.
//! * `Pty` — a thin wrapper around `rexpect::PtySession` tailored to
//!   the §5 prompt strings. Every `[PTY]`-tagged bullet in
//!   `IMPLEMENTATION_PLAN_02_CLI.md` runs through this harness.
//! * `paladin_command_without_tty()` — the no-controlling-tty
//!   companion to `paladin_command()`. Used by the `[PTY]` bullets
//!   that assert the `io_error` `operation: "..._prompt"` envelope
//!   when `/dev/tty` cannot be opened.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::cargo::CommandCargoExt;
use rexpect::process::wait::WaitStatus;
use rexpect::session::{spawn_command, PtySession};
use tempfile::TempDir;

/// Default per-call PTY timeout (30 s) — same value `pexpect`
/// recommends for automation, and plenty for one Argon2id KDF run at
/// the §4.4 minimum (`m=8 MiB, t=1, p=1`) under the dev profile
/// `opt-level = 3` overrides set in the workspace `Cargo.toml`.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// `assert_cmd::Command` for the cargo-built `paladin` binary with a
/// cleared `NO_COLOR` so tests don't inherit terminal-coloring
/// preferences from the developer's shell.
pub fn paladin() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("paladin").expect("cargo bin");
    cmd.env_remove("NO_COLOR");
    cmd
}

/// `std::process::Command` for the same `paladin` binary used by
/// `paladin()`. Used by the PTY harness, which needs a real
/// `Command` to hand off to `rexpect::session::spawn_command`.
pub fn paladin_command() -> StdCommand {
    let mut cmd = StdCommand::cargo_bin("paladin").expect("cargo bin");
    cmd.env_remove("NO_COLOR");
    cmd
}

/// `std::process::Command` for `paladin` that runs without a
/// controlling terminal. Wraps the binary in `setsid(1)` from
/// util-linux so the child is exec'd into a fresh session, after
/// which any in-process `open("/dev/tty")` returns `ENXIO`. The
/// `--wait` flag propagates the wrapped program's exit code in the
/// uncommon path where `setsid(1)` forks (caller already a session
/// leader); on the common no-fork path it is a no-op because
/// `setsid(1)` execs into `paladin` directly.
///
/// Used by `[PTY]` bullets that need to drive the
/// `prompt::write_prompt` ENXIO branch end-to-end without scripting
/// a real PTY (none exists, by definition). The workspace forbids
/// `unsafe_code`, so we cannot call `setsid(2)` via `pre_exec`;
/// `setsid(1)` is part of every Linux base install (util-linux) and
/// gives the same effect.
pub fn paladin_command_without_tty() -> StdCommand {
    let paladin = StdCommand::cargo_bin("paladin").expect("cargo bin");
    let bin = paladin.get_program().to_os_string();
    let mut cmd = StdCommand::new("setsid");
    cmd.arg("--wait");
    cmd.arg(bin);
    cmd.env_remove("NO_COLOR");
    cmd
}

/// Fresh `0700` parent dir + path to a not-yet-created `vault.bin`.
/// The returned `TempDir` must outlive `path`.
pub fn fresh_vault_path() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    (dir, path)
}

/// Write a 16-byte `PALADIN1` plaintext header to `path` so `inspect`
/// classifies it as `VaultStatus::Plaintext` and `init` (without
/// `--force`) sees an existing primary. Mode is set to `0600` so the
/// §4.3 file-perm check accepts the fixture.
pub fn write_existing_plaintext_vault(path: &Path) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PALADIN1");
    bytes.push(1); // format_ver
    bytes.push(0); // mode = plaintext
    bytes.extend_from_slice(&[0u8; 6]); // reserved
    std::fs::write(path, &bytes).expect("write existing vault");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
}

// --- PTY harness ------------------------------------------------------------

/// Scripted-`/dev/tty` session wrapping `rexpect::PtySession`. The
/// child has its stdin/stdout/stderr connected to the PTY slave so
/// writes to `/dev/tty` reach the parent (`expect`) and
/// `send_line` reaches the child's `rpassword` /
/// `read_visible_line` calls. Captured bytes from `expect` and
/// `wait_for_exit` are concatenated into `transcript` so a failing
/// assertion can include the full PTY trace.
pub struct Pty {
    session: PtySession,
    transcript: String,
}

impl Pty {
    /// Spawn `paladin` with the given args + extra env on a fresh
    /// PTY. Each entry of `envs` is applied via `Command::env`.
    pub fn spawn<I, S>(args: I, envs: &[(&str, &str)]) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = paladin_command();
        cmd.args(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let session = spawn_command(cmd, Some(DEFAULT_TIMEOUT_MS)).expect("spawn paladin on a PTY");
        Self {
            session,
            transcript: String::new(),
        }
    }

    /// Wait for `needle` to appear on the PTY (stdin/stdout/stderr
    /// are all muxed through the slave). Returns the bytes consumed
    /// up to but not including `needle` so callers can grep for
    /// neighboring advisories. The full bytes (including `needle`)
    /// are appended to `transcript`.
    pub fn expect(&mut self, needle: &str) -> String {
        let consumed = self.session.exp_string(needle).unwrap_or_else(|err| {
            panic!(
                "expected {needle:?} on PTY but {err}\n--- transcript so far ---\n{}",
                self.transcript
            )
        });
        self.transcript.push_str(&consumed);
        self.transcript.push_str(needle);
        consumed
    }

    /// Send `line` followed by `\n` on the PTY (writes to the
    /// child's `/dev/tty`). Echo is disabled by `PtyProcess::new`,
    /// so the line is **not** echoed back into the transcript.
    pub fn send_line(&mut self, line: &str) {
        self.session.send_line(line).expect("send_line");
    }

    /// Drain remaining output to EOF, wait for the child to exit,
    /// and return its exit code together with the full PTY
    /// transcript. Panics if the child is killed by a signal or
    /// fails to exit within the timeout.
    pub fn wait_for_exit(mut self) -> ExitInfo {
        match self.session.exp_eof() {
            Ok(rest) => self.transcript.push_str(&rest),
            Err(err) => panic!(
                "waiting for child EOF: {err}\n--- transcript so far ---\n{}",
                self.transcript
            ),
        }
        let status = self.session.process.wait().unwrap_or_else(|err| {
            panic!(
                "waiting on child: {err}\n--- transcript ---\n{}",
                self.transcript
            )
        });
        let code = match status {
            WaitStatus::Exited(_, code) => code,
            other => panic!(
                "child terminated abnormally: {other:?}\n--- transcript ---\n{}",
                self.transcript
            ),
        };
        ExitInfo {
            code,
            transcript: self.transcript,
        }
    }
}

/// Result of a completed PTY session.
pub struct ExitInfo {
    pub code: i32,
    pub transcript: String,
}

impl ExitInfo {
    pub fn assert_exit(&self, expected: i32) {
        assert_eq!(
            self.code, expected,
            "expected exit code {expected}, got {}\n--- transcript ---\n{}",
            self.code, self.transcript
        );
    }

    pub fn assert_transcript_contains(&self, needle: &str) {
        assert!(
            self.transcript.contains(needle),
            "expected transcript to contain {needle:?}\n--- transcript ---\n{}",
            self.transcript
        );
    }

    pub fn assert_transcript_lacks(&self, needle: &str) {
        assert!(
            !self.transcript.contains(needle),
            "expected transcript NOT to contain {needle:?}\n--- transcript ---\n{}",
            self.transcript
        );
    }
}
