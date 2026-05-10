// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin tui`, the `execvp` wrapper around
//! `paladin-tui`. See `IMPLEMENTATION_PLAN_02_CLI.md` "`paladin tui`
//! exec wrapper". These tests place a stub `paladin-tui` script on
//! `PATH` whose only job is to record its argv to a file so the
//! wrapper's flag forwarding can be asserted from the parent test
//! process.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

/// Build an `assert_cmd::Command` for the `paladin` binary with a
/// clean ANSI environment. Tests that need a controlled `PATH` set it
/// explicitly via [`Command::env`] — `cargo_bin` returns an absolute
/// path so the parent process always finds the binary regardless.
fn paladin() -> Command {
    let mut cmd = Command::cargo_bin("paladin").expect("cargo bin");
    cmd.env_remove("NO_COLOR");
    cmd
}

/// Write a stub `paladin-tui` script that records its argv (one
/// argument per line) to `argv.log` in the same directory and exits
/// `0` after printing the marker `EXEC_OK` to stdout.
fn stub_dir_with_argv_recorder() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let script = dir.path().join("paladin-tui");
    let log = dir.path().join("argv.log");
    let body = format!(
        "#!/bin/sh\n\
         for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{0}'; done\n\
         echo EXEC_OK\n",
        log.display(),
    );
    fs::write(&script, body).expect("write stub");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod stub 0755");
    dir
}

/// Path to the argv-recording log written by the stub `paladin-tui`.
fn argv_log(dir: &TempDir) -> PathBuf {
    dir.path().join("argv.log")
}

/// Read the recorded argv as a Vec of strings, in the order the stub
/// observed them. Returns an empty Vec if the log file does not
/// exist (i.e. the stub was never invoked).
fn read_argv(log: &Path) -> Vec<String> {
    if !log.exists() {
        return Vec::new();
    }
    fs::read_to_string(log)
        .expect("read argv log")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn paladin_tui_execs_paladin_tui_with_no_extra_flags_when_globals_are_default() {
    let stub = stub_dir_with_argv_recorder();
    let assert = paladin()
        .env("PATH", stub.path())
        .args(["tui"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert!(
        stdout.contains("EXEC_OK"),
        "expected stub to run; got stdout={stdout:?}",
    );
    assert!(
        read_argv(&argv_log(&stub)).is_empty(),
        "expected no forwarded argv when no globals were supplied",
    );
}

#[test]
fn paladin_tui_forwards_vault_in_global_position() {
    let stub = stub_dir_with_argv_recorder();
    paladin()
        .env("PATH", stub.path())
        .args(["--vault", "/tmp/some-vault.bin", "tui"])
        .assert()
        .success();
    assert_eq!(
        read_argv(&argv_log(&stub)),
        vec!["--vault".to_string(), "/tmp/some-vault.bin".to_string()],
    );
}

#[test]
fn paladin_tui_forwards_vault_in_subcommand_position() {
    let stub = stub_dir_with_argv_recorder();
    paladin()
        .env("PATH", stub.path())
        .args(["tui", "--vault", "/tmp/some-vault.bin"])
        .assert()
        .success();
    assert_eq!(
        read_argv(&argv_log(&stub)),
        vec!["--vault".to_string(), "/tmp/some-vault.bin".to_string()],
    );
}

#[test]
fn paladin_tui_forwards_no_color_in_global_position() {
    let stub = stub_dir_with_argv_recorder();
    paladin()
        .env("PATH", stub.path())
        .args(["--no-color", "tui"])
        .assert()
        .success();
    assert_eq!(read_argv(&argv_log(&stub)), vec!["--no-color".to_string()],);
}

#[test]
fn paladin_tui_forwards_no_color_in_subcommand_position() {
    let stub = stub_dir_with_argv_recorder();
    paladin()
        .env("PATH", stub.path())
        .args(["tui", "--no-color"])
        .assert()
        .success();
    assert_eq!(read_argv(&argv_log(&stub)), vec!["--no-color".to_string()],);
}

#[test]
fn paladin_tui_forwards_both_vault_and_no_color() {
    let stub = stub_dir_with_argv_recorder();
    paladin()
        .env("PATH", stub.path())
        .args(["--vault", "/tmp/v", "--no-color", "tui"])
        .assert()
        .success();
    let argv = read_argv(&argv_log(&stub));
    assert!(
        argv.contains(&"--vault".to_string()) && argv.contains(&"/tmp/v".to_string()),
        "expected --vault forwarded, got {argv:?}",
    );
    assert!(
        argv.contains(&"--no-color".to_string()),
        "expected --no-color forwarded, got {argv:?}",
    );
}

#[test]
fn paladin_json_tui_rejects_at_parse_time_with_validation_error_envelope() {
    let stub = stub_dir_with_argv_recorder();
    let assert = paladin()
        .env("PATH", stub.path())
        .args(["--json", "tui"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim())
        .unwrap_or_else(|e| panic!("expected JSON error envelope on stderr; got {stderr:?}: {e}"));
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(
        value["reason"],
        serde_json::json!("tui_unsupported_under_json"),
    );
    assert!(
        assert.get_output().stdout.is_empty(),
        "stdout must be empty under --json on failure",
    );
    assert!(
        !argv_log(&stub).exists(),
        "exec_tui must not invoke paladin-tui when --json is rejected",
    );
}

#[test]
fn paladin_tui_json_after_subcommand_rejects_with_validation_error_envelope() {
    let stub = stub_dir_with_argv_recorder();
    let assert = paladin()
        .env("PATH", stub.path())
        .args(["tui", "--json"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(
        value["reason"],
        serde_json::json!("tui_unsupported_under_json"),
    );
    assert!(assert.get_output().stdout.is_empty());
    assert!(!argv_log(&stub).exists());
}

#[test]
fn paladin_json_tui_help_emits_help_envelope_without_inspecting_path() {
    // `--help` is a success-terminal path intercepted by the JSON
    // help envelope renderer in `main.rs::handle_parse_err`. The exec
    // wrapper must not be reached, so the empty-PATH stub is never
    // invoked.
    let stub = stub_dir_with_argv_recorder();
    let assert = paladin()
        .env("PATH", stub.path())
        .args(["--json", "tui", "--help"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["help"]["command"], serde_json::json!("paladin tui"));
    let text = value["help"]["text"].as_str().expect("help text");
    assert!(
        text.contains("Usage: tui"),
        "help text missing tui usage line: {text:?}",
    );
    assert!(
        text.contains("paladin-tui"),
        "help text missing tui description that names paladin-tui: {text:?}",
    );
    assert!(
        !argv_log(&stub).exists(),
        "--json tui --help must not exec paladin-tui",
    );
}

#[test]
fn paladin_tui_text_mode_with_missing_paladin_tui_returns_io_error_exec_paladin_tui() {
    // Empty PATH guarantees `paladin-tui` cannot be resolved; the
    // wrapper surfaces `io_error` with `operation: "exec_paladin_tui"`
    // per the implementation plan.
    let empty = TempDir::new().expect("tempdir");
    let assert = paladin()
        .env("PATH", empty.path())
        .args(["tui"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.starts_with("paladin: "),
        "expected program-name prefix, got {stderr:?}",
    );
    assert!(
        stderr.contains("exec_paladin_tui"),
        "expected exec_paladin_tui operation tag in stderr, got {stderr:?}",
    );
}
