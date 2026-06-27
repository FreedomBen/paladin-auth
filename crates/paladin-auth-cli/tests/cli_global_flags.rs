// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for the global flags + output renderers
//! (`--vault`, `--no-color`, `--json`, plus `--help` / `--version`
//! interception). See docs/DESIGN.md §5 and `docs/IMPLEMENTATION_PLAN_02_CLI.md`.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use assert_cmd::Command;
use paladin_auth_core::{parse_otpauth, Store, VaultInit};
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

fn paladin_auth() -> Command {
    let mut cmd = Command::cargo_bin("paladin-auth").expect("cargo bin");
    // Tests must not pick up an inherited NO_COLOR; the renderer's
    // env-driven branch is exercised explicitly below.
    cmd.env_remove("NO_COLOR");
    cmd
}

fn fresh_vault_path() -> (TempDir, PathBuf) {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    (dir, path)
}

fn seed_populated_plaintext_vault(path: &Path) {
    let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    let now = SystemTime::now();
    for uri in [
        "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=6&period=30",
        "otpauth://hotp/Acme:bob?secret=KRSXG5DJN5XGS3DPMNQXG43JN5XGS3BB&digits=6&counter=11",
    ] {
        let validated = parse_otpauth(uri, now).expect("parse fixture");
        let _ = vault.add(validated.account);
    }
    vault.save(&store).expect("save");
}

/// Assert the byte slice contains no ESC (`0x1B`) byte. The CLI's §5
/// contract is that ANSI styling is suppressed under `--no-color`,
/// `NO_COLOR`, or non-TTY stdout — and currently the CLI never emits
/// ANSI in any path. These regression tests pin the absence so a
/// future styling addition cannot quietly bypass the suppression
/// triggers.
fn assert_no_ansi_escapes(label: &str, bytes: &[u8]) {
    assert!(
        !bytes.contains(&0x1B),
        "{label} must not contain ANSI ESC bytes; got: {:?}",
        String::from_utf8_lossy(bytes),
    );
}

#[test]
fn text_help_succeeds_and_prints_usage_to_stdout() {
    paladin_auth()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: paladin-auth"))
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn text_version_succeeds_and_prints_version_to_stdout() {
    paladin_auth()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(PKG_VERSION));
}

#[test]
fn json_help_emits_envelope_with_resolved_command_path() {
    let assert = paladin_auth().args(["--json", "--help"]).assert().success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected one JSON document on stdout; got {stdout:?}: {e}");
    });
    assert_eq!(value["help"]["command"], serde_json::json!("paladin-auth"));
    let text = value["help"]["text"]
        .as_str()
        .expect("help.text is a string");
    assert!(
        text.contains("Usage: paladin-auth"),
        "help text missing usage line: {text:?}"
    );
}

#[test]
fn json_help_for_subcommand_resolves_command_path() {
    let assert = paladin_auth()
        .args(["--json", "passphrase", "set", "--help"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        value["help"]["command"],
        serde_json::json!("paladin-auth passphrase set")
    );
    let text = value["help"]["text"].as_str().unwrap();
    assert!(text.contains("--kdf-memory-mib"));
}

#[test]
fn json_version_emits_name_and_version_envelope() {
    let assert = paladin_auth()
        .args(["--json", "--version"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "version": { "name": "paladin-auth", "version": PKG_VERSION }
        })
    );
}

#[test]
fn json_syntax_error_reroutes_to_validation_error_argv_usage() {
    let assert = paladin_auth()
        .args(["--json", "definitely-not-a-subcommand"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap_or_else(|e| {
        panic!("expected JSON error envelope on stderr; got {stderr:?}: {e}");
    });
    assert_eq!(
        value,
        serde_json::json!({
            "error_kind": "validation_error",
            "field": "argv",
            "reason": "usage",
        })
    );
    // stdout must be empty under --json on failure.
    assert!(
        assert.get_output().stdout.is_empty(),
        "stdout must be empty on JSON error path"
    );
}

#[test]
fn json_missing_required_query_reroutes_to_validation_error_envelope() {
    let assert = paladin_auth().args(["--json", "show"]).assert().failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(value["reason"], serde_json::json!("usage"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn text_syntax_error_uses_clap_diagnostic_and_exits_nonzero() {
    let assert = paladin_auth()
        .arg("definitely-not-a-subcommand")
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    // Clap prefixes its usage errors with "error:".
    assert!(
        stderr.contains("error:"),
        "expected clap diagnostic, got {stderr:?}"
    );
    // No JSON envelope on stderr without --json.
    assert!(
        serde_json::from_str::<Value>(stderr).is_err(),
        "text-mode error must not parse as JSON: {stderr:?}"
    );
}

#[test]
fn json_help_short_flag_is_intercepted() {
    let assert = paladin_auth().args(["--json", "-h"]).assert().success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["help"]["command"], serde_json::json!("paladin-auth"));
}

#[test]
fn json_version_short_flag_is_intercepted() {
    let assert = paladin_auth().args(["--json", "-V"]).assert().success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["version"]["name"], serde_json::json!("paladin-auth"));
    assert_eq!(value["version"]["version"], serde_json::json!(PKG_VERSION));
}

// =========================================================================
// `--no-color` / `NO_COLOR` / non-TTY ANSI suppression
//
// `Mode::resolve` (in `output/mod.rs`) sets `color = false` when any of
// `--no-color`, `NO_COLOR`, or non-TTY stdout fires. The current text
// renderers do not emit any ANSI escapes regardless, but these tests
// pin the contract end-to-end across each suppression trigger so a
// future styling addition cannot regress one of the three paths.
// `paladin-auth list` against a populated plaintext vault is the cheapest
// non-trivial text output to exercise (multi-row, no prompts).
// =========================================================================

#[test]
fn text_no_color_flag_disables_ansi_in_text_mode_output() {
    let (_dir, vault_path) = fresh_vault_path();
    seed_populated_plaintext_vault(&vault_path);

    let assert = paladin_auth()
        .args([
            "--no-color",
            "--vault",
            vault_path.to_str().unwrap(),
            "list",
        ])
        .assert()
        .success();
    assert_no_ansi_escapes("stdout", &assert.get_output().stdout);
    assert_no_ansi_escapes("stderr", &assert.get_output().stderr);
}

#[test]
fn text_no_color_env_var_disables_ansi_when_flag_is_absent() {
    let (_dir, vault_path) = fresh_vault_path();
    seed_populated_plaintext_vault(&vault_path);

    let mut cmd = Command::cargo_bin("paladin-auth").expect("cargo bin");
    // Override the `paladin_auth()` helper's `env_remove("NO_COLOR")` so
    // this test exercises the env-var branch of `Mode::resolve`.
    cmd.env("NO_COLOR", "1");
    let assert = cmd
        .args(["--vault", vault_path.to_str().unwrap(), "list"])
        .assert()
        .success();
    assert_no_ansi_escapes("stdout", &assert.get_output().stdout);
    assert_no_ansi_escapes("stderr", &assert.get_output().stderr);
}

#[test]
fn text_non_tty_stdout_disables_ansi_without_flag_or_env() {
    // `assert_cmd` always pipes the child's stdout to a buffer, so
    // `std::io::stdout().is_terminal()` is `false` in this test
    // process. With neither `--no-color` nor `NO_COLOR` set,
    // `Mode::resolve` still picks `color = false` because the TTY
    // probe fails. This locks the §5 "non-TTY → no ANSI" trigger
    // independently of the other two.
    let (_dir, vault_path) = fresh_vault_path();
    seed_populated_plaintext_vault(&vault_path);

    let assert = paladin_auth()
        .args(["--vault", vault_path.to_str().unwrap(), "list"])
        .assert()
        .success();
    assert_no_ansi_escapes("stdout", &assert.get_output().stdout);
    assert_no_ansi_escapes("stderr", &assert.get_output().stderr);
}
