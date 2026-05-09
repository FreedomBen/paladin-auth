// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for the global flags + output renderers
//! (`--vault`, `--no-color`, `--json`, plus `--help` / `--version`
//! interception). See DESIGN.md §5 and `IMPLEMENTATION_PLAN_02_CLI.md`.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

fn paladin() -> Command {
    let mut cmd = Command::cargo_bin("paladin").expect("cargo bin");
    // Tests must not pick up an inherited NO_COLOR; the renderer's
    // env-driven branch is exercised explicitly below.
    cmd.env_remove("NO_COLOR");
    cmd
}

#[test]
fn text_help_succeeds_and_prints_usage_to_stdout() {
    paladin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: paladin"))
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("--json"));
}

#[test]
fn text_version_succeeds_and_prints_version_to_stdout() {
    paladin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(PKG_VERSION));
}

#[test]
fn json_help_emits_envelope_with_resolved_command_path() {
    let assert = paladin().args(["--json", "--help"]).assert().success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected one JSON document on stdout; got {stdout:?}: {e}");
    });
    assert_eq!(value["help"]["command"], serde_json::json!("paladin"));
    let text = value["help"]["text"]
        .as_str()
        .expect("help.text is a string");
    assert!(
        text.contains("Usage: paladin"),
        "help text missing usage line: {text:?}"
    );
}

#[test]
fn json_help_for_subcommand_resolves_command_path() {
    let assert = paladin()
        .args(["--json", "passphrase", "set", "--help"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        value["help"]["command"],
        serde_json::json!("paladin passphrase set")
    );
    let text = value["help"]["text"].as_str().unwrap();
    assert!(text.contains("--kdf-memory-mib"));
}

#[test]
fn json_version_emits_name_and_version_envelope() {
    let assert = paladin().args(["--json", "--version"]).assert().success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "version": { "name": "paladin", "version": PKG_VERSION }
        })
    );
}

#[test]
fn json_syntax_error_reroutes_to_validation_error_argv_usage() {
    let assert = paladin()
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
    let assert = paladin().args(["--json", "show"]).assert().failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(value["reason"], serde_json::json!("usage"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn text_syntax_error_uses_clap_diagnostic_and_exits_nonzero() {
    let assert = paladin()
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
fn text_stub_command_writes_paladin_prefixed_message_to_stderr() {
    paladin()
        .arg("show")
        .arg("query")
        .assert()
        .failure()
        .stderr("paladin: command 'show' is not yet implemented\n");
}

#[test]
fn json_stub_command_emits_synthetic_envelope_to_stderr() {
    let assert = paladin()
        .args(["--json", "show", "query"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    // Stub-only envelope; replaced by real §5 errors as commands land.
    assert_eq!(value["error_kind"], serde_json::json!("io_error"));
    assert_eq!(
        value["operation"],
        serde_json::json!("command_not_implemented")
    );
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_help_short_flag_is_intercepted() {
    let assert = paladin().args(["--json", "-h"]).assert().success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["help"]["command"], serde_json::json!("paladin"));
}

#[test]
fn json_version_short_flag_is_intercepted() {
    let assert = paladin().args(["--json", "-V"]).assert().success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["version"]["name"], serde_json::json!("paladin"));
    assert_eq!(value["version"]["version"], serde_json::json!(PKG_VERSION));
}
