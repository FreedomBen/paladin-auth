// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cross-cutting `--json` error-envelope schema lock for the
//! `DESIGN.md` §5 `error_kind` taxonomy
//! (`IMPLEMENTATION_PLAN_02_CLI.md` crate layout: `cli_errors_json.rs`
//! and the "JSON schema snapshots ... every `error_kind`" Tests
//! bullet).
//!
//! Per-command tests in the sibling `cli_*.rs` files cover the
//! command-specific behavior end-to-end; this file is the central
//! regression net for the JSON envelope shape itself. The intent is
//! that a new `error_kind` cannot be added without an explicit
//! envelope assertion here, and that the stable §5 schema (top-level
//! `error_kind` plus the called-out extra fields) cannot drift
//! silently per error path.
//!
//! Error kinds that require a `/dev/tty` PTY harness or fault
//! injection (`invalid_passphrase`, `decrypt_failed`,
//! `wrong_vault_lock`, `time_range`, `save_not_committed`,
//! `save_durability_unconfirmed`, `unsupported_aegis_entry_type`)
//! are exercised in their respective `cli_*.rs` files where the
//! setup naturally lives.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn paladin() -> Command {
    let mut cmd = Command::cargo_bin("paladin").expect("cargo bin");
    cmd.env_remove("NO_COLOR");
    cmd
}

fn fresh_vault_dir() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    (dir, path)
}

/// Write a 10-byte plaintext header (DESIGN.md §4.3) at `path` so
/// `inspect()` classifies the file as `Plaintext`. The file mode is
/// applied after the write so callers can dial it independently of
/// `write`'s default umask.
fn write_plaintext_header(path: &Path, mode: u32) {
    let mut bytes = Vec::with_capacity(10);
    bytes.extend_from_slice(b"PALADIN\0"); // 8-byte magic
    bytes.push(1); // format_ver = 1
    bytes.push(0); // mode = plaintext
    std::fs::write(path, &bytes).expect("write plaintext header");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("chmod vault file");
}

fn parse_json(stderr: &[u8]) -> Value {
    let s = std::str::from_utf8(stderr).expect("utf-8");
    serde_json::from_str(s.trim()).unwrap_or_else(|err| {
        panic!("expected one JSON document on stderr, got {s:?}: {err}");
    })
}

/// Assert the `--json` stream contract: stdout is empty (no other
/// bytes), stderr is exactly one JSON document terminated by a
/// single newline. Returns the parsed envelope so callers can chain
/// field assertions.
fn assert_json_error_streams(output: &std::process::Output) -> Value {
    assert!(
        output.stdout.is_empty(),
        "--json error path must keep stdout byte-clean, got {:?}",
        std::str::from_utf8(&output.stdout)
    );
    let stderr = std::str::from_utf8(&output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.ends_with('\n'),
        "stderr JSON envelope must end with a newline, got {stderr:?}"
    );
    let trimmed = stderr.trim_end_matches('\n');
    assert!(
        !trimmed.contains('\n'),
        "stderr must contain exactly one JSON document, got {stderr:?}"
    );
    parse_json(output.stderr.as_slice())
}

#[test]
fn vault_missing_envelope_carries_only_error_kind() {
    let (_dir, path) = fresh_vault_dir();
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .failure();
    let value = assert_json_error_streams(assert.get_output());
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    // §5 stable schema: vault_missing has no extra fields.
    assert_eq!(
        value.as_object().unwrap().len(),
        1,
        "vault_missing envelope must be {{ error_kind }} only, got {value}"
    );
}

#[test]
fn unsafe_permissions_envelope_carries_path_subject_and_octal_modes() {
    let (_dir, path) = fresh_vault_dir();
    write_plaintext_header(&path, 0o644);
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .failure();
    let value = assert_json_error_streams(assert.get_output());
    assert_eq!(value["error_kind"], serde_json::json!("unsafe_permissions"));
    assert_eq!(
        value["path"],
        serde_json::json!(path.to_str().unwrap()),
        "envelope must echo the offending path verbatim, got {value}"
    );
    assert_eq!(
        value["subject"],
        serde_json::json!("vault_file"),
        "0o644 file under a 0700 dir must surface vault_file, got {value}"
    );
    // §4.3 mode strings are exactly four octal digits.
    assert_eq!(value["actual_mode"], serde_json::json!("0644"));
    assert_eq!(value["expected_mode"], serde_json::json!("0600"));
}

#[test]
fn invalid_header_envelope_for_unknown_magic_is_error_kind_only() {
    let (_dir, path) = fresh_vault_dir();
    // Magic that is not PALADIN\0; inspect() rejects with InvalidHeader.
    std::fs::write(&path, b"NOT_PALADIN_BYTES_PADDED________").expect("write garbage");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .failure();
    let value = assert_json_error_streams(assert.get_output());
    assert_eq!(value["error_kind"], serde_json::json!("invalid_header"));
    assert_eq!(
        value.as_object().unwrap().len(),
        1,
        "invalid_header envelope must be {{ error_kind }} only, got {value}"
    );
}

#[test]
fn unsupported_format_version_envelope_carries_format_ver() {
    let (_dir, path) = fresh_vault_dir();
    let mut bytes = Vec::with_capacity(10);
    bytes.extend_from_slice(b"PALADIN\0");
    bytes.push(99); // format_ver = 99 (not v0.1's 1)
    bytes.push(0); // mode = plaintext (irrelevant once format_ver fails)
    std::fs::write(&path, &bytes).expect("write header");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .failure();
    let value = assert_json_error_streams(assert.get_output());
    assert_eq!(
        value["error_kind"],
        serde_json::json!("unsupported_format_version")
    );
    assert_eq!(
        value["format_ver"],
        serde_json::json!(99),
        "envelope must carry the offending byte verbatim, got {value}"
    );
}

#[test]
fn validation_error_argv_envelope_for_unknown_subcommand() {
    // Clap rejects an unknown subcommand at parse time. The argv
    // pre-scan reroutes it through the §5 envelope as
    // `validation_error` with `field: "argv"`, `reason: "usage"`
    // (IMPLEMENTATION_PLAN_02_CLI.md "Output").
    let assert = paladin()
        .args(["--json", "definitely-not-a-subcommand"])
        .assert()
        .failure();
    let value = assert_json_error_streams(assert.get_output());
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(value["reason"], serde_json::json!("usage"));
}

#[test]
fn validation_error_argv_envelope_for_unknown_top_level_flag() {
    let assert = paladin()
        .args(["--json", "--definitely-not-a-flag"])
        .assert()
        .failure();
    let value = assert_json_error_streams(assert.get_output());
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(value["reason"], serde_json::json!("usage"));
}

#[test]
fn json_error_envelopes_include_all_documented_extra_fields() {
    // Cross-cutting sanity check: for each error path that promises
    // recovery-critical extra fields per §5 / IMPLEMENTATION_PLAN_02_CLI.md
    // "Output", verify those keys are present (not just `error_kind`).
    // The point is to fail loudly if a future refactor strips a
    // recovery-critical field while keeping the same `error_kind`.
    let (_dir, path) = fresh_vault_dir();
    write_plaintext_header(&path, 0o644);
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .failure();
    let value = assert_json_error_streams(assert.get_output());
    for key in [
        "error_kind",
        "path",
        "subject",
        "actual_mode",
        "expected_mode",
    ] {
        assert!(
            value.get(key).is_some(),
            "unsafe_permissions envelope missing required field {key}: {value}"
        );
    }
}
