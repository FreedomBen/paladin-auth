// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin list`. These exercise the no-prompt
//! paths only — `vault_missing`, an empty plaintext vault, and a
//! populated plaintext vault under both text and `--json`. Encrypted
//! coverage requires a scripted `/dev/tty` and lands with the PTY
//! harness called out in `IMPLEMENTATION_PLAN_02_CLI.md`.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use assert_cmd::Command;
use paladin_core::{parse_otpauth, Account, Store, VaultInit};
use serde_json::Value;
use tempfile::TempDir;

fn paladin() -> Command {
    let mut cmd = Command::cargo_bin("paladin").expect("cargo bin");
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

fn fixture_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_totp(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri =
        format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP&digits=6&period=30");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn make_hotp(label: &str, issuer: Option<&str>, counter: u64) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!(
        "otpauth://hotp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP&digits=6&counter={counter}"
    );
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn create_empty_plaintext_vault(path: &Path) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    vault.save(&store).expect("save");
}

fn create_populated_plaintext_vault(path: &Path) {
    let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    vault.add(make_totp("alice", Some("Acme")));
    vault.add(make_hotp("bob", None, 42));
    vault.save(&store).expect("save");
}

#[test]
fn json_missing_vault_rejects_with_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn text_missing_vault_rejects_without_writing_to_stdout() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "list"])
        .assert()
        .failure();
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_empty_vault_renders_empty_accounts_array() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value, serde_json::json!({ "accounts": [] }));
    assert!(assert.get_output().stderr.is_empty());
}

#[test]
fn text_empty_vault_writes_no_rows_to_stdout() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    assert_eq!(assert.get_output().stdout, b"");
}

#[test]
fn json_populated_vault_returns_account_summaries_in_insertion_order() {
    let (_dir, path) = fresh_vault_path();
    create_populated_plaintext_vault(&path);

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let arr = value["accounts"].as_array().expect("accounts is array");
    assert_eq!(arr.len(), 2);

    // Insertion order: alice (TOTP) then bob (HOTP).
    assert_eq!(arr[0]["label"], serde_json::json!("alice"));
    assert_eq!(arr[0]["issuer"], serde_json::json!("Acme"));
    assert_eq!(arr[0]["kind"], serde_json::json!("totp"));
    assert_eq!(arr[0]["period"], serde_json::json!(30));
    assert_eq!(arr[0]["counter"], serde_json::Value::Null);

    assert_eq!(arr[1]["label"], serde_json::json!("bob"));
    assert_eq!(arr[1]["issuer"], serde_json::Value::Null);
    assert_eq!(arr[1]["kind"], serde_json::json!("hotp"));
    assert_eq!(arr[1]["counter"], serde_json::json!(42));
    assert_eq!(arr[1]["period"], serde_json::Value::Null);

    // No secret bytes in any row.
    for row in arr {
        let obj = row.as_object().expect("row is object");
        assert!(!obj.contains_key("secret"), "row leaked secret: {row}");
    }
}

#[test]
fn text_populated_vault_emits_one_line_per_account_in_insertion_order() {
    let (_dir, path) = fresh_vault_path();
    create_populated_plaintext_vault(&path);

    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected one line per account: {stdout:?}");

    // Row 0: TOTP alice with issuer; period rendered as `30s`.
    assert!(lines[0].contains("Acme:alice"), "row 0 = {:?}", lines[0]);
    assert!(lines[0].contains("totp/sha1/6"), "row 0 = {:?}", lines[0]);
    assert!(lines[0].contains("30s"), "row 0 = {:?}", lines[0]);
    assert!(lines[0].contains("id:"), "row 0 missing id prefix");

    // Row 1: HOTP bob without issuer; counter rendered as `c=42`.
    assert!(lines[1].contains("bob"), "row 1 = {:?}", lines[1]);
    assert!(
        !lines[1].contains(":bob"),
        "bare label must not have issuer prefix"
    );
    assert!(lines[1].contains("hotp/sha1/6"), "row 1 = {:?}", lines[1]);
    assert!(lines[1].contains("c=42"), "row 1 = {:?}", lines[1]);
}
