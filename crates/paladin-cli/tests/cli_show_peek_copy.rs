// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin show`. These exercise the no-prompt
//! paths only — `vault_missing`, single-match TOTP / HOTP, multi-match
//! cardinality (all-TOTP allowed, any-HOTP rejected), and HOTP counter
//! overflow against a plaintext vault. Encrypted coverage requires a
//! scripted `/dev/tty` and lands with the dedicated PTY harness called
//! out in `IMPLEMENTATION_PLAN_02_CLI.md`. `peek` and `copy` land in
//! subsequent commits and reuse the helpers in this file.

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
    let dir = TempDir::new().expect("tempdir");
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

fn create_vault_with(accounts: Vec<Account>, path: &Path) {
    let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    for acct in accounts {
        vault.add(acct);
    }
    vault.save(&store).expect("save");
}

fn list_accounts_json(path: &Path) -> Value {
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    serde_json::from_str(stdout.trim()).unwrap()
}

// --- vault_missing / cardinality / parse errors --------------------------

#[test]
fn json_show_missing_vault_rejects_with_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "show",
            "anything",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_show_no_match_rejects_with_no_match_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "show", "ghost"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("no_match"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_show_id_prefix_too_short_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "show",
            "id:abc",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert!(assert.get_output().stdout.is_empty());
}

// --- single TOTP match ---------------------------------------------------

#[test]
fn json_show_single_totp_match_emits_codes_envelope_with_counter_used_null() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "show", "alice"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let arr = value["codes"].as_array().expect("codes is array");
    assert_eq!(arr.len(), 1);
    let row = &arr[0];
    let code = row["code"].as_str().expect("code is string");
    assert_eq!(code.len(), 6, "got {code:?}");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "code must be all digits, got {code:?}",
    );
    assert_eq!(row["counter_used"], serde_json::Value::Null);
    assert!(row["valid_from"].is_number());
    assert!(row["valid_until"].is_number());
    assert!(row["seconds_remaining"].is_number());
    assert_eq!(row["account"]["label"], serde_json::json!("alice"));
    assert_eq!(row["account"]["kind"], serde_json::json!("totp"));
    assert!(assert.get_output().stderr.is_empty());
}

#[test]
fn text_show_single_totp_match_writes_tab_separated_row_to_stdout() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "show", "alice"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "got {lines:?}");
    let fields: Vec<&str> = lines[0].split('\t').collect();
    assert_eq!(
        fields.len(),
        4,
        "expected 4 tab-separated fields, got {fields:?}"
    );
    assert!(fields[0].starts_with("id:"), "{fields:?}");
    assert_eq!(fields[1], "Acme:alice");
    assert_eq!(fields[2].len(), 6);
    assert!(fields[3].ends_with('s'), "{fields:?}");
}

// --- single HOTP match: persists post-advance counter --------------------

#[test]
fn json_show_single_hotp_match_advances_and_persists_counter() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_hotp("bob", None, 42)], &path);

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "show", "bob"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let row = &value["codes"][0];
    // pre-advance counter that produced the code
    assert_eq!(row["counter_used"], serde_json::json!(42));
    // post-advance, persisted state
    assert_eq!(row["account"]["counter"], serde_json::json!(43));
    assert_eq!(row["account"]["kind"], serde_json::json!("hotp"));
    assert_eq!(row["valid_from"], serde_json::Value::Null);
    assert_eq!(row["valid_until"], serde_json::Value::Null);
    assert_eq!(row["seconds_remaining"], serde_json::Value::Null);

    // Confirm the post-advance counter was actually written to disk.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["counter"], serde_json::json!(43));

    // Re-running show advances again from 43 to 44.
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "show", "bob"])
        .assert()
        .success();
    let value: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(value["codes"][0]["counter_used"], serde_json::json!(43));
    assert_eq!(
        value["codes"][0]["account"]["counter"],
        serde_json::json!(44)
    );
}

#[test]
fn json_show_hotp_at_u64_max_rejects_with_counter_overflow_before_save() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_hotp("bob", None, u64::MAX)], &path);

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "show", "bob"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("counter_overflow"));
    assert!(assert.get_output().stdout.is_empty());

    // Overflow rejection must happen before any save: the on-disk
    // counter is still u64::MAX after the failed `show`.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr[0]["counter"], serde_json::json!(u64::MAX));
}

// --- multi-match cardinality --------------------------------------------

#[test]
fn json_show_multi_match_all_totp_returns_one_row_per_match_in_insertion_order() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp("alice", Some("GitHub")),
            make_totp("alice", Some("GitLab")),
        ],
        &path,
    );

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "show", "alice"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let arr = value["codes"].as_array().expect("codes is array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["account"]["issuer"], serde_json::json!("GitHub"));
    assert_eq!(arr[1]["account"]["issuer"], serde_json::json!("GitLab"));
    for row in arr {
        assert_eq!(row["account"]["kind"], serde_json::json!("totp"));
        assert_eq!(row["counter_used"], serde_json::Value::Null);
    }
}

#[test]
fn json_show_multi_match_with_any_hotp_rejects_with_multiple_matches() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp("alice", Some("GitHub")),
            make_hotp("alice", Some("GitLab"), 7),
        ],
        &path,
    );

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "show", "alice"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("multiple_matches"));
    let candidates = value["candidates"].as_array().expect("candidates is array");
    assert_eq!(candidates.len(), 2);
    for c in candidates {
        let disambig = c["disambiguator"].as_str().expect("disambiguator string");
        assert!(disambig.starts_with("id:"), "{disambig:?}");
    }
    assert!(assert.get_output().stdout.is_empty());

    // The HOTP counter must not have been touched on the rejected path.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    let hotp = arr
        .iter()
        .find(|a| a["kind"] == serde_json::json!("hotp"))
        .expect("hotp row present");
    assert_eq!(hotp["counter"], serde_json::json!(7));
}

#[test]
fn json_show_id_prefix_selects_unique_account_even_with_substring_collisions() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp("alice", Some("GitHub")),
            make_totp("alice", Some("GitLab")),
        ],
        &path,
    );

    // Pull one of the disambiguators from a multi-match attempt and
    // re-run with `id:` to land on exactly one account.
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "show", "alice"])
        .assert()
        .success();
    let value: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();
    let id = value["codes"][0]["account"]["id"]
        .as_str()
        .expect("id string");
    let hex = id.replace('-', "");
    let selector = format!("id:{}", &hex[..8]);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "show",
            &selector,
        ])
        .assert()
        .success();
    let value: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();
    let arr = value["codes"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["account"]["id"], serde_json::json!(id));
}
