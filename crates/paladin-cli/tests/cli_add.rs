// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin add`. Covers the no-prompt input
//! modes only — `--uri`, manual flags, mode-combination rejection,
//! `--json` interactive rejection, and duplicate detection. Interactive
//! happy-path coverage requires a scripted `/dev/tty` and lands with
//! the dedicated PTY harness called out in
//! `IMPLEMENTATION_PLAN_02_CLI.md`. `--qr` happy-path coverage needs
//! synthetic QR fixtures and lands alongside that change.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use paladin_core::{Store, VaultInit};
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

fn create_empty_plaintext_vault(path: &Path) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    vault.save(&store).expect("save");
}

const SAMPLE_TOTP_URI: &str =
    "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=6&period=30";
const SAMPLE_HOTP_URI: &str =
    "otpauth://hotp/Beta:bob?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=6&counter=7";
const LONG_BASE32_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

fn list_accounts_json(path: &Path) -> Value {
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    serde_json::from_str(stdout.trim()).unwrap()
}

// --- --uri input mode -----------------------------------------------------

#[test]
fn json_uri_totp_succeeds_and_account_appears_in_list() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            SAMPLE_TOTP_URI,
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("alice"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Acme"));
    assert_eq!(value["account"]["kind"], serde_json::json!("totp"));
    assert_eq!(value["warnings"], serde_json::json!([]));
    assert!(assert.get_output().stderr.is_empty());

    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], serde_json::json!("alice"));
}

#[test]
fn json_uri_hotp_preserves_counter_and_appears_in_list() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            SAMPLE_HOTP_URI,
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["kind"], serde_json::json!("hotp"));
    assert_eq!(value["account"]["counter"], serde_json::json!(7));
    assert_eq!(value["account"]["period"], Value::Null);
}

#[test]
fn text_uri_add_writes_human_line_to_stdout_with_disambiguator() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            SAMPLE_TOTP_URI,
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert!(
        stdout.starts_with("Added Acme:alice (id:"),
        "got {stdout:?}"
    );
    assert!(stdout.ends_with(").\n"), "got {stdout:?}");
}

#[test]
fn json_uri_short_secret_warning_appears_in_warnings_array() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    // 16-char base32 → 10 bytes decoded, below the recommended 16-byte
    // floor, so `validate_manual` attaches a `short_secret` warning.
    let uri = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30";
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            uri,
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let warns = value["warnings"].as_array().expect("warnings");
    assert_eq!(warns.len(), 1);
    assert_eq!(warns[0]["kind"], serde_json::json!("short_secret"));
    // Stderr stays byte-clean under --json (warnings flow into envelope).
    assert!(assert.get_output().stderr.is_empty());
}

#[test]
fn text_uri_short_secret_warning_writes_to_stderr() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let uri = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30";
    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "add", "--uri", uri])
        .assert()
        .success();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.contains("warning"),
        "expected stderr warning, got {stderr:?}"
    );
}

#[test]
fn json_uri_malformed_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            "not-an-otpauth-uri",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert!(assert.get_output().stdout.is_empty());
}

// --- Manual input mode ----------------------------------------------------

#[test]
fn json_manual_totp_succeeds_with_minimum_required_flags() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--label",
            "alice",
            "--secret",
            LONG_BASE32_SECRET,
            "--issuer",
            "Acme",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("alice"));
    assert_eq!(value["account"]["kind"], serde_json::json!("totp"));
    assert_eq!(value["account"]["digits"], serde_json::json!(6));
    assert_eq!(value["account"]["period"], serde_json::json!(30));
    assert_eq!(value["account"]["counter"], Value::Null);
}

#[test]
fn json_manual_hotp_with_explicit_kind_and_counter() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--label",
            "bob",
            "--secret",
            LONG_BASE32_SECRET,
            "--kind",
            "hotp",
            "--counter",
            "42",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["kind"], serde_json::json!("hotp"));
    assert_eq!(value["account"]["counter"], serde_json::json!(42));
    assert_eq!(value["account"]["period"], Value::Null);
}

#[test]
fn json_manual_missing_label_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--secret",
            LONG_BASE32_SECRET,
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("label"));
}

#[test]
fn json_manual_missing_secret_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--label",
            "alice",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("secret"));
}

#[test]
fn json_manual_period_with_hotp_kind_rejects_as_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--label",
            "bob",
            "--secret",
            LONG_BASE32_SECRET,
            "--kind",
            "hotp",
            "--period",
            "30",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("period"));
    assert_eq!(value["reason"], serde_json::json!("rejected_on_hotp"));
}

#[test]
fn json_manual_counter_without_kind_hotp_rejects_as_validation_error() {
    // `--kind` defaults to TOTP, so passing `--counter` without
    // `--kind hotp` is rejected by `validate_manual` per §5.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--label",
            "alice",
            "--secret",
            LONG_BASE32_SECRET,
            "--counter",
            "5",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("counter"));
    assert_eq!(value["reason"], serde_json::json!("rejected_on_totp"));
}

#[test]
fn json_manual_invalid_icon_hint_slug_rejects_as_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--label",
            "alice",
            "--secret",
            LONG_BASE32_SECRET,
            "--icon-hint",
            "Not A Slug!",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("icon_hint"));
}

// --- Mode-combination rejection (clap parse-time) -------------------------

#[test]
fn uri_plus_label_rejects_at_parse_time() {
    let assert = paladin()
        .args(["add", "--uri", SAMPLE_TOTP_URI, "--label", "alice"])
        .assert()
        .failure();
    // Clap's text diagnostic on stderr; non-zero exit. Exact wording is
    // not asserted because it tracks the upstream clap version.
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.contains("error"),
        "expected clap error, got {stderr:?}"
    );
}

#[test]
fn qr_plus_uri_rejects_at_parse_time() {
    let (_dir, path) = fresh_vault_path();
    let qr_path = path.with_file_name("does-not-exist.png");
    let assert = paladin()
        .args([
            "add",
            "--uri",
            SAMPLE_TOTP_URI,
            "--qr",
            qr_path.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.contains("error"),
        "expected clap error, got {stderr:?}"
    );
}

#[test]
fn qr_plus_allow_duplicate_rejects_at_parse_time() {
    let (_dir, path) = fresh_vault_path();
    let qr_path = path.with_file_name("does-not-exist.png");
    let assert = paladin()
        .args([
            "add",
            "--qr",
            qr_path.to_str().unwrap(),
            "--allow-duplicate",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.contains("error"),
        "expected clap error, got {stderr:?}"
    );
}

#[test]
fn icon_hint_plus_no_icon_hint_rejects_at_parse_time() {
    let assert = paladin()
        .args([
            "add",
            "--label",
            "alice",
            "--secret",
            LONG_BASE32_SECRET,
            "--icon-hint",
            "github",
            "--no-icon-hint",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.contains("error"),
        "expected clap error, got {stderr:?}"
    );
}

// --- --json without input mode -------------------------------------------

#[test]
fn json_add_without_input_mode_rejects_as_validation_error() {
    // No --uri, no --qr, no manual flags: would normally drop into
    // interactive mode; under --json that is parse-time invalid per §5.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "add"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert!(assert.get_output().stdout.is_empty());
}

// --- Duplicate detection -------------------------------------------------

#[test]
fn json_duplicate_add_rejects_with_duplicate_account_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    // First add succeeds.
    paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            SAMPLE_TOTP_URI,
        ])
        .assert()
        .success();

    // Identical second add (same secret/issuer/label) rejects.
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            SAMPLE_TOTP_URI,
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("duplicate_account"));
    assert_eq!(value["account"]["label"], serde_json::json!("alice"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Acme"));

    // The vault still has exactly one entry — duplicate rejection is
    // pre-mutation.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
}

#[test]
fn json_duplicate_with_allow_duplicate_appends_a_second_account() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            SAMPLE_TOTP_URI,
        ])
        .assert()
        .success();

    paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            SAMPLE_TOTP_URI,
            "--allow-duplicate",
        ])
        .assert()
        .success();

    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 2, "--allow-duplicate must append a second row");
}

// --- Vault state ---------------------------------------------------------

#[test]
fn json_missing_vault_rejects_with_vault_missing() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "add",
            "--uri",
            SAMPLE_TOTP_URI,
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    assert!(assert.get_output().stdout.is_empty());
}
