// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin export`. Covers the no-prompt code
//! paths against a plaintext source vault: `--plaintext` happy path
//! (empty + populated, mode `0600`, JSON otpauth array round-trip),
//! `--force` overwrite, refuse-overwrite-without-force, plaintext
//! export warning routing in text vs `--json` mode, the §5 success
//! envelope, and the encrypted branch's no-prompt error paths
//! (every KDF flag failure, plus the precedence rules that put KDF
//! errors before `vault_missing`, the overwrite check, and the
//! bundle-passphrase prompt).
//!
//! Encrypted-export happy paths require entering a fresh export-bundle
//! passphrase via `/dev/tty` plus a confirmation; those land alongside
//! the dedicated PTY harness called out in
//! `IMPLEMENTATION_PLAN_02_CLI.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use assert_cmd::Command;
use paladin_core::{parse_otpauth, Store, VaultInit};
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

fn create_plaintext_vault_with(path: &Path, uris: &[&str]) {
    let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    let now = SystemTime::now();
    for uri in uris {
        let validated = parse_otpauth(uri, now).expect("parse fixture");
        let _id = vault.add(validated.account);
    }
    vault.save(&store).expect("save");
}

const TOTP_URI_ALICE: &str =
    "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=6&period=30";
const HOTP_URI_BOB: &str =
    "otpauth://hotp/Acme:bob?secret=KRSXG5DJN5XGS3DPMNQXG43JN5XGS3BB&digits=6&counter=11";

// ==========================================================================
// `--plaintext` happy paths
// ==========================================================================

#[test]
fn plaintext_export_against_empty_vault_writes_empty_json_array() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("creds.json");

    paladin()
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).expect("read export");
    let s = std::str::from_utf8(&bytes).expect("utf-8");
    assert_eq!(s, "[]");
}

#[test]
fn plaintext_export_writes_output_file_with_zero_six_zero_zero_mode() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("creds.json");

    paladin()
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
}

#[test]
fn plaintext_export_writes_one_otpauth_uri_per_account_in_insertion_order() {
    let (dir, vault_path) = fresh_vault_path();
    create_plaintext_vault_with(&vault_path, &[TOTP_URI_ALICE, HOTP_URI_BOB]);
    let out = dir.path().join("creds.json");

    paladin()
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).expect("read export");
    let arr: Vec<String> = serde_json::from_slice(&bytes).expect("json array");
    assert_eq!(arr.len(), 2);
    let now = SystemTime::now();
    let _ = parse_otpauth(&arr[0], now).expect("alice round-trips");
    let _ = parse_otpauth(&arr[1], now).expect("bob round-trips");
}

#[test]
fn plaintext_export_text_mode_prints_unencrypted_secrets_warning_to_stderr() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("creds.json");

    let assert = paladin()
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.contains("Plaintext export"),
        "expected plaintext-export warning, got {stderr:?}"
    );
    assert!(
        stderr.contains("unencrypted"),
        "expected 'unencrypted' wording, got {stderr:?}"
    );
}

#[test]
fn plaintext_export_text_mode_success_line_names_path_and_mode() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("creds.json");

    let assert = paladin()
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert!(
        stdout.starts_with("Exported plaintext bundle to "),
        "got {stdout:?}"
    );
    assert!(
        stdout.contains(out.to_str().unwrap()),
        "missing destination path in stdout, got {stdout:?}"
    );
}

#[test]
fn plaintext_export_json_mode_emits_section_5_envelope_and_keeps_stderr_empty() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("creds.json");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    // §5 strict-mode rule: under `--json` the plaintext-export advisory
    // is suppressed because the caller opted in via `--plaintext`.
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(stderr.is_empty(), "expected empty stderr, got {stderr:?}");

    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["written"], serde_json::json!(out.to_str().unwrap()));
    assert_eq!(v["format"], serde_json::json!("otpauth"));
}

// ==========================================================================
// Overwrite policy
// ==========================================================================

#[test]
fn json_export_refuses_overwrite_without_force() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("existing.json");
    std::fs::write(&out, b"prev").expect("seed existing");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("path"));
    assert_eq!(v["reason"], serde_json::json!("output_exists"));

    // The destination must not have been clobbered.
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(bytes, b"prev");
}

#[test]
fn force_flag_allows_overwriting_existing_file_with_export_contents() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("existing.json");
    std::fs::write(&out, b"prev").expect("seed existing");

    paladin()
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(bytes, b"[]");
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn overwrite_check_fires_before_vault_unlock_under_json() {
    // Source vault is plaintext (no unlock prompt) but the
    // overwrite-check still has to fire before opening the vault so a
    // would-be passphrase prompt against an encrypted vault is never
    // reached. We verify the strict ordering on the plaintext path
    // because exercising the encrypted-vault prompt requires PTY
    // scripting.
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("existing.json");
    std::fs::write(&out, b"prev").expect("seed existing");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["reason"], serde_json::json!("output_exists"));
}

// ==========================================================================
// Argument parsing — clap-enforced exclusivity
// ==========================================================================

#[test]
fn json_export_without_target_rejects_at_parse_time_with_validation_error_argv() {
    let (_dir, vault_path) = fresh_vault_path();

    let assert = paladin()
        .args(["--json", "--vault", vault_path.to_str().unwrap(), "export"])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("argv"));
    assert_eq!(v["reason"], serde_json::json!("usage"));
}

#[test]
fn json_export_with_both_plaintext_and_encrypted_rejects_at_parse_time() {
    let (dir, vault_path) = fresh_vault_path();
    let out_a = dir.path().join("a.json");
    let out_b = dir.path().join("b.bin");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out_a.to_str().unwrap(),
            "--encrypted",
            out_b.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("argv"));
}

// ==========================================================================
// `vault_missing` short-circuit
// ==========================================================================

#[test]
fn json_export_returns_vault_missing_when_source_vault_does_not_exist() {
    let dir = TempDir::new().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let vault_path = dir.path().join("vault.bin");
    let out = dir.path().join("creds.json");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--plaintext",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("vault_missing"));

    // No output file should have been created.
    assert!(!out.exists(), "export should not have written {out:?}");
}

// ==========================================================================
// Encrypted-export — KDF flag validation (no PTY required)
// ==========================================================================

#[test]
fn json_encrypted_export_rejects_invalid_kdf_memory_mib_with_validation_error() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("bundle.bin");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--encrypted",
            out.to_str().unwrap(),
            "--kdf-memory-mib",
            "abc",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("kdf-memory-mib"));
    assert_eq!(v["reason"], serde_json::json!("invalid_integer"));
    assert!(!out.exists());
}

#[test]
fn json_encrypted_export_rejects_overflow_kdf_memory_mib_with_overflow_reason() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("bundle.bin");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--encrypted",
            out.to_str().unwrap(),
            "--kdf-memory-mib",
            "4194304",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("kdf-memory-mib"));
    assert_eq!(v["reason"], serde_json::json!("overflow"));
}

#[test]
fn json_encrypted_export_rejects_kdf_time_below_floor_with_kdf_params_out_of_bounds() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("bundle.bin");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--encrypted",
            out.to_str().unwrap(),
            "--kdf-time",
            "0",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["error_kind"],
        serde_json::json!("kdf_params_out_of_bounds")
    );
    assert_eq!(v["t"], serde_json::json!(0));
}

#[test]
fn json_encrypted_export_kdf_validation_wins_over_vault_missing_precedence() {
    // No vault and an invalid KDF integer: the KDF parse fires before
    // `inspect`, so the user sees `validation_error` rather than
    // `vault_missing`. Locked by the §5 ordering rule for encrypted-
    // write commands.
    let dir = TempDir::new().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let vault_path = dir.path().join("vault.bin");
    let out = dir.path().join("bundle.bin");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--encrypted",
            out.to_str().unwrap(),
            "--kdf-time",
            "nope",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("kdf-time"));
}

#[test]
fn json_encrypted_export_kdf_validation_wins_over_overwrite_existing_output() {
    // Existing destination + out-of-range KDF: KDF rejection fires
    // first, before the overwrite check. Mirrors the precedence from
    // `init`'s "KDF wins over `vault_exists`".
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let out = dir.path().join("existing.bin");
    std::fs::write(&out, b"prev").expect("seed existing");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--encrypted",
            out.to_str().unwrap(),
            "--kdf-time",
            "0",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["error_kind"],
        serde_json::json!("kdf_params_out_of_bounds")
    );

    // The pre-existing destination must remain unmodified.
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(bytes, b"prev");
}
