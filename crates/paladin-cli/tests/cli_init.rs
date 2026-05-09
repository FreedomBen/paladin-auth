// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin init`. These tests exercise the
//! no-prompt error paths only — KDF flag validation, the
//! `vault_exists` pre-check without `--force`, and the precedence rule
//! that invalid KDF input wins over `vault_exists`. Happy-path
//! coverage (empty-passphrase plaintext init, encrypted init, and
//! `--force` clobber) requires a scripted `/dev/tty` and lands with
//! the dedicated PTY test harness called out in
//! `IMPLEMENTATION_PLAN_02_CLI.md`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use assert_cmd::Command;
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

/// Write a minimal plaintext vault file at `path` so `init` (without
/// `--force`) sees an existing primary. The byte layout matches the
/// §4.3 plaintext header so `inspect` classifies the file as
/// `Plaintext`. Set `0600` mode so the §4.3 perms check accepts it.
fn write_existing_plaintext_vault(path: &std::path::Path) {
    // Magic "PALADIN1" + format_ver=1 + mode=0 (plaintext) + reserved
    // bytes — see DESIGN.md §4.3 / §4.4. The body is empty bincode
    // payload bytes after the 16-byte header (here we just write the
    // 16 header bytes plus a minimal empty bincode-encoded payload).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PALADIN1");
    bytes.push(1); // format_ver
    bytes.push(0); // mode = plaintext
    bytes.extend_from_slice(&[0u8; 6]); // reserved
                                        // Empty `VaultPayload` bincoded — for inspect() we only need the
                                        // header, so trailing bytes are tolerated.
    std::fs::write(path, &bytes).expect("write existing vault");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
}

#[test]
fn json_invalid_kdf_memory_mib_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--kdf-memory-mib",
            "abc",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("kdf-memory-mib"));
    assert_eq!(value["reason"], serde_json::json!("invalid_integer"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_overflow_kdf_memory_mib_rejects_with_overflow_reason() {
    let (_dir, path) = fresh_vault_path();
    // u32::MAX / 1024 == 4_194_303, so 4_194_304 overflows on `* 1024`.
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--kdf-memory-mib",
            "4194304",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("kdf-memory-mib"));
    assert_eq!(value["reason"], serde_json::json!("overflow"));
}

#[test]
fn json_kdf_time_below_floor_rejects_with_kdf_params_out_of_bounds() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--kdf-time",
            "0",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        value["error_kind"],
        serde_json::json!("kdf_params_out_of_bounds")
    );
    assert_eq!(value["t"], serde_json::json!(0));
}

#[test]
fn json_existing_vault_without_force_rejects_with_vault_exists() {
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "init"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_exists"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_kdf_validation_wins_over_vault_exists_precedence() {
    // Existing vault + invalid KDF integer: the KDF parse fires first,
    // before `inspect` runs the existence pre-check, so the user sees
    // `validation_error` rather than `vault_exists`. Locked by the
    // §5 ordering rule in IMPLEMENTATION_PLAN_02_CLI.md.
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--kdf-time",
            "nope",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("kdf-time"));
    assert_eq!(value["reason"], serde_json::json!("invalid_integer"));
}

#[test]
fn json_kdf_validation_wins_over_vault_exists_with_force() {
    // Same precedence rule applies even with `--force`: the KDF parser
    // fires before the pre-check, so the user sees the validation
    // error rather than the warning + clobber path.
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--force",
            "--kdf-parallelism",
            "999",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        value["error_kind"],
        serde_json::json!("kdf_params_out_of_bounds")
    );
    assert_eq!(value["p"], serde_json::json!(999));
}

#[test]
fn text_existing_vault_without_force_emits_paladin_vault_exists_message() {
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "init"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.starts_with("paladin: "),
        "expected paladin: prefix, got {stderr:?}"
    );
    assert!(
        stderr.to_lowercase().contains("vault"),
        "expected vault_exists wording, got {stderr:?}"
    );
}
