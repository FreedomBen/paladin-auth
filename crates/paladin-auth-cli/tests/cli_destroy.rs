// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-level tests for `paladin-auth destroy [--yes]` (Milestone 10).
//!
//! Each test creates a fresh temp dir, `--vault`s a path inside it,
//! writes the on-disk state directly with `std::fs::write` (destroy
//! never opens / inspects / enforces perms, so a raw byte blob is a
//! valid fixture and sidesteps the sandbox's 0770 tempdir default that
//! `Store::create`'s perms gate would trip on), invokes `paladin-auth
//! destroy`, and asserts stdout / stderr / exit code plus the
//! post-condition on disk (primary present / absent, `.bak` present /
//! absent).
//!
//! Deferred `[PTY]` items (await the PTY harness that does not yet
//! exist in `tests/common`):
//!   * plaintext-vault prompt then accept `yes` then `Deleted vault.`
//!   * encrypted-vault prompt accepts `yes` without calling the KDF
//!   * sibling `.bak` present then both unlinked (interactive path)
//!   * no `.bak` then `Deleted vault (backup remained on disk).`
//!     (interactive)
//!   * `destroy --yes` text mode: warning still printed to stderr (PTY
//!     variant; a non-PTY `--yes` stdout/stderr split is covered below)
//!   * confirmation decline (non-`yes`) then a `validation_error`
//!     (`reason: "declined"`) with no unlink
//!   * no `/dev/tty` then an `io_error` (`confirmation_prompt`)
//!
//! The non-PTY items below cover everything else in the §"`destroy`"
//! test plan.

mod common;

use std::path::Path;

use common::{fresh_vault_path, paladin_auth};
use serde_json::Value;

/// Minimal non-empty byte blob standing in for a vault file. Destroy
/// unlinks by path and never parses the contents, so the bytes are
/// arbitrary.
const VAULT_BYTES: &[u8] = b"not-a-real-vault";

fn write_vault(path: &Path) {
    std::fs::write(path, VAULT_BYTES).expect("write vault fixture");
}

fn bak_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().expect("file name").to_os_string();
    name.push(".bak");
    path.with_file_name(name)
}

#[test]
fn json_yes_succeeds_and_emits_destroyed_envelope_without_backup() {
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let destroyed = &value["destroyed"];
    assert_eq!(
        destroyed["vault_path"],
        serde_json::json!(path.to_str().unwrap())
    );
    assert_eq!(destroyed["primary_deleted"], serde_json::json!(true));
    // No `.bak` was present, so the report records it was not deleted.
    assert_eq!(destroyed["backup_deleted"], serde_json::json!(false));
    // Strict mode: nothing on stderr.
    assert!(assert.get_output().stderr.is_empty());
    assert!(!path.exists(), "primary should be unlinked");
}

#[test]
fn json_yes_with_backup_reports_backup_deleted_true() {
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);
    let bak = bak_path(&path);
    std::fs::write(&bak, VAULT_BYTES).expect("write bak fixture");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        value["destroyed"]["backup_deleted"],
        serde_json::json!(true)
    );
    assert!(!path.exists(), "primary should be unlinked");
    assert!(!bak.exists(), "backup should be unlinked");
}

#[test]
fn json_without_yes_rejects_at_parse_time_with_confirmation_required() {
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);

    let assert = paladin_auth()
        .args(["--json", "--vault", path.to_str().unwrap(), "destroy"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(value["reason"], serde_json::json!("confirmation_required"));
    assert!(assert.get_output().stdout.is_empty());
    // Parse-time rejection fires before any I/O.
    assert!(
        path.exists(),
        "vault must be untouched on a parse-time reject"
    );
}

#[test]
fn json_rejects_kdf_flags_at_parse_time_before_vault_missing() {
    // KDF rejection wins precedence over vault_missing: the vault does
    // not exist here, yet the kdf_flags_not_supported rejection fires
    // first because it is a parse-time check.
    let (_dir, path) = fresh_vault_path();

    for flag in ["--kdf-memory-mib", "--kdf-time", "--kdf-parallelism"] {
        let assert = paladin_auth()
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "destroy",
                "--yes",
                flag,
                "8",
            ])
            .assert()
            .failure();
        let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
        let value: Value = serde_json::from_str(stderr.trim()).unwrap();
        assert_eq!(
            value["error_kind"],
            serde_json::json!("validation_error"),
            "flag {flag}"
        );
        assert_eq!(value["field"], serde_json::json!("argv"), "flag {flag}");
        assert_eq!(
            value["reason"],
            serde_json::json!("kdf_flags_not_supported"),
            "flag {flag}"
        );
    }
}

#[test]
fn json_missing_vault_rejects_with_vault_missing_and_path_no_bak_touched() {
    let (_dir, path) = fresh_vault_path();
    // Leave a `.bak` in place to prove destroy never touches it when
    // the primary is absent (idempotency / no-op contract).
    let bak = bak_path(&path);
    std::fs::write(&bak, VAULT_BYTES).expect("write bak fixture");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    assert_eq!(value["path"], serde_json::json!(path.to_str().unwrap()));
    assert!(assert.get_output().stdout.is_empty());
    assert!(
        bak.exists(),
        "the sibling .bak must survive a missing-primary destroy"
    );
}

#[test]
fn json_idempotent_first_succeeds_second_is_vault_missing() {
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);

    // First call succeeds.
    paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .success();
    assert!(!path.exists());

    // Second call is a no-op that reports vault_missing.
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
}

#[test]
fn json_symlinked_primary_rejects_with_vault_file_is_symlink() {
    let (_dir, path) = fresh_vault_path();
    // Target the symlink points at; destroy must not follow it.
    let target = path.with_file_name("real-target.bin");
    std::fs::write(&target, VAULT_BYTES).expect("write symlink target");
    std::os::unix::fs::symlink(&target, &path).expect("create symlink primary");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("io_error"));
    assert_eq!(
        value["operation"],
        serde_json::json!("vault_file_is_symlink")
    );
    assert_eq!(value["path"], serde_json::json!(path.to_str().unwrap()));
    // The symlink target survives byte-identical.
    assert_eq!(std::fs::read(&target).unwrap(), VAULT_BYTES);
}

#[test]
fn json_symlinked_backup_rejects_with_backup_file_is_symlink() {
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);
    let bak = bak_path(&path);
    let target = path.with_file_name("real-bak-target.bin");
    std::fs::write(&target, VAULT_BYTES).expect("write bak symlink target");
    std::os::unix::fs::symlink(&target, &bak).expect("create symlink bak");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("io_error"));
    assert_eq!(
        value["operation"],
        serde_json::json!("backup_file_is_symlink")
    );
    // The symlink probe fires before any unlink: the primary survives.
    assert!(
        path.exists(),
        "primary must survive a backup-symlink rejection"
    );
}

#[test]
fn json_destroy_succeeds_on_perms_drifted_vault() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);
    // Drift the primary to a world-readable mode that the open-path
    // perms gate would reject; destroy ignores the perms gate.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 0644");

    paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .success();
    assert!(
        !path.exists(),
        "perms-drifted vault must still be deletable"
    );
}

#[test]
fn json_destroy_succeeds_on_corrupted_header_vault() {
    let (_dir, path) = fresh_vault_path();
    // A garbage header `inspect` would reject; destroy never inspects.
    std::fs::write(&path, b"\x00\x01\x02\x03 corrupted header bytes").expect("write corrupted");

    paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .success();
    assert!(!path.exists(), "corrupted vault must still be deletable");
}

#[test]
fn json_partial_failure_unlink_backup_file_carries_state_fields() {
    // Make the `.bak` a *directory*: it is not a symlink (probe passes,
    // backup_present = true), the primary unlink succeeds, then
    // `remove_file` on the directory fails → DestroyIoError
    // (unlink_backup_file) with primary_deleted=true, backup_deleted=false.
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);
    let bak = bak_path(&path);
    std::fs::create_dir(&bak).expect("create .bak directory");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "destroy",
            "--yes",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("io_error"));
    assert_eq!(value["operation"], serde_json::json!("unlink_backup_file"));
    assert_eq!(value["primary_deleted"], serde_json::json!(true));
    assert_eq!(value["backup_deleted"], serde_json::json!(false));
    assert_eq!(value["path"], serde_json::json!(path.to_str().unwrap()));
    // The primary really was removed before the backup unlink failed.
    assert!(!path.exists(), "primary should be gone on partial failure");
    assert!(bak.exists(), "the .bak directory remains on disk");
    // Clean up the directory so TempDir teardown succeeds.
    std::fs::remove_dir(&bak).ok();
}

#[test]
fn text_yes_with_backup_prints_deleted_vault_and_warning_to_stderr() {
    // A `.bak` present and deleted yields the plain `Deleted vault.`
    // success line (the `backup_deleted == true` branch).
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);
    let bak = bak_path(&path);
    std::fs::write(&bak, VAULT_BYTES).expect("write bak fixture");

    let assert = paladin_auth()
        .args(["--vault", path.to_str().unwrap(), "destroy", "--yes"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert_eq!(stdout, "Deleted vault.\n");
    // The destructive warning rides on stderr even under `--yes`.
    assert!(
        stderr.contains("This will permanently delete the vault"),
        "warning should print to stderr; got {stderr:?}"
    );
    assert!(!path.exists());
    assert!(!bak.exists());
}

#[test]
fn text_yes_no_backup_branch_reports_backup_remained() {
    // With no `.bak` on disk the report sets `backup_deleted == false`,
    // so the CLI prints the "(backup remained on disk)" branch. The
    // plan's PTY bullet labels this as the `backup_deleted: false`
    // helper-text branch.
    let (_dir, path) = fresh_vault_path();
    write_vault(&path);

    let assert = paladin_auth()
        .args(["--vault", path.to_str().unwrap(), "destroy", "--yes"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert_eq!(stdout, "Deleted vault (backup remained on disk).\n");
}
