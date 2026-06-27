// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin-auth settings get|set`. Exercises every §5
//! dotted key against a plaintext vault — encrypted-vault coverage
//! requires a scripted `/dev/tty` and lands with the PTY harness called
//! out in `docs/IMPLEMENTATION_PLAN_02_CLI.md`.
//!
//! Invariants under test:
//! * `get` defaults — fresh vault returns the §5 default values.
//! * `get` text-mode filtering — `<dotted-key>=<value>` for one key,
//!   full table when no key is given.
//! * `get`/`set` JSON shape — always the full nested `VaultSettings`
//!   object; dotted keys never appear on the wire.
//! * `set` round-trips through both `bool` keys and both `u32` keys at
//!   the inclusive minimum and maximum bounds.
//! * Unknown dotted keys reject with `validation_error`/`field: "key"`/
//!   `reason: "unknown_setting_key"` for both `get <key>` and `set
//!   <key> <value>` — before any vault open under both text and JSON.
//! * Malformed values reject with the dotted-key field and the
//!   per-grammar reason (`expected_bool`, `expected_u32`,
//!   `out_of_range`).
//! * `set` persists the post-mutation value: a follow-up `get` against
//!   the same vault returns the new value.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use paladin_auth_core::{Store, VaultInit};
use serde_json::Value;
use tempfile::TempDir;

fn paladin_auth() -> Command {
    let mut cmd = Command::cargo_bin("paladin-auth").expect("cargo bin");
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

fn create_empty_plaintext_vault(path: &Path) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    vault.save(&store).expect("save");
}

fn defaults_value() -> Value {
    serde_json::json!({
        "auto_lock":  { "enabled": false, "timeout_secs": 300 },
        "clipboard":  { "clear_enabled": false, "clear_secs": 20 },
    })
}

#[test]
fn json_get_returns_full_nested_defaults_for_fresh_vault() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "get",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value, defaults_value());
    assert!(assert.get_output().stderr.is_empty());
}

#[test]
fn json_get_with_dotted_key_still_returns_full_settings_object() {
    // §5: dotted key names never appear on the JSON wire — even when
    // the caller filters with a key, JSON `get` must return the full
    // nested object so consumers can use one parse path.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "get",
            "auto_lock.timeout_secs",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value, defaults_value());
}

#[test]
fn text_get_lists_every_dotted_key_for_fresh_vault() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args(["--vault", path.to_str().unwrap(), "settings", "get"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert_eq!(
        stdout,
        "auto_lock.enabled=false\n\
         auto_lock.timeout_secs=300\n\
         clipboard.clear_enabled=false\n\
         clipboard.clear_secs=20\n",
    );
}

#[test]
fn text_get_filters_to_a_single_dotted_key_when_supplied() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "get",
            "clipboard.clear_secs",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert_eq!(stdout, "clipboard.clear_secs=20\n");
}

#[test]
fn json_set_bool_key_returns_post_mutation_full_settings_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "set",
            "auto_lock.enabled",
            "true",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["auto_lock"]["enabled"], serde_json::json!(true));
    // Other fields keep their defaults.
    assert_eq!(value["auto_lock"]["timeout_secs"], serde_json::json!(300));
    assert_eq!(
        value["clipboard"]["clear_enabled"],
        serde_json::json!(false)
    );
    assert_eq!(value["clipboard"]["clear_secs"], serde_json::json!(20));
}

#[test]
fn json_set_persists_through_a_follow_up_get_against_the_same_vault() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "set",
            "clipboard.clear_secs",
            "45",
        ])
        .assert()
        .success();

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "get",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["clipboard"]["clear_secs"], serde_json::json!(45));
}

#[test]
fn json_set_accepts_inrange_minimum_and_maximum_for_each_secs_key() {
    // auto_lock.timeout_secs: 30..=86_400; clipboard.clear_secs: 5..=600.
    for (key, vals) in [
        ("auto_lock.timeout_secs", ["30", "86400"]),
        ("clipboard.clear_secs", ["5", "600"]),
    ] {
        for val in vals {
            let (_dir, path) = fresh_vault_path();
            create_empty_plaintext_vault(&path);
            let assert = paladin_auth()
                .args([
                    "--json",
                    "--vault",
                    path.to_str().unwrap(),
                    "settings",
                    "set",
                    key,
                    val,
                ])
                .assert()
                .success();
            let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
            let value: Value = serde_json::from_str(stdout.trim()).unwrap();
            // Pick the right nested field depending on the key.
            let observed = match key {
                "auto_lock.timeout_secs" => &value["auto_lock"]["timeout_secs"],
                "clipboard.clear_secs" => &value["clipboard"]["clear_secs"],
                _ => unreachable!(),
            };
            let expected: u32 = val.parse().unwrap();
            assert_eq!(observed, &serde_json::json!(expected), "{key} = {val}");
        }
    }
}

#[test]
fn text_set_renders_full_post_mutation_settings_table() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "set",
            "clipboard.clear_enabled",
            "true",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert_eq!(
        stdout,
        "auto_lock.enabled=false\n\
         auto_lock.timeout_secs=300\n\
         clipboard.clear_enabled=true\n\
         clipboard.clear_secs=20\n",
    );
}

#[test]
fn json_set_unknown_dotted_key_rejects_with_validation_error_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "set",
            "auto_lock.unknown",
            "true",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("key"));
    assert_eq!(value["reason"], serde_json::json!("unknown_setting_key"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_get_unknown_dotted_key_rejects_with_validation_error_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "get",
            "auto_lock.bogus",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("key"));
    assert_eq!(value["reason"], serde_json::json!("unknown_setting_key"));
}

#[test]
fn unknown_get_key_rejects_before_vault_open_when_no_vault_exists() {
    // Plan rule: unknown-dotted-key validation runs before any vault
    // open. With no vault on disk, an unknown key still surfaces
    // `validation_error` (not `vault_missing`).
    let (_dir, path) = fresh_vault_path();
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "get",
            "auto_lock.bogus",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("key"));
}

#[test]
fn unknown_set_key_rejects_before_vault_open_when_no_vault_exists() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "set",
            "auto_lock.bogus",
            "true",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("key"));
}

#[test]
fn json_set_bool_value_must_be_lowercase_true_or_false() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    for bad in ["True", "TRUE", "yes", "1", "t", " true"] {
        let assert = paladin_auth()
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "settings",
                "set",
                "auto_lock.enabled",
                bad,
            ])
            .assert()
            .failure();
        let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
        let value: Value = serde_json::from_str(stderr.trim()).unwrap();
        assert_eq!(
            value["error_kind"],
            serde_json::json!("validation_error"),
            "value = {bad:?}",
        );
        assert_eq!(value["field"], serde_json::json!("auto_lock.enabled"));
        assert_eq!(value["reason"], serde_json::json!("expected_bool"));
    }
}

#[test]
fn json_set_u32_value_must_be_base_10_digits_only() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    // `--` separates leading-dash and empty-string positionals from
    // clap's flag parser so the §5 grammar (and not clap) is what
    // rejects them.
    for bad in [
        "", "60s", "+60", "-60", "60.0", "abc", "1_000", "0x3c", "60 ",
    ] {
        let assert = paladin_auth()
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "settings",
                "set",
                "auto_lock.timeout_secs",
                "--",
                bad,
            ])
            .assert()
            .failure();
        let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
        let value: Value = serde_json::from_str(stderr.trim()).unwrap();
        assert_eq!(
            value["error_kind"],
            serde_json::json!("validation_error"),
            "value = {bad:?}",
        );
        assert_eq!(
            value["field"],
            serde_json::json!("auto_lock.timeout_secs"),
            "value = {bad:?}",
        );
        assert_eq!(value["reason"], serde_json::json!("expected_u32"));
    }
}

#[test]
fn json_set_u32_below_minimum_rejects_with_out_of_range() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    // auto_lock.timeout_secs minimum is 30.
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "set",
            "auto_lock.timeout_secs",
            "29",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("auto_lock.timeout_secs"));
    assert_eq!(value["reason"], serde_json::json!("out_of_range"));
}

#[test]
fn json_set_u32_above_maximum_rejects_with_out_of_range() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    // clipboard.clear_secs maximum is 600.
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "set",
            "clipboard.clear_secs",
            "601",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("clipboard.clear_secs"));
    assert_eq!(value["reason"], serde_json::json!("out_of_range"));
}

#[test]
fn json_get_missing_vault_rejects_after_key_validation() {
    // With a *valid* dotted key but no vault on disk, the open
    // pipeline surfaces `vault_missing` — confirming key validation
    // does not short-circuit when the key parses cleanly.
    let (_dir, path) = fresh_vault_path();
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "settings",
            "get",
            "auto_lock.enabled",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
}

#[test]
fn json_get_succeeds_for_each_dotted_key_against_default_vault() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    for key in [
        "auto_lock.enabled",
        "auto_lock.timeout_secs",
        "clipboard.clear_enabled",
        "clipboard.clear_secs",
    ] {
        let assert = paladin_auth()
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "settings",
                "get",
                key,
            ])
            .assert()
            .success();
        let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
        let value: Value = serde_json::from_str(stdout.trim()).unwrap();
        // §5 JSON: full nested envelope regardless of which key was
        // passed; never the dotted key as a top-level field.
        assert_eq!(value, defaults_value(), "key = {key}");
    }
}
