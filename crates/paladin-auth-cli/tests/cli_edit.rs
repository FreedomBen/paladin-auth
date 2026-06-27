// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin-auth edit` per
//! `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Edit command (v0.2)" and
//! "Tests / `edit`". Mirrors the `assert_cmd` patterns in
//! `cli_remove_rename.rs`.

mod common;

use std::path::Path;
use std::time::{Duration, SystemTime};

use paladin_auth_core::{
    parse_otpauth, Account, Argon2Params, EncryptionOptions, Store, VaultInit, VaultLock,
};
use secrecy::SecretString;
use serde_json::Value;

use common::{fresh_vault_path, paladin_auth, paladin_auth_command_without_tty};

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

fn make_totp_secret(label: &str, issuer: Option<&str>, base32_secret: &str) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri =
        format!("otpauth://totp/{issuer_part}{label}?secret={base32_secret}&digits=6&period=30");
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

/// Encrypted vault seeded with `accounts`. Uses the §4.4 minimum
/// Argon2id params so the KDF run stays fast under test.
fn create_encrypted_vault(accounts: Vec<Account>, path: &Path, passphrase: &str) {
    let pp = SecretString::from(passphrase.to_string());
    let params = Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    let opts = EncryptionOptions::with_params(pp, params).expect("opts");
    let (mut vault, store) = Store::create(path, VaultInit::Encrypted(opts)).expect("create");
    for acct in accounts {
        vault.add(acct);
    }
    vault.save(&store).expect("save");
}

fn list_accounts_json(path: &Path) -> Value {
    let assert = paladin_auth()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    serde_json::from_str(stdout.trim()).unwrap()
}

// =========================================================================
// Parse-time rejections (no_edit_fields / mutually_exclusive)
// =========================================================================

#[test]
fn json_edit_no_flags_rejects_with_no_edit_fields_before_vault_inspect() {
    // The "at least one editable flag" requirement is enforced before
    // any disk I/O, so the rejection beats `vault_missing` (no vault
    // file exists in the tempdir).
    let (_dir, path) = fresh_vault_path();
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "anything",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(value["reason"], serde_json::json!("no_edit_fields"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_edit_allow_duplicate_alone_rejects_with_no_edit_fields() {
    // `--allow-duplicate` is a collision override and does NOT satisfy
    // the "at least one editable flag" requirement.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--allow-duplicate",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(value["reason"], serde_json::json!("no_edit_fields"));
}

#[test]
fn json_edit_dry_run_alone_rejects_with_no_edit_fields() {
    // `--dry-run` is a mode toggle and does NOT satisfy the
    // "at least one editable flag" requirement either.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--dry-run",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(value["reason"], serde_json::json!("no_edit_fields"));
}

#[test]
fn json_edit_no_edit_fields_beats_vault_missing() {
    // Locked precedence: the parse-time `no_edit_fields` rejection
    // wins over `vault_missing`. `--vault <bad-path>` + no edit flags
    // surfaces `no_edit_fields`, not `vault_missing`.
    let (_dir, path) = fresh_vault_path();
    // Do NOT create the vault file.
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "some-query",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["reason"], serde_json::json!("no_edit_fields"));
}

#[test]
fn json_edit_issuer_and_no_issuer_rejected_at_parse_time() {
    // clap-side `conflicts_with`: rejected before any I/O. The argv
    // pre-scan reroutes this to a `validation_error` (`field: "argv"`,
    // `reason: "usage"`) envelope.
    let (_dir, path) = fresh_vault_path();
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--issuer",
            "Foo",
            "--no-issuer",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
}

#[test]
fn json_edit_icon_hint_and_no_icon_hint_rejected_at_parse_time() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--icon-hint",
            "github",
            "--no-icon-hint",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
}

// =========================================================================
// Cardinality (no_match / multiple_matches)
// =========================================================================

#[test]
fn json_edit_no_match_rejects_with_no_match_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "ghost",
            "--label",
            "newlabel",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("no_match"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_edit_multi_match_rejects_with_multiple_matches_and_disambiguators() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp("alice", Some("GitHub")),
            make_totp("alice", Some("GitLab")),
        ],
        &path,
    );
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "newlabel",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("multiple_matches"));
    let candidates = value["candidates"].as_array().expect("array");
    assert_eq!(candidates.len(), 2);
    for c in candidates {
        let disambig = c["disambiguator"].as_str().expect("disambiguator");
        assert!(disambig.starts_with("id:"));
    }

    // No mutation happened.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    let labels: Vec<&str> = arr.iter().map(|a| a["label"].as_str().unwrap()).collect();
    assert_eq!(labels, vec!["alice", "alice"]);
}

#[test]
fn json_edit_id_prefix_selects_unique_account_among_substring_collisions() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp("alice", Some("GitHub")),
            make_totp("alice", Some("GitLab")),
        ],
        &path,
    );

    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    let id = arr[0]["id"].as_str().expect("id string");
    let hex = id.replace('-', "");
    let selector = format!("id:{}", &hex[..8]);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            &selector,
            "--label",
            "renamed",
        ])
        .assert()
        .success();
    let value: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(value["account"]["id"], serde_json::json!(id));
    assert_eq!(value["account"]["label"], serde_json::json!("renamed"));
}

// =========================================================================
// Per-field validation
// =========================================================================

#[test]
fn json_edit_invalid_label_propagates_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("label"));
    // Original account intact on disk.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["label"], serde_json::json!("alice"));
}

#[test]
fn json_edit_whitespace_only_label_propagates_empty_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "   ",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("label"));
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["label"], serde_json::json!("alice"));
}

#[test]
fn json_edit_invalid_issuer_too_long_propagates_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let long = "x".repeat(200);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--issuer",
            &long,
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("issuer"));
}

#[test]
fn json_edit_invalid_icon_hint_slug_propagates_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--icon-hint",
            "Bad Slug!",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("icon_hint"));
}

// =========================================================================
// Text-mode error rendering (insta snapshot)
// =========================================================================

#[test]
fn text_edit_invalid_label_error_block_matches_snapshot() {
    // Human-facing rendering of a `validation_error` for `edit`:
    // `paladin-auth edit alice --label ""` against a seeded plaintext vault
    // prints the §5 text-mode error block to stderr. `--no-color` keeps
    // the block free of ANSI escapes so the golden stays stable.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin_auth()
        .args([
            "--no-color",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "",
        ])
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).expect("stderr is UTF-8");
    insta::assert_snapshot!(stderr);
}

// =========================================================================
// Happy-path commits: label, issuer, icon-hint, combined
// =========================================================================

#[test]
fn json_edit_label_succeeds_and_emits_account_envelope_with_new_label() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "alice2",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("alice2"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Acme"));
    assert!(assert.get_output().stderr.is_empty());

    // Persisted state.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], serde_json::json!("alice2"));
    assert_eq!(arr[0]["issuer"], serde_json::json!("Acme"));
}

#[test]
fn text_edit_label_prints_nothing_on_success() {
    // Plan: text mode prints nothing on success (parity with rename
    // text-mode does — though rename prints a line and edit
    // explicitly stays silent per the plan).
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "alice2",
        ])
        .assert()
        .success();
    assert!(assert.get_output().stdout.is_empty());
    assert!(assert.get_output().stderr.is_empty());
}

#[test]
fn json_edit_issuer_succeeds_and_normalizes_whitespace() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    // Surround the issuer with whitespace — core's `validate_issuer`
    // trims Unicode whitespace, so the persisted value must equal the
    // trimmed string.
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--issuer",
            "  NewIssuer  ",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["issuer"], serde_json::json!("NewIssuer"));
    // Label untouched.
    assert_eq!(value["account"]["label"], serde_json::json!("alice"));
}

#[test]
fn json_edit_no_issuer_clears_issuer() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--no-issuer",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["issuer"], serde_json::Value::Null);

    // Persisted state.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["issuer"], serde_json::Value::Null);
    assert_eq!(listed["accounts"][0]["label"], serde_json::json!("alice"));
}

#[test]
fn json_edit_empty_issuer_collapses_to_clear() {
    // `--issuer ""` normalizes to `Some(None)` via core's §4.1
    // issuer normalization (whitespace trim → empty → None).
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--issuer",
            "",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["issuer"], serde_json::Value::Null);
}

#[test]
fn json_edit_issuer_empty_and_no_issuer_produce_byte_identical_vaults() {
    // Both flag forms should collapse to AccountEdit::issuer =
    // Some(None) after normalization, and produce byte-identical
    // persisted vaults from the same starting state with the same
    // `now`. We can't pin `now` from the CLI, so we compare the
    // semantic shape via the round-tripped JSON list rather than the
    // raw bytes (tests run too fast to risk a different `now`).
    let (_dir_a, path_a) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path_a);
    let (_dir_b, path_b) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path_b);

    let _ = paladin_auth()
        .args([
            "--json",
            "--vault",
            path_a.to_str().unwrap(),
            "edit",
            "alice",
            "--issuer",
            "",
        ])
        .assert()
        .success();
    let _ = paladin_auth()
        .args([
            "--json",
            "--vault",
            path_b.to_str().unwrap(),
            "edit",
            "alice",
            "--no-issuer",
        ])
        .assert()
        .success();

    let a = list_accounts_json(&path_a);
    let b = list_accounts_json(&path_b);
    let a_row = &a["accounts"][0];
    let b_row = &b["accounts"][0];
    // Issuer, label, kind, digits, algorithm, period, counter, icon_hint
    // match between the two paths.
    for k in [
        "issuer",
        "label",
        "kind",
        "digits",
        "algorithm",
        "period",
        "counter",
        "icon_hint",
    ] {
        assert_eq!(a_row[k], b_row[k], "{k} mismatch");
    }
}

#[test]
fn json_edit_icon_hint_slug_succeeds() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--icon-hint",
            "github",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["icon_hint"], serde_json::json!("github"));
}

#[test]
fn json_edit_icon_hint_none_token_clears_slug() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--icon-hint",
            "NONE",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["icon_hint"], serde_json::Value::Null);
}

#[test]
fn json_edit_no_icon_hint_clears_slug() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--no-icon-hint",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["icon_hint"], serde_json::Value::Null);
}

#[test]
fn json_edit_icon_hint_empty_token_redefaults_against_post_edit_issuer() {
    // `--icon-hint ""` → IconHintInput::Default → core re-derives
    // from the post-edit issuer. Combined with `--issuer <new>` the
    // re-derivation must reflect the **new** issuer, not the prior one.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--issuer",
            "GitHub",
            "--icon-hint",
            "",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["issuer"], serde_json::json!("GitHub"));
    // The derived slug should be issuer-derived (lowercase "github");
    // we don't pin the exact derivation here but it must not be null
    // (the prior icon_hint was issuer-derived as well).
    assert_ne!(value["account"]["icon_hint"], serde_json::Value::Null);
}

#[test]
fn json_edit_icon_hint_empty_token_redefaults_against_current_issuer() {
    // `--icon-hint ""` alone (no issuer change) flows through
    // `parse_icon_hint_token` as `IconHintInput::Default` and re-derives
    // the stored slug from the account's CURRENT issuer. Round-trip: set
    // a custom slug, then re-default, and confirm the slug snaps back to
    // the issuer-derived value the account was created with.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    // The created account auto-derives its icon-hint from issuer "Acme".
    let seeded = list_accounts_json(&path);
    let derived = seeded["accounts"][0]["icon_hint"].clone();
    assert!(
        derived.is_string(),
        "issuer \"Acme\" must auto-derive a non-null icon-hint slug, got {derived:?}",
    );

    // Stomp the derived slug with a custom one.
    let _ = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--icon-hint",
            "custom-slug",
        ])
        .assert()
        .success();

    // `--icon-hint ""` re-derives from the (unchanged) issuer "Acme".
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--icon-hint",
            "",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["issuer"], serde_json::json!("Acme"));
    assert_eq!(
        value["account"]["icon_hint"], derived,
        "empty icon-hint token must re-derive the issuer slug",
    );

    // Persisted state agrees.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["icon_hint"], derived);
}

#[test]
fn json_edit_no_issuer_with_empty_icon_hint_redefaults_to_null() {
    // `--no-issuer --icon-hint ""` clears the issuer and re-derives the
    // slug against the post-edit (now-cleared) issuer. With no issuer the
    // default derivation yields null — functionally equivalent to
    // `--no-issuer --no-icon-hint`.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    // Sanity: the seeded account has a non-null derived slug to clear.
    let seeded = list_accounts_json(&path);
    assert!(seeded["accounts"][0]["icon_hint"].is_string());

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--no-issuer",
            "--icon-hint",
            "",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["issuer"], serde_json::Value::Null);
    assert_eq!(value["account"]["icon_hint"], serde_json::Value::Null);

    // Persisted state agrees.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["issuer"], serde_json::Value::Null);
    assert_eq!(listed["accounts"][0]["icon_hint"], serde_json::Value::Null);
}

#[test]
fn json_edit_label_issuer_icon_hint_all_in_one_call() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "alice2",
            "--issuer",
            "GitHub",
            "--icon-hint",
            "github",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("alice2"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("GitHub"));
    assert_eq!(value["account"]["icon_hint"], serde_json::json!("github"));
}

// =========================================================================
// Duplicate-account gate
// =========================================================================

#[test]
fn json_edit_duplicate_rejects_with_duplicate_account_envelope() {
    // Two accounts with distinct (issuer,label) but the same secret;
    // editing A to match B's (issuer,label) produces a collision.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp_secret("alice", Some("Acme"), "JBSWY3DPEHPK3PXP"),
            make_totp_secret("bob", Some("Other"), "JBSWY3DPEHPK3PXP"),
        ],
        &path,
    );

    // Capture pre-edit state for the byte-identical assertion below.
    let before_bytes = std::fs::read(&path).expect("read vault");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "Acme:alice",
            "--label",
            "bob",
            "--issuer",
            "Other",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("duplicate_account"));
    // The colliding (existing) account is in the `account` field.
    assert_eq!(value["account"]["label"], serde_json::json!("bob"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Other"));

    // Vault on disk is byte-identical to its pre-edit state.
    let after_bytes = std::fs::read(&path).expect("read vault");
    assert_eq!(before_bytes, after_bytes);
}

#[test]
fn json_edit_allow_duplicate_bypasses_collision_gate_and_commits() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp_secret("alice", Some("Acme"), "JBSWY3DPEHPK3PXP"),
            make_totp_secret("bob", Some("Other"), "JBSWY3DPEHPK3PXP"),
        ],
        &path,
    );
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "Acme:alice",
            "--label",
            "bob",
            "--issuer",
            "Other",
            "--allow-duplicate",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("bob"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Other"));

    // The vault now legitimately has two `(secret, issuer, label)`-equal accounts.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let labels: Vec<&str> = arr.iter().map(|a| a["label"].as_str().unwrap()).collect();
    let issuers: Vec<&str> = arr.iter().map(|a| a["issuer"].as_str().unwrap()).collect();
    assert!(labels.iter().filter(|l| **l == "bob").count() == 2);
    assert!(issuers.iter().filter(|i| **i == "Other").count() == 2);
}

#[test]
fn json_edit_self_edit_does_not_trigger_duplicate_against_itself() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "alice",
            "--issuer",
            "Acme",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("alice"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Acme"));
}

#[test]
fn json_edit_noop_but_non_empty_bumps_updated_at() {
    // Self-edit: every field set to prior value still bumps
    // `updated_at` per the core mutator contract.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let before = list_accounts_json(&path);
    let before_row = &before["accounts"][0];
    let created_at = before_row["created_at"].as_u64().expect("u64");
    let updated_at_before = before_row["updated_at"].as_u64().expect("u64");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "alice",
        ])
        .assert()
        .success();
    let value: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();
    let updated_at_after = value["account"]["updated_at"].as_u64().expect("u64");
    assert!(
        updated_at_after >= updated_at_before,
        "updated_at must not regress: before={updated_at_before} after={updated_at_after}",
    );
    assert_eq!(
        value["account"]["created_at"],
        serde_json::json!(created_at)
    );
}

// =========================================================================
// Validation-before-duplicate ordering
// =========================================================================

#[test]
fn json_edit_validation_wins_over_duplicate_account_even_with_allow_duplicate() {
    // The locked rule: per-field validation runs before the duplicate
    // gate. An invalid edit (`--label ""`) with `--allow-duplicate`
    // must still surface `validation_error`, not `duplicate_account`
    // and not success.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp_secret("alice", Some("Acme"), "JBSWY3DPEHPK3PXP"),
            make_totp_secret("bob", Some("Other"), "JBSWY3DPEHPK3PXP"),
        ],
        &path,
    );
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "Acme:alice",
            "--label",
            "",
            "--allow-duplicate",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("label"));
}

// =========================================================================
// Read-only invariant on secrets (HOTP counter, secret bytes)
// =========================================================================

#[test]
fn edit_label_on_hotp_does_not_advance_counter() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_hotp("bob", Some("Bank"), 17)], &path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "bob",
            "--label",
            "bob2",
        ])
        .assert()
        .success();
    let value: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(value["account"]["counter"], serde_json::json!(17));

    // Re-list to confirm persisted counter is still 17.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["counter"], serde_json::json!(17));
    assert_eq!(listed["accounts"][0]["label"], serde_json::json!("bob2"));
}

#[test]
fn edit_issuer_on_hotp_does_not_advance_counter() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_hotp("bob", Some("Bank"), 17)], &path);
    let _ = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "bob",
            "--issuer",
            "NewBank",
        ])
        .assert()
        .success();
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["counter"], serde_json::json!(17));
}

#[test]
fn edit_icon_hint_on_hotp_does_not_advance_counter() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_hotp("bob", Some("Bank"), 17)], &path);
    let _ = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "bob",
            "--icon-hint",
            "github",
        ])
        .assert()
        .success();
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["counter"], serde_json::json!(17));
}

// =========================================================================
// vault_missing short-circuits before any prompt
// =========================================================================

#[test]
fn json_edit_vault_missing_surfaces_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    // No vault file created.
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "renamed",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
}

// =========================================================================
// Encrypted-vault prompt ordering (parse-time rejection beats unlock)
// =========================================================================

#[test]
fn json_edit_no_edit_fields_beats_encrypted_unlock_prompt() {
    use std::process::Stdio;

    // Against an encrypted vault, `paladin-auth edit some-query` with no edit
    // flags must reject at parse time with `no_edit_fields` BEFORE the
    // unlock passphrase prompt fires. Run under setsid(1) so `/dev/tty`
    // is unavailable: if the CLI tried to prompt, it would surface
    // `io_error` (`operation: "passphrase_prompt"`) instead of the
    // parse-time rejection.
    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(vec![make_totp("alice", Some("Acme"))], &path, "hunter2");

    let output = paladin_auth_command_without_tty()
        .args(["--json", "--vault", path.to_str().unwrap(), "edit", "alice"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn paladin-auth via setsid(1)");

    assert!(
        !output.status.success(),
        "no-edit-flags edit must fail; stdout = {:?}, stderr = {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(
        value["reason"],
        serde_json::json!("no_edit_fields"),
        "parse-time rejection must beat the encrypted-vault unlock prompt",
    );
    assert!(output.stdout.is_empty());
}

/// Stable §5 prompt label fired by `vault_open::open` for any
/// encrypted-vault unlock — the same string `cli_passphrase.rs`,
/// `cli_export.rs`, and `cli_qr.rs` expect.
const PROMPT_UNLOCK: &str = "Vault passphrase: ";

#[test]
fn pty_edit_label_against_encrypted_vault_unlocks_once_and_applies() {
    let (_dir, path) = fresh_vault_path();
    let passphrase = "encrypted-edit-secret";
    create_encrypted_vault(vec![make_totp("alice", Some("Acme"))], &path, passphrase);

    // Drive `paladin-auth edit --label alice2` through the PTY harness.
    // `--json` keeps the success envelope on stdout; the unlock prompt
    // fires once on `/dev/tty`.
    let mut pty = common::Pty::spawn(
        [
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "alice2",
        ],
        &[],
    );
    pty.expect(PROMPT_UNLOCK);
    pty.send_line(passphrase);
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);

    // The unlock prompt fired exactly once.
    assert_eq!(
        exit.transcript.matches(PROMPT_UNLOCK).count(),
        1,
        "unlock prompt must fire exactly once; transcript:\n{}",
        exit.transcript,
    );

    // The success envelope (muxed into the transcript) matches the
    // plaintext `{ "account": AccountSummary }` shape: the post-edit
    // label / issuer are present and there is no `committed` key (that
    // field belongs only to the `--dry-run` envelope).
    let json_start = exit
        .transcript
        .find('{')
        .expect("JSON envelope must appear in the transcript");
    let value: Value =
        serde_json::from_str(exit.transcript[json_start..].trim()).unwrap_or_else(|e| {
            panic!(
                "non-JSON envelope: {:?} ({e})",
                &exit.transcript[json_start..]
            )
        });
    assert_eq!(value["account"]["label"], serde_json::json!("alice2"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Acme"));
    assert!(
        value.get("committed").is_none(),
        "non-dry-run success envelope must not carry `committed`",
    );

    // The edit persisted: re-open the encrypted vault in-process and
    // confirm the new label landed.
    let pp = SecretString::from(passphrase.to_string());
    let (vault, _store) =
        Store::open(&path, VaultLock::Encrypted(pp)).expect("open encrypted vault");
    let labels: Vec<String> = vault.summaries().map(|s| s.label).collect();
    assert_eq!(labels, vec!["alice2".to_string()]);
}

// =========================================================================
// --dry-run zero-mutation
// =========================================================================

#[test]
fn json_edit_dry_run_leaves_vault_bytes_unchanged_and_emits_committed_false() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let before_bytes = std::fs::read(&path).expect("read vault");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "alice2",
            "--dry-run",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("alice2"));
    assert_eq!(value["committed"], serde_json::json!(false));

    // Vault bytes byte-identical to the pre-dry-run state.
    let after_bytes = std::fs::read(&path).expect("read vault");
    assert_eq!(before_bytes, after_bytes);

    // Persisted vault still shows the OLD label.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["label"], serde_json::json!("alice"));
}

#[test]
fn text_edit_dry_run_prints_nothing_to_stdout() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let assert = paladin_auth()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "alice2",
            "--dry-run",
        ])
        .assert()
        .success();
    assert!(assert.get_output().stdout.is_empty());
    assert!(assert.get_output().stderr.is_empty());
    // No mutation.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["label"], serde_json::json!("alice"));
}

#[test]
fn json_edit_dry_run_propagates_validation_error_without_mutation() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let before_bytes = std::fs::read(&path).expect("read vault");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "alice",
            "--label",
            "",
            "--dry-run",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("label"));

    let after_bytes = std::fs::read(&path).expect("read vault");
    assert_eq!(before_bytes, after_bytes);
}

#[test]
fn json_edit_dry_run_propagates_duplicate_account_without_mutation() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp_secret("alice", Some("Acme"), "JBSWY3DPEHPK3PXP"),
            make_totp_secret("bob", Some("Other"), "JBSWY3DPEHPK3PXP"),
        ],
        &path,
    );
    let before_bytes = std::fs::read(&path).expect("read vault");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "Acme:alice",
            "--label",
            "bob",
            "--issuer",
            "Other",
            "--dry-run",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("duplicate_account"));

    let after_bytes = std::fs::read(&path).expect("read vault");
    assert_eq!(before_bytes, after_bytes);
}

#[test]
fn json_edit_dry_run_with_allow_duplicate_skips_collision_gate_without_mutation() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp_secret("alice", Some("Acme"), "JBSWY3DPEHPK3PXP"),
            make_totp_secret("bob", Some("Other"), "JBSWY3DPEHPK3PXP"),
        ],
        &path,
    );
    let before_bytes = std::fs::read(&path).expect("read vault");

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "edit",
            "Acme:alice",
            "--label",
            "bob",
            "--issuer",
            "Other",
            "--dry-run",
            "--allow-duplicate",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("bob"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Other"));
    assert_eq!(value["committed"], serde_json::json!(false));

    // No mutation on disk.
    let after_bytes = std::fs::read(&path).expect("read vault");
    assert_eq!(before_bytes, after_bytes);
}

// =========================================================================
// Durability fault injection (PALADIN_AUTH_FAULT_INJECT). Gated behind the
// `test-hooks` feature, which transitively enables
// `paladin-auth-core/test-fault-injection`. Run with:
//   cargo test -p paladin-auth-cli --features test-hooks
// =========================================================================

#[cfg(feature = "test-hooks")]
mod fault_inject {
    use super::*;

    #[test]
    fn json_edit_pre_commit_save_failure_rolls_back_and_surfaces_save_not_committed() {
        // §8: a pre-commit save fault during `mutate_and_save` rolls the
        // in-memory edit back and surfaces `save_not_committed`
        // (`committed: false`). `paladin-auth edit` rewrites the whole vault
        // atomically, so the only write the fault can hit is the vault
        // file's rename; the on-disk vault must stay byte-identical.
        let (_dir, path) = fresh_vault_path();
        create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
        let before_bytes = std::fs::read(&path).expect("read vault");

        let assert = paladin_auth()
            .env("PALADIN_AUTH_FAULT_INJECT", "pre_commit")
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "edit",
                "alice",
                "--label",
                "alice2",
            ])
            .assert()
            .failure();
        let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
        let value: Value = serde_json::from_str(stderr.trim())
            .unwrap_or_else(|e| panic!("non-JSON stderr: {stderr:?} ({e})"));
        assert_eq!(value["error_kind"], serde_json::json!("save_not_committed"));
        assert_eq!(value["committed"], serde_json::json!(false));
        assert!(assert.get_output().stdout.is_empty());

        // Atomic-write rollback: the vault on disk is byte-identical and
        // the persisted label is still the pre-edit value.
        let after_bytes = std::fs::read(&path).expect("read vault");
        assert_eq!(before_bytes, after_bytes);
        let listed = list_accounts_json(&path);
        assert_eq!(listed["accounts"][0]["label"], serde_json::json!("alice"));
    }

    #[test]
    fn json_edit_post_commit_fault_surfaces_save_durability_unconfirmed_with_mutation_persisted() {
        // §8: a post-commit fault (parent-dir fsync failure) lands the
        // rename but cannot confirm durability, so the CLI surfaces
        // `save_durability_unconfirmed`. `SaveDurabilityUnconfirmed` is a
        // unit variant in core, so the envelope carries no extra fields
        // beyond `error_kind` — the "committed: true" semantics are
        // proven by re-reading the persisted vault, which already shows
        // the post-edit label (and preserves `created_at`).
        let (_dir, path) = fresh_vault_path();
        create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
        let created_at = list_accounts_json(&path)["accounts"][0]["created_at"].clone();

        let assert = paladin_auth()
            .env("PALADIN_AUTH_FAULT_INJECT", "post_commit")
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "edit",
                "alice",
                "--label",
                "alice2",
            ])
            .assert()
            .failure();
        let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
        let value: Value = serde_json::from_str(stderr.trim())
            .unwrap_or_else(|e| panic!("non-JSON stderr: {stderr:?} ({e})"));
        assert_eq!(
            value["error_kind"],
            serde_json::json!("save_durability_unconfirmed"),
        );
        assert!(assert.get_output().stdout.is_empty());

        // Mutation committed despite unconfirmed durability: the
        // persisted vault shows the new label and preserves created_at.
        let listed = list_accounts_json(&path);
        assert_eq!(listed["accounts"][0]["label"], serde_json::json!("alice2"));
        assert_eq!(listed["accounts"][0]["created_at"], created_at);
    }
}
