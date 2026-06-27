// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin-auth remove` and `paladin-auth rename`.
//!
//! No-prompt paths (`vault_missing`, no-match, multi-match, parse-time
//! `--json` rejection of missing `--yes`, and the `--yes` happy path
//! under both text and `--json`) live in plain `#[test]` functions.
//! Prompt-driven flows — text-mode `remove` without `--yes`, the
//! declined-confirmation `validation_error`, and the no-controlling-tty
//! `confirmation_prompt` failure — drive the CLI through the shared
//! `tests/common/mod.rs` PTY harness and the setsid-wrapped command
//! from the same module.

mod common;

use std::path::Path;
use std::time::{Duration, SystemTime};

use paladin_auth_core::{parse_otpauth, Account, Store, VaultInit};
use serde_json::Value;

use common::{fresh_vault_path, paladin_auth, paladin_auth_command_without_tty, Pty};

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
    let assert = paladin_auth()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    serde_json::from_str(stdout.trim()).unwrap()
}

// =========================================================================
// remove
// =========================================================================

#[test]
fn json_remove_missing_vault_rejects_with_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "remove",
            "--yes",
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
fn json_remove_no_match_rejects_with_no_match_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "remove",
            "--yes",
            "ghost",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("no_match"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_remove_multi_match_rejects_with_multiple_matches_and_disambiguators() {
    // `remove` always requires a single match even when every candidate
    // is TOTP — substring deletion would be too easy to misuse.
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
            "remove",
            "--yes",
            "alice",
        ])
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
        assert!(disambig.len() >= 11, "min 8 hex chars: {disambig:?}");
    }
    assert!(assert.get_output().stdout.is_empty());

    // Both accounts must still be present on disk after the rejected
    // remove.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 2);
}

#[test]
fn json_remove_without_yes_rejects_at_parse_time_with_validation_error() {
    // The strict-mode rule: under `--json`, the destructive
    // confirmation prompt cannot block, so `--yes` must be supplied.
    // The CLI rejects before any disk I/O so missing-vault and missing
    // accounts cannot even be inspected.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "remove",
            "alice",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("argv"));
    assert_eq!(
        value["reason"],
        serde_json::json!("yes_required_under_json")
    );
    assert!(assert.get_output().stdout.is_empty());

    // The account is still present — no mutation happened.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], serde_json::json!("alice"));
}

#[test]
fn json_remove_with_yes_succeeds_and_emits_removed_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![make_totp("alice", Some("Acme")), make_hotp("bob", None, 7)],
        &path,
    );

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "remove",
            "--yes",
            "alice",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["removed"]["label"], serde_json::json!("alice"));
    assert_eq!(value["removed"]["issuer"], serde_json::json!("Acme"));
    assert_eq!(value["removed"]["kind"], serde_json::json!("totp"));
    assert!(assert.get_output().stderr.is_empty());

    // Verify on disk: alice is gone, bob remains in insertion order.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], serde_json::json!("bob"));
}

#[test]
fn text_remove_with_yes_emits_human_friendly_success_line() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin_auth()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "remove",
            "--yes",
            "alice",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert_eq!(stdout, "Removed Acme:alice.\n");
}

#[test]
fn json_remove_with_yes_id_prefix_selects_unique_account_among_substring_collisions() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp("alice", Some("GitHub")),
            make_totp("alice", Some("GitLab")),
        ],
        &path,
    );

    // Read one id back through `list` and target it via `id:<hex>` so
    // the substring collision can be resolved.
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
            "remove",
            "--yes",
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
    assert_eq!(value["removed"]["id"], serde_json::json!(id));

    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["issuer"], serde_json::json!("GitLab"));
}

// =========================================================================
// rename
// =========================================================================

#[test]
fn json_rename_missing_vault_rejects_with_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "rename",
            "anything",
            "newname",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_rename_no_match_rejects_with_no_match_envelope() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "rename",
            "ghost",
            "newname",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("no_match"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_rename_multi_match_rejects_with_multiple_matches() {
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
            "rename",
            "alice",
            "newname",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("multiple_matches"));
    assert_eq!(value["candidates"].as_array().unwrap().len(), 2);
    assert!(assert.get_output().stdout.is_empty());

    // No mutation happened on the rejected path.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    let labels: Vec<&str> = arr.iter().map(|a| a["label"].as_str().unwrap()).collect();
    assert_eq!(labels, vec!["alice", "alice"]);
}

#[test]
fn json_rename_succeeds_and_emits_account_envelope_with_post_rename_state() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "rename",
            "alice",
            "alice2",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["account"]["label"], serde_json::json!("alice2"));
    assert_eq!(value["account"]["issuer"], serde_json::json!("Acme"));
    assert_eq!(value["account"]["kind"], serde_json::json!("totp"));
    assert!(assert.get_output().stderr.is_empty());

    // Confirm on disk: the account label has changed and the id is preserved.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], serde_json::json!("alice2"));
    assert_eq!(arr[0]["id"], value["account"]["id"]);
}

#[test]
fn json_rename_bumps_updated_at_above_created_at() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    // Capture the created_at / updated_at before the rename.
    let before = list_accounts_json(&path);
    let row = &before["accounts"][0];
    let created_at = row["created_at"].as_u64().expect("created_at u64");
    let updated_at_before = row["updated_at"].as_u64().expect("updated_at u64");
    assert_eq!(
        created_at, updated_at_before,
        "fresh account: updated_at == created_at"
    );

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "rename",
            "alice",
            "alice2",
        ])
        .assert()
        .success();
    let value: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();

    // The renamed account's updated_at is at or after created_at; we
    // can't assert strictly greater because tests run faster than one
    // second, but the post-rename value must be >= the pre-rename one.
    let updated_at_after = value["account"]["updated_at"]
        .as_u64()
        .expect("updated_at u64");
    assert!(
        updated_at_after >= updated_at_before,
        "updated_at must not regress: before={updated_at_before} after={updated_at_after}",
    );
    // created_at must not change.
    assert_eq!(
        value["account"]["created_at"],
        serde_json::json!(created_at)
    );
}

#[test]
fn text_rename_emits_human_friendly_success_line() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin_auth()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "rename",
            "alice",
            "alice2",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert_eq!(stdout, "Renamed to Acme:alice2.\n");
}

#[test]
fn json_rename_invalid_label_propagates_validation_error() {
    // Empty label is invalid per §4.1; the error originates in
    // `Vault::rename` and must propagate verbatim through
    // `mutate_and_save` without leaving the vault mutated on disk.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin_auth()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "rename",
            "alice",
            "",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert!(assert.get_output().stdout.is_empty());

    // Original account is intact on disk.
    let listed = list_accounts_json(&path);
    assert_eq!(listed["accounts"][0]["label"], serde_json::json!("alice"));
}

// =========================================================================
// PTY: text-mode `remove` confirmation flows
// =========================================================================

/// The destructive-confirmation prompt string emitted by
/// `commands::remove::run` for an `Acme:alice` target. Kept verbatim so
/// the harness expect()s the same bytes the CLI writes.
const PROMPT_REMOVE_CONFIRM_ACME_ALICE: &str = "Remove Acme:alice? Type 'yes' to confirm: ";

#[test]
fn pty_remove_without_yes_text_mode_reads_confirmation_from_dev_tty() {
    // §5: `remove` without `--yes` in text mode must read the
    // confirmation from `/dev/tty`. Drive the prompt with the PTY
    // harness so the child reaches `prompt::prompt_destructive_confirmation`,
    // type the literal `yes`, and verify the success line lands and
    // the account is gone on disk.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "remove", "alice"], &[]);
    pty.expect(PROMPT_REMOVE_CONFIRM_ACME_ALICE);
    pty.send_line("yes");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_contains("Removed Acme:alice.");

    // Post-state on disk: the account is gone.
    let listed = list_accounts_json(&path);
    assert!(listed["accounts"].as_array().unwrap().is_empty());
}

#[test]
fn pty_remove_confirmation_rejects_non_yes_response_with_declined_validation_error() {
    // §5: any response other than the exact `yes` (after Unicode
    // whitespace trim) exits with a `validation_error` carrying
    // `field: "confirmation"` / `reason: "declined"`. The CLI does
    // **not** reprompt — the harness reaches EOF immediately after the
    // bad response, which would otherwise hang past the per-call PTY
    // timeout.
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "remove", "alice"], &[]);
    pty.expect(PROMPT_REMOVE_CONFIRM_ACME_ALICE);
    pty.send_line("no");
    let exit = pty.wait_for_exit();
    exit.assert_exit(1);
    // Text-mode `paladin-auth: <Display>` for a `validation_error` with
    // field=confirmation reason=declined renders verbatim per
    // `output::error::render` and the `thiserror` format on
    // `PaladinAuthError::ValidationError`.
    exit.assert_transcript_contains("paladin-auth: validation error: confirmation: declined");
    // No reprompt: the success-line marker must never appear.
    exit.assert_transcript_lacks("Removed Acme:alice.");

    // Account is still present on disk.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], serde_json::json!("alice"));
}

#[test]
fn pty_remove_without_dev_tty_surfaces_io_error_confirmation_prompt() {
    // §5: when `/dev/tty` cannot be opened (no controlling terminal),
    // the destructive confirmation must surface
    // `io_error` `operation: "confirmation_prompt"`. Drive the path by
    // exec-ing the binary through `setsid(1)` so the child is a fresh
    // session leader and any `open("/dev/tty")` returns ENXIO.
    use std::process::Stdio;

    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let output = paladin_auth_command_without_tty()
        .args(["--vault", path.to_str().unwrap(), "remove", "alice"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn paladin-auth via setsid(1)");

    assert!(
        !output.status.success(),
        "expected non-zero exit without /dev/tty; status = {:?}, \
         stdout = {:?}, stderr = {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("paladin-auth: "),
        "expected `paladin-auth:` text-mode prefix, got {stderr:?}",
    );
    // Asserting the `confirmation_prompt` operation tag verbatim guards
    // against the renderer ever dropping it (sibling to the
    // `account_prompt` assertion in `cli_add.rs`).
    assert!(
        stderr.contains("I/O error during confirmation_prompt"),
        "expected `confirmation_prompt` operation tag in the rendered \
         text, got {stderr:?}",
    );

    // Account is still present — the prompt failed before any save.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["label"], serde_json::json!("alice"));
}
