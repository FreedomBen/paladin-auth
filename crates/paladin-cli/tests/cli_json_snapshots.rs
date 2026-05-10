// SPDX-License-Identifier: AGPL-3.0-or-later

//! Golden snapshot tests for the stable §5 JSON envelopes. Each
//! `#[test]` here drives one named code path through real `paladin`
//! process invocations and locks the resulting envelope shape via
//! `insta::assert_json_snapshot!`. Three groupings, mirroring the
//! `IMPLEMENTATION_PLAN_02_CLI.md` Tests checklist:
//!
//! 1. Per-command success envelopes (`list`, `add`, `show`, `peek`,
//!    `remove`, `rename`, `settings`, `export --plaintext`).
//! 2. Per-`error_kind` envelopes (`validation_error`, `vault_missing`,
//!    `vault_exists`, `no_match`, `multiple_matches`,
//!    `unsupported_format_version`, `invalid_header`,
//!    `duplicate_account`).
//! 3. `--help` / `--version` envelopes (top-level + subcommand).
//!
//! Volatile fields — `UUIDv4` account IDs, timestamps, the test temp
//! path, and the package version — are redacted via insta selectors
//! so the snapshot bytes stay stable across runs.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, SystemTime};

use insta::assert_json_snapshot;
use paladin_core::{parse_otpauth, Account, Store, VaultInit};
use serde_json::Value;
use tempfile::TempDir;

use common::paladin_command_without_tty;

/// Deterministic timestamp used by every fixture so `created_at` /
/// `updated_at` are reproducible. Picked at 2023-11-14 22:13:20 UTC.
const FIXTURE_NOW_SECS: u64 = 1_700_000_000;

fn fixture_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW_SECS)
}

/// Spawn `paladin` via `setsid(1)` so the child runs in a fresh
/// session with no controlling terminal. Any in-process
/// `open("/dev/tty")` returns `ENXIO`, which means a regression that
/// adds an unexpected prompt to one of these snapshot code paths
/// surfaces as `io_error operation: "passphrase_prompt"` (a
/// snapshot-breaking diff) rather than a hung test waiting on the
/// developer's terminal. Stdin is null and stdout / stderr are piped
/// so the captured `Output` is deterministic.
fn run_paladin(args: &[&str]) -> Output {
    paladin_command_without_tty()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn paladin via setsid(1)")
}

fn fresh_vault_path() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    (dir, path)
}

fn make_totp(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri =
        format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP&digits=6&period=30");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn make_hotp(label: &str, counter: u64) -> Account {
    let uri = format!(
        "otpauth://hotp/{label}?secret=KRSXG5DJN5XGS3DPMNQXG43JN5XGS3BB&digits=6&counter={counter}"
    );
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn seed_empty_plaintext_vault(path: &Path) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    vault.save(&store).expect("save");
}

fn seed_populated_plaintext_vault(path: &Path) {
    let (mut vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    let _ = vault.add(make_totp("alice", Some("Acme")));
    let _ = vault.add(make_hotp("bob", 42));
    vault.save(&store).expect("save");
}

fn assert_success(out: &Output) {
    assert!(
        out.status.success(),
        "expected success; status = {:?}, stdout = {:?}, stderr = {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn assert_failure(out: &Output) {
    assert!(
        !out.status.success(),
        "expected non-zero exit; status = {:?}, stdout = {:?}, stderr = {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn parse_stdout_json(out: &Output) -> Value {
    let stdout = std::str::from_utf8(&out.stdout).unwrap();
    serde_json::from_str(stdout.trim()).expect("stdout is JSON envelope")
}

fn parse_stderr_json(out: &Output) -> Value {
    let stderr = std::str::from_utf8(&out.stderr).unwrap();
    serde_json::from_str(stderr.trim()).expect("stderr is JSON envelope")
}

// =========================================================================
// Success envelopes (plan: "Per-command success envelopes are locked via
// insta golden snapshots")
// =========================================================================

#[test]
fn snapshot_list_empty_vault_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_empty_plaintext_vault(&path);
    let out = run_paladin(&["--json", "--vault", path.to_str().unwrap(), "list"]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out));
}

#[test]
fn snapshot_list_populated_vault_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_populated_plaintext_vault(&path);
    let out = run_paladin(&["--json", "--vault", path.to_str().unwrap(), "list"]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".accounts[].id" => "[uuid]",
        ".accounts[].created_at" => "[timestamp]",
        ".accounts[].updated_at" => "[timestamp]",
    });
}

#[test]
fn snapshot_add_uri_success_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_empty_plaintext_vault(&path);
    let out = run_paladin(&[
        "--json",
        "--vault",
        path.to_str().unwrap(),
        "add",
        "--uri",
        "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=6&period=30",
    ]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".account.id" => "[uuid]",
        ".account.created_at" => "[timestamp]",
        ".account.updated_at" => "[timestamp]",
    });
}

#[test]
fn snapshot_show_totp_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_populated_plaintext_vault(&path);
    let out = run_paladin(&["--json", "--vault", path.to_str().unwrap(), "show", "alice"]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".codes[].account.id" => "[uuid]",
        ".codes[].account.created_at" => "[timestamp]",
        ".codes[].account.updated_at" => "[timestamp]",
        ".codes[].code" => "[code]",
        ".codes[].valid_from" => "[valid_from]",
        ".codes[].valid_until" => "[valid_until]",
        ".codes[].seconds_remaining" => "[seconds_remaining]",
    });
}

#[test]
fn snapshot_peek_totp_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_populated_plaintext_vault(&path);
    let out = run_paladin(&["--json", "--vault", path.to_str().unwrap(), "peek", "alice"]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".codes[].account.id" => "[uuid]",
        ".codes[].account.created_at" => "[timestamp]",
        ".codes[].account.updated_at" => "[timestamp]",
        ".codes[].code" => "[code]",
        ".codes[].valid_from" => "[valid_from]",
        ".codes[].valid_until" => "[valid_until]",
        ".codes[].seconds_remaining" => "[seconds_remaining]",
    });
}

#[test]
fn snapshot_remove_yes_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_populated_plaintext_vault(&path);
    let out = run_paladin(&[
        "--json",
        "--vault",
        path.to_str().unwrap(),
        "remove",
        "alice",
        "--yes",
    ]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".removed.id" => "[uuid]",
        ".removed.created_at" => "[timestamp]",
        ".removed.updated_at" => "[timestamp]",
    });
}

#[test]
fn snapshot_rename_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_populated_plaintext_vault(&path);
    let out = run_paladin(&[
        "--json",
        "--vault",
        path.to_str().unwrap(),
        "rename",
        "alice",
        "alice2",
    ]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".account.id" => "[uuid]",
        ".account.created_at" => "[timestamp]",
        ".account.updated_at" => "[timestamp]",
    });
}

#[test]
fn snapshot_settings_get_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_empty_plaintext_vault(&path);
    let out = run_paladin(&[
        "--json",
        "--vault",
        path.to_str().unwrap(),
        "settings",
        "get",
    ]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out));
}

#[test]
fn snapshot_settings_set_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_empty_plaintext_vault(&path);
    let out = run_paladin(&[
        "--json",
        "--vault",
        path.to_str().unwrap(),
        "settings",
        "set",
        "auto_lock.enabled",
        "true",
    ]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out));
}

#[test]
fn snapshot_export_plaintext_envelope() {
    let (dir, vault_path) = fresh_vault_path();
    seed_empty_plaintext_vault(&vault_path);
    let written = dir.path().join("creds.json");
    let out = run_paladin(&[
        "--json",
        "--vault",
        vault_path.to_str().unwrap(),
        "export",
        "--plaintext",
        written.to_str().unwrap(),
    ]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".written" => "[path]",
    });
}

// =========================================================================
// Error envelopes (plan: "Per-error_kind envelopes are locked via insta
// golden snapshots")
// =========================================================================

#[test]
fn snapshot_validation_error_unknown_subcommand_envelope() {
    let out = run_paladin(&["--json", "definitely-not-a-subcommand"]);
    assert_failure(&out);
    assert_json_snapshot!(parse_stderr_json(&out));
}

#[test]
fn snapshot_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    let out = run_paladin(&["--json", "--vault", path.to_str().unwrap(), "list"]);
    assert_failure(&out);
    assert_json_snapshot!(parse_stderr_json(&out));
}

#[test]
fn snapshot_vault_exists_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_empty_plaintext_vault(&path);
    let out = run_paladin(&["--json", "--vault", path.to_str().unwrap(), "init"]);
    assert_failure(&out);
    assert_json_snapshot!(parse_stderr_json(&out));
}

#[test]
fn snapshot_no_match_envelope() {
    let (_dir, path) = fresh_vault_path();
    seed_populated_plaintext_vault(&path);
    let out = run_paladin(&[
        "--json",
        "--vault",
        path.to_str().unwrap(),
        "show",
        "no-such-account",
    ]);
    assert_failure(&out);
    assert_json_snapshot!(parse_stderr_json(&out));
}

#[test]
fn snapshot_multiple_matches_envelope() {
    // Seed two accounts whose label/issuer share the substring "Acme"
    // so a `show` substring query collides; one is HOTP so the
    // all-TOTP short-circuit doesn't fire.
    let (_dir, path) = fresh_vault_path();
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create");
    let _ = vault.add(make_totp("alice", Some("Acme")));
    let _ = vault.add(make_hotp("Acme-bob", 7));
    vault.save(&store).expect("save");

    let out = run_paladin(&[
        "--json",
        "--vault",
        path.to_str().unwrap(),
        "remove",
        "Acme",
        "--yes",
    ]);
    assert_failure(&out);
    assert_json_snapshot!(parse_stderr_json(&out), {
        ".candidates[].id" => "[uuid]",
        ".candidates[].created_at" => "[timestamp]",
        ".candidates[].updated_at" => "[timestamp]",
        ".candidates[].disambiguator" => "[disambiguator]",
    });
}

#[test]
fn snapshot_unsupported_format_version_envelope() {
    // Hand-roll a header whose `format_ver` byte (offset 8) is `2` so
    // `inspect` returns `unsupported_format_version` with `format_ver`.
    let (_dir, path) = fresh_vault_path();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PALADIN\0");
    bytes.push(2); // format_ver — unsupported
    bytes.push(0); // mode — plaintext
    bytes.extend_from_slice(&[0u8; 6]); // reserved
    std::fs::write(&path, &bytes).expect("write header");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");

    let out = run_paladin(&["--json", "--vault", path.to_str().unwrap(), "list"]);
    assert_failure(&out);
    assert_json_snapshot!(parse_stderr_json(&out));
}

#[test]
fn snapshot_invalid_header_envelope() {
    let (_dir, path) = fresh_vault_path();
    std::fs::write(&path, b"NOTAVAULT\0").expect("write bogus header");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");

    let out = run_paladin(&["--json", "--vault", path.to_str().unwrap(), "list"]);
    assert_failure(&out);
    assert_json_snapshot!(parse_stderr_json(&out));
}

#[test]
fn snapshot_duplicate_account_envelope() {
    let (_dir, path) = fresh_vault_path();
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create");
    let _ = vault.add(make_totp("alice", Some("Acme")));
    vault.save(&store).expect("save");

    let out = run_paladin(&[
        "--json",
        "--vault",
        path.to_str().unwrap(),
        "add",
        "--uri",
        "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
    ]);
    assert_failure(&out);
    assert_json_snapshot!(parse_stderr_json(&out), {
        ".account.id" => "[uuid]",
        ".account.created_at" => "[timestamp]",
        ".account.updated_at" => "[timestamp]",
    });
}

// =========================================================================
// Help / version envelopes (plan: "Help / version success envelopes are
// locked via insta golden snapshots")
// =========================================================================

#[test]
fn snapshot_help_envelope_top_level() {
    let out = run_paladin(&["--json", "--help"]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        // Clap renders the binary version inside `--help` text; redact
        // so the snapshot survives version bumps.
        ".help.text" => "[help-text]",
    });
}

#[test]
fn snapshot_help_envelope_subcommand() {
    let out = run_paladin(&["--json", "init", "--help"]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".help.text" => "[help-text]",
    });
}

#[test]
fn snapshot_version_envelope() {
    let out = run_paladin(&["--json", "--version"]);
    assert_success(&out);
    assert_json_snapshot!(parse_stdout_json(&out), {
        ".version.version" => "[version]",
    });
}
