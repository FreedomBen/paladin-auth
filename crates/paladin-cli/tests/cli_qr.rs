// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin qr <query>`. Covers the no-prompt
//! Phase L bullets from `docs/IMPLEMENTATION_PLAN_02_CLI.md` against
//! a plaintext source vault: single-match cardinality, `no_match`,
//! read-only HOTP semantics, ANSI default to stdout, the four
//! parse-time rejections (`--format=png|svg` without `--out`,
//! `--format=ansi` with `--out`, `--json` without `--out`,
//! `--module-size-px` out of bounds), PNG / SVG to `--out` mode bits,
//! overwrite gate, `--json` success envelope, `--no-color` /
//! `NO_COLOR` no-op on ANSI, `id:<hex>` selector, empty-query rejection,
//! and a thinness regression guard that the `qrcode` crate is never a
//! production dependency.
//!
//! Encrypted-vault coverage requires a scripted `/dev/tty` and lands
//! through the shared `common::Pty` harness. Fault-injection coverage
//! is gated behind the `paladin-cli/test-hooks` cargo feature.

#![allow(clippy::too_many_lines)]

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

// ==========================================================================
// Cardinality / read-only semantics
// ==========================================================================

#[test]
fn json_qr_single_match_writes_png_to_out_path() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let v: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(v["written"], serde_json::json!(out.to_str().unwrap()));
    assert_eq!(v["format"], serde_json::json!("qr_png"));
    assert_eq!(v["account"]["label"], serde_json::json!("alice"));
    assert_eq!(v["account"]["issuer"], serde_json::json!("Acme"));
}

#[test]
fn json_qr_no_match_against_populated_vault_emits_no_match_envelope() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "nonexistent",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("no_match"));
    assert!(assert.get_output().stdout.is_empty());
    // --out was never created since no_match short-circuits before write.
    assert!(!out.exists());
}

#[test]
fn json_qr_multi_match_emits_multiple_matches_envelope() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(
        vec![
            make_totp("alice", Some("GitHub")),
            make_totp("alice", Some("GitLab")),
        ],
        &path,
    );
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("multiple_matches"));
    let cands = v["candidates"].as_array().expect("array");
    assert_eq!(cands.len(), 2);
    assert!(!out.exists());
}

#[test]
fn qr_read_only_hotp_counter_is_unchanged_after_three_invocations() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_hotp("bob", None, 17)], &path);
    let out = dir.path().join("qr.png");

    for _ in 0..3 {
        paladin()
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "qr",
                "bob",
                "--out",
                out.to_str().unwrap(),
                "--force",
            ])
            .assert()
            .success();
    }

    let listed = list_accounts_json(&path);
    assert_eq!(
        listed["accounts"][0]["counter"],
        serde_json::json!(17),
        "qr must never advance a HOTP counter",
    );
}

#[test]
fn qr_read_only_peek_observes_same_counter_before_and_after() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_hotp("bob", None, 17)], &path);
    let out = dir.path().join("qr.png");

    let before = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "peek", "bob"])
        .assert()
        .success();
    let before_v: Value = serde_json::from_str(
        std::str::from_utf8(&before.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();

    paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "bob",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let after = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "peek", "bob"])
        .assert()
        .success();
    let after_v: Value = serde_json::from_str(
        std::str::from_utf8(&after.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();

    assert_eq!(before_v, after_v, "peek before/after qr must agree");
}

// ==========================================================================
// ANSI default to stdout
// ==========================================================================

#[test]
fn qr_text_mode_default_renders_ansi_half_blocks_to_stdout_and_warning_to_stderr() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "qr", "alice"])
        .assert()
        .success();

    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    // Body must contain at least one Unicode half-block glyph emitted
    // by the `Dense1x2` renderer.
    let has_block =
        stdout.contains('\u{2580}') || stdout.contains('\u{2584}') || stdout.contains('\u{2588}');
    assert!(
        has_block,
        "ANSI body must contain Unicode half-block glyphs, got {:?}",
        &stdout[..stdout.len().min(80)],
    );

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.contains("QR code"),
        "expected QR-export warning on stderr, got {stderr:?}",
    );
    assert!(
        stderr.contains("plaintext export"),
        "expected 'plaintext export' wording on stderr, got {stderr:?}",
    );
}

#[test]
fn qr_no_color_and_no_color_env_do_not_change_ansi_body_bytes() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let baseline = paladin()
        .args(["--vault", path.to_str().unwrap(), "qr", "alice"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let with_flag = paladin()
        .args([
            "--no-color",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        baseline, with_flag,
        "--no-color must not alter the ANSI half-block body",
    );

    let with_env = paladin()
        .env("NO_COLOR", "1")
        .args(["--vault", path.to_str().unwrap(), "qr", "alice"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        baseline, with_env,
        "NO_COLOR must not alter the ANSI half-block body",
    );
}

// ==========================================================================
// Parse-time rejections (fire before vault inspection / unlock)
// ==========================================================================

#[test]
fn qr_format_png_without_out_rejects_at_parse_time() {
    // The vault is intentionally missing — parse-time rejection must
    // win over `vault_missing`.
    let (_dir, path) = fresh_vault_path();

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--format",
            "png",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("out"));
    assert_eq!(v["reason"], serde_json::json!("required_for_binary_format"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn qr_format_svg_without_out_rejects_at_parse_time() {
    let (_dir, path) = fresh_vault_path();

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--format",
            "svg",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("out"));
    assert_eq!(v["reason"], serde_json::json!("required_for_binary_format"));
}

#[test]
fn qr_format_ansi_with_out_rejects_at_parse_time() {
    let (dir, path) = fresh_vault_path();
    let out = dir.path().join("qr.txt");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--format",
            "ansi",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("format"));
    assert_eq!(v["reason"], serde_json::json!("ansi_requires_no_out"));
}

#[test]
fn qr_json_without_out_rejects_at_parse_time() {
    let (_dir, path) = fresh_vault_path();

    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "qr", "alice"])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("out"));
    assert_eq!(v["reason"], serde_json::json!("required_under_json"));
}

#[test]
fn qr_module_size_px_below_min_rejects_with_out_of_bounds() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
            "--module-size-px",
            "0",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("module_size_px"));
    assert_eq!(v["reason"], serde_json::json!("out_of_bounds"));
}

#[test]
fn qr_module_size_px_above_max_rejects_with_out_of_bounds() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
            "--module-size-px",
            "65",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("module_size_px"));
    assert_eq!(v["reason"], serde_json::json!("out_of_bounds"));
}

#[test]
fn qr_module_size_px_out_of_bounds_wins_precedence_over_vault_missing() {
    // The vault is intentionally missing — out-of-bounds module size
    // must reject before vault inspection.
    let (_dir, path) = fresh_vault_path();
    let out = path.with_file_name("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
            "--module-size-px",
            "0",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("module_size_px"));
}

#[test]
fn qr_module_size_px_accepted_on_format_ansi() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    paladin()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--format",
            "ansi",
            "--module-size-px",
            "8",
        ])
        .assert()
        .success();
}

#[test]
fn qr_empty_query_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "",
            "--out",
            "/tmp/should-not-be-written.png",
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("query"));
}

// ==========================================================================
// PNG / SVG to --out: 0600 / overwrite gate / --force
// ==========================================================================

const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[test]
fn qr_png_to_out_writes_zero_six_zero_zero_mode_with_png_signature() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    paladin()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let bytes = std::fs::read(&out).expect("read png");
    assert!(
        bytes.starts_with(PNG_MAGIC),
        "expected PNG signature at start, got {:?}",
        &bytes[..bytes.len().min(8)],
    );
    assert!(!bytes.is_empty());
}

#[test]
fn qr_svg_to_out_writes_zero_six_zero_zero_mode_with_xml_or_svg_prefix() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.svg");

    paladin()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
            "--format",
            "svg",
        ])
        .assert()
        .success();

    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let bytes = std::fs::read(&out).expect("read svg");
    let s = std::str::from_utf8(&bytes).expect("utf-8 svg");
    assert!(
        s.starts_with("<?xml") || s.starts_with("<svg"),
        "expected XML / SVG prefix, got {:?}",
        &s[..s.len().min(40)],
    );
}

#[test]
fn qr_refuses_to_overwrite_existing_out_without_force() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");
    std::fs::write(&out, b"prev").expect("seed existing");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("out"));
    assert_eq!(v["reason"], serde_json::json!("exists"));

    // Existing file must be byte-identical to the seed.
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(bytes, b"prev");
}

#[test]
fn qr_force_flag_overwrites_existing_out_with_new_png_bytes() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");
    std::fs::write(&out, b"prev").expect("seed existing");

    paladin()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    assert!(bytes.starts_with(PNG_MAGIC));
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// ==========================================================================
// --json envelope shape and stream cleanliness
// ==========================================================================

#[test]
fn qr_json_success_envelope_carries_written_format_and_account_summary() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["written"], serde_json::json!(out.to_str().unwrap()));
    assert_eq!(v["format"], serde_json::json!("qr_png"));
    let account = &v["account"];
    assert_eq!(account["label"], serde_json::json!("alice"));
    assert_eq!(account["issuer"], serde_json::json!("Acme"));
    assert_eq!(account["kind"], serde_json::json!("totp"));
    assert!(account["id"].is_string());
    assert!(account["digits"].is_number());
    assert!(account["period"].is_number());
    assert!(account["created_at"].is_number());
    assert!(account["updated_at"].is_number());
    // Read-only invariant: updated_at must equal created_at because
    // `qr` never mutates the account.
    assert_eq!(account["updated_at"], account["created_at"]);

    // --json stderr must be empty (warning is suppressed).
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.is_empty(),
        "expected empty stderr under --json, got {stderr:?}"
    );
}

#[test]
fn qr_json_svg_success_envelope_uses_qr_svg_format_label() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.svg");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
            "--format",
            "svg",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["format"], serde_json::json!("qr_svg"));
}

#[test]
fn qr_json_mode_warning_text_never_appears_on_stdout_or_stderr() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    for stream in [stdout, stderr] {
        assert!(
            !stream.contains("QR code encodes"),
            "warning text leaked into a stream under --json: {stream:?}",
        );
    }
}

// ==========================================================================
// id:<hex> selector
// ==========================================================================

#[test]
fn qr_id_prefix_selects_unique_account_against_substring_overlap() {
    let (dir, path) = fresh_vault_path();
    // Two accounts whose issuer:label substrings overlap on the
    // canonical "alice" key.
    let alice = make_totp("alice", Some("alice-corp"));
    let alice_id = alice.id();
    create_vault_with(vec![alice, make_totp("alice", Some("acme"))], &path);
    let out = dir.path().join("qr.png");

    let hex = alice_id.to_hyphenated().replace('-', "");
    let prefix = &hex[..8];

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            &format!("id:{prefix}"),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();
    let v: Value = serde_json::from_str(
        std::str::from_utf8(&assert.get_output().stdout)
            .unwrap()
            .trim(),
    )
    .unwrap();
    assert_eq!(v["account"]["issuer"], serde_json::json!("alice-corp"));
}

#[test]
fn qr_id_prefix_too_short_rejects_with_validation_error() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "id:abc",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("query"));
}

#[test]
fn qr_id_prefix_too_long_rejects_with_validation_error() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");
    let too_long = format!("id:{}", "0".repeat(33));

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            &too_long,
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("query"));
}

#[test]
fn qr_id_prefix_non_hex_rejects_with_validation_error() {
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Acme"))], &path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "id:gggggggg",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("query"));
}

// ==========================================================================
// Empty vault on disk
// ==========================================================================

#[test]
fn qr_vault_missing_rejects_with_vault_missing_envelope() {
    let (dir, path) = fresh_vault_path();
    let out = dir.path().join("qr.png");
    // Path intentionally not created.

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("vault_missing"));
}

#[test]
fn qr_empty_vault_returns_no_match() {
    let (dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);
    let out = dir.path().join("qr.png");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("no_match"));
}

// ==========================================================================
// --module-size-px: non-integer and overflow variants
// ==========================================================================

#[test]
fn qr_module_size_px_non_integer_rejects_with_invalid_integer() {
    // Three variants of "not a non-negative base-10 integer" — a
    // word, a fractional value, and a negative — all surface the
    // same `validation_error` (`field: "module_size_px"`,
    // `reason: "invalid_integer"`). Paired with `--vault
    // /nonexistent.bin` to also pin that parse-time validation wins
    // over `vault_missing`. `--out` is supplied so `resolve_target`
    // (which runs before `parse_module_size_px`) does not fire
    // `required_under_json` first.
    for raw in ["abc", "1.5", "-1"] {
        let dir = test_tempdir();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
        let out = dir.path().join("qr.png");
        // Use the `--flag=value` form so clap does not interpret a
        // leading-minus value (e.g. "-1") as a separate flag — the
        // `usage` parser would surface `field: "argv"` first and
        // hide the per-flag rejection we are pinning here.
        let module_arg = format!("--module-size-px={raw}");
        let assert = paladin()
            .args([
                "--json",
                "--vault",
                "/nonexistent.bin",
                "qr",
                "alice",
                "--out",
                out.to_str().unwrap(),
                module_arg.as_str(),
            ])
            .assert()
            .failure();

        let stdout = assert.get_output().stdout.clone();
        assert!(
            stdout.is_empty(),
            "stdout must stay empty under --json parse rejection; got {stdout:?}",
        );
        let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
        let v: Value = serde_json::from_str(stderr.trim())
            .unwrap_or_else(|e| panic!("non-JSON stderr for {raw:?}: {stderr:?} ({e})"));
        assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
        assert_eq!(v["field"], serde_json::json!("module_size_px"));
        assert_eq!(
            v["reason"],
            serde_json::json!("invalid_integer"),
            "raw={raw:?} envelope={v}",
        );
        // The destination must not have been touched.
        assert!(
            !out.exists(),
            "parse-time rejection must not create the --out path",
        );
    }
}

#[test]
fn qr_module_size_px_overflow_rejects_with_overflow() {
    // `u32::MAX + 1` parses cleanly as u64 but cannot be narrowed to
    // u32 — `parse_module_size_px` must surface that as `overflow`,
    // distinct from the malformed-integer family. Mirrors the
    // `kdf-memory-mib` overflow precedent. As with the
    // non-integer case, `--vault /nonexistent.bin` proves the
    // overflow rejection wins over `vault_missing`.
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let out = dir.path().join("qr.png");

    let raw = (u64::from(u32::MAX) + 1).to_string();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            "/nonexistent.bin",
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
            "--module-size-px",
            &raw,
        ])
        .assert()
        .failure();

    let stdout = assert.get_output().stdout.clone();
    assert!(
        stdout.is_empty(),
        "stdout must stay empty under --json parse rejection; got {stdout:?}",
    );
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("module_size_px"));
    assert_eq!(v["reason"], serde_json::json!("overflow"));
    assert!(
        !out.exists(),
        "parse-time rejection must not create the --out path",
    );
}

// ==========================================================================
// PNG / SVG decode-back round trips (test-side decoders)
// ==========================================================================

/// Decode a PNG byte slice via `rqrr` and return the embedded payload.
/// Mirrors `paladin-core/tests/export_qr.rs::decode_png_to_payload` so
/// the CLI test sees the same QR payload a real scanner would.
fn decode_png_to_payload(path: &Path) -> String {
    let img = image::open(path).expect("decode PNG file");
    let luma = img.to_luma8();
    let (w, h) = luma.dimensions();
    let raw = luma.into_raw();
    let buf = image::ImageBuffer::<image::Luma<u8>, _>::from_raw(w, h, raw).expect("rebuild luma");
    let mut decoder = rqrr::PreparedImage::prepare(buf);
    let grids = decoder.detect_grids();
    assert_eq!(grids.len(), 1, "QR image must contain exactly one code");
    let (_meta, content) = grids[0].decode().expect("decode QR grid");
    content
}

/// Compute the `otpauth://` URI a real scanner would see for the
/// single account in `vault_path`. Goes through
/// `paladin_core::export::otpauth_list`, the same emitter the
/// QR pipeline uses, so we are not rebaking parser-side normalisation
/// into the test.
fn expected_otpauth_uri_for_single_account_vault(vault_path: &Path) -> String {
    let (vault, _store) =
        paladin_core::Store::open(vault_path, paladin_core::VaultLock::Plaintext).expect("open");
    let list = paladin_core::export::otpauth_list(&vault);
    let trimmed = list.trim_end_matches('\n');
    assert!(
        !trimmed.contains('\n'),
        "this helper assumes a single-account vault, got: {trimmed}",
    );
    trimmed.to_string()
}

#[test]
fn qr_png_to_out_decodes_back_to_matching_otpauth_uri() {
    // `paladin qr alice --out <path>.png` writes a PNG whose embedded
    // payload, decoded through `rqrr`, must equal the URI
    // `paladin_core::export::otpauth_list` would emit for the same
    // account (parity with the core round-trip test
    // `paladin-core/tests/export_qr.rs::
    // export_qr_png_round_trips_through_rqrr_for_totp_and_hotp`).
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Example"))], &path);
    let out = dir.path().join("qr.png");

    paladin()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let expected = expected_otpauth_uri_for_single_account_vault(&path);
    let decoded = decode_png_to_payload(&out);
    assert_eq!(
        decoded, expected,
        "QR PNG must round-trip back to the same otpauth URI",
    );
    // Mode is checked elsewhere, but reaffirm here so the round-trip
    // case also pins the §4.3 contract.
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn qr_svg_to_out_decodes_through_quick_xml_sanity_check() {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    // The SVG file must be well-formed XML, parseable by `quick-xml`,
    // with an `<svg>` root and at least one `<rect>` or `<path>`
    // child (so we know the QR modules were actually drawn). Pairs
    // with the existing `qr_svg_to_out_writes_zero_six_zero_zero_
    // mode_with_xml_or_svg_prefix` test which only checks the prefix.
    let (dir, path) = fresh_vault_path();
    create_vault_with(vec![make_totp("alice", Some("Example"))], &path);
    let out = dir.path().join("qr.svg");

    paladin()
        .args([
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
            "--format",
            "svg",
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).expect("read svg");
    let s = std::str::from_utf8(&bytes).expect("utf-8 svg");
    assert!(
        s.starts_with("<?xml") || s.starts_with("<svg"),
        "SVG file must start with <?xml or <svg, got: {:?}",
        &s[..s.len().min(40)],
    );

    let mut reader = Reader::from_str(s);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut svg_root_seen = false;
    let mut module_child_seen = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                // `local_name()` is the tag without any namespace
                // prefix; SVG documents may or may not declare one.
                let name = e.local_name();
                let local = std::str::from_utf8(name.as_ref()).expect("utf-8 tag name");
                if local == "svg" {
                    svg_root_seen = true;
                }
                if local == "rect" || local == "path" {
                    module_child_seen = true;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => panic!("quick-xml parse error: {e}"),
            _ => {}
        }
        buf.clear();
    }

    assert!(svg_root_seen, "SVG document must contain an <svg> element");
    assert!(
        module_child_seen,
        "SVG document must contain at least one <rect> or <path> drawing the QR modules",
    );
}

// ==========================================================================
// `--out` durability — `PALADIN_FAULT_INJECT` round-trip
// ==========================================================================

#[cfg(feature = "test-hooks")]
mod fault_inject {
    use super::*;

    #[test]
    fn qr_out_pre_commit_fault_surfaces_save_not_committed() {
        // §5: a `pre_commit` save fault on the QR `--out` atomic
        // write must surface the `save_not_committed` envelope with
        // `committed: false`. `paladin qr` opens its source vault
        // read-only and writes a fresh `--out` path, so the only
        // atomic write the fault can hit is the QR file's rename.
        // Mirrors `cli_export.rs::fault_inject::
        // pty_encrypted_export_pre_commit_surfaces_save_not_committed`
        // but against a plaintext source vault — no unlock prompt
        // fires, so we drive it with `assert_cmd` rather than the
        // PTY harness.
        let (dir, path) = fresh_vault_path();
        create_vault_with(vec![make_totp("alice", Some("Example"))], &path);
        let out = dir.path().join("qr.png");

        let assert = paladin()
            .env("PALADIN_FAULT_INJECT", "pre_commit")
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "qr",
                "alice",
                "--out",
                out.to_str().unwrap(),
            ])
            .assert()
            .failure();

        let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
        let v: Value = serde_json::from_str(stderr.trim())
            .unwrap_or_else(|e| panic!("non-JSON stderr: {stderr:?} ({e})"));
        assert_eq!(v["error_kind"], serde_json::json!("save_not_committed"));
        assert_eq!(v["committed"], serde_json::json!(false));

        // §4.3 atomic-write rollback: the destination must not exist
        // because the rename never landed.
        assert!(
            !out.exists(),
            "pre-commit fault must leave the --out path untouched",
        );
    }

    #[test]
    fn qr_out_post_commit_fault_surfaces_save_durability_unconfirmed() {
        // §5: a `post_commit` save fault on the QR `--out` atomic
        // write must surface the `save_durability_unconfirmed`
        // envelope — the rename succeeded, only the post-commit
        // `fsync` of the parent directory failed.
        // `SaveDurabilityUnconfirmed` is a unit variant in core, so
        // the envelope carries no extra fields beyond `error_kind`.
        let (dir, path) = fresh_vault_path();
        create_vault_with(vec![make_totp("alice", Some("Example"))], &path);
        let out = dir.path().join("qr.png");

        let assert = paladin()
            .env("PALADIN_FAULT_INJECT", "post_commit")
            .args([
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "qr",
                "alice",
                "--out",
                out.to_str().unwrap(),
            ])
            .assert()
            .failure();

        let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
        let v: Value = serde_json::from_str(stderr.trim())
            .unwrap_or_else(|e| panic!("non-JSON stderr: {stderr:?} ({e})"));
        assert_eq!(
            v["error_kind"],
            serde_json::json!("save_durability_unconfirmed"),
        );

        // The rename committed even though the post-commit fsync
        // failed: the destination exists and starts with the PNG
        // magic bytes.
        let bytes = std::fs::read(&out).expect("read png");
        assert!(
            bytes.starts_with(PNG_MAGIC),
            "post-commit fault must leave the PNG on disk"
        );
    }
}

// ==========================================================================
// Encrypted vault end-to-end (PTY) — single unlock prompt, decode-back
// ==========================================================================

/// Stable §5 prompt label fired by `vault_open::open` for any
/// encrypted-vault unlock — same string `cli_passphrase.rs` and
/// `cli_export.rs` expect.
const PROMPT_UNLOCK_QR: &str = "Vault passphrase: ";

#[test]
fn pty_qr_against_encrypted_vault_unlocks_once_and_decodes_correctly() {
    use paladin_core::{Argon2Params, EncryptionOptions, VaultInit};
    use secrecy::SecretString;

    // 1. Seed an encrypted vault with §4.4 minimum Argon2 params so
    //    the unlock derivation stays cheap. One TOTP account so the
    //    decoded QR maps to exactly one `otpauth_list` line.
    let (_dir, path) = fresh_vault_path();
    let out_dir = common::test_tempdir();
    std::fs::set_permissions(out_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod out_dir 0700");
    let out = out_dir.path().join("qr.png");
    let passphrase = "encrypted-qr-secret";

    {
        let pp = SecretString::from(passphrase.to_string());
        let params = Argon2Params {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        let opts = EncryptionOptions::with_params(pp, params).expect("opts");
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(opts)).expect("create encrypted");
        vault.add(make_totp("alice", Some("Example")));
        vault.save(&store).expect("save");
    }

    // Expected URI uses the same passphrase to read back the seeded
    // vault through `otpauth_list`.
    let expected = {
        let pp = SecretString::from(passphrase.to_string());
        let (vault, _store) =
            Store::open(&path, paladin_core::VaultLock::Encrypted(pp)).expect("open encrypted");
        let list = paladin_core::export::otpauth_list(&vault);
        list.trim_end_matches('\n').to_string()
    };

    // 2. Drive `paladin qr` through the PTY harness. `--json` keeps
    //    the success envelope on stdout; the unlock prompt must fire
    //    exactly once.
    let mut pty = common::Pty::spawn(
        [
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "qr",
            "alice",
            "--out",
            out.to_str().unwrap(),
        ],
        &[],
    );
    pty.expect(PROMPT_UNLOCK_QR);
    pty.send_line(passphrase);
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);

    // Exactly one unlock prompt in the transcript.
    let prompt_count = exit.transcript.matches(PROMPT_UNLOCK_QR).count();
    assert_eq!(
        prompt_count, 1,
        "unlock prompt must fire exactly once, transcript:\n{}",
        exit.transcript,
    );

    // 3. The JSON success envelope must appear in the transcript
    //    (stdout muxes through the PTY).
    assert!(
        exit.transcript.contains("\"format\":\"qr_png\""),
        "JSON success envelope must carry format=qr_png; transcript:\n{}",
        exit.transcript,
    );

    // 4. The on-disk PNG must decode back to the expected URI via
    //    the same `rqrr` helper the plaintext round-trip uses.
    let decoded = decode_png_to_payload(&out);
    assert_eq!(
        decoded, expected,
        "encrypted-vault QR PNG must round-trip back to the same otpauth URI",
    );
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// ==========================================================================
// Thinness regression — `qrcode` must never be a production [dependencies]
// entry of crates/paladin-cli/Cargo.toml. The dev-dependency stays.
// ==========================================================================

#[test]
fn deny_qrcode_in_runtime_deps() {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));

    let mut in_dependencies = false;
    let mut hits = Vec::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(header) = rest.strip_suffix(']') {
                in_dependencies = header == "dependencies";
                if header == "dependencies.qrcode" {
                    hits.push("[dependencies.qrcode]".to_string());
                }
                continue;
            }
        }
        if !in_dependencies {
            continue;
        }
        if let Some(eq_idx) = trimmed.find('=') {
            let key = trimmed[..eq_idx].trim();
            if key == "qrcode" {
                hits.push("dependencies.qrcode".to_string());
            }
        }
    }
    assert!(
        hits.is_empty(),
        "paladin-cli must not declare `qrcode` as a runtime dependency \
         (it is permitted only under [dev-dependencies] for test fixtures); \
         got: {hits:?}",
    );
}
