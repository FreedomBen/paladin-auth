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
