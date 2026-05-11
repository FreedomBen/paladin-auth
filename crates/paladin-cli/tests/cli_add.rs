// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin add`. Covers the no-prompt input
//! modes (`--uri`, manual flags, mode-combination rejection,
//! `--json` interactive rejection, and duplicate detection) plus the
//! `[PTY]` interactive happy / invalid-input flows that drive the
//! shared `tests/common/mod.rs` PTY harness so writes to `/dev/tty`
//! and `rpassword` reads round-trip end to end. `--qr` happy-path
//! coverage still needs synthetic QR fixtures and lands alongside
//! that change.

mod common;

use common::test_tempdir;

use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use image::{ImageBuffer, ImageFormat, Luma};
use paladin_core::{Store, VaultInit};
use qrcode::QrCode;
use serde_json::Value;
use tempfile::TempDir;

use common::Pty;

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

/// Render two QR codes side-by-side into one PNG so a single
/// `paladin add --qr` invocation has to walk every grid that
/// `rqrr::PreparedImage::detect_grids` returns. Mirrors the
/// `make_side_by_side_rgba` shape used by
/// `paladin-core/tests/import_qr.rs`, but writes a real PNG on disk
/// so we exercise the CLI's `read_import_file` -> facade path.
fn write_two_qr_png(dir: &Path, name: &str, left: &str, right: &str) -> PathBuf {
    let left_qr = QrCode::new(left.as_bytes())
        .expect("encode left QR")
        .render::<Luma<u8>>()
        .min_dimensions(160, 160)
        .quiet_zone(true)
        .build();
    let right_qr = QrCode::new(right.as_bytes())
        .expect("encode right QR")
        .render::<Luma<u8>>()
        .min_dimensions(160, 160)
        .quiet_zone(true)
        .build();
    let (lw, lh) = left_qr.dimensions();
    let (rw, rh) = right_qr.dimensions();
    let h = lh.max(rh);
    // 32-pixel white gutter so rqrr resolves the two grids cleanly.
    let gutter: u32 = 32;
    let w = lw + gutter + rw;
    let mut combined = ImageBuffer::<Luma<u8>, Vec<u8>>::from_pixel(w, h, Luma([0xFF]));
    for y in 0..lh {
        for x in 0..lw {
            combined.put_pixel(x, y, *left_qr.get_pixel(x, y));
        }
    }
    for y in 0..rh {
        for x in 0..rw {
            let dx = lw + gutter + x;
            combined.put_pixel(dx, y, *right_qr.get_pixel(x, y));
        }
    }
    let path = dir.join(format!("{name}.png"));
    let mut buf = Cursor::new(Vec::<u8>::new());
    combined
        .write_to(&mut buf, ImageFormat::Png)
        .expect("encode PNG");
    std::fs::write(&path, buf.into_inner()).expect("write PNG");
    path
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

// --- Interactive add via the scripted /dev/tty PTY harness ---------------

const PROMPT_LABEL: &str = "Label: ";
const PROMPT_ISSUER: &str = "Issuer (optional): ";
const PROMPT_SECRET: &str = "Secret (Base32): ";
const PROMPT_DIGITS: &str = "Digits [6]: ";
const PROMPT_KIND: &str = "Kind [totp/hotp, default totp]: ";
const PROMPT_PERIOD: &str = "Period seconds [30]: ";
const PROMPT_ICON_HINT: &str = "Icon hint (slug, blank for default, 'none' to clear): ";

#[test]
fn pty_interactive_add_reads_manual_fields_once_with_defaults() {
    // §5: interactive `add` collects the manual-mode form once from
    // `/dev/tty`, hides the secret entry via `rpassword`, and routes
    // the result through `paladin_core::validate_manual` with the
    // §4.1 manual defaults (TOTP, SHA1, 6 digits, 30 s period,
    // issuer-derived icon).
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "add"], &[]);
    pty.expect(PROMPT_LABEL);
    pty.send_line("alice");
    pty.expect(PROMPT_ISSUER);
    pty.send_line("Acme");
    pty.expect(PROMPT_SECRET);
    pty.send_line(LONG_BASE32_SECRET);
    pty.expect(PROMPT_DIGITS);
    pty.send_line("");
    pty.expect(PROMPT_KIND);
    pty.send_line("");
    pty.expect(PROMPT_PERIOD);
    pty.send_line("");
    pty.expect(PROMPT_ICON_HINT);
    pty.send_line("");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);

    // Hidden secret entry: `rpassword` disables echo on the slave
    // PTY, so the Base32 secret never reaches the parent transcript
    // even though every visible prompt does.
    exit.assert_transcript_lacks(LONG_BASE32_SECRET);

    // Manual-mode defaults survive the round-trip through
    // `validate_manual`.
    let listed = list_accounts_json(&path);
    let arr = listed["accounts"].as_array().expect("accounts array");
    assert_eq!(arr.len(), 1);
    let a = &arr[0];
    assert_eq!(a["label"], serde_json::json!("alice"));
    assert_eq!(a["issuer"], serde_json::json!("Acme"));
    assert_eq!(a["kind"], serde_json::json!("totp"));
    assert_eq!(a["digits"], serde_json::json!(6));
    assert_eq!(a["period"], serde_json::json!(30));
    assert_eq!(a["counter"], Value::Null);
}

#[test]
fn pty_interactive_add_without_dev_tty_surfaces_io_error_account_prompt() {
    // §5: interactive `add` must read account fields from `/dev/tty`,
    // never from stdin. When the child has no controlling terminal,
    // `prompt::write_prompt`'s `OpenOptions::open("/dev/tty")` fails
    // with `ENXIO` and the CLI exits with `io_error`,
    // `operation: "account_prompt"`. Drive that path by exec-ing
    // through `setsid(1)` so the child is a fresh session leader.
    use std::process::Stdio;

    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let output = common::paladin_command_without_tty()
        .args(["--vault", path.to_str().unwrap(), "add"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn paladin via setsid(1)");

    assert!(
        !output.status.success(),
        "expected non-zero exit without /dev/tty; status = {:?}, \
         stdout = {:?}, stderr = {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Text-mode `paladin: <message>` prefix from `output::error::render`.
    assert!(
        stderr.starts_with("paladin: "),
        "expected `paladin:` text-mode prefix, got {stderr:?}",
    );
    // `PaladinError::IoError` Display is
    // `"I/O error during {operation}: {source}"` per
    // `paladin_core::error::PaladinError`. Asserting the operation tag
    // verbatim guards against the renderer ever dropping it.
    assert!(
        stderr.contains("I/O error during account_prompt"),
        "expected the §5 `account_prompt` operation tag in the \
         rendered text, got {stderr:?}",
    );
    // The prompt failed before the vault could be mutated.
    let listed = list_accounts_json(&path);
    assert!(listed["accounts"].as_array().unwrap().is_empty());
}

#[test]
fn pty_interactive_add_invalid_secret_rejects_without_reprompt() {
    // §5: invalid input surfaces as a `validation_error` after the
    // single-pass form is collected; the CLI never re-asks for the
    // bad field. A bad-Base32 secret therefore exits non-zero, the
    // vault is unchanged, and the harness reaches `wait_for_exit`
    // immediately after the icon-hint reply (a reprompt would hang
    // the child past the per-call PTY timeout).
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "add"], &[]);
    pty.expect(PROMPT_LABEL);
    pty.send_line("alice");
    pty.expect(PROMPT_ISSUER);
    pty.send_line("");
    pty.expect(PROMPT_SECRET);
    pty.send_line("not-base32!");
    pty.expect(PROMPT_DIGITS);
    pty.send_line("");
    pty.expect(PROMPT_KIND);
    pty.send_line("");
    pty.expect(PROMPT_PERIOD);
    pty.send_line("");
    pty.expect(PROMPT_ICON_HINT);
    pty.send_line("");
    let exit = pty.wait_for_exit();
    exit.assert_exit(1);

    let listed = list_accounts_json(&path);
    assert!(listed["accounts"].as_array().unwrap().is_empty());
}

// --- --qr multi-entry image happy-path / fixed-skip-policy ---------------

#[test]
fn json_add_qr_multi_entry_image_emits_import_envelope_with_two_accounts() {
    // §5: `add --qr` is multi-entry, so it shares the `import` /
    // `add --qr` success envelope shape: imported / skipped /
    // replaced / appended counts plus an `accounts` array of
    // `AccountSummary` objects and a `warnings` array. A single PNG
    // carrying two distinct otpauth URIs must therefore land both
    // accounts on the first run with imported = 2 and every other
    // count zero.
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);

    let qr_path = write_two_qr_png(dir.path(), "pair", SAMPLE_TOTP_URI, SAMPLE_HOTP_URI);

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "add",
            "--qr",
            qr_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(v["imported"], serde_json::json!(2));
    assert_eq!(v["skipped"], serde_json::json!(0));
    assert_eq!(v["replaced"], serde_json::json!(0));
    assert_eq!(v["appended"], serde_json::json!(0));
    let accounts = v["accounts"].as_array().expect("accounts array");
    assert_eq!(accounts.len(), 2);
    assert!(v["warnings"].is_array());
    assert!(assert.get_output().stderr.is_empty());

    // Both URIs landed in the vault, and the post-merge IDs in the
    // success envelope resolved to the same accounts that `list`
    // reports.
    let listed = list_accounts_json(&vault_path);
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 2);
}

#[test]
fn json_add_qr_uses_fixed_skip_policy_on_collision() {
    // §5: `add --qr` always uses `ImportConflict::Skip` (not
    // configurable from the CLI), so re-importing the same image
    // counts every entry as skipped and leaves the vault unchanged.
    // Asserting the fixed policy here guards against a future drift
    // toward `replace` / `append` for `add --qr`, which would make
    // the command silently destructive.
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);

    let qr_path = write_two_qr_png(dir.path(), "pair", SAMPLE_TOTP_URI, SAMPLE_HOTP_URI);

    // First run inserts both.
    paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "add",
            "--qr",
            qr_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Second run on the same image: every entry collides and the
    // fixed skip policy short-circuits each.
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "add",
            "--qr",
            qr_path.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(v["imported"], serde_json::json!(0));
    assert_eq!(v["skipped"], serde_json::json!(2));
    assert_eq!(v["replaced"], serde_json::json!(0));
    assert_eq!(v["appended"], serde_json::json!(0));

    // Vault is still exactly two accounts — skip is non-destructive.
    let listed = list_accounts_json(&vault_path);
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 2);
}
