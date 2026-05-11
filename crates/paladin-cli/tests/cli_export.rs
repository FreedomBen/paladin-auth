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
use paladin_core::{parse_otpauth, Argon2Params, EncryptionOptions, Store, VaultInit};
use secrecy::SecretString;
use serde_json::Value;
use tempfile::TempDir;

mod common;

use common::test_tempdir;
use common::Pty;

const PALADIN_MAGIC: &[u8; 8] = b"PALADIN\0";

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
    let dir = test_tempdir();
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
    let dir = test_tempdir();
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

// ==========================================================================
// Encrypted-export PTY round-trip
// ==========================================================================

/// §5 prompt label fired by `vault_open::open` for any encrypted-vault
/// unlock.
const PROMPT_UNLOCK: &str = "Vault passphrase: ";
/// §5 prompt label fired by `paladin export --encrypted` for the new
/// bundle passphrase.
const PROMPT_EXPORT: &str = "Export passphrase: ";
/// §5 prompt label fired right after `PROMPT_EXPORT` to confirm the
/// bundle passphrase entry.
const PROMPT_CONFIRM: &str = "Confirm passphrase: ";
/// §5 prompt label fired by `paladin import` after
/// `classify_paladin_import_precheck` returns `PromptForPassphrase` for
/// an encrypted Paladin bundle.
const PROMPT_BUNDLE: &str = "Bundle passphrase: ";

/// Build an encrypted source vault under §4.4 minimum Argon2 params and
/// preload it with `uris` so the export round-trip has something
/// non-empty to ferry through the bundle. Min KDF params keep CI fast
/// while still going through the real `Store::create` /
/// `Vault::save` pipeline.
fn create_encrypted_vault_with(path: &Path, passphrase: &str, uris: &[&str]) {
    let pp = SecretString::from(passphrase.to_string());
    let params = Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    let opts = EncryptionOptions::with_params(pp, params).expect("opts");
    let (mut vault, store) = Store::create(path, VaultInit::Encrypted(opts)).expect("create");
    let now = SystemTime::now();
    for uri in uris {
        let validated = parse_otpauth(uri, now).expect("parse fixture");
        let _id = vault.add(validated.account);
    }
    vault.save(&store).expect("save");
}

#[test]
fn pty_encrypted_export_round_trips_through_import_with_independent_passphrases() {
    // §5 / "Passphrase prompts": the `export --encrypted` bundle
    // passphrase protects only the exported Paladin bundle. It is
    // independent of the selected vault's own unlock passphrase. To
    // lock that contract, drive a full export → import round-trip
    // where the two passphrases are deliberately different and the
    // import succeeds with the *bundle* passphrase only.
    let (src_dir, src_vault_path) = fresh_vault_path();
    let vault_pass = "vault-secret";
    let bundle_pass = "bundle-secret-different";
    assert_ne!(
        vault_pass, bundle_pass,
        "test fixture must use distinct passphrases to assert independence",
    );
    create_encrypted_vault_with(&src_vault_path, vault_pass, &[TOTP_URI_ALICE]);

    let bundle_path = src_dir.path().join("alice.paladin");

    // Export over PTY: vault unlock first, then bundle passphrase
    // (twice to satisfy the new-passphrase confirmation rule).
    // Pin the bundle KDF to §4.4 minimums so the test is fast.
    let mut export_pty = Pty::spawn(
        [
            "--vault",
            src_vault_path.to_str().unwrap(),
            "export",
            "--encrypted",
            bundle_path.to_str().unwrap(),
            "--kdf-memory-mib",
            "8",
            "--kdf-time",
            "1",
            "--kdf-parallelism",
            "1",
        ],
        &[],
    );
    export_pty.expect(PROMPT_UNLOCK);
    export_pty.send_line(vault_pass);
    export_pty.expect(PROMPT_EXPORT);
    export_pty.send_line(bundle_pass);
    export_pty.expect(PROMPT_CONFIRM);
    export_pty.send_line(bundle_pass);
    let export_exit = export_pty.wait_for_exit();
    export_exit.assert_exit(0);
    assert!(
        bundle_path.exists(),
        "encrypted bundle file must exist after export, transcript:\n{}",
        export_exit.transcript,
    );

    // Import the bundle into a fresh plaintext destination vault. The
    // destination has no unlock passphrase, so the *only* prompt that
    // fires is the bundle prompt — proving the bundle passphrase is
    // not the source vault unlock passphrase.
    let (_dst_dir, dst_path) = fresh_vault_path();
    create_empty_plaintext_vault(&dst_path);

    let mut import_pty = Pty::spawn(
        [
            "--vault",
            dst_path.to_str().unwrap(),
            "import",
            bundle_path.to_str().unwrap(),
        ],
        &[],
    );
    import_pty.expect(PROMPT_BUNDLE);
    import_pty.send_line(bundle_pass);
    let import_exit = import_pty.wait_for_exit();
    import_exit.assert_exit(0);

    // Round-trip succeeded: the imported account matches the source.
    let listed = paladin()
        .args(["--json", "--vault", dst_path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&listed.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    let accounts = v["accounts"].as_array().expect("accounts array");
    assert_eq!(accounts.len(), 1, "exactly one account round-tripped");
    assert_eq!(accounts[0]["label"], serde_json::json!("alice"));
    assert_eq!(accounts[0]["issuer"], serde_json::json!("Acme"));
}

#[test]
fn pty_encrypted_export_with_custom_kdf_writes_requested_params_to_bundle_header() {
    // §5 + §4.4: `export --encrypted` honors the supplied
    // `--kdf-memory-mib` / `--kdf-time` / `--kdf-parallelism` flags
    // and writes them verbatim into the bundle's encrypted header.
    // The companion test
    // `pty_encrypted_export_with_default_kdf_writes_section_4_4_defaults_to_bundle_header`
    // covers the no-flags default path; this one pins the custom
    // path. Source vault is plaintext so the only prompts are the
    // bundle's new-passphrase + confirmation, and the only Argon2id
    // derivation is the one for the bundle key — at §4.4 minimums,
    // so CI stays fast.
    let (dir, vault_path) = fresh_vault_path();
    create_plaintext_vault_with(&vault_path, &[TOTP_URI_ALICE]);
    let bundle_path = dir.path().join("alice-custom.paladin");

    let mut pty = Pty::spawn(
        [
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--encrypted",
            bundle_path.to_str().unwrap(),
            "--kdf-memory-mib",
            "8",
            "--kdf-time",
            "1",
            "--kdf-parallelism",
            "1",
        ],
        &[],
    );
    pty.expect(PROMPT_EXPORT);
    pty.send_line("bundle-secret");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("bundle-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    assert!(
        bundle_path.exists(),
        "encrypted bundle file must exist after export, transcript:\n{}",
        exit.transcript,
    );

    // Bundle is byte-compatible with the on-disk encrypted vault
    // header per `build_encrypted_bundle_for_export` (DESIGN.md
    // §4.6): magic (8) + format_ver (1) + mode (1) + kdf_id (1) +
    // m_kib LE u32 (4) + t LE u32 (4) + p LE u32 (4) + salt (16) +
    // aead_id (1) + nonce (24).
    let header = std::fs::read(&bundle_path).expect("read bundle");
    assert!(header.len() >= 64, "encrypted header should be ≥ 64 bytes");
    assert_eq!(&header[..8], PALADIN_MAGIC);
    assert_eq!(header[8], 1, "format_ver");
    assert_eq!(header[9], 1, "mode == encrypted");
    assert_eq!(header[10], 1, "kdf_id == Argon2id");
    let m_kib = u32::from_le_bytes(header[11..15].try_into().unwrap());
    let t = u32::from_le_bytes(header[15..19].try_into().unwrap());
    let p = u32::from_le_bytes(header[19..23].try_into().unwrap());
    assert_eq!(m_kib, 8 * 1024);
    assert_eq!(t, 1);
    assert_eq!(p, 1);
    assert_eq!(header[39], 1, "aead_id == XChaCha20-Poly1305");

    let perms = std::fs::metadata(&bundle_path)
        .expect("metadata")
        .permissions();
    assert_eq!(perms.mode() & 0o7777, 0o600);
}

#[test]
fn pty_encrypted_export_with_default_kdf_writes_section_4_4_defaults_to_bundle_header() {
    // §5 + §4.4: when no `--kdf-*` flags are passed,
    // `export --encrypted` must build the bundle under the
    // production defaults (`m_kib = 65_536`, `t = 3`, `p = 1`).
    // Source vault is plaintext so the only Argon2id derivation
    // performed in this test is the one for the bundle key at
    // defaults; there is no unlock prompt.
    let (dir, vault_path) = fresh_vault_path();
    create_plaintext_vault_with(&vault_path, &[TOTP_URI_ALICE]);
    let bundle_path = dir.path().join("alice-default.paladin");

    let mut pty = Pty::spawn(
        [
            "--vault",
            vault_path.to_str().unwrap(),
            "export",
            "--encrypted",
            bundle_path.to_str().unwrap(),
        ],
        &[],
    );
    pty.expect(PROMPT_EXPORT);
    pty.send_line("bundle-secret");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("bundle-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    assert!(
        bundle_path.exists(),
        "encrypted bundle file must exist after export, transcript:\n{}",
        exit.transcript,
    );

    let header = std::fs::read(&bundle_path).expect("read bundle");
    assert!(header.len() >= 64, "encrypted header should be ≥ 64 bytes");
    assert_eq!(&header[..8], PALADIN_MAGIC);
    assert_eq!(header[8], 1, "format_ver");
    assert_eq!(header[9], 1, "mode == encrypted");
    assert_eq!(header[10], 1, "kdf_id == Argon2id");
    let m_kib = u32::from_le_bytes(header[11..15].try_into().unwrap());
    let t = u32::from_le_bytes(header[15..19].try_into().unwrap());
    let p = u32::from_le_bytes(header[19..23].try_into().unwrap());
    assert_eq!(m_kib, 65_536, "default m_kib must match §4.4 (64 MiB)");
    assert_eq!(t, 3, "default t must match §4.4");
    assert_eq!(p, 1, "default p must match §4.4");
    assert_eq!(header[39], 1, "aead_id == XChaCha20-Poly1305");

    let perms = std::fs::metadata(&bundle_path)
        .expect("metadata")
        .permissions();
    assert_eq!(perms.mode() & 0o7777, 0o600);
}

#[cfg(feature = "test-hooks")]
mod fault_inject {
    use super::*;

    /// `export --encrypted` against a plaintext source vault is the
    /// cheapest fault fixture: no unlock derivation, only the bundle
    /// new-key derivation runs, and minimum KDF params keep that
    /// cheap. The rename of the staged bundle file is what the
    /// `pre_commit` / `post_commit` fault hooks intercept inside
    /// `write_secret_file_atomic`.
    #[test]
    fn pty_encrypted_export_pre_commit_surfaces_save_not_committed() {
        // §5: a `pre_commit` save fault on the bundle's atomic write
        // must surface the `save_not_committed` envelope with
        // `committed: false`. The bundle has no rotated backup (only
        // `init --force` rotates a primary file) so `backup_path` is
        // not present on this envelope.
        let (dir, vault_path) = fresh_vault_path();
        create_plaintext_vault_with(&vault_path, &[TOTP_URI_ALICE]);
        let bundle_path = dir.path().join("bundle.paladin");

        let mut pty = Pty::spawn(
            [
                "--json",
                "--vault",
                vault_path.to_str().unwrap(),
                "export",
                "--encrypted",
                bundle_path.to_str().unwrap(),
                "--kdf-memory-mib",
                "8",
                "--kdf-time",
                "1",
                "--kdf-parallelism",
                "1",
            ],
            &[("PALADIN_FAULT_INJECT", "pre_commit")],
        );
        pty.expect(PROMPT_EXPORT);
        pty.send_line("bundle-secret");
        pty.expect(PROMPT_CONFIRM);
        pty.send_line("bundle-secret");
        let exit = pty.wait_for_exit();
        exit.assert_exit(1);
        let env = extract_json(&exit.transcript).expect("error envelope must appear in transcript");
        assert_eq!(env["error_kind"], serde_json::json!("save_not_committed"));
        assert_eq!(env["committed"], serde_json::json!(false));

        // §4.3 atomic-write rollback: the destination must not exist
        // because the rename never happened.
        assert!(
            !bundle_path.exists(),
            "pre-commit fault must leave the bundle path untouched, transcript:\n{}",
            exit.transcript,
        );
    }

    #[test]
    fn pty_encrypted_export_post_commit_surfaces_save_durability_unconfirmed() {
        // §5: a `post_commit` save fault on the bundle's atomic write
        // must surface the `save_durability_unconfirmed` envelope —
        // the rename succeeded, only the post-commit `fsync` of the
        // parent directory failed. `SaveDurabilityUnconfirmed` is a
        // unit variant in core, so the envelope carries no extra
        // fields beyond `error_kind`. The on-disk side proves the
        // rename committed: the bundle now exists with the Paladin
        // magic bytes at the head.
        let (dir, vault_path) = fresh_vault_path();
        create_plaintext_vault_with(&vault_path, &[TOTP_URI_ALICE]);
        let bundle_path = dir.path().join("bundle.paladin");

        let mut pty = Pty::spawn(
            [
                "--json",
                "--vault",
                vault_path.to_str().unwrap(),
                "export",
                "--encrypted",
                bundle_path.to_str().unwrap(),
                "--kdf-memory-mib",
                "8",
                "--kdf-time",
                "1",
                "--kdf-parallelism",
                "1",
            ],
            &[("PALADIN_FAULT_INJECT", "post_commit")],
        );
        pty.expect(PROMPT_EXPORT);
        pty.send_line("bundle-secret");
        pty.expect(PROMPT_CONFIRM);
        pty.send_line("bundle-secret");
        let exit = pty.wait_for_exit();
        exit.assert_exit(1);
        let env = extract_json(&exit.transcript).expect("error envelope must appear in transcript");
        assert_eq!(
            env["error_kind"],
            serde_json::json!("save_durability_unconfirmed"),
        );

        let bytes = std::fs::read(&bundle_path).expect("read bundle");
        assert!(
            bytes.len() >= 64,
            "post-commit fault must leave the bundle on disk; got {} bytes",
            bytes.len(),
        );
        assert_eq!(&bytes[..8], PALADIN_MAGIC);
        assert_eq!(bytes[9], 1, "bundle mode == encrypted");
    }

    /// Pull the JSON envelope out of a PTY transcript. Under `--json`
    /// the error envelope is one document on stderr (and stdout is
    /// empty), so the transcript ends with the JSON document followed
    /// by a newline. Mirrors `cli_init.rs::fault_inject::extract_json`
    /// and `cli_passphrase.rs::fault_inject::extract_json`.
    fn extract_json(transcript: &str) -> Option<serde_json::Value> {
        let bytes = transcript.as_bytes();
        let end = bytes.iter().rposition(|&b| b == b'}')?;
        let mut depth = 0i32;
        let mut start = end;
        for i in (0..=end).rev() {
            match bytes[i] {
                b'}' => depth += 1,
                b'{' => {
                    depth -= 1;
                    if depth == 0 {
                        start = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let s = &transcript[start..=end];
        serde_json::from_str(s).ok()
    }
}
