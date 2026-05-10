// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin passphrase {set,change,remove}`.
//! Covers the no-prompt error paths — KDF flag validation, KDF
//! precedence over `vault_missing` and `invalid_state`, the
//! wrong-state gate (`set` on encrypted, `change` / `remove` on
//! plaintext), `vault_missing` on a missing file, and the
//! parse-time rejection of `passphrase remove --json` without
//! `--yes`. PTY-driven happy paths and prompt-I/O failures use the
//! shared `tests/common/mod.rs` harness to script `/dev/tty`.
//!
//! The set-on-encrypted `invalid_state` test creates a real encrypted
//! vault with the §4.4 minimum Argon2 parameters (`m_kib = 8192`,
//! `t = 1`, `p = 1`) so `inspect` classifies the file as encrypted
//! without hand-rolling header bytes; the wrong-state gate fires
//! before any unlock attempt so the test never needs the passphrase
//! again.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use paladin_core::{Argon2Params, EncryptionOptions, Store, VaultInit};
use secrecy::SecretString;
use serde_json::Value;
use tempfile::TempDir;

use common::Pty;

/// `PALADIN\0` magic prefix on every vault file (DESIGN.md §4.6).
const PALADIN_MAGIC: &[u8; 8] = b"PALADIN\0";

/// Stable §5 prompt label for the first new-passphrase entry. Used by
/// `init`, `passphrase set`, `passphrase change`, and
/// `export --encrypted`.
const PROMPT_NEW_PASSPHRASE: &str = "New passphrase: ";

/// Stable §5 prompt label for the new-passphrase confirmation entry.
const PROMPT_CONFIRM: &str = "Confirm passphrase: ";

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

fn create_empty_plaintext_vault(path: &Path) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create");
    vault.save(&store).expect("save");
}

/// Create a real encrypted vault under the §4.4 minimum Argon2
/// parameters so `inspect` returns `Encrypted` without hand-rolling
/// header bytes. Used only by the wrong-state-on-encrypted tests; the
/// passphrase is never re-entered because the gate fires before any
/// unlock attempt.
fn create_encrypted_vault(path: &Path, passphrase: &str) {
    let pp = SecretString::from(passphrase.to_string());
    let params = Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    let opts = EncryptionOptions::with_params(pp, params).expect("opts");
    let (vault, store) = Store::create(path, VaultInit::Encrypted(opts)).expect("create");
    vault.save(&store).expect("save");
}

// =========================================================================
// passphrase set
// =========================================================================

#[test]
fn json_set_invalid_kdf_memory_mib_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "set",
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
fn json_set_kdf_time_below_floor_rejects_with_kdf_params_out_of_bounds() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "set",
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
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_set_kdf_validation_wins_over_vault_missing_precedence() {
    // No vault on disk + invalid KDF integer: KDF parse fires before
    // `inspect`, so the user sees `validation_error` rather than
    // `vault_missing`. Locked by the §5 ordering rule.
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "set",
            "--kdf-time",
            "nope",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("kdf-time"));
}

#[test]
fn json_set_missing_vault_rejects_with_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "set",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_set_on_encrypted_vault_rejects_with_invalid_state_already_encrypted() {
    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(&path, "secret");
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "set",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("invalid_state"));
    assert_eq!(value["operation"], serde_json::json!("set_passphrase"));
    assert_eq!(value["state"], serde_json::json!("already_encrypted"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_set_kdf_validation_wins_over_invalid_state_already_encrypted() {
    // Encrypted vault + invalid KDF integer: KDF parse fires before
    // `inspect`'s wrong-state gate, so the user sees the validation
    // error rather than `invalid_state`.
    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(&path, "secret");
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "set",
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
fn pty_set_on_open_plaintext_vault_succeeds_and_writes_encrypted_with_requested_kdf_params() {
    // §5: `passphrase set` on a plaintext vault prompts for the new
    // passphrase + a matching confirmation via `/dev/tty` (no unlock
    // prompt: the source vault is plaintext), encrypts the vault
    // under the requested Argon2id parameters, and prints the
    // text-mode `Encrypted vault.` success line. Drive the prompts
    // through the shared PTY harness with the §4.4 minimum KDF params
    // so Argon2id stays fast in CI.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let mut pty = Pty::spawn(
        [
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "set",
            "--kdf-memory-mib",
            "8",
            "--kdf-time",
            "1",
            "--kdf-parallelism",
            "1",
        ],
        &[],
    );
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("hunter2-newpass");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("hunter2-newpass");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_contains("Encrypted vault.");

    // Post-state on disk: the vault is now encrypted under the
    // requested KDF parameters. Header layout per DESIGN.md §4.6 —
    // magic (8) + format_ver (1) + mode (1) + kdf_id (1) +
    // m_kib LE u32 (4) + t LE u32 (4) + p LE u32 (4) + salt (16) +
    // aead_id (1) + nonce (24).
    let header = std::fs::read(&path).expect("read encrypted vault");
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

    // File mode preserved at `0o600` across the rotation.
    let perms = std::fs::metadata(&path).expect("metadata").permissions();
    assert_eq!(perms.mode() & 0o7777, 0o600);
}

// =========================================================================
// passphrase change
// =========================================================================

#[test]
fn json_change_invalid_kdf_memory_mib_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "change",
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
}

#[test]
fn json_change_missing_vault_rejects_with_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "change",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_change_on_plaintext_vault_rejects_with_invalid_state_not_encrypted() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "change",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("invalid_state"));
    assert_eq!(value["operation"], serde_json::json!("change_passphrase"));
    assert_eq!(value["state"], serde_json::json!("not_encrypted"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_change_kdf_validation_wins_over_invalid_state_not_encrypted() {
    // Plaintext vault + invalid KDF integer: KDF parse fires before
    // `inspect`'s wrong-state gate, so the user sees the validation
    // error rather than `invalid_state`.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "change",
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

// =========================================================================
// passphrase remove
// =========================================================================

#[test]
fn json_remove_without_yes_rejects_at_parse_time_with_yes_required_under_json() {
    // No vault file is needed because the parse-time check fires
    // before any disk I/O. This mirrors the `paladin remove --json`
    // pattern.
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "remove",
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
}

#[test]
fn json_remove_with_yes_missing_vault_rejects_with_vault_missing_envelope() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "remove",
            "--yes",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_missing"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_remove_with_yes_on_plaintext_vault_rejects_with_invalid_state_not_encrypted() {
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "remove",
            "--yes",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("invalid_state"));
    assert_eq!(value["operation"], serde_json::json!("remove_passphrase"));
    assert_eq!(value["state"], serde_json::json!("not_encrypted"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn text_remove_without_yes_under_json_emits_validation_error_envelope() {
    // Sanity-check the parse-time `--json --yes` rule under the
    // text-mode default — the rejection only fires under `--json`,
    // so without `--json` the command should reach the wrong-state
    // gate against the plaintext vault and emit `invalid_state`
    // rather than `yes_required_under_json`. Locked the rule that
    // `--yes` is only required under `--json`.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);
    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "passphrase", "remove"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.contains("invalid state") && stderr.contains("not_encrypted"),
        "expected wrong-state error, got: {stderr:?}"
    );
}
