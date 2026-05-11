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

use common::test_tempdir;

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

/// Stable §5 prompt label fired by `vault_open::open` for any
/// encrypted-vault unlock (`change` / `remove` / `add` / `list` / …).
const PROMPT_UNLOCK: &str = "Vault passphrase: ";

/// Stable §5 destructive-confirmation prompt fired by
/// `passphrase remove` (text mode, no `--yes`) before the vault is
/// re-saved as plaintext.
const PROMPT_REMOVE_CONFIRM: &str = "Decrypt vault to plaintext? Type 'yes' to confirm: ";

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

#[test]
fn pty_set_confirmation_mismatch_rejects_with_invalid_passphrase_before_mutation() {
    // §5: A new-passphrase confirmation mismatch must surface
    // `invalid_passphrase` `reason: "confirmation_mismatch"` before
    // any mutation. `passphrase set` on a plaintext vault is the
    // simplest path because it has no unlock prompt — only the new
    // entry + confirmation are prompted for. The on-disk vault must
    // remain plaintext (mode byte still 0) and the file must not be
    // re-encrypted.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let before = std::fs::read(&path).expect("read pre-set vault");
    assert_eq!(&before[..8], PALADIN_MAGIC);
    assert_eq!(before[9], 0, "fixture should be plaintext");

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
    pty.send_line("password-a");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("password-b");
    let exit = pty.wait_for_exit();
    // Runtime errors exit `1` per §5.
    exit.assert_exit(1);
    // Text-mode renderer prefixes `paladin: ` to the
    // `Display::fmt` body of `PaladinError::InvalidPassphrase`,
    // which is `invalid passphrase: <reason>`.
    exit.assert_transcript_contains("paladin: invalid passphrase: confirmation_mismatch");
    // Mutation must not have occurred — no encrypted re-save and no
    // success line.
    exit.assert_transcript_lacks("Encrypted vault.");

    // Post-state on disk: still plaintext, header byte-identical.
    let after = std::fs::read(&path).expect("read post-set vault");
    assert_eq!(after, before, "vault file must not be mutated on mismatch");
}

#[test]
fn pty_set_without_dev_tty_surfaces_io_error_passphrase_prompt() {
    // §5: when `/dev/tty` cannot be opened (no controlling terminal),
    // any passphrase-prompt path must surface `io_error`
    // `operation: "passphrase_prompt"`. `passphrase set` on a
    // plaintext vault is the simplest fixture: no unlock prompt or
    // destructive confirmation precedes the new-passphrase prompt,
    // so the failure unambiguously originates from the passphrase
    // prompt itself. Drive the path by exec-ing the binary through
    // `setsid(1)` so the child is a fresh session leader and any
    // `open("/dev/tty")` returns `ENXIO`.
    use std::process::Stdio;

    use common::paladin_command_without_tty;

    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let before = std::fs::read(&path).expect("read pre-set vault");
    assert_eq!(before[9], 0, "fixture should be plaintext");

    let output = paladin_command_without_tty()
        .args(["--vault", path.to_str().unwrap(), "passphrase", "set"])
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
    assert!(
        stderr.starts_with("paladin: ") || stderr.contains("\npaladin: "),
        "expected `paladin:` text-mode prefix on the error line, got {stderr:?}",
    );
    // The `passphrase_prompt` operation tag is asserted verbatim so
    // a future refactor that mis-tags the prompt I/O failure (e.g.
    // as `confirmation_prompt`) trips this test loudly.
    assert!(
        stderr.contains("I/O error during passphrase_prompt"),
        "expected `passphrase_prompt` operation tag, got {stderr:?}",
    );
    // Vault on disk must be untouched (still plaintext, byte-identical).
    let after = std::fs::read(&path).expect("read vault");
    assert_eq!(
        after, before,
        "vault must remain unchanged when the prompt itself fails"
    );
}

#[test]
fn pty_set_with_default_kdf_writes_section_4_4_defaults_on_disk() {
    // §5 + §4.4: when no `--kdf-*` flags are passed, `passphrase set`
    // must encrypt under the §4.4 production defaults
    // (`m_kib = 65_536`, `t = 3`, `p = 1`). The companion test at
    // `pty_set_on_open_plaintext_vault_succeeds_and_writes_encrypted_with_requested_kdf_params`
    // covers the custom-params path; this one covers the no-flags
    // path. A single Argon2id derivation is performed (one for the
    // new key — there is no unlock prompt on a plaintext source).
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let mut pty = Pty::spawn(
        ["--vault", path.to_str().unwrap(), "passphrase", "set"],
        &[],
    );
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("hunter2-newpass");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("hunter2-newpass");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_contains("Encrypted vault.");

    let header = std::fs::read(&path).expect("read encrypted vault");
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

#[test]
fn pty_change_on_open_encrypted_vault_succeeds_and_rotates_salt_under_requested_kdf_params() {
    // §5: `passphrase change` on an encrypted vault first prompts
    // for the existing unlock passphrase, then for the new
    // passphrase + a matching confirmation, all via `/dev/tty`.
    // After re-encrypting, the on-disk vault stays in encrypted mode
    // under the requested Argon2id parameters and the salt has
    // rotated (DESIGN.md §4.4 — every save rolls fresh salt + nonce).
    // The test fixture is created with the §4.4 minimum KDF params
    // so both the unlock derivation and the post-change derivation
    // stay fast in CI.
    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(&path, "old-secret");

    // Salt before the change — proves the rotation actually happened.
    let before = std::fs::read(&path).expect("read pre-change vault");
    assert_eq!(before[9], 1, "fixture should be encrypted");
    let salt_before: [u8; 16] = before[23..39].try_into().unwrap();

    let mut pty = Pty::spawn(
        [
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "change",
            "--kdf-memory-mib",
            "8",
            "--kdf-time",
            "1",
            "--kdf-parallelism",
            "1",
        ],
        &[],
    );
    pty.expect(PROMPT_UNLOCK);
    pty.send_line("old-secret");
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("new-secret");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("new-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_contains("Re-encrypted vault.");

    // Post-state on disk: still encrypted under the requested KDF
    // params, with a fresh salt.
    let after = std::fs::read(&path).expect("read post-change vault");
    assert!(after.len() >= 64, "encrypted header should be ≥ 64 bytes");
    assert_eq!(&after[..8], PALADIN_MAGIC);
    assert_eq!(after[8], 1, "format_ver");
    assert_eq!(after[9], 1, "mode == encrypted");
    assert_eq!(after[10], 1, "kdf_id == Argon2id");
    let m_kib = u32::from_le_bytes(after[11..15].try_into().unwrap());
    let t = u32::from_le_bytes(after[15..19].try_into().unwrap());
    let p = u32::from_le_bytes(after[19..23].try_into().unwrap());
    assert_eq!(m_kib, 8 * 1024);
    assert_eq!(t, 1);
    assert_eq!(p, 1);
    assert_eq!(after[39], 1, "aead_id == XChaCha20-Poly1305");

    let salt_after: [u8; 16] = after[23..39].try_into().unwrap();
    assert_ne!(
        salt_before, salt_after,
        "salt must rotate on every save (DESIGN.md §4.4)",
    );

    // File mode preserved at `0o600` across the rotation.
    let perms = std::fs::metadata(&path).expect("metadata").permissions();
    assert_eq!(perms.mode() & 0o7777, 0o600);
}

#[test]
fn pty_change_with_default_kdf_writes_section_4_4_defaults_on_disk() {
    // §5 + §4.4: when no `--kdf-*` flags are passed, `passphrase
    // change` must re-encrypt under the §4.4 production defaults
    // (`m_kib = 65_536`, `t = 3`, `p = 1`). The companion test at
    // `pty_change_on_open_encrypted_vault_succeeds_and_rotates_salt_under_requested_kdf_params`
    // covers the custom-params path; this one covers the no-flags
    // path. The encrypted fixture itself is created with the §4.4
    // minimum params so the unlock derivation stays cheap; only the
    // new-key derivation runs at defaults.
    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(&path, "old-secret");

    let mut pty = Pty::spawn(
        ["--vault", path.to_str().unwrap(), "passphrase", "change"],
        &[],
    );
    pty.expect(PROMPT_UNLOCK);
    pty.send_line("old-secret");
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("new-secret");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("new-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_contains("Re-encrypted vault.");

    let after = std::fs::read(&path).expect("read post-change vault");
    assert!(after.len() >= 64, "encrypted header should be ≥ 64 bytes");
    assert_eq!(&after[..8], PALADIN_MAGIC);
    assert_eq!(after[8], 1, "format_ver");
    assert_eq!(after[9], 1, "mode == encrypted");
    assert_eq!(after[10], 1, "kdf_id == Argon2id");
    let m_kib = u32::from_le_bytes(after[11..15].try_into().unwrap());
    let t = u32::from_le_bytes(after[15..19].try_into().unwrap());
    let p = u32::from_le_bytes(after[19..23].try_into().unwrap());
    assert_eq!(m_kib, 65_536, "default m_kib must match §4.4 (64 MiB)");
    assert_eq!(t, 3, "default t must match §4.4");
    assert_eq!(p, 1, "default p must match §4.4");
    assert_eq!(after[39], 1, "aead_id == XChaCha20-Poly1305");

    let perms = std::fs::metadata(&path).expect("metadata").permissions();
    assert_eq!(perms.mode() & 0o7777, 0o600);
}

#[test]
fn pty_set_under_json_keeps_streams_clean_after_prompts_consume_dev_tty() {
    // §5 strict-mode rule: under `--json`, `paladin passphrase set`
    // writes **only** the success JSON envelope to stdout and nothing
    // to stderr. Prompt strings are written to `/dev/tty` via the
    // CLI's `prompt::write_tty_line` helper (see `prompt.rs`), so
    // even when `/dev/tty` is rerouted to a controlling-terminal PTY
    // for testing, the prompt bytes never leak into stdout / stderr.
    //
    // The shared `Pty` harness muxes the PTY slave to all three child
    // descriptors, so this test verifies the stream-cleanliness
    // contract by slicing the merged transcript at the last prompt
    // boundary: between the prompts and the JSON envelope only
    // whitespace (the `rpassword` post-input newline) may appear, and
    // text-mode artifacts like `Encrypted vault.` or the
    // plaintext-storage advisory must be absent.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let mut pty = Pty::spawn(
        [
            "--json",
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

    // Slice the transcript at the last prompt boundary; the suffix is
    // whatever the child wrote after `rpassword` finished consuming
    // the confirmation entry. Under `--json`, that suffix must be
    // (whitespace) + JSON envelope + (whitespace).
    let transcript = &exit.transcript;
    let cut = transcript
        .rfind(PROMPT_CONFIRM)
        .expect("PROMPT_CONFIRM must appear in transcript")
        + PROMPT_CONFIRM.len();
    let suffix = &transcript[cut..];

    let trimmed = suffix.trim();
    let envelope: Value = serde_json::from_str(trimmed).unwrap_or_else(|err| {
        panic!(
            "post-prompt suffix must parse as the JSON success envelope; \
             got {trimmed:?}: {err}"
        )
    });
    // §5 success envelope shape for `passphrase set` is
    // `{ "ok": true, "status": ... }`.
    assert_eq!(envelope["ok"], serde_json::json!(true));
    assert!(
        envelope.get("status").is_some(),
        "passphrase-set envelope must carry `status`, got {envelope}"
    );

    // No text-mode artifacts may appear anywhere in the stream — the
    // text-mode success line, the plaintext-storage advisory, and any
    // `warning:` prefix would all leak under `--json` if the
    // suppression rule regressed.
    exit.assert_transcript_lacks("Encrypted vault.");
    exit.assert_transcript_lacks("Plaintext");
    exit.assert_transcript_lacks("warning:");
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

#[test]
fn pty_remove_on_open_encrypted_vault_confirms_then_decrypts_to_plaintext() {
    // §5: text-mode `passphrase remove` (no `--yes`) on an encrypted
    // vault prints the plaintext-storage advisory, prompts for the
    // destructive confirmation, *then* prompts for the unlock
    // passphrase. Only after the literal `yes` (and a successful
    // unlock) does the CLI re-save the vault as plaintext and print
    // `Decrypted vault to plaintext.`. The confirm-before-unlock
    // ordering means a declined or no-`/dev/tty` confirmation never
    // asks the user for the unlock passphrase first — see L726.
    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(&path, "the-secret");

    // Pre-state: file is encrypted.
    let before = std::fs::read(&path).expect("read pre-remove vault");
    assert_eq!(before[9], 1, "fixture should be encrypted");

    let mut pty = Pty::spawn(
        ["--vault", path.to_str().unwrap(), "passphrase", "remove"],
        &[],
    );
    // The plaintext-storage advisory must land *before* the
    // destructive prompt so the user sees the warning before deciding.
    // `Pty::expect` on the prompt also captures the bytes preceding
    // it into the transcript, so the post-exit
    // `assert_transcript_contains("Plaintext storage keeps")` covers
    // ordering as well as presence.
    pty.expect(PROMPT_REMOVE_CONFIRM);
    pty.send_line("yes");
    pty.expect(PROMPT_UNLOCK);
    pty.send_line("the-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_contains("Plaintext storage keeps account secrets unencrypted");
    exit.assert_transcript_contains("Decrypted vault to plaintext.");

    // Post-state on disk: now plaintext, magic + format_ver intact,
    // mode flipped to 0, file mode preserved at `0o600`.
    let after = std::fs::read(&path).expect("read post-remove vault");
    assert!(after.len() >= 10, "header too short: {} bytes", after.len());
    assert_eq!(&after[..8], PALADIN_MAGIC);
    assert_eq!(after[8], 1, "format_ver");
    assert_eq!(after[9], 0, "mode == plaintext");

    let perms = std::fs::metadata(&path).expect("metadata").permissions();
    assert_eq!(perms.mode() & 0o7777, 0o600);
}

#[test]
fn pty_remove_with_yes_skips_only_confirmation_not_unlock_prompt() {
    // §5: `--yes` skips the destructive confirmation but **not** the
    // unlock prompt. On an encrypted vault, `passphrase remove --yes`
    // must still prompt for the unlock passphrase via `/dev/tty`
    // before re-saving as plaintext. Text-mode `--yes` does not
    // suppress the plaintext-storage advisory (the strict-mode
    // suppression rule applies only under `--json`); it skips only
    // the confirmation prompt.
    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(&path, "the-secret");

    // Pre-state: file is encrypted.
    let before = std::fs::read(&path).expect("read pre-remove vault");
    assert_eq!(before[9], 1, "fixture should be encrypted");

    let mut pty = Pty::spawn(
        [
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "remove",
            "--yes",
        ],
        &[],
    );
    // No destructive confirmation prompt — `--yes` opts in. The unlock
    // prompt is still required to decrypt the source vault before
    // re-saving as plaintext.
    pty.expect(PROMPT_UNLOCK);
    pty.send_line("the-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    // Text-mode `--yes` skips only the confirmation, so the
    // plaintext-storage advisory still appears on stderr and the
    // success line still prints.
    exit.assert_transcript_contains("Plaintext storage keeps account secrets unencrypted");
    exit.assert_transcript_contains("Decrypted vault to plaintext.");
    // The destructive-confirmation prompt must never appear.
    exit.assert_transcript_lacks(PROMPT_REMOVE_CONFIRM);

    // Post-state on disk: now plaintext, magic + format_ver intact,
    // mode flipped to 0, file mode preserved at `0o600`.
    let after = std::fs::read(&path).expect("read post-remove vault");
    assert!(after.len() >= 10, "header too short: {} bytes", after.len());
    assert_eq!(&after[..8], PALADIN_MAGIC);
    assert_eq!(after[8], 1, "format_ver");
    assert_eq!(after[9], 0, "mode == plaintext");

    let perms = std::fs::metadata(&path).expect("metadata").permissions();
    assert_eq!(perms.mode() & 0o7777, 0o600);
}

#[test]
fn pty_remove_without_dev_tty_surfaces_io_error_confirmation_prompt() {
    // §5: when `/dev/tty` cannot be opened (no controlling terminal),
    // text-mode `passphrase remove` (no `--yes`) must surface
    // `io_error` `operation: "confirmation_prompt"` — the destructive
    // confirmation fires *before* the unlock prompt (see L724), so
    // the user is never asked for the unlock passphrase. Drive the
    // path by exec-ing the binary through `setsid(1)` so the child is
    // a fresh session leader and any `open("/dev/tty")` returns ENXIO.
    use std::process::Stdio;

    use common::paladin_command_without_tty;

    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(&path, "the-secret");

    let output = paladin_command_without_tty()
        .args(["--vault", path.to_str().unwrap(), "passphrase", "remove"])
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
    assert!(
        stderr.starts_with("paladin: ") || stderr.contains("\npaladin: "),
        "expected `paladin:` text-mode prefix on the error line, got {stderr:?}",
    );
    // Asserting the `confirmation_prompt` operation tag verbatim
    // guards the §5 ordering: if a future refactor moves the unlock
    // ahead of the confirmation, this test will start surfacing
    // `passphrase_prompt` instead and fail loudly.
    assert!(
        stderr.contains("I/O error during confirmation_prompt"),
        "expected `confirmation_prompt` operation tag in the rendered \
         text, got {stderr:?}",
    );
    // Vault on disk must be untouched (still encrypted).
    let after = std::fs::read(&path).expect("read vault");
    assert_eq!(
        after[9], 1,
        "vault must remain encrypted on confirm failure"
    );
}

// --- Fault-injection PTY tests (gated on `test-hooks`) -------------------

#[cfg(feature = "test-hooks")]
mod fault_inject {
    use super::*;

    /// `passphrase set` on a plaintext vault is the cheapest fault
    /// fixture for `passphrase` mutations: no unlock derivation,
    /// minimum §4.4 KDF params for the new key, and a single rename
    /// at commit time. The fault hook lives in `Vault::save`, which
    /// is shared across `set` / `change` / `remove`, so covering one
    /// subcommand verifies the wiring for all three.
    #[test]
    fn pty_set_pre_commit_surfaces_save_not_committed_with_committed_false() {
        // §5: a `pre_commit` save fault on a `passphrase` mutation
        // must surface the `save_not_committed` envelope with
        // `committed: false`. The mutation is `passphrase set` on a
        // plaintext fixture; minimum KDF params keep the Argon2
        // derivation cheap so the test is dominated by the rename
        // path that the fault hook intercepts.
        let (_dir, path) = fresh_vault_path();
        create_empty_plaintext_vault(&path);
        let before = std::fs::read(&path).expect("read pre-set vault");

        let mut pty = Pty::spawn(
            [
                "--json",
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
            &[("PALADIN_FAULT_INJECT", "pre_commit")],
        );
        pty.expect(PROMPT_NEW_PASSPHRASE);
        pty.send_line("hunter2-newpass");
        pty.expect(PROMPT_CONFIRM);
        pty.send_line("hunter2-newpass");
        let exit = pty.wait_for_exit();
        exit.assert_exit(1);
        let env = extract_json(&exit.transcript).expect("error envelope must appear in transcript");
        assert_eq!(env["error_kind"], serde_json::json!("save_not_committed"));
        assert_eq!(env["committed"], serde_json::json!(false));

        // §8 rollback: the on-disk vault must remain byte-identical
        // when the pre-commit rename never happened. `passphrase set`
        // does not rotate the existing file, so there is no
        // `backup_path` field on this envelope (unlike `init --force`).
        let after = std::fs::read(&path).expect("read post-fault vault");
        assert_eq!(
            after, before,
            "plaintext vault must remain byte-identical after pre-commit fault",
        );
    }

    #[test]
    fn pty_set_post_commit_surfaces_save_durability_unconfirmed() {
        // §5: a `post_commit` save fault on a `passphrase` mutation
        // must surface the `save_durability_unconfirmed` envelope —
        // the rename succeeded, only the post-commit `fsync` of the
        // parent directory failed. `SaveDurabilityUnconfirmed` is a
        // unit variant in core, so the envelope carries no extra
        // fields beyond `error_kind` (mirrors `cli_init.rs::
        // fault_inject::pty_init_force_post_commit_surfaces_save_durability_unconfirmed`).
        // The on-disk side proves the rename committed: the primary
        // file is now encrypted (mode byte flipped to 1).
        let (_dir, path) = fresh_vault_path();
        create_empty_plaintext_vault(&path);

        let mut pty = Pty::spawn(
            [
                "--json",
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
            &[("PALADIN_FAULT_INJECT", "post_commit")],
        );
        pty.expect(PROMPT_NEW_PASSPHRASE);
        pty.send_line("hunter2-newpass");
        pty.expect(PROMPT_CONFIRM);
        pty.send_line("hunter2-newpass");
        let exit = pty.wait_for_exit();
        exit.assert_exit(1);
        let env = extract_json(&exit.transcript).expect("error envelope must appear in transcript");
        assert_eq!(
            env["error_kind"],
            serde_json::json!("save_durability_unconfirmed"),
        );

        // The post-commit fault fires after the primary rename, so
        // the on-disk file is the new encrypted vault (mode byte
        // flipped to 1). The rename actually landed even though the
        // parent-directory `fsync` could not be confirmed.
        let after = std::fs::read(&path).expect("read post-fault vault");
        assert_eq!(&after[..8], PALADIN_MAGIC);
        assert_eq!(after[9], 1, "primary rename must have committed");
    }

    /// Pull the JSON envelope out of a PTY transcript. Under `--json`
    /// the error envelope is one document on stderr (and stdout is
    /// empty), so the transcript ends with the JSON document followed
    /// by a newline. Mirrors `cli_init.rs::fault_inject::extract_json`.
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
