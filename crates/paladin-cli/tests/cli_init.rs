// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin init`.
//!
//! No-prompt error paths (KDF flag validation, the `vault_exists`
//! pre-check, KDF-vs-`vault_exists` precedence, the `Propagate(_)`
//! branch of `classify_init_precheck`) live in plain `#[test]`
//! functions. Prompt-driven flows — empty / non-empty passphrase,
//! `--force` clobber, custom-KDF-on-disk verification, the
//! plaintext-storage advisory, and the unsafe-parent-dir
//! `unsafe_permissions` rendering — drive the CLI through the
//! shared `tests/common/mod.rs` PTY harness so writes to `/dev/tty`
//! and `rpassword` reads round-trip end to end.
//!
//! The fault-injection tests (`init --force` under
//! `PALADIN_FAULT_INJECT={pre,post}_commit`) are gated on the
//! `paladin-cli/test-hooks` cargo feature so the hook is compiled
//! into the binary.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use paladin_core::{Argon2Params, EncryptionOptions, Store, VaultInit};
use secrecy::SecretString;
use serde_json::Value;

use common::{fresh_vault_path, paladin, write_existing_plaintext_vault, Pty};

// --- Local fixture helpers --------------------------------------------------

/// Magic bytes whose last byte is `\0` (matching `paladin-core`'s
/// `MAGIC` constant) so `inspect` parses the file as a real Paladin
/// header rather than rejecting the magic.
const PALADIN_MAGIC: &[u8; 8] = b"PALADIN\0";

/// Write a 16-byte file whose magic does **not** match
/// `PALADIN\0`. `inspect` rejects it as `invalid_header` →
/// `InitPrecheck::Existing`.
fn write_invalid_header_vault(path: &Path) {
    let bytes = [0u8; 16];
    std::fs::write(path, bytes).expect("write invalid-header vault");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
}

/// Write a 16-byte file with valid magic and `format_ver = 99` so
/// `inspect` rejects it as `unsupported_format_version` →
/// `InitPrecheck::Existing`.
fn write_unsupported_format_version_vault(path: &Path) {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(PALADIN_MAGIC);
    bytes.push(99); // format_ver — anything != 1
    bytes.push(0); // mode (irrelevant once the version check trips)
    bytes.extend_from_slice(&[0u8; 6]); // padding
    std::fs::write(path, &bytes).expect("write unsupported-format-version vault");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
}

/// Write a real encrypted Paladin vault at `path` with the §4.4
/// minimum Argon2 params (`m=8 MiB, t=1, p=1`) so test setup is
/// fast. The §4.3 perm bits are applied by `Store::create`.
fn write_existing_encrypted_vault(path: &Path, passphrase: &str) {
    let argon = Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    let init = VaultInit::Encrypted(
        EncryptionOptions::with_params(SecretString::from(passphrase.to_string()), argon)
            .expect("encryption options"),
    );
    let (vault, store) = Store::create(path, init).expect("create encrypted vault");
    vault.save(&store).expect("save encrypted vault");
}

/// Make `path` unreadable to the current user so the next `inspect`
/// call surfaces `io_error { operation: "read_vault_file" }` and
/// classifies as `InitPrecheck::Propagate`.
fn write_unreadable_vault(path: &Path) {
    std::fs::write(path, b"unreadable").expect("write file before chmod");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
}

// --- Existing no-prompt tests (KDF validation + vault_exists Plaintext) ----

#[test]
fn json_invalid_kdf_memory_mib_rejects_with_validation_error() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
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
fn json_overflow_kdf_memory_mib_rejects_with_overflow_reason() {
    let (_dir, path) = fresh_vault_path();
    // u32::MAX / 1024 == 4_194_303, so 4_194_304 overflows on `* 1024`.
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--kdf-memory-mib",
            "4194304",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(value["field"], serde_json::json!("kdf-memory-mib"));
    assert_eq!(value["reason"], serde_json::json!("overflow"));
}

#[test]
fn json_kdf_time_below_floor_rejects_with_kdf_params_out_of_bounds() {
    let (_dir, path) = fresh_vault_path();
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
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
}

#[test]
fn json_existing_vault_without_force_rejects_with_vault_exists() {
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "init"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_exists"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_kdf_validation_wins_over_vault_exists_precedence() {
    // Existing vault + invalid KDF integer: the KDF parse fires first,
    // before `inspect` runs the existence pre-check, so the user sees
    // `validation_error` rather than `vault_exists`. Locked by the
    // §5 ordering rule in docs/IMPLEMENTATION_PLAN_02_CLI.md.
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
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
fn json_kdf_validation_wins_over_vault_exists_with_force() {
    // Same precedence rule applies even with `--force`: the KDF parser
    // fires before the pre-check, so the user sees the validation
    // error rather than the warning + clobber path.
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let assert = paladin()
        .args([
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--force",
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
fn text_existing_vault_without_force_emits_paladin_vault_exists_message() {
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let assert = paladin()
        .args(["--vault", path.to_str().unwrap(), "init"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.starts_with("paladin: "),
        "expected paladin: prefix, got {stderr:?}"
    );
    assert!(
        stderr.to_lowercase().contains("vault"),
        "expected vault_exists wording, got {stderr:?}"
    );
}

// --- New: vault_exists pre-check covers all `Existing` shapes -------------

#[test]
fn json_existing_encrypted_vault_without_force_rejects_with_vault_exists() {
    let (_dir, path) = fresh_vault_path();
    write_existing_encrypted_vault(&path, "shape-only-passphrase");
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "init"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_exists"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_existing_invalid_header_file_without_force_rejects_with_vault_exists() {
    let (_dir, path) = fresh_vault_path();
    write_invalid_header_vault(&path);
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "init"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_exists"));
}

#[test]
fn json_existing_unsupported_format_version_rejects_with_vault_exists() {
    let (_dir, path) = fresh_vault_path();
    write_unsupported_format_version_vault(&path);
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "init"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("vault_exists"));
}

#[test]
fn json_init_propagate_io_error_does_not_rewrite_as_vault_exists() {
    // mode-000 file: `inspect` fails to read it and surfaces an
    // `io_error`. `classify_init_precheck` maps that to
    // `Propagate(...)`, which the CLI must forward verbatim — never
    // rewrite as `vault_exists`. Locked by docs/IMPLEMENTATION_PLAN_02_CLI.md
    // "Vault interaction pattern".
    let (_dir, path) = fresh_vault_path();
    write_unreadable_vault(&path);
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "init"])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    // Restore perms so the TempDir destructor can clean up.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("restore perms for cleanup");
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error_kind"], serde_json::json!("io_error"));
    assert_eq!(
        value["operation"],
        serde_json::json!("read_vault_file"),
        "io_error.operation should be the inspect read tag, got {value}",
    );
}

// --- New: PTY happy paths ---------------------------------------------------

const PROMPT_NEW_PASSPHRASE: &str = "New passphrase";
const PROMPT_CONFIRM: &str = "Confirm passphrase";

#[test]
fn pty_text_empty_passphrase_creates_plaintext_with_warning() {
    let (dir, path) = fresh_vault_path();
    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "init"], &[]);
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_contains("Plaintext storage keeps account secrets unencrypted");
    exit.assert_transcript_contains("Created");

    // §4.3: file is `0600`, parent dir is `0700`, header is plaintext.
    let file_meta = std::fs::metadata(&path).expect("vault file exists");
    assert_eq!(file_meta.permissions().mode() & 0o7777, 0o600);
    let dir_meta = std::fs::metadata(dir.path()).expect("vault dir exists");
    assert_eq!(dir_meta.permissions().mode() & 0o7777, 0o700);
    let header = std::fs::read(&path).expect("read vault");
    assert!(
        header.len() >= 10,
        "header too short: {} bytes",
        header.len()
    );
    assert_eq!(&header[..8], PALADIN_MAGIC);
    assert_eq!(header[8], 1, "format_ver");
    assert_eq!(header[9], 0, "mode == plaintext");
}

#[test]
fn pty_non_empty_passphrase_creates_encrypted_vault() {
    let (_dir, path) = fresh_vault_path();
    let mut pty = Pty::spawn(
        [
            "--vault",
            path.to_str().unwrap(),
            "init",
            // Use the §4.4 minimum so Argon2id is fast in CI.
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
    pty.send_line("hunter2-encrypted");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("hunter2-encrypted");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    // No plaintext-storage advisory on the encrypted path.
    exit.assert_transcript_lacks("Plaintext storage keeps");

    let header = std::fs::read(&path).expect("read encrypted vault");
    assert!(header.len() >= 64, "encrypted header should be ≥ 64 bytes");
    assert_eq!(&header[..8], PALADIN_MAGIC);
    assert_eq!(header[9], 1, "mode == encrypted");
    assert_eq!(header[10], 1, "kdf_id == Argon2id");
    let m_kib = u32::from_le_bytes(header[11..15].try_into().unwrap());
    let t = u32::from_le_bytes(header[15..19].try_into().unwrap());
    let p = u32::from_le_bytes(header[19..23].try_into().unwrap());
    assert_eq!(m_kib, 8 * 1024);
    assert_eq!(t, 1);
    assert_eq!(p, 1);
    assert_eq!(header[39], 1, "aead_id == XChaCha20-Poly1305");
}

#[test]
fn pty_confirmation_mismatch_rejects_before_mutation() {
    let (_dir, path) = fresh_vault_path();
    let mut pty = Pty::spawn(
        [
            "--vault",
            path.to_str().unwrap(),
            "init",
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
    pty.send_line("first-entry");
    pty.expect(PROMPT_CONFIRM);
    pty.send_line("DIFFERENT-entry");
    let exit = pty.wait_for_exit();
    exit.assert_exit(1);
    exit.assert_transcript_contains("paladin: ");
    // Vault file was never created because the mismatch fires before
    // `Store::create`.
    assert!(!path.exists(), "vault file should not exist after mismatch");
}

#[test]
fn pty_force_rotates_paladin_existing_into_bak() {
    let (_dir, path) = fresh_vault_path();
    write_existing_plaintext_vault(&path);
    let bak = path.with_file_name("vault.bin.bak");
    // A pre-existing `.bak` (sentinel content) lets us assert the
    // §5 staged clobber overwrites it.
    std::fs::write(&bak, b"sentinel-bak-must-be-overwritten").expect("write sentinel .bak");
    std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600))
        .expect("chmod sentinel .bak 0600");
    let original = std::fs::read(&path).expect("read original vault");

    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "init", "--force"], &[]);
    pty.expect("rotated to");
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);

    // The new primary is a fresh plaintext vault; the rotated
    // backup is the **verbatim** original bytes (overwriting the
    // sentinel that was there).
    let bak_now = std::fs::read(&bak).expect("read .bak after force");
    assert_eq!(bak_now, original, "backup should hold the original bytes");
    assert_ne!(bak_now, b"sentinel-bak-must-be-overwritten");
    let new_primary = std::fs::read(&path).expect("read primary after force");
    assert_eq!(&new_primary[..8], PALADIN_MAGIC);
    assert_eq!(new_primary[9], 0, "new primary is plaintext");
}

#[test]
fn pty_force_rotates_non_paladin_existing_into_bak() {
    // §5: `create_force` rotates the old file verbatim regardless of
    // its content, including non-Paladin garbage. The clobber warning
    // also fires because `classify_init_precheck` maps
    // `InvalidHeader` to `Existing`.
    let (_dir, path) = fresh_vault_path();
    let original = b"not-a-paladin-vault-at-all-just-bytes" as &[u8];
    std::fs::write(&path, original).expect("write non-paladin file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    let bak = path.with_file_name("vault.bin.bak");

    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "init", "--force"], &[]);
    pty.expect("rotated to");
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);

    let bak_now = std::fs::read(&bak).expect("read .bak after force");
    assert_eq!(bak_now, original);
}

#[test]
fn pty_force_clobber_warning_suppressed_on_clear() {
    // No existing file → `Clear` → no force warning, even with
    // `--force`. Locked by docs/IMPLEMENTATION_PLAN_02_CLI.md "init force
    // checked".
    let (_dir, path) = fresh_vault_path();
    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "init", "--force"], &[]);
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_lacks("rotated to");
    exit.assert_transcript_lacks("any prior backup");
}

#[test]
fn pty_custom_kdf_flags_unused_with_empty_passphrase() {
    // Empty first entry on `init` selects plaintext storage. Custom
    // KDF flags are still parsed and validated (so an out-of-range
    // value would have rejected before the prompt) but their values
    // are unused — the on-disk file is plaintext.
    let (_dir, path) = fresh_vault_path();
    let mut pty = Pty::spawn(
        [
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--kdf-memory-mib",
            "16",
            "--kdf-time",
            "2",
            "--kdf-parallelism",
            "1",
        ],
        &[],
    );
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    let header = std::fs::read(&path).expect("read vault");
    assert_eq!(header[9], 0, "vault is plaintext (mode == 0)");
}

#[test]
fn pty_init_unsafe_parent_dir_surfaces_unsafe_permissions_with_chmod_hint() {
    // Loosen the parent dir to `0750` so `enforce_dir_perms` rejects
    // it. The CLI prompts first (since `inspect` returns `Missing`
    // and skips perm checks), then `Store::create` fires the perm
    // check and surfaces `unsafe_permissions { vault_dir }`. Text mode
    // renders the `chmod 0700 <dir>` repair hint via
    // `format_unsafe_permissions`.
    let (dir, path) = fresh_vault_path();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750))
        .expect("loosen parent dir to 0750");
    let mut pty = Pty::spawn(["--vault", path.to_str().unwrap(), "init"], &[]);
    pty.expect(PROMPT_NEW_PASSPHRASE);
    pty.send_line("");
    let exit = pty.wait_for_exit();
    // Restore parent mode so TempDir cleanup succeeds.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore parent 0700");
    exit.assert_exit(1);
    exit.assert_transcript_contains("paladin: unsafe permissions");
    // Text mode uses the human-readable subject label
    // (`format_unsafe_permissions` → "vault directory") so the user
    // sees plain English; the §5 wire format `subject: "vault_dir"`
    // is asserted on `--json` paths in `cli_errors_json.rs`.
    exit.assert_transcript_contains("vault directory");
    exit.assert_transcript_contains("0750");
    // §4.3 / docs/IMPLEMENTATION_PLAN_02_CLI.md "format_unsafe_permissions":
    // the chmod repair hint is rendered for text mode so users get a
    // copy-pasteable fix.
    let dir_str = dir.path().to_string_lossy();
    let expected_hint = format!("chmod 0700 {dir_str}");
    exit.assert_transcript_contains(&expected_hint);
}

// --- Fault-injection PTY tests (gated on `test-hooks`) -------------------

#[cfg(feature = "test-hooks")]
mod fault_inject {
    use super::*;

    #[test]
    fn pty_init_force_pre_commit_surfaces_save_not_committed_with_backup_path() {
        // Existing Paladin file → `--force` rotates it to `.bak`,
        // then the staged primary rename trips the `pre_commit` fault
        // hook. §5 requires the resulting `save_not_committed` envelope
        // to carry `committed: false` and the `backup_path` so the
        // user can recover the rotated file.
        let (_dir, path) = fresh_vault_path();
        write_existing_plaintext_vault(&path);
        let bak = path.with_file_name("vault.bin.bak");

        let mut pty = Pty::spawn(
            [
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "init",
                "--force",
            ],
            &[("PALADIN_FAULT_INJECT", "pre_commit")],
        );
        // Under `--json`, the warning is suppressed (caller opted in
        // with `--force`) so we go straight to the prompt.
        pty.expect(PROMPT_NEW_PASSPHRASE);
        pty.send_line("");
        let exit = pty.wait_for_exit();
        exit.assert_exit(1);
        let stderr_json =
            extract_json(&exit.transcript).expect("error envelope must appear in transcript");
        assert_eq!(
            stderr_json["error_kind"],
            serde_json::json!("save_not_committed")
        );
        assert_eq!(stderr_json["committed"], serde_json::json!(false));
        let bp = stderr_json["backup_path"]
            .as_str()
            .expect("backup_path field required after force rotation");
        assert_eq!(Path::new(bp), bak);
    }

    #[test]
    fn pty_init_force_post_commit_surfaces_save_durability_unconfirmed() {
        let (_dir, path) = fresh_vault_path();
        write_existing_plaintext_vault(&path);

        let mut pty = Pty::spawn(
            [
                "--json",
                "--vault",
                path.to_str().unwrap(),
                "init",
                "--force",
            ],
            &[("PALADIN_FAULT_INJECT", "post_commit")],
        );
        pty.expect(PROMPT_NEW_PASSPHRASE);
        pty.send_line("");
        let exit = pty.wait_for_exit();
        exit.assert_exit(1);
        let stderr_json =
            extract_json(&exit.transcript).expect("error envelope must appear in transcript");
        assert_eq!(
            stderr_json["error_kind"],
            serde_json::json!("save_durability_unconfirmed"),
        );
    }

    /// Pull the JSON envelope out of a PTY transcript. Under `--json`
    /// the error envelope is one document on stderr (and stdout is
    /// empty), so the transcript ends with the JSON document followed
    /// by a newline. We scan the transcript for the last `{ ... }`
    /// block by locating the final `}` and walking back to its
    /// matching `{`.
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
