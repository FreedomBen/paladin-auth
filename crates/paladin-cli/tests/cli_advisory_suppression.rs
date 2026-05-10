// SPDX-License-Identifier: AGPL-3.0-or-later

//! Centralized cross-command sweep for the §5 strict-mode advisory
//! suppression rule under `--json`.
//!
//! Per `IMPLEMENTATION_PLAN_02_CLI.md` "Output", every text-mode
//! advisory must be suppressed when the caller has opted in via
//! `--force` (`init --force` clobber warning), an empty `init`
//! passphrase (plaintext-storage advisory), `--yes` (`passphrase
//! remove` plaintext-storage advisory), or `--plaintext`
//! (plaintext-export advisory). The corresponding warning strings
//! come from `paladin_core::format_init_force_warning`,
//! `format_plaintext_storage_warning`, and
//! `format_plaintext_export_warning`. This sweep asserts that none
//! of those strings ever appear on stdout / stderr (or any merged
//! PTY transcript) under `--json`.
//!
//! Per-command happy-path tests live in `cli_init.rs`,
//! `cli_passphrase.rs`, and `cli_export.rs`. This file exists to
//! lock the cross-command rule in one place so a regression in any
//! single command is caught here too.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use paladin_core::{Argon2Params, EncryptionOptions, Store, VaultInit};
use secrecy::SecretString;
use serde_json::Value;
use tempfile::TempDir;

use common::Pty;

/// Substring from `format_init_force_warning(path)` that uniquely
/// identifies the clobber advisory; pinning the substring keeps this
/// sweep stable across stylistic edits to the warning wording.
const ADVISORY_INIT_FORCE: &str = "This will overwrite the existing vault";

/// Substring from `format_plaintext_storage_warning()`. The advisory
/// fires from `init` (empty passphrase) and `passphrase remove`
/// (text mode, encrypted source); both are suppressed under `--json`.
const ADVISORY_PLAINTEXT_STORAGE: &str = "Plaintext storage keeps account secrets unencrypted";

/// Substring from `format_plaintext_export_warning()`.
const ADVISORY_PLAINTEXT_EXPORT: &str = "Plaintext export writes account secrets unencrypted";

/// §5 prompt-string prefix shared by `init`'s
/// `"New passphrase (empty for plaintext): "` and
/// `passphrase set`'s `"New passphrase: "`. Using the common prefix
/// keeps this sweep tolerant of the slight wording difference.
const PROMPT_NEW_PASSPHRASE_PREFIX: &str = "New passphrase";
const PROMPT_UNLOCK: &str = "Vault passphrase: ";

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
/// parameters so `inspect` classifies it as `Encrypted` without
/// hand-rolling header bytes. Min KDF params keep CI fast.
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

fn assert_lacks_advisory(label: &str, haystack: &str, advisory: &str) {
    assert!(
        !haystack.contains(advisory),
        "{label} must not contain advisory {advisory:?}; got: {haystack:?}"
    );
}

#[test]
fn json_init_empty_passphrase_suppresses_plaintext_storage_advisory() {
    // §5: an empty first passphrase entry on `paladin init` selects
    // plaintext storage. Text mode prints
    // `format_plaintext_storage_warning()`; under `--json` the
    // advisory is suppressed because the caller opted in by entering
    // an empty passphrase.
    let (_dir, path) = fresh_vault_path();

    let mut pty = Pty::spawn(["--json", "--vault", path.to_str().unwrap(), "init"], &[]);
    pty.expect(PROMPT_NEW_PASSPHRASE_PREFIX);
    pty.send_line(""); // empty → select plaintext mode
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_lacks(ADVISORY_PLAINTEXT_STORAGE);
}

#[test]
fn json_init_force_suppresses_clobber_advisory() {
    // §5: `init --force` against an existing vault prints
    // `format_init_force_warning(path)` in text mode before
    // prompting; under `--json` the advisory is suppressed because
    // the caller opted in with `--force`.
    let (_dir, path) = fresh_vault_path();
    create_empty_plaintext_vault(&path);

    let mut pty = Pty::spawn(
        [
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "init",
            "--force",
        ],
        &[],
    );
    pty.expect(PROMPT_NEW_PASSPHRASE_PREFIX);
    pty.send_line(""); // empty → plaintext for speed; no Argon2 needed
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_lacks(ADVISORY_INIT_FORCE);
    // Also verify the path-mention substring (defensive).
    exit.assert_transcript_lacks("rotated to");
}

#[test]
fn json_passphrase_remove_yes_suppresses_plaintext_storage_advisory() {
    // §5: text-mode `passphrase remove` prints
    // `format_plaintext_storage_warning()` after verifying the
    // encrypted starting state and before the destructive
    // confirmation. `--yes` skips the confirmation but in text mode
    // the advisory still appears so the caller sees what they opted
    // in to. Under `--json`, `--yes` is required at parse time and
    // the advisory is suppressed because the caller opted in.
    let (_dir, path) = fresh_vault_path();
    create_encrypted_vault(&path, "the-secret");

    let mut pty = Pty::spawn(
        [
            "--json",
            "--vault",
            path.to_str().unwrap(),
            "passphrase",
            "remove",
            "--yes",
        ],
        &[],
    );
    pty.expect(PROMPT_UNLOCK);
    pty.send_line("the-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);
    exit.assert_transcript_lacks(ADVISORY_PLAINTEXT_STORAGE);
}

#[test]
fn json_export_plaintext_suppresses_unencrypted_secrets_advisory() {
    // §5: `export --plaintext` prints
    // `format_plaintext_export_warning()` to stderr in text mode
    // before writing unencrypted secrets. Under `--json` the advisory
    // is suppressed because the caller opted in with `--plaintext`.
    // No PTY needed — a plaintext source vault has no unlock prompt.
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
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert_lacks_advisory("stderr", stderr, ADVISORY_PLAINTEXT_EXPORT);
    assert_lacks_advisory("stdout", stdout, ADVISORY_PLAINTEXT_EXPORT);
    // Sanity: the §5 success envelope is on stdout.
    let env: Value = serde_json::from_str(stdout.trim()).expect("stdout is JSON envelope");
    assert_eq!(env["written"], serde_json::json!(out.to_str().unwrap()));
}
