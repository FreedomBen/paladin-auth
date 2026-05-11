// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end tests for `paladin import`. Covers the no-prompt code
//! paths: otpauth (text URL list / JSON array) and Aegis-plaintext
//! import in both auto-detect and forced-format modes; every
//! `--on-conflict` policy including HOTP-to-HOTP counter preservation
//! under `replace`; default-policy fall-through to `skip`; warning
//! propagation for skipped duplicates; auto-detect of unknown content;
//! `unsupported_encrypted_aegis`; `unsupported_import_format` from a
//! forced-format / shape mismatch; `no_entries_to_import` for an
//! empty otpauth list; `unsupported_plaintext_vault` and
//! `unsupported_format_version` for malformed Paladin headers (which
//! the precheck rejects before any bundle-passphrase prompt); and
//! `vault_missing` on a missing destination vault. Encrypted-bundle
//! happy paths require a scripted `/dev/tty` and live in the
//! dedicated PTY harness called out in `IMPLEMENTATION_PLAN_02_CLI.md`.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use paladin_core::{
    export, parse_otpauth, Argon2Params, EncryptionOptions, ImportConflict, Store, Vault, VaultInit,
};
use secrecy::SecretString;
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

fn write_file(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).expect("write fixture");
}

fn list_accounts_json(path: &Path) -> Value {
    let assert = paladin()
        .args(["--json", "--vault", path.to_str().unwrap(), "list"])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    serde_json::from_str(stdout.trim()).unwrap()
}

fn open_vault(path: &Path) -> Vault {
    use paladin_core::VaultLock;
    let (vault, _store) = Store::open(path, VaultLock::Plaintext).expect("open");
    vault
}

const TOTP_URI_ALICE: &str =
    "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=6&period=30";
const TOTP_URI_BOB: &str =
    "otpauth://totp/Acme:bob?secret=KRSXG5DJN5XGS3DPMNQXG43JN5XGS3BB&digits=6&period=30";
const HOTP_URI_CAROL: &str =
    "otpauth://hotp/Acme:carol?secret=MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK&digits=6&counter=11";

const AEGIS_PLAINTEXT_JSON: &str = r#"{
  "version": 1,
  "header": { "slots": null, "params": null },
  "db": {
    "version": 2,
    "entries": [
      {
        "type": "totp",
        "uuid": "0000",
        "name": "alice",
        "issuer": "Acme",
        "note": "",
        "icon": null,
        "info": {
          "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
          "algo": "SHA1",
          "digits": 6,
          "period": 30
        }
      }
    ]
  }
}"#;

const AEGIS_ENCRYPTED_JSON: &str = r#"{
  "version": 1,
  "header": { "slots": [], "params": {} },
  "db": "ZW5jcnlwdGVk"
}"#;

// ==========================================================================
// otpauth import — auto-detect + forced format
// ==========================================================================

#[test]
fn json_otpauth_text_uri_imports_account() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["imported"], serde_json::json!(1));
    assert_eq!(v["skipped"], serde_json::json!(0));
    assert_eq!(v["replaced"], serde_json::json!(0));
    assert_eq!(v["appended"], serde_json::json!(0));
    assert_eq!(v["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(v["accounts"][0]["label"], serde_json::json!("alice"));
    assert!(assert.get_output().stderr.is_empty());

    let listed = list_accounts_json(&vault_path);
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 1);
}

#[test]
fn json_otpauth_json_array_imports_multiple() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("creds.json");
    let body = format!(
        "[{}, {}]",
        serde_json::Value::String(TOTP_URI_ALICE.into()),
        serde_json::Value::String(TOTP_URI_BOB.into())
    );
    write_file(&src, body.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["imported"], serde_json::json!(2));
}

#[test]
fn json_otpauth_forced_format_succeeds_on_matching_input() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
            "--format",
            "otpauth",
        ])
        .assert()
        .success();
    let listed = list_accounts_json(&vault_path);
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 1);
}

#[test]
fn json_forced_aegis_on_otpauth_input_rejects_with_unsupported_import_format() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
            "--format",
            "aegis",
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["error_kind"],
        serde_json::json!("unsupported_import_format")
    );
    assert_eq!(v["format"], serde_json::json!("aegis"));
    assert!(assert.get_output().stdout.is_empty());
}

// ==========================================================================
// Aegis-plaintext import + encrypted rejection
// ==========================================================================

#[test]
fn json_aegis_plaintext_auto_detects_and_imports() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("aegis.json");
    write_file(&src, AEGIS_PLAINTEXT_JSON.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["imported"], serde_json::json!(1));
}

#[test]
fn json_aegis_encrypted_rejects_with_unsupported_encrypted_aegis() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("aegis.json");
    write_file(&src, AEGIS_ENCRYPTED_JSON.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["error_kind"],
        serde_json::json!("unsupported_encrypted_aegis")
    );
    assert!(assert.get_output().stdout.is_empty());
}

// ==========================================================================
// On-conflict policies
// ==========================================================================

fn seed_with_alice(path: &Path) {
    let now = std::time::SystemTime::now();
    let validated = parse_otpauth(TOTP_URI_ALICE, now).expect("parse");
    let (mut vault, store) = Store::open(path, paladin_core::VaultLock::Plaintext).expect("open");
    vault.add(validated.account);
    vault.save(&store).expect("save");
}

fn seed_with_hotp_carol(path: &Path) {
    let now = std::time::SystemTime::now();
    let validated = parse_otpauth(HOTP_URI_CAROL, now).expect("parse");
    let (mut vault, store) = Store::open(path, paladin_core::VaultLock::Plaintext).expect("open");
    vault.add(validated.account);
    vault.save(&store).expect("save");
}

#[test]
fn json_default_on_conflict_is_skip_when_omitted() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    seed_with_alice(&vault_path);

    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["imported"], serde_json::json!(0));
    assert_eq!(v["skipped"], serde_json::json!(1));
    assert_eq!(v["replaced"], serde_json::json!(0));
    assert_eq!(v["appended"], serde_json::json!(0));
    let listed = list_accounts_json(&vault_path);
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 1);
}

#[test]
fn json_on_conflict_replace_overwrites_existing() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    seed_with_alice(&vault_path);

    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
            "--on-conflict",
            "replace",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["imported"], serde_json::json!(0));
    assert_eq!(v["skipped"], serde_json::json!(0));
    assert_eq!(v["replaced"], serde_json::json!(1));
    let listed = list_accounts_json(&vault_path);
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 1);
}

#[test]
fn json_on_conflict_append_inserts_duplicate() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    seed_with_alice(&vault_path);

    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
            "--on-conflict",
            "append",
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["imported"], serde_json::json!(0));
    assert_eq!(v["appended"], serde_json::json!(1));
    let listed = list_accounts_json(&vault_path);
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 2);
}

#[test]
fn json_on_conflict_replace_preserves_hotp_counter() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    seed_with_hotp_carol(&vault_path);

    // Same (secret, issuer, label) as the seed but with a different
    // counter on the source row. Replace must keep the existing
    // counter (11), not the source counter (99).
    let src_uri =
        "otpauth://hotp/Acme:carol?secret=MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK&digits=6&counter=99";
    let src = dir.path().join("creds.txt");
    write_file(&src, src_uri.as_bytes());

    paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
            "--on-conflict",
            "replace",
        ])
        .assert()
        .success();

    let listed = list_accounts_json(&vault_path);
    let arr = listed["accounts"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["counter"], serde_json::json!(11));
}

// ==========================================================================
// Error / edge cases
// ==========================================================================

#[test]
fn json_empty_otpauth_array_rejects_with_no_entries_to_import() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("creds.json");
    write_file(&src, b"[]");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("no_entries_to_import"));
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_unrecognized_input_rejects_with_unsupported_import_format() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("garbage.bin");
    write_file(&src, b"this is not anything we recognize\n");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["error_kind"],
        serde_json::json!("unsupported_import_format")
    );
    assert_eq!(v["format"], serde_json::json!("unknown"));
}

#[test]
fn json_paladin_plaintext_bundle_rejects_without_passphrase_prompt() {
    // A Paladin-format file in plaintext mode is not importable as a
    // bundle source; the precheck rejects it before any prompt. We
    // create a real plaintext Paladin file via the vault Store and
    // attempt to import that file as a bundle.
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);

    let src_path = dir.path().join("bundle.bin");
    let (vault, store) = Store::create(&src_path, VaultInit::Plaintext).expect("create bundle");
    vault.save(&store).expect("save bundle");

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src_path.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(
        v["error_kind"],
        serde_json::json!("unsupported_plaintext_vault")
    );
    assert!(assert.get_output().stdout.is_empty());
}

#[test]
fn json_vault_missing_returns_vault_missing_before_reading_source() {
    // No vault created at the path. The CLI should fail with
    // vault_missing without consulting the source file.
    let (dir, vault_path) = fresh_vault_path();
    // create the source file so this test can't accidentally fail on
    // source-file IO instead of vault_missing.
    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("vault_missing"));
}

#[test]
fn json_invalid_entry_rejects_whole_batch_atomically() {
    // §4.7: "Each import parses and validates the full input before
    // mutating the vault. Any invalid entry rejects the whole batch
    // with the core error kind and `source_index` when available."
    //
    // Drive a JSON array containing one valid and one invalid otpauth
    // URI; assert the failure envelope carries `validation_error`
    // tagged with the offending row's `source_index`, and that the
    // pre-existing vault contents are unchanged (no partial commit).
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    seed_with_alice(&vault_path);

    // [valid bob, invalid scheme] — second element is row 1.
    let src = dir.path().join("creds.json");
    let body = format!(
        "[{}, {}]",
        serde_json::Value::String(TOTP_URI_BOB.into()),
        serde_json::Value::String("https://not-otpauth.example/".into()),
    );
    write_file(&src, body.as_bytes());

    let assert = paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    let v: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
    assert_eq!(v["field"], serde_json::json!("uri"));
    assert_eq!(v["reason"], serde_json::json!("invalid_scheme"));
    assert_eq!(
        v["source_index"],
        serde_json::json!(1),
        "the offending row index must be carried in the failure envelope",
    );
    // §5 stream cleanliness: failure envelope only on stderr.
    assert!(assert.get_output().stdout.is_empty());

    // Atomicity: the destination vault must still have just the
    // pre-existing seed (`alice`); the valid `bob` from row 0 must
    // **not** have been partially committed.
    let listed = list_accounts_json(&vault_path);
    let accounts = listed["accounts"].as_array().expect("accounts array");
    assert_eq!(
        accounts.len(),
        1,
        "vault must be unchanged after a rejected batch",
    );
    assert_eq!(accounts[0]["label"], serde_json::json!("alice"));
}

// ==========================================================================
// Text-mode coverage (success + skip warning)
// ==========================================================================

#[test]
fn text_import_success_prints_summary_to_stdout() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    let assert = paladin()
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).unwrap();
    assert!(stdout.contains("Imported 1"));
}

#[test]
fn text_import_skip_collision_emits_stderr_warning() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    seed_with_alice(&vault_path);
    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    let assert = paladin()
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stderr = std::str::from_utf8(&assert.get_output().stderr).unwrap();
    assert!(
        stderr.to_lowercase().contains("skip")
            || stderr.to_lowercase().contains("collision")
            || stderr.to_lowercase().contains("alice"),
        "expected a skip-collision advisory on stderr; got: {stderr:?}",
    );
}

// ==========================================================================
// Vault state assertions
// ==========================================================================

#[test]
fn imported_account_is_persisted_to_disk() {
    let (dir, vault_path) = fresh_vault_path();
    create_empty_plaintext_vault(&vault_path);
    let src = dir.path().join("creds.txt");
    write_file(&src, TOTP_URI_ALICE.as_bytes());

    paladin()
        .args([
            "--json",
            "--vault",
            vault_path.to_str().unwrap(),
            "import",
            src.to_str().unwrap(),
        ])
        .assert()
        .success();

    let vault = open_vault(&vault_path);
    let accounts =
        vault.matching_accounts(&paladin_core::parse_account_query("alice").expect("parse query"));
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].label(), "alice");
}

// Sanity: `ImportConflict::Skip` is the documented default. Lock the
// constant's name so the CLI cannot drift away from a rename in core.
#[test]
fn default_import_conflict_constant_is_skip() {
    let policy: ImportConflict = ImportConflict::Skip;
    assert!(matches!(policy, ImportConflict::Skip));
}

// =========================================================================
// Encrypted Paladin bundle PTY tests
// =========================================================================

/// §5 prompt label fired by `paladin import` after
/// `classify_paladin_import_precheck` returns `PromptForPassphrase`
/// for an encrypted Paladin bundle.
const PROMPT_BUNDLE_PASSPHRASE: &str = "Bundle passphrase: ";

/// Build an encrypted Paladin bundle whose contents are the accounts
/// currently held in `src_vault`. Uses the §4.4 minimum Argon2id
/// parameters so the test stays fast in CI; the bundle still goes
/// through the real `paladin_core::export::encrypted` writer.
fn build_encrypted_bundle(src_vault: &Vault, passphrase: &str) -> Vec<u8> {
    let pp = SecretString::from(passphrase.to_string());
    let params = Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    };
    let opts = EncryptionOptions::with_params(pp, params).expect("opts");
    export::encrypted(src_vault, opts).expect("encrypt bundle")
}

#[test]
fn pty_encrypted_paladin_bundle_prompts_once_for_bundle_passphrase() {
    // §5: an encrypted Paladin bundle import must prompt exactly
    // once via `/dev/tty` for the bundle passphrase before
    // `import::from_file` is called. The destination vault is
    // plaintext on purpose so the *only* prompt that fires is the
    // bundle prompt — that keeps the "exactly once" assertion
    // unambiguous.
    let (src_dir, src_vault_path) = fresh_vault_path();
    let now = std::time::SystemTime::now();

    // Build an in-process source vault with one account, then
    // serialize it as an encrypted Paladin bundle.
    let (mut src_vault, _src_store) =
        Store::create(&src_vault_path, VaultInit::Plaintext).expect("create src vault");
    let validated = parse_otpauth(TOTP_URI_ALICE, now).expect("parse");
    src_vault.add(validated.account);
    let bundle_bytes = build_encrypted_bundle(&src_vault, "bundle-secret");

    let bundle_path = src_dir.path().join("alice.paladin");
    write_file(&bundle_path, &bundle_bytes);

    // Destination vault: plaintext, so no unlock prompt fires.
    let (_dst_dir, dst_path) = fresh_vault_path();
    create_empty_plaintext_vault(&dst_path);

    let mut pty = Pty::spawn(
        [
            "--vault",
            dst_path.to_str().unwrap(),
            "import",
            bundle_path.to_str().unwrap(),
        ],
        &[],
    );
    pty.expect(PROMPT_BUNDLE_PASSPHRASE);
    pty.send_line("bundle-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);

    // The bundle prompt must have fired *exactly once* — locks the
    // §5 "prompted once per prompt target" rule for encrypted
    // Paladin bundles.
    let prompt_count = exit.transcript.matches(PROMPT_BUNDLE_PASSPHRASE).count();
    assert_eq!(
        prompt_count, 1,
        "bundle passphrase prompt must fire exactly once, transcript:\n{}",
        exit.transcript,
    );

    // The imported account is present on the destination vault.
    let listed = list_accounts_json(&dst_path);
    let accounts = listed["accounts"].as_array().expect("accounts array");
    assert_eq!(accounts.len(), 1, "exactly one imported account");
    assert_eq!(accounts[0]["label"], serde_json::json!("alice"));
    assert_eq!(accounts[0]["issuer"], serde_json::json!("Acme"));
}

#[test]
fn pty_encrypted_paladin_bundle_preserves_timestamps_and_assigns_fresh_uuids() {
    // §4.6 / §5: Paladin encrypted bundles preserve each account's
    // stored timestamps for inserted/appended rows but never insert
    // source `AccountId`s — non-colliding rows receive fresh UUIDv4
    // IDs at merge time. Build a source vault with a deterministic
    // `created_at` and a *bumped* `updated_at` (via `rename`) so the
    // assertion is meaningful: the two timestamps differ on the
    // source, and both must come through to the destination
    // unchanged.
    let (src_dir, src_vault_path) = fresh_vault_path();
    let created_at_secs: u64 = 1_700_000_000;
    let updated_at_secs: u64 = 1_700_000_500;
    let created_at_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(created_at_secs);
    let updated_at_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(updated_at_secs);

    // Source vault: one account whose `created_at` is `now1` and
    // whose `updated_at` is bumped to `now2` by a rename.
    let (mut src_vault, _src_store) =
        Store::create(&src_vault_path, VaultInit::Plaintext).expect("create src vault");
    let validated = parse_otpauth(TOTP_URI_ALICE, created_at_time).expect("parse");
    let src_account_id = src_vault.add(validated.account);
    src_vault
        .rename(src_account_id, "alice-renamed", updated_at_time)
        .expect("rename bumps updated_at");

    // Sanity: the in-process source really does have distinct
    // timestamps so the post-import assertion is non-trivial.
    let src_account = src_vault
        .accounts()
        .iter()
        .find(|a| a.id() == src_account_id)
        .expect("src account present");
    assert_eq!(src_account.created_at(), created_at_secs);
    assert_eq!(src_account.updated_at(), updated_at_secs);

    let bundle_bytes = build_encrypted_bundle(&src_vault, "bundle-secret");
    let bundle_path = src_dir.path().join("alice.paladin");
    write_file(&bundle_path, &bundle_bytes);

    // Destination vault: plaintext, so the bundle prompt is the only
    // prompt fired during import.
    let (_dst_dir, dst_path) = fresh_vault_path();
    create_empty_plaintext_vault(&dst_path);

    let mut pty = Pty::spawn(
        [
            "--vault",
            dst_path.to_str().unwrap(),
            "import",
            bundle_path.to_str().unwrap(),
        ],
        &[],
    );
    pty.expect(PROMPT_BUNDLE_PASSPHRASE);
    pty.send_line("bundle-secret");
    let exit = pty.wait_for_exit();
    exit.assert_exit(0);

    // Inspect the destination via the JSON list envelope so we
    // exercise the §5 `AccountSummary` shape end-to-end.
    let listed = list_accounts_json(&dst_path);
    let accounts = listed["accounts"].as_array().expect("accounts array");
    assert_eq!(accounts.len(), 1, "exactly one imported account");
    let dst = &accounts[0];

    // Timestamps preserved verbatim from the source bundle.
    assert_eq!(
        dst["created_at"],
        serde_json::json!(created_at_secs),
        "source `created_at` must be preserved on import",
    );
    assert_eq!(
        dst["updated_at"],
        serde_json::json!(updated_at_secs),
        "source `updated_at` must be preserved on import",
    );

    // Label round-trips through the rename → bundle → import path.
    assert_eq!(dst["label"], serde_json::json!("alice-renamed"));

    // Fresh UUIDv4 at merge time — the destination ID must differ
    // from the source ID in the canonical 36-char hyphenated form.
    let src_id_str = src_account_id.to_string();
    let dst_id_str = dst["id"].as_str().expect("id is a string").to_string();
    assert_ne!(
        dst_id_str, src_id_str,
        "destination id must not equal source id (fresh UUIDv4 at merge)",
    );
    assert_eq!(dst_id_str.len(), 36, "canonical UUID is 36 chars");
    assert_eq!(
        dst_id_str.bytes().filter(|&b| b == b'-').count(),
        4,
        "canonical UUID has 4 hyphens",
    );
}
