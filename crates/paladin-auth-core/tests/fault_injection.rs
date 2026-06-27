// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Cross-save-site fault-injection coverage (docs/DESIGN.md §10 / Phase E.7
// + Phase J.6 cross-save-site table).
//
// Compiles and runs only with the `test-fault-injection` cargo feature
// enabled — production builds never see this surface. The shared hook
// in `paladin_auth_core::storage::fault` honors `PALADIN_AUTH_FAULT_INJECT` and
// must reach every atomic-write site uniformly. This file enumerates
// the (save_site × fault_phase) cells across the full §4.7 save
// surface and asserts each one surfaces the right error: `pre_commit`
// → `save_not_committed`, `post_commit` →
// `save_durability_unconfirmed`.
//
// Per-cell rollback semantics (mode/key in-memory state, on-disk
// authoritativeness) are pinned in `tests/passphrase_transitions_fault.rs`;
// this file's job is the cross-product matrix proving the hook itself
// reaches every site uniformly.
//
// Env-var manipulation is process-wide, so every test holds a single
// shared mutex for its full duration (setup + fault + assertions).
// `run_serial` clears the env var on entry and exit so a panicking
// test never leaves a fault state set for the next test.

#![cfg(feature = "test-fault-injection")]

mod common;

use common::test_tempdir;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use paladin_auth_core::{
    destroy_vault, parse_otpauth, write_secret_file_atomic, Account, AccountEdit, Argon2Params,
    EncryptionOptions, ErrorKind, IconHintInput, PaladinAuthError, Store, VaultInit, VaultLock,
    VaultMode,
};
use secrecy::SecretString;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

const ENV: &str = "PALADIN_AUTH_FAULT_INJECT";
const PRE: &str = "pre_commit";
const POST: &str = "post_commit";
const CSPRNG: &str = "csprng_read";
const KDF: &str = "kdf_allocation";

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Run `f` while holding the shared env-var lock and ensure
/// `PALADIN_AUTH_FAULT_INJECT` is unset on entry and exit. Every test in
/// this file wraps its body in `run_serial` so setup saves and
/// fault-injected saves cannot race against another test's env-var
/// manipulation. Panics propagate after the env var is cleared so a
/// failed assertion never leaks a fault state into the next test.
fn run_serial<F: FnOnce()>(f: F) {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::env::remove_var(ENV);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::env::remove_var(ENV);
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

/// Run `f` with `PALADIN_AUTH_FAULT_INJECT=phase` set, restoring the
/// cleared state on exit. Caller must already hold the env lock via
/// `run_serial`.
fn with_fault<R>(phase: &str, f: impl FnOnce() -> R) -> R {
    std::env::set_var(ENV, phase);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::env::remove_var(ENV);
    match result {
        Ok(v) => v,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn vault_path_in(dir: &TempDir) -> PathBuf {
    let p = dir.path().join("vault.bin");
    // §4.3 dir mode gate: `Store::create` rejects a parent dir that
    // grants any group / other perms, so tighten the tempdir up front.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    p
}

fn assert_save_not_committed(err: &PaladinAuthError, expect_backup: bool) {
    assert_eq!(
        err.kind(),
        ErrorKind::SaveNotCommitted,
        "expected save_not_committed, got {err:?}"
    );
    match err {
        PaladinAuthError::SaveNotCommitted {
            committed,
            backup_path,
        } => {
            assert!(!*committed, "pre_commit fault must not commit");
            if expect_backup {
                assert!(
                    backup_path.is_some(),
                    "expected backup_path Some, got {backup_path:?}"
                );
            } else {
                assert!(
                    backup_path.is_none(),
                    "expected backup_path None, got {backup_path:?}"
                );
            }
        }
        _ => unreachable!(),
    }
}

fn assert_save_durability_unconfirmed(err: &PaladinAuthError) {
    assert_eq!(
        err.kind(),
        ErrorKind::SaveDurabilityUnconfirmed,
        "expected save_durability_unconfirmed, got {err:?}"
    );
}

fn no_tmp_residue(path: &Path) {
    for suffix in [".tmp", ".bak.tmp"] {
        let mut s = path.as_os_str().to_os_string();
        s.push(suffix);
        let probe = PathBuf::from(s);
        assert!(
            !probe.exists(),
            "expected no leftover tempfile, found {}",
            probe.display(),
        );
    }
}

// ──────────────────────────────────────────────────────────────────
// regular save (Vault::save → save_plaintext)
// ──────────────────────────────────────────────────────────────────

#[test]
fn regular_save_pre_commit_surfaces_save_not_committed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();
        let primary_before = std::fs::read(&path).unwrap();

        let err = with_fault(PRE, || vault.save(&store)).expect_err("pre_commit must fail");
        // §5: regular-save pre-commit leaves the old primary at
        // `vault.bin` authoritative, so the user does not need
        // backup-file recovery — `backup_path` is None.
        assert_save_not_committed(&err, false);

        // Primary unchanged: the step-4 rename never happened.
        assert_eq!(std::fs::read(&path).unwrap(), primary_before);
        // Step 3 (rename `.bak.tmp` → `.bak`) ran before the fault, so
        // the rotated `.bak` exists and contains the pre-save primary
        // bytes verbatim.
        let bak_path = path.with_file_name("vault.bin.bak");
        assert_eq!(
            std::fs::read(&bak_path).unwrap(),
            primary_before,
            "vault.bin.bak must hold the pre-save primary bytes",
        );
        no_tmp_residue(&path);

        // A fresh open after the fault reads the pre-save state.
        let (_reopened_vault, _reopened_store) =
            Store::open(&path, VaultLock::Plaintext).expect("reopen after pre_commit must succeed");
    });
}

#[test]
fn regular_save_post_commit_surfaces_save_durability_unconfirmed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();

        let err = with_fault(POST, || vault.save(&store)).expect_err("post_commit must fail");
        assert_save_durability_unconfirmed(&err);

        // Primary is in place after a post-commit fault — only durability
        // is in question. The step-4 rename committed even though the
        // parent fsync did not, so `vault.bin` is the freshly renamed
        // primary; for an unmutated plaintext payload the bytes are
        // byte-identical to the prior primary, which is fine — the
        // contract is "rename committed, durability unclear".
        assert!(path.exists(), "primary must be in place post-commit");
        no_tmp_residue(&path);

        // A fresh open after the fault reads the new state — the rename
        // committed even though the parent fsync did not.
        let (_reopened_vault, _reopened_store) = Store::open(&path, VaultLock::Plaintext)
            .expect("reopen after post_commit must succeed");
    });
}

// ──────────────────────────────────────────────────────────────────
// create_force (Store::create_force → save_plaintext_clobber)
// ──────────────────────────────────────────────────────────────────

#[test]
fn create_force_pre_commit_surfaces_save_not_committed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();

        // create_force on an existing primary rotates `vault.bin` →
        // `vault.bin.bak` before staging the new primary; pre_commit
        // fault fires after that rotation, so backup_path is Some.
        let err = with_fault(PRE, || Store::create_force(&path, VaultInit::Plaintext))
            .map(|_| ())
            .expect_err("pre_commit must fail");
        assert_save_not_committed(&err, true);
        no_tmp_residue(&path);
    });
}

#[test]
fn create_force_post_commit_surfaces_save_durability_unconfirmed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();

        let err = with_fault(POST, || Store::create_force(&path, VaultInit::Plaintext))
            .map(|_| ())
            .expect_err("post_commit must fail");
        assert_save_durability_unconfirmed(&err);
        assert!(path.exists(), "primary must be in place post-commit");
        no_tmp_residue(&path);
    });
}

// ──────────────────────────────────────────────────────────────────
// Phase F.17 — encrypted `create` / `create_force` follow the same
// pre/post-commit semantics as plaintext: `pre_commit` →
// `save_not_committed` (with `backup_path` empty when no prior
// primary exists, populated when create_force rotates one), and
// `post_commit` → `save_durability_unconfirmed`. The hook fires
// inside `save_encrypted` / `save_encrypted_clobber`, the same
// shared rename/fsync sites that drive the plaintext pre/post-commit
// rows above.
//
// Cheap Argon2 params keep wall time bounded (§4.4 acceptance floor:
// `m_kib >= 8192`, `t >= 1`, `p >= 1`).
// ──────────────────────────────────────────────────────────────────

const F17_PASSPHRASE: &str = "f17-fault-pass";

fn f17_encrypted_options() -> EncryptionOptions {
    let params = Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    };
    EncryptionOptions::with_params(SecretString::from(F17_PASSPHRASE.to_string()), params)
        .expect("cheap_params are in §4.4 bounds")
}

#[test]
fn encrypted_create_pre_commit_surfaces_save_not_committed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);

        let err = with_fault(PRE, || {
            Store::create(&path, VaultInit::Encrypted(f17_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("pre_commit must fail");
        // Encrypted `create` (non-clobber) routes through `save_encrypted`,
        // which never rotates a `.bak` — `backup_path` is None.
        assert_save_not_committed(&err, false);

        // No primary or `.bak` survives the failed create.
        assert!(
            !path.exists(),
            "primary must not exist after pre_commit fault"
        );
        assert!(!path.with_file_name("vault.bin.bak").exists());
        no_tmp_residue(&path);
    });
}

#[test]
fn encrypted_create_post_commit_surfaces_save_durability_unconfirmed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);

        let err = with_fault(POST, || {
            Store::create(&path, VaultInit::Encrypted(f17_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("post_commit must fail");
        assert_save_durability_unconfirmed(&err);

        // Post-commit means the rename happened — the primary exists and
        // a fresh open with the same passphrase reads back an empty
        // encrypted vault.
        assert!(path.exists(), "primary must be in place post-commit");
        no_tmp_residue(&path);
        let (reopened, _) = Store::open(
            &path,
            VaultLock::Encrypted(SecretString::from(F17_PASSPHRASE.to_string())),
        )
        .expect("reopen after post_commit must succeed");
        assert!(reopened.accounts().is_empty());
        assert!(reopened.is_encrypted());
    });
}

#[test]
fn encrypted_create_force_pre_commit_surfaces_save_not_committed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let _ = Store::create(&path, VaultInit::Encrypted(f17_encrypted_options()))
            .expect("setup: create encrypted primary");

        // create_force rotates the existing primary → `.bak` before
        // staging the new primary; pre_commit fault fires after that
        // rotation, so `backup_path` is Some.
        let err = with_fault(PRE, || {
            Store::create_force(&path, VaultInit::Encrypted(f17_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("pre_commit must fail");
        assert_save_not_committed(&err, true);
        no_tmp_residue(&path);

        // The pre-commit fault left the rotated `.bak` on disk; the
        // primary path no longer holds an encrypted vault, so a fresh
        // `Store::open` against `vault.bin` should fail with
        // `vault_missing` (the rotation moved it to .bak).
        let bak = path.with_file_name("vault.bin.bak");
        assert!(bak.exists(), "rotated .bak must be in place");
        let reopen_err = Store::open(
            &path,
            VaultLock::Encrypted(SecretString::from(F17_PASSPHRASE.to_string())),
        )
        .map(|_| ())
        .unwrap_err();
        assert_eq!(reopen_err.kind(), ErrorKind::VaultMissing);
    });
}

#[test]
fn encrypted_create_force_post_commit_surfaces_save_durability_unconfirmed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let _ = Store::create(&path, VaultInit::Encrypted(f17_encrypted_options()))
            .expect("setup: create encrypted primary");

        let err = with_fault(POST, || {
            Store::create_force(&path, VaultInit::Encrypted(f17_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("post_commit must fail");
        assert_save_durability_unconfirmed(&err);

        // Post-commit means the rename committed — the primary is the
        // freshly clobbered encrypted vault and reopens cleanly.
        assert!(path.exists(), "primary must be in place post-commit");
        no_tmp_residue(&path);
        let (reopened, _) = Store::open(
            &path,
            VaultLock::Encrypted(SecretString::from(F17_PASSPHRASE.to_string())),
        )
        .expect("reopen after post_commit must succeed");
        assert!(reopened.accounts().is_empty());
        assert!(reopened.is_encrypted());
    });
}

// ──────────────────────────────────────────────────────────────────
// write_secret_file_atomic (shared export writer)
// ──────────────────────────────────────────────────────────────────

#[test]
fn write_secret_file_atomic_pre_commit_surfaces_save_not_committed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = dir.path().join("export.bin");

        let err = with_fault(PRE, || write_secret_file_atomic(&path, b"export-payload"))
            .expect_err("pre_commit must fail");
        // §4.7 contract: write_secret_file_atomic never rotates a `.bak`,
        // so backup_path is always None.
        assert_save_not_committed(&err, false);

        // Destination must not exist after pre_commit on a fresh path.
        assert!(
            !path.exists(),
            "destination must be untouched on pre_commit"
        );
        no_tmp_residue(&path);
    });
}

#[test]
fn write_secret_file_atomic_post_commit_surfaces_save_durability_unconfirmed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = dir.path().join("export.bin");

        let err = with_fault(POST, || write_secret_file_atomic(&path, b"export-payload"))
            .expect_err("post_commit must fail");
        assert_save_durability_unconfirmed(&err);

        // Post-commit means the rename happened — destination exists with
        // the supplied content.
        assert_eq!(std::fs::read(&path).unwrap(), b"export-payload");
        no_tmp_residue(&path);
    });
}

// ──────────────────────────────────────────────────────────────────
// Cross-save-site coverage table — one assertion per cell, proving
// the hook reaches every site uniformly.
// ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum SaveSite {
    RegularSave,
    CreateForce,
    SetPassphrase,
    ChangePassphrase,
    RemovePassphrase,
    WriteSecretFileAtomic,
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    PreCommit,
    PostCommit,
}

fn drive(site: SaveSite, phase: Phase) -> PaladinAuthError {
    let dir = test_tempdir();
    let path = vault_path_in(&dir);
    let phase_str = match phase {
        Phase::PreCommit => PRE,
        Phase::PostCommit => POST,
    };
    match site {
        SaveSite::RegularSave => {
            let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
            vault.save(&store).unwrap();
            with_fault(phase_str, || vault.save(&store)).unwrap_err()
        }
        SaveSite::CreateForce => {
            let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
            vault.save(&store).unwrap();
            with_fault(phase_str, || {
                Store::create_force(&path, VaultInit::Plaintext)
            })
            .map(|_| ())
            .unwrap_err()
        }
        SaveSite::SetPassphrase => {
            // Plaintext → encrypted transition. The save site is the
            // first encrypted write of the rotated vault.
            let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
            vault.save(&store).unwrap();
            with_fault(phase_str, || {
                vault.set_passphrase(&store, f17_encrypted_options())
            })
            .unwrap_err()
        }
        SaveSite::ChangePassphrase => {
            // Encrypted → encrypted transition (new key). The save
            // site is the re-encrypted write under the new derived
            // key.
            let (mut vault, store) =
                Store::create(&path, VaultInit::Encrypted(f17_encrypted_options())).unwrap();
            vault.save(&store).unwrap();
            let new_options = EncryptionOptions::with_params(
                SecretString::from(format!("{F17_PASSPHRASE}-rotated")),
                Argon2Params {
                    m_kib: 8_192,
                    t: 1,
                    p: 1,
                },
            )
            .expect("cheap_params are in §4.4 bounds");
            with_fault(phase_str, || vault.change_passphrase(&store, new_options)).unwrap_err()
        }
        SaveSite::RemovePassphrase => {
            // Encrypted → plaintext transition. The save site is the
            // first plaintext write of the rotated vault.
            let (mut vault, store) =
                Store::create(&path, VaultInit::Encrypted(f17_encrypted_options())).unwrap();
            vault.save(&store).unwrap();
            with_fault(phase_str, || vault.remove_passphrase(&store)).unwrap_err()
        }
        SaveSite::WriteSecretFileAtomic => {
            let target = dir.path().join("export.bin");
            with_fault(phase_str, || write_secret_file_atomic(&target, b"x")).unwrap_err()
        }
    }
}

#[test]
fn fault_hook_reaches_every_save_site() {
    run_serial(|| {
        let cells = [
            (SaveSite::RegularSave, Phase::PreCommit),
            (SaveSite::RegularSave, Phase::PostCommit),
            (SaveSite::CreateForce, Phase::PreCommit),
            (SaveSite::CreateForce, Phase::PostCommit),
            (SaveSite::SetPassphrase, Phase::PreCommit),
            (SaveSite::SetPassphrase, Phase::PostCommit),
            (SaveSite::ChangePassphrase, Phase::PreCommit),
            (SaveSite::ChangePassphrase, Phase::PostCommit),
            (SaveSite::RemovePassphrase, Phase::PreCommit),
            (SaveSite::RemovePassphrase, Phase::PostCommit),
            (SaveSite::WriteSecretFileAtomic, Phase::PreCommit),
            (SaveSite::WriteSecretFileAtomic, Phase::PostCommit),
        ];
        for (site, phase) in cells {
            let err = drive(site, phase);
            let expected = match phase {
                Phase::PreCommit => ErrorKind::SaveNotCommitted,
                Phase::PostCommit => ErrorKind::SaveDurabilityUnconfirmed,
            };
            assert_eq!(
                err.kind(),
                expected,
                "site={site:?} phase={phase:?} -> unexpected error {err:?}",
            );
        }
    });
}

// ──────────────────────────────────────────────────────────────────
// Repeated pre_commit on the same Store must not leak state from the
// first failure into the second — no half-applied mutation, no
// leftover `.tmp`.
// ──────────────────────────────────────────────────────────────────

#[test]
fn repeated_pre_commit_does_not_leak_state() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();
        let primary_after_first = std::fs::read(&path).unwrap();

        let first = with_fault(PRE, || vault.save(&store)).expect_err("first must fail");
        // Regular-save pre-commit: primary stays authoritative, so
        // `backup_path` is None per §5.
        assert_save_not_committed(&first, false);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            primary_after_first,
            "primary must be unchanged after first pre_commit fault",
        );
        no_tmp_residue(&path);

        let second = with_fault(PRE, || vault.save(&store)).expect_err("second must fail");
        assert_save_not_committed(&second, false);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            primary_after_first,
            "primary must remain unchanged after second pre_commit fault",
        );
        no_tmp_residue(&path);
    });
}

// ──────────────────────────────────────────────────────────────────
// Default behavior (no env var): the hook is dormant and saves
// commit normally even with the feature enabled. This locks in the
// "off-by-default" guarantee at the binary-test surface.
// ──────────────────────────────────────────────────────────────────

#[test]
fn no_env_var_leaves_save_pipeline_intact() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault
            .save(&store)
            .expect("save must succeed with no fault env");
        no_tmp_residue(&path);
    });
}

// ──────────────────────────────────────────────────────────────────
// `Store::for_test_fault_injection` builds a Store without going
// through open / create, and the resulting Store drives the hook the
// same way as a regular Store.
// ──────────────────────────────────────────────────────────────────

#[test]
fn store_for_test_constructor_drives_fault_hook() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        // Establish a saved primary so a follow-up save on a synthetic
        // Store goes through the rotation path.
        {
            let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
            vault.save(&store).unwrap();
        }

        let synthetic = Store::for_test_fault_injection(path.clone(), VaultMode::Plaintext);
        // Reopen to get a Vault we can save through `synthetic`.
        let (vault, _store) = Store::open(&path, paladin_auth_core::VaultLock::Plaintext).unwrap();

        let err = with_fault(PRE, || vault.save(&synthetic))
            .expect_err("pre_commit must fail through synthetic Store");
        // Regular save through the synthetic Store still routes through
        // `save_plaintext`, which leaves the old primary authoritative
        // and reports `backup_path: None` per §5.
        assert_save_not_committed(&err, false);
    });
}

// ──────────────────────────────────────────────────────────────────
// CSPRNG failure surface (Phase F.15 / docs/DESIGN.md §5).
//
// Every encrypted-write site reads the OS CSPRNG to draw a fresh salt
// (encrypted `create` / `create_force`) or fresh nonce (every encrypted
// save, including the freshly-built initial save inside `create*`). A
// `getrandom::Error` from either call must surface as
// `io_error { operation: "csprng_read" }`, must not write a partial
// vault file, must not rotate or clobber any pre-existing primary, and
// must not leak intermediate plaintext to disk. The fault-injection
// hook reuses the existing `PALADIN_AUTH_FAULT_INJECT` env-var contract with
// a new `csprng_read` value (see `storage::fault`).
//
// Phase H (`set_passphrase` / `change_passphrase` / `remove_passphrase`)
// and Phase I (`export::encrypted`) extend this matrix when they land.
// ──────────────────────────────────────────────────────────────────

const CSPRNG_PASSPHRASE: &str = "csprng-fault-pass";

fn cheap_encrypted_options() -> EncryptionOptions {
    // §4.4 acceptance floor (`m_kib >= 8192`, `t >= 1`, `p >= 1`).
    let params = Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    };
    EncryptionOptions::with_params(SecretString::from(CSPRNG_PASSPHRASE.to_string()), params)
        .expect("cheap_params are in §4.4 bounds")
}

fn assert_csprng_io_error(err: &PaladinAuthError) {
    assert_eq!(
        err.kind(),
        ErrorKind::IoError,
        "expected io_error, got {err:?}"
    );
    match err {
        PaladinAuthError::IoError { operation, .. } => {
            assert_eq!(
                *operation, "csprng_read",
                "expected operation=csprng_read, got {operation:?}"
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn encrypted_create_csprng_failure_surfaces_io_error() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let opts = cheap_encrypted_options();

        let err = with_fault(CSPRNG, || Store::create(&path, VaultInit::Encrypted(opts)))
            .map(|_| ())
            .expect_err("csprng_read fault must fail Store::create");

        assert_csprng_io_error(&err);
        // No partial primary or temp/backup siblings on disk: the salt
        // is drawn before any staging, so a CSPRNG fault must abort
        // before touching the filesystem.
        assert!(!path.exists(), "vault.bin must not be created");
        no_tmp_residue(&path);
        let bak_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".bak");
            PathBuf::from(s)
        };
        assert!(!bak_path.exists(), "vault.bin.bak must not be created");
    });
}

#[test]
fn encrypted_create_force_csprng_failure_preserves_primary() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        // Establish a committed encrypted primary so the fault path
        // exercises the staged-clobber branch (vs. the empty-dir branch
        // covered above).
        let _ = Store::create(&path, VaultInit::Encrypted(cheap_encrypted_options()))
            .expect("setup: create encrypted primary");
        let primary_before = std::fs::read(&path).expect("read primary before fault");
        let bak_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".bak");
            PathBuf::from(s)
        };
        let bak_before = bak_path.exists().then(|| std::fs::read(&bak_path).unwrap());

        let err = with_fault(CSPRNG, || {
            Store::create_force(&path, VaultInit::Encrypted(cheap_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("csprng_read fault must fail Store::create_force");

        assert_csprng_io_error(&err);
        // Primary remains byte-identical to its pre-fault state — the
        // CSPRNG draw is the very first crypto step so no rotation,
        // staging, or rename has happened.
        let primary_after = std::fs::read(&path).expect("read primary after fault");
        assert_eq!(
            primary_after, primary_before,
            "create_force csprng fault must not modify the primary"
        );
        // No temp residue, and the .bak (if any) is unchanged.
        no_tmp_residue(&path);
        match bak_before {
            Some(before) => {
                let after = std::fs::read(&bak_path).expect("read .bak after fault");
                assert_eq!(after, before, ".bak must be unchanged");
            }
            None => assert!(!bak_path.exists(), ".bak must not be created by fault"),
        }
    });
}

#[test]
fn encrypted_regular_save_csprng_failure_preserves_primary() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        // Establish a committed encrypted primary, drop, reopen so the
        // follow-up `vault.save` exercises the regular-save path with a
        // fresh nonce draw inside `build_encrypted_on_disk`.
        let _ = Store::create(&path, VaultInit::Encrypted(cheap_encrypted_options()))
            .expect("setup: create encrypted primary");
        let primary_before = std::fs::read(&path).expect("read primary before fault");
        let (vault, store) = Store::open(
            &path,
            VaultLock::Encrypted(SecretString::from(CSPRNG_PASSPHRASE.to_string())),
        )
        .expect("reopen encrypted vault");

        let err = with_fault(CSPRNG, || vault.save(&store))
            .expect_err("csprng_read fault must fail Vault::save");

        assert_csprng_io_error(&err);
        // The nonce is drawn before any tempfile is staged, so the
        // primary must be unchanged byte-for-byte.
        let primary_after = std::fs::read(&path).expect("read primary after fault");
        assert_eq!(
            primary_after, primary_before,
            "regular encrypted save csprng fault must not modify the primary"
        );
        no_tmp_residue(&path);
        // A subsequent unfaulted save must succeed and produce a
        // byte-distinct primary (fresh nonce) — proves the fault did
        // not corrupt the cached key or in-memory state.
        vault
            .save(&store)
            .expect("save without fault must succeed after csprng fault");
        let primary_recovered = std::fs::read(&path).expect("read primary after recovery save");
        assert_ne!(
            primary_recovered, primary_before,
            "post-recovery save must rotate ciphertext (fresh nonce)"
        );
    });
}

#[test]
fn csprng_fault_reaches_every_encrypted_write_site() {
    run_serial(|| {
        // Coverage row: each currently-implemented encrypted-write site
        // must surface the same `io_error { operation: "csprng_read" }`
        // when the hook fires. Phase H / Phase I will extend this list.
        let dir = test_tempdir();

        // Site 1: encrypted create on a fresh path.
        let path1 = vault_path_in(&dir);
        let err1 = with_fault(CSPRNG, || {
            Store::create(&path1, VaultInit::Encrypted(cheap_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("create");
        assert_csprng_io_error(&err1);

        // Site 2: encrypted create_force over an existing primary.
        let dir2 = test_tempdir();
        let path2 = vault_path_in(&dir2);
        let _ = Store::create(&path2, VaultInit::Encrypted(cheap_encrypted_options())).unwrap();
        let err2 = with_fault(CSPRNG, || {
            Store::create_force(&path2, VaultInit::Encrypted(cheap_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("create_force");
        assert_csprng_io_error(&err2);

        // Site 3: regular encrypted save on a reopened vault.
        let dir3 = test_tempdir();
        let path3 = vault_path_in(&dir3);
        let _ = Store::create(&path3, VaultInit::Encrypted(cheap_encrypted_options())).unwrap();
        let (vault, store) = Store::open(
            &path3,
            VaultLock::Encrypted(SecretString::from(CSPRNG_PASSPHRASE.to_string())),
        )
        .unwrap();
        let err3 = with_fault(CSPRNG, || vault.save(&store)).expect_err("regular save");
        assert_csprng_io_error(&err3);
    });
}

#[test]
fn csprng_fault_value_does_not_trip_pre_or_post_commit_paths() {
    run_serial(|| {
        // Plaintext save has no CSPRNG draw — the `csprng_read` fault
        // value must not accidentally fire a pre/post-commit hook there.
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();
        with_fault(CSPRNG, || vault.save(&store))
            .expect("plaintext save must succeed under csprng_read fault");
        no_tmp_residue(&path);
    });
}

// ──────────────────────────────────────────────────────────────────
// Argon2id allocation failure surface (Phase F.16 / docs/DESIGN.md §5).
//
// Every encrypted save / open path runs Argon2id to derive the 32-byte
// AEAD key. On a memory-constrained host the underlying allocator can
// fail after the §4.4 bounds have already passed; that failure must
// surface as `io_error { operation: "kdf_allocation" }` without
// panicking, must not write a partial vault file, must not rotate or
// clobber any pre-existing primary on write paths, and must not
// construct a `Vault` on the open path. The fault-injection hook
// reuses the existing `PALADIN_AUTH_FAULT_INJECT` env-var contract with a
// new `kdf_allocation` value (see `storage::fault`).
//
// Phase H (`set_passphrase` / `change_passphrase` / `remove_passphrase`)
// and Phase I (`export::encrypted`) extend this matrix when they land.
// ──────────────────────────────────────────────────────────────────

const KDF_PASSPHRASE: &str = "kdf-fault-pass";

fn kdf_encrypted_options() -> EncryptionOptions {
    // §4.4 acceptance floor (`m_kib >= 8192`, `t >= 1`, `p >= 1`).
    let params = Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    };
    EncryptionOptions::with_params(SecretString::from(KDF_PASSPHRASE.to_string()), params)
        .expect("cheap_params are in §4.4 bounds")
}

fn assert_kdf_allocation_io_error(err: &PaladinAuthError) {
    assert_eq!(
        err.kind(),
        ErrorKind::IoError,
        "expected io_error, got {err:?}"
    );
    match err {
        PaladinAuthError::IoError { operation, .. } => {
            assert_eq!(
                *operation, "kdf_allocation",
                "expected operation=kdf_allocation, got {operation:?}"
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn encrypted_create_kdf_allocation_failure_surfaces_io_error() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let opts = kdf_encrypted_options();

        let err = with_fault(KDF, || Store::create(&path, VaultInit::Encrypted(opts)))
            .map(|_| ())
            .expect_err("kdf_allocation fault must fail Store::create");

        assert_kdf_allocation_io_error(&err);
        // No partial primary or temp/backup siblings on disk: the KDF
        // runs before any tempfile staging, so a fault must abort
        // before touching the filesystem.
        assert!(!path.exists(), "vault.bin must not be created");
        no_tmp_residue(&path);
        let bak_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".bak");
            PathBuf::from(s)
        };
        assert!(!bak_path.exists(), "vault.bin.bak must not be created");
    });
}

#[test]
fn encrypted_create_force_kdf_allocation_failure_preserves_primary() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        // Establish a committed encrypted primary so the fault path
        // exercises the staged-clobber branch (vs. the empty-dir branch
        // covered above).
        let _ = Store::create(&path, VaultInit::Encrypted(kdf_encrypted_options()))
            .expect("setup: create encrypted primary");
        let primary_before = std::fs::read(&path).expect("read primary before fault");
        let bak_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".bak");
            PathBuf::from(s)
        };
        let bak_before = bak_path.exists().then(|| std::fs::read(&bak_path).unwrap());

        let err = with_fault(KDF, || {
            Store::create_force(&path, VaultInit::Encrypted(kdf_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("kdf_allocation fault must fail Store::create_force");

        assert_kdf_allocation_io_error(&err);
        // Primary remains byte-identical to its pre-fault state — the
        // KDF runs before any rotation, staging, or rename, so the
        // fault must not perturb on-disk state.
        let primary_after = std::fs::read(&path).expect("read primary after fault");
        assert_eq!(
            primary_after, primary_before,
            "primary must be unchanged by kdf_allocation fault on create_force"
        );
        no_tmp_residue(&path);
        match bak_before {
            Some(before) => {
                let after = std::fs::read(&bak_path).expect("read .bak after fault");
                assert_eq!(after, before, ".bak must be unchanged");
            }
            None => assert!(!bak_path.exists(), ".bak must not be created by fault"),
        }
    });
}

#[test]
fn encrypted_regular_save_kdf_allocation_failure_preserves_primary() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        // Establish a committed encrypted primary, drop, reopen so the
        // follow-up `vault.save` exercises the regular-save path.
        // `Store::open` uses the AEAD key cache (Phase F.13), but a
        // future swap to a re-derive-on-save path must still surface
        // the KDF allocation failure cleanly — explicit coverage here
        // documents the expected operation string at the save site.
        let _ = Store::create(&path, VaultInit::Encrypted(kdf_encrypted_options()))
            .expect("setup: create encrypted primary");
        let primary_before = std::fs::read(&path).expect("read primary before fault");
        let (vault, store) = Store::open(
            &path,
            VaultLock::Encrypted(SecretString::from(KDF_PASSPHRASE.to_string())),
        )
        .expect("reopen encrypted vault");

        // The cached AEAD key means a regular save under the
        // `kdf_allocation` fault commits successfully today (no KDF
        // call on the save path). Either outcome is acceptable as a
        // surface check: success means the cache short-circuited the
        // fault, while a returned error must carry the
        // `kdf_allocation` operation string. Pin the pre-existing
        // cache invariant explicitly so a regression that re-derives
        // on every save is forced to surface the §5 string.
        let result = with_fault(KDF, || vault.save(&store));
        match result {
            Ok(()) => {
                // Cache hit: the save did not run the KDF, so the
                // primary is rotated normally.
                no_tmp_residue(&path);
            }
            Err(err) => {
                assert_kdf_allocation_io_error(&err);
                let primary_after = std::fs::read(&path).expect("read primary after fault");
                assert_eq!(
                    primary_after, primary_before,
                    "regular encrypted save kdf_allocation fault must not modify the primary",
                );
                no_tmp_residue(&path);
            }
        }
    });
}

#[test]
fn encrypted_open_kdf_allocation_failure_surfaces_io_error() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        // Establish a committed encrypted primary so the fault fires
        // during the unlock KDF derivation, not during create.
        let _ = Store::create(&path, VaultInit::Encrypted(kdf_encrypted_options()))
            .expect("setup: create encrypted primary");
        let primary_before = std::fs::read(&path).expect("read primary before fault");

        let err = with_fault(KDF, || {
            Store::open(
                &path,
                VaultLock::Encrypted(SecretString::from(KDF_PASSPHRASE.to_string())),
            )
        })
        .map(|_| ())
        .expect_err("kdf_allocation fault must fail Store::open");

        assert_kdf_allocation_io_error(&err);
        // Open is a read-only path: the KDF runs after the header is
        // parsed but before any `Vault` is constructed, so the file
        // bytes must be byte-identical and no temp siblings appear.
        let primary_after = std::fs::read(&path).expect("read primary after fault");
        assert_eq!(
            primary_after, primary_before,
            "encrypted open must not mutate the primary on a kdf_allocation fault",
        );
        no_tmp_residue(&path);

        // A subsequent unfaulted open must succeed — the fault did not
        // corrupt the on-disk header, the AEAD key cache, or any
        // intermediate state.
        let (_vault, _store) = Store::open(
            &path,
            VaultLock::Encrypted(SecretString::from(KDF_PASSPHRASE.to_string())),
        )
        .expect("unfaulted reopen must succeed after kdf_allocation fault");
    });
}

#[test]
fn kdf_allocation_fault_reaches_every_encrypted_kdf_site() {
    run_serial(|| {
        // Coverage row: each currently-implemented Argon2id derivation
        // site must surface the same `io_error { operation:
        // "kdf_allocation" }` when the hook fires. Phase H / Phase I
        // will extend this list with `set_passphrase`,
        // `change_passphrase`, `remove_passphrase`, and
        // `export::encrypted` rows.
        let dir = test_tempdir();

        // Site 1: encrypted create on a fresh path.
        let path1 = vault_path_in(&dir);
        let err1 = with_fault(KDF, || {
            Store::create(&path1, VaultInit::Encrypted(kdf_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("create");
        assert_kdf_allocation_io_error(&err1);

        // Site 2: encrypted create_force over an existing primary.
        let dir2 = test_tempdir();
        let path2 = vault_path_in(&dir2);
        let _ = Store::create(&path2, VaultInit::Encrypted(kdf_encrypted_options())).unwrap();
        let err2 = with_fault(KDF, || {
            Store::create_force(&path2, VaultInit::Encrypted(kdf_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("create_force");
        assert_kdf_allocation_io_error(&err2);

        // Site 3: encrypted open on a committed primary.
        let dir3 = test_tempdir();
        let path3 = vault_path_in(&dir3);
        let _ = Store::create(&path3, VaultInit::Encrypted(kdf_encrypted_options())).unwrap();
        let err3 = with_fault(KDF, || {
            Store::open(
                &path3,
                VaultLock::Encrypted(SecretString::from(KDF_PASSPHRASE.to_string())),
            )
        })
        .map(|_| ())
        .expect_err("open");
        assert_kdf_allocation_io_error(&err3);
    });
}

#[test]
fn kdf_allocation_fault_value_does_not_trip_pre_or_post_commit_paths() {
    run_serial(|| {
        // Plaintext save has no KDF — the `kdf_allocation` fault value
        // must not accidentally fire a pre/post-commit hook there.
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();
        with_fault(KDF, || vault.save(&store))
            .expect("plaintext save must succeed under kdf_allocation fault");
        no_tmp_residue(&path);
    });
}

// ──────────────────────────────────────────────────────────────────
// Vault::hotp_advance rollback / durability (Phase G.5)
//
// `hotp_advance` mutates the in-memory counter and `updated_at` then
// routes through `Vault::save`. A pre-commit save fault must roll
// the in-memory state back to its pre-call values so the user does
// not see a counter advance that was never persisted; a post-commit
// fault leaves the mutated state in place because the primary file
// has already been renamed into position and a subsequent peek must
// match the on-disk counter.
// ──────────────────────────────────────────────────────────────────

const HOTP_SECRET_B32: &str = "JBSWY3DPEHPK3PXP";

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn later_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_001_000)
}

fn make_hotp_account(label: &str, counter: u64) -> Account {
    let uri = format!("otpauth://hotp/{label}?secret={HOTP_SECRET_B32}&counter={counter}");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

#[test]
fn hotp_advance_pre_commit_rolls_counter_and_updated_at_back() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        let id = vault.add(make_hotp_account("alice", 5));
        // Persist the baseline so the pre-commit fault has a primary
        // to leave authoritative.
        vault.save(&store).unwrap();
        let pre_counter = vault.get(id).unwrap().counter();
        let pre_updated_at = vault.get(id).unwrap().updated_at();
        let primary_before = std::fs::read(&path).unwrap();

        let err = with_fault(PRE, || vault.hotp_advance(&store, id, later_now()))
            .map(|_| ())
            .expect_err("pre_commit must fail");
        assert_save_not_committed(&err, false);

        // In-memory state reverted to pre-call values.
        assert_eq!(vault.get(id).unwrap().counter(), pre_counter);
        assert_eq!(vault.get(id).unwrap().updated_at(), pre_updated_at);
        // On-disk primary unchanged.
        assert_eq!(std::fs::read(&path).unwrap(), primary_before);
    });
}

#[test]
fn hotp_advance_post_commit_keeps_mutation_and_surfaces_durability_unconfirmed() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        let id = vault.add(make_hotp_account("alice", 5));
        vault.save(&store).unwrap();
        let pre_counter = vault.get(id).unwrap().counter().unwrap();

        let err = with_fault(POST, || vault.hotp_advance(&store, id, later_now()))
            .map(|_| ())
            .expect_err("post_commit must fail");
        assert_save_durability_unconfirmed(&err);

        // Mutated state remains in memory because the primary file
        // commit point was reached — a subsequent peek would need to
        // match the on-disk counter.
        assert_eq!(vault.get(id).unwrap().counter(), Some(pre_counter + 1));
        assert_eq!(vault.get(id).unwrap().updated_at(), 1_700_001_000);

        // The primary file holds the post-advance bytes; reopening
        // surfaces the new counter to confirm the post-commit fault
        // fired after the rename.
        drop(vault);
        drop(store);
        let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).unwrap();
        assert_eq!(
            reopened.get(id).unwrap().counter(),
            Some(pre_counter + 1),
            "post-commit fault must leave the renamed primary in place",
        );
    });
}

// ──────────────────────────────────────────────────────────────────
// Vault::mutate_and_save (Phase G.9 / G.10).
//
// The closure-error rollback case is fault-free and lives in
// `vault_mutate_and_save.rs`. The save-error rollback rows live
// here because they require the `PALADIN_AUTH_FAULT_INJECT` hook and
// must serialize on the shared env-var mutex.
//
// Locked semantics, per docs/DESIGN.md §4.7:
//   - `save_not_committed`           → restore the snapshot
//   - `save_durability_unconfirmed`  → keep the mutated state in memory
//
// G.10 covers the cross-field variant: a single closure that
// mutates accounts AND every `VaultSettings` field must roll back
// (or retain) both jointly, never half-applying.
// ──────────────────────────────────────────────────────────────────

fn make_totp_account_for_mutate(label: &str) -> Account {
    let uri = format!("otpauth://totp/{label}?secret={HOTP_SECRET_B32}");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

#[test]
fn mutate_and_save_save_not_committed_restores_snapshot() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        let alice_id = vault.add(make_totp_account_for_mutate("alice"));
        vault.save(&store).unwrap();
        let primary_before = std::fs::read(&path).unwrap();
        let pre_settings = *vault.settings();

        let err = with_fault(PRE, || {
            vault.mutate_and_save(&store, |v| -> Result<(), PaladinAuthError> {
                v.add(make_totp_account_for_mutate("bob"));
                Ok(())
            })
        })
        .expect_err("pre_commit must fail");
        // Regular-save pre-commit leaves the old primary authoritative,
        // so `backup_path` is None per §5.
        assert_save_not_committed(&err, false);

        // Snapshot restore: the closure's mutation reverted in memory
        // because the §4.3 atomic write pipeline did not commit.
        let labels: Vec<_> = vault.iter().map(|a| a.label().to_string()).collect();
        assert_eq!(labels, vec!["alice"]);
        assert!(vault.get(alice_id).is_some());
        assert_eq!(*vault.settings(), pre_settings);
        // On-disk primary remains the pre-call snapshot byte-for-byte.
        assert_eq!(std::fs::read(&path).unwrap(), primary_before);
    });
}

#[test]
fn mutate_and_save_save_durability_unconfirmed_keeps_mutated_state() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.add(make_totp_account_for_mutate("alice"));
        vault.save(&store).unwrap();

        let err = with_fault(POST, || {
            vault.mutate_and_save(&store, |v| -> Result<(), PaladinAuthError> {
                v.add(make_totp_account_for_mutate("bob"));
                Ok(())
            })
        })
        .expect_err("post_commit must fail");
        assert_save_durability_unconfirmed(&err);

        // Post-commit fault: the primary-file rename succeeded before
        // the parent fsync errored, so memory keeps the mutation to
        // match the on-disk vault.
        let labels: Vec<_> = vault.iter().map(|a| a.label().to_string()).collect();
        assert_eq!(labels, vec!["alice", "bob"]);

        // Reopen confirms the on-disk vault carries the new account.
        drop(vault);
        drop(store);
        let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).unwrap();
        let reopened_labels: Vec<_> = reopened.iter().map(|a| a.label().to_string()).collect();
        assert_eq!(reopened_labels, vec!["alice", "bob"]);
    });
}

#[test]
fn mutate_and_save_cross_field_save_not_committed_restores_both_fields() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        let alice_id = vault.add(make_totp_account_for_mutate("alice"));
        vault.save(&store).unwrap();
        let pre_settings = *vault.settings();

        let err = with_fault(PRE, || {
            vault.mutate_and_save(&store, |v| -> Result<(), PaladinAuthError> {
                v.add(make_totp_account_for_mutate("bob"));
                v.set_auto_lock_enabled(true);
                v.set_clipboard_clear_secs(120)?;
                Ok(())
            })
        })
        .expect_err("pre_commit must fail");
        // Regular-save pre-commit leaves the old primary authoritative,
        // so `backup_path` is None per §5.
        assert_save_not_committed(&err, false);

        // Both accounts and settings reverted jointly.
        let labels: Vec<_> = vault.iter().map(|a| a.label().to_string()).collect();
        assert_eq!(labels, vec!["alice"]);
        assert!(vault.get(alice_id).is_some());
        assert_eq!(*vault.settings(), pre_settings);
        assert!(!vault.settings().auto_lock_enabled());
        assert_eq!(vault.settings().clipboard_clear_secs(), 20);
    });
}

#[test]
fn mutate_and_save_cross_field_save_durability_unconfirmed_keeps_both_fields() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.add(make_totp_account_for_mutate("alice"));
        vault.save(&store).unwrap();

        let err = with_fault(POST, || {
            vault.mutate_and_save(&store, |v| -> Result<(), PaladinAuthError> {
                v.add(make_totp_account_for_mutate("bob"));
                v.set_auto_lock_enabled(true);
                v.set_clipboard_clear_secs(120)?;
                Ok(())
            })
        })
        .expect_err("post_commit must fail");
        assert_save_durability_unconfirmed(&err);

        // Both accounts and settings retained because the rename
        // committed; in-memory state must match what's on disk.
        let labels: Vec<_> = vault.iter().map(|a| a.label().to_string()).collect();
        assert_eq!(labels, vec!["alice", "bob"]);
        assert!(vault.settings().auto_lock_enabled());
        assert_eq!(vault.settings().clipboard_clear_secs(), 120);

        drop(vault);
        drop(store);
        let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).unwrap();
        let reopened_labels: Vec<_> = reopened.iter().map(|a| a.label().to_string()).collect();
        assert_eq!(reopened_labels, vec!["alice", "bob"]);
        assert!(reopened.settings().auto_lock_enabled());
        assert_eq!(reopened.settings().clipboard_clear_secs(), 120);
    });
}

// ──────────────────────────────────────────────────────────────────
// Vault::edit_account_metadata rollback (Phase M).
//
// Mirrors the rename-rollback contract — a pre-commit save failure
// on an `edit_account_metadata` call routed through
// `Vault::mutate_and_save` must restore the `Account`'s `label`,
// `issuer`, `icon_hint`, and `updated_at` to their pre-call byte
// values. Pins that both mutators share one rollback-correctness
// contract.
// ──────────────────────────────────────────────────────────────────

#[test]
fn edit_account_metadata_mutate_and_save_pre_commit_rolls_back_all_fields() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = vault_path_in(&dir);
        let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        // Seed with an account that has a known issuer + icon_hint so
        // we can prove every field rolls back.
        let uri = format!("otpauth://totp/Acme:alice?secret={HOTP_SECRET_B32}");
        let stored = parse_otpauth(&uri, fixture_now()).unwrap();
        let id = vault.add(stored.account);
        vault.save(&store).unwrap();
        let primary_before = std::fs::read(&path).unwrap();

        let pre_label = vault.get(id).unwrap().label().to_string();
        let pre_issuer = vault.get(id).unwrap().issuer().map(str::to_string);
        let pre_icon = vault.get(id).unwrap().icon_hint().map(str::to_string);
        let pre_updated_at = vault.get(id).unwrap().updated_at();

        let err = with_fault(PRE, || {
            vault.mutate_and_save(&store, |v| -> Result<(), PaladinAuthError> {
                let edit = AccountEdit {
                    label: Some("alice-prime".to_string()),
                    issuer: Some(Some("NewCorp".to_string())),
                    icon_hint: Some(IconHintInput::Slug("newcorp".to_string())),
                };
                v.edit_account_metadata(id, edit, later_now())
            })
        })
        .expect_err("pre_commit must fail");
        assert_save_not_committed(&err, false);

        // Every editable field reverted to its pre-call value, plus
        // updated_at.
        let after = vault.get(id).unwrap();
        assert_eq!(after.label(), pre_label);
        assert_eq!(after.issuer().map(str::to_string), pre_issuer);
        assert_eq!(after.icon_hint().map(str::to_string), pre_icon);
        assert_eq!(after.updated_at(), pre_updated_at);
        // On-disk primary unchanged.
        assert_eq!(std::fs::read(&path).unwrap(), primary_before);
    });
}

// ──────────────────────────────────────────────────────────────────
// destroy_vault — its parent-directory fsync reuses the post_commit
// injection point, but maps a fired fault to `io_error` rather than
// `save_durability_unconfirmed` (docs/DESIGN.md §4.3 step 5).
// ──────────────────────────────────────────────────────────────────

#[test]
fn destroy_vault_post_commit_surfaces_fsync_vault_dir_partial() {
    run_serial(|| {
        let dir = test_tempdir();
        let path = dir.path().join("vault.bin");
        let bak = dir.path().join("vault.bin.bak");
        // destroy_vault is file-level and skips the §4.3 perms gate, so
        // a byte blob is a faithful primary + backup pair.
        std::fs::write(&path, b"primary bytes").unwrap();
        std::fs::write(&bak, b"backup bytes").unwrap();

        let err = with_fault(POST, || destroy_vault(&path)).expect_err("post_commit must fail");

        // The fault fires only after both unlinks, so the error reports
        // the completed state and serializes as `io_error`, not
        // `save_durability_unconfirmed`.
        assert_eq!(err.kind(), ErrorKind::IoError);
        match err {
            PaladinAuthError::DestroyIoError {
                operation,
                primary_deleted,
                backup_deleted,
                ..
            } => {
                assert_eq!(operation, "fsync_vault_dir");
                assert!(primary_deleted, "primary was unlinked before the fsync");
                assert!(backup_deleted, "backup was unlinked before the fsync");
            }
            other => panic!("expected DestroyIoError, got {other:?}"),
        }

        // Both files are genuinely gone — only durability is unconfirmed.
        assert!(!path.exists(), "primary must be unlinked");
        assert!(!bak.exists(), "backup must be unlinked");
    });
}
