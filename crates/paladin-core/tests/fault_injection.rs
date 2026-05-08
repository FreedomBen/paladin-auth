// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Cross-save-site fault-injection coverage (DESIGN.md §10 / Phase E.7).
//
// Compiles and runs only with the `test-fault-injection` cargo feature
// enabled — production builds never see this surface. The shared hook
// in `paladin_core::storage::fault` honors `PALADIN_FAULT_INJECT` and
// must reach every atomic-write site uniformly. This file enumerates
// the (save_site × fault_phase) cells that exist today and asserts
// each one surfaces the right error: `pre_commit` →
// `save_not_committed`, `post_commit` →
// `save_durability_unconfirmed`.
//
// Phase F adds encrypted save and the passphrase-transition surfaces
// (`set_passphrase`, `change_passphrase`, `remove_passphrase`); those
// reuse the same hook and gain rows here when they land.
//
// Env-var manipulation is process-wide, so every test holds a single
// shared mutex for its full duration (setup + fault + assertions).
// `run_serial` clears the env var on entry and exit so a panicking
// test never leaves a fault state set for the next test.

#![cfg(feature = "test-fault-injection")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use paladin_core::{
    write_secret_file_atomic, Argon2Params, EncryptionOptions, ErrorKind, PaladinError, Store,
    VaultInit, VaultLock, VaultMode,
};
use secrecy::SecretString;
use tempfile::TempDir;

const ENV: &str = "PALADIN_FAULT_INJECT";
const PRE: &str = "pre_commit";
const POST: &str = "post_commit";
const CSPRNG: &str = "csprng_read";
const KDF: &str = "kdf_allocation";

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Run `f` while holding the shared env-var lock and ensure
/// `PALADIN_FAULT_INJECT` is unset on entry and exit. Every test in
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

/// Run `f` with `PALADIN_FAULT_INJECT=phase` set, restoring the
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

fn assert_save_not_committed(err: &PaladinError, expect_backup: bool) {
    assert_eq!(
        err.kind(),
        ErrorKind::SaveNotCommitted,
        "expected save_not_committed, got {err:?}"
    );
    match err {
        PaladinError::SaveNotCommitted {
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

fn assert_save_durability_unconfirmed(err: &PaladinError) {
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        assert!(!path.exists(), "primary must not exist after pre_commit fault");
        assert!(!path.with_file_name("vault.bin.bak").exists());
        no_tmp_residue(&path);
    });
}

#[test]
fn encrypted_create_post_commit_surfaces_save_durability_unconfirmed() {
    run_serial(|| {
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
    WriteSecretFileAtomic,
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    PreCommit,
    PostCommit,
}

fn drive(site: SaveSite, phase: Phase) -> PaladinError {
    let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
        let path = vault_path_in(&dir);
        // Establish a saved primary so a follow-up save on a synthetic
        // Store goes through the rotation path.
        {
            let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
            vault.save(&store).unwrap();
        }

        let synthetic = Store::for_test_fault_injection(path.clone(), VaultMode::Plaintext);
        // Reopen to get a Vault we can save through `synthetic`.
        let (vault, _store) = Store::open(&path, paladin_core::VaultLock::Plaintext).unwrap();

        let err = with_fault(PRE, || vault.save(&synthetic))
            .expect_err("pre_commit must fail through synthetic Store");
        // Regular save through the synthetic Store still routes through
        // `save_plaintext`, which leaves the old primary authoritative
        // and reports `backup_path: None` per §5.
        assert_save_not_committed(&err, false);
    });
}

// ──────────────────────────────────────────────────────────────────
// CSPRNG failure surface (Phase F.15 / DESIGN.md §5).
//
// Every encrypted-write site reads the OS CSPRNG to draw a fresh salt
// (encrypted `create` / `create_force`) or fresh nonce (every encrypted
// save, including the freshly-built initial save inside `create*`). A
// `getrandom::Error` from either call must surface as
// `io_error { operation: "csprng_read" }`, must not write a partial
// vault file, must not rotate or clobber any pre-existing primary, and
// must not leak intermediate plaintext to disk. The fault-injection
// hook reuses the existing `PALADIN_FAULT_INJECT` env-var contract with
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

fn assert_csprng_io_error(err: &PaladinError) {
    assert_eq!(
        err.kind(),
        ErrorKind::IoError,
        "expected io_error, got {err:?}"
    );
    match err {
        PaladinError::IoError { operation, .. } => {
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();

        // Site 1: encrypted create on a fresh path.
        let path1 = vault_path_in(&dir);
        let err1 = with_fault(CSPRNG, || {
            Store::create(&path1, VaultInit::Encrypted(cheap_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("create");
        assert_csprng_io_error(&err1);

        // Site 2: encrypted create_force over an existing primary.
        let dir2 = TempDir::new().unwrap();
        let path2 = vault_path_in(&dir2);
        let _ = Store::create(&path2, VaultInit::Encrypted(cheap_encrypted_options())).unwrap();
        let err2 = with_fault(CSPRNG, || {
            Store::create_force(&path2, VaultInit::Encrypted(cheap_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("create_force");
        assert_csprng_io_error(&err2);

        // Site 3: regular encrypted save on a reopened vault.
        let dir3 = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();
        with_fault(CSPRNG, || vault.save(&store))
            .expect("plaintext save must succeed under csprng_read fault");
        no_tmp_residue(&path);
    });
}

// ──────────────────────────────────────────────────────────────────
// Argon2id allocation failure surface (Phase F.16 / DESIGN.md §5).
//
// Every encrypted save / open path runs Argon2id to derive the 32-byte
// AEAD key. On a memory-constrained host the underlying allocator can
// fail after the §4.4 bounds have already passed; that failure must
// surface as `io_error { operation: "kdf_allocation" }` without
// panicking, must not write a partial vault file, must not rotate or
// clobber any pre-existing primary on write paths, and must not
// construct a `Vault` on the open path. The fault-injection hook
// reuses the existing `PALADIN_FAULT_INJECT` env-var contract with a
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

fn assert_kdf_allocation_io_error(err: &PaladinError) {
    assert_eq!(
        err.kind(),
        ErrorKind::IoError,
        "expected io_error, got {err:?}"
    );
    match err {
        PaladinError::IoError { operation, .. } => {
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();

        // Site 1: encrypted create on a fresh path.
        let path1 = vault_path_in(&dir);
        let err1 = with_fault(KDF, || {
            Store::create(&path1, VaultInit::Encrypted(kdf_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("create");
        assert_kdf_allocation_io_error(&err1);

        // Site 2: encrypted create_force over an existing primary.
        let dir2 = TempDir::new().unwrap();
        let path2 = vault_path_in(&dir2);
        let _ = Store::create(&path2, VaultInit::Encrypted(kdf_encrypted_options())).unwrap();
        let err2 = with_fault(KDF, || {
            Store::create_force(&path2, VaultInit::Encrypted(kdf_encrypted_options()))
        })
        .map(|_| ())
        .expect_err("create_force");
        assert_kdf_allocation_io_error(&err2);

        // Site 3: encrypted open on a committed primary.
        let dir3 = TempDir::new().unwrap();
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
        let dir = TempDir::new().unwrap();
        let path = vault_path_in(&dir);
        let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault.save(&store).unwrap();
        with_fault(KDF, || vault.save(&store))
            .expect("plaintext save must succeed under kdf_allocation fault");
        no_tmp_residue(&path);
    });
}
