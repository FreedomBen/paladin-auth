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
    write_secret_file_atomic, ErrorKind, PaladinError, Store, VaultInit, VaultLock, VaultMode,
};
use tempfile::TempDir;

const ENV: &str = "PALADIN_FAULT_INJECT";
const PRE: &str = "pre_commit";
const POST: &str = "post_commit";

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
