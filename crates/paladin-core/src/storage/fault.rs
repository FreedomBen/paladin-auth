// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Save-pipeline fault injection (docs/DESIGN.md §10 / Phase E.7).
//
// Compiled in only when the `test-fault-injection` cargo feature is
// enabled — production builds get the no-op stubs at the bottom so
// the fault checks compile away. The hook honors the
// `PALADIN_FAULT_INJECT=pre_commit|post_commit|csprng_read|kdf_allocation`
// env var:
//
// * `pre_commit` — return true at the pre-rename injection point so
//   the surrounding save site bails out via its existing
//   `save_not_committed` error path. The destination is left
//   unchanged from the operation's perspective: any leftover tempfile
//   is best-effort unlinked, and the typed error reports
//   `committed: false` plus an optional `backup_path` (set when the
//   save site rotates the old primary out of `vault.bin` ahead of the
//   rename — e.g. `init --force`'s clobber — so the caller knows
//   where to find the previous vault content; regular saves leave the
//   old primary at `vault.bin` and report `backup_path: None` per
//   docs/DESIGN.md §5).
//
// * `post_commit` — return true at the post-rename / parent-fsync
//   injection point so the surrounding save site bails out via its
//   existing `save_durability_unconfirmed` error path. The
//   destination is in place but a power loss before the next durable
//   write to its parent directory may lose the rename.
//
// * `csprng_read` — return true at every OS CSPRNG draw used to
//   generate Argon2 salts and XChaCha20-Poly1305 nonces in the
//   encrypted-write pipeline (Phase F.15 / docs/DESIGN.md §5). The
//   surrounding generator surfaces `io_error { operation:
//   "csprng_read" }` and the encrypted save / create / create_force
//   path bails out before staging any tempfile, so no partial vault
//   bytes hit disk and pre-existing primaries are left untouched.
//
// * `kdf_allocation` — return true at every Argon2id key-derivation
//   call in both encrypted-write and encrypted-read pipelines (Phase
//   F.16 / docs/DESIGN.md §5). The surrounding wrapper short-circuits the
//   real KDF and surfaces `io_error { operation: "kdf_allocation" }`
//   without panicking, so a host that runs out of memory while
//   deriving the AEAD key fails cleanly. On write paths no partial
//   vault file is written and pre-existing primaries are left
//   untouched; on the open / unlock path no `Vault` is constructed.
//
// The hook applies uniformly to every atomic-write site in
// `paladin-core`: regular `save_plaintext`, `save_plaintext_clobber`
// (the `init --force` clobber path), and `write_secret_file_atomic`
// (the shared export writer). When Phase F lands the encrypted save
// pipeline and the passphrase-transition surfaces (`set_passphrase`,
// `change_passphrase`, `remove_passphrase`), those sites call into
// these same two checks so the cross-save-site coverage test in
// `tests/fault_injection.rs` extends with two more rows per surface
// without changing the hook. The `csprng_read` value extends the same
// matrix to every encrypted-write surface that draws fresh salt or
// nonce bytes from the OS. The `kdf_allocation` value extends the
// matrix to every encrypted-read and encrypted-write surface that
// runs the Argon2id derivation, including `Store::open`.
//
// Excluded from the stable §4.7 public API — the constants and
// behavior here are an internal contract between the test surface
// and the save sites, not a downstream extension point.

#[cfg(feature = "test-fault-injection")]
const ENV: &str = "PALADIN_FAULT_INJECT";

#[cfg(feature = "test-fault-injection")]
const PRE_COMMIT_VALUE: &str = "pre_commit";

#[cfg(feature = "test-fault-injection")]
const POST_COMMIT_VALUE: &str = "post_commit";

#[cfg(feature = "test-fault-injection")]
const CSPRNG_READ_VALUE: &str = "csprng_read";

#[cfg(feature = "test-fault-injection")]
const KDF_ALLOCATION_VALUE: &str = "kdf_allocation";

/// Returns `true` when the pre-commit fault should fire at the call
/// site — i.e. the `test-fault-injection` cargo feature is enabled and
/// `PALADIN_FAULT_INJECT=pre_commit` is set in the process environment.
/// Always `false` on production builds.
#[inline]
pub(crate) fn pre_commit_should_fail() -> bool {
    #[cfg(feature = "test-fault-injection")]
    {
        std::env::var(ENV).as_deref() == Ok(PRE_COMMIT_VALUE)
    }
    #[cfg(not(feature = "test-fault-injection"))]
    {
        false
    }
}

/// Returns `true` when the post-commit fault should fire at the call
/// site — i.e. the `test-fault-injection` cargo feature is enabled and
/// `PALADIN_FAULT_INJECT=post_commit` is set in the process environment.
/// Always `false` on production builds.
#[inline]
pub(crate) fn post_commit_should_fail() -> bool {
    #[cfg(feature = "test-fault-injection")]
    {
        std::env::var(ENV).as_deref() == Ok(POST_COMMIT_VALUE)
    }
    #[cfg(not(feature = "test-fault-injection"))]
    {
        false
    }
}

/// Returns `true` when the CSPRNG-read fault should fire at the call
/// site — i.e. the `test-fault-injection` cargo feature is enabled and
/// `PALADIN_FAULT_INJECT=csprng_read` is set in the process
/// environment. Wired into every Argon2 salt / AEAD nonce generator in
/// the encrypted save pipeline so the surrounding code can surface
/// `io_error { operation: "csprng_read" }` deterministically. Always
/// `false` on production builds.
#[inline]
pub(crate) fn csprng_read_should_fail() -> bool {
    #[cfg(feature = "test-fault-injection")]
    {
        std::env::var(ENV).as_deref() == Ok(CSPRNG_READ_VALUE)
    }
    #[cfg(not(feature = "test-fault-injection"))]
    {
        false
    }
}

/// Returns `true` when the Argon2id allocation fault should fire at
/// the call site — i.e. the `test-fault-injection` cargo feature is
/// enabled and `PALADIN_FAULT_INJECT=kdf_allocation` is set in the
/// process environment. Wired around every Argon2id derivation in the
/// encrypted save / open pipeline so the surrounding code can surface
/// `io_error { operation: "kdf_allocation" }` without panicking and
/// without writing any partial vault bytes. Always `false` on
/// production builds.
#[inline]
pub(crate) fn kdf_allocation_should_fail() -> bool {
    #[cfg(feature = "test-fault-injection")]
    {
        std::env::var(ENV).as_deref() == Ok(KDF_ALLOCATION_VALUE)
    }
    #[cfg(not(feature = "test-fault-injection"))]
    {
        false
    }
}

#[cfg(all(test, feature = "test-fault-injection"))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-var manipulation is process-wide, so the hook tests below
    // serialize on a single mutex. Keep this lock private to this
    // module — the integration tests in `tests/fault_injection.rs`
    // hold their own lock for the same reason.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap();
        match value {
            Some(v) => std::env::set_var(ENV, v),
            None => std::env::remove_var(ENV),
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        std::env::remove_var(ENV);
        match result {
            Ok(v) => v,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    #[test]
    fn pre_commit_fires_only_for_pre_commit_value() {
        with_env(Some(PRE_COMMIT_VALUE), || {
            assert!(pre_commit_should_fail());
            assert!(!post_commit_should_fail());
            assert!(!csprng_read_should_fail());
            assert!(!kdf_allocation_should_fail());
        });
    }

    #[test]
    fn post_commit_fires_only_for_post_commit_value() {
        with_env(Some(POST_COMMIT_VALUE), || {
            assert!(!pre_commit_should_fail());
            assert!(post_commit_should_fail());
            assert!(!csprng_read_should_fail());
            assert!(!kdf_allocation_should_fail());
        });
    }

    #[test]
    fn csprng_read_fires_only_for_csprng_read_value() {
        with_env(Some(CSPRNG_READ_VALUE), || {
            assert!(!pre_commit_should_fail());
            assert!(!post_commit_should_fail());
            assert!(csprng_read_should_fail());
            assert!(!kdf_allocation_should_fail());
        });
    }

    #[test]
    fn kdf_allocation_fires_only_for_kdf_allocation_value() {
        with_env(Some(KDF_ALLOCATION_VALUE), || {
            assert!(!pre_commit_should_fail());
            assert!(!post_commit_should_fail());
            assert!(!csprng_read_should_fail());
            assert!(kdf_allocation_should_fail());
        });
    }

    #[test]
    fn unknown_value_fires_neither() {
        // Garbage values are silently ignored — only the four
        // reserved strings activate the hook so a stray
        // `PALADIN_FAULT_INJECT=1` in the environment cannot
        // accidentally drive a save into a failure mode.
        with_env(Some("garbage"), || {
            assert!(!pre_commit_should_fail());
            assert!(!post_commit_should_fail());
            assert!(!csprng_read_should_fail());
            assert!(!kdf_allocation_should_fail());
        });
    }

    #[test]
    fn absent_var_fires_neither() {
        with_env(None, || {
            assert!(!pre_commit_should_fail());
            assert!(!post_commit_should_fail());
            assert!(!csprng_read_should_fail());
            assert!(!kdf_allocation_should_fail());
        });
    }
}
