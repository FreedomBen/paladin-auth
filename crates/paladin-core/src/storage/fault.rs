// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Save-pipeline fault injection (DESIGN.md §10 / Phase E.7).
//
// Compiled in only when the `test-fault-injection` cargo feature is
// enabled — production builds get the no-op stubs at the bottom so
// the fault checks compile away. The hook honors the
// `PALADIN_FAULT_INJECT=pre_commit|post_commit` env var:
//
// * `pre_commit` — return true at the pre-rename injection point so
//   the surrounding save site bails out via its existing
//   `save_not_committed` error path. The destination is left
//   unchanged from the operation's perspective: any leftover tempfile
//   is best-effort unlinked, and the typed error reports
//   `committed: false` plus the rotated `backup_path` (when the save
//   site rotates a `.bak` ahead of the rename) so the caller can
//   reason about commit state without inspecting a source error.
//
// * `post_commit` — return true at the post-rename / parent-fsync
//   injection point so the surrounding save site bails out via its
//   existing `save_durability_unconfirmed` error path. The
//   destination is in place but a power loss before the next durable
//   write to its parent directory may lose the rename.
//
// The hook applies uniformly to every atomic-write site in
// `paladin-core`: regular `save_plaintext`, `save_plaintext_clobber`
// (the `init --force` clobber path), and `write_secret_file_atomic`
// (the shared export writer). When Phase F lands the encrypted save
// pipeline and the passphrase-transition surfaces (`set_passphrase`,
// `change_passphrase`, `remove_passphrase`), those sites call into
// these same two checks so the cross-save-site coverage test in
// `tests/fault_injection.rs` extends with two more rows per surface
// without changing the hook.
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
        });
    }

    #[test]
    fn post_commit_fires_only_for_post_commit_value() {
        with_env(Some(POST_COMMIT_VALUE), || {
            assert!(!pre_commit_should_fail());
            assert!(post_commit_should_fail());
        });
    }

    #[test]
    fn unknown_value_fires_neither() {
        // Garbage values are silently ignored — only the two reserved
        // strings activate the hook so a stray `PALADIN_FAULT_INJECT=1`
        // in the environment cannot accidentally drive a save into a
        // failure mode.
        with_env(Some("garbage"), || {
            assert!(!pre_commit_should_fail());
            assert!(!post_commit_should_fail());
        });
    }

    #[test]
    fn absent_var_fires_neither() {
        with_env(None, || {
            assert!(!pre_commit_should_fail());
            assert!(!post_commit_should_fail());
        });
    }
}
