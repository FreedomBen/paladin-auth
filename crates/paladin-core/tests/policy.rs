// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `policy` module behavior (DESIGN.md §6 / §7,
// IMPLEMENTATION_PLAN_01_CORE.md Phase G.18 / G.19 / G.20).
//
// The `policy` module owns the timer math and decision protocols
// shared by the TUI and the GTK GUI:
//
//   * `policy::auto_lock::IdlePolicy` — encrypted-only gating, idle
//     next-deadline arithmetic, and monotonic-expiry comparison.
//   * `policy::clipboard_clear::ClipboardClearPolicy` — schedule
//     decision, monotonic token issuance, only-if-unchanged
//     byte-equality decision.
//   * `policy::hotp_reveal::deadline` — HOTP reveal countdown
//     deadline shared by the TUI reveal panel and the GTK GUI
//     reveal panel.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use paladin_core::policy::auto_lock::IdlePolicy;
use paladin_core::policy::clipboard_clear::{ClipboardClearPolicy, ClipboardClearToken};
use paladin_core::policy::hotp_reveal;
use paladin_core::{
    Argon2Params, EncryptionOptions, Store, Vault, VaultInit, VaultSettings, HOTP_REVEAL_SECS,
};
use secrecy::SecretString;

// `ClipboardClearPolicy::schedule` advances a process-wide monotonic
// counter, so any test that relies on strictly adjacent token issuance
// (`token_n.successor() == token_{n+1}`) must serialize against every
// other test in this binary that calls `schedule`. Tests that only
// inspect token relationships in isolation, or that exercise
// `should_clear` byte equality, do not need to hold the lock.
static SCHEDULE_LOCK: Mutex<()> = Mutex::new(());

fn schedule_lock() -> std::sync::MutexGuard<'static, ()> {
    SCHEDULE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn empty_plaintext_vault() -> Vault {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault
}

fn empty_encrypted_vault() -> Vault {
    // A cheap in-bounds Argon2 profile keeps the test snappy; the
    // policy only reads `&VaultSettings` and never touches the KDF.
    let cheap = Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    };
    let opts = EncryptionOptions::with_params(SecretString::from("hunter2".to_string()), cheap)
        .expect("cheap params are in §4.4 bounds and the passphrase is non-empty");
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, _store) = Store::create(&path, VaultInit::Encrypted(opts)).unwrap();
    vault
}

// ---------------------------------------------------------------------------
// IdlePolicy::should_arm
// ---------------------------------------------------------------------------

#[test]
fn should_arm_true_only_when_encrypted_and_auto_lock_enabled() {
    let mut vault = empty_encrypted_vault();
    vault.set_auto_lock_enabled(true);
    let settings = vault.settings();
    assert!(IdlePolicy::should_arm(true, settings));
}

#[test]
fn should_arm_false_when_encrypted_but_auto_lock_disabled() {
    // Default `VaultSettings::auto_lock_enabled` is false (DESIGN §5).
    let settings = VaultSettings::default();
    assert!(!settings.auto_lock_enabled());
    assert!(!IdlePolicy::should_arm(true, &settings));
}

#[test]
fn should_arm_false_for_plaintext_even_when_auto_lock_enabled() {
    // Plaintext vaults never arm auto-lock — DESIGN §6 / §7
    // plaintext no-op rule, pinned in core rather than in front ends.
    let mut vault = empty_plaintext_vault();
    vault.set_auto_lock_enabled(true);
    let settings = vault.settings();
    assert!(settings.auto_lock_enabled());
    assert!(!IdlePolicy::should_arm(false, settings));
}

#[test]
fn should_arm_false_for_plaintext_when_auto_lock_disabled() {
    let settings = VaultSettings::default();
    assert!(!IdlePolicy::should_arm(false, &settings));
}

// ---------------------------------------------------------------------------
// IdlePolicy::next_deadline
// ---------------------------------------------------------------------------

#[test]
fn next_deadline_armed_returns_now_plus_timeout_secs() {
    let mut vault = empty_encrypted_vault();
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(45).unwrap();
    let settings = vault.settings();

    let now = Instant::now();
    let got = IdlePolicy::next_deadline(now, true, settings);

    assert_eq!(got, Some(now + Duration::from_secs(45)));
}

#[test]
fn next_deadline_armed_uses_default_timeout_300_when_unchanged() {
    let mut vault = empty_encrypted_vault();
    vault.set_auto_lock_enabled(true);
    let settings = vault.settings();
    assert_eq!(settings.auto_lock_timeout_secs(), 300);

    let now = Instant::now();
    let got = IdlePolicy::next_deadline(now, true, settings);

    assert_eq!(got, Some(now + Duration::from_secs(300)));
}

#[test]
fn next_deadline_returns_none_when_encrypted_but_auto_lock_disabled() {
    let settings = VaultSettings::default();
    let now = Instant::now();
    assert_eq!(IdlePolicy::next_deadline(now, true, &settings), None);
}

#[test]
fn next_deadline_returns_none_for_plaintext_regardless_of_auto_lock_enabled() {
    let mut vault = empty_plaintext_vault();
    vault.set_auto_lock_enabled(true);
    let settings = vault.settings();

    let now = Instant::now();
    assert_eq!(IdlePolicy::next_deadline(now, false, settings), None);

    let default = VaultSettings::default();
    assert_eq!(IdlePolicy::next_deadline(now, false, &default), None);
}

#[test]
fn next_deadline_at_max_timeout_does_not_overflow_and_matches_24h() {
    let mut vault = empty_encrypted_vault();
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(86_400).unwrap();
    let settings = vault.settings();

    let now = Instant::now();
    let got = IdlePolicy::next_deadline(now, true, settings);
    assert_eq!(got, Some(now + Duration::from_secs(86_400)));
}

// ---------------------------------------------------------------------------
// IdlePolicy::is_expired
// ---------------------------------------------------------------------------

#[test]
fn is_expired_false_strictly_before_deadline() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(10);
    assert!(!IdlePolicy::is_expired(deadline, now));
}

#[test]
fn is_expired_true_at_deadline_boundary() {
    // Monotonic comparison is `now >= deadline` — equality counts as
    // expired so a tick that lands exactly on the deadline fires the
    // lock.
    let now = Instant::now();
    let deadline = now;
    assert!(IdlePolicy::is_expired(deadline, now));
}

#[test]
fn is_expired_true_after_deadline() {
    let earlier = Instant::now();
    let deadline = earlier + Duration::from_millis(1);
    let later = deadline + Duration::from_secs(1);
    assert!(IdlePolicy::is_expired(deadline, later));
}

// ---------------------------------------------------------------------------
// ClipboardClearPolicy::schedule — disabled cases
// ---------------------------------------------------------------------------

#[test]
fn schedule_returns_none_when_clipboard_clear_disabled_default() {
    // Default `VaultSettings::clipboard_clear_enabled` is false (DESIGN §5).
    let _guard = schedule_lock();
    let settings = VaultSettings::default();
    assert!(!settings.clipboard_clear_enabled());
    let now = Instant::now();
    assert_eq!(ClipboardClearPolicy::schedule(now, &settings), None);
}

#[test]
fn schedule_returns_none_when_disabled_with_custom_clear_secs() {
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_secs(60).unwrap();
    let settings = vault.settings();
    assert!(!settings.clipboard_clear_enabled());
    let now = Instant::now();
    assert_eq!(ClipboardClearPolicy::schedule(now, settings), None);
}

// ---------------------------------------------------------------------------
// ClipboardClearPolicy::schedule — enabled cases (deadline arithmetic)
// ---------------------------------------------------------------------------

#[test]
fn schedule_enabled_returns_now_plus_clear_secs() {
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    vault.set_clipboard_clear_secs(45).unwrap();
    let settings = vault.settings();

    let now = Instant::now();
    let (_, deadline) = ClipboardClearPolicy::schedule(now, settings).expect("scheduled");
    assert_eq!(deadline, now + Duration::from_secs(45));
}

#[test]
fn schedule_enabled_uses_default_clear_secs_20_when_unchanged() {
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    let settings = vault.settings();
    assert_eq!(settings.clipboard_clear_secs(), 20);

    let now = Instant::now();
    let (_, deadline) = ClipboardClearPolicy::schedule(now, settings).expect("scheduled");
    assert_eq!(deadline, now + Duration::from_secs(20));
}

#[test]
fn schedule_enabled_at_min_clear_secs_5() {
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    vault.set_clipboard_clear_secs(5).unwrap();
    let settings = vault.settings();

    let now = Instant::now();
    let (_, deadline) = ClipboardClearPolicy::schedule(now, settings).expect("scheduled");
    assert_eq!(deadline, now + Duration::from_secs(5));
}

#[test]
fn schedule_enabled_at_max_clear_secs_600() {
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    vault.set_clipboard_clear_secs(600).unwrap();
    let settings = vault.settings();

    let now = Instant::now();
    let (_, deadline) = ClipboardClearPolicy::schedule(now, settings).expect("scheduled");
    assert_eq!(deadline, now + Duration::from_secs(600));
}

#[test]
fn schedule_does_not_gate_on_encryption_unlike_auto_lock() {
    // `ClipboardClearPolicy` schedules clears for both plaintext and
    // encrypted vaults — the §6 / §7 plaintext no-op rule applies to
    // auto-lock, not to clipboard wiping. The CLI ignores the policy
    // entirely (it's stateless), but TUI and GUI both honor it.
    let _guard = schedule_lock();

    let mut plaintext = empty_plaintext_vault();
    plaintext.set_clipboard_clear_enabled(true);
    let now = Instant::now();
    assert!(ClipboardClearPolicy::schedule(now, plaintext.settings()).is_some());

    let mut encrypted = empty_encrypted_vault();
    encrypted.set_clipboard_clear_enabled(true);
    let now = Instant::now();
    assert!(ClipboardClearPolicy::schedule(now, encrypted.settings()).is_some());
}

// ---------------------------------------------------------------------------
// ClipboardClearPolicy::schedule — monotonic token issuance
// ---------------------------------------------------------------------------

#[test]
fn schedule_tokens_are_monotonically_issued_with_successor_adjacency() {
    // `token_n.successor() == token_{n+1}` per Phase G.19 contract:
    // every successful `schedule` increments the process-wide token
    // counter by exactly one.
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    let settings = vault.settings();

    let (t1, _) = ClipboardClearPolicy::schedule(Instant::now(), settings).expect("scheduled");
    let (t2, _) = ClipboardClearPolicy::schedule(Instant::now(), settings).expect("scheduled");
    assert_eq!(t1.successor(), t2);
    assert!(t1 < t2);
    assert_ne!(t1, t2);
}

#[test]
fn schedule_does_not_advance_token_counter_when_disabled() {
    // A `schedule` call that returns `None` must not advance the
    // global token counter, otherwise token issuance would not be
    // strictly contiguous across enable / disable transitions.
    let _guard = schedule_lock();
    let mut vault_on = empty_plaintext_vault();
    vault_on.set_clipboard_clear_enabled(true);

    let vault_off = empty_plaintext_vault();
    assert!(!vault_off.settings().clipboard_clear_enabled());

    let (t1, _) =
        ClipboardClearPolicy::schedule(Instant::now(), vault_on.settings()).expect("scheduled");
    assert_eq!(
        ClipboardClearPolicy::schedule(Instant::now(), vault_off.settings()),
        None
    );
    let (t2, _) =
        ClipboardClearPolicy::schedule(Instant::now(), vault_on.settings()).expect("scheduled");

    // The disabled call between the two enabled calls did not advance
    // the counter, so successor adjacency still holds.
    assert_eq!(t1.successor(), t2);
}

// ---------------------------------------------------------------------------
// ClipboardClearToken — derived behavior
// ---------------------------------------------------------------------------

#[test]
fn token_equality_is_reflexive_under_copy() {
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    let (t, _) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings()).expect("scheduled");
    let copied: ClipboardClearToken = t;
    assert_eq!(t, copied);
}

#[test]
fn token_distinct_issuances_are_unequal() {
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    let (t1, _) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings()).expect("scheduled");
    let (t2, _) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings()).expect("scheduled");
    assert_ne!(t1, t2);
}

#[test]
fn token_successor_is_strictly_greater_purely() {
    // `successor` must produce a strictly greater token without
    // touching the global counter — pure on a token value.
    let _guard = schedule_lock();
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    let (t1, _) =
        ClipboardClearPolicy::schedule(Instant::now(), vault.settings()).expect("scheduled");
    let s1 = t1.successor();
    let s2 = s1.successor();
    assert!(t1 < s1);
    assert!(s1 < s2);
    assert!(t1 < s2);
    assert_ne!(t1, s1);
    assert_ne!(s1, s2);
}

// ---------------------------------------------------------------------------
// ClipboardClearPolicy::should_clear — only-if-unchanged byte equality
// ---------------------------------------------------------------------------

#[test]
fn should_clear_true_when_bytes_match() {
    assert!(ClipboardClearPolicy::should_clear(b"123456", b"123456"));
}

#[test]
fn should_clear_false_when_bytes_differ_same_length() {
    assert!(!ClipboardClearPolicy::should_clear(b"123456", b"654321"));
    assert!(!ClipboardClearPolicy::should_clear(b"abcdef", b"abcdeg"));
}

#[test]
fn should_clear_false_when_lengths_differ() {
    assert!(!ClipboardClearPolicy::should_clear(b"123456", b"12345"));
    assert!(!ClipboardClearPolicy::should_clear(b"12345", b"123456"));
    assert!(!ClipboardClearPolicy::should_clear(b"123456", b"1234567"));
}

#[test]
fn should_clear_handles_empty_slices() {
    assert!(ClipboardClearPolicy::should_clear(b"", b""));
    assert!(!ClipboardClearPolicy::should_clear(b"", b"x"));
    assert!(!ClipboardClearPolicy::should_clear(b"x", b""));
}

#[test]
fn should_clear_treats_non_utf8_bytes_byte_for_byte() {
    // The clipboard adapter passes raw bytes — the policy must not
    // reinterpret them as UTF-8 or normalize them.
    let captured: &[u8] = &[0xff, 0x00, 0x80, 0x7f];
    let same: &[u8] = &[0xff, 0x00, 0x80, 0x7f];
    let different: &[u8] = &[0xff, 0x00, 0x80, 0x7e];
    assert!(ClipboardClearPolicy::should_clear(captured, same));
    assert!(!ClipboardClearPolicy::should_clear(captured, different));
}

// ---------------------------------------------------------------------------
// Crate-root re-export — guards against an internal-module-only surface
// ---------------------------------------------------------------------------

#[test]
fn clipboard_clear_policy_and_token_reachable_at_crate_root() {
    // Both the policy struct and the token newtype must be reachable
    // through `paladin_core::ClipboardClearPolicy` and
    // `paladin_core::ClipboardClearToken` so a refactor that moves
    // internal modules cannot silently drop the surface.
    let _: paladin_core::ClipboardClearPolicy;
    let _: Option<(paladin_core::ClipboardClearToken, Instant)> =
        paladin_core::ClipboardClearPolicy::schedule(Instant::now(), &VaultSettings::default());
}

// ---------------------------------------------------------------------------
// hotp_reveal::deadline — pure addition pinned to HOTP_REVEAL_SECS
// ---------------------------------------------------------------------------

#[test]
fn hotp_reveal_deadline_is_now_plus_hotp_reveal_secs_exactly() {
    // The TUI reveal countdown and the GUI reveal countdown both
    // source their deadline through this function so a config change
    // to `HOTP_REVEAL_SECS` updates both presentation crates without
    // either having to hard-code the duration.
    let now = Instant::now();
    let got = hotp_reveal::deadline(now);
    assert_eq!(got, now + Duration::from_secs(HOTP_REVEAL_SECS));
}

#[test]
fn hotp_reveal_deadline_uses_pinned_120_second_horizon() {
    // `HOTP_REVEAL_SECS` is pinned at 120 by `ui_contract`; the
    // deadline must equal `now + 120 s` for that exact value, so a
    // future refactor that moves the constant cannot silently change
    // the reveal horizon.
    assert_eq!(HOTP_REVEAL_SECS, 120);
    let now = Instant::now();
    assert_eq!(hotp_reveal::deadline(now), now + Duration::from_secs(120));
}

#[test]
fn hotp_reveal_deadline_is_pure_with_respect_to_now() {
    // Distinct `now` inputs produce deadlines that differ by exactly
    // the same offset — proves the function is a pure addition with
    // no hidden state and no clock sampling.
    let now_a = Instant::now();
    let now_b = now_a + Duration::from_secs(7);
    let got_a = hotp_reveal::deadline(now_a);
    let got_b = hotp_reveal::deadline(now_b);
    assert_eq!(got_a, now_a + Duration::from_secs(HOTP_REVEAL_SECS));
    assert_eq!(got_b, now_b + Duration::from_secs(HOTP_REVEAL_SECS));
    // Same call with the same input is deterministic (idempotent).
    assert_eq!(hotp_reveal::deadline(now_a), got_a);
}

#[test]
fn hotp_reveal_deadline_reachable_at_crate_root_re_export() {
    // The policy's deadline function must be reachable at the crate
    // root as `paladin_core::hotp_reveal_deadline` so a refactor that
    // moves the internal module cannot silently drop the surface
    // (matches the IdlePolicy / ClipboardClearPolicy precedent).
    let now = Instant::now();
    let got: Instant = paladin_core::hotp_reveal_deadline(now);
    assert_eq!(got, now + Duration::from_secs(HOTP_REVEAL_SECS));
    // The submodule path must continue to resolve to the same function
    // so callers can pick whichever import style fits their crate.
    assert_eq!(got, paladin_core::policy::hotp_reveal::deadline(now));
}
