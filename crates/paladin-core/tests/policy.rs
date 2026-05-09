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
//     byte-equality decision (later phase).
//   * `policy::hotp_reveal::deadline` — HOTP reveal countdown
//     deadline (later phase).
//
// This file pins the IdlePolicy contract; the other two land with the
// next plan bullets.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use paladin_core::policy::auto_lock::IdlePolicy;
use paladin_core::{Argon2Params, EncryptionOptions, Store, Vault, VaultInit, VaultSettings};
use secrecy::SecretString;

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
