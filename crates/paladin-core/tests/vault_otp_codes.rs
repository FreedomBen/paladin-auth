// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.7: read-only OTP code projections on `Vault`
// (DESIGN.md §4.2 / §4.7).
//
// Covers the happy-path semantics of `Vault::hotp_peek` and
// `Vault::totp_code`: both are `&self`, neither mutates the in-memory
// vault, and neither touches the `Store`. A `hotp_peek` after a
// committed `hotp_advance` observes the new (post-advance) counter.
// Validation-error ordering for these methods is covered separately
// in the upcoming account-ID stable-error tests.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{parse_otpauth, Account, Store, Vault, VaultInit};
use tempfile::TempDir;

/// Base32-encoded RFC 4226 / RFC 6238 SHA1 reference key
/// ("12345678901234567890" ASCII bytes).
const RFC_SHA1_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn at_unix(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn make_hotp_account(label: &str, counter: u64) -> Account {
    let uri = format!(
        "otpauth://hotp/{label}?secret={RFC_SHA1_SECRET_B32}&counter={counter}&algorithm=SHA1&digits=6",
    );
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn make_totp_account(label: &str, period: u32, digits: u8) -> Account {
    let uri = format!(
        "otpauth://totp/{label}?secret={RFC_SHA1_SECRET_B32}&algorithm=SHA1&digits={digits}&period={period}",
    );
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn vault_with_path() -> (Vault, Store, TempDir) {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    (vault, store, dir)
}

// ---- hotp_peek ----------------------------------------------------

#[test]
fn hotp_peek_returns_code_for_current_stored_counter() {
    // §4.2: HOTP RFC 4226 Appendix D: counter 7 → "162583".
    let (mut vault, _store, _dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 7));

    let code = vault.hotp_peek(id).expect("hotp_peek must succeed");

    assert_eq!(code.code, "162583");
    assert_eq!(code.counter_used, Some(7));
    // §4.2: HOTP `Code` projections leave TOTP validity fields as `None`.
    assert!(code.valid_from.is_none());
    assert!(code.valid_until.is_none());
    assert!(code.seconds_remaining.is_none());
}

#[test]
fn hotp_peek_is_idempotent_and_stable_across_repeat_calls() {
    // §4.2: peek never advances the counter, so successive calls
    // without an intervening `hotp_advance` return the same code.
    let (mut vault, _store, _dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 3));

    let first = vault.hotp_peek(id).unwrap();
    let second = vault.hotp_peek(id).unwrap();
    let third = vault.hotp_peek(id).unwrap();

    assert_eq!(first.code, second.code);
    assert_eq!(second.code, third.code);
    assert_eq!(first.counter_used, Some(3));
    // The stored counter is untouched.
    assert_eq!(vault.get(id).unwrap().counter(), Some(3));
}

#[test]
fn hotp_peek_after_committed_hotp_advance_returns_post_advance_counter_code() {
    // §4.7: `hotp_advance` returns the *pre-advance* code and bumps
    // the stored counter to `prev + 1`. A subsequent `hotp_peek` must
    // therefore observe the new counter, not the one that was just
    // emitted — this is the user-visible "next code" the UI renders.
    let (mut vault, store, _dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 0));

    // Pre-advance peek: RFC 4226 Appendix D, counter 0 → "755224".
    let pre_advance = vault.hotp_peek(id).expect("pre-advance peek");
    assert_eq!(pre_advance.code, "755224");
    assert_eq!(pre_advance.counter_used, Some(0));

    // Advance: emits the same counter-0 code, persists counter 1.
    let advanced = vault
        .hotp_advance(&store, id, fixture_now())
        .expect("hotp_advance must commit");
    assert_eq!(advanced.code, "755224");
    assert_eq!(advanced.counter_used, Some(0));

    // Post-advance peek now reflects counter 1: RFC vector → "287082".
    let post_advance = vault.hotp_peek(id).expect("post-advance peek");
    assert_eq!(post_advance.code, "287082");
    assert_eq!(post_advance.counter_used, Some(1));

    // The post-advance peek does not match the pre-advance peek —
    // the §4.2 sequence has actually shifted by one counter.
    assert_ne!(pre_advance.code, post_advance.code);

    // Repeated peeks remain stable on the new counter (still 1).
    let post_advance_again = vault.hotp_peek(id).unwrap();
    assert_eq!(post_advance_again.code, post_advance.code);
    assert_eq!(post_advance_again.counter_used, Some(1));
}

#[test]
fn hotp_peek_does_not_mutate_vault_or_touch_store() {
    // §4.7: peek is read-only. After persisting a baseline vault,
    // calling `hotp_peek` must leave the on-disk primary file
    // byte-identical and must not bump `counter` or `updated_at`.
    let (mut vault, store, dir) = vault_with_path();
    let id = vault.add(make_hotp_account("alice", 5));
    vault.save(&store).expect("baseline save");
    let path = dir.path().join("vault.bin");
    let primary_before = std::fs::read(&path).unwrap();
    let pre_counter = vault.get(id).unwrap().counter();
    let pre_updated_at = vault.get(id).unwrap().updated_at();

    let _ = vault.hotp_peek(id).expect("hotp_peek must succeed");

    assert_eq!(vault.get(id).unwrap().counter(), pre_counter);
    assert_eq!(vault.get(id).unwrap().updated_at(), pre_updated_at);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        primary_before,
        "hotp_peek must not rewrite the primary vault file",
    );
}

// ---- totp_code ----------------------------------------------------

#[test]
fn totp_code_matches_rfc6238_sha1_vector() {
    // §4.2: RFC 6238 Appendix B SHA1 key, period=30, digits=8 →
    // T = 59 yields "94287082" with the active counter being
    // `floor(59 / 30) = 1`.
    let (mut vault, _store, _dir) = vault_with_path();
    let id = vault.add(make_totp_account("alice", 30, 8));

    let code = vault.totp_code(id, at_unix(59)).expect("totp_code");

    assert_eq!(code.code, "94287082");
    // §4.2: TOTP projections leave `counter_used` unset and populate
    // the half-open validity window `[valid_from, valid_until)`.
    assert!(code.counter_used.is_none());
    assert_eq!(code.valid_from, Some(30));
    assert_eq!(code.valid_until, Some(60));
    // `seconds_remaining = valid_until - now`; at t=59 that is 1.
    assert_eq!(code.seconds_remaining, Some(1));
}

#[test]
fn totp_code_tracks_now_across_window_boundaries() {
    // §4.2: window selection is `floor(now / period)`. Stepping `now`
    // across the period boundary advances the active counter and
    // shifts the validity window by exactly `period` seconds.
    let (mut vault, _store, _dir) = vault_with_path();
    let id = vault.add(make_totp_account("alice", 30, 8));

    let inside = vault.totp_code(id, at_unix(59)).unwrap();
    let boundary = vault.totp_code(id, at_unix(60)).unwrap();

    assert_eq!(inside.valid_from, Some(30));
    assert_eq!(inside.valid_until, Some(60));
    assert_eq!(boundary.valid_from, Some(60));
    assert_eq!(boundary.valid_until, Some(90));
    // The active counter shifted, so the codes must differ.
    assert_ne!(inside.code, boundary.code);
    // On the exact boundary, `seconds_remaining` reports the full
    // period (DESIGN §4.2 half-open window invariant).
    assert_eq!(boundary.seconds_remaining, Some(30));
}

#[test]
fn totp_code_does_not_mutate_vault_or_touch_store() {
    // §4.7: `totp_code` takes `&self` and never persists. After
    // persisting a baseline vault, repeated calls at varying `now`
    // must leave the on-disk primary file byte-identical and must
    // not bump `updated_at`.
    let (mut vault, store, dir) = vault_with_path();
    let id = vault.add(make_totp_account("alice", 30, 8));
    vault.save(&store).expect("baseline save");
    let path = dir.path().join("vault.bin");
    let primary_before = std::fs::read(&path).unwrap();
    let pre_updated_at = vault.get(id).unwrap().updated_at();

    let _ = vault.totp_code(id, at_unix(59)).expect("totp_code at 59");
    let _ = vault
        .totp_code(id, at_unix(1_111_111_109))
        .expect("totp_code at later vector");
    let _ = vault.totp_code(id, at_unix(60)).expect("totp_code at 60");

    assert_eq!(vault.get(id).unwrap().updated_at(), pre_updated_at);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        primary_before,
        "totp_code must not rewrite the primary vault file",
    );
}
