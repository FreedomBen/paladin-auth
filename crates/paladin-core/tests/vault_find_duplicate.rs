// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.3: `Vault::find_duplicate` (docs/DESIGN.md §4.7 `impl Vault`).
//
// Front ends call this to render the §5 `duplicate_account` error
// without re-implementing the secret/issuer/label comparison. Core
// owns the secret-bearing comparison; presentation layers handle
// the user-facing error and any "add anyway" / `--allow-duplicate`
// policy.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{parse_otpauth, Store, ValidatedAccount, Vault, VaultInit};

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// Build a `ValidatedAccount` directly — `Vault::find_duplicate`
/// takes one. The otpauth parser produces a `ValidatedAccount`,
/// so we go through it for shape parity with the real call sites.
fn validated(label: &str, issuer: Option<&str>, secret_b32: &str) -> ValidatedAccount {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret={secret_b32}");
    parse_otpauth(&uri, fixture_now()).unwrap()
}

fn empty_plaintext_vault() -> Vault {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault
}

const SECRET_A: &str = "JBSWY3DPEHPK3PXP";
const SECRET_B: &str = "GEZDGNBVGY3TQOJQ";

#[test]
fn returns_none_on_empty_vault() {
    let vault = empty_plaintext_vault();
    let candidate = validated("alice", Some("Acme"), SECRET_A);
    assert!(vault.find_duplicate(&candidate).is_none());
}

#[test]
fn returns_some_for_exact_secret_issuer_label_collision() {
    let mut vault = empty_plaintext_vault();
    let stored = validated("alice", Some("Acme"), SECRET_A);
    let stored_id = stored.account.id();
    vault.add(stored.account);

    // A fresh ValidatedAccount with identical (secret, issuer, label)
    // but a different `AccountId` (parse_otpauth allocates a new ID)
    // should still report the existing stored entry as the duplicate.
    let candidate = validated("alice", Some("Acme"), SECRET_A);
    let hit = vault.find_duplicate(&candidate).expect("expected match");
    assert_eq!(hit.id(), stored_id);
    assert_eq!(hit.label(), "alice");
    assert_eq!(hit.issuer(), Some("Acme"));
}

#[test]
fn returns_none_when_secret_differs() {
    let mut vault = empty_plaintext_vault();
    vault.add(validated("alice", Some("Acme"), SECRET_A).account);
    let candidate = validated("alice", Some("Acme"), SECRET_B);
    assert!(vault.find_duplicate(&candidate).is_none());
}

#[test]
fn returns_none_when_label_differs() {
    let mut vault = empty_plaintext_vault();
    vault.add(validated("alice", Some("Acme"), SECRET_A).account);
    let candidate = validated("bob", Some("Acme"), SECRET_A);
    assert!(vault.find_duplicate(&candidate).is_none());
}

#[test]
fn returns_none_when_issuer_differs() {
    let mut vault = empty_plaintext_vault();
    vault.add(validated("alice", Some("Acme"), SECRET_A).account);
    let candidate = validated("alice", Some("Other"), SECRET_A);
    assert!(vault.find_duplicate(&candidate).is_none());
}

#[test]
fn issuer_comparison_is_case_sensitive() {
    // §5 / `account_match_key` keeps original casing; case-folding
    // happens at the front-end search layer, not at the duplicate
    // check. Front ends apply `--allow-duplicate` policy anyway, so
    // a true exact-match check is the right primitive here.
    let mut vault = empty_plaintext_vault();
    vault.add(validated("alice", Some("Acme"), SECRET_A).account);
    let candidate = validated("alice", Some("acme"), SECRET_A);
    assert!(vault.find_duplicate(&candidate).is_none());
}

#[test]
fn label_comparison_is_case_sensitive() {
    let mut vault = empty_plaintext_vault();
    vault.add(validated("Alice", Some("Acme"), SECRET_A).account);
    let candidate = validated("alice", Some("Acme"), SECRET_A);
    assert!(vault.find_duplicate(&candidate).is_none());
}

#[test]
fn issuer_none_does_not_match_some_with_same_label_and_secret() {
    let mut vault = empty_plaintext_vault();
    // Stored account has no issuer.
    vault.add(validated("alice", None, SECRET_A).account);
    // Candidate has issuer Some("Acme").
    let candidate = validated("alice", Some("Acme"), SECRET_A);
    assert!(vault.find_duplicate(&candidate).is_none());
    // And the reverse symmetry: stored Some, candidate None.
    let mut vault2 = empty_plaintext_vault();
    vault2.add(validated("alice", Some("Acme"), SECRET_A).account);
    let candidate2 = validated("alice", None, SECRET_A);
    assert!(vault2.find_duplicate(&candidate2).is_none());
}

#[test]
fn issuer_none_matches_issuer_none_with_same_label_and_secret() {
    let mut vault = empty_plaintext_vault();
    let stored_id = {
        let v = validated("alice", None, SECRET_A);
        let id = v.account.id();
        vault.add(v.account);
        id
    };
    let candidate = validated("alice", None, SECRET_A);
    let hit = vault.find_duplicate(&candidate).expect("expected match");
    assert_eq!(hit.id(), stored_id);
    assert_eq!(hit.issuer(), None);
}

#[test]
fn returns_first_match_when_multiple_collisions_exist() {
    // The vault should not normally contain two identical entries —
    // duplicate detection prevents that — but a corrupted or
    // hand-edited vault could. `find_duplicate` reports the first
    // collision in insertion order so the front-end error is
    // deterministic in that case.
    let mut vault = empty_plaintext_vault();
    let first = validated("alice", Some("Acme"), SECRET_A);
    let first_id = first.account.id();
    vault.add(first.account);
    let second = validated("alice", Some("Acme"), SECRET_A);
    vault.add(second.account);

    let candidate = validated("alice", Some("Acme"), SECRET_A);
    let hit = vault.find_duplicate(&candidate).expect("expected match");
    assert_eq!(hit.id(), first_id);
}

#[test]
fn finds_cross_kind_collision_on_secret_issuer_label_match() {
    // §5: the `(secret, issuer, label)` triple is the duplicate
    // equivalence relation — TOTP-vs-HOTP `kind` is not part of it.
    // A stored TOTP account therefore collides with an incoming HOTP
    // candidate sharing the triple, so the front-end "duplicate_account"
    // warning surfaces regardless of kind mismatch. Pins the rule that
    // `find_duplicate` ignores kind so a future "scope duplicates per
    // kind" change cannot land without flipping this test.
    let mut vault = empty_plaintext_vault();
    let totp_uri = format!("otpauth://totp/Acme:alice?secret={SECRET_A}");
    let stored = parse_otpauth(&totp_uri, fixture_now()).unwrap();
    let stored_id = stored.account.id();
    vault.add(stored.account);

    let hotp_uri = format!("otpauth://hotp/Acme:alice?secret={SECRET_A}&counter=0");
    let candidate = parse_otpauth(&hotp_uri, fixture_now()).unwrap();
    let hit = vault.find_duplicate(&candidate).expect("cross-kind hit");
    assert_eq!(hit.id(), stored_id);
}

#[test]
fn ignores_unrelated_fields_like_digits_or_period() {
    // Two TOTP accounts with identical (secret, issuer, label) but
    // different `digits` / `period` are still duplicates per §5 —
    // the secret-bearing tuple is the equivalence relation.
    let mut vault = empty_plaintext_vault();
    let stored_uri = format!("otpauth://totp/Acme:alice?secret={SECRET_A}&digits=6&period=30");
    let stored = parse_otpauth(&stored_uri, fixture_now()).unwrap();
    let stored_id = stored.account.id();
    vault.add(stored.account);

    let candidate_uri = format!("otpauth://totp/Acme:alice?secret={SECRET_A}&digits=8&period=60");
    let candidate = parse_otpauth(&candidate_uri, fixture_now()).unwrap();
    let hit = vault.find_duplicate(&candidate).expect("expected match");
    assert_eq!(hit.id(), stored_id);
}

#[test]
fn remove_clears_duplicate_hit_for_subsequent_find() {
    // Round-trip: a candidate that matches a stored account should
    // stop matching after the stored account is removed. Guards
    // against an internal cache or index that survives `remove` and
    // would let a stale duplicate hit linger.
    let mut vault = empty_plaintext_vault();
    let stored = validated("alice", Some("Acme"), SECRET_A);
    let stored_id = stored.account.id();
    vault.add(stored.account);

    let candidate = validated("alice", Some("Acme"), SECRET_A);
    let hit = vault.find_duplicate(&candidate).expect("hit before remove");
    assert_eq!(hit.id(), stored_id);

    let removed = vault.remove(stored_id).expect("alice removed");
    assert_eq!(removed.id(), stored_id);

    assert!(
        vault.find_duplicate(&candidate).is_none(),
        "find_duplicate must report no match after the colliding account is removed"
    );
}
