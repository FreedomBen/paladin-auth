// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.12 — `account_match_key(&Account)` (DESIGN.md §4.7, §5).
//
// Pin the canonical `"{issuer}:{label}"` projection used by all front
// ends to match accounts. The colon is always present so callers can
// compare both halves uniformly even when the issuer is empty; the
// helper preserves the user's original casing because callers apply
// `str::to_lowercase()` themselves at compare time
// (`account_matches_search`, see Phase G.13).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    account_match_key, validate_manual, Account, AccountInput, AccountKindInput, Algorithm,
    IconHintInput,
};
use secrecy::SecretString;

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn input(label: &str, issuer: Option<&str>) -> AccountInput {
    AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    }
}

fn account(label: &str, issuer: Option<&str>) -> Account {
    validate_manual(input(label, issuer), fixture_now())
        .expect("valid manual input")
        .account
}

#[test]
fn empty_issuer_keeps_colon_prefix() {
    let acct = account("alice", None);
    assert_eq!(account_match_key(&acct), ":alice");
}

#[test]
fn whitespace_only_issuer_collapses_to_empty_and_keeps_colon() {
    // `validate_issuer` trims to empty → stores `None`, so the helper
    // still emits the leading colon. Pins the §5 contract that the
    // colon is structural, not derived from the issuer being present.
    let acct = account("alice", Some("   "));
    assert_eq!(account_match_key(&acct), ":alice");
}

#[test]
fn ascii_issuer_label_pair_uses_canonical_form() {
    let acct = account("alice", Some("Acme"));
    assert_eq!(account_match_key(&acct), "Acme:alice");
}

#[test]
fn preserves_mixed_case_in_issuer_and_label() {
    let acct = account("Alice@Example.COM", Some("AcmeCorp"));
    let key = account_match_key(&acct);
    assert_eq!(key, "AcmeCorp:Alice@Example.COM");
    // Sanity: the helper does not silently lowercase. A regression to
    // `to_lowercase()` would make this `key == key.to_lowercase()`.
    assert_ne!(key, key.to_lowercase());
}

#[test]
fn preserves_unicode_label_without_normalization() {
    // U+00E9 (precomposed `é`, NFC form, 2 UTF-8 bytes) versus
    // U+0065 U+0301 (`e` + combining acute, NFD form, 3 UTF-8 bytes).
    // Both render identically but their byte sequences differ; the
    // helper applies no normalization and must keep them distinct so
    // a regression to `unicode_normalization::nfc()` (or similar) is
    // caught here.
    let nfc = account("café", Some("Issuer"));
    let nfd = account("cafe\u{0301}", Some("Issuer"));
    assert_eq!(account_match_key(&nfc), "Issuer:café");
    assert_eq!(account_match_key(&nfd), "Issuer:cafe\u{0301}");
    assert_ne!(account_match_key(&nfc), account_match_key(&nfd));
}

#[test]
fn preserves_unicode_in_issuer() {
    // Non-ASCII issuer characters (Cyrillic Я) are passed through
    // verbatim with no transliteration / case folding.
    let acct = account("user", Some("Яндекс"));
    assert_eq!(account_match_key(&acct), "Яндекс:user");
}

#[test]
fn shared_issuer_label_pair_round_trips_equality() {
    // Two accounts with identical (issuer, label) but different
    // secrets produce equal match keys, so callers can use the key as
    // a deduplication / lookup key without worrying about secrets
    // bleeding into comparisons.
    let mut a = input("alice", Some("Acme"));
    let mut b = input("alice", Some("Acme"));
    a.secret = SecretString::from("JBSWY3DPEHPK3PXP".to_string());
    b.secret = SecretString::from("KRSXG5DPOJUW4ZJANRSXG43A".to_string());
    let acct_a = validate_manual(a, fixture_now()).unwrap().account;
    let acct_b = validate_manual(b, fixture_now()).unwrap().account;
    assert_eq!(account_match_key(&acct_a), account_match_key(&acct_b));
}

#[test]
fn distinct_issuer_or_label_produces_distinct_keys() {
    let alice_acme = account("alice", Some("Acme"));
    let alice_other = account("alice", Some("OtherCorp"));
    let bob_acme = account("bob", Some("Acme"));
    let alice_no_issuer = account("alice", None);

    assert_ne!(
        account_match_key(&alice_acme),
        account_match_key(&alice_other)
    );
    assert_ne!(
        account_match_key(&alice_acme),
        account_match_key(&bob_acme)
    );
    assert_ne!(
        account_match_key(&alice_acme),
        account_match_key(&alice_no_issuer)
    );
}
