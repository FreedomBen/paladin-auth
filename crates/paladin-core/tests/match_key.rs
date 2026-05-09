// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.12 — `account_match_key(&Account)` (DESIGN.md §4.7, §5).
// Phase G.13 — `account_matches_search(&Account, query)` (DESIGN.md §4.7, §5).
//
// Pin the canonical `"{issuer}:{label}"` projection used by all front
// ends to match accounts. The colon is always present so callers can
// compare both halves uniformly even when the issuer is empty; the
// helper preserves the user's original casing because
// `account_matches_search` lowercases both sides at compare time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    account_match_key, account_matches_search, validate_manual, Account, AccountInput,
    AccountKindInput, Algorithm, IconHintInput,
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
    assert_ne!(account_match_key(&alice_acme), account_match_key(&bob_acme));
    assert_ne!(
        account_match_key(&alice_acme),
        account_match_key(&alice_no_issuer)
    );
}

// ---------------------------------------------------------------------------
// Phase G.13 — `account_matches_search(&Account, query)`.
//
// The predicate lowercases both `account_match_key(account)` and `query`
// with `str::to_lowercase()` and tests substring containment. The empty
// query matches every account; the leading colon for empty-issuer
// accounts stays observable to the predicate; no Unicode normalization
// or locale-specific casing is applied.

#[test]
fn empty_query_matches_any_account() {
    // Pins the §5 list-filter rule: an empty search bar matches every
    // account so the visible list is the full vault contents.
    let acct = account("alice", Some("Acme"));
    assert!(account_matches_search(&acct, ""));

    let no_issuer = account("alice", None);
    assert!(account_matches_search(&no_issuer, ""));
}

#[test]
fn substring_match_on_label_is_case_insensitive() {
    let acct = account("Alice@Example.COM", Some("AcmeCorp"));
    assert!(account_matches_search(&acct, "alice"));
    assert!(account_matches_search(&acct, "ALICE"));
    assert!(account_matches_search(&acct, "AlIcE"));
    assert!(account_matches_search(&acct, "example.com"));
    // Substring need not start at the boundary.
    assert!(account_matches_search(&acct, "ce@ex"));
}

#[test]
fn substring_match_on_issuer_is_case_insensitive() {
    let acct = account("alice", Some("AcmeCorp"));
    assert!(account_matches_search(&acct, "acme"));
    assert!(account_matches_search(&acct, "ACMECORP"));
    assert!(account_matches_search(&acct, "mecor"));
}

#[test]
fn substring_match_spans_the_colon_separator() {
    // The match key is `"AcmeCorp:alice"`, so the predicate sees the
    // colon between issuer and label and must allow queries that span
    // it. Pins the §5 contract that the separator is part of the
    // searchable surface, not stripped at compare time.
    let acct = account("alice", Some("AcmeCorp"));
    assert!(account_matches_search(&acct, "corp:al"));
    assert!(account_matches_search(&acct, "p:a"));
    assert!(account_matches_search(&acct, ":"));
}

#[test]
fn empty_issuer_colon_is_searchable_for_no_issuer_accounts() {
    // No-issuer account's match key is `":alice"`. The leading colon
    // must remain visible to the predicate so callers can specifically
    // surface no-issuer rows by typing a leading colon.
    let no_issuer = account("alice", None);
    assert!(account_matches_search(&no_issuer, ":"));
    assert!(account_matches_search(&no_issuer, ":alice"));
    assert!(account_matches_search(&no_issuer, ":a"));

    // Sanity: an account with an issuer also contains a colon in its
    // match key (`"Acme:alice"`), so a bare `:` matches it too. The
    // leading-colon discriminator is a UI affordance, not a hard
    // empty-issuer filter on its own.
    let with_issuer = account("alice", Some("Acme"));
    assert!(account_matches_search(&with_issuer, ":"));
}

#[test]
fn non_matching_query_returns_false() {
    let acct = account("alice", Some("Acme"));
    assert!(!account_matches_search(&acct, "bob"));
    assert!(!account_matches_search(&acct, "othercorp"));
    assert!(!account_matches_search(&acct, "zzz"));
}

#[test]
fn no_unicode_normalization_in_search() {
    // U+00E9 (precomposed `é`, NFC) versus U+0065 U+0301 (`e` + combining
    // acute, NFD). Their byte sequences differ; `account_matches_search`
    // applies no normalization, so an NFC query against an NFD label
    // (or vice versa) must miss. Guards against a regression to
    // `unicode_normalization::nfc()` (or similar) during search.
    let nfc = account("café", Some("Issuer"));
    let nfd = account("cafe\u{0301}", Some("Issuer"));

    // Same-form match succeeds.
    assert!(account_matches_search(&nfc, "café"));
    assert!(account_matches_search(&nfd, "cafe\u{0301}"));

    // Cross-form match fails — pin the no-normalization behavior.
    assert!(!account_matches_search(&nfc, "cafe\u{0301}"));
    assert!(!account_matches_search(&nfd, "café"));
}

#[test]
fn lowercase_uses_unicode_default_no_locale_folding() {
    // Cyrillic Я (U+042F) lowercases to я (U+044F) under
    // `str::to_lowercase()` regardless of locale; the predicate must
    // honor that mapping without applying locale-specific rules
    // (e.g. Turkish dotless-i). We assert two things:
    //   1. Cyrillic case folding via the standard library mapping works.
    //   2. Latin `i`/`I` round-trip through ASCII case folding (the
    //      Turkish dotless-i convention is **not** applied — that
    //      would be locale-dependent behavior).
    let cyr = account("user", Some("Яндекс"));
    assert!(account_matches_search(&cyr, "яндекс"));
    assert!(account_matches_search(&cyr, "ЯНДЕКС"));

    // Latin small/capital `i` fold to each other under
    // `str::to_lowercase()`. A locale-aware Turkish lower-casing would
    // map `I` → `ı` (U+0131, dotless) and could break this assertion.
    let ascii = account("Iris", Some("Acme"));
    assert!(account_matches_search(&ascii, "iris"));
    assert!(account_matches_search(&ascii, "IRIS"));
}
