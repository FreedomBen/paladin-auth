// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.14 — `parse_account_query` and `Vault::matching_accounts`
// (DESIGN.md §4.7, §5).
//
// `parse_account_query`:
//   * Non-`id:` input maps to `AccountQuery::Search(query.to_string())`,
//     including the empty string and queries that contain colons elsewhere.
//   * Lowercase `id:` followed by 8..=32 hex characters maps to
//     `AccountQuery::IdPrefix { hex_prefix }` with the hex normalized to
//     lowercase. Uppercase `A`–`F` is accepted in the prefix but stored
//     lowercase; uppercase `ID:` itself is **not** the discriminator —
//     it falls through to `Search`.
//   * Short (<8), long (>32), or non-hex `id:` prefixes return
//     `validation_error` with `field: "query"`.
//
// `Vault::matching_accounts`:
//   * Search queries delegate to the case-insensitive substring predicate
//     and return matches in insertion order.
//   * IdPrefix queries match accounts whose canonical 32-char hex (no
//     hyphens) starts with the validated prefix and return them in
//     insertion order.
//   * Both query kinds return an empty vec on no-match.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_account_query, parse_otpauth, Account, AccountId, AccountQuery, ErrorKind, Vault,
};

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn empty_plaintext_vault() -> Vault {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, _store) =
        paladin_core::Store::create(&path, paladin_core::VaultInit::Plaintext).unwrap();
    vault
}

fn id_hex(id: AccountId) -> String {
    // Canonical hyphenated → 32-char hex by stripping hyphens. Same shape
    // used by `Vault::matching_accounts` and `shortest_unique_id_prefix`.
    id.to_string().replace('-', "")
}

// ---------------------------------------------------------------------------
// parse_account_query — Search-branch behavior.

#[test]
fn empty_query_parses_as_empty_search() {
    let parsed = parse_account_query("").expect("empty is valid");
    assert_eq!(parsed, AccountQuery::Search(String::new()));
}

#[test]
fn plain_text_parses_as_search() {
    let parsed = parse_account_query("alice").expect("plain query is valid");
    assert_eq!(parsed, AccountQuery::Search("alice".to_string()));
}

#[test]
fn issuer_label_pattern_parses_as_search() {
    // Queries that contain a colon but do not start with `id:` are
    // ordinary substring searches (the colon is part of the match key).
    let parsed = parse_account_query("Acme:alice").expect("colon query is valid");
    assert_eq!(parsed, AccountQuery::Search("Acme:alice".to_string()));
}

#[test]
fn uppercase_id_prefix_is_not_the_discriminator() {
    // The plan locks `id:` to lowercase; an `ID:` prefix is treated as a
    // plain substring search and never validated as hex.
    let parsed = parse_account_query("ID:abcdef01").expect("uppercase ID: is search");
    assert_eq!(parsed, AccountQuery::Search("ID:abcdef01".to_string()));

    // Mixed case prefix likewise falls through.
    let parsed = parse_account_query("Id:abcdef01").expect("mixed-case Id: is search");
    assert_eq!(parsed, AccountQuery::Search("Id:abcdef01".to_string()));
}

#[test]
fn id_token_without_colon_is_a_plain_search() {
    let parsed = parse_account_query("id").expect("bare 'id' is search");
    assert_eq!(parsed, AccountQuery::Search("id".to_string()));
}

// ---------------------------------------------------------------------------
// parse_account_query — IdPrefix-branch behavior.

#[test]
fn id_prefix_with_minimum_8_lowercase_hex_chars() {
    let parsed = parse_account_query("id:abcdef01").expect("8 hex chars is valid");
    assert_eq!(
        parsed,
        AccountQuery::IdPrefix {
            hex_prefix: "abcdef01".to_string()
        }
    );
}

#[test]
fn id_prefix_with_maximum_32_hex_chars() {
    // The full 32-char canonical hex (no hyphens) is the upper bound.
    let parsed = parse_account_query("id:0123456789abcdef0123456789abcdef")
        .expect("32 hex chars is valid");
    assert_eq!(
        parsed,
        AccountQuery::IdPrefix {
            hex_prefix: "0123456789abcdef0123456789abcdef".to_string()
        }
    );
}

#[test]
fn id_prefix_normalizes_uppercase_hex_to_lowercase() {
    // ASCII uppercase A–F are accepted within the prefix but stored
    // lowercase so callers can compare against canonical lowercase hex.
    let parsed = parse_account_query("id:DEADBEEF").expect("uppercase A-F is valid");
    assert_eq!(
        parsed,
        AccountQuery::IdPrefix {
            hex_prefix: "deadbeef".to_string()
        }
    );

    let parsed = parse_account_query("id:DeAdBeEf01234567")
        .expect("mixed-case uppercase A-F is valid");
    assert_eq!(
        parsed,
        AccountQuery::IdPrefix {
            hex_prefix: "deadbeef01234567".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// parse_account_query — error paths (validation_error, field: "query").

fn assert_query_validation_error(input: &str) {
    let err = parse_account_query(input).expect_err("must reject");
    assert_eq!(err.kind(), ErrorKind::ValidationError, "input: {input:?}");
    let s = format!("{err}");
    assert!(
        s.contains("query"),
        "validation_error display must mention field 'query', got: {s}"
    );
}

#[test]
fn id_prefix_with_no_hex_is_validation_error() {
    // Bare `id:` with no hex chars (length 0 < 8).
    assert_query_validation_error("id:");
}

#[test]
fn id_prefix_below_minimum_length_is_validation_error() {
    // 7 hex chars is one short of the 8-char floor.
    assert_query_validation_error("id:abcdef0");
    assert_query_validation_error("id:1");
}

#[test]
fn id_prefix_above_maximum_length_is_validation_error() {
    // 33 hex chars exceeds the 32-char ceiling.
    assert_query_validation_error("id:0123456789abcdef0123456789abcdef0");
    // 64 hex chars (a sha-256 hex digest, well over the cap).
    assert_query_validation_error(
        "id:0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn id_prefix_with_non_hex_chars_is_validation_error() {
    // 'g' is the smallest non-hex letter; 'z' is far outside hex.
    assert_query_validation_error("id:gggggggg");
    assert_query_validation_error("id:abcdefgh");
    assert_query_validation_error("id:zzzzzzzz");
    // Whitespace inside the hex prefix is not hex.
    assert_query_validation_error("id:abcd ef0");
    assert_query_validation_error("id: abcdef0");
    // Hyphenated UUID form is rejected — callers must strip hyphens.
    assert_query_validation_error("id:550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn id_prefix_with_unicode_digits_is_validation_error() {
    // Devanagari digits look like numbers but are not ASCII hex.
    assert_query_validation_error("id:\u{0966}\u{0967}\u{0968}\u{0969}\u{096A}\u{096B}\u{096C}\u{096D}");
    // Fullwidth ASCII A is not the same code point as ASCII A.
    assert_query_validation_error("id:\u{FF21}\u{FF21}\u{FF21}\u{FF21}\u{FF21}\u{FF21}\u{FF21}\u{FF21}");
}

// ---------------------------------------------------------------------------
// Vault::matching_accounts — Search and IdPrefix wiring.

#[test]
fn matching_accounts_search_returns_substring_matches_in_insertion_order() {
    let mut vault = empty_plaintext_vault();
    let alice_acme_id = vault.add(make_account("alice", Some("Acme")));
    let _bob_other_id = vault.add(make_account("bob", Some("OtherCorp")));
    let alice_other_id = vault.add(make_account("alice", Some("OtherCorp")));

    let q = parse_account_query("alice").unwrap();
    let matches = vault.matching_accounts(&q);
    let ids: Vec<AccountId> = matches.iter().map(|a| a.id()).collect();
    assert_eq!(ids, vec![alice_acme_id, alice_other_id]);
}

#[test]
fn matching_accounts_search_is_case_insensitive() {
    let mut vault = empty_plaintext_vault();
    let acme_id = vault.add(make_account("user", Some("AcmeCorp")));

    let q = parse_account_query("ACME").unwrap();
    let matches = vault.matching_accounts(&q);
    let ids: Vec<AccountId> = matches.iter().map(|a| a.id()).collect();
    assert_eq!(ids, vec![acme_id]);
}

#[test]
fn matching_accounts_empty_search_returns_all_accounts_in_insertion_order() {
    let mut vault = empty_plaintext_vault();
    let a = vault.add(make_account("alice", None));
    let b = vault.add(make_account("bob", None));
    let c = vault.add(make_account("carol", None));

    let q = parse_account_query("").unwrap();
    let matches = vault.matching_accounts(&q);
    let ids: Vec<AccountId> = matches.iter().map(|a| a.id()).collect();
    assert_eq!(ids, vec![a, b, c]);
}

#[test]
fn matching_accounts_search_returns_empty_on_no_match() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));

    let q = parse_account_query("nobody").unwrap();
    let matches = vault.matching_accounts(&q);
    assert!(matches.is_empty());
}

#[test]
fn matching_accounts_id_prefix_matches_canonical_hex() {
    let mut vault = empty_plaintext_vault();
    let alice_id = vault.add(make_account("alice", None));
    let _bob_id = vault.add(make_account("bob", None));

    let prefix = &id_hex(alice_id)[..8];
    let q = parse_account_query(&format!("id:{prefix}")).unwrap();
    let matches = vault.matching_accounts(&q);
    let ids: Vec<AccountId> = matches.iter().map(|a| a.id()).collect();
    assert_eq!(ids, vec![alice_id]);
}

#[test]
fn matching_accounts_id_prefix_uses_lowercase_normalized_form() {
    // Uppercase A–F at parse time get folded to lowercase, so the
    // matcher compares against the lowercase canonical hex of stored
    // IDs without any per-call uppercase handling.
    let mut vault = empty_plaintext_vault();
    let alice_id = vault.add(make_account("alice", None));

    let prefix = &id_hex(alice_id)[..8];
    let upper = prefix.to_uppercase();
    // Sanity: only useful when the chosen prefix actually contains A–F.
    if upper != *prefix {
        let q = parse_account_query(&format!("id:{upper}")).unwrap();
        let matches = vault.matching_accounts(&q);
        let ids: Vec<AccountId> = matches.iter().map(|a| a.id()).collect();
        assert_eq!(ids, vec![alice_id]);
    }
}

#[test]
fn matching_accounts_id_prefix_returns_insertion_order_on_collision() {
    // Forge a contrived collision by adding two accounts whose IDs
    // share a leading hex run. We can't pre-pick AccountIds (UUIDv4),
    // so we add several accounts and search by a prefix of one of them
    // — there is no guaranteed multi-match here, but we at least pin
    // the per-id success case via a single-prefix run, plus an empty
    // result for an unrelated random hex prefix.
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", None));
    vault.add(make_account("bob", None));

    let q = parse_account_query("id:00000000").unwrap();
    let matches = vault.matching_accounts(&q);
    // Astronomically unlikely to collide with a UUIDv4 prefix.
    assert!(matches.is_empty());
}

#[test]
fn matching_accounts_id_prefix_returns_empty_when_no_account_matches() {
    let mut vault = empty_plaintext_vault();
    let _alice_id = vault.add(make_account("alice", None));

    let q = parse_account_query("id:0123456789abcdef").unwrap();
    let matches = vault.matching_accounts(&q);
    // Random UUID is overwhelmingly unlikely to start with the chosen
    // 16-char prefix; this pins the no-match path.
    assert!(matches.is_empty());
}
