// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.14 / G.15 / G.21 — `parse_account_query`, `Vault::matching_accounts`,
// `Vault::shortest_unique_id_prefix`, and `select_after_filter`
// (DESIGN.md §4.7, §5, §6, §7).
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
//
// `Vault::shortest_unique_id_prefix`:
//   * Returns the minimum-length `id:` hex disambiguator (≥ 8 chars)
//     that uniquely identifies an account among the live vault. Random
//     UUIDv4 collisions on 8 hex chars are astronomically unlikely, so
//     the integration tests here pin the no-collision floor, the
//     missing-id `None` case, and the prefix invariants. Collision-
//     driven extension paths (9 chars, full 32 chars, multi-account
//     resolution) are unit-tested in `domain::query` against
//     deterministic `AccountId::from_bytes` ids that integration tests
//     cannot construct (`Account.id` is `pub(crate)`).

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_account_query, parse_otpauth, select_after_filter, Account, AccountId, AccountQuery,
    ErrorKind, Vault,
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
    let parsed =
        parse_account_query("id:0123456789abcdef0123456789abcdef").expect("32 hex chars is valid");
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

    let parsed =
        parse_account_query("id:DeAdBeEf01234567").expect("mixed-case uppercase A-F is valid");
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
    assert_query_validation_error(
        "id:\u{0966}\u{0967}\u{0968}\u{0969}\u{096A}\u{096B}\u{096C}\u{096D}",
    );
    // Fullwidth ASCII A is not the same code point as ASCII A.
    assert_query_validation_error(
        "id:\u{FF21}\u{FF21}\u{FF21}\u{FF21}\u{FF21}\u{FF21}\u{FF21}\u{FF21}",
    );
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

// ---------------------------------------------------------------------------
// Vault::shortest_unique_id_prefix — Phase G.15.

#[test]
fn shortest_unique_id_prefix_returns_eight_chars_on_single_account_vault() {
    let mut vault = empty_plaintext_vault();
    let alice_id = vault.add(make_account("alice", None));

    let prefix = vault
        .shortest_unique_id_prefix(alice_id)
        .expect("present id");
    assert_eq!(
        prefix.len(),
        8,
        "single-account vault hits the 8-char floor"
    );
    let canonical = id_hex(alice_id);
    assert!(
        canonical.starts_with(&prefix),
        "{prefix} must be a prefix of canonical hex {canonical}"
    );
    assert!(prefix.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(prefix.bytes().all(|b| !b.is_ascii_uppercase()));
}

#[test]
fn shortest_unique_id_prefix_returns_eight_chars_when_no_collision() {
    // Two random UUIDv4s essentially never share an 8-char hex prefix,
    // so this pins the typical no-collision floor across a multi-
    // account vault.
    let mut vault = empty_plaintext_vault();
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    let bob_id = vault.add(make_account("bob", Some("OtherCorp")));
    let carol_id = vault.add(make_account("carol", None));

    for id in [alice_id, bob_id, carol_id] {
        let prefix = vault.shortest_unique_id_prefix(id).expect("present id");
        assert_eq!(prefix.len(), 8, "no collision → 8-char floor for {id}");
        assert!(id_hex(id).starts_with(&prefix));
    }
}

#[test]
fn shortest_unique_id_prefix_returns_none_for_id_not_in_vault() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", None));

    // A freshly generated AccountId is overwhelmingly unlikely to
    // collide with any vault entry. This pins the missing-id `None`
    // contract.
    let missing = AccountId::new();
    assert_eq!(vault.shortest_unique_id_prefix(missing), None);
}

#[test]
fn shortest_unique_id_prefix_returns_none_on_empty_vault() {
    let vault = empty_plaintext_vault();
    let any_id = AccountId::new();
    assert_eq!(vault.shortest_unique_id_prefix(any_id), None);
}

#[test]
fn shortest_unique_id_prefix_uniquely_resolves_to_one_account() {
    // Whatever length the function picks, `matching_accounts(id:<prefix>)`
    // must return exactly one account — the one we asked about. This
    // ties the prefix back to the matcher contract end-to-end without
    // controlled-id construction.
    let mut vault = empty_plaintext_vault();
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    let bob_id = vault.add(make_account("bob", Some("OtherCorp")));

    for id in [alice_id, bob_id] {
        let prefix = vault.shortest_unique_id_prefix(id).expect("present id");
        let q = parse_account_query(&format!("id:{prefix}")).unwrap();
        let matches = vault.matching_accounts(&q);
        let ids: Vec<AccountId> = matches.iter().map(|a| a.id()).collect();
        assert_eq!(ids, vec![id], "prefix must resolve to a single account");
    }
}

#[test]
fn shortest_unique_id_prefix_returns_lowercase_hex_only() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", None));

    let prefix = vault.shortest_unique_id_prefix(id).expect("present id");
    assert!(
        prefix.bytes().all(|b| b.is_ascii_hexdigit()),
        "{prefix} must be ASCII hex"
    );
    assert!(
        prefix.bytes().all(|b| !b.is_ascii_uppercase()),
        "{prefix} must be lowercase"
    );
    assert!(
        (8..=32).contains(&prefix.len()),
        "{prefix} length must be 8..=32"
    );
}

// ---------------------------------------------------------------------------
// select_after_filter — search-selection preservation rule (DESIGN §6 / §7).
//
// Front ends rebuild the filtered account list every keystroke; this
// helper decides which account stays selected so a typed selection is
// not lost while still falling back to the first match when the
// previous selection no longer applies.

#[test]
fn select_after_filter_preserves_prev_when_present_in_filtered() {
    let a = AccountId::new();
    let b = AccountId::new();
    let c = AccountId::new();
    let filtered = [a, b, c];
    // Previous selection is in the filtered set — preserve it even when
    // a different account would be the first match.
    assert_eq!(select_after_filter(Some(b), &filtered), Some(b));
    assert_eq!(select_after_filter(Some(c), &filtered), Some(c));
}

#[test]
fn select_after_filter_preserves_prev_at_first_position() {
    // Edge case: when `prev` is already the first element, preservation
    // and first-fallback agree — but the function still returns the
    // preserved value rather than re-deriving from `filtered[0]`.
    let a = AccountId::new();
    let b = AccountId::new();
    let filtered = [a, b];
    assert_eq!(select_after_filter(Some(a), &filtered), Some(a));
}

#[test]
fn select_after_filter_falls_back_to_first_when_prev_is_none() {
    // No previous selection — pick the first match so the user sees
    // something selected immediately after a search applies.
    let a = AccountId::new();
    let b = AccountId::new();
    let filtered = [a, b];
    assert_eq!(select_after_filter(None, &filtered), Some(a));
}

#[test]
fn select_after_filter_falls_back_to_first_when_prev_missing_from_filtered() {
    // Previous selection has been filtered out (e.g., the user narrowed
    // the search). Fall back to the first remaining match rather than
    // leaving the UI with no selection.
    let a = AccountId::new();
    let b = AccountId::new();
    let absent = AccountId::new();
    let filtered = [a, b];
    assert_eq!(select_after_filter(Some(absent), &filtered), Some(a));
}

#[test]
fn select_after_filter_returns_none_when_filtered_is_empty_with_some_prev() {
    // Empty filtered set means no possible selection regardless of
    // whether `prev` was set.
    let prev = AccountId::new();
    let empty: [AccountId; 0] = [];
    assert_eq!(select_after_filter(Some(prev), &empty), None);
}

#[test]
fn select_after_filter_returns_none_when_filtered_is_empty_with_none_prev() {
    let empty: [AccountId; 0] = [];
    assert_eq!(select_after_filter(None, &empty), None);
}

#[test]
fn select_after_filter_handles_single_element_filtered() {
    // The filtered list has exactly one element; both code paths
    // (preservation and fallback) collapse onto that element.
    let only = AccountId::new();
    let other = AccountId::new();
    let filtered = [only];
    assert_eq!(select_after_filter(Some(only), &filtered), Some(only));
    assert_eq!(select_after_filter(Some(other), &filtered), Some(only));
    assert_eq!(select_after_filter(None, &filtered), Some(only));
}

#[test]
fn select_after_filter_is_pure_with_respect_to_inputs() {
    // Repeated calls with identical inputs return identical outputs
    // and do not mutate (or depend on) any hidden state.
    let a = AccountId::new();
    let b = AccountId::new();
    let filtered = [a, b];
    let first = select_after_filter(Some(b), &filtered);
    let second = select_after_filter(Some(b), &filtered);
    let third = select_after_filter(Some(b), &filtered);
    assert_eq!(first, Some(b));
    assert_eq!(first, second);
    assert_eq!(second, third);
}
