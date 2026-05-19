// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `domain::query` — shared account-selector grammar (DESIGN.md §4.7, §5).
//
// `parse_account_query` owns the `id:` prefix validation so the CLI's
// query grammar and the TUI / GUI search bars share one source of
// truth. `Vault::matching_accounts` consumes the parsed `AccountQuery`
// and returns matching accounts in insertion order; this module also
// holds the per-id-prefix matcher used internally by that method.
// `shortest_unique_id_prefix` computes CLI candidate disambiguators
// using the same canonical 32-char lowercase hex form.

use crate::domain::match_key::account_matches_search;
use crate::domain::{Account, AccountId};
use crate::error::{PaladinError, Result};

const ID_PREFIX_DISCRIMINATOR: &str = "id:";
const HEX_MIN: usize = 8;
const HEX_MAX: usize = 32;

/// Account selector parsed from a CLI / TUI / GUI query string
/// (DESIGN.md §4.7).
///
/// `Search` carries the raw substring query (no normalization beyond
/// what `account_matches_search` applies at compare time). `IdPrefix`
/// carries a validated 8..=32 character lowercase ASCII hex string
/// used to disambiguate accounts by `AccountId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountQuery {
    /// Free-text substring query (no normalization beyond `account_matches_search`).
    Search(String),
    /// Validated lowercase ASCII hex prefix (8..=32 chars) used to match `AccountId`.
    IdPrefix {
        /// Lowercase hex prefix (uppercase A–F accepted on input, stored lowercase).
        hex_prefix: String,
    },
}

/// Parse the shared account-selector grammar (DESIGN.md §5).
///
/// A query starting with the lowercase ASCII discriminator `id:` is
/// validated as an 8..=32 hex prefix; ASCII uppercase A–F is accepted
/// inside the prefix but stored lowercase. Any other input — including
/// the empty string, plain text, and queries that contain `:` elsewhere
/// (or even an uppercase `ID:` token) — becomes
/// [`AccountQuery::Search`] with the original casing preserved so the
/// substring predicate can lowercase both sides at compare time.
///
/// Invalid `id:` prefixes (under 8 hex chars, over 32 hex chars, or
/// containing any non-hex character) return `validation_error` with
/// `field: "query"`.
pub fn parse_account_query(query: &str) -> Result<AccountQuery> {
    let Some(hex) = query.strip_prefix(ID_PREFIX_DISCRIMINATOR) else {
        return Ok(AccountQuery::Search(query.to_string()));
    };
    if hex.len() < HEX_MIN || hex.len() > HEX_MAX {
        return Err(PaladinError::validation(
            "query",
            format!(
                "id_prefix_length_out_of_range: expected {HEX_MIN}..={HEX_MAX} hex chars, got {}",
                hex.len()
            ),
        ));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PaladinError::validation(
            "query",
            "id_prefix_non_hex: expected ASCII 0-9 / a-f / A-F",
        ));
    }
    Ok(AccountQuery::IdPrefix {
        hex_prefix: hex.to_ascii_lowercase(),
    })
}

/// Filter `accounts` against `query` in insertion order.
///
/// `Search` queries delegate to [`account_matches_search`], which
/// applies `str::to_lowercase()` to both sides before substring
/// matching. `IdPrefix` queries compare the validated lowercase hex
/// against the canonical 32-char lowercase hex of each account's
/// `AccountId`.
pub(crate) fn matching_accounts<'a, I>(accounts: I, query: &AccountQuery) -> Vec<&'a Account>
where
    I: IntoIterator<Item = &'a Account>,
{
    match query {
        AccountQuery::Search(needle) => accounts
            .into_iter()
            .filter(|a| account_matches_search(a, needle))
            .collect(),
        AccountQuery::IdPrefix { hex_prefix } => accounts
            .into_iter()
            .filter(|a| a.id().hex_prefix(HEX_MAX).starts_with(hex_prefix))
            .collect(),
    }
}

/// Compute the minimum lowercase-hex disambiguator that uniquely
/// identifies `id` among `accounts`.
///
/// Returns `None` if `id` is not present in `accounts`. Otherwise
/// returns the shortest prefix of the canonical 32-char lowercase hex
/// form of `id` that no other account's hex prefix starts with, with a
/// floor of [`HEX_MIN`] (8 chars) and a ceiling of [`HEX_MAX`] (32
/// chars). Because two distinct UUIDs cannot share the same 32-char
/// hex, the 32-char form is always unique whenever `id` is present.
pub(crate) fn shortest_unique_id_prefix(accounts: &[Account], id: AccountId) -> Option<String> {
    if !accounts.iter().any(|a| a.id() == id) {
        return None;
    }
    let target = id.hex_prefix(HEX_MAX);
    for len in HEX_MIN..=HEX_MAX {
        let candidate = &target[..len];
        let collides = accounts
            .iter()
            .filter(|a| a.id() != id)
            .any(|a| a.id().hex_prefix(HEX_MAX).starts_with(candidate));
        if !collides {
            return Some(candidate.to_string());
        }
    }
    Some(target)
}

/// Pick the surviving selection after a search filter rebuild
/// (DESIGN.md §6 / §7 search-selection preservation rule).
///
/// Returns `prev` when `prev` is `Some` and that id appears in
/// `filtered`. Otherwise — `prev` is `None`, or `prev` was filtered
/// out — returns the first element of `filtered`, or `None` when
/// `filtered` is empty. Pure: depends only on its arguments and never
/// mutates either side.
#[must_use]
pub fn select_after_filter(prev: Option<AccountId>, filtered: &[AccountId]) -> Option<AccountId> {
    if let Some(id) = prev {
        if filtered.contains(&id) {
            return Some(id);
        }
    }
    filtered.first().copied()
}

#[cfg(test)]
mod tests {
    // Phase G.15 — `shortest_unique_id_prefix` collision-driven
    // extension paths. Integration tests in `tests/query.rs` cover the
    // no-collision and missing-id cases with random UUIDs; the bullets
    // here use controlled `AccountId::from_bytes` ids so the
    // collision-extension and full-32-char-prefix paths are exercised
    // deterministically.
    use super::*;
    use crate::otpauth::parse_otpauth;
    use std::time::{Duration, UNIX_EPOCH};

    fn id_from_hex(hex: &str) -> AccountId {
        assert_eq!(hex.len(), 32, "test ids are 32 hex chars");
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            let s = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(s, 16).expect("hex digit");
        }
        AccountId::from_bytes(bytes)
    }

    fn make_account_with_id(label: &str, id: AccountId) -> Account {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let uri = format!("otpauth://totp/{label}?secret=JBSWY3DPEHPK3PXP");
        let mut account = parse_otpauth(&uri, now).unwrap().account;
        account.id = id;
        account
    }

    #[test]
    fn returns_eight_chars_when_no_collision() {
        let id_a = id_from_hex("aaaaaaaa11111111111111111111111a");
        let id_b = id_from_hex("bbbbbbbb22222222222222222222222b");
        let accounts = vec![
            make_account_with_id("alice", id_a),
            make_account_with_id("bob", id_b),
        ];
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_a).as_deref(),
            Some("aaaaaaaa")
        );
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_b).as_deref(),
            Some("bbbbbbbb")
        );
    }

    #[test]
    fn returns_eight_chars_on_single_account_vault() {
        let id_a = id_from_hex("0123456789abcdef0123456789abcdef");
        let accounts = vec![make_account_with_id("solo", id_a)];
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_a).as_deref(),
            Some("01234567"),
        );
    }

    #[test]
    fn extends_to_nine_chars_when_eight_collide() {
        // Two ids share the first 8 hex chars and diverge at char 9.
        let id_a = id_from_hex("aaaaaaaa1111111111111111111111aa");
        let id_b = id_from_hex("aaaaaaaa2222222222222222222222bb");
        let accounts = vec![
            make_account_with_id("a", id_a),
            make_account_with_id("b", id_b),
        ];
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_a).as_deref(),
            Some("aaaaaaaa1"),
        );
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_b).as_deref(),
            Some("aaaaaaaa2"),
        );
    }

    #[test]
    fn extends_to_full_thirty_two_chars_when_only_last_char_differs() {
        // Two ids share the first 31 hex chars; only the final hex
        // nibble differs. The disambiguator extends all the way to
        // the 32-char ceiling — proves the full-hex return path.
        let id_a = id_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1");
        let id_b = id_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2");
        let accounts = vec![
            make_account_with_id("a", id_a),
            make_account_with_id("b", id_b),
        ];
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_a).as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"),
        );
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_b).as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"),
        );
    }

    #[test]
    fn returns_none_for_id_not_in_accounts() {
        let id_present = id_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let id_missing = id_from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let accounts = vec![make_account_with_id("present", id_present)];
        assert_eq!(shortest_unique_id_prefix(&accounts, id_missing), None);
    }

    #[test]
    fn returns_none_on_empty_accounts() {
        let id = id_from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let accounts: Vec<Account> = vec![];
        assert_eq!(shortest_unique_id_prefix(&accounts, id), None);
    }

    #[test]
    fn picks_per_id_minimum_among_three_accounts() {
        // a and b share the first 8 hex chars; c diverges at char 1.
        // a/b need 9 chars; c stays at the 8-char floor.
        let id_a = id_from_hex("aaaaaaaa1111111111111111111111aa");
        let id_b = id_from_hex("aaaaaaaa2222222222222222222222bb");
        let id_c = id_from_hex("11111111aaaaaaaaaaaaaaaaaaaaaacc");
        let accounts = vec![
            make_account_with_id("a", id_a),
            make_account_with_id("b", id_b),
            make_account_with_id("c", id_c),
        ];
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_a).as_deref(),
            Some("aaaaaaaa1"),
        );
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_b).as_deref(),
            Some("aaaaaaaa2"),
        );
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_c).as_deref(),
            Some("11111111"),
        );
    }

    #[test]
    fn extension_stops_at_first_disambiguating_length() {
        // Three ids sharing the first 9 hex chars but diverging at
        // char 10. The returned disambiguator must be exactly 10
        // chars — neither 9 (still colliding) nor 11+ (more than
        // necessary).
        let id_a = id_from_hex("aaaaaaaaa1bbbbbbbbbbbbbbbbbbbbbb");
        let id_b = id_from_hex("aaaaaaaaa2bbbbbbbbbbbbbbbbbbbbbb");
        let id_c = id_from_hex("aaaaaaaaa3bbbbbbbbbbbbbbbbbbbbbb");
        let accounts = vec![
            make_account_with_id("a", id_a),
            make_account_with_id("b", id_b),
            make_account_with_id("c", id_c),
        ];
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_a).as_deref(),
            Some("aaaaaaaaa1"),
        );
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_b).as_deref(),
            Some("aaaaaaaaa2"),
        );
        assert_eq!(
            shortest_unique_id_prefix(&accounts, id_c).as_deref(),
            Some("aaaaaaaaa3"),
        );
    }

    #[test]
    fn returned_prefix_is_lowercase_subset_of_canonical_hex() {
        let id = id_from_hex("0123456789ABCDEF0123456789abcdef".to_lowercase().as_str());
        let accounts = vec![make_account_with_id("only", id)];
        let got = shortest_unique_id_prefix(&accounts, id).expect("id present");
        let canonical = id.hex_prefix(HEX_MAX);
        assert!(
            canonical.starts_with(&got),
            "{got} not a prefix of {canonical}"
        );
        assert!(got.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(got.bytes().all(|b| !b.is_ascii_uppercase()));
        assert!(got.len() >= HEX_MIN && got.len() <= HEX_MAX);
    }

    /// Forced-collision iteration past 8 chars. Pins that the
    /// disambiguator extends one hex char beyond the deepest
    /// common prefix even when that takes the length far beyond
    /// the 8-char floor, and that the returned slice is a prefix
    /// of the target id but not of the colliding sibling.
    #[test]
    fn shortest_unique_id_prefix_extends_past_eight_chars_on_id_collision() {
        // Sub-case 1: bytes share their first 4 bytes (8 hex
        // chars), the 5th byte's high nibble differs → exactly 9.
        {
            let id_a = id_from_hex("aaaaaaaa1bcdef0123456789abcdef01");
            let id_b = id_from_hex("aaaaaaaa2bcdef0123456789abcdef02");
            let accounts = vec![
                make_account_with_id("a", id_a),
                make_account_with_id("b", id_b),
            ];
            let got_a = shortest_unique_id_prefix(&accounts, id_a).expect("id present");
            let target_hex = id_a.hex_prefix(HEX_MAX);
            let sibling_hex = id_b.hex_prefix(HEX_MAX);
            assert_eq!(got_a.len(), 9);
            assert_eq!(got_a, target_hex[..9]);
            assert!(
                !sibling_hex.starts_with(&got_a),
                "{got_a} must not be a prefix of {sibling_hex}",
            );
        }

        // Sub-case 2: bytes share their first 6 bytes (12 hex
        // chars), the 7th byte's high nibble differs → exactly 13.
        {
            let id_a = id_from_hex("aaaaaaaaaaaa1ef0123456789abcdef0");
            let id_b = id_from_hex("aaaaaaaaaaaa2ef0123456789abcdef0");
            let accounts = vec![
                make_account_with_id("a", id_a),
                make_account_with_id("b", id_b),
            ];
            let got_a = shortest_unique_id_prefix(&accounts, id_a).expect("id present");
            let target_hex = id_a.hex_prefix(HEX_MAX);
            let sibling_hex = id_b.hex_prefix(HEX_MAX);
            assert_eq!(got_a.len(), 13);
            assert_eq!(got_a, target_hex[..13]);
            assert!(
                !sibling_hex.starts_with(&got_a),
                "{got_a} must not be a prefix of {sibling_hex}",
            );
        }
    }
}
