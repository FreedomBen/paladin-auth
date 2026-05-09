// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `domain::query` — shared account-selector grammar (DESIGN.md §4.7, §5).
//
// `parse_account_query` owns the `id:` prefix validation so the CLI's
// query grammar and the TUI / GUI search bars share one source of
// truth. `Vault::matching_accounts` consumes the parsed `AccountQuery`
// and returns matching accounts in insertion order; this module also
// holds the per-id-prefix matcher used internally by that method.

use crate::domain::match_key::account_matches_search;
use crate::domain::Account;
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
    Search(String),
    IdPrefix { hex_prefix: String },
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
