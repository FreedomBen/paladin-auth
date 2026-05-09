// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `domain::match_key` — canonical `"{issuer}:{label}"` matching helpers
// shared by every front end (DESIGN.md §4.7, §5).
//
// `account_match_key` is the single source of truth for the projection
// used by CLI / TUI / GUI search bars and de-duplication paths.
// `account_matches_search` (Phase G.13) layers the case-insensitive
// substring predicate on top.

use crate::domain::Account;

/// Build the canonical `"{issuer}:{label}"` projection used by all
/// front ends to match accounts (DESIGN.md §5).
///
/// The colon is always present so callers can compare both halves
/// uniformly even when the issuer is empty (`None` after
/// `validate_issuer` collapses whitespace-only input). The helper
/// preserves the user's original casing and applies no Unicode
/// normalization — case-insensitive substring matching belongs to
/// [`account_matches_search`] (Phase G.13), which lower-cases both
/// sides at compare time.
#[must_use]
pub fn account_match_key(account: &Account) -> String {
    let issuer = account.issuer().unwrap_or("");
    format!("{issuer}:{}", account.label())
}

/// Case-insensitive substring predicate used by every front end's
/// list-search bar (DESIGN.md §4.7, §5).
///
/// Both `account_match_key(account)` and `query` are lower-cased with
/// `str::to_lowercase()` (Unicode-default, locale-independent) before
/// substring matching. The empty query matches every account so an
/// empty search bar shows the full vault. The leading colon for
/// no-issuer accounts is part of the match key and therefore visible
/// to the predicate. No Unicode normalization is applied — callers
/// who need NFC/NFD equivalence must normalize their inputs at the
/// edge.
#[must_use]
pub fn account_matches_search(account: &Account, query: &str) -> bool {
    let key = account_match_key(account).to_lowercase();
    let needle = query.to_lowercase();
    key.contains(&needle)
}
