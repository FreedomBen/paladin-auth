// SPDX-License-Identifier: AGPL-3.0-or-later

//! Incremental search filter over [`Vault::iter`].
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` §3 (project layout) and the
//! "Tests > Search" checklist, the TUI delegates issuer / label
//! matching to [`paladin_auth_core::account_matches_search`] so the
//! search-bar predicate stays byte-for-byte identical to the CLI
//! query resolution path in `docs/DESIGN.md` §5. Insertion order is
//! preserved because [`Vault::iter`] already walks accounts in
//! insertion order.

use paladin_auth_core::{account_matches_search, select_after_filter, AccountId, Vault};

/// Return the [`AccountId`]s of every account in `vault` whose
/// `"{issuer}:{label}"` match key contains `query` case-insensitively,
/// in vault insertion order.
///
/// Empty `query` matches every account (per
/// [`paladin_auth_core::account_matches_search`]'s "empty needle matches
/// everything" contract). The TUI does **not** honor the CLI-only
/// `id:` prefix form — that is parsed by
/// [`paladin_auth_core::parse_account_query`] for CLI single-account
/// resolution and is out of scope for the list-search bar.
#[must_use]
pub fn filtered_account_ids(vault: &Vault, query: &str) -> Vec<AccountId> {
    vault
        .iter()
        .filter(|account| account_matches_search(account, query))
        .map(paladin_auth_core::Account::id)
        .collect()
}

/// Pick the surviving list selection after a search-query change.
///
/// Composes [`filtered_account_ids`] with
/// [`paladin_auth_core::select_after_filter`] so the TUI's list-view
/// selection follows the docs/DESIGN.md §6 / §7 search-selection
/// preservation rule:
///
/// * if `prev` is `Some` and still appears in the new filtered set,
///   it is preserved verbatim (the user's cursor stays put across an
///   incremental search refinement);
/// * otherwise the first match of the new filtered set is selected
///   (vault insertion order);
/// * `None` is returned only when the new filtered set is empty.
#[must_use]
pub fn select_after_search(
    vault: &Vault,
    query: &str,
    prev: Option<AccountId>,
) -> Option<AccountId> {
    let filtered = filtered_account_ids(vault, query);
    select_after_filter(prev, &filtered)
}
