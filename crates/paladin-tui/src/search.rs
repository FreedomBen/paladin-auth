// SPDX-License-Identifier: AGPL-3.0-or-later

//! Incremental search filter over [`Vault::iter`].
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` §3 (project layout) and the
//! "Tests > Search" checklist, the TUI delegates issuer / label
//! matching to [`paladin_core::account_matches_search`] so the
//! search-bar predicate stays byte-for-byte identical to the CLI
//! query resolution path in `DESIGN.md` §5. Insertion order is
//! preserved because [`Vault::iter`] already walks accounts in
//! insertion order.

use paladin_core::{account_matches_search, AccountId, Vault};

/// Return the [`AccountId`]s of every account in `vault` whose
/// `"{issuer}:{label}"` match key contains `query` case-insensitively,
/// in vault insertion order.
///
/// Empty `query` matches every account (per
/// [`paladin_core::account_matches_search`]'s "empty needle matches
/// everything" contract). The TUI does **not** honor the CLI-only
/// `id:` prefix form — that is parsed by
/// [`paladin_core::parse_account_query`] for CLI single-account
/// resolution and is out of scope for the list-search bar.
#[must_use]
pub fn filtered_account_ids(vault: &Vault, query: &str) -> Vec<AccountId> {
    vault
        .iter()
        .filter(|account| account_matches_search(account, query))
        .map(paladin_core::Account::id)
        .collect()
}
