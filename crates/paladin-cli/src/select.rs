// SPDX-License-Identifier: AGPL-3.0-or-later

//! Thin wrapper around `paladin_core::parse_account_query`,
//! `Vault::matching_accounts`, and `Vault::shortest_unique_id_prefix`. The
//! CLI owns only command-specific cardinality decisions and error rendering;
//! parsing, matching, and shortest-unique-prefix computation stay in
//! `paladin-core` (see `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Query resolution"
//! and docs/DESIGN.md §5).
//!
//! Public surface:
//!
//! - [`resolve_unique`] — `copy` / `remove` / `rename`: exactly one match
//!   required; rejects empty and multi-match sets.
//! - [`resolve_all`] — `peek`: returns every match unconditionally; rejects
//!   only the empty set.
//! - [`resolve_for_show`] — `show`: returns every match when all matches
//!   are TOTP, otherwise requires a single match so one command cannot
//!   silently advance multiple HOTP counters.
//!
//! All three return [`CliError::NoMatch`] / [`CliError::MultipleMatches`]
//! presentation envelopes; query-string parse failures propagate verbatim
//! as `CliError::Paladin(PaladinError::ValidationError { field: "query", … })`.

// `resolve_*` are not yet wired into the binary; the dispatch handlers
// land in subsequent commits. The unit tests below exercise the
// cardinality policy end-to-end against a real `Vault`.
#![allow(dead_code)]

use paladin_core::{Account, AccountKindSummary, AccountQuery, Vault};

use crate::output::error::{Candidate, CliError};

/// Result of a `show` selection. `Single` is the only safe option
/// whenever any HOTP account matched (since `show` advances HOTP
/// counters); `AllTotp` is allowed when every match is TOTP so a
/// substring search can broadcast read-only codes.
#[derive(Debug)]
pub enum ShowSelection<'v> {
    /// One account matched. `show` prints exactly one code.
    Single(&'v Account),
    /// Multiple matches, all TOTP. `show` may print one code per row.
    AllTotp(Vec<&'v Account>),
}

/// Single-match resolver for `copy`, `remove`, and `rename`.
///
/// - Zero matches → [`CliError::NoMatch`].
/// - One match → that account (borrowed from `vault`).
/// - Many matches → [`CliError::MultipleMatches`] with disambiguators.
///
/// Query parse failures (e.g. malformed `id:` prefix) propagate as the
/// `validation_error` returned by [`paladin_core::parse_account_query`].
pub fn resolve_unique<'v>(vault: &'v Vault, query_text: &str) -> Result<&'v Account, CliError> {
    let matches = matching_accounts(vault, query_text)?;
    match matches.as_slice() {
        [] => Err(no_match(query_text)),
        [only] => Ok(*only),
        many => Err(multiple_matches(vault, query_text, many)),
    }
}

/// Multi-match resolver for `peek`, which never advances HOTP and
/// therefore prints every match unconditionally.
///
/// - Zero matches → [`CliError::NoMatch`].
/// - One or more matches → all matches in insertion order.
pub fn resolve_all<'v>(vault: &'v Vault, query_text: &str) -> Result<Vec<&'v Account>, CliError> {
    let matches = matching_accounts(vault, query_text)?;
    if matches.is_empty() {
        return Err(no_match(query_text));
    }
    Ok(matches)
}

/// Selection resolver for `show`.
///
/// - Zero matches → [`CliError::NoMatch`].
/// - One match → [`ShowSelection::Single`].
/// - Many matches, all TOTP → [`ShowSelection::AllTotp`].
/// - Many matches, any HOTP → [`CliError::MultipleMatches`] (advancing
///   multiple HOTP counters in one command would be silent and
///   irreversible; the user must re-target with `id:<hex>`).
pub fn resolve_for_show<'v>(
    vault: &'v Vault,
    query_text: &str,
) -> Result<ShowSelection<'v>, CliError> {
    let matches = matching_accounts(vault, query_text)?;
    match matches.as_slice() {
        [] => Err(no_match(query_text)),
        [only] => Ok(ShowSelection::Single(only)),
        many if many
            .iter()
            .all(|a| a.summary().kind == AccountKindSummary::Totp) =>
        {
            Ok(ShowSelection::AllTotp(matches))
        }
        many => Err(multiple_matches(vault, query_text, many)),
    }
}

fn matching_accounts<'v>(vault: &'v Vault, query_text: &str) -> Result<Vec<&'v Account>, CliError> {
    let query: AccountQuery = paladin_core::parse_account_query(query_text)?;
    Ok(vault.matching_accounts(&query))
}

fn no_match(query_text: &str) -> CliError {
    CliError::NoMatch {
        query: query_text.to_string(),
    }
}

fn multiple_matches(vault: &Vault, query_text: &str, matches: &[&Account]) -> CliError {
    let candidates = matches
        .iter()
        .map(|a| Candidate {
            disambiguator: format!(
                "id:{}",
                vault
                    .shortest_unique_id_prefix(a.id())
                    .expect("matched account ID must be present in the live vault")
            ),
            summary: a.summary(),
        })
        .collect();
    CliError::MultipleMatches {
        query: query_text.to_string(),
        candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use paladin_core::{parse_otpauth, ErrorKind, PaladinError, Store, Vault, VaultInit};

    fn fixture_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// Tempdir that ignores `$TMPDIR` so scratch never leaks into the
    /// workspace when a developer has `TMPDIR=$(pwd)` exported.
    fn test_tempdir() -> tempfile::TempDir {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        tempfile::Builder::new()
            .prefix(".tmp")
            .tempdir_in(root)
            .expect("create test tempdir")
    }

    /// Build an `Account` from a synthesized otpauth URI. `kind` is
    /// `"totp"` or `"hotp"`; HOTP entries get an explicit `counter=0`.
    fn make_account(kind: &str, label: &str, issuer: Option<&str>) -> paladin_core::Account {
        let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
        let mut uri =
            format!("otpauth://{kind}/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP&digits=6");
        if kind == "hotp" {
            uri.push_str("&counter=0");
        }
        parse_otpauth(&uri, fixture_now()).unwrap().account
    }

    /// Plaintext vault rooted in a fresh tempdir (chmod'd to `0700` so the
    /// `Store::create` parent-permissions invariant holds). The `TempDir`
    /// is leaked so the test file outlives the borrow.
    fn empty_plaintext_vault() -> Vault {
        let dir = test_tempdir();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
        let path = dir.path().join("vault.bin");
        std::mem::forget(dir);
        let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
        vault
    }

    fn add_totp(vault: &mut Vault, label: &str, issuer: Option<&str>) -> paladin_core::AccountId {
        vault.add(make_account("totp", label, issuer))
    }

    fn add_hotp(vault: &mut Vault, label: &str, issuer: Option<&str>) -> paladin_core::AccountId {
        vault.add(make_account("hotp", label, issuer))
    }

    // -----------------------------------------------------------------
    // Query parse failures propagate verbatim from core.

    #[test]
    fn malformed_id_prefix_propagates_validation_error_from_core() {
        let vault = empty_plaintext_vault();
        let err = resolve_unique(&vault, "id:short").expect_err("must reject");
        match err {
            CliError::Paladin(PaladinError::ValidationError { field, .. }) => {
                assert_eq!(field, "query");
            }
            other => panic!("expected validation_error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_id_prefix_in_resolve_all_propagates_too() {
        let vault = empty_plaintext_vault();
        let err = resolve_all(&vault, "id:short").expect_err("must reject");
        assert!(matches!(err, CliError::Paladin(p) if p.kind() == ErrorKind::ValidationError));
    }

    #[test]
    fn malformed_id_prefix_in_resolve_for_show_propagates_too() {
        let vault = empty_plaintext_vault();
        let err = resolve_for_show(&vault, "id:nothex!!").expect_err("must reject");
        assert!(matches!(err, CliError::Paladin(p) if p.kind() == ErrorKind::ValidationError));
    }

    // -----------------------------------------------------------------
    // resolve_unique cardinality.

    #[test]
    fn resolve_unique_no_match_returns_no_match_envelope_with_query() {
        let mut vault = empty_plaintext_vault();
        let _ = add_totp(&mut vault, "alice", Some("Acme"));
        let err = resolve_unique(&vault, "zzz").expect_err("must miss");
        match err {
            CliError::NoMatch { query } => assert_eq!(query, "zzz"),
            other => panic!("expected NoMatch, got {other:?}"),
        }
    }

    #[test]
    fn resolve_unique_single_match_returns_borrowed_account() {
        let mut vault = empty_plaintext_vault();
        let alice = add_totp(&mut vault, "alice", Some("Acme"));
        let _bob = add_totp(&mut vault, "bob", Some("Acme"));
        let got = resolve_unique(&vault, "alice").expect("single match");
        assert_eq!(got.id(), alice);
    }

    #[test]
    fn resolve_unique_multi_match_returns_multiple_matches_with_disambiguators() {
        let mut vault = empty_plaintext_vault();
        let _ = add_totp(&mut vault, "alice", Some("GitHub"));
        let _ = add_totp(&mut vault, "alice", Some("GitLab"));
        let err = resolve_unique(&vault, "alice").expect_err("multiple");
        match err {
            CliError::MultipleMatches { query, candidates } => {
                assert_eq!(query, "alice");
                assert_eq!(candidates.len(), 2);
                for c in &candidates {
                    assert!(
                        c.disambiguator.starts_with("id:"),
                        "disambiguator must be `id:<hex>`, got {:?}",
                        c.disambiguator
                    );
                    let hex = &c.disambiguator[3..];
                    assert!(
                        (8..=32).contains(&hex.len()),
                        "id hex must be 8..=32 chars, got {hex:?}"
                    );
                    assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
                }
                // Insertion order is preserved.
                assert_eq!(candidates[0].summary.issuer.as_deref(), Some("GitHub"));
                assert_eq!(candidates[1].summary.issuer.as_deref(), Some("GitLab"));
            }
            other => panic!("expected MultipleMatches, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // resolve_all cardinality.

    #[test]
    fn resolve_all_returns_every_match_in_insertion_order() {
        let mut vault = empty_plaintext_vault();
        let a = add_totp(&mut vault, "alice", None);
        let b = add_totp(&mut vault, "alice2", None);
        let _ = add_totp(&mut vault, "bob", None);
        let got = resolve_all(&vault, "alice").expect("two matches");
        assert_eq!(got.iter().map(|x| x.id()).collect::<Vec<_>>(), vec![a, b]);
    }

    #[test]
    fn resolve_all_no_match_returns_no_match() {
        let vault = empty_plaintext_vault();
        let err = resolve_all(&vault, "anything").expect_err("empty vault");
        assert!(matches!(err, CliError::NoMatch { .. }));
    }

    #[test]
    fn resolve_all_does_not_reject_multiple_hotp_matches() {
        // peek is read-only; HOTP rows are fine in a multi-match set.
        let mut vault = empty_plaintext_vault();
        let _ = add_hotp(&mut vault, "alice", Some("Acme"));
        let _ = add_hotp(&mut vault, "alice", Some("Beta"));
        let got = resolve_all(&vault, "alice").expect("two matches");
        assert_eq!(got.len(), 2);
    }

    // -----------------------------------------------------------------
    // resolve_for_show cardinality.

    #[test]
    fn resolve_for_show_single_match_returns_single_variant() {
        let mut vault = empty_plaintext_vault();
        let alice = add_totp(&mut vault, "alice", None);
        match resolve_for_show(&vault, "alice").expect("single") {
            ShowSelection::Single(a) => assert_eq!(a.id(), alice),
            ShowSelection::AllTotp(_) => panic!("expected Single"),
        }
    }

    #[test]
    fn resolve_for_show_all_totp_multi_match_returns_all_totp_variant() {
        let mut vault = empty_plaintext_vault();
        let _ = add_totp(&mut vault, "alice", Some("GitHub"));
        let _ = add_totp(&mut vault, "alice", Some("GitLab"));
        match resolve_for_show(&vault, "alice").expect("all-TOTP") {
            ShowSelection::AllTotp(rows) => {
                assert_eq!(rows.len(), 2);
                for a in &rows {
                    assert_eq!(a.summary().kind, AccountKindSummary::Totp);
                }
            }
            ShowSelection::Single(_) => panic!("expected AllTotp"),
        }
    }

    #[test]
    fn resolve_for_show_any_hotp_multi_match_rejects_with_multiple_matches() {
        let mut vault = empty_plaintext_vault();
        let _ = add_totp(&mut vault, "alice", Some("GitHub"));
        let _ = add_hotp(&mut vault, "alice", Some("Bank"));
        let err = resolve_for_show(&vault, "alice").expect_err("must reject");
        match err {
            CliError::MultipleMatches { candidates, .. } => {
                assert_eq!(candidates.len(), 2);
                // Both candidates are present even though the rejection
                // reason is the HOTP entry; one shared error type covers
                // both so the user sees one disambiguator list.
                assert!(candidates
                    .iter()
                    .any(|c| c.summary.kind == AccountKindSummary::Hotp));
                assert!(candidates
                    .iter()
                    .any(|c| c.summary.kind == AccountKindSummary::Totp));
            }
            other => panic!("expected MultipleMatches, got {other:?}"),
        }
    }

    #[test]
    fn resolve_for_show_no_match_returns_no_match() {
        let vault = empty_plaintext_vault();
        let err = resolve_for_show(&vault, "nope").expect_err("empty vault");
        assert!(matches!(err, CliError::NoMatch { .. }));
    }

    // -----------------------------------------------------------------
    // id:<hex> queries route through core unchanged.

    #[test]
    fn id_prefix_query_resolves_through_core_match_path() {
        let mut vault = empty_plaintext_vault();
        let id = add_totp(&mut vault, "alice", Some("Acme"));
        let hex = id.to_hyphenated().replace('-', "");
        let prefix = &hex[..8];
        let got = resolve_unique(&vault, &format!("id:{prefix}")).expect("match");
        assert_eq!(got.id(), id);
    }
}
