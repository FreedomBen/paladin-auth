// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search filter tests for `paladin-auth-tui`.
//!
//! Tracks the "Tests > Search (`tests/search_tests.rs`)" checklist in
//! `docs/IMPLEMENTATION_PLAN_03_TUI.md`.

mod common;

use common::test_tempdir;

use std::path::Path;
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_auth_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, IconHintInput, Store,
    Vault, VaultInit, VaultLock,
};
use paladin_auth_tui::search::{filtered_account_ids, select_after_search};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn secure_tempdir() -> tempfile::TempDir {
    let dir = test_tempdir();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

fn open_plaintext_pair(path: &Path) -> (Vault, Store) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(path, VaultLock::Plaintext).expect("reopen plaintext")
}

fn add_account(vault: &mut Vault, store: &Store, issuer: Option<&str>, label: &str) -> AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

// ---------------------------------------------------------------------------
// Case-insensitive substring match through `paladin_auth_core::account_matches_search`
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Search — bullet 1)
// ---------------------------------------------------------------------------

#[test]
fn empty_query_yields_every_account_in_insertion_order() {
    // Base case: an empty search bar shows the full vault per
    // `account_matches_search`'s "empty needle matches everything"
    // contract (which the TUI inherits because it delegates to the
    // core helper). Also pins bullet 2 (insertion order) at the
    // unfiltered limit.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let a = add_account(&mut vault, &store, Some("Google"), "alice");
    let b = add_account(&mut vault, &store, Some("GitHub"), "bob");
    let c = add_account(&mut vault, &store, Some("Acme"), "carol");

    let ids = filtered_account_ids(&vault, "");
    assert_eq!(
        ids,
        vec![a, b, c],
        "empty query must yield every account in insertion order"
    );
}

#[test]
fn case_insensitive_substring_matches_via_paladin_auth_core_helper() {
    // bullet 1 (positive case): query "GMAIL" must match an account
    // whose issuer / label contains "gmail" in any casing — the
    // shared `paladin_auth_core::account_matches_search` lower-cases both
    // sides at compare time.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let _g = add_account(&mut vault, &store, Some("Google"), "alice");
    let gh = add_account(&mut vault, &store, Some("Gmail"), "bob");
    let _a = add_account(&mut vault, &store, Some("Acme"), "carol");

    let ids = filtered_account_ids(&vault, "GMAIL");
    assert_eq!(
        ids,
        vec![gh],
        "case-insensitive query must hit the Gmail account regardless of casing"
    );
}

#[test]
fn empty_issuer_account_matchable_via_label_with_colon_prefix_in_key() {
    // bullet 1 sub-clause: "empty issuer allowed and the colon is
    // still present in the match key." An account with no issuer
    // builds the key `":label"`, so a query containing the colon or
    // a substring of the label both match.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let _g = add_account(&mut vault, &store, Some("Google"), "alice");
    let noissuer = add_account(&mut vault, &store, None, "carol");

    let by_label = filtered_account_ids(&vault, "carol");
    assert_eq!(
        by_label,
        vec![noissuer],
        "an empty-issuer account must still be findable by its label substring"
    );

    let by_colon = filtered_account_ids(&vault, ":carol");
    assert_eq!(
        by_colon,
        vec![noissuer],
        "the leading colon for no-issuer accounts is part of the match key"
    );
}

#[test]
fn no_unicode_normalization_in_search_predicate() {
    // bullet 1 sub-clause: "no Unicode normalization." A search for
    // "a" must not match an account whose only "a-like" character is
    // the precomposed `ä` — the helper applies `str::to_lowercase()`
    // but no NFC/NFD folding.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let plain = add_account(&mut vault, &store, Some("Apex"), "label");
    let _accented = add_account(&mut vault, &store, Some("ÄRE"), "no-match");

    let ids = filtered_account_ids(&vault, "ap");
    assert_eq!(
        ids,
        vec![plain],
        "ascii substring must not normalize-match the precomposed `Ä` issuer"
    );
}

// ---------------------------------------------------------------------------
// Insertion order is preserved among matches
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Search — bullet 2)
// ---------------------------------------------------------------------------

#[test]
fn matches_returned_in_vault_insertion_order() {
    // Three accounts share the substring "x"; the helper must return
    // them in the order they were added, not in any other order
    // (alphabetical, ID, etc.) since the TUI list view renders in
    // insertion order per docs/DESIGN.md §4.7.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let a = add_account(&mut vault, &store, Some("alpha-xray"), "a");
    let _b = add_account(&mut vault, &store, Some("Acme"), "bob");
    let c = add_account(&mut vault, &store, Some("Xenon"), "c");
    let _d = add_account(&mut vault, &store, Some("Delta"), "d");
    let e = add_account(&mut vault, &store, Some("Box"), "e");

    let ids = filtered_account_ids(&vault, "x");
    assert_eq!(
        ids,
        vec![a, c, e],
        "filtered matches must keep vault insertion order"
    );
}

// ---------------------------------------------------------------------------
// Filter changes route through `paladin_auth_core::select_after_filter`
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Search — bullet 3)
//
// `select_after_search` composes `filtered_account_ids` with
// `paladin_auth_core::select_after_filter`: the previous selection is
// preserved when still visible after the filter rebuild; otherwise the
// first match is selected; the result is `None` only when the filtered
// set is empty.
// ---------------------------------------------------------------------------

#[test]
fn select_after_search_preserves_prev_when_still_visible() {
    // bullet 3 (preserve): when the new filter still includes the
    // previously selected account, the helper must return that same
    // `AccountId` so the user's cursor stays put across an
    // incremental search refinement.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let _a = add_account(&mut vault, &store, Some("Google"), "alice");
    let b = add_account(&mut vault, &store, Some("Gmail"), "bob");
    let _c = add_account(&mut vault, &store, Some("Acme"), "carol");

    let next = select_after_search(&vault, "gm", Some(b));
    assert_eq!(
        next,
        Some(b),
        "previously selected id that still matches the new query must be preserved"
    );
}

#[test]
fn select_after_search_falls_back_to_first_match_when_prev_filtered_out() {
    // bullet 3 (fall-back): when the previously selected account no
    // longer matches the new query, the helper must select the first
    // account of the new filtered set (vault insertion order).
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let a = add_account(&mut vault, &store, Some("Google"), "alice");
    let _b = add_account(&mut vault, &store, Some("Gmail"), "bob");
    let c = add_account(&mut vault, &store, Some("Acme"), "carol");

    // Previous selection is `a` (Google/alice). New query "ac"
    // matches only `c` (Acme/carol), so the helper falls back to the
    // first match in the new filtered set.
    let next = select_after_search(&vault, "ac", Some(a));
    assert_eq!(
        next,
        Some(c),
        "prev filtered out → helper must return the first match in the new filtered set"
    );
}

#[test]
fn select_after_search_returns_none_when_filtered_set_is_empty() {
    // bullet 3 (empty): when no account matches the new query, the
    // helper must return `None` regardless of the previous
    // selection. The list view's empty-state row has no selection.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let a = add_account(&mut vault, &store, Some("Google"), "alice");
    let _b = add_account(&mut vault, &store, Some("Gmail"), "bob");

    let next = select_after_search(&vault, "zzz-no-match", Some(a));
    assert_eq!(
        next, None,
        "empty filtered set must drop any prior selection"
    );
}

#[test]
fn select_after_search_with_none_prev_returns_first_match() {
    // bullet 3 (no prev): when there is no previous selection (e.g.
    // the list was previously empty and accounts now match the
    // query), the helper selects the first match.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let _a = add_account(&mut vault, &store, Some("Google"), "alice");
    let b = add_account(&mut vault, &store, Some("Gmail"), "bob");
    let _c = add_account(&mut vault, &store, Some("Acme"), "carol");

    let next = select_after_search(&vault, "gm", None);
    assert_eq!(
        next,
        Some(b),
        "with no previous selection the helper must return the first match"
    );
}

#[test]
fn select_after_search_empty_query_preserves_prev() {
    // bullet 3 (empty query / preserve): the empty query matches
    // every account, so the previous selection is always still
    // visible and must be preserved verbatim.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let _a = add_account(&mut vault, &store, Some("Google"), "alice");
    let b = add_account(&mut vault, &store, Some("Gmail"), "bob");
    let _c = add_account(&mut vault, &store, Some("Acme"), "carol");

    let next = select_after_search(&vault, "", Some(b));
    assert_eq!(
        next,
        Some(b),
        "empty query (matches all) must preserve the prior selection"
    );
}

#[test]
fn select_after_search_empty_query_empty_vault_returns_none() {
    // bullet 3 (empty vault): on an empty vault no account exists to
    // select, so the helper must return `None` even on the empty
    // query (which would otherwise match every account).
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let next = select_after_search(&vault, "", None);
    assert_eq!(
        next, None,
        "empty vault must return None regardless of query or prior selection"
    );
}

// ---------------------------------------------------------------------------
// The `id:` prefix form is CLI-only and is NOT honored by the TUI search
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Search — bullet 5)
//
// `paladin_auth_core::parse_account_query` recognizes `id:<hex>` as an
// `AccountQuery::IdPrefix` selector for CLI single-account resolution
// (docs/DESIGN.md §5). The TUI search bar deliberately does NOT call that
// parser — it delegates to `account_matches_search`, which treats the
// query as a plain case-insensitive substring needle. So `id:<hex>`
// typed into the search bar must look for the literal four-byte
// substring `"id:<hex>"` in `"{issuer}:{label}"`, never resolve as an
// account-id lookup.
// ---------------------------------------------------------------------------

/// Compute the lowercase 8-char hex prefix of an `AccountId`'s raw
/// bytes — the same projection the CLI's `id:` selector validates
/// against.
fn account_id_hex8(id: AccountId) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(32);
    for byte in id.as_bytes() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex.truncate(8);
    hex
}

#[test]
fn id_colon_hex_prefix_query_does_not_resolve_account_in_tui_search() {
    // bullet 5: CLI behavior — `id:<hex>` resolves to a single account
    // by `AccountId` prefix. TUI behavior — the same string is just a
    // substring needle, so an account whose `"{issuer}:{label}"` does
    // not contain the literal text `"id:<hex>"` must not match.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let alice = add_account(&mut vault, &store, Some("Google"), "alice");
    let _bob = add_account(&mut vault, &store, Some("GitHub"), "bob");

    // The CLI would resolve `id:<hex>` to alice. The TUI must not.
    let query = format!("id:{}", account_id_hex8(alice));
    let ids = filtered_account_ids(&vault, &query);
    assert!(
        ids.is_empty(),
        "TUI search must not resolve `id:<hex>` to an account by id; got {ids:?}"
    );

    // `select_after_search` composes the same predicate, so it too
    // must drop the prior selection (no account survives the filter).
    let next = select_after_search(&vault, &query, Some(alice));
    assert_eq!(
        next, None,
        "select_after_search must not honor `id:<hex>` either (no substring match → no selection)"
    );
}

#[test]
fn literal_id_colon_substring_in_issuer_still_matches_via_substring() {
    // bullet 5 (positive control): the TUI does not treat `id:` as a
    // selector, but it does see it as part of the substring needle.
    // An account whose issuer literally contains `"id:foo"` must be
    // found by a query of `"id:foo"`, exactly like any other
    // case-insensitive substring search.
    let tmp = secure_tempdir();
    let path = tmp.path().join("plain.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let _a = add_account(&mut vault, &store, Some("Google"), "alice");
    let weird = add_account(&mut vault, &store, Some("id:foo"), "carol");
    let _b = add_account(&mut vault, &store, Some("GitHub"), "bob");

    let ids = filtered_account_ids(&vault, "id:foo");
    assert_eq!(
        ids,
        vec![weird],
        "literal `id:foo` substring in issuer must still match — `id:` is not a selector here"
    );
}
