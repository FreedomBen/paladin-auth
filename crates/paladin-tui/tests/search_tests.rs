// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search filter tests for `paladin-tui`.
//!
//! Tracks the "Tests > Search (`tests/search_tests.rs`)" checklist in
//! `IMPLEMENTATION_PLAN_03_TUI.md`.

use std::path::Path;
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, IconHintInput, Store,
    Vault, VaultInit, VaultLock,
};
use paladin_tui::search::filtered_account_ids;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
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
// Case-insensitive substring match through `paladin_core::account_matches_search`
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Search — bullet 1)
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
fn case_insensitive_substring_matches_via_paladin_core_helper() {
    // bullet 1 (positive case): query "GMAIL" must match an account
    // whose issuer / label contains "gmail" in any casing — the
    // shared `paladin_core::account_matches_search` lower-cases both
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
// (IMPLEMENTATION_PLAN_03_TUI.md > Tests > Search — bullet 2)
// ---------------------------------------------------------------------------

#[test]
fn matches_returned_in_vault_insertion_order() {
    // Three accounts share the substring "x"; the helper must return
    // them in the order they were added, not in any other order
    // (alphabetical, ID, etc.) since the TUI list view renders in
    // insertion order per DESIGN.md §4.7.
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
