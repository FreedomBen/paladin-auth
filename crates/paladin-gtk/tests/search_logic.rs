// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic search tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/search_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Filtering routes through `paladin_core::account_matches_search`
//!   with the same case-insensitive substring rules as the CLI / TUI
//!   (empty issuer keeps the colon in the match key, no Unicode
//!   normalization).
//! * Post-filter selection routes through
//!   `paladin_core::select_after_filter` (preserve prior selection if
//!   still present, else first match).
//! * The CLI's `id:<hex>` prefix form is NOT honored by the GUI
//!   search (parity with the TUI).
//!
//! The tests build a plaintext vault in a `0700` tempdir so they run
//! on ordinary CI without a display server (per the §"Pure-logic
//! unit tests" preamble — these tests do not touch GTK).

use std::path::Path;
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm, IconHintInput, Store,
    Vault, VaultInit, VaultLock,
};
use paladin_gtk::search::{filtered_account_ids, select_after_search};

// --- fixtures ----------------------------------------------------------------

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
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

fn add_totp(vault: &mut Vault, store: &Store, issuer: Option<&str>, label: &str) -> AccountId {
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

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    _store: Store,
    a: AccountId,
    b: AccountId,
    c: AccountId,
}

fn build_three() -> Fixture {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let a = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let b = add_totp(&mut vault, &store, Some("GitLab"), "alice");
    let c = add_totp(&mut vault, &store, None, "solo");
    Fixture {
        _dir: dir,
        vault,
        _store: store,
        a,
        b,
        c,
    }
}

// --- filtered_account_ids ---------------------------------------------------

#[test]
fn empty_query_returns_all_account_ids_in_insertion_order() {
    let fx = build_three();
    assert_eq!(filtered_account_ids(&fx.vault, ""), vec![fx.a, fx.b, fx.c]);
}

#[test]
fn filter_is_case_insensitive_substring_match() {
    let fx = build_three();
    // "git" matches both "GitHub" and "GitLab" issuers, in insertion order.
    assert_eq!(filtered_account_ids(&fx.vault, "git"), vec![fx.a, fx.b]);
    // Uppercase query is normalized to the same result.
    assert_eq!(filtered_account_ids(&fx.vault, "GIT"), vec![fx.a, fx.b]);
    // Mixed case at the boundary still matches.
    assert_eq!(filtered_account_ids(&fx.vault, "GiTlAb"), vec![fx.b]);
    // Substring matches against the label, not just the issuer.
    assert_eq!(filtered_account_ids(&fx.vault, "alice"), vec![fx.b]);
}

#[test]
fn match_key_keeps_colon_for_empty_issuer() {
    let fx = build_three();
    // Account `c` has `issuer = None`; the match key is `":solo"` so a
    // bare `":"` query matches it (alongside `a` and `b`, whose `":"`
    // separators sit between issuer and label in their match keys).
    let ids = filtered_account_ids(&fx.vault, ":");
    assert!(
        ids.contains(&fx.c),
        "empty issuer must keep the colon in the match key"
    );
    // The label-only path still matches `c` without the colon.
    assert_eq!(filtered_account_ids(&fx.vault, "solo"), vec![fx.c]);
}

#[test]
fn no_match_returns_empty_vec() {
    let fx = build_three();
    assert!(filtered_account_ids(&fx.vault, "no-such-issuer").is_empty());
}

// --- select_after_search ----------------------------------------------------

#[test]
fn select_after_search_preserves_prev_when_still_visible() {
    let fx = build_three();
    // Query "git" keeps both `a` and `b`. Prev = `b` should survive.
    assert_eq!(
        select_after_search(&fx.vault, "git", Some(fx.b)),
        Some(fx.b)
    );
}

#[test]
fn select_after_search_falls_back_to_first_match_when_prev_filtered_out() {
    let fx = build_three();
    // "git" filters out `c`; prev = `c` should land on the first match `a`.
    assert_eq!(
        select_after_search(&fx.vault, "git", Some(fx.c)),
        Some(fx.a)
    );
    // None prev defaults to the first match.
    assert_eq!(select_after_search(&fx.vault, "git", None), Some(fx.a));
    // When only `c` matches, prev = `a` slides to `c` (insertion order
    // among a single-element filtered set is trivially preserved).
    assert_eq!(
        select_after_search(&fx.vault, "solo", Some(fx.a)),
        Some(fx.c)
    );
}

#[test]
fn select_after_search_returns_none_for_empty_filter() {
    let fx = build_three();
    assert_eq!(select_after_search(&fx.vault, "xyz", Some(fx.a)), None);
    assert_eq!(select_after_search(&fx.vault, "xyz", None), None);
}

// --- CLI id: prefix parity --------------------------------------------------

#[test]
fn cli_id_prefix_form_is_not_honored() {
    let fx = build_three();
    let raw_uuid = format!("{}", fx.a);
    let cli_form = format!("id:{}", fx.a);
    // Neither the raw UUID nor the CLI `id:<hex>` shorthand should
    // match — the GUI search filter only considers the
    // `issuer:label` match key, parity with `paladin_tui::search`.
    assert!(
        filtered_account_ids(&fx.vault, &raw_uuid).is_empty(),
        "raw UUID `{raw_uuid}` must not match the issuer:label key"
    );
    assert!(
        filtered_account_ids(&fx.vault, &cli_form).is_empty(),
        "CLI `{cli_form}` shorthand must be ignored by the GUI search"
    );
}
