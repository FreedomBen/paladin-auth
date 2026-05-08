// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.1: in-memory `Vault` account-list operations (DESIGN.md §4.7
// `impl Vault` block). Covers `add` returning a stable `AccountId`,
// `iter` (insertion order), `get` by ID, `remove` by ID, and
// `summaries` non-secret projection. Storage round-trip stays in
// `vault_lifecycle.rs`; rename / find_duplicate / settings setters
// land in subsequent Phase G commits.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{parse_otpauth, Account, AccountId, AccountKindSummary, Algorithm, Vault};

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn empty_plaintext_vault() -> Vault {
    // `Vault::empty()` is `pub(crate)`; tests construct an in-memory
    // vault by going through the public storage entry point with a
    // throwaway `Store`. The G.1 surface is pure in-memory mutation,
    // so the storage layer is incidental scaffolding here.
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    // Leak the tempdir so the path stays valid for the returned Vault's
    // optional later save; we don't save in these tests, but holding the
    // dir keeps the layout symmetrical with `vault_lifecycle.rs`.
    std::mem::forget(dir);
    let (vault, _store) =
        paladin_core::Store::create(&path, paladin_core::VaultInit::Plaintext).unwrap();
    vault
}

#[test]
fn add_returns_the_accounts_stable_id() {
    let mut vault = empty_plaintext_vault();
    let account = make_account("alice", Some("Acme"));
    let expected_id = account.id();
    let returned_id = vault.add(account);
    assert_eq!(returned_id, expected_id);
    // The same account is retrievable by the returned id.
    assert!(vault.get(returned_id).is_some());
}

#[test]
fn add_yields_distinct_ids_for_each_appended_account() {
    let mut vault = empty_plaintext_vault();
    let id_a = vault.add(make_account("alice", None));
    let id_b = vault.add(make_account("bob", None));
    let id_c = vault.add(make_account("carol", None));
    assert_ne!(id_a, id_b);
    assert_ne!(id_b, id_c);
    assert_ne!(id_a, id_c);
}

#[test]
fn iter_yields_accounts_in_insertion_order() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", None));
    vault.add(make_account("bob", None));
    vault.add(make_account("carol", None));

    let labels: Vec<&str> = vault.iter().map(Account::label).collect();
    assert_eq!(labels, ["alice", "bob", "carol"]);
}

#[test]
fn iter_on_empty_vault_yields_nothing() {
    let vault = empty_plaintext_vault();
    assert!(vault.iter().next().is_none());
}

#[test]
fn get_returns_the_account_for_a_known_id() {
    let mut vault = empty_plaintext_vault();
    let id_a = vault.add(make_account("alice", None));
    let id_b = vault.add(make_account("bob", None));

    let alice = vault.get(id_a).expect("alice present");
    assert_eq!(alice.label(), "alice");
    assert_eq!(alice.id(), id_a);

    let bob = vault.get(id_b).expect("bob present");
    assert_eq!(bob.label(), "bob");
}

#[test]
fn get_returns_none_for_unknown_id() {
    let vault = empty_plaintext_vault();
    let unknown = AccountId::new();
    assert!(vault.get(unknown).is_none());
}

#[test]
fn remove_takes_the_account_by_id_and_returns_it() {
    let mut vault = empty_plaintext_vault();
    let id_a = vault.add(make_account("alice", None));
    let id_b = vault.add(make_account("bob", None));

    let removed = vault.remove(id_a).expect("alice removed");
    assert_eq!(removed.id(), id_a);
    assert_eq!(removed.label(), "alice");

    // alice is gone, bob remains.
    assert!(vault.get(id_a).is_none());
    assert!(vault.get(id_b).is_some());
    let labels: Vec<&str> = vault.iter().map(Account::label).collect();
    assert_eq!(labels, ["bob"]);
}

#[test]
fn remove_returns_none_for_unknown_id_and_does_not_mutate() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", None));
    vault.add(make_account("bob", None));
    let unknown = AccountId::new();

    assert!(vault.remove(unknown).is_none());
    let labels: Vec<&str> = vault.iter().map(Account::label).collect();
    assert_eq!(labels, ["alice", "bob"]);
}

#[test]
fn remove_preserves_insertion_order_of_remaining_accounts() {
    let mut vault = empty_plaintext_vault();
    let _id_a = vault.add(make_account("alice", None));
    let id_b = vault.add(make_account("bob", None));
    let _id_c = vault.add(make_account("carol", None));
    let _id_d = vault.add(make_account("dave", None));

    let _ = vault.remove(id_b).expect("bob removed");
    let labels: Vec<&str> = vault.iter().map(Account::label).collect();
    assert_eq!(labels, ["alice", "carol", "dave"]);
}

#[test]
fn summaries_yield_insertion_order_non_secret_projections() {
    let mut vault = empty_plaintext_vault();
    let id_a = vault.add(make_account("alice", Some("Acme")));
    let id_b = vault.add(make_account("bob", None));
    let id_c = vault.add(make_account("carol", Some("Acme")));

    let summaries: Vec<_> = vault.summaries().collect();
    assert_eq!(summaries.len(), 3);

    // Insertion order preserved.
    assert_eq!(summaries[0].id, id_a);
    assert_eq!(summaries[0].label, "alice");
    assert_eq!(summaries[0].issuer.as_deref(), Some("Acme"));
    assert_eq!(summaries[0].kind, AccountKindSummary::Totp);
    assert_eq!(summaries[0].algorithm, Algorithm::Sha1);
    assert_eq!(summaries[0].digits, 6);
    // TOTP entries report `period`, not `counter`.
    assert_eq!(summaries[0].period, Some(30));
    assert_eq!(summaries[0].counter, None);

    assert_eq!(summaries[1].id, id_b);
    assert_eq!(summaries[1].label, "bob");
    assert_eq!(summaries[1].issuer, None);

    assert_eq!(summaries[2].id, id_c);
    assert_eq!(summaries[2].label, "carol");
}

#[test]
fn summaries_match_account_summary_for_each_entry() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));
    vault.add(make_account("bob", None));

    let from_iter: Vec<_> = vault.iter().map(Account::summary).collect();
    let from_summaries: Vec<_> = vault.summaries().collect();
    assert_eq!(from_iter.len(), from_summaries.len());
    for (a, b) in from_iter.iter().zip(from_summaries.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.label, b.label);
        assert_eq!(a.issuer, b.issuer);
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.algorithm, b.algorithm);
        assert_eq!(a.digits, b.digits);
        assert_eq!(a.period, b.period);
        assert_eq!(a.counter, b.counter);
        assert_eq!(a.icon_hint, b.icon_hint);
        assert_eq!(a.created_at, b.created_at);
        assert_eq!(a.updated_at, b.updated_at);
    }
}
