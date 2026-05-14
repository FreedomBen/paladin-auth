// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic coverage for `account_list::row_models_from_vault` and
//! the shared `account_list::format_rendered_marker` helper.
//!
//! `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AccountListComponent` pins the row factory to a `gio::ListStore`
//! built from `paladin_core::AccountSummary` projections — the
//! widget layer never touches secret bytes. These tests exercise
//! the projection layer directly so the assertions run without a
//! display server (the parallel `tests/gtk_smoke.rs` covers the same
//! path end-to-end under `xvfb-run` in CI).
//!
//! The `format_rendered_marker` helper is the source of truth for
//! the stdout marker `paladin-gtk` emits under `--exit-after-startup`
//! once the `AccountListComponent` has been bound. The smoke test in
//! `tests/gtk_smoke.rs` greps for that line, so the string format is
//! locked here.

use std::path::Path;
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, AccountKindSummary, Algorithm,
    IconHintInput, Store, Vault, VaultInit, VaultLock,
};
use paladin_gtk::account_list::{format_rendered_marker, row_models_from_vault, AccountRowModel};

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

fn add_hotp(
    vault: &mut Vault,
    store: &Store,
    issuer: Option<&str>,
    label: &str,
    counter: u64,
) -> AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Hotp,
        period_secs: None,
        counter: Some(counter),
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

// ---------------------------------------------------------------------------
// `row_models_from_vault`
// ---------------------------------------------------------------------------

#[test]
fn row_models_empty_vault_is_empty() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let rows = row_models_from_vault(&vault);
    assert!(
        rows.is_empty(),
        "an empty vault projects no rows, got: {rows:?}",
    );
}

#[test]
fn row_models_preserves_insertion_order() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let a = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let b = add_totp(&mut vault, &store, Some("GitLab"), "alice");
    let c = add_totp(&mut vault, &store, None, "solo");

    let rows = row_models_from_vault(&vault);
    let ids: Vec<AccountId> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids,
        vec![a, b, c],
        "row projection must follow Vault::summaries() insertion order",
    );
}

#[test]
fn row_models_carry_summary_and_label() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp(&mut vault, &store, Some("GitHub"), "ben");
    add_hotp(&mut vault, &store, None, "solo", 7);

    let rows = row_models_from_vault(&vault);
    assert_eq!(rows.len(), 2);

    assert_eq!(rows[0].kind, AccountKindSummary::Totp);
    assert_eq!(rows[0].display_label, "GitHub:ben");

    assert_eq!(rows[1].kind, AccountKindSummary::Hotp);
    assert_eq!(rows[1].display_label, "solo");
    assert_eq!(rows[1].counter, Some(7));
}

#[test]
fn row_models_drop_empty_issuer_in_display_label() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    // Issuer-only-empty must collapse to the bare label so the row
    // never carries a dangling `:label` colon (parity with
    // `account_row::display_label` and `remove_dialog::summary_display_label`).
    add_totp(&mut vault, &store, Some(""), "alice");

    let rows = row_models_from_vault(&vault);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].display_label, "alice");
}

// ---------------------------------------------------------------------------
// `format_rendered_marker`
// ---------------------------------------------------------------------------

#[test]
fn marker_empty_list_emits_empty_suffix() {
    let rendered: Vec<AccountRowModel> = Vec::new();
    assert_eq!(
        format_rendered_marker(&rendered),
        "paladin-gtk: account_list_rows="
    );
}

#[test]
fn marker_pipe_joins_display_labels_in_order() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp(&mut vault, &store, Some("GitHub"), "ben");
    add_totp(&mut vault, &store, Some("GitLab"), "alice");
    add_hotp(&mut vault, &store, None, "solo", 0);

    let rows = row_models_from_vault(&vault);
    assert_eq!(
        format_rendered_marker(&rows),
        "paladin-gtk: account_list_rows=GitHub:ben|GitLab:alice|solo",
    );
}
