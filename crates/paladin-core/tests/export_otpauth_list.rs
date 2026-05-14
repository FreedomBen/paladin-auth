// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.8 — `export::otpauth_list` (DESIGN.md §4.6 / §4.7).

#![cfg(unix)]

mod common;

use common::test_tempdir;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    export, import, parse_otpauth, Account, AccountKindSummary, ImportOptions, Store, VaultInit,
};
use tempfile::TempDir;

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn vault_test_dir() -> TempDir {
    let dir = test_tempdir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn make_account(uri: &str) -> Account {
    parse_otpauth(uri, import_time()).unwrap().account
}

const URI_TOTP_A: &str = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
const URI_HOTP_B: &str =
    "otpauth://hotp/Globex:bob?secret=NBSWY3DPEHPK3PXP&issuer=Globex&counter=7";

#[test]
fn empty_vault_emits_empty_json_array() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    assert_eq!(export::otpauth_list(&vault), "[]");
}

#[test]
fn single_account_emits_one_uri_in_array() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    let json = export::otpauth_list(&vault);

    let arr: Vec<String> = serde_json::from_str(&json).unwrap();
    assert_eq!(arr.len(), 1);
    assert!(arr[0].starts_with("otpauth://totp/"));
    assert!(arr[0].contains("secret="));
    assert!(arr[0].contains("issuer=Acme"));
}

#[test]
fn multiple_accounts_preserve_insertion_order() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    let _ = vault.add(make_account(URI_HOTP_B));
    let json = export::otpauth_list(&vault);
    let arr: Vec<String> = serde_json::from_str(&json).unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr[0].contains("totp"));
    assert!(arr[1].contains("hotp"));
}

#[test]
fn round_trip_yields_matching_validated_accounts_modulo_timestamps() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    let _ = vault.add(make_account(URI_HOTP_B));
    let json = export::otpauth_list(&vault);

    // Re-import via the auto-detect facade: detect should classify as
    // Otpauth and the importer should parse every URI back.
    let imported =
        import::from_bytes(json.as_bytes(), ImportOptions::default(), import_time()).unwrap();
    assert_eq!(imported.len(), 2);

    let exported_accounts: Vec<&Account> = vault.iter().collect();
    for (orig, va) in exported_accounts.iter().zip(imported.iter()) {
        let imp = &va.account;
        assert_eq!(orig.label(), imp.label());
        assert_eq!(orig.issuer(), imp.issuer());
        // Secret-byte equality is asserted in the in-crate unit test
        // `src/export/otpauth_list.rs::tests::
        // round_trip_preserves_secret_bytes_for_every_account` —
        // `Account::secret()` is `pub(crate)` so it cannot be checked
        // from this integration-test scope.
        assert_eq!(orig.algorithm(), imp.algorithm());
        assert_eq!(orig.digits(), imp.digits());
        assert_eq!(orig.kind(), imp.kind());
        if matches!(orig.kind(), AccountKindSummary::Hotp) {
            assert_eq!(orig.counter(), imp.counter());
        } else {
            assert_eq!(orig.period(), imp.period());
        }
        assert_eq!(orig.icon_hint(), imp.icon_hint());
        // Timestamps come from import_time on re-import; equal here
        // only because we used the same import_time on both sides.
        assert_eq!(imp.created_at(), 1_700_000_000);
        assert_eq!(imp.updated_at(), 1_700_000_000);
    }
}

#[test]
fn export_uses_canonical_emitter_so_each_uri_round_trips_through_parse_otpauth() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    let _ = vault.add(make_account(URI_HOTP_B));
    let json = export::otpauth_list(&vault);
    let arr: Vec<String> = serde_json::from_str(&json).unwrap();
    for uri in arr {
        let _ = parse_otpauth(&uri, import_time())
            .expect("emitted URI should round-trip through parse_otpauth");
    }
}
