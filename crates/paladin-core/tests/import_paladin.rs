// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.4 — `import::paladin` (DESIGN.md §4.6 / §4.7).
//
// A Paladin import bundle is the same on-disk format as the encrypted
// vault file (magic + 64-byte AAD-bound header + AEAD ciphertext over a
// bincode `VaultPayload`). The importer reads bytes only; perms and
// path are the caller's concern.
//
// Behavior pinned here:
//   - Encrypted bundle round-trips with the on-disk encrypted format,
//     preserving `icon_hint` / timestamps and discarding the source
//     `VaultSettings` (only accounts are returned).
//   - Plaintext-mode Paladin file → `unsupported_plaintext_vault`.
//   - Wrong passphrase → `decrypt_failed` (AAD/AEAD mismatch).
//   - Empty bundle → `no_entries_to_import`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    import, parse_otpauth, Account, Argon2Params, EncryptionOptions, ErrorKind, Store, Vault,
    VaultInit,
};
use secrecy::SecretString;
use tempfile::TempDir;

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn vault_test_dir() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    dir
}

fn cheap_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    }
}

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(pp(passphrase), cheap_params()).expect("in-bounds params")
}

fn make_account(uri: &str) -> Account {
    parse_otpauth(uri, import_time()).unwrap().account
}

/// Write an encrypted vault to a fresh tempdir with the supplied
/// accounts, return its on-disk bytes.
fn build_bundle_bytes(passphrase: &str, accounts: &[&str]) -> Vec<u8> {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options(passphrase))).unwrap();
    for uri in accounts {
        let _ = vault.add(make_account(uri));
    }
    vault.save(&store).unwrap();
    fs::read(&path).unwrap()
}

const URI_TOTP_A: &str = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
const URI_HOTP_B: &str =
    "otpauth://hotp/Globex:bob?secret=NBSWY3DPEHPK3PXP&issuer=Globex&counter=7";

// ---------- Round-trip ----------

#[test]
fn encrypted_bundle_round_trips_with_correct_passphrase() {
    let bytes = build_bundle_bytes("hunter2", &[URI_TOTP_A, URI_HOTP_B]);
    let imported = import::paladin(&bytes, pp("hunter2")).unwrap();
    assert_eq!(imported.len(), 2);
    assert_eq!(imported[0].account.label(), "alice");
    assert_eq!(imported[1].account.label(), "bob");
    assert_eq!(imported[1].account.counter(), Some(7));
}

#[test]
fn round_trip_preserves_icon_hint_and_timestamps() {
    let bytes = build_bundle_bytes("hunter2", &[URI_TOTP_A]);
    let imported = import::paladin(&bytes, pp("hunter2")).unwrap();
    let acct = &imported[0].account;
    // parse_otpauth defaults icon_hint from issuer (Acme).
    assert_eq!(acct.icon_hint(), Some("acme"));
    // Bundle timestamps are preserved (they came from import_time at
    // build time, equal to the in-vault values).
    assert_eq!(acct.created_at(), 1_700_000_000);
    assert_eq!(acct.updated_at(), 1_700_000_000);
}

// ---------- Plaintext rejection ----------

#[test]
fn plaintext_paladin_file_rejects_unsupported_plaintext_vault() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    vault.save(&store).unwrap();
    let bytes = fs::read(&path).unwrap();

    let err = import::paladin(&bytes, pp("hunter2")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedPlaintextVault);
}

// ---------- Wrong passphrase ----------

#[test]
fn wrong_passphrase_returns_decrypt_failed() {
    let bytes = build_bundle_bytes("hunter2", &[URI_TOTP_A]);
    let err = import::paladin(&bytes, pp("wrong-passphrase")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed);
}

#[test]
fn corrupt_ciphertext_byte_returns_decrypt_failed() {
    let mut bytes = build_bundle_bytes("hunter2", &[URI_TOTP_A]);
    // Flip a byte deep in the ciphertext (after the 64-byte header).
    let last = bytes.len() - 1;
    bytes[last] ^= 0x42;
    let err = import::paladin(&bytes, pp("hunter2")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed);
}

// ---------- Empty bundle ----------

#[test]
fn empty_bundle_returns_no_entries_to_import() {
    let bytes = build_bundle_bytes("hunter2", &[]);
    let err = import::paladin(&bytes, pp("hunter2")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
}

// ---------- Source VaultSettings discarded ----------

#[test]
fn source_vault_settings_are_discarded() {
    // Build a bundle whose source vault has non-default settings;
    // import::paladin must surface only accounts (no settings type
    // is exposed). The Vec we get back has no settings field at all,
    // which is the discarding mechanism.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    // Flip a non-default setting before save.
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(900).unwrap();
    vault.save(&store).unwrap();
    let bytes = fs::read(&path).unwrap();

    let imported = import::paladin(&bytes, pp("hunter2")).unwrap();
    assert_eq!(imported.len(), 1);
    // Pin: caller cannot reach into VaultSettings via the imported
    // Vec — there is nothing to reach. (Also pinned at the type
    // level — Vec<ValidatedAccount> has no settings field.)
    let _: &paladin_core::ValidatedAccount = &imported[0];
}

// ---------- Header / format errors ----------

#[test]
fn invalid_magic_returns_invalid_header() {
    let bytes = vec![0u8; 200];
    let err = import::paladin(&bytes, pp("hunter2")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidHeader);
}

#[test]
fn truncated_input_returns_invalid_header() {
    let err = import::paladin(b"PAL", pp("hunter2")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidHeader);
}

#[test]
fn bundle_with_unsupported_format_version_is_rejected() {
    let mut bytes = build_bundle_bytes("hunter2", &[URI_TOTP_A]);
    bytes[8] = 99; // mutate format_ver
    let err = import::paladin(&bytes, pp("hunter2")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedFormatVersion);
}

// ---------- Helper exists once Vault::add is available ----------
// (sanity: the imported Vault impl must surface set_auto_lock_*)

#[allow(dead_code)]
fn _vault_setters_exist(v: &mut Vault) {
    v.set_auto_lock_enabled(true);
    let _ = v.set_auto_lock_timeout_secs(60);
}
