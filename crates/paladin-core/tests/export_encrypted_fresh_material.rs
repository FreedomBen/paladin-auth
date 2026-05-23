// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.10 — `export::encrypted` fresh salt + nonce per call.
//
// Pinning: across `N = 64` exports of the same vault under the same
// passphrase and Argon2 params, every observed bundle `salt` and
// `nonce` is pairwise distinct, every bundle imports successfully
// with the passphrase, and the exported account set is identical.
//
// Catches a fixed-salt or fixed-nonce regression in the export-only
// crypto path (separate from `Store` saves, which have their own
// fresh-material tests).

#![cfg(unix)]

mod common;

use common::test_tempdir;

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    export, import, parse_otpauth, Account, Argon2Params, EncryptionOptions, Store, VaultInit,
};
use secrecy::SecretString;
use tempfile::TempDir;

const N: usize = 64;

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(
        pp(passphrase),
        Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        },
    )
    .unwrap()
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
fn n_exports_use_pairwise_distinct_salts_and_nonces_and_all_round_trip() {
    let dir = vault_test_dir();
    let path = dir.path().join("source.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    let _ = vault.add(make_account(URI_HOTP_B));

    let mut salts: HashSet<[u8; 16]> = HashSet::with_capacity(N);
    let mut nonces: HashSet<[u8; 24]> = HashSet::with_capacity(N);

    for _ in 0..N {
        let bundle = export::encrypted(&vault, cheap_options("hunter2")).unwrap();

        // Bundle layout (docs/DESIGN.md §4.3 encrypted header):
        //   [0..8]   "PALADIN\0"
        //   [8]      format_ver = 1
        //   [9]      mode       = 1 (encrypted)
        //   [10]     kdf_id     = 1
        //   [11..23] m_kib | t | p (each u32 LE)
        //   [23..39] salt (16 bytes)
        //   [39]     aead_id    = 1
        //   [40..64] nonce (24 bytes)
        let salt: [u8; 16] = bundle[23..39].try_into().unwrap();
        let nonce: [u8; 24] = bundle[40..64].try_into().unwrap();
        assert!(salts.insert(salt), "duplicate salt across exports");
        assert!(nonces.insert(nonce), "duplicate nonce across exports");

        // Round-trips with the same passphrase.
        let imported = import::paladin(&bundle, pp("hunter2")).unwrap();
        assert_eq!(imported.len(), 2);
        assert_eq!(imported[0].account.label(), "alice");
        assert_eq!(imported[1].account.label(), "bob");
        assert_eq!(imported[1].account.counter(), Some(7));
    }

    assert_eq!(salts.len(), N);
    assert_eq!(nonces.len(), N);
}
