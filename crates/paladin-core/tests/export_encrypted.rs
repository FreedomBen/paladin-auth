// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.9 — `export::encrypted` (DESIGN.md §4.6 / §4.7).
//
// Pinning:
//   - Round-trip with `import::paladin` recovers the same accounts.
//   - Wrong passphrase opens to `decrypt_failed` (B opens an A bundle).
//   - Corrupt ciphertext byte → `decrypt_failed` (AAD/AEAD mismatch).
//   - Garbage plaintext under the right key (re-encrypt) → `invalid_payload`
//     with `reason: "decode_failed"`.
//   - These three failure modes are distinct from
//     `unsupported_plaintext_vault` (covered in Phase I.4 /
//     `import_paladin.rs`).
//   - Empty passphrase rejected at `EncryptionOptions::new`.
//   - Source `VaultSettings` are dropped (the bundle holds
//     `VaultSettings::default()`).

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    export, import, parse_otpauth, Account, Argon2Params, EncryptionOptions, ErrorKind,
    PaladinError, Store, VaultInit,
};
use secrecy::SecretString;
use tempfile::TempDir;

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
    .expect("in-bounds")
}

fn vault_test_dir() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn make_account(uri: &str) -> Account {
    parse_otpauth(uri, import_time()).unwrap().account
}

const URI_TOTP_A: &str = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
const URI_HOTP_B: &str =
    "otpauth://hotp/Globex:bob?secret=NBSWY3DPEHPK3PXP&issuer=Globex&counter=7";

fn sample_vault() -> (TempDir, paladin_core::Vault, Store) {
    let dir = vault_test_dir();
    let path = dir.path().join("source.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    let _ = vault.add(make_account(URI_HOTP_B));
    (dir, vault, store)
}

// ---------- Round-trip ----------

#[test]
fn round_trip_via_import_paladin_returns_same_accounts() {
    let (_dir, vault, _store) = sample_vault();
    let bundle = export::encrypted(&vault, cheap_options("hunter2")).unwrap();

    let imported = import::paladin(&bundle, pp("hunter2")).unwrap();
    assert_eq!(imported.len(), 2);
    assert_eq!(imported[0].account.label(), "alice");
    assert_eq!(imported[1].account.label(), "bob");
    assert_eq!(imported[1].account.counter(), Some(7));
}

#[test]
fn bundle_starts_with_paladin_magic_and_is_encrypted_mode() {
    let (_dir, vault, _store) = sample_vault();
    let bundle = export::encrypted(&vault, cheap_options("hunter2")).unwrap();
    assert!(bundle.len() >= 64);
    assert_eq!(&bundle[0..8], b"PALADIN\0");
    assert_eq!(bundle[8], 1, "format_ver");
    assert_eq!(bundle[9], 1, "encrypted mode");
}

// ---------- Failure mode: wrong passphrase ----------

#[test]
fn bundle_written_with_passphrase_a_opened_with_b_returns_decrypt_failed() {
    let (_dir, vault, _store) = sample_vault();
    let bundle = export::encrypted(&vault, cheap_options("aaa")).unwrap();
    let err = import::paladin(&bundle, pp("bbb")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed);
}

// ---------- Failure mode: corrupt ciphertext ----------

#[test]
fn corrupt_ciphertext_byte_returns_decrypt_failed() {
    let (_dir, vault, _store) = sample_vault();
    let mut bundle = export::encrypted(&vault, cheap_options("hunter2")).unwrap();
    let last = bundle.len() - 1;
    bundle[last] ^= 0x42;
    let err = import::paladin(&bundle, pp("hunter2")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed);
}

// ---------- Failure mode: corrupt plaintext (decode_failed) ----------

#[cfg(feature = "test-zeroize-witness")]
#[test]
fn garbage_plaintext_under_right_key_returns_invalid_payload() {
    use paladin_core::_testing_write_encrypted_with_raw_plaintext;

    let dir = vault_test_dir();
    let path = dir.path().join("garbage.bin");
    // Encrypt non-bincode bytes under a known passphrase. AEAD
    // authenticates (right key, intact AAD), so the failure surfaces
    // from `decode_vault_payload` after the bytes round-trip through
    // the AEAD. Per-reason discriminator follows the existing
    // `zeroize_witness.rs` matrix: any of the three known
    // bincode-failure reasons is acceptable here.
    let garbage: Vec<u8> = (0..256u32).map(|i| (i as u8) ^ 0xA5).collect();
    _testing_write_encrypted_with_raw_plaintext(&path, &pp("hunter2"), cheap_params(), &garbage)
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    let err = import::paladin(&bytes, pp("hunter2")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);
    if let PaladinError::InvalidPayload { reason } = err {
        assert!(matches!(
            reason,
            "decode_failed" | "trailing_bytes" | "exceeds_size_limit"
        ));
    }
}

// ---------- EncryptionOptions rejects empty passphrase ----------

#[test]
fn empty_passphrase_rejected_by_encryption_options_constructor() {
    let err = EncryptionOptions::with_params(pp(""), cheap_params()).unwrap_err();
    let PaladinError::InvalidPassphrase { reason } = err else {
        panic!("expected InvalidPassphrase, got {err:?}");
    };
    assert_eq!(reason, "zero_length");
}

fn cheap_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    }
}

// ---------- Source VaultSettings discarded ----------

#[test]
fn source_vault_settings_are_replaced_with_defaults_in_bundle() {
    // Build a source vault with non-default settings.
    let dir = vault_test_dir();
    let path = dir.path().join("source.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(900).unwrap();

    let bundle = export::encrypted(&vault, cheap_options("hunter2")).unwrap();

    // Open the bundle as a vault (Store::open) and verify settings are
    // reset to defaults — only accounts crossed the boundary.
    let bundle_path = dir.path().join("bundle.bin");
    fs::write(&bundle_path, &bundle).unwrap();
    fs::set_permissions(&bundle_path, fs::Permissions::from_mode(0o600)).unwrap();
    let (opened, _store) = Store::open(
        &bundle_path,
        paladin_core::VaultLock::Encrypted(pp("hunter2")),
    )
    .unwrap();
    let s = opened.settings();
    assert!(!s.auto_lock_enabled());
    assert_eq!(s.auto_lock_timeout_secs(), 300);
    assert!(!s.clipboard_clear_enabled());
    assert_eq!(s.clipboard_clear_secs(), 20);
}

// ---------- Custom Argon2 params written into header ----------

#[test]
fn custom_argon2_params_are_written_into_bundle_header() {
    let (_dir, vault, _store) = sample_vault();
    let custom = Argon2Params {
        m_kib: 16_384,
        t: 2,
        p: 1,
    };
    let opts = EncryptionOptions::with_params(pp("hunter2"), custom).unwrap();
    let bundle = export::encrypted(&vault, opts).unwrap();
    // Per §4.3 header layout: m_kib at bytes [11..15], t at [15..19], p at [19..23].
    let m = u32::from_le_bytes(bundle[11..15].try_into().unwrap());
    let t = u32::from_le_bytes(bundle[15..19].try_into().unwrap());
    let p = u32::from_le_bytes(bundle[19..23].try_into().unwrap());
    assert_eq!(m, 16_384);
    assert_eq!(t, 2);
    assert_eq!(p, 1);
}
