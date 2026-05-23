// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.6 — `import::from_file` / `import::from_bytes` facade
// (docs/DESIGN.md §4.6 / §4.7).

#![cfg(unix)]

mod common;

use common::test_tempdir;

use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use image::{ImageFormat, Luma};
use paladin_core::{
    import, parse_otpauth, Account, Argon2Params, EncryptionOptions, ImportFormat, ImportOptions,
    PaladinError, Store, VaultInit,
};
use qrcode::QrCode;
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

fn aegis_bytes_one_totp() -> Vec<u8> {
    br#"{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[{"type":"totp","name":"alice","issuer":"Acme","info":{"secret":"JBSWY3DPEHPK3PXP"}}]}}"#.to_vec()
}

fn paladin_bundle_bytes(passphrase: &str, accounts: &[&str]) -> Vec<u8> {
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

fn write_qr_png(dir: &TempDir, name: &str, payload: &str) -> PathBuf {
    let code = QrCode::new(payload.as_bytes()).expect("encode QR");
    let luma = code
        .render::<Luma<u8>>()
        .min_dimensions(160, 160)
        .quiet_zone(true)
        .build();
    let path = dir.path().join(format!("{name}.png"));
    let mut buf = Cursor::new(Vec::new());
    luma.write_to(&mut buf, ImageFormat::Png).unwrap();
    fs::write(&path, buf.into_inner()).unwrap();
    path
}

fn qr_png_bytes(payload: &str) -> Vec<u8> {
    let code = QrCode::new(payload.as_bytes()).expect("encode QR");
    let luma = code
        .render::<Luma<u8>>()
        .min_dimensions(160, 160)
        .quiet_zone(true)
        .build();
    let mut buf = Cursor::new(Vec::new());
    luma.write_to(&mut buf, ImageFormat::Png).unwrap();
    buf.into_inner()
}

// ---------- ImportOptions defaults ----------

#[test]
fn default_import_options_has_no_format_or_passphrase() {
    let opts = ImportOptions::default();
    assert!(opts.format.is_none());
    assert!(opts.paladin_passphrase.is_none());
}

// ---------- from_bytes auto-detect ----------

#[test]
fn from_bytes_auto_detects_otpauth() {
    let imported = import::from_bytes(
        URI_TOTP_A.as_bytes(),
        ImportOptions::default(),
        import_time(),
    )
    .unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].account.label(), "alice");
}

#[test]
fn from_bytes_auto_detects_aegis() {
    let bytes = aegis_bytes_one_totp();
    let imported = import::from_bytes(&bytes, ImportOptions::default(), import_time()).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].account.label(), "alice");
}

#[test]
fn from_bytes_auto_detects_qr_image_via_png_decode() {
    let bytes = qr_png_bytes(URI_TOTP_A);
    let imported = import::from_bytes(&bytes, ImportOptions::default(), import_time()).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].account.label(), "alice");
}

#[test]
fn from_bytes_auto_detects_paladin_with_passphrase() {
    let bytes = paladin_bundle_bytes("hunter2", &[URI_TOTP_A]);
    let opts = ImportOptions {
        format: None,
        paladin_passphrase: Some(pp("hunter2")),
    };
    let imported = import::from_bytes(&bytes, opts, import_time()).unwrap();
    assert_eq!(imported.len(), 1);
}

#[test]
fn from_bytes_unknown_returns_unsupported_import_format_unknown() {
    let bytes = b"random gibberish that matches no format";
    let err = import::from_bytes(bytes, ImportOptions::default(), import_time()).unwrap_err();
    let PaladinError::UnsupportedImportFormat { format } = err else {
        panic!("expected UnsupportedImportFormat, got {err:?}");
    };
    assert_eq!(format, "unknown");
}

#[test]
fn from_bytes_paladin_without_passphrase_returns_invalid_state_missing_passphrase() {
    let bytes = paladin_bundle_bytes("hunter2", &[URI_TOTP_A]);
    let err = import::from_bytes(&bytes, ImportOptions::default(), import_time()).unwrap_err();
    let PaladinError::InvalidState { operation, state } = err else {
        panic!("expected InvalidState, got {err:?}");
    };
    assert_eq!(operation, "import_paladin");
    assert_eq!(state, "missing_passphrase");
}

// ---------- from_bytes forced format ----------

#[test]
fn from_bytes_forced_otpauth_succeeds_on_otpauth_text() {
    let opts = ImportOptions {
        format: Some(ImportFormat::Otpauth),
        paladin_passphrase: None,
    };
    let imported = import::from_bytes(URI_TOTP_A.as_bytes(), opts, import_time()).unwrap();
    assert_eq!(imported.len(), 1);
}

#[test]
fn from_bytes_forced_qr_on_otpauth_text_returns_unsupported_import_format_qr() {
    let opts = ImportOptions {
        format: Some(ImportFormat::QrImage),
        paladin_passphrase: None,
    };
    let err = import::from_bytes(URI_TOTP_A.as_bytes(), opts, import_time()).unwrap_err();
    let PaladinError::UnsupportedImportFormat { format } = err else {
        panic!("expected UnsupportedImportFormat, got {err:?}");
    };
    assert_eq!(format, "qr");
}

#[test]
fn from_bytes_forced_paladin_on_aegis_returns_unsupported_import_format_paladin() {
    let opts = ImportOptions {
        format: Some(ImportFormat::Paladin),
        paladin_passphrase: Some(pp("hunter2")),
    };
    let err = import::from_bytes(&aegis_bytes_one_totp(), opts, import_time()).unwrap_err();
    let PaladinError::UnsupportedImportFormat { format } = err else {
        panic!("expected UnsupportedImportFormat, got {err:?}");
    };
    assert_eq!(format, "paladin");
}

// ---------- from_file auto-detect ----------

#[test]
fn from_file_auto_detects_otpauth_text_file() {
    let dir = test_tempdir();
    let path = dir.path().join("uris.txt");
    fs::write(&path, URI_TOTP_A).unwrap();
    let imported = import::from_file(&path, ImportOptions::default(), import_time()).unwrap();
    assert_eq!(imported.len(), 1);
}

#[test]
fn from_file_auto_detects_aegis_json_file() {
    let dir = test_tempdir();
    let path = dir.path().join("aegis.json");
    fs::write(&path, aegis_bytes_one_totp()).unwrap();
    let imported = import::from_file(&path, ImportOptions::default(), import_time()).unwrap();
    assert_eq!(imported.len(), 1);
}

#[test]
fn from_file_auto_detects_qr_png_file() {
    let dir = test_tempdir();
    let path = write_qr_png(&dir, "totp_a", URI_HOTP_B);
    let imported = import::from_file(&path, ImportOptions::default(), import_time()).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].account.label(), "bob");
}

#[test]
fn from_file_auto_detects_paladin_bundle_file() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    vault.save(&store).unwrap();

    let opts = ImportOptions {
        format: None,
        paladin_passphrase: Some(pp("hunter2")),
    };
    let imported = import::from_file(&path, opts, import_time()).unwrap();
    assert_eq!(imported.len(), 1);
}

#[test]
fn from_file_missing_file_returns_io_error() {
    let dir = test_tempdir();
    let path = dir.path().join("nope.bin");
    let err = import::from_file(&path, ImportOptions::default(), import_time()).unwrap_err();
    let PaladinError::IoError { operation, .. } = err else {
        panic!("expected IoError, got {err:?}");
    };
    assert_eq!(operation, "read_import_file");
}

#[test]
fn from_file_paladin_without_passphrase_returns_invalid_state() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let _ = vault.add(make_account(URI_TOTP_A));
    vault.save(&store).unwrap();

    let err = import::from_file(&path, ImportOptions::default(), import_time()).unwrap_err();
    let PaladinError::InvalidState { operation, state } = err else {
        panic!("expected InvalidState, got {err:?}");
    };
    assert_eq!(operation, "import_paladin");
    assert_eq!(state, "missing_passphrase");
}

#[test]
fn from_file_unknown_returns_unsupported_import_format_unknown() {
    let dir = test_tempdir();
    let path = dir.path().join("random.bin");
    fs::write(&path, b"this is not any known import format").unwrap();
    let err = import::from_file(&path, ImportOptions::default(), import_time()).unwrap_err();
    let PaladinError::UnsupportedImportFormat { format } = err else {
        panic!("expected UnsupportedImportFormat, got {err:?}");
    };
    assert_eq!(format, "unknown");
}
