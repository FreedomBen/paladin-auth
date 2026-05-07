// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Integration tests for `default_vault_path`, `inspect`, and the
// `classify_init_precheck` truth table (DESIGN.md §4.3 / §4.7 / §5).
//
// Subsequent Phase E commits will extend this file with `Store::open`,
// `Store::create`, `create_force`, and `mutate_and_save` coverage.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use paladin_core::{
    classify_init_precheck, default_vault_path, inspect, ErrorKind, InitPrecheck, PaladinError,
    VaultStatus,
};
use tempfile::TempDir;

/// Bytes of a valid 10-byte plaintext header.
fn plaintext_header_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    // PALADIN\0 + format_ver=1 + mode=0
    v.extend_from_slice(b"PALADIN\0");
    v.push(1);
    v.push(0);
    v
}

/// Bytes of a valid 64-byte encrypted header (sample params: defaults).
fn encrypted_header_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"PALADIN\0");
    v.push(1); // format_ver
    v.push(1); // mode = encrypted
    v.push(1); // kdf_id = Argon2id
    v.extend_from_slice(&65_536u32.to_le_bytes());
    v.extend_from_slice(&3u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&[0u8; 16]); // salt
    v.push(1); // aead_id = XChaCha20-Poly1305
    v.extend_from_slice(&[0u8; 24]); // nonce
    v
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.path().join(name);
    let mut f = fs::File::create(&p).expect("create test file");
    f.write_all(bytes).expect("write test bytes");
    p
}

#[test]
fn default_vault_path_resolves_under_paladin_with_vault_bin_filename() {
    let path = default_vault_path().expect("default_vault_path resolves on this platform");
    assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("vault.bin"));
    assert!(path.to_string_lossy().contains("paladin"));
}

#[test]
fn inspect_missing_returns_status_missing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.bin");
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Missing);
}

#[test]
fn inspect_plaintext_returns_plaintext() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "vault.bin", &plaintext_header_bytes());
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
}

#[test]
fn inspect_encrypted_returns_encrypted() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "vault.bin", &encrypted_header_bytes());
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
}

#[test]
fn inspect_does_not_enforce_permissions() {
    // §4.7: inspect deliberately skips the §4.3 permissions check so
    // callers can probe vault mode before fixing perms.
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "vault.bin", &plaintext_header_bytes());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
}

#[test]
fn inspect_unrecognized_magic_is_invalid_header() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "vault.bin", b"NOTPALADIN\0\x01\x00");
    assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
}

#[test]
fn inspect_unsupported_format_version_propagates() {
    let dir = TempDir::new().unwrap();
    let mut bytes = plaintext_header_bytes();
    bytes[8] = 99;
    let path = write(&dir, "vault.bin", &bytes);
    assert_eq!(
        inspect(&path).unwrap_err().kind(),
        ErrorKind::UnsupportedFormatVersion
    );
}

#[test]
fn classify_init_precheck_truth_table() {
    // Missing → Clear
    assert!(matches!(
        classify_init_precheck(Ok(VaultStatus::Missing)),
        InitPrecheck::Clear
    ));
    // Plaintext → Existing
    assert!(matches!(
        classify_init_precheck(Ok(VaultStatus::Plaintext)),
        InitPrecheck::Existing
    ));
    // Encrypted → Existing
    assert!(matches!(
        classify_init_precheck(Ok(VaultStatus::Encrypted)),
        InitPrecheck::Existing
    ));
    // InvalidHeader → Existing
    assert!(matches!(
        classify_init_precheck(Err(PaladinError::InvalidHeader)),
        InitPrecheck::Existing
    ));
    // UnsupportedFormatVersion → Existing
    assert!(matches!(
        classify_init_precheck(Err(PaladinError::UnsupportedFormatVersion)),
        InitPrecheck::Existing
    ));
    // Other Err → Propagate
    match classify_init_precheck(Err(PaladinError::VaultMissing)) {
        InitPrecheck::Propagate(PaladinError::VaultMissing) => {}
        other => panic!("expected Propagate(VaultMissing), got {other:?}"),
    }
}
