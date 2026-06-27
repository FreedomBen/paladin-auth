// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Encrypted-mode tamper matrix (docs/DESIGN.md §4.3 + §4.4).
//
// One named test per region asserts that flipping bytes inside a
// fully-committed encrypted vault drives `Store::open` into the
// discriminating §5 error kind. Every header byte after the magic is
// AEAD AAD, so a tamper that survives the parse-time gates still has
// to fail decryption rather than silently returning a vault.
//
// Cheap Argon2 params (`m_kib=8192 / t=1 / p=1`) keep the suite quick.
// The canonical encrypted vault is built once via `OnceLock`, then
// each test clones the bytes, mutates one region, and writes a fresh
// tempdir copy to drive `Store::open`.

mod common;

use common::test_tempdir;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_auth_core::{
    parse_otpauth, Account, Argon2Params, EncryptionOptions, ErrorKind, PaladinAuthError, Store,
    VaultInit, VaultLock, VaultMode,
};
use secrecy::SecretString;
use tempfile::TempDir;

const PASSPHRASE: &str = "hunter2";
const ENCRYPTED_HEADER_LEN: usize = 64;
const AEAD_TAG_LEN: usize = 16;

// Header region offsets (docs/DESIGN.md §4.3).
const MAGIC_RANGE: std::ops::Range<usize> = 0..8;
const FORMAT_VER_OFFSET: usize = 8;
const MODE_OFFSET: usize = 9;
const KDF_ID_OFFSET: usize = 10;
const M_KIB_RANGE: std::ops::Range<usize> = 11..15;
const T_RANGE: std::ops::Range<usize> = 15..19;
const P_RANGE: std::ops::Range<usize> = 19..23;
const SALT_RANGE: std::ops::Range<usize> = 23..39;
const AEAD_ID_OFFSET: usize = 39;
const NONCE_RANGE: std::ops::Range<usize> = 40..64;

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn vault_test_dir() -> TempDir {
    let dir = test_tempdir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod tempdir 0700");
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
    EncryptionOptions::with_params(pp(passphrase), cheap_params())
        .expect("cheap_params are in §4.4 bounds and the passphrase is non-empty")
}

/// Canonical encrypted-vault bytes, built once and reused across
/// tamper rows. The file holds one account so the ciphertext region
/// has substance distinct from the 16-byte AEAD tag.
fn canonical_encrypted_bytes() -> &'static Vec<u8> {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (mut vault, store) =
            Store::create(&path, VaultInit::Encrypted(cheap_options(PASSPHRASE)))
                .expect("create encrypted vault");
        vault.add(make_account("alice", Some("Acme")));
        vault.save(&store).expect("encrypted save");
        drop(vault);
        drop(store);
        let bytes = fs::read(&path).expect("read encrypted vault");
        // Sanity: header + at least one ciphertext byte + tag.
        assert!(
            bytes.len() > ENCRYPTED_HEADER_LEN + AEAD_TAG_LEN,
            "canonical encrypted vault must have ciphertext bytes (got {} bytes)",
            bytes.len()
        );
        bytes
    })
}

/// Build a writable on-disk copy of the canonical bytes (cloned,
/// pre-tamper) so a test can mutate the buffer and then commit it.
fn canonical_clone() -> Vec<u8> {
    canonical_encrypted_bytes().clone()
}

/// Write `bytes` to a fresh `vault.bin` under a fresh §4.3-mode 0700
/// tempdir, applying 0600 so the perms gate does not pre-empt the
/// tamper assertion. Returns the owning `TempDir` and the path.
fn commit(bytes: &[u8]) -> (TempDir, PathBuf) {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    fs::write(&path, bytes).expect("write tampered vault");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("0600 mode for tampered vault");
    (dir, path)
}

/// Drive `Store::open` against the tampered file at `path` and return
/// the unwrapped error.
fn open_after_tamper(path: &Path) -> PaladinAuthError {
    Store::open(path, VaultLock::Encrypted(pp(PASSPHRASE)))
        .expect_err("tampered vault must not open")
}

/// Convenience: assert a tampered byte slice yields the given error
/// kind on `Store::open`.
fn assert_kind(bytes: &[u8], expected: ErrorKind) {
    let (_dir, path) = commit(bytes);
    let err = open_after_tamper(&path);
    assert_eq!(
        err.kind(),
        expected,
        "expected {expected:?}, got {err:?} (kind {:?})",
        err.kind()
    );
}

// ---------- magic (bytes 0..8) → invalid_header ----------

#[test]
fn tamper_magic_first_byte_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[MAGIC_RANGE.start] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

#[test]
fn tamper_magic_middle_byte_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[4] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

#[test]
fn tamper_magic_last_byte_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[MAGIC_RANGE.end - 1] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

// ---------- format_ver (byte 8) → unsupported_format_version ----------

/// Drive `Store::open` against a tampered file and assert that the
/// returned error is `UnsupportedFormatVersion` carrying the offending
/// `format_ver` value as a §5 extra field.
fn assert_unsupported_format_ver(bytes: &[u8], expected_ver: u8) {
    let (_dir, path) = commit(bytes);
    let err = open_after_tamper(&path);
    match err {
        PaladinAuthError::UnsupportedFormatVersion { format_ver } => {
            assert_eq!(
                format_ver, expected_ver,
                "format_ver field must carry the offending value"
            );
        }
        other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
    }
}

#[test]
fn tamper_format_ver_to_zero_returns_unsupported_format_version() {
    let mut bytes = canonical_clone();
    bytes[FORMAT_VER_OFFSET] = 0;
    assert_unsupported_format_ver(&bytes, 0);
}

#[test]
fn tamper_format_ver_to_two_returns_unsupported_format_version() {
    let mut bytes = canonical_clone();
    bytes[FORMAT_VER_OFFSET] = 2;
    assert_unsupported_format_ver(&bytes, 2);
}

#[test]
fn tamper_format_ver_to_max_returns_unsupported_format_version() {
    let mut bytes = canonical_clone();
    bytes[FORMAT_VER_OFFSET] = 0xFF;
    assert_unsupported_format_ver(&bytes, 0xFF);
}

// ---------- mode (byte 9) ----------

#[test]
fn tamper_mode_to_two_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[MODE_OFFSET] = 2;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

#[test]
fn tamper_mode_to_max_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[MODE_OFFSET] = 0xFF;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

#[test]
fn tamper_mode_encrypted_flipped_to_plaintext_returns_wrong_vault_lock() {
    // Encrypted file with `mode` flipped to `0` (plaintext) opened
    // against `VaultLock::Encrypted` must surface `wrong_vault_lock`,
    // not `decrypt_failed`. parse_header is the gate that reports the
    // mode mismatch before any AEAD work.
    let mut bytes = canonical_clone();
    bytes[MODE_OFFSET] = 0;
    let (_dir, path) = commit(&bytes);
    let err = open_after_tamper(&path);
    match err {
        PaladinAuthError::WrongVaultLock { expected, actual } => {
            assert_eq!(expected, VaultMode::Encrypted);
            assert_eq!(actual, VaultMode::Plaintext);
        }
        other => panic!("expected WrongVaultLock, got {other:?}"),
    }
}

// ---------- kdf_id (byte 10) ----------

#[test]
fn tamper_kdf_id_to_unknown_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[KDF_ID_OFFSET] = 2;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

#[test]
fn tamper_kdf_id_to_zero_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[KDF_ID_OFFSET] = 0;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

// ---------- m_kib (bytes 11..15) ----------

#[test]
fn tamper_m_kib_below_floor_returns_kdf_params_out_of_bounds() {
    // Floor is 8192. Anything strictly below trips the bounds check
    // before any KDF work.
    let mut bytes = canonical_clone();
    bytes[M_KIB_RANGE.clone()].copy_from_slice(&7_000u32.to_le_bytes());
    let (_dir, path) = commit(&bytes);
    let err = open_after_tamper(&path);
    match err {
        PaladinAuthError::KdfParamsOutOfBounds { m_kib, t, p } => {
            assert_eq!(m_kib, 7_000);
            assert_eq!(t, 1);
            assert_eq!(p, 1);
        }
        other => panic!("expected KdfParamsOutOfBounds, got {other:?}"),
    }
}

#[test]
fn tamper_m_kib_above_ceiling_returns_kdf_params_out_of_bounds() {
    let mut bytes = canonical_clone();
    bytes[M_KIB_RANGE.clone()].copy_from_slice(&1_048_577u32.to_le_bytes());
    assert_kind(&bytes, ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn tamper_m_kib_in_bounds_change_returns_decrypt_failed() {
    // Original is 8192; 65536 is also in §4.4 bounds. The KDF runs
    // with the new m_kib (different key) and AAD now diverges from
    // what was sealed, so AEAD authentication fails.
    let mut bytes = canonical_clone();
    bytes[M_KIB_RANGE.clone()].copy_from_slice(&65_536u32.to_le_bytes());
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

// ---------- t (bytes 15..19) ----------

#[test]
fn tamper_t_to_zero_returns_kdf_params_out_of_bounds() {
    let mut bytes = canonical_clone();
    bytes[T_RANGE.clone()].copy_from_slice(&0u32.to_le_bytes());
    assert_kind(&bytes, ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn tamper_t_above_ceiling_returns_kdf_params_out_of_bounds() {
    let mut bytes = canonical_clone();
    bytes[T_RANGE.clone()].copy_from_slice(&11u32.to_le_bytes());
    assert_kind(&bytes, ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn tamper_t_in_bounds_change_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[T_RANGE.clone()].copy_from_slice(&2u32.to_le_bytes());
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

// ---------- p (bytes 19..23) ----------

#[test]
fn tamper_p_to_zero_returns_kdf_params_out_of_bounds() {
    let mut bytes = canonical_clone();
    bytes[P_RANGE.clone()].copy_from_slice(&0u32.to_le_bytes());
    assert_kind(&bytes, ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn tamper_p_above_ceiling_returns_kdf_params_out_of_bounds() {
    let mut bytes = canonical_clone();
    bytes[P_RANGE.clone()].copy_from_slice(&5u32.to_le_bytes());
    assert_kind(&bytes, ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn tamper_p_in_bounds_change_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[P_RANGE.clone()].copy_from_slice(&2u32.to_le_bytes());
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

// ---------- salt (bytes 23..39, 16 bytes) → decrypt_failed ----------

#[test]
fn tamper_salt_first_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[SALT_RANGE.start] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

#[test]
fn tamper_salt_middle_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[SALT_RANGE.start + 7] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

#[test]
fn tamper_salt_last_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[SALT_RANGE.end - 1] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

// ---------- aead_id (byte 39) → invalid_header ----------

#[test]
fn tamper_aead_id_to_unknown_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[AEAD_ID_OFFSET] = 2;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

#[test]
fn tamper_aead_id_to_zero_returns_invalid_header() {
    let mut bytes = canonical_clone();
    bytes[AEAD_ID_OFFSET] = 0;
    assert_kind(&bytes, ErrorKind::InvalidHeader);
}

// ---------- nonce (bytes 40..64, 24 bytes) → decrypt_failed ----------

#[test]
fn tamper_nonce_first_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[NONCE_RANGE.start] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

#[test]
fn tamper_nonce_middle_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[NONCE_RANGE.start + 11] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

#[test]
fn tamper_nonce_last_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[NONCE_RANGE.end - 1] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

// ---------- ciphertext (bytes 64..len-16) → decrypt_failed ----------

#[test]
fn tamper_ciphertext_first_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    bytes[ENCRYPTED_HEADER_LEN] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

#[test]
fn tamper_ciphertext_middle_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    let mid = (ENCRYPTED_HEADER_LEN + bytes.len() - AEAD_TAG_LEN) / 2;
    assert!(
        mid > ENCRYPTED_HEADER_LEN && mid < bytes.len() - AEAD_TAG_LEN,
        "middle index must land inside the ciphertext region",
    );
    bytes[mid] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

#[test]
fn tamper_ciphertext_last_byte_before_tag_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    let idx = bytes.len() - AEAD_TAG_LEN - 1;
    assert!(
        idx >= ENCRYPTED_HEADER_LEN,
        "ciphertext must have at least one byte for the last-before-tag flip",
    );
    bytes[idx] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

// ---------- aead_tag (last 16 bytes) → decrypt_failed ----------

#[test]
fn tamper_aead_tag_first_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    let len = bytes.len();
    bytes[len - AEAD_TAG_LEN] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

#[test]
fn tamper_aead_tag_last_byte_returns_decrypt_failed() {
    let mut bytes = canonical_clone();
    let len = bytes.len();
    bytes[len - 1] ^= 0xFF;
    assert_kind(&bytes, ErrorKind::DecryptFailed);
}

// ---------- truncated body (< AEAD_TAG_LEN bytes after header) ----------
//
// A file with an intact 64-byte encrypted header but a body shorter
// than the 16-byte AEAD tag cannot form a valid `ciphertext + tag`.
// `Store::open` must surface `invalid_payload` /
// `ciphertext_too_short` from the AEAD-decrypt entry point rather
// than panic on a slice underflow inside the AEAD library.

fn assert_ciphertext_too_short(bytes: &[u8]) {
    let (_dir, path) = commit(bytes);
    let err = open_after_tamper(&path);
    match err {
        PaladinAuthError::InvalidPayload { reason } => assert_eq!(
            reason, "ciphertext_too_short",
            "expected reason `ciphertext_too_short`, got `{reason}`"
        ),
        other => panic!("expected InvalidPayload, got {other:?}"),
    }
}

#[test]
fn truncated_body_zero_bytes_returns_ciphertext_too_short() {
    // Header only, body length 0 — fewer than 16 tag bytes.
    let bytes = canonical_clone()[..ENCRYPTED_HEADER_LEN].to_vec();
    assert_eq!(bytes.len(), ENCRYPTED_HEADER_LEN);
    assert_ciphertext_too_short(&bytes);
}

#[test]
fn truncated_body_one_byte_returns_ciphertext_too_short() {
    let bytes = canonical_clone()[..=ENCRYPTED_HEADER_LEN].to_vec();
    assert_eq!(bytes.len(), ENCRYPTED_HEADER_LEN + 1);
    assert_ciphertext_too_short(&bytes);
}

#[test]
fn truncated_body_fifteen_bytes_returns_ciphertext_too_short() {
    // Body is one byte short of a complete AEAD tag.
    let bytes = canonical_clone()[..ENCRYPTED_HEADER_LEN + AEAD_TAG_LEN - 1].to_vec();
    assert_eq!(bytes.len(), ENCRYPTED_HEADER_LEN + AEAD_TAG_LEN - 1);
    assert_ciphertext_too_short(&bytes);
}
