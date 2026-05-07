// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Vault storage (DESIGN.md §4.3).
//
// Phase E lands the in-memory `VaultPayload` and the bincode v2 codec
// pinned by §4.3 (little-endian, fixed-int, 16 MiB cap, full-input
// consumption), the on-disk header parser, the default vault-path
// resolver, the `inspect` header probe, and the `classify_init_precheck`
// truth table that CLI and GUI init flows share. Filesystem I/O
// (atomic writes, permissions, backup rotation, `Store::open` /
// `Store::create`) lands in subsequent commits.
//
// Public surface from this module (re-exported at the crate root via
// `lib.rs`):
//
// * `default_vault_path`
// * `inspect`
// * `VaultStatus`
// * `VaultSettings` (already published from `payload`)
// * `InitPrecheck` + `classify_init_precheck`

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::{PaladinError, Result};

pub(crate) mod header;
pub mod path;
pub mod payload;

pub use path::default_vault_path;
pub use payload::VaultSettings;
// Re-exported for use by upcoming Phase E filesystem code (Store, open,
// create_force, atomic-write pipeline). The codec itself lives in
// `payload`; callers within the crate go through these aliases.
#[allow(unused_imports)]
pub(crate) use payload::{decode_vault_payload, encode_vault_payload, VaultPayload};

use header::{parse_header, ParsedHeader, ENCRYPTED_HEADER_LEN};

/// Result of the `inspect()` header probe (DESIGN.md §4.7).
///
/// `Missing` reflects an absent primary file — distinct from any I/O
/// error (which is propagated as `io_error`) and from an unrecognized
/// header (`invalid_header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStatus {
    /// Plaintext vault file present at the path.
    Plaintext,
    /// Encrypted vault file present at the path.
    Encrypted,
    /// No primary file at the path.
    Missing,
}

/// Read the header of `path` and report the vault mode without
/// decrypting the payload.
///
/// * `Ok(Missing)` iff the primary file does not exist.
/// * `Ok(Plaintext)` / `Ok(Encrypted)` for a valid v0.1 header.
/// * `Err(invalid_header)` for unknown magic / mode / KDF id / AEAD id.
/// * `Err(unsupported_format_version)` for `format_ver != 1`.
/// * `Err(io_error { operation: "read_vault_file" })` for any other
///   filesystem failure (e.g. permission denied).
///
/// `inspect` deliberately does **not** enforce the §4.3 permissions
/// check — only `open`, `create`, and `create_force` do — so callers
/// can probe a vault's mode before fixing perms.
pub fn inspect(path: &Path) -> Result<VaultStatus> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VaultStatus::Missing);
        }
        Err(err) => {
            return Err(PaladinError::IoError {
                operation: "read_vault_file",
                source: err,
            });
        }
    };

    // We only need up to ENCRYPTED_HEADER_LEN bytes to classify the
    // file. Reading more would be wasteful, and reading less would
    // mishandle encrypted vaults whose trailer extends to byte 64.
    let mut buf = [0u8; ENCRYPTED_HEADER_LEN];
    let n = read_up_to(&mut file, &mut buf)?;
    match parse_header(&buf[..n])? {
        ParsedHeader::Plaintext => Ok(VaultStatus::Plaintext),
        ParsedHeader::Encrypted(_) => Ok(VaultStatus::Encrypted),
    }
}

/// Read up to `buf.len()` bytes from `f`, returning the number actually
/// filled. Short files are not an error; a read error becomes an
/// `io_error` with `operation: "read_vault_file"`.
fn read_up_to(f: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => (),
            Err(err) => {
                return Err(PaladinError::IoError {
                    operation: "read_vault_file",
                    source: err,
                });
            }
        }
    }
    Ok(filled)
}

/// Init-flow precheck classification (DESIGN.md §5).
///
/// CLI `init` and GUI `InitDialog` share this truth table so they
/// agree on when an existing vault must be confirmed-clobbered with
/// `--force` and when a non-init error should bubble verbatim.
#[derive(Debug)]
pub enum InitPrecheck {
    /// No conflicting file exists; init can proceed.
    Clear,
    /// A conflicting file (or a header indicating one used to exist)
    /// is present; init must require `--force` to clobber.
    Existing,
    /// A non-init failure occurred (e.g. unsafe perms, transient I/O
    /// error). Front ends propagate it verbatim.
    Propagate(PaladinError),
}

/// Map a `Result<VaultStatus>` from `inspect` (or any equivalent probe)
/// to an init-flow decision.
///
/// `Missing` → `Clear`. `Plaintext`, `Encrypted`, `invalid_header`, and
/// `unsupported_format_version` all signal "something is on disk; user
/// must confirm clobber" → `Existing`. Every other error becomes
/// `Propagate(err)`.
pub fn classify_init_precheck(probe: Result<VaultStatus>) -> InitPrecheck {
    match probe {
        Ok(VaultStatus::Missing) => InitPrecheck::Clear,
        Ok(VaultStatus::Plaintext | VaultStatus::Encrypted) => InitPrecheck::Existing,
        Err(PaladinError::InvalidHeader | PaladinError::UnsupportedFormatVersion) => {
            InitPrecheck::Existing
        }
        Err(other) => InitPrecheck::Propagate(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_bytes(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.path().join(name);
        let mut f = fs::File::create(&p).expect("create test file");
        f.write_all(bytes).expect("write test bytes");
        p
    }

    fn plaintext_header() -> Vec<u8> {
        let mut v = Vec::new();
        header::write_plaintext_header(&mut v);
        v
    }

    fn encrypted_header() -> Vec<u8> {
        let mut v = Vec::new();
        header::write_encrypted_header(
            &mut v,
            &header::EncryptedHeaderTrailer {
                kdf_id: header::KDF_ID_ARGON2ID,
                m_kib: 65_536,
                t: 3,
                p: 1,
                salt: [0; 16],
                aead_id: header::AEAD_ID_XCHACHA20_POLY1305,
                nonce: [0; 24],
            },
        );
        v
    }

    #[test]
    fn inspect_returns_missing_for_absent_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.bin");
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Missing);
    }

    #[test]
    fn inspect_returns_plaintext_for_plaintext_header() {
        let dir = TempDir::new().unwrap();
        let path = write_bytes(&dir, "vault.bin", &plaintext_header());
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
    }

    #[test]
    fn inspect_returns_encrypted_for_encrypted_header() {
        let dir = TempDir::new().unwrap();
        let path = write_bytes(&dir, "vault.bin", &encrypted_header());
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
    }

    #[test]
    fn inspect_ignores_payload_bytes_after_header() {
        let dir = TempDir::new().unwrap();
        let mut bytes = plaintext_header();
        bytes.extend_from_slice(&[0xAA; 1024]);
        let path = write_bytes(&dir, "vault.bin", &bytes);
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
    }

    #[test]
    fn inspect_rejects_unrecognized_magic() {
        let dir = TempDir::new().unwrap();
        let mut bad = plaintext_header();
        bad[0] = b'X';
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_rejects_unsupported_format_version() {
        let dir = TempDir::new().unwrap();
        let mut bad = plaintext_header();
        bad[8] = 99;
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(
            inspect(&path).unwrap_err().kind(),
            ErrorKind::UnsupportedFormatVersion
        );
    }

    #[test]
    fn inspect_rejects_unknown_mode() {
        let dir = TempDir::new().unwrap();
        let mut bad = plaintext_header();
        bad[9] = 0x42;
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_rejects_unknown_kdf_id() {
        let dir = TempDir::new().unwrap();
        let mut bad = encrypted_header();
        bad[10] = 99;
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_rejects_unknown_aead_id() {
        let dir = TempDir::new().unwrap();
        let mut bad = encrypted_header();
        bad[39] = 99;
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_rejects_truncated_file() {
        // Anything shorter than the 10-byte plaintext header is
        // invalid_header (not Missing).
        let dir = TempDir::new().unwrap();
        let path = write_bytes(&dir, "vault.bin", b"PALAD");
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_skips_permissions_check() {
        // §4.7 explicitly says inspect does not enforce permissions.
        // Write the vault file with a wide-open mode and confirm we
        // get a clean classification rather than `unsafe_permissions`.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = write_bytes(&dir, "vault.bin", &plaintext_header());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        // Parent dir mode also wide open (would fail an open() perms
        // check).
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
    }

    #[test]
    fn classify_init_precheck_truth_table() {
        // Missing → Clear
        assert!(matches!(
            classify_init_precheck(Ok(VaultStatus::Missing)),
            InitPrecheck::Clear
        ));

        // Plaintext / Encrypted → Existing
        assert!(matches!(
            classify_init_precheck(Ok(VaultStatus::Plaintext)),
            InitPrecheck::Existing
        ));
        assert!(matches!(
            classify_init_precheck(Ok(VaultStatus::Encrypted)),
            InitPrecheck::Existing
        ));

        // InvalidHeader / UnsupportedFormatVersion → Existing
        assert!(matches!(
            classify_init_precheck(Err(PaladinError::InvalidHeader)),
            InitPrecheck::Existing
        ));
        assert!(matches!(
            classify_init_precheck(Err(PaladinError::UnsupportedFormatVersion)),
            InitPrecheck::Existing
        ));

        // Other errors → Propagate
        match classify_init_precheck(Err(PaladinError::VaultMissing)) {
            InitPrecheck::Propagate(PaladinError::VaultMissing) => {}
            other => panic!("expected Propagate(VaultMissing), got {other:?}"),
        }
        match classify_init_precheck(Err(PaladinError::IoError {
            operation: "read_vault_file",
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        })) {
            InitPrecheck::Propagate(PaladinError::IoError { operation, .. }) => {
                assert_eq!(operation, "read_vault_file");
            }
            other => panic!("expected Propagate(IoError), got {other:?}"),
        }
        match classify_init_precheck(Err(PaladinError::DecryptFailed)) {
            InitPrecheck::Propagate(PaladinError::DecryptFailed) => {}
            other => panic!("expected Propagate(DecryptFailed), got {other:?}"),
        }
    }
}
