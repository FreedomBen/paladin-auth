// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Vault file header (DESIGN.md §4.3).
//
// The plaintext header is **10 bytes**:
//
// | Bytes  | Field        | Notes                              |
// |--------|--------------|------------------------------------|
// | 0..8   | `magic`      | `"PALADIN\0"`                      |
// | 8      | `format_ver` | `1` for v0.1                       |
// | 9      | `mode`       | `0` plaintext, `1` encrypted       |
//
// In encrypted mode the header is **64 bytes** total — the plaintext
// header followed by:
//
// | Bytes   | Field    | Notes                                   |
// |---------|----------|-----------------------------------------|
// | 10      | `kdf_id` | `1` = Argon2id; other ids reserved      |
// | 11..15  | `m_kib`  | u32 little-endian Argon2 memory (KiB)   |
// | 15..19  | `t`      | u32 little-endian Argon2 time cost      |
// | 19..23  | `p`      | u32 little-endian Argon2 parallelism    |
// | 23..39  | `salt`   | 16-byte Argon2 salt                     |
// | 39      | `aead_id`| `1` = XChaCha20-Poly1305; others reserved |
// | 40..64  | `nonce`  | 24-byte XChaCha20-Poly1305 nonce        |
//
// Every byte after the magic — `format_ver`, `mode`, `kdf_id`, the
// Argon2 params, `salt`, `aead_id`, `nonce` — is bound as AEAD AAD
// (§4.4) so any tamper invalidates decryption.
//
// This module owns the byte layout and three error gates:
//   * unrecognized magic → `invalid_header`
//   * unsupported `format_ver` → `unsupported_format_version`
//   * unknown `mode` / `kdf_id` / `aead_id` → `invalid_header`
//
// Argon2 parameter bounds (`kdf_params_out_of_bounds`) are deferred to
// the encrypted-mode `open` site (Phase F); this module only confirms
// the IDs themselves.

use crate::error::{PaladinError, Result};

/// Magic bytes at the start of every Paladin vault file.
pub(crate) const MAGIC: [u8; 8] = *b"PALADIN\0";

/// Current on-disk format version. Bumped on any breaking change to the
/// header layout or `VaultPayload` schema.
pub(crate) const FORMAT_VER: u8 = 1;

/// Mode discriminant for plaintext vaults.
pub(crate) const MODE_PLAINTEXT: u8 = 0;

/// Mode discriminant for encrypted vaults.
pub(crate) const MODE_ENCRYPTED: u8 = 1;

/// KDF identifier for Argon2id (§4.4). Other identifiers are reserved
/// for future format versions.
pub(crate) const KDF_ID_ARGON2ID: u8 = 1;

/// AEAD identifier for XChaCha20-Poly1305 (§4.4). Other identifiers
/// are reserved.
pub(crate) const AEAD_ID_XCHACHA20_POLY1305: u8 = 1;

/// Plaintext-mode header length in bytes.
pub(crate) const PLAINTEXT_HEADER_LEN: usize = 10;

/// Encrypted-mode header length in bytes (plaintext header + KDF/AEAD
/// trailer).
pub(crate) const ENCRYPTED_HEADER_LEN: usize = 64;

/// Encrypted-header trailer (everything after the 10-byte plaintext
/// header). Crate-private: presentation crates inspect mode through
/// `VaultStatus`, not the raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Wired up by Phase F (`Store::open` for encrypted vaults).
pub(crate) struct EncryptedHeaderTrailer {
    pub(crate) kdf_id: u8,
    pub(crate) m_kib: u32,
    pub(crate) t: u32,
    pub(crate) p: u32,
    pub(crate) salt: [u8; 16],
    pub(crate) aead_id: u8,
    pub(crate) nonce: [u8; 24],
}

/// Parsed header. The encrypted variant carries the full trailer so
/// callers can validate Argon2 bounds and feed AAD to AEAD without
/// re-reading the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // `Encrypted` consumed by Phase F.
pub(crate) enum ParsedHeader {
    Plaintext,
    Encrypted(EncryptedHeaderTrailer),
}

impl ParsedHeader {
    /// On-disk length of this header (10 plaintext, 64 encrypted).
    #[must_use]
    #[allow(dead_code)] // Used once payload reading lands in Phase E continuation.
    pub(crate) fn on_disk_len(&self) -> usize {
        match self {
            Self::Plaintext => PLAINTEXT_HEADER_LEN,
            Self::Encrypted(_) => ENCRYPTED_HEADER_LEN,
        }
    }
}

/// Parse the header off the front of `bytes`. The slice must start at
/// the magic. Trailing bytes (the payload / ciphertext + tag) are not
/// touched.
///
/// Validation order matches §4.3 / §4.4:
/// 1. Length large enough for the plaintext header → otherwise
///    `invalid_header`.
/// 2. Magic equals `PALADIN\0` → otherwise `invalid_header`.
/// 3. `format_ver` equals the current `FORMAT_VER` → otherwise
///    `unsupported_format_version`.
/// 4. `mode` is `0` or `1` → otherwise `invalid_header`.
/// 5. For encrypted mode: trailer length, `kdf_id`, `aead_id`
///    validated; Argon2 bounds and AEAD verification happen later in
///    Phase F.
#[allow(dead_code)] // Public in-crate via storage::inspect (Phase E continuation).
pub(crate) fn parse_header(bytes: &[u8]) -> Result<ParsedHeader> {
    if bytes.len() < PLAINTEXT_HEADER_LEN {
        return Err(PaladinError::InvalidHeader);
    }
    if bytes[0..8] != MAGIC {
        return Err(PaladinError::InvalidHeader);
    }
    let format_ver = bytes[8];
    if format_ver != FORMAT_VER {
        return Err(PaladinError::UnsupportedFormatVersion);
    }
    match bytes[9] {
        MODE_PLAINTEXT => Ok(ParsedHeader::Plaintext),
        MODE_ENCRYPTED => parse_encrypted_trailer(bytes).map(ParsedHeader::Encrypted),
        _ => Err(PaladinError::InvalidHeader),
    }
}

fn parse_encrypted_trailer(bytes: &[u8]) -> Result<EncryptedHeaderTrailer> {
    if bytes.len() < ENCRYPTED_HEADER_LEN {
        return Err(PaladinError::InvalidHeader);
    }
    let kdf_id = bytes[10];
    if kdf_id != KDF_ID_ARGON2ID {
        return Err(PaladinError::InvalidHeader);
    }
    let m_kib = u32::from_le_bytes(bytes[11..15].try_into().expect("4 bytes"));
    let t = u32::from_le_bytes(bytes[15..19].try_into().expect("4 bytes"));
    let p = u32::from_le_bytes(bytes[19..23].try_into().expect("4 bytes"));
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes[23..39]);
    let aead_id = bytes[39];
    if aead_id != AEAD_ID_XCHACHA20_POLY1305 {
        return Err(PaladinError::InvalidHeader);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&bytes[40..64]);
    Ok(EncryptedHeaderTrailer {
        kdf_id,
        m_kib,
        t,
        p,
        salt,
        aead_id,
        nonce,
    })
}

/// Append the 10-byte plaintext header to `out`.
#[allow(dead_code)] // Used by Phase E continuation.
pub(crate) fn write_plaintext_header(out: &mut Vec<u8>) {
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VER);
    out.push(MODE_PLAINTEXT);
}

/// Append the 64-byte encrypted header (plaintext header + trailer) to
/// `out`. Phase F uses this when wrapping ciphertext.
#[allow(dead_code)]
pub(crate) fn write_encrypted_header(out: &mut Vec<u8>, trailer: &EncryptedHeaderTrailer) {
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VER);
    out.push(MODE_ENCRYPTED);
    out.push(trailer.kdf_id);
    out.extend_from_slice(&trailer.m_kib.to_le_bytes());
    out.extend_from_slice(&trailer.t.to_le_bytes());
    out.extend_from_slice(&trailer.p.to_le_bytes());
    out.extend_from_slice(&trailer.salt);
    out.push(trailer.aead_id);
    out.extend_from_slice(&trailer.nonce);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    fn plaintext_header_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        write_plaintext_header(&mut buf);
        buf
    }

    fn sample_trailer() -> EncryptedHeaderTrailer {
        EncryptedHeaderTrailer {
            kdf_id: KDF_ID_ARGON2ID,
            m_kib: 65_536,
            t: 3,
            p: 1,
            salt: [0xAB; 16],
            aead_id: AEAD_ID_XCHACHA20_POLY1305,
            nonce: [0xCD; 24],
        }
    }

    fn encrypted_header_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        write_encrypted_header(&mut buf, &sample_trailer());
        buf
    }

    #[test]
    fn magic_constant_locks_section_4_3() {
        assert_eq!(MAGIC, *b"PALADIN\0");
        assert_eq!(MAGIC.len(), 8);
    }

    #[test]
    fn format_version_constant_locks_v0_1_at_one() {
        assert_eq!(FORMAT_VER, 1);
    }

    #[test]
    fn mode_constants_lock_assignments() {
        assert_eq!(MODE_PLAINTEXT, 0);
        assert_eq!(MODE_ENCRYPTED, 1);
    }

    #[test]
    fn id_constants_lock_assignments() {
        assert_eq!(KDF_ID_ARGON2ID, 1);
        assert_eq!(AEAD_ID_XCHACHA20_POLY1305, 1);
    }

    #[test]
    fn header_lengths_lock_section_4_3() {
        assert_eq!(PLAINTEXT_HEADER_LEN, 10);
        assert_eq!(ENCRYPTED_HEADER_LEN, 64);
    }

    #[test]
    fn write_plaintext_header_emits_ten_bytes_with_correct_layout() {
        let bytes = plaintext_header_bytes();
        assert_eq!(bytes.len(), PLAINTEXT_HEADER_LEN);
        assert_eq!(&bytes[0..8], b"PALADIN\0");
        assert_eq!(bytes[8], FORMAT_VER);
        assert_eq!(bytes[9], MODE_PLAINTEXT);
    }

    #[test]
    fn write_encrypted_header_emits_64_bytes_with_correct_layout() {
        let bytes = encrypted_header_bytes();
        assert_eq!(bytes.len(), ENCRYPTED_HEADER_LEN);
        assert_eq!(&bytes[0..8], b"PALADIN\0");
        assert_eq!(bytes[8], FORMAT_VER);
        assert_eq!(bytes[9], MODE_ENCRYPTED);
        assert_eq!(bytes[10], KDF_ID_ARGON2ID);
        // Argon2 defaults little-endian: m_kib=65536 → 00 00 01 00,
        // t=3 → 03 00 00 00, p=1 → 01 00 00 00.
        assert_eq!(&bytes[11..15], &[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(&bytes[15..19], &[0x03, 0x00, 0x00, 0x00]);
        assert_eq!(&bytes[19..23], &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(&bytes[23..39], &[0xAB; 16]);
        assert_eq!(bytes[39], AEAD_ID_XCHACHA20_POLY1305);
        assert_eq!(&bytes[40..64], &[0xCD; 24]);
    }

    #[test]
    fn parse_plaintext_header_round_trips() {
        let bytes = plaintext_header_bytes();
        assert_eq!(parse_header(&bytes).unwrap(), ParsedHeader::Plaintext);
    }

    #[test]
    fn parse_encrypted_header_round_trips() {
        let bytes = encrypted_header_bytes();
        match parse_header(&bytes).unwrap() {
            ParsedHeader::Encrypted(trailer) => assert_eq!(trailer, sample_trailer()),
            other @ ParsedHeader::Plaintext => panic!("expected Encrypted, got {other:?}"),
        }
    }

    #[test]
    fn parse_header_tolerates_trailing_bytes() {
        // Real files have a payload after the header; parse_header
        // must not require an exact-length slice.
        let mut bytes = plaintext_header_bytes();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22]);
        assert_eq!(parse_header(&bytes).unwrap(), ParsedHeader::Plaintext);

        let mut bytes = encrypted_header_bytes();
        bytes.extend_from_slice(&[0x99; 32]);
        assert!(matches!(
            parse_header(&bytes).unwrap(),
            ParsedHeader::Encrypted(_)
        ));
    }

    #[test]
    fn parse_header_rejects_short_slice() {
        for len in 0..PLAINTEXT_HEADER_LEN {
            let bytes = vec![0u8; len];
            assert_eq!(
                parse_header(&bytes).unwrap_err().kind(),
                ErrorKind::InvalidHeader,
                "slice of len {len} should be invalid_header"
            );
        }
    }

    #[test]
    fn parse_header_rejects_unknown_magic() {
        let mut bytes = plaintext_header_bytes();
        bytes[0] = b'X';
        assert_eq!(
            parse_header(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidHeader,
        );

        // Lowercase variant is also wrong.
        let mut bytes = plaintext_header_bytes();
        bytes[..8].copy_from_slice(b"paladin\0");
        assert_eq!(
            parse_header(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidHeader,
        );
    }

    #[test]
    fn parse_header_rejects_unsupported_format_version() {
        // version 0 (pre-v0.1) and version 2 (future-incompatible)
        for ver in [0u8, 2, 3, 99, 255] {
            let mut bytes = plaintext_header_bytes();
            bytes[8] = ver;
            assert_eq!(
                parse_header(&bytes).unwrap_err().kind(),
                ErrorKind::UnsupportedFormatVersion,
                "format_ver {ver} should be unsupported_format_version"
            );
        }
    }

    #[test]
    fn parse_header_rejects_unknown_mode() {
        for mode in [2u8, 3, 0xFF] {
            let mut bytes = plaintext_header_bytes();
            bytes[9] = mode;
            assert_eq!(
                parse_header(&bytes).unwrap_err().kind(),
                ErrorKind::InvalidHeader,
                "mode {mode} should be invalid_header"
            );
        }
    }

    #[test]
    fn parse_header_rejects_unknown_kdf_id() {
        let mut bytes = encrypted_header_bytes();
        bytes[10] = 2; // unknown
        assert_eq!(
            parse_header(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidHeader,
        );
    }

    #[test]
    fn parse_header_rejects_unknown_aead_id() {
        let mut bytes = encrypted_header_bytes();
        bytes[39] = 2; // unknown
        assert_eq!(
            parse_header(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidHeader,
        );
    }

    #[test]
    fn parse_header_rejects_truncated_encrypted_trailer() {
        // 10-byte plaintext header + a `mode = 1` byte but no trailer.
        // Slice is exactly 10 bytes long; mode says encrypted but
        // trailer is missing.
        let mut bytes = vec![0u8; PLAINTEXT_HEADER_LEN];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8] = FORMAT_VER;
        bytes[9] = MODE_ENCRYPTED;
        assert_eq!(
            parse_header(&bytes).unwrap_err().kind(),
            ErrorKind::InvalidHeader,
        );

        // Cover every shorter-than-64 length too.
        for len in PLAINTEXT_HEADER_LEN..ENCRYPTED_HEADER_LEN {
            let mut bytes = encrypted_header_bytes();
            bytes.truncate(len);
            assert_eq!(
                parse_header(&bytes).unwrap_err().kind(),
                ErrorKind::InvalidHeader,
                "truncated encrypted header of len {len} should reject"
            );
        }
    }

    #[test]
    fn parse_header_preserves_argon_params_round_trip() {
        // Custom in-range params (we don't enforce bounds here — that's
        // Phase F — but we do need them to round-trip bit-identically).
        let mut buf = Vec::new();
        let trailer = EncryptedHeaderTrailer {
            kdf_id: KDF_ID_ARGON2ID,
            m_kib: 8_192,
            t: 1,
            p: 1,
            salt: [0x01; 16],
            aead_id: AEAD_ID_XCHACHA20_POLY1305,
            nonce: [0x02; 24],
        };
        write_encrypted_header(&mut buf, &trailer);
        match parse_header(&buf).unwrap() {
            ParsedHeader::Encrypted(parsed) => assert_eq!(parsed, trailer),
            other @ ParsedHeader::Plaintext => panic!("expected Encrypted, got {other:?}"),
        }

        // Pin the bytes for `m_kib = 8192` little-endian.
        assert_eq!(&buf[11..15], &[0x00, 0x20, 0x00, 0x00]);
    }

    #[test]
    fn on_disk_len_returns_section_4_3_constants() {
        assert_eq!(ParsedHeader::Plaintext.on_disk_len(), PLAINTEXT_HEADER_LEN);
        assert_eq!(
            ParsedHeader::Encrypted(sample_trailer()).on_disk_len(),
            ENCRYPTED_HEADER_LEN
        );
    }
}
