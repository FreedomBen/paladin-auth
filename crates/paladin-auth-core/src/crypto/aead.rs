// SPDX-License-Identifier: AGPL-3.0-or-later
//
// XChaCha20-Poly1305 AEAD wrapper (docs/DESIGN.md §4.4).
//
// 32-byte key, 24-byte nonce, 16-byte Poly1305 tag. The encrypted
// save/open paths bind every header byte after the magic
// (`format_ver`, `mode`, `kdf_id`, Argon2 params, `salt`, `aead_id`,
// `nonce`) as AEAD associated data so any tamper invalidates
// decryption.
//
// Phase F.2 lands the pure encrypt/decrypt primitives. Phase F.3+
// wires them into `Store::open` / `Store::save`.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};

use crate::crypto::kdf::AEAD_KEY_LEN;
use crate::error::{PaladinAuthError, Result};

/// XChaCha20-Poly1305 nonce length in bytes.
pub(crate) const AEAD_NONCE_LEN: usize = 24;
/// Poly1305 authentication-tag length in bytes.
pub(crate) const AEAD_TAG_LEN: usize = 16;

/// Encrypt `plaintext` under `key` / `nonce` with `aad` as AEAD
/// associated data. Returns `ciphertext || tag` (ciphertext then the
/// 16-byte Poly1305 tag, concatenated).
///
/// Panics in the unreachable case where the AEAD library reports an
/// encryption failure: encryption is infallible for plaintexts well
/// below the practical AEAD limit, and the storage layer enforces a
/// 16 MiB payload cap upstream.
#[allow(dead_code)] // Wired into encrypted save in later F-series commits.
pub(crate) fn aead_encrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect(
            "XChaCha20-Poly1305 encryption is infallible for plaintexts under \
             the practical AEAD limit; vault payloads are capped at 16 MiB upstream",
        )
}

/// Decrypt `ciphertext_and_tag` under `key` / `nonce` with `aad`.
///
/// Returns `decrypt_failed` on tag mismatch (wrong key, wrong nonce,
/// tampered ciphertext, tampered tag, AAD mismatch). Returns
/// `invalid_payload` with reason `ciphertext_too_short` if the input
/// cannot fit a 16-byte tag.
#[allow(dead_code)] // Wired into encrypted open in later F-series commits.
pub(crate) fn aead_decrypt(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext_and_tag.len() < AEAD_TAG_LEN {
        return Err(PaladinAuthError::InvalidPayload {
            reason: "ciphertext_too_short",
        });
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| PaladinAuthError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    struct KatVector {
        key: [u8; AEAD_KEY_LEN],
        nonce: [u8; AEAD_NONCE_LEN],
        aad: Vec<u8>,
        plaintext: Vec<u8>,
        ciphertext_and_tag: Vec<u8>,
    }

    /// IETF XChaCha20-Poly1305 test vector
    /// (draft-irtf-cfrg-xchacha-03 §A.3.1).
    fn rfc_xchacha20_poly1305_vector() -> KatVector {
        let mut key = [0u8; AEAD_KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = 0x80u8.wrapping_add(u8::try_from(i).expect("0..32 fits u8"));
        }
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = 0x40u8.wrapping_add(u8::try_from(i).expect("0..24 fits u8"));
        }
        let aad: Vec<u8> = vec![
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: Vec<u8> = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let expected_ct_tag: Vec<u8> = vec![
            // Ciphertext (114 bytes)
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0,
            0xe9, 0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c,
            0x21, 0x39, 0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3,
            0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
            0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5,
            0xd9, 0x45, 0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b,
            0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9,
            0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
            0xb5, 0x2e, // Tag (16 bytes)
            0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a,
            0xcf, 0x49,
        ];
        assert_eq!(plaintext.len(), 114);
        assert_eq!(expected_ct_tag.len(), 130);
        KatVector {
            key,
            nonce,
            aad,
            plaintext,
            ciphertext_and_tag: expected_ct_tag,
        }
    }

    #[test]
    fn aead_encrypt_matches_rfc_kat() {
        let v = rfc_xchacha20_poly1305_vector();
        let actual = aead_encrypt(&v.key, &v.nonce, &v.aad, &v.plaintext);
        assert_eq!(
            actual, v.ciphertext_and_tag,
            "RFC XChaCha20-Poly1305 KAT mismatch"
        );
    }

    #[test]
    fn aead_decrypt_matches_rfc_kat() {
        let v = rfc_xchacha20_poly1305_vector();
        let actual =
            aead_decrypt(&v.key, &v.nonce, &v.aad, &v.ciphertext_and_tag).expect("decrypt KAT");
        assert_eq!(actual, v.plaintext);
    }

    #[test]
    fn aead_round_trip_recovers_plaintext() {
        let key = [0xCC; AEAD_KEY_LEN];
        let nonce = [0xDD; AEAD_NONCE_LEN];
        let aad = b"vault-header-aad";
        let plaintext = b"some secret stuff";
        let ct = aead_encrypt(&key, &nonce, aad, plaintext);
        // Output must include the 16-byte tag.
        assert_eq!(ct.len(), plaintext.len() + AEAD_TAG_LEN);
        let pt = aead_decrypt(&key, &nonce, aad, &ct).expect("round-trip decrypts");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn aead_decrypt_rejects_short_ciphertext_with_invalid_payload() {
        let key = [0u8; AEAD_KEY_LEN];
        let nonce = [0u8; AEAD_NONCE_LEN];
        let too_short = vec![0u8; AEAD_TAG_LEN - 1];
        let err = aead_decrypt(&key, &nonce, b"", &too_short).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPayload);
        match err {
            PaladinAuthError::InvalidPayload { reason } => {
                assert_eq!(reason, "ciphertext_too_short");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn aead_decrypt_rejects_aad_mismatch() {
        let key = [0xCC; AEAD_KEY_LEN];
        let nonce = [0xDD; AEAD_NONCE_LEN];
        let ct = aead_encrypt(&key, &nonce, b"original-aad", b"payload");
        let err = aead_decrypt(&key, &nonce, b"tampered-aad", &ct).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DecryptFailed);
    }

    #[test]
    fn aead_decrypt_rejects_wrong_key() {
        let nonce = [0xDD; AEAD_NONCE_LEN];
        let ct = aead_encrypt(&[0xCC; AEAD_KEY_LEN], &nonce, b"aad", b"payload");
        let mut wrong_key = [0xCC; AEAD_KEY_LEN];
        wrong_key[0] ^= 0x01;
        let err = aead_decrypt(&wrong_key, &nonce, b"aad", &ct).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DecryptFailed);
    }

    #[test]
    fn aead_decrypt_rejects_wrong_nonce() {
        let key = [0xCC; AEAD_KEY_LEN];
        let nonce = [0xDD; AEAD_NONCE_LEN];
        let ct = aead_encrypt(&key, &nonce, b"aad", b"payload");
        let mut wrong_nonce = nonce;
        wrong_nonce[5] ^= 0x01;
        let err = aead_decrypt(&key, &wrong_nonce, b"aad", &ct).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DecryptFailed);
    }

    #[test]
    fn aead_decrypt_rejects_ciphertext_byte_flip() {
        let key = [0xCC; AEAD_KEY_LEN];
        let nonce = [0xDD; AEAD_NONCE_LEN];
        let mut ct = aead_encrypt(&key, &nonce, b"aad", b"some-meaningful-data");
        // Flip a byte in the ciphertext region (before the 16-byte tag).
        let last_ct_idx = ct.len() - AEAD_TAG_LEN - 1;
        ct[last_ct_idx] ^= 0x01;
        let err = aead_decrypt(&key, &nonce, b"aad", &ct).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DecryptFailed);
    }

    #[test]
    fn aead_decrypt_rejects_tag_byte_flip() {
        let key = [0xCC; AEAD_KEY_LEN];
        let nonce = [0xDD; AEAD_NONCE_LEN];
        let mut ct = aead_encrypt(&key, &nonce, b"aad", b"payload");
        let tag_idx = ct.len() - 1;
        ct[tag_idx] ^= 0x01;
        let err = aead_decrypt(&key, &nonce, b"aad", &ct).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DecryptFailed);
    }

    #[test]
    fn aead_encrypt_emits_distinct_ciphertext_for_distinct_nonces() {
        let key = [0xCC; AEAD_KEY_LEN];
        let nonce_a = [0xAA; AEAD_NONCE_LEN];
        let nonce_b = [0xBB; AEAD_NONCE_LEN];
        let a = aead_encrypt(&key, &nonce_a, b"aad", b"payload");
        let b = aead_encrypt(&key, &nonce_b, b"aad", b"payload");
        assert_ne!(a, b);
    }

    #[test]
    fn aead_encrypt_with_empty_plaintext_emits_just_tag() {
        let key = [0xCC; AEAD_KEY_LEN];
        let nonce = [0xDD; AEAD_NONCE_LEN];
        let ct = aead_encrypt(&key, &nonce, b"aad", b"");
        assert_eq!(ct.len(), AEAD_TAG_LEN);
        let pt = aead_decrypt(&key, &nonce, b"aad", &ct).expect("empty round-trip");
        assert!(pt.is_empty());
    }

    /// Algorithm-choice lock — same KAT key / aad / plaintext run through
    /// the IETF `chacha20poly1305::ChaCha20Poly1305` (12-byte nonce)
    /// must produce ciphertext + tag that **differ** from the committed
    /// XChaCha20-Poly1305 RFC fixture. Pins the §4.4 choice of
    /// XChaCha20-Poly1305 (24-byte nonce) over the IETF
    /// ChaCha20-Poly1305 against silent-misconfig regressions in
    /// `aead_encrypt`. The negative-variant fixture is committed, not
    /// recomputed at test time.
    #[test]
    fn xchacha20_kat_inputs_through_chacha20_poly1305_produce_distinct_committed_output() {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Key as ChachaKey, Nonce as ChachaNonce,
        };

        let v = rfc_xchacha20_poly1305_vector();
        // ChaCha20-Poly1305 (IETF) takes a 12-byte nonce, not the 24-byte
        // XChaCha20 nonce. The first 12 bytes of the XChaCha20 KAT nonce
        // are the canonical "same nonce inputs" projection per §4.4.
        let nonce_ietf: [u8; 12] = v.nonce[..12]
            .try_into()
            .expect("12-byte slice of 24-byte nonce");

        let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&v.key));
        let actual = cipher
            .encrypt(
                ChachaNonce::from_slice(&nonce_ietf),
                Payload {
                    msg: &v.plaintext,
                    aad: &v.aad,
                },
            )
            .expect("ChaCha20-Poly1305 encrypt KAT");

        // Pinned bytes captured from `chacha20poly1305 = "0.10"` running
        // `ChaCha20Poly1305` (IETF, 12-byte nonce) on the same KAT
        // key / aad / plaintext as `rfc_xchacha20_poly1305_vector` with
        // the first 12 bytes of that vector's 24-byte nonce.
        let expected_chacha20: [u8; 130] = [
            0x11, 0xE1, 0x36, 0x53, 0xFB, 0x6A, 0x1B, 0x94, 0x47, 0xCB, 0x3B, 0x36, 0xA1, 0xB7,
            0x73, 0x09, 0x72, 0x75, 0xEB, 0x2C, 0xFE, 0xBB, 0xA4, 0xAA, 0xAF, 0xCF, 0x70, 0xD8,
            0x48, 0xE0, 0xE9, 0xB3, 0x4B, 0x3E, 0xDD, 0x5C, 0x46, 0x6D, 0x23, 0x9D, 0x6D, 0x1B,
            0x83, 0xBD, 0xA2, 0x5B, 0x12, 0x93, 0x20, 0xA1, 0x47, 0x51, 0x77, 0x28, 0x28, 0x91,
            0x75, 0x2B, 0xC9, 0x74, 0x8A, 0x74, 0x7B, 0xDF, 0x02, 0x17, 0x68, 0x32, 0xB3, 0x9B,
            0xBA, 0xFC, 0x01, 0xCD, 0x1F, 0x4F, 0x82, 0xBF, 0x77, 0x01, 0x72, 0x39, 0x73, 0xEB,
            0x1E, 0x76, 0x89, 0xB1, 0xA9, 0x35, 0xBB, 0xDF, 0xD2, 0xB5, 0x46, 0x0B, 0x4A, 0xFC,
            0xFC, 0xD9, 0xDE, 0xD8, 0x26, 0xCE, 0xAB, 0x20, 0x8F, 0x51, 0x34, 0x59, 0x2E, 0xA2,
            0xCC, 0x3D, 0x84, 0x11, 0x4A, 0xD9, 0xA2, 0x36, 0xD5, 0xFD, 0xAF, 0x9A, 0xA8, 0xF7,
            0x13, 0xEE, 0x39, 0x93,
        ];
        assert_eq!(
            actual, expected_chacha20,
            "ChaCha20-Poly1305 committed fixture mismatch (drop-in regression?)"
        );
        assert_ne!(
            actual, v.ciphertext_and_tag,
            "ChaCha20-Poly1305 (IETF, 12-byte nonce) must differ from XChaCha20-Poly1305 KAT"
        );
    }
}
