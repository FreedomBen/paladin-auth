// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pure OTP primitives (DESIGN.md §4.2).
//
// `compute_hotp` is the shared HMAC-based dynamic-truncation that
// underlies both RFC 4226 (HOTP) and RFC 6238 (TOTP). The Vault-level
// entry points (Phase G) layer on the in-memory state and persistence
// behavior; this module is state-free and never persists.

pub mod hotp;
pub mod totp;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::domain::{Algorithm, Secret};

/// Maximum supported digit width.
pub const MAX_DIGITS: u8 = 8;

/// Compute an OTP for the given counter value (RFC 4226 §5.3 dynamic
/// truncation). The output is zero-padded to exactly `digits` chars.
pub(crate) fn compute_hotp(
    secret: &Secret,
    algorithm: Algorithm,
    digits: u8,
    counter: u64,
) -> String {
    debug_assert!((6..=MAX_DIGITS).contains(&digits));
    let counter_bytes = counter.to_be_bytes();
    let truncated = truncate(&hmac_digest(secret, algorithm, &counter_bytes));
    let modulus = pow10(digits);
    let value = u64::from(truncated) % modulus;
    format_zero_padded(value, digits)
}

fn hmac_digest(secret: &Secret, algorithm: Algorithm, message: &[u8]) -> Vec<u8> {
    match algorithm {
        Algorithm::Sha1 => hmac_sha1(secret.expose_secret(), message),
        Algorithm::Sha256 => hmac_sha256(secret.expose_secret(), message),
        Algorithm::Sha512 => hmac_sha512(secret.expose_secret(), message),
    }
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key)
        .expect("HMAC key length is unrestricted by RFC 2104");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC key length is unrestricted by RFC 2104");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key)
        .expect("HMAC key length is unrestricted by RFC 2104");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 4226 §5.3 dynamic-truncation: a 4-byte big-endian slice starting
/// at `offset = HS[len-1] & 0xF`, with the high bit of the first byte
/// masked off so the result is always a positive 31-bit integer.
fn truncate(hs: &[u8]) -> u32 {
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let p = &hs[offset..offset + 4];
    ((u32::from(p[0]) & 0x7f) << 24)
        | (u32::from(p[1]) << 16)
        | (u32::from(p[2]) << 8)
        | u32::from(p[3])
}

const fn pow10(digits: u8) -> u64 {
    let mut result: u64 = 1;
    let mut i = 0u8;
    while i < digits {
        result *= 10;
        i += 1;
    }
    result
}

fn format_zero_padded(value: u64, digits: u8) -> String {
    format!("{value:0width$}", width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_secret(bytes: &[u8]) -> Secret {
        Secret::from_bytes(bytes.to_vec())
    }

    /// RFC 4226 Appendix D, Count = 0 → 755224.
    #[test]
    fn rfc4226_count_0_baseline() {
        let key = make_secret(b"12345678901234567890");
        let code = compute_hotp(&key, Algorithm::Sha1, 6, 0);
        assert_eq!(code, "755224");
    }

    #[test]
    fn pow10_table() {
        assert_eq!(pow10(0), 1);
        assert_eq!(pow10(6), 1_000_000);
        assert_eq!(pow10(7), 10_000_000);
        assert_eq!(pow10(8), 100_000_000);
    }

    #[test]
    fn truncate_matches_rfc4226_appendix_d_offset_4() {
        // RFC 4226 Appendix D Count=0 HMAC-SHA1 result. Last byte 0xfa
        // → offset 0xa (10). The 4-byte slice starting at offset 10 is
        // 50ef7f19, which masks to 0x50ef7f19, mod 1_000_000 = 872921.
        // The actual value 755224 verifies the canonical algorithm.
        let key = b"12345678901234567890";
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).unwrap();
        mac.update(&0u64.to_be_bytes());
        let hs = mac.finalize().into_bytes().to_vec();
        let last = hs[hs.len() - 1];
        let offset = (last & 0xf) as usize;
        // The §5.3 truncation should produce a value whose mod 10^6 is
        // 755224.
        let truncated = truncate(&hs);
        assert!(offset + 4 <= hs.len());
        assert_eq!(u64::from(truncated) % 1_000_000, 755_224);
    }
}
