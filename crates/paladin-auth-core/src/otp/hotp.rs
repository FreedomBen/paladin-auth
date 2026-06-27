// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HOTP code computation (RFC 4226). The Vault-level entry points
// `Vault::hotp_peek` and `Vault::hotp_advance` (Phase G) wrap this
// function plus the in-memory state plus persistence behavior.

use crate::domain::{Algorithm, Code, Secret};

use super::compute_hotp;

/// Compute the HOTP code for the given counter, returning a `Code`
/// projection with `counter_used` populated and TOTP validity fields
/// set to `None`.
#[must_use]
pub fn compute(secret: &Secret, algorithm: Algorithm, digits: u8, counter: u64) -> Code {
    let code = compute_hotp(secret, algorithm, digits, counter);
    Code {
        code,
        valid_from: None,
        valid_until: None,
        seconds_remaining: None,
        counter_used: Some(counter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_secret(bytes: &[u8]) -> Secret {
        Secret::from_bytes(bytes.to_vec())
    }

    /// RFC 4226 Appendix D, Count = 0..=9, Truncated 6-digit values.
    #[test]
    fn rfc4226_appendix_d_vectors_all_counters() {
        let key = make_secret(b"12345678901234567890");
        let expected = [
            (0u64, "755224"),
            (1, "287082"),
            (2, "359152"),
            (3, "969429"),
            (4, "338314"),
            (5, "254676"),
            (6, "287922"),
            (7, "162583"),
            (8, "399871"),
            (9, "520489"),
        ];
        for (counter, want) in expected {
            let code = compute(&key, Algorithm::Sha1, 6, counter);
            assert_eq!(code.code, want, "counter {counter}");
            assert_eq!(code.counter_used, Some(counter));
            assert!(code.valid_from.is_none());
            assert!(code.valid_until.is_none());
            assert!(code.seconds_remaining.is_none());
        }
    }

    /// Cross-product: algorithm ∈ {SHA1, SHA256, SHA512} × digits ∈
    /// {6, 7, 8} at counter = 1, using the matching RFC 6238 Appendix B
    /// keys. The 8-digit values match the published Appendix B T=59
    /// vectors (T=59 with period=30 → counter=1); the 6/7-digit forms
    /// are the `mod 10^digits` truncation with zero-padding. Mirrors
    /// `totp_digits_cross_product` to give the pure HOTP primitive the
    /// same per-algorithm × per-digits coverage TOTP already has.
    #[test]
    fn rfc6238_hotp_primitive_algorithm_digits_cross_product() {
        let table: &[(Algorithm, &[u8], [&str; 3])] = &[
            (
                Algorithm::Sha1,
                b"12345678901234567890",
                ["287082", "4287082", "94287082"],
            ),
            (
                Algorithm::Sha256,
                b"12345678901234567890123456789012",
                ["119246", "6119246", "46119246"],
            ),
            (
                Algorithm::Sha512,
                b"1234567890123456789012345678901234567890123456789012345678901234",
                ["693936", "0693936", "90693936"],
            ),
        ];
        for &(alg, key_bytes, expected) in table {
            let key = make_secret(key_bytes);
            let eight = expected[2];
            let eight_num: u64 = eight.parse().expect("8-digit fixture parses");
            for (digits, want) in [6u8, 7, 8].into_iter().zip(expected.iter()) {
                let code = compute(&key, alg, digits, 1);
                assert_eq!(code.code, *want, "alg={alg:?} digits={digits}");
                assert_eq!(code.code.len(), digits as usize);
                let modulus = 10u64.pow(u32::from(digits));
                let want_num = eight_num % modulus;
                let got_num: u64 = code.code.parse().expect("digit string parses");
                assert_eq!(
                    got_num, want_num,
                    "alg={alg:?} digits={digits} truncation of 8-digit form"
                );
                assert_eq!(code.counter_used, Some(1));
                assert!(code.valid_from.is_none());
                assert!(code.valid_until.is_none());
                assert!(code.seconds_remaining.is_none());
            }
        }
    }

    /// `compute` at the two endpoints of the `u64` counter range
    /// must not panic. `counter = 0` re-pins RFC 4226 Appendix D
    /// row 0 at the primitive layer. `counter = u64::MAX` returns
    /// a digit string of the requested length with `counter_used
    /// == Some(u64::MAX)` — overflow-on-advance is a `Vault`-level
    /// concern enforced by `Vault::hotp_advance`, not a primitive
    /// concern. Pins the layering so a future refactor that pulls
    /// the overflow check into `compute` is caught.
    #[test]
    fn hotp_compute_at_counter_zero_and_u64_max_does_not_panic() {
        let key = make_secret(b"12345678901234567890");

        let zero = compute(&key, Algorithm::Sha1, 6, 0);
        assert_eq!(zero.code, "755224");
        assert_eq!(zero.code.len(), 6);
        assert_eq!(zero.counter_used, Some(0));
        assert!(zero.valid_from.is_none());
        assert!(zero.valid_until.is_none());
        assert!(zero.seconds_remaining.is_none());

        let max = compute(&key, Algorithm::Sha1, 6, u64::MAX);
        assert_eq!(max.code.len(), 6);
        assert!(max.code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(max.counter_used, Some(u64::MAX));
        assert!(max.valid_from.is_none());
        assert!(max.valid_until.is_none());
        assert!(max.seconds_remaining.is_none());
    }
}
