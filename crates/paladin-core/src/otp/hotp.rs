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
}
