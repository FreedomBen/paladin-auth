// SPDX-License-Identifier: AGPL-3.0-or-later
//
// TOTP code computation (RFC 6238). Computes the active counter from
// the supplied `now: SystemTime`, returns a `Code` with TOTP validity
// fields populated, and rejects pre-epoch / overflowing time inputs.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{Algorithm, Code, Secret};
use crate::error::{PaladinError, TimeRangeKind};

use super::compute_hotp;

/// Compute the TOTP code for `now` using the supplied period (seconds).
///
/// The validity window is half-open: `[valid_from, valid_until)`.
/// `seconds_remaining` is `valid_until - now_unix`; on the exact
/// counter boundary (`now_unix == counter * period`) it equals
/// `period`. Pre-epoch inputs are rejected with `time_range`
/// (`pre_epoch`); a `valid_until` overflow rejects with
/// `time_range` (`overflow`).
pub fn compute(
    secret: &Secret,
    algorithm: Algorithm,
    period: u32,
    digits: u8,
    now: SystemTime,
    operation: &'static str,
) -> Result<Code, PaladinError> {
    debug_assert!(period >= 1);
    let now_unix = system_time_to_unix(now, operation)?;
    let period_u64 = u64::from(period);
    let counter = now_unix / period_u64;
    let valid_from = counter
        .checked_mul(period_u64)
        .ok_or(PaladinError::TimeRange {
            operation,
            kind: TimeRangeKind::Overflow,
        })?;
    let valid_until = valid_from
        .checked_add(period_u64)
        .ok_or(PaladinError::TimeRange {
            operation,
            kind: TimeRangeKind::Overflow,
        })?;
    let seconds_remaining = valid_until - now_unix;
    debug_assert!((1..=period_u64).contains(&seconds_remaining));
    // `seconds_remaining` is bounded by `period_u64`, which itself is
    // u32, so the cast is well-defined. `try_from` keeps clippy happy
    // and pins the invariant in code.
    let seconds_remaining_u32 =
        u32::try_from(seconds_remaining).expect("seconds_remaining bounded by u32 period");
    let code = compute_hotp(secret, algorithm, digits, counter);
    Ok(Code {
        code,
        valid_from: Some(valid_from),
        valid_until: Some(valid_until),
        seconds_remaining: Some(seconds_remaining_u32),
        counter_used: None,
    })
}

fn system_time_to_unix(now: SystemTime, operation: &'static str) -> Result<u64, PaladinError> {
    let dur = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PaladinError::TimeRange {
            operation,
            kind: TimeRangeKind::PreEpoch,
        })?;
    Ok(dur.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_secret(bytes: &[u8]) -> Secret {
        Secret::from_bytes(bytes.to_vec())
    }

    fn at_unix(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// RFC 6238 Appendix B test vectors for SHA1 (key = ASCII
    /// "12345678901234567890"). All 8-digit values, 30s period.
    #[test]
    fn rfc6238_appendix_b_sha1() {
        let key = make_secret(b"12345678901234567890");
        let cases: &[(u64, &str)] = &[
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for &(t, want) in cases {
            let code = compute(&key, Algorithm::Sha1, 30, 8, at_unix(t), "totp_code").unwrap();
            assert_eq!(code.code, want, "T={t}");
            assert_eq!(code.valid_until.unwrap() - code.valid_from.unwrap(), 30);
            assert!(code.counter_used.is_none());
        }
    }

    /// RFC 6238 Appendix B test vectors for SHA256 (key = ASCII
    /// "12345678901234567890123456789012", 32 bytes).
    #[test]
    fn rfc6238_appendix_b_sha256() {
        let key = make_secret(b"12345678901234567890123456789012");
        let cases: &[(u64, &str)] = &[
            (59, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ];
        for &(t, want) in cases {
            let code = compute(&key, Algorithm::Sha256, 30, 8, at_unix(t), "totp_code").unwrap();
            assert_eq!(code.code, want, "T={t}");
        }
    }

    /// RFC 6238 Appendix B test vectors for SHA512 (key = ASCII
    /// "1234567890" repeated to 64 bytes).
    #[test]
    fn rfc6238_appendix_b_sha512() {
        let key = make_secret(b"1234567890123456789012345678901234567890123456789012345678901234");
        let cases: &[(u64, &str)] = &[
            (59, "90693936"),
            (1_111_111_109, "25091201"),
            (1_111_111_111, "99943326"),
            (1_234_567_890, "93441116"),
            (2_000_000_000, "38618901"),
            (20_000_000_000, "47863826"),
        ];
        for &(t, want) in cases {
            let code = compute(&key, Algorithm::Sha512, 30, 8, at_unix(t), "totp_code").unwrap();
            assert_eq!(code.code, want, "T={t}");
        }
    }

    /// Cross-product: digits ∈ {6,7,8} × algorithm ∈ {SHA1,SHA256,
    /// SHA512} for at least one TOTP vector. Catches zero-padding and
    /// HMAC-truncation regressions per algorithm.
    #[test]
    fn totp_digits_cross_product() {
        // T = 59 across the three RFC 6238 keys.
        // Expected values derived from the 8-digit RFC 6238 vectors:
        // SHA1   at T=59 = 94287082
        // SHA256 at T=59 = 46119246
        // SHA512 at T=59 = 90693936
        // The 6/7-digit forms are mod 10^6 / 10^7 with zero-padding.
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
            for (digits, want) in [6u8, 7, 8].into_iter().zip(expected.iter()) {
                let code = compute(&key, alg, 30, digits, at_unix(59), "totp_code").unwrap();
                assert_eq!(code.code, *want, "digits={digits} alg={alg:?}");
                assert_eq!(code.code.len(), digits as usize);
            }
        }
    }

    #[test]
    fn totp_window_half_open_seconds_remaining_in_1_through_period() {
        let key = make_secret(b"12345678901234567890");
        let period = 30u32;
        // At now = 30, counter = 1, valid_from = 30, valid_until = 60,
        // seconds_remaining = 30 (full period at the exact boundary).
        let code = compute(&key, Algorithm::Sha1, period, 6, at_unix(30), "totp_code").unwrap();
        assert_eq!(code.valid_from, Some(30));
        assert_eq!(code.valid_until, Some(60));
        assert_eq!(code.seconds_remaining, Some(30));

        // At now = 31, counter still 1, seconds_remaining = 29.
        let code = compute(&key, Algorithm::Sha1, period, 6, at_unix(31), "totp_code").unwrap();
        assert_eq!(code.seconds_remaining, Some(29));

        // At now = 59 (last second of the window), seconds_remaining = 1.
        let code = compute(&key, Algorithm::Sha1, period, 6, at_unix(59), "totp_code").unwrap();
        assert_eq!(code.seconds_remaining, Some(1));

        // At now = 60 (next window opens), counter = 2, valid_from = 60,
        // valid_until = 90, seconds_remaining = 30.
        let code = compute(&key, Algorithm::Sha1, period, 6, at_unix(60), "totp_code").unwrap();
        assert_eq!(code.valid_from, Some(60));
        assert_eq!(code.valid_until, Some(90));
        assert_eq!(code.seconds_remaining, Some(30));
    }

    #[test]
    fn totp_pre_epoch_rejected() {
        let key = make_secret(b"12345678901234567890");
        let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
        let err = compute(&key, Algorithm::Sha1, 30, 6, pre_epoch, "totp_code").unwrap_err();
        match err {
            PaladinError::TimeRange { operation, kind } => {
                assert_eq!(operation, "totp_code");
                assert_eq!(kind, TimeRangeKind::PreEpoch);
            }
            other => panic!("expected TimeRange::PreEpoch, got {other:?}"),
        }
    }

    /// The operation tag flows from the caller through every
    /// `TimeRange` returned by `compute`, so `totp_next_code`
    /// (defined on `Vault`) surfaces its own operation name rather
    /// than leaking the `"totp_code"` tag from the primitive.
    #[test]
    fn totp_pre_epoch_uses_caller_supplied_operation_tag() {
        let key = make_secret(b"12345678901234567890");
        let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
        let err = compute(&key, Algorithm::Sha1, 30, 6, pre_epoch, "totp_next_code").unwrap_err();
        match err {
            PaladinError::TimeRange { operation, kind } => {
                assert_eq!(operation, "totp_next_code");
                assert_eq!(kind, TimeRangeKind::PreEpoch);
            }
            other => panic!("expected TimeRange::PreEpoch, got {other:?}"),
        }
    }

    /// Feed an explicit u64 unix-seconds value through the overflow
    /// checks `compute` performs after `system_time_to_unix`.
    /// `SystemTime` itself rejects values past its platform-specific
    /// upper bound, so we can't construct one directly in the
    /// overflow window.
    fn compute_from_unix(
        secret: &Secret,
        algorithm: Algorithm,
        period: u32,
        digits: u8,
        now_unix: u64,
        operation: &'static str,
    ) -> Result<Code, PaladinError> {
        let period_u64 = u64::from(period);
        let counter = now_unix / period_u64;
        let valid_from = counter
            .checked_mul(period_u64)
            .ok_or(PaladinError::TimeRange {
                operation,
                kind: TimeRangeKind::Overflow,
            })?;
        let valid_until = valid_from
            .checked_add(period_u64)
            .ok_or(PaladinError::TimeRange {
                operation,
                kind: TimeRangeKind::Overflow,
            })?;
        let seconds_remaining = valid_until - now_unix;
        let seconds_remaining_u32 =
            u32::try_from(seconds_remaining).expect("seconds_remaining bounded by u32 period");
        let code = crate::otp::compute_hotp(secret, algorithm, digits, counter);
        Ok(Code {
            code,
            valid_from: Some(valid_from),
            valid_until: Some(valid_until),
            seconds_remaining: Some(seconds_remaining_u32),
            counter_used: None,
        })
    }

    #[test]
    fn totp_valid_until_overflow_rejected() {
        let key = make_secret(b"12345678901234567890");
        let period = 30u32;

        // The largest accepted `now_unix` is the last second of the
        // window whose `valid_until` exactly fits in u64.
        let counter_max = (u64::MAX - u64::from(period)) / u64::from(period);
        let valid_from_max = counter_max * u64::from(period);
        let last_in_window = valid_from_max + u64::from(period) - 1;
        let code = compute_from_unix(
            &key,
            Algorithm::Sha1,
            period,
            6,
            last_in_window,
            "totp_code",
        )
        .unwrap();
        assert_eq!(code.valid_from, Some(valid_from_max));
        assert_eq!(code.valid_until, Some(valid_from_max + u64::from(period)));

        // Step into the next window: `valid_until` overflows.
        let next_counter_window = last_in_window + 1;
        let err = compute_from_unix(
            &key,
            Algorithm::Sha1,
            period,
            6,
            next_counter_window,
            "totp_code",
        )
        .unwrap_err();
        match err {
            PaladinError::TimeRange { operation, kind } => {
                assert_eq!(operation, "totp_code");
                assert_eq!(kind, TimeRangeKind::Overflow);
            }
            other => panic!("expected TimeRange::Overflow, got {other:?}"),
        }
    }
}
