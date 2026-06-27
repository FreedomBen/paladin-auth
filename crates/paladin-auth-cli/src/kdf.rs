// SPDX-License-Identifier: AGPL-3.0-or-later

//! Encrypted-write KDF flag parser. Converts the raw `--kdf-memory-mib`,
//! `--kdf-time`, and `--kdf-parallelism` strings captured by clap into
//! validated `paladin_auth_core::Argon2Params` / `paladin_auth_core::EncryptionOptions`
//! per `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Encrypted-write KDF flags".
//!
//! Error contract (docs/DESIGN.md §5):
//!
//! - Integer parse failure → `validation_error` with `field` set to the
//!   hyphenated flag name (`"kdf-memory-mib"`, `"kdf-time"`,
//!   `"kdf-parallelism"`) and `reason: "invalid_integer"`.
//! - `mib * 1024` overflow → `validation_error` with `field:
//!   "kdf-memory-mib"` and `reason: "overflow"`.
//! - In-bounds parse but `(m_kib, t, p)` outside the §4.4 acceptance
//!   range → `kdf_params_out_of_bounds` carrying the offending values
//!   verbatim (delegated to `Argon2Params::validate`).
//!
//! Order of checks: integer-parse failures are detected per flag in
//! declaration order (`kdf-memory-mib` first, then `kdf-time`, then
//! `kdf-parallelism`). Overflow on `mib * 1024` runs after all three
//! parses succeed but before the `Argon2Params::validate` bounds check.
//! Empty-passphrase rejection on `parse_encryption_options` runs after
//! the KDF parameters validate, so KDF input failures still surface
//! before the user re-enters a passphrase.

// `parse_argon2_params` / `parse_encryption_options` are not yet wired
// into the binary; the dispatch handlers land in subsequent commits.
// The unit tests below exercise the contract end-to-end.
#![allow(dead_code)]

use paladin_auth_core::{Argon2Params, EncryptionOptions, PaladinAuthError};
use secrecy::SecretString;

use crate::cli::KdfArgs;

/// Stable §5 `field` value for a `--kdf-memory-mib` parse / overflow failure.
const F_MEMORY_MIB: &str = "kdf-memory-mib";
/// Stable §5 `field` value for a `--kdf-time` parse failure.
const F_TIME: &str = "kdf-time";
/// Stable §5 `field` value for a `--kdf-parallelism` parse failure.
const F_PARALLELISM: &str = "kdf-parallelism";

/// Parse the raw clap-captured KDF flag strings into a validated
/// [`Argon2Params`]. Omitted flags fall back to the §4.4 defaults
/// (`m_kib = 65_536`, `t = 3`, `p = 1`); supplied values flow through
/// the per-flag parser and the overflow / bounds checks documented in
/// the module header.
pub fn parse_argon2_params(args: &KdfArgs) -> Result<Argon2Params, PaladinAuthError> {
    let mib = parse_optional_u32(args.kdf_memory_mib.as_deref(), F_MEMORY_MIB)?;
    let t = parse_optional_u32(args.kdf_time.as_deref(), F_TIME)?;
    let p = parse_optional_u32(args.kdf_parallelism.as_deref(), F_PARALLELISM)?;

    let defaults = Argon2Params::default();
    let m_kib = match mib {
        Some(v) => v
            .checked_mul(1024)
            .ok_or_else(|| validation_err(F_MEMORY_MIB, "overflow"))?,
        None => defaults.m_kib,
    };
    let params = Argon2Params {
        m_kib,
        t: t.unwrap_or(defaults.t),
        p: p.unwrap_or(defaults.p),
    };
    params.validate()?;
    Ok(params)
}

/// Build an [`EncryptionOptions`] under the parsed [`Argon2Params`] and
/// the supplied passphrase. KDF parsing / validation happens first, so
/// any invalid flag wins over an empty-passphrase rejection — matching
/// the plan's "validate KDF flags before any prompt" rule.
pub fn parse_encryption_options(
    args: &KdfArgs,
    passphrase: SecretString,
) -> Result<EncryptionOptions, PaladinAuthError> {
    let params = parse_argon2_params(args)?;
    EncryptionOptions::with_params(passphrase, params)
}

fn parse_optional_u32(
    raw: Option<&str>,
    field: &'static str,
) -> Result<Option<u32>, PaladinAuthError> {
    match raw {
        None => Ok(None),
        Some(s) => s
            .parse::<u32>()
            .map(Some)
            .map_err(|_| validation_err(field, "invalid_integer")),
    }
}

fn validation_err(field: &'static str, reason: &'static str) -> PaladinAuthError {
    PaladinAuthError::ValidationError {
        field,
        reason: reason.to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paladin_auth_core::ErrorKind;
    use secrecy::ExposeSecret;

    fn args(mib: Option<&str>, t: Option<&str>, p: Option<&str>) -> KdfArgs {
        KdfArgs {
            kdf_memory_mib: mib.map(str::to_string),
            kdf_time: t.map(str::to_string),
            kdf_parallelism: p.map(str::to_string),
        }
    }

    fn empty() -> KdfArgs {
        args(None, None, None)
    }

    fn assert_validation(err: &PaladinAuthError, field: &str, reason: &str) {
        match err {
            PaladinAuthError::ValidationError {
                field: f,
                reason: r,
                source_index,
                decoded_len,
                recommended_min,
                entry_type,
            } => {
                assert_eq!(*f, field, "expected field {field}");
                assert_eq!(r, reason, "expected reason {reason}");
                assert!(source_index.is_none());
                assert!(decoded_len.is_none());
                assert!(recommended_min.is_none());
                assert!(entry_type.is_none());
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Defaults / Some-fields populated.

    #[test]
    fn all_unset_returns_section_4_4_defaults() {
        let p = parse_argon2_params(&empty()).expect("defaults valid");
        assert_eq!(p, Argon2Params::default());
        assert_eq!(p.m_kib, 65_536);
        assert_eq!(p.t, 3);
        assert_eq!(p.p, 1);
    }

    #[test]
    fn only_memory_mib_supplied_other_fields_default() {
        let p = parse_argon2_params(&args(Some("128"), None, None)).expect("128 MiB valid");
        assert_eq!(p.m_kib, 128 * 1024);
        assert_eq!(p.t, 3);
        assert_eq!(p.p, 1);
    }

    #[test]
    fn only_time_supplied_other_fields_default() {
        let p = parse_argon2_params(&args(None, Some("5"), None)).expect("t=5 valid");
        assert_eq!(p.m_kib, 65_536);
        assert_eq!(p.t, 5);
        assert_eq!(p.p, 1);
    }

    #[test]
    fn only_parallelism_supplied_other_fields_default() {
        let p = parse_argon2_params(&args(None, None, Some("4"))).expect("p=4 valid");
        assert_eq!(p.m_kib, 65_536);
        assert_eq!(p.t, 3);
        assert_eq!(p.p, 4);
    }

    #[test]
    fn all_three_supplied_in_range() {
        let p =
            parse_argon2_params(&args(Some("256"), Some("4"), Some("2"))).expect("custom valid");
        assert_eq!(p.m_kib, 256 * 1024);
        assert_eq!(p.t, 4);
        assert_eq!(p.p, 2);
    }

    #[test]
    fn memory_mib_at_section_4_4_floor_accepted() {
        // 8 MiB → m_kib = 8192 == M_KIB_MIN
        let p = parse_argon2_params(&args(Some("8"), None, None)).expect("8 MiB at floor");
        assert_eq!(p.m_kib, 8 * 1024);
    }

    #[test]
    fn memory_mib_at_section_4_4_ceiling_accepted() {
        // 1024 MiB → m_kib = 1_048_576 == M_KIB_MAX
        let p = parse_argon2_params(&args(Some("1024"), None, None)).expect("1024 MiB at ceiling");
        assert_eq!(p.m_kib, 1024 * 1024);
    }

    // ---------------------------------------------------------------
    // Per-flag invalid_integer.

    #[test]
    fn memory_mib_non_numeric_rejects_with_invalid_integer() {
        let err = parse_argon2_params(&args(Some("abc"), None, None)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValidationError);
        assert_validation(&err, "kdf-memory-mib", "invalid_integer");
    }

    #[test]
    fn memory_mib_negative_rejects_with_invalid_integer() {
        // u32 parse rejects "-1" — surface as the per-flag validation_error.
        let err = parse_argon2_params(&args(Some("-1"), None, None)).unwrap_err();
        assert_validation(&err, "kdf-memory-mib", "invalid_integer");
    }

    #[test]
    fn memory_mib_empty_string_rejects_with_invalid_integer() {
        let err = parse_argon2_params(&args(Some(""), None, None)).unwrap_err();
        assert_validation(&err, "kdf-memory-mib", "invalid_integer");
    }

    #[test]
    fn time_non_numeric_rejects_with_invalid_integer() {
        let err = parse_argon2_params(&args(None, Some("xyz"), None)).unwrap_err();
        assert_validation(&err, "kdf-time", "invalid_integer");
    }

    #[test]
    fn time_negative_rejects_with_invalid_integer() {
        let err = parse_argon2_params(&args(None, Some("-1"), None)).unwrap_err();
        assert_validation(&err, "kdf-time", "invalid_integer");
    }

    #[test]
    fn parallelism_non_numeric_rejects_with_invalid_integer() {
        let err = parse_argon2_params(&args(None, None, Some("two"))).unwrap_err();
        assert_validation(&err, "kdf-parallelism", "invalid_integer");
    }

    #[test]
    fn parallelism_negative_rejects_with_invalid_integer() {
        let err = parse_argon2_params(&args(None, None, Some("-3"))).unwrap_err();
        assert_validation(&err, "kdf-parallelism", "invalid_integer");
    }

    // ---------------------------------------------------------------
    // mib * 1024 overflow.

    #[test]
    fn memory_mib_at_overflow_boundary_rejects_with_overflow() {
        // u32::MAX / 1024 == 4_194_303.999..., so 4_194_304 overflows.
        let err = parse_argon2_params(&args(Some("4194304"), None, None)).unwrap_err();
        assert_validation(&err, "kdf-memory-mib", "overflow");
    }

    #[test]
    fn memory_mib_u32_max_rejects_with_overflow() {
        let raw = u32::MAX.to_string();
        let err = parse_argon2_params(&args(Some(&raw), None, None)).unwrap_err();
        assert_validation(&err, "kdf-memory-mib", "overflow");
    }

    #[test]
    fn memory_mib_above_u32_rejects_with_invalid_integer() {
        // u32::MAX + 1 overflows u32::from_str itself, which surfaces
        // first as `invalid_integer` — overflow-on-multiply only fires
        // for inputs that *do* parse to a u32.
        let raw = (u64::from(u32::MAX) + 1).to_string();
        let err = parse_argon2_params(&args(Some(&raw), None, None)).unwrap_err();
        assert_validation(&err, "kdf-memory-mib", "invalid_integer");
    }

    // ---------------------------------------------------------------
    // kdf_params_out_of_bounds (delegated to core).

    #[test]
    fn memory_mib_below_floor_rejects_with_kdf_out_of_bounds() {
        let err = parse_argon2_params(&args(Some("7"), None, None)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
        match err {
            PaladinAuthError::KdfParamsOutOfBounds { m_kib, t, p } => {
                assert_eq!(m_kib, 7 * 1024);
                assert_eq!(t, 3);
                assert_eq!(p, 1);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn memory_mib_above_ceiling_rejects_with_kdf_out_of_bounds() {
        // 1025 MiB → m_kib = 1_049_600 > M_KIB_MAX (1_048_576).
        let err = parse_argon2_params(&args(Some("1025"), None, None)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
        match err {
            PaladinAuthError::KdfParamsOutOfBounds { m_kib, .. } => {
                assert_eq!(m_kib, 1025 * 1024);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn time_below_floor_rejects_with_kdf_out_of_bounds() {
        let err = parse_argon2_params(&args(None, Some("0"), None)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
        match err {
            PaladinAuthError::KdfParamsOutOfBounds { t, .. } => assert_eq!(t, 0),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn time_above_ceiling_rejects_with_kdf_out_of_bounds() {
        let err = parse_argon2_params(&args(None, Some("11"), None)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
        match err {
            PaladinAuthError::KdfParamsOutOfBounds { t, .. } => assert_eq!(t, 11),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn parallelism_below_floor_rejects_with_kdf_out_of_bounds() {
        let err = parse_argon2_params(&args(None, None, Some("0"))).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
        match err {
            PaladinAuthError::KdfParamsOutOfBounds { p, .. } => assert_eq!(p, 0),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn parallelism_above_ceiling_rejects_with_kdf_out_of_bounds() {
        let err = parse_argon2_params(&args(None, None, Some("5"))).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
        match err {
            PaladinAuthError::KdfParamsOutOfBounds { p, .. } => assert_eq!(p, 5),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Ordering: parse > overflow > bounds.

    #[test]
    fn invalid_integer_in_memory_mib_wins_over_other_invalid_flags() {
        // All three flags would individually fail; declaration order
        // in `KdfArgs` is mib → time → parallelism, so we surface the
        // mib parse failure first.
        let err = parse_argon2_params(&args(Some("nope"), Some("11"), Some("99"))).unwrap_err();
        assert_validation(&err, "kdf-memory-mib", "invalid_integer");
    }

    #[test]
    fn invalid_integer_in_time_wins_over_invalid_parallelism() {
        let err = parse_argon2_params(&args(None, Some("nope"), Some("nope"))).unwrap_err();
        assert_validation(&err, "kdf-time", "invalid_integer");
    }

    #[test]
    fn overflow_in_memory_mib_wins_over_out_of_range_time() {
        // mib parses but mib*1024 overflows u32; t=11 would fail bounds.
        let err = parse_argon2_params(&args(Some("4194304"), Some("11"), None)).unwrap_err();
        assert_validation(&err, "kdf-memory-mib", "overflow");
    }

    #[test]
    fn out_of_range_memory_mib_wins_over_in_range_time_and_parallelism() {
        // Bounds check fires after all three integers parse and the
        // overflow check passes; mib=7 (<8 MiB floor) is the first
        // out-of-range field returned.
        let err = parse_argon2_params(&args(Some("7"), Some("3"), Some("1"))).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
    }

    // ---------------------------------------------------------------
    // parse_encryption_options.

    #[test]
    fn encryption_options_uses_default_params_for_empty_args() {
        let opts = parse_encryption_options(&empty(), SecretString::from("hunter2".to_string()))
            .expect("non-empty passphrase + default KDF");
        assert_eq!(opts.kdf_params, Argon2Params::default());
        assert_eq!(opts.passphrase.expose_secret(), "hunter2");
    }

    #[test]
    fn encryption_options_threads_custom_in_range_params() {
        let opts = parse_encryption_options(
            &args(Some("256"), Some("4"), Some("2")),
            SecretString::from("hunter2".to_string()),
        )
        .expect("custom KDF accepted");
        assert_eq!(opts.kdf_params.m_kib, 256 * 1024);
        assert_eq!(opts.kdf_params.t, 4);
        assert_eq!(opts.kdf_params.p, 2);
    }

    #[test]
    fn encryption_options_kdf_validation_wins_over_empty_passphrase() {
        // Out-of-bounds KDF + empty passphrase: the KDF parser rejects
        // first, matching the plan's "validate KDF flags before any
        // prompt" rule.
        let err = parse_encryption_options(
            &args(Some("7"), None, None),
            SecretString::from(String::new()),
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
    }

    #[test]
    fn encryption_options_invalid_integer_wins_over_empty_passphrase() {
        let err = parse_encryption_options(
            &args(Some("abc"), None, None),
            SecretString::from(String::new()),
        )
        .unwrap_err();
        assert_validation(&err, "kdf-memory-mib", "invalid_integer");
    }

    #[test]
    fn encryption_options_empty_passphrase_after_valid_kdf_rejects() {
        let err =
            parse_encryption_options(&empty(), SecretString::from(String::new())).unwrap_err();
        match err {
            PaladinAuthError::InvalidPassphrase { reason } => assert_eq!(reason, "zero_length"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
