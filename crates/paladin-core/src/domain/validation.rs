// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared validation entry points (DESIGN.md §4.1, §4.7).
//
// `validate_manual` is the one place where flag-driven manual input is
// turned into a fully validated `Account`. The same validation table
// is reused by the otpauth parser (Phase D) and the importers
// (Phase I) so all three paths fail identically on the same input.

use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};

use crate::error::{PaladinError, TimeRangeKind};

use super::secret::Secret;
use super::{Account, AccountId, AccountKindInput, Algorithm, IconHintInput, OtpKind};

pub const LABEL_MAX_BYTES: usize = 128;
pub const ISSUER_MAX_BYTES: usize = 128;
pub const SECRET_MIN_BYTES: usize = 10;
pub const SECRET_MAX_BYTES: usize = 1024;
pub const SHORT_SECRET_THRESHOLD_BYTES: usize = 16;
/// Minimum OTP digit count accepted by `validate_digits` (inclusive).
pub const DIGITS_MIN: u8 = 6;
/// Maximum OTP digit count accepted by `validate_digits` (inclusive).
pub const DIGITS_MAX: u8 = 8;
/// CLI manual-add and importer fallback digit count per `DESIGN.md` §5.
pub const DIGITS_DEFAULT: u8 = 6;
/// Minimum TOTP period in seconds accepted by `validate_totp_period`
/// (inclusive).
pub const TOTP_PERIOD_MIN: u32 = 1;
/// Maximum TOTP period in seconds accepted by `validate_totp_period`
/// (inclusive).
pub const TOTP_PERIOD_MAX: u32 = 300;
/// CLI manual-add and importer fallback TOTP period per `DESIGN.md` §5.
pub const TOTP_PERIOD_DEFAULT: u32 = 30;
/// Inclusive upper bound on Unix-seconds timestamps stored in the
/// vault: `9999-12-31T23:59:59Z`.
pub const TIMESTAMP_MAX_INCLUSIVE: u64 = 253_402_300_799;

/// Manual flag-driven input for `validate_manual`. The CLI's
/// `paladin add` flow constructs this from CLI arguments and passes it
/// straight to core. Importers and the otpauth parser do **not** use
/// this struct — they call the lower-level helpers in this module
/// directly.
pub struct AccountInput {
    /// Account label (max 128 bytes after trimming).
    pub label: String,
    /// Optional issuer (max 128 bytes).
    pub issuer: Option<String>,
    /// Base32-encoded shared secret (zeroized on drop).
    pub secret: SecretString,
    /// HMAC algorithm.
    pub algorithm: Algorithm,
    /// Number of OTP digits (6, 7, or 8).
    pub digits: u8,
    /// `Totp` or `Hotp`.
    pub kind: AccountKindInput,
    /// TOTP period in seconds (TOTP only); rejected when `kind` is `Hotp`.
    pub period_secs: Option<u32>,
    /// HOTP starting counter (HOTP only); rejected when `kind` is `Totp`.
    pub counter: Option<u64>,
    /// Icon-hint tri-state (default-from-issuer, clear, or supplied slug).
    pub icon_hint: IconHintInput,
}

/// Non-fatal warning surfaced alongside a validated account.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "error-serde",
    serde(tag = "kind", rename_all = "snake_case")
)]
pub enum ValidationWarning {
    /// Decoded secret is shorter than the recommended minimum (RFC 4226 §4 R6).
    ShortSecret {
        /// Length of the decoded secret in bytes.
        decoded_len: usize,
        /// Recommended minimum length (`SHORT_SECRET_THRESHOLD_BYTES`).
        recommended_min: usize,
    },
}

/// Output of `validate_manual` (and the import paths). Carries the
/// validated `Account` plus any non-fatal warnings.
///
/// `Debug` is derived only because `Account`'s manual `Debug` impl
/// omits the secret bytes — see the runtime audits in
/// `tests/secret_audits.rs`.
#[derive(Debug)]
pub struct ValidatedAccount {
    /// The validated account ready for insertion into the vault.
    pub account: Account,
    /// Non-fatal warnings collected during validation (e.g. `ShortSecret`).
    pub warnings: Vec<ValidationWarning>,
}

/// Manual flag-driven path: turn `AccountInput` into a `ValidatedAccount`.
///
/// The same table covers the otpauth parser and the importers (Phase D
/// + I), via the lower-level helpers in this module.
pub fn validate_manual(
    input: AccountInput,
    now: SystemTime,
) -> Result<ValidatedAccount, PaladinError> {
    let label = validate_label(&input.label)?;
    let issuer = validate_issuer(input.issuer.as_deref())?;

    let (secret, secret_warning) = decode_and_validate_secret(input.secret.expose_secret())?;
    let algorithm = input.algorithm;
    let digits = validate_digits(input.digits, DIGITS_DEFAULT)?;

    let kind = match input.kind {
        AccountKindInput::Totp => OtpKind::Totp {
            period: validate_totp_period(input.period_secs.unwrap_or(TOTP_PERIOD_DEFAULT))?,
        },
        AccountKindInput::Hotp => OtpKind::Hotp {
            counter: input.counter.unwrap_or(0),
        },
    };

    if matches!(input.kind, AccountKindInput::Totp) && input.counter.is_some() {
        return Err(PaladinError::validation("counter", "rejected_on_totp"));
    }
    if matches!(input.kind, AccountKindInput::Hotp) && input.period_secs.is_some() {
        return Err(PaladinError::validation("period", "rejected_on_hotp"));
    }

    let icon_hint = input.icon_hint.resolve(issuer.as_deref())?;

    let now_secs = system_time_to_secs(now)?;

    let account = Account {
        id: AccountId::new(),
        label,
        issuer,
        secret,
        algorithm,
        digits,
        kind,
        icon_hint,
        created_at: now_secs,
        updated_at: now_secs,
    };

    let mut warnings = Vec::new();
    if let Some(w) = secret_warning {
        warnings.push(w);
    }

    Ok(ValidatedAccount { account, warnings })
}

/// Trim Unicode whitespace and reject empty / overlong labels.
///
/// Returns the trimmed label on success or
/// `PaladinError::ValidationError { field: "label", reason: … }` for
/// `empty` / `too_long` rejections (§4.1 length rules / §5 stable
/// error codes). Public so the TUI / GUI front-ends can pre-validate
/// Rename modal input before emitting a save effect — the
/// post-emission core path (`Vault::rename`) re-validates idempotently.
pub fn validate_label(raw: &str) -> Result<String, PaladinError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PaladinError::validation("label", "empty"));
    }
    if trimmed.len() > LABEL_MAX_BYTES {
        return Err(PaladinError::validation("label", "too_long"));
    }
    Ok(trimmed.to_owned())
}

/// Trim Unicode whitespace and reject overlong issuers. Empty becomes `None`.
pub(crate) fn validate_issuer(raw: Option<&str>) -> Result<Option<String>, PaladinError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > ISSUER_MAX_BYTES {
        return Err(PaladinError::validation("issuer", "too_long"));
    }
    Ok(Some(trimmed.to_owned()))
}

/// Validate `digits ∈ [6, 8]`. Caller passes a default when the
/// upstream input did not specify one.
pub(crate) fn validate_digits(digits: u8, _default: u8) -> Result<u8, PaladinError> {
    if !(DIGITS_MIN..=DIGITS_MAX).contains(&digits) {
        return Err(PaladinError::validation("digits", "out_of_range"));
    }
    Ok(digits)
}

pub(crate) fn validate_totp_period(period: u32) -> Result<u32, PaladinError> {
    if !(TOTP_PERIOD_MIN..=TOTP_PERIOD_MAX).contains(&period) {
        return Err(PaladinError::validation("period", "out_of_range"));
    }
    Ok(period)
}

/// Decode RFC 4648 base32 (case-insensitive, optional `=` padding,
/// ASCII-whitespace rejected) and apply the §4.1 length rules.
///
/// Returns `(secret, optional_short_secret_warning)`.
pub(crate) fn decode_and_validate_secret(
    text: &str,
) -> Result<(Secret, Option<ValidationWarning>), PaladinError> {
    if text.is_empty() {
        return Err(PaladinError::validation("secret", "empty"));
    }
    if text.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(PaladinError::validation("secret", "whitespace"));
    }
    decode_secret_bytes(text.as_bytes())
}

pub(crate) fn decode_secret_bytes(
    text: &[u8],
) -> Result<(Secret, Option<ValidationWarning>), PaladinError> {
    let upper = text.to_ascii_uppercase();
    let trimmed = trim_padding_bytes(&upper);
    let trimmed_str = std::str::from_utf8(trimmed)
        .map_err(|_| PaladinError::validation("secret", "decode_failed"))?;
    let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, trimmed_str)
        .ok_or_else(|| PaladinError::validation("secret", "decode_failed"))?;
    let len = bytes.len();
    if len < SECRET_MIN_BYTES {
        return Err(PaladinError::ValidationError {
            field: "secret",
            reason: "too_short".into(),
            source_index: None,
            decoded_len: Some(len),
            recommended_min: Some(SECRET_MIN_BYTES),
            entry_type: None,
        });
    }
    if len > SECRET_MAX_BYTES {
        return Err(PaladinError::ValidationError {
            field: "secret",
            reason: "too_long".into(),
            source_index: None,
            decoded_len: Some(len),
            recommended_min: None,
            entry_type: None,
        });
    }
    let warning = if len < SHORT_SECRET_THRESHOLD_BYTES {
        Some(ValidationWarning::ShortSecret {
            decoded_len: len,
            recommended_min: SHORT_SECRET_THRESHOLD_BYTES,
        })
    } else {
        None
    };
    Ok((Secret::from_bytes(bytes), warning))
}

fn trim_padding_bytes(input: &[u8]) -> &[u8] {
    let mut end = input.len();
    while end > 0 && input[end - 1] == b'=' {
        end -= 1;
    }
    &input[..end]
}

/// Convert a `SystemTime` into Unix seconds, rejecting pre-epoch and
/// timestamps beyond the §4.1 year-9999 cap.
pub(crate) fn system_time_to_secs(now: SystemTime) -> Result<u64, PaladinError> {
    system_time_to_secs_for("validate_manual", now)
}

/// `system_time_to_secs` variant whose `time_range` errors carry the
/// caller's `operation` label (e.g. `"rename"`, `"hotp_advance"`).
pub(crate) fn system_time_to_secs_for(
    operation: &'static str,
    now: SystemTime,
) -> Result<u64, PaladinError> {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PaladinError::TimeRange {
            operation,
            kind: TimeRangeKind::PreEpoch,
        })?
        .as_secs();
    if secs > TIMESTAMP_MAX_INCLUSIVE {
        return Err(PaladinError::TimeRange {
            operation,
            kind: TimeRangeKind::OutOfRange,
        });
    }
    Ok(secs)
}

/// Borrow-only construction used by the otpauth parser and importers
/// (Phase D / I). `id` is generated, timestamps come from the
/// import-time clock, and the secret is supplied as already-decoded
/// bytes.
pub(crate) struct ParsedAccount {
    pub label: String,
    pub issuer: Option<String>,
    pub secret: Secret,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub kind: OtpKind,
    pub icon_hint: Option<String>,
}

impl ParsedAccount {
    pub(crate) fn into_validated(
        self,
        now: SystemTime,
        warnings: Vec<ValidationWarning>,
    ) -> Result<ValidatedAccount, PaladinError> {
        let now_secs = system_time_to_secs(now)?;
        Ok(ValidatedAccount {
            account: Account {
                id: AccountId::new(),
                label: self.label,
                issuer: self.issuer,
                secret: self.secret,
                algorithm: self.algorithm,
                digits: self.digits,
                kind: self.kind,
                icon_hint: self.icon_hint,
                created_at: now_secs,
                updated_at: now_secs,
            },
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_for_tests() -> SystemTime {
        // 2026-05-07T12:00:00Z (a stable in-range timestamp).
        UNIX_EPOCH + std::time::Duration::from_secs(1_778_414_400)
    }

    fn base32_secret(bytes: &[u8]) -> SecretString {
        SecretString::from(base32::encode(
            base32::Alphabet::Rfc4648 { padding: true },
            bytes,
        ))
    }

    fn manual_input(label: &str) -> AccountInput {
        AccountInput {
            label: label.into(),
            issuer: Some("Acme".into()),
            secret: base32_secret(&[0x42; 20]),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: AccountKindInput::Totp,
            period_secs: None,
            counter: None,
            icon_hint: IconHintInput::Default,
        }
    }

    #[test]
    fn happy_path_totp_default() {
        let v = validate_manual(manual_input("alice@example.com"), now_for_tests()).unwrap();
        assert!(v.warnings.is_empty());
        assert_eq!(v.account.label(), "alice@example.com");
        assert_eq!(v.account.issuer(), Some("Acme"));
        assert_eq!(v.account.digits(), 6);
        assert_eq!(v.account.algorithm(), Algorithm::Sha1);
        assert_eq!(v.account.period(), Some(30));
        assert_eq!(v.account.counter(), None);
        assert_eq!(v.account.icon_hint(), Some("acme"));
    }

    #[test]
    fn label_trimmed_and_required() {
        let mut input = manual_input("  alice  ");
        let v = validate_manual(
            AccountInput {
                label: input.label.clone(),
                ..manual_input("alice")
            },
            now_for_tests(),
        )
        .unwrap();
        assert_eq!(v.account.label(), "alice");
        input.label = "   ".into();
        let err = validate_manual(input, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "label");
                assert_eq!(reason, "empty");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn label_boundary_127_128_129() {
        let ok_127 = "a".repeat(127);
        let ok_128 = "a".repeat(128);
        let bad_129 = "a".repeat(129);
        for label in [ok_127, ok_128] {
            let mut input = manual_input("placeholder");
            input.label = label;
            assert!(validate_manual(input, now_for_tests()).is_ok());
        }
        let mut bad = manual_input("placeholder");
        bad.label = bad_129;
        let err = validate_manual(bad, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "label");
                assert_eq!(reason, "too_long");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn label_multibyte_codepoint_at_byte_128_rejects_without_truncation() {
        // 127 ASCII bytes + a 2-byte é (0xC3 0xA9) = 129 bytes total
        // Crucially, the character boundary lies between bytes 128
        // and 129; a naive byte-truncation would split é.
        let label = format!("{}é", "a".repeat(127));
        assert_eq!(label.len(), 129);
        let mut input = manual_input("placeholder");
        input.label = label;
        let err = validate_manual(input, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "label");
                assert_eq!(reason, "too_long");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn issuer_whitespace_only_becomes_none() {
        let mut input = manual_input("alice");
        input.issuer = Some("   ".into());
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert_eq!(v.account.issuer(), None);
        // No issuer → no derived icon hint.
        assert_eq!(v.account.icon_hint(), None);
    }

    #[test]
    fn issuer_too_long_rejects() {
        let mut input = manual_input("alice");
        input.issuer = Some("a".repeat(129));
        let err = validate_manual(input, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "issuer");
                assert_eq!(reason, "too_long");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn digits_range_6_to_8() {
        for d in [5u8, 9u8, 0u8] {
            let mut input = manual_input("alice");
            input.digits = d;
            assert!(validate_manual(input, now_for_tests()).is_err());
        }
        for d in [6u8, 7u8, 8u8] {
            let mut input = manual_input("alice");
            input.digits = d;
            let v = validate_manual(input, now_for_tests()).unwrap();
            assert_eq!(v.account.digits(), d);
        }
    }

    #[test]
    fn totp_period_bounds() {
        for bad in [0u32, 301u32] {
            let mut input = manual_input("alice");
            input.period_secs = Some(bad);
            assert!(validate_manual(input, now_for_tests()).is_err());
        }
        for good in [1u32, 30u32, 60u32, 300u32] {
            let mut input = manual_input("alice");
            input.period_secs = Some(good);
            let v = validate_manual(input, now_for_tests()).unwrap();
            assert_eq!(v.account.period(), Some(good));
        }
    }

    #[test]
    fn period_rejected_on_hotp_input() {
        let mut input = manual_input("alice");
        input.kind = AccountKindInput::Hotp;
        input.period_secs = Some(30);
        let err = validate_manual(input, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "period");
                assert_eq!(reason, "rejected_on_hotp");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn counter_rejected_on_totp_input() {
        let mut input = manual_input("alice");
        input.counter = Some(0);
        let err = validate_manual(input, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "counter");
                assert_eq!(reason, "rejected_on_totp");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn hotp_default_counter_zero() {
        let mut input = manual_input("alice");
        input.kind = AccountKindInput::Hotp;
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert_eq!(v.account.kind(), super::super::AccountKindSummary::Hotp);
        assert_eq!(v.account.counter(), Some(0));
        assert_eq!(v.account.period(), None);
    }

    #[test]
    fn secret_length_boundaries() {
        // Exactly 9 bytes → reject.
        let mut input = manual_input("alice");
        input.secret = base32_secret(&[1u8; 9]);
        assert!(matches!(
            validate_manual(input, now_for_tests()).unwrap_err(),
            PaladinError::ValidationError { field, reason, decoded_len, .. }
                if field == "secret" && reason == "too_short" && decoded_len == Some(9)
        ));

        // Exactly 10 bytes → accept (with short-secret warning).
        let mut input = manual_input("alice");
        input.secret = base32_secret(&[1u8; 10]);
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert_eq!(
            v.warnings,
            vec![ValidationWarning::ShortSecret {
                decoded_len: 10,
                recommended_min: 16,
            }]
        );

        // 15 bytes → still warns.
        let mut input = manual_input("alice");
        input.secret = base32_secret(&[1u8; 15]);
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert_eq!(
            v.warnings,
            vec![ValidationWarning::ShortSecret {
                decoded_len: 15,
                recommended_min: 16,
            }]
        );

        // 16 bytes → no warning.
        let mut input = manual_input("alice");
        input.secret = base32_secret(&[1u8; 16]);
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert!(v.warnings.is_empty());

        // 1024 bytes → accept.
        let mut input = manual_input("alice");
        input.secret = base32_secret(&[1u8; 1024]);
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert!(v.warnings.is_empty());

        // 1025 bytes → reject.
        let mut input = manual_input("alice");
        input.secret = base32_secret(&[1u8; 1025]);
        let err = validate_manual(input, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError {
                field,
                reason,
                decoded_len,
                ..
            } => {
                assert_eq!(field, "secret");
                assert_eq!(reason, "too_long");
                assert_eq!(decoded_len, Some(1025));
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn secret_lowercase_and_padding_accepted() {
        let raw = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &[0x42u8; 20]);
        let lower = raw.to_lowercase();
        // Both should decode the same way.
        let mut a = manual_input("alice");
        a.secret = SecretString::from(lower);
        let mut b = manual_input("alice");
        b.secret = SecretString::from(raw);
        let va = validate_manual(a, now_for_tests()).unwrap();
        let vb = validate_manual(b, now_for_tests()).unwrap();
        assert_eq!(
            va.account.secret().expose_secret(),
            vb.account.secret().expose_secret()
        );
    }

    #[test]
    fn secret_whitespace_rejected() {
        for bad in [" ABCDEFGH", "ABCDEFGH ", "AB CDEFGH", "AB\tCDEFGH"] {
            let mut input = manual_input("alice");
            input.secret = SecretString::from(bad.to_string());
            let err = validate_manual(input, now_for_tests()).unwrap_err();
            match err {
                PaladinError::ValidationError { field, reason, .. } => {
                    assert_eq!(field, "secret");
                    assert_eq!(reason, "whitespace");
                }
                other => panic!("expected ValidationError, got {other:?}"),
            }
        }
    }

    #[test]
    fn secret_decode_failure_returns_decode_failed() {
        let mut input = manual_input("alice");
        input.secret = SecretString::from("notbase32!".to_string());
        let err = validate_manual(input, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "secret");
                assert_eq!(reason, "decode_failed");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn icon_hint_default_derives_from_issuer() {
        let v = validate_manual(manual_input("alice"), now_for_tests()).unwrap();
        assert_eq!(v.account.icon_hint(), Some("acme"));
    }

    #[test]
    fn icon_hint_clear_overrides_default() {
        let mut input = manual_input("alice");
        input.icon_hint = IconHintInput::Clear;
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert_eq!(v.account.icon_hint(), None);
    }

    #[test]
    fn icon_hint_explicit_slug_validated() {
        let mut input = manual_input("alice");
        input.icon_hint = IconHintInput::Slug("custom-icon".into());
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert_eq!(v.account.icon_hint(), Some("custom-icon"));

        let mut input = manual_input("alice");
        input.icon_hint = IconHintInput::Slug("Bad Slug!".into());
        let err = validate_manual(input, now_for_tests()).unwrap_err();
        match err {
            PaladinError::ValidationError { field, .. } => {
                assert_eq!(field, "icon_hint");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn icon_hint_default_with_invalid_issuer_yields_none() {
        let mut input = manual_input("alice");
        input.issuer = Some("!!!".into());
        let v = validate_manual(input, now_for_tests()).unwrap();
        assert_eq!(v.account.icon_hint(), None);
    }

    #[test]
    fn timestamps_at_year_9999_boundary() {
        let just_in = UNIX_EPOCH + std::time::Duration::from_secs(TIMESTAMP_MAX_INCLUSIVE);
        let just_out = UNIX_EPOCH + std::time::Duration::from_secs(TIMESTAMP_MAX_INCLUSIVE + 1);
        let v = validate_manual(manual_input("a"), just_in).unwrap();
        assert_eq!(v.account.created_at(), TIMESTAMP_MAX_INCLUSIVE);

        let err = validate_manual(manual_input("a"), just_out).unwrap_err();
        assert!(matches!(
            err,
            PaladinError::TimeRange {
                operation: "validate_manual",
                kind: TimeRangeKind::OutOfRange
            }
        ));
    }
}

// Property tests asserting that the base32 secret decoder round-trips
// to the original bytes. Internal to the crate because the assertions
// inspect raw `Secret` bytes via the `pub(crate)` accessor; the
// projection boundary keeps secret bytes off the public API.
#[cfg(test)]
mod proptests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use proptest::prelude::*;
    use secrecy::SecretString;

    use super::{validate_manual, AccountInput};
    use crate::domain::{AccountKindInput, Algorithm, IconHintInput};

    fn import_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn account_input_from_secret(secret: SecretString) -> AccountInput {
        AccountInput {
            label: "alice".to_string(),
            issuer: None,
            secret,
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: AccountKindInput::Totp,
            period_secs: None,
            counter: None,
            icon_hint: IconHintInput::Default,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// `bytes → base32 encode → validate_manual → Secret` recovers the
        /// original bytes exactly. Length spans the §4.1 inclusive range
        /// `[SECRET_MIN_BYTES = 10, SECRET_MAX_BYTES = 1024]`. Catches a
        /// regression where the decoder silently rewrites bytes — the
        /// inline `parse → emit → re-parse` self-consistency check would
        /// not fail on such a bug.
        #[test]
        fn base32_secret_round_trips_to_original_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 10..=1024),
        ) {
            let encoded = base32::encode(
                base32::Alphabet::Rfc4648 { padding: false },
                &bytes,
            );
            let validated = validate_manual(
                account_input_from_secret(SecretString::from(encoded)),
                import_time(),
            )
            .expect("valid base32 of an in-range secret must decode");
            prop_assert_eq!(validated.account.secret().expose_secret(), bytes.as_slice());
        }

        /// RFC 4648 case-insensitivity: lowercase base32 decodes to the
        /// same bytes as the canonical uppercase form.
        #[test]
        fn base32_secret_round_trips_lowercase(
            bytes in proptest::collection::vec(any::<u8>(), 10..=64),
        ) {
            let encoded = base32::encode(
                base32::Alphabet::Rfc4648 { padding: false },
                &bytes,
            )
            .to_ascii_lowercase();
            let validated = validate_manual(
                account_input_from_secret(SecretString::from(encoded)),
                import_time(),
            )
            .expect("lowercase base32 must decode identically to uppercase");
            prop_assert_eq!(validated.account.secret().expose_secret(), bytes.as_slice());
        }

        /// RFC 4648 trailing `=` padding is tolerated: an arbitrary number
        /// of trailing `=` characters does not perturb the decoded bytes.
        #[test]
        fn base32_secret_round_trips_with_padding(
            bytes in proptest::collection::vec(any::<u8>(), 10..=64),
            pad_chars in 0usize..=8,
        ) {
            let mut encoded = base32::encode(
                base32::Alphabet::Rfc4648 { padding: false },
                &bytes,
            );
            for _ in 0..pad_chars {
                encoded.push('=');
            }
            let validated = validate_manual(
                account_input_from_secret(SecretString::from(encoded)),
                import_time(),
            )
            .expect("trailing '=' padding must not perturb decoding");
            prop_assert_eq!(validated.account.secret().expose_secret(), bytes.as_slice());
        }
    }
}
