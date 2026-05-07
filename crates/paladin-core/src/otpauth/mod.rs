// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `otpauth://` URI parser and emitter (DESIGN.md §4.4).
//
// `parse_otpauth` is the single canonical entry point that turns an
// `otpauth://` URI into a `ValidatedAccount`. It re-uses the
// `domain::validation` helpers so the manual flag path, this parser,
// and the importers (Phase I) all reject identical bad input
// identically.
//
// `emit_otpauth` is the internal canonical emitter used by
// `export::otpauth_list` (Phase I). The emit + parse round-trip is
// pinned in tests so a regression in either side fails the build.

use std::time::SystemTime;

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use url::Url;

use crate::domain::validation::{
    decode_and_validate_secret, validate_digits, validate_issuer, validate_label,
    validate_totp_period, ParsedAccount, DIGITS_DEFAULT, TOTP_PERIOD_DEFAULT,
};
use crate::domain::{Account, Algorithm, IconHintInput, OtpKind, ValidatedAccount};
use crate::error::PaladinError;

/// Percent-encode set covering everything outside of the RFC 3986
/// "unreserved" set (`A-Za-z0-9 - _ . ~`). Used for both the path
/// (label and issuer-prefixed label) and query values; encoding the
/// gen-delims and sub-delims removes any chance of an emitted URI
/// being misparsed by a downstream authenticator.
const URI_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Known query-string parameters collected from an `otpauth://` URI.
/// Unknown keys are dropped at parse time per §4.4.
#[derive(Default)]
struct QueryParams {
    secret: Option<String>,
    issuer: Option<String>,
    algorithm: Option<String>,
    digits: Option<String>,
    period: Option<String>,
    counter: Option<String>,
}

/// Parse an `otpauth://` URI into a fully validated account. Bound to
/// `import_time` for `created_at` / `updated_at`; the URI itself does
/// not carry timestamps.
pub fn parse_otpauth(uri: &str, import_time: SystemTime) -> Result<ValidatedAccount, PaladinError> {
    let url = parse_scheme_and_url(uri)?;
    let is_hotp = parse_kind(&url)?;
    let (label_issuer_raw, label_account_raw) = parse_label_path(&url)?;
    let params = collect_query_params(&url)?;

    // Issuer reconciliation. Both `validate_issuer` calls trim and
    // enforce the 128-byte cap. The §4.4 rule requires byte-equality
    // after both have been normalized; case is preserved.
    let normalized_label_issuer = validate_issuer(label_issuer_raw.as_deref())?;
    let normalized_query_issuer = validate_issuer(params.issuer.as_deref())?;
    let issuer = match (normalized_label_issuer, normalized_query_issuer) {
        (Some(a), Some(b)) if a != b => {
            return Err(PaladinError::validation("issuer", "mismatch"));
        }
        (Some(a), _) | (None, Some(a)) => Some(a),
        (None, None) => None,
    };

    let label = validate_label(&label_account_raw)?;

    let secret_text = params
        .secret
        .ok_or_else(|| PaladinError::validation("secret", "missing"))?;
    let (secret, secret_warning) = decode_and_validate_secret(&secret_text)?;

    let algorithm = match params.algorithm.as_deref() {
        None => Algorithm::Sha1,
        Some(s) => parse_algorithm(s)?,
    };

    let digits = match params.digits.as_deref() {
        None => DIGITS_DEFAULT,
        Some(s) => s
            .parse::<u8>()
            .map_err(|_| PaladinError::validation("digits", "out_of_range"))?,
    };
    let digits = validate_digits(digits, DIGITS_DEFAULT)?;

    let kind = resolve_kind(is_hotp, params.period.as_deref(), params.counter.as_deref())?;

    // 12. Icon hint: derived from the resolved issuer; otpauth URIs
    //     do not carry an explicit icon hint.
    let icon_hint = IconHintInput::Default.resolve(issuer.as_deref())?;

    let parsed = ParsedAccount {
        label,
        issuer,
        secret,
        algorithm,
        digits,
        kind,
        icon_hint,
    };
    let warnings = secret_warning.into_iter().collect();
    parsed.into_validated(import_time, warnings)
}

/// Reject non-otpauth schemes *before* the URL parse so callers like
/// the `import::otpauth` line-list see a stable `validation_error` for
/// `https://`, `mailto:`, `paladin://`, etc., instead of opaque
/// url-crate parser errors.
fn parse_scheme_and_url(uri: &str) -> Result<Url, PaladinError> {
    let colon_idx = uri
        .find(':')
        .ok_or_else(|| PaladinError::validation("uri", "missing_scheme"))?;
    if !uri[..colon_idx].eq_ignore_ascii_case("otpauth") {
        return Err(PaladinError::validation("uri", "invalid_scheme"));
    }
    Url::parse(uri).map_err(|_| PaladinError::validation("uri", "malformed"))
}

/// Map the URL's host/authority to the OTP kind discriminator.
/// Returns `true` for HOTP, `false` for TOTP. Case-insensitive per §4.4.
fn parse_kind(url: &Url) -> Result<bool, PaladinError> {
    let host = url
        .host_str()
        .ok_or_else(|| PaladinError::validation("type", "missing"))?;
    match host.to_ascii_lowercase().as_str() {
        "totp" => Ok(false),
        "hotp" => Ok(true),
        _ => Err(PaladinError::validation("type", "invalid")),
    }
}

/// Percent-decode the path, reject empty/whitespace-only labels, and
/// split on the first `:` for the optional issuer prefix.
fn parse_label_path(url: &Url) -> Result<(Option<String>, String), PaladinError> {
    let raw_path = url.path();
    let path_inner = raw_path.strip_prefix('/').unwrap_or(raw_path);
    if path_inner.is_empty() {
        return Err(PaladinError::validation("label", "empty"));
    }
    let decoded_label = percent_decode_str(path_inner)
        .decode_utf8()
        .map_err(|_| PaladinError::validation("label", "invalid_utf8"))?
        .into_owned();
    if decoded_label.trim().is_empty() {
        return Err(PaladinError::validation("label", "empty"));
    }
    Ok(match decoded_label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.to_owned()), account.to_owned()),
        None => (None, decoded_label),
    })
}

/// Collect known query parameters; reject duplicates of any known key;
/// ignore unknown keys.
fn collect_query_params(url: &Url) -> Result<QueryParams, PaladinError> {
    let mut params = QueryParams::default();
    for (key, value) in url.query_pairs() {
        let lower = key.to_ascii_lowercase();
        let (slot, field): (&mut Option<String>, &'static str) = match lower.as_str() {
            "secret" => (&mut params.secret, "secret"),
            "issuer" => (&mut params.issuer, "issuer"),
            "algorithm" => (&mut params.algorithm, "algorithm"),
            "digits" => (&mut params.digits, "digits"),
            "period" => (&mut params.period, "period"),
            "counter" => (&mut params.counter, "counter"),
            _ => continue,
        };
        if slot.is_some() {
            return Err(PaladinError::validation(field, "duplicate"));
        }
        *slot = Some(value.into_owned());
    }
    Ok(params)
}

/// Apply the §4.4 kind-specific rules: HOTP requires `counter` and
/// rejects `period`; TOTP defaults `period` and rejects `counter`.
fn resolve_kind(
    is_hotp: bool,
    period_param: Option<&str>,
    counter_param: Option<&str>,
) -> Result<OtpKind, PaladinError> {
    if is_hotp {
        if period_param.is_some() {
            return Err(PaladinError::validation("period", "rejected_on_hotp"));
        }
        let counter_text =
            counter_param.ok_or_else(|| PaladinError::validation("counter", "missing"))?;
        let counter: u64 = counter_text
            .parse()
            .map_err(|_| PaladinError::validation("counter", "out_of_range"))?;
        Ok(OtpKind::Hotp { counter })
    } else {
        if counter_param.is_some() {
            return Err(PaladinError::validation("counter", "rejected_on_totp"));
        }
        let period = match period_param {
            None => TOTP_PERIOD_DEFAULT,
            Some(s) => s
                .parse::<u32>()
                .map_err(|_| PaladinError::validation("period", "out_of_range"))?,
        };
        let period = validate_totp_period(period)?;
        Ok(OtpKind::Totp { period })
    }
}

fn parse_algorithm(text: &str) -> Result<Algorithm, PaladinError> {
    match text.to_ascii_uppercase().as_str() {
        "SHA1" => Ok(Algorithm::Sha1),
        "SHA256" => Ok(Algorithm::Sha256),
        "SHA512" => Ok(Algorithm::Sha512),
        _ => Err(PaladinError::validation("algorithm", "invalid")),
    }
}

/// Emit the canonical `otpauth://` representation of an account.
///
/// Always includes `secret`, `issuer` (when present), `algorithm`, and
/// `digits`; adds `period` for TOTP and `counter` for HOTP. The
/// path label is `{issuer}:{label}` when an issuer is set, with both
/// halves percent-encoded. The output is round-trip-stable: parsing it
/// produces an account whose `(label, issuer, secret, algorithm,
/// digits, kind, icon_hint)` are all equal to the input's.
#[must_use]
#[allow(dead_code)] // Wired up by export::otpauth_list (Phase I).
pub(crate) fn emit_otpauth(account: &Account) -> String {
    use std::fmt::Write;
    let kind_token = match account.kind() {
        crate::domain::AccountKindSummary::Totp => "totp",
        crate::domain::AccountKindSummary::Hotp => "hotp",
    };
    let label_path = match account.issuer() {
        Some(issuer) => format!(
            "{}:{}",
            utf8_percent_encode(issuer, URI_ENCODE),
            utf8_percent_encode(account.label(), URI_ENCODE),
        ),
        None => utf8_percent_encode(account.label(), URI_ENCODE).to_string(),
    };

    let secret_b32 = base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        account.secret().expose_secret(),
    );

    let mut uri = format!("otpauth://{kind_token}/{label_path}?secret={secret_b32}");
    if let Some(issuer) = account.issuer() {
        let _ = write!(uri, "&issuer={}", utf8_percent_encode(issuer, URI_ENCODE));
    }
    let _ = write!(uri, "&algorithm={}", account.algorithm().as_str());
    let _ = write!(uri, "&digits={}", account.digits());
    match account.kind() {
        crate::domain::AccountKindSummary::Totp => {
            if let Some(period) = account.period() {
                let _ = write!(uri, "&period={period}");
            }
        }
        crate::domain::AccountKindSummary::Hotp => {
            if let Some(counter) = account.counter() {
                let _ = write!(uri, "&counter={counter}");
            }
        }
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    use crate::domain::AccountKindSummary;

    fn now_for_tests() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_778_414_400) // 2026-05-07T12:00:00Z
    }

    /// 20-byte all-`B` secret base32-encodes to a clean ASCII string.
    /// It is also `>= SHORT_SECRET_THRESHOLD_BYTES` so no warning fires.
    const SECRET_20_B32: &str = "IJBECQSCIJBECQSCIJBECQSCIJBECQSC"; // base32(b"BBBBBBBBBBBBBBBBBBBB")

    fn assert_validation(err: &PaladinError, want_field: &str, want_reason: &str) {
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(*field, want_field, "field");
                assert_eq!(reason, want_reason, "reason");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    // ---- 1. Scheme + type ----

    #[test]
    fn scheme_otpauth_lowercase_accepted() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.label(), "alice");
        assert_eq!(v.account.kind(), AccountKindSummary::Totp);
        assert_eq!(v.account.algorithm(), Algorithm::Sha1);
        assert_eq!(v.account.digits(), 6);
        assert_eq!(v.account.period(), Some(30));
    }

    #[test]
    fn scheme_otpauth_uppercase_accepted() {
        let uri = format!("OTPAUTH://TOTP/alice?secret={SECRET_20_B32}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.label(), "alice");
        assert_eq!(v.account.kind(), AccountKindSummary::Totp);
    }

    #[test]
    fn scheme_otpauth_mixed_case_accepted() {
        let uri = format!("OtPaUtH://hOtP/alice?secret={SECRET_20_B32}&counter=0");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.kind(), AccountKindSummary::Hotp);
        assert_eq!(v.account.counter(), Some(0));
    }

    #[test]
    fn rejects_non_otpauth_scheme_https() {
        let err = parse_otpauth("https://example.com/totp/alice?secret=ABC", now_for_tests())
            .unwrap_err();
        assert_validation(&err, "uri", "invalid_scheme");
    }

    #[test]
    fn rejects_non_otpauth_scheme_mailto() {
        let err = parse_otpauth("mailto:alice@example.com", now_for_tests()).unwrap_err();
        assert_validation(&err, "uri", "invalid_scheme");
    }

    #[test]
    fn rejects_non_otpauth_scheme_paladin() {
        let err = parse_otpauth("paladin://totp/alice", now_for_tests()).unwrap_err();
        assert_validation(&err, "uri", "invalid_scheme");
    }

    #[test]
    fn rejects_missing_scheme() {
        let err = parse_otpauth("totp/alice?secret=ABCD", now_for_tests()).unwrap_err();
        assert_validation(&err, "uri", "missing_scheme");
    }

    #[test]
    fn rejects_invalid_type() {
        let uri = format!("otpauth://nope/alice?secret={SECRET_20_B32}");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "type", "invalid");
    }

    // ---- 2. Label / issuer parsing ----

    #[test]
    fn percent_decoded_label() {
        // Label: "alice@example.com" with @ percent-encoded.
        let uri = format!("otpauth://totp/alice%40example.com?secret={SECRET_20_B32}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.label(), "alice@example.com");
    }

    #[test]
    fn label_required_non_empty_after_trim() {
        // Path is just "/" → empty label.
        let uri = format!("otpauth://totp/?secret={SECRET_20_B32}");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "label", "empty");
    }

    #[test]
    fn label_whitespace_only_is_empty() {
        let uri = format!("otpauth://totp/%20%20%20?secret={SECRET_20_B32}");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "label", "empty");
    }

    #[test]
    fn issuer_prefix_first_colon_split() {
        let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.issuer(), Some("Acme"));
        assert_eq!(v.account.label(), "alice");
    }

    #[test]
    fn issuer_prefix_only_first_colon_consumed() {
        // "Acme:alice:bob" → issuer "Acme", label "alice:bob".
        let uri = format!("otpauth://totp/Acme:alice:bob?secret={SECRET_20_B32}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.issuer(), Some("Acme"));
        assert_eq!(v.account.label(), "alice:bob");
    }

    #[test]
    fn issuer_query_only() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&issuer=Acme");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.issuer(), Some("Acme"));
        assert_eq!(v.account.label(), "alice");
    }

    #[test]
    fn issuer_prefix_and_query_match() {
        let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.issuer(), Some("Acme"));
        assert_eq!(v.account.label(), "alice");
    }

    #[test]
    fn issuer_prefix_and_query_mismatch_case_sensitive() {
        // Spec says byte-equal (case-sensitive) after normalization,
        // so "Acme" vs "acme" must reject.
        let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=acme");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "issuer", "mismatch");
    }

    #[test]
    fn issuer_prefix_and_query_mismatch_value() {
        let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Globex");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "issuer", "mismatch");
    }

    #[test]
    fn issuer_query_percent_decoded() {
        // "Big Corp" with the space encoded as %20.
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&issuer=Big%20Corp");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.issuer(), Some("Big Corp"));
    }

    #[test]
    fn empty_issuer_prefix_treated_as_none() {
        let uri = format!("otpauth://totp/:alice?secret={SECRET_20_B32}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.issuer(), None);
        assert_eq!(v.account.label(), "alice");
    }

    // ---- 3. Secret ----

    #[test]
    fn secret_required() {
        let err = parse_otpauth("otpauth://totp/alice", now_for_tests()).unwrap_err();
        assert_validation(&err, "secret", "missing");
    }

    #[test]
    fn secret_lowercase_accepted() {
        let lower = SECRET_20_B32.to_lowercase();
        let uri = format!("otpauth://totp/alice?secret={lower}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        // Round-trip via emit to confirm the bytes round-tripped.
        let emitted = emit_otpauth(&v.account);
        let v2 = parse_otpauth(&emitted, now_for_tests()).unwrap();
        assert_eq!(
            v.account.secret().expose_secret(),
            v2.account.secret().expose_secret()
        );
    }

    #[test]
    fn secret_padded_accepted() {
        // Re-encode with padding to confirm `=` is accepted.
        let padded = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &[0x42u8; 20]);
        // url-encode `=` so the URL parses cleanly.
        let padded_pct = padded.replace('=', "%3D");
        let uri = format!("otpauth://totp/alice?secret={padded_pct}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.secret().expose_secret(), &[0x42u8; 20][..]);
    }

    #[test]
    fn secret_internal_whitespace_rejected() {
        // Build the URI with a literal space in the secret value.
        let half = &SECRET_20_B32[..16];
        let other = &SECRET_20_B32[16..];
        let uri = format!("otpauth://totp/alice?secret={half}%20{other}");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "secret", "whitespace");
    }

    #[test]
    fn secret_invalid_base32_rejected() {
        let uri = "otpauth://totp/alice?secret=ZZZZ!";
        let err = parse_otpauth(uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "secret", "decode_failed");
    }

    // ---- 4. Algorithm / digits / period / counter ranges ----

    #[test]
    fn algorithm_default_sha1() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.algorithm(), Algorithm::Sha1);
    }

    #[test]
    fn algorithm_sha256_lowercase_accepted() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&algorithm=sha256");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.algorithm(), Algorithm::Sha256);
    }

    #[test]
    fn algorithm_invalid_rejected() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&algorithm=md5");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "algorithm", "invalid");
    }

    #[test]
    fn digits_in_range_accepted() {
        for d in [6u8, 7, 8] {
            let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&digits={d}");
            let v = parse_otpauth(&uri, now_for_tests()).unwrap();
            assert_eq!(v.account.digits(), d);
        }
    }

    #[test]
    fn digits_out_of_range_rejected() {
        for d in [0u8, 5, 9, 100] {
            let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&digits={d}");
            let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
            assert_validation(&err, "digits", "out_of_range");
        }
    }

    #[test]
    fn digits_non_integer_rejected() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&digits=abc");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "digits", "out_of_range");
    }

    #[test]
    fn period_default_30_for_totp() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.period(), Some(30));
    }

    #[test]
    fn period_custom_in_range() {
        for p in [1u32, 60, 300] {
            let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&period={p}");
            let v = parse_otpauth(&uri, now_for_tests()).unwrap();
            assert_eq!(v.account.period(), Some(p));
        }
    }

    #[test]
    fn period_out_of_range_rejected() {
        for p in [0u32, 301, 9999] {
            let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&period={p}");
            let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
            assert_validation(&err, "period", "out_of_range");
        }
    }

    #[test]
    fn period_rejected_on_hotp() {
        let uri = format!("otpauth://hotp/alice?secret={SECRET_20_B32}&counter=0&period=30");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "period", "rejected_on_hotp");
    }

    #[test]
    fn counter_required_on_hotp() {
        let uri = format!("otpauth://hotp/alice?secret={SECRET_20_B32}");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "counter", "missing");
    }

    #[test]
    fn counter_in_range_accepted() {
        for c in [0u64, 1, 1_000_000, u64::MAX] {
            let uri = format!("otpauth://hotp/alice?secret={SECRET_20_B32}&counter={c}");
            let v = parse_otpauth(&uri, now_for_tests()).unwrap();
            assert_eq!(v.account.counter(), Some(c));
        }
    }

    #[test]
    fn counter_overflow_u64_rejected() {
        // 2^64 = 18446744073709551616 — one past u64::MAX.
        let uri =
            format!("otpauth://hotp/alice?secret={SECRET_20_B32}&counter=18446744073709551616");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "counter", "out_of_range");
    }

    #[test]
    fn counter_negative_rejected() {
        let uri = format!("otpauth://hotp/alice?secret={SECRET_20_B32}&counter=-1");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "counter", "out_of_range");
    }

    #[test]
    fn counter_rejected_on_totp() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&counter=42");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "counter", "rejected_on_totp");
    }

    // ---- 5. Duplicate / unknown parameters ----

    #[test]
    fn duplicate_secret_rejected() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&secret={SECRET_20_B32}");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "secret", "duplicate");
    }

    #[test]
    fn duplicate_issuer_rejected() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&issuer=Acme&issuer=Acme");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "issuer", "duplicate");
    }

    #[test]
    fn duplicate_algorithm_rejected() {
        let uri =
            format!("otpauth://totp/alice?secret={SECRET_20_B32}&algorithm=SHA1&algorithm=SHA256");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "algorithm", "duplicate");
    }

    #[test]
    fn duplicate_digits_rejected() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&digits=6&digits=8");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "digits", "duplicate");
    }

    #[test]
    fn duplicate_period_rejected() {
        let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}&period=30&period=60");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "period", "duplicate");
    }

    #[test]
    fn duplicate_counter_rejected() {
        let uri = format!("otpauth://hotp/alice?secret={SECRET_20_B32}&counter=0&counter=1");
        let err = parse_otpauth(&uri, now_for_tests()).unwrap_err();
        assert_validation(&err, "counter", "duplicate");
    }

    #[test]
    fn unknown_param_image_ignored() {
        // Google Authenticator and others sometimes attach `image=...`.
        let uri = format!(
            "otpauth://totp/alice?secret={SECRET_20_B32}&image=https%3A%2F%2Fexample.com%2Fa.png"
        );
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.label(), "alice");
    }

    #[test]
    fn unknown_param_with_known_param_unaffected() {
        let uri =
            format!("otpauth://totp/alice?xxx=1&secret={SECRET_20_B32}&yyy=2&issuer=Acme&zzz=3");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.account.issuer(), Some("Acme"));
    }

    // ---- 6. Round-trip: parse → emit → parse ----

    fn assert_round_trip_normalized(uri: &str) {
        let a = parse_otpauth(uri, now_for_tests()).unwrap();
        let emitted = emit_otpauth(&a.account);
        let b = parse_otpauth(&emitted, now_for_tests()).unwrap();
        assert_eq!(a.account.label(), b.account.label(), "label");
        assert_eq!(a.account.issuer(), b.account.issuer(), "issuer");
        assert_eq!(
            a.account.secret().expose_secret(),
            b.account.secret().expose_secret(),
            "secret"
        );
        assert_eq!(a.account.algorithm(), b.account.algorithm(), "algorithm");
        assert_eq!(a.account.digits(), b.account.digits(), "digits");
        assert_eq!(a.account.kind(), b.account.kind(), "kind");
        assert_eq!(a.account.period(), b.account.period(), "period");
        assert_eq!(a.account.counter(), b.account.counter(), "counter");
        assert_eq!(a.account.icon_hint(), b.account.icon_hint(), "icon_hint");
    }

    #[test]
    fn round_trip_totp_no_issuer() {
        assert_round_trip_normalized(&format!("otpauth://totp/alice?secret={SECRET_20_B32}"));
    }

    #[test]
    fn round_trip_totp_with_issuer_prefix() {
        assert_round_trip_normalized(&format!(
            "otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme&algorithm=SHA256&digits=8&period=60"
        ));
    }

    #[test]
    fn round_trip_hotp_with_issuer() {
        assert_round_trip_normalized(&format!(
            "otpauth://hotp/Globex:bob%40example.com?secret={SECRET_20_B32}&issuer=Globex&counter=42&digits=7"
        ));
    }

    #[test]
    fn round_trip_label_with_special_chars() {
        // Label "alice@host:9000" — colons inside the account part are
        // preserved by the first-colon split rule.
        assert_round_trip_normalized(&format!(
            "otpauth://totp/Acme:alice%40host%3A9000?secret={SECRET_20_B32}&issuer=Acme"
        ));
    }

    #[test]
    fn round_trip_issuer_with_space() {
        assert_round_trip_normalized(&format!(
            "otpauth://totp/Big%20Corp:alice?secret={SECRET_20_B32}&issuer=Big%20Corp"
        ));
    }

    // ---- 7. Short-secret warning surfaces ----

    #[test]
    fn short_secret_warning_surfaces() {
        // 10-byte secret triggers the short-secret warning.
        let secret = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &[0x42u8; 10]);
        let uri = format!("otpauth://totp/alice?secret={secret}");
        let v = parse_otpauth(&uri, now_for_tests()).unwrap();
        assert_eq!(v.warnings.len(), 1);
    }
}

#[cfg(test)]
mod proptests {
    //! Property tests for the `otpauth://` parser/emitter (Phase D).
    //!
    //! Two complementary properties:
    //!
    //! 1. **Round-trip:** generated valid `(label, issuer, secret_len,
    //!    algorithm, digits, kind)` tuples emit to a URI that re-parses
    //!    to the same normalized account.
    //! 2. **No panics on garbage:** arbitrary bytes / strings handed to
    //!    `parse_otpauth` either succeed or return a `PaladinError`,
    //!    never panic. This guards against decoder regressions where a
    //!    malformed URL fragment slips past `Url::parse` and makes a
    //!    helper trip an `unwrap` or out-of-range slice.

    use super::*;
    use std::fmt::Write as _;
    use std::time::{Duration, UNIX_EPOCH};

    use proptest::prelude::*;

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_778_414_400)
    }

    /// Strategy for a label that won't trip empty/whitespace/length
    /// rules and contains no `:` (which would change the issuer-prefix
    /// semantics on round-trip).
    fn label_strategy() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof![
                Just(b'a'..=b'z').prop_flat_map(|r| r.prop_map(|c| c as char)),
                Just(b'A'..=b'Z').prop_flat_map(|r| r.prop_map(|c| c as char)),
                Just(b'0'..=b'9').prop_flat_map(|r| r.prop_map(|c| c as char)),
                Just('@'),
                Just('.'),
                Just('-'),
                Just('_'),
                Just(' '),
            ],
            1..=64,
        )
        // Avoid a trailing/leading space because validate_label trims
        // it; the round-trip target is a normalized form that already
        // had it trimmed.
        .prop_map(|chars| chars.into_iter().collect::<String>().trim().to_string())
        .prop_filter("non-empty after trim", |s| !s.is_empty())
    }

    /// Strategy for an issuer string. Same alphabet as label (no `:`).
    fn issuer_strategy() -> impl Strategy<Value = String> {
        label_strategy().prop_filter(
            "issuer slug derives non-empty",
            // Avoid issuers whose icon-hint slug derivation collapses
            // to empty (e.g. "  ", "..."). The icon hint is part of
            // the round-trip equality check; the parser re-derives it
            // from the issuer on the emit side, so as long as the
            // issuer is round-trip-stable so is the slug.
            |s| !s.is_empty(),
        )
    }

    fn algorithm_strategy() -> impl Strategy<Value = Algorithm> {
        prop_oneof![
            Just(Algorithm::Sha1),
            Just(Algorithm::Sha256),
            Just(Algorithm::Sha512),
        ]
    }

    /// Strategy for a secret of `>= SHORT_SECRET_THRESHOLD_BYTES` bytes,
    /// so the `ShortSecret` warning doesn't introduce non-determinism in
    /// the round-trip account.
    fn secret_bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 16..=64)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Round-trip property: emit → parse yields a structurally
        /// equal account on every input the manual validation pipeline
        /// would accept.
        #[test]
        fn round_trip_emits_then_parses_to_equal_account(
            label in label_strategy(),
            issuer in proptest::option::of(issuer_strategy()),
            secret in secret_bytes_strategy(),
            algorithm in algorithm_strategy(),
            digits in 6u8..=8,
            is_hotp in any::<bool>(),
            counter in any::<u64>(),
            period in 1u32..=300,
        ) {
            // Skip combos that would be rejected by validate_issuer's
            // length cap or label cap (post-trim already filtered).
            prop_assume!(label.len() <= 128);
            if let Some(i) = &issuer {
                prop_assume!(i.len() <= 128);
            }
            // URL path normalization (RFC 3986 / WHATWG) removes "."
            // and ".." segments, even when percent-encoded as "%2E" /
            // "%2E%2E". When `issuer` is None, the entire path segment
            // *is* the label, so labels of "." or ".." cannot survive
            // any URL round-trip. The `validate_label` rule itself
            // still accepts these strings; they just cannot appear as
            // a standalone path segment in an otpauth URI. Filter the
            // pathological combination here.
            prop_assume!(!(issuer.is_none() && matches!(label.as_str(), "." | "..")));

            // Build a URI by hand using the same encode path the
            // emitter does — but starting from raw bytes, not from a
            // pre-parsed Account. This way we don't depend on
            // ParsedAccount construction here.
            let secret_b32 =
                base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);
            let kind_token = if is_hotp { "hotp" } else { "totp" };
            let label_path = match &issuer {
                Some(iss) => format!(
                    "{}:{}",
                    utf8_percent_encode(iss, URI_ENCODE),
                    utf8_percent_encode(&label, URI_ENCODE),
                ),
                None => utf8_percent_encode(&label, URI_ENCODE).to_string(),
            };
            let mut uri = format!("otpauth://{kind_token}/{label_path}?secret={secret_b32}");
            if let Some(iss) = &issuer {
                let _ = write!(uri, "&issuer={}", utf8_percent_encode(iss, URI_ENCODE));
            }
            let _ = write!(uri, "&algorithm={}", algorithm.as_str());
            let _ = write!(uri, "&digits={digits}");
            if is_hotp {
                let _ = write!(uri, "&counter={counter}");
            } else {
                let _ = write!(uri, "&period={period}");
            }

            // Parse, emit, re-parse — and assert equality.
            let a = parse_otpauth(&uri, now()).unwrap();
            let emitted = emit_otpauth(&a.account);
            let b = parse_otpauth(&emitted, now()).unwrap();
            prop_assert_eq!(a.account.label(), b.account.label());
            prop_assert_eq!(a.account.issuer(), b.account.issuer());
            prop_assert_eq!(
                a.account.secret().expose_secret(),
                b.account.secret().expose_secret()
            );
            prop_assert_eq!(a.account.algorithm(), b.account.algorithm());
            prop_assert_eq!(a.account.digits(), b.account.digits());
            prop_assert_eq!(a.account.kind(), b.account.kind());
            prop_assert_eq!(a.account.period(), b.account.period());
            prop_assert_eq!(a.account.counter(), b.account.counter());
            prop_assert_eq!(a.account.icon_hint(), b.account.icon_hint());
        }

        /// No-panic property: every UTF-8 string input either parses
        /// successfully or returns a `PaladinError`. Catches a future
        /// regression where a panicking helper (e.g. an out-of-range
        /// index) escapes from a valid-looking URI.
        #[test]
        fn parse_never_panics_on_arbitrary_strings(s in ".{0,256}") {
            let _ = parse_otpauth(&s, now());
        }

        /// No-panic property over the otpauth scheme prefix, exercising
        /// the parser past the scheme gate.
        #[test]
        fn parse_never_panics_with_otpauth_prefix(rest in ".{0,256}") {
            let uri = format!("otpauth://{rest}");
            let _ = parse_otpauth(&uri, now());
        }

        /// No-panic property over `parse_otpauth`'s base32 decode path:
        /// random `secret=` query values must produce ok-or-error, not
        /// panic.
        #[test]
        fn parse_never_panics_on_arbitrary_secrets(s in "[A-Za-z0-9 =]{0,256}") {
            let uri = format!("otpauth://totp/alice?secret={s}");
            let _ = parse_otpauth(&uri, now());
        }
    }
}
