// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Icon-name slug rules (docs/DESIGN.md §4.1).
//
// The slug grammar is a strict subset of the freedesktop icon-naming
// spec: lowercase ASCII letters, digits, underscore, and hyphen, up to
// 64 bytes. `derive_default_from_issuer` is the canonical issuer →
// slug mapping used by manual add (with `IconHintInput::Default`),
// otpauth import, Aegis import, and QR import.

use crate::error::PaladinError;

use super::IconHintInput;

pub const ICON_HINT_MAX_BYTES: usize = 64;

/// Validate a user-supplied slug against the §4.1 grammar. Empty slugs
/// and slugs longer than 64 bytes are rejected with
/// `validation_error { field: "icon_hint" }`.
pub fn validate_slug(slug: &str) -> Result<String, PaladinError> {
    if slug.is_empty() {
        return Err(PaladinError::validation("icon_hint", "empty"));
    }
    if slug.len() > ICON_HINT_MAX_BYTES {
        return Err(PaladinError::validation("icon_hint", "too_long"));
    }
    if !slug.bytes().all(is_slug_byte) {
        return Err(PaladinError::validation("icon_hint", "invalid_chars"));
    }
    Ok(slug.to_owned())
}

/// Slug-only public wrapper around [`validate_slug`] for UI surfaces
/// that have already committed to the [`IconHintInput::Slug`] arm
/// (docs/DESIGN.md §4.7 / Phase M).
///
/// Runs the §4.1 `[a-z0-9_-]+` check verbatim and returns
/// `IconHintInput::Slug(slug.to_string())` on success. Failures are
/// the same typed `validation_error` ([`field`][`PaladinError::ValidationError::field`] =
/// `"icon_hint"`, reasons `"empty"` / `"too_long"` / `"invalid_chars"`)
/// that [`validate_slug`] emits and that
/// [`super::prompt_input::parse_icon_hint_token`] re-exports for its
/// slug-shape arm.
///
/// **No trim**: any whitespace in the input is rejected as
/// `invalid_chars`. Callers (TUI *Slug:* row, GTK slug input) are
/// responsible for trimming user input before calling — there is one
/// slug grammar in the crate, no caller-side / core-side normalization
/// split.
///
/// The literal slugs `"default"` and `"none"` round-trip as slugs
/// here: this entry point is for UI surfaces that have already
/// resolved the `IconHintInput::Default` / `Clear` tri-state through
/// dedicated affordances, so the textual `default` / `none` tokens
/// must not silently reroute. The free-form CLI `--icon-hint <token>`
/// flag and the CLI / GTK Add prompts continue to route through
/// [`super::prompt_input::parse_icon_hint_token`] unchanged.
pub fn validate_icon_hint_slug(slug: &str) -> Result<IconHintInput, PaladinError> {
    let validated = validate_slug(slug)?;
    Ok(IconHintInput::Slug(validated))
}

/// Derive a slug from an issuer string, returning `None` if the result
/// is empty or longer than the slug cap. This is the
/// `IconHintInput::Default` codepath; `validate_manual` calls it when
/// the caller did not supply an explicit slug or `Clear`.
#[must_use]
pub fn derive_default_from_issuer(issuer: Option<&str>) -> Option<String> {
    let raw = issuer?;
    let slug = slugify(raw);
    if slug.is_empty() || slug.len() > ICON_HINT_MAX_BYTES {
        None
    } else {
        Some(slug)
    }
}

fn slugify(input: &str) -> String {
    // Lowercase, then replace each run of disallowed characters with a
    // single `-`, then trim leading / trailing `-`.
    let lower: String = input.chars().flat_map(char::to_lowercase).collect();
    let mut out = String::with_capacity(lower.len());
    let mut last_was_dash = false;
    let mut started = false;
    for byte in lower.bytes() {
        if is_slug_byte(byte) && byte != b'-' {
            out.push(byte as char);
            last_was_dash = false;
            started = true;
        } else {
            // Run of disallowed (or hyphen) characters collapses to one
            // `-`. Leading hyphens are suppressed via `started`.
            if started && !last_was_dash {
                out.push('-');
                last_was_dash = true;
            }
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

const fn is_slug_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_slug_accepts_grammar() {
        assert!(validate_slug("github").is_ok());
        assert!(validate_slug("google-cloud").is_ok());
        assert!(validate_slug("aws_cli").is_ok());
        assert!(validate_slug("a1-b2_c3").is_ok());
    }

    #[test]
    fn validate_slug_rejects_empty() {
        let err = validate_slug("").unwrap_err();
        assert_eq!(err.kind(), crate::error::ErrorKind::ValidationError);
    }

    #[test]
    fn validate_slug_rejects_uppercase() {
        let err = validate_slug("GitHub").unwrap_err();
        match err {
            PaladinError::ValidationError { field, reason, .. } => {
                assert_eq!(field, "icon_hint");
                assert_eq!(reason, "invalid_chars");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn validate_slug_rejects_disallowed_chars() {
        for bad in ["github!", "gh.com", "with space", "tab\there"] {
            assert!(validate_slug(bad).is_err(), "expected reject: {bad}");
        }
    }

    #[test]
    fn validate_slug_boundary_64_accept_65_reject() {
        let exactly_64 = "a".repeat(64);
        assert!(validate_slug(&exactly_64).is_ok());
        let exactly_65 = "a".repeat(65);
        assert!(validate_slug(&exactly_65).is_err());
    }

    #[test]
    fn derive_default_from_issuer_examples() {
        assert_eq!(
            derive_default_from_issuer(Some("GitHub")).as_deref(),
            Some("github")
        );
        assert_eq!(
            derive_default_from_issuer(Some("Google Cloud")).as_deref(),
            Some("google-cloud")
        );
        assert_eq!(
            derive_default_from_issuer(Some("Acme, Inc.")).as_deref(),
            Some("acme-inc")
        );
        assert_eq!(derive_default_from_issuer(None), None);
    }

    #[test]
    fn derive_default_collapses_disallowed_runs() {
        assert_eq!(
            derive_default_from_issuer(Some("a   b   c")).as_deref(),
            Some("a-b-c")
        );
        assert_eq!(
            derive_default_from_issuer(Some("---x---")).as_deref(),
            Some("x")
        );
    }

    #[test]
    fn derive_default_returns_none_for_purely_invalid_issuer() {
        // Issuer slugifying to empty (e.g. "!!!") yields icon_hint = None.
        assert_eq!(derive_default_from_issuer(Some("!!!")), None);
        assert_eq!(derive_default_from_issuer(Some("///")), None);
    }

    #[test]
    fn derive_default_returns_none_when_overlong() {
        // 65-character all-letter issuer slugifies to >64 bytes → None.
        let long = "a".repeat(65);
        assert_eq!(derive_default_from_issuer(Some(&long)), None);
    }
}
