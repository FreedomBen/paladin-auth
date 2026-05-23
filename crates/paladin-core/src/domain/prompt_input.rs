// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared icon-hint prompt grammar (docs/DESIGN.md §4.7 / Phase B).
//
// CLI add prompts and TUI / GUI add modals route their text input
// through this helper so all three front ends agree on the empty /
// `none` / slug grammar.

use crate::error::PaladinError;

use super::slug;
use super::IconHintInput;

/// Map a free-form prompt token to an `IconHintInput`:
///
/// * `""` (or any input that trims to empty under Unicode whitespace)
///   → `IconHintInput::Default`.
/// * `"none"` (case-insensitive after trim, including `" NONE\t"`,
///   `"None"`, etc.) → `IconHintInput::Clear`.
/// * any other token → `IconHintInput::Slug(slug)`, validated against
///   the §4.1 slug grammar. Malformed slugs return
///   `validation_error { field: "icon_hint" }`.
pub fn parse_icon_hint_token(token: &str) -> Result<IconHintInput, PaladinError> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Ok(IconHintInput::Default);
    }
    if trimmed.eq_ignore_ascii_case("none") {
        return Ok(IconHintInput::Clear);
    }
    let validated = slug::validate_slug(trimmed)?;
    Ok(IconHintInput::Slug(validated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_default() {
        for empty in ["", "   ", "\t", "\n  \t"] {
            assert!(matches!(
                parse_icon_hint_token(empty).unwrap(),
                IconHintInput::Default
            ));
        }
    }

    #[test]
    fn none_token_case_insensitive_returns_clear() {
        for none in ["none", "NONE", "None", " NONE\t", "  none  "] {
            assert!(matches!(
                parse_icon_hint_token(none).unwrap(),
                IconHintInput::Clear
            ));
        }
    }

    #[test]
    fn valid_slug_returns_slug_variant() {
        let result = parse_icon_hint_token("github").unwrap();
        match result {
            IconHintInput::Slug(s) => assert_eq!(s, "github"),
            other => panic!("expected Slug, got {other:?}"),
        }
    }

    #[test]
    fn slug_is_trimmed() {
        let result = parse_icon_hint_token("  github  ").unwrap();
        match result {
            IconHintInput::Slug(s) => assert_eq!(s, "github"),
            other => panic!("expected Slug, got {other:?}"),
        }
    }

    #[test]
    fn malformed_slug_rejected_with_icon_hint_field() {
        let err = parse_icon_hint_token("Bad Slug!").unwrap_err();
        match err {
            PaladinError::ValidationError { field, .. } => {
                assert_eq!(field, "icon_hint");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }
}
