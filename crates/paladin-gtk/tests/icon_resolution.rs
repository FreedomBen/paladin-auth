// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic icon-resolution tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/icon_resolution.rs`"
//! checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * `None` / empty slug routes to the placeholder icon without
//!   invoking `gtk::IconTheme` (the actual lookup is exercised by the
//!   smoke test).
//! * Failed `gtk::IconTheme` lookup falls back to the placeholder
//!   icon.
//! * Icon-hint token parsing through
//!   `paladin_core::parse_icon_hint_token` (slug / `default` / `none`)
//!   matches the CLI / TUI add-modal behavior.

use paladin_gtk::icon_resolution::{resolve_display_icon, PLACEHOLDER_ICON_NAME};

// --- None / empty / whitespace cases must not invoke has_icon ---------------

#[test]
fn none_hint_returns_placeholder_without_calling_has_icon() {
    let result = resolve_display_icon(None, |_| {
        panic!("gtk::IconTheme must not be consulted for `None` hint")
    });
    assert_eq!(result, PLACEHOLDER_ICON_NAME);
}

#[test]
fn empty_hint_returns_placeholder_without_calling_has_icon() {
    let result = resolve_display_icon(Some(""), |_| {
        panic!("gtk::IconTheme must not be consulted for an empty hint")
    });
    assert_eq!(result, PLACEHOLDER_ICON_NAME);
}

#[test]
fn whitespace_only_hint_returns_placeholder_without_calling_has_icon() {
    let result = resolve_display_icon(Some("   "), |_| {
        panic!("gtk::IconTheme must not be consulted for a whitespace-only hint")
    });
    assert_eq!(result, PLACEHOLDER_ICON_NAME);
}

// --- Successful / failed gtk::IconTheme lookups -----------------------------

#[test]
fn successful_lookup_returns_the_supplied_slug() {
    let result = resolve_display_icon(Some("github-com"), |_| true);
    assert_eq!(result, "github-com");
}

#[test]
fn failed_lookup_falls_back_to_placeholder() {
    let result = resolve_display_icon(Some("github-com"), |_| false);
    assert_eq!(result, PLACEHOLDER_ICON_NAME);
}

#[test]
fn has_icon_closure_receives_the_supplied_slug() {
    // Captures the argument so we can assert the slug reaches the
    // gtk::IconTheme membership probe verbatim (no trimming, no
    // case-folding, no derivation).
    let mut received = String::new();
    let result = resolve_display_icon(Some("gitlab-com"), |slug| {
        received.push_str(slug);
        true
    });
    assert_eq!(result, "gitlab-com");
    assert_eq!(received, "gitlab-com");
}

// --- parse_icon_hint_token contract (used by the add-modal path) ------------

#[test]
fn add_modal_icon_hint_input_uses_paladin_core_parse_icon_hint_token() {
    // Documents the contract the GTK add modal will follow when
    // it lands: icon-hint text-field input routes through
    // `paladin_core::parse_icon_hint_token` so the slug /
    // default-for-empty / none-for-clear categories parse identically
    // across CLI, TUI, and GUI.
    use paladin_core::{parse_icon_hint_token, IconHintInput};

    // Empty / whitespace → Default (issuer-derived).
    assert!(matches!(
        parse_icon_hint_token("").unwrap(),
        IconHintInput::Default
    ));
    assert!(matches!(
        parse_icon_hint_token("   ").unwrap(),
        IconHintInput::Default
    ));

    // Case-insensitive "none" → Clear (force-store None).
    assert!(matches!(
        parse_icon_hint_token("none").unwrap(),
        IconHintInput::Clear
    ));
    assert!(matches!(
        parse_icon_hint_token("NONE").unwrap(),
        IconHintInput::Clear
    ));
    assert!(matches!(
        parse_icon_hint_token("None").unwrap(),
        IconHintInput::Clear
    ));

    // Validated slugs round-trip verbatim.
    let parsed = parse_icon_hint_token("github-com").unwrap();
    assert!(matches!(&parsed, IconHintInput::Slug(s) if s == "github-com"));

    // Malformed slugs surface a `paladin_core::PaladinError` rather
    // than being silently coerced.
    assert!(parse_icon_hint_token("not a slug!").is_err());
}
