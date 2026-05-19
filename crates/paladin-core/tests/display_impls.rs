// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase K coverage — public-surface `Display` impls for the
// non-secret projection types front ends format into logs, error
// messages, and column rows.
//
// `Algorithm::as_str` is unit-tested next to the type, but the
// public surface advertises `Display` (via `#[derive(thiserror::Error)]`
// for `PaladinError`, list-rendering callers in the CLI, and the
// `format!("{alg}")` use sites). A regression that diverges `Display`
// from `as_str` (e.g. a hand-rolled `f.write_fmt` that lowercases or
// adds prefixes) would compile but silently change every downstream
// formatter. These tests pin the equivalence at the boundary.

use paladin_core::{parse_otpauth, Algorithm};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[test]
fn algorithm_display_matches_as_str_for_all_variants() {
    assert_eq!(format!("{}", Algorithm::Sha1), "SHA1");
    assert_eq!(format!("{}", Algorithm::Sha256), "SHA256");
    assert_eq!(format!("{}", Algorithm::Sha512), "SHA512");

    for alg in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
        assert_eq!(format!("{alg}"), alg.as_str());
    }
}

#[test]
fn account_id_display_renders_canonical_36_char_hyphenated_form() {
    // The on-the-wire identity for an account is the canonical
    // 36-character hyphenated UUIDv4 form. `Display` must produce
    // that exact shape (8-4-4-4-12) for CLI / TUI / GUI rendering.
    let acct = parse_otpauth(
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP",
        import_time(),
    )
    .unwrap()
    .account;
    let s = format!("{}", acct.id());
    assert_eq!(s.len(), 36);
    let parts: Vec<&str> = s.split('-').collect();
    assert_eq!(
        parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "expected 8-4-4-4-12 hyphenated UUID, got {s}",
    );
    assert!(
        s.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
        "Display must be lowercase hex digits + hyphens only, got {s}",
    );
    assert!(
        !s.chars().any(|c| c.is_ascii_uppercase()),
        "Display must be lowercase, got {s}",
    );
}

#[test]
fn account_id_display_round_trips_through_to_string() {
    // `AccountId: Display` is the form CLI/TUI/GUI logs and renders;
    // `to_string()` and direct `format!` must produce identical output.
    let acct = parse_otpauth(
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP",
        import_time(),
    )
    .unwrap()
    .account;
    let from_format = format!("{}", acct.id());
    let from_to_string = acct.id().to_string();
    assert_eq!(from_format, from_to_string);
}
