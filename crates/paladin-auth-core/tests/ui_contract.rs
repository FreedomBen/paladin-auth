// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `ui_contract` constants locked by fixture (docs/DESIGN.md §6 / §7,
// docs/IMPLEMENTATION_PLAN_01_CORE.md Phase G.17).
//
// Pins the values shared by `paladin-auth-tui` and `paladin-auth-gtk` so a
// presentation crate cannot drift out of sync with the core. Each
// constant is referenced through the `paladin_auth_core::` crate-root path
// to also pin its public re-export — a refactor that moves an
// internal module cannot silently drop the surface.

#[test]
fn hotp_reveal_secs_is_120() {
    assert_eq!(paladin_auth_core::HOTP_REVEAL_SECS, 120);
}

#[test]
fn qr_rgba_max_bytes_is_64_mib() {
    assert_eq!(paladin_auth_core::QR_RGBA_MAX_BYTES, 64 * 1024 * 1024);
}

#[test]
fn tick_interval_ms_is_250() {
    assert_eq!(paladin_auth_core::TICK_INTERVAL_MS, 250);
}

#[test]
fn auto_lock_secs_min_is_30() {
    assert_eq!(paladin_auth_core::AUTO_LOCK_SECS_MIN, 30);
}

#[test]
fn auto_lock_secs_max_is_86_400() {
    assert_eq!(paladin_auth_core::AUTO_LOCK_SECS_MAX, 86_400);
}

#[test]
fn clipboard_clear_secs_min_is_5() {
    assert_eq!(paladin_auth_core::CLIPBOARD_CLEAR_SECS_MIN, 5);
}

#[test]
fn clipboard_clear_secs_max_is_600() {
    assert_eq!(paladin_auth_core::CLIPBOARD_CLEAR_SECS_MAX, 600);
}

// Pin the inferred types so a presentation crate that builds a
// `Duration::from_secs(AUTO_LOCK_SECS_MAX)` or a millisecond timer
// from `TICK_INTERVAL_MS` does not need to guess the integer width.
// Compile-time `const _: T = ...` forces the named integer width on
// each constant.
const _HOTP_REVEAL_SECS_IS_U64: u64 = paladin_auth_core::HOTP_REVEAL_SECS;
const _QR_RGBA_MAX_BYTES_IS_USIZE: usize = paladin_auth_core::QR_RGBA_MAX_BYTES;
const _TICK_INTERVAL_MS_IS_U64: u64 = paladin_auth_core::TICK_INTERVAL_MS;
const _AUTO_LOCK_SECS_MIN_IS_U32: u32 = paladin_auth_core::AUTO_LOCK_SECS_MIN;
const _AUTO_LOCK_SECS_MAX_IS_U32: u32 = paladin_auth_core::AUTO_LOCK_SECS_MAX;
const _CLIPBOARD_CLEAR_SECS_MIN_IS_U32: u32 = paladin_auth_core::CLIPBOARD_CLEAR_SECS_MIN;
const _CLIPBOARD_CLEAR_SECS_MAX_IS_U32: u32 = paladin_auth_core::CLIPBOARD_CLEAR_SECS_MAX;
const _QR_MODULE_SIZE_PX_MIN_IS_U32: u32 = paladin_auth_core::QR_MODULE_SIZE_PX_MIN;
const _QR_MODULE_SIZE_PX_MAX_IS_U32: u32 = paladin_auth_core::QR_MODULE_SIZE_PX_MAX;
const _QR_MODULE_SIZE_PX_DEFAULT_IS_U32: u32 = paladin_auth_core::QR_MODULE_SIZE_PX_DEFAULT;

// ---------- summary_display_label (Phase L) ----------
//
// Front-end caption helper shared by the CLI status text, the TUI
// QR / rename / remove modals, and the GTK `ExportQrDialog` /
// `RenameDialog` / `RemoveDialog` subtitles (docs/DESIGN.md §4.6 /
// §7). Building the fixture summaries through `parse_otpauth` keeps
// the test pinned to the same `AccountSummary::issuer` / `label`
// shape the production code observes — not a hand-rolled struct
// literal that could mask a field rename.

use std::time::{Duration, UNIX_EPOCH};

use paladin_auth_core::{parse_otpauth, summary_display_label, AccountSummary};

fn summary_for(uri: &str) -> AccountSummary {
    parse_otpauth(uri, UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        .expect("fixture URI parses")
        .account
        .summary()
}

#[test]
fn summary_display_label_renders_issuer_colon_label() {
    let summary = summary_for("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme");
    assert_eq!(summary_display_label(&summary), "Acme:alice");
}

#[test]
fn summary_display_label_with_empty_issuer_collapses_to_bare_label() {
    // No `issuer` query parameter and an unprefixed label → the parser
    // leaves `issuer: None`, which must collapse to the bare label
    // rather than rendering a stray leading colon.
    let summary = summary_for("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP");
    assert_eq!(summary.issuer, None);
    assert_eq!(summary_display_label(&summary), "alice");
}

#[test]
fn summary_display_label_with_whitespace_only_issuer_collapses_to_bare_label() {
    // The validation layer rejects whitespace-only issuer values from
    // user input, so build the summary directly to pin the
    // whitespace-only branch of the helper: any future relaxation that
    // surfaces `Some("   ")` from a third-party importer must still
    // collapse to the bare label.
    let base = summary_for("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP");
    let summary = AccountSummary {
        issuer: Some("   ".to_string()),
        ..base
    };
    assert_eq!(summary_display_label(&summary), "alice");
}
