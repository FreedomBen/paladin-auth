// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `ui_contract` constants locked by fixture (docs/DESIGN.md §6 / §7,
// docs/IMPLEMENTATION_PLAN_01_CORE.md Phase G.17).
//
// Pins the values shared by `paladin-tui` and `paladin-gtk` so a
// presentation crate cannot drift out of sync with the core. Each
// constant is referenced through the `paladin_core::` crate-root path
// to also pin its public re-export — a refactor that moves an
// internal module cannot silently drop the surface.

#[test]
fn hotp_reveal_secs_is_120() {
    assert_eq!(paladin_core::HOTP_REVEAL_SECS, 120);
}

#[test]
fn qr_rgba_max_bytes_is_64_mib() {
    assert_eq!(paladin_core::QR_RGBA_MAX_BYTES, 64 * 1024 * 1024);
}

#[test]
fn tick_interval_ms_is_250() {
    assert_eq!(paladin_core::TICK_INTERVAL_MS, 250);
}

#[test]
fn auto_lock_secs_min_is_30() {
    assert_eq!(paladin_core::AUTO_LOCK_SECS_MIN, 30);
}

#[test]
fn auto_lock_secs_max_is_86_400() {
    assert_eq!(paladin_core::AUTO_LOCK_SECS_MAX, 86_400);
}

#[test]
fn clipboard_clear_secs_min_is_5() {
    assert_eq!(paladin_core::CLIPBOARD_CLEAR_SECS_MIN, 5);
}

#[test]
fn clipboard_clear_secs_max_is_600() {
    assert_eq!(paladin_core::CLIPBOARD_CLEAR_SECS_MAX, 600);
}

// Pin the inferred types so a presentation crate that builds a
// `Duration::from_secs(AUTO_LOCK_SECS_MAX)` or a millisecond timer
// from `TICK_INTERVAL_MS` does not need to guess the integer width.
// Compile-time `const _: T = ...` forces the named integer width on
// each constant.
const _HOTP_REVEAL_SECS_IS_U64: u64 = paladin_core::HOTP_REVEAL_SECS;
const _QR_RGBA_MAX_BYTES_IS_USIZE: usize = paladin_core::QR_RGBA_MAX_BYTES;
const _TICK_INTERVAL_MS_IS_U64: u64 = paladin_core::TICK_INTERVAL_MS;
const _AUTO_LOCK_SECS_MIN_IS_U32: u32 = paladin_core::AUTO_LOCK_SECS_MIN;
const _AUTO_LOCK_SECS_MAX_IS_U32: u32 = paladin_core::AUTO_LOCK_SECS_MAX;
const _CLIPBOARD_CLEAR_SECS_MIN_IS_U32: u32 = paladin_core::CLIPBOARD_CLEAR_SECS_MIN;
const _CLIPBOARD_CLEAR_SECS_MAX_IS_U32: u32 = paladin_core::CLIPBOARD_CLEAR_SECS_MAX;
