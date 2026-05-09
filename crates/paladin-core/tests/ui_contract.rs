// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `ui_contract` constants locked by fixture (DESIGN.md §6 / §7,
// IMPLEMENTATION_PLAN_01_CORE.md Phase G.17).
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
#[test]
fn ui_contract_constant_types_are_stable() {
    let _hotp_reveal: u64 = paladin_core::HOTP_REVEAL_SECS;
    let _qr_rgba: usize = paladin_core::QR_RGBA_MAX_BYTES;
    let _tick: u64 = paladin_core::TICK_INTERVAL_MS;
    let _auto_min: u32 = paladin_core::AUTO_LOCK_SECS_MIN;
    let _auto_max: u32 = paladin_core::AUTO_LOCK_SECS_MAX;
    let _clip_min: u32 = paladin_core::CLIPBOARD_CLEAR_SECS_MIN;
    let _clip_max: u32 = paladin_core::CLIPBOARD_CLEAR_SECS_MAX;
}
