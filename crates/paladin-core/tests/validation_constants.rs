// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pins the publicly-re-exported §4.1 validation limits so a refactor
// that changes the numeric bounds — or quietly drops the
// `pub use domain::validation::{…}` re-export — fails CI. The
// validators themselves are exercised by `src/domain/validation.rs`
// inline tests; this file locks the constant *values* and their
// crate-root paths.

#[test]
fn digits_default_is_6() {
    assert_eq!(paladin_core::DIGITS_DEFAULT, 6);
}

#[test]
fn digits_min_is_6() {
    assert_eq!(paladin_core::DIGITS_MIN, 6);
}

#[test]
fn digits_max_is_8() {
    assert_eq!(paladin_core::DIGITS_MAX, 8);
}

#[test]
fn totp_period_default_is_30() {
    assert_eq!(paladin_core::TOTP_PERIOD_DEFAULT, 30);
}

#[test]
fn totp_period_min_is_1() {
    assert_eq!(paladin_core::TOTP_PERIOD_MIN, 1);
}

#[test]
fn totp_period_max_is_300() {
    assert_eq!(paladin_core::TOTP_PERIOD_MAX, 300);
}

// Pin the inferred integer widths so a presentation crate that
// stuffs `DIGITS_MAX` into a `u8` field, or `TOTP_PERIOD_MAX` into a
// `u32` `Duration::from_secs` argument, does not need to guess.
const _DIGITS_DEFAULT_IS_U8: u8 = paladin_core::DIGITS_DEFAULT;
const _DIGITS_MIN_IS_U8: u8 = paladin_core::DIGITS_MIN;
const _DIGITS_MAX_IS_U8: u8 = paladin_core::DIGITS_MAX;
const _TOTP_PERIOD_DEFAULT_IS_U32: u32 = paladin_core::TOTP_PERIOD_DEFAULT;
const _TOTP_PERIOD_MIN_IS_U32: u32 = paladin_core::TOTP_PERIOD_MIN;
const _TOTP_PERIOD_MAX_IS_U32: u32 = paladin_core::TOTP_PERIOD_MAX;
