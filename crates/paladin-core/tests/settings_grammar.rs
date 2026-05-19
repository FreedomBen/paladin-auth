// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.16 — `parse_setting_key`, `parse_setting_patch`, and
// `Vault::apply_setting_patch` (DESIGN.md §4.7, §5).
//
// `parse_setting_key` accepts exactly the four §5 dotted keys
// (`auto_lock.enabled`, `auto_lock.timeout_secs`,
// `clipboard.clear_enabled`, `clipboard.clear_secs`) and rejects
// unknown keys with `validation_error`.
//
// `parse_setting_patch` reuses the key parser; it accepts lowercase
// ASCII `"true"` / `"false"` for the two `*_enabled` keys and base-10
// `u32` for the two `*_secs` keys, and rejects malformed values plus
// values outside the §5 inclusive bounds.
//
// `Vault::apply_setting_patch` routes through the same typed setters
// as direct CLI / TUI / GUI calls so dotted patches and direct
// setters cannot diverge in bound checks. Most accept/reject parser
// matrix coverage lives next to the parser as crate-internal unit
// tests; this file pins the end-to-end Vault behavior.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;

use paladin_core::{
    parse_setting_key, parse_setting_patch, ErrorKind, SettingKey, SettingPatch, Store, Vault,
    VaultInit, AUTO_LOCK_SECS_MAX, AUTO_LOCK_SECS_MIN, CLIPBOARD_CLEAR_SECS_MAX,
    CLIPBOARD_CLEAR_SECS_MIN,
};
use tempfile::TempDir;

fn empty_plaintext_vault() -> Vault {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault
}

// Variant of `empty_plaintext_vault` that keeps the `TempDir` alive so
// the caller can read the on-disk primary bytes after `Vault::save`.
fn plaintext_vault_with_path() -> (Vault, Store, TempDir) {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    (vault, store, dir)
}

// ---------------------------------------------------------------------------
// parse_setting_key — pinned at the public surface so callers can
// import it from the crate root without reaching into modules.

#[test]
fn parse_setting_key_accepts_each_dotted_key_at_crate_root() {
    assert_eq!(
        parse_setting_key("auto_lock.enabled").unwrap(),
        SettingKey::AutoLockEnabled,
    );
    assert_eq!(
        parse_setting_key("auto_lock.timeout_secs").unwrap(),
        SettingKey::AutoLockTimeoutSecs,
    );
    assert_eq!(
        parse_setting_key("clipboard.clear_enabled").unwrap(),
        SettingKey::ClipboardClearEnabled,
    );
    assert_eq!(
        parse_setting_key("clipboard.clear_secs").unwrap(),
        SettingKey::ClipboardClearSecs,
    );
}

#[test]
fn parse_setting_key_rejects_unknown_dotted_key_with_field_key() {
    let err = parse_setting_key("auto_lock.idle_secs").expect_err("unknown");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let s = format!("{err}");
    assert!(s.contains("key"), "want field 'key' in {s}");
}

// ---------------------------------------------------------------------------
// parse_setting_patch — surface-level smoke test; per-value matrix
// coverage lives in `domain::settings` unit tests.

#[test]
fn parse_setting_patch_round_trips_each_key_at_crate_root() {
    assert_eq!(
        parse_setting_patch("auto_lock.enabled", "true").unwrap(),
        SettingPatch::AutoLockEnabled(true),
    );
    assert_eq!(
        parse_setting_patch("auto_lock.timeout_secs", "300").unwrap(),
        SettingPatch::AutoLockTimeoutSecs(300),
    );
    assert_eq!(
        parse_setting_patch("clipboard.clear_enabled", "false").unwrap(),
        SettingPatch::ClipboardClearEnabled(false),
    );
    assert_eq!(
        parse_setting_patch("clipboard.clear_secs", "20").unwrap(),
        SettingPatch::ClipboardClearSecs(20),
    );
}

// ---------------------------------------------------------------------------
// Vault::apply_setting_patch — routes through the typed setters.

#[test]
fn apply_setting_patch_sets_auto_lock_enabled() {
    let mut vault = empty_plaintext_vault();
    assert!(!vault.settings().auto_lock_enabled());

    vault
        .apply_setting_patch(SettingPatch::AutoLockEnabled(true))
        .unwrap();
    assert!(vault.settings().auto_lock_enabled());

    vault
        .apply_setting_patch(SettingPatch::AutoLockEnabled(false))
        .unwrap();
    assert!(!vault.settings().auto_lock_enabled());
}

#[test]
fn apply_setting_patch_sets_auto_lock_timeout_secs_within_bounds() {
    let mut vault = empty_plaintext_vault();

    for secs in [AUTO_LOCK_SECS_MIN, 600, AUTO_LOCK_SECS_MAX] {
        vault
            .apply_setting_patch(SettingPatch::AutoLockTimeoutSecs(secs))
            .unwrap();
        assert_eq!(vault.settings().auto_lock_timeout_secs(), secs);
    }
}

#[test]
fn apply_setting_patch_sets_clipboard_clear_enabled() {
    let mut vault = empty_plaintext_vault();
    assert!(!vault.settings().clipboard_clear_enabled());

    vault
        .apply_setting_patch(SettingPatch::ClipboardClearEnabled(true))
        .unwrap();
    assert!(vault.settings().clipboard_clear_enabled());
}

#[test]
fn apply_setting_patch_sets_clipboard_clear_secs_within_bounds() {
    let mut vault = empty_plaintext_vault();

    for secs in [CLIPBOARD_CLEAR_SECS_MIN, 60, CLIPBOARD_CLEAR_SECS_MAX] {
        vault
            .apply_setting_patch(SettingPatch::ClipboardClearSecs(secs))
            .unwrap();
        assert_eq!(vault.settings().clipboard_clear_secs(), secs);
    }
}

// The two timeout setters reject out-of-range values — same bounds
// that `parse_setting_patch` enforces at parse time. Constructing
// `SettingPatch::*Secs(out_of_range)` is only possible by callers
// that bypass the parser (e.g. TUI / GUI that build the patch
// directly); even there, `apply_setting_patch` must reject so the
// shared bound rule cannot be bypassed.

#[test]
fn apply_setting_patch_rejects_out_of_range_auto_lock_timeout() {
    let mut vault = empty_plaintext_vault();
    let prior = vault.settings().auto_lock_timeout_secs();

    let err = vault
        .apply_setting_patch(SettingPatch::AutoLockTimeoutSecs(AUTO_LOCK_SECS_MIN - 1))
        .expect_err("below minimum");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    assert!(format!("{err}").contains("auto_lock.timeout_secs"));

    let err = vault
        .apply_setting_patch(SettingPatch::AutoLockTimeoutSecs(AUTO_LOCK_SECS_MAX + 1))
        .expect_err("above maximum");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    assert!(format!("{err}").contains("auto_lock.timeout_secs"));

    // The prior value must be left unchanged across rejected patches.
    assert_eq!(vault.settings().auto_lock_timeout_secs(), prior);
}

#[test]
fn apply_setting_patch_rejects_out_of_range_clipboard_clear_secs() {
    let mut vault = empty_plaintext_vault();
    let prior = vault.settings().clipboard_clear_secs();

    let err = vault
        .apply_setting_patch(SettingPatch::ClipboardClearSecs(
            CLIPBOARD_CLEAR_SECS_MIN - 1,
        ))
        .expect_err("below minimum");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    assert!(format!("{err}").contains("clipboard.clear_secs"));

    let err = vault
        .apply_setting_patch(SettingPatch::ClipboardClearSecs(
            CLIPBOARD_CLEAR_SECS_MAX + 1,
        ))
        .expect_err("above maximum");
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    assert!(format!("{err}").contains("clipboard.clear_secs"));

    assert_eq!(vault.settings().clipboard_clear_secs(), prior);
}

#[test]
fn apply_setting_patch_matches_direct_setters_for_auto_lock_timeout() {
    // End-to-end "cannot diverge" check: a value accepted by the
    // direct setter must also be accepted by the equivalent patch,
    // and vice versa for rejected values.
    let mut a = empty_plaintext_vault();
    let mut b = empty_plaintext_vault();

    a.set_auto_lock_timeout_secs(AUTO_LOCK_SECS_MAX).unwrap();
    b.apply_setting_patch(SettingPatch::AutoLockTimeoutSecs(AUTO_LOCK_SECS_MAX))
        .unwrap();
    assert_eq!(
        a.settings().auto_lock_timeout_secs(),
        b.settings().auto_lock_timeout_secs(),
    );

    let direct_err = a.set_auto_lock_timeout_secs(AUTO_LOCK_SECS_MIN - 1);
    let patch_err =
        b.apply_setting_patch(SettingPatch::AutoLockTimeoutSecs(AUTO_LOCK_SECS_MIN - 1));
    assert!(direct_err.is_err() && patch_err.is_err());
    assert_eq!(direct_err.unwrap_err().kind(), ErrorKind::ValidationError);
    assert_eq!(patch_err.unwrap_err().kind(), ErrorKind::ValidationError);
}

#[test]
fn apply_setting_patch_matches_direct_setters_for_clipboard_clear_secs() {
    let mut a = empty_plaintext_vault();
    let mut b = empty_plaintext_vault();

    a.set_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MAX)
        .unwrap();
    b.apply_setting_patch(SettingPatch::ClipboardClearSecs(CLIPBOARD_CLEAR_SECS_MAX))
        .unwrap();
    assert_eq!(
        a.settings().clipboard_clear_secs(),
        b.settings().clipboard_clear_secs(),
    );

    let direct_err = a.set_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MIN - 1);
    let patch_err = b.apply_setting_patch(SettingPatch::ClipboardClearSecs(
        CLIPBOARD_CLEAR_SECS_MIN - 1,
    ));
    assert!(direct_err.is_err() && patch_err.is_err());
}

#[test]
fn parse_setting_patch_rejects_type_mismatched_values() {
    // §5 malformed-value contract for the dotted-key parser. Distinct
    // from the existing `_out_of_range_*` tests, which only exercise
    // in-range-shape numeric values that fall outside the §5 inclusive
    // bounds. This pins the current single-discriminating-reason shape
    // (`expected_u32` / `expected_bool`) that the parser collapses
    // every type-shape mismatch into.
    for key in ["auto_lock.timeout_secs", "clipboard.clear_secs"] {
        for value in ["", "abc", "300x", "-1", "30.0", "9999999999999999999999"] {
            let err = parse_setting_patch(key, value)
                .expect_err(&format!("expected reject {key}={value:?}"));
            assert_eq!(err.kind(), ErrorKind::ValidationError);
            let s = format!("{err}");
            assert!(s.contains(key), "want field {key:?} in {s}");
            assert!(
                s.contains("expected_u32"),
                "want reason 'expected_u32' for {key}={value:?}, got {s}",
            );
        }
    }

    for key in ["auto_lock.enabled", "clipboard.clear_enabled"] {
        for value in ["", "True", "TRUE", "yes", "1", "false ", "0"] {
            let err = parse_setting_patch(key, value)
                .expect_err(&format!("expected reject {key}={value:?}"));
            assert_eq!(err.kind(), ErrorKind::ValidationError);
            let s = format!("{err}");
            assert!(s.contains(key), "want field {key:?} in {s}");
            assert!(
                s.contains("expected_bool"),
                "want reason 'expected_bool' for {key}={value:?}, got {s}",
            );
        }
    }
}

#[test]
fn apply_setting_patch_repeat_same_value_writes_byte_identical_payload() {
    // §5 "same input → same output" determinism for the settings
    // setters. Plaintext vault so the on-disk bytes compare directly
    // without nonce/AEAD rotation. Catches a regression where
    // `VaultSettings` grows hidden state (e.g. a `last_patched_at`
    // timestamp) that breaks bincode determinism downstream.
    for patch in [
        SettingPatch::AutoLockTimeoutSecs(300),
        SettingPatch::AutoLockEnabled(true),
        SettingPatch::ClipboardClearEnabled(false),
        SettingPatch::ClipboardClearSecs(45),
    ] {
        let (mut vault, store, dir) = plaintext_vault_with_path();
        let path = dir.path().join("vault.bin");

        vault.apply_setting_patch(patch).unwrap();
        vault.save(&store).expect("first save");
        let bytes_a = std::fs::read(&path).unwrap();

        vault.apply_setting_patch(patch).unwrap();
        vault.save(&store).expect("second save");
        let bytes_b = std::fs::read(&path).unwrap();

        assert_eq!(
            bytes_a, bytes_b,
            "repeat apply of {patch:?} must produce byte-identical primary payloads",
        );
    }
}

#[test]
fn parsed_patch_applied_to_vault_round_trips_each_key() {
    // The parser → patch → apply pipeline lands the values the CLI
    // would set via `settings set <key> <value>`.
    let mut vault = empty_plaintext_vault();

    let patch = parse_setting_patch("auto_lock.enabled", "true").unwrap();
    vault.apply_setting_patch(patch).unwrap();
    assert!(vault.settings().auto_lock_enabled());

    let patch = parse_setting_patch("auto_lock.timeout_secs", "600").unwrap();
    vault.apply_setting_patch(patch).unwrap();
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 600);

    let patch = parse_setting_patch("clipboard.clear_enabled", "true").unwrap();
    vault.apply_setting_patch(patch).unwrap();
    assert!(vault.settings().clipboard_clear_enabled());

    let patch = parse_setting_patch("clipboard.clear_secs", "60").unwrap();
    vault.apply_setting_patch(patch).unwrap();
    assert_eq!(vault.settings().clipboard_clear_secs(), 60);
}
