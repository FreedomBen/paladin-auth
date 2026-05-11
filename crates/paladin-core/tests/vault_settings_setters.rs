// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G.4: `Vault::set_auto_lock_enabled`, `Vault::set_auto_lock_timeout_secs`,
// `Vault::set_clipboard_clear_enabled`, `Vault::set_clipboard_clear_secs`
// and the public timeout-bound constants from DESIGN.md §4.7.
// `apply_setting_patch` + `SettingPatch` parsing land in a later
// Phase G bullet alongside the dotted-key grammar.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;

use paladin_core::{
    PaladinError, Store, Vault, VaultInit, VaultSettings, AUTO_LOCK_SECS_MAX, AUTO_LOCK_SECS_MIN,
    CLIPBOARD_CLEAR_SECS_MAX, CLIPBOARD_CLEAR_SECS_MIN,
};

fn empty_plaintext_vault() -> Vault {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault
}

#[test]
fn vault_settings_defaults_match_design_section_5_table() {
    // Re-asserted here for completeness — `VaultSettings::default`
    // has its own unit test, but the DESIGN.md §5 settings table
    // pins these specific values for the cross-frontend behavior.
    let s = VaultSettings::default();
    assert!(!s.auto_lock_enabled());
    assert_eq!(s.auto_lock_timeout_secs(), 300);
    assert!(!s.clipboard_clear_enabled());
    assert_eq!(s.clipboard_clear_secs(), 20);
}

#[test]
fn timeout_bound_constants_match_design_section_4_7() {
    assert_eq!(AUTO_LOCK_SECS_MIN, 30);
    assert_eq!(AUTO_LOCK_SECS_MAX, 86_400);
    assert_eq!(CLIPBOARD_CLEAR_SECS_MIN, 5);
    assert_eq!(CLIPBOARD_CLEAR_SECS_MAX, 600);
}

// ---------- set_auto_lock_enabled ----------

#[test]
fn set_auto_lock_enabled_flips_the_flag() {
    let mut vault = empty_plaintext_vault();
    assert!(!vault.settings().auto_lock_enabled());
    vault.set_auto_lock_enabled(true);
    assert!(vault.settings().auto_lock_enabled());
    vault.set_auto_lock_enabled(false);
    assert!(!vault.settings().auto_lock_enabled());
}

#[test]
fn set_auto_lock_enabled_does_not_disturb_other_fields() {
    let mut vault = empty_plaintext_vault();
    vault.set_auto_lock_enabled(true);
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);
    assert!(!vault.settings().clipboard_clear_enabled());
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);
}

// ---------- set_auto_lock_timeout_secs ----------

#[test]
fn set_auto_lock_timeout_secs_accepts_lower_bound() {
    let mut vault = empty_plaintext_vault();
    vault
        .set_auto_lock_timeout_secs(AUTO_LOCK_SECS_MIN)
        .unwrap();
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 30);
}

#[test]
fn set_auto_lock_timeout_secs_accepts_upper_bound() {
    let mut vault = empty_plaintext_vault();
    vault
        .set_auto_lock_timeout_secs(AUTO_LOCK_SECS_MAX)
        .unwrap();
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 86_400);
}

#[test]
fn set_auto_lock_timeout_secs_accepts_default_300() {
    let mut vault = empty_plaintext_vault();
    vault.set_auto_lock_timeout_secs(300).unwrap();
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);
}

#[test]
fn set_auto_lock_timeout_secs_rejects_zero() {
    let mut vault = empty_plaintext_vault();
    let err = vault.set_auto_lock_timeout_secs(0).unwrap_err();
    match err {
        PaladinError::ValidationError { field, reason, .. } => {
            assert_eq!(field, "auto_lock.timeout_secs");
            assert_eq!(reason, "out_of_range");
        }
        other => panic!("expected validation_error, got {other:?}"),
    }
    // Prior value untouched.
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);
}

#[test]
fn set_auto_lock_timeout_secs_rejects_just_below_min() {
    let mut vault = empty_plaintext_vault();
    let err = vault
        .set_auto_lock_timeout_secs(AUTO_LOCK_SECS_MIN - 1)
        .unwrap_err();
    match err {
        PaladinError::ValidationError { field, .. } => {
            assert_eq!(field, "auto_lock.timeout_secs");
        }
        other => panic!("expected validation_error, got {other:?}"),
    }
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);
}

#[test]
fn set_auto_lock_timeout_secs_rejects_just_above_max() {
    let mut vault = empty_plaintext_vault();
    let err = vault
        .set_auto_lock_timeout_secs(AUTO_LOCK_SECS_MAX + 1)
        .unwrap_err();
    match err {
        PaladinError::ValidationError { field, .. } => {
            assert_eq!(field, "auto_lock.timeout_secs");
        }
        other => panic!("expected validation_error, got {other:?}"),
    }
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);
}

#[test]
fn set_auto_lock_timeout_secs_rejects_u32_max() {
    let mut vault = empty_plaintext_vault();
    assert!(vault.set_auto_lock_timeout_secs(u32::MAX).is_err());
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);
}

// ---------- set_clipboard_clear_enabled ----------

#[test]
fn set_clipboard_clear_enabled_flips_the_flag() {
    let mut vault = empty_plaintext_vault();
    assert!(!vault.settings().clipboard_clear_enabled());
    vault.set_clipboard_clear_enabled(true);
    assert!(vault.settings().clipboard_clear_enabled());
    vault.set_clipboard_clear_enabled(false);
    assert!(!vault.settings().clipboard_clear_enabled());
}

#[test]
fn set_clipboard_clear_enabled_does_not_disturb_other_fields() {
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_enabled(true);
    assert!(!vault.settings().auto_lock_enabled());
    assert_eq!(vault.settings().auto_lock_timeout_secs(), 300);
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);
}

// ---------- set_clipboard_clear_secs ----------

#[test]
fn set_clipboard_clear_secs_accepts_lower_bound() {
    let mut vault = empty_plaintext_vault();
    vault
        .set_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MIN)
        .unwrap();
    assert_eq!(vault.settings().clipboard_clear_secs(), 5);
}

#[test]
fn set_clipboard_clear_secs_accepts_upper_bound() {
    let mut vault = empty_plaintext_vault();
    vault
        .set_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MAX)
        .unwrap();
    assert_eq!(vault.settings().clipboard_clear_secs(), 600);
}

#[test]
fn set_clipboard_clear_secs_accepts_default_20() {
    let mut vault = empty_plaintext_vault();
    vault.set_clipboard_clear_secs(20).unwrap();
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);
}

#[test]
fn set_clipboard_clear_secs_rejects_zero() {
    let mut vault = empty_plaintext_vault();
    let err = vault.set_clipboard_clear_secs(0).unwrap_err();
    match err {
        PaladinError::ValidationError { field, reason, .. } => {
            assert_eq!(field, "clipboard.clear_secs");
            assert_eq!(reason, "out_of_range");
        }
        other => panic!("expected validation_error, got {other:?}"),
    }
    // Prior value untouched.
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);
}

#[test]
fn set_clipboard_clear_secs_rejects_just_below_min() {
    let mut vault = empty_plaintext_vault();
    let err = vault
        .set_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MIN - 1)
        .unwrap_err();
    match err {
        PaladinError::ValidationError { field, .. } => {
            assert_eq!(field, "clipboard.clear_secs");
        }
        other => panic!("expected validation_error, got {other:?}"),
    }
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);
}

#[test]
fn set_clipboard_clear_secs_rejects_just_above_max() {
    let mut vault = empty_plaintext_vault();
    let err = vault
        .set_clipboard_clear_secs(CLIPBOARD_CLEAR_SECS_MAX + 1)
        .unwrap_err();
    match err {
        PaladinError::ValidationError { field, .. } => {
            assert_eq!(field, "clipboard.clear_secs");
        }
        other => panic!("expected validation_error, got {other:?}"),
    }
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);
}

#[test]
fn set_clipboard_clear_secs_rejects_u32_max() {
    let mut vault = empty_plaintext_vault();
    assert!(vault.set_clipboard_clear_secs(u32::MAX).is_err());
    assert_eq!(vault.settings().clipboard_clear_secs(), 20);
}

// ---------- composition: setters compose, settings persist mutations ----------

#[test]
fn setters_compose_into_a_combined_settings_state() {
    let mut vault = empty_plaintext_vault();
    vault.set_auto_lock_enabled(true);
    vault.set_auto_lock_timeout_secs(60).unwrap();
    vault.set_clipboard_clear_enabled(true);
    vault.set_clipboard_clear_secs(10).unwrap();

    let s = vault.settings();
    assert!(s.auto_lock_enabled());
    assert_eq!(s.auto_lock_timeout_secs(), 60);
    assert!(s.clipboard_clear_enabled());
    assert_eq!(s.clipboard_clear_secs(), 10);
}
