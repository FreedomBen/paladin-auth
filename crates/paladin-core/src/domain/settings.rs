// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `domain::settings` — shared dotted settings grammar (docs/DESIGN.md §4.7,
// §5).
//
// Owns the stable §5 dotted key list, the lowercase ASCII bool /
// base-10 `u32` value grammar, and bound checks for the timeout keys.
// `Vault::apply_setting_patch` routes through the same typed setters
// so the CLI's dotted `settings set` and the TUI / GUI typed controls
// share one validation source.

use crate::error::{PaladinError, Result};
use crate::ui_contract::{
    AUTO_LOCK_SECS_MAX, AUTO_LOCK_SECS_MIN, CLIPBOARD_CLEAR_SECS_MAX, CLIPBOARD_CLEAR_SECS_MIN,
};

/// Stable §5 dotted key for the four `VaultSettings` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingKey {
    /// `auto_lock.enabled` (bool).
    AutoLockEnabled,
    /// `auto_lock.timeout_secs` (u32, `30..=86_400`).
    AutoLockTimeoutSecs,
    /// `clipboard.clear_enabled` (bool).
    ClipboardClearEnabled,
    /// `clipboard.clear_secs` (u32, `5..=600`).
    ClipboardClearSecs,
}

impl SettingKey {
    /// The §5 dotted key string.
    #[must_use]
    pub const fn dotted(self) -> &'static str {
        match self {
            Self::AutoLockEnabled => "auto_lock.enabled",
            Self::AutoLockTimeoutSecs => "auto_lock.timeout_secs",
            Self::ClipboardClearEnabled => "clipboard.clear_enabled",
            Self::ClipboardClearSecs => "clipboard.clear_secs",
        }
    }
}

/// Typed §5 settings patch produced by [`parse_setting_patch`] and
/// applied via [`crate::Vault::apply_setting_patch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingPatch {
    /// New value for `auto_lock.enabled`.
    AutoLockEnabled(bool),
    /// New value for `auto_lock.timeout_secs` (validated `30..=86_400`).
    AutoLockTimeoutSecs(u32),
    /// New value for `clipboard.clear_enabled`.
    ClipboardClearEnabled(bool),
    /// New value for `clipboard.clear_secs` (validated `5..=600`).
    ClipboardClearSecs(u32),
}

/// Parse a §5 dotted settings key without a value.
///
/// Accepts exactly the four §5 dotted keys (lowercase, no whitespace,
/// no aliases). Unknown keys return `validation_error` with
/// `field: "key"`.
pub fn parse_setting_key(key: &str) -> Result<SettingKey> {
    match key {
        "auto_lock.enabled" => Ok(SettingKey::AutoLockEnabled),
        "auto_lock.timeout_secs" => Ok(SettingKey::AutoLockTimeoutSecs),
        "clipboard.clear_enabled" => Ok(SettingKey::ClipboardClearEnabled),
        "clipboard.clear_secs" => Ok(SettingKey::ClipboardClearSecs),
        _ => Err(PaladinError::validation("key", "unknown_setting_key")),
    }
}

/// Parse a §5 dotted settings key/value pair into a typed
/// [`SettingPatch`].
///
/// Reuses [`parse_setting_key`] for the key portion, then parses the
/// value according to the key's typed shape:
///
/// * The two `*_enabled` keys accept exactly the lowercase ASCII
///   strings `"true"` and `"false"`. Any other casing (`"True"`,
///   `"TRUE"`), aliases (`"yes"`, `"1"`), or surrounding whitespace
///   are rejected.
/// * The two `*_secs` keys accept a base-10 `u32`. Empty strings,
///   leading whitespace, signs, non-digit characters, and values
///   outside `0..=u32::MAX` are rejected.
///
/// The `*_secs` keys additionally enforce the §5 inclusive bounds
/// (`auto_lock.timeout_secs ∈ 30..=86_400`,
/// `clipboard.clear_secs ∈ 5..=600`) so callers cannot patch the
/// timeout keys to out-of-range values. The same constants are used
/// by `Vault::set_auto_lock_timeout_secs` /
/// `Vault::set_clipboard_clear_secs`, so direct setters and dotted
/// patches share one bound table.
///
/// Errors are `validation_error`. The `field` is `"key"` for unknown
/// keys and the dotted key string itself for malformed or
/// out-of-range values.
pub fn parse_setting_patch(key: &str, value: &str) -> Result<SettingPatch> {
    let parsed_key = parse_setting_key(key)?;
    match parsed_key {
        SettingKey::AutoLockEnabled => Ok(SettingPatch::AutoLockEnabled(parse_bool(
            "auto_lock.enabled",
            value,
        )?)),
        SettingKey::ClipboardClearEnabled => Ok(SettingPatch::ClipboardClearEnabled(parse_bool(
            "clipboard.clear_enabled",
            value,
        )?)),
        SettingKey::AutoLockTimeoutSecs => {
            let secs = parse_u32("auto_lock.timeout_secs", value)?;
            if !(AUTO_LOCK_SECS_MIN..=AUTO_LOCK_SECS_MAX).contains(&secs) {
                return Err(PaladinError::validation(
                    "auto_lock.timeout_secs",
                    "out_of_range",
                ));
            }
            Ok(SettingPatch::AutoLockTimeoutSecs(secs))
        }
        SettingKey::ClipboardClearSecs => {
            let secs = parse_u32("clipboard.clear_secs", value)?;
            if !(CLIPBOARD_CLEAR_SECS_MIN..=CLIPBOARD_CLEAR_SECS_MAX).contains(&secs) {
                return Err(PaladinError::validation(
                    "clipboard.clear_secs",
                    "out_of_range",
                ));
            }
            Ok(SettingPatch::ClipboardClearSecs(secs))
        }
    }
}

fn parse_bool(field: &'static str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(PaladinError::validation(field, "expected_bool")),
    }
}

fn parse_u32(field: &'static str, value: &str) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PaladinError::validation(field, "expected_u32"));
    }
    value
        .parse::<u32>()
        .map_err(|_| PaladinError::validation(field, "expected_u32"))
}

#[cfg(test)]
mod tests {
    // Unit-level coverage for the dotted key/value grammar.
    // Integration tests (in `tests/settings_grammar.rs`) cover
    // `Vault::apply_setting_patch` end-to-end; these unit tests focus
    // on the parser's accept/reject matrix without constructing a
    // Vault.
    use super::*;
    use crate::error::ErrorKind;

    fn assert_validation(err: &PaladinError, field: &str) {
        assert_eq!(err.kind(), ErrorKind::ValidationError);
        let s = format!("{err}");
        assert!(s.contains(field), "want field {field:?} in {s}");
    }

    #[test]
    fn parse_setting_key_accepts_the_four_dotted_keys() {
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
    fn dotted_round_trips_each_setting_key() {
        for key in [
            SettingKey::AutoLockEnabled,
            SettingKey::AutoLockTimeoutSecs,
            SettingKey::ClipboardClearEnabled,
            SettingKey::ClipboardClearSecs,
        ] {
            assert_eq!(parse_setting_key(key.dotted()).unwrap(), key);
        }
    }

    #[test]
    fn parse_setting_key_rejects_unknown_keys() {
        for bad in [
            "",
            "auto_lock",
            "auto_lock.",
            "auto_lock.enabled.extra",
            "auto_lock.timeout",
            "AUTO_LOCK.ENABLED",
            "Auto_Lock.Enabled",
            "clipboard",
            "clipboard.clear",
            "clipboard_clear_enabled",
            " auto_lock.enabled",
            "auto_lock.enabled ",
            "auto_lock.enabled\n",
            "passphrase.required",
        ] {
            let err = parse_setting_key(bad).expect_err(bad);
            assert_validation(&err, "key");
        }
    }

    #[test]
    fn parse_setting_patch_accepts_lowercase_bools_for_enabled_keys() {
        assert_eq!(
            parse_setting_patch("auto_lock.enabled", "true").unwrap(),
            SettingPatch::AutoLockEnabled(true),
        );
        assert_eq!(
            parse_setting_patch("auto_lock.enabled", "false").unwrap(),
            SettingPatch::AutoLockEnabled(false),
        );
        assert_eq!(
            parse_setting_patch("clipboard.clear_enabled", "true").unwrap(),
            SettingPatch::ClipboardClearEnabled(true),
        );
        assert_eq!(
            parse_setting_patch("clipboard.clear_enabled", "false").unwrap(),
            SettingPatch::ClipboardClearEnabled(false),
        );
    }

    #[test]
    fn parse_setting_patch_rejects_non_lowercase_bool_values() {
        for bad in [
            "True", "TRUE", "False", "FALSE", "yes", "no", "1", "0", "t", "f", " true", "true ", "",
        ] {
            let err =
                parse_setting_patch("auto_lock.enabled", bad).expect_err(&format!("bool {bad:?}"));
            assert_validation(&err, "auto_lock.enabled");

            let err = parse_setting_patch("clipboard.clear_enabled", bad)
                .expect_err(&format!("bool {bad:?}"));
            assert_validation(&err, "clipboard.clear_enabled");
        }
    }

    #[test]
    fn parse_setting_patch_accepts_inrange_u32_values_for_secs_keys() {
        // auto_lock.timeout_secs: 30..=86_400
        for secs in [
            AUTO_LOCK_SECS_MIN,
            AUTO_LOCK_SECS_MIN + 1,
            300,
            AUTO_LOCK_SECS_MAX - 1,
            AUTO_LOCK_SECS_MAX,
        ] {
            let s = secs.to_string();
            assert_eq!(
                parse_setting_patch("auto_lock.timeout_secs", &s).unwrap(),
                SettingPatch::AutoLockTimeoutSecs(secs),
            );
        }
        // clipboard.clear_secs: 5..=600
        for secs in [
            CLIPBOARD_CLEAR_SECS_MIN,
            CLIPBOARD_CLEAR_SECS_MIN + 1,
            20,
            CLIPBOARD_CLEAR_SECS_MAX - 1,
            CLIPBOARD_CLEAR_SECS_MAX,
        ] {
            let s = secs.to_string();
            assert_eq!(
                parse_setting_patch("clipboard.clear_secs", &s).unwrap(),
                SettingPatch::ClipboardClearSecs(secs),
            );
        }
    }

    #[test]
    fn parse_setting_patch_rejects_below_minimum_u32_values() {
        let auto_lock_below = (AUTO_LOCK_SECS_MIN - 1).to_string();
        let err = parse_setting_patch("auto_lock.timeout_secs", &auto_lock_below).unwrap_err();
        assert_validation(&err, "auto_lock.timeout_secs");

        for s in ["0", "1", "29"] {
            let err = parse_setting_patch("auto_lock.timeout_secs", s).unwrap_err();
            assert_validation(&err, "auto_lock.timeout_secs");
        }

        for s in ["0", "1", "4"] {
            let err = parse_setting_patch("clipboard.clear_secs", s).unwrap_err();
            assert_validation(&err, "clipboard.clear_secs");
        }
    }

    #[test]
    fn parse_setting_patch_rejects_above_maximum_u32_values() {
        let auto_lock_above = (AUTO_LOCK_SECS_MAX + 1).to_string();
        let err = parse_setting_patch("auto_lock.timeout_secs", &auto_lock_above).unwrap_err();
        assert_validation(&err, "auto_lock.timeout_secs");

        let clipboard_above = (CLIPBOARD_CLEAR_SECS_MAX + 1).to_string();
        let err = parse_setting_patch("clipboard.clear_secs", &clipboard_above).unwrap_err();
        assert_validation(&err, "clipboard.clear_secs");
    }

    #[test]
    fn parse_setting_patch_rejects_malformed_u32_values() {
        for bad in [
            "",
            " 60",
            "60 ",
            "60s",
            "+60",
            "-60",
            "60.0",
            "0x3c",
            "abc",
            "1_000",
            "4294967296", // u32::MAX + 1
            "9999999999999",
        ] {
            let err = parse_setting_patch("auto_lock.timeout_secs", bad)
                .expect_err(&format!("u32 {bad:?}"));
            assert_validation(&err, "auto_lock.timeout_secs");
        }
    }

    #[test]
    fn parse_setting_patch_unknown_key_uses_key_field() {
        // Even with a syntactically valid value, the unknown-key error
        // surfaces from `parse_setting_key` first.
        let err = parse_setting_patch("auto_lock.unknown", "true").unwrap_err();
        assert_validation(&err, "key");
    }
}
