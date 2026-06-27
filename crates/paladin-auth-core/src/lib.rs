// SPDX-License-Identifier: AGPL-3.0-or-later

//! Paladin Auth core: domain types, OTP math, vault storage, crypto, and import/export.
//!
//! The public surface is locked to docs/DESIGN.md §4.7; anything not re-exported
//! here is `pub(crate)` and an implementation detail. See docs/DESIGN.md §3 for
//! the workspace layout and §4 for module-by-module behavior.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// §4.7 mandates these three submodule namespaces; everything else is
// reached through the `pub use` block below.
/// Vault export pipelines (otpauth list, encrypted Paladin Auth bundle). See docs/DESIGN.md §4.6.
pub mod export;
/// Vault import detection, parsers, and dispatch facade. See docs/DESIGN.md §4.6.
pub mod import;
/// Front-end UI policies (auto-lock, clipboard-clear, HOTP reveal). See docs/DESIGN.md §4.5.
pub mod policy;

mod crypto;
mod domain;
mod error;
mod otp;
mod otpauth;
mod storage;
mod text;
mod ui_contract;
mod vault;

pub use crypto::{Argon2Params, EncryptionOptions};

#[cfg(feature = "test-fault-injection")]
pub use crypto::argon2_derivation_count;

#[cfg(feature = "test-zeroize-witness")]
pub use crypto::zeroize_witness;
pub use domain::validation::{
    AccountInput, DIGITS_DEFAULT, DIGITS_MAX, DIGITS_MIN, TOTP_PERIOD_DEFAULT, TOTP_PERIOD_MAX,
    TOTP_PERIOD_MIN,
};
pub use domain::{
    account_match_key, account_matches_search, parse_account_query, parse_icon_hint_token,
    parse_setting_key, parse_setting_patch, select_after_filter, validate_account_edit,
    validate_icon_hint_slug, validate_label, validate_manual, Account, AccountEdit, AccountId,
    AccountKindInput, AccountKindSummary, AccountQuery, AccountSummary, Algorithm, Code,
    IconHintInput, ImportConflict, ImportReport, ImportWarning, Secret, SettingKey, SettingPatch,
    ValidatedAccount, ValidationWarning,
};
pub use error::{ErrorKind, PaladinAuthError, PermissionSubject, Result, TimeRangeKind, VaultMode};
pub use export::QrRenderOptions;
pub use import::{
    classify_paladin_auth_import_precheck, detect, ImportFormat, ImportOptions,
    PaladinAuthImportPrecheck,
};
pub use otpauth::parse_otpauth;
pub use policy::{hotp_reveal_deadline, ClipboardClearPolicy, ClipboardClearToken, IdlePolicy};
#[cfg(feature = "test-zeroize-witness")]
pub use storage::_testing_write_encrypted_with_raw_plaintext;
pub use storage::{
    classify_init_precheck, default_vault_path, destroy_vault, inspect, write_secret_file_atomic,
    DestroyReport, InitPrecheck, Store, VaultInit, VaultLock, VaultSettings, VaultStatus,
};
pub use text::{
    format_create_vault_dir_error, format_destroy_warning, format_init_force_warning,
    format_plaintext_export_warning, format_plaintext_qr_export_warning,
    format_plaintext_storage_warning, format_unsafe_permissions, format_validation_warning,
};
pub use ui_contract::{
    summary_display_label, AUTO_LOCK_SECS_MAX, AUTO_LOCK_SECS_MIN, CLIPBOARD_CLEAR_SECS_MAX,
    CLIPBOARD_CLEAR_SECS_MIN, HOTP_REVEAL_SECS, QR_MODULE_SIZE_PX_DEFAULT, QR_MODULE_SIZE_PX_MAX,
    QR_MODULE_SIZE_PX_MIN, QR_RGBA_MAX_BYTES, TICK_INTERVAL_MS,
};
pub use vault::Vault;
