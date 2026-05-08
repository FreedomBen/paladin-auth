// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Paladin core library.
//
// Public surface tracks DESIGN.md §4.7. Anything not re-exported here
// is `pub(crate)` and an implementation detail.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod domain;
pub mod error;
pub mod otp;
pub mod otpauth;
pub mod storage;
pub mod text;
pub mod vault;

pub use crypto::{Argon2Params, EncryptionOptions};

#[cfg(feature = "test-fault-injection")]
pub use crypto::argon2_derivation_count;

#[cfg(feature = "test-zeroize-witness")]
pub use crypto::zeroize_witness;
#[cfg(feature = "test-zeroize-witness")]
pub use storage::_testing_write_encrypted_with_raw_plaintext;
pub use domain::validation::AccountInput;
pub use domain::{
    parse_icon_hint_token, validate_manual, Account, AccountId, AccountKindInput,
    AccountKindSummary, AccountSummary, Algorithm, Code, IconHintInput, Secret, ValidatedAccount,
    ValidationWarning,
};
pub use error::{ErrorKind, PaladinError, PermissionSubject, Result, TimeRangeKind, VaultMode};
pub use otpauth::parse_otpauth;
pub use storage::{
    classify_init_precheck, default_vault_path, inspect, write_secret_file_atomic, InitPrecheck,
    Store, VaultInit, VaultLock, VaultSettings, VaultStatus,
};
pub use text::{
    format_init_force_warning, format_plaintext_export_warning, format_plaintext_storage_warning,
    format_unsafe_permissions, format_validation_warning,
};
pub use vault::Vault;
