// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Paladin core library.
//
// Public surface tracks DESIGN.md §4.7. Anything not re-exported here
// is `pub(crate)` and an implementation detail.

#![forbid(unsafe_code)]

pub mod domain;
pub mod error;
pub mod otp;
pub mod otpauth;
pub mod storage;

pub use domain::validation::AccountInput;
pub use domain::{
    parse_icon_hint_token, validate_manual, Account, AccountId, AccountKindInput,
    AccountKindSummary, AccountSummary, Algorithm, Code, IconHintInput, Secret, ValidatedAccount,
    ValidationWarning,
};
pub use error::{ErrorKind, PaladinError, PermissionSubject, Result, TimeRangeKind, VaultMode};
pub use otpauth::parse_otpauth;
pub use storage::{
    classify_init_precheck, default_vault_path, inspect, InitPrecheck, VaultSettings, VaultStatus,
};
