// SPDX-License-Identifier: AGPL-3.0-or-later
//
// In-memory `Vault` (DESIGN.md §4.7).
//
// Phase E ships the minimum needed for the plaintext save/open
// round-trip: a `Vault` holds an ordered `Vec<Account>` plus
// `VaultSettings`, exposes read-only views, and routes saves through
// the matching `Store`. Account-level mutation helpers
// (find_duplicate, rename, hotp_advance, totp_code, mutate_and_save,
// import_accounts) and passphrase transitions land in Phase G / H.

use std::fmt;

use crate::domain::Account;
use crate::error::Result;
use crate::storage::payload::VaultPayload;
use crate::storage::{Store, VaultSettings};

/// Top-level in-memory representation of a Paladin vault.
///
/// Construct via [`Store::open`] or [`Store::create`]; persist via
/// [`Vault::save`]. Accounts are kept in insertion order — iteration
/// via [`Vault::accounts`] is stable across saves and reopens
/// (DESIGN.md §4.3 wire-format guarantee on the bincode `Vec<Account>`).
pub struct Vault {
    accounts: Vec<Account>,
    settings: VaultSettings,
}

impl Vault {
    /// Empty vault used by `Store::create`.
    pub(crate) fn empty() -> Self {
        Self {
            accounts: Vec::new(),
            settings: VaultSettings::default(),
        }
    }

    /// Build a `Vault` from a decoded payload. Used by `Store::open`.
    pub(crate) fn from_payload(payload: VaultPayload) -> Self {
        Self {
            accounts: payload.accounts,
            settings: payload.settings,
        }
    }

    /// Snapshot the current state into a fresh `VaultPayload` so the
    /// `Store` can encode and write it. Phase E clones the account
    /// list because save is not on a hot path; Phase G may revisit
    /// this if `mutate_and_save`'s rollback machinery shares the same
    /// snapshot.
    pub(crate) fn snapshot_payload(&self) -> VaultPayload {
        VaultPayload {
            accounts: self.accounts.clone(),
            settings: self.settings,
        }
    }

    /// Borrow the stored accounts in insertion order.
    #[must_use]
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Borrow the live `VaultSettings`.
    #[must_use]
    pub fn settings(&self) -> &VaultSettings {
        &self.settings
    }

    /// Append an account.
    ///
    /// Phase E ships only the API needed by the storage round-trip.
    /// Phase G layers `(secret, issuer, label)` collision detection,
    /// `find_duplicate`, and the import merge-policy hooks on top of
    /// the same underlying `Vec<Account>`.
    pub fn add(&mut self, account: Account) {
        self.accounts.push(account);
    }

    /// Persist the vault through the supplied `Store`.
    ///
    /// Implements the §4.3 atomic write pipeline. Pre-commit failures
    /// (steps 1–3) surface as `save_not_committed`; a parent-fsync
    /// failure post-commit (step 5) surfaces as
    /// `save_durability_unconfirmed`.
    pub fn save(&self, store: &Store) -> Result<()> {
        store.save_payload(&self.snapshot_payload())
    }
}

// `Vault` holds `Account`s, which carry `Secret` bytes. Manual
// `Debug` redacts the account list to a count so a stray
// `dbg!(&vault)` cannot leak secret bytes; the §4.7 audit covers
// this surface.
impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("accounts", &self.accounts.len())
            .field("settings", &self.settings)
            .finish()
    }
}
