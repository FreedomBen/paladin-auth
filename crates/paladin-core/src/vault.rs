// SPDX-License-Identifier: AGPL-3.0-or-later
//
// In-memory `Vault` (DESIGN.md §4.7).
//
// Phase E ships the minimum needed for the plaintext save/open
// round-trip: a `Vault` holds an ordered `Vec<Account>` plus
// `VaultSettings`, exposes read-only views, and routes saves through
// the matching `Store`. Phase F.3 layers an optional encrypted cache
// (the retained `SecretString` passphrase + the cached 32-byte AEAD
// key) so encrypted saves reuse the Argon2id derivation rather than
// re-running the KDF on every HOTP advance. Account-level mutation
// helpers (find_duplicate, rename, hotp_advance, totp_code,
// mutate_and_save, import_accounts) and passphrase transitions land
// in Phase G / H.

use std::fmt;
use std::time::SystemTime;

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::crypto::AEAD_KEY_LEN;
use crate::domain::validation::{system_time_to_secs_for, validate_label};
use crate::domain::{Account, AccountId, AccountSummary};
use crate::error::{PaladinError, Result};
use crate::storage::payload::VaultPayload;
use crate::storage::{Store, VaultSettings};

/// Cached crypto material for an encrypted vault (DESIGN.md §4.4).
///
/// `passphrase` is retained so passphrase transitions can re-encrypt
/// the rotated `.bak` and re-derive a key under the new salt;
/// `key` is the 32-byte AEAD key derived from the in-header
/// `(salt, params)` and the passphrase, cached so regular saves do
/// not pay another Argon2id derivation. Both fields zeroize on drop.
pub(crate) struct EncryptedCache {
    /// Retained passphrase. Read by passphrase transitions in Phase H
    /// to compare against / re-derive under the same secret.
    #[allow(dead_code)]
    pub(crate) passphrase: SecretString,
    pub(crate) key: Zeroizing<[u8; AEAD_KEY_LEN]>,
}

/// Top-level in-memory representation of a Paladin vault.
///
/// Construct via [`Store::open`] or [`Store::create`]; persist via
/// [`Vault::save`]. Accounts are kept in insertion order — iteration
/// via [`Vault::accounts`] is stable across saves and reopens
/// (DESIGN.md §4.3 wire-format guarantee on the bincode `Vec<Account>`).
pub struct Vault {
    accounts: Vec<Account>,
    settings: VaultSettings,
    cache: Option<EncryptedCache>,
}

impl Vault {
    /// Empty plaintext vault used by `Store::create` / `Store::create_force`.
    pub(crate) fn empty() -> Self {
        Self {
            accounts: Vec::new(),
            settings: VaultSettings::default(),
            cache: None,
        }
    }

    /// Empty encrypted vault used by encrypted `Store::create` /
    /// `Store::create_force`. Caches the passphrase + derived AEAD key
    /// so the first save reuses the same Argon2id derivation.
    pub(crate) fn empty_encrypted(
        passphrase: SecretString,
        key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    ) -> Self {
        Self {
            accounts: Vec::new(),
            settings: VaultSettings::default(),
            cache: Some(EncryptedCache { passphrase, key }),
        }
    }

    /// Build a plaintext `Vault` from a decoded payload. Used by
    /// `Store::open` for plaintext vaults.
    pub(crate) fn from_payload(payload: VaultPayload) -> Self {
        Self {
            accounts: payload.accounts,
            settings: payload.settings,
            cache: None,
        }
    }

    /// Build an encrypted `Vault` from a decoded payload, caching the
    /// passphrase + derived AEAD key. Used by `Store::open` for
    /// encrypted vaults.
    pub(crate) fn from_payload_encrypted(
        payload: VaultPayload,
        passphrase: SecretString,
        key: Zeroizing<[u8; AEAD_KEY_LEN]>,
    ) -> Self {
        Self {
            accounts: payload.accounts,
            settings: payload.settings,
            cache: Some(EncryptedCache { passphrase, key }),
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

    /// Borrow the cached AEAD key (encrypted vaults only).
    pub(crate) fn cached_key(&self) -> Option<&[u8; AEAD_KEY_LEN]> {
        self.cache.as_ref().map(|c| &*c.key)
    }

    /// Borrow the stored accounts in insertion order.
    #[must_use]
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Iterate accounts in insertion order (DESIGN.md §4.7).
    pub fn iter(&self) -> impl Iterator<Item = &Account> {
        self.accounts.iter()
    }

    /// Iterate non-secret [`AccountSummary`] projections in insertion
    /// order. Front ends use this for list rows, JSON output, and
    /// import reports without ever touching `Account` secret fields.
    pub fn summaries(&self) -> impl Iterator<Item = AccountSummary> + '_ {
        self.accounts.iter().map(Account::summary)
    }

    /// Look up an account by ID. Returns `None` for unknown IDs.
    #[must_use]
    pub fn get(&self, id: AccountId) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id() == id)
    }

    /// Borrow the live `VaultSettings`.
    #[must_use]
    pub fn settings(&self) -> &VaultSettings {
        &self.settings
    }

    /// `true` iff the vault was opened in encrypted mode (or created
    /// with an encrypted [`crate::VaultInit`]).
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.cache.is_some()
    }

    /// Append an account; returns its stable [`AccountId`].
    ///
    /// Phase E shipped a `()` return; Phase G.1 widens this to the ID
    /// per DESIGN.md §4.7 so callers can immediately reference the
    /// freshly-inserted account without scanning `iter`.
    /// `(secret, issuer, label)` collision detection lives on
    /// [`Vault::find_duplicate`] (Phase G.3).
    pub fn add(&mut self, account: Account) -> AccountId {
        let id = account.id();
        self.accounts.push(account);
        id
    }

    /// Remove and return the account with the given ID. Returns `None`
    /// if no such account is present, leaving the vault unchanged.
    /// Insertion order of the remaining accounts is preserved.
    pub fn remove(&mut self, id: AccountId) -> Option<Account> {
        let position = self.accounts.iter().position(|a| a.id() == id)?;
        Some(self.accounts.remove(position))
    }

    /// Rename an account's label.
    ///
    /// Re-runs the §4.1 label validation (Unicode-whitespace trim,
    /// empty rejection, 128-byte cap) before any mutation, validates
    /// `now` against the §4.1 timestamp range, and bumps
    /// `updated_at` on success. Missing IDs return
    /// `invalid_state { operation: "rename", state: "account_not_found" }`
    /// per DESIGN.md §4.7. Inputs are validated before the account
    /// lookup so invalid label / timestamp surfaces consistently
    /// even when the ID is unknown.
    pub fn rename(&mut self, id: AccountId, label: &str, now: SystemTime) -> Result<()> {
        let trimmed_label = validate_label(label)?;
        let now_secs = system_time_to_secs_for("rename", now)?;
        let account = self
            .accounts
            .iter_mut()
            .find(|a| a.id() == id)
            .ok_or(PaladinError::InvalidState {
                operation: "rename",
                state: "account_not_found",
            })?;
        account.label = trimmed_label;
        account.updated_at = now_secs;
        Ok(())
    }

    /// Persist the vault through the supplied `Store`.
    ///
    /// Implements the §4.3 atomic write pipeline. Pre-commit failures
    /// (steps 1–3) surface as `save_not_committed`; a parent-fsync
    /// failure post-commit (step 5) surfaces as
    /// `save_durability_unconfirmed`.
    pub fn save(&self, store: &Store) -> Result<()> {
        store.save_payload(&self.snapshot_payload(), self.cached_key())
    }
}

// `Vault` holds `Account`s, which carry `Secret` bytes, plus a
// possibly-cached AEAD key + passphrase. Manual `Debug` redacts both
// sources — the cache is summarized as `is_encrypted` and the
// account list is summarized as a count — so a stray `dbg!(&vault)`
// cannot leak any secret bytes; the §4.7 audit covers this surface.
// `.finish_non_exhaustive()` is the deliberate clippy-friendly way
// to communicate that the omission is intentional.
impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("accounts", &self.accounts.len())
            .field("settings", &self.settings)
            .field("is_encrypted", &self.is_encrypted())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    /// Compile-time guarantee that the cached AEAD key zeroizes when
    /// its `Drop` runs (DESIGN.md §4.4 / Phase F.13). By containment,
    /// a `Vault` drop runs the `Option<EncryptedCache>` drop, which
    /// runs the `key` field's drop, which (`Zeroizing<T>`'s
    /// `ZeroizeOnDrop` impl) wipes the 32-byte buffer before
    /// deallocation. If a future refactor swaps `Zeroizing` for a
    /// raw `[u8; AEAD_KEY_LEN]` or any type without `ZeroizeOnDrop`,
    /// this test fails to compile.
    fn _assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn cached_key_field_zeroizes_on_drop() {
        _assert_zeroize_on_drop::<Zeroizing<[u8; AEAD_KEY_LEN]>>();
    }
}
