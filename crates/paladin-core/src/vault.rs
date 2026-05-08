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

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::crypto::AEAD_KEY_LEN;
use crate::domain::Account;
use crate::error::Result;
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
