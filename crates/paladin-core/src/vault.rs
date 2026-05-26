// SPDX-License-Identifier: AGPL-3.0-or-later
//
// In-memory `Vault` (docs/DESIGN.md §4.7).
//
// Phase E ships the minimum needed for the plaintext save/open
// round-trip: a `Vault` holds an ordered `Vec<Account>` plus
// `VaultSettings`, exposes read-only views, and routes saves through
// the matching `Store`. Phase F.3 layers an optional encrypted cache
// (the retained `SecretString` passphrase + the cached 32-byte AEAD
// key) so encrypted saves reuse the Argon2id derivation rather than
// re-running the KDF on every HOTP advance. Account-level mutation
// helpers (find_duplicate, rename, hotp_advance, hotp_peek, totp_code,
// mutate_and_save, import_accounts) and passphrase transitions land
// in Phase G / H.

use std::fmt;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::time::SystemTime;

use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::zeroize_witness::{observe, WitnessSite};
use crate::crypto::{EncryptionOptions, AEAD_KEY_LEN};
use crate::domain::validation::{system_time_to_secs_for, validate_label};
use crate::domain::{
    Account, AccountId, AccountSummary, Code, ImportConflict, ImportReport, ImportWarning, OtpKind,
    ValidatedAccount,
};
use crate::error::{ErrorKind, PaladinError, Result};
use crate::otp::{hotp, totp};
use crate::storage::payload::VaultPayload;
use crate::storage::{Store, VaultSettings};

/// Cached AEAD key bytes (docs/DESIGN.md §4.4 / Phase H).
///
/// Inline 32-byte buffer wrapped so that `Drop` runs an in-place
/// zeroize *and* fires the `EncryptedCacheKeyDrop` witness before the
/// stack/inline storage is reused. A regression that swaps this for
/// a raw `[u8; AEAD_KEY_LEN]` (or a buffer container that does not
/// zeroize-before-deallocation) leaves the witness silent and fails
/// the Phase H zeroize tests.
pub(crate) struct CachedAeadKey {
    bytes: [u8; AEAD_KEY_LEN],
}

impl CachedAeadKey {
    // `value` is taken by value rather than by reference so the
    // caller's outer `Zeroizing<[u8; AEAD_KEY_LEN]>` is moved into
    // this constructor and dropped at the end of the call: that
    // drop runs the upstream `Zeroizing` zeroize on the caller's
    // copy *before* the function returns, leaving only this
    // wrapper's `bytes` field as the live key buffer.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn from_zeroizing(value: Zeroizing<[u8; AEAD_KEY_LEN]>) -> Self {
        Self { bytes: *value }
    }

    pub(crate) fn as_bytes(&self) -> &[u8; AEAD_KEY_LEN] {
        &self.bytes
    }
}

impl Drop for CachedAeadKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        observe(
            WitnessSite::EncryptedCacheKeyDrop,
            &self.bytes,
            AEAD_KEY_LEN,
        );
    }
}

/// Cached passphrase bytes (UTF-8) for an encrypted vault
/// (docs/DESIGN.md §4.4 / Phase H).
///
/// Heap-owned `Box<[u8]>` so the bytes live at a stable allocation
/// across passphrase transitions. `Drop` runs an in-place zeroize and
/// fires the `EncryptedCachePassphraseDrop` witness before the
/// allocation is freed; a regression that "replaces with a new
/// allocation while old bytes leak" leaves the witness silent.
pub(crate) struct CachedPassphrase {
    bytes: Box<[u8]>,
}

impl CachedPassphrase {
    pub(crate) fn from_secret(secret: &SecretString) -> Self {
        let bytes = secret
            .expose_secret()
            .as_bytes()
            .to_vec()
            .into_boxed_slice();
        Self { bytes }
    }

    /// Reconstitute a `SecretString` from the retained bytes (the
    /// original passphrase was supplied as a UTF-8 `SecretString`,
    /// so the bytes are valid UTF-8 by construction). Reserved for
    /// later phases / front ends that surface a confirm-old-passphrase
    /// flow; v0.1 transitions do not currently call this, but the
    /// retained-passphrase invariant is asserted by the §4.4 zeroize
    /// witness tests.
    #[allow(dead_code)]
    pub(crate) fn to_secret(&self) -> SecretString {
        let text = std::str::from_utf8(&self.bytes)
            .expect("CachedPassphrase bytes were copied from a SecretString (UTF-8)");
        SecretString::from(text.to_owned())
    }
}

impl Drop for CachedPassphrase {
    fn drop(&mut self) {
        let len = self.bytes.len();
        self.bytes.zeroize();
        observe(WitnessSite::EncryptedCachePassphraseDrop, &self.bytes, len);
    }
}

/// Cached crypto material for an encrypted vault (docs/DESIGN.md §4.4).
///
/// `passphrase` is retained so passphrase transitions / front-end
/// confirm-old-passphrase flows can re-derive or compare without
/// re-prompting; `key` is the 32-byte AEAD key derived from the
/// in-header `(salt, params)` and the passphrase, cached so regular
/// saves do not pay another Argon2id derivation. Both fields
/// zeroize *and* fire a Phase H zeroize-witness observation before
/// their backing storage is reused. The `passphrase` field is not
/// read by the v0.1 transition code paths (see `to_secret` above);
/// the §4.4 retain-and-zeroize invariant is asserted directly via
/// the witness tests.
pub(crate) struct EncryptedCache {
    #[allow(dead_code)]
    pub(crate) passphrase: CachedPassphrase,
    pub(crate) key: CachedAeadKey,
}

impl EncryptedCache {
    // `passphrase` and `key` are taken by value to anchor the
    // memory-hygiene invariant: the caller's `SecretString` /
    // `Zeroizing<[u8; 32]>` are moved into this constructor and
    // dropped at the end of the call, zeroizing any caller-side
    // copies before the function returns.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn new(passphrase: SecretString, key: Zeroizing<[u8; AEAD_KEY_LEN]>) -> Self {
        Self {
            passphrase: CachedPassphrase::from_secret(&passphrase),
            key: CachedAeadKey::from_zeroizing(key),
        }
    }
}

/// Top-level in-memory representation of a Paladin vault.
///
/// Construct via [`Store::open`] or [`Store::create`]; persist via
/// [`Vault::save`]. Accounts are kept in insertion order — iteration
/// via [`Vault::accounts`] is stable across saves and reopens
/// (docs/DESIGN.md §4.3 wire-format guarantee on the bincode `Vec<Account>`).
pub struct Vault {
    accounts: Vec<Account>,
    settings: VaultSettings,
    cache: Option<EncryptedCache>,
}

/// Internal rollback snapshot for [`Vault::mutate_and_save`]
/// (docs/DESIGN.md §4.7).
///
/// Captures the two non-cache fields whose mutations the helper
/// rolls back (accounts and settings); the encrypted-cache material
/// is invariant across `mutate_and_save` (passphrase transitions go
/// through their own Phase H entry points), so the snapshot does
/// not duplicate the cached AEAD key. `Account` owns a
/// [`crate::domain::Secret`] whose `ZeroizeOnDrop` impl wipes the
/// secret bytes when the `Vec<Account>` is dropped, so the snapshot
/// itself zeroizes its secret-bearing data on drop without an
/// explicit `Drop` impl.
struct VaultSnapshot {
    accounts: Vec<Account>,
    settings: VaultSettings,
}

impl VaultSnapshot {
    fn capture(vault: &Vault) -> Self {
        Self {
            accounts: vault.accounts.clone(),
            settings: vault.settings,
        }
    }

    /// Move the captured state back into `vault`, replacing the
    /// current contents. Consumes the snapshot so the secret-bearing
    /// `Vec<Account>` is dropped (and zeroized) immediately after
    /// the move.
    fn restore_into(self, vault: &mut Vault) {
        vault.accounts = self.accounts;
        vault.settings = self.settings;
    }
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
            cache: Some(EncryptedCache::new(passphrase, key)),
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
            cache: Some(EncryptedCache::new(passphrase, key)),
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
        self.cache.as_ref().map(|c| c.key.as_bytes())
    }

    /// Borrow the stored accounts in insertion order.
    #[must_use]
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Iterate accounts in insertion order (docs/DESIGN.md §4.7).
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

    /// Render the matching account's `otpauth://` URI as PNG bytes.
    ///
    /// Read-only: never advances HOTP counters, never touches the
    /// on-disk vault. Returns `invalid_state { operation:
    /// "export_qr_png", state: "account_not_found" }` if `id` does not
    /// resolve. See [`crate::export::qr_png`] for renderer details.
    pub fn export_qr_png(
        &self,
        id: AccountId,
        opts: &crate::QrRenderOptions,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let account = self.get(id).ok_or(PaladinError::InvalidState {
            operation: "export_qr_png",
            state: "account_not_found",
        })?;
        crate::export::qr_png(account, opts)
    }

    /// Render the matching account's `otpauth://` URI as an SVG document.
    ///
    /// Read-only contract identical to [`Self::export_qr_png`]; returns
    /// `invalid_state { operation: "export_qr_svg", state:
    /// "account_not_found" }` on unknown `id`.
    pub fn export_qr_svg(
        &self,
        id: AccountId,
        opts: &crate::QrRenderOptions,
    ) -> Result<zeroize::Zeroizing<String>> {
        let account = self.get(id).ok_or(PaladinError::InvalidState {
            operation: "export_qr_svg",
            state: "account_not_found",
        })?;
        crate::export::qr_svg(account, opts)
    }

    /// Render the matching account's `otpauth://` URI as a Unicode
    /// half-block grid (terminal preview).
    ///
    /// Read-only contract identical to [`Self::export_qr_png`]; returns
    /// `invalid_state { operation: "export_qr_ansi", state:
    /// "account_not_found" }` on unknown `id`. The output uses only the
    /// glyphs `' '`, `'\u{2580}'`, `'\u{2584}'`, `'\u{2588}'`, and
    /// `'\n'` — no ANSI escape sequences.
    pub fn export_qr_ansi(&self, id: AccountId) -> Result<zeroize::Zeroizing<String>> {
        let account = self.get(id).ok_or(PaladinError::InvalidState {
            operation: "export_qr_ansi",
            state: "account_not_found",
        })?;
        crate::export::qr_ansi(account)
    }

    /// Filter accounts by the shared selector grammar (docs/DESIGN.md §4.7).
    ///
    /// `Search` queries delegate to the case-insensitive substring
    /// predicate; `IdPrefix` queries match accounts whose canonical
    /// 32-char lowercase hex starts with the validated prefix. Both
    /// kinds return matches in insertion order so callers can apply
    /// command-specific cardinality rules without re-sorting.
    #[must_use]
    pub fn matching_accounts(&self, query: &crate::AccountQuery) -> Vec<&Account> {
        crate::domain::query::matching_accounts(&self.accounts, query)
    }

    /// Compute the shortest `id:` hex disambiguator that uniquely
    /// identifies `id` among the current vault accounts (docs/DESIGN.md
    /// §4.7).
    ///
    /// The returned string is the lowercase hex prefix only — callers
    /// (CLI candidate lists in particular) format it as `id:<hex>`.
    /// The prefix is at least 8 chars and at most the full 32-char
    /// canonical hex; the function returns `None` when `id` is not
    /// present in the vault.
    #[must_use]
    pub fn shortest_unique_id_prefix(&self, id: AccountId) -> Option<String> {
        crate::domain::query::shortest_unique_id_prefix(&self.accounts, id)
    }

    /// Borrow the live `VaultSettings`.
    #[must_use]
    pub fn settings(&self) -> &VaultSettings {
        &self.settings
    }

    /// Toggle the encrypted-only auto-lock-on-idle preference. The CLI
    /// ignores this; the TUI / GUI consult it via
    /// [`crate::VaultSettings::auto_lock_enabled`].
    pub fn set_auto_lock_enabled(&mut self, enabled: bool) {
        self.settings.set_auto_lock_enabled(enabled);
    }

    /// Set the auto-lock idle timeout in seconds. Rejects values
    /// outside the inclusive range
    /// [`crate::AUTO_LOCK_SECS_MIN`]..=[`crate::AUTO_LOCK_SECS_MAX`]
    /// with a `validation_error` for `auto_lock.timeout_secs`. The
    /// prior value is left unchanged on rejection.
    pub fn set_auto_lock_timeout_secs(&mut self, secs: u32) -> Result<()> {
        self.settings.set_auto_lock_timeout_secs(secs)
    }

    /// Toggle the wipe-after-copy clipboard preference (TUI / GUI
    /// only — CLI ignores).
    pub fn set_clipboard_clear_enabled(&mut self, enabled: bool) {
        self.settings.set_clipboard_clear_enabled(enabled);
    }

    /// Set the clipboard wipe-after-copy delay in seconds. Rejects
    /// values outside the inclusive range
    /// [`crate::CLIPBOARD_CLEAR_SECS_MIN`]..=[`crate::CLIPBOARD_CLEAR_SECS_MAX`]
    /// with a `validation_error` for `clipboard.clear_secs`. The
    /// prior value is left unchanged on rejection.
    pub fn set_clipboard_clear_secs(&mut self, secs: u32) -> Result<()> {
        self.settings.set_clipboard_clear_secs(secs)
    }

    /// Apply a typed §5 [`crate::SettingPatch`] in place.
    ///
    /// Routes through the same typed setters
    /// (`set_auto_lock_enabled`, `set_auto_lock_timeout_secs`,
    /// `set_clipboard_clear_enabled`, `set_clipboard_clear_secs`) so
    /// the CLI's dotted `settings set` patches and direct TUI / GUI
    /// setters share one validation source. The prior
    /// [`crate::VaultSettings`] is left unchanged on rejection;
    /// callers persist accepted patches via
    /// [`Vault::mutate_and_save`] or [`Vault::save`].
    pub fn apply_setting_patch(&mut self, patch: crate::SettingPatch) -> Result<()> {
        match patch {
            crate::SettingPatch::AutoLockEnabled(v) => {
                self.set_auto_lock_enabled(v);
                Ok(())
            }
            crate::SettingPatch::AutoLockTimeoutSecs(secs) => self.set_auto_lock_timeout_secs(secs),
            crate::SettingPatch::ClipboardClearEnabled(v) => {
                self.set_clipboard_clear_enabled(v);
                Ok(())
            }
            crate::SettingPatch::ClipboardClearSecs(secs) => self.set_clipboard_clear_secs(secs),
        }
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
    /// per docs/DESIGN.md §4.7 so callers can immediately reference the
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

    /// Return the first stored account whose `(secret, issuer, label)`
    /// tuple exactly matches the candidate's, or `None` if no
    /// collision is found.
    ///
    /// Comparison is byte-for-byte on the secret bytes and
    /// case-sensitive on the issuer / label strings; the §5
    /// case-insensitive search semantics live in
    /// `account_matches_search`, not here. Front ends use this
    /// helper to render the §5 `duplicate_account` error and to
    /// drive the `--allow-duplicate` / "add anyway" policy.
    #[must_use]
    pub fn find_duplicate(&self, account: &ValidatedAccount) -> Option<&Account> {
        let candidate = &account.account;
        self.accounts.iter().find(|existing| {
            existing.secret() == candidate.secret()
                && existing.issuer() == candidate.issuer()
                && existing.label() == candidate.label()
        })
    }

    /// Apply a batch of pre-validated rows to the in-memory vault using
    /// the §5 `--on-conflict` merge policy (docs/DESIGN.md §4.7).
    ///
    /// Collisions are determined by the exact `(secret, issuer, label)`
    /// triple — the same predicate as [`Vault::find_duplicate`]. The
    /// [`ImportConflict`] argument selects the merge action:
    ///
    /// - [`ImportConflict::Skip`] keeps the existing entry, increments
    ///   `skipped`, and does **not** add the source row's ID to
    ///   [`ImportReport::accounts`].
    /// - [`ImportConflict::Replace`] overwrites the existing entry,
    ///   preserving its `id` and `created_at`, sets `updated_at = now`,
    ///   and (for HOTP-to-HOTP collisions) preserves the existing
    ///   `Hotp.counter`. Cross-kind replacements swap the whole `kind`.
    /// - [`ImportConflict::Append`] inserts the colliding row as an
    ///   additional account with a fresh [`AccountId`].
    ///
    /// Non-colliding rows always receive a fresh [`AccountId`] at merge
    /// time per §4.6, so source IDs from a Paladin bundle never leak
    /// into the destination vault.
    ///
    /// Any [`crate::ValidationWarning`]s on the input rows are pushed
    /// into [`ImportReport::warnings`] **before** the merge policy runs,
    /// so a warning attached to a row that is later skipped under
    /// `Skip` is still surfaced.
    ///
    /// `now` must be within the §4.1 timestamp range; out-of-range
    /// values return `time_range` before any mutation. The method
    /// itself does not persist — wrap the call in
    /// [`Vault::mutate_and_save`] for atomic merge-and-save semantics.
    pub fn import_accounts(
        &mut self,
        accounts: Vec<ValidatedAccount>,
        policy: ImportConflict,
        now: SystemTime,
    ) -> Result<ImportReport> {
        let now_secs = system_time_to_secs_for("import_accounts", now)?;
        let mut report = ImportReport::default();

        for (idx, va) in accounts.iter().enumerate() {
            for warning in &va.warnings {
                report.warnings.push(ImportWarning {
                    source_index: idx,
                    warning: warning.clone(),
                });
            }
        }

        for va in accounts {
            let candidate = va.account;
            let collision_pos = self.accounts.iter().position(|existing| {
                existing.secret() == candidate.secret()
                    && existing.issuer() == candidate.issuer()
                    && existing.label() == candidate.label()
            });

            match (collision_pos, policy) {
                (None, _) => {
                    let mut acct = candidate;
                    acct.id = AccountId::new();
                    report.accounts.push(acct.id);
                    self.accounts.push(acct);
                    report.imported += 1;
                }
                (Some(_), ImportConflict::Skip) => {
                    report.skipped += 1;
                }
                (Some(pos), ImportConflict::Replace) => {
                    let existing = &self.accounts[pos];
                    let preserved_id = existing.id;
                    let preserved_created_at = existing.created_at;
                    let new_kind = match (existing.kind, candidate.kind) {
                        (OtpKind::Hotp { counter }, OtpKind::Hotp { .. }) => {
                            OtpKind::Hotp { counter }
                        }
                        (_, incoming) => incoming,
                    };
                    self.accounts[pos] = Account {
                        id: preserved_id,
                        label: candidate.label,
                        issuer: candidate.issuer,
                        secret: candidate.secret,
                        algorithm: candidate.algorithm,
                        digits: candidate.digits,
                        kind: new_kind,
                        icon_hint: candidate.icon_hint,
                        created_at: preserved_created_at,
                        updated_at: now_secs,
                    };
                    report.accounts.push(preserved_id);
                    report.replaced += 1;
                }
                (Some(_), ImportConflict::Append) => {
                    let mut acct = candidate;
                    acct.id = AccountId::new();
                    report.accounts.push(acct.id);
                    self.accounts.push(acct);
                    report.appended += 1;
                }
            }
        }

        Ok(report)
    }

    /// Rename an account's label.
    ///
    /// Re-runs the §4.1 label validation (Unicode-whitespace trim,
    /// empty rejection, 128-byte cap) before any mutation, validates
    /// `now` against the §4.1 timestamp range, and bumps
    /// `updated_at` on success. Missing IDs return
    /// `invalid_state { operation: "rename", state: "account_not_found" }`
    /// per docs/DESIGN.md §4.7. Inputs are validated before the account
    /// lookup so invalid label / timestamp surfaces consistently
    /// even when the ID is unknown.
    pub fn rename(&mut self, id: AccountId, label: &str, now: SystemTime) -> Result<()> {
        let trimmed_label = validate_label(label)?;
        let now_secs = system_time_to_secs_for("rename", now)?;
        let account =
            self.accounts
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

    /// Encrypt a previously-plaintext vault under `options`
    /// (docs/DESIGN.md §4.5 / Phase H).
    ///
    /// Wrong-state guard runs before any crypto: a vault that is
    /// already encrypted returns
    /// `invalid_state { operation: "set_passphrase", state: "already_encrypted" }`.
    /// A zero-length passphrase (the user supplied an empty
    /// `SecretString` directly into `EncryptionOptions`'s public
    /// fields, bypassing the constructor) returns
    /// `invalid_passphrase { reason: "zero_length" }`. Whitespace and
    /// Unicode passphrases are accepted byte-for-byte (no trim, no
    /// normalization). `kdf_params` is validated through
    /// [`crate::Argon2Params::validate`].
    ///
    /// On success: the on-disk primary is replaced with an encrypted
    /// vault under fresh `(salt, nonce_primary)`, and the rotated
    /// `.bak` is also encrypted under the new key with a separate
    /// fresh nonce so it does not retain the previous plaintext
    /// secrets. The Store updates its mode to encrypted with the
    /// new `(salt, params)`, and this `Vault`'s in-memory cache is
    /// replaced with the new key + retained passphrase.
    ///
    /// On a pre-commit failure (`save_not_committed`): the on-disk
    /// primary is unchanged, and this `Vault` and the `Store` remain
    /// in plaintext mode (cache is still `None`). On a post-commit
    /// `save_durability_unconfirmed`: the on-disk primary already
    /// carries the new encrypted bytes, so the in-memory state is
    /// updated to match (cache populated, Store marked encrypted)
    /// and the error is propagated for the caller to surface.
    pub fn set_passphrase(&mut self, store: &Store, options: EncryptionOptions) -> Result<()> {
        if self.is_encrypted() {
            return Err(PaladinError::InvalidState {
                operation: "set_passphrase",
                state: "already_encrypted",
            });
        }
        if options.passphrase.expose_secret().is_empty() {
            return Err(PaladinError::InvalidPassphrase {
                reason: "zero_length",
            });
        }
        let pending = store.prepare_encryption(&options)?;
        let payload = self.snapshot_payload();
        let result = store.commit_encryption(&payload, &pending);
        match result {
            Ok(()) => {
                self.cache = Some(EncryptedCache::new(options.passphrase, pending.key));
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::SaveDurabilityUnconfirmed => {
                self.cache = Some(EncryptedCache::new(options.passphrase, pending.key));
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    /// Re-encrypt an encrypted vault under a new passphrase
    /// (docs/DESIGN.md §4.5 / Phase H).
    ///
    /// Wrong-state guard: a plaintext vault returns
    /// `invalid_state { operation: "change_passphrase", state: "not_encrypted" }`.
    /// Zero-length / params validation as per
    /// [`Vault::set_passphrase`].
    ///
    /// On success the on-disk primary is rewritten under fresh
    /// `(salt, nonce_primary)`, the rotated `.bak` is also encrypted
    /// under the new key with a separate fresh nonce so the old
    /// (possibly-compromised) key cannot recover prior contents from
    /// the backup, and the in-memory cache is replaced with the new
    /// key + retained passphrase. The previously-cached AEAD key
    /// bytes and passphrase bytes are zeroized in place before the
    /// underlying allocations are freed (witnessed under the
    /// `test-zeroize-witness` feature).
    pub fn change_passphrase(&mut self, store: &Store, options: EncryptionOptions) -> Result<()> {
        if !self.is_encrypted() {
            return Err(PaladinError::InvalidState {
                operation: "change_passphrase",
                state: "not_encrypted",
            });
        }
        if options.passphrase.expose_secret().is_empty() {
            return Err(PaladinError::InvalidPassphrase {
                reason: "zero_length",
            });
        }
        let pending = store.prepare_encryption(&options)?;
        let payload = self.snapshot_payload();
        let result = store.commit_encryption(&payload, &pending);
        match result {
            Ok(()) => {
                self.cache = Some(EncryptedCache::new(options.passphrase, pending.key));
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::SaveDurabilityUnconfirmed => {
                self.cache = Some(EncryptedCache::new(options.passphrase, pending.key));
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    /// Drop encryption from an encrypted vault (docs/DESIGN.md §4.5 /
    /// Phase H).
    ///
    /// Wrong-state guard: a plaintext vault returns
    /// `invalid_state { operation: "remove_passphrase", state: "not_encrypted" }`.
    ///
    /// On success the on-disk primary is rewritten as plaintext, and
    /// the rotated `.bak` is also written as plaintext (so it
    /// remains accessible without the just-removed passphrase per
    /// §4.5). The in-memory encrypted cache (key + passphrase) is
    /// dropped and zeroized (witnessed under `test-zeroize-witness`).
    pub fn remove_passphrase(&mut self, store: &Store) -> Result<()> {
        if !self.is_encrypted() {
            return Err(PaladinError::InvalidState {
                operation: "remove_passphrase",
                state: "not_encrypted",
            });
        }
        let payload = self.snapshot_payload();
        let result = store.commit_plaintext(&payload);
        match result {
            Ok(()) => {
                self.cache = None;
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::SaveDurabilityUnconfirmed => {
                self.cache = None;
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    /// Run `mutator` against this vault and persist the result through
    /// `store`, with snapshot-based rollback (docs/DESIGN.md §4.7).
    ///
    /// The internal snapshot captures the account list and every
    /// `VaultSettings` field before `mutator` runs, so a closure that
    /// touches both fields and then errors leaves the vault byte-for-
    /// byte at its pre-call state. Each `Account` in the snapshot
    /// owns a [`crate::domain::Secret`] whose `ZeroizeOnDrop` impl
    /// wipes the secret bytes when the snapshot is dropped, so a
    /// rollback path cannot leave secret-bearing copies on the stack.
    ///
    /// Resolution rules:
    ///
    /// - `mutator` returns `Err` → restore the snapshot, return the
    ///   error. The `Store::save` path is **not** entered.
    /// - `mutator` returns `Ok(value)` and `Vault::save` returns
    ///   `Ok(())` → return `value`.
    /// - `Vault::save` returns `save_not_committed` → restore the
    ///   snapshot (memory matches the unchanged on-disk primary)
    ///   and return the error.
    /// - `Vault::save` returns `save_durability_unconfirmed` (or any
    ///   other error after the rename commit point) → keep the
    ///   mutated state in memory because the on-disk primary already
    ///   carries it; return the error.
    ///
    /// Front ends (CLI, TUI, GUI) drive add / remove / settings /
    /// import-merge flows through this single helper so each crate
    /// does not duplicate snapshot machinery.
    ///
    /// Closure panic safety: the mutator runs inside
    /// `std::panic::catch_unwind(AssertUnwindSafe(...))`. If the
    /// closure unwinds, the rollback snapshot is restored before the
    /// panic is resumed, so callers that catch the unwind further up
    /// observe the pre-mutation state. The `Store::save` path is not
    /// entered on a closure panic.
    pub fn mutate_and_save<F, R>(&mut self, store: &Store, mutator: F) -> Result<R>
    where
        F: FnOnce(&mut Vault) -> Result<R>,
    {
        let snapshot = VaultSnapshot::capture(self);
        let mutator_result = catch_unwind(AssertUnwindSafe(|| mutator(self)));
        let value = match mutator_result {
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                snapshot.restore_into(self);
                return Err(err);
            }
            Err(panic_payload) => {
                snapshot.restore_into(self);
                resume_unwind(panic_payload);
            }
        };
        match self.save(store) {
            Ok(()) => Ok(value),
            Err(err) if err.kind() == ErrorKind::SaveNotCommitted => {
                snapshot.restore_into(self);
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    /// Compute the TOTP code for an account at the supplied wall-clock
    /// time. Read-only — never mutates the vault and never touches the
    /// `Store` (docs/DESIGN.md §4.2 / §4.7).
    ///
    /// Missing IDs return
    /// `invalid_state { operation: "totp_code", state: "account_not_found" }`;
    /// HOTP accounts return
    /// `invalid_state { operation: "totp_code", state: "not_totp" }`.
    /// Pre-Unix-epoch / `valid_until`-overflow timestamps surface as
    /// `time_range` from the underlying TOTP primitive.
    pub fn totp_code(&self, id: AccountId, now: SystemTime) -> Result<Code> {
        let account =
            self.accounts
                .iter()
                .find(|a| a.id() == id)
                .ok_or(PaladinError::InvalidState {
                    operation: "totp_code",
                    state: "account_not_found",
                })?;
        let period = match account.kind {
            OtpKind::Totp { period } => period,
            OtpKind::Hotp { .. } => {
                return Err(PaladinError::InvalidState {
                    operation: "totp_code",
                    state: "not_totp",
                });
            }
        };
        totp::compute(
            account.secret(),
            account.algorithm(),
            period,
            account.digits(),
            now,
            "totp_code",
        )
    }

    /// Compute the TOTP code for the *next* window — the code that
    /// will become current at `((now_unix / period) + 1) * period`.
    /// Read-only — never mutates the vault and never touches the
    /// `Store` (docs/DESIGN.md §4.2 / §4.7).
    ///
    /// At an exact window boundary (`now_unix % period == 0`) the
    /// returned code is for the window immediately after the
    /// boundary, never two windows ahead.
    ///
    /// Missing IDs return
    /// `invalid_state { operation: "totp_next_code", state: "account_not_found" }`;
    /// HOTP accounts return
    /// `invalid_state { operation: "totp_next_code", state: "not_totp" }`.
    /// Pre-Unix-epoch / `valid_until`-overflow timestamps surface as
    /// `time_range` tagged `operation: "totp_next_code"`.
    pub fn totp_next_code(&self, id: AccountId, now: SystemTime) -> Result<Code> {
        let account =
            self.accounts
                .iter()
                .find(|a| a.id() == id)
                .ok_or(PaladinError::InvalidState {
                    operation: "totp_next_code",
                    state: "account_not_found",
                })?;
        let period = match account.kind {
            OtpKind::Totp { period } => period,
            OtpKind::Hotp { .. } => {
                return Err(PaladinError::InvalidState {
                    operation: "totp_next_code",
                    state: "not_totp",
                });
            }
        };
        let now_unix = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| PaladinError::TimeRange {
                operation: "totp_next_code",
                kind: crate::error::TimeRangeKind::PreEpoch,
            })?
            .as_secs();
        let period_u64 = u64::from(period);
        let current_counter = now_unix / period_u64;
        let next_window_start_secs = current_counter
            .checked_add(1)
            .and_then(|c| c.checked_mul(period_u64))
            .ok_or(PaladinError::TimeRange {
                operation: "totp_next_code",
                kind: crate::error::TimeRangeKind::Overflow,
            })?;
        let next_window_start =
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(next_window_start_secs);
        totp::compute(
            account.secret(),
            account.algorithm(),
            period,
            account.digits(),
            next_window_start,
            "totp_next_code",
        )
    }

    /// Compute the HOTP code at the current stored counter without
    /// advancing it. Read-only — never mutates the vault and never
    /// touches the `Store` (docs/DESIGN.md §4.2 / §4.7).
    ///
    /// A `hotp_peek` immediately following a successful `hotp_advance`
    /// observes the post-advance counter (`prev + 1`), so successive
    /// calls without an intervening `hotp_advance` return the same
    /// code, while a `hotp_advance` between them shifts to the next
    /// code in the RFC 4226 sequence.
    ///
    /// Missing IDs return
    /// `invalid_state { operation: "hotp_peek", state: "account_not_found" }`;
    /// TOTP accounts return
    /// `invalid_state { operation: "hotp_peek", state: "not_hotp" }`.
    pub fn hotp_peek(&self, id: AccountId) -> Result<Code> {
        let account =
            self.accounts
                .iter()
                .find(|a| a.id() == id)
                .ok_or(PaladinError::InvalidState {
                    operation: "hotp_peek",
                    state: "account_not_found",
                })?;
        let counter = match account.kind {
            OtpKind::Hotp { counter } => counter,
            OtpKind::Totp { .. } => {
                return Err(PaladinError::InvalidState {
                    operation: "hotp_peek",
                    state: "not_hotp",
                });
            }
        };
        Ok(hotp::compute(
            account.secret(),
            account.algorithm(),
            account.digits(),
            counter,
        ))
    }

    /// Compute the HOTP code at the current counter, advance the
    /// stored counter, bump `updated_at`, and persist the vault
    /// atomically through `store` (docs/DESIGN.md §4.7).
    ///
    /// Validation order is locked so the §5 error taxonomy stays
    /// stable: invalid timestamps return `time_range` before any
    /// account lookup or mutation; missing IDs return
    /// `invalid_state { operation: "hotp_advance", state: "account_not_found" }`;
    /// TOTP accounts return
    /// `invalid_state { operation: "hotp_advance", state: "not_hotp" }`;
    /// counters at `u64::MAX` return `counter_overflow` before
    /// touching memory or attempting a save.
    ///
    /// On a successful save the in-memory counter is `prev + 1` and
    /// the returned [`Code`] reflects the *pre-advance* counter
    /// (RFC 4226: emit-then-increment), so a subsequent
    /// `hotp_peek` returns the next code in the sequence. When the
    /// `Store` save returns `save_not_committed` (pre-rename
    /// failure), the in-memory counter and `updated_at` are reverted
    /// to their pre-call values so the user does not see a counter
    /// advance that was never persisted. When the save returns
    /// `save_durability_unconfirmed` (post-rename, parent-fsync
    /// failure), the mutated state is left in place because the
    /// primary file is already on disk and a subsequent
    /// `hotp_peek` must match the on-disk counter.
    pub fn hotp_advance(&mut self, store: &Store, id: AccountId, now: SystemTime) -> Result<Code> {
        let now_secs = system_time_to_secs_for("hotp_advance", now)?;
        let pos =
            self.accounts
                .iter()
                .position(|a| a.id() == id)
                .ok_or(PaladinError::InvalidState {
                    operation: "hotp_advance",
                    state: "account_not_found",
                })?;
        let counter = match self.accounts[pos].kind {
            OtpKind::Hotp { counter } => counter,
            OtpKind::Totp { .. } => {
                return Err(PaladinError::InvalidState {
                    operation: "hotp_advance",
                    state: "not_hotp",
                });
            }
        };
        if counter == u64::MAX {
            return Err(PaladinError::CounterOverflow {
                account: self.accounts[pos].summary(),
            });
        }
        let account = &self.accounts[pos];
        let code = hotp::compute(
            account.secret(),
            account.algorithm(),
            account.digits(),
            counter,
        );
        let prev_updated_at = account.updated_at;

        self.accounts[pos].kind = OtpKind::Hotp {
            counter: counter + 1,
        };
        self.accounts[pos].updated_at = now_secs;

        match self.save(store) {
            Ok(()) => Ok(code),
            Err(err) => {
                if err.kind() == ErrorKind::SaveNotCommitted {
                    // Pre-rename failure: the on-disk primary is
                    // unchanged, so revert the in-memory mutation
                    // to keep memory and disk consistent.
                    self.accounts[pos].kind = OtpKind::Hotp { counter };
                    self.accounts[pos].updated_at = prev_updated_at;
                }
                // `save_durability_unconfirmed` and any other error
                // kind leave the mutation in place: the rename has
                // committed, so the on-disk vault already carries
                // the post-advance counter.
                Err(err)
            }
        }
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
    use crate::crypto::zeroize_witness::{clear_observations, take_observations};
    use static_assertions::assert_not_impl_all;
    use zeroize::ZeroizeOnDrop;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    // Phase B audit (docs/DESIGN.md §8 / docs/IMPLEMENTATION_PLAN_01_CORE.md
    // Phase B): the rollback snapshot owns secret-bearing
    // `Vec<Account>` data and must never gain a `Debug` derive.
    // `VaultSnapshot` is `pub(super)`, so the equivalent trybuild
    // proof in `tests/trybuild/` cannot reach it from an external
    // crate; this in-tree assertion keeps the guarantee visible.
    assert_not_impl_all!(VaultSnapshot: std::fmt::Debug);

    /// Containment witness for `VaultSnapshot`'s secret-bearing field
    /// (docs/DESIGN.md §4.7 / Phase G.9): the snapshot owns a
    /// `Vec<Account>`, whose drop runs each `Account`'s drop, which
    /// runs the `Secret` field's `ZeroizeOnDrop` impl and wipes the
    /// secret bytes before deallocation. If a future refactor swaps
    /// the snapshot's secret-bearing field for a non-zeroizing
    /// container, the per-`Secret` test here keeps failing
    /// alongside its corresponding domain-level coverage.
    #[test]
    fn vault_snapshot_secret_field_zeroizes_on_drop() {
        assert_zeroize_on_drop::<crate::domain::Secret>();
    }

    /// `CachedAeadKey::drop` runs an in-place zeroize and fires the
    /// Phase H key-drop witness with `all_zero == true` so a regression
    /// that swaps the wrapper for a raw `[u8; 32]` (no Drop) silently
    /// loses key bytes — and the witness goes silent.
    #[test]
    fn cached_aead_key_drop_zeroizes_and_witnesses() {
        clear_observations();
        let mut bytes = [0u8; AEAD_KEY_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            // i is bounded by AEAD_KEY_LEN = 32, so the cast is exact.
            *b = u8::try_from(i).unwrap().wrapping_add(1);
        }
        let key = CachedAeadKey::from_zeroizing(Zeroizing::new(bytes));
        drop(key);
        let obs = take_observations();
        let key_obs: Vec<_> = obs
            .iter()
            .filter(|o| o.site == WitnessSite::EncryptedCacheKeyDrop)
            .collect();
        assert_eq!(key_obs.len(), 1, "exactly one key-drop observation");
        assert!(
            key_obs[0].all_zero,
            "key bytes zeroized before deallocation"
        );
        assert_eq!(key_obs[0].original_len, AEAD_KEY_LEN);
    }

    /// `CachedPassphrase::drop` runs an in-place zeroize and fires the
    /// Phase H passphrase-drop witness with `all_zero == true`.
    #[test]
    fn cached_passphrase_drop_zeroizes_and_witnesses() {
        clear_observations();
        let pp = CachedPassphrase::from_secret(&SecretString::from("hunter2".to_owned()));
        drop(pp);
        let obs = take_observations();
        let pp_obs: Vec<_> = obs
            .iter()
            .filter(|o| o.site == WitnessSite::EncryptedCachePassphraseDrop)
            .collect();
        assert_eq!(pp_obs.len(), 1, "exactly one passphrase-drop observation");
        assert!(
            pp_obs[0].all_zero,
            "passphrase bytes zeroized before deallocation"
        );
        assert_eq!(pp_obs[0].original_len, "hunter2".len());
    }

    #[test]
    fn cached_passphrase_round_trips_through_secret_string() {
        let pp = CachedPassphrase::from_secret(&SecretString::from("hunter2".to_owned()));
        assert_eq!(pp.to_secret().expose_secret(), "hunter2");
    }
}
