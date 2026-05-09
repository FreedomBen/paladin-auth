// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `import::paladin` — encrypted Paladin bundle (DESIGN.md §4.6 / §4.7).
//
// A Paladin bundle is byte-identical to the on-disk encrypted vault
// format (magic + 64-byte AAD-bound header + AEAD ciphertext over a
// bincode `VaultPayload`). The importer reads bytes only.
//
// Behavior:
//   - Encrypted bundle decrypts via the §4.4 pipeline shared with
//     `Store::open`; account `icon_hint` and timestamps are
//     preserved verbatim. Source `VaultSettings` are dropped (only
//     accounts are returned).
//   - Plaintext-mode Paladin file → `unsupported_plaintext_vault`.
//   - Wrong passphrase or AAD/ciphertext tamper → `decrypt_failed`.
//   - Garbage plaintext (right key, corrupt bincode) →
//     `invalid_payload`.
//   - Empty bundle → `no_entries_to_import`.

use secrecy::SecretString;

use crate::domain::{ValidatedAccount, ValidationWarning};
use crate::error::{PaladinError, Result};
use crate::storage::decrypt_paladin_bundle;

/// Decrypt an encrypted Paladin bundle and return its accounts.
pub fn paladin(bytes: &[u8], passphrase: SecretString) -> Result<Vec<ValidatedAccount>> {
    let payload = decrypt_paladin_bundle(bytes, passphrase)?;
    if payload.accounts.is_empty() {
        return Err(PaladinError::NoEntriesToImport);
    }
    let warnings: Vec<ValidationWarning> = Vec::new();
    let out = payload
        .accounts
        .into_iter()
        .map(|account| ValidatedAccount {
            account,
            warnings: warnings.clone(),
        })
        .collect();
    Ok(out)
}
