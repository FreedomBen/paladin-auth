// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `export::encrypted` (docs/DESIGN.md §4.6 / §4.7).
//
// Produces an encrypted Paladin Auth bundle that is byte-compatible with
// the on-disk encrypted vault format (so `import::paladin_auth` and
// `Store::open(VaultLock::Encrypted)` can both consume it). The
// bundle wraps the source vault's accounts in a fresh
// `VaultSettings::default()` payload — the source vault's settings
// are *never* persisted into the bundle.
//
// `EncryptionOptions::new` / `with_params` already reject empty
// passphrases, so this function inherits that rejection through the
// `EncryptionOptions` constructor (no extra check needed at the
// call site).
//
// Each call generates a fresh salt and fresh nonce; two back-to-back
// exports of the same vault under the same passphrase therefore
// produce distinct ciphertext bytes.

use crate::crypto::EncryptionOptions;
use crate::error::Result;
use crate::storage::build_encrypted_bundle_for_export;
use crate::vault::Vault;

/// Encrypt and serialize `vault`'s accounts into a Paladin Auth bundle.
//
// `options` is taken by value: the §4.7 frozen public surface
// documents `EncryptionOptions` as moved-in, mirroring the rest of
// the crypto API where the caller surrenders the secret-bearing
// parameter at the call boundary.
#[allow(clippy::needless_pass_by_value)]
pub fn encrypted(vault: &Vault, options: EncryptionOptions) -> Result<Vec<u8>> {
    let accounts = vault.iter().cloned().collect::<Vec<_>>();
    build_encrypted_bundle_for_export(accounts, &options)
}
