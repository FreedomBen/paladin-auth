// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `export::otpauth_list` (DESIGN.md §4.6 / §4.7).
//
// Infallible JSON-array dump of the vault's accounts as canonical
// `otpauth://` URIs. The emitter (`crate::otpauth::emit_otpauth`) is
// the same one tested by the parser round-trip suite, so a fresh
// import via `import::from_bytes` yields a `Vec<ValidatedAccount>`
// with the same `(label, issuer, secret, algorithm, digits, kind,
// icon_hint)` for each account modulo the import-time timestamp rule.
//
// Returns a UTF-8 `String`. Callers that need bytes can `.into_bytes()`
// before passing through `crate::write_secret_file_atomic`.

use crate::otpauth::emit_otpauth;
use crate::vault::Vault;

/// Render every account in `vault` as a JSON array of `otpauth://`
/// URIs.
#[must_use]
pub fn otpauth_list(vault: &Vault) -> String {
    let uris: Vec<String> = vault.iter().map(emit_otpauth).collect();
    serde_json::to_string(&uris).expect("Vec<String> serializes infallibly to JSON")
}
