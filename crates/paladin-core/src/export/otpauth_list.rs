// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `export::otpauth_list` (docs/DESIGN.md §4.6 / §4.7).
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

#[cfg(test)]
mod tests {
    //! Unit test for the secret-byte round-trip property. Lives inside
    //! the crate because asserting equality of decoded `Secret` bytes
    //! requires `pub(crate)` access; the projection boundary keeps
    //! secret bytes off the public API.

    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::import::{self, ImportOptions};
    use crate::otpauth::parse_otpauth;
    use crate::vault::Vault;

    const URI_TOTP_A: &str = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
    const URI_HOTP_B: &str =
        "otpauth://hotp/Globex:bob?secret=NBSWY3DPEHPK3PXP&issuer=Globex&counter=7";

    fn import_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn round_trip_preserves_secret_bytes_for_every_account() {
        // `export::otpauth_list` followed by `import::from_bytes` must
        // recover the original secret bytes for each account. Non-secret
        // round-trip properties (labels, issuer, kind, timestamps, etc.)
        // are pinned by the integration test of the same name; this
        // unit test owns the secret-bytes invariant because it requires
        // crate-private access to `Account::secret()`.
        let mut vault = Vault::empty();
        let _ = vault.add(parse_otpauth(URI_TOTP_A, import_time()).unwrap().account);
        let _ = vault.add(parse_otpauth(URI_HOTP_B, import_time()).unwrap().account);

        let json = otpauth_list(&vault);
        let imported =
            import::from_bytes(json.as_bytes(), ImportOptions::default(), import_time()).unwrap();
        assert_eq!(imported.len(), 2);

        let originals: Vec<_> = vault.iter().collect();
        for (orig, va) in originals.iter().zip(imported.iter()) {
            assert_eq!(
                orig.secret().expose_secret(),
                va.account.secret().expose_secret(),
            );
        }
    }
}
