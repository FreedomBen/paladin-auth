// SPDX-License-Identifier: AGPL-3.0-or-later
//
// No-panic property tests for the public URI and base32 entry points
// (DESIGN.md §4.4, §4.6).
//
// Round-trip property coverage that asserts decoded `Secret` byte
// equality lives in `src/domain/validation.rs`'s `proptests` module:
// secret bytes never leave the crate via the public API, so those
// assertions must be expressed at internal-test scope. The two
// no-panic properties below stay at integration-test scope to pin
// the public surface against arbitrary UTF-8 input.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_otpauth, validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput,
};
use proptest::prelude::*;
use secrecy::SecretString;

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn account_input_from_secret(secret: SecretString) -> AccountInput {
    AccountInput {
        label: "alice".to_string(),
        issuer: None,
        secret,
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// No-panic over the public manual base32 entry point: any UTF-8
    /// input handed to `validate_manual` as the secret either
    /// validates or returns a `PaladinError`. Pairs with the URI-side
    /// no-panic property so both public base32 entry points are
    /// exercised against arbitrary input.
    #[test]
    fn base32_secret_decode_never_panics_on_arbitrary_text(s in ".{0,256}") {
        let _ = validate_manual(
            account_input_from_secret(SecretString::from(s)),
            import_time(),
        );
    }

    /// No-panic over the public URI parse path: any UTF-8 string fed
    /// to `parse_otpauth` either validates or returns a
    /// `PaladinError`. Mirrors the inline property in
    /// `otpauth/mod.rs`; re-pinned at integration scope.
    #[test]
    fn parse_otpauth_never_panics_on_arbitrary_strings(s in ".{0,256}") {
        let _ = parse_otpauth(&s, import_time());
    }
}
