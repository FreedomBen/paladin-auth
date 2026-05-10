// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Property tests for the public URI parser and base32 secret decoder
// entry points (DESIGN.md §4.4, §4.6).
//
// The inline `proptests` module in `src/otpauth/mod.rs` already pins
// the URI emit → parse round-trip and a no-panic property over the
// URI path. This file adds independent property coverage for the
// base32 decoder via the public `validate_manual` entry point and
// re-pins the URI no-panic property at integration-test scope so a
// future refactor of `otpauth/mod.rs` cannot silently drop it.

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

    /// `bytes → base32 encode → validate_manual → Secret` recovers the
    /// original bytes exactly. Length spans the §4.1 inclusive range
    /// `[SECRET_MIN_BYTES = 10, SECRET_MAX_BYTES = 1024]`. Catches a
    /// regression where the decoder silently rewrites bytes — the
    /// inline `parse → emit → re-parse` self-consistency check would
    /// not fail on such a bug.
    #[test]
    fn base32_secret_round_trips_to_original_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 10..=1024),
    ) {
        let encoded = base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &bytes,
        );
        let validated = validate_manual(
            account_input_from_secret(SecretString::from(encoded)),
            import_time(),
        )
        .expect("valid base32 of an in-range secret must decode");
        prop_assert_eq!(validated.account.secret().expose_secret(), bytes.as_slice());
    }

    /// RFC 4648 case-insensitivity: lowercase base32 decodes to the
    /// same bytes as the canonical uppercase form.
    #[test]
    fn base32_secret_round_trips_lowercase(
        bytes in proptest::collection::vec(any::<u8>(), 10..=64),
    ) {
        let encoded = base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &bytes,
        )
        .to_ascii_lowercase();
        let validated = validate_manual(
            account_input_from_secret(SecretString::from(encoded)),
            import_time(),
        )
        .expect("lowercase base32 must decode identically to uppercase");
        prop_assert_eq!(validated.account.secret().expose_secret(), bytes.as_slice());
    }

    /// RFC 4648 trailing `=` padding is tolerated: an arbitrary number
    /// of trailing `=` characters does not perturb the decoded bytes.
    #[test]
    fn base32_secret_round_trips_with_padding(
        bytes in proptest::collection::vec(any::<u8>(), 10..=64),
        pad_chars in 0usize..=8,
    ) {
        let mut encoded = base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &bytes,
        );
        for _ in 0..pad_chars {
            encoded.push('=');
        }
        let validated = validate_manual(
            account_input_from_secret(SecretString::from(encoded)),
            import_time(),
        )
        .expect("trailing '=' padding must not perturb decoding");
        prop_assert_eq!(validated.account.secret().expose_secret(), bytes.as_slice());
    }

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
