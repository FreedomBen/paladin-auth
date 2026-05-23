// SPDX-License-Identifier: AGPL-3.0-or-later
//
// No-panic property tests for the public URI and base32 entry points
// (docs/DESIGN.md §4.4, §4.6).
//
// Round-trip property coverage that asserts decoded `Secret` byte
// equality lives in `src/domain/validation.rs`'s `proptests` module:
// secret bytes never leave the crate via the public API, so those
// assertions must be expressed at internal-test scope. The two
// no-panic properties below stay at integration-test scope to pin
// the public surface against arbitrary UTF-8 input.

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_otpauth, validate_manual, AccountInput, AccountKindInput, Algorithm, IconHintInput,
    Store, VaultInit,
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
    #![proptest_config(ProptestConfig::with_cases(256))]

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

    /// `Vault::totp_code` (which routes straight into
    /// `otp::totp::compute`) is a pure function of its inputs —
    /// calling it twice on the same stored account at the same `now`
    /// must produce field-identical `Code` values. Pins the
    /// pure-function contract against a regression that introduces
    /// hidden state (cache, lazy init, RNG, time sampling) into the
    /// primitive. The strategy covers every supported `Algorithm`,
    /// all three `digits` widths, the full `period` range (1..=300),
    /// and the entire `now_secs` window up to 2^48 so the property
    /// cannot be silently disabled by a narrow hard-coded fast path.
    #[test]
    fn otp_totp_compute_is_pure_idempotent_over_random_inputs(
        secret_bytes in proptest::collection::vec(any::<u8>(), 10..=32),
        algorithm in prop_oneof![
            Just(Algorithm::Sha1),
            Just(Algorithm::Sha256),
            Just(Algorithm::Sha512),
        ],
        digits in prop_oneof![Just(6u8), Just(7u8), Just(8u8)],
        period in 1u32..=300,
        now_secs in 0u64..=(1u64 << 48),
    ) {
        let encoded = base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            &secret_bytes,
        );
        let input = AccountInput {
            label: "alice".to_string(),
            issuer: None,
            secret: SecretString::from(encoded),
            algorithm,
            digits,
            kind: AccountKindInput::Totp,
            period_secs: Some(period),
            counter: None,
            icon_hint: IconHintInput::Default,
        };
        let validated = validate_manual(input, import_time())
            .expect("in-range inputs must validate");

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
        let path = dir.path().join("vault.bin");
        let (mut vault, _store) =
            Store::create(&path, VaultInit::Plaintext).expect("create");
        let id = vault.add(validated.account);

        let now = UNIX_EPOCH + Duration::from_secs(now_secs);
        let a = vault.totp_code(id, now).expect("first compute");
        let b = vault.totp_code(id, now).expect("second compute");
        prop_assert_eq!(a.code.clone(), b.code.clone());
        prop_assert_eq!(a.valid_from, b.valid_from);
        prop_assert_eq!(a.valid_until, b.valid_until);
        prop_assert_eq!(a.seconds_remaining, b.seconds_remaining);
        prop_assert_eq!(a.counter_used, b.counter_used);
    }
}
