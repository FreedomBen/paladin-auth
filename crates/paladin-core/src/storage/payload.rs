// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `VaultPayload` codec (DESIGN.md §4.3).
//
// `VaultPayload = { accounts: Vec<Account>, settings: VaultSettings }`
// is encoded with bincode v2 using little-endian + fixed-int encoding
// and capped at 16 MiB serialized bytes. Both ends must consume the
// entire input slice — trailing bytes are an `invalid_payload` error.
//
// The encoding is deterministic: encoding the same value twice
// produces bit-identical output. That property is what lets us bind
// vault bytes as AEAD AAD in encrypted mode without re-encoding noise.

use bincode::config::{Configuration, Fixint, Limit, LittleEndian};
use bincode::error::DecodeError;
use bincode::{Decode, Encode};

use crate::domain::Account;
use crate::error::PaladinError;

/// Maximum serialized `VaultPayload` size, in bytes (DESIGN.md §4.3).
///
/// Applies to the bincode-encoded payload — i.e. excludes the §4.3
/// header bytes and the AEAD tag in encrypted mode.
#[allow(dead_code)] // Wired up by storage::Store (Phase E continuation).
pub(crate) const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// On-disk vault payload (DESIGN.md §4.3).
///
/// Crate-private: presentation crates interact through `Vault`, never
/// the raw payload struct.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[allow(dead_code)] // Wired up by storage::Store (Phase E continuation).
pub(crate) struct VaultPayload {
    pub(crate) accounts: Vec<Account>,
    pub(crate) settings: VaultSettings,
}

/// Per-vault user preferences (DESIGN.md §4.7).
///
/// Persisted **inside** the vault payload (not the file header) so an
/// encrypted vault's settings are covered by the AEAD tag and cannot
/// be tampered with on disk.
///
/// Fields are private; readers go through `VaultSettings`'s getters
/// and writers go through `Vault`'s validated setters (Phase G).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct VaultSettings {
    auto_lock_enabled: bool,
    auto_lock_timeout_secs: u32,
    clipboard_clear_enabled: bool,
    clipboard_clear_secs: u32,
}

impl VaultSettings {
    /// Whether the TUI/GUI should auto-lock on idle (CLI ignores).
    #[must_use]
    pub fn auto_lock_enabled(&self) -> bool {
        self.auto_lock_enabled
    }

    /// Idle timeout in seconds before auto-lock fires (when enabled).
    #[must_use]
    pub fn auto_lock_timeout_secs(&self) -> u32 {
        self.auto_lock_timeout_secs
    }

    /// Whether the TUI/GUI schedules a clipboard wipe after copy
    /// (CLI ignores).
    #[must_use]
    pub fn clipboard_clear_enabled(&self) -> bool {
        self.clipboard_clear_enabled
    }

    /// Wipe-after-copy timeout in seconds (when enabled).
    #[must_use]
    pub fn clipboard_clear_secs(&self) -> u32 {
        self.clipboard_clear_secs
    }
}

impl Default for VaultSettings {
    fn default() -> Self {
        // Defaults pinned by DESIGN.md §5 settings table:
        // auto-lock and clipboard-clear are off by default; timeouts
        // are 300s and 20s respectively.
        Self {
            auto_lock_enabled: false,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
        }
    }
}

/// Bincode v2 configuration locked to DESIGN.md §4.3.
#[allow(dead_code)] // Wired up by storage::Store (Phase E continuation).
fn bincode_config() -> Configuration<LittleEndian, Fixint, Limit<MAX_PAYLOAD_BYTES>> {
    bincode::config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_PAYLOAD_BYTES>()
}

/// Encode a `VaultPayload` to its on-disk byte representation.
///
/// Rejects payloads whose encoded size exceeds the §4.3 16 MiB cap
/// with `invalid_payload { reason: "exceeds_size_limit" }`.
#[allow(dead_code)] // Wired up by storage::Store (Phase E continuation).
pub(crate) fn encode_vault_payload(payload: &VaultPayload) -> Result<Vec<u8>, PaladinError> {
    let bytes = bincode::encode_to_vec(payload, bincode_config()).map_err(|_| {
        PaladinError::InvalidPayload {
            reason: "encode_failed",
        }
    })?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(PaladinError::InvalidPayload {
            reason: "exceeds_size_limit",
        });
    }
    Ok(bytes)
}

/// Decode bytes produced by `encode_vault_payload`.
///
/// Enforces the §4.3 contract:
/// - Input slices longer than 16 MiB are rejected before decoding.
/// - Trailing bytes after the encoded `VaultPayload` are rejected.
/// - The 16 MiB limit is also enforced inside bincode for any
///   length-prefixed sub-collection that would exceed it.
#[allow(dead_code)] // Wired up by storage::Store (Phase E continuation).
pub(crate) fn decode_vault_payload(bytes: &[u8]) -> Result<VaultPayload, PaladinError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(PaladinError::InvalidPayload {
            reason: "exceeds_size_limit",
        });
    }
    let (payload, consumed) =
        bincode::decode_from_slice::<VaultPayload, _>(bytes, bincode_config()).map_err(|err| {
            match err {
                DecodeError::LimitExceeded => PaladinError::InvalidPayload {
                    reason: "exceeds_size_limit",
                },
                _ => PaladinError::InvalidPayload {
                    reason: "decode_failed",
                },
            }
        })?;
    if consumed != bytes.len() {
        return Err(PaladinError::InvalidPayload {
            reason: "trailing_bytes",
        });
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::domain::validation::{validate_manual, AccountInput};
    use crate::domain::{Account, AccountId, AccountKindInput, Algorithm, IconHintInput, OtpKind};
    use crate::domain::{Secret, ValidatedAccount};
    use secrecy::SecretString;
    use std::time::SystemTime;

    fn fixed_time(unix_secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(unix_secs)
    }

    fn fixture_account(seed: u8, label: &str, kind: OtpKind) -> Account {
        // Build an account with deterministic id/secret/timestamps so
        // round-trip and golden tests are reproducible.
        Account {
            id: AccountId::from_bytes([seed; 16]),
            label: label.to_string(),
            issuer: Some("Example".to_string()),
            secret: Secret::from_bytes(vec![seed; 20]),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind,
            icon_hint: Some("example".to_string()),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        }
    }

    fn validated_via_input(label: &str) -> Account {
        // Smoke-test that accounts produced by the public validation
        // entry point also round-trip — covers any field the fixture
        // builder might miss.
        let input = AccountInput {
            label: label.to_string(),
            issuer: Some("Acme".to_string()),
            secret: SecretString::from("JBSWY3DPEHPK3PXP"),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: AccountKindInput::Totp,
            period_secs: Some(30),
            counter: None,
            icon_hint: IconHintInput::Default,
        };
        let ValidatedAccount { account, .. } =
            validate_manual(input, fixed_time(1_714_824_000)).unwrap();
        account
    }

    #[test]
    fn roundtrip_default_payload_preserves_settings_and_empty_accounts() {
        let payload = VaultPayload {
            accounts: Vec::new(),
            settings: VaultSettings::default(),
        };
        let bytes = encode_vault_payload(&payload).unwrap();
        let decoded = decode_vault_payload(&bytes).unwrap();
        assert_eq!(decoded.accounts.len(), 0);
        assert_eq!(decoded.settings, VaultSettings::default());
    }

    #[test]
    fn roundtrip_with_validated_account() {
        let account = validated_via_input("alice@example.com");
        let payload = VaultPayload {
            accounts: vec![account.clone()],
            settings: VaultSettings::default(),
        };
        let bytes = encode_vault_payload(&payload).unwrap();
        let decoded = decode_vault_payload(&bytes).unwrap();
        assert_eq!(decoded.accounts.len(), 1);
        let got = &decoded.accounts[0];
        assert_eq!(got.id(), account.id());
        assert_eq!(got.label(), account.label());
        assert_eq!(got.issuer(), account.issuer());
        assert_eq!(got.algorithm(), account.algorithm());
        assert_eq!(got.digits(), account.digits());
        assert_eq!(got.period(), account.period());
        assert_eq!(got.counter(), account.counter());
        assert_eq!(got.icon_hint(), account.icon_hint());
        assert_eq!(got.created_at(), account.created_at());
        assert_eq!(got.updated_at(), account.updated_at());
        assert_eq!(
            got.secret().expose_secret(),
            account.secret().expose_secret()
        );
    }

    #[test]
    fn roundtrip_preserves_account_insertion_order() {
        // Pins `VaultPayload.accounts` as an ordered `Vec<Account>`
        // (not, say, a `HashMap<AccountId, Account>`). Adding A, B, C
        // must yield A, B, C after a save/reopen cycle.
        let a = fixture_account(0xaa, "alice", OtpKind::Totp { period: 30 });
        let b = fixture_account(0xbb, "bob", OtpKind::Totp { period: 30 });
        let c = fixture_account(0xcc, "carol", OtpKind::Hotp { counter: 7 });
        let payload = VaultPayload {
            accounts: vec![a.clone(), b.clone(), c.clone()],
            settings: VaultSettings::default(),
        };
        let bytes = encode_vault_payload(&payload).unwrap();
        let decoded = decode_vault_payload(&bytes).unwrap();
        let labels: Vec<&str> = decoded.accounts.iter().map(Account::label).collect();
        assert_eq!(labels, vec!["alice", "bob", "carol"]);
        assert_eq!(decoded.accounts[0].id(), a.id());
        assert_eq!(decoded.accounts[1].id(), b.id());
        assert_eq!(decoded.accounts[2].id(), c.id());
        assert_eq!(decoded.accounts[2].counter(), Some(7));
    }

    #[test]
    fn encoding_is_deterministic_byte_for_byte() {
        // Encoding the same `VaultPayload` value twice must produce
        // bit-identical bytes. This pins the §4.3 wire format so a
        // future swap of `Vec<Account>` for `HashMap<AccountId,
        // Account>`, an unstable field reorder, or any other source
        // of nondeterminism fails the test instead of silently
        // breaking AAD reproducibility.
        let payload = VaultPayload {
            accounts: vec![
                fixture_account(0x01, "first", OtpKind::Totp { period: 30 }),
                fixture_account(0x02, "second", OtpKind::Hotp { counter: 42 }),
            ],
            settings: VaultSettings::default(),
        };
        let a = encode_vault_payload(&payload).unwrap();
        let b = encode_vault_payload(&payload).unwrap();
        assert_eq!(a, b, "encoding is non-deterministic");
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let payload = VaultPayload {
            accounts: Vec::new(),
            settings: VaultSettings::default(),
        };
        let mut bytes = encode_vault_payload(&payload).unwrap();
        bytes.extend_from_slice(b"junk");
        let err = decode_vault_payload(&bytes).unwrap_err();
        match err {
            PaladinError::InvalidPayload { reason } => {
                assert_eq!(reason, "trailing_bytes");
            }
            other => panic!("expected invalid_payload trailing_bytes, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_oversize_input_pre_decode() {
        // A slice larger than 16 MiB must be rejected before bincode
        // touches it, so a hostile or corrupt vault file cannot force
        // the decoder to allocate against attacker-controlled length
        // prefixes.
        let oversize = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let err = decode_vault_payload(&oversize).unwrap_err();
        match err {
            PaladinError::InvalidPayload { reason } => {
                assert_eq!(reason, "exceeds_size_limit");
            }
            other => panic!("expected invalid_payload exceeds_size_limit, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_size_limit_inside_bincode() {
        // Even when the outer slice fits, a length-prefix inside the
        // payload that would expand past 16 MiB must be rejected by
        // bincode's `with_limit` and surfaced as `exceeds_size_limit`.
        // Construct a deliberately oversized inner length: 8-byte u64
        // claiming a Vec<Account> of `MAX_PAYLOAD_BYTES + 1` entries,
        // followed by no actual data.
        let too_big: u64 = (MAX_PAYLOAD_BYTES as u64) + 1;
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&too_big.to_le_bytes());
        let err = decode_vault_payload(&bytes).unwrap_err();
        match err {
            PaladinError::InvalidPayload { reason } => {
                assert_eq!(reason, "exceeds_size_limit");
            }
            other => panic!("expected invalid_payload exceeds_size_limit, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let payload = VaultPayload {
            accounts: vec![fixture_account(0x42, "x", OtpKind::Totp { period: 30 })],
            settings: VaultSettings::default(),
        };
        let bytes = encode_vault_payload(&payload).unwrap();
        let truncated = &bytes[..bytes.len() - 1];
        let err = decode_vault_payload(truncated).unwrap_err();
        match err {
            PaladinError::InvalidPayload { reason } => {
                assert_eq!(reason, "decode_failed");
            }
            other => panic!("expected invalid_payload decode_failed, got {other:?}"),
        }
    }

    #[test]
    fn vault_settings_default_matches_design_table() {
        // DESIGN.md §5 settings table pins the off-by-default
        // behavior and the timeout defaults (300s / 20s).
        let s = VaultSettings::default();
        assert!(!s.auto_lock_enabled());
        assert_eq!(s.auto_lock_timeout_secs(), 300);
        assert!(!s.clipboard_clear_enabled());
        assert_eq!(s.clipboard_clear_secs(), 20);
    }

    #[test]
    fn golden_fixture_byte_string() {
        // Golden fixture: pins the exact §4.3 wire format. If a
        // future bincode upgrade or field reorder changes the bytes,
        // this test fails immediately rather than silently rotating
        // the format and breaking on-disk vaults.
        //
        // Composition (little-endian, fixed-int):
        //   accounts: Vec<Account> length = 1   (u64 LE = 8 bytes)
        //     id: [u8; 16]                       = 16 bytes of 0x10
        //     label: "x"                          (u64 LE len=1 + 'x')
        //     issuer: Some("Example")             (1 tag + u64 LE len=7 + bytes)
        //     secret: Vec<u8> len=4               (u64 LE len + 4 bytes)
        //     algorithm: Sha1                     (u32 LE = 0)
        //     digits: 6                           (u8 = 6)
        //     kind: Totp { period: 30 }           (u32 LE tag=0 + u32 LE 30)
        //     icon_hint: None                     (1 tag = 0)
        //     created_at: 1                       (u64 LE)
        //     updated_at: 2                       (u64 LE)
        //   settings: defaults
        //     auto_lock_enabled: false            (u8 = 0)
        //     auto_lock_timeout_secs: 300         (u32 LE)
        //     clipboard_clear_enabled: false      (u8 = 0)
        //     clipboard_clear_secs: 20            (u32 LE)
        let account = Account {
            id: AccountId::from_bytes([0x10; 16]),
            label: "x".to_string(),
            issuer: Some("Example".to_string()),
            secret: Secret::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: OtpKind::Totp { period: 30 },
            icon_hint: None,
            created_at: 1,
            updated_at: 2,
        };
        let payload = VaultPayload {
            accounts: vec![account],
            settings: VaultSettings::default(),
        };
        let actual = encode_vault_payload(&payload).unwrap();

        let mut expected: Vec<u8> = Vec::new();
        // accounts vec length (u64 LE = 1)
        expected.extend_from_slice(&1u64.to_le_bytes());
        // AccountId 16 bytes
        expected.extend_from_slice(&[0x10; 16]);
        // label "x" length + bytes
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(b"x");
        // issuer Some("Example")
        expected.push(1);
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(b"Example");
        // secret bytes
        expected.extend_from_slice(&4u64.to_le_bytes());
        expected.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        // algorithm Sha1 (u32 LE = 0)
        expected.extend_from_slice(&0u32.to_le_bytes());
        // digits = 6
        expected.push(6);
        // kind Totp variant tag (u32 LE = 0) + period (u32 LE = 30)
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&30u32.to_le_bytes());
        // icon_hint None
        expected.push(0);
        // created_at = 1, updated_at = 2
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(&2u64.to_le_bytes());
        // VaultSettings defaults
        expected.push(0); // auto_lock_enabled = false
        expected.extend_from_slice(&300u32.to_le_bytes());
        expected.push(0); // clipboard_clear_enabled = false
        expected.extend_from_slice(&20u32.to_le_bytes());

        assert_eq!(
            actual,
            expected,
            "golden fixture mismatch: actual.len={} expected.len={}",
            actual.len(),
            expected.len()
        );

        // Round-trip the golden bytes back to a `VaultPayload`.
        let decoded = decode_vault_payload(&expected).unwrap();
        assert_eq!(decoded.accounts.len(), 1);
        let got = &decoded.accounts[0];
        assert_eq!(got.label(), "x");
        assert_eq!(got.issuer(), Some("Example"));
        assert_eq!(got.secret().expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(got.created_at(), 1);
        assert_eq!(got.updated_at(), 2);
    }
}
