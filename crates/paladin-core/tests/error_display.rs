// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase K — `PaladinError` `Display` snapshot per variant.
//
// `error_serde.rs` pins the machine surface (`error_kind` + extra
// fields). Nothing else pins the human-readable surface that the CLI
// / TUI / GUI render. A regression that changes capitalization,
// punctuation, or a field's render order silently shifts every
// front-end's user-visible text without failing any test. This file
// closes that gap by byte-comparing `format!("{error}")` against a
// committed fixture per variant.
//
// The variant fixture set is intentionally duplicated from
// `tests/error_serde.rs`'s `one_per_variant()` helper — same
// duplication precedent as `tests/error_matrix.rs`.

use std::io::Error as IoError;
use std::path::PathBuf;

use paladin_core::{
    AccountId, AccountKindSummary, AccountSummary, Algorithm, ErrorKind, PaladinError,
    PermissionSubject, TimeRangeKind, VaultMode,
};

fn fixture_summary() -> AccountSummary {
    AccountSummary {
        id: AccountId::new(),
        issuer: Some("issuer".to_string()),
        label: "label".to_string(),
        kind: AccountKindSummary::Hotp,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: None,
        counter: Some(0),
        icon_hint: None,
        created_at: 0,
        updated_at: 0,
    }
}

#[allow(clippy::too_many_lines)] // mechanical fixture, one block per variant
fn one_per_variant() -> Vec<(PaladinError, ErrorKind)> {
    vec![
        (
            PaladinError::ValidationError {
                field: "x",
                reason: "y".into(),
                source_index: None,
                decoded_len: None,
                recommended_min: None,
                entry_type: None,
            },
            ErrorKind::ValidationError,
        ),
        (
            PaladinError::InvalidPassphrase {
                reason: "zero_length",
            },
            ErrorKind::InvalidPassphrase,
        ),
        (
            PaladinError::InvalidState {
                operation: "set_passphrase",
                state: "already_encrypted",
            },
            ErrorKind::InvalidState,
        ),
        (PaladinError::VaultMissing, ErrorKind::VaultMissing),
        (PaladinError::VaultExists, ErrorKind::VaultExists),
        (
            PaladinError::UnsafePermissions {
                path: PathBuf::from("/tmp/x"),
                subject: PermissionSubject::VaultFile,
                actual_mode: "0644".into(),
                expected_mode: "0600".into(),
            },
            ErrorKind::UnsafePermissions,
        ),
        (
            PaladinError::WrongVaultLock {
                expected: VaultMode::Encrypted,
                actual: VaultMode::Plaintext,
            },
            ErrorKind::WrongVaultLock,
        ),
        (PaladinError::DecryptFailed, ErrorKind::DecryptFailed),
        (PaladinError::InvalidHeader, ErrorKind::InvalidHeader),
        (
            PaladinError::InvalidPayload {
                reason: "decode_failed",
            },
            ErrorKind::InvalidPayload,
        ),
        (
            PaladinError::UnsupportedFormatVersion { format_ver: 99 },
            ErrorKind::UnsupportedFormatVersion,
        ),
        (
            PaladinError::KdfParamsOutOfBounds {
                m_kib: 1,
                t: 1,
                p: 1,
            },
            ErrorKind::KdfParamsOutOfBounds,
        ),
        (
            PaladinError::UnsupportedImportFormat {
                format: "unknown".into(),
            },
            ErrorKind::UnsupportedImportFormat,
        ),
        (
            PaladinError::UnsupportedPlaintextVault,
            ErrorKind::UnsupportedPlaintextVault,
        ),
        (
            PaladinError::UnsupportedEncryptedAegis,
            ErrorKind::UnsupportedEncryptedAegis,
        ),
        (
            PaladinError::UnsupportedAegisEntryType {
                source_index: 0,
                entry_type: "steam".into(),
            },
            ErrorKind::UnsupportedAegisEntryType,
        ),
        (
            PaladinError::NoEntriesToImport,
            ErrorKind::NoEntriesToImport,
        ),
        (
            PaladinError::CounterOverflow {
                account: fixture_summary(),
            },
            ErrorKind::CounterOverflow,
        ),
        (
            PaladinError::TimeRange {
                operation: "totp_code",
                kind: TimeRangeKind::Overflow,
            },
            ErrorKind::TimeRange,
        ),
        (
            PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            },
            ErrorKind::SaveNotCommitted,
        ),
        (
            PaladinError::SaveDurabilityUnconfirmed,
            ErrorKind::SaveDurabilityUnconfirmed,
        ),
        (
            PaladinError::IoError {
                operation: "read_vault_file",
                source: IoError::other("x"),
            },
            ErrorKind::IoError,
        ),
    ]
}

#[test]
fn paladin_error_display_matches_fixture_per_variant() {
    let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("error_display");

    for (err, kind) in one_per_variant() {
        let actual = format!("{err}");
        let path = fixtures_dir.join(format!("{}.txt", kind.as_str()));
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("missing fixture: {}", path.display()));
        assert_eq!(
            actual,
            expected,
            "Display drift on ErrorKind::{kind:?} ({}): expected fixture at {} to match",
            kind.as_str(),
            path.display(),
        );
    }
}
