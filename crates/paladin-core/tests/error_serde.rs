// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire-format guards for the off-by-default `error-serde` cargo
//! feature. The CLI's `--json` envelopes (docs/DESIGN.md §5) consume these
//! impls, so any drift would silently change a public scripting
//! contract. Every test below pins the shape with `serde_json::json!`.

#![cfg(feature = "error-serde")]

use std::path::PathBuf;

use paladin_core::{
    AccountId, AccountKindSummary, AccountSummary, Algorithm, Code, ErrorKind, ImportConflict,
    ImportReport, ImportWarning, PaladinError, PermissionSubject, TimeRangeKind, ValidationWarning,
    VaultMode, VaultSettings,
};
use serde_json::json;

fn fixture_summary() -> AccountSummary {
    AccountSummary {
        id: AccountId::new(),
        issuer: Some("GitHub".to_string()),
        label: "ben@example.com".to_string(),
        kind: AccountKindSummary::Totp,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: Some(30),
        counter: None,
        icon_hint: Some("github".to_string()),
        created_at: 1_777_939_200,
        updated_at: 1_777_939_200,
    }
}

#[test]
fn error_kind_serializes_as_snake_case_strings() {
    let cases = [
        (ErrorKind::ValidationError, "validation_error"),
        (ErrorKind::InvalidPassphrase, "invalid_passphrase"),
        (ErrorKind::InvalidState, "invalid_state"),
        (ErrorKind::VaultMissing, "vault_missing"),
        (ErrorKind::VaultExists, "vault_exists"),
        (ErrorKind::UnsafePermissions, "unsafe_permissions"),
        (ErrorKind::WrongVaultLock, "wrong_vault_lock"),
        (ErrorKind::DecryptFailed, "decrypt_failed"),
        (ErrorKind::InvalidHeader, "invalid_header"),
        (ErrorKind::InvalidPayload, "invalid_payload"),
        (
            ErrorKind::UnsupportedFormatVersion,
            "unsupported_format_version",
        ),
        (ErrorKind::KdfParamsOutOfBounds, "kdf_params_out_of_bounds"),
        (
            ErrorKind::UnsupportedImportFormat,
            "unsupported_import_format",
        ),
        (
            ErrorKind::UnsupportedPlaintextVault,
            "unsupported_plaintext_vault",
        ),
        (
            ErrorKind::UnsupportedEncryptedAegis,
            "unsupported_encrypted_aegis",
        ),
        (
            ErrorKind::UnsupportedAegisEntryType,
            "unsupported_aegis_entry_type",
        ),
        (ErrorKind::NoEntriesToImport, "no_entries_to_import"),
        (ErrorKind::CounterOverflow, "counter_overflow"),
        (ErrorKind::TimeRange, "time_range"),
        (ErrorKind::SaveNotCommitted, "save_not_committed"),
        (
            ErrorKind::SaveDurabilityUnconfirmed,
            "save_durability_unconfirmed",
        ),
        (ErrorKind::IoError, "io_error"),
    ];
    for (kind, expected) in cases {
        let actual = serde_json::to_value(kind).unwrap();
        assert_eq!(actual, json!(expected), "ErrorKind::{kind:?}");
        // The Serialize impl must agree with `as_str()`.
        assert_eq!(kind.as_str(), expected);
    }
}

#[test]
fn vault_mode_serializes_lowercase() {
    assert_eq!(
        serde_json::to_value(VaultMode::Plaintext).unwrap(),
        json!("plaintext")
    );
    assert_eq!(
        serde_json::to_value(VaultMode::Encrypted).unwrap(),
        json!("encrypted")
    );
}

#[test]
fn permission_subject_serializes_snake_case() {
    assert_eq!(
        serde_json::to_value(PermissionSubject::VaultDir).unwrap(),
        json!("vault_dir")
    );
    assert_eq!(
        serde_json::to_value(PermissionSubject::VaultFile).unwrap(),
        json!("vault_file")
    );
    assert_eq!(
        serde_json::to_value(PermissionSubject::BackupFile).unwrap(),
        json!("backup_file")
    );
}

#[test]
fn time_range_kind_serializes_snake_case() {
    assert_eq!(
        serde_json::to_value(TimeRangeKind::PreEpoch).unwrap(),
        json!("pre_epoch")
    );
    assert_eq!(
        serde_json::to_value(TimeRangeKind::Overflow).unwrap(),
        json!("overflow")
    );
    assert_eq!(
        serde_json::to_value(TimeRangeKind::OutOfRange).unwrap(),
        json!("out_of_range")
    );
}

#[test]
fn algorithm_serializes_lowercase() {
    assert_eq!(
        serde_json::to_value(Algorithm::Sha1).unwrap(),
        json!("sha1")
    );
    assert_eq!(
        serde_json::to_value(Algorithm::Sha256).unwrap(),
        json!("sha256")
    );
    assert_eq!(
        serde_json::to_value(Algorithm::Sha512).unwrap(),
        json!("sha512")
    );
}

#[test]
fn account_kind_summary_serializes_lowercase() {
    assert_eq!(
        serde_json::to_value(AccountKindSummary::Totp).unwrap(),
        json!("totp")
    );
    assert_eq!(
        serde_json::to_value(AccountKindSummary::Hotp).unwrap(),
        json!("hotp")
    );
}

#[test]
fn import_conflict_serializes_snake_case() {
    assert_eq!(
        serde_json::to_value(ImportConflict::Skip).unwrap(),
        json!("skip")
    );
    assert_eq!(
        serde_json::to_value(ImportConflict::Replace).unwrap(),
        json!("replace")
    );
    assert_eq!(
        serde_json::to_value(ImportConflict::Append).unwrap(),
        json!("append")
    );
}

#[test]
fn account_summary_matches_design_5_shape() {
    let summary = fixture_summary();
    let id_str = summary.id.to_hyphenated();
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(
        value,
        json!({
            "id": id_str,
            "issuer": "GitHub",
            "label": "ben@example.com",
            "kind": "totp",
            "algorithm": "sha1",
            "digits": 6,
            "period": 30,
            "counter": null,
            "icon_hint": "github",
            "created_at": 1_777_939_200_u64,
            "updated_at": 1_777_939_200_u64,
        })
    );
}

#[test]
fn account_summary_hotp_omits_period_and_carries_counter() {
    let summary = AccountSummary {
        kind: AccountKindSummary::Hotp,
        period: None,
        counter: Some(42),
        ..fixture_summary()
    };
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(value["kind"], json!("hotp"));
    assert_eq!(value["period"], json!(null));
    assert_eq!(value["counter"], json!(42));
}

#[test]
fn account_summary_null_issuer_and_icon_serialize_as_null() {
    let summary = AccountSummary {
        issuer: None,
        icon_hint: None,
        ..fixture_summary()
    };
    let value = serde_json::to_value(&summary).unwrap();
    assert_eq!(value["issuer"], json!(null));
    assert_eq!(value["icon_hint"], json!(null));
}

#[test]
fn code_serializes_with_optional_timing_fields() {
    let totp = Code {
        code: "012345".to_string(),
        valid_from: Some(1_777_939_200),
        valid_until: Some(1_777_939_230),
        seconds_remaining: Some(7),
        counter_used: None,
    };
    assert_eq!(
        serde_json::to_value(&totp).unwrap(),
        json!({
            "code": "012345",
            "valid_from": 1_777_939_200_u64,
            "valid_until": 1_777_939_230_u64,
            "seconds_remaining": 7,
            "counter_used": null,
        })
    );

    let hotp = Code {
        code: "987654".to_string(),
        valid_from: None,
        valid_until: None,
        seconds_remaining: None,
        counter_used: Some(99),
    };
    assert_eq!(
        serde_json::to_value(&hotp).unwrap(),
        json!({
            "code": "987654",
            "valid_from": null,
            "valid_until": null,
            "seconds_remaining": null,
            "counter_used": 99_u64,
        })
    );
}

#[test]
fn vault_settings_emits_nested_shape() {
    let settings = VaultSettings::default();
    assert_eq!(
        serde_json::to_value(settings).unwrap(),
        json!({
            "auto_lock":  { "enabled": false, "timeout_secs": 300 },
            "clipboard":  { "clear_enabled": false, "clear_secs": 20 },
        })
    );
}

#[test]
fn validation_warning_short_secret_emits_kind_tag() {
    let w = ValidationWarning::ShortSecret {
        decoded_len: 10,
        recommended_min: 16,
    };
    assert_eq!(
        serde_json::to_value(&w).unwrap(),
        json!({
            "kind": "short_secret",
            "decoded_len": 10,
            "recommended_min": 16,
        })
    );
}

#[test]
fn import_warning_flattens_validation_warning_fields() {
    let w = ImportWarning {
        source_index: 3,
        warning: ValidationWarning::ShortSecret {
            decoded_len: 10,
            recommended_min: 16,
        },
    };
    assert_eq!(
        serde_json::to_value(&w).unwrap(),
        json!({
            "source_index": 3,
            "kind": "short_secret",
            "decoded_len": 10,
            "recommended_min": 16,
        })
    );
}

#[test]
fn import_report_serializes_all_fields() {
    let id = AccountId::new();
    let report = ImportReport {
        imported: 2,
        skipped: 1,
        replaced: 0,
        appended: 1,
        accounts: vec![id],
        warnings: Vec::new(),
    };
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["imported"], json!(2));
    assert_eq!(value["skipped"], json!(1));
    assert_eq!(value["replaced"], json!(0));
    assert_eq!(value["appended"], json!(1));
    assert_eq!(value["accounts"], json!([id.to_hyphenated()]));
    assert_eq!(value["warnings"], json!([]));
}

#[test]
fn paladin_error_validation_envelope_skips_none_options() {
    let err = PaladinError::ValidationError {
        field: "secret",
        reason: "too_short".to_string(),
        source_index: None,
        decoded_len: Some(10),
        recommended_min: Some(16),
        entry_type: None,
    };
    assert_eq!(
        serde_json::to_value(&err).unwrap(),
        json!({
            "error_kind": "validation_error",
            "field": "secret",
            "reason": "too_short",
            "decoded_len": 10,
            "recommended_min": 16,
        })
    );
}

#[test]
fn paladin_error_unit_variants_carry_only_kind() {
    for (err, expected_kind) in [
        (PaladinError::VaultMissing, "vault_missing"),
        (PaladinError::VaultExists, "vault_exists"),
        (PaladinError::DecryptFailed, "decrypt_failed"),
        (PaladinError::InvalidHeader, "invalid_header"),
        (
            PaladinError::UnsupportedPlaintextVault,
            "unsupported_plaintext_vault",
        ),
        (
            PaladinError::UnsupportedEncryptedAegis,
            "unsupported_encrypted_aegis",
        ),
        (PaladinError::NoEntriesToImport, "no_entries_to_import"),
        (
            PaladinError::SaveDurabilityUnconfirmed,
            "save_durability_unconfirmed",
        ),
    ] {
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(
            value,
            json!({ "error_kind": expected_kind }),
            "PaladinError::{err:?}"
        );
    }
}

#[test]
fn paladin_error_unsafe_permissions_envelope() {
    let err = PaladinError::UnsafePermissions {
        path: PathBuf::from("/home/u/.local/share/paladin"),
        subject: PermissionSubject::VaultDir,
        actual_mode: "0755".to_string(),
        expected_mode: "0700".to_string(),
    };
    assert_eq!(
        serde_json::to_value(&err).unwrap(),
        json!({
            "error_kind": "unsafe_permissions",
            "path": "/home/u/.local/share/paladin",
            "subject": "vault_dir",
            "actual_mode": "0755",
            "expected_mode": "0700",
        })
    );
}

#[test]
fn paladin_error_wrong_vault_lock_envelope() {
    let err = PaladinError::WrongVaultLock {
        expected: VaultMode::Encrypted,
        actual: VaultMode::Plaintext,
    };
    assert_eq!(
        serde_json::to_value(&err).unwrap(),
        json!({
            "error_kind": "wrong_vault_lock",
            "expected": "encrypted",
            "actual": "plaintext",
        })
    );
}

#[test]
fn paladin_error_kdf_params_out_of_bounds_envelope() {
    let err = PaladinError::KdfParamsOutOfBounds {
        m_kib: 99,
        t: 10,
        p: 1,
    };
    assert_eq!(
        serde_json::to_value(&err).unwrap(),
        json!({
            "error_kind": "kdf_params_out_of_bounds",
            "m_kib": 99,
            "t": 10,
            "p": 1,
        })
    );
}

#[test]
fn paladin_error_save_not_committed_includes_optional_backup_path() {
    let no_backup = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    assert_eq!(
        serde_json::to_value(&no_backup).unwrap(),
        json!({
            "error_kind": "save_not_committed",
            "committed": false,
        })
    );

    let with_backup = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: Some(PathBuf::from("/path/to/vault.bin.bak")),
    };
    assert_eq!(
        serde_json::to_value(&with_backup).unwrap(),
        json!({
            "error_kind": "save_not_committed",
            "committed": false,
            "backup_path": "/path/to/vault.bin.bak",
        })
    );
}

#[test]
fn paladin_error_io_error_skips_underlying_source() {
    let err = PaladinError::IoError {
        operation: "read_vault_file",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "EACCES"),
    };
    let value = serde_json::to_value(&err).unwrap();
    assert_eq!(
        value,
        json!({
            "error_kind": "io_error",
            "operation": "read_vault_file",
        })
    );
    // Belt-and-braces: the underlying message must not leak into JSON.
    let s = serde_json::to_string(&err).unwrap();
    assert!(!s.contains("EACCES"), "io::Error message leaked: {s}");
}

#[test]
fn paladin_error_counter_overflow_includes_account_summary() {
    let summary = fixture_summary();
    let err = PaladinError::CounterOverflow {
        account: summary.clone(),
    };
    let value = serde_json::to_value(&err).unwrap();
    assert_eq!(value["error_kind"], json!("counter_overflow"));
    assert_eq!(value["account"], serde_json::to_value(&summary).unwrap());
}

/// One representative `PaladinError` value per variant. Used by the
/// round-trip test below to guard `kind() == as_str(serialized_tag)`.
#[allow(clippy::too_many_lines)] // mechanical fixture, one line per variant
fn one_per_variant() -> Vec<(PaladinError, ErrorKind)> {
    use std::io::Error as IoError;
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
fn paladin_error_kind_round_trips_through_serialize_for_every_variant() {
    for (err, kind) in one_per_variant() {
        let value = serde_json::to_value(&err).unwrap();
        let actual = value["error_kind"].as_str().unwrap();
        assert_eq!(actual, kind.as_str(), "kind/serialize drift on {err:?}");
    }
}

// Account / Secret remain !Serialize even with this feature enabled;
// that contract is enforced by the trybuild compile-fail tests in
// `tests/trybuild/` (run by `tests/trybuild_audit.rs`), which compile
// `tests/trybuild/{account,secret}_not_serialize.rs` and assert they
// *fail* to build.
