// SPDX-License-Identifier: AGPL-3.0-or-later
//
// §5 / §4.7 error-kind matrix (Phase J).
//
// Produces every core-returnable §5 `error_kind` at least once and
// asserts the kind plus every stable extra field. Coverage rows
// intentionally duplicate per-feature test files — this file's job
// is to fail loudly when a variant is renamed, an extra field is
// dropped from a JSON-relevant variant, or a stable string
// (`invalid_state.operation`/`state`, `time_range.operation`,
// `io_error.operation`) is silently changed.
//
// Where a row is reachable from the public API, the test triggers it
// through a real call. Where production requires platform / filesystem
// fault injection that lives behind a separate cargo feature, the test
// constructs the variant directly so the operation string and field
// shape are still pinned.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::import;
use paladin_core::{
    detect, parse_account_query, parse_otpauth, parse_setting_patch, validate_manual, Account,
    AccountId, AccountInput, AccountKindInput, AccountKindSummary, Algorithm, Argon2Params,
    EncryptionOptions, ErrorKind, IconHintInput, ImportFormat, ImportOptions, PaladinError,
    PermissionSubject, Store, TimeRangeKind, VaultInit, VaultLock, VaultMode,
};
use secrecy::SecretString;
use tempfile::TempDir;

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn make_hotp_account(label: &str, counter: u64) -> Account {
    let uri = format!("otpauth://hotp/{label}?secret=JBSWY3DPEHPK3PXP&counter={counter}",);
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn vault_test_dir() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod tempdir 0700");
    dir
}

fn cheap_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    }
}

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(pp(passphrase), cheap_params())
        .expect("cheap_params are in §4.4 bounds and the passphrase is non-empty")
}

fn manual_input(label: &str) -> AccountInput {
    AccountInput {
        label: label.to_string(),
        issuer: Some("Acme".to_string()),
        secret: pp("JBSWY3DPEHPK3PXP"),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: Some(30),
        counter: None,
        icon_hint: IconHintInput::Default,
    }
}

// -----------------------------------------------------------------------------
// validation_error — one row per field/reason production site (§4.6 / §4.7)
// -----------------------------------------------------------------------------

#[test]
fn validation_error_manual_add_label_empty_carries_field_and_reason() {
    let mut input = manual_input("");
    input.label = String::new();
    let err = validate_manual(input, fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let PaladinError::ValidationError {
        field,
        reason,
        source_index,
        decoded_len,
        recommended_min,
        entry_type,
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "label");
    assert_eq!(reason, "empty");
    assert!(source_index.is_none());
    assert!(decoded_len.is_none());
    assert!(recommended_min.is_none());
    assert!(entry_type.is_none());
}

#[test]
fn validation_error_otpauth_parse_missing_scheme() {
    let err = parse_otpauth("not-a-uri", fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let PaladinError::ValidationError { field, reason, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "uri");
    assert_eq!(reason, "missing_scheme");
}

#[test]
fn validation_error_aegis_import_missing_required_field_carries_source_index() {
    // Aegis row 0 missing required `info.secret`. Per §4.6 the importer
    // tags the row index on the underlying validation error.
    let json = br#"{
        "version": 1,
        "header": {"slots": null, "params": null},
        "db": {
            "version": 2,
            "entries": [
                {
                    "type": "totp",
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "name": "alice",
                    "issuer": "",
                    "note": "",
                    "icon": null,
                    "icon_mime": null,
                    "info": {"algo": "SHA1", "digits": 6, "period": 30}
                }
            ]
        }
    }"#;
    let err = import::aegis_plaintext(json, fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let PaladinError::ValidationError {
        field,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "secret");
    assert_eq!(source_index, Some(0));
}

#[test]
fn validation_error_qr_image_too_large_rejected_pre_decode() {
    // §4.6: `qr_image_bytes` rejects RGBA buffers above the cap with
    // `validation_error { field: "qr_image", reason: "image_too_large" }`
    // before any decode work.
    let huge_dim = 16_384u32;
    let bytes = vec![0u8; 4]; // body length is checked inside; cap check uses dimensions.
    let err = import::qr_image_bytes(huge_dim, huge_dim, &bytes, fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let PaladinError::ValidationError { field, reason, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "qr_image");
    assert_eq!(reason, "image_too_large");
}

#[test]
fn validation_error_settings_parse_unknown_key() {
    let err = parse_setting_patch("auto_lock.unknown_subkey", "true").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let PaladinError::ValidationError { field, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "key");
}

#[test]
fn validation_error_query_parse_short_id_prefix() {
    let err = parse_account_query("id:abc").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let PaladinError::ValidationError { field, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "query");
}

// -----------------------------------------------------------------------------
// invalid_passphrase
// -----------------------------------------------------------------------------

#[test]
fn invalid_passphrase_zero_length_carries_reason() {
    let err = EncryptionOptions::with_params(pp(""), cheap_params()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidPassphrase);
    let PaladinError::InvalidPassphrase { reason } = err else {
        panic!("expected InvalidPassphrase, got {err:?}");
    };
    assert_eq!(reason, "zero_length");
}

// -----------------------------------------------------------------------------
// invalid_state — every stable §4.7 operation/state pair
// -----------------------------------------------------------------------------

fn assert_invalid_state(err: &PaladinError, expected_op: &str, expected_state: &str) {
    assert_eq!(err.kind(), ErrorKind::InvalidState, "{err:?}");
    match err {
        PaladinError::InvalidState { operation, state } => {
            assert_eq!(*operation, expected_op);
            assert_eq!(*state, expected_state);
        }
        other => panic!("expected InvalidState, got {other:?}"),
    }
}

#[test]
fn invalid_state_set_passphrase_already_encrypted() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let err = vault
        .set_passphrase(&store, cheap_options("hunter3"))
        .unwrap_err();
    assert_invalid_state(&err, "set_passphrase", "already_encrypted");
}

#[test]
fn invalid_state_change_passphrase_not_encrypted() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let err = vault
        .change_passphrase(&store, cheap_options("hunter2"))
        .unwrap_err();
    assert_invalid_state(&err, "change_passphrase", "not_encrypted");
}

#[test]
fn invalid_state_remove_passphrase_not_encrypted() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let err = vault.remove_passphrase(&store).unwrap_err();
    assert_invalid_state(&err, "remove_passphrase", "not_encrypted");
}

#[test]
fn invalid_state_rename_account_not_found() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let bogus = AccountId::new();
    let err = vault.rename(bogus, "alice", fixture_now()).unwrap_err();
    assert_invalid_state(&err, "rename", "account_not_found");
}

#[test]
fn invalid_state_totp_code_account_not_found() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let bogus = AccountId::new();
    let err = vault.totp_code(bogus, fixture_now()).unwrap_err();
    assert_invalid_state(&err, "totp_code", "account_not_found");
}

#[test]
fn invalid_state_totp_code_not_totp() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_hotp_account("alice", 0));
    let err = vault.totp_code(id, fixture_now()).unwrap_err();
    assert_invalid_state(&err, "totp_code", "not_totp");
}

#[test]
fn invalid_state_hotp_peek_account_not_found() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let bogus = AccountId::new();
    let err = vault.hotp_peek(bogus).unwrap_err();
    assert_invalid_state(&err, "hotp_peek", "account_not_found");
}

#[test]
fn invalid_state_hotp_peek_not_hotp() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account("alice", None));
    let err = vault.hotp_peek(id).unwrap_err();
    assert_invalid_state(&err, "hotp_peek", "not_hotp");
}

#[test]
fn invalid_state_hotp_advance_account_not_found() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let bogus = AccountId::new();
    let err = vault
        .hotp_advance(&store, bogus, fixture_now())
        .unwrap_err();
    assert_invalid_state(&err, "hotp_advance", "account_not_found");
}

#[test]
fn invalid_state_hotp_advance_not_hotp() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account("alice", None));
    let err = vault.hotp_advance(&store, id, fixture_now()).unwrap_err();
    assert_invalid_state(&err, "hotp_advance", "not_hotp");
}

#[test]
fn invalid_state_import_paladin_missing_passphrase() {
    // Build a real encrypted Paladin bundle, then drop the passphrase
    // when invoking the facade.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.add(make_account("alice", None));
    let bundle = paladin_core::export::encrypted(&vault, cheap_options("hunter2"))
        .expect("encrypted bundle");
    let err = import::from_bytes(
        &bundle,
        ImportOptions {
            format: Some(ImportFormat::Paladin),
            paladin_passphrase: None,
        },
        fixture_now(),
    )
    .unwrap_err();
    assert_invalid_state(&err, "import_paladin", "missing_passphrase");
}

// -----------------------------------------------------------------------------
// vault_missing / vault_exists
// -----------------------------------------------------------------------------

#[test]
fn vault_missing_kind_when_opening_absent_path() {
    let dir = vault_test_dir();
    let path = dir.path().join("does-not-exist.bin");
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultMissing);
    matches!(err, PaladinError::VaultMissing);
}

#[test]
fn vault_exists_kind_when_creating_existing_path() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);
    let err = Store::create(&path, VaultInit::Plaintext).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::VaultExists);
    matches!(err, PaladinError::VaultExists);
}

// -----------------------------------------------------------------------------
// unsafe_permissions
// -----------------------------------------------------------------------------

#[test]
fn unsafe_permissions_carries_path_subject_and_modes() {
    let dir = TempDir::new().expect("tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))
        .expect("loosen tempdir to 0755");
    let path = dir.path().join("vault.bin");
    let err = Store::create(&path, VaultInit::Plaintext).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsafePermissions);
    let PaladinError::UnsafePermissions {
        path: bad_path,
        subject,
        actual_mode,
        expected_mode,
    } = err
    else {
        panic!("expected UnsafePermissions, got {err:?}");
    };
    assert_eq!(bad_path, dir.path());
    assert_eq!(subject, PermissionSubject::VaultDir);
    assert_eq!(subject.as_str(), "vault_dir");
    assert_eq!(actual_mode.len(), 4, "actual_mode is 4-digit octal");
    assert_eq!(expected_mode, "0700");
}

// -----------------------------------------------------------------------------
// wrong_vault_lock — both directions
// -----------------------------------------------------------------------------

#[test]
fn wrong_vault_lock_plaintext_supplied_for_encrypted_file() {
    // Supplying VaultLock::Plaintext to an encrypted file: `expected`
    // names the lock the caller supplied, `actual` names the on-disk
    // mode that disagrees with it.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WrongVaultLock);
    let PaladinError::WrongVaultLock { expected, actual } = err else {
        panic!("expected WrongVaultLock, got {err:?}");
    };
    assert_eq!(expected, VaultMode::Plaintext);
    assert_eq!(actual, VaultMode::Encrypted);
    assert_eq!(expected.as_str(), "plaintext");
    assert_eq!(actual.as_str(), "encrypted");
}

#[test]
fn wrong_vault_lock_encrypted_supplied_for_plaintext_file() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault.save(&store).unwrap();
    drop(vault);
    drop(store);
    let err = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WrongVaultLock);
    let PaladinError::WrongVaultLock { expected, actual } = err else {
        panic!("expected WrongVaultLock, got {err:?}");
    };
    assert_eq!(expected, VaultMode::Encrypted);
    assert_eq!(actual, VaultMode::Plaintext);
}

// -----------------------------------------------------------------------------
// decrypt_failed
// -----------------------------------------------------------------------------

#[test]
fn decrypt_failed_with_wrong_passphrase() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (_v, _s) = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let err = Store::open(&path, VaultLock::Encrypted(pp("wrong"))).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::DecryptFailed);
    matches!(err, PaladinError::DecryptFailed);
}

// -----------------------------------------------------------------------------
// invalid_header
// -----------------------------------------------------------------------------

#[test]
fn invalid_header_when_file_has_unknown_magic() {
    // Write a bogus file at the vault path; the open path's header probe
    // should reject the magic before any decrypt work.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    fs::write(&path, b"NOTAPALADIN\0".repeat(8)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let err = Store::open(&path, VaultLock::Plaintext).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidHeader);
    matches!(err, PaladinError::InvalidHeader);
}

// -----------------------------------------------------------------------------
// invalid_payload — one row per stable reason
// -----------------------------------------------------------------------------

fn assert_invalid_payload(err: PaladinError, expected_reason: &str) {
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);
    match err {
        PaladinError::InvalidPayload { reason } => assert_eq!(reason, expected_reason),
        other => panic!("expected InvalidPayload, got {other:?}"),
    }
}

#[test]
fn invalid_payload_reasons_are_constructible_with_stable_strings() {
    // Pin the reason strings used at production sites
    // (§4.3 / §4.4 / §4.6). Real triggers exist in
    // tests/encrypted_tamper.rs and storage::payload unit tests; here
    // we pin that the variant accepts each stable reason verbatim so a
    // rename surfaces in the matrix as well.
    for reason in [
        "exceeds_size_limit",
        "trailing_bytes",
        "decode_failed",
        "ciphertext_too_short",
    ] {
        assert_invalid_payload(PaladinError::InvalidPayload { reason }, reason);
    }
}

// -----------------------------------------------------------------------------
// unsupported_format_version
// -----------------------------------------------------------------------------

#[test]
fn unsupported_format_version_carries_offending_byte() {
    // Direct-construct: the matching production path requires writing
    // a structurally valid header with a future format_ver, exercised
    // in encrypted_tamper.rs. The matrix pins the stable field name.
    let err = PaladinError::UnsupportedFormatVersion { format_ver: 99 };
    assert_eq!(err.kind(), ErrorKind::UnsupportedFormatVersion);
    let PaladinError::UnsupportedFormatVersion { format_ver } = err else {
        panic!("expected UnsupportedFormatVersion, got {err:?}");
    };
    assert_eq!(format_ver, 99);
}

// -----------------------------------------------------------------------------
// kdf_params_out_of_bounds
// -----------------------------------------------------------------------------

#[test]
fn kdf_params_out_of_bounds_via_argon2_validation() {
    // §4.4: Argon2Params validation rejects out-of-range m_kib before
    // any KDF work and surfaces the offending value.
    let err = EncryptionOptions::with_params(
        pp("hunter2"),
        Argon2Params {
            m_kib: 1,
            t: 1,
            p: 1,
        },
    )
    .unwrap_err();
    // The validator surfaces this as a typed validation_error per
    // Phase H — but the §5 row for kdf_params_out_of_bounds is
    // produced from header decode at open time. Pin both directions:
    // the validation_error path here, plus the direct-construct kind
    // assertion below.
    match err {
        PaladinError::ValidationError { field, .. } => assert!(field.starts_with("kdf_params")),
        PaladinError::KdfParamsOutOfBounds { .. } => {}
        other => panic!("expected ValidationError or KdfParamsOutOfBounds, got {other:?}"),
    }

    let direct = PaladinError::KdfParamsOutOfBounds {
        m_kib: 1,
        t: 1,
        p: 1,
    };
    assert_eq!(direct.kind(), ErrorKind::KdfParamsOutOfBounds);
    let PaladinError::KdfParamsOutOfBounds { m_kib, t, p } = direct else {
        panic!("expected KdfParamsOutOfBounds");
    };
    assert_eq!(m_kib, 1);
    assert_eq!(t, 1);
    assert_eq!(p, 1);
}

// -----------------------------------------------------------------------------
// unsupported_import_format — auto-detect failure + forced-format failure
// -----------------------------------------------------------------------------

#[test]
fn unsupported_import_format_auto_detect_unknown() {
    let bytes = b"not a known import format";
    assert_eq!(detect(bytes), ImportFormat::Unknown);
    let err = import::from_bytes(bytes, ImportOptions::default(), fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedImportFormat);
    let PaladinError::UnsupportedImportFormat { format } = err else {
        panic!("expected UnsupportedImportFormat, got {err:?}");
    };
    assert_eq!(format, "unknown");
}

#[test]
fn unsupported_import_format_forced_mismatch_uses_requested_format() {
    // Force `Aegis` on bytes that auto-detect reports as `Otpauth`.
    let bytes = b"otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP\n";
    let err = import::from_bytes(
        bytes,
        ImportOptions {
            format: Some(ImportFormat::Aegis),
            paladin_passphrase: None,
        },
        fixture_now(),
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedImportFormat);
    let PaladinError::UnsupportedImportFormat { format } = err else {
        panic!("expected UnsupportedImportFormat, got {err:?}");
    };
    assert_eq!(format, "aegis");
}

// -----------------------------------------------------------------------------
// unsupported_plaintext_vault / unsupported_encrypted_aegis
// -----------------------------------------------------------------------------

#[test]
fn unsupported_plaintext_vault_is_a_bare_variant() {
    let err = PaladinError::UnsupportedPlaintextVault;
    assert_eq!(err.kind(), ErrorKind::UnsupportedPlaintextVault);
    matches!(err, PaladinError::UnsupportedPlaintextVault);
}

#[test]
fn unsupported_encrypted_aegis_via_real_aegis_input() {
    // Aegis JSON whose top-level `header.slots` is non-null indicates
    // an encrypted backup; §4.6 rejects it with the typed bare variant.
    let json = br#"{
        "version": 1,
        "header": {
            "slots": [{"type": 1}],
            "params": {"nonce": "00", "tag": "00"}
        },
        "db": "encrypted-blob"
    }"#;
    let err = import::aegis_plaintext(json, fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedEncryptedAegis);
    matches!(err, PaladinError::UnsupportedEncryptedAegis);
}

// -----------------------------------------------------------------------------
// unsupported_aegis_entry_type
// -----------------------------------------------------------------------------

#[test]
fn unsupported_aegis_entry_type_carries_source_index_and_type() {
    let json = br#"{
        "version": 1,
        "header": {"slots": null, "params": null},
        "db": {
            "version": 2,
            "entries": [
                {
                    "type": "totp",
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "name": "alice",
                    "issuer": "",
                    "note": "",
                    "icon": null,
                    "icon_mime": null,
                    "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "period": 30}
                },
                {
                    "type": "steam",
                    "uuid": "11111111-1111-1111-1111-111111111111",
                    "name": "bob",
                    "issuer": "",
                    "note": "",
                    "icon": null,
                    "icon_mime": null,
                    "info": {"secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 5, "period": 30}
                }
            ]
        }
    }"#;
    let err = import::aegis_plaintext(json, fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedAegisEntryType);
    let PaladinError::UnsupportedAegisEntryType {
        source_index,
        entry_type,
    } = err
    else {
        panic!("expected UnsupportedAegisEntryType, got {err:?}");
    };
    assert_eq!(source_index, 1);
    assert_eq!(entry_type, "steam");
}

// -----------------------------------------------------------------------------
// no_entries_to_import
// -----------------------------------------------------------------------------

#[test]
fn no_entries_to_import_when_aegis_db_is_empty() {
    let json = br#"{
        "version": 1,
        "header": {"slots": null, "params": null},
        "db": {"version": 2, "entries": []}
    }"#;
    let err = import::aegis_plaintext(json, fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
    matches!(err, PaladinError::NoEntriesToImport);
}

// -----------------------------------------------------------------------------
// counter_overflow
// -----------------------------------------------------------------------------

#[test]
fn counter_overflow_carries_account_summary() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_hotp_account("alice", u64::MAX));
    let err = vault.hotp_advance(&store, id, fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::CounterOverflow);
    let PaladinError::CounterOverflow { account } = err else {
        panic!("expected CounterOverflow, got {err:?}");
    };
    assert_eq!(account.id, id);
    assert_eq!(account.kind, AccountKindSummary::Hotp);
    assert_eq!(account.counter, Some(u64::MAX));
}

// -----------------------------------------------------------------------------
// time_range — TOTP, hotp_advance, rename
// -----------------------------------------------------------------------------

fn pre_epoch() -> SystemTime {
    UNIX_EPOCH - Duration::from_secs(1)
}

#[test]
fn time_range_totp_code_pre_epoch() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account("alice", None));
    let err = vault.totp_code(id, pre_epoch()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimeRange);
    let PaladinError::TimeRange { operation, kind } = err else {
        panic!("expected TimeRange, got {err:?}");
    };
    assert_eq!(operation, "totp_code");
    assert_eq!(kind, TimeRangeKind::PreEpoch);
    assert_eq!(kind.as_str(), "pre_epoch");
}

#[test]
fn time_range_hotp_advance_pre_epoch() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_hotp_account("alice", 0));
    let err = vault.hotp_advance(&store, id, pre_epoch()).unwrap_err();
    let PaladinError::TimeRange { operation, kind } = err else {
        panic!("expected TimeRange, got {err:?}");
    };
    assert_eq!(operation, "hotp_advance");
    assert_eq!(kind, TimeRangeKind::PreEpoch);
}

#[test]
fn time_range_rename_pre_epoch() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account("alice", None));
    let err = vault.rename(id, "bob", pre_epoch()).unwrap_err();
    let PaladinError::TimeRange { operation, kind } = err else {
        panic!("expected TimeRange, got {err:?}");
    };
    assert_eq!(operation, "rename");
    assert_eq!(kind, TimeRangeKind::PreEpoch);
}

// -----------------------------------------------------------------------------
// save_not_committed / save_durability_unconfirmed
// -----------------------------------------------------------------------------

#[test]
fn save_not_committed_carries_committed_false_and_optional_backup_path() {
    // Direct-construct: real production paths are exercised in
    // tests/vault_lifecycle.rs and tests/fault_injection.rs. The
    // matrix pins the stable field shape (committed: bool,
    // backup_path: Option<PathBuf>).
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: Some(PathBuf::from("/tmp/vault.bin.bak")),
    };
    assert_eq!(err.kind(), ErrorKind::SaveNotCommitted);
    let PaladinError::SaveNotCommitted {
        committed,
        backup_path,
    } = err
    else {
        panic!("expected SaveNotCommitted");
    };
    assert!(!committed);
    assert_eq!(backup_path, Some(PathBuf::from("/tmp/vault.bin.bak")));

    let bare = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let PaladinError::SaveNotCommitted { backup_path, .. } = bare else {
        panic!();
    };
    assert!(backup_path.is_none());
}

#[test]
fn save_durability_unconfirmed_is_a_bare_variant() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    assert_eq!(err.kind(), ErrorKind::SaveDurabilityUnconfirmed);
    matches!(err, PaladinError::SaveDurabilityUnconfirmed);
}

// -----------------------------------------------------------------------------
// io_error — one row per stable §5 operation string (table-driven)
// -----------------------------------------------------------------------------

/// Stable §5 `io_error.operation` strings. Renaming any of these
/// breaks the JSON envelope contract for the CLI's `--json` output.
const STABLE_IO_OPERATIONS: &[&str] = &[
    "resolve_default_vault_path",
    "unsupported_platform_permissions",
    "create_vault_dir",
    "stat_vault_dir",
    "stat_vault_file",
    "stat_backup_file",
    "read_vault_file",
    "write_vault_tmp",
    "write_backup_tmp",
    "fsync_temp_file",
    "rename_backup",
    "rename_primary",
    "fsync_vault_dir",
    "cleanup_temp_file",
    "read_import_file",
    "read_qr_image",
    "decode_image_bytes",
    "decode_qr_image",
    "write_secret_file_tmp",
    "fsync_secret_file_tmp",
    "rename_secret_file",
    "fsync_secret_file_dir",
    "csprng_read",
    "kdf_allocation",
    "vault_file_is_symlink",
    "backup_file_is_symlink",
    "vault_dir_is_symlink",
];

#[test]
fn io_error_every_stable_operation_is_constructible_and_round_trips() {
    for op in STABLE_IO_OPERATIONS {
        let err = PaladinError::IoError {
            operation: op,
            source: io::Error::other("fixture"),
        };
        assert_eq!(err.kind(), ErrorKind::IoError, "kind mismatch for {op}");
        match err {
            PaladinError::IoError { operation, source } => {
                assert_eq!(operation, *op, "operation mismatch");
                assert_eq!(source.kind(), io::ErrorKind::Other);
            }
            other => panic!("expected IoError, got {other:?}"),
        }
    }
}

#[test]
fn io_error_read_import_file_via_missing_path() {
    // Real production trigger: import facade reads a path that
    // doesn't exist. Pins one io_error row through the public API.
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("does-not-exist.json");
    let err = import::from_file(&path, ImportOptions::default(), fixture_now()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::IoError);
    let PaladinError::IoError { operation, .. } = err else {
        panic!("expected IoError, got {err:?}");
    };
    assert_eq!(operation, "read_import_file");
}

// -----------------------------------------------------------------------------
// ErrorKind / discriminator stability — every variant produces the
// expected §5 string. Catches the rename regression independently of
// the per-feature rows above.
// -----------------------------------------------------------------------------

#[test]
fn error_kind_strings_match_section_5_table() {
    assert_eq!(ErrorKind::ValidationError.as_str(), "validation_error");
    assert_eq!(ErrorKind::InvalidPassphrase.as_str(), "invalid_passphrase");
    assert_eq!(ErrorKind::InvalidState.as_str(), "invalid_state");
    assert_eq!(ErrorKind::VaultMissing.as_str(), "vault_missing");
    assert_eq!(ErrorKind::VaultExists.as_str(), "vault_exists");
    assert_eq!(ErrorKind::UnsafePermissions.as_str(), "unsafe_permissions");
    assert_eq!(ErrorKind::WrongVaultLock.as_str(), "wrong_vault_lock");
    assert_eq!(ErrorKind::DecryptFailed.as_str(), "decrypt_failed");
    assert_eq!(ErrorKind::InvalidHeader.as_str(), "invalid_header");
    assert_eq!(ErrorKind::InvalidPayload.as_str(), "invalid_payload");
    assert_eq!(
        ErrorKind::UnsupportedFormatVersion.as_str(),
        "unsupported_format_version"
    );
    assert_eq!(
        ErrorKind::KdfParamsOutOfBounds.as_str(),
        "kdf_params_out_of_bounds"
    );
    assert_eq!(
        ErrorKind::UnsupportedImportFormat.as_str(),
        "unsupported_import_format"
    );
    assert_eq!(
        ErrorKind::UnsupportedPlaintextVault.as_str(),
        "unsupported_plaintext_vault"
    );
    assert_eq!(
        ErrorKind::UnsupportedEncryptedAegis.as_str(),
        "unsupported_encrypted_aegis"
    );
    assert_eq!(
        ErrorKind::UnsupportedAegisEntryType.as_str(),
        "unsupported_aegis_entry_type"
    );
    assert_eq!(
        ErrorKind::NoEntriesToImport.as_str(),
        "no_entries_to_import"
    );
    assert_eq!(ErrorKind::CounterOverflow.as_str(), "counter_overflow");
    assert_eq!(ErrorKind::TimeRange.as_str(), "time_range");
    assert_eq!(ErrorKind::SaveNotCommitted.as_str(), "save_not_committed");
    assert_eq!(
        ErrorKind::SaveDurabilityUnconfirmed.as_str(),
        "save_durability_unconfirmed"
    );
    assert_eq!(ErrorKind::IoError.as_str(), "io_error");
}

#[test]
fn time_range_kind_strings_match_section_5() {
    assert_eq!(TimeRangeKind::PreEpoch.as_str(), "pre_epoch");
    assert_eq!(TimeRangeKind::Overflow.as_str(), "overflow");
    assert_eq!(TimeRangeKind::OutOfRange.as_str(), "out_of_range");
}

#[test]
fn permission_subject_strings_match_section_5() {
    assert_eq!(PermissionSubject::VaultDir.as_str(), "vault_dir");
    assert_eq!(PermissionSubject::VaultFile.as_str(), "vault_file");
    assert_eq!(PermissionSubject::BackupFile.as_str(), "backup_file");
}

#[test]
fn vault_mode_strings_match_section_5() {
    assert_eq!(VaultMode::Plaintext.as_str(), "plaintext");
    assert_eq!(VaultMode::Encrypted.as_str(), "encrypted");
}
