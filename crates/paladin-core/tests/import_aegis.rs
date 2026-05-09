// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.3 — `import::aegis_plaintext` (DESIGN.md §4.6 / §4.7).
//
// Aegis Authenticator JSON exports come in two shapes:
//   - Plaintext: `db` is a JSON object with `version` + `entries[]`.
//   - Encrypted: `db` is a base64 string. We reject these as
//     `unsupported_encrypted_aegis` in v0.1.
//
// Per-entry rules (§4.6):
//   - `type` must be `"totp"` or `"hotp"`. Any other value rejects the
//     batch with `unsupported_aegis_entry_type` carrying the offending
//     row's `source_index` and `entry_type`.
//   - Required: `name`, `info.secret`. Missing → `validation_error`
//     tagged with the row's `source_index`.
//   - TOTP `info.period` defaults to 30; HOTP `info.counter` is
//     required.
//   - `info.algo` defaults to SHA1 (case-insensitive parse).
//   - `info.digits` defaults to 6.
//   - Aegis `icon` / `note` fields are dropped; `icon_hint` derives
//     from `issuer`.
//   - Empty `entries[]` returns `no_entries_to_import`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    import, AccountKindSummary, Algorithm, ErrorKind, PaladinError,
};

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn aegis_plaintext_with(entries_json: &str) -> Vec<u8> {
    format!(
        r#"{{"version":1,"header":{{"slots":null,"params":null}},"db":{{"version":2,"entries":{entries_json}}}}}"#
    )
    .into_bytes()
}

// ---------- Happy path ----------

#[test]
fn totp_entry_full_field_mapping() {
    let bytes = aegis_plaintext_with(
        r#"[{
            "type": "totp",
            "uuid": "00000000-0000-0000-0000-000000000001",
            "name": "alice",
            "issuer": "Acme",
            "note": "ignored",
            "icon": "data:image/png;base64,IGNORED",
            "info": {
                "secret": "JBSWY3DPEHPK3PXP",
                "algo": "SHA256",
                "digits": 8,
                "period": 60
            }
        }]"#,
    );
    let imported = import::aegis_plaintext(&bytes, import_time()).unwrap();
    assert_eq!(imported.len(), 1);
    let acct = &imported[0].account;
    assert_eq!(acct.label(), "alice");
    assert_eq!(acct.issuer(), Some("Acme"));
    assert_eq!(acct.algorithm(), Algorithm::Sha256);
    assert_eq!(acct.digits(), 8);
    assert_eq!(acct.kind(), AccountKindSummary::Totp);
    assert_eq!(acct.period(), Some(60));
    assert_eq!(acct.created_at(), 1_700_000_000);
    assert_eq!(acct.updated_at(), 1_700_000_000);
}

#[test]
fn totp_entry_period_defaults_to_30() {
    let bytes = aegis_plaintext_with(
        r#"[{
            "type": "totp",
            "name": "alice",
            "issuer": "Acme",
            "info": {"secret": "JBSWY3DPEHPK3PXP"}
        }]"#,
    );
    let imported = import::aegis_plaintext(&bytes, import_time()).unwrap();
    assert_eq!(imported[0].account.period(), Some(30));
    assert_eq!(imported[0].account.algorithm(), Algorithm::Sha1);
    assert_eq!(imported[0].account.digits(), 6);
}

#[test]
fn hotp_entry_full_field_mapping() {
    let bytes = aegis_plaintext_with(
        r#"[{
            "type": "hotp",
            "name": "bob",
            "issuer": "Globex",
            "info": {
                "secret": "NBSWY3DPEHPK3PXP",
                "algo": "sha512",
                "digits": 7,
                "counter": 42
            }
        }]"#,
    );
    let imported = import::aegis_plaintext(&bytes, import_time()).unwrap();
    let acct = &imported[0].account;
    assert_eq!(acct.label(), "bob");
    assert_eq!(acct.issuer(), Some("Globex"));
    assert_eq!(acct.kind(), AccountKindSummary::Hotp);
    assert_eq!(acct.counter(), Some(42));
    assert_eq!(acct.algorithm(), Algorithm::Sha512);
    assert_eq!(acct.digits(), 7);
}

#[test]
fn icon_hint_derived_from_issuer_aegis_icon_fields_ignored() {
    let bytes = aegis_plaintext_with(
        r#"[{
            "type": "totp",
            "name": "alice",
            "issuer": "GitHub",
            "icon": "data:image/png;base64,SHOULDBEIGNORED",
            "info": {"secret": "JBSWY3DPEHPK3PXP"}
        }]"#,
    );
    let imported = import::aegis_plaintext(&bytes, import_time()).unwrap();
    assert_eq!(imported[0].account.icon_hint(), Some("github"));
}

#[test]
fn entries_preserve_input_order() {
    let bytes = aegis_plaintext_with(
        r#"[
            {"type":"totp","name":"a","info":{"secret":"JBSWY3DPEHPK3PXP"}},
            {"type":"totp","name":"b","info":{"secret":"JBSWY3DPEHPK3PXP"}},
            {"type":"hotp","name":"c","info":{"secret":"JBSWY3DPEHPK3PXP","counter":3}}
        ]"#,
    );
    let imported = import::aegis_plaintext(&bytes, import_time()).unwrap();
    assert_eq!(imported.len(), 3);
    assert_eq!(imported[0].account.label(), "a");
    assert_eq!(imported[1].account.label(), "b");
    assert_eq!(imported[2].account.label(), "c");
}

// ---------- Encrypted backup ----------

#[test]
fn encrypted_aegis_db_string_returns_unsupported_encrypted_aegis() {
    let bytes = br#"{"version":1,"header":{"slots":[],"params":{}},"db":"BASE64STRING"}"#;
    let err = import::aegis_plaintext(bytes, import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedEncryptedAegis);
}

// ---------- Invalid entry type ----------

#[test]
fn non_totp_or_hotp_entry_rejects_batch_with_source_index() {
    let bytes = aegis_plaintext_with(
        r#"[
            {"type":"totp","name":"a","info":{"secret":"JBSWY3DPEHPK3PXP"}},
            {"type":"steam","name":"b","info":{"secret":"JBSWY3DPEHPK3PXP"}},
            {"type":"totp","name":"c","info":{"secret":"JBSWY3DPEHPK3PXP"}}
        ]"#,
    );
    let err = import::aegis_plaintext(&bytes, import_time()).unwrap_err();
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

// ---------- Required fields ----------

#[test]
fn missing_name_rejects_with_validation_error_and_source_index() {
    let bytes = aegis_plaintext_with(
        r#"[
            {"type":"totp","name":"a","info":{"secret":"JBSWY3DPEHPK3PXP"}},
            {"type":"totp","info":{"secret":"JBSWY3DPEHPK3PXP"}}
        ]"#,
    );
    let err = import::aegis_plaintext(&bytes, import_time()).unwrap_err();
    let PaladinError::ValidationError {
        field,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "name");
    assert_eq!(source_index, Some(1));
}

#[test]
fn missing_info_secret_rejects_with_validation_error_and_source_index() {
    let bytes = aegis_plaintext_with(
        r#"[
            {"type":"totp","name":"a","info":{"secret":"JBSWY3DPEHPK3PXP"}},
            {"type":"totp","name":"b","info":{"algo":"SHA1"}}
        ]"#,
    );
    let err = import::aegis_plaintext(&bytes, import_time()).unwrap_err();
    let PaladinError::ValidationError {
        field,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "secret");
    assert_eq!(source_index, Some(1));
}

#[test]
fn missing_hotp_counter_rejects_with_validation_error_and_source_index() {
    let bytes = aegis_plaintext_with(
        r#"[
            {"type":"totp","name":"a","info":{"secret":"JBSWY3DPEHPK3PXP"}},
            {"type":"hotp","name":"b","info":{"secret":"JBSWY3DPEHPK3PXP"}}
        ]"#,
    );
    let err = import::aegis_plaintext(&bytes, import_time()).unwrap_err();
    let PaladinError::ValidationError {
        field,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "counter");
    assert_eq!(source_index, Some(1));
}

// ---------- Malformed JSON / shape ----------

#[test]
fn empty_entries_returns_no_entries_to_import() {
    let bytes = aegis_plaintext_with("[]");
    let err = import::aegis_plaintext(&bytes, import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
}

#[test]
fn missing_db_field_returns_validation_error() {
    let bytes = br#"{"version":1,"header":{}}"#;
    let err = import::aegis_plaintext(bytes, import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}

#[test]
fn deeply_nested_json_does_not_panic() {
    let mut bytes = vec![b'['; 1000];
    bytes.extend(std::iter::repeat(b']').take(1000));
    let err = import::aegis_plaintext(&bytes, import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}

#[test]
fn invalid_utf8_input_rejects_with_validation_error() {
    let bytes = b"\xff\xfe\xfd";
    let err = import::aegis_plaintext(bytes, import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}

#[test]
fn invalid_algo_string_rejects_with_source_index() {
    let bytes = aegis_plaintext_with(
        r#"[
            {"type":"totp","name":"a","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"MD5"}}
        ]"#,
    );
    let err = import::aegis_plaintext(&bytes, import_time()).unwrap_err();
    let PaladinError::ValidationError {
        field,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "algorithm");
    assert_eq!(source_index, Some(0));
}
