// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.2 — `import::otpauth` wrapper covering single URI / line list /
// JSON array variants (DESIGN.md §4.6 / §4.7).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{import, AccountKindSummary, ErrorKind, PaladinError};

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

const URI_TOTP_A: &str = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
const URI_HOTP_B: &str = "otpauth://hotp/Globex:bob?secret=NBSWY3DPEHPK3PXP&issuer=Globex&counter=7";

// ---------- Single URI ----------

#[test]
fn single_uri_returns_one_validated_account() {
    let bytes = URI_TOTP_A.as_bytes();
    let imported = import::otpauth(bytes, import_time()).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].account.label(), "alice");
    assert_eq!(imported[0].account.issuer(), Some("Acme"));
}

#[test]
fn single_uri_with_surrounding_whitespace_succeeds() {
    let bytes = format!("\n  \t{URI_TOTP_A}  \n");
    let imported = import::otpauth(bytes.as_bytes(), import_time()).unwrap();
    assert_eq!(imported.len(), 1);
}

#[test]
fn single_uri_sets_created_at_equal_updated_at_equal_import_time() {
    let imported = import::otpauth(URI_TOTP_A.as_bytes(), import_time()).unwrap();
    let acct = &imported[0].account;
    assert_eq!(acct.created_at(), 1_700_000_000);
    assert_eq!(acct.updated_at(), 1_700_000_000);
}

// ---------- Line list ----------

#[test]
fn line_list_two_uris_returns_two_accounts_in_order() {
    let bytes = format!("{URI_TOTP_A}\n{URI_HOTP_B}\n");
    let imported = import::otpauth(bytes.as_bytes(), import_time()).unwrap();
    assert_eq!(imported.len(), 2);
    assert_eq!(imported[0].account.label(), "alice");
    assert_eq!(imported[1].account.label(), "bob");
    assert_eq!(imported[1].account.kind(), AccountKindSummary::Hotp);
    assert_eq!(imported[1].account.counter(), Some(7));
}

#[test]
fn line_list_blank_lines_are_tolerated() {
    let bytes = format!("\n\n{URI_TOTP_A}\n\n   \n{URI_HOTP_B}\n\n");
    let imported = import::otpauth(bytes.as_bytes(), import_time()).unwrap();
    assert_eq!(imported.len(), 2);
}

#[test]
fn line_list_crlf_is_tolerated() {
    let bytes = format!("{URI_TOTP_A}\r\n{URI_HOTP_B}\r\n");
    let imported = import::otpauth(bytes.as_bytes(), import_time()).unwrap();
    assert_eq!(imported.len(), 2);
}

#[test]
fn line_list_with_invalid_uri_aborts_batch_with_source_index() {
    let bytes = format!("{URI_TOTP_A}\nnot-an-otpauth-uri\n{URI_HOTP_B}\n");
    let err = import::otpauth(bytes.as_bytes(), import_time()).unwrap_err();
    let PaladinError::ValidationError { source_index, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(source_index, Some(1), "offending row index zero-based");
}

#[test]
fn line_list_embedded_nul_byte_aborts_with_source_index_before_decoding() {
    // Spec: NUL bytes in a row reject with validation_error +
    // source_index *before* secret decoding.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(URI_TOTP_A.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(b"otpauth://totp/X:y?secret=JBSWY3DP\0EHPK3PXP\n");
    bytes.extend_from_slice(URI_HOTP_B.as_bytes());
    bytes.push(b'\n');
    let err = import::otpauth(&bytes, import_time()).unwrap_err();
    let PaladinError::ValidationError {
        field,
        reason,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "uri");
    assert_eq!(reason, "embedded_nul");
    assert_eq!(source_index, Some(1));
}

// ---------- JSON array ----------

#[test]
fn json_array_of_uris_returns_accounts_in_input_order() {
    let json = format!(r#"["{URI_TOTP_A}","{URI_HOTP_B}"]"#);
    let imported = import::otpauth(json.as_bytes(), import_time()).unwrap();
    assert_eq!(imported.len(), 2);
    assert_eq!(imported[0].account.label(), "alice");
    assert_eq!(imported[1].account.label(), "bob");
}

#[test]
fn empty_json_array_returns_no_entries_to_import() {
    let err = import::otpauth(b"[]", import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
}

#[test]
fn whitespace_only_input_returns_no_entries_to_import() {
    let err = import::otpauth(b"  \n\t   \n", import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
}

#[test]
fn empty_input_returns_no_entries_to_import() {
    let err = import::otpauth(b"", import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
}

#[test]
fn json_array_with_non_string_element_rejects_with_source_index() {
    let json = format!(r#"["{URI_TOTP_A}",123,"{URI_HOTP_B}"]"#);
    let err = import::otpauth(json.as_bytes(), import_time()).unwrap_err();
    let PaladinError::ValidationError {
        field,
        reason,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "uri");
    assert_eq!(reason, "expected_string");
    assert_eq!(source_index, Some(1));
}

#[test]
fn json_array_with_invalid_uri_string_propagates_source_index() {
    let json = format!(r#"["{URI_TOTP_A}","not-an-otpauth"]"#);
    let err = import::otpauth(json.as_bytes(), import_time()).unwrap_err();
    let PaladinError::ValidationError { source_index, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(source_index, Some(1));
}

#[test]
fn malformed_json_array_returns_validation_error_without_panic() {
    let err = import::otpauth(b"[\"otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP\",", import_time())
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}

#[test]
fn deeply_nested_json_does_not_panic() {
    // 1000 nested arrays — must not exhaust the stack and must
    // surface as validation_error rather than a panic.
    let mut bytes = vec![b'['; 1000];
    bytes.extend(std::iter::repeat_n(b']', 1000));
    let result = import::otpauth(&bytes, import_time());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}

// ---------- Invalid UTF-8 ----------

#[test]
fn invalid_utf8_input_rejects_with_validation_error() {
    let bytes = b"\xff\xfe\xfd";
    let err = import::otpauth(bytes, import_time()).unwrap_err();
    let PaladinError::ValidationError { field, reason, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "input");
    assert_eq!(reason, "invalid_utf8");
}
