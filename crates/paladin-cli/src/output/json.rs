// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable JSON envelope renderers per docs/DESIGN.md §5. Each helper writes
//! exactly one JSON document to the supplied `Write` followed by a
//! single newline, with no other bytes — matching the CLI's
//! "stdout is one document plus newline" wire contract under `--json`.

use std::io::Write;

use paladin_core::{
    AccountSummary, Code, ImportReport, ImportWarning, ValidationWarning, VaultMode, VaultSettings,
};
use serde::Serialize;

/// `init` and `passphrase {set,change,remove}` success envelope:
/// `{ "ok": true, "status": "plaintext" | "encrypted" }` per the §5
/// JSON shape table.
#[derive(Debug, Serialize)]
struct OkStatus {
    ok: bool,
    status: &'static str,
}

/// Render an `{ "ok": true, "status": ... }` envelope for `init` and
/// `passphrase` success paths.
pub fn write_ok_status(mode: VaultMode, mut out: impl Write) -> std::io::Result<()> {
    let env = OkStatus {
        ok: true,
        status: mode.as_str(),
    };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// One row in the `paladin list` success envelope. Each row is an
/// [`AccountSummary`] flattened with three optional code fields. TOTP
/// rows fill `code`, `seconds_remaining`, and `next_code`; HOTP rows
/// set all three to `null` because `list` never advances or peeks an
/// HOTP counter (see docs/DESIGN.md §5).
#[derive(Debug, Serialize)]
pub struct ListAccountRow<'a> {
    #[serde(flatten)]
    pub account: &'a AccountSummary,
    /// Current TOTP code, zero-padded to the entry's `digits`. `None`
    /// (serialized as `null`) for HOTP rows.
    pub code: Option<&'a str>,
    /// Seconds remaining in the current TOTP window. `None` for HOTP
    /// rows.
    pub seconds_remaining: Option<u32>,
    /// Next TOTP code, zero-padded to the entry's `digits`. `None`
    /// for HOTP rows.
    pub next_code: Option<&'a str>,
}

/// `paladin list` success envelope: `{ "accounts": [ListAccountRow] }`
/// per the §5 JSON shape table. The slice is serialized in insertion
/// order; an empty vault renders `{ "accounts": [] }`.
#[derive(Debug, Serialize)]
struct AccountList<'a> {
    accounts: &'a [ListAccountRow<'a>],
}

/// Render the `paladin list` success envelope.
pub fn write_account_list(
    accounts: &[ListAccountRow<'_>],
    mut out: impl Write,
) -> std::io::Result<()> {
    let env = AccountList { accounts };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// `paladin add` (single-entry) success envelope:
/// `{ "account": AccountSummary, "warnings": [Warning] }` per the §5
/// JSON shape table. The `warnings` array carries any
/// [`ValidationWarning`]s the validator produced (e.g. `short_secret`)
/// so JSON consumers do not have to peek at stderr.
#[derive(Debug, Serialize)]
struct AddSingle<'a> {
    account: &'a AccountSummary,
    warnings: &'a [ValidationWarning],
}

/// Render the `paladin add` (single-entry) success envelope. Used by
/// `--uri`, manual-flag, and interactive modes; `--qr` uses
/// [`write_qr_import_success`] because it is multi-entry.
pub fn write_add_success(
    account: &AccountSummary,
    warnings: &[ValidationWarning],
    mut out: impl Write,
) -> std::io::Result<()> {
    let env = AddSingle { account, warnings };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// `paladin add --qr` / `paladin import` success envelope:
/// `{ "imported", "skipped", "replaced", "appended", "accounts",
/// "warnings" }` per the §5 JSON shape table. `add --qr` always uses
/// the fixed `--on-conflict=skip` policy, so `replaced` and `appended`
/// are zero on that path.
#[derive(Debug, Serialize)]
struct ImportSummary<'a> {
    imported: usize,
    skipped: usize,
    replaced: usize,
    appended: usize,
    accounts: &'a [AccountSummary],
    warnings: &'a [ImportWarning],
}

/// One `CodeResult` row in the `show` / `peek` success envelope per
/// the §5 JSON shape table. The `account` summary reflects persisted
/// state after the command — for `show` on HOTP that means the
/// post-advance counter — and the [`Code`] timing fields are flattened
/// alongside it (`code`, `valid_from`, `valid_until`,
/// `seconds_remaining`, `counter_used`). TOTP rows have
/// `counter_used: null`; HOTP rows have the validity fields `null`.
#[derive(Debug, Serialize)]
pub struct CodeRow<'a> {
    /// Account state *after* the command (post-advance for HOTP `show`).
    pub account: &'a AccountSummary,
    /// Generated OTP projection — flattened so the row is a flat
    /// `{ account, code, valid_from, valid_until, seconds_remaining,
    /// counter_used }` object, matching the §5 `CodeResult` shape.
    #[serde(flatten)]
    pub code: &'a Code,
}

#[derive(Debug, Serialize)]
struct ShowEnvelope<'a> {
    codes: &'a [CodeRow<'a>],
}

/// Render the `paladin show` / `paladin peek` success envelope:
/// `{ "codes": [CodeResult] }`. Always emits a single top-level
/// document with the codes array — single-match commands still produce
/// a one-element array so JSON consumers can use one parse path.
pub fn write_show_codes(rows: &[CodeRow<'_>], mut out: impl Write) -> std::io::Result<()> {
    let env = ShowEnvelope { codes: rows };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// `paladin copy` success envelope per the §5 JSON shape table:
/// `{ "copied": true, "account": AccountSummary, "counter_used":
/// number_or_null }`. The `account` summary reflects persisted state
/// after the (possibly committed) HOTP advance; for TOTP `counter_used`
/// is `null`.
#[derive(Debug, Serialize)]
struct CopySuccess<'a> {
    copied: bool,
    account: &'a AccountSummary,
    counter_used: Option<u64>,
}

/// Render the `paladin copy` success envelope.
pub fn write_copy_success(
    account: &AccountSummary,
    counter_used: Option<u64>,
    mut out: impl Write,
) -> std::io::Result<()> {
    let env = CopySuccess {
        copied: true,
        account,
        counter_used,
    };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// `paladin remove` success envelope per the §5 JSON shape table:
/// `{ "removed": AccountSummary }`. The summary captures the state of
/// the account at the moment of removal, so callers can correlate the
/// removed entry with the prior `list` output by `id`.
#[derive(Debug, Serialize)]
struct RemoveSuccess<'a> {
    removed: &'a AccountSummary,
}

/// Render the `paladin remove` success envelope.
pub fn write_remove_success(account: &AccountSummary, mut out: impl Write) -> std::io::Result<()> {
    let env = RemoveSuccess { removed: account };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// `paladin rename` success envelope per the §5 JSON shape table:
/// `{ "account": AccountSummary }`. The summary reflects the
/// post-rename state — including the bumped `updated_at` — so JSON
/// consumers can confirm the new label landed and observe the new
/// timestamp without a follow-up `list`.
#[derive(Debug, Serialize)]
struct RenameSuccess<'a> {
    account: &'a AccountSummary,
}

/// Render the `paladin rename` success envelope.
pub fn write_rename_success(account: &AccountSummary, mut out: impl Write) -> std::io::Result<()> {
    let env = RenameSuccess { account };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// Render the `paladin add --qr` / `paladin import` success envelope.
pub fn write_qr_import_success(
    report: &ImportReport,
    accounts: &[AccountSummary],
    mut out: impl Write,
) -> std::io::Result<()> {
    let env = ImportSummary {
        imported: report.imported,
        skipped: report.skipped,
        replaced: report.replaced,
        appended: report.appended,
        accounts,
        warnings: &report.warnings,
    };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// `paladin export` success envelope per the §5 JSON shape table:
/// `{ "written": "/path/to/out", "format": "otpauth"|"paladin" }`.
/// `format` reflects the exporter that produced the file: `"otpauth"`
/// for plaintext exports (JSON `otpauth://` array) and `"paladin"` for
/// encrypted Paladin bundles.
#[derive(Debug, Serialize)]
struct ExportSuccess<'a> {
    written: &'a str,
    format: &'a str,
}

/// Render the `paladin export` success envelope.
pub fn write_export_success(
    written_path: &std::path::Path,
    format_label: &str,
    mut out: impl Write,
) -> std::io::Result<()> {
    let written = written_path.to_string_lossy();
    let env = ExportSuccess {
        written: &written,
        format: format_label,
    };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// `paladin qr <query> --out <path>` success envelope per the §5 JSON
/// shape table: `{ "written": "/path/to/out", "format": "qr_png" |
/// "qr_svg", "account": AccountSummary }`. JSON consumers can correlate
/// the written file back to the account without re-querying. The
/// `account` field is the resolved account's [`AccountSummary`] — `qr`
/// never mutates the vault, so `updated_at` matches the pre-run state.
#[derive(Debug, Serialize)]
struct QrExportSuccess<'a> {
    written: &'a str,
    format: &'a str,
    account: &'a AccountSummary,
}

/// Render the `paladin qr` success envelope (PNG or SVG file write).
/// ANSI rendering never reaches this helper — `--json` without `--out`
/// is rejected at parse time.
pub fn write_qr_export_success(
    written_path: &std::path::Path,
    format_label: &str,
    account: &AccountSummary,
    mut out: impl Write,
) -> std::io::Result<()> {
    let written = written_path.to_string_lossy();
    let env = QrExportSuccess {
        written: &written,
        format: format_label,
        account,
    };
    serde_json::to_writer(&mut out, &env).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

/// Render the `paladin settings {get,set}` success envelope per the §5
/// JSON shape table: the full nested [`VaultSettings`] object — `get`
/// renders the current settings, `set` renders the post-mutation
/// settings after `apply_setting_patch` commits. Dotted key names never
/// appear in the JSON output (they are CLI-side text-mode filters
/// only).
pub fn write_settings(settings: &VaultSettings, mut out: impl Write) -> std::io::Result<()> {
    serde_json::to_writer(&mut out, settings).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_ok_status(mode: VaultMode) -> serde_json::Value {
        let mut buf: Vec<u8> = Vec::new();
        write_ok_status(mode, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        serde_json::from_str(s.trim()).expect("valid json")
    }

    #[test]
    fn ok_status_plaintext_envelope_matches_section_5_shape() {
        let v = render_ok_status(VaultMode::Plaintext);
        assert_eq!(v, serde_json::json!({ "ok": true, "status": "plaintext" }));
    }

    #[test]
    fn ok_status_encrypted_envelope_matches_section_5_shape() {
        let v = render_ok_status(VaultMode::Encrypted);
        assert_eq!(v, serde_json::json!({ "ok": true, "status": "encrypted" }));
    }

    fn render_account_list(accounts: &[ListAccountRow<'_>]) -> serde_json::Value {
        let mut buf: Vec<u8> = Vec::new();
        write_account_list(accounts, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        serde_json::from_str(s.trim()).expect("valid json")
    }

    #[test]
    fn empty_account_list_renders_empty_accounts_array() {
        let v = render_account_list(&[]);
        assert_eq!(v, serde_json::json!({ "accounts": [] }));
    }

    #[test]
    fn account_list_envelope_flattens_summary_with_code_fields_for_totp() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
            now,
        )
        .unwrap()
        .account;
        let summary = acct.summary();
        let rows = [ListAccountRow {
            account: &summary,
            code: Some("123456"),
            seconds_remaining: Some(25),
            next_code: Some("654321"),
        }];
        let v = render_account_list(&rows);
        let arr = v["accounts"].as_array().expect("accounts is array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["label"], serde_json::json!("alice"));
        assert_eq!(arr[0]["issuer"], serde_json::json!("Acme"));
        assert_eq!(arr[0]["kind"], serde_json::json!("totp"));
        assert_eq!(arr[0]["digits"], serde_json::json!(6));
        assert_eq!(arr[0]["period"], serde_json::json!(30));
        assert_eq!(arr[0]["counter"], serde_json::Value::Null);
        assert_eq!(arr[0]["code"], serde_json::json!("123456"));
        assert_eq!(arr[0]["seconds_remaining"], serde_json::json!(25));
        assert_eq!(arr[0]["next_code"], serde_json::json!("654321"));
    }

    #[test]
    fn account_list_envelope_renders_null_code_fields_for_hotp() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://hotp/Beta:bob?secret=JBSWY3DPEHPK3PXP&digits=6&counter=42",
            now,
        )
        .unwrap()
        .account;
        let summary = acct.summary();
        let rows = [ListAccountRow {
            account: &summary,
            code: None,
            seconds_remaining: None,
            next_code: None,
        }];
        let v = render_account_list(&rows);
        let arr = v["accounts"].as_array().expect("accounts is array");
        assert_eq!(arr[0]["kind"], serde_json::json!("hotp"));
        assert_eq!(arr[0]["counter"], serde_json::json!(42));
        assert_eq!(arr[0]["code"], serde_json::Value::Null);
        assert_eq!(arr[0]["seconds_remaining"], serde_json::Value::Null);
        assert_eq!(arr[0]["next_code"], serde_json::Value::Null);
    }

    fn render_add_success(
        account: &AccountSummary,
        warnings: &[ValidationWarning],
    ) -> serde_json::Value {
        let mut buf: Vec<u8> = Vec::new();
        write_add_success(account, warnings, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        serde_json::from_str(s.trim()).expect("valid json")
    }

    #[test]
    fn add_success_envelope_carries_account_and_empty_warnings() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
            now,
        )
        .unwrap()
        .account;
        let v = render_add_success(&acct.summary(), &[]);
        assert_eq!(v["account"]["label"], serde_json::json!("alice"));
        assert_eq!(v["account"]["issuer"], serde_json::json!("Acme"));
        assert_eq!(v["warnings"], serde_json::json!([]));
    }

    #[test]
    fn add_success_envelope_includes_short_secret_warning_in_warnings_array() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // 10 bytes decoded from JBSWY3DPEHPK3PXP is 10 bytes (< 16-byte
        // recommended-min) so a `short_secret` validation warning fires.
        let va = parse_otpauth(
            "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
            now,
        )
        .unwrap();
        assert!(!va.warnings.is_empty(), "fixture must produce a warning");
        let v = render_add_success(&va.account.summary(), &va.warnings);
        let warns = v["warnings"].as_array().expect("warnings is array");
        assert_eq!(warns.len(), 1);
        assert_eq!(warns[0]["kind"], serde_json::json!("short_secret"));
    }

    #[test]
    fn show_codes_envelope_wraps_single_totp_row_under_codes_key() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
            now,
        )
        .unwrap()
        .account;
        let summary = acct.summary();
        let code = Code {
            code: "123456".into(),
            valid_from: Some(1_700_000_000),
            valid_until: Some(1_700_000_030),
            seconds_remaining: Some(30),
            counter_used: None,
        };
        let row = CodeRow {
            account: &summary,
            code: &code,
        };
        let mut buf: Vec<u8> = Vec::new();
        write_show_codes(&[row], &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        let arr = v["codes"].as_array().expect("codes is array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["code"], serde_json::json!("123456"));
        assert_eq!(arr[0]["valid_from"], serde_json::json!(1_700_000_000));
        assert_eq!(arr[0]["valid_until"], serde_json::json!(1_700_000_030));
        assert_eq!(arr[0]["seconds_remaining"], serde_json::json!(30));
        assert_eq!(arr[0]["counter_used"], serde_json::Value::Null);
        assert_eq!(arr[0]["account"]["label"], serde_json::json!("alice"));
        assert_eq!(arr[0]["account"]["kind"], serde_json::json!("totp"));
    }

    #[test]
    fn show_codes_envelope_emits_hotp_row_with_counter_used_and_null_validity() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://hotp/Beta:bob?secret=JBSWY3DPEHPK3PXP&digits=6&counter=42",
            now,
        )
        .unwrap()
        .account;
        let summary = acct.summary();
        let code = Code {
            code: "654321".into(),
            valid_from: None,
            valid_until: None,
            seconds_remaining: None,
            counter_used: Some(42),
        };
        let row = CodeRow {
            account: &summary,
            code: &code,
        };
        let mut buf: Vec<u8> = Vec::new();
        write_show_codes(&[row], &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        let arr = v["codes"].as_array().expect("codes is array");
        assert_eq!(arr[0]["valid_from"], serde_json::Value::Null);
        assert_eq!(arr[0]["valid_until"], serde_json::Value::Null);
        assert_eq!(arr[0]["seconds_remaining"], serde_json::Value::Null);
        assert_eq!(arr[0]["counter_used"], serde_json::json!(42));
        assert_eq!(arr[0]["account"]["kind"], serde_json::json!("hotp"));
    }

    #[test]
    fn show_codes_envelope_empty_codes_array_when_no_rows() {
        let mut buf: Vec<u8> = Vec::new();
        write_show_codes(&[], &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        assert_eq!(v, serde_json::json!({ "codes": [] }));
    }

    #[test]
    fn copy_success_envelope_carries_copied_account_and_counter_used_for_hotp() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://hotp/Beta:bob?secret=JBSWY3DPEHPK3PXP&digits=6&counter=43",
            now,
        )
        .unwrap()
        .account;
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_copy_success(&summary, Some(42), &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        assert_eq!(v["copied"], serde_json::json!(true));
        assert_eq!(v["account"]["counter"], serde_json::json!(43));
        assert_eq!(v["account"]["kind"], serde_json::json!("hotp"));
        assert_eq!(v["counter_used"], serde_json::json!(42));
    }

    #[test]
    fn copy_success_envelope_renders_null_counter_used_for_totp() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
            now,
        )
        .unwrap()
        .account;
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_copy_success(&summary, None, &mut buf).expect("render");
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert_eq!(v["copied"], serde_json::json!(true));
        assert_eq!(v["counter_used"], serde_json::Value::Null);
        assert_eq!(v["account"]["kind"], serde_json::json!("totp"));
    }

    #[test]
    fn remove_success_envelope_carries_account_under_removed_key() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
            now,
        )
        .unwrap()
        .account;
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_remove_success(&summary, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        assert_eq!(v["removed"]["label"], serde_json::json!("alice"));
        assert_eq!(v["removed"]["issuer"], serde_json::json!("Acme"));
        assert_eq!(v["removed"]["kind"], serde_json::json!("totp"));
    }

    #[test]
    fn rename_success_envelope_carries_account_under_account_key() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://totp/Acme:newname?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
            now,
        )
        .unwrap()
        .account;
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_rename_success(&summary, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        assert_eq!(v["account"]["label"], serde_json::json!("newname"));
        assert_eq!(v["account"]["issuer"], serde_json::json!("Acme"));
    }

    #[test]
    fn qr_import_success_envelope_uses_section_5_field_names() {
        let report = ImportReport::default();
        let mut buf: Vec<u8> = Vec::new();
        write_qr_import_success(&report, &[], &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        assert_eq!(v["imported"], serde_json::json!(0));
        assert_eq!(v["skipped"], serde_json::json!(0));
        assert_eq!(v["replaced"], serde_json::json!(0));
        assert_eq!(v["appended"], serde_json::json!(0));
        assert_eq!(v["accounts"], serde_json::json!([]));
        assert_eq!(v["warnings"], serde_json::json!([]));
    }

    #[test]
    fn export_success_envelope_carries_written_path_and_format() {
        let path = std::path::Path::new("/tmp/example/creds.json");
        let mut buf: Vec<u8> = Vec::new();
        write_export_success(path, "otpauth", &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        assert_eq!(v["written"], serde_json::json!("/tmp/example/creds.json"));
        assert_eq!(v["format"], serde_json::json!("otpauth"));
    }

    #[test]
    fn export_success_envelope_uses_paladin_format_for_encrypted_bundle() {
        let path = std::path::Path::new("/tmp/bundle.bin");
        let mut buf: Vec<u8> = Vec::new();
        write_export_success(path, "paladin", &mut buf).expect("render");
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert_eq!(v["format"], serde_json::json!("paladin"));
    }

    #[test]
    fn settings_envelope_emits_nested_section_5_shape_with_default_values() {
        let settings = VaultSettings::default();
        let mut buf: Vec<u8> = Vec::new();
        write_settings(&settings, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.ends_with('\n'), "expected single trailing newline");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("valid json");
        assert_eq!(
            v,
            serde_json::json!({
                "auto_lock":  { "enabled": false, "timeout_secs": 300 },
                "clipboard":  { "clear_enabled": false, "clear_secs": 20 },
            }),
        );
    }
}
