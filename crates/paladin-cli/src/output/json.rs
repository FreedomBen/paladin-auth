// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable JSON envelope renderers per DESIGN.md §5. Each helper writes
//! exactly one JSON document to the supplied `Write` followed by a
//! single newline, with no other bytes — matching the CLI's
//! "stdout is one document plus newline" wire contract under `--json`.

use std::io::Write;

use paladin_core::{AccountSummary, ImportReport, ImportWarning, ValidationWarning, VaultMode};
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

/// `paladin list` success envelope: `{ "accounts": [AccountSummary] }`
/// per the §5 JSON shape table. The slice is serialized in insertion
/// order; an empty vault renders `{ "accounts": [] }`.
#[derive(Debug, Serialize)]
struct AccountList<'a> {
    accounts: &'a [AccountSummary],
}

/// Render the `paladin list` success envelope.
pub fn write_account_list(accounts: &[AccountSummary], mut out: impl Write) -> std::io::Result<()> {
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

    fn render_account_list(accounts: &[AccountSummary]) -> serde_json::Value {
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
    fn account_list_envelope_contains_summaries_under_accounts_key() {
        use paladin_core::parse_otpauth;
        use std::time::{Duration, SystemTime};
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let acct = parse_otpauth(
            "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30",
            now,
        )
        .unwrap()
        .account;
        let summaries = vec![acct.summary()];
        let v = render_account_list(&summaries);
        let arr = v["accounts"].as_array().expect("accounts is array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["label"], serde_json::json!("alice"));
        assert_eq!(arr[0]["issuer"], serde_json::json!("Acme"));
        assert_eq!(arr[0]["kind"], serde_json::json!("totp"));
        assert_eq!(arr[0]["digits"], serde_json::json!(6));
        assert_eq!(arr[0]["period"], serde_json::json!(30));
        assert_eq!(arr[0]["counter"], serde_json::Value::Null);
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
}
