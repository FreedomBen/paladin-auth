// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable JSON envelope renderers per DESIGN.md §5. Each helper writes
//! exactly one JSON document to the supplied `Write` followed by a
//! single newline, with no other bytes — matching the CLI's
//! "stdout is one document plus newline" wire contract under `--json`.

use std::io::Write;

use paladin_core::{AccountSummary, VaultMode};
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
}
