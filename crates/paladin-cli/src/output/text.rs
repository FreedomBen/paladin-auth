// SPDX-License-Identifier: AGPL-3.0-or-later

//! Human text renderers per DESIGN.md §5. Each helper writes a short,
//! parseable line to the supplied `Write` and is parameterized so the
//! command bodies don't have to thread `format!` calls through their
//! own logic.

use std::io::Write;
use std::path::Path;

use paladin_core::{
    format_validation_warning, AccountKindSummary, AccountSummary, Algorithm, Code, ImportReport,
    ValidationWarning, VaultMode,
};

/// Print the success line for `paladin init` to stdout, e.g.
/// "Created plaintext vault at /path/to/vault.bin." Mirrors the §5 JSON
/// envelope's `status` field so the text and JSON paths stay
/// in sync.
pub fn write_init_success(
    mode: VaultMode,
    path: &Path,
    mut out: impl Write,
) -> std::io::Result<()> {
    writeln!(
        out,
        "Created {} vault at {}.",
        mode.as_str(),
        path.display()
    )
}

/// One row in the `paladin list` text output. The CLI passes the
/// shortest unique `id:` hex prefix (computed in core via
/// `Vault::shortest_unique_id_prefix`) so list output and the
/// `multiple_matches` candidate lines share a single disambiguator
/// shape.
pub struct ListRow<'a> {
    pub disambiguator: &'a str,
    pub summary: &'a AccountSummary,
}

/// Print account metadata for `paladin list` to stdout. An empty
/// `rows` slice writes zero bytes — the §5 contract is "no codes, no
/// rows for an empty vault".
///
/// Format: tab-separated, one line per account, mirroring how
/// command-line tools like `kubectl get` or `column -t` consume
/// output. Fields: `<id-prefix>` `<kind>/<alg>/<digits>`
/// `<period|counter>` `<issuer:label>`.
pub fn write_account_list(rows: &[ListRow<'_>], mut out: impl Write) -> std::io::Result<()> {
    for row in rows {
        let s = row.summary;
        let kind = match s.kind {
            AccountKindSummary::Totp => "totp",
            AccountKindSummary::Hotp => "hotp",
        };
        let alg = match s.algorithm {
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
        };
        let kind_field = format!("{kind}/{alg}/{}", s.digits);
        let period_or_counter = match (s.period, s.counter) {
            (Some(p), None) => format!("{p}s"),
            (None, Some(c)) => format!("c={c}"),
            // §4.7 invariants guarantee TOTP has period and HOTP has
            // counter; both branches missing or both set would be a
            // core bug, so render a placeholder rather than panicking.
            _ => "-".to_string(),
        };
        let label = display_label(s);
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            row.disambiguator, kind_field, period_or_counter, label
        )?;
    }
    Ok(())
}

/// `issuer:label` if issuer is set and non-empty, else just `label`.
fn display_label(s: &AccountSummary) -> String {
    match s.issuer.as_deref().filter(|i| !i.is_empty()) {
        Some(issuer) => format!("{issuer}:{}", s.label),
        None => s.label.clone(),
    }
}

/// One row in the `paladin show` / `paladin peek` text output.
/// `disambiguator` is the shortest unique `id:<hex>` prefix from
/// `Vault::shortest_unique_id_prefix`, so a multi-row response keeps
/// the same selector shape as `list` and `multiple_matches` candidate
/// lines.
pub struct CodeRow<'a> {
    pub disambiguator: &'a str,
    pub account: &'a AccountSummary,
    pub code: &'a Code,
}

/// Print one line per `CodeRow` to stdout. Format is tab-separated:
/// `<id-prefix>` `<issuer:label>` `<code>` `<remaining-or-counter>`,
/// mirroring the `list` row shape with the code replacing the
/// `<kind>/<alg>/<digits>` column. TOTP rows render the trailing
/// column as `<seconds_remaining>s` and HOTP rows render it as
/// `c=<counter_used>`. An empty `rows` slice writes zero bytes; the
/// CLI rejects empty match sets earlier with `no_match`.
pub fn write_code_rows(rows: &[CodeRow<'_>], mut out: impl Write) -> std::io::Result<()> {
    for row in rows {
        let trailing = match (row.code.seconds_remaining, row.code.counter_used) {
            (Some(secs), None) => format!("{secs}s"),
            (None, Some(c)) => format!("c={c}"),
            // Mirrors the `list` placeholder for the impossible
            // (TOTP+HOTP / neither) case so a core invariant break
            // surfaces a "-" instead of panicking.
            _ => "-".to_string(),
        };
        let label = display_label(row.account);
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            row.disambiguator, label, row.code.code, trailing
        )?;
    }
    Ok(())
}

/// Print the success line for `paladin add` (single-entry) to stdout,
/// e.g. "Added Acme:alice (id:abcdef01).". `disambiguator` is the
/// shortest unique `id:<hex>` prefix from
/// `Vault::shortest_unique_id_prefix`.
pub fn write_add_success(
    account: &AccountSummary,
    disambiguator: &str,
    mut out: impl Write,
) -> std::io::Result<()> {
    writeln!(out, "Added {} ({}).", display_label(account), disambiguator)
}

/// Print the `paladin copy` success line to stdout. Mirrors the §5
/// JSON envelope's `copied: true` flag in human-readable form. The
/// CLI never auto-clears the clipboard, so the wording is unchanged
/// regardless of the vault's `clipboard.clear_enabled` setting.
pub fn write_copy_success(account: &AccountSummary, mut out: impl Write) -> std::io::Result<()> {
    writeln!(out, "Copied {} code to clipboard.", display_label(account))
}

/// Print the success line for `paladin remove` to stdout, e.g.
/// "Removed Acme:alice." Mirrors the §5 JSON envelope's `removed` key
/// in human-readable form. The CLI prompts for destructive
/// confirmation (or rejects under `--json` without `--yes`) before
/// the mutation runs, so this success line only fires after a
/// committed save.
pub fn write_remove_success(account: &AccountSummary, mut out: impl Write) -> std::io::Result<()> {
    writeln!(out, "Removed {}.", display_label(account))
}

/// Print the success line for `paladin rename` to stdout, e.g.
/// "Renamed to Acme:newname." `account` reflects the post-rename
/// state (new label + bumped `updated_at`) so the rendered line
/// matches what a follow-up `list` would show.
pub fn write_rename_success(account: &AccountSummary, mut out: impl Write) -> std::io::Result<()> {
    writeln!(out, "Renamed to {}.", display_label(account))
}

/// Print the success line for `paladin passphrase
/// {set,change,remove}` to stdout. Mirrors the JSON envelope's
/// `{ "ok": true, "status": ... }` in human-readable form. Callers
/// pick the line so the renderer stays oblivious to which subcommand
/// fired and the wording cannot drift between subcommands without a
/// callsite change.
pub fn write_passphrase_success(line: &str, mut out: impl Write) -> std::io::Result<()> {
    writeln!(out, "{line}")
}

/// Print the success summary for `paladin add --qr` (multi-entry) to
/// stdout. Mirrors the §5 JSON envelope counts so text and JSON paths
/// stay in sync. `--on-conflict=skip` is fixed for `add --qr`, so
/// `replaced` / `appended` are zero on this path.
pub fn write_qr_import_success(report: &ImportReport, mut out: impl Write) -> std::io::Result<()> {
    writeln!(
        out,
        "Imported {} account(s) (skipped {}).",
        report.imported, report.skipped,
    )
}

/// Print the success line for `paladin export` to stdout. `format_label`
/// is the §5 stable string (`"otpauth"` for plaintext, `"paladin"` for
/// encrypted) and is rendered as the human-readable mode prefix.
pub fn write_export_success(
    written_path: &Path,
    format_label: &str,
    mut out: impl Write,
) -> std::io::Result<()> {
    // Mirror the §5 JSON `format` strings so the human output and the
    // wire envelope agree on which mode wrote the file.
    let mode = match format_label {
        "otpauth" => "plaintext",
        "paladin" => "encrypted",
        other => other,
    };
    writeln!(
        out,
        "Exported {} bundle to {}.",
        mode,
        written_path.display()
    )
}

/// Write a single `short_secret` validation-warning advisory to the
/// supplied stream, prefixed with `paladin: warning:`. The CLI calls
/// this in text mode only — under `--json` warnings flow through the
/// success envelope's `warnings` array (per the strict-mode rule in
/// `IMPLEMENTATION_PLAN_02_CLI.md`).
pub fn write_validation_warning(
    warning: &ValidationWarning,
    mut out: impl Write,
) -> std::io::Result<()> {
    writeln!(
        out,
        "paladin: warning: {}",
        format_validation_warning(warning)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use paladin_core::{parse_otpauth, Account};
    use std::time::{Duration, SystemTime};

    fn render_init_success(mode: VaultMode, path: &Path) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_init_success(mode, path, &mut buf).expect("render");
        String::from_utf8(buf).expect("utf-8")
    }

    #[test]
    fn init_success_includes_mode_and_path_with_trailing_newline() {
        let path = PathBuf::from("/tmp/example/vault.bin");
        let s = render_init_success(VaultMode::Plaintext, &path);
        assert_eq!(s, "Created plaintext vault at /tmp/example/vault.bin.\n");
    }

    #[test]
    fn init_success_encrypted_uses_encrypted_label() {
        let path = PathBuf::from("/tmp/v.bin");
        let s = render_init_success(VaultMode::Encrypted, &path);
        assert_eq!(s, "Created encrypted vault at /tmp/v.bin.\n");
    }

    fn fixture_now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn make_totp(label: &str, issuer: Option<&str>) -> Account {
        let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
        let uri = format!(
            "otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP&digits=6&period=30"
        );
        parse_otpauth(&uri, fixture_now()).unwrap().account
    }

    fn make_hotp(label: &str, issuer: Option<&str>, counter: u64) -> Account {
        let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
        let uri = format!(
            "otpauth://hotp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP&digits=6&counter={counter}"
        );
        parse_otpauth(&uri, fixture_now()).unwrap().account
    }

    fn render_list(rows: &[ListRow<'_>]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_account_list(rows, &mut buf).expect("render");
        String::from_utf8(buf).expect("utf-8")
    }

    #[test]
    fn empty_account_list_writes_zero_bytes() {
        assert_eq!(render_list(&[]), "");
    }

    #[test]
    fn totp_row_renders_period_in_seconds_and_issuer_label() {
        let acct = make_totp("alice", Some("Acme"));
        let summary = acct.summary();
        let rows = [ListRow {
            disambiguator: "id:abcdef01",
            summary: &summary,
        }];
        let s = render_list(&rows);
        assert_eq!(s, "id:abcdef01\ttotp/sha1/6\t30s\tAcme:alice\n");
    }

    #[test]
    fn hotp_row_renders_counter_marker_and_bare_label_when_no_issuer() {
        let acct = make_hotp("bob", None, 42);
        let summary = acct.summary();
        let rows = [ListRow {
            disambiguator: "id:fedcba98",
            summary: &summary,
        }];
        let s = render_list(&rows);
        assert_eq!(s, "id:fedcba98\thotp/sha1/6\tc=42\tbob\n");
    }

    #[test]
    fn add_success_includes_label_disambiguator_and_trailing_newline() {
        let acct = make_totp("alice", Some("Acme"));
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_add_success(&summary, "id:abcdef01", &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Added Acme:alice (id:abcdef01).\n");
    }

    #[test]
    fn add_success_falls_back_to_bare_label_when_issuer_empty() {
        let acct = make_totp("bob", None);
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_add_success(&summary, "id:fedcba98", &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Added bob (id:fedcba98).\n");
    }

    #[test]
    fn copy_success_includes_label_and_trailing_newline() {
        let acct = make_totp("alice", Some("Acme"));
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_copy_success(&summary, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Copied Acme:alice code to clipboard.\n");
    }

    #[test]
    fn copy_success_falls_back_to_bare_label_when_issuer_empty() {
        let acct = make_totp("bob", None);
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_copy_success(&summary, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Copied bob code to clipboard.\n");
    }

    #[test]
    fn remove_success_includes_label_and_trailing_newline() {
        let acct = make_totp("alice", Some("Acme"));
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_remove_success(&summary, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Removed Acme:alice.\n");
    }

    #[test]
    fn remove_success_falls_back_to_bare_label_when_issuer_empty() {
        let acct = make_hotp("bob", None, 0);
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_remove_success(&summary, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Removed bob.\n");
    }

    #[test]
    fn rename_success_renders_post_rename_label_with_trailing_newline() {
        let acct = make_totp("newname", Some("Acme"));
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_rename_success(&summary, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Renamed to Acme:newname.\n");
    }

    #[test]
    fn rename_success_falls_back_to_bare_label_when_issuer_empty() {
        let acct = make_totp("newname", None);
        let summary = acct.summary();
        let mut buf: Vec<u8> = Vec::new();
        write_rename_success(&summary, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Renamed to newname.\n");
    }

    fn render_passphrase(line: &str) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_passphrase_success(line, &mut buf).expect("render");
        String::from_utf8(buf).expect("utf-8")
    }

    #[test]
    fn passphrase_success_writes_caller_line_with_trailing_newline() {
        assert_eq!(render_passphrase("Encrypted vault."), "Encrypted vault.\n");
        assert_eq!(
            render_passphrase("Re-encrypted vault."),
            "Re-encrypted vault.\n"
        );
        assert_eq!(
            render_passphrase("Decrypted vault to plaintext."),
            "Decrypted vault to plaintext.\n"
        );
    }

    #[test]
    fn qr_import_success_reports_imported_and_skipped_counts() {
        let report = ImportReport {
            imported: 3,
            skipped: 1,
            ..ImportReport::default()
        };
        let mut buf: Vec<u8> = Vec::new();
        write_qr_import_success(&report, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Imported 3 account(s) (skipped 1).\n");
    }

    #[test]
    fn export_success_renders_plaintext_mode_label_for_otpauth_format() {
        let path = PathBuf::from("/tmp/example/creds.json");
        let mut buf: Vec<u8> = Vec::new();
        write_export_success(&path, "otpauth", &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Exported plaintext bundle to /tmp/example/creds.json.\n");
    }

    #[test]
    fn export_success_renders_encrypted_mode_label_for_paladin_format() {
        let path = PathBuf::from("/tmp/bundle.bin");
        let mut buf: Vec<u8> = Vec::new();
        write_export_success(&path, "paladin", &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "Exported encrypted bundle to /tmp/bundle.bin.\n");
    }

    #[test]
    fn code_row_totp_renders_seconds_remaining_with_s_suffix() {
        let acct = make_totp("alice", Some("Acme"));
        let summary = acct.summary();
        let code = Code {
            code: "123456".into(),
            valid_from: Some(1_700_000_000),
            valid_until: Some(1_700_000_030),
            seconds_remaining: Some(25),
            counter_used: None,
        };
        let row = CodeRow {
            disambiguator: "id:abcdef01",
            account: &summary,
            code: &code,
        };
        let mut buf: Vec<u8> = Vec::new();
        write_code_rows(&[row], &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "id:abcdef01\tAcme:alice\t123456\t25s\n");
    }

    #[test]
    fn code_row_hotp_renders_c_prefix_with_pre_advance_counter_used() {
        let acct = make_hotp("bob", None, 42);
        let summary = acct.summary();
        let code = Code {
            code: "654321".into(),
            valid_from: None,
            valid_until: None,
            seconds_remaining: None,
            counter_used: Some(42),
        };
        let row = CodeRow {
            disambiguator: "id:fedcba98",
            account: &summary,
            code: &code,
        };
        let mut buf: Vec<u8> = Vec::new();
        write_code_rows(&[row], &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert_eq!(s, "id:fedcba98\tbob\t654321\tc=42\n");
    }

    #[test]
    fn code_rows_empty_slice_writes_zero_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_code_rows(&[], &mut buf).expect("render");
        assert!(buf.is_empty());
    }

    #[test]
    fn code_rows_emit_one_line_per_entry_in_supplied_order() {
        let a = make_totp("alice", Some("Acme"));
        let b = make_totp("alice", Some("Beta"));
        let sa = a.summary();
        let sb = b.summary();
        let code_a = Code {
            code: "111111".into(),
            valid_from: Some(0),
            valid_until: Some(30),
            seconds_remaining: Some(10),
            counter_used: None,
        };
        let code_b = Code {
            code: "222222".into(),
            valid_from: Some(0),
            valid_until: Some(30),
            seconds_remaining: Some(10),
            counter_used: None,
        };
        let rows = [
            CodeRow {
                disambiguator: "id:11111111",
                account: &sa,
                code: &code_a,
            },
            CodeRow {
                disambiguator: "id:22222222",
                account: &sb,
                code: &code_b,
            },
        ];
        let mut buf: Vec<u8> = Vec::new();
        write_code_rows(&rows, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Acme:alice"));
        assert!(lines[0].contains("111111"));
        assert!(lines[1].contains("Beta:alice"));
        assert!(lines[1].contains("222222"));
    }

    #[test]
    fn validation_warning_writes_paladin_warning_prefix_to_stream() {
        let warning = ValidationWarning::ShortSecret {
            decoded_len: 10,
            recommended_min: 16,
        };
        let mut buf: Vec<u8> = Vec::new();
        write_validation_warning(&warning, &mut buf).expect("render");
        let s = String::from_utf8(buf).expect("utf-8");
        assert!(s.starts_with("paladin: warning: "), "got {s:?}");
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn multiple_rows_emit_one_line_per_account_in_order() {
        let a = make_totp("alice", Some("Acme"));
        let b = make_hotp("bob", Some("Beta"), 0);
        let sa = a.summary();
        let sb = b.summary();
        let rows = [
            ListRow {
                disambiguator: "id:11111111",
                summary: &sa,
            },
            ListRow {
                disambiguator: "id:22222222",
                summary: &sb,
            },
        ];
        let s = render_list(&rows);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Acme:alice"));
        assert!(lines[1].contains("Beta:bob"));
    }
}
