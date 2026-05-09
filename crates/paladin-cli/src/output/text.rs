// SPDX-License-Identifier: AGPL-3.0-or-later

//! Human text renderers per DESIGN.md §5. Each helper writes a short,
//! parseable line to the supplied `Write` and is parameterized so the
//! command bodies don't have to thread `format!` calls through their
//! own logic.

use std::io::Write;
use std::path::Path;

use paladin_core::{AccountKindSummary, AccountSummary, Algorithm, VaultMode};

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
