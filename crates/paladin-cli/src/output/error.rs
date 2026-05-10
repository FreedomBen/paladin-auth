// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error envelope rendering. Maps the CLI-level [`CliError`] onto the
//! DESIGN.md §5 `error_kind` taxonomy. Behind `--json` every error
//! exits with one JSON document on stderr; in text mode the renderer
//! delegates to whichever upstream wrote the message (clap for syntax
//! errors, `Display` on `PaladinError` for runtime errors).

use std::io::Write;

use paladin_core::{AccountSummary, PaladinError};
use serde::Serialize;

use super::Mode;

/// One row in a `multiple_matches` envelope. Embeds the public §5
/// [`AccountSummary`] verbatim and adds the shortest `id:<hex>` prefix
/// that uniquely identifies the entry in the current vault (computed
/// by `Vault::shortest_unique_id_prefix`, ≥ 8 hex chars). The
/// `disambiguator` lets a user re-issue the failing command with
/// `id:<hex>` to pick exactly one of the matches.
///
/// JSON shape: the [`AccountSummary`] fields are flattened into the
/// candidate object, with `disambiguator` appended — matching the
/// stable §5 wire format called out in `IMPLEMENTATION_PLAN_02_CLI.md`.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// Public account summary fields per §5 (`id`, `issuer`, `label`,
    /// `kind`, `algorithm`, `digits`, `period`, `counter`, `icon_hint`,
    /// `created_at`, `updated_at`).
    #[serde(flatten)]
    pub summary: AccountSummary,
    /// Shortest unique `id:<hex>` prefix for this account, ≥ 8 hex chars.
    pub disambiguator: String,
}

/// Errors that the CLI surfaces to the caller. Distinguished from
/// `paladin_core::PaladinError` so we can route clap diagnostics,
/// presentation-only §5 kinds (`no_match`, `multiple_matches`), and
/// scaffold-only stubs through the same rendering pipeline.
#[derive(Debug)]
pub enum CliError {
    /// A real §5 error from `paladin-core`. Rendered as the verbatim
    /// JSON envelope under `--json`, or `Display` on `PaladinError`
    /// in text mode.
    Paladin(PaladinError),
    /// Clap detected a syntax / usage failure. `text_message` is the
    /// rendered diagnostic clap would have written in text mode; the
    /// JSON path emits a `validation_error` with `field: "argv"`,
    /// `reason: "usage"` per the plan's argv pre-scan rule.
    Usage {
        /// Verbatim clap diagnostic (already terminated) for text mode.
        text_message: String,
    },
    /// Query matched zero accounts. Presentation-only `error_kind`
    /// per DESIGN.md §5 — `paladin-core` exposes the matching primitives
    /// but never returns this kind; the CLI is responsible for
    /// rejecting empty match sets.
    NoMatch {
        /// Original query text the user supplied. Reflected in the
        /// text-mode message; the JSON envelope carries only
        /// `error_kind` per the §5 stable schema.
        query: String,
    },
    /// Query matched more than one account when the command requires
    /// a single target (or for `show` when any HOTP account is in the
    /// match set). Presentation-only `error_kind` per DESIGN.md §5.
    MultipleMatches {
        /// Original query text the user supplied. Reflected in the
        /// text-mode message; the JSON envelope carries `error_kind`
        /// and `candidates` per the §5 stable schema.
        query: String,
        /// Match set with stable disambiguators, in insertion order.
        candidates: Vec<Candidate>,
    },
    /// `add` collided with an existing `(secret, issuer, label)` entry
    /// and `--allow-duplicate` was not supplied. Presentation-only
    /// `error_kind` per DESIGN.md §5 — `paladin-core` exposes
    /// [`paladin_core::Vault::find_duplicate`] for the comparison but
    /// never returns this kind.
    DuplicateAccount {
        /// Existing account that collides with the candidate. Carried
        /// verbatim into the §5 `account` field of the JSON envelope.
        account: AccountSummary,
    },
    /// `paladin copy` clipboard write failed *after* any HOTP advance
    /// has already committed to disk. Presentation-only `error_kind`
    /// per DESIGN.md §5 — the CLI does not roll the counter back
    /// because the code may already have been exposed to the clipboard
    /// provider. The carried `account` reflects the persisted
    /// post-advance state and `counter_used` is the pre-advance counter
    /// that produced the visible code (`None` for TOTP).
    ClipboardWriteFailed {
        /// Persisted account state after the (possibly committed) HOTP
        /// advance — surfaced as `account` in the §5 JSON envelope.
        account: AccountSummary,
        /// Pre-advance counter for HOTP, `None` for TOTP. Surfaced as
        /// `counter_used` in the §5 JSON envelope.
        counter_used: Option<u64>,
    },
}

impl From<PaladinError> for CliError {
    fn from(err: PaladinError) -> Self {
        Self::Paladin(err)
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paladin(p) => std::fmt::Display::fmt(p, f),
            Self::Usage { text_message } => f.write_str(text_message),
            Self::NoMatch { query } => {
                write!(f, "no account matched query {query:?}")
            }
            Self::MultipleMatches { query, candidates } => {
                write!(f, "query {query:?} matched {} accounts:", candidates.len())?;
                for c in candidates {
                    write!(f, "\n  {} ({})", display_label(&c.summary), c.disambiguator)?;
                }
                Ok(())
            }
            Self::DuplicateAccount { account } => {
                write!(
                    f,
                    "account already exists with the same (secret, issuer, label): {} (re-run with --allow-duplicate to add anyway)",
                    display_label(account),
                )
            }
            Self::ClipboardWriteFailed { account, .. } => {
                write!(
                    f,
                    "clipboard write failed for {} (the OTP code was generated; for HOTP the counter advance was committed before the failed write)",
                    display_label(account),
                )
            }
        }
    }
}

/// Render a candidate's `issuer:label` (or just `label` when the issuer
/// is empty) for the text-mode `multiple_matches` list.
fn display_label(s: &AccountSummary) -> String {
    match s.issuer.as_deref().filter(|i| !i.is_empty()) {
        Some(issuer) => format!("{issuer}:{}", s.label),
        None => s.label.clone(),
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Paladin(p) => Some(p),
            _ => None,
        }
    }
}

/// Render `err` to `out` in the chosen [`Mode`]. The caller is
/// responsible for picking the stream (stderr) and flushing.
///
/// Under `--json`, exactly one JSON document is written (terminated by
/// a single newline) and nothing else. In text mode the renderer prints
/// `paladin: <message>` for runtime errors and the verbatim clap
/// diagnostic for usage errors.
pub fn render(err: &CliError, mode: Mode, mut out: impl Write) -> std::io::Result<()> {
    match (mode, err) {
        (Mode::Json, CliError::Paladin(p)) => {
            serde_json::to_writer(&mut out, p).map_err(std::io::Error::other)?;
            writeln!(out)?;
        }
        (Mode::Json, CliError::Usage { .. }) => {
            let envelope = serde_json::json!({
                "error_kind": "validation_error",
                "field": "argv",
                "reason": "usage",
            });
            serde_json::to_writer(&mut out, &envelope).map_err(std::io::Error::other)?;
            writeln!(out)?;
        }
        (Mode::Json, CliError::NoMatch { .. }) => {
            let envelope = serde_json::json!({ "error_kind": "no_match" });
            serde_json::to_writer(&mut out, &envelope).map_err(std::io::Error::other)?;
            writeln!(out)?;
        }
        (Mode::Json, CliError::MultipleMatches { candidates, .. }) => {
            let envelope = serde_json::json!({
                "error_kind": "multiple_matches",
                "candidates": candidates,
            });
            serde_json::to_writer(&mut out, &envelope).map_err(std::io::Error::other)?;
            writeln!(out)?;
        }
        (Mode::Json, CliError::DuplicateAccount { account }) => {
            let envelope = serde_json::json!({
                "error_kind": "duplicate_account",
                "account": account,
            });
            serde_json::to_writer(&mut out, &envelope).map_err(std::io::Error::other)?;
            writeln!(out)?;
        }
        (
            Mode::Json,
            CliError::ClipboardWriteFailed {
                account,
                counter_used,
            },
        ) => {
            let envelope = serde_json::json!({
                "error_kind": "clipboard_write_failed",
                "account": account,
                "counter_used": counter_used,
            });
            serde_json::to_writer(&mut out, &envelope).map_err(std::io::Error::other)?;
            writeln!(out)?;
        }
        (Mode::Text { .. }, CliError::Usage { text_message }) => {
            // Clap's render() already terminates with a newline.
            write!(out, "{text_message}")?;
        }
        (
            Mode::Text { .. },
            CliError::Paladin(_)
            | CliError::NoMatch { .. }
            | CliError::DuplicateAccount { .. }
            | CliError::ClipboardWriteFailed { .. },
        ) => {
            writeln!(out, "paladin: {err}")?;
        }
        (Mode::Text { .. }, CliError::MultipleMatches { .. }) => {
            // Multi-line via `Display`; one trailing newline.
            writeln!(out, "paladin: {err}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use paladin_core::{AccountId, AccountKindSummary, Algorithm};

    fn render_to_string(err: &CliError, mode: Mode) -> String {
        let mut buf: Vec<u8> = Vec::new();
        render(err, mode, &mut buf).expect("render");
        String::from_utf8(buf).expect("utf-8")
    }

    fn fixture_summary(label: &str, issuer: Option<&str>) -> AccountSummary {
        AccountSummary {
            id: AccountId::new(),
            issuer: issuer.map(str::to_string),
            label: label.to_string(),
            kind: AccountKindSummary::Totp,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: Some(30),
            counter: None,
            icon_hint: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn fixture_candidate(label: &str, issuer: Option<&str>, disambig: &str) -> Candidate {
        Candidate {
            summary: fixture_summary(label, issuer),
            disambiguator: disambig.to_string(),
        }
    }

    #[test]
    fn json_mode_emits_paladin_error_envelope_with_kind() {
        let err = CliError::Paladin(PaladinError::VaultMissing);
        let s = render_to_string(&err, Mode::Json);
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["error_kind"], serde_json::json!("vault_missing"));
    }

    #[test]
    fn json_mode_usage_uses_argv_validation_error() {
        let err = CliError::Usage {
            text_message: "ignored in json".into(),
        };
        let s = render_to_string(&err, Mode::Json);
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["error_kind"], serde_json::json!("validation_error"));
        assert_eq!(v["field"], serde_json::json!("argv"));
        assert_eq!(v["reason"], serde_json::json!("usage"));
    }

    #[test]
    fn text_mode_paladin_error_prefixed_with_program_name() {
        let err = CliError::Paladin(PaladinError::VaultMissing);
        let s = render_to_string(&err, Mode::Text { color: false });
        assert!(
            s.starts_with("paladin: "),
            "expected program-name prefix, got {s:?}"
        );
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn text_mode_usage_writes_clap_message_verbatim() {
        let err = CliError::Usage {
            text_message: "error: missing <QUERY>\n".into(),
        };
        let s = render_to_string(&err, Mode::Text { color: false });
        assert_eq!(s, "error: missing <QUERY>\n");
    }

    #[test]
    fn json_mode_no_match_envelope_carries_only_error_kind() {
        let err = CliError::NoMatch {
            query: "alice".into(),
        };
        let s = render_to_string(&err, Mode::Json);
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["error_kind"], serde_json::json!("no_match"));
        // §5 stable schema: query text is not on the wire.
        assert!(v.get("query").is_none(), "unexpected `query` field: {v:?}");
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn text_mode_no_match_includes_query_in_message() {
        let err = CliError::NoMatch {
            query: "alice".into(),
        };
        let s = render_to_string(&err, Mode::Text { color: false });
        assert!(s.starts_with("paladin: "), "got {s:?}");
        assert!(s.contains("alice"), "missing query in message: {s:?}");
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn json_mode_multiple_matches_flattens_summary_and_appends_disambiguator() {
        let err = CliError::MultipleMatches {
            query: "alice".into(),
            candidates: vec![
                fixture_candidate("alice", Some("GitHub"), "id:abcdef01"),
                fixture_candidate("alice", Some("GitLab"), "id:12345678"),
            ],
        };
        let s = render_to_string(&err, Mode::Json);
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["error_kind"], serde_json::json!("multiple_matches"));
        let cands = v["candidates"].as_array().expect("array");
        assert_eq!(cands.len(), 2);
        // Flattened summary: top-level `issuer`, `label`, `kind`, …, plus `disambiguator`.
        assert_eq!(cands[0]["issuer"], serde_json::json!("GitHub"));
        assert_eq!(cands[0]["label"], serde_json::json!("alice"));
        assert_eq!(cands[0]["kind"], serde_json::json!("totp"));
        assert_eq!(cands[0]["disambiguator"], serde_json::json!("id:abcdef01"));
        assert_eq!(cands[1]["disambiguator"], serde_json::json!("id:12345678"));
        // Schema is locked: no `query` and no nested `summary` object.
        assert!(v.get("query").is_none());
        assert!(cands[0].get("summary").is_none());
    }

    #[test]
    fn json_mode_duplicate_account_envelope_carries_account_summary() {
        let err = CliError::DuplicateAccount {
            account: fixture_summary("alice", Some("Acme")),
        };
        let s = render_to_string(&err, Mode::Json);
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["error_kind"], serde_json::json!("duplicate_account"));
        assert_eq!(v["account"]["label"], serde_json::json!("alice"));
        assert_eq!(v["account"]["issuer"], serde_json::json!("Acme"));
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn text_mode_duplicate_account_includes_label_and_recovery_hint() {
        let err = CliError::DuplicateAccount {
            account: fixture_summary("alice", Some("Acme")),
        };
        let s = render_to_string(&err, Mode::Text { color: false });
        assert!(s.starts_with("paladin: "), "got {s:?}");
        assert!(s.contains("Acme:alice"), "missing label: {s:?}");
        assert!(s.contains("--allow-duplicate"), "missing hint: {s:?}");
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn json_mode_clipboard_write_failed_carries_account_and_counter_used_for_hotp() {
        let mut summary = fixture_summary("bob", None);
        summary.kind = AccountKindSummary::Hotp;
        summary.period = None;
        summary.counter = Some(43);
        let err = CliError::ClipboardWriteFailed {
            account: summary,
            counter_used: Some(42),
        };
        let s = render_to_string(&err, Mode::Json);
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["error_kind"], serde_json::json!("clipboard_write_failed"));
        // post-advance summary in `account`, pre-advance in `counter_used`.
        assert_eq!(v["account"]["counter"], serde_json::json!(43));
        assert_eq!(v["counter_used"], serde_json::json!(42));
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn json_mode_clipboard_write_failed_emits_null_counter_used_for_totp() {
        let err = CliError::ClipboardWriteFailed {
            account: fixture_summary("alice", Some("Acme")),
            counter_used: None,
        };
        let s = render_to_string(&err, Mode::Json);
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["error_kind"], serde_json::json!("clipboard_write_failed"));
        assert_eq!(v["counter_used"], serde_json::Value::Null);
    }

    #[test]
    fn text_mode_clipboard_write_failed_includes_label_and_advance_disclaimer() {
        let err = CliError::ClipboardWriteFailed {
            account: fixture_summary("alice", Some("Acme")),
            counter_used: None,
        };
        let s = render_to_string(&err, Mode::Text { color: false });
        assert!(s.starts_with("paladin: "), "got {s:?}");
        assert!(s.contains("Acme:alice"), "missing label: {s:?}");
        assert!(s.contains("counter advance"), "missing disclaimer: {s:?}");
    }

    #[test]
    fn text_mode_multiple_matches_lists_each_candidate_with_disambiguator() {
        let err = CliError::MultipleMatches {
            query: "alice".into(),
            candidates: vec![
                fixture_candidate("alice", Some("GitHub"), "id:abcdef01"),
                fixture_candidate("alice", None, "id:12345678"),
            ],
        };
        let s = render_to_string(&err, Mode::Text { color: false });
        assert!(s.starts_with("paladin: "), "got {s:?}");
        assert!(s.contains("alice"), "missing query: {s:?}");
        assert!(
            s.contains("GitHub:alice (id:abcdef01)"),
            "missing first candidate: {s:?}"
        );
        // Issuer-less candidate falls back to bare label.
        assert!(
            s.contains("alice (id:12345678)"),
            "missing second candidate: {s:?}"
        );
        assert!(s.ends_with('\n'));
    }
}
