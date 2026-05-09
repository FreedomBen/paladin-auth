// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/dev/tty` passphrase, account, and destructive-confirmation
//! prompts per `IMPLEMENTATION_PLAN_02_CLI.md` "Passphrase prompts"
//! and "Non-passphrase TTY prompts" and DESIGN.md §5.
//!
//! All interactive prompts go through `/dev/tty` in both text and
//! `--json` modes — never stdin/stdout/stderr — so a script that
//! redirects either stream still sees clean machine-readable output.
//! Passphrase prompt strings are written to `/dev/tty` directly
//! (rather than `rpassword::prompt_password`, which writes to stderr)
//! so the `--json` byte-clean contract is preserved end-to-end.
//!
//! `/dev/tty` is unconditionally targeted because Paladin v0.1 is
//! Linux-only (DESIGN.md §2). Cross-platform abstraction can land
//! later if the target list grows.

// The public prompt entry points and their tty I/O helpers are unused
// in the binary until the command handlers wire them in (see
// `IMPLEMENTATION_PLAN_02_CLI.md` checklist). The pure-logic helpers
// are covered by the unit tests below; the I/O helpers are exercised
// end-to-end by the future `assert_cmd` + scripted-tty tests. Drop this
// `allow` once `init`/`passphrase`/`add`/`remove` start calling in.
#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};

use paladin_core::PaladinError;
use secrecy::{ExposeSecret, SecretString};

/// Stable §5 `operation` tag for passphrase prompt I/O failures.
const OP_PASSPHRASE: &str = "passphrase_prompt";
/// Stable §5 `operation` tag for interactive `add` prompt I/O
/// failures (visible field lines and hidden-input secret entries).
const OP_ACCOUNT: &str = "account_prompt";
/// Stable §5 `operation` tag for destructive-confirmation prompt I/O
/// failures (`remove` and `passphrase remove` without `--yes`).
const OP_CONFIRM: &str = "confirmation_prompt";

/// Empty-entry policy for the **first** prompt of a new-passphrase
/// pair. The confirmation entry is always treated as a literal: an
/// empty confirmation against a non-empty first entry is a mismatch,
/// not a plaintext signal.
#[derive(Debug, Clone, Copy)]
pub enum NewPassphraseEmptyPolicy {
    /// `init` only: empty first entry returns `Ok(None)` so the caller
    /// can fall through to plaintext storage with the
    /// `format_plaintext_storage_warning` advisory.
    AllowAsPlaintext,
    /// `passphrase set`, `passphrase change`, and `export --encrypted`:
    /// empty first entry returns `InvalidPassphrase { reason: "zero_length" }`.
    Reject,
}

// --- I/O helpers (touch /dev/tty) -------------------------------------------

fn io_err(operation: &'static str) -> impl Fn(io::Error) -> PaladinError {
    move |source| PaladinError::IoError { operation, source }
}

fn open_tty_write(op: &'static str) -> Result<File, PaladinError> {
    OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(io_err(op))
}

fn open_tty_read(op: &'static str) -> Result<File, PaladinError> {
    OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map_err(io_err(op))
}

fn write_prompt(prompt: &str, op: &'static str) -> Result<(), PaladinError> {
    let mut w = open_tty_write(op)?;
    write!(w, "{prompt}").map_err(io_err(op))?;
    w.flush().map_err(io_err(op))?;
    Ok(())
}

fn read_visible_line(op: &'static str) -> Result<String, PaladinError> {
    let f = open_tty_read(op)?;
    let mut reader = io::BufReader::new(f);
    let mut buf = String::new();
    reader.read_line(&mut buf).map_err(io_err(op))?;
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

// --- Pure-logic helpers (unit-testable without a tty) -----------------------

fn check_confirmation_match(
    first: &SecretString,
    second: &SecretString,
) -> Result<(), PaladinError> {
    if first.expose_secret() == second.expose_secret() {
        Ok(())
    } else {
        Err(PaladinError::InvalidPassphrase {
            reason: "confirmation_mismatch",
        })
    }
}

fn classify_first_entry_empty(
    policy: NewPassphraseEmptyPolicy,
) -> Result<Option<SecretString>, PaladinError> {
    match policy {
        NewPassphraseEmptyPolicy::AllowAsPlaintext => Ok(None),
        NewPassphraseEmptyPolicy::Reject => Err(PaladinError::InvalidPassphrase {
            reason: "zero_length",
        }),
    }
}

/// Classify a destructive-confirmation response. Trims surrounding
/// Unicode whitespace (matching `str::trim`) and accepts only the
/// exact string `"yes"`. Anything else — including `y`, `Yes`,
/// `YES`, `yes!`, embedded whitespace, or empty — returns
/// `validation_error` with `field: "confirmation"`,
/// `reason: "declined"`. The CLI never reprompts.
fn classify_destructive_response(line: &str) -> Result<(), PaladinError> {
    if line.trim() == "yes" {
        Ok(())
    } else {
        Err(PaladinError::ValidationError {
            field: "confirmation",
            reason: "declined".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        })
    }
}

// --- Public prompts ---------------------------------------------------------

/// Prompt for a single passphrase. The label is written to `/dev/tty`
/// (not stdout/stderr); the response is read with echo disabled via
/// `rpassword`. Passphrase bytes are not trimmed, case-folded, or
/// Unicode-normalized — only the line ending consumed by the terminal
/// prompt is removed.
///
/// On `/dev/tty` open failure or rpassword I/O error, returns
/// `io_error` with `operation: "passphrase_prompt"`.
pub fn prompt_passphrase(prompt: &str) -> Result<SecretString, PaladinError> {
    write_prompt(prompt, OP_PASSPHRASE)?;
    let s = rpassword::read_password().map_err(io_err(OP_PASSPHRASE))?;
    Ok(SecretString::from(s))
}

/// Prompt for a new passphrase plus a confirmation entry. The empty-
/// entry behavior on the **first** prompt is governed by `policy`. A
/// non-empty first entry is always followed by a confirmation prompt;
/// any byte difference (including pure trailing-whitespace divergence,
/// case difference, or precomposed-vs-decomposed Unicode forms)
/// surfaces as `InvalidPassphrase { reason: "confirmation_mismatch" }`.
pub fn prompt_new_passphrase(
    first_prompt: &str,
    confirm_prompt: &str,
    policy: NewPassphraseEmptyPolicy,
) -> Result<Option<SecretString>, PaladinError> {
    let first = prompt_passphrase(first_prompt)?;
    if first.expose_secret().is_empty() {
        return classify_first_entry_empty(policy);
    }
    let confirm = prompt_passphrase(confirm_prompt)?;
    check_confirmation_match(&first, &confirm)?;
    Ok(Some(first))
}

/// Prompt for a visible-input account-entry field (label, issuer,
/// digits, period, counter, icon-hint slug). Returns the entered line
/// with the terminating newline stripped; the caller decides what to
/// do with empty input via `validate_manual` defaults.
///
/// On `/dev/tty` open or read failure returns `io_error` with
/// `operation: "account_prompt"`.
pub fn prompt_account_line(prompt: &str) -> Result<String, PaladinError> {
    write_prompt(prompt, OP_ACCOUNT)?;
    read_visible_line(OP_ACCOUNT)
}

/// Prompt for a hidden-input account secret. Same `/dev/tty` path as
/// passphrase prompts but tagged with `operation: "account_prompt"`
/// because it is part of the interactive `add` flow.
pub fn prompt_account_secret(prompt: &str) -> Result<SecretString, PaladinError> {
    write_prompt(prompt, OP_ACCOUNT)?;
    let s = rpassword::read_password().map_err(io_err(OP_ACCOUNT))?;
    Ok(SecretString::from(s))
}

/// Destructive-confirmation prompt. Reads one line from `/dev/tty`,
/// trims surrounding Unicode whitespace, and accepts only the exact
/// string `"yes"`. Anything else exits before mutation with
/// `validation_error` (`field: "confirmation"`, `reason: "declined"`).
/// `/dev/tty` open or read failures surface as `io_error` with
/// `operation: "confirmation_prompt"`.
pub fn prompt_destructive_confirmation(prompt: &str) -> Result<(), PaladinError> {
    write_prompt(prompt, OP_CONFIRM)?;
    let line = read_visible_line(OP_CONFIRM)?;
    classify_destructive_response(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    // -- destructive confirmation ------------------------------------------

    #[test]
    fn destructive_yes_exact_accepted() {
        assert!(classify_destructive_response("yes").is_ok());
    }

    #[test]
    fn destructive_yes_with_ascii_whitespace_accepted() {
        for input in ["yes\n", "  yes  ", "\tyes\r\n", " yes ", "\n\nyes\n"] {
            assert!(
                classify_destructive_response(input).is_ok(),
                "{input:?} should be accepted",
            );
        }
    }

    #[test]
    fn destructive_yes_with_unicode_whitespace_accepted() {
        // Unicode White_Space code points: U+00A0 NBSP, U+2003 EM SPACE,
        // U+1680 OGHAM SPACE MARK, U+2028 LINE SEPARATOR.
        for input in [
            "\u{00A0}yes\u{00A0}",
            "\u{2003}yes\u{2003}",
            "\u{1680}yes\u{2028}",
        ] {
            assert!(
                classify_destructive_response(input).is_ok(),
                "{input:?} should be accepted",
            );
        }
    }

    #[test]
    fn destructive_anything_else_declines() {
        for input in [
            "", "y", "Yes", "YES", "yEs", "no", "yes!", "ye s", "nope", "  no  ", "y e s", "yess",
            "1", "true",
        ] {
            let err = classify_destructive_response(input).unwrap_err();
            match err {
                PaladinError::ValidationError {
                    field,
                    reason,
                    source_index,
                    decoded_len,
                    recommended_min,
                    entry_type,
                } => {
                    assert_eq!(field, "confirmation", "input {input:?}");
                    assert_eq!(reason, "declined", "input {input:?}");
                    assert!(source_index.is_none());
                    assert!(decoded_len.is_none());
                    assert!(recommended_min.is_none());
                    assert!(entry_type.is_none());
                }
                other => panic!("input {input:?}: expected ValidationError, got {other:?}"),
            }
        }
    }

    // -- new-passphrase confirmation matching ------------------------------

    #[test]
    fn confirmation_match_ok_on_byte_equal() {
        let a = secret("abc 123 \u{2728}");
        let b = secret("abc 123 \u{2728}");
        assert!(check_confirmation_match(&a, &b).is_ok());
    }

    #[test]
    fn confirmation_match_does_not_normalize_or_trim_or_case_fold() {
        // Trailing space matters; case matters; Unicode forms are
        // compared byte-for-byte (no NFC normalization).
        let pairs = [
            ("abc", "ABC"),
            ("abc ", "abc"),
            ("abc", "abc "),
            ("a\u{0301}", "\u{00E1}"), // a + combining acute vs precomposed á
            ("", "x"),
            ("x", ""),
        ];
        for (l, r) in pairs {
            let a = secret(l);
            let b = secret(r);
            let err = check_confirmation_match(&a, &b).unwrap_err();
            assert!(
                matches!(
                    err,
                    PaladinError::InvalidPassphrase {
                        reason: "confirmation_mismatch"
                    }
                ),
                "{l:?} vs {r:?}: {err:?}",
            );
        }
    }

    // -- new-passphrase empty-entry policy ---------------------------------

    #[test]
    fn first_entry_empty_allow_returns_none_for_plaintext() {
        let v = classify_first_entry_empty(NewPassphraseEmptyPolicy::AllowAsPlaintext).unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn first_entry_empty_reject_returns_zero_length() {
        let err = classify_first_entry_empty(NewPassphraseEmptyPolicy::Reject).unwrap_err();
        assert!(
            matches!(
                err,
                PaladinError::InvalidPassphrase {
                    reason: "zero_length"
                }
            ),
            "{err:?}",
        );
    }

    // -- error-kind sanity (cross-check against §5 taxonomy) ---------------

    #[test]
    fn confirmation_decline_kind_is_validation_error() {
        let err = classify_destructive_response("nope").unwrap_err();
        assert_eq!(err.kind(), paladin_core::ErrorKind::ValidationError);
    }

    #[test]
    fn confirmation_mismatch_kind_is_invalid_passphrase() {
        let a = secret("alpha");
        let b = secret("beta");
        let err = check_confirmation_match(&a, &b).unwrap_err();
        assert_eq!(err.kind(), paladin_core::ErrorKind::InvalidPassphrase);
    }

    #[test]
    fn first_entry_empty_reject_kind_is_invalid_passphrase() {
        let err = classify_first_entry_empty(NewPassphraseEmptyPolicy::Reject).unwrap_err();
        assert_eq!(err.kind(), paladin_core::ErrorKind::InvalidPassphrase);
    }
}
