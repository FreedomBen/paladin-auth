// SPDX-License-Identifier: AGPL-3.0-or-later

//! Error envelope rendering. Maps the CLI-level [`CliError`] onto the
//! DESIGN.md §5 `error_kind` taxonomy. Behind `--json` every error
//! exits with one JSON document on stderr; in text mode the renderer
//! delegates to whichever upstream wrote the message (clap for syntax
//! errors, `Display` on `PaladinError` for runtime errors).

use std::io::Write;

use paladin_core::PaladinError;

use super::Mode;

/// Errors that the CLI surfaces to the caller. Distinguished from
/// `paladin_core::PaladinError` so we can route clap diagnostics and
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
    /// Scaffold sentinel: a command body has not been implemented yet.
    /// Removed as commands land — this branch never appears in shipped
    /// builds.
    NotYetImplemented(&'static str),
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
            Self::NotYetImplemented(name) => {
                write!(f, "command '{name}' is not yet implemented")
            }
        }
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
        (Mode::Json, CliError::NotYetImplemented(_)) => {
            // Scaffold-only: this branch is never reached from a
            // production build. We still emit valid JSON so callers
            // that mistakenly hit a stub under `--json` get a
            // parseable document on stderr instead of plain text.
            let envelope = serde_json::json!({
                "error_kind": "io_error",
                "operation": "command_not_implemented",
            });
            serde_json::to_writer(&mut out, &envelope).map_err(std::io::Error::other)?;
            writeln!(out)?;
        }
        (Mode::Text { .. }, CliError::Paladin(p)) => {
            writeln!(out, "paladin: {p}")?;
        }
        (Mode::Text { .. }, CliError::Usage { text_message }) => {
            // Clap's render() already terminates with a newline.
            write!(out, "{text_message}")?;
        }
        (Mode::Text { .. }, CliError::NotYetImplemented(name)) => {
            writeln!(out, "paladin: command '{name}' is not yet implemented")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_to_string(err: &CliError, mode: Mode) -> String {
        let mut buf: Vec<u8> = Vec::new();
        render(err, mode, &mut buf).expect("render");
        String::from_utf8(buf).expect("utf-8")
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
}
