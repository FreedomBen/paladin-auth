// SPDX-License-Identifier: AGPL-3.0-or-later

//! Output mode resolution and renderer entry points. See docs/DESIGN.md §5 and
//! `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Output".
//!
//! - `Mode::Text { color }` honors `--no-color`, `NO_COLOR`, and TTY
//!   detection on `stdout`.
//! - `Mode::Json` emits stable §5 envelopes — success on stdout, error
//!   on stderr, nothing else.
//! - `argv_has_json_flag` is the script-contract pre-scan: when an
//!   exact `--json` token is present anywhere in argv, even clap's
//!   syntax-error diagnostics are rerouted into a JSON envelope.

use std::ffi::OsStr;
use std::io::IsTerminal;

pub mod error;
pub mod help;
pub mod json;
pub mod text;
pub mod version;

/// Selected output dialect for one CLI invocation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Human-readable text. `color = true` enables ANSI styling.
    Text {
        /// `true` iff ANSI styling is allowed on stdout.
        color: bool,
    },
    /// Stable §5 JSON envelopes only.
    Json,
}

impl Mode {
    /// Resolve the dialect from the parsed `--json` / `--no-color`
    /// flags. ANSI is disabled when `--no-color` is set, when the
    /// `NO_COLOR` env var is present, or when stdout is not a TTY.
    #[must_use]
    pub fn resolve(json: bool, no_color: bool) -> Self {
        if json {
            return Self::Json;
        }
        let no_color_env = std::env::var_os("NO_COLOR").is_some();
        let stdout_is_tty = std::io::stdout().is_terminal();
        let color = !no_color && !no_color_env && stdout_is_tty;
        Self::Text { color }
    }
}

/// Pre-scan argv for an exact `--json` token. Used before clap parsing
/// so syntax / usage failures can render a JSON error envelope to
/// stderr instead of clap's text diagnostics. The scan ignores `argv[0]`
/// (the binary name).
#[must_use]
pub fn argv_has_json_flag<I, S>(argv: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    argv.into_iter()
        .skip(1)
        .any(|arg| arg.as_ref() == OsStr::new("--json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_pre_scan_finds_json_flag() {
        assert!(argv_has_json_flag(["paladin-auth", "--json", "list"]));
        assert!(argv_has_json_flag(["paladin-auth", "show", "x", "--json"]));
        assert!(argv_has_json_flag([
            "paladin-auth",
            "--vault",
            "/v",
            "--json"
        ]));
    }

    #[test]
    fn argv_pre_scan_ignores_argv0_and_substring_matches() {
        assert!(!argv_has_json_flag(["--json", "list"]));
        assert!(!argv_has_json_flag(["paladin-auth", "list"]));
        assert!(!argv_has_json_flag(["paladin-auth", "--json=true"]));
        assert!(!argv_has_json_flag(["paladin-auth", "--jsonish"]));
    }

    #[test]
    fn json_flag_overrides_no_color_and_tty() {
        assert_eq!(Mode::resolve(true, false), Mode::Json);
        assert_eq!(Mode::resolve(true, true), Mode::Json);
    }

    #[test]
    fn no_color_flag_disables_color_in_text_mode() {
        let Mode::Text { color } = Mode::resolve(false, true) else {
            panic!("expected Text mode");
        };
        assert!(!color, "--no-color must disable ANSI styling");
    }
}
