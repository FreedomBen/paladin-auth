// SPDX-License-Identifier: AGPL-3.0-or-later

//! `--help` envelope. Under `--json` the rendered shape is
//!
//! ```json
//! { "help": { "command": "paladin-auth add", "text": "..." } }
//! ```
//!
//! per docs/DESIGN.md §5. Text mode keeps clap's normal help rendering and
//! is handled at the call site. The JSON shape is locked by the
//! integration tests in `tests/cli_global_flags.rs`.

use std::io::Write;

/// Walk argv against the live clap command tree and return the
/// resolved subcommand path with no flags and no trailing `--help` /
/// `-h`. Examples (with `argv[0]` = `paladin-auth`):
///
/// - `["paladin-auth", "--help"]`              → `"paladin-auth"`
/// - `["paladin-auth", "--vault", "/v", "-h"]` → `"paladin-auth"`
/// - `["paladin-auth", "add", "--help"]`       → `"paladin-auth add"`
/// - `["paladin-auth", "add", "--bogus", "-h"]`→ `"paladin-auth add"` (subcommand
///   already resolved before the bad flag short-circuited clap)
pub fn resolve_command_path<I, S>(argv: I, root: &clap::Command) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut path = vec![root.get_name().to_string()];
    let mut current = root;
    let mut iter = argv.into_iter();
    let _ = iter.next(); // drop argv[0]
    for arg in iter {
        let arg = arg.as_ref();
        if arg.starts_with('-') {
            // Skip flags entirely; their values are out of scope for
            // command-path resolution. We only care about subcommand
            // tokens.
            continue;
        }
        // `help <SUBCMD>` is clap's stand-alone help command; treat the
        // following token as the resolved subcommand.
        if arg == "help" {
            continue;
        }
        if let Some(sub) = current.find_subcommand(arg) {
            path.push(sub.get_name().to_string());
            current = sub;
        }
        // Non-matching tokens (flag *values*, positional arguments, or
        // typos) are silently skipped; the path stays at whatever
        // subcommand was last resolved. This mirrors clap's "deepest
        // resolved command" semantics for `--help`.
    }
    path.join(" ")
}

/// Write `{ "help": { "command": <command>, "text": <text> } }` plus
/// a trailing newline.
pub fn render_json(command: &str, text: &str, mut out: impl Write) -> std::io::Result<()> {
    let envelope = serde_json::json!({
        "help": { "command": command, "text": text },
    });
    serde_json::to_writer(&mut out, &envelope).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cli::Cli;
    use clap::CommandFactory;

    #[test]
    fn resolve_for_top_level_help_returns_paladin_auth() {
        let cmd = Cli::command();
        assert_eq!(
            resolve_command_path(["paladin-auth", "--help"], &cmd),
            "paladin-auth"
        );
        assert_eq!(
            resolve_command_path(["paladin-auth", "-h"], &cmd),
            "paladin-auth"
        );
    }

    #[test]
    fn resolve_skips_flag_values_before_subcommand() {
        let cmd = Cli::command();
        assert_eq!(
            resolve_command_path(["paladin-auth", "--vault", "/v", "add", "--help"], &cmd),
            "paladin-auth add"
        );
    }

    #[test]
    fn resolve_walks_into_subcommand_tree_for_passphrase_set() {
        let cmd = Cli::command();
        assert_eq!(
            resolve_command_path(["paladin-auth", "passphrase", "set", "--help"], &cmd),
            "paladin-auth passphrase set"
        );
    }

    #[test]
    fn resolve_handles_clap_help_command_form() {
        let cmd = Cli::command();
        assert_eq!(
            resolve_command_path(["paladin-auth", "help", "show"], &cmd),
            "paladin-auth show"
        );
    }

    #[test]
    fn render_json_envelope_is_valid_json_with_command_and_text_fields() {
        let mut buf = Vec::new();
        render_json("paladin-auth add", "Usage: paladin-auth add ...", &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["help"]["command"], serde_json::json!("paladin-auth add"));
        assert_eq!(
            v["help"]["text"],
            serde_json::json!("Usage: paladin-auth add ...")
        );
    }
}
