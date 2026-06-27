// SPDX-License-Identifier: AGPL-3.0-or-later

//! `--version` envelope. Under `--json` the rendered shape is
//!
//! ```json
//! { "version": { "name": "paladin-auth", "version": "x.y.z" } }
//! ```
//!
//! per docs/DESIGN.md §5. Text mode keeps clap's normal `clap::crate_version!`
//! rendering and is handled at the call site.

use std::io::Write;

/// Cargo package version baked in at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Write the `{ "version": ... }` envelope plus a trailing newline.
pub fn render_json(mut out: impl Write) -> std::io::Result<()> {
    let envelope = serde_json::json!({
        "version": { "name": "paladin-auth", "version": VERSION },
    });
    serde_json::to_writer(&mut out, &envelope).map_err(std::io::Error::other)?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_json_emits_name_and_version_fields() {
        let mut buf = Vec::new();
        render_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["version"]["name"], serde_json::json!("paladin-auth"));
        assert_eq!(v["version"]["version"], serde_json::json!(VERSION));
    }
}
