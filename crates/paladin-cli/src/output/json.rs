// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable JSON envelope renderers per DESIGN.md §5. Each helper writes
//! exactly one JSON document to the supplied `Write` followed by a
//! single newline, with no other bytes — matching the CLI's
//! "stdout is one document plus newline" wire contract under `--json`.

use std::io::Write;

use paladin_core::VaultMode;
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
}
