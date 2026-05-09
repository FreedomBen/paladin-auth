// SPDX-License-Identifier: AGPL-3.0-or-later

//! Human text renderers per DESIGN.md §5. Each helper writes a short,
//! parseable line to the supplied `Write` and is parameterized so the
//! command bodies don't have to thread `format!` calls through their
//! own logic.

use std::io::Write;
use std::path::Path;

use paladin_core::VaultMode;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
}
