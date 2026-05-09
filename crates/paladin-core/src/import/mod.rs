// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Import facade (DESIGN.md §4.6 / §4.7).
//
// This module owns the public import surface:
//   - [`ImportFormat`] — discriminator returned by [`detect`] and
//     accepted by `from_file` / `from_bytes` as a forced format.
//   - [`detect`] — content-sniffing classifier in the §4.6 fixed
//     order: Paladin magic → image magic → Aegis JSON shape →
//     otpauth text/JSON → `Unknown`.
//
// Format-specific importers, the `from_file` / `from_bytes` facade,
// and the Paladin import precheck land in subsequent Phase I steps.
//
// Detection inspects shape only. Empty inputs return `Unknown` and
// never error here; the importer is what later returns
// `no_entries_to_import`.

mod otpauth;

pub use otpauth::otpauth;

use crate::storage::header::MAGIC as PALADIN_MAGIC;

/// Discriminator returned by [`detect`] and accepted by the import
/// facade as a forced format (DESIGN.md §4.6 / §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportFormat {
    /// Single `otpauth://` URI, line list of URIs, or JSON array of
    /// URIs. Detected by literal `otpauth://` prefix (case-insensitive)
    /// or a JSON array opener.
    Otpauth,
    /// Aegis Authenticator JSON export — plaintext (`db` is an object)
    /// or encrypted (`db` is a base64 string).
    Aegis,
    /// Paladin native vault file or encrypted bundle. Detected by the
    /// `PALADIN\0` magic prefix, regardless of mode.
    Paladin,
    /// QR-bearing image. Detected by the leading bytes of PNG, JPEG,
    /// GIF, BMP, or WebP.
    QrImage,
    /// No format matched. Front-ends surface this as
    /// `unsupported_import_format` at the importer call site.
    Unknown,
}

impl ImportFormat {
    /// Stable lowercase token used in error payloads
    /// (`unsupported_import_format` / `import_paladin`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Otpauth => "otpauth",
            Self::Aegis => "aegis",
            Self::Paladin => "paladin",
            Self::QrImage => "qr",
            Self::Unknown => "unknown",
        }
    }
}

/// Sniff the format of `bytes` per the §4.6 fixed precedence:
///
/// 1. **Paladin magic** — first 8 bytes equal `b"PALADIN\0"`. Magic
///    wins over every other shape check.
/// 2. **Image magic** — PNG, JPEG, GIF, BMP, or WebP leading bytes
///    (regardless of whether the image actually contains a QR code).
/// 3. **Aegis JSON shape** — JSON object with a top-level `"db"` key;
///    matches both plaintext (`db` is an object) and encrypted (`db`
///    is a base64 string) Aegis exports.
/// 4. **otpauth text/JSON** — leading `otpauth://` prefix
///    (case-insensitive, surrounding ASCII whitespace tolerated), or a
///    JSON array (empty arrays count as `Otpauth` because the
///    importer is what later rejects with `no_entries_to_import`).
/// 5. Otherwise `Unknown` — including empty input.
///
/// Detection inspects shape only and never returns an error.
#[must_use]
pub fn detect(bytes: &[u8]) -> ImportFormat {
    if is_paladin(bytes) {
        return ImportFormat::Paladin;
    }
    if is_image(bytes) {
        return ImportFormat::QrImage;
    }
    let trimmed = trim_ascii_whitespace(bytes);
    if trimmed.is_empty() {
        return ImportFormat::Unknown;
    }
    if let Some(format) = sniff_json(trimmed) {
        return format;
    }
    if starts_with_otpauth_scheme(trimmed) {
        return ImportFormat::Otpauth;
    }
    ImportFormat::Unknown
}

fn is_paladin(bytes: &[u8]) -> bool {
    bytes.starts_with(&PALADIN_MAGIC)
}

fn is_image(b: &[u8]) -> bool {
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        return true;
    }
    // JPEG: FF D8 FF
    if b.len() >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF {
        return true;
    }
    // GIF
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return true;
    }
    // BMP
    if b.starts_with(b"BM") {
        return true;
    }
    // WebP: RIFF....WEBP
    if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return true;
    }
    false
}

/// Try to classify `trimmed` as a JSON-shaped Aegis export or
/// otpauth JSON array. Returns `None` if `trimmed` does not start with
/// `{` or `[`, or if JSON parsing fails. Falls through to the
/// otpauth-text and Unknown branches in [`detect`].
fn sniff_json(trimmed: &[u8]) -> Option<ImportFormat> {
    let head = *trimmed.first()?;
    if head == b'{' {
        let value: serde_json::Value = serde_json::from_slice(trimmed).ok()?;
        let obj = value.as_object()?;
        if obj.contains_key("db") {
            return Some(ImportFormat::Aegis);
        }
        return None;
    }
    if head == b'[' {
        let value: serde_json::Value = serde_json::from_slice(trimmed).ok()?;
        let arr = value.as_array()?;
        if arr.is_empty() {
            return Some(ImportFormat::Otpauth);
        }
        let first = arr.first()?;
        let s = first.as_str()?;
        if has_otpauth_prefix(s.as_bytes()) {
            return Some(ImportFormat::Otpauth);
        }
        return None;
    }
    None
}

fn starts_with_otpauth_scheme(trimmed: &[u8]) -> bool {
    has_otpauth_prefix(trimmed)
}

fn has_otpauth_prefix(bytes: &[u8]) -> bool {
    const PREFIX: &[u8] = b"otpauth://";
    if bytes.len() < PREFIX.len() {
        return false;
    }
    bytes[..PREFIX.len()]
        .iter()
        .zip(PREFIX.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_format_as_str_matches_design() {
        assert_eq!(ImportFormat::Otpauth.as_str(), "otpauth");
        assert_eq!(ImportFormat::Aegis.as_str(), "aegis");
        assert_eq!(ImportFormat::Paladin.as_str(), "paladin");
        assert_eq!(ImportFormat::QrImage.as_str(), "qr");
        assert_eq!(ImportFormat::Unknown.as_str(), "unknown");
    }

    #[test]
    fn trim_ascii_whitespace_handles_only_ws() {
        assert_eq!(trim_ascii_whitespace(b"   \n\t "), b"");
    }
}
