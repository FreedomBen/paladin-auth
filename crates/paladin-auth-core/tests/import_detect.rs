// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I — `import::detect` content-sniffing matrix (docs/DESIGN.md §4.6).
//
// Detection order: Paladin Auth magic → image magic → Aegis JSON shape →
// otpauth text/JSON → Unknown. `detect` inspects shape only and never
// returns `no_entries_to_import` — emptiness is the importer's job.

use paladin_auth_core::{detect, ImportFormat};

// ---------- Paladin Auth magic ----------

#[test]
fn paladin_auth_plaintext_magic_returns_paladin_auth() {
    let mut bytes = b"PALAUTH\0".to_vec();
    bytes.push(1); // format_ver
    bytes.push(0); // mode = plaintext
    bytes.extend_from_slice(&[0; 64]); // arbitrary payload
    assert_eq!(detect(&bytes), ImportFormat::PaladinAuth);
}

#[test]
fn paladin_auth_encrypted_magic_returns_paladin_auth() {
    let mut bytes = b"PALAUTH\0".to_vec();
    bytes.push(1); // format_ver
    bytes.push(1); // mode = encrypted
    bytes.extend_from_slice(&[0; 200]);
    assert_eq!(detect(&bytes), ImportFormat::PaladinAuth);
}

#[test]
fn paladin_auth_magic_takes_precedence_over_image_magic() {
    // Even if subsequent bytes resemble an image, magic wins (it
    // never can in practice — `PALAUTH\0` is not an image magic — but
    // the rule is shape-only and Paladin Auth is checked first).
    let mut bytes = b"PALAUTH\0".to_vec();
    bytes.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    assert_eq!(detect(&bytes), ImportFormat::PaladinAuth);
}

#[test]
fn paladin_auth_magic_only_when_full_eight_bytes_present() {
    // Truncated to 7 bytes — no full magic match.
    let bytes = b"PALAUTH".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Unknown);
}

// ---------- Image magic ----------

#[test]
fn png_magic_returns_qr_image() {
    let bytes = b"\x89PNG\r\n\x1a\nthe rest is irrelevant".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::QrImage);
}

#[test]
fn jpeg_magic_returns_qr_image() {
    let bytes = b"\xFF\xD8\xFF\xE0\0\x10JFIF\0".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::QrImage);
}

#[test]
fn jpeg_exif_magic_returns_qr_image() {
    let bytes = b"\xFF\xD8\xFF\xE1abcd".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::QrImage);
}

#[test]
fn gif87a_magic_returns_qr_image() {
    let bytes = b"GIF87a more bytes".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::QrImage);
}

#[test]
fn gif89a_magic_returns_qr_image() {
    let bytes = b"GIF89a more bytes".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::QrImage);
}

#[test]
fn bmp_magic_returns_qr_image() {
    let bytes = b"BM\0\0\0\0\0\0\0\0".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::QrImage);
}

#[test]
fn webp_magic_returns_qr_image() {
    let bytes = b"RIFF\0\0\0\0WEBPVP8 ".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::QrImage);
}

#[test]
fn riff_without_webp_chunk_is_not_image() {
    // RIFF...WAVE shouldn't be classified as a QR image; falls
    // through to JSON/otpauth checks → Unknown.
    let bytes = b"RIFF\0\0\0\0WAVEfmt ".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Unknown);
}

// ---------- Aegis JSON shape ----------

#[test]
fn aegis_plaintext_db_shape_returns_aegis() {
    // Aegis plaintext export: top-level `{"version":..., "db":{...}}`.
    let bytes =
        br#"{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[]}}"#
            .to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Aegis);
}

#[test]
fn aegis_encrypted_db_string_shape_returns_aegis() {
    // Aegis encrypted export: `db` is a base64 ciphertext string.
    let bytes = br#"{"version":1,"header":{"slots":[],"params":{}},"db":"BASE64STRING"}"#.to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Aegis);
}

#[test]
fn aegis_with_leading_whitespace_returns_aegis() {
    let bytes = b"   \n\t  {\"version\":1,\"db\":{\"entries\":[]}}".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Aegis);
}

// ---------- otpauth ----------

#[test]
fn single_otpauth_uri_returns_otpauth() {
    let bytes = b"otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Otpauth);
}

#[test]
fn otpauth_with_surrounding_whitespace_returns_otpauth() {
    let bytes = b"  \n\totpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme\n  ".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Otpauth);
}

#[test]
fn otpauth_uppercase_scheme_returns_otpauth() {
    let bytes = b"OTPAUTH://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Otpauth);
}

#[test]
fn otpauth_line_list_returns_otpauth() {
    let bytes = b"\
otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP

otpauth://hotp/B:b?secret=JBSWY3DPEHPK3PXP&counter=0
"
    .to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Otpauth);
}

#[test]
fn json_array_of_uris_returns_otpauth() {
    let bytes = br#"["otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP","otpauth://hotp/B:b?secret=JBSWY3DPEHPK3PXP&counter=0"]"#.to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Otpauth);
}

#[test]
fn json_array_with_leading_whitespace_returns_otpauth() {
    let bytes = b"\n  [\"otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP\"]\n".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Otpauth);
}

#[test]
fn empty_json_array_returns_otpauth_not_unknown() {
    // detect() inspects shape only; emptiness is the importer's job.
    let bytes = b"[]".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Otpauth);
}

// ---------- Unknown ----------

#[test]
fn empty_input_returns_unknown_without_error() {
    assert_eq!(detect(b""), ImportFormat::Unknown);
}

#[test]
fn whitespace_only_returns_unknown() {
    assert_eq!(detect(b"   \n\t  "), ImportFormat::Unknown);
}

#[test]
fn arbitrary_text_returns_unknown() {
    assert_eq!(detect(b"hello world"), ImportFormat::Unknown);
}

#[test]
fn http_url_returns_unknown() {
    assert_eq!(detect(b"https://example.com/foo"), ImportFormat::Unknown);
}

#[test]
fn json_object_without_aegis_shape_returns_unknown() {
    let bytes = br#"{"name":"alice","secret":"JBSWY3DPEHPK3PXP"}"#.to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Unknown);
}

#[test]
fn json_array_of_non_otpauth_strings_returns_unknown() {
    let bytes = br#"["hello","world"]"#.to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Unknown);
}

#[test]
fn json_array_with_object_first_element_returns_unknown() {
    let bytes = br#"[{"foo":1}]"#.to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Unknown);
}

#[test]
fn paladin_auth_magic_with_wrong_byte_is_unknown() {
    // Differ in last byte of magic.
    let bytes = b"PALAUTH\x01extra".to_vec();
    assert_eq!(detect(&bytes), ImportFormat::Unknown);
}
