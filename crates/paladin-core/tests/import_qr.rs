// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase I.5 — QR import helpers (docs/DESIGN.md §4.6 / §4.7).

mod common;

use common::test_tempdir;

use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use image::{ImageFormat, Luma};
use paladin_core::{import, ErrorKind, PaladinError, QR_RGBA_MAX_BYTES};
use qrcode::QrCode;
use tempfile::TempDir;

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

const URI_TOTP_A: &str = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
const URI_HOTP_B: &str =
    "otpauth://hotp/Globex:bob?secret=NBSWY3DPEHPK3PXP&issuer=Globex&counter=7";

/// Render `payload` as a QR code into an RGBA8 buffer of `(width, height, rgba)`.
fn make_qr_rgba(payload: &str) -> (u32, u32, Vec<u8>) {
    let code = QrCode::new(payload.as_bytes()).expect("encode QR");
    let luma = code
        .render::<Luma<u8>>()
        .min_dimensions(160, 160)
        .quiet_zone(true)
        .build();
    let (w, h) = luma.dimensions();
    let raw = luma.into_raw();
    let mut rgba = Vec::with_capacity(raw.len() * 4);
    for v in raw {
        rgba.extend_from_slice(&[v, v, v, 0xFF]);
    }
    (w, h, rgba)
}

/// Render `payload` as a QR PNG and write it to `dir/<name>.png`.
fn write_qr_png(dir: &TempDir, name: &str, payload: &str) -> std::path::PathBuf {
    let code = QrCode::new(payload.as_bytes()).expect("encode QR");
    let luma = code
        .render::<Luma<u8>>()
        .min_dimensions(160, 160)
        .quiet_zone(true)
        .build();
    let path = dir.path().join(format!("{name}.png"));
    let mut buf = Cursor::new(Vec::new());
    luma.write_to(&mut buf, ImageFormat::Png)
        .expect("encode PNG");
    std::fs::write(&path, buf.into_inner()).expect("write PNG");
    path
}

// ---------- read_qr_image_bytes: dimension / size validation ----------

#[test]
fn zero_width_rejected() {
    let err = import::read_qr_image_bytes(0, 10, &[]).unwrap_err();
    let PaladinError::ValidationError { field, reason, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "qr_image");
    assert_eq!(reason, "zero_dimensions");
}

#[test]
fn zero_height_rejected() {
    let err = import::read_qr_image_bytes(10, 0, &[]).unwrap_err();
    let PaladinError::ValidationError { reason, .. } = err else {
        panic!("expected ValidationError");
    };
    assert_eq!(reason, "zero_dimensions");
}

#[test]
fn dimensions_overflow_rejected() {
    // u32::MAX × u32::MAX overflows usize on 64-bit. Pass a dummy
    // empty slice — validation must fire before the slice is touched.
    let err = import::read_qr_image_bytes(u32::MAX, u32::MAX, &[]).unwrap_err();
    let PaladinError::ValidationError { reason, .. } = err else {
        panic!("expected ValidationError");
    };
    assert_eq!(reason, "dimensions_overflow");
}

#[test]
fn dimensions_pixel_count_overflow_in_times_4_rejected() {
    // pixels = (1<<62), pixels*4 overflows usize on 64-bit.
    // 2^31 × 2^31 = 2^62 pixels; ×4 = 2^64 → overflow.
    let err = import::read_qr_image_bytes(1 << 31, 1 << 31, &[]).unwrap_err();
    let PaladinError::ValidationError { reason, .. } = err else {
        panic!("expected ValidationError");
    };
    assert_eq!(reason, "dimensions_overflow");
}

#[test]
fn buffer_just_above_qr_rgba_max_rejected_pre_decode() {
    // Pick a (w, h) whose w*h*4 = QR_RGBA_MAX_BYTES + 4 (one pixel
    // past the cap). 64 MiB / 4 = 16,777,216 pixels → 4096 × 4096.
    // Add one pixel-worth (4 bytes) by going to 4096 × 4097.
    let w: u32 = 4096;
    let h: u32 = 4097;
    let err = import::read_qr_image_bytes(w, h, &[]).unwrap_err();
    let PaladinError::ValidationError { reason, .. } = err else {
        panic!("expected ValidationError");
    };
    assert_eq!(reason, "image_too_large");
}

#[test]
fn buffer_at_exactly_qr_rgba_max_passes_dimension_check() {
    // 4096 × 4096 × 4 = 64 MiB exactly. Allocate 64 MiB of zeros.
    let w: u32 = 4096;
    let h: u32 = 4096;
    let expected_len = (w as usize) * (h as usize) * 4;
    assert_eq!(expected_len, QR_RGBA_MAX_BYTES);
    let rgba = vec![0u8; expected_len];
    // No QR in an all-black image — the helper must return an empty
    // Vec, not an error.
    let payloads = import::read_qr_image_bytes(w, h, &rgba).unwrap();
    assert!(payloads.is_empty());
}

#[test]
fn buffer_length_mismatch_rejected() {
    // 4 × 4 × 4 = 64 bytes expected. Provide 32.
    let err = import::read_qr_image_bytes(4, 4, &[0u8; 32]).unwrap_err();
    let PaladinError::ValidationError { reason, .. } = err else {
        panic!("expected ValidationError");
    };
    assert_eq!(reason, "buffer_length_mismatch");
}

// ---------- read_qr_image_bytes: decode ----------

#[test]
fn read_qr_image_bytes_decodes_one_qr() {
    let (w, h, rgba) = make_qr_rgba(URI_TOTP_A);
    let payloads = import::read_qr_image_bytes(w, h, &rgba).unwrap();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0], URI_TOTP_A);
}

#[test]
fn read_qr_image_bytes_returns_empty_when_no_qr() {
    // 32 × 32 plain-white image — no QR.
    let w: u32 = 32;
    let h: u32 = 32;
    let rgba = vec![0xFFu8; (w * h * 4) as usize];
    let payloads = import::read_qr_image_bytes(w, h, &rgba).unwrap();
    assert!(payloads.is_empty());
}

// ---------- read_qr_image (file path) ----------

#[test]
fn read_qr_image_decodes_png_on_disk() {
    let dir = test_tempdir();
    let path = write_qr_png(&dir, "totp_a", URI_TOTP_A);
    let payloads = import::read_qr_image(&path).unwrap();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0], URI_TOTP_A);
}

#[test]
fn read_qr_image_missing_file_returns_io_error() {
    let dir = test_tempdir();
    let path = dir.path().join("nope.png");
    let err = import::read_qr_image(&path).unwrap_err();
    let PaladinError::IoError { operation, .. } = err else {
        panic!("expected IoError, got {err:?}");
    };
    assert_eq!(operation, "read_image_file");
}

#[test]
fn read_qr_image_truncated_png_returns_io_error_decode_image_bytes() {
    let dir = test_tempdir();
    let path = dir.path().join("trunc.png");
    // Only the 8-byte PNG magic — image decode must fail without
    // panic, surfaced as io_error operation = "decode_image_bytes".
    std::fs::write(&path, b"\x89PNG\r\n\x1a\n").unwrap();
    let err = import::read_qr_image(&path).unwrap_err();
    let PaladinError::IoError { operation, .. } = err else {
        panic!("expected IoError, got {err:?}");
    };
    assert_eq!(operation, "decode_image_bytes");
}

// ---------- import::qr_image_bytes wrapper ----------

#[test]
fn qr_image_bytes_returns_validated_account_for_otpauth_qr() {
    let (w, h, rgba) = make_qr_rgba(URI_TOTP_A);
    let imported = import::qr_image_bytes(w, h, &rgba, import_time()).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].account.label(), "alice");
}

#[test]
fn qr_image_bytes_imports_set_created_at_equal_updated_at_equal_import_time() {
    let (w, h, rgba) = make_qr_rgba(URI_TOTP_A);
    let imported = import::qr_image_bytes(w, h, &rgba, import_time()).unwrap();
    assert_eq!(imported[0].account.created_at(), 1_700_000_000);
    assert_eq!(imported[0].account.updated_at(), 1_700_000_000);
}

#[test]
fn qr_image_bytes_with_no_qr_returns_no_entries_to_import() {
    let w: u32 = 32;
    let h: u32 = 32;
    let rgba = vec![0xFFu8; (w * h * 4) as usize];
    let err = import::qr_image_bytes(w, h, &rgba, import_time()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
}

#[test]
fn qr_image_bytes_with_non_otpauth_payload_rejects_with_source_index() {
    let (w, h, rgba) = make_qr_rgba("https://example.com/not-otpauth");
    let err = import::qr_image_bytes(w, h, &rgba, import_time()).unwrap_err();
    let PaladinError::ValidationError {
        field,
        reason,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "qr_image");
    assert_eq!(reason, "non_otpauth_payload");
    assert_eq!(source_index, Some(0));
}

// ---------- Mixed multi-QR image ----------

/// Stitch two QR payloads side-by-side into one RGBA8 buffer with a
/// generous quiet zone in between so rqrr detects both grids.
fn make_side_by_side_rgba(left: &str, right: &str) -> (u32, u32, Vec<u8>) {
    let left_qr = QrCode::new(left.as_bytes())
        .unwrap()
        .render::<Luma<u8>>()
        .min_dimensions(160, 160)
        .quiet_zone(true)
        .build();
    let right_qr = QrCode::new(right.as_bytes())
        .unwrap()
        .render::<Luma<u8>>()
        .min_dimensions(160, 160)
        .quiet_zone(true)
        .build();
    let (lw, lh) = left_qr.dimensions();
    let (rw, rh) = right_qr.dimensions();
    // Pad each side to the taller height.
    let h = lh.max(rh);
    // Leave a 32-pixel white gutter between the two QRs.
    let gutter: u32 = 32;
    let w = lw + gutter + rw;
    let mut rgba = vec![0xFFu8; (w as usize) * (h as usize) * 4];
    for y in 0..lh {
        for x in 0..lw {
            let luma = left_qr.get_pixel(x, y).0[0];
            let dst = ((y as usize) * (w as usize) + (x as usize)) * 4;
            rgba[dst] = luma;
            rgba[dst + 1] = luma;
            rgba[dst + 2] = luma;
            rgba[dst + 3] = 0xFF;
        }
    }
    for y in 0..rh {
        for x in 0..rw {
            let luma = right_qr.get_pixel(x, y).0[0];
            let dx = lw + gutter + x;
            let dst = ((y as usize) * (w as usize) + (dx as usize)) * 4;
            rgba[dst] = luma;
            rgba[dst + 1] = luma;
            rgba[dst + 2] = luma;
            rgba[dst + 3] = 0xFF;
        }
    }
    (w, h, rgba)
}

#[test]
fn image_with_two_qrs_one_non_otpauth_rejects_batch_with_source_index_for_offender() {
    // Construct an image whose two QRs decode to (a) a non-otpauth
    // string and (b) a valid otpauth URI. The wrapping import must
    // reject the batch and tag the source_index for the non-otpauth
    // payload, not the otpauth one.
    let (w, h, rgba) = make_side_by_side_rgba("https://example.com/not-otpauth", URI_TOTP_A);
    let payloads = import::read_qr_image_bytes(w, h, &rgba).unwrap();
    assert_eq!(
        payloads.len(),
        2,
        "both QRs must decode for the test to be meaningful"
    );
    let bad_idx = payloads
        .iter()
        .position(|s| !s.starts_with("otpauth://"))
        .expect("at least one decoded payload must be non-otpauth");
    let err = import::qr_image_bytes(w, h, &rgba, import_time()).unwrap_err();
    let PaladinError::ValidationError {
        field,
        reason,
        source_index,
        ..
    } = err
    else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "qr_image");
    assert_eq!(reason, "non_otpauth_payload");
    assert_eq!(source_index, Some(bad_idx));
}

// ---------- import::qr_image (file path) ----------

#[test]
fn qr_image_path_returns_validated_account() {
    let dir = test_tempdir();
    let path = write_qr_png(&dir, "hotp_b", URI_HOTP_B);
    let imported = import::qr_image(&path, import_time()).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].account.label(), "bob");
    assert_eq!(imported[0].account.counter(), Some(7));
}
