// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `import::qr_image` / `import::qr_image_bytes` and the lower-level
// raw-payload helpers `read_qr_image` / `read_qr_image_bytes`
// (DESIGN.md §4.6 / §4.7).
//
// The raw helpers return one decoded payload string per detected QR
// (or an empty `Vec` when the image contains no QRs). The wrapping
// importers turn those payloads into `Vec<ValidatedAccount>`,
// rejecting the whole batch with `validation_error` + `source_index`
// when any decoded QR is not a valid `otpauth://` URI, and surfacing
// `no_entries_to_import` when no QR decodes.
//
// Size validation for the byte form precedes the actual decode (per
// the §4.6 "reject before allocation" rule):
//   - Zero width or height        → `validation_error` (`zero_dimensions`)
//   - `width * height * 4` overflow → `validation_error` (`dimensions_overflow`)
//   - Computed byte count > `QR_RGBA_MAX_BYTES` (64 MiB)
//                                 → `validation_error` (`image_too_large`)
//   - `rgba.len()` does not equal `width * height * 4`
//                                 → `validation_error` (`buffer_length_mismatch`)

use std::path::Path;
use std::time::SystemTime;

use image::{GrayImage, ImageBuffer, Luma};

use crate::domain::ValidatedAccount;
use crate::error::{PaladinError, Result};
use crate::otpauth::parse_otpauth;
use crate::ui_contract::QR_RGBA_MAX_BYTES;

/// Decode every QR code in an in-memory RGBA8 buffer.
pub fn read_qr_image_bytes(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<String>> {
    validate_rgba_dims(width, height, rgba)?;
    let luma = rgba_to_luma(width, height, rgba);
    Ok(decode_grids(&luma))
}

/// Decode every QR code in an image file on disk.
pub fn read_qr_image(path: &Path) -> Result<Vec<String>> {
    let bytes = std::fs::read(path).map_err(|err| PaladinError::IoError {
        operation: "read_image_file",
        source: err,
    })?;
    let img = image::load_from_memory(&bytes).map_err(|err| PaladinError::IoError {
        operation: "decode_image_bytes",
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()),
    })?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let raw = rgba.into_raw();
    read_qr_image_bytes(w, h, &raw)
}

/// Decode an in-memory RGBA8 buffer's QRs and validate them as
/// `otpauth://` URIs.
pub fn qr_image_bytes(
    width: u32,
    height: u32,
    rgba: &[u8],
    import_time: SystemTime,
) -> Result<Vec<ValidatedAccount>> {
    let payloads = read_qr_image_bytes(width, height, rgba)?;
    payloads_to_accounts(payloads, import_time)
}

/// Read an image file and validate every decoded QR as an
/// `otpauth://` URI.
pub fn qr_image(path: &Path, import_time: SystemTime) -> Result<Vec<ValidatedAccount>> {
    let payloads = read_qr_image(path)?;
    payloads_to_accounts(payloads, import_time)
}

fn payloads_to_accounts(
    payloads: Vec<String>,
    import_time: SystemTime,
) -> Result<Vec<ValidatedAccount>> {
    if payloads.is_empty() {
        return Err(PaladinError::NoEntriesToImport);
    }
    let mut out = Vec::with_capacity(payloads.len());
    for (idx, payload) in payloads.into_iter().enumerate() {
        let trimmed = payload.trim();
        if !is_otpauth_uri(trimmed) {
            return Err(
                PaladinError::validation("qr_image", "non_otpauth_payload").tag_source_index(idx),
            );
        }
        let va = parse_otpauth(trimmed, import_time).map_err(|e| e.tag_source_index(idx))?;
        out.push(va);
    }
    Ok(out)
}

fn is_otpauth_uri(s: &str) -> bool {
    const PREFIX: &[u8] = b"otpauth://";
    let bytes = s.as_bytes();
    bytes.len() >= PREFIX.len()
        && bytes[..PREFIX.len()]
            .iter()
            .zip(PREFIX.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn validate_rgba_dims(width: u32, height: u32, rgba: &[u8]) -> Result<()> {
    if width == 0 || height == 0 {
        return Err(PaladinError::validation("qr_image", "zero_dimensions"));
    }
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| PaladinError::validation("qr_image", "dimensions_overflow"))?;
    let expected = pixels
        .checked_mul(4)
        .ok_or_else(|| PaladinError::validation("qr_image", "dimensions_overflow"))?;
    if expected > QR_RGBA_MAX_BYTES {
        return Err(PaladinError::validation("qr_image", "image_too_large"));
    }
    if rgba.len() != expected {
        return Err(PaladinError::validation(
            "qr_image",
            "buffer_length_mismatch",
        ));
    }
    Ok(())
}

/// Convert RGBA8 to Luma8 via the BT.601 luminance formula. rqrr only
/// inspects intensity, so a precise greyscale matters less than that
/// the formula is consistent across our path / byte routes.
fn rgba_to_luma(width: u32, height: u32, rgba: &[u8]) -> GrayImage {
    let mut buf: Vec<u8> = Vec::with_capacity((width as usize) * (height as usize));
    for pixel in rgba.chunks_exact(4) {
        let r = u32::from(pixel[0]);
        let g = u32::from(pixel[1]);
        let b = u32::from(pixel[2]);
        // BT.601: Y = 0.299 R + 0.587 G + 0.114 B (×1024 in fixed point).
        // Coefficients sum to 1024, each input is ≤ 255, so the shifted
        // result is in 0..=255 by construction.
        #[allow(clippy::cast_possible_truncation)]
        let y = ((r * 306 + g * 601 + b * 117) >> 10) as u8;
        buf.push(y);
    }
    ImageBuffer::<Luma<u8>, _>::from_raw(width, height, buf)
        .expect("luma buffer length matches dimensions; validated above")
}

fn decode_grids(luma: &GrayImage) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare(luma.clone());
    let grids = prepared.detect_grids();
    let mut out = Vec::with_capacity(grids.len());
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            out.push(content);
        }
    }
    out
}
