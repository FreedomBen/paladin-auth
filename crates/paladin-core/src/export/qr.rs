// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `export::qr` — per-account QR rendering (docs/DESIGN.md §4.6 / §4.7).
//
// Three render targets are supported. All three encode the same
// `otpauth://` URI that `export::otpauth_list` would emit for the
// account, sourced through the shared `otpauth::emit_otpauth` emitter
// so a scanner that imports otpauth URIs sees byte-identical content
// whether the user scans the QR or pipes the plaintext list.
//
// * [`qr_png`] — PNG bytes, scalable via `QrRenderOptions::module_size_px`.
// * [`qr_svg`] — SVG document text (sharp at any zoom).
// * [`qr_ansi`] — Unicode half-block grid (terminal preview).
//
// All outputs are wrapped in [`Zeroizing`] because the encoded body
// embeds the account secret; the buffer is wiped on drop so the bytes
// do not linger in heap memory after the front end has written them
// out (PNG / SVG) or rendered them to the terminal (ANSI).
//
// The pipeline is read-only: nothing here advances HOTP counters, mints
// new timestamps, or touches the on-disk vault. HOTP exports carry the
// *current* `counter` value in the URI so a second device scanned from
// the QR stays in sync with the original.

use image::{ImageBuffer, ImageFormat, Luma};
use qrcode::render::{svg, unicode::Dense1x2};
use qrcode::QrCode;
use std::io::Cursor;
use zeroize::Zeroizing;

use crate::domain::Account;
use crate::error::{PaladinError, Result};
use crate::otpauth::emit_otpauth;
use crate::ui_contract::{QR_MODULE_SIZE_PX_DEFAULT, QR_MODULE_SIZE_PX_MAX, QR_MODULE_SIZE_PX_MIN};

/// Renderer options for the PNG / SVG QR export paths.
///
/// `module_size_px` is bounded to `[QR_MODULE_SIZE_PX_MIN,
/// QR_MODULE_SIZE_PX_MAX]` (inclusive); `[QrRenderOptions::validate]`
/// is the boundary check every front end runs before calling the
/// render functions. `quiet_zone` is the standard 4-module quiet border
/// most scanners expect; setting it to `false` is supported but only
/// for embedding inside a larger layout that already provides the
/// border itself.
///
/// The Unicode half-block path takes no options — the cell size is
/// fixed by the renderer and the quiet zone is always emitted for
/// scannability (see [`qr_ansi`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QrRenderOptions {
    /// Per-module pixel size for raster (PNG) and vector (SVG) output.
    pub module_size_px: u32,
    /// Whether to emit the standard quiet-zone border around the code.
    pub quiet_zone: bool,
}

impl Default for QrRenderOptions {
    fn default() -> Self {
        Self {
            module_size_px: QR_MODULE_SIZE_PX_DEFAULT,
            quiet_zone: true,
        }
    }
}

impl QrRenderOptions {
    /// Reject any out-of-range `module_size_px` before the renderer is
    /// invoked. Returns `validation_error { field: "qr_render", reason:
    /// "module_size_px_out_of_bounds" }` for any value outside
    /// `[QR_MODULE_SIZE_PX_MIN, QR_MODULE_SIZE_PX_MAX]` inclusive.
    pub fn validate(&self) -> Result<()> {
        if !(QR_MODULE_SIZE_PX_MIN..=QR_MODULE_SIZE_PX_MAX).contains(&self.module_size_px) {
            return Err(PaladinError::validation(
                "qr_render",
                "module_size_px_out_of_bounds",
            ));
        }
        Ok(())
    }
}

/// Render the account's `otpauth://` URI as PNG bytes.
///
/// `opts.module_size_px` controls the per-module pixel size and
/// `opts.quiet_zone` controls the quiet-zone border. The returned
/// `Zeroizing<Vec<u8>>` is wiped on drop because the PNG body
/// encodes the account secret.
///
/// Encoder failures (e.g. an exotic payload that exceeds QR version
/// 40 — today's `otpauth://` URIs never reach this) surface as
/// `validation_error { field: "qr_render", reason: <encoder slug> }`,
/// distinct from the `module_size_px_out_of_bounds` bounds-check
/// reason produced by [`QrRenderOptions::validate`].
pub fn qr_png(account: &Account, opts: &QrRenderOptions) -> Result<Zeroizing<Vec<u8>>> {
    opts.validate()?;
    let uri = Zeroizing::new(emit_otpauth(account));
    let code = QrCode::new(uri.as_bytes()).map_err(qr_render_err)?;
    let image: ImageBuffer<Luma<u8>, Vec<u8>> = code
        .render::<Luma<u8>>()
        .module_dimensions(opts.module_size_px, opts.module_size_px)
        .quiet_zone(opts.quiet_zone)
        .build();
    let mut buf = Cursor::new(Vec::new());
    image
        .write_to(&mut buf, ImageFormat::Png)
        .map_err(|_| PaladinError::validation("qr_render", "png_encode_failed"))?;
    Ok(Zeroizing::new(buf.into_inner()))
}

/// Render the account's `otpauth://` URI as an SVG document.
///
/// Identical contract to [`qr_png`] except the output is XML text. The
/// returned `Zeroizing<String>` is wiped on drop because the SVG body
/// encodes the account secret.
pub fn qr_svg(account: &Account, opts: &QrRenderOptions) -> Result<Zeroizing<String>> {
    opts.validate()?;
    let uri = Zeroizing::new(emit_otpauth(account));
    let code = QrCode::new(uri.as_bytes()).map_err(qr_render_err)?;
    let svg = code
        .render::<svg::Color>()
        .module_dimensions(opts.module_size_px, opts.module_size_px)
        .quiet_zone(opts.quiet_zone)
        .build();
    Ok(Zeroizing::new(svg))
}

/// Render the account's `otpauth://` URI as a Unicode half-block
/// terminal grid.
///
/// Glyphs are limited to `' '`, `'\u{2580}'` (▀), `'\u{2584}'` (▄),
/// `'\u{2588}'` (█), and `'\n'` — no ANSI colour/style escape sequences.
/// The quiet zone is always emitted; cell dimensions are fixed by the
/// renderer.
pub fn qr_ansi(account: &Account) -> Result<Zeroizing<String>> {
    let uri = Zeroizing::new(emit_otpauth(account));
    let code = QrCode::new(uri.as_bytes()).map_err(qr_render_err)?;
    let body = code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Dark)
        .light_color(Dense1x2::Light)
        .quiet_zone(true)
        .build();
    Ok(Zeroizing::new(body))
}

fn qr_render_err(err: qrcode::types::QrError) -> PaladinError {
    let reason = match err {
        qrcode::types::QrError::DataTooLong => "data_too_long",
        qrcode::types::QrError::InvalidVersion => "invalid_version",
        qrcode::types::QrError::UnsupportedCharacterSet => "unsupported_character_set",
        qrcode::types::QrError::InvalidEciDesignator => "invalid_eci_designator",
        qrcode::types::QrError::InvalidCharacter => "invalid_character",
    };
    PaladinError::validation("qr_render", reason)
}
