// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clipboard-QR add-image pure-logic glue for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AddAccountComponent` and §"Tests > Pure-logic unit tests >
//! `tests/qr_clipboard_logic.rs`", the "scan from clipboard image"
//! path reads a `gdk::Texture` from the GDK clipboard, allocates an
//! exact `width * height * 4` straight (non-premultiplied) RGBA8
//! buffer, rejects sizes above [`paladin_core::QR_RGBA_MAX_BYTES`]
//! *before* allocation / download, and downloads via a
//! `gdk::TextureDownloader` set to `gdk::MemoryFormat::R8g8b8a8` with
//! row stride `width * 4`. Width, height, bytes, and `import_time`
//! are then passed to [`paladin_core::import::qr_image_bytes`], and
//! the resulting [`paladin_core::ValidatedAccount`]s are merged into
//! the vault with a fixed [`ImportConflict::Skip`] (parity with §6).
//!
//! Splitting this out keeps the size check, the conflict-policy
//! constant, and the post-merge count summary testable without a
//! live `gdk::Display` / clipboard / GTK theme — see
//! [`tests/qr_clipboard_logic.rs`].

use std::time::SystemTime;

use paladin_core::{
    import::qr_image_bytes, ImportConflict, ImportReport, Result, ValidatedAccount,
    QR_RGBA_MAX_BYTES,
};

/// Fixed merge policy for clipboard-QR additions.
///
/// §6 / `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent`" pin
/// the clipboard-QR path to [`ImportConflict::Skip`]: a colliding
/// `(secret, issuer, label)` triple keeps the existing entry and is
/// counted under [`ImportReport::skipped`]. The user can run an
/// explicit Import flow if they want `Replace` / `Append` semantics.
pub const CLIPBOARD_QR_CONFLICT_POLICY: ImportConflict = ImportConflict::Skip;

/// Why an RGBA8 buffer layout was rejected before allocation / download.
///
/// All variants signal a pre-allocation rejection: no GDK download
/// has happened, and no Rust-side buffer has been requested. Callers
/// surface these inline at the `AddAccountComponent` clipboard-QR
/// sub-flow without mutating the vault, per §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrLayoutError {
    /// Width or height was zero.
    ZeroDimensions,
    /// `width * height` or `width * height * 4` overflowed `usize`.
    DimensionsOverflow,
    /// The computed byte count exceeds [`QR_RGBA_MAX_BYTES`].
    ImageTooLarge {
        /// `width * height * 4`, the number of bytes the buffer would have used.
        requested_bytes: usize,
        /// [`QR_RGBA_MAX_BYTES`] — the upper bound a clipboard-QR image may consume.
        max_bytes: usize,
    },
}

impl core::fmt::Display for QrLayoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroDimensions => f.write_str("clipboard texture has zero width or height"),
            Self::DimensionsOverflow => f.write_str("clipboard texture dimensions overflow usize"),
            Self::ImageTooLarge {
                requested_bytes,
                max_bytes,
            } => write!(
                f,
                "clipboard texture is too large ({requested_bytes} > {max_bytes} bytes)"
            ),
        }
    }
}

impl std::error::Error for QrLayoutError {}

/// Pre-allocation RGBA8 layout for a `gdk::Texture` clipboard download.
///
/// Built by [`prepare_rgba_layout`]; the live binary uses
/// [`row_stride`](Self::row_stride) to drive
/// `gdk::TextureDownloader::set_format(R8g8b8a8)` plus
/// `set_stride(row_stride)`, and [`buffer_bytes`](Self::buffer_bytes)
/// to allocate the destination `Vec<u8>` exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RgbaLayout {
    width: u32,
    height: u32,
    row_stride: usize,
    buffer_bytes: usize,
}

impl RgbaLayout {
    /// Source clipboard texture width in pixels.
    #[must_use]
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Source clipboard texture height in pixels.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Bytes per row — exactly `width * 4` for straight RGBA8.
    #[must_use]
    pub fn row_stride(&self) -> usize {
        self.row_stride
    }

    /// Total buffer size — exactly `width * height * 4`.
    #[must_use]
    pub fn buffer_bytes(&self) -> usize {
        self.buffer_bytes
    }
}

/// Compute the RGBA8 buffer layout for a clipboard texture, rejecting
/// oversized / overflowing / zero-sized inputs *before* any allocation
/// or `gdk::TextureDownloader` download.
///
/// The function takes only `width` / `height` so that the rejection
/// path cannot have allocated a destination buffer — see
/// [`tests/qr_clipboard_logic.rs::prepare_rgba_layout_runs_before_buffer_is_allocated`].
///
/// All multiplications go through `checked_mul`. On platforms where
/// `usize` is wider than the dimensions of any plausible clipboard
/// texture, the `DimensionsOverflow` arm is unreachable for typical
/// inputs but still trips deterministically for adversarial sizes.
pub fn prepare_rgba_layout(
    width: u32,
    height: u32,
) -> std::result::Result<RgbaLayout, QrLayoutError> {
    if width == 0 || height == 0 {
        return Err(QrLayoutError::ZeroDimensions);
    }
    let pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or(QrLayoutError::DimensionsOverflow)?;
    let buffer_bytes = pixels
        .checked_mul(4)
        .ok_or(QrLayoutError::DimensionsOverflow)?;
    if buffer_bytes > QR_RGBA_MAX_BYTES {
        return Err(QrLayoutError::ImageTooLarge {
            requested_bytes: buffer_bytes,
            max_bytes: QR_RGBA_MAX_BYTES,
        });
    }
    let row_stride = (width as usize)
        .checked_mul(4)
        .ok_or(QrLayoutError::DimensionsOverflow)?;
    Ok(RgbaLayout {
        width,
        height,
        row_stride,
        buffer_bytes,
    })
}

/// Hand a downloaded RGBA8 buffer to
/// [`paladin_core::import::qr_image_bytes`] and surface its
/// `Vec<ValidatedAccount>` (or [`PaladinError`]) verbatim.
///
/// The wrapper exists so the gtk side never re-derives width / height
/// from the byte slice — it always uses the validated [`RgbaLayout`].
/// Errors are forwarded as-is; the caller (`AddAccountComponent`)
/// renders them inline at the dialog without mutating the vault.
pub fn decode_clipboard_qr(
    layout: &RgbaLayout,
    rgba: &[u8],
    import_time: SystemTime,
) -> Result<Vec<ValidatedAccount>> {
    qr_image_bytes(layout.width, layout.height, rgba, import_time)
}

/// Post-merge counts surfaced by the clipboard-QR add modal.
///
/// Mirrors the §6 add-modal counts panel: only `imported`, `skipped`,
/// and `warnings` are meaningful for a `CLIPBOARD_QR_CONFLICT_POLICY`
/// merge (`replaced` / `appended` are always zero under
/// [`ImportConflict::Skip`]). Kept as a thin projection so the
/// `AddAccountComponent` can render it without re-summing fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QrImportSummary {
    /// Source rows added as new accounts.
    pub imported: usize,
    /// Source rows skipped under [`ImportConflict::Skip`].
    pub skipped: usize,
    /// Non-fatal validation warnings collected before the merge.
    pub warnings: usize,
}

impl QrImportSummary {
    /// Extract the §6 counts panel projection from a paladin-core report.
    #[must_use]
    pub fn from_report(report: &ImportReport) -> Self {
        Self {
            imported: report.imported,
            skipped: report.skipped,
            warnings: report.warnings.len(),
        }
    }
}
