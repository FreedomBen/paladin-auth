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
    import::qr_image_bytes, ImportConflict, ImportReport, PaladinError, Result, ValidatedAccount,
    QR_RGBA_MAX_BYTES,
};
use relm4::gtk::gdk;

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

/// `gdk::MemoryFormat` the clipboard-QR download must request.
///
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR clipboard
/// image path" pins the download format to
/// [`gdk::MemoryFormat::R8g8b8a8`] — straight (non-premultiplied)
/// 8-bit RGBA. The default `gdk::Texture::download` path yields
/// `R8g8b8a8Premultiplied`, which silently produces wrong pixels for
/// the `rqrr`-based QR decoder behind
/// [`paladin_core::import::qr_image_bytes`]. The live wiring in
/// `AppModel`'s clipboard-QR worker passes the return value of this
/// helper into [`gdk::TextureDownloader::set_format`] so the format
/// selection stays in one place rather than scattering the constant
/// across the call site.
#[must_use]
pub fn clipboard_qr_memory_format() -> gdk::MemoryFormat {
    gdk::MemoryFormat::R8g8b8a8
}

/// Why a downloaded clipboard texture failed the post-download layout
/// check against the validated [`RgbaLayout`].
///
/// `gdk::TextureDownloader::download_bytes` returns `(glib::Bytes,
/// usize)` — the GDK-owned buffer plus the row stride GDK chose. GDK
/// is allowed to return a larger-than-asked stride (e.g. for
/// alignment), and the buffer length is whatever GDK allocated. The
/// `rqrr` decoder upstream requires `width * 4` row stride exactly,
/// so a mismatch here is a hard reject rather than a recoverable
/// realignment. Pre-allocation rejection lives on [`QrLayoutError`];
/// this enum covers the post-download path where GDK's actual layout
/// might still drift from our expected layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadMismatch {
    /// Downloaded buffer's length disagrees with
    /// [`RgbaLayout::buffer_bytes`].
    BufferLength {
        /// `bytes.len()` returned by `gdk::TextureDownloader::download_bytes`.
        actual_bytes: usize,
        /// `layout.buffer_bytes()` from the pre-download
        /// [`prepare_rgba_layout`] gate.
        expected_bytes: usize,
    },
    /// GDK chose a row stride other than [`RgbaLayout::row_stride`].
    RowStride {
        /// Stride returned by `gdk::TextureDownloader::download_bytes`.
        actual_stride: usize,
        /// `layout.row_stride()` — exactly `width * 4`.
        expected_stride: usize,
    },
}

impl core::fmt::Display for DownloadMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferLength {
                actual_bytes,
                expected_bytes,
            } => write!(
                f,
                "clipboard texture download returned {actual_bytes} bytes, expected {expected_bytes}"
            ),
            Self::RowStride {
                actual_stride,
                expected_stride,
            } => write!(
                f,
                "clipboard texture download returned row stride {actual_stride}, expected {expected_stride}"
            ),
        }
    }
}

impl std::error::Error for DownloadMismatch {}

/// Defensively verify that `gdk::TextureDownloader::download_bytes`'s
/// returned `(bytes_len, row_stride)` matches the pre-download
/// [`RgbaLayout`].
///
/// The downloader is configured via [`clipboard_qr_memory_format`]
/// and the validated dimensions, so a matching layout is the
/// expected case. A mismatch indicates GDK returned an unexpected
/// stride (e.g. row padding for alignment) or buffer length —
/// surfaces as a typed [`DownloadMismatch`] the `AppModel` clipboard-
/// QR dispatch projects into an inline error before
/// [`decode_clipboard_qr`] sees the bytes.
pub fn verify_download_layout(
    layout: &RgbaLayout,
    downloaded_bytes: usize,
    downloaded_stride: usize,
) -> std::result::Result<(), DownloadMismatch> {
    if downloaded_stride != layout.row_stride() {
        return Err(DownloadMismatch::RowStride {
            actual_stride: downloaded_stride,
            expected_stride: layout.row_stride(),
        });
    }
    if downloaded_bytes != layout.buffer_bytes() {
        return Err(DownloadMismatch::BufferLength {
            actual_bytes: downloaded_bytes,
            expected_bytes: layout.buffer_bytes(),
        });
    }
    Ok(())
}

/// Materialize the destination RGBA8 buffer for a validated layout.
///
/// Returns a zero-initialized `Vec<u8>` of exactly
/// [`RgbaLayout::buffer_bytes`] in length, ready for
/// `gdk::TextureDownloader::download_into(...)` to fill in pixel
/// values at row stride [`RgbaLayout::row_stride`]. The signature takes
/// `&RgbaLayout` rather than raw `(width, height)` so a caller cannot
/// bypass [`prepare_rgba_layout`]'s overflow / size gate — the
/// `RgbaLayout` value is the proof that the layout passed the gate.
///
/// Zero-initialization protects against a partial download leaking
/// prior heap contents into the QR decode buffer. The allocation is
/// the *first* time we touch the heap on the clipboard-QR add path —
/// [`prepare_rgba_layout`] runs to acceptance before this call, so
/// rejecting an oversized clipboard image never lands here.
#[must_use]
pub fn allocate_rgba_buffer(layout: &RgbaLayout) -> Vec<u8> {
    vec![0_u8; layout.buffer_bytes()]
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

/// Post-download outcome the live `AppModel` clipboard-QR handler
/// projects from a single call.
///
/// Wraps the post-download verify + decode pipeline so the live
/// dispatch site cannot reach
/// [`paladin_core::import::qr_image_bytes`] without first running
/// the [`verify_download_layout`] check. Each variant maps onto an
/// inline error category surfaced in the Add dialog without
/// mutating the vault, per `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"`AddAccountComponent` QR clipboard image path".
#[derive(Debug)]
pub enum QrDecodeOutcome {
    /// `qr_image_bytes` returned a populated batch. The
    /// [`AppModel`] dispatch site hands the vector into a
    /// [`crate::add_account::QrWorkerInput`] for
    /// `Vault::mutate_and_save(|v| v.import_accounts(...))` under
    /// [`CLIPBOARD_QR_CONFLICT_POLICY`].
    Decoded(Vec<ValidatedAccount>),
    /// `gdk::TextureDownloader::download_bytes` returned a layout
    /// the validated [`RgbaLayout`] cannot consume — surfaces as an
    /// inline error in the Add dialog. The decode is never
    /// attempted on a buffer whose layout disagrees with the
    /// pre-allocation gate.
    DownloadMismatch(DownloadMismatch),
    /// [`paladin_core::import::qr_image_bytes`] rejected the
    /// buffer. Covers `NoEntriesToImport` (no QR present),
    /// `validation_error` (decoded payload is not an `otpauth://`
    /// URI or fails [`paladin_core::parse_otpauth`]), and any
    /// other typed [`PaladinError`] the core decoder surfaces.
    DecodeError(PaladinError),
}

/// Compose the post-download QR decode outcome for the live
/// `AppModel` clipboard-QR handler.
///
/// Runs [`verify_download_layout`] first so a mismatched download
/// layout never reaches [`decode_clipboard_qr`]. On a matching
/// layout, forwards width / height (from `layout`), `rgba`, and
/// `import_time` into [`paladin_core::import::qr_image_bytes`] via
/// [`decode_clipboard_qr`]. Per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR
/// clipboard image path", the call returns `Vec<ValidatedAccount>`
/// regardless of QR count, and the dispatch site forwards it
/// through [`crate::app::state::compose_qr_worker_input`] for the
/// `gio::spawn_blocking` merge under [`CLIPBOARD_QR_CONFLICT_POLICY`].
///
/// Keeping the verify + decode glue here means the live `AppModel`
/// handler stays a thin GDK shim and the cross-cutting rule
/// "verify before decode" is unit-testable in
/// [`tests/qr_clipboard_logic.rs`] without a live `gdk::Display` /
/// clipboard round-trip.
#[must_use]
pub fn compose_qr_decode_outcome(
    layout: &RgbaLayout,
    rgba: &[u8],
    downloaded_stride: usize,
    import_time: SystemTime,
) -> QrDecodeOutcome {
    if let Err(mismatch) = verify_download_layout(layout, rgba.len(), downloaded_stride) {
        return QrDecodeOutcome::DownloadMismatch(mismatch);
    }
    match decode_clipboard_qr(layout, rgba, import_time) {
        Ok(accounts) => QrDecodeOutcome::Decoded(accounts),
        Err(err) => QrDecodeOutcome::DecodeError(err),
    }
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
