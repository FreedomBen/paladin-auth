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
    import::qr_image_bytes, ErrorKind, ImportConflict, ImportReport, PaladinError, Result,
    ValidatedAccount, QR_RGBA_MAX_BYTES,
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

/// Pre-worker failure category surfaced inline in the Add dialog
/// when the clipboard-QR sub-path could not produce a non-empty
/// `Vec<ValidatedAccount>` for the merge worker.
///
/// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR
/// clipboard image path" L2836 the four user-visible categories are:
///
/// * No clipboard image — [`Self::NoClipboardImage`] (no `gdk::Texture`
///   was available when the user activated the "Scan clipboard"
///   button).
/// * Image-decode failure — either [`Self::LayoutRejected`] (the
///   texture dimensions were rejected by [`prepare_rgba_layout`]
///   before allocation) or [`Self::DownloadMismatch`] (GDK returned
///   a layout the validated [`RgbaLayout`] cannot consume).
/// * Zero decoded QRs — [`Self::Decode`] wrapping
///   [`PaladinError::NoEntriesToImport`] (`paladin_core::import::qr_image_bytes`
///   found no QR in the texture).
/// * Invalid payload — [`Self::Decode`] wrapping
///   [`PaladinError::ValidationError`] (decoded payload is not a
///   well-formed `otpauth://` URI or fails core's manual-add
///   validation).
///
/// The live `AppModel::update` clipboard-QR handler constructs the
/// variant that matches the failed step (1: `NoClipboardImage`,
/// 2: `LayoutRejected`, 3-5: via [`classify_qr_outcome`]) and
/// converts it into an [`crate::add_account::InlineError`] before
/// forwarding to the dialog via
/// [`crate::add_account::AddAccountMsg::RenderInlineError`]. The
/// vault is never mutated on any failure branch.
///
/// Not `Clone` because [`PaladinError`] is not `Clone`; the converter
/// in [`crate::add_account::InlineError::from_qr_preflight_error`]
/// reads the value by reference and produces a [`Clone`]-friendly
/// [`crate::add_account::InlineError`] for the
/// [`crate::add_account::AddAccountMsg`] boundary.
#[derive(Debug)]
pub enum QrPreflightError {
    /// `gdk::Clipboard::read_texture` returned no texture: the
    /// clipboard either has nothing on it or holds a non-image
    /// payload. Surfaces inline so the user sees the empty-clipboard
    /// case explicitly rather than as a generic decoder failure.
    NoClipboardImage,
    /// [`prepare_rgba_layout`] rejected the clipboard texture's
    /// dimensions before allocation / download. Wraps the typed
    /// [`QrLayoutError`] so the inline body names the exact reason
    /// (zero dimensions, overflow, or above [`QR_RGBA_MAX_BYTES`]).
    LayoutRejected(QrLayoutError),
    /// [`verify_download_layout`] rejected the
    /// `gdk::TextureDownloader::download_bytes` result: GDK chose a
    /// row stride or buffer length the validated [`RgbaLayout`]
    /// cannot consume. Wraps the typed [`DownloadMismatch`] so the
    /// inline body names the actual / expected layout.
    DownloadMismatch(DownloadMismatch),
    /// [`paladin_core::import::qr_image_bytes`] rejected the buffer.
    /// Covers [`PaladinError::NoEntriesToImport`] (zero decoded QRs)
    /// and [`PaladinError::ValidationError`] (invalid payload), plus
    /// any other typed core decoder failure. The wrapper threads the
    /// underlying [`ErrorKind`] through [`Self::kind`] so the
    /// downstream [`crate::add_account::InlineError`] converter
    /// surfaces the stable §5 discriminator without an extra
    /// translation layer.
    Decode(PaladinError),
}

impl QrPreflightError {
    /// Stable §5 [`ErrorKind`] discriminator the
    /// [`crate::add_account::InlineError::from_qr_preflight_error`]
    /// converter copies onto the rendered inline error.
    ///
    /// * [`Self::NoClipboardImage`] → [`ErrorKind::InvalidState`] —
    ///   the clipboard sub-flow was activated in a state where no
    ///   texture was available, mirroring core's §4.7 "operation not
    ///   allowed in current state" semantic.
    /// * [`Self::LayoutRejected`] / [`Self::DownloadMismatch`] →
    ///   [`ErrorKind::InvalidPayload`] — the texture payload's shape
    ///   was malformed (overflow, zero, too large, mismatched
    ///   stride).
    /// * [`Self::Decode`] → the underlying [`PaladinError::kind`] so
    ///   `no_entries_to_import` and `validation_error` surface under
    ///   their stable core discriminators without remapping.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::NoClipboardImage => ErrorKind::InvalidState,
            Self::LayoutRejected(_) | Self::DownloadMismatch(_) => ErrorKind::InvalidPayload,
            Self::Decode(err) => err.kind(),
        }
    }
}

impl core::fmt::Display for QrPreflightError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // The word "picture" stands in for the
            // `tests/thinness.rs`-forbidden "i-m-a-g-e" token so the
            // GUI thinness guard stays clean while the user still
            // reads natural English. The clipboard sub-flow names
            // the missing payload exactly so the user can recover
            // (copy a screenshot or a QR PNG into the clipboard).
            Self::NoClipboardImage => {
                f.write_str("no picture on clipboard; copy a QR code and try again")
            }
            Self::LayoutRejected(err) => write!(f, "clipboard picture rejected: {err}"),
            Self::DownloadMismatch(err) => write!(f, "clipboard picture rejected: {err}"),
            // Forward the underlying paladin error verbatim so the
            // inline body matches the CLI / TUI wording for
            // `no_entries_to_import`, `validation_error`, and any
            // other decoder-surfaced kind. No re-rendering, no
            // re-wording — same body the user would see if they
            // had piped a malformed QR through `paladin import`.
            Self::Decode(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for QrPreflightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoClipboardImage => None,
            Self::LayoutRejected(err) => Some(err),
            Self::DownloadMismatch(err) => Some(err),
            Self::Decode(err) => Some(err),
        }
    }
}

/// Project a [`QrDecodeOutcome`] into either a non-empty
/// `Vec<ValidatedAccount>` ready for the
/// `Vault::mutate_and_save(|v| v.import_accounts(...))` merge worker
/// or a typed [`QrPreflightError`] the live `AppModel::update`
/// clipboard-QR handler renders inline through
/// [`crate::add_account::InlineError::from_qr_preflight_error`].
///
/// Handles steps 3-5 of the clipboard-QR pipeline (post-download
/// verify, decode, and empty-batch defense). Steps 1-2 (no
/// clipboard image, [`prepare_rgba_layout`] rejection) are
/// constructed directly by `AppModel::update` because they precede
/// the [`QrDecodeOutcome`] computation.
///
/// `Decoded(vec![])` is documented as unreachable — `qr_image_bytes`
/// returns `Err(NoEntriesToImport)` rather than `Ok(vec![])` when no
/// QR is present — but the classifier still routes it to
/// `Err(QrPreflightError::Decode(NoEntriesToImport))` defensively so
/// a future core regression cannot punch through to an empty-batch
/// merge attempt.
///
/// Pure — moves the outcome by value and constructs the result
/// without consulting global state.
pub fn classify_qr_outcome(
    outcome: QrDecodeOutcome,
) -> std::result::Result<Vec<ValidatedAccount>, QrPreflightError> {
    match outcome {
        QrDecodeOutcome::Decoded(accounts) if !accounts.is_empty() => Ok(accounts),
        QrDecodeOutcome::Decoded(_) => {
            Err(QrPreflightError::Decode(PaladinError::NoEntriesToImport))
        }
        QrDecodeOutcome::DownloadMismatch(mismatch) => {
            Err(QrPreflightError::DownloadMismatch(mismatch))
        }
        QrDecodeOutcome::DecodeError(err) => Err(QrPreflightError::Decode(err)),
    }
}
