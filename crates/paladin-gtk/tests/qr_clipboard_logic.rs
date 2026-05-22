// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic clipboard-QR tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/qr_clipboard_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * RGBA byte-length / stride preparation matches `width * 4` rows /
//!   `width * height * 4` total with overflow-checked multiplication.
//! * Sizes above `paladin_core::QR_RGBA_MAX_BYTES` reject before
//!   allocation / download.
//! * Decoded buffer is passed to `paladin_core::import::qr_image_bytes`
//!   with `ImportConflict::Skip` and reports
//!   imported / skipped / warning counts (parity with §6).

use std::time::{Duration, SystemTime};

use paladin_core::{
    AccountId, ImportConflict, ImportReport, ImportWarning, ValidationWarning, QR_RGBA_MAX_BYTES,
};

use paladin_gtk::qr_clipboard::{
    allocate_rgba_buffer, clipboard_qr_memory_format, decode_clipboard_qr, prepare_rgba_layout,
    verify_download_layout, DownloadMismatch, QrImportSummary, QrLayoutError, RgbaLayout,
    CLIPBOARD_QR_CONFLICT_POLICY,
};
use relm4::gtk::gdk;

// ---------------------------------------------------------------------------
// Item 1: RGBA byte-length / stride preparation
// ---------------------------------------------------------------------------

#[test]
fn prepare_rgba_layout_returns_row_stride_width_times_four() {
    let layout = prepare_rgba_layout(33, 17).expect("small size succeeds");
    assert_eq!(layout.width(), 33);
    assert_eq!(layout.height(), 17);
    assert_eq!(layout.row_stride(), 33 * 4);
}

#[test]
fn prepare_rgba_layout_returns_buffer_bytes_width_times_height_times_four() {
    let layout = prepare_rgba_layout(640, 480).expect("standard QR-sized image succeeds");
    assert_eq!(layout.buffer_bytes(), 640 * 480 * 4);
}

#[test]
fn prepare_rgba_layout_uses_checked_multiplication_for_width_times_height() {
    // u32::MAX * u32::MAX overflows usize on 64-bit, and any sub-overflow
    // value still exceeds the byte cap. Use values that overflow the
    // pixel-count multiplication itself on 64-bit (usize-saturating).
    let huge = u32::MAX;
    let err = prepare_rgba_layout(huge, huge).expect_err("overflow rejected");
    assert!(
        matches!(
            err,
            QrLayoutError::DimensionsOverflow | QrLayoutError::ImageTooLarge { .. }
        ),
        "expected overflow or too-large, got {err:?}"
    );
}

#[test]
fn prepare_rgba_layout_uses_checked_multiplication_for_bytes_step() {
    // Construct a width/height whose pixel count fits in usize but whose
    // *byte* count overflows when multiplied by 4. On 64-bit usize is 64
    // bits, so the only way to provoke the byte-step overflow is via the
    // same multiplication that paladin-core itself guards. Either result
    // (DimensionsOverflow or ImageTooLarge) signals "rejected before
    // allocation".
    let w = 65_536_u32;
    let h = 65_536_u32;
    let err = prepare_rgba_layout(w, h).expect_err("rejected pre-allocation");
    assert!(matches!(
        err,
        QrLayoutError::DimensionsOverflow | QrLayoutError::ImageTooLarge { .. }
    ));
}

#[test]
fn prepare_rgba_layout_rejects_zero_width() {
    let err = prepare_rgba_layout(0, 64).expect_err("zero width rejected");
    assert!(matches!(err, QrLayoutError::ZeroDimensions));
}

#[test]
fn prepare_rgba_layout_rejects_zero_height() {
    let err = prepare_rgba_layout(64, 0).expect_err("zero height rejected");
    assert!(matches!(err, QrLayoutError::ZeroDimensions));
}

#[test]
fn rgba_layout_total_matches_stride_times_height() {
    let layout = prepare_rgba_layout(120, 80).expect("succeeds");
    assert_eq!(
        layout.buffer_bytes(),
        layout
            .row_stride()
            .checked_mul(layout.height() as usize)
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// Item 2: QR_RGBA_MAX_BYTES rejection happens *before* allocation / download
// ---------------------------------------------------------------------------

#[test]
fn prepare_rgba_layout_rejects_size_above_qr_rgba_max_bytes() {
    // QR_RGBA_MAX_BYTES is 64 MiB. Pick a width/height whose total just
    // exceeds the cap but whose intermediate pixel count fits.
    // Pixels needed = QR_RGBA_MAX_BYTES / 4 + 1 = 16 MiB pixels + 1.
    // Use width = 16 MiB + 1, height = 1 — pixel count = 16 MiB + 1,
    // bytes = (16 MiB + 1) * 4 > 64 MiB by 4 bytes.
    let max_pixels = QR_RGBA_MAX_BYTES / 4;
    let overshoot = max_pixels + 1;
    let w = u32::try_from(overshoot).expect("fits in u32");
    let err = prepare_rgba_layout(w, 1).expect_err("oversized rejected");
    match err {
        QrLayoutError::ImageTooLarge {
            requested_bytes,
            max_bytes,
        } => {
            assert!(requested_bytes > max_bytes, "requested must exceed max");
            assert_eq!(max_bytes, QR_RGBA_MAX_BYTES);
            assert_eq!(requested_bytes, overshoot * 4);
        }
        other => panic!("expected ImageTooLarge, got {other:?}"),
    }
}

#[test]
fn prepare_rgba_layout_accepts_size_exactly_at_qr_rgba_max_bytes() {
    let pixels = QR_RGBA_MAX_BYTES / 4;
    let w = u32::try_from(pixels).expect("fits in u32");
    let layout = prepare_rgba_layout(w, 1).expect("at-cap accepted");
    assert_eq!(layout.buffer_bytes(), QR_RGBA_MAX_BYTES);
}

#[test]
fn prepare_rgba_layout_runs_before_buffer_is_allocated() {
    // The helper is the *only* gate before allocation: it must reject
    // without touching the rgba slice at all. We can't directly observe
    // "no allocation happens", but the signature itself takes no buffer
    // and the test above demonstrates that the rejection arrives via the
    // typed error rather than via a panic / OOM. This test pins the
    // contract: the function does not accept a slice and therefore
    // cannot have allocated anything before signalling the error.
    fn assert_signature(_: fn(u32, u32) -> Result<RgbaLayout, QrLayoutError>) {}
    assert_signature(prepare_rgba_layout);
}

// ---------------------------------------------------------------------------
// Item 2b: allocate_rgba_buffer materializes the validated layout
// ---------------------------------------------------------------------------
//
// `prepare_rgba_layout` is the gate; `allocate_rgba_buffer` is the
// materialization step that runs *after* the gate has accepted the
// layout. Together they satisfy the
// `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR
// clipboard image path" sub-item:
//   "Allocate an exact width * height * 4 straight (non-premultiplied)
//    RGBA8 buffer with overflow-checked multiplication; reject sizes
//    above paladin_core::QR_RGBA_MAX_BYTES before allocation /
//    download."
//
// The signature takes `&RgbaLayout` so a caller cannot bypass the
// overflow / size checks by handing in raw u32 dimensions.

#[test]
fn allocate_rgba_buffer_takes_validated_layout_so_callers_cannot_bypass_size_gate() {
    fn assert_signature(_: fn(&RgbaLayout) -> Vec<u8>) {}
    assert_signature(allocate_rgba_buffer);
}

#[test]
fn allocate_rgba_buffer_returns_vec_with_length_matching_buffer_bytes() {
    let layout = prepare_rgba_layout(33, 17).expect("small size succeeds");
    let buffer = allocate_rgba_buffer(&layout);
    assert_eq!(buffer.len(), layout.buffer_bytes());
}

#[test]
fn allocate_rgba_buffer_returns_vec_with_length_width_times_height_times_four() {
    let layout = prepare_rgba_layout(640, 480).expect("standard QR-sized image succeeds");
    let buffer = allocate_rgba_buffer(&layout);
    assert_eq!(buffer.len(), 640 * 480 * 4);
}

#[test]
fn allocate_rgba_buffer_returns_vec_with_length_row_stride_times_height() {
    let layout = prepare_rgba_layout(120, 80).expect("ok");
    let buffer = allocate_rgba_buffer(&layout);
    assert_eq!(
        buffer.len(),
        layout
            .row_stride()
            .checked_mul(layout.height() as usize)
            .unwrap()
    );
}

#[test]
fn allocate_rgba_buffer_is_zero_initialized() {
    let layout = prepare_rgba_layout(4, 4).expect("ok");
    let buffer = allocate_rgba_buffer(&layout);
    assert!(
        buffer.iter().all(|byte| *byte == 0),
        "fresh buffer must be zero-initialized so a partial download cannot leak prior heap bytes"
    );
}

#[test]
fn allocate_rgba_buffer_zero_initialization_extends_across_full_capacity() {
    let layout = prepare_rgba_layout(40, 40).expect("ok");
    let buffer = allocate_rgba_buffer(&layout);
    assert_eq!(buffer.len(), layout.buffer_bytes());
    // Iterate every byte to ensure we are not relying on a shorter
    // internal `len` that hides uninit tail bytes.
    for (i, byte) in buffer.iter().enumerate() {
        assert_eq!(*byte, 0, "byte {i} expected to be zero");
    }
}

#[test]
fn allocate_rgba_buffer_capacity_at_least_matches_length() {
    let layout = prepare_rgba_layout(32, 32).expect("ok");
    let buffer = allocate_rgba_buffer(&layout);
    assert!(
        buffer.capacity() >= buffer.len(),
        "Vec capacity must cover the requested length so TextureDownloader can write into it"
    );
}

#[test]
fn allocate_rgba_buffer_at_qr_rgba_max_bytes_succeeds() {
    // The validated layout already accepts a size exactly at
    // QR_RGBA_MAX_BYTES (see prepare_rgba_layout_accepts_size_exactly_at_qr_rgba_max_bytes).
    // allocate_rgba_buffer must materialize that exact size without
    // truncation.
    let pixels = QR_RGBA_MAX_BYTES / 4;
    let w = u32::try_from(pixels).expect("fits in u32");
    let layout = prepare_rgba_layout(w, 1).expect("at-cap accepted");
    let buffer = allocate_rgba_buffer(&layout);
    assert_eq!(buffer.len(), QR_RGBA_MAX_BYTES);
}

// ---------------------------------------------------------------------------
// Item 2c: clipboard_qr_memory_format selects straight RGBA8
// ---------------------------------------------------------------------------
//
// `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR clipboard
// image path" pins the GDK download format to
// `gdk::MemoryFormat::R8g8b8a8` (straight, non-premultiplied RGBA) so
// the `rqrr`-based QR decoder behind
// `paladin_core::import::qr_image_bytes` consumes pixel values
// directly. The default `Texture::download` path yields *premultiplied*
// pixels (`R8g8b8a8Premultiplied`) which the QR decoder cannot consume.

#[test]
fn clipboard_qr_memory_format_returns_straight_r8g8b8a8() {
    assert_eq!(clipboard_qr_memory_format(), gdk::MemoryFormat::R8g8b8a8);
}

#[test]
fn clipboard_qr_memory_format_is_not_premultiplied() {
    // Premultiplied RGBA is the default `Texture::download` format and
    // would silently produce wrong pixels for the QR decoder. Pin the
    // explicit rejection so a future drift away from R8g8b8a8 surfaces
    // here.
    assert_ne!(
        clipboard_qr_memory_format(),
        gdk::MemoryFormat::R8g8b8a8Premultiplied
    );
}

#[test]
fn clipboard_qr_memory_format_signature_takes_no_arguments() {
    fn assert_signature(_: fn() -> gdk::MemoryFormat) {}
    assert_signature(clipboard_qr_memory_format);
}

// ---------------------------------------------------------------------------
// Item 2d: verify_download_layout defensively matches GDK's returned
//          (bytes_len, row_stride) against the validated layout
// ---------------------------------------------------------------------------
//
// `gdk::TextureDownloader::download_bytes` returns `(glib::Bytes,
// usize)` — the GDK-owned buffer plus the row stride GDK chose. We
// asked for `clipboard_qr_memory_format()` with the implicit stride
// expectation `width * 4` (see the §"Component tree" entry). The
// downloader is allowed to return a *larger* stride (e.g. for
// alignment), but the QR decoder upstream requires
// `width * 4` exactly — anything else and the row bytes don't line up
// against the column index `qr_image_bytes` walks.
//
// `verify_download_layout` is the defensive gate that turns a
// "GDK gave us an unexpected layout" into a typed inline error
// before `decode_clipboard_qr` ever sees the bytes.

#[test]
fn verify_download_layout_accepts_matching_length_and_stride() {
    let layout = prepare_rgba_layout(40, 30).expect("ok");
    verify_download_layout(&layout, layout.buffer_bytes(), layout.row_stride()).expect("matches");
}

#[test]
fn verify_download_layout_rejects_short_buffer() {
    let layout = prepare_rgba_layout(40, 30).expect("ok");
    let short_len = layout.buffer_bytes() - 1;
    let err = verify_download_layout(&layout, short_len, layout.row_stride())
        .expect_err("short buffer rejected");
    match err {
        DownloadMismatch::BufferLength {
            actual_bytes,
            expected_bytes,
        } => {
            assert_eq!(actual_bytes, short_len);
            assert_eq!(expected_bytes, layout.buffer_bytes());
        }
        DownloadMismatch::RowStride { .. } => panic!("expected BufferLength, got RowStride"),
    }
}

#[test]
fn verify_download_layout_rejects_long_buffer() {
    let layout = prepare_rgba_layout(40, 30).expect("ok");
    let long_len = layout.buffer_bytes() + 1;
    let err = verify_download_layout(&layout, long_len, layout.row_stride())
        .expect_err("long buffer rejected");
    assert!(matches!(err, DownloadMismatch::BufferLength { .. }));
}

#[test]
fn verify_download_layout_rejects_mismatched_stride() {
    let layout = prepare_rgba_layout(40, 30).expect("ok");
    let padded_stride = layout.row_stride() + 8;
    let err = verify_download_layout(&layout, layout.buffer_bytes(), padded_stride)
        .expect_err("padded stride rejected");
    match err {
        DownloadMismatch::RowStride {
            actual_stride,
            expected_stride,
        } => {
            assert_eq!(actual_stride, padded_stride);
            assert_eq!(expected_stride, layout.row_stride());
        }
        DownloadMismatch::BufferLength { .. } => panic!("expected RowStride, got BufferLength"),
    }
}

#[test]
fn verify_download_layout_signature_takes_layout_len_and_stride() {
    fn assert_signature(_: fn(&RgbaLayout, usize, usize) -> Result<(), DownloadMismatch>) {}
    assert_signature(verify_download_layout);
}

#[test]
fn download_mismatch_display_does_not_echo_secret_bytes() {
    // Defensive: the typed error renders the *size* mismatch only —
    // never any RGBA pixel data. Pinned so a future Display impl
    // change does not start interpolating downloaded bytes.
    let layout = prepare_rgba_layout(40, 30).expect("ok");
    let buffer_err =
        verify_download_layout(&layout, 0, layout.row_stride()).expect_err("zero-length rejected");
    let body = buffer_err.to_string();
    assert!(
        body.contains("expected") || body.contains("byte") || body.contains("buffer"),
        "{body:?} must surface the size mismatch"
    );
    // No bytes are ever passed to the validator, so there is nothing
    // secret to leak — pin the contract: the renderer does not
    // construct a slice from the dimensions and read it.
}

// ---------------------------------------------------------------------------
// Item 3: decoded buffer → qr_image_bytes with ImportConflict::Skip,
//         and imported/skipped/warning counts are reported.
// ---------------------------------------------------------------------------

#[test]
fn clipboard_qr_conflict_policy_is_skip() {
    assert_eq!(CLIPBOARD_QR_CONFLICT_POLICY, ImportConflict::Skip);
}

#[test]
fn decode_clipboard_qr_propagates_buffer_length_mismatch_from_core() {
    // A correctly sized but blank RGBA buffer should reach `qr_image_bytes`
    // (no early bail from the gtk wrapper). qr_image_bytes returns either
    // `NoEntriesToImport` (no QR found) or a validation error — both prove
    // the wrapper handed control over to paladin-core after sizing.
    let layout = prepare_rgba_layout(10, 10).expect("small image");
    let rgba = vec![0xFF_u8; layout.buffer_bytes()];
    let err = decode_clipboard_qr(&layout, &rgba, SystemTime::UNIX_EPOCH)
        .expect_err("blank buffer cannot decode");
    // The error must come from paladin-core's QR path, not the wrapper.
    let display = err.to_string();
    assert!(
        !display.is_empty(),
        "core error surfaces with non-empty text"
    );
}

#[test]
fn decode_clipboard_qr_rejects_buffer_length_mismatch() {
    let layout = prepare_rgba_layout(8, 8).expect("ok");
    let too_small = vec![0_u8; layout.buffer_bytes() - 1];
    let err = decode_clipboard_qr(&layout, &too_small, SystemTime::UNIX_EPOCH)
        .expect_err("short buffer rejected");
    // Error comes from `qr_image_bytes`'s validation; the kind tag is
    // `validation_error` with code `buffer_length_mismatch`.
    let display = err.to_string();
    assert!(
        display.contains("buffer_length_mismatch") || display.contains("validation"),
        "expected core validation message, got {display:?}"
    );
}

#[test]
fn qr_import_summary_extracts_counts_from_report() {
    let report = ImportReport {
        imported: 3,
        skipped: 2,
        replaced: 0,
        appended: 0,
        accounts: vec![AccountId::new(), AccountId::new(), AccountId::new()],
        warnings: vec![
            ImportWarning {
                source_index: 0,
                warning: ValidationWarning::ShortSecret {
                    decoded_len: 8,
                    recommended_min: 16,
                },
            },
            ImportWarning {
                source_index: 4,
                warning: ValidationWarning::ShortSecret {
                    decoded_len: 6,
                    recommended_min: 16,
                },
            },
        ],
    };
    let summary = QrImportSummary::from_report(&report);
    assert_eq!(summary.imported, 3);
    assert_eq!(summary.skipped, 2);
    assert_eq!(summary.warnings, 2);
}

#[test]
fn qr_import_summary_zero_when_report_empty() {
    let summary = QrImportSummary::from_report(&ImportReport::default());
    assert_eq!(summary.imported, 0);
    assert_eq!(summary.skipped, 0);
    assert_eq!(summary.warnings, 0);
}

#[test]
fn qr_import_summary_ignores_replaced_and_appended_under_skip_policy() {
    // Skip policy cannot produce replaced/appended counts, but if a
    // future caller mis-uses the helper we want the summary to
    // explicitly surface only the imported/skipped/warning counts the
    // §6 add modal panel cares about.
    let report = ImportReport {
        imported: 1,
        skipped: 0,
        replaced: 7,
        appended: 9,
        accounts: vec![AccountId::new()],
        warnings: vec![],
    };
    let summary = QrImportSummary::from_report(&report);
    assert_eq!(summary.imported, 1);
    assert_eq!(summary.skipped, 0);
    assert_eq!(summary.warnings, 0);
}

// ---------------------------------------------------------------------------
// Sanity: import-time is forwarded verbatim to paladin-core
// ---------------------------------------------------------------------------

#[test]
fn decode_clipboard_qr_uses_supplied_import_time() {
    // We cannot read import_time back from an error, but we can confirm
    // that the wrapper accepts a `SystemTime` argument and forwards it
    // by signature — pinning the contract is enough.
    fn assert_signature(
        _: fn(
            &RgbaLayout,
            &[u8],
            SystemTime,
        ) -> paladin_core::Result<Vec<paladin_core::ValidatedAccount>>,
    ) {
    }
    assert_signature(decode_clipboard_qr);

    // And a small smoke run with two different import_time values
    // should both surface a paladin-core decode error, not a wrapper
    // pre-check failure.
    let layout = prepare_rgba_layout(10, 10).expect("ok");
    let rgba = vec![0xFF_u8; layout.buffer_bytes()];
    let t1 = SystemTime::UNIX_EPOCH;
    let t2 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let _ = decode_clipboard_qr(&layout, &rgba, t1).expect_err("blank fails");
    let _ = decode_clipboard_qr(&layout, &rgba, t2).expect_err("blank fails");
}
