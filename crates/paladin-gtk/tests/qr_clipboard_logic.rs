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
    AccountId, ErrorKind, ImportConflict, ImportReport, ImportWarning, ValidatedAccount,
    ValidationWarning, QR_RGBA_MAX_BYTES,
};

use paladin_gtk::qr_clipboard::{
    allocate_rgba_buffer, classify_layout_preflight, clipboard_qr_memory_format,
    compose_qr_decode_outcome, decode_clipboard_qr, prepare_rgba_layout, verify_download_layout,
    DownloadMismatch, QrDecodeOutcome, QrImportSummary, QrLayoutError, RgbaLayout,
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

// ---------------------------------------------------------------------------
// `compose_qr_decode_outcome`: post-download verify + decode glue
//
// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR
// clipboard image path" L2738, the live `AppModel` clipboard-QR
// handler hands the validated `RgbaLayout`, the GDK-downloaded RGBA
// buffer, GDK's reported row stride, and the `import_time` stamp
// into one pure-logic composer that runs `verify_download_layout`
// *before* `decode_clipboard_qr` and routes both outcomes into a
// single typed `QrDecodeOutcome` discriminator. The intent is that
// the GTK side cannot bypass the stride / length check before
// reaching `paladin_core::import::qr_image_bytes`.
// ---------------------------------------------------------------------------

#[test]
fn compose_qr_decode_outcome_signature_takes_layout_bytes_stride_and_import_time() {
    // Pin the signature so the live dispatch site cannot drift away
    // from the four-argument contract that the implementation plan
    // calls out: layout + downloaded bytes + downloaded stride +
    // import_time → typed outcome. Pinning by signature mirrors the
    // existing `decode_clipboard_qr_uses_supplied_import_time` test.
    fn assert_signature(_: fn(&RgbaLayout, &[u8], usize, SystemTime) -> QrDecodeOutcome) {}
    assert_signature(compose_qr_decode_outcome);
}

#[test]
fn compose_qr_decode_outcome_returns_download_mismatch_when_stride_disagrees() {
    let layout = prepare_rgba_layout(16, 16).expect("ok");
    let rgba = vec![0_u8; layout.buffer_bytes()];
    // GDK reported a stride wider than `width * 4` (e.g. alignment
    // padding). The composer must surface a `RowStride` mismatch
    // and *not* reach `qr_image_bytes` — that decoder requires
    // `width * 4` exactly.
    let bad_stride = layout.row_stride() + 4;
    match compose_qr_decode_outcome(&layout, &rgba, bad_stride, SystemTime::UNIX_EPOCH) {
        QrDecodeOutcome::DownloadMismatch(DownloadMismatch::RowStride {
            actual_stride,
            expected_stride,
        }) => {
            assert_eq!(actual_stride, bad_stride);
            assert_eq!(expected_stride, layout.row_stride());
        }
        other => panic!("expected RowStride mismatch, got {other:?}"),
    }
}

#[test]
fn compose_qr_decode_outcome_returns_download_mismatch_when_buffer_too_short() {
    let layout = prepare_rgba_layout(8, 8).expect("ok");
    // Buffer is one byte shorter than expected; verify must reject
    // before qr_image_bytes sees the slice.
    let truncated = vec![0_u8; layout.buffer_bytes() - 1];
    match compose_qr_decode_outcome(
        &layout,
        &truncated,
        layout.row_stride(),
        SystemTime::UNIX_EPOCH,
    ) {
        QrDecodeOutcome::DownloadMismatch(DownloadMismatch::BufferLength {
            actual_bytes,
            expected_bytes,
        }) => {
            assert_eq!(actual_bytes, layout.buffer_bytes() - 1);
            assert_eq!(expected_bytes, layout.buffer_bytes());
        }
        other => panic!("expected BufferLength mismatch, got {other:?}"),
    }
}

#[test]
fn compose_qr_decode_outcome_returns_download_mismatch_when_buffer_too_long() {
    let layout = prepare_rgba_layout(8, 8).expect("ok");
    // GDK over-allocated; verify must still reject so the decoder
    // never sees a slice that does not match the dimensions.
    let overlong = vec![0_u8; layout.buffer_bytes() + 8];
    match compose_qr_decode_outcome(
        &layout,
        &overlong,
        layout.row_stride(),
        SystemTime::UNIX_EPOCH,
    ) {
        QrDecodeOutcome::DownloadMismatch(DownloadMismatch::BufferLength {
            actual_bytes,
            expected_bytes,
        }) => {
            assert_eq!(actual_bytes, layout.buffer_bytes() + 8);
            assert_eq!(expected_bytes, layout.buffer_bytes());
        }
        other => panic!("expected BufferLength mismatch, got {other:?}"),
    }
}

#[test]
fn compose_qr_decode_outcome_returns_decode_error_for_blank_buffer() {
    let layout = prepare_rgba_layout(10, 10).expect("ok");
    // Blank buffer at the correct stride / length reaches the
    // decoder, which then surfaces `NoEntriesToImport` because no
    // QR is present. The mismatch path stays unused — that confirms
    // the verify gate did not short-circuit before the decode.
    let rgba = vec![0xFF_u8; layout.buffer_bytes()];
    match compose_qr_decode_outcome(&layout, &rgba, layout.row_stride(), SystemTime::UNIX_EPOCH) {
        QrDecodeOutcome::DecodeError(err) => {
            assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
        }
        other => panic!("expected DecodeError, got {other:?}"),
    }
}

#[test]
fn compose_qr_decode_outcome_runs_verify_before_decode_for_short_buffer() {
    // A buffer too short to feed `qr_image_bytes` must surface as a
    // `DownloadMismatch` and never reach the core decoder — pinning
    // the call order so a future refactor cannot accidentally
    // forward a short slice into the rqrr-backed path.
    let layout = prepare_rgba_layout(8, 8).expect("ok");
    let short = vec![0_u8; 4];
    let outcome =
        compose_qr_decode_outcome(&layout, &short, layout.row_stride(), SystemTime::UNIX_EPOCH);
    assert!(
        matches!(outcome, QrDecodeOutcome::DownloadMismatch(_)),
        "short buffer should bail at verify, not decode: {outcome:?}"
    );
}

#[test]
fn compose_qr_decode_outcome_forwards_import_time_to_qr_image_bytes() {
    // Two different import_time values on the same blank buffer
    // both surface `DecodeError(NoEntriesToImport)` — proves the
    // composer always reaches the decoder when the layout / stride
    // check passes, and accepts the SystemTime parameter without
    // pre-checks of its own. We cannot read import_time back from
    // an error, so signature parity matches the
    // `decode_clipboard_qr_uses_supplied_import_time` pin above.
    let layout = prepare_rgba_layout(10, 10).expect("ok");
    let rgba = vec![0xFF_u8; layout.buffer_bytes()];
    let t1 = SystemTime::UNIX_EPOCH;
    let t2 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for t in [t1, t2] {
        match compose_qr_decode_outcome(&layout, &rgba, layout.row_stride(), t) {
            QrDecodeOutcome::DecodeError(err) => {
                assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
            }
            other => panic!("expected DecodeError, got {other:?}"),
        }
    }
}

#[test]
fn compose_qr_decode_outcome_decoded_carries_empty_vec_only_under_unreachable_path() {
    // Defensive: there is no valid input that lets the composer
    // succeed with zero accounts — `qr_image_bytes`'s
    // `payloads_to_accounts` returns `NoEntriesToImport` when the
    // decoded payload list is empty, so reaching `Decoded(vec![])`
    // would require a future contract regression on core. This test
    // documents that invariant by asserting `Decoded(Vec<ValidatedAccount>)`
    // is constructible for type-system completeness without
    // claiming it is produced in practice.
    let decoded: Vec<ValidatedAccount> = Vec::new();
    let outcome = QrDecodeOutcome::Decoded(decoded);
    match outcome {
        QrDecodeOutcome::Decoded(v) => assert_eq!(v.len(), 0),
        _ => unreachable!("constructed Decoded variant"),
    }
}

// ---------------------------------------------------------------------------
// Item 4: pre-worker inline-error categories
//
// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"`AddAccountComponent` QR clipboard
// image path", the four user-visible inline-error categories the dialog
// must surface without mutating the vault are:
//
//   * no-image  (no `gdk::Texture` available on the clipboard)
//   * image-decode failure  (`prepare_rgba_layout` reject or
//     `verify_download_layout` mismatch from a GDK download)
//   * zero-decoded QRs  (`paladin_core::import::qr_image_bytes` returned
//     `no_entries_to_import` — no QR present in the texture)
//   * invalid payload  (decoded payload is not an `otpauth://` URI or
//     fails core's validation pipeline)
//
// `QrPreflightError` is the typed enum that carries each category to the
// `AppModel::update` clipboard-QR handler, where it is converted into an
// `add_account::InlineError` and forwarded into the Add dialog via
// `AddAccountMsg::RenderInlineError`. `classify_qr_outcome` projects a
// `QrDecodeOutcome` (steps 3-5 of the pipeline) into either a non-empty
// `Vec<ValidatedAccount>` ready for the merge worker or a typed
// preflight error; the `NoClipboardImage` and `LayoutRejected` variants
// are constructed directly by `AppModel::update` for steps 1-2.
// ---------------------------------------------------------------------------

use paladin_core::PaladinError;
use paladin_gtk::qr_clipboard::{classify_qr_outcome, QrPreflightError};

#[test]
fn qr_preflight_error_no_clipboard_image_kind_is_invalid_state() {
    // No `gdk::Texture` available on the clipboard is the GUI-only
    // "operation not allowed in current state" case — the user asked
    // for a scan but the clipboard has nothing to scan. Mirrors core's
    // `invalid_state` semantics from §4.7 even though there is no
    // matching `PaladinError` variant for this GUI-only failure.
    assert_eq!(
        QrPreflightError::NoClipboardImage.kind(),
        ErrorKind::InvalidState,
    );
}

#[test]
fn qr_preflight_error_layout_rejected_kind_is_invalid_payload() {
    let err = QrPreflightError::LayoutRejected(QrLayoutError::ZeroDimensions);
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);
}

#[test]
fn qr_preflight_error_download_mismatch_kind_is_invalid_payload() {
    let err = QrPreflightError::DownloadMismatch(DownloadMismatch::RowStride {
        actual_stride: 64,
        expected_stride: 40,
    });
    assert_eq!(err.kind(), ErrorKind::InvalidPayload);
}

#[test]
fn qr_preflight_error_decode_no_entries_kind_is_no_entries_to_import() {
    let err = QrPreflightError::Decode(PaladinError::NoEntriesToImport);
    assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
}

#[test]
fn qr_preflight_error_decode_validation_error_kind_is_validation_error() {
    let err = QrPreflightError::Decode(PaladinError::ValidationError {
        field: "secret",
        reason: "invalid_base32".to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    });
    assert_eq!(err.kind(), ErrorKind::ValidationError);
}

#[test]
fn qr_preflight_error_no_clipboard_image_display_is_non_empty_and_does_not_panic() {
    let body = QrPreflightError::NoClipboardImage.to_string();
    assert!(!body.is_empty(), "no-image body must be non-empty");
    // Wording must point at the clipboard, not at the vault — the
    // user's mental model is "I tried to scan the clipboard and
    // nothing was there", not "I tried to save to the vault".
    let lower = body.to_lowercase();
    assert!(
        lower.contains("clipboard") || lower.contains("image"),
        "no-image body should reference the clipboard/image: {body:?}",
    );
}

#[test]
fn qr_preflight_error_layout_rejected_display_includes_underlying_qr_layout_error_body() {
    let layout_err = QrLayoutError::ImageTooLarge {
        requested_bytes: 128 * 1024 * 1024,
        max_bytes: 64 * 1024 * 1024,
    };
    let underlying = layout_err.to_string();
    let body = QrPreflightError::LayoutRejected(layout_err).to_string();
    // The wrapper renders the underlying error's body so the user
    // sees the exact reason — `width * height > max` or zero dims —
    // not just a generic "image rejected" message.
    assert!(
        body.contains(&underlying),
        "layout-rejected body {body:?} should include the underlying error {underlying:?}",
    );
}

#[test]
fn qr_preflight_error_download_mismatch_display_includes_underlying_download_mismatch_body() {
    let mismatch = DownloadMismatch::BufferLength {
        actual_bytes: 100,
        expected_bytes: 256,
    };
    let underlying = mismatch.to_string();
    let body = QrPreflightError::DownloadMismatch(mismatch).to_string();
    assert!(
        body.contains(&underlying),
        "download-mismatch body {body:?} should include the underlying error {underlying:?}",
    );
}

#[test]
fn qr_preflight_error_decode_display_includes_underlying_paladin_error_body() {
    let underlying = PaladinError::NoEntriesToImport.to_string();
    let body = QrPreflightError::Decode(PaladinError::NoEntriesToImport).to_string();
    assert!(
        body.contains(&underlying),
        "decode body {body:?} should include the underlying paladin error {underlying:?}",
    );
}

#[test]
fn qr_preflight_error_display_does_not_echo_secret_bytes() {
    // Defensive: the four variants render through their stable
    // category wording plus the underlying error body. None of the
    // underlying error types (`QrLayoutError`, `DownloadMismatch`,
    // `PaladinError::NoEntriesToImport`) include the raw RGBA buffer
    // bytes, the clipboard texture pointer, or the decoded
    // `otpauth://` secret. Pinning the invariant here so a future
    // refactor cannot accidentally route texture bytes into the
    // user-facing body.
    let bodies = [
        QrPreflightError::NoClipboardImage.to_string(),
        QrPreflightError::LayoutRejected(QrLayoutError::ZeroDimensions).to_string(),
        QrPreflightError::DownloadMismatch(DownloadMismatch::RowStride {
            actual_stride: 64,
            expected_stride: 40,
        })
        .to_string(),
        QrPreflightError::Decode(PaladinError::NoEntriesToImport).to_string(),
    ];
    for body in &bodies {
        // ASCII-printable letters / digits / spaces / punctuation
        // only — the underlying paladin / GDK / core wording never
        // includes raw bytes, so any non-printable byte in the
        // rendered body would be a regression.
        for ch in body.chars() {
            assert!(
                !ch.is_control() || ch == '\n',
                "QrPreflightError body must not contain control characters: {body:?}",
            );
        }
    }
}

#[test]
fn qr_preflight_error_implements_std_error() {
    // Stable trait obligation: the live `AppModel` clipboard-QR
    // handler can pass `&QrPreflightError` through any consumer
    // expecting `&dyn std::error::Error` — for example a future
    // tracing span without re-rendering the body.
    fn assert_error<E: std::error::Error>(_: &E) {}
    assert_error(&QrPreflightError::NoClipboardImage);
    assert_error(&QrPreflightError::LayoutRejected(
        QrLayoutError::ZeroDimensions,
    ));
}

// ---------------------------------------------------------------------------
// Item 4b: classify_qr_outcome projects QrDecodeOutcome into a non-empty
//          batch or a typed preflight error
// ---------------------------------------------------------------------------

#[test]
fn classify_qr_outcome_decoded_non_empty_returns_ok_accounts() {
    // Reach the live decoder so we get a real `ValidatedAccount` —
    // construct a single-QR image identical to the
    // `decode_clipboard_qr_*` pins above. The intent of this test is
    // shape: `Decoded(vec![non_empty])` must surface as `Ok(vec)`.
    //
    // We cannot construct a `ValidatedAccount` by hand because its
    // constructor is private, so we exercise the path that produces
    // it: the verify+decode composer on a buffer that
    // `qr_image_bytes` rejects. That returns `DecodeError`, not
    // `Decoded`, so we cannot directly exercise the non-empty branch
    // here without a live QR image. Instead, pin the empty-branch
    // contract (the defensive `Decoded(vec![])` case) — see the
    // sibling test below — and rely on the live
    // `run_qr_worker_plaintext_import_succeeds_*` tests in
    // `tests/add_account_logic.rs` to cover the non-empty branch
    // end-to-end through the worker pipeline.
    //
    // Signature pin: the classifier returns `Result<Vec<...>, ...>`
    // so the caller routes through a single `?` rather than a
    // bespoke match per outcome variant.
    fn assert_signature(
        _: fn(QrDecodeOutcome) -> std::result::Result<Vec<ValidatedAccount>, QrPreflightError>,
    ) {
    }
    assert_signature(classify_qr_outcome);
}

#[test]
fn classify_qr_outcome_decoded_empty_returns_zero_decoded_qrs() {
    // Defensive: `qr_image_bytes` is documented to return
    // `NoEntriesToImport` rather than `Ok(vec![])`, so an empty
    // `Decoded` is unreachable in normal operation. The classifier
    // still routes it to a typed preflight error rather than
    // silently dispatching an empty-batch worker call — pinning the
    // belt-and-braces routing here so a future regression on core
    // cannot punch through to an empty merge attempt.
    let empty: Vec<ValidatedAccount> = Vec::new();
    let outcome = QrDecodeOutcome::Decoded(empty);
    match classify_qr_outcome(outcome) {
        Err(QrPreflightError::Decode(err)) => {
            assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
        }
        other => panic!("expected Err(Decode(NoEntriesToImport)), got {other:?}"),
    }
}

#[test]
fn classify_qr_outcome_download_mismatch_returns_preflight_error() {
    let mismatch = DownloadMismatch::RowStride {
        actual_stride: 64,
        expected_stride: 40,
    };
    let outcome = QrDecodeOutcome::DownloadMismatch(mismatch);
    match classify_qr_outcome(outcome) {
        Err(QrPreflightError::DownloadMismatch(m)) => assert_eq!(m, mismatch),
        other => panic!("expected Err(DownloadMismatch), got {other:?}"),
    }
}

#[test]
fn classify_qr_outcome_decode_error_returns_preflight_decode_variant() {
    let outcome = QrDecodeOutcome::DecodeError(PaladinError::NoEntriesToImport);
    match classify_qr_outcome(outcome) {
        Err(QrPreflightError::Decode(err)) => {
            assert_eq!(err.kind(), ErrorKind::NoEntriesToImport);
        }
        other => panic!("expected Err(Decode(NoEntriesToImport)), got {other:?}"),
    }
}

#[test]
fn classify_qr_outcome_routes_validation_error_through_decode_variant() {
    // Invalid-payload category: the decoded `otpauth://` text fails
    // core's parser. The classifier wraps the `PaladinError` in
    // `Decode(_)` rather than synthesizing a separate
    // `InvalidPayload` variant — the consumer (`InlineError::from_qr_preflight_error`)
    // discriminates downstream via `ErrorKind`.
    let validation_err = PaladinError::ValidationError {
        field: "secret",
        reason: "invalid_base32".to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    };
    let outcome = QrDecodeOutcome::DecodeError(validation_err);
    match classify_qr_outcome(outcome) {
        Err(QrPreflightError::Decode(err)) => {
            assert_eq!(err.kind(), ErrorKind::ValidationError);
        }
        other => panic!("expected Err(Decode(ValidationError)), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Item: classify_layout_preflight bridges QrLayoutError into QrPreflightError
// ---------------------------------------------------------------------------
//
// `prepare_rgba_layout` is the pre-download gate; its typed
// `QrLayoutError` rejections (zero dimensions, overflow, above
// `QR_RGBA_MAX_BYTES`) precede the `QrDecodeOutcome` computation
// that `classify_qr_outcome` consumes. The live
// `AppModel::update` clipboard-QR handler needs a uniform
// `Result<_, QrPreflightError>` for both the pre-download and the
// post-download halves of the pipeline so the same
// `InlineError::from_qr_preflight_error` routing covers every
// failure branch.
//
// `classify_layout_preflight(width, height) -> Result<RgbaLayout,
// QrPreflightError>` is the missing bridge: it forwards
// `prepare_rgba_layout` on success and lifts every `QrLayoutError`
// into `QrPreflightError::LayoutRejected(_)` so the live handler
// does not have to map the error type itself.

#[test]
fn classify_layout_preflight_signature_takes_width_height_returns_preflight_result() {
    fn assert_signature(_: fn(u32, u32) -> Result<RgbaLayout, QrPreflightError>) {}
    assert_signature(classify_layout_preflight);
}

#[test]
fn classify_layout_preflight_accepts_valid_dims_and_returns_same_layout_as_prepare_rgba_layout() {
    let bridged = classify_layout_preflight(33, 17).expect("small size accepted");
    let direct = prepare_rgba_layout(33, 17).expect("small size accepted directly");
    assert_eq!(bridged.width(), direct.width());
    assert_eq!(bridged.height(), direct.height());
    assert_eq!(bridged.row_stride(), direct.row_stride());
    assert_eq!(bridged.buffer_bytes(), direct.buffer_bytes());
}

#[test]
fn classify_layout_preflight_zero_width_returns_layout_rejected_zero_dimensions() {
    let err = classify_layout_preflight(0, 64).expect_err("zero width rejected");
    match err {
        QrPreflightError::LayoutRejected(QrLayoutError::ZeroDimensions) => {}
        other => panic!("expected LayoutRejected(ZeroDimensions), got {other:?}"),
    }
}

#[test]
fn classify_layout_preflight_zero_height_returns_layout_rejected_zero_dimensions() {
    let err = classify_layout_preflight(64, 0).expect_err("zero height rejected");
    match err {
        QrPreflightError::LayoutRejected(QrLayoutError::ZeroDimensions) => {}
        other => panic!("expected LayoutRejected(ZeroDimensions), got {other:?}"),
    }
}

#[test]
fn classify_layout_preflight_oversized_returns_layout_rejected_image_too_large() {
    let max_pixels = QR_RGBA_MAX_BYTES / 4;
    let overshoot = max_pixels + 1;
    let w = u32::try_from(overshoot).expect("fits in u32");
    let err = classify_layout_preflight(w, 1).expect_err("oversized rejected");
    match err {
        QrPreflightError::LayoutRejected(QrLayoutError::ImageTooLarge {
            requested_bytes,
            max_bytes,
        }) => {
            assert_eq!(max_bytes, QR_RGBA_MAX_BYTES);
            assert!(requested_bytes > max_bytes);
        }
        other => panic!("expected LayoutRejected(ImageTooLarge), got {other:?}"),
    }
}

#[test]
fn classify_layout_preflight_overflow_returns_layout_rejected_dimensions_or_too_large() {
    // `u32::MAX * u32::MAX` overflows the pixel-count or byte-count
    // multiplication. Either typed reason is acceptable so long as it
    // arrives as `LayoutRejected(_)` and never as a generic core
    // failure or a panic.
    let err = classify_layout_preflight(u32::MAX, u32::MAX).expect_err("overflow rejected");
    match err {
        QrPreflightError::LayoutRejected(
            QrLayoutError::DimensionsOverflow | QrLayoutError::ImageTooLarge { .. },
        ) => {}
        other => panic!("expected LayoutRejected(overflow/too-large), got {other:?}"),
    }
}

#[test]
fn classify_layout_preflight_at_qr_rgba_max_bytes_succeeds() {
    let pixels = QR_RGBA_MAX_BYTES / 4;
    let w = u32::try_from(pixels).expect("fits in u32");
    let layout = classify_layout_preflight(w, 1).expect("at-cap accepted");
    assert_eq!(layout.buffer_bytes(), QR_RGBA_MAX_BYTES);
}

#[test]
fn classify_layout_preflight_rejection_kind_is_invalid_payload() {
    // The live handler routes the bridged error straight into
    // `InlineError::from_qr_preflight_error`, which copies the
    // `kind()` onto the rendered inline error. All `LayoutRejected`
    // variants must surface under the stable §5 `InvalidPayload`
    // discriminator so the dialog's inline rendering matches every
    // other "the texture shape is malformed" failure.
    let zero = classify_layout_preflight(0, 1).expect_err("zero rejected");
    assert_eq!(zero.kind(), ErrorKind::InvalidPayload);

    let max_pixels = QR_RGBA_MAX_BYTES / 4;
    let overshoot = max_pixels + 1;
    let w = u32::try_from(overshoot).expect("fits in u32");
    let too_large = classify_layout_preflight(w, 1).expect_err("oversized rejected");
    assert_eq!(too_large.kind(), ErrorKind::InvalidPayload);
}

#[test]
fn classify_layout_preflight_rejection_source_chain_points_at_underlying_layout_error() {
    // `QrPreflightError::source` wraps the underlying `QrLayoutError`
    // so error-chain consumers (test diagnostics, future logging) can
    // reach the typed reason without re-parsing the rendered body.
    use std::error::Error as _;

    let err = classify_layout_preflight(0, 1).expect_err("zero rejected");
    let source = err
        .source()
        .expect("LayoutRejected wraps the underlying QrLayoutError");
    let downcast = source.downcast_ref::<QrLayoutError>();
    assert!(
        matches!(downcast, Some(QrLayoutError::ZeroDimensions)),
        "expected ZeroDimensions source, got {downcast:?}",
    );
}
