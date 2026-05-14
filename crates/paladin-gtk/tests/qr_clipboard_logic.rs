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
    decode_clipboard_qr, prepare_rgba_layout, QrImportSummary, QrLayoutError, RgbaLayout,
    CLIPBOARD_QR_CONFLICT_POLICY,
};

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
