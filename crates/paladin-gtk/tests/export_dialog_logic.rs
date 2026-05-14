// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic export-dialog tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/export_dialog_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Overwrite gate resets when the destination or format changes.
//! * Plaintext-warning gate resets when the destination or format
//!   changes; the rendered text matches
//!   [`paladin_core::format_plaintext_export_warning`] verbatim.
//! * Encrypted twice-confirm match accepts; mismatch rejects with
//!   `invalid_passphrase` (`reason: "confirmation_mismatch"`).
//! * Empty encrypted passphrase rejects with `invalid_passphrase`
//!   (`reason: "zero_length"`).
//! * Destination or format change after passphrase entry clears the
//!   password rows and re-prompts.
//! * Export writer errors (`io_error`, `save_not_committed`,
//!   `save_durability_unconfirmed`) stay inline; export does not
//!   mutate the vault, so no rollback path runs.
//!
//! The module under test (`paladin_gtk::export_dialog`) is the pure-
//! logic state machine the GTK `ExportDialog` shadows. It owns no
//! widgets; the widget layer drives the gate-reset and twice-confirm
//! helpers on user input and `classify_export_result` on the writer
//! outcome of `paladin_core::write_secret_file_atomic` wrapping the
//! `paladin_core::export::otpauth_list` / `paladin_core::export::encrypted`
//! payload.

use std::path::{Path, PathBuf};

use paladin_core::{format_plaintext_export_warning, ErrorKind, PaladinError};

use paladin_gtk::export_dialog::{
    classify_export_result, overwrite_gate_needs_reset, passphrase_needs_reset,
    plaintext_warning_body, plaintext_warning_needs_reset, prepare_encrypted_export,
    ExportFormatChoice, ExportOutcome, InlineError, InlineWarning, SubmitRejection,
};
use secrecy::ExposeSecret;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dest_a() -> PathBuf {
    PathBuf::from("/home/u/exports/vault.json")
}

fn dest_b() -> PathBuf {
    PathBuf::from("/home/u/exports/other.json")
}

fn save_not_committed_no_backup() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    }
}

fn save_not_committed_with_backup() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: true,
        backup_path: Some(PathBuf::from("/home/u/exports/vault.json.bak")),
    }
}

fn io_error_export() -> PaladinError {
    PaladinError::IoError {
        operation: "write_secret_file_tmp",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    }
}

fn assert_inline_with_kind(err: PaladinError, expected: ErrorKind) {
    let rendered = err.to_string();
    let outcome = classify_export_result(Err(err));
    let ExportOutcome::Inline(inline) = outcome else {
        panic!("expected Inline({expected:?}), got {outcome:?}");
    };
    assert_eq!(inline.kind, expected);
    assert_eq!(inline.rendered, rendered);
}

// ---------------------------------------------------------------------------
// ExportFormatChoice — gate predicates by format
// ---------------------------------------------------------------------------

#[test]
fn format_choice_plaintext_requires_plaintext_warning_only() {
    assert!(ExportFormatChoice::PlaintextOtpauth.requires_plaintext_warning());
    assert!(!ExportFormatChoice::PlaintextOtpauth.requires_passphrase());
}

#[test]
fn format_choice_encrypted_requires_passphrase_only() {
    assert!(ExportFormatChoice::EncryptedPaladin.requires_passphrase());
    assert!(!ExportFormatChoice::EncryptedPaladin.requires_plaintext_warning());
}

// ---------------------------------------------------------------------------
// Overwrite gate — resets when destination or format changes
// ---------------------------------------------------------------------------

#[test]
fn overwrite_gate_unchanged_when_destination_and_format_match() {
    let prev = dest_a();
    let new = dest_a();
    assert!(!overwrite_gate_needs_reset(
        &prev,
        ExportFormatChoice::PlaintextOtpauth,
        &new,
        ExportFormatChoice::PlaintextOtpauth,
    ));
}

#[test]
fn overwrite_gate_resets_when_destination_changes() {
    assert!(overwrite_gate_needs_reset(
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
        &dest_b(),
        ExportFormatChoice::PlaintextOtpauth,
    ));
}

#[test]
fn overwrite_gate_resets_when_format_changes() {
    assert!(overwrite_gate_needs_reset(
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
        &dest_a(),
        ExportFormatChoice::EncryptedPaladin,
    ));
}

#[test]
fn overwrite_gate_resets_when_both_change() {
    assert!(overwrite_gate_needs_reset(
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
        &dest_b(),
        ExportFormatChoice::EncryptedPaladin,
    ));
}

// ---------------------------------------------------------------------------
// Plaintext-warning gate — same reset semantics as overwrite gate
// ---------------------------------------------------------------------------

#[test]
fn plaintext_warning_gate_unchanged_when_destination_and_format_match() {
    assert!(!plaintext_warning_needs_reset(
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
    ));
}

#[test]
fn plaintext_warning_gate_resets_when_destination_changes() {
    assert!(plaintext_warning_needs_reset(
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
        &dest_b(),
        ExportFormatChoice::PlaintextOtpauth,
    ));
}

#[test]
fn plaintext_warning_gate_resets_when_format_changes() {
    assert!(plaintext_warning_needs_reset(
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
        &dest_a(),
        ExportFormatChoice::EncryptedPaladin,
    ));
}

// ---------------------------------------------------------------------------
// Plaintext-warning text — matches paladin_core verbatim
// ---------------------------------------------------------------------------

#[test]
fn plaintext_warning_body_matches_paladin_core_verbatim() {
    assert_eq!(plaintext_warning_body(), format_plaintext_export_warning());
}

// ---------------------------------------------------------------------------
// prepare_encrypted_export — twice-confirm + zero-length validation
// ---------------------------------------------------------------------------

#[test]
fn prepare_encrypted_export_match_returns_encryption_options() {
    let opts = prepare_encrypted_export("hunter2", "hunter2")
        .expect("matching non-empty pair must accept");
    assert_eq!(opts.passphrase.expose_secret(), "hunter2");
}

#[test]
fn prepare_encrypted_export_mismatch_rejects_with_confirmation_mismatch() {
    let err =
        prepare_encrypted_export("hunter2", "hunter3").expect_err("mismatched pair must reject");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);
    assert_eq!(err.error_kind(), ErrorKind::InvalidPassphrase);
    assert_eq!(err.reason(), "confirmation_mismatch");
}

#[test]
fn prepare_encrypted_export_one_empty_rejects_with_confirmation_mismatch() {
    // Either-empty pair is a mismatch: the user has typed in only one
    // of the two rows. Mirrors `init_dialog::SubmitRejection`'s
    // distinction between "the two fields differ" and "both are empty".
    let err = prepare_encrypted_export("hunter2", "")
        .expect_err("passphrase set but confirm empty must reject");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);

    let err = prepare_encrypted_export("", "hunter2")
        .expect_err("passphrase empty but confirm set must reject");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);
}

#[test]
fn prepare_encrypted_export_both_empty_rejects_with_zero_length() {
    let err =
        prepare_encrypted_export("", "").expect_err("zero-length encrypted passphrase must reject");
    assert_eq!(err, SubmitRejection::ZeroLength);
    assert_eq!(err.error_kind(), ErrorKind::InvalidPassphrase);
    assert_eq!(err.reason(), "zero_length");
}

#[test]
fn submit_rejection_always_maps_to_invalid_passphrase_kind() {
    // §5 contract: every twice-confirm rejection surfaces as
    // `invalid_passphrase` regardless of `reason`.
    assert_eq!(
        SubmitRejection::ConfirmationMismatch.error_kind(),
        ErrorKind::InvalidPassphrase
    );
    assert_eq!(
        SubmitRejection::ZeroLength.error_kind(),
        ErrorKind::InvalidPassphrase
    );
}

// ---------------------------------------------------------------------------
// passphrase_needs_reset — destination / format change clears the row
// ---------------------------------------------------------------------------

#[test]
fn passphrase_unchanged_when_destination_and_format_match() {
    assert!(!passphrase_needs_reset(
        &dest_a(),
        ExportFormatChoice::EncryptedPaladin,
        &dest_a(),
        ExportFormatChoice::EncryptedPaladin,
    ));
}

#[test]
fn passphrase_clears_on_destination_change() {
    assert!(passphrase_needs_reset(
        &dest_a(),
        ExportFormatChoice::EncryptedPaladin,
        &dest_b(),
        ExportFormatChoice::EncryptedPaladin,
    ));
}

#[test]
fn passphrase_clears_on_format_change_off_encrypted() {
    // Switching off the encrypted format wipes the row even if the
    // destination is unchanged.
    assert!(passphrase_needs_reset(
        &dest_a(),
        ExportFormatChoice::EncryptedPaladin,
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
    ));
}

#[test]
fn passphrase_clears_on_format_change_onto_encrypted() {
    // Switching onto the encrypted format also restarts the prompt:
    // any row content that survived the prior session is invalid for
    // the new mode.
    assert!(passphrase_needs_reset(
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
        &dest_a(),
        ExportFormatChoice::EncryptedPaladin,
    ));
}

// ---------------------------------------------------------------------------
// classify_export_result — writer errors stay inline; no rollback path
// ---------------------------------------------------------------------------

#[test]
fn classify_export_result_success_returns_success() {
    let outcome = classify_export_result(Ok(()));
    assert!(matches!(outcome, ExportOutcome::Success));
}

#[test]
fn classify_export_result_save_not_committed_no_backup_stays_inline() {
    let err = save_not_committed_no_backup();
    let rendered = err.to_string();
    let outcome = classify_export_result(Err(err));
    let ExportOutcome::Inline(inline) = outcome else {
        panic!("expected Inline, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert_eq!(inline.rendered, rendered);
}

#[test]
fn classify_export_result_save_not_committed_with_backup_stays_inline() {
    // The exporter writer does not rotate `.bak`, so `backup_path`
    // is irrelevant to the outcome routing — but we exercise the
    // variant to pin the contract.
    let err = save_not_committed_with_backup();
    let rendered = err.to_string();
    let outcome = classify_export_result(Err(err));
    let ExportOutcome::Inline(inline) = outcome else {
        panic!("expected Inline, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
    assert_eq!(inline.rendered, rendered);
}

#[test]
fn classify_export_result_save_durability_unconfirmed_surfaces_warning() {
    // The export file is on disk; only the parent-directory `fsync`
    // failed. The dialog surfaces the warning so the user can decide
    // whether to retry, but the file itself is not removed.
    let outcome = classify_export_result(Err(PaladinError::SaveDurabilityUnconfirmed));
    let ExportOutcome::DurabilityWarning(warning) = outcome else {
        panic!("expected DurabilityWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert_eq!(
        warning.rendered,
        PaladinError::SaveDurabilityUnconfirmed.to_string()
    );
}

#[test]
fn classify_export_result_io_error_stays_inline() {
    assert_inline_with_kind(io_error_export(), ErrorKind::IoError);
}

// ---------------------------------------------------------------------------
// InlineError / InlineWarning — Display body comes from PaladinError
// ---------------------------------------------------------------------------

#[test]
fn inline_error_renders_through_paladin_error_display() {
    let err = io_error_export();
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::IoError);
    assert_eq!(inline.rendered, err.to_string());
}

#[test]
fn inline_warning_renders_through_paladin_error_display() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let warning = InlineWarning::from_error(&err);
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert_eq!(warning.rendered, err.to_string());
}

#[test]
fn inline_error_clones_freely_for_reactive_state() {
    let err = io_error_export();
    let inline = InlineError::from_error(&err);
    let cloned = inline.clone();
    assert_eq!(cloned.kind, inline.kind);
    assert_eq!(cloned.rendered, inline.rendered);
}

#[test]
fn inline_warning_clones_freely_for_reactive_state() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let warning = InlineWarning::from_error(&err);
    let cloned = warning.clone();
    assert_eq!(cloned.kind, warning.kind);
    assert_eq!(cloned.rendered, warning.rendered);
}

// ---------------------------------------------------------------------------
// Path equality semantics — the helpers do not canonicalize
// ---------------------------------------------------------------------------

#[test]
fn gates_treat_paths_by_raw_equality_no_canonicalize() {
    // The dialog does not canonicalize destination paths before
    // comparing — `./vault.json` and `vault.json` look different here
    // even though they may resolve identically. The widget layer
    // owns canonicalization (via the file picker); the pure-logic
    // helper sticks to raw `Path` equality so it remains
    // filesystem-free for tests.
    let prev: &Path = Path::new("./vault.json");
    let new: &Path = Path::new("vault.json");
    assert!(overwrite_gate_needs_reset(
        prev,
        ExportFormatChoice::PlaintextOtpauth,
        new,
        ExportFormatChoice::PlaintextOtpauth,
    ));
    assert!(plaintext_warning_needs_reset(
        prev,
        ExportFormatChoice::PlaintextOtpauth,
        new,
        ExportFormatChoice::PlaintextOtpauth,
    ));
    assert!(passphrase_needs_reset(
        prev,
        ExportFormatChoice::EncryptedPaladin,
        new,
        ExportFormatChoice::EncryptedPaladin,
    ));
}
