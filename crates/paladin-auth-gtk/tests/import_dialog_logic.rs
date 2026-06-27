// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic import-dialog tests for `paladin-auth-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/import_dialog_logic.rs`"
//! checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Format-selector routing (auto-detect / explicit `otpauth` /
//!   `aegis` / `paladin-auth` / `qr`) reaches the correct
//!   `paladin_auth_core::import::from_file` invocation via
//!   [`paladin_auth_core::ImportOptions`].
//! * On-conflict policy (`skip` / `replace` / `append`) threads
//!   through [`paladin_auth_core::ImportConflict`] and is reflected in
//!   the merge outcome.
//! * `paladin_auth_core::classify_paladin_auth_import_precheck` routing for
//!   `PromptForPassphrase`, `Reject(err)`, and `NoPrompt` covers
//!   encrypted Paladin Auth, plaintext Paladin Auth, malformed / unsupported
//!   Paladin Auth headers, missing files, non-Paladin Auth content, and
//!   forced-format mismatches.
//! * Bundle-passphrase row clears when the source path or forced
//!   format changes after entry, and the probe / prompt flow
//!   restarts.
//! * Post-merge counts (`imported` / `skipped` / `replaced` /
//!   `appended` / `warnings`) map to inline display.
//! * Importer errors stay inline and never mutate vault state:
//!   `unsupported_import_format`, `unsupported_plaintext_vault`,
//!   `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
//!   `validation_error`, `no_entries_to_import`, `decrypt_failed`,
//!   `invalid_header`, `invalid_payload`,
//!   `unsupported_format_version`, `kdf_params_out_of_bounds`,
//!   `io_error`.
//! * `save_not_committed` after a successful merge restores the
//!   `Vault::mutate_and_save` snapshot (the dialog stays inline);
//!   `save_durability_unconfirmed` keeps the merged accounts and
//!   surfaces the warning inline.
//!
//! The module under test (`paladin_auth_gtk::import_dialog`) is the
//! pure-logic state machine the GTK `ImportDialog` shadows. It owns
//! no widgets; the widget layer drives the precheck / format /
//! conflict helpers on user input and `classify_merge_result` on
//! the worker outcome of
//! `Vault::mutate_and_save(|v| { from_file(...) → v.import_accounts(...) })`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use paladin_auth_core::{
    classify_paladin_auth_import_precheck, AccountId, ErrorKind, ImportConflict, ImportFormat,
    ImportReport, ImportWarning, PaladinAuthError, PaladinAuthImportPrecheck, ValidationWarning,
};

use paladin_auth_gtk::import_dialog::{
    apply_msg, build_import_options, classify_merge_result, classify_precheck,
    compose_counts_panel_appended_label, compose_counts_panel_imported_label,
    compose_counts_panel_replaced_label, compose_counts_panel_skipped_label,
    compose_counts_panel_visible, compose_counts_panel_warnings_label, compose_inline_error_body,
    compose_inline_error_revealed, compose_inline_warning_body, compose_inline_warning_revealed,
    compose_passphrase_row_visible, compose_source_row_subtitle, compose_submit_button_sensitive,
    compose_submit_outcome, conflict_choice_from_index, format_choice_from_index,
    format_import_dialog_cancel_label, format_import_dialog_choose_source_label,
    format_import_dialog_conflict_labels, format_import_dialog_conflict_row_title,
    format_import_dialog_counts_group_title, format_import_dialog_dismiss_label,
    format_import_dialog_format_labels, format_import_dialog_format_row_title,
    format_import_dialog_import_label, format_import_dialog_options_group_title,
    format_import_dialog_passphrase_row_title, format_import_dialog_source_group_title,
    format_import_dialog_source_row_placeholder, format_import_dialog_source_row_title,
    format_import_dialog_subtitle, format_import_dialog_title, passphrase_needs_reset,
    run_import_worker, ConflictChoice, FormatChoice, ImportDialogMsg, ImportDialogOutput,
    ImportDialogState, ImportSubmitPayload, ImportWorkerCompletion, ImportWorkerInput, InlineError,
    InlineWarning, MergeOutcome, MergeSummary, PrecheckOutcome, SubmitOutcome,
};
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn secure_tempdir() -> TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    dir
}

fn make_paladin_auth_bundle(dir: &TempDir, name: &str, passphrase: &str) -> PathBuf {
    use paladin_auth_core::{Argon2Params, EncryptionOptions, Store, VaultInit};

    let path = dir.path().join(name);
    let opts = EncryptionOptions::with_params(
        SecretString::from(passphrase.to_string()),
        Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        },
    )
    .expect("encryption options");
    let (vault, store) = Store::create(&path, VaultInit::Encrypted(opts)).expect("create vault");
    vault.save(&store).expect("save vault");
    path
}

fn make_plaintext_paladin_auth_bundle(dir: &TempDir, name: &str) -> PathBuf {
    use paladin_auth_core::{Store, VaultInit};
    let path = dir.path().join(name);
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("save plaintext");
    path
}

fn save_not_committed_no_backup() -> PaladinAuthError {
    PaladinAuthError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    }
}

fn save_not_committed_with_backup() -> PaladinAuthError {
    PaladinAuthError::SaveNotCommitted {
        committed: true,
        backup_path: Some(PathBuf::from("/tmp/vault.bin.bak")),
    }
}

fn import_report_with_counts(
    imported: usize,
    skipped: usize,
    replaced: usize,
    appended: usize,
) -> ImportReport {
    let accounts: Vec<AccountId> = (0..(imported + replaced + appended))
        .map(|_| AccountId::new())
        .collect();
    ImportReport {
        imported,
        skipped,
        replaced,
        appended,
        accounts,
        warnings: Vec::new(),
    }
}

fn import_report_with_warnings(warnings: usize) -> ImportReport {
    let ws: Vec<ImportWarning> = (0..warnings)
        .map(|i| ImportWarning {
            source_index: i,
            warning: ValidationWarning::ShortSecret {
                decoded_len: 5,
                recommended_min: 16,
            },
        })
        .collect();
    ImportReport {
        imported: 1,
        skipped: 0,
        replaced: 0,
        appended: 0,
        accounts: vec![AccountId::new()],
        warnings: ws,
    }
}

// ---------------------------------------------------------------------------
// FormatChoice — UI selector → forced ImportFormat for paladin_auth_core::import
// ---------------------------------------------------------------------------

#[test]
fn format_choice_auto_detect_yields_no_forced_format() {
    assert_eq!(FormatChoice::AutoDetect.forced_format(), None);
}

#[test]
fn format_choice_otpauth_forces_otpauth_format() {
    assert_eq!(
        FormatChoice::Otpauth.forced_format(),
        Some(ImportFormat::Otpauth)
    );
}

#[test]
fn format_choice_aegis_forces_aegis_format() {
    assert_eq!(
        FormatChoice::Aegis.forced_format(),
        Some(ImportFormat::Aegis)
    );
}

#[test]
fn format_choice_paladin_auth_forces_paladin_auth_format() {
    assert_eq!(
        FormatChoice::PaladinAuth.forced_format(),
        Some(ImportFormat::PaladinAuth)
    );
}

#[test]
fn format_choice_qr_forces_qr_image_format() {
    assert_eq!(
        FormatChoice::Qr.forced_format(),
        Some(ImportFormat::QrImage)
    );
}

// ---------------------------------------------------------------------------
// ConflictChoice — UI selector → Vault::import_accounts policy
// ---------------------------------------------------------------------------

#[test]
fn conflict_choice_skip_yields_import_conflict_skip() {
    assert_eq!(ConflictChoice::Skip.into_policy(), ImportConflict::Skip);
}

#[test]
fn conflict_choice_replace_yields_import_conflict_replace() {
    assert_eq!(
        ConflictChoice::Replace.into_policy(),
        ImportConflict::Replace
    );
}

#[test]
fn conflict_choice_append_yields_import_conflict_append() {
    assert_eq!(ConflictChoice::Append.into_policy(), ImportConflict::Append);
}

// ---------------------------------------------------------------------------
// build_import_options — format + passphrase thread through verbatim
// ---------------------------------------------------------------------------

#[test]
fn build_import_options_auto_detect_no_passphrase() {
    let opts = build_import_options(FormatChoice::AutoDetect, None);
    assert_eq!(opts.format, None);
    assert!(opts.paladin_auth_passphrase.is_none());
}

#[test]
fn build_import_options_otpauth_threads_format() {
    let opts = build_import_options(FormatChoice::Otpauth, None);
    assert_eq!(opts.format, Some(ImportFormat::Otpauth));
}

#[test]
fn build_import_options_aegis_threads_format() {
    let opts = build_import_options(FormatChoice::Aegis, None);
    assert_eq!(opts.format, Some(ImportFormat::Aegis));
}

#[test]
fn build_import_options_qr_threads_format() {
    let opts = build_import_options(FormatChoice::Qr, None);
    assert_eq!(opts.format, Some(ImportFormat::QrImage));
}

#[test]
fn build_import_options_paladin_auth_carries_passphrase_verbatim() {
    let pp = SecretString::from("hunter2".to_string());
    let opts = build_import_options(FormatChoice::PaladinAuth, Some(pp));
    assert_eq!(opts.format, Some(ImportFormat::PaladinAuth));
    let returned = opts.paladin_auth_passphrase.expect("passphrase preserved");
    assert_eq!(returned.expose_secret(), "hunter2");
}

#[test]
fn build_import_options_non_paladin_auth_with_passphrase_threads_through() {
    // The facade ignores `paladin_auth_passphrase` for non-paladin-auth formats
    // but the dialog still surfaces whatever it captured; the helper
    // doesn't second-guess the caller.
    let pp = SecretString::from("ignored".to_string());
    let opts = build_import_options(FormatChoice::Otpauth, Some(pp));
    assert_eq!(opts.format, Some(ImportFormat::Otpauth));
    assert!(opts.paladin_auth_passphrase.is_some());
}

// ---------------------------------------------------------------------------
// classify_precheck — PaladinAuthImportPrecheck → routing decision
// ---------------------------------------------------------------------------

#[test]
fn classify_precheck_no_prompt_proceeds() {
    let outcome = classify_precheck(PaladinAuthImportPrecheck::NoPrompt);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn classify_precheck_prompt_for_passphrase_routes_to_prompt() {
    let outcome = classify_precheck(PaladinAuthImportPrecheck::PromptForPassphrase);
    assert!(matches!(outcome, PrecheckOutcome::PromptForPassphrase));
}

#[test]
fn classify_precheck_reject_unsupported_plaintext_vault_inlines_typed_error() {
    let probe = PaladinAuthImportPrecheck::Reject(PaladinAuthError::UnsupportedPlaintextVault);
    let outcome = classify_precheck(probe);
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::UnsupportedPlaintextVault);
}

#[test]
fn classify_precheck_reject_invalid_header_inlines_typed_error() {
    let probe = PaladinAuthImportPrecheck::Reject(PaladinAuthError::InvalidHeader);
    let outcome = classify_precheck(probe);
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::InvalidHeader);
}

#[test]
fn classify_precheck_reject_unsupported_format_version_inlines_typed_error() {
    let probe = PaladinAuthImportPrecheck::Reject(PaladinAuthError::UnsupportedFormatVersion {
        format_ver: 99,
    });
    let outcome = classify_precheck(probe);
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::UnsupportedFormatVersion);
}

// ---------------------------------------------------------------------------
// classify_paladin_auth_import_precheck → classify_precheck integration
// ---------------------------------------------------------------------------

#[test]
fn precheck_integration_encrypted_paladin_auth_routes_to_prompt() {
    let dir = secure_tempdir();
    let path = make_paladin_auth_bundle(&dir, "vault.bin", "hunter2");
    let probe = classify_paladin_auth_import_precheck(&path, None);
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::PromptForPassphrase));
}

#[test]
fn precheck_integration_plaintext_paladin_auth_routes_to_inline_unsupported_plaintext_vault() {
    let dir = secure_tempdir();
    let path = make_plaintext_paladin_auth_bundle(&dir, "vault.bin");
    let probe = classify_paladin_auth_import_precheck(&path, None);
    let outcome = classify_precheck(probe);
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::UnsupportedPlaintextVault);
}

#[test]
fn precheck_integration_missing_file_routes_to_proceed() {
    // Missing path under auto-detect maps to NoPrompt → Proceed; the
    // importer itself surfaces the read error so the dialog stays in
    // sync with the CLI / TUI flow.
    let dir = secure_tempdir();
    let path = dir.path().join("does-not-exist");
    let probe = classify_paladin_auth_import_precheck(&path, None);
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn precheck_integration_non_paladin_auth_bytes_route_to_proceed() {
    // Non-Paladin Auth content (e.g. JSON / otpauth text) under auto-
    // detect skips the prompt entirely.
    let dir = secure_tempdir();
    let path = dir.path().join("otpauth.json");
    fs::write(&path, b"otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP").unwrap();
    let probe = classify_paladin_auth_import_precheck(&path, None);
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn precheck_integration_malformed_paladin_auth_header_routes_to_inline_invalid_header() {
    // PALAUTH\0 magic followed by gibberish triggers Reject(InvalidHeader).
    let dir = secure_tempdir();
    let path = dir.path().join("malformed.bin");
    let mut bytes = b"PALAUTH\0".to_vec();
    bytes.extend_from_slice(&[0xFF; 8]);
    fs::write(&path, &bytes).unwrap();
    let probe = classify_paladin_auth_import_precheck(&path, None);
    let outcome = classify_precheck(probe);
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    // The Reject is one of the header-stage errors; either InvalidHeader
    // or UnsupportedFormatVersion are valid here depending on the bytes.
    assert!(matches!(
        inline.kind,
        ErrorKind::InvalidHeader | ErrorKind::UnsupportedFormatVersion
    ));
}

#[test]
fn precheck_integration_forced_otpauth_routes_to_proceed_without_probing() {
    // Forced non-paladin-auth format skips the probe entirely; even an
    // encrypted-Paladin Auth file under a forced otpauth setting yields
    // NoPrompt → Proceed so from_file can return the typed
    // unsupported_import_format mismatch.
    let dir = secure_tempdir();
    let path = make_paladin_auth_bundle(&dir, "vault.bin", "hunter2");
    let probe = classify_paladin_auth_import_precheck(&path, Some(ImportFormat::Otpauth));
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn precheck_integration_forced_aegis_routes_to_proceed_without_probing() {
    let dir = secure_tempdir();
    let path = dir.path().join("does-not-exist");
    let probe = classify_paladin_auth_import_precheck(&path, Some(ImportFormat::Aegis));
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn precheck_integration_forced_qr_routes_to_proceed_without_probing() {
    let dir = secure_tempdir();
    let path = dir.path().join("does-not-exist");
    let probe = classify_paladin_auth_import_precheck(&path, Some(ImportFormat::QrImage));
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

// ---------------------------------------------------------------------------
// passphrase_needs_reset — path or forced format change clears the row
// ---------------------------------------------------------------------------

#[test]
fn passphrase_needs_reset_returns_false_when_nothing_changed() {
    let p = PathBuf::from("/tmp/vault.bin");
    assert!(!passphrase_needs_reset(
        &p,
        Some(ImportFormat::PaladinAuth),
        &p,
        Some(ImportFormat::PaladinAuth)
    ));
}

#[test]
fn passphrase_needs_reset_returns_true_when_path_changes() {
    let prev = PathBuf::from("/tmp/old.bin");
    let new = PathBuf::from("/tmp/new.bin");
    assert!(passphrase_needs_reset(
        &prev,
        Some(ImportFormat::PaladinAuth),
        &new,
        Some(ImportFormat::PaladinAuth)
    ));
}

#[test]
fn passphrase_needs_reset_returns_true_when_forced_format_changes() {
    let p = PathBuf::from("/tmp/vault.bin");
    assert!(passphrase_needs_reset(
        &p,
        Some(ImportFormat::PaladinAuth),
        &p,
        None
    ));
}

#[test]
fn passphrase_needs_reset_returns_true_when_format_flips_to_paladin_auth() {
    // Switching from Aegis → Paladin Auth requires a fresh probe and
    // passphrase prompt; the prior row must clear even though the
    // path is unchanged.
    let p = PathBuf::from("/tmp/vault.bin");
    assert!(passphrase_needs_reset(
        &p,
        Some(ImportFormat::Aegis),
        &p,
        Some(ImportFormat::PaladinAuth)
    ));
}

#[test]
fn passphrase_needs_reset_returns_true_when_auto_detect_flips_to_explicit_match() {
    // Even when the explicit choice resolves to the same format as
    // auto-detect would, we still treat it as a change so the probe
    // re-runs (the helper does not pre-detect for us).
    let p = PathBuf::from("/tmp/vault.bin");
    assert!(passphrase_needs_reset(
        &p,
        None,
        &p,
        Some(ImportFormat::PaladinAuth)
    ));
}

// ---------------------------------------------------------------------------
// MergeSummary — projection from ImportReport for the counts panel
// ---------------------------------------------------------------------------

#[test]
fn merge_summary_from_report_threads_all_counts() {
    let report = import_report_with_counts(3, 1, 2, 4);
    let summary = MergeSummary::from_report(&report);
    assert_eq!(summary.imported, 3);
    assert_eq!(summary.skipped, 1);
    assert_eq!(summary.replaced, 2);
    assert_eq!(summary.appended, 4);
    assert_eq!(summary.warnings, 0);
}

#[test]
fn merge_summary_from_report_threads_warning_count() {
    let report = import_report_with_warnings(3);
    let summary = MergeSummary::from_report(&report);
    assert_eq!(summary.imported, 1);
    assert_eq!(summary.warnings, 3);
}

// ---------------------------------------------------------------------------
// classify_merge_result — Vault::mutate_and_save outcome → dialog routing
// ---------------------------------------------------------------------------

#[test]
fn classify_merge_result_success_renders_counts_panel() {
    let report = import_report_with_counts(2, 0, 1, 1);
    let outcome = classify_merge_result(Ok(report));
    let MergeOutcome::Success(summary) = outcome else {
        panic!("expected Success, got {outcome:?}");
    };
    assert_eq!(summary.imported, 2);
    assert_eq!(summary.replaced, 1);
    assert_eq!(summary.appended, 1);
}

#[test]
fn classify_merge_result_save_not_committed_routes_to_not_committed() {
    let outcome = classify_merge_result(Err(save_not_committed_no_backup()));
    let MergeOutcome::NotCommitted(inline) = outcome else {
        panic!("expected NotCommitted, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
}

#[test]
fn classify_merge_result_save_not_committed_with_backup_path_still_routes_to_not_committed() {
    let outcome = classify_merge_result(Err(save_not_committed_with_backup()));
    let MergeOutcome::NotCommitted(inline) = outcome else {
        panic!("expected NotCommitted, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
}

#[test]
fn classify_merge_result_save_durability_unconfirmed_routes_to_durability_warning() {
    let outcome = classify_merge_result(Err(PaladinAuthError::SaveDurabilityUnconfirmed));
    let MergeOutcome::DurabilityWarning(warning) = outcome else {
        panic!("expected DurabilityWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
}

// ---------------------------------------------------------------------------
// classify_merge_result — every importer / import_accounts error stays inline
// ---------------------------------------------------------------------------

fn assert_inline_with_kind(err: PaladinAuthError, expected: ErrorKind) {
    let outcome = classify_merge_result(Err(err));
    let MergeOutcome::Inline(inline) = outcome else {
        panic!("expected Inline for {expected:?}, got {outcome:?}");
    };
    assert_eq!(inline.kind, expected);
}

#[test]
fn classify_merge_result_unsupported_import_format_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::UnsupportedImportFormat {
            format: "unknown".to_string(),
        },
        ErrorKind::UnsupportedImportFormat,
    );
}

#[test]
fn classify_merge_result_unsupported_plaintext_vault_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::UnsupportedPlaintextVault,
        ErrorKind::UnsupportedPlaintextVault,
    );
}

#[test]
fn classify_merge_result_unsupported_encrypted_aegis_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::UnsupportedEncryptedAegis,
        ErrorKind::UnsupportedEncryptedAegis,
    );
}

#[test]
fn classify_merge_result_unsupported_aegis_entry_type_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::UnsupportedAegisEntryType {
            source_index: 0,
            entry_type: "yubikey".to_string(),
        },
        ErrorKind::UnsupportedAegisEntryType,
    );
}

#[test]
fn classify_merge_result_validation_error_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::ValidationError {
            field: "secret",
            reason: "invalid_base32".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        },
        ErrorKind::ValidationError,
    );
}

#[test]
fn classify_merge_result_no_entries_to_import_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::NoEntriesToImport,
        ErrorKind::NoEntriesToImport,
    );
}

#[test]
fn classify_merge_result_decrypt_failed_stays_inline() {
    assert_inline_with_kind(PaladinAuthError::DecryptFailed, ErrorKind::DecryptFailed);
}

#[test]
fn classify_merge_result_invalid_header_stays_inline() {
    assert_inline_with_kind(PaladinAuthError::InvalidHeader, ErrorKind::InvalidHeader);
}

#[test]
fn classify_merge_result_invalid_payload_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::InvalidPayload {
            reason: "truncated",
        },
        ErrorKind::InvalidPayload,
    );
}

#[test]
fn classify_merge_result_unsupported_format_version_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::UnsupportedFormatVersion { format_ver: 99 },
        ErrorKind::UnsupportedFormatVersion,
    );
}

#[test]
fn classify_merge_result_kdf_params_out_of_bounds_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::KdfParamsOutOfBounds {
            m_kib: u32::MAX,
            t: 0,
            p: 0,
        },
        ErrorKind::KdfParamsOutOfBounds,
    );
}

#[test]
fn classify_merge_result_io_error_stays_inline() {
    assert_inline_with_kind(
        PaladinAuthError::IoError {
            operation: "read_import_file",
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        },
        ErrorKind::IoError,
    );
}

// ---------------------------------------------------------------------------
// InlineError / InlineWarning — Display body comes from PaladinAuthError
// ---------------------------------------------------------------------------

#[test]
fn inline_error_renders_through_paladin_auth_error_display() {
    let err = PaladinAuthError::DecryptFailed;
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::DecryptFailed);
    assert_eq!(inline.rendered, err.to_string());
}

#[test]
fn inline_warning_renders_through_paladin_auth_error_display() {
    let err = PaladinAuthError::SaveDurabilityUnconfirmed;
    let warning = InlineWarning::from_error(&err);
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert_eq!(warning.rendered, err.to_string());
}

// ---------------------------------------------------------------------------
// Path / format aliasing — passphrase row reset is path-aware
// ---------------------------------------------------------------------------

#[test]
fn passphrase_needs_reset_distinguishes_relative_paths() {
    // Both paths point at "vault.bin" but live in different parents
    // — the helper compares raw Path equality and treats them as
    // different.
    let a: &Path = Path::new("/tmp/a/vault.bin");
    let b: &Path = Path::new("/tmp/b/vault.bin");
    assert!(passphrase_needs_reset(
        a,
        Some(ImportFormat::PaladinAuth),
        b,
        Some(ImportFormat::PaladinAuth)
    ));
}

// ---------------------------------------------------------------------------
// ImportDialogComponent scaffold (Milestone 7 component-tree wiring)
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" entry
// "Relm4 component tree (Init / Unlock / List / Row / Add / Remove /
// Rename / Import / Export / Passphrase / Settings / StartupError)",
// `ImportDialogComponent` joins the eight already-mounted controllers
// (`AccountListComponent`, `StartupErrorComponent`,
// `InitDialogComponent`, `UnlockDialogComponent`,
// `EditDialogComponent`, `RemoveDialogComponent`,
// `AddAccountComponent`, `SettingsComponent`) with the same scaffold
// shape: `<Name>Init` / `<Name>Msg` / `<Name>Output` plus a
// `relm4::SimpleComponent` impl. The widget body (file picker +
// format selector + on-conflict selector + bundle-passphrase row)
// lands in follow-up commits alongside the live-apply behavior —
// this commit only adds the controller so the menu's Import… entry
// can mount it.

#[test]
fn import_dialog_init_round_trips_vault_path() {
    use paladin_auth_gtk::import_dialog::ImportDialogInit;

    let vault_path = PathBuf::from("/tmp/import-scaffold/vault.bin");
    let init = ImportDialogInit {
        vault_path: vault_path.clone(),
    };
    assert_eq!(init.vault_path, vault_path);
}

#[test]
fn import_dialog_output_close_is_constructible() {
    use paladin_auth_gtk::import_dialog::ImportDialogOutput;

    let output = ImportDialogOutput::Close;
    assert!(matches!(output, ImportDialogOutput::Close));
}

#[test]
fn import_dialog_component_input_and_output_match_dispatch_edges() {
    use paladin_auth_gtk::import_dialog::{
        ImportDialogComponent, ImportDialogMsg, ImportDialogOutput,
    };
    use relm4::SimpleComponent;

    // Compile-only assertion that ties `ImportDialogComponent` to its
    // associated `Input` / `Output` types so the AppModel dispatch
    // edges stay in lock-step with the component declaration. If a
    // future refactor renames `ImportDialogMsg` or
    // `ImportDialogOutput`, this test fails at compile time before
    // the AppModel build does.
    fn assert_types<C>()
    where
        C: SimpleComponent<Input = ImportDialogMsg, Output = ImportDialogOutput>,
    {
    }
    assert_types::<ImportDialogComponent>();
}

// ---------------------------------------------------------------------------
// ImportDialogState — accessors / mutators
// ---------------------------------------------------------------------------

fn proceed_state(path: PathBuf) -> ImportDialogState {
    // Build a state whose `compose_submit_outcome` is `Proceed`:
    // a source path picked, an auto-detect format, and a `NoPrompt`
    // precheck routing so no passphrase is needed.
    let mut state = ImportDialogState::new();
    state.set_source_path(path, PaladinAuthImportPrecheck::NoPrompt);
    state
}

#[test]
fn import_dialog_state_new_defaults_to_auto_detect_skip_no_source() {
    let state = ImportDialogState::new();
    assert!(state.source_path().is_none());
    assert_eq!(state.format(), FormatChoice::AutoDetect);
    assert_eq!(state.conflict(), ConflictChoice::Skip);
    assert!(state.precheck_outcome().is_none());
    assert!(!state.is_busy());
    assert!(state.inline_error().is_none());
    assert!(state.inline_warning().is_none());
    assert!(state.merge_summary().is_none());
    assert!(state.passphrase_text().is_empty());
    assert!(!state.passphrase_visible());
}

#[test]
fn import_dialog_state_set_source_path_updates_path_and_precheck() {
    let mut state = ImportDialogState::new();
    let path = PathBuf::from("/tmp/import-source.json");
    state.set_source_path(path.clone(), PaladinAuthImportPrecheck::NoPrompt);
    assert_eq!(state.source_path(), Some(path.as_path()));
    assert!(matches!(
        state.precheck_outcome(),
        Some(PrecheckOutcome::Proceed)
    ));
}

#[test]
fn import_dialog_state_set_source_path_with_prompt_routes_passphrase_visible() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/encrypted.bin"),
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    assert!(state.passphrase_visible());
    assert!(matches!(
        state.precheck_outcome(),
        Some(PrecheckOutcome::PromptForPassphrase)
    ));
}

#[test]
fn import_dialog_state_set_source_path_with_reject_stages_inline_error() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/plaintext.bin"),
        PaladinAuthImportPrecheck::Reject(PaladinAuthError::UnsupportedPlaintextVault),
    );
    let err = state.inline_error().expect("inline error staged");
    assert_eq!(err.kind, ErrorKind::UnsupportedPlaintextVault);
}

#[test]
fn import_dialog_state_set_format_changes_format_and_refreshes_precheck() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/source"),
        PaladinAuthImportPrecheck::NoPrompt,
    );
    state.set_format(
        FormatChoice::PaladinAuth,
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    assert_eq!(state.format(), FormatChoice::PaladinAuth);
    assert!(state.passphrase_visible());
}

#[test]
fn import_dialog_state_set_conflict_updates_policy() {
    let mut state = ImportDialogState::new();
    state.set_conflict(ConflictChoice::Replace);
    assert_eq!(state.conflict(), ConflictChoice::Replace);
}

#[test]
fn import_dialog_state_set_passphrase_shadows_buffer() {
    let mut state = ImportDialogState::new();
    state.set_passphrase("hunter2");
    assert_eq!(state.passphrase_text(), "hunter2");
}

#[test]
fn import_dialog_state_set_passphrase_dismisses_prior_inline_error() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/plaintext.bin"),
        PaladinAuthImportPrecheck::Reject(PaladinAuthError::UnsupportedPlaintextVault),
    );
    assert!(state.inline_error().is_some());
    state.set_passphrase("a");
    assert!(state.inline_error().is_none());
}

#[test]
fn import_dialog_state_set_source_path_clears_passphrase_on_path_change() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/first.bin"),
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    state.set_passphrase("hunter2");
    assert_eq!(state.passphrase_text(), "hunter2");
    state.set_source_path(
        PathBuf::from("/tmp/second.bin"),
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    assert_eq!(state.passphrase_text(), "");
}

#[test]
fn import_dialog_state_set_format_clears_passphrase_on_format_change() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/source.bin"),
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    state.set_passphrase("hunter2");
    state.set_format(FormatChoice::Otpauth, PaladinAuthImportPrecheck::NoPrompt);
    assert_eq!(state.passphrase_text(), "");
}

#[test]
fn import_dialog_state_set_busy_toggles_busy() {
    let mut state = ImportDialogState::new();
    state.set_busy(true);
    assert!(state.is_busy());
    state.set_busy(false);
    assert!(!state.is_busy());
}

// ---------------------------------------------------------------------------
// apply_merge_outcome — post-worker rendering routing
// ---------------------------------------------------------------------------

#[test]
fn apply_merge_outcome_success_parks_summary_clears_busy_and_errors() {
    let mut state = ImportDialogState::new();
    state.set_busy(true);
    let summary = MergeSummary::from_report(&import_report_with_counts(3, 1, 0, 0));
    state.apply_merge_outcome(MergeOutcome::Success(summary.clone()));
    assert!(!state.is_busy());
    assert_eq!(state.merge_summary(), Some(&summary));
    assert!(state.inline_error().is_none());
    assert!(state.inline_warning().is_none());
}

#[test]
fn apply_merge_outcome_durability_warning_parks_warning_and_clears_summary() {
    let mut state = ImportDialogState::new();
    state.set_busy(true);
    let warning = InlineWarning::from_error(&PaladinAuthError::SaveDurabilityUnconfirmed);
    state.apply_merge_outcome(MergeOutcome::DurabilityWarning(warning.clone()));
    assert!(!state.is_busy());
    assert_eq!(state.inline_warning().map(|w| w.kind), Some(warning.kind));
    assert!(state.merge_summary().is_none());
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_merge_outcome_not_committed_parks_inline_error() {
    let mut state = ImportDialogState::new();
    state.set_busy(true);
    let err = InlineError::from_error(&save_not_committed_no_backup());
    state.apply_merge_outcome(MergeOutcome::NotCommitted(err.clone()));
    assert!(!state.is_busy());
    assert_eq!(
        state.inline_error().map(|e| e.kind),
        Some(ErrorKind::SaveNotCommitted)
    );
}

#[test]
fn apply_merge_outcome_inline_parks_inline_error() {
    let mut state = ImportDialogState::new();
    state.set_busy(true);
    let err = InlineError::from_error(&PaladinAuthError::DecryptFailed);
    state.apply_merge_outcome(MergeOutcome::Inline(err.clone()));
    assert!(!state.is_busy());
    assert_eq!(
        state.inline_error().map(|e| e.kind),
        Some(ErrorKind::DecryptFailed)
    );
}

#[test]
fn dismiss_counts_clears_summary() {
    let mut state = ImportDialogState::new();
    state.apply_merge_outcome(MergeOutcome::Success(MergeSummary::from_report(
        &import_report_with_counts(1, 0, 0, 0),
    )));
    state.dismiss_counts();
    assert!(state.merge_summary().is_none());
}

// ---------------------------------------------------------------------------
// compose_submit_outcome — Submit-button routing
// ---------------------------------------------------------------------------

#[test]
fn compose_submit_outcome_needs_source_when_path_unset() {
    let state = ImportDialogState::new();
    assert!(matches!(
        compose_submit_outcome(&state),
        SubmitOutcome::NeedsSourcePath
    ));
}

#[test]
fn compose_submit_outcome_proceed_with_no_prompt() {
    let state = proceed_state(PathBuf::from("/tmp/source.json"));
    let outcome = compose_submit_outcome(&state);
    let SubmitOutcome::Proceed(payload) = outcome else {
        panic!("expected Proceed");
    };
    assert_eq!(payload.source_path, PathBuf::from("/tmp/source.json"));
    assert_eq!(payload.options.format, None);
    assert!(payload.options.paladin_auth_passphrase.is_none());
    assert_eq!(payload.conflict, ImportConflict::Skip);
}

#[test]
fn compose_submit_outcome_awaiting_passphrase_when_prompt_and_buffer_empty() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/encrypted.bin"),
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    assert!(matches!(
        compose_submit_outcome(&state),
        SubmitOutcome::AwaitingPassphrase
    ));
}

#[test]
fn compose_submit_outcome_proceed_with_prompt_and_passphrase_filled() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/encrypted.bin"),
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    state.set_passphrase("hunter2");
    let outcome = compose_submit_outcome(&state);
    let SubmitOutcome::Proceed(payload) = outcome else {
        panic!("expected Proceed");
    };
    let pp = payload
        .options
        .paladin_auth_passphrase
        .as_ref()
        .expect("passphrase present");
    assert_eq!(pp.expose_secret(), "hunter2");
}

#[test]
fn compose_submit_outcome_rejected_carries_precheck_inline_error() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/plaintext.bin"),
        PaladinAuthImportPrecheck::Reject(PaladinAuthError::UnsupportedPlaintextVault),
    );
    let outcome = compose_submit_outcome(&state);
    let SubmitOutcome::Rejected(err) = outcome else {
        panic!("expected Rejected");
    };
    assert_eq!(err.kind, ErrorKind::UnsupportedPlaintextVault);
}

// ---------------------------------------------------------------------------
// apply_msg — dialog state-machine routing
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_cancel_emits_cancel_output() {
    let mut state = ImportDialogState::new();
    let out = apply_msg(&mut state, ImportDialogMsg::Cancel);
    assert!(matches!(out, Some(ImportDialogOutput::Cancel)));
}

#[test]
fn apply_msg_close_emits_close_output() {
    let mut state = ImportDialogState::new();
    let out = apply_msg(&mut state, ImportDialogMsg::Close);
    assert!(matches!(out, Some(ImportDialogOutput::Close)));
}

#[test]
fn apply_msg_source_path_picked_updates_state_emits_none() {
    let mut state = ImportDialogState::new();
    let out = apply_msg(
        &mut state,
        ImportDialogMsg::SourcePathPicked {
            path: PathBuf::from("/tmp/source.json"),
            precheck: PaladinAuthImportPrecheck::NoPrompt,
        },
    );
    assert!(out.is_none());
    assert_eq!(state.source_path(), Some(Path::new("/tmp/source.json")));
}

#[test]
fn apply_msg_format_changed_updates_state_emits_none() {
    let mut state = ImportDialogState::new();
    let out = apply_msg(
        &mut state,
        ImportDialogMsg::FormatChanged {
            format: FormatChoice::Otpauth,
            precheck: PaladinAuthImportPrecheck::NoPrompt,
        },
    );
    assert!(out.is_none());
    assert_eq!(state.format(), FormatChoice::Otpauth);
}

#[test]
fn apply_msg_conflict_changed_updates_state_emits_none() {
    let mut state = ImportDialogState::new();
    let out = apply_msg(
        &mut state,
        ImportDialogMsg::ConflictChanged(ConflictChoice::Append),
    );
    assert!(out.is_none());
    assert_eq!(state.conflict(), ConflictChoice::Append);
}

#[test]
fn apply_msg_passphrase_changed_shadows_buffer_emits_none() {
    let mut state = ImportDialogState::new();
    let out = apply_msg(
        &mut state,
        ImportDialogMsg::PassphraseChanged("hunter2".to_string()),
    );
    assert!(out.is_none());
    assert_eq!(state.passphrase_text(), "hunter2");
}

#[test]
fn apply_msg_submit_clicked_proceed_emits_submit_sets_busy() {
    let mut state = proceed_state(PathBuf::from("/tmp/source.json"));
    let out = apply_msg(&mut state, ImportDialogMsg::SubmitClicked);
    assert!(matches!(out, Some(ImportDialogOutput::Submit(_))));
    assert!(state.is_busy());
}

#[test]
fn apply_msg_submit_clicked_needs_source_emits_none() {
    let mut state = ImportDialogState::new();
    let out = apply_msg(&mut state, ImportDialogMsg::SubmitClicked);
    assert!(out.is_none());
    assert!(!state.is_busy());
}

#[test]
fn apply_msg_submit_clicked_awaiting_passphrase_emits_none() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/encrypted.bin"),
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    let out = apply_msg(&mut state, ImportDialogMsg::SubmitClicked);
    assert!(out.is_none());
    assert!(!state.is_busy());
}

#[test]
fn apply_msg_submit_clicked_rejected_stages_inline_error_emits_none() {
    let mut state = ImportDialogState::new();
    state.set_source_path(
        PathBuf::from("/tmp/plaintext.bin"),
        PaladinAuthImportPrecheck::Reject(PaladinAuthError::UnsupportedPlaintextVault),
    );
    // Clear inline_error first so we can verify SubmitClicked re-stages it.
    let _ = apply_msg(
        &mut state,
        ImportDialogMsg::PassphraseChanged(String::new()),
    );
    let out = apply_msg(&mut state, ImportDialogMsg::SubmitClicked);
    assert!(out.is_none());
    assert_eq!(
        state.inline_error().map(|e| e.kind),
        Some(ErrorKind::UnsupportedPlaintextVault)
    );
    assert!(!state.is_busy());
}

#[test]
fn apply_msg_set_busy_toggles_busy_emits_none() {
    let mut state = ImportDialogState::new();
    let out = apply_msg(&mut state, ImportDialogMsg::SetBusy(true));
    assert!(out.is_none());
    assert!(state.is_busy());
}

#[test]
fn apply_msg_worker_completed_success_parks_summary_lifts_busy() {
    let mut state = proceed_state(PathBuf::from("/tmp/source.json"));
    let _ = apply_msg(&mut state, ImportDialogMsg::SubmitClicked);
    let summary = MergeSummary::from_report(&import_report_with_counts(2, 0, 0, 0));
    let out = apply_msg(
        &mut state,
        ImportDialogMsg::WorkerCompleted(MergeOutcome::Success(summary.clone())),
    );
    assert!(out.is_none());
    assert_eq!(state.merge_summary(), Some(&summary));
    assert!(!state.is_busy());
}

#[test]
fn apply_msg_worker_completed_inline_parks_inline_error_lifts_busy() {
    let mut state = proceed_state(PathBuf::from("/tmp/source.json"));
    let _ = apply_msg(&mut state, ImportDialogMsg::SubmitClicked);
    let err = InlineError::from_error(&PaladinAuthError::DecryptFailed);
    let out = apply_msg(
        &mut state,
        ImportDialogMsg::WorkerCompleted(MergeOutcome::Inline(err)),
    );
    assert!(out.is_none());
    assert_eq!(
        state.inline_error().map(|e| e.kind),
        Some(ErrorKind::DecryptFailed)
    );
    assert!(!state.is_busy());
}

#[test]
fn apply_msg_dismiss_counts_clears_summary_emits_close() {
    let mut state = ImportDialogState::new();
    state.apply_merge_outcome(MergeOutcome::Success(MergeSummary::from_report(
        &import_report_with_counts(1, 0, 0, 0),
    )));
    let out = apply_msg(&mut state, ImportDialogMsg::DismissCounts);
    assert!(matches!(out, Some(ImportDialogOutput::Close)));
    assert!(state.merge_summary().is_none());
}

// ---------------------------------------------------------------------------
// compose render helpers
// ---------------------------------------------------------------------------

#[test]
fn compose_submit_button_sensitive_false_no_path() {
    let state = ImportDialogState::new();
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_when_busy() {
    let mut state = proceed_state(PathBuf::from("/tmp/source.json"));
    state.set_busy(true);
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_true_when_proceed_and_not_busy() {
    let state = proceed_state(PathBuf::from("/tmp/source.json"));
    assert!(compose_submit_button_sensitive(&state));
}

#[test]
fn compose_passphrase_row_visible_only_on_prompt() {
    let mut state = ImportDialogState::new();
    assert!(!compose_passphrase_row_visible(&state));
    state.set_source_path(
        PathBuf::from("/tmp/encrypted.bin"),
        PaladinAuthImportPrecheck::PromptForPassphrase,
    );
    assert!(compose_passphrase_row_visible(&state));
}

#[test]
fn compose_counts_panel_visible_only_on_summary() {
    let mut state = ImportDialogState::new();
    assert!(!compose_counts_panel_visible(&state));
    state.apply_merge_outcome(MergeOutcome::Success(MergeSummary::from_report(
        &import_report_with_counts(1, 0, 0, 0),
    )));
    assert!(compose_counts_panel_visible(&state));
}

#[test]
fn compose_counts_panel_labels_format_summary_fields() {
    let mut state = ImportDialogState::new();
    state.apply_merge_outcome(MergeOutcome::Success(MergeSummary::from_report(
        &import_report_with_counts(3, 1, 2, 4),
    )));
    let summary = state.merge_summary().expect("summary parked");
    let _ = summary; // suppress unused; we tested via counts below.
    assert_eq!(
        compose_counts_panel_imported_label(&state).as_deref(),
        Some("Imported: 3")
    );
    assert_eq!(
        compose_counts_panel_skipped_label(&state).as_deref(),
        Some("Skipped: 1")
    );
    assert_eq!(
        compose_counts_panel_replaced_label(&state).as_deref(),
        Some("Replaced: 2")
    );
    assert_eq!(
        compose_counts_panel_appended_label(&state).as_deref(),
        Some("Appended: 4")
    );
    assert_eq!(
        compose_counts_panel_warnings_label(&state).as_deref(),
        Some("Warnings: 0")
    );
}

#[test]
fn compose_counts_panel_warnings_label_threads_warning_count() {
    let mut state = ImportDialogState::new();
    state.apply_merge_outcome(MergeOutcome::Success(MergeSummary::from_report(
        &import_report_with_warnings(2),
    )));
    assert_eq!(
        compose_counts_panel_warnings_label(&state).as_deref(),
        Some("Warnings: 2")
    );
}

#[test]
fn compose_inline_error_revealed_when_set() {
    let mut state = ImportDialogState::new();
    assert!(!compose_inline_error_revealed(&state));
    state.apply_merge_outcome(MergeOutcome::Inline(InlineError::from_error(
        &PaladinAuthError::DecryptFailed,
    )));
    assert!(compose_inline_error_revealed(&state));
    assert!(compose_inline_error_body(&state).is_some());
}

#[test]
fn compose_inline_warning_revealed_when_set() {
    let mut state = ImportDialogState::new();
    assert!(!compose_inline_warning_revealed(&state));
    state.apply_merge_outcome(MergeOutcome::DurabilityWarning(InlineWarning::from_error(
        &PaladinAuthError::SaveDurabilityUnconfirmed,
    )));
    assert!(compose_inline_warning_revealed(&state));
    assert!(compose_inline_warning_body(&state).is_some());
}

// ---------------------------------------------------------------------------
// run_import_worker — integration against a real Vault / Store / source file
// ---------------------------------------------------------------------------

fn open_plaintext_vault(
    dir: &TempDir,
    name: &str,
) -> (paladin_auth_core::Vault, paladin_auth_core::Store) {
    use paladin_auth_core::{Store, VaultInit};
    let path = dir.path().join(name);
    Store::create(&path, VaultInit::Plaintext).expect("create plaintext vault")
}

fn write_otpauth_json(dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    let body = r#"["otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"]"#;
    fs::write(&path, body).expect("write otpauth json");
    let mut perms = fs::metadata(&path).expect("stat").permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms).expect("chmod");
    path
}

fn import_time() -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
}

#[test]
fn run_import_worker_otpauth_success_threads_summary() {
    let dir = secure_tempdir();
    let (vault, store) = open_plaintext_vault(&dir, "vault.bin");
    let source = write_otpauth_json(&dir, "import.json");

    let input = ImportWorkerInput {
        vault,
        store,
        source_path: source,
        options: paladin_auth_core::ImportOptions {
            format: Some(ImportFormat::Otpauth),
            paladin_auth_passphrase: None,
        },
        conflict: ImportConflict::Skip,
        import_time: import_time(),
    };
    let ImportWorkerCompletion {
        outcome,
        vault,
        store: _,
    } = run_import_worker(input);
    let MergeOutcome::Success(summary) = outcome else {
        panic!("expected Success, got {outcome:?}");
    };
    assert_eq!(summary.imported, 1);
    assert_eq!(summary.skipped, 0);
    // The merge landed in memory: the returned vault has the account.
    assert_eq!(vault.iter().count(), 1);
}

#[test]
fn run_import_worker_missing_source_returns_inline_io_error() {
    let dir = secure_tempdir();
    let (vault, store) = open_plaintext_vault(&dir, "vault.bin");
    let missing = dir.path().join("does-not-exist.json");

    let input = ImportWorkerInput {
        vault,
        store,
        source_path: missing,
        options: paladin_auth_core::ImportOptions {
            format: Some(ImportFormat::Otpauth),
            paladin_auth_passphrase: None,
        },
        conflict: ImportConflict::Skip,
        import_time: import_time(),
    };
    let ImportWorkerCompletion { outcome, vault, .. } = run_import_worker(input);
    let MergeOutcome::Inline(err) = outcome else {
        panic!("expected Inline for missing source");
    };
    assert_eq!(err.kind, ErrorKind::IoError);
    // Vault is unchanged (the error fired before any mutation).
    assert_eq!(vault.iter().count(), 0);
}

#[test]
fn run_import_worker_unsupported_format_returns_inline() {
    let dir = secure_tempdir();
    let (vault, store) = open_plaintext_vault(&dir, "vault.bin");
    // Write non-JSON, non-Aegis bytes and force `Otpauth` — the
    // importer rejects with `validation_error` / `invalid_payload`.
    let source = dir.path().join("garbage.bin");
    fs::write(&source, b"\x00\x01\x02not-json").expect("write garbage");
    let mut perms = fs::metadata(&source).expect("stat").permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&source, perms).expect("chmod");

    let input = ImportWorkerInput {
        vault,
        store,
        source_path: source,
        options: paladin_auth_core::ImportOptions {
            format: Some(ImportFormat::Otpauth),
            paladin_auth_passphrase: None,
        },
        conflict: ImportConflict::Skip,
        import_time: import_time(),
    };
    let ImportWorkerCompletion { outcome, .. } = run_import_worker(input);
    assert!(
        matches!(outcome, MergeOutcome::Inline(_)),
        "expected Inline, got {outcome:?}"
    );
}

#[test]
fn import_submit_payload_carries_path_format_conflict_passphrase() {
    let path = PathBuf::from("/tmp/source.bin");
    let options = paladin_auth_core::ImportOptions {
        format: Some(ImportFormat::PaladinAuth),
        paladin_auth_passphrase: Some(SecretString::from("hunter2".to_string())),
    };
    let payload = ImportSubmitPayload {
        source_path: path.clone(),
        options,
        conflict: ImportConflict::Replace,
    };
    assert_eq!(payload.source_path, path);
    assert_eq!(payload.options.format, Some(ImportFormat::PaladinAuth));
    assert_eq!(payload.conflict, ImportConflict::Replace);
    assert_eq!(
        payload
            .options
            .paladin_auth_passphrase
            .as_ref()
            .expect("passphrase")
            .expose_secret(),
        "hunter2"
    );
}

// ---------------------------------------------------------------------------
// format_import_dialog_* — pinned label / title strings shared by the
// `view!` tree and the pure-logic tests. Each helper returns a `'static`
// `&str` so the wording is single-sourced; the test guards keep label
// churn from drifting away from the dialog header / footer / row titles
// the user actually sees.
// ---------------------------------------------------------------------------

#[test]
fn format_import_dialog_title_is_import_accounts() {
    assert_eq!(format_import_dialog_title(), "Import accounts");
}

#[test]
fn format_import_dialog_subtitle_describes_merge() {
    let subtitle = format_import_dialog_subtitle();
    assert!(
        subtitle.contains("Merge") || subtitle.contains("merge"),
        "subtitle wording must reference the merge semantics: {subtitle:?}",
    );
    assert!(
        subtitle.contains("vault") || subtitle.contains("Vault"),
        "subtitle wording must reference the target vault: {subtitle:?}",
    );
}

#[test]
fn format_import_dialog_source_titles_are_distinct() {
    let group = format_import_dialog_source_group_title();
    let row = format_import_dialog_source_row_title();
    let placeholder = format_import_dialog_source_row_placeholder();
    let button = format_import_dialog_choose_source_label();
    assert_ne!(group, row);
    assert_ne!(row, placeholder);
    assert_ne!(row, button);
    assert!(
        button.ends_with('…'),
        "button label uses an ellipsis to signal it opens a follow-up dialog: {button:?}",
    );
}

#[test]
fn format_import_dialog_options_titles_are_distinct() {
    let group = format_import_dialog_options_group_title();
    let format = format_import_dialog_format_row_title();
    let conflict = format_import_dialog_conflict_row_title();
    let passphrase = format_import_dialog_passphrase_row_title();
    assert_ne!(group, format);
    assert_ne!(format, conflict);
    assert_ne!(conflict, passphrase);
    assert_ne!(format, passphrase);
}

#[test]
fn format_import_dialog_counts_group_title_is_import_complete() {
    assert_eq!(format_import_dialog_counts_group_title(), "Import complete");
}

#[test]
fn format_import_dialog_footer_labels_are_distinct() {
    let cancel = format_import_dialog_cancel_label();
    let import = format_import_dialog_import_label();
    let dismiss = format_import_dialog_dismiss_label();
    assert_eq!(cancel, "Cancel");
    assert_eq!(import, "Import");
    assert_eq!(dismiss, "Dismiss");
    assert_ne!(cancel, import);
    assert_ne!(import, dismiss);
}

// ---------------------------------------------------------------------------
// format_import_dialog_format_labels / format_import_dialog_conflict_labels
// — `AdwComboRow` model display labels, ordered to match the inverse
// mapping in `format_choice_from_index` / `conflict_choice_from_index`.
// ---------------------------------------------------------------------------

#[test]
fn format_import_dialog_format_labels_has_five_choices_in_canonical_order() {
    let labels = format_import_dialog_format_labels();
    assert_eq!(labels.len(), 5);
    assert_eq!(labels[0], "Auto-detect");
    // Each subsequent label must match the explicit format choice
    // produced by `format_choice_from_index(idx)`.
    let canonical = [
        FormatChoice::AutoDetect,
        FormatChoice::Otpauth,
        FormatChoice::Aegis,
        FormatChoice::PaladinAuth,
        FormatChoice::Qr,
    ];
    for (idx, choice) in canonical.iter().enumerate() {
        let from_index = format_choice_from_index(u32::try_from(idx).unwrap())
            .expect("canonical index has a choice");
        assert_eq!(from_index, *choice, "canonical order at idx={idx}");
    }
}

#[test]
fn format_import_dialog_conflict_labels_has_three_choices_in_canonical_order() {
    let labels = format_import_dialog_conflict_labels();
    assert_eq!(labels.len(), 3);
    let canonical = [
        ConflictChoice::Skip,
        ConflictChoice::Replace,
        ConflictChoice::Append,
    ];
    for (idx, choice) in canonical.iter().enumerate() {
        let from_index = conflict_choice_from_index(u32::try_from(idx).unwrap())
            .expect("canonical index has a choice");
        assert_eq!(from_index, *choice, "canonical order at idx={idx}");
    }
}

// ---------------------------------------------------------------------------
// `FormatChoice::index` / `format_choice_from_index` and
// `ConflictChoice::index` / `conflict_choice_from_index` are inverses
// over the canonical [0, n) range; out-of-range selections route to
// `None` so the dispatch arm leaves the draft untouched (matching the
// `parse_manual_kind_from_selected` pattern in `add_account.rs`).
// ---------------------------------------------------------------------------

#[test]
fn format_choice_index_round_trips() {
    let canonical = [
        FormatChoice::AutoDetect,
        FormatChoice::Otpauth,
        FormatChoice::Aegis,
        FormatChoice::PaladinAuth,
        FormatChoice::Qr,
    ];
    for choice in canonical {
        let idx = choice.index();
        assert_eq!(
            format_choice_from_index(idx),
            Some(choice),
            "format choice round-trips through index for choice={choice:?} idx={idx}",
        );
    }
}

#[test]
fn format_choice_from_index_rejects_out_of_range() {
    assert_eq!(format_choice_from_index(5), None);
    assert_eq!(format_choice_from_index(42), None);
    assert_eq!(format_choice_from_index(u32::MAX), None);
}

#[test]
fn conflict_choice_index_round_trips() {
    let canonical = [
        ConflictChoice::Skip,
        ConflictChoice::Replace,
        ConflictChoice::Append,
    ];
    for choice in canonical {
        let idx = choice.index();
        assert_eq!(
            conflict_choice_from_index(idx),
            Some(choice),
            "conflict choice round-trips through index for choice={choice:?} idx={idx}",
        );
    }
}

#[test]
fn conflict_choice_from_index_rejects_out_of_range() {
    assert_eq!(conflict_choice_from_index(3), None);
    assert_eq!(conflict_choice_from_index(99), None);
    assert_eq!(conflict_choice_from_index(u32::MAX), None);
}

// ---------------------------------------------------------------------------
// `compose_source_row_subtitle` — subtitle binding for the source
// `adw::ActionRow`. Pure projection over `ImportDialogState::source_path`.
// ---------------------------------------------------------------------------

#[test]
fn compose_source_row_subtitle_shows_placeholder_when_no_source() {
    let state = ImportDialogState::new();
    assert_eq!(
        compose_source_row_subtitle(&state),
        format_import_dialog_source_row_placeholder(),
        "no-source state surfaces the placeholder verbatim",
    );
}

#[test]
fn compose_source_row_subtitle_shows_picked_path_after_source_picked() {
    let mut state = ImportDialogState::new();
    let path = PathBuf::from("/tmp/import-source.json");
    state.set_source_path(path.clone(), PaladinAuthImportPrecheck::NoPrompt);
    let subtitle = compose_source_row_subtitle(&state);
    assert_eq!(subtitle, path.display().to_string());
    assert_ne!(
        subtitle,
        format_import_dialog_source_row_placeholder(),
        "with a path picked the subtitle must not be the placeholder",
    );
}

// ---------------------------------------------------------------------------
// MergeOutcome must be Clone-able so `compose_import_dispatch` can
// embed it in `ImportDialogMsg::WorkerCompleted` without consuming the
// dispatch-site outcome (the dispatch composer takes the outcome by
// reference and the call site needs to keep it for refresh / state
// inspection).
// ---------------------------------------------------------------------------

#[test]
fn merge_outcome_success_is_clone() {
    let report = import_report_with_counts(2, 1, 3, 4);
    let outcome = classify_merge_result(Ok(report));
    let cloned = outcome.clone();
    match (outcome, cloned) {
        (MergeOutcome::Success(a), MergeOutcome::Success(b)) => {
            assert_eq!(a.imported, b.imported);
            assert_eq!(a.skipped, b.skipped);
            assert_eq!(a.replaced, b.replaced);
            assert_eq!(a.appended, b.appended);
            assert_eq!(a.warnings, b.warnings);
        }
        _ => panic!("expected Success on both sides"),
    }
}

#[test]
fn merge_outcome_inline_is_clone() {
    let outcome = classify_merge_result(Err(PaladinAuthError::NoEntriesToImport));
    let cloned = outcome.clone();
    match (outcome, cloned) {
        (MergeOutcome::Inline(a), MergeOutcome::Inline(b)) => {
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.rendered, b.rendered);
        }
        _ => panic!("expected Inline on both sides"),
    }
}
