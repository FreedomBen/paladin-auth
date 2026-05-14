// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic import-dialog tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/import_dialog_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Format-selector routing (auto-detect / explicit `otpauth` /
//!   `aegis` / `paladin` / `qr`) reaches the correct
//!   `paladin_core::import::from_file` invocation via
//!   [`paladin_core::ImportOptions`].
//! * On-conflict policy (`skip` / `replace` / `append`) threads
//!   through [`paladin_core::ImportConflict`] and is reflected in
//!   the merge outcome.
//! * `paladin_core::classify_paladin_import_precheck` routing for
//!   `PromptForPassphrase`, `Reject(err)`, and `NoPrompt` covers
//!   encrypted Paladin, plaintext Paladin, malformed / unsupported
//!   Paladin headers, missing files, non-Paladin content, and
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
//! The module under test (`paladin_gtk::import_dialog`) is the
//! pure-logic state machine the GTK `ImportDialog` shadows. It owns
//! no widgets; the widget layer drives the precheck / format /
//! conflict helpers on user input and `classify_merge_result` on
//! the worker outcome of
//! `Vault::mutate_and_save(|v| { from_file(...) → v.import_accounts(...) })`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use paladin_core::{
    classify_paladin_import_precheck, AccountId, ErrorKind, ImportConflict, ImportFormat,
    ImportReport, ImportWarning, PaladinError, PaladinImportPrecheck, ValidationWarning,
};

use paladin_gtk::import_dialog::{
    build_import_options, classify_merge_result, classify_precheck, passphrase_needs_reset,
    ConflictChoice, FormatChoice, InlineError, InlineWarning, MergeOutcome, MergeSummary,
    PrecheckOutcome,
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

fn make_paladin_bundle(dir: &TempDir, name: &str, passphrase: &str) -> PathBuf {
    use paladin_core::{Argon2Params, EncryptionOptions, Store, VaultInit};

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

fn make_plaintext_paladin_bundle(dir: &TempDir, name: &str) -> PathBuf {
    use paladin_core::{Store, VaultInit};
    let path = dir.path().join(name);
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("save plaintext");
    path
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
// FormatChoice — UI selector → forced ImportFormat for paladin_core::import
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
fn format_choice_paladin_forces_paladin_format() {
    assert_eq!(
        FormatChoice::Paladin.forced_format(),
        Some(ImportFormat::Paladin)
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
    assert!(opts.paladin_passphrase.is_none());
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
fn build_import_options_paladin_carries_passphrase_verbatim() {
    let pp = SecretString::from("hunter2".to_string());
    let opts = build_import_options(FormatChoice::Paladin, Some(pp));
    assert_eq!(opts.format, Some(ImportFormat::Paladin));
    let returned = opts.paladin_passphrase.expect("passphrase preserved");
    assert_eq!(returned.expose_secret(), "hunter2");
}

#[test]
fn build_import_options_non_paladin_with_passphrase_threads_through() {
    // The facade ignores `paladin_passphrase` for non-paladin formats
    // but the dialog still surfaces whatever it captured; the helper
    // doesn't second-guess the caller.
    let pp = SecretString::from("ignored".to_string());
    let opts = build_import_options(FormatChoice::Otpauth, Some(pp));
    assert_eq!(opts.format, Some(ImportFormat::Otpauth));
    assert!(opts.paladin_passphrase.is_some());
}

// ---------------------------------------------------------------------------
// classify_precheck — PaladinImportPrecheck → routing decision
// ---------------------------------------------------------------------------

#[test]
fn classify_precheck_no_prompt_proceeds() {
    let outcome = classify_precheck(PaladinImportPrecheck::NoPrompt);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn classify_precheck_prompt_for_passphrase_routes_to_prompt() {
    let outcome = classify_precheck(PaladinImportPrecheck::PromptForPassphrase);
    assert!(matches!(outcome, PrecheckOutcome::PromptForPassphrase));
}

#[test]
fn classify_precheck_reject_unsupported_plaintext_vault_inlines_typed_error() {
    let probe = PaladinImportPrecheck::Reject(PaladinError::UnsupportedPlaintextVault);
    let outcome = classify_precheck(probe);
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::UnsupportedPlaintextVault);
}

#[test]
fn classify_precheck_reject_invalid_header_inlines_typed_error() {
    let probe = PaladinImportPrecheck::Reject(PaladinError::InvalidHeader);
    let outcome = classify_precheck(probe);
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::InvalidHeader);
}

#[test]
fn classify_precheck_reject_unsupported_format_version_inlines_typed_error() {
    let probe =
        PaladinImportPrecheck::Reject(PaladinError::UnsupportedFormatVersion { format_ver: 99 });
    let outcome = classify_precheck(probe);
    let PrecheckOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::UnsupportedFormatVersion);
}

// ---------------------------------------------------------------------------
// classify_paladin_import_precheck → classify_precheck integration
// ---------------------------------------------------------------------------

#[test]
fn precheck_integration_encrypted_paladin_routes_to_prompt() {
    let dir = secure_tempdir();
    let path = make_paladin_bundle(&dir, "vault.bin", "hunter2");
    let probe = classify_paladin_import_precheck(&path, None);
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::PromptForPassphrase));
}

#[test]
fn precheck_integration_plaintext_paladin_routes_to_inline_unsupported_plaintext_vault() {
    let dir = secure_tempdir();
    let path = make_plaintext_paladin_bundle(&dir, "vault.bin");
    let probe = classify_paladin_import_precheck(&path, None);
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
    let probe = classify_paladin_import_precheck(&path, None);
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn precheck_integration_non_paladin_bytes_route_to_proceed() {
    // Non-Paladin content (e.g. JSON / otpauth text) under auto-
    // detect skips the prompt entirely.
    let dir = secure_tempdir();
    let path = dir.path().join("otpauth.json");
    fs::write(&path, b"otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP").unwrap();
    let probe = classify_paladin_import_precheck(&path, None);
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn precheck_integration_malformed_paladin_header_routes_to_inline_invalid_header() {
    // PALADIN\0 magic followed by gibberish triggers Reject(InvalidHeader).
    let dir = secure_tempdir();
    let path = dir.path().join("malformed.bin");
    let mut bytes = b"PALADIN\0".to_vec();
    bytes.extend_from_slice(&[0xFF; 8]);
    fs::write(&path, &bytes).unwrap();
    let probe = classify_paladin_import_precheck(&path, None);
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
    // Forced non-paladin format skips the probe entirely; even an
    // encrypted-Paladin file under a forced otpauth setting yields
    // NoPrompt → Proceed so from_file can return the typed
    // unsupported_import_format mismatch.
    let dir = secure_tempdir();
    let path = make_paladin_bundle(&dir, "vault.bin", "hunter2");
    let probe = classify_paladin_import_precheck(&path, Some(ImportFormat::Otpauth));
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn precheck_integration_forced_aegis_routes_to_proceed_without_probing() {
    let dir = secure_tempdir();
    let path = dir.path().join("does-not-exist");
    let probe = classify_paladin_import_precheck(&path, Some(ImportFormat::Aegis));
    let outcome = classify_precheck(probe);
    assert!(matches!(outcome, PrecheckOutcome::Proceed));
}

#[test]
fn precheck_integration_forced_qr_routes_to_proceed_without_probing() {
    let dir = secure_tempdir();
    let path = dir.path().join("does-not-exist");
    let probe = classify_paladin_import_precheck(&path, Some(ImportFormat::QrImage));
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
        Some(ImportFormat::Paladin),
        &p,
        Some(ImportFormat::Paladin)
    ));
}

#[test]
fn passphrase_needs_reset_returns_true_when_path_changes() {
    let prev = PathBuf::from("/tmp/old.bin");
    let new = PathBuf::from("/tmp/new.bin");
    assert!(passphrase_needs_reset(
        &prev,
        Some(ImportFormat::Paladin),
        &new,
        Some(ImportFormat::Paladin)
    ));
}

#[test]
fn passphrase_needs_reset_returns_true_when_forced_format_changes() {
    let p = PathBuf::from("/tmp/vault.bin");
    assert!(passphrase_needs_reset(
        &p,
        Some(ImportFormat::Paladin),
        &p,
        None
    ));
}

#[test]
fn passphrase_needs_reset_returns_true_when_format_flips_to_paladin() {
    // Switching from Aegis → Paladin requires a fresh probe and
    // passphrase prompt; the prior row must clear even though the
    // path is unchanged.
    let p = PathBuf::from("/tmp/vault.bin");
    assert!(passphrase_needs_reset(
        &p,
        Some(ImportFormat::Aegis),
        &p,
        Some(ImportFormat::Paladin)
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
        Some(ImportFormat::Paladin)
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
    let outcome = classify_merge_result(Err(PaladinError::SaveDurabilityUnconfirmed));
    let MergeOutcome::DurabilityWarning(warning) = outcome else {
        panic!("expected DurabilityWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
}

// ---------------------------------------------------------------------------
// classify_merge_result — every importer / import_accounts error stays inline
// ---------------------------------------------------------------------------

fn assert_inline_with_kind(err: PaladinError, expected: ErrorKind) {
    let outcome = classify_merge_result(Err(err));
    let MergeOutcome::Inline(inline) = outcome else {
        panic!("expected Inline for {expected:?}, got {outcome:?}");
    };
    assert_eq!(inline.kind, expected);
}

#[test]
fn classify_merge_result_unsupported_import_format_stays_inline() {
    assert_inline_with_kind(
        PaladinError::UnsupportedImportFormat {
            format: "unknown".to_string(),
        },
        ErrorKind::UnsupportedImportFormat,
    );
}

#[test]
fn classify_merge_result_unsupported_plaintext_vault_stays_inline() {
    assert_inline_with_kind(
        PaladinError::UnsupportedPlaintextVault,
        ErrorKind::UnsupportedPlaintextVault,
    );
}

#[test]
fn classify_merge_result_unsupported_encrypted_aegis_stays_inline() {
    assert_inline_with_kind(
        PaladinError::UnsupportedEncryptedAegis,
        ErrorKind::UnsupportedEncryptedAegis,
    );
}

#[test]
fn classify_merge_result_unsupported_aegis_entry_type_stays_inline() {
    assert_inline_with_kind(
        PaladinError::UnsupportedAegisEntryType {
            source_index: 0,
            entry_type: "yubikey".to_string(),
        },
        ErrorKind::UnsupportedAegisEntryType,
    );
}

#[test]
fn classify_merge_result_validation_error_stays_inline() {
    assert_inline_with_kind(
        PaladinError::ValidationError {
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
        PaladinError::NoEntriesToImport,
        ErrorKind::NoEntriesToImport,
    );
}

#[test]
fn classify_merge_result_decrypt_failed_stays_inline() {
    assert_inline_with_kind(PaladinError::DecryptFailed, ErrorKind::DecryptFailed);
}

#[test]
fn classify_merge_result_invalid_header_stays_inline() {
    assert_inline_with_kind(PaladinError::InvalidHeader, ErrorKind::InvalidHeader);
}

#[test]
fn classify_merge_result_invalid_payload_stays_inline() {
    assert_inline_with_kind(
        PaladinError::InvalidPayload {
            reason: "truncated",
        },
        ErrorKind::InvalidPayload,
    );
}

#[test]
fn classify_merge_result_unsupported_format_version_stays_inline() {
    assert_inline_with_kind(
        PaladinError::UnsupportedFormatVersion { format_ver: 99 },
        ErrorKind::UnsupportedFormatVersion,
    );
}

#[test]
fn classify_merge_result_kdf_params_out_of_bounds_stays_inline() {
    assert_inline_with_kind(
        PaladinError::KdfParamsOutOfBounds {
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
        PaladinError::IoError {
            operation: "read_import_file",
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        },
        ErrorKind::IoError,
    );
}

// ---------------------------------------------------------------------------
// InlineError / InlineWarning — Display body comes from PaladinError
// ---------------------------------------------------------------------------

#[test]
fn inline_error_renders_through_paladin_error_display() {
    let err = PaladinError::DecryptFailed;
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::DecryptFailed);
    assert_eq!(inline.rendered, err.to_string());
}

#[test]
fn inline_warning_renders_through_paladin_error_display() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
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
        Some(ImportFormat::Paladin),
        b,
        Some(ImportFormat::Paladin)
    ));
}
