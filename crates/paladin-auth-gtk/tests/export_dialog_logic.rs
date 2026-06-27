// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic export-dialog tests for `paladin-auth-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/export_dialog_logic.rs`"
//! checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Overwrite gate resets when the destination or format changes.
//! * Plaintext-warning gate resets when the destination or format
//!   changes; the rendered text matches
//!   [`paladin_auth_core::format_plaintext_export_warning`] verbatim.
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
//! The module under test (`paladin_auth_gtk::export_dialog`) is the pure-
//! logic state machine the GTK `ExportDialog` shadows. It owns no
//! widgets; the widget layer drives the gate-reset and twice-confirm
//! helpers on user input and `classify_export_result` on the writer
//! outcome of `paladin_auth_core::write_secret_file_atomic` wrapping the
//! `paladin_auth_core::export::otpauth_list` / `paladin_auth_core::export::encrypted`
//! payload.

use std::path::{Path, PathBuf};

use paladin_auth_core::{format_plaintext_export_warning, ErrorKind, PaladinAuthError};

use paladin_auth_gtk::export_dialog::{
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

fn save_not_committed_no_backup() -> PaladinAuthError {
    PaladinAuthError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    }
}

fn save_not_committed_with_backup() -> PaladinAuthError {
    PaladinAuthError::SaveNotCommitted {
        committed: true,
        backup_path: Some(PathBuf::from("/home/u/exports/vault.json.bak")),
    }
}

fn io_error_export() -> PaladinAuthError {
    PaladinAuthError::IoError {
        operation: "write_secret_file_tmp",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    }
}

fn assert_inline_with_kind(err: PaladinAuthError, expected: ErrorKind) {
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
    assert!(ExportFormatChoice::EncryptedPaladinAuth.requires_passphrase());
    assert!(!ExportFormatChoice::EncryptedPaladinAuth.requires_plaintext_warning());
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
        ExportFormatChoice::EncryptedPaladinAuth,
    ));
}

#[test]
fn overwrite_gate_resets_when_both_change() {
    assert!(overwrite_gate_needs_reset(
        &dest_a(),
        ExportFormatChoice::PlaintextOtpauth,
        &dest_b(),
        ExportFormatChoice::EncryptedPaladinAuth,
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
        ExportFormatChoice::EncryptedPaladinAuth,
    ));
}

// ---------------------------------------------------------------------------
// Plaintext-warning text — matches paladin_auth_core verbatim
// ---------------------------------------------------------------------------

#[test]
fn plaintext_warning_body_matches_paladin_auth_core_verbatim() {
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
        ExportFormatChoice::EncryptedPaladinAuth,
        &dest_a(),
        ExportFormatChoice::EncryptedPaladinAuth,
    ));
}

#[test]
fn passphrase_clears_on_destination_change() {
    assert!(passphrase_needs_reset(
        &dest_a(),
        ExportFormatChoice::EncryptedPaladinAuth,
        &dest_b(),
        ExportFormatChoice::EncryptedPaladinAuth,
    ));
}

#[test]
fn passphrase_clears_on_format_change_off_encrypted() {
    // Switching off the encrypted format wipes the row even if the
    // destination is unchanged.
    assert!(passphrase_needs_reset(
        &dest_a(),
        ExportFormatChoice::EncryptedPaladinAuth,
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
        ExportFormatChoice::EncryptedPaladinAuth,
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
    let outcome = classify_export_result(Err(PaladinAuthError::SaveDurabilityUnconfirmed));
    let ExportOutcome::DurabilityWarning(warning) = outcome else {
        panic!("expected DurabilityWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert_eq!(
        warning.rendered,
        PaladinAuthError::SaveDurabilityUnconfirmed.to_string()
    );
}

#[test]
fn classify_export_result_io_error_stays_inline() {
    assert_inline_with_kind(io_error_export(), ErrorKind::IoError);
}

// ---------------------------------------------------------------------------
// InlineError / InlineWarning — Display body comes from PaladinAuthError
// ---------------------------------------------------------------------------

#[test]
fn inline_error_renders_through_paladin_auth_error_display() {
    let err = io_error_export();
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::IoError);
    assert_eq!(inline.rendered, err.to_string());
}

#[test]
fn inline_warning_renders_through_paladin_auth_error_display() {
    let err = PaladinAuthError::SaveDurabilityUnconfirmed;
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
    let err = PaladinAuthError::SaveDurabilityUnconfirmed;
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
        ExportFormatChoice::EncryptedPaladinAuth,
        new,
        ExportFormatChoice::EncryptedPaladinAuth,
    ));
}

// ---------------------------------------------------------------------------
// ExportDialogComponent scaffold (Milestone 7 component-tree wiring)
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" entry
// "Relm4 component tree (Init / Unlock / List / Row / Add / Remove /
// Rename / Import / Export / Passphrase / Settings / StartupError)",
// `ExportDialogComponent` joins the nine already-mounted controllers
// (`AccountListComponent`, `StartupErrorComponent`,
// `InitDialogComponent`, `UnlockDialogComponent`,
// `EditDialogComponent`, `RemoveDialogComponent`,
// `AddAccountComponent`, `SettingsComponent`, `ImportDialogComponent`)
// with the same scaffold shape: `<Name>Init` / `<Name>Msg` /
// `<Name>Output` plus a `relm4::SimpleComponent` impl. The widget
// body (file picker + format selector + overwrite gate + plaintext
// warning + twice-confirm passphrase row) lands in follow-up commits
// alongside the live-apply behavior — this commit only adds the
// controller so the menu's Export… entry can mount it.

#[test]
fn export_dialog_init_round_trips_vault_path() {
    use paladin_auth_gtk::export_dialog::ExportDialogInit;

    let vault_path = PathBuf::from("/tmp/export-scaffold/vault.bin");
    let init = ExportDialogInit {
        vault_path: vault_path.clone(),
    };
    assert_eq!(init.vault_path, vault_path);
}

#[test]
fn export_dialog_output_close_is_constructible() {
    use paladin_auth_gtk::export_dialog::ExportDialogOutput;

    let output = ExportDialogOutput::Close;
    assert!(matches!(output, ExportDialogOutput::Close));
}

#[test]
fn export_dialog_component_input_and_output_match_dispatch_edges() {
    use paladin_auth_gtk::export_dialog::{
        ExportDialogComponent, ExportDialogMsg, ExportDialogOutput,
    };
    use relm4::SimpleComponent;

    // Compile-only assertion that ties `ExportDialogComponent` to its
    // associated `Input` / `Output` types so the AppModel dispatch
    // edges stay in lock-step with the component declaration. If a
    // future refactor renames `ExportDialogMsg` or
    // `ExportDialogOutput`, this test fails at compile time before
    // the AppModel build does.
    fn assert_types<C>()
    where
        C: SimpleComponent<Input = ExportDialogMsg, Output = ExportDialogOutput>,
    {
    }
    assert_types::<ExportDialogComponent>();
}

// ---------------------------------------------------------------------------
// Format selector — labels, index <-> ExportFormatChoice round-trip, default
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
// `ExportDialogComponent` > "Add a format selector (plaintext
// `otpauth://` URI list or encrypted Paladin Auth bundle) and pick the
// destination via `gtk::FileDialog`." The widget binds an
// `adw::ComboRow` to `format_export_dialog_format_labels()` and reads
// `ExportFormatChoice` selections back through
// `format_choice_from_index`; the inverse `ExportFormatChoice::index`
// keeps the `set_selected` binding aligned with the state machine on
// every refresh.

#[test]
fn format_export_dialog_format_labels_returns_plaintext_then_encrypted() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_format_labels;

    let labels = format_export_dialog_format_labels();
    assert_eq!(labels.len(), 2);
    assert_eq!(labels[0], "Plaintext otpauth:// URI list");
    assert_eq!(labels[1], "Encrypted Paladin Auth bundle");
}

#[test]
fn format_export_dialog_format_labels_match_export_format_choice_order() {
    use paladin_auth_gtk::export_dialog::{
        format_choice_from_index, format_export_dialog_format_labels,
    };

    // Each label index must round-trip back to a real choice so the
    // widget never lands on a `None` slot.
    let labels = format_export_dialog_format_labels();
    for (idx, _label) in labels.iter().enumerate() {
        let idx_u32 = u32::try_from(idx).expect("label count fits in u32");
        assert!(
            format_choice_from_index(idx_u32).is_some(),
            "label index {idx} must map to an ExportFormatChoice"
        );
    }
}

#[test]
fn export_format_choice_index_plaintext_is_zero() {
    assert_eq!(ExportFormatChoice::PlaintextOtpauth.index(), 0);
}

#[test]
fn export_format_choice_index_encrypted_is_one() {
    assert_eq!(ExportFormatChoice::EncryptedPaladinAuth.index(), 1);
}

#[test]
fn format_choice_from_index_zero_returns_plaintext() {
    use paladin_auth_gtk::export_dialog::format_choice_from_index;

    assert_eq!(
        format_choice_from_index(0),
        Some(ExportFormatChoice::PlaintextOtpauth)
    );
}

#[test]
fn format_choice_from_index_one_returns_encrypted() {
    use paladin_auth_gtk::export_dialog::format_choice_from_index;

    assert_eq!(
        format_choice_from_index(1),
        Some(ExportFormatChoice::EncryptedPaladinAuth)
    );
}

#[test]
fn format_choice_from_index_out_of_range_returns_none() {
    use paladin_auth_gtk::export_dialog::format_choice_from_index;

    assert_eq!(format_choice_from_index(2), None);
    assert_eq!(format_choice_from_index(u32::MAX), None);
}

#[test]
fn format_choice_index_round_trip_across_every_variant() {
    use paladin_auth_gtk::export_dialog::format_choice_from_index;

    for choice in [
        ExportFormatChoice::PlaintextOtpauth,
        ExportFormatChoice::EncryptedPaladinAuth,
    ] {
        assert_eq!(format_choice_from_index(choice.index()), Some(choice));
    }
}

#[test]
fn export_format_choice_default_is_plaintext_otpauth() {
    // CLI parity: `paladin-auth export <DEST>` defaults to the plaintext
    // newline-separated `otpauth://` URI list when no `--format` is
    // provided. The dialog opens on the same format so the user's
    // first interaction matches the CLI documentation.
    assert_eq!(
        ExportFormatChoice::default(),
        ExportFormatChoice::PlaintextOtpauth
    );
}

// ---------------------------------------------------------------------------
// Dialog title / row labels — non-empty fixed strings the view! binds
// ---------------------------------------------------------------------------

#[test]
fn format_export_dialog_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_title;

    assert!(!format_export_dialog_title().is_empty());
}

#[test]
fn format_export_dialog_subtitle_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_subtitle;

    assert!(!format_export_dialog_subtitle().is_empty());
}

#[test]
fn format_export_dialog_destination_group_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_destination_group_title;

    assert!(!format_export_dialog_destination_group_title().is_empty());
}

#[test]
fn format_export_dialog_destination_row_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_destination_row_title;

    assert!(!format_export_dialog_destination_row_title().is_empty());
}

#[test]
fn format_export_dialog_destination_row_placeholder_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_destination_row_placeholder;

    assert!(!format_export_dialog_destination_row_placeholder().is_empty());
}

#[test]
fn format_export_dialog_choose_destination_label_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_choose_destination_label;

    assert!(!format_export_dialog_choose_destination_label().is_empty());
}

#[test]
fn format_export_dialog_options_group_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_options_group_title;

    assert!(!format_export_dialog_options_group_title().is_empty());
}

#[test]
fn format_export_dialog_format_row_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_format_row_title;

    assert!(!format_export_dialog_format_row_title().is_empty());
}

#[test]
fn format_export_dialog_cancel_label_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_cancel_label;

    assert!(!format_export_dialog_cancel_label().is_empty());
}

#[test]
fn format_export_dialog_export_label_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_export_label;

    assert!(!format_export_dialog_export_label().is_empty());
}

// ---------------------------------------------------------------------------
// ExportDialogState — fresh defaults, destination + format accessors
// ---------------------------------------------------------------------------

#[test]
fn export_dialog_state_new_has_no_destination() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let state = ExportDialogState::new();
    assert!(state.destination_path().is_none());
}

#[test]
fn export_dialog_state_new_format_matches_default() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let state = ExportDialogState::new();
    assert_eq!(state.format(), ExportFormatChoice::default());
}

#[test]
fn export_dialog_state_set_destination_updates_path() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    assert_eq!(state.destination_path(), Some(dest_a().as_path()));
}

#[test]
fn export_dialog_state_set_destination_replaces_prior_path() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_destination(dest_b(), false);
    assert_eq!(state.destination_path(), Some(dest_b().as_path()));
}

#[test]
fn export_dialog_state_set_format_updates_format() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    assert_eq!(state.format(), ExportFormatChoice::EncryptedPaladinAuth);
}

#[test]
fn export_dialog_state_set_format_back_to_plaintext_replaces_encrypted() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    assert_eq!(state.format(), ExportFormatChoice::PlaintextOtpauth);
}

// ---------------------------------------------------------------------------
// compose_destination_row_subtitle — placeholder when empty, display path else
// ---------------------------------------------------------------------------

#[test]
fn compose_destination_row_subtitle_uses_placeholder_when_no_destination() {
    use paladin_auth_gtk::export_dialog::{
        compose_destination_row_subtitle, format_export_dialog_destination_row_placeholder,
        ExportDialogState,
    };

    let state = ExportDialogState::new();
    assert_eq!(
        compose_destination_row_subtitle(&state),
        format_export_dialog_destination_row_placeholder()
    );
}

#[test]
fn compose_destination_row_subtitle_renders_display_path_when_set() {
    use paladin_auth_gtk::export_dialog::{compose_destination_row_subtitle, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    assert_eq!(
        compose_destination_row_subtitle(&state),
        dest_a().display().to_string()
    );
}

// ---------------------------------------------------------------------------
// compose_submit_button_sensitive — gated on destination presence
// ---------------------------------------------------------------------------

#[test]
fn compose_submit_button_sensitive_false_when_no_destination() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let state = ExportDialogState::new();
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_true_when_destination_set_and_no_overwrite_needed() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    // Switch to encrypted to isolate the destination-presence gate
    // from the plaintext-warning gate; the encrypted-path twice-
    // confirm passphrase row is satisfied with matching non-empty
    // entries below so this test exercises destination presence
    // alone.
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    assert!(compose_submit_button_sensitive(&state));
}

// ---------------------------------------------------------------------------
// apply_msg — DestinationPicked / FormatChanged / Cancel / Close
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_destination_picked_updates_state_and_emits_no_output() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    let output = apply_msg(
        &mut state,
        ExportDialogMsg::DestinationPicked {
            path: dest_a(),
            exists: false,
        },
    );
    assert!(output.is_none());
    assert_eq!(state.destination_path(), Some(dest_a().as_path()));
}

#[test]
fn apply_msg_format_changed_updates_state_and_emits_no_output() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    let output = apply_msg(
        &mut state,
        ExportDialogMsg::FormatChanged(ExportFormatChoice::EncryptedPaladinAuth),
    );
    assert!(output.is_none());
    assert_eq!(state.format(), ExportFormatChoice::EncryptedPaladinAuth);
}

#[test]
fn apply_msg_cancel_emits_cancel_output() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, ExportDialogMsg, ExportDialogOutput, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    let output = apply_msg(&mut state, ExportDialogMsg::Cancel);
    assert!(matches!(output, Some(ExportDialogOutput::Cancel)));
}

#[test]
fn apply_msg_close_emits_close_output() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, ExportDialogMsg, ExportDialogOutput, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    let output = apply_msg(&mut state, ExportDialogMsg::Close);
    assert!(matches!(output, Some(ExportDialogOutput::Close)));
}

#[test]
fn apply_msg_destination_picked_replaces_prior_destination() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    apply_msg(
        &mut state,
        ExportDialogMsg::DestinationPicked {
            path: dest_a(),
            exists: false,
        },
    );
    apply_msg(
        &mut state,
        ExportDialogMsg::DestinationPicked {
            path: dest_b(),
            exists: false,
        },
    );
    assert_eq!(state.destination_path(), Some(dest_b().as_path()));
}

#[test]
fn export_dialog_output_cancel_is_distinct_from_close() {
    use paladin_auth_gtk::export_dialog::ExportDialogOutput;

    // §"Component tree" > `ExportDialog` distinguishes the explicit
    // Cancel button from the parent-close path so a future
    // "Discard draft?" prompt can attach to one dispatch arm without
    // affecting the other. Both currently drop the controller in
    // `AppModel`, but the variants must stay separate.
    let cancel = ExportDialogOutput::Cancel;
    let close = ExportDialogOutput::Close;
    assert!(!matches!(cancel, ExportDialogOutput::Close));
    assert!(!matches!(close, ExportDialogOutput::Cancel));
}

// ---------------------------------------------------------------------------
// Overwrite gate — reject overwriting an existing file unless ack'd
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
// `ExportDialogComponent` > "Reject overwriting an existing file
// unless the user confirms an inline overwrite gate (parity with CLI
// `--force`); resolve the overwrite gate before accepting any
// encrypted-bundle passphrase rows." The widget runs
// `Path::try_exists` after the `gtk::FileDialog::save` callback and
// passes the result into `ExportDialogMsg::DestinationPicked { path,
// exists }`; the state machine arms the inline overwrite gate iff
// `exists == true`, and `compose_submit_button_sensitive` refuses
// submission until the user toggles the gate on.

#[test]
fn export_dialog_state_new_has_destination_exists_false() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let state = ExportDialogState::new();
    assert!(!state.destination_exists());
}

#[test]
fn export_dialog_state_new_overwrite_not_acknowledged() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let state = ExportDialogState::new();
    assert!(!state.is_overwrite_acknowledged());
}

#[test]
fn export_dialog_state_set_destination_records_exists_true() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    assert!(state.destination_exists());
}

#[test]
fn export_dialog_state_set_destination_records_exists_false() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    assert!(!state.destination_exists());
}

#[test]
fn export_dialog_state_set_destination_replaces_exists_value() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    state.set_destination(dest_b(), false);
    assert!(!state.destination_exists());
}

#[test]
fn export_dialog_state_set_overwrite_acknowledged_true() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_overwrite_acknowledged(true);
    assert!(state.is_overwrite_acknowledged());
}

#[test]
fn export_dialog_state_set_overwrite_acknowledged_back_to_false() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_overwrite_acknowledged(true);
    state.set_overwrite_acknowledged(false);
    assert!(!state.is_overwrite_acknowledged());
}

#[test]
fn export_dialog_state_set_destination_resets_overwrite_ack_on_path_change() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    // The user has ack'd the gate for `dest_a`. Picking a different
    // path must clear the prior ack so the new destination's gate
    // starts unticked.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    state.set_overwrite_acknowledged(true);
    state.set_destination(dest_b(), true);
    assert!(!state.is_overwrite_acknowledged());
}

#[test]
fn export_dialog_state_set_destination_keeps_overwrite_ack_when_path_and_format_match() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    // Setting the same destination twice (with the same format) must
    // not invalidate the ack — the widget may re-emit the picker
    // result on focus restoration or window-close races.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    state.set_overwrite_acknowledged(true);
    state.set_destination(dest_a(), true);
    assert!(state.is_overwrite_acknowledged());
}

#[test]
fn export_dialog_state_set_format_resets_overwrite_ack_on_format_change() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    // Switching the active format invalidates the prior ack: the
    // overwrite gate is keyed to (path, format) per
    // `overwrite_gate_needs_reset`. Plaintext otpauth and encrypted
    // bundle write distinct files even at the same path.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    state.set_overwrite_acknowledged(true);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    assert!(!state.is_overwrite_acknowledged());
}

#[test]
fn export_dialog_state_set_format_keeps_overwrite_ack_when_format_unchanged() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    state.set_overwrite_acknowledged(true);
    // Re-set the same format — should not invalidate the ack.
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    assert!(state.is_overwrite_acknowledged());
}

// ---------------------------------------------------------------------------
// compose_overwrite_gate_visible — armed iff destination exists
// ---------------------------------------------------------------------------

#[test]
fn compose_overwrite_gate_visible_false_when_no_destination() {
    use paladin_auth_gtk::export_dialog::{compose_overwrite_gate_visible, ExportDialogState};

    let state = ExportDialogState::new();
    assert!(!compose_overwrite_gate_visible(&state));
}

#[test]
fn compose_overwrite_gate_visible_false_when_destination_does_not_exist() {
    use paladin_auth_gtk::export_dialog::{compose_overwrite_gate_visible, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    assert!(!compose_overwrite_gate_visible(&state));
}

#[test]
fn compose_overwrite_gate_visible_true_when_destination_exists() {
    use paladin_auth_gtk::export_dialog::{compose_overwrite_gate_visible, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    assert!(compose_overwrite_gate_visible(&state));
}

// ---------------------------------------------------------------------------
// compose_submit_button_sensitive — gated on overwrite ack when armed
// ---------------------------------------------------------------------------

#[test]
fn compose_submit_button_sensitive_false_when_overwrite_gate_armed_unacked() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_true_when_overwrite_gate_acked() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    // Switch to encrypted so this test isolates the overwrite gate
    // from the plaintext-warning gate; fill the twice-confirm
    // passphrase rows so the encrypted-format passphrase gate is
    // satisfied and the overwrite gate is the only remaining toggle.
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), true);
    state.set_overwrite_acknowledged(true);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    assert!(compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_again_after_overwrite_ack_revoked() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    // The widget binds the gate to an `AdwSwitchRow` — the user can
    // toggle it off after acking. The submit button must dim again.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    state.set_overwrite_acknowledged(true);
    state.set_overwrite_acknowledged(false);
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_after_destination_change_resets_ack() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    // After the ack-reset on destination change, the submit button
    // must reflect the rearmed (unacked) gate.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    state.set_overwrite_acknowledged(true);
    state.set_destination(dest_b(), true);
    assert!(!compose_submit_button_sensitive(&state));
}

// ---------------------------------------------------------------------------
// apply_msg — DestinationPicked struct variant + OverwriteAcknowledged
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_destination_picked_records_exists_true() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    let output = apply_msg(
        &mut state,
        ExportDialogMsg::DestinationPicked {
            path: dest_a(),
            exists: true,
        },
    );
    assert!(output.is_none());
    assert!(state.destination_exists());
}

#[test]
fn apply_msg_overwrite_acknowledged_true_updates_state() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    let output = apply_msg(&mut state, ExportDialogMsg::OverwriteAcknowledged(true));
    assert!(output.is_none());
    assert!(state.is_overwrite_acknowledged());
}

#[test]
fn apply_msg_overwrite_acknowledged_false_clears_state() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    apply_msg(&mut state, ExportDialogMsg::OverwriteAcknowledged(true));
    apply_msg(&mut state, ExportDialogMsg::OverwriteAcknowledged(false));
    assert!(!state.is_overwrite_acknowledged());
}

// ---------------------------------------------------------------------------
// Overwrite gate row labels — non-empty fixed strings the view! binds
// ---------------------------------------------------------------------------

#[test]
fn format_export_dialog_overwrite_gate_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_overwrite_gate_title;

    assert!(!format_export_dialog_overwrite_gate_title().is_empty());
}

#[test]
fn format_export_dialog_overwrite_gate_subtitle_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_overwrite_gate_subtitle;

    assert!(!format_export_dialog_overwrite_gate_subtitle().is_empty());
}

// ---------------------------------------------------------------------------
// Plaintext-warning gate — verbatim warning + ack required before write
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
// `ExportDialogComponent` > "Render
// `paladin_auth_core::format_plaintext_export_warning()` verbatim on the
// plaintext path and require explicit confirmation before the write
// proceeds." The widget mounts the warning body (verbatim through
// the existing `plaintext_warning_body` helper) above an
// `AdwSwitchRow` ack toggle whose visibility tracks the active
// format; `compose_submit_button_sensitive` refuses submission on
// the plaintext path until the user toggles the ack on.

#[test]
fn export_dialog_state_new_plaintext_warning_not_acknowledged() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let state = ExportDialogState::new();
    assert!(!state.is_plaintext_warning_acknowledged());
}

#[test]
fn export_dialog_state_set_plaintext_warning_acknowledged_true() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_plaintext_warning_acknowledged(true);
    assert!(state.is_plaintext_warning_acknowledged());
}

#[test]
fn export_dialog_state_set_plaintext_warning_acknowledged_back_to_false() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_plaintext_warning_acknowledged(true);
    state.set_plaintext_warning_acknowledged(false);
    assert!(!state.is_plaintext_warning_acknowledged());
}

#[test]
fn export_dialog_state_set_destination_resets_plaintext_ack_on_path_change() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    // The user has ack'd the warning for `dest_a` on the plaintext
    // path. Picking a different path must clear the prior ack so
    // the new destination's warning starts unticked.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    state.set_destination(dest_b(), false);
    assert!(!state.is_plaintext_warning_acknowledged());
}

#[test]
fn export_dialog_state_set_destination_keeps_plaintext_ack_when_path_and_format_match() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    // Setting the same destination twice (with the same format) must
    // not invalidate the ack — the widget may re-emit the picker
    // result on focus restoration or window-close races.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    state.set_destination(dest_a(), false);
    assert!(state.is_plaintext_warning_acknowledged());
}

#[test]
fn export_dialog_state_set_format_resets_plaintext_ack_on_format_change() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    // Switching off the plaintext format invalidates the prior ack:
    // when the user switches back to plaintext, the warning must be
    // re-acknowledged. `plaintext_warning_needs_reset` already
    // expresses this contract; the state machine routes through it
    // so the dialog cannot drift off the helper.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    assert!(!state.is_plaintext_warning_acknowledged());
}

#[test]
fn export_dialog_state_set_format_keeps_plaintext_ack_when_format_unchanged() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    // Re-set the same format — should not invalidate the ack.
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    assert!(state.is_plaintext_warning_acknowledged());
}

#[test]
fn export_dialog_state_set_format_resets_plaintext_ack_onto_plaintext_from_encrypted() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    // Switching onto the plaintext format also restarts the prompt:
    // any ack carried while the warning was hidden is invalid for
    // the new mode — the user must re-acknowledge after the format
    // change.
    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    assert!(!state.is_plaintext_warning_acknowledged());
}

// ---------------------------------------------------------------------------
// compose_plaintext_warning_visible — gated to PlaintextOtpauth format
// ---------------------------------------------------------------------------

#[test]
fn compose_plaintext_warning_visible_true_on_plaintext_format() {
    use paladin_auth_gtk::export_dialog::{compose_plaintext_warning_visible, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    assert!(compose_plaintext_warning_visible(&state));
}

#[test]
fn compose_plaintext_warning_visible_false_on_encrypted_format() {
    use paladin_auth_gtk::export_dialog::{compose_plaintext_warning_visible, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    assert!(!compose_plaintext_warning_visible(&state));
}

#[test]
fn compose_plaintext_warning_visible_true_on_default_state() {
    use paladin_auth_gtk::export_dialog::{compose_plaintext_warning_visible, ExportDialogState};

    // The default format is `PlaintextOtpauth` so a fresh dialog
    // shows the warning until the user switches to encrypted.
    let state = ExportDialogState::new();
    assert!(compose_plaintext_warning_visible(&state));
}

// ---------------------------------------------------------------------------
// compose_plaintext_warning_body — verbatim core wording
// ---------------------------------------------------------------------------

#[test]
fn compose_plaintext_warning_body_matches_paladin_auth_core_verbatim() {
    use paladin_auth_gtk::export_dialog::compose_plaintext_warning_body;

    // Renders verbatim through `paladin_auth_core::format_plaintext_export_warning`
    // so CLI / TUI / GUI all surface the same wording.
    assert_eq!(
        compose_plaintext_warning_body(),
        format_plaintext_export_warning()
    );
}

// ---------------------------------------------------------------------------
// compose_submit_button_sensitive — plaintext ack required when visible
// ---------------------------------------------------------------------------

#[test]
fn compose_submit_button_sensitive_false_when_plaintext_warning_visible_unacked() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    // Default format is PlaintextOtpauth so the warning is visible
    // and unacked; submit must stay dim.
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_true_after_plaintext_warning_acked() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    assert!(compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_true_on_encrypted_format_without_plaintext_ack() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    // Encrypted path hides the plaintext warning entirely, so the
    // ack is irrelevant. The encrypted-path twice-confirm passphrase
    // gate is the relevant gate here — satisfy it with matching
    // non-empty entries so the test isolates the plaintext-ack
    // independence.
    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    assert!(compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_after_plaintext_ack_revoked() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    // Toggling the ack off after acking it must dim the button
    // again — the widget binds the gate to an `AdwSwitchRow`.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    state.set_plaintext_warning_acknowledged(false);
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_requires_both_overwrite_and_plaintext_ack_when_both_armed() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    // Composition: when both the overwrite gate AND the plaintext
    // warning are visible, both must be ack'd before submit enables.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true); // file exists, arm overwrite
    assert!(!compose_submit_button_sensitive(&state));

    state.set_overwrite_acknowledged(true);
    // Plaintext warning still unacked.
    assert!(!compose_submit_button_sensitive(&state));

    state.set_plaintext_warning_acknowledged(true);
    // Both gates acked — submit enables.
    assert!(compose_submit_button_sensitive(&state));
}

// ---------------------------------------------------------------------------
// apply_msg — PlaintextWarningAcknowledged
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_plaintext_warning_acknowledged_true_updates_state() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    let output = apply_msg(
        &mut state,
        ExportDialogMsg::PlaintextWarningAcknowledged(true),
    );
    assert!(output.is_none());
    assert!(state.is_plaintext_warning_acknowledged());
}

#[test]
fn apply_msg_plaintext_warning_acknowledged_false_clears_state() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    apply_msg(
        &mut state,
        ExportDialogMsg::PlaintextWarningAcknowledged(true),
    );
    apply_msg(
        &mut state,
        ExportDialogMsg::PlaintextWarningAcknowledged(false),
    );
    assert!(!state.is_plaintext_warning_acknowledged());
}

// ---------------------------------------------------------------------------
// Plaintext-warning row labels — non-empty fixed strings the view! binds
// ---------------------------------------------------------------------------

#[test]
fn format_export_dialog_plaintext_warning_group_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_plaintext_warning_group_title;

    assert!(!format_export_dialog_plaintext_warning_group_title().is_empty());
}

#[test]
fn format_export_dialog_plaintext_warning_ack_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_plaintext_warning_ack_title;

    assert!(!format_export_dialog_plaintext_warning_ack_title().is_empty());
}

#[test]
fn format_export_dialog_plaintext_warning_ack_subtitle_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_plaintext_warning_ack_subtitle;

    assert!(!format_export_dialog_plaintext_warning_ack_subtitle().is_empty());
}

// ---------------------------------------------------------------------------
// Twice-confirm passphrase rows — encrypted-format gate, clear on
// destination / format change
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" >
// `ExportDialogComponent` > "Reset overwrite and plaintext-warning
// confirmations when the destination or format changes; clear the
// passphrase rows and re-prompt when the destination or format
// changes after passphrase entry." and "Prompt twice for the
// encrypted-bundle passphrase; reject mismatch with
// `invalid_passphrase` (`reason: "confirmation_mismatch"`) and
// zero-length with `invalid_passphrase` (`reason: "zero_length"`)
// inline." The widget mounts two `AdwPasswordEntryRow` entries
// (passphrase + confirm) inside an `adw::PreferencesGroup` whose
// visibility binds to the encrypted-format predicate
// `compose_passphrase_rows_visible`; the submit button stays dim
// until both rows are non-empty AND match.

#[test]
fn export_dialog_state_new_has_empty_passphrase() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let state = ExportDialogState::new();
    assert_eq!(state.passphrase_text(), "");
}

#[test]
fn export_dialog_state_new_has_empty_confirm_passphrase() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let state = ExportDialogState::new();
    assert_eq!(state.confirm_passphrase_text(), "");
}

#[test]
fn export_dialog_state_set_passphrase_updates_text() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_passphrase("hunter2");
    assert_eq!(state.passphrase_text(), "hunter2");
}

#[test]
fn export_dialog_state_set_passphrase_replaces_prior_text() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_passphrase("first");
    state.set_passphrase("second");
    assert_eq!(state.passphrase_text(), "second");
}

#[test]
fn export_dialog_state_set_confirm_passphrase_updates_text() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_confirm_passphrase("hunter2");
    assert_eq!(state.confirm_passphrase_text(), "hunter2");
}

#[test]
fn export_dialog_state_set_confirm_passphrase_replaces_prior_text() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_confirm_passphrase("first");
    state.set_confirm_passphrase("second");
    assert_eq!(state.confirm_passphrase_text(), "second");
}

#[test]
fn export_dialog_state_set_destination_clears_passphrase_on_path_change() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    state.set_destination(dest_b(), false);
    assert_eq!(state.passphrase_text(), "");
    assert_eq!(state.confirm_passphrase_text(), "");
}

#[test]
fn export_dialog_state_set_destination_keeps_passphrase_when_path_and_format_match() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    // Re-picking the same path is idempotent; the typed passphrase
    // must survive so an `exists` probe-only refresh does not erase
    // the user's input.
    state.set_destination(dest_a(), false);
    assert_eq!(state.passphrase_text(), "hunter2");
    assert_eq!(state.confirm_passphrase_text(), "hunter2");
}

#[test]
fn export_dialog_state_set_format_clears_passphrase_on_format_change_off_encrypted() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    assert_eq!(state.passphrase_text(), "");
    assert_eq!(state.confirm_passphrase_text(), "");
}

#[test]
fn export_dialog_state_set_format_clears_passphrase_on_format_change_onto_encrypted() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    // Even though the rows were hidden on the plaintext path, any
    // residual text invalidates on a switch back onto the encrypted
    // path — the user re-prompts from a clean slate.
    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    assert_eq!(state.passphrase_text(), "");
    assert_eq!(state.confirm_passphrase_text(), "");
}

#[test]
fn export_dialog_state_set_format_keeps_passphrase_when_format_unchanged() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    assert_eq!(state.passphrase_text(), "hunter2");
    assert_eq!(state.confirm_passphrase_text(), "hunter2");
}

#[test]
fn compose_passphrase_rows_visible_true_on_encrypted_format() {
    use paladin_auth_gtk::export_dialog::{compose_passphrase_rows_visible, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    assert!(compose_passphrase_rows_visible(&state));
}

#[test]
fn compose_passphrase_rows_visible_false_on_plaintext_format() {
    use paladin_auth_gtk::export_dialog::{compose_passphrase_rows_visible, ExportDialogState};

    let state = ExportDialogState::new();
    assert!(!compose_passphrase_rows_visible(&state));
}

#[test]
fn compose_submit_button_sensitive_false_on_encrypted_without_passphrase() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    // Passphrase rows empty — submit must stay dim even though every
    // other gate is satisfied (no overwrite, no plaintext-warning).
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_on_encrypted_with_only_passphrase_no_confirm() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_on_encrypted_with_only_confirm_no_passphrase() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_confirm_passphrase("hunter2");
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_on_encrypted_with_mismatched_passphrases() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter3");
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_true_on_encrypted_with_matching_passphrases() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    assert!(compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_unaffected_by_passphrases_on_plaintext() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    // Plaintext path hides the passphrase rows entirely. Even if a
    // hidden residual value existed, the plaintext-format predicate
    // means the passphrase gate is not consulted — only the plaintext
    // warning ack matters.
    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    // No passphrases typed at all.
    assert!(compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_after_passphrases_cleared_by_destination_change() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    assert!(compose_submit_button_sensitive(&state));
    state.set_destination(dest_b(), false);
    // Destination change clears the passphrase rows; submit dims.
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn compose_submit_button_sensitive_false_after_passphrases_cleared_by_format_change() {
    use paladin_auth_gtk::export_dialog::{compose_submit_button_sensitive, ExportDialogState};

    // Switch onto encrypted, fill rows, switch back off, switch back
    // on — the rows must be empty so submit dims.
    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    assert!(!compose_submit_button_sensitive(&state));
}

#[test]
fn apply_msg_passphrase_changed_updates_state_and_emits_no_output() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    let output = apply_msg(
        &mut state,
        ExportDialogMsg::PassphraseChanged("hunter2".to_string()),
    );
    assert!(output.is_none());
    assert_eq!(state.passphrase_text(), "hunter2");
}

#[test]
fn apply_msg_confirm_passphrase_changed_updates_state_and_emits_no_output() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    let output = apply_msg(
        &mut state,
        ExportDialogMsg::ConfirmPassphraseChanged("hunter2".to_string()),
    );
    assert!(output.is_none());
    assert_eq!(state.confirm_passphrase_text(), "hunter2");
}

#[test]
fn apply_msg_passphrase_changed_to_empty_string_clears_text() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    apply_msg(
        &mut state,
        ExportDialogMsg::PassphraseChanged("hunter2".to_string()),
    );
    apply_msg(
        &mut state,
        ExportDialogMsg::PassphraseChanged(String::new()),
    );
    assert_eq!(state.passphrase_text(), "");
}

// ---------------------------------------------------------------------------
// Passphrase row labels — non-empty fixed strings the view! binds
// ---------------------------------------------------------------------------

#[test]
fn format_export_dialog_passphrase_group_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_passphrase_group_title;

    assert!(!format_export_dialog_passphrase_group_title().is_empty());
}

#[test]
fn format_export_dialog_passphrase_row_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_passphrase_row_title;

    assert!(!format_export_dialog_passphrase_row_title().is_empty());
}

#[test]
fn format_export_dialog_confirm_passphrase_row_title_is_non_empty() {
    use paladin_auth_gtk::export_dialog::format_export_dialog_confirm_passphrase_row_title;

    assert!(!format_export_dialog_confirm_passphrase_row_title().is_empty());
}

// ---------------------------------------------------------------------------
// SubmitClicked twice-confirm validation
//
// The Submit button is gated by `compose_submit_button_sensitive`, but the
// `apply_msg(SubmitClicked)` arm runs the same pre-flight validation
// (`prepare_encrypted_export`) as a defense in depth so a stale widget state
// can never sneak an empty / mismatched passphrase into the worker
// dispatch. Mismatched and zero-length pairs stage an inline error on
// `ExportDialogState` so the dialog body re-renders the `invalid_passphrase`
// projection inline; the `error_kind` / `reason` pair matches the §5
// wire codes the CLI / TUI surface.
// ---------------------------------------------------------------------------

#[test]
fn inline_error_from_rejection_confirmation_mismatch_is_invalid_passphrase() {
    use paladin_auth_gtk::export_dialog::InlineError;

    let inline = InlineError::from_rejection(SubmitRejection::ConfirmationMismatch);
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    let expected = PaladinAuthError::InvalidPassphrase {
        reason: "confirmation_mismatch",
    }
    .to_string();
    assert_eq!(inline.rendered, expected);
}

#[test]
fn inline_error_from_rejection_zero_length_is_invalid_passphrase() {
    use paladin_auth_gtk::export_dialog::InlineError;

    let inline = InlineError::from_rejection(SubmitRejection::ZeroLength);
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    let expected = PaladinAuthError::InvalidPassphrase {
        reason: "zero_length",
    }
    .to_string();
    assert_eq!(inline.rendered, expected);
}

#[test]
fn export_dialog_state_new_has_no_inline_error() {
    use paladin_auth_gtk::export_dialog::ExportDialogState;

    let state = ExportDialogState::new();
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_msg_submit_clicked_encrypted_mismatched_stages_confirmation_mismatch_inline() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("different");

    let output = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(output.is_none());
    let inline = state.inline_error().expect("mismatch stages inline error");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    let expected = PaladinAuthError::InvalidPassphrase {
        reason: "confirmation_mismatch",
    }
    .to_string();
    assert_eq!(inline.rendered, expected);
}

#[test]
fn apply_msg_submit_clicked_encrypted_zero_length_stages_zero_length_inline() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    // Both rows left empty.

    let output = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(output.is_none());
    let inline = state
        .inline_error()
        .expect("zero-length stages inline error");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    let expected = PaladinAuthError::InvalidPassphrase {
        reason: "zero_length",
    }
    .to_string();
    assert_eq!(inline.rendered, expected);
}

#[test]
fn apply_msg_submit_clicked_encrypted_one_empty_stages_confirmation_mismatch_inline() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("");

    let output = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(output.is_none());
    let inline = state.inline_error().expect("one-empty stages inline error");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    let expected = PaladinAuthError::InvalidPassphrase {
        reason: "confirmation_mismatch",
    }
    .to_string();
    assert_eq!(inline.rendered, expected);
}

#[test]
fn apply_msg_submit_clicked_encrypted_matching_clears_prior_inline_error() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    // First click stages a mismatch error.
    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("different");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(state.inline_error().is_some());

    // User fixes the confirm field and re-submits — the stale inline
    // error must clear so the dialog does not surface a dismissed
    // failure beside the freshly accepted pair.
    state.set_confirm_passphrase("hunter2");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_msg_submit_clicked_plaintext_does_not_stage_inline_error() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::PlaintextOtpauth);
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);

    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    // The plaintext path has no twice-confirm passphrase to validate;
    // SubmitClicked must not stage an `invalid_passphrase` inline error.
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_msg_passphrase_changed_clears_prior_inline_error() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    // Stage an inline error via a SubmitClicked on a mismatched pair.
    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("different");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(state.inline_error().is_some());

    // Editing the passphrase clears the stale error so the user is
    // not stuck staring at a dismissed `invalid_passphrase` body
    // while typing the fix.
    let _ = apply_msg(
        &mut state,
        ExportDialogMsg::PassphraseChanged("hunter3".to_string()),
    );
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_msg_confirm_passphrase_changed_clears_prior_inline_error() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("different");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(state.inline_error().is_some());

    let _ = apply_msg(
        &mut state,
        ExportDialogMsg::ConfirmPassphraseChanged("hunter2".to_string()),
    );
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_msg_destination_picked_clears_prior_inline_error() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("different");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(state.inline_error().is_some());

    // Picking a different destination clears the stale inline error so
    // the user is not stuck staring at an `invalid_passphrase` body
    // attached to the prior path — the passphrase rows are also cleared
    // by `passphrase_needs_reset`, so leaving the inline error up would
    // contradict the empty passphrase rows.
    let _ = apply_msg(
        &mut state,
        ExportDialogMsg::DestinationPicked {
            path: dest_b(),
            exists: false,
        },
    );
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_msg_format_changed_clears_prior_inline_error() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("different");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(state.inline_error().is_some());

    // Switching off the encrypted path drops the passphrase rows and
    // makes the prior `invalid_passphrase` inline error irrelevant.
    let _ = apply_msg(
        &mut state,
        ExportDialogMsg::FormatChanged(ExportFormatChoice::PlaintextOtpauth),
    );
    assert!(state.inline_error().is_none());
}

#[test]
fn compose_inline_error_revealed_returns_false_when_no_error() {
    use paladin_auth_gtk::export_dialog::{compose_inline_error_revealed, ExportDialogState};

    let state = ExportDialogState::new();
    assert!(!compose_inline_error_revealed(&state));
}

#[test]
fn compose_inline_error_revealed_returns_true_when_error_staged() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, compose_inline_error_revealed, ExportDialogMsg, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("a");
    state.set_confirm_passphrase("b");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(compose_inline_error_revealed(&state));
}

#[test]
fn compose_inline_error_body_returns_none_when_no_error() {
    use paladin_auth_gtk::export_dialog::{compose_inline_error_body, ExportDialogState};

    let state = ExportDialogState::new();
    assert!(compose_inline_error_body(&state).is_none());
}

#[test]
fn compose_inline_error_body_renders_staged_invalid_passphrase() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, compose_inline_error_body, ExportDialogMsg, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_destination(dest_a(), false);
    state.set_passphrase("a");
    state.set_confirm_passphrase("b");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    let expected = PaladinAuthError::InvalidPassphrase {
        reason: "confirmation_mismatch",
    }
    .to_string();
    assert_eq!(compose_inline_error_body(&state), Some(expected.as_str()));
}

// ---------------------------------------------------------------------------
// compose_submit_outcome — Proceed / Rejected / NotReady routing
// ---------------------------------------------------------------------------

#[test]
fn compose_submit_outcome_plaintext_ready_returns_proceed_with_destination() {
    use paladin_auth_gtk::export_dialog::{
        compose_submit_outcome, ExportDialogState, SubmitOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);

    let outcome = compose_submit_outcome(&state);
    let SubmitOutcome::Proceed(payload) = outcome else {
        panic!("expected Proceed, got something else");
    };
    assert_eq!(payload.destination, dest_a());
    assert_eq!(payload.format, ExportFormatChoice::PlaintextOtpauth);
    assert!(payload.encryption_options.is_none());
}

#[test]
fn compose_submit_outcome_encrypted_ready_returns_proceed_with_options() {
    use paladin_auth_gtk::export_dialog::{
        compose_submit_outcome, ExportDialogState, SubmitOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");

    let outcome = compose_submit_outcome(&state);
    let SubmitOutcome::Proceed(payload) = outcome else {
        panic!("expected Proceed, got something else");
    };
    assert_eq!(payload.destination, dest_a());
    assert_eq!(payload.format, ExportFormatChoice::EncryptedPaladinAuth);
    let opts = payload
        .encryption_options
        .expect("encrypted Proceed carries EncryptionOptions");
    assert_eq!(opts.passphrase.expose_secret(), "hunter2");
}

#[test]
fn compose_submit_outcome_encrypted_mismatch_returns_rejected_invalid_passphrase() {
    use paladin_auth_gtk::export_dialog::{
        compose_submit_outcome, ExportDialogState, SubmitOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter3");

    let outcome = compose_submit_outcome(&state);
    let SubmitOutcome::Rejected(inline) = outcome else {
        panic!("expected Rejected for mismatched twice-confirm");
    };
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
}

#[test]
fn compose_submit_outcome_encrypted_empty_returns_rejected_zero_length() {
    use paladin_auth_gtk::export_dialog::{
        compose_submit_outcome, ExportDialogState, SubmitOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);

    let outcome = compose_submit_outcome(&state);
    let SubmitOutcome::Rejected(inline) = outcome else {
        panic!("expected Rejected for both-empty twice-confirm");
    };
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
    assert_eq!(
        inline.rendered,
        PaladinAuthError::InvalidPassphrase {
            reason: "zero_length",
        }
        .to_string()
    );
}

#[test]
fn compose_submit_outcome_no_destination_returns_not_ready() {
    use paladin_auth_gtk::export_dialog::{
        compose_submit_outcome, ExportDialogState, SubmitOutcome,
    };

    let state = ExportDialogState::new();
    assert!(matches!(
        compose_submit_outcome(&state),
        SubmitOutcome::NotReady
    ));
}

#[test]
fn compose_submit_outcome_overwrite_unacked_returns_not_ready() {
    use paladin_auth_gtk::export_dialog::{
        compose_submit_outcome, ExportDialogState, SubmitOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), true);
    state.set_plaintext_warning_acknowledged(true);
    // overwrite still unacked.
    assert!(matches!(
        compose_submit_outcome(&state),
        SubmitOutcome::NotReady
    ));
}

#[test]
fn compose_submit_outcome_plaintext_warning_unacked_returns_not_ready() {
    use paladin_auth_gtk::export_dialog::{
        compose_submit_outcome, ExportDialogState, SubmitOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    // plaintext warning still unacked.
    assert!(matches!(
        compose_submit_outcome(&state),
        SubmitOutcome::NotReady
    ));
}

// ---------------------------------------------------------------------------
// apply_msg::SubmitClicked emits Submit on Proceed
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_submit_clicked_proceed_plaintext_emits_submit_output() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, ExportDialogMsg, ExportDialogOutput, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);

    let out = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    match out {
        Some(ExportDialogOutput::Submit(payload)) => {
            assert_eq!(payload.destination, dest_a());
            assert_eq!(payload.format, ExportFormatChoice::PlaintextOtpauth);
            assert!(payload.encryption_options.is_none());
        }
        other => panic!("expected Submit, got {other:?}"),
    }
}

#[test]
fn apply_msg_submit_clicked_proceed_encrypted_emits_submit_and_clears_passphrase_buffers() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, ExportDialogMsg, ExportDialogOutput, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");

    let out = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    let Some(ExportDialogOutput::Submit(payload)) = out else {
        panic!("expected Submit, got {out:?}");
    };
    // Passphrase has moved into the payload's EncryptionOptions; the
    // state-side SecretEntry buffers must be cleared on submit per
    // §"Secret entry handling".
    assert!(state.passphrase_text().is_empty());
    assert!(state.confirm_passphrase_text().is_empty());
    let opts = payload
        .encryption_options
        .expect("encrypted Proceed carries EncryptionOptions");
    assert_eq!(opts.passphrase.expose_secret(), "hunter2");
}

#[test]
fn apply_msg_submit_clicked_rejected_stays_in_dialog_with_inline_error() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("a");
    state.set_confirm_passphrase("b");

    let out = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(out.is_none(), "Rejected pre-flight emits no output");
    let inline = state.inline_error().expect("inline error staged");
    assert_eq!(inline.kind, ErrorKind::InvalidPassphrase);
}

#[test]
fn apply_msg_submit_clicked_not_ready_emits_no_output() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    // No destination — submit button shouldn't have been enabled, but
    // defense-in-depth: a stray click emits no output and stages no
    // inline error.
    let out = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(out.is_none());
    assert!(state.inline_error().is_none());
}

// ---------------------------------------------------------------------------
// apply_msg::Cancel / Close zeroize passphrase buffers
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_cancel_clears_passphrase_buffers() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, ExportDialogMsg, ExportDialogOutput, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");

    let out = apply_msg(&mut state, ExportDialogMsg::Cancel);
    assert!(matches!(out, Some(ExportDialogOutput::Cancel)));
    assert!(state.passphrase_text().is_empty());
    assert!(state.confirm_passphrase_text().is_empty());
}

#[test]
fn apply_msg_close_clears_passphrase_buffers() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, ExportDialogMsg, ExportDialogOutput, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");

    let out = apply_msg(&mut state, ExportDialogMsg::Close);
    assert!(matches!(out, Some(ExportDialogOutput::Close)));
    assert!(state.passphrase_text().is_empty());
    assert!(state.confirm_passphrase_text().is_empty());
}

// ---------------------------------------------------------------------------
// Busy state + submit-button sensitivity gate
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_set_busy_toggles_state() {
    use paladin_auth_gtk::export_dialog::{apply_msg, ExportDialogMsg, ExportDialogState};

    let mut state = ExportDialogState::new();
    assert!(!state.is_busy());
    let _ = apply_msg(&mut state, ExportDialogMsg::SetBusy(true));
    assert!(state.is_busy());
    let _ = apply_msg(&mut state, ExportDialogMsg::SetBusy(false));
    assert!(!state.is_busy());
}

#[test]
fn compose_submit_button_sensitive_false_when_busy() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, compose_submit_button_sensitive, ExportDialogMsg, ExportDialogState,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_plaintext_warning_acknowledged(true);
    assert!(compose_submit_button_sensitive(&state));

    let _ = apply_msg(&mut state, ExportDialogMsg::SetBusy(true));
    assert!(
        !compose_submit_button_sensitive(&state),
        "busy state dims the Export button"
    );
}

// ---------------------------------------------------------------------------
// apply_msg::WorkerCompleted — Success / DurabilityWarning / Inline routing
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_worker_completed_success_clears_busy_and_emits_close() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, ExportDialogMsg, ExportDialogOutput, ExportDialogState, ExportOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_format(ExportFormatChoice::EncryptedPaladinAuth);
    state.set_passphrase("hunter2");
    state.set_confirm_passphrase("hunter2");
    let _ = apply_msg(&mut state, ExportDialogMsg::SubmitClicked);
    assert!(state.passphrase_text().is_empty());
    let _ = apply_msg(&mut state, ExportDialogMsg::SetBusy(true));

    let out = apply_msg(
        &mut state,
        ExportDialogMsg::WorkerCompleted(ExportOutcome::Success),
    );
    assert!(matches!(out, Some(ExportDialogOutput::Close)));
    assert!(!state.is_busy());
}

#[test]
fn apply_msg_worker_completed_durability_warning_stages_warning_keeps_dialog_open() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, classify_export_result, ExportDialogMsg, ExportDialogState, ExportOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    let _ = apply_msg(&mut state, ExportDialogMsg::SetBusy(true));

    let outcome = classify_export_result(Err(PaladinAuthError::SaveDurabilityUnconfirmed));
    let ExportOutcome::DurabilityWarning(_) = outcome else {
        panic!("setup: classify_export_result should map SaveDurabilityUnconfirmed to DurabilityWarning");
    };
    let out = apply_msg(&mut state, ExportDialogMsg::WorkerCompleted(outcome));
    assert!(out.is_none(), "durability-warning keeps the dialog open");
    assert!(!state.is_busy());
    assert!(state.inline_warning().is_some());
    assert!(state.inline_error().is_none());
}

#[test]
fn apply_msg_worker_completed_inline_stages_error_keeps_dialog_open() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, classify_export_result, ExportDialogMsg, ExportDialogState, ExportOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    let _ = apply_msg(&mut state, ExportDialogMsg::SetBusy(true));

    let outcome = classify_export_result(Err(io_error_export()));
    let ExportOutcome::Inline(_) = outcome else {
        panic!("setup: classify_export_result should map IoError to Inline");
    };
    let out = apply_msg(&mut state, ExportDialogMsg::WorkerCompleted(outcome));
    assert!(out.is_none(), "writer error keeps the dialog open");
    assert!(!state.is_busy());
    assert!(state.inline_error().is_some());
    assert!(state.inline_warning().is_none());
}

#[test]
fn apply_msg_worker_completed_success_clears_prior_inline_error_and_warning() {
    use paladin_auth_gtk::export_dialog::{
        apply_msg, classify_export_result, ExportDialogMsg, ExportDialogState, ExportOutcome,
    };

    let mut state = ExportDialogState::new();
    state.set_destination(dest_a(), false);
    state.set_inline_error(Some(InlineError::from_error(&io_error_export())));
    let ExportOutcome::DurabilityWarning(warning) =
        classify_export_result(Err(PaladinAuthError::SaveDurabilityUnconfirmed))
    else {
        panic!("setup")
    };
    state.set_inline_warning(Some(warning));

    let _ = apply_msg(
        &mut state,
        ExportDialogMsg::WorkerCompleted(ExportOutcome::Success),
    );
    assert!(state.inline_error().is_none());
    assert!(state.inline_warning().is_none());
}

// ---------------------------------------------------------------------------
// compose_inline_warning_revealed / compose_inline_warning_body view helpers
// ---------------------------------------------------------------------------

#[test]
fn compose_inline_warning_revealed_returns_false_when_no_warning() {
    use paladin_auth_gtk::export_dialog::{compose_inline_warning_revealed, ExportDialogState};

    let state = ExportDialogState::new();
    assert!(!compose_inline_warning_revealed(&state));
}

#[test]
fn compose_inline_warning_revealed_returns_true_when_warning_staged() {
    use paladin_auth_gtk::export_dialog::{
        classify_export_result, compose_inline_warning_revealed, ExportDialogState, ExportOutcome,
    };

    let mut state = ExportDialogState::new();
    let ExportOutcome::DurabilityWarning(warning) =
        classify_export_result(Err(PaladinAuthError::SaveDurabilityUnconfirmed))
    else {
        panic!("setup")
    };
    state.set_inline_warning(Some(warning));
    assert!(compose_inline_warning_revealed(&state));
}

#[test]
fn compose_inline_warning_body_returns_durability_unconfirmed_display() {
    use paladin_auth_gtk::export_dialog::{
        classify_export_result, compose_inline_warning_body, ExportDialogState, ExportOutcome,
    };

    let mut state = ExportDialogState::new();
    let ExportOutcome::DurabilityWarning(warning) =
        classify_export_result(Err(PaladinAuthError::SaveDurabilityUnconfirmed))
    else {
        panic!("setup")
    };
    state.set_inline_warning(Some(warning));
    let expected = PaladinAuthError::SaveDurabilityUnconfirmed.to_string();
    assert_eq!(compose_inline_warning_body(&state), Some(expected.as_str()));
}

// ---------------------------------------------------------------------------
// run_export_worker — integration against a real Vault / Store
// ---------------------------------------------------------------------------

mod worker_integration {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    use paladin_auth_gtk::export_dialog::{
        run_export_worker, ExportFormatChoice, ExportOutcome, ExportWorkerCompletion,
        ExportWorkerInput,
    };

    fn secure_tempdir() -> TempDir {
        let dir = tempfile::tempdir().expect("create tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 so paladin_auth_core::Store::create accepts the parent");
        dir
    }

    fn open_plaintext_vault(
        dir: &TempDir,
        name: &str,
    ) -> (paladin_auth_core::Vault, paladin_auth_core::Store) {
        use paladin_auth_core::{Store, VaultInit};
        let path = dir.path().join(name);
        Store::create(&path, VaultInit::Plaintext).expect("create plaintext vault")
    }

    #[test]
    fn run_export_worker_plaintext_writes_otpauth_list_and_returns_success() {
        let dir = secure_tempdir();
        let (vault, store) = open_plaintext_vault(&dir, "vault.bin");
        let dest = dir.path().join("export.txt");

        let input = ExportWorkerInput {
            vault,
            store,
            destination: dest.clone(),
            format: ExportFormatChoice::PlaintextOtpauth,
            encryption_options: None,
        };
        let ExportWorkerCompletion {
            outcome,
            destination,
            ..
        } = run_export_worker(input);
        assert!(matches!(outcome, ExportOutcome::Success));
        assert_eq!(destination, dest);
        let bytes = fs::read(&dest).expect("read written export");
        let s = String::from_utf8(bytes).expect("utf8");
        // Empty vault → empty file (no `otpauth://` lines).
        assert_eq!(s, "");
        let mode = fs::metadata(&dest).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "write_secret_file_atomic enforces 0600");
    }

    fn light_params() -> paladin_auth_core::Argon2Params {
        // §4.4 acceptance-bound minimum so encrypted-bundle round-trips
        // run quickly in the suite (the production default 64 MiB would
        // balloon the test runtime). The bounds check still passes —
        // `m_kib >= 8192`, `t >= 1`, `p >= 1`.
        paladin_auth_core::Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        }
    }

    #[test]
    fn run_export_worker_encrypted_writes_paladin_auth_bundle_and_returns_success() {
        use paladin_auth_core::EncryptionOptions;
        use secrecy::SecretString;

        let dir = secure_tempdir();
        let (vault, store) = open_plaintext_vault(&dir, "vault.bin");
        let dest = dir.path().join("export.paladin-auth");

        let opts = EncryptionOptions::with_params(SecretString::from("hunter2"), light_params())
            .expect("EncryptionOptions::with_params");
        let input = ExportWorkerInput {
            vault,
            store,
            destination: dest.clone(),
            format: ExportFormatChoice::EncryptedPaladinAuth,
            encryption_options: Some(opts),
        };
        let ExportWorkerCompletion { outcome, .. } = run_export_worker(input);
        assert!(matches!(outcome, ExportOutcome::Success));
        let bytes = fs::read(&dest).expect("read written bundle");
        // Encrypted bundle is not an `otpauth://` text dump — assert
        // its first byte is not the lowercase `o` that begins every
        // `otpauth://` URI emitted by the plaintext writer.
        assert_ne!(bytes.first().copied(), Some(b'o'));
        // Paladin Auth bundle starts with the magic header bytes; confirm
        // it's not empty.
        assert!(!bytes.is_empty(), "encrypted bundle should not be empty");
    }

    #[test]
    fn run_export_worker_plaintext_io_error_returns_inline() {
        let dir = secure_tempdir();
        let (vault, store) = open_plaintext_vault(&dir, "vault.bin");
        // Write into a path whose parent is read-only so
        // write_secret_file_atomic fails with io_error.
        let ro_parent = dir.path().join("readonly");
        fs::create_dir(&ro_parent).expect("create dir");
        fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o500)).expect("chmod 0500");

        // Root (or CAP_DAC_OVERRIDE) bypasses DAC bits; CI containers
        // commonly run as root. Probe by attempting a write under the
        // 0500 parent — if it succeeds, the export worker will commit
        // and the Inline-outcome assertion below is meaningless, so
        // skip.
        let probe = ro_parent.join(".paladin-auth-root-probe");
        if fs::write(&probe, b"").is_ok() {
            let _ = fs::remove_file(&probe);
            fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o700)).ok();
            return;
        }

        let dest = ro_parent.join("export.json");

        let input = ExportWorkerInput {
            vault,
            store,
            destination: dest,
            format: ExportFormatChoice::PlaintextOtpauth,
            encryption_options: None,
        };
        let ExportWorkerCompletion { outcome, vault, .. } = run_export_worker(input);
        let ExportOutcome::Inline(err) = outcome else {
            panic!("expected Inline for read-only destination, got {outcome:?}");
        };
        // `write_secret_file_atomic` may surface either `IoError`
        // (the tmpfile create / fsync failed) or `SaveNotCommitted`
        // (the staging rename did not commit) depending on which
        // step inside the staged-clobber pipeline fails first. Both
        // are valid Inline outcomes per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
        // §"Effect errors" > Export.
        assert!(
            matches!(err.kind, ErrorKind::IoError | ErrorKind::SaveNotCommitted),
            "expected IoError or SaveNotCommitted, got {:?}",
            err.kind
        );
        // Export does not mutate the vault.
        assert_eq!(vault.iter().count(), 0);

        // Restore permissions so TempDir can clean up.
        fs::set_permissions(&ro_parent, fs::Permissions::from_mode(0o700)).ok();
    }
}

// ---------------------------------------------------------------------------
// ExportSubmitPayload — shape test for the dispatch payload
// ---------------------------------------------------------------------------

#[test]
fn export_submit_payload_carries_destination_format_and_optional_options() {
    use paladin_auth_core::{Argon2Params, EncryptionOptions};
    use paladin_auth_gtk::export_dialog::ExportSubmitPayload;
    use secrecy::SecretString;

    let plain = ExportSubmitPayload {
        destination: dest_a(),
        format: ExportFormatChoice::PlaintextOtpauth,
        encryption_options: None,
    };
    assert_eq!(plain.destination, dest_a());
    assert_eq!(plain.format, ExportFormatChoice::PlaintextOtpauth);
    assert!(plain.encryption_options.is_none());

    let params = Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    };
    let opts = EncryptionOptions::with_params(SecretString::from("hunter2"), params)
        .expect("EncryptionOptions::with_params");
    let enc = ExportSubmitPayload {
        destination: dest_b(),
        format: ExportFormatChoice::EncryptedPaladinAuth,
        encryption_options: Some(opts),
    };
    assert_eq!(enc.destination, dest_b());
    assert_eq!(enc.format, ExportFormatChoice::EncryptedPaladinAuth);
    assert!(enc.encryption_options.is_some());
}
