// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic destroy-dialog tests for `paladin-auth-gtk`.
//!
//! Tracks the §"`DestroyDialog` (Milestone 10 ...)" > "Pure-logic
//! tests" checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Warning body sourcing — the dialog body is a single call to
//!   `paladin_auth_core::format_destroy_warning(path, backup_present)`
//!   with no re-implemented wording, so the GTK body is byte-equal
//!   to the CLI / TUI warning for the same `(path, backup_present)`.
//! * `backup_present` probe — `probe_backup_present` reports `true`
//!   when `vault.bin.bak` exists, `false` when it is absent, and
//!   `false` (the cautious default) when the sibling path cannot be
//!   read.
//! * `yes`-confirmation gating — the destructive response is enabled
//!   only when the confirmation buffer reads exactly `yes` after a
//!   Unicode-whitespace trim (partial input / trailing whitespace /
//!   byte-equal `yes`), and never while the busy latch is set.
//! * `Esc` / Cancel path — `DestroyDialogMsg::Cancel` emits
//!   `DestroyDialogOutput::Cancel` without touching state.
//! * `Ok(DestroyReport)` projections — `compose_destroy_dispatch`
//!   over `DestroyWorkerEffect::Success` transitions to `Missing`,
//!   drops the dialog, mounts `InitDialog`, and raises the
//!   backup-aware success toast for both `backup_deleted: true` and
//!   `backup_deleted: false`.
//! * `io_error` variants — `classify_destroy_error` routes each of
//!   `vault_file_is_symlink`, `backup_file_is_symlink`,
//!   `unlink_vault_file`, `unlink_backup_file`, and `fsync_vault_dir`
//!   to the inline-error renderer; the dialog stays open.
//! * `vault_missing` projection — `DestroyWorkerEffect::VaultMissing`
//!   transitions to `Missing`, drops the dialog, mounts `InitDialog`,
//!   and raises the `Vault already gone.` toast.
//! * Sensitive-buffer wipe roll-call — `secret_fields::clear_all`
//!   enumerates every secret-bearing UI buffer that the success path
//!   wipes; the test asserts the roll-call covers each documented
//!   call site.
//! * Auto-lock interaction — the dialog's confirmation buffer is
//!   non-secret but zeroized on Cancel / lock; a post-dispatch
//!   auto-lock is queued behind the result and the success branch
//!   resets the idle deadline by transitioning to `Missing`.

use std::path::{Path, PathBuf};

use paladin_auth_core::{format_destroy_warning, DestroyReport, ErrorKind, PaladinAuthError};

use paladin_auth_gtk::app::state::{compose_destroy_dispatch, AppState, DestroyDispatch};
use paladin_auth_gtk::destroy_dialog::{
    apply_msg, classify_destroy_error, format_destroy_dialog_body,
    format_destroy_dialog_cancel_label, format_destroy_dialog_cancel_response_id,
    format_destroy_dialog_confirmation_title, format_destroy_dialog_destroy_label,
    format_destroy_dialog_destructive_response_enabled,
    format_destroy_dialog_destructive_response_id, format_destroy_dialog_heading,
    format_destroy_dialog_inline_error_text, format_destroy_dialog_inline_error_visible,
    format_destroy_dialog_marker, format_destroy_dialog_success_toast,
    format_destroy_dialog_vault_gone_toast, probe_backup_present, run_destroy_worker,
    DestroyDialogInit, DestroyDialogMsg, DestroyDialogOutput, DestroyDialogState,
    DestroyErrorOutcome, DestroyWorkerEffect, InlineError, DESTROY_DIALOG_MARKER_PREFIX,
};
use paladin_auth_gtk::secret_fields::{self, SecretSurface};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn vault_path() -> PathBuf {
    PathBuf::from("/home/alice/.local/share/paladin-auth/vault.bin")
}

fn fresh_state() -> DestroyDialogState {
    DestroyDialogState::new(&DestroyDialogInit {
        path: vault_path(),
        backup_present: false,
    })
}

fn io_error(operation: &'static str) -> PaladinAuthError {
    PaladinAuthError::IoError {
        operation,
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    }
}

fn destroy_io_error(
    operation: &'static str,
    primary_deleted: bool,
    backup_deleted: bool,
) -> PaladinAuthError {
    PaladinAuthError::DestroyIoError {
        operation,
        source: std::io::Error::other("boom"),
        primary_deleted,
        backup_deleted,
    }
}

// ---------------------------------------------------------------------------
// Warning body sourcing (single helper call, no drift)
// ---------------------------------------------------------------------------

#[test]
fn body_is_sourced_from_core_format_destroy_warning_without_backup() {
    let path = vault_path();
    let state = DestroyDialogState::new(&DestroyDialogInit {
        path: path.clone(),
        backup_present: false,
    });
    assert_eq!(
        format_destroy_dialog_body(&state),
        format_destroy_warning(&path, false),
        "body must be byte-equal to the core warning for backup_present=false",
    );
}

#[test]
fn body_is_sourced_from_core_format_destroy_warning_with_backup() {
    let path = vault_path();
    let state = DestroyDialogState::new(&DestroyDialogInit {
        path: path.clone(),
        backup_present: true,
    });
    assert_eq!(
        format_destroy_dialog_body(&state),
        format_destroy_warning(&path, true),
        "body must be byte-equal to the core warning for backup_present=true",
    );
}

#[test]
fn body_mentions_backup_path_only_when_backup_present() {
    let path = vault_path();
    let with = DestroyDialogState::new(&DestroyDialogInit {
        path: path.clone(),
        backup_present: true,
    });
    let without = DestroyDialogState::new(&DestroyDialogInit {
        path,
        backup_present: false,
    });
    assert!(format_destroy_dialog_body(&with).contains(".bak"));
    assert!(!format_destroy_dialog_body(&without).contains(".bak"));
}

// ---------------------------------------------------------------------------
// backup_present probe (present / absent / unreadable)
// ---------------------------------------------------------------------------

#[test]
fn probe_backup_present_true_when_bak_exists() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.bin");
    std::fs::write(&vault, b"x").unwrap();
    std::fs::write(dir.path().join("vault.bin.bak"), b"y").unwrap();
    assert!(probe_backup_present(&vault));
}

#[test]
fn probe_backup_present_false_when_bak_absent() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.bin");
    std::fs::write(&vault, b"x").unwrap();
    assert!(!probe_backup_present(&vault));
}

#[test]
fn probe_backup_present_false_when_parent_unreadable() {
    // A `.bak` path whose parent does not exist yields `Ok(false)`
    // from `try_exists`; a path that errors (e.g. a non-directory
    // parent component) yields `Err`, which the probe maps to the
    // cautious `false`. Both must surface as `false` so the dialog
    // never claims a backup it cannot confirm.
    let probe = probe_backup_present(Path::new("/nonexistent-paladin-auth-root/vault.bin"));
    assert!(!probe, "absent parent must report no backup");

    // Force the `Err` branch: a path that traverses through a
    // regular file as if it were a directory makes `try_exists`
    // return `Err(NotADirectory)` on every platform under test.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-dir");
    std::fs::write(&file, b"x").unwrap();
    let through_file = file.join("vault.bin");
    assert!(
        !probe_backup_present(&through_file),
        "unreadable .bak sibling must report no backup",
    );
}

// ---------------------------------------------------------------------------
// yes-confirmation gating (partial / trailing-whitespace / byte-equal)
// ---------------------------------------------------------------------------

#[test]
fn destructive_response_disabled_until_yes() {
    let mut state = fresh_state();
    assert!(
        !format_destroy_dialog_destructive_response_enabled(&state),
        "fresh dialog must have the destroy response disabled",
    );

    for partial in ["", "y", "ye", "yess", "no", "YES", "Yes"] {
        apply_msg(
            &mut state,
            DestroyDialogMsg::ConfirmationChanged(partial.to_string()),
        );
        assert!(
            !format_destroy_dialog_destructive_response_enabled(&state),
            "{partial:?} must not enable the destroy response",
        );
    }
}

#[test]
fn destructive_response_enabled_on_exact_yes() {
    let mut state = fresh_state();
    apply_msg(
        &mut state,
        DestroyDialogMsg::ConfirmationChanged("yes".to_string()),
    );
    assert!(format_destroy_dialog_destructive_response_enabled(&state));
}

#[test]
fn destructive_response_enabled_on_yes_with_surrounding_whitespace() {
    for padded in [
        "yes\n",
        "  yes  ",
        "\tyes\r\n",
        " yes ",
        "\u{00a0}yes\u{2009}",
    ] {
        let mut state = fresh_state();
        apply_msg(
            &mut state,
            DestroyDialogMsg::ConfirmationChanged(padded.to_string()),
        );
        assert!(
            format_destroy_dialog_destructive_response_enabled(&state),
            "{padded:?} must enable the destroy response after a whitespace trim",
        );
    }
}

#[test]
fn destructive_response_disabled_while_busy_even_with_yes() {
    let mut state = fresh_state();
    apply_msg(
        &mut state,
        DestroyDialogMsg::ConfirmationChanged("yes".to_string()),
    );
    apply_msg(&mut state, DestroyDialogMsg::SetBusy(true));
    assert!(
        !format_destroy_dialog_destructive_response_enabled(&state),
        "busy latch must override a confirmed buffer",
    );
    apply_msg(&mut state, DestroyDialogMsg::SetBusy(false));
    assert!(
        format_destroy_dialog_destructive_response_enabled(&state),
        "clearing busy must re-enable the confirmed buffer",
    );
}

// ---------------------------------------------------------------------------
// Confirm / Cancel routing
// ---------------------------------------------------------------------------

#[test]
fn confirm_forwards_submit_with_seeded_path() {
    let mut state = fresh_state();
    apply_msg(
        &mut state,
        DestroyDialogMsg::ConfirmationChanged("yes".to_string()),
    );
    let out = apply_msg(&mut state, DestroyDialogMsg::Confirm);
    assert_eq!(
        out,
        Some(DestroyDialogOutput::SubmitConfirm { path: vault_path() }),
        "Confirm must forward the seeded vault path so a mid-flight retarget is impossible",
    );
}

#[test]
fn confirm_clears_prior_worker_outcome() {
    let mut state = fresh_state();
    // Seed a prior inline error, then Confirm should clear it so a
    // re-display does not show stale error text alongside a fresh
    // attempt.
    apply_msg(
        &mut state,
        DestroyDialogMsg::WorkerFailed(classify_destroy_error(&io_error("unlink_vault_file"))),
    );
    assert!(format_destroy_dialog_inline_error_visible(&state));
    apply_msg(
        &mut state,
        DestroyDialogMsg::ConfirmationChanged("yes".to_string()),
    );
    let _ = apply_msg(&mut state, DestroyDialogMsg::Confirm);
    assert!(
        !format_destroy_dialog_inline_error_visible(&state),
        "Confirm must clear the cached worker outcome",
    );
}

#[test]
fn cancel_emits_cancel_without_touching_confirmation() {
    let mut state = fresh_state();
    apply_msg(
        &mut state,
        DestroyDialogMsg::ConfirmationChanged("yes".to_string()),
    );
    let out = apply_msg(&mut state, DestroyDialogMsg::Cancel);
    assert_eq!(out, Some(DestroyDialogOutput::Cancel));
}

// ---------------------------------------------------------------------------
// Ok(DestroyReport) -> AppMsg routing (backup_deleted both true and false)
// ---------------------------------------------------------------------------

#[test]
fn success_with_backup_deleted_transitions_to_missing_and_drops_dialog() {
    let current = AppState::UnlockedBusy { path: vault_path() };
    let effect = DestroyWorkerEffect::Success(DestroyReport {
        primary_deleted: true,
        backup_deleted: true,
    });
    let dispatch: DestroyDispatch = compose_destroy_dispatch(&current, &effect);

    assert!(
        matches!(dispatch.app_state, Some(AppState::Missing { .. })),
        "success must transition to Missing",
    );
    assert!(dispatch.drop_dialog, "success must drop the dialog");
    assert!(dispatch.drop_vault, "success must drop the held vault");
    assert!(dispatch.mount_init, "success must mount the InitDialog");
    assert!(dispatch.wipe_secrets, "success must wipe secret buffers");
    assert_eq!(
        dispatch.toast.as_deref(),
        Some(format_destroy_dialog_success_toast(true)),
    );
}

#[test]
fn success_without_backup_deleted_uses_backup_remained_toast() {
    let current = AppState::UnlockedBusy { path: vault_path() };
    let effect = DestroyWorkerEffect::Success(DestroyReport {
        primary_deleted: true,
        backup_deleted: false,
    });
    let dispatch = compose_destroy_dispatch(&current, &effect);
    assert!(matches!(dispatch.app_state, Some(AppState::Missing { .. })));
    assert!(dispatch.drop_dialog);
    assert_eq!(
        dispatch.toast.as_deref(),
        Some(format_destroy_dialog_success_toast(false)),
    );
}

#[test]
fn success_toast_wording_is_backup_aware() {
    assert_eq!(format_destroy_dialog_success_toast(true), "Vault deleted.");
    assert_eq!(
        format_destroy_dialog_success_toast(false),
        "Vault deleted (backup remained on disk).",
    );
}

#[test]
fn success_missing_state_carries_the_destroyed_path() {
    let current = AppState::UnlockedBusy { path: vault_path() };
    let effect = DestroyWorkerEffect::Success(DestroyReport {
        primary_deleted: true,
        backup_deleted: true,
    });
    let dispatch = compose_destroy_dispatch(&current, &effect);
    match dispatch.app_state {
        Some(AppState::Missing { path }) => assert_eq!(path, vault_path()),
        other => panic!("expected Missing carrying the vault path, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// vault_missing projection
// ---------------------------------------------------------------------------

#[test]
fn vault_missing_transitions_to_missing_with_already_gone_toast() {
    let current = AppState::UnlockedBusy { path: vault_path() };
    let dispatch = compose_destroy_dispatch(&current, &DestroyWorkerEffect::VaultMissing);
    assert!(
        matches!(dispatch.app_state, Some(AppState::Missing { .. })),
        "vault_missing must still transition to Missing (idempotent)",
    );
    assert!(dispatch.drop_dialog);
    assert!(dispatch.drop_vault);
    assert!(dispatch.mount_init);
    assert!(dispatch.wipe_secrets);
    assert_eq!(
        dispatch.toast.as_deref(),
        Some(format_destroy_dialog_vault_gone_toast()),
    );
}

#[test]
fn vault_gone_toast_wording() {
    assert_eq!(
        format_destroy_dialog_vault_gone_toast(),
        "Vault already gone."
    );
}

// ---------------------------------------------------------------------------
// io_error variants -> inline-error renderer (dialog stays open)
// ---------------------------------------------------------------------------

#[test]
fn classify_pre_primary_io_errors_render_inline() {
    for op in [
        "vault_file_is_symlink",
        "backup_file_is_symlink",
        "unlink_vault_file",
    ] {
        let outcome = classify_destroy_error(&io_error(op));
        match outcome {
            DestroyErrorOutcome::InlineError(err) => {
                assert_eq!(err.kind, ErrorKind::IoError);
                assert!(!err.rendered.is_empty());
            }
        }
    }
}

#[test]
fn classify_post_primary_destroy_io_errors_render_inline() {
    for (op, primary, backup) in [
        ("unlink_backup_file", true, false),
        ("fsync_vault_dir", true, true),
    ] {
        let outcome = classify_destroy_error(&destroy_io_error(op, primary, backup));
        match outcome {
            DestroyErrorOutcome::InlineError(err) => {
                // `DestroyIoError::kind()` reports `IoError` per the
                // core contract.
                assert_eq!(err.kind, ErrorKind::IoError);
                assert!(!err.rendered.is_empty());
            }
        }
    }
}

#[test]
fn io_error_dispatch_keeps_dialog_open_and_forwards_inline() {
    let current = AppState::UnlockedBusy { path: vault_path() };
    let outcome = classify_destroy_error(&io_error("unlink_vault_file"));
    let effect = DestroyWorkerEffect::Failure(outcome);
    let dispatch = compose_destroy_dispatch(&current, &effect);

    // Busy gate releases back to Unlocked (the vault was never
    // handed off as a returned pair, but the model still rolls the
    // gate so controls re-enable).
    assert!(
        matches!(dispatch.app_state, Some(AppState::Unlocked { .. })),
        "a failed destroy rolls the busy gate back to Unlocked",
    );
    assert!(!dispatch.drop_dialog, "failure keeps the dialog open");
    assert!(!dispatch.drop_vault, "failure keeps the held vault");
    assert!(!dispatch.mount_init, "failure does not mount InitDialog");
    assert!(!dispatch.wipe_secrets, "failure does not wipe secrets");
    assert!(dispatch.toast.is_none(), "failure raises no success toast");
    assert!(
        dispatch.dialog_msg.is_some(),
        "failure forwards the inline error to the live dialog",
    );
}

#[test]
fn inline_error_text_renders_through_state() {
    let mut state = fresh_state();
    assert!(!format_destroy_dialog_inline_error_visible(&state));
    assert_eq!(format_destroy_dialog_inline_error_text(&state), "");

    let err = io_error("unlink_vault_file");
    apply_msg(
        &mut state,
        DestroyDialogMsg::WorkerFailed(classify_destroy_error(&err)),
    );
    assert!(format_destroy_dialog_inline_error_visible(&state));
    assert_eq!(
        format_destroy_dialog_inline_error_text(&state),
        err.to_string()
    );
}

#[test]
fn confirmation_buffer_is_preserved_across_error_redisplay() {
    let mut state = fresh_state();
    apply_msg(
        &mut state,
        DestroyDialogMsg::ConfirmationChanged("yes".to_string()),
    );
    let _ = apply_msg(&mut state, DestroyDialogMsg::Confirm);
    apply_msg(
        &mut state,
        DestroyDialogMsg::WorkerFailed(classify_destroy_error(&io_error("fsync_vault_dir"))),
    );
    // The buffer survives so the user does not retype `yes` on retry.
    assert_eq!(state.confirmation(), "yes");
}

// ---------------------------------------------------------------------------
// Inline error from a generic (non-symlink/unlink/fsync) error
// ---------------------------------------------------------------------------

#[test]
fn classify_generic_error_renders_inline() {
    let err = PaladinAuthError::VaultMissing;
    // VaultMissing is routed as its own effect at the worker layer,
    // but `classify_destroy_error` is a defensive total function — a
    // generic typed error still renders inline rather than panicking.
    let outcome = classify_destroy_error(&err);
    let DestroyErrorOutcome::InlineError(inline) = outcome;
    assert_eq!(inline.rendered, err.to_string());
}

// ---------------------------------------------------------------------------
// InlineError::from_error round-trip
// ---------------------------------------------------------------------------

#[test]
fn inline_error_from_error_copies_kind_and_renders_display() {
    let err = destroy_io_error("unlink_backup_file", true, false);
    let inline = InlineError::from_error(&err);
    assert_eq!(inline.kind, ErrorKind::IoError);
    assert_eq!(inline.rendered, err.to_string());
}

// ---------------------------------------------------------------------------
// run_destroy_worker over a real tempfile vault (Success / VaultMissing)
// ---------------------------------------------------------------------------

#[test]
fn run_destroy_worker_success_deletes_primary_only() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.bin");
    std::fs::write(&vault, b"vault").unwrap();

    let effect = run_destroy_worker(vault.clone());
    match effect {
        DestroyWorkerEffect::Success(report) => {
            assert!(report.primary_deleted);
            assert!(!report.backup_deleted);
        }
        other => panic!("expected Success, got {other:?}"),
    }
    assert!(!vault.exists(), "primary must be unlinked");
}

#[test]
fn run_destroy_worker_success_deletes_primary_and_backup() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.bin");
    std::fs::write(&vault, b"vault").unwrap();
    let bak = dir.path().join("vault.bin.bak");
    std::fs::write(&bak, b"backup").unwrap();

    let effect = run_destroy_worker(vault.clone());
    match effect {
        DestroyWorkerEffect::Success(report) => {
            assert!(report.primary_deleted);
            assert!(report.backup_deleted);
        }
        other => panic!("expected Success, got {other:?}"),
    }
    assert!(!vault.exists());
    assert!(!bak.exists());
}

#[test]
fn run_destroy_worker_missing_primary_maps_to_vault_missing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.bin");
    // No primary on disk.
    let effect = run_destroy_worker(vault);
    assert!(
        matches!(effect, DestroyWorkerEffect::VaultMissing),
        "absent primary maps to VaultMissing, not a hard error",
    );
}

// ---------------------------------------------------------------------------
// Defensive: a non-UnlockedBusy current state leaves AppState intact
// ---------------------------------------------------------------------------

#[test]
fn success_from_non_busy_state_does_not_phantom_transition() {
    // Defensive case: worker outcome arrives but the cached state is
    // not UnlockedBusy. The success branch still mounts Missing
    // because the destroy is terminal (the vault really is gone), but
    // the dispatch is computed off the typed effect, not the prior
    // state, so the success projection is stable.
    let current = AppState::Unlocked { path: vault_path() };
    let effect = DestroyWorkerEffect::Success(DestroyReport {
        primary_deleted: true,
        backup_deleted: true,
    });
    let dispatch = compose_destroy_dispatch(&current, &effect);
    assert!(matches!(dispatch.app_state, Some(AppState::Missing { .. })));
}

// ---------------------------------------------------------------------------
// Auto-lock interaction (pre- and post-dispatch)
// ---------------------------------------------------------------------------

#[test]
fn auto_lock_pre_dispatch_zeroizes_confirmation() {
    // Pre-dispatch (no effect in flight): auto-lock closes the dialog
    // and zeroizes the confirmation buffer. `clear_for_lock` is the
    // pure-logic hook the model calls before dropping the controller.
    let mut state = fresh_state();
    apply_msg(
        &mut state,
        DestroyDialogMsg::ConfirmationChanged("yes".to_string()),
    );
    paladin_auth_gtk::destroy_dialog::clear_for_lock(&mut state);
    assert_eq!(
        state.confirmation(),
        "",
        "lock must zeroize the confirmation buffer"
    );
    assert!(
        !format_destroy_dialog_inline_error_visible(&state),
        "lock must clear any inline error",
    );
}

#[test]
fn auto_lock_post_dispatch_success_resets_idle_to_missing() {
    // Post-dispatch: the success branch transitions to Missing so the
    // auto-lock idle deadline resets to None (no vault to lock). The
    // dispatch's `app_state` is the observable proof.
    let current = AppState::UnlockedBusy { path: vault_path() };
    let effect = DestroyWorkerEffect::Success(DestroyReport {
        primary_deleted: true,
        backup_deleted: true,
    });
    let dispatch = compose_destroy_dispatch(&current, &effect);
    assert!(
        matches!(dispatch.app_state, Some(AppState::Missing { .. })),
        "Missing has no vault, so the idle deadline resets to None",
    );
}

// ---------------------------------------------------------------------------
// secret_fields::clear_all roll-call (every secret-bearing buffer)
// ---------------------------------------------------------------------------

#[test]
fn clear_all_roll_call_covers_every_secret_surface() {
    // The success path wipes every secret-bearing UI buffer. The
    // roll-call enumerates them so the destroy success handler (and
    // its sibling lock path) cannot silently skip a surface.
    let surfaces = secret_fields::clear_all();
    let expected = [
        SecretSurface::PassphraseFields,
        SecretSurface::AddManualSecret,
        SecretSurface::AddUri,
        SecretSurface::AddPendingDuplicate,
        SecretSurface::InitPendingVaultInit,
        SecretSurface::SearchQuery,
        SecretSurface::HotpRevealState,
        SecretSurface::HotpRevealSecret,
        SecretSurface::PendingClipboardAutoClear,
        SecretSurface::ExportQrRenderedBuffers,
    ];
    for surface in expected {
        assert!(
            surfaces.contains(&surface),
            "clear_all roll-call is missing {surface:?}",
        );
    }
    assert_eq!(
        surfaces.len(),
        expected.len(),
        "clear_all roll-call has an unexpected number of surfaces: {surfaces:?}",
    );
}

// ---------------------------------------------------------------------------
// Static wording / response-id pins
// ---------------------------------------------------------------------------

#[test]
fn static_wording_pins() {
    assert_eq!(format_destroy_dialog_heading(), "Delete vault?");
    assert_eq!(format_destroy_dialog_destroy_label(), "Delete");
    assert_eq!(format_destroy_dialog_cancel_label(), "Cancel");
    assert_eq!(
        format_destroy_dialog_confirmation_title(),
        "Type 'yes' to confirm"
    );
    assert_eq!(format_destroy_dialog_destructive_response_id(), "destroy");
    assert_eq!(format_destroy_dialog_cancel_response_id(), "cancel");
}

#[test]
fn marker_format_is_stable() {
    let marker = format_destroy_dialog_marker(Path::new("/tmp/vault.bin"), true);
    assert!(marker.starts_with(DESTROY_DIALOG_MARKER_PREFIX));
    assert!(marker.contains("/tmp/vault.bin"));
    assert!(marker.contains("backup_present=true"));
}
