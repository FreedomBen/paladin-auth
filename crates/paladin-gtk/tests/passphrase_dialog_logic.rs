// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic passphrase-dialog tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests >
//! `tests/passphrase_dialog_logic.rs`" checklist in
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Sub-flow gating against `Vault::is_encrypted()`: `set` is
//!   available only when the getter returns `false`; `change` and
//!   `remove` only when `true`.
//! * `set` / `change` twice-confirm match accepts; mismatch rejects
//!   with `invalid_passphrase` (`reason: "confirmation_mismatch"`).
//! * `set` / `change` reject zero-length new passphrases with
//!   `invalid_passphrase` (`reason: "zero_length"`).
//! * `remove` renders
//!   `paladin_core::format_plaintext_storage_warning()` verbatim and
//!   requires explicit confirmation before mutation.
//! * Switching sub-flows clears all passphrase rows and pending
//!   plaintext-removal confirmation.
//! * Passphrase entry buffers zeroize on submit / cancel / dialog
//!   close.
//!
//! The module under test (`paladin_gtk::passphrase_dialog`) is the
//! pure-logic state machine the GTK `PassphraseDialog` shadows. It
//! owns no widgets; the `PassphraseSecretState` from
//! [`paladin_gtk::secret_fields`] holds the secret-bearing
//! passphrase buffers and the pending plaintext-removal
//! confirmation across the destructive gate (DESIGN §8 / plan
//! §"Secret entry handling").

use std::path::PathBuf;

use paladin_core::{format_plaintext_storage_warning, ErrorKind};

use paladin_gtk::passphrase_dialog::{
    apply_msg, available_sub_flows, classify_passphrase_error, default_sub_flow_for,
    prepare_new_passphrase, remove_warning_body, run_passphrase_worker, PassphraseDialogMsg,
    PassphraseDialogOutput, PassphraseDialogState, PassphraseErrorOutcome,
    PassphraseWorkerCompletion, PassphraseWorkerEffect, PassphraseWorkerInput, SubFlow,
    SubmitPayload, SubmitRejection,
};
use paladin_gtk::secret_fields::{ClearReason, PassphraseSecretState};

// ---------------------------------------------------------------------------
// Sub-flow gating against `Vault::is_encrypted()`
// ---------------------------------------------------------------------------

#[test]
fn sub_flow_set_available_only_when_plaintext() {
    assert!(SubFlow::Set.is_available(false));
    assert!(!SubFlow::Set.is_available(true));
}

#[test]
fn sub_flow_change_available_only_when_encrypted() {
    assert!(!SubFlow::Change.is_available(false));
    assert!(SubFlow::Change.is_available(true));
}

#[test]
fn sub_flow_remove_available_only_when_encrypted() {
    assert!(!SubFlow::Remove.is_available(false));
    assert!(SubFlow::Remove.is_available(true));
}

#[test]
fn available_sub_flows_plaintext_returns_only_set() {
    let flows = available_sub_flows(false);
    assert_eq!(flows, [SubFlow::Set]);
}

#[test]
fn available_sub_flows_encrypted_returns_change_and_remove() {
    let flows = available_sub_flows(true);
    assert_eq!(flows, [SubFlow::Change, SubFlow::Remove]);
}

// ---------------------------------------------------------------------------
// prepare_new_passphrase — twice-confirm match accepts
// ---------------------------------------------------------------------------

#[test]
fn prepare_new_passphrase_match_returns_encryption_options() {
    let opts = prepare_new_passphrase("hunter2", "hunter2").expect("matching pair accepted");
    // Drop here — the SecretString inside zeroizes its bytes in place.
    drop(opts);
}

// ---------------------------------------------------------------------------
// prepare_new_passphrase — mismatch rejects with confirmation_mismatch
// ---------------------------------------------------------------------------

#[test]
fn prepare_new_passphrase_mismatch_rejects_with_confirmation_mismatch() {
    let err =
        prepare_new_passphrase("hunter2", "hunter3").expect_err("mismatched pair must reject");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);
}

#[test]
fn prepare_new_passphrase_one_empty_rejects_with_confirmation_mismatch() {
    let err = prepare_new_passphrase("hunter2", "").expect_err("one-empty must reject as mismatch");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);
    let err = prepare_new_passphrase("", "hunter2").expect_err("one-empty must reject as mismatch");
    assert_eq!(err, SubmitRejection::ConfirmationMismatch);
}

// ---------------------------------------------------------------------------
// prepare_new_passphrase — both empty rejects with zero_length
// ---------------------------------------------------------------------------

#[test]
fn prepare_new_passphrase_both_empty_rejects_with_zero_length() {
    let err = prepare_new_passphrase("", "").expect_err("both-empty must reject as zero_length");
    assert_eq!(err, SubmitRejection::ZeroLength);
}

// ---------------------------------------------------------------------------
// SubmitRejection wire codes mirror §5 invalid_passphrase reasons
// ---------------------------------------------------------------------------

#[test]
fn submit_rejection_confirmation_mismatch_renders_invalid_passphrase_reason() {
    let rej = SubmitRejection::ConfirmationMismatch;
    assert_eq!(rej.error_kind(), ErrorKind::InvalidPassphrase);
    assert_eq!(rej.reason(), "confirmation_mismatch");
}

#[test]
fn submit_rejection_zero_length_renders_invalid_passphrase_reason() {
    let rej = SubmitRejection::ZeroLength;
    assert_eq!(rej.error_kind(), ErrorKind::InvalidPassphrase);
    assert_eq!(rej.reason(), "zero_length");
}

// ---------------------------------------------------------------------------
// remove_warning_body — verbatim format_plaintext_storage_warning
// ---------------------------------------------------------------------------

#[test]
fn remove_warning_body_matches_paladin_core_verbatim() {
    assert_eq!(remove_warning_body(), format_plaintext_storage_warning());
}

// ---------------------------------------------------------------------------
// PassphraseSecretState — fresh state and remove acknowledgement gate
// ---------------------------------------------------------------------------

#[test]
fn passphrase_state_new_starts_with_empty_buffers_and_no_remove_confirmation() {
    let state = PassphraseSecretState::new(SubFlow::Set);
    assert_eq!(state.sub_flow, SubFlow::Set);
    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
    assert!(!state.remove_confirmed);
}

#[test]
fn passphrase_state_acknowledge_remove_sets_flag() {
    let mut state = PassphraseSecretState::new(SubFlow::Remove);
    assert!(!state.remove_confirmed);
    state.acknowledge_remove();
    assert!(state.remove_confirmed);
}

// ---------------------------------------------------------------------------
// PassphraseSecretState::switch_sub_flow — wipes all rows + pending
// plaintext-removal confirmation
// ---------------------------------------------------------------------------

#[test]
fn passphrase_state_switch_change_to_remove_clears_passphrase_rows() {
    let mut state = PassphraseSecretState::new(SubFlow::Change);
    state.new_passphrase.set("hunter2");
    state.confirm_passphrase.set("hunter2");

    state.switch_sub_flow(SubFlow::Remove);

    assert_eq!(state.sub_flow, SubFlow::Remove);
    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
    assert!(!state.remove_confirmed);
}

#[test]
fn passphrase_state_switch_remove_to_change_clears_pending_remove_confirmation() {
    let mut state = PassphraseSecretState::new(SubFlow::Remove);
    state.acknowledge_remove();
    assert!(state.remove_confirmed);

    state.switch_sub_flow(SubFlow::Change);

    assert_eq!(state.sub_flow, SubFlow::Change);
    assert!(!state.remove_confirmed);
    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
}

#[test]
fn passphrase_state_switch_set_to_change_clears_passphrase_rows() {
    let mut state = PassphraseSecretState::new(SubFlow::Set);
    state.new_passphrase.set("first");
    state.confirm_passphrase.set("first");

    state.switch_sub_flow(SubFlow::Change);

    assert_eq!(state.sub_flow, SubFlow::Change);
    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
    assert!(!state.remove_confirmed);
}

#[test]
fn passphrase_state_switch_change_to_set_clears_passphrase_rows() {
    let mut state = PassphraseSecretState::new(SubFlow::Change);
    state.new_passphrase.set("hunter2");
    state.confirm_passphrase.set("hunter2");

    state.switch_sub_flow(SubFlow::Set);

    assert_eq!(state.sub_flow, SubFlow::Set);
    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
}

#[test]
fn passphrase_state_switch_remove_to_set_clears_pending_remove_confirmation() {
    let mut state = PassphraseSecretState::new(SubFlow::Remove);
    state.acknowledge_remove();
    assert!(state.remove_confirmed);

    state.switch_sub_flow(SubFlow::Set);

    assert_eq!(state.sub_flow, SubFlow::Set);
    assert!(!state.remove_confirmed);
}

#[test]
fn passphrase_state_switch_to_same_sub_flow_is_noop() {
    // Mirrors the AddSecretState::switch_path idempotent-re-entry
    // contract: same-target call leaves typed buffers and the
    // pending acknowledgement untouched so accidental re-fires do
    // not erase user input.
    let mut state = PassphraseSecretState::new(SubFlow::Change);
    state.new_passphrase.set("hunter2");
    state.confirm_passphrase.set("hunter2");

    state.switch_sub_flow(SubFlow::Change);

    assert_eq!(state.sub_flow, SubFlow::Change);
    assert!(!state.new_passphrase.is_empty());
    assert!(!state.confirm_passphrase.is_empty());
}

#[test]
fn passphrase_state_switch_remove_to_remove_preserves_acknowledgement() {
    let mut state = PassphraseSecretState::new(SubFlow::Remove);
    state.acknowledge_remove();

    state.switch_sub_flow(SubFlow::Remove);

    assert!(state.remove_confirmed);
}

// ---------------------------------------------------------------------------
// PassphraseSecretState::clear_for — wipes buffers + pending on Submit /
// Cancel / Close / AutoLock
// ---------------------------------------------------------------------------

#[test]
fn passphrase_state_clear_for_submit_wipes_all_state() {
    let mut state = PassphraseSecretState::new(SubFlow::Change);
    state.new_passphrase.set("hunter2");
    state.confirm_passphrase.set("hunter2");
    state.acknowledge_remove();

    state.clear_for(ClearReason::Submit);

    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
    assert!(!state.remove_confirmed);
    // Sub-flow itself is not changed by clear_for (the dialog is
    // closing, not switching).
    assert_eq!(state.sub_flow, SubFlow::Change);
}

#[test]
fn passphrase_state_clear_for_cancel_wipes_all_state() {
    let mut state = PassphraseSecretState::new(SubFlow::Change);
    state.new_passphrase.set("hunter2");
    state.confirm_passphrase.set("hunter2");
    state.acknowledge_remove();

    state.clear_for(ClearReason::Cancel);

    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
    assert!(!state.remove_confirmed);
}

#[test]
fn passphrase_state_clear_for_close_wipes_all_state() {
    let mut state = PassphraseSecretState::new(SubFlow::Change);
    state.new_passphrase.set("hunter2");
    state.confirm_passphrase.set("hunter2");
    state.acknowledge_remove();

    state.clear_for(ClearReason::Close);

    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
    assert!(!state.remove_confirmed);
}

#[test]
fn passphrase_state_clear_for_auto_lock_wipes_all_state() {
    let mut state = PassphraseSecretState::new(SubFlow::Change);
    state.new_passphrase.set("hunter2");
    state.confirm_passphrase.set("hunter2");
    state.acknowledge_remove();

    state.clear_for(ClearReason::AutoLock);

    assert!(state.new_passphrase.is_empty());
    assert!(state.confirm_passphrase.is_empty());
    assert!(!state.remove_confirmed);
}

// ---------------------------------------------------------------------------
// PassphraseDialogComponent scaffold (Milestone 7 component-tree wiring)
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" entry
// "Relm4 component tree (Init / Unlock / List / Row / Add / Remove /
// Rename / Import / Export / Passphrase / Settings / StartupError)",
// `PassphraseDialogComponent` joins the ten already-mounted
// controllers (`AccountListComponent`, `StartupErrorComponent`,
// `InitDialogComponent`, `UnlockDialogComponent`,
// `RenameDialogComponent`, `RemoveDialogComponent`,
// `AddAccountComponent`, `SettingsComponent`,
// `ImportDialogComponent`, `ExportDialogComponent`) with the same
// scaffold shape: `<Name>Init` / `<Name>Msg` / `<Name>Output` plus a
// `relm4::SimpleComponent` impl. The widget body (sub-flow segmented
// control + Set / Change / Remove fields + destructive
// `adw::AlertDialog` gate + worker wiring) lands in follow-up
// commits alongside the live-apply behavior — this commit only adds
// the controller so the menu's Passphrase… entry can mount it.

#[test]
fn passphrase_dialog_init_round_trips_vault_path_and_encryption_state() {
    use paladin_gtk::passphrase_dialog::PassphraseDialogInit;

    let vault_path = PathBuf::from("/tmp/passphrase-scaffold/vault.bin");
    let init = PassphraseDialogInit {
        vault_path: vault_path.clone(),
        is_encrypted: true,
    };
    assert_eq!(init.vault_path, vault_path);
    assert!(init.is_encrypted);
}

#[test]
fn passphrase_dialog_init_round_trips_plaintext_vault() {
    use paladin_gtk::passphrase_dialog::PassphraseDialogInit;

    // Sub-flow gating depends on `is_encrypted`: a plaintext vault
    // exposes only `SubFlow::Set`. The scaffold init must preserve
    // the bit so the follow-up `available_sub_flows` wiring threads
    // the correct value.
    let init = PassphraseDialogInit {
        vault_path: PathBuf::from("/tmp/passphrase-scaffold/plaintext.bin"),
        is_encrypted: false,
    };
    assert!(!init.is_encrypted);
}

#[test]
fn passphrase_dialog_output_close_is_constructible() {
    use paladin_gtk::passphrase_dialog::PassphraseDialogOutput;

    let output = PassphraseDialogOutput::Close;
    assert!(matches!(output, PassphraseDialogOutput::Close));
}

#[test]
fn passphrase_dialog_component_input_and_output_match_dispatch_edges() {
    use paladin_gtk::passphrase_dialog::PassphraseDialogComponent;
    use relm4::SimpleComponent;

    // Compile-only assertion that ties `PassphraseDialogComponent` to
    // its associated `Input` / `Output` types so the AppModel
    // dispatch edges stay in lock-step with the component
    // declaration. If a future refactor renames
    // `PassphraseDialogMsg` or `PassphraseDialogOutput`, this test
    // fails at compile time before the AppModel build does.
    fn assert_types<C>()
    where
        C: SimpleComponent<Input = PassphraseDialogMsg, Output = PassphraseDialogOutput>,
    {
    }
    assert_types::<PassphraseDialogComponent>();
}

// ---------------------------------------------------------------------------
// default_sub_flow_for — initial sub-flow chosen for the dialog's
// segmented control given the live vault encryption state.
// ---------------------------------------------------------------------------

#[test]
fn default_sub_flow_for_plaintext_returns_set() {
    // A plaintext vault can only expose `Set` — the segmented
    // control should arm `Set` on open so the user does not see
    // a sub-flow gated to `false` by `is_available`.
    assert_eq!(default_sub_flow_for(false), SubFlow::Set);
}

#[test]
fn default_sub_flow_for_encrypted_returns_change() {
    // An encrypted vault exposes `Change` and `Remove`. The default
    // is the non-destructive option (`Change`); `Remove` requires
    // an additional plaintext-storage acknowledgement.
    assert_eq!(default_sub_flow_for(true), SubFlow::Change);
}

// ---------------------------------------------------------------------------
// PassphraseDialogState — initial shape per encryption mode
// ---------------------------------------------------------------------------

#[test]
fn passphrase_dialog_state_new_plaintext_seeds_set_with_empty_buffers() {
    let state = PassphraseDialogState::new(false);
    assert_eq!(state.sub_flow(), SubFlow::Set);
    assert!(!state.is_encrypted());
    assert!(state.new_passphrase().is_empty());
    assert!(state.confirm_passphrase().is_empty());
    assert!(!state.remove_confirmed());
    assert!(state.inline_rejection().is_none());
    assert!(state.worker_outcome().is_none());
}

#[test]
fn passphrase_dialog_state_new_encrypted_seeds_change_with_empty_buffers() {
    let state = PassphraseDialogState::new(true);
    assert_eq!(state.sub_flow(), SubFlow::Change);
    assert!(state.is_encrypted());
    assert!(state.new_passphrase().is_empty());
    assert!(state.confirm_passphrase().is_empty());
    assert!(!state.remove_confirmed());
}

// ---------------------------------------------------------------------------
// apply_msg — SubFlowSelected routes through PassphraseSecretState
// and clears prior worker outcome / inline rejection.
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_sub_flow_selected_switches_active_sub_flow() {
    let mut state = PassphraseDialogState::new(true);
    assert_eq!(state.sub_flow(), SubFlow::Change);

    let output = apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );
    assert!(output.is_none());
    assert_eq!(state.sub_flow(), SubFlow::Remove);
}

#[test]
fn apply_msg_sub_flow_selected_clears_passphrase_buffers() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );
    assert!(!state.new_passphrase().is_empty());

    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );

    assert!(state.new_passphrase().is_empty());
    assert!(state.confirm_passphrase().is_empty());
}

#[test]
fn apply_msg_sub_flow_selected_clears_remove_confirmed_flag() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );
    apply_msg(&mut state, PassphraseDialogMsg::AcknowledgeRemove(true));
    assert!(state.remove_confirmed());

    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Change),
    );

    assert!(!state.remove_confirmed());
}

#[test]
fn apply_msg_sub_flow_selected_unavailable_is_noop() {
    // Defensive: a stray SubFlowSelected for a sub-flow that is not
    // available given the vault's encryption mode (e.g. `Set` on an
    // encrypted vault) leaves the state untouched.
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Set),
    );
    assert_eq!(state.sub_flow(), SubFlow::Change);
}

// ---------------------------------------------------------------------------
// apply_msg — passphrase buffer mutators
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_new_passphrase_changed_updates_buffer() {
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    assert_eq!(state.new_passphrase(), "hunter2");
}

#[test]
fn apply_msg_confirm_passphrase_changed_updates_buffer() {
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );
    assert_eq!(state.confirm_passphrase(), "hunter2");
}

#[test]
fn apply_msg_typing_clears_stale_inline_rejection() {
    // A prior submit with mismatched passphrases would stamp
    // SubmitRejection::ConfirmationMismatch; resuming typing must
    // clear the inline rejection so the row no longer shows a stale
    // error against the new input.
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("a".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("b".into()),
    );
    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);
    assert!(state.inline_rejection().is_some());

    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("ab".into()),
    );

    assert!(state.inline_rejection().is_none());
}

// ---------------------------------------------------------------------------
// apply_msg — AcknowledgeRemove
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_acknowledge_remove_sets_flag() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );
    apply_msg(&mut state, PassphraseDialogMsg::AcknowledgeRemove(true));
    assert!(state.remove_confirmed());
}

#[test]
fn apply_msg_acknowledge_remove_unset_unsets_flag() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );
    apply_msg(&mut state, PassphraseDialogMsg::AcknowledgeRemove(true));
    apply_msg(&mut state, PassphraseDialogMsg::AcknowledgeRemove(false));
    assert!(!state.remove_confirmed());
}

// ---------------------------------------------------------------------------
// apply_msg — SubmitClicked: Set sub-flow accepts twice-confirmed
// non-empty passphrase and emits Submit(Set(...))
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_submit_set_with_match_emits_submit_and_clears_secrets() {
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );

    let output = apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    match output {
        Some(PassphraseDialogOutput::Submit(SubmitPayload::Set(_options))) => {}
        other => panic!("expected Submit(Set(_)), got {other:?}"),
    }
    // Submit takes the secret out of the state's shadow buffers.
    assert!(state.new_passphrase().is_empty());
    assert!(state.confirm_passphrase().is_empty());
}

#[test]
fn apply_msg_submit_set_with_mismatch_stamps_inline_rejection_and_no_output() {
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter3".into()),
    );

    let output = apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(output.is_none());
    assert_eq!(
        state.inline_rejection(),
        Some(&SubmitRejection::ConfirmationMismatch)
    );
    // Buffers stay so the user can fix without retyping.
    assert_eq!(state.new_passphrase(), "hunter2");
    assert_eq!(state.confirm_passphrase(), "hunter3");
}

#[test]
fn apply_msg_submit_set_with_both_empty_stamps_zero_length() {
    let mut state = PassphraseDialogState::new(false);
    let output = apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);
    assert!(output.is_none());
    assert_eq!(state.inline_rejection(), Some(&SubmitRejection::ZeroLength));
}

// ---------------------------------------------------------------------------
// apply_msg — SubmitClicked: Change sub-flow mirrors Set
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_submit_change_with_match_emits_submit_change() {
    let mut state = PassphraseDialogState::new(true);
    assert_eq!(state.sub_flow(), SubFlow::Change);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );

    let output = apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);
    match output {
        Some(PassphraseDialogOutput::Submit(SubmitPayload::Change(_))) => {}
        other => panic!("expected Submit(Change(_)), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// apply_msg — SubmitClicked: Remove sub-flow needs the acknowledgement
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_submit_remove_without_ack_is_blocked() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );

    let output = apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(output.is_none());
    // No inline_rejection — the gate is the un-ticked checkbox, not
    // a passphrase validation error.
    assert!(state.inline_rejection().is_none());
}

#[test]
fn apply_msg_submit_remove_with_ack_emits_submit_remove() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );
    apply_msg(&mut state, PassphraseDialogMsg::AcknowledgeRemove(true));

    let output = apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);
    match output {
        Some(PassphraseDialogOutput::Submit(SubmitPayload::Remove)) => {}
        other => panic!("expected Submit(Remove), got {other:?}"),
    }
    // Acknowledgement consumed on submit; the dialog will close on success.
    assert!(!state.remove_confirmed());
}

// ---------------------------------------------------------------------------
// apply_msg — Cancel clears all secret state and emits Close.
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_cancel_emits_close_and_wipes_secrets() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );

    let output = apply_msg(&mut state, PassphraseDialogMsg::Cancel);
    assert!(matches!(output, Some(PassphraseDialogOutput::Close)));
    assert!(state.new_passphrase().is_empty());
    assert!(state.confirm_passphrase().is_empty());
    assert!(!state.remove_confirmed());
}

// ---------------------------------------------------------------------------
// apply_msg — WorkerFailed re-renders inline error / warning
// ---------------------------------------------------------------------------

#[test]
fn apply_msg_worker_failed_save_not_committed_routes_to_inline_error() {
    use paladin_core::PaladinError;

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_passphrase_error(&err);
    assert!(matches!(outcome, PassphraseErrorOutcome::RestorePrior(_)));

    let mut state = PassphraseDialogState::new(false);
    let output = apply_msg(&mut state, PassphraseDialogMsg::WorkerFailed(outcome));
    assert!(output.is_none());
    assert!(matches!(
        state.worker_outcome(),
        Some(PassphraseErrorOutcome::RestorePrior(_))
    ));
}

#[test]
fn apply_msg_worker_failed_durability_unconfirmed_routes_to_warning() {
    use paladin_core::PaladinError;

    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_passphrase_error(&err);
    assert!(matches!(
        outcome,
        PassphraseErrorOutcome::KeepNewWithWarning(_)
    ));

    let mut state = PassphraseDialogState::new(false);
    apply_msg(&mut state, PassphraseDialogMsg::WorkerFailed(outcome));
    assert!(matches!(
        state.worker_outcome(),
        Some(PassphraseErrorOutcome::KeepNewWithWarning(_))
    ));
}

#[test]
fn classify_passphrase_error_invalid_state_routes_to_inline_error_variant() {
    use paladin_core::PaladinError;

    let err = PaladinError::InvalidState {
        operation: "set_passphrase",
        state: "already_encrypted",
    };
    let outcome = classify_passphrase_error(&err);
    assert!(matches!(outcome, PassphraseErrorOutcome::InlineError(_)));
}

// ---------------------------------------------------------------------------
// PassphraseDialogState::submit_button_sensitive — gates the Save
// button so the user cannot bypass the visible gate.
// ---------------------------------------------------------------------------

#[test]
fn submit_button_insensitive_for_set_with_empty_buffers() {
    let state = PassphraseDialogState::new(false);
    assert!(!state.submit_button_sensitive());
}

#[test]
fn submit_button_sensitive_for_set_with_matching_non_empty_buffers() {
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );
    assert!(state.submit_button_sensitive());
}

#[test]
fn submit_button_insensitive_for_change_with_mismatched_buffers() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter3".into()),
    );
    assert!(!state.submit_button_sensitive());
}

#[test]
fn submit_button_insensitive_for_remove_without_acknowledgement() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );
    assert!(!state.submit_button_sensitive());
}

#[test]
fn submit_button_sensitive_for_remove_with_acknowledgement() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );
    apply_msg(&mut state, PassphraseDialogMsg::AcknowledgeRemove(true));
    assert!(state.submit_button_sensitive());
}

// ---------------------------------------------------------------------------
// run_passphrase_worker — round-trips (vault, store) and runs the
// matching Vault transition for each sub-flow against an on-disk
// tempfile vault so the §4.5 rollback / durability semantics are
// authoritative.
// ---------------------------------------------------------------------------

fn fresh_plaintext_vault() -> (paladin_core::Vault, paladin_core::Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    let path = dir.path().join("vault.bin");
    let (vault, store) =
        paladin_core::Store::create(path.as_path(), paladin_core::VaultInit::Plaintext)
            .expect("store create");
    (vault, store, dir)
}

#[test]
fn run_passphrase_worker_set_encrypts_plaintext_vault() {
    use secrecy::SecretString;

    let (vault, store, _dir) = fresh_plaintext_vault();
    assert!(!vault.is_encrypted());

    let options = paladin_core::EncryptionOptions::new(SecretString::from("hunter2".to_string()))
        .expect("encryption options");
    let input = PassphraseWorkerInput {
        vault,
        store,
        payload: SubmitPayload::Set(options),
    };

    let PassphraseWorkerCompletion {
        effect,
        vault,
        store: _,
    } = run_passphrase_worker(input);

    match effect {
        PassphraseWorkerEffect::Success {
            sub_flow,
            new_is_encrypted,
        } => {
            assert_eq!(sub_flow, SubFlow::Set);
            assert!(new_is_encrypted);
        }
        PassphraseWorkerEffect::Failure(_) => panic!("expected Success"),
    }
    assert!(vault.is_encrypted());
}

#[test]
fn run_passphrase_worker_remove_decrypts_encrypted_vault() {
    use secrecy::SecretString;

    // Build an encrypted vault by going through Set first.
    let (vault, store, _dir) = fresh_plaintext_vault();
    let opts = paladin_core::EncryptionOptions::new(SecretString::from("hunter2".to_string()))
        .expect("options");
    let completion = run_passphrase_worker(PassphraseWorkerInput {
        vault,
        store,
        payload: SubmitPayload::Set(opts),
    });
    let vault = completion.vault;
    let store = completion.store;
    assert!(vault.is_encrypted());

    let completion = run_passphrase_worker(PassphraseWorkerInput {
        vault,
        store,
        payload: SubmitPayload::Remove,
    });
    match completion.effect {
        PassphraseWorkerEffect::Success {
            sub_flow,
            new_is_encrypted,
        } => {
            assert_eq!(sub_flow, SubFlow::Remove);
            assert!(!new_is_encrypted);
        }
        PassphraseWorkerEffect::Failure(_) => panic!("expected Success"),
    }
    assert!(!completion.vault.is_encrypted());
}

#[test]
fn run_passphrase_worker_set_on_already_encrypted_returns_failure_with_pair() {
    use secrecy::SecretString;

    let (vault, store, _dir) = fresh_plaintext_vault();
    let opts = paladin_core::EncryptionOptions::new(SecretString::from("hunter2".to_string()))
        .expect("options");
    let completion = run_passphrase_worker(PassphraseWorkerInput {
        vault,
        store,
        payload: SubmitPayload::Set(opts),
    });
    let vault = completion.vault;
    let store = completion.store;
    assert!(vault.is_encrypted());

    // Now attempt Set again — should fail with invalid_state.
    let opts2 = paladin_core::EncryptionOptions::new(SecretString::from("hunter3".to_string()))
        .expect("options");
    let completion = run_passphrase_worker(PassphraseWorkerInput {
        vault,
        store,
        payload: SubmitPayload::Set(opts2),
    });
    assert!(matches!(
        completion.effect,
        PassphraseWorkerEffect::Failure(PassphraseErrorOutcome::InlineError(_))
    ));
    // (Vault, Store) pair returned on failure so AppModel can reinstall.
    assert!(completion.vault.is_encrypted());
}

// ---------------------------------------------------------------------------
// Dispatching / busy state — pin the §"In-flight effect ownership"
// gating shadow the `PassphraseDialog` owns. `AppModel` mounts the
// `Unlocked → UnlockedBusy` busy-gate at the same instant the
// dialog flips `dispatching = true`; the dialog's own controls
// disable so a stray keyboard accelerator cannot fire a second
// Submit / Cancel while the `gio::spawn_blocking` worker is in
// flight.
// ---------------------------------------------------------------------------

#[test]
fn passphrase_dialog_state_new_starts_idle() {
    let plaintext = PassphraseDialogState::new(false);
    assert!(!plaintext.is_dispatching());
    let encrypted = PassphraseDialogState::new(true);
    assert!(!encrypted.is_dispatching());
}

#[test]
fn apply_msg_submit_set_with_match_flips_dispatching_true() {
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );

    let output = apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(matches!(
        output,
        Some(PassphraseDialogOutput::Submit(SubmitPayload::Set(_)))
    ));
    assert!(
        state.is_dispatching(),
        "successful Submit must arm the dispatching busy gate"
    );
}

#[test]
fn apply_msg_submit_change_with_match_flips_dispatching_true() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );

    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(state.is_dispatching());
}

#[test]
fn apply_msg_submit_remove_with_ack_flips_dispatching_true() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );
    apply_msg(&mut state, PassphraseDialogMsg::AcknowledgeRemove(true));

    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(state.is_dispatching());
}

#[test]
fn apply_msg_submit_set_with_mismatch_leaves_dispatching_false() {
    // A pre-submit rejection (mismatch) must not arm the busy gate —
    // no worker is dispatched, so the dialog stays interactive.
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter3".into()),
    );

    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(
        !state.is_dispatching(),
        "rejected Submit must not arm the busy gate"
    );
}

#[test]
fn apply_msg_submit_remove_without_ack_leaves_dispatching_false() {
    let mut state = PassphraseDialogState::new(true);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::SubFlowSelected(SubFlow::Remove),
    );

    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(!state.is_dispatching());
}

#[test]
fn apply_msg_worker_failed_clears_dispatching() {
    use paladin_core::PaladinError;

    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );
    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);
    assert!(state.is_dispatching());

    let outcome = classify_passphrase_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    apply_msg(&mut state, PassphraseDialogMsg::WorkerFailed(outcome));

    assert!(
        !state.is_dispatching(),
        "WorkerFailed must release the busy gate so the dialog re-enables"
    );
}

#[test]
fn submit_button_insensitive_while_dispatching() {
    // Save button is bound to `submit_button_sensitive`; once the
    // worker is in flight the gate must close so a stray accelerator
    // cannot fire a second Submit over the running worker.
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );
    assert!(state.submit_button_sensitive());

    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(state.is_dispatching());
    assert!(
        !state.submit_button_sensitive(),
        "Save button must be insensitive while a worker is in flight"
    );
}

#[test]
fn cancel_button_insensitive_while_dispatching() {
    // Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect
    // ownership": "Dialog close/cancel is disabled for the surface
    // that owns the in-flight mutation until the worker returns".
    let mut state = PassphraseDialogState::new(false);
    assert!(state.cancel_button_sensitive());

    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );
    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(state.is_dispatching());
    assert!(
        !state.cancel_button_sensitive(),
        "Cancel must be insensitive while a worker is in flight"
    );
}

#[test]
fn spinner_visible_while_dispatching() {
    let mut state = PassphraseDialogState::new(false);
    assert!(!state.spinner_visible());

    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );
    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);

    assert!(state.spinner_visible());
}

#[test]
fn apply_msg_cancel_clears_dispatching_flag() {
    // Defensive: the widget hides Cancel while dispatching, but if a
    // stray Cancel arrives anyway, releasing the busy gate keeps the
    // post-state usable rather than locking the dialog up forever.
    let mut state = PassphraseDialogState::new(false);
    apply_msg(
        &mut state,
        PassphraseDialogMsg::NewPassphraseChanged("hunter2".into()),
    );
    apply_msg(
        &mut state,
        PassphraseDialogMsg::ConfirmPassphraseChanged("hunter2".into()),
    );
    apply_msg(&mut state, PassphraseDialogMsg::SubmitClicked);
    assert!(state.is_dispatching());

    apply_msg(&mut state, PassphraseDialogMsg::Cancel);

    assert!(!state.is_dispatching());
}
