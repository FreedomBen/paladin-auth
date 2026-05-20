// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic passphrase-dialog tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests >
//! `tests/passphrase_dialog_logic.rs`" checklist in
//! `IMPLEMENTATION_PLAN_04_GTK.md`:
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
    available_sub_flows, prepare_new_passphrase, remove_warning_body, SubFlow, SubmitRejection,
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
// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" entry
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
    use paladin_gtk::passphrase_dialog::{
        PassphraseDialogComponent, PassphraseDialogMsg, PassphraseDialogOutput,
    };
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
